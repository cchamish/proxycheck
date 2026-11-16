"""Offline threat intelligence stores and local database freshness metadata."""

from __future__ import annotations

import contextlib
import csv
import gzip
import hashlib
import io
import ipaddress
import json
import logging
import os
import socket
import sqlite3
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generic, Iterable, List, Optional, Tuple, TypeVar

from proxycheck.settings import (
    MAXMIND_ASN_DB_FILENAME,
    MAXMIND_CITY_DB_FILENAME,
    MAXMIND_COUNTRY_DB_FILENAME,
)

logger = logging.getLogger(__name__)

SFS_TOXIC_CIDR_FILENAME = "toxic_ip_cidr.txt"
SFS_LISTED_90_FILENAMES = (
    "listed_ip_90_ipv46_all.zip",
    "listed_ip_90_ipv46_all.txt",
    "listed_ip_90_ipv46_all.csv",
    "listed_ip_90_ipv46_all.gz",
    "listed_ip_90_ipv46_all.txt.gz",
    "listed_ip_90_ipv46_all.csv.gz",
)
SFS_LISTED_1_FILENAMES = (
    "listed_ip_1_ipv46_all.zip",
    "listed_ip_1_ipv46_all.txt",
    "listed_ip_1_ipv46_all.csv",
    "listed_ip_1_ipv46_all.gz",
    "listed_ip_1_ipv46_all.txt.gz",
    "listed_ip_1_ipv46_all.csv.gz",
)
SFS_SQLITE_FILENAME = "stopforumspam.sqlite3"

_SOURCE_MASK_90 = 1
_SOURCE_MASK_1 = 2

_DEFAULT_STALE_MAXMIND_SECONDS = 14 * 86400
_DEFAULT_STALE_SFS_TOXIC_SECONDS = 7 * 86400
_DEFAULT_STALE_SFS_90_SECONDS = 2 * 86400
_DEFAULT_STALE_SFS_1_SECONDS = 6 * 3600
_DEFAULT_STALE_RULES_SECONDS = 90 * 86400

_sfs_cache_lock = threading.Lock()
_sfs_toxic_cache_key: Optional[Tuple[str, int, int]] = None
_sfs_toxic_cache_index: Optional["_StopForumSpamCidrIndex"] = None
_sfs_sqlite_validated_state: Optional[Tuple[Optional[str], str, Optional[Tuple[int, int]]]] = None
_sfs_cache_warmed = False


class StopForumSpamCorruptDataError(ValueError):
    """Raised when a local StopForumSpam offline database archive cannot be parsed."""


def _get_setting(name: str, default: Any = None) -> Any:
    try:
        from django.conf import settings as django_settings

        if django_settings.configured:
            return getattr(django_settings, name, default)
    except ImportError, RuntimeError:
        return default
    return default


def _get_setting_or_env(name: str, default: str = "") -> str:
    setting_val = _get_setting(name, None)
    if isinstance(setting_val, str) and setting_val.strip():
        return setting_val.strip()
    env_val = os.environ.get(name, "").strip()
    if env_val:
        return env_val
    return default


def _get_positive_int_setting(name: str, default: int) -> int:
    raw = _get_setting(name, default)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
        return default
    return raw


def _expand_path(raw_path: str) -> str:
    cleaned = str(raw_path or "").strip()
    if not cleaned:
        return ""
    return os.path.expanduser(os.path.expandvars(cleaned))


def _base_dir() -> Path:
    configured = _get_setting("BASE_DIR", None)
    if configured:
        return Path(str(configured))
    return Path(__file__).resolve().parent.parent


def _standard_data_directories() -> List[Path]:
    from proxycheck.settings import _standard_data_directories as settings_data_dirs

    return list(settings_data_dirs(_base_dir()))


def _get_file_stat_signature(file_path: str | Path) -> Optional[Tuple[int, int]]:
    try:
        stat_res = os.stat(file_path)
    except OSError:
        return None
    return (stat_res.st_mtime_ns, stat_res.st_size)


def _find_in_directory(directory: Path, filenames: Tuple[str, ...]) -> Optional[Path]:
    for fname in filenames:
        direct = directory / fname
        if direct.is_file():
            return direct
    nested_dir = directory / "stopforumspam"
    if nested_dir.is_dir():
        for fname in filenames:
            nested = nested_dir / fname
            if nested.is_file():
                return nested
    return None


def _resolve_sfs_component_path(
    override_setting: str,
    configured_dir: str,
    filenames: Tuple[str, ...],
) -> Optional[Path]:
    explicit_raw = _expand_path(_get_setting_or_env(override_setting))
    if explicit_raw:
        explicit = Path(explicit_raw)
        if explicit.is_file():
            return explicit
        if explicit.is_dir():
            return _find_in_directory(explicit, filenames)
        return None

    if configured_dir:
        base = Path(_expand_path(configured_dir))
        if base.is_dir():
            return _find_in_directory(base, filenames)
        return None

    for directory in _standard_data_directories():
        matched = _find_in_directory(directory, filenames)
        if matched is not None:
            return matched
    return None


def _resolve_sfs_sqlite_path(
    configured_dir: str,
    listed_90: Optional[Path],
    listed_1: Optional[Path],
    toxic_cidr: Optional[Path],
) -> Optional[Path]:
    explicit_raw = _expand_path(_get_setting_or_env("STOPFORUMSPAM_SQLITE_PATH"))
    if explicit_raw:
        explicit = Path(explicit_raw)
        if explicit.is_dir():
            return explicit / SFS_SQLITE_FILENAME
        return explicit

    if configured_dir:
        return Path(_expand_path(configured_dir)) / SFS_SQLITE_FILENAME

    for anchor in (listed_90, listed_1, toxic_cidr):
        if anchor is not None:
            return anchor.parent / SFS_SQLITE_FILENAME

    for directory in _standard_data_directories():
        existing = _find_in_directory(directory, (SFS_SQLITE_FILENAME,))
        if existing is not None:
            return existing

    return _base_dir().parent / "data" / SFS_SQLITE_FILENAME


def resolve_stopforumspam_paths() -> Dict[str, Optional[Path]]:
    """Resolves local StopForumSpam database file paths using configured overrides or standard directories."""
    configured_dir = _get_setting_or_env("STOPFORUMSPAM_DB_DIR")
    toxic_cidr = _resolve_sfs_component_path(
        "STOPFORUMSPAM_TOXIC_CIDR_PATH",
        configured_dir,
        (SFS_TOXIC_CIDR_FILENAME,),
    )
    listed_90 = _resolve_sfs_component_path(
        "STOPFORUMSPAM_LISTED_90_PATH",
        configured_dir,
        SFS_LISTED_90_FILENAMES,
    )
    listed_1 = _resolve_sfs_component_path(
        "STOPFORUMSPAM_LISTED_1_PATH",
        configured_dir,
        SFS_LISTED_1_FILENAMES,
    )
    sqlite_index = _resolve_sfs_sqlite_path(configured_dir, listed_90, listed_1, toxic_cidr)
    return {
        "toxic_cidr": toxic_cidr,
        "listed_90": listed_90,
        "listed_1": listed_1,
        "sqlite_index": sqlite_index,
    }


def resolve_writable_data_dir(explicit_dir: str = "", setting_dir_name: str = "") -> Path:
    """Resolves the target directory for downloading and updating offline database files."""
    if explicit_dir.strip():
        return Path(_expand_path(explicit_dir))

    if setting_dir_name:
        configured = _expand_path(_get_setting_or_env(setting_dir_name))
        if configured:
            return Path(configured)

    tool_data_dir = _expand_path(os.environ.get("TOOL_DATA_DIR", ""))
    if tool_data_dir:
        tool_root = Path(tool_data_dir)
        legacy_www_data = tool_root / "www" / "python" / "data"
        if legacy_www_data.is_dir():
            return legacy_www_data
        return tool_root / "data"

    return _base_dir().parent / "data"


def has_any_local_stopforumspam_db() -> bool:
    """Returns True when at least one StopForumSpam offline dataset or index exists on disk."""
    paths = resolve_stopforumspam_paths()
    for key in ("toxic_cidr", "listed_90", "listed_1"):
        candidate = paths.get(key)
        if candidate is not None and candidate.is_file():
            return True
    sqlite_path = paths.get("sqlite_index")
    return bool(sqlite_path is not None and sqlite_path.is_file())


def get_stopforumspam_db_version() -> int:
    """Returns the newest nanosecond mtime across active StopForumSpam files, or zero when absent."""
    paths = resolve_stopforumspam_paths()
    newest = 0
    for key in ("toxic_cidr", "listed_90", "listed_1", "sqlite_index"):
        candidate = paths.get(key)
        if candidate is None:
            continue
        sig = _get_file_stat_signature(candidate)
        if sig is not None and sig[0] > newest:
            newest = sig[0]
    return newest


def _newest_mtime_iso(paths: Iterable[Optional[Path]]) -> Optional[str]:
    newest_mtime: Optional[float] = None
    for candidate in paths:
        if candidate is None:
            continue
        try:
            stat_res = os.stat(candidate)
        except OSError:
            continue
        if newest_mtime is None or stat_res.st_mtime > newest_mtime:
            newest_mtime = stat_res.st_mtime
    if newest_mtime is None:
        return None
    return datetime.fromtimestamp(newest_mtime, tz=timezone.utc).isoformat()


def _pack_ip_bytes(raw_ip: str) -> Optional[bytes]:
    cleaned = raw_ip.strip()
    if not cleaned:
        return None
    if ":" in cleaned:
        if "%" in cleaned:
            cleaned = cleaned.split("%", 1)[0]
        try:
            return socket.inet_pton(socket.AF_INET6, cleaned)
        except OSError:
            return None
    try:
        return socket.inet_pton(socket.AF_INET, cleaned)
    except OSError:
        return None


def _resolve_lookup_byte_keys(ip: str) -> Tuple[Optional[bytes], Optional[bytes]]:
    """Returns primary packed IP bytes plus an optional IPv4-mapped IPv4 fallback key."""
    if not isinstance(ip, str) or not ip.strip():
        return None, None
    cleaned = ip.strip()
    if "%" in cleaned and ":" in cleaned:
        cleaned = cleaned.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return None, None
    primary = addr.packed
    mapped = addr.ipv4_mapped.packed if getattr(addr, "ipv4_mapped", None) is not None else None
    return primary, mapped


_T = TypeVar("_T")


class PrefixCidrIndex(Generic[_T]):
    """In-memory prefix-bucketed index for fast IPv4 and IPv6 CIDR matching."""

    def __init__(self, entries: Iterable[Tuple[str, _T]]) -> None:
        v4_buckets: Dict[int, Dict[int, Tuple[str, _T]]] = {}
        v6_buckets: Dict[int, Dict[int, Tuple[str, _T]]] = {}

        for raw_cidr, payload in entries:
            if not isinstance(raw_cidr, str) or not raw_cidr.strip():
                continue
            try:
                net = ipaddress.ip_network(raw_cidr.strip(), strict=False)
            except ValueError:
                continue
            if net.prefixlen <= 0:
                continue
            target_buckets = v4_buckets if net.version == 4 else v6_buckets
            bucket = target_buckets.setdefault(net.prefixlen, {})
            net_int = int(net.network_address)
            if net_int not in bucket:
                bucket[net_int] = (str(net), payload)

        self.v4_prefixes: Tuple[Tuple[int, int, Dict[int, Tuple[str, _T]]], ...] = self._build_prefix_table(
            v4_buckets, 32
        )
        self.v6_prefixes: Tuple[Tuple[int, int, Dict[int, Tuple[str, _T]]], ...] = self._build_prefix_table(
            v6_buckets, 128
        )

    @staticmethod
    def _build_prefix_table(
        buckets: Dict[int, Dict[int, Tuple[str, _T]]],
        width: int,
    ) -> Tuple[Tuple[int, int, Dict[int, Tuple[str, _T]]], ...]:
        full_mask = (1 << width) - 1
        return tuple(
            (prefix_len, full_mask ^ ((1 << (width - prefix_len)) - 1), buckets[prefix_len])
            for prefix_len in sorted(buckets.keys(), reverse=True)
        )

    def lookup(self, ip: Optional[str]) -> Optional[Tuple[str, int, _T]]:
        """Matches an IPv4, IPv6, or IPv4-mapped IPv6 address against the longest prefix."""
        if not ip or not isinstance(ip, str):
            return None
        cleaned = ip.strip()
        if not cleaned:
            return None
        if "%" in cleaned and ":" in cleaned:
            cleaned = cleaned.split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(cleaned)
        except ValueError:
            return None

        if addr.version == 6:
            addr_int = int(addr)
            for prefix_len, mask, bucket in self.v6_prefixes:
                hit = bucket.get(addr_int & mask)
                if hit is not None:
                    return hit[0], prefix_len, hit[1]
            mapped_v4 = getattr(addr, "ipv4_mapped", None)
            if mapped_v4 is None:
                return None
            addr = mapped_v4

        addr_int = int(addr)
        for prefix_len, mask, bucket in self.v4_prefixes:
            hit = bucket.get(addr_int & mask)
            if hit is not None:
                return hit[0], prefix_len, hit[1]
        return None


def _iter_sfs_cidr_tokens(cidrs: Iterable[str]) -> Iterable[Tuple[str, None]]:
    for raw_line in cidrs:
        cleaned = raw_line.strip()
        if not cleaned or cleaned.startswith(("#", ";")):
            continue
        yield cleaned.split()[0].strip(), None


class _StopForumSpamCidrIndex(PrefixCidrIndex[None]):
    """In-memory prefix-bucketed index for StopForumSpam toxic CIDR lookups."""

    def __init__(self, cidrs: Iterable[str]) -> None:
        super().__init__(_iter_sfs_cidr_tokens(cidrs))

    def match(self, ip: Optional[str]) -> Optional[str]:
        hit = self.lookup(ip)
        return hit[0] if hit is not None else None


_EMPTY_SFS_CIDR_INDEX = _StopForumSpamCidrIndex(())


def _get_toxic_cidr_index(toxic_path: Optional[Path]) -> _StopForumSpamCidrIndex:
    global _sfs_toxic_cache_key, _sfs_toxic_cache_index

    if toxic_path is None or not toxic_path.is_file():
        with _sfs_cache_lock:
            _sfs_toxic_cache_key = None
            _sfs_toxic_cache_index = _EMPTY_SFS_CIDR_INDEX
        return _EMPTY_SFS_CIDR_INDEX

    sig = _get_file_stat_signature(toxic_path)
    if sig is None:
        return _EMPTY_SFS_CIDR_INDEX
    cache_key = (str(toxic_path), sig[0], sig[1])

    with _sfs_cache_lock:
        if _sfs_toxic_cache_key == cache_key and _sfs_toxic_cache_index is not None:
            return _sfs_toxic_cache_index

    with toxic_path.open("r", encoding="utf-8", errors="replace") as handle:
        index = _StopForumSpamCidrIndex(handle)

    with _sfs_cache_lock:
        _sfs_toxic_cache_key = cache_key
        _sfs_toxic_cache_index = index
    return index


def _compute_listed_source_signature(listed_90: Optional[Path], listed_1: Optional[Path]) -> Optional[str]:
    entries: List[List[Any]] = []
    for role, path in (("90d", listed_90), ("1d", listed_1)):
        if path is None:
            continue
        sig = _get_file_stat_signature(path)
        if sig is not None:
            entries.append([role, str(path), sig[0], sig[1]])
    if not entries:
        return None
    return json.dumps(entries, separators=(",", ":"))


@contextlib.contextmanager
def _open_sfs_text_stream(file_path: Path):
    suffix = file_path.suffix.lower()
    if suffix == ".zip":
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                members = [info for info in zf.infolist() if not info.is_dir()]
                if not members:
                    raise StopForumSpamCorruptDataError(f"Zip archive contains no data files: {file_path.name}")
                with zf.open(members[0], "r") as raw_member:
                    yield io.TextIOWrapper(raw_member, encoding="utf-8", errors="replace", newline="")
        except zipfile.BadZipFile as exc:
            raise StopForumSpamCorruptDataError(f"Corrupt StopForumSpam zip archive: {file_path.name}") from exc
    elif suffix == ".gz":
        try:
            with gzip.open(file_path, "rt", encoding="utf-8", errors="replace", newline="") as gz_handle:
                yield gz_handle
        except (OSError, EOFError, gzip.BadGzipFile) as exc:
            raise StopForumSpamCorruptDataError(f"Corrupt StopForumSpam gzip archive: {file_path.name}") from exc
    else:
        with file_path.open("r", encoding="utf-8", errors="replace", newline="") as txt_handle:
            yield txt_handle


def _parse_sfs_listed_line(raw_line: str) -> Optional[Tuple[bytes, int, str]]:
    stripped = raw_line.strip()
    if not stripped or stripped.startswith(("#", ";")):
        return None

    # Fast path for standard StopForumSpam Excel CSV lines: "IP","frequency","lastseen"
    if stripped.startswith('"') and stripped.endswith('"') and '","' in stripped:
        parts = stripped[1:-1].split('","')
        if len(parts) >= 3 and '"' not in parts[0] and '"' not in parts[1]:
            ip_bytes = _pack_ip_bytes(parts[0])
            if ip_bytes is None:
                return None
            try:
                frequency = max(0, int(parts[1].strip()))
            except ValueError:
                frequency = 1
            last_seen = parts[2].strip()
            return ip_bytes, frequency, last_seen

    row = next(csv.reader([stripped]))
    if not row:
        return None
    ip_bytes = _pack_ip_bytes(row[0])
    if ip_bytes is None:
        return None
    frequency = 1
    last_seen = ""
    if len(row) >= 2 and row[1].strip():
        try:
            frequency = max(0, int(row[1].strip()))
        except ValueError:
            frequency = 1
    if len(row) >= 3:
        last_seen = row[2].strip()
    return ip_bytes, frequency, last_seen


def _iter_sfs_listed_rows(file_path: Path, source_mask: int) -> Iterable[Tuple[bytes, int, str, int]]:
    with _open_sfs_text_stream(file_path) as stream:
        for line in stream:
            parsed = _parse_sfs_listed_line(line)
            if parsed is not None:
                yield parsed[0], parsed[1], parsed[2], source_mask


def _read_sqlite_source_signature(sqlite_path: Path) -> Optional[str]:
    if not sqlite_path.is_file():
        return None
    try:
        uri = f"{sqlite_path.resolve().as_uri()}?mode=ro"
        with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=1.0)) as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = ?", ("source_signature",)).fetchone()
            return str(row[0]) if row and row[0] is not None else None
    except sqlite3.Error, OSError:
        return None


def _atomic_replace_with_retry(src_path: Path, dst_path: Path) -> None:
    """Replaces dst_path atomically, retrying briefly on Windows transient reader collisions."""
    for attempt in range(6):
        try:
            os.replace(src_path, dst_path)
            return
        except PermissionError:
            if attempt == 5:
                raise
            time.sleep(0.05 * (attempt + 1))


atomic_replace_with_retry = _atomic_replace_with_retry


def build_stopforumspam_sqlite_index(
    target_sqlite_path: Path,
    listed_90: Optional[Path],
    listed_1: Optional[Path],
    *,
    source_signature: Optional[str] = None,
) -> int:
    """Builds a compact WITHOUT ROWID SQLite index from 90-day and 1-day SFS dumps and swaps it atomically."""
    computed_sig = source_signature or _compute_listed_source_signature(listed_90, listed_1)
    if computed_sig is None:
        raise ValueError("At least one StopForumSpam listed IP file is required to build the SQLite index.")

    target_sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target_sqlite_path.with_name(f".{target_sqlite_path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    total_inserted = 0

    try:
        conn = sqlite3.connect(tmp_path)
        try:
            conn.execute("PRAGMA journal_mode = OFF")
            conn.execute("PRAGMA synchronous = OFF")
            conn.execute("PRAGMA temp_store = MEMORY")
            conn.execute("PRAGMA cache_size = -32768")
            conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute(
                "CREATE TABLE listed_ips ("
                "ip BLOB PRIMARY KEY, "
                "frequency INTEGER NOT NULL, "
                "last_seen TEXT NOT NULL, "
                "source_mask INTEGER NOT NULL"
                ") WITHOUT ROWID"
            )
            upsert_sql = (
                "INSERT INTO listed_ips (ip, frequency, last_seen, source_mask) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(ip) DO UPDATE SET "
                "frequency = MAX(listed_ips.frequency, excluded.frequency), "
                "last_seen = CASE WHEN excluded.last_seen > listed_ips.last_seen "
                "THEN excluded.last_seen ELSE listed_ips.last_seen END, "
                "source_mask = listed_ips.source_mask | excluded.source_mask"
            )

            batch: List[Tuple[bytes, int, str, int]] = []
            for path, mask in ((listed_90, _SOURCE_MASK_90), (listed_1, _SOURCE_MASK_1)):
                if path is None or not path.is_file():
                    continue
                for entry in _iter_sfs_listed_rows(path, mask):
                    batch.append(entry)
                    total_inserted += 1
                    if len(batch) >= 20000:
                        conn.executemany(upsert_sql, batch)
                        batch.clear()
            if batch:
                conn.executemany(upsert_sql, batch)
                batch.clear()

            row_count_row = conn.execute("SELECT COUNT(*) FROM listed_ips").fetchone()
            unique_count = int(row_count_row[0]) if row_count_row else 0
            conn.executemany(
                "INSERT INTO meta (key, value) VALUES (?, ?)",
                (
                    ("source_signature", computed_sig),
                    ("built_at", datetime.now(timezone.utc).isoformat()),
                    ("unique_ips", str(unique_count)),
                    ("raw_rows", str(total_inserted)),
                ),
            )
            conn.commit()
        finally:
            conn.close()

        with contextlib.suppress(OSError):
            os.chmod(tmp_path, 0o644)
        _atomic_replace_with_retry(tmp_path, target_sqlite_path)
        return total_inserted
    finally:
        if tmp_path.exists():
            with contextlib.suppress(OSError):
                tmp_path.unlink()


def _fallback_temp_sqlite_path(source_signature: str) -> Path:
    digest = hashlib.sha256(source_signature.encode("utf-8")).hexdigest()[:12]
    return Path(tempfile.gettempdir()) / "proxycheck_sfs_cache" / f"stopforumspam_{digest}.sqlite3"


def _ensure_stopforumspam_sqlite_index(paths: Dict[str, Optional[Path]]) -> Optional[Path]:
    global _sfs_sqlite_validated_state

    listed_90 = paths.get("listed_90")
    listed_1 = paths.get("listed_1")
    sqlite_path = paths.get("sqlite_index")
    source_sig = _compute_listed_source_signature(listed_90, listed_1)

    if source_sig is None:
        if sqlite_path is not None and sqlite_path.is_file():
            return sqlite_path
        with _sfs_cache_lock:
            _sfs_sqlite_validated_state = None
        return None

    candidate_primary = sqlite_path or (_base_dir().parent / "data" / SFS_SQLITE_FILENAME)
    with _sfs_cache_lock:
        validated = _sfs_sqlite_validated_state
    if validated is not None and validated[0] == source_sig:
        cached_path = Path(validated[1])
        if _get_file_stat_signature(cached_path) == validated[2]:
            return cached_path

    with _sfs_cache_lock:
        validated = _sfs_sqlite_validated_state
        if validated is not None and validated[0] == source_sig:
            cached_path = Path(validated[1])
            if _get_file_stat_signature(cached_path) == validated[2]:
                return cached_path

        fallback_path = _fallback_temp_sqlite_path(source_sig)
        for existing_candidate in (candidate_primary, fallback_path):
            if _read_sqlite_source_signature(existing_candidate) == source_sig:
                _sfs_sqlite_validated_state = (
                    source_sig,
                    str(existing_candidate),
                    _get_file_stat_signature(existing_candidate),
                )
                return existing_candidate

        try:
            build_stopforumspam_sqlite_index(
                candidate_primary,
                listed_90,
                listed_1,
                source_signature=source_sig,
            )
            chosen_path = candidate_primary
        except (OSError, sqlite3.Error) as primary_err:
            logger.warning(
                "Could not write StopForumSpam index to %s (%s); building in temporary cache directory",
                candidate_primary,
                primary_err,
            )
            build_stopforumspam_sqlite_index(
                fallback_path,
                listed_90,
                listed_1,
                source_signature=source_sig,
            )
            chosen_path = fallback_path

        _sfs_sqlite_validated_state = (
            source_sig,
            str(chosen_path),
            _get_file_stat_signature(chosen_path),
        )
        return chosen_path


def _lookup_ip_in_sqlite(sqlite_path: Path, ip: str) -> Optional[Tuple[int, str, int]]:
    primary_key, mapped_key = _resolve_lookup_byte_keys(ip)
    if primary_key is None:
        return None
    uri = f"{sqlite_path.resolve().as_uri()}?mode=ro"
    with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=1.0)) as conn:
        row = conn.execute(
            "SELECT frequency, last_seen, source_mask FROM listed_ips WHERE ip = ?",
            (primary_key,),
        ).fetchone()
        if row is None and mapped_key is not None:
            row = conn.execute(
                "SELECT frequency, last_seen, source_mask FROM listed_ips WHERE ip = ?",
                (mapped_key,),
            ).fetchone()
    if row is None:
        return None
    return int(row[0]), str(row[1] or ""), int(row[2])


def query_stopforumspam_offline(ip: str) -> Dict[str, Any]:
    """Queries local StopForumSpam toxic CIDR and listed IP databases with automatic mtime hot-reload."""
    global _sfs_cache_warmed

    paths = resolve_stopforumspam_paths()
    toxic_path = paths.get("toxic_cidr")
    listed_90_path = paths.get("listed_90")
    listed_1_path = paths.get("listed_1")
    sqlite_path = paths.get("sqlite_index")

    has_toxic = toxic_path is not None and toxic_path.is_file()
    has_listed = (
        (listed_90_path is not None and listed_90_path.is_file())
        or (listed_1_path is not None and listed_1_path.is_file())
        or (sqlite_path is not None and sqlite_path.is_file())
    )

    if not has_toxic and not has_listed:
        return {
            "has_db": False,
            "appears": False,
            "blacklisted": False,
            "toxic_cidr": None,
            "frequency": 0,
            "last_seen": None,
            "sources": [],
            "offline_db_updated_at": None,
            "db_version": 0,
        }

    toxic_cidr_hit: Optional[str] = None
    if has_toxic:
        toxic_cidr_hit = _get_toxic_cidr_index(toxic_path).match(ip)

    listed_hit: Optional[Tuple[int, str, int]] = None
    active_sqlite: Optional[Path] = None
    if has_listed:
        active_sqlite = _ensure_stopforumspam_sqlite_index(paths)
        if active_sqlite is not None and active_sqlite.is_file():
            listed_hit = _lookup_ip_in_sqlite(active_sqlite, ip)

    with _sfs_cache_lock:
        _sfs_cache_warmed = True

    sources: List[str] = []
    if toxic_cidr_hit is not None:
        sources.append("toxic_ip_cidr")
    frequency = 0
    last_seen: Optional[str] = None
    if listed_hit is not None:
        frequency = max(0, listed_hit[0])
        last_seen = listed_hit[1].strip() or None
        source_mask = listed_hit[2]
        if source_mask & _SOURCE_MASK_90:
            sources.append("listed_ip_90")
        if source_mask & _SOURCE_MASK_1:
            sources.append("listed_ip_1")

    blacklisted = toxic_cidr_hit is not None
    appears = blacklisted or (listed_hit is not None)
    active_files = [toxic_path, listed_90_path, listed_1_path, active_sqlite]
    return {
        "has_db": True,
        "appears": appears,
        "blacklisted": blacklisted,
        "toxic_cidr": toxic_cidr_hit,
        "frequency": frequency,
        "last_seen": last_seen,
        "sources": sources,
        "offline_db_updated_at": _newest_mtime_iso(active_files),
        "db_version": get_stopforumspam_db_version(),
    }


def warm_stopforumspam_caches() -> None:
    """Preloads StopForumSpam toxic CIDRs and builds or validates the SQLite index off the event loop."""
    global _sfs_cache_warmed

    paths = resolve_stopforumspam_paths()
    toxic_path = paths.get("toxic_cidr")
    _get_toxic_cidr_index(toxic_path)
    try:
        _ensure_stopforumspam_sqlite_index(paths)
    except (OSError, sqlite3.Error, ValueError) as exc:
        logger.warning("Failed to warm StopForumSpam SQLite index: %s", exc)
    with _sfs_cache_lock:
        _sfs_cache_warmed = True


def are_stopforumspam_caches_warm() -> bool:
    with _sfs_cache_lock:
        return _sfs_cache_warmed


def clear_stopforumspam_caches() -> None:
    global _sfs_toxic_cache_key, _sfs_toxic_cache_index, _sfs_sqlite_validated_state, _sfs_cache_warmed
    with _sfs_cache_lock:
        _sfs_toxic_cache_key = None
        _sfs_toxic_cache_index = None
        _sfs_sqlite_validated_state = None
        _sfs_cache_warmed = False


def resolve_maxmind_paths() -> Dict[str, Path]:
    """Resolves Country, City, and ASN MMDB paths using configured MAXMIND_DB_DIR or fallbacks."""
    from proxycheck.settings import resolve_mmdb_file

    base_dir = _base_dir()
    configured_dir = _get_setting_or_env("MAXMIND_DB_DIR")
    return {
        "country": Path(resolve_mmdb_file(configured_dir, MAXMIND_COUNTRY_DB_FILENAME, base_dir)),
        "city": Path(resolve_mmdb_file(configured_dir, MAXMIND_CITY_DB_FILENAME, base_dir)),
        "asn": Path(resolve_mmdb_file(configured_dir, MAXMIND_ASN_DB_FILENAME, base_dir)),
    }


def get_maxmind_newest_mtime_iso() -> Optional[str]:
    """Returns the newest UTC ISO-8601 modification timestamp across existing MaxMind MMDB files."""
    paths = resolve_maxmind_paths()
    return _newest_mtime_iso(path for path in paths.values() if path.is_file())


def _resolve_rule_file(setting_name: str, filenames: Tuple[str, ...]) -> Tuple[Optional[Path], str]:
    from proxycheck.settings import resolve_data_file

    raw_configured = _get_setting_or_env(setting_name)
    base_dir = _base_dir()
    if raw_configured:
        expanded = Path(_expand_path(raw_configured))
        if expanded.is_file():
            return expanded, expanded.name
        if expanded.is_dir():
            for fname in filenames:
                candidate = expanded / fname
                if candidate.is_file():
                    return candidate, candidate.name
            return None, filenames[0]
        default_missing = base_dir.parent / "data" / filenames[0]
        if expanded != default_missing:
            return None, expanded.name or filenames[0]

    for fname in filenames:
        resolved = resolve_data_file("", fname, base_dir, default_missing="")
        if resolved:
            candidate = Path(resolved)
            if candidate.is_file():
                return candidate, candidate.name
    return None, filenames[0]


def _build_offline_db_entry(
    *,
    key: str,
    source: str,
    name: str,
    file_path: Optional[Path],
    fallback_filename: str,
    optional: bool,
    stale_after_seconds: int,
    now_ts: float,
    missing_label: Optional[str] = None,
) -> Dict[str, Any]:
    filename = file_path.name if file_path is not None else fallback_filename
    stat_res = None
    if file_path is not None:
        try:
            if file_path.is_file():
                stat_res = os.stat(file_path)
        except OSError:
            stat_res = None

    if stat_res is None:
        resolved_missing_label = (
            missing_label if missing_label is not None else ("Optional (Not Configured)" if optional else "Missing")
        )
        return {
            "key": key,
            "source": source,
            "name": name,
            "filename": filename,
            "exists": False,
            "optional": optional,
            "sizeBytes": None,
            "lastModifiedIso": None,
            "ageSeconds": None,
            "staleAfterSeconds": stale_after_seconds,
            "status": "missing",
            "statusLabel": resolved_missing_label,
        }

    mtime_ts = float(stat_res.st_mtime)
    age_seconds = max(0, int(now_ts - mtime_ts))
    is_stale = stale_after_seconds > 0 and age_seconds > stale_after_seconds
    last_modified_iso = datetime.fromtimestamp(mtime_ts, tz=timezone.utc).isoformat()
    return {
        "key": key,
        "source": source,
        "name": name,
        "filename": filename,
        "exists": True,
        "optional": optional,
        "sizeBytes": int(stat_res.st_size),
        "lastModifiedIso": last_modified_iso,
        "ageSeconds": age_seconds,
        "staleAfterSeconds": stale_after_seconds,
        "status": "stale" if is_stale else "healthy",
        "statusLabel": "Stale" if is_stale else "Healthy",
    }


def build_offline_database_entries(
    *,
    maxmind_paths: Dict[str, Optional[Path]],
    sfs_paths: Dict[str, Optional[Path]],
    cloud_cidr_path: Optional[Path],
    cloud_cidr_name: str,
    hosting_rules_path: Optional[Path],
    hosting_rules_name: str,
    maxmind_stale: int,
    sfs_toxic_stale: int,
    sfs_90_stale: int,
    sfs_1_stale: int,
    rules_stale: int,
    now_ts: float,
    include_resolved_path: bool = False,
) -> List[Dict[str, Any]]:
    """Builds standardised status entries for all configured offline databases and rule files."""
    specs = (
        (
            "maxmind_country",
            "MaxMind",
            "MaxMind GeoLite2 Country",
            maxmind_paths.get("country"),
            MAXMIND_COUNTRY_DB_FILENAME,
            False,
            maxmind_stale,
            None,
        ),
        (
            "maxmind_city",
            "MaxMind",
            "MaxMind GeoLite2 City",
            maxmind_paths.get("city"),
            MAXMIND_CITY_DB_FILENAME,
            False,
            maxmind_stale,
            None,
        ),
        (
            "maxmind_asn",
            "MaxMind",
            "MaxMind GeoLite2 ASN",
            maxmind_paths.get("asn"),
            MAXMIND_ASN_DB_FILENAME,
            False,
            maxmind_stale,
            None,
        ),
        (
            "stopforumspam_toxic_cidr",
            "StopForumSpam",
            "StopForumSpam Toxic CIDRs",
            sfs_paths.get("toxic_cidr"),
            SFS_TOXIC_CIDR_FILENAME,
            False,
            sfs_toxic_stale,
            None,
        ),
        (
            "stopforumspam_listed_90",
            "StopForumSpam",
            "StopForumSpam Listed IPs (90d)",
            sfs_paths.get("listed_90"),
            SFS_LISTED_90_FILENAMES[0],
            False,
            sfs_90_stale,
            None,
        ),
        (
            "stopforumspam_listed_1",
            "StopForumSpam",
            "StopForumSpam Listed IPs (1d)",
            sfs_paths.get("listed_1"),
            SFS_LISTED_1_FILENAMES[0],
            True,
            sfs_1_stale,
            None,
        ),
        (
            "stopforumspam_index",
            "StopForumSpam",
            "StopForumSpam Local SQLite Index",
            sfs_paths.get("sqlite_index"),
            SFS_SQLITE_FILENAME,
            True,
            sfs_90_stale,
            None,
        ),
        (
            "cloud_cidrs",
            "Cloud CIDRs",
            "Cloud Provider CIDRs",
            cloud_cidr_path,
            cloud_cidr_name,
            True,
            rules_stale,
            "Built-in (Optional)",
        ),
        (
            "hosting_asn_rules",
            "Hosting Rules",
            "Hosting ASN Rules",
            hosting_rules_path,
            hosting_rules_name,
            True,
            rules_stale,
            "Built-in (Optional)",
        ),
    )

    entries: List[Dict[str, Any]] = []
    for key, source, name, file_path, fallback_filename, optional, stale_after_seconds, missing_label in specs:
        entry = _build_offline_db_entry(
            key=key,
            source=source,
            name=name,
            file_path=file_path,
            fallback_filename=fallback_filename,
            optional=optional,
            stale_after_seconds=stale_after_seconds,
            now_ts=now_ts,
            missing_label=missing_label,
        )
        if include_resolved_path:
            entry["resolvedPath"] = str(file_path) if file_path is not None else ""
        entries.append(entry)
    return entries


def collect_offline_databases_status(*, now_dt: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Inventories all local offline databases and rules using file mtime metadata."""
    current_dt = now_dt or datetime.now(timezone.utc)
    now_ts = current_dt.timestamp()

    maxmind_stale = _get_positive_int_setting("OFFLINE_DB_MAXMIND_STALE_SECONDS", _DEFAULT_STALE_MAXMIND_SECONDS)
    sfs_toxic_stale = _get_positive_int_setting("OFFLINE_DB_SFS_TOXIC_STALE_SECONDS", _DEFAULT_STALE_SFS_TOXIC_SECONDS)
    sfs_90_stale = _get_positive_int_setting("OFFLINE_DB_SFS_90_STALE_SECONDS", _DEFAULT_STALE_SFS_90_SECONDS)
    sfs_1_stale = _get_positive_int_setting("OFFLINE_DB_SFS_1_STALE_SECONDS", _DEFAULT_STALE_SFS_1_SECONDS)
    rules_stale = _get_positive_int_setting("OFFLINE_DB_RULES_STALE_SECONDS", _DEFAULT_STALE_RULES_SECONDS)

    maxmind_paths = resolve_maxmind_paths()
    sfs_paths = resolve_stopforumspam_paths()
    cloud_cidr_path, cloud_cidr_name = _resolve_rule_file(
        "CLOUD_CIDR_DB_PATH", ("cloud_cidrs.json", "computehosts.json")
    )
    hosting_rules_path, hosting_rules_name = _resolve_rule_file("HOSTING_ASN_RULES_PATH", ("hosting_asn_rules.json",))

    return build_offline_database_entries(
        maxmind_paths=maxmind_paths,
        sfs_paths=sfs_paths,
        cloud_cidr_path=cloud_cidr_path,
        cloud_cidr_name=cloud_cidr_name,
        hosting_rules_path=hosting_rules_path,
        hosting_rules_name=hosting_rules_name,
        maxmind_stale=maxmind_stale,
        sfs_toxic_stale=sfs_toxic_stale,
        sfs_90_stale=sfs_90_stale,
        sfs_1_stale=sfs_1_stale,
        rules_stale=rules_stale,
        now_ts=now_ts,
    )
