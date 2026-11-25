"""StopForumSpam offline SQLite index builder, reader, and toxic CIDR matcher."""

from __future__ import annotations

import contextlib
import csv
import gzip
import io
import json
import logging
import os
import sqlite3
import threading
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from proxycheck.settings import expand_configured_path

from .prefix_index import sync_file_to_ephemeral_cache
from .store import (
    _SOURCE_MASK_1,
    _SOURCE_MASK_90,
    SFS_LISTED_1_FILENAMES,
    SFS_LISTED_90_FILENAMES,
    SFS_SQLITE_FILENAME,
    SFS_TOXIC_CIDR_FILENAME,
    FileStatCache,
    PrefixCidrIndex,
    _effective_base_dir,
    _effective_standard_dirs,
    _is_regular_file,
    _lookup_config_value,
    _newest_mtime_iso,
    _pack_ip_bytes,
    _resolve_lookup_byte_keys,
    atomic_temp_path,
    get_file_stat_signature,
    resolve_configured_data_dir,
    resolve_local_ephemeral_cache_dir,
)

logger = logging.getLogger(__name__)


class StopForumSpamCorruptDataError(ValueError):
    """Raised when a local StopForumSpam offline database archive cannot be parsed."""


def find_sfs_in_directory(
    directory: Path,
    filenames: Tuple[str, ...],
    *,
    bypass_throttle: bool = False,
) -> Optional[Path]:
    """Locates a StopForumSpam data file in directory or its nested stopforumspam subfolder."""
    for fname in filenames:
        direct = directory / fname
        if _is_regular_file(direct, bypass_throttle=bypass_throttle):
            return direct
    nested_dir = directory / "stopforumspam"
    for fname in filenames:
        nested = nested_dir / fname
        if _is_regular_file(nested, bypass_throttle=bypass_throttle):
            return nested
    return None


def _resolve_sfs_component_path(
    override_setting: str,
    configured_dir: str,
    filenames: Tuple[str, ...],
    standard_dirs: Sequence[Path],
    *,
    env_overrides: Optional[Mapping[str, str]] = None,
    bypass_throttle: bool = False,
) -> Optional[Path]:
    explicit_raw = expand_configured_path(_lookup_config_value(override_setting, env_overrides=env_overrides))
    if explicit_raw:
        explicit = Path(explicit_raw)
        if _is_regular_file(explicit, bypass_throttle=bypass_throttle):
            return explicit
        return find_sfs_in_directory(explicit, filenames, bypass_throttle=bypass_throttle)

    if configured_dir:
        base = Path(expand_configured_path(configured_dir))
        return find_sfs_in_directory(base, filenames, bypass_throttle=bypass_throttle)

    for directory in standard_dirs:
        matched = find_sfs_in_directory(directory, filenames, bypass_throttle=bypass_throttle)
        if matched is not None:
            return matched
    return None


def _resolve_sfs_sqlite_path(
    configured_dir: str,
    listed_90: Optional[Path],
    listed_1: Optional[Path],
    toxic_cidr: Optional[Path],
    standard_dirs: Sequence[Path],
    resolved_base: Path,
    *,
    env_overrides: Optional[Mapping[str, str]] = None,
    bypass_throttle: bool = False,
) -> Optional[Path]:
    explicit_raw = expand_configured_path(
        _lookup_config_value("STOPFORUMSPAM_SQLITE_PATH", env_overrides=env_overrides)
    )
    if explicit_raw:
        explicit = Path(explicit_raw)
        if explicit.suffix.lower() in (".sqlite3", ".sqlite", ".db") or _is_regular_file(
            explicit, bypass_throttle=bypass_throttle
        ):
            return explicit
        if explicit.is_dir():
            return explicit / SFS_SQLITE_FILENAME
        return explicit

    if configured_dir:
        return Path(expand_configured_path(configured_dir)) / SFS_SQLITE_FILENAME

    for anchor in (listed_90, listed_1, toxic_cidr):
        if anchor is not None:
            return anchor.parent / SFS_SQLITE_FILENAME

    for directory in standard_dirs:
        existing = find_sfs_in_directory(directory, (SFS_SQLITE_FILENAME,), bypass_throttle=bypass_throttle)
        if existing is not None:
            return existing

    return resolved_base.parent / "data" / SFS_SQLITE_FILENAME


def resolve_stopforumspam_paths(
    *,
    env_overrides: Optional[Mapping[str, str]] = None,
    base_dir: Optional[Path] = None,
    bypass_throttle: bool = False,
) -> Dict[str, Optional[Path]]:
    """Resolves local StopForumSpam database file paths using TOOL_DATA_DIR, overrides, or fallbacks."""
    resolved_base = _effective_base_dir(base_dir)
    standard_dirs = _effective_standard_dirs(env_overrides=env_overrides, base_dir=resolved_base)
    configured_dir = resolve_configured_data_dir(env_overrides=env_overrides)

    toxic_cidr = _resolve_sfs_component_path(
        "STOPFORUMSPAM_TOXIC_CIDR_PATH",
        configured_dir,
        (SFS_TOXIC_CIDR_FILENAME,),
        standard_dirs,
        env_overrides=env_overrides,
        bypass_throttle=bypass_throttle,
    )
    listed_90 = _resolve_sfs_component_path(
        "STOPFORUMSPAM_LISTED_90_PATH",
        configured_dir,
        SFS_LISTED_90_FILENAMES,
        standard_dirs,
        env_overrides=env_overrides,
        bypass_throttle=bypass_throttle,
    )
    listed_1 = _resolve_sfs_component_path(
        "STOPFORUMSPAM_LISTED_1_PATH",
        configured_dir,
        SFS_LISTED_1_FILENAMES,
        standard_dirs,
        env_overrides=env_overrides,
        bypass_throttle=bypass_throttle,
    )
    sqlite_index = _resolve_sfs_sqlite_path(
        configured_dir,
        listed_90,
        listed_1,
        toxic_cidr,
        standard_dirs,
        resolved_base,
        env_overrides=env_overrides,
        bypass_throttle=bypass_throttle,
    )
    return {
        "toxic_cidr": toxic_cidr,
        "listed_90": listed_90,
        "listed_1": listed_1,
        "sqlite_index": sqlite_index,
    }


def has_any_local_stopforumspam_db() -> bool:
    """Returns True when a StopForumSpam toxic CIDR list or prebuilt SQLite index exists on disk."""
    paths = resolve_stopforumspam_paths()
    return _is_regular_file(paths.get("toxic_cidr")) or _is_regular_file(paths.get("sqlite_index"))


def get_stopforumspam_db_version() -> int:
    """Returns the newest nanosecond mtime across active StopForumSpam lookup files, or zero when absent."""
    paths = resolve_stopforumspam_paths()
    newest = 0
    for key in ("toxic_cidr", "sqlite_index"):
        candidate = paths.get(key)
        if candidate is None:
            continue
        sig = get_file_stat_signature(candidate)
        if sig is not None and sig[0] > newest:
            newest = sig[0]
    return newest


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
_toxic_cidr_cache: FileStatCache[Tuple[str, int, int], _StopForumSpamCidrIndex] = FileStatCache()
_sfs_sqlite_sync_lock = threading.Lock()
_sfs_local_sqlite_cache: Tuple[Optional[Tuple[str, int, int]], Optional[Path]] = (None, None)
_sfs_conn_lock = threading.Lock()
_sfs_thread_connections: Dict[Tuple[int, str], sqlite3.Connection] = {}
_sfs_warm_lock = threading.Lock()
_sfs_cache_warmed = False


def _get_toxic_cidr_index(toxic_path: Optional[Path]) -> _StopForumSpamCidrIndex:
    if toxic_path is None:
        return _toxic_cidr_cache.set_constant(("__missing__", -1, -1), _EMPTY_SFS_CIDR_INDEX)

    sig = get_file_stat_signature(toxic_path)
    if sig is None:
        return _toxic_cidr_cache.set_constant(("__missing__", -1, -1), _EMPTY_SFS_CIDR_INDEX)

    def _load() -> _StopForumSpamCidrIndex:
        with toxic_path.open("r", encoding="utf-8", errors="replace") as handle:
            return _StopForumSpamCidrIndex(handle)

    return _toxic_cidr_cache.get_or_load((str(toxic_path), sig[0], sig[1]), _load)


def _compute_listed_source_signature(listed_90: Optional[Path], listed_1: Optional[Path]) -> Optional[str]:
    entries: List[List[Any]] = []
    for role, path in (("90d", listed_90), ("1d", listed_1)):
        if path is None:
            continue
        sig = get_file_stat_signature(path, bypass_throttle=True)
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
            return ip_bytes, frequency, parts[2].strip()

    row = next(csv.reader([stripped]))
    if not row:
        return None
    ip_bytes = _pack_ip_bytes(row[0])
    if ip_bytes is None:
        return None
    frequency = 1
    if len(row) >= 2 and row[1].strip():
        try:
            frequency = max(0, int(row[1].strip()))
        except ValueError:
            frequency = 1
    last_seen = row[2].strip() if len(row) >= 3 else ""
    return ip_bytes, frequency, last_seen


def _iter_sfs_listed_rows(file_path: Path, source_mask: int) -> Iterable[Tuple[bytes, int, str, int]]:
    with _open_sfs_text_stream(file_path) as stream:
        for line in stream:
            parsed = _parse_sfs_listed_line(line)
            if parsed is not None:
                yield parsed[0], parsed[1], parsed[2], source_mask


def _populate_sfs_sqlite_file(
    tmp_path: Path,
    listed_90: Optional[Path],
    listed_1: Optional[Path],
    computed_sig: str,
) -> int:
    total_inserted = 0
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
    return total_inserted


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

    prefix = f".{target_sqlite_path.name}.{os.getpid()}.{threading.get_ident()}."
    with atomic_temp_path(target_sqlite_path, prefix=prefix) as tmp_path:
        return _populate_sfs_sqlite_file(tmp_path, listed_90, listed_1, computed_sig)


def _close_sfs_connections(*, keep_local_path: Optional[str] = None) -> None:
    to_close: List[sqlite3.Connection] = []
    with _sfs_conn_lock:
        keys = list(_sfs_thread_connections.keys())
        for key in keys:
            if keep_local_path is None or key[1] != keep_local_path:
                conn = _sfs_thread_connections.pop(key, None)
                if conn is not None:
                    to_close.append(conn)
    for conn in to_close:
        with contextlib.suppress(sqlite3.Error):
            conn.close()


def _resolve_local_sfs_sqlite_copy(sqlite_path: Path, sig: Tuple[int, int]) -> Path:
    global _sfs_local_sqlite_cache

    target_key = (str(sqlite_path), sig[0], sig[1])
    cached_key, cached_local = _sfs_local_sqlite_cache
    if cached_key == target_key and cached_local is not None:
        return cached_local

    with _sfs_sqlite_sync_lock:
        cached_key, cached_local = _sfs_local_sqlite_cache
        if cached_key == target_key and cached_local is not None:
            return cached_local

        ephemeral_dir = resolve_local_ephemeral_cache_dir()
        local_copy = sync_file_to_ephemeral_cache(sqlite_path, ephemeral_dir, stat_sig=sig)
        _sfs_local_sqlite_cache = (target_key, local_copy)
        _close_sfs_connections(keep_local_path=str(local_copy))
        return local_copy


def _get_thread_sfs_connection(local_sqlite_path: Path) -> sqlite3.Connection:
    path_str = str(local_sqlite_path)
    conn_key = (threading.get_ident(), path_str)
    with _sfs_conn_lock:
        existing = _sfs_thread_connections.get(conn_key)
        if existing is not None:
            return existing

    base_uri = local_sqlite_path.resolve().as_uri()
    try:
        conn = sqlite3.connect(f"{base_uri}?mode=ro&immutable=1", uri=True, timeout=1.0, check_same_thread=False)
    except sqlite3.OperationalError:
        conn = sqlite3.connect(f"{base_uri}?mode=ro", uri=True, timeout=1.0, check_same_thread=False)

    with _sfs_conn_lock:
        raced = _sfs_thread_connections.get(conn_key)
        if raced is not None:
            with contextlib.suppress(sqlite3.Error):
                conn.close()
            return raced
        _sfs_thread_connections[conn_key] = conn
        return conn


def _evict_thread_sfs_connection(local_sqlite_path: Path) -> None:
    conn_key = (threading.get_ident(), str(local_sqlite_path))
    with _sfs_conn_lock:
        stale = _sfs_thread_connections.pop(conn_key, None)
    if stale is not None:
        with contextlib.suppress(sqlite3.Error):
            stale.close()


def _lookup_ip_in_sqlite(local_sqlite_path: Path, ip: str) -> Optional[Tuple[int, str, int]]:
    primary_key, mapped_key = _resolve_lookup_byte_keys(ip)
    if primary_key is None:
        return None
    conn = _get_thread_sfs_connection(local_sqlite_path)
    try:
        row = conn.execute(
            "SELECT frequency, last_seen, source_mask FROM listed_ips WHERE ip = ?",
            (primary_key,),
        ).fetchone()
        if row is None and mapped_key is not None:
            row = conn.execute(
                "SELECT frequency, last_seen, source_mask FROM listed_ips WHERE ip = ?",
                (mapped_key,),
            ).fetchone()
    except sqlite3.Error:
        _evict_thread_sfs_connection(local_sqlite_path)
        raise
    if row is None:
        return None
    return int(row[0]), str(row[1] or ""), int(row[2])


def query_stopforumspam_offline(ip: str) -> Dict[str, Any]:
    """Queries local StopForumSpam toxic CIDR and local ephemeral SQLite copy without Web rebuilds."""
    global _sfs_cache_warmed

    paths = resolve_stopforumspam_paths()
    toxic_path = paths.get("toxic_cidr")
    sqlite_path = paths.get("sqlite_index")

    toxic_sig = get_file_stat_signature(toxic_path) if toxic_path is not None else None
    sqlite_sig = get_file_stat_signature(sqlite_path) if sqlite_path is not None else None

    if toxic_sig is None and sqlite_sig is None:
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

    toxic_cidr_hit = _get_toxic_cidr_index(toxic_path).match(ip) if toxic_sig is not None else None

    listed_hit: Optional[Tuple[int, str, int]] = None
    if sqlite_path is not None and sqlite_sig is not None:
        local_sqlite = _resolve_local_sfs_sqlite_copy(sqlite_path, sqlite_sig)
        listed_hit = _lookup_ip_in_sqlite(local_sqlite, ip)

    with _sfs_warm_lock:
        _sfs_cache_warmed = True

    sources: List[str] = ["toxic_ip_cidr"] if toxic_cidr_hit is not None else []
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
    active_files = [
        toxic_path if toxic_sig is not None else None,
        sqlite_path if sqlite_sig is not None else None,
    ]
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
    """Preloads StopForumSpam toxic CIDRs and syncs any prebuilt SQLite index to local ephemeral storage."""
    global _sfs_cache_warmed

    paths = resolve_stopforumspam_paths()
    _get_toxic_cidr_index(paths.get("toxic_cidr"))
    sqlite_path = paths.get("sqlite_index")
    if sqlite_path is not None:
        sqlite_sig = get_file_stat_signature(sqlite_path)
        if sqlite_sig is not None:
            try:
                local_copy = _resolve_local_sfs_sqlite_copy(sqlite_path, sqlite_sig)
                _get_thread_sfs_connection(local_copy)
            except (OSError, sqlite3.Error) as exc:
                logger.warning("Failed to warm StopForumSpam local SQLite copy: %s", exc)
    with _sfs_warm_lock:
        _sfs_cache_warmed = True


def are_stopforumspam_caches_warm() -> bool:
    with _sfs_warm_lock:
        return _sfs_cache_warmed


def clear_sfs_caches() -> None:
    """Clears StopForumSpam caches and closes cached SQLite connections."""
    global _sfs_cache_warmed, _sfs_local_sqlite_cache

    _toxic_cidr_cache.clear()
    _sfs_local_sqlite_cache = (None, None)
    _close_sfs_connections()
    with _sfs_warm_lock:
        _sfs_cache_warmed = False
