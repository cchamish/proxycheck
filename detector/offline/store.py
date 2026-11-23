"""Shared offline database constants, file-stat caches, atomic file writes, and data path resolution."""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import os
import socket
import stat
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, Generic, Iterable, List, Mapping, Optional, Tuple, TypeVar

from proxycheck.settings import (
    MAXMIND_ASN_DB_FILENAME,
    MAXMIND_CITY_DB_FILENAME,
    MAXMIND_COUNTRY_DB_FILENAME,
    expand_configured_path,
    resolve_tool_data_subdir,
    standard_data_directories,
)

from .prefix_index import (
    BinaryPrefixFormatError,
    BinaryPrefixIndexReader,
)

logger = logging.getLogger(__name__)

SFS_TOXIC_CIDR_FILENAME = "toxic_ip_cidr.txt"
SFS_LISTED_90_ZIP_NAME = "listed_ip_90_ipv46_all.zip"
SFS_LISTED_1_ZIP_NAME = "listed_ip_1_ipv46_all.zip"
SFS_LISTED_90_FILENAMES = (
    SFS_LISTED_90_ZIP_NAME,
    "listed_ip_90_ipv46_all.txt",
    "listed_ip_90_ipv46_all.csv",
    "listed_ip_90_ipv46_all.gz",
    "listed_ip_90_ipv46_all.txt.gz",
    "listed_ip_90_ipv46_all.csv.gz",
)
SFS_LISTED_1_FILENAMES = (
    SFS_LISTED_1_ZIP_NAME,
    "listed_ip_1_ipv46_all.txt",
    "listed_ip_1_ipv46_all.csv",
    "listed_ip_1_ipv46_all.gz",
    "listed_ip_1_ipv46_all.txt.gz",
    "listed_ip_1_ipv46_all.csv.gz",
)
SFS_SQLITE_FILENAME = "stopforumspam.sqlite3"

HOSTING_RULES_FILENAME = "hosting_asn_rules.json"

SHARED_CIDRS_BIN_FILENAME = "shared_cidrs.bin"
PRIVACY_RELAYS_BIN_FILENAME = "privacy_relays.bin"
IPSUM_DROP_BIN_FILENAME = "ipsum_drop.bin"
TOR_ONIONOO_SUMMARY_FILENAME = "tor_onionoo_summary.json"
BGP_TOOLS_BIN_FILENAME = "bgp_tools.bin"
BGP_TAGS_JSON_FILENAME = "bgp_tags.json"
OPENASN_MMDB_FILENAME = "openasn.mmdb"
MOBILE_ASNS_JSON_FILENAME = "mobile_asns.json"
HTTP_FEED_METADATA_FILENAME = "http_feed_metadata.json"

MOBILE_BGP_TAG_TOKENS: FrozenSet[str] = frozenset(
    {"mobile", "cellular", "cell", "lte", "5g", "wireless_mobile", "cgnat"}
)

REZMOSS_EXCLUDED_PROVIDERS: FrozenSet[str] = frozenset({"apple_private_relay", "tor"})

REZMOSS_PROVIDER_CATALOG: Dict[str, Tuple[str, str]] = {
    # cloud (24)
    "aws": ("AWS", "cloud"),
    "azure": ("Azure", "cloud"),
    "googlecloud": ("Google Cloud", "cloud"),
    "oracle": ("Oracle Cloud", "cloud"),
    "digitalocean": ("DigitalOcean", "cloud"),
    "linode": ("Linode", "cloud"),
    "vultr": ("Vultr", "cloud"),
    "alibaba": ("Alibaba Cloud", "cloud"),
    "tencent": ("Tencent Cloud", "cloud"),
    "huawei": ("Huawei Cloud", "cloud"),
    "ibmcloud": ("IBM Cloud", "cloud"),
    "hetzner": ("Hetzner", "cloud"),
    "ovhcloud": ("OVHcloud", "cloud"),
    "scaleway": ("Scaleway", "cloud"),
    "leaseweb": ("Leaseweb", "cloud"),
    "rackspace": ("Rackspace", "cloud"),
    "contabo": ("Contabo", "cloud"),
    "upcloud": ("UpCloud", "cloud"),
    "play2go": ("Play2Go", "cloud"),
    "nhncloud": ("NHN Cloud", "cloud"),
    "hostway": ("Hostway", "cloud"),
    "gabia": ("Gabia", "cloud"),
    "wasabi": ("Wasabi", "cloud"),
    "backblaze": ("Backblaze", "cloud"),
    # vpn (1)
    "mullvad": ("Mullvad", "vpn"),
    # enterprise_gateway (1)
    "zscaler": ("Zscaler", "enterprise_gateway"),
    # cdn (11)
    "cloudflare": ("Cloudflare", "cdn"),
    "fastly": ("Fastly", "cdn"),
    "akamai": ("Akamai", "cdn"),
    "imperva": ("Imperva", "cdn"),
    "gcore": ("G-Core", "cdn"),
    "cachefly": ("CacheFly", "cdn"),
    "gocache": ("GoCache", "cdn"),
    "quiccloud": ("QUIC.cloud", "cdn"),
    "bunny": ("Bunny CDN", "cdn"),
    "sucuri": ("Sucuri", "cdn"),
    "stormwall": ("StormWall", "cdn"),
    # saas (19)
    "github": ("GitHub", "saas"),
    "googleservices": ("Google Services", "saas"),
    "microsoft365": ("Microsoft 365", "saas"),
    "zoom": ("Zoom", "saas"),
    "atlassian": ("Atlassian", "saas"),
    "salesforce": ("Salesforce", "saas"),
    "zoho": ("Zoho", "saas"),
    "meta": ("Meta", "saas"),
    "yandex": ("Yandex", "saas"),
    "baidu": ("Baidu", "saas"),
    "telegram": ("Telegram", "saas"),
    "discord": ("Discord", "saas"),
    "circleci": ("CircleCI", "saas"),
    "teamcity": ("TeamCity", "saas"),
    "datadog": ("Datadog", "saas"),
    "uptimerobot": ("UptimeRobot", "saas"),
    "statuscake": ("StatusCake", "saas"),
    "pingdom": ("Pingdom", "saas"),
    "internetarchive": ("Internet Archive", "saas"),
    # bot (9)
    "googlebot": ("GoogleBot", "bot"),
    "bingbot": ("BingBot", "bot"),
    "gptbot": ("GPTBot", "bot"),
    "claudebot": ("ClaudeBot", "bot"),
    "applebot": ("AppleBot", "bot"),
    "perplexitybot": ("PerplexityBot", "bot"),
    "duckduckbot": ("DuckDuckBot", "bot"),
    "amazonbot": ("Amazonbot", "bot"),
    "commoncrawl": ("Common Crawl", "bot"),
}

MAXMIND_EDITION_SPECS: Tuple[Tuple[str, str], ...] = (
    ("GeoLite2-Country", MAXMIND_COUNTRY_DB_FILENAME),
    ("GeoLite2-City", MAXMIND_CITY_DB_FILENAME),
    ("GeoLite2-ASN", MAXMIND_ASN_DB_FILENAME),
)

_SOURCE_MASK_90 = 1
_SOURCE_MASK_1 = 2

OFFLINE_STAT_THROTTLE_SECONDS = 30.0
DEFAULT_STALE_MAXMIND_SECONDS = 14 * 86400
DEFAULT_STALE_SFS_TOXIC_SECONDS = 7 * 86400
DEFAULT_STALE_SFS_90_SECONDS = 2 * 86400
DEFAULT_STALE_SFS_1_SECONDS = 6 * 3600
DEFAULT_STALE_SHARED_CIDRS_SECONDS = 7 * 86400
DEFAULT_STALE_OPENASN_SECONDS = 14 * 86400
DEFAULT_STALE_TOR_ONIONOO_SECONDS = 6 * 3600
DEFAULT_STALE_DAILY_FEED_SECONDS = 7 * 86400
DEFAULT_STALE_RULES_SECONDS = 90 * 86400

_K = TypeVar("_K")
_V = TypeVar("_V")
_T = TypeVar("_T")


class FileStatCache(Generic[_K, _V]):
    """
    Thread-safe per-resource cache keyed by file stat signature or configuration tuple.
    Uses an independent fine-grained lock and a monotonic generation counter so slow
    disk parsing runs outside the lock without risking stale overwrite races.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._key: Optional[_K] = None
        self._value: Optional[_V] = None
        self._has_value = False
        self._generation = 0

    def get_or_load(self, key: _K, loader: Callable[[], _V], *, cache_result: bool = True) -> _V:
        with self._lock:
            if self._has_value and self._key == key:
                return self._value  # type: ignore[return-value]
            gen_before = self._generation

        loaded = loader()
        if not cache_result:
            return loaded

        with self._lock:
            if self._generation == gen_before:
                self._key = key
                self._value = loaded
                self._has_value = True
                self._generation += 1
            elif self._has_value and self._key == key:
                return self._value  # type: ignore[return-value]
        return loaded

    def set_constant(self, key: _K, value: _V) -> _V:
        with self._lock:
            if not self._has_value or self._key != key:
                self._key = key
                self._value = value
                self._has_value = True
                self._generation += 1
        return value

    def peek_matching(self, predicate: Callable[[_K, _V], bool]) -> Optional[_V]:
        with self._lock:
            if (
                self._has_value
                and self._key is not None
                and self._value is not None
                and predicate(self._key, self._value)
            ):
                return self._value
            return None

    def store(self, key: _K, value: _V) -> None:
        with self._lock:
            self._key = key
            self._value = value
            self._has_value = True
            self._generation += 1

    def is_populated(self) -> bool:
        with self._lock:
            return self._has_value

    def clear(self) -> None:
        with self._lock:
            self._key = None
            self._value = None
            self._has_value = False
            self._generation += 1


class _BinaryIndexCache:
    """Thread-safe cache managing memory-mapped binary prefix readers and clean handle disposal."""

    def __init__(self, filename: str, override_setting: str = "") -> None:
        self._filename = filename
        self._override_setting = override_setting
        self._lock = threading.Lock()
        self._key: Optional[Tuple[str, int, int]] = None
        self._reader: Optional[BinaryPrefixIndexReader] = None
        self._retired: List[BinaryPrefixIndexReader] = []

    def get_reader_and_mtime(self) -> Tuple[Optional[BinaryPrefixIndexReader], Optional[str]]:
        path = resolve_feed_data_path(self._filename, override_setting=self._override_setting)
        if path is None:
            return None, None
        sig = get_file_stat_signature(path)
        if sig is None:
            return None, None

        updated_iso = datetime.fromtimestamp(sig[0] / 1_000_000_000.0, tz=timezone.utc).isoformat()
        target_key = (str(path), sig[0], sig[1])

        with self._lock:
            if self._key == target_key and self._reader is not None and not self._reader.closed:
                return self._reader, updated_iso

        ephemeral_dir = resolve_local_ephemeral_cache_dir()
        try:
            opened = BinaryPrefixIndexReader.open_from_source(path, ephemeral_dir, stat_sig=sig)
        except (BinaryPrefixFormatError, OSError, ValueError) as exc:
            logger.warning("Failed to open binary prefix index %s: %s", path, exc)
            return None, updated_iso

        stale_to_close: List[BinaryPrefixIndexReader] = []
        with self._lock:
            if self._key == target_key and self._reader is not None and not self._reader.closed:
                stale_to_close.append(opened)
                active = self._reader
            else:
                if self._reader is not None:
                    self._retired.append(self._reader)
                    while len(self._retired) > 2:
                        stale_to_close.append(self._retired.pop(0))
                self._key = target_key
                self._reader = opened
                active = opened

        for old_reader in stale_to_close:
            old_reader.close()
        return active, updated_iso

    def clear(self) -> None:
        with self._lock:
            to_close: List[BinaryPrefixIndexReader] = list(self._retired)
            if self._reader is not None:
                to_close.append(self._reader)
            self._retired.clear()
            self._reader = None
            self._key = None
        for reader in to_close:
            reader.close()


_stat_throttle_lock = threading.Lock()
_stat_throttle_cache: Dict[str, Tuple[float, Optional[Tuple[int, int]]]] = {}


def get_setting(name: str, default: Any = None) -> Any:
    """Reads a Django setting when configured, returning default otherwise."""
    try:
        from django.conf import settings as django_settings

        if django_settings.configured:
            return getattr(django_settings, name, default)
    except ImportError, RuntimeError:
        return default
    return default


def _lookup_config_value(
    name: str,
    *,
    env_overrides: Optional[Mapping[str, str]] = None,
    default: str = "",
) -> str:
    if env_overrides is not None:
        raw_override = env_overrides.get(name, "")
        return str(raw_override).strip() if raw_override else default
    setting_val = get_setting(name, None)
    if isinstance(setting_val, (str, Path)) and str(setting_val).strip():
        return str(setting_val).strip()
    env_val = os.environ.get(name, "").strip()
    return env_val if env_val else default


def resolve_local_ephemeral_cache_dir(*, env_overrides: Optional[Mapping[str, str]] = None) -> Path:
    """Resolves the local non-NFS ephemeral cache directory across POSIX containers and Windows hosts."""
    configured = expand_configured_path(_lookup_config_value("LOCAL_EPHEMERAL_CACHE_DIR", env_overrides=env_overrides))
    if configured:
        return Path(configured)
    if sys.platform != "win32":
        return Path("/tmp/proxycheck-local")  # noqa: S108
    return Path(tempfile.gettempdir()) / "proxycheck-local"


def _effective_stat_throttle_seconds() -> float:
    raw = get_setting("OFFLINE_STAT_THROTTLE_SECONDS", OFFLINE_STAT_THROTTLE_SECONDS)
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return OFFLINE_STAT_THROTTLE_SECONDS
    val = float(raw)
    return val if val >= 0.0 else OFFLINE_STAT_THROTTLE_SECONDS


def clear_stat_throttle_cache() -> None:
    """Clears the monotonic file metadata stat cache."""
    with _stat_throttle_lock:
        _stat_throttle_cache.clear()


def get_file_stat_signature(
    file_path: str | Path,
    *,
    bypass_throttle: bool = False,
) -> Optional[Tuple[int, int]]:
    """Returns nanosecond modification time and byte size for a regular file with 30-second monotonic caching."""
    key = os.fspath(file_path)
    throttle_s = 0.0 if bypass_throttle else _effective_stat_throttle_seconds()
    now_mono = time.monotonic()

    if throttle_s > 0.0:
        with _stat_throttle_lock:
            cached = _stat_throttle_cache.get(key)
            if cached is not None and 0.0 <= (now_mono - cached[0]) < throttle_s:
                return cached[1]

    try:
        stat_res = os.stat(key)
        sig = (stat_res.st_mtime_ns, stat_res.st_size) if stat.S_ISREG(stat_res.st_mode) else None
    except OSError:
        sig = None

    if throttle_s > 0.0:
        with _stat_throttle_lock:
            if len(_stat_throttle_cache) >= 4096:
                _stat_throttle_cache.clear()
            _stat_throttle_cache[key] = (now_mono, sig)
    return sig


def _is_regular_file(file_path: Optional[Path], *, bypass_throttle: bool = False) -> bool:
    if file_path is None:
        return False
    return get_file_stat_signature(file_path, bypass_throttle=bypass_throttle) is not None


def get_positive_int_setting(
    name: str,
    default: int,
    *,
    env_overrides: Optional[Mapping[str, str]] = None,
) -> int:
    """Resolves a positive integer setting from an explicit mapping or Django settings."""
    if env_overrides is not None:
        raw_text = str(env_overrides.get(name, "") or "").strip()
        if not raw_text:
            return default
        try:
            parsed = int(raw_text)
        except ValueError:
            return default
        return parsed if parsed > 0 else default
    raw = get_setting(name, default)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
        return default
    return raw


def _effective_base_dir(base_dir: Optional[Path] = None) -> Path:
    if base_dir is not None:
        return Path(str(base_dir))
    configured = get_setting("BASE_DIR", None)
    if configured:
        return Path(str(configured))
    return Path(__file__).resolve().parent.parent


def _effective_standard_dirs(
    *,
    env_overrides: Optional[Mapping[str, str]] = None,
    base_dir: Optional[Path] = None,
) -> List[Path]:
    resolved_base = _effective_base_dir(base_dir)
    if env_overrides is not None:
        return list(standard_data_directories(resolved_base, tool_data_dir=env_overrides.get("TOOL_DATA_DIR", "")))
    return list(standard_data_directories(resolved_base))


def resolve_configured_data_dir(*, env_overrides: Optional[Mapping[str, str]] = None) -> str:
    """Returns the resolved TOOL_DATA_DIR offline data subdirectory, or empty string when unset."""
    tool_data_dir = expand_configured_path(_lookup_config_value("TOOL_DATA_DIR", env_overrides=env_overrides))
    if not tool_data_dir:
        return ""
    return str(resolve_tool_data_subdir(tool_data_dir))


def resolve_feed_data_path(
    filename: str,
    *,
    override_setting: str = "",
    env_overrides: Optional[Mapping[str, str]] = None,
    base_dir: Optional[Path] = None,
    bypass_throttle: bool = False,
) -> Optional[Path]:
    """Resolves a single offline feed file across explicit settings, TOOL_DATA_DIR, and standard directories."""
    if override_setting:
        raw_override = expand_configured_path(_lookup_config_value(override_setting, env_overrides=env_overrides))
        if raw_override:
            explicit = Path(raw_override)
            if _is_regular_file(explicit, bypass_throttle=bypass_throttle):
                return explicit
            nested = explicit / filename
            if _is_regular_file(nested, bypass_throttle=bypass_throttle):
                return nested
            return None

    configured_dir = resolve_configured_data_dir(env_overrides=env_overrides)
    if configured_dir:
        candidate = Path(expand_configured_path(configured_dir)) / filename
        return candidate if _is_regular_file(candidate, bypass_throttle=bypass_throttle) else None

    resolved_base = _effective_base_dir(base_dir)
    for directory in _effective_standard_dirs(env_overrides=env_overrides, base_dir=resolved_base):
        candidate = directory / filename
        if _is_regular_file(candidate, bypass_throttle=bypass_throttle):
            return candidate
    return None


def resolve_writable_data_dir(
    explicit_dir: str = "",
    *,
    env_overrides: Optional[Mapping[str, str]] = None,
    base_dir: Optional[Path] = None,
) -> Path:
    """Resolves the target directory for downloading and updating offline database files."""
    if explicit_dir.strip():
        return Path(expand_configured_path(explicit_dir))

    configured_dir = resolve_configured_data_dir(env_overrides=env_overrides)
    if configured_dir:
        return Path(configured_dir)

    resolved_base = _effective_base_dir(base_dir)
    if resolved_base.parent == Path(resolved_base.anchor):
        return Path.home() / "data"
    return resolved_base.parent / "data"


def _newest_mtime_iso(paths: Iterable[Optional[Path]]) -> Optional[str]:
    newest_ns: Optional[int] = None
    for candidate in paths:
        if candidate is None:
            continue
        sig = get_file_stat_signature(candidate)
        if sig is None:
            continue
        if newest_ns is None or sig[0] > newest_ns:
            newest_ns = sig[0]
    if newest_ns is None:
        return None
    return datetime.fromtimestamp(newest_ns / 1_000_000_000.0, tz=timezone.utc).isoformat()


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


def atomic_replace_with_retry(src_path: Path, dst_path: Path) -> None:
    """Replaces dst_path atomically, retrying briefly on Windows transient reader collisions."""
    for attempt in range(6):
        try:
            os.replace(src_path, dst_path)
            return
        except PermissionError:
            if attempt == 5:
                raise
            time.sleep(0.05 * (attempt + 1))


def replace_temp_file_atomically(tmp_path: Path, target_path: Path, *, mode: int = 0o644) -> None:
    """Applies permissions and swaps an existing temporary file into target_path, cleaning up on failure."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with contextlib.suppress(OSError):
            os.chmod(tmp_path, mode)
        atomic_replace_with_retry(tmp_path, target_path)
    finally:
        if tmp_path.exists():
            with contextlib.suppress(OSError):
                tmp_path.unlink()


@contextlib.contextmanager
def atomic_temp_path(target_path: Path, *, prefix: Optional[str] = None, mode: int = 0o644):
    """Creates a sibling temporary file, yields it for writing, and atomically replaces target_path on clean exit."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    effective_prefix = prefix or f".{target_path.name}.tmp."
    fd, tmp_name = tempfile.mkstemp(prefix=effective_prefix, dir=str(target_path.parent))
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        yield tmp_path
        with contextlib.suppress(OSError):
            os.chmod(tmp_path, mode)
        atomic_replace_with_retry(tmp_path, target_path)
    finally:
        if tmp_path.exists():
            with contextlib.suppress(OSError):
                tmp_path.unlink()


def _parse_asn_int(raw_asn: Any) -> Optional[int]:
    if isinstance(raw_asn, bool) or raw_asn is None:
        return None
    if isinstance(raw_asn, int):
        return raw_asn if raw_asn > 0 else None
    if isinstance(raw_asn, str):
        cleaned = raw_asn.strip().upper()
        if cleaned.startswith("AS"):
            cleaned = cleaned[2:].strip()
        if cleaned.isdigit():
            parsed = int(cleaned)
            return parsed if parsed > 0 else None
    return None


def resolve_hosting_rules_path(
    *,
    env_overrides: Optional[Mapping[str, str]] = None,
    base_dir: Optional[Path] = None,
    bypass_throttle: bool = False,
) -> Tuple[Optional[Path], str]:
    """Resolves the hosting ASN rules JSON file across explicit overrides and standard data directories."""
    filenames = (HOSTING_RULES_FILENAME,)
    raw_configured = _lookup_config_value("HOSTING_ASN_RULES_PATH", env_overrides=env_overrides)
    resolved_base = _effective_base_dir(base_dir)
    if raw_configured:
        expanded = Path(expand_configured_path(raw_configured))
        if _is_regular_file(expanded, bypass_throttle=bypass_throttle):
            return expanded, expanded.name
        for fname in filenames:
            candidate = expanded / fname
            if _is_regular_file(candidate, bypass_throttle=bypass_throttle):
                return candidate, candidate.name
        if expanded.is_dir():
            return None, filenames[0]
        if env_overrides is not None or expanded != resolved_base.parent / "data" / filenames[0]:
            return None, expanded.name or filenames[0]

    for directory in _effective_standard_dirs(env_overrides=env_overrides, base_dir=resolved_base):
        for fname in filenames:
            candidate = directory / fname
            if _is_regular_file(candidate, bypass_throttle=bypass_throttle):
                return candidate, candidate.name
    return None, filenames[0]
