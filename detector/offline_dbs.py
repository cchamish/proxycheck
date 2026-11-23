"""Offline threat intelligence stores, thread-safe file caches, and database freshness metadata."""

from __future__ import annotations

import contextlib
import csv
import gzip
import io
import ipaddress
import json
import logging
import os
import socket
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, Generic, Iterable, List, Mapping, Optional, Sequence, Tuple, TypeVar

from detector.binary_prefix_index import (
    BinaryPrefixFormatError,
    BinaryPrefixIndexReader,
    sync_file_to_ephemeral_cache,
)
from proxycheck.settings import (
    MAXMIND_ASN_DB_FILENAME,
    MAXMIND_CITY_DB_FILENAME,
    MAXMIND_COUNTRY_DB_FILENAME,
    expand_configured_path,
    find_mmdb_in_directory,
    resolve_mmdb_file,
    resolve_tool_data_subdir,
    standard_data_directories,
)

try:
    import maxminddb
except ImportError:
    maxminddb = None

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


class StopForumSpamCorruptDataError(ValueError):
    """Raised when a local StopForumSpam offline database archive cannot be parsed."""


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


def resolve_configured_data_dir(*, env_overrides: Optional[Mapping[str, str]] = None) -> str:
    """Returns the resolved TOOL_DATA_DIR offline data subdirectory, or empty string when unset."""
    tool_data_dir = expand_configured_path(_lookup_config_value("TOOL_DATA_DIR", env_overrides=env_overrides))
    if not tool_data_dir:
        return ""
    return str(resolve_tool_data_subdir(tool_data_dir))


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

_shared_cidrs_index = _BinaryIndexCache(SHARED_CIDRS_BIN_FILENAME, "SHARED_CIDRS_BIN_PATH")
_privacy_relays_index = _BinaryIndexCache(PRIVACY_RELAYS_BIN_FILENAME, "PRIVACY_RELAYS_BIN_PATH")
_ipsum_drop_index = _BinaryIndexCache(IPSUM_DROP_BIN_FILENAME, "IPSUM_DROP_BIN_PATH")
_bgp_tools_index = _BinaryIndexCache(BGP_TOOLS_BIN_FILENAME, "BGP_TOOLS_BIN_PATH")

_tor_onionoo_cache: FileStatCache[Tuple[str, int, int], Dict[str, List[Dict[str, Any]]]] = FileStatCache()
_bgp_tags_cache: FileStatCache[Tuple[str, int, int], Tuple[Dict[int, Tuple[str, ...]], FrozenSet[int]]] = (
    FileStatCache()
)
_mobile_asns_cache: FileStatCache[Tuple[str, int, int], FrozenSet[int]] = FileStatCache()


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


def clear_stopforumspam_caches() -> None:
    """Clears StopForumSpam caches, closes all cached SQLite and mmap handles, and resets stat throttling."""
    global _sfs_cache_warmed, _sfs_local_sqlite_cache

    _toxic_cidr_cache.clear()
    _sfs_local_sqlite_cache = (None, None)
    _close_sfs_connections()
    _shared_cidrs_index.clear()
    _privacy_relays_index.clear()
    _ipsum_drop_index.clear()
    _bgp_tools_index.clear()
    _tor_onionoo_cache.clear()
    _bgp_tags_cache.clear()
    _mobile_asns_cache.clear()
    clear_stat_throttle_cache()
    with _sfs_warm_lock:
        _sfs_cache_warmed = False


def classify_rezmoss_provider(slug: str) -> Optional[Tuple[str, str]]:
    """Maps a Rezmoss provider slug to (display_label, category), or None when excluded."""
    cleaned = slug.strip().lower() if isinstance(slug, str) else ""
    if not cleaned or cleaned in REZMOSS_EXCLUDED_PROVIDERS:
        return None
    known = REZMOSS_PROVIDER_CATALOG.get(cleaned)
    if known is not None:
        return known
    category = "bot" if cleaned.endswith("bot") else "cloud"
    return cleaned.replace("_", " ").title(), category


def lookup_shared_cidr_offline(ip: str) -> Optional[Dict[str, Any]]:
    """Looks up an IP in the compiled Rezmoss shared-egress binary prefix index."""
    reader, _updated = _shared_cidrs_index.get_reader_and_mtime()
    if reader is None:
        return None
    hit = reader.lookup_with_prefix_len(ip)
    if hit is None:
        return None
    matched_cidr, prefix_len, payload = hit
    if not isinstance(payload, Mapping):
        return None
    provider = payload.get("p") or payload.get("provider")
    category = payload.get("c") or payload.get("category")
    if not isinstance(provider, str) or not provider.strip():
        return None
    if not isinstance(category, str) or not category.strip():
        category = "cloud"
    return {
        "cidr": matched_cidr,
        "prefixLength": prefix_len,
        "provider": provider.strip(),
        "category": category.strip().lower(),
    }


def lookup_privacy_relay_offline(ip: str) -> Optional[str]:
    """Returns icloud_private_relay or cloudflare_warp when matched, excluding Cloudflare CDN ranges."""
    reader, _updated = _privacy_relays_index.get_reader_and_mtime()
    if reader is None:
        return None
    hit = reader.lookup(ip)
    if hit is None:
        return None
    category = hit[1]
    if category in ("icloud_private_relay", "cloudflare_warp"):
        return str(category)
    return None


def _empty_ipsum_drop_result(*, has_db: bool, updated_at: Optional[str]) -> Dict[str, Any]:
    return {
        "hasDb": has_db,
        "has_db": has_db,
        "isListed": False,
        "ipsumScore": 0,
        "isIpsumListed": False,
        "isHighRisk": False,
        "inSpamhausDrop": False,
        "dropSblId": None,
        "dropCidr": None,
        "matchedCidr": None,
        "offlineDbUpdatedAt": updated_at,
    }


def query_ipsum_drop_offline(ip: str) -> Dict[str, Any]:
    """Queries the compiled IPsum and Spamhaus DROP binary prefix index for IPv4 and IPv6 targets."""
    reader, updated_at = _ipsum_drop_index.get_reader_and_mtime()
    if reader is None:
        return _empty_ipsum_drop_result(has_db=False, updated_at=None)

    hit = reader.lookup(ip)
    if hit is None:
        return _empty_ipsum_drop_result(has_db=True, updated_at=updated_at)

    matched_cidr, payload = hit
    ipsum_score = 0
    in_drop = False
    drop_sbl_id: Optional[str] = None
    drop_cidr: Optional[str] = None

    if isinstance(payload, int) and not isinstance(payload, bool):
        ipsum_score = max(0, payload)
    elif isinstance(payload, dict):
        raw_score = payload.get("score")
        if isinstance(raw_score, int) and not isinstance(raw_score, bool):
            ipsum_score = max(0, raw_score)
        in_drop = bool(payload.get("drop"))
        raw_sbl = payload.get("sblid")
        if isinstance(raw_sbl, str) and raw_sbl.strip():
            drop_sbl_id = raw_sbl.strip()
        raw_drop_cidr = payload.get("drop_cidr")
        drop_cidr = raw_drop_cidr.strip() if isinstance(raw_drop_cidr, str) and raw_drop_cidr.strip() else matched_cidr

    is_ipsum_listed = ipsum_score >= 2
    is_listed = is_ipsum_listed or in_drop
    if not is_listed:
        return _empty_ipsum_drop_result(has_db=True, updated_at=updated_at)

    return {
        "hasDb": True,
        "has_db": True,
        "isListed": True,
        "ipsumScore": ipsum_score,
        "isIpsumListed": is_ipsum_listed,
        "isHighRisk": in_drop or ipsum_score >= 3,
        "inSpamhausDrop": in_drop,
        "dropSblId": drop_sbl_id,
        "dropCidr": drop_cidr if in_drop else None,
        "matchedCidr": matched_cidr,
        "offlineDbUpdatedAt": updated_at,
    }


def _extract_onionoo_canonical_ip(raw_entry: Any) -> Optional[str]:
    if not isinstance(raw_entry, str):
        return None
    candidate = raw_entry.strip()
    if not candidate:
        return None
    if candidate.startswith("["):
        end_idx = candidate.find("]")
        if end_idx <= 1:
            return None
        candidate = candidate[1:end_idx]
    if "%" in candidate and ":" in candidate:
        candidate = candidate.split("%", 1)[0]
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        pass
    if candidate.count(":") == 1 and "." in candidate:
        host_part = candidate.split(":", 1)[0].strip()
        try:
            return ipaddress.ip_address(host_part).compressed
        except ValueError:
            return None
    return None


def _index_onionoo_summary_payload(payload: Any) -> Optional[Dict[str, List[Dict[str, Any]]]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("relays"), list):
        return None
    by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for relay in payload["relays"]:
        if not isinstance(relay, dict):
            continue
        seen_for_relay: set[str] = set()
        for field_name in ("a", "or_addresses", "exit_addresses"):
            entries = relay.get(field_name)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                canonical = _extract_onionoo_canonical_ip(entry)
                if canonical and canonical not in seen_for_relay:
                    seen_for_relay.add(canonical)
                    by_ip.setdefault(canonical, []).append(relay)
    return by_ip


def lookup_tor_onionoo_offline(ip: str) -> Optional[Dict[str, Any]]:
    """
    Looks up an IP in the local Onionoo summary mirror in sub-millisecond time.
    Returns None only when the local mirror is absent or unreadable so HTTP fallback can run.
    """
    path = resolve_feed_data_path(TOR_ONIONOO_SUMMARY_FILENAME, override_setting="TOR_ONIONOO_SUMMARY_PATH")
    if path is None:
        return None
    sig = get_file_stat_signature(path)
    if sig is None:
        return None

    target_key = (str(path), sig[0], sig[1])
    hit = _tor_onionoo_cache.peek_matching(lambda key, _val: key == target_key)
    if hit is None:
        try:
            raw_json = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("Failed to load local Tor Onionoo summary %s: %s", path, exc)
            return None
        indexed = _index_onionoo_summary_payload(raw_json)
        if indexed is None:
            return None
        hit = _tor_onionoo_cache.get_or_load(target_key, lambda: indexed)

    canonical = _extract_onionoo_canonical_ip(ip)
    matched = hit.get(canonical, ()) if canonical else ()
    return {
        "relays": [dict(relay) for relay in matched],
        "bridges": [],
    }


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


def _get_bgp_tags_data() -> Tuple[Dict[int, Tuple[str, ...]], FrozenSet[int]]:
    path = resolve_feed_data_path(BGP_TAGS_JSON_FILENAME, override_setting="BGP_TAGS_JSON_PATH")
    if path is None:
        return _bgp_tags_cache.set_constant(("__missing__", -1, -1), ({}, frozenset()))
    sig = get_file_stat_signature(path)
    if sig is None:
        return _bgp_tags_cache.set_constant(("__missing__", -1, -1), ({}, frozenset()))

    target_key = (str(path), sig[0], sig[1])
    hit = _bgp_tags_cache.peek_matching(lambda key, _val: key == target_key)
    if hit is not None:
        return hit

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning("Failed to parse BGP tags file %s: %s", path, exc)
        return {}, frozenset()

    asn_tags: Dict[int, Tuple[str, ...]] = {}
    mobile_asns: set[int] = set()
    if isinstance(payload, dict):
        raw_map = payload.get("asn_tags") if isinstance(payload.get("asn_tags"), dict) else payload
        for raw_key, raw_tags in raw_map.items():
            if raw_key in ("mobile_asns", "tag_counts"):
                continue
            asn_num = _parse_asn_int(raw_key)
            if asn_num is None or not isinstance(raw_tags, list):
                continue
            cleaned_tags = tuple(str(t).strip().lower() for t in raw_tags if isinstance(t, str) and str(t).strip())
            if cleaned_tags:
                asn_tags[asn_num] = cleaned_tags
                if any(tag in MOBILE_BGP_TAG_TOKENS for tag in cleaned_tags):
                    mobile_asns.add(asn_num)

        explicit_mobile = payload.get("mobile_asns")
        if isinstance(explicit_mobile, list):
            for item in explicit_mobile:
                asn_num = _parse_asn_int(item)
                if asn_num is not None:
                    mobile_asns.add(asn_num)

    parsed = (asn_tags, frozenset(mobile_asns))
    return _bgp_tags_cache.get_or_load(target_key, lambda: parsed)


def lookup_bgp_tools_offline(ip: str) -> Optional[Dict[str, Any]]:
    """Looks up the longest BGP routing prefix, origin ASN, and network tags from offline bgp.tools data."""
    reader, _updated = _bgp_tools_index.get_reader_and_mtime()
    if reader is None:
        return None
    hit = reader.lookup(ip)
    if hit is None:
        return None
    matched_cidr, payload = hit
    asn_num = _parse_asn_int(payload.get("asn") if isinstance(payload, dict) else payload)
    asn_tags_map, _mobile = _get_bgp_tags_data()
    tags = list(asn_tags_map.get(asn_num, ())) if asn_num is not None else []
    if isinstance(payload, dict) and isinstance(payload.get("tags"), list):
        for extra_tag in payload["tags"]:
            cleaned_tag = str(extra_tag).strip().lower()
            if cleaned_tag and cleaned_tag not in tags:
                tags.append(cleaned_tag)
    return {
        "bgpPrefix": matched_cidr,
        "asn": asn_num,
        "tags": tags,
    }


_MAX_MAXMIND_READERS = 8
_MAX_MISSING_CITY_LOGGED_PATHS = 16
_maxmind_lock = threading.Lock()
_maxmind_readers: Dict[str, Any] = {}
_maxmind_reader_stats: Dict[str, Optional[Tuple[int, int]]] = {}
_missing_city_db_logged_paths: set[str] = set()

MAXMIND_DB_SPECS = (
    ("country", MAXMIND_COUNTRY_DB_FILENAME),
    ("city", MAXMIND_CITY_DB_FILENAME),
    ("asn", MAXMIND_ASN_DB_FILENAME),
)

_MAXMIND_PROBE_TTL_SECONDS = 5.0
_maxmind_probe_lock = threading.Lock()
_maxmind_city_db_cache: Optional[Tuple[Tuple[Any, ...], float, bool]] = None
_maxmind_any_db_cache: Optional[Tuple[Tuple[Any, ...], float, bool]] = None


def _close_mmdb_reader_safely(reader: Any) -> None:
    if reader is None:
        return
    close_fn = getattr(reader, "close", None)
    if not callable(close_fn):
        return
    try:
        close_fn()
    except (OSError, ValueError, RuntimeError) as exc:
        logger.debug("Failed to close MaxMind reader: %s", exc)


def get_maxmind_reader(db_path: str, maxminddb_module: Any) -> Any:
    """Returns a cached MMDB reader, reopening outside the lock when the file changes on disk."""
    current_sig = get_file_stat_signature(db_path)
    stale_reader: Optional[Any] = None
    with _maxmind_lock:
        reader = _maxmind_readers.get(db_path)
        if reader is not None:
            if current_sig is not None and _maxmind_reader_stats.get(db_path) == current_sig:
                _maxmind_readers[db_path] = _maxmind_readers.pop(db_path)
                return reader
            stale_reader = _maxmind_readers.pop(db_path, None)
            _maxmind_reader_stats.pop(db_path, None)

    _close_mmdb_reader_safely(stale_reader)

    candidate_reader = maxminddb_module.open_database(db_path)
    duplicate_reader: Optional[Any] = None
    lru_evicted_reader: Optional[Any] = None
    selected_reader = candidate_reader

    with _maxmind_lock:
        existing_reader = _maxmind_readers.get(db_path)
        if (
            existing_reader is not None
            and current_sig is not None
            and _maxmind_reader_stats.get(db_path) == current_sig
        ):
            _maxmind_readers[db_path] = _maxmind_readers.pop(db_path)
            selected_reader = existing_reader
            duplicate_reader = candidate_reader
        else:
            if existing_reader is not None:
                lru_evicted_reader = _maxmind_readers.pop(db_path, None)
                _maxmind_reader_stats.pop(db_path, None)
            elif len(_maxmind_readers) >= _MAX_MAXMIND_READERS:
                oldest_key = next(iter(_maxmind_readers))
                lru_evicted_reader = _maxmind_readers.pop(oldest_key, None)
                _maxmind_reader_stats.pop(oldest_key, None)
            if current_sig is not None:
                _maxmind_readers[db_path] = candidate_reader
                _maxmind_reader_stats[db_path] = current_sig

    _close_mmdb_reader_safely(duplicate_reader)
    _close_mmdb_reader_safely(lru_evicted_reader)
    return selected_reader


def evict_maxmind_reader(db_path: str) -> None:
    """Removes and closes a cached MMDB reader when an error occurs or the file is absent."""
    with _maxmind_lock:
        reader = _maxmind_readers.pop(db_path, None)
        _maxmind_reader_stats.pop(db_path, None)
    _close_mmdb_reader_safely(reader)


def evict_missing_maxmind_readers(filename: str, resolved_path: str) -> None:
    """Evicts cached readers matching a missing MMDB path or filename so deleted files never leak handles."""
    with _maxmind_lock:
        stale_keys = [key for key in _maxmind_readers if key == resolved_path or os.path.basename(key) == filename]
    for key in stale_keys:
        evict_maxmind_reader(key)


def clear_maxmind_readers() -> None:
    """Closes and removes all cached MMDB readers and resets missing-file log tracking."""
    with _maxmind_lock:
        readers = list(_maxmind_readers.values())
        _maxmind_readers.clear()
        _maxmind_reader_stats.clear()
        _missing_city_db_logged_paths.clear()
    for reader in readers:
        _close_mmdb_reader_safely(reader)


def record_city_db_presence(city_path: str, *, is_present: bool) -> bool:
    """Updates missing City MMDB log state and returns True once per newly missing path."""
    with _maxmind_lock:
        if is_present:
            _missing_city_db_logged_paths.discard(city_path)
            return False
        if city_path in _missing_city_db_logged_paths:
            return False
        if len(_missing_city_db_logged_paths) >= _MAX_MISSING_CITY_LOGGED_PATHS:
            _missing_city_db_logged_paths.clear()
        _missing_city_db_logged_paths.add(city_path)
        return True


def resolve_maxmind_db_paths() -> Dict[str, str]:
    """Resolves Country, City, and ASN MMDB paths using configured TOOL_DATA_DIR or fallbacks."""
    base_dir = _effective_base_dir(None)
    configured_dir = resolve_configured_data_dir()
    return {key: resolve_mmdb_file(configured_dir, filename, base_dir) for key, filename in MAXMIND_DB_SPECS}


def clear_maxmind_probe_cache() -> None:
    """Clears short-TTL MaxMind file existence probe caches."""
    global _maxmind_city_db_cache, _maxmind_any_db_cache
    with _maxmind_probe_lock:
        _maxmind_city_db_cache = None
        _maxmind_any_db_cache = None


def has_local_maxmind_city_db() -> bool:
    """Returns True when GeoLite2-City.mmdb is present on disk at its resolved location."""
    global _maxmind_city_db_cache
    base_dir = _effective_base_dir(None)
    configured_dir = resolve_configured_data_dir()
    tool_data_dir = str(get_setting("TOOL_DATA_DIR", "") or os.environ.get("TOOL_DATA_DIR", "")).strip()
    cache_key = (configured_dir, str(base_dir), tool_data_dir)
    now_mono = time.monotonic()
    with _maxmind_probe_lock:
        if (
            _maxmind_city_db_cache is not None
            and _maxmind_city_db_cache[0] == cache_key
            and 0.0 <= (now_mono - _maxmind_city_db_cache[1]) < _MAXMIND_PROBE_TTL_SECONDS
        ):
            return _maxmind_city_db_cache[2]

    city_path = resolve_mmdb_file(configured_dir, MAXMIND_CITY_DB_FILENAME, base_dir)
    result = bool(city_path and os.path.exists(city_path))
    with _maxmind_probe_lock:
        _maxmind_city_db_cache = (cache_key, now_mono, result)
    return result


def has_any_local_maxmind_db() -> bool:
    """Returns True when at least one local MaxMind MMDB file exists on disk."""
    global _maxmind_any_db_cache
    base_dir = _effective_base_dir(None)
    configured_dir = resolve_configured_data_dir()
    tool_data_dir = str(get_setting("TOOL_DATA_DIR", "") or os.environ.get("TOOL_DATA_DIR", "")).strip()
    cache_key = (configured_dir, str(base_dir), tool_data_dir)
    now_mono = time.monotonic()
    with _maxmind_probe_lock:
        if (
            _maxmind_any_db_cache is not None
            and _maxmind_any_db_cache[0] == cache_key
            and 0.0 <= (now_mono - _maxmind_any_db_cache[1]) < _MAXMIND_PROBE_TTL_SECONDS
        ):
            return _maxmind_any_db_cache[2]

    result = any(path and os.path.exists(path) for path in resolve_maxmind_db_paths().values())
    with _maxmind_probe_lock:
        _maxmind_any_db_cache = (cache_key, now_mono, result)
    return result


def resolve_openasn_mmdb_path(
    *,
    env_overrides: Optional[Mapping[str, str]] = None,
    base_dir: Optional[Path] = None,
    bypass_throttle: bool = False,
) -> Optional[Path]:
    """Resolves the local OpenASN MMDB across OPENASN_MMDB_PATH, TOOL_DATA_DIR, and standard data directories."""
    return resolve_feed_data_path(
        OPENASN_MMDB_FILENAME,
        override_setting="OPENASN_MMDB_PATH",
        env_overrides=env_overrides,
        base_dir=base_dir,
        bypass_throttle=bypass_throttle,
    )


def get_openasn_mtime_iso() -> Optional[str]:
    """Returns the OpenASN MMDB modification time as an ISO timestamp, or None when it is absent."""
    path = resolve_openasn_mmdb_path()
    if path is None:
        return None
    sig = get_file_stat_signature(path)
    if sig is None:
        return None
    return datetime.fromtimestamp(sig[0] / 1_000_000_000.0, tz=timezone.utc).isoformat()


def _empty_openasn_result(*, has_db: bool, updated_at: Optional[str]) -> Dict[str, Any]:
    return {
        "hasDb": has_db,
        "has_db": has_db,
        "lookupStatus": "unrouted",
        "asn": None,
        "asOrg": None,
        "category": None,
        "networkRole": None,
        "badAsn": False,
        "vpnProvider": False,
        "mobileCarrier": False,
        "enterpriseGw": False,
        "cdn": False,
        "hostingExtra": False,
        "vpnRange": False,
        "datacenterRange": False,
        "coreVerdict": "unknown",
        "coreSources": ["unrouted"],
        "offlineDbUpdatedAt": updated_at,
        "rawRecord": {},
    }


def _optional_text(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def query_openasn_offline(ip: str) -> Dict[str, Any]:
    """Queries the local OpenASN MMDB without surfacing tree prefix lengths as block ranges."""
    path = resolve_openasn_mmdb_path()
    if path is None or maxminddb is None:
        if path is None:
            evict_missing_maxmind_readers(OPENASN_MMDB_FILENAME, "")
        return _empty_openasn_result(has_db=False, updated_at=None)

    updated_at = get_openasn_mtime_iso()
    cleaned = ip.strip() if isinstance(ip, str) else ""
    if "%" in cleaned and ":" in cleaned:
        cleaned = cleaned.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return _empty_openasn_result(has_db=True, updated_at=updated_at)

    if addr.version == 6:
        mapped = addr.ipv4_mapped
        if mapped is not None:
            lookup_ip = str(mapped)
        elif int(addr) >> 32 == 0:
            return _empty_openasn_result(has_db=True, updated_at=updated_at)
        else:
            lookup_ip = str(addr)
    else:
        lookup_ip = str(addr)

    try:
        reader = get_maxmind_reader(str(path), maxminddb)
        raw = reader.get(lookup_ip)
    except (OSError, ValueError, RuntimeError) as exc:
        logger.warning("Failed to query OpenASN MMDB %s: %s", path, exc)
        evict_maxmind_reader(str(path))
        return _empty_openasn_result(has_db=False, updated_at=None)
    if not isinstance(raw, Mapping):
        return _empty_openasn_result(has_db=True, updated_at=updated_at)

    raw_asn = raw.get("asn")
    asn = raw_asn if isinstance(raw_asn, int) and not isinstance(raw_asn, bool) else None
    verdict = raw.get("core_verdict")
    raw_sources = raw.get("core_sources")
    sources = [s for s in raw_sources if isinstance(s, str) and s] if isinstance(raw_sources, list) else []
    return {
        "hasDb": True,
        "has_db": True,
        "lookupStatus": "matched",
        "asn": asn,
        "asOrg": _optional_text(raw.get("as_org")),
        "category": _optional_text(raw.get("category")),
        "networkRole": _optional_text(raw.get("network_role")),
        "badAsn": bool(raw.get("bad_asn")),
        "vpnProvider": bool(raw.get("vpn_provider")),
        "mobileCarrier": bool(raw.get("mobile_carrier")),
        "enterpriseGw": bool(raw.get("enterprise_gw")),
        "cdn": bool(raw.get("cdn")),
        "hostingExtra": bool(raw.get("hosting_extra")),
        "vpnRange": bool(raw.get("vpn_range")),
        "datacenterRange": bool(raw.get("datacenter_range")),
        "coreVerdict": verdict if isinstance(verdict, str) and verdict else "unknown",
        "coreSources": sources,
        "offlineDbUpdatedAt": updated_at,
        "rawRecord": dict(raw),
    }


def is_mobile_asn_offline(asn: Optional[int]) -> bool:
    """Returns True when an ASN is tagged as mobile in PeeringDB mobile_asns.json or bgp_tags.json."""
    asn_num = _parse_asn_int(asn)
    if asn_num is None:
        return False

    path = resolve_feed_data_path(MOBILE_ASNS_JSON_FILENAME, override_setting="MOBILE_ASNS_JSON_PATH")
    peeringdb_asns: FrozenSet[int]
    if path is None:
        peeringdb_asns = _mobile_asns_cache.set_constant(("__missing__", -1, -1), frozenset())
    else:
        sig = get_file_stat_signature(path)
        if sig is None:
            peeringdb_asns = _mobile_asns_cache.set_constant(("__missing__", -1, -1), frozenset())
        else:
            target_key = (str(path), sig[0], sig[1])
            hit = _mobile_asns_cache.peek_matching(lambda key, _val: key == target_key)
            if hit is not None:
                peeringdb_asns = hit
            else:
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    logger.warning("Failed to parse mobile ASNs file %s: %s", path, exc)
                    peeringdb_asns = frozenset()
                else:
                    raw_items: Iterable[Any] = ()
                    if isinstance(payload, list):
                        raw_items = payload
                    elif isinstance(payload, dict):
                        for key in ("mobile_asns", "asns", "data"):
                            candidate = payload.get(key)
                            if isinstance(candidate, list):
                                raw_items = candidate
                                break
                    parsed_asns: set[int] = set()
                    for item in raw_items:
                        parsed_num = _parse_asn_int(item.get("asn")) if isinstance(item, dict) else _parse_asn_int(item)
                        if parsed_num is not None:
                            parsed_asns.add(parsed_num)
                    frozen_asns = frozenset(parsed_asns)
                    peeringdb_asns = _mobile_asns_cache.get_or_load(target_key, lambda: frozen_asns)

    if asn_num in peeringdb_asns:
        return True
    _tags_map, bgp_mobile_asns = _get_bgp_tags_data()
    return asn_num in bgp_mobile_asns


def _resolve_mmdb_path_with_overrides(
    configured_dir: str,
    filename: str,
    standard_dirs: Sequence[Path],
) -> Optional[Path]:
    expanded = expand_configured_path(configured_dir)
    if expanded:
        configured = Path(expanded)
        if configured.is_file():
            return configured
        if configured.is_dir():
            return find_mmdb_in_directory(configured, filename)
        return None
    for directory in standard_dirs:
        matched = find_mmdb_in_directory(directory, filename)
        if matched is not None:
            return matched
    return None


def resolve_maxmind_paths(
    *,
    env_overrides: Optional[Mapping[str, str]] = None,
    base_dir: Optional[Path] = None,
) -> Dict[str, Optional[Path]]:
    """Resolves Country, City, and ASN MMDB paths using configured TOOL_DATA_DIR or fallbacks."""
    resolved_base = _effective_base_dir(base_dir)
    configured_dir = resolve_configured_data_dir(env_overrides=env_overrides)
    if env_overrides is not None:
        standard_dirs = _effective_standard_dirs(env_overrides=env_overrides, base_dir=resolved_base)
        return {
            "country": _resolve_mmdb_path_with_overrides(configured_dir, MAXMIND_COUNTRY_DB_FILENAME, standard_dirs),
            "city": _resolve_mmdb_path_with_overrides(configured_dir, MAXMIND_CITY_DB_FILENAME, standard_dirs),
            "asn": _resolve_mmdb_path_with_overrides(configured_dir, MAXMIND_ASN_DB_FILENAME, standard_dirs),
        }
    return {
        "country": Path(resolve_mmdb_file(configured_dir, MAXMIND_COUNTRY_DB_FILENAME, resolved_base)),
        "city": Path(resolve_mmdb_file(configured_dir, MAXMIND_CITY_DB_FILENAME, resolved_base)),
        "asn": Path(resolve_mmdb_file(configured_dir, MAXMIND_ASN_DB_FILENAME, resolved_base)),
    }


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


def get_maxmind_newest_mtime_iso() -> Optional[str]:
    """Returns the newest UTC ISO-8601 modification timestamp across existing MaxMind MMDB files."""
    paths = resolve_maxmind_paths()
    return _newest_mtime_iso(path for path in paths.values() if _is_regular_file(path))


def build_offline_database_entries(
    *,
    maxmind_paths: Dict[str, Optional[Path]],
    sfs_paths: Dict[str, Optional[Path]],
    hosting_rules_path: Optional[Path],
    hosting_rules_name: str,
    maxmind_stale: int,
    sfs_toxic_stale: int,
    sfs_90_stale: int,
    sfs_1_stale: int,
    rules_stale: int,
    now_ts: float,
    extra_feed_specs: Optional[Sequence[Tuple[str, str, str, Optional[Path], str, bool, int, Optional[str]]]] = None,
    include_resolved_path: bool = False,
) -> List[Dict[str, Any]]:
    """Builds standardised status entries for all configured offline databases and rule files."""
    specs: List[Tuple[str, str, str, Optional[Path], str, bool, int, Optional[str]]] = [
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
            SFS_LISTED_90_ZIP_NAME,
            False,
            sfs_90_stale,
            None,
        ),
        (
            "stopforumspam_listed_1",
            "StopForumSpam",
            "StopForumSpam Listed IPs (1d)",
            sfs_paths.get("listed_1"),
            SFS_LISTED_1_ZIP_NAME,
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
            "hosting_asn_rules",
            "Hosting Rules",
            "Hosting ASN Rules",
            hosting_rules_path,
            hosting_rules_name,
            True,
            rules_stale,
            "Built-in (Optional)",
        ),
    ]
    if extra_feed_specs:
        specs.extend(extra_feed_specs)

    entries: List[Dict[str, Any]] = []
    for key, source, name, file_path, fallback_filename, optional, stale_after_seconds, missing_label in specs:
        filename = file_path.name if file_path is not None else fallback_filename
        sig = get_file_stat_signature(file_path, bypass_throttle=True) if file_path is not None else None
        if sig is None:
            resolved_missing_label = (
                missing_label if missing_label is not None else ("Optional (Not Configured)" if optional else "Missing")
            )
            entry: Dict[str, Any] = {
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
        else:
            mtime_ts = sig[0] / 1_000_000_000.0
            age_seconds = max(0, int(now_ts - mtime_ts))
            is_stale = stale_after_seconds > 0 and age_seconds > stale_after_seconds
            entry = {
                "key": key,
                "source": source,
                "name": name,
                "filename": filename,
                "exists": True,
                "optional": optional,
                "sizeBytes": int(sig[1]),
                "lastModifiedIso": datetime.fromtimestamp(mtime_ts, tz=timezone.utc).isoformat(),
                "ageSeconds": age_seconds,
                "staleAfterSeconds": stale_after_seconds,
                "status": "stale" if is_stale else "healthy",
                "statusLabel": "Stale" if is_stale else "Healthy",
            }
        if include_resolved_path:
            entry["resolvedPath"] = str(file_path) if (file_path is not None and entry["exists"]) else ""
        entries.append(entry)
    return entries


def collect_offline_databases_status(
    *,
    now_dt: Optional[datetime] = None,
    env_overrides: Optional[Mapping[str, str]] = None,
    base_dir: Optional[Path] = None,
    include_resolved_path: bool = False,
) -> List[Dict[str, Any]]:
    """Inventories all local offline databases and rules using file mtime metadata."""
    current_dt = now_dt or datetime.now(timezone.utc)
    now_ts = current_dt.timestamp()

    maxmind_stale = get_positive_int_setting(
        "OFFLINE_DB_MAXMIND_STALE_SECONDS", DEFAULT_STALE_MAXMIND_SECONDS, env_overrides=env_overrides
    )
    sfs_toxic_stale = get_positive_int_setting(
        "OFFLINE_DB_SFS_TOXIC_STALE_SECONDS", DEFAULT_STALE_SFS_TOXIC_SECONDS, env_overrides=env_overrides
    )
    sfs_90_stale = get_positive_int_setting(
        "OFFLINE_DB_SFS_90_STALE_SECONDS", DEFAULT_STALE_SFS_90_SECONDS, env_overrides=env_overrides
    )
    sfs_1_stale = get_positive_int_setting(
        "OFFLINE_DB_SFS_1_STALE_SECONDS", DEFAULT_STALE_SFS_1_SECONDS, env_overrides=env_overrides
    )
    shared_cidrs_stale = get_positive_int_setting(
        "OFFLINE_DB_SHARED_CIDRS_STALE_SECONDS", DEFAULT_STALE_SHARED_CIDRS_SECONDS, env_overrides=env_overrides
    )
    openasn_stale = get_positive_int_setting(
        "OFFLINE_DB_OPENASN_STALE_SECONDS", DEFAULT_STALE_OPENASN_SECONDS, env_overrides=env_overrides
    )
    rules_stale = get_positive_int_setting(
        "OFFLINE_DB_RULES_STALE_SECONDS", DEFAULT_STALE_RULES_SECONDS, env_overrides=env_overrides
    )
    tor_stale = get_positive_int_setting(
        "OFFLINE_DB_TOR_ONIONOO_STALE_SECONDS", DEFAULT_STALE_TOR_ONIONOO_SECONDS, env_overrides=env_overrides
    )
    daily_feed_stale = get_positive_int_setting(
        "OFFLINE_DB_DAILY_FEED_STALE_SECONDS", DEFAULT_STALE_DAILY_FEED_SECONDS, env_overrides=env_overrides
    )

    maxmind_paths = resolve_maxmind_paths(env_overrides=env_overrides, base_dir=base_dir)
    sfs_paths = resolve_stopforumspam_paths(env_overrides=env_overrides, base_dir=base_dir, bypass_throttle=True)
    hosting_rules_path, hosting_rules_name = resolve_hosting_rules_path(
        env_overrides=env_overrides, base_dir=base_dir, bypass_throttle=True
    )

    extra_specs = (
        (
            "shared_cidrs",
            "Shared CIDRs",
            "Rezmoss Shared Egress CIDRs",
            resolve_feed_data_path(
                SHARED_CIDRS_BIN_FILENAME,
                override_setting="SHARED_CIDRS_BIN_PATH",
                env_overrides=env_overrides,
                base_dir=base_dir,
                bypass_throttle=True,
            ),
            SHARED_CIDRS_BIN_FILENAME,
            True,
            shared_cidrs_stale,
            None,
        ),
        (
            "privacy_relays",
            "Privacy Relays",
            "Apple Private Relay and Cloudflare WARP",
            resolve_feed_data_path(
                PRIVACY_RELAYS_BIN_FILENAME,
                override_setting="PRIVACY_RELAYS_BIN_PATH",
                env_overrides=env_overrides,
                base_dir=base_dir,
                bypass_throttle=True,
            ),
            PRIVACY_RELAYS_BIN_FILENAME,
            True,
            daily_feed_stale,
            None,
        ),
        (
            "ipsum_drop",
            "IPsum and DROP",
            "IPsum and Spamhaus DROP Index",
            resolve_feed_data_path(
                IPSUM_DROP_BIN_FILENAME,
                override_setting="IPSUM_DROP_BIN_PATH",
                env_overrides=env_overrides,
                base_dir=base_dir,
                bypass_throttle=True,
            ),
            IPSUM_DROP_BIN_FILENAME,
            True,
            daily_feed_stale,
            None,
        ),
        (
            "tor_onionoo",
            "Tor Onionoo",
            "Tor Onionoo Summary Mirror",
            resolve_feed_data_path(
                TOR_ONIONOO_SUMMARY_FILENAME,
                override_setting="TOR_ONIONOO_SUMMARY_PATH",
                env_overrides=env_overrides,
                base_dir=base_dir,
                bypass_throttle=True,
            ),
            TOR_ONIONOO_SUMMARY_FILENAME,
            True,
            tor_stale,
            None,
        ),
        (
            "bgp_tools",
            "BGP Tools",
            "BGP Routing Table Prefix Index",
            resolve_feed_data_path(
                BGP_TOOLS_BIN_FILENAME,
                override_setting="BGP_TOOLS_BIN_PATH",
                env_overrides=env_overrides,
                base_dir=base_dir,
                bypass_throttle=True,
            ),
            BGP_TOOLS_BIN_FILENAME,
            True,
            daily_feed_stale,
            None,
        ),
        (
            "openasn",
            "OpenASN",
            "OpenASN IP/ASN Classification",
            resolve_feed_data_path(
                OPENASN_MMDB_FILENAME,
                override_setting="OPENASN_MMDB_PATH",
                env_overrides=env_overrides,
                base_dir=base_dir,
                bypass_throttle=True,
            ),
            OPENASN_MMDB_FILENAME,
            True,
            openasn_stale,
            None,
        ),
        (
            "peeringdb_mobile",
            "PeeringDB",
            "PeeringDB Mobile ASNs",
            resolve_feed_data_path(
                MOBILE_ASNS_JSON_FILENAME,
                override_setting="MOBILE_ASNS_JSON_PATH",
                env_overrides=env_overrides,
                base_dir=base_dir,
                bypass_throttle=True,
            ),
            MOBILE_ASNS_JSON_FILENAME,
            True,
            daily_feed_stale,
            None,
        ),
    )

    return build_offline_database_entries(
        maxmind_paths=maxmind_paths,
        sfs_paths=sfs_paths,
        hosting_rules_path=hosting_rules_path,
        hosting_rules_name=hosting_rules_name,
        maxmind_stale=maxmind_stale,
        sfs_toxic_stale=sfs_toxic_stale,
        sfs_90_stale=sfs_90_stale,
        sfs_1_stale=sfs_1_stale,
        rules_stale=rules_stale,
        extra_feed_specs=extra_specs,
        now_ts=now_ts,
        include_resolved_path=include_resolved_path,
    )
