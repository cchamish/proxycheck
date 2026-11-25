"""MaxMind GeoLite2/GeoIP2 and OpenASN MMDB reader pool and path resolution."""

from __future__ import annotations

import ipaddress
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

import maxminddb

from proxycheck.settings import (
    MAXMIND_ASN_DB_FILENAME,
    MAXMIND_CITY_DB_FILENAME,
    MAXMIND_COUNTRY_DB_FILENAME,
    expand_configured_path,
    find_mmdb_in_directory,
    resolve_mmdb_file,
)

from .store import (
    OPENASN_MMDB_FILENAME,
    _effective_base_dir,
    _effective_standard_dirs,
    _is_regular_file,
    _newest_mtime_iso,
    get_file_stat_signature,
    get_setting,
    resolve_configured_data_dir,
    resolve_feed_data_path,
)

logger = logging.getLogger(__name__)

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


def get_maxmind_newest_mtime_iso() -> Optional[str]:
    """Returns the newest UTC ISO-8601 modification timestamp across existing MaxMind MMDB files."""
    paths = resolve_maxmind_paths()
    return _newest_mtime_iso(path for path in paths.values() if _is_regular_file(path))
