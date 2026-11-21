"""ToolsDB L2 persistent cache repository, compliance sanitisation, and non-degrading merge."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import threading
import weakref
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from asgiref.sync import sync_to_async
from django.conf import settings
from django.db import Error as DjangoDbError
from django.db import close_old_connections, connection

from . import sanitization
from .intelligence import MAX_BATCH_IPS, canonicalize_ip, normalize_query_mode
from .models import IpIntelligenceCache
from .provider_registry import (
    DEFAULT_PROVIDER_L2_MAX_RETENTION_DAYS,
    L1_ONLY_PROVIDERS,
    OFFLINE_REHYDRATE_PROVIDERS,
    PROVIDER_BY_KEY,
    PROVIDER_BY_LABEL,
)

logger = logging.getLogger("detector.views")

L2_SCHEMA_VERSION = 1
L2_DB_CONCURRENCY_LIMIT = 3
MAX_L2_BULK_IPS = MAX_BATCH_IPS

_IPV4_MAPPED_PREFIX = b"\x00" * 10 + b"\xff\xff"

_PROVIDER_KEY_LOWER: Dict[str, str] = {key.lower(): key for key in PROVIDER_BY_KEY}
_PROVIDER_LABEL_LOWER: Dict[str, str] = {label.lower(): meta.key for label, meta in PROVIDER_BY_LABEL.items()}

_L2_COMMERCIAL_KEYS = frozenset(
    meta.key
    for meta in PROVIDER_BY_KEY.values()
    if meta.is_commercial_arbitration and meta.key not in L1_ONLY_PROVIDERS
)

_UNCONFIGURED_OR_SKIPPED_STATUSES = frozenset(
    {
        "No API Key",
        "Database Missing",
        "Offline DB Missing",
        "Skipped (IPv6)",
        "Deferred (Light Mode)",
    }
)

_SHODAN_ALLOWED_ROW_KEYS = frozenset(
    {
        "provider",
        "providerKey",
        "status",
        "statusCode",
        "latencyMs",
        "latency",
        "durationMs",
        "openProxyPorts",
        "tags",
        "hostnames",
        "asn",
        "isp",
        "organisation",
        "location",
        "usageType",
        "securityFlags",
        "isHistoricalFallback",
    }
)

_FORBIDDEN_TOP_LEVEL_SNAPSHOT_KEYS = frozenset(
    {
        "rawJson",
        "durationSeconds",
        "memoryMb",
        "username",
        "session",
        "sessionId",
        "tempAccount",
        "temporaryAccount",
        "revId",
        "logId",
        "rangeblock",
        "pendingProviders",
    }
)

_l2_semaphore_lock = threading.Lock()
_l2_semaphores_by_loop: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore]" = (
    weakref.WeakKeyDictionary()
)


@dataclass(frozen=True)
class L2MergeResult:
    """Outcome of a non-degrading L2 cache merge and upsert operation."""

    saved: bool
    degraded_fallback: bool
    fetched_at: Optional[str]
    snapshot: Optional[Dict[str, Any]]
    valid_commercial_count: int
    has_degraded_sources: bool
    retained_historical_providers: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "saved": self.saved,
            "degraded_fallback": self.degraded_fallback,
            "degradedRefreshFallback": self.degraded_fallback,
            "fetched_at": self.fetched_at,
            "fetchedAt": self.fetched_at,
            "snapshot": self.snapshot,
            "valid_commercial_count": self.valid_commercial_count,
            "has_degraded_sources": self.has_degraded_sources,
            "retained_historical_providers": list(self.retained_historical_providers),
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)


def get_l2_db_semaphore() -> asyncio.Semaphore:
    """Returns the per-event-loop semaphore capping concurrent ToolsDB operations to 3."""
    current_loop = asyncio.get_running_loop()
    with _l2_semaphore_lock:
        closed_loops = [loop for loop in list(_l2_semaphores_by_loop.keys()) if loop.is_closed()]
        for stale_loop in closed_loops:
            _l2_semaphores_by_loop.pop(stale_loop, None)
        sem = _l2_semaphores_by_loop.get(current_loop)
        if sem is None:
            sem = asyncio.Semaphore(L2_DB_CONCURRENCY_LIMIT)
            _l2_semaphores_by_loop[current_loop] = sem
        return sem


def clear_l2_db_semaphores() -> None:
    """Clears cached per-loop semaphores for deterministic tests."""
    with _l2_semaphore_lock:
        _l2_semaphores_by_loop.clear()


def pack_ip_binary(raw_ip: str) -> Tuple[bytes, int, str]:
    """Converts an IPv4 or IPv6 address into a 16-byte binary key, version, and canonical text."""
    canonical = canonicalize_ip(raw_ip)
    if not canonical:
        raise ValueError(f"Invalid IP address: {raw_ip!r}")
    addr = ipaddress.ip_address(canonical)
    if addr.version == 4:
        return _IPV4_MAPPED_PREFIX + addr.packed, 4, addr.compressed
    return addr.packed, 6, addr.compressed


def ip_to_bin(raw_ip: str) -> bytes:
    """Returns the 16-byte packed IPv6 or RFC 4291 IPv4-mapped binary representation."""
    ip_bin, _, _ = pack_ip_binary(raw_ip)
    return ip_bin


def unpack_ip_binary(ip_bin: bytes | memoryview) -> str:
    """Restores the canonical IPv4 or IPv6 string from a 16-byte binary key."""
    raw = bytes(ip_bin)
    if len(raw) != 16:
        raise ValueError(f"Expected 16-byte packed IP key, got {len(raw)} bytes.")
    if raw[:12] == _IPV4_MAPPED_PREFIX:
        return ipaddress.IPv4Address(raw[12:]).compressed
    return ipaddress.IPv6Address(raw).compressed


def _ensure_utc(dt_value: Optional[datetime] = None) -> datetime:
    if dt_value is None:
        return datetime.now(timezone.utc)
    if dt_value.tzinfo is None:
        return dt_value.replace(tzinfo=timezone.utc)
    return dt_value.astimezone(timezone.utc)


def _parse_timestamp_epoch(raw_value: Any) -> Optional[float]:
    if isinstance(raw_value, (int, float)) and not isinstance(raw_value, bool):
        return float(raw_value)
    if isinstance(raw_value, str) and raw_value.strip():
        cleaned = raw_value.strip()
        if cleaned.endswith("Z"):
            cleaned = f"{cleaned[:-1]}+00:00"
        try:
            parsed_dt = datetime.fromisoformat(cleaned)
        except ValueError:
            try:
                return float(cleaned)
            except ValueError:
                return None
        return _ensure_utc(parsed_dt).timestamp()
    return None


def _is_l2_cache_enabled() -> bool:
    if not bool(getattr(settings, "ENABLE_L2_TOOLSDB_CACHE", True)):
        return False
    databases = getattr(settings, "DATABASES", None)
    default_db = databases.get("default") if isinstance(databases, dict) else None
    db_name = str(default_db.get("NAME") or "").strip() if isinstance(default_db, dict) else ""
    if db_name.lower().endswith("_p"):
        logger.error("Refusing ToolsDB L2 operation because configured database name ends with public suffix '_p'.")
        return False
    return True


def _get_retention_days_map() -> Dict[str, int]:
    configured = getattr(settings, "PROVIDER_L2_MAX_RETENTION_DAYS", None)
    source = configured if isinstance(configured, Mapping) else DEFAULT_PROVIDER_L2_MAX_RETENTION_DAYS
    out: Dict[str, int] = {}
    for raw_key, raw_days in source.items():
        if isinstance(raw_days, int) and not isinstance(raw_days, bool) and raw_days > 0:
            resolved = resolve_provider_key(str(raw_key)) or str(raw_key).strip().lower()
            out[resolved] = raw_days
    return out


def resolve_provider_key(row_or_identifier: Mapping[str, Any] | str) -> Optional[str]:
    """Resolves the canonical provider registry key from a provider row or label string."""
    if isinstance(row_or_identifier, Mapping):
        explicit_key = row_or_identifier.get("providerKey")
        if isinstance(explicit_key, str) and explicit_key.strip():
            lowered_key = explicit_key.strip().lower()
            if lowered_key in _PROVIDER_KEY_LOWER:
                return _PROVIDER_KEY_LOWER[lowered_key]
        label_val = row_or_identifier.get("provider")
        if isinstance(label_val, str) and label_val.strip():
            cleaned_label = label_val.strip()
            if cleaned_label in PROVIDER_BY_LABEL:
                return PROVIDER_BY_LABEL[cleaned_label].key
            lowered_label = cleaned_label.lower()
            if lowered_label in _PROVIDER_LABEL_LOWER:
                return _PROVIDER_LABEL_LOWER[lowered_label]
            if lowered_label in _PROVIDER_KEY_LOWER:
                return _PROVIDER_KEY_LOWER[lowered_label]
        return None

    if isinstance(row_or_identifier, str) and row_or_identifier.strip():
        cleaned = row_or_identifier.strip()
        if cleaned in PROVIDER_BY_KEY:
            return cleaned
        if cleaned in PROVIDER_BY_LABEL:
            return PROVIDER_BY_LABEL[cleaned].key
        lowered = cleaned.lower()
        return _PROVIDER_KEY_LOWER.get(lowered) or _PROVIDER_LABEL_LOWER.get(lowered)
    return None


def is_provider_allowed_in_l2(provider_key: Optional[str]) -> bool:
    """Returns True when a provider is permitted in L2 persistent storage under compliance rules."""
    if not provider_key:
        return False
    return provider_key not in OFFLINE_REHYDRATE_PROVIDERS and provider_key not in L1_ONLY_PROVIDERS


def _sanitize_shodan_row(row: Mapping[str, Any]) -> Dict[str, Any]:
    cleaned: Dict[str, Any] = {}
    for key, val in row.items():
        if key not in _SHODAN_ALLOWED_ROW_KEYS or key in ("rawJson", "vulns", "cpes"):
            continue
        if key == "tags" and isinstance(val, list):
            cleaned[key] = [
                str(tag).strip()
                for tag in val
                if isinstance(tag, str) and tag.strip() and not tag.strip().lower().startswith("cve-")
            ]
        elif key == "openProxyPorts" and isinstance(val, list):
            cleaned[key] = [int(port) for port in val if isinstance(port, int) and not isinstance(port, bool)]
        elif key == "hostnames" and isinstance(val, list):
            cleaned[key] = [str(host).strip() for host in val if isinstance(host, str) and host.strip()]
        else:
            cleaned[key] = val
    return sanitization.sanitize_payload(cleaned)


def sanitize_provider_row_for_l2(
    row: Mapping[str, Any], provider_key: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Applies four-tier compliance stripping to a single provider result row before L2 persistence."""
    resolved_key = provider_key or resolve_provider_key(row)
    if not is_provider_allowed_in_l2(resolved_key):
        return None
    if resolved_key == "shodan_internetdb":
        return _sanitize_shodan_row(row)
    stripped = {key: val for key, val in row.items() if key != "rawJson"}
    return sanitization.sanitize_payload(stripped)


def sanitize_snapshot_for_l2(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    """Returns a compliance-sanitised snapshot copy suitable for L2 compression."""
    sanitized_top: Dict[str, Any] = {}
    for key, val in snapshot.items():
        if key in _FORBIDDEN_TOP_LEVEL_SNAPSHOT_KEYS or key == "results":
            continue
        sanitized_top[key] = sanitization.sanitize_payload(val)

    raw_results = snapshot.get("results")
    sanitized_results: List[Dict[str, Any]] = []
    if isinstance(raw_results, list):
        for item in raw_results:
            if not isinstance(item, Mapping):
                continue
            cleaned_row = sanitize_provider_row_for_l2(item)
            if cleaned_row is not None:
                sanitized_results.append(cleaned_row)

    sanitized_top["results"] = sanitized_results
    return sanitized_top


def compress_l2_payload(payload: Mapping[str, Any]) -> bytes:
    """Serialises and zlib-compresses a sanitised L2 snapshot dictionary."""
    raw_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return zlib.compress(raw_bytes, level=6)


def decompress_l2_payload(compressed_blob: bytes | memoryview) -> Optional[Dict[str, Any]]:
    """Decompresses and parses an L2 zlib payload blob."""
    if not compressed_blob:
        return None
    try:
        decompressed = zlib.decompress(bytes(compressed_blob))
        parsed = json.loads(decompressed.decode("utf-8"))
    except zlib.error, ValueError, TypeError, UnicodeDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _is_valid_l2_provider_row(row: Mapping[str, Any], provider_key: Optional[str] = None) -> bool:
    status_code = row.get("statusCode")
    status_text = row.get("status")
    if status_code == 200 and status_text == "200 OK":
        return True
    return bool(
        provider_key == "shodan_internetdb"
        and status_code == 404
        and not row.get("isCooldown")
        and not row.get("isQuotaGuard")
    )


def _is_unconfigured_or_skipped_row(row: Mapping[str, Any]) -> bool:
    if row.get("isDeferred") is True:
        return True
    return row.get("statusCode") is None and str(row.get("status") or "") in _UNCONFIGURED_OR_SKIPPED_STATUSES


def _is_failed_online_row(row: Mapping[str, Any], provider_key: Optional[str]) -> bool:
    if provider_key in OFFLINE_REHYDRATE_PROVIDERS:
        return False
    return not (_is_valid_l2_provider_row(row, provider_key) or _is_unconfigured_or_skipped_row(row))


def _count_valid_commercial_rows(rows: Sequence[Mapping[str, Any]], *, exclude_historical: bool = False) -> int:
    count = 0
    for item in rows:
        if exclude_historical and item.get("isHistoricalFallback") is True:
            continue
        pkey = resolve_provider_key(item)
        if pkey in _L2_COMMERCIAL_KEYS and _is_valid_l2_provider_row(item, pkey):
            count += 1
    return count


def _is_provider_expired(
    provider_key: str,
    fetched_map: Mapping[str, Any],
    row_fetched_epoch: float,
    now_epoch: float,
    retention_days_map: Mapping[str, int],
) -> bool:
    max_days = retention_days_map.get(provider_key)
    if max_days is None or max_days <= 0:
        return False
    prov_epoch = _parse_timestamp_epoch(fetched_map.get(provider_key))
    if prov_epoch is None:
        prov_epoch = row_fetched_epoch
    return (now_epoch - prov_epoch) > (float(max_days) * 86400.0)


def _decode_and_filter_l2_row(
    db_row: IpIntelligenceCache,
    *,
    now_utc: datetime,
    retention_days_map: Mapping[str, int],
) -> Optional[Dict[str, Any]]:
    payload = decompress_l2_payload(db_row.payload_compressed)
    if payload is None:
        return None

    row_fetched_utc = _ensure_utc(db_row.fetched_at)
    row_fetched_iso = row_fetched_utc.isoformat()
    row_fetched_epoch = row_fetched_utc.timestamp()
    now_epoch = now_utc.timestamp()
    raw_fetched_map = db_row.provider_fetched_map if isinstance(db_row.provider_fetched_map, Mapping) else {}

    filtered_results: List[Dict[str, Any]] = []
    filtered_fetched_map: Dict[str, int] = {}
    raw_results = payload.get("results")
    if isinstance(raw_results, list):
        for item in raw_results:
            if not isinstance(item, Mapping):
                continue
            pkey = resolve_provider_key(item)
            if not is_provider_allowed_in_l2(pkey) or pkey is None:
                continue
            if _is_provider_expired(pkey, raw_fetched_map, row_fetched_epoch, now_epoch, retention_days_map):
                continue
            cleaned_row = sanitize_provider_row_for_l2(item, pkey)
            if cleaned_row is None:
                continue
            filtered_results.append(cleaned_row)
            prov_ts = _parse_timestamp_epoch(raw_fetched_map.get(pkey))
            filtered_fetched_map[pkey] = int(prov_ts if prov_ts is not None else row_fetched_epoch)

    snapshot_out = {
        key: val for key, val in payload.items() if key not in _FORBIDDEN_TOP_LEVEL_SNAPSHOT_KEYS and key != "results"
    }
    snapshot_out["ip"] = db_row.canonical_ip
    snapshot_out["queryMode"] = normalize_query_mode(db_row.query_mode)
    snapshot_out["fetchedAt"] = row_fetched_iso
    snapshot_out["results"] = filtered_results
    snapshot_out["providerFetchedMap"] = filtered_fetched_map
    snapshot_out["validCommercialCount"] = _count_valid_commercial_rows(filtered_results)
    snapshot_out["hasDegradedSources"] = bool(db_row.has_degraded_sources)
    snapshot_out["schemaVersion"] = int(db_row.schema_version)
    return snapshot_out


def get_ip_snapshot(
    canonical_ip: str,
    *,
    mode: Optional[str] = None,
    now_dt: Optional[datetime] = None,
) -> Optional[Dict[str, Any]]:
    """Reads a single IP snapshot from ToolsDB L2 with compliance retention filtering."""
    if not _is_l2_cache_enabled():
        return None
    try:
        ip_bin, _, _ = pack_ip_binary(canonical_ip)
    except ValueError:
        return None

    now_utc = _ensure_utc(now_dt)
    retention_map = _get_retention_days_map()
    try:
        close_old_connections()
        db_row = IpIntelligenceCache.objects.filter(ip_bin=ip_bin).first()
        if db_row is None:
            return None
        if mode is not None and normalize_query_mode(mode) == "full" and db_row.query_mode == "light":
            return None
        return _decode_and_filter_l2_row(db_row, now_utc=now_utc, retention_days_map=retention_map)
    except DjangoDbError as db_err:
        safe_err = sanitization.sanitize_error_message(str(db_err))
        logger.warning(f"ToolsDB L2 single read bypassed due to database error: {safe_err}")
        return None
    finally:
        close_old_connections()


async def aget_ip_snapshot(
    canonical_ip: str,
    *,
    mode: Optional[str] = None,
    now_dt: Optional[datetime] = None,
) -> Optional[Dict[str, Any]]:
    """Asynchronously reads a single IP snapshot from ToolsDB L2 under the worker concurrency semaphore."""
    if not _is_l2_cache_enabled():
        return None
    async with get_l2_db_semaphore():
        return await sync_to_async(get_ip_snapshot, thread_sensitive=True)(
            canonical_ip,
            mode=mode,
            now_dt=now_dt,
        )


def get_ip_snapshots_bulk(
    canonical_ips: Sequence[str],
    *,
    mode: Optional[str] = None,
    now_dt: Optional[datetime] = None,
) -> Dict[str, Dict[str, Any]]:
    """Reads up to 25 IP snapshots in a single ToolsDB WHERE IN query."""
    if not _is_l2_cache_enabled() or not canonical_ips:
        return {}

    packed_keys: List[bytes] = []
    seen_bins: set[bytes] = set()
    for raw_ip in canonical_ips:
        if not isinstance(raw_ip, str) or not raw_ip.strip():
            continue
        try:
            ip_bin, _, _ = pack_ip_binary(raw_ip)
        except ValueError:
            continue
        if ip_bin not in seen_bins:
            seen_bins.add(ip_bin)
            packed_keys.append(ip_bin)
            if len(packed_keys) >= MAX_L2_BULK_IPS:
                break

    if not packed_keys:
        return {}

    now_utc = _ensure_utc(now_dt)
    retention_map = _get_retention_days_map()
    requested_full = mode is not None and normalize_query_mode(mode) == "full"
    try:
        close_old_connections()
        rows = list(IpIntelligenceCache.objects.filter(ip_bin__in=packed_keys))
        hits: Dict[str, Dict[str, Any]] = {}
        for db_row in rows:
            if requested_full and db_row.query_mode == "light":
                continue
            decoded = _decode_and_filter_l2_row(db_row, now_utc=now_utc, retention_days_map=retention_map)
            if decoded is not None:
                hits[db_row.canonical_ip] = decoded
        return hits
    except DjangoDbError as db_err:
        safe_err = sanitization.sanitize_error_message(str(db_err))
        logger.warning(f"ToolsDB L2 bulk read bypassed due to database error: {safe_err}")
        return {}
    finally:
        close_old_connections()


async def aget_ip_snapshots_bulk(
    canonical_ips: Sequence[str],
    *,
    mode: Optional[str] = None,
    now_dt: Optional[datetime] = None,
) -> Dict[str, Dict[str, Any]]:
    """Asynchronously reads up to 25 IP snapshots from ToolsDB L2 under the worker semaphore."""
    if not _is_l2_cache_enabled() or not canonical_ips:
        return {}
    async with get_l2_db_semaphore():
        return await sync_to_async(get_ip_snapshots_bulk, thread_sensitive=True)(
            canonical_ips,
            mode=mode,
            now_dt=now_dt,
        )


def _evaluate_incoming_rows(raw_results: Any) -> Tuple[int, int, bool]:
    if not isinstance(raw_results, list):
        return 0, 0, False
    new_valid_comm = 0
    failed_comm = 0
    any_degraded = False
    for item in raw_results:
        if not isinstance(item, Mapping):
            continue
        pkey = resolve_provider_key(item)
        if (
            pkey in _L2_COMMERCIAL_KEYS
            and _is_valid_l2_provider_row(item, pkey)
            and not item.get("isHistoricalFallback")
        ):
            new_valid_comm += 1
        elif _is_failed_online_row(item, pkey):
            any_degraded = True
            if pkey is not None and pkey in PROVIDER_BY_KEY and PROVIDER_BY_KEY[pkey].is_commercial_arbitration:
                failed_comm += 1
    return new_valid_comm, failed_comm, any_degraded


def _should_abort_degraded_overwrite(
    existing_row: Optional[IpIntelligenceCache],
    new_valid_comm: int,
    failed_comm: int,
) -> bool:
    if existing_row is None:
        return new_valid_comm == 0 and failed_comm > 0
    existing_comm = int(existing_row.valid_commercial_count)
    if new_valid_comm == 0 and (existing_comm > 0 or failed_comm > 0):
        return True
    return existing_comm > 0 and new_valid_comm < max(1.0, existing_comm * 0.5)


def _build_merged_l2_rows(
    raw_results: Any,
    *,
    existing_snapshot: Optional[Mapping[str, Any]],
    explicit_fetched_map: Mapping[str, Any],
    now_epoch: int,
    existing_epoch: Optional[int],
) -> Tuple[List[Dict[str, Any]], Dict[str, int], List[str], bool]:
    existing_rows_by_key: Dict[str, Dict[str, Any]] = {}
    existing_map: Mapping[str, Any] = {}
    if existing_snapshot is not None:
        existing_map = (
            existing_snapshot.get("providerFetchedMap")
            if isinstance(existing_snapshot.get("providerFetchedMap"), Mapping)
            else {}
        )
        for prior_item in existing_snapshot.get("results") or ():
            if isinstance(prior_item, Mapping):
                prior_key = resolve_provider_key(prior_item)
                if (
                    prior_key
                    and is_provider_allowed_in_l2(prior_key)
                    and _is_valid_l2_provider_row(prior_item, prior_key)
                ):
                    existing_rows_by_key[prior_key] = dict(prior_item)

    merged_rows: List[Dict[str, Any]] = []
    merged_fetched_map: Dict[str, int] = {}
    retained_keys: List[str] = []
    seen_keys: set[str] = set()
    had_fallback = False

    for item in raw_results if isinstance(raw_results, list) else ():
        if not isinstance(item, Mapping):
            continue
        pkey = resolve_provider_key(item)
        if not is_provider_allowed_in_l2(pkey) or pkey is None:
            continue
        seen_keys.add(pkey)
        if _is_valid_l2_provider_row(item, pkey) and not item.get("isHistoricalFallback"):
            cleaned = sanitize_provider_row_for_l2(item, pkey)
            if cleaned is not None:
                cleaned.pop("isHistoricalFallback", None)
                merged_rows.append(cleaned)
                explicit_ts = _parse_timestamp_epoch(explicit_fetched_map.get(pkey))
                merged_fetched_map[pkey] = int(explicit_ts if explicit_ts is not None else now_epoch)
        elif pkey in existing_rows_by_key and _is_failed_online_row(item, pkey):
            fallback_row = sanitize_provider_row_for_l2(existing_rows_by_key[pkey], pkey)
            if fallback_row is not None:
                fallback_row["isHistoricalFallback"] = True
                merged_rows.append(fallback_row)
                prior_ts = _parse_timestamp_epoch(existing_map.get(pkey))
                merged_fetched_map[pkey] = int(
                    prior_ts if prior_ts is not None else (existing_epoch if existing_epoch is not None else now_epoch)
                )
                retained_keys.append(pkey)
                had_fallback = True

    for prior_key, prior_row in existing_rows_by_key.items():
        if prior_key in seen_keys:
            continue
        fallback_row = sanitize_provider_row_for_l2(prior_row, prior_key)
        if fallback_row is not None:
            fallback_row["isHistoricalFallback"] = True
            merged_rows.append(fallback_row)
            prior_ts = _parse_timestamp_epoch(existing_map.get(prior_key))
            merged_fetched_map[prior_key] = int(
                prior_ts if prior_ts is not None else (existing_epoch if existing_epoch is not None else now_epoch)
            )
            retained_keys.append(prior_key)

    return merged_rows, merged_fetched_map, retained_keys, had_fallback


def merge_and_upsert_l2_snapshot(
    canonical_ip: str,
    snapshot: Mapping[str, Any],
    *,
    query_mode: Optional[str] = None,
    now_dt: Optional[datetime] = None,
) -> L2MergeResult:
    """Sanitises, merges without degradation, compresses, and upserts an IP snapshot in ToolsDB L2."""
    if not _is_l2_cache_enabled() or not isinstance(snapshot, Mapping):
        return L2MergeResult(
            saved=False,
            degraded_fallback=False,
            fetched_at=None,
            snapshot=None,
            valid_commercial_count=0,
            has_degraded_sources=False,
        )

    try:
        ip_bin, ip_version, normalized_ip = pack_ip_binary(canonical_ip)
    except ValueError:
        return L2MergeResult(
            saved=False,
            degraded_fallback=False,
            fetched_at=None,
            snapshot=None,
            valid_commercial_count=0,
            has_degraded_sources=False,
        )

    now_utc = _ensure_utc(now_dt)
    now_iso = now_utc.isoformat()
    now_epoch = int(now_utc.timestamp())
    retention_map = _get_retention_days_map()
    effective_mode = normalize_query_mode(query_mode or snapshot.get("queryMode"), default="full")

    raw_results = snapshot.get("results")
    new_valid_comm, failed_comm, any_degraded = _evaluate_incoming_rows(raw_results)
    if snapshot.get("hasDegradedSources") is True:
        any_degraded = True

    try:
        close_old_connections()
        existing_row = IpIntelligenceCache.objects.filter(ip_bin=ip_bin).first()
        existing_snapshot = (
            _decode_and_filter_l2_row(existing_row, now_utc=now_utc, retention_days_map=retention_map)
            if existing_row is not None
            else None
        )

        if _should_abort_degraded_overwrite(existing_row, new_valid_comm, failed_comm):
            preserved_fetched_at = (
                _ensure_utc(existing_row.fetched_at).isoformat() if existing_row is not None else None
            )
            preserved_comm = int(existing_row.valid_commercial_count) if existing_row is not None else 0
            return L2MergeResult(
                saved=False,
                degraded_fallback=True,
                fetched_at=preserved_fetched_at,
                snapshot=existing_snapshot,
                valid_commercial_count=preserved_comm,
                has_degraded_sources=True,
            )

        raw_explicit_map = snapshot.get("providerFetchedMap") or snapshot.get("provider_fetched_map")
        explicit_map = raw_explicit_map if isinstance(raw_explicit_map, Mapping) else {}
        existing_epoch = int(_ensure_utc(existing_row.fetched_at).timestamp()) if existing_row is not None else None

        merged_rows, merged_fetched_map, retained_keys, had_fallback = _build_merged_l2_rows(
            raw_results,
            existing_snapshot=existing_snapshot,
            explicit_fetched_map=explicit_map,
            now_epoch=now_epoch,
            existing_epoch=existing_epoch,
        )
        final_degraded = any_degraded or had_fallback
        final_mode = (
            "full"
            if (existing_row is not None and existing_row.query_mode == "full" and effective_mode == "light")
            else effective_mode
        )

        base_sanitized = sanitize_snapshot_for_l2(snapshot)
        if base_sanitized.get("ptrHostname") is None and existing_snapshot is not None:
            prior_ptr = existing_snapshot.get("ptrHostname")
            if isinstance(prior_ptr, str) and prior_ptr:
                base_sanitized["ptrHostname"] = prior_ptr

        base_sanitized["ip"] = normalized_ip
        base_sanitized["queryMode"] = final_mode
        base_sanitized["results"] = merged_rows
        compressed_blob = compress_l2_payload(base_sanitized)
        final_valid_comm = _count_valid_commercial_rows(merged_rows)

        IpIntelligenceCache.objects.update_or_create(
            ip_bin=ip_bin,
            defaults={
                "ip_version": ip_version,
                "canonical_ip": normalized_ip,
                "schema_version": L2_SCHEMA_VERSION,
                "query_mode": final_mode,
                "payload_compressed": compressed_blob,
                "provider_fetched_map": merged_fetched_map,
                "valid_commercial_count": final_valid_comm,
                "has_degraded_sources": final_degraded,
                "fetched_at": now_utc,
            },
        )

        stored_snapshot = {
            **base_sanitized,
            "fetchedAt": now_iso,
            "providerFetchedMap": merged_fetched_map,
            "validCommercialCount": final_valid_comm,
            "hasDegradedSources": final_degraded,
            "schemaVersion": L2_SCHEMA_VERSION,
        }
        return L2MergeResult(
            saved=True,
            degraded_fallback=False,
            fetched_at=now_iso,
            snapshot=stored_snapshot,
            valid_commercial_count=final_valid_comm,
            has_degraded_sources=final_degraded,
            retained_historical_providers=tuple(retained_keys),
        )
    except DjangoDbError as db_err:
        safe_err = sanitization.sanitize_error_message(str(db_err))
        logger.warning(f"ToolsDB L2 upsert bypassed due to database error: {safe_err}")
        return L2MergeResult(
            saved=False,
            degraded_fallback=False,
            fetched_at=None,
            snapshot=None,
            valid_commercial_count=0,
            has_degraded_sources=any_degraded,
        )
    finally:
        close_old_connections()


async def amerge_and_upsert_l2_snapshot(
    canonical_ip: str,
    snapshot: Mapping[str, Any],
    *,
    query_mode: Optional[str] = None,
    now_dt: Optional[datetime] = None,
) -> L2MergeResult:
    """Asynchronously merges and upserts an IP snapshot into ToolsDB L2 under the worker semaphore."""
    if not _is_l2_cache_enabled():
        return L2MergeResult(
            saved=False,
            degraded_fallback=False,
            fetched_at=None,
            snapshot=None,
            valid_commercial_count=0,
            has_degraded_sources=False,
        )
    async with get_l2_db_semaphore():
        return await sync_to_async(merge_and_upsert_l2_snapshot, thread_sensitive=True)(
            canonical_ip,
            snapshot,
            query_mode=query_mode,
            now_dt=now_dt,
        )


def _clean_expired_providers_on_row(
    db_row: IpIntelligenceCache,
    *,
    now_epoch: float,
    retention_map: Mapping[str, int],
    dry_run: bool,
) -> Tuple[bool, int]:
    payload = decompress_l2_payload(db_row.payload_compressed)
    raw_map = dict(db_row.provider_fetched_map) if isinstance(db_row.provider_fetched_map, Mapping) else {}
    row_fetched_epoch = _ensure_utc(db_row.fetched_at).timestamp()

    removed_count = 0
    updated_results: List[Any] = []
    if isinstance(payload, dict) and isinstance(payload.get("results"), list):
        for item in payload["results"]:
            if not isinstance(item, Mapping):
                continue
            pkey = resolve_provider_key(item)
            if pkey and _is_provider_expired(pkey, raw_map, row_fetched_epoch, now_epoch, retention_map):
                removed_count += 1
                raw_map.pop(pkey, None)
                continue
            updated_results.append(item)

    for map_key in list(raw_map.keys()):
        resolved_key = resolve_provider_key(map_key) or map_key
        if _is_provider_expired(resolved_key, raw_map, row_fetched_epoch, now_epoch, retention_map):
            raw_map.pop(map_key, None)
            if removed_count == 0:
                removed_count += 1

    if removed_count == 0 or payload is None:
        return False, 0

    if not dry_run:
        updated_payload = {**payload, "results": updated_results}
        db_row.payload_compressed = compress_l2_payload(updated_payload)
        db_row.provider_fetched_map = raw_map
        db_row.valid_commercial_count = _count_valid_commercial_rows(
            [item for item in updated_results if isinstance(item, Mapping)]
        )
        db_row.save(
            update_fields=["payload_compressed", "provider_fetched_map", "valid_commercial_count", "updated_at"]
        )
    return True, removed_count


def _scan_purge_queryset(
    base_qs: Any,
    *,
    batch_size: int,
    now_epoch: float,
    retention_map: Mapping[str, int],
    dry_run: bool,
    seen_bins: set[bytes],
) -> Tuple[int, int, int]:
    scanned = 0
    updated = 0
    purged_providers = 0
    last_ip_bin: Optional[bytes] = None

    while True:
        qs = base_qs.order_by("ip_bin")
        if last_ip_bin is not None:
            qs = qs.filter(ip_bin__gt=last_ip_bin)
        batch = list(qs[:batch_size])
        if not batch:
            break
        for db_row in batch:
            raw_bin = bytes(db_row.ip_bin)
            last_ip_bin = raw_bin
            if raw_bin in seen_bins:
                continue
            seen_bins.add(raw_bin)
            scanned += 1
            changed, removed = _clean_expired_providers_on_row(
                db_row,
                now_epoch=now_epoch,
                retention_map=retention_map,
                dry_run=dry_run,
            )
            if changed:
                updated += 1
                purged_providers += removed
        if len(batch) < batch_size:
            break

    return scanned, updated, purged_providers


def purge_expired_provider_fields(
    *,
    batch_size: int = 500,
    dry_run: bool = False,
    now_dt: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Scans indexed L2 rows in batches and erases provider details exceeding their retention limit."""
    effective_batch = max(1, int(batch_size))
    retention_map = _get_retention_days_map()
    if not _is_l2_cache_enabled() or not retention_map:
        return {"scanned": 0, "updated": 0, "purged_providers": 0, "dry_run": bool(dry_run), "failed": False}

    now_utc = _ensure_utc(now_dt)
    now_epoch = now_utc.timestamp()
    min_retention_days = min(retention_map.values())
    cutoff_dt = now_utc - timedelta(days=min_retention_days)
    seen_bins: set[bytes] = set()

    try:
        close_old_connections()
        older_qs = IpIntelligenceCache.objects.filter(fetched_at__lte=cutoff_dt)
        scanned, updated, purged_providers = _scan_purge_queryset(
            older_qs,
            batch_size=effective_batch,
            now_epoch=now_epoch,
            retention_map=retention_map,
            dry_run=dry_run,
            seen_bins=seen_bins,
        )

        for restricted_key in retention_map:
            fallback_qs = IpIntelligenceCache.objects.filter(
                fetched_at__gt=cutoff_dt,
                provider_fetched_map__has_key=restricted_key,
            )
            extra_scanned, extra_updated, extra_purged = _scan_purge_queryset(
                fallback_qs,
                batch_size=effective_batch,
                now_epoch=now_epoch,
                retention_map=retention_map,
                dry_run=dry_run,
                seen_bins=seen_bins,
            )
            scanned += extra_scanned
            updated += extra_updated
            purged_providers += extra_purged

        return {
            "scanned": scanned,
            "updated": updated,
            "purged_providers": purged_providers,
            "dry_run": bool(dry_run),
            "failed": False,
        }
    except DjangoDbError as db_err:
        connection.close()
        safe_err = sanitization.sanitize_error_message(str(db_err))
        logger.warning(f"ToolsDB L2 retention purge bypassed due to database error: {safe_err}")
        return {"scanned": 0, "updated": 0, "purged_providers": 0, "dry_run": bool(dry_run), "failed": True}
    finally:
        close_old_connections()
