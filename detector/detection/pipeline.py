"""Shared IP intelligence detection pipeline stages reused by single/batch and SSE services."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

import httpx

from .. import offline as offline_dbs
from ..cache import l2_store as l2_cache
from ..cache import quota_telemetry
from ..cache.quota_telemetry import is_provider_configured
from ..cache.redis_backend import (
    decode_cached_provider_entry,
    decode_cached_ptr_entry,
    decode_cooldown_entry,
    get_cached_ip_snapshot,
    get_provider_cache_ttl,
    get_redis_client,
    is_ip_updating_locked,
    is_swr_backed_off,
    provider_cache_key,
    provider_cooldown_key,
    safe_redis_mget,
    set_cached_ip_snapshot,
    should_refresh_cached_maxmind_entry,
    should_refresh_cached_stopforumspam_entry,
)
from ..core import sanitization
from ..core.ip_utils import normalize_query_mode, parse_compact_flag
from ..offline import (
    cidr_attribution,
    get_maxmind_newest_mtime_iso,
    get_openasn_mtime_iso,
    get_positive_int_setting,
    get_stopforumspam_db_version,
    has_any_local_stopforumspam_db,
)
from ..provider_registry import (
    DNSBL_PROVIDER_KEYS,
    LIGHT_MODE_ACTIVE_PROVIDER_KEYS,
    NO_REDIS_CACHE_PROVIDER_KEYS,
    OFFLINE_PROVIDER_KEYS,
    OFFLINE_REHYDRATE_PROVIDERS,
)
from ..providers import (
    PROVIDER_SPECS,
    ProviderSpec,
    build_unhandled_provider_error_row,
    is_provider_result_cacheable,
    is_unconfigured_provider_row,
)
from . import arbitration as intelligence

logger = logging.getLogger("detector.views")

_BATCH_DETECT_CONCURRENCY = 5
_LOCK_POLL_INTERVAL_SECONDS = 0.25
_LOCK_POLL_MAX_WAIT_SECONDS = 15.0
_FRESH_RECHECK_THRESHOLD_SECONDS = 60.0
_DEFAULT_SWR_STALE_DAYS = 7
_DEFAULT_REFRESH_COOLDOWN_SECONDS = 300
_DEFAULT_SWR_BACKOFF_SECONDS = 600


async def _safe_l2_aget_snapshot(ip: str, *, mode: str) -> Optional[Dict[str, Any]]:
    try:
        return await l2_cache.aget_ip_snapshot(ip, mode=mode)
    except AssertionError as exc:
        if type(exc).__name__ == "DatabaseOperationForbidden":
            return None
        raise


async def _safe_l2_amerge_snapshot(
    ip: str,
    snapshot: Dict[str, Any],
    *,
    query_mode: str,
    now_dt: datetime,
) -> l2_cache.L2MergeResult:
    try:
        return await l2_cache.amerge_and_upsert_l2_snapshot(
            ip,
            snapshot,
            query_mode=query_mode,
            now_dt=now_dt,
        )
    except AssertionError as exc:
        if type(exc).__name__ == "DatabaseOperationForbidden":
            return l2_cache.L2MergeResult(
                saved=False,
                degraded_fallback=False,
                fetched_at=now_dt.isoformat(),
                snapshot=None,
                valid_commercial_count=0,
                has_degraded_sources=False,
            )
        raise


def _get_spec_by_key() -> Dict[str, ProviderSpec]:
    return {spec.key: spec for spec in PROVIDER_SPECS}


def _get_stale_threshold_seconds() -> int:
    stale_days = get_positive_int_setting("CACHE_SWR_STALE_DAYS", _DEFAULT_SWR_STALE_DAYS)
    return stale_days * 86400


def _compute_age_and_staleness(
    fetched_at_iso: Optional[str],
    now_dt: datetime,
) -> Tuple[str, int, int, bool]:
    stale_threshold = _get_stale_threshold_seconds()
    parsed_fetched: Optional[datetime] = None
    if isinstance(fetched_at_iso, str) and fetched_at_iso.strip():
        cleaned = fetched_at_iso.strip()
        if cleaned.endswith("Z"):
            cleaned = f"{cleaned[:-1]}+00:00"
        try:
            dt_val = datetime.fromisoformat(cleaned)
            parsed_fetched = (
                dt_val.replace(tzinfo=timezone.utc) if dt_val.tzinfo is None else dt_val.astimezone(timezone.utc)
            )
        except ValueError:
            parsed_fetched = None
    if parsed_fetched is None:
        return now_dt.isoformat(), 0, stale_threshold, False
    age_seconds = max(0, int((now_dt - parsed_fetched).total_seconds()))
    return fetched_at_iso or now_dt.isoformat(), age_seconds, stale_threshold, age_seconds > stale_threshold


def _current_offline_provider_signature(provider_key: str) -> str:
    if provider_key == "maxmind":
        return f"{get_maxmind_newest_mtime_iso() or 'none'}|{int(offline_dbs.has_local_maxmind_city_db())}"
    if provider_key == "stopforumspam":
        return f"v:{get_stopforumspam_db_version()}"
    if provider_key == "ipsum_drop":
        return offline_dbs._ipsum_drop_index.get_reader_and_mtime()[1] or "none"
    if provider_key == "openasn":
        return get_openasn_mtime_iso() or "none"
    return "none"


def _stamp_offline_signatures(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    stamped: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        pkey = l2_cache.resolve_provider_key(row)
        if pkey in NO_REDIS_CACHE_PROVIDER_KEYS:
            continue
        if pkey in OFFLINE_REHYDRATE_PROVIDERS:
            stamped.append({**row, "_rehydrate_sig": _current_offline_provider_signature(pkey)})
        else:
            stamped.append(dict(row))
    return stamped


def is_compact_request(request: Any, body: Optional[Dict[str, Any]] = None) -> bool:
    """Checks query parameters and optional JSON body for compact mode requests."""
    raw_query = request.GET.get("compact")
    if raw_query is not None and str(raw_query).strip():
        return parse_compact_flag(str(raw_query))
    if isinstance(body, dict) and "compact" in body:
        return parse_compact_flag(body.get("compact"))
    return False


def resolve_query_mode(request: Any, body: Optional[Dict[str, Any]] = None, *, default: str = "full") -> str:
    """Checks query parameters and optional JSON body for the detection query mode."""
    raw_query = request.GET.get("mode")
    if raw_query is not None and str(raw_query).strip():
        return normalize_query_mode(raw_query, default=default)
    if isinstance(body, dict) and "mode" in body and body.get("mode") is not None:
        raw_body_mode = str(body.get("mode")).strip()
        if raw_body_mode:
            return normalize_query_mode(raw_body_mode, default=default)
    return "light" if default == "light" else "full"


async def _ensure_offline_caches_warm() -> None:
    if not cidr_attribution.are_offline_intelligence_caches_warm():
        await asyncio.to_thread(cidr_attribution.warm_offline_intelligence_caches)


async def _read_provider_caches(
    ip: str,
) -> Tuple[Dict[str, Tuple[Dict[str, Any], Optional[str]]], Optional[Tuple[Optional[str], Optional[str]]]]:
    if get_redis_client() is None:
        return {}, None
    read_specs = [spec for spec in PROVIDER_SPECS if spec.key not in NO_REDIS_CACHE_PROVIDER_KEYS]
    keys = [provider_cache_key(spec.key, ip) for spec in read_specs]
    keys.append(provider_cache_key("ptr", ip))
    raw_values = await safe_redis_mget(keys)
    cached_providers: Dict[str, Tuple[Dict[str, Any], Optional[str]]] = {}
    for idx, spec in enumerate(read_specs):
        decoded = decode_cached_provider_entry(raw_values[idx])
        if decoded is not None:
            if spec.key == "maxmind" and should_refresh_cached_maxmind_entry(raw_values[idx], decoded[0]):
                continue
            if spec.key == "stopforumspam" and should_refresh_cached_stopforumspam_entry(decoded[0]):
                continue
            cached_providers[spec.key] = decoded
    cached_ptr = decode_cached_ptr_entry(raw_values[-1])
    return cached_providers, cached_ptr


def _plan_provider_execution(
    cached_providers: Dict[str, Tuple[Dict[str, Any], Optional[str]]],
    normalized_mode: str,
    is_ipv4: bool,
) -> Tuple[FrozenSet[str], FrozenSet[str], List[str]]:
    """Computes expected cache keys, light-mode deferrals, and cooldown lookup keys in one pass."""
    expected: Set[str] = set()
    deferred: Set[str] = set()
    missed_cooldown_keys: List[str] = []

    for spec in PROVIDER_SPECS:
        key = spec.key
        is_expected = (
            key not in NO_REDIS_CACHE_PROVIDER_KEYS
            and (is_ipv4 or (key not in DNSBL_PROVIDER_KEYS and key not in {"shodan_internetdb", "iphunter"}))
            and is_provider_configured(key)
            and not (key == "maxmind" and not offline_dbs.has_any_local_maxmind_db())
            and not (key == "stopforumspam" and not has_any_local_stopforumspam_db())
            and not (key == "ipsum_drop" and offline_dbs._ipsum_drop_index.get_reader_and_mtime()[0] is None)
        )
        if is_expected:
            expected.add(key)
        if key in cached_providers:
            continue
        if normalized_mode == "light" and key not in LIGHT_MODE_ACTIVE_PROVIDER_KEYS and is_provider_configured(key):
            deferred.add(key)
            continue
        if spec.supports_cooldown and is_expected:
            missed_cooldown_keys.append(key)

    return frozenset(expected), frozenset(deferred), missed_cooldown_keys


def _assemble_detection_payload(
    ip: str,
    clean_results: List[Dict[str, Any]],
    ptr_hostname: Optional[str],
    *,
    hit_count: int,
    miss_count: int,
    cooldown_count: int,
    cached_at_timestamps: List[str],
    query_mode: str = "full",
    is_partial_mode: bool = False,
    bgp_prefix: Optional[str] = None,
    layer: Optional[str] = None,
    fetched_at_override: Optional[str] = None,
    should_auto_refresh: bool = False,
    refresh_in_progress: bool = False,
    degraded_refresh_fallback: bool = False,
    all_from_snapshot: bool = False,
    now_dt: Optional[datetime] = None,
) -> Dict[str, Any]:
    current_dt = now_dt or datetime.now(timezone.utc)
    aggregated = intelligence.aggregate_intelligence_metrics(
        ip,
        clean_results,
        ptr_hostname=ptr_hostname,
        bgp_prefix=bgp_prefix,
    )
    total_active = hit_count + miss_count + cooldown_count
    is_cached = all_from_snapshot or (hit_count > 0 and hit_count == total_active)
    is_partial = not all_from_snapshot and hit_count > 0 and hit_count < total_active

    effective_layer = layer or ("L1" if is_cached else "upstream")
    earliest_cached_at = min(cached_at_timestamps) if cached_at_timestamps else None
    raw_fetched = fetched_at_override or (earliest_cached_at if is_cached else current_dt.isoformat())

    if effective_layer == "upstream" and not degraded_refresh_fallback:
        resolved_fetched = raw_fetched
        age_seconds = 0
        stale_threshold = _get_stale_threshold_seconds()
        is_stale = False
    else:
        resolved_fetched, age_seconds, stale_threshold, is_stale = _compute_age_and_staleness(raw_fetched, current_dt)

    if is_cached:
        cache_status = "stale" if is_stale else "hit"
    elif is_partial:
        cache_status = "partial"
    else:
        cache_status = "miss"

    hit_providers: List[str] = []
    missed_providers: List[str] = []
    for row in clean_results:
        if not isinstance(row, dict) or is_unconfigured_provider_row(row) or row.get("isDeferred"):
            continue
        pkey = l2_cache.resolve_provider_key(row)
        if not pkey or pkey in NO_REDIS_CACHE_PROVIDER_KEYS:
            continue
        (hit_providers if (all_from_snapshot or row.get("isCached")) else missed_providers).append(pkey)
    recommend_fresh_recheck = bool(
        aggregated.get("suspectedResidentialProxy") and age_seconds > _FRESH_RECHECK_THRESHOLD_SECONDS
    )

    return {
        **aggregated,
        "fetchedAt": resolved_fetched,
        "queryMode": normalize_query_mode(query_mode),
        "isPartialMode": is_partial_mode,
        "isCached": is_cached,
        "cacheMeta": {
            "status": cache_status,
            "layer": effective_layer,
            "isPartial": is_partial,
            "hitCount": hit_count,
            "missCount": miss_count,
            "cooldownCount": cooldown_count,
            "totalSources": total_active,
            "cachedAt": earliest_cached_at
            if earliest_cached_at is not None
            else (resolved_fetched if is_cached else None),
            "fetchedAt": resolved_fetched,
            "ageSeconds": age_seconds,
            "staleThresholdSeconds": stale_threshold,
            "isStale": is_stale,
            "shouldAutoRefresh": bool(should_auto_refresh),
            "refreshInProgress": bool(refresh_in_progress),
            "degradedRefreshFallback": bool(degraded_refresh_fallback),
            "recommendFreshRecheck": recommend_fresh_recheck,
            "hitProviders": hit_providers,
            "missedProviders": missed_providers,
        },
    }


async def _fetch_provider_cooldowns(active_redis: Any, missed_cooldown_keys: List[str]) -> Dict[str, Dict[str, Any]]:
    if active_redis is None or not missed_cooldown_keys:
        return {}
    raw_cooldowns = await safe_redis_mget([provider_cooldown_key(k) for k in missed_cooldown_keys])
    cooldown_entries: Dict[str, Dict[str, Any]] = {}
    for provider_key, raw_cd in zip(missed_cooldown_keys, raw_cooldowns, strict=True):
        decoded_cd = decode_cooldown_entry(raw_cd)
        if decoded_cd is not None:
            cooldown_entries[provider_key] = decoded_cd
    return cooldown_entries


async def _evaluate_quota_candidates(
    active_redis: Any,
    candidate_specs: List[ProviderSpec],
    is_ipv4: bool,
) -> Tuple[Dict[str, Dict[str, Any]], Set[str]]:
    quota_dt = datetime.now(timezone.utc)
    quota_candidates = [
        spec.key
        for spec in candidate_specs
        if (
            spec.key not in OFFLINE_PROVIDER_KEYS
            and (is_ipv4 or (spec.key not in DNSBL_PROVIDER_KEYS and spec.key not in {"shodan_internetdb", "iphunter"}))
            and is_provider_configured(spec.key)
        )
    ]
    quota_blocked_entries: Dict[str, Dict[str, Any]] = {}
    quota_consumed_keys: Set[str] = set()
    if active_redis is None or not quota_candidates:
        return quota_blocked_entries, quota_consumed_keys

    quota_results = await asyncio.gather(
        *(quota_telemetry.check_and_consume_quota(key, now_dt=quota_dt) for key in quota_candidates)
    )
    for provider_key, quota_res in zip(quota_candidates, quota_results, strict=True):
        if quota_res.allowed:
            quota_consumed_keys.add(provider_key)
            continue
        window_unit = "min" if quota_res.window == "rpm" else "day"
        cooldown_secs = 60 if quota_res.window == "rpm" else None
        quota_blocked_entries[provider_key] = {
            "statusCode": 429,
            "isQuotaGuard": True,
            "statusLabel": f"Local Quota Guard ({quota_res.used}/{quota_res.limit} req/{window_unit})",
            "reason": f"Local quota limit reached ({quota_res.used}/{quota_res.limit} req/{window_unit})",
            "window": quota_res.window,
            "used": quota_res.used,
            "limit": quota_res.limit,
            "cooldownSeconds": cooldown_secs,
        }
    return quota_blocked_entries, quota_consumed_keys


def _build_telemetry_entry(
    provider_key: str,
    row: Dict[str, Any],
    event: Optional[Dict[str, Any]],
    miss_triggered_exception: bool,
    raw_res: Any,
    quota_consumed_keys: Set[str],
) -> Optional[Dict[str, Any]]:
    if is_unconfigured_provider_row(row):
        return None
    status_code = row.get("statusCode")
    is_timeout_outcome = bool(
        (event and event.get("isTimeout"))
        or status_code == 504
        or (
            miss_triggered_exception
            and isinstance(raw_res, (httpx.TimeoutException, asyncio.TimeoutError, TimeoutError))
        )
    )
    if is_provider_result_cacheable(row):
        outcome_name: Optional[str] = "ok"
    elif is_timeout_outcome:
        outcome_name = "timeout"
    elif status_code == 429 or (event and event.get("statusCode") == 429):
        outcome_name = "429"
    elif miss_triggered_exception or (isinstance(status_code, int) and status_code >= 500):
        outcome_name = "5xx"
    else:
        return None

    should_refund_quota = bool(
        provider_key in quota_consumed_keys
        and (miss_triggered_exception or (event and event.get("isTransportError") is True))
    )
    return {
        "provider_key": provider_key,
        "outcome": outcome_name,
        "upstream_remaining": event.get("upstreamRemaining") if event else None,
        "upstream_limit": event.get("upstreamLimit") if event else None,
        "upstream_used": event.get("upstreamUsed") if event else None,
        "refund_quota": should_refund_quota,
    }


def _build_cache_or_cooldown_write(
    spec: ProviderSpec,
    ip: str,
    row: Dict[str, Any],
    event: Optional[Dict[str, Any]],
    miss_triggered_exception: bool,
    now_dt: datetime,
    now_iso: str,
    default_cooldown: int,
) -> Optional[Tuple[str, str, int]]:
    if spec.key in NO_REDIS_CACHE_PROVIDER_KEYS:
        return None
    if is_provider_result_cacheable(row):
        entry_payload: Dict[str, Any] = {"row": row, "cachedAt": now_iso, "sanitized": True}
        if spec.key == "maxmind":
            entry_payload["cityDbLoaded"] = offline_dbs.has_local_maxmind_city_db()
            mm_updated = get_maxmind_newest_mtime_iso()
            if mm_updated:
                entry_payload["dbUpdatedAt"] = mm_updated
        elif spec.key == "stopforumspam":
            entry_payload["dbVersion"] = get_stopforumspam_db_version()
        return (
            provider_cache_key(spec.key, ip),
            json.dumps(entry_payload),
            get_provider_cache_ttl(spec.key, row),
        )

    if not spec.supports_cooldown:
        return None
    status_code = row.get("statusCode")
    should_cooldown = bool(event and event.get("trigger")) or (
        miss_triggered_exception or status_code == 429 or (isinstance(status_code, int) and status_code >= 500)
    )
    if not should_cooldown:
        return None

    cd_seconds = (
        event.get("cooldownSeconds") if event and isinstance(event.get("cooldownSeconds"), int) else None
    ) or default_cooldown
    cd_status = (
        event.get("statusCode")
        if event and isinstance(event.get("statusCode"), int)
        else (status_code if isinstance(status_code, int) else 502)
    )
    cd_reason = (event.get("reason") if event else "") or str(row.get("status") or "Upstream error")
    until_iso = datetime.fromtimestamp(now_dt.timestamp() + cd_seconds, tz=timezone.utc).isoformat()
    cooldown_payload = json.dumps(
        {
            "provider": spec.label,
            "providerKey": spec.key,
            "statusCode": cd_status,
            "reason": cd_reason,
            "cooldownSeconds": cd_seconds,
            "triggeredAt": now_iso,
            "until": until_iso,
        }
    )
    return provider_cooldown_key(spec.key), cooldown_payload, cd_seconds


def _normalize_executed_row(provider_name: str, raw_res: Any) -> Tuple[Dict[str, Any], bool]:
    miss_triggered_exception = isinstance(raw_res, Exception)
    if miss_triggered_exception:
        safe_message = sanitization.sanitize_error_message(str(raw_res))
        logger.error(f"Provider {provider_name} unhandled exception: {safe_message}")
        return build_unhandled_provider_error_row(provider_name, safe_message), True
    if not isinstance(raw_res, dict):
        return build_unhandled_provider_error_row(provider_name, "Invalid provider response"), False
    row = dict(raw_res)
    # Last line of defence so upstream echoes of a key never reach the response or the cache.
    if "rawJson" in row:
        row["rawJson"] = sanitization.sanitize_payload(row["rawJson"])
    return row, False


def _resolve_ptr_outcome(
    ip: str,
    cached_ptr: Optional[Tuple[Optional[str], Optional[str]]],
    ptr_raw: Any,
    rdns_state: Dict[str, str],
    active_redis: Any,
    now_iso: str,
) -> Tuple[Optional[str], int, int, Optional[str], Optional[Tuple[str, str, int]]]:
    if cached_ptr is not None:
        ptr_hostname, ptr_cached_at = cached_ptr
        return ptr_hostname, 1, 0, ptr_cached_at, None

    if isinstance(ptr_raw, Exception):
        ptr_hostname: Optional[str] = None
        rdns_state["status"] = "error"
    elif isinstance(ptr_raw, str):
        ptr_hostname = ptr_raw
    else:
        ptr_hostname = None

    ptr_status = rdns_state.get("status", "ok")
    write_entry: Optional[Tuple[str, str, int]] = None
    if active_redis is not None and ptr_status in ("ok", "nxdomain"):
        ptr_entry = json.dumps({"hostname": ptr_hostname, "status": ptr_status, "cachedAt": now_iso})
        write_entry = (provider_cache_key("ptr", ip), ptr_entry, get_provider_cache_ttl("ptr"))
    return ptr_hostname, 0, 1, None, write_entry


def _has_transient_upstream_failures(
    clean_results: List[Dict[str, Any]],
    *,
    cooldown_count: int,
    cached_ptr: Optional[Tuple[Optional[str], Optional[str]]],
    rdns_state: Dict[str, str],
) -> bool:
    if cooldown_count > 0:
        return True
    if cached_ptr is None and rdns_state.get("status", "ok") not in ("ok", "nxdomain"):
        return True
    for row in clean_results:
        if not isinstance(row, dict):
            continue
        if is_unconfigured_provider_row(row) or row.get("isDeferred"):
            continue
        if not is_provider_result_cacheable(row):
            return True
    return False


async def _try_read_l1_snapshot(ip: str, normalized_mode: str) -> Optional[Dict[str, Any]]:
    if normalized_mode == "light":
        full_snap = await get_cached_ip_snapshot(ip, mode="full")
        if full_snap is not None:
            return full_snap
        return await get_cached_ip_snapshot(ip, mode="light")
    return await get_cached_ip_snapshot(ip, mode="full")


async def _rehydrate_snapshot_payload(
    ip: str,
    snapshot: Dict[str, Any],
    *,
    layer: str,
    normalized_mode: str,
    force_rehydrate_offline: bool,
    allow_auto_refresh: bool = True,
    force_should_auto_refresh: Optional[bool] = None,
    force_refresh_in_progress: bool = False,
    degraded_refresh_fallback: bool = False,
    backfill_l1: bool = False,
    record_provider_hits: bool = True,
) -> Dict[str, Any]:
    await _ensure_offline_caches_warm()
    now_dt = datetime.now(timezone.utc)

    spec_by_key = _get_spec_by_key()
    rows_by_key: Dict[str, Dict[str, Any]] = {}
    for item in snapshot.get("results") or ():
        if isinstance(item, dict):
            pkey = l2_cache.resolve_provider_key(item)
            if pkey:
                rows_by_key[pkey] = dict(item)

    if "tor_onionoo" not in rows_by_key and "isTor" in snapshot:
        is_tor = bool(snapshot.get("isTor"))
        tor_is_exit = bool(snapshot.get("torIsExit"))
        raw_flags = snapshot.get("torFlags")
        tor_label = snapshot.get("torLabel") or (("Tor Exit" if tor_is_exit else "Tor Node") if is_tor else None)
        rows_by_key["tor_onionoo"] = {
            "provider": "Tor Onionoo",
            "status": "200 OK",
            "statusCode": 200,
            "asn": "-",
            "isp": "Tor Network" if is_tor else "-",
            "organisation": "Tor Network" if is_tor else "-",
            "location": "-",
            "usageType": str(snapshot.get("torSummary") or ("Tor Node" if is_tor else "Not a Tor Node")),
            "securityFlags": [{"label": str(tor_label), "isHighRisk": True}]
            if is_tor
            else [{"label": "No Flags", "isHighRisk": False}],
            "isTor": is_tor,
            "torIsExit": tor_is_exit,
            "torRunning": bool(snapshot.get("torRunning", is_tor)),
            "torFlags": [str(f) for f in raw_flags if f] if isinstance(raw_flags, list) else [],
            "torLabel": tor_label,
            "torSummary": snapshot.get("torSummary"),
        }

    to_rehydrate = [
        offline_key
        for offline_key in OFFLINE_REHYDRATE_PROVIDERS
        if offline_key in spec_by_key
        and (
            force_rehydrate_offline
            or offline_key in NO_REDIS_CACHE_PROVIDER_KEYS
            or rows_by_key.get(offline_key) is None
            or rows_by_key[offline_key].get("_rehydrate_sig") != _current_offline_provider_signature(offline_key)
        )
    ]
    if to_rehydrate:
        rehydrated_results = await asyncio.gather(*(spec_by_key[k].invoke(None, ip) for k in to_rehydrate))
        for pkey, fresh_row in zip(to_rehydrate, rehydrated_results, strict=True):
            if isinstance(fresh_row, dict):
                rows_by_key[pkey] = {
                    **fresh_row,
                    "_rehydrate_sig": _current_offline_provider_signature(pkey),
                }

    merged_rows = [
        {**rows_by_key[spec.key], "isCached": spec.key not in NO_REDIS_CACHE_PROVIDER_KEYS}
        for spec in PROVIDER_SPECS
        if spec.key in rows_by_key
    ]

    active_row_count = sum(1 for r in merged_rows if not is_unconfigured_provider_row(r) and not r.get("isDeferred"))
    ptr_resolved = snapshot.get("_ptrResolved", True) is not False
    hit_count = active_row_count + (1 if ptr_resolved else 0)

    raw_fetched_at = snapshot.get("fetchedAt")
    if not (isinstance(raw_fetched_at, str) and raw_fetched_at.strip()):
        snap_meta = snapshot.get("cacheMeta")
        raw_fetched_at = snap_meta.get("fetchedAt") if isinstance(snap_meta, dict) else None
    preserved_fetched_at, age_seconds, _, is_stale = _compute_age_and_staleness(raw_fetched_at, now_dt)

    effective_force_auto_refresh = False if not allow_auto_refresh else force_should_auto_refresh
    refresh_in_progress = bool(force_refresh_in_progress)
    if effective_force_auto_refresh is not None:
        should_auto_refresh = bool(effective_force_auto_refresh)
    elif degraded_refresh_fallback or refresh_in_progress or not is_stale:
        should_auto_refresh = False
    elif await is_ip_updating_locked(ip):
        should_auto_refresh, refresh_in_progress = False, True
    elif await is_swr_backed_off(ip) or await quota_telemetry.should_suppress_auto_refresh_for_quota(
        age_seconds, now_dt=now_dt
    ):
        should_auto_refresh = False
    else:
        should_auto_refresh = True

    ptr_hostname = snapshot.get("ptrHostname") if isinstance(snapshot.get("ptrHostname"), str) else None
    bgp_prefix = snapshot.get("bgpPrefix") if isinstance(snapshot.get("bgpPrefix"), str) else None
    snapshot_mode = normalize_query_mode(snapshot.get("queryMode") or normalized_mode, default=normalized_mode)
    is_partial_mode = bool(snapshot.get("isPartialMode")) if snapshot_mode == "light" else False

    payload = _assemble_detection_payload(
        ip,
        merged_rows,
        ptr_hostname,
        hit_count=hit_count,
        miss_count=0,
        cooldown_count=0,
        cached_at_timestamps=[preserved_fetched_at],
        query_mode=normalized_mode if snapshot_mode == "light" else "full",
        is_partial_mode=is_partial_mode,
        bgp_prefix=bgp_prefix,
        layer=layer,
        fetched_at_override=preserved_fetched_at,
        should_auto_refresh=should_auto_refresh,
        refresh_in_progress=refresh_in_progress,
        degraded_refresh_fallback=degraded_refresh_fallback,
        all_from_snapshot=True,
        now_dt=now_dt,
    )

    bg_ops = []
    if backfill_l1:
        l1_target_mode = "light" if snapshot_mode == "light" else "full"
        backfill_doc = {
            **payload,
            "fetchedAt": preserved_fetched_at,
            "results": _stamp_offline_signatures(merged_rows),
            "_ptrResolved": ptr_resolved,
        }
        bg_ops.append(set_cached_ip_snapshot(ip, backfill_doc, mode=l1_target_mode))

    if record_provider_hits and get_redis_client() is not None:
        hit_keys = payload["cacheMeta"].get("hitProviders") or []
        if hit_keys:
            bg_ops.append(
                quota_telemetry.record_provider_outcomes_batch(
                    [{"provider_key": pkey, "outcome": "cache_hit"} for pkey in hit_keys],
                    now_dt=now_dt,
                )
            )
    if bg_ops:
        await asyncio.gather(*bg_ops)

    return payload


def _resolve_cache_layer_telemetry_event(cache_meta: Dict[str, Any]) -> Optional[str]:
    layer = cache_meta.get("layer")
    if layer == "L1":
        return "l1_hit"
    if layer == "L2":
        return "l2_hit_stale_swr" if cache_meta.get("isStale") else "l2_hit_fresh"
    if layer == "upstream":
        return "upstream_miss"
    return None
