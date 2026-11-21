"""
Upstream detection orchestration, singleflight coalescing, bounded batch execution,
and staged cache-backed intelligence gathering.
"""

import asyncio
import concurrent.futures
import contextlib
import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Set, Tuple

import httpx

from . import (
    cache_backends,
    cidr_attribution,
    dns_providers,
    http_client,
    intelligence,
    l2_cache,
    offline_dbs,
    quota_telemetry,
    rangeblock_service,
    sanitization,
)
from .cache_backends import (
    acquire_ip_updating_lock,
    decode_cached_provider_entry,
    decode_cached_ptr_entry,
    decode_cooldown_entry,
    get_cached_ip_snapshot,
    get_cached_ip_snapshots_bulk,
    get_cooldown_bounds,
    get_provider_cache_ttl,
    get_redis_client,
    has_local_maxmind_city_db,
    is_ip_updating_locked,
    is_refresh_on_cooldown,
    is_swr_backed_off,
    provider_cache_key,
    provider_cooldown_key,
    release_ip_updating_lock,
    safe_redis_mget,
    safe_redis_set_many,
    set_cached_ip_snapshot,
    set_refresh_cooldown,
    set_swr_backoff,
    should_refresh_cached_maxmind_entry,
    should_refresh_cached_stopforumspam_entry,
)
from .dns_providers import (
    provider_upstream_events,
    rdns_context_state,
    reverse_ipv4_octets,
)
from .intelligence import (
    attach_request_diagnostics,
    build_non_public_response_payload,
    classify_non_public_ip,
    normalize_query_mode,
    parse_compact_flag,
    strip_raw_json_from_payload,
)
from .offline_dbs import (
    get_maxmind_newest_mtime_iso,
    get_openasn_mtime_iso,
    get_positive_int_setting,
    get_stopforumspam_db_version,
    has_any_local_stopforumspam_db,
    lookup_bgp_tools_offline,
)
from .provider_registry import (
    DNSBL_PROVIDER_KEYS,
    LIGHT_MODE_ACTIVE_PROVIDER_KEYS,
    NO_REDIS_CACHE_PROVIDER_KEYS,
    OFFLINE_PROVIDER_KEYS,
    OFFLINE_REHYDRATE_PROVIDERS,
)
from .providers import (
    PROVIDER_SPECS,
    ProviderSpec,
    build_cooldown_provider_row,
    build_deferred_provider_row,
    build_unhandled_provider_error_row,
    is_provider_result_cacheable,
    is_unconfigured_provider_row,
)
from .quota_telemetry import is_provider_configured

logger = logging.getLogger("detector.views")

_BATCH_DETECT_CONCURRENCY = 6
_LOCK_POLL_INTERVAL_SECONDS = 0.25
_LOCK_POLL_MAX_WAIT_SECONDS = 8.0
_FRESH_RECHECK_THRESHOLD_SECONDS = 7 * 86400
_DEFAULT_SWR_STALE_DAYS = 90
_DEFAULT_REFRESH_COOLDOWN_SECONDS = 60
_DEFAULT_SWR_BACKOFF_SECONDS = 1800
_ip_detect_inflight: Dict[Tuple[str, str], asyncio.Task] = {}
_ip_detect_inflight_lock = threading.Lock()


async def _safe_l2_aget_snapshot(ip: str, *, mode: str) -> Optional[Dict[str, Any]]:
    try:
        return await l2_cache.aget_ip_snapshot(ip, mode=mode)
    except AssertionError as exc:
        if type(exc).__name__ == "DatabaseOperationForbidden":
            return None
        raise


async def _safe_l2_aget_snapshots_bulk(ips: List[str], *, mode: str) -> Dict[str, Dict[str, Any]]:
    try:
        return await l2_cache.aget_ip_snapshots_bulk(ips, mode=mode)
    except AssertionError as exc:
        if type(exc).__name__ == "DatabaseOperationForbidden":
            return {}
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


def _parse_iso_utc(raw_iso: Optional[str]) -> Optional[datetime]:
    if not isinstance(raw_iso, str) or not raw_iso.strip():
        return None
    cleaned = raw_iso.strip()
    if cleaned.endswith("Z"):
        cleaned = f"{cleaned[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _compute_age_and_staleness(
    fetched_at_iso: Optional[str],
    now_dt: datetime,
) -> Tuple[str, int, int, bool]:
    stale_threshold = _get_stale_threshold_seconds()
    parsed_fetched = _parse_iso_utc(fetched_at_iso)
    if parsed_fetched is None:
        return now_dt.isoformat(), 0, stale_threshold, False
    age_seconds = max(0, int((now_dt - parsed_fetched).total_seconds()))
    return fetched_at_iso or now_dt.isoformat(), age_seconds, stale_threshold, age_seconds > stale_threshold


def _current_offline_provider_signature(provider_key: str) -> str:
    if provider_key == "maxmind":
        return f"{get_maxmind_newest_mtime_iso() or 'none'}|{int(has_local_maxmind_city_db())}"
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


def _is_provider_cache_expected(provider_key: str, is_ipv4: bool) -> bool:
    """Returns False for sources that never write a cache entry for this address family or configuration."""
    if provider_key in NO_REDIS_CACHE_PROVIDER_KEYS:
        return False
    if not is_ipv4 and (provider_key in DNSBL_PROVIDER_KEYS or provider_key in {"shodan_internetdb", "iphunter"}):
        return False
    if not is_provider_configured(provider_key):
        return False
    # Offline databases answer Database Missing or Offline DB Missing uncached when local files are absent.
    if provider_key == "maxmind" and not cache_backends._has_any_local_maxmind_db():
        return False
    if provider_key == "stopforumspam" and not has_any_local_stopforumspam_db():
        return False
    return not (provider_key == "ipsum_drop" and offline_dbs._ipsum_drop_index.get_reader_and_mtime()[0] is None)


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
        is_expected = _is_provider_cache_expected(key, is_ipv4)
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


def _extract_hit_and_missed_providers(
    clean_results: List[Dict[str, Any]],
    *,
    all_from_snapshot: bool = False,
) -> Tuple[List[str], List[str]]:
    hit_providers: List[str] = []
    missed_providers: List[str] = []
    for row in clean_results:
        if not isinstance(row, dict) or is_unconfigured_provider_row(row) or row.get("isDeferred"):
            continue
        pkey = l2_cache.resolve_provider_key(row)
        if not pkey or pkey in NO_REDIS_CACHE_PROVIDER_KEYS:
            continue
        if all_from_snapshot or row.get("isCached"):
            hit_providers.append(pkey)
        else:
            missed_providers.append(pkey)
    return hit_providers, missed_providers


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

    hit_providers, missed_providers = _extract_hit_and_missed_providers(
        clean_results,
        all_from_snapshot=all_from_snapshot,
    )
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


async def _dispatch_upstream_queries(
    ip: str,
    specs_to_execute: List[ProviderSpec],
    *,
    needs_http_client: bool,
    needs_ptr: bool,
    needs_cymru_bgp: bool = False,
) -> Tuple[Dict[str, Any], Any, Optional[str], Dict[str, Dict[str, Any]], Dict[str, str]]:
    """Concurrently executes uncached provider queries, optional PTR and BGP lookups, and rule warmup."""
    upstream_events: Dict[str, Dict[str, Any]] = {}
    events_token = provider_upstream_events.set(upstream_events)
    rdns_state: Dict[str, str] = {"status": "ok"}
    rdns_token = rdns_context_state.set(rdns_state)
    executed_provider_results: Dict[str, Any] = {}
    ptr_raw: Any = None
    cymru_bgp_prefix: Optional[str] = None
    maxmind_will_run = any(spec.key == "maxmind" for spec in specs_to_execute)

    try:
        client = await http_client.get_shared_http_client() if needs_http_client else None
        coroutines: List[Any] = [spec.invoke(client, ip) for spec in specs_to_execute]
        ptr_index: Optional[int] = None
        if needs_ptr:
            ptr_index = len(coroutines)
            coroutines.append(dns_providers.query_rdns_ptr(ip))
        cymru_index: Optional[int] = None
        if needs_cymru_bgp:
            cymru_index = len(coroutines)
            coroutines.append(dns_providers.query_cymru_bgp_prefix(ip))
        if not maxmind_will_run and not cidr_attribution.are_offline_intelligence_caches_warm():
            coroutines.append(_ensure_offline_caches_warm())
        if coroutines:
            gathered = await asyncio.gather(*coroutines, return_exceptions=True)
            for pos, spec in enumerate(specs_to_execute):
                executed_provider_results[spec.key] = gathered[pos]
            if ptr_index is not None:
                ptr_raw = gathered[ptr_index]
            if cymru_index is not None and isinstance(gathered[cymru_index], dict):
                raw_bgp = gathered[cymru_index].get("bgpPrefix")
                if isinstance(raw_bgp, str) and raw_bgp.strip():
                    cymru_bgp_prefix = raw_bgp.strip()
    finally:
        rdns_context_state.reset(rdns_token)
        provider_upstream_events.reset(events_token)

    return executed_provider_results, ptr_raw, cymru_bgp_prefix, upstream_events, rdns_state


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
            entry_payload["cityDbLoaded"] = has_local_maxmind_city_db()
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


def _collect_detection_outcomes(
    ip: str,
    *,
    active_redis: Any,
    cached_providers: Dict[str, Tuple[Dict[str, Any], Optional[str]]],
    deferred_provider_keys: FrozenSet[str],
    cooldown_entries: Dict[str, Dict[str, Any]],
    quota_blocked_entries: Dict[str, Dict[str, Any]],
    executed_provider_results: Dict[str, Any],
    upstream_events: Dict[str, Dict[str, Any]],
    quota_consumed_keys: Set[str],
    now_dt: datetime,
    now_iso: str,
) -> Tuple[List[Dict[str, Any]], List[Tuple[str, str, int]], List[Dict[str, Any]], int, int, int, List[str]]:
    clean_results: List[Dict[str, Any]] = []
    redis_set_entries: List[Tuple[str, str, int]] = []
    telemetry_entries: List[Dict[str, Any]] = []
    cached_at_timestamps: List[str] = []
    default_cooldown, _, _ = get_cooldown_bounds()
    hit_count = miss_count = cooldown_count = 0

    for spec in PROVIDER_SPECS:
        provider_key = spec.key
        provider_name = spec.label
        if provider_key in cached_providers:
            row, cached_at = cached_providers[provider_key]
            row_copy = {**row, "isCached": True}
            if cached_at:
                row_copy["cachedAt"] = cached_at
            clean_results.append(row_copy)
            if not is_unconfigured_provider_row(row_copy):
                hit_count += 1
                if cached_at:
                    cached_at_timestamps.append(cached_at)
                if active_redis is not None:
                    telemetry_entries.append({"provider_key": provider_key, "outcome": "cache_hit"})
            continue

        if provider_key in deferred_provider_keys:
            clean_results.append(build_deferred_provider_row(provider_name))
            continue

        if provider_key in cooldown_entries or provider_key in quota_blocked_entries:
            cd_info = cooldown_entries.get(provider_key) or quota_blocked_entries[provider_key]
            clean_results.append(build_cooldown_provider_row(provider_name, cd_info))
            cooldown_count += 1
            continue

        raw_res = executed_provider_results.get(provider_key)
        row, miss_triggered_exception = _normalize_executed_row(provider_name, raw_res)
        clean_results.append(row)
        if not is_unconfigured_provider_row(row) and provider_key not in NO_REDIS_CACHE_PROVIDER_KEYS:
            miss_count += 1

        if active_redis is None:
            continue
        event = upstream_events.get(provider_key)
        tel_entry = _build_telemetry_entry(
            provider_key, row, event, miss_triggered_exception, raw_res, quota_consumed_keys
        )
        if tel_entry is not None:
            telemetry_entries.append(tel_entry)
        write_entry = _build_cache_or_cooldown_write(
            spec, ip, row, event, miss_triggered_exception, now_dt, now_iso, default_cooldown
        )
        if write_entry is not None:
            redis_set_entries.append(write_entry)

    return (
        clean_results,
        redis_set_entries,
        telemetry_entries,
        hit_count,
        miss_count,
        cooldown_count,
        cached_at_timestamps,
    )


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


async def _execute_detection_with_cache(
    ip: str,
    *,
    initial_cache: Optional[
        Tuple[Dict[str, Tuple[Dict[str, Any], Optional[str]]], Optional[Tuple[Optional[str], Optional[str]]]]
    ] = None,
    query_mode: str = "full",
    persist_snapshots: bool = True,
) -> Dict[str, Any]:
    """Runs cache read, concurrent upstream acquisition, quota settlement, and dual-layer write-back."""
    normalized_mode = normalize_query_mode(query_mode)
    cached_providers, cached_ptr = initial_cache if initial_cache is not None else await _read_provider_caches(ip)

    is_ipv4 = reverse_ipv4_octets(ip) is not None
    cache_expected_keys, deferred_provider_keys, missed_cooldown_keys = _plan_provider_execution(
        cached_providers, normalized_mode, is_ipv4
    )

    active_redis = get_redis_client()
    cooldown_entries = await _fetch_provider_cooldowns(active_redis, missed_cooldown_keys)
    candidate_specs = [
        spec
        for spec in PROVIDER_SPECS
        if spec.key not in cached_providers
        and spec.key not in deferred_provider_keys
        and spec.key not in cooldown_entries
    ]
    quota_blocked_entries, quota_consumed_keys = await _evaluate_quota_candidates(
        active_redis, candidate_specs, is_ipv4
    )
    specs_to_execute = [spec for spec in candidate_specs if spec.key not in quota_blocked_entries]
    needs_ptr = cached_ptr is None
    needs_cymru_bgp = needs_ptr and lookup_bgp_tools_offline(ip) is None
    (
        executed_provider_results,
        ptr_raw,
        cymru_bgp_prefix,
        upstream_events,
        rdns_state,
    ) = await _dispatch_upstream_queries(
        ip,
        specs_to_execute,
        needs_http_client=any(spec.uses_http_client and spec.key in cache_expected_keys for spec in specs_to_execute),
        needs_ptr=needs_ptr,
        needs_cymru_bgp=needs_cymru_bgp,
    )

    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    clean_results, redis_set_entries, telemetry_entries, hit_count, miss_count, cooldown_count, cached_at_timestamps = (
        _collect_detection_outcomes(
            ip,
            active_redis=active_redis,
            cached_providers=cached_providers,
            deferred_provider_keys=deferred_provider_keys,
            cooldown_entries=cooldown_entries,
            quota_blocked_entries=quota_blocked_entries,
            executed_provider_results=executed_provider_results,
            upstream_events=upstream_events,
            quota_consumed_keys=quota_consumed_keys,
            now_dt=now_dt,
            now_iso=now_iso,
        )
    )

    ptr_hostname, ptr_hit, ptr_miss, ptr_cached_at, ptr_write = _resolve_ptr_outcome(
        ip, cached_ptr, ptr_raw, rdns_state, active_redis, now_iso
    )
    hit_count += ptr_hit
    miss_count += ptr_miss
    if ptr_cached_at:
        cached_at_timestamps.append(ptr_cached_at)
    if ptr_write is not None:
        redis_set_entries.append(ptr_write)

    redis_write_ops = []
    if redis_set_entries:
        redis_write_ops.append(safe_redis_set_many(redis_set_entries))
    if active_redis is not None and telemetry_entries:
        redis_write_ops.append(quota_telemetry.record_provider_outcomes_batch(telemetry_entries, now_dt=now_dt))
    if redis_write_ops:
        await asyncio.gather(*redis_write_ops)

    await _ensure_offline_caches_warm()

    all_cached_l1 = miss_count == 0 and cooldown_count == 0 and hit_count > 0
    assembled = _assemble_detection_payload(
        ip,
        clean_results,
        ptr_hostname,
        hit_count=hit_count,
        miss_count=miss_count,
        cooldown_count=cooldown_count,
        cached_at_timestamps=cached_at_timestamps,
        query_mode=normalized_mode,
        is_partial_mode=bool(deferred_provider_keys),
        bgp_prefix=cymru_bgp_prefix,
        layer="L1" if all_cached_l1 else "upstream",
        now_dt=now_dt,
    )

    has_transient_failure = _has_transient_upstream_failures(
        clean_results,
        cooldown_count=cooldown_count,
        cached_ptr=cached_ptr,
        rdns_state=rdns_state,
    )
    if persist_snapshots and not all_cached_l1 and not deferred_provider_keys and not has_transient_failure:
        snapshot_for_storage = {
            **assembled,
            "fetchedAt": now_iso,
            "results": _stamp_offline_signatures(clean_results),
            "_ptrResolved": True,
        }
        await asyncio.gather(
            set_cached_ip_snapshot(ip, snapshot_for_storage, mode="full"),
            _safe_l2_amerge_snapshot(
                ip,
                {**assembled, "fetchedAt": now_iso, "results": clean_results},
                query_mode="full",
                now_dt=now_dt,
            ),
        )
    elif not persist_snapshots:
        assembled["_rawCleanResults"] = clean_results
        assembled["_hasTransientFailure"] = has_transient_failure

    return assembled


def _release_inflight_task(inflight_key: Tuple[str, str], task: Optional[asyncio.Task]) -> None:
    if task is None:
        return
    with _ip_detect_inflight_lock:
        if _ip_detect_inflight.get(inflight_key) is task:
            _ip_detect_inflight.pop(inflight_key, None)


class _StaleInflightLoopError(Exception):
    """Raised when the event loop owning an in-flight detection task closes mid-wait."""


async def _await_inflight_task(
    inflight_task: asyncio.Task,
    current_loop: asyncio.AbstractEventLoop,
) -> Dict[str, Any]:
    task_loop = inflight_task.get_loop()
    if task_loop is current_loop:
        return await asyncio.shield(inflight_task)

    if task_loop.is_closed():
        if inflight_task.done() and not inflight_task.cancelled():
            return inflight_task.result()
        raise _StaleInflightLoopError("Inflight owner event loop closed")

    if inflight_task.done():
        if inflight_task.cancelled():
            raise _StaleInflightLoopError("Inflight task was cancelled on another loop")
        return inflight_task.result()

    bridge_future: concurrent.futures.Future = concurrent.futures.Future()

    def _resolve_bridge(done_task: asyncio.Task) -> None:
        if bridge_future.done():
            return
        if done_task.cancelled():
            bridge_future.set_exception(_StaleInflightLoopError("Inflight task was cancelled on another loop"))
            return
        exc = done_task.exception()
        if exc is not None:
            bridge_future.set_exception(exc)
        else:
            bridge_future.set_result(done_task.result())

    def _attach_on_owner_loop() -> None:
        if inflight_task.done():
            _resolve_bridge(inflight_task)
        else:
            inflight_task.add_done_callback(_resolve_bridge)

    try:
        task_loop.call_soon_threadsafe(_attach_on_owner_loop)
    except RuntimeError as exc:
        if inflight_task.done() and not inflight_task.cancelled():
            return inflight_task.result()
        raise _StaleInflightLoopError("Inflight owner event loop closed before callback attachment") from exc

    return await asyncio.shield(asyncio.wrap_future(bridge_future))


async def _try_read_l1_snapshot(ip: str, normalized_mode: str) -> Optional[Dict[str, Any]]:
    if normalized_mode == "light":
        full_snap = await get_cached_ip_snapshot(ip, mode="full")
        if full_snap is not None:
            return full_snap
        return await get_cached_ip_snapshot(ip, mode="light")
    return await get_cached_ip_snapshot(ip, mode="full")


def _synthesise_tor_row_if_missing(
    rows_by_key: Dict[str, Dict[str, Any]],
    snapshot: Dict[str, Any],
) -> None:
    if "tor_onionoo" in rows_by_key or "isTor" not in snapshot:
        return
    is_tor = bool(snapshot.get("isTor"))
    tor_is_exit = bool(snapshot.get("torIsExit"))
    tor_running = bool(snapshot.get("torRunning", is_tor))
    raw_flags = snapshot.get("torFlags")
    tor_flags = [str(f) for f in raw_flags if f] if isinstance(raw_flags, list) else []
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
        "torRunning": tor_running,
        "torFlags": tor_flags,
        "torLabel": tor_label,
        "torSummary": snapshot.get("torSummary"),
    }


async def _build_rehydrated_rows(
    ip: str,
    snapshot: Dict[str, Any],
    *,
    force_rehydrate_offline: bool,
) -> List[Dict[str, Any]]:
    spec_by_key = _get_spec_by_key()
    rows_by_key: Dict[str, Dict[str, Any]] = {}
    for item in snapshot.get("results") or ():
        if isinstance(item, dict):
            pkey = l2_cache.resolve_provider_key(item)
            if pkey:
                rows_by_key[pkey] = dict(item)

    _synthesise_tor_row_if_missing(rows_by_key, snapshot)

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

    return [
        {**rows_by_key[spec.key], "isCached": spec.key not in NO_REDIS_CACHE_PROVIDER_KEYS}
        for spec in PROVIDER_SPECS
        if spec.key in rows_by_key
    ]


async def _resolve_swr_refresh_flags(
    ip: str,
    *,
    age_seconds: int,
    is_stale: bool,
    force_should_auto_refresh: Optional[bool],
    force_refresh_in_progress: bool,
    degraded_refresh_fallback: bool,
    now_dt: datetime,
) -> Tuple[bool, bool]:
    refresh_in_progress = bool(force_refresh_in_progress)
    if force_should_auto_refresh is not None:
        return bool(force_should_auto_refresh), refresh_in_progress
    if degraded_refresh_fallback or refresh_in_progress or not is_stale:
        return False, refresh_in_progress
    if await is_ip_updating_locked(ip):
        return False, True
    if await is_swr_backed_off(ip) or await quota_telemetry.should_suppress_auto_refresh_for_quota(
        age_seconds, now_dt=now_dt
    ):
        return False, refresh_in_progress
    return True, refresh_in_progress


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
    merged_rows = await _build_rehydrated_rows(
        ip,
        snapshot,
        force_rehydrate_offline=force_rehydrate_offline,
    )

    active_row_count = sum(1 for r in merged_rows if not is_unconfigured_provider_row(r) and not r.get("isDeferred"))
    ptr_resolved = snapshot.get("_ptrResolved", True) is not False
    hit_count = active_row_count + (1 if ptr_resolved else 0)

    raw_fetched_at = snapshot.get("fetchedAt")
    if not (isinstance(raw_fetched_at, str) and raw_fetched_at.strip()):
        snap_meta = snapshot.get("cacheMeta")
        raw_fetched_at = snap_meta.get("fetchedAt") if isinstance(snap_meta, dict) else None
    preserved_fetched_at, age_seconds, _, is_stale = _compute_age_and_staleness(raw_fetched_at, now_dt)

    effective_force_auto_refresh = False if not allow_auto_refresh else force_should_auto_refresh
    should_auto_refresh, refresh_in_progress = await _resolve_swr_refresh_flags(
        ip,
        age_seconds=age_seconds,
        is_stale=is_stale,
        force_should_auto_refresh=effective_force_auto_refresh,
        force_refresh_in_progress=force_refresh_in_progress,
        degraded_refresh_fallback=degraded_refresh_fallback,
        now_dt=now_dt,
    )

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


async def _poll_for_concurrent_snapshot(
    ip: str,
    normalized_mode: str,
) -> Optional[Dict[str, Any]]:
    max_attempts = max(1, int(_LOCK_POLL_MAX_WAIT_SECONDS / _LOCK_POLL_INTERVAL_SECONDS))
    for _ in range(max_attempts):
        await asyncio.sleep(_LOCK_POLL_INTERVAL_SECONDS)
        l1_snap = await _try_read_l1_snapshot(ip, normalized_mode)
        if l1_snap is not None:
            return await _rehydrate_snapshot_payload(
                ip,
                l1_snap,
                layer="L1",
                normalized_mode=normalized_mode,
                force_rehydrate_offline=False,
            )
        if not await is_ip_updating_locked(ip):
            l1_after = await _try_read_l1_snapshot(ip, normalized_mode)
            if l1_after is not None:
                return await _rehydrate_snapshot_payload(
                    ip,
                    l1_after,
                    layer="L1",
                    normalized_mode=normalized_mode,
                    force_rehydrate_offline=False,
                )
            l2_after = await _safe_l2_aget_snapshot(ip, mode=normalized_mode)
            if l2_after is not None:
                return await _rehydrate_snapshot_payload(
                    ip,
                    l2_after,
                    layer="L2",
                    normalized_mode=normalized_mode,
                    force_rehydrate_offline=True,
                    backfill_l1=True,
                )
            break
    return None


def _all_expected_providers_cached(
    ip: str,
    normalized_mode: str,
    cached_providers: Dict[str, Tuple[Dict[str, Any], Optional[str]]],
    cached_ptr: Optional[Tuple[Optional[str], Optional[str]]],
) -> bool:
    if cached_ptr is None:
        return False
    is_ipv4 = reverse_ipv4_octets(ip) is not None
    expected_keys, deferred_keys, _ = _plan_provider_execution(cached_providers, normalized_mode, is_ipv4)
    required_keys = expected_keys - deferred_keys
    return required_keys.issubset(cached_providers.keys())


async def _execute_l1_l2_or_upstream(
    target_ip: str,
    target_mode: str,
    *,
    skip_prefetched_snapshots: bool = False,
) -> Dict[str, Any]:
    if not skip_prefetched_snapshots:
        l1_snap = await _try_read_l1_snapshot(target_ip, target_mode)
        if l1_snap is not None:
            return await _rehydrate_snapshot_payload(
                target_ip,
                l1_snap,
                layer="L1",
                normalized_mode=target_mode,
                force_rehydrate_offline=False,
            )

        l2_snap = await _safe_l2_aget_snapshot(target_ip, mode=target_mode)
        if l2_snap is not None:
            return await _rehydrate_snapshot_payload(
                target_ip,
                l2_snap,
                layer="L2",
                normalized_mode=target_mode,
                force_rehydrate_offline=True,
                backfill_l1=True,
            )

    cached_providers, cached_ptr = await _read_provider_caches(target_ip)
    if _all_expected_providers_cached(target_ip, target_mode, cached_providers, cached_ptr):
        return await _execute_detection_with_cache(
            target_ip,
            initial_cache=(cached_providers, cached_ptr),
            query_mode=target_mode,
        )

    lock_token = await acquire_ip_updating_lock(target_ip)
    if lock_token is None and await is_ip_updating_locked(target_ip):
        polled = await _poll_for_concurrent_snapshot(
            target_ip,
            target_mode,
        )
        if polled is not None:
            return polled

    try:
        return await _execute_detection_with_cache(
            target_ip,
            initial_cache=(cached_providers, cached_ptr),
            query_mode=target_mode,
        )
    finally:
        if lock_token is not None:
            await release_ip_updating_lock(target_ip, lock_token)


def _resolve_cache_layer_telemetry_event(cache_meta: Dict[str, Any]) -> Optional[str]:
    layer = cache_meta.get("layer")
    if layer == "L1":
        return "l1_hit"
    if layer == "L2":
        return "l2_hit_stale_swr" if cache_meta.get("isStale") else "l2_hit_fresh"
    if layer == "upstream":
        return "upstream_miss"
    return None


async def detect_single_canonical_ip(
    ip: str,
    auth_mode: str,
    start_time: float,
    *,
    compact: bool = False,
    query_mode: str = "full",
    skip_prefetched_snapshots: bool = False,
    wiki: Optional[str] = None,
    skip_rangeblock: bool = False,
) -> Dict[str, Any]:
    """Runs singleflight-coalesced dual-layer intelligence detection for one canonical IP address."""
    normalized_mode = normalize_query_mode(query_mode)
    non_public = classify_non_public_ip(ip)
    if non_public is not None:
        payload = build_non_public_response_payload(
            ip, non_public[0], non_public[1], start_time, query_mode=normalized_mode
        )
        if not skip_rangeblock:
            payload["rangeblock"] = rangeblock_service.build_empty_rangeblock_summary(ip)
        return payload

    current_loop = asyncio.get_running_loop()
    inflight_key = (ip, normalized_mode)

    # Register the shared task before any await so concurrent callers never duplicate cache reads or queries.
    with _ip_detect_inflight_lock:
        existing_task = _ip_detect_inflight.get(inflight_key)
        if existing_task is not None:
            try:
                existing_loop = existing_task.get_loop()
            except AttributeError, RuntimeError:
                existing_loop = None
            if existing_loop is None or existing_loop.is_closed() or existing_task.done():
                _ip_detect_inflight.pop(inflight_key, None)
                existing_task = None

        if existing_task is not None:
            inflight_task = existing_task
        else:

            async def _run_coalesced_detection(
                target_ip: str = ip,
                target_mode: str = normalized_mode,
            ) -> Dict[str, Any]:
                own_task = asyncio.current_task()
                try:
                    return await _execute_l1_l2_or_upstream(
                        target_ip,
                        target_mode,
                        skip_prefetched_snapshots=skip_prefetched_snapshots,
                    )
                finally:
                    _release_inflight_task((target_ip, target_mode), own_task)

            created_task = current_loop.create_task(_run_coalesced_detection(target_ip=ip, target_mode=normalized_mode))

            def _finalize_inflight(done_task: asyncio.Task, task_key: Tuple[str, str] = inflight_key) -> None:
                _release_inflight_task(task_key, done_task)
                if not done_task.cancelled():
                    done_task.exception()

            created_task.add_done_callback(_finalize_inflight)
            _ip_detect_inflight[inflight_key] = created_task
            inflight_task = created_task

    rb_task = (
        None if skip_rangeblock else asyncio.create_task(rangeblock_service.query_rangeblocks_for_ip(ip, wiki=wiki))
    )
    try:
        shared_payload = await _await_inflight_task(inflight_task, current_loop)
    except _StaleInflightLoopError:
        _release_inflight_task(inflight_key, inflight_task)
        shared_payload = await _execute_l1_l2_or_upstream(
            ip,
            normalized_mode,
            skip_prefetched_snapshots=skip_prefetched_snapshots,
        )

    rb_summary = await rb_task if rb_task is not None else None

    base_payload = shared_payload
    cache_meta = base_payload.get("cacheMeta") or {}
    cache_status = cache_meta.get("status")
    if isinstance(cache_status, str) and cache_status in ("hit", "stale", "partial", "miss"):
        await quota_telemetry.record_global_request_telemetry(
            cache_status,
            auth_mode,
            cache_layer_event=_resolve_cache_layer_telemetry_event(cache_meta),
        )

    response_payload = strip_raw_json_from_payload(base_payload) if compact else dict(base_payload)
    if rb_summary is not None:
        response_payload["rangeblock"] = rb_summary
    return attach_request_diagnostics(response_payload, start_time)


_detect_single_canonical_ip = detect_single_canonical_ip


def _merge_retained_historical_rows(
    raw_clean_results: List[Dict[str, Any]],
    stored_snapshot: Optional[Dict[str, Any]],
    retained_keys: Tuple[str, ...],
) -> List[Dict[str, Any]]:
    if not retained_keys or not isinstance(stored_snapshot, dict):
        return raw_clean_results
    retained_set = set(retained_keys)
    historical_by_key: Dict[str, Dict[str, Any]] = {}
    for item in stored_snapshot.get("results") or ():
        if isinstance(item, dict):
            pkey = l2_cache.resolve_provider_key(item)
            if pkey in retained_set:
                historical_by_key[pkey] = dict(item)
    if not historical_by_key:
        return raw_clean_results

    merged: List[Dict[str, Any]] = []
    seen_keys: Set[str] = set()
    for row in raw_clean_results:
        if not isinstance(row, dict):
            continue
        pkey = l2_cache.resolve_provider_key(row)
        if pkey:
            seen_keys.add(pkey)
        if pkey in historical_by_key:
            merged.append({**historical_by_key[pkey], "isHistoricalFallback": True})
        else:
            merged.append(row)
    for pkey, hist_row in historical_by_key.items():
        if pkey not in seen_keys:
            merged.append({**hist_row, "isHistoricalFallback": True})
    return merged


async def _try_serve_existing_snapshot_for_refresh(
    ip: str,
    normalized_mode: str,
    *,
    refresh_in_progress: bool,
) -> Optional[Dict[str, Any]]:
    l1_snap = await _try_read_l1_snapshot(ip, normalized_mode)
    if l1_snap is not None:
        return await _rehydrate_snapshot_payload(
            ip,
            l1_snap,
            layer="L1",
            normalized_mode=normalized_mode,
            force_rehydrate_offline=False,
            force_should_auto_refresh=False,
            force_refresh_in_progress=refresh_in_progress,
        )
    l2_snap = await _safe_l2_aget_snapshot(ip, mode=normalized_mode)
    if l2_snap is not None:
        return await _rehydrate_snapshot_payload(
            ip,
            l2_snap,
            layer="L2",
            normalized_mode=normalized_mode,
            force_rehydrate_offline=True,
            force_should_auto_refresh=False,
            force_refresh_in_progress=refresh_in_progress,
            backfill_l1=True,
        )
    return None


async def refresh_single_canonical_ip(
    ip: str,
    auth_mode: str,
    start_time: float,
    *,
    username: Optional[str] = None,
    is_admin: bool = False,
    compact: bool = False,
    query_mode: str = "full",
    wiki: Optional[str] = None,
) -> Tuple[Dict[str, Any], int, Dict[str, str]]:
    """
    Executes an authenticated manual or stale-while-revalidate refresh with per-IP cooldown,
    per-user and global rate limits, distributed singleflight locking, and non-degrading merge.
    """
    normalized_mode = normalize_query_mode(query_mode, default="full")
    non_public = classify_non_public_ip(ip)
    if non_public is not None:
        non_public_payload = build_non_public_response_payload(
            ip, non_public[0], non_public[1], start_time, query_mode=normalized_mode
        )
        non_public_payload["rangeblock"] = rangeblock_service.build_empty_rangeblock_summary(ip)
        return non_public_payload, 200, {}

    if await is_refresh_on_cooldown(ip):
        cooldown_cached = await _try_serve_existing_snapshot_for_refresh(
            ip,
            normalized_mode,
            refresh_in_progress=False,
        )
        if cooldown_cached is not None:
            cache_meta = cooldown_cached.get("cacheMeta") or {}
            await quota_telemetry.record_global_request_telemetry(
                str(cache_meta.get("status") or "hit"),
                auth_mode,
                cache_layer_event=_resolve_cache_layer_telemetry_event(cache_meta),
            )
            out_payload = strip_raw_json_from_payload(cooldown_cached) if compact else cooldown_cached
            return attach_request_diagnostics(out_payload, start_time), 200, {}

    rl_res = await quota_telemetry.check_and_consume_refresh_rate_limit(username, is_admin=is_admin)
    if not rl_res.allowed:
        return (
            {
                "error": "rate_limited",
                "reason": rl_res.reason,
                "message": "Refresh rate limit exceeded. Please wait before retrying.",
                "retryAfterSeconds": rl_res.retry_after_seconds,
            },
            429,
            {"Retry-After": str(rl_res.retry_after_seconds)},
        )

    lock_token = await acquire_ip_updating_lock(ip)
    if lock_token is None and await is_ip_updating_locked(ip):
        in_progress_cached = await _try_serve_existing_snapshot_for_refresh(
            ip,
            normalized_mode,
            refresh_in_progress=True,
        )
        if in_progress_cached is not None:
            out_payload = strip_raw_json_from_payload(in_progress_cached) if compact else in_progress_cached
            return attach_request_diagnostics(out_payload, start_time), 200, {}
        polled = await _poll_for_concurrent_snapshot(ip, normalized_mode)
        if polled is not None:
            out_payload = strip_raw_json_from_payload(polled) if compact else polled
            return attach_request_diagnostics(out_payload, start_time), 200, {}

    try:
        prior_l1 = await _try_read_l1_snapshot(ip, normalized_mode)
        fresh_assembled = await _execute_detection_with_cache(
            ip,
            initial_cache=({}, None),
            query_mode=normalized_mode,
            persist_snapshots=False,
        )
        raw_clean_results = fresh_assembled.pop("_rawCleanResults", fresh_assembled.get("results", []))
        fresh_assembled.pop("_hasTransientFailure", False)

        now_dt = datetime.now(timezone.utc)
        merge_res = await _safe_l2_amerge_snapshot(
            ip,
            {**fresh_assembled, "results": raw_clean_results},
            query_mode=normalized_mode,
            now_dt=now_dt,
        )

        if merge_res.degraded_fallback:
            await set_swr_backoff(ip, ttl_seconds=_DEFAULT_SWR_BACKOFF_SECONDS)
            fallback_source = merge_res.snapshot if merge_res.snapshot is not None else prior_l1
            if fallback_source is not None:
                fallback_layer = "L2" if merge_res.snapshot is not None else "L1"
                preserved_payload = await _rehydrate_snapshot_payload(
                    ip,
                    fallback_source,
                    layer=fallback_layer,
                    normalized_mode=normalized_mode,
                    force_rehydrate_offline=True,
                    force_should_auto_refresh=False,
                    degraded_refresh_fallback=True,
                    backfill_l1=merge_res.snapshot is not None,
                    record_provider_hits=False,
                )
                out_payload = strip_raw_json_from_payload(preserved_payload) if compact else preserved_payload
                return attach_request_diagnostics(out_payload, start_time), 200, {}

            fresh_meta = dict(fresh_assembled.get("cacheMeta") or {})
            fresh_meta["degradedRefreshFallback"] = True
            fresh_meta["shouldAutoRefresh"] = False
            degraded_payload = {**fresh_assembled, "cacheMeta": fresh_meta}
            out_payload = strip_raw_json_from_payload(degraded_payload) if compact else degraded_payload
            return attach_request_diagnostics(out_payload, start_time), 200, {}

        merged_rows = _merge_retained_historical_rows(
            raw_clean_results,
            merge_res.snapshot,
            merge_res.retained_historical_providers,
        )
        resolved_fetched_at = merge_res.fetched_at or now_dt.isoformat()
        resolved_ptr = fresh_assembled.get("ptrHostname")
        if resolved_ptr is None and isinstance(merge_res.snapshot, dict):
            prior_ptr = merge_res.snapshot.get("ptrHostname")
            if isinstance(prior_ptr, str) and prior_ptr:
                resolved_ptr = prior_ptr

        active_count = sum(
            1
            for r in merged_rows
            if isinstance(r, dict) and not is_unconfigured_provider_row(r) and not r.get("isDeferred")
        )
        final_payload = _assemble_detection_payload(
            ip,
            merged_rows,
            resolved_ptr,
            hit_count=0,
            miss_count=active_count + 1,
            cooldown_count=0,
            cached_at_timestamps=[],
            query_mode=normalized_mode,
            is_partial_mode=bool(fresh_assembled.get("isPartialMode")),
            bgp_prefix=fresh_assembled.get("bgpPrefix"),
            layer="upstream",
            fetched_at_override=resolved_fetched_at,
            should_auto_refresh=False,
            now_dt=now_dt,
        )

        if not final_payload.get("isPartialMode"):
            l1_doc = {
                **final_payload,
                "fetchedAt": resolved_fetched_at,
                "results": _stamp_offline_signatures(merged_rows),
                "_ptrResolved": True,
            }
            await set_cached_ip_snapshot(ip, l1_doc, mode="full")

        await asyncio.gather(
            set_refresh_cooldown(ip, ttl_seconds=_DEFAULT_REFRESH_COOLDOWN_SECONDS),
            quota_telemetry.record_global_request_telemetry(
                "miss",
                auth_mode,
                cache_layer_event="refresh_ok",
                now_dt=now_dt,
            ),
        )
        out_payload = strip_raw_json_from_payload(final_payload) if compact else dict(final_payload)
        out_payload["rangeblock"] = await rangeblock_service.query_rangeblocks_for_ip(ip, wiki=wiki)
        return attach_request_diagnostics(out_payload, start_time), 200, {}
    finally:
        if lock_token is not None:
            await release_ip_updating_lock(ip, lock_token)


async def _prefetch_batch_l1_snapshots(
    public_ips: List[str],
    normalized_mode: str,
) -> Dict[str, Dict[str, Any]]:
    if not public_ips:
        return {}
    if normalized_mode == "light":
        full_hits = await get_cached_ip_snapshots_bulk(public_ips, mode="full")
        remaining = [ip for ip in public_ips if ip not in full_hits]
        if not remaining:
            return full_hits
        light_hits = await get_cached_ip_snapshots_bulk(remaining, mode="light")
        return {**light_hits, **full_hits}
    return await get_cached_ip_snapshots_bulk(public_ips, mode="full")


async def detect_canonical_ip_batch(
    unique_canonical_ips: List[str],
    *,
    auth_mode: str,
    compact: bool = False,
    query_mode: str = "light",
    wiki: Optional[str] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Executes bounded-concurrency intelligence detection across up to 25 unique canonical IPs
    using a single Redis MGET and a single ToolsDB WHERE IN bulk query upfront.
    """
    normalized_mode = normalize_query_mode(query_mode, default="light")
    public_ips = [ip for ip in unique_canonical_ips if classify_non_public_ip(ip) is None]

    l1_hits, rangeblock_by_ip = await asyncio.gather(
        _prefetch_batch_l1_snapshots(public_ips, normalized_mode),
        rangeblock_service.query_rangeblocks_for_ips(public_ips, wiki=wiki),
    )
    l1_miss_ips = [ip for ip in public_ips if ip not in l1_hits]
    l2_hits = await _safe_l2_aget_snapshots_bulk(l1_miss_ips, mode=normalized_mode) if l1_miss_ips else {}

    semaphore = asyncio.Semaphore(_BATCH_DETECT_CONCURRENCY)

    async def _detect_bounded(canonical_ip: str) -> Tuple[str, Dict[str, Any]]:
        async with semaphore:
            ip_start_time = time.perf_counter()
            if canonical_ip in l1_hits:
                rehydrated = await _rehydrate_snapshot_payload(
                    canonical_ip,
                    l1_hits[canonical_ip],
                    layer="L1",
                    normalized_mode=normalized_mode,
                    force_rehydrate_offline=False,
                    allow_auto_refresh=False,
                )
                await quota_telemetry.record_global_request_telemetry(
                    str(rehydrated["cacheMeta"].get("status") or "hit"),
                    auth_mode,
                    cache_layer_event="l1_hit",
                )
                payload = strip_raw_json_from_payload(rehydrated) if compact else rehydrated
                payload = attach_request_diagnostics(payload, ip_start_time)
            elif canonical_ip in l2_hits:
                rehydrated = await _rehydrate_snapshot_payload(
                    canonical_ip,
                    l2_hits[canonical_ip],
                    layer="L2",
                    normalized_mode=normalized_mode,
                    force_rehydrate_offline=True,
                    allow_auto_refresh=False,
                    backfill_l1=True,
                )
                layer_event = "l2_hit_stale_swr" if rehydrated["cacheMeta"].get("isStale") else "l2_hit_fresh"
                await quota_telemetry.record_global_request_telemetry(
                    str(rehydrated["cacheMeta"].get("status") or "hit"),
                    auth_mode,
                    cache_layer_event=layer_event,
                )
                payload = strip_raw_json_from_payload(rehydrated) if compact else rehydrated
                payload = attach_request_diagnostics(payload, ip_start_time)
            else:
                payload = await detect_single_canonical_ip(
                    canonical_ip,
                    auth_mode,
                    ip_start_time,
                    compact=compact,
                    query_mode=normalized_mode,
                    skip_prefetched_snapshots=True,
                    wiki=wiki,
                    skip_rangeblock=True,
                )

            rb_summary = rangeblock_by_ip.get(canonical_ip) or rangeblock_service.build_empty_rangeblock_summary(
                canonical_ip
            )
            payload = {**payload, "rangeblock": rb_summary}
            if isinstance(payload.get("cacheMeta"), dict):
                payload = {**payload, "cacheMeta": {**payload["cacheMeta"], "shouldAutoRefresh": False}}
            return canonical_ip, payload

    pairs = await asyncio.gather(*(_detect_bounded(ip) for ip in unique_canonical_ips))
    return dict(pairs)


def _format_sse_event(event_name: str, payload: Dict[str, Any]) -> bytes:
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return f"event: {event_name}\ndata: {encoded}\n\n".encode("utf-8")


def _extract_overview_fields(assembled: Dict[str, Any]) -> Dict[str, Any]:
    overview_keys = (
        "ip",
        "is_broadcast_ip",
        "isTor",
        "torIsExit",
        "torRunning",
        "torFlags",
        "torLabel",
        "torSummary",
        "prediction_score",
        "predictionLabel",
        "predictionTier",
        "getipintel_chance",
        "residentialProxy",
        "highlySuspectedResidentialProxy",
        "arbitrationVerdict",
        "arbitrationTier",
        "isMajorityProxyVpn",
        "suspectedResidentialProxy",
        "primaryCountry",
        "primaryAsn",
        "ptrHostname",
        "ptrCategory",
        "ptrLabel",
        "ptrIsHighRisk",
        "recommendedCidr",
        "defaultCidr",
        "mmdbCidr",
        "sharedCidr",
        "sharedProvider",
        "sharedCategory",
        "cidrNote",
        "bgpPrefix",
        "escalationCidr",
        "cidrRationale",
        "isMobileOrCgnat",
        "sharedPrivacyEgress",
        "openProxyPorts",
    )
    return {k: assembled[k] for k in overview_keys if k in assembled}


def _order_provider_rows(rows_by_key: Mapping[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [rows_by_key[spec.key] for spec in PROVIDER_SPECS if spec.key in rows_by_key]


async def _run_isolated_stream_task(
    task_kind: str,
    spec: Optional[ProviderSpec],
    client: Optional[httpx.AsyncClient],
    ip: str,
) -> Tuple[str, Optional[ProviderSpec], Any, Dict[str, Dict[str, Any]], Dict[str, str]]:
    """Executes one stream upstream query with isolated ContextVars for events and rDNS state."""
    upstream_events: Dict[str, Dict[str, Any]] = {}
    events_token = provider_upstream_events.set(upstream_events)
    rdns_state: Dict[str, str] = {"status": "ok"}
    rdns_token = rdns_context_state.set(rdns_state)
    try:
        if task_kind == "provider" and spec is not None:
            result = await spec.invoke(client, ip)
            return task_kind, spec, result, upstream_events, rdns_state
        if task_kind == "ptr":
            result = await dns_providers.query_rdns_ptr(ip)
            return task_kind, None, result, upstream_events, rdns_state
        result = await dns_providers.query_cymru_bgp_prefix(ip)
        return task_kind, None, result, upstream_events, rdns_state
    except Exception as exc:  # noqa: BLE001
        return task_kind, spec, exc, upstream_events, rdns_state
    finally:
        rdns_context_state.reset(rdns_token)
        provider_upstream_events.reset(events_token)


async def _persist_stream_provider_outcome(
    spec: ProviderSpec,
    ip: str,
    row: Dict[str, Any],
    event: Optional[Dict[str, Any]],
    miss_triggered_exception: bool,
    raw_res: Any,
    quota_consumed_keys: Set[str],
    active_redis: Any,
    now_dt: datetime,
    now_iso: str,
    default_cooldown: int,
) -> None:
    if active_redis is None:
        return
    ops = []
    write_entry = _build_cache_or_cooldown_write(
        spec, ip, row, event, miss_triggered_exception, now_dt, now_iso, default_cooldown
    )
    if write_entry is not None:
        ops.append(safe_redis_set_many([write_entry]))
    tel_entry = _build_telemetry_entry(spec.key, row, event, miss_triggered_exception, raw_res, quota_consumed_keys)
    if tel_entry is not None:
        ops.append(quota_telemetry.record_provider_outcomes_batch([tel_entry], now_dt=now_dt))
    if ops:
        await asyncio.gather(*ops)


async def _run_immediate_offline_sources(
    ip: str,
    cached_providers: Dict[str, Tuple[Dict[str, Any], Optional[str]]],
    deferred_keys: FrozenSet[str],
) -> Dict[str, Dict[str, Any]]:
    """Executes uncached offline databases and offline Tor Onionoo immediately for the first SSE frame."""
    await _ensure_offline_caches_warm()
    spec_by_key = _get_spec_by_key()
    offline_keys = [
        spec.key
        for spec in PROVIDER_SPECS
        if spec.key in OFFLINE_PROVIDER_KEYS and spec.key not in cached_providers and spec.key not in deferred_keys
    ]
    coros = [spec_by_key[k].invoke(None, ip) for k in offline_keys]
    out: Dict[str, Dict[str, Any]] = {}
    if coros:
        results = await asyncio.gather(*coros, return_exceptions=True)
        for pkey, raw_res in zip(offline_keys, results, strict=True):
            row, _ = _normalize_executed_row(spec_by_key[pkey].label, raw_res)
            out[pkey] = row

    if "tor_onionoo" not in cached_providers and "tor_onionoo" not in deferred_keys:
        offline_tor = offline_dbs.lookup_tor_onionoo_offline(ip)
        if isinstance(offline_tor, dict):
            from .adapters import adapt_tor_onionoo

            out["tor_onionoo"] = adapt_tor_onionoo(offline_tor, status_code=200, ip=ip)
    return out


async def _emit_cached_or_non_public_sse(
    ip: str,
    auth_mode: str,
    start_time: float,
    *,
    compact: bool,
    normalized_mode: str,
    wiki: Optional[str],
):
    non_public = classify_non_public_ip(ip)
    if non_public is not None:
        payload = build_non_public_response_payload(
            ip, non_public[0], non_public[1], start_time, query_mode=normalized_mode
        )
        payload["rangeblock"] = rangeblock_service.build_empty_rangeblock_summary(ip)
        payload["pendingProviders"] = []
        yield _format_sse_event("snapshot", payload)
        yield _format_sse_event(
            "done",
            attach_request_diagnostics(
                {
                    "ip": ip,
                    "isCached": False,
                    "fetchedAt": payload.get("fetchedAt"),
                    "cacheMeta": payload.get("cacheMeta"),
                },
                start_time,
            ),
        )
        return

    l1_task = asyncio.create_task(_try_read_l1_snapshot(ip, normalized_mode))
    rb_task = asyncio.create_task(rangeblock_service.query_rangeblocks_for_ip(ip, wiki=wiki))
    l1_snap = await l1_task
    snapshot = l1_snap
    layer = "L1"
    force_offline = False
    backfill_l1 = False
    if snapshot is None:
        snapshot = await _safe_l2_aget_snapshot(ip, mode=normalized_mode)
        layer = "L2"
        force_offline = True
        backfill_l1 = True

    if snapshot is None:
        rb_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await rb_task
        return

    rehydrated, rb_summary = await asyncio.gather(
        _rehydrate_snapshot_payload(
            ip,
            snapshot,
            layer=layer,
            normalized_mode=normalized_mode,
            force_rehydrate_offline=force_offline,
            backfill_l1=backfill_l1,
        ),
        rb_task,
    )
    cache_meta = rehydrated.get("cacheMeta") or {}
    cache_status = cache_meta.get("status")
    if isinstance(cache_status, str) and cache_status in ("hit", "stale", "partial", "miss"):
        await quota_telemetry.record_global_request_telemetry(
            cache_status,
            auth_mode,
            cache_layer_event=_resolve_cache_layer_telemetry_event(cache_meta),
        )

    out_payload = strip_raw_json_from_payload(rehydrated) if compact else dict(rehydrated)
    out_payload["rangeblock"] = rb_summary
    out_payload["pendingProviders"] = []
    out_payload = attach_request_diagnostics(out_payload, start_time)
    yield _format_sse_event("snapshot", out_payload)
    yield _format_sse_event(
        "done",
        attach_request_diagnostics(
            {
                "ip": ip,
                "isCached": out_payload.get("isCached", False),
                "fetchedAt": out_payload.get("fetchedAt"),
                "cacheMeta": out_payload.get("cacheMeta"),
            },
            start_time,
        ),
    )


def _build_initial_stream_state(
    ip: str,
    *,
    cached_providers: Dict[str, Tuple[Dict[str, Any], Optional[str]]],
    deferred_provider_keys: FrozenSet[str],
    cooldown_entries: Dict[str, Dict[str, Any]],
    quota_blocked_entries: Dict[str, Dict[str, Any]],
    immediate_offline: Dict[str, Dict[str, Any]],
    active_redis: Any,
    now_dt: datetime,
    now_iso: str,
) -> Tuple[Dict[str, Dict[str, Any]], List[str], int, int, int, List[Tuple[str, str, int]]]:
    rows_by_key: Dict[str, Dict[str, Any]] = {}
    cached_at_timestamps: List[str] = []
    hit_count = cooldown_count = miss_count = 0
    default_cooldown, _, _ = get_cooldown_bounds()
    offline_writes: List[Tuple[str, str, int]] = []

    for spec in PROVIDER_SPECS:
        key = spec.key
        if key in cached_providers:
            row, cached_at = cached_providers[key]
            row_copy = {**row, "isCached": True}
            if cached_at:
                row_copy["cachedAt"] = cached_at
                cached_at_timestamps.append(cached_at)
            rows_by_key[key] = row_copy
            if not is_unconfigured_provider_row(row_copy):
                hit_count += 1
        elif key in deferred_provider_keys:
            rows_by_key[key] = build_deferred_provider_row(spec.label)
        elif key in cooldown_entries or key in quota_blocked_entries:
            cd_info = cooldown_entries.get(key) or quota_blocked_entries[key]
            rows_by_key[key] = build_cooldown_provider_row(spec.label, cd_info)
            cooldown_count += 1
        elif key in immediate_offline:
            row = immediate_offline[key]
            rows_by_key[key] = row
            if not is_unconfigured_provider_row(row) and key not in NO_REDIS_CACHE_PROVIDER_KEYS:
                miss_count += 1
            if active_redis is not None:
                w = _build_cache_or_cooldown_write(spec, ip, row, None, False, now_dt, now_iso, default_cooldown)
                if w is not None:
                    offline_writes.append(w)

    return rows_by_key, cached_at_timestamps, hit_count, miss_count, cooldown_count, offline_writes


async def _finalise_stream_detection(
    ip: str,
    auth_mode: str,
    start_time: float,
    *,
    rows_by_key: Dict[str, Dict[str, Any]],
    ptr_hostname: Optional[str],
    hit_count: int,
    miss_count: int,
    cooldown_count: int,
    cached_at_timestamps: List[str],
    normalized_mode: str,
    deferred_provider_keys: FrozenSet[str],
    cymru_bgp_prefix: Optional[str],
    cached_ptr: Optional[Tuple[Optional[str], Optional[str]]],
    rdns_state: Dict[str, str],
    now_dt: datetime,
    now_iso: str,
) -> bytes:
    final_rows = _order_provider_rows(rows_by_key)
    all_cached_l1 = miss_count == 0 and cooldown_count == 0 and hit_count > 0
    final_payload = _assemble_detection_payload(
        ip,
        final_rows,
        ptr_hostname,
        hit_count=hit_count,
        miss_count=miss_count,
        cooldown_count=cooldown_count,
        cached_at_timestamps=cached_at_timestamps,
        query_mode=normalized_mode,
        is_partial_mode=bool(deferred_provider_keys),
        bgp_prefix=cymru_bgp_prefix,
        layer="L1" if all_cached_l1 else "upstream",
        now_dt=now_dt,
    )
    has_transient = _has_transient_upstream_failures(
        final_rows,
        cooldown_count=cooldown_count,
        cached_ptr=cached_ptr,
        rdns_state=rdns_state,
    )
    if not all_cached_l1 and not deferred_provider_keys and not has_transient:
        snapshot_doc = {
            **final_payload,
            "fetchedAt": now_iso,
            "results": _stamp_offline_signatures(final_rows),
            "_ptrResolved": True,
        }
        await asyncio.gather(
            set_cached_ip_snapshot(ip, snapshot_doc, mode="full"),
            _safe_l2_amerge_snapshot(
                ip,
                {**final_payload, "fetchedAt": now_iso, "results": final_rows},
                query_mode="full",
                now_dt=now_dt,
            ),
        )

    cache_meta = final_payload.get("cacheMeta") or {}
    cache_status = cache_meta.get("status")
    if isinstance(cache_status, str) and cache_status in ("hit", "stale", "partial", "miss"):
        await quota_telemetry.record_global_request_telemetry(
            cache_status,
            auth_mode,
            cache_layer_event=_resolve_cache_layer_telemetry_event(cache_meta),
        )

    done_body = attach_request_diagnostics(
        {
            "ip": ip,
            "isCached": final_payload.get("isCached", False),
            "fetchedAt": final_payload.get("fetchedAt"),
            "cacheMeta": final_payload.get("cacheMeta"),
            "pendingProviders": [],
            **_extract_overview_fields(final_payload),
        },
        start_time,
    )
    return _format_sse_event("done", done_body)


def _create_stream_tasks(
    ip: str,
    specs_to_execute: List[ProviderSpec],
    client: Optional[httpx.AsyncClient],
    cached_ptr: Optional[Tuple[Optional[str], Optional[str]]],
    cymru_bgp_prefix: Optional[str],
) -> List[asyncio.Task[Any]]:
    tasks = [asyncio.create_task(_run_isolated_stream_task("provider", spec, client, ip)) for spec in specs_to_execute]
    if cached_ptr is None:
        tasks.append(asyncio.create_task(_run_isolated_stream_task("ptr", None, None, ip)))
        if cymru_bgp_prefix is None:
            tasks.append(asyncio.create_task(_run_isolated_stream_task("bgp", None, None, ip)))
    return tasks


async def _consume_stream_tasks(
    ip: str,
    *,
    tasks: List[asyncio.Task[Any]],
    pending_set: List[str],
    rows_by_key: Dict[str, Dict[str, Any]],
    stream_ctx: Dict[str, Any],
    hit_count: int,
    cooldown_count: int,
    cached_at_timestamps: List[str],
    normalized_mode: str,
    deferred_provider_keys: FrozenSet[str],
    quota_consumed_keys: Set[str],
    active_redis: Any,
    now_dt: datetime,
    now_iso: str,
    default_cooldown: int,
    compact: bool,
):
    for completed in asyncio.as_completed(tasks):
        task_kind, spec, raw_res, task_events, task_rdns = await completed
        if task_kind == "ptr":
            ptr_hostname, _, ptr_miss, _, ptr_write = _resolve_ptr_outcome(
                ip, None, raw_res, task_rdns, active_redis, now_iso
            )
            stream_ctx["ptr_hostname"] = ptr_hostname
            stream_ctx["rdns_state"] = task_rdns
            stream_ctx["miss_count"] += ptr_miss
            if ptr_write is not None:
                await safe_redis_set_many([ptr_write])
            continue
        if task_kind == "bgp":
            if isinstance(raw_res, dict) and isinstance(raw_res.get("bgpPrefix"), str):
                cleaned_bgp = raw_res["bgpPrefix"].strip()
                if cleaned_bgp:
                    stream_ctx["cymru_bgp_prefix"] = cleaned_bgp
            continue
        if spec is None:
            continue

        row, miss_exc = _normalize_executed_row(spec.label, raw_res)
        rows_by_key[spec.key] = row
        if not is_unconfigured_provider_row(row) and spec.key not in NO_REDIS_CACHE_PROVIDER_KEYS:
            stream_ctx["miss_count"] += 1
        if spec.label in pending_set:
            pending_set.remove(spec.label)

        await _persist_stream_provider_outcome(
            spec,
            ip,
            row,
            task_events.get(spec.key),
            miss_exc,
            raw_res,
            quota_consumed_keys,
            active_redis,
            now_dt,
            now_iso,
            default_cooldown,
        )
        updated_payload = _assemble_detection_payload(
            ip,
            _order_provider_rows(rows_by_key),
            stream_ctx["ptr_hostname"],
            hit_count=hit_count,
            miss_count=stream_ctx["miss_count"],
            cooldown_count=cooldown_count,
            cached_at_timestamps=cached_at_timestamps,
            query_mode=normalized_mode,
            is_partial_mode=bool(deferred_provider_keys),
            bgp_prefix=stream_ctx["cymru_bgp_prefix"],
            layer="upstream",
            now_dt=now_dt,
        )
        out_row = {k: v for k, v in row.items() if k != "rawJson"} if compact else row
        yield _format_sse_event(
            "provider",
            {
                "provider": spec.label,
                "providerKey": spec.key,
                "row": out_row,
                "pendingProviders": list(pending_set),
                **_extract_overview_fields(updated_payload),
            },
        )


async def stream_single_canonical_ip_sse(
    ip: str,
    auth_mode: str,
    start_time: float,
    *,
    compact: bool = False,
    query_mode: str = "full",
    wiki: Optional[str] = None,
):
    """Streams snapshot, per-provider incremental updates, and done SSE frames for one IP."""
    normalized_mode = normalize_query_mode(query_mode)
    emitted_fast = False
    async for chunk in _emit_cached_or_non_public_sse(
        ip,
        auth_mode,
        start_time,
        compact=compact,
        normalized_mode=normalized_mode,
        wiki=wiki,
    ):
        emitted_fast = True
        yield chunk
    if emitted_fast:
        return

    is_ipv4 = reverse_ipv4_octets(ip) is not None
    (cached_providers, cached_ptr), rb_summary = await asyncio.gather(
        _read_provider_caches(ip),
        rangeblock_service.query_rangeblocks_for_ip(ip, wiki=wiki),
    )

    cache_expected_keys, deferred_provider_keys, missed_cooldown_keys = _plan_provider_execution(
        cached_providers, normalized_mode, is_ipv4
    )
    active_redis = get_redis_client()
    cooldown_entries, immediate_offline = await asyncio.gather(
        _fetch_provider_cooldowns(active_redis, missed_cooldown_keys),
        _run_immediate_offline_sources(ip, cached_providers, deferred_provider_keys),
    )

    candidate_specs = [
        spec
        for spec in PROVIDER_SPECS
        if spec.key not in cached_providers
        and spec.key not in deferred_provider_keys
        and spec.key not in cooldown_entries
        and spec.key not in immediate_offline
    ]
    quota_blocked_entries, quota_consumed_keys = await _evaluate_quota_candidates(
        active_redis, candidate_specs, is_ipv4
    )
    specs_to_execute = [spec for spec in candidate_specs if spec.key not in quota_blocked_entries]

    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    default_cooldown, _, _ = get_cooldown_bounds()
    rows_by_key, cached_at_timestamps, hit_count, miss_count, cooldown_count, offline_writes = (
        _build_initial_stream_state(
            ip,
            cached_providers=cached_providers,
            deferred_provider_keys=deferred_provider_keys,
            cooldown_entries=cooldown_entries,
            quota_blocked_entries=quota_blocked_entries,
            immediate_offline=immediate_offline,
            active_redis=active_redis,
            now_dt=now_dt,
            now_iso=now_iso,
        )
    )
    if offline_writes:
        await safe_redis_set_many(offline_writes)

    ptr_hostname: Optional[str] = cached_ptr[0] if cached_ptr is not None else None
    if cached_ptr is not None:
        hit_count += 1
        if cached_ptr[1]:
            cached_at_timestamps.append(cached_ptr[1])
    cymru_bgp_prefix: Optional[str] = lookup_bgp_tools_offline(ip)
    rdns_state: Dict[str, str] = {"status": "ok"}

    pending_labels = [spec.label for spec in specs_to_execute]
    initial_payload = _assemble_detection_payload(
        ip,
        _order_provider_rows(rows_by_key),
        ptr_hostname,
        hit_count=hit_count,
        miss_count=miss_count,
        cooldown_count=cooldown_count,
        cached_at_timestamps=cached_at_timestamps,
        query_mode=normalized_mode,
        is_partial_mode=bool(deferred_provider_keys),
        bgp_prefix=cymru_bgp_prefix,
        layer="L1"
        if (not specs_to_execute and miss_count == 0 and cooldown_count == 0 and hit_count > 0)
        else "upstream",
        now_dt=now_dt,
    )
    initial_payload = strip_raw_json_from_payload(initial_payload) if compact else initial_payload
    initial_payload["rangeblock"] = rb_summary
    initial_payload["pendingProviders"] = pending_labels
    yield _format_sse_event("snapshot", attach_request_diagnostics(initial_payload, start_time))

    lock_token = await acquire_ip_updating_lock(ip) if specs_to_execute else None
    tasks: List[asyncio.Task[Any]] = []
    try:
        needs_http = any(spec.uses_http_client and spec.key in cache_expected_keys for spec in specs_to_execute)
        client = await http_client.get_shared_http_client() if needs_http else None
        tasks = _create_stream_tasks(ip, specs_to_execute, client, cached_ptr, cymru_bgp_prefix)

        stream_ctx: Dict[str, Any] = {
            "ptr_hostname": ptr_hostname,
            "cymru_bgp_prefix": cymru_bgp_prefix,
            "rdns_state": rdns_state,
            "miss_count": miss_count,
        }
        async for chunk in _consume_stream_tasks(
            ip,
            tasks=tasks,
            pending_set=list(pending_labels),
            rows_by_key=rows_by_key,
            stream_ctx=stream_ctx,
            hit_count=hit_count,
            cooldown_count=cooldown_count,
            cached_at_timestamps=cached_at_timestamps,
            normalized_mode=normalized_mode,
            deferred_provider_keys=deferred_provider_keys,
            quota_consumed_keys=quota_consumed_keys,
            active_redis=active_redis,
            now_dt=now_dt,
            now_iso=now_iso,
            default_cooldown=default_cooldown,
            compact=compact,
        ):
            yield chunk

        yield await _finalise_stream_detection(
            ip,
            auth_mode,
            start_time,
            rows_by_key=rows_by_key,
            ptr_hostname=stream_ctx["ptr_hostname"],
            hit_count=hit_count,
            miss_count=stream_ctx["miss_count"],
            cooldown_count=cooldown_count,
            cached_at_timestamps=cached_at_timestamps,
            normalized_mode=normalized_mode,
            deferred_provider_keys=deferred_provider_keys,
            cymru_bgp_prefix=stream_ctx["cymru_bgp_prefix"],
            cached_ptr=cached_ptr,
            rdns_state=stream_ctx["rdns_state"],
            now_dt=now_dt,
            now_iso=now_iso,
        )
    except asyncio.CancelledError:
        for t in tasks:
            if not t.done():
                t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        raise
    finally:
        if lock_token is not None:
            await release_ip_updating_lock(ip, lock_token)
