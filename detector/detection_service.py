"""
Upstream detection orchestration, singleflight coalescing, bounded batch execution,
and staged cache-backed intelligence gathering.
"""

import asyncio
import concurrent.futures
import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

import httpx

from . import (
    cache_backends,
    cidr_attribution,
    dns_providers,
    http_client,
    intelligence,
    quota_telemetry,
    sanitization,
)
from .cache_backends import (
    decode_cached_provider_entry,
    decode_cached_ptr_entry,
    decode_cooldown_entry,
    get_cooldown_bounds,
    get_provider_cache_ttl,
    get_redis_client,
    has_local_maxmind_city_db,
    provider_cache_key,
    provider_cooldown_key,
    safe_redis_mget,
    safe_redis_set_many,
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
from .offline_dbs import get_maxmind_newest_mtime_iso, get_stopforumspam_db_version, has_any_local_stopforumspam_db
from .provider_registry import DNSBL_PROVIDER_KEYS, LIGHT_MODE_ACTIVE_PROVIDER_KEYS, OFFLINE_PROVIDER_KEYS
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
_ip_detect_inflight: Dict[Tuple[str, str], asyncio.Task] = {}
_ip_detect_inflight_lock = threading.Lock()


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
    if not is_ipv4 and provider_key in DNSBL_PROVIDER_KEYS:
        return False
    if not is_provider_configured(provider_key):
        return False
    # Offline databases answer Database Missing or Offline DB Missing uncached when local files are absent.
    if provider_key == "maxmind" and not cache_backends._has_any_local_maxmind_db():
        return False
    return not (provider_key == "stopforumspam" and not has_any_local_stopforumspam_db())


async def _ensure_offline_caches_warm() -> None:
    if not cidr_attribution.are_offline_intelligence_caches_warm():
        await asyncio.to_thread(cidr_attribution.warm_offline_intelligence_caches)


async def _read_provider_caches(
    ip: str,
) -> Tuple[Dict[str, Tuple[Dict[str, Any], Optional[str]]], Optional[Tuple[Optional[str], Optional[str]]]]:
    if get_redis_client() is None:
        return {}, None
    keys = [provider_cache_key(spec.key, ip) for spec in PROVIDER_SPECS]
    keys.append(provider_cache_key("ptr", ip))
    raw_values = await safe_redis_mget(keys)
    cached_providers: Dict[str, Tuple[Dict[str, Any], Optional[str]]] = {}
    for idx, spec in enumerate(PROVIDER_SPECS):
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
) -> Dict[str, Any]:
    aggregated = intelligence.aggregate_intelligence_metrics(ip, clean_results, ptr_hostname=ptr_hostname)
    total_active = hit_count + miss_count + cooldown_count
    is_cached = hit_count > 0 and hit_count == total_active
    is_partial = hit_count > 0 and hit_count < total_active
    cache_status = "hit" if is_cached else ("partial" if is_partial else "miss")
    return {
        **aggregated,
        "queryMode": normalize_query_mode(query_mode),
        "isPartialMode": is_partial_mode,
        "isCached": is_cached,
        "cacheMeta": {
            "status": cache_status,
            "isPartial": is_partial,
            "hitCount": hit_count,
            "missCount": miss_count,
            "cooldownCount": cooldown_count,
            "totalSources": total_active,
            "cachedAt": min(cached_at_timestamps) if cached_at_timestamps else None,
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
            and (is_ipv4 or spec.key not in DNSBL_PROVIDER_KEYS)
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
) -> Tuple[Dict[str, Any], Any, Dict[str, Dict[str, Any]], Dict[str, str]]:
    """Concurrently executes uncached provider queries, optional PTR lookup, and rule warmup."""
    upstream_events: Dict[str, Dict[str, Any]] = {}
    events_token = provider_upstream_events.set(upstream_events)
    rdns_state: Dict[str, str] = {"status": "ok"}
    rdns_token = rdns_context_state.set(rdns_state)
    executed_provider_results: Dict[str, Any] = {}
    ptr_raw: Any = None
    maxmind_will_run = any(spec.key == "maxmind" for spec in specs_to_execute)

    try:
        client = await http_client.get_shared_http_client() if needs_http_client else None
        coroutines: List[Any] = [spec.invoke(client, ip) for spec in specs_to_execute]
        ptr_index: Optional[int] = None
        if needs_ptr:
            ptr_index = len(coroutines)
            coroutines.append(dns_providers.query_rdns_ptr(ip))
        if not maxmind_will_run and not cidr_attribution.are_offline_intelligence_caches_warm():
            coroutines.append(_ensure_offline_caches_warm())
        if coroutines:
            gathered = await asyncio.gather(*coroutines, return_exceptions=True)
            for pos, spec in enumerate(specs_to_execute):
                executed_provider_results[spec.key] = gathered[pos]
            if ptr_index is not None:
                ptr_raw = gathered[ptr_index]
    finally:
        rdns_context_state.reset(rdns_token)
        provider_upstream_events.reset(events_token)

    return executed_provider_results, ptr_raw, upstream_events, rdns_state


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
        if not is_unconfigured_provider_row(row):
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


async def _execute_detection_with_cache(
    ip: str,
    *,
    initial_cache: Optional[
        Tuple[Dict[str, Tuple[Dict[str, Any], Optional[str]]], Optional[Tuple[Optional[str], Optional[str]]]]
    ] = None,
    query_mode: str = "full",
) -> Dict[str, Any]:
    """Runs cache read, concurrent upstream acquisition, quota settlement, and cache write-back."""
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
    executed_provider_results, ptr_raw, upstream_events, rdns_state = await _dispatch_upstream_queries(
        ip,
        specs_to_execute,
        needs_http_client=any(spec.uses_http_client and spec.key in cache_expected_keys for spec in specs_to_execute),
        needs_ptr=cached_ptr is None,
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

    return _assemble_detection_payload(
        ip,
        clean_results,
        ptr_hostname,
        hit_count=hit_count,
        miss_count=miss_count,
        cooldown_count=cooldown_count,
        cached_at_timestamps=cached_at_timestamps,
        query_mode=normalized_mode,
        is_partial_mode=bool(deferred_provider_keys),
    )


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


async def detect_single_canonical_ip(
    ip: str,
    auth_mode: str,
    start_time: float,
    *,
    compact: bool = False,
    query_mode: str = "full",
) -> Dict[str, Any]:
    """Runs singleflight-coalesced intelligence detection for one canonical IP address."""
    normalized_mode = normalize_query_mode(query_mode)
    non_public = classify_non_public_ip(ip)
    if non_public is not None:
        return build_non_public_response_payload(
            ip, non_public[0], non_public[1], start_time, query_mode=normalized_mode
        )

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
                    cached_providers, cached_ptr = await _read_provider_caches(target_ip)
                    return await _execute_detection_with_cache(
                        target_ip,
                        initial_cache=(cached_providers, cached_ptr),
                        query_mode=target_mode,
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

    try:
        base_payload = await _await_inflight_task(inflight_task, current_loop)
    except _StaleInflightLoopError:
        _release_inflight_task(inflight_key, inflight_task)
        base_payload = await _execute_detection_with_cache(ip, query_mode=normalized_mode)

    cache_status = (base_payload.get("cacheMeta") or {}).get("status")
    if isinstance(cache_status, str) and cache_status in ("hit", "partial", "miss"):
        await quota_telemetry.record_global_request_telemetry(cache_status, auth_mode)

    response_payload = strip_raw_json_from_payload(base_payload) if compact else base_payload
    return attach_request_diagnostics(response_payload, start_time)


_detect_single_canonical_ip = detect_single_canonical_ip


async def detect_canonical_ip_batch(
    unique_canonical_ips: List[str],
    *,
    auth_mode: str,
    compact: bool = False,
    query_mode: str = "light",
) -> Dict[str, Dict[str, Any]]:
    """Executes bounded-concurrency intelligence detection across unique canonical IP addresses."""
    normalized_mode = normalize_query_mode(query_mode, default="light")
    semaphore = asyncio.Semaphore(_BATCH_DETECT_CONCURRENCY)

    async def _detect_bounded(canonical_ip: str) -> Tuple[str, Dict[str, Any]]:
        async with semaphore:
            ip_start_time = time.perf_counter()
            payload = await detect_single_canonical_ip(
                canonical_ip,
                auth_mode,
                ip_start_time,
                compact=compact,
                query_mode=normalized_mode,
            )
            return canonical_ip, payload

    pairs = await asyncio.gather(*(_detect_bounded(ip) for ip in unique_canonical_ips))
    return dict(pairs)
