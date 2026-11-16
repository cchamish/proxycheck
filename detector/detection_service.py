"""
Upstream detection orchestration, shared HTTP client lifecycle, singleflight coalescing,
and staged cache-backed execution.
"""

import asyncio
import concurrent.futures
import http.cookiejar
import inspect
import json
import logging
import threading
import weakref
from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

import httpx

from .adapters import are_offline_intelligence_caches_warm, warm_offline_intelligence_caches
from .cache_backends import (
    _decode_cached_provider_entry,
    _decode_cached_ptr_entry,
    _decode_cooldown_entry,
    _get_cooldown_bounds,
    _get_provider_cache_ttl,
    _get_redis_client,
    _has_any_local_maxmind_db,
    _has_local_maxmind_city_db,
    _provider_cache_key,
    _provider_cooldown_key,
    _safe_redis_mget,
    _safe_redis_set_many,
    _should_refresh_cached_maxmind_entry,
    _should_refresh_cached_stopforumspam_entry,
    _views_attr,
)
from .dns_providers import (
    _provider_upstream_events,
    _rdns_context_state,
    _reverse_ipv4_octets,
    query_rdns_ptr,
)
from .intelligence import (
    _attach_request_diagnostics,
    _build_non_public_response_payload,
    _classify_non_public_ip,
    _normalize_query_mode,
    _strip_raw_json_from_payload,
    aggregate_intelligence_metrics,
)
from .offline_dbs import get_maxmind_newest_mtime_iso, get_stopforumspam_db_version, has_any_local_stopforumspam_db
from .providers import (
    _PROVIDER_SPECS,
    _build_cooldown_provider_row,
    _build_deferred_provider_row,
    _build_unhandled_provider_error_row,
    _is_provider_result_cacheable,
    _is_unconfigured_provider_row,
)
from .quota_telemetry import (
    check_and_consume_quota,
    is_provider_configured,
    record_global_request_telemetry,
    record_provider_outcomes_batch,
)
from .sanitization import _sanitize_error_message, _sanitize_payload

logger = logging.getLogger("detector.views")

_http_client_lock = threading.Lock()
_http_clients_by_loop: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, Any]" = weakref.WeakKeyDictionary()

_ip_detect_inflight: Dict[Tuple[str, str], asyncio.Task] = {}
_ip_detect_inflight_lock = threading.Lock()

_DNSBL_PROVIDER_KEYS = frozenset({"spamhaus_zen", "spamcop"})
_OFFLINE_PROVIDER_KEYS = frozenset({"maxmind", "stopforumspam"})
_LIGHT_MODE_ACTIVE_PROVIDERS = frozenset(
    {"maxmind", "stopforumspam", "tor_onionoo", "dshield", "spamhaus_zen", "spamcop", "cloudflare_radar"}
)


async def _strip_request_cookie_header(request: httpx.Request) -> None:
    request.headers.pop("cookie", None)


_DEFAULT_HTTP_LIMITS = httpx.Limits(max_connections=100, max_keepalive_connections=20)


async def _close_http_client_safely(client: Any) -> None:
    """Closes a superseded httpx.AsyncClient instance without propagating loop-state errors."""
    if client is None or getattr(client, "is_closed", False) is True:
        return
    aclose_fn = getattr(client, "aclose", None)
    if not callable(aclose_fn):
        return
    try:
        maybe_coro = aclose_fn()
        if inspect.isawaitable(maybe_coro):
            await maybe_coro
    except (httpx.HTTPError, RuntimeError, OSError) as exc:
        logger.debug(f"Ignoring error while closing superseded HTTP client: {exc}")


def _build_cookieless_http_client() -> httpx.AsyncClient:
    # Pass the CookieJar directly because httpx.AsyncClient copies httpx.Cookies into a new default jar.
    cookie_jar = http.cookiejar.CookieJar(
        policy=http.cookiejar.DefaultCookiePolicy(allowed_domains=[]),
    )
    return httpx.AsyncClient(
        timeout=10.0,
        limits=_DEFAULT_HTTP_LIMITS,
        cookies=cookie_jar,
        event_hooks={"request": [_strip_request_cookie_header]},
    )


async def _get_shared_http_client() -> httpx.AsyncClient:
    """
    Returns a reusable cookieless httpx.AsyncClient bound to the currently running event loop.
    Isolated per event loop so concurrent worker threads never close each other's active clients.
    """
    current_loop = asyncio.get_running_loop()
    stale_clients: List[Any] = []
    selected_client: Optional[Any] = None

    with _http_client_lock:
        closed_loops = [
            loop
            for loop in list(_http_clients_by_loop.keys())
            if loop.is_closed() or getattr(_http_clients_by_loop.get(loop), "is_closed", False) is True
        ]
        for dead_loop in closed_loops:
            dead_client = _http_clients_by_loop.pop(dead_loop, None)
            if dead_client is not None:
                stale_clients.append(dead_client)

        existing_client = _http_clients_by_loop.get(current_loop)
        if (
            existing_client is not None
            and not current_loop.is_closed()
            and getattr(existing_client, "is_closed", False) is not True
        ):
            selected_client = existing_client
        else:
            new_client = _build_cookieless_http_client()
            _http_clients_by_loop[current_loop] = new_client
            selected_client = new_client

    for stale_client in stale_clients:
        if stale_client is not selected_client:
            await _close_http_client_safely(stale_client)

    return selected_client


def _is_provider_cache_expected(provider_key: str, is_ipv4: bool) -> bool:
    """Returns False for sources that never write a cache entry for this address family or configuration."""
    if not is_ipv4 and provider_key in _DNSBL_PROVIDER_KEYS:
        return False
    if not is_provider_configured(provider_key):
        return False
    # Offline databases answer Database Missing or Offline DB Missing uncached when local files are absent
    if provider_key == "maxmind" and not _views_attr("_has_any_local_maxmind_db", _has_any_local_maxmind_db)():
        return False
    return not (provider_key == "stopforumspam" and not has_any_local_stopforumspam_db())


async def _read_provider_caches(
    ip: str,
) -> Tuple[Dict[str, Tuple[Dict[str, Any], Optional[str]]], Optional[Tuple[Optional[str], Optional[str]]]]:
    if _get_redis_client() is None:
        return {}, None
    keys = [_provider_cache_key(provider_key, ip) for provider_key, _, _, _, _ in _PROVIDER_SPECS]
    keys.append(_provider_cache_key("ptr", ip))
    raw_values = await _safe_redis_mget(keys)
    cached_providers: Dict[str, Tuple[Dict[str, Any], Optional[str]]] = {}
    for idx, (provider_key, _, _, _, _) in enumerate(_PROVIDER_SPECS):
        decoded = _decode_cached_provider_entry(raw_values[idx])
        if decoded is not None:
            if provider_key == "maxmind" and _should_refresh_cached_maxmind_entry(raw_values[idx], decoded[0]):
                continue
            if provider_key == "stopforumspam" and _should_refresh_cached_stopforumspam_entry(decoded[0]):
                continue
            cached_providers[provider_key] = decoded
    cached_ptr = _decode_cached_ptr_entry(raw_values[-1])
    return cached_providers, cached_ptr


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
    aggregate_fn = _views_attr("aggregate_intelligence_metrics", aggregate_intelligence_metrics)
    aggregated = aggregate_fn(ip, clean_results, ptr_hostname=ptr_hostname)
    total_active = hit_count + miss_count + cooldown_count
    is_cached = hit_count > 0 and hit_count == total_active
    is_partial = hit_count > 0 and hit_count < total_active
    cache_status = "hit" if is_cached else ("partial" if is_partial else "miss")
    return {
        **aggregated,
        "queryMode": _normalize_query_mode(query_mode),
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
    raw_cooldowns = await _safe_redis_mget([_provider_cooldown_key(k) for k in missed_cooldown_keys])
    cooldown_entries: Dict[str, Dict[str, Any]] = {}
    for provider_key, raw_cd in zip(missed_cooldown_keys, raw_cooldowns, strict=True):
        decoded_cd = _decode_cooldown_entry(raw_cd)
        if decoded_cd is not None:
            cooldown_entries[provider_key] = decoded_cd
    return cooldown_entries


async def _evaluate_quota_candidates(
    active_redis: Any,
    candidate_specs: List[Tuple[int, Tuple[str, str, bool, bool, Any]]],
    is_ipv4: bool,
) -> Tuple[Dict[str, Dict[str, Any]], Set[str]]:
    quota_dt = datetime.now(timezone.utc)
    quota_candidates = [
        spec[0]
        for _, spec in candidate_specs
        if (
            spec[0] not in _OFFLINE_PROVIDER_KEYS
            and (is_ipv4 or spec[0] not in _DNSBL_PROVIDER_KEYS)
            and is_provider_configured(spec[0])
        )
    ]
    quota_blocked_entries: Dict[str, Dict[str, Any]] = {}
    quota_consumed_keys: Set[str] = set()
    if active_redis is None or not quota_candidates:
        return quota_blocked_entries, quota_consumed_keys

    quota_fn = _views_attr("check_and_consume_quota", check_and_consume_quota)
    quota_results = await asyncio.gather(*(quota_fn(key, now_dt=quota_dt) for key in quota_candidates))
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
    specs_to_execute: List[Tuple[int, Tuple[str, str, bool, bool, Any]]],
    *,
    needs_http_client: bool,
    needs_ptr: bool,
    needs_rule_warmup: bool,
    maxmind_will_run: bool,
) -> Tuple[Dict[str, Any], Any, Dict[str, Dict[str, Any]], Dict[str, str]]:
    """Concurrently executes uncached provider queries, optional PTR lookup, and rule warmup."""
    upstream_events: Dict[str, Dict[str, Any]] = {}
    events_token = _provider_upstream_events.set(upstream_events)
    rdns_state: Dict[str, str] = {"status": "ok"}
    rdns_token = _rdns_context_state.set(rdns_state)
    executed_provider_results: Dict[str, Any] = {}
    ptr_raw: Any = None

    get_client_fn = _views_attr("_get_shared_http_client", _get_shared_http_client)
    rdns_fn = _views_attr("query_rdns_ptr", query_rdns_ptr)
    warmup_fn = _views_attr("warm_offline_intelligence_caches", warm_offline_intelligence_caches)

    try:
        client = await get_client_fn() if needs_http_client else None
        coroutines = [spec[4](client, ip) for _, spec in specs_to_execute]
        ptr_index: Optional[int] = None
        if needs_ptr:
            ptr_index = len(coroutines)
            coroutines.append(rdns_fn(ip))
        if needs_rule_warmup and not maxmind_will_run:
            coroutines.append(asyncio.to_thread(warmup_fn))
        if coroutines:
            gathered = await asyncio.gather(*coroutines, return_exceptions=True)
            for pos, (_, (provider_key, _, _, _, _)) in enumerate(specs_to_execute):
                executed_provider_results[provider_key] = gathered[pos]
            if ptr_index is not None:
                ptr_raw = gathered[ptr_index]
    finally:
        _rdns_context_state.reset(rdns_token)
        _provider_upstream_events.reset(events_token)

    return executed_provider_results, ptr_raw, upstream_events, rdns_state


def _build_telemetry_entry(
    provider_key: str,
    row: Dict[str, Any],
    event: Optional[Dict[str, Any]],
    miss_triggered_exception: bool,
    raw_res: Any,
    quota_consumed_keys: Set[str],
) -> Optional[Dict[str, Any]]:
    if _is_unconfigured_provider_row(row):
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
    if _is_provider_result_cacheable(row):
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
    provider_key: str,
    provider_name: str,
    ip: str,
    row: Dict[str, Any],
    event: Optional[Dict[str, Any]],
    miss_triggered_exception: bool,
    supports_cooldown: bool,
    now_dt: datetime,
    now_iso: str,
    default_cooldown: int,
) -> Optional[Tuple[str, str, int]]:
    if _is_provider_result_cacheable(row):
        entry_payload: Dict[str, Any] = {"row": row, "cachedAt": now_iso, "sanitized": True}
        if provider_key == "maxmind":
            entry_payload["cityDbLoaded"] = _has_local_maxmind_city_db()
            mm_updated = get_maxmind_newest_mtime_iso()
            if mm_updated:
                entry_payload["dbUpdatedAt"] = mm_updated
        elif provider_key == "stopforumspam":
            entry_payload["dbVersion"] = get_stopforumspam_db_version()
        return (
            _provider_cache_key(provider_key, ip),
            json.dumps(entry_payload),
            _get_provider_cache_ttl(provider_key, row),
        )

    if not supports_cooldown:
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
            "provider": provider_name,
            "providerKey": provider_key,
            "statusCode": cd_status,
            "reason": cd_reason,
            "cooldownSeconds": cd_seconds,
            "triggeredAt": now_iso,
            "until": until_iso,
        }
    )
    return _provider_cooldown_key(provider_key), cooldown_payload, cd_seconds


def _normalize_executed_row(provider_name: str, raw_res: Any) -> Tuple[Dict[str, Any], bool]:
    miss_triggered_exception = isinstance(raw_res, Exception)
    if miss_triggered_exception:
        safe_message = _sanitize_error_message(str(raw_res))
        logger.error(f"Provider {provider_name} unhandled exception: {safe_message}")
        return _build_unhandled_provider_error_row(provider_name, safe_message), True
    if not isinstance(raw_res, dict):
        return _build_unhandled_provider_error_row(provider_name, "Invalid provider response"), False
    row = dict(raw_res)
    # Last line of defence so upstream echoes of a key never reach the response or the cache
    if "rawJson" in row:
        row["rawJson"] = _views_attr("_sanitize_payload", _sanitize_payload)(row["rawJson"])
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
    default_cooldown, _, _ = _get_cooldown_bounds()
    hit_count = miss_count = cooldown_count = 0

    for provider_key, provider_name, _uses_http, supports_cooldown, _ in _PROVIDER_SPECS:
        if provider_key in cached_providers:
            row, cached_at = cached_providers[provider_key]
            row_copy = {**row, "isCached": True}
            if cached_at:
                row_copy["cachedAt"] = cached_at
            clean_results.append(row_copy)
            if not _is_unconfigured_provider_row(row_copy):
                hit_count += 1
                if cached_at:
                    cached_at_timestamps.append(cached_at)
                if active_redis is not None:
                    telemetry_entries.append({"provider_key": provider_key, "outcome": "cache_hit"})
            continue

        if provider_key in deferred_provider_keys:
            clean_results.append(_build_deferred_provider_row(provider_name))
            continue

        if provider_key in cooldown_entries or provider_key in quota_blocked_entries:
            cd_info = cooldown_entries.get(provider_key) or quota_blocked_entries[provider_key]
            clean_results.append(_build_cooldown_provider_row(provider_name, cd_info))
            cooldown_count += 1
            continue

        raw_res = executed_provider_results.get(provider_key)
        row, miss_triggered_exception = _normalize_executed_row(provider_name, raw_res)
        clean_results.append(row)
        if not _is_unconfigured_provider_row(row):
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
            provider_key,
            provider_name,
            ip,
            row,
            event,
            miss_triggered_exception,
            supports_cooldown,
            now_dt,
            now_iso,
            default_cooldown,
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
        write_entry = (_provider_cache_key("ptr", ip), ptr_entry, _get_provider_cache_ttl("ptr"))
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
    normalized_mode = _normalize_query_mode(query_mode)
    read_caches_fn = _views_attr("_read_provider_caches", _read_provider_caches)
    cached_providers, cached_ptr = initial_cache if initial_cache is not None else await read_caches_fn(ip)

    is_ipv4 = _reverse_ipv4_octets(ip) is not None
    # Sources that are skipped for this address or lack configuration answer statically, so they need
    # neither a cooldown lookup nor the shared HTTP client
    cache_expected_keys = frozenset(
        provider_key
        for provider_key, _, _, _, _ in _PROVIDER_SPECS
        if _is_provider_cache_expected(provider_key, is_ipv4)
    )
    deferred_provider_keys = frozenset(
        provider_key
        for provider_key, _, _, _, _ in _PROVIDER_SPECS
        if (
            normalized_mode == "light"
            and provider_key not in cached_providers
            and provider_key not in _LIGHT_MODE_ACTIVE_PROVIDERS
            and is_provider_configured(provider_key)
        )
    )
    missed_cooldown_keys = [
        provider_key
        for provider_key, _, _, supports_cooldown, _ in _PROVIDER_SPECS
        if (
            provider_key not in cached_providers
            and provider_key not in deferred_provider_keys
            and supports_cooldown
            and provider_key in cache_expected_keys
        )
    ]

    active_redis = _get_redis_client()
    cooldown_entries = await _fetch_provider_cooldowns(active_redis, missed_cooldown_keys)
    candidate_specs = [
        (idx, spec)
        for idx, spec in enumerate(_PROVIDER_SPECS)
        if spec[0] not in cached_providers and spec[0] not in deferred_provider_keys and spec[0] not in cooldown_entries
    ]
    quota_blocked_entries, quota_consumed_keys = await _evaluate_quota_candidates(
        active_redis, candidate_specs, is_ipv4
    )
    specs_to_execute = [(idx, spec) for idx, spec in candidate_specs if spec[0] not in quota_blocked_entries]
    executed_provider_results, ptr_raw, upstream_events, rdns_state = await _dispatch_upstream_queries(
        ip,
        specs_to_execute,
        needs_http_client=any(spec[2] and spec[0] in cache_expected_keys for _, spec in specs_to_execute),
        needs_ptr=cached_ptr is None,
        needs_rule_warmup=not are_offline_intelligence_caches_warm(),
        maxmind_will_run=any(spec[0] == "maxmind" for _, spec in specs_to_execute),
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
        redis_write_ops.append(_safe_redis_set_many(redis_set_entries))
    if active_redis is not None and telemetry_entries:
        tel_fn = _views_attr("record_provider_outcomes_batch", record_provider_outcomes_batch)
        redis_write_ops.append(tel_fn(telemetry_entries, now_dt=now_dt))
    if redis_write_ops:
        await asyncio.gather(*redis_write_ops)

    if not are_offline_intelligence_caches_warm():
        await asyncio.to_thread(_views_attr("warm_offline_intelligence_caches", warm_offline_intelligence_caches))

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


async def _detect_single_canonical_ip(
    ip: str,
    auth_mode: str,
    start_time: float,
    *,
    compact: bool = False,
    query_mode: str = "full",
) -> Dict[str, Any]:
    """Runs singleflight-coalesced intelligence detection for one canonical IP address."""
    normalized_mode = _normalize_query_mode(query_mode)
    non_public = _classify_non_public_ip(ip)
    if non_public is not None:
        return _build_non_public_response_payload(
            ip, non_public[0], non_public[1], start_time, query_mode=normalized_mode
        )

    current_loop = asyncio.get_running_loop()
    inflight_key = (ip, normalized_mode)
    read_caches_fn = _views_attr("_read_provider_caches", _read_provider_caches)
    exec_detection_fn = _views_attr("_execute_detection_with_cache", _execute_detection_with_cache)
    release_fn = _views_attr("_release_inflight_task", _release_inflight_task)

    # Register the shared task before any await so concurrent callers never duplicate cache reads or queries
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
                    cached_providers, cached_ptr = await read_caches_fn(target_ip)
                    return await exec_detection_fn(
                        target_ip,
                        initial_cache=(cached_providers, cached_ptr),
                        query_mode=target_mode,
                    )
                finally:
                    release_fn((target_ip, target_mode), own_task)

            created_task = current_loop.create_task(_run_coalesced_detection(target_ip=ip, target_mode=normalized_mode))

            def _finalize_inflight(done_task: asyncio.Task, task_key: Tuple[str, str] = inflight_key) -> None:
                release_fn(task_key, done_task)
                if not done_task.cancelled():
                    done_task.exception()

            created_task.add_done_callback(_finalize_inflight)
            _ip_detect_inflight[inflight_key] = created_task
            inflight_task = created_task

    try:
        base_payload = await _await_inflight_task(inflight_task, current_loop)
    except _StaleInflightLoopError:
        release_fn(inflight_key, inflight_task)
        base_payload = await exec_detection_fn(ip, query_mode=normalized_mode)

    cache_status = (base_payload.get("cacheMeta") or {}).get("status")
    if isinstance(cache_status, str) and cache_status in ("hit", "partial", "miss"):
        tel_global_fn = _views_attr("record_global_request_telemetry", record_global_request_telemetry)
        await tel_global_fn(cache_status, auth_mode)

    response_payload = _strip_raw_json_from_payload(base_payload) if compact else base_payload
    return _attach_request_diagnostics(response_payload, start_time)
