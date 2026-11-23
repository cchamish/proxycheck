"""
IP intelligence detection orchestration: singleflight coalescing, L1/L2 cache fallback,
and staged cache-backed intelligence gathering.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from ..cache import l2_store as l2_cache
from ..cache import quota_telemetry
from ..cache.redis_backend import (
    acquire_ip_updating_lock,
    get_cached_ip_snapshots_bulk,
    get_cooldown_bounds,
    get_redis_client,
    is_ip_updating_locked,
    is_refresh_on_cooldown,
    release_ip_updating_lock,
    safe_redis_set_many,
    set_cached_ip_snapshot,
    set_refresh_cooldown,
    set_swr_backoff,
)
from ..core import http_client
from ..core.context import provider_upstream_events, rdns_context_state
from ..core.ip_utils import (
    classify_non_public_ip,
    normalize_query_mode,
)
from ..offline import (
    cidr_attribution,
    lookup_bgp_tools_offline,
)
from ..provider_registry import (
    NO_REDIS_CACHE_PROVIDER_KEYS,
)
from ..providers import (
    PROVIDER_SPECS,
    build_cooldown_provider_row,
    build_deferred_provider_row,
    is_unconfigured_provider_row,
)
from ..providers import dns_local as dns_providers
from ..providers.dns_local import reverse_ipv4_octets
from ..rangeblock import service as rangeblock_service
from .arbitration import (
    attach_request_diagnostics,
    build_non_public_response_payload,
    strip_raw_json_from_payload,
)
from .pipeline import (
    _BATCH_DETECT_CONCURRENCY,
    _DEFAULT_REFRESH_COOLDOWN_SECONDS,
    _DEFAULT_SWR_BACKOFF_SECONDS,
    _LOCK_POLL_INTERVAL_SECONDS,
    _LOCK_POLL_MAX_WAIT_SECONDS,
    _assemble_detection_payload,
    _build_cache_or_cooldown_write,
    _build_telemetry_entry,
    _ensure_offline_caches_warm,
    _evaluate_quota_candidates,
    _fetch_provider_cooldowns,
    _has_transient_upstream_failures,
    _normalize_executed_row,
    _plan_provider_execution,
    _read_provider_caches,
    _rehydrate_snapshot_payload,
    _resolve_cache_layer_telemetry_event,
    _resolve_ptr_outcome,
    _safe_l2_aget_snapshot,
    _safe_l2_amerge_snapshot,
    _stamp_offline_signatures,
    _try_read_l1_snapshot,
)

logger = logging.getLogger("detector.views")

_ip_detect_inflight: Dict[Tuple[str, str], Tuple[asyncio.Task[Dict[str, Any]], asyncio.AbstractEventLoop]] = {}
_ip_detect_inflight_lock = threading.Lock()


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
    needs_http_client = any(spec.uses_http_client and spec.key in cache_expected_keys for spec in specs_to_execute)

    upstream_events: Dict[str, Dict[str, Any]] = {}
    events_token = provider_upstream_events.set(upstream_events)
    rdns_state: Dict[str, str] = {"status": "ok"}
    rdns_token = rdns_context_state.set(rdns_state)
    executed_provider_results: Dict[str, Any] = {}
    ptr_raw: Any = None
    cymru_bgp_prefix: Optional[str] = None
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
        if (
            not any(spec.key == "maxmind" for spec in specs_to_execute)
            and not cidr_attribution.are_offline_intelligence_caches_warm()
        ):
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

    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
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
    all_cached = False
    if cached_ptr is not None:
        expected_keys, deferred_keys, _ = _plan_provider_execution(
            cached_providers, target_mode, reverse_ipv4_octets(target_ip) is not None
        )
        all_cached = (expected_keys - deferred_keys).issubset(cached_providers.keys())
    if all_cached:
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

    async def _prefetch_l1() -> Dict[str, Dict[str, Any]]:
        if not public_ips:
            return {}
        full_hits = await get_cached_ip_snapshots_bulk(public_ips, mode="full")
        if normalized_mode != "light":
            return full_hits
        remaining = [ip for ip in public_ips if ip not in full_hits]
        if not remaining:
            return full_hits
        light_hits = await get_cached_ip_snapshots_bulk(remaining, mode="light")
        return {**light_hits, **full_hits}

    l1_hits, rangeblock_by_ip = await asyncio.gather(
        _prefetch_l1(),
        rangeblock_service.query_rangeblocks_for_ips(public_ips, wiki=wiki),
    )
    l1_miss_ips = [ip for ip in public_ips if ip not in l1_hits]
    l2_hits: Dict[str, Dict[str, Any]] = {}
    if l1_miss_ips:
        try:
            l2_hits = await l2_cache.aget_ip_snapshots_bulk(l1_miss_ips, mode=normalized_mode)
        except AssertionError as exc:
            if type(exc).__name__ != "DatabaseOperationForbidden":
                raise

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
