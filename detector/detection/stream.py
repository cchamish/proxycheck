"""
Progressive Server-Sent Events (SSE) detection streaming for single canonical IP addresses.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

import httpx

from ..cache import quota_telemetry
from ..cache.redis_backend import (
    acquire_ip_updating_lock,
    get_cooldown_bounds,
    get_redis_client,
    is_ip_updating_locked,
    release_ip_updating_lock,
    safe_redis_set_many,
)
from ..core import http_client
from ..core.context import provider_upstream_events, rdns_context_state
from ..core.ip_utils import classify_non_public_ip, normalize_query_mode
from ..providers import dns as dns_providers
from ..providers.common import PROVIDER_SPECS, ProviderSpec
from ..providers.dns import reverse_ipv4_octets
from ..rangeblock import service as rangeblock_service
from .arbitration import (
    attach_request_diagnostics,
    build_non_public_response_payload,
    strip_raw_json_from_payload,
)
from .pipeline import (
    OFFLINE_PROVIDER_KEYS,
    _assemble_detection_payload,
    _ensure_offline_caches_warm,
    _evaluate_quota_candidates,
    _extract_offline_bgp_prefix,
    _fetch_provider_cooldowns,
    _get_spec_by_key,
    _has_transient_upstream_failures,
    _persist_full_snapshot,
    _plan_provider_execution,
    _poll_for_concurrent_snapshot,
    _read_provider_caches,
    _record_global_cache_telemetry,
    _rehydrate_layer_snapshot,
    _resolve_offline_tor_row,
    _resolve_ptr_outcome,
    _settle_executed_provider_row,
    _settle_provider_rows,
    _try_read_snapshot_with_layer,
)

_SSE_NON_OVERVIEW_KEYS = frozenset(
    {
        "results",
        "fetchedAt",
        "queryMode",
        "isPartialMode",
        "isCached",
        "cacheMeta",
        "rangeblock",
        "pendingProviders",
        "durationSeconds",
        "memoryMb",
        "isNonPublic",
        "nonPublicCategory",
        "nonPublicReason",
    }
)


def _format_sse_event(event_name: str, payload: Dict[str, Any]) -> bytes:
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return f"event: {event_name}\ndata: {encoded}\n\n".encode("utf-8")


def _extract_overview_fields(assembled: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in assembled.items() if k not in _SSE_NON_OVERVIEW_KEYS}


def _build_done_event(
    ip: str,
    payload: Mapping[str, Any],
    start_time: float,
    *,
    include_overview: bool = False,
) -> bytes:
    done_body: Dict[str, Any] = {
        "ip": ip,
        "isCached": payload.get("isCached", False),
        "fetchedAt": payload.get("fetchedAt"),
        "cacheMeta": payload.get("cacheMeta"),
    }
    if include_overview:
        done_body["pendingProviders"] = []
        done_body.update(_extract_overview_fields(dict(payload)))
    return _format_sse_event("done", attach_request_diagnostics(done_body, start_time))


async def _build_terminal_snapshot_frames(
    ip: str,
    rehydrated: Dict[str, Any],
    rb_summary: Dict[str, Any],
    auth_mode: str,
    start_time: float,
    compact: bool,
) -> Tuple[bytes, bytes]:
    await _record_global_cache_telemetry(rehydrated.get("cacheMeta"), auth_mode)
    out_payload = strip_raw_json_from_payload(rehydrated) if compact else dict(rehydrated)
    out_payload["rangeblock"] = rb_summary
    out_payload["pendingProviders"] = []
    out_payload = attach_request_diagnostics(out_payload, start_time)
    return (
        _format_sse_event("snapshot", out_payload),
        _build_done_event(ip, out_payload, start_time),
    )


async def _run_immediate_offline_providers(
    ip: str,
    cached_providers: Mapping[str, Tuple[Dict[str, Any], Optional[str]]],
    deferred_provider_keys: FrozenSet[str],
) -> Dict[str, Any]:
    await _ensure_offline_caches_warm()
    spec_by_key = _get_spec_by_key()
    offline_keys = [
        spec.key
        for spec in PROVIDER_SPECS
        if spec.key in OFFLINE_PROVIDER_KEYS
        and spec.key not in cached_providers
        and spec.key not in deferred_provider_keys
    ]
    if not offline_keys:
        return {}
    results = await asyncio.gather(*(spec_by_key[k].invoke(None, ip) for k in offline_keys), return_exceptions=True)
    return dict(zip(offline_keys, results, strict=True))


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


async def _flush_single_provider_redis_ops(
    active_redis: Any,
    write_entry: Optional[Tuple[str, str, int]],
    tel_entry: Optional[Dict[str, Any]],
    now_dt: datetime,
) -> None:
    if active_redis is None:
        return
    ops = []
    if write_entry is not None:
        ops.append(safe_redis_set_many([write_entry]))
    if tel_entry is not None:
        ops.append(quota_telemetry.record_provider_outcomes_batch([tel_entry], now_dt=now_dt))
    if ops:
        await asyncio.gather(*ops)


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
    normalised_mode = normalize_query_mode(query_mode)

    non_public = classify_non_public_ip(ip)
    if non_public is not None:
        payload = build_non_public_response_payload(
            ip, non_public[0], non_public[1], start_time, query_mode=normalised_mode
        )
        payload["rangeblock"] = rangeblock_service.build_empty_rangeblock_summary(ip)
        payload["pendingProviders"] = []
        yield _format_sse_event("snapshot", payload)
        yield _build_done_event(ip, payload, start_time)
        return

    snap_task = asyncio.create_task(_try_read_snapshot_with_layer(ip, normalised_mode))
    rb_task = asyncio.create_task(rangeblock_service.query_rangeblocks_for_ip(ip, wiki=wiki))
    snapshot, layer = await snap_task
    if snapshot is not None:
        rehydrated, rb_summary = await asyncio.gather(
            _rehydrate_layer_snapshot(ip, snapshot, layer=layer, normalized_mode=normalised_mode),
            rb_task,
        )
        for frame in await _build_terminal_snapshot_frames(ip, rehydrated, rb_summary, auth_mode, start_time, compact):
            yield frame
        return

    # Both L1 and L2 missed: reuse the already-running rangeblock query alongside provider cache reads.
    is_ipv4 = reverse_ipv4_octets(ip) is not None
    (cached_providers, cached_ptr), rb_summary = await asyncio.gather(_read_provider_caches(ip), rb_task)
    cache_expected_keys, deferred_provider_keys, missed_cooldown_keys = _plan_provider_execution(
        cached_providers, normalised_mode, is_ipv4
    )

    all_cached = cached_ptr is not None and (cache_expected_keys - deferred_provider_keys).issubset(
        cached_providers.keys()
    )
    lock_token: Optional[str] = None
    if not all_cached and normalised_mode != "light":
        lock_token = await acquire_ip_updating_lock(ip)
        if lock_token is None and await is_ip_updating_locked(ip):
            polled = await _poll_for_concurrent_snapshot(ip, normalised_mode)
            if polled is not None:
                for frame in await _build_terminal_snapshot_frames(
                    ip, polled, rb_summary, auth_mode, start_time, compact
                ):
                    yield frame
                return
            cached_providers, cached_ptr = await _read_provider_caches(ip)
            cache_expected_keys, deferred_provider_keys, missed_cooldown_keys = _plan_provider_execution(
                cached_providers, normalised_mode, is_ipv4
            )

    tasks: List[asyncio.Task[Any]] = []
    try:
        active_redis = get_redis_client()
        offline_tor_row, deferred_provider_keys, missed_cooldown_keys = _resolve_offline_tor_row(
            ip,
            normalised_mode,
            cached_providers,
            deferred_provider_keys,
            missed_cooldown_keys,
            include_full_mode=True,
        )
        cooldown_entries, immediate_offline = await asyncio.gather(
            _fetch_provider_cooldowns(active_redis, missed_cooldown_keys),
            _run_immediate_offline_providers(ip, cached_providers, deferred_provider_keys),
        )
        if offline_tor_row is not None:
            immediate_offline["tor_onionoo"] = offline_tor_row

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
        settled = _settle_provider_rows(
            ip,
            cached_providers=cached_providers,
            deferred_provider_keys=deferred_provider_keys,
            cooldown_entries=cooldown_entries,
            quota_blocked_entries=quota_blocked_entries,
            executed_results=immediate_offline,
            upstream_events={},
            quota_consumed_keys=quota_consumed_keys,
            active_redis=active_redis,
            now_dt=now_dt,
            now_iso=now_iso,
            default_cooldown=default_cooldown,
            include_missing_executed=False,
        )

        initial_redis_ops = []
        if settled.redis_set_entries:
            initial_redis_ops.append(safe_redis_set_many(settled.redis_set_entries))
        if active_redis is not None and settled.telemetry_entries:
            initial_redis_ops.append(
                quota_telemetry.record_provider_outcomes_batch(settled.telemetry_entries, now_dt=now_dt)
            )
        if initial_redis_ops:
            await asyncio.gather(*initial_redis_ops)

        ptr_hostname: Optional[str] = cached_ptr[0] if cached_ptr is not None else None
        if cached_ptr is not None:
            settled.hit_count += 1
            if cached_ptr[1]:
                settled.cached_at_timestamps.append(cached_ptr[1])
        cymru_bgp_prefix = _extract_offline_bgp_prefix(ip)
        rdns_state: Dict[str, str] = {"status": "ok"}

        pending_labels = [spec.label for spec in specs_to_execute]
        initial_layer = (
            "L1"
            if (
                not specs_to_execute
                and settled.miss_count == 0
                and settled.cooldown_count == 0
                and settled.hit_count > 0
            )
            else "upstream"
        )
        initial_payload = _assemble_detection_payload(
            ip,
            settled.ordered_rows(),
            ptr_hostname,
            hit_count=settled.hit_count,
            miss_count=settled.miss_count,
            cooldown_count=settled.cooldown_count,
            cached_at_timestamps=settled.cached_at_timestamps,
            query_mode=normalised_mode,
            is_partial_mode=bool(deferred_provider_keys),
            bgp_prefix=cymru_bgp_prefix,
            layer=initial_layer,
            now_dt=now_dt,
        )
        initial_payload = strip_raw_json_from_payload(initial_payload) if compact else initial_payload
        initial_payload["rangeblock"] = rb_summary
        initial_payload["pendingProviders"] = pending_labels
        initial_payload["providerOrder"] = [spec.label for spec in PROVIDER_SPECS]
        yield _format_sse_event("snapshot", attach_request_diagnostics(initial_payload, start_time))

        needs_http = any(spec.uses_http_client and spec.key in cache_expected_keys for spec in specs_to_execute)
        client = await http_client.get_shared_http_client() if needs_http else None
        tasks = [
            asyncio.create_task(_run_isolated_stream_task("provider", spec, client, ip)) for spec in specs_to_execute
        ]
        if cached_ptr is None and normalised_mode != "light":
            tasks.append(asyncio.create_task(_run_isolated_stream_task("ptr", None, None, ip)))
            if cymru_bgp_prefix is None:
                tasks.append(asyncio.create_task(_run_isolated_stream_task("bgp", None, None, ip)))

        pending_set = list(pending_labels)
        for completed in asyncio.as_completed(tasks):
            task_kind, spec, raw_res, task_events, task_rdns = await completed
            if task_kind == "ptr":
                ptr_hostname, _, ptr_miss, _, ptr_write = _resolve_ptr_outcome(
                    ip, None, raw_res, task_rdns, active_redis, now_iso
                )
                rdns_state = task_rdns
                settled.miss_count += ptr_miss
                if ptr_write is not None:
                    await safe_redis_set_many([ptr_write])
                continue
            if task_kind == "bgp":
                if (
                    isinstance(raw_res, dict)
                    and isinstance(raw_res.get("bgpPrefix"), str)
                    and raw_res["bgpPrefix"].strip()
                ):
                    cymru_bgp_prefix = raw_res["bgpPrefix"].strip()
                continue
            if spec is None:
                continue

            row, write_entry, tel_entry = _settle_executed_provider_row(
                settled,
                spec,
                ip,
                raw_res,
                event=task_events.get(spec.key),
                quota_consumed_keys=quota_consumed_keys,
                active_redis=active_redis,
                now_dt=now_dt,
                now_iso=now_iso,
                default_cooldown=default_cooldown,
            )
            if spec.label in pending_set:
                pending_set.remove(spec.label)
            await _flush_single_provider_redis_ops(active_redis, write_entry, tel_entry, now_dt)

            updated_payload = _assemble_detection_payload(
                ip,
                settled.ordered_rows(),
                ptr_hostname,
                hit_count=settled.hit_count,
                miss_count=settled.miss_count,
                cooldown_count=settled.cooldown_count,
                cached_at_timestamps=settled.cached_at_timestamps,
                query_mode=normalised_mode,
                is_partial_mode=bool(deferred_provider_keys),
                bgp_prefix=cymru_bgp_prefix,
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

        final_rows = settled.ordered_rows()
        all_cached_l1 = settled.miss_count == 0 and settled.cooldown_count == 0 and settled.hit_count > 0
        final_payload = _assemble_detection_payload(
            ip,
            final_rows,
            ptr_hostname,
            hit_count=settled.hit_count,
            miss_count=settled.miss_count,
            cooldown_count=settled.cooldown_count,
            cached_at_timestamps=settled.cached_at_timestamps,
            query_mode=normalised_mode,
            is_partial_mode=bool(deferred_provider_keys),
            bgp_prefix=cymru_bgp_prefix,
            layer="L1" if all_cached_l1 else "upstream",
            now_dt=now_dt,
        )
        has_transient = _has_transient_upstream_failures(
            final_rows,
            cooldown_count=settled.cooldown_count,
            cached_ptr=cached_ptr,
            rdns_state=rdns_state,
        )
        if not all_cached_l1 and not deferred_provider_keys and not has_transient:
            await _persist_full_snapshot(ip, final_payload, final_rows, now_dt=now_dt, now_iso=now_iso)

        await _record_global_cache_telemetry(final_payload.get("cacheMeta"), auth_mode)
        yield _build_done_event(ip, final_payload, start_time, include_overview=True)
    finally:
        pending = [t for t in tasks if not t.done()]
        for t in pending:
            t.cancel()
        try:
            if pending:
                with contextlib.suppress(asyncio.CancelledError):
                    await asyncio.gather(*pending, return_exceptions=True)
        finally:
            if lock_token is not None:
                await release_ip_updating_lock(ip, lock_token)
