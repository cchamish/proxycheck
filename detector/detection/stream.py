"""
Progressive Server-Sent Events (SSE) detection streaming for single canonical IP addresses.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Tuple

import httpx

from .. import offline as offline_dbs
from ..cache import quota_telemetry
from ..cache.redis_backend import (
    acquire_ip_updating_lock,
    get_cooldown_bounds,
    get_redis_client,
    release_ip_updating_lock,
    safe_redis_set_many,
    set_cached_ip_snapshot,
)
from ..core import http_client
from ..core.context import provider_upstream_events, rdns_context_state
from ..core.ip_utils import classify_non_public_ip, normalize_query_mode
from ..offline import lookup_bgp_tools_offline
from ..providers import (
    adapt_tor_onionoo,
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
    NO_REDIS_CACHE_PROVIDER_KEYS,
    OFFLINE_PROVIDER_KEYS,
    PROVIDER_SPECS,
    ProviderSpec,
    _assemble_detection_payload,
    _build_cache_or_cooldown_write,
    _build_telemetry_entry,
    _ensure_offline_caches_warm,
    _evaluate_quota_candidates,
    _fetch_provider_cooldowns,
    _get_spec_by_key,
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

_SSE_OVERVIEW_KEYS = (
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
    "confirmedResidentialProxy",
    "confirmedResidentialProxyProvider",
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


def _format_sse_event(event_name: str, payload: Dict[str, Any]) -> bytes:
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return f"event: {event_name}\ndata: {encoded}\n\n".encode("utf-8")


def _extract_overview_fields(assembled: Dict[str, Any]) -> Dict[str, Any]:
    return {k: assembled[k] for k in _SSE_OVERVIEW_KEYS if k in assembled}


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


async def stream_single_canonical_ip_sse(  # noqa: C901
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

    l1_task = asyncio.create_task(_try_read_l1_snapshot(ip, normalised_mode))
    rb_task = asyncio.create_task(rangeblock_service.query_rangeblocks_for_ip(ip, wiki=wiki))
    snapshot = await l1_task
    layer = "L1"
    force_offline = False
    backfill_l1 = False
    if snapshot is None:
        snapshot = await _safe_l2_aget_snapshot(ip, mode=normalised_mode)
        layer = "L2"
        force_offline = True
        backfill_l1 = True

    if snapshot is not None:
        rehydrated, rb_summary = await asyncio.gather(
            _rehydrate_snapshot_payload(
                ip,
                snapshot,
                layer=layer,
                normalized_mode=normalised_mode,
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
        return

    # Both L1 and L2 missed: reuse the already-running rangeblock query alongside provider cache reads.
    is_ipv4 = reverse_ipv4_octets(ip) is not None
    (cached_providers, cached_ptr), rb_summary = await asyncio.gather(_read_provider_caches(ip), rb_task)

    cache_expected_keys, deferred_provider_keys, missed_cooldown_keys = _plan_provider_execution(
        cached_providers, normalised_mode, is_ipv4
    )
    active_redis = get_redis_client()

    async def _run_offline_now() -> Dict[str, Dict[str, Any]]:
        await _ensure_offline_caches_warm()
        spec_by_key = _get_spec_by_key()
        offline_keys = [
            spec.key
            for spec in PROVIDER_SPECS
            if spec.key in OFFLINE_PROVIDER_KEYS
            and spec.key not in cached_providers
            and spec.key not in deferred_provider_keys
        ]
        out: Dict[str, Dict[str, Any]] = {}
        if offline_keys:
            results = await asyncio.gather(
                *(spec_by_key[k].invoke(None, ip) for k in offline_keys), return_exceptions=True
            )
            for pkey, raw_res in zip(offline_keys, results, strict=True):
                row, _ = _normalize_executed_row(spec_by_key[pkey].label, raw_res)
                out[pkey] = row
        if "tor_onionoo" not in cached_providers and "tor_onionoo" not in deferred_provider_keys:
            offline_tor = offline_dbs.lookup_tor_onionoo_offline(ip)
            if isinstance(offline_tor, dict):
                out["tor_onionoo"] = adapt_tor_onionoo(offline_tor, status_code=200, ip=ip)
        return out

    cooldown_entries, immediate_offline = await asyncio.gather(
        _fetch_provider_cooldowns(active_redis, missed_cooldown_keys),
        _run_offline_now(),
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

    rows_by_key: Dict[str, Dict[str, Any]] = {}
    cached_at_timestamps: List[str] = []
    hit_count = miss_count = cooldown_count = 0
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
        query_mode=normalised_mode,
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
        tasks = [
            asyncio.create_task(_run_isolated_stream_task("provider", spec, client, ip)) for spec in specs_to_execute
        ]
        if cached_ptr is None:
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
                miss_count += ptr_miss
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

            row, miss_exc = _normalize_executed_row(spec.label, raw_res)
            rows_by_key[spec.key] = row
            if not is_unconfigured_provider_row(row) and spec.key not in NO_REDIS_CACHE_PROVIDER_KEYS:
                miss_count += 1
            if spec.label in pending_set:
                pending_set.remove(spec.label)

            if active_redis is not None:
                ops = []
                write_entry = _build_cache_or_cooldown_write(
                    spec, ip, row, task_events.get(spec.key), miss_exc, now_dt, now_iso, default_cooldown
                )
                if write_entry is not None:
                    ops.append(safe_redis_set_many([write_entry]))
                tel_entry = _build_telemetry_entry(
                    spec.key, row, task_events.get(spec.key), miss_exc, raw_res, quota_consumed_keys
                )
                if tel_entry is not None:
                    ops.append(quota_telemetry.record_provider_outcomes_batch([tel_entry], now_dt=now_dt))
                if ops:
                    await asyncio.gather(*ops)

            updated_payload = _assemble_detection_payload(
                ip,
                _order_provider_rows(rows_by_key),
                ptr_hostname,
                hit_count=hit_count,
                miss_count=miss_count,
                cooldown_count=cooldown_count,
                cached_at_timestamps=cached_at_timestamps,
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
            query_mode=normalised_mode,
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

        yield _format_sse_event(
            "done",
            attach_request_diagnostics(
                {
                    "ip": ip,
                    "isCached": final_payload.get("isCached", False),
                    "fetchedAt": final_payload.get("fetchedAt"),
                    "cacheMeta": final_payload.get("cacheMeta"),
                    "pendingProviders": [],
                    **_extract_overview_fields(final_payload),
                },
                start_time,
            ),
        )
    except asyncio.CancelledError:
        for t in tasks:
            if not t.done():
                t.cancel()
        if tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.gather(*tasks, return_exceptions=True)
        raise
    finally:
        if lock_token is not None:
            await release_ip_updating_lock(ip, lock_token)
