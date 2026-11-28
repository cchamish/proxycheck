"""
Admin provider dashboard snapshot aggregation across Redis telemetry, ToolsDB L2, and offline databases.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from asgiref.sync import sync_to_async
from django.conf import settings
from django.db import Error as DjangoDbError
from django.db import close_old_connections, connections

from ..models import IpIntelligenceCache
from ..offline import collect_offline_databases_status
from ..provider_registry import PROVIDER_REGISTRY, REDIS_TRANSPORT_ERRORS
from .quota_telemetry import (
    _decode_redis_str,
    _global_telemetry_key,
    _parse_non_negative_int,
    _provider_telemetry_key,
    _quota_daily_key,
    _quota_minute_key,
    get_provider_quota_limits,
    is_provider_configured,
)
from .redis_backend import (
    get_redis_client,
    mark_redis_failure,
    provider_cooldown_key,
)

logger = logging.getLogger(__name__)


def _decode_hash(raw_hash: Any) -> Dict[str, str]:
    if not isinstance(raw_hash, dict):
        return {}
    return {
        (k.decode("utf-8", errors="replace") if isinstance(k, bytes) else str(k)): (
            v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
        )
        for k, v in raw_hash.items()
    }


def _hash_int(hash_data: Dict[str, str], field: str, default: int = 0) -> int:
    parsed = _parse_non_negative_int(hash_data.get(field))
    return parsed if parsed is not None else default


def _estimate_l2_table_rows_sync() -> Optional[int]:
    if not bool(getattr(settings, "ENABLE_L2_TOOLSDB_CACHE", True)):
        return None
    try:
        close_old_connections()
        conn = connections["default"]
        if conn.vendor == "mysql":
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT table_rows FROM information_schema.tables "
                    "WHERE table_schema = DATABASE() AND table_name = %s",
                    [IpIntelligenceCache._meta.db_table],
                )
                row = cursor.fetchone()
                if row and row[0] is not None:
                    return max(0, int(row[0]))
        return max(0, int(IpIntelligenceCache.objects.count()))
    except DjangoDbError, ValueError, TypeError, OSError:
        return None
    except AssertionError as exc:
        if type(exc).__name__ == "DatabaseOperationForbidden":
            return None
        raise
    finally:
        close_old_connections()


async def build_dashboard_snapshot(*, now_dt: Optional[datetime] = None) -> Dict[str, Any]:
    """
    Aggregates global request telemetry and all provider quota, cooldown TTL, and status
    metrics in a single Redis pipeline without exposing IP addresses or user identities.
    """
    current_dt = now_dt or datetime.now(timezone.utc)
    redis_available = False
    global_hash: Dict[str, str] = {}
    provider_pipeline_rows: Dict[str, Tuple[int, int, int, Optional[str], Dict[str, str]]] = {}

    client = get_redis_client()
    pipeline_fn = getattr(client, "pipeline", None) if client is not None else None
    if callable(pipeline_fn):
        try:
            pipe = pipeline_fn(transaction=False)
            pipe.hgetall(_global_telemetry_key(current_dt))
            for meta in PROVIDER_REGISTRY:
                cooldown_key = provider_cooldown_key(meta.key)
                pipe.get(_quota_minute_key(meta.key, current_dt))
                pipe.get(_quota_daily_key(meta.key, current_dt))
                pipe.ttl(cooldown_key)
                pipe.get(cooldown_key)
                pipe.hgetall(_provider_telemetry_key(meta.key, current_dt))

            exec_call = pipe.execute()
            if inspect.isawaitable(exec_call):
                results = await exec_call
                expected_len = 1 + (len(PROVIDER_REGISTRY) * 5)
                if isinstance(results, (list, tuple)) and len(results) == expected_len:
                    redis_available = True
                    global_hash = _decode_hash(results[0])
                    for idx, meta in enumerate(PROVIDER_REGISTRY):
                        base = 1 + (idx * 5)
                        raw_min = (
                            _decode_redis_str(results[base]) if isinstance(results[base], bytes) else results[base]
                        )
                        raw_day = (
                            _decode_redis_str(results[base + 1])
                            if isinstance(results[base + 1], bytes)
                            else results[base + 1]
                        )
                        raw_ttl = results[base + 2]
                        ttl_val = (
                            raw_ttl if isinstance(raw_ttl, int) and not isinstance(raw_ttl, bool) and raw_ttl > 0 else 0
                        )
                        provider_pipeline_rows[meta.key] = (
                            _parse_non_negative_int(raw_min) or 0,
                            _parse_non_negative_int(raw_day) or 0,
                            ttl_val,
                            _decode_redis_str(results[base + 3]),
                            _decode_hash(results[base + 4]),
                        )
        except REDIS_TRANSPORT_ERRORS as exc:
            mark_redis_failure(exc)
            logger.warning("Dashboard snapshot fell back to empty telemetry (%s)", type(exc).__name__)

    offline_databases = await asyncio.to_thread(collect_offline_databases_status, now_dt=current_dt)
    l2_estimated_rows = await sync_to_async(_estimate_l2_table_rows_sync, thread_sensitive=True)()
    has_maxmind_db = any(
        entry.get("key", "").startswith("maxmind_") and entry.get("exists") for entry in offline_databases
    )
    has_sfs_db = any(
        entry.get("key", "").startswith("stopforumspam_") and entry.get("exists") for entry in offline_databases
    )
    has_ipsum_db = any(entry.get("key") == "ipsum_drop" and entry.get("exists") for entry in offline_databases)
    has_openasn_db = any(entry.get("key") == "openasn" and entry.get("exists") for entry in offline_databases)
    has_oxylabs_db = any(entry.get("key") == "oxylabs" and entry.get("exists") for entry in offline_databases)

    providers_out: List[Dict[str, Any]] = []
    for meta in PROVIDER_REGISTRY:
        configured = is_provider_configured(meta.key)
        rpm_limit, daily_limit = get_provider_quota_limits(meta.key)
        minute_used, daily_used, cooldown_ttl, cd_raw, tel_hash = provider_pipeline_rows.get(
            meta.key, (0, 0, 0, None, {})
        )

        if meta.key == "maxmind" and not has_maxmind_db:
            status_key, status_label = "db_missing", "Database Missing"
        elif (
            (meta.key == "stopforumspam" and not has_sfs_db)
            or (meta.key == "ipsum_drop" and not has_ipsum_db)
            or (meta.key == "openasn" and not has_openasn_db)
            or (meta.key == "oxylabs" and not has_oxylabs_db)
        ):
            status_key, status_label = "db_missing", "Offline DB Missing"
        elif not configured:
            status_key, status_label = "no_api_key", "No API Key"
        elif cooldown_ttl > 0:
            status_key, status_label = "cooldown", f"Cooldown ({cooldown_ttl}s)"
        elif (rpm_limit > 0 and minute_used >= rpm_limit) or (daily_limit > 0 and daily_used >= daily_limit):
            status_key, status_label = "quota_guarded", "Quota Guarded"
        else:
            status_key, status_label = "healthy", "Healthy"

        cooldown_reason: Optional[str] = None
        if cooldown_ttl > 0 and cd_raw:
            try:
                parsed_cd = json.loads(cd_raw)
                if isinstance(parsed_cd, dict) and isinstance(parsed_cd.get("reason"), str):
                    cooldown_reason = parsed_cd["reason"]
            except ValueError:
                cooldown_reason = None

        providers_out.append(
            {
                "key": meta.key,
                "name": meta.label,
                "usesHttp": meta.uses_http,
                "configured": configured,
                "status": status_label,
                "statusKey": status_key,
                "cooldownTtlSeconds": cooldown_ttl,
                "cooldownReason": cooldown_reason,
                "minuteUsed": minute_used,
                "minuteLimit": rpm_limit,
                "dailyUsed": daily_used,
                "dailyLimit": daily_limit,
                "upstreamRemaining": _parse_non_negative_int(tel_hash.get("upstream_remaining")),
                "upstreamLimit": _parse_non_negative_int(tel_hash.get("upstream_limit")),
                "upstreamUsed": _parse_non_negative_int(tel_hash.get("upstream_used")),
                "lastStatusAt": tel_hash.get("last_status_at") or None,
                "telemetry": {
                    "ok": _hash_int(tel_hash, "ok"),
                    "cacheHit": _hash_int(tel_hash, "cache_hit"),
                    "rateLimited429": _hash_int(tel_hash, "429"),
                    "error5xx": _hash_int(tel_hash, "5xx"),
                    "timeout": _hash_int(tel_hash, "timeout"),
                    "quotaBlocked": _hash_int(tel_hash, "quota_blocked"),
                },
            }
        )

    l1_hit = _hash_int(global_hash, "l1_hit")
    l2_hit_fresh = _hash_int(global_hash, "l2_hit_fresh")
    l2_hit_stale_swr = _hash_int(global_hash, "l2_hit_stale_swr")
    upstream_miss = _hash_int(global_hash, "upstream_miss")
    refresh_ok = _hash_int(global_hash, "refresh_ok")
    refresh_rate_limited = _hash_int(global_hash, "refresh_rate_limited")
    layer_total = l1_hit + l2_hit_fresh + l2_hit_stale_swr + upstream_miss
    dual_hit_rate = (
        round(((l1_hit + l2_hit_fresh + l2_hit_stale_swr) / layer_total) * 100.0, 1) if layer_total > 0 else 0.0
    )

    cache_telemetry = {
        "l1Hit": l1_hit,
        "l2HitFresh": l2_hit_fresh,
        "l2HitStaleSwr": l2_hit_stale_swr,
        "upstreamMiss": upstream_miss,
        "refreshOk": refresh_ok,
        "refreshRateLimited": refresh_rate_limited,
        "l1_hit": l1_hit,
        "l2_hit_fresh": l2_hit_fresh,
        "l2_hit_stale_swr": l2_hit_stale_swr,
        "upstream_miss": upstream_miss,
        "refresh_ok": refresh_ok,
        "refresh_rate_limited": refresh_rate_limited,
        "dualLayerHitRatePercent": dual_hit_rate,
        "l2EstimatedRows": l2_estimated_rows,
    }

    auth_session = _hash_int(global_hash, "auth_session")
    auth_gadget = _hash_int(global_hash, "auth_gadget")
    cache_hit = _hash_int(global_hash, "cache_hit")
    cache_partial = _hash_int(global_hash, "cache_partial")
    cache_miss = _hash_int(global_hash, "cache_miss")
    cache_total = cache_hit + cache_partial + cache_miss

    global_summary = {
        "totalRequestsToday": max(cache_total, auth_session + auth_gadget),
        "authSession": auth_session,
        "authGadget": auth_gadget,
        "cacheHit": cache_hit,
        "cachePartial": cache_partial,
        "cacheMiss": cache_miss,
        "fullCacheHitRatePercent": round((cache_hit / cache_total) * 100.0, 1) if cache_total > 0 else 0.0,
        "l1Hit": l1_hit,
        "l2HitFresh": l2_hit_fresh,
        "l2HitStaleSwr": l2_hit_stale_swr,
        "upstreamMiss": upstream_miss,
        "refreshOk": refresh_ok,
        "refreshRateLimited": refresh_rate_limited,
        "dualLayerHitRatePercent": dual_hit_rate,
        "l2EstimatedRows": l2_estimated_rows,
        "totalQuotaBlocksToday": sum(entry["telemetry"]["quotaBlocked"] for entry in providers_out),
        "activeCooldownCount": sum(1 for entry in providers_out if entry["statusKey"] == "cooldown"),
        "activeQuotaGuardCount": sum(1 for entry in providers_out if entry["statusKey"] == "quota_guarded"),
    }

    return {
        "generatedAt": current_dt.isoformat(),
        "dateBucket": current_dt.strftime("%Y%m%d"),
        "redisAvailable": redis_available,
        "cacheTelemetry": cache_telemetry,
        "global": global_summary,
        "providers": providers_out,
        "offlineDatabases": offline_databases,
    }
