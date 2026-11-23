"""
Proactive multi-window API quota guard, endpoint rate limits, and anonymised Redis telemetry.
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import logging
import os
import re
import secrets
import weakref
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from django.conf import settings
from django.core.signals import setting_changed

from .cache_backends import (
    get_redis_client,
    get_redis_namespace,
    mark_redis_failure,
    safe_redis_mget,
)
from .provider_registry import (
    DEFAULT_QUOTA_LIMITS,
    PROVIDER_CREDENTIAL_SETTINGS,
    PROVIDER_REGISTRY,
    REDIS_TRANSPORT_ERRORS,
)

logger = logging.getLogger(__name__)

MINUTE_QUOTA_TTL_SECONDS = 120
HOURLY_QUOTA_TTL_SECONDS = 7200
DAILY_QUOTA_TTL_SECONDS = 172800
TELEMETRY_TTL_SECONDS = 7 * 86400

DEFAULT_REFRESH_USER_RPM_LIMIT = 6
DEFAULT_REFRESH_USER_RPH_LIMIT = 60
DEFAULT_REFRESH_GLOBAL_RPM_LIMIT = 30
DEFAULT_COMMERCIAL_SWR_GUARD_RATIO = 0.15
DEFAULT_COMMERCIAL_SWR_GUARD_MAX_AGE_DAYS = 180

VALID_CACHE_TELEMETRY_EVENTS = frozenset(
    {
        "l1_hit",
        "l2_hit_fresh",
        "l2_hit_stale_swr",
        "upstream_miss",
        "refresh_ok",
        "refresh_rate_limited",
    }
)

VALID_PROVIDER_OUTCOMES = frozenset(
    {
        "ok",
        "cache_hit",
        "429",
        "5xx",
        "timeout",
        "quota_blocked",
    }
)

PROVIDER_QUOTA_SPECS: Dict[str, Tuple[int, int]] = DEFAULT_QUOTA_LIMITS

_QUOTA_CONSUME_LUA = """
local min_key = KEYS[1]
local day_key = KEYS[2]
local tel_key = KEYS[3]
local rpm_limit = tonumber(ARGV[1]) or 0
local rpd_limit = tonumber(ARGV[2]) or 0
local min_ttl = tonumber(ARGV[3]) or 120
local day_ttl = tonumber(ARGV[4]) or 172800
local tel_ttl = tonumber(ARGV[5]) or 604800

local min_val = redis.call("INCR", min_key)
if min_val == 1 or redis.call("TTL", min_key) < 0 then
    redis.call("EXPIRE", min_key, min_ttl)
end

local day_val = redis.call("INCR", day_key)
if day_val == 1 or redis.call("TTL", day_key) < 0 then
    redis.call("EXPIRE", day_key, day_ttl)
end

local blocked_window = ""
if rpm_limit > 0 and min_val > rpm_limit then
    blocked_window = "rpm"
elseif rpd_limit > 0 and day_val > rpd_limit then
    blocked_window = "rpd"
end

if blocked_window ~= "" then
    local rolled_min = redis.call("DECR", min_key)
    if rolled_min < 0 then
        redis.call("SET", min_key, 0, "EX", min_ttl)
        rolled_min = 0
    end
    local rolled_day = redis.call("DECR", day_key)
    if rolled_day < 0 then
        redis.call("SET", day_key, 0, "EX", day_ttl)
        rolled_day = 0
    end
    redis.call("HINCRBY", tel_key, "quota_blocked", 1)
    if redis.call("TTL", tel_key) < 0 then
        redis.call("EXPIRE", tel_key, tel_ttl)
    end
    return {0, blocked_window, rolled_min, rolled_day}
end

return {1, "", min_val, day_val}
"""

_OVERRIDDEN_SETTING_KEYS: Set[str] = set()


def _on_quota_setting_changed(*, setting: str, enter: bool, **kwargs: Any) -> None:
    if setting == "PROVIDER_QUOTA_LIMITS" or setting.endswith(("_RPM_LIMIT", "_DAILY_LIMIT")):
        if enter:
            _OVERRIDDEN_SETTING_KEYS.add(setting)
        else:
            _OVERRIDDEN_SETTING_KEYS.discard(setting)


setting_changed.connect(_on_quota_setting_changed, dispatch_uid="detector.quota_telemetry.setting_changed")


def _parse_non_negative_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        cleaned = value.strip()
        if re.fullmatch(r"\d+", cleaned):
            return int(cleaned)
    return None


def _is_valid_counter(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _decode_redis_str(raw_value: Any) -> Optional[str]:
    if isinstance(raw_value, bytes):
        return raw_value.decode("utf-8", errors="replace")
    return raw_value if isinstance(raw_value, str) else None


@dataclass(frozen=True)
class QuotaCheckResult:
    """Result returned by the atomic multi-window quota check."""

    allowed: bool
    window: Optional[str] = None
    used: int = 0
    limit: int = 0
    minute_used: int = 0
    minute_limit: int = 0
    daily_used: int = 0
    daily_limit: int = 0


@dataclass(frozen=True)
class RefreshRateLimitResult:
    """Outcome of per-user and global manual or endpoint rate-limit checks."""

    allowed: bool
    reason: Optional[str] = None
    retry_after_seconds: int = 0
    used: int = 0
    limit: int = 0


def is_provider_configured(provider_key: str) -> bool:
    """Returns True when the provider either needs no credentials or has one configured."""
    setting_name = PROVIDER_CREDENTIAL_SETTINGS.get(provider_key)
    if not setting_name:
        return True
    raw_value = os.environ.get(setting_name) or getattr(settings, setting_name, "")
    return isinstance(raw_value, str) and bool(raw_value.strip())


def get_provider_quota_limits(provider_key: str) -> Tuple[int, int]:
    """Resolves effective (rpm_limit, daily_limit) for a provider across settings and environment."""
    default_rpm, default_daily = DEFAULT_QUOTA_LIMITS.get(provider_key, (0, 0))
    prefix = provider_key.upper()
    rpm_name = f"{prefix}_RPM_LIMIT"
    daily_name = f"{prefix}_DAILY_LIMIT"

    setting_rpm = _parse_non_negative_int(getattr(settings, rpm_name, None))
    setting_daily = _parse_non_negative_int(getattr(settings, daily_name, None))
    current_dict = getattr(settings, "PROVIDER_QUOTA_LIMITS", None)
    dict_entry = current_dict.get(provider_key) if isinstance(current_dict, dict) else None
    dict_overridden = "PROVIDER_QUOTA_LIMITS" in _OVERRIDDEN_SETTING_KEYS

    def _resolve_window(setting_name: str, setting_val: Optional[int], dict_field: str, fallback: int) -> int:
        dict_val = _parse_non_negative_int(dict_entry.get(dict_field)) if isinstance(dict_entry, dict) else None
        if setting_name in _OVERRIDDEN_SETTING_KEYS and setting_val is not None:
            return setting_val
        if dict_overridden and dict_val is not None:
            return dict_val
        if setting_name in os.environ:
            env_val = _parse_non_negative_int(os.environ.get(setting_name))
            if env_val is not None:
                return env_val
        if setting_val is not None and setting_val != fallback:
            return setting_val
        if dict_val is not None and dict_val != fallback:
            return dict_val
        if setting_val is not None:
            return setting_val
        return fallback

    return (
        _resolve_window(rpm_name, setting_rpm, "rpm", default_rpm),
        _resolve_window(daily_name, setting_daily, "daily", default_daily),
    )


def _quota_minute_key(provider_key: str, now_dt: datetime) -> str:
    return f"{get_redis_namespace()}:quota:{provider_key}:min:{now_dt.strftime('%Y%m%d%H%M')}"


def _quota_daily_key(provider_key: str, now_dt: datetime) -> str:
    return f"{get_redis_namespace()}:quota:{provider_key}:day:{now_dt.strftime('%Y%m%d')}"


def _provider_telemetry_key(provider_key: str, now_dt: datetime) -> str:
    return f"{get_redis_namespace()}:telemetry:{provider_key}:day:{now_dt.strftime('%Y%m%d')}"


def _global_telemetry_key(now_dt: datetime) -> str:
    return f"{get_redis_namespace()}:telemetry:global:day:{now_dt.strftime('%Y%m%d')}"


_DAILY_RL_SALT_CACHE: Dict[str, Tuple[Any, str]] = {}

_ENDPOINT_RATE_LIMIT_SPECS: Dict[str, Tuple[int, int, Optional[str], str]] = {
    "detect": (120, 600, "DETECT_USER_RPM_LIMIT", "DETECT_GLOBAL_RPM_LIMIT"),
    "detect_batch": (20, 100, "DETECT_BATCH_USER_RPM_LIMIT", "DETECT_BATCH_GLOBAL_RPM_LIMIT"),
    "rangeblock": (120, 600, "RANGEBLOCK_USER_RPM_LIMIT", "RANGEBLOCK_GLOBAL_RPM_LIMIT"),
    "gadget_token": (15, 240, "GADGET_TOKEN_USER_RPM_LIMIT", "GADGET_TOKEN_GLOBAL_RPM_LIMIT"),
}


def hash_username_for_rate_limit(username: str, *, salt: Optional[str] = None) -> str:
    """Computes an anonymised HMAC-SHA256 digest for per-user rate-limit keys without storing usernames."""
    secret = str(salt if salt is not None else getattr(settings, "SECRET_KEY", "") or "proxycheck-default-secret")
    normalised = " ".join(str(username or "").strip().replace("_", " ").split())
    return hmac.new(secret.encode("utf-8"), normalised.encode("utf-8"), hashlib.sha256).hexdigest()[:24]


async def _get_daily_rate_limit_salt(client: Any, current_dt: datetime) -> str:
    salt_key = f"{get_redis_namespace()}:rl_salt:day:{current_dt.strftime('%Y%m%d')}"
    cached = _DAILY_RL_SALT_CACHE.get(salt_key)
    if cached is not None:
        cached_ref, cached_salt = cached
        if cached_ref is not None and cached_ref() is client:
            return cached_salt

    candidate = secrets.token_hex(16)
    set_fn = getattr(client, "set", None)
    if callable(set_fn):
        put_call = set_fn(salt_key, candidate, ex=DAILY_QUOTA_TTL_SECONDS, nx=True)
        if inspect.isawaitable(put_call):
            await put_call

    resolved = candidate
    get_fn = getattr(client, "get", None)
    if callable(get_fn):
        raw_call = get_fn(salt_key)
        raw_val = await raw_call if inspect.isawaitable(raw_call) else raw_call
        decoded = _decode_redis_str(raw_val)
        if isinstance(decoded, str) and decoded.strip():
            resolved = decoded.strip()

    try:
        client_ref = weakref.ref(client)
    except TypeError:
        client_ref = None
    if len(_DAILY_RL_SALT_CACHE) >= 8:
        _DAILY_RL_SALT_CACHE.pop(next(iter(_DAILY_RL_SALT_CACHE)))
    _DAILY_RL_SALT_CACHE[salt_key] = (client_ref, resolved)
    return resolved


def _build_blocked_result(
    blocked_window: str,
    minute_used: int,
    daily_used: int,
    rpm_limit: int,
    daily_limit: int,
) -> QuotaCheckResult:
    is_rpm = blocked_window == "rpm"
    return QuotaCheckResult(
        allowed=False,
        window="rpm" if is_rpm else "rpd",
        used=minute_used if is_rpm else daily_used,
        limit=rpm_limit if is_rpm else daily_limit,
        minute_used=minute_used,
        minute_limit=rpm_limit,
        daily_used=daily_used,
        daily_limit=daily_limit,
    )


async def _clamp_negative_quota_counters(
    pipeline_fn: Any,
    tracked_ops: List[Optional[Tuple[str, int]]],
    results: Any,
) -> None:
    if not tracked_ops or not isinstance(results, (list, tuple)):
        return
    negative_targets = [
        op_meta
        for op_meta, raw_val in zip(tracked_ops, results, strict=False)
        if op_meta is not None and _is_valid_counter(raw_val) and raw_val < 0
    ]
    if not negative_targets:
        return
    clamp_pipe = pipeline_fn(transaction=False)
    set_fn = getattr(clamp_pipe, "set", None)
    exec_fn = getattr(clamp_pipe, "execute", None)
    if not callable(set_fn) or not callable(exec_fn):
        return
    for key, ttl_seconds in negative_targets:
        set_fn(key, 0, ex=ttl_seconds)
    clamp_call = exec_fn()
    if inspect.isawaitable(clamp_call):
        await clamp_call


async def check_and_consume_quota(
    provider_key: str,
    *,
    now_dt: Optional[datetime] = None,
) -> QuotaCheckResult:
    """
    Atomically increments minute and daily quota windows in Redis and rolls back both
    counters when either configured limit is exceeded. Fails open if Redis is unavailable.
    """
    rpm_limit, daily_limit = get_provider_quota_limits(provider_key)
    client = get_redis_client()
    if client is None:
        return QuotaCheckResult(allowed=True, minute_limit=rpm_limit, daily_limit=daily_limit)

    current_dt = now_dt or datetime.now(timezone.utc)
    min_key = _quota_minute_key(provider_key, current_dt)
    day_key = _quota_daily_key(provider_key, current_dt)
    tel_key = _provider_telemetry_key(provider_key, current_dt)

    eval_fn = getattr(client, "eval", None)
    if callable(eval_fn):
        try:
            call_result = eval_fn(
                _QUOTA_CONSUME_LUA,
                3,
                min_key,
                day_key,
                tel_key,
                rpm_limit,
                daily_limit,
                MINUTE_QUOTA_TTL_SECONDS,
                DAILY_QUOTA_TTL_SECONDS,
                TELEMETRY_TTL_SECONDS,
            )
            if inspect.isawaitable(call_result):
                raw_res = await call_result
                if isinstance(raw_res, (list, tuple)) and len(raw_res) == 4:
                    allowed_flag, raw_window, raw_min, raw_day = raw_res
                    if _is_valid_counter(allowed_flag):
                        minute_used = int(raw_min) if _is_valid_counter(raw_min) else 0
                        daily_used = int(raw_day) if _is_valid_counter(raw_day) else 0
                        if allowed_flag == 1:
                            return QuotaCheckResult(
                                allowed=True,
                                minute_used=minute_used,
                                minute_limit=rpm_limit,
                                daily_used=daily_used,
                                daily_limit=daily_limit,
                            )
                        window_str = raw_window.decode("utf-8") if isinstance(raw_window, bytes) else str(raw_window)
                        return _build_blocked_result(
                            "rpm" if window_str == "rpm" else "rpd",
                            minute_used,
                            daily_used,
                            rpm_limit,
                            daily_limit,
                        )
        except NotImplementedError:
            pass
        except REDIS_TRANSPORT_ERRORS as exc:
            mark_redis_failure(exc)
            logger.warning("Quota Lua check bypassed for %s due to Redis error (%s)", provider_key, type(exc).__name__)
            return QuotaCheckResult(allowed=True, minute_limit=rpm_limit, daily_limit=daily_limit)

    pipeline_fn = getattr(client, "pipeline", None)
    if not callable(pipeline_fn):
        return QuotaCheckResult(allowed=True, minute_limit=rpm_limit, daily_limit=daily_limit)

    try:
        pipe = pipeline_fn(transaction=True)
        ttl_fn = getattr(pipe, "ttl", None)
        supports_ttl = callable(ttl_fn)
        pipe.incr(min_key)
        if supports_ttl:
            ttl_fn(min_key)
        pipe.incr(day_key)
        if supports_ttl:
            ttl_fn(day_key)

        exec_call = pipe.execute()
        if not inspect.isawaitable(exec_call):
            return QuotaCheckResult(allowed=True, minute_limit=rpm_limit, daily_limit=daily_limit)
        results = await exec_call
        min_len = 4 if supports_ttl else 2
        if not isinstance(results, (list, tuple)) or len(results) < min_len:
            return QuotaCheckResult(allowed=True, minute_limit=rpm_limit, daily_limit=daily_limit)

        min_val = results[0]
        day_val = results[2] if supports_ttl else results[1]
        if not _is_valid_counter(min_val) or not _is_valid_counter(day_val):
            return QuotaCheckResult(allowed=True, minute_limit=rpm_limit, daily_limit=daily_limit)

        min_ttl = results[1] if supports_ttl else (-1 if min_val == 1 else MINUTE_QUOTA_TTL_SECONDS)
        day_ttl = results[3] if supports_ttl else (-1 if day_val == 1 else DAILY_QUOTA_TTL_SECONDS)
        need_min_expire = min_val <= 1 or (_is_valid_counter(min_ttl) and min_ttl < 0)
        need_day_expire = day_val <= 1 or (_is_valid_counter(day_ttl) and day_ttl < 0)

        blocked_window: Optional[str] = None
        if rpm_limit > 0 and min_val > rpm_limit:
            blocked_window = "rpm"
        elif daily_limit > 0 and day_val > daily_limit:
            blocked_window = "rpd"

        if blocked_window is None:
            if need_min_expire or need_day_expire:
                exp_pipe = pipeline_fn(transaction=False)
                if need_min_expire:
                    exp_pipe.expire(min_key, MINUTE_QUOTA_TTL_SECONDS)
                if need_day_expire:
                    exp_pipe.expire(day_key, DAILY_QUOTA_TTL_SECONDS)
                exp_call = exp_pipe.execute()
                if inspect.isawaitable(exp_call):
                    await exp_call
            return QuotaCheckResult(
                allowed=True,
                minute_used=min_val,
                minute_limit=rpm_limit,
                daily_used=day_val,
                daily_limit=daily_limit,
            )

        rb_pipe = pipeline_fn(transaction=True)
        rb_pipe.decr(min_key)
        rb_pipe.decr(day_key)
        if need_min_expire:
            rb_pipe.expire(min_key, MINUTE_QUOTA_TTL_SECONDS)
        if need_day_expire:
            rb_pipe.expire(day_key, DAILY_QUOTA_TTL_SECONDS)
        rb_pipe.hincrby(tel_key, "quota_blocked", 1)
        rb_pipe.expire(tel_key, TELEMETRY_TTL_SECONDS)

        rolled_min = max(0, min_val - 1)
        rolled_day = max(0, day_val - 1)
        rb_exec = rb_pipe.execute()
        if inspect.isawaitable(rb_exec):
            rb_res = await rb_exec
            if isinstance(rb_res, (list, tuple)) and len(rb_res) >= 2:
                if _is_valid_counter(rb_res[0]):
                    rolled_min = max(0, rb_res[0])
                if _is_valid_counter(rb_res[1]):
                    rolled_day = max(0, rb_res[1])
                await _clamp_negative_quota_counters(
                    pipeline_fn,
                    [(min_key, MINUTE_QUOTA_TTL_SECONDS), (day_key, DAILY_QUOTA_TTL_SECONDS)],
                    rb_res[:2],
                )
        return _build_blocked_result(blocked_window, rolled_min, rolled_day, rpm_limit, daily_limit)
    except REDIS_TRANSPORT_ERRORS as exc:
        mark_redis_failure(exc)
        logger.warning("Quota pipeline check bypassed for %s due to Redis error (%s)", provider_key, type(exc).__name__)
        return QuotaCheckResult(allowed=True, minute_limit=rpm_limit, daily_limit=daily_limit)


def extract_upstream_rate_limit(
    resp: Any,
    payload: Any = None,
    provider_key: str = "",
) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """
    Extracts non-negative integer rate-limit metadata from standard upstream HTTP headers
    or IPData response bodies. Returns (upstream_remaining, upstream_limit, upstream_used).
    """
    headers = getattr(resp, "headers", None)
    normalised_headers: Dict[str, Any] = {}
    items_fn = getattr(headers, "items", None) if headers is not None else None
    if callable(items_fn):
        try:
            raw_items = items_fn()
            if isinstance(raw_items, Iterable):
                for key, value in raw_items:
                    if isinstance(key, str):
                        normalised_headers[key.strip().lower()] = value
        except AttributeError, TypeError, ValueError:
            normalised_headers = {}

    getter = getattr(headers, "get", None)

    def _lookup(candidates: Tuple[str, ...]) -> Optional[int]:
        for header_name in candidates:
            if header_name in normalised_headers:
                parsed = _parse_non_negative_int(normalised_headers[header_name])
                if parsed is not None:
                    return parsed
            if callable(getter):
                for variant in (header_name, header_name.title()):
                    parsed = _parse_non_negative_int(getter(variant))
                    if parsed is not None:
                        return parsed
        return None

    upstream_remaining = _lookup(("x-ratelimit-remaining", "ratelimit-remaining", "x-rate-limit-remaining"))
    upstream_limit = _lookup(("x-ratelimit-limit", "ratelimit-limit", "x-rate-limit-limit"))
    upstream_used: Optional[int] = None

    if provider_key == "ipdata" and isinstance(payload, dict):
        upstream_used = _parse_non_negative_int(payload.get("count"))
        if upstream_used is not None and upstream_remaining is None:
            _, configured_daily = get_provider_quota_limits("ipdata")
            effective_limit = upstream_limit if upstream_limit is not None else (configured_daily or None)
            if effective_limit is not None and effective_limit > 0:
                upstream_limit = effective_limit
                upstream_remaining = max(0, effective_limit - upstream_used)

    return upstream_remaining, upstream_limit, upstream_used


async def record_provider_outcomes_batch(
    entries: List[Dict[str, Any]],
    *,
    now_dt: Optional[datetime] = None,
) -> None:
    """Records multiple per-provider outcomes and optional quota refunds in one Redis pipeline."""
    if not entries:
        return
    client = get_redis_client()
    if client is None:
        return
    pipeline_fn = getattr(client, "pipeline", None)
    if not callable(pipeline_fn):
        return

    current_dt = now_dt or datetime.now(timezone.utc)
    try:
        pipe = pipeline_fn(transaction=False)
        tracked_ops: List[Optional[Tuple[str, int]]] = []
        queued = False
        decr_fn = getattr(pipe, "decr", None)

        for entry in entries:
            outcome = entry.get("outcome")
            provider_key = entry.get("provider_key")
            refund_quota = bool(entry.get("refund_quota", False))
            if not provider_key:
                continue

            if outcome in VALID_PROVIDER_OUTCOMES:
                queued = True
                tel_key = _provider_telemetry_key(provider_key, current_dt)
                pipe.hincrby(tel_key, outcome, 1)
                tracked_ops.append(None)

                fields: Dict[str, str] = {}
                if outcome in {"ok", "429", "5xx", "timeout"}:
                    fields["last_status_at"] = current_dt.isoformat()
                if entry.get("upstream_remaining") is not None:
                    fields["upstream_remaining"] = str(entry["upstream_remaining"])
                if entry.get("upstream_limit") is not None:
                    fields["upstream_limit"] = str(entry["upstream_limit"])
                if entry.get("upstream_used") is not None:
                    fields["upstream_used"] = str(entry["upstream_used"])
                if fields:
                    pipe.hset(tel_key, mapping=fields)
                    tracked_ops.append(None)

                pipe.expire(tel_key, TELEMETRY_TTL_SECONDS)
                tracked_ops.append(None)

            if refund_quota and PROVIDER_QUOTA_SPECS.get(provider_key) is not None and callable(decr_fn):
                queued = True
                min_key = _quota_minute_key(provider_key, current_dt)
                day_key = _quota_daily_key(provider_key, current_dt)
                decr_fn(min_key)
                decr_fn(day_key)
                tracked_ops.append((min_key, MINUTE_QUOTA_TTL_SECONDS))
                tracked_ops.append((day_key, DAILY_QUOTA_TTL_SECONDS))

        if not queued:
            return
        exec_call = pipe.execute()
        results = await exec_call if inspect.isawaitable(exec_call) else None
        await _clamp_negative_quota_counters(pipeline_fn, tracked_ops, results)
    except REDIS_TRANSPORT_ERRORS as exc:
        mark_redis_failure(exc)
        logger.warning("Batch telemetry write bypassed due to Redis error (%s)", type(exc).__name__)


async def record_global_request_telemetry(
    cache_status: str,
    auth_mode: str,
    *,
    cache_layer_event: Optional[str] = None,
    now_dt: Optional[datetime] = None,
) -> None:
    """Records anonymised daily global cache-efficiency, dual-layer SWR, and authentication-mode counters."""
    cache_field = {"hit": "cache_hit", "stale": "cache_hit", "partial": "cache_partial", "miss": "cache_miss"}.get(
        cache_status
    )
    auth_field = {"session": "auth_session", "gadget": "auth_gadget"}.get(auth_mode)
    layer_field = cache_layer_event if cache_layer_event in VALID_CACHE_TELEMETRY_EVENTS else None
    fields_to_inc = [f for f in (cache_field, auth_field, layer_field) if f]
    if not fields_to_inc:
        return

    client = get_redis_client()
    if client is None:
        return

    current_dt = now_dt or datetime.now(timezone.utc)
    global_key = _global_telemetry_key(current_dt)
    try:
        pipeline_fn = getattr(client, "pipeline", None)
        if callable(pipeline_fn):
            pipe = pipeline_fn(transaction=False)
            for field_name in fields_to_inc:
                pipe.hincrby(global_key, field_name, 1)
            pipe.expire(global_key, TELEMETRY_TTL_SECONDS)
            exec_call = pipe.execute()
            if inspect.isawaitable(exec_call):
                await exec_call
            return

        hincrby_fn = getattr(client, "hincrby", None)
        if callable(hincrby_fn):
            for field_name in fields_to_inc:
                pending = hincrby_fn(global_key, field_name, 1)
                if inspect.isawaitable(pending):
                    await pending
            expire_fn = getattr(client, "expire", None)
            if callable(expire_fn):
                exp_pending = expire_fn(global_key, TELEMETRY_TTL_SECONDS)
                if inspect.isawaitable(exp_pending):
                    await exp_pending
    except REDIS_TRANSPORT_ERRORS as exc:
        mark_redis_failure(exc)
        logger.warning("Global telemetry write bypassed due to Redis error (%s)", type(exc).__name__)


async def record_cache_telemetry_event(
    event_name: str,
    *,
    count: int = 1,
    now_dt: Optional[datetime] = None,
) -> None:
    """Increments a daily dual-layer cache or refresh telemetry counter in Redis."""
    if event_name not in VALID_CACHE_TELEMETRY_EVENTS or count <= 0:
        return
    client = get_redis_client()
    if client is None:
        return

    current_dt = now_dt or datetime.now(timezone.utc)
    global_key = _global_telemetry_key(current_dt)
    try:
        pipeline_fn = getattr(client, "pipeline", None)
        if callable(pipeline_fn):
            pipe = pipeline_fn(transaction=False)
            pipe.hincrby(global_key, event_name, int(count))
            pipe.expire(global_key, TELEMETRY_TTL_SECONDS)
            exec_call = pipe.execute()
            if inspect.isawaitable(exec_call):
                await exec_call
            return

        hincrby_fn = getattr(client, "hincrby", None)
        if callable(hincrby_fn):
            pending = hincrby_fn(global_key, event_name, int(count))
            if inspect.isawaitable(pending):
                await pending
    except REDIS_TRANSPORT_ERRORS as exc:
        mark_redis_failure(exc)
        logger.warning("Cache telemetry write bypassed due to Redis error (%s)", type(exc).__name__)


async def _consume_rate_limit_windows(
    client: Any,
    windows: List[Tuple[str, int, int, str, int]],
    current_dt: datetime,
    *,
    telemetry_event: Optional[str],
) -> RefreshRateLimitResult:
    incremented_keys: List[Tuple[str, int]] = []
    incr_fn = getattr(client, "incr", None)
    decr_fn = getattr(client, "decr", None)
    get_fn = getattr(client, "get", None)
    set_fn = getattr(client, "set", None)
    expire_fn = getattr(client, "expire", None)

    for key, ttl_seconds, limit, reason, retry_after_seconds in windows:
        if limit <= 0:
            continue

        val: Optional[int] = None
        if callable(incr_fn):
            pending = incr_fn(key)
            raw_val = await pending if inspect.isawaitable(pending) else pending
            if _is_valid_counter(raw_val):
                val = raw_val
                if val == 1 and callable(expire_fn):
                    exp = expire_fn(key, ttl_seconds)
                    if inspect.isawaitable(exp):
                        await exp
        if val is None and callable(get_fn) and callable(set_fn):
            raw_cur = get_fn(key)
            cur = await raw_cur if inspect.isawaitable(raw_cur) else raw_cur
            cur_num = _parse_non_negative_int(_decode_redis_str(cur) if isinstance(cur, bytes) else cur) or 0
            val = cur_num + 1
            put_call = set_fn(key, str(val), ex=ttl_seconds)
            if inspect.isawaitable(put_call):
                await put_call

        if val is None:
            continue

        incremented_keys.append((key, ttl_seconds))
        if val <= limit:
            continue

        for rk, rttl in incremented_keys:
            if callable(decr_fn):
                pending = decr_fn(rk)
                dec_val = await pending if inspect.isawaitable(pending) else pending
                if _is_valid_counter(dec_val) and dec_val < 0 and callable(set_fn):
                    put_call = set_fn(rk, "0", ex=rttl)
                    if inspect.isawaitable(put_call):
                        await put_call
            elif callable(get_fn) and callable(set_fn):
                raw_cur = get_fn(rk)
                cur = await raw_cur if inspect.isawaitable(raw_cur) else raw_cur
                cur_num = _parse_non_negative_int(_decode_redis_str(cur) if isinstance(cur, bytes) else cur) or 0
                put_call = set_fn(rk, str(max(0, cur_num - 1)), ex=rttl)
                if inspect.isawaitable(put_call):
                    await put_call

        if telemetry_event:
            await record_cache_telemetry_event(telemetry_event, now_dt=current_dt)
        return RefreshRateLimitResult(
            allowed=False,
            reason=reason,
            retry_after_seconds=retry_after_seconds,
            used=limit,
            limit=limit,
        )

    return RefreshRateLimitResult(allowed=True)


async def check_and_consume_refresh_rate_limit(
    username: Optional[str],
    *,
    is_admin: bool = False,
    now_dt: Optional[datetime] = None,
) -> RefreshRateLimitResult:
    """Enforces anonymised per-user (6/min, 60/hr) and global (30/min) refresh rate limits."""
    client = get_redis_client()
    if client is None:
        return RefreshRateLimitResult(allowed=True)

    current_dt = now_dt or datetime.now(timezone.utc)
    user_rpm_opt = _parse_non_negative_int(getattr(settings, "REFRESH_USER_RPM_LIMIT", None))
    user_rph_opt = _parse_non_negative_int(getattr(settings, "REFRESH_USER_RPH_LIMIT", None))
    global_rpm_opt = _parse_non_negative_int(getattr(settings, "REFRESH_GLOBAL_RPM_LIMIT", None))
    user_rpm_limit = DEFAULT_REFRESH_USER_RPM_LIMIT if user_rpm_opt is None else user_rpm_opt
    user_rph_limit = DEFAULT_REFRESH_USER_RPH_LIMIT if user_rph_opt is None else user_rph_opt
    global_rpm_limit = DEFAULT_REFRESH_GLOBAL_RPM_LIMIT if global_rpm_opt is None else global_rpm_opt

    cleaned_user = str(username or "").strip()
    ns = get_redis_namespace()
    min_retry = max(1, 60 - current_dt.second)
    hr_retry = max(60, 3600 - (current_dt.minute * 60 + current_dt.second))
    min_bucket = current_dt.strftime("%Y%m%d%H%M")
    hr_bucket = current_dt.strftime("%Y%m%d%H")

    try:
        windows: List[Tuple[str, int, int, str, int]] = []
        if not bool(is_admin) and cleaned_user:
            daily_salt = await _get_daily_rate_limit_salt(client, current_dt)
            user_digest = hash_username_for_rate_limit(cleaned_user, salt=daily_salt)
            windows.append(
                (
                    f"{ns}:refresh_rl:user:{user_digest}:min:{min_bucket}",
                    MINUTE_QUOTA_TTL_SECONDS,
                    user_rpm_limit,
                    "user_rpm",
                    min_retry,
                )
            )
            windows.append(
                (
                    f"{ns}:refresh_rl:user:{user_digest}:hr:{hr_bucket}",
                    HOURLY_QUOTA_TTL_SECONDS,
                    user_rph_limit,
                    "user_rph",
                    hr_retry,
                )
            )
        windows.append(
            (
                f"{ns}:refresh_rl:global:min:{min_bucket}",
                MINUTE_QUOTA_TTL_SECONDS,
                global_rpm_limit,
                "global_rpm",
                min_retry,
            )
        )
        return await _consume_rate_limit_windows(client, windows, current_dt, telemetry_event="refresh_rate_limited")
    except REDIS_TRANSPORT_ERRORS as exc:
        mark_redis_failure(exc)
        logger.warning("Refresh rate-limit check bypassed due to Redis error (%s)", type(exc).__name__)
        return RefreshRateLimitResult(allowed=True)


async def check_and_consume_endpoint_rate_limit(
    endpoint: str,
    username: Optional[str] = None,
    *,
    scope: str = "all",
    now_dt: Optional[datetime] = None,
) -> RefreshRateLimitResult:
    """Enforces short-lived volatile Redis per-minute limits for detect, batch, and gadget-token endpoints."""
    if scope not in {"all", "global", "user"}:
        raise ValueError(f"Unsupported rate-limit scope: {scope!r}")
    spec = _ENDPOINT_RATE_LIMIT_SPECS.get(endpoint)
    if spec is None:
        return RefreshRateLimitResult(allowed=True)
    client = get_redis_client()
    if client is None:
        return RefreshRateLimitResult(allowed=True)

    default_user_rpm, default_global_rpm, user_setting, global_setting = spec
    override_user = _parse_non_negative_int(getattr(settings, user_setting, None)) if user_setting else None
    user_rpm = override_user if override_user is not None else default_user_rpm
    override_global = _parse_non_negative_int(getattr(settings, global_setting, None))
    global_rpm = override_global if override_global is not None else default_global_rpm

    current_dt = now_dt or datetime.now(timezone.utc)
    min_retry = max(1, 60 - current_dt.second)
    minute_bucket = current_dt.strftime("%Y%m%d%H%M")
    ns = get_redis_namespace()
    cleaned_user = str(username or "").strip()

    try:
        windows: List[Tuple[str, int, int, str, int]] = []
        if scope in {"all", "user"} and user_rpm > 0 and cleaned_user:
            daily_salt = await _get_daily_rate_limit_salt(client, current_dt)
            user_digest = hash_username_for_rate_limit(cleaned_user, salt=daily_salt)
            windows.append(
                (
                    f"{ns}:rl:{endpoint}:user:{user_digest}:min:{minute_bucket}",
                    MINUTE_QUOTA_TTL_SECONDS,
                    user_rpm,
                    f"{endpoint}_user_rpm",
                    min_retry,
                )
            )
        if scope in {"all", "global"} and global_rpm > 0:
            windows.append(
                (
                    f"{ns}:rl:{endpoint}:global:min:{minute_bucket}",
                    MINUTE_QUOTA_TTL_SECONDS,
                    global_rpm,
                    f"{endpoint}_global_rpm",
                    min_retry,
                )
            )
        return await _consume_rate_limit_windows(client, windows, current_dt, telemetry_event=None)
    except REDIS_TRANSPORT_ERRORS as exc:
        mark_redis_failure(exc)
        logger.warning("Endpoint rate-limit check bypassed due to Redis error (%s)", type(exc).__name__)
        return RefreshRateLimitResult(allowed=True)


async def should_suppress_auto_refresh_for_quota(
    age_seconds: int,
    *,
    now_dt: Optional[datetime] = None,
) -> bool:
    """
    Returns True when background stale-while-revalidate should be paused for records younger
    than 180 days because configured commercial providers have less than 15% daily quota left.
    """
    max_age_days = _parse_non_negative_int(getattr(settings, "COMMERCIAL_QUOTA_SWR_MAX_AGE_DAYS", None))
    effective_max_days = DEFAULT_COMMERCIAL_SWR_GUARD_MAX_AGE_DAYS if max_age_days is None else max_age_days
    if age_seconds >= effective_max_days * 86400:
        return False

    raw_ratio = getattr(settings, "COMMERCIAL_QUOTA_SWR_GUARD_RATIO", DEFAULT_COMMERCIAL_SWR_GUARD_RATIO)
    guard_ratio = (
        float(raw_ratio)
        if isinstance(raw_ratio, (int, float)) and not isinstance(raw_ratio, bool) and 0.0 < float(raw_ratio) < 1.0
        else DEFAULT_COMMERCIAL_SWR_GUARD_RATIO
    )

    tracked: List[Tuple[str, int]] = []
    for meta in PROVIDER_REGISTRY:
        if not meta.is_commercial_arbitration or not is_provider_configured(meta.key):
            continue
        _, daily_limit = get_provider_quota_limits(meta.key)
        if daily_limit > 0:
            tracked.append((meta.key, daily_limit))

    if not tracked or get_redis_client() is None:
        return False

    current_dt = now_dt or datetime.now(timezone.utc)
    day_keys = [_quota_daily_key(provider_key, current_dt) for provider_key, _ in tracked]
    raw_values = await safe_redis_mget(day_keys)
    total_limit = sum(limit for _, limit in tracked)
    if total_limit <= 0:
        return False

    total_remaining = sum(
        max(0, limit - (_parse_non_negative_int(raw_val) or 0))
        for (_, limit), raw_val in zip(tracked, raw_values, strict=True)
    )
    return (total_remaining / float(total_limit)) < guard_ratio
