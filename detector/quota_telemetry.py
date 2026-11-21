"""
Proactive multi-window API quota guard and strictly anonymised Redis telemetry.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
import json
import logging
import os
import re
import secrets
import weakref
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from asgiref.sync import sync_to_async
from django.conf import settings
from django.core.signals import setting_changed
from django.db import Error as DjangoDbError
from django.db import close_old_connections, connections

from .cache_backends import (
    get_redis_client,
    get_redis_namespace,
    mark_redis_failure,
    provider_cooldown_key,
    safe_redis_mget,
)
from .models import IpIntelligenceCache
from .oauth import is_allowlisted_wiki_user
from .offline_dbs import collect_offline_databases_status
from .provider_registry import (
    DEFAULT_QUOTA_LIMITS,
    PROVIDER_CREDENTIAL_SETTINGS,
    PROVIDER_REGISTRY,
    REDIS_TRANSPORT_ERRORS,
    ProviderMetadata,
)

logger = logging.getLogger(__name__)
_get_redis_client = get_redis_client

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
    """Tracks active Django test setting overrides without mutating import-time baselines."""
    if setting == "PROVIDER_QUOTA_LIMITS" or setting.endswith(("_RPM_LIMIT", "_DAILY_LIMIT")):
        if enter:
            _OVERRIDDEN_SETTING_KEYS.add(setting)
        else:
            _OVERRIDDEN_SETTING_KEYS.discard(setting)


setting_changed.connect(_on_quota_setting_changed, dispatch_uid="detector.quota_telemetry.setting_changed")


def _parse_non_negative_int(value: Any) -> Optional[int]:
    """Parses a non-negative integer value and rejects booleans and invalid text."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        cleaned = value.strip()
        if re.fullmatch(r"\d+", cleaned):
            return int(cleaned)
    return None


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


def is_provider_configured(provider_key: str) -> bool:
    """Returns True when the provider either needs no credentials or has one configured."""
    setting_name = PROVIDER_CREDENTIAL_SETTINGS.get(provider_key)
    if not setting_name:
        return True
    raw_value = os.environ.get(setting_name) or getattr(settings, setting_name, "")
    return isinstance(raw_value, str) and bool(raw_value.strip())


def get_provider_quota_limits(provider_key: str) -> Tuple[int, int]:
    """
    Resolves effective (rpm_limit, daily_limit) for a provider, honouring Django
    override_settings on individual limits or PROVIDER_QUOTA_LIMITS as well as os.environ.
    """
    default_rpm, default_daily = DEFAULT_QUOTA_LIMITS.get(provider_key, (0, 0))
    prefix = provider_key.upper()
    rpm_name = f"{prefix}_RPM_LIMIT"
    daily_name = f"{prefix}_DAILY_LIMIT"

    setting_rpm = _parse_non_negative_int(getattr(settings, rpm_name, None))
    setting_daily = _parse_non_negative_int(getattr(settings, daily_name, None))

    current_dict = getattr(settings, "PROVIDER_QUOTA_LIMITS", None)
    dict_entry = current_dict.get(provider_key) if isinstance(current_dict, dict) else None
    dict_overridden = "PROVIDER_QUOTA_LIMITS" in _OVERRIDDEN_SETTING_KEYS

    def _resolve_window(
        setting_name: str,
        setting_val: Optional[int],
        dict_field: str,
        fallback: int,
    ) -> int:
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


def is_admin_user(session_user: Any) -> bool:
    """
    Returns True only when an authenticated session user holds active access
    and their username appears in ALLOWED_WIKI_USERS.
    """
    if not isinstance(session_user, dict):
        return False
    if not session_user.get("isLoggedIn") or not session_user.get("hasAccess"):
        return False
    username = str(session_user.get("username") or "").strip()
    if not username or username.startswith("~"):
        return False
    return is_allowlisted_wiki_user(username)


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
    normalized = " ".join(str(username or "").strip().replace("_", " ").split())
    return hmac.new(secret.encode("utf-8"), normalized.encode("utf-8"), hashlib.sha256).hexdigest()[:24]


async def _get_daily_rate_limit_salt(client: Any, current_dt: datetime) -> str:
    """Fetches or lazily creates a volatile daily random salt in Redis without persisting usernames."""
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


def _refresh_user_minute_key(user_digest: str, now_dt: datetime) -> str:
    return f"{get_redis_namespace()}:refresh_rl:user:{user_digest}:min:{now_dt.strftime('%Y%m%d%H%M')}"


def _refresh_user_hour_key(user_digest: str, now_dt: datetime) -> str:
    return f"{get_redis_namespace()}:refresh_rl:user:{user_digest}:hr:{now_dt.strftime('%Y%m%d%H')}"


def _refresh_global_minute_key(now_dt: datetime) -> str:
    return f"{get_redis_namespace()}:refresh_rl:global:min:{now_dt.strftime('%Y%m%d%H%M')}"


@dataclass(frozen=True)
class RefreshRateLimitResult:
    """Outcome of per-user and global manual or background refresh rate-limit checks."""

    allowed: bool
    reason: Optional[str] = None
    retry_after_seconds: int = 0
    used: int = 0
    limit: int = 0


def _build_blocked_result(
    blocked_window: str,
    minute_used: int,
    daily_used: int,
    rpm_limit: int,
    daily_limit: int,
) -> QuotaCheckResult:
    if blocked_window == "rpm":
        return QuotaCheckResult(
            allowed=False,
            window="rpm",
            used=minute_used,
            limit=rpm_limit,
            minute_used=minute_used,
            minute_limit=rpm_limit,
            daily_used=daily_used,
            daily_limit=daily_limit,
        )
    return QuotaCheckResult(
        allowed=False,
        window="rpd",
        used=daily_used,
        limit=daily_limit,
        minute_used=minute_used,
        minute_limit=rpm_limit,
        daily_used=daily_used,
        daily_limit=daily_limit,
    )


async def _run_quota_lua(
    client: Any,
    min_key: str,
    day_key: str,
    tel_key: str,
    rpm_limit: int,
    daily_limit: int,
) -> Optional[QuotaCheckResult]:
    eval_fn = getattr(client, "eval", None)
    if not callable(eval_fn):
        return None
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
    if not inspect.isawaitable(call_result):
        return None
    raw_res = await call_result
    if not isinstance(raw_res, (list, tuple)) or len(raw_res) != 4:
        return None
    allowed_flag, raw_window, raw_min, raw_day = raw_res
    if isinstance(allowed_flag, bool) or not isinstance(allowed_flag, int):
        return None
    minute_used = int(raw_min) if isinstance(raw_min, int) and not isinstance(raw_min, bool) else 0
    daily_used = int(raw_day) if isinstance(raw_day, int) and not isinstance(raw_day, bool) else 0
    if allowed_flag == 1:
        return QuotaCheckResult(
            allowed=True,
            minute_used=minute_used,
            minute_limit=rpm_limit,
            daily_used=daily_used,
            daily_limit=daily_limit,
        )
    window_str = raw_window.decode("utf-8") if isinstance(raw_window, bytes) else str(raw_window)
    blocked_window = "rpm" if window_str == "rpm" else "rpd"
    return _build_blocked_result(blocked_window, minute_used, daily_used, rpm_limit, daily_limit)


def _needs_window_expiry(counter_val: int, observed_ttl: Any) -> bool:
    if counter_val <= 1:
        return True
    return isinstance(observed_ttl, int) and not isinstance(observed_ttl, bool) and observed_ttl < 0


def _is_valid_counter(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


async def _increment_quota_windows_via_pipeline(
    pipeline_fn: Any,
    min_key: str,
    day_key: str,
) -> Optional[Tuple[int, int, bool, bool]]:
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
        return None
    results = await exec_call
    min_len = 4 if supports_ttl else 2
    if not isinstance(results, (list, tuple)) or len(results) < min_len:
        return None

    min_val = results[0]
    day_val = results[2] if supports_ttl else results[1]
    if not _is_valid_counter(min_val) or not _is_valid_counter(day_val):
        return None

    min_ttl = results[1] if supports_ttl else (-1 if min_val == 1 else MINUTE_QUOTA_TTL_SECONDS)
    day_ttl = results[3] if supports_ttl else (-1 if day_val == 1 else DAILY_QUOTA_TTL_SECONDS)
    return (
        min_val,
        day_val,
        _needs_window_expiry(min_val, min_ttl),
        _needs_window_expiry(day_val, day_ttl),
    )


async def _rollback_quota_pipeline(
    pipeline_fn: Any,
    min_key: str,
    day_key: str,
    tel_key: str,
    min_val: int,
    day_val: int,
    *,
    need_min_expire: bool,
    need_day_expire: bool,
) -> Tuple[int, int]:
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
    if not inspect.isawaitable(rb_exec):
        return rolled_min, rolled_day

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
    return rolled_min, rolled_day


async def _run_quota_pipeline(
    client: Any,
    min_key: str,
    day_key: str,
    tel_key: str,
    rpm_limit: int,
    daily_limit: int,
) -> Optional[QuotaCheckResult]:
    pipeline_fn = getattr(client, "pipeline", None)
    if not callable(pipeline_fn):
        return None
    incremented = await _increment_quota_windows_via_pipeline(pipeline_fn, min_key, day_key)
    if incremented is None:
        return None
    min_val, day_val, need_min_expire, need_day_expire = incremented

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

    rolled_min, rolled_day = await _rollback_quota_pipeline(
        pipeline_fn,
        min_key,
        day_key,
        tel_key,
        min_val,
        day_val,
        need_min_expire=need_min_expire,
        need_day_expire=need_day_expire,
    )
    return _build_blocked_result(blocked_window, rolled_min, rolled_day, rpm_limit, daily_limit)


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
    client = _get_redis_client()
    if client is None:
        return QuotaCheckResult(allowed=True, minute_limit=rpm_limit, daily_limit=daily_limit)

    current_dt = now_dt or datetime.now(timezone.utc)
    min_key = _quota_minute_key(provider_key, current_dt)
    day_key = _quota_daily_key(provider_key, current_dt)
    tel_key = _provider_telemetry_key(provider_key, current_dt)

    try:
        lua_result = await _run_quota_lua(client, min_key, day_key, tel_key, rpm_limit, daily_limit)
        if lua_result is not None:
            return lua_result
    except NotImplementedError:
        pass
    except REDIS_TRANSPORT_ERRORS as exc:
        mark_redis_failure(exc)
        logger.warning(f"Quota Lua check bypassed for {provider_key} due to Redis error ({type(exc).__name__})")
        return QuotaCheckResult(allowed=True, minute_limit=rpm_limit, daily_limit=daily_limit)

    try:
        pipe_result = await _run_quota_pipeline(client, min_key, day_key, tel_key, rpm_limit, daily_limit)
        if pipe_result is not None:
            return pipe_result
    except REDIS_TRANSPORT_ERRORS as exc:
        mark_redis_failure(exc)
        logger.warning(f"Quota pipeline check bypassed for {provider_key} due to Redis error ({type(exc).__name__})")

    return QuotaCheckResult(allowed=True, minute_limit=rpm_limit, daily_limit=daily_limit)


def _normalize_response_headers(headers: Any) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    if headers is None:
        return normalized
    items_fn = getattr(headers, "items", None)
    if not callable(items_fn):
        return normalized
    try:
        raw_items = items_fn()
        if isinstance(raw_items, Iterable):
            for key, value in raw_items:
                if isinstance(key, str):
                    normalized[key.strip().lower()] = value
    except AttributeError, TypeError, ValueError:
        return {}
    return normalized


def _lookup_int_header(
    headers: Any,
    normalized_headers: Dict[str, Any],
    candidates: Tuple[str, ...],
) -> Optional[int]:
    getter = getattr(headers, "get", None)
    for header_name in candidates:
        if header_name in normalized_headers:
            parsed = _parse_non_negative_int(normalized_headers[header_name])
            if parsed is not None:
                return parsed
        if callable(getter):
            for variant in (header_name, header_name.title()):
                parsed = _parse_non_negative_int(getter(variant))
                if parsed is not None:
                    return parsed
    return None


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
    normalized_headers = _normalize_response_headers(headers)

    upstream_remaining = _lookup_int_header(
        headers, normalized_headers, ("x-ratelimit-remaining", "ratelimit-remaining", "x-rate-limit-remaining")
    )
    upstream_limit = _lookup_int_header(
        headers, normalized_headers, ("x-ratelimit-limit", "ratelimit-limit", "x-rate-limit-limit")
    )
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


def _queue_quota_refund_commands(
    pipe: Any,
    provider_key: str,
    *,
    now_dt: datetime,
    _tracked_ops: Optional[List[Optional[Tuple[str, int]]]] = None,
) -> bool:
    """Queues Redis DECR commands for minute and daily quota windows."""
    if not provider_key or PROVIDER_QUOTA_SPECS.get(provider_key) is None:
        return False
    decr_fn = getattr(pipe, "decr", None)
    if not callable(decr_fn):
        return False
    min_key = _quota_minute_key(provider_key, now_dt)
    day_key = _quota_daily_key(provider_key, now_dt)
    decr_fn(min_key)
    decr_fn(day_key)
    if _tracked_ops is not None:
        _tracked_ops.append((min_key, MINUTE_QUOTA_TTL_SECONDS))
        _tracked_ops.append((day_key, DAILY_QUOTA_TTL_SECONDS))
    return True


async def _clamp_negative_quota_counters(
    pipeline_fn: Any,
    tracked_ops: List[Optional[Tuple[str, int]]],
    results: Any,
) -> None:
    """Resets any quota counter that dropped below zero back to zero with its window TTL."""
    if not tracked_ops or not isinstance(results, (list, tuple)):
        return
    negative_targets: List[Tuple[str, int]] = []
    for op_meta, raw_val in zip(tracked_ops, results, strict=False):
        if op_meta is None:
            continue
        if isinstance(raw_val, int) and not isinstance(raw_val, bool) and raw_val < 0:
            negative_targets.append(op_meta)
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


def _queue_provider_telemetry_commands(
    pipe: Any,
    provider_key: str,
    outcome: str,
    *,
    now_dt: datetime,
    upstream_remaining: Optional[int] = None,
    upstream_limit: Optional[int] = None,
    upstream_used: Optional[int] = None,
    refund_quota: bool = False,
    _tracked_ops: Optional[List[Optional[Tuple[str, int]]]] = None,
) -> None:
    if outcome not in VALID_PROVIDER_OUTCOMES:
        return
    tel_key = _provider_telemetry_key(provider_key, now_dt)
    pipe.hincrby(tel_key, outcome, 1)
    if _tracked_ops is not None:
        _tracked_ops.append(None)

    fields: Dict[str, str] = {}
    if outcome in {"ok", "429", "5xx", "timeout"}:
        fields["last_status_at"] = now_dt.isoformat()
    if upstream_remaining is not None:
        fields["upstream_remaining"] = str(upstream_remaining)
    if upstream_limit is not None:
        fields["upstream_limit"] = str(upstream_limit)
    if upstream_used is not None:
        fields["upstream_used"] = str(upstream_used)
    if fields:
        pipe.hset(tel_key, mapping=fields)
        if _tracked_ops is not None:
            _tracked_ops.append(None)

    pipe.expire(tel_key, TELEMETRY_TTL_SECONDS)
    if _tracked_ops is not None:
        _tracked_ops.append(None)

    if refund_quota:
        _queue_quota_refund_commands(
            pipe,
            provider_key,
            now_dt=now_dt,
            _tracked_ops=_tracked_ops,
        )


async def record_provider_outcomes_batch(
    entries: List[Dict[str, Any]],
    *,
    now_dt: Optional[datetime] = None,
) -> None:
    """Records multiple per-provider outcomes in one Redis pipeline to minimise round trips."""
    if not entries:
        return
    client = _get_redis_client()
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
        for entry in entries:
            outcome = entry.get("outcome")
            provider_key = entry.get("provider_key")
            refund_quota = bool(entry.get("refund_quota", False))
            if not provider_key:
                continue
            if outcome in VALID_PROVIDER_OUTCOMES:
                queued = True
                _queue_provider_telemetry_commands(
                    pipe,
                    provider_key,
                    outcome,
                    now_dt=current_dt,
                    upstream_remaining=entry.get("upstream_remaining"),
                    upstream_limit=entry.get("upstream_limit"),
                    upstream_used=entry.get("upstream_used"),
                    refund_quota=refund_quota,
                    _tracked_ops=tracked_ops,
                )
            elif refund_quota and _queue_quota_refund_commands(
                pipe,
                provider_key,
                now_dt=current_dt,
                _tracked_ops=tracked_ops,
            ):
                queued = True
        if not queued:
            return
        exec_call = pipe.execute()
        results = await exec_call if inspect.isawaitable(exec_call) else None
        await _clamp_negative_quota_counters(pipeline_fn, tracked_ops, results)
    except REDIS_TRANSPORT_ERRORS as exc:
        mark_redis_failure(exc)
        logger.warning(f"Batch telemetry write bypassed due to Redis error ({type(exc).__name__})")


async def record_global_request_telemetry(
    cache_status: str,
    auth_mode: str,
    *,
    cache_layer_event: Optional[str] = None,
    now_dt: Optional[datetime] = None,
) -> None:
    """Records anonymised daily global cache-efficiency, dual-layer SWR, and authentication-mode counters."""
    cache_field = {
        "hit": "cache_hit",
        "stale": "cache_hit",
        "partial": "cache_partial",
        "miss": "cache_miss",
    }.get(cache_status)
    auth_field = {
        "session": "auth_session",
        "gadget": "auth_gadget",
    }.get(auth_mode)
    layer_field = cache_layer_event if cache_layer_event in VALID_CACHE_TELEMETRY_EVENTS else None
    if not cache_field and not auth_field and not layer_field:
        return

    client = _get_redis_client()
    if client is None:
        return

    current_dt = now_dt or datetime.now(timezone.utc)
    global_key = _global_telemetry_key(current_dt)
    try:
        pipeline_fn = getattr(client, "pipeline", None)
        if callable(pipeline_fn):
            pipe = pipeline_fn(transaction=False)
            if cache_field:
                pipe.hincrby(global_key, cache_field, 1)
            if auth_field:
                pipe.hincrby(global_key, auth_field, 1)
            if layer_field:
                pipe.hincrby(global_key, layer_field, 1)
            pipe.expire(global_key, TELEMETRY_TTL_SECONDS)
            exec_call = pipe.execute()
            if inspect.isawaitable(exec_call):
                await exec_call
            return

        hincrby_fn = getattr(client, "hincrby", None)
        if callable(hincrby_fn):
            for field_name in (cache_field, auth_field, layer_field):
                if field_name:
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
        logger.warning(f"Global telemetry write bypassed due to Redis error ({type(exc).__name__})")


async def record_cache_telemetry_event(
    event_name: str,
    *,
    count: int = 1,
    now_dt: Optional[datetime] = None,
) -> None:
    """Increments a daily dual-layer cache or refresh telemetry counter in Redis."""
    if event_name not in VALID_CACHE_TELEMETRY_EVENTS or count <= 0:
        return
    client = _get_redis_client()
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
        logger.warning(f"Cache telemetry write bypassed due to Redis error ({type(exc).__name__})")


def _resolve_refresh_limits() -> Tuple[int, int, int]:
    user_rpm = _parse_non_negative_int(getattr(settings, "REFRESH_USER_RPM_LIMIT", None))
    user_rph = _parse_non_negative_int(getattr(settings, "REFRESH_USER_RPH_LIMIT", None))
    global_rpm = _parse_non_negative_int(getattr(settings, "REFRESH_GLOBAL_RPM_LIMIT", None))
    return (
        DEFAULT_REFRESH_USER_RPM_LIMIT if user_rpm is None else user_rpm,
        DEFAULT_REFRESH_USER_RPH_LIMIT if user_rph is None else user_rph,
        DEFAULT_REFRESH_GLOBAL_RPM_LIMIT if global_rpm is None else global_rpm,
    )


async def _atomic_incr_with_ttl(client: Any, key: str, ttl_seconds: int) -> Optional[int]:
    incr_fn = getattr(client, "incr", None)
    if callable(incr_fn):
        pending = incr_fn(key)
        val = await pending if inspect.isawaitable(pending) else pending
        if _is_valid_counter(val):
            if val == 1:
                expire_fn = getattr(client, "expire", None)
                if callable(expire_fn):
                    exp = expire_fn(key, ttl_seconds)
                    if inspect.isawaitable(exp):
                        await exp
            return val
    get_fn = getattr(client, "get", None)
    set_fn = getattr(client, "set", None)
    if callable(get_fn) and callable(set_fn):
        raw_cur = get_fn(key)
        cur = await raw_cur if inspect.isawaitable(raw_cur) else raw_cur
        cur_num = _parse_non_negative_int(_decode_redis_str(cur) if isinstance(cur, bytes) else cur) or 0
        next_val = cur_num + 1
        put_call = set_fn(key, str(next_val), ex=ttl_seconds)
        if inspect.isawaitable(put_call):
            await put_call
        return next_val
    return None


async def _atomic_decr_clamped(client: Any, key: str, ttl_seconds: int) -> None:
    decr_fn = getattr(client, "decr", None)
    set_fn = getattr(client, "set", None)
    if callable(decr_fn):
        pending = decr_fn(key)
        val = await pending if inspect.isawaitable(pending) else pending
        if _is_valid_counter(val) and val < 0 and callable(set_fn):
            put_call = set_fn(key, "0", ex=ttl_seconds)
            if inspect.isawaitable(put_call):
                await put_call
        return
    get_fn = getattr(client, "get", None)
    if callable(get_fn) and callable(set_fn):
        raw_cur = get_fn(key)
        cur = await raw_cur if inspect.isawaitable(raw_cur) else raw_cur
        cur_num = _parse_non_negative_int(_decode_redis_str(cur) if isinstance(cur, bytes) else cur) or 0
        put_call = set_fn(key, str(max(0, cur_num - 1)), ex=ttl_seconds)
        if inspect.isawaitable(put_call):
            await put_call


async def _consume_single_refresh_window(
    client: Any,
    key: str,
    ttl_seconds: int,
    limit: int,
    reason: str,
    retry_after_seconds: int,
    incremented_keys: List[Tuple[str, int]],
    current_dt: datetime,
    *,
    telemetry_event: Optional[str] = "refresh_rate_limited",
) -> Optional[RefreshRateLimitResult]:
    if limit <= 0:
        return None
    val = await _atomic_incr_with_ttl(client, key, ttl_seconds)
    if val is None:
        return None
    incremented_keys.append((key, ttl_seconds))
    if val <= limit:
        return None
    for rk, rttl in incremented_keys:
        await _atomic_decr_clamped(client, rk, rttl)
    if telemetry_event:
        await record_cache_telemetry_event(telemetry_event, now_dt=current_dt)
    return RefreshRateLimitResult(
        allowed=False,
        reason=reason,
        retry_after_seconds=retry_after_seconds,
        used=limit,
        limit=limit,
    )


async def check_and_consume_refresh_rate_limit(
    username: Optional[str],
    *,
    is_admin: bool = False,
    now_dt: Optional[datetime] = None,
) -> RefreshRateLimitResult:
    """
    Enforces anonymised per-user (6 per minute, 60 per hour) and global (30 per minute)
    refresh rate limits, exempting allowlisted admin sessions via the explicit is_admin flag.
    """
    client = _get_redis_client()
    if client is None:
        return RefreshRateLimitResult(allowed=True)

    current_dt = now_dt or datetime.now(timezone.utc)
    user_rpm_limit, user_rph_limit, global_rpm_limit = _resolve_refresh_limits()
    cleaned_user = str(username or "").strip()
    exempt_user = bool(is_admin)
    min_retry = max(1, 60 - current_dt.second)
    hr_retry = max(60, 3600 - (current_dt.minute * 60 + current_dt.second))

    incremented_keys: List[Tuple[str, int]] = []
    try:
        windows: List[Tuple[str, int, int, str, int]] = []
        if not exempt_user and cleaned_user:
            daily_salt = await _get_daily_rate_limit_salt(client, current_dt)
            user_digest = hash_username_for_rate_limit(cleaned_user, salt=daily_salt)
            windows.append(
                (
                    _refresh_user_minute_key(user_digest, current_dt),
                    MINUTE_QUOTA_TTL_SECONDS,
                    user_rpm_limit,
                    "user_rpm",
                    min_retry,
                )
            )
            windows.append(
                (
                    _refresh_user_hour_key(user_digest, current_dt),
                    HOURLY_QUOTA_TTL_SECONDS,
                    user_rph_limit,
                    "user_rph",
                    hr_retry,
                )
            )
        windows.append(
            (
                _refresh_global_minute_key(current_dt),
                MINUTE_QUOTA_TTL_SECONDS,
                global_rpm_limit,
                "global_rpm",
                min_retry,
            )
        )

        for key, ttl_s, limit, reason, retry_s in windows:
            blocked = await _consume_single_refresh_window(
                client, key, ttl_s, limit, reason, retry_s, incremented_keys, current_dt
            )
            if blocked is not None:
                return blocked
    except REDIS_TRANSPORT_ERRORS as exc:
        mark_redis_failure(exc)
        logger.warning(f"Refresh rate-limit check bypassed due to Redis error ({type(exc).__name__})")
        return RefreshRateLimitResult(allowed=True)

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
    client = _get_redis_client()
    if client is None:
        return RefreshRateLimitResult(allowed=True)

    default_user_rpm, default_global_rpm, user_setting, global_setting = spec
    user_rpm = default_user_rpm
    if user_setting:
        override_user = _parse_non_negative_int(getattr(settings, user_setting, None))
        if override_user is not None:
            user_rpm = override_user
    global_rpm = default_global_rpm
    override_global = _parse_non_negative_int(getattr(settings, global_setting, None))
    if override_global is not None:
        global_rpm = override_global

    current_dt = now_dt or datetime.now(timezone.utc)
    min_retry = max(1, 60 - current_dt.second)
    minute_bucket = current_dt.strftime("%Y%m%d%H%M")
    ns = get_redis_namespace()
    cleaned_user = str(username or "").strip()

    incremented_keys: List[Tuple[str, int]] = []
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
        for key, ttl_s, limit, reason, retry_s in windows:
            blocked = await _consume_single_refresh_window(
                client,
                key,
                ttl_s,
                limit,
                reason,
                retry_s,
                incremented_keys,
                current_dt,
                telemetry_event=None,
            )
            if blocked is not None:
                return blocked
    except REDIS_TRANSPORT_ERRORS as exc:
        mark_redis_failure(exc)
        logger.warning(f"Endpoint rate-limit check bypassed due to Redis error ({type(exc).__name__})")
        return RefreshRateLimitResult(allowed=True)

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

    if not tracked or _get_redis_client() is None:
        return False

    current_dt = now_dt or datetime.now(timezone.utc)
    day_keys = [_quota_daily_key(provider_key, current_dt) for provider_key, _ in tracked]
    raw_values = await safe_redis_mget(day_keys)
    total_limit = sum(limit for _, limit in tracked)
    if total_limit <= 0:
        return False

    total_remaining = 0
    for (_, limit), raw_val in zip(tracked, raw_values, strict=True):
        used = _parse_non_negative_int(raw_val) or 0
        total_remaining += max(0, limit - used)

    return (total_remaining / float(total_limit)) < guard_ratio


def _decode_hash(raw_hash: Any) -> Dict[str, str]:
    if not isinstance(raw_hash, dict):
        return {}
    decoded: Dict[str, str] = {}
    for k, v in raw_hash.items():
        key_str = k.decode("utf-8", errors="replace") if isinstance(k, bytes) else str(k)
        val_str = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
        decoded[key_str] = val_str
    return decoded


def _safe_hash_int(hash_data: Dict[str, str], field: str, default: int = 0) -> int:
    parsed = _parse_non_negative_int(hash_data.get(field))
    return parsed if parsed is not None else default


def _safe_optional_hash_int(hash_data: Dict[str, str], field: str) -> Optional[int]:
    return _parse_non_negative_int(hash_data.get(field))


def _decode_redis_str(raw_value: Any) -> Optional[str]:
    if isinstance(raw_value, bytes):
        return raw_value.decode("utf-8", errors="replace")
    return raw_value if isinstance(raw_value, str) else None


def _decode_pipeline_provider_row(results: Any, idx: int) -> Tuple[int, int, int, Optional[str], Dict[str, str]]:
    base = 1 + (idx * 5)
    min_val = _parse_non_negative_int(
        _decode_redis_str(results[base]) if isinstance(results[base], bytes) else results[base]
    )
    day_val = _parse_non_negative_int(
        _decode_redis_str(results[base + 1]) if isinstance(results[base + 1], bytes) else results[base + 1]
    )
    raw_ttl = results[base + 2]
    ttl_val = raw_ttl if isinstance(raw_ttl, int) and not isinstance(raw_ttl, bool) and raw_ttl > 0 else 0
    cd_str = _decode_redis_str(results[base + 3])
    return min_val or 0, day_val or 0, ttl_val, cd_str, _decode_hash(results[base + 4])


async def _fetch_dashboard_pipeline_data(
    client: Any,
    registry: Tuple[ProviderMetadata, ...],
    current_dt: datetime,
) -> Tuple[bool, Dict[str, str], Dict[str, Tuple[int, int, int, Optional[str], Dict[str, str]]]]:
    """Fetches global telemetry and per-provider quota and cooldown metrics in a single Redis pipeline."""
    if client is None:
        return False, {}, {}
    pipeline_fn = getattr(client, "pipeline", None)
    if not callable(pipeline_fn):
        return False, {}, {}

    try:
        pipe = pipeline_fn(transaction=False)
        pipe.hgetall(_global_telemetry_key(current_dt))
        for meta in registry:
            cooldown_key = provider_cooldown_key(meta.key)
            pipe.get(_quota_minute_key(meta.key, current_dt))
            pipe.get(_quota_daily_key(meta.key, current_dt))
            pipe.ttl(cooldown_key)
            pipe.get(cooldown_key)
            pipe.hgetall(_provider_telemetry_key(meta.key, current_dt))

        exec_call = pipe.execute()
        if not inspect.isawaitable(exec_call):
            return False, {}, {}
        results = await exec_call
        expected_len = 1 + (len(registry) * 5)
        if not isinstance(results, (list, tuple)) or len(results) != expected_len:
            return False, {}, {}
        global_hash = _decode_hash(results[0])
        provider_rows = {meta.key: _decode_pipeline_provider_row(results, idx) for idx, meta in enumerate(registry)}
        return True, global_hash, provider_rows
    except REDIS_TRANSPORT_ERRORS as exc:
        mark_redis_failure(exc)
        logger.warning(f"Dashboard snapshot fell back to empty telemetry ({type(exc).__name__})")
        return False, {}, {}


def _decode_cooldown_reason(cooldown_ttl: int, cd_raw: Optional[str]) -> Optional[str]:
    if cooldown_ttl <= 0 or not cd_raw:
        return None
    try:
        parsed_cd = json.loads(cd_raw)
        if isinstance(parsed_cd, dict) and isinstance(parsed_cd.get("reason"), str):
            return parsed_cd["reason"]
    except ValueError:
        return None
    return None


def _resolve_provider_dashboard_status(
    provider_key: str,
    *,
    configured: bool,
    cooldown_ttl: int,
    minute_used: int,
    rpm_limit: int,
    daily_used: int,
    daily_limit: int,
    has_maxmind_db: bool,
    has_sfs_db: bool,
    has_ipsum_db: bool = True,
    has_openasn_db: bool = True,
) -> Tuple[str, str]:
    if provider_key == "maxmind" and not has_maxmind_db:
        return "db_missing", "Database Missing"
    if provider_key == "stopforumspam" and not has_sfs_db:
        return "db_missing", "Offline DB Missing"
    if provider_key == "ipsum_drop" and not has_ipsum_db:
        return "db_missing", "Offline DB Missing"
    if provider_key == "openasn" and not has_openasn_db:
        return "db_missing", "Offline DB Missing"
    if not configured:
        return "no_api_key", "No API Key"
    if cooldown_ttl > 0:
        return "cooldown", f"Cooldown ({cooldown_ttl}s)"
    minute_exhausted = rpm_limit > 0 and minute_used >= rpm_limit
    daily_exhausted = daily_limit > 0 and daily_used >= daily_limit
    if minute_exhausted or daily_exhausted:
        return "quota_guarded", "Quota Guarded"
    return "healthy", "Healthy"


def _build_provider_dashboard_entry(
    meta: ProviderMetadata,
    pipeline_row: Tuple[int, int, int, Optional[str], Dict[str, str]],
    *,
    has_maxmind_db: bool,
    has_sfs_db: bool,
    has_ipsum_db: bool = True,
    has_openasn_db: bool = True,
) -> Dict[str, Any]:
    configured = is_provider_configured(meta.key)
    rpm_limit, daily_limit = get_provider_quota_limits(meta.key)
    minute_used, daily_used, cooldown_ttl, cd_raw, tel_hash = pipeline_row
    status_key, status_label = _resolve_provider_dashboard_status(
        meta.key,
        configured=configured,
        cooldown_ttl=cooldown_ttl,
        minute_used=minute_used,
        rpm_limit=rpm_limit,
        daily_used=daily_used,
        daily_limit=daily_limit,
        has_maxmind_db=has_maxmind_db,
        has_sfs_db=has_sfs_db,
        has_ipsum_db=has_ipsum_db,
        has_openasn_db=has_openasn_db,
    )
    return {
        "key": meta.key,
        "name": meta.label,
        "usesHttp": meta.uses_http,
        "configured": configured,
        "status": status_label,
        "statusKey": status_key,
        "cooldownTtlSeconds": cooldown_ttl,
        "cooldownReason": _decode_cooldown_reason(cooldown_ttl, cd_raw),
        "minuteUsed": minute_used,
        "minuteLimit": rpm_limit,
        "dailyUsed": daily_used,
        "dailyLimit": daily_limit,
        "upstreamRemaining": _safe_optional_hash_int(tel_hash, "upstream_remaining"),
        "upstreamLimit": _safe_optional_hash_int(tel_hash, "upstream_limit"),
        "upstreamUsed": _safe_optional_hash_int(tel_hash, "upstream_used"),
        "lastStatusAt": tel_hash.get("last_status_at") or None,
        "telemetry": {
            "ok": _safe_hash_int(tel_hash, "ok"),
            "cacheHit": _safe_hash_int(tel_hash, "cache_hit"),
            "rateLimited429": _safe_hash_int(tel_hash, "429"),
            "error5xx": _safe_hash_int(tel_hash, "5xx"),
            "timeout": _safe_hash_int(tel_hash, "timeout"),
            "quotaBlocked": _safe_hash_int(tel_hash, "quota_blocked"),
        },
    }


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


def _build_cache_telemetry_summary(
    global_hash: Dict[str, str],
    *,
    l2_estimated_rows: Optional[int],
) -> Dict[str, Any]:
    l1_hit = _safe_hash_int(global_hash, "l1_hit")
    l2_hit_fresh = _safe_hash_int(global_hash, "l2_hit_fresh")
    l2_hit_stale_swr = _safe_hash_int(global_hash, "l2_hit_stale_swr")
    upstream_miss = _safe_hash_int(global_hash, "upstream_miss")
    refresh_ok = _safe_hash_int(global_hash, "refresh_ok")
    refresh_rate_limited = _safe_hash_int(global_hash, "refresh_rate_limited")

    layer_total = l1_hit + l2_hit_fresh + l2_hit_stale_swr + upstream_miss
    dual_layer_hits = l1_hit + l2_hit_fresh + l2_hit_stale_swr
    dual_hit_rate = round((dual_layer_hits / layer_total) * 100.0, 1) if layer_total > 0 else 0.0

    return {
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


def _build_global_dashboard_summary(
    global_hash: Dict[str, str],
    providers_out: List[Dict[str, Any]],
    cache_telemetry: Dict[str, Any],
) -> Dict[str, Any]:
    auth_session = _safe_hash_int(global_hash, "auth_session")
    auth_gadget = _safe_hash_int(global_hash, "auth_gadget")
    cache_hit = _safe_hash_int(global_hash, "cache_hit")
    cache_partial = _safe_hash_int(global_hash, "cache_partial")
    cache_miss = _safe_hash_int(global_hash, "cache_miss")
    cache_total = cache_hit + cache_partial + cache_miss
    total_requests = max(cache_total, auth_session + auth_gadget)
    hit_rate_percent = round((cache_hit / cache_total) * 100.0, 1) if cache_total > 0 else 0.0

    return {
        "totalRequestsToday": total_requests,
        "authSession": auth_session,
        "authGadget": auth_gadget,
        "cacheHit": cache_hit,
        "cachePartial": cache_partial,
        "cacheMiss": cache_miss,
        "fullCacheHitRatePercent": hit_rate_percent,
        "l1Hit": cache_telemetry["l1Hit"],
        "l2HitFresh": cache_telemetry["l2HitFresh"],
        "l2HitStaleSwr": cache_telemetry["l2HitStaleSwr"],
        "upstreamMiss": cache_telemetry["upstreamMiss"],
        "refreshOk": cache_telemetry["refreshOk"],
        "refreshRateLimited": cache_telemetry["refreshRateLimited"],
        "dualLayerHitRatePercent": cache_telemetry["dualLayerHitRatePercent"],
        "l2EstimatedRows": cache_telemetry["l2EstimatedRows"],
        "totalQuotaBlocksToday": sum(entry["telemetry"]["quotaBlocked"] for entry in providers_out),
        "activeCooldownCount": sum(1 for entry in providers_out if entry["statusKey"] == "cooldown"),
        "activeQuotaGuardCount": sum(1 for entry in providers_out if entry["statusKey"] == "quota_guarded"),
    }


async def build_dashboard_snapshot(*, now_dt: Optional[datetime] = None) -> Dict[str, Any]:
    """
    Aggregates global request telemetry and all provider quota, cooldown TTL, and status
    metrics in a single Redis pipeline without exposing IP addresses or user identities.
    """
    current_dt = now_dt or datetime.now(timezone.utc)
    redis_available, global_hash, provider_pipeline_rows = await _fetch_dashboard_pipeline_data(
        _get_redis_client(),
        PROVIDER_REGISTRY,
        current_dt,
    )

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

    providers_out = [
        _build_provider_dashboard_entry(
            meta,
            provider_pipeline_rows.get(meta.key, (0, 0, 0, None, {})),
            has_maxmind_db=has_maxmind_db,
            has_sfs_db=has_sfs_db,
            has_ipsum_db=has_ipsum_db,
            has_openasn_db=has_openasn_db,
        )
        for meta in PROVIDER_REGISTRY
    ]
    cache_telemetry = _build_cache_telemetry_summary(global_hash, l2_estimated_rows=l2_estimated_rows)

    return {
        "generatedAt": current_dt.isoformat(),
        "dateBucket": current_dt.strftime("%Y%m%d"),
        "redisAvailable": redis_available,
        "cacheTelemetry": cache_telemetry,
        "global": _build_global_dashboard_summary(global_hash, providers_out, cache_telemetry),
        "providers": providers_out,
        "offlineDatabases": offline_databases,
    }
