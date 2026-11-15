"""
Proactive multi-window API quota guard and strictly anonymised Redis telemetry.
"""

from __future__ import annotations

import inspect
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from django.conf import settings

from .oauth import is_allowlisted_wiki_user

logger = logging.getLogger(__name__)

MINUTE_QUOTA_TTL_SECONDS = 120
DAILY_QUOTA_TTL_SECONDS = 172800
TELEMETRY_TTL_SECONDS = 7 * 86400
REDIS_KEY_NAMESPACE = "proxycheck:v1"

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

_PROVIDER_CREDENTIAL_SETTING: Dict[str, str] = {
    "cloudflare_radar": "CLOUDFLARE_RADAR_TOKEN",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "ipdata": "IPDATA_API_KEY",
    "ipregistry": "IPREGISTRY_API_KEY",
    "ip2location": "IP2LOCATION_API_KEY",
    "getipintel": "GETIPINTEL_CONTACT_EMAIL",
    "proxycheck": "PROXYCHECK_API_KEY",
    "iphub": "IPHUB_API_KEY",
    "iphunter": "IPHUNTER_API_KEY",
}

_DEFAULT_QUOTA_LIMITS: Dict[str, Tuple[int, int]] = {
    "cloudflare_radar": (0, 0),
    "abuseipdb": (0, 0),
    "ipdata": (0, 0),
    "ipregistry": (0, 0),
    "ip2location": (0, 0),
    "getipintel": (15, 5000),
    "proxycheck": (0, 1000),
    "iphub": (0, 1000),
    "iphunter": (0, 1000),
    "maxmind": (0, 0),
    "spamhaus_zen": (1000, 0),
    "spamcop": (0, 0),
    "tor_onionoo": (0, 0),
    "stopforumspam": (0, 0),
    "dshield": (1000, 0),
}

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

_INITIAL_SETTING_LIMITS: Dict[str, Tuple[Optional[int], Optional[int]]] = {}
_INITIAL_DICT_LIMITS: Optional[Dict[str, Dict[str, int]]] = None


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


def _capture_initial_limits_once() -> None:
    """Snapshots import-time quota settings so runtime overrides are always detected."""
    global _INITIAL_DICT_LIMITS
    if _INITIAL_SETTING_LIMITS:
        return
    if not getattr(settings, "configured", False):
        return

    for provider_key in _DEFAULT_QUOTA_LIMITS:
        prefix = provider_key.upper()
        rpm_val = _parse_non_negative_int(getattr(settings, f"{prefix}_RPM_LIMIT", None))
        daily_val = _parse_non_negative_int(getattr(settings, f"{prefix}_DAILY_LIMIT", None))
        _INITIAL_SETTING_LIMITS[provider_key] = (rpm_val, daily_val)

    raw_dict = getattr(settings, "PROVIDER_QUOTA_LIMITS", None)
    if isinstance(raw_dict, dict):
        copied: Dict[str, Dict[str, int]] = {}
        for key, entry in raw_dict.items():
            if isinstance(entry, dict):
                copied[key] = {
                    "rpm": _parse_non_negative_int(entry.get("rpm")) or 0,
                    "daily": _parse_non_negative_int(entry.get("daily")) or 0,
                }
        _INITIAL_DICT_LIMITS = copied


_capture_initial_limits_once()


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


def _get_redis_client() -> Optional[Any]:
    """Delegates to the shared event-loop-scoped Redis client helper."""
    from detector import views as detector_views

    return detector_views._get_redis_client()


def _mark_redis_failure(exc: BaseException) -> None:
    """Propagates connection or timeout failures to the shared Redis circuit breaker."""
    from detector import views as detector_views

    detector_views.mark_redis_failure(exc)


def is_provider_configured(provider_key: str) -> bool:
    """Returns True when the provider either needs no credentials or has one configured."""
    setting_name = _PROVIDER_CREDENTIAL_SETTING.get(provider_key)
    if not setting_name:
        return True
    raw_value = os.environ.get(setting_name) or getattr(settings, setting_name, "")
    return isinstance(raw_value, str) and bool(raw_value.strip())


def get_provider_quota_limits(provider_key: str) -> Tuple[int, int]:
    """
    Resolves effective (rpm_limit, daily_limit) for a provider, honouring Django
    override_settings on individual limits or PROVIDER_QUOTA_LIMITS as well as os.environ.
    """
    _capture_initial_limits_once()
    default_rpm, default_daily = _DEFAULT_QUOTA_LIMITS.get(provider_key, (0, 0))
    prefix = provider_key.upper()
    rpm_name = f"{prefix}_RPM_LIMIT"
    daily_name = f"{prefix}_DAILY_LIMIT"

    initial_rpm, initial_daily = _INITIAL_SETTING_LIMITS.get(provider_key, (None, None))
    setting_rpm = _parse_non_negative_int(getattr(settings, rpm_name, None))
    setting_daily = _parse_non_negative_int(getattr(settings, daily_name, None))

    current_dict = getattr(settings, "PROVIDER_QUOTA_LIMITS", None)
    dict_entry = current_dict.get(provider_key) if isinstance(current_dict, dict) else None
    initial_dict_entry = _INITIAL_DICT_LIMITS.get(provider_key) if _INITIAL_DICT_LIMITS else None

    def _resolve_window(
        setting_val: Optional[int],
        initial_val: Optional[int],
        env_name: str,
        dict_field: str,
        fallback: int,
    ) -> int:
        if setting_val is not None and initial_val is not None and setting_val != initial_val:
            return setting_val
        if isinstance(dict_entry, dict):
            dict_val = _parse_non_negative_int(dict_entry.get(dict_field))
            initial_dict_val = initial_dict_entry.get(dict_field) if isinstance(initial_dict_entry, dict) else None
            if dict_val is not None and dict_val != initial_dict_val:
                return dict_val
        if env_name in os.environ:
            env_val = _parse_non_negative_int(os.environ.get(env_name))
            if env_val is not None:
                return env_val
        if setting_val is not None:
            return setting_val
        return fallback

    return (
        _resolve_window(setting_rpm, initial_rpm, rpm_name, "rpm", default_rpm),
        _resolve_window(setting_daily, initial_daily, daily_name, "daily", default_daily),
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
    return f"{REDIS_KEY_NAMESPACE}:quota:{provider_key}:min:{now_dt.strftime('%Y%m%d%H%M')}"


def _quota_daily_key(provider_key: str, now_dt: datetime) -> str:
    return f"{REDIS_KEY_NAMESPACE}:quota:{provider_key}:day:{now_dt.strftime('%Y%m%d')}"


def _provider_telemetry_key(provider_key: str, now_dt: datetime) -> str:
    return f"{REDIS_KEY_NAMESPACE}:telemetry:{provider_key}:day:{now_dt.strftime('%Y%m%d')}"


def _global_telemetry_key(now_dt: datetime) -> str:
    return f"{REDIS_KEY_NAMESPACE}:telemetry:global:day:{now_dt.strftime('%Y%m%d')}"


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
    pipe = pipeline_fn(transaction=True)
    pipe.incr(min_key)
    pipe.expire(min_key, MINUTE_QUOTA_TTL_SECONDS)
    pipe.incr(day_key)
    pipe.expire(day_key, DAILY_QUOTA_TTL_SECONDS)
    exec_call = pipe.execute()
    if not inspect.isawaitable(exec_call):
        return None
    results = await exec_call
    if not isinstance(results, (list, tuple)) or len(results) < 4:
        return None
    min_val, _, day_val, _ = results[0], results[1], results[2], results[3]
    if (
        isinstance(min_val, bool)
        or not isinstance(min_val, int)
        or isinstance(day_val, bool)
        or not isinstance(day_val, int)
    ):
        return None

    blocked_window: Optional[str] = None
    if rpm_limit > 0 and min_val > rpm_limit:
        blocked_window = "rpm"
    elif daily_limit > 0 and day_val > daily_limit:
        blocked_window = "rpd"

    if blocked_window is None:
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
    rb_pipe.hincrby(tel_key, "quota_blocked", 1)
    rb_pipe.expire(tel_key, TELEMETRY_TTL_SECONDS)
    rb_exec = rb_pipe.execute()
    rolled_min = max(0, min_val - 1)
    rolled_day = max(0, day_val - 1)
    if inspect.isawaitable(rb_exec):
        rb_res = await rb_exec
        if isinstance(rb_res, (list, tuple)) and len(rb_res) >= 2:
            if isinstance(rb_res[0], int) and not isinstance(rb_res[0], bool):
                rolled_min = max(0, rb_res[0])
            if isinstance(rb_res[1], int) and not isinstance(rb_res[1], bool):
                rolled_day = max(0, rb_res[1])

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
    except Exception as exc:
        _mark_redis_failure(exc)
        logger.warning(f"Quota Lua check bypassed for {provider_key} due to Redis error ({type(exc).__name__})")
        return QuotaCheckResult(allowed=True, minute_limit=rpm_limit, daily_limit=daily_limit)

    try:
        pipe_result = await _run_quota_pipeline(client, min_key, day_key, tel_key, rpm_limit, daily_limit)
        if pipe_result is not None:
            return pipe_result
    except Exception as exc:
        _mark_redis_failure(exc)
        logger.warning(f"Quota pipeline check bypassed for {provider_key} due to Redis error ({type(exc).__name__})")

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
    normalized_headers: Dict[str, Any] = {}
    if headers is not None:
        items_fn = getattr(headers, "items", None)
        if callable(items_fn):
            try:
                raw_items = items_fn()
                if isinstance(raw_items, Iterable):
                    for key, value in raw_items:
                        if isinstance(key, str):
                            normalized_headers[key.strip().lower()] = value
            except Exception:
                normalized_headers = {}

    def _lookup_header(candidates: Tuple[str, ...]) -> Optional[int]:
        for header_name in candidates:
            if header_name in normalized_headers:
                parsed = _parse_non_negative_int(normalized_headers[header_name])
                if parsed is not None:
                    return parsed
            getter = getattr(headers, "get", None)
            if callable(getter):
                for variant in (header_name, header_name.title()):
                    candidate_val = getter(variant)
                    parsed = _parse_non_negative_int(candidate_val)
                    if parsed is not None:
                        return parsed
        return None

    upstream_remaining = _lookup_header(("x-ratelimit-remaining", "ratelimit-remaining", "x-rate-limit-remaining"))
    upstream_limit = _lookup_header(("x-ratelimit-limit", "ratelimit-limit", "x-rate-limit-limit"))
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


def _queue_provider_telemetry_commands(
    pipe: Any,
    provider_key: str,
    outcome: str,
    *,
    now_dt: datetime,
    upstream_remaining: Optional[int] = None,
    upstream_limit: Optional[int] = None,
    upstream_used: Optional[int] = None,
) -> None:
    if outcome not in VALID_PROVIDER_OUTCOMES:
        return
    tel_key = _provider_telemetry_key(provider_key, now_dt)
    pipe.hincrby(tel_key, outcome, 1)

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

    pipe.expire(tel_key, TELEMETRY_TTL_SECONDS)


async def record_provider_outcome(
    provider_key: str,
    outcome: str,
    *,
    upstream_remaining: Optional[int] = None,
    upstream_limit: Optional[int] = None,
    upstream_used: Optional[int] = None,
    now_dt: Optional[datetime] = None,
) -> None:
    """Records a single anonymised per-provider outcome into Redis daily telemetry hashes."""
    if outcome not in VALID_PROVIDER_OUTCOMES:
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
        _queue_provider_telemetry_commands(
            pipe,
            provider_key,
            outcome,
            now_dt=current_dt,
            upstream_remaining=upstream_remaining,
            upstream_limit=upstream_limit,
            upstream_used=upstream_used,
        )
        exec_call = pipe.execute()
        if inspect.isawaitable(exec_call):
            await exec_call
    except Exception as exc:
        _mark_redis_failure(exc)
        logger.warning(f"Telemetry write bypassed for {provider_key} due to Redis error ({type(exc).__name__})")


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
        queued = False
        for entry in entries:
            outcome = entry.get("outcome")
            provider_key = entry.get("provider_key")
            if not provider_key or outcome not in VALID_PROVIDER_OUTCOMES:
                continue
            queued = True
            _queue_provider_telemetry_commands(
                pipe,
                provider_key,
                outcome,
                now_dt=current_dt,
                upstream_remaining=entry.get("upstream_remaining"),
                upstream_limit=entry.get("upstream_limit"),
                upstream_used=entry.get("upstream_used"),
            )
        if not queued:
            return
        exec_call = pipe.execute()
        if inspect.isawaitable(exec_call):
            await exec_call
    except Exception as exc:
        _mark_redis_failure(exc)
        logger.warning(f"Batch telemetry write bypassed due to Redis error ({type(exc).__name__})")


async def record_global_request_telemetry(
    cache_status: str,
    auth_mode: str,
    *,
    now_dt: Optional[datetime] = None,
) -> None:
    """Records anonymised daily global cache-efficiency and authentication-mode counters."""
    cache_field = {
        "hit": "cache_hit",
        "partial": "cache_partial",
        "miss": "cache_miss",
    }.get(cache_status)
    auth_field = {
        "session": "auth_session",
        "gadget": "auth_gadget",
    }.get(auth_mode)
    if not cache_field and not auth_field:
        return

    client = _get_redis_client()
    if client is None:
        return
    pipeline_fn = getattr(client, "pipeline", None)
    if not callable(pipeline_fn):
        return

    current_dt = now_dt or datetime.now(timezone.utc)
    global_key = _global_telemetry_key(current_dt)
    try:
        pipe = pipeline_fn(transaction=False)
        if cache_field:
            pipe.hincrby(global_key, cache_field, 1)
        if auth_field:
            pipe.hincrby(global_key, auth_field, 1)
        pipe.expire(global_key, TELEMETRY_TTL_SECONDS)
        exec_call = pipe.execute()
        if inspect.isawaitable(exec_call):
            await exec_call
    except Exception as exc:
        _mark_redis_failure(exc)
        logger.warning(f"Global telemetry write bypassed due to Redis error ({type(exc).__name__})")


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


async def build_dashboard_snapshot(*, now_dt: Optional[datetime] = None) -> Dict[str, Any]:
    """
    Aggregates global request telemetry and all provider quota, cooldown TTL, and status
    metrics in a single Redis pipeline without exposing IP addresses or user identities.
    """
    from detector import views as detector_views

    current_dt = now_dt or datetime.now(timezone.utc)
    specs = detector_views._PROVIDER_SPECS
    client = _get_redis_client()

    redis_available = False
    global_hash: Dict[str, str] = {}
    provider_pipeline_rows: Dict[str, Tuple[int, int, int, Optional[str], Dict[str, str]]] = {}

    if client is not None:
        pipeline_fn = getattr(client, "pipeline", None)
        if callable(pipeline_fn):
            try:
                pipe = pipeline_fn(transaction=False)
                pipe.hgetall(_global_telemetry_key(current_dt))
                for provider_key, _, _, _, _ in specs:
                    pipe.get(_quota_minute_key(provider_key, current_dt))
                    pipe.get(_quota_daily_key(provider_key, current_dt))
                    pipe.ttl(detector_views._provider_cooldown_key(provider_key))
                    pipe.get(detector_views._provider_cooldown_key(provider_key))
                    pipe.hgetall(_provider_telemetry_key(provider_key, current_dt))

                exec_call = pipe.execute()
                if inspect.isawaitable(exec_call):
                    results = await exec_call
                    expected_len = 1 + (len(specs) * 5)
                    if isinstance(results, (list, tuple)) and len(results) == expected_len:
                        redis_available = True
                        global_hash = _decode_hash(results[0])
                        for idx, (provider_key, _, _, _, _) in enumerate(specs):
                            base = 1 + (idx * 5)
                            raw_min = results[base]
                            raw_day = results[base + 1]
                            raw_ttl = results[base + 2]
                            raw_cd_payload = results[base + 3]
                            raw_tel_hash = results[base + 4]

                            min_val = _parse_non_negative_int(
                                raw_min.decode("utf-8", errors="replace") if isinstance(raw_min, bytes) else raw_min
                            )
                            day_val = _parse_non_negative_int(
                                raw_day.decode("utf-8", errors="replace") if isinstance(raw_day, bytes) else raw_day
                            )
                            ttl_val = (
                                raw_ttl
                                if isinstance(raw_ttl, int) and not isinstance(raw_ttl, bool) and raw_ttl > 0
                                else 0
                            )
                            cd_str = (
                                raw_cd_payload.decode("utf-8", errors="replace")
                                if isinstance(raw_cd_payload, bytes)
                                else (raw_cd_payload if isinstance(raw_cd_payload, str) else None)
                            )
                            provider_pipeline_rows[provider_key] = (
                                min_val or 0,
                                day_val or 0,
                                ttl_val,
                                cd_str,
                                _decode_hash(raw_tel_hash),
                            )
            except Exception as exc:
                _mark_redis_failure(exc)
                logger.warning(f"Dashboard snapshot fell back to empty telemetry ({type(exc).__name__})")
                redis_available = False

    auth_session = _safe_hash_int(global_hash, "auth_session")
    auth_gadget = _safe_hash_int(global_hash, "auth_gadget")
    cache_hit = _safe_hash_int(global_hash, "cache_hit")
    cache_partial = _safe_hash_int(global_hash, "cache_partial")
    cache_miss = _safe_hash_int(global_hash, "cache_miss")

    cache_total = cache_hit + cache_partial + cache_miss
    auth_total = auth_session + auth_gadget
    total_requests = max(cache_total, auth_total)
    hit_rate_percent = round((cache_hit / cache_total) * 100.0, 1) if cache_total > 0 else 0.0

    providers_out: List[Dict[str, Any]] = []
    total_quota_blocks_today = 0
    active_cooldown_count = 0
    active_quota_guard_count = 0

    for provider_key, provider_name, uses_http, _supports_cooldown, _ in specs:
        configured = is_provider_configured(provider_key)
        rpm_limit, daily_limit = get_provider_quota_limits(provider_key)
        minute_used, daily_used, cooldown_ttl, cd_raw, tel_hash = provider_pipeline_rows.get(
            provider_key, (0, 0, 0, None, {})
        )

        cooldown_reason: Optional[str] = None
        if cooldown_ttl > 0 and cd_raw:
            try:
                parsed_cd = json.loads(cd_raw)
                if isinstance(parsed_cd, dict) and isinstance(parsed_cd.get("reason"), str):
                    cooldown_reason = parsed_cd["reason"]
            except Exception:
                cooldown_reason = None

        quota_blocked = _safe_hash_int(tel_hash, "quota_blocked")
        total_quota_blocks_today += quota_blocked

        minute_exhausted = rpm_limit > 0 and minute_used >= rpm_limit
        daily_exhausted = daily_limit > 0 and daily_used >= daily_limit

        if not configured:
            status_key = "no_api_key"
            status_label = "No API Key"
        elif cooldown_ttl > 0:
            status_key = "cooldown"
            status_label = f"Cooldown ({cooldown_ttl}s)"
            active_cooldown_count += 1
        elif minute_exhausted or daily_exhausted:
            status_key = "quota_guarded"
            status_label = "Quota Guarded"
            active_quota_guard_count += 1
        else:
            status_key = "healthy"
            status_label = "Healthy"

        upstream_remaining = _safe_optional_hash_int(tel_hash, "upstream_remaining")
        upstream_limit = _safe_optional_hash_int(tel_hash, "upstream_limit")
        upstream_used = _safe_optional_hash_int(tel_hash, "upstream_used")
        last_status_at = tel_hash.get("last_status_at") or None

        providers_out.append(
            {
                "key": provider_key,
                "name": provider_name,
                "usesHttp": uses_http,
                "configured": configured,
                "status": status_label,
                "statusKey": status_key,
                "cooldownTtlSeconds": cooldown_ttl,
                "cooldownReason": cooldown_reason,
                "minuteUsed": minute_used,
                "minuteLimit": rpm_limit,
                "dailyUsed": daily_used,
                "dailyLimit": daily_limit,
                "upstreamRemaining": upstream_remaining,
                "upstreamLimit": upstream_limit,
                "upstreamUsed": upstream_used,
                "lastStatusAt": last_status_at,
                "telemetry": {
                    "ok": _safe_hash_int(tel_hash, "ok"),
                    "cacheHit": _safe_hash_int(tel_hash, "cache_hit"),
                    "rateLimited429": _safe_hash_int(tel_hash, "429"),
                    "error5xx": _safe_hash_int(tel_hash, "5xx"),
                    "timeout": _safe_hash_int(tel_hash, "timeout"),
                    "quotaBlocked": quota_blocked,
                },
            }
        )

    return {
        "generatedAt": current_dt.isoformat(),
        "dateBucket": current_dt.strftime("%Y%m%d"),
        "redisAvailable": redis_available,
        "global": {
            "totalRequestsToday": total_requests,
            "authSession": auth_session,
            "authGadget": auth_gadget,
            "cacheHit": cache_hit,
            "cachePartial": cache_partial,
            "cacheMiss": cache_miss,
            "fullCacheHitRatePercent": hit_rate_percent,
            "totalQuotaBlocksToday": total_quota_blocks_today,
            "activeCooldownCount": active_cooldown_count,
            "activeQuotaGuardCount": active_quota_guard_count,
        },
        "providers": providers_out,
    }
