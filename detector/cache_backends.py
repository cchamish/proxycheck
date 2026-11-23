"""
Redis client lifecycle, circuit breaking, cache key builders, snapshot caching, and singleflight locks.
"""

import asyncio
import inspect
import json
import logging
import math
import os
import re
import threading
import time
import uuid
import weakref
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, TypeVar

from django.conf import settings
from django.core.signals import setting_changed

from . import sanitization
from .offline_dbs import (
    get_maxmind_newest_mtime_iso,
    get_positive_int_setting,
    get_stopforumspam_db_version,
    has_local_maxmind_city_db,
)
from .provider_registry import (
    REDIS_TRANSPORT_ERRORS,
    build_redis_namespace,
    hash_ip_for_redis,
)

logger = logging.getLogger("detector.views")

# Short socket timeouts prevent a degraded Toolforge Redis instance from stalling upstream queries.
try:
    import redis.asyncio as aioredis
except ImportError as redis_init_err:
    logger.warning("Redis initialisation warning (fault tolerance active): %s", redis_init_err)
    aioredis = None

_REDIS_SOCKET_TIMEOUT_SECONDS = 2.0
_REDIS_CIRCUIT_BREAKER_DEFAULT_SECONDS = 5.0
_REDIS_CIRCUIT_FAILURE_ERRORS: Tuple[type[BaseException], ...] = REDIS_TRANSPORT_ERRORS
_REDIS_INIT_ERRORS: Tuple[type[BaseException], ...] = (*_REDIS_CIRCUIT_FAILURE_ERRORS, ValueError)
_DEFAULT_REDIS_SENTINEL = object()
_redis_client_lock = threading.Lock()
_redis_clients_by_loop: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, Tuple[str, Any]]" = (
    weakref.WeakKeyDictionary()
)
redis_client: Any = _DEFAULT_REDIS_SENTINEL
_redis_circuit_open_until: float = 0.0
_redis_circuit_client_ref: Any = _DEFAULT_REDIS_SENTINEL


def _sync_circuit_client_ref_locked() -> None:
    global _redis_circuit_open_until, _redis_circuit_client_ref
    if redis_client is not _redis_circuit_client_ref:
        _redis_circuit_open_until = 0.0
        _redis_circuit_client_ref = redis_client


def is_redis_circuit_open() -> bool:
    """Returns True while the default Redis client circuit breaker is within its cooldown window."""
    global _redis_circuit_open_until
    with _redis_client_lock:
        _sync_circuit_client_ref_locked()
        if redis_client is None or redis_client is not _DEFAULT_REDIS_SENTINEL:
            return False
        if _redis_circuit_open_until <= 0.0:
            return False
        if time.monotonic() < _redis_circuit_open_until:
            return True
        _redis_circuit_open_until = 0.0
        return False


def mark_redis_failure(exc: BaseException) -> None:
    """Opens the short-term Redis circuit breaker after a connection or timeout error."""
    global _redis_circuit_open_until
    if not isinstance(exc, _REDIS_CIRCUIT_FAILURE_ERRORS):
        return

    raw_cooldown = getattr(settings, "REDIS_CIRCUIT_BREAKER_SECONDS", _REDIS_CIRCUIT_BREAKER_DEFAULT_SECONDS)
    if isinstance(raw_cooldown, bool):
        cooldown_seconds = _REDIS_CIRCUIT_BREAKER_DEFAULT_SECONDS
    else:
        try:
            parsed_cooldown = float(raw_cooldown)
        except TypeError, ValueError:
            cooldown_seconds = _REDIS_CIRCUIT_BREAKER_DEFAULT_SECONDS
        else:
            cooldown_seconds = parsed_cooldown if (math.isfinite(parsed_cooldown) and parsed_cooldown > 0.0) else 0.0

    with _redis_client_lock:
        _sync_circuit_client_ref_locked()
        if redis_client is None or redis_client is not _DEFAULT_REDIS_SENTINEL:
            return
        if cooldown_seconds <= 0.0:
            _redis_circuit_open_until = 0.0
            return
        now = time.monotonic()
        was_closed = now >= _redis_circuit_open_until
        candidate_until = now + cooldown_seconds
        if candidate_until > _redis_circuit_open_until:
            _redis_circuit_open_until = candidate_until
        if was_closed:
            logger.warning("Redis circuit breaker opened for %.1fs after %s", cooldown_seconds, type(exc).__name__)


def reset_redis_circuit_breaker() -> None:
    """Resets the process-local Redis circuit breaker state."""
    global _redis_circuit_open_until, _redis_circuit_client_ref
    with _redis_client_lock:
        _redis_circuit_open_until = 0.0
        _redis_circuit_client_ref = redis_client


def get_redis_client() -> Optional[Any]:
    """Returns an async Redis client bound to the active running event loop."""
    if redis_client is None:
        with _redis_client_lock:
            _sync_circuit_client_ref_locked()
        return None
    if redis_client is not _DEFAULT_REDIS_SENTINEL:
        with _redis_client_lock:
            _sync_circuit_client_ref_locked()
        return redis_client
    if aioredis is None or is_redis_circuit_open():
        return None

    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        return None
    if current_loop.is_closed():
        return None

    redis_url = getattr(settings, "REDIS_URL", "redis://127.0.0.1:6379/0")
    init_err: Optional[BaseException] = None
    superseded_client: Optional[Any] = None
    selected_client: Optional[Any] = None

    with _redis_client_lock:
        for stale_loop in [loop for loop in list(_redis_clients_by_loop.keys()) if loop.is_closed()]:
            _redis_clients_by_loop.pop(stale_loop, None)

        cached_entry = _redis_clients_by_loop.get(current_loop)
        if cached_entry is not None and cached_entry[0] == redis_url:
            return cached_entry[1]
        if cached_entry is not None:
            superseded_client = cached_entry[1]
            _redis_clients_by_loop.pop(current_loop, None)

        try:
            try:
                loop_client = aioredis.from_url(
                    redis_url,
                    encoding="utf-8",
                    decode_responses=True,
                    socket_timeout=_REDIS_SOCKET_TIMEOUT_SECONDS,
                    socket_connect_timeout=_REDIS_SOCKET_TIMEOUT_SECONDS,
                    health_check_interval=30,
                    socket_keepalive=True,
                    retry_on_timeout=True,
                )
            except TypeError as kw_err:
                if "unexpected keyword argument" not in str(kw_err):
                    raise
                loop_client = aioredis.from_url(
                    redis_url,
                    encoding="utf-8",
                    decode_responses=True,
                    socket_timeout=_REDIS_SOCKET_TIMEOUT_SECONDS,
                    socket_connect_timeout=_REDIS_SOCKET_TIMEOUT_SECONDS,
                )
        except (*_REDIS_INIT_ERRORS, TypeError) as redis_loop_err:
            logger.warning("Redis initialisation warning (fault tolerance active): %s", redis_loop_err)
            init_err = redis_loop_err
        else:
            _redis_clients_by_loop[current_loop] = (redis_url, loop_client)
            selected_client = loop_client

    if superseded_client is not None and superseded_client is not selected_client and not current_loop.is_closed():
        aclose_fn = getattr(superseded_client, "aclose", None)
        if callable(aclose_fn) and inspect.iscoroutinefunction(aclose_fn):

            async def _close_superseded() -> None:
                try:
                    await aclose_fn()
                except (*_REDIS_CIRCUIT_FAILURE_ERRORS, RuntimeError) as exc:
                    logger.debug("Ignoring error whilst closing superseded Redis client: %s", exc)

            current_loop.create_task(_close_superseded())

    if init_err is not None:
        mark_redis_failure(init_err)
    return selected_client


DYNAMIC_CACHE_PROVIDERS = frozenset(
    {"ptr", "dnsbl", "spamhaus_zen", "spamcop", "tor_onionoo", "stopforumspam", "dshield"}
)

DEFAULT_STATIC_CACHE_TTL_SECONDS = 86400
DEFAULT_DYNAMIC_CACHE_TTL_SECONDS = 7200
DEFAULT_GETIPINTEL_STABLE_CACHE_TTL_SECONDS = 259200
DEFAULT_COOLDOWN_SECONDS = 120
MIN_COOLDOWN_SECONDS = 60
MAX_COOLDOWN_SECONDS = 300


def get_provider_cache_ttl(provider_key: str, row: Optional[Dict[str, Any]] = None) -> int:
    """Returns the Redis TTL in seconds for a static commercial or dynamic threat feed."""
    if provider_key in DYNAMIC_CACHE_PROVIDERS:
        return get_positive_int_setting("PROVIDER_DYNAMIC_CACHE_TTL_SECONDS", DEFAULT_DYNAMIC_CACHE_TTL_SECONDS)
    static_ttl = get_positive_int_setting("PROVIDER_STATIC_CACHE_TTL_SECONDS", DEFAULT_STATIC_CACHE_TTL_SECONDS)
    if provider_key == "getipintel" and isinstance(row, dict):
        is_stable = False
        raw_json = row.get("rawJson")
        if isinstance(raw_json, dict) and "result" in raw_json:
            try:
                raw_prob = float(raw_json["result"])
            except TypeError, ValueError:
                raw_prob = None
            if raw_prob is not None and math.isfinite(raw_prob) and 0.0 <= raw_prob <= 1.0:
                is_stable = raw_prob <= 0.05 or raw_prob >= 0.95
        if not is_stable:
            chance = row.get("chance")
            if isinstance(chance, (int, float)) and not isinstance(chance, bool):
                chance_val = float(chance)
                if math.isfinite(chance_val) and 0.0 <= chance_val <= 100.0:
                    is_stable = chance_val <= 5.0 or chance_val >= 95.0
        if is_stable:
            stable_ttl = get_positive_int_setting(
                "GETIPINTEL_STABLE_CACHE_TTL_SECONDS",
                DEFAULT_GETIPINTEL_STABLE_CACHE_TTL_SECONDS,
            )
            return max(static_ttl, stable_ttl)
    return static_ttl


def get_cooldown_bounds() -> Tuple[int, int, int]:
    min_s = get_positive_int_setting("PROVIDER_COOLDOWN_MIN_SECONDS", MIN_COOLDOWN_SECONDS)
    max_s = get_positive_int_setting("PROVIDER_COOLDOWN_MAX_SECONDS", MAX_COOLDOWN_SECONDS)
    low, high = min(min_s, max_s), max(min_s, max_s)
    default_s = get_positive_int_setting("PROVIDER_COOLDOWN_DEFAULT_SECONDS", DEFAULT_COOLDOWN_SECONDS)
    return max(low, min(high, default_s)), low, high


_OVERRIDDEN_REDIS_SETTINGS: set[str] = set()

_RELEASE_UPDATING_LOCK_LUA = """
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
else
    return 0
end
"""


def _on_redis_setting_changed(*, setting: str, enter: bool, **kwargs: Any) -> None:
    if setting in ("REDIS_KEY_PREFIX", "REDIS_KEY_SECRET", "SECRET_KEY"):
        if enter:
            _OVERRIDDEN_REDIS_SETTINGS.add(setting)
        else:
            _OVERRIDDEN_REDIS_SETTINGS.discard(setting)


setting_changed.connect(_on_redis_setting_changed, dispatch_uid="detector.cache_backends.setting_changed")


def _resolve_effective_redis_secret() -> str:
    if "REDIS_KEY_SECRET" in _OVERRIDDEN_REDIS_SETTINGS:
        raw_secret = str(getattr(settings, "REDIS_KEY_SECRET", "") or "").strip()
    else:
        raw_secret = str(getattr(settings, "REDIS_KEY_SECRET", "") or os.environ.get("REDIS_KEY_SECRET", "")).strip()
    if raw_secret:
        return raw_secret
    return str(getattr(settings, "SECRET_KEY", "") or "").strip()


def get_redis_namespace() -> str:
    """Returns the environment-isolated and secret-keyed Redis namespace."""
    if "REDIS_KEY_PREFIX" in _OVERRIDDEN_REDIS_SETTINGS:
        raw_prefix = getattr(settings, "REDIS_KEY_PREFIX", "")
    else:
        raw_prefix = os.environ.get("REDIS_KEY_PREFIX") or getattr(settings, "REDIS_KEY_PREFIX", "proxycheck_dev_")
    return build_redis_namespace(str(raw_prefix or "proxycheck_dev_"), _resolve_effective_redis_secret())


def get_redis_ip_digest(canonical_ip: str) -> str:
    """Returns a 24-character HMAC-SHA256 digest for a canonical IP address."""
    return hash_ip_for_redis(canonical_ip, _resolve_effective_redis_secret())


def provider_cache_key(provider_key: str, canonical_ip: str) -> str:
    return f"{get_redis_namespace()}:prov:{provider_key}:{get_redis_ip_digest(canonical_ip)}"


def provider_cooldown_key(provider_key: str) -> str:
    return f"{get_redis_namespace()}:cooldown:{provider_key}"


def snapshot_cache_key(canonical_ip: str, mode: str = "full") -> str:
    normalised_mode = "light" if str(mode or "").strip().lower() == "light" else "full"
    return f"{get_redis_namespace()}:snap:{normalised_mode}:{get_redis_ip_digest(canonical_ip)}"


def updating_lock_key(canonical_ip: str) -> str:
    return f"{get_redis_namespace()}:updating:{get_redis_ip_digest(canonical_ip)}"


def refresh_cooldown_key(canonical_ip: str) -> str:
    return f"{get_redis_namespace()}:refresh_cd:{get_redis_ip_digest(canonical_ip)}"


def swr_backoff_key(canonical_ip: str) -> str:
    return f"{get_redis_namespace()}:swr_backoff:{get_redis_ip_digest(canonical_ip)}"


_T = TypeVar("_T")


def _decode_redis_text_value(raw_value: Any) -> Optional[str]:
    if raw_value is None:
        return None
    if isinstance(raw_value, bytes):
        return raw_value.decode("utf-8", errors="replace")
    return raw_value if isinstance(raw_value, str) else None


async def _run_redis_cache_op(
    operation_label: str,
    target_desc: str,
    operation: Callable[[Any], Awaitable[_T]],
    *,
    default: Any = None,
) -> Any:
    client = get_redis_client()
    if client is None:
        return default
    try:
        return await operation(client)
    except _REDIS_CIRCUIT_FAILURE_ERRORS as redis_err:
        if operation_label == "read" and (
            isinstance(redis_err, ConnectionError) or redis_err.__class__.__name__ == "ConnectionError"
        ):
            try:
                current_loop = asyncio.get_running_loop()
                with _redis_client_lock:
                    cached_entry = _redis_clients_by_loop.get(current_loop)
                    if cached_entry is not None and cached_entry[1] is client:
                        _redis_clients_by_loop.pop(current_loop, None)
                aclose_fn = getattr(client, "aclose", None)
                if callable(aclose_fn):
                    aclose_result = aclose_fn()
                    if inspect.isawaitable(aclose_result):
                        await aclose_result
            except (*_REDIS_CIRCUIT_FAILURE_ERRORS, RuntimeError):
                pass

            reconnected_client = get_redis_client()
            if reconnected_client is not None:
                try:
                    return await operation(reconnected_client)
                except _REDIS_CIRCUIT_FAILURE_ERRORS as retry_err:
                    redis_err = retry_err
        mark_redis_failure(redis_err)
        logger.warning("Redis cache %s bypassed for %s due to error: %s", operation_label, target_desc, redis_err)
        return default


async def safe_redis_get(key: str) -> Optional[str]:
    raw_value = await _run_redis_cache_op("read", key, lambda client: client.get(key))
    return _decode_redis_text_value(raw_value)


async def safe_redis_set(key: str, value: str, *, ex: int) -> None:
    await _run_redis_cache_op("write", key, lambda client: client.set(key, value, ex=ex))


async def safe_redis_mget(keys: List[str]) -> List[Optional[str]]:
    """Reads several keys in one round trip, falling back to single reads for clients without mget."""
    client = get_redis_client()
    if client is None or not keys:
        return [None] * len(keys)
    mget_method = getattr(client, "mget", None)
    if callable(mget_method):
        try:
            pending = mget_method(keys)
            raw_values = await pending if inspect.isawaitable(pending) else pending
        except (AttributeError, TypeError) as mget_unsupported_err:
            logger.debug("Redis mget unavailable, falling back to single reads: %s", mget_unsupported_err)
        except _REDIS_CIRCUIT_FAILURE_ERRORS as redis_read_err:
            mark_redis_failure(redis_read_err)
            logger.warning("Redis batch cache read bypassed for %d keys due to error: %s", len(keys), redis_read_err)
            return [None] * len(keys)
        else:
            if isinstance(raw_values, (list, tuple)) and len(raw_values) == len(keys):
                return [_decode_redis_text_value(raw_value) for raw_value in raw_values]
    return list(await asyncio.gather(*(safe_redis_get(key) for key in keys)))


async def safe_redis_set_many(entries: List[Tuple[str, str, int]]) -> None:
    """Writes several keys with expiry in one pipelined round trip, falling back to single writes."""
    if not entries:
        return
    client = get_redis_client()
    if client is None:
        return

    pipeline_succeeded = False
    try:
        pipeline_factory = getattr(client, "pipeline", None)
        if callable(pipeline_factory):
            pipe = pipeline_factory(transaction=False)
            if inspect.isawaitable(pipe):
                if inspect.iscoroutine(pipe):
                    pipe.close()
            else:
                queue_set = getattr(pipe, "set", None)
                execute = getattr(pipe, "execute", None)
                if callable(queue_set) and callable(execute):
                    aborted = False
                    for key, value, ttl_seconds in entries:
                        queued = queue_set(key, value, ex=ttl_seconds)
                        if inspect.isawaitable(queued):
                            if inspect.iscoroutine(queued):
                                queued.close()
                            aborted = True
                            break
                    if not aborted:
                        pending = execute()
                        if inspect.isawaitable(pending):
                            results = await pending
                            pipeline_succeeded = isinstance(results, (list, tuple)) and len(results) == len(entries)
    except (AttributeError, TypeError) as pipeline_unsupported_err:
        logger.debug("Redis pipeline unavailable, falling back to single writes: %s", pipeline_unsupported_err)
    except _REDIS_CIRCUIT_FAILURE_ERRORS as redis_write_err:
        mark_redis_failure(redis_write_err)
        logger.warning("Redis batch cache write bypassed for %d keys due to error: %s", len(entries), redis_write_err)
        return

    if not pipeline_succeeded:
        await asyncio.gather(*(safe_redis_set(key, value, ex=ttl_seconds) for key, value, ttl_seconds in entries))


class _DecodedProviderRow(dict):
    """Dictionary subclass carrying internal cache wrapper metadata without altering visible keys."""

    __slots__ = ("_city_db_loaded", "_db_updated_at", "_db_version", "_source_raw_value")

    def __init__(
        self,
        mapping: Dict[str, Any],
        *,
        city_db_loaded: bool = False,
        db_updated_at: Optional[str] = None,
        db_version: Optional[int] = None,
        source_raw_value: Optional[str] = None,
    ) -> None:
        super().__init__(mapping)
        self._city_db_loaded = city_db_loaded
        self._db_updated_at = db_updated_at
        self._db_version = db_version
        self._source_raw_value = source_raw_value


_TRAILING_COORDS_RE = re.compile(r"\s*\(\s*[+-]?\d+(?:\.\d+)?\s*,\s*[+-]?\d+(?:\.\d+)?\s*\)\s*$")


def scrub_legacy_coordinates_from_row(row: Mapping[str, Any]) -> Dict[str, Any]:
    """Returns a shallow copy of a provider row without legacy coordinate fields or suffixes."""
    cleaned_row = {key: val for key, val in row.items() if key != "coordinates"}
    loc = cleaned_row.get("location")
    if isinstance(loc, str) and _TRAILING_COORDS_RE.search(loc):
        stripped_loc = _TRAILING_COORDS_RE.sub("", loc).strip()
        cleaned_row["location"] = "-" if stripped_loc in ("", "Unknown") else stripped_loc
    return cleaned_row


def decode_cached_provider_entry(raw_value: Optional[str]) -> Optional[Tuple[Dict[str, Any], Optional[str]]]:
    if not raw_value:
        return None
    try:
        parsed = json.loads(raw_value)
    except ValueError, TypeError:
        return None
    if not isinstance(parsed, dict):
        return None
    city_db_loaded = parsed.get("cityDbLoaded") is True
    raw_db_updated = parsed.get("dbUpdatedAt")
    db_updated_at = raw_db_updated if isinstance(raw_db_updated, str) and raw_db_updated.strip() else None
    raw_db_version = parsed.get("dbVersion")
    db_version = (
        int(raw_db_version) if isinstance(raw_db_version, int) and not isinstance(raw_db_version, bool) else None
    )
    sanitise_fn = sanitization.sanitize_payload
    if "row" in parsed and isinstance(parsed["row"], dict):
        row = scrub_legacy_coordinates_from_row(parsed["row"])
        if not parsed.get("sanitized") and isinstance(row.get("rawJson"), (dict, list)):
            row = {**row, "rawJson": sanitise_fn(row["rawJson"])}
        cached_at = parsed.get("cachedAt")
        cached_at_str = cached_at if isinstance(cached_at, str) and cached_at else None
        return (
            _DecodedProviderRow(
                row,
                city_db_loaded=city_db_loaded,
                db_updated_at=db_updated_at,
                db_version=db_version,
                source_raw_value=raw_value,
            ),
            cached_at_str,
        )
    if "status" in parsed and "provider" in parsed:
        cleaned_row = scrub_legacy_coordinates_from_row(parsed)
        if not parsed.get("sanitized") and isinstance(cleaned_row.get("rawJson"), (dict, list)):
            cleaned_row = {**cleaned_row, "rawJson": sanitise_fn(cleaned_row["rawJson"])}
        return (
            _DecodedProviderRow(
                cleaned_row,
                city_db_loaded=city_db_loaded,
                db_updated_at=db_updated_at,
                db_version=db_version,
                source_raw_value=raw_value,
            ),
            None,
        )
    return None


def decode_cached_ptr_entry(raw_value: Optional[str]) -> Optional[Tuple[Optional[str], Optional[str]]]:
    if not raw_value:
        return None
    try:
        parsed = json.loads(raw_value)
    except ValueError, TypeError:
        return None
    if not isinstance(parsed, dict) or parsed.get("status") not in ("ok", "nxdomain"):
        return None
    hostname = parsed.get("hostname")
    if hostname is not None and not isinstance(hostname, str):
        return None
    cached_at = parsed.get("cachedAt")
    return hostname, (cached_at if isinstance(cached_at, str) and cached_at else None)


def decode_cooldown_entry(raw_value: Optional[str]) -> Optional[Dict[str, Any]]:
    if not raw_value:
        return None
    try:
        parsed = json.loads(raw_value)
    except ValueError, TypeError:
        return None
    if isinstance(parsed, dict):
        return parsed
    return {"statusCode": 503, "reason": "Provider cooldown active"}


def should_refresh_cached_maxmind_entry(raw_value: Optional[str], row: Dict[str, Any]) -> bool:
    """Invalidates stale or pre-City cached MaxMind entries when local MMDB files change."""
    cached_db_updated = getattr(row, "_db_updated_at", None)
    if isinstance(cached_db_updated, str) and cached_db_updated:
        current_updated = get_maxmind_newest_mtime_iso()
        if current_updated and current_updated != cached_db_updated:
            return True
    if not has_local_maxmind_city_db():
        return False
    city_db_loaded = getattr(row, "_city_db_loaded", None)
    if isinstance(city_db_loaded, bool) and (not raw_value or getattr(row, "_source_raw_value", None) == raw_value):
        return not city_db_loaded
    if raw_value:
        try:
            parsed = json.loads(raw_value)
        except (ValueError, TypeError) as exc:
            logger.debug("Invalid cached MaxMind payload during city DB check: %s", exc)
            return True
        if isinstance(parsed, dict) and parsed.get("cityDbLoaded") is True:
            return False
    return True


def should_refresh_cached_stopforumspam_entry(row: Dict[str, Any]) -> bool:
    """Invalidates cached StopForumSpam entries when local database files change mtime."""
    cached_db_version = getattr(row, "_db_version", None)
    if cached_db_version is None:
        return False
    return cached_db_version != get_stopforumspam_db_version()


def _sanitise_snapshot_rows(results: Any) -> Any:
    if not isinstance(results, list):
        return results
    sanitise_fn = sanitization.sanitize_payload
    sanitised_rows: List[Any] = []
    for item in results:
        if isinstance(item, Mapping):
            cleaned = scrub_legacy_coordinates_from_row(item)
            if isinstance(cleaned.get("rawJson"), (dict, list)):
                cleaned["rawJson"] = sanitise_fn(cleaned["rawJson"])
            sanitised_rows.append(cleaned)
        else:
            sanitised_rows.append(item)
    return sanitised_rows


def _decode_cached_snapshot_entry(raw_value: Optional[str]) -> Optional[Dict[str, Any]]:
    if not raw_value:
        return None
    try:
        parsed = json.loads(raw_value)
    except ValueError, TypeError:
        return None
    if not isinstance(parsed, dict):
        return None

    is_sanitised = parsed.get("sanitized") is True
    envelope_fetched_at = parsed.get("fetchedAt")
    if isinstance(parsed.get("snapshot"), dict):
        raw_snapshot = parsed["snapshot"]
        snapshot = {k: v for k, v in raw_snapshot.items() if k != "primaryCoordinates"}
        if isinstance(snapshot.get("results"), list):
            snapshot["results"] = [
                scrub_legacy_coordinates_from_row(item) if isinstance(item, Mapping) else item
                for item in snapshot["results"]
            ]
        existing_fetched = snapshot.get("fetchedAt")
        if (
            not (isinstance(existing_fetched, str) and existing_fetched.strip())
            and isinstance(envelope_fetched_at, str)
            and envelope_fetched_at.strip()
        ):
            snapshot["fetchedAt"] = envelope_fetched_at
        if not is_sanitised and "results" in snapshot:
            snapshot["results"] = _sanitise_snapshot_rows(snapshot["results"])
        return snapshot

    if "ip" in parsed or "results" in parsed:
        snapshot = {k: v for k, v in parsed.items() if k != "primaryCoordinates"}
        if isinstance(snapshot.get("results"), list):
            snapshot["results"] = [
                scrub_legacy_coordinates_from_row(item) if isinstance(item, Mapping) else item
                for item in snapshot["results"]
            ]
        if not is_sanitised and "results" in snapshot:
            snapshot["results"] = _sanitise_snapshot_rows(snapshot["results"])
        return snapshot
    return None


async def get_cached_ip_snapshot(canonical_ip: str, mode: str = "full") -> Optional[Dict[str, Any]]:
    """Reads a full or light IP intelligence snapshot from Redis L1 cache."""
    if not isinstance(canonical_ip, str) or not canonical_ip.strip():
        return None
    raw_value = await safe_redis_get(snapshot_cache_key(canonical_ip, mode=mode))
    return _decode_cached_snapshot_entry(raw_value)


async def get_cached_ip_snapshots_bulk(
    canonical_ips: Sequence[str],
    mode: str = "full",
) -> Dict[str, Dict[str, Any]]:
    """Reads multiple IP intelligence snapshots from Redis L1 in a single MGET round trip."""
    unique_ips = list(dict.fromkeys(ip.strip() for ip in canonical_ips if isinstance(ip, str) and ip.strip()))
    if not unique_ips or get_redis_client() is None:
        return {}
    keys = [snapshot_cache_key(ip, mode=mode) for ip in unique_ips]
    raw_values = await safe_redis_mget(keys)
    hits: Dict[str, Dict[str, Any]] = {}
    for ip, raw_val in zip(unique_ips, raw_values, strict=True):
        decoded = _decode_cached_snapshot_entry(raw_val)
        if decoded is not None:
            hits[ip] = decoded
    return hits


async def set_cached_ip_snapshot(
    canonical_ip: str,
    snapshot: Dict[str, Any],
    *,
    mode: str = "full",
    ttl_seconds: int = DEFAULT_STATIC_CACHE_TTL_SECONDS,
) -> None:
    """Writes an IP snapshot to Redis L1 whilst preserving existing fetchedAt timestamps verbatim."""
    if not isinstance(canonical_ip, str) or not canonical_ip.strip() or not isinstance(snapshot, dict):
        return
    if ttl_seconds <= 0:
        return

    payload = dict(snapshot)
    existing_fetched = payload.get("fetchedAt")
    if isinstance(existing_fetched, str) and existing_fetched.strip():
        preserved_fetched_at = existing_fetched
    else:
        cache_meta = payload.get("cacheMeta")
        meta_fetched = cache_meta.get("fetchedAt") if isinstance(cache_meta, dict) else None
        if isinstance(meta_fetched, str) and meta_fetched.strip():
            preserved_fetched_at = meta_fetched
        else:
            preserved_fetched_at = datetime.now(timezone.utc).isoformat()
        payload["fetchedAt"] = preserved_fetched_at

    if "results" in payload:
        payload["results"] = _sanitise_snapshot_rows(payload["results"])

    envelope = {
        "snapshot": payload,
        "fetchedAt": preserved_fetched_at,
        "sanitized": True,
    }
    await safe_redis_set(
        snapshot_cache_key(canonical_ip, mode=mode),
        json.dumps(envelope),
        ex=int(ttl_seconds),
    )


async def is_ip_updating_locked(canonical_ip: str) -> bool:
    """Returns True when another worker currently holds the singleflight refresh lock for this IP."""
    if not isinstance(canonical_ip, str) or not canonical_ip.strip():
        return False
    return (await safe_redis_get(updating_lock_key(canonical_ip))) is not None


async def acquire_ip_updating_lock(canonical_ip: str, ttl_seconds: int = 25) -> Optional[str]:
    """Atomically acquires a distributed singleflight lock for an IP and returns its release token."""
    if not isinstance(canonical_ip, str) or not canonical_ip.strip() or ttl_seconds <= 0:
        return None
    client = get_redis_client()
    if client is None:
        return None

    token = uuid.uuid4().hex
    lock_key = updating_lock_key(canonical_ip)
    ttl = int(ttl_seconds)
    try:
        pending = client.set(lock_key, token, nx=True, ex=ttl)
        acquired = await pending if inspect.isawaitable(pending) else pending
    except TypeError:
        existing = await safe_redis_get(lock_key)
        if existing is not None:
            return None
        await safe_redis_set(lock_key, token, ex=ttl)
        return token
    except _REDIS_CIRCUIT_FAILURE_ERRORS as redis_err:
        mark_redis_failure(redis_err)
        logger.warning("Redis lock acquire bypassed for %s due to error: %s", lock_key, redis_err)
        return None
    return token if acquired else None


async def release_ip_updating_lock(canonical_ip: str, token: str) -> bool:
    """Releases the distributed singleflight lock only when the caller owns the matching token."""
    if not isinstance(canonical_ip, str) or not canonical_ip.strip() or not isinstance(token, str) or not token:
        return False
    client = get_redis_client()
    if client is None:
        return False

    lock_key = updating_lock_key(canonical_ip)
    try:
        eval_fn = getattr(client, "eval", None)
        if callable(eval_fn):
            try:
                pending = eval_fn(_RELEASE_UPDATING_LOCK_LUA, 1, lock_key, token)
                raw_res = await pending if inspect.isawaitable(pending) else pending
            except AttributeError, TypeError, NotImplementedError:
                raw_res = None
            if isinstance(raw_res, bool):
                return raw_res
            if isinstance(raw_res, int):
                return raw_res > 0

        pending_get = client.get(lock_key)
        raw_current = await pending_get if inspect.isawaitable(pending_get) else pending_get
        if _decode_redis_text_value(raw_current) != token:
            return False

        delete_fn = getattr(client, "delete", None)
        if callable(delete_fn):
            pending_del = delete_fn(lock_key)
            raw_del = await pending_del if inspect.isawaitable(pending_del) else pending_del
            if isinstance(raw_del, bool):
                return raw_del
            if isinstance(raw_del, int):
                return raw_del > 0
            return True

        strings_map = getattr(client, "strings", None)
        if isinstance(strings_map, dict):
            removed = strings_map.pop(lock_key, None) is not None
            ttls_map = getattr(client, "ttls", None)
            if isinstance(ttls_map, dict):
                ttls_map.pop(lock_key, None)
            return removed
        return False
    except _REDIS_CIRCUIT_FAILURE_ERRORS as redis_err:
        mark_redis_failure(redis_err)
        logger.warning("Redis lock release bypassed for %s due to error: %s", lock_key, redis_err)
        return False


async def is_refresh_on_cooldown(canonical_ip: str) -> bool:
    """Returns True whilst an IP is within its minimum manual refresh cooldown window."""
    if not isinstance(canonical_ip, str) or not canonical_ip.strip():
        return False
    return (await safe_redis_get(refresh_cooldown_key(canonical_ip))) is not None


async def set_refresh_cooldown(canonical_ip: str, ttl_seconds: int = 60) -> None:
    """Sets the per-IP manual refresh cooldown key in Redis."""
    if not isinstance(canonical_ip, str) or not canonical_ip.strip() or ttl_seconds <= 0:
        return
    await safe_redis_set(refresh_cooldown_key(canonical_ip), "1", ex=int(ttl_seconds))


async def is_swr_backed_off(canonical_ip: str) -> bool:
    """Returns True whilst background stale-while-revalidate refreshes are backed off for an IP."""
    if not isinstance(canonical_ip, str) or not canonical_ip.strip():
        return False
    return (await safe_redis_get(swr_backoff_key(canonical_ip))) is not None


async def set_swr_backoff(canonical_ip: str, ttl_seconds: int = 1800) -> None:
    """Sets the background stale-while-revalidate backoff marker after a degraded refresh."""
    if not isinstance(canonical_ip, str) or not canonical_ip.strip() or ttl_seconds <= 0:
        return
    await safe_redis_set(swr_backoff_key(canonical_ip), "1", ex=int(ttl_seconds))
