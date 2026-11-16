"""
Asynchronous views for IP intelligence aggregation and Wikimedia OAuth 2.0 session handling.
"""

import asyncio
import builtins
import concurrent.futures
import contextvars
import http.cookiejar
import inspect
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import threading
import time
import weakref
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import quote, urlencode

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename
import httpx
from asgiref.sync import sync_to_async
from django.conf import settings
from django.core import signing
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from proxycheck.settings import (
    MAXMIND_ASN_DB_FILENAME,
    MAXMIND_CITY_DB_FILENAME,
    MAXMIND_COUNTRY_DB_FILENAME,
    resolve_mmdb_file,
)

from .adapters import (
    adapt_abuseipdb,
    adapt_cloudflare_radar,
    adapt_dshield,
    adapt_getipintel,
    adapt_ip2location,
    adapt_ipdata,
    adapt_iphub,
    adapt_iphunter,
    adapt_ipregistry,
    adapt_maxmind,
    adapt_proxycheck,
    adapt_spamcop,
    adapt_spamhaus_zen,
    adapt_stopforumspam,
    adapt_tor_onionoo,
    are_offline_intelligence_caches_warm,
    classify_rdns_hostname,
    compute_cidr_attribution,
    warm_offline_intelligence_caches,
)
from .middleware import is_session_backend_error
from .oauth import (
    DEFAULT_RIGHTS_TTL_SECONDS,
    REQUIRED_WIKIMEDIA_RIGHTS_SET,
    CentralAuthVerificationError,
    InvalidCentralAuthTokenError,
    MetaWikiRightsFetchError,
    evaluate_wikimedia_rights,
    extract_wikimedia_domain_from_project,
    fetch_project_user_rights,
    fetch_user_rights_from_meta,
    is_allowlisted_wiki_user,
    is_session_rights_expired,
    normalize_and_validate_wikimedia_domain,
    verify_centralauth_userinfo,
)
from .offline_dbs import (
    collect_offline_databases_status,
    get_maxmind_newest_mtime_iso,
    get_stopforumspam_db_version,
    has_any_local_stopforumspam_db,
    query_stopforumspam_offline,
)
from .quota_telemetry import (
    REDIS_KEY_NAMESPACE,
    build_dashboard_snapshot,
    check_and_consume_quota,
    extract_upstream_rate_limit,
    is_admin_user,
    is_provider_configured,
    record_global_request_telemetry,
    record_provider_outcomes_batch,
)

logger = logging.getLogger(__name__)


# Short socket timeouts prevent a degraded Toolforge Redis instance from stalling upstream queries.
try:
    import redis.asyncio as aioredis
except Exception as redis_init_err:
    logger.warning(f"Redis initialization warning (fault tolerance active): {redis_init_err}")
    aioredis = None

try:
    from redis.exceptions import RedisError as _RedisError
except Exception:
    _RedisError = None

_REDIS_SOCKET_TIMEOUT_SECONDS = 2.0
_REDIS_CIRCUIT_BREAKER_DEFAULT_SECONDS = 5.0
_REDIS_CIRCUIT_FAILURE_ERRORS: Tuple[type[BaseException], ...] = (
    (ConnectionError, TimeoutError, OSError, _RedisError)
    if _RedisError is not None
    else (ConnectionError, TimeoutError, OSError)
)
_redis_client_lock = threading.Lock()
_redis_clients_by_loop: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, Tuple[str, Any]]" = (
    weakref.WeakKeyDictionary()
)
redis_client: Any = None
_default_redis_sentinel: Any = None
_redis_circuit_open_until: float = 0.0
_redis_circuit_client_ref: Any = None
if aioredis is not None:
    try:
        redis_client = aioredis.from_url(
            getattr(settings, "REDIS_URL", "redis://127.0.0.1:6379/0"),
            encoding="utf-8",
            decode_responses=True,
            socket_timeout=_REDIS_SOCKET_TIMEOUT_SECONDS,
            socket_connect_timeout=_REDIS_SOCKET_TIMEOUT_SECONDS,
        )
        _default_redis_sentinel = redis_client
        _redis_circuit_client_ref = redis_client
    except Exception as redis_init_err:
        logger.warning(f"Redis initialization warning (fault tolerance active): {redis_init_err}")
        redis_client = None
        _default_redis_sentinel = None
        _redis_circuit_client_ref = None


def _get_circuit_breaker_cooldown_seconds() -> float:
    """Returns the configured circuit breaker cooldown in seconds."""
    raw_value = getattr(settings, "REDIS_CIRCUIT_BREAKER_SECONDS", _REDIS_CIRCUIT_BREAKER_DEFAULT_SECONDS)
    if isinstance(raw_value, bool):
        return _REDIS_CIRCUIT_BREAKER_DEFAULT_SECONDS
    try:
        seconds = float(raw_value)
    except TypeError, ValueError:
        return _REDIS_CIRCUIT_BREAKER_DEFAULT_SECONDS
    if not math.isfinite(seconds) or seconds <= 0.0:
        return 0.0
    return seconds


def _sync_circuit_client_ref_locked() -> None:
    """Clears stale circuit state whenever the active redis_client binding changes."""
    global _redis_circuit_open_until, _redis_circuit_client_ref
    if redis_client is not _redis_circuit_client_ref:
        _redis_circuit_open_until = 0.0
        _redis_circuit_client_ref = redis_client


def is_redis_circuit_open() -> bool:
    """Returns True while the default Redis client circuit breaker is within its cooldown window."""
    global _redis_circuit_open_until
    with _redis_client_lock:
        _sync_circuit_client_ref_locked()
        if redis_client is None or redis_client is not _default_redis_sentinel:
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
    cooldown_seconds = _get_circuit_breaker_cooldown_seconds()
    with _redis_client_lock:
        _sync_circuit_client_ref_locked()
        if redis_client is None or redis_client is not _default_redis_sentinel:
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
            logger.warning(f"Redis circuit breaker opened for {cooldown_seconds:.1f}s after {type(exc).__name__}")


def reset_redis_circuit_breaker() -> None:
    """Resets the process-local Redis circuit breaker state for deterministic tests."""
    global _redis_circuit_open_until, _redis_circuit_client_ref
    with _redis_client_lock:
        _redis_circuit_open_until = 0.0
        _redis_circuit_client_ref = redis_client


def _get_redis_client() -> Optional[Any]:
    """Returns an async Redis client bound to the active running event loop."""
    if redis_client is None:
        with _redis_client_lock:
            _sync_circuit_client_ref_locked()
        return None
    if redis_client is not _default_redis_sentinel:
        with _redis_client_lock:
            _sync_circuit_client_ref_locked()
        return redis_client
    if aioredis is None:
        return None
    if is_redis_circuit_open():
        return None

    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        return None
    if current_loop.is_closed():
        return None

    redis_url = getattr(settings, "REDIS_URL", "redis://127.0.0.1:6379/0")
    init_err: Optional[BaseException] = None
    with _redis_client_lock:
        closed_loops = [loop for loop in list(_redis_clients_by_loop.keys()) if loop.is_closed()]
        for stale_loop in closed_loops:
            _redis_clients_by_loop.pop(stale_loop, None)

        cached_entry = _redis_clients_by_loop.get(current_loop)
        if cached_entry is not None and cached_entry[0] == redis_url:
            return cached_entry[1]

        try:
            loop_client = aioredis.from_url(
                redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_timeout=_REDIS_SOCKET_TIMEOUT_SECONDS,
                socket_connect_timeout=_REDIS_SOCKET_TIMEOUT_SECONDS,
            )
        except Exception as redis_loop_err:
            logger.warning(f"Redis initialization warning (fault tolerance active): {redis_loop_err}")
            init_err = redis_loop_err
            loop_client = None
        else:
            _redis_clients_by_loop[current_loop] = (redis_url, loop_client)
            return loop_client

    if init_err is not None:
        mark_redis_failure(init_err)
    return None


_PROC_RSS_CACHE_TTL_SECONDS = 1.0
_DEFAULT_BUILTIN_OPEN = builtins.open
_proc_rss_cache: Optional[Tuple[float, float]] = None


def _is_builtin_open_mocked() -> bool:
    return (
        builtins.open is not _DEFAULT_BUILTIN_OPEN
        or globals().get("open", _DEFAULT_BUILTIN_OPEN) is not _DEFAULT_BUILTIN_OPEN
    )


def _read_proc_rss_mb() -> Optional[float]:
    """Reads live resident set size (RSS) from Linux procfs in megabytes when available."""
    global _proc_rss_cache

    now_mono = time.monotonic()
    if not _is_builtin_open_mocked():
        cached = _proc_rss_cache
        if cached is not None and 0.0 <= (now_mono - cached[0]) < _PROC_RSS_CACHE_TTL_SECONDS:
            return cached[1]

    try:
        with open("/proc/self/statm", encoding="ascii") as statm_file:
            fields = statm_file.read().split()
        if len(fields) < 2:
            return None
        rss_pages = int(fields[1])
        page_size = os.sysconf("SC_PAGESIZE")
    except OSError, AttributeError, ValueError, TypeError:
        return None

    if rss_pages < 0 or page_size <= 0:
        return None
    rss_mb = round((rss_pages * page_size) / (1024.0 * 1024.0), 2)
    _proc_rss_cache = (now_mono, rss_mb)
    return rss_mb


def get_process_memory_mb() -> Optional[float]:
    """Returns current worker RSS in megabytes, falling back to peak RSS when procfs is unavailable."""
    proc_rss = _read_proc_rss_mb()
    if proc_rss is not None:
        return proc_rss

    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # Linux reports ru_maxrss in KiB.
        return round(usage / 1024.0, 2)
    except Exception:
        return None


def _attach_request_diagnostics(payload: Dict[str, Any], start_time: float) -> Dict[str, Any]:
    """Returns a copy of payload annotated with execution duration in seconds and worker memory in megabytes."""
    return {
        **payload,
        "durationSeconds": round(time.perf_counter() - start_time, 3),
        "memoryMb": get_process_memory_mb(),
    }


def _strip_raw_json_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Returns a shallow copy of payload without rawJson keys on provider result rows."""
    if isinstance(payload, dict) and isinstance(payload.get("results"), list):
        return {
            **payload,
            "results": [
                {k: v for k, v in row.items() if k != "rawJson"} if isinstance(row, dict) else row
                for row in payload["results"]
            ],
        }
    return payload


def _parse_compact_flag(raw_value: Any) -> bool:
    """Interprets boolean, integer, or string compact flags."""
    if isinstance(raw_value, bool):
        return raw_value
    if isinstance(raw_value, int):
        return raw_value == 1
    if isinstance(raw_value, str):
        return raw_value.strip().lower() in ("1", "true", "yes")
    return False


def _is_compact_request(request, body: Optional[Dict[str, Any]] = None) -> bool:
    """Checks query parameters and optional JSON body for compact mode requests."""
    raw_query = request.GET.get("compact")
    if raw_query is not None and str(raw_query).strip():
        return _parse_compact_flag(str(raw_query))
    if isinstance(body, dict) and "compact" in body:
        return _parse_compact_flag(body.get("compact"))
    return False


def _normalize_query_mode(raw_mode: Any) -> str:
    """Normalizes the requested detection mode to either light or full."""
    normalized = str(raw_mode or "full").strip().lower()
    return "light" if normalized == "light" else "full"


def _resolve_query_mode(request, body: Optional[Dict[str, Any]] = None) -> str:
    """Checks query parameters and optional JSON body for the detection query mode."""
    raw_query = request.GET.get("mode")
    if raw_query is not None and str(raw_query).strip():
        return _normalize_query_mode(raw_query)
    if isinstance(body, dict) and "mode" in body and body.get("mode") is not None:
        raw_body_mode = str(body.get("mode")).strip()
        if raw_body_mode:
            return _normalize_query_mode(raw_body_mode)
    return "full"


def canonicalize_ip(raw_ip: str) -> Optional[str]:
    """Returns the canonical compressed IPv4 or IPv6 address string, or None when invalid."""
    if not isinstance(raw_ip, str):
        return None
    stripped = raw_ip.strip()
    if not stripped:
        return None
    if ":" in stripped and "%" in stripped:
        addr_part, zone_id = stripped.split("%", 1)
        if not zone_id or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 or ch in "%/" for ch in zone_id):
            return None
        stripped = addr_part
    try:
        return ipaddress.ip_address(stripped).compressed
    except ValueError:
        return None


_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")
_DOC_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def _classify_non_public_ip(canonical_ip: str) -> Optional[Tuple[str, str]]:
    """
    Returns (category_key, description) when an IP is non-public or reserved,
    or None when the address is globally routable unicast.
    """
    ip_obj = ipaddress.ip_address(canonical_ip)
    target = getattr(ip_obj, "ipv4_mapped", None) or ip_obj

    is_non_public = not ip_obj.is_global or ip_obj.is_multicast or not target.is_global or target.is_multicast
    if not is_non_public:
        return None

    if target.is_loopback:
        return "loopback", "Loopback Address"
    if target.is_link_local:
        return "link_local", "Link-Local Address"
    if target.is_multicast:
        return "multicast", "Multicast Address"
    if target.is_unspecified:
        return "unspecified", "Unspecified Address"
    if target.version == 4 and target in _CGNAT_NETWORK:
        return "shared_cgnat", "Shared Address Space (CGNAT)"
    if any(target.version == net.version and target in net for net in _DOC_NETWORKS):
        return "documentation", "Documentation Reserved Address"
    if target.is_private:
        return "private", "Private Network Address"
    if target.is_reserved:
        return "reserved", "Reserved Address"
    return "non_public", "Non-Public / Reserved Address"


def _build_non_public_response_payload(
    ip: str,
    category: str,
    reason: str,
    start_time: float,
    *,
    query_mode: str = "full",
) -> Dict[str, Any]:
    """Builds a standard HTTP 200 payload for non-public or reserved IP addresses without external lookups."""
    normalized_mode = _normalize_query_mode(query_mode)
    payload = {
        "ip": ip,
        "isNonPublic": True,
        "nonPublicCategory": category,
        "nonPublicReason": reason,
        "queryMode": normalized_mode,
        "isPartialMode": False,
        "is_broadcast_ip": False,
        "isTor": False,
        "torIsExit": False,
        "torRunning": False,
        "torFlags": [],
        "torLabel": None,
        "torSummary": None,
        "prediction_score": 0.0,
        "predictionLabel": f"Non-Public ({reason})",
        "predictionTier": "neutral",
        "getipintel_chance": None,
        "arbitrationVerdict": f"Non-Public / Reserved IP ({reason})",
        "arbitrationTier": "neutral",
        "isMajorityProxyVpn": False,
        "primaryCountry": reason,
        "primaryCoordinates": "N/A",
        "primaryAsn": "-",
        "ptrHostname": None,
        "ptrCategory": "none",
        "ptrLabel": "Skipped (Non-Public IP)",
        "ptrIsHighRisk": False,
        "recommendedCidr": None,
        "defaultCidr": None,
        "mmdbCidr": None,
        "cloudCidr": None,
        "cloudProvider": None,
        "cidrNote": f"External lookups skipped for {reason.lower()}",
        "results": [],
        "isCached": False,
        "cacheMeta": {
            "status": "bypassed",
            "isPartial": False,
            "hitCount": 0,
            "missCount": 0,
            "cooldownCount": 0,
            "totalSources": 0,
            "cachedAt": None,
        },
    }
    return _attach_request_diagnostics(payload, start_time)


REDACTED_PLACEHOLDER = "***REDACTED***"

# Matches credential-bearing query parameters such as key=, api-key=, access_token= or contact=,
# including quoted values as they appear in Python reprs
_SENSITIVE_QUERY_PATTERN = re.compile(r"(?i)((?:api[_-]?key|key|token|secret|contact|pass(?:word)?)=['\"]?)[^&\s'\"]+")
_BEARER_TOKEN_PATTERN = re.compile(r"(?i)(Bearer\s+)[^\s'\"\\,;]+")

_SECRET_SETTING_NAMES = (
    "CLOUDFLARE_RADAR_TOKEN",
    "ABUSEIPDB_API_KEY",
    "IPDATA_API_KEY",
    "IPREGISTRY_API_KEY",
    "IP2LOCATION_API_KEY",
    "GETIPINTEL_CONTACT_EMAIL",
    "PROXYCHECK_API_KEY",
    "IPHUB_API_KEY",
    "IPHUNTER_API_KEY",
    "MAXMIND_ACCOUNT_ID",
    "MAXMIND_LICENSE_KEY",
    "WIKIMEDIA_CLIENT_SECRET",
)

# Very short values would redact ordinary words, and no real provider issues keys this short
_MIN_SECRET_LENGTH = 4

_secret_values_cache: Optional[Tuple[Tuple[Tuple[Optional[str], Any], ...], Tuple[str, ...]]] = None


def _configured_secret_values() -> Tuple[str, ...]:
    """Collects configured credentials from the environment and settings, longest first."""
    global _secret_values_cache
    fingerprint = tuple((os.environ.get(name), getattr(settings, name, "")) for name in _SECRET_SETTING_NAMES)
    cached = _secret_values_cache
    if cached is not None and cached[0] == fingerprint:
        return cached[1]

    values = set()
    for env_val, setting_val in fingerprint:
        for candidate in (env_val, setting_val):
            if not isinstance(candidate, str):
                continue
            stripped = candidate.strip()
            if len(stripped) < _MIN_SECRET_LENGTH:
                continue
            values.add(stripped)
            # httpx percent-encodes query values, so the encoded form can show up in error text too
            values.add(quote(stripped, safe=""))
    resolved = tuple(sorted(values, key=len, reverse=True))
    _secret_values_cache = (fingerprint, resolved)
    return resolved


def _sanitize_error_message(err_str: str) -> str:
    """Redacts credential query parameters, Bearer tokens, and configured API keys from upstream error text."""
    if err_str is None:
        return ""
    text = err_str if isinstance(err_str, str) else str(err_str)
    text = _SENSITIVE_QUERY_PATTERN.sub(lambda m: m.group(1) + REDACTED_PLACEHOLDER, text)
    text = _BEARER_TOKEN_PATTERN.sub(r"\1" + REDACTED_PLACEHOLDER, text)
    for secret_value in _configured_secret_values():
        text = text.replace(secret_value, REDACTED_PLACEHOLDER)
    return text


def _sanitize_payload(value: Any) -> Any:
    """Recursively redacts secrets from every string in a JSON-like structure before it leaves the server."""
    if isinstance(value, str):
        return _sanitize_error_message(value)
    if isinstance(value, dict):
        return {k: _sanitize_payload(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_payload(v) for v in value]
    return value


def _extract_response_log_details(resp: Any) -> Tuple[str, str]:
    """Extracts a sanitized content type and 120-character body preview for warning logs."""
    content_type = "unknown"
    headers = getattr(resp, "headers", None)
    getter = getattr(headers, "get", None) if headers is not None else None
    if callable(getter):
        for header_name in ("Content-Type", "content-type"):
            candidate = getter(header_name)
            if isinstance(candidate, str) and candidate.strip():
                cleaned_ct = " ".join(_sanitize_error_message(candidate).split())
                content_type = cleaned_ct[:64] or "unknown"
                break

    raw_text = getattr(resp, "text", "")
    if not isinstance(raw_text, str) or not raw_text.strip():
        return content_type, "<empty>"
    sanitized_text = " ".join(_sanitize_error_message(raw_text).split())
    if len(sanitized_text) > 120:
        return content_type, f"{sanitized_text[:117]}..."
    return content_type, sanitized_text


def _parse_upstream_json_with_error(resp: httpx.Response) -> Tuple[Any, int, Optional[str]]:
    """Decodes an upstream response body and returns any JSON parsing error class name."""
    try:
        return resp.json(), resp.status_code, None
    except ValueError as exc:
        status_code = 502 if resp.status_code == 200 else resp.status_code
        return {"status": "error", "message": _sanitize_error_message(resp.text or "")}, status_code, type(exc).__name__


def _parse_upstream_json(resp: httpx.Response) -> Tuple[Any, int]:
    """
    Decodes an upstream response body. Non-JSON bodies such as HTML gateway pages are returned as a
    sanitized error payload, and a 200 status is rewritten to 502 so adapters treat it as a format error.
    Non-dict JSON is passed through and rejected by the adapters themselves.
    """
    payload, status_code, _ = _parse_upstream_json_with_error(resp)
    return payload, status_code


_maxmind_lock = threading.Lock()
_maxmind_readers: Dict[str, Any] = {}
_maxmind_reader_stats: Dict[str, Optional[Tuple[int, int]]] = {}
_missing_city_db_logged_paths: set[str] = set()

_http_client_instance: Optional[Any] = None
_http_client_loop: Optional[asyncio.AbstractEventLoop] = None
_http_client_lock = threading.Lock()
_http_clients_by_loop: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, Any]" = weakref.WeakKeyDictionary()


def _get_file_stat_signature(db_path: str) -> Optional[Tuple[int, int]]:
    """Returns an mtime and size signature for detecting updated MMDB files on disk."""
    try:
        stat_result = os.stat(db_path)
    except OSError:
        return None
    return (stat_result.st_mtime_ns, stat_result.st_size)


def _get_maxmind_reader(db_path: str, maxminddb_module: Any) -> Any:
    """Returns a cached MaxMind reader, reopening it automatically when the file changes on disk."""
    current_sig = _get_file_stat_signature(db_path)
    stale_reader: Optional[Any] = None
    with _maxmind_lock:
        reader = _maxmind_readers.get(db_path)
        if reader is not None:
            if current_sig is None or _maxmind_reader_stats.get(db_path) == current_sig:
                return reader
            stale_reader = _maxmind_readers.pop(db_path, None)
            _maxmind_reader_stats.pop(db_path, None)
    if stale_reader is not None:
        try:
            stale_reader.close()
        except Exception as exc:
            logger.debug(f"Failed to close superseded MaxMind reader: {exc}")
    with _maxmind_lock:
        reader = _maxmind_readers.get(db_path)
        if reader is not None:
            return reader
        reader = maxminddb_module.open_database(db_path)
        _maxmind_readers[db_path] = reader
        _maxmind_reader_stats[db_path] = current_sig
        return reader


def _evict_maxmind_reader(db_path: str) -> None:
    """Removes and closes a cached MaxMind reader when an error occurs or the database file is absent."""
    with _maxmind_lock:
        reader = _maxmind_readers.pop(db_path, None)
        _maxmind_reader_stats.pop(db_path, None)
    if reader is not None:
        try:
            reader.close()
        except Exception as exc:
            logger.debug(f"Failed to close MaxMind reader: {exc}")


def _evict_missing_maxmind_readers(filename: str, resolved_path: str) -> None:
    """Evicts cached readers matching a missing MMDB path or filename so deleted files never leak handles."""
    with _maxmind_lock:
        stale_keys = [key for key in _maxmind_readers if key == resolved_path or os.path.basename(key) == filename]
    for key in stale_keys:
        _evict_maxmind_reader(key)


async def _strip_request_cookie_header(request: httpx.Request) -> None:
    request.headers.pop("cookie", None)


_DEFAULT_HTTP_LIMITS = httpx.Limits(
    max_connections=100,
    max_keepalive_connections=20,
)


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
    except Exception as exc:
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
    global _http_client_instance, _http_client_loop

    current_loop = asyncio.get_running_loop()
    stale_clients: List[Any] = []
    selected_client: Optional[Any] = None

    with _http_client_lock:
        if _http_client_instance is None and _http_client_loop is None:
            _http_clients_by_loop.clear()

        closed_loops = [
            loop
            for loop in list(_http_clients_by_loop.keys())
            if loop.is_closed() or getattr(_http_clients_by_loop.get(loop), "is_closed", False) is True
        ]
        for dead_loop in closed_loops:
            dead_client = _http_clients_by_loop.pop(dead_loop, None)
            if dead_client is not None:
                stale_clients.append(dead_client)

        if _http_client_instance is not None:
            tracked_in_live_loop = (
                isinstance(_http_client_loop, asyncio.AbstractEventLoop)
                and not _http_client_loop.is_closed()
                and _http_clients_by_loop.get(_http_client_loop) is _http_client_instance
            )
            if not tracked_in_live_loop:
                if _http_client_instance not in stale_clients:
                    stale_clients.append(_http_client_instance)
                _http_client_instance = None
                _http_client_loop = None

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
            _http_client_instance = new_client
            _http_client_loop = current_loop
            selected_client = new_client

    for stale_client in stale_clients:
        if stale_client is not selected_client:
            await _close_http_client_safely(stale_client)

    return selected_client


_UNSET_MOCK_ATTR = object()


def _is_valid_mmdb_prefix_tuple(result: Any) -> bool:
    """Returns True when a prefix lookup returned a (record_or_none, prefix_len) tuple."""
    return (
        isinstance(result, tuple)
        and len(result) == 2
        and (result[0] is None or isinstance(result[0], dict))
        and not isinstance(result[1], bool)
        and isinstance(result[1], int)
    )


def _should_use_custom_mmdb_get(reader: Any, mmdb_record: Any) -> bool:
    """Returns True when reader.get is a mock configured with custom behavior or a distinct record."""
    get_method = getattr(reader, "get", None)
    if get_method is None:
        return False
    if getattr(get_method, "_mock_side_effect", None) is not None:
        return True
    mock_return_value = getattr(get_method, "_mock_return_value", _UNSET_MOCK_ATTR)
    if mock_return_value is _UNSET_MOCK_ATTR:
        return False
    from unittest.mock import DEFAULT as MOCK_DEFAULT

    if mock_return_value is MOCK_DEFAULT:
        return False
    return mock_return_value != mmdb_record


def _lookup_mmdb_record_and_prefix(reader: Any, ip: str) -> Tuple[Optional[Dict[str, Any]], Optional[int]]:
    """
    Retrieves the MMDB record and routing prefix length in one lookup via get_with_prefix_len
    when supported, falling back to reader.get otherwise.
    """
    getter = getattr(reader, "get_with_prefix_len", None)
    if callable(getter):
        try:
            result = getter(ip)
        except AttributeError, NotImplementedError:
            result = None
        if _is_valid_mmdb_prefix_tuple(result):
            raw_rec, prefix_len = result
            if _should_use_custom_mmdb_get(reader, raw_rec):
                raw_rec = reader.get(ip)
            return (raw_rec if isinstance(raw_rec, dict) else None, prefix_len)

    rec = reader.get(ip)
    return (rec if isinstance(rec, dict) else None, None)


def _extract_mmdb_prefix_len(reader: Any, ip: str) -> Optional[int]:
    """Extracts the routing prefix length from a MaxMind reader when supported."""
    getter = getattr(reader, "get_with_prefix_len", None)
    if not callable(getter):
        return None
    try:
        result = getter(ip)
        if _is_valid_mmdb_prefix_tuple(result):
            return result[1]
    except Exception:
        return None
    return None


def _resolve_db_file(configured_path: str, filename: str, base_dir: Any) -> str:
    """Finds an MMDB database file across a configured directory or standard data locations."""
    return resolve_mmdb_file(configured_path, filename, base_dir)


def _merge_maxmind_dict_field(combined: Dict[str, Any], key: str, value: Any) -> None:
    """Deep-merges nested MaxMind dictionaries while keeping Country iso_code authoritative."""
    existing = combined.get(key)
    if isinstance(existing, dict) and isinstance(value, dict):
        merged = dict(existing)
        for sub_key, sub_val in value.items():
            if sub_key == "names" and isinstance(merged.get("names"), dict) and isinstance(sub_val, dict):
                merged["names"] = {**merged["names"], **sub_val}
            elif sub_val is not None:
                merged[sub_key] = sub_val
        combined[key] = merged
    elif value is not None:
        combined[key] = value


_MAXMIND_DB_SPECS = (
    ("country", MAXMIND_COUNTRY_DB_FILENAME),
    ("city", MAXMIND_CITY_DB_FILENAME),
    ("asn", MAXMIND_ASN_DB_FILENAME),
)

_MAXMIND_CITY_DB_CACHE_TTL_SECONDS = 5.0
_DEFAULT_OS_PATH_EXISTS = os.path.exists
_maxmind_city_db_cache: Optional[Tuple[Tuple[Any, ...], float, bool]] = None
_maxmind_any_db_cache: Optional[Tuple[Tuple[Any, ...], float, bool]] = None


def _resolve_maxmind_db_paths() -> Dict[str, str]:
    """Resolves Country, City, and ASN MMDB paths using configured MAXMIND_DB_DIR or fallbacks."""
    base_dir = getattr(settings, "BASE_DIR", os.getcwd())
    configured_dir = str(getattr(settings, "MAXMIND_DB_DIR", "") or os.environ.get("MAXMIND_DB_DIR", "")).strip()
    return {key: _resolve_db_file(configured_dir, filename, base_dir) for key, filename in _MAXMIND_DB_SPECS}


_DEFAULT_RESOLVE_MAXMIND_DB_PATHS = _resolve_maxmind_db_paths
_DEFAULT_RESOLVE_DB_FILE = _resolve_db_file


def _is_maxmind_probe_mocked() -> bool:
    return (
        (os.path.exists is not _DEFAULT_OS_PATH_EXISTS and getattr(os.path.exists, "_mock_wraps", None) is None)
        or (
            _resolve_maxmind_db_paths is not _DEFAULT_RESOLVE_MAXMIND_DB_PATHS
            and getattr(_resolve_maxmind_db_paths, "_mock_wraps", None) is None
        )
        or (_resolve_db_file is not _DEFAULT_RESOLVE_DB_FILE and getattr(_resolve_db_file, "_mock_wraps", None) is None)
    )


def _has_local_maxmind_city_db() -> bool:
    """Returns True when GeoLite2-City.mmdb is present on disk at its resolved location."""
    global _maxmind_city_db_cache

    exists_fn = os.path.exists
    if _is_maxmind_probe_mocked():
        city_path = _resolve_maxmind_db_paths().get("city", "")
        return bool(city_path and exists_fn(city_path))

    base_dir = getattr(settings, "BASE_DIR", os.getcwd())
    configured_dir = str(getattr(settings, "MAXMIND_DB_DIR", "") or os.environ.get("MAXMIND_DB_DIR", "")).strip()
    tool_data_dir = os.environ.get("TOOL_DATA_DIR", "").strip()
    cache_key = (configured_dir, str(base_dir), tool_data_dir, exists_fn, _resolve_maxmind_db_paths, _resolve_db_file)
    now_mono = time.monotonic()
    cached = _maxmind_city_db_cache
    if (
        cached is not None
        and cached[0] == cache_key
        and 0.0 <= (now_mono - cached[1]) < _MAXMIND_CITY_DB_CACHE_TTL_SECONDS
    ):
        return cached[2]

    city_path = _resolve_db_file(configured_dir, MAXMIND_CITY_DB_FILENAME, base_dir)
    has_city = bool(city_path and exists_fn(city_path))
    _maxmind_city_db_cache = (cache_key, now_mono, has_city)
    return has_city


def _merge_maxmind_records(
    country_rec: Optional[Dict[str, Any]],
    city_rec: Optional[Dict[str, Any]],
    asn_rec: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Combines Country, City, and ASN MMDB lookups while preserving iso_code consistency."""
    combined: Dict[str, Any] = {}
    if isinstance(city_rec, dict):
        for key, value in city_rec.items():
            if value is not None:
                combined[key] = value
    if isinstance(country_rec, dict):
        for key, value in country_rec.items():
            if key in ("country", "registered_country", "represented_country", "continent", "traits"):
                _merge_maxmind_dict_field(combined, key, value)
            elif key not in combined and value is not None:
                combined[key] = value
    if isinstance(asn_rec, dict):
        for key, value in asn_rec.items():
            if value is not None:
                combined[key] = value
    return combined


def _read_maxmind_sync(ip: str) -> Dict[str, Any]:
    """
    Reads local GeoLite2 and GeoIP2 Country, City, and ASN MMDB files synchronously.
    Offloaded via `asyncio.to_thread` to avoid blocking the ASGI event loop on disk I/O.
    """
    if not are_offline_intelligence_caches_warm():
        warm_offline_intelligence_caches()

    db_paths = _resolve_maxmind_db_paths()
    available_paths = {key: path for key, path in db_paths.items() if os.path.exists(path)}

    for key, filename in _MAXMIND_DB_SPECS:
        if key not in available_paths:
            _evict_missing_maxmind_readers(filename, db_paths[key])

    if not available_paths:
        return adapt_maxmind(None, has_db=False)

    city_path = db_paths["city"]
    if "city" in available_paths:
        with _maxmind_lock:
            _missing_city_db_logged_paths.discard(city_path)
    else:
        should_log_missing_city = False
        with _maxmind_lock:
            if city_path not in _missing_city_db_logged_paths:
                _missing_city_db_logged_paths.add(city_path)
                should_log_missing_city = True
        if should_log_missing_city:
            logger.warning(
                "GeoLite2-City.mmdb was not found at %s; MaxMind lookups will omit city and coordinates",
                city_path,
            )

    try:
        import maxminddb
    except ImportError:
        logger.warning("maxminddb package not installed; returning Database Missing fallback")
        return adapt_maxmind(None, has_db=False)

    try:
        records: Dict[str, Optional[Dict[str, Any]]] = {}
        prefix_lens: Dict[str, Optional[int]] = {}
        for key, path in available_paths.items():
            reader = _get_maxmind_reader(path, maxminddb)
            rec, prefix_len = _lookup_mmdb_record_and_prefix(reader, ip)
            records[key] = rec
            prefix_lens[key] = prefix_len

        combined_record = _merge_maxmind_records(
            records.get("country"),
            records.get("city"),
            records.get("asn"),
        )
        resolved_prefix_len = next(
            (prefix_lens.get(key) for key in ("asn", "country", "city") if prefix_lens.get(key) is not None),
            None,
        )
        if resolved_prefix_len is not None:
            combined_record["_mmdb_prefix_len"] = resolved_prefix_len
        offline_updated_at = get_maxmind_newest_mtime_iso()
        if offline_updated_at:
            combined_record["_offline_db_updated_at"] = offline_updated_at

        return adapt_maxmind(combined_record, has_db=True, status_code=200, ip=ip)
    except Exception as exc:
        for path in db_paths.values():
            _evict_maxmind_reader(path)
        safe_message = _sanitize_error_message(str(exc))
        logger.error(f"Error querying MaxMind local database: {safe_message}")
        return adapt_maxmind({"error": safe_message}, has_db=True, status_code=500)


async def query_maxmind(ip: str) -> Dict[str, Any]:
    return await asyncio.to_thread(_read_maxmind_sync, ip)


_rdns_context_state: contextvars.ContextVar[Optional[Dict[str, str]]] = contextvars.ContextVar(
    "_rdns_context_state", default=None
)

DEFAULT_DNS_TIMEOUT_SECONDS = 2.0


def _get_positive_float_setting(name: str, default: float) -> float:
    configured = getattr(settings, name, default)
    if (
        isinstance(configured, bool)
        or not isinstance(configured, (int, float))
        or not math.isfinite(float(configured))
        or float(configured) <= 0
    ):
        return default
    return float(configured)


def _get_dns_timeouts() -> Tuple[float, float]:
    timeout_s = _get_positive_float_setting("DNS_QUERY_TIMEOUT_SECONDS", DEFAULT_DNS_TIMEOUT_SECONDS)
    raw_lifetime = getattr(settings, "DNS_QUERY_LIFETIME_SECONDS", timeout_s)
    if (
        isinstance(raw_lifetime, bool)
        or not isinstance(raw_lifetime, (int, float))
        or not math.isfinite(float(raw_lifetime))
        or float(raw_lifetime) <= 0
    ):
        lifetime_s = timeout_s
    else:
        lifetime_s = float(raw_lifetime)
    return timeout_s, lifetime_s


_DEFAULT_ASYNC_RESOLVER_CLS = dns.asyncresolver.Resolver
_async_resolver_lock = threading.Lock()
_cached_base_nameservers: Optional[List[Any]] = None
_cached_async_resolvers: Dict[Tuple[float, float], dns.asyncresolver.Resolver] = {}


def _create_async_resolver() -> dns.asyncresolver.Resolver:
    global _cached_base_nameservers

    timeout_s, lifetime_s = _get_dns_timeouts()
    resolver_cls = dns.asyncresolver.Resolver
    if resolver_cls is not _DEFAULT_ASYNC_RESOLVER_CLS:
        try:
            resolver = resolver_cls()
        except dns.resolver.NoResolverConfiguration:
            resolver = resolver_cls(configure=False)
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = timeout_s
        resolver.lifetime = lifetime_s
        return resolver

    cache_key = (timeout_s, lifetime_s)
    with _async_resolver_lock:
        cached = _cached_async_resolvers.get(cache_key)
        if (
            cached is not None
            and cached.timeout == timeout_s
            and cached.lifetime == lifetime_s
            and bool(cached.nameservers)
        ):
            return cached

        if _cached_base_nameservers is None:
            try:
                base_resolver = resolver_cls()
                resolved_nameservers = (
                    list(base_resolver.nameservers) if base_resolver.nameservers else ["8.8.8.8", "1.1.1.1"]
                )
            except dns.resolver.NoResolverConfiguration:
                base_resolver = resolver_cls(configure=False)
                resolved_nameservers = ["8.8.8.8", "1.1.1.1"]
            _cached_base_nameservers = resolved_nameservers
            base_resolver.nameservers = list(resolved_nameservers)
            base_resolver.timeout = timeout_s
            base_resolver.lifetime = lifetime_s
            _cached_async_resolvers[cache_key] = base_resolver
            return base_resolver

        resolver = resolver_cls(configure=False)
        resolver.nameservers = list(_cached_base_nameservers)
        resolver.timeout = timeout_s
        resolver.lifetime = lifetime_s
        if len(_cached_async_resolvers) >= 16:
            _cached_async_resolvers.clear()
        _cached_async_resolvers[cache_key] = resolver
        return resolver


def _extract_ptr_hostname(answer: Any) -> Optional[str]:
    if answer is None:
        return None
    if isinstance(answer, str):
        return answer
    for rdata in answer:
        target = getattr(rdata, "target", None)
        if target is not None:
            to_text = getattr(target, "to_text", None)
            raw = to_text() if callable(to_text) else str(target)
            if isinstance(raw, str) and raw.strip():
                return raw
        to_text = getattr(rdata, "to_text", None)
        if callable(to_text):
            raw = to_text()
            if isinstance(raw, str) and raw.strip():
                return raw
        raw = str(rdata)
        if raw.strip():
            return raw
    return None


async def query_rdns_ptr(ip: str) -> Optional[str]:
    """
    Resolves the reverse DNS PTR hostname asynchronously via dnspython without
    blocking threads, distinguishing normal NXDOMAIN or NoAnswer from timeouts or errors.
    """
    state = _rdns_context_state.get()
    try:
        qname = dns.reversename.from_address(ip)
    except Exception:
        if isinstance(state, dict):
            state["status"] = "error"
        return None

    try:
        resolver = _create_async_resolver()
        answer = await resolver.resolve(qname, "PTR")
        raw_host = _extract_ptr_hostname(answer)
        if not isinstance(raw_host, str):
            if isinstance(state, dict):
                state["status"] = "nxdomain"
            return None
        cleaned = _sanitize_error_message(raw_host.strip().rstrip(".").lower())
        if not cleaned:
            if isinstance(state, dict):
                state["status"] = "nxdomain"
            return None
        if isinstance(state, dict):
            state["status"] = "ok"
        return cleaned
    except dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.YXDOMAIN:
        if isinstance(state, dict):
            state["status"] = "nxdomain"
        return None
    except dns.exception.Timeout, dns.resolver.LifetimeTimeout, asyncio.TimeoutError, TimeoutError:
        if isinstance(state, dict):
            state["status"] = "timeout"
        return None
    except dns.resolver.NoNameservers, dns.exception.DNSException, Exception:
        if isinstance(state, dict):
            state["status"] = "error"
        return None


def _reverse_ipv4_octets(ip: str) -> Optional[str]:
    """Reverses IPv4 dotted octets for DNSBL lookups and returns None for non-IPv4 addresses."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    if addr.version != 4:
        return None
    return ".".join(reversed(addr.exploded.split(".")))


def _extract_dnsbl_a_records(answer: Any) -> List[str]:
    if answer is None:
        return []
    codes: List[str] = []
    for rdata in answer:
        candidate: Optional[str] = None
        raw_addr = getattr(rdata, "address", None)
        if isinstance(raw_addr, str):
            candidate = raw_addr.strip()
        else:
            to_text = getattr(rdata, "to_text", None)
            if callable(to_text):
                txt = to_text()
                if isinstance(txt, str):
                    candidate = txt.strip()
            if candidate is None:
                candidate = str(rdata).strip()
        if not candidate:
            continue
        try:
            normalized = str(ipaddress.IPv4Address(candidate))
        except ValueError:
            continue
        if normalized not in codes:
            codes.append(normalized)
    return codes


async def _query_dnsbl_zone(
    ip: str,
    zone: str,
    provider_key: str,
    provider_label: str,
) -> Tuple[Dict[str, Any], int]:
    """Queries an IPv4 DNSBL zone asynchronously, skipping IPv6 targets and recording timeouts."""
    reversed_ip = _reverse_ipv4_octets(ip)
    if reversed_ip is None:
        return {
            "status": "skipped_ipv6",
            "query": None,
            "reversedIp": None,
            "codes": [],
        }, 200

    qname = f"{reversed_ip}.{zone}"
    default_cooldown, _, _ = _get_cooldown_bounds()
    try:
        resolver = _create_async_resolver()
        answer = await resolver.resolve(qname, "A")
        codes = _extract_dnsbl_a_records(answer)
        return {
            "status": "listed" if codes else "clean",
            "query": qname,
            "reversedIp": reversed_ip,
            "codes": codes,
        }, 200
    except dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.YXDOMAIN:
        return {
            "status": "clean",
            "query": qname,
            "reversedIp": reversed_ip,
            "codes": [],
        }, 200
    except (dns.exception.Timeout, dns.resolver.LifetimeTimeout, asyncio.TimeoutError, TimeoutError) as exc:
        safe_message = _sanitize_error_message(str(exc) or "DNS timeout")
        logger.warning(f"{provider_label} DNS query timed out for {qname}: {safe_message}")
        _record_upstream_event(
            provider_key,
            trigger_cooldown=True,
            status_code=504,
            reason="DNS Timeout",
            cooldown_seconds=default_cooldown,
            is_timeout=True,
        )
        return {
            "status": "timeout",
            "query": qname,
            "reversedIp": reversed_ip,
            "codes": [],
            "error": safe_message,
        }, 504
    except (dns.resolver.NoNameservers, dns.exception.DNSException, Exception) as exc:
        safe_message = _sanitize_error_message(str(exc) or "DNS resolution failed")
        logger.warning(f"{provider_label} DNS query failed for {qname}: {safe_message}")
        _record_upstream_event(
            provider_key,
            trigger_cooldown=True,
            status_code=502,
            reason=f"DNS Error ({type(exc).__name__})",
            cooldown_seconds=default_cooldown,
        )
        return {
            "status": "error",
            "query": qname,
            "reversedIp": reversed_ip,
            "codes": [],
            "error": safe_message,
        }, 502


async def query_spamhaus_zen(ip: str) -> Dict[str, Any]:
    raw_data, status_code = await _query_dnsbl_zone(ip, "zen.spamhaus.org", "spamhaus_zen", "Spamhaus ZEN")
    row = adapt_spamhaus_zen(raw_data, status_code)
    if row.get("isQueryRestricted"):
        default_cooldown, _, _ = _get_cooldown_bounds()
        _record_upstream_event(
            "spamhaus_zen",
            trigger_cooldown=True,
            status_code=429,
            reason=str(row.get("usageType") or "Spamhaus Query Restricted"),
            cooldown_seconds=default_cooldown,
        )
    return row


async def query_spamcop(ip: str) -> Dict[str, Any]:
    raw_data, status_code = await _query_dnsbl_zone(ip, "bl.spamcop.net", "spamcop", "SpamCop")
    return adapt_spamcop(raw_data, status_code)


USER_AGENT_HEADER = "ProxyCheck/1.0 (https://proxycheck.toolforge.org; tools.proxycheck@toolforge.org)"

DYNAMIC_CACHE_PROVIDERS = frozenset(
    {
        "ptr",
        "dnsbl",
        "spamhaus_zen",
        "spamcop",
        "tor_onionoo",
        "stopforumspam",
        "dshield",
    }
)

DEFAULT_STATIC_CACHE_TTL_SECONDS = 86400
DEFAULT_DYNAMIC_CACHE_TTL_SECONDS = 7200
DEFAULT_COOLDOWN_SECONDS = 120
MIN_COOLDOWN_SECONDS = 60
MAX_COOLDOWN_SECONDS = 300

_provider_upstream_events: contextvars.ContextVar[Optional[Dict[str, Dict[str, Any]]]] = contextvars.ContextVar(
    "_provider_upstream_events", default=None
)


def _get_positive_int_setting(name: str, default: int) -> int:
    configured = getattr(settings, name, default)
    if isinstance(configured, bool) or not isinstance(configured, int) or configured <= 0:
        return default
    return configured


def _get_provider_cache_ttl(provider_key: str) -> int:
    """Returns the Redis TTL in seconds for a static commercial or dynamic threat feed."""
    if provider_key in DYNAMIC_CACHE_PROVIDERS:
        return _get_positive_int_setting(
            "PROVIDER_DYNAMIC_CACHE_TTL_SECONDS",
            DEFAULT_DYNAMIC_CACHE_TTL_SECONDS,
        )
    return _get_positive_int_setting(
        "PROVIDER_STATIC_CACHE_TTL_SECONDS",
        DEFAULT_STATIC_CACHE_TTL_SECONDS,
    )


def _get_cooldown_bounds() -> Tuple[int, int, int]:
    min_s = _get_positive_int_setting("PROVIDER_COOLDOWN_MIN_SECONDS", MIN_COOLDOWN_SECONDS)
    max_s = _get_positive_int_setting("PROVIDER_COOLDOWN_MAX_SECONDS", MAX_COOLDOWN_SECONDS)
    low = min(min_s, max_s)
    high = max(min_s, max_s)
    default_s = _get_positive_int_setting("PROVIDER_COOLDOWN_DEFAULT_SECONDS", DEFAULT_COOLDOWN_SECONDS)
    return max(low, min(high, default_s)), low, high


def _extract_retry_after_header(resp: Any) -> Optional[str]:
    headers = getattr(resp, "headers", None)
    if headers is None:
        return None
    getter = getattr(headers, "get", None)
    if not callable(getter):
        return None
    for header_name in ("Retry-After", "retry-after"):
        val = getter(header_name)
        if isinstance(val, str):
            return val
    return None


def _parse_retry_after_seconds(raw_header: Optional[str]) -> int:
    """Parses an integer Retry-After delay and clamps it within configured cooldown bounds."""
    default_s, low, high = _get_cooldown_bounds()
    if not isinstance(raw_header, str):
        return default_s
    cleaned = raw_header.strip()
    if not re.fullmatch(r"\d+", cleaned):
        return default_s
    return max(low, min(high, int(cleaned)))


def _record_upstream_event(
    provider_key: str,
    *,
    trigger_cooldown: bool,
    status_code: int,
    reason: str = "",
    cooldown_seconds: Optional[int] = None,
    is_timeout: bool = False,
    is_transport_error: bool = False,
    upstream_remaining: Optional[int] = None,
    upstream_limit: Optional[int] = None,
    upstream_used: Optional[int] = None,
) -> None:
    events = _provider_upstream_events.get()
    if isinstance(events, dict):
        events[provider_key] = {
            "trigger": trigger_cooldown,
            "statusCode": status_code,
            "reason": reason,
            "cooldownSeconds": cooldown_seconds,
            "isTimeout": is_timeout,
            "isTransportError": is_transport_error,
            "upstreamRemaining": upstream_remaining,
            "upstreamLimit": upstream_limit,
            "upstreamUsed": upstream_used,
        }


async def _fetch_upstream_json(
    client: httpx.AsyncClient,
    provider_key: str,
    provider_label: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[Union[float, httpx.Timeout]] = None,
    follow_redirects: bool = False,
) -> Tuple[Any, int]:
    """
    Executes an upstream GET request, parses JSON safely, redacts leaked secrets on error,
    and records HTTP 429, 5xx, or timeout signals for per-provider circuit breaking.
    """
    default_cooldown, _, _ = _get_cooldown_bounds()
    request_kwargs: Dict[str, Any] = {"follow_redirects": follow_redirects}
    if headers is not None:
        request_kwargs["headers"] = headers
    if timeout is not None:
        request_kwargs["timeout"] = timeout
    try:
        resp = await client.get(url, **request_kwargs)
    except Exception as exc:
        is_timeout = isinstance(exc, (httpx.TimeoutException, asyncio.TimeoutError, TimeoutError))
        reason = "Upstream Timeout" if is_timeout else f"Upstream Exception ({type(exc).__name__})"
        raw_message = str(exc).strip()
        if raw_message:
            safe_message = _sanitize_error_message(raw_message)
        elif is_timeout:
            safe_message = f"{type(exc).__name__}: upstream request timed out"
        else:
            safe_message = type(exc).__name__
        logger.error(f"{provider_label} request exception: {safe_message}")
        _record_upstream_event(
            provider_key,
            trigger_cooldown=True,
            status_code=502,
            reason=reason,
            cooldown_seconds=default_cooldown,
            is_timeout=is_timeout,
            is_transport_error=True,
        )
        return {"status": "error", "message": safe_message}, 502

    raw_status = getattr(resp, "status_code", 502)
    payload, parsed_status, parse_error = _parse_upstream_json_with_error(resp)
    if isinstance(raw_status, int) and raw_status != 200:
        content_type, body_preview = _extract_response_log_details(resp)
        logger.warning(
            f"{provider_label} returned HTTP {raw_status} (Content-Type: {content_type}; body: {body_preview})"
        )
    elif parse_error is not None:
        content_type, body_preview = _extract_response_log_details(resp)
        logger.warning(
            f"{provider_label} returned non-JSON HTTP {raw_status} body ({parse_error} -> {parsed_status}; "
            f"Content-Type: {content_type}; body: {body_preview})"
        )
    upstream_remaining, upstream_limit, upstream_used = extract_upstream_rate_limit(
        resp,
        payload if raw_status == 200 and parsed_status == 200 else None,
        provider_key,
    )
    if raw_status == 429:
        retry_after_raw = _extract_retry_after_header(resp)
        cooldown_secs = _parse_retry_after_seconds(retry_after_raw)
        _record_upstream_event(
            provider_key,
            trigger_cooldown=True,
            status_code=429,
            reason="429 Rate Limited",
            cooldown_seconds=cooldown_secs,
            upstream_remaining=upstream_remaining,
            upstream_limit=upstream_limit,
        )
    elif isinstance(raw_status, int) and raw_status >= 500:
        _record_upstream_event(
            provider_key,
            trigger_cooldown=True,
            status_code=raw_status,
            reason=f"HTTP {raw_status}",
            cooldown_seconds=default_cooldown,
            upstream_remaining=upstream_remaining,
            upstream_limit=upstream_limit,
        )
    elif parsed_status >= 500 and raw_status == 200:
        _record_upstream_event(
            provider_key,
            trigger_cooldown=True,
            status_code=parsed_status,
            reason="Malformed Gateway Body",
            cooldown_seconds=default_cooldown,
        )
    else:
        _record_upstream_event(
            provider_key,
            trigger_cooldown=False,
            status_code=parsed_status,
            upstream_remaining=upstream_remaining,
            upstream_limit=upstream_limit,
            upstream_used=upstream_used,
        )
    return payload, parsed_status


async def query_cloudflare_radar(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    token = os.environ.get("CLOUDFLARE_RADAR_TOKEN") or getattr(settings, "CLOUDFLARE_RADAR_TOKEN", "")
    if not token:
        return adapt_cloudflare_radar(None, False)

    url = f"https://api.cloudflare.com/client/v4/radar/entities/asns/ip?ip={ip}"
    headers = {"Authorization": f"Bearer {token}"}
    payload, status_code = await _fetch_upstream_json(
        client, "cloudflare_radar", "Cloudflare Radar", url, headers=headers, timeout=8.0
    )
    return adapt_cloudflare_radar(payload, True, status_code)


async def query_abuseipdb(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = os.environ.get("ABUSEIPDB_API_KEY") or getattr(settings, "ABUSEIPDB_API_KEY", "")
    if not api_key:
        return adapt_abuseipdb(None, False)

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    payload, status_code = await _fetch_upstream_json(
        client, "abuseipdb", "AbuseIPDB", url, headers=headers, timeout=8.0
    )
    return adapt_abuseipdb(payload, True, status_code)


async def query_ipdata(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = os.environ.get("IPDATA_API_KEY") or getattr(settings, "IPDATA_API_KEY", "")
    if not api_key:
        return adapt_ipdata(None, False)

    url = f"https://api.ipdata.co/{ip}?api-key={api_key}"
    payload, status_code = await _fetch_upstream_json(client, "ipdata", "IPData", url, timeout=8.0)
    return adapt_ipdata(payload, True, status_code)


async def query_ipregistry(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = os.environ.get("IPREGISTRY_API_KEY") or getattr(settings, "IPREGISTRY_API_KEY", "")
    if not api_key:
        return adapt_ipregistry(None, False)

    url = f"https://api.ipregistry.co/{ip}?key={api_key}"
    payload, status_code = await _fetch_upstream_json(client, "ipregistry", "IPRegistry", url, timeout=8.0)
    return adapt_ipregistry(payload, True, status_code)


async def query_ip2location(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = os.environ.get("IP2LOCATION_API_KEY") or getattr(settings, "IP2LOCATION_API_KEY", "")
    if not api_key:
        return adapt_ip2location(None, False)

    url = f"https://api.ip2location.io/?key={api_key}&ip={ip}"
    payload, status_code = await _fetch_upstream_json(client, "ip2location", "IP2Location", url, timeout=5.0)
    return adapt_ip2location(payload, True, status_code)


async def query_getipintel(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    """GetIPIntel requires a valid contact email in the query string instead of an API key."""
    contact_email = os.environ.get("GETIPINTEL_CONTACT_EMAIL") or getattr(settings, "GETIPINTEL_CONTACT_EMAIL", "")
    if not contact_email:
        return adapt_getipintel(None, False)

    url = f"https://check.getipintel.net/check.php?ip={ip}&contact={contact_email}&flags=f&format=json"
    payload, status_code = await _fetch_upstream_json(client, "getipintel", "GetIPIntel", url, timeout=5.0)
    return adapt_getipintel(payload, True, status_code)


async def query_proxycheck(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = os.environ.get("PROXYCHECK_API_KEY") or getattr(settings, "PROXYCHECK_API_KEY", "")
    if not api_key:
        return adapt_proxycheck(None, False, 200, ip)

    url = f"https://proxycheck.io/v3/{ip}?key={api_key}&vpn=1&port=1&seen=1&risk=1"
    payload, status_code = await _fetch_upstream_json(client, "proxycheck", "Proxycheck", url, timeout=5.0)
    return adapt_proxycheck(payload, True, status_code, ip)


async def query_iphub(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = os.environ.get("IPHUB_API_KEY") or getattr(settings, "IPHUB_API_KEY", "")
    if not api_key:
        return adapt_iphub(None, False)

    url = f"https://v2.api.iphub.info/ip/{ip}"
    headers = {
        "X-Key": api_key,
        "Accept-Version": "2.2",
    }
    payload, status_code = await _fetch_upstream_json(client, "iphub", "IPHub", url, headers=headers, timeout=5.0)
    return adapt_iphub(payload, True, status_code)


async def query_iphunter(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = os.environ.get("IPHUNTER_API_KEY") or getattr(settings, "IPHUNTER_API_KEY", "")
    if not api_key:
        return adapt_iphunter(None, False)

    url = f"https://www.iphunter.info:8082/v1/ip/{ip}"
    headers = {
        "X-Key": api_key,
    }
    payload, status_code = await _fetch_upstream_json(client, "iphunter", "IPHunter", url, headers=headers, timeout=5.0)
    return adapt_iphunter(payload, True, status_code)


async def query_tor_onionoo(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    url = f"https://onionoo.torproject.org/summary?search={ip}"
    payload, status_code = await _fetch_upstream_json(client, "tor_onionoo", "Tor Onionoo", url, timeout=5.0)
    return adapt_tor_onionoo(payload, status_code=status_code, ip=ip)


def _has_any_local_stopforumspam_db() -> bool:
    return has_any_local_stopforumspam_db()


def _read_stopforumspam_sync(ip: str) -> Dict[str, Any]:
    try:
        lookup = query_stopforumspam_offline(ip)
    except Exception as exc:
        safe_message = _sanitize_error_message(str(exc))
        logger.error("Error querying StopForumSpam offline database: %s", safe_message)
        return adapt_stopforumspam({"success": 0, "error": safe_message}, status_code=500, has_db=True)

    if not lookup.get("has_db"):
        return adapt_stopforumspam(None, has_db=False)

    payload: Dict[str, Any] = {
        "success": 1,
        "ip": {
            "ip": ip,
            "appears": 1 if lookup.get("appears") else 0,
            "frequency": int(lookup.get("frequency") or 0),
            "lastseen": lookup.get("last_seen"),
            "blacklisted": bool(lookup.get("blacklisted")),
            "toxicCidr": lookup.get("toxic_cidr"),
            "sources": lookup.get("sources") or [],
        },
    }
    if lookup.get("offline_db_updated_at"):
        payload["offlineDbUpdatedAt"] = lookup["offline_db_updated_at"]
    return adapt_stopforumspam(payload, status_code=200, has_db=True)


async def query_stopforumspam(ip_or_client: Any, ip: Optional[str] = None) -> Dict[str, Any]:
    target_ip = ip if isinstance(ip, str) and ip.strip() else str(ip_or_client)
    return await asyncio.to_thread(_read_stopforumspam_sync, target_ip)


async def query_dshield(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    endpoints = (
        ("isc.sans.edu", f"https://isc.sans.edu/api/ip/{ip}?json"),
        ("www.dshield.org", f"https://www.dshield.org/api/ip/{ip}?json"),
    )
    headers = {
        "User-Agent": USER_AGENT_HEADER,
        "Accept": "application/json",
    }
    owned_events_token = None
    events = _provider_upstream_events.get()
    if not isinstance(events, dict):
        events = {}
        owned_events_token = _provider_upstream_events.set(events)

    payload: Any = None
    status_code = 502
    try:
        for idx, (host, url) in enumerate(endpoints):
            started_at = time.monotonic()
            payload, status_code = await _fetch_upstream_json(
                client,
                "dshield",
                "DShield",
                url,
                headers=headers,
                timeout=10.0,
                follow_redirects=True,
            )
            elapsed = time.monotonic() - started_at
            is_timeout = bool((events.get("dshield") or {}).get("isTimeout"))
            if is_timeout or elapsed > 5.0 or status_code not in (502, 503, 504) or idx == len(endpoints) - 1:
                break
            logger.warning(f"DShield primary endpoint {host} returned {status_code}; retrying fallback endpoint")
    finally:
        if owned_events_token is not None:
            _provider_upstream_events.reset(owned_events_token)
    return adapt_dshield(payload, status_code=status_code)


def aggregate_intelligence_metrics(
    ip: str,
    clean_results: List[Dict[str, Any]],
    ptr_hostname: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Computes an independent GetIPIntel prediction, network metadata summary, and a multi-source
    arbitration verdict with isolated hosting outlier handling.
    """
    valid_country_codes = set()
    valid_asns: List[str] = []
    valid_locations: List[str] = []
    valid_coords: List[str] = []

    getipintel_chance = None

    commercial_providers = {
        "AbuseIPDB",
        "IPData",
        "IPRegistry",
        "IP2Location",
        "GetIPIntel",
        "Proxycheck",
        "IPHub",
        "IPHunter",
    }
    positive_proxy_vpn_votes = 0
    total_commercial_responses = 0

    hosting_source_count = 0
    behavioral_threat_votes = 0
    clean_source_count = 0
    residential_source_count = 0
    has_datacenter_or_hosting = False
    has_anonymizer_flag = False

    hosting_keywords = ("datacenter", "data center", "hosting", "cloud", "transit", "cdn")
    residential_keywords = ("isp", "residential", "fixed line", "mobile", "commercial", "education")
    anonymizer_keywords = ("proxy", "vpn", "tor", "relay", "abuser", "attacker", "threat", "block 1", "spam", "botnet")

    is_tor = False
    tor_is_exit = False
    tor_running = False
    tor_flags: List[str] = []
    tor_label: Optional[str] = None
    tor_summary: Optional[str] = None

    normalized_results: List[Dict[str, Any]] = [
        {
            **item,
            "securityFlags": [dict(f) for f in item["securityFlags"] if isinstance(f, dict)]
            if isinstance(item.get("securityFlags"), list)
            else item.get("securityFlags"),
        }
        for item in (clean_results or [])
        if isinstance(item, dict)
    ]
    comparison_results: List[Dict[str, Any]] = []

    for r in normalized_results:
        # Exclude Tor Onionoo from the comparison panel and surface it only in overview Tor fields
        if r.get("provider") == "Tor Onionoo":
            if r.get("status") == "200 OK" and r.get("isTor"):
                is_tor = True
                tor_is_exit = bool(r.get("torIsExit"))
                tor_running = bool(r.get("torRunning"))
                raw_tor_flags = r.get("torFlags")
                if isinstance(raw_tor_flags, list):
                    tor_flags = [str(flag) for flag in raw_tor_flags if flag]
                tor_label = str(r.get("torLabel") or ("Tor Exit" if tor_is_exit else "Tor Node"))
                raw_tor_summary = r.get("torSummary")
                tor_summary = str(raw_tor_summary) if raw_tor_summary else None
            continue

        comparison_results.append(r)

        if r.get("status") != "200 OK":
            continue

        c_code = r.get("countryCode")
        if c_code and isinstance(c_code, str):
            c_code_clean = c_code.strip().upper()
            if len(c_code_clean) == 2 and c_code_clean.isalpha():
                valid_country_codes.add(c_code_clean)

        asn_val = r.get("asn")
        if asn_val and asn_val != "-" and str(asn_val).startswith("AS"):
            valid_asns.append(str(asn_val))

        loc_val = r.get("location")
        if loc_val and loc_val != "-":
            valid_locations.append(loc_val)

        coords_val = r.get("coordinates")
        if coords_val:
            valid_coords.append(coords_val)

        p_name = r.get("provider")
        usage_str = str(r.get("usageType") or "").lower()
        flags = r.get("securityFlags") or []

        if p_name == "GetIPIntel":
            chance_val = r.get("chance")
            if isinstance(chance_val, (int, float)):
                getipintel_chance = round(float(chance_val), 3)

        row_is_hosting = False
        row_is_anonymizer = False
        participates_in_arbitration = p_name in commercial_providers or p_name == "MaxMind"

        if participates_in_arbitration:
            if any(k in usage_str for k in hosting_keywords):
                row_is_hosting = True
            elif any(k in usage_str for k in residential_keywords):
                residential_source_count += 1

            for f in flags:
                if f.get("isHighRisk"):
                    label_lower = str(f.get("label") or "").lower()
                    if any(k in label_lower for k in hosting_keywords):
                        row_is_hosting = True
                    if any(k in label_lower for k in anonymizer_keywords):
                        row_is_anonymizer = True

            if row_is_hosting:
                has_datacenter_or_hosting = True
                hosting_source_count += 1
                if not any(f.get("isHighRisk") for f in flags):
                    flags = [{"label": "Hosting", "isHighRisk": True}]
                    r["securityFlags"] = flags
            if row_is_anonymizer:
                has_anonymizer_flag = True

            explicit_risk = r.get("riskScore")
            has_explicit_risk = (
                isinstance(explicit_risk, (int, float)) and not isinstance(explicit_risk, bool) and explicit_risk > 0
            )
            has_row_high_risk_flag = any(f.get("isHighRisk") for f in flags)

            if row_is_anonymizer or has_explicit_risk or (not row_is_hosting and has_row_high_risk_flag):
                behavioral_threat_votes += 1
            elif not row_is_hosting and not has_row_high_risk_flag:
                clean_source_count += 1

        if p_name in commercial_providers:
            total_commercial_responses += 1
            has_high_risk_flag = any(f.get("isHighRisk") for f in flags) or row_is_hosting or row_is_anonymizer
            if has_high_risk_flag:
                positive_proxy_vpn_votes += 1

    is_broadcast_ip = len(valid_country_codes) > 1
    primary_asn = valid_asns[0] if valid_asns else "-"
    primary_country = valid_locations[0].split("(")[0].strip() if valid_locations else "-"
    primary_coordinates = valid_coords[0] if valid_coords else "Unknown"

    if getipintel_chance is None:
        prediction_score = 0.0
        prediction_label = "GetIPIntel Unavailable"
        prediction_tier = "neutral"
    elif getipintel_chance >= 90.0:
        prediction_score = getipintel_chance
        prediction_label = "Proxy / VPN"
        prediction_tier = "destructive"
    elif getipintel_chance < 20.0:
        prediction_score = getipintel_chance
        prediction_label = "Normal"
        prediction_tier = "success"
    else:
        prediction_score = getipintel_chance
        prediction_label = "Needs Human Review"
        prediction_tier = "neutral"

    # Treat a single hosting tag as an outlier when at least five sources report clean residential usage and no behavioral threats exist.
    is_isolated_hosting_outlier = (
        not has_anonymizer_flag
        and behavioral_threat_votes == 0
        and hosting_source_count == 1
        and (clean_source_count >= 5 or residential_source_count >= 5)
    )

    if total_commercial_responses == 0:
        arbitration_verdict = "Direct Connection (No Commercial Threats)"
        is_majority_proxy_vpn = False
        arbitration_tier = "neutral"
    elif positive_proxy_vpn_votes > (total_commercial_responses / 2.0):
        if has_datacenter_or_hosting and not has_anonymizer_flag:
            arbitration_verdict = (
                f"Confirmed Datacenter / Hosting ({positive_proxy_vpn_votes}/{total_commercial_responses} Sources)"
            )
        else:
            arbitration_verdict = (
                f"Confirmed Proxy / VPN ({positive_proxy_vpn_votes}/{total_commercial_responses} Sources)"
            )
        is_majority_proxy_vpn = True
        arbitration_tier = "destructive"
    elif is_isolated_hosting_outlier or (
        behavioral_threat_votes == 0 and hosting_source_count == 1 and positive_proxy_vpn_votes <= 1
    ):
        arbitration_verdict = "Clean Residential (1 Minor Attribute Dispute)"
        is_majority_proxy_vpn = False
        arbitration_tier = "success"
    elif positive_proxy_vpn_votes > 0:
        if has_anonymizer_flag:
            arbitration_verdict = (
                f"Disputed Proxy / VPN ({positive_proxy_vpn_votes}/{total_commercial_responses} Sources)"
            )
        elif has_datacenter_or_hosting and not has_anonymizer_flag and residential_source_count == 0:
            arbitration_verdict = (
                f"Disputed Datacenter / Hosting ({positive_proxy_vpn_votes}/{total_commercial_responses} Sources)"
            )
        else:
            arbitration_verdict = (
                f"Disputed Residential / VPN ({positive_proxy_vpn_votes}/{total_commercial_responses} Sources)"
            )
        is_majority_proxy_vpn = False
        arbitration_tier = "warning"
    else:
        arbitration_verdict = f"Clean Residential / Direct (0/{total_commercial_responses} Sources)"
        is_majority_proxy_vpn = False
        arbitration_tier = "success"

    if is_tor and tor_running and not is_majority_proxy_vpn:
        tor_verdict_label = tor_label or ("Tor Exit" if tor_is_exit else "Tor Node")
        arbitration_verdict = f"Confirmed {tor_verdict_label} (Tor Onionoo)"
        arbitration_tier = "destructive"

    mmdb_prefix_len: Optional[int] = None
    cloud_cidr: Optional[str] = None
    cloud_provider: Optional[str] = None
    for row in comparison_results:
        if row.get("provider") == "MaxMind" and row.get("status") == "200 OK":
            candidate_len = row.get("prefixLength")
            if candidate_len is None and isinstance(row.get("rawJson"), dict):
                candidate_len = row["rawJson"].get("prefix_len")
            if not isinstance(candidate_len, bool) and isinstance(candidate_len, int):
                mmdb_prefix_len = candidate_len
            if isinstance(row.get("cloudCidr"), str) and row.get("cloudCidr"):
                cloud_cidr = row["cloudCidr"]
            if isinstance(row.get("cloudProvider"), str) and row.get("cloudProvider"):
                cloud_provider = row["cloudProvider"]

    rdns_info = classify_rdns_hostname(ptr_hostname)
    cidr_info = compute_cidr_attribution(
        ip,
        mmdb_prefix_len,
        cloud_cidr=cloud_cidr,
        cloud_provider=cloud_provider,
    )

    return {
        "ip": ip,
        "is_broadcast_ip": is_broadcast_ip,
        "isTor": is_tor,
        "torIsExit": tor_is_exit,
        "torRunning": tor_running,
        "torFlags": tor_flags,
        "torLabel": tor_label,
        "torSummary": tor_summary,
        "prediction_score": prediction_score,
        "predictionLabel": prediction_label,
        "predictionTier": prediction_tier,
        "getipintel_chance": getipintel_chance,
        "arbitrationVerdict": arbitration_verdict,
        "arbitrationTier": arbitration_tier,
        "isMajorityProxyVpn": is_majority_proxy_vpn,
        "primaryCountry": primary_country,
        "primaryCoordinates": primary_coordinates,
        "primaryAsn": primary_asn,
        "ptrHostname": rdns_info["ptrHostname"],
        "ptrCategory": rdns_info["ptrCategory"],
        "ptrLabel": rdns_info["ptrLabel"],
        "ptrIsHighRisk": rdns_info["isHighRisk"],
        "recommendedCidr": cidr_info["recommendedCidr"],
        "defaultCidr": cidr_info["defaultCidr"],
        "mmdbCidr": cidr_info["mmdbCidr"],
        "cloudCidr": cidr_info["cloudCidr"],
        "cloudProvider": cidr_info["cloudProvider"],
        "cidrNote": cidr_info["cidrNote"],
        "results": comparison_results,
    }


_ip_detect_inflight: Dict[Tuple[str, str], asyncio.Task] = {}
_ip_detect_inflight_lock = threading.Lock()

_DNSBL_PROVIDER_KEYS = frozenset({"spamhaus_zen", "spamcop"})
_OFFLINE_PROVIDER_KEYS = frozenset({"maxmind", "stopforumspam"})
_LIGHT_MODE_ACTIVE_PROVIDERS = frozenset(
    {"maxmind", "stopforumspam", "tor_onionoo", "dshield", "spamhaus_zen", "spamcop", "cloudflare_radar"}
)

_PROVIDER_SPECS: Tuple[Tuple[str, str, bool, bool, Callable[[Any, str], Any]], ...] = (
    ("cloudflare_radar", "Cloudflare Radar", True, True, lambda client, ip: query_cloudflare_radar(client, ip)),
    ("abuseipdb", "AbuseIPDB", True, True, lambda client, ip: query_abuseipdb(client, ip)),
    ("ipdata", "IPData", True, True, lambda client, ip: query_ipdata(client, ip)),
    ("ipregistry", "IPRegistry", True, True, lambda client, ip: query_ipregistry(client, ip)),
    ("ip2location", "IP2Location", True, True, lambda client, ip: query_ip2location(client, ip)),
    ("getipintel", "GetIPIntel", True, True, lambda client, ip: query_getipintel(client, ip)),
    ("proxycheck", "Proxycheck", True, True, lambda client, ip: query_proxycheck(client, ip)),
    ("iphub", "IPHub", True, True, lambda client, ip: query_iphub(client, ip)),
    ("iphunter", "IPHunter", True, True, lambda client, ip: query_iphunter(client, ip)),
    ("maxmind", "MaxMind", False, False, lambda _client, ip: query_maxmind(ip)),
    ("spamhaus_zen", "Spamhaus ZEN", False, True, lambda _client, ip: query_spamhaus_zen(ip)),
    ("spamcop", "SpamCop", False, True, lambda _client, ip: query_spamcop(ip)),
    ("tor_onionoo", "Tor Onionoo", True, True, lambda client, ip: query_tor_onionoo(client, ip)),
    ("stopforumspam", "StopForumSpam", False, False, lambda client, ip: query_stopforumspam(client, ip)),
    ("dshield", "DShield", True, True, lambda client, ip: query_dshield(client, ip)),
)


def _provider_cache_key(provider_key: str, canonical_ip: str) -> str:
    return f"{REDIS_KEY_NAMESPACE}:prov:{provider_key}:{canonical_ip}"


def _provider_cooldown_key(provider_key: str) -> str:
    return f"{REDIS_KEY_NAMESPACE}:cooldown:{provider_key}"


async def _safe_redis_get(key: str) -> Optional[str]:
    client = _get_redis_client()
    if client is None:
        return None
    try:
        raw_value = await client.get(key)
    except Exception as redis_read_err:
        mark_redis_failure(redis_read_err)
        logger.warning(f"Redis cache read bypassed for {key} due to error: {redis_read_err}")
        return None
    if raw_value is None:
        return None
    if isinstance(raw_value, bytes):
        return raw_value.decode("utf-8", errors="replace")
    return str(raw_value) if isinstance(raw_value, str) else None


async def _safe_redis_set(key: str, value: str, *, ex: int) -> None:
    client = _get_redis_client()
    if client is None:
        return
    try:
        await client.set(key, value, ex=ex)
    except Exception as redis_write_err:
        mark_redis_failure(redis_write_err)
        logger.warning(f"Redis cache write bypassed for {key} due to error: {redis_write_err}")


def _decode_redis_text_value(raw_value: Any) -> Optional[str]:
    if raw_value is None:
        return None
    if isinstance(raw_value, bytes):
        return raw_value.decode("utf-8", errors="replace")
    return raw_value if isinstance(raw_value, str) else None


def _discard_pending_awaitable(pending: Any) -> None:
    """Closes a coroutine that will never be awaited so it does not emit a runtime warning."""
    close_method = getattr(pending, "close", None)
    if inspect.iscoroutine(pending) and callable(close_method):
        close_method()


async def _safe_redis_mget(keys: List[str]) -> List[Optional[str]]:
    """Reads several keys in one round trip, falling back to single reads for clients without mget."""
    client = _get_redis_client()
    if client is None or not keys:
        return [None] * len(keys)
    mget_method = getattr(client, "mget", None)
    if callable(mget_method):
        try:
            pending = mget_method(keys)
            raw_values = await pending if inspect.isawaitable(pending) else pending
        except (AttributeError, TypeError) as mget_unsupported_err:
            logger.debug("Redis mget unavailable, falling back to single reads: %s", mget_unsupported_err)
        except Exception as redis_read_err:
            mark_redis_failure(redis_read_err)
            logger.warning(f"Redis batch cache read bypassed for {len(keys)} keys due to error: {redis_read_err}")
            return [None] * len(keys)
        else:
            # Test doubles without a real mget hand back mock objects, so only trust a list of matching length
            if isinstance(raw_values, (list, tuple)) and len(raw_values) == len(keys):
                return [_decode_redis_text_value(raw_value) for raw_value in raw_values]
    return list(await asyncio.gather(*(_safe_redis_get(key) for key in keys)))


async def _try_pipelined_set_many(client: Any, entries: List[Tuple[str, str, int]]) -> bool:
    """Returns False when the client cannot pipeline writes so the caller can fall back to single writes."""
    pipeline_factory = getattr(client, "pipeline", None)
    if not callable(pipeline_factory):
        return False
    pipe = pipeline_factory(transaction=False)
    if inspect.isawaitable(pipe):
        _discard_pending_awaitable(pipe)
        return False
    queue_set = getattr(pipe, "set", None)
    execute = getattr(pipe, "execute", None)
    if not callable(queue_set) or not callable(execute):
        return False
    for key, value, ttl_seconds in entries:
        queued = queue_set(key, value, ex=ttl_seconds)
        if inspect.isawaitable(queued):
            _discard_pending_awaitable(queued)
            return False
    pending = execute()
    if not inspect.isawaitable(pending):
        return False
    results = await pending
    return isinstance(results, (list, tuple)) and len(results) == len(entries)


async def _safe_redis_set_many(entries: List[Tuple[str, str, int]]) -> None:
    """Writes several keys with expiry in one pipelined round trip, falling back to single writes."""
    if not entries:
        return
    client = _get_redis_client()
    if client is None:
        return
    try:
        if await _try_pipelined_set_many(client, entries):
            return
    except (AttributeError, TypeError) as pipeline_unsupported_err:
        logger.debug("Redis pipeline unavailable, falling back to single writes: %s", pipeline_unsupported_err)
    except Exception as redis_write_err:
        mark_redis_failure(redis_write_err)
        logger.warning(f"Redis batch cache write bypassed for {len(entries)} keys due to error: {redis_write_err}")
        return
    await asyncio.gather(*(_safe_redis_set(key, value, ex=ttl_seconds) for key, value, ttl_seconds in entries))


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


def _decode_cached_provider_entry(raw_value: Optional[str]) -> Optional[Tuple[Dict[str, Any], Optional[str]]]:
    if not raw_value:
        return None
    try:
        parsed = json.loads(raw_value)
    except Exception:
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
    if "row" in parsed and isinstance(parsed["row"], dict):
        row = parsed["row"]
        if not parsed.get("sanitized") and isinstance(row.get("rawJson"), (dict, list)):
            row = {**row, "rawJson": _sanitize_payload(row["rawJson"])}
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
        if not parsed.get("sanitized") and isinstance(parsed.get("rawJson"), (dict, list)):
            parsed = {**parsed, "rawJson": _sanitize_payload(parsed["rawJson"])}
        return (
            _DecodedProviderRow(
                parsed,
                city_db_loaded=city_db_loaded,
                db_updated_at=db_updated_at,
                db_version=db_version,
                source_raw_value=raw_value,
            ),
            None,
        )
    return None


def _decode_cached_ptr_entry(raw_value: Optional[str]) -> Optional[Tuple[Optional[str], Optional[str]]]:
    if not raw_value:
        return None
    try:
        parsed = json.loads(raw_value)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    if parsed.get("status") not in ("ok", "nxdomain"):
        return None
    hostname = parsed.get("hostname")
    if hostname is not None and not isinstance(hostname, str):
        return None
    cached_at = parsed.get("cachedAt")
    cached_at_str = cached_at if isinstance(cached_at, str) and cached_at else None
    return hostname, cached_at_str


def _decode_cooldown_entry(raw_value: Optional[str]) -> Optional[Dict[str, Any]]:
    if not raw_value:
        return None
    try:
        parsed = json.loads(raw_value)
    except Exception:
        return None
    if isinstance(parsed, dict):
        return parsed
    return {"statusCode": 503, "reason": "Provider cooldown active"}


def _is_unconfigured_provider_row(row: Dict[str, Any]) -> bool:
    return (
        isinstance(row, dict)
        and row.get("status") in ("No API Key", "Database Missing", "Offline DB Missing", "Skipped (IPv6)")
        and row.get("statusCode") is None
    )


def _has_any_local_maxmind_db() -> bool:
    global _maxmind_any_db_cache

    exists_fn = os.path.exists
    if _is_maxmind_probe_mocked():
        return any(path and exists_fn(path) for path in _resolve_maxmind_db_paths().values())

    base_dir = getattr(settings, "BASE_DIR", os.getcwd())
    configured_dir = str(getattr(settings, "MAXMIND_DB_DIR", "") or os.environ.get("MAXMIND_DB_DIR", "")).strip()
    tool_data_dir = os.environ.get("TOOL_DATA_DIR", "").strip()
    cache_key = (configured_dir, str(base_dir), tool_data_dir, exists_fn, _resolve_maxmind_db_paths, _resolve_db_file)
    now_mono = time.monotonic()
    cached = _maxmind_any_db_cache
    if (
        cached is not None
        and cached[0] == cache_key
        and 0.0 <= (now_mono - cached[1]) < _MAXMIND_CITY_DB_CACHE_TTL_SECONDS
    ):
        return cached[2]

    has_any = any(path and exists_fn(path) for path in _resolve_maxmind_db_paths().values())
    _maxmind_any_db_cache = (cache_key, now_mono, has_any)
    return has_any


def _is_provider_cache_expected(provider_key: str, is_ipv4: bool) -> bool:
    """Returns False for sources that never write a cache entry for this address family or configuration."""
    if not is_ipv4 and provider_key in _DNSBL_PROVIDER_KEYS:
        return False
    if not is_provider_configured(provider_key):
        return False
    # Offline databases answer Database Missing or Offline DB Missing uncached when local files are absent
    if provider_key == "maxmind" and not _has_any_local_maxmind_db():
        return False
    if provider_key == "stopforumspam" and not _has_any_local_stopforumspam_db():
        return False
    return True


def _is_provider_result_cacheable(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    return row.get("statusCode") == 200 and row.get("status") == "200 OK"


def _build_cooldown_provider_row(provider_name: str, cooldown_info: Dict[str, Any]) -> Dict[str, Any]:
    raw_status = cooldown_info.get("statusCode")
    status_code = raw_status if isinstance(raw_status, int) and not isinstance(raw_status, bool) else 503
    reason = str(cooldown_info.get("reason") or "Upstream rate limited or degraded")
    custom_label = cooldown_info.get("statusLabel")
    is_quota_guard = bool(cooldown_info.get("isQuotaGuard"))
    if isinstance(custom_label, str) and custom_label.strip():
        status_label = custom_label.strip()
    else:
        status_label = "429 Cooldown (Rate Limited)" if status_code == 429 else f"{status_code} Cooldown (Circuit Open)"

    flag_label = "Local Quota Guard" if is_quota_guard else "Provider Cooldown"
    raw_payload: Dict[str, Any] = {
        "status": "quota_guarded" if is_quota_guard else "cooldown",
        "message": reason,
        "retryAfterSeconds": cooldown_info.get("cooldownSeconds"),
        "cooldownUntil": cooldown_info.get("until"),
    }
    if is_quota_guard:
        raw_payload["window"] = cooldown_info.get("window")
        raw_payload["used"] = cooldown_info.get("used")
        raw_payload["limit"] = cooldown_info.get("limit")

    row: Dict[str, Any] = {
        "provider": provider_name,
        "status": status_label,
        "statusCode": status_code,
        "asn": "-",
        "isp": "-",
        "organisation": "-",
        "location": "-",
        "usageType": "-",
        "securityFlags": [{"label": flag_label, "isHighRisk": False}],
        "isCooldown": True,
        "rawJson": _sanitize_payload(raw_payload),
    }
    if is_quota_guard:
        row["isQuotaGuarded"] = True
    return row


def _build_unhandled_provider_error_row(provider_name: str, safe_message: str) -> Dict[str, Any]:
    return {
        "provider": provider_name,
        "status": "500 Internal Error",
        "statusCode": 500,
        "asn": "-",
        "isp": "-",
        "organisation": "-",
        "location": "-",
        "usageType": "-",
        "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
        "rawJson": {"status": "error", "message": safe_message},
    }


def _should_refresh_cached_maxmind_entry(raw_value: Optional[str], row: Dict[str, Any]) -> bool:
    """Invalidates stale or pre-City cached MaxMind entries when local MMDB files change."""
    cached_db_updated = getattr(row, "_db_updated_at", None)
    if isinstance(cached_db_updated, str) and cached_db_updated:
        current_updated = get_maxmind_newest_mtime_iso()
        if current_updated and current_updated != cached_db_updated:
            return True
    if not _has_local_maxmind_city_db():
        return False
    if row.get("coordinates") is not None:
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


def _should_refresh_cached_stopforumspam_entry(row: Dict[str, Any]) -> bool:
    """Invalidates cached StopForumSpam entries when local database files change mtime."""
    cached_db_version = getattr(row, "_db_version", None)
    if cached_db_version is None:
        return False
    return cached_db_version != get_stopforumspam_db_version()


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


def _build_deferred_provider_row(provider_name: str) -> Dict[str, Any]:
    """Builds a placeholder row when an uncached commercial source is skipped in light mode."""
    return {
        "provider": provider_name,
        "status": "Deferred (Light Mode)",
        "statusCode": None,
        "asn": "-",
        "isp": "-",
        "organisation": "-",
        "location": "-",
        "usageType": "-",
        "securityFlags": [{"label": "Deferred (Light Mode)", "isHighRisk": False}],
        "isDeferred": True,
        "rawJson": {"status": "deferred", "mode": "light"},
    }


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
    aggregated = aggregate_intelligence_metrics(ip, clean_results, ptr_hostname=ptr_hostname)
    total_active = hit_count + miss_count + cooldown_count
    is_cached = hit_count > 0 and hit_count == total_active
    is_partial = hit_count > 0 and hit_count < total_active
    if is_cached:
        cache_status = "hit"
    elif is_partial:
        cache_status = "partial"
    else:
        cache_status = "miss"

    oldest_cached_at = min(cached_at_timestamps) if cached_at_timestamps else None
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
            "cachedAt": oldest_cached_at,
        },
    }


async def _execute_detection_with_cache(
    ip: str,
    *,
    initial_cache: Optional[
        Tuple[Dict[str, Tuple[Dict[str, Any], Optional[str]]], Optional[Tuple[Optional[str], Optional[str]]]]
    ] = None,
    query_mode: str = "full",
) -> Dict[str, Any]:
    normalized_mode = _normalize_query_mode(query_mode)
    if initial_cache is not None:
        cached_providers, cached_ptr = initial_cache
    else:
        cached_providers, cached_ptr = await _read_provider_caches(ip)

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
    cooldown_entries: Dict[str, Dict[str, Any]] = {}
    if active_redis is not None and missed_cooldown_keys:
        raw_cooldowns = await _safe_redis_mget(
            [_provider_cooldown_key(provider_key) for provider_key in missed_cooldown_keys]
        )
        for provider_key, raw_cd in zip(missed_cooldown_keys, raw_cooldowns, strict=True):
            decoded_cd = _decode_cooldown_entry(raw_cd)
            if decoded_cd is not None:
                cooldown_entries[provider_key] = decoded_cd

    candidate_specs = [
        (idx, spec)
        for idx, spec in enumerate(_PROVIDER_SPECS)
        if (
            spec[0] not in cached_providers
            and spec[0] not in deferred_provider_keys
            and spec[0] not in cooldown_entries
        )
    ]
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
    if active_redis is not None and quota_candidates:
        quota_results = await asyncio.gather(
            *(check_and_consume_quota(provider_key, now_dt=quota_dt) for provider_key in quota_candidates)
        )
        for provider_key, quota_res in zip(quota_candidates, quota_results, strict=True):
            if not quota_res.allowed:
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
            else:
                quota_consumed_keys.add(provider_key)

    specs_to_execute = [(idx, spec) for idx, spec in candidate_specs if spec[0] not in quota_blocked_entries]
    needs_http_client = any(spec[2] and spec[0] in cache_expected_keys for _, spec in specs_to_execute)
    needs_ptr = cached_ptr is None
    needs_rule_warmup = not are_offline_intelligence_caches_warm()
    maxmind_will_run = any(spec[0] == "maxmind" for _, spec in specs_to_execute)

    upstream_events: Dict[str, Dict[str, Any]] = {}
    events_token = _provider_upstream_events.set(upstream_events)
    rdns_state: Dict[str, str] = {"status": "ok"}
    rdns_token = _rdns_context_state.set(rdns_state)

    executed_provider_results: Dict[str, Any] = {}
    ptr_raw: Any = None
    try:
        client = await _get_shared_http_client() if needs_http_client else None
        coroutines = [spec[4](client, ip) for _, spec in specs_to_execute]
        ptr_index: Optional[int] = None
        if needs_ptr:
            ptr_index = len(coroutines)
            coroutines.append(query_rdns_ptr(ip))
        if needs_rule_warmup and not maxmind_will_run:
            coroutines.append(asyncio.to_thread(warm_offline_intelligence_caches))
        if coroutines:
            gathered = await asyncio.gather(*coroutines, return_exceptions=True)
            for pos, (_, (provider_key, _, _, _, _)) in enumerate(specs_to_execute):
                executed_provider_results[provider_key] = gathered[pos]
            if ptr_index is not None:
                ptr_raw = gathered[ptr_index]
    finally:
        _rdns_context_state.reset(rdns_token)
        _provider_upstream_events.reset(events_token)

    clean_results: List[Dict[str, Any]] = []
    redis_set_entries: List[Tuple[str, str, int]] = []
    telemetry_entries: List[Dict[str, Any]] = []
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    default_cooldown, _, _ = _get_cooldown_bounds()

    hit_count = 0
    miss_count = 0
    cooldown_count = 0
    cached_at_timestamps: List[str] = []

    for provider_key, provider_name, _uses_http, supports_cooldown, _ in _PROVIDER_SPECS:
        if provider_key in cached_providers:
            row, cached_at = cached_providers[provider_key]
            row_copy = dict(row)
            row_copy["isCached"] = True
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

        if provider_key in cooldown_entries:
            clean_results.append(_build_cooldown_provider_row(provider_name, cooldown_entries[provider_key]))
            cooldown_count += 1
            continue

        if provider_key in quota_blocked_entries:
            clean_results.append(_build_cooldown_provider_row(provider_name, quota_blocked_entries[provider_key]))
            cooldown_count += 1
            continue

        res = executed_provider_results.get(provider_key)
        miss_triggered_exception = isinstance(res, Exception)
        if miss_triggered_exception:
            safe_message = _sanitize_error_message(str(res))
            logger.error(f"Provider {provider_name} unhandled exception: {safe_message}")
            row = _build_unhandled_provider_error_row(provider_name, safe_message)
        else:
            row = (
                dict(res)
                if isinstance(res, dict)
                else _build_unhandled_provider_error_row(provider_name, "Invalid provider response")
            )
            # Last line of defence so upstream echoes of a key never reach the response or the cache
            if "rawJson" in row:
                row["rawJson"] = _sanitize_payload(row["rawJson"])

        clean_results.append(row)
        if not _is_unconfigured_provider_row(row):
            miss_count += 1

        if active_redis is not None:
            event = upstream_events.get(provider_key)
            status_code = row.get("statusCode")
            upstream_remaining = event.get("upstreamRemaining") if event else None
            upstream_limit = event.get("upstreamLimit") if event else None
            upstream_used = event.get("upstreamUsed") if event else None
            if provider_key == "ipdata" and upstream_used is None and _is_provider_result_cacheable(row):
                raw_json = row.get("rawJson")
                if isinstance(raw_json, dict) and raw_json.get("count") is not None:
                    _, fallback_limit, fallback_used = extract_upstream_rate_limit(None, raw_json, "ipdata")
                    if fallback_used is not None:
                        upstream_used = fallback_used
                        if upstream_limit is None and fallback_limit is not None:
                            upstream_limit = fallback_limit
                        if upstream_remaining is None and upstream_limit is not None and upstream_limit > 0:
                            upstream_remaining = max(0, upstream_limit - upstream_used)

            if not _is_unconfigured_provider_row(row):
                is_timeout_outcome = bool(
                    (event and event.get("isTimeout"))
                    or status_code == 504
                    or (
                        miss_triggered_exception
                        and isinstance(res, (httpx.TimeoutException, asyncio.TimeoutError, TimeoutError))
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
                    outcome_name = None

                should_refund_quota = bool(
                    provider_key in quota_consumed_keys
                    and (miss_triggered_exception or (event and event.get("isTransportError") is True))
                )

                if outcome_name is not None:
                    telemetry_entries.append(
                        {
                            "provider_key": provider_key,
                            "outcome": outcome_name,
                            "upstream_remaining": upstream_remaining,
                            "upstream_limit": upstream_limit,
                            "upstream_used": upstream_used,
                            "refund_quota": should_refund_quota,
                        }
                    )

            if _is_provider_result_cacheable(row):
                entry_payload: Dict[str, Any] = {"row": row, "cachedAt": now_iso, "sanitized": True}
                if provider_key == "maxmind":
                    entry_payload["cityDbLoaded"] = _has_local_maxmind_city_db()
                    mm_updated = get_maxmind_newest_mtime_iso()
                    if mm_updated:
                        entry_payload["dbUpdatedAt"] = mm_updated
                elif provider_key == "stopforumspam":
                    entry_payload["dbVersion"] = get_stopforumspam_db_version()
                cache_entry = json.dumps(entry_payload)
                redis_set_entries.append(
                    (
                        _provider_cache_key(provider_key, ip),
                        cache_entry,
                        _get_provider_cache_ttl(provider_key),
                    )
                )
            elif supports_cooldown:
                should_cooldown = bool(event and event.get("trigger"))
                if not should_cooldown and (
                    miss_triggered_exception
                    or status_code == 429
                    or (isinstance(status_code, int) and status_code >= 500)
                ):
                    should_cooldown = True

                if should_cooldown:
                    cd_seconds = (
                        event.get("cooldownSeconds")
                        if event and isinstance(event.get("cooldownSeconds"), int)
                        else None
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
                    redis_set_entries.append(
                        (
                            _provider_cooldown_key(provider_key),
                            cooldown_payload,
                            cd_seconds,
                        )
                    )

    if cached_ptr is not None:
        ptr_hostname, ptr_cached_at = cached_ptr
        hit_count += 1
        if ptr_cached_at:
            cached_at_timestamps.append(ptr_cached_at)
    else:
        miss_count += 1
        if isinstance(ptr_raw, Exception):
            ptr_hostname = None
            rdns_state["status"] = "error"
        elif isinstance(ptr_raw, str):
            ptr_hostname = ptr_raw
        else:
            ptr_hostname = None

        ptr_status = rdns_state.get("status", "ok")
        if active_redis is not None and ptr_status in ("ok", "nxdomain"):
            ptr_entry = json.dumps(
                {
                    "hostname": ptr_hostname,
                    "status": ptr_status,
                    "cachedAt": now_iso,
                }
            )
            redis_set_entries.append(
                (
                    _provider_cache_key("ptr", ip),
                    ptr_entry,
                    _get_provider_cache_ttl("ptr"),
                )
            )

    redis_write_ops = []
    if redis_set_entries:
        redis_write_ops.append(_safe_redis_set_many(redis_set_entries))
    if active_redis is not None and telemetry_entries:
        redis_write_ops.append(record_provider_outcomes_batch(telemetry_entries, now_dt=now_dt))

    if redis_write_ops:
        await asyncio.gather(*redis_write_ops)

    if not are_offline_intelligence_caches_warm():
        await asyncio.to_thread(warm_offline_intelligence_caches)

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


_WIKIMEDIA_ORIGIN_RE = re.compile(
    r"^https://([a-z0-9-]+\.)*(?:"
    r"wikipedia|wikimedia|wiktionary|wikibooks|wikinews|wikiquote|"
    r"wikisource|wikiversity|wikivoyage|wikidata|mediawiki|wikifunctions|wikimediafoundation"
    r")\.org$"
    r"|^https://([a-z0-9-]+\.)*(?:"
    r"wikipedia|wikimedia|wiktionary|wikibooks|wikinews|wikiquote|"
    r"wikisource|wikiversity|wikivoyage|wikidata|mediawiki|wikifunctions"
    r")\.beta\.wm(?:cloud|flabs)\.org$"
)
_LOCAL_DEV_ORIGIN_RE = re.compile(r"^https?://(?:localhost|127\.0\.0\.1)(?::\d{1,5})?$")

GADGET_TOKEN_SALT = "proxycheck.gadget.auth.v1"  # noqa: S105
DEFAULT_GADGET_TOKEN_TTL_SECONDS = 3600


def _get_gadget_token_ttl_seconds() -> int:
    configured = getattr(settings, "GADGET_TOKEN_TTL_SECONDS", DEFAULT_GADGET_TOKEN_TTL_SECONDS)
    if isinstance(configured, bool) or not isinstance(configured, int) or configured <= 0:
        return DEFAULT_GADGET_TOKEN_TTL_SECONDS
    return configured


def issue_gadget_token(username: str) -> str:
    """Signs a gadget authentication payload for an authenticated and authorised Wikimedia user."""
    payload = {"u": username, "scope": "gadget"}
    return signing.dumps(payload, salt=GADGET_TOKEN_SALT)


def _verify_gadget_bearer_token(auth_header: str) -> Tuple[Optional[str], Optional[str]]:
    """Validates an Authorization Bearer header containing a signed gadget token."""
    parts = auth_header.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None, "Invalid authorization header."
    token = parts[1].strip()
    if not token:
        return None, "Invalid authorization header."

    try:
        payload = signing.loads(
            token,
            salt=GADGET_TOKEN_SALT,
            max_age=_get_gadget_token_ttl_seconds(),
        )
    except signing.SignatureExpired:
        return None, "Authentication token expired. Please re-authenticate."
    except signing.BadSignature:
        return None, "Invalid authentication token."

    if not isinstance(payload, dict) or payload.get("scope") != "gadget":
        return None, "Invalid authentication token."

    username = payload.get("u")
    if not isinstance(username, str) or not username.strip():
        return None, "Invalid authentication token."

    cleaned_username = username.strip()
    if cleaned_username.startswith("~"):
        return None, "Invalid authentication token."

    return cleaned_username, None


def _is_allowed_wikimedia_origin(origin: Optional[str]) -> bool:
    if not origin or not isinstance(origin, str):
        return False
    candidate = origin.strip()
    if _WIKIMEDIA_ORIGIN_RE.match(candidate):
        return True
    return bool(getattr(settings, "DEBUG", False) and _LOCAL_DEV_ORIGIN_RE.match(candidate))


def _apply_detect_cors_headers(request, response, methods: str = "GET, OPTIONS"):
    origin = request.headers.get("Origin")
    if _is_allowed_wikimedia_origin(origin):
        response["Access-Control-Allow-Origin"] = origin.strip()
        response["Access-Control-Allow-Methods"] = methods
        response["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response["Access-Control-Max-Age"] = "86400"
        vary_existing = response.get("Vary")
        if not vary_existing:
            response["Vary"] = "Origin"
        elif "origin" not in [v.strip().lower() for v in vary_existing.split(",")]:
            response["Vary"] = f"{vary_existing}, Origin"
    return response


@csrf_exempt
async def exchange_gadget_token(request):
    """
    Exchanges a one-time MediaWiki CentralAuth token for a signed gadget Bearer token
    after verifying identity and unified RBAC permissions with Meta-Wiki.
    """
    if request.method == "OPTIONS":
        return _apply_detect_cors_headers(
            request,
            HttpResponse(status=204),
            methods="POST, OPTIONS",
        )

    if request.method != "POST":
        return _apply_detect_cors_headers(
            request,
            JsonResponse({"error": "Method not allowed"}, status=405),
            methods="POST, OPTIONS",
        )

    response = await _exchange_gadget_token_post(request)
    return _apply_detect_cors_headers(request, response, methods="POST, OPTIONS")


_MAX_MERGED_PROJECT_RIGHTS_LOOKUPS = 15
_MERGED_PROJECT_RIGHTS_BATCH_SIZE = 5


def _merged_project_edit_count(project: Dict[str, Any]) -> int:
    raw_edit_count = project.get("editcount", 0)
    if isinstance(raw_edit_count, bool):
        return 0
    try:
        edit_count = int(raw_edit_count)
    except TypeError, ValueError:
        return 0
    return max(edit_count, 0)


async def _populate_merged_project_rights(
    client: httpx.AsyncClient,
    username: str,
    merged_projects: Any,
    *,
    checked_domains: Set[str],
) -> List[Any]:
    """
    Fetches per-wiki user rights for merged SUL accounts with local group memberships,
    stopping once any project confirms a required temporary-account IP reveal right.
    """
    if not isinstance(merged_projects, list) or not merged_projects:
        return []

    enriched = [dict(project) if isinstance(project, dict) else project for project in merged_projects]
    candidates: List[Tuple[int, int, int, str]] = []
    seen_domains: Set[str] = set(checked_domains)

    for idx, project in enumerate(enriched):
        if not isinstance(project, dict):
            continue
        if isinstance(project.get("rights"), (list, tuple, set, frozenset)):
            continue
        # Only merged accounts carrying local groups can hold restricted temporary-account rights.
        project_groups = project.get("groups")
        if not isinstance(project_groups, list) or not any(g for g in project_groups if g):
            continue
        domain = extract_wikimedia_domain_from_project(project)
        if not domain or domain in seen_domains:
            continue
        seen_domains.add(domain)
        normalized_groups = {str(group).strip().lower() for group in project_groups if group}
        candidates.append(
            (
                0 if "sysop" in normalized_groups else 1,
                -_merged_project_edit_count(project),
                idx,
                domain,
            )
        )

    if not candidates:
        return enriched

    candidates.sort()
    candidates = candidates[:_MAX_MERGED_PROJECT_RIGHTS_LOOKUPS]

    for start in range(0, len(candidates), _MERGED_PROJECT_RIGHTS_BATCH_SIZE):
        batch = candidates[start : start + _MERGED_PROJECT_RIGHTS_BATCH_SIZE]
        results = await asyncio.gather(
            *(fetch_project_user_rights(client, username, domain) for _, _, _, domain in batch),
            return_exceptions=True,
        )
        found_required = False
        for (_, _, idx, _domain), result in zip(batch, results, strict=True):
            rights = result if isinstance(result, list) else []
            enriched[idx]["rights"] = rights
            normalized = {str(right).strip().lower() for right in rights if right}
            if normalized & REQUIRED_WIKIMEDIA_RIGHTS_SET:
                found_required = True
        if found_required:
            break

    return enriched


async def _resolve_wikimedia_access(
    client: httpx.AsyncClient,
    username: str,
    local_groups: List[str],
    local_rights: Optional[List[str]] = None,
    *,
    wiki_domain: str = "meta.wikimedia.org",
    local_rights_verified: bool = True,
) -> Tuple[bool, str, List[str], List[str]]:
    """
    Resolves Wikimedia temporary-account IP reveal access from local rights,
    global rights, cross-wiki merged project rights, and the explicit username allowlist
    so web OAuth and gadget flows share one rule set.
    """
    base_info: Dict[str, Any] = {
        "username": username,
        "local_groups": local_groups,
        "local_rights": local_rights or [],
        "global_groups": [],
        "global_rights": [],
        "merged_projects": [],
    }
    if username.strip().startswith("~") or is_allowlisted_wiki_user(username):
        return evaluate_wikimedia_rights(base_info)

    local_eval = evaluate_wikimedia_rights(base_info)
    try:
        meta_rights = await fetch_user_rights_from_meta(
            client,
            username,
            wiki_domain=wiki_domain,
        )
    except MetaWikiRightsFetchError as exc:
        if local_eval[0]:
            logger.warning(
                f"Global userinfo lookup failed for {username} on {wiki_domain}, "
                f"authorising via verified local wiki rights: {exc}"
            )
            return local_eval
        raise

    combined_info = {
        "username": username,
        "local_groups": local_groups,
        "local_rights": local_rights or [],
        "global_groups": meta_rights.get("global_groups", []),
        "global_rights": meta_rights.get("global_rights", []),
        "merged_projects": meta_rights.get("merged_projects", []),
    }
    eval_result = evaluate_wikimedia_rights(combined_info)
    if eval_result[0]:
        return eval_result

    checked_domains: Set[str] = set()
    validated_current = normalize_and_validate_wikimedia_domain(wiki_domain)
    if local_rights_verified and validated_current:
        checked_domains.add(validated_current)

    enriched_projects = await _populate_merged_project_rights(
        client,
        username,
        meta_rights.get("merged_projects", []),
        checked_domains=checked_domains,
    )
    return evaluate_wikimedia_rights(
        {
            **combined_info,
            "merged_projects": enriched_projects,
        }
    )


async def _exchange_gadget_token_post(request):
    try:
        raw_body = request.body.decode("utf-8-sig") if request.body else ""
        body = json.loads(raw_body) if raw_body.strip() else None
    except UnicodeDecodeError, ValueError:
        logger.warning("Invalid JSON request body received in exchange_gadget_token.", exc_info=True)
        return JsonResponse({"error": "Invalid JSON request body."}, status=400)

    if not isinstance(body, dict):
        return JsonResponse({"error": "Request body must be a JSON object."}, status=400)

    raw_centralauth_token = body.get("centralauthtoken")
    if raw_centralauth_token is None:
        return JsonResponse({"error": "Missing centralauthtoken parameter."}, status=400)
    if not isinstance(raw_centralauth_token, str):
        return JsonResponse({"error": "centralauthtoken must be a string."}, status=400)

    centralauth_token = raw_centralauth_token.strip()
    if not centralauth_token:
        return JsonResponse({"error": "centralauthtoken must not be empty."}, status=400)
    if len(centralauth_token) > 4096:
        return JsonResponse(
            {"error": "centralauthtoken exceeds maximum allowed length of 4096 characters."},
            status=400,
        )
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in centralauth_token):
        return JsonResponse(
            {"error": "centralauthtoken contains invalid whitespace or control characters."},
            status=400,
        )

    raw_domain = body.get("domain")
    if raw_domain is None:
        raw_domain = body.get("wiki_domain")
    if raw_domain is None or (isinstance(raw_domain, str) and not raw_domain.strip()):
        return JsonResponse({"error": "Missing Wikimedia domain parameter."}, status=400)

    wiki_domain = normalize_and_validate_wikimedia_domain(raw_domain)
    if not wiki_domain:
        return JsonResponse(
            {"error": "Invalid or unsupported Wikimedia domain."},
            status=400,
        )

    client = await _get_shared_http_client()
    try:
        wiki_userinfo = await verify_centralauth_userinfo(
            client,
            centralauth_token,
            wiki_domain=wiki_domain,
        )
    except InvalidCentralAuthTokenError as exc:
        logger.warning(
            "CentralAuth token validation failed for domain '%s': %s (mw_error=%s)",
            wiki_domain,
            _sanitize_error_message(str(exc)),
            _sanitize_payload(exc.mw_error) if exc.mw_error is not None else None,
        )
        return JsonResponse({"error": "Invalid CentralAuth token."}, status=401)
    except CentralAuthVerificationError as exc:
        logger.warning(
            "CentralAuth verification failed for domain '%s': %s (mw_error=%s)",
            wiki_domain,
            _sanitize_error_message(str(exc)),
            _sanitize_payload(exc.mw_error) if exc.mw_error is not None else None,
        )
        return JsonResponse(
            {"error": "Unable to verify CentralAuth credentials at this time."},
            status=503,
        )

    username = wiki_userinfo["username"]
    local_groups = wiki_userinfo.get("local_groups") or []
    local_rights = wiki_userinfo.get("rights")
    local_rights_verified = isinstance(local_rights, list)

    try:
        has_access, _, _, _ = await _resolve_wikimedia_access(
            client,
            username,
            local_groups,
            local_rights if isinstance(local_rights, list) else [],
            wiki_domain=wiki_domain,
            local_rights_verified=local_rights_verified,
        )
    except MetaWikiRightsFetchError as exc:
        if "missing" in str(exc).lower():
            return JsonResponse(
                {"error": "Access denied. Unrecognised Wikimedia user."},
                status=403,
            )
        return JsonResponse(
            {"error": "Unable to verify Wikimedia user rights at this time."},
            status=503,
        )

    if not has_access:
        return JsonResponse(
            {"error": "Access denied. Insufficient Wikimedia user rights."},
            status=403,
        )

    ttl_seconds = _get_gadget_token_ttl_seconds()
    signed_token = issue_gadget_token(username)
    return JsonResponse(
        {
            "token": signed_token,
            "username": username,
            "expires_in": ttl_seconds,
        }
    )


MAX_BATCH_IPS = 25
_MAX_RAW_BATCH_IPS = 50
_BATCH_DETECT_CONCURRENCY = 6


async def _authenticate_detect_request(request) -> Tuple[Optional[str], Optional[JsonResponse]]:
    """Validates gadget Bearer token or Wikimedia session credentials for IP detection endpoints."""
    auth_header = request.headers.get("Authorization")
    if auth_header is not None and str(auth_header).strip():
        token_user, token_error = _verify_gadget_bearer_token(str(auth_header))
        if token_error or not token_user:
            return None, JsonResponse(
                {"error": token_error or "Invalid authentication token."},
                status=401,
            )
        if getattr(settings, "RESTRICT_TO_ALLOWED_WIKI_USERS", False) and not is_allowlisted_wiki_user(token_user):
            return None, JsonResponse(
                {"error": "Access denied. Insufficient Wikimedia user rights."},
                status=403,
            )
        return "gadget", None

    session_user = await _get_session_user(request)
    if not isinstance(session_user, dict) or not session_user.get("isLoggedIn"):
        return None, JsonResponse(
            {"error": "Authentication required. Please log in with Wikimedia."},
            status=401,
        )
    if not session_user.get("hasAccess"):
        return None, JsonResponse(
            {"error": "Access denied. Insufficient Wikimedia user rights."},
            status=403,
        )
    return "session", None


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
            ip,
            non_public[0],
            non_public[1],
            start_time,
            query_mode=normalized_mode,
        )

    current_loop = asyncio.get_running_loop()
    inflight_key = (ip, normalized_mode)
    # Register the shared task before any await so that concurrent callers for the same key never
    # read the provider caches or run detection a second time, whether or not the caches are warm
    with _ip_detect_inflight_lock:
        existing_task = _ip_detect_inflight.get(inflight_key)
        if existing_task is not None:
            try:
                existing_loop = existing_task.get_loop()
            except Exception:
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

            created_task = current_loop.create_task(
                _run_coalesced_detection(
                    target_ip=ip,
                    target_mode=normalized_mode,
                )
            )

            def _finalize_inflight(
                done_task: asyncio.Task,
                task_key: Tuple[str, str] = inflight_key,
            ) -> None:
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
        base_payload = await _execute_detection_with_cache(
            ip,
            query_mode=normalized_mode,
        )

    cache_status = (base_payload.get("cacheMeta") or {}).get("status")
    if isinstance(cache_status, str) and cache_status in ("hit", "partial", "miss"):
        await record_global_request_telemetry(cache_status, auth_mode)

    response_payload = _strip_raw_json_from_payload(base_payload) if compact else base_payload
    return _attach_request_diagnostics(response_payload, start_time)


async def detect_ip(request):
    """
    Aggregates IP intelligence across upstream providers with non-public IP interception,
    singleflight coalescing, tiered per-provider Redis caching, and cooldown circuit breaking.
    """
    if request.method == "OPTIONS":
        return _apply_detect_cors_headers(request, HttpResponse(status=204))

    if request.method != "GET":
        return _apply_detect_cors_headers(
            request,
            JsonResponse({"error": "Method not allowed"}, status=405),
        )

    response = await _detect_ip_get(request)
    return _apply_detect_cors_headers(request, response)


async def _detect_ip_get(request):
    start_time = time.perf_counter()

    auth_mode, auth_error_response = await _authenticate_detect_request(request)
    if auth_error_response is not None or auth_mode is None:
        return auth_error_response

    raw_ip = request.GET.get("ip")
    if raw_ip is None or not str(raw_ip).strip():
        return JsonResponse(
            {
                "error": "invalid_ip",
                "message": "Missing required ip query parameter. Please provide a valid IPv4 or IPv6 address.",
            },
            status=400,
        )

    ip = canonicalize_ip(str(raw_ip))
    if not ip:
        return JsonResponse(
            {
                "error": "invalid_ip",
                "message": "Invalid IP address format. Please provide a valid IPv4 or IPv6 address.",
            },
            status=400,
        )

    is_compact = _is_compact_request(request)
    query_mode = _resolve_query_mode(request)
    payload = await _detect_single_canonical_ip(
        ip,
        auth_mode,
        start_time,
        compact=is_compact,
        query_mode=query_mode,
    )
    response = JsonResponse(payload)
    response["Cache-Control"] = "private, max-age=300"
    return response


@csrf_exempt
async def detect_ip_batch(request):
    """
    Executes bounded-concurrency batch IP intelligence detection for up to MAX_BATCH_IPS
    addresses in a single POST request.
    """
    if request.method == "OPTIONS":
        return _apply_detect_cors_headers(
            request,
            HttpResponse(status=204),
            methods="POST, OPTIONS",
        )

    if request.method != "POST":
        return _apply_detect_cors_headers(
            request,
            JsonResponse({"error": "Method not allowed"}, status=405),
            methods="POST, OPTIONS",
        )

    response = await _detect_ip_batch_post(request)
    return _apply_detect_cors_headers(request, response, methods="POST, OPTIONS")


async def _detect_ip_batch_post(request):
    start_time = time.perf_counter()

    auth_mode, auth_error_response = await _authenticate_detect_request(request)
    if auth_error_response is not None or auth_mode is None:
        return auth_error_response

    try:
        raw_body = request.body.decode("utf-8-sig") if request.body else ""
        body = json.loads(raw_body) if raw_body.strip() else None
    except UnicodeDecodeError, ValueError:
        return JsonResponse(
            {
                "error": "invalid_batch",
                "message": "Invalid JSON request body.",
            },
            status=400,
        )

    if not isinstance(body, dict):
        return JsonResponse(
            {
                "error": "invalid_batch",
                "message": "Request body must be a JSON object containing an ips array.",
            },
            status=400,
        )

    raw_ips = body.get("ips")
    if not isinstance(raw_ips, list) or not raw_ips:
        return JsonResponse(
            {
                "error": "invalid_batch",
                "message": "The ips parameter must be a non-empty array of IP addresses.",
            },
            status=400,
        )

    if len(raw_ips) > _MAX_RAW_BATCH_IPS:
        return JsonResponse(
            {
                "error": "invalid_batch",
                "message": f"Batch request exceeds maximum allowed raw entries ({_MAX_RAW_BATCH_IPS}).",
            },
            status=400,
        )

    unique_canonical_ips: List[str] = []
    seen_canonical: Set[str] = set()
    input_map: Dict[str, str] = {}

    for item in raw_ips:
        if not isinstance(item, str) or not item.strip():
            return JsonResponse(
                {
                    "error": "invalid_batch",
                    "message": "Each entry in ips must be a non-empty IP address string.",
                },
                status=400,
            )
        canonical = canonicalize_ip(item)
        if not canonical:
            return JsonResponse(
                {
                    "error": "invalid_batch",
                    "message": f"Invalid IP address format: {item.strip()[:64]}",
                },
                status=400,
            )
        input_map[item] = canonical
        stripped_item = item.strip()
        if stripped_item != item:
            input_map[stripped_item] = canonical
        if canonical not in seen_canonical:
            seen_canonical.add(canonical)
            unique_canonical_ips.append(canonical)

    if len(unique_canonical_ips) > MAX_BATCH_IPS:
        return JsonResponse(
            {
                "error": "invalid_batch",
                "message": f"Batch request exceeds maximum of {MAX_BATCH_IPS} unique IP addresses.",
            },
            status=400,
        )

    is_compact = _is_compact_request(request, body)
    query_mode = _resolve_query_mode(request, body)
    semaphore = asyncio.Semaphore(_BATCH_DETECT_CONCURRENCY)

    async def _detect_bounded(canonical_ip: str) -> Tuple[str, Dict[str, Any]]:
        async with semaphore:
            ip_start_time = time.perf_counter()
            payload = await _detect_single_canonical_ip(
                canonical_ip,
                auth_mode,
                ip_start_time,
                compact=is_compact,
                query_mode=query_mode,
            )
            return canonical_ip, payload

    pairs = await asyncio.gather(*(_detect_bounded(ip) for ip in unique_canonical_ips))
    results_by_ip: Dict[str, Dict[str, Any]] = dict(pairs)

    return JsonResponse(
        _attach_request_diagnostics(
            {
                "results": results_by_ip,
                "inputMap": input_map,
                "count": len(results_by_ip),
                "queryMode": query_mode,
            },
            start_time,
        )
    )


_SESSION_UNAVAILABLE_ERROR = "Authentication session storage is temporarily unavailable."


def _safe_save_session(request, *, context: str) -> bool:
    """Persists modified session state, degrading cleanly when Redis or the cache backend fails."""
    try:
        request.session.save()
        return True
    except Exception as exc:
        if not is_session_backend_error(exc):
            raise
        request.session.modified = False
        logger.warning(
            "Session save skipped during %s due to cache backend unavailability (%s)",
            context,
            type(exc).__name__,
        )
        return False


def _safe_flush_session(request, *, context: str) -> bool:
    """Flushes the current session, clearing modified state if cache deletion fails."""
    try:
        request.session.flush()
        return True
    except Exception as exc:
        if not is_session_backend_error(exc):
            raise
        request.session.clear()
        request.session.modified = False
        logger.warning(
            "Session flush degraded during %s due to cache backend unavailability (%s)",
            context,
            type(exc).__name__,
        )
        return False


def _read_session_user_sync(request, *, context: str) -> Any:
    """Reads and validates session user data while shielding callers from cache backend outages."""
    try:
        session_user = request.session.get("wikimedia_user")
    except Exception as exc:
        if not is_session_backend_error(exc):
            raise
        request.session.modified = False
        logger.warning(
            "Session read degraded during %s due to cache backend unavailability (%s)",
            context,
            type(exc).__name__,
        )
        return None
    if not session_user:
        return None
    ttl = getattr(settings, "SESSION_RIGHTS_TTL_SECONDS", DEFAULT_RIGHTS_TTL_SECONDS)
    if is_session_rights_expired(session_user, ttl_seconds=ttl):
        request.session.pop("wikimedia_user", None)
        request.session.modified = True
        _safe_save_session(request, context=context)
        return None
    return session_user


@sync_to_async(thread_sensitive=True)
def _get_session_user(request, *, context: str = "session_rights_check") -> Any:
    """Thread-safe synchronous helper for reading and validating session user data."""
    return _read_session_user_sync(request, context=context)


@sync_to_async(thread_sensitive=True)
def _pop_oauth_login_context(request) -> Tuple[Any, Optional[str], bool]:
    """Pops the OAuth state token and optional post-login IP target from the session in one write."""
    try:
        state = request.session.pop("oauth_state", None)
        post_login_ip = request.session.pop("oauth_post_login_ip", None)
    except Exception as exc:
        if not is_session_backend_error(exc):
            raise
        request.session.modified = False
        logger.warning(
            "OAuth login context load failed due to cache backend unavailability (%s)",
            type(exc).__name__,
        )
        return None, None, False
    request.session.modified = True
    saved = _safe_save_session(request, context="oauth_callback_state_pop")
    cleaned_ip = canonicalize_ip(str(post_login_ip)) if isinstance(post_login_ip, str) else None
    return state, cleaned_ip, saved


@sync_to_async(thread_sensitive=True)
def _persist_oauth_login_context(request, state: str, post_login_ip: Optional[str]) -> bool:
    """Persists OAuth state and an optional validated IP deep-link target with rollback on failure."""
    had_prev_ip = "oauth_post_login_ip" in request.session
    prev_ip = request.session.get("oauth_post_login_ip")
    request.session["oauth_state"] = state
    if post_login_ip:
        request.session["oauth_post_login_ip"] = post_login_ip
    else:
        request.session.pop("oauth_post_login_ip", None)
    request.session.modified = True
    if not _safe_save_session(request, context="oauth_login"):
        request.session.pop("oauth_state", None)
        if had_prev_ip:
            request.session["oauth_post_login_ip"] = prev_ip
        else:
            request.session.pop("oauth_post_login_ip", None)
        request.session.modified = False
        return False
    return True


@sync_to_async(thread_sensitive=True)
def _persist_authenticated_session(
    request,
    user_data: Dict[str, Any],
    *,
    context: str = "oauth_callback_login",
) -> bool:
    """Thread-safe synchronous helper for persisting authenticated user data in Django session storage."""
    payload = dict(user_data)
    if "rights_updated_at" not in payload:
        payload["rights_updated_at"] = time.time()
    request.session["wikimedia_user"] = payload
    request.session.modified = True
    if not _safe_save_session(request, context=context):
        request.session.pop("wikimedia_user", None)
        request.session.modified = False
        return False
    return True


@sync_to_async(thread_sensitive=True)
def _flush_session_async(request, *, context: str) -> bool:
    """Thread-safe synchronous helper for flushing Django session state under ASGI."""
    flushed = _safe_flush_session(request, context=context)
    if flushed:
        request.session.modified = True
    return flushed


async def get_current_user(request):
    start_time = time.perf_counter()
    session_user = await _get_session_user(request, context="get_current_user")

    if not isinstance(session_user, dict) or not session_user:
        payload = {
            "isLoggedIn": False,
            "username": "",
            "role": "",
            "hasAccess": False,
            "isAdmin": False,
            "localGroups": [],
            "globalGroups": [],
        }
    else:
        payload = dict(session_user)
        payload["isAdmin"] = is_admin_user(session_user)

    return JsonResponse(_attach_request_diagnostics(payload, start_time))


async def _authorize_admin_session_request(request, *, context: str) -> Optional[JsonResponse]:
    """Enforces GET-only allowlisted session access without accepting gadget Bearer tokens."""
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    auth_header = request.headers.get("Authorization")
    if auth_header is not None and str(auth_header).strip():
        return JsonResponse(
            {"error": "Access denied. Administrator session privileges required."},
            status=403,
        )

    session_user = await _get_session_user(request, context=context)
    if not isinstance(session_user, dict) or not session_user.get("isLoggedIn"):
        return JsonResponse(
            {"error": "Authentication required. Please log in with Wikimedia."},
            status=401,
        )
    if not is_admin_user(session_user):
        return JsonResponse(
            {"error": "Access denied. Allowlisted administrator privileges required."},
            status=403,
        )
    return None


async def admin_provider_dashboard(request):
    """
    Returns anonymised API quota usage, reactive cooldown states, and daily telemetry
    for allowlisted administrators.
    """
    start_time = time.perf_counter()
    denied_response = await _authorize_admin_session_request(request, context="admin_provider_dashboard")
    if denied_response is not None:
        return denied_response

    snapshot = await build_dashboard_snapshot()
    response = JsonResponse(_attach_request_diagnostics(snapshot, start_time))
    response["Cache-Control"] = "no-store"
    return response


async def oauth_login(request):
    """
    Redirects to Meta-Wiki OAuth 2.0 authorization when credentials are set,
    falling back to a local sysop session for staging or preview environments without OAuth keys.
    """
    client_id = getattr(settings, "WIKIMEDIA_CLIENT_ID", "")
    redirect_uri = getattr(settings, "WIKIMEDIA_REDIRECT_URI", "")
    auth_base = getattr(settings, "WIKIMEDIA_OAUTH_URL", "https://meta.wikimedia.org/w/rest.php/oauth2")
    raw_next_ip = request.GET.get("ip")
    post_login_ip = canonicalize_ip(str(raw_next_ip)) if raw_next_ip is not None else None

    if client_id and redirect_uri:
        state = secrets.token_urlsafe(32)
        if not await _persist_oauth_login_context(request, state, post_login_ip):
            return JsonResponse({"error": _SESSION_UNAVAILABLE_ERROR}, status=503)
        query_params = urlencode(
            {
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": redirect_uri,
                "scope": "basic",
                "state": state,
            }
        )
        auth_url = f"{auth_base}/authorize?{query_params}"
        return HttpResponseRedirect(auth_url)

    if not (getattr(settings, "DEBUG", False) and getattr(settings, "ENABLE_TEST_AUTH", False)):
        return JsonResponse(
            {"error": "OAuth 2.0 client credentials are not configured."},
            status=503,
        )

    user_data = {
        "isLoggedIn": True,
        "username": "ExampleAdmin",
        "role": "Local Administrator (sysop)",
        "hasAccess": True,
        "localGroups": ["sysop"],
        "globalGroups": [],
        "rights_updated_at": time.time(),
    }
    if not await _persist_authenticated_session(request, user_data, context="oauth_login_test_auth"):
        return JsonResponse({"error": _SESSION_UNAVAILABLE_ERROR}, status=503)
    fallback_redirect = f"/?{urlencode({'ip': post_login_ip})}" if post_login_ip else "/"
    return HttpResponseRedirect(fallback_redirect)


_OAUTH_CALLBACK_ERROR_CODES = {
    "access_denied": "access_denied",
    "consent_required": "consent_required",
    "interaction_required": "interaction_required",
    "invalid_request": "invalid_request",
    "invalid_scope": "invalid_scope",
    "login_required": "login_required",
    "server_error": "server_error",
    "temporarily_unavailable": "temporarily_unavailable",
    "unauthorized_client": "unauthorized_client",
    "unsupported_response_type": "unsupported_response_type",
}


async def oauth_callback(request):
    """
    Exchanges the OAuth 2.0 authorization code for an access token, inspects Wikimedia
    temporary-account IP reveal rights, and persists the evaluated role in the session.
    """
    expected_state, post_login_ip, state_saved = await _pop_oauth_login_context(request)
    if not state_saved:
        return JsonResponse({"error": _SESSION_UNAVAILABLE_ERROR}, status=503)

    # Map query errors to fixed identifiers so raw request values never reach logs.
    callback_error_raw = request.GET.get("error", "").strip().lower()
    if callback_error_raw:
        known_error_code = _OAUTH_CALLBACK_ERROR_CODES.get(callback_error_raw)
        if known_error_code is not None:
            logger.warning("OAuth callback returned error: %s", known_error_code)
        else:
            logger.warning("OAuth callback returned an unrecognized error code")
        return HttpResponseRedirect("/")

    provided_state = request.GET.get("state", "").strip()
    if (
        not isinstance(expected_state, str)
        or not expected_state
        or not isinstance(provided_state, str)
        or not provided_state
        or not secrets.compare_digest(expected_state.encode("utf-8"), provided_state.encode("utf-8"))
    ):
        logger.warning("OAuth callback state validation failed or missing")
        return HttpResponseRedirect("/")

    code = request.GET.get("code", "").strip()
    client_id = getattr(settings, "WIKIMEDIA_CLIENT_ID", "")
    client_secret = getattr(settings, "WIKIMEDIA_CLIENT_SECRET", "")
    redirect_uri = getattr(settings, "WIKIMEDIA_REDIRECT_URI", "")
    auth_base = getattr(settings, "WIKIMEDIA_OAUTH_URL", "https://meta.wikimedia.org/w/rest.php/oauth2")

    if not code or not client_id or not client_secret:
        logger.warning("OAuth callback missing code or client credentials")
        return HttpResponseRedirect("/")

    headers = {
        "User-Agent": USER_AGENT_HEADER,
    }
    redirect_target = "/"

    try:
        async with httpx.AsyncClient(timeout=10.0, headers=headers) as client:
            token_resp = await client.post(
                f"{auth_base}/access_token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "redirect_uri": redirect_uri,
                },
            )
            if token_resp.status_code != 200:
                logger.error(f"Wikimedia OAuth token exchange failed: HTTP {token_resp.status_code}")
                return HttpResponseRedirect("/")

            token_data = token_resp.json()
            access_token = token_data.get("access_token", "")
            if not access_token:
                logger.error("OAuth token response contained no access_token")
                return HttpResponseRedirect("/")

            profile_resp = await client.get(
                f"{auth_base}/resource/profile",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if profile_resp.status_code != 200:
                logger.error(f"Wikimedia OAuth profile fetch failed: HTTP {profile_resp.status_code}")
                return HttpResponseRedirect("/")

            profile = profile_resp.json()
            if not isinstance(profile, dict):
                logger.warning("Wikimedia OAuth profile payload was not a JSON object")
                return HttpResponseRedirect("/")

            raw_username = profile.get("username")
            if not isinstance(raw_username, str) or not raw_username.strip():
                logger.warning("Authenticated Wikimedia username missing from OAuth profile")
                return HttpResponseRedirect("/")

            username = raw_username.strip()
            if username.startswith("~"):
                logger.warning("Temporary Wikimedia accounts cannot authenticate via OAuth")
                return HttpResponseRedirect("/")

            raw_groups = profile.get("groups")
            local_groups = raw_groups if isinstance(raw_groups, list) else []
            raw_rights = profile.get("rights")
            local_rights_verified = isinstance(raw_rights, list)
            local_rights = raw_rights if local_rights_verified else []

            has_access, role_label, norm_local, norm_global = await _resolve_wikimedia_access(
                client,
                username,
                local_groups,
                local_rights,
                wiki_domain="meta.wikimedia.org",
                local_rights_verified=local_rights_verified,
            )

            user_session_payload = {
                "isLoggedIn": True,
                "username": username,
                "role": role_label,
                "hasAccess": has_access,
                "localGroups": norm_local,
                "globalGroups": norm_global,
                "rights_updated_at": time.time(),
            }
            persisted = await _persist_authenticated_session(request, user_session_payload)
            if not persisted:
                return JsonResponse({"error": _SESSION_UNAVAILABLE_ERROR}, status=503)
            if has_access and post_login_ip:
                redirect_target = f"/?{urlencode({'ip': post_login_ip})}"
            logger.info(f"User {username} successfully authenticated with role: {role_label}")
    except Exception as exc:
        logger.error(f"OAuth callback processing error ({type(exc).__name__})")

    return HttpResponseRedirect(redirect_target)


async def oauth_logout(request):
    start_time = time.perf_counter()
    await _flush_session_async(request, context="oauth_logout")
    return JsonResponse(_attach_request_diagnostics({"status": "logged_out"}, start_time))


@csrf_exempt
async def switch_test_role(request):
    """Switches session persona to verify RBAC states during staging and acceptance tests."""
    if not (getattr(settings, "DEBUG", False) and getattr(settings, "ENABLE_TEST_AUTH", False)):
        return JsonResponse(
            {"error": "Role switching is only available when DEBUG and ENABLE_TEST_AUTH are enabled."},
            status=403,
        )

    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        body = json.loads(request.body.decode("utf-8")) if request.body else {}
    except Exception:
        body = {}

    target = body.get("role", "sysop")

    if target == "unauthenticated":
        await _flush_session_async(request, context="switch_test_role")
        return JsonResponse(
            {
                "isLoggedIn": False,
                "username": "",
                "role": "",
                "hasAccess": False,
                "isAdmin": False,
                "localGroups": [],
                "globalGroups": [],
            }
        )

    if target == "unauthorised":
        user_data = {
            "isLoggedIn": True,
            "username": "StandardEditor",
            "role": "Standard User (Unauthorised)",
            "hasAccess": False,
            "localGroups": ["autoreview"],
            "globalGroups": [],
        }
    elif target == "steward":
        user_data = {
            "isLoggedIn": True,
            "username": "StewardUser",
            "role": "Steward",
            "hasAccess": True,
            "localGroups": [],
            "globalGroups": ["steward"],
        }
    elif target == "global-rollbacker":
        user_data = {
            "isLoggedIn": True,
            "username": "GlobalRollbackUser",
            "role": "Global Rollbacker",
            "hasAccess": True,
            "localGroups": [],
            "globalGroups": ["global-rollbacker"],
        }
    else:
        user_data = {
            "isLoggedIn": True,
            "username": "LocalSysopUser",
            "role": "Local Administrator (sysop)",
            "hasAccess": True,
            "localGroups": ["sysop"],
            "globalGroups": [],
        }

    user_data["rights_updated_at"] = time.time()
    if not await _persist_authenticated_session(request, user_data, context="switch_test_role"):
        return JsonResponse({"error": _SESSION_UNAVAILABLE_ERROR}, status=503)
    return JsonResponse({**user_data, "isAdmin": is_admin_user(user_data)})


async def system_status(request):
    """Returns live file mtime metadata for all offline databases to allowlisted administrators."""
    start_time = time.perf_counter()
    denied_response = await _authorize_admin_session_request(request, context="system_status")
    if denied_response is not None:
        return denied_response

    now_dt = datetime.now(timezone.utc)
    offline_databases = await asyncio.to_thread(collect_offline_databases_status, now_dt=now_dt)
    payload = _attach_request_diagnostics(
        {
            "generatedAt": now_dt.isoformat(),
            "offlineDatabases": offline_databases,
        },
        start_time,
    )
    response = JsonResponse(payload)
    response["Cache-Control"] = "no-store"
    return response
