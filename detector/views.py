"""
Asynchronous HTTP views and backwards-compatible facade exports for IP intelligence
aggregation and Wikimedia OAuth 2.0 session handling.
"""

import asyncio
import json
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, Tuple
from urllib.parse import urlencode

import dns
import httpx
from django.conf import settings
from django.core import signing
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .adapters import adapt_getipintel, warm_offline_intelligence_caches
from .cache_backends import (
    _DEFAULT_OS_PATH_EXISTS,
    _DEFAULT_RESOLVE_DB_FILE,
    _DEFAULT_RESOLVE_MAXMIND_DB_PATHS,
    _MAXMIND_CITY_DB_CACHE_TTL_SECONDS,
    _MAXMIND_DB_SPECS,
    _REDIS_CIRCUIT_BREAKER_DEFAULT_SECONDS,
    _REDIS_CIRCUIT_FAILURE_ERRORS,
    _REDIS_INIT_ERRORS,
    _REDIS_SOCKET_TIMEOUT_SECONDS,
    _UNSET_MOCK_ATTR,
    DEFAULT_COOLDOWN_SECONDS,
    DEFAULT_DYNAMIC_CACHE_TTL_SECONDS,
    DEFAULT_GETIPINTEL_STABLE_CACHE_TTL_SECONDS,
    DEFAULT_STATIC_CACHE_TTL_SECONDS,
    DYNAMIC_CACHE_PROVIDERS,
    MAX_COOLDOWN_SECONDS,
    MIN_COOLDOWN_SECONDS,
    _decode_cached_provider_entry,
    _decode_cached_ptr_entry,
    _decode_cooldown_entry,
    _decode_redis_text_value,
    _DecodedProviderRow,
    _discard_pending_awaitable,
    _evict_maxmind_reader,
    _evict_missing_maxmind_readers,
    _get_circuit_breaker_cooldown_seconds,
    _get_cooldown_bounds,
    _get_maxmind_reader,
    _get_provider_cache_ttl,
    _get_redis_client,
    _has_any_local_maxmind_db,
    _has_local_maxmind_city_db,
    _is_maxmind_probe_mocked,
    _is_stable_getipintel_result,
    _maxmind_any_db_cache,
    _maxmind_city_db_cache,
    _maxmind_lock,
    _maxmind_reader_stats,
    _maxmind_readers,
    _missing_city_db_logged_paths,
    _provider_cache_key,
    _provider_cooldown_key,
    _redis_client_lock,
    _redis_clients_by_loop,
    _resolve_db_file,
    _resolve_maxmind_db_paths,
    _run_redis_cache_op,
    _safe_redis_get,
    _safe_redis_mget,
    _safe_redis_set,
    _safe_redis_set_many,
    _should_refresh_cached_maxmind_entry,
    _should_refresh_cached_stopforumspam_entry,
    _try_pipelined_set_many,
    aioredis,
    is_redis_circuit_open,
    mark_redis_failure,
    redis_client,
    reset_redis_circuit_breaker,
)
from .detection_service import (
    _DEFAULT_HTTP_LIMITS,
    _DNSBL_PROVIDER_KEYS,
    _LIGHT_MODE_ACTIVE_PROVIDERS,
    _OFFLINE_PROVIDER_KEYS,
    _assemble_detection_payload,
    _await_inflight_task,
    _build_cookieless_http_client,
    _close_http_client_safely,
    _detect_single_canonical_ip,
    _execute_detection_with_cache,
    _get_shared_http_client,
    _http_client_lock,
    _http_clients_by_loop,
    _ip_detect_inflight,
    _ip_detect_inflight_lock,
    _is_provider_cache_expected,
    _read_provider_caches,
    _release_inflight_task,
    _StaleInflightLoopError,
    _strip_raw_json_from_payload,
    _strip_request_cookie_header,
)
from .dns_providers import (
    _DEFAULT_ASYNC_RESOLVER_CLS,
    DEFAULT_DNS_TIMEOUT_SECONDS,
    _async_resolver_lock,
    _cached_async_resolvers,
    _cached_base_nameservers,
    _create_async_resolver,
    _extract_dnsbl_a_records,
    _extract_ptr_hostname,
    _is_valid_mmdb_prefix_tuple,
    _lookup_mmdb_record_and_prefix,
    _merge_maxmind_dict_field,
    _merge_maxmind_records,
    _provider_upstream_events,
    _query_dnsbl_zone,
    _rdns_context_state,
    _read_maxmind_sync,
    _read_stopforumspam_sync,
    _record_upstream_event,
    _reverse_ipv4_octets,
    _should_use_custom_mmdb_get,
    query_maxmind,
    query_rdns_ptr,
    query_spamcop,
    query_spamhaus_zen,
    query_stopforumspam,
)
from .intelligence import (
    _CGNAT_NETWORK,
    _DOC_NETWORKS,
    _PROC_RSS_CACHE_TTL_SECONDS,
    MAX_BATCH_IPS,
    _attach_request_diagnostics,
    _build_non_public_response_payload,
    _classify_non_public_ip,
    _is_builtin_open_mocked,
    _is_compact_request,
    _normalize_query_mode,
    _parse_batch_ips,
    _proc_rss_cache,
    _read_proc_rss_mb,
    _resolve_query_mode,
    aggregate_intelligence_metrics,
    canonicalize_ip,
    get_process_memory_mb,
)
from .oauth import (
    CentralAuthVerificationError,
    InvalidCentralAuthTokenError,
    MetaWikiRightsFetchError,
    fetch_project_user_rights,
    fetch_user_rights_from_meta,
    verify_centralauth_userinfo,
)
from .offline_dbs import collect_offline_databases_status
from .providers import (
    _PROVIDER_SPECS,
    USER_AGENT_HEADER,
    _build_cooldown_provider_row,
    _build_deferred_provider_row,
    _build_unhandled_provider_error_row,
    _extract_retry_after_header,
    _fetch_upstream_json,
    _is_provider_result_cacheable,
    _is_unconfigured_provider_row,
    _parse_retry_after_seconds,
    query_abuseipdb,
    query_cloudflare_radar,
    query_dshield,
    query_getipintel,
    query_ip2location,
    query_ipdata,
    query_iphub,
    query_iphunter,
    query_ipregistry,
    query_proxycheck,
    query_tor_onionoo,
)
from .quota_telemetry import (
    build_dashboard_snapshot,
    check_and_consume_quota,
    is_admin_user,
    record_global_request_telemetry,
    record_provider_outcomes_batch,
)
from .sanitization import (
    _MIN_SECRET_LENGTH,
    _SECRET_SETTING_NAMES,
    REDACTED_PLACEHOLDER,
    _configured_secret_values,
    _extract_response_log_details,
    _parse_upstream_json_with_error,
    _sanitize_error_message,
    _sanitize_payload,
)
from .session_auth import (
    _LOCAL_DEV_ORIGIN_RE,
    _MAX_MERGED_PROJECT_RIGHTS_LOOKUPS,
    _MERGED_PROJECT_RIGHTS_BATCH_SIZE,
    _SESSION_UNAVAILABLE_ERROR,
    _TEST_ROLE_PROFILES,
    _WIKIMEDIA_ORIGIN_RE,
    DEFAULT_GADGET_TOKEN_TTL_SECONDS,
    GADGET_TOKEN_SALT,
    _apply_detect_cors_headers,
    _authenticate_detect_request,
    _authorize_admin_session_request,
    _flush_session_async,
    _get_gadget_token_ttl_seconds,
    _get_session_user,
    _is_allowed_wikimedia_origin,
    _merged_project_edit_count,
    _parse_gadget_token_payload,
    _persist_authenticated_session,
    _persist_oauth_login_context,
    _pop_oauth_login_context,
    _populate_merged_project_rights,
    _read_session_user_sync,
    _resolve_wikimedia_access,
    _safe_flush_session,
    _safe_save_session,
    _verify_gadget_bearer_token,
    issue_gadget_token,
)

__all__ = [
    "DEFAULT_COOLDOWN_SECONDS", "DEFAULT_DNS_TIMEOUT_SECONDS", "DEFAULT_DYNAMIC_CACHE_TTL_SECONDS",
    "DEFAULT_GADGET_TOKEN_TTL_SECONDS", "DEFAULT_GETIPINTEL_STABLE_CACHE_TTL_SECONDS",
    "DEFAULT_STATIC_CACHE_TTL_SECONDS", "DYNAMIC_CACHE_PROVIDERS", "GADGET_TOKEN_SALT", "MAX_BATCH_IPS",
    "MAX_COOLDOWN_SECONDS", "MIN_COOLDOWN_SECONDS", "REDACTED_PLACEHOLDER", "USER_AGENT_HEADER", "_CGNAT_NETWORK",
    "_DEFAULT_ASYNC_RESOLVER_CLS", "_DEFAULT_HTTP_LIMITS", "_DEFAULT_OS_PATH_EXISTS", "_DEFAULT_RESOLVE_DB_FILE",
    "_DEFAULT_RESOLVE_MAXMIND_DB_PATHS", "_DNSBL_PROVIDER_KEYS", "_DOC_NETWORKS", "_DecodedProviderRow",
    "_LIGHT_MODE_ACTIVE_PROVIDERS", "_LOCAL_DEV_ORIGIN_RE", "_MAXMIND_CITY_DB_CACHE_TTL_SECONDS",
    "_MAXMIND_DB_SPECS", "_MAX_MERGED_PROJECT_RIGHTS_LOOKUPS", "_MERGED_PROJECT_RIGHTS_BATCH_SIZE",
    "_MIN_SECRET_LENGTH", "_OFFLINE_PROVIDER_KEYS", "_PROC_RSS_CACHE_TTL_SECONDS", "_PROVIDER_SPECS",
    "_REDIS_CIRCUIT_BREAKER_DEFAULT_SECONDS", "_REDIS_CIRCUIT_FAILURE_ERRORS", "_REDIS_INIT_ERRORS",
    "_REDIS_SOCKET_TIMEOUT_SECONDS", "_SECRET_SETTING_NAMES", "_SESSION_UNAVAILABLE_ERROR",
    "_StaleInflightLoopError", "_UNSET_MOCK_ATTR", "_WIKIMEDIA_ORIGIN_RE", "_apply_detect_cors_headers",
    "_assemble_detection_payload", "_async_resolver_lock", "_attach_request_diagnostics",
    "_authenticate_detect_request", "_authorize_admin_session_request", "_await_inflight_task",
    "_build_cookieless_http_client", "_build_cooldown_provider_row", "_build_deferred_provider_row",
    "_build_non_public_response_payload", "_build_unhandled_provider_error_row", "_cached_async_resolvers",
    "_cached_base_nameservers", "_classify_non_public_ip", "_close_http_client_safely", "_configured_secret_values",
    "_create_async_resolver", "_decode_cached_provider_entry", "_decode_cached_ptr_entry", "_decode_cooldown_entry",
    "_decode_redis_text_value", "_detect_single_canonical_ip", "_discard_pending_awaitable",
    "_evict_maxmind_reader", "_evict_missing_maxmind_readers", "_execute_detection_with_cache",
    "_extract_dnsbl_a_records", "_extract_ptr_hostname", "_extract_response_log_details",
    "_extract_retry_after_header", "_fetch_upstream_json", "_flush_session_async",
    "_get_circuit_breaker_cooldown_seconds", "_get_cooldown_bounds", "_get_gadget_token_ttl_seconds",
    "_get_maxmind_reader", "_get_provider_cache_ttl", "_get_redis_client", "_get_session_user",
    "_get_shared_http_client", "_has_any_local_maxmind_db", "_has_local_maxmind_city_db", "_http_client_lock",
    "_http_clients_by_loop", "_ip_detect_inflight", "_ip_detect_inflight_lock", "_is_allowed_wikimedia_origin",
    "_is_builtin_open_mocked", "_is_maxmind_probe_mocked", "_is_provider_cache_expected",
    "_is_provider_result_cacheable", "_is_stable_getipintel_result", "_is_unconfigured_provider_row",
    "_is_valid_mmdb_prefix_tuple", "_lookup_mmdb_record_and_prefix", "_maxmind_any_db_cache",
    "_maxmind_city_db_cache", "_maxmind_lock", "_maxmind_reader_stats", "_maxmind_readers",
    "_merge_maxmind_dict_field", "_merge_maxmind_records", "_merged_project_edit_count",
    "_missing_city_db_logged_paths", "_normalize_query_mode", "_parse_retry_after_seconds",
    "_parse_upstream_json_with_error", "_persist_authenticated_session", "_persist_oauth_login_context",
    "_pop_oauth_login_context", "_populate_merged_project_rights", "_proc_rss_cache", "_provider_cache_key",
    "_provider_cooldown_key", "_provider_upstream_events", "_query_dnsbl_zone", "_rdns_context_state",
    "_read_maxmind_sync", "_read_proc_rss_mb", "_read_provider_caches", "_read_session_user_sync",
    "_read_stopforumspam_sync", "_record_upstream_event", "_redis_client_lock", "_redis_clients_by_loop",
    "_release_inflight_task", "_resolve_db_file", "_resolve_maxmind_db_paths", "_resolve_wikimedia_access",
    "_reverse_ipv4_octets", "_run_redis_cache_op", "_safe_flush_session", "_safe_redis_get", "_safe_redis_mget",
    "_safe_redis_set", "_safe_redis_set_many", "_safe_save_session", "_sanitize_error_message", "_sanitize_payload",
    "_should_refresh_cached_maxmind_entry", "_should_refresh_cached_stopforumspam_entry",
    "_should_use_custom_mmdb_get", "_strip_raw_json_from_payload", "_strip_request_cookie_header",
    "_try_pipelined_set_many", "_verify_gadget_bearer_token", "adapt_getipintel", "admin_provider_dashboard",
    "aggregate_intelligence_metrics", "aioredis", "canonicalize_ip", "check_and_consume_quota", "detect_ip",
    "detect_ip_batch", "dns", "exchange_gadget_token", "fetch_project_user_rights", "fetch_user_rights_from_meta",
    "get_current_user", "get_process_memory_mb", "httpx", "is_redis_circuit_open", "issue_gadget_token", "json",
    "mark_redis_failure", "oauth_callback", "oauth_login", "oauth_logout", "os", "query_abuseipdb",
    "query_cloudflare_radar", "query_dshield", "query_getipintel", "query_ip2location", "query_ipdata",
    "query_iphub", "query_iphunter", "query_ipregistry", "query_maxmind", "query_proxycheck", "query_rdns_ptr",
    "query_spamcop", "query_spamhaus_zen", "query_stopforumspam", "query_tor_onionoo",
    "record_global_request_telemetry", "record_provider_outcomes_batch", "redis_client",
    "reset_redis_circuit_breaker", "signing", "switch_test_role", "system_status", "time",
    "verify_centralauth_userinfo", "warm_offline_intelligence_caches",
]

logger = logging.getLogger(__name__)

_BATCH_DETECT_CONCURRENCY = 6

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


@csrf_exempt
async def exchange_gadget_token(request):
    """
    Exchanges a one-time MediaWiki CentralAuth token for a signed gadget Bearer token
    after verifying identity and unified RBAC permissions with Meta-Wiki.
    """
    if request.method == "OPTIONS":
        return _apply_detect_cors_headers(request, HttpResponse(status=204), methods="POST, OPTIONS")

    if request.method != "POST":
        return _apply_detect_cors_headers(
            request,
            JsonResponse({"error": "Method not allowed"}, status=405),
            methods="POST, OPTIONS",
        )

    response = await _exchange_gadget_token_post(request)
    return _apply_detect_cors_headers(request, response, methods="POST, OPTIONS")


async def _exchange_gadget_token_post(request):
    parsed, error_response = _parse_gadget_token_payload(request)
    if error_response is not None or parsed is None:
        return error_response
    centralauth_token, wiki_domain = parsed

    client = await _get_shared_http_client()
    try:
        wiki_userinfo = await verify_centralauth_userinfo(client, centralauth_token, wiki_domain=wiki_domain)
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
        return JsonResponse({"error": "Unable to verify CentralAuth credentials at this time."}, status=503)

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
            return JsonResponse({"error": "Access denied. Unrecognised Wikimedia user."}, status=403)
        return JsonResponse({"error": "Unable to verify Wikimedia user rights at this time."}, status=503)

    if not has_access:
        return JsonResponse({"error": "Access denied. Insufficient Wikimedia user rights."}, status=403)

    return JsonResponse(
        {
            "token": issue_gadget_token(username),
            "username": username,
            "expires_in": _get_gadget_token_ttl_seconds(),
        }
    )


async def detect_ip(request):
    """
    Aggregates IP intelligence across upstream providers with non-public IP interception,
    singleflight coalescing, tiered per-provider Redis caching, and cooldown circuit breaking.
    """
    if request.method == "OPTIONS":
        return _apply_detect_cors_headers(request, HttpResponse(status=204))

    if request.method != "GET":
        return _apply_detect_cors_headers(request, JsonResponse({"error": "Method not allowed"}, status=405))

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

    payload = await _detect_single_canonical_ip(
        ip,
        auth_mode,
        start_time,
        compact=_is_compact_request(request),
        query_mode=_resolve_query_mode(request),
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
        return _apply_detect_cors_headers(request, HttpResponse(status=204), methods="POST, OPTIONS")

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
        return JsonResponse({"error": "invalid_batch", "message": "Invalid JSON request body."}, status=400)

    if not isinstance(body, dict):
        return JsonResponse(
            {"error": "invalid_batch", "message": "Request body must be a JSON object containing an ips array."},
            status=400,
        )

    parsed_batch, batch_error = _parse_batch_ips(body.get("ips"))
    if batch_error is not None or parsed_batch is None:
        return batch_error
    unique_canonical_ips, input_map = parsed_batch

    is_compact = _is_compact_request(request, body)
    query_mode = _resolve_query_mode(request, body, default="light")
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
        return HttpResponseRedirect(f"{auth_base}/authorize?{query_params}")

    if not (getattr(settings, "DEBUG", False) and getattr(settings, "ENABLE_TEST_AUTH", False)):
        return JsonResponse({"error": "OAuth 2.0 client credentials are not configured."}, status=503)

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

    headers = {"User-Agent": USER_AGENT_HEADER}
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

            access_token = token_resp.json().get("access_token", "")
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
            if not await _persist_authenticated_session(request, user_session_payload):
                return JsonResponse({"error": _SESSION_UNAVAILABLE_ERROR}, status=503)
            if has_access and post_login_ip:
                redirect_target = f"/?{urlencode({'ip': post_login_ip})}"
            logger.info(f"User {username} successfully authenticated with role: {role_label}")
    # Top-level OAuth callback boundary prevents upstream or runtime failures from leaking tokens in error pages
    except Exception as exc:  # noqa: BLE001
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
    except ValueError, UnicodeDecodeError:
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

    user_data = dict(_TEST_ROLE_PROFILES.get(target, _TEST_ROLE_PROFILES["sysop"]))
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
