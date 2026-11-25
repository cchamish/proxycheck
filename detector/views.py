"""
Asynchronous HTTP views for IP intelligence aggregation and Wikimedia OAuth 2.0 sessions.
"""

import asyncio
import functools
import json
import logging
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict
from urllib.parse import urlencode

from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, StreamingHttpResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt

from .auth import oauth
from .auth.oauth import (
    CentralAuthVerificationError,
    InvalidCentralAuthTokenError,
    MetaWikiRightsFetchError,
    normalize_and_validate_wikimedia_domain,
)
from .auth.session import (
    GADGET_TOKEN_SALT,
    SESSION_UNAVAILABLE_ERROR,
    TEST_ROLE_PROFILES,
    apply_detect_cors_headers,
    authenticate_detect_request,
    authorise_admin_session_request,
    flush_session_async,
    get_gadget_token_ttl_seconds,
    get_session_user,
    is_admin_user,
    issue_gadget_token,
    normalize_post_login_route,
    persist_authenticated_session,
    persist_oauth_login_context,
    pop_oauth_login_context,
    resolve_wikimedia_access,
    verify_gadget_bearer_token,
)
from .cache.dashboard import build_dashboard_snapshot
from .cache.quota_telemetry import (
    RefreshRateLimitResult,
    check_and_consume_endpoint_rate_limit,
)
from .core import http_client
from .core.ip_utils import MAX_BATCH_IPS, canonicalize_ip, parse_batch_ip_list
from .core.sanitization import sanitize_error_message, sanitize_payload
from .detection.arbitration import (
    aggregate_intelligence_metrics,
    attach_request_diagnostics,
)
from .detection.pipeline import (
    is_compact_request,
    resolve_query_mode,
)
from .detection.service import (
    detect_canonical_ip_batch,
    detect_single_canonical_ip,
    refresh_single_canonical_ip,
)
from .detection.stream import stream_single_canonical_ip_sse
from .offline import collect_offline_databases_status
from .provider_registry import USER_AGENT_HEADER
from .rangeblock import service as rangeblock_service

__all__ = [
    "GADGET_TOKEN_SALT",
    "MAX_BATCH_IPS",
    "USER_AGENT_HEADER",
    "admin_provider_dashboard",
    "aggregate_intelligence_metrics",
    "canonicalize_ip",
    "detect_ip",
    "detect_ip_batch",
    "detect_ip_stream",
    "exchange_gadget_token",
    "get_current_user",
    "issue_gadget_token",
    "oauth_callback",
    "oauth_login",
    "oauth_logout",
    "rangeblock_lookup",
    "refresh_ip_detection",
    "switch_test_role",
    "system_status",
]

logger = logging.getLogger(__name__)

_MAX_GADGET_TOKEN_BODY_BYTES = 8192

_OAUTH_CALLBACK_ERROR_CODES = {
    code: code
    for code in (
        "access_denied",
        "consent_required",
        "interaction_required",
        "invalid_request",
        "invalid_scope",
        "login_required",
        "server_error",
        "temporarily_unavailable",
        "unauthorized_client",
        "unsupported_response_type",
    )
}


def _unauthenticated_user_payload() -> Dict[str, Any]:
    return {
        "isLoggedIn": False,
        "username": "",
        "role": "",
        "hasAccess": False,
        "isAdmin": False,
        "localGroups": [],
        "globalGroups": [],
    }


def _cors_endpoint(expected_method: str) -> Callable[[Callable[..., Awaitable[HttpResponse]]], Any]:
    allowed_methods = f"{expected_method}, OPTIONS"

    def decorator(view_fn: Callable[..., Awaitable[HttpResponse]]):
        @functools.wraps(view_fn)
        async def wrapped(request, *args, **kwargs) -> HttpResponse:
            if request.method == "OPTIONS":
                return apply_detect_cors_headers(request, HttpResponse(status=204), methods=allowed_methods)
            if request.method != expected_method:
                return apply_detect_cors_headers(
                    request,
                    JsonResponse({"error": "Method not allowed"}, status=405),
                    methods=allowed_methods,
                )
            response = await view_fn(request, *args, **kwargs)
            return apply_detect_cors_headers(request, response, methods=allowed_methods)

        return wrapped

    return decorator


def _build_rate_limit_response(rl_res: RefreshRateLimitResult, message: str) -> JsonResponse:
    response = JsonResponse(
        {
            "error": "rate_limited",
            "reason": rl_res.reason,
            "message": message,
            "retryAfterSeconds": rl_res.retry_after_seconds,
        },
        status=429,
    )
    response["Retry-After"] = str(rl_res.retry_after_seconds)
    response["Cache-Control"] = "no-store"
    return response


async def _resolve_authenticated_identity(request, auth_mode: str) -> tuple[str, bool]:
    if auth_mode == "gadget":
        token_user, _ = verify_gadget_bearer_token(str(request.headers.get("Authorization") or ""))
        return str(token_user or "").strip(), False
    session_user = await get_session_user(request)
    if not isinstance(session_user, dict):
        return "", False
    return str(session_user.get("username") or "").strip(), is_admin_user(session_user)


def _parse_query_ip(request) -> tuple[str | None, JsonResponse | None]:
    raw_ip = request.GET.get("ip")
    if raw_ip is None or not str(raw_ip).strip():
        return None, JsonResponse(
            {
                "error": "invalid_ip",
                "message": "Missing required ip query parameter. Please provide a valid IPv4 or IPv6 address.",
            },
            status=400,
        )
    ip = canonicalize_ip(str(raw_ip))
    if not ip:
        return None, JsonResponse(
            {
                "error": "invalid_ip",
                "message": "Invalid IP address format. Please provide a valid IPv4 or IPv6 address.",
            },
            status=400,
        )
    return ip, None


@csrf_exempt
@_cors_endpoint("POST")
async def exchange_gadget_token(request):
    """Exchanges a one-time MediaWiki CentralAuth token for a signed gadget Bearer token."""
    raw_bytes = request.body or b""
    if len(raw_bytes) > _MAX_GADGET_TOKEN_BODY_BYTES:
        resp = JsonResponse(
            {"error": f"Request body exceeds maximum allowed size of {_MAX_GADGET_TOKEN_BODY_BYTES} bytes."},
            status=413,
        )
        resp["Cache-Control"] = "no-store"
        return resp

    try:
        raw_body = raw_bytes.decode("utf-8-sig") if raw_bytes else ""
        body = json.loads(raw_body) if raw_body.strip() else None
    except UnicodeDecodeError, ValueError:
        logger.warning("Invalid JSON request body received in exchange_gadget_token.")
        resp = JsonResponse({"error": "Invalid JSON request body."}, status=400)
        resp["Cache-Control"] = "no-store"
        return resp

    if not isinstance(body, dict):
        resp = JsonResponse({"error": "Request body must be a JSON object."}, status=400)
        resp["Cache-Control"] = "no-store"
        return resp

    raw_token = body.get("centralauthtoken")
    validation_error: str | None = None
    centralauth_token = ""
    if raw_token is None:
        validation_error = "Missing centralauthtoken parameter."
    elif not isinstance(raw_token, str):
        validation_error = "centralauthtoken must be a string."
    else:
        centralauth_token = raw_token.strip()
        if not centralauth_token:
            validation_error = "centralauthtoken must not be empty."
        elif len(centralauth_token) > 4096:
            validation_error = "centralauthtoken exceeds maximum allowed length of 4096 characters."
        elif any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in centralauth_token):
            validation_error = "centralauthtoken contains invalid whitespace or control characters."

    wiki_domain = ""
    if validation_error is None:
        raw_domain = body.get("domain")
        if raw_domain is None:
            raw_domain = body.get("wiki_domain")
        if raw_domain is None or (isinstance(raw_domain, str) and not raw_domain.strip()):
            validation_error = "Missing Wikimedia domain parameter."
        else:
            wiki_domain = normalize_and_validate_wikimedia_domain(raw_domain) or ""
            if not wiki_domain:
                validation_error = "Invalid or unsupported Wikimedia domain."

    if validation_error is not None:
        resp = JsonResponse({"error": validation_error}, status=400)
        resp["Cache-Control"] = "no-store"
        return resp

    global_rl = await check_and_consume_endpoint_rate_limit("gadget_token", scope="global")
    if not global_rl.allowed:
        return _build_rate_limit_response(global_rl, "Gadget token rate limit exceeded. Please wait before retrying.")

    client = await http_client.get_shared_http_client()
    try:
        wiki_userinfo = await oauth.verify_centralauth_userinfo(client, centralauth_token, wiki_domain=wiki_domain)
    except InvalidCentralAuthTokenError as exc:
        logger.warning(
            "CentralAuth token validation failed for domain '%s': %s (mw_error=%s)",
            wiki_domain,
            sanitize_error_message(str(exc)),
            sanitize_payload(exc.mw_error) if exc.mw_error is not None else None,
        )
        resp = JsonResponse({"error": "Invalid CentralAuth token."}, status=401)
        resp["Cache-Control"] = "no-store"
        return resp
    except CentralAuthVerificationError as exc:
        logger.warning(
            "CentralAuth verification failed for domain '%s': %s (mw_error=%s)",
            wiki_domain,
            sanitize_error_message(str(exc)),
            sanitize_payload(exc.mw_error) if exc.mw_error is not None else None,
        )
        resp = JsonResponse({"error": "Unable to verify CentralAuth credentials at this time."}, status=503)
        resp["Cache-Control"] = "no-store"
        return resp

    username = wiki_userinfo["username"]
    user_rl = await check_and_consume_endpoint_rate_limit("gadget_token", username, scope="user")
    if not user_rl.allowed:
        return _build_rate_limit_response(
            user_rl, "Too many token requests for this account. Please wait before retrying."
        )

    local_groups = wiki_userinfo.get("local_groups") or []
    local_rights = wiki_userinfo.get("rights")
    local_rights_verified = isinstance(local_rights, list)

    try:
        has_access, _, _, _ = await resolve_wikimedia_access(
            client,
            username,
            local_groups,
            local_rights if isinstance(local_rights, list) else [],
            wiki_domain=wiki_domain,
            local_rights_verified=local_rights_verified,
            skip_meta_if_local_granted=True,
        )
    except MetaWikiRightsFetchError as exc:
        if "missing" in str(exc).lower():
            resp = JsonResponse({"error": "Access denied. Unrecognised Wikimedia user."}, status=403)
        else:
            resp = JsonResponse({"error": "Unable to verify Wikimedia user rights at this time."}, status=503)
        resp["Cache-Control"] = "no-store"
        return resp

    if not has_access:
        resp = JsonResponse({"error": "Access denied. Insufficient Wikimedia user rights."}, status=403)
        resp["Cache-Control"] = "no-store"
        return resp

    resp = JsonResponse(
        {
            "token": issue_gadget_token(username),
            "username": username,
            "expires_in": get_gadget_token_ttl_seconds(),
        }
    )
    resp["Cache-Control"] = "no-store"
    return resp


@_cors_endpoint("GET")
async def detect_ip(request):
    """Aggregates IP intelligence across upstream providers with L1/L2 caching and singleflight coalescing."""
    start_time = time.perf_counter()

    auth_mode, auth_error_response = await authenticate_detect_request(request)
    if auth_error_response is not None or auth_mode is None:
        return auth_error_response

    username, _ = await _resolve_authenticated_identity(request, auth_mode)
    rl_res = await check_and_consume_endpoint_rate_limit("detect", username)
    if not rl_res.allowed:
        return _build_rate_limit_response(rl_res, "Detection rate limit exceeded. Please wait before retrying.")

    ip, ip_error = _parse_query_ip(request)
    if ip_error is not None or ip is None:
        return ip_error

    payload = await detect_single_canonical_ip(
        ip,
        auth_mode,
        start_time,
        compact=is_compact_request(request),
        query_mode=resolve_query_mode(request),
        wiki=rangeblock_service.normalize_wiki_dbname(request.GET.get("wiki")),
    )
    response = JsonResponse(payload)
    response["Cache-Control"] = "private, no-cache"
    return response


@_cors_endpoint("GET")
async def detect_ip_stream(request):
    """Streams progressive IP detection results over Server-Sent Events."""
    start_time = time.perf_counter()

    auth_mode, auth_error_response = await authenticate_detect_request(request)
    if auth_error_response is not None or auth_mode is None:
        return auth_error_response

    username, _ = await _resolve_authenticated_identity(request, auth_mode)
    rl_res = await check_and_consume_endpoint_rate_limit("detect", username)
    if not rl_res.allowed:
        return _build_rate_limit_response(rl_res, "Detection rate limit exceeded. Please wait before retrying.")

    ip, ip_error = _parse_query_ip(request)
    if ip_error is not None or ip is None:
        return ip_error

    stream_iter = stream_single_canonical_ip_sse(
        ip,
        auth_mode,
        start_time,
        compact=is_compact_request(request),
        query_mode=resolve_query_mode(request),
        wiki=rangeblock_service.normalize_wiki_dbname(request.GET.get("wiki")),
    )
    response = StreamingHttpResponse(stream_iter, content_type="text/event-stream; charset=utf-8")
    response["Cache-Control"] = "private, no-cache"
    response["X-Accel-Buffering"] = "no"
    return response


@_cors_endpoint("GET")
async def rangeblock_lookup(request):
    """Queries cross-wiki rangeblock aggregates and real-time Wiki Replicas status for an IP."""
    start_time = time.perf_counter()

    auth_mode, auth_error_response = await authenticate_detect_request(request)
    if auth_error_response is not None or auth_mode is None:
        return auth_error_response

    username, _ = await _resolve_authenticated_identity(request, auth_mode)
    rl_res = await check_and_consume_endpoint_rate_limit("rangeblock", username)
    if not rl_res.allowed:
        return _build_rate_limit_response(rl_res, "Rangeblock lookup rate limit exceeded. Please wait before retrying.")

    ip, ip_error = _parse_query_ip(request)
    if ip_error is not None or ip is None:
        return ip_error

    wiki = rangeblock_service.normalize_wiki_dbname(request.GET.get("wiki"))
    payload = await rangeblock_service.query_rangeblocks_for_ip(ip, wiki=wiki)
    response = JsonResponse(attach_request_diagnostics(payload, start_time))
    response["Cache-Control"] = "private, no-cache"
    return response


@csrf_exempt
@_cors_endpoint("POST")
async def refresh_ip_detection(request):
    """Executes an authenticated manual IP intelligence refresh with rate guards and L2 merge protection."""
    start_time = time.perf_counter()

    auth_mode, auth_error_response = await authenticate_detect_request(request, require_csrf_for_session=True)
    if auth_error_response is not None or auth_mode is None:
        return auth_error_response

    body: Dict[str, Any] = {}
    if request.body:
        try:
            raw_body = request.body.decode("utf-8-sig")
            parsed_body = json.loads(raw_body) if raw_body.strip() else {}
        except UnicodeDecodeError, ValueError:
            return JsonResponse({"error": "invalid_refresh", "message": "Invalid JSON request body."}, status=400)
        if not isinstance(parsed_body, dict):
            return JsonResponse(
                {"error": "invalid_refresh", "message": "Request body must be a JSON object."},
                status=400,
            )
        body = parsed_body

    raw_ip = body.get("ip")
    if raw_ip is None or not isinstance(raw_ip, str) or not raw_ip.strip():
        return JsonResponse(
            {
                "error": "invalid_ip",
                "message": "Missing required ip parameter. Please provide a valid IPv4 or IPv6 address.",
            },
            status=400,
        )

    ip = canonicalize_ip(raw_ip)
    if not ip:
        return JsonResponse(
            {
                "error": "invalid_ip",
                "message": "Invalid IP address format. Please provide a valid IPv4 or IPv6 address.",
            },
            status=400,
        )

    username, admin_flag = await _resolve_authenticated_identity(request, auth_mode)
    wiki = rangeblock_service.normalize_wiki_dbname(body.get("wiki") or request.GET.get("wiki"))
    payload, status_code, extra_headers = await refresh_single_canonical_ip(
        ip,
        auth_mode,
        start_time,
        username=username,
        is_admin=admin_flag,
        compact=is_compact_request(request, body),
        query_mode=resolve_query_mode(request, body, default="full"),
        wiki=wiki,
    )
    response = JsonResponse(payload, status=status_code)
    response["Cache-Control"] = "private, no-cache"
    for hdr_name, hdr_val in extra_headers.items():
        response[hdr_name] = hdr_val
    return response


@csrf_exempt
@_cors_endpoint("POST")
async def detect_ip_batch(request):
    """Executes bounded-concurrency batch IP intelligence detection for up to MAX_BATCH_IPS addresses."""
    start_time = time.perf_counter()

    auth_mode, auth_error_response = await authenticate_detect_request(request, require_csrf_for_session=True)
    if auth_error_response is not None or auth_mode is None:
        return auth_error_response

    username, _ = await _resolve_authenticated_identity(request, auth_mode)
    rl_res = await check_and_consume_endpoint_rate_limit("detect_batch", username)
    if not rl_res.allowed:
        return _build_rate_limit_response(rl_res, "Batch detection rate limit exceeded. Please wait before retrying.")

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

    parsed_batch, batch_error_message = parse_batch_ip_list(body.get("ips"))
    if batch_error_message is not None or parsed_batch is None:
        return JsonResponse({"error": "invalid_batch", "message": batch_error_message}, status=400)
    unique_canonical_ips, input_map = parsed_batch

    query_mode = resolve_query_mode(request, body, default="light")
    wiki = rangeblock_service.normalize_wiki_dbname(body.get("wiki") or request.GET.get("wiki"))
    results_by_ip = await detect_canonical_ip_batch(
        unique_canonical_ips,
        auth_mode=auth_mode,
        compact=is_compact_request(request, body),
        query_mode=query_mode,
        wiki=wiki,
    )

    response = JsonResponse(
        attach_request_diagnostics(
            {
                "results": results_by_ip,
                "inputMap": input_map,
                "count": len(results_by_ip),
                "queryMode": query_mode,
            },
            start_time,
        )
    )
    response["Cache-Control"] = "private, no-cache"
    return response


async def get_current_user(request):
    start_time = time.perf_counter()
    get_token(request)
    session_user = await get_session_user(request, context="get_current_user")

    if not isinstance(session_user, dict) or not session_user:
        payload = _unauthenticated_user_payload()
        include_memory = False
    else:
        payload = dict(session_user)
        payload["isAdmin"] = is_admin_user(session_user)
        include_memory = bool(session_user.get("isLoggedIn"))

    response = JsonResponse(attach_request_diagnostics(payload, start_time, include_memory=include_memory))
    response["Cache-Control"] = "no-store"
    return response


async def admin_provider_dashboard(request):
    """Returns anonymised API quota usage, reactive cooldown states, and daily telemetry for allowlisted admins."""
    start_time = time.perf_counter()
    denied_response = await authorise_admin_session_request(request, context="admin_provider_dashboard")
    if denied_response is not None:
        return denied_response

    snapshot = await build_dashboard_snapshot()
    response = JsonResponse(attach_request_diagnostics(snapshot, start_time))
    response["Cache-Control"] = "no-store"
    return response


async def oauth_login(request):
    """Redirects to Meta-Wiki OAuth 2.0 authorisation, or creates a local sysop session when test auth is enabled."""
    client_id = getattr(settings, "WIKIMEDIA_CLIENT_ID", "")
    redirect_uri = getattr(settings, "WIKIMEDIA_REDIRECT_URI", "")
    auth_base = getattr(settings, "WIKIMEDIA_OAUTH_URL", "https://meta.wikimedia.org/w/rest.php/oauth2")
    post_login_route = normalize_post_login_route(request.GET)

    if client_id and redirect_uri:
        state = secrets.token_urlsafe(32)
        if not await persist_oauth_login_context(request, state, post_login_route):
            return JsonResponse({"error": SESSION_UNAVAILABLE_ERROR}, status=503)
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
    if not await persist_authenticated_session(request, user_data, context="oauth_login_test_auth"):
        return JsonResponse({"error": SESSION_UNAVAILABLE_ERROR}, status=503)
    fallback_redirect = f"/?{urlencode(post_login_route)}" if post_login_route else "/"
    return HttpResponseRedirect(fallback_redirect)


async def oauth_callback(request):
    """Exchanges the OAuth 2.0 authorisation code for a token, evaluates Wikimedia rights, and saves the session."""
    expected_state, post_login_route, state_saved = await pop_oauth_login_context(request)
    if not state_saved:
        return JsonResponse({"error": SESSION_UNAVAILABLE_ERROR}, status=503)

    callback_error_raw = request.GET.get("error", "").strip().lower()
    if callback_error_raw:
        known_error_code = _OAUTH_CALLBACK_ERROR_CODES.get(callback_error_raw)
        if known_error_code is not None:
            logger.warning("OAuth callback returned error: %s", known_error_code)
        else:
            logger.warning("OAuth callback returned an unrecognised error code")
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
        async with http_client.build_cookieless_http_client(headers=headers) as client:
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
                logger.error("Wikimedia OAuth token exchange failed: HTTP %s", token_resp.status_code)
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
                logger.error("Wikimedia OAuth profile fetch failed: HTTP %s", profile_resp.status_code)
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

            has_access, role_label, norm_local, norm_global = await resolve_wikimedia_access(
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
            if not await persist_authenticated_session(request, user_session_payload):
                return JsonResponse({"error": SESSION_UNAVAILABLE_ERROR}, status=503)
            if has_access and post_login_route:
                redirect_target = f"/?{urlencode(post_login_route)}"
            logger.info("User %s successfully authenticated with role: %s", username, role_label)
    # Top-level OAuth boundary prevents upstream failures from leaking tokens in error pages.
    except Exception as exc:  # noqa: BLE001
        logger.error("OAuth callback processing error (%s)", type(exc).__name__)

    return HttpResponseRedirect(redirect_target)


async def oauth_logout(request):
    start_time = time.perf_counter()
    if request.method != "POST":
        response = JsonResponse({"error": "Method not allowed"}, status=405)
        response["Cache-Control"] = "no-store"
        return response
    session_user = await get_session_user(request, context="oauth_logout")
    include_memory = isinstance(session_user, dict) and bool(session_user.get("isLoggedIn"))
    await flush_session_async(request, context="oauth_logout")
    response = JsonResponse(
        attach_request_diagnostics({"status": "logged_out"}, start_time, include_memory=include_memory)
    )
    response["Cache-Control"] = "no-store"
    response.delete_cookie(
        settings.SESSION_COOKIE_NAME,
        path=getattr(settings, "SESSION_COOKIE_PATH", "/"),
        domain=getattr(settings, "SESSION_COOKIE_DOMAIN", None),
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )
    return response


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
        await flush_session_async(request, context="switch_test_role")
        return JsonResponse(_unauthenticated_user_payload())

    user_data = dict(TEST_ROLE_PROFILES.get(target, TEST_ROLE_PROFILES["sysop"]))
    user_data["rights_updated_at"] = time.time()
    if not await persist_authenticated_session(request, user_data, context="switch_test_role"):
        return JsonResponse({"error": SESSION_UNAVAILABLE_ERROR}, status=503)
    return JsonResponse({**user_data, "isAdmin": is_admin_user(user_data)})


async def system_status(request):
    """Returns live file mtime metadata for all offline databases to allowlisted administrators."""
    start_time = time.perf_counter()
    denied_response = await authorise_admin_session_request(request, context="system_status")
    if denied_response is not None:
        return denied_response

    now_dt = datetime.now(timezone.utc)
    offline_databases = await asyncio.to_thread(collect_offline_databases_status, now_dt=now_dt)
    payload = attach_request_diagnostics(
        {
            "generatedAt": now_dt.isoformat(),
            "offlineDatabases": offline_databases,
        },
        start_time,
    )
    response = JsonResponse(payload)
    response["Cache-Control"] = "no-store"
    return response
