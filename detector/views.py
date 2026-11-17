"""
Asynchronous HTTP views and public API exports for IP intelligence
aggregation and Wikimedia OAuth 2.0 session handling.
"""

import asyncio
import json
import logging
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict
from urllib.parse import urlencode

from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from . import http_client, oauth
from .detection_service import (
    detect_canonical_ip_batch,
    detect_single_canonical_ip,
    is_compact_request,
    refresh_single_canonical_ip,
    resolve_query_mode,
)
from .intelligence import (
    MAX_BATCH_IPS,
    aggregate_intelligence_metrics,
    attach_request_diagnostics,
    canonicalize_ip,
    parse_batch_ip_list,
)
from .oauth import (
    CentralAuthVerificationError,
    InvalidCentralAuthTokenError,
    MetaWikiRightsFetchError,
)
from .offline_dbs import collect_offline_databases_status
from .provider_registry import USER_AGENT_HEADER
from .quota_telemetry import (
    build_dashboard_snapshot,
    is_admin_user,
)
from .sanitization import (
    sanitize_error_message,
    sanitize_payload,
)
from .session_auth import (
    GADGET_TOKEN_SALT,
    SESSION_UNAVAILABLE_ERROR,
    TEST_ROLE_PROFILES,
    _verify_gadget_bearer_token,
    apply_detect_cors_headers,
    authenticate_detect_request,
    authorize_admin_session_request,
    flush_session_async,
    get_gadget_token_ttl_seconds,
    get_session_user,
    issue_gadget_token,
    parse_gadget_token_payload,
    persist_authenticated_session,
    persist_oauth_login_context,
    pop_oauth_login_context,
    resolve_wikimedia_access,
)

__all__ = [
    "GADGET_TOKEN_SALT",
    "MAX_BATCH_IPS",
    "USER_AGENT_HEADER",
    "admin_provider_dashboard",
    "aggregate_intelligence_metrics",
    "canonicalize_ip",
    "detect_ip",
    "detect_ip_batch",
    "exchange_gadget_token",
    "get_current_user",
    "issue_gadget_token",
    "oauth_callback",
    "oauth_login",
    "oauth_logout",
    "refresh_ip_detection",
    "switch_test_role",
    "system_status",
]

logger = logging.getLogger(__name__)

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


def _build_unauthenticated_user_payload() -> Dict[str, Any]:
    return {
        "isLoggedIn": False,
        "username": "",
        "role": "",
        "hasAccess": False,
        "isAdmin": False,
        "localGroups": [],
        "globalGroups": [],
    }


async def _dispatch_cors_endpoint(
    request,
    expected_method: str,
    handler: Callable[[Any], Awaitable[HttpResponse]],
) -> HttpResponse:
    allowed_methods = f"{expected_method}, OPTIONS"
    if request.method == "OPTIONS":
        return apply_detect_cors_headers(request, HttpResponse(status=204), methods=allowed_methods)
    if request.method != expected_method:
        return apply_detect_cors_headers(
            request,
            JsonResponse({"error": "Method not allowed"}, status=405),
            methods=allowed_methods,
        )
    response = await handler(request)
    return apply_detect_cors_headers(request, response, methods=allowed_methods)


@csrf_exempt
async def exchange_gadget_token(request):
    """
    Exchanges a one-time MediaWiki CentralAuth token for a signed gadget Bearer token
    after verifying identity and unified RBAC permissions with Meta-Wiki.
    """
    return await _dispatch_cors_endpoint(request, "POST", _exchange_gadget_token_post)


async def _exchange_gadget_token_post(request):
    parsed, error_response = parse_gadget_token_payload(request)
    if error_response is not None or parsed is None:
        return error_response
    centralauth_token, wiki_domain = parsed

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
        return JsonResponse({"error": "Invalid CentralAuth token."}, status=401)
    except CentralAuthVerificationError as exc:
        logger.warning(
            "CentralAuth verification failed for domain '%s': %s (mw_error=%s)",
            wiki_domain,
            sanitize_error_message(str(exc)),
            sanitize_payload(exc.mw_error) if exc.mw_error is not None else None,
        )
        return JsonResponse({"error": "Unable to verify CentralAuth credentials at this time."}, status=503)

    username = wiki_userinfo["username"]
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
            "expires_in": get_gadget_token_ttl_seconds(),
        }
    )


async def detect_ip(request):
    """
    Aggregates IP intelligence across upstream providers with non-public IP interception,
    singleflight coalescing, tiered per-provider Redis caching, and cooldown circuit breaking.
    """
    return await _dispatch_cors_endpoint(request, "GET", _detect_ip_get)


async def _detect_ip_get(request):
    start_time = time.perf_counter()

    auth_mode, auth_error_response = await authenticate_detect_request(request)
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

    payload = await detect_single_canonical_ip(
        ip,
        auth_mode,
        start_time,
        compact=is_compact_request(request),
        query_mode=resolve_query_mode(request),
    )
    response = JsonResponse(payload)
    response["Cache-Control"] = "private, no-cache"
    return response


@csrf_exempt
async def refresh_ip_detection(request):
    """
    Executes an authenticated manual or stale-while-revalidate IP intelligence refresh
    with per-user and global rate guards and non-degrading ToolsDB L2 merge protection.
    """
    return await _dispatch_cors_endpoint(request, "POST", _refresh_ip_detection_post)


async def _resolve_authenticated_identity(request, auth_mode: str) -> tuple[str, bool]:
    if auth_mode == "gadget":
        token_user, _ = _verify_gadget_bearer_token(str(request.headers.get("Authorization") or ""))
        cleaned = str(token_user or "").strip()
        return cleaned, bool(cleaned and oauth.is_allowlisted_wiki_user(cleaned))
    session_user = await get_session_user(request)
    if not isinstance(session_user, dict):
        return "", False
    cleaned = str(session_user.get("username") or "").strip()
    return cleaned, is_admin_user(session_user)


async def _refresh_ip_detection_post(request):
    start_time = time.perf_counter()

    auth_mode, auth_error_response = await authenticate_detect_request(request)
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

    raw_ip = body.get("ip") if "ip" in body else request.GET.get("ip")
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
    payload, status_code, extra_headers = await refresh_single_canonical_ip(
        ip,
        auth_mode,
        start_time,
        username=username,
        is_admin=admin_flag,
        compact=is_compact_request(request, body),
        query_mode=resolve_query_mode(request, body, default="full"),
    )
    response = JsonResponse(payload, status=status_code)
    response["Cache-Control"] = "private, no-cache"
    for hdr_name, hdr_val in extra_headers.items():
        response[hdr_name] = hdr_val
    return response


@csrf_exempt
async def detect_ip_batch(request):
    """
    Executes bounded-concurrency batch IP intelligence detection for up to MAX_BATCH_IPS
    addresses in a single POST request.
    """
    return await _dispatch_cors_endpoint(request, "POST", _detect_ip_batch_post)


async def _detect_ip_batch_post(request):
    start_time = time.perf_counter()

    auth_mode, auth_error_response = await authenticate_detect_request(request)
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

    parsed_batch, batch_error_message = parse_batch_ip_list(body.get("ips"))
    if batch_error_message is not None or parsed_batch is None:
        return JsonResponse({"error": "invalid_batch", "message": batch_error_message}, status=400)
    unique_canonical_ips, input_map = parsed_batch

    query_mode = resolve_query_mode(request, body, default="light")
    results_by_ip = await detect_canonical_ip_batch(
        unique_canonical_ips,
        auth_mode=auth_mode,
        compact=is_compact_request(request, body),
        query_mode=query_mode,
    )

    return JsonResponse(
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


async def get_current_user(request):
    start_time = time.perf_counter()
    session_user = await get_session_user(request, context="get_current_user")

    if not isinstance(session_user, dict) or not session_user:
        payload = _build_unauthenticated_user_payload()
    else:
        payload = dict(session_user)
        payload["isAdmin"] = is_admin_user(session_user)

    return JsonResponse(attach_request_diagnostics(payload, start_time))


async def admin_provider_dashboard(request):
    """
    Returns anonymised API quota usage, reactive cooldown states, and daily telemetry
    for allowlisted administrators.
    """
    start_time = time.perf_counter()
    denied_response = await authorize_admin_session_request(request, context="admin_provider_dashboard")
    if denied_response is not None:
        return denied_response

    snapshot = await build_dashboard_snapshot()
    response = JsonResponse(attach_request_diagnostics(snapshot, start_time))
    response["Cache-Control"] = "no-store"
    return response


async def oauth_login(request):
    """
    Redirects to Meta-Wiki OAuth 2.0 authorisation when credentials are set,
    falling back to a local sysop session for staging or preview environments without OAuth keys.
    """
    client_id = getattr(settings, "WIKIMEDIA_CLIENT_ID", "")
    redirect_uri = getattr(settings, "WIKIMEDIA_REDIRECT_URI", "")
    auth_base = getattr(settings, "WIKIMEDIA_OAUTH_URL", "https://meta.wikimedia.org/w/rest.php/oauth2")
    raw_next_ip = request.GET.get("ip")
    post_login_ip = canonicalize_ip(str(raw_next_ip)) if raw_next_ip is not None else None

    if client_id and redirect_uri:
        state = secrets.token_urlsafe(32)
        if not await persist_oauth_login_context(request, state, post_login_ip):
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
    fallback_redirect = f"/?{urlencode({'ip': post_login_ip})}" if post_login_ip else "/"
    return HttpResponseRedirect(fallback_redirect)


async def oauth_callback(request):
    """
    Exchanges the OAuth 2.0 authorisation code for an access token, inspects Wikimedia
    temporary-account IP reveal rights, and persists the evaluated role in the session.
    """
    expected_state, post_login_ip, state_saved = await pop_oauth_login_context(request)
    if not state_saved:
        return JsonResponse({"error": SESSION_UNAVAILABLE_ERROR}, status=503)

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
            if has_access and post_login_ip:
                redirect_target = f"/?{urlencode({'ip': post_login_ip})}"
            logger.info(f"User {username} successfully authenticated with role: {role_label}")
    # Top-level OAuth callback boundary prevents upstream or runtime failures from leaking tokens in error pages.
    except Exception as exc:  # noqa: BLE001
        logger.error(f"OAuth callback processing error ({type(exc).__name__})")

    return HttpResponseRedirect(redirect_target)


async def oauth_logout(request):
    start_time = time.perf_counter()
    await flush_session_async(request, context="oauth_logout")
    return JsonResponse(attach_request_diagnostics({"status": "logged_out"}, start_time))


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
        return JsonResponse(_build_unauthenticated_user_payload())

    user_data = dict(TEST_ROLE_PROFILES.get(target, TEST_ROLE_PROFILES["sysop"]))
    user_data["rights_updated_at"] = time.time()
    if not await persist_authenticated_session(request, user_data, context="switch_test_role"):
        return JsonResponse({"error": SESSION_UNAVAILABLE_ERROR}, status=503)
    return JsonResponse({**user_data, "isAdmin": is_admin_user(user_data)})


async def system_status(request):
    """Returns live file mtime metadata for all offline databases to allowlisted administrators."""
    start_time = time.perf_counter()
    denied_response = await authorize_admin_session_request(request, context="system_status")
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
