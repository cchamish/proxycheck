"""
Session persistence wrappers, Wikimedia OAuth and CentralAuth rights resolution,
gadget Bearer token verification, and CORS response helpers.
"""

import asyncio
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx
from asgiref.sync import sync_to_async
from django.conf import settings
from django.core import signing
from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware

from . import oauth
from .intelligence import canonicalize_ip
from .middleware import is_session_backend_error
from .oauth import (
    DEFAULT_RIGHTS_TTL_SECONDS,
    REQUIRED_WIKIMEDIA_RIGHTS_SET,
    WIKIMEDIA_BETA_SUFFIXES,
    WIKIMEDIA_HOST_SUFFIXES,
    MetaWikiRightsFetchError,
    evaluate_wikimedia_rights,
    extract_wikimedia_domain_from_project,
    is_allowlisted_wiki_user,
    is_session_rights_expired,
    normalize_and_validate_wikimedia_domain,
)
from .quota_telemetry import is_admin_user

logger = logging.getLogger("detector.views")

_WIKIMEDIA_ORIGIN_RE = re.compile(rf"^https://([a-z0-9-]+\.)*(?:{WIKIMEDIA_HOST_SUFFIXES})\.org$")
_WIKIMEDIA_BETA_ORIGIN_RE = re.compile(
    rf"^https://([a-z0-9-]+\.)*(?:{WIKIMEDIA_BETA_SUFFIXES})\.beta\.wm(?:cloud|flabs)\.org$"
)
_LOCAL_DEV_ORIGIN_RE = re.compile(r"^https?://(?:localhost|127\.0\.0\.1)(?::\d{1,5})?$")

GADGET_TOKEN_SALT = "proxycheck.gadget.auth.v1"  # noqa: S105
DEFAULT_GADGET_TOKEN_TTL_SECONDS = 900
_MAX_GADGET_TOKEN_BODY_BYTES = 8192

_MAX_MERGED_PROJECT_RIGHTS_LOOKUPS = 15
_MERGED_PROJECT_RIGHTS_BATCH_SIZE = 5
SESSION_UNAVAILABLE_ERROR = "Authentication session storage is temporarily unavailable."


def get_gadget_token_ttl_seconds() -> int:
    configured = getattr(settings, "GADGET_TOKEN_TTL_SECONDS", DEFAULT_GADGET_TOKEN_TTL_SECONDS)
    if isinstance(configured, bool) or not isinstance(configured, int) or configured <= 0:
        return DEFAULT_GADGET_TOKEN_TTL_SECONDS
    return configured


def issue_gadget_token(username: str) -> str:
    """Signs a gadget authentication payload for an authenticated and authorised Wikimedia user."""
    payload = {"u": username, "scope": "gadget"}
    return signing.dumps(payload, salt=GADGET_TOKEN_SALT)


def _verify_gadget_bearer_token(auth_header: str) -> Tuple[Optional[str], Optional[str]]:
    """Validates a Bearer header containing a signed gadget token."""
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
            max_age=get_gadget_token_ttl_seconds(),
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
    if oauth.is_wikimedia_beta_origins_allowed() and _WIKIMEDIA_BETA_ORIGIN_RE.match(candidate):
        return True
    return bool(getattr(settings, "DEBUG", False) and _LOCAL_DEV_ORIGIN_RE.match(candidate))


def apply_detect_cors_headers(request, response, methods: str = "GET, OPTIONS"):
    origin = request.headers.get("Origin")
    if _is_allowed_wikimedia_origin(origin):
        response["Access-Control-Allow-Origin"] = origin.strip()
        response["Access-Control-Allow-Methods"] = methods
        response["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response["Access-Control-Expose-Headers"] = "Retry-After"
        response["Access-Control-Max-Age"] = "86400"
        vary_existing = response.get("Vary")
        if not vary_existing:
            response["Vary"] = "Origin"
        elif "origin" not in [v.strip().lower() for v in vary_existing.split(",")]:
            response["Vary"] = f"{vary_existing}, Origin"
    return response


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
            *(oauth.fetch_project_user_rights(client, username, domain) for _, _, _, domain in batch),
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


async def resolve_wikimedia_access(
    client: httpx.AsyncClient,
    username: str,
    local_groups: List[str],
    local_rights: Optional[List[str]] = None,
    *,
    wiki_domain: str = "meta.wikimedia.org",
    local_rights_verified: bool = True,
    skip_meta_if_local_granted: bool = False,
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
    if skip_meta_if_local_granted and local_eval[0]:
        return local_eval
    try:
        meta_rights = await oauth.fetch_user_rights_from_meta(
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
def get_session_user(request, *, context: str = "session_rights_check") -> Any:
    """Thread-safe synchronous helper for reading and validating session user data."""
    return _read_session_user_sync(request, context=context)


@sync_to_async(thread_sensitive=True)
def pop_oauth_login_context(request) -> Tuple[Any, Optional[str], bool]:
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
def persist_oauth_login_context(request, state: str, post_login_ip: Optional[str]) -> bool:
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
def persist_authenticated_session(
    request,
    user_data: Dict[str, Any],
    *,
    context: str = "oauth_callback_login",
) -> bool:
    """Thread-safe synchronous helper for persisting authenticated user data in Django session storage."""
    payload = dict(user_data)
    if "rights_updated_at" not in payload:
        payload["rights_updated_at"] = time.time()
    try:
        request.session.cycle_key()
    except Exception as exc:
        if not is_session_backend_error(exc):
            raise
        request.session.modified = False
        logger.warning(
            "Session key rotation skipped during %s due to cache backend unavailability (%s)",
            context,
            type(exc).__name__,
        )
        return False
    request.session["wikimedia_user"] = payload
    request.session.modified = True
    if not _safe_save_session(request, context=context):
        request.session.pop("wikimedia_user", None)
        request.session.modified = False
        return False
    return True


def _csrf_protected_sentinel(_request):
    return None


def validate_session_csrf(request) -> Optional[JsonResponse]:
    """Enforces Django CSRF verification for session-authenticated POST endpoints."""
    middleware = CsrfViewMiddleware(lambda _req: None)
    if "CSRF_COOKIE" not in request.META:
        middleware.process_request(request)
    rejection = middleware.process_view(request, _csrf_protected_sentinel, (), {})
    if rejection is not None:
        return JsonResponse(
            {"error": "csrf_failed", "message": "CSRF verification failed."},
            status=403,
        )
    return None


@sync_to_async(thread_sensitive=True)
def flush_session_async(request, *, context: str) -> bool:
    """Thread-safe synchronous helper for flushing Django session state under ASGI."""
    flushed = _safe_flush_session(request, context=context)
    if flushed:
        request.session.modified = True
    return flushed


async def authenticate_detect_request(
    request,
    *,
    require_csrf_for_session: bool = False,
) -> Tuple[Optional[str], Optional[JsonResponse]]:
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

    session_user = await get_session_user(request)
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
    if require_csrf_for_session:
        csrf_error = validate_session_csrf(request)
        if csrf_error is not None:
            return None, csrf_error
    return "session", None


async def authorize_admin_session_request(request, *, context: str) -> Optional[JsonResponse]:
    """Enforces GET-only allowlisted session access without accepting gadget Bearer tokens."""
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    auth_header = request.headers.get("Authorization")
    if auth_header is not None and str(auth_header).strip():
        return JsonResponse(
            {"error": "Access denied. Administrator session privileges required."},
            status=403,
        )

    session_user = await get_session_user(request, context=context)
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


TEST_ROLE_PROFILES: Dict[str, Dict[str, Any]] = {
    "unauthorised": {
        "isLoggedIn": True,
        "username": "StandardEditor",
        "role": "Standard User (Unauthorised)",
        "hasAccess": False,
        "localGroups": ["autoreview"],
        "globalGroups": [],
    },
    "steward": {
        "isLoggedIn": True,
        "username": "StewardUser",
        "role": "Steward",
        "hasAccess": True,
        "localGroups": [],
        "globalGroups": ["steward"],
    },
    "global-rollbacker": {
        "isLoggedIn": True,
        "username": "GlobalRollbackUser",
        "role": "Global Rollbacker",
        "hasAccess": True,
        "localGroups": [],
        "globalGroups": ["global-rollbacker"],
    },
    "sysop": {
        "isLoggedIn": True,
        "username": "LocalSysopUser",
        "role": "Local Administrator (sysop)",
        "hasAccess": True,
        "localGroups": ["sysop"],
        "globalGroups": [],
    },
}


def parse_gadget_token_payload(request) -> Tuple[Optional[Tuple[str, str]], Optional[JsonResponse]]:
    """Parses and validates the CentralAuth token and Wikimedia domain from a gadget token request."""
    raw_bytes = request.body or b""
    if len(raw_bytes) > _MAX_GADGET_TOKEN_BODY_BYTES:
        return None, JsonResponse(
            {"error": f"Request body exceeds maximum allowed size of {_MAX_GADGET_TOKEN_BODY_BYTES} bytes."},
            status=413,
        )
    try:
        raw_body = raw_bytes.decode("utf-8-sig") if raw_bytes else ""
        body = json.loads(raw_body) if raw_body.strip() else None
    except UnicodeDecodeError, ValueError:
        logger.warning("Invalid JSON request body received in exchange_gadget_token.")
        return None, JsonResponse({"error": "Invalid JSON request body."}, status=400)

    if not isinstance(body, dict):
        return None, JsonResponse({"error": "Request body must be a JSON object."}, status=400)

    raw_centralauth_token = body.get("centralauthtoken")
    if raw_centralauth_token is None:
        return None, JsonResponse({"error": "Missing centralauthtoken parameter."}, status=400)
    if not isinstance(raw_centralauth_token, str):
        return None, JsonResponse({"error": "centralauthtoken must be a string."}, status=400)

    centralauth_token = raw_centralauth_token.strip()
    if not centralauth_token:
        return None, JsonResponse({"error": "centralauthtoken must not be empty."}, status=400)
    if len(centralauth_token) > 4096:
        return None, JsonResponse(
            {"error": "centralauthtoken exceeds maximum allowed length of 4096 characters."},
            status=400,
        )
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in centralauth_token):
        return None, JsonResponse(
            {"error": "centralauthtoken contains invalid whitespace or control characters."},
            status=400,
        )

    raw_domain = body.get("domain")
    if raw_domain is None:
        raw_domain = body.get("wiki_domain")
    if raw_domain is None or (isinstance(raw_domain, str) and not raw_domain.strip()):
        return None, JsonResponse({"error": "Missing Wikimedia domain parameter."}, status=400)

    wiki_domain = normalize_and_validate_wikimedia_domain(raw_domain)
    if not wiki_domain:
        return None, JsonResponse({"error": "Invalid or unsupported Wikimedia domain."}, status=400)
    return (centralauth_token, wiki_domain), None
