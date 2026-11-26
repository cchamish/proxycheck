"""
Session persistence, Wikimedia OAuth and CentralAuth rights resolution,
gadget Bearer token verification, and CORS response headers.
"""

import asyncio
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

from ..core.ip_utils import canonicalize_ip
from ..middleware import is_session_backend_error
from . import oauth
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

logger = logging.getLogger("detector.views")
auth_mode_logger = logging.getLogger("detector.auth_mode")

_WIKIMEDIA_ORIGIN_RE = re.compile(rf"^https://([a-z0-9-]+\.)*(?:{WIKIMEDIA_HOST_SUFFIXES})\.org$")
_WIKIMEDIA_BETA_ORIGIN_RE = re.compile(
    rf"^https://([a-z0-9-]+\.)*(?:{WIKIMEDIA_BETA_SUFFIXES})\.beta\.wm(?:cloud|flabs)\.org$"
)
_LOCAL_DEV_ORIGIN_RE = re.compile(r"^https?://(?:localhost|127\.0\.0\.1)(?::\d{1,5})?$")

GADGET_TOKEN_SALT = "proxycheck.gadget.auth.v1"  # noqa: S105
DEFAULT_GADGET_TOKEN_TTL_SECONDS = 900

_MAX_MERGED_PROJECT_RIGHTS_LOOKUPS = 15
_MERGED_PROJECT_RIGHTS_BATCH_SIZE = 5
SESSION_UNAVAILABLE_ERROR = "Authentication session storage is temporarily unavailable."


def is_admin_user(session_user: Any) -> bool:
    """Returns True only when an authenticated session user holds active access and is allowlisted."""
    if not isinstance(session_user, dict):
        return False
    if not session_user.get("isLoggedIn") or not session_user.get("hasAccess"):
        return False
    username = str(session_user.get("username") or "").strip()
    if not username or username.startswith("~"):
        return False
    return is_allowlisted_wiki_user(username)


def get_gadget_token_ttl_seconds() -> int:
    configured = getattr(settings, "GADGET_TOKEN_TTL_SECONDS", DEFAULT_GADGET_TOKEN_TTL_SECONDS)
    if isinstance(configured, bool) or not isinstance(configured, int) or configured <= 0:
        return DEFAULT_GADGET_TOKEN_TTL_SECONDS
    return configured


def issue_gadget_token(username: str) -> str:
    """Signs a gadget authentication payload for an authenticated and authorised Wikimedia user."""
    return signing.dumps({"u": username, "scope": "gadget"}, salt=GADGET_TOKEN_SALT)


def verify_gadget_bearer_token(auth_header: str) -> Tuple[Optional[str], Optional[str]]:
    """Validates a Bearer header containing a signed gadget token."""
    parts = auth_header.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None, "Invalid authorisation header."
    token = parts[1].strip()
    if not token:
        return None, "Invalid authorisation header."

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


def apply_detect_cors_headers(request, response, methods: str = "GET, OPTIONS"):
    origin = request.headers.get("Origin")
    if isinstance(origin, str) and origin:
        candidate = origin.strip()
        allowed = (
            bool(_WIKIMEDIA_ORIGIN_RE.match(candidate))
            or bool(oauth.is_wikimedia_beta_origins_allowed() and _WIKIMEDIA_BETA_ORIGIN_RE.match(candidate))
            or bool(getattr(settings, "DEBUG", False) and _LOCAL_DEV_ORIGIN_RE.match(candidate))
        )
        if allowed:
            response["Access-Control-Allow-Origin"] = candidate
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
    global rights, cross-wiki merged project rights, and the explicit username allowlist.
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
                "Global userinfo lookup failed for %s on %s, authorising via verified local wiki rights: %s",
                username,
                wiki_domain,
                exc,
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

    merged_projects = meta_rights.get("merged_projects", [])
    if not isinstance(merged_projects, list) or not merged_projects:
        return eval_result

    seen_domains: Set[str] = set()
    validated_current = normalize_and_validate_wikimedia_domain(wiki_domain)
    if local_rights_verified and validated_current:
        seen_domains.add(validated_current)

    enriched = [dict(project) if isinstance(project, dict) else project for project in merged_projects]
    candidates: List[Tuple[int, int, int, str]] = []
    for idx, project in enumerate(enriched):
        if not isinstance(project, dict):
            continue
        if isinstance(project.get("rights"), (list, tuple, set, frozenset)):
            continue
        project_groups = project.get("groups")
        if not isinstance(project_groups, list) or not any(g for g in project_groups if g):
            continue
        domain = extract_wikimedia_domain_from_project(project)
        if not domain or domain in seen_domains:
            continue
        seen_domains.add(domain)
        normalised_groups = {str(group).strip().lower() for group in project_groups if group}
        raw_edit_count = project.get("editcount", 0)
        if isinstance(raw_edit_count, bool):
            edit_count = 0
        else:
            try:
                edit_count = max(int(raw_edit_count), 0)
            except TypeError, ValueError:
                edit_count = 0
        candidates.append((0 if "sysop" in normalised_groups else 1, -edit_count, idx, domain))

    if not candidates:
        return evaluate_wikimedia_rights({**combined_info, "merged_projects": enriched})

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
            normalised = {str(right).strip().lower() for right in rights if right}
            if normalised & REQUIRED_WIKIMEDIA_RIGHTS_SET:
                found_required = True
        if found_required:
            break

    return evaluate_wikimedia_rights({**combined_info, "merged_projects": enriched})


def _safe_save_session(request, *, context: str) -> bool:
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


@sync_to_async(thread_sensitive=True)
def get_session_user(request, *, context: str = "session_rights_check") -> Any:
    """Reads and validates session user data whilst shielding callers from cache backend outages."""
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
    """Persists authenticated user data in Django session storage with key rotation."""
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


def validate_session_csrf(request) -> Optional[JsonResponse]:
    """Enforces Django CSRF verification for session-authenticated POST endpoints."""
    middleware = CsrfViewMiddleware(lambda _req: None)
    if "CSRF_COOKIE" not in request.META:
        middleware.process_request(request)
    rejection = middleware.process_view(request, lambda _req: None, (), {})
    if rejection is not None:
        return JsonResponse(
            {"error": "csrf_failed", "message": "CSRF verification failed."},
            status=403,
        )
    return None


@sync_to_async(thread_sensitive=True)
def flush_session_async(request, *, context: str) -> bool:
    """Flushes Django session state under ASGI, degrading cleanly if cache deletion fails."""
    try:
        request.session.flush()
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
    request.session.modified = True
    return True


async def authenticate_detect_request(
    request,
    *,
    require_csrf_for_session: bool = False,
) -> Tuple[Optional[str], Optional[JsonResponse]]:
    """Validates gadget Bearer token or Wikimedia session credentials for IP detection endpoints."""
    auth_mode: Optional[str] = None
    error: Optional[JsonResponse] = None

    auth_header = request.headers.get("Authorization")
    if auth_header is not None and str(auth_header).strip():
        token_user, token_error = verify_gadget_bearer_token(str(auth_header))
        if token_error or not token_user:
            error = JsonResponse({"error": token_error or "Invalid authentication token."}, status=401)
        elif getattr(settings, "RESTRICT_TO_ALLOWED_WIKI_USERS", False) and not is_allowlisted_wiki_user(token_user):
            error = JsonResponse({"error": "Access denied. Insufficient Wikimedia user rights."}, status=403)
        else:
            auth_mode = "gadget"
    else:
        session_user = await get_session_user(request)
        if not isinstance(session_user, dict) or not session_user.get("isLoggedIn"):
            error = JsonResponse({"error": "Authentication required. Please log in with Wikimedia."}, status=401)
        elif not session_user.get("hasAccess"):
            error = JsonResponse({"error": "Access denied. Insufficient Wikimedia user rights."}, status=403)
        elif require_csrf_for_session and (csrf_error := validate_session_csrf(request)) is not None:
            error = csrf_error
        else:
            auth_mode = "session"

    auth_mode_logger.info("auth_mode=%s", auth_mode or "unauthenticated")
    return auth_mode, error


async def authorise_admin_session_request(request, *, context: str) -> Optional[JsonResponse]:
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
