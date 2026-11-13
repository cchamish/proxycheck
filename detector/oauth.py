"""
Wikimedia OAuth 2.0 group inspection, CentralAuth verification, and role-based access control.
"""

import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx
from django.conf import settings

logger = logging.getLogger(__name__)

MEDIAWIKI_API_URL = "https://meta.wikimedia.org/w/api.php"
WIKIMEDIA_USER_AGENT = "ProxyCheck/1.0 (https://proxycheck.toolforge.org; tools.proxycheck@toolforge.org)"
DEFAULT_RIGHTS_TTL_SECONDS = 3600

WIKIMEDIA_HOST_SUFFIXES = (
    r"wikipedia|wikimedia|wiktionary|wikibooks|wikinews|wikiquote|"
    r"wikisource|wikiversity|wikivoyage|wikidata|mediawiki|wikifunctions|wikimediafoundation"
)
WIKIMEDIA_BETA_SUFFIXES = (
    r"wikipedia|wikimedia|wiktionary|wikibooks|wikinews|wikiquote|"
    r"wikisource|wikiversity|wikivoyage|wikidata|mediawiki|wikifunctions"
)
WIKIMEDIA_HOST_RE = re.compile(
    rf"^(?:[a-z0-9-]+\.)*(?:{WIKIMEDIA_HOST_SUFFIXES})\.org$"
    rf"|^(?:[a-z0-9-]+\.)*(?:{WIKIMEDIA_BETA_SUFFIXES})\.beta\.wm(?:cloud|flabs)\.org$"
)

PRIVILEGED_GLOBAL_GROUP_LABELS: Dict[str, str] = {
    "steward": "Steward",
    "global-sysop": "Global Sysop",
    "global-rollbacker": "Global Rollbacker",
    "global-temporary-account-viewer": "Global Temporary Account Viewer",
    "ombuds": "Ombuds",
    "staff": "Wikimedia Foundation Staff",
}

PRIVILEGED_LOCAL_GROUP_LABELS: Dict[str, str] = {
    "sysop": "Local Administrator (sysop)",
    "administrator": "Local Administrator (sysop)",
    "checkuser": "CheckUser",
    "oversight": "Oversight",
    "suppress": "Suppress",
    "arbcom": "Arbitration Committee",
    "temporary-account-viewer": "Temporary Account Viewer",
}

_TRANSIENT_MEDIAWIKI_ERROR_CODES = frozenset({"maxlag", "readonly", "ratelimited"})


class MetaWikiRightsFetchError(RuntimeError):
    """Raised when Meta-Wiki globaluserinfo cannot be retrieved or returns an error payload."""


class CentralAuthVerificationError(RuntimeError):
    """Raised when Wikimedia CentralAuth token verification fails due to an upstream error."""

    def __init__(self, message: str, mw_error: Any = None):
        super().__init__(message)
        self.mw_error = mw_error


class InvalidCentralAuthTokenError(RuntimeError):
    """Raised when Wikimedia rejects a CentralAuth token or identifies an anonymous or temporary user."""

    def __init__(self, message: str, mw_error: Any = None):
        super().__init__(message)
        self.mw_error = mw_error


def normalize_and_validate_wikimedia_domain(raw_domain: Any) -> Optional[str]:
    """
    Validates and normalizes a Wikimedia project hostname without scheme, port, or path.
    """
    if not isinstance(raw_domain, str):
        return None
    candidate = raw_domain.strip().lower()
    if not candidate or len(candidate) > 253:
        return None
    if not WIKIMEDIA_HOST_RE.match(candidate):
        return None
    for label in candidate.split("."):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return None
    return candidate


def _clear_client_cookies(client: Any) -> None:
    cookies = getattr(client, "cookies", None)
    if isinstance(cookies, httpx.Cookies):
        cookies.clear()


def normalize_wiki_username(raw_username: Any) -> str:
    """Normalizes a Wikimedia username with underscores replaced and initial character capitalized."""
    if not isinstance(raw_username, str):
        return ""
    cleaned = raw_username.replace("_", " ").strip()
    if not cleaned:
        return ""
    return cleaned[0].upper() + cleaned[1:]


def get_allowed_wiki_users() -> Set[str]:
    """Returns normalized usernames configured in the ALLOWED_WIKI_USERS setting or environment."""
    configured = getattr(settings, "ALLOWED_WIKI_USERS", None)
    if configured is None or configured == "":
        configured = os.environ.get("ALLOWED_WIKI_USERS", "")
    if isinstance(configured, str):
        raw_items = [item.strip() for item in configured.split(",") if item.strip()]
    elif isinstance(configured, (list, tuple, set, frozenset)):
        raw_items = [str(item).strip() for item in configured if str(item).strip()]
    else:
        raw_items = []
    return {normalize_wiki_username(item) for item in raw_items if normalize_wiki_username(item)}


def is_allowlisted_wiki_user(username: Any) -> bool:
    """Returns True when the normalized username is present in ALLOWED_WIKI_USERS."""
    normalized = normalize_wiki_username(username)
    if not normalized:
        return False
    return normalized in get_allowed_wiki_users()


def is_session_rights_expired(
    user_data: Dict[str, Any],
    ttl_seconds: int = DEFAULT_RIGHTS_TTL_SECONDS,
    now: Optional[float] = None,
) -> bool:
    """
    Returns True when the cached Wikimedia group evaluation in the user session
    has exceeded its refresh window.
    """
    if not isinstance(user_data, dict):
        return True
    updated_at = user_data.get("rights_updated_at")
    if updated_at is None:
        return False
    if isinstance(updated_at, bool) or not isinstance(updated_at, (int, float)):
        return True
    current_time = time.time() if now is None else now
    return (current_time - float(updated_at)) > float(ttl_seconds)


def _format_local_project_role(group: str, label: str, wiki_name: str) -> str:
    if group in ("sysop", "administrator"):
        return f"Local Administrator (sysop: {wiki_name})"
    return f"{label} ({wiki_name})"


def evaluate_wikimedia_rights(user_info: Dict[str, Any]) -> Tuple[bool, str, List[str], List[str]]:
    """
    Evaluates Wikimedia RBAC permissions across global groups, local groups,
    SUL-merged project groups, and the configured username allowlist.
    """
    global_groups = [str(g).strip().lower() for g in (user_info.get("global_groups") or []) if g]
    local_groups = [str(g).strip().lower() for g in (user_info.get("local_groups") or []) if g]
    merged_projects = user_info.get("merged_projects") or []
    username = user_info.get("username") or ""

    global_group_set = set(global_groups)
    for group, label in PRIVILEGED_GLOBAL_GROUP_LABELS.items():
        if group in global_group_set:
            return True, label, local_groups, global_groups

    local_group_set = set(local_groups)
    for group, label in PRIVILEGED_LOCAL_GROUP_LABELS.items():
        if group in local_group_set:
            return True, label, local_groups, global_groups

    # The OAuth profile endpoint only returns groups on the central Meta-Wiki,
    # so inspect SUL-merged wikis to recognize project-local privileges.
    for project in merged_projects:
        if not isinstance(project, dict):
            continue
        project_groups = {str(g).strip().lower() for g in (project.get("groups") or []) if g}
        wiki_name = project.get("wiki", "project")
        for group, label in PRIVILEGED_LOCAL_GROUP_LABELS.items():
            if group in project_groups:
                return True, _format_local_project_role(group, label, wiki_name), local_groups, global_groups

    if username and is_allowlisted_wiki_user(username):
        return True, "Allowlisted Wikimedia User", local_groups, global_groups

    return False, "Standard User (Unauthorised)", local_groups, global_groups


async def verify_centralauth_userinfo(
    client: httpx.AsyncClient,
    centralauth_token: str,
    wiki_domain: str = "meta.wikimedia.org",
) -> Dict[str, Any]:
    """
    Verifies a one-time MediaWiki CentralAuth token against the target Wikimedia project API
    without sending cookies and returns the authenticated username alongside local groups and rights.
    """
    validated_domain = normalize_and_validate_wikimedia_domain(wiki_domain)
    if not validated_domain:
        raise InvalidCentralAuthTokenError(
            "Invalid or unsupported Wikimedia domain.",
            mw_error={"code": "invalid_domain", "domain": str(wiki_domain)},
        )

    api_url = f"https://{validated_domain}/w/api.php"
    params = {
        "action": "query",
        "meta": "userinfo",
        "uiprop": "groups|rights|centralids",
        "format": "json",
        "centralauthtoken": centralauth_token,
    }
    headers = {"User-Agent": WIKIMEDIA_USER_AGENT}
    _clear_client_cookies(client)
    try:
        resp = await client.get(api_url, params=params, headers=headers, timeout=10.0)
    except Exception as exc:
        logger.warning(f"Error verifying CentralAuth token with {validated_domain}: {type(exc).__name__}")
        raise CentralAuthVerificationError(
            f"Wikimedia CentralAuth verification request failed on {validated_domain}.",
            mw_error={"code": "upstream_network_error", "exception": type(exc).__name__},
        ) from exc
    finally:
        _clear_client_cookies(client)

    if resp.status_code != 200:
        logger.warning(f"{validated_domain} returned HTTP {resp.status_code} during CentralAuth verification")
        raise CentralAuthVerificationError(
            f"{validated_domain} returned HTTP {resp.status_code}.",
            mw_error={"code": "http_error", "status": resp.status_code, "domain": validated_domain},
        )

    try:
        data = resp.json()
    except ValueError as exc:
        logger.warning(f"{validated_domain} returned invalid JSON during CentralAuth verification")
        raise CentralAuthVerificationError(
            f"{validated_domain} returned invalid JSON.",
            mw_error={"code": "invalid_json", "domain": validated_domain},
        ) from exc

    if not isinstance(data, dict):
        raise CentralAuthVerificationError(
            f"{validated_domain} returned unexpected CentralAuth payload type.",
            mw_error={"code": "invalid_payload_type", "domain": validated_domain},
        )

    if "error" in data:
        err_obj = data.get("error")
        err_code = str(err_obj.get("code", "")).strip() if isinstance(err_obj, dict) else ""
        err_info = str(err_obj.get("info", "")).strip() if isinstance(err_obj, dict) else ""
        error_detail = err_code or "unknown"
        if err_info:
            error_detail = f"{error_detail}: {err_info}"
        normalized_code = err_code.lower()
        if normalized_code.startswith("internal_api_error") or normalized_code in _TRANSIENT_MEDIAWIKI_ERROR_CODES:
            logger.warning(
                f"Transient MediaWiki error on {validated_domain} during CentralAuth verification: {error_detail}"
            )
            raise CentralAuthVerificationError(
                f"MediaWiki transient error on {validated_domain}: {error_detail}",
                mw_error=err_obj,
            )
        logger.warning(f"{validated_domain} rejected CentralAuth token: {error_detail}")
        raise InvalidCentralAuthTokenError(
            f"MediaWiki rejected CentralAuth token ({error_detail}).",
            mw_error=err_obj,
        )

    query_obj = data.get("query")
    userinfo = query_obj.get("userinfo") if isinstance(query_obj, dict) else None
    if not isinstance(userinfo, dict):
        logger.warning(f"{validated_domain} userinfo missing from CentralAuth verification response")
        raise CentralAuthVerificationError(
            f"{validated_domain} userinfo missing from response.",
            mw_error={"code": "missing_userinfo", "domain": validated_domain},
        )

    if "anon" in userinfo or userinfo.get("id", 0) == 0:
        raise InvalidCentralAuthTokenError(
            "Anonymous Wikimedia users cannot authenticate.",
            mw_error={
                "code": "anon",
                "info": "MediaWiki resolved CentralAuth token to an anonymous user.",
                "domain": validated_domain,
            },
        )

    username = userinfo.get("name")
    if not isinstance(username, str) or not username.strip():
        raise InvalidCentralAuthTokenError(
            "Authenticated Wikimedia username missing from userinfo.",
            mw_error={"code": "missing_username", "domain": validated_domain},
        )

    cleaned_username = username.strip()
    if "temp" in userinfo or cleaned_username.startswith("~"):
        raise InvalidCentralAuthTokenError(
            "Temporary Wikimedia accounts cannot authenticate.",
            mw_error={
                "code": "temp",
                "info": "Temporary Wikimedia accounts are not permitted.",
                "domain": validated_domain,
            },
        )

    raw_groups = userinfo.get("groups")
    local_groups = [str(g).strip().lower() for g in raw_groups if g] if isinstance(raw_groups, list) else []
    raw_rights = userinfo.get("rights")
    rights = [str(r).strip() for r in raw_rights if r] if isinstance(raw_rights, list) else []
    raw_centralids = userinfo.get("centralids")
    centralids = raw_centralids if isinstance(raw_centralids, dict) else {}

    return {
        "username": cleaned_username,
        "local_groups": local_groups,
        "rights": rights,
        "centralids": centralids,
        "domain": validated_domain,
    }


async def fetch_user_rights_from_meta(
    client: httpx.AsyncClient,
    username: str,
    wiki_domain: str = "meta.wikimedia.org",
) -> Dict[str, Any]:
    """
    Fetches global groups and per-wiki SUL account memberships via Wikimedia's
    `meta=globaluserinfo` Action API.
    Raises MetaWikiRightsFetchError when the upstream request fails or returns a non-200
    or malformed payload, distinguishing transient API failures from normal users with no groups.
    """
    validated_domain = normalize_and_validate_wikimedia_domain(wiki_domain)
    api_url = f"https://{validated_domain}/w/api.php" if validated_domain else MEDIAWIKI_API_URL
    params = {
        "action": "query",
        "meta": "globaluserinfo",
        "guiuser": username,
        "guiprop": "groups|rights|merged",
        "format": "json",
    }
    headers = {
        "User-Agent": WIKIMEDIA_USER_AGENT,
    }
    _clear_client_cookies(client)
    try:
        resp = await client.get(api_url, params=params, headers=headers, timeout=10.0)
    except Exception as exc:
        logger.warning(f"Error querying Meta-Wiki for user rights: {exc}")
        raise MetaWikiRightsFetchError(f"Meta-Wiki request failed: {exc}") from exc
    finally:
        _clear_client_cookies(client)

    if resp.status_code != 200:
        logger.warning(f"Meta-Wiki returned HTTP {resp.status_code} for user rights query")
        raise MetaWikiRightsFetchError(f"Meta-Wiki returned HTTP {resp.status_code}")

    try:
        data = resp.json()
    except ValueError as exc:
        logger.warning(f"Meta-Wiki returned invalid JSON for user rights query: {exc}")
        raise MetaWikiRightsFetchError("Meta-Wiki returned invalid JSON") from exc

    if not isinstance(data, dict) or "error" in data:
        logger.warning("Meta-Wiki response contained an API error or unexpected payload type")
        raise MetaWikiRightsFetchError("Meta-Wiki returned an API error payload")

    query_obj = data.get("query")
    gui = query_obj.get("globaluserinfo") if isinstance(query_obj, dict) else None
    if not isinstance(gui, dict) or "missing" in gui:
        logger.warning("Meta-Wiki globaluserinfo missing from response")
        raise MetaWikiRightsFetchError("Meta-Wiki globaluserinfo missing from response")

    global_groups = gui.get("groups")
    if not isinstance(global_groups, list):
        global_groups = gui.get("globalgroups")
    merged = gui.get("merged")
    return {
        "global_groups": global_groups if isinstance(global_groups, list) else [],
        "merged_projects": merged if isinstance(merged, list) else [],
    }
