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

REQUIRED_WIKIMEDIA_RIGHTS: Tuple[str, ...] = (
    "checkuser-temporary-account-no-preference",
    "checkuser-temporary-account",
)
REQUIRED_WIKIMEDIA_RIGHTS_SET = frozenset(REQUIRED_WIKIMEDIA_RIGHTS)

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
    Returns True when the cached Wikimedia rights evaluation in the user session
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


def _normalize_str_list(values: Any, *, lowercase: bool = False) -> List[str]:
    if not isinstance(values, (list, tuple, set, frozenset)):
        return []
    normalized: List[str] = []
    for item in values:
        if not item:
            continue
        cleaned = str(item).strip()
        if not cleaned:
            continue
        normalized.append(cleaned.lower() if lowercase else cleaned)
    return normalized


def _find_required_right(rights: Any) -> Optional[str]:
    """Returns the matching temporary-account IP reveal right when present."""
    normalized = set(_normalize_str_list(rights, lowercase=True))
    for right in REQUIRED_WIKIMEDIA_RIGHTS:
        if right in normalized:
            return right
    return None


def extract_wikimedia_domain_from_project(project: Any) -> Optional[str]:
    """Extracts and validates a Wikimedia project hostname from a merged SUL entry."""
    if not isinstance(project, dict):
        return None
    raw_url = project.get("url")
    if not isinstance(raw_url, str):
        return None
    cleaned = raw_url.strip()
    if cleaned.startswith("https://"):
        host = cleaned[8:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    elif cleaned.startswith("http://"):
        host = cleaned[7:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    else:
        return None
    return normalize_and_validate_wikimedia_domain(host)


def evaluate_wikimedia_rights(user_info: Dict[str, Any]) -> Tuple[bool, str, List[str], List[str]]:
    """
    Evaluates Wikimedia permissions directly from user rights (`checkuser-temporary-account`
    or `checkuser-temporary-account-no-preference`) rather than user group names,
    alongside the configured operator username allowlist.
    """
    global_groups = _normalize_str_list(user_info.get("global_groups") or [], lowercase=True)
    local_groups = _normalize_str_list(user_info.get("local_groups") or [], lowercase=True)
    raw_local_rights = user_info.get("local_rights") if "local_rights" in user_info else user_info.get("rights")
    local_rights = _normalize_str_list(raw_local_rights or [], lowercase=True)
    global_rights = _normalize_str_list(user_info.get("global_rights") or [], lowercase=True)
    merged_projects = user_info.get("merged_projects") or []
    username = str(user_info.get("username") or "").strip()

    if username.startswith("~"):
        return False, "Standard User (Unauthorised)", local_groups, global_groups

    if getattr(settings, "RESTRICT_TO_ALLOWED_WIKI_USERS", False):
        if is_allowlisted_wiki_user(username):
            return True, "Allowlisted Wikimedia User", local_groups, global_groups
        return False, "Access Denied (restricted user allowlist)", local_groups, global_groups

    matched_global_right = _find_required_right(global_rights)
    if matched_global_right:
        return True, f"Temporary Account Access (global: {matched_global_right})", local_groups, global_groups

    matched_local_right = _find_required_right(local_rights)
    if matched_local_right:
        return True, f"Temporary Account Access (local: {matched_local_right})", local_groups, global_groups

    if isinstance(merged_projects, list):
        for project in merged_projects:
            if not isinstance(project, dict):
                continue
            matched_project_right = _find_required_right(project.get("rights"))
            if matched_project_right:
                wiki_name = str(project.get("wiki") or "project").strip() or "project"
                return (
                    True,
                    f"Temporary Account Access ({wiki_name}: {matched_project_right})",
                    local_groups,
                    global_groups,
                )

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
    Fetches global rights, global groups, and per-wiki SUL account memberships via Wikimedia's
    `meta=globaluserinfo` Action API.
    Raises MetaWikiRightsFetchError when the upstream request fails or returns a non-200
    or malformed payload, distinguishing transient API failures from normal users without rights.
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
    global_rights = gui.get("rights")
    merged = gui.get("merged")
    return {
        "global_groups": global_groups if isinstance(global_groups, list) else [],
        "global_rights": _normalize_str_list(global_rights, lowercase=True),
        "merged_projects": merged if isinstance(merged, list) else [],
    }


async def fetch_project_user_rights(
    client: httpx.AsyncClient,
    username: str,
    wiki_domain: str,
) -> List[str]:
    """
    Fetches effective local user rights for an account on a specific Wikimedia project
    using `action=query&list=users&usprop=rights`.
    Degrades to an empty list when an individual project endpoint fails so other merged
    wikis can still be evaluated.
    """
    validated_domain = normalize_and_validate_wikimedia_domain(wiki_domain)
    if not validated_domain:
        return []

    api_url = f"https://{validated_domain}/w/api.php"
    params = {
        "action": "query",
        "list": "users",
        "ususers": username,
        "usprop": "rights",
        "format": "json",
    }
    headers = {"User-Agent": WIKIMEDIA_USER_AGENT}
    _clear_client_cookies(client)
    try:
        resp = await client.get(api_url, params=params, headers=headers, timeout=10.0)
    except Exception as exc:
        logger.warning(f"Error querying {validated_domain} for user rights: {type(exc).__name__}")
        return []
    finally:
        _clear_client_cookies(client)

    if resp.status_code != 200:
        logger.warning(f"{validated_domain} returned HTTP {resp.status_code} for user rights query")
        return []

    try:
        data = resp.json()
    except ValueError:
        logger.warning(f"{validated_domain} returned invalid JSON for user rights query")
        return []

    if not isinstance(data, dict) or "error" in data:
        return []

    query_obj = data.get("query")
    users = query_obj.get("users") if isinstance(query_obj, dict) else None
    if not isinstance(users, list) or not users:
        return []

    first_user = users[0]
    if not isinstance(first_user, dict) or "missing" in first_user or "invalid" in first_user:
        return []

    return _normalize_str_list(first_user.get("rights"), lowercase=True)
