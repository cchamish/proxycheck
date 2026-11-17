"""
Credential redaction and safe upstream HTTP response logging helpers.
"""

import os
import re
from typing import Any, Optional, Tuple
from urllib.parse import quote

import httpx
from django.conf import settings

from .provider_registry import SECRET_SETTING_NAMES

REDACTED_PLACEHOLDER = "***REDACTED***"

# Matches credential-bearing query parameters such as key=, api-key=, access_token= or contact=,
# including quoted values as they appear in Python reprs
_SENSITIVE_QUERY_PATTERN = re.compile(r"(?i)((?:api[_-]?key|key|token|secret|contact|pass(?:word)?)=['\"]?)[^&\s'\"]+")
_BEARER_TOKEN_PATTERN = re.compile(r"(?i)(Bearer\s+)[^\s'\"\\,;]+")

# Very short values would redact ordinary words, and no real provider issues keys this short
_MIN_SECRET_LENGTH = 4

_secret_values_cache: Optional[Tuple[Tuple[Tuple[Optional[str], Any], ...], Tuple[str, ...]]] = None


def clear_secret_values_cache() -> None:
    """Clears the memoised credential fingerprint cache."""
    global _secret_values_cache
    _secret_values_cache = None


def configured_secret_values() -> Tuple[str, ...]:
    """Collects configured credentials from the environment and settings, longest first."""
    global _secret_values_cache
    fingerprint = tuple((os.environ.get(name), getattr(settings, name, "")) for name in SECRET_SETTING_NAMES)
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


def sanitize_error_message(err_str: str) -> str:
    """Redacts credential query parameters, Bearer tokens, and configured API keys from upstream error text."""
    if err_str is None:
        return ""
    text = err_str if isinstance(err_str, str) else str(err_str)
    text = _SENSITIVE_QUERY_PATTERN.sub(lambda m: m.group(1) + REDACTED_PLACEHOLDER, text)
    text = _BEARER_TOKEN_PATTERN.sub(r"\1" + REDACTED_PLACEHOLDER, text)
    for secret_value in configured_secret_values():
        text = text.replace(secret_value, REDACTED_PLACEHOLDER)
    return text


def sanitize_payload(value: Any) -> Any:
    """Recursively redacts secrets from every string in a JSON-like structure before it leaves the server."""
    if isinstance(value, str):
        return sanitize_error_message(value)
    if isinstance(value, dict):
        return {k: sanitize_payload(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_payload(v) for v in value]
    return value


def extract_response_log_details(resp: Any) -> Tuple[str, str]:
    """Extracts a sanitised content type and 120-character body preview for warning logs."""
    content_type = "unknown"
    headers = getattr(resp, "headers", None)
    getter = getattr(headers, "get", None) if headers is not None else None
    if callable(getter):
        for header_name in ("Content-Type", "content-type"):
            candidate = getter(header_name)
            if isinstance(candidate, str) and candidate.strip():
                cleaned_ct = " ".join(sanitize_error_message(candidate).split())
                content_type = cleaned_ct[:64] or "unknown"
                break

    raw_text = getattr(resp, "text", "")
    if not isinstance(raw_text, str) or not raw_text.strip():
        return content_type, "<empty>"
    sanitized_text = " ".join(sanitize_error_message(raw_text).split())
    if len(sanitized_text) > 120:
        return content_type, f"{sanitized_text[:117]}..."
    return content_type, sanitized_text


def parse_upstream_json_with_error(resp: httpx.Response) -> Tuple[Any, int, Optional[str]]:
    """Decodes an upstream response body and returns any JSON parsing error class name."""
    try:
        return resp.json(), resp.status_code, None
    except ValueError as exc:
        status_code = 502 if resp.status_code == 200 else resp.status_code
        return {"status": "error", "message": sanitize_error_message(resp.text or "")}, status_code, type(exc).__name__
