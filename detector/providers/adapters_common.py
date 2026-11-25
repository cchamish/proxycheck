"""Shared response adapter row builders, payload guards, and formatting helpers."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

_ERROR_STATUS_LABELS: Dict[int, str] = {
    401: "401 Unauthorised",
    429: "429 Rate Limited",
}


def _default_no_flags() -> List[Dict[str, Any]]:
    return [{"label": "No Flags", "isHighRisk": False}]


def _safe_int(val: Any, default: Optional[int] = 0) -> Optional[int]:
    """Converts a numeric-looking value to int, falling back to default for null, NaN, booleans, or invalid text."""
    if val is None or isinstance(val, bool):
        return default
    try:
        num = float(val)
    except TypeError, ValueError:
        return default
    if not math.isfinite(num):
        return default
    return int(num)


def _guard_payload(raw_data: Any, status_code: int) -> Tuple[Optional[Dict[str, Any]], int]:
    """Downgrades non-dictionary upstream bodies to a format error so adapters never call dictionary methods on them."""
    if raw_data is None or isinstance(raw_data, dict):
        return raw_data, status_code
    error_payload = {
        "status": "error",
        "message": f"Unexpected upstream payload type: {type(raw_data).__name__}",
    }
    return error_payload, (502 if status_code == 200 else status_code)


def _build_error_row(
    provider: str,
    status_code: Optional[int] = None,
    raw_data: Optional[Dict[str, Any]] = None,
    *,
    status: Optional[str] = None,
    usage_type: str = "-",
    security_flags: Optional[List[Dict[str, Any]]] = None,
    raw_message: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Builds a standardised adapter error or unconfigured provider row."""
    if status is not None:
        resolved_status = status
    elif status_code is None:
        resolved_status = "No API Key"
    else:
        resolved_status = _ERROR_STATUS_LABELS.get(status_code, f"{status_code} Error")

    resolved_flags = security_flags if security_flags is not None else _default_no_flags()
    default_message = "API key not configured" if status_code is None else f"HTTP {status_code}"
    resolved_raw_json = raw_data if raw_data else {"status": "error", "message": raw_message or default_message}

    return {
        "provider": provider,
        "status": resolved_status,
        "statusCode": status_code,
        "asn": "-",
        "isp": "-",
        "organisation": "-",
        "location": "-",
        "usageType": usage_type,
        "securityFlags": resolved_flags,
        **(extra or {}),
        "rawJson": resolved_raw_json,
    }


def _build_ok_row(
    provider: str,
    raw_data: Any,
    *,
    asn: str = "-",
    isp: str = "-",
    organisation: Optional[str] = None,
    location: str = "-",
    usage_type: str = "-",
    security_flags: Optional[List[Dict[str, Any]]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Builds a normalised HTTP 200 provider row with default organisation and flag fallbacks."""
    return {
        "provider": provider,
        "status": "200 OK",
        "statusCode": 200,
        "asn": asn,
        "isp": isp,
        "organisation": isp if organisation is None else organisation,
        "location": location,
        "usageType": usage_type,
        "securityFlags": security_flags if security_flags else _default_no_flags(),
        **(extra or {}),
        "rawJson": raw_data,
    }


def _build_risk_flags(*flag_specs: Tuple[str, Any]) -> List[Dict[str, Any]]:
    """Constructs high-risk security flag entries from label and boolean-condition pairs."""
    flags = [{"label": label, "isHighRisk": True} for label, active in flag_specs if active]
    return flags if flags else _default_no_flags()


def _format_asn_str(asn_val: Any, *, strict_numeric: bool = False) -> str:
    """Formats an ASN value with a leading AS prefix, falling back to a hyphen."""
    if strict_numeric:
        asn_int = _safe_int(asn_val, default=None)
        if asn_int is not None and asn_int > 0:
            return f"AS{asn_int}"
        if isinstance(asn_val, str) and asn_val.strip().upper().startswith("AS"):
            return asn_val.strip().upper()
        return "-"
    if asn_val:
        text = str(asn_val)
        return text if text.startswith("AS") else f"AS{text}"
    return "-"


def _format_location(parts: Iterable[Any]) -> str:
    """Joins non-empty geographic parts into a display string, falling back to a hyphen."""
    clean_parts = [str(part) for part in parts if part]
    return ", ".join(clean_parts) if clean_parts else "-"


def _normalize_timestamp_or_text(value: Any) -> Optional[str]:
    """Converts a positive Unix timestamp or non-empty date string to normalised text."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if not math.isfinite(value) or value <= 0:
            return None
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
        except OverflowError, OSError, ValueError:
            return None
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned or cleaned.lower() in ("-", "null", "none", "never", "false", "0"):
            return None
        return cleaned
    return None
