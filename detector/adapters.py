"""
Response adapters normalising upstream IP intelligence payloads into a unified schema.
"""

from __future__ import annotations

import ipaddress
import math
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .cidr_attribution import (
    are_offline_intelligence_caches_warm,
    classify_rdns_hostname,
    clear_offline_intelligence_caches,
    compute_cidr_attribution,
    match_cloud_cidr,
    match_hosting_asn_or_org,
    parse_cloud_cidr_payload,
    warm_offline_intelligence_caches,
)

_parse_cloud_cidr_payload = parse_cloud_cidr_payload

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


def _format_coordinates(lat: Any, lon: Any, *, reject_blank: bool = False) -> Optional[str]:
    if lat is None or lon is None:
        return None
    if reject_blank:
        if isinstance(lat, bool) or isinstance(lon, bool):
            return None
        if str(lat).strip() == "" or str(lon).strip() == "":
            return None
    return f"{lat}, {lon}"


def _format_location_with_coords(
    parts: Iterable[Any],
    lat: Any = None,
    lon: Any = None,
    *,
    reject_blank_coords: bool = False,
    empty_with_coords_prefix: str = "",
) -> Tuple[str, Optional[str]]:
    """Joins non-empty geographic parts and appends parenthesised coordinates when present."""
    clean_parts = [str(part) for part in parts if part]
    coords = _format_coordinates(lat, lon, reject_blank=reject_blank_coords)
    loc_str = ", ".join(clean_parts)
    if coords:
        if loc_str:
            loc_str = f"{loc_str} ({coords})"
        elif empty_with_coords_prefix:
            loc_str = f"{empty_with_coords_prefix} ({coords})"
        else:
            loc_str = f" ({coords})"
    return (loc_str if loc_str else "-"), coords


def _extract_carrier_name(carrier_val: Any) -> Optional[str]:
    """Extracts a clean carrier name from a provider carrier dictionary or string."""
    candidate = carrier_val.get("name") if isinstance(carrier_val, dict) else carrier_val
    if isinstance(candidate, str):
        cleaned = candidate.strip()
        if cleaned and cleaned != "-":
            return cleaned
    return None


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


def adapt_cloudflare_radar(
    raw_data: Optional[Dict[str, Any]], has_api_key: bool, status_code: int = 200
) -> Dict[str, Any]:
    if not has_api_key:
        return _build_error_row("Cloudflare Radar", security_flags=[])

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data or not raw_data.get("success", False):
        return _build_error_row("Cloudflare Radar", status_code, raw_data, security_flags=[])

    result_obj = raw_data.get("result")
    asn_obj = result_obj.get("asn") if isinstance(result_obj, dict) and isinstance(result_obj.get("asn"), dict) else {}
    asn_num = asn_obj.get("asn")
    org_name = asn_obj.get("name") or asn_obj.get("orgName") or "-"

    return _build_ok_row(
        "Cloudflare Radar",
        raw_data,
        asn=f"AS{asn_num}" if asn_num is not None else "-",
        isp=org_name,
        location=asn_obj.get("countryName") or asn_obj.get("country") or "-",
        usage_type=asn_obj.get("type") or "infrastructure",
        extra={"countryCode": asn_obj.get("country")},
    )


def adapt_abuseipdb(raw_data: Optional[Dict[str, Any]], has_api_key: bool, status_code: int = 200) -> Dict[str, Any]:
    extra = {"abuseConfidenceScore": None, "totalReports": None, "numDistinctUsers": None, "lastSeen": None}
    if not has_api_key:
        return _build_error_row("AbuseIPDB", extra=extra)

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data or not isinstance(raw_data.get("data"), dict):
        return _build_error_row("AbuseIPDB", status_code, raw_data, extra=extra)

    data = raw_data["data"]
    raw_usage = data.get("usageType")
    usage_type = raw_usage.strip() if isinstance(raw_usage, str) and raw_usage.strip() else "-"
    usage_lower = usage_type.lower()
    is_datacenter = any(kw in usage_lower for kw in ("data center", "datacenter", "web hosting", "transit"))

    flags = _build_risk_flags(
        ("Tor Exit Node", data.get("isTor")),
        ("Datacenter / Hosting", is_datacenter),
    )
    location, _ = _format_location_with_coords((data.get("countryName"), data.get("countryCode")))

    raw_abuse_score = _safe_int(data.get("abuseConfidenceScore"), default=None)
    raw_total_reports = _safe_int(data.get("totalReports"), default=None)
    raw_distinct_users = _safe_int(data.get("numDistinctUsers"), default=None)

    return _build_ok_row(
        "AbuseIPDB",
        raw_data,
        isp=data.get("isp") or "-",
        location=location,
        usage_type=usage_type,
        security_flags=flags,
        extra={
            "abuseConfidenceScore": max(0, min(100, raw_abuse_score)) if raw_abuse_score is not None else None,
            "totalReports": max(0, raw_total_reports) if raw_total_reports is not None else None,
            "numDistinctUsers": max(0, raw_distinct_users) if raw_distinct_users is not None else None,
            "lastSeen": _normalize_timestamp_or_text(data.get("lastReportedAt")),
            "countryCode": data.get("countryCode"),
        },
    )


def adapt_ipdata(raw_data: Optional[Dict[str, Any]], has_api_key: bool, status_code: int = 200) -> Dict[str, Any]:
    if not has_api_key:
        return _build_error_row("IPData", extra={"carrier": None})

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data or "message" in raw_data:
        return _build_error_row("IPData", status_code, raw_data, extra={"carrier": None})

    threat = raw_data.get("threat") if isinstance(raw_data.get("threat"), dict) else {}
    company = raw_data.get("company") if isinstance(raw_data.get("company"), dict) else {}
    flags = _build_risk_flags(
        ("Proxy", threat.get("is_proxy")),
        ("Datacenter", threat.get("is_datacenter")),
        ("Tor", threat.get("is_tor")),
        ("VPN", threat.get("is_vpn")),
        ("iCloud Private Relay", threat.get("is_icloud_relay")),
        ("Known Attacker", threat.get("is_known_attacker")),
    )

    asn_val = raw_data.get("asn")
    if isinstance(asn_val, dict):
        asn_str = _format_asn_str(asn_val.get("asn") or asn_val.get("number"))
        org_fallback = asn_val.get("name")
    else:
        asn_str = _format_asn_str(asn_val)
        org_fallback = None

    location, coords = _format_location_with_coords(
        (raw_data.get("city"), raw_data.get("region"), raw_data.get("country_name")),
        raw_data.get("latitude"),
        raw_data.get("longitude"),
    )
    carrier_name = _extract_carrier_name(raw_data.get("carrier"))
    company_type = company.get("type")
    normalized_company_type = company_type.strip() if isinstance(company_type, str) and company_type.strip() else None

    return _build_ok_row(
        "IPData",
        raw_data,
        asn=asn_str,
        isp=raw_data.get("organisation") or org_fallback or company.get("name") or carrier_name or "-",
        location=location,
        usage_type=normalized_company_type or ("mobile" if carrier_name else "-"),
        security_flags=flags,
        extra={
            "carrier": carrier_name,
            "countryCode": raw_data.get("country_code"),
            "coordinates": coords,
        },
    )


def adapt_ipregistry(raw_data: Optional[Dict[str, Any]], has_api_key: bool, status_code: int = 200) -> Dict[str, Any]:
    if not has_api_key:
        return _build_error_row("IPRegistry", extra={"isMobile": False})

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data or "code" in raw_data:
        return _build_error_row("IPRegistry", status_code, raw_data, extra={"isMobile": False})

    security = raw_data.get("security") if isinstance(raw_data.get("security"), dict) else {}
    connection = raw_data.get("connection") if isinstance(raw_data.get("connection"), dict) else {}
    loc = raw_data.get("location") if isinstance(raw_data.get("location"), dict) else {}
    conn_type = connection.get("type") or "-"
    conn_type_lower = str(conn_type).strip().lower()
    is_cloud = bool(security.get("is_cloud_provider"))

    flags = _build_risk_flags(
        ("Proxy", security.get("is_proxy")),
        ("VPN", security.get("is_vpn")),
        ("Tor", security.get("is_tor")),
        ("Relay", security.get("is_relay")),
        ("Known Abuser", security.get("is_abuser")),
        ("Threat Detected", security.get("is_threat")),
        ("Cloud Provider", is_cloud),
        ("Hosting", not is_cloud and conn_type_lower in ("hosting", "datacenter")),
    )

    region_obj = loc.get("region") if isinstance(loc.get("region"), dict) else {}
    country_obj = loc.get("country") if isinstance(loc.get("country"), dict) else {}
    location, coords = _format_location_with_coords(
        (loc.get("city"), region_obj.get("name"), country_obj.get("name")),
        loc.get("latitude"),
        loc.get("longitude"),
    )

    return _build_ok_row(
        "IPRegistry",
        raw_data,
        asn=_format_asn_str(connection.get("asn")),
        isp=connection.get("organization") or "-",
        location=location,
        usage_type=conn_type,
        security_flags=flags,
        extra={
            "isMobile": conn_type_lower == "mobile",
            "countryCode": country_obj.get("code"),
            "coordinates": coords,
        },
    )


def adapt_ip2location(raw_data: Optional[Dict[str, Any]], has_api_key: bool, status_code: int = 200) -> Dict[str, Any]:
    if not has_api_key:
        return _build_error_row("IP2Location", extra={"mobileBrand": None})

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data or "error" in raw_data:
        err_obj = raw_data.get("error", {}) if isinstance(raw_data, dict) else {}
        err_msg = err_obj.get("error_message") if isinstance(err_obj, dict) else None
        return _build_error_row(
            "IP2Location",
            status_code,
            raw_data,
            raw_message=err_msg,
            extra={"mobileBrand": None},
        )

    proxy_obj = raw_data.get("proxy") if isinstance(raw_data.get("proxy"), dict) else {}
    flags = _build_risk_flags(
        ("Proxy", raw_data.get("is_proxy") or proxy_obj.get("is_proxy")),
        ("VPN", proxy_obj.get("is_vpn")),
        ("Tor", proxy_obj.get("is_tor")),
        ("Datacenter", proxy_obj.get("is_data_center")),
        ("Threat Detected", proxy_obj.get("is_spammer") or proxy_obj.get("is_scanner") or proxy_obj.get("is_botnet")),
    )

    location, coords = _format_location_with_coords(
        (raw_data.get("city_name"), raw_data.get("region_name"), raw_data.get("country_name")),
        raw_data.get("latitude"),
        raw_data.get("longitude"),
    )
    raw_mobile_brand = raw_data.get("mobile_brand")
    mobile_brand = (
        raw_mobile_brand.strip()
        if isinstance(raw_mobile_brand, str) and raw_mobile_brand.strip() and raw_mobile_brand.strip() != "-"
        else None
    )
    raw_usage = raw_data.get("usage_type") or proxy_obj.get("proxy_type")
    cleaned_usage = raw_usage.strip() if isinstance(raw_usage, str) and raw_usage.strip() else ""
    usage_type = cleaned_usage if cleaned_usage and cleaned_usage != "-" else ("mobile" if mobile_brand else "-")

    return _build_ok_row(
        "IP2Location",
        raw_data,
        asn=_format_asn_str(raw_data.get("asn")),
        isp=raw_data.get("as") or raw_data.get("isp") or mobile_brand or "-",
        location=location,
        usage_type=usage_type,
        security_flags=flags,
        extra={
            "mobileBrand": mobile_brand,
            "countryCode": raw_data.get("country_code"),
            "coordinates": coords,
        },
    )


def _extract_maxmind_name(node: Any) -> str:
    """Extracts a display name from a GeoLite2 or GeoIP2 field value, preferring English."""
    if isinstance(node, dict):
        names = node.get("names")
        if isinstance(names, dict):
            en_name = names.get("en")
            if isinstance(en_name, str) and en_name.strip():
                return en_name.strip()
            for candidate in names.values():
                if isinstance(candidate, str) and candidate.strip():
                    return candidate.strip()
        direct_name = node.get("name")
        if isinstance(direct_name, str) and direct_name.strip():
            return direct_name.strip()
    elif isinstance(node, str) and node.strip():
        return node.strip()
    return ""


def _extract_maxmind_subdivision(raw_subdivisions: Any) -> str:
    """Extracts the primary administrative subdivision name or code from MaxMind records."""
    if isinstance(raw_subdivisions, (list, tuple)):
        for entry in raw_subdivisions:
            name = _extract_maxmind_name(entry)
            if name:
                return name
            if isinstance(entry, dict):
                iso_code = entry.get("iso_code")
                if isinstance(iso_code, str) and iso_code.strip():
                    return iso_code.strip()
        return ""
    if isinstance(raw_subdivisions, dict):
        return _extract_maxmind_name(raw_subdivisions)
    return ""


def _extract_maxmind_geo(raw_data: Dict[str, Any]) -> Tuple[str, Optional[str], Optional[str]]:
    """Extracts country code, formatted location string, and coordinates from MMDB data."""
    country_obj = raw_data.get("country") or {}
    country_name = _extract_maxmind_name(country_obj)
    country_code = ""
    if isinstance(country_obj, dict) and isinstance(country_obj.get("iso_code"), str):
        country_code = country_obj["iso_code"].strip().upper()
    if not country_code and raw_data.get("country_code"):
        country_code = str(raw_data["country_code"]).strip().upper()

    subdivision_name = _extract_maxmind_subdivision(raw_data.get("subdivisions") or raw_data.get("subdivision"))
    city_name = _extract_maxmind_name(raw_data.get("city"))

    loc_parts: List[str] = []
    seen_parts = set()
    for part in (city_name, subdivision_name, country_name):
        if part and part.lower() not in seen_parts:
            loc_parts.append(part)
            seen_parts.add(part.lower())

    loc_obj = raw_data.get("location") if isinstance(raw_data.get("location"), dict) else {}
    loc_str, coords = _format_location_with_coords(
        loc_parts,
        loc_obj.get("latitude"),
        loc_obj.get("longitude"),
        reject_blank_coords=True,
        empty_with_coords_prefix="Unknown",
    )
    return loc_str, country_code or None, coords


def _extract_maxmind_signals(
    raw_data: Dict[str, Any],
    *,
    cloud_match: Optional[Dict[str, Any]],
    hosting_match: Optional[Dict[str, Any]],
) -> Tuple[str, List[Dict[str, Any]]]:
    """Derives MaxMind usage type and risk flags using MMDB traits and offline hosting hints."""
    traits = raw_data.get("traits") if isinstance(raw_data.get("traits"), dict) else {}
    # Free GeoLite2 databases omit traits.user_type, so offline cloud CIDR and hosting ASN rules fill the gap
    raw_user_type = traits.get("user_type") or raw_data.get("usage_type") or raw_data.get("user_type")
    usage_type = str(raw_user_type).strip() if isinstance(raw_user_type, str) and raw_user_type.strip() else "unknown"
    usage_lower = usage_type.lower()

    is_hosting = usage_lower in ("hosting", "datacenter", "data center") or bool(traits.get("is_hosting_provider"))
    if usage_lower == "unknown" and (cloud_match is not None or hosting_match is not None):
        is_hosting = True
        usage_type = "hosting"

    flags = _build_risk_flags(
        ("Tor", traits.get("is_tor_exit_node")),
        ("Proxy", traits.get("is_anonymous_proxy") or traits.get("is_public_proxy")),
        ("VPN", traits.get("is_anonymous_vpn")),
        ("Hosting", is_hosting),
    )
    return usage_type, flags


def adapt_maxmind(
    raw_data: Optional[Dict[str, Any]],
    has_db: bool = True,
    status_code: int = 200,
    *,
    ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Normalises combined GeoLite2 and GeoIP2 Country, City, and ASN MMDB records."""
    if not has_db:
        return _build_error_row("MaxMind", status="Database Missing", raw_message="Local MMDB files not found")

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data:
        return _build_error_row("MaxMind", status_code, raw_data)

    asn_val = raw_data.get("autonomous_system_number") or raw_data.get("asn")
    org_name = raw_data.get("autonomous_system_organization") or raw_data.get("as") or raw_data.get("isp") or "-"
    loc_str, country_code, coords = _extract_maxmind_geo(raw_data)

    target_ip = ip if isinstance(ip, str) and ip.strip() else raw_data.get("_ip")
    cloud_match = match_cloud_cidr(target_ip) if target_ip else None
    hosting_match = match_hosting_asn_or_org(asn_val, org_name)
    usage_type, flags = _extract_maxmind_signals(raw_data, cloud_match=cloud_match, hosting_match=hosting_match)

    raw_prefix_val = (
        raw_data.get("_mmdb_prefix_len") if raw_data.get("_mmdb_prefix_len") is not None else raw_data.get("prefix_len")
    )
    prefix_length = _safe_int(raw_prefix_val, default=None)
    if prefix_length is not None and not (0 < prefix_length <= 128):
        prefix_length = None

    internal_keys = ("_mmdb_prefix_len", "_ip", "_offline_db_updated_at")
    clean_raw_json = (
        {k: v for k, v in raw_data.items() if k not in internal_keys}
        if any(k in raw_data for k in internal_keys)
        else raw_data
    )

    extra: Dict[str, Any] = {"countryCode": country_code, "coordinates": coords}
    if prefix_length is not None:
        extra["prefixLength"] = prefix_length
    if cloud_match is not None:
        extra["cloudProvider"] = cloud_match["provider"]
        extra["cloudCidr"] = cloud_match["cidr"]
        extra["cloudPrefixLength"] = cloud_match["prefixLength"]
    if hosting_match is not None:
        extra["hostingProvider"] = hosting_match["provider"]
    offline_updated = raw_data.get("_offline_db_updated_at")
    if isinstance(offline_updated, str) and offline_updated.strip():
        extra["offlineDbUpdatedAt"] = offline_updated.strip()

    return _build_ok_row(
        "MaxMind",
        clean_raw_json,
        asn=_format_asn_str(asn_val),
        isp=org_name,
        location=loc_str,
        usage_type=usage_type,
        security_flags=flags,
        extra=extra,
    )


def adapt_getipintel(
    raw_data: Optional[Dict[str, Any]], has_contact_email: bool, status_code: int = 200
) -> Dict[str, Any]:
    """Normalises GetIPIntel probability scores and assigns confidence-tiered arbitration weights."""
    error_extra = {"chance": None, "residentialProxy": None, "arbitrationWeight": 0.0}
    if not has_contact_email:
        return _build_error_row(
            "GetIPIntel",
            usage_type="ML Prediction",
            raw_message="GETIPINTEL_CONTACT_EMAIL not configured",
            extra=error_extra,
        )

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data:
        return _build_error_row(
            "GetIPIntel",
            status_code,
            raw_data,
            usage_type="ML Prediction",
            extra=error_extra,
        )

    try:
        raw_result = float(raw_data.get("result", -1))
    except ValueError, TypeError:
        raw_result = -1.0
    if not math.isfinite(raw_result):
        raw_result = -1.0

    # GetIPIntel returns HTTP 200 with negative result codes on invalid input or rate limits.
    if raw_result < 0 or str(raw_data.get("status", "")).lower() == "error":
        return _build_error_row(
            "GetIPIntel",
            400,
            raw_data,
            usage_type="ML Prediction",
            extra=error_extra,
        )

    chance = round(raw_result * 100.0, 3)
    residential_proxy: Optional[float] = None
    try:
        raw_residential_proxy = float(raw_data.get("ResidentialProxy", -1))
    except ValueError, TypeError:
        raw_residential_proxy = -1.0
    if math.isfinite(raw_residential_proxy) and 0.0 <= raw_residential_proxy <= 1.0:
        residential_proxy = round(raw_residential_proxy, 4)

    if raw_result >= 0.90:
        arbitration_weight = 1.0
        flags: List[Dict[str, Any]] = [{"label": "High-Probability Proxy/VPN", "isHighRisk": True}]
    elif raw_result >= 0.75:
        arbitration_weight = 0.5
        flags = [{"label": "Moderate Prediction", "isHighRisk": False}]
    elif chance >= 20.0:
        arbitration_weight = 0.0
        flags = [{"label": "Moderate Prediction", "isHighRisk": False}]
    else:
        arbitration_weight = 0.0
        flags = _default_no_flags()

    return _build_ok_row(
        "GetIPIntel",
        raw_data,
        usage_type="ML Prediction",
        security_flags=flags,
        extra={
            "chance": chance,
            "residentialProxy": residential_proxy,
            "arbitrationWeight": arbitration_weight,
        },
    )


def _extract_proxycheck_port(value: Any) -> Optional[int]:
    port_num = _safe_int(value, default=None)
    return port_num if port_num is not None and 1 <= port_num <= 65535 else None


def _proxycheck_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("yes", "true", "1")
    if isinstance(val, (int, float)):
        return val > 0
    return False


def _extract_proxycheck_ip_obj(raw_data: Dict[str, Any], ip: str) -> Dict[str, Any]:
    if ip and isinstance(raw_data.get(ip), dict):
        return raw_data[ip]
    for k, v in raw_data.items():
        if k not in ("status", "message", "query_time") and isinstance(v, dict):
            return v
    return raw_data


def _extract_proxycheck_flags(
    detections: Dict[str, Any],
    ip_obj: Dict[str, Any],
    network: Dict[str, Any],
) -> Tuple[str, List[Dict[str, Any]]]:
    raw_type = network.get("type") or ip_obj.get("type") or detections.get("type") or ""
    type_str = str(raw_type).strip().upper()
    is_hosting = _proxycheck_bool(
        detections.get("hosting", ip_obj.get("hosting", ip_obj.get("is_hosting")))
    ) or type_str in ("HOSTING", "DATACENTER", "DATA CENTER")
    is_proxy = _proxycheck_bool(detections.get("proxy", ip_obj.get("proxy", ip_obj.get("is_proxy")))) or (
        type_str == "PROXY"
    )
    is_tor = _proxycheck_bool(detections.get("tor", ip_obj.get("tor", ip_obj.get("is_tor")))) or type_str == "TOR"
    is_vpn = _proxycheck_bool(detections.get("vpn", ip_obj.get("vpn", ip_obj.get("is_vpn")))) or type_str == "VPN"

    flags = _build_risk_flags(
        ("Proxy", is_proxy),
        ("VPN", is_vpn),
        ("Tor", is_tor),
        ("Hosting", is_hosting),
    )
    usage_type = "hosting" if is_hosting else (str(raw_type).strip().lower() if raw_type else "-")
    return usage_type, flags


def _extract_proxycheck_location(ip_obj: Dict[str, Any]) -> Tuple[str, Optional[str], Optional[str]]:
    loc_obj = ip_obj.get("location") if isinstance(ip_obj.get("location"), dict) else {}
    country_name = ip_obj.get("country") or loc_obj.get("country_name") or ""
    country_code = ip_obj.get("isocode") or ip_obj.get("country_code") or loc_obj.get("country_code") or ""
    city_name = ip_obj.get("city") or loc_obj.get("city") or ""
    coords = _format_coordinates(
        ip_obj.get("latitude") or loc_obj.get("latitude"),
        ip_obj.get("longitude") or loc_obj.get("longitude"),
    )
    loc_parts = [p for p in (city_name, country_name) if p]
    loc_str = ", ".join(loc_parts) if loc_parts else (country_code or "-")
    if coords and loc_str != "-":
        loc_str = f"{loc_str} ({coords})"
    return loc_str, (str(country_code).upper() if country_code else None), coords


def _first_parsed(candidates: Iterable[Any], parser: Any) -> Any:
    for candidate in candidates:
        parsed = parser(candidate)
        if parsed is not None:
            return parsed
    return None


def adapt_proxycheck(
    raw_data: Optional[Dict[str, Any]], has_api_key: bool, status_code: int = 200, ip: str = ""
) -> Dict[str, Any]:
    """Normalises Proxycheck v2 and v3 responses, handling both IP-keyed and flat payloads."""
    extra = {"port": None, "lastSeen": None}
    if not has_api_key:
        return _build_error_row("Proxycheck", raw_message="PROXYCHECK_API_KEY not configured", extra=extra)

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data or str(raw_data.get("status", "")).lower() in ("error", "denied"):
        return _build_error_row("Proxycheck", status_code, raw_data, extra=extra)

    ip_obj = _extract_proxycheck_ip_obj(raw_data, ip)
    detections = ip_obj.get("detections") if isinstance(ip_obj.get("detections"), dict) else {}
    network = ip_obj.get("network") if isinstance(ip_obj.get("network"), dict) else {}
    usage_type, flags = _extract_proxycheck_flags(detections, ip_obj, network)
    loc_str, country_code, coords = _extract_proxycheck_location(ip_obj)

    org_val = (
        ip_obj.get("organisation")
        or ip_obj.get("organization")
        or ip_obj.get("provider")
        or ip_obj.get("isp")
        or network.get("provider")
        or network.get("organisation")
        or network.get("organization")
        or network.get("isp")
        or "-"
    )

    raw_risk = detections.get("risk") if detections.get("risk") is not None else ip_obj.get("risk")
    parsed_risk: Optional[int] = None
    if raw_risk is not None and not isinstance(raw_risk, bool):
        try:
            parsed_risk = max(0, min(100, int(round(float(raw_risk)))))
        except ValueError, TypeError:
            parsed_risk = None

    last_seen_keys = ("lastSeen", "last_seen", "last seen human", "last_seen_human", "last seen", "seen")
    normalized_last_seen = _first_parsed(
        (*(ip_obj.get(k) for k in last_seen_keys), *(detections.get(k) for k in last_seen_keys)),
        _normalize_timestamp_or_text,
    )

    return _build_ok_row(
        "Proxycheck",
        raw_data,
        asn=_format_asn_str(ip_obj.get("asn") or network.get("asn")),
        isp=org_val,
        location=loc_str,
        usage_type=usage_type,
        security_flags=flags,
        extra={
            "riskScore": parsed_risk,
            "port": _first_parsed(
                (detections.get("port"), ip_obj.get("port"), network.get("port")),
                _extract_proxycheck_port,
            ),
            "lastSeen": normalized_last_seen,
            "countryCode": country_code,
            "coordinates": coords,
        },
    )


def adapt_iphub(raw_data: Optional[Dict[str, Any]], has_api_key: bool, status_code: int = 200) -> Dict[str, Any]:
    """Normalises IPHub v2 block classification responses."""
    if not has_api_key:
        return _build_error_row("IPHub", raw_message="IPHUB_API_KEY not configured", extra={"block": None})

    raw_data, status_code = _guard_payload(raw_data, status_code)
    block_val = _safe_int(raw_data.get("block"), default=None) if raw_data else None
    if status_code == 200 and raw_data and "block" in raw_data and block_val is None:
        raw_data = {"status": "error", "message": "Unparseable block value in upstream payload", "payload": raw_data}
        status_code = 502

    if status_code != 200 or not raw_data or "block" not in raw_data:
        return _build_error_row("IPHub", status_code, raw_data, extra={"block": None})

    flags = _build_risk_flags(
        ("Proxy / Hosting (Block 1)", block_val == 1),
        ("Suspicious / Mixed (Block 2)", block_val == 2),
    )
    country_name = raw_data.get("countryName") or ""
    country_code = raw_data.get("countryCode") or ""
    loc_parts = [p for p in (country_name, country_code) if p and p != "ZZ"]

    return _build_ok_row(
        "IPHub",
        raw_data,
        asn=_format_asn_str(raw_data.get("asn")),
        isp=raw_data.get("isp") or raw_data.get("hostname") or "-",
        location=", ".join(loc_parts) if loc_parts else "-",
        usage_type="hosting / proxy" if block_val == 1 else ("mixed" if block_val == 2 else "residential"),
        security_flags=flags,
        extra={
            "block": block_val,
            "countryCode": str(country_code).upper() if country_code and country_code != "ZZ" else None,
        },
    )


def adapt_iphunter(raw_data: Optional[Dict[str, Any]], has_api_key: bool, status_code: int = 200) -> Dict[str, Any]:
    """Normalises IPHunter v1 responses."""
    if not has_api_key:
        return _build_error_row("IPHunter", raw_message="IPHUNTER_API_KEY not configured", extra={"block": None})

    raw_data, status_code = _guard_payload(raw_data, status_code)
    data: Dict[str, Any] = {}
    block_val: Optional[int] = None
    if raw_data:
        data = raw_data.get("data") if isinstance(raw_data.get("data"), dict) else raw_data
        # A missing block keeps the historical residential default, while a null or invalid value fails closed
        block_val = _safe_int(data.get("block", 0), default=None)
        if status_code == 200 and block_val is None:
            raw_data = {
                "status": "error",
                "message": "Unparseable block value in upstream payload",
                "payload": raw_data,
            }
            status_code = 502

    if status_code != 200 or not raw_data or str(raw_data.get("status", "")).lower() == "error":
        return _build_error_row("IPHunter", status_code, raw_data, extra={"block": None})

    flags = _build_risk_flags(
        ("Proxy / Threat (Block 1)", block_val == 1),
        ("Suspicious (Block 2)", block_val == 2),
    )
    country_code = data.get("country_code") or ""
    location, _ = _format_location_with_coords((data.get("city"), data.get("country_name"), country_code))

    return _build_ok_row(
        "IPHunter",
        raw_data,
        asn=_format_asn_str(data.get("asn")),
        isp=data.get("isp") or data.get("domain") or "-",
        location=location,
        usage_type="proxy / hosting" if block_val == 1 else "residential",
        security_flags=flags,
        extra={
            "block": block_val,
            "countryCode": str(country_code).upper() if country_code else None,
        },
    )


_SPAMHAUS_CODE_MAP: Dict[str, Tuple[str, str, bool]] = {
    "127.0.0.2": ("SBL", "Spamhaus SBL", True),
    "127.0.0.3": ("CSS", "Spamhaus CSS", True),
    "127.0.0.4": ("XBL/CBL", "Spamhaus XBL/CBL", True),
    "127.0.0.5": ("XBL/CBL", "Spamhaus XBL/CBL", True),
    "127.0.0.6": ("XBL/CBL", "Spamhaus XBL/CBL", True),
    "127.0.0.7": ("XBL/CBL", "Spamhaus XBL/CBL", True),
    "127.0.0.9": ("SBL DROP/EDROP", "Spamhaus DROP/EDROP", True),
    "127.0.0.10": ("Policy/Dynamic ISP Range (PBL)", "Policy/Dynamic ISP Range (PBL)", False),
    "127.0.0.11": ("Policy/Dynamic ISP Range (PBL)", "Policy/Dynamic ISP Range (PBL)", False),
}


def _extract_dnsbl_codes(raw_data: Dict[str, Any]) -> List[str]:
    raw_codes = raw_data.get("codes")
    if not isinstance(raw_codes, list):
        return []
    seen = set()
    cleaned: List[str] = []
    for item in raw_codes:
        if isinstance(item, str):
            val = item.strip()
            if val and val not in seen:
                seen.add(val)
                cleaned.append(val)
    return cleaned


def _adapt_dnsbl_precheck(
    provider_name: str,
    raw_data: Optional[Dict[str, Any]],
    status_code: int,
) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    guarded, effective_status = _guard_payload(raw_data, status_code)
    payload = guarded if isinstance(guarded, dict) else {}
    state = str(payload.get("status") or "").strip().lower()

    if state == "skipped_ipv6":
        return (
            _build_error_row(
                provider_name,
                None,
                payload,
                status="Skipped (IPv6)",
                usage_type="IPv4 Only (Skipped for IPv6)",
                extra={"isListed": False, "isSkippedIpv6": True, "listedCodes": [], "listedCategories": []},
            ),
            payload,
        )

    if effective_status != 200 or state in ("timeout", "error") or not raw_data:
        if state == "timeout" or effective_status == 504:
            status_text, out_code = "504 Timeout", 504
        elif effective_status == 429:
            status_text, out_code = "429 Rate Limited", 429
        else:
            out_code = effective_status if effective_status != 200 else 502
            status_text = f"{out_code} DNS Error"
        return (
            _build_error_row(
                provider_name,
                out_code,
                payload or None,
                status=status_text,
                raw_message=status_text,
                extra={"isListed": False, "listedCodes": [], "listedCategories": []},
            ),
            payload,
        )

    return None, payload


def _build_clean_dnsbl_row(provider_name: str, raw_data: Dict[str, Any]) -> Dict[str, Any]:
    return _build_ok_row(
        provider_name,
        raw_data,
        usage_type="Clean (Not Listed)",
        extra={"isListed": False, "listedCodes": [], "listedCategories": []},
    )


def adapt_spamhaus_zen(raw_data: Optional[Dict[str, Any]], status_code: int = 200) -> Dict[str, Any]:
    """Normalises Spamhaus ZEN DNSBL A-record responses including SBL, CSS, XBL, PBL, and policy blocks."""
    early_row, payload = _adapt_dnsbl_precheck("Spamhaus ZEN", raw_data, status_code)
    if early_row is not None:
        return early_row

    codes = _extract_dnsbl_codes(payload)
    blocked_codes = [code for code in codes if code.startswith("127.255.255.")]
    if blocked_codes:
        reason_detail = (
            "Public DNS Refused or Rate Limited"
            if any(c in ("127.255.255.254", "127.255.255.255") for c in blocked_codes)
            else "Query Format Error"
        )
        return _build_error_row(
            "Spamhaus ZEN",
            429,
            payload,
            status="429 Query Blocked",
            usage_type=f"Query Restricted ({', '.join(blocked_codes)}: {reason_detail})",
            security_flags=[{"label": "Query Restricted (Unapplied)", "isHighRisk": False}],
            extra={"isListed": False, "isQueryRestricted": True, "listedCodes": [], "listedCategories": []},
        )

    if not codes:
        return _build_clean_dnsbl_row("Spamhaus ZEN", payload)

    flags: List[Dict[str, Any]] = []
    usage_parts: List[str] = []
    categories: List[str] = []
    seen_labels = set()

    for code in codes:
        category, flag_label, is_high_risk = _SPAMHAUS_CODE_MAP.get(
            code,
            (f"Spamhaus Code {code}", f"Spamhaus Listed ({code})", True),
        )
        if category not in categories:
            categories.append(category)
        if code in ("127.0.0.10", "127.0.0.11"):
            usage_parts.append(f"Policy/Dynamic ISP Range (PBL: {code})")
            full_label = flag_label
        else:
            usage_parts.append(f"{category} ({code})")
            full_label = f"{flag_label} ({code})"

        if full_label not in seen_labels:
            seen_labels.add(full_label)
            flags.append({"label": full_label, "isHighRisk": is_high_risk})

    is_only_pbl = all(code in ("127.0.0.10", "127.0.0.11") for code in codes)
    usage_text = ", ".join(usage_parts) if is_only_pbl else f"Listed: {', '.join(usage_parts)}"

    return _build_ok_row(
        "Spamhaus ZEN",
        payload,
        usage_type=usage_text,
        security_flags=flags,
        extra={
            "isListed": True,
            "isPolicyRange": is_only_pbl,
            "listedCodes": codes,
            "listedCategories": categories,
        },
    )


def adapt_spamcop(raw_data: Optional[Dict[str, Any]], status_code: int = 200) -> Dict[str, Any]:
    """Normalises SpamCop DNSBL A-record responses."""
    early_row, payload = _adapt_dnsbl_precheck("SpamCop", raw_data, status_code)
    if early_row is not None:
        return early_row

    codes = _extract_dnsbl_codes(payload)
    if not codes:
        return _build_clean_dnsbl_row("SpamCop", payload)

    return _build_ok_row(
        "SpamCop",
        payload,
        usage_type=f"Listed: Spam Source ({', '.join(codes)})",
        security_flags=[{"label": f"SpamCop Listed ({code})", "isHighRisk": True} for code in codes],
        extra={
            "isListed": True,
            "listedCodes": codes,
            "listedCategories": ["Spam Source"],
        },
    )


def _extract_canonical_ip_from_onionoo_entry(value: Any) -> Optional[str]:
    """Parses a bare IP, bracketed IPv6, or host-and-port endpoint into a compressed IP string."""
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None

    if candidate.startswith("["):
        end_bracket = candidate.find("]")
        if end_bracket <= 1:
            return None
        candidate = candidate[1:end_bracket].strip()

    if "%" in candidate and ":" in candidate:
        candidate = candidate.split("%", 1)[0]

    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        pass

    # IPv4 entries in Onionoo address lists can include a port suffix such as 1.2.3.4:9001.
    if candidate.count(":") == 1 and "." in candidate:
        host_part = candidate.split(":", 1)[0].strip()
        try:
            return ipaddress.ip_address(host_part).compressed
        except ValueError:
            return None

    return None


def _parse_optional_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value == 1:
            return True
        if value == 0:
            return False
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "yes", "1"):
            return True
        if lowered in ("false", "no", "0"):
            return False
    return None


def _match_onionoo_relay(relay: Dict[str, Any], target_ip: Optional[str]) -> Tuple[bool, bool, List[str], bool]:
    or_entries: List[Any] = []
    for list_key in ("a", "or_addresses"):
        candidate_list = relay.get(list_key)
        if isinstance(candidate_list, list):
            or_entries.extend(candidate_list)
    exit_entries = relay.get("exit_addresses") if isinstance(relay.get("exit_addresses"), list) else []

    matched_or = target_ip is not None and any(
        _extract_canonical_ip_from_onionoo_entry(entry) == target_ip for entry in or_entries
    )
    matched_exit = target_ip is not None and any(
        _extract_canonical_ip_from_onionoo_entry(entry) == target_ip for entry in exit_entries
    )
    if not matched_or and not matched_exit:
        return False, False, [], False

    raw_flags = relay.get("flags")
    relay_flags = (
        [f.strip() for f in raw_flags if isinstance(f, str) and f.strip()] if isinstance(raw_flags, list) else []
    )
    running_val = _parse_optional_bool(relay.get("running"))
    if running_val is None:
        running_val = _parse_optional_bool(relay.get("r"))
    if running_val is None:
        running_val = any(f.lower() == "running" for f in relay_flags)
    return True, matched_exit, relay_flags, bool(running_val)


def _merge_unique_onionoo_flags(relay_flags: List[str], seen_flags: set[str], target_flags: List[str]) -> None:
    for flag in relay_flags:
        key = flag.lower()
        if key not in seen_flags:
            seen_flags.add(key)
            target_flags.append(flag)


def _build_onionoo_response(
    raw_data: Dict[str, Any],
    *,
    isp: str,
    usage_type: str,
    security_flags: Optional[List[Dict[str, Any]]] = None,
    is_tor: bool,
    tor_is_exit: bool,
    tor_running: bool,
    tor_flags: List[str],
    tor_label: Optional[str],
    tor_summary: str,
) -> Dict[str, Any]:
    return _build_ok_row(
        "Tor Onionoo",
        raw_data,
        isp=isp,
        usage_type=usage_type,
        security_flags=security_flags,
        extra={
            "isTor": is_tor,
            "torIsExit": tor_is_exit,
            "torRunning": tor_running,
            "torFlags": tor_flags,
            "torLabel": tor_label,
            "torSummary": tor_summary,
        },
    )


def adapt_tor_onionoo(
    raw_data: Optional[Dict[str, Any]],
    status_code: int = 200,
    ip: str = "",
) -> Dict[str, Any]:
    """Normalises Tor Project Onionoo summary responses and verifies exact IP membership across relay addresses."""
    raw_data, status_code = _guard_payload(raw_data, status_code)
    relays = raw_data.get("relays") if isinstance(raw_data, dict) else None
    if status_code != 200 or not raw_data or not isinstance(relays, list):
        if status_code == 200:
            status_code = 502
        return _build_error_row(
            "Tor Onionoo",
            status_code,
            raw_data,
            extra={
                "isTor": False,
                "torIsExit": False,
                "torRunning": False,
                "torFlags": [],
                "torLabel": None,
                "torSummary": None,
            },
        )

    target_ip = _extract_canonical_ip_from_onionoo_entry(ip)
    active_flags: List[str] = []
    seen_active: set[str] = set()
    offline_flags: List[str] = []
    seen_offline: set[str] = set()
    active_matches = 0
    offline_matches = 0
    active_is_exit = False

    for relay in relays:
        if not isinstance(relay, dict):
            continue
        matched, matched_exit, relay_flags, running_val = _match_onionoo_relay(relay, target_ip)
        if not matched:
            continue
        if running_val:
            active_matches += 1
            _merge_unique_onionoo_flags(relay_flags, seen_active, active_flags)
            if matched_exit and "exit" not in seen_active:
                seen_active.add("exit")
                active_flags.append("Exit")
            active_is_exit = active_is_exit or matched_exit or ("exit" in seen_active)
        else:
            offline_matches += 1
            _merge_unique_onionoo_flags(relay_flags, seen_offline, offline_flags)

    if active_matches > 0:
        tor_label = "Tor Exit" if active_is_exit else ("Tor Guard" if "guard" in seen_active else "Tor Node")
        tor_summary = f"{tor_label} (Flags: {', '.join(active_flags)})" if active_flags else f"{tor_label} (Running)"
        return _build_onionoo_response(
            raw_data,
            isp="Tor Network",
            usage_type=tor_summary,
            security_flags=[{"label": tor_label, "isHighRisk": True}],
            is_tor=True,
            tor_is_exit=active_is_exit,
            tor_running=True,
            tor_flags=active_flags,
            tor_label=tor_label,
            tor_summary=tor_summary,
        )

    if offline_matches > 0:
        offline_summary = (
            f"Offline Tor Relay (Flags: {', '.join(offline_flags)})"
            if offline_flags
            else "Offline Tor Relay (Not Running)"
        )
        return _build_onionoo_response(
            raw_data,
            isp="-",
            usage_type=offline_summary,
            is_tor=False,
            tor_is_exit=False,
            tor_running=False,
            tor_flags=offline_flags,
            tor_label=None,
            tor_summary=offline_summary,
        )

    return _build_onionoo_response(
        raw_data,
        isp="-",
        usage_type="Not a Tor Node",
        is_tor=False,
        tor_is_exit=False,
        tor_running=False,
        tor_flags=[],
        tor_label=None,
        tor_summary="Not a Tor Node",
    )


def _extract_sfs_confidence(ip_block: Dict[str, Any], blacklisted: bool, appears: bool) -> Optional[float]:
    raw_conf = ip_block.get("confidence")
    if raw_conf is not None and not isinstance(raw_conf, bool):
        try:
            conf_num = float(raw_conf)
            if math.isfinite(conf_num):
                return round(max(0.0, min(100.0, conf_num)), 2)
        except TypeError, ValueError:
            pass
    if blacklisted:
        return 100.0
    return 0.0 if not appears else None


def _build_sfs_flags_and_usage(
    blacklisted: bool,
    toxic_cidr: Optional[str],
    appears: bool,
    frequency: int,
) -> Tuple[List[Dict[str, Any]], str]:
    toxic_label = f"Blacklisted Toxic CIDR ({toxic_cidr})" if toxic_cidr else "Blacklisted Toxic CIDR"
    flags = _build_risk_flags(
        (toxic_label, blacklisted),
        (f"Forum Spam ({frequency}x)", appears and (frequency > 0 or not blacklisted)),
    )
    if blacklisted and frequency > 0:
        return flags, "Blacklisted Toxic CIDR / Forum Spam Reported"
    if blacklisted:
        return flags, "Blacklisted Toxic CIDR"
    if appears:
        return flags, "Forum Spam Reported"
    return flags, "Clean (Not Listed)"


def adapt_stopforumspam(
    raw_data: Optional[Dict[str, Any]],
    status_code: int = 200,
    *,
    has_db: bool = True,
) -> Dict[str, Any]:
    """Normalises local or API-shaped StopForumSpam IP reputation responses."""
    extra = {
        "appears": False,
        "blacklisted": False,
        "toxicCidr": None,
        "frequency": None,
        "confidence": None,
        "lastSeen": None,
    }
    if not has_db:
        return _build_error_row(
            "StopForumSpam",
            status="Offline DB Missing",
            usage_type="Offline DB Missing",
            raw_data={"status": "unconfigured", "message": "StopForumSpam offline database files not found"},
            extra=extra,
        )

    raw_data, status_code = _guard_payload(raw_data, status_code)
    has_ip_block = isinstance(raw_data, dict) and isinstance(raw_data.get("ip"), dict)
    success_flag = raw_data.get("success") if isinstance(raw_data, dict) else None
    is_explicit_api_error = isinstance(raw_data, dict) and success_flag == 0

    if status_code != 200 or not raw_data or is_explicit_api_error or (success_flag is None and not has_ip_block):
        if status_code == 200:
            status_code = 400 if is_explicit_api_error else 502
        return _build_error_row("StopForumSpam", status_code, raw_data, extra=extra)

    ip_block = raw_data.get("ip") if isinstance(raw_data.get("ip"), dict) else {}
    raw_toxic = ip_block.get("toxicCidr") or ip_block.get("toxic_cidr")
    toxic_cidr = raw_toxic.strip() if isinstance(raw_toxic, str) and raw_toxic.strip() else None
    blacklisted = bool(ip_block.get("blacklisted")) or toxic_cidr is not None

    raw_appears = ip_block.get("appears")
    appears = blacklisted or (
        raw_appears if isinstance(raw_appears, bool) else (_safe_int(raw_appears, default=0) or 0) > 0
    )
    frequency = max(0, _safe_int(ip_block.get("frequency"), default=0) or 0)
    flags, usage_type = _build_sfs_flags_and_usage(blacklisted, toxic_cidr, appears, frequency)

    row_extra: Dict[str, Any] = {
        "appears": appears,
        "blacklisted": blacklisted,
        "toxicCidr": toxic_cidr,
        "frequency": frequency,
        "confidence": _extract_sfs_confidence(ip_block, blacklisted, appears),
        "lastSeen": _normalize_timestamp_or_text(
            ip_block.get("lastseen") or ip_block.get("last_seen") or ip_block.get("lastSeen")
        ),
    }
    offline_updated = raw_data.get("offlineDbUpdatedAt") or ip_block.get("offlineDbUpdatedAt")
    if isinstance(offline_updated, str) and offline_updated.strip():
        row_extra["offlineDbUpdatedAt"] = offline_updated.strip()

    return _build_ok_row(
        "StopForumSpam",
        raw_data,
        asn=_format_asn_str(ip_block.get("asn"), strict_numeric=True),
        usage_type=usage_type,
        security_flags=flags,
        extra=row_extra,
    )


def _extract_dshield_threatfeeds(raw_feeds: Any) -> Tuple[List[str], Optional[str]]:
    """Extracts feed names and any nested last-seen date from DShield threatfeeds structures."""
    names: List[str] = []
    seen_names = set()
    latest_feed_date: Optional[str] = None

    def _add_feed(raw_name: Any, nested_obj: Optional[Dict[str, Any]] = None) -> None:
        nonlocal latest_feed_date
        if isinstance(raw_name, str) and raw_name.strip():
            cleaned = raw_name.strip()
            if cleaned not in seen_names:
                seen_names.add(cleaned)
                names.append(cleaned)
        if isinstance(nested_obj, dict):
            candidate_seen = _normalize_timestamp_or_text(nested_obj.get("lastseen") or nested_obj.get("last_seen"))
            if candidate_seen and (latest_feed_date is None or candidate_seen > latest_feed_date):
                latest_feed_date = candidate_seen

    if isinstance(raw_feeds, dict):
        for feed_key, feed_val in raw_feeds.items():
            _add_feed(feed_key, feed_val if isinstance(feed_val, dict) else None)
    elif isinstance(raw_feeds, list):
        for entry in raw_feeds:
            if isinstance(entry, str):
                _add_feed(entry)
            elif isinstance(entry, dict):
                _add_feed(entry.get("name") or entry.get("feed") or entry.get("type"), entry)

    return names, latest_feed_date


def adapt_dshield(raw_data: Optional[Dict[str, Any]], status_code: int = 200) -> Dict[str, Any]:
    """Normalises DShield and SANS ISC IP threat intelligence responses."""
    raw_data, status_code = _guard_payload(raw_data, status_code)

    ip_block: Optional[Dict[str, Any]] = None
    if isinstance(raw_data, dict):
        if isinstance(raw_data.get("ip"), dict):
            ip_block = raw_data["ip"]
        elif any(k in raw_data for k in ("attacks", "count", "number", "threatfeeds")):
            ip_block = raw_data

    if status_code != 200 or not raw_data or "error" in raw_data or ip_block is None:
        if status_code == 200:
            status_code = 502
        return _build_error_row(
            "DShield",
            status_code,
            raw_data,
            extra={
                "attacks": None,
                "count": None,
                "threatfeeds": [],
                "maxDate": None,
                "lastSeen": None,
            },
        )

    attacks = max(0, _safe_int(ip_block.get("attacks"), default=0) or 0)
    count = max(0, _safe_int(ip_block.get("count"), default=0) or 0)
    threatfeeds, feed_lastseen = _extract_dshield_threatfeeds(ip_block.get("threatfeeds"))

    max_date = _normalize_timestamp_or_text(ip_block.get("maxdate"))
    last_seen = (
        _normalize_timestamp_or_text(ip_block.get("lastseen") or ip_block.get("last_seen"))
        or max_date
        or feed_lastseen
        or _normalize_timestamp_or_text(ip_block.get("updated"))
    )

    has_attacks = attacks > 0 or count > 0
    has_activity = has_attacks or len(threatfeeds) > 0
    flags = _build_risk_flags(
        (f"Attack Activity ({attacks} attacks)", has_attacks),
        (f"Feeds: {', '.join(threatfeeds[:3])}", bool(threatfeeds)),
    )
    usage_type = (
        ("Malicious Activity" if has_attacks else "Threat Feed Listed") if has_activity else "Clean (No Activity)"
    )

    return _build_ok_row(
        "DShield",
        raw_data,
        asn=_format_asn_str(ip_block.get("as") or ip_block.get("asn"), strict_numeric=True),
        isp=str(ip_block.get("asname") or ip_block.get("org") or "-").strip() or "-",
        location=str(ip_block.get("ascountry") or "-").strip() or "-",
        usage_type=usage_type,
        security_flags=flags,
        extra={
            "attacks": attacks,
            "count": count,
            "threatfeeds": threatfeeds,
            "maxDate": max_date,
            "lastSeen": last_seen,
        },
    )


SHODAN_HIGH_RISK_PROXY_PORTS: frozenset[int] = frozenset({1080, 1081, 3128, 8080, 8118, 8888, 9050})
_SHODAN_HIGH_RISK_TAGS: frozenset[str] = frozenset({"proxy", "vpn", "tor", "compromised", "malware", "botnet", "c2"})


def adapt_ipsum_drop(
    raw_data: Optional[Dict[str, Any]],
    status_code: int = 200,
    *,
    has_db: bool = True,
) -> Dict[str, Any]:
    """Normalises offline IPsum multi-blacklist scores and Spamhaus DROP prefix hits."""
    extra: Dict[str, Any] = {
        "isListed": False,
        "ipsumScore": 0,
        "isIpsumListed": False,
        "inSpamhausDrop": False,
        "dropSblId": None,
        "dropCidr": None,
        "matchedCidr": None,
    }
    if not has_db:
        return _build_error_row(
            "IPsum / DROP",
            status="Offline DB Missing",
            usage_type="Offline DB Missing",
            raw_data={"status": "unconfigured", "message": "IPsum and Spamhaus DROP offline index not found"},
            extra=extra,
        )

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data or "error" in raw_data or raw_data.get("status") == "error":
        if status_code == 200:
            status_code = 502
        return _build_error_row("IPsum / DROP", status_code, raw_data, extra=extra)

    in_drop = bool(raw_data.get("inSpamhausDrop"))
    ipsum_score = max(0, _safe_int(raw_data.get("ipsumScore"), default=0) or 0)
    is_ipsum_listed = bool(raw_data.get("isIpsumListed")) or ipsum_score >= 2
    is_listed = in_drop or is_ipsum_listed

    raw_sbl = raw_data.get("dropSblId")
    drop_sbl_id = raw_sbl.strip() if isinstance(raw_sbl, str) and raw_sbl.strip() else None
    raw_drop_cidr = raw_data.get("dropCidr")
    drop_cidr = raw_drop_cidr.strip() if isinstance(raw_drop_cidr, str) and raw_drop_cidr.strip() else None
    raw_matched = raw_data.get("matchedCidr")
    matched_cidr = raw_matched.strip() if isinstance(raw_matched, str) and raw_matched.strip() else None

    flags: List[Dict[str, Any]] = []
    if in_drop:
        drop_label = f"Spamhaus DROP ({drop_sbl_id})" if drop_sbl_id else "Spamhaus DROP"
        flags.append({"label": drop_label, "isHighRisk": True})
    if ipsum_score >= 3:
        flags.append({"label": f"IPsum Threat Feed ({ipsum_score} lists)", "isHighRisk": True})
    elif ipsum_score == 2:
        flags.append({"label": "IPsum Moderate (2 lists)", "isHighRisk": False})

    if in_drop and ipsum_score >= 2:
        usage_type = "Spamhaus DROP / IPsum Listed"
    elif in_drop:
        usage_type = "Spamhaus DROP Listed"
    elif ipsum_score >= 3:
        usage_type = f"IPsum High-Confidence ({ipsum_score} lists)"
    elif ipsum_score == 2:
        usage_type = "IPsum Moderate (2 lists)"
    else:
        usage_type = "Clean (Not Listed)"

    row_extra: Dict[str, Any] = {
        "isListed": is_listed,
        "ipsumScore": ipsum_score,
        "isIpsumListed": is_ipsum_listed,
        "inSpamhausDrop": in_drop,
        "dropSblId": drop_sbl_id,
        "dropCidr": drop_cidr,
        "matchedCidr": matched_cidr,
    }
    offline_updated = raw_data.get("offlineDbUpdatedAt")
    if isinstance(offline_updated, str) and offline_updated.strip():
        row_extra["offlineDbUpdatedAt"] = offline_updated.strip()

    return _build_ok_row(
        "IPsum / DROP",
        raw_data,
        usage_type=usage_type,
        security_flags=flags or _default_no_flags(),
        extra=row_extra,
    )


def adapt_x4bnet_vpn(
    raw_data: Optional[Dict[str, Any]],
    status_code: int = 200,
    *,
    has_db: bool = True,
) -> Dict[str, Any]:
    """Normalises offline X4BNet VPN and hosting CIDR index lookups."""
    extra: Dict[str, Any] = {
        "isListed": False,
        "isVpn": False,
        "isDatacenter": False,
        "isHosting": False,
        "matchedCidr": None,
        "category": None,
        "sources": [],
    }
    if not has_db:
        return _build_error_row(
            "X4BNet VPN",
            status="Offline DB Missing",
            usage_type="Offline DB Missing",
            raw_data={"status": "unconfigured", "message": "X4BNet VPN offline index not found"},
            extra=extra,
        )

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data or "error" in raw_data or raw_data.get("status") == "error":
        if status_code == 200:
            status_code = 502
        return _build_error_row("X4BNet VPN", status_code, raw_data, extra=extra)

    is_vpn = bool(raw_data.get("isVpn"))
    is_datacenter = bool(raw_data.get("isDatacenter"))
    is_hosting = bool(raw_data.get("isHosting")) or is_datacenter
    is_listed = bool(raw_data.get("isListed")) or is_vpn or is_hosting
    raw_matched = raw_data.get("matchedCidr")
    matched_cidr = raw_matched.strip() if isinstance(raw_matched, str) and raw_matched.strip() else None
    raw_sources = raw_data.get("sources")
    sources = (
        [str(src).strip() for src in raw_sources if isinstance(src, str) and str(src).strip()]
        if isinstance(raw_sources, list)
        else []
    )
    category = "vpn" if is_vpn else ("datacenter" if is_datacenter else ("hosting" if is_hosting else None))

    flags: List[Dict[str, Any]] = []
    if is_vpn:
        flags.append({"label": "High-Risk VPN", "isHighRisk": True})
    if is_hosting:
        flags.append({"label": "Hosting / Datacentre", "isHighRisk": False})

    usage_type = (
        "vpn" if is_vpn else ("datacenter" if is_datacenter else ("hosting" if is_hosting else "Clean (Not Listed)"))
    )
    row_extra: Dict[str, Any] = {
        "isListed": is_listed,
        "isVpn": is_vpn,
        "isDatacenter": is_datacenter,
        "isHosting": is_hosting,
        "matchedCidr": matched_cidr,
        "category": category,
        "sources": sources,
    }
    offline_updated = raw_data.get("offlineDbUpdatedAt")
    if isinstance(offline_updated, str) and offline_updated.strip():
        row_extra["offlineDbUpdatedAt"] = offline_updated.strip()

    return _build_ok_row(
        "X4BNet VPN",
        raw_data,
        usage_type=usage_type,
        security_flags=flags or _default_no_flags(),
        extra=row_extra,
    )


def _extract_shodan_ports_and_lists(
    raw_data: Dict[str, Any],
) -> Tuple[List[int], List[int], List[str], List[str]]:
    ports_set: set[int] = set()
    raw_ports = raw_data.get("ports")
    if isinstance(raw_ports, list):
        for item in raw_ports:
            parsed = _safe_int(item, default=None)
            if parsed is not None and 1 <= parsed <= 65535:
                ports_set.add(parsed)
    raw_proxy_ports = raw_data.get("openProxyPorts")
    if isinstance(raw_proxy_ports, list):
        for item in raw_proxy_ports:
            parsed = _safe_int(item, default=None)
            if parsed is not None and parsed in SHODAN_HIGH_RISK_PROXY_PORTS:
                ports_set.add(parsed)

    ports = sorted(ports_set)
    open_proxy_ports = sorted(p for p in ports if p in SHODAN_HIGH_RISK_PROXY_PORTS)

    tags: List[str] = []
    seen_tags: set[str] = set()
    raw_tags = raw_data.get("tags")
    if isinstance(raw_tags, list):
        for tag in raw_tags:
            if isinstance(tag, str) and tag.strip():
                cleaned = tag.strip()
                lowered = cleaned.lower()
                if not lowered.startswith("cve-") and lowered not in seen_tags:
                    seen_tags.add(lowered)
                    tags.append(cleaned)

    hostnames: List[str] = []
    seen_hosts: set[str] = set()
    raw_hosts = raw_data.get("hostnames")
    if isinstance(raw_hosts, list):
        for host in raw_hosts:
            if isinstance(host, str) and host.strip():
                cleaned_host = host.strip().rstrip(".")
                if cleaned_host and cleaned_host.lower() not in seen_hosts:
                    seen_hosts.add(cleaned_host.lower())
                    hostnames.append(cleaned_host)

    return ports, open_proxy_ports, tags, hostnames


def adapt_shodan_internetdb(raw_data: Optional[Dict[str, Any]], status_code: int = 200) -> Dict[str, Any]:
    """Normalises Shodan InternetDB responses, treating HTTP 404 as an empty clean record."""
    empty_extra: Dict[str, Any] = {
        "ports": [],
        "openProxyPorts": [],
        "tags": [],
        "hostnames": [],
    }
    if isinstance(raw_data, dict) and str(raw_data.get("status") or "").strip().lower() == "skipped_ipv6":
        return _build_error_row(
            "Shodan InternetDB",
            None,
            raw_data,
            status="Skipped (IPv6)",
            usage_type="IPv4 Only (Skipped for IPv6)",
            extra={**empty_extra, "isSkippedIpv6": True},
        )

    if status_code == 404:
        clean_raw = (
            raw_data
            if isinstance(raw_data, dict) and raw_data.get("status") != "error" and "error" not in raw_data
            else {"detail": "No information available"}
        )
        return _build_ok_row(
            "Shodan InternetDB",
            clean_raw,
            usage_type="Clean (No Open Ports)",
            extra=dict(empty_extra),
        )

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data or "error" in raw_data or raw_data.get("status") == "error":
        return _build_error_row("Shodan InternetDB", status_code, raw_data, extra=empty_extra)

    ports, open_proxy_ports, tags, hostnames = _extract_shodan_ports_and_lists(raw_data)

    flags: List[Dict[str, Any]] = []
    if open_proxy_ports:
        port_list_text = ", ".join(str(p) for p in open_proxy_ports)
        flags.append({"label": f"Open Proxy Ports ({port_list_text})", "isHighRisk": True})
    for tag in tags:
        if tag.lower() in _SHODAN_HIGH_RISK_TAGS:
            flags.append({"label": f"Shodan Tag: {tag}", "isHighRisk": True})
        else:
            flags.append({"label": f"Shodan Tag: {tag}", "isHighRisk": False})

    if open_proxy_ports:
        usage_type = f"Open Proxy Ports ({', '.join(str(p) for p in open_proxy_ports)})"
    elif tags:
        usage_type = f"Tags: {', '.join(tags[:4])}"
    elif ports:
        usage_type = f"Indexed Ports ({len(ports)})"
    else:
        usage_type = "Clean (No Open Ports)"

    return _build_ok_row(
        "Shodan InternetDB",
        raw_data,
        usage_type=usage_type,
        security_flags=flags or _default_no_flags(),
        extra={
            "ports": ports,
            "openProxyPorts": open_proxy_ports,
            "tags": tags,
            "hostnames": hostnames,
        },
    )


ADAPTER_DISPATCH_TABLE: Dict[str, Any] = {
    "cloudflare_radar": adapt_cloudflare_radar,
    "abuseipdb": adapt_abuseipdb,
    "ipdata": adapt_ipdata,
    "ipregistry": adapt_ipregistry,
    "ip2location": adapt_ip2location,
    "maxmind": adapt_maxmind,
    "getipintel": adapt_getipintel,
    "proxycheck": adapt_proxycheck,
    "iphub": adapt_iphub,
    "iphunter": adapt_iphunter,
    "spamhaus_zen": adapt_spamhaus_zen,
    "spamcop": adapt_spamcop,
    "tor_onionoo": adapt_tor_onionoo,
    "stopforumspam": adapt_stopforumspam,
    "dshield": adapt_dshield,
    "ipsum_drop": adapt_ipsum_drop,
    "x4bnet_vpn": adapt_x4bnet_vpn,
    "shodan_internetdb": adapt_shodan_internetdb,
}


__all__ = [
    "ADAPTER_DISPATCH_TABLE",
    "SHODAN_HIGH_RISK_PROXY_PORTS",
    "_parse_cloud_cidr_payload",
    "_safe_int",
    "adapt_abuseipdb",
    "adapt_cloudflare_radar",
    "adapt_dshield",
    "adapt_getipintel",
    "adapt_ip2location",
    "adapt_ipdata",
    "adapt_iphub",
    "adapt_iphunter",
    "adapt_ipregistry",
    "adapt_ipsum_drop",
    "adapt_maxmind",
    "adapt_proxycheck",
    "adapt_shodan_internetdb",
    "adapt_spamcop",
    "adapt_spamhaus_zen",
    "adapt_stopforumspam",
    "adapt_tor_onionoo",
    "adapt_x4bnet_vpn",
    "are_offline_intelligence_caches_warm",
    "classify_rdns_hostname",
    "clear_offline_intelligence_caches",
    "compute_cidr_attribution",
    "match_cloud_cidr",
    "match_hosting_asn_or_org",
    "parse_cloud_cidr_payload",
    "warm_offline_intelligence_caches",
]
