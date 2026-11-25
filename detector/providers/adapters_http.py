"""Response adapters for external HTTP IP intelligence providers."""

from __future__ import annotations

import ipaddress
import math
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .adapters_common import (
    _build_error_row,
    _build_ok_row,
    _build_risk_flags,
    _default_no_flags,
    _format_asn_str,
    _format_location,
    _guard_payload,
    _normalize_timestamp_or_text,
    _safe_int,
)


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
        ("Datacentre / Hosting", is_datacenter),
    )
    location = _format_location((data.get("countryName"), data.get("countryCode")))

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
        ("Datacentre", threat.get("is_datacenter")),
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

    location = _format_location((raw_data.get("city"), raw_data.get("region"), raw_data.get("country_name")))
    carrier_val = raw_data.get("carrier")
    carrier_candidate = carrier_val.get("name") if isinstance(carrier_val, dict) else carrier_val
    carrier_name = (
        carrier_candidate.strip()
        if isinstance(carrier_candidate, str) and carrier_candidate.strip() not in ("", "-")
        else None
    )
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
    location = _format_location((loc.get("city"), region_obj.get("name"), country_obj.get("name")))

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
        ("Datacentre", proxy_obj.get("is_data_center")),
        ("Threat Detected", proxy_obj.get("is_spammer") or proxy_obj.get("is_scanner") or proxy_obj.get("is_botnet")),
    )

    location = _format_location((raw_data.get("city_name"), raw_data.get("region_name"), raw_data.get("country_name")))
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
        },
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


def _proxycheck_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("yes", "true", "1")
    if isinstance(val, (int, float)):
        return val > 0
    return False


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

    # v2 payloads key the record by IP; v3 and flat payloads expose it directly.
    if ip and isinstance(raw_data.get(ip), dict):
        ip_obj = raw_data[ip]
    else:
        ip_obj = next(
            (v for k, v in raw_data.items() if k not in ("status", "message", "query_time") and isinstance(v, dict)),
            raw_data,
        )
    detections = ip_obj.get("detections") if isinstance(ip_obj.get("detections"), dict) else {}
    network = ip_obj.get("network") if isinstance(ip_obj.get("network"), dict) else {}

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

    loc_obj = ip_obj.get("location") if isinstance(ip_obj.get("location"), dict) else {}
    country_name = ip_obj.get("country") or loc_obj.get("country_name") or ""
    raw_country_code = ip_obj.get("isocode") or ip_obj.get("country_code") or loc_obj.get("country_code") or ""
    loc_str = _format_location((ip_obj.get("city") or loc_obj.get("city") or "", country_name))
    if loc_str == "-" and raw_country_code:
        loc_str = str(raw_country_code)
    country_code = str(raw_country_code).upper() if raw_country_code else None

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
            "port": next(
                (
                    port
                    for port in (
                        _safe_int(v, default=None)
                        for v in (detections.get("port"), ip_obj.get("port"), network.get("port"))
                    )
                    if port is not None and 1 <= port <= 65535
                ),
                None,
            ),
            "lastSeen": normalized_last_seen,
            "countryCode": country_code,
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

    if isinstance(raw_data, dict) and str(raw_data.get("status") or "").strip().lower() == "skipped_ipv6":
        return _build_error_row(
            "IPHunter",
            None,
            raw_data,
            status="Skipped (IPv6)",
            usage_type="IPv4 Only (Skipped for IPv6)",
            extra={"block": None, "isSkippedIpv6": True},
        )

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
    location = _format_location((data.get("city"), data.get("country_name"), country_code))

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
        or_entries: List[Any] = []
        for list_key in ("a", "or_addresses"):
            if isinstance(relay.get(list_key), list):
                or_entries.extend(relay[list_key])
        exit_entries = relay.get("exit_addresses") if isinstance(relay.get("exit_addresses"), list) else []
        matched_or = target_ip is not None and any(
            _extract_canonical_ip_from_onionoo_entry(entry) == target_ip for entry in or_entries
        )
        matched_exit = target_ip is not None and any(
            _extract_canonical_ip_from_onionoo_entry(entry) == target_ip for entry in exit_entries
        )
        if not matched_or and not matched_exit:
            continue

        raw_flags = relay.get("flags")
        relay_flags = (
            [f.strip() for f in raw_flags if isinstance(f, str) and f.strip()] if isinstance(raw_flags, list) else []
        )
        running_val = _parse_optional_bool(relay.get("running"))
        if running_val is None:
            running_val = _parse_optional_bool(relay.get("r"))
        if running_val is None:
            running_val = any(f.lower() == "running" for f in relay_flags)
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

    raw_feeds = ip_block.get("threatfeeds")
    threatfeeds: List[str] = []
    seen_feeds: set[str] = set()
    feed_lastseen: Optional[str] = None
    feed_items: List[Tuple[Any, Optional[Dict[str, Any]]]] = []
    if isinstance(raw_feeds, dict):
        feed_items = [(k, v if isinstance(v, dict) else None) for k, v in raw_feeds.items()]
    elif isinstance(raw_feeds, list):
        for entry in raw_feeds:
            if isinstance(entry, str):
                feed_items.append((entry, None))
            elif isinstance(entry, dict):
                feed_items.append((entry.get("name") or entry.get("feed") or entry.get("type"), entry))
    for raw_name, nested_obj in feed_items:
        if isinstance(raw_name, str) and raw_name.strip():
            cleaned = raw_name.strip()
            if cleaned not in seen_feeds:
                seen_feeds.add(cleaned)
                threatfeeds.append(cleaned)
        if isinstance(nested_obj, dict):
            candidate_seen = _normalize_timestamp_or_text(nested_obj.get("lastseen") or nested_obj.get("last_seen"))
            if candidate_seen and (feed_lastseen is None or candidate_seen > feed_lastseen):
                feed_lastseen = candidate_seen

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

    flags: List[Dict[str, Any]] = []
    if open_proxy_ports:
        port_list_text = ", ".join(str(p) for p in open_proxy_ports)
        flags.append({"label": f"Open Proxy Ports ({port_list_text})", "isHighRisk": True})
    elif ports:
        flags.append({"label": "Open Ports", "isHighRisk": False})
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
