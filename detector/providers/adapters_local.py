"""Response adapters for offline local databases and DNSBL lookups."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

from ..offline import lookup_shared_cidr_offline
from ..offline.cidr_attribution import match_hosting_asn_or_org
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

    country_obj = raw_data.get("country") or {}
    country_name = _extract_maxmind_name(country_obj)
    country_code = ""
    if isinstance(country_obj, dict) and isinstance(country_obj.get("iso_code"), str):
        country_code = country_obj["iso_code"].strip().upper()
    if not country_code and raw_data.get("country_code"):
        country_code = str(raw_data["country_code"]).strip().upper()

    raw_subdivisions = raw_data.get("subdivisions") or raw_data.get("subdivision")
    subdivision_name = ""
    if isinstance(raw_subdivisions, (list, tuple)):
        for entry in raw_subdivisions:
            iso_code = entry.get("iso_code") if isinstance(entry, dict) else None
            subdivision_name = _extract_maxmind_name(entry) or (
                iso_code.strip() if isinstance(iso_code, str) and iso_code.strip() else ""
            )
            if subdivision_name:
                break
    elif isinstance(raw_subdivisions, dict):
        subdivision_name = _extract_maxmind_name(raw_subdivisions)

    loc_parts: List[str] = []
    seen_parts = set()
    for part in (_extract_maxmind_name(raw_data.get("city")), subdivision_name, country_name):
        if part and part.lower() not in seen_parts:
            loc_parts.append(part)
            seen_parts.add(part.lower())
    loc_str = _format_location(loc_parts)

    target_ip = ip if isinstance(ip, str) and ip.strip() else raw_data.get("_ip")
    shared_hit = lookup_shared_cidr_offline(target_ip) if target_ip else None
    hosting_match = match_hosting_asn_or_org(asn_val, org_name)

    traits = raw_data.get("traits") if isinstance(raw_data.get("traits"), dict) else {}
    # Free GeoLite2 databases omit traits.user_type, so offline cloud CIDR and hosting ASN rules fill the gap.
    raw_user_type = traits.get("user_type") or raw_data.get("usage_type") or raw_data.get("user_type")
    usage_type = str(raw_user_type).strip() if isinstance(raw_user_type, str) and raw_user_type.strip() else "unknown"
    usage_lower = usage_type.lower()
    is_hosting = usage_lower in ("hosting", "datacenter", "data center") or bool(traits.get("is_hosting_provider"))
    has_cloud_hint = shared_hit is not None and shared_hit.get("category") in ("cloud", "vpn")
    if usage_lower == "unknown" and (has_cloud_hint or hosting_match is not None):
        is_hosting = True
        usage_type = "hosting"
    flags = _build_risk_flags(
        ("Tor", traits.get("is_tor_exit_node")),
        ("Proxy", traits.get("is_anonymous_proxy") or traits.get("is_public_proxy")),
        ("VPN", traits.get("is_anonymous_vpn")),
        ("Hosting", is_hosting),
    )

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

    extra: Dict[str, Any] = {"countryCode": country_code or None}
    if prefix_length is not None:
        extra["prefixLength"] = prefix_length
    if shared_hit is not None:
        extra["sharedProvider"] = shared_hit["provider"]
        extra["sharedCidr"] = shared_hit["cidr"]
        extra["sharedCategory"] = shared_hit["category"]
        extra["sharedPrefixLength"] = shared_hit["prefixLength"]
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
    flags = _build_risk_flags(
        (f"Blacklisted Toxic CIDR ({toxic_cidr})" if toxic_cidr else "Blacklisted Toxic CIDR", blacklisted),
        (f"Forum Spam ({frequency}x)", appears and (frequency > 0 or not blacklisted)),
    )
    if blacklisted and frequency > 0:
        usage_type = "Blacklisted Toxic CIDR / Forum Spam Reported"
    elif blacklisted:
        usage_type = "Blacklisted Toxic CIDR"
    elif appears:
        usage_type = "Forum Spam Reported"
    else:
        usage_type = "Clean (Not Listed)"

    confidence: Optional[float] = 100.0 if blacklisted else (0.0 if not appears else None)
    raw_conf = ip_block.get("confidence")
    if raw_conf is not None and not isinstance(raw_conf, bool):
        try:
            conf_num = float(raw_conf)
            if math.isfinite(conf_num):
                confidence = round(max(0.0, min(100.0, conf_num)), 2)
        except TypeError, ValueError:
            pass

    row_extra: Dict[str, Any] = {
        "appears": appears,
        "blacklisted": blacklisted,
        "toxicCidr": toxic_cidr,
        "frequency": frequency,
        "confidence": confidence,
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


def adapt_openasn(
    raw_data: Optional[Dict[str, Any]],
    status_code: int = 200,
    *,
    has_db: bool = True,
) -> Dict[str, Any]:
    """Normalises offline OpenASN MMDB classification lookups without treating bad_asn as malicious."""
    extra: Dict[str, Any] = {
        "coreVerdict": "unknown",
        "coreSources": [],
        "category": None,
        "networkRole": None,
        "isVpn": False,
        "isHosting": False,
        "isDatacenter": False,
        "isCdn": False,
        "isMobile": False,
        "isEnterpriseGateway": False,
        "isBadAsn": False,
        "lookupStatus": "unrouted",
    }
    if not has_db:
        return _build_error_row(
            "OpenASN",
            status="Offline DB Missing",
            usage_type="Offline DB Missing",
            raw_data={"status": "unconfigured", "message": "OpenASN offline database not found"},
            extra=extra,
        )

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data or "error" in raw_data or raw_data.get("status") == "error":
        if status_code == 200:
            status_code = 502
        return _build_error_row("OpenASN", status_code, raw_data, extra=extra)

    verdict = raw_data.get("coreVerdict")
    core_verdict = verdict if isinstance(verdict, str) and verdict else "unknown"
    is_cdn = bool(raw_data.get("cdn"))
    is_datacenter = bool(raw_data.get("datacenterRange"))
    is_pure_cdn = core_verdict == "hosting" and is_cdn and not is_datacenter
    is_hosting = core_verdict == "hosting" and not is_pure_cdn
    is_mobile = core_verdict == "mobile"
    raw_sources = raw_data.get("coreSources")
    raw_asn = raw_data.get("asn")
    as_org = raw_data.get("asOrg")
    org_text = as_org if isinstance(as_org, str) and as_org else "-"

    row_extra: Dict[str, Any] = {
        "coreVerdict": core_verdict,
        "coreSources": [s for s in raw_sources if isinstance(s, str) and s] if isinstance(raw_sources, list) else [],
        "category": raw_data.get("category"),
        "networkRole": raw_data.get("networkRole"),
        "isVpn": core_verdict == "vpn",
        "isHosting": is_hosting,
        "isDatacenter": is_datacenter,
        "isCdn": is_cdn,
        "isMobile": is_mobile,
        "isEnterpriseGateway": core_verdict == "enterprise_gateway",
        "isBadAsn": bool(raw_data.get("badAsn")),
        "lookupStatus": raw_data.get("lookupStatus") or "unrouted",
    }
    offline_updated = raw_data.get("offlineDbUpdatedAt")
    if isinstance(offline_updated, str) and offline_updated.strip():
        row_extra["offlineDbUpdatedAt"] = offline_updated.strip()

    flags = [
        {"label": label, "isHighRisk": label == "VPN"}
        for label, active in (
            ("VPN", core_verdict == "vpn"),
            ("Enterprise Gateway", core_verdict == "enterprise_gateway"),
            ("CDN", is_pure_cdn),
            ("Hosting / Datacentre", is_hosting),
            ("Mobile Carrier", is_mobile),
        )
        if active
    ]
    asn_text = f"AS{raw_asn}" if isinstance(raw_asn, int) and not isinstance(raw_asn, bool) else "-"
    return _build_ok_row(
        "OpenASN",
        raw_data,
        asn=asn_text,
        isp=org_text,
        usage_type="cdn" if is_pure_cdn else core_verdict,
        security_flags=flags or _default_no_flags(),
        extra=row_extra,
    )
