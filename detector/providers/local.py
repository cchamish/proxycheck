"""Local offline database provider queries and response adapters."""

from __future__ import annotations

import asyncio
import logging
import math
import os
import sqlite3
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..core.sanitization import sanitize_error_message
from ..offline import cidr_attribution
from ..offline import mmdb as offline_mmdb
from ..offline.cidr_attribution import match_hosting_asn_or_org
from ..offline.feeds import (
    lookup_shared_cidr_offline,
    query_ipsum_drop_offline,
    query_oxylabs_offline,
)
from ..offline.mmdb import (
    MAXMIND_DB_SPECS,
    evict_maxmind_reader,
    evict_missing_maxmind_readers,
    get_maxmind_newest_mtime_iso,
    get_maxmind_reader,
    query_openasn_offline,
    record_city_db_presence,
)
from ..offline.sfs import query_stopforumspam_offline
from .common import (
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

logger = logging.getLogger("detector.views")


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


def adapt_oxylabs(
    raw_data: Optional[Dict[str, Any]],
    status_code: int = 200,
    *,
    has_db: bool = True,
) -> Dict[str, Any]:
    """Normalises offline Oxylabs residential proxy JSONL lookups."""
    extra: Dict[str, Any] = {
        "isListed": False,
        "residentialProxyProvider": None,
    }
    if not has_db:
        return _build_error_row(
            "Oxylabs",
            status="Offline DB Missing",
            usage_type="Offline DB Missing",
            raw_data={"status": "unconfigured", "message": "Oxylabs offline dataset not found"},
            extra=extra,
        )

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data or "error" in raw_data or raw_data.get("status") == "error":
        if status_code == 200:
            status_code = 502
        return _build_error_row("Oxylabs", status_code, raw_data, extra=extra)

    offline_updated = raw_data.get("offlineDbUpdatedAt")
    offline_updated_text = (
        offline_updated.strip() if isinstance(offline_updated, str) and offline_updated.strip() else None
    )

    if bool(raw_data.get("isListed")):
        raw_org = raw_data.get("orgName")
        isp_text = raw_org.strip() if isinstance(raw_org, str) and raw_org.strip() else "-"
        raw_source = raw_data.get("sourceFile")
        source_file = raw_source.strip() if isinstance(raw_source, str) and raw_source.strip() else None
        row_extra: Dict[str, Any] = {
            "isListed": True,
            "residentialProxyProvider": "Oxylabs",
            "lastSeen": _normalize_timestamp_or_text(raw_data.get("updatedAt")),
            "sourceFile": source_file,
        }
        if offline_updated_text is not None:
            row_extra["offlineDbUpdatedAt"] = offline_updated_text
        return _build_ok_row(
            "Oxylabs",
            raw_data,
            asn=_format_asn_str(raw_data.get("asn"), strict_numeric=True),
            isp=isp_text,
            usage_type="Confirmed Residential Proxy: Oxylabs",
            security_flags=[{"label": "Confirmed Residential Proxy: Oxylabs", "isHighRisk": True}],
            extra=row_extra,
        )

    row_extra = dict(extra)
    if offline_updated_text is not None:
        row_extra["offlineDbUpdatedAt"] = offline_updated_text
    return _build_ok_row(
        "Oxylabs",
        raw_data,
        usage_type="Clean (Not Listed)",
        security_flags=_default_no_flags(),
        extra=row_extra,
    )


async def query_maxmind(ip: str) -> Dict[str, Any]:
    """Reads local GeoLite2 and GeoIP2 Country, City, and ASN MMDB files off the ASGI event loop."""

    def _run() -> Dict[str, Any]:
        if not cidr_attribution.are_offline_intelligence_caches_warm():
            cidr_attribution.warm_offline_intelligence_caches()

        db_paths = offline_mmdb.resolve_maxmind_db_paths()
        available_paths = {key: path for key, path in db_paths.items() if os.path.exists(path)}

        for key, filename in MAXMIND_DB_SPECS:
            if key not in available_paths:
                evict_missing_maxmind_readers(filename, db_paths[key])

        if not available_paths:
            return adapt_maxmind(None, has_db=False)

        city_path = db_paths["city"]
        if record_city_db_presence(city_path, is_present="city" in available_paths):
            logger.warning("GeoLite2-City.mmdb was not found at %s; MaxMind lookups will omit city", city_path)

        try:
            import maxminddb
        except ImportError:
            logger.warning("maxminddb package not installed; returning Database Missing fallback")
            return adapt_maxmind(None, has_db=False)

        try:
            records: Dict[str, Optional[Dict[str, Any]]] = {}
            prefix_lens: Dict[str, Optional[int]] = {}
            for key, path in available_paths.items():
                reader = get_maxmind_reader(path, maxminddb)
                rec: Optional[Dict[str, Any]] = None
                prefix_len: Optional[int] = None
                getter = getattr(reader, "get_with_prefix_len", None)
                if callable(getter):
                    try:
                        res = getter(ip)
                    except AttributeError, NotImplementedError:
                        res = None
                    if (
                        isinstance(res, tuple)
                        and len(res) == 2
                        and (res[0] is None or isinstance(res[0], dict))
                        and isinstance(res[1], int)
                        and not isinstance(res[1], bool)
                    ):
                        rec = res[0] if isinstance(res[0], dict) else None
                        prefix_len = res[1]
                    else:
                        raw = reader.get(ip)
                        rec = raw if isinstance(raw, dict) else None
                else:
                    raw = reader.get(ip)
                    rec = raw if isinstance(raw, dict) else None
                records[key] = rec
                prefix_lens[key] = prefix_len

            # Combine City, Country (keeping Country iso_code authoritative), and ASN records.
            combined_record: Dict[str, Any] = {}
            if isinstance(records.get("city"), dict):
                combined_record.update({k: v for k, v in records["city"].items() if v is not None})
            if isinstance(records.get("country"), dict):
                for key, value in records["country"].items():
                    if key in ("country", "registered_country", "represented_country", "continent", "traits"):
                        existing = combined_record.get(key)
                        if isinstance(existing, dict) and isinstance(value, dict):
                            merged = dict(existing)
                            for sub_key, sub_val in value.items():
                                if (
                                    sub_key == "names"
                                    and isinstance(merged.get("names"), dict)
                                    and isinstance(sub_val, dict)
                                ):
                                    merged["names"] = {**merged["names"], **sub_val}
                                elif sub_val is not None:
                                    merged[sub_key] = sub_val
                            combined_record[key] = merged
                        elif value is not None:
                            combined_record[key] = value
                    elif key not in combined_record and value is not None:
                        combined_record[key] = value
            if isinstance(records.get("asn"), dict):
                combined_record.update({k: v for k, v in records["asn"].items() if v is not None})

            resolved_prefix_len = next(
                (prefix_lens.get(key) for key in ("asn", "country", "city") if prefix_lens.get(key) is not None),
                None,
            )
            if resolved_prefix_len is not None:
                combined_record["_mmdb_prefix_len"] = resolved_prefix_len
            offline_updated_at = get_maxmind_newest_mtime_iso()
            if offline_updated_at:
                combined_record["_offline_db_updated_at"] = offline_updated_at

            return adapt_maxmind(combined_record, has_db=True, status_code=200, ip=ip)
        except (OSError, ValueError, RuntimeError) as exc:
            for path in db_paths.values():
                evict_maxmind_reader(path)
            safe_message = sanitize_error_message(str(exc))
            logger.error("Error querying MaxMind local database: %s", safe_message)
            return adapt_maxmind({"error": safe_message}, has_db=True, status_code=500)

    return await asyncio.to_thread(_run)


async def _run_offline_provider(
    ip: str,
    lookup_fn: Callable[[str], Dict[str, Any]],
    adapt_fn: Callable[..., Dict[str, Any]],
    *,
    error_label: str,
    extra_exceptions: Tuple[type[BaseException], ...] = (),
    payload_builder: Optional[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = None,
    error_payload_builder: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Runs a synchronous local offline lookup off the event loop and adapts its response."""

    def _run() -> Dict[str, Any]:
        try:
            lookup = lookup_fn(ip)
        except (OSError, ValueError, RuntimeError, *extra_exceptions) as exc:
            safe_message = sanitize_error_message(str(exc))
            logger.error("Error querying %s: %s", error_label, safe_message)
            err_payload = (
                error_payload_builder(safe_message)
                if error_payload_builder is not None
                else {"status": "error", "error": safe_message}
            )
            return adapt_fn(err_payload, status_code=500, has_db=True)
        if not lookup.get("has_db"):
            return adapt_fn(None, has_db=False)
        payload = payload_builder(ip, lookup) if payload_builder is not None else lookup
        return adapt_fn(payload, status_code=200, has_db=True)

    return await asyncio.to_thread(_run)


def _build_stopforumspam_payload(ip: str, lookup: Dict[str, Any]) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "success": 1,
        "ip": {
            "ip": ip,
            "appears": 1 if lookup.get("appears") else 0,
            "frequency": int(lookup.get("frequency") or 0),
            "lastseen": lookup.get("last_seen"),
            "blacklisted": bool(lookup.get("blacklisted")),
            "toxicCidr": lookup.get("toxic_cidr"),
            "sources": lookup.get("sources") or [],
        },
    }
    if lookup.get("offline_db_updated_at"):
        payload["offlineDbUpdatedAt"] = lookup["offline_db_updated_at"]
    return payload


async def query_stopforumspam(ip: str) -> Dict[str, Any]:
    return await _run_offline_provider(
        ip,
        query_stopforumspam_offline,
        adapt_stopforumspam,
        error_label="StopForumSpam offline database",
        extra_exceptions=(sqlite3.Error,),
        payload_builder=_build_stopforumspam_payload,
        error_payload_builder=lambda msg: {"success": 0, "error": msg},
    )


async def query_ipsum_drop(ip: str) -> Dict[str, Any]:
    return await _run_offline_provider(
        ip,
        query_ipsum_drop_offline,
        adapt_ipsum_drop,
        error_label="IPsum and Spamhaus DROP offline index",
    )


async def query_openasn(ip: str) -> Dict[str, Any]:
    return await _run_offline_provider(
        ip,
        query_openasn_offline,
        adapt_openasn,
        error_label="OpenASN offline database",
    )


async def query_oxylabs(ip: str) -> Dict[str, Any]:
    return await _run_offline_provider(
        ip,
        query_oxylabs_offline,
        adapt_oxylabs,
        error_label="Oxylabs offline dataset",
    )
