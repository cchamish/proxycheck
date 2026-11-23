"""
IP canonicalisation, non-public IP classification, process memory diagnostics,
and multi-source intelligence aggregation and arbitration.
"""

import ipaddress
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .cidr_attribution import classify_rdns_hostname, compute_cidr_attribution
from .provider_registry import COMMERCIAL_ARBITRATION_PROVIDERS

_PROC_RSS_CACHE_TTL_SECONDS = 1.0
_proc_rss_lock = threading.Lock()
_proc_rss_cache: Optional[Tuple[float, float]] = None


def clear_proc_rss_cache() -> None:
    """Clears the short-lived process RSS diagnostic cache."""
    global _proc_rss_cache
    with _proc_rss_lock:
        _proc_rss_cache = None


def get_process_memory_mb() -> Optional[float]:
    """Returns current worker RSS in megabytes, falling back to peak RSS when procfs is unavailable."""
    global _proc_rss_cache

    now_mono = time.monotonic()
    with _proc_rss_lock:
        cached = _proc_rss_cache
    if cached is not None and 0.0 <= (now_mono - cached[0]) < _PROC_RSS_CACHE_TTL_SECONDS:
        return cached[1]

    try:
        with open("/proc/self/statm", encoding="ascii") as statm_file:
            fields = statm_file.read().split()
        if len(fields) >= 2:
            rss_pages = int(fields[1])
            page_size = os.sysconf("SC_PAGESIZE")
            if rss_pages >= 0 and page_size > 0:
                rss_mb = round((rss_pages * page_size) / (1024.0 * 1024.0), 2)
                with _proc_rss_lock:
                    _proc_rss_cache = (now_mono, rss_mb)
                return rss_mb
    except OSError, AttributeError, ValueError, TypeError:
        pass

    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(usage / 1024.0, 2)
    except ImportError, OSError, AttributeError:
        return None


def attach_request_diagnostics(
    payload: Dict[str, Any],
    start_time: float,
    *,
    include_memory: bool = True,
) -> Dict[str, Any]:
    """Returns a copy of payload annotated with execution duration and optional worker RSS memory."""
    annotated = {
        **payload,
        "durationSeconds": round(time.perf_counter() - start_time, 3),
    }
    if include_memory:
        annotated["memoryMb"] = get_process_memory_mb()
    return annotated


def strip_raw_json_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Returns a shallow copy of payload without rawJson keys on provider result rows."""
    if isinstance(payload, dict) and isinstance(payload.get("results"), list):
        return {
            **payload,
            "results": [
                {k: v for k, v in row.items() if k != "rawJson"} if isinstance(row, dict) else row
                for row in payload["results"]
            ],
        }
    return payload


def parse_compact_flag(raw_value: Any) -> bool:
    """Interprets boolean, integer, or string compact flags."""
    if isinstance(raw_value, bool):
        return raw_value
    if isinstance(raw_value, int):
        return raw_value == 1
    if isinstance(raw_value, str):
        return raw_value.strip().lower() in ("1", "true", "yes")
    return False


def normalize_query_mode(raw_mode: Any, *, default: str = "full") -> str:
    """Normalises the requested detection mode to either light or full."""
    fallback = "light" if default == "light" else "full"
    cleaned = str(raw_mode or "").strip().lower()
    if cleaned in ("light", "full"):
        return cleaned
    return fallback


MAX_BATCH_IPS = 25
_MAX_RAW_BATCH_IPS = 50


def parse_batch_ip_list(raw_ips: Any) -> Tuple[Optional[Tuple[List[str], Dict[str, str]]], Optional[str]]:
    """Validates and deduplicates a raw batch IP list, returning either (unique_ips, input_map) or an error message."""
    if not isinstance(raw_ips, list) or not raw_ips:
        return None, "The ips parameter must be a non-empty array of IP addresses."

    if len(raw_ips) > _MAX_RAW_BATCH_IPS:
        return None, f"Batch request exceeds maximum allowed raw entries ({_MAX_RAW_BATCH_IPS})."

    unique_canonical_ips: List[str] = []
    seen_canonical: Set[str] = set()
    input_map: Dict[str, str] = {}

    for item in raw_ips:
        if not isinstance(item, str) or not item.strip():
            return None, "Each entry in ips must be a non-empty IP address string."
        canonical = canonicalize_ip(item)
        if not canonical:
            return None, f"Invalid IP address format: {item.strip()[:64]}"
        input_map[item] = canonical
        stripped_item = item.strip()
        if stripped_item != item:
            input_map[stripped_item] = canonical
        if canonical not in seen_canonical:
            seen_canonical.add(canonical)
            unique_canonical_ips.append(canonical)

    if len(unique_canonical_ips) > MAX_BATCH_IPS:
        return None, f"Batch request exceeds maximum of {MAX_BATCH_IPS} unique IP addresses."
    return (unique_canonical_ips, input_map), None


def canonicalize_ip(raw_ip: str) -> Optional[str]:
    """Returns the canonical compressed IPv4 or IPv6 address string, or None when invalid."""
    if not isinstance(raw_ip, str):
        return None
    stripped = raw_ip.strip()
    if not stripped:
        return None
    if ":" in stripped and "%" in stripped:
        addr_part, zone_id = stripped.split("%", 1)
        if not zone_id or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 or ch in "%/" for ch in zone_id):
            return None
        stripped = addr_part
    try:
        return ipaddress.ip_address(stripped).compressed
    except ValueError:
        return None


_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")
_DOC_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def classify_non_public_ip(canonical_ip: str) -> Optional[Tuple[str, str]]:
    """
    Returns (category_key, description) when an IP is non-public or reserved,
    or None when the address is globally routable unicast.
    """
    ip_obj = ipaddress.ip_address(canonical_ip)
    target = getattr(ip_obj, "ipv4_mapped", None) or ip_obj

    is_non_public = not ip_obj.is_global or ip_obj.is_multicast or not target.is_global or target.is_multicast
    if not is_non_public:
        return None

    if target.is_loopback:
        return "loopback", "Loopback Address"
    if target.is_link_local:
        return "link_local", "Link-Local Address"
    if target.is_multicast:
        return "multicast", "Multicast Address"
    if target.is_unspecified:
        return "unspecified", "Unspecified Address"
    if target.version == 4 and target in _CGNAT_NETWORK:
        return "shared_cgnat", "Shared Address Space (CGNAT)"
    if any(target.version == net.version and target in net for net in _DOC_NETWORKS):
        return "documentation", "Documentation Reserved Address"
    if target.is_private:
        return "private", "Private Network Address"
    if target.is_reserved:
        return "reserved", "Reserved Address"
    return "non_public", "Non-Public / Reserved Address"


def build_non_public_response_payload(
    ip: str,
    category: str,
    reason: str,
    start_time: float,
    *,
    query_mode: str = "full",
) -> Dict[str, Any]:
    """Builds a standard HTTP 200 payload for non-public or reserved IP addresses without external lookups."""
    normalized_mode = normalize_query_mode(query_mode)
    payload = {
        "ip": ip,
        "isNonPublic": True,
        "nonPublicCategory": category,
        "nonPublicReason": reason,
        "queryMode": normalized_mode,
        "isPartialMode": False,
        "is_broadcast_ip": False,
        "isTor": False,
        "torIsExit": False,
        "torRunning": False,
        "torFlags": [],
        "torLabel": None,
        "torSummary": None,
        "prediction_score": 0.0,
        "predictionLabel": f"Non-Public ({reason})",
        "predictionTier": "neutral",
        "getipintel_chance": None,
        "arbitrationVerdict": f"Non-Public / Reserved IP ({reason})",
        "arbitrationTier": "neutral",
        "isMajorityProxyVpn": False,
        "primaryCountry": reason,
        "primaryAsn": "-",
        "ptrHostname": None,
        "ptrCategory": "none",
        "ptrLabel": "Skipped (Non-Public IP)",
        "ptrIsHighRisk": False,
        "recommendedCidr": None,
        "defaultCidr": None,
        "mmdbCidr": None,
        "sharedCidr": None,
        "sharedProvider": None,
        "sharedCategory": None,
        "cidrNote": f"External lookups skipped for {reason.lower()}",
        "bgpPrefix": None,
        "escalationCidr": None,
        "cidrRationale": f"External lookups skipped for {reason.lower()}",
        "isMobileOrCgnat": category == "shared_cgnat",
        "sharedPrivacyEgress": None,
        "suspectedResidentialProxy": False,
        "fetchedAt": None,
        "results": [],
        "isCached": False,
        "cacheMeta": {
            "status": "bypassed",
            "layer": "bypassed",
            "isPartial": False,
            "hitCount": 0,
            "missCount": 0,
            "cooldownCount": 0,
            "totalSources": 0,
            "cachedAt": None,
            "fetchedAt": None,
            "ageSeconds": 0,
            "staleThresholdSeconds": 0,
            "isStale": False,
            "shouldAutoRefresh": False,
            "refreshInProgress": False,
            "degradedRefreshFallback": False,
            "recommendFreshRecheck": False,
            "hitProviders": [],
            "missedProviders": [],
        },
    }
    return attach_request_diagnostics(payload, start_time)


_HOSTING_KEYWORDS = ("datacenter", "data center", "hosting", "cloud", "transit", "cdn")
_RESIDENTIAL_KEYWORDS = ("isp", "residential", "fixed line", "mobile", "commercial", "education")
_ANONYMISER_KEYWORDS = ("proxy", "vpn", "tor", "relay", "abuser", "attacker", "threat", "block 1", "spam", "botnet")
_SHODAN_PARADOX_TAGS = frozenset({"proxy", "vpn", "compromised"})
_RECENT_ACTIVITY_WINDOW_SECONDS = 30 * 86400


def _is_recent_or_undated(raw_value: Any) -> bool:
    """Treats missing or unparseable timestamps as recent so undated listings still count."""
    if not isinstance(raw_value, str) or not raw_value.strip():
        return True
    cleaned = raw_value.strip()
    if cleaned.endswith("Z"):
        cleaned = f"{cleaned[:-1]}+00:00"
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            parsed = datetime.fromisoformat(cleaned) if fmt is None else datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - parsed).total_seconds() <= _RECENT_ACTIVITY_WINDOW_SECONDS
    return True


def _as_int(raw_value: Any) -> int:
    return int(raw_value) if isinstance(raw_value, int) and not isinstance(raw_value, bool) else 0


@dataclass
class _ArbitrationSignals:
    comparison_results: List[Dict[str, Any]] = field(default_factory=list)
    is_tor: bool = False
    tor_is_exit: bool = False
    tor_running: bool = False
    tor_flags: List[str] = field(default_factory=list)
    tor_label: Optional[str] = None
    tor_summary: Optional[str] = None
    country_codes: Set[str] = field(default_factory=set)
    asns: List[str] = field(default_factory=list)
    orgs: List[str] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)
    getipintel_chance: Optional[float] = None
    residential_proxy: Optional[float] = None
    mmdb_prefix_len: Optional[int] = None
    shared_cidr: Optional[str] = None
    shared_provider: Optional[str] = None
    shared_category: Optional[str] = None
    proxy_vpn_votes: float = 0.0
    commercial_responses: int = 0
    hosting_source_count: int = 0
    behavioural_threat_votes: int = 0
    residential_source_count: int = 0
    has_hosting: bool = False
    has_anonymiser_flag: bool = False
    has_shodan_proxy_ports: bool = False
    has_shodan_paradox_tag: bool = False
    max_ipsum_score: int = 0
    has_spamhaus_listing: bool = False
    has_recent_sfs_activity: bool = False
    has_recent_dshield_activity: bool = False
    has_high_abuseipdb: bool = False


def _collect_arbitration_signals(rows: List[Dict[str, Any]]) -> _ArbitrationSignals:  # noqa: C901
    """Scans provider rows once and tallies every network, Tor, commercial, and OSINT arbitration signal."""
    sig = _ArbitrationSignals()

    for row in rows:
        provider = row.get("provider")
        # Tor Onionoo only feeds the overview Tor fields, never the comparison panel.
        if provider == "Tor Onionoo":
            sig.is_tor = row.get("status") == "200 OK" and bool(row.get("isTor"))
            sig.tor_is_exit = sig.is_tor and bool(row.get("torIsExit"))
            sig.tor_running = sig.is_tor and bool(row.get("torRunning"))
            raw_tor_flags = row.get("torFlags")
            sig.tor_flags = (
                [str(f) for f in raw_tor_flags if f] if sig.is_tor and isinstance(raw_tor_flags, list) else []
            )
            sig.tor_label = (
                str(row.get("torLabel") or ("Tor Exit" if sig.tor_is_exit else "Tor Node")) if sig.is_tor else None
            )
            sig.tor_summary = str(row["torSummary"]) if sig.is_tor and row.get("torSummary") else None
            continue

        sig.comparison_results.append(row)
        if row.get("status") != "200 OK":
            continue

        c_code = row.get("countryCode")
        if isinstance(c_code, str):
            c_code = c_code.strip().upper()
            if len(c_code) == 2 and c_code.isalpha():
                sig.country_codes.add(c_code)
        asn_val = row.get("asn")
        if asn_val and asn_val != "-" and str(asn_val).startswith("AS"):
            sig.asns.append(str(asn_val))
        org_val = row.get("organisation") or row.get("isp")
        if isinstance(org_val, str) and org_val.strip() and org_val.strip() != "-":
            sig.orgs.append(org_val.strip())
        loc_val = row.get("location")
        if loc_val and loc_val != "-":
            sig.locations.append(loc_val)

        flags = row.get("securityFlags") or []

        if provider == "GetIPIntel":
            chance_val = row.get("chance")
            if isinstance(chance_val, (int, float)):
                sig.getipintel_chance = round(float(chance_val), 3)
            residential_proxy = row.get("residentialProxy")
            if isinstance(residential_proxy, (int, float)) and not isinstance(residential_proxy, bool):
                sig.residential_proxy = round(float(residential_proxy), 4)

        if provider == "MaxMind":
            candidate_len = row.get("prefixLength")
            if candidate_len is None and isinstance(row.get("rawJson"), dict):
                candidate_len = row["rawJson"].get("prefix_len")
            if not isinstance(candidate_len, bool) and isinstance(candidate_len, int):
                sig.mmdb_prefix_len = candidate_len
            raw_shared_cidr = row.get("sharedCidr") or row.get("cloudCidr")
            if isinstance(raw_shared_cidr, str) and raw_shared_cidr:
                sig.shared_cidr = raw_shared_cidr
            raw_shared_provider = row.get("sharedProvider") or row.get("cloudProvider")
            if isinstance(raw_shared_provider, str) and raw_shared_provider:
                sig.shared_provider = raw_shared_provider
            raw_shared_category = row.get("sharedCategory") or ("cloud" if row.get("cloudProvider") else None)
            if isinstance(raw_shared_category, str) and raw_shared_category:
                sig.shared_category = raw_shared_category

        if provider == "AbuseIPDB":
            raw_abuse = row.get("abuseConfidenceScore")
            if (
                isinstance(raw_abuse, (int, float)) and not isinstance(raw_abuse, bool) and float(raw_abuse) >= 25.0
            ) or any(f.get("isHighRisk") and "abuse score" in str(f.get("label") or "").lower() for f in flags):
                sig.has_high_abuseipdb = True

        row_is_hosting = False
        row_is_anonymiser = False
        if provider in COMMERCIAL_ARBITRATION_PROVIDERS or provider == "MaxMind":
            usage_str = str(row.get("usageType") or "").lower()
            row_is_hosting = any(k in usage_str for k in _HOSTING_KEYWORDS)
            if not row_is_hosting and any(k in usage_str for k in _RESIDENTIAL_KEYWORDS):
                sig.residential_source_count += 1
            for flag in flags:
                if not flag.get("isHighRisk"):
                    continue
                label_lower = str(flag.get("label") or "").lower()
                if any(k in label_lower for k in _HOSTING_KEYWORDS):
                    row_is_hosting = True
                if any(k in label_lower for k in _ANONYMISER_KEYWORDS):
                    row_is_anonymiser = True

            if row_is_hosting:
                sig.has_hosting = True
                sig.hosting_source_count += 1
                if not any(f.get("isHighRisk") for f in flags):
                    flags = [{"label": "Hosting", "isHighRisk": True}]
                    row["securityFlags"] = flags
            if row_is_anonymiser:
                sig.has_anonymiser_flag = True

            explicit_risk = row.get("riskScore")
            has_explicit_risk = (
                isinstance(explicit_risk, (int, float)) and not isinstance(explicit_risk, bool) and explicit_risk > 0
            )
            if (
                row_is_anonymiser
                or has_explicit_risk
                or (not row_is_hosting and any(f.get("isHighRisk") for f in flags))
            ):
                sig.behavioural_threat_votes += 1

        if provider in COMMERCIAL_ARBITRATION_PROVIDERS:
            sig.commercial_responses += 1
            if provider == "GetIPIntel":
                raw_weight = row.get("arbitrationWeight")
                chance_val = row.get("chance")
                if isinstance(raw_weight, (int, float)) and not isinstance(raw_weight, bool):
                    gii_weight = max(0.0, min(1.0, float(raw_weight)))
                elif isinstance(chance_val, (int, float)) and not isinstance(chance_val, bool):
                    gii_weight = 1.0 if float(chance_val) >= 90.0 else 0.5 if float(chance_val) >= 75.0 else 0.0
                else:
                    gii_weight = 1.0 if any(f.get("isHighRisk") for f in flags) else 0.0
                sig.proxy_vpn_votes += gii_weight
                if gii_weight >= 0.5:
                    sig.has_anonymiser_flag = True
            elif any(f.get("isHighRisk") for f in flags) or row_is_hosting or row_is_anonymiser:
                sig.proxy_vpn_votes += 1.0
            continue

        # Free OSINT listings count as affirmative commercial-equivalent votes.
        is_affirmative_osint = False
        if provider == "Spamhaus ZEN":
            is_listed = bool(row.get("isListed"))
            is_policy = bool(row.get("isPolicyRange"))
            codes = row.get("listedCodes")
            has_non_pbl_code = (
                any(code not in ("127.0.0.10", "127.0.0.11") for code in codes if isinstance(code, str))
                if isinstance(codes, list) and codes
                else (is_listed and not is_policy)
            )
            if is_listed and not is_policy and has_non_pbl_code:
                sig.has_spamhaus_listing = True
                is_affirmative_osint = True
        elif provider == "IPsum / DROP":
            in_drop = bool(row.get("inSpamhausDrop"))
            ipsum_score = _as_int(row.get("ipsumScore"))
            sig.max_ipsum_score = max(sig.max_ipsum_score, ipsum_score)
            if in_drop:
                sig.has_spamhaus_listing = True
            is_affirmative_osint = in_drop or ipsum_score >= 3
        elif provider == "OpenASN":
            if bool(row.get("isVpn")):
                is_affirmative_osint = True
            elif bool(row.get("isHosting")):
                sig.has_hosting = True
        elif provider == "Shodan InternetDB":
            raw_proxy_ports = row.get("openProxyPorts")
            if isinstance(raw_proxy_ports, list) and len(raw_proxy_ports) > 0:
                sig.has_shodan_proxy_ports = True
                is_affirmative_osint = True
            raw_tags = row.get("tags")
            if isinstance(raw_tags, list):
                lowered_tags = {str(tag).strip().lower() for tag in raw_tags if isinstance(tag, str)}
                if lowered_tags & _SHODAN_PARADOX_TAGS:
                    sig.has_shodan_paradox_tag = True
        elif provider == "StopForumSpam":
            if bool(row.get("blacklisted")) or (
                bool(row.get("appears"))
                and _as_int(row.get("frequency")) > 0
                and _is_recent_or_undated(row.get("lastSeen"))
            ):
                sig.has_recent_sfs_activity = True
        elif provider == "DShield":
            has_attacks = (
                _as_int(row.get("attacks")) > 0 or _as_int(row.get("count")) > 0 or bool(row.get("threatfeeds"))
            )
            sig.has_recent_dshield_activity |= has_attacks and _is_recent_or_undated(
                row.get("lastSeen") or row.get("maxDate")
            )

        if is_affirmative_osint:
            sig.behavioural_threat_votes += 1
            sig.has_anonymiser_flag = True
            sig.commercial_responses += 1
            sig.proxy_vpn_votes += 1.0

    return sig


def aggregate_intelligence_metrics(  # noqa: C901
    ip: str,
    clean_results: List[Dict[str, Any]],
    ptr_hostname: Optional[str] = None,
    *,
    bgp_prefix: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Computes an independent GetIPIntel prediction, network metadata summary, CIDR block attribution,
    and a confidence-weighted multi-source arbitration verdict.
    """
    normalised_results: List[Dict[str, Any]] = [
        {
            **{k: v for k, v in item.items() if k != "_rehydrate_sig"},
            "securityFlags": [dict(f) for f in item["securityFlags"] if isinstance(f, dict)]
            if isinstance(item.get("securityFlags"), list)
            else item.get("securityFlags"),
        }
        for item in (clean_results or [])
        if isinstance(item, dict)
    ]
    sig = _collect_arbitration_signals(normalised_results)

    chance = sig.getipintel_chance
    if chance is None:
        prediction_score, prediction_label, prediction_tier = 0.0, "GetIPIntel Unavailable", "neutral"
    elif chance >= 90.0:
        prediction_score, prediction_label, prediction_tier = chance, "Proxy / VPN", "destructive"
    elif chance < 20.0:
        prediction_score, prediction_label, prediction_tier = chance, "Normal", "success"
    else:
        prediction_score, prediction_label, prediction_tier = chance, "Needs Human Review", "neutral"

    highly_suspected_residential_proxy = sig.residential_proxy is not None and sig.residential_proxy >= 0.95
    rdns_info = classify_rdns_hostname(ptr_hostname)
    primary_asn = sig.asns[0] if sig.asns else "-"
    cidr_info = compute_cidr_attribution(
        ip,
        sig.mmdb_prefix_len,
        shared_cidr=sig.shared_cidr,
        shared_provider=sig.shared_provider,
        shared_category=sig.shared_category,
        bgp_prefix=bgp_prefix,
        asn=primary_asn if primary_asn != "-" else None,
        org_name=sig.orgs[0] if sig.orgs else None,
        ptr_hostname=rdns_info["ptrHostname"],
        ptr_category=rdns_info["ptrCategory"],
        provider_rows=sig.comparison_results,
        highly_suspected_residential_proxy=highly_suspected_residential_proxy,
    )
    shared_privacy_egress = cidr_info["sharedPrivacyEgress"]

    # Residential context paired with proxy ports or attack feeds suggests a compromised home host.
    is_residential_context = sig.residential_source_count >= 2 or rdns_info["ptrCategory"] == "dynamic_residential"
    suspected_residential_proxy = (
        shared_privacy_egress is None
        and not sig.is_tor
        and is_residential_context
        and (
            sig.has_shodan_proxy_ports
            or sig.has_shodan_paradox_tag
            or (sig.max_ipsum_score >= 3 and (sig.has_recent_sfs_activity or sig.has_recent_dshield_activity))
        )
    )
    has_malicious_abuse_records = (
        sig.has_recent_sfs_activity
        or sig.has_recent_dshield_activity
        or sig.has_high_abuseipdb
        or sig.has_spamhaus_listing
        or sig.max_ipsum_score >= 3
    )

    total = sig.commercial_responses
    votes = sig.proxy_vpn_votes
    rounded_votes = round(float(votes), 2)
    votes_str = str(int(rounded_votes)) if rounded_votes.is_integer() else f"{rounded_votes:.1f}"

    if highly_suspected_residential_proxy:
        verdict, tier, is_majority = "Highly Suspected Residential Proxy", "destructive", True
    elif (
        shared_privacy_egress in ("icloud_private_relay", "cloudflare_warp")
        and not sig.is_tor
        and not has_malicious_abuse_records
    ):
        verdict, tier, is_majority = "Shared Privacy Egress (iCloud Relay / WARP)", "warning", False
    else:
        if total == 0:
            verdict, tier, is_majority = "Direct Connection (No Commercial Threats)", "neutral", False
        elif votes > (total / 2.0):
            prefix = (
                "Confirmed Datacenter / Hosting"
                if sig.has_hosting and not sig.has_anonymiser_flag
                else "Confirmed Proxy / VPN"
            )
            verdict, tier, is_majority = f"{prefix} ({votes_str}/{total} Sources)", "destructive", True
        elif sig.behavioural_threat_votes == 0 and sig.hosting_source_count == 1 and votes == 1.0:
            # A lone hosting classification without behavioural threat votes is only a minor attribute dispute.
            verdict, tier, is_majority = "Clean Residential (1 Minor Attribute Dispute)", "success", False
        elif votes > 0:
            if sig.has_anonymiser_flag:
                prefix = "Disputed Proxy / VPN"
            elif sig.has_hosting and sig.residential_source_count == 0:
                prefix = "Disputed Datacenter / Hosting"
            else:
                prefix = "Disputed Residential / VPN"
            verdict, tier, is_majority = f"{prefix} ({votes_str}/{total} Sources)", "warning", False
        else:
            verdict, tier, is_majority = f"Clean Residential / Direct (0/{total} Sources)", "success", False

        if sig.is_tor and sig.tor_running and not is_majority:
            verdict, tier, is_majority = f"Confirmed {sig.tor_label} (Tor Onionoo)", "destructive", False
        elif suspected_residential_proxy:
            verdict = "Suspected Residential Proxy / Compromised Host"
            tier = "destructive" if is_majority else "warning"

    return {
        "ip": ip,
        "is_broadcast_ip": len(sig.country_codes) > 1,
        "isTor": sig.is_tor,
        "torIsExit": sig.tor_is_exit,
        "torRunning": sig.tor_running,
        "torFlags": sig.tor_flags,
        "torLabel": sig.tor_label,
        "torSummary": sig.tor_summary,
        "prediction_score": prediction_score,
        "predictionLabel": prediction_label,
        "predictionTier": prediction_tier,
        "getipintel_chance": sig.getipintel_chance,
        "residentialProxy": sig.residential_proxy,
        "highlySuspectedResidentialProxy": highly_suspected_residential_proxy,
        "arbitrationVerdict": verdict,
        "arbitrationTier": tier,
        "isMajorityProxyVpn": is_majority,
        "suspectedResidentialProxy": suspected_residential_proxy,
        "primaryCountry": sig.locations[0].split("(")[0].strip() if sig.locations else "-",
        "primaryAsn": primary_asn,
        "ptrHostname": rdns_info["ptrHostname"],
        "ptrCategory": rdns_info["ptrCategory"],
        "ptrLabel": rdns_info["ptrLabel"],
        "ptrIsHighRisk": rdns_info["isHighRisk"],
        **{
            key: cidr_info[key]
            for key in (
                "recommendedCidr",
                "defaultCidr",
                "mmdbCidr",
                "sharedCidr",
                "sharedProvider",
                "sharedCategory",
                "cidrNote",
                "bgpPrefix",
                "escalationCidr",
                "cidrRationale",
                "isMobileOrCgnat",
            )
        },
        "sharedPrivacyEgress": shared_privacy_egress,
        "results": sig.comparison_results,
    }
