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


def _read_proc_rss_mb() -> Optional[float]:
    """Reads live resident set size (RSS) from Linux procfs in megabytes when available."""
    global _proc_rss_cache

    now_mono = time.monotonic()
    with _proc_rss_lock:
        cached = _proc_rss_cache
    if cached is not None and 0.0 <= (now_mono - cached[0]) < _PROC_RSS_CACHE_TTL_SECONDS:
        return cached[1]

    try:
        with open("/proc/self/statm", encoding="ascii") as statm_file:
            fields = statm_file.read().split()
        if len(fields) < 2:
            return None
        rss_pages = int(fields[1])
        page_size = os.sysconf("SC_PAGESIZE")
    except OSError, AttributeError, ValueError, TypeError:
        return None

    if rss_pages < 0 or page_size <= 0:
        return None
    rss_mb = round((rss_pages * page_size) / (1024.0 * 1024.0), 2)
    with _proc_rss_lock:
        _proc_rss_cache = (now_mono, rss_mb)
    return rss_mb


def get_process_memory_mb() -> Optional[float]:
    """Returns current worker RSS in megabytes, falling back to peak RSS when procfs is unavailable."""
    proc_rss = _read_proc_rss_mb()
    if proc_rss is not None:
        return proc_rss

    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # Linux reports ru_maxrss in KiB.
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
        "primaryCoordinates": "N/A",
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


_build_non_public_response_payload = build_non_public_response_payload


_HOSTING_KEYWORDS = ("datacenter", "data center", "hosting", "cloud", "transit", "cdn")
_RESIDENTIAL_KEYWORDS = ("isp", "residential", "fixed line", "mobile", "commercial", "education")
_ANONYMIZER_KEYWORDS = ("proxy", "vpn", "tor", "relay", "abuser", "attacker", "threat", "block 1", "spam", "botnet")
_SHODAN_PARADOX_TAGS = frozenset({"proxy", "vpn", "compromised"})
_RECENT_ACTIVITY_WINDOW_SECONDS = 30 * 86400


@dataclass
class _TorOverview:
    is_tor: bool = False
    tor_is_exit: bool = False
    tor_running: bool = False
    tor_flags: List[str] = field(default_factory=list)
    tor_label: Optional[str] = None
    tor_summary: Optional[str] = None


@dataclass
class _ArbitrationAccumulator:
    valid_country_codes: Set[str] = field(default_factory=set)
    valid_asns: List[str] = field(default_factory=list)
    valid_orgs: List[str] = field(default_factory=list)
    valid_locations: List[str] = field(default_factory=list)
    valid_coords: List[str] = field(default_factory=list)
    getipintel_chance: Optional[float] = None
    residential_proxy: Optional[float] = None
    positive_proxy_vpn_votes: float = 0.0
    total_commercial_responses: int = 0
    hosting_source_count: int = 0
    behavioral_threat_votes: int = 0
    clean_source_count: int = 0
    residential_source_count: int = 0
    has_datacenter_or_hosting: bool = False
    has_anonymizer_flag: bool = False
    has_shodan_proxy_ports: bool = False
    has_shodan_paradox_tag: bool = False
    max_ipsum_score: int = 0
    has_spamhaus_sbl_xbl_drop: bool = False
    has_recent_sfs_activity: bool = False
    has_recent_dshield_activity: bool = False
    has_high_abuseipdb: bool = False


def _parse_activity_datetime(raw_value: Any) -> Optional[datetime]:
    if not isinstance(raw_value, str) or not raw_value.strip():
        return None
    cleaned = raw_value.strip()
    if cleaned.endswith("Z"):
        cleaned = f"{cleaned[:-1]}+00:00"
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            parsed = datetime.fromisoformat(cleaned) if fmt is None else datetime.strptime(cleaned, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            continue
    return None


def _is_timestamp_recent(raw_value: Any, *, window_seconds: int = _RECENT_ACTIVITY_WINDOW_SECONDS) -> Optional[bool]:
    parsed = _parse_activity_datetime(raw_value)
    if parsed is None:
        return None
    age_seconds = (datetime.now(timezone.utc) - parsed).total_seconds()
    return age_seconds <= window_seconds


def _format_vote_count(votes: float) -> str:
    rounded = round(float(votes), 2)
    if rounded.is_integer():
        return str(int(rounded))
    return f"{rounded:.1f}"


def _extract_tor_overview(row: Dict[str, Any]) -> _TorOverview:
    if row.get("status") != "200 OK" or not row.get("isTor"):
        return _TorOverview()
    tor_is_exit = bool(row.get("torIsExit"))
    raw_tor_flags = row.get("torFlags")
    tor_flags = [str(flag) for flag in raw_tor_flags if flag] if isinstance(raw_tor_flags, list) else []
    raw_tor_summary = row.get("torSummary")
    return _TorOverview(
        is_tor=True,
        tor_is_exit=tor_is_exit,
        tor_running=bool(row.get("torRunning")),
        tor_flags=tor_flags,
        tor_label=str(row.get("torLabel") or ("Tor Exit" if tor_is_exit else "Tor Node")),
        tor_summary=str(raw_tor_summary) if raw_tor_summary else None,
    )


def _record_row_network_metadata(row: Dict[str, Any], acc: _ArbitrationAccumulator) -> None:
    c_code = row.get("countryCode")
    if isinstance(c_code, str):
        c_code_clean = c_code.strip().upper()
        if len(c_code_clean) == 2 and c_code_clean.isalpha():
            acc.valid_country_codes.add(c_code_clean)

    asn_val = row.get("asn")
    if asn_val and asn_val != "-" and str(asn_val).startswith("AS"):
        acc.valid_asns.append(str(asn_val))

    org_val = row.get("organisation") or row.get("isp")
    if isinstance(org_val, str) and org_val.strip() and org_val.strip() != "-":
        acc.valid_orgs.append(org_val.strip())

    loc_val = row.get("location")
    if loc_val and loc_val != "-":
        acc.valid_locations.append(loc_val)

    coords_val = row.get("coordinates")
    if coords_val:
        acc.valid_coords.append(coords_val)

    if row.get("provider") == "GetIPIntel":
        chance_val = row.get("chance")
        if isinstance(chance_val, (int, float)):
            acc.getipintel_chance = round(float(chance_val), 3)
        residential_proxy = row.get("residentialProxy")
        if isinstance(residential_proxy, (int, float)) and not isinstance(residential_proxy, bool):
            acc.residential_proxy = round(float(residential_proxy), 4)


def _resolve_getipintel_vote_weight(row: Dict[str, Any], flags: List[Dict[str, Any]]) -> float:
    raw_weight = row.get("arbitrationWeight")
    if isinstance(raw_weight, (int, float)) and not isinstance(raw_weight, bool):
        return max(0.0, min(1.0, float(raw_weight)))
    chance_val = row.get("chance")
    if isinstance(chance_val, (int, float)) and not isinstance(chance_val, bool):
        if float(chance_val) >= 90.0:
            return 1.0
        if float(chance_val) >= 75.0:
            return 0.5
        return 0.0
    return 1.0 if any(f.get("isHighRisk") for f in flags) else 0.0


def _add_affirmative_osint_vote(acc: _ArbitrationAccumulator) -> None:
    acc.behavioral_threat_votes += 1
    acc.has_anonymizer_flag = True
    acc.total_commercial_responses += 1
    acc.positive_proxy_vpn_votes += 1.0


def _classify_spamhaus_or_ipsum_row(p_name: str, row: Dict[str, Any], acc: _ArbitrationAccumulator) -> None:
    if p_name == "Spamhaus ZEN":
        is_listed = bool(row.get("isListed"))
        is_policy = bool(row.get("isPolicyRange"))
        codes = row.get("listedCodes")
        has_non_pbl_code = (
            any(code not in ("127.0.0.10", "127.0.0.11") for code in codes if isinstance(code, str))
            if isinstance(codes, list) and codes
            else (is_listed and not is_policy)
        )
        if is_listed and not is_policy and has_non_pbl_code:
            acc.has_spamhaus_sbl_xbl_drop = True
            _add_affirmative_osint_vote(acc)
        return

    in_drop = bool(row.get("inSpamhausDrop"))
    raw_score = row.get("ipsumScore")
    ipsum_score = int(raw_score) if isinstance(raw_score, int) and not isinstance(raw_score, bool) else 0
    acc.max_ipsum_score = max(acc.max_ipsum_score, ipsum_score)
    if in_drop:
        acc.has_spamhaus_sbl_xbl_drop = True
    if in_drop or ipsum_score >= 3:
        _add_affirmative_osint_vote(acc)


def _classify_activity_feed_row(p_name: str, row: Dict[str, Any], acc: _ArbitrationAccumulator) -> None:
    if p_name == "StopForumSpam":
        if bool(row.get("blacklisted")):
            acc.has_recent_sfs_activity = True
            return
        raw_freq = row.get("frequency")
        freq = int(raw_freq) if isinstance(raw_freq, int) and not isinstance(raw_freq, bool) else 0
        if bool(row.get("appears")) and freq > 0 and _is_timestamp_recent(row.get("lastSeen")) in (True, None):
            acc.has_recent_sfs_activity = True
        return

    raw_attacks = row.get("attacks")
    attacks = int(raw_attacks) if isinstance(raw_attacks, int) and not isinstance(raw_attacks, bool) else 0
    raw_count = row.get("count")
    count = int(raw_count) if isinstance(raw_count, int) and not isinstance(raw_count, bool) else 0
    if (attacks > 0 or count > 0 or bool(row.get("threatfeeds"))) and _is_timestamp_recent(
        row.get("lastSeen") or row.get("maxDate")
    ) in (True, None):
        acc.has_recent_dshield_activity = True


def _classify_osint_arbitration_signals(row: Dict[str, Any], acc: _ArbitrationAccumulator) -> None:
    p_name = row.get("provider")
    if p_name in ("Spamhaus ZEN", "IPsum / DROP"):
        _classify_spamhaus_or_ipsum_row(str(p_name), row, acc)
    elif p_name == "OpenASN":
        if bool(row.get("isVpn")):
            _add_affirmative_osint_vote(acc)
        elif bool(row.get("isHosting")):
            acc.has_datacenter_or_hosting = True
    elif p_name == "Shodan InternetDB":
        raw_proxy_ports = row.get("openProxyPorts")
        if isinstance(raw_proxy_ports, list) and len(raw_proxy_ports) > 0:
            acc.has_shodan_proxy_ports = True
            _add_affirmative_osint_vote(acc)
        raw_tags = row.get("tags")
        if isinstance(raw_tags, list):
            lowered_tags = {str(tag).strip().lower() for tag in raw_tags if isinstance(tag, str)}
            if lowered_tags & _SHODAN_PARADOX_TAGS:
                acc.has_shodan_paradox_tag = True
    elif p_name in ("StopForumSpam", "DShield"):
        _classify_activity_feed_row(str(p_name), row, acc)


def _row_has_high_abuseipdb(row: Dict[str, Any], flags: List[Dict[str, Any]]) -> bool:
    raw_abuse = row.get("abuseConfidenceScore")
    if isinstance(raw_abuse, (int, float)) and not isinstance(raw_abuse, bool) and float(raw_abuse) >= 25.0:
        return True
    return any(f.get("isHighRisk") and "abuse score" in str(f.get("label") or "").lower() for f in flags)


def _extract_commercial_or_maxmind_traits(
    row: Dict[str, Any],
    flags: List[Dict[str, Any]],
    acc: _ArbitrationAccumulator,
) -> Tuple[bool, bool]:
    usage_str = str(row.get("usageType") or "").lower()
    row_is_hosting = any(k in usage_str for k in _HOSTING_KEYWORDS)
    if not row_is_hosting and any(k in usage_str for k in _RESIDENTIAL_KEYWORDS):
        acc.residential_source_count += 1

    row_is_anonymizer = False
    for flag in flags:
        if not flag.get("isHighRisk"):
            continue
        label_lower = str(flag.get("label") or "").lower()
        if any(k in label_lower for k in _HOSTING_KEYWORDS):
            row_is_hosting = True
        if any(k in label_lower for k in _ANONYMIZER_KEYWORDS):
            row_is_anonymizer = True

    if row_is_hosting:
        acc.has_datacenter_or_hosting = True
        acc.hosting_source_count += 1
        if not any(f.get("isHighRisk") for f in flags):
            flags = [{"label": "Hosting", "isHighRisk": True}]
            row["securityFlags"] = flags
    if row_is_anonymizer:
        acc.has_anonymizer_flag = True

    explicit_risk = row.get("riskScore")
    has_explicit_risk = (
        isinstance(explicit_risk, (int, float)) and not isinstance(explicit_risk, bool) and explicit_risk > 0
    )
    has_row_high_risk_flag = any(f.get("isHighRisk") for f in flags)
    if row_is_anonymizer or has_explicit_risk or (not row_is_hosting and has_row_high_risk_flag):
        acc.behavioral_threat_votes += 1
    elif not row_is_hosting and not has_row_high_risk_flag:
        acc.clean_source_count += 1
    return row_is_hosting, row_is_anonymizer


def _classify_row_arbitration_signals(row: Dict[str, Any], acc: _ArbitrationAccumulator) -> None:
    """Updates hosting, anonymiser, behavioural, OSINT, and commercial vote counters for one 200 OK row."""
    p_name = row.get("provider")
    flags = row.get("securityFlags") or []
    row_is_hosting = False
    row_is_anonymizer = False

    if p_name == "AbuseIPDB" and _row_has_high_abuseipdb(row, flags):
        acc.has_high_abuseipdb = True

    if p_name in COMMERCIAL_ARBITRATION_PROVIDERS or p_name == "MaxMind":
        row_is_hosting, row_is_anonymizer = _extract_commercial_or_maxmind_traits(row, flags, acc)
        flags = row.get("securityFlags") or flags

    if p_name in COMMERCIAL_ARBITRATION_PROVIDERS:
        acc.total_commercial_responses += 1
        if p_name == "GetIPIntel":
            gii_weight = _resolve_getipintel_vote_weight(row, flags)
            acc.positive_proxy_vpn_votes += gii_weight
            if gii_weight >= 0.5:
                acc.has_anonymizer_flag = True
        elif any(f.get("isHighRisk") for f in flags) or row_is_hosting or row_is_anonymizer:
            acc.positive_proxy_vpn_votes += 1.0
        return

    _classify_osint_arbitration_signals(row, acc)


def _compute_getipintel_prediction(getipintel_chance: Optional[float]) -> Tuple[float, str, str]:
    if getipintel_chance is None:
        return 0.0, "GetIPIntel Unavailable", "neutral"
    if getipintel_chance >= 90.0:
        return getipintel_chance, "Proxy / VPN", "destructive"
    if getipintel_chance < 20.0:
        return getipintel_chance, "Normal", "success"
    return getipintel_chance, "Needs Human Review", "neutral"


def _has_malicious_abuse_records(acc: _ArbitrationAccumulator) -> bool:
    return (
        acc.has_recent_sfs_activity
        or acc.has_recent_dshield_activity
        or acc.has_high_abuseipdb
        or acc.has_spamhaus_sbl_xbl_drop
        or acc.max_ipsum_score >= 3
    )


def _detect_residential_signal_paradox(
    acc: _ArbitrationAccumulator,
    *,
    ptr_category: str,
    shared_privacy_egress: Optional[str],
    is_tor: bool,
) -> bool:
    if shared_privacy_egress is not None or is_tor:
        return False
    is_residential_context = acc.residential_source_count >= 2 or ptr_category == "dynamic_residential"
    if not is_residential_context:
        return False
    has_shodan_signal = acc.has_shodan_proxy_ports or acc.has_shodan_paradox_tag
    has_ipsum_attack_signal = acc.max_ipsum_score >= 3 and (
        acc.has_recent_sfs_activity or acc.has_recent_dshield_activity
    )
    return has_shodan_signal or has_ipsum_attack_signal


def _resolve_arbitration_verdict(
    acc: _ArbitrationAccumulator,
    tor: _TorOverview,
    *,
    shared_privacy_egress: Optional[str] = None,
    suspected_residential_proxy: bool = False,
) -> Tuple[str, str, bool]:
    """Resolves final multi-source verdict label, tier, and majority proxy or VPN flag."""
    if (
        shared_privacy_egress in ("icloud_private_relay", "cloudflare_warp")
        and not tor.is_tor
        and not _has_malicious_abuse_records(acc)
    ):
        return (
            "Shared Privacy Egress (iCloud Relay / WARP)",
            "warning",
            False,
        )

    total = acc.total_commercial_responses
    votes = acc.positive_proxy_vpn_votes
    votes_str = _format_vote_count(votes)

    if total == 0:
        verdict, tier, is_majority = "Direct Connection (No Commercial Threats)", "neutral", False
    elif votes > (total / 2.0):
        prefix = (
            "Confirmed Datacenter / Hosting"
            if acc.has_datacenter_or_hosting and not acc.has_anonymizer_flag
            else "Confirmed Proxy / VPN"
        )
        verdict, tier, is_majority = f"{prefix} ({votes_str}/{total} Sources)", "destructive", True
    elif acc.behavioral_threat_votes == 0 and acc.hosting_source_count == 1 and votes == 1.0:
        # Treat a lone hosting classification without behavioural threat votes as a minor attribute dispute.
        verdict, tier, is_majority = "Clean Residential (1 Minor Attribute Dispute)", "success", False
    elif votes > 0:
        if acc.has_anonymizer_flag:
            prefix = "Disputed Proxy / VPN"
        elif acc.has_datacenter_or_hosting and acc.residential_source_count == 0:
            prefix = "Disputed Datacenter / Hosting"
        else:
            prefix = "Disputed Residential / VPN"
        verdict, tier, is_majority = f"{prefix} ({votes_str}/{total} Sources)", "warning", False
    else:
        verdict, tier, is_majority = f"Clean Residential / Direct (0/{total} Sources)", "success", False

    if tor.is_tor and tor.tor_running and not is_majority:
        tor_verdict_label = tor.tor_label or ("Tor Exit" if tor.tor_is_exit else "Tor Node")
        return f"Confirmed {tor_verdict_label} (Tor Onionoo)", "destructive", False

    if suspected_residential_proxy:
        paradox_tier = "destructive" if is_majority else "warning"
        return "Suspected Residential Proxy / Compromised Host", paradox_tier, is_majority

    return verdict, tier, is_majority


def _extract_maxmind_cidr_hints(
    comparison_results: List[Dict[str, Any]],
) -> Tuple[Optional[int], Optional[str], Optional[str], Optional[str]]:
    mmdb_prefix_len: Optional[int] = None
    shared_cidr: Optional[str] = None
    shared_provider: Optional[str] = None
    shared_category: Optional[str] = None
    for row in comparison_results:
        if row.get("provider") != "MaxMind" or row.get("status") != "200 OK":
            continue
        candidate_len = row.get("prefixLength")
        if candidate_len is None and isinstance(row.get("rawJson"), dict):
            candidate_len = row["rawJson"].get("prefix_len")
        if not isinstance(candidate_len, bool) and isinstance(candidate_len, int):
            mmdb_prefix_len = candidate_len
        raw_shared_cidr = row.get("sharedCidr") or row.get("cloudCidr")
        if isinstance(raw_shared_cidr, str) and raw_shared_cidr:
            shared_cidr = raw_shared_cidr
        raw_shared_provider = row.get("sharedProvider") or row.get("cloudProvider")
        if isinstance(raw_shared_provider, str) and raw_shared_provider:
            shared_provider = raw_shared_provider
        raw_shared_category = row.get("sharedCategory") or ("cloud" if row.get("cloudProvider") else None)
        if isinstance(raw_shared_category, str) and raw_shared_category:
            shared_category = raw_shared_category
    return mmdb_prefix_len, shared_cidr, shared_provider, shared_category


def aggregate_intelligence_metrics(
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
    normalized_results: List[Dict[str, Any]] = [
        {
            **{k: v for k, v in item.items() if k != "_rehydrate_sig"},
            "securityFlags": [dict(f) for f in item["securityFlags"] if isinstance(f, dict)]
            if isinstance(item.get("securityFlags"), list)
            else item.get("securityFlags"),
        }
        for item in (clean_results or [])
        if isinstance(item, dict)
    ]

    tor = _TorOverview()
    acc = _ArbitrationAccumulator()
    comparison_results: List[Dict[str, Any]] = []

    for row in normalized_results:
        # Exclude Tor Onionoo from the comparison panel and surface it only in overview Tor fields
        if row.get("provider") == "Tor Onionoo":
            tor = _extract_tor_overview(row)
            continue
        comparison_results.append(row)
        if row.get("status") == "200 OK":
            _record_row_network_metadata(row, acc)
            _classify_row_arbitration_signals(row, acc)

    prediction_score, prediction_label, prediction_tier = _compute_getipintel_prediction(acc.getipintel_chance)
    highly_suspected_residential_proxy = acc.residential_proxy is not None and acc.residential_proxy >= 0.95
    mmdb_prefix_len, shared_cidr, shared_provider, shared_category = _extract_maxmind_cidr_hints(comparison_results)
    rdns_info = classify_rdns_hostname(ptr_hostname)
    primary_asn = acc.valid_asns[0] if acc.valid_asns else "-"
    primary_org = acc.valid_orgs[0] if acc.valid_orgs else None
    cidr_info = compute_cidr_attribution(
        ip,
        mmdb_prefix_len,
        shared_cidr=shared_cidr,
        shared_provider=shared_provider,
        shared_category=shared_category,
        bgp_prefix=bgp_prefix,
        asn=primary_asn if primary_asn != "-" else None,
        org_name=primary_org,
        ptr_hostname=rdns_info["ptrHostname"],
        ptr_category=rdns_info["ptrCategory"],
        provider_rows=comparison_results,
        highly_suspected_residential_proxy=highly_suspected_residential_proxy,
    )
    shared_privacy_egress = cidr_info["sharedPrivacyEgress"]
    suspected_residential_proxy = _detect_residential_signal_paradox(
        acc,
        ptr_category=rdns_info["ptrCategory"],
        shared_privacy_egress=shared_privacy_egress,
        is_tor=tor.is_tor,
    )
    if highly_suspected_residential_proxy:
        arbitration_verdict = "Highly Suspected Residential Proxy"
        arbitration_tier = "destructive"
        is_majority_proxy_vpn = True
    else:
        arbitration_verdict, arbitration_tier, is_majority_proxy_vpn = _resolve_arbitration_verdict(
            acc,
            tor,
            shared_privacy_egress=shared_privacy_egress,
            suspected_residential_proxy=suspected_residential_proxy,
        )

    return {
        "ip": ip,
        "is_broadcast_ip": len(acc.valid_country_codes) > 1,
        "isTor": tor.is_tor,
        "torIsExit": tor.tor_is_exit,
        "torRunning": tor.tor_running,
        "torFlags": tor.tor_flags,
        "torLabel": tor.tor_label,
        "torSummary": tor.tor_summary,
        "prediction_score": prediction_score,
        "predictionLabel": prediction_label,
        "predictionTier": prediction_tier,
        "getipintel_chance": acc.getipintel_chance,
        "residentialProxy": acc.residential_proxy,
        "highlySuspectedResidentialProxy": highly_suspected_residential_proxy,
        "arbitrationVerdict": arbitration_verdict,
        "arbitrationTier": arbitration_tier,
        "isMajorityProxyVpn": is_majority_proxy_vpn,
        "suspectedResidentialProxy": suspected_residential_proxy,
        "primaryCountry": acc.valid_locations[0].split("(")[0].strip() if acc.valid_locations else "-",
        "primaryCoordinates": acc.valid_coords[0] if acc.valid_coords else "Unknown",
        "primaryAsn": primary_asn,
        "ptrHostname": rdns_info["ptrHostname"],
        "ptrCategory": rdns_info["ptrCategory"],
        "ptrLabel": rdns_info["ptrLabel"],
        "ptrIsHighRisk": rdns_info["isHighRisk"],
        "recommendedCidr": cidr_info["recommendedCidr"],
        "defaultCidr": cidr_info["defaultCidr"],
        "mmdbCidr": cidr_info["mmdbCidr"],
        "sharedCidr": cidr_info["sharedCidr"],
        "sharedProvider": cidr_info["sharedProvider"],
        "sharedCategory": cidr_info["sharedCategory"],
        "cidrNote": cidr_info["cidrNote"],
        "bgpPrefix": cidr_info["bgpPrefix"],
        "escalationCidr": cidr_info["escalationCidr"],
        "cidrRationale": cidr_info["cidrRationale"],
        "isMobileOrCgnat": cidr_info["isMobileOrCgnat"],
        "sharedPrivacyEgress": shared_privacy_egress,
        "results": comparison_results,
    }
