"""
Reverse DNS hostname classification, cloud CIDR prefix indexing, hosting ASN and
organisation keyword matching, and recommended block CIDR attribution.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .offline_dbs import (
    MOBILE_BGP_TAG_TOKENS,
    FileStatCache,
    are_stopforumspam_caches_warm,
    clear_stopforumspam_caches,
    get_file_stat_signature,
    get_setting,
    is_mobile_asn_offline,
    lookup_bgp_tools_offline,
    lookup_privacy_relay_offline,
    lookup_shared_cidr_offline,
    query_openasn_offline,
    resolve_hosting_rules_path,
    warm_stopforumspam_caches,
)

logger = logging.getLogger(__name__)

_MEDIAWIKI_MIN_IPV4_PREFIX = 16
_MEDIAWIKI_MIN_IPV6_PREFIX = 19
_HOSTING_IPV6_MIN_ESCALATION_PREFIX = 48
_HOSTING_IPV6_MAX_ESCALATION_PREFIX = 64
_RESIDENTIAL_IPV6_ESCALATION_PREFIX = 56
_RESIDENTIAL_IPV6_MAX_BGP_FOR_ESCALATION = 48
_SHARED_CGNAT_V4_NET = ipaddress.ip_network("100.64.0.0/10")

_HOSTING_GATEWAY_DOMAIN_MARKERS = (
    "amazonaws.com",
    "compute.internal",
    "googleusercontent.com",
    "cloud.google.com",
    "appspot.com",
    "cloudapp.net",
    "azure.com",
    "trafficmanager.net",
    "digitalocean.com",
    "linode.com",
    "linodeusercontent.com",
    "vultr.com",
    "choopa.net",
    "your-server.de",
    "hetzner.",
    "ovh.net",
    "ovh.ca",
    "ovh.us",
    "kimsufi.com",
    "soyoustart.com",
    "contabo.",
    "contaboserver.net",
    "m247.com",
    "leaseweb.",
    "scaleway.com",
    "online.net",
    "kamatera.",
    "upcloud.",
    "oraclecloud.com",
    "aliyuncs.com",
    "myqcloud.com",
    "torproject.org",
    "tor-exit",
    "torexit",
    "exit-node",
    "exitnode",
    "datacenter",
    "data-center",
)

_HOSTING_GATEWAY_TOKENS = frozenset(
    {
        "vpn",
        "openvpnas",
        "wireguard",
        "ipsec",
        "proxy",
        "socks",
        "tor",
        "exit",
        "anonymizer",
        "hosting",
        "vps",
        "vserver",
        "dedicated",
        "dedi",
        "colocation",
        "colo",
        "server",
        "srv",
        "cloud",
        "compute",
        "ec2",
        "droplet",
        "hetzner",
        "vultr",
        "linode",
        "contabo",
        "m247",
        "choopa",
        "leaseweb",
        "ovh",
    }
)

_MOBILE_OR_CGNAT_TOKENS = frozenset(
    {
        "mobile",
        "cellular",
        "lte",
        "5g",
        "nr",
        "epc",
        "ggsn",
        "pgw",
        "cgn",
        "cgnat",
        "nat444",
        "gprs",
    }
)

_DYNAMIC_RESIDENTIAL_DOMAIN_MARKERS = (
    "t-ipconnect.de",
    "dynamic.hinet.net",
    "hsd1.",
    "comcast.net",
    "rr.com",
    "sbcglobal.net",
    "ameritech.net",
    "bellsouth.net",
    "pacbell.net",
    "prodigy.net",
    "swbell.net",
    "verizon.net",
    "fios.",
    "optonline.net",
    "cox.net",
    "charter.com",
    "spectrum.com",
    "btcentralplus.com",
    "virginm.net",
    "sky.com",
    "talktalk.net",
    "plus.com",
    "proxad.net",
    "wanadoo.fr",
    "orange.fr",
    "vodafone.",
    "telekom.de",
    "unitymediagroup.de",
    "kdg.vodafone.de",
)

_DYNAMIC_RESIDENTIAL_TOKENS = frozenset(
    {
        "dynamic",
        "dyn",
        "dynip",
        "dip",
        "dip0",
        "pool",
        "pools",
        "pppoe",
        "ppp",
        "pptp",
        "dsl",
        "adsl",
        "vdsl",
        "sdsl",
        "dslb",
        "cable",
        "docsis",
        "cmts",
        "fios",
        "ftth",
        "fttb",
        "fiber",
        "fibre",
        "dhcp",
        "broadband",
        "residential",
        "home",
        "cust",
        "customer",
        "subscriber",
        "umts",
        "cdma",
        "wireless",
        "cpe",
        "dialup",
        "dial",
        "hsd",
    }
)

_BUILTIN_HOSTING_ASNS: Dict[int, str] = {
    9009: "M247",
    12876: "Scaleway",
    14061: "DigitalOcean",
    14618: "Amazon AWS",
    16276: "OVH",
    16509: "Amazon AWS",
    20473: "Choopa / Vultr",
    21859: "Zenlayer",
    24940: "Hetzner",
    31898: "Oracle Cloud",
    36352: "ColoCrossing",
    51167: "Contabo",
    60781: "Leaseweb",
    63949: "Linode",
    132203: "Tencent Cloud",
    197540: "netcup",
    396982: "Google Cloud",
}

_BUILTIN_HOSTING_ORG_KEYWORDS: Tuple[str, ...] = (
    "digitalocean",
    "hetzner",
    "vultr",
    "choopa",
    "linode",
    "ovh",
    "contabo",
    "scaleway",
    "leaseweb",
    "m247",
    "colocrossing",
    "netcup",
    "upcloud",
    "kamatera",
    "kimsufi",
    "soyoustart",
    "amazon web services",
    "amazon.com",
    "aws",
    "google cloud",
    "oracle cloud",
    "alibaba cloud",
    "aliyun",
    "tencent cloud",
    "microsoft azure",
    "datacenter",
    "data center",
    "web hosting",
    "cloud hosting",
    "hosting",
    "vps",
    "colocation",
    "serverstack",
)


def classify_rdns_hostname(hostname: Optional[str]) -> Dict[str, Any]:
    """Classifies a reverse DNS PTR hostname into hosting, mobile or CGNAT, residential, or standard categories."""
    cleaned = hostname.strip().rstrip(".").lower() if isinstance(hostname, str) else ""
    if not cleaned:
        return {
            "ptrHostname": None,
            "ptrCategory": "none",
            "ptrLabel": "No PTR Record",
            "isHighRisk": False,
        }

    raw_segments = [seg for seg in re.split(r"[.\-_]+", cleaned) if seg]
    token_set = set(raw_segments)
    for seg in raw_segments:
        alpha_stem = re.sub(r"\d+", "", seg)
        if len(alpha_stem) >= 3:
            token_set.add(alpha_stem)

    if any(marker in cleaned for marker in _HOSTING_GATEWAY_DOMAIN_MARKERS) or (token_set & _HOSTING_GATEWAY_TOKENS):
        return {
            "ptrHostname": cleaned,
            "ptrCategory": "hosting_or_gateway",
            "ptrLabel": "Cloud or Hosting Gateway",
            "isHighRisk": True,
        }

    if token_set & _MOBILE_OR_CGNAT_TOKENS:
        return {
            "ptrHostname": cleaned,
            "ptrCategory": "mobile_or_cgnat",
            "ptrLabel": "Mobile or CGNAT",
            "isHighRisk": False,
        }

    if any(marker in cleaned for marker in _DYNAMIC_RESIDENTIAL_DOMAIN_MARKERS) or (
        token_set & _DYNAMIC_RESIDENTIAL_TOKENS
    ):
        return {
            "ptrHostname": cleaned,
            "ptrCategory": "dynamic_residential",
            "ptrLabel": "Dynamic Residential",
            "isHighRisk": False,
        }

    return {
        "ptrHostname": cleaned,
        "ptrCategory": "unclassified",
        "ptrLabel": "Standard Hostname",
        "isHighRisk": False,
    }


def _normalize_asn_number(asn_val: Any) -> Optional[int]:
    """Parses a positive autonomous system number from integers or AS-prefixed strings."""
    if isinstance(asn_val, bool) or asn_val is None:
        return None
    if isinstance(asn_val, int):
        return asn_val if asn_val > 0 else None
    if isinstance(asn_val, float):
        if math.isfinite(asn_val) and asn_val > 0 and asn_val.is_integer():
            return int(asn_val)
        return None
    if isinstance(asn_val, str):
        cleaned = asn_val.strip().upper()
        if cleaned.startswith("AS"):
            cleaned = cleaned[2:].strip()
        if cleaned.isdigit():
            parsed = int(cleaned)
            return parsed if parsed > 0 else None
    return None


_hosting_rules_cache: FileStatCache[
    Tuple[str, int, Tuple[str, ...], Tuple[str, ...]],
    Tuple[Dict[int, str], Optional[re.Pattern[str]]],
] = FileStatCache()


def _ingest_hosting_rule_entry(
    entry: Any,
    asn_map: Dict[int, str],
    keywords: List[str],
) -> None:
    if isinstance(entry, dict):
        provider_name = (
            str(entry.get("name") or entry.get("provider") or "Hosting Provider").strip() or "Hosting Provider"
        )
        single_asn = _normalize_asn_number(entry.get("asn"))
        if single_asn is not None:
            asn_map[single_asn] = provider_name
        raw_asns = entry.get("asns")
        if isinstance(raw_asns, list):
            for asn_item in raw_asns:
                parsed_asn = _normalize_asn_number(asn_item)
                if parsed_asn is not None:
                    asn_map[parsed_asn] = provider_name
        for kw_key in ("keywords", "searchterms", "orgKeywords"):
            raw_kws = entry.get(kw_key)
            if isinstance(raw_kws, list):
                keywords.extend(kw.strip().lower() for kw in raw_kws if isinstance(kw, str) and kw.strip())
        return

    parsed_asn = _normalize_asn_number(entry)
    if parsed_asn is not None:
        asn_map[parsed_asn] = f"AS{parsed_asn}"


def _get_hosting_rules() -> Tuple[Dict[int, str], Optional[re.Pattern[str]]]:
    path, _ = resolve_hosting_rules_path()
    mtime_ns = 0
    path_str = ""
    if path is not None:
        sig = get_file_stat_signature(path)
        if sig is not None:
            mtime_ns = sig[0]
            path_str = str(path)
        else:
            path = None

    def _setting_tuple(name: str) -> Tuple[str, ...]:
        raw_val = get_setting(name, ())
        if isinstance(raw_val, str):
            return tuple(part.strip() for part in raw_val.split(",") if part.strip())
        if isinstance(raw_val, (list, tuple, set, frozenset)):
            return tuple(str(part).strip() for part in raw_val if str(part).strip())
        return ()

    configured_asns = _setting_tuple("HOSTING_ASNS")
    configured_keywords = _setting_tuple("HOSTING_ORG_KEYWORDS")
    cache_key = (path_str, mtime_ns, configured_asns, configured_keywords)

    def _load() -> Tuple[Dict[int, str], Optional[re.Pattern[str]]]:
        asn_map: Dict[int, str] = dict(_BUILTIN_HOSTING_ASNS)
        keywords: List[str] = list(_BUILTIN_HOSTING_ORG_KEYWORDS)

        if path is not None:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(payload, list):
                    for item in payload:
                        _ingest_hosting_rule_entry(item, asn_map, keywords)
                elif isinstance(payload, dict):
                    raw_asns = payload.get("asns")
                    if isinstance(raw_asns, dict):
                        for k, v in raw_asns.items():
                            parsed_asn = _normalize_asn_number(k)
                            if parsed_asn is not None:
                                asn_map[parsed_asn] = (
                                    v.strip() if isinstance(v, str) and v.strip() else f"AS{parsed_asn}"
                                )
                    elif isinstance(raw_asns, list):
                        for item in raw_asns:
                            _ingest_hosting_rule_entry(item, asn_map, keywords)
                    for hosts_key in ("hosts", "providers", "rules"):
                        raw_hosts = payload.get(hosts_key)
                        entries = (
                            raw_hosts
                            if isinstance(raw_hosts, list)
                            else (raw_hosts.values() if isinstance(raw_hosts, dict) else ())
                        )
                        for entry in entries:
                            _ingest_hosting_rule_entry(entry, asn_map, keywords)
                    for kw_key in ("keywords", "orgKeywords", "searchterms"):
                        raw_kws = payload.get(kw_key)
                        if isinstance(raw_kws, list):
                            keywords.extend(kw.strip().lower() for kw in raw_kws if isinstance(kw, str) and kw.strip())
            except (OSError, ValueError) as exc:
                logger.warning("Failed to load hosting ASN rules from %s: %s", path, exc)

        for raw_asn in configured_asns:
            parsed_asn = _normalize_asn_number(raw_asn)
            if parsed_asn is not None and parsed_asn not in asn_map:
                asn_map[parsed_asn] = f"AS{parsed_asn}"
        keywords.extend(raw_kw.lower() for raw_kw in configured_keywords)

        unique_keywords = sorted(
            {kw.strip().lower() for kw in keywords if isinstance(kw, str) and kw.strip()},
            key=len,
            reverse=True,
        )
        pattern = (
            re.compile(
                rf"(?<![a-z0-9])(?:{'|'.join(re.escape(kw) for kw in unique_keywords)})(?![a-z0-9])", re.IGNORECASE
            )
            if unique_keywords
            else None
        )
        return asn_map, pattern

    return _hosting_rules_cache.get_or_load(cache_key, _load)


def match_hosting_asn_or_org(asn: Any, org_name: Optional[str]) -> Optional[Dict[str, str]]:
    """Checks whether an ASN or organisation name matches configured or built-in hosting rules."""
    asn_map, keyword_pattern = _get_hosting_rules()
    asn_num = _normalize_asn_number(asn)
    if asn_num is not None and asn_num in asn_map:
        return {"provider": asn_map[asn_num], "matchedBy": "asn"}

    if isinstance(org_name, str):
        cleaned_org = org_name.strip()
        if cleaned_org and cleaned_org != "-" and keyword_pattern is not None:
            matched = keyword_pattern.search(cleaned_org)
            if matched:
                return {"provider": matched.group(0), "matchedBy": "keyword"}

    return None


def clear_offline_intelligence_caches() -> None:
    """Clears in-memory hosting ASN rule, stat throttle, mmap, and StopForumSpam caches."""
    _hosting_rules_cache.clear()
    clear_stopforumspam_caches()


def are_offline_intelligence_caches_warm() -> bool:
    """Returns True when offline hosting ASN rule and StopForumSpam caches are populated."""
    return _hosting_rules_cache.is_populated() and are_stopforumspam_caches_warm()


def warm_offline_intelligence_caches() -> None:
    """Preloads offline hosting ASN rules and StopForumSpam offline indexes in the caller thread."""
    _get_hosting_rules()
    warm_stopforumspam_caches()


def _empty_cidr_attribution() -> Dict[str, Any]:
    return {
        "recommendedCidr": None,
        "defaultCidr": None,
        "mmdbCidr": None,
        "sharedCidr": None,
        "sharedProvider": None,
        "sharedCategory": None,
        "cidrNote": None,
        "bgpPrefix": None,
        "escalationCidr": None,
        "cidrRationale": None,
        "isMobileOrCgnat": False,
        "sharedPrivacyEgress": None,
    }


def _clamp_mediawiki_prefix_len(version: int, prefix_len: int) -> int:
    if version == 4:
        return max(_MEDIAWIKI_MIN_IPV4_PREFIX, min(32, prefix_len))
    return max(_MEDIAWIKI_MIN_IPV6_PREFIX, min(128, prefix_len))


def _format_clamped_cidr(addr: ipaddress.IPv4Address | ipaddress.IPv6Address, prefix_len: int) -> str:
    clamped = _clamp_mediawiki_prefix_len(addr.version, prefix_len)
    return str(ipaddress.ip_network(f"{addr.compressed}/{clamped}", strict=False))


def _extract_asn_from_rows(provider_rows: Optional[Iterable[Mapping[str, Any]]]) -> Optional[int]:
    if provider_rows is None:
        return None
    for row in provider_rows:
        if not isinstance(row, Mapping):
            continue
        parsed = _normalize_asn_number(row.get("asn"))
        if parsed is not None:
            return parsed
    return None


def detect_mobile_or_cgnat(
    *,
    ptr_category: Optional[str] = None,
    ptr_hostname: Optional[str] = None,
    asn: Any = None,
    bgp_tags: Iterable[str] = (),
    provider_rows: Optional[Iterable[Mapping[str, Any]]] = None,
    ip_compressed: Optional[str] = None,
) -> bool:
    """Determines whether rDNS, PeeringDB, BGP tags, OpenASN, or provider signals indicate mobile or CGNAT."""
    resolved_ptr = ptr_category
    if not resolved_ptr and ptr_hostname:
        resolved_ptr = classify_rdns_hostname(ptr_hostname)["ptrCategory"]
    if resolved_ptr == "mobile_or_cgnat":
        return True

    asn_num = _normalize_asn_number(asn) or _extract_asn_from_rows(provider_rows)
    if asn_num is not None and is_mobile_asn_offline(asn_num):
        return True

    if any(str(tag).strip().lower() in MOBILE_BGP_TAG_TOKENS for tag in bgp_tags):
        return True

    if provider_rows is not None:
        for row in provider_rows:
            if not isinstance(row, Mapping):
                continue
            status = row.get("status")
            if isinstance(status, str) and status and status != "200 OK":
                continue
            if row.get("isMobile") is True or row.get("coreVerdict") == "mobile":
                return True
            for field_name in ("carrier", "mobileBrand"):
                raw_label = row.get(field_name)
                if isinstance(raw_label, str) and raw_label.strip() and raw_label.strip() != "-":
                    return True
            if str(row.get("usageType") or "").strip().lower() in ("mobile", "cellular"):
                return True

    return bool(ip_compressed and query_openasn_offline(ip_compressed).get("coreVerdict") == "mobile")


def compute_cidr_attribution(  # noqa: C901
    ip: str,
    mmdb_prefix_len: Optional[int] = None,
    shared_cidr: Optional[str] = None,
    shared_provider: Optional[str] = None,
    bgp_prefix: Optional[str] = None,
    *,
    shared_category: Optional[str] = None,
    asn: Any = None,
    org_name: Optional[str] = None,
    ptr_hostname: Optional[str] = None,
    ptr_category: Optional[str] = None,
    provider_rows: Optional[Iterable[Mapping[str, Any]]] = None,
    is_mobile_or_cgnat: Optional[bool] = None,
    is_hosting: Optional[bool] = None,
    highly_suspected_residential_proxy: bool = False,
) -> Dict[str, Any]:
    """
    Computes the recommended block CIDR and optional IPv6 escalation CIDR for an IP address.
    Locks mobile cellular and CGNAT networks to single-host IPv4 or 64-bit IPv6 masks and clamps
    all output prefixes strictly within MediaWiki block boundaries.
    """
    if not ip or not isinstance(ip, str):
        return _empty_cidr_attribution()

    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return _empty_cidr_attribution()

    default_prefix = 24 if addr.version == 4 else 64
    default_cidr = _format_clamped_cidr(addr, default_prefix)
    valid_mmdb_prefix = (
        mmdb_prefix_len
        if not isinstance(mmdb_prefix_len, bool)
        and isinstance(mmdb_prefix_len, int)
        and 0 < mmdb_prefix_len <= addr.max_prefixlen
        else None
    )
    mmdb_cidr = (
        str(ipaddress.ip_network(f"{addr.compressed}/{valid_mmdb_prefix}", strict=False))
        if valid_mmdb_prefix is not None
        else None
    )

    bgp_lookup = lookup_bgp_tools_offline(addr.compressed)
    shared_privacy_egress = lookup_privacy_relay_offline(addr.compressed)

    # Resolve shared-infrastructure attribution (privacy relays, cloud/VPN CIDRs, or OpenASN fallback).
    resolved_shared_cidr: Optional[str] = None
    resolved_shared_provider: Optional[str] = None
    resolved_shared_category: Optional[str] = None
    valid_shared_prefix: Optional[int] = None
    if shared_privacy_egress == "icloud_private_relay":
        resolved_shared_provider, resolved_shared_category = "iCloud Relay", "relay"
    elif shared_privacy_egress == "cloudflare_warp":
        resolved_shared_provider, resolved_shared_category = "Cloudflare WARP", "relay"
    else:
        cand_provider = (
            shared_provider.strip() if isinstance(shared_provider, str) and shared_provider.strip() else None
        )
        cand_category = (
            shared_category.strip().lower() if isinstance(shared_category, str) and shared_category.strip() else None
        )
        raw_cidr = shared_cidr
        if raw_cidr is None and cand_provider is None:
            shared_hit = lookup_shared_cidr_offline(addr.compressed)
            if shared_hit is not None:
                raw_cidr = shared_hit["cidr"]
                cand_provider = shared_hit.get("provider")
                cand_category = shared_hit.get("category")

        if isinstance(raw_cidr, str) and raw_cidr.strip():
            try:
                shared_net = ipaddress.ip_network(raw_cidr.strip(), strict=False)
                if shared_net.version == addr.version and shared_net.prefixlen > 0 and addr in shared_net:
                    resolved_shared_cidr = str(shared_net)
                    resolved_shared_provider = cand_provider
                    resolved_shared_category = cand_category or "cloud"
                    valid_shared_prefix = shared_net.prefixlen
            except ValueError:
                pass

        if resolved_shared_cidr is None and cand_provider is not None:
            resolved_shared_provider = cand_provider
            resolved_shared_category = cand_category or "cloud"
        elif resolved_shared_cidr is None:
            openasn_row = next(
                (
                    row
                    for row in (provider_rows or ())
                    if isinstance(row, Mapping) and row.get("provider") == "OpenASN" and row.get("status") == "200 OK"
                ),
                None,
            )
            if openasn_row is not None:
                oa_verdict = openasn_row.get("coreVerdict")
                oa_cdn = bool(openasn_row.get("isCdn") or (openasn_row.get("rawJson") or {}).get("cdn"))
                oa_dc = bool(
                    openasn_row.get("isDatacenter") or (openasn_row.get("rawJson") or {}).get("datacenterRange")
                )
                oa_org_raw = (
                    openasn_row.get("isp")
                    or openasn_row.get("organisation")
                    or (openasn_row.get("rawJson") or {}).get("asOrg")
                )
            else:
                oa_lookup = query_openasn_offline(addr.compressed)
                if oa_lookup.get("has_db"):
                    oa_verdict = oa_lookup.get("coreVerdict")
                    oa_cdn = bool(oa_lookup.get("cdn"))
                    oa_dc = bool(oa_lookup.get("datacenterRange"))
                    oa_org_raw = oa_lookup.get("asOrg")
                else:
                    oa_verdict, oa_cdn, oa_dc, oa_org_raw = None, False, False, None

            oa_org = (
                oa_org_raw.strip()
                if isinstance(oa_org_raw, str) and oa_org_raw.strip() and oa_org_raw.strip() != "-"
                else None
            )
            if oa_verdict == "enterprise_gateway":
                resolved_shared_provider, resolved_shared_category = (
                    oa_org or "Enterprise Gateway",
                    "enterprise_gateway",
                )
            elif oa_verdict == "hosting" and oa_cdn and not oa_dc:
                resolved_shared_provider, resolved_shared_category = oa_org or "CDN", "cdn"

    is_narrowing_shared = resolved_shared_category in ("cloud", "vpn")
    narrowing_provider = resolved_shared_provider if is_narrowing_shared else None
    narrowing_cidr = resolved_shared_cidr if is_narrowing_shared else None
    narrowing_prefix = valid_shared_prefix if is_narrowing_shared else None

    # Resolve BGP prefix containing addr.
    resolved_bgp_prefix: Optional[str] = None
    valid_bgp_prefix: Optional[int] = None
    bgp_candidates: List[str] = []
    if isinstance(bgp_prefix, str) and bgp_prefix.strip():
        bgp_candidates.append(bgp_prefix.strip())
    if (
        isinstance(bgp_lookup, dict)
        and isinstance(bgp_lookup.get("bgpPrefix"), str)
        and bgp_lookup["bgpPrefix"].strip()
    ):
        bgp_candidates.append(bgp_lookup["bgpPrefix"].strip())
    for raw_bgp in bgp_candidates:
        try:
            net = ipaddress.ip_network(raw_bgp, strict=False)
        except ValueError:
            continue
        if net.version == addr.version and addr in net:
            resolved_bgp_prefix, valid_bgp_prefix = str(net), net.prefixlen
            break

    bgp_tags = bgp_lookup.get("tags", ()) if isinstance(bgp_lookup, dict) else ()
    asn_num = (
        _normalize_asn_number(asn)
        or (_normalize_asn_number(bgp_lookup.get("asn")) if isinstance(bgp_lookup, dict) else None)
        or _extract_asn_from_rows(provider_rows)
    )
    resolved_ptr_category = (
        ptr_category
        if isinstance(ptr_category, str) and ptr_category
        else (classify_rdns_hostname(ptr_hostname)["ptrCategory"] if ptr_hostname else "none")
    )

    if is_mobile_or_cgnat is not None:
        mobile_detected = bool(is_mobile_or_cgnat)
    elif addr.version == 4 and addr in _SHARED_CGNAT_V4_NET:
        mobile_detected = True
    else:
        mobile_detected = detect_mobile_or_cgnat(
            ptr_category=resolved_ptr_category,
            asn=asn_num,
            bgp_tags=bgp_tags,
            provider_rows=provider_rows,
            ip_compressed=addr.compressed,
        )

    if mobile_detected:
        locked_prefix = 32 if addr.version == 4 else 64
        recommended_cidr = _format_clamped_cidr(addr, locked_prefix)
        escalation_cidr: Optional[str] = None
        cidr_note = (
            f"Locked to /{locked_prefix} due to mobile cellular or CGNAT attribution to prevent collateral blocking"
        )
        cidr_rationale = cidr_note
    else:
        narrow_mmdb = valid_mmdb_prefix is not None and valid_mmdb_prefix > default_prefix
        narrow_cloud = narrowing_prefix is not None and narrowing_prefix > default_prefix
        provider_label = f"{narrowing_provider} " if narrowing_provider else ""

        if narrow_mmdb and (not narrow_cloud or (valid_mmdb_prefix or 0) >= (narrowing_prefix or 0)):
            clamped_mmdb = _clamp_mediawiki_prefix_len(addr.version, valid_mmdb_prefix or default_prefix)
            recommended_cidr = _format_clamped_cidr(addr, clamped_mmdb)
            cidr_note = f"Narrower MMDB prefix /{clamped_mmdb} selected over default /{default_prefix} to avoid collateral blocking"
        elif narrow_cloud:
            clamped_cloud = _clamp_mediawiki_prefix_len(addr.version, narrowing_prefix or default_prefix)
            recommended_cidr = _format_clamped_cidr(addr, clamped_cloud)
            cidr_note = (
                f"Narrower {provider_label}cloud prefix /{clamped_cloud} selected over default "
                f"/{default_prefix} to avoid collateral blocking"
            )
        elif valid_mmdb_prefix is not None and valid_mmdb_prefix < default_prefix:
            recommended_cidr = default_cidr
            cidr_note = (
                f"Default /{default_prefix} retained because MMDB prefix "
                f"/{valid_mmdb_prefix} is wider than standard block granularity"
            )
        elif valid_mmdb_prefix == default_prefix:
            recommended_cidr = default_cidr
            cidr_note = f"MMDB prefix matches default /{default_prefix} block granularity"
        elif narrowing_prefix is not None and narrowing_prefix < default_prefix:
            recommended_cidr = default_cidr
            cidr_note = (
                f"Default /{default_prefix} retained because {provider_label}cloud prefix "
                f"/{narrowing_prefix} is wider than standard block granularity"
            )
        elif narrowing_prefix == default_prefix:
            recommended_cidr = default_cidr
            cidr_note = f"{provider_label}Cloud prefix matches default /{default_prefix} block granularity"
        else:
            recommended_cidr = default_cidr
            cidr_note = f"Default /{default_prefix} range selected"

        escalation_cidr = None
        cidr_rationale = cidr_note
        if addr.version == 6:
            if is_hosting is not None:
                hosting_flag = bool(is_hosting)
            elif (
                narrowing_cidr is not None
                or narrowing_provider is not None
                or resolved_ptr_category == "hosting_or_gateway"
                or match_hosting_asn_or_org(asn_num, org_name) is not None
                or any(str(tag).strip().lower() in ("vpn", "hosting", "datacenter", "cloud") for tag in bgp_tags)
            ):
                hosting_flag = True
            else:
                oa_host = query_openasn_offline(addr.compressed)
                oa_v = oa_host.get("coreVerdict")
                hosting_flag = (
                    oa_v == "vpn"
                    or (oa_v == "hosting" and not (oa_host.get("cdn") and not oa_host.get("datacenterRange")))
                    or any(
                        isinstance(row, Mapping)
                        and (
                            not isinstance(row.get("status"), str)
                            or not row.get("status")
                            or row.get("status") == "200 OK"
                        )
                        and any(
                            kw in str(row.get("usageType") or "").strip().lower()
                            for kw in ("hosting", "datacenter", "data center", "cloud")
                        )
                        for row in (provider_rows or ())
                    )
                )

            if hosting_flag:
                raw_candidates = [p for p in (narrowing_prefix, valid_bgp_prefix, valid_mmdb_prefix) if p is not None]
                raw_esc = raw_candidates[0] if raw_candidates else _HOSTING_IPV6_MIN_ESCALATION_PREFIX
                clamped_esc = max(
                    _HOSTING_IPV6_MIN_ESCALATION_PREFIX, min(_HOSTING_IPV6_MAX_ESCALATION_PREFIX, raw_esc)
                )
                escalation_cidr = _format_clamped_cidr(addr, clamped_esc)
                cidr_rationale = f"{cidr_note}; hosting escalation range clamped to /{clamped_esc}"
            elif valid_bgp_prefix is not None and valid_bgp_prefix <= _RESIDENTIAL_IPV6_MAX_BGP_FOR_ESCALATION:
                escalation_cidr = _format_clamped_cidr(addr, _RESIDENTIAL_IPV6_ESCALATION_PREFIX)
                cidr_rationale = f"{cidr_note}; residential /{_RESIDENTIAL_IPV6_ESCALATION_PREFIX} escalation available within BGP /{valid_bgp_prefix}"

    if shared_privacy_egress is not None:
        cidr_rationale = f"{cidr_rationale}; shared privacy egress ({shared_privacy_egress})"

    if highly_suspected_residential_proxy:
        locked_prefix = 32 if addr.version == 4 else 128
        recommended_cidr = _format_clamped_cidr(addr, locked_prefix)
        escalation_cidr = None
        cidr_note = "Highly suspected residential proxy: use the single IP only and proceed with discretion on CIDR."
        cidr_rationale = cidr_note

    return {
        "recommendedCidr": recommended_cidr,
        "defaultCidr": default_cidr,
        "mmdbCidr": mmdb_cidr,
        "sharedCidr": resolved_shared_cidr,
        "sharedProvider": resolved_shared_provider,
        "sharedCategory": resolved_shared_category,
        "cidrNote": cidr_note,
        "bgpPrefix": resolved_bgp_prefix,
        "escalationCidr": escalation_cidr,
        "cidrRationale": cidr_rationale,
        "isMobileOrCgnat": mobile_detected,
        "sharedPrivacyEgress": shared_privacy_egress,
    }
