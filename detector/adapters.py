"""
Response adapters normalising upstream IP intelligence payloads into a unified schema.
"""

import ipaddress
import json
import logging
import math
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .offline_dbs import (
    PrefixCidrIndex,
    _get_file_stat_signature,
    resolve_cloud_cidr_path,
    resolve_configured_data_dir,
)
from .offline_dbs import (
    _get_setting as _get_django_setting,
)

logger = logging.getLogger(__name__)


def _safe_int(val: Any, default: Optional[int] = 0) -> Optional[int]:
    """Converts a numeric-looking value to int, falling back to default for null, NaN, booleans or garbage."""
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
    """
    Downgrades non-dict upstream bodies such as arrays or bare strings to an upstream format error,
    so adapters never call dict methods on them.
    """
    if raw_data is None or isinstance(raw_data, dict):
        return raw_data, status_code
    error_payload = {
        "status": "error",
        "message": f"Unexpected upstream payload type: {type(raw_data).__name__}",
    }
    return error_payload, (502 if status_code == 200 else status_code)


_ERROR_STATUS_LABELS: Dict[int, str] = {
    401: "401 Unauthorised",
    429: "429 Rate Limited",
}


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

    resolved_flags = security_flags if security_flags is not None else [{"label": "No Flags", "isHighRisk": False}]
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

_HOSTING_GATEWAY_TOKENS = {
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

_DYNAMIC_RESIDENTIAL_TOKENS = {
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
    "mobile",
    "cellular",
    "lte",
    "gprs",
    "umts",
    "cdma",
    "wireless",
    "cpe",
    "dialup",
    "dial",
    "hsd",
}


def classify_rdns_hostname(hostname: Optional[str]) -> Dict[str, Any]:
    """Classifies a reverse DNS PTR hostname into residential, cloud gateway, or unclassified categories."""
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


_REPO_PARENT_DIR = Path(__file__).resolve().parent.parent.parent

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

_CLOUD_SERVICE_ALIASES: Dict[str, str] = {
    "amazon": "Amazon AWS",
    "aws": "Amazon AWS",
    "amazon aws": "Amazon AWS",
    "google": "Google Cloud",
    "gcp": "Google Cloud",
    "google cloud": "Google Cloud",
    "oracle": "Oracle Cloud",
    "oci": "Oracle Cloud",
    "oracle cloud": "Oracle Cloud",
    "azure": "Microsoft Azure",
    "microsoft azure": "Microsoft Azure",
}

_offline_cache_lock = threading.Lock()
_cloud_cidr_cache_key: Optional[Tuple[str, Tuple[int, int] | int]] = None
_cloud_cidr_cache_index: Optional["_CloudCidrIndex"] = None
_hosting_rules_cache_key: Optional[Tuple[Any, ...]] = None
_hosting_rules_cache_data: Optional[Tuple[Dict[int, str], Optional[re.Pattern[str]]]] = None


def _resolve_offline_file(setting_name: str, filenames: Tuple[str, ...]) -> Optional[Path]:
    configured = str(_get_django_setting(setting_name, "") or "").strip()
    base_dir = _get_django_setting("BASE_DIR", Path(__file__).resolve().parent.parent)
    try:
        from proxycheck.settings import resolve_data_file
    except ImportError:
        resolve_data_file = None

    if configured:
        configured_path = Path(configured)
        if configured_path.is_file():
            return configured_path
        if configured_path.is_dir():
            for fname in filenames:
                candidate = configured_path / fname
                if candidate.is_file():
                    return candidate
            return None
        default_missing = _REPO_PARENT_DIR / "data" / filenames[0]
        if configured_path != default_missing:
            return None

    if resolve_data_file is not None:
        for fname in filenames:
            resolved = resolve_data_file("", fname, base_dir, default_missing="")
            if resolved:
                candidate = Path(resolved)
                if candidate.is_file():
                    return candidate
    return None


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


def _normalize_cloud_provider_name(raw_name: Any, default: str = "Cloud Provider") -> str:
    if isinstance(raw_name, str):
        cleaned = raw_name.strip()
        if cleaned:
            return _CLOUD_SERVICE_ALIASES.get(cleaned.lower(), cleaned)
    return default


def _parse_cloud_cidr_list(items: List[Any], default_provider: str) -> List[Tuple[str, str]]:
    """Extracts (cidr, provider_name) entries from a list of CIDR strings or rule objects."""
    entries: List[Tuple[str, str]] = []
    for item in items:
        if isinstance(item, str):
            entries.append((item, default_provider))
            continue
        if not isinstance(item, dict):
            continue
        raw_cidr = (
            item.get("range")
            or item.get("cidr")
            or item.get("prefix")
            or item.get("ip_prefix")
            or item.get("ipv6_prefix")
        )
        if isinstance(raw_cidr, str):
            provider_name = _normalize_cloud_provider_name(
                item.get("provider") or item.get("providerName") or item.get("service") or item.get("name"),
                default=default_provider,
            )
            entries.append((raw_cidr, provider_name))
    return entries


def _parse_aws_ip_ranges(payload: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Extracts IPv4 and IPv6 prefixes from an AWS ip-ranges document."""
    entries: List[Tuple[str, str]] = []
    for key in ("prefixes", "ipv6_prefixes"):
        prefix_list = payload.get(key)
        if not isinstance(prefix_list, list):
            continue
        for item in prefix_list:
            if not isinstance(item, dict):
                continue
            raw_cidr = item.get("ip_prefix") or item.get("ipv6_prefix") or item.get("cidr") or item.get("range")
            if isinstance(raw_cidr, str):
                entries.append((raw_cidr, "Amazon AWS"))
    return entries


def _parse_cloud_cidr_payload(payload: Any, default_provider: str = "Cloud Provider") -> List[Tuple[str, str]]:
    """Extracts (cidr, provider_name) entries from computehosts, AWS ip-ranges, or provider-keyed JSON."""
    if isinstance(payload, list):
        return _parse_cloud_cidr_list(payload, default_provider)

    if not isinstance(payload, dict):
        return []

    if isinstance(payload.get("prefixes"), list) or isinstance(payload.get("ipv6_prefixes"), list):
        return _parse_aws_ip_ranges(payload)

    entries: List[Tuple[str, str]] = []
    for key, value in payload.items():
        if not isinstance(key, str) or not isinstance(value, list):
            continue
        provider_name = (
            default_provider
            if key.strip().lower() in ("ranges", "cidrs", "entries", "items")
            else _normalize_cloud_provider_name(key, default=default_provider)
        )
        entries.extend(_parse_cloud_cidr_payload(value, default_provider=provider_name))
    return entries


class _CloudCidrIndex(PrefixCidrIndex[str]):
    """In-memory prefix-bucketed index for fast IPv4 and IPv6 cloud CIDR matching."""

    def match(self, ip: Optional[str]) -> Optional[Dict[str, Any]]:
        hit = self.lookup(ip)
        if hit is None:
            return None
        return {
            "cidr": hit[0],
            "prefixLength": hit[1],
            "provider": hit[2],
        }


_EMPTY_CLOUD_CIDR_INDEX = _CloudCidrIndex(())


def _get_cloud_cidr_index() -> _CloudCidrIndex:
    global _cloud_cidr_cache_key, _cloud_cidr_cache_index

    path, _ = resolve_cloud_cidr_path()
    if path is None:
        configured = resolve_configured_data_dir()
        missing_key = (f"__missing__:{configured}", -1)
        with _offline_cache_lock:
            _cloud_cidr_cache_key = missing_key
            _cloud_cidr_cache_index = _EMPTY_CLOUD_CIDR_INDEX
        return _EMPTY_CLOUD_CIDR_INDEX

    stat_sig = _get_file_stat_signature(path)
    if stat_sig is None:
        return _EMPTY_CLOUD_CIDR_INDEX

    cache_key = (str(path), stat_sig)
    with _offline_cache_lock:
        if _cloud_cidr_cache_key == cache_key and _cloud_cidr_cache_index is not None:
            return _cloud_cidr_cache_index

    try:
        raw_payload = json.loads(path.read_text(encoding="utf-8"))
        entries = _parse_cloud_cidr_payload(raw_payload)
        index = _CloudCidrIndex(entries)
    except (OSError, ValueError) as exc:
        logger.warning("Failed to load cloud CIDR data from %s: %s", path, exc)
        return _EMPTY_CLOUD_CIDR_INDEX

    with _offline_cache_lock:
        _cloud_cidr_cache_key = cache_key
        _cloud_cidr_cache_index = index
    return index


def match_cloud_cidr(ip: Optional[str]) -> Optional[Dict[str, Any]]:
    """Matches an IPv4 or IPv6 address against the cached in-memory cloud CIDR index."""
    return _get_cloud_cidr_index().match(ip)


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
                for kw in raw_kws:
                    if isinstance(kw, str) and kw.strip():
                        keywords.append(kw.strip().lower())
    else:
        parsed_asn = _normalize_asn_number(entry)
        if parsed_asn is not None:
            asn_map[parsed_asn] = f"AS{parsed_asn}"


def _ingest_hosting_asns_block(raw_asns: Any, asn_map: Dict[int, str], keywords: List[str]) -> None:
    """Ingests top-level ASN mappings or rule lists into asn_map and keywords."""
    if isinstance(raw_asns, dict):
        for k, v in raw_asns.items():
            parsed_asn = _normalize_asn_number(k)
            if parsed_asn is not None:
                asn_map[parsed_asn] = v.strip() if isinstance(v, str) and v.strip() else f"AS{parsed_asn}"
    elif isinstance(raw_asns, list):
        for item in raw_asns:
            _ingest_hosting_rule_entry(item, asn_map, keywords)


def _ingest_hosting_keywords_block(mapping: Dict[str, Any], keywords: List[str]) -> None:
    """Collects normalised hosting organisation keywords from a rule mapping."""
    for kw_key in ("keywords", "orgKeywords", "searchterms"):
        raw_kws = mapping.get(kw_key)
        if isinstance(raw_kws, list):
            keywords.extend(kw.strip().lower() for kw in raw_kws if isinstance(kw, str) and kw.strip())


def _parse_hosting_rules_payload(payload: Any) -> Tuple[Dict[int, str], List[str]]:
    """Extracts hosting ASN labels and organisation keywords from rule JSON."""
    asn_map: Dict[int, str] = {}
    keywords: List[str] = []

    if isinstance(payload, list):
        for item in payload:
            _ingest_hosting_rule_entry(item, asn_map, keywords)
        return asn_map, keywords

    if not isinstance(payload, dict):
        return asn_map, keywords

    _ingest_hosting_asns_block(payload.get("asns"), asn_map, keywords)
    for hosts_key in ("hosts", "providers", "rules"):
        raw_hosts = payload.get(hosts_key)
        entries = (
            raw_hosts if isinstance(raw_hosts, list) else (raw_hosts.values() if isinstance(raw_hosts, dict) else ())
        )
        for entry in entries:
            _ingest_hosting_rule_entry(entry, asn_map, keywords)
    _ingest_hosting_keywords_block(payload, keywords)
    return asn_map, keywords


def _build_hosting_keyword_pattern(keywords: Iterable[str]) -> Optional[re.Pattern[str]]:
    unique_keywords = sorted(
        {kw.strip().lower() for kw in keywords if isinstance(kw, str) and kw.strip()}, key=len, reverse=True
    )
    if not unique_keywords:
        return None
    escaped = "|".join(re.escape(kw) for kw in unique_keywords)
    return re.compile(rf"(?<![a-z0-9])(?:{escaped})(?![a-z0-9])", re.IGNORECASE)


def _normalize_setting_sequence(raw_val: Any) -> Tuple[str, ...]:
    if isinstance(raw_val, str):
        return tuple(part.strip() for part in raw_val.split(",") if part.strip())
    if isinstance(raw_val, (list, tuple, set, frozenset)):
        return tuple(str(part).strip() for part in raw_val if str(part).strip())
    return ()


def _get_hosting_rules() -> Tuple[Dict[int, str], Optional[re.Pattern[str]]]:
    global _hosting_rules_cache_key, _hosting_rules_cache_data

    path = _resolve_offline_file("HOSTING_ASN_RULES_PATH", ("hosting_asn_rules.json",))
    mtime_ns = 0
    path_str = ""
    if path is not None:
        try:
            mtime_ns = path.stat().st_mtime_ns
            path_str = str(path)
        except OSError:
            path = None

    configured_asns = _normalize_setting_sequence(_get_django_setting("HOSTING_ASNS", ()))
    configured_keywords = _normalize_setting_sequence(_get_django_setting("HOSTING_ORG_KEYWORDS", ()))
    cache_key = (path_str, mtime_ns, configured_asns, configured_keywords)

    with _offline_cache_lock:
        if _hosting_rules_cache_key == cache_key and _hosting_rules_cache_data is not None:
            return _hosting_rules_cache_data

    asn_map: Dict[int, str] = dict(_BUILTIN_HOSTING_ASNS)
    keywords: List[str] = list(_BUILTIN_HOSTING_ORG_KEYWORDS)

    if path is not None:
        try:
            raw_payload = json.loads(path.read_text(encoding="utf-8"))
            file_asns, file_keywords = _parse_hosting_rules_payload(raw_payload)
            asn_map.update(file_asns)
            keywords.extend(file_keywords)
        except (OSError, ValueError) as exc:
            logger.warning("Failed to load hosting ASN rules from %s: %s", path, exc)

    for raw_asn in configured_asns:
        parsed_asn = _normalize_asn_number(raw_asn)
        if parsed_asn is not None and parsed_asn not in asn_map:
            asn_map[parsed_asn] = f"AS{parsed_asn}"
    for raw_kw in configured_keywords:
        keywords.append(raw_kw.lower())

    compiled_pattern = _build_hosting_keyword_pattern(keywords)
    result = (asn_map, compiled_pattern)

    with _offline_cache_lock:
        _hosting_rules_cache_key = cache_key
        _hosting_rules_cache_data = result
    return result


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
    """Clears in-memory cloud CIDR, hosting ASN rule, and StopForumSpam offline caches."""
    global _cloud_cidr_cache_key, _cloud_cidr_cache_index, _hosting_rules_cache_key, _hosting_rules_cache_data
    from .offline_dbs import clear_stopforumspam_caches

    with _offline_cache_lock:
        _cloud_cidr_cache_key = None
        _cloud_cidr_cache_index = None
        _hosting_rules_cache_key = None
        _hosting_rules_cache_data = None
    clear_stopforumspam_caches()


def are_offline_intelligence_caches_warm() -> bool:
    """Returns True when offline cloud CIDR, hosting ASN rule, and StopForumSpam caches are populated."""
    from .offline_dbs import are_stopforumspam_caches_warm

    with _offline_cache_lock:
        rules_warm = _cloud_cidr_cache_index is not None and _hosting_rules_cache_data is not None
    return rules_warm and are_stopforumspam_caches_warm()


def warm_offline_intelligence_caches() -> None:
    """Preloads offline cloud CIDR, hosting ASN rules, and StopForumSpam offline indexes in the caller thread."""
    from .offline_dbs import warm_stopforumspam_caches

    _get_cloud_cidr_index()
    _get_hosting_rules()
    warm_stopforumspam_caches()


def _format_asn_str(asn_val: Any) -> str:
    """Formats a non-empty ASN value with a leading AS prefix, falling back to a hyphen."""
    return f"AS{asn_val}" if asn_val and not str(asn_val).startswith("AS") else (str(asn_val) if asn_val else "-")


def _format_numeric_or_prefixed_asn(asn_val: Any) -> str:
    """Formats a positive numeric ASN or uppercase AS-prefixed string, falling back to a hyphen."""
    asn_int = _safe_int(asn_val, default=None)
    if asn_int is not None and asn_int > 0:
        return f"AS{asn_int}"
    if isinstance(asn_val, str) and asn_val.strip().upper().startswith("AS"):
        return asn_val.strip().upper()
    return "-"


def _extract_carrier_name(carrier_val: Any) -> Optional[str]:
    """Extracts a clean carrier name from a provider carrier dictionary or string."""
    if isinstance(carrier_val, dict):
        candidate = carrier_val.get("name")
    elif isinstance(carrier_val, str):
        candidate = carrier_val
    else:
        return None
    if isinstance(candidate, str):
        cleaned = candidate.strip()
        if cleaned and cleaned != "-":
            return cleaned
    return None


def _empty_cidr_attribution() -> Dict[str, Optional[str]]:
    return {
        "recommendedCidr": None,
        "defaultCidr": None,
        "mmdbCidr": None,
        "cloudCidr": None,
        "cloudProvider": None,
        "cidrNote": None,
    }


def _resolve_cloud_cidr_attribution(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    cloud_cidr: Optional[str],
    cloud_provider: Optional[str],
) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """Validates or looks up matching cloud CIDR metadata for the target IP."""
    resolved_provider = cloud_provider.strip() if isinstance(cloud_provider, str) and cloud_provider.strip() else None
    raw_cloud_cidr = cloud_cidr
    if raw_cloud_cidr is None:
        cloud_hit = match_cloud_cidr(addr.compressed)
        if cloud_hit is not None:
            raw_cloud_cidr = cloud_hit["cidr"]
            if resolved_provider is None:
                resolved_provider = cloud_hit.get("provider")

    if isinstance(raw_cloud_cidr, str) and raw_cloud_cidr.strip():
        try:
            cloud_net = ipaddress.ip_network(raw_cloud_cidr.strip(), strict=False)
            if cloud_net.version == addr.version and cloud_net.prefixlen > 0 and addr in cloud_net:
                return str(cloud_net), resolved_provider, cloud_net.prefixlen
        except ValueError:
            pass
    return None, None, None


def _select_cidr_recommendation(
    default_cidr: str,
    default_prefix: int,
    mmdb_cidr: Optional[str],
    valid_mmdb_prefix: Optional[int],
    resolved_cloud_cidr: Optional[str],
    resolved_cloud_provider: Optional[str],
    valid_cloud_prefix: Optional[int],
) -> Tuple[str, str]:
    """Selects the recommended CIDR and human-readable rationale note."""
    narrow_mmdb = valid_mmdb_prefix is not None and valid_mmdb_prefix > default_prefix
    narrow_cloud = valid_cloud_prefix is not None and valid_cloud_prefix > default_prefix
    provider_label = f"{resolved_cloud_provider} " if resolved_cloud_provider else ""

    if (
        narrow_mmdb
        and mmdb_cidr is not None
        and (not narrow_cloud or (valid_mmdb_prefix or 0) >= (valid_cloud_prefix or 0))
    ):
        return mmdb_cidr, (
            f"Narrower MMDB prefix /{valid_mmdb_prefix} selected over default "
            f"/{default_prefix} to avoid collateral blocking"
        )
    if narrow_cloud and resolved_cloud_cidr is not None:
        return resolved_cloud_cidr, (
            f"Narrower {provider_label}cloud prefix /{valid_cloud_prefix} selected over default "
            f"/{default_prefix} to avoid collateral blocking"
        )
    if valid_mmdb_prefix is not None and valid_mmdb_prefix < default_prefix:
        note = (
            f"Default /{default_prefix} retained because MMDB prefix "
            f"/{valid_mmdb_prefix} is wider than standard block granularity"
        )
    elif valid_mmdb_prefix == default_prefix:
        note = f"MMDB prefix matches default /{default_prefix} block granularity"
    elif valid_cloud_prefix is not None and valid_cloud_prefix < default_prefix:
        note = (
            f"Default /{default_prefix} retained because {provider_label}cloud prefix "
            f"/{valid_cloud_prefix} is wider than standard block granularity"
        )
    elif valid_cloud_prefix == default_prefix:
        note = f"{provider_label}Cloud prefix matches default /{default_prefix} block granularity"
    else:
        note = f"Default /{default_prefix} range selected"
    return default_cidr, note


def compute_cidr_attribution(
    ip: str,
    mmdb_prefix_len: Optional[int] = None,
    cloud_cidr: Optional[str] = None,
    cloud_provider: Optional[str] = None,
) -> Dict[str, Optional[str]]:
    """
    Computes the recommended block CIDR range for an IPv4 or IPv6 address.
    Uses prefix length 24 for IPv4 and 64 for IPv6 by default, preferring a narrower MaxMind or
    official cloud prefix when available to prevent collateral blocks while capping wider prefixes.
    """
    if not ip or not isinstance(ip, str):
        return _empty_cidr_attribution()

    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return _empty_cidr_attribution()

    default_prefix = 24 if addr.version == 4 else 64
    default_cidr = str(ipaddress.ip_network(f"{addr.compressed}/{default_prefix}", strict=False))
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
    resolved_cloud_cidr, resolved_cloud_provider, valid_cloud_prefix = _resolve_cloud_cidr_attribution(
        addr, cloud_cidr, cloud_provider
    )
    recommended_cidr, cidr_note = _select_cidr_recommendation(
        default_cidr,
        default_prefix,
        mmdb_cidr,
        valid_mmdb_prefix,
        resolved_cloud_cidr,
        resolved_cloud_provider,
        valid_cloud_prefix,
    )
    return {
        "recommendedCidr": recommended_cidr,
        "defaultCidr": default_cidr,
        "mmdbCidr": mmdb_cidr,
        "cloudCidr": resolved_cloud_cidr,
        "cloudProvider": resolved_cloud_provider,
        "cidrNote": cidr_note,
    }


def adapt_cloudflare_radar(
    raw_data: Optional[Dict[str, Any]], has_api_key: bool, status_code: int = 200
) -> Dict[str, Any]:
    if not has_api_key:
        return _build_error_row("Cloudflare Radar", security_flags=[])

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data or not raw_data.get("success", False):
        return _build_error_row("Cloudflare Radar", status_code, raw_data, security_flags=[])

    result_obj = raw_data.get("result")
    asn_obj = result_obj.get("asn") if isinstance(result_obj, dict) else None
    if not isinstance(asn_obj, dict):
        asn_obj = {}
    asn_num = asn_obj.get("asn")
    asn_str = f"AS{asn_num}" if asn_num is not None else "-"
    org_name = asn_obj.get("name") or asn_obj.get("orgName") or "-"
    country = asn_obj.get("countryName") or asn_obj.get("country") or "-"

    return {
        "provider": "Cloudflare Radar",
        "status": "200 OK",
        "statusCode": 200,
        "asn": asn_str,
        "isp": org_name,
        "organisation": org_name,
        "location": country,
        "usageType": asn_obj.get("type") or "infrastructure",
        "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
        "countryCode": asn_obj.get("country"),
        "rawJson": raw_data,
    }


def adapt_abuseipdb(raw_data: Optional[Dict[str, Any]], has_api_key: bool, status_code: int = 200) -> Dict[str, Any]:
    extra = {"totalReports": None, "numDistinctUsers": None, "lastSeen": None}
    if not has_api_key:
        return _build_error_row("AbuseIPDB", extra=extra)

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data or not isinstance(raw_data.get("data"), dict):
        return _build_error_row("AbuseIPDB", status_code, raw_data, extra=extra)

    data = raw_data["data"]
    flags: List[Dict[str, Any]] = []
    raw_usage = data.get("usageType")
    usage_type = raw_usage.strip() if isinstance(raw_usage, str) and raw_usage.strip() else "-"
    usage_lower = usage_type.lower()
    is_datacenter_usage = any(kw in usage_lower for kw in ("data center", "datacenter", "web hosting", "transit"))

    if data.get("isTor"):
        flags.append({"label": "Tor Exit Node", "isHighRisk": True})
    if is_datacenter_usage:
        flags.append({"label": "Datacenter / Hosting", "isHighRisk": True})

    loc_parts = [p for p in [data.get("countryName"), data.get("countryCode")] if p]
    location = ", ".join(loc_parts) if loc_parts else "-"

    raw_total_reports = _safe_int(data.get("totalReports"), default=None)
    total_reports = max(0, raw_total_reports) if raw_total_reports is not None else None
    raw_distinct_users = _safe_int(data.get("numDistinctUsers"), default=None)
    num_distinct_users = max(0, raw_distinct_users) if raw_distinct_users is not None else None
    last_seen = _normalize_timestamp_or_text(data.get("lastReportedAt"))

    isp_val = data.get("isp") or "-"
    return {
        "provider": "AbuseIPDB",
        "status": "200 OK",
        "statusCode": 200,
        "asn": "-",
        "isp": isp_val,
        "organisation": isp_val,
        "location": location,
        "usageType": usage_type,
        "securityFlags": flags if flags else [{"label": "No Flags", "isHighRisk": False}],
        "totalReports": total_reports,
        "numDistinctUsers": num_distinct_users,
        "lastSeen": last_seen,
        "countryCode": data.get("countryCode"),
        "rawJson": raw_data,
    }


def adapt_ipdata(raw_data: Optional[Dict[str, Any]], has_api_key: bool, status_code: int = 200) -> Dict[str, Any]:
    if not has_api_key:
        return _build_error_row("IPData", extra={"carrier": None})

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data or "message" in raw_data:
        return _build_error_row("IPData", status_code, raw_data, extra={"carrier": None})

    threat = raw_data.get("threat")
    if not isinstance(threat, dict):
        threat = {}
    company = raw_data.get("company")
    if not isinstance(company, dict):
        company = {}
    flags: List[Dict[str, Any]] = []

    if threat.get("is_proxy"):
        flags.append({"label": "Proxy", "isHighRisk": True})
    if threat.get("is_datacenter"):
        flags.append({"label": "Datacenter", "isHighRisk": True})
    if threat.get("is_tor"):
        flags.append({"label": "Tor", "isHighRisk": True})
    if threat.get("is_vpn"):
        flags.append({"label": "VPN", "isHighRisk": True})
    if threat.get("is_icloud_relay"):
        flags.append({"label": "iCloud Private Relay", "isHighRisk": True})
    if threat.get("is_known_attacker"):
        flags.append({"label": "Known Attacker", "isHighRisk": True})

    asn_val = raw_data.get("asn")
    if isinstance(asn_val, dict):
        asn_num = asn_val.get("asn") or asn_val.get("number")
        asn_str = str(asn_num) if str(asn_num).startswith("AS") else f"AS{asn_num}" if asn_num else "-"
        org_fallback = asn_val.get("name")
    elif asn_val:
        asn_str = str(asn_val) if str(asn_val).startswith("AS") else f"AS{asn_val}"
        org_fallback = None
    else:
        asn_str = "-"
        org_fallback = None

    loc_parts = [p for p in [raw_data.get("city"), raw_data.get("region"), raw_data.get("country_name")] if p]
    loc_str = ", ".join(loc_parts)
    lat = raw_data.get("latitude")
    lon = raw_data.get("longitude")
    coords = f"{lat}, {lon}" if lat is not None and lon is not None else None
    if coords:
        loc_str += f" ({coords})"
    location = loc_str if loc_str else "-"

    carrier_name = _extract_carrier_name(raw_data.get("carrier"))
    company_type = company.get("type")
    normalized_company_type = company_type.strip() if isinstance(company_type, str) and company_type.strip() else None
    usage_type = normalized_company_type or ("mobile" if carrier_name else "-")
    isp_name = raw_data.get("organisation") or org_fallback or company.get("name") or carrier_name or "-"

    return {
        "provider": "IPData",
        "status": "200 OK",
        "statusCode": 200,
        "asn": asn_str,
        "isp": isp_name,
        "organisation": isp_name,
        "location": location,
        "usageType": usage_type,
        "securityFlags": flags if flags else [{"label": "No Flags", "isHighRisk": False}],
        "carrier": carrier_name,
        "countryCode": raw_data.get("country_code"),
        "coordinates": coords,
        "rawJson": raw_data,
    }


def adapt_ipregistry(raw_data: Optional[Dict[str, Any]], has_api_key: bool, status_code: int = 200) -> Dict[str, Any]:
    if not has_api_key:
        return _build_error_row("IPRegistry", extra={"isMobile": False})

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data or "code" in raw_data:
        return _build_error_row("IPRegistry", status_code, raw_data, extra={"isMobile": False})

    security = raw_data.get("security")
    if not isinstance(security, dict):
        security = {}
    connection = raw_data.get("connection")
    if not isinstance(connection, dict):
        connection = {}
    loc = raw_data.get("location")
    if not isinstance(loc, dict):
        loc = {}
    conn_type = connection.get("type") or "-"
    conn_type_lower = str(conn_type).strip().lower()
    is_hosting_conn = conn_type_lower in ("hosting", "datacenter")
    is_mobile_conn = conn_type_lower == "mobile"
    is_relay = bool(security.get("is_relay"))
    is_abuser = bool(security.get("is_abuser"))

    flags: List[Dict[str, Any]] = []
    if security.get("is_proxy"):
        flags.append({"label": "Proxy", "isHighRisk": True})
    if security.get("is_vpn"):
        flags.append({"label": "VPN", "isHighRisk": True})
    if security.get("is_tor"):
        flags.append({"label": "Tor", "isHighRisk": True})
    if is_relay:
        flags.append({"label": "Relay", "isHighRisk": True})
    if is_abuser:
        flags.append({"label": "Known Abuser", "isHighRisk": True})
    if security.get("is_threat"):
        flags.append({"label": "Threat Detected", "isHighRisk": True})
    if security.get("is_cloud_provider"):
        flags.append({"label": "Cloud Provider", "isHighRisk": True})
    elif is_hosting_conn:
        flags.append({"label": "Hosting", "isHighRisk": True})

    asn_num = connection.get("asn")
    asn_str = f"AS{asn_num}" if asn_num else "-"

    region_obj = loc.get("region") if isinstance(loc.get("region"), dict) else {}
    country_obj = loc.get("country") if isinstance(loc.get("country"), dict) else {}
    loc_parts = [p for p in [loc.get("city"), region_obj.get("name"), country_obj.get("name")] if p]
    loc_str = ", ".join(loc_parts)
    lat = loc.get("latitude")
    lon = loc.get("longitude")
    coords = f"{lat}, {lon}" if lat is not None and lon is not None else None
    if coords:
        loc_str += f" ({coords})"
    location = loc_str if loc_str else "-"

    org_val = connection.get("organization") or "-"
    country_code = country_obj.get("code")

    return {
        "provider": "IPRegistry",
        "status": "200 OK",
        "statusCode": 200,
        "asn": asn_str,
        "isp": org_val,
        "organisation": org_val,
        "location": location,
        "usageType": conn_type,
        "securityFlags": flags if flags else [{"label": "No Flags", "isHighRisk": False}],
        "isMobile": is_mobile_conn,
        "countryCode": country_code,
        "coordinates": coords,
        "rawJson": raw_data,
    }


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

    proxy_obj = raw_data.get("proxy")
    if not isinstance(proxy_obj, dict):
        proxy_obj = {}
    flags: List[Dict[str, Any]] = []

    is_proxy = bool(raw_data.get("is_proxy") or proxy_obj.get("is_proxy"))
    is_vpn = bool(proxy_obj.get("is_vpn"))
    is_tor = bool(proxy_obj.get("is_tor"))
    is_data_center = bool(proxy_obj.get("is_data_center"))
    is_spam = bool(proxy_obj.get("is_spammer") or proxy_obj.get("is_scanner") or proxy_obj.get("is_botnet"))

    if is_proxy:
        flags.append({"label": "Proxy", "isHighRisk": True})
    if is_vpn:
        flags.append({"label": "VPN", "isHighRisk": True})
    if is_tor:
        flags.append({"label": "Tor", "isHighRisk": True})
    if is_data_center:
        flags.append({"label": "Datacenter", "isHighRisk": True})
    if is_spam:
        flags.append({"label": "Threat Detected", "isHighRisk": True})

    asn_str = _format_asn_str(raw_data.get("asn"))

    loc_parts = [p for p in [raw_data.get("city_name"), raw_data.get("region_name"), raw_data.get("country_name")] if p]
    loc_str = ", ".join(loc_parts)
    lat = raw_data.get("latitude")
    lon = raw_data.get("longitude")
    coords = f"{lat}, {lon}" if lat is not None and lon is not None else None
    if coords:
        loc_str += f" ({coords})"
    location = loc_str if loc_str else "-"

    raw_mobile_brand = raw_data.get("mobile_brand")
    mobile_brand = (
        raw_mobile_brand.strip()
        if isinstance(raw_mobile_brand, str) and raw_mobile_brand.strip() and raw_mobile_brand.strip() != "-"
        else None
    )
    raw_usage = raw_data.get("usage_type") or proxy_obj.get("proxy_type")
    cleaned_usage = raw_usage.strip() if isinstance(raw_usage, str) and raw_usage.strip() else ""
    usage_type = cleaned_usage if cleaned_usage and cleaned_usage != "-" else ("mobile" if mobile_brand else "-")
    isp_val = raw_data.get("as") or raw_data.get("isp") or mobile_brand or "-"

    return {
        "provider": "IP2Location",
        "status": "200 OK",
        "statusCode": 200,
        "asn": asn_str,
        "isp": isp_val,
        "organisation": isp_val,
        "location": location,
        "usageType": usage_type,
        "securityFlags": flags if flags else [{"label": "No Flags", "isHighRisk": False}],
        "mobileBrand": mobile_brand,
        "countryCode": raw_data.get("country_code"),
        "coordinates": coords,
        "rawJson": raw_data,
    }


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

    loc_obj = raw_data.get("location") or {}
    lat = loc_obj.get("latitude") if isinstance(loc_obj, dict) else None
    lon = loc_obj.get("longitude") if isinstance(loc_obj, dict) else None
    has_coords = (
        lat is not None
        and lon is not None
        and not isinstance(lat, bool)
        and not isinstance(lon, bool)
        and str(lat).strip() != ""
        and str(lon).strip() != ""
    )
    coords = f"{lat}, {lon}" if has_coords else None

    loc_parts: List[str] = []
    seen_parts = set()
    for part in (city_name, subdivision_name, country_name):
        if part and part.lower() not in seen_parts:
            loc_parts.append(part)
            seen_parts.add(part.lower())

    loc_str = ", ".join(loc_parts) if loc_parts else "-"
    if coords:
        loc_str = f"{loc_str} ({coords})" if loc_parts else f"Unknown ({coords})"
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

    flag_specs = (
        ("Tor", bool(traits.get("is_tor_exit_node"))),
        ("Proxy", bool(traits.get("is_anonymous_proxy") or traits.get("is_public_proxy"))),
        ("VPN", bool(traits.get("is_anonymous_vpn"))),
        ("Hosting", is_hosting),
    )
    flags = [{"label": label, "isHighRisk": True} for label, active in flag_specs if active]
    return usage_type, flags or [{"label": "No Flags", "isHighRisk": False}]


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
    asn_str = _format_asn_str(asn_val)
    org_name = raw_data.get("autonomous_system_organization") or raw_data.get("as") or raw_data.get("isp") or "-"
    loc_str, country_code, coords = _extract_maxmind_geo(raw_data)

    target_ip = ip if isinstance(ip, str) and ip.strip() else raw_data.get("_ip")
    cloud_match = match_cloud_cidr(target_ip) if target_ip else None
    hosting_match = match_hosting_asn_or_org(asn_val, org_name)
    usage_type, flags = _extract_maxmind_signals(raw_data, cloud_match=cloud_match, hosting_match=hosting_match)

    raw_prefix_val = raw_data.get("_mmdb_prefix_len")
    if raw_prefix_val is None:
        raw_prefix_val = raw_data.get("prefix_len")
    prefix_length = _safe_int(raw_prefix_val, default=None)
    if prefix_length is not None and not (0 < prefix_length <= 128):
        prefix_length = None

    internal_keys = ("_mmdb_prefix_len", "_ip", "_offline_db_updated_at")
    clean_raw_json = (
        {k: v for k, v in raw_data.items() if k not in internal_keys}
        if any(k in raw_data for k in internal_keys)
        else raw_data
    )

    adapted_row: Dict[str, Any] = {
        "provider": "MaxMind",
        "status": "200 OK",
        "statusCode": 200,
        "asn": asn_str,
        "isp": org_name,
        "organisation": org_name,
        "location": loc_str,
        "usageType": usage_type,
        "securityFlags": flags,
        "countryCode": country_code,
        "coordinates": coords,
        "rawJson": clean_raw_json,
    }
    if prefix_length is not None:
        adapted_row["prefixLength"] = prefix_length
    if cloud_match is not None:
        adapted_row["cloudProvider"] = cloud_match["provider"]
        adapted_row["cloudCidr"] = cloud_match["cidr"]
        adapted_row["cloudPrefixLength"] = cloud_match["prefixLength"]
    if hosting_match is not None:
        adapted_row["hostingProvider"] = hosting_match["provider"]
    offline_updated = raw_data.get("_offline_db_updated_at")
    if isinstance(offline_updated, str) and offline_updated.strip():
        adapted_row["offlineDbUpdatedAt"] = offline_updated.strip()
    return adapted_row


def adapt_getipintel(
    raw_data: Optional[Dict[str, Any]], has_contact_email: bool, status_code: int = 200
) -> Dict[str, Any]:
    """Normalises GetIPIntel probability scores from a unit float to a percentage."""
    if not has_contact_email:
        return _build_error_row(
            "GetIPIntel",
            usage_type="ML Prediction",
            raw_message="GETIPINTEL_CONTACT_EMAIL not configured",
            extra={"chance": None},
        )

    raw_data, status_code = _guard_payload(raw_data, status_code)
    if status_code != 200 or not raw_data:
        return _build_error_row(
            "GetIPIntel",
            status_code,
            raw_data,
            usage_type="ML Prediction",
            extra={"chance": None},
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
            extra={"chance": None},
        )

    chance = round(raw_result * 100.0, 3)
    flags: List[Dict[str, Any]] = []
    if chance > 90.0:
        flags.append({"label": "High-Probability Proxy/VPN", "isHighRisk": True})
    elif chance >= 20.0:
        flags.append({"label": "Moderate Prediction", "isHighRisk": True})

    return {
        "provider": "GetIPIntel",
        "status": "200 OK",
        "statusCode": 200,
        "asn": "-",
        "isp": "-",
        "organisation": "-",
        "location": "-",
        "usageType": "ML Prediction",
        "securityFlags": flags if flags else [{"label": "No Flags", "isHighRisk": False}],
        "chance": chance,
        "rawJson": raw_data,
    }


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


def _extract_proxycheck_port(value: Any) -> Optional[int]:
    """Parses a valid TCP or UDP port number from Proxycheck metadata."""
    port_num = _safe_int(value, default=None)
    if port_num is not None and 1 <= port_num <= 65535:
        return port_num
    return None


def _proxycheck_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("yes", "true", "1")
    if isinstance(val, (int, float)):
        return val > 0
    return False


def _extract_proxycheck_ip_obj(raw_data: Dict[str, Any], ip: str) -> Dict[str, Any]:
    """Resolves the IP-scoped sub-object across Proxycheck v2 and v3 response shapes."""
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
    """Extracts Proxycheck usage type and security flags."""
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

    flag_specs = (("Proxy", is_proxy), ("VPN", is_vpn), ("Tor", is_tor), ("Hosting", is_hosting))
    flags = [{"label": label, "isHighRisk": True} for label, active in flag_specs if active]
    usage_type = "hosting" if is_hosting else (str(raw_type).strip().lower() if raw_type else "-")
    return usage_type, flags or [{"label": "No Flags", "isHighRisk": False}]


def _extract_proxycheck_location(ip_obj: Dict[str, Any]) -> Tuple[str, Optional[str], Optional[str]]:
    """Extracts formatted location, uppercase country code, and coordinates from Proxycheck."""
    loc_obj = ip_obj.get("location") or {}
    country_name = ip_obj.get("country") or loc_obj.get("country_name") or ""
    country_code = ip_obj.get("isocode") or ip_obj.get("country_code") or loc_obj.get("country_code") or ""
    city_name = ip_obj.get("city") or loc_obj.get("city") or ""
    lat = ip_obj.get("latitude") or loc_obj.get("latitude")
    lon = ip_obj.get("longitude") or loc_obj.get("longitude")
    coords = f"{lat}, {lon}" if lat is not None and lon is not None else None
    loc_parts = [p for p in (city_name, country_name) if p]
    loc_str = ", ".join(loc_parts) if loc_parts else (country_code or "-")
    if coords and loc_str != "-":
        loc_str += f" ({coords})"
    return loc_str, (str(country_code).upper() if country_code else None), coords


def _extract_proxycheck_first_match(candidates: Tuple[Any, ...], parser: Any) -> Any:
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

    asn_str = _format_asn_str(ip_obj.get("asn") or network.get("asn"))
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

    normalized_port = _extract_proxycheck_first_match(
        (detections.get("port"), ip_obj.get("port"), network.get("port")),
        _extract_proxycheck_port,
    )
    normalized_last_seen = _extract_proxycheck_first_match(
        (
            ip_obj.get("lastSeen"),
            ip_obj.get("last_seen"),
            ip_obj.get("last seen human"),
            ip_obj.get("last_seen_human"),
            ip_obj.get("last seen"),
            detections.get("lastSeen"),
            detections.get("last_seen"),
            detections.get("last seen human"),
            detections.get("last_seen_human"),
            detections.get("last seen"),
            ip_obj.get("seen"),
            detections.get("seen"),
        ),
        _normalize_timestamp_or_text,
    )

    return {
        "provider": "Proxycheck",
        "status": "200 OK",
        "statusCode": 200,
        "asn": asn_str,
        "isp": org_val,
        "organisation": org_val,
        "location": loc_str,
        "usageType": usage_type,
        "securityFlags": flags,
        "riskScore": parsed_risk,
        "port": normalized_port,
        "lastSeen": normalized_last_seen,
        "countryCode": country_code,
        "coordinates": coords,
        "rawJson": raw_data,
    }


def adapt_iphub(raw_data: Optional[Dict[str, Any]], has_api_key: bool, status_code: int = 200) -> Dict[str, Any]:
    """Normalises IPHub v2 block classification responses."""
    if not has_api_key:
        return _build_error_row(
            "IPHub",
            raw_message="IPHUB_API_KEY not configured",
            extra={"block": None},
        )

    raw_data, status_code = _guard_payload(raw_data, status_code)
    block_val = _safe_int(raw_data.get("block"), default=None) if raw_data else None
    if status_code == 200 and raw_data and "block" in raw_data and block_val is None:
        # A null or non-numeric block cannot be classified, so treat it as an upstream format error
        raw_data = {"status": "error", "message": "Unparseable block value in upstream payload", "payload": raw_data}
        status_code = 502

    if status_code != 200 or not raw_data or "block" not in raw_data:
        return _build_error_row("IPHub", status_code, raw_data, extra={"block": None})

    flags: List[Dict[str, Any]] = []
    if block_val == 1:
        flags.append({"label": "Proxy / Hosting (Block 1)", "isHighRisk": True})
    elif block_val == 2:
        flags.append({"label": "Suspicious / Mixed (Block 2)", "isHighRisk": True})

    asn_str = _format_asn_str(raw_data.get("asn"))
    isp_val = raw_data.get("isp") or raw_data.get("hostname") or "-"
    country_name = raw_data.get("countryName") or ""
    country_code = raw_data.get("countryCode") or ""
    loc_parts = [p for p in [country_name, country_code] if p and p != "ZZ"]
    location = ", ".join(loc_parts) if loc_parts else "-"

    usage_type = "hosting / proxy" if block_val == 1 else ("mixed" if block_val == 2 else "residential")

    return {
        "provider": "IPHub",
        "status": "200 OK",
        "statusCode": 200,
        "asn": asn_str,
        "isp": isp_val,
        "organisation": isp_val,
        "location": location,
        "usageType": usage_type,
        "securityFlags": flags if flags else [{"label": "No Flags", "isHighRisk": False}],
        "block": block_val,
        "countryCode": str(country_code).upper() if country_code and country_code != "ZZ" else None,
        "rawJson": raw_data,
    }


def adapt_iphunter(raw_data: Optional[Dict[str, Any]], has_api_key: bool, status_code: int = 200) -> Dict[str, Any]:
    """Normalises IPHunter v1 responses."""
    if not has_api_key:
        return _build_error_row(
            "IPHunter",
            raw_message="IPHUNTER_API_KEY not configured",
            extra={"block": None},
        )

    raw_data, status_code = _guard_payload(raw_data, status_code)
    data: Dict[str, Any] = {}
    block_val: Optional[int] = None
    if raw_data:
        data = raw_data.get("data") if isinstance(raw_data.get("data"), dict) else raw_data
        # A missing block keeps the historical residential default, but a null or garbage block is unclassifiable
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

    flags: List[Dict[str, Any]] = []
    if block_val == 1:
        flags.append({"label": "Proxy / Threat (Block 1)", "isHighRisk": True})
    elif block_val == 2:
        flags.append({"label": "Suspicious (Block 2)", "isHighRisk": True})

    asn_str = _format_asn_str(data.get("asn"))
    isp_val = data.get("isp") or data.get("domain") or "-"
    city_name = data.get("city") or ""
    country_name = data.get("country_name") or ""
    country_code = data.get("country_code") or ""
    loc_parts = [p for p in [city_name, country_name, country_code] if p]
    location = ", ".join(loc_parts) if loc_parts else "-"

    usage_type = "proxy / hosting" if block_val == 1 else "residential"

    return {
        "provider": "IPHunter",
        "status": "200 OK",
        "statusCode": 200,
        "asn": asn_str,
        "isp": isp_val,
        "organisation": isp_val,
        "location": location,
        "usageType": usage_type,
        "securityFlags": flags if flags else [{"label": "No Flags", "isHighRisk": False}],
        "block": block_val,
        "countryCode": str(country_code).upper() if country_code else None,
        "rawJson": raw_data,
    }


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
            status_text = "504 Timeout"
            out_code = 504
        elif effective_status == 429:
            status_text = "429 Rate Limited"
            out_code = 429
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
    return {
        "provider": provider_name,
        "status": "200 OK",
        "statusCode": 200,
        "asn": "-",
        "isp": "-",
        "organisation": "-",
        "location": "-",
        "usageType": "Clean (Not Listed)",
        "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
        "isListed": False,
        "listedCodes": [],
        "listedCategories": [],
        "rawJson": raw_data,
    }


def adapt_spamhaus_zen(raw_data: Optional[Dict[str, Any]], status_code: int = 200) -> Dict[str, Any]:
    """Normalises Spamhaus ZEN DNSBL A-record responses including SBL, CSS, XBL, PBL and policy blocks."""
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
        if code in _SPAMHAUS_CODE_MAP:
            category, flag_label, is_high_risk = _SPAMHAUS_CODE_MAP[code]
        else:
            category, flag_label, is_high_risk = (
                f"Spamhaus Code {code}",
                f"Spamhaus Listed ({code})",
                True,
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

    return {
        "provider": "Spamhaus ZEN",
        "status": "200 OK",
        "statusCode": 200,
        "asn": "-",
        "isp": "-",
        "organisation": "-",
        "location": "-",
        "usageType": usage_text,
        "securityFlags": flags,
        "isListed": True,
        "isPolicyRange": is_only_pbl,
        "listedCodes": codes,
        "listedCategories": categories,
        "rawJson": payload,
    }


def adapt_spamcop(raw_data: Optional[Dict[str, Any]], status_code: int = 200) -> Dict[str, Any]:
    """Normalises SpamCop DNSBL A-record responses."""
    early_row, payload = _adapt_dnsbl_precheck("SpamCop", raw_data, status_code)
    if early_row is not None:
        return early_row

    codes = _extract_dnsbl_codes(payload)
    if not codes:
        return _build_clean_dnsbl_row("SpamCop", payload)

    flags = [{"label": f"SpamCop Listed ({code})", "isHighRisk": True} for code in codes]
    return {
        "provider": "SpamCop",
        "status": "200 OK",
        "statusCode": 200,
        "asn": "-",
        "isp": "-",
        "organisation": "-",
        "location": "-",
        "usageType": f"Listed: Spam Source ({', '.join(codes)})",
        "securityFlags": flags,
        "isListed": True,
        "listedCodes": codes,
        "listedCategories": ["Spam Source"],
        "rawJson": payload,
    }


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
    """Checks whether an Onionoo relay matches target_ip and returns (matched, matched_exit, flags, running)."""
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
    security_flags: List[Dict[str, Any]],
    is_tor: bool,
    tor_is_exit: bool,
    tor_running: bool,
    tor_flags: List[str],
    tor_label: Optional[str],
    tor_summary: str,
) -> Dict[str, Any]:
    return {
        "provider": "Tor Onionoo",
        "status": "200 OK",
        "statusCode": 200,
        "asn": "-",
        "isp": isp,
        "organisation": isp,
        "location": "-",
        "usageType": usage_type,
        "securityFlags": security_flags,
        "isTor": is_tor,
        "torIsExit": tor_is_exit,
        "torRunning": tor_running,
        "torFlags": tor_flags,
        "torLabel": tor_label,
        "torSummary": tor_summary,
        "rawJson": raw_data,
    }


def adapt_tor_onionoo(
    raw_data: Optional[Dict[str, Any]],
    status_code: int = 200,
    ip: str = "",
) -> Dict[str, Any]:
    """
    Normalises Tor Project Onionoo summary responses and verifies exact IP membership
    across OR address (`a` or `or_addresses`) and `exit_addresses` lists.
    """
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
            security_flags=[{"label": "No Flags", "isHighRisk": False}],
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
        security_flags=[{"label": "No Flags", "isHighRisk": False}],
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
    flags: List[Dict[str, Any]] = []
    if blacklisted:
        toxic_label = f"Blacklisted Toxic CIDR ({toxic_cidr})" if toxic_cidr else "Blacklisted Toxic CIDR"
        flags.append({"label": toxic_label, "isHighRisk": True})
    if appears and (frequency > 0 or not blacklisted):
        flags.append({"label": f"Forum Spam ({frequency}x)", "isHighRisk": True})

    if blacklisted and frequency > 0:
        return flags, "Blacklisted Toxic CIDR / Forum Spam Reported"
    if blacklisted:
        return flags, "Blacklisted Toxic CIDR"
    if appears:
        return flags, "Forum Spam Reported"
    return [{"label": "No Flags", "isHighRisk": False}], "Clean (Not Listed)"


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
    confidence = _extract_sfs_confidence(ip_block, blacklisted, appears)
    last_seen = _normalize_timestamp_or_text(
        ip_block.get("lastseen") or ip_block.get("last_seen") or ip_block.get("lastSeen")
    )
    flags, usage_type = _build_sfs_flags_and_usage(blacklisted, toxic_cidr, appears, frequency)

    row: Dict[str, Any] = {
        "provider": "StopForumSpam",
        "status": "200 OK",
        "statusCode": 200,
        "asn": _format_numeric_or_prefixed_asn(ip_block.get("asn")),
        "isp": "-",
        "organisation": "-",
        "location": "-",
        "usageType": usage_type,
        "securityFlags": flags,
        "appears": appears,
        "blacklisted": blacklisted,
        "toxicCidr": toxic_cidr,
        "frequency": frequency,
        "confidence": confidence,
        "lastSeen": last_seen,
        "rawJson": raw_data,
    }
    offline_updated = raw_data.get("offlineDbUpdatedAt") or ip_block.get("offlineDbUpdatedAt")
    if isinstance(offline_updated, str) and offline_updated.strip():
        row["offlineDbUpdatedAt"] = offline_updated.strip()
    return row


def _extract_dshield_threatfeeds(raw_feeds: Any) -> Tuple[List[str], Optional[str]]:
    """Extracts feed names and any nested last-seen date from DShield threatfeeds structures."""
    names: List[str] = []
    seen_names = set()
    latest_feed_date: Optional[str] = None

    if isinstance(raw_feeds, dict):
        for feed_key, feed_val in raw_feeds.items():
            if not isinstance(feed_key, str) or not feed_key.strip():
                continue
            cleaned_name = feed_key.strip()
            if cleaned_name not in seen_names:
                seen_names.add(cleaned_name)
                names.append(cleaned_name)
            if isinstance(feed_val, dict):
                candidate_seen = _normalize_timestamp_or_text(feed_val.get("lastseen") or feed_val.get("last_seen"))
                if candidate_seen and (latest_feed_date is None or candidate_seen > latest_feed_date):
                    latest_feed_date = candidate_seen
    elif isinstance(raw_feeds, list):
        for entry in raw_feeds:
            if isinstance(entry, str) and entry.strip():
                cleaned = entry.strip()
                if cleaned not in seen_names:
                    seen_names.add(cleaned)
                    names.append(cleaned)
            elif isinstance(entry, dict):
                feed_name = entry.get("name") or entry.get("feed") or entry.get("type")
                if isinstance(feed_name, str) and feed_name.strip():
                    cleaned = feed_name.strip()
                    if cleaned not in seen_names:
                        seen_names.add(cleaned)
                        names.append(cleaned)
                candidate_seen = _normalize_timestamp_or_text(entry.get("lastseen") or entry.get("last_seen"))
                if candidate_seen and (latest_feed_date is None or candidate_seen > latest_feed_date):
                    latest_feed_date = candidate_seen

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

    asn_str = _format_numeric_or_prefixed_asn(ip_block.get("as") or ip_block.get("asn"))

    isp_val = str(ip_block.get("asname") or ip_block.get("org") or "-").strip() or "-"
    loc_val = str(ip_block.get("ascountry") or "-").strip() or "-"

    has_activity = attacks > 0 or count > 0 or len(threatfeeds) > 0
    if has_activity:
        flags: List[Dict[str, Any]] = []
        if attacks > 0 or count > 0:
            flags.append({"label": f"Attack Activity ({attacks} attacks)", "isHighRisk": True})
        if threatfeeds:
            flags.append({"label": f"Feeds: {', '.join(threatfeeds[:3])}", "isHighRisk": True})
        usage_type = "Malicious Activity" if (attacks > 0 or count > 0) else "Threat Feed Listed"
    else:
        flags = [{"label": "No Flags", "isHighRisk": False}]
        usage_type = "Clean (No Activity)"

    return {
        "provider": "DShield",
        "status": "200 OK",
        "statusCode": 200,
        "asn": asn_str,
        "isp": isp_val,
        "organisation": isp_val,
        "location": loc_val,
        "usageType": usage_type,
        "securityFlags": flags,
        "attacks": attacks,
        "count": count,
        "threatfeeds": threatfeeds,
        "maxDate": max_date,
        "lastSeen": last_seen,
        "rawJson": raw_data,
    }
