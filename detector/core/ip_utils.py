"""Pure IP canonicalisation, non-public address classification, and query parameter parsing."""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Set, Tuple

MAX_BATCH_IPS = 25
_MAX_RAW_BATCH_IPS = 50

_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")
_DOC_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


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
