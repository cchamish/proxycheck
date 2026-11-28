"""Offline threat, CIDR, Tor Onionoo, BGP.tools, and mobile ASN feeds plus database freshness status."""

from __future__ import annotations

import ipaddress
import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

from proxycheck.settings import (
    MAXMIND_ASN_DB_FILENAME,
    MAXMIND_CITY_DB_FILENAME,
    MAXMIND_COUNTRY_DB_FILENAME,
)

from .mmdb import resolve_maxmind_paths
from .sfs import clear_sfs_caches, resolve_stopforumspam_paths
from .store import (
    BGP_TAGS_JSON_FILENAME,
    BGP_TOOLS_BIN_FILENAME,
    HOSTING_RULES_FILENAME,
    IPSUM_DROP_BIN_FILENAME,
    MOBILE_ASNS_JSON_FILENAME,
    MOBILE_BGP_TAG_TOKENS,
    OPENASN_MMDB_FILENAME,
    PRIVACY_RELAYS_BIN_FILENAME,
    REZMOSS_EXCLUDED_PROVIDERS,
    REZMOSS_PROVIDER_CATALOG,
    SFS_LISTED_1_ZIP_NAME,
    SFS_LISTED_90_ZIP_NAME,
    SFS_SQLITE_FILENAME,
    SFS_TOXIC_CIDR_FILENAME,
    SHARED_CIDRS_BIN_FILENAME,
    TOR_ONIONOO_SUMMARY_FILENAME,
    FileStatCache,
    _BinaryIndexCache,
    _effective_base_dir,
    _effective_stat_throttle_seconds,
    _lookup_config_value,
    _parse_asn_int,
    clear_stat_throttle_cache,
    get_file_stat_signature,
    get_positive_int_setting,
    resolve_feed_data_dir,
    resolve_feed_data_path,
    resolve_hosting_rules_path,
)

OXYLABS_DIR_NAME = "oxylabs"

DEFAULT_STALE_MAXMIND_SECONDS = 14 * 86400
DEFAULT_STALE_SFS_TOXIC_SECONDS = 7 * 86400
DEFAULT_STALE_SFS_90_SECONDS = 2 * 86400
DEFAULT_STALE_SFS_1_SECONDS = 6 * 3600
DEFAULT_STALE_SHARED_CIDRS_SECONDS = 7 * 86400
DEFAULT_STALE_OPENASN_SECONDS = 14 * 86400
DEFAULT_STALE_OXYLABS_SECONDS = 7 * 86400
DEFAULT_STALE_TOR_ONIONOO_SECONDS = 6 * 3600
DEFAULT_STALE_DAILY_FEED_SECONDS = 7 * 86400
DEFAULT_STALE_RULES_SECONDS = 90 * 86400


@dataclass(frozen=True, slots=True)
class OfflineDatasetSpec:
    """Declarative metadata for one offline database, path override, and staleness rule."""

    key: str
    source: str
    name: str
    filename: str
    stale_setting: str
    default_stale_seconds: int
    stale_description: str
    provider_key: Optional[str] = None
    override_setting: Optional[str] = None
    override_description: Optional[str] = None
    optional: bool = True
    missing_label: Optional[str] = None
    glob_pattern: Optional[str] = None


OFFLINE_DATASET_SPECS: Tuple[OfflineDatasetSpec, ...] = (
    OfflineDatasetSpec(
        key="maxmind_country",
        source="MaxMind",
        name="MaxMind GeoLite2 Country",
        filename=MAXMIND_COUNTRY_DB_FILENAME,
        stale_setting="OFFLINE_DB_MAXMIND_STALE_SECONDS",
        default_stale_seconds=DEFAULT_STALE_MAXMIND_SECONDS,
        stale_description="MaxMind MMDB staleness warning threshold",
        provider_key="maxmind",
        optional=False,
    ),
    OfflineDatasetSpec(
        key="maxmind_city",
        source="MaxMind",
        name="MaxMind GeoLite2 City",
        filename=MAXMIND_CITY_DB_FILENAME,
        stale_setting="OFFLINE_DB_MAXMIND_STALE_SECONDS",
        default_stale_seconds=DEFAULT_STALE_MAXMIND_SECONDS,
        stale_description="MaxMind MMDB staleness warning threshold",
        provider_key="maxmind",
        optional=False,
    ),
    OfflineDatasetSpec(
        key="maxmind_asn",
        source="MaxMind",
        name="MaxMind GeoLite2 ASN",
        filename=MAXMIND_ASN_DB_FILENAME,
        stale_setting="OFFLINE_DB_MAXMIND_STALE_SECONDS",
        default_stale_seconds=DEFAULT_STALE_MAXMIND_SECONDS,
        stale_description="MaxMind MMDB staleness warning threshold",
        provider_key="maxmind",
        optional=False,
    ),
    OfflineDatasetSpec(
        key="stopforumspam_toxic_cidr",
        source="StopForumSpam",
        name="StopForumSpam Toxic CIDRs",
        filename=SFS_TOXIC_CIDR_FILENAME,
        stale_setting="OFFLINE_DB_SFS_TOXIC_STALE_SECONDS",
        default_stale_seconds=DEFAULT_STALE_SFS_TOXIC_SECONDS,
        stale_description="StopForumSpam toxic_ip_cidr.txt staleness threshold",
        provider_key="stopforumspam",
        override_setting="STOPFORUMSPAM_TOXIC_CIDR_PATH",
        override_description="Override file or directory path for toxic_ip_cidr.txt",
        optional=False,
    ),
    OfflineDatasetSpec(
        key="stopforumspam_listed_90",
        source="StopForumSpam",
        name="StopForumSpam Listed IPs (90d)",
        filename=SFS_LISTED_90_ZIP_NAME,
        stale_setting="OFFLINE_DB_SFS_90_STALE_SECONDS",
        default_stale_seconds=DEFAULT_STALE_SFS_90_SECONDS,
        stale_description="StopForumSpam 90-day dump staleness threshold",
        provider_key="stopforumspam",
        override_setting="STOPFORUMSPAM_LISTED_90_PATH",
        override_description="Override path for StopForumSpam 90-day listed IP archive",
        optional=False,
    ),
    OfflineDatasetSpec(
        key="stopforumspam_listed_1",
        source="StopForumSpam",
        name="StopForumSpam Listed IPs (1d)",
        filename=SFS_LISTED_1_ZIP_NAME,
        stale_setting="OFFLINE_DB_SFS_1_STALE_SECONDS",
        default_stale_seconds=DEFAULT_STALE_SFS_1_SECONDS,
        stale_description="StopForumSpam 1-day dump staleness threshold",
        provider_key="stopforumspam",
        override_setting="STOPFORUMSPAM_LISTED_1_PATH",
        override_description="Override path for StopForumSpam 1-day listed IP archive",
        optional=True,
    ),
    OfflineDatasetSpec(
        key="stopforumspam_index",
        source="StopForumSpam",
        name="StopForumSpam Local SQLite Index",
        filename=SFS_SQLITE_FILENAME,
        stale_setting="OFFLINE_DB_SFS_90_STALE_SECONDS",
        default_stale_seconds=DEFAULT_STALE_SFS_90_SECONDS,
        stale_description="StopForumSpam 90-day dump staleness threshold",
        provider_key="stopforumspam",
        override_setting="STOPFORUMSPAM_SQLITE_PATH",
        override_description="Override path for stopforumspam.sqlite3 index",
        optional=True,
    ),
    OfflineDatasetSpec(
        key="hosting_asn_rules",
        source="Hosting Rules",
        name="Hosting ASN Rules",
        filename=HOSTING_RULES_FILENAME,
        stale_setting="OFFLINE_DB_RULES_STALE_SECONDS",
        default_stale_seconds=DEFAULT_STALE_RULES_SECONDS,
        stale_description="Hosting ASN rules staleness threshold",
        override_setting="HOSTING_ASN_RULES_PATH",
        override_description="Override path for hosting_asn_rules.json",
        optional=True,
        missing_label="Built-in (Optional)",
    ),
    OfflineDatasetSpec(
        key="shared_cidrs",
        source="Shared CIDRs",
        name="Rezmoss Shared Egress CIDRs",
        filename=SHARED_CIDRS_BIN_FILENAME,
        stale_setting="OFFLINE_DB_SHARED_CIDRS_STALE_SECONDS",
        default_stale_seconds=DEFAULT_STALE_SHARED_CIDRS_SECONDS,
        stale_description="Rezmoss shared egress CIDRs staleness threshold",
        override_setting="SHARED_CIDRS_BIN_PATH",
        override_description="Override path for shared_cidrs.bin",
    ),
    OfflineDatasetSpec(
        key="privacy_relays",
        source="Privacy Relays",
        name="Apple Private Relay and Cloudflare WARP",
        filename=PRIVACY_RELAYS_BIN_FILENAME,
        stale_setting="OFFLINE_DB_DAILY_FEED_STALE_SECONDS",
        default_stale_seconds=DEFAULT_STALE_DAILY_FEED_SECONDS,
        stale_description="Daily offline threat and relay feed staleness threshold",
        override_setting="PRIVACY_RELAYS_BIN_PATH",
        override_description="Override path for privacy_relays.bin",
    ),
    OfflineDatasetSpec(
        key="ipsum_drop",
        source="IPsum and DROP",
        name="IPsum and Spamhaus DROP Index",
        filename=IPSUM_DROP_BIN_FILENAME,
        stale_setting="OFFLINE_DB_DAILY_FEED_STALE_SECONDS",
        default_stale_seconds=DEFAULT_STALE_DAILY_FEED_SECONDS,
        stale_description="Daily offline threat and relay feed staleness threshold",
        provider_key="ipsum_drop",
        override_setting="IPSUM_DROP_BIN_PATH",
        override_description="Override path for ipsum_drop.bin",
    ),
    OfflineDatasetSpec(
        key="tor_onionoo",
        source="Tor Onionoo",
        name="Tor Onionoo Summary Mirror",
        filename=TOR_ONIONOO_SUMMARY_FILENAME,
        stale_setting="OFFLINE_DB_TOR_ONIONOO_STALE_SECONDS",
        default_stale_seconds=DEFAULT_STALE_TOR_ONIONOO_SECONDS,
        stale_description="Tor Onionoo local mirror staleness threshold",
        override_setting="TOR_ONIONOO_SUMMARY_PATH",
        override_description="Override path for tor_onionoo_summary.json",
    ),
    OfflineDatasetSpec(
        key="bgp_tools",
        source="BGP Tools",
        name="BGP Routing Table Prefix Index",
        filename=BGP_TOOLS_BIN_FILENAME,
        stale_setting="OFFLINE_DB_DAILY_FEED_STALE_SECONDS",
        default_stale_seconds=DEFAULT_STALE_DAILY_FEED_SECONDS,
        stale_description="Daily offline threat and relay feed staleness threshold",
        override_setting="BGP_TOOLS_BIN_PATH",
        override_description="Override path for bgp_tools.bin",
    ),
    OfflineDatasetSpec(
        key="openasn",
        source="OpenASN",
        name="OpenASN IP/ASN Classification",
        filename=OPENASN_MMDB_FILENAME,
        stale_setting="OFFLINE_DB_OPENASN_STALE_SECONDS",
        default_stale_seconds=DEFAULT_STALE_OPENASN_SECONDS,
        stale_description="OpenASN MMDB staleness threshold",
        provider_key="openasn",
        override_setting="OPENASN_MMDB_PATH",
        override_description="Override path for openasn.mmdb",
    ),
    OfflineDatasetSpec(
        key="mobile_carriers",
        source="Mobile Carriers",
        name="Mobile Carrier ASNs",
        filename=MOBILE_ASNS_JSON_FILENAME,
        stale_setting="OFFLINE_DB_DAILY_FEED_STALE_SECONDS",
        default_stale_seconds=DEFAULT_STALE_DAILY_FEED_SECONDS,
        stale_description="Daily offline threat and relay feed staleness threshold",
        override_setting="MOBILE_ASNS_JSON_PATH",
        override_description="Override path for mobile_asns.json",
    ),
    OfflineDatasetSpec(
        key="oxylabs",
        source="Oxylabs",
        name="Oxylabs Residential Proxy Datasets",
        filename=OXYLABS_DIR_NAME,
        stale_setting="OFFLINE_DB_OXYLABS_STALE_SECONDS",
        default_stale_seconds=DEFAULT_STALE_OXYLABS_SECONDS,
        stale_description="Oxylabs JSONL datasets staleness threshold",
        provider_key="oxylabs",
        override_setting="OXYLABS_DATA_DIR",
        override_description="Override directory path for Oxylabs JSONL datasets",
        glob_pattern="*.jsonl",
    ),
)

logger = logging.getLogger(__name__)

_shared_cidrs_index = _BinaryIndexCache(SHARED_CIDRS_BIN_FILENAME, "SHARED_CIDRS_BIN_PATH")
_privacy_relays_index = _BinaryIndexCache(PRIVACY_RELAYS_BIN_FILENAME, "PRIVACY_RELAYS_BIN_PATH")
_ipsum_drop_index = _BinaryIndexCache(IPSUM_DROP_BIN_FILENAME, "IPSUM_DROP_BIN_PATH")
_bgp_tools_index = _BinaryIndexCache(BGP_TOOLS_BIN_FILENAME, "BGP_TOOLS_BIN_PATH")

_tor_onionoo_cache: FileStatCache[Tuple[str, int, int], Dict[str, List[Dict[str, Any]]]] = FileStatCache()
_bgp_tags_cache: FileStatCache[Tuple[str, int, int], Tuple[Dict[int, Tuple[str, ...]], FrozenSet[int]]] = (
    FileStatCache()
)
_mobile_asns_cache: FileStatCache[Tuple[str, int, int], FrozenSet[int]] = FileStatCache()
_OxylabsRecord = Tuple[Optional[int], Optional[str], Optional[str], str]
_oxylabs_cache: FileStatCache[Tuple[Tuple[str, int, int], ...], Dict[str, _OxylabsRecord]] = FileStatCache()
_oxylabs_scan_lock = threading.Lock()
_oxylabs_scan_cache: Optional[Tuple[Tuple[str, str, str], float, Optional[Path], Tuple[Tuple[Path, int, int], ...]]] = (
    None
)


def classify_rezmoss_provider(slug: str) -> Optional[Tuple[str, str]]:
    """Maps a Rezmoss provider slug to (display_label, category), or None when excluded."""
    cleaned = slug.strip().lower() if isinstance(slug, str) else ""
    if not cleaned or cleaned in REZMOSS_EXCLUDED_PROVIDERS:
        return None
    known = REZMOSS_PROVIDER_CATALOG.get(cleaned)
    if known is not None:
        return known
    category = "bot" if cleaned.endswith("bot") else "cloud"
    return cleaned.replace("_", " ").title(), category


def lookup_shared_cidr_offline(ip: str) -> Optional[Dict[str, Any]]:
    """Looks up an IP in the compiled Rezmoss shared-egress binary prefix index."""
    reader, _updated = _shared_cidrs_index.get_reader_and_mtime()
    if reader is None:
        return None
    hit = reader.lookup_with_prefix_len(ip)
    if hit is None:
        return None
    matched_cidr, prefix_len, payload = hit
    if not isinstance(payload, Mapping):
        return None
    provider = payload.get("p") or payload.get("provider")
    category = payload.get("c") or payload.get("category")
    if not isinstance(provider, str) or not provider.strip():
        return None
    if not isinstance(category, str) or not category.strip():
        category = "cloud"
    return {
        "cidr": matched_cidr,
        "prefixLength": prefix_len,
        "provider": provider.strip(),
        "category": category.strip().lower(),
    }


def lookup_privacy_relay_offline(ip: str) -> Optional[str]:
    """Returns icloud_private_relay or cloudflare_warp when matched, excluding Cloudflare CDN ranges."""
    reader, _updated = _privacy_relays_index.get_reader_and_mtime()
    if reader is None:
        return None
    hit = reader.lookup(ip)
    if hit is None:
        return None
    category = hit[1]
    if category in ("icloud_private_relay", "cloudflare_warp"):
        return str(category)
    return None


def _empty_ipsum_drop_result(*, has_db: bool, updated_at: Optional[str]) -> Dict[str, Any]:
    return {
        "hasDb": has_db,
        "has_db": has_db,
        "isListed": False,
        "ipsumScore": 0,
        "isIpsumListed": False,
        "isHighRisk": False,
        "inSpamhausDrop": False,
        "dropSblId": None,
        "dropCidr": None,
        "matchedCidr": None,
        "offlineDbUpdatedAt": updated_at,
    }


def query_ipsum_drop_offline(ip: str) -> Dict[str, Any]:
    """Queries the compiled IPsum and Spamhaus DROP binary prefix index for IPv4 and IPv6 targets."""
    reader, updated_at = _ipsum_drop_index.get_reader_and_mtime()
    if reader is None:
        return _empty_ipsum_drop_result(has_db=False, updated_at=None)

    hit = reader.lookup(ip)
    if hit is None:
        return _empty_ipsum_drop_result(has_db=True, updated_at=updated_at)

    matched_cidr, payload = hit
    ipsum_score = 0
    in_drop = False
    drop_sbl_id: Optional[str] = None
    drop_cidr: Optional[str] = None

    if isinstance(payload, int) and not isinstance(payload, bool):
        ipsum_score = max(0, payload)
    elif isinstance(payload, dict):
        raw_score = payload.get("score")
        if isinstance(raw_score, int) and not isinstance(raw_score, bool):
            ipsum_score = max(0, raw_score)
        in_drop = bool(payload.get("drop"))
        raw_sbl = payload.get("sblid")
        if isinstance(raw_sbl, str) and raw_sbl.strip():
            drop_sbl_id = raw_sbl.strip()
        raw_drop_cidr = payload.get("drop_cidr")
        drop_cidr = raw_drop_cidr.strip() if isinstance(raw_drop_cidr, str) and raw_drop_cidr.strip() else matched_cidr

    is_ipsum_listed = ipsum_score >= 2
    is_listed = is_ipsum_listed or in_drop
    if not is_listed:
        return _empty_ipsum_drop_result(has_db=True, updated_at=updated_at)

    return {
        "hasDb": True,
        "has_db": True,
        "isListed": True,
        "ipsumScore": ipsum_score,
        "isIpsumListed": is_ipsum_listed,
        "isHighRisk": in_drop or ipsum_score >= 3,
        "inSpamhausDrop": in_drop,
        "dropSblId": drop_sbl_id,
        "dropCidr": drop_cidr if in_drop else None,
        "matchedCidr": matched_cidr,
        "offlineDbUpdatedAt": updated_at,
    }


def _extract_onionoo_canonical_ip(raw_entry: Any) -> Optional[str]:
    if not isinstance(raw_entry, str):
        return None
    candidate = raw_entry.strip()
    if not candidate:
        return None
    if candidate.startswith("["):
        end_idx = candidate.find("]")
        if end_idx <= 1:
            return None
        candidate = candidate[1:end_idx]
    if "%" in candidate and ":" in candidate:
        candidate = candidate.split("%", 1)[0]
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        pass
    if candidate.count(":") == 1 and "." in candidate:
        host_part = candidate.split(":", 1)[0].strip()
        try:
            return ipaddress.ip_address(host_part).compressed
        except ValueError:
            return None
    return None


def _index_onionoo_summary_payload(payload: Any) -> Optional[Dict[str, List[Dict[str, Any]]]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("relays"), list):
        return None
    by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for relay in payload["relays"]:
        if not isinstance(relay, dict):
            continue
        seen_for_relay: set[str] = set()
        for field_name in ("a", "or_addresses", "exit_addresses"):
            entries = relay.get(field_name)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                canonical = _extract_onionoo_canonical_ip(entry)
                if canonical and canonical not in seen_for_relay:
                    seen_for_relay.add(canonical)
                    by_ip.setdefault(canonical, []).append(relay)
    return by_ip


def lookup_tor_onionoo_offline(ip: str) -> Optional[Dict[str, Any]]:
    """
    Looks up an IP in the local Onionoo summary mirror in sub-millisecond time.
    Returns None only when the local mirror is absent or unreadable so HTTP fallback can run.
    """
    path = resolve_feed_data_path(TOR_ONIONOO_SUMMARY_FILENAME, override_setting="TOR_ONIONOO_SUMMARY_PATH")
    if path is None:
        return None
    sig = get_file_stat_signature(path)
    if sig is None:
        return None

    target_key = (str(path), sig[0], sig[1])
    hit = _tor_onionoo_cache.peek_matching(lambda key, _val: key == target_key)
    if hit is None:
        try:
            raw_json = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("Failed to load local Tor Onionoo summary %s: %s", path, exc)
            return None
        indexed = _index_onionoo_summary_payload(raw_json)
        if indexed is None:
            return None
        hit = _tor_onionoo_cache.get_or_load(target_key, lambda: indexed)

    canonical = _extract_onionoo_canonical_ip(ip)
    matched = hit.get(canonical, ()) if canonical else ()
    return {
        "relays": [dict(relay) for relay in matched],
        "bridges": [],
    }


def _get_bgp_tags_data() -> Tuple[Dict[int, Tuple[str, ...]], FrozenSet[int]]:
    path = resolve_feed_data_path(BGP_TAGS_JSON_FILENAME, override_setting="BGP_TAGS_JSON_PATH")
    if path is None:
        return _bgp_tags_cache.set_constant(("__missing__", -1, -1), ({}, frozenset()))
    sig = get_file_stat_signature(path)
    if sig is None:
        return _bgp_tags_cache.set_constant(("__missing__", -1, -1), ({}, frozenset()))

    target_key = (str(path), sig[0], sig[1])
    hit = _bgp_tags_cache.peek_matching(lambda key, _val: key == target_key)
    if hit is not None:
        return hit

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning("Failed to parse BGP tags file %s: %s", path, exc)
        return {}, frozenset()

    asn_tags: Dict[int, Tuple[str, ...]] = {}
    mobile_asns: set[int] = set()
    if isinstance(payload, dict):
        raw_map = payload.get("asn_tags") if isinstance(payload.get("asn_tags"), dict) else payload
        for raw_key, raw_tags in raw_map.items():
            if raw_key in ("mobile_asns", "tag_counts"):
                continue
            asn_num = _parse_asn_int(raw_key)
            if asn_num is None or not isinstance(raw_tags, list):
                continue
            cleaned_tags = tuple(str(t).strip().lower() for t in raw_tags if isinstance(t, str) and str(t).strip())
            if cleaned_tags:
                asn_tags[asn_num] = cleaned_tags
                if any(tag in MOBILE_BGP_TAG_TOKENS for tag in cleaned_tags):
                    mobile_asns.add(asn_num)

        explicit_mobile = payload.get("mobile_asns")
        if isinstance(explicit_mobile, list):
            for item in explicit_mobile:
                asn_num = _parse_asn_int(item)
                if asn_num is not None:
                    mobile_asns.add(asn_num)

    parsed = (asn_tags, frozenset(mobile_asns))
    return _bgp_tags_cache.get_or_load(target_key, lambda: parsed)


def lookup_bgp_tools_offline(ip: str) -> Optional[Dict[str, Any]]:
    """Looks up the longest BGP routing prefix, origin ASN, and network tags from offline bgp.tools data."""
    reader, _updated = _bgp_tools_index.get_reader_and_mtime()
    if reader is None:
        return None
    hit = reader.lookup(ip)
    if hit is None:
        return None
    matched_cidr, payload = hit
    asn_num = _parse_asn_int(payload.get("asn") if isinstance(payload, dict) else payload)
    asn_tags_map, _mobile = _get_bgp_tags_data()
    tags = list(asn_tags_map.get(asn_num, ())) if asn_num is not None else []
    if isinstance(payload, dict) and isinstance(payload.get("tags"), list):
        for extra_tag in payload["tags"]:
            cleaned_tag = str(extra_tag).strip().lower()
            if cleaned_tag and cleaned_tag not in tags:
                tags.append(cleaned_tag)
    return {
        "bgpPrefix": matched_cidr,
        "asn": asn_num,
        "tags": tags,
    }


def is_mobile_asn_offline(asn: Optional[int]) -> bool:
    """Returns True when an ASN is tagged as mobile in mobile_asns.json or bgp_tags.json."""
    asn_num = _parse_asn_int(asn)
    if asn_num is None:
        return False

    path = resolve_feed_data_path(MOBILE_ASNS_JSON_FILENAME, override_setting="MOBILE_ASNS_JSON_PATH")
    carrier_asns: FrozenSet[int]
    if path is None:
        carrier_asns = _mobile_asns_cache.set_constant(("__missing__", -1, -1), frozenset())
    else:
        sig = get_file_stat_signature(path)
        if sig is None:
            carrier_asns = _mobile_asns_cache.set_constant(("__missing__", -1, -1), frozenset())
        else:
            target_key = (str(path), sig[0], sig[1])
            hit = _mobile_asns_cache.peek_matching(lambda key, _val: key == target_key)
            if hit is not None:
                carrier_asns = hit
            else:
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    logger.warning("Failed to parse mobile ASNs file %s: %s", path, exc)
                    carrier_asns = frozenset()
                else:
                    raw_items: Iterable[Any] = ()
                    if isinstance(payload, list):
                        raw_items = payload
                    elif isinstance(payload, dict):
                        for key in ("mobile_asns", "asns", "data"):
                            candidate = payload.get(key)
                            if isinstance(candidate, list):
                                raw_items = candidate
                                break
                    parsed_asns: set[int] = set()
                    for item in raw_items:
                        parsed_num = _parse_asn_int(item.get("asn")) if isinstance(item, dict) else _parse_asn_int(item)
                        if parsed_num is not None:
                            parsed_asns.add(parsed_num)
                    frozen_asns = frozenset(parsed_asns)
                    carrier_asns = _mobile_asns_cache.get_or_load(target_key, lambda: frozen_asns)

    if asn_num in carrier_asns:
        return True
    _tags_map, bgp_mobile_asns = _get_bgp_tags_data()
    return asn_num in bgp_mobile_asns


def _scan_oxylabs_files(
    *,
    env_overrides: Optional[Mapping[str, str]] = None,
    base_dir: Optional[Path] = None,
    bypass_throttle: bool = False,
) -> Tuple[Optional[Path], Tuple[Tuple[Path, int, int], ...]]:
    global _oxylabs_scan_cache

    use_throttle = env_overrides is None and base_dir is None and not bypass_throttle
    throttle_s = _effective_stat_throttle_seconds() if use_throttle else 0.0
    config_key: Optional[Tuple[str, str, str]] = None
    now_mono = 0.0
    if throttle_s > 0.0:
        config_key = (
            _lookup_config_value("OXYLABS_DATA_DIR"),
            _lookup_config_value("TOOL_DATA_DIR"),
            str(_effective_base_dir(None)),
        )
        now_mono = time.monotonic()
        with _oxylabs_scan_lock:
            cached = _oxylabs_scan_cache
            if cached is not None and cached[0] == config_key and 0.0 <= (now_mono - cached[1]) < throttle_s:
                return cached[2], cached[3]

    data_dir = resolve_feed_data_dir(
        OXYLABS_DIR_NAME,
        override_setting="OXYLABS_DATA_DIR",
        env_overrides=env_overrides,
        base_dir=base_dir,
    )
    if data_dir is None:
        result: Tuple[Optional[Path], Tuple[Tuple[Path, int, int], ...]] = (None, ())
    else:
        try:
            candidates = sorted(data_dir.glob("*.jsonl"), key=lambda path: path.name)
        except OSError:
            return data_dir, ()
        matched: List[Tuple[Path, int, int]] = []
        for file_path in candidates:
            sig = get_file_stat_signature(file_path, bypass_throttle=bypass_throttle)
            if sig is not None:
                matched.append((file_path, sig[0], sig[1]))
        result = (data_dir, tuple(matched))

    if config_key is not None:
        with _oxylabs_scan_lock:
            _oxylabs_scan_cache = (config_key, now_mono, result[0], result[1])
    return result


def _parse_oxylabs_line(raw_line: str, source_file: str) -> Optional[Tuple[str, _OxylabsRecord]]:
    cleaned_line = raw_line.strip()
    if not cleaned_line:
        return None
    try:
        obj = json.loads(cleaned_line)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    raw_ip = obj.get("ip")
    if not isinstance(raw_ip, str) or not raw_ip.strip():
        return None
    ip_text = raw_ip.strip()
    if "%" in ip_text and ":" in ip_text:
        ip_text = ip_text.split("%", 1)[0]
    try:
        canonical_ip = ipaddress.ip_address(ip_text).compressed
    except ValueError:
        return None
    raw_org = obj.get("org_name")
    org_name = raw_org.strip() if isinstance(raw_org, str) and raw_org.strip() else None
    raw_updated = obj.get("updated_at")
    updated_at = raw_updated.strip() if isinstance(raw_updated, str) and raw_updated.strip() else None
    return canonical_ip, (_parse_asn_int(obj.get("asn")), org_name, updated_at, source_file)


def _load_oxylabs_index(files: Tuple[Tuple[Path, int, int], ...]) -> Dict[str, _OxylabsRecord]:
    index: Dict[str, _OxylabsRecord] = {}
    for file_path, _mtime_ns, _size in files:
        try:
            with file_path.open("r", encoding="utf-8") as handle:
                for raw_line in handle:
                    parsed = _parse_oxylabs_line(raw_line, file_path.name)
                    if parsed is None:
                        continue
                    canonical_ip, entry = parsed
                    existing = index.get(canonical_ip)
                    if existing is None or (entry[2] and (not existing[2] or entry[2] > existing[2])):
                        index[canonical_ip] = entry
        except OSError as exc:
            logger.warning("Failed to read Oxylabs JSONL file %s: %s", file_path, exc)
    return index


def _empty_oxylabs_result(*, has_db: bool, updated_at: Optional[str]) -> Dict[str, Any]:
    return {
        "has_db": has_db,
        "isListed": False,
        "asn": None,
        "orgName": None,
        "updatedAt": None,
        "sourceFile": None,
        "offlineDbUpdatedAt": updated_at,
    }


def query_oxylabs_offline(ip: str) -> Dict[str, Any]:
    """Queries in-memory Oxylabs JSONL datasets for IPv4, IPv6, and IPv4-mapped IPv6 addresses."""
    _data_dir, files = _scan_oxylabs_files()
    if not files:
        return _empty_oxylabs_result(has_db=False, updated_at=None)

    newest_ns = max(mtime_ns for _, mtime_ns, _ in files)
    updated_iso = datetime.fromtimestamp(newest_ns / 1_000_000_000.0, tz=timezone.utc).isoformat()
    cache_key = tuple((str(file_path), mtime_ns, size) for file_path, mtime_ns, size in files)
    index = _oxylabs_cache.get_or_load(cache_key, lambda: _load_oxylabs_index(files))

    if not isinstance(ip, str) or not ip.strip():
        return _empty_oxylabs_result(has_db=True, updated_at=updated_iso)
    cleaned = ip.strip()
    if "%" in cleaned and ":" in cleaned:
        cleaned = cleaned.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return _empty_oxylabs_result(has_db=True, updated_at=updated_iso)

    hit = index.get(addr.compressed)
    if hit is None:
        mapped_v4 = getattr(addr, "ipv4_mapped", None)
        if mapped_v4 is not None:
            hit = index.get(mapped_v4.compressed)
    if hit is None:
        return _empty_oxylabs_result(has_db=True, updated_at=updated_iso)

    return {
        "has_db": True,
        "isListed": True,
        "asn": hit[0],
        "orgName": hit[1],
        "updatedAt": hit[2],
        "sourceFile": hit[3],
        "offlineDbUpdatedAt": updated_iso,
    }


def _build_status_entry(
    spec: OfflineDatasetSpec,
    *,
    filename: str,
    exists: bool,
    size_bytes: Optional[int],
    mtime_ns: Optional[int],
    stale_after_seconds: int,
    now_ts: float,
    resolved_path: Optional[Path],
    include_resolved_path: bool,
) -> Dict[str, Any]:
    if not exists or mtime_ns is None:
        resolved_missing_label = (
            spec.missing_label
            if spec.missing_label is not None
            else ("Optional (Not Configured)" if spec.optional else "Missing")
        )
        entry: Dict[str, Any] = {
            "key": spec.key,
            "providerKey": spec.provider_key,
            "source": spec.source,
            "name": spec.name,
            "filename": filename,
            "exists": False,
            "optional": spec.optional,
            "sizeBytes": None,
            "lastModifiedIso": None,
            "ageSeconds": None,
            "staleAfterSeconds": stale_after_seconds,
            "status": "missing",
            "statusLabel": resolved_missing_label,
        }
    else:
        mtime_ts = mtime_ns / 1_000_000_000.0
        age_seconds = max(0, int(now_ts - mtime_ts))
        is_stale = stale_after_seconds > 0 and age_seconds > stale_after_seconds
        entry = {
            "key": spec.key,
            "providerKey": spec.provider_key,
            "source": spec.source,
            "name": spec.name,
            "filename": filename,
            "exists": True,
            "optional": spec.optional,
            "sizeBytes": int(size_bytes) if size_bytes is not None else 0,
            "lastModifiedIso": datetime.fromtimestamp(mtime_ts, tz=timezone.utc).isoformat(),
            "ageSeconds": age_seconds,
            "staleAfterSeconds": stale_after_seconds,
            "status": "stale" if is_stale else "healthy",
            "statusLabel": "Stale" if is_stale else "Healthy",
        }
    if include_resolved_path:
        entry["resolvedPath"] = str(resolved_path) if (resolved_path is not None and entry["exists"]) else ""
    return entry


def _scan_glob_dataset_files(
    spec: OfflineDatasetSpec,
    *,
    env_overrides: Optional[Mapping[str, str]] = None,
    base_dir: Optional[Path] = None,
) -> Tuple[Optional[Path], Tuple[Tuple[Path, int, int], ...]]:
    data_dir = resolve_feed_data_dir(
        spec.filename,
        override_setting=spec.override_setting or "",
        env_overrides=env_overrides,
        base_dir=base_dir,
    )
    if data_dir is None or not spec.glob_pattern:
        return data_dir, ()
    try:
        candidates = sorted(data_dir.glob(spec.glob_pattern), key=lambda path: path.name)
    except OSError:
        return data_dir, ()
    matched: List[Tuple[Path, int, int]] = []
    for file_path in candidates:
        sig = get_file_stat_signature(file_path, bypass_throttle=True)
        if sig is not None:
            matched.append((file_path, sig[0], sig[1]))
    return data_dir, tuple(matched)


def collect_offline_databases_status(
    *,
    now_dt: Optional[datetime] = None,
    env_overrides: Optional[Mapping[str, str]] = None,
    base_dir: Optional[Path] = None,
    include_resolved_path: bool = False,
) -> List[Dict[str, Any]]:
    """Inventories all local offline databases and rules from OFFLINE_DATASET_SPECS using file mtime metadata."""
    current_dt = now_dt or datetime.now(timezone.utc)
    now_ts = current_dt.timestamp()

    maxmind_paths = resolve_maxmind_paths(env_overrides=env_overrides, base_dir=base_dir)
    sfs_paths = resolve_stopforumspam_paths(env_overrides=env_overrides, base_dir=base_dir, bypass_throttle=True)
    hosting_rules_path, hosting_rules_name = resolve_hosting_rules_path(
        env_overrides=env_overrides, base_dir=base_dir, bypass_throttle=True
    )
    resolved_special_paths: Dict[str, Tuple[Optional[Path], Optional[str]]] = {
        "maxmind_country": (maxmind_paths.get("country"), None),
        "maxmind_city": (maxmind_paths.get("city"), None),
        "maxmind_asn": (maxmind_paths.get("asn"), None),
        "stopforumspam_toxic_cidr": (sfs_paths.get("toxic_cidr"), None),
        "stopforumspam_listed_90": (sfs_paths.get("listed_90"), None),
        "stopforumspam_listed_1": (sfs_paths.get("listed_1"), None),
        "stopforumspam_index": (sfs_paths.get("sqlite_index"), None),
        "hosting_asn_rules": (hosting_rules_path, hosting_rules_name),
    }

    entries: List[Dict[str, Any]] = []
    for spec in OFFLINE_DATASET_SPECS:
        stale_after = get_positive_int_setting(
            spec.stale_setting, spec.default_stale_seconds, env_overrides=env_overrides
        )
        if spec.glob_pattern:
            dataset_dir, matched_files = _scan_glob_dataset_files(spec, env_overrides=env_overrides, base_dir=base_dir)
            if not matched_files:
                entries.append(
                    _build_status_entry(
                        spec,
                        filename=f"{spec.filename}/{spec.glob_pattern}",
                        exists=False,
                        size_bytes=None,
                        mtime_ns=None,
                        stale_after_seconds=stale_after,
                        now_ts=now_ts,
                        resolved_path=dataset_dir,
                        include_resolved_path=include_resolved_path,
                    )
                )
            else:
                entries.append(
                    _build_status_entry(
                        spec,
                        filename=f"{spec.filename}/{spec.glob_pattern} ({len(matched_files)} files)",
                        exists=True,
                        size_bytes=sum(size for _, _, size in matched_files),
                        mtime_ns=max(mtime_ns for _, mtime_ns, _ in matched_files),
                        stale_after_seconds=stale_after,
                        now_ts=now_ts,
                        resolved_path=dataset_dir,
                        include_resolved_path=include_resolved_path,
                    )
                )
            continue

        if spec.key in resolved_special_paths:
            file_path, custom_fallback = resolved_special_paths[spec.key]
            fallback_filename = custom_fallback or spec.filename
        else:
            file_path = resolve_feed_data_path(
                spec.filename,
                override_setting=spec.override_setting or "",
                env_overrides=env_overrides,
                base_dir=base_dir,
                bypass_throttle=True,
            )
            fallback_filename = spec.filename

        filename = file_path.name if file_path is not None else fallback_filename
        sig = get_file_stat_signature(file_path, bypass_throttle=True) if file_path is not None else None
        entries.append(
            _build_status_entry(
                spec,
                filename=filename,
                exists=sig is not None,
                size_bytes=sig[1] if sig is not None else None,
                mtime_ns=sig[0] if sig is not None else None,
                stale_after_seconds=stale_after,
                now_ts=now_ts,
                resolved_path=file_path,
                include_resolved_path=include_resolved_path,
            )
        )
    return entries


def clear_offline_feed_caches() -> None:
    """Clears StopForumSpam and offline feed caches, closes handles, and resets stat throttling."""
    global _oxylabs_scan_cache

    clear_sfs_caches()
    _shared_cidrs_index.clear()
    _privacy_relays_index.clear()
    _ipsum_drop_index.clear()
    _bgp_tools_index.clear()
    _tor_onionoo_cache.clear()
    _bgp_tags_cache.clear()
    _mobile_asns_cache.clear()
    _oxylabs_cache.clear()
    with _oxylabs_scan_lock:
        _oxylabs_scan_cache = None
    clear_stat_throttle_cache()
