"""Offline threat, CIDR, Tor Onionoo, BGP.tools, and mobile ASN feeds plus database freshness status."""

from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

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
    DEFAULT_STALE_DAILY_FEED_SECONDS,
    DEFAULT_STALE_MAXMIND_SECONDS,
    DEFAULT_STALE_OPENASN_SECONDS,
    DEFAULT_STALE_RULES_SECONDS,
    DEFAULT_STALE_SFS_1_SECONDS,
    DEFAULT_STALE_SFS_90_SECONDS,
    DEFAULT_STALE_SFS_TOXIC_SECONDS,
    DEFAULT_STALE_SHARED_CIDRS_SECONDS,
    DEFAULT_STALE_TOR_ONIONOO_SECONDS,
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
    _parse_asn_int,
    clear_stat_throttle_cache,
    get_file_stat_signature,
    get_positive_int_setting,
    resolve_feed_data_path,
    resolve_hosting_rules_path,
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
    """Returns True when an ASN is tagged as mobile in PeeringDB mobile_asns.json or bgp_tags.json."""
    asn_num = _parse_asn_int(asn)
    if asn_num is None:
        return False

    path = resolve_feed_data_path(MOBILE_ASNS_JSON_FILENAME, override_setting="MOBILE_ASNS_JSON_PATH")
    peeringdb_asns: FrozenSet[int]
    if path is None:
        peeringdb_asns = _mobile_asns_cache.set_constant(("__missing__", -1, -1), frozenset())
    else:
        sig = get_file_stat_signature(path)
        if sig is None:
            peeringdb_asns = _mobile_asns_cache.set_constant(("__missing__", -1, -1), frozenset())
        else:
            target_key = (str(path), sig[0], sig[1])
            hit = _mobile_asns_cache.peek_matching(lambda key, _val: key == target_key)
            if hit is not None:
                peeringdb_asns = hit
            else:
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    logger.warning("Failed to parse mobile ASNs file %s: %s", path, exc)
                    peeringdb_asns = frozenset()
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
                    peeringdb_asns = _mobile_asns_cache.get_or_load(target_key, lambda: frozen_asns)

    if asn_num in peeringdb_asns:
        return True
    _tags_map, bgp_mobile_asns = _get_bgp_tags_data()
    return asn_num in bgp_mobile_asns


def build_offline_database_entries(
    *,
    maxmind_paths: Dict[str, Optional[Path]],
    sfs_paths: Dict[str, Optional[Path]],
    hosting_rules_path: Optional[Path],
    hosting_rules_name: str,
    maxmind_stale: int,
    sfs_toxic_stale: int,
    sfs_90_stale: int,
    sfs_1_stale: int,
    rules_stale: int,
    now_ts: float,
    extra_feed_specs: Optional[Sequence[Tuple[str, str, str, Optional[Path], str, bool, int, Optional[str]]]] = None,
    include_resolved_path: bool = False,
) -> List[Dict[str, Any]]:
    """Builds standardised status entries for all configured offline databases and rule files."""
    specs: List[Tuple[str, str, str, Optional[Path], str, bool, int, Optional[str]]] = [
        (
            "maxmind_country",
            "MaxMind",
            "MaxMind GeoLite2 Country",
            maxmind_paths.get("country"),
            MAXMIND_COUNTRY_DB_FILENAME,
            False,
            maxmind_stale,
            None,
        ),
        (
            "maxmind_city",
            "MaxMind",
            "MaxMind GeoLite2 City",
            maxmind_paths.get("city"),
            MAXMIND_CITY_DB_FILENAME,
            False,
            maxmind_stale,
            None,
        ),
        (
            "maxmind_asn",
            "MaxMind",
            "MaxMind GeoLite2 ASN",
            maxmind_paths.get("asn"),
            MAXMIND_ASN_DB_FILENAME,
            False,
            maxmind_stale,
            None,
        ),
        (
            "stopforumspam_toxic_cidr",
            "StopForumSpam",
            "StopForumSpam Toxic CIDRs",
            sfs_paths.get("toxic_cidr"),
            SFS_TOXIC_CIDR_FILENAME,
            False,
            sfs_toxic_stale,
            None,
        ),
        (
            "stopforumspam_listed_90",
            "StopForumSpam",
            "StopForumSpam Listed IPs (90d)",
            sfs_paths.get("listed_90"),
            SFS_LISTED_90_ZIP_NAME,
            False,
            sfs_90_stale,
            None,
        ),
        (
            "stopforumspam_listed_1",
            "StopForumSpam",
            "StopForumSpam Listed IPs (1d)",
            sfs_paths.get("listed_1"),
            SFS_LISTED_1_ZIP_NAME,
            True,
            sfs_1_stale,
            None,
        ),
        (
            "stopforumspam_index",
            "StopForumSpam",
            "StopForumSpam Local SQLite Index",
            sfs_paths.get("sqlite_index"),
            SFS_SQLITE_FILENAME,
            True,
            sfs_90_stale,
            None,
        ),
        (
            "hosting_asn_rules",
            "Hosting Rules",
            "Hosting ASN Rules",
            hosting_rules_path,
            hosting_rules_name,
            True,
            rules_stale,
            "Built-in (Optional)",
        ),
    ]
    if extra_feed_specs:
        specs.extend(extra_feed_specs)

    entries: List[Dict[str, Any]] = []
    for key, source, name, file_path, fallback_filename, optional, stale_after_seconds, missing_label in specs:
        filename = file_path.name if file_path is not None else fallback_filename
        sig = get_file_stat_signature(file_path, bypass_throttle=True) if file_path is not None else None
        if sig is None:
            resolved_missing_label = (
                missing_label if missing_label is not None else ("Optional (Not Configured)" if optional else "Missing")
            )
            entry: Dict[str, Any] = {
                "key": key,
                "source": source,
                "name": name,
                "filename": filename,
                "exists": False,
                "optional": optional,
                "sizeBytes": None,
                "lastModifiedIso": None,
                "ageSeconds": None,
                "staleAfterSeconds": stale_after_seconds,
                "status": "missing",
                "statusLabel": resolved_missing_label,
            }
        else:
            mtime_ts = sig[0] / 1_000_000_000.0
            age_seconds = max(0, int(now_ts - mtime_ts))
            is_stale = stale_after_seconds > 0 and age_seconds > stale_after_seconds
            entry = {
                "key": key,
                "source": source,
                "name": name,
                "filename": filename,
                "exists": True,
                "optional": optional,
                "sizeBytes": int(sig[1]),
                "lastModifiedIso": datetime.fromtimestamp(mtime_ts, tz=timezone.utc).isoformat(),
                "ageSeconds": age_seconds,
                "staleAfterSeconds": stale_after_seconds,
                "status": "stale" if is_stale else "healthy",
                "statusLabel": "Stale" if is_stale else "Healthy",
            }
        if include_resolved_path:
            entry["resolvedPath"] = str(file_path) if (file_path is not None and entry["exists"]) else ""
        entries.append(entry)
    return entries


def collect_offline_databases_status(
    *,
    now_dt: Optional[datetime] = None,
    env_overrides: Optional[Mapping[str, str]] = None,
    base_dir: Optional[Path] = None,
    include_resolved_path: bool = False,
) -> List[Dict[str, Any]]:
    """Inventories all local offline databases and rules using file mtime metadata."""
    current_dt = now_dt or datetime.now(timezone.utc)
    now_ts = current_dt.timestamp()

    maxmind_stale = get_positive_int_setting(
        "OFFLINE_DB_MAXMIND_STALE_SECONDS", DEFAULT_STALE_MAXMIND_SECONDS, env_overrides=env_overrides
    )
    sfs_toxic_stale = get_positive_int_setting(
        "OFFLINE_DB_SFS_TOXIC_STALE_SECONDS", DEFAULT_STALE_SFS_TOXIC_SECONDS, env_overrides=env_overrides
    )
    sfs_90_stale = get_positive_int_setting(
        "OFFLINE_DB_SFS_90_STALE_SECONDS", DEFAULT_STALE_SFS_90_SECONDS, env_overrides=env_overrides
    )
    sfs_1_stale = get_positive_int_setting(
        "OFFLINE_DB_SFS_1_STALE_SECONDS", DEFAULT_STALE_SFS_1_SECONDS, env_overrides=env_overrides
    )
    shared_cidrs_stale = get_positive_int_setting(
        "OFFLINE_DB_SHARED_CIDRS_STALE_SECONDS", DEFAULT_STALE_SHARED_CIDRS_SECONDS, env_overrides=env_overrides
    )
    openasn_stale = get_positive_int_setting(
        "OFFLINE_DB_OPENASN_STALE_SECONDS", DEFAULT_STALE_OPENASN_SECONDS, env_overrides=env_overrides
    )
    rules_stale = get_positive_int_setting(
        "OFFLINE_DB_RULES_STALE_SECONDS", DEFAULT_STALE_RULES_SECONDS, env_overrides=env_overrides
    )
    tor_stale = get_positive_int_setting(
        "OFFLINE_DB_TOR_ONIONOO_STALE_SECONDS", DEFAULT_STALE_TOR_ONIONOO_SECONDS, env_overrides=env_overrides
    )
    daily_feed_stale = get_positive_int_setting(
        "OFFLINE_DB_DAILY_FEED_STALE_SECONDS", DEFAULT_STALE_DAILY_FEED_SECONDS, env_overrides=env_overrides
    )

    maxmind_paths = resolve_maxmind_paths(env_overrides=env_overrides, base_dir=base_dir)
    sfs_paths = resolve_stopforumspam_paths(env_overrides=env_overrides, base_dir=base_dir, bypass_throttle=True)
    hosting_rules_path, hosting_rules_name = resolve_hosting_rules_path(
        env_overrides=env_overrides, base_dir=base_dir, bypass_throttle=True
    )

    extra_specs = (
        (
            "shared_cidrs",
            "Shared CIDRs",
            "Rezmoss Shared Egress CIDRs",
            resolve_feed_data_path(
                SHARED_CIDRS_BIN_FILENAME,
                override_setting="SHARED_CIDRS_BIN_PATH",
                env_overrides=env_overrides,
                base_dir=base_dir,
                bypass_throttle=True,
            ),
            SHARED_CIDRS_BIN_FILENAME,
            True,
            shared_cidrs_stale,
            None,
        ),
        (
            "privacy_relays",
            "Privacy Relays",
            "Apple Private Relay and Cloudflare WARP",
            resolve_feed_data_path(
                PRIVACY_RELAYS_BIN_FILENAME,
                override_setting="PRIVACY_RELAYS_BIN_PATH",
                env_overrides=env_overrides,
                base_dir=base_dir,
                bypass_throttle=True,
            ),
            PRIVACY_RELAYS_BIN_FILENAME,
            True,
            daily_feed_stale,
            None,
        ),
        (
            "ipsum_drop",
            "IPsum and DROP",
            "IPsum and Spamhaus DROP Index",
            resolve_feed_data_path(
                IPSUM_DROP_BIN_FILENAME,
                override_setting="IPSUM_DROP_BIN_PATH",
                env_overrides=env_overrides,
                base_dir=base_dir,
                bypass_throttle=True,
            ),
            IPSUM_DROP_BIN_FILENAME,
            True,
            daily_feed_stale,
            None,
        ),
        (
            "tor_onionoo",
            "Tor Onionoo",
            "Tor Onionoo Summary Mirror",
            resolve_feed_data_path(
                TOR_ONIONOO_SUMMARY_FILENAME,
                override_setting="TOR_ONIONOO_SUMMARY_PATH",
                env_overrides=env_overrides,
                base_dir=base_dir,
                bypass_throttle=True,
            ),
            TOR_ONIONOO_SUMMARY_FILENAME,
            True,
            tor_stale,
            None,
        ),
        (
            "bgp_tools",
            "BGP Tools",
            "BGP Routing Table Prefix Index",
            resolve_feed_data_path(
                BGP_TOOLS_BIN_FILENAME,
                override_setting="BGP_TOOLS_BIN_PATH",
                env_overrides=env_overrides,
                base_dir=base_dir,
                bypass_throttle=True,
            ),
            BGP_TOOLS_BIN_FILENAME,
            True,
            daily_feed_stale,
            None,
        ),
        (
            "openasn",
            "OpenASN",
            "OpenASN IP/ASN Classification",
            resolve_feed_data_path(
                OPENASN_MMDB_FILENAME,
                override_setting="OPENASN_MMDB_PATH",
                env_overrides=env_overrides,
                base_dir=base_dir,
                bypass_throttle=True,
            ),
            OPENASN_MMDB_FILENAME,
            True,
            openasn_stale,
            None,
        ),
        (
            "peeringdb_mobile",
            "PeeringDB",
            "PeeringDB Mobile ASNs",
            resolve_feed_data_path(
                MOBILE_ASNS_JSON_FILENAME,
                override_setting="MOBILE_ASNS_JSON_PATH",
                env_overrides=env_overrides,
                base_dir=base_dir,
                bypass_throttle=True,
            ),
            MOBILE_ASNS_JSON_FILENAME,
            True,
            daily_feed_stale,
            None,
        ),
    )

    return build_offline_database_entries(
        maxmind_paths=maxmind_paths,
        sfs_paths=sfs_paths,
        hosting_rules_path=hosting_rules_path,
        hosting_rules_name=hosting_rules_name,
        maxmind_stale=maxmind_stale,
        sfs_toxic_stale=sfs_toxic_stale,
        sfs_90_stale=sfs_90_stale,
        sfs_1_stale=sfs_1_stale,
        rules_stale=rules_stale,
        extra_feed_specs=extra_specs,
        now_ts=now_ts,
        include_resolved_path=include_resolved_path,
    )


def clear_stopforumspam_caches() -> None:
    """Clears StopForumSpam and offline feed caches, closes handles, and resets stat throttling."""
    clear_sfs_caches()
    _shared_cidrs_index.clear()
    _privacy_relays_index.clear()
    _ipsum_drop_index.clear()
    _bgp_tools_index.clear()
    _tor_onionoo_cache.clear()
    _bgp_tags_cache.clear()
    _mobile_asns_cache.clear()
    clear_stat_throttle_cache()
