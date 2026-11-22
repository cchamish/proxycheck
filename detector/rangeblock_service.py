"""Cross-wiki rangeblock lookup combining ToolsDB aggregates with live Wiki Replicas queries."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import quote

import pymysql
from asgiref.sync import sync_to_async
from django.conf import settings
from django.db import Error as DjangoDbError
from django.db import close_old_connections

from proxycheck.settings import discover_wiki_replica_credentials

from . import sanitization
from .intelligence import canonicalize_ip, classify_non_public_ip
from .models import RangeblockAggregate, RangeblockSyncState

logger = logging.getLogger("detector.views")

_WIKI_DBNAME_RE = re.compile(r"^[a-z0-9_]{2,64}$")
_SPECIAL_WIKI_DOMAINS: Dict[str, str] = {
    "global": "meta.wikimedia.org",
    "metawiki": "meta.wikimedia.org",
    "commonswiki": "commons.wikimedia.org",
    "wikidatawiki": "www.wikidata.org",
    "mediawikiwiki": "www.mediawiki.org",
    "specieswiki": "species.wikimedia.org",
    "incubatorwiki": "incubator.wikimedia.org",
    "sourceswiki": "wikisource.org",
    "outreachwiki": "outreach.wikimedia.org",
    "foundationwiki": "foundation.wikimedia.org",
    "wikimaniawiki": "wikimania.wikimedia.org",
    "testwiki": "test.wikipedia.org",
    "test2wiki": "test2.wikipedia.org",
    "simplewiki": "simple.wikipedia.org",
    "enwiki": "en.wikipedia.org",
    "zhwiki": "zh.wikipedia.org",
}
_WIKI_SUFFIX_MAP: Tuple[Tuple[str, str], ...] = (
    ("wiktionary", "wiktionary.org"),
    ("wikibooks", "wikibooks.org"),
    ("wikinews", "wikinews.org"),
    ("wikiquote", "wikiquote.org"),
    ("wikisource", "wikisource.org"),
    ("wikiversity", "wikiversity.org"),
    ("wikivoyage", "wikivoyage.org"),
    ("wikimedia", "wikimedia.org"),
    ("wiki", "wikipedia.org"),
)


@dataclass(frozen=True, slots=True)
class RangeblockCandidate:
    """Represents one candidate single-IP or CIDR lookup target."""

    target: str
    cidr: Optional[int]
    upper_bound: str
    range_start_bin: bytes
    range_end_bin: bytes


def normalize_wiki_dbname(raw_wiki: Any) -> Optional[str]:
    """Validates and normalises a Wikimedia database name."""
    if not isinstance(raw_wiki, str):
        return None
    cleaned = raw_wiki.strip().lower()
    if not cleaned or not _WIKI_DBNAME_RE.fullmatch(cleaned):
        return None
    return cleaned


def get_configured_realtime_wikis() -> Tuple[str, ...]:
    """Returns configured real-time Wiki Replicas database names, defaulting to enwiki."""
    raw = getattr(settings, "RANGEBLOCK_REALTIME_WIKIS", "enwiki")
    items: Iterable[str]
    if isinstance(raw, str):
        items = raw.split(",")
    elif isinstance(raw, Iterable):
        items = (str(item) for item in raw)
    else:
        return ("enwiki",)

    out: List[str] = []
    for item in items:
        norm = normalize_wiki_dbname(item)
        if norm and norm != "global" and norm not in out:
            out.append(norm)
    return tuple(out) if out else ("enwiki",)


def compute_effective_block_count(log_count: int, has_active: bool) -> int:
    """Ensures an active block without a matching log entry counts as 1 without double-counting."""
    safe_logs = max(0, int(log_count))
    if has_active and safe_logs == 0:
        return 1
    return safe_logs


def _pack_address_bin(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bytes:
    if addr.version == 4:
        return b"\x00" * 10 + b"\xff\xff" + addr.packed
    return addr.packed


def normalize_block_target(raw_target: str) -> Optional[Tuple[str, int, Optional[int], bytes, bytes]]:
    """Normalises a single IP or allowed CIDR target and rejects IPv6 prefixes narrower than /64."""
    if not isinstance(raw_target, str):
        return None
    cleaned = raw_target.strip()
    if cleaned.lower().startswith("user:"):
        cleaned = cleaned[5:].strip()
    if not cleaned:
        return None

    if "/" not in cleaned:
        canonical = canonicalize_ip(cleaned)
        if not canonical:
            return None
        addr = ipaddress.ip_address(canonical)
        packed = _pack_address_bin(addr)
        return addr.compressed, addr.version, None, packed, packed

    try:
        net = ipaddress.ip_network(cleaned, strict=False)
    except ValueError:
        return None

    if net.version == 4 and not (16 <= net.prefixlen <= 32):
        return None
    if net.version == 6 and not (19 <= net.prefixlen <= 64):
        return None

    start_bin = _pack_address_bin(net.network_address)
    end_bin = _pack_address_bin(net.broadcast_address)
    return str(net), net.version, int(net.prefixlen), start_bin, end_bin


def generate_rangeblock_candidates(canonical_ip: str) -> Tuple[int, List[RangeblockCandidate]]:
    """Builds the ordered candidate target list for IPv4 (/32 to /16) or IPv6 (/64 to /19)."""
    addr = ipaddress.ip_address(canonical_ip)
    single_bin = _pack_address_bin(addr)
    candidates: List[RangeblockCandidate] = [
        RangeblockCandidate(
            target=addr.compressed,
            cidr=None,
            upper_bound=addr.compressed,
            range_start_bin=single_bin,
            range_end_bin=single_bin,
        )
    ]

    prefixes = range(32, 15, -1) if addr.version == 4 else range(64, 18, -1)

    for prefix in prefixes:
        net = ipaddress.ip_network(f"{addr.compressed}/{prefix}", strict=False)
        candidates.append(
            RangeblockCandidate(
                target=str(net),
                cidr=prefix,
                upper_bound=net.broadcast_address.compressed,
                range_start_bin=_pack_address_bin(net.network_address),
                range_end_bin=_pack_address_bin(net.broadcast_address),
            )
        )
    return addr.version, candidates


def parse_mw_expiry(raw_expiry: Any) -> Tuple[Optional[datetime], bool]:
    """Parses a MediaWiki block expiry timestamp or infinity marker into UTC datetime and indefinite flag."""
    if raw_expiry is None:
        return None, False
    if isinstance(raw_expiry, datetime):
        dt_val = (
            raw_expiry.replace(tzinfo=timezone.utc)
            if raw_expiry.tzinfo is None
            else raw_expiry.astimezone(timezone.utc)
        )
        return dt_val, False
    text = (
        raw_expiry.decode("utf-8", errors="ignore") if isinstance(raw_expiry, (bytes, bytearray)) else str(raw_expiry)
    )
    cleaned = text.strip().lower()
    if not cleaned:
        return None, False
    if cleaned in ("infinity", "indefinite", "infinite"):
        return None, True
    if len(cleaned) == 14 and cleaned.isdigit():
        try:
            return datetime.strptime(cleaned, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc), False
        except ValueError:
            return None, False
    return None, False


def parse_mw_timestamp(raw_ts: Any) -> Optional[datetime]:
    """Parses a 14-digit MediaWiki UTC timestamp into a timezone-aware datetime."""
    dt_val, _ = parse_mw_expiry(raw_ts)
    return dt_val


def resolve_wiki_domain(wiki_dbname: str, domain_map: Optional[Mapping[str, str]] = None) -> str:
    """Resolves a Wikimedia database name to its canonical HTTPS hostname."""
    if wiki_dbname == "global":
        return "meta.wikimedia.org"
    if domain_map:
        mapped = domain_map.get(wiki_dbname)
        if isinstance(mapped, str) and mapped.strip():
            cleaned = mapped.strip().removeprefix("https://").removeprefix("http://").split("/")[0]
            if cleaned:
                return cleaned
    if wiki_dbname in _SPECIAL_WIKI_DOMAINS:
        return _SPECIAL_WIKI_DOMAINS[wiki_dbname]
    for suffix, base_domain in _WIKI_SUFFIX_MAP:
        if wiki_dbname.endswith(suffix) and len(wiki_dbname) > len(suffix):
            prefix = wiki_dbname[: -len(suffix)].replace("_", "-")
            return f"{prefix}.{base_domain}"
    return "meta.wikimedia.org"


def build_rangeblock_links(wiki_dbname: str, domain: str, target: str) -> Tuple[str, str]:
    """Builds Special:Log and Special:BlockList or GlobalBlockList URLs for a target."""
    encoded_target = quote(target, safe="/:")
    if wiki_dbname == "global":
        return (
            f"https://meta.wikimedia.org/wiki/Special:Log?type=gblblock&page=User:{encoded_target}",
            f"https://meta.wikimedia.org/wiki/Special:GlobalBlockList?ip={encoded_target}",
        )
    return (
        f"https://{domain}/wiki/Special:Log?type=block&page=User:{encoded_target}",
        f"https://{domain}/wiki/Special:BlockList?wpTarget={encoded_target}",
    )


def build_empty_rangeblock_summary(canonical_ip: str, *, realtime_degraded: bool = False) -> Dict[str, Any]:
    """Returns a zeroed rangeblock summary payload for non-public or unblocked addresses."""
    ip_version = 6 if ":" in canonical_ip else 4
    return {
        "ip": canonical_ip,
        "ipVersion": ip_version,
        "localTotal": 0,
        "globalTotal": 0,
        "hasActive": False,
        "realtimeDegraded": realtime_degraded,
        "wikis": [],
    }


def _query_toolsdb_aggregates_sync(
    v4_targets: Sequence[str],
    v6_targets: Sequence[str],
) -> Tuple[List[RangeblockAggregate], Dict[str, str]]:
    rows: List[RangeblockAggregate] = []
    domain_map: Dict[str, str] = {}
    try:
        close_old_connections()
        if v4_targets:
            rows.extend(RangeblockAggregate.objects.filter(ip_version=4, target_cidr__in=list(v4_targets)))
        if v6_targets:
            rows.extend(RangeblockAggregate.objects.filter(ip_version=6, target_cidr__in=list(v6_targets)))
        wiki_names = {row.wiki_dbname for row in rows if row.wiki_dbname != "global"}
        if wiki_names:
            for state in RangeblockSyncState.objects.filter(wiki_dbname__in=list(wiki_names)):
                if state.wiki_domain:
                    domain_map[state.wiki_dbname] = state.wiki_domain
    except DjangoDbError as db_err:
        logger.warning(
            "Rangeblock ToolsDB query bypassed due to database error: %s",
            sanitization.sanitize_error_message(str(db_err)),
        )
        return [], {}
    except AssertionError as exc:
        if type(exc).__name__ == "DatabaseOperationForbidden":
            return [], {}
        raise
    finally:
        close_old_connections()
    return rows, domain_map


def _mediawiki_target_spelling(target: str) -> str:
    """Spells an IPv6 target as MediaWiki stores it (IPUtils::sanitizeIP): eight uppercase words, no leading zeros."""
    address, separator, prefix = target.partition("/")
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return target
    if addr.version == 4:
        return target
    words = ":".join(f"{int(word, 16):X}" for word in addr.exploded.split(":"))
    return f"{words}{separator}{prefix}"


def expand_db_lookup_targets(targets: Sequence[str]) -> List[str]:
    """Returns each target alongside its MediaWiki spelling for exact-match replica lookups."""
    expanded: List[str] = []
    seen: Set[str] = set()
    for target in targets:
        for variant in (target, _mediawiki_target_spelling(target)):
            if variant not in seen:
                seen.add(variant)
                expanded.append(variant)
    return expanded


def _empty_target_entry() -> Dict[str, Any]:
    return {
        "block_count": 0,
        "has_active": False,
        "active_expiry": None,
        "active_indefinite": False,
        "last_blocked_at": None,
    }


def _apply_active_block_row(
    bucket: Dict[str, Dict[str, Any]],
    raw_target: Any,
    raw_expiry: Any,
) -> None:
    target_text = (
        raw_target.decode("utf-8", errors="ignore")
        if isinstance(raw_target, (bytes, bytearray))
        else str(raw_target or "")
    )
    normalised = normalize_block_target(target_text)
    if normalised is None:
        return
    norm_target = normalised[0]
    entry = bucket.setdefault(norm_target, _empty_target_entry())
    expiry_dt, is_indef = parse_mw_expiry(raw_expiry)
    entry["has_active"] = True
    if is_indef:
        entry["active_indefinite"] = True
        entry["active_expiry"] = None
    elif (
        expiry_dt is not None
        and not entry["active_indefinite"]
        and (entry["active_expiry"] is None or expiry_dt > entry["active_expiry"])
    ):
        entry["active_expiry"] = expiry_dt


def _apply_log_count_row(
    bucket: Dict[str, Dict[str, Any]],
    raw_target: Any,
    raw_count: Any,
    raw_last_ts: Any,
) -> None:
    target_text = (
        raw_target.decode("utf-8", errors="ignore")
        if isinstance(raw_target, (bytes, bytearray))
        else str(raw_target or "")
    )
    normalised = normalize_block_target(target_text)
    if normalised is None:
        return
    norm_target = normalised[0]
    entry = bucket.setdefault(norm_target, _empty_target_entry())
    entry["block_count"] += max(0, int(raw_count or 0))
    last_dt = parse_mw_timestamp(raw_last_ts)
    if last_dt is not None and (entry["last_blocked_at"] is None or last_dt > entry["last_blocked_at"]):
        entry["last_blocked_at"] = last_dt


def _query_local_wiki_tables(
    cursor: Any,
    targets: Sequence[str],
    now_mw: str,
) -> Dict[str, Dict[str, Any]]:
    bucket: Dict[str, Dict[str, Any]] = {}
    placeholders = ", ".join(["%s"] * len(targets))
    active_sql = (
        "SELECT bt.bt_address, b.bl_expiry FROM block b "  # noqa: S608
        "JOIN block_target bt ON b.bl_target = bt.bt_id "
        f"WHERE bt.bt_user IS NULL AND bt.bt_address IN ({placeholders}) "
        "AND (b.bl_expiry = 'infinity' OR b.bl_expiry > %s)"
    )
    cursor.execute(active_sql, [*targets, now_mw])
    for raw_target, raw_expiry in cursor.fetchall():
        _apply_active_block_row(bucket, raw_target, raw_expiry)

    log_sql = (
        "SELECT log_title, COUNT(*), MAX(log_timestamp) FROM logging_logindex "  # noqa: S608
        "WHERE log_type = 'block' AND log_action = 'block' AND log_namespace = 2 "
        f"AND log_title IN ({placeholders}) GROUP BY log_title"
    )
    cursor.execute(log_sql, list(targets))
    for raw_target, raw_count, raw_ts in cursor.fetchall():
        _apply_log_count_row(bucket, raw_target, raw_count, raw_ts)
    return bucket


def _query_global_wiki_tables(
    cursor: Any,
    targets: Sequence[str],
    now_mw: str,
) -> Dict[str, Dict[str, Any]]:
    bucket: Dict[str, Dict[str, Any]] = {}
    placeholders = ", ".join(["%s"] * len(targets))
    gbl_log_sql = (
        "SELECT log_title, COUNT(*), MAX(log_timestamp) FROM logging_logindex "  # noqa: S608
        "WHERE log_type = 'gblblock' AND log_action IN ('gblock', 'gblock2') AND log_namespace = 2 "
        f"AND log_title IN ({placeholders}) GROUP BY log_title"
    )
    cursor.execute(gbl_log_sql, list(targets))
    for raw_target, raw_count, raw_ts in cursor.fetchall():
        _apply_log_count_row(bucket, raw_target, raw_count, raw_ts)
    return bucket


def _query_active_global_blocks(
    bucket: Dict[str, Dict[str, Any]],
    targets: Sequence[str],
    now_mw: str,
    creds: Tuple[str, str],
) -> None:
    user, password = creds
    placeholders = ", ".join(["%s"] * len(targets))
    conn = pymysql.connect(
        host="centralauth.web.db.svc.wikimedia.cloud",
        user=user,
        password=password,
        database="centralauth_p",
        port=3306,
        connect_timeout=2,
        read_timeout=3,
        write_timeout=3,
        charset="utf8mb4",
        autocommit=True,
    )
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT gb_address, gb_expiry FROM globalblocks "  # noqa: S608
                f"WHERE gb_address IN ({placeholders}) AND (gb_expiry = 'infinity' OR gb_expiry > %s)",
                [*targets, now_mw],
            )
            for raw_target, raw_expiry in cursor.fetchall():
                _apply_active_block_row(bucket, raw_target, raw_expiry)
    finally:
        conn.close()


def _query_single_replica_wiki_sync(
    wiki_dbname: str,
    db_targets: Sequence[str],
    creds: Tuple[str, str],
) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Queries a single Wiki Replicas database synchronously using PyMySQL."""
    if not db_targets:
        return {}
    user, password = creds
    now_mw = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    conn = pymysql.connect(
        host=f"{wiki_dbname}.web.db.svc.wikimedia.cloud",
        user=user,
        password=password,
        database=f"{wiki_dbname}_p",
        port=3306,
        connect_timeout=2,
        read_timeout=3,
        write_timeout=3,
        charset="utf8mb4",
        autocommit=True,
    )
    try:
        out: Dict[str, Dict[str, Dict[str, Any]]] = {}
        with conn.cursor() as cursor:
            out[wiki_dbname] = _query_local_wiki_tables(cursor, db_targets, now_mw)
            if wiki_dbname == "metawiki":
                out["global"] = _query_global_wiki_tables(cursor, db_targets, now_mw)
        if wiki_dbname == "metawiki":
            _query_active_global_blocks(out["global"], db_targets, now_mw, creds)
        return out
    finally:
        conn.close()


async def _fetch_realtime_wiki_blocks(
    all_targets: Sequence[str],
    realtime_wikis: Sequence[str],
) -> Tuple[Dict[str, Dict[str, Dict[str, Any]]], Set[str], bool]:
    if not all_targets or not realtime_wikis:
        return {}, set(), False
    creds = discover_wiki_replica_credentials()
    if creds is None:
        return {}, set(), False

    expanded_targets = expand_db_lookup_targets(all_targets)
    results = await asyncio.gather(
        *(
            asyncio.to_thread(_query_single_replica_wiki_sync, wiki_name, expanded_targets, creds)
            for wiki_name in realtime_wikis
        ),
        return_exceptions=True,
    )

    realtime_by_wiki: Dict[str, Dict[str, Dict[str, Any]]] = {}
    succeeded_wikis: Set[str] = set()
    degraded = False
    for wiki_name, res in zip(realtime_wikis, results, strict=True):
        if isinstance(res, Exception):
            degraded = True
            logger.warning(
                "Wiki Replicas real-time rangeblock query degraded for %s: %s",
                wiki_name,
                sanitization.sanitize_error_message(str(res)),
            )
            continue
        if isinstance(res, dict):
            succeeded_wikis.add(wiki_name)
            if wiki_name == "metawiki":
                succeeded_wikis.add("global")
            for k, v in res.items():
                realtime_by_wiki[k] = v
    return realtime_by_wiki, succeeded_wikis, degraded


def _row_from_record(
    wiki_dbname: str,
    domain: str,
    candidate: RangeblockCandidate,
    rec: Mapping[str, Any],
) -> Dict[str, Any]:
    has_active = bool(rec.get("has_active"))
    count = compute_effective_block_count(int(rec.get("block_count") or 0), has_active)
    expiry_dt = rec.get("active_expiry")
    is_indef = bool(rec.get("active_indefinite"))
    last_dt = rec.get("last_blocked_at")
    log_url, block_list_url = build_rangeblock_links(wiki_dbname, domain, candidate.target)
    return {
        "target": candidate.target,
        "cidr": candidate.cidr,
        "upperBound": candidate.upper_bound,
        "count": count,
        "isActive": has_active,
        "expiry": expiry_dt.isoformat() if isinstance(expiry_dt, datetime) else None,
        "indefinite": is_indef,
        "lastBlockedAt": last_dt.isoformat() if isinstance(last_dt, datetime) else None,
        "logUrl": log_url,
        "blockListUrl": block_list_url,
    }


def merge_rangeblock_records(
    canonical_ip: str,
    ip_version: int,
    candidates: Sequence[RangeblockCandidate],
    toolsdb_rows: Sequence[RangeblockAggregate],
    realtime_by_wiki: Mapping[str, Mapping[str, Mapping[str, Any]]],
    succeeded_realtime_wikis: Set[str],
    domain_map: Optional[Mapping[str, str]] = None,
    *,
    realtime_degraded: bool = False,
) -> Dict[str, Any]:
    """Merges ToolsDB aggregates with real-time Wiki Replicas results for one IP."""
    candidate_by_target = {cand.target: cand for cand in candidates}
    candidate_order = {cand.target: idx for idx, cand in enumerate(candidates)}

    merged_by_wiki: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for row in toolsdb_rows:
        if row.target_cidr not in candidate_by_target:
            continue
        if row.wiki_dbname in succeeded_realtime_wikis:
            continue
        wiki_bucket = merged_by_wiki.setdefault(row.wiki_dbname, {})
        wiki_bucket[row.target_cidr] = {
            "block_count": int(row.block_count),
            "has_active": bool(row.has_active),
            "active_expiry": row.active_expiry,
            "active_indefinite": bool(row.active_indefinite),
            "last_blocked_at": row.last_blocked_at,
        }

    for wiki_dbname, target_map in realtime_by_wiki.items():
        if wiki_dbname not in succeeded_realtime_wikis:
            continue
        wiki_bucket = merged_by_wiki.setdefault(wiki_dbname, {})
        for target_cidr, rec in target_map.items():
            if target_cidr in candidate_by_target:
                wiki_bucket[target_cidr] = dict(rec)

    wikis_out: List[Dict[str, Any]] = []
    local_total = 0
    global_total = 0
    any_active = False

    for wiki_dbname, target_map in merged_by_wiki.items():
        if not target_map:
            continue
        domain = resolve_wiki_domain(wiki_dbname, domain_map)
        rows_out = [
            _row_from_record(wiki_dbname, domain, candidate_by_target[target], rec)
            for target, rec in sorted(target_map.items(), key=lambda item: candidate_order.get(item[0], 999))
            if target in candidate_by_target
        ]
        rows_out = [r for r in rows_out if r["count"] > 0 or r["isActive"]]
        if not rows_out:
            continue

        wiki_count = sum(r["count"] for r in rows_out)
        wiki_active = any(r["isActive"] for r in rows_out)
        is_global = wiki_dbname == "global"
        if is_global:
            global_total += wiki_count
        else:
            local_total += wiki_count
        if wiki_active:
            any_active = True

        wikis_out.append(
            {
                "wiki": wiki_dbname,
                "isGlobal": is_global,
                "count": wiki_count,
                "hasActive": wiki_active,
                "domain": domain,
                "rows": rows_out,
            }
        )

    wikis_out.sort(
        key=lambda item: (
            0 if item["hasActive"] else 1,
            0 if item["isGlobal"] else 1,
            -int(item["count"]),
            item["wiki"],
        )
    )

    return {
        "ip": canonical_ip,
        "ipVersion": ip_version,
        "localTotal": local_total,
        "globalTotal": global_total,
        "hasActive": any_active,
        "realtimeDegraded": realtime_degraded,
        "wikis": wikis_out,
    }


def _resolve_realtime_wiki_list(requested_wiki: Optional[str]) -> Tuple[str, ...]:
    ordered: List[str] = ["metawiki"]
    for w in get_configured_realtime_wikis():
        if w not in ordered:
            ordered.append(w)
    norm_req = normalize_wiki_dbname(requested_wiki)
    if norm_req and norm_req != "global" and norm_req not in ordered:
        ordered.append(norm_req)
    return tuple(ordered)


async def query_rangeblocks_for_ips(
    canonical_ips: Sequence[str],
    *,
    wiki: Optional[str] = None,
) -> Dict[str, Dict[str, Any]]:
    """Queries cross-wiki rangeblock summaries for one or more canonical IPs in parallel."""
    out: Dict[str, Dict[str, Any]] = {}
    public_specs: List[Tuple[str, int, List[RangeblockCandidate]]] = []
    v4_targets: Set[str] = set()
    v6_targets: Set[str] = set()

    for raw_ip in canonical_ips:
        canonical = canonicalize_ip(str(raw_ip))
        if not canonical:
            continue
        if classify_non_public_ip(canonical) is not None:
            out[canonical] = build_empty_rangeblock_summary(canonical)
            continue
        ip_version, candidates = generate_rangeblock_candidates(canonical)
        public_specs.append((canonical, ip_version, candidates))
        target_bucket = v4_targets if ip_version == 4 else v6_targets
        for cand in candidates:
            target_bucket.add(cand.target)

    if not public_specs:
        return out

    all_targets = sorted(v4_targets | v6_targets)
    realtime_wikis = _resolve_realtime_wiki_list(wiki)
    toolsdb_task = sync_to_async(_query_toolsdb_aggregates_sync, thread_sensitive=True)(
        sorted(v4_targets), sorted(v6_targets)
    )
    realtime_task = _fetch_realtime_wiki_blocks(all_targets, realtime_wikis)
    (toolsdb_rows, domain_map), (realtime_by_wiki, succeeded_wikis, realtime_degraded) = await asyncio.gather(
        toolsdb_task,
        realtime_task,
    )

    for canonical, ip_version, candidates in public_specs:
        out[canonical] = merge_rangeblock_records(
            canonical,
            ip_version,
            candidates,
            toolsdb_rows,
            realtime_by_wiki,
            succeeded_wikis,
            domain_map,
            realtime_degraded=realtime_degraded,
        )
    return out


async def query_rangeblocks_for_ip(
    canonical_ip: str,
    *,
    wiki: Optional[str] = None,
) -> Dict[str, Any]:
    """Queries cross-wiki rangeblock summary for a single canonical IP address."""
    canonical = canonicalize_ip(canonical_ip) or canonical_ip
    results = await query_rangeblocks_for_ips([canonical], wiki=wiki)
    return results.get(canonical) or build_empty_rangeblock_summary(canonical)
