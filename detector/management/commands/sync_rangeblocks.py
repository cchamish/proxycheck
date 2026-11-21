"""Hourly management command to synchronise cross-wiki rangeblock aggregates from Wiki Replicas."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pymysql
from django.core.management.base import BaseCommand, CommandError
from django.db import close_old_connections, transaction

from detector.models import RangeblockAggregate, RangeblockSyncState
from detector.rangeblock_service import (
    compute_effective_block_count,
    normalize_block_target,
    parse_mw_expiry,
    parse_mw_timestamp,
)
from detector.sanitization import sanitize_error_message
from proxycheck.settings import discover_wiki_replica_credentials

logger = logging.getLogger("detector.views")

_DEFAULT_BATCH_SIZE = 50000


def _decode_str(raw_val: Any) -> str:
    if isinstance(raw_val, (bytes, bytearray)):
        return raw_val.decode("utf-8", errors="ignore")
    return str(raw_val or "")


def _extract_domain_from_url(raw_url: Any) -> str:
    text = _decode_str(raw_url).strip()
    text = text.removeprefix("https://").removeprefix("http://")
    return text.split("/")[0].strip()


def _normalise_section(raw_section: Any) -> str:
    return _decode_str(raw_section).strip().lower().split(".", 1)[0] or "s1"


def _connect_replica(host: str, database: str, creds: Tuple[str, str]) -> pymysql.connections.Connection:
    user, password = creds
    return pymysql.connect(
        host=host,
        user=user,
        password=password,
        database=database,
        port=3306,
        connect_timeout=5,
        read_timeout=30,
        write_timeout=10,
        charset="utf8mb4",
        autocommit=True,
    )


def _fetch_active_wikis(
    creds: Tuple[str, str],
    *,
    filter_wikis: Optional[set[str]] = None,
    filter_sections: Optional[set[str]] = None,
) -> List[Tuple[str, str, str]]:
    conn = _connect_replica("meta.analytics.db.svc.wikimedia.cloud", "meta_p", creds)
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT dbname, url, slice FROM meta_p.wiki WHERE is_closed = 0 ORDER BY slice, dbname")
            out: List[Tuple[str, str, str]] = []
            for raw_db, raw_url, raw_slice in cursor.fetchall():
                dbname = _decode_str(raw_db).strip().lower()
                domain = _extract_domain_from_url(raw_url)
                section = _normalise_section(raw_slice)
                if not dbname:
                    continue
                if filter_wikis and dbname not in filter_wikis:
                    continue
                if filter_sections and section not in filter_sections:
                    continue
                out.append((dbname, domain, section))
            return out
    finally:
        conn.close()


def _collect_active_local_blocks(cursor: Any, wiki_db: str, now_mw: str) -> Dict[str, Dict[str, Any]]:
    sql = (
        f"SELECT bt.bt_address, b.bl_expiry FROM `{wiki_db}`.`block` b "  # noqa: S608
        f"JOIN `{wiki_db}`.`block_target` bt ON b.bl_target = bt.bt_id "  # noqa: S608
        "WHERE bt.bt_user IS NULL AND (b.bl_expiry = 'infinity' OR b.bl_expiry > %s)"
    )
    cursor.execute(sql, [now_mw])
    return _aggregate_active_rows(cursor.fetchall())


def _collect_active_global_blocks(creds: Tuple[str, str], now_mw: str) -> Dict[str, Dict[str, Any]]:
    conn = _connect_replica("centralauth.analytics.db.svc.wikimedia.cloud", "centralauth_p", creds)
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT gb_address, gb_expiry FROM globalblocks WHERE gb_expiry = 'infinity' OR gb_expiry > %s",
                [now_mw],
            )
            return _aggregate_active_rows(cursor.fetchall())
    finally:
        conn.close()


def _aggregate_active_rows(rows: Iterable[Tuple[Any, Any]]) -> Dict[str, Dict[str, Any]]:
    active_map: Dict[str, Dict[str, Any]] = {}
    for raw_target, raw_expiry in rows:
        normalised = normalize_block_target(_decode_str(raw_target))
        if normalised is None:
            continue
        target_cidr, ip_version, cidr_prefix, start_bin, end_bin = normalised
        expiry_dt, is_indef = parse_mw_expiry(raw_expiry)
        entry = active_map.get(target_cidr)
        if entry is None:
            active_map[target_cidr] = {
                "ip_version": ip_version,
                "cidr_prefix": cidr_prefix,
                "range_start_bin": start_bin,
                "range_end_bin": end_bin,
                "active_expiry": None if is_indef else expiry_dt,
                "active_indefinite": is_indef,
            }
            continue
        if is_indef:
            entry["active_indefinite"] = True
            entry["active_expiry"] = None
        elif (
            expiry_dt is not None
            and not entry["active_indefinite"]
            and (entry["active_expiry"] is None or expiry_dt > entry["active_expiry"])
        ):
            entry["active_expiry"] = expiry_dt
    return active_map


def _collect_incremental_logs(
    cursor: Any,
    wiki_db: str,
    *,
    log_type: str,
    log_actions: Tuple[str, ...],
    last_log_id: int,
    batch_size: int,
) -> Tuple[Dict[str, Dict[str, Any]], int, str]:
    action_placeholders = ", ".join(["%s"] * len(log_actions))
    cursor.execute(
        f"SELECT COALESCE(MAX(log_id), 0) FROM `{wiki_db}`.`logging_logindex` "  # noqa: S608
        f"WHERE log_type = %s AND log_action IN ({action_placeholders}) AND log_namespace = 2",
        [log_type, *log_actions],
    )
    max_row = cursor.fetchone()
    target_max_id = int(max_row[0] or 0) if max_row else 0
    if target_max_id <= last_log_id:
        return {}, last_log_id, ""

    deltas: Dict[str, Dict[str, Any]] = {}
    cursor_id = last_log_id
    latest_ts = ""

    while cursor_id < target_max_id:
        upper_id = min(target_max_id, cursor_id + batch_size)
        sql = (
            f"SELECT log_title, COUNT(*), MAX(log_timestamp) FROM `{wiki_db}`.`logging_logindex` "  # noqa: S608
            "WHERE log_id > %s AND log_id <= %s AND log_type = %s "
            f"AND log_action IN ({action_placeholders}) AND log_namespace = 2 "
            "GROUP BY log_title"
        )
        cursor.execute(sql, [cursor_id, upper_id, log_type, *log_actions])
        for raw_title, raw_count, raw_ts in cursor.fetchall():
            normalised = normalize_block_target(_decode_str(raw_title))
            if normalised is None:
                continue
            target_cidr, ip_version, cidr_prefix, start_bin, end_bin = normalised
            ts_str = _decode_str(raw_ts).strip()
            if ts_str and ts_str > latest_ts:
                latest_ts = ts_str
            last_dt = parse_mw_timestamp(ts_str)
            entry = deltas.get(target_cidr)
            if entry is None:
                deltas[target_cidr] = {
                    "ip_version": ip_version,
                    "cidr_prefix": cidr_prefix,
                    "range_start_bin": start_bin,
                    "range_end_bin": end_bin,
                    "delta": max(0, int(raw_count or 0)),
                    "last_blocked_at": last_dt,
                }
            else:
                entry["delta"] += max(0, int(raw_count or 0))
                if last_dt is not None and (entry["last_blocked_at"] is None or last_dt > entry["last_blocked_at"]):
                    entry["last_blocked_at"] = last_dt
        cursor_id = upper_id

    return deltas, target_max_id, latest_ts


def _apply_wiki_sync_to_toolsdb(
    storage_wiki: str,
    wiki_domain: str,
    active_map: Dict[str, Dict[str, Any]],
    log_deltas: Dict[str, Dict[str, Any]],
    new_last_log_id: int,
    new_last_ts: str,
    *,
    now_dt: datetime,
) -> Tuple[int, int]:
    """Persists active rangeblock flags and incremental log counts into ToolsDB atomically."""
    close_old_connections()
    with transaction.atomic():
        existing_rows = {row.target_cidr: row for row in RangeblockAggregate.objects.filter(wiki_dbname=storage_wiki)}

        deactivated_ids = [
            row.id for target, row in existing_rows.items() if row.has_active and target not in active_map
        ]
        if deactivated_ids:
            RangeblockAggregate.objects.filter(id__in=deactivated_ids).update(
                has_active=False,
                active_expiry=None,
                active_indefinite=False,
                updated_at=now_dt,
            )

        all_targets = set(active_map.keys()) | set(log_deltas.keys())
        to_create: List[RangeblockAggregate] = []
        to_update: List[RangeblockAggregate] = []

        for target in all_targets:
            active_info = active_map.get(target)
            delta_info = log_deltas.get(target)
            has_active = active_info is not None
            delta_count = int(delta_info["delta"]) if delta_info else 0
            existing = existing_rows.get(target)

            if existing is None:
                meta = active_info or delta_info
                if meta is None:
                    continue
                to_create.append(
                    RangeblockAggregate(
                        wiki_dbname=storage_wiki,
                        target_cidr=target,
                        ip_version=meta["ip_version"],
                        cidr_prefix=meta["cidr_prefix"],
                        range_start_bin=meta["range_start_bin"],
                        range_end_bin=meta["range_end_bin"],
                        block_count=compute_effective_block_count(delta_count, has_active),
                        has_active=has_active,
                        active_expiry=active_info["active_expiry"] if active_info else None,
                        active_indefinite=active_info["active_indefinite"] if active_info else False,
                        last_blocked_at=delta_info["last_blocked_at"] if delta_info else None,
                    )
                )
                continue

            # When a previously unlogged active block (synthetic count 1) gains its first log, replace 1 with delta.
            if (
                existing.last_blocked_at is None
                and existing.has_active
                and existing.block_count == 1
                and delta_count > 0
            ):
                new_count = delta_count
            else:
                new_count = compute_effective_block_count(existing.block_count + delta_count, has_active)

            existing.block_count = new_count
            existing.has_active = has_active
            existing.active_expiry = active_info["active_expiry"] if active_info else None
            existing.active_indefinite = active_info["active_indefinite"] if active_info else False
            if (
                delta_info
                and delta_info["last_blocked_at"] is not None
                and (existing.last_blocked_at is None or delta_info["last_blocked_at"] > existing.last_blocked_at)
            ):
                existing.last_blocked_at = delta_info["last_blocked_at"]
            existing.updated_at = now_dt
            to_update.append(existing)

        if to_create:
            RangeblockAggregate.objects.bulk_create(to_create, batch_size=1000)
        if to_update:
            RangeblockAggregate.objects.bulk_update(
                to_update,
                [
                    "block_count",
                    "has_active",
                    "active_expiry",
                    "active_indefinite",
                    "last_blocked_at",
                    "updated_at",
                ],
                batch_size=1000,
            )

        state_obj, _ = RangeblockSyncState.objects.get_or_create(wiki_dbname=storage_wiki)
        if wiki_domain:
            state_obj.wiki_domain = wiki_domain
        if new_last_log_id > state_obj.last_log_id:
            state_obj.last_log_id = new_last_log_id
        if new_last_ts and new_last_ts > state_obj.last_log_timestamp:
            state_obj.last_log_timestamp = new_last_ts
        state_obj.synced_at = now_dt
        state_obj.save()

    return len(to_create), len(to_update)


class Command(BaseCommand):
    """Synchronises active rangeblocks and incremental block logs across Wikimedia projects."""

    help = "Synchronises cross-wiki active blocks and incremental block log counts from Wiki Replicas into ToolsDB."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--wikis", type=str, default="", help="Comma-separated wiki dbnames to sync.")
        parser.add_argument(
            "--sections", type=str, default="", help="Comma-separated Wiki Replicas sections (e.g. s1,s3)."
        )
        parser.add_argument("--batch-size", type=int, default=_DEFAULT_BATCH_SIZE, help="Log ID chunk size per query.")
        parser.add_argument("--dry-run", action="store_true", help="Inspect counts without modifying ToolsDB.")

    def _sync_wiki_target(
        self,
        cursor: Any,
        *,
        replica_db: str,
        creds: Tuple[str, str],
        storage_wiki: str,
        wiki_domain: str,
        log_type: str,
        log_actions: Tuple[str, ...],
        is_global: bool,
        now_mw: str,
        now_dt: datetime,
        batch_size: int,
        dry_run: bool,
    ) -> Tuple[int, int]:
        state = RangeblockSyncState.objects.filter(wiki_dbname=storage_wiki).first()
        last_log_id = int(state.last_log_id) if state is not None else 0
        active_map = (
            _collect_active_global_blocks(creds, now_mw)
            if is_global
            else _collect_active_local_blocks(cursor, replica_db, now_mw)
        )
        deltas, max_log_id, latest_ts = _collect_incremental_logs(
            cursor,
            replica_db,
            log_type=log_type,
            log_actions=log_actions,
            last_log_id=last_log_id,
            batch_size=batch_size,
        )
        if dry_run:
            return len(active_map), len(deltas)
        return _apply_wiki_sync_to_toolsdb(
            storage_wiki,
            wiki_domain,
            active_map,
            deltas,
            max_log_id,
            latest_ts,
            now_dt=now_dt,
        )

    def handle(self, *args: Any, **options: Any) -> None:
        creds = discover_wiki_replica_credentials()
        if creds is None:
            raise CommandError("Wiki Replicas credentials were not found in TOOL_REPLICA_* or replica.my.cnf.")

        batch_size = max(1000, int(options.get("batch_size") or _DEFAULT_BATCH_SIZE))
        dry_run = bool(options.get("dry_run"))
        filter_wikis = {w.strip().lower() for w in str(options.get("wikis") or "").split(",") if w.strip()} or None
        filter_sections = {
            _normalise_section(s) for s in str(options.get("sections") or "").split(",") if s.strip()
        } or None

        wikis = _fetch_active_wikis(creds, filter_wikis=filter_wikis, filter_sections=filter_sections)
        by_section: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
        for dbname, domain, section in wikis:
            by_section[section].append((dbname, domain))

        now_dt = datetime.now(timezone.utc)
        now_mw = now_dt.strftime("%Y%m%d%H%M%S")
        synced_count = 0
        failed_wikis: List[str] = []

        for section, entries in sorted(by_section.items()):
            host = f"{section}.analytics.db.svc.wikimedia.cloud"
            first_db = f"{entries[0][0]}_p"
            try:
                conn = _connect_replica(host, first_db, creds)
            except pymysql.MySQLError as exc:
                logger.warning(
                    "Skipping section %s due to connection error: %s", section, sanitize_error_message(str(exc))
                )
                failed_wikis.extend(db for db, _ in entries)
                continue

            try:
                with conn.cursor() as cursor:
                    for dbname, domain in entries:
                        replica_db = f"{dbname}_p"
                        try:
                            self._sync_wiki_target(
                                cursor,
                                replica_db=replica_db,
                                creds=creds,
                                storage_wiki=dbname,
                                wiki_domain=domain,
                                log_type="block",
                                log_actions=("block",),
                                is_global=False,
                                now_mw=now_mw,
                                now_dt=now_dt,
                                batch_size=batch_size,
                                dry_run=dry_run,
                            )
                            synced_count += 1
                            if dbname == "metawiki":
                                self._sync_wiki_target(
                                    cursor,
                                    replica_db=replica_db,
                                    creds=creds,
                                    storage_wiki="global",
                                    wiki_domain="meta.wikimedia.org",
                                    log_type="gblblock",
                                    log_actions=("gblock", "gblock2"),
                                    is_global=True,
                                    now_mw=now_mw,
                                    now_dt=now_dt,
                                    batch_size=batch_size,
                                    dry_run=dry_run,
                                )
                                synced_count += 1
                        except pymysql.MySQLError as exc:
                            failed_wikis.append(dbname)
                            logger.warning(
                                "Rangeblock sync failed for %s: %s",
                                dbname,
                                sanitize_error_message(str(exc)),
                            )
            finally:
                conn.close()

        summary = (
            f"Synchronised {synced_count} rangeblock wiki targets (dry_run={dry_run}, failed={len(failed_wikis)})."
        )
        if synced_count == 0 and failed_wikis:
            raise CommandError(f"Rangeblock sync failed for all targets: {summary}")
        self.stdout.write(self.style.SUCCESS(summary))
