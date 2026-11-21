"""Hourly management command to synchronise cross-wiki rangeblock aggregates from Wiki Replicas."""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, TypeVar

import pymysql
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError, OperationalError, close_old_connections, connection, transaction

from detector.models import RangeblockAggregate, RangeblockSyncState
from detector.rangeblock_service import (
    normalize_block_target,
    parse_mw_expiry,
    parse_mw_timestamp,
)
from detector.sanitization import sanitize_error_message
from proxycheck.settings import discover_wiki_replica_credentials

logger = logging.getLogger("detector.views")

_DEFAULT_BATCH_SIZE = 50000
_UPSERT_SQL_BATCH_SIZE = 200
_DEACTIVATE_BATCH_SIZE = 500
_PROGRESS_WIKIS = frozenset({"enwiki", "metawiki", "global", "commonswiki", "wikidatawiki", "zhwiki"})
_TRANSIENT_TOOLSDB_ERROR_CODES = frozenset({2006, 2013, 1205, 1213})
_TOOLSDB_MAX_RETRIES = 3
_TOOLSDB_RETRY_BASE_DELAY_SECONDS = 1.0

_T = TypeVar("_T")


def _extract_mysql_error_code(exc: BaseException) -> Optional[int]:
    if exc.args:
        first = exc.args[0]
        if isinstance(first, int) and not isinstance(first, bool):
            return first
    cause = getattr(exc, "__cause__", None)
    cause_args = getattr(cause, "args", None) if cause is not None else None
    if cause_args:
        first = cause_args[0]
        if isinstance(first, int) and not isinstance(first, bool):
            return first
    return None


def _run_toolsdb_with_retry(
    operation: Callable[[], _T],
    *,
    context: str,
    max_retries: int = _TOOLSDB_MAX_RETRIES,
    base_delay: float = _TOOLSDB_RETRY_BASE_DELAY_SECONDS,
) -> _T:
    """Runs an idempotent ToolsDB operation, reconnecting and backing off on transient MySQL errors."""
    for attempt in range(max_retries + 1):
        try:
            close_old_connections()
            return operation()
        except OperationalError as exc:
            error_code = _extract_mysql_error_code(exc)
            connection.close()
            if error_code not in _TRANSIENT_TOOLSDB_ERROR_CODES or attempt >= max_retries:
                raise
            delay = base_delay * (2**attempt)
            logger.warning(
                "Transient ToolsDB error (code=%s) during %s; retrying (%d/%d) in %.1fs: %s",
                error_code,
                context,
                attempt + 1,
                max_retries,
                delay,
                sanitize_error_message(str(exc)),
            )
            time.sleep(delay)
    raise AssertionError("Unreachable retry loop exit")


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


def _prep_db_datetime(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    utc_naive = dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo is not None else dt
    return connection.ops.adapt_datetimefield_value(utc_naive)


def _normalise_utc_datetime(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _iter_batches(items: List[Any], size: int) -> Iterable[List[Any]]:
    for idx in range(0, len(items), size):
        yield items[idx : idx + size]


def _advance_sync_state(
    storage_wiki: str,
    *,
    wiki_domain: str,
    now_dt: datetime,
    last_log_id: Optional[int] = None,
    last_log_timestamp: str = "",
) -> None:
    state_obj, _ = RangeblockSyncState.objects.get_or_create(wiki_dbname=storage_wiki)
    if wiki_domain:
        state_obj.wiki_domain = wiki_domain
    if last_log_id is not None and last_log_id > state_obj.last_log_id:
        state_obj.last_log_id = last_log_id
    if last_log_timestamp and last_log_timestamp > state_obj.last_log_timestamp:
        state_obj.last_log_timestamp = last_log_timestamp
    state_obj.synced_at = now_dt
    state_obj.save()


def _upsert_log_chunk(
    storage_wiki: str,
    chunk_deltas: Dict[str, Dict[str, Any]],
    *,
    now_dt: datetime,
) -> int:
    if not chunk_deltas:
        return 0

    now_db = _prep_db_datetime(now_dt)
    rows: List[Tuple[Any, ...]] = [
        (
            storage_wiki,
            target_cidr,
            info["ip_version"],
            info["cidr_prefix"],
            info["range_start_bin"],
            info["range_end_bin"],
            info["delta"],
            0,
            None,
            0,
            _prep_db_datetime(info["last_blocked_at"]),
            now_db,
        )
        for target_cidr, info in chunk_deltas.items()
    ]

    is_sqlite = connection.vendor == "sqlite"
    row_placeholder = "(" + ", ".join(["%s"] * 12) + ")"
    with connection.cursor() as db_cursor:
        for batch in _iter_batches(rows, _UPSERT_SQL_BATCH_SIZE):
            values_sql = ", ".join([row_placeholder] * len(batch))
            params = [val for row in batch for val in row]
            if is_sqlite:
                sql = (
                    "INSERT INTO detector_rangeblock_agg ("  # noqa: S608
                    "wiki_dbname, target_cidr, ip_version, cidr_prefix, "
                    "range_start_bin, range_end_bin, block_count, "
                    "has_active, active_expiry, active_indefinite, "
                    "last_blocked_at, updated_at"
                    f") VALUES {values_sql} "
                    "ON CONFLICT(wiki_dbname, target_cidr) DO UPDATE SET "
                    "block_count = detector_rangeblock_agg.block_count + excluded.block_count, "
                    "last_blocked_at = CASE "
                    "WHEN detector_rangeblock_agg.last_blocked_at IS NULL THEN excluded.last_blocked_at "
                    "WHEN excluded.last_blocked_at IS NULL THEN detector_rangeblock_agg.last_blocked_at "
                    "WHEN excluded.last_blocked_at > detector_rangeblock_agg.last_blocked_at "
                    "THEN excluded.last_blocked_at "
                    "ELSE detector_rangeblock_agg.last_blocked_at END, "
                    "updated_at = excluded.updated_at"
                )
            else:
                sql = (
                    "INSERT INTO detector_rangeblock_agg ("  # noqa: S608
                    "wiki_dbname, target_cidr, ip_version, cidr_prefix, "
                    "range_start_bin, range_end_bin, block_count, "
                    "has_active, active_expiry, active_indefinite, "
                    "last_blocked_at, updated_at"
                    f") VALUES {values_sql} "
                    "ON DUPLICATE KEY UPDATE "
                    "block_count = block_count + VALUES(block_count), "
                    "last_blocked_at = CASE "
                    "WHEN last_blocked_at IS NULL THEN VALUES(last_blocked_at) "
                    "WHEN VALUES(last_blocked_at) IS NULL THEN last_blocked_at "
                    "WHEN VALUES(last_blocked_at) > last_blocked_at THEN VALUES(last_blocked_at) "
                    "ELSE last_blocked_at END, "
                    "updated_at = VALUES(updated_at)"
                )
            db_cursor.execute(sql, params)
    return len(rows)


def _upsert_active_blocks(
    storage_wiki: str,
    active_entries: Dict[str, Dict[str, Any]],
    *,
    now_dt: datetime,
) -> int:
    if not active_entries:
        return 0

    now_db = _prep_db_datetime(now_dt)
    rows: List[Tuple[Any, ...]] = [
        (
            storage_wiki,
            target_cidr,
            info["ip_version"],
            info["cidr_prefix"],
            info["range_start_bin"],
            info["range_end_bin"],
            1,
            1,
            _prep_db_datetime(info["active_expiry"]),
            1 if info["active_indefinite"] else 0,
            None,
            now_db,
        )
        for target_cidr, info in active_entries.items()
    ]

    is_sqlite = connection.vendor == "sqlite"
    row_placeholder = "(" + ", ".join(["%s"] * 12) + ")"
    with connection.cursor() as db_cursor:
        for batch in _iter_batches(rows, _UPSERT_SQL_BATCH_SIZE):
            values_sql = ", ".join([row_placeholder] * len(batch))
            params = [val for row in batch for val in row]
            if is_sqlite:
                sql = (
                    "INSERT INTO detector_rangeblock_agg ("  # noqa: S608
                    "wiki_dbname, target_cidr, ip_version, cidr_prefix, "
                    "range_start_bin, range_end_bin, block_count, "
                    "has_active, active_expiry, active_indefinite, "
                    "last_blocked_at, updated_at"
                    f") VALUES {values_sql} "
                    "ON CONFLICT(wiki_dbname, target_cidr) DO UPDATE SET "
                    "block_count = MAX(detector_rangeblock_agg.block_count, 1), "
                    "has_active = excluded.has_active, "
                    "active_expiry = excluded.active_expiry, "
                    "active_indefinite = excluded.active_indefinite, "
                    "updated_at = excluded.updated_at"
                )
            else:
                sql = (
                    "INSERT INTO detector_rangeblock_agg ("  # noqa: S608
                    "wiki_dbname, target_cidr, ip_version, cidr_prefix, "
                    "range_start_bin, range_end_bin, block_count, "
                    "has_active, active_expiry, active_indefinite, "
                    "last_blocked_at, updated_at"
                    f") VALUES {values_sql} "
                    "ON DUPLICATE KEY UPDATE "
                    "block_count = GREATEST(block_count, 1), "
                    "has_active = VALUES(has_active), "
                    "active_expiry = VALUES(active_expiry), "
                    "active_indefinite = VALUES(active_indefinite), "
                    "updated_at = VALUES(updated_at)"
                )
            db_cursor.execute(sql, params)
    return len(rows)


def _stream_incremental_logs(
    cursor: Any,
    wiki_db: str,
    *,
    storage_wiki: str,
    wiki_domain: str,
    log_type: str,
    log_actions: Tuple[str, ...],
    last_log_id: int,
    batch_size: int,
    now_dt: datetime,
    dry_run: bool,
) -> int:
    """Streams incremental block log chunks from Wiki Replicas and commits each chunk with its watermark."""
    action_placeholders = ", ".join(["%s"] * len(log_actions))
    cursor.execute(
        f"SELECT COALESCE(MAX(log_id), 0) FROM `{wiki_db}`.`logging_logindex` "  # noqa: S608
        f"WHERE log_type = %s AND log_action IN ({action_placeholders}) AND log_namespace = 2",
        [log_type, *log_actions],
    )
    max_row = cursor.fetchone()
    target_max_id = int(max_row[0] or 0) if max_row else 0
    if target_max_id <= last_log_id:
        return 0

    total_targets = 0
    cursor_id = last_log_id

    while cursor_id < target_max_id:
        upper_id = min(target_max_id, cursor_id + batch_size)
        sql = (
            f"SELECT log_title, COUNT(*), MAX(log_timestamp) FROM `{wiki_db}`.`logging_logindex` "  # noqa: S608
            "WHERE log_id > %s AND log_id <= %s AND log_type = %s "
            f"AND log_action IN ({action_placeholders}) AND log_namespace = 2 "
            "GROUP BY log_title"
        )
        cursor.execute(sql, [cursor_id, upper_id, log_type, *log_actions])
        chunk_deltas: Dict[str, Dict[str, Any]] = {}
        chunk_latest_ts = ""
        for raw_title, raw_count, raw_ts in cursor.fetchall():
            normalised = normalize_block_target(_decode_str(raw_title))
            if normalised is None:
                continue
            target_cidr, ip_version, cidr_prefix, start_bin, end_bin = normalised
            ts_str = _decode_str(raw_ts).strip()
            if ts_str and ts_str > chunk_latest_ts:
                chunk_latest_ts = ts_str
            last_dt = parse_mw_timestamp(ts_str)
            delta_val = max(0, int(raw_count or 0))
            entry = chunk_deltas.get(target_cidr)
            if entry is None:
                chunk_deltas[target_cidr] = {
                    "ip_version": ip_version,
                    "cidr_prefix": cidr_prefix,
                    "range_start_bin": start_bin,
                    "range_end_bin": end_bin,
                    "delta": delta_val,
                    "last_blocked_at": last_dt,
                }
            else:
                entry["delta"] += delta_val
                if last_dt is not None and (entry["last_blocked_at"] is None or last_dt > entry["last_blocked_at"]):
                    entry["last_blocked_at"] = last_dt

        total_targets += len(chunk_deltas)
        if not dry_run:

            def _commit_log_chunk(
                deltas: Dict[str, Dict[str, Any]] = chunk_deltas,
                log_id: int = upper_id,
                latest_ts: str = chunk_latest_ts,
            ) -> None:
                with transaction.atomic():
                    if deltas:
                        _upsert_log_chunk(storage_wiki, deltas, now_dt=now_dt)
                    _advance_sync_state(
                        storage_wiki,
                        wiki_domain=wiki_domain,
                        now_dt=now_dt,
                        last_log_id=log_id,
                        last_log_timestamp=latest_ts,
                    )

            _run_toolsdb_with_retry(
                _commit_log_chunk,
                context=f"log chunk upsert for {storage_wiki} (up to log_id={upper_id})",
            )
        cursor_id = upper_id

    return total_targets


def _sync_active_blocks_to_toolsdb(
    storage_wiki: str,
    wiki_domain: str,
    active_map: Dict[str, Dict[str, Any]],
    *,
    now_dt: datetime,
) -> Tuple[int, int]:
    """Reconciles only the active block subset in ToolsDB without loading historical rows."""

    def _reconcile_active_blocks() -> Tuple[int, int]:
        with transaction.atomic():
            local_active_rows = list(
                RangeblockAggregate.objects.filter(wiki_dbname=storage_wiki, has_active=True).values_list(
                    "id", "target_cidr", "active_expiry", "active_indefinite"
                )
            )
            local_active_meta: Dict[str, Tuple[Optional[datetime], bool]] = {}
            deactivated_ids: List[int] = []
            for row_id, target_cidr, local_expiry, local_indef in local_active_rows:
                if target_cidr not in active_map:
                    deactivated_ids.append(row_id)
                else:
                    local_active_meta[target_cidr] = (_normalise_utc_datetime(local_expiry), bool(local_indef))

            active_to_upsert: Dict[str, Dict[str, Any]] = {}
            for target_cidr, info in active_map.items():
                existing_meta = local_active_meta.get(target_cidr)
                desired_meta = (info["active_expiry"], bool(info["active_indefinite"]))
                if existing_meta is None or existing_meta != desired_meta:
                    active_to_upsert[target_cidr] = info

            for id_batch in _iter_batches(deactivated_ids, _DEACTIVATE_BATCH_SIZE):
                RangeblockAggregate.objects.filter(id__in=id_batch).update(
                    has_active=False,
                    active_expiry=None,
                    active_indefinite=False,
                    updated_at=now_dt,
                )

            upserted_count = 0
            if active_to_upsert:
                upserted_count = _upsert_active_blocks(storage_wiki, active_to_upsert, now_dt=now_dt)

            _advance_sync_state(storage_wiki, wiki_domain=wiki_domain, now_dt=now_dt)

        return upserted_count, len(deactivated_ids)

    return _run_toolsdb_with_retry(
        _reconcile_active_blocks,
        context=f"active block reconciliation for {storage_wiki}",
    )


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

    def _write_progress(self, message: str) -> None:
        self.stdout.write(message, ending="\n")
        flush = getattr(self.stdout, "flush", None)
        if callable(flush):
            flush()

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
        state = _run_toolsdb_with_retry(
            lambda: RangeblockSyncState.objects.filter(wiki_dbname=storage_wiki).first(),
            context=f"sync state lookup for {storage_wiki}",
        )
        last_log_id = int(state.last_log_id) if state is not None else 0
        log_targets = _stream_incremental_logs(
            cursor,
            replica_db,
            storage_wiki=storage_wiki,
            wiki_domain=wiki_domain,
            log_type=log_type,
            log_actions=log_actions,
            last_log_id=last_log_id,
            batch_size=batch_size,
            now_dt=now_dt,
            dry_run=dry_run,
        )
        active_map = (
            _collect_active_global_blocks(creds, now_mw)
            if is_global
            else _collect_active_local_blocks(cursor, replica_db, now_mw)
        )
        if dry_run:
            return len(active_map), log_targets
        active_upserted, active_deactivated = _sync_active_blocks_to_toolsdb(
            storage_wiki,
            wiki_domain,
            active_map,
            now_dt=now_dt,
        )
        return active_upserted + active_deactivated, log_targets

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
            section_synced = 0
            section_failed = 0
            try:
                conn = _connect_replica(host, first_db, creds)
            except pymysql.MySQLError as exc:
                logger.warning(
                    "Skipping section %s due to connection error: %s", section, sanitize_error_message(str(exc))
                )
                failed_wikis.extend(db for db, _ in entries)
                self._write_progress(
                    f"[section {section}] skipped due to connection error ({len(entries)} wikis failed)."
                )
                continue

            try:
                with conn.cursor() as cursor:
                    for dbname, domain in entries:
                        replica_db = f"{dbname}_p"
                        try:
                            active_changes, log_targets = self._sync_wiki_target(
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
                            section_synced += 1
                            if dbname in _PROGRESS_WIKIS:
                                self._write_progress(
                                    f"[{dbname}] completed (log_targets={log_targets}, active_updates={active_changes})."
                                )
                            if dbname == "metawiki":
                                global_active, global_logs = self._sync_wiki_target(
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
                                section_synced += 1
                                self._write_progress(
                                    f"[global] completed (log_targets={global_logs}, active_updates={global_active})."
                                )
                        except (pymysql.MySQLError, DatabaseError) as exc:
                            connection.close()
                            failed_wikis.append(dbname)
                            section_failed += 1
                            logger.warning(
                                "Rangeblock sync failed for %s: %s",
                                dbname,
                                sanitize_error_message(str(exc)),
                            )
            finally:
                conn.close()

            self._write_progress(f"[section {section}] completed (synced={section_synced}, failed={section_failed}).")

        summary = (
            f"Synchronised {synced_count} rangeblock wiki targets (dry_run={dry_run}, failed={len(failed_wikis)})."
        )
        if synced_count == 0 and failed_wikis:
            raise CommandError(f"Rangeblock sync failed for all targets: {summary}")
        self._write_progress(self.style.SUCCESS(summary))
