"""Hourly management command to synchronise cross-wiki rangeblock aggregates from Wiki Replicas."""

from __future__ import annotations

import contextlib
import logging
import re
import sys
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, TypeVar

import pymysql
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError, OperationalError, close_old_connections, connection, transaction

from detector.cache_backends import get_redis_namespace
from detector.models import RangeblockAggregate, RangeblockSyncState
from detector.provider_registry import REDIS_TRANSPORT_ERRORS
from detector.rangeblock_service import (
    expand_db_lookup_targets,
    get_configured_realtime_wikis,
    normalize_block_target,
    parse_mw_expiry,
    parse_mw_timestamp,
)
from detector.sanitization import sanitize_error_message
from proxycheck.settings import discover_wiki_replica_credentials

try:
    import redis as sync_redis
except ImportError:
    sync_redis = None

logger = logging.getLogger("detector.views")

_DEFAULT_BATCH_SIZE = 200000
_MIN_BATCH_SIZE = 10000
_MAX_BATCH_SIZE = 1000000
_FAST_CHUNK_THRESHOLD_SECONDS = 8.0
_SLOW_CHUNK_THRESHOLD_SECONDS = 20.0
_DEFAULT_MAX_SECONDS_PER_WIKI = 600
_STREAM_FETCH_SIZE = 2000
_UPSERT_SQL_BATCH_SIZE = 200
_TARGETED_ACTIVE_BATCH_SIZE = 200
_REPLICA_CONNECT_TIMEOUT_SECONDS = 5
_REPLICA_READ_TIMEOUT_SECONDS = 120
_REPLICA_WRITE_TIMEOUT_SECONDS = 10
_MYSQL_MAX_STATEMENT_TIME_ERR = 1969
_TRANSIENT_TOOLSDB_ERROR_CODES = frozenset({2006, 2013, 1205, 1213})
_TOOLSDB_MAX_RETRIES = 3
_TOOLSDB_RETRY_BASE_DELAY_SECONDS = 1.0
_SYNC_LOCK_TTL_SECONDS = 3600
_SYNC_LOCK_KEY_SUFFIX = "sync_world_block:lock"
_REDIS_LOCK_SOCKET_TIMEOUT_SECONDS = 2.0
_SLOWEST_WIKIS_LIMIT = 10
_REPLICA_DB_RE = re.compile(r"^[a-z0-9_]+$")

_LOCAL_LOG_ACTIONS: Tuple[str, ...] = ("block", "reblock", "unblock")
_LOCAL_COUNT_ACTIONS: frozenset[str] = frozenset({"block"})
_GLOBAL_LOG_ACTIONS: Tuple[str, ...] = ("gblock", "gblock2", "gunblock", "modify")
_GLOBAL_COUNT_ACTIONS: frozenset[str] = frozenset({"gblock", "gblock2"})

_SET_REPLICA_STATEMENT_TIMEOUT_SQL = "SET SESSION max_statement_time = 100"
_RESET_REPLICA_STATEMENT_TIMEOUT_SQL = "SET SESSION max_statement_time = DEFAULT"

_RELEASE_LOCK_LUA = """
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
else
    return 0
end
"""

_LOCAL_ACTIVE_BLOCKS_SQL = (
    "SELECT bt.bt_address, b.bl_expiry "
    "FROM block b "
    "JOIN block_target bt ON b.bl_target = bt.bt_id "
    "WHERE bt.bt_user IS NULL AND bt.bt_auto = 0 AND bt.bt_address IS NOT NULL "
    "AND (b.bl_expiry = 'infinity' OR b.bl_expiry > %s)"
)

_GLOBAL_ACTIVE_BLOCKS_SQL = (
    "SELECT gb_address, gb_expiry "
    "FROM globalblocks "
    "WHERE gb_address IS NOT NULL AND (gb_expiry = 'infinity' OR gb_expiry > %s)"
)

_TARGETED_LOCAL_ACTIVE_SQL = (
    "SELECT bt.bt_address, b.bl_expiry "
    "FROM block b "
    "JOIN block_target bt ON b.bl_target = bt.bt_id "
    "WHERE bt.bt_user IS NULL AND bt.bt_auto = 0 "
    "AND bt.bt_address IN %s "
    "AND (b.bl_expiry = 'infinity' OR b.bl_expiry > %s)"
)

_TARGETED_GLOBAL_ACTIVE_SQL = (
    "SELECT gb_address, gb_expiry "
    "FROM globalblocks "
    "WHERE gb_address IN %s "
    "AND (gb_expiry = 'infinity' OR gb_expiry > %s)"
)

_MAX_LOG_ID_LOCAL_SQL = (
    "SELECT COALESCE(MAX(log_id), 0) FROM logging_logindex "
    "WHERE log_id > %s AND log_type = %s "
    "AND log_action IN (%s, %s, %s) AND log_namespace = 2"
)

_MAX_LOG_ID_GLOBAL_SQL = (
    "SELECT COALESCE(MAX(log_id), 0) FROM logging_logindex "
    "WHERE log_id > %s AND log_type = %s "
    "AND log_action IN (%s, %s, %s, %s) AND log_namespace = 2"
)

_INCREMENTAL_LOGS_LOCAL_SQL = (
    "SELECT log_title, log_action, COUNT(*), MAX(log_timestamp) FROM logging_logindex "
    "WHERE log_id > %s AND log_id <= %s AND log_type = %s "
    "AND log_action IN (%s, %s, %s) AND log_namespace = 2 "
    "GROUP BY log_title, log_action"
)

_INCREMENTAL_LOGS_GLOBAL_SQL = (
    "SELECT log_title, log_action, COUNT(*), MAX(log_timestamp) FROM logging_logindex "
    "WHERE log_id > %s AND log_id <= %s AND log_type = %s "
    "AND log_action IN (%s, %s, %s, %s) AND log_namespace = 2 "
    "GROUP BY log_title, log_action"
)

_UPSERT_LOG_SQLITE_SQL = (
    "INSERT INTO detector_rangeblock_agg ("
    "wiki_dbname, target_cidr, ip_version, cidr_prefix, "
    "range_start_bin, range_end_bin, block_count, "
    "has_active, active_expiry, active_indefinite, "
    "last_blocked_at, updated_at"
    ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
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

_UPSERT_LOG_MYSQL_SQL = (
    "INSERT INTO detector_rangeblock_agg ("
    "wiki_dbname, target_cidr, ip_version, cidr_prefix, "
    "range_start_bin, range_end_bin, block_count, "
    "has_active, active_expiry, active_indefinite, "
    "last_blocked_at, updated_at"
    ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
    "ON DUPLICATE KEY UPDATE "
    "block_count = block_count + VALUES(block_count), "
    "last_blocked_at = CASE "
    "WHEN last_blocked_at IS NULL THEN VALUES(last_blocked_at) "
    "WHEN VALUES(last_blocked_at) IS NULL THEN last_blocked_at "
    "WHEN VALUES(last_blocked_at) > last_blocked_at THEN VALUES(last_blocked_at) "
    "ELSE last_blocked_at END, "
    "updated_at = VALUES(updated_at)"
)

_UPSERT_ACTIVE_SQLITE_SQL = (
    "INSERT INTO detector_rangeblock_agg ("
    "wiki_dbname, target_cidr, ip_version, cidr_prefix, "
    "range_start_bin, range_end_bin, block_count, "
    "has_active, active_expiry, active_indefinite, "
    "last_blocked_at, updated_at"
    ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
    "ON CONFLICT(wiki_dbname, target_cidr) DO UPDATE SET "
    "block_count = MAX(detector_rangeblock_agg.block_count, 1), "
    "has_active = excluded.has_active, "
    "active_expiry = CASE "
    "WHEN detector_rangeblock_agg.updated_at = excluded.updated_at THEN "
    "CASE "
    "WHEN detector_rangeblock_agg.active_indefinite = 1 OR excluded.active_indefinite = 1 THEN NULL "
    "WHEN detector_rangeblock_agg.active_expiry IS NULL THEN excluded.active_expiry "
    "WHEN excluded.active_expiry IS NULL THEN detector_rangeblock_agg.active_expiry "
    "WHEN excluded.active_expiry > detector_rangeblock_agg.active_expiry THEN excluded.active_expiry "
    "ELSE detector_rangeblock_agg.active_expiry END "
    "ELSE excluded.active_expiry END, "
    "active_indefinite = CASE "
    "WHEN detector_rangeblock_agg.updated_at = excluded.updated_at THEN "
    "CASE WHEN detector_rangeblock_agg.active_indefinite = 1 OR excluded.active_indefinite = 1 THEN 1 ELSE 0 END "
    "ELSE excluded.active_indefinite END, "
    "updated_at = excluded.updated_at"
)

_UPSERT_ACTIVE_MYSQL_SQL = (
    "INSERT INTO detector_rangeblock_agg ("
    "wiki_dbname, target_cidr, ip_version, cidr_prefix, "
    "range_start_bin, range_end_bin, block_count, "
    "has_active, active_expiry, active_indefinite, "
    "last_blocked_at, updated_at"
    ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
    "ON DUPLICATE KEY UPDATE "
    "block_count = GREATEST(block_count, 1), "
    "has_active = VALUES(has_active), "
    "active_expiry = CASE "
    "WHEN updated_at = VALUES(updated_at) THEN "
    "CASE "
    "WHEN active_indefinite = 1 OR VALUES(active_indefinite) = 1 THEN NULL "
    "WHEN active_expiry IS NULL THEN VALUES(active_expiry) "
    "WHEN VALUES(active_expiry) IS NULL THEN active_expiry "
    "WHEN VALUES(active_expiry) > active_expiry THEN VALUES(active_expiry) "
    "ELSE active_expiry END "
    "ELSE VALUES(active_expiry) END, "
    "active_indefinite = CASE "
    "WHEN updated_at = VALUES(updated_at) THEN "
    "CASE WHEN active_indefinite = 1 OR VALUES(active_indefinite) = 1 THEN 1 ELSE 0 END "
    "ELSE VALUES(active_indefinite) END, "
    "updated_at = VALUES(updated_at)"
)

_UPSERT_TARGETED_ACTIVE_SQLITE_SQL = (
    "INSERT INTO detector_rangeblock_agg ("
    "wiki_dbname, target_cidr, ip_version, cidr_prefix, "
    "range_start_bin, range_end_bin, block_count, "
    "has_active, active_expiry, active_indefinite, "
    "last_blocked_at, updated_at"
    ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
    "ON CONFLICT(wiki_dbname, target_cidr) DO UPDATE SET "
    "block_count = MAX(detector_rangeblock_agg.block_count, 1), "
    "has_active = excluded.has_active, "
    "active_expiry = excluded.active_expiry, "
    "active_indefinite = excluded.active_indefinite, "
    "updated_at = excluded.updated_at"
)

_UPSERT_TARGETED_ACTIVE_MYSQL_SQL = (
    "INSERT INTO detector_rangeblock_agg ("
    "wiki_dbname, target_cidr, ip_version, cidr_prefix, "
    "range_start_bin, range_end_bin, block_count, "
    "has_active, active_expiry, active_indefinite, "
    "last_blocked_at, updated_at"
    ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
    "ON DUPLICATE KEY UPDATE "
    "block_count = GREATEST(block_count, 1), "
    "has_active = VALUES(has_active), "
    "active_expiry = VALUES(active_expiry), "
    "active_indefinite = VALUES(active_indefinite), "
    "updated_at = VALUES(updated_at)"
)

_DEACTIVATE_STALE_ACTIVE_MYSQL_SQL = (
    "UPDATE detector_rangeblock_agg "
    "SET has_active = 0, active_expiry = NULL, active_indefinite = 0, updated_at = %s "
    "WHERE wiki_dbname = %s AND has_active = 1 AND updated_at < %s "
    "LIMIT 5000"
)

_DEACTIVATE_STALE_ACTIVE_SQLITE_SQL = (
    "UPDATE detector_rangeblock_agg "
    "SET has_active = 0, active_expiry = NULL, active_indefinite = 0, updated_at = %s "
    "WHERE id IN ("
    "SELECT id FROM detector_rangeblock_agg "
    "WHERE wiki_dbname = %s AND has_active = 1 AND updated_at < %s "
    "LIMIT 5000"
    ")"
)

_FETCH_EXPIRED_ACTIVE_WIKIS_SQL = (
    "SELECT DISTINCT wiki_dbname "
    "FROM detector_rangeblock_agg "
    "WHERE has_active = 1 AND active_indefinite = 0 "
    "AND active_expiry IS NOT NULL AND active_expiry <= %s"
)

_FETCH_EXPIRED_ACTIVE_WIKIS_BY_WIKI_SQL_PREFIX = (
    "SELECT DISTINCT wiki_dbname "
    "FROM detector_rangeblock_agg "
    "WHERE wiki_dbname IN ({placeholders}) "
    "AND has_active = 1 AND active_indefinite = 0 "
    "AND active_expiry IS NOT NULL AND active_expiry <= %s"
)
_EXPIRED_WIKIS_BATCH_SIZE = 50

_DEACTIVATE_EXPIRED_ACTIVE_MYSQL_SQL = (
    "UPDATE detector_rangeblock_agg "
    "SET has_active = 0, active_expiry = NULL, active_indefinite = 0, updated_at = %s "
    "WHERE wiki_dbname = %s AND has_active = 1 AND active_indefinite = 0 "
    "AND active_expiry IS NOT NULL AND active_expiry <= %s "
    "LIMIT 5000"
)

_DEACTIVATE_EXPIRED_ACTIVE_SQLITE_SQL = (
    "UPDATE detector_rangeblock_agg "
    "SET has_active = 0, active_expiry = NULL, active_indefinite = 0, updated_at = %s "
    "WHERE id IN ("
    "SELECT id FROM detector_rangeblock_agg "
    "WHERE wiki_dbname = %s AND has_active = 1 AND active_indefinite = 0 "
    "AND active_expiry IS NOT NULL AND active_expiry <= %s "
    "LIMIT 5000"
    ")"
)

_PURGE_WIKI_AGG_MYSQL_SQL = "DELETE FROM detector_rangeblock_agg WHERE wiki_dbname = %s LIMIT 5000"

_PURGE_WIKI_AGG_SQLITE_SQL = (
    "DELETE FROM detector_rangeblock_agg "
    "WHERE id IN (SELECT id FROM detector_rangeblock_agg WHERE wiki_dbname = %s LIMIT 5000)"
)

_T = TypeVar("_T")


@dataclass
class _WikiTiming:
    """Tracks per-stage execution durations in seconds for one wiki target."""

    wiki: str
    max_id: float = 0.0
    logs: float = 0.0
    active_read: float = 0.0
    active_write: float = 0.0
    expire: float = 0.0

    @property
    def total(self) -> float:
        return self.max_id + self.logs + self.active_read + self.active_write + self.expire


@dataclass
class _WikiSyncStage:
    """Tracks the active processing stage and log watermark for structured error logging."""

    stage: str = "init"
    log_id: int = 0


@dataclass(frozen=True)
class _SyncTargetSpec:
    """Describes one local or global rangeblock synchronisation target."""

    replica_db: str
    storage_wiki: str
    wiki_domain: str
    log_type: str
    log_actions: Tuple[str, ...]
    count_actions: frozenset[str]
    is_global: bool


@dataclass(frozen=True)
class _SyncRunConfig:
    """Immutable run-wide configuration and startup caches shared across sections."""

    creds: Tuple[str, str]
    now_mw: str
    now_dt: datetime
    batch_size: int
    max_seconds_per_wiki: int
    full_active_reconcile: bool
    dry_run: bool
    sync_states: Dict[str, RangeblockSyncState]
    expired_wikis: Set[str]


@dataclass
class _LogStreamResult:
    """Summarises the outcome of an incremental log streaming pass."""

    log_targets: int
    active_changes: int
    chunks_committed: int
    budget_reached: bool


@dataclass
class _WikiSyncResult:
    """Summarises the outcome of synchronising one wiki target."""

    active_changes: int
    log_targets: int
    used_fast_path: bool
    budget_reached: bool
    timing: _WikiTiming


class _ReplicaSession:
    """Manages a section-scoped Wiki Replicas connection with safe reconnection."""

    def __init__(self, host: str, creds: Tuple[str, str], conn: Any = None) -> None:
        self.host = host
        self.creds = creds
        self.conn = conn

    def select_db(self, database: str) -> Any:
        if self.conn is None:
            self.conn = _connect_replica(self.host, database, self.creds)
        else:
            self.conn.select_db(database)
        return self.conn

    def reconnect(self, database: str) -> Any:
        self.close()
        self.conn = _connect_replica(self.host, database, self.creds)
        return self.conn

    def close(self) -> None:
        _safe_close_replica(self.conn)
        self.conn = None


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


def _is_test_environment() -> bool:
    if "test" in sys.argv or "pytest" in sys.modules:
        return True
    default_cache = getattr(settings, "CACHES", {}).get("default", {})
    return default_cache.get("BACKEND") == "django.core.cache.backends.locmem.LocMemCache"


def _safe_close_redis(client: Any) -> None:
    if client is None:
        return
    close_fn = getattr(client, "close", None)
    if callable(close_fn):
        with contextlib.suppress(*REDIS_TRANSPORT_ERRORS, RuntimeError):
            close_fn()


def _build_sync_redis_client(redis_url: str) -> Any:
    try:
        return sync_redis.from_url(
            redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_timeout=_REDIS_LOCK_SOCKET_TIMEOUT_SECONDS,
            socket_connect_timeout=_REDIS_LOCK_SOCKET_TIMEOUT_SECONDS,
            health_check_interval=30,
            socket_keepalive=True,
        )
    except TypeError as exc:
        if "unexpected keyword argument" not in str(exc):
            raise
        return sync_redis.from_url(
            redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_timeout=_REDIS_LOCK_SOCKET_TIMEOUT_SECONDS,
            socket_connect_timeout=_REDIS_LOCK_SOCKET_TIMEOUT_SECONDS,
        )


def _acquire_sync_lock() -> Tuple[Optional[Any], str, str, str, bool]:
    """Acquires the distributed Redis mutex lock for sync_world_block.

    Returns (client, redis_url, lock_key, token, should_proceed). When should_proceed is False,
    another process already holds the lock and this invocation should exit cleanly.
    """
    if sync_redis is None:
        logger.warning("Redis client library is unavailable; running sync_world_block without distributed lock.")
        return None, "", "", "", True

    redis_url = str(getattr(settings, "REDIS_URL", "") or "").strip()
    if not redis_url:
        logger.warning("REDIS_URL is not configured; running sync_world_block without distributed lock.")
        return None, "", "", "", True

    lock_key = f"{get_redis_namespace()}:{_SYNC_LOCK_KEY_SUFFIX}"
    token = uuid.uuid4().hex
    client: Any = None
    try:
        client = _build_sync_redis_client(redis_url)
        acquired = bool(client.set(lock_key, token, nx=True, ex=_SYNC_LOCK_TTL_SECONDS))
    except (*REDIS_TRANSPORT_ERRORS, ValueError, TypeError) as exc:
        _safe_close_redis(client)
        logger.warning(
            "Redis unavailable for sync_world_block lock (%s); continuing without distributed lock.",
            sanitize_error_message(str(exc)),
        )
        return None, "", "", "", True

    if not acquired:
        _safe_close_redis(client)
        return None, redis_url, lock_key, "", False
    return client, redis_url, lock_key, token, True


def _release_sync_lock(client: Any, lock_key: str, token: str, redis_url: str = "") -> None:
    """Atomically releases the distributed Redis mutex lock when the token matches."""
    if client is None or not lock_key or not token:
        return
    try:
        client.eval(_RELEASE_LOCK_LUA, 1, lock_key, token)
        return
    except REDIS_TRANSPORT_ERRORS as first_exc:
        _safe_close_redis(client)
        client = None
        if sync_redis is not None and redis_url:
            retry_client: Any = None
            try:
                retry_client = _build_sync_redis_client(redis_url)
                retry_client.eval(_RELEASE_LOCK_LUA, 1, lock_key, token)
                return
            except (*REDIS_TRANSPORT_ERRORS, ValueError, TypeError) as retry_exc:
                logger.warning(
                    "Failed to release Redis sync lock %s after reconnect: %s",
                    lock_key,
                    sanitize_error_message(str(retry_exc)),
                )
                return
            finally:
                _safe_close_redis(retry_client)
        logger.warning(
            "Failed to release Redis sync lock %s: %s",
            lock_key,
            sanitize_error_message(str(first_exc)),
        )
    finally:
        _safe_close_redis(client)


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
    conn = pymysql.connect(
        host=host,
        user=user,
        password=password,
        database=database,
        port=3306,
        connect_timeout=_REPLICA_CONNECT_TIMEOUT_SECONDS,
        read_timeout=_REPLICA_READ_TIMEOUT_SECONDS,
        write_timeout=_REPLICA_WRITE_TIMEOUT_SECONDS,
        charset="utf8mb4",
        autocommit=True,
    )
    try:
        with conn.cursor() as cursor:
            cursor.execute(_SET_REPLICA_STATEMENT_TIMEOUT_SQL)
    except pymysql.MySQLError, OSError:
        _safe_close_replica(conn)
        raise
    return conn


def _fetch_active_wikis(
    creds: Tuple[str, str],
    *,
    filter_wikis: Optional[Set[str]] = None,
    filter_sections: Optional[Set[str]] = None,
    exclude_wikis: Optional[Set[str]] = None,
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
                if exclude_wikis and dbname in exclude_wikis:
                    continue
                if filter_wikis and dbname not in filter_wikis:
                    continue
                if filter_sections and section not in filter_sections:
                    continue
                out.append((dbname, domain, section))
            return out
    finally:
        _safe_close_replica(conn)


def _safe_close_replica(conn: Any) -> None:
    if conn is None:
        return
    with contextlib.suppress(pymysql.MySQLError, OSError):
        conn.close()


def _safe_close_cursor(cursor: Any) -> None:
    if cursor is None:
        return
    with contextlib.suppress(pymysql.MySQLError, OSError):
        cursor.close()


def _merge_active_rows(active_map: Dict[str, Dict[str, Any]], rows: Iterable[Tuple[Any, Any]]) -> None:
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


def _next_sync_mark_dt(now_dt: datetime, state: Optional[RangeblockSyncState]) -> datetime:
    """Returns a strictly monotonic UTC timestamp for active-block reconciliation."""
    sync_mark_dt = datetime.now(timezone.utc)
    prior_candidates = [now_dt]
    if state is not None and state.synced_at is not None:
        normalised_synced = _normalise_utc_datetime(state.synced_at)
        if normalised_synced is not None:
            prior_candidates.append(normalised_synced)
    latest_prior = max(prior_candidates)
    if sync_mark_dt <= latest_prior:
        return latest_prior + timedelta(microseconds=1)
    return sync_mark_dt


def _set_replica_statement_timeout(conn: Any, sql: str) -> None:
    with conn.cursor() as cursor:
        cursor.execute(sql)


def _stream_active_from_conn(
    conn: Any,
    sql: str,
    params: Sequence[Any],
    *,
    storage_wiki: str,
    sync_mark_dt: datetime,
    dry_run: bool,
) -> Tuple[int, float, float]:
    """Streams active blocks in bounded batches and upserts each batch immediately to keep memory constant."""
    total_processed = 0
    read_seconds = 0.0
    write_seconds = 0.0
    # Full active table streams on large wikis exceed 100s when interleaved with ToolsDB writes.
    _set_replica_statement_timeout(conn, _RESET_REPLICA_STATEMENT_TIMEOUT_SQL)
    stream_cursor = conn.cursor(pymysql.cursors.SSCursor)
    try:
        read_start = time.monotonic()
        stream_cursor.execute(sql, params)
        read_seconds += time.monotonic() - read_start
        while True:
            fetch_start = time.monotonic()
            rows = stream_cursor.fetchmany(_STREAM_FETCH_SIZE)
            read_seconds += time.monotonic() - fetch_start
            if not rows:
                break
            batch_active: Dict[str, Dict[str, Any]] = {}
            _merge_active_rows(batch_active, rows)
            if batch_active:
                if dry_run:
                    total_processed += len(batch_active)
                else:

                    def _commit_active_batch(entries: Dict[str, Dict[str, Any]] = batch_active) -> int:
                        with transaction.atomic():
                            return _upsert_active_blocks(storage_wiki, entries, now_dt=sync_mark_dt)

                    write_start = time.monotonic()
                    total_processed += _run_toolsdb_with_retry(
                        _commit_active_batch,
                        context=f"active block batch upsert for {storage_wiki}",
                    )
                    write_seconds += time.monotonic() - write_start
                batch_active.clear()
    finally:
        _safe_close_cursor(stream_cursor)
        with contextlib.suppress(pymysql.MySQLError, OSError):
            _set_replica_statement_timeout(conn, _SET_REPLICA_STATEMENT_TIMEOUT_SQL)
    return total_processed, read_seconds, write_seconds


def _stream_active_local_blocks(
    session: _ReplicaSession,
    wiki_db: str,
    now_mw: str,
    *,
    storage_wiki: str,
    sync_mark_dt: datetime,
    dry_run: bool,
) -> Tuple[int, float, float]:
    conn = session.select_db(wiki_db)
    return _stream_active_from_conn(
        conn,
        _LOCAL_ACTIVE_BLOCKS_SQL,
        [now_mw],
        storage_wiki=storage_wiki,
        sync_mark_dt=sync_mark_dt,
        dry_run=dry_run,
    )


def _stream_active_global_blocks(
    creds: Tuple[str, str],
    now_mw: str,
    *,
    storage_wiki: str,
    sync_mark_dt: datetime,
    dry_run: bool,
) -> Tuple[int, float, float]:
    conn = _connect_replica("centralauth.analytics.db.svc.wikimedia.cloud", "centralauth_p", creds)
    try:
        return _stream_active_from_conn(
            conn,
            _GLOBAL_ACTIVE_BLOCKS_SQL,
            [now_mw],
            storage_wiki=storage_wiki,
            sync_mark_dt=sync_mark_dt,
            dry_run=dry_run,
        )
    finally:
        _safe_close_replica(conn)


def _fetch_targeted_active_from_conn(
    conn: Any,
    sql: str,
    targets: Sequence[str],
    now_mw: str,
) -> Dict[str, Dict[str, Any]]:
    expanded = expand_db_lookup_targets(targets)
    active_map: Dict[str, Dict[str, Any]] = {}
    with conn.cursor() as cursor:
        for batch in _iter_batches(expanded, _TARGETED_ACTIVE_BATCH_SIZE):
            cursor.execute(sql, (tuple(batch), now_mw))
            rows = cursor.fetchall()
            if rows:
                _merge_active_rows(active_map, rows)
    return active_map


def _fetch_targeted_active_local_blocks(
    session: _ReplicaSession,
    wiki_db: str,
    targets: Sequence[str],
    now_mw: str,
) -> Dict[str, Dict[str, Any]]:
    conn = session.select_db(wiki_db)
    return _fetch_targeted_active_from_conn(conn, _TARGETED_LOCAL_ACTIVE_SQL, targets, now_mw)


def _fetch_targeted_active_global_blocks(
    global_session: _ReplicaSession,
    targets: Sequence[str],
    now_mw: str,
) -> Dict[str, Dict[str, Any]]:
    conn = global_session.select_db("centralauth_p")
    return _fetch_targeted_active_from_conn(conn, _TARGETED_GLOBAL_ACTIVE_SQL, targets, now_mw)


def _prep_db_datetime(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    utc_naive = dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo is not None else dt
    return connection.ops.adapt_datetimefield_value(utc_naive)


def _normalise_utc_datetime(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _iter_batches(items: Sequence[Any], size: int) -> Iterable[List[Any]]:
    for idx in range(0, len(items), size):
        yield list(items[idx : idx + size])


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


def _batch_update_synced_at(wiki_dbnames: Sequence[str], *, synced_at: datetime) -> int:
    """Updates synced_at in bounded batches for idle wikis that required no per-wiki writes."""
    if not wiki_dbnames:
        return 0
    total_updated = 0
    unique_wikis = list(dict.fromkeys(wiki_dbnames))
    for batch in _iter_batches(unique_wikis, _UPSERT_SQL_BATCH_SIZE):

        def _update_batch(target_wikis: List[str] = batch) -> int:
            with transaction.atomic():
                return RangeblockSyncState.objects.filter(wiki_dbname__in=target_wikis).update(synced_at=synced_at)

        total_updated += _run_toolsdb_with_retry(
            _update_batch,
            context=f"batch synced_at update ({len(batch)} wikis)",
        )
    return total_updated


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

    sql = _UPSERT_LOG_SQLITE_SQL if connection.vendor == "sqlite" else _UPSERT_LOG_MYSQL_SQL
    with connection.cursor() as db_cursor:
        for batch in _iter_batches(rows, _UPSERT_SQL_BATCH_SIZE):
            db_cursor.executemany(sql, batch)
    return len(rows)


def _build_active_upsert_rows(
    storage_wiki: str,
    active_entries: Dict[str, Dict[str, Any]],
    *,
    now_dt: datetime,
) -> List[Tuple[Any, ...]]:
    now_db = _prep_db_datetime(now_dt)
    return [
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


def _upsert_active_blocks(
    storage_wiki: str,
    active_entries: Dict[str, Dict[str, Any]],
    *,
    now_dt: datetime,
    targeted: bool = False,
) -> int:
    if not active_entries:
        return 0

    rows = _build_active_upsert_rows(storage_wiki, active_entries, now_dt=now_dt)
    if targeted:
        sql = _UPSERT_TARGETED_ACTIVE_SQLITE_SQL if connection.vendor == "sqlite" else _UPSERT_TARGETED_ACTIVE_MYSQL_SQL
    else:
        sql = _UPSERT_ACTIVE_SQLITE_SQL if connection.vendor == "sqlite" else _UPSERT_ACTIVE_MYSQL_SQL
    with connection.cursor() as db_cursor:
        for batch in _iter_batches(rows, _UPSERT_SQL_BATCH_SIZE):
            db_cursor.executemany(sql, batch)
    return len(rows)


def _deactivate_specific_targets(
    storage_wiki: str,
    targets: Sequence[str],
    *,
    now_dt: datetime,
) -> int:
    if not targets:
        return 0

    total_deactivated = 0
    for batch in _iter_batches(targets, _UPSERT_SQL_BATCH_SIZE):
        total_deactivated += RangeblockAggregate.objects.filter(
            wiki_dbname=storage_wiki,
            target_cidr__in=batch,
            has_active=True,
        ).update(
            has_active=False,
            active_expiry=None,
            active_indefinite=False,
            updated_at=now_dt,
        )
    return total_deactivated


def _merge_log_rows(
    chunk_deltas: Dict[str, Dict[str, Any]],
    rows: Iterable[Tuple[Any, Any, Any, Any]],
    chunk_latest_ts: str,
    *,
    count_actions: frozenset[str],
    touched_targets: Optional[Set[str]],
) -> str:
    for raw_title, raw_action, raw_count, raw_ts in rows:
        normalised = normalize_block_target(_decode_str(raw_title))
        if normalised is None:
            continue
        target_cidr, ip_version, cidr_prefix, start_bin, end_bin = normalised
        ts_str = _decode_str(raw_ts).strip()
        if ts_str and ts_str > chunk_latest_ts:
            chunk_latest_ts = ts_str
        if touched_targets is not None:
            touched_targets.add(target_cidr)
        action = _decode_str(raw_action).strip().lower()
        if action not in count_actions:
            continue
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
    return chunk_latest_ts


def _resolve_log_queries(log_actions: Tuple[str, ...]) -> Tuple[str, str]:
    if len(log_actions) == 3:
        return _MAX_LOG_ID_LOCAL_SQL, _INCREMENTAL_LOGS_LOCAL_SQL
    if len(log_actions) == 4:
        return _MAX_LOG_ID_GLOBAL_SQL, _INCREMENTAL_LOGS_GLOBAL_SQL
    raise ValueError(f"Unsupported log_actions count: {len(log_actions)}")


def _adjust_chunk_size(current_size: int, replica_elapsed: float) -> int:
    if replica_elapsed < _FAST_CHUNK_THRESHOLD_SECONDS:
        return min(_MAX_BATCH_SIZE, current_size * 2)
    if replica_elapsed > _SLOW_CHUNK_THRESHOLD_SECONDS:
        return max(_MIN_BATCH_SIZE, current_size // 2)
    return current_size


def _query_max_log_id(
    session: _ReplicaSession,
    spec: _SyncTargetSpec,
    last_log_id: int,
) -> int:
    if not isinstance(spec.replica_db, str) or not _REPLICA_DB_RE.fullmatch(spec.replica_db):
        raise ValueError(f"Invalid replica database name: {spec.replica_db!r}")
    max_log_id_sql, _ = _resolve_log_queries(spec.log_actions)
    conn = session.select_db(spec.replica_db)
    with conn.cursor() as cursor:
        cursor.execute(max_log_id_sql, [last_log_id, spec.log_type, *spec.log_actions])
        max_row = cursor.fetchone()
    target_max_id = int(max_row[0] or 0) if max_row else 0
    return target_max_id if target_max_id > last_log_id else 0


def _fetch_log_chunk(
    session: _ReplicaSession,
    spec: _SyncTargetSpec,
    incremental_logs_sql: str,
    *,
    cursor_id: int,
    upper_id: int,
    collect_touched: bool,
) -> Tuple[Dict[str, Dict[str, Any]], Set[str], str, float]:
    chunk_deltas: Dict[str, Dict[str, Any]] = {}
    chunk_touched: Set[str] = set()
    chunk_latest_ts = ""
    conn = session.select_db(spec.replica_db)
    stream_cursor = conn.cursor(pymysql.cursors.SSCursor)
    replica_start = time.monotonic()
    try:
        stream_cursor.execute(
            incremental_logs_sql,
            [cursor_id, upper_id, spec.log_type, *spec.log_actions],
        )
        while rows := stream_cursor.fetchmany(_STREAM_FETCH_SIZE):
            chunk_latest_ts = _merge_log_rows(
                chunk_deltas,
                rows,
                chunk_latest_ts,
                count_actions=spec.count_actions,
                touched_targets=chunk_touched if collect_touched else None,
            )
    finally:
        _safe_close_cursor(stream_cursor)
    replica_elapsed = time.monotonic() - replica_start
    return chunk_deltas, chunk_touched, chunk_latest_ts, replica_elapsed


def _fetch_chunk_targeted_active(
    session: _ReplicaSession,
    global_session: Optional[_ReplicaSession],
    spec: _SyncTargetSpec,
    chunk_touched: Set[str],
    *,
    now_mw: str,
    stage_ctx: _WikiSyncStage,
    timing: _WikiTiming,
) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    if not chunk_touched:
        return {}, []
    sorted_targets = sorted(chunk_touched)
    stage_ctx.stage = "active_read"
    read_start = time.monotonic()
    if spec.is_global:
        if global_session is None:
            raise RuntimeError("Global Replica session is required for targeted global active lookups.")
        active_map = _fetch_targeted_active_global_blocks(global_session, sorted_targets, now_mw)
    else:
        active_map = _fetch_targeted_active_local_blocks(session, spec.replica_db, sorted_targets, now_mw)
    timing.active_read += time.monotonic() - read_start
    inactive_targets = sorted(chunk_touched - active_map.keys())
    return active_map, inactive_targets


def _commit_log_chunk_with_retry(
    spec: _SyncTargetSpec,
    chunk_deltas: Dict[str, Dict[str, Any]],
    *,
    active_map: Dict[str, Dict[str, Any]],
    inactive_targets: Sequence[str],
    upper_id: int,
    latest_ts: str,
    log_now_dt: datetime,
    active_now_dt: datetime,
    stage_ctx: _WikiSyncStage,
    timing: _WikiTiming,
) -> int:
    has_active_writes = bool(active_map or inactive_targets)
    if has_active_writes:
        stage_ctx.stage = "active_write"

    def _commit_log_chunk() -> Tuple[int, float, float]:
        log_write_seconds = 0.0
        active_write_seconds = 0.0
        active_changes = 0
        with transaction.atomic():
            if chunk_deltas:
                log_start = time.monotonic()
                _upsert_log_chunk(spec.storage_wiki, chunk_deltas, now_dt=log_now_dt)
                log_write_seconds += time.monotonic() - log_start
            if has_active_writes:
                active_start = time.monotonic()
                if active_map:
                    active_changes += _upsert_active_blocks(
                        spec.storage_wiki,
                        active_map,
                        now_dt=active_now_dt,
                        targeted=True,
                    )
                if inactive_targets:
                    active_changes += _deactivate_specific_targets(
                        spec.storage_wiki,
                        inactive_targets,
                        now_dt=active_now_dt,
                    )
                active_write_seconds += time.monotonic() - active_start
            state_start = time.monotonic()
            _advance_sync_state(
                spec.storage_wiki,
                wiki_domain=spec.wiki_domain,
                now_dt=active_now_dt if has_active_writes else log_now_dt,
                last_log_id=upper_id,
                last_log_timestamp=latest_ts,
            )
            log_write_seconds += time.monotonic() - state_start
        return active_changes, log_write_seconds, active_write_seconds

    active_changes, log_write_seconds, active_write_seconds = _run_toolsdb_with_retry(
        _commit_log_chunk,
        context=f"log chunk upsert for {spec.storage_wiki} (up to log_id={upper_id})",
    )
    timing.logs += log_write_seconds
    timing.active_write += active_write_seconds
    return active_changes


def _handle_log_chunk_timeout(
    session: _ReplicaSession,
    spec: _SyncTargetSpec,
    exc: pymysql.MySQLError,
    *,
    cursor_id: int,
    upper_id: int,
    current_batch_size: int,
) -> int:
    error_code = _extract_mysql_error_code(exc)
    if error_code != _MYSQL_MAX_STATEMENT_TIME_ERR:
        raise exc
    attempted_span = upper_id - cursor_id
    if attempted_span <= _MIN_BATCH_SIZE or current_batch_size <= _MIN_BATCH_SIZE:
        session.close()
        raise exc
    next_batch_size = max(_MIN_BATCH_SIZE, min(current_batch_size, attempted_span) // 2)
    session.reconnect(spec.replica_db)
    logger.warning(
        "Replica statement timeout (wiki=%s, stage=logs, log_id=%d, error_code=%s); "
        "reconnected and reduced batch size from %d to %d",
        spec.storage_wiki,
        cursor_id,
        error_code,
        current_batch_size,
        next_batch_size,
    )
    return next_batch_size


def _stream_incremental_logs(
    session: _ReplicaSession,
    spec: _SyncTargetSpec,
    *,
    last_log_id: int,
    target_max_id: int,
    config: _SyncRunConfig,
    collect_touched: bool,
    active_now_dt: datetime,
    stage_ctx: _WikiSyncStage,
    timing: _WikiTiming,
) -> _LogStreamResult:
    """Streams incremental log chunks with adaptive sizing, timeout recovery, and per-chunk active reconciliation."""
    _, incremental_logs_sql = _resolve_log_queries(spec.log_actions)
    total_targets = 0
    total_active_changes = 0
    chunks_committed = 0
    budget_reached = False
    cursor_id = last_log_id
    current_batch_size = config.batch_size
    loop_started_at = time.monotonic()
    global_session = (
        _ReplicaSession("centralauth.analytics.db.svc.wikimedia.cloud", config.creds)
        if spec.is_global and collect_touched
        else None
    )

    try:
        while cursor_id < target_max_id:
            if time.monotonic() - loop_started_at >= config.max_seconds_per_wiki:
                budget_reached = True
                logger.info(
                    "Per-wiki time budget reached (wiki=%s, stage=logs, log_id=%d, target_max_id=%d, budget=%ds)",
                    spec.storage_wiki,
                    cursor_id,
                    target_max_id,
                    config.max_seconds_per_wiki,
                )
                break

            stage_ctx.stage = "logs"
            stage_ctx.log_id = cursor_id
            upper_id = min(target_max_id, cursor_id + current_batch_size)
            try:
                chunk_deltas, chunk_touched, chunk_latest_ts, replica_elapsed = _fetch_log_chunk(
                    session,
                    spec,
                    incremental_logs_sql,
                    cursor_id=cursor_id,
                    upper_id=upper_id,
                    collect_touched=collect_touched,
                )
            except pymysql.MySQLError as exc:
                current_batch_size = _handle_log_chunk_timeout(
                    session,
                    spec,
                    exc,
                    cursor_id=cursor_id,
                    upper_id=upper_id,
                    current_batch_size=current_batch_size,
                )
                continue

            timing.logs += replica_elapsed
            total_targets += len(chunk_deltas)
            active_map: Dict[str, Dict[str, Any]] = {}
            inactive_targets: List[str] = []
            if collect_touched and chunk_touched:
                active_map, inactive_targets = _fetch_chunk_targeted_active(
                    session,
                    global_session,
                    spec,
                    chunk_touched,
                    now_mw=config.now_mw,
                    stage_ctx=stage_ctx,
                    timing=timing,
                )
            if config.dry_run:
                total_active_changes += len(active_map) + len(inactive_targets)
            else:
                total_active_changes += _commit_log_chunk_with_retry(
                    spec,
                    chunk_deltas,
                    active_map=active_map,
                    inactive_targets=inactive_targets,
                    upper_id=upper_id,
                    latest_ts=chunk_latest_ts,
                    log_now_dt=config.now_dt,
                    active_now_dt=active_now_dt,
                    stage_ctx=stage_ctx,
                    timing=timing,
                )
                chunks_committed += 1
            chunk_deltas.clear()
            cursor_id = upper_id
            stage_ctx.log_id = cursor_id
            current_batch_size = _adjust_chunk_size(current_batch_size, replica_elapsed)
    finally:
        if global_session is not None:
            global_session.close()

    return _LogStreamResult(
        log_targets=total_targets,
        active_changes=total_active_changes,
        chunks_committed=chunks_committed,
        budget_reached=budget_reached,
    )


def _fetch_wikis_with_expired_active_blocks_for_batch(now_dt: datetime, wikis: Sequence[str]) -> Set[str]:
    """Queries expired active rows scoped to an explicit batch of wiki_dbnames."""
    if not wikis:
        return set()
    now_db = _prep_db_datetime(now_dt)
    placeholders = ", ".join(["%s"] * len(wikis))
    sql = _FETCH_EXPIRED_ACTIVE_WIKIS_BY_WIKI_SQL_PREFIX.format(placeholders=placeholders)
    with connection.cursor() as db_cursor:
        db_cursor.execute(sql, [*wikis, now_db])
        return {_decode_str(row[0]).strip().lower() for row in db_cursor.fetchall() if row and row[0]}


def _fetch_wikis_with_expired_active_blocks_batched(now_dt: datetime, wikis: Sequence[str]) -> Set[str]:
    """Scans expired active rows in bounded wiki batches using idx_rb_agg_wiki_active."""
    expired: Set[str] = set()
    for start in range(0, len(wikis), _EXPIRED_WIKIS_BATCH_SIZE):
        batch = wikis[start : start + _EXPIRED_WIKIS_BATCH_SIZE]
        expired.update(
            _run_toolsdb_with_retry(
                lambda batch=batch: _fetch_wikis_with_expired_active_blocks_for_batch(now_dt, batch),
                context="startup expired active blocks batched scan",
            )
        )
    return expired


def _fetch_wikis_with_expired_active_blocks(
    now_dt: datetime,
    *,
    filter_wikis: Optional[Set[str]] = None,
    known_wikis: Optional[Iterable[str]] = None,
) -> Set[str]:
    """Finds wikis that currently hold naturally expired rows still marked as active in ToolsDB."""
    if filter_wikis:
        return _fetch_wikis_with_expired_active_blocks_batched(now_dt, sorted(filter_wikis))

    now_db = _prep_db_datetime(now_dt)
    try:
        with connection.cursor() as db_cursor:
            db_cursor.execute(_FETCH_EXPIRED_ACTIVE_WIKIS_SQL, [now_db])
            return {_decode_str(row[0]).strip().lower() for row in db_cursor.fetchall() if row and row[0]}
    except OperationalError as exc:
        error_code = _extract_mysql_error_code(exc)
        if error_code in {2013, _MYSQL_MAX_STATEMENT_TIME_ERR} and known_wikis:
            logger.warning(
                "Global expired active blocks scan timed out (code=%s); falling back to per-wiki batched scan.",
                error_code,
            )
            connection.close()
            return _fetch_wikis_with_expired_active_blocks_batched(now_dt, sorted(set(known_wikis)))
        raise


def _deactivate_stale_active_blocks(storage_wiki: str, *, sync_mark_dt: datetime) -> int:
    """Deactivates rows still marked active from earlier rounds in bounded SQL batches."""
    total_deactivated = 0

    def _deactivate_batch() -> int:
        sync_mark_db = _prep_db_datetime(sync_mark_dt)
        sql = (
            _DEACTIVATE_STALE_ACTIVE_SQLITE_SQL if connection.vendor == "sqlite" else _DEACTIVATE_STALE_ACTIVE_MYSQL_SQL
        )
        with transaction.atomic(), connection.cursor() as db_cursor:
            db_cursor.execute(sql, [sync_mark_db, storage_wiki, sync_mark_db])
            return max(0, int(db_cursor.rowcount or 0))

    while True:
        affected = _run_toolsdb_with_retry(
            _deactivate_batch,
            context=f"stale active block deactivation for {storage_wiki}",
        )
        if affected == 0:
            break
        total_deactivated += affected
    return total_deactivated


def _deactivate_expired_active_blocks(storage_wiki: str, *, now_dt: datetime, updated_dt: datetime) -> int:
    """Deactivates naturally expired active rows locally in ToolsDB in bounded batches."""
    total_deactivated = 0

    def _deactivate_batch() -> int:
        now_db = _prep_db_datetime(now_dt)
        updated_db = _prep_db_datetime(updated_dt)
        sql = (
            _DEACTIVATE_EXPIRED_ACTIVE_SQLITE_SQL
            if connection.vendor == "sqlite"
            else _DEACTIVATE_EXPIRED_ACTIVE_MYSQL_SQL
        )
        with transaction.atomic(), connection.cursor() as db_cursor:
            db_cursor.execute(sql, [updated_db, storage_wiki, now_db])
            return max(0, int(db_cursor.rowcount or 0))

    while True:
        affected = _run_toolsdb_with_retry(
            _deactivate_batch,
            context=f"expired active block deactivation for {storage_wiki}",
        )
        if affected == 0:
            break
        total_deactivated += affected
    return total_deactivated


def _purge_wiki_rangeblocks(storage_wiki: str) -> Tuple[int, int]:
    """Deletes all aggregate rows (in 5000-row batches) and sync state for an excluded wiki."""
    total_agg_deleted = 0

    def _delete_agg_batch() -> int:
        sql = _PURGE_WIKI_AGG_SQLITE_SQL if connection.vendor == "sqlite" else _PURGE_WIKI_AGG_MYSQL_SQL
        with transaction.atomic(), connection.cursor() as db_cursor:
            db_cursor.execute(sql, [storage_wiki])
            return max(0, int(db_cursor.rowcount or 0))

    while True:
        deleted = _run_toolsdb_with_retry(
            _delete_agg_batch,
            context=f"excluded wiki aggregate purge for {storage_wiki}",
        )
        if deleted == 0:
            break
        total_agg_deleted += deleted

    def _delete_sync_state() -> int:
        with transaction.atomic():
            count, _ = RangeblockSyncState.objects.filter(wiki_dbname=storage_wiki).delete()
            return int(count or 0)

    state_deleted = _run_toolsdb_with_retry(
        _delete_sync_state,
        context=f"excluded wiki sync state purge for {storage_wiki}",
    )
    return total_agg_deleted, state_deleted


def _reconcile_full_active(
    session: _ReplicaSession,
    spec: _SyncTargetSpec,
    *,
    config: _SyncRunConfig,
    sync_mark_dt: datetime,
    stage_ctx: _WikiSyncStage,
    timing: _WikiTiming,
) -> int:
    """Executes full O(1)-memory streaming mark-and-sweep reconciliation for one target."""
    stage_ctx.stage = "active_read"
    if spec.is_global:
        active_upserted, read_seconds, write_seconds = _stream_active_global_blocks(
            config.creds,
            config.now_mw,
            storage_wiki=spec.storage_wiki,
            sync_mark_dt=sync_mark_dt,
            dry_run=config.dry_run,
        )
    else:
        active_upserted, read_seconds, write_seconds = _stream_active_local_blocks(
            session,
            spec.replica_db,
            config.now_mw,
            storage_wiki=spec.storage_wiki,
            sync_mark_dt=sync_mark_dt,
            dry_run=config.dry_run,
        )
    timing.active_read += read_seconds
    timing.active_write += write_seconds
    if config.dry_run:
        return active_upserted

    stage_ctx.stage = "active_write"
    sweep_start = time.monotonic()
    active_deactivated = _deactivate_stale_active_blocks(spec.storage_wiki, sync_mark_dt=sync_mark_dt)
    timing.active_write += time.monotonic() - sweep_start
    return active_upserted + active_deactivated


class Command(BaseCommand):
    """Synchronises active rangeblocks and incremental block logs across Wikimedia projects."""

    help = "Synchronises cross-wiki active blocks and incremental block log counts from Wiki Replicas into ToolsDB."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--wikis", type=str, default="", help="Comma-separated wiki dbnames to sync.")
        parser.add_argument(
            "--sections", type=str, default="", help="Comma-separated Wiki Replicas sections (e.g. s1,s3)."
        )
        parser.add_argument("--batch-size", type=int, default=_DEFAULT_BATCH_SIZE, help="Log ID chunk size per query.")
        parser.add_argument(
            "--max-seconds-per-wiki",
            type=int,
            default=_DEFAULT_MAX_SECONDS_PER_WIKI,
            help="Maximum seconds spent in the incremental log loop per wiki target.",
        )
        parser.add_argument(
            "--full-active-reconcile",
            action="store_true",
            help="Force full streaming mark-and-sweep reconciliation of active blocks.",
        )
        parser.add_argument(
            "--exclude-wikis",
            type=str,
            default="",
            help="Comma-separated wiki dbnames to exclude from syncing (in addition to RANGEBLOCK_REALTIME_WIKIS).",
        )
        parser.add_argument(
            "--include-realtime-wikis",
            action="store_true",
            help="Do not automatically exclude RANGEBLOCK_REALTIME_WIKIS from syncing.",
        )
        parser.add_argument(
            "--purge-excluded",
            action="store_true",
            help="Delete existing ToolsDB aggregate and sync-state rows for excluded wikis in bounded batches.",
        )
        parser.add_argument("--dry-run", action="store_true", help="Inspect counts without modifying ToolsDB.")

    def _write_progress(self, message: str) -> None:
        self.stdout.write(message, ending="\n")
        flush = getattr(self.stdout, "flush", None)
        if callable(flush):
            flush()

    def _commit_target_sync_state(
        self,
        spec: _SyncTargetSpec,
        *,
        sync_mark_dt: datetime,
        stage_ctx: _WikiSyncStage,
    ) -> None:
        stage_ctx.stage = "sync_state"

        def _commit_sync_state() -> None:
            with transaction.atomic():
                _advance_sync_state(spec.storage_wiki, wiki_domain=spec.wiki_domain, now_dt=sync_mark_dt)

        _run_toolsdb_with_retry(
            _commit_sync_state,
            context=f"sync state update for {spec.storage_wiki}",
        )

    def _sync_wiki_target(
        self,
        session: _ReplicaSession,
        spec: _SyncTargetSpec,
        *,
        config: _SyncRunConfig,
        stage_ctx: _WikiSyncStage,
    ) -> _WikiSyncResult:
        timing = _WikiTiming(wiki=spec.storage_wiki)
        state = config.sync_states.get(spec.storage_wiki)
        last_log_id = int(state.last_log_id) if state is not None else 0
        stage_ctx.log_id = last_log_id
        use_full_active = last_log_id == 0 or config.full_active_reconcile
        has_expired_rows = spec.storage_wiki in config.expired_wikis

        stage_ctx.stage = "max_id"
        max_id_start = time.monotonic()
        target_max_id = _query_max_log_id(session, spec, last_log_id)
        timing.max_id = time.monotonic() - max_id_start
        has_new_logs = target_max_id > last_log_id

        if not use_full_active and not has_new_logs and not has_expired_rows:
            return _WikiSyncResult(
                active_changes=0,
                log_targets=0,
                used_fast_path=True,
                budget_reached=False,
                timing=timing,
            )

        sync_mark_dt = _next_sync_mark_dt(config.now_dt, state)
        log_result = _LogStreamResult(log_targets=0, active_changes=0, chunks_committed=0, budget_reached=False)
        if has_new_logs:
            log_result = _stream_incremental_logs(
                session,
                spec,
                last_log_id=last_log_id,
                target_max_id=target_max_id,
                config=config,
                collect_touched=not use_full_active,
                active_now_dt=sync_mark_dt,
                stage_ctx=stage_ctx,
                timing=timing,
            )

        if use_full_active:
            full_sync_mark_dt = _next_sync_mark_dt(config.now_dt, state)
            active_changes = _reconcile_full_active(
                session,
                spec,
                config=config,
                sync_mark_dt=full_sync_mark_dt,
                stage_ctx=stage_ctx,
                timing=timing,
            )
            state_sync_dt = full_sync_mark_dt
        else:
            active_changes = log_result.active_changes
            if has_expired_rows and not config.dry_run:
                stage_ctx.stage = "expire"
                expire_start = time.monotonic()
                active_changes += _deactivate_expired_active_blocks(
                    spec.storage_wiki,
                    now_dt=config.now_dt,
                    updated_dt=sync_mark_dt,
                )
                timing.expire = time.monotonic() - expire_start
            state_sync_dt = sync_mark_dt

        if not config.dry_run and (use_full_active or log_result.chunks_committed == 0):
            self._commit_target_sync_state(spec, sync_mark_dt=state_sync_dt, stage_ctx=stage_ctx)

        return _WikiSyncResult(
            active_changes=active_changes,
            log_targets=log_result.log_targets,
            used_fast_path=False,
            budget_reached=log_result.budget_reached,
            timing=timing,
        )

    def _run_single_target(
        self,
        session: _ReplicaSession,
        spec: _SyncTargetSpec,
        *,
        config: _SyncRunConfig,
    ) -> Optional[_WikiSyncResult]:
        stage_ctx = _WikiSyncStage()
        try:
            return self._sync_wiki_target(session, spec, config=config, stage_ctx=stage_ctx)
        except (pymysql.MySQLError, DatabaseError, OSError) as exc:
            connection.close()
            session.close()
            error_code = _extract_mysql_error_code(exc)
            logger.warning(
                "Rangeblock sync failed (wiki=%s, stage=%s, log_id=%d, error_code=%s): %s",
                spec.storage_wiki,
                stage_ctx.stage,
                stage_ctx.log_id,
                error_code if error_code is not None else "unknown",
                sanitize_error_message(str(exc)),
            )
            return None

    def _report_section_summary(
        self,
        section: str,
        *,
        section_synced: int,
        section_failed: int,
        fast_path_count: int,
        elapsed_seconds: float,
        timings: Sequence[_WikiTiming],
    ) -> None:
        self._write_progress(
            f"[section {section}] completed (synced={section_synced}, failed={section_failed}, "
            f"fast_path={fast_path_count}, elapsed={elapsed_seconds:.2f}s)."
        )
        if not timings:
            return
        slowest = sorted(timings, key=lambda item: item.total, reverse=True)[:_SLOWEST_WIKIS_LIMIT]
        self._write_progress(f"[section {section}] slowest wikis (top {len(slowest)}):")
        for item in slowest:
            self._write_progress(
                f"  {item.wiki}: total={item.total:.2f}s "
                f"(max_id={item.max_id:.2f}s, logs={item.logs:.2f}s, "
                f"active_read={item.active_read:.2f}s, active_write={item.active_write:.2f}s, "
                f"expire={item.expire:.2f}s)"
            )

    def _sync_section(
        self,
        section: str,
        entries: List[Tuple[str, str]],
        *,
        config: _SyncRunConfig,
    ) -> Tuple[int, List[str]]:
        host = f"{section}.analytics.db.svc.wikimedia.cloud"
        first_db = f"{entries[0][0]}_p"
        total_entries = len(entries)
        section_synced = 0
        section_failed_wikis: List[str] = []
        deferred_synced_at_wikis: List[str] = []
        section_timings: List[_WikiTiming] = []
        section_started_at = time.monotonic()

        self._write_progress(f"[section {section}] starting ({total_entries} wikis).")
        try:
            initial_conn = _connect_replica(host, first_db, config.creds)
        except (pymysql.MySQLError, OSError) as exc:
            error_code = _extract_mysql_error_code(exc)
            logger.warning(
                "Skipping section %s due to connection error (wiki=%s, stage=connect, log_id=0, error_code=%s): %s",
                section,
                entries[0][0],
                error_code if error_code is not None else "unknown",
                sanitize_error_message(str(exc)),
            )
            self._write_progress(f"[section {section}] skipped due to connection error ({total_entries} wikis failed).")
            return 0, [db for db, _ in entries]

        session = _ReplicaSession(host, config.creds, initial_conn)
        try:
            for idx, (dbname, domain) in enumerate(entries, start=1):
                replica_db = f"{dbname}_p"
                local_spec = _SyncTargetSpec(
                    replica_db=replica_db,
                    storage_wiki=dbname,
                    wiki_domain=domain,
                    log_type="block",
                    log_actions=_LOCAL_LOG_ACTIONS,
                    count_actions=_LOCAL_COUNT_ACTIONS,
                    is_global=False,
                )
                local_result = self._run_single_target(session, local_spec, config=config)
                if local_result is None:
                    section_failed_wikis.append(dbname)
                else:
                    section_synced += 1
                    section_timings.append(local_result.timing)
                    if local_result.used_fast_path:
                        deferred_synced_at_wikis.append(dbname)

                if dbname == "metawiki":
                    global_spec = _SyncTargetSpec(
                        replica_db=replica_db,
                        storage_wiki="global",
                        wiki_domain="meta.wikimedia.org",
                        log_type="gblblock",
                        log_actions=_GLOBAL_LOG_ACTIONS,
                        count_actions=_GLOBAL_COUNT_ACTIONS,
                        is_global=True,
                    )
                    global_result = self._run_single_target(session, global_spec, config=config)
                    if global_result is None:
                        section_failed_wikis.append("global")
                    else:
                        section_synced += 1
                        section_timings.append(global_result.timing)
                        if global_result.used_fast_path:
                            deferred_synced_at_wikis.append("global")
                        self._write_progress(
                            f"[global] completed (log_targets={global_result.log_targets}, "
                            f"active_updates={global_result.active_changes}, "
                            f"fast_path={global_result.used_fast_path})."
                        )

                self._write_progress(
                    f"[section {section}] progress {idx}/{total_entries} "
                    f"(latest={dbname}, synced={section_synced}, failed={len(section_failed_wikis)})"
                )
        finally:
            session.close()

        if deferred_synced_at_wikis and not config.dry_run:
            try:
                _batch_update_synced_at(deferred_synced_at_wikis, synced_at=datetime.now(timezone.utc))
            except DatabaseError as exc:
                error_code = _extract_mysql_error_code(exc)
                logger.warning(
                    "Batch synced_at update failed (wiki=%s, stage=batch_synced_at, log_id=0, error_code=%s): %s",
                    section,
                    error_code if error_code is not None else "unknown",
                    sanitize_error_message(str(exc)),
                )

        self._report_section_summary(
            section,
            section_synced=section_synced,
            section_failed=len(section_failed_wikis),
            fast_path_count=len(deferred_synced_at_wikis),
            elapsed_seconds=time.monotonic() - section_started_at,
            timings=section_timings,
        )
        return section_synced, section_failed_wikis

    def handle(self, *args: Any, **options: Any) -> None:
        creds = discover_wiki_replica_credentials()
        if creds is None:
            raise CommandError("Wiki Replicas credentials were not found in TOOL_REPLICA_* or replica.my.cnf.")

        raw_batch_size = int(options.get("batch_size") or _DEFAULT_BATCH_SIZE)
        batch_size = max(_MIN_BATCH_SIZE, min(_MAX_BATCH_SIZE, raw_batch_size))
        max_seconds_per_wiki = max(1, int(options.get("max_seconds_per_wiki") or _DEFAULT_MAX_SECONDS_PER_WIKI))
        full_active_reconcile = bool(options.get("full_active_reconcile"))
        dry_run = bool(options.get("dry_run"))
        filter_wikis = {w.strip().lower() for w in str(options.get("wikis") or "").split(",") if w.strip()} or None
        filter_sections = {
            _normalise_section(s) for s in str(options.get("sections") or "").split(",") if s.strip()
        } or None
        exclude_wikis: Set[str] = {
            w.strip().lower() for w in str(options.get("exclude_wikis") or "").split(",") if w.strip()
        }
        if not bool(options.get("include_realtime_wikis")):
            exclude_wikis.update(get_configured_realtime_wikis())
        if filter_wikis:
            exclude_wikis -= filter_wikis
        purge_excluded = bool(options.get("purge_excluded"))

        lock_client: Optional[Any] = None
        lock_redis_url = ""
        lock_key = ""
        lock_token = ""
        if not dry_run and not _is_test_environment():
            lock_client, lock_redis_url, lock_key, lock_token, should_proceed = _acquire_sync_lock()
            if not should_proceed:
                self._write_progress(
                    f"Skipping sync_world_block because another instance currently holds lock {lock_key}."
                )
                return

        try:
            if purge_excluded and exclude_wikis:
                for excluded_wiki in sorted(exclude_wikis):
                    if dry_run:
                        self._write_progress(f"[dry-run] Would purge excluded wiki {excluded_wiki} from ToolsDB.")
                    else:
                        agg_del, state_del = _purge_wiki_rangeblocks(excluded_wiki)
                        self._write_progress(
                            f"Purged excluded wiki {excluded_wiki}: "
                            f"{agg_del} aggregate rows, {state_del} sync-state rows."
                        )

            now_dt = datetime.now(timezone.utc)
            now_mw = now_dt.strftime("%Y%m%d%H%M%S")
            sync_states = _run_toolsdb_with_retry(
                lambda: {state.wiki_dbname: state for state in RangeblockSyncState.objects.all()},
                context="startup sync state prefetch",
            )
            known_non_excluded = [w for w in sync_states if w not in exclude_wikis]
            if filter_wikis:
                expired_wikis = _fetch_wikis_with_expired_active_blocks(
                    now_dt,
                    filter_wikis=filter_wikis,
                )
            else:
                expired_wikis = _run_toolsdb_with_retry(
                    lambda: _fetch_wikis_with_expired_active_blocks(
                        now_dt,
                        known_wikis=known_non_excluded,
                    ),
                    context="startup expired active blocks scan",
                )
            config = _SyncRunConfig(
                creds=creds,
                now_mw=now_mw,
                now_dt=now_dt,
                batch_size=batch_size,
                max_seconds_per_wiki=max_seconds_per_wiki,
                full_active_reconcile=full_active_reconcile,
                dry_run=dry_run,
                sync_states=sync_states,
                expired_wikis=expired_wikis,
            )

            wikis = _fetch_active_wikis(
                creds,
                filter_wikis=filter_wikis,
                filter_sections=filter_sections,
                exclude_wikis=exclude_wikis or None,
            )
            by_section: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
            for dbname, domain, section in wikis:
                by_section[section].append((dbname, domain))

            synced_count = 0
            failed_wikis: List[str] = []

            for section, entries in sorted(by_section.items()):
                section_synced, section_failed = self._sync_section(section, entries, config=config)
                synced_count += section_synced
                failed_wikis.extend(section_failed)

            summary = (
                f"Synchronised {synced_count} rangeblock wiki targets "
                f"(dry_run={dry_run}, full_active_reconcile={full_active_reconcile}, failed={len(failed_wikis)})."
            )
            if synced_count == 0 and failed_wikis:
                raise CommandError(f"Rangeblock sync failed for all targets: {summary}")
            self._write_progress(self.style.SUCCESS(summary))
        finally:
            _release_sync_lock(lock_client, lock_key, lock_token, redis_url=lock_redis_url)
