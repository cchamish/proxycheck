"""Core P0 tests for rangeblock invariants, real-time overrides, auth guards, and SSE streaming."""

import json
import sqlite3
from unittest.mock import AsyncMock, patch

import dns.resolver
from asgiref.sync import sync_to_async
from django.test import AsyncClient, TestCase, override_settings

from detector import cache_backends, rangeblock_service
from detector.models import RangeblockAggregate

from .helpers import _login_authorised, start_non_dnsbl_provider_stubs


async def _add_agg(wiki: str, count: int, *, active: bool = False) -> None:
    target, ver, prefix, start_bin, end_bin = rangeblock_service.normalize_block_target("8.8.8.0/24")
    await sync_to_async(RangeblockAggregate.objects.create, thread_sensitive=True)(
        wiki_dbname=wiki,
        target_cidr=target,
        ip_version=ver,
        cidr_prefix=prefix,
        range_start_bin=start_bin,
        range_end_bin=end_bin,
        block_count=count,
        has_active=active,
    )


class RangeblockAndSseTests(TestCase):
    def setUp(self):
        cache_backends.reset_redis_circuit_breaker()
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock, side_effect=dns.resolver.NXDOMAIN()
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)

    async def test_rangeblock_invariants_override_and_degradation(self):
        """P0: IPv4/IPv6 CIDR bounds, global/metawiki split, replica override, and graceful degradation."""
        _, v4 = rangeblock_service.generate_rangeblock_candidates("198.51.100.42")
        _, v6 = rangeblock_service.generate_rangeblock_candidates("2606:4700:4700::1111")
        self.assertEqual([c.cidr for c in v4], [None, *range(32, 15, -1)])
        self.assertEqual([c.cidr for c in v6], [None, *range(64, 18, -1)])
        self.assertEqual(rangeblock_service.compute_effective_block_count(3, True), 3)
        self.assertEqual(rangeblock_service.compute_effective_block_count(0, True), 1)

        await _add_agg("global", 2, active=True)
        await _add_agg("metawiki", 5)
        await _add_agg("enwiki", 1)

        def _mock_replica(wiki_dbname, _targets, _creds):
            if wiki_dbname == "enwiki":
                return {"enwiki": {"8.8.8.0/24": {"block_count": 3, "has_active": True, "active_indefinite": True}}}
            return {"metawiki": {}, "global": {}}

        with (
            patch("detector.rangeblock_service.discover_wiki_replica_credentials", return_value=("u", "p")),
            patch("detector.rangeblock_service._resolve_realtime_wiki_list", return_value=("enwiki",)),
            patch("detector.rangeblock_service._query_single_replica_wiki_sync", side_effect=_mock_replica),
        ):
            merged = await rangeblock_service.query_rangeblocks_for_ip("8.8.8.8")
        self.assertFalse(merged["realtimeDegraded"])
        self.assertEqual((merged["globalTotal"], merged["localTotal"]), (2, 8))
        self.assertEqual([w["wiki"] for w in merged["wikis"]], ["global", "enwiki", "metawiki"])

        with (
            patch("detector.rangeblock_service.discover_wiki_replica_credentials", return_value=("u", "p")),
            patch("detector.rangeblock_service._query_single_replica_wiki_sync", side_effect=OSError("down")),
        ):
            degraded = await rangeblock_service.query_rangeblocks_for_ip("8.8.8.8")
        self.assertTrue(degraded["realtimeDegraded"])
        self.assertEqual(degraded["localTotal"], 6)

    async def test_rangeblock_and_stream_auth_guards(self):
        """P0: Both new endpoints enforce 401/403."""
        client = AsyncClient()
        for path in ("/api/v1/rangeblock?ip=8.8.8.8", "/api/v1/detect/stream?ip=8.8.8.8"):
            with self.subTest(path=path):
                await client.alogout()
                self.assertEqual((await client.get(path)).status_code, 401)
                session = await sync_to_async(lambda: client.session, thread_sensitive=True)()
                session["wikimedia_user"] = {"isLoggedIn": True, "username": "NoAccess", "hasAccess": False}
                await sync_to_async(session.save, thread_sensitive=True)()
                self.assertEqual((await client.get(path)).status_code, 403)

    async def test_detect_stream_sse_order(self):
        """P0: /api/v1/detect/stream emits snapshot -> provider -> done in order."""
        _login_authorised(self)
        start_non_dnsbl_provider_stubs(
            self,
            overrides={
                "proxycheck": {
                    "provider": "Proxycheck",
                    "status": "200 OK",
                    "statusCode": 200,
                    "asn": "AS15169",
                    "isp": "Google LLC",
                    "organisation": "Google LLC",
                    "location": "US",
                    "usageType": "isp",
                    "securityFlags": [],
                    "rawJson": {},
                }
            },
        )
        client = AsyncClient()
        client.cookies.load(self.client.cookies.output(header=""))
        with (
            override_settings(PROXYCHECK_API_KEY="test-key"),
            patch("detector.rangeblock_service.discover_wiki_replica_credentials", return_value=None),
        ):
            resp = await client.get("/api/v1/detect/stream?ip=8.8.8.8")
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(resp.headers.get("Content-Type", "").startswith("text/event-stream"))
            chunks = [c.decode("utf-8") if isinstance(c, bytes) else str(c) async for c in resp.streaming_content]
            body = "".join(chunks)

        events = [
            (lines[0].removeprefix("event:").strip(), json.loads(lines[1].removeprefix("data:").strip()))
            for block in body.split("\n\n")
            if (lines := [ln for ln in block.splitlines() if ln.startswith(("event:", "data:"))]) and len(lines) == 2
        ]
        self.assertEqual(events[0][0], "snapshot")
        self.assertIn("rangeblock", events[0][1])
        self.assertIn("provider", [name for name, _ in events[1:-1]])
        self.assertEqual(events[-1][0], "done")


class _ReplicaCursor:
    """Runs the live replica SQL against SQLite tables seeded with MediaWiki's stored target spellings."""

    def __init__(self, conn):
        self._cursor = conn.cursor()

    def execute(self, sql, params):
        self._cursor.execute(sql.replace("%s", "?"), list(params))

    def fetchall(self):
        return self._cursor.fetchall()


def _seed_replica(stored_targets):
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.executescript(
        "CREATE TABLE block_target (bt_id INTEGER PRIMARY KEY, bt_address TEXT, bt_user INTEGER);"
        "CREATE TABLE block (bl_id INTEGER PRIMARY KEY, bl_target INTEGER, bl_expiry TEXT);"
        "CREATE TABLE logging_logindex (log_type TEXT, log_action TEXT, log_namespace INTEGER, "
        "log_title TEXT, log_timestamp TEXT);"
    )
    for bt_id, target in enumerate(stored_targets, start=1):
        conn.execute("INSERT INTO block_target VALUES (?, ?, NULL)", (bt_id, target))
        conn.execute("INSERT INTO block VALUES (?, ?, 'infinity')", (bt_id, bt_id))
        conn.execute(
            "INSERT INTO logging_logindex VALUES ('block', 'block', 2, ?, '20260101000000')",
            (target,),
        )
    return conn


class RangeblockReplicaTargetSpellingTests(TestCase):
    """Live replica lookups must match the targets as MediaWiki stores them (IPUtils::sanitizeIP)."""

    async def _query_live(self, ip, stored_targets):
        conn = _seed_replica(stored_targets)
        self.addCleanup(conn.close)

        def _sqlite_replica(wiki_dbname, db_targets, _creds):
            return {wiki_dbname: rangeblock_service._query_local_wiki_tables(_ReplicaCursor(conn), db_targets, "0")}

        with (
            patch("detector.rangeblock_service.discover_wiki_replica_credentials", return_value=("u", "p")),
            patch("detector.rangeblock_service._resolve_realtime_wiki_list", return_value=("enwiki",)),
            patch("detector.rangeblock_service._query_single_replica_wiki_sync", side_effect=_sqlite_replica),
        ):
            summary = await rangeblock_service.query_rangeblocks_for_ip(ip)
        return [(row["target"], row["count"], row["isActive"]) for wiki in summary["wikis"] for row in wiki["rows"]]

    async def test_ipv6_single_ip_block_matches_expanded_spelling(self):
        rows = await self._query_live("2606:4700:4700::1111", ["2606:4700:4700:0:0:0:0:1111"])
        self.assertEqual(rows, [("2606:4700:4700::1111", 1, True)])

    async def test_ipv6_cidr_block_matches_expanded_spelling(self):
        rows = await self._query_live("2606:4700:4700::1111", ["2606:4700:4700:0:0:0:0:0/48"])
        self.assertEqual(rows, [("2606:4700:4700::/48", 1, True)])

    async def test_ipv4_blocks_still_match(self):
        rows = await self._query_live("8.8.8.8", ["8.8.8.8", "8.8.8.0/24"])
        self.assertEqual(rows, [("8.8.8.8", 1, True), ("8.8.8.0/24", 1, True)])

    def test_lookup_targets_include_mediawiki_spelling(self):
        self.assertEqual(
            rangeblock_service.expand_db_lookup_targets(["8.8.8.0/24", "2606:4700:4700::1111", "2606:4700:4700::/48"]),
            [
                "8.8.8.0/24",
                "2606:4700:4700::1111",
                "2606:4700:4700:0:0:0:0:1111",
                "2606:4700:4700::/48",
                "2606:4700:4700:0:0:0:0:0/48",
            ],
        )
