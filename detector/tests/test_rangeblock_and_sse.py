"""Core P0 tests for rangeblock invariants, real-time overrides, auth guards, and SSE streaming."""

import json
from unittest.mock import AsyncMock, patch

import dns.resolver
from asgiref.sync import sync_to_async
from django.db import OperationalError
from django.test import AsyncClient, TestCase, override_settings

from detector.cache import redis_backend as cache_backends
from detector.models import RangeblockAggregate
from detector.rangeblock import service as rangeblock_service

from .helpers import TEST_UPSTREAM_SECRETS, _login_authorised, start_non_dnsbl_provider_stubs


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
    async def _lookup_blocks(self):
        _login_authorised(self)
        client = AsyncClient()
        client.cookies.load(self.client.cookies.output(header=""))
        response = await client.get("/api/v1/rangeblock?ip=8.8.8.8")
        self.assertEqual(response.status_code, 200)
        return response.json()

    async def test_block_data_query_failure_is_degraded(self):
        with (
            patch(
                "detector.rangeblock.service.RangeblockAggregate.objects.filter",
                side_effect=OperationalError("missing table"),
            ),
            patch("detector.rangeblock.service._fetch_realtime_wiki_blocks", return_value=({}, set(), False)),
        ):
            result = await self._lookup_blocks()
        self.assertTrue(result.get("blockDataDegraded", False))
        self.assertEqual(result["wikis"], [])

    async def test_empty_block_data_query_is_not_degraded(self):
        with patch("detector.rangeblock.service._fetch_realtime_wiki_blocks", return_value=({}, set(), False)):
            result = await self._lookup_blocks()
        self.assertFalse(result.get("blockDataDegraded", False))
        self.assertEqual((result["localTotal"], result["globalTotal"], result["wikis"]), (0, 0, []))

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
            patch("detector.rangeblock.service.discover_wiki_replica_credentials", return_value=("u", "p")),
            patch("detector.rangeblock.service._resolve_realtime_wiki_list", return_value=("enwiki",)),
            patch("detector.rangeblock.service._query_single_replica_wiki_sync", side_effect=_mock_replica),
        ):
            merged = await rangeblock_service.query_rangeblocks_for_ip("8.8.8.8")
        self.assertFalse(merged["realtimeDegraded"])
        self.assertEqual((merged["globalTotal"], merged["localTotal"]), (2, 8))
        self.assertEqual([w["wiki"] for w in merged["wikis"]], ["global", "enwiki", "metawiki"])

        with (
            patch("detector.rangeblock.service.discover_wiki_replica_credentials", return_value=("u", "p")),
            patch("detector.rangeblock.service._query_single_replica_wiki_sync", side_effect=OSError("down")),
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
            patch("detector.rangeblock.service.discover_wiki_replica_credentials", return_value=None),
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

    async def test_detect_stream_light_mode_defers_tor_and_skips_dns_lookups(self):
        """Light-mode SSE defers Tor Onionoo when offline misses, skips live PTR/BGP, and extracts bgpPrefix string."""
        _login_authorised(self)
        mocks = start_non_dnsbl_provider_stubs(self)
        ptr_spy = AsyncMock(return_value="dns.google")
        bgp_spy = AsyncMock(return_value={"bgpPrefix": "8.8.8.0/24", "asn": 15169})
        client = AsyncClient()
        client.cookies.load(self.client.cookies.output(header=""))
        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch("detector.cache.redis_backend.redis_client", None),
            patch("detector.rangeblock.service.discover_wiki_replica_credentials", return_value=None),
            patch("detector.offline.feeds.lookup_tor_onionoo_offline", return_value=None),
            patch(
                "detector.offline.feeds.lookup_bgp_tools_offline",
                return_value={"bgpPrefix": "8.8.8.0/24", "asn": 15169, "tags": []},
            ),
            patch("detector.providers.dns.query_rdns_ptr", ptr_spy),
            patch("detector.providers.dns.query_cymru_bgp_prefix", bgp_spy),
        ):
            resp = await client.get("/api/v1/detect/stream?ip=8.8.8.8&mode=light")
            self.assertEqual(resp.status_code, 200)
            chunks = [c.decode("utf-8") if isinstance(c, bytes) else str(c) async for c in resp.streaming_content]

        events = [
            (lines[0].removeprefix("event:").strip(), json.loads(lines[1].removeprefix("data:").strip()))
            for block in "".join(chunks).split("\n\n")
            if (lines := [ln for ln in block.splitlines() if ln.startswith(("event:", "data:"))]) and len(lines) == 2
        ]
        self.assertEqual(events[0][0], "snapshot")
        self.assertEqual(events[0][1]["pendingProviders"], [])
        self.assertEqual(events[0][1]["bgpPrefix"], "8.8.8.0/24")
        self.assertEqual(events[-1][0], "done")
        mocks["tor_onionoo"].assert_not_awaited()
        mocks["proxycheck"].assert_not_awaited()
        ptr_spy.assert_not_awaited()
        bgp_spy.assert_not_awaited()

    async def test_detect_stream_coalesces_on_concurrent_updating_lock(self):
        """Polls for a concurrent worker snapshot when the Redis updating lock is held instead of fanning out."""
        _login_authorised(self)
        mocks = start_non_dnsbl_provider_stubs(self)
        polled_payload = {
            "ip": "8.8.8.8",
            "isCached": True,
            "fetchedAt": "2026-11-28T00:00:00+00:00",
            "results": [],
            "cacheMeta": {"status": "hit", "layer": "L1", "isStale": False, "shouldAutoRefresh": False},
        }
        client = AsyncClient()
        client.cookies.load(self.client.cookies.output(header=""))
        with (
            patch("detector.cache.redis_backend.redis_client", None),
            patch("detector.rangeblock.service.discover_wiki_replica_credentials", return_value=None),
            patch("detector.detection.stream.acquire_ip_updating_lock", AsyncMock(return_value=None)),
            patch("detector.detection.stream.is_ip_updating_locked", AsyncMock(return_value=True)),
            patch("detector.detection.stream._poll_for_concurrent_snapshot", AsyncMock(return_value=polled_payload)),
        ):
            resp = await client.get("/api/v1/detect/stream?ip=8.8.8.8")
            self.assertEqual(resp.status_code, 200)
            chunks = [c.decode("utf-8") if isinstance(c, bytes) else str(c) async for c in resp.streaming_content]

        events = [
            (lines[0].removeprefix("event:").strip(), json.loads(lines[1].removeprefix("data:").strip()))
            for block in "".join(chunks).split("\n\n")
            if (lines := [ln for ln in block.splitlines() if ln.startswith(("event:", "data:"))]) and len(lines) == 2
        ]
        self.assertEqual([name for name, _ in events], ["snapshot", "done"])
        self.assertEqual(events[0][1]["pendingProviders"], [])
        self.assertTrue(events[0][1]["isCached"])
        mocks["proxycheck"].assert_not_awaited()
