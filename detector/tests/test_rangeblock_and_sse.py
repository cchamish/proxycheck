"""Core P0 tests for rangeblock invariants, real-time overrides, auth guards, and SSE streaming."""

import json
from unittest.mock import AsyncMock, patch

import dns.resolver
from asgiref.sync import sync_to_async
from django.db import OperationalError
from django.test import AsyncClient, TestCase, override_settings

from detector.cache import l2_store as l2_cache
from detector.cache import redis_backend as cache_backends
from detector.detection import service as detection_service
from detector.models import RangeblockAggregate
from detector.rangeblock import service as rangeblock_service

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

    async def test_refresh_includes_rangeblock_on_cached_in_progress_and_degraded_paths(self):
        """P0: /api/v1/detect/refresh includes rangeblock on cooldown, in-progress, polled, and degraded returns."""
        expected_rb = {
            **rangeblock_service.build_empty_rangeblock_summary("8.8.8.8"),
            "hasActive": True,
            "localTotal": 1,
            "blockDataDegraded": True,
            "wikis": [{"wiki": "enwiki", "blockCount": 1, "hasActive": True}],
        }
        base_snapshot = {
            "ip": "8.8.8.8",
            "results": [],
            "isCached": True,
            "cacheMeta": {"status": "hit", "layer": "L1"},
        }
        allowed_rl = AsyncMock(return_value=type("RL", (), {"allowed": True})())

        with (
            patch(
                "detector.rangeblock.service.query_rangeblocks_for_ip",
                new_callable=AsyncMock,
                return_value=expected_rb,
            ) as mock_rb,
            patch(
                "detector.cache.quota_telemetry.record_global_request_telemetry",
                new_callable=AsyncMock,
            ),
            patch(
                "detector.cache.quota_telemetry.check_and_consume_refresh_rate_limit",
                allowed_rl,
            ),
        ):
            with (
                self.subTest(path="cooldown_cached"),
                patch.object(detection_service, "is_refresh_on_cooldown", AsyncMock(return_value=True)),
                patch.object(
                    detection_service,
                    "_try_serve_existing_snapshot_for_refresh",
                    AsyncMock(return_value=dict(base_snapshot)),
                ),
            ):
                payload, status, _ = await detection_service.refresh_single_canonical_ip(
                    "8.8.8.8", "session", 0.0, username="ExampleAdmin", is_admin=True, compact=True, wiki="enwiki"
                )
                self.assertEqual(status, 200)
                self.assertEqual(payload.get("rangeblock"), expected_rb)
                mock_rb.assert_awaited_with("8.8.8.8", wiki="enwiki")

            with (
                self.subTest(path="in_progress_cached"),
                patch.object(detection_service, "is_refresh_on_cooldown", AsyncMock(return_value=False)),
                patch.object(detection_service, "acquire_ip_updating_lock", AsyncMock(return_value=None)),
                patch.object(detection_service, "is_ip_updating_locked", AsyncMock(return_value=True)),
                patch.object(
                    detection_service,
                    "_try_serve_existing_snapshot_for_refresh",
                    AsyncMock(return_value=dict(base_snapshot)),
                ),
            ):
                payload, status, _ = await detection_service.refresh_single_canonical_ip(
                    "8.8.8.8", "session", 0.0, username="ExampleAdmin", is_admin=True, wiki="enwiki"
                )
                self.assertEqual(status, 200)
                self.assertEqual(payload.get("rangeblock"), expected_rb)

            with (
                self.subTest(path="in_progress_polled"),
                patch.object(detection_service, "is_refresh_on_cooldown", AsyncMock(return_value=False)),
                patch.object(detection_service, "acquire_ip_updating_lock", AsyncMock(return_value=None)),
                patch.object(detection_service, "is_ip_updating_locked", AsyncMock(return_value=True)),
                patch.object(
                    detection_service, "_try_serve_existing_snapshot_for_refresh", AsyncMock(return_value=None)
                ),
                patch.object(
                    detection_service,
                    "_poll_for_concurrent_snapshot",
                    AsyncMock(return_value=dict(base_snapshot)),
                ),
            ):
                payload, status, _ = await detection_service.refresh_single_canonical_ip(
                    "8.8.8.8", "session", 0.0, username="ExampleAdmin", is_admin=True, wiki="enwiki"
                )
                self.assertEqual(status, 200)
                self.assertEqual(payload.get("rangeblock"), expected_rb)

            with (
                self.subTest(path="degraded_fallback_with_snapshot"),
                patch.object(detection_service, "is_refresh_on_cooldown", AsyncMock(return_value=False)),
                patch.object(detection_service, "acquire_ip_updating_lock", AsyncMock(return_value="tok")),
                patch.object(detection_service, "release_ip_updating_lock", AsyncMock()),
                patch.object(detection_service, "_try_read_l1_snapshot", AsyncMock(return_value=None)),
                patch.object(
                    detection_service,
                    "_execute_detection_with_cache",
                    AsyncMock(return_value={**base_snapshot, "_rawCleanResults": []}),
                ),
                patch.object(
                    detection_service,
                    "_safe_l2_amerge_snapshot",
                    AsyncMock(
                        return_value=l2_cache.L2MergeResult(
                            snapshot=dict(base_snapshot),
                            saved=False,
                            fetched_at=None,
                            valid_commercial_count=0,
                            has_degraded_sources=True,
                            degraded_fallback=True,
                        )
                    ),
                ),
                patch.object(detection_service, "set_swr_backoff", AsyncMock()),
                patch.object(
                    detection_service,
                    "_rehydrate_snapshot_payload",
                    AsyncMock(
                        return_value={
                            **base_snapshot,
                            "cacheMeta": {"status": "stale", "degradedRefreshFallback": True},
                        }
                    ),
                ),
            ):
                payload, status, _ = await detection_service.refresh_single_canonical_ip(
                    "8.8.8.8", "session", 0.0, username="ExampleAdmin", is_admin=True, wiki="enwiki"
                )
                self.assertEqual(status, 200)
                self.assertEqual(payload.get("rangeblock"), expected_rb)
                self.assertTrue(payload["cacheMeta"]["degradedRefreshFallback"])

            with (
                self.subTest(path="degraded_fallback_without_snapshot"),
                patch.object(detection_service, "is_refresh_on_cooldown", AsyncMock(return_value=False)),
                patch.object(detection_service, "acquire_ip_updating_lock", AsyncMock(return_value="tok")),
                patch.object(detection_service, "release_ip_updating_lock", AsyncMock()),
                patch.object(detection_service, "_try_read_l1_snapshot", AsyncMock(return_value=None)),
                patch.object(
                    detection_service,
                    "_execute_detection_with_cache",
                    AsyncMock(return_value={**base_snapshot, "_rawCleanResults": []}),
                ),
                patch.object(
                    detection_service,
                    "_safe_l2_amerge_snapshot",
                    AsyncMock(
                        return_value=l2_cache.L2MergeResult(
                            snapshot=None,
                            saved=False,
                            fetched_at=None,
                            valid_commercial_count=0,
                            has_degraded_sources=True,
                            degraded_fallback=True,
                        )
                    ),
                ),
                patch.object(detection_service, "set_swr_backoff", AsyncMock()),
            ):
                payload, status, _ = await detection_service.refresh_single_canonical_ip(
                    "8.8.8.8", "session", 0.0, username="ExampleAdmin", is_admin=True, wiki="enwiki"
                )
                self.assertEqual(status, 200)
                self.assertEqual(payload.get("rangeblock"), expected_rb)
                self.assertTrue(payload["cacheMeta"]["degradedRefreshFallback"])

            with (
                self.subTest(path="fresh_refresh"),
                patch.object(detection_service, "is_refresh_on_cooldown", AsyncMock(return_value=False)),
                patch.object(detection_service, "acquire_ip_updating_lock", AsyncMock(return_value="tok")),
                patch.object(detection_service, "release_ip_updating_lock", AsyncMock()),
                patch.object(detection_service, "_try_read_l1_snapshot", AsyncMock(return_value=None)),
                patch.object(
                    detection_service,
                    "_execute_detection_with_cache",
                    AsyncMock(return_value={**base_snapshot, "_rawCleanResults": []}),
                ),
                patch.object(
                    detection_service,
                    "_safe_l2_amerge_snapshot",
                    AsyncMock(
                        return_value=l2_cache.L2MergeResult(
                            snapshot=None,
                            saved=True,
                            fetched_at="2026-11-26T00:00:00+00:00",
                            valid_commercial_count=1,
                            has_degraded_sources=False,
                            degraded_fallback=False,
                        )
                    ),
                ),
                patch.object(detection_service, "set_cached_ip_snapshot", AsyncMock()),
                patch.object(detection_service, "set_refresh_cooldown", AsyncMock()),
            ):
                payload, status, _ = await detection_service.refresh_single_canonical_ip(
                    "8.8.8.8", "session", 0.0, username="ExampleAdmin", is_admin=True, compact=True, wiki="enwiki"
                )
                self.assertEqual(status, 200)
                self.assertEqual(payload.get("rangeblock"), expected_rb)
                self.assertTrue(payload["rangeblock"]["blockDataDegraded"])

            mock_rb.reset_mock()
            denied_rl = AsyncMock(
                return_value=type("RL", (), {"allowed": False, "reason": "user_rpm", "retry_after_seconds": 30})()
            )
            mock_serve = AsyncMock(return_value=dict(base_snapshot))
            with (
                self.subTest(path="cooldown_cached_rate_limited"),
                patch.object(detection_service, "is_refresh_on_cooldown", AsyncMock(return_value=True)),
                patch.object(
                    detection_service,
                    "_try_serve_existing_snapshot_for_refresh",
                    mock_serve,
                ),
                patch("detector.cache.quota_telemetry.check_and_consume_endpoint_rate_limit", denied_rl),
            ):
                payload, status, headers = await detection_service.refresh_single_canonical_ip(
                    "8.8.8.8", "session", 0.0, username="ExampleAdmin", is_admin=True, wiki="enwiki"
                )
                self.assertEqual(status, 429)
                self.assertEqual(payload["error"], "rate_limited")
                self.assertEqual(headers.get("Retry-After"), "30")
                mock_serve.assert_not_awaited()
                mock_rb.assert_not_awaited()
