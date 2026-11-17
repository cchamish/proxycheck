"""Tests for dual-layer L1 and L2 90-day SWR orchestration, refresh endpoint, and rate guards."""

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import dns.resolver
from django.test import TestCase, override_settings

from detector import cache_backends, detection_service, l2_cache, quota_telemetry, views
from detector.adapters import adapt_ipsum_drop, adapt_stopforumspam
from detector.models import IpIntelligenceCache

from .helpers import (
    MAXMIND_STUB,
    TEST_UPSTREAM_SECRETS,
    _BatchingFakeRedis,
    _login_authorised,
    start_non_dnsbl_provider_stubs,
)


def _build_provider_row(
    provider: str,
    *,
    status: str = "200 OK",
    status_code: int | None = 200,
    usage: str = "isp",
    high_risk_flag: str | None = None,
) -> dict:
    flags = (
        [{"label": high_risk_flag, "isHighRisk": True}]
        if high_risk_flag
        else [{"label": "No Flags", "isHighRisk": False}]
    )
    return {
        "provider": provider,
        "status": status,
        "statusCode": status_code,
        "asn": "AS15169",
        "isp": "Example Residential ISP",
        "organisation": "Example Residential ISP",
        "location": "United States",
        "usageType": usage,
        "countryCode": "US",
        "securityFlags": flags,
        "rawJson": {"provider": provider, "sample": True},
    }


def _seed_l2_record(ip: str, *, age_days: int, mode: str = "full") -> str:
    fetched_dt = datetime.now(timezone.utc) - timedelta(days=age_days)
    rows = [
        _build_provider_row("Cloudflare Radar"),
        _build_provider_row("AbuseIPDB"),
        _build_provider_row("IPData"),
        _build_provider_row("IPRegistry"),
        _build_provider_row("Proxycheck"),
        _build_provider_row("DShield"),
    ]
    res = l2_cache.merge_and_upsert_l2_snapshot(
        ip,
        {
            "ip": ip,
            "queryMode": mode,
            "ptrHostname": "cpe-pool.example.net",
            "bgpPrefix": "94.140.14.0/24",
            "results": rows,
        },
        query_mode=mode,
        now_dt=fetched_dt,
    )
    assert res.saved and res.fetched_at is not None
    return res.fetched_at


class DualLayerSwrOrchestrationTests(TestCase):
    """Tests L1 and L2 hit semantics, timestamp preservation, offline rehydration, and SWR flags."""

    def setUp(self):
        detection_service._ip_detect_inflight.clear()
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)
        _login_authorised(self)

    def tearDown(self):
        detection_service._ip_detect_inflight.clear()

    def test_l2_fresh_hit_backfills_l1_preserving_original_fetched_at_and_rehydrates_offline_dbs(self):
        target_ip = "94.140.14.14"
        original_fetched_at = _seed_l2_record(target_ip, age_days=45)
        fake_redis = _BatchingFakeRedis()
        stubs = start_non_dnsbl_provider_stubs(
            self,
            overrides={"maxmind": dict(MAXMIND_STUB)},
            row_builder=_build_provider_row,
        )

        with patch("detector.cache_backends.redis_client", fake_redis):
            l2_resp = self.client.get(f"/api/v1/detect?ip={target_ip}")
            l1_resp = self.client.get(f"/api/v1/detect?ip={target_ip}")

        self.assertEqual(l2_resp.status_code, 200)
        l2_payload = l2_resp.json()
        self.assertTrue(l2_payload["isCached"])
        self.assertEqual(l2_payload["fetchedAt"], original_fetched_at)
        self.assertEqual(l2_payload["cacheMeta"]["layer"], "L2")
        self.assertEqual(l2_payload["cacheMeta"]["status"], "hit")
        self.assertFalse(l2_payload["cacheMeta"]["isStale"])
        self.assertFalse(l2_payload["cacheMeta"]["shouldAutoRefresh"])
        self.assertGreaterEqual(l2_payload["cacheMeta"]["ageSeconds"], 45 * 86400 - 5)

        # Online commercial providers must never be called on L2 or L1 hits
        stubs["ipdata"].assert_not_awaited()
        stubs["proxycheck"].assert_not_awaited()

        self.assertEqual(l1_resp.status_code, 200)
        l1_payload = l1_resp.json()
        self.assertEqual(l1_payload["cacheMeta"]["layer"], "L1")
        self.assertEqual(l1_payload["fetchedAt"], original_fetched_at)
        self.assertEqual(l1_payload["cacheMeta"]["fetchedAt"], original_fetched_at)
        self.assertGreaterEqual(l1_payload["cacheMeta"]["ageSeconds"], 45 * 86400 - 5)

        # Updating local offline intelligence on disk rehydrates immediately and triggers recommendFreshRecheck
        recent_iso = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        stubs["ipsum_drop"].return_value = adapt_ipsum_drop({"ipsumScore": 4, "isIpsumListed": True})
        stubs["stopforumspam"].return_value = adapt_stopforumspam(
            {"success": 1, "ip": {"appears": 1, "frequency": 9, "lastseen": recent_iso}},
            status_code=200,
        )
        with (
            patch("detector.cache_backends.redis_client", fake_redis),
            patch("detector.detection_service._current_offline_provider_signature", return_value="updated-sig"),
        ):
            rehydrated_resp = self.client.get(f"/api/v1/detect?ip={target_ip}")

        rehydrated_data = rehydrated_resp.json()
        self.assertTrue(rehydrated_data["suspectedResidentialProxy"])
        self.assertEqual(rehydrated_data["arbitrationVerdict"], "Suspected Residential Proxy / Compromised Host")
        self.assertTrue(rehydrated_data["cacheMeta"]["recommendFreshRecheck"])

    def test_stale_swr_flags_lock_backoff_and_commercial_daily_quota_guard(self):
        stale_120_ip = "208.67.222.222"
        stale_195_ip = "208.67.220.220"
        _seed_l2_record(stale_120_ip, age_days=120)
        _seed_l2_record(stale_195_ip, age_days=195)
        fake_redis = _BatchingFakeRedis()
        start_non_dnsbl_provider_stubs(
            self,
            overrides={"maxmind": dict(MAXMIND_STUB)},
            row_builder=_build_provider_row,
        )

        with patch("detector.cache_backends.redis_client", fake_redis):
            stale_resp = self.client.get(f"/api/v1/detect?ip={stale_120_ip}")
        stale_meta = stale_resp.json()["cacheMeta"]
        self.assertEqual(stale_meta["status"], "stale")
        self.assertTrue(stale_meta["isStale"])
        self.assertTrue(stale_meta["shouldAutoRefresh"])
        self.assertFalse(stale_meta["refreshInProgress"])

        # Active updating lock suppresses shouldAutoRefresh and surfaces refreshInProgress
        fake_redis.strings[cache_backends.updating_lock_key(stale_120_ip)] = "worker-lock-token"
        with patch("detector.cache_backends.redis_client", fake_redis):
            locked_resp = self.client.get(f"/api/v1/detect?ip={stale_120_ip}")
        locked_meta = locked_resp.json()["cacheMeta"]
        self.assertTrue(locked_meta["refreshInProgress"])
        self.assertFalse(locked_meta["shouldAutoRefresh"])
        fake_redis.strings.pop(cache_backends.updating_lock_key(stale_120_ip), None)

        # Active SWR backoff suppresses shouldAutoRefresh for 30 minutes
        fake_redis.strings[cache_backends.swr_backoff_key(stale_120_ip)] = "1"
        with patch("detector.cache_backends.redis_client", fake_redis):
            backoff_resp = self.client.get(f"/api/v1/detect?ip={stale_120_ip}")
        self.assertFalse(backoff_resp.json()["cacheMeta"]["shouldAutoRefresh"])
        fake_redis.strings.pop(cache_backends.swr_backoff_key(stale_120_ip), None)

        # Commercial daily quota < 15% pauses auto-refresh for < 180d records while keeping >= 180d active
        only_abuse_configured = {**{k: "" for k in TEST_UPSTREAM_SECRETS}, "ABUSEIPDB_API_KEY": "abuse-key"}
        with (
            override_settings(**only_abuse_configured, ABUSEIPDB_DAILY_LIMIT=100),
            patch.dict(os.environ, only_abuse_configured),
            patch("detector.cache_backends.redis_client", fake_redis),
        ):
            day_key = quota_telemetry._quota_daily_key("abuseipdb", datetime.now(timezone.utc))
            fake_redis.strings[day_key] = "90"
            suppressed_resp = self.client.get(f"/api/v1/detect?ip={stale_120_ip}")
            ancient_resp = self.client.get(f"/api/v1/detect?ip={stale_195_ip}")

        self.assertFalse(suppressed_resp.json()["cacheMeta"]["shouldAutoRefresh"])
        self.assertTrue(ancient_resp.json()["cacheMeta"]["shouldAutoRefresh"])

    async def test_concurrent_miss_polls_distributed_updating_lock_without_duplicate_upstream_calls(self):
        target_ip = "149.112.112.112"
        fake_redis = _BatchingFakeRedis()
        stubs = start_non_dnsbl_provider_stubs(
            self,
            overrides={"maxmind": dict(MAXMIND_STUB)},
            row_builder=_build_provider_row,
        )

        with patch("detector.cache_backends.redis_client", fake_redis):
            fake_redis.strings[cache_backends.updating_lock_key(target_ip)] = "other-worker"

            async def _populate_from_peer_worker():
                await asyncio.sleep(0.05)
                await cache_backends.set_cached_ip_snapshot(
                    target_ip,
                    {
                        "ip": target_ip,
                        "fetchedAt": "2026-11-17T10:00:00+00:00",
                        "ptrHostname": "dns.quad9.net",
                        "results": [_build_provider_row("IPData"), _build_provider_row("Proxycheck")],
                    },
                    mode="full",
                )
                fake_redis.strings.pop(cache_backends.updating_lock_key(target_ip), None)

            with patch.object(detection_service, "_LOCK_POLL_INTERVAL_SECONDS", 0.02):
                _, result = await asyncio.gather(
                    _populate_from_peer_worker(),
                    detection_service.detect_single_canonical_ip(target_ip, "session", 0.0),
                )

        self.assertEqual(result["cacheMeta"]["layer"], "L1")
        self.assertEqual(result["ptrHostname"], "dns.quad9.net")
        stubs["ipdata"].assert_not_awaited()


class RefreshEndpointAndRateGuardTests(TestCase):
    """Tests POST /api/v1/detect/refresh authentication, CORS, cooldowns, rate limits, and non-degrading merge."""

    def setUp(self):
        detection_service._ip_detect_inflight.clear()
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)

    def tearDown(self):
        detection_service._ip_detect_inflight.clear()

    def test_refresh_endpoint_enforces_auth_cors_methods_and_input_validation(self):
        preflight = self.client.options(
            "/api/v1/detect/refresh",
            HTTP_ORIGIN="https://zh.wikipedia.org",
        )
        self.assertEqual(preflight.status_code, 204)
        self.assertEqual(preflight.headers.get("Access-Control-Allow-Origin"), "https://zh.wikipedia.org")
        self.assertIn("POST", preflight.headers.get("Access-Control-Allow-Methods", ""))

        self.assertEqual(self.client.get("/api/v1/detect/refresh").status_code, 405)
        self.assertEqual(
            self.client.post(
                "/api/v1/detect/refresh",
                data=json.dumps({"ip": "8.8.8.8"}),
                content_type="application/json",
            ).status_code,
            401,
        )

        _login_authorised(self)
        for bad_body, expected_error in (
            ("{bad-json", "invalid_refresh"),
            (json.dumps(["8.8.8.8"]), "invalid_refresh"),
            (json.dumps({}), "invalid_ip"),
            (json.dumps({"ip": "999.999.999.999"}), "invalid_ip"),
        ):
            with self.subTest(body=bad_body):
                bad_resp = self.client.post("/api/v1/detect/refresh/", data=bad_body, content_type="application/json")
                self.assertEqual(bad_resp.status_code, 400)
                self.assertEqual(bad_resp.json()["error"], expected_error)

        loopback_resp = self.client.post(
            "/api/v1/detect/refresh",
            data=json.dumps({"ip": "127.0.0.1"}),
            content_type="application/json",
        )
        self.assertEqual(loopback_resp.status_code, 200)
        self.assertEqual(loopback_resp.json()["cacheMeta"]["status"], "bypassed")

    def test_refresh_updates_l1_and_l2_respects_60s_cooldown_and_handles_active_lock(self):
        target_ip = "149.112.112.112"
        old_fetched_at = _seed_l2_record(target_ip, age_days=120)
        fake_redis = _BatchingFakeRedis()
        stubs = start_non_dnsbl_provider_stubs(
            self,
            overrides={"maxmind": dict(MAXMIND_STUB)},
            row_builder=_build_provider_row,
        )
        gadget_token = views.issue_gadget_token("GadgetPatroller")

        # When another worker already holds the updating lock, return existing snapshot with refreshInProgress
        with patch("detector.cache_backends.redis_client", fake_redis):
            fake_redis.strings[cache_backends.updating_lock_key(target_ip)] = "peer-lock"
            in_prog_resp = self.client.post(
                "/api/v1/detect/refresh",
                data=json.dumps({"ip": target_ip}),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {gadget_token}",
                HTTP_ORIGIN="https://en.wikipedia.org",
            )
            fake_redis.strings.pop(cache_backends.updating_lock_key(target_ip), None)

        self.assertEqual(in_prog_resp.status_code, 200)
        self.assertEqual(in_prog_resp.headers.get("Access-Control-Allow-Origin"), "https://en.wikipedia.org")
        self.assertTrue(in_prog_resp.json()["cacheMeta"]["refreshInProgress"])
        self.assertFalse(in_prog_resp.json()["cacheMeta"]["shouldAutoRefresh"])
        stubs["ipdata"].assert_not_awaited()

        # Unlocked refresh updates L2 and L1, resets ageSeconds to 0, and sets 60s refresh cooldown
        with patch("detector.cache_backends.redis_client", fake_redis):
            fresh_resp = self.client.post(
                "/api/v1/detect/refresh",
                data=json.dumps({"ip": target_ip}),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {gadget_token}",
            )
            self.assertEqual(fresh_resp.status_code, 200)
            self.assertEqual(fresh_resp.headers.get("Cache-Control"), "private, no-cache")
            fresh_data = fresh_resp.json()
            self.assertNotEqual(fresh_data["fetchedAt"], old_fetched_at)
            self.assertEqual(fresh_data["cacheMeta"]["layer"], "upstream")
            self.assertEqual(fresh_data["cacheMeta"]["ageSeconds"], 0)
            self.assertFalse(fresh_data["cacheMeta"]["isStale"])
            self.assertEqual(stubs["ipdata"].await_count, 1)

            # Immediate duplicate click within 60s returns idempotent 200 with zero extra upstream calls
            cooldown_resp = self.client.post(
                "/api/v1/detect/refresh/",
                data=json.dumps({"ip": target_ip, "compact": True}),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {gadget_token}",
            )

        self.assertEqual(cooldown_resp.status_code, 200)
        self.assertEqual(stubs["ipdata"].await_count, 1)
        for row in cooldown_resp.json()["results"]:
            self.assertNotIn("rawJson", row)

    def test_degraded_refresh_preserves_l2_history_and_sets_1800s_swr_backoff(self):
        target_ip = "94.140.15.15"
        original_fetched_at = _seed_l2_record(target_ip, age_days=110)
        fake_redis = _BatchingFakeRedis()
        _login_authorised(self)

        def _failing_commercial(name: str) -> dict:
            if name in ("AbuseIPDB", "IPData", "IPRegistry", "IP2Location", "GetIPIntel", "Proxycheck", "IPHub", "IPHunter"):
                return _build_provider_row(name, status="503 Error", status_code=503)
            return _build_provider_row(name)

        start_non_dnsbl_provider_stubs(
            self,
            overrides={"maxmind": dict(MAXMIND_STUB)},
            row_builder=_failing_commercial,
        )

        with patch("detector.cache_backends.redis_client", fake_redis):
            resp = self.client.post(
                "/api/v1/detect/refresh",
                data=json.dumps({"ip": target_ip}),
                content_type="application/json",
            )

        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["fetchedAt"], original_fetched_at)
        self.assertTrue(payload["cacheMeta"]["degradedRefreshFallback"])
        self.assertFalse(payload["cacheMeta"]["shouldAutoRefresh"])
        backoff_key = cache_backends.swr_backoff_key(target_ip)
        self.assertIn(backoff_key, fake_redis.strings)
        self.assertEqual(fake_redis.ttls.get(backoff_key), 1800)

        db_row = IpIntelligenceCache.objects.get(canonical_ip=target_ip)
        self.assertEqual(db_row.fetched_at.astimezone(timezone.utc).isoformat(), original_fetched_at)
        self.assertGreaterEqual(db_row.valid_commercial_count, 4)

    def test_per_user_hmac_rate_limits_admin_exemption_and_global_refresh_limit(self):
        fake_redis = _BatchingFakeRedis()
        start_non_dnsbl_provider_stubs(
            self,
            overrides={"maxmind": dict(MAXMIND_STUB)},
            row_builder=_build_provider_row,
        )
        reviewer_token = views.issue_gadget_token("ReviewerAlpha")
        admin_token = views.issue_gadget_token("AllowlistedMaintainer")

        with (
            override_settings(
                ALLOWED_WIKI_USERS="AllowlistedMaintainer",
                REFRESH_USER_RPM_LIMIT=2,
                REFRESH_USER_RPH_LIMIT=60,
                REFRESH_GLOBAL_RPM_LIMIT=4,
            ),
            patch.dict(os.environ, {"ALLOWED_WIKI_USERS": "AllowlistedMaintainer"}),
            patch("detector.cache_backends.redis_client", fake_redis),
        ):
            for idx in range(2):
                ok_resp = self.client.post(
                    "/api/v1/detect/refresh",
                    data=json.dumps({"ip": f"8.8.8.{idx + 1}"}),
                    content_type="application/json",
                    HTTP_AUTHORIZATION=f"Bearer {reviewer_token}",
                )
                self.assertEqual(ok_resp.status_code, 200)

            user_limited = self.client.post(
                "/api/v1/detect/refresh",
                data=json.dumps({"ip": "8.8.8.9"}),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {reviewer_token}",
            )
            self.assertEqual(user_limited.status_code, 429)
            self.assertEqual(user_limited.json()["reason"], "user_rpm")
            self.assertIsNotNone(user_limited.headers.get("Retry-After"))
            self.assertFalse(any("ReviewerAlpha" in k for k in fake_redis.strings))

            # Allowlisted administrator bypasses per-user cap until global cap (4/min) is reached
            for idx in range(2):
                admin_ok = self.client.post(
                    "/api/v1/detect/refresh",
                    data=json.dumps({"ip": f"1.1.1.{idx + 1}"}),
                    content_type="application/json",
                    HTTP_AUTHORIZATION=f"Bearer {admin_token}",
                )
                self.assertEqual(admin_ok.status_code, 200)

            global_limited = self.client.post(
                "/api/v1/detect/refresh",
                data=json.dumps({"ip": "1.1.1.9"}),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {admin_token}",
            )
            self.assertEqual(global_limited.status_code, 429)
            self.assertEqual(global_limited.json()["reason"], "global_rpm")

        ns = cache_backends.get_redis_namespace()
        global_tel_key = next(k for k in fake_redis.hashes if k.startswith(f"{ns}:telemetry:global:day:"))
        self.assertEqual(fake_redis.hashes[global_tel_key].get("refresh_ok"), "4")
        self.assertEqual(fake_redis.hashes[global_tel_key].get("refresh_rate_limited"), "2")


class BatchBulkPrefetchAndSwrGuardTests(TestCase):
    """Tests single MGET and single WHERE IN batch prefetching and strict shouldAutoRefresh suppression."""

    def setUp(self):
        detection_service._ip_detect_inflight.clear()
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)
        _login_authorised(self)

    def test_batch_executes_single_mget_and_single_l2_bulk_query_and_forces_auto_refresh_false(self):
        l1_ip = "8.8.8.8"
        l2_fresh_ip = "94.140.14.14"
        l2_stale_ip = "208.67.222.222"
        miss_ip = "1.1.1.1"
        _seed_l2_record(l2_fresh_ip, age_days=10)
        _seed_l2_record(l2_stale_ip, age_days=130)

        fake_redis = _BatchingFakeRedis()
        start_non_dnsbl_provider_stubs(
            self,
            overrides={"maxmind": dict(MAXMIND_STUB)},
            row_builder=_build_provider_row,
        )

        with patch("detector.cache_backends.redis_client", fake_redis):
            asyncio.run(
                cache_backends.set_cached_ip_snapshot(
                    l1_ip,
                    {
                        "ip": l1_ip,
                        "fetchedAt": (datetime.now(timezone.utc) - timedelta(days=125)).isoformat(),
                        "queryMode": "full",
                        "results": [_build_provider_row("IPData"), _build_provider_row("Proxycheck")],
                    },
                    mode="full",
                )
            )
            with (
                patch(
                    "detector.detection_service.get_cached_ip_snapshots_bulk",
                    wraps=cache_backends.get_cached_ip_snapshots_bulk,
                ) as spy_l1_bulk,
                patch(
                    "detector.l2_cache.aget_ip_snapshots_bulk",
                    wraps=l2_cache.aget_ip_snapshots_bulk,
                ) as spy_l2_bulk,
            ):
                resp = self.client.post(
                    "/api/v1/detect/batch",
                    data=json.dumps(
                        {
                            "ips": [l1_ip, l2_fresh_ip, l2_stale_ip, miss_ip, "127.0.0.1"],
                            "mode": "full",
                        }
                    ),
                    content_type="application/json",
                )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(spy_l1_bulk.await_count, 1)
        self.assertEqual(spy_l2_bulk.await_count, 1)
        self.assertEqual(set(spy_l2_bulk.await_args.args[0]), {l2_fresh_ip, l2_stale_ip, miss_ip})

        results = resp.json()["results"]
        self.assertEqual(results[l1_ip]["cacheMeta"]["layer"], "L1")
        self.assertTrue(results[l1_ip]["cacheMeta"]["isStale"])
        self.assertEqual(results[l2_fresh_ip]["cacheMeta"]["layer"], "L2")
        self.assertFalse(results[l2_fresh_ip]["cacheMeta"]["isStale"])
        self.assertEqual(results[l2_stale_ip]["cacheMeta"]["layer"], "L2")
        self.assertTrue(results[l2_stale_ip]["cacheMeta"]["isStale"])
        self.assertEqual(results[miss_ip]["cacheMeta"]["layer"], "upstream")

        for ip_key, item in results.items():
            with self.subTest(ip=ip_key):
                self.assertFalse(item["cacheMeta"]["shouldAutoRefresh"])
