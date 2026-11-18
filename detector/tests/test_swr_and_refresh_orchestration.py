"""Tests for dual-layer L1 and L2 90-day SWR orchestration, refresh endpoint, and rate guards."""

import asyncio
import io
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import dns.resolver
from django.core.management import call_command
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from detector import cache_backends, cidr_attribution, detection_service, l2_cache, quota_telemetry, views
from detector.adapters import adapt_ipsum_drop, adapt_shodan_internetdb, adapt_stopforumspam, adapt_x4bnet_vpn
from detector.binary_prefix_index import compile_binary_prefix_index
from detector.models import IpIntelligenceCache
from detector.provider_registry import (
    L1_ONLY_PROVIDERS,
    OFFLINE_REHYDRATE_PROVIDERS,
    PROVIDER_REGISTRY,
)

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
            if name in (
                "AbuseIPDB",
                "IPData",
                "IPRegistry",
                "IP2Location",
                "GetIPIntel",
                "Proxycheck",
                "IPHub",
                "IPHunter",
            ):
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

    def test_batch_light_and_full_modes_enforce_single_sql_select_bulk_mget_and_no_auto_refresh(self):
        for batch_mode in ("light", "full"):
            with self.subTest(mode=batch_mode):
                IpIntelligenceCache.objects.all().delete()
                detection_service._ip_detect_inflight.clear()

                l1_fresh_ip = "8.8.4.4"
                l1_stale_ip = "9.9.9.9"
                l2_fresh_ip = "94.140.14.15"
                l2_stale_ip = "208.67.222.123"
                cold_v4_ip = "1.0.0.1"
                cold_v6_expanded = "2606:4700:4700:0000:0000:0000:0000:1111"
                cold_v6_canon = "2606:4700:4700::1111"

                _seed_l2_record(l2_fresh_ip, age_days=12, mode="full")
                _seed_l2_record(l2_stale_ip, age_days=130, mode="full")

                fake_redis = _BatchingFakeRedis()
                start_non_dnsbl_provider_stubs(
                    self,
                    overrides={"maxmind": dict(MAXMIND_STUB)},
                    row_builder=_build_provider_row,
                )

                now_utc = datetime.now(timezone.utc)
                with patch("detector.cache_backends.redis_client", fake_redis):
                    asyncio.run(
                        cache_backends.set_cached_ip_snapshot(
                            l1_fresh_ip,
                            {
                                "ip": l1_fresh_ip,
                                "fetchedAt": (now_utc - timedelta(days=5)).isoformat(),
                                "queryMode": "full",
                                "results": [_build_provider_row("IPData"), _build_provider_row("Proxycheck")],
                            },
                            mode="full",
                        )
                    )
                    asyncio.run(
                        cache_backends.set_cached_ip_snapshot(
                            l1_stale_ip,
                            {
                                "ip": l1_stale_ip,
                                "fetchedAt": (now_utc - timedelta(days=125)).isoformat(),
                                "queryMode": "full",
                                "results": [_build_provider_row("IPData"), _build_provider_row("Proxycheck")],
                            },
                            mode="full",
                        )
                    )
                    fake_redis.get_calls.clear()
                    fake_redis.mget_calls.clear()

                    with CaptureQueriesContext(connection) as sql_ctx:
                        resp = self.client.post(
                            "/api/v1/detect/batch",
                            data=json.dumps(
                                {
                                    "ips": [
                                        l1_fresh_ip,
                                        l1_stale_ip,
                                        l2_fresh_ip,
                                        l2_stale_ip,
                                        cold_v4_ip,
                                        cold_v6_expanded,
                                        cold_v6_canon,
                                        "10.0.0.1",
                                    ],
                                    "mode": batch_mode,
                                }
                            ),
                            content_type="application/json",
                        )

                self.assertEqual(resp.status_code, 200)
                l2_selects = [
                    q["sql"]
                    for q in sql_ctx.captured_queries
                    if "detector_ip_cache" in q["sql"] and q["sql"].lstrip().upper().startswith("SELECT")
                ]
                if batch_mode == "light":
                    self.assertEqual(len(l2_selects), 1)
                else:
                    # One bulk WHERE IN prefetch plus upserts for the two cold public IPs
                    where_in_selects = [sql for sql in l2_selects if " IN " in sql.upper()]
                    self.assertEqual(len(where_in_selects), 1)

                snap_mgets = [
                    batch_keys for batch_keys in fake_redis.mget_calls if any(":snap:" in key for key in batch_keys)
                ]
                expected_snap_mgets = 2 if batch_mode == "light" else 1
                self.assertEqual(len(snap_mgets), expected_snap_mgets)
                self.assertEqual(len(snap_mgets[0]), 6)
                snap_single_gets = [key for key in fake_redis.get_calls if ":snap:" in key]
                self.assertEqual(snap_single_gets, [])

                payload = resp.json()
                self.assertEqual(payload["inputMap"][cold_v6_expanded], cold_v6_canon)
                results = payload["results"]
                self.assertEqual(results[l1_fresh_ip]["cacheMeta"]["layer"], "L1")
                self.assertFalse(results[l1_fresh_ip]["cacheMeta"]["isStale"])
                self.assertEqual(results[l1_stale_ip]["cacheMeta"]["layer"], "L1")
                self.assertTrue(results[l1_stale_ip]["cacheMeta"]["isStale"])
                self.assertEqual(results[l2_fresh_ip]["cacheMeta"]["layer"], "L2")
                self.assertFalse(results[l2_fresh_ip]["cacheMeta"]["isStale"])
                self.assertEqual(results[l2_stale_ip]["cacheMeta"]["layer"], "L2")
                self.assertTrue(results[l2_stale_ip]["cacheMeta"]["isStale"])
                self.assertEqual(results[cold_v4_ip]["cacheMeta"]["layer"], "upstream")
                self.assertEqual(results[cold_v6_canon]["cacheMeta"]["layer"], "upstream")
                self.assertEqual(results["10.0.0.1"]["cacheMeta"]["layer"], "bypassed")

                for ip_key, item in results.items():
                    with self.subTest(mode=batch_mode, ip=ip_key):
                        self.assertFalse(item["cacheMeta"]["shouldAutoRefresh"])


class FourBranchStateMachineAndComplianceMatrixTests(TestCase):
    """Table-driven verification of four-branch cache state transitions, compliance stripping, and merge safety."""

    def setUp(self):
        detection_service._ip_detect_inflight.clear()
        cidr_attribution.clear_offline_intelligence_caches()
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)
        self.addCleanup(cidr_attribution.clear_offline_intelligence_caches)
        _login_authorised(self)

    def tearDown(self):
        detection_service._ip_detect_inflight.clear()

    def test_four_branch_detect_state_machine_and_backfill_timestamp_fidelity(self):
        fake_redis = _BatchingFakeRedis()
        stubs = start_non_dnsbl_provider_stubs(
            self,
            overrides={"maxmind": dict(MAXMIND_STUB)},
            row_builder=_build_provider_row,
        )

        direct_l1_ip = "1.1.1.2"
        l1_seeded_iso = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        with patch("detector.cache_backends.redis_client", fake_redis):
            asyncio.run(
                cache_backends.set_cached_ip_snapshot(
                    direct_l1_ip,
                    {
                        "ip": direct_l1_ip,
                        "fetchedAt": l1_seeded_iso,
                        "queryMode": "full",
                        "ptrHostname": "one.one.one.one",
                        "results": [_build_provider_row("IPData"), _build_provider_row("Proxycheck")],
                    },
                    mode="full",
                )
            )

        l2_fresh_45_iso = _seed_l2_record("94.140.14.45", age_days=45)
        l2_fresh_89_iso = _seed_l2_record("94.140.14.89", age_days=89)
        l2_stale_91_iso = _seed_l2_record("94.140.14.91", age_days=91)
        l2_stale_140_iso = _seed_l2_record("94.140.14.140", age_days=140)

        matrix_cases = (
            ("cold_cache_miss", "1.1.1.3", None, 0, "upstream", "miss", False, False, False, 1),
            ("direct_l1_hit_30d", direct_l1_ip, l1_seeded_iso, 30, "L1", "hit", True, False, False, 0),
            ("l2_fresh_45d", "94.140.14.45", l2_fresh_45_iso, 45, "L2", "hit", True, False, False, 0),
            ("l2_fresh_boundary_89d", "94.140.14.89", l2_fresh_89_iso, 89, "L2", "hit", True, False, False, 0),
            ("l2_stale_boundary_91d", "94.140.14.91", l2_stale_91_iso, 91, "L2", "stale", True, True, True, 0),
            ("l2_stale_140d", "94.140.14.140", l2_stale_140_iso, 140, "L2", "stale", True, True, True, 0),
        )

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.cache_backends.redis_client", fake_redis),
        ):
            for (
                case_label,
                ip_addr,
                expected_iso,
                expected_min_days,
                expected_first_layer,
                expected_first_status,
                expected_first_cached,
                expected_stale,
                expected_auto_refresh,
                expected_upstream_delta,
            ) in matrix_cases:
                with self.subTest(branch=case_label):
                    before_calls = stubs["ipdata"].await_count
                    first_resp = self.client.get(f"/api/v1/detect?ip={ip_addr}")
                    self.assertEqual(first_resp.status_code, 200)
                    self.assertEqual(first_resp.headers.get("Cache-Control"), "private, no-cache")

                    first_data = first_resp.json()
                    first_meta = first_data["cacheMeta"]
                    self.assertEqual(first_data["isCached"], expected_first_cached)
                    self.assertEqual(first_meta["layer"], expected_first_layer)
                    self.assertEqual(first_meta["status"], expected_first_status)
                    self.assertEqual(first_meta["isStale"], expected_stale)
                    self.assertEqual(first_meta["shouldAutoRefresh"], expected_auto_refresh)
                    self.assertEqual(stubs["ipdata"].await_count - before_calls, expected_upstream_delta)

                    if expected_iso is None:
                        self.assertEqual(first_meta["ageSeconds"], 0)
                        preserved_iso = first_data["fetchedAt"]
                    else:
                        self.assertEqual(first_data["fetchedAt"], expected_iso)
                        self.assertEqual(first_meta["fetchedAt"], expected_iso)
                        self.assertGreaterEqual(first_meta["ageSeconds"], expected_min_days * 86400 - 5)
                        preserved_iso = expected_iso

                    # Second GET must hit L1 while keeping original fetchedAt, ageSeconds, and staleness intact
                    second_resp = self.client.get(f"/api/v1/detect?ip={ip_addr}")
                    self.assertEqual(second_resp.status_code, 200)
                    second_data = second_resp.json()
                    second_meta = second_data["cacheMeta"]
                    self.assertTrue(second_data["isCached"])
                    self.assertEqual(second_meta["layer"], "L1")
                    self.assertEqual(second_meta["status"], "stale" if expected_stale else "hit")
                    self.assertEqual(second_meta["isStale"], expected_stale)
                    self.assertEqual(second_meta["shouldAutoRefresh"], expected_auto_refresh)
                    self.assertEqual(second_data["fetchedAt"], preserved_iso)
                    self.assertEqual(second_meta["fetchedAt"], preserved_iso)
                    if expected_min_days > 0:
                        self.assertGreaterEqual(second_meta["ageSeconds"], expected_min_days * 86400 - 5)
                    self.assertEqual(stubs["ipdata"].await_count - before_calls, expected_upstream_delta)

    def test_eighteen_provider_compliance_tiers_retention_purge_and_live_rehydration(self):
        target_ip = "195.220.101.42"
        fake_redis = _BatchingFakeRedis()

        shodan_full_row = {
            **adapt_shodan_internetdb(
                {
                    "ports": [22, 80, 1080, 3128],
                    "tags": ["proxy", "compromised", "CVE-2025-1111"],
                    "hostnames": ["proxy-exit.example.org"],
                    "vulns": ["CVE-2025-1111"],
                    "cpes": ["cpe:/a:squid:squid"],
                },
                status_code=200,
            ),
            "vulns": ["CVE-2025-1111"],
            "cpes": ["cpe:/a:squid:squid"],
            "rawJson": {"ports": [22, 80, 1080, 3128], "vulns": ["CVE-2025-1111"]},
        }
        tor_exit_row = _build_provider_row("Tor Onionoo")
        tor_exit_row.update(
            {
                "isTor": True,
                "torIsExit": True,
                "torRunning": True,
                "torFlags": ["Exit", "Running"],
                "torLabel": "Tor Exit",
                "torSummary": "Tor Exit (Flags: Exit, Running)",
            }
        )

        stubs = start_non_dnsbl_provider_stubs(
            self,
            overrides={
                "shodan_internetdb": shodan_full_row,
                "tor_onionoo": tor_exit_row,
            },
            row_builder=_build_provider_row,
        )
        spamhaus_stub = patch(
            "detector.dns_providers.query_spamhaus_zen",
            new_callable=AsyncMock,
            return_value=_build_provider_row("Spamhaus ZEN"),
        ).start()
        spamcop_stub = patch(
            "detector.dns_providers.query_spamcop",
            new_callable=AsyncMock,
            return_value=_build_provider_row("SpamCop"),
        ).start()
        self.addCleanup(patch.stopall)

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.cache_backends._has_any_local_maxmind_db", return_value=True),
            patch("detector.detection_service.has_any_local_stopforumspam_db", return_value=True),
            patch("detector.cache_backends.redis_client", fake_redis),
        ):
            cold_resp = self.client.get(f"/api/v1/detect?ip={target_ip}")
            self.assertEqual(cold_resp.status_code, 200)

            l1_snap = asyncio.run(cache_backends.get_cached_ip_snapshot(target_ip, mode="full"))

        self.assertIsNotNone(l1_snap)
        assert l1_snap is not None
        l1_by_key = {l2_cache.resolve_provider_key(r): r for r in l1_snap["results"]}

        db_row = IpIntelligenceCache.objects.get(canonical_ip=target_ip)
        l2_raw = l2_cache.decompress_l2_payload(db_row.payload_compressed)
        assert l2_raw is not None
        l2_by_key = {l2_cache.resolve_provider_key(r): r for r in l2_raw["results"]}

        self.assertEqual(len(PROVIDER_REGISTRY), 18)
        for meta in PROVIDER_REGISTRY:
            with self.subTest(provider=meta.key):
                self.assertIn(meta.key, l1_by_key)
                self.assertIn("rawJson", l1_by_key[meta.key])
                if meta.key in L1_ONLY_PROVIDERS or meta.key in OFFLINE_REHYDRATE_PROVIDERS:
                    self.assertNotIn(meta.key, l2_by_key)
                    self.assertNotIn(meta.key, db_row.provider_fetched_map)
                else:
                    self.assertIn(meta.key, l2_by_key)
                    self.assertNotIn("rawJson", l2_by_key[meta.key])

        shodan_l2 = l2_by_key["shodan_internetdb"]
        for forbidden_shodan_key in ("rawJson", "vulns", "cpes", "ports"):
            self.assertNotIn(forbidden_shodan_key, shodan_l2)
        self.assertEqual(shodan_l2["openProxyPorts"], [1080, 3128])
        self.assertEqual(shodan_l2["tags"], ["proxy", "compromised"])
        self.assertEqual(shodan_l2["hostnames"], ["proxy-exit.example.org"])
        self.assertTrue(l2_by_key["tor_onionoo"]["isTor"])
        self.assertTrue(l2_by_key["tor_onionoo"]["torIsExit"])

        # Verify 30-day ip2location read filtering and physical purge while keeping >30d commercial rows intact
        base_now = datetime(2026, 11, 18, 8, 0, tzinfo=timezone.utc)
        all_18_rows = [l1_by_key[meta.key] for meta in PROVIDER_REGISTRY]
        retention_ips = (
            ("203.0.113.25", 25, True),
            ("203.0.113.35", 35, False),
            ("203.0.113.95", 95, False),
        )
        for ret_ip, age_days, expect_ip2location in retention_ips:
            l2_cache.merge_and_upsert_l2_snapshot(
                ret_ip,
                {"ip": ret_ip, "queryMode": "full", "results": all_18_rows},
                now_dt=base_now - timedelta(days=age_days),
            )
            with self.subTest(stage="read_filter", ip=ret_ip, age_days=age_days):
                read_snap = l2_cache.get_ip_snapshot(ret_ip, now_dt=base_now)
                assert read_snap is not None
                read_keys = {l2_cache.resolve_provider_key(r) for r in read_snap["results"]}
                self.assertEqual("ip2location" in read_keys, expect_ip2location)
                for unrestricted_comm in ("abuseipdb", "ipdata", "ipregistry", "getipintel", "proxycheck", "iphunter"):
                    self.assertIn(unrestricted_comm, read_keys)
                self.assertIn("tor_onionoo", read_keys)

        with patch(
            "detector.l2_cache._ensure_utc",
            side_effect=lambda dt=None: base_now if dt is None else dt.astimezone(timezone.utc),
        ):
            call_command("purge_l2_cache", batch_size=2, stdout=io.StringIO())

        for ret_ip, age_days, expect_ip2location in retention_ips:
            with self.subTest(stage="physical_purge", ip=ret_ip, age_days=age_days):
                persisted = IpIntelligenceCache.objects.get(canonical_ip=ret_ip)
                persisted_blob = l2_cache.decompress_l2_payload(persisted.payload_compressed)
                assert persisted_blob is not None
                persisted_keys = {l2_cache.resolve_provider_key(r) for r in persisted_blob["results"]}
                self.assertEqual("ip2location" in persisted_keys, expect_ip2location)
                self.assertEqual("ip2location" in persisted.provider_fetched_map, expect_ip2location)
                for unrestricted_comm in ("abuseipdb", "ipdata", "ipregistry", "getipintel", "proxycheck", "iphunter"):
                    self.assertIn(unrestricted_comm, persisted_keys)

        # Evict L1, update offline files and offline provider stubs, and verify live L2 rehydration
        fake_redis.strings.clear()
        spamhaus_stub.reset_mock()
        spamcop_stub.reset_mock()
        stubs["iphub"].reset_mock()
        stubs["tor_onionoo"].reset_mock()

        with tempfile.TemporaryDirectory() as tmp_dir:
            tool_root = Path(tmp_dir) / "tool"
            data_dir = tool_root / "data"
            ephemeral_dir = Path(tmp_dir) / "ephemeral"
            data_dir.mkdir(parents=True)
            compile_binary_prefix_index(
                [(f"{target_ip}/32", "cloudflare_warp")],
                data_dir / "privacy_relays.bin",
            )
            compile_binary_prefix_index(
                [("195.220.101.0/24", 64555)],
                data_dir / "bgp_tools.bin",
            )
            (data_dir / "bgp_tags.json").write_text(
                json.dumps({"asn_tags": {"64555": ["mobile"]}}),
                encoding="utf-8",
            )
            (data_dir / "mobile_asns.json").write_text(json.dumps({"mobile_asns": [64555]}), encoding="utf-8")

            updated_maxmind = _build_provider_row("MaxMind")
            updated_maxmind["asn"] = "AS64555"
            stubs["maxmind"].return_value = updated_maxmind
            stubs["x4bnet_vpn"].return_value = adapt_x4bnet_vpn(
                {"isListed": True, "isVpn": False, "isDatacenter": True, "isHosting": True}
            )
            stubs["ipsum_drop"].return_value = adapt_ipsum_drop({"ipsumScore": 2, "isIpsumListed": True})
            stubs["stopforumspam"].return_value = adapt_stopforumspam(
                {"success": 1, "ip": {"appears": 0, "frequency": 0}},
                status_code=200,
            )

            with (
                override_settings(
                    **TEST_UPSTREAM_SECRETS,
                    TOOL_DATA_DIR=str(tool_root),
                    LOCAL_EPHEMERAL_CACHE_DIR=str(ephemeral_dir),
                ),
                patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
                patch("detector.cache_backends.redis_client", fake_redis),
            ):
                rehydrated_l2_resp = self.client.get(f"/api/v1/detect?ip={target_ip}")

            cidr_attribution.clear_offline_intelligence_caches()

        self.assertEqual(rehydrated_l2_resp.status_code, 200)
        rehydrated_payload = rehydrated_l2_resp.json()
        self.assertEqual(rehydrated_payload["cacheMeta"]["layer"], "L2")
        self.assertTrue(rehydrated_payload["isTor"])
        self.assertTrue(rehydrated_payload["torIsExit"])
        self.assertEqual(rehydrated_payload["sharedPrivacyEgress"], "cloudflare_warp")
        self.assertTrue(rehydrated_payload["isMobileOrCgnat"])
        self.assertEqual(rehydrated_payload["recommendedCidr"], f"{target_ip}/32")

        rehydrated_providers = {r["provider"] for r in rehydrated_payload["results"]}
        for expected_rehydrated in ("MaxMind", "StopForumSpam", "IPsum / DROP", "X4BNet VPN"):
            self.assertIn(expected_rehydrated, rehydrated_providers)
        for excluded_l1_only in ("IPHub", "Spamhaus ZEN", "SpamCop"):
            self.assertNotIn(excluded_l1_only, rehydrated_providers)
        stubs["iphub"].assert_not_awaited()
        stubs["tor_onionoo"].assert_not_awaited()
        spamhaus_stub.assert_not_awaited()
        spamcop_stub.assert_not_awaited()

    def test_refresh_default_rate_limits_quota_guard_boundaries_and_partial_or_collapsed_merge(self):
        fake_redis = _BatchingFakeRedis()
        start_non_dnsbl_provider_stubs(
            self,
            overrides={"maxmind": dict(MAXMIND_STUB)},
            row_builder=_build_provider_row,
        )
        patroller_token = views.issue_gadget_token("PatrollerSixPerMin")
        admin_token = views.issue_gadget_token("MaintainerThirtyPerMin")

        # Verify production default 6 per minute per-user limit, 60 per hour limit, and 30 per minute global limit
        with (
            override_settings(ALLOWED_WIKI_USERS="MaintainerThirtyPerMin"),
            patch.dict(os.environ, {"ALLOWED_WIKI_USERS": "MaintainerThirtyPerMin"}),
            patch("detector.cache_backends.redis_client", fake_redis),
        ):
            for idx in range(6):
                resp_ok = self.client.post(
                    "/api/v1/detect/refresh",
                    data=json.dumps({"ip": f"8.8.4.{idx + 10}"}),
                    content_type="application/json",
                    HTTP_AUTHORIZATION=f"Bearer {patroller_token}",
                )
                self.assertEqual(resp_ok.status_code, 200)

            seventh_resp = self.client.post(
                "/api/v1/detect/refresh",
                data=json.dumps({"ip": "8.8.4.99"}),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {patroller_token}",
            )
            self.assertEqual(seventh_resp.status_code, 429)
            self.assertEqual(seventh_resp.json()["reason"], "user_rpm")
            self.assertGreater(int(seventh_resp.headers["Retry-After"]), 0)
            self.assertFalse(any("PatrollerSixPerMin" in k for k in fake_redis.strings))

            for idx in range(24):
                admin_resp = self.client.post(
                    "/api/v1/detect/refresh",
                    data=json.dumps({"ip": f"1.0.0.{idx + 10}"}),
                    content_type="application/json",
                    HTTP_AUTHORIZATION=f"Bearer {admin_token}",
                )
                self.assertEqual(admin_resp.status_code, 200)

            thirty_first_resp = self.client.post(
                "/api/v1/detect/refresh",
                data=json.dumps({"ip": "1.0.0.200"}),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {admin_token}",
            )
            self.assertEqual(thirty_first_resp.status_code, 429)
            self.assertEqual(thirty_first_resp.json()["reason"], "global_rpm")
            self.assertGreater(int(thirty_first_resp.headers["Retry-After"]), 0)

        # Verify commercial daily quota 15% and 180-day boundary matrix
        quota_boundary_cases = (
            ("below_15pct_age_120d_paused", 86, 120 * 86400, True),
            ("below_15pct_age_179d_paused", 86, 179 * 86400, True),
            ("below_15pct_age_180d_allowed", 86, 180 * 86400, False),
            ("exact_15pct_age_120d_allowed", 85, 120 * 86400, False),
        )
        only_abuse = {**{k: "" for k in TEST_UPSTREAM_SECRETS}, "ABUSEIPDB_API_KEY": "abuse-key"}
        now_utc = datetime.now(timezone.utc)
        for label, daily_used, age_secs, expected_suppressed in quota_boundary_cases:
            with self.subTest(quota_case=label):
                quota_redis = _BatchingFakeRedis()
                quota_redis.strings[quota_telemetry._quota_daily_key("abuseipdb", now_utc)] = str(daily_used)
                with (
                    override_settings(**only_abuse, ABUSEIPDB_DAILY_LIMIT=100),
                    patch.dict(os.environ, only_abuse),
                    patch("detector.cache_backends.redis_client", quota_redis),
                ):
                    suppressed = asyncio.run(
                        quota_telemetry.should_suppress_auto_refresh_for_quota(age_secs, now_dt=now_utc)
                    )
                self.assertEqual(suppressed, expected_suppressed)

        # Verify partial upstream failure vs <50% and 0% commercial collapse on POST /api/v1/detect/refresh
        merge_scenarios = (
            (
                "partial_failure_retains_historical_rows",
                "94.140.15.20",
                {"AbuseIPDB": 200, "IPRegistry": 200, "IPData": 504, "Proxycheck": 429},
                False,
                {"IPData", "Proxycheck"},
            ),
            (
                "sub_fifty_percent_collapse_preserves_l2",
                "94.140.15.21",
                {"AbuseIPDB": 200, "IPRegistry": 503, "IPData": 504, "Proxycheck": 429},
                True,
                set(),
            ),
            (
                "zero_commercial_collapse_preserves_l2",
                "94.140.15.22",
                {"AbuseIPDB": 503, "IPRegistry": 503, "IPData": 504, "Proxycheck": 429},
                True,
                set(),
            ),
        )
        four_comm_secrets = {
            **{k: "" for k in TEST_UPSTREAM_SECRETS},
            "CLOUDFLARE_RADAR_TOKEN": "cf-tok",
            "ABUSEIPDB_API_KEY": "k1",
            "IPDATA_API_KEY": "k2",
            "IPREGISTRY_API_KEY": "k3",
            "PROXYCHECK_API_KEY": "k4",
        }

        unconfigured_comm_labels = {"IP2Location", "GetIPIntel", "IPHub", "IPHunter"}

        for scenario_name, ip_addr, status_by_label, expect_degraded_abort, expected_hist_labels in merge_scenarios:
            with self.subTest(merge_case=scenario_name):
                prior_iso = _seed_l2_record(ip_addr, age_days=105)
                prior_epoch = int(datetime.fromisoformat(prior_iso).timestamp())
                scenario_redis = _BatchingFakeRedis()

                def _scenario_builder(
                    provider_label: str,
                    mapping: dict[str, int] = status_by_label,
                ) -> dict:
                    if provider_label in unconfigured_comm_labels:
                        return _build_provider_row(provider_label, status="No API Key", status_code=None)
                    code = mapping.get(provider_label, 200)
                    if code == 200:
                        return _build_provider_row(
                            provider_label,
                            high_risk_flag="VPN" if provider_label == "AbuseIPDB" else None,
                        )
                    if code == 429:
                        row = _build_provider_row(provider_label, status="Local Quota Guard", status_code=429)
                        row["isQuotaGuard"] = True
                        return row
                    return _build_provider_row(provider_label, status=f"{code} Upstream Error", status_code=code)

                start_non_dnsbl_provider_stubs(
                    self,
                    overrides={"maxmind": dict(MAXMIND_STUB)},
                    row_builder=_scenario_builder,
                )

                with (
                    override_settings(**four_comm_secrets),
                    patch.dict(os.environ, four_comm_secrets),
                    patch("detector.cache_backends.redis_client", scenario_redis),
                ):
                    refresh_resp = self.client.post(
                        "/api/v1/detect/refresh",
                        data=json.dumps({"ip": ip_addr}),
                        content_type="application/json",
                    )

                self.assertEqual(refresh_resp.status_code, 200)
                body = refresh_resp.json()
                db_after = IpIntelligenceCache.objects.get(canonical_ip=ip_addr)

                if expect_degraded_abort:
                    self.assertTrue(body["cacheMeta"]["degradedRefreshFallback"])
                    self.assertFalse(body["cacheMeta"]["shouldAutoRefresh"])
                    self.assertEqual(body["fetchedAt"], prior_iso)
                    self.assertEqual(db_after.fetched_at.astimezone(timezone.utc).isoformat(), prior_iso)
                    backoff_key = cache_backends.swr_backoff_key(ip_addr)
                    self.assertEqual(scenario_redis.ttls.get(backoff_key), 1800)
                else:
                    self.assertFalse(body["cacheMeta"]["degradedRefreshFallback"])
                    self.assertNotEqual(body["fetchedAt"], prior_iso)
                    rows_by_label = {r["provider"]: r for r in body["results"]}
                    for hist_label in expected_hist_labels:
                        self.assertEqual(rows_by_label[hist_label]["status"], "200 OK")
                        self.assertTrue(rows_by_label[hist_label].get("isHistoricalFallback"))
                    self.assertFalse(rows_by_label["AbuseIPDB"].get("isHistoricalFallback", False))
                    self.assertEqual(db_after.provider_fetched_map["ipdata"], prior_epoch)
                    self.assertGreater(db_after.provider_fetched_map["abuseipdb"], prior_epoch)

    async def test_concurrent_cold_refresh_polls_peer_snapshot_without_duplicate_upstream_calls(self):
        cold_ip = "149.112.112.9"
        fake_redis = _BatchingFakeRedis()
        stubs = start_non_dnsbl_provider_stubs(
            self,
            overrides={"maxmind": dict(MAXMIND_STUB)},
            row_builder=_build_provider_row,
        )

        with patch("detector.cache_backends.redis_client", fake_redis):
            fake_redis.strings[cache_backends.updating_lock_key(cold_ip)] = "peer-refresh-worker"

            async def _peer_finishes_refresh():
                await asyncio.sleep(0.04)
                await cache_backends.set_cached_ip_snapshot(
                    cold_ip,
                    {
                        "ip": cold_ip,
                        "fetchedAt": "2026-11-18T07:30:00+00:00",
                        "ptrHostname": "peer-refreshed.example.net",
                        "results": [_build_provider_row("IPData"), _build_provider_row("Proxycheck")],
                    },
                    mode="full",
                )
                fake_redis.strings.pop(cache_backends.updating_lock_key(cold_ip), None)

            with patch.object(detection_service, "_LOCK_POLL_INTERVAL_SECONDS", 0.015):
                _, (payload, status_code, _) = await asyncio.gather(
                    _peer_finishes_refresh(),
                    detection_service.refresh_single_canonical_ip(
                        cold_ip,
                        "session",
                        0.0,
                        username="SysopUser",
                        is_admin=True,
                    ),
                )

        self.assertEqual(status_code, 200)
        self.assertEqual(payload["cacheMeta"]["layer"], "L1")
        self.assertEqual(payload["ptrHostname"], "peer-refreshed.example.net")
        stubs["ipdata"].assert_not_awaited()
