"""Tests for proactive provider quota telemetry and check_setup environment diagnostics."""

import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
import httpx
from django.test import TestCase, override_settings

from detector import cache_backends, providers, views
from detector.provider_registry import PROVIDER_REGISTRY

from .helpers import (
    EMPTY_UPSTREAM_SECRETS,
    MAXMIND_STUB,
    TEST_UPSTREAM_SECRETS,
    FakeAsyncRedis,
    _login_authorised,
    _mock_response,
    _patch_async_client,
    build_provider_http_response,
    clean_dns_side_effect,
)


class ProactiveQuotaAndTelemetryTests(TestCase):
    """Tests for multi-window proactive quota protection, anonymised telemetry, and admin dashboard access."""

    _build_provider_http_response = staticmethod(build_provider_http_response)
    _clean_dns_side_effect = staticmethod(clean_dns_side_effect)

    @override_settings(
        **TEST_UPSTREAM_SECRETS,
        GETIPINTEL_RPM_LIMIT=2,
        GETIPINTEL_DAILY_LIMIT=0,
        PROXYCHECK_DAILY_LIMIT=1000,
        SPAMHAUS_ZEN_RPM_LIMIT=1000,
        DSHIELD_RPM_LIMIT=1000,
    )
    def test_proactive_rpm_limit_blocks_excess_requests_without_outbound_http_call(self):
        fake_redis = FakeAsyncRedis()
        called_urls = []
        _login_authorised(self)

        async def fake_get(url, **kwargs):
            called_urls.append(url)
            target_ip = kwargs.get("params", {}).get("ip", "8.8.8.8")
            if "1.1.1.1" in url:
                target_ip = "1.1.1.1"
            elif "9.9.9.9" in url:
                target_ip = "9.9.9.9"
            return self._build_provider_http_response(url, ip=target_ip)

        fake_resolver = MagicMock()
        fake_resolver.resolve = AsyncMock(side_effect=self._clean_dns_side_effect)

        with (
            patch("detector.cache_backends.redis_client", fake_redis),
            patch("detector.http_client.httpx.AsyncClient") as mock_client_cls,
            patch("detector.dns_providers.dns.asyncresolver.Resolver", return_value=fake_resolver),
            patch("detector.dns_providers.query_maxmind", new_callable=AsyncMock, return_value=dict(MAXMIND_STUB)),
        ):
            _patch_async_client(mock_client_cls, fake_get)
            first_response = self.client.get("/api/v1/detect?ip=8.8.8.8")
            second_response = self.client.get("/api/v1/detect?ip=1.1.1.1")
            third_response = self.client.get("/api/v1/detect?ip=9.9.9.9")

        self.assertEqual(first_response.status_code, 200)
        self.assertEqual(second_response.status_code, 200)
        self.assertEqual(third_response.status_code, 200)

        getipintel_calls = [url for url in called_urls if "getipintel.net" in url]
        proxycheck_calls = [url for url in called_urls if "proxycheck.io" in url]
        self.assertEqual(len(getipintel_calls), 2)
        self.assertEqual(len(proxycheck_calls), 3)

        third_rows = {row["provider"]: row for row in third_response.json()["results"]}
        guarded_row = third_rows["GetIPIntel"]
        self.assertEqual(guarded_row["status"], "Local Quota Guard (2/2 req/min)")
        self.assertEqual(guarded_row["statusCode"], 429)
        self.assertTrue(guarded_row["isQuotaGuarded"])
        self.assertTrue(guarded_row["isQuotaGuard"])
        self.assertEqual(guarded_row["rawJson"]["status"], "quota_guarded")
        self.assertEqual(guarded_row["rawJson"]["window"], "rpm")
        self.assertEqual(third_rows["Proxycheck"]["status"], "200 OK")

        from_guarded_key = providers._build_cooldown_provider_row(
            "GetIPIntel",
            {"statusCode": 429, "isQuotaGuarded": True, "reason": "RPM limit"},
        )
        self.assertTrue(from_guarded_key["isQuotaGuarded"])
        self.assertTrue(from_guarded_key["isQuotaGuard"])
        normal_cooldown = providers._build_cooldown_provider_row(
            "GetIPIntel",
            {"statusCode": 503, "reason": "Upstream 503"},
        )
        self.assertNotIn("isQuotaGuarded", normal_cooldown)
        self.assertNotIn("isQuotaGuard", normal_cooldown)

        ns = cache_backends.get_redis_namespace()
        min_keys = [key for key in fake_redis.strings if key.startswith(f"{ns}:quota:getipintel:min:")]
        self.assertEqual(len(min_keys), 1)
        self.assertEqual(fake_redis.strings[min_keys[0]], "2")

        telemetry_keys = [key for key in fake_redis.hashes if key.startswith(f"{ns}:telemetry:getipintel:day:")]
        self.assertEqual(len(telemetry_keys), 1)
        self.assertEqual(fake_redis.hashes[telemetry_keys[0]].get("ok"), "2")
        self.assertEqual(fake_redis.hashes[telemetry_keys[0]].get("quota_blocked"), "1")

    @override_settings(
        **TEST_UPSTREAM_SECRETS,
        PROXYCHECK_RPM_LIMIT=10,
        PROXYCHECK_DAILY_LIMIT=1,
    )
    def test_proactive_daily_limit_blocks_and_rolls_back_both_window_counters(self):
        fake_redis = FakeAsyncRedis()
        called_urls = []
        _login_authorised(self)

        async def fake_get(url, **kwargs):
            called_urls.append(url)
            target_ip = "1.1.1.1" if "1.1.1.1" in url else "8.8.8.8"
            return self._build_provider_http_response(url, ip=target_ip)

        fake_resolver = MagicMock()
        fake_resolver.resolve = AsyncMock(side_effect=self._clean_dns_side_effect)

        with (
            patch("detector.cache_backends.redis_client", fake_redis),
            patch("detector.http_client.httpx.AsyncClient") as mock_client_cls,
            patch("detector.dns_providers.dns.asyncresolver.Resolver", return_value=fake_resolver),
            patch("detector.dns_providers.query_maxmind", new_callable=AsyncMock, return_value=dict(MAXMIND_STUB)),
        ):
            _patch_async_client(mock_client_cls, fake_get)
            self.client.get("/api/v1/detect?ip=8.8.8.8")
            blocked_response = self.client.get("/api/v1/detect?ip=1.1.1.1")

        self.assertEqual(blocked_response.status_code, 200)
        proxycheck_calls = [url for url in called_urls if "proxycheck.io" in url]
        self.assertEqual(len(proxycheck_calls), 1)

        rows = {row["provider"]: row for row in blocked_response.json()["results"]}
        self.assertEqual(rows["Proxycheck"]["status"], "Local Quota Guard (1/1 req/day)")
        self.assertEqual(rows["Proxycheck"]["rawJson"]["window"], "rpd")

        ns = cache_backends.get_redis_namespace()
        min_keys = [key for key in fake_redis.strings if key.startswith(f"{ns}:quota:proxycheck:min:")]
        day_keys = [key for key in fake_redis.strings if key.startswith(f"{ns}:quota:proxycheck:day:")]
        self.assertEqual(fake_redis.strings[min_keys[0]], "1")
        self.assertEqual(fake_redis.strings[day_keys[0]], "1")

    @override_settings(GETIPINTEL_RPM_LIMIT=15, GETIPINTEL_DAILY_LIMIT=5000)
    def test_lua_script_evaluation_and_redis_outage_fail_open(self):
        from asgiref.sync import async_to_sync

        from detector import quota_telemetry

        lua_client = MagicMock()
        lua_client.eval = AsyncMock(side_effect=[[1, "", 1, 1], [0, "rpm", 15, 42]])
        with patch("detector.cache_backends.redis_client", lua_client):
            allowed_res = async_to_sync(quota_telemetry.check_and_consume_quota)("getipintel")
            blocked_res = async_to_sync(quota_telemetry.check_and_consume_quota)("getipintel")

        self.assertTrue(allowed_res.allowed)
        self.assertEqual(allowed_res.minute_used, 1)
        self.assertEqual(allowed_res.daily_used, 1)
        self.assertFalse(blocked_res.allowed)
        self.assertEqual(blocked_res.window, "rpm")
        self.assertEqual(blocked_res.used, 15)
        self.assertEqual(blocked_res.limit, 15)

        failing_client = MagicMock()
        failing_client.eval = AsyncMock(side_effect=ConnectionError("redis offline"))
        failing_client.pipeline = MagicMock(side_effect=ConnectionError("redis offline"))
        with patch("detector.cache_backends.redis_client", failing_client):
            fail_open_res = async_to_sync(quota_telemetry.check_and_consume_quota)("getipintel")
            snapshot = async_to_sync(quota_telemetry.build_dashboard_snapshot)()

        self.assertTrue(fail_open_res.allowed)
        self.assertFalse(snapshot["redisAvailable"])
        self.assertIn("providers", snapshot)

        with patch("detector.cache_backends.redis_client", None):
            no_redis_res = async_to_sync(quota_telemetry.check_and_consume_quota)("getipintel")
        self.assertTrue(no_redis_res.allowed)

        with (
            override_settings(GETIPINTEL_RPM_LIMIT=0, GETIPINTEL_DAILY_LIMIT=0),
            patch("detector.cache_backends.redis_client", FakeAsyncRedis()),
        ):
            for _ in range(2):
                zero_limit_res = async_to_sync(quota_telemetry.check_and_consume_quota)("getipintel")
                self.assertTrue(zero_limit_res.allowed)

    @override_settings(**EMPTY_UPSTREAM_SECRETS, GETIPINTEL_RPM_LIMIT=1, SPAMCOP_RPM_LIMIT=1)
    def test_unconfigured_providers_and_ipv6_dnsbl_skips_do_not_consume_quota(self):
        fake_redis = FakeAsyncRedis()
        _login_authorised(self)

        fake_resolver = MagicMock()
        fake_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

        with (
            patch("detector.cache_backends.redis_client", fake_redis),
            patch("detector.dns_providers.dns.asyncresolver.Resolver", return_value=fake_resolver),
            patch("detector.dns_providers.query_maxmind", new_callable=AsyncMock, return_value=dict(MAXMIND_STUB)),
        ):
            response = self.client.get("/api/v1/detect?ip=2001:4860:4860::8888")

        self.assertEqual(response.status_code, 200)
        rows = {row["provider"]: row for row in response.json()["results"]}
        self.assertEqual(rows["GetIPIntel"]["status"], "No API Key")
        self.assertEqual(rows["SpamCop"]["status"], "Skipped (IPv6)")
        ns = cache_backends.get_redis_namespace()
        self.assertFalse(any(key.startswith(f"{ns}:quota:getipintel:") for key in fake_redis.strings))
        self.assertFalse(any(key.startswith(f"{ns}:quota:spamcop:") for key in fake_redis.strings))

    @override_settings(**TEST_UPSTREAM_SECRETS)
    def test_anonymised_telemetry_records_headers_and_never_stores_ip_or_username(self):
        fake_redis = FakeAsyncRedis()
        _login_authorised(self)
        session = self.client.session
        session["wikimedia_user"] = {
            "isLoggedIn": True,
            "username": "SensitiveReviewerName",
            "role": "Local Administrator (sysop)",
            "hasAccess": True,
            "localGroups": ["sysop"],
            "globalGroups": [],
        }
        session.save()

        async def fake_get(url, **kwargs):
            target_ip = "1.1.1.1" if "1.1.1.1" in url else "8.8.8.8"
            return self._build_provider_http_response(url, ip=target_ip)

        fake_resolver = MagicMock()
        fake_resolver.resolve = AsyncMock(side_effect=self._clean_dns_side_effect)
        gadget_client = self.client.__class__()
        gadget_token = views.issue_gadget_token("SensitiveGadgetUser")

        with (
            patch("detector.cache_backends.redis_client", fake_redis),
            patch("detector.http_client.httpx.AsyncClient") as mock_client_cls,
            patch("detector.dns_providers.dns.asyncresolver.Resolver", return_value=fake_resolver),
            patch("detector.dns_providers.query_maxmind", new_callable=AsyncMock, return_value=dict(MAXMIND_STUB)),
        ):
            _patch_async_client(mock_client_cls, fake_get)
            first_session = self.client.get(
                "/api/v1/detect?ip=8.8.8.8",
                HTTP_USER_AGENT="SecretBrowserFingerprint/9.9",
            )
            cached_session = self.client.get(
                "/api/v1/detect?ip=8.8.8.8",
                HTTP_USER_AGENT="SecretBrowserFingerprint/9.9",
            )
            gadget_miss = gadget_client.get(
                "/api/v1/detect?ip=1.1.1.1",
                HTTP_AUTHORIZATION=f"Bearer {gadget_token}",
                HTTP_USER_AGENT="SecretGadgetAgent/1.0",
            )

        self.assertEqual(first_session.status_code, 200)
        self.assertEqual(cached_session.status_code, 200)
        self.assertEqual(gadget_miss.status_code, 200)

        ns = cache_backends.get_redis_namespace()
        serialised_quota_and_telemetry = json.dumps(
            {
                "strings": {
                    k: v for k, v in fake_redis.strings.items() if k.startswith((f"{ns}:quota:", f"{ns}:telemetry:"))
                },
                "hashes": {
                    k: v for k, v in fake_redis.hashes.items() if k.startswith((f"{ns}:quota:", f"{ns}:telemetry:"))
                },
            }
        )
        for sensitive in (
            "8.8.8.8",
            "1.1.1.1",
            "SensitiveReviewerName",
            "SensitiveGadgetUser",
            "SecretBrowserFingerprint",
            "SecretGadgetAgent",
            gadget_token,
        ):
            self.assertNotIn(sensitive, serialised_quota_and_telemetry)

        global_key = next(key for key in fake_redis.hashes if key.startswith(f"{ns}:telemetry:global:day:"))
        global_hash = fake_redis.hashes[global_key]
        self.assertEqual(global_hash.get("auth_session"), "2")
        self.assertEqual(global_hash.get("auth_gadget"), "1")
        self.assertEqual(global_hash.get("cache_hit"), "1")
        self.assertEqual(global_hash.get("cache_miss"), "2")
        self.assertEqual(global_hash.get("l1_hit"), "1")
        self.assertEqual(global_hash.get("upstream_miss"), "2")

        abuse_key = next(key for key in fake_redis.hashes if key.startswith(f"{ns}:telemetry:abuseipdb:day:"))
        self.assertEqual(fake_redis.hashes[abuse_key].get("upstream_remaining"), "982")
        self.assertEqual(fake_redis.hashes[abuse_key].get("upstream_limit"), "1000")
        self.assertEqual(fake_redis.hashes[abuse_key].get("ok"), "2")
        self.assertEqual(fake_redis.hashes[abuse_key].get("cache_hit"), "1")

        ipdata_key = next(key for key in fake_redis.hashes if key.startswith(f"{ns}:telemetry:ipdata:day:"))
        self.assertEqual(fake_redis.hashes[ipdata_key].get("upstream_used"), "142")

        ipregistry_key = next(key for key in fake_redis.hashes if key.startswith(f"{ns}:telemetry:ipregistry:day:"))
        self.assertEqual(fake_redis.hashes[ipregistry_key].get("upstream_remaining"), "4950")

    @override_settings(**TEST_UPSTREAM_SECRETS)
    def test_telemetry_tracks_rate_limits_server_errors_timeouts_and_partial_cache(self):
        fake_redis = FakeAsyncRedis()
        _login_authorised(self)

        async def fake_get(url, **kwargs):
            if "abuseipdb.com" in url:
                resp = _mock_response(status_code=429, json_value={"errors": [{"detail": "Rate limit"}]})
                resp.headers = {"Retry-After": "120"}
                return resp
            if "ipregistry.co" in url:
                return _mock_response(status_code=503, json_value={"message": "Backend overloaded"})
            if "proxycheck.io" in url:
                raise httpx.ReadTimeout("upstream timed out")
            return self._build_provider_http_response(url)

        fake_resolver = MagicMock()
        fake_resolver.resolve = AsyncMock(side_effect=self._clean_dns_side_effect)

        with (
            patch("detector.cache_backends.redis_client", fake_redis),
            patch("detector.http_client.httpx.AsyncClient") as mock_client_cls,
            patch("detector.dns_providers.dns.asyncresolver.Resolver", return_value=fake_resolver),
            patch("detector.dns_providers.query_maxmind", new_callable=AsyncMock, return_value=dict(MAXMIND_STUB)),
        ):
            _patch_async_client(mock_client_cls, fake_get)
            first_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")
            second_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")

        self.assertEqual(first_resp.status_code, 200)
        self.assertEqual(second_resp.status_code, 200)
        self.assertEqual(second_resp.json()["cacheMeta"]["status"], "partial")

        ns = cache_backends.get_redis_namespace()
        global_key = next(key for key in fake_redis.hashes if key.startswith(f"{ns}:telemetry:global:day:"))
        self.assertEqual(fake_redis.hashes[global_key].get("cache_miss"), "1")
        self.assertEqual(fake_redis.hashes[global_key].get("cache_partial"), "1")

        abuse_key = next(key for key in fake_redis.hashes if key.startswith(f"{ns}:telemetry:abuseipdb:day:"))
        self.assertEqual(fake_redis.hashes[abuse_key].get("429"), "1")

        ipregistry_key = next(key for key in fake_redis.hashes if key.startswith(f"{ns}:telemetry:ipregistry:day:"))
        self.assertEqual(fake_redis.hashes[ipregistry_key].get("5xx"), "1")

        proxycheck_key = next(key for key in fake_redis.hashes if key.startswith(f"{ns}:telemetry:proxycheck:day:"))
        self.assertEqual(fake_redis.hashes[proxycheck_key].get("timeout"), "1")

    def test_admin_provider_dashboard_only_honours_allowlisted_wiki_users(self):
        fake_redis = FakeAsyncRedis()
        gadget_client = self.client.__class__()
        gadget_token = views.issue_gadget_token("AllowlistedDashboardAdmin")

        with patch("detector.cache_backends.redis_client", fake_redis):
            with (
                override_settings(ALLOWED_WIKI_USERS="AllowlistedDashboardAdmin, second_admin, ~2026-12345"),
                patch.dict(
                    os.environ,
                    {"ALLOWED_WIKI_USERS": "AllowlistedDashboardAdmin, second_admin, ~2026-12345"},
                ),
            ):
                unauthenticated = self.client.get("/api/v1/admin/provider-dashboard")
                self.assertEqual(unauthenticated.status_code, 401)

                gadget_attempt = gadget_client.get(
                    "/api/v1/admin/provider-dashboard",
                    HTTP_AUTHORIZATION=f"Bearer {gadget_token}",
                )
                self.assertEqual(gadget_attempt.status_code, 403)

                disallowed_sessions = [
                    {
                        "isLoggedIn": True,
                        "username": "PlainUser",
                        "role": "Standard User (Unauthorised)",
                        "hasAccess": False,
                        "localGroups": [],
                        "globalGroups": [],
                    },
                    {
                        "isLoggedIn": True,
                        "username": "SysopUser",
                        "role": "Local Administrator (sysop)",
                        "hasAccess": True,
                        "localGroups": ["sysop"],
                        "globalGroups": [],
                    },
                    {
                        "isLoggedIn": True,
                        "username": "CheckUserAccount",
                        "role": "CheckUser",
                        "hasAccess": True,
                        "localGroups": ["checkuser"],
                        "globalGroups": [],
                    },
                    {
                        "isLoggedIn": True,
                        "username": "StewardUser",
                        "role": "Steward",
                        "hasAccess": True,
                        "localGroups": [],
                        "globalGroups": ["steward"],
                    },
                    {
                        "isLoggedIn": True,
                        "username": "RollbackerUser",
                        "role": "Global Rollbacker",
                        "hasAccess": True,
                        "localGroups": [],
                        "globalGroups": ["global-rollbacker"],
                    },
                    {
                        "isLoggedIn": True,
                        "username": "TempViewer",
                        "role": "Temporary Account Access (local: checkuser-temporary-account)",
                        "hasAccess": True,
                        "localGroups": ["checkuser-temporary-account"],
                        "globalGroups": [],
                    },
                    {
                        "isLoggedIn": True,
                        "username": "~2026-12345",
                        "role": "Allowlisted Wikimedia User",
                        "hasAccess": True,
                        "localGroups": [],
                        "globalGroups": [],
                    },
                    {
                        "isLoggedIn": True,
                        "username": "AllowlistedDashboardAdmin",
                        "role": "Standard User (Unauthorised)",
                        "hasAccess": False,
                        "localGroups": [],
                        "globalGroups": [],
                    },
                ]
                for user_state in disallowed_sessions:
                    session = self.client.session
                    session["wikimedia_user"] = user_state
                    session.save()
                    forbidden = self.client.get("/api/v1/admin/provider-dashboard")
                    self.assertEqual(forbidden.status_code, 403, f"Expected 403 for {user_state['username']}")
                    user_response = self.client.get("/api/v1/auth/user")
                    self.assertEqual(user_response.status_code, 200)
                    self.assertFalse(user_response.json()["isAdmin"])

                for allowed_user in (
                    {
                        "isLoggedIn": True,
                        "username": "AllowlistedDashboardAdmin",
                        "role": "Allowlisted Wikimedia User",
                        "hasAccess": True,
                        "localGroups": [],
                        "globalGroups": [],
                    },
                    {
                        "isLoggedIn": True,
                        "username": "second admin",
                        "role": "Temporary Account Access (local: checkuser-temporary-account)",
                        "hasAccess": True,
                        "localGroups": [],
                        "globalGroups": [],
                    },
                ):
                    session = self.client.session
                    session["wikimedia_user"] = allowed_user
                    session.save()
                    ok_response = self.client.get("/api/v1/admin/provider-dashboard")
                    self.assertEqual(ok_response.status_code, 200)
                    self.assertTrue(self.client.get("/api/v1/auth/user").json()["isAdmin"])

                method_not_allowed = self.client.post("/api/v1/admin/provider-dashboard")
                self.assertEqual(method_not_allowed.status_code, 405)

            with override_settings(ALLOWED_WIKI_USERS=""), patch.dict(os.environ, {"ALLOWED_WIKI_USERS": ""}):
                session = self.client.session
                session["wikimedia_user"] = {
                    "isLoggedIn": True,
                    "username": "AllowlistedDashboardAdmin",
                    "role": "Steward",
                    "hasAccess": True,
                    "localGroups": ["sysop"],
                    "globalGroups": ["steward"],
                }
                session.save()
                self.assertEqual(self.client.get("/api/v1/admin/provider-dashboard").status_code, 403)
                self.assertFalse(self.client.get("/api/v1/auth/user").json()["isAdmin"])

    @override_settings(
        **{**TEST_UPSTREAM_SECRETS, "ABUSEIPDB_API_KEY": ""},
        ALLOWED_WIKI_USERS="SysopUser",
        GETIPINTEL_RPM_LIMIT=15,
        GETIPINTEL_DAILY_LIMIT=5000,
    )
    def test_admin_provider_dashboard_returns_aggregated_schema(self):
        from datetime import datetime, timezone

        fake_redis = FakeAsyncRedis()
        now_dt = datetime(2026, 11, 15, 10, 30, tzinfo=timezone.utc)
        min_bucket = now_dt.strftime("%Y%m%d%H%M")
        day_bucket = now_dt.strftime("%Y%m%d")

        ns = cache_backends.get_redis_namespace()
        fake_redis.strings[f"{ns}:quota:getipintel:min:{min_bucket}"] = "15"
        fake_redis.strings[f"{ns}:quota:getipintel:day:{day_bucket}"] = "320"
        fake_redis.strings[f"{ns}:cooldown:ipregistry"] = json.dumps({"reason": "HTTP 429"})
        fake_redis.ttls[f"{ns}:cooldown:ipregistry"] = 95

        fake_redis.hashes[f"{ns}:telemetry:global:day:{day_bucket}"] = {
            "auth_session": "7",
            "auth_gadget": "3",
            "cache_hit": "4",
            "cache_partial": "2",
            "cache_miss": "4",
            "l1_hit": "2",
            "l2_hit_fresh": "1",
            "l2_hit_stale_swr": "1",
            "upstream_miss": "4",
            "refresh_ok": "2",
            "refresh_rate_limited": "1",
        }
        fake_redis.hashes[f"{ns}:telemetry:getipintel:day:{day_bucket}"] = {
            "ok": "11",
            "cache_hit": "4",
            "quota_blocked": "2",
            "429": "0",
            "5xx": "0",
            "timeout": "0",
        }
        fake_redis.hashes[f"{ns}:telemetry:proxycheck:day:{day_bucket}"] = {
            "ok": "9",
            "cache_hit": "6",
            "upstream_remaining": "991",
            "upstream_limit": "1000",
            "last_status_at": "2026-11-15T10:29:00+00:00",
        }

        _login_authorised(self)
        fake_dt_cls = MagicMock()
        fake_dt_cls.now.return_value = now_dt
        with (
            patch("detector.cache_backends.redis_client", fake_redis),
            patch("detector.quota_telemetry.datetime", fake_dt_cls),
        ):
            response = self.client.get("/api/v1/admin/provider-dashboard")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["redisAvailable"])
        self.assertEqual(payload["dateBucket"], day_bucket)
        self.assertEqual(payload["cacheTelemetry"]["l1Hit"], 2)
        self.assertEqual(payload["cacheTelemetry"]["l2HitFresh"], 1)
        self.assertEqual(payload["cacheTelemetry"]["l2HitStaleSwr"], 1)
        self.assertEqual(payload["cacheTelemetry"]["upstreamMiss"], 4)
        self.assertEqual(payload["cacheTelemetry"]["refreshOk"], 2)
        self.assertEqual(payload["cacheTelemetry"]["refreshRateLimited"], 1)
        self.assertEqual(payload["cacheTelemetry"]["dualLayerHitRatePercent"], 50.0)

        kpis = payload["global"]
        self.assertEqual(kpis["totalRequestsToday"], 10)
        self.assertEqual(kpis["authSession"], 7)
        self.assertEqual(kpis["authGadget"], 3)
        self.assertEqual(kpis["cacheHit"], 4)
        self.assertEqual(kpis["cachePartial"], 2)
        self.assertEqual(kpis["cacheMiss"], 4)
        self.assertEqual(kpis["fullCacheHitRatePercent"], 40.0)
        self.assertEqual(kpis["totalQuotaBlocksToday"], 2)
        self.assertEqual(kpis["activeCooldownCount"], 1)
        self.assertEqual(kpis["activeQuotaGuardCount"], 1)

        providers_map = {row["key"]: row for row in payload["providers"]}
        self.assertEqual(set(providers_map.keys()), {meta.key for meta in PROVIDER_REGISTRY})

        self.assertEqual(providers_map["abuseipdb"]["status"], "No API Key")
        self.assertEqual(providers_map["abuseipdb"]["statusKey"], "no_api_key")
        self.assertFalse(providers_map["abuseipdb"]["configured"])

        self.assertEqual(providers_map["getipintel"]["status"], "Quota Guarded")
        self.assertEqual(providers_map["getipintel"]["statusKey"], "quota_guarded")
        self.assertEqual(providers_map["getipintel"]["minuteUsed"], 15)
        self.assertEqual(providers_map["getipintel"]["minuteLimit"], 15)
        self.assertEqual(providers_map["getipintel"]["telemetry"]["quotaBlocked"], 2)

        self.assertEqual(providers_map["ipregistry"]["status"], "Cooldown (95s)")
        self.assertEqual(providers_map["ipregistry"]["statusKey"], "cooldown")
        self.assertEqual(providers_map["ipregistry"]["cooldownTtlSeconds"], 95)
        self.assertEqual(providers_map["ipregistry"]["cooldownReason"], "HTTP 429")

        self.assertEqual(providers_map["proxycheck"]["status"], "Healthy")
        self.assertEqual(providers_map["proxycheck"]["statusKey"], "healthy")
        self.assertEqual(providers_map["proxycheck"]["upstreamRemaining"], 991)
        self.assertEqual(providers_map["proxycheck"]["upstreamLimit"], 1000)
        self.assertEqual(providers_map["proxycheck"]["telemetry"]["cacheHit"], 6)

    @override_settings(
        **TEST_UPSTREAM_SECRETS,
        GETIPINTEL_RPM_LIMIT=1,
        GETIPINTEL_DAILY_LIMIT=5000,
        PROXYCHECK_RPM_LIMIT=1,
        PROXYCHECK_DAILY_LIMIT=1000,
        ABUSEIPDB_RPM_LIMIT=10,
        ABUSEIPDB_DAILY_LIMIT=100,
        IPDATA_RPM_LIMIT=10,
        IPDATA_DAILY_LIMIT=100,
    )
    def test_transport_errors_and_timeouts_refund_quota_while_http_responses_retain_quota(self):
        fake_redis = FakeAsyncRedis()
        _login_authorised(self)

        async def fake_get(url, **kwargs):
            if "getipintel.net" in url:
                raise httpx.ConnectError("connection refused by upstream")
            if "proxycheck.io" in url:
                raise httpx.TimeoutException("read timed out")
            if "abuseipdb.com" in url:
                resp = _mock_response(status_code=429, json_value={"errors": [{"detail": "Rate limit"}]})
                resp.headers = {"Retry-After": "60"}
                return resp
            return self._build_provider_http_response(url, ip="8.8.8.8")

        fake_resolver = MagicMock()
        fake_resolver.resolve = AsyncMock(side_effect=self._clean_dns_side_effect)

        with (
            patch("detector.cache_backends.redis_client", fake_redis),
            patch("detector.http_client.httpx.AsyncClient") as mock_client_cls,
            patch("detector.dns_providers.dns.asyncresolver.Resolver", return_value=fake_resolver),
            patch("detector.dns_providers.query_maxmind", new_callable=AsyncMock, return_value=dict(MAXMIND_STUB)),
        ):
            _patch_async_client(mock_client_cls, fake_get)
            response = self.client.get("/api/v1/detect?ip=8.8.8.8")

        self.assertEqual(response.status_code, 200)

        ns = cache_backends.get_redis_namespace()
        # ConnectError and TimeoutException must roll back both minute and daily quota counters to zero
        for refunded_provider in ("getipintel", "proxycheck"):
            min_key = next(key for key in fake_redis.strings if key.startswith(f"{ns}:quota:{refunded_provider}:min:"))
            day_key = next(key for key in fake_redis.strings if key.startswith(f"{ns}:quota:{refunded_provider}:day:"))
            self.assertEqual(fake_redis.strings[min_key], "0")
            self.assertEqual(fake_redis.strings[day_key], "0")

        # Valid HTTP 200 and HTTP 429 responses must retain their consumed quota count
        for retained_provider in ("abuseipdb", "ipdata"):
            min_key = next(key for key in fake_redis.strings if key.startswith(f"{ns}:quota:{retained_provider}:min:"))
            day_key = next(key for key in fake_redis.strings if key.startswith(f"{ns}:quota:{retained_provider}:day:"))
            self.assertEqual(fake_redis.strings[min_key], "1")
            self.assertEqual(fake_redis.strings[day_key], "1")
