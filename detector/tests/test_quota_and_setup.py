"""Tests for proactive provider quota telemetry and check_setup environment diagnostics."""

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from django.test import SimpleTestCase, TestCase, override_settings

from detector import views

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
            patch("detector.views.redis_client", fake_redis),
            patch("detector.views.httpx.AsyncClient") as mock_client_cls,
            patch("detector.views.dns.asyncresolver.Resolver", return_value=fake_resolver),
            patch("detector.views.query_maxmind", new_callable=AsyncMock, return_value=dict(MAXMIND_STUB)),
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

        from_guarded_key = views._build_cooldown_provider_row(
            "GetIPIntel",
            {"statusCode": 429, "isQuotaGuarded": True, "reason": "RPM limit"},
        )
        self.assertTrue(from_guarded_key["isQuotaGuarded"])
        self.assertTrue(from_guarded_key["isQuotaGuard"])
        normal_cooldown = views._build_cooldown_provider_row(
            "GetIPIntel",
            {"statusCode": 503, "reason": "Upstream 503"},
        )
        self.assertNotIn("isQuotaGuarded", normal_cooldown)
        self.assertNotIn("isQuotaGuard", normal_cooldown)

        min_keys = [key for key in fake_redis.strings if key.startswith("proxycheck:v1:quota:getipintel:min:")]
        self.assertEqual(len(min_keys), 1)
        self.assertEqual(fake_redis.strings[min_keys[0]], "2")

        telemetry_keys = [key for key in fake_redis.hashes if key.startswith("proxycheck:v1:telemetry:getipintel:day:")]
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
            patch("detector.views.redis_client", fake_redis),
            patch("detector.views.httpx.AsyncClient") as mock_client_cls,
            patch("detector.views.dns.asyncresolver.Resolver", return_value=fake_resolver),
            patch("detector.views.query_maxmind", new_callable=AsyncMock, return_value=dict(MAXMIND_STUB)),
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

        min_keys = [key for key in fake_redis.strings if key.startswith("proxycheck:v1:quota:proxycheck:min:")]
        day_keys = [key for key in fake_redis.strings if key.startswith("proxycheck:v1:quota:proxycheck:day:")]
        self.assertEqual(fake_redis.strings[min_keys[0]], "1")
        self.assertEqual(fake_redis.strings[day_keys[0]], "1")

    @override_settings(**TEST_UPSTREAM_SECRETS, GETIPINTEL_RPM_LIMIT=0, GETIPINTEL_DAILY_LIMIT=0)
    def test_zero_quota_limit_disables_local_interception(self):
        fake_redis = FakeAsyncRedis()
        called_urls = []
        _login_authorised(self)

        async def fake_get(url, **kwargs):
            called_urls.append(url)
            return self._build_provider_http_response(url)

        fake_resolver = MagicMock()
        fake_resolver.resolve = AsyncMock(side_effect=self._clean_dns_side_effect)

        with (
            patch("detector.views.redis_client", fake_redis),
            patch("detector.views.httpx.AsyncClient") as mock_client_cls,
            patch("detector.views.dns.asyncresolver.Resolver", return_value=fake_resolver),
            patch("detector.views.query_maxmind", new_callable=AsyncMock, return_value=dict(MAXMIND_STUB)),
        ):
            _patch_async_client(mock_client_cls, fake_get)
            self.client.get("/api/v1/detect?ip=8.8.8.8")
            second_response = self.client.get("/api/v1/detect?ip=1.1.1.1")

        self.assertEqual(second_response.status_code, 200)
        getipintel_calls = [url for url in called_urls if "getipintel.net" in url]
        self.assertEqual(len(getipintel_calls), 2)
        rows = {row["provider"]: row for row in second_response.json()["results"]}
        self.assertEqual(rows["GetIPIntel"]["status"], "200 OK")

    @override_settings(GETIPINTEL_RPM_LIMIT=15, GETIPINTEL_DAILY_LIMIT=5000)
    def test_lua_script_evaluation_and_redis_outage_fail_open(self):
        from asgiref.sync import async_to_sync

        from detector import quota_telemetry

        lua_client = MagicMock()
        lua_client.eval = AsyncMock(side_effect=[[1, "", 1, 1], [0, "rpm", 15, 42]])
        with patch("detector.views.redis_client", lua_client):
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
        with patch("detector.views.redis_client", failing_client):
            fail_open_res = async_to_sync(quota_telemetry.check_and_consume_quota)("getipintel")
            snapshot = async_to_sync(quota_telemetry.build_dashboard_snapshot)()

        self.assertTrue(fail_open_res.allowed)
        self.assertFalse(snapshot["redisAvailable"])
        self.assertIn("providers", snapshot)

        with patch("detector.views.redis_client", None):
            no_redis_res = async_to_sync(quota_telemetry.check_and_consume_quota)("getipintel")
        self.assertTrue(no_redis_res.allowed)

    @override_settings(**EMPTY_UPSTREAM_SECRETS, GETIPINTEL_RPM_LIMIT=1, SPAMCOP_RPM_LIMIT=1)
    def test_unconfigured_providers_and_ipv6_dnsbl_skips_do_not_consume_quota(self):
        fake_redis = FakeAsyncRedis()
        _login_authorised(self)

        fake_resolver = MagicMock()
        fake_resolver.resolve = AsyncMock(side_effect=views.dns.resolver.NXDOMAIN())

        with (
            patch("detector.views.redis_client", fake_redis),
            patch("detector.views.dns.asyncresolver.Resolver", return_value=fake_resolver),
            patch("detector.views.query_maxmind", new_callable=AsyncMock, return_value=dict(MAXMIND_STUB)),
        ):
            response = self.client.get("/api/v1/detect?ip=2001:4860:4860::8888")

        self.assertEqual(response.status_code, 200)
        rows = {row["provider"]: row for row in response.json()["results"]}
        self.assertEqual(rows["GetIPIntel"]["status"], "No API Key")
        self.assertEqual(rows["SpamCop"]["status"], "Skipped (IPv6)")
        self.assertFalse(any(key.startswith("proxycheck:v1:quota:getipintel:") for key in fake_redis.strings))
        self.assertFalse(any(key.startswith("proxycheck:v1:quota:spamcop:") for key in fake_redis.strings))

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
            patch("detector.views.redis_client", fake_redis),
            patch("detector.views.httpx.AsyncClient") as mock_client_cls,
            patch("detector.views.dns.asyncresolver.Resolver", return_value=fake_resolver),
            patch("detector.views.query_maxmind", new_callable=AsyncMock, return_value=dict(MAXMIND_STUB)),
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

        serialised_quota_and_telemetry = json.dumps(
            {
                "strings": {
                    k: v
                    for k, v in fake_redis.strings.items()
                    if k.startswith(("proxycheck:v1:quota:", "proxycheck:v1:telemetry:"))
                },
                "hashes": {
                    k: v
                    for k, v in fake_redis.hashes.items()
                    if k.startswith(("proxycheck:v1:quota:", "proxycheck:v1:telemetry:"))
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

        global_key = next(key for key in fake_redis.hashes if key.startswith("proxycheck:v1:telemetry:global:day:"))
        global_hash = fake_redis.hashes[global_key]
        self.assertEqual(global_hash.get("auth_session"), "2")
        self.assertEqual(global_hash.get("auth_gadget"), "1")
        self.assertEqual(global_hash.get("cache_hit"), "1")
        self.assertEqual(global_hash.get("cache_miss"), "2")

        abuse_key = next(key for key in fake_redis.hashes if key.startswith("proxycheck:v1:telemetry:abuseipdb:day:"))
        self.assertEqual(fake_redis.hashes[abuse_key].get("upstream_remaining"), "982")
        self.assertEqual(fake_redis.hashes[abuse_key].get("upstream_limit"), "1000")
        self.assertEqual(fake_redis.hashes[abuse_key].get("ok"), "2")
        self.assertEqual(fake_redis.hashes[abuse_key].get("cache_hit"), "1")

        ipdata_key = next(key for key in fake_redis.hashes if key.startswith("proxycheck:v1:telemetry:ipdata:day:"))
        self.assertEqual(fake_redis.hashes[ipdata_key].get("upstream_used"), "142")

        ipregistry_key = next(
            key for key in fake_redis.hashes if key.startswith("proxycheck:v1:telemetry:ipregistry:day:")
        )
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
            patch("detector.views.redis_client", fake_redis),
            patch("detector.views.httpx.AsyncClient") as mock_client_cls,
            patch("detector.views.dns.asyncresolver.Resolver", return_value=fake_resolver),
            patch("detector.views.query_maxmind", new_callable=AsyncMock, return_value=dict(MAXMIND_STUB)),
        ):
            _patch_async_client(mock_client_cls, fake_get)
            first_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")
            second_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")

        self.assertEqual(first_resp.status_code, 200)
        self.assertEqual(second_resp.status_code, 200)
        self.assertEqual(second_resp.json()["cacheMeta"]["status"], "partial")

        global_key = next(key for key in fake_redis.hashes if key.startswith("proxycheck:v1:telemetry:global:day:"))
        self.assertEqual(fake_redis.hashes[global_key].get("cache_miss"), "1")
        self.assertEqual(fake_redis.hashes[global_key].get("cache_partial"), "1")

        abuse_key = next(key for key in fake_redis.hashes if key.startswith("proxycheck:v1:telemetry:abuseipdb:day:"))
        self.assertEqual(fake_redis.hashes[abuse_key].get("429"), "1")

        ipregistry_key = next(
            key for key in fake_redis.hashes if key.startswith("proxycheck:v1:telemetry:ipregistry:day:")
        )
        self.assertEqual(fake_redis.hashes[ipregistry_key].get("5xx"), "1")

        proxycheck_key = next(
            key for key in fake_redis.hashes if key.startswith("proxycheck:v1:telemetry:proxycheck:day:")
        )
        self.assertEqual(fake_redis.hashes[proxycheck_key].get("timeout"), "1")

    def test_admin_provider_dashboard_only_honours_allowlisted_wiki_users(self):
        fake_redis = FakeAsyncRedis()
        gadget_client = self.client.__class__()
        gadget_token = views.issue_gadget_token("AllowlistedDashboardAdmin")

        with patch("detector.views.redis_client", fake_redis):
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

        fake_redis.strings[f"proxycheck:v1:quota:getipintel:min:{min_bucket}"] = "15"
        fake_redis.strings[f"proxycheck:v1:quota:getipintel:day:{day_bucket}"] = "320"
        fake_redis.strings["proxycheck:v1:cooldown:ipregistry"] = json.dumps({"reason": "HTTP 429"})
        fake_redis.ttls["proxycheck:v1:cooldown:ipregistry"] = 95

        fake_redis.hashes[f"proxycheck:v1:telemetry:global:day:{day_bucket}"] = {
            "auth_session": "7",
            "auth_gadget": "3",
            "cache_hit": "4",
            "cache_partial": "2",
            "cache_miss": "4",
        }
        fake_redis.hashes[f"proxycheck:v1:telemetry:getipintel:day:{day_bucket}"] = {
            "ok": "11",
            "cache_hit": "4",
            "quota_blocked": "2",
            "429": "0",
            "5xx": "0",
            "timeout": "0",
        }
        fake_redis.hashes[f"proxycheck:v1:telemetry:proxycheck:day:{day_bucket}"] = {
            "ok": "9",
            "cache_hit": "6",
            "upstream_remaining": "991",
            "upstream_limit": "1000",
            "last_status_at": "2026-11-15T10:29:00+00:00",
        }

        _login_authorised(self)
        fake_dt_cls = MagicMock()
        fake_dt_cls.now.return_value = now_dt
        with patch("detector.views.redis_client", fake_redis), patch("detector.quota_telemetry.datetime", fake_dt_cls):
            response = self.client.get("/api/v1/admin/provider-dashboard")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["redisAvailable"])
        self.assertEqual(payload["dateBucket"], day_bucket)

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

        providers = {row["key"]: row for row in payload["providers"]}
        self.assertEqual(set(providers.keys()), {spec[0] for spec in views._PROVIDER_SPECS})

        self.assertEqual(providers["abuseipdb"]["status"], "No API Key")
        self.assertEqual(providers["abuseipdb"]["statusKey"], "no_api_key")
        self.assertFalse(providers["abuseipdb"]["configured"])

        self.assertEqual(providers["getipintel"]["status"], "Quota Guarded")
        self.assertEqual(providers["getipintel"]["statusKey"], "quota_guarded")
        self.assertEqual(providers["getipintel"]["minuteUsed"], 15)
        self.assertEqual(providers["getipintel"]["minuteLimit"], 15)
        self.assertEqual(providers["getipintel"]["telemetry"]["quotaBlocked"], 2)

        self.assertEqual(providers["ipregistry"]["status"], "Cooldown (95s)")
        self.assertEqual(providers["ipregistry"]["statusKey"], "cooldown")
        self.assertEqual(providers["ipregistry"]["cooldownTtlSeconds"], 95)
        self.assertEqual(providers["ipregistry"]["cooldownReason"], "HTTP 429")

        self.assertEqual(providers["proxycheck"]["status"], "Healthy")
        self.assertEqual(providers["proxycheck"]["statusKey"], "healthy")
        self.assertEqual(providers["proxycheck"]["upstreamRemaining"], 991)
        self.assertEqual(providers["proxycheck"]["upstreamLimit"], 1000)
        self.assertEqual(providers["proxycheck"]["telemetry"]["cacheHit"], 6)

    def test_redis_key_builders_use_proxycheck_v1_namespace(self):
        from datetime import datetime, timezone

        from detector import quota_telemetry

        sample_dt = datetime(2026, 11, 15, 10, 30, tzinfo=timezone.utc)
        self.assertEqual(views._provider_cache_key("proxycheck", "8.8.8.8"), "proxycheck:v1:prov:proxycheck:8.8.8.8")
        self.assertEqual(views._provider_cooldown_key("proxycheck"), "proxycheck:v1:cooldown:proxycheck")
        self.assertEqual(
            quota_telemetry._quota_minute_key("getipintel", sample_dt),
            "proxycheck:v1:quota:getipintel:min:202611151030",
        )
        self.assertEqual(
            quota_telemetry._quota_daily_key("getipintel", sample_dt),
            "proxycheck:v1:quota:getipintel:day:20261115",
        )
        self.assertEqual(
            quota_telemetry._provider_telemetry_key("getipintel", sample_dt),
            "proxycheck:v1:telemetry:getipintel:day:20261115",
        )
        self.assertEqual(
            quota_telemetry._global_telemetry_key(sample_dt),
            "proxycheck:v1:telemetry:global:day:20261115",
        )

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
            patch("detector.views.redis_client", fake_redis),
            patch("detector.views.httpx.AsyncClient") as mock_client_cls,
            patch("detector.views.dns.asyncresolver.Resolver", return_value=fake_resolver),
            patch("detector.views.query_maxmind", new_callable=AsyncMock, return_value=dict(MAXMIND_STUB)),
        ):
            _patch_async_client(mock_client_cls, fake_get)
            response = self.client.get("/api/v1/detect?ip=8.8.8.8")

        self.assertEqual(response.status_code, 200)

        # ConnectError and TimeoutException must roll back both minute and daily quota counters to zero
        for refunded_provider in ("getipintel", "proxycheck"):
            min_key = next(
                key for key in fake_redis.strings if key.startswith(f"proxycheck:v1:quota:{refunded_provider}:min:")
            )
            day_key = next(
                key for key in fake_redis.strings if key.startswith(f"proxycheck:v1:quota:{refunded_provider}:day:")
            )
            self.assertEqual(fake_redis.strings[min_key], "0")
            self.assertEqual(fake_redis.strings[day_key], "0")

        # Valid HTTP 200 and HTTP 429 responses must retain their consumed quota count
        for retained_provider in ("abuseipdb", "ipdata"):
            min_key = next(
                key for key in fake_redis.strings if key.startswith(f"proxycheck:v1:quota:{retained_provider}:min:")
            )
            day_key = next(
                key for key in fake_redis.strings if key.startswith(f"proxycheck:v1:quota:{retained_provider}:day:")
            )
            self.assertEqual(fake_redis.strings[min_key], "1")
            self.assertEqual(fake_redis.strings[day_key], "1")

class CheckSetupCommandTests(SimpleTestCase):
    """Tests environment detection, secret masking, interactive completion, and job checks."""

    def test_secret_masking_and_redis_url_redaction(self):
        from detector.management.commands import check_setup

        self.assertEqual(check_setup.mask_secret(""), "")
        self.assertEqual(check_setup.mask_secret("abc"), "***")
        self.assertEqual(check_setup.mask_secret("abcd1234"), "a******4")
        self.assertEqual(check_setup.mask_secret("1234567890"), "12...90")
        self.assertEqual(check_setup.mask_secret("sk_live_abcdefgh_9876"), "sk_l...9876")
        self.assertEqual(
            check_setup.redact_url_credentials("redis://:supersecret@redis.example.org:6379/0"),
            "redis://:***@redis.example.org:6379/0",
        )
        self.assertEqual(
            check_setup.redact_url_credentials("redis://127.0.0.1:6379/0"),
            "redis://127.0.0.1:6379/0",
        )

    def test_environment_detection_and_toolforge_account_resolution(self):
        from django.core.management.base import CommandError

        from detector.management.commands import check_setup

        with tempfile.TemporaryDirectory() as tmp_dir:
            wmcs_file = Path(tmp_dir) / "wmcs-project"
            wmcs_file.write_text("tools\n", encoding="utf-8")

            mode, toolforge_bin, account = check_setup.detect_runtime_environment(
                "auto",
                environ={"USER": "tools.proxycheck-dev", "HOME": "/data/project/proxycheck-dev"},
                which_fn=lambda name: "/usr/bin/toolforge" if name == "toolforge" else None,
                wmcs_project_path=wmcs_file,
            )
            self.assertEqual(mode, "bastion")
            self.assertEqual(toolforge_bin, "/usr/bin/toolforge")
            self.assertEqual(account, "proxycheck-dev")

            container_mode, _, container_account = check_setup.detect_runtime_environment(
                "auto",
                environ={
                    "CNB_STACK_ID": "heroku-22",
                    "TOOL_DATA_DIR": "/data/project/proxycheck",
                },
                which_fn=lambda _name: None,
                wmcs_project_path=Path(tmp_dir) / "absent",
            )
            self.assertEqual(container_mode, "local")
            self.assertEqual(container_account, "proxycheck")

            with self.assertRaises(CommandError):
                check_setup.detect_runtime_environment(
                    "bastion",
                    environ={},
                    which_fn=lambda _name: None,
                )

    def test_local_no_input_masks_secrets_and_strict_mode_fails_on_missing_required(self):
        import io

        from django.core.management import call_command
        from django.core.management.base import CommandError

        with tempfile.TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            project_root = workspace / "proxycheck"
            project_root.mkdir()
            (project_root / ".env").write_text(
                "DJANGO_SECRET_KEY='very-secret-key-abcdef123456'\nABUSEIPDB_API_KEY='abuse-secret-token-xyz9'\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            stderr = io.StringIO()
            clean_env = {
                key: val
                for key, val in os.environ.items()
                if key not in ("DJANGO_SECRET_KEY", "WIKIMEDIA_CLIENT_ID", "WIKIMEDIA_CLIENT_SECRET", "TOOL_DATA_DIR")
            }
            with (
                override_settings(BASE_DIR=project_root),
                patch.dict(os.environ, clean_env, clear=True),
                patch("pathlib.Path.home", return_value=workspace / "home"),
            ):
                call_command("check_setup", no_input=True, env_mode="local", stdout=stdout, stderr=stderr)
                output = stdout.getvalue()
                self.assertIn("very...3456", output)
                self.assertNotIn("very-secret-key-abcdef123456", output)
                self.assertIn("abus...xyz9", output)
                self.assertNotIn("abuse-secret-token-xyz9", output)
                self.assertIn("WIKIMEDIA_CLIENT_ID: MISSING", output)
                self.assertIn("Tuning & Quota Limits (38 optional vars)", output)

                with self.assertRaises(CommandError):
                    call_command(
                        "check_setup",
                        no_input=True,
                        env_mode="local",
                        strict=True,
                        stdout=io.StringIO(),
                        stderr=io.StringIO(),
                    )

    def test_local_interactive_writes_dotenv_ensures_gitignore_and_creates_directory(self):
        import io

        from django.core.management import call_command
        from dotenv import dotenv_values

        with tempfile.TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            project_root = workspace / "proxycheck"
            project_root.mkdir()
            (project_root / ".gitignore").write_text("*.pyc\n", encoding="utf-8")

            stdout = io.StringIO()
            # Required prompts: DJANGO_SECRET_KEY (gen), WIKIMEDIA_CLIENT_ID, WIKIMEDIA_CLIENT_SECRET
            # Recommended prompts (7): all skipped via empty string
            # Provider yes/no: N
            # Missing directory prompt: y
            getpass_answers = iter(["gen", "wiki-secret-1234567890", "", ""])
            input_answers = iter(["wiki-client-id", "", "", "", "", "", "N", "y"])

            clean_env = {
                key: val
                for key, val in os.environ.items()
                if key
                not in (
                    "DJANGO_SECRET_KEY",
                    "WIKIMEDIA_CLIENT_ID",
                    "WIKIMEDIA_CLIENT_SECRET",
                    "DJANGO_ALLOWED_HOSTS",
                    "WIKIMEDIA_REDIRECT_URI",
                    "REDIS_URL",
                    "TOOL_DATA_DIR",
                    "MAXMIND_ACCOUNT_ID",
                    "MAXMIND_LICENSE_KEY",
                    "ALLOWED_WIKI_USERS",
                )
            }
            with (
                override_settings(BASE_DIR=project_root),
                patch.dict(os.environ, clean_env, clear=True),
                patch("pathlib.Path.home", return_value=workspace / "home"),
                patch("getpass.getpass", side_effect=lambda _prompt="": next(getpass_answers)),
                patch("builtins.input", side_effect=lambda _prompt="": next(input_answers)),
            ):
                call_command("check_setup", env_mode="local", stdout=stdout, stderr=io.StringIO())

            written_env = dotenv_values(project_root / ".env")
            self.assertEqual(len(written_env["DJANGO_SECRET_KEY"]), 50)
            self.assertEqual(written_env["WIKIMEDIA_CLIENT_ID"], "wiki-client-id")
            self.assertEqual(written_env["WIKIMEDIA_CLIENT_SECRET"], "wiki-secret-1234567890")
            self.assertNotIn(written_env["DJANGO_SECRET_KEY"], stdout.getvalue())
            self.assertNotIn("wiki-secret-1234567890", stdout.getvalue())
            self.assertIn(".env", (project_root / ".gitignore").read_text(encoding="utf-8").splitlines())
            self.assertTrue((workspace / "data").is_dir())

    def test_bastion_interactive_uses_stdin_for_envvars_and_adapts_dev_jobs(self):
        import io
        import subprocess

        from django.core.management import call_command

        from detector.management.commands import check_setup

        with tempfile.TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            project_root = workspace / "proxycheck"
            project_root.mkdir()
            (project_root / "jobs.yaml").write_text(
                "---\n"
                "- name: update-sfs-db\n"
                "  command: python manage.py update_offline_dbs --sources stopforumspam\n"
                "  image: tool-proxycheck/tool-proxycheck:latest\n"
                '  schedule: "@hourly"\n'
                "  mount: all\n"
                "- name: update-maxmind-db\n"
                "  command: python manage.py update_offline_dbs --sources maxmind\n"
                "  image: tool-proxycheck/tool-proxycheck:latest\n"
                '  schedule: "@daily"\n'
                "  mount: all\n",
                encoding="utf-8",
            )
            home_dir = workspace / "home"
            (home_dir / "data").mkdir(parents=True)

            recorded_calls = []

            def _fake_run(cmd, *, input=None, text=None, capture_output=None, timeout=None, check=None):
                recorded_calls.append((list(cmd), input))
                if cmd[1:] == ["envvars", "list", "--show-values"]:
                    return subprocess.CompletedProcess(
                        cmd,
                        0,
                        stdout=(
                            "name                    value\n"
                            "DJANGO_ALLOWED_HOSTS     localhost\n"
                            "WIKIMEDIA_REDIRECT_URI  https://proxycheck.toolforge.org/oauth/callback\n"
                        ),
                        stderr="",
                    )
                if cmd[1:] == ["jobs", "list", "--output", "long"]:
                    return subprocess.CompletedProcess(cmd, 0, stdout="No jobs found.\n", stderr="")
                if cmd[1:3] == ["envvars", "create"]:
                    return subprocess.CompletedProcess(cmd, 0, stdout=f"name value\n{cmd[3]} ***\n", stderr="")
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            # Missing required: DJANGO_SECRET_KEY (gen), WIKIMEDIA_CLIENT_ID, WIKIMEDIA_CLIENT_SECRET
            # Attention recommended: DJANGO_ALLOWED_HOSTS (local only), WIKIMEDIA_REDIRECT_URI (prod URL on dev),
            # REDIS_URL (missing), TOOL_DATA_DIR, MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY, ALLOWED_WIKI_USERS
            # Provider y/N -> y, then 9 provider prompts (first set, remaining 8 skipped)
            getpass_answers = iter(
                [
                    "gen",
                    "wiki-secret-bastion-0001",
                    "",
                    "",
                    "",
                    "abuse-key-bastion-1234",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                ]
            )
            input_answers = iter(
                [
                    "wiki-client-bastion",
                    "localhost,127.0.0.1,.toolforge.org,.wmcloud.org",
                    "https://proxycheck-dev.toolforge.org/oauth/callback",
                    "",
                    "",
                    "",
                    "y",
                ]
            )

            stdout = io.StringIO()
            bastion_env = {
                "USER": "tools.proxycheck-dev",
                "HOME": str(home_dir),
            }
            with (
                override_settings(BASE_DIR=project_root),
                patch.dict(os.environ, bastion_env, clear=True),
                patch("pathlib.Path.home", return_value=home_dir),
                patch.object(check_setup.shutil, "which", return_value="/usr/bin/toolforge"),
                patch.object(check_setup.subprocess, "run", side_effect=_fake_run),
                patch("getpass.getpass", side_effect=lambda _prompt="": next(getpass_answers)),
                patch("builtins.input", side_effect=lambda _prompt="": next(input_answers)),
            ):
                call_command("check_setup", env_mode="bastion", stdout=stdout, stderr=io.StringIO())

            output = stdout.getvalue()
            create_calls = [(cmd, val) for cmd, val in recorded_calls if cmd[1:3] == ["envvars", "create"]]
            created_keys = [cmd[3] for cmd, _ in create_calls]
            self.assertEqual(
                created_keys,
                [
                    "DJANGO_SECRET_KEY",
                    "WIKIMEDIA_CLIENT_ID",
                    "WIKIMEDIA_CLIENT_SECRET",
                    "DJANGO_ALLOWED_HOSTS",
                    "WIKIMEDIA_REDIRECT_URI",
                    "ABUSEIPDB_API_KEY",
                ],
            )
            # Secret values must pass via stdin, never as CLI argv elements
            for cmd, stdin_val in create_calls:
                self.assertEqual(len(cmd), 4)
                self.assertTrue(stdin_val)

            self.assertIn("tool-proxycheck-dev/tool-proxycheck-dev:latest", output)
            self.assertIn("toolforge webservice buildservice restart --mount=all", output)
            self.assertIn('--schedule "@hourly"', output)
            self.assertIn('--schedule "@daily"', output)
            self.assertEqual(output.count("tmp_jobs=$(mktemp)"), 1)

    def test_bastion_fallback_envvars_show_matching_jobs_and_nfs_mount_detection(self):
        import io
        import subprocess

        from django.core.management import call_command

        from detector.management.commands import check_setup

        with tempfile.TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            project_root = workspace / "proxycheck"
            project_root.mkdir()
            (project_root / "jobs.yaml").write_text(
                "---\n"
                "- name: update-sfs-db\n"
                "  command: python manage.py update_offline_dbs --sources stopforumspam\n"
                "  image: tool-proxycheck/tool-proxycheck:latest\n"
                '  schedule: "@hourly"\n'
                "  mount: all\n"
                "- name: update-maxmind-db\n"
                "  command: python manage.py update_offline_dbs --sources maxmind\n"
                "  image: tool-proxycheck/tool-proxycheck:latest\n"
                '  schedule: "@daily"\n'
                "  mount: all\n",
                encoding="utf-8",
            )
            data_dir = workspace / "data"
            data_dir.mkdir()
            mounts_file = workspace / "mounts"
            mounts_file.write_text(
                f"nfs.svc:/tools {workspace.as_posix()} nfs4 rw,relatime 0 0\n",
                encoding="utf-8",
            )

            def _fake_run(cmd, *, input=None, text=None, capture_output=None, timeout=None, check=None):
                if cmd[1:] == ["envvars", "list", "--show-values"]:
                    return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="unknown option --show-values")
                if cmd[1:] == ["envvars", "list"]:
                    return subprocess.CompletedProcess(
                        cmd,
                        0,
                        stdout="name\nDJANGO_SECRET_KEY\nWIKIMEDIA_CLIENT_ID\nWIKIMEDIA_CLIENT_SECRET\n",
                        stderr="",
                    )
                if cmd[1:3] == ["envvars", "show"]:
                    key = cmd[3]
                    if key == "DJANGO_SECRET_KEY":
                        return subprocess.CompletedProcess(cmd, 0, stdout="********\n", stderr="")
                    return subprocess.CompletedProcess(cmd, 0, stdout=f"{key} value-{key}-12345\n", stderr="")
                if cmd[1:] == ["jobs", "list", "--output", "long"]:
                    return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="unknown option --output")
                if cmd[1:] == ["jobs", "list"]:
                    return subprocess.CompletedProcess(
                        cmd,
                        0,
                        stdout=(
                            "Job name:              Job type:              Status:\n"
                            "---------------------- ---------------------- -------------------\n"
                            "update-offline-dbs     scheduled: 0 * * * *   Waiting for next\n"
                        ),
                        stderr="",
                    )
                if cmd[1:] == ["jobs", "show", "update-offline-dbs"]:
                    return subprocess.CompletedProcess(
                        cmd,
                        0,
                        stdout=(
                            "Job name: update-offline-dbs\n"
                            "Command: python manage.py update_offline_dbs\n"
                            "Image: tool-proxycheck/tool-proxycheck:latest\n"
                            "Schedule: 0 * * * *\n"
                            "Mount: all\n"
                        ),
                        stderr="",
                    )
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            mounts = check_setup._parse_mounts_table(mounts_file)
            mount_summary, is_ephemeral = check_setup._detect_mount_info(data_dir, mounts=mounts)
            self.assertIn("NFS (nfs4, rw)", mount_summary)
            self.assertFalse(is_ephemeral)

            stdout = io.StringIO()
            with (
                override_settings(BASE_DIR=project_root),
                patch.dict(os.environ, {"USER": "tools.proxycheck", "HOME": str(workspace)}, clear=True),
                patch("pathlib.Path.home", return_value=workspace),
                patch.object(check_setup.shutil, "which", return_value="/usr/bin/toolforge"),
                patch.object(check_setup.subprocess, "run", side_effect=_fake_run),
            ):
                call_command("check_setup", no_input=True, env_mode="bastion", stdout=stdout, stderr=io.StringIO())

            output = stdout.getvalue()
            self.assertIn("DJANGO_SECRET_KEY: CONFIGURED (hidden by CLI", output)
            self.assertIn("update-sfs-db: OK", output)
            self.assertIn("covered by 'update-offline-dbs'", output)
            self.assertIn("Toolforge scheduled jobs match jobs.yaml.", output)

    def test_manage_py_check_setup_starts_without_secret_key(self):
        import subprocess

        manage_py = Path(__file__).resolve().parent.parent.parent / "manage.py"
        clean_env = {key: val for key, val in os.environ.items() if key not in ("DJANGO_SECRET_KEY", "DJANGO_DEBUG")}
        clean_env["DJANGO_DEBUG"] = "False"
        completed = subprocess.run(  # noqa: S603
            [sys.executable, str(manage_py), "check_setup", "--no-input", "--env", "local"],
            env=clean_env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, msg=completed.stderr)
        self.assertIn("Proxy Detector Environment Check", completed.stdout)

    def test_all_options_offline_db_health_and_job_mismatch_warnings(self):
        import io
        import subprocess

        from django.core.management import call_command

        from detector.management.commands import check_setup

        with tempfile.TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            project_root = workspace / "proxycheck"
            project_root.mkdir()
            (project_root / "jobs.yaml").write_text(
                "---\n"
                "- name: update-offline-dbs\n"
                "  command: python manage.py update_offline_dbs\n"
                "  image: tool-proxycheck/tool-proxycheck:latest\n"
                '  schedule: "0 * * * *"\n'
                "  mount: all\n",
                encoding="utf-8",
            )
            data_dir = workspace / "data"
            data_dir.mkdir()
            for fname in (
                "GeoLite2-Country.mmdb",
                "GeoLite2-City.mmdb",
                "GeoLite2-ASN.mmdb",
                "toxic_ip_cidr.txt",
                "listed_ip_90_ipv46_all.zip",
            ):
                (data_dir / fname).write_bytes(b"stub-db")
            stale_time = time.time() - (20 * 86400)
            os.utime(data_dir / "GeoLite2-Country.mmdb", (stale_time, stale_time))

            def _fake_run(cmd, *, input=None, text=None, capture_output=None, timeout=None, check=None):
                if cmd[1:] == ["envvars", "list", "--show-values"]:
                    return subprocess.CompletedProcess(
                        cmd,
                        0,
                        stdout=(
                            "name                         value\n"
                            "DJANGO_SECRET_KEY            test-secret-value-000001\n"
                            "WIKIMEDIA_CLIENT_ID          client-id\n"
                            "WIKIMEDIA_CLIENT_SECRET      client-secret-000001\n"
                            "ABUSEIPDB_DAILY_LIMIT        500\n"
                        ),
                        stderr="",
                    )
                if cmd[1:] == ["jobs", "list", "--output", "long"]:
                    return subprocess.CompletedProcess(
                        cmd,
                        0,
                        stdout=(
                            "+--------------------+---------------------------------------+-----------------------+----------------------------------------+---------+---------+\n"
                            "|     Job name:      |               Command:                |       Job type:       |                 Image:                 | Mounts: | Status: |\n"
                            "+--------------------+---------------------------------------+-----------------------+----------------------------------------+---------+---------+\n"
                            "| update-offline-dbs | python manage.py update_offline_dbs   | scheduled: 0 * * * *  | tool-proxycheck/tool-proxycheck:latest |  none   | Running |\n"
                            "+--------------------+---------------------------------------+-----------------------+----------------------------------------+---------+---------+\n"
                        ),
                        stderr="",
                    )
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            stdout = io.StringIO()
            with (
                override_settings(BASE_DIR=project_root),
                patch.dict(os.environ, {"USER": "tools.proxycheck-dev", "HOME": str(workspace)}, clear=True),
                patch("pathlib.Path.home", return_value=workspace),
                patch.object(check_setup.shutil, "which", return_value="/usr/bin/toolforge"),
                patch.object(check_setup.subprocess, "run", side_effect=_fake_run),
            ):
                call_command(
                    "check_setup",
                    no_input=True,
                    env_mode="bastion",
                    all_options=True,
                    stdout=stdout,
                    stderr=io.StringIO(),
                )

            output = stdout.getvalue()
            self.assertIn("ABUSEIPDB_DAILY_LIMIT: CUSTOMISED = 500", output)
            self.assertIn("PROVIDER_STATIC_CACHE_TTL_SECONDS: USING DEFAULT (86400)", output)
            self.assertIn("GeoLite2-Country.mmdb): STALE", output)
            self.assertIn("GeoLite2-City.mmdb): HEALTHY", output)
            self.assertIn("mount is 'none' (expected 'all')", output)
            self.assertIn("image is 'tool-proxycheck/tool-proxycheck:latest'", output)

    def test_bastion_long_prettytable_dual_jobs_shared_dirs_and_placeholder_secret(self):
        import io
        import subprocess

        from django.core.management import call_command

        from detector.management.commands import check_setup

        with tempfile.TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            project_root = workspace / "proxycheck"
            project_root.mkdir()
            (project_root / "jobs.yaml").write_text(
                "---\n"
                "- name: update-sfs-db\n"
                "  command: python manage.py update_offline_dbs --sources stopforumspam\n"
                "  image: tool-proxycheck/tool-proxycheck:latest\n"
                '  schedule: "@hourly"\n'
                "  mount: all\n"
                "- name: update-maxmind-db\n"
                "  command: python manage.py update_offline_dbs --sources maxmind\n"
                "  image: tool-proxycheck/tool-proxycheck:latest\n"
                '  schedule: "@daily"\n'
                "  mount: all\n",
                encoding="utf-8",
            )
            data_dir = workspace / "data"
            data_dir.mkdir()

            def _fake_run(cmd, *, input=None, text=None, capture_output=None, timeout=None, check=None):
                if cmd[1:] == ["envvars", "list", "--show-values"]:
                    return subprocess.CompletedProcess(
                        cmd,
                        0,
                        stdout=(
                            "name                         value\n"
                            "DJANGO_SECRET_KEY            your-placeholder-secret\n"
                            "WIKIMEDIA_CLIENT_ID          client-id\n"
                            "WIKIMEDIA_CLIENT_SECRET      client-secret-000001\n"
                            f"MAXMIND_DB_DIR               {data_dir}\n"
                            f"STOPFORUMSPAM_DB_DIR         {data_dir}\n"
                        ),
                        stderr="",
                    )
                if cmd[1:] == ["jobs", "list", "--output", "long"]:
                    return subprocess.CompletedProcess(
                        cmd,
                        0,
                        stdout=(
                            "+-------------------+---------------------------------------------------------------------+-----------------------+------------------------------------------------+---------+--------------------+\n"
                            "|     Job name:     |                              Command:                               |       Job type:       |                     Image:                     | Mounts: |      Status:       |\n"
                            "+-------------------+---------------------------------------------------------------------+-----------------------+------------------------------------------------+---------+--------------------+\n"
                            "| update-maxmind-db |    sh -c 'python manage.py update_offline_dbs --sources maxmind'    | scheduled: 22 5 * * * | tool-proxycheck-dev/tool-proxycheck-dev:latest |   all   |  Pending for 46m   |\n"
                            "|   update-sfs-db   | sh -c 'python manage.py update_offline_dbs --sources stopforumspam' | scheduled: 22 * * * * | tool-proxycheck-dev/tool-proxycheck-dev:latest |   all   | Pending for 46m15s |\n"
                            "+-------------------+---------------------------------------------------------------------+-----------------------+------------------------------------------------+---------+--------------------+\n"
                        ),
                        stderr="",
                    )
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            stdout = io.StringIO()
            with (
                override_settings(BASE_DIR=project_root),
                patch.dict(os.environ, {"USER": "tools.proxycheck-dev", "HOME": str(workspace)}, clear=True),
                patch("pathlib.Path.home", return_value=workspace),
                patch.object(check_setup.shutil, "which", return_value="/usr/bin/toolforge"),
                patch.object(check_setup.subprocess, "run", side_effect=_fake_run),
            ):
                call_command("check_setup", no_input=True, env_mode="bastion", stdout=stdout, stderr=io.StringIO())

            output = stdout.getvalue()
            self.assertIn("DJANGO_SECRET_KEY: WEAK / PLACEHOLDER", output)
            self.assertIn("not required; MAXMIND_DB_DIR and STOPFORUMSPAM_DB_DIR configured", output)
            self.assertIn("Offline data directory (MAXMIND_DB_DIR, STOPFORUMSPAM_DB_DIR, ~/data): OK", output)
            self.assertIn("NOT ON BASTION NFS", output)
            self.assertIn("update-sfs-db: OK (scheduled: 22 * * * *; Pending for 46m15s)", output)
            self.assertIn("update-maxmind-db: OK (scheduled: 22 5 * * *; Pending for 46m)", output)
            self.assertIn("Toolforge scheduled jobs match jobs.yaml.", output)
            self.assertNotIn("toolforge jobs load", output)
