"""Tests for singleflight coalescing, provider caching, circuit breaking, and client reuse."""

import asyncio
import json
import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.name
import dns.resolver
import dns.reversename
import httpx
import redis.exceptions
from django.test import AsyncRequestFactory, TestCase, override_settings

from detector import adapters, cache_backends, detection_service, http_client, providers, views
from detector.oauth import (
    fetch_project_user_rights,
    fetch_user_rights_from_meta,
    verify_centralauth_userinfo,
)

from .helpers import (
    EMPTY_UPSTREAM_SECRETS,
    MAXMIND_STUB,
    TEST_UPSTREAM_SECRETS,
    FakeAsyncRedis,
    _BatchingFakeRedis,
    _login_authorised,
    _mock_response,
    _patch_async_client,
    _ptr_or_clean_dns_side_effect,
    patch_non_dnsbl_providers,
)


class ConnectionAndReaderReuseTests(TestCase):
    """Tests event-loop-aware HTTP client reuse and lazy MaxMind reader caching."""

    def setUp(self):
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)

    def test_http_client_reused_in_same_loop_and_rebuilt_across_closed_loops(self):
        async def _acquire_twice():
            first = await http_client.get_shared_http_client()
            second = await http_client.get_shared_http_client()
            self.assertIs(first, second)
            return first

        with patch("detector.http_client.httpx.AsyncClient", wraps=httpx.AsyncClient) as spy_cls:
            client_loop_one = asyncio.run(_acquire_twice())
            self.assertEqual(spy_cls.call_count, 1)

            # Running in a new event loop after the previous one closed must rebuild the client cleanly
            client_loop_two = asyncio.run(_acquire_twice())
            self.assertEqual(spy_cls.call_count, 2)
            self.assertIsNot(client_loop_one, client_loop_two)

    @patch("detector.dns_providers.query_maxmind", new_callable=AsyncMock)
    @patch("detector.http_client.httpx.AsyncClient")
    def test_sequential_async_requests_do_not_raise_closed_event_loop_error(self, mock_async_client_cls, mock_mm):
        mock_mm.return_value = dict(MAXMIND_STUB)

        async def _ok_response(url, **kwargs):
            return _mock_response(status_code=200, json_value={"status": "ok", "block": 0})

        _patch_async_client(mock_async_client_cls, _ok_response)
        _login_authorised(self)

        with (
            override_settings(**EMPTY_UPSTREAM_SECRETS),
            patch.dict(os.environ, EMPTY_UPSTREAM_SECRETS),
            patch("detector.cache_backends.redis_client", None),
        ):
            first_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")
            second_resp = self.client.get("/api/v1/detect?ip=1.1.1.1")

        self.assertEqual(first_resp.status_code, 200)
        self.assertEqual(second_resp.status_code, 200)


class NonPublicIpInterceptionTests(TestCase):
    """Tests early 200 OK interception for loopback, private, link-local, multicast and reserved IPs."""

    def setUp(self):
        _login_authorised(self)

    @patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock)
    @patch("detector.dns_providers.query_maxmind", new_callable=AsyncMock)
    @patch("detector.http_client.httpx.AsyncClient")
    def test_non_public_ips_return_200_with_zero_external_or_redis_calls(
        self, mock_async_client_cls, mock_mm, mock_dns
    ):
        mock_redis = MagicMock()
        mock_redis.get = AsyncMock()
        mock_redis.set = AsyncMock()

        non_public_samples = (
            ("127.0.0.1", "127.0.0.1"),
            ("10.0.0.1", "10.0.0.1"),
            ("169.254.1.1", "169.254.1.1"),
            ("192.168.1.1", "192.168.1.1"),
            ("224.0.0.1", "224.0.0.1"),
            ("0.0.0.0", "0.0.0.0"),
            ("100.64.0.1", "100.64.0.1"),
            ("::1", "::1"),
            ("::", "::"),
            ("fe80::1%eth0", "fe80::1"),
            ("FE80::1%ens33", "fe80::1"),
            ("fc00::1", "fc00::1"),
            ("ff02::1", "ff02::1"),
            ("2001:db8::1", "2001:db8::1"),
            ("::ffff:127.0.0.1", "::ffff:127.0.0.1"),
        )

        with patch("detector.cache_backends.redis_client", mock_redis):
            for raw_ip, expected_canonical in non_public_samples:
                with self.subTest(raw_ip=raw_ip):
                    resp = self.client.get(f"/api/v1/detect?ip={raw_ip}")
                    self.assertEqual(resp.status_code, 200)
                    payload = resp.json()
                    self.assertEqual(payload["ip"], expected_canonical)
                    self.assertTrue(payload["isNonPublic"])
                    self.assertTrue(payload["nonPublicCategory"])
                    self.assertTrue(payload["nonPublicReason"])
                    self.assertEqual(payload["results"], [])
                    self.assertFalse(payload["isCached"])
                    self.assertEqual(payload["cacheMeta"]["status"], "bypassed")

        mock_async_client_cls.assert_not_called()
        mock_dns.assert_not_called()
        mock_mm.assert_not_called()
        mock_redis.get.assert_not_called()
        mock_redis.set.assert_not_called()

    def test_malformed_zone_id_returns_400(self):
        for raw_ip in ("fe80::1%", "fe80::1%eth 0", "fe80::1%eth0%eth1", "127.0.0.1%eth0", "fe80::1%eth/0"):
            with self.subTest(raw_ip=raw_ip):
                self.assertIsNone(views.canonicalize_ip(raw_ip))

        for bad_ip in ("fe80::1%25", "fe80::1%", "127.0.0.1%eth0"):
            with self.subTest(bad_ip=bad_ip):
                resp = self.client.get(f"/api/v1/detect?ip={bad_ip}")
                self.assertEqual(resp.status_code, 400)
                self.assertEqual(resp.json()["error"], "invalid_ip")


class SingleflightCoalescingTests(TestCase):
    """Tests singleflight coalescing of concurrent uncached IP detection requests."""

    def tearDown(self):
        detection_service._ip_detect_inflight.clear()

    async def test_five_concurrent_requests_for_uncached_ip_call_upstream_once(self):
        provider_calls = {"count": 0}
        dns_calls = {"count": 0}

        def _make_slow_ok(name):
            async def _impl(client, ip):
                if name == "Proxycheck":
                    provider_calls["count"] += 1
                    await asyncio.sleep(0.03)
                return {
                    "provider": name,
                    "status": "200 OK",
                    "statusCode": 200,
                    "asn": "AS15169",
                    "isp": "Google",
                    "organisation": "Google",
                    "location": "United States",
                    "usageType": "isp",
                    "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
                    "countryCode": "US",
                    "rawJson": {},
                }

            return _impl

        async def _fake_dns(ip):
            dns_calls["count"] += 1
            await asyncio.sleep(0.01)
            return "dns.google"

        fake_redis = _BatchingFakeRedis()
        auth_headers = {"Authorization": f"Bearer {views.issue_gadget_token('SysopUser')}"}
        factory = AsyncRequestFactory()
        requests = [factory.get("/api/v1/detect?ip=8.8.4.4", headers=auth_headers) for _ in range(5)]

        mock_client = AsyncMock()
        mock_client.is_closed = False
        with (
            patch("detector.cache_backends.redis_client", fake_redis),
            patch("detector.dns_providers.query_rdns_ptr", side_effect=_fake_dns),
            patch("detector.http_client.get_shared_http_client", AsyncMock(return_value=mock_client)),
            patch_non_dnsbl_providers(
                _make_slow_ok,
                overrides={"maxmind": AsyncMock(return_value=dict(MAXMIND_STUB))},
            ),
        ):
            responses = await asyncio.gather(*(views.detect_ip(req) for req in requests))

        self.assertEqual(len(responses), 5)
        for resp in responses:
            self.assertEqual(resp.status_code, 200)
            payload = json.loads(resp.content)
            self.assertEqual(payload["ip"], "8.8.4.4")
            self.assertEqual(payload["ptrHostname"], "dns.google")

        self.assertEqual(provider_calls["count"], 1)
        self.assertEqual(dns_calls["count"], 1)
        self.assertEqual(len(fake_redis.mget_calls), 2)
        self.assertEqual(len(fake_redis.mget_calls[0]), len(providers._PROVIDER_SPECS) + 1)
        self.assertEqual(len(detection_service._ip_detect_inflight), 0)

    async def test_shield_protects_shared_inflight_task_when_one_waiter_cancels(self):
        started = asyncio.Event()
        release = asyncio.Event()
        provider_calls = {"count": 0}

        def _make_gated_provider(name):
            async def _impl(client, ip):
                if name == "Proxycheck":
                    provider_calls["count"] += 1
                    started.set()
                    await release.wait()
                return {
                    "provider": name,
                    "status": "200 OK",
                    "statusCode": 200,
                    "asn": "AS15169",
                    "isp": "Google",
                    "organisation": "Google",
                    "location": "United States",
                    "usageType": "isp",
                    "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
                    "countryCode": "US",
                    "rawJson": {},
                }

            return _impl

        auth_headers = {"Authorization": f"Bearer {views.issue_gadget_token('SysopUser')}"}
        mock_client = AsyncMock()
        mock_client.is_closed = False
        factory = AsyncRequestFactory()
        req_one = factory.get("/api/v1/detect?ip=8.8.4.4", headers=auth_headers)
        req_two = factory.get("/api/v1/detect?ip=8.8.4.4", headers=auth_headers)

        with (
            patch("detector.cache_backends.redis_client", None),
            patch("detector.http_client.get_shared_http_client", AsyncMock(return_value=mock_client)),
            patch("detector.dns_providers.query_rdns_ptr", AsyncMock(return_value=None)),
            patch_non_dnsbl_providers(
                _make_gated_provider,
                overrides={"maxmind": AsyncMock(return_value=dict(MAXMIND_STUB))},
            ),
        ):
            first_task = asyncio.create_task(views.detect_ip(req_one))
            await started.wait()
            second_task = asyncio.create_task(views.detect_ip(req_two))
            await asyncio.sleep(0)

            first_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await first_task

            release.set()
            second_resp = await second_task

        self.assertEqual(second_resp.status_code, 200)
        self.assertEqual(json.loads(second_resp.content)["ip"], "8.8.4.4")
        self.assertEqual(provider_calls["count"], 1)
        self.assertEqual(len(detection_service._ip_detect_inflight), 0)

    async def test_inflight_map_cleaned_up_on_unexpected_exception(self):
        auth_headers = {"Authorization": f"Bearer {views.issue_gadget_token('SysopUser')}"}

        with (
            patch("detector.cache_backends.redis_client", None),
            patch(
                "detector.detection_service._execute_detection_with_cache", AsyncMock(side_effect=RuntimeError("boom"))
            ),
            self.assertRaises(RuntimeError),
        ):
            await self.async_client.get("/api/v1/detect?ip=8.8.4.4", headers=auth_headers)

        self.assertEqual(len(detection_service._ip_detect_inflight), 0)

    async def test_concurrent_waiters_receive_independent_payload_copies(self):
        shared_payload = {"ip": "8.8.4.4", "results": [], "cacheMeta": {"status": "miss"}}

        async def _slow_cache_read(ip):
            await asyncio.sleep(0.02)
            return {}, None

        with (
            patch("detector.detection_service._read_provider_caches", side_effect=_slow_cache_read),
            patch("detector.detection_service._execute_detection_with_cache", AsyncMock(return_value=shared_payload)),
            patch("detector.quota_telemetry.record_global_request_telemetry", AsyncMock()),
        ):
            payloads = await asyncio.gather(
                *(
                    detection_service._detect_single_canonical_ip("8.8.4.4", "gadget", time.perf_counter())
                    for _ in range(5)
                )
            )

        self.assertEqual(len({id(payload) for payload in payloads}), 5)
        for payload in payloads:
            self.assertIsNot(payload, shared_payload)
            self.assertIn("durationSeconds", payload)
        self.assertNotIn("durationSeconds", shared_payload)
        self.assertEqual(len(detection_service._ip_detect_inflight), 0)


class PerProviderCacheAndCircuitBreakerTests(TestCase):
    """Tests per-provider tiered TTL caching and HTTP 429 or 5xx cooldown circuit breaking."""

    def setUp(self):
        _login_authorised(self)

    def test_retry_after_header_parsed_and_clamped_within_cooldown_bounds(self):
        self.assertEqual(providers._parse_retry_after_seconds("15"), 60)
        self.assertEqual(providers._parse_retry_after_seconds("180"), 180)
        self.assertEqual(providers._parse_retry_after_seconds("999"), 300)
        self.assertEqual(providers._parse_retry_after_seconds("Wed, 21 Oct 2015 07:28:00 GMT"), 120)
        self.assertEqual(providers._parse_retry_after_seconds(None), 120)

    def _ok_upstream_response(self, url, ip="8.8.8.8"):
        if "ipregistry.co" in url:
            return _mock_response(
                status_code=200,
                json_value={
                    "company": {"name": "Google"},
                    "connection": {"asn": 15169, "type": "isp"},
                    "location": {"country": {"name": "United States", "code": "US"}},
                    "security": {},
                },
            )
        if "ip2location.io" in url:
            return _mock_response(
                status_code=200,
                json_value={"asn": "15169", "as": "Google", "country_name": "United States", "country_code": "US"},
            )
        if "ipdata.co" in url:
            return _mock_response(
                status_code=200,
                json_value={
                    "asn": {"asn": "AS15169", "name": "Google", "type": "isp"},
                    "country_name": "United States",
                    "country_code": "US",
                    "threat": {},
                },
            )
        if "abuseipdb.com" in url:
            return _mock_response(
                status_code=200, json_value={"data": {"isp": "Google", "countryCode": "US", "abuseConfidenceScore": 0}}
            )
        if "getipintel.net" in url:
            return _mock_response(status_code=200, json_value={"status": "success", "result": "0.0"})
        if "proxycheck.io" in url:
            return _mock_response(
                status_code=200,
                json_value={
                    "status": "ok",
                    ip: {"asn": "AS15169", "provider": "Google", "country": "United States", "isocode": "US"},
                },
            )
        if "iphub.info" in url:
            return _mock_response(
                status_code=200,
                json_value={
                    "asn": 15169,
                    "isp": "Google",
                    "countryName": "United States",
                    "countryCode": "US",
                    "block": 0,
                },
            )
        if "iphunter.info" in url:
            return _mock_response(
                status_code=200,
                json_value={
                    "status": "success",
                    "data": {"isp": "Google", "country_name": "United States", "country_code": "US", "block": 0},
                },
            )
        if "onionoo.torproject.org" in url:
            return _mock_response(status_code=200, json_value={"relays": []})
        if "stopforumspam.org" in url:
            return _mock_response(
                status_code=200, json_value={"success": 1, "ip": {"appears": 0, "frequency": 0, "confidence": 0.0}}
            )
        if "sans.edu" in url or "dshield" in url:
            return _mock_response(status_code=200, json_value={"ip": {"attacks": 0, "count": 0}})
        return _mock_response(
            status_code=200,
            json_value={
                "success": True,
                "result": {
                    "location": {"countryName": "United States", "countryCode": "US"},
                    "asn": {"asn": 15169, "name": "Google"},
                },
            },
        )

    @patch(
        "dns.asyncresolver.Resolver.resolve",
        new_callable=AsyncMock,
        side_effect=_ptr_or_clean_dns_side_effect(ptr_hostname="dns.google."),
    )
    @patch("detector.dns_providers.query_maxmind", new_callable=AsyncMock)
    @patch("detector.http_client.httpx.AsyncClient")
    def test_provider_429_triggers_cooldown_skip_without_overwriting_valid_caches(
        self, mock_async_client_cls, mock_mm, _mock_dns
    ):
        mock_mm.return_value = dict(MAXMIND_STUB)

        historical_proxycheck_1111 = json.dumps(
            {
                "row": {
                    "provider": "Proxycheck",
                    "status": "200 OK",
                    "statusCode": 200,
                    "asn": "AS13335",
                    "isp": "Cloudflare",
                    "organisation": "Cloudflare",
                    "location": "United States",
                    "usageType": "cdn",
                    "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
                    "countryCode": "US",
                    "rawJson": {},
                },
                "cachedAt": "2026-11-13T07:00:00+00:00",
            }
        )
        proxycheck_1111_key = cache_backends.provider_cache_key("proxycheck", "1.1.1.1")
        cache_store = {
            proxycheck_1111_key: historical_proxycheck_1111,
        }
        written_ttls = {}
        requested_urls = []

        async def _fake_get(key):
            return cache_store.get(key)

        async def _fake_set(key, val, ex=None, nx=False):
            if nx and key in cache_store:
                return False
            cache_store[key] = val
            written_ttls[key] = ex
            return True

        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(side_effect=_fake_get)
        mock_redis.set = AsyncMock(side_effect=_fake_set)

        async def _upstream_side_effect(url, **kwargs):
            requested_urls.append(url)
            if "proxycheck.io" in url:
                resp = _mock_response(status_code=429, json_value={"status": "error", "message": "Rate limited"})
                resp.headers = {"Retry-After": "180"}
                return resp
            return self._ok_upstream_response(url, ip="8.8.8.8")

        _patch_async_client(mock_async_client_cls, _upstream_side_effect)

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.cache_backends.redis_client", mock_redis),
        ):
            first_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")

        self.assertEqual(first_resp.status_code, 200)
        first_payload = first_resp.json()
        first_rows = {row["provider"]: row for row in first_payload["results"]}
        self.assertEqual(first_rows["Proxycheck"]["statusCode"], 429)
        proxycheck_cd_key = cache_backends.provider_cooldown_key("proxycheck")
        self.assertIn(proxycheck_cd_key, cache_store)
        self.assertEqual(written_ttls[proxycheck_cd_key], 180)
        self.assertNotIn(cache_backends.provider_cache_key("proxycheck", "8.8.8.8"), cache_store)
        self.assertEqual(cache_store[proxycheck_1111_key], historical_proxycheck_1111)

        for healthy_key in (
            "cloudflare_radar",
            "abuseipdb",
            "ipdata",
            "ipregistry",
            "ip2location",
            "iphub",
            "iphunter",
            "shodan_internetdb",
        ):
            healthy_cache_key = cache_backends.provider_cache_key(healthy_key, "8.8.8.8")
            self.assertIn(healthy_cache_key, cache_store)
            self.assertEqual(written_ttls[healthy_cache_key], 86400)
        gii_key = cache_backends.provider_cache_key("getipintel", "8.8.8.8")
        self.assertIn(gii_key, cache_store)
        self.assertEqual(written_ttls[gii_key], 259200)
        self.assertEqual(written_ttls[cache_backends.provider_cache_key("ptr", "8.8.8.8")], 7200)

        requested_urls.clear()
        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.cache_backends.redis_client", mock_redis),
        ):
            second_resp = self.client.get("/api/v1/detect?ip=9.9.9.9")

        self.assertEqual(second_resp.status_code, 200)
        self.assertFalse(any("proxycheck.io" in u for u in requested_urls))
        second_rows = {row["provider"]: row for row in second_resp.json()["results"]}
        self.assertTrue(second_rows["Proxycheck"].get("isCooldown"))
        self.assertIn("429 Cooldown", second_rows["Proxycheck"]["status"])
        self.assertIn(cache_backends.provider_cache_key("cloudflare_radar", "9.9.9.9"), cache_store)

        requested_urls.clear()
        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.cache_backends.redis_client", mock_redis),
        ):
            historical_resp = self.client.get("/api/v1/detect?ip=1.1.1.1")

        self.assertEqual(historical_resp.status_code, 200)
        historical_rows = {row["provider"]: row for row in historical_resp.json()["results"]}
        self.assertEqual(historical_rows["Proxycheck"]["status"], "200 OK")
        self.assertEqual(historical_rows["Proxycheck"]["isp"], "Cloudflare")
        self.assertFalse(any("proxycheck.io" in u for u in requested_urls))

    @patch(
        "dns.asyncresolver.Resolver.resolve",
        new_callable=AsyncMock,
        side_effect=_ptr_or_clean_dns_side_effect(ptr_hostname="dns.google."),
    )
    @patch("detector.dns_providers.query_maxmind", new_callable=AsyncMock)
    @patch("detector.http_client.httpx.AsyncClient")
    def test_timeout_triggers_default_cooldown_and_respects_ttl_settings(
        self, mock_async_client_cls, mock_mm, _mock_dns
    ):
        mock_mm.return_value = dict(MAXMIND_STUB)
        cache_store = {}
        written_ttls = {}

        async def _fake_get(key):
            return cache_store.get(key)

        async def _fake_set(key, val, ex=None, nx=False):
            if nx and key in cache_store:
                return False
            cache_store[key] = val
            written_ttls[key] = ex
            return True

        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(side_effect=_fake_get)
        mock_redis.set = AsyncMock(side_effect=_fake_set)

        async def _timeout_proxycheck(url, **kwargs):
            if "proxycheck.io" in url:
                raise httpx.ReadTimeout("timed out")
            return self._ok_upstream_response(url, ip="8.8.8.8")

        _patch_async_client(mock_async_client_cls, _timeout_proxycheck)

        with (
            override_settings(
                **TEST_UPSTREAM_SECRETS,
                PROVIDER_STATIC_CACHE_TTL_SECONDS=43200,
                PROVIDER_DYNAMIC_CACHE_TTL_SECONDS=1800,
            ),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.cache_backends.redis_client", mock_redis),
        ):
            resp = self.client.get("/api/v1/detect?ip=8.8.8.8")
            self.assertEqual(cache_backends._get_provider_cache_ttl("dnsbl"), 1800)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(written_ttls.get(cache_backends.provider_cooldown_key("proxycheck")), 120)
        self.assertNotIn(cache_backends.provider_cache_key("proxycheck", "8.8.8.8"), cache_store)
        self.assertEqual(written_ttls.get(cache_backends.provider_cache_key("ptr", "8.8.8.8")), 1800)
        self.assertEqual(written_ttls.get(cache_backends.provider_cache_key("cloudflare_radar", "8.8.8.8")), 43200)

    def test_getipintel_stable_scores_extend_cache_ttl(self):
        stable_low_row = adapters.adapt_getipintel({"status": "success", "result": "0.05"}, True, 200)
        stable_high_row = adapters.adapt_getipintel({"status": "success", "result": "0.95"}, True, 200)
        uncertain_row = adapters.adapt_getipintel({"status": "success", "result": "0.50"}, True, 200)

        self.assertEqual(cache_backends._get_provider_cache_ttl("getipintel", stable_low_row), 259200)
        self.assertEqual(cache_backends._get_provider_cache_ttl("getipintel", stable_high_row), 259200)
        self.assertEqual(cache_backends._get_provider_cache_ttl("getipintel", uncertain_row), 86400)
        self.assertEqual(cache_backends._get_provider_cache_ttl("getipintel"), 86400)

        with override_settings(PROVIDER_STATIC_CACHE_TTL_SECONDS=86400, GETIPINTEL_STABLE_CACHE_TTL_SECONDS=604800):
            self.assertEqual(cache_backends._get_provider_cache_ttl("getipintel", stable_low_row), 604800)
            self.assertEqual(cache_backends._get_provider_cache_ttl("getipintel", uncertain_row), 86400)


class HttpClientLifecycleTests(TestCase):
    """Tests cookieless HTTP client isolation across concurrent Wikimedia API calls."""

    async def test_concurrent_wikimedia_api_calls_on_cookieless_client_preserve_isolation(self):
        captured_requests = []

        def _handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(
                (str(request.url), request.headers.get("cookie"), request.headers.get("user-agent"))
            )
            query = str(request.url)
            if "meta=userinfo" in query:
                payload = {"query": {"userinfo": {"id": 42, "name": "StewardUser", "groups": ["sysop"], "rights": []}}}
            elif "meta=globaluserinfo" in query:
                payload = {"query": {"globaluserinfo": {"groups": ["steward"], "rights": [], "merged": []}}}
            else:
                payload = {"query": {"users": [{"name": "StewardUser", "rights": ["checkuser-temporary-account"]}]}}
            return httpx.Response(
                200,
                headers=[("Set-Cookie", "GeoIP=US; Path=/"), ("Set-Cookie", "centralauth_Session=leak; Path=/")],
                json=payload,
            )

        client = http_client.build_cookieless_http_client()
        try:
            # Clear proxy transport mounts inherited from environment variables so MockTransport handles all URLs
            client._mounts = {}
            client._transport = httpx.MockTransport(_handler)
            await client.get("https://zh.wikipedia.org/w/api.php", headers={"Cookie": "injected=1"})
            userinfo, meta_rights, project_rights = await asyncio.gather(
                verify_centralauth_userinfo(client, "valid-token", wiki_domain="zh.wikipedia.org"),
                fetch_user_rights_from_meta(client, "StewardUser"),
                fetch_project_user_rights(client, "StewardUser", "zh.wikipedia.org"),
            )

            self.assertEqual(len(client.cookies), 0)
            self.assertEqual(userinfo["username"], "StewardUser")
            self.assertEqual(meta_rights["global_groups"], ["steward"])
            self.assertEqual(project_rights, ["checkuser-temporary-account"])
            self.assertEqual(len(captured_requests), 4)
            for url, cookie_hdr, ua_hdr in captured_requests:
                self.assertIsNone(cookie_hdr)
                if "meta=" in url or "list=users" in url:
                    self.assertIn("ProxyCheck/1.0", ua_hdr or "")
        finally:
            await http_client.close_http_client_safely(client)


class RedisBatchingAndCacheCompletenessTests(TestCase):
    """Tests for batched Redis reads and writes and for the full cache hit check on partial source sets."""

    IPV6_TARGET = "2001:4860:4860::8888"

    @staticmethod
    def _cached_row_entry(provider_name):
        return json.dumps(
            {
                "row": {
                    "provider": provider_name,
                    "status": "200 OK",
                    "statusCode": 200,
                    "asn": "AS15169",
                    "isp": "Google",
                    "organisation": "Google",
                    "location": "United States",
                    "usageType": "isp",
                    "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
                    "countryCode": "US",
                    "rawJson": {},
                },
                "cachedAt": "2026-11-13T08:00:00+00:00",
                "sanitized": True,
            }
        )

    async def test_mget_reads_provider_caches_in_one_round_trip_and_falls_back_without_mget(self):
        fake_batch_redis = _BatchingFakeRedis()
        ipdata_key = cache_backends.provider_cache_key("ipdata", "8.8.8.8")
        iphub_key = cache_backends.provider_cache_key("iphub", "8.8.8.8")
        fake_batch_redis.strings[ipdata_key] = self._cached_row_entry("IPData")

        with patch("detector.cache_backends.redis_client", fake_batch_redis):
            cached_providers, cached_ptr = await detection_service._read_provider_caches("8.8.8.8")

        self.assertEqual(list(cached_providers), ["ipdata"])
        self.assertIsNone(cached_ptr)
        self.assertEqual(len(fake_batch_redis.mget_calls), 1)
        self.assertEqual(len(fake_batch_redis.mget_calls[0]), len(providers._PROVIDER_SPECS) + 1)
        self.assertEqual(fake_batch_redis.get_calls, [])

        fake_no_mget_redis = FakeAsyncRedis()
        fake_no_mget_redis.strings[ipdata_key] = "cached-ipdata"
        with patch("detector.cache_backends.redis_client", fake_no_mget_redis):
            values = await cache_backends._safe_redis_mget([ipdata_key, iphub_key])
        self.assertEqual(values, ["cached-ipdata", None])

    async def test_mget_degrades_to_empty_values_on_connection_errors_and_empty_inputs(self):
        mock_redis = MagicMock()
        mock_redis.mget = AsyncMock(side_effect=redis.exceptions.ConnectionError("redis offline"))
        mock_redis.get = AsyncMock(return_value="should-not-be-read")
        keys = ["proxycheck:v1:prov:ipdata:8.8.8.8", "proxycheck:v1:prov:iphub:8.8.8.8"]

        with (
            patch("detector.cache_backends.redis_client", mock_redis),
            self.assertLogs("detector.views", level="WARNING") as logs,
        ):
            values = await cache_backends._safe_redis_mget(keys)

        self.assertEqual(values, [None, None])
        mock_redis.get.assert_not_awaited()
        self.assertTrue(any("redis offline" in line for line in logs.output))

        with patch("detector.cache_backends.redis_client", None):
            self.assertEqual(await cache_backends._safe_redis_mget(["a", "b"]), [None, None])
        with patch("detector.cache_backends.redis_client", _BatchingFakeRedis()):
            self.assertEqual(await cache_backends._safe_redis_mget([]), [])

    async def test_set_many_flushes_entries_through_one_pipeline(self):
        fake_redis = _BatchingFakeRedis()
        entries = [
            ("proxycheck:v1:prov:ipdata:8.8.8.8", "row-a", 3600),
            ("proxycheck:v1:cooldown:iphub", "cooldown-b", 120),
        ]

        with patch("detector.cache_backends.redis_client", fake_redis):
            await cache_backends._safe_redis_set_many(entries)

        self.assertEqual(fake_redis.pipeline_calls, [False])
        self.assertEqual(fake_redis.strings["proxycheck:v1:prov:ipdata:8.8.8.8"], "row-a")
        self.assertEqual(fake_redis.strings["proxycheck:v1:cooldown:iphub"], "cooldown-b")
        self.assertEqual(fake_redis.ttls["proxycheck:v1:prov:ipdata:8.8.8.8"], 3600)
        self.assertEqual(fake_redis.ttls["proxycheck:v1:cooldown:iphub"], 120)

    async def test_set_many_logs_and_skips_writes_when_pipeline_fails(self):
        failing_pipe = MagicMock()
        failing_pipe.execute = AsyncMock(side_effect=redis.exceptions.TimeoutError("redis timed out"))
        mock_redis = MagicMock()
        mock_redis.pipeline = MagicMock(return_value=failing_pipe)
        mock_redis.set = AsyncMock()

        with (
            patch("detector.cache_backends.redis_client", mock_redis),
            self.assertLogs("detector.views", level="WARNING") as logs,
        ):
            await cache_backends._safe_redis_set_many([("proxycheck:v1:prov:ipdata:8.8.8.8", "row-a", 3600)])

        mock_redis.set.assert_not_awaited()
        self.assertTrue(any("redis timed out" in line for line in logs.output))

    @override_settings(**{**TEST_UPSTREAM_SECRETS, "IPHUNTER_API_KEY": ""})
    @patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock)
    def test_ipv6_with_all_expected_sources_cached_takes_full_hit_fast_path(self, mock_dns_resolve):
        target_ip = views.canonicalize_ip(self.IPV6_TARGET)
        uncached_keys = {"spamhaus_zen", "spamcop", "iphunter", "maxmind"}
        cache_store = {}
        for provider_key, provider_name, _, _, _ in providers._PROVIDER_SPECS:
            if provider_key not in uncached_keys:
                cache_store[cache_backends._provider_cache_key(provider_key, target_ip)] = self._cached_row_entry(
                    provider_name
                )
        cache_store[cache_backends._provider_cache_key("ptr", target_ip)] = json.dumps(
            {"hostname": "dns.google", "status": "ok", "cachedAt": "2026-11-13T08:30:00+00:00"}
        )

        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(side_effect=lambda key: cache_store.get(key))
        mock_redis.set = AsyncMock()
        shared_client = AsyncMock()
        _login_authorised(self)

        with (
            patch("detector.cache_backends.redis_client", mock_redis),
            patch("detector.cache_backends._has_any_local_maxmind_db", return_value=False),
            patch("detector.dns_providers.query_maxmind", AsyncMock(return_value=dict(MAXMIND_STUB))),
            patch("detector.http_client.get_shared_http_client", shared_client),
        ):
            response = self.client.get(f"/api/v1/detect?ip={self.IPV6_TARGET}")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["isCached"])
        self.assertEqual(payload["cacheMeta"]["status"], "hit")
        self.assertFalse(payload["cacheMeta"]["isPartial"])
        self.assertEqual(payload["cacheMeta"]["missCount"], 0)
        self.assertEqual(payload["cacheMeta"]["cooldownCount"], 0)
        expected_hits = len(providers._PROVIDER_SPECS) - len(uncached_keys) + 1
        self.assertEqual(payload["cacheMeta"]["hitCount"], expected_hits)
        self.assertEqual(payload["ptrHostname"], "dns.google")

        shared_client.assert_not_awaited()
        mock_dns_resolve.assert_not_called()
        read_keys = [call.args[0] for call in mock_redis.get.await_args_list]
        self.assertFalse(any(":cooldown:" in key for key in read_keys))
        mock_redis.set.assert_not_awaited()

        statuses = {row["provider"]: row["status"] for row in payload["results"]}
        self.assertEqual(statuses["Spamhaus ZEN"], "Skipped (IPv6)")
        self.assertEqual(statuses["SpamCop"], "Skipped (IPv6)")
        self.assertEqual(statuses["IPHunter"], "No API Key")
        self.assertEqual(statuses["MaxMind"], "Database Missing")
