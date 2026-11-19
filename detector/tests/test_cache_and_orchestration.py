"""Core P0 tests for non-public IP interception, singleflight coalescing, and cooldown isolation."""

import asyncio
import json
from unittest.mock import AsyncMock, patch

import dns.resolver
import httpx
from django.test import AsyncRequestFactory, TestCase, override_settings

from detector import cache_backends, detection_service, providers, views

from .helpers import MAXMIND_STUB, _BatchingFakeRedis, _mock_response, patch_non_dnsbl_providers


class CacheAndOrchestrationTests(TestCase):
    """P0 tests for private IP bypass, singleflight coalescing, and 429/timeout circuit breaking."""

    def setUp(self):
        cache_backends.reset_redis_circuit_breaker()
        detection_service._ip_detect_inflight.clear()
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock, side_effect=dns.resolver.NXDOMAIN()
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)

    def tearDown(self):
        detection_service._ip_detect_inflight.clear()
        cache_backends.reset_redis_circuit_breaker()

    def test_non_public_ips_intercepted_with_zero_external_or_redis_calls(self):
        """Intercepts private/loopback/reserved IPs locally without calling Redis or upstream APIs."""
        token = views.issue_gadget_token("SysopUser")
        with (
            patch(
                "detector.cache_backends.get_redis_client", side_effect=AssertionError("Redis called")
            ) as _mock_redis,
            patch("detector.http_client.get_shared_http_client", side_effect=AssertionError("HTTP called")),
        ):
            for ip in ("127.0.0.1", "10.0.0.1", "192.168.1.5", "::1", "fc00::1"):
                with self.subTest(ip=ip):
                    resp = self.client.get(f"/api/v1/detect?ip={ip}", HTTP_AUTHORIZATION=f"Bearer {token}")
                    self.assertEqual(resp.status_code, 200)
                    body = resp.json()
                    self.assertTrue(body["isNonPublic"])
                    self.assertEqual(body["cacheMeta"]["status"], "bypassed")

    async def test_singleflight_coalesces_concurrent_requests_for_same_canonical_ip(self):
        """Coalesces concurrent uncached requests for one IP so upstream providers run once."""
        calls = {"proxycheck": 0}

        def _make_provider(name):
            async def _impl(client, ip):
                if name == "Proxycheck":
                    calls["proxycheck"] += 1
                    await asyncio.sleep(0.02)
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

        fake_redis = _BatchingFakeRedis()
        auth_headers = {"Authorization": f"Bearer {views.issue_gadget_token('SysopUser')}"}
        factory = AsyncRequestFactory()
        mock_client = AsyncMock()
        mock_client.is_closed = False

        with (
            patch("detector.cache_backends.redis_client", fake_redis),
            patch("detector.dns_providers.query_rdns_ptr", AsyncMock(return_value="dns.google")),
            patch("detector.http_client.get_shared_http_client", AsyncMock(return_value=mock_client)),
            patch_non_dnsbl_providers(
                _make_provider, overrides={"maxmind": AsyncMock(return_value=dict(MAXMIND_STUB))}
            ),
        ):
            responses = await asyncio.gather(
                *(views.detect_ip(factory.get("/api/v1/detect?ip=8.8.4.4", headers=auth_headers)) for _ in range(5))
            )

        self.assertEqual(calls["proxycheck"], 1)
        self.assertTrue(all(r.status_code == 200 and json.loads(r.content)["ip"] == "8.8.4.4" for r in responses))
        self.assertEqual(len(detection_service._ip_detect_inflight), 0)

    def test_provider_429_and_timeout_trigger_cooldown_without_polluting_cache(self):
        """Records provider cooldown on HTTP 429 or timeout and skips writing transient failures to Redis cache."""
        fake_redis = _BatchingFakeRedis()
        resp_429 = _mock_response(429, {"error": "rate limited"}, text="rate limited")
        resp_429.headers = {"Retry-After": "90"}

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.get = AsyncMock(side_effect=[resp_429, httpx.TimeoutException("upstream timeout")])

        with (
            override_settings(PROXYCHECK_API_KEY="test-proxycheck-key"),
            patch("detector.cache_backends.redis_client", fake_redis),
            patch("detector.dns_providers.query_rdns_ptr", AsyncMock(return_value=None)),
            patch("detector.http_client.get_shared_http_client", AsyncMock(return_value=mock_client)),
            patch_non_dnsbl_providers(
                lambda name: AsyncMock(return_value=dict(MAXMIND_STUB, provider=name)),
                overrides={
                    "proxycheck": providers.query_proxycheck,
                    "maxmind": AsyncMock(return_value=dict(MAXMIND_STUB)),
                },
            ),
        ):
            payload_429 = asyncio.run(detection_service.detect_single_canonical_ip("8.8.8.8", "session", 0.0))
            row_429 = next(r for r in payload_429["results"] if r["provider"] == "Proxycheck")
            self.assertEqual(row_429["statusCode"], 429)
            self.assertFalse(providers.is_provider_result_cacheable(row_429))
            cd_key = cache_backends.provider_cooldown_key("proxycheck")
            self.assertIn(cd_key, fake_redis.strings)
            self.assertEqual(fake_redis.ttls.get(cd_key), 90)
            self.assertNotIn(cache_backends.provider_cache_key("proxycheck", "8.8.8.8"), fake_redis.strings)

            fake_redis.strings.pop(cd_key, None)
            payload_timeout = asyncio.run(detection_service.detect_single_canonical_ip("8.8.4.4", "session", 0.0))
            row_timeout = next(r for r in payload_timeout["results"] if r["provider"] == "Proxycheck")
            self.assertEqual(row_timeout["statusCode"], 502)
            self.assertFalse(providers.is_provider_result_cacheable(row_timeout))
            self.assertIn(cd_key, fake_redis.strings)
            self.assertNotIn(cache_backends.provider_cache_key("proxycheck", "8.8.4.4"), fake_redis.strings)
