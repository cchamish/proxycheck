"""Core P0 tests for batch IP detection, light mode quota exclusion, and ASGI stateless bypass."""

import asyncio
import json
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import dns.resolver
from django.http import HttpResponse
from django.test import AsyncRequestFactory, Client, SimpleTestCase, TestCase, override_settings

from detector import views
from detector.cache import quota_telemetry
from detector.cache import redis_backend as cache_backends
from detector.detection import service as detection_service
from detector.middleware import ResilientSessionMiddleware
from detector.provider_registry import PROVIDER_REGISTRY

from .helpers import (
    MAXMIND_STUB,
    TEST_UPSTREAM_SECRETS,
    _BatchingFakeRedis,
    patch_non_dnsbl_providers,
    start_non_dnsbl_provider_stubs,
)


class BatchDetectTests(TestCase):
    """P0 tests for /api/v1/detect/batch auth, CSRF, cache headers, and light mode."""

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

    def test_batch_detect_auth_csrf_validation_and_cache_control(self):
        """Enforces auth, session CSRF, payload bounds, Cache-Control, and non-mutating shouldAutoRefresh=False."""
        csrf_client = Client(enforce_csrf_checks=True)
        self.assertEqual(
            csrf_client.post(
                "/api/v1/detect/batch", data=json.dumps({"ips": ["8.8.8.8"]}), content_type="application/json"
            ).status_code,
            401,
        )

        session = csrf_client.session
        session["wikimedia_user"] = {
            "isLoggedIn": True,
            "username": "SysopUser",
            "role": "Local Administrator (sysop)",
            "hasAccess": True,
            "localGroups": ["sysop"],
            "globalGroups": [],
        }
        session.save()
        self.assertEqual(
            csrf_client.post(
                "/api/v1/detect/batch", data=json.dumps({"ips": ["8.8.8.8"]}), content_type="application/json"
            ).status_code,
            403,
        )

        csrf_token = csrf_client.get("/api/v1/auth/user/").cookies["csrftoken"].value
        start_non_dnsbl_provider_stubs(self)

        for bad_ips in ([], ["invalid-ip"], [f"8.8.8.{i}" for i in range(26)]):
            with self.subTest(bad_ips=len(bad_ips)):
                bad_resp = csrf_client.post(
                    "/api/v1/detect/batch",
                    data=json.dumps({"ips": bad_ips}),
                    content_type="application/json",
                    headers={"X-CSRFToken": csrf_token},
                )
                self.assertEqual(bad_resp.status_code, 400)

        bearer = views.issue_gadget_token("SysopUser")
        shared_meta = {"status": "stale", "layer": "L2", "isStale": True, "shouldAutoRefresh": True}
        shared_payload = {
            "ip": "8.8.8.8",
            "isCached": True,
            "isNonPublic": False,
            "results": [],
            "cacheMeta": shared_meta,
        }
        with patch("detector.detection.service.detect_single_canonical_ip", AsyncMock(return_value=shared_payload)):
            ok_resp = csrf_client.post(
                "/api/v1/detect/batch",
                data=json.dumps({"ips": ["8.8.8.8"]}),
                content_type="application/json",
                headers={"Authorization": f"Bearer {bearer}"},
            )
        self.assertEqual(ok_resp.status_code, 200)
        self.assertEqual(ok_resp.headers.get("Cache-Control"), "private, no-cache")
        self.assertFalse(ok_resp.json()["results"]["8.8.8.8"]["cacheMeta"]["shouldAutoRefresh"])
        # Shared singleflight dict must remain unmutated.
        self.assertTrue(shared_meta["shouldAutoRefresh"])

        # L1 stale snapshot in batch returns shouldAutoRefresh=False via allow_auto_refresh=False.
        stale_ts = (datetime.now(timezone.utc) - timedelta(days=95)).isoformat()
        fake_redis = _BatchingFakeRedis()
        fake_redis.strings[cache_backends.snapshot_cache_key("8.8.8.8", "light")] = json.dumps(
            {
                "ip": "8.8.8.8",
                "fetchedAt": stale_ts,
                "queryMode": "light",
                "isPartialMode": True,
                "results": [],
            }
        )
        with patch("detector.cache.redis_backend.redis_client", fake_redis):
            l1_batch = csrf_client.post(
                "/api/v1/detect/batch",
                data=json.dumps({"ips": ["8.8.8.8"]}),
                content_type="application/json",
                headers={"Authorization": f"Bearer {bearer}"},
            )
        self.assertEqual(l1_batch.status_code, 200)
        self.assertFalse(l1_batch.json()["results"]["8.8.8.8"]["cacheMeta"]["shouldAutoRefresh"])

    def test_batch_light_mode_skips_commercial_providers_and_quota(self):
        """Skips uncached commercial providers and quota in light mode while deduplicating variants."""
        fake_redis = _BatchingFakeRedis()
        bearer = views.issue_gadget_token("SysopUser")
        called_providers = []

        def _make_stub(label):
            async def _impl(client, ip):
                called_providers.append(label)
                return {
                    "provider": label,
                    "status": "200 OK",
                    "statusCode": 200,
                    "asn": "AS15169",
                    "isp": "Google",
                    "organisation": "Google",
                    "location": "US",
                    "usageType": "isp",
                    "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
                    "rawJson": {},
                }

            return _impl

        mock_client = AsyncMock()
        mock_client.is_closed = False
        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch("detector.cache.redis_backend.redis_client", fake_redis),
            patch("detector.providers.dns_local.query_rdns_ptr", AsyncMock(return_value="dns.google")),
            patch("detector.core.http_client.get_shared_http_client", AsyncMock(return_value=mock_client)),
            patch_non_dnsbl_providers(_make_stub, overrides={"maxmind": AsyncMock(return_value=dict(MAXMIND_STUB))}),
            patch.object(
                quota_telemetry, "check_and_consume_quota", wraps=quota_telemetry.check_and_consume_quota
            ) as spy_quota,
        ):
            resp = self.client.post(
                "/api/v1/detect/batch",
                data=json.dumps({"ips": ["127.0.0.1", "2001:0db8:0:0::1", "2001:db8::1"]}),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {bearer}",
            )

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["queryMode"], "light")
        self.assertEqual(body["count"], 2)
        self.assertEqual(body["inputMap"]["2001:0db8:0:0::1"], "2001:db8::1")
        commercial_labels = {m.label for m in PROVIDER_REGISTRY if m.is_commercial_arbitration}
        self.assertFalse(commercial_labels & set(called_providers))
        commercial_keys = {m.key for m in PROVIDER_REGISTRY if m.is_commercial_arbitration}
        quota_called_keys = {call.args[0] for call in spy_quota.call_args_list if call.args}
        self.assertFalse(commercial_keys & quota_called_keys)


class AsgiStatelessMiddlewareTests(SimpleTestCase):
    """P0 ASGI middleware test verifying Bearer requests bypass blocking session writes."""

    def test_asgi_middleware_stateless_bearer_bypass(self):
        async def async_next(_request):
            return HttpResponse("async-ok")

        async def async_mutating_next(request):
            request.session["oauth_state"] = "state_value"
            return HttpResponse("mutated")

        async_mw = ResilientSessionMiddleware(async_next)
        mutating_mw = ResilientSessionMiddleware(async_mutating_next)
        factory = AsyncRequestFactory()
        release_save = threading.Event()
        unblocked = []

        async def _run():
            loop = asyncio.get_running_loop()
            started = asyncio.Event()

            def blocking_save(*_args, **_kwargs):
                loop.call_soon_threadsafe(started.set)
                unblocked.append(release_save.wait(timeout=2.0))

            with patch(
                "django.contrib.sessions.backends.cache.SessionStore.save", autospec=True, side_effect=blocking_save
            ):
                slow_task = asyncio.create_task(mutating_mw(factory.get("/api/v1/auth/login/")))
                await started.wait()
                bearer_resp = await async_mw(
                    factory.get("/api/v1/detect?ip=8.8.8.8", headers={"Authorization": "Bearer signed-token"})
                )
                release_save.set()
                slow_resp = await slow_task
                return bearer_resp, slow_resp

        bearer_resp, slow_resp = asyncio.run(_run())
        self.assertEqual(unblocked, [True])
        self.assertEqual(bearer_resp.status_code, 200)
        self.assertEqual(slow_resp.status_code, 200)
