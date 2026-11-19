"""Tests for ASGI runtime behaviour, batch IP detection, compact responses, and query modes."""

import asyncio
import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.name
import dns.resolver
import dns.reversename
import httpx
import redis.exceptions
from asgiref.sync import SyncToAsync, iscoroutinefunction
from django.http import HttpResponse
from django.test import AsyncRequestFactory, RequestFactory, SimpleTestCase, TestCase, override_settings

from detector import cache_backends, detection_service, providers, quota_telemetry, views
from detector.middleware import AsyncWhiteNoiseMiddleware, ResilientSessionMiddleware
from detector.provider_registry import PROVIDER_REGISTRY

from .helpers import (
    CANONICAL_PROVIDER_PATCH_TARGETS,
    MAXMIND_STUB,
    TEST_UPSTREAM_SECRETS,
    FakeAsyncRedis,
    _BatchingFakeRedis,
    _login_authorised,
    _patch_async_client,
    _run_uvicorn_smoke_server,
    build_provider_http_response,
    clean_dns_side_effect,
    patch_non_dnsbl_providers,
    start_non_dnsbl_provider_stubs,
)


class AsgiSmokeTests(SimpleTestCase):
    """End-to-end ASGI smoke tests covering middleware headers, concurrency, and WhiteNoise."""

    def test_asgi_application_middleware_forwarded_proto_and_concurrent_requests(self):
        from proxycheck.asgi import application

        self.assertTrue(iscoroutinefunction(application._middleware_chain))
        self.assertNotIsInstance(application._middleware_chain, SyncToAsync)

        async def _send_concurrent_requests(base_url: str):
            async with httpx.AsyncClient(base_url=base_url, timeout=5.0, trust_env=False) as client:
                return await asyncio.gather(
                    client.get("/", headers={"X-Forwarded-Proto": "https"}),
                    client.get("/"),
                    client.get("/api/v1/auth/user/", headers={"X-Forwarded-Proto": "https"}),
                    client.get("/api/v1/auth/user/", headers={"X-Forwarded-Proto": "https"}),
                    client.get("/api/v1/detect?ip=8.8.8.8", headers={"X-Forwarded-Proto": "https"}),
                    client.get("/Proxycheck.svg", headers={"X-Forwarded-Proto": "https"}),
                )

        with _run_uvicorn_smoke_server(application) as base_url:
            https_root, plain_root, auth_one, auth_two, detect_unauth, favicon = asyncio.run(
                _send_concurrent_requests(base_url)
            )

        self.assertEqual(https_root.status_code, 200)
        self.assertIn("text/html", https_root.headers.get("content-type", ""))
        self.assertIn("max-age=31536000", https_root.headers.get("strict-transport-security", ""))
        self.assertEqual(https_root.headers.get("x-frame-options"), "DENY")

        self.assertEqual(plain_root.status_code, 200)
        self.assertIsNone(plain_root.headers.get("strict-transport-security"))

        for auth_resp in (auth_one, auth_two):
            self.assertEqual(auth_resp.status_code, 200)
            self.assertFalse(auth_resp.json()["isLoggedIn"])
            self.assertFalse(auth_resp.json()["hasAccess"])
            self.assertIn("Cookie", auth_resp.headers.get("vary", ""))

        self.assertEqual(detect_unauth.status_code, 401)
        self.assertEqual(favicon.status_code, 200)
        self.assertIn("image/svg+xml", favicon.headers.get("content-type", ""))

    def test_async_whitenoise_middleware_preserves_sync_and_async_dispatch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir)
            static_root = base_dir / "staticfiles"
            static_root.mkdir(parents=True, exist_ok=True)
            (static_root / "widget.js").write_bytes(b"console.log('ok');\n")

            with override_settings(BASE_DIR=base_dir, STATIC_ROOT=static_root, STATICFILES_DIRS=[]):
                sync_called = []

                def sync_next(request):
                    sync_called.append(request.path)
                    return HttpResponse("sync-ok")

                sync_middleware = AsyncWhiteNoiseMiddleware(sync_next)
                self.assertFalse(sync_middleware.async_mode)
                self.assertFalse(iscoroutinefunction(sync_middleware))
                sync_factory = RequestFactory()
                sync_static_resp = sync_middleware(sync_factory.get("/assets/widget.js"))
                try:
                    self.assertEqual(sync_static_resp.status_code, 200)
                    self.assertEqual(b"".join(sync_static_resp.streaming_content), b"console.log('ok');\n")
                finally:
                    sync_static_resp.close()
                sync_api_resp = sync_middleware(sync_factory.get("/api/v1/auth/user/"))
                self.assertEqual(sync_api_resp.content, b"sync-ok")
                self.assertEqual(sync_called, ["/api/v1/auth/user/"])

                async_called = []

                async def async_next(request):
                    async_called.append(request.path)
                    return HttpResponse("async-ok")

                async_middleware = AsyncWhiteNoiseMiddleware(async_next)
                self.assertTrue(async_middleware.async_mode)
                self.assertTrue(iscoroutinefunction(async_middleware))
                async_factory = AsyncRequestFactory()

                async def _exercise_async():
                    static_resp = await async_middleware(async_factory.get("/assets/widget.js"))
                    try:
                        self.assertTrue(static_resp.is_async)
                        chunks = [chunk async for chunk in static_resp]
                    finally:
                        static_resp.close()
                    api_resp = await async_middleware(async_factory.get("/api/v1/auth/user/"))
                    return b"".join(chunks), api_resp.content

                static_bytes, api_bytes = asyncio.run(_exercise_async())
                self.assertEqual(static_bytes, b"console.log('ok');\n")
                self.assertEqual(api_bytes, b"async-ok")
                self.assertEqual(async_called, ["/api/v1/auth/user/"])

    def test_stateless_bearer_requests_do_not_block_on_slow_session_save(self):
        async def async_next(_request):
            return HttpResponse("async-ok")

        async def async_mutating_next(request):
            request.session["oauth_state"] = "state_value"
            return HttpResponse("mutated")

        async_middleware = ResilientSessionMiddleware(async_next)
        mutating_middleware = ResilientSessionMiddleware(async_mutating_next)
        async_factory = AsyncRequestFactory()
        release_save = threading.Event()
        unblocked_in_time = []

        async def _exercise_concurrent_stateless_during_blocked_session_thread():
            loop = asyncio.get_running_loop()
            save_started = asyncio.Event()

            def blocking_save(store_self, *args, **kwargs):
                loop.call_soon_threadsafe(save_started.set)
                unblocked_in_time.append(release_save.wait(timeout=2.0))

            with patch(
                "django.contrib.sessions.backends.cache.SessionStore.save",
                autospec=True,
                side_effect=blocking_save,
            ):
                slow_task = asyncio.create_task(mutating_middleware(async_factory.get("/api/v1/auth/login/")))
                await save_started.wait()
                bearer_resp = await async_middleware(
                    async_factory.get(
                        "/api/v1/detect?ip=8.8.8.8",
                        headers={"Authorization": "Bearer signed-gadget-token"},
                    )
                )
                release_save.set()
                slow_resp = await slow_task
                return bearer_resp, slow_resp

        concurrent_bearer_resp, concurrent_slow_resp = asyncio.run(
            _exercise_concurrent_stateless_during_blocked_session_thread()
        )

        self.assertEqual(unblocked_in_time, [True])
        self.assertEqual(concurrent_bearer_resp.status_code, 200)
        self.assertEqual(concurrent_slow_resp.status_code, 200)

    def test_asgi_detect_bearer_bypasses_session_while_session_auth_degrades_safely(self):
        import django.utils.deprecation as django_deprecation

        bearer_token = views.issue_gadget_token("SysopUser")
        real_sync_to_async = django_deprecation.sync_to_async
        bridged_calls = []

        def spy_sync_to_async(func, *args, **kwargs):
            bridged_calls.append(getattr(func, "__qualname__", repr(func)))
            return real_sync_to_async(func, *args, **kwargs)

        async def _run_stateless_requests():
            bearer_resp = await self.async_client.get(
                "/api/v1/detect?ip=127.0.0.1",
                headers={"Authorization": f"Bearer {bearer_token}"},
            )
            options_resp = await self.async_client.options(
                "/api/v1/detect",
                headers={"Origin": "https://meta.wikimedia.org"},
            )
            gadget_options_resp = await self.async_client.options(
                "/api/v1/auth/gadget-token/",
                headers={"Origin": "https://meta.wikimedia.org"},
            )
            return bearer_resp, options_resp, gadget_options_resp

        with (
            patch("django.utils.deprecation.sync_to_async", side_effect=spy_sync_to_async),
            patch(
                "django.contrib.sessions.backends.cache.SessionStore.load",
                side_effect=redis.exceptions.ConnectionError("Redis unavailable"),
            ) as mock_load,
            patch(
                "django.contrib.sessions.backends.cache.SessionStore.save",
                side_effect=redis.exceptions.ConnectionError("Redis unavailable"),
            ) as mock_save,
        ):
            bearer_resp, options_resp, gadget_options_resp = asyncio.run(_run_stateless_requests())

        self.assertEqual(bearer_resp.status_code, 200)
        self.assertEqual(bearer_resp.json()["ip"], "127.0.0.1")
        self.assertEqual(options_resp.status_code, 204)
        self.assertEqual(gadget_options_resp.status_code, 204)
        mock_load.assert_not_called()
        mock_save.assert_not_called()
        self.assertFalse(
            any("SessionMiddleware" in name for name in bridged_calls),
            f"Unexpected session sync bridging on stateless requests: {bridged_calls}",
        )

        async def _setup_and_run_session_requests():
            session = await self.async_client.asession()
            session["wikimedia_user"] = {
                "isLoggedIn": True,
                "username": "SysopUser",
                "role": "Local Administrator (sysop)",
                "hasAccess": True,
                "localGroups": ["sysop"],
                "globalGroups": [],
                "rights_updated_at": time.time(),
            }
            await session.asave()
            ok_resp = await self.async_client.get("/api/v1/detect?ip=127.0.0.1")
            with (
                patch(
                    "django.contrib.sessions.backends.cache.SessionStore.load",
                    side_effect=redis.exceptions.ConnectionError("Redis load outage"),
                ),
                self.assertLogs("detector.views", level="WARNING"),
            ):
                degraded_resp = await self.async_client.get("/api/v1/detect?ip=127.0.0.1")
            return ok_resp, degraded_resp

        session_ok_resp, session_degraded_resp = asyncio.run(_setup_and_run_session_requests())
        self.assertEqual(session_ok_resp.status_code, 200)
        self.assertEqual(session_ok_resp.json()["ip"], "127.0.0.1")
        self.assertIn("Cookie", session_ok_resp.headers.get("Vary", ""))
        self.assertEqual(session_degraded_resp.status_code, 401)
        self.assertIn("Cookie", session_degraded_resp.headers.get("Vary", ""))


class BatchDetectionEndpointTests(TestCase):
    """Tests for the batch IP detection endpoint covering authentication, validation, CORS, and mixed IP lookups."""

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

    def _patch_all_providers(self):
        start_non_dnsbl_provider_stubs(self)

    def test_batch_detect_unauthenticated_and_unauthorised_requests(self):
        for route in ("/api/v1/detect/batch", "/api/v1/detect/batch/"):
            with self.subTest(route=route):
                unauth_resp = self.client.post(
                    route,
                    data=json.dumps({"ips": ["1.1.1.1"]}),
                    content_type="application/json",
                    HTTP_ORIGIN="https://meta.wikimedia.org",
                )
                self.assertEqual(unauth_resp.status_code, 401)
                self.assertIn("error", unauth_resp.json())
                self.assertEqual(
                    unauth_resp.headers.get("Access-Control-Allow-Origin"),
                    "https://meta.wikimedia.org",
                )

                bad_token_resp = self.client.post(
                    route,
                    data=json.dumps({"ips": ["1.1.1.1"]}),
                    content_type="application/json",
                    HTTP_AUTHORIZATION="Bearer invalid-gadget-token",
                    HTTP_ORIGIN="https://meta.wikimedia.org",
                )
                self.assertEqual(bad_token_resp.status_code, 401)

        session = self.client.session
        session["wikimedia_user"] = {
            "isLoggedIn": True,
            "username": "UnprivilegedEditor",
            "role": "Standard User (Unauthorised)",
            "hasAccess": False,
            "localGroups": ["user"],
            "globalGroups": [],
        }
        session.save()

        forbidden_resp = self.client.post(
            "/api/v1/detect/batch",
            data=json.dumps({"ips": ["1.1.1.1"]}),
            content_type="application/json",
        )
        self.assertEqual(forbidden_resp.status_code, 403)
        self.assertIn("error", forbidden_resp.json())

    def test_batch_detect_options_preflight_and_method_guard(self):
        for route in ("/api/v1/detect/batch", "/api/v1/detect/batch/"):
            with self.subTest(route=route):
                options_resp = self.client.options(
                    route,
                    HTTP_ORIGIN="https://zh.wikipedia.org",
                )
                self.assertEqual(options_resp.status_code, 204)
                self.assertEqual(
                    options_resp.headers.get("Access-Control-Allow-Origin"),
                    "https://zh.wikipedia.org",
                )
                self.assertEqual(
                    options_resp.headers.get("Access-Control-Allow-Methods"),
                    "POST, OPTIONS",
                )
                self.assertIn("Authorization", options_resp.headers.get("Access-Control-Allow-Headers", ""))
                self.assertIn("Content-Type", options_resp.headers.get("Access-Control-Allow-Headers", ""))
                self.assertEqual(options_resp.headers.get("Access-Control-Max-Age"), "86400")

                get_resp = self.client.get(
                    route,
                    HTTP_ORIGIN="https://zh.wikipedia.org",
                )
                self.assertEqual(get_resp.status_code, 405)
                self.assertEqual(
                    get_resp.headers.get("Access-Control-Allow-Origin"),
                    "https://zh.wikipedia.org",
                )

    def test_batch_detect_rejects_empty_oversized_and_invalid_ip_lists_with_400(self):
        bearer_token = views.issue_gadget_token("SysopUser")
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {bearer_token}",
            "HTTP_ORIGIN": "https://meta.wikimedia.org",
        }

        too_many_unique = [f"198.51.100.{idx}" for idx in range(1, 27)]
        too_many_raw = ["1.1.1.1"] * 51

        invalid_payloads = (
            "{malformed-json",
            json.dumps(["1.1.1.1"]),
            json.dumps({}),
            json.dumps({"ips": []}),
            json.dumps({"ips": "1.1.1.1"}),
            json.dumps({"ips": [12345]}),
            json.dumps({"ips": ["   "]}),
            json.dumps({"ips": ["1.1.1.1", "999.999.999.999"]}),
            json.dumps({"ips": ["fe80::1%"]}),
            json.dumps({"ips": too_many_unique}),
            json.dumps({"ips": too_many_raw}),
        )

        for raw_body in invalid_payloads:
            with self.subTest(raw_body=raw_body[:60]):
                resp = self.client.post(
                    "/api/v1/detect/batch",
                    data=raw_body,
                    content_type="application/json",
                    **headers,
                )
                self.assertEqual(resp.status_code, 400)
                body = resp.json()
                self.assertEqual(body.get("error"), "invalid_batch")
                self.assertTrue(body.get("message"))
                self.assertEqual(
                    resp.headers.get("Access-Control-Allow-Origin"),
                    "https://meta.wikimedia.org",
                )

    @patch("detector.cache_backends.redis_client", None)
    def test_batch_detect_returns_mixed_public_and_non_public_results_with_deduplication(self):
        self._patch_all_providers()
        bearer_token = views.issue_gadget_token("SysopUser")

        batch_ips = [
            "1.1.1.1",
            "2001:4860:4860:0000:0000:0000:0000:8888",
            "2001:4860:4860::8888",
            "127.0.0.1",
            "192.168.1.50",
            "fe80::1%eth0",
        ]
        resp = self.client.post(
            "/api/v1/detect/batch/",
            data=json.dumps({"ips": batch_ips}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {bearer_token}",
            HTTP_ORIGIN="https://meta.wikimedia.org",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("Access-Control-Allow-Origin"), "https://meta.wikimedia.org")

        payload = resp.json()
        self.assertEqual(payload["count"], 5)
        self.assertIn("durationSeconds", payload)
        self.assertIn("memoryMb", payload)
        self.assertEqual(
            set(payload["results"].keys()),
            {"1.1.1.1", "2001:4860:4860::8888", "127.0.0.1", "192.168.1.50", "fe80::1"},
        )
        self.assertEqual(
            payload["inputMap"]["2001:4860:4860:0000:0000:0000:0000:8888"],
            "2001:4860:4860::8888",
        )
        self.assertEqual(payload["inputMap"]["fe80::1%eth0"], "fe80::1")

        public_v4 = payload["results"]["1.1.1.1"]
        self.assertEqual(public_v4["ip"], "1.1.1.1")
        self.assertFalse(public_v4.get("isNonPublic", False))
        self.assertEqual(len(public_v4["results"]), 17)

        public_v6 = payload["results"]["2001:4860:4860::8888"]
        self.assertEqual(public_v6["ip"], "2001:4860:4860::8888")
        self.assertFalse(public_v6.get("isNonPublic", False))
        self.assertEqual(len(public_v6["results"]), 17)

        loopback_res = payload["results"]["127.0.0.1"]
        self.assertTrue(loopback_res["isNonPublic"])
        self.assertEqual(loopback_res["nonPublicCategory"], "loopback")
        self.assertEqual(loopback_res["results"], [])

        private_res = payload["results"]["192.168.1.50"]
        self.assertTrue(private_res["isNonPublic"])
        self.assertEqual(private_res["nonPublicCategory"], "private")
        self.assertEqual(private_res["results"], [])

        link_local_res = payload["results"]["fe80::1"]
        self.assertTrue(link_local_res["isNonPublic"])
        self.assertEqual(link_local_res["nonPublicCategory"], "link_local")
        self.assertEqual(link_local_res["results"], [])


class CompactResponseAndCacheControlTests(TestCase):
    """Tests for compact response stripping, cache control headers, and shared cache preservation."""

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

    @staticmethod
    def _stub_provider(name: str) -> dict:
        return {
            "provider": name,
            "status": "200 OK",
            "statusCode": 200,
            "asn": "AS15169",
            "isp": "Google LLC",
            "organisation": "Google LLC",
            "location": "United States",
            "usageType": "isp",
            "countryCode": "US",
            "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
            "rawJson": {"provider": name, "count": 10},
        }

    def test_detect_ip_error_responses_omit_cache_control_header(self):
        unauth_resp = self.client.get("/api/v1/detect?ip=8.8.8.8&compact=1")
        self.assertEqual(unauth_resp.status_code, 401)
        self.assertIsNone(unauth_resp.headers.get("Cache-Control"))

        session = self.client.session
        session["wikimedia_user"] = {
            "isLoggedIn": True,
            "username": "UnprivilegedEditor",
            "role": "Standard User (Unauthorised)",
            "hasAccess": False,
            "localGroups": ["user"],
            "globalGroups": [],
        }
        session.save()
        forbidden_resp = self.client.get("/api/v1/detect?ip=8.8.8.8&compact=1")
        self.assertEqual(forbidden_resp.status_code, 403)
        self.assertIsNone(forbidden_resp.headers.get("Cache-Control"))

        _login_authorised(self)
        bad_ip_resp = self.client.get("/api/v1/detect?ip=not-an-ip&compact=1")
        self.assertEqual(bad_ip_resp.status_code, 400)
        self.assertIsNone(bad_ip_resp.headers.get("Cache-Control"))

    async def test_compact_singleflight_does_not_strip_raw_json_from_concurrent_full_request(self):
        provider_calls = {"count": 0}

        def _make_slow_ok(name):
            async def _impl(client, ip):
                if name == "Proxycheck":
                    provider_calls["count"] += 1
                    await asyncio.sleep(0.03)
                return self._stub_provider(name)

            return _impl

        auth_headers = {"Authorization": f"Bearer {views.issue_gadget_token('SysopUser')}"}
        factory = AsyncRequestFactory()
        compact_req = factory.get("/api/v1/detect?ip=8.8.4.4&compact=1", headers=auth_headers)
        full_req = factory.get("/api/v1/detect?ip=8.8.4.4", headers=auth_headers)

        mock_client = AsyncMock()
        mock_client.is_closed = False
        with (
            patch("detector.cache_backends.redis_client", None),
            patch("detector.http_client.get_shared_http_client", AsyncMock(return_value=mock_client)),
            patch("detector.dns_providers.query_rdns_ptr", AsyncMock(return_value="dns.google")),
            patch_non_dnsbl_providers(
                _make_slow_ok,
                overrides={"maxmind": AsyncMock(return_value=dict(MAXMIND_STUB))},
            ),
        ):
            compact_resp, full_resp = await asyncio.gather(
                views.detect_ip(compact_req),
                views.detect_ip(full_req),
            )

        self.assertEqual(provider_calls["count"], 1)
        self.assertEqual(compact_resp.status_code, 200)
        self.assertEqual(full_resp.status_code, 200)
        self.assertEqual(compact_resp.headers.get("Cache-Control"), "private, no-cache")
        self.assertEqual(full_resp.headers.get("Cache-Control"), "private, no-cache")

        compact_payload = json.loads(compact_resp.content)
        full_payload = json.loads(full_resp.content)
        for row in compact_payload["results"]:
            self.assertNotIn("rawJson", row)
        for row in full_payload["results"]:
            self.assertIn("rawJson", row)

    @override_settings(**TEST_UPSTREAM_SECRETS)
    def test_compact_miss_preserves_redis_raw_json_and_ipdata_telemetry(self):
        fake_redis = FakeAsyncRedis()
        _login_authorised(self)

        async def fake_get(url, **kwargs):
            return build_provider_http_response(url, ip="8.8.8.8")

        fake_resolver = MagicMock()
        fake_resolver.resolve = AsyncMock(side_effect=clean_dns_side_effect)

        with (
            patch("detector.cache_backends.redis_client", fake_redis),
            patch("detector.http_client.httpx.AsyncClient") as mock_client_cls,
            patch("detector.dns_providers.dns.asyncresolver.Resolver", return_value=fake_resolver),
            patch("detector.dns_providers.query_maxmind", new_callable=AsyncMock, return_value=dict(MAXMIND_STUB)),
        ):
            _patch_async_client(mock_client_cls, fake_get)
            compact_resp = self.client.get("/api/v1/detect?ip=8.8.8.8&compact=1")
            full_cached_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")
            compact_cached_resp = self.client.get("/api/v1/detect?ip=8.8.8.8&compact=true")

        self.assertEqual(compact_resp.status_code, 200)
        self.assertEqual(compact_resp.headers.get("Cache-Control"), "private, no-cache")
        for row in compact_resp.json()["results"]:
            self.assertNotIn("rawJson", row)

        # Ensure IPData usage count was still extracted from rawJson before stripping the response
        ns = cache_backends.get_redis_namespace()
        ipdata_key = next(key for key in fake_redis.hashes if key.startswith(f"{ns}:telemetry:ipdata:day:"))
        self.assertEqual(fake_redis.hashes[ipdata_key].get("upstream_used"), "142")

        self.assertEqual(full_cached_resp.status_code, 200)
        full_payload = full_cached_resp.json()
        self.assertTrue(full_payload["isCached"])
        for row in full_payload["results"]:
            self.assertIn("rawJson", row)

        self.assertEqual(compact_cached_resp.status_code, 200)
        compact_cached_payload = compact_cached_resp.json()
        self.assertTrue(compact_cached_payload["isCached"])
        for row in compact_cached_payload["results"]:
            self.assertNotIn("rawJson", row)


class TwoTierQueryModeTests(TestCase):
    """Tests for light and full two-tier detection modes across single, batch, and singleflight paths."""

    def setUp(self):
        detection_service._ip_detect_inflight.clear()

    def tearDown(self):
        detection_service._ip_detect_inflight.clear()

    @staticmethod
    def _build_ok_row(provider_name: str, *, chance: Optional[float] = None) -> dict:
        row = {
            "provider": provider_name,
            "status": "200 OK",
            "statusCode": 200,
            "asn": "AS15169",
            "isp": "Google LLC",
            "organisation": "Google LLC",
            "location": "United States",
            "usageType": "isp",
            "countryCode": "US",
            "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
            "rawJson": {"provider": provider_name, "status": "success"},
        }
        if chance is not None:
            row["chance"] = chance
        return row

    def _patch_provider_suite(self):
        mocks = {}
        for meta in PROVIDER_REGISTRY:
            chance = 0.985 if meta.key == "getipintel" else None
            mock_fn = AsyncMock(return_value=self._build_ok_row(meta.label, chance=chance))
            patcher = patch(CANONICAL_PROVIDER_PATCH_TARGETS[meta.key], mock_fn)
            patcher.start()
            self.addCleanup(patcher.stop)
            mocks[meta.key] = mock_fn

        ptr_patcher = patch("detector.dns_providers.query_rdns_ptr", AsyncMock(return_value="dns.google"))
        ptr_patcher.start()
        self.addCleanup(ptr_patcher.stop)

        http_client = AsyncMock()
        http_client.is_closed = False
        client_patcher = patch("detector.http_client.get_shared_http_client", AsyncMock(return_value=http_client))
        client_patcher.start()
        self.addCleanup(client_patcher.stop)

        mm_db_patcher = patch("detector.cache_backends._has_any_local_maxmind_db", return_value=True)
        mm_db_patcher.start()
        self.addCleanup(mm_db_patcher.stop)

        return mocks

    def test_light_mode_skips_uncached_commercial_sources_and_quota(self):
        fake_redis = _BatchingFakeRedis()
        mocks = self._patch_provider_suite()
        _login_authorised(self)

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.cache_backends.redis_client", fake_redis),
            patch(
                "detector.quota_telemetry.check_and_consume_quota",
                wraps=quota_telemetry.check_and_consume_quota,
            ) as quota_spy,
        ):
            response = self.client.get("/api/v1/detect?ip=8.8.8.8&mode=light")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["queryMode"], "light")
        self.assertTrue(payload["isPartialMode"])
        self.assertIsNone(payload["getipintel_chance"])

        ns = cache_backends.get_redis_namespace()
        for deferred_key in (
            "abuseipdb",
            "ipdata",
            "ipregistry",
            "ip2location",
            "getipintel",
            "proxycheck",
            "iphub",
            "iphunter",
            "shodan_internetdb",
        ):
            mocks[deferred_key].assert_not_awaited()
            self.assertNotIn(cache_backends.provider_cache_key(deferred_key, "8.8.8.8"), fake_redis.strings)

        for active_key in (
            "cloudflare_radar",
            "maxmind",
            "stopforumspam",
            "spamhaus_zen",
            "spamcop",
            "tor_onionoo",
            "dshield",
            "ipsum_drop",
            "x4bnet_vpn",
        ):
            mocks[active_key].assert_awaited_once()
            self.assertIn(cache_backends.provider_cache_key(active_key, "8.8.8.8"), fake_redis.strings)

        consumed_providers = {call.args[0] for call in quota_spy.await_args_list}
        self.assertNotIn("getipintel", consumed_providers)
        self.assertNotIn("proxycheck", consumed_providers)
        self.assertNotIn("shodan_internetdb", consumed_providers)
        self.assertFalse(any(key.startswith(f"{ns}:quota:getipintel:") for key in fake_redis.strings))

        rows = {row["provider"]: row for row in payload["results"]}
        self.assertEqual(rows["GetIPIntel"]["status"], "Deferred (Light Mode)")
        self.assertIsNone(rows["GetIPIntel"]["statusCode"])
        self.assertTrue(rows["GetIPIntel"]["isDeferred"])
        self.assertEqual(rows["Cloudflare Radar"]["status"], "200 OK")

    def test_light_mode_returns_cached_getipintel_and_sets_non_partial_when_all_cached(self):
        fake_redis = _BatchingFakeRedis()
        mocks = self._patch_provider_suite()
        _login_authorised(self)

        cached_getipintel = json.dumps(
            {
                "row": self._build_ok_row("GetIPIntel", chance=0.972),
                "cachedAt": "2026-11-16T04:00:00+00:00",
                "sanitized": True,
            }
        )
        fake_redis.strings[cache_backends.provider_cache_key("getipintel", "8.8.8.8")] = cached_getipintel

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.cache_backends.redis_client", fake_redis),
        ):
            partial_resp = self.client.get("/api/v1/detect?ip=8.8.8.8&mode=light")

        self.assertEqual(partial_resp.status_code, 200)
        partial_payload = partial_resp.json()
        self.assertEqual(partial_payload["queryMode"], "light")
        self.assertTrue(partial_payload["isPartialMode"])
        self.assertEqual(partial_payload["getipintel_chance"], 0.972)
        mocks["getipintel"].assert_not_awaited()
        partial_rows = {row["provider"]: row for row in partial_payload["results"]}
        self.assertEqual(partial_rows["GetIPIntel"]["status"], "200 OK")
        self.assertTrue(partial_rows["GetIPIntel"]["isCached"])
        self.assertEqual(partial_rows["Proxycheck"]["status"], "Deferred (Light Mode)")

        # Pre-populate the remaining commercial sources so light mode requires no deferrals
        for provider_key, provider_name, _, _, _ in providers._PROVIDER_SPECS:
            cache_key = cache_backends.provider_cache_key(provider_key, "8.8.8.8")
            if cache_key not in fake_redis.strings:
                chance_val = 0.972 if provider_key == "getipintel" else None
                fake_redis.strings[cache_key] = json.dumps(
                    {
                        "row": self._build_ok_row(provider_name, chance=chance_val),
                        "cachedAt": "2026-11-16T04:00:00+00:00",
                        "sanitized": True,
                    }
                )

        for mock_fn in mocks.values():
            mock_fn.reset_mock()

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.cache_backends.redis_client", fake_redis),
        ):
            complete_resp = self.client.get("/api/v1/detect?ip=8.8.8.8&mode=light")

        self.assertEqual(complete_resp.status_code, 200)
        complete_payload = complete_resp.json()
        self.assertEqual(complete_payload["queryMode"], "light")
        self.assertFalse(complete_payload["isPartialMode"])
        self.assertEqual(complete_payload["getipintel_chance"], 0.972)
        for mock_fn in mocks.values():
            mock_fn.assert_not_awaited()

    def test_follow_up_full_mode_queries_uncached_commercial_sources_and_writes_redis(self):
        fake_redis = _BatchingFakeRedis()
        mocks = self._patch_provider_suite()
        _login_authorised(self)

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.cache_backends.redis_client", fake_redis),
        ):
            light_resp = self.client.get("/api/v1/detect?ip=8.8.8.8&mode=light")
            self.assertEqual(light_resp.status_code, 200)
            self.assertTrue(light_resp.json()["isPartialMode"])
            mocks["getipintel"].assert_not_awaited()

            for mock_fn in mocks.values():
                mock_fn.reset_mock()

            full_resp = self.client.get("/api/v1/detect?ip=8.8.8.8&mode=full")

        self.assertEqual(full_resp.status_code, 200)
        full_payload = full_resp.json()
        self.assertEqual(full_payload["queryMode"], "full")
        self.assertFalse(full_payload["isPartialMode"])
        self.assertEqual(full_payload["getipintel_chance"], 0.985)

        mocks["getipintel"].assert_awaited_once()
        mocks["proxycheck"].assert_awaited_once()
        # Sources already populated by the light query stay served from Redis
        for active_key in ("cloudflare_radar", "maxmind", "stopforumspam", "tor_onionoo", "dshield"):
            mocks[active_key].assert_not_awaited()

        ns = cache_backends.get_redis_namespace()
        self.assertIn(cache_backends.provider_cache_key("getipintel", "8.8.8.8"), fake_redis.strings)
        self.assertTrue(any(key.startswith(f"{ns}:quota:getipintel:") for key in fake_redis.strings))

    def test_default_invalid_and_non_public_modes_preserve_backward_compatibility(self):
        fake_redis = _BatchingFakeRedis()
        mocks = self._patch_provider_suite()
        _login_authorised(self)

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.cache_backends.redis_client", fake_redis),
        ):
            default_resp = self.client.get("/api/v1/detect?ip=1.1.1.1")
            invalid_mode_resp = self.client.get("/api/v1/detect?ip=1.0.0.1&mode=invalid")
            non_public_light_resp = self.client.get("/api/v1/detect?ip=127.0.0.1&mode=light")

        self.assertEqual(default_resp.status_code, 200)
        self.assertEqual(default_resp.json()["queryMode"], "full")
        self.assertFalse(default_resp.json()["isPartialMode"])

        self.assertEqual(invalid_mode_resp.status_code, 200)
        self.assertEqual(invalid_mode_resp.json()["queryMode"], "full")
        self.assertFalse(invalid_mode_resp.json()["isPartialMode"])
        self.assertEqual(mocks["getipintel"].await_count, 2)

        self.assertEqual(non_public_light_resp.status_code, 200)
        non_public_payload = non_public_light_resp.json()
        self.assertTrue(non_public_payload["isNonPublic"])
        self.assertEqual(non_public_payload["queryMode"], "light")
        self.assertFalse(non_public_payload["isPartialMode"])

    def test_batch_detect_defaults_to_light_mode_supports_compact_and_explicit_full_mode(self):
        fake_redis = _BatchingFakeRedis()
        mocks = self._patch_provider_suite()
        bearer_token = views.issue_gadget_token("SysopUser")
        headers = {"HTTP_AUTHORIZATION": f"Bearer {bearer_token}"}

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.cache_backends.redis_client", fake_redis),
        ):
            default_resp = self.client.post(
                "/api/v1/detect/batch",
                data=json.dumps({"ips": ["8.8.8.8"]}),
                content_type="application/json",
                **headers,
            )
            invalid_resp = self.client.post(
                "/api/v1/detect/batch",
                data=json.dumps({"ips": ["1.1.1.1"], "mode": "unknown"}),
                content_type="application/json",
                **headers,
            )
            compact_light_resp = self.client.post(
                "/api/v1/detect/batch?compact=1",
                data=json.dumps({"ips": ["8.8.8.8"], "mode": "light"}),
                content_type="application/json",
                **headers,
            )
            body_compact_resp = self.client.post(
                "/api/v1/detect/batch",
                data=json.dumps({"ips": ["8.8.8.8"], "compact": True}),
                content_type="application/json",
                **headers,
            )

        self.assertEqual(default_resp.status_code, 200)
        default_payload = default_resp.json()
        self.assertEqual(default_payload["queryMode"], "light")
        self.assertTrue(default_payload["results"]["8.8.8.8"]["isPartialMode"])
        self.assertEqual(default_payload["results"]["8.8.8.8"]["queryMode"], "light")
        for row in default_payload["results"]["8.8.8.8"]["results"]:
            self.assertIn("rawJson", row)

        self.assertEqual(invalid_resp.status_code, 200)
        self.assertEqual(invalid_resp.json()["queryMode"], "light")
        self.assertTrue(invalid_resp.json()["results"]["1.1.1.1"]["isPartialMode"])

        for compact_resp in (compact_light_resp, body_compact_resp):
            self.assertEqual(compact_resp.status_code, 200)
            for row in compact_resp.json()["results"]["8.8.8.8"]["results"]:
                self.assertNotIn("rawJson", row)

        mocks["getipintel"].assert_not_awaited()
        self.assertFalse(any(key.startswith("proxycheck:v1:quota:getipintel:") for key in fake_redis.strings))

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.cache_backends.redis_client", fake_redis),
        ):
            explicit_full_resp = self.client.post(
                "/api/v1/detect/batch",
                data=json.dumps({"ips": ["8.8.8.8"], "mode": "full"}),
                content_type="application/json",
                **headers,
            )

        self.assertEqual(explicit_full_resp.status_code, 200)
        full_payload = explicit_full_resp.json()
        self.assertEqual(full_payload["queryMode"], "full")
        self.assertFalse(full_payload["results"]["8.8.8.8"]["isPartialMode"])
        self.assertEqual(full_payload["results"]["8.8.8.8"]["getipintel_chance"], 0.985)
        mocks["getipintel"].assert_awaited_once()

    async def test_concurrent_light_and_full_requests_do_not_collide_in_singleflight(self):
        light_started = asyncio.Event()
        release_light = asyncio.Event()
        radar_calls = {"count": 0}
        mocks = self._patch_provider_suite()

        async def _gated_radar(client, ip):
            radar_calls["count"] += 1
            if radar_calls["count"] == 1:
                light_started.set()
                await release_light.wait()
            return self._build_ok_row("Cloudflare Radar")

        mocks["cloudflare_radar"].side_effect = _gated_radar
        auth_headers = {"Authorization": f"Bearer {views.issue_gadget_token('SysopUser')}"}
        factory = AsyncRequestFactory()
        light_req = factory.get("/api/v1/detect?ip=8.8.4.4&mode=light", headers=auth_headers)
        full_req = factory.get("/api/v1/detect?ip=8.8.4.4&mode=full", headers=auth_headers)

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.cache_backends.redis_client", None),
        ):
            light_task = asyncio.create_task(views.detect_ip(light_req))
            await light_started.wait()
            # Full request must start independently instead of joining the in-flight light task
            full_resp = await views.detect_ip(full_req)
            release_light.set()
            light_resp = await light_task

        self.assertEqual(full_resp.status_code, 200)
        full_payload = json.loads(full_resp.content)
        self.assertEqual(full_payload["queryMode"], "full")
        self.assertFalse(full_payload["isPartialMode"])
        self.assertEqual(full_payload["getipintel_chance"], 0.985)

        self.assertEqual(light_resp.status_code, 200)
        light_payload = json.loads(light_resp.content)
        self.assertEqual(light_payload["queryMode"], "light")
        self.assertTrue(light_payload["isPartialMode"])
        self.assertIsNone(light_payload["getipintel_chance"])
        mocks["getipintel"].assert_awaited_once()
        self.assertEqual(len(detection_service._ip_detect_inflight), 0)
