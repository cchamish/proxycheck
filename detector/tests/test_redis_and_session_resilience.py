"""Core P0 tests for Redis transport degradation and resilient session/logout handling."""

from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
from django.conf import settings
from django.test import Client, TestCase

from detector.cache import redis_backend as cache_backends

from .helpers import _login_authorised, start_non_dnsbl_provider_stubs


class RedisAndSessionResilienceTests(TestCase):
    """P0 tests ensuring Redis outages never crash detection, user status, or logout cookie clearing."""

    def setUp(self):
        cache_backends.reset_redis_circuit_breaker()
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock, side_effect=dns.resolver.NXDOMAIN()
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)

    def tearDown(self):
        cache_backends.reset_redis_circuit_breaker()

    def test_detect_ip_degrades_safely_when_redis_raises_transport_errors(self):
        """Falls back to upstream detection when Redis raises connection or timeout errors."""
        _login_authorised(self)
        start_non_dnsbl_provider_stubs(self)
        broken = AsyncMock()
        broken.get.side_effect = ConnectionError("redis down")
        broken.mget.side_effect = ConnectionError("redis down")
        broken.set.side_effect = TimeoutError("redis timeout")
        broken_pipe = MagicMock()
        broken_pipe.execute = AsyncMock(side_effect=ConnectionError("redis down"))
        broken.pipeline = MagicMock(return_value=broken_pipe)

        with patch("detector.cache.redis_backend.redis_client", broken):
            resp = self.client.get("/api/v1/detect?ip=8.8.8.8")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["ip"], "8.8.8.8")

    def test_session_backend_outage_degrades_safely_on_oauth_user_and_logout(self):
        """Returns safe fallback on session failure and deletes session cookie even if Redis flush fails."""
        with patch(
            "django.contrib.sessions.backends.cache.SessionStore.load", side_effect=ConnectionError("redis down")
        ):
            user_resp = self.client.get("/api/v1/auth/user/")
        self.assertEqual(user_resp.status_code, 200)
        self.assertFalse(user_resp.json()["isLoggedIn"])

        csrf_client = Client(enforce_csrf_checks=True)
        csrf_token = csrf_client.get("/api/v1/auth/user/").cookies["csrftoken"].value
        with patch(
            "django.contrib.sessions.backends.cache.SessionStore.flush", side_effect=ConnectionError("redis down")
        ):
            logout_resp = csrf_client.post("/api/v1/auth/logout/", headers={"X-CSRFToken": csrf_token})
        self.assertEqual(logout_resp.status_code, 200)
        self.assertEqual(logout_resp.headers.get("Cache-Control"), "no-store")
        self.assertEqual(logout_resp.cookies[settings.SESSION_COOKIE_NAME].value, "")
