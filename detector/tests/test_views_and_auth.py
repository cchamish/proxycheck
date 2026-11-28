"""Core P0 tests for view authentication, session CSRF, OAuth cycling, logout, and admin guards."""

import json
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import dns.resolver
from django.conf import settings
from django.test import Client, TestCase, override_settings

from detector import views
from detector.auth.oauth import MetaWikiRightsFetchError
from detector.cache import redis_backend as cache_backends
from detector.providers.adapters_http import adapt_dshield, adapt_tor_onionoo
from detector.providers.local import adapt_stopforumspam

from .helpers import FakeAsyncRedis, _login_authorised, _mock_response, start_non_dnsbl_provider_stubs


class DetectorViewsAndAuthTests(TestCase):
    """P0 regression tests covering detect, refresh, OAuth, logout, CSRF, and admin endpoints."""

    def setUp(self):
        cache_backends.reset_redis_circuit_breaker()
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock, side_effect=dns.resolver.NXDOMAIN()
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)

    def _patch_detect_providers(self):
        start_non_dnsbl_provider_stubs(
            self,
            overrides={
                "tor_onionoo": adapt_tor_onionoo({"relays": []}, 200, "8.8.8.8"),
                "stopforumspam": adapt_stopforumspam(
                    {"success": 1, "ip": {"appears": 0, "frequency": 0, "confidence": 0.0}}, 200
                ),
                "dshield": adapt_dshield({"ip": {"attacks": 0, "count": 0}}, 200),
            },
        )

    def test_detect_ip_enforces_authentication_and_rbac(self):
        """Enforces 401/403/200, invalid IP rejection, and private cache headers on detect."""
        self.assertEqual(self.client.get("/api/v1/detect?ip=8.8.8.8").status_code, 401)

        session = self.client.session
        session["wikimedia_user"] = {
            "isLoggedIn": True,
            "username": "RegularEditor",
            "role": "Standard User (Unauthorised)",
            "hasAccess": False,
            "localGroups": ["autoconfirmed"],
            "globalGroups": [],
        }
        session.save()
        self.assertEqual(self.client.get("/api/v1/detect?ip=8.8.8.8").status_code, 403)

        _login_authorised(self)
        self._patch_detect_providers()
        ok_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")
        self.assertEqual(ok_resp.status_code, 200)
        self.assertEqual(ok_resp.headers.get("Cache-Control"), "private, no-cache")

        for query in ("", "?ip=", "?ip=not-an-ip"):
            with self.subTest(query=query):
                bad_resp = self.client.get(f"/api/v1/detect{query}")
                self.assertEqual(bad_resp.status_code, 400)
                self.assertEqual(bad_resp.json()["error"], "invalid_ip")

    def test_refresh_endpoint_enforces_auth_session_csrf_and_body_ip(self):
        """Enforces auth, session CSRF, JSON body IP without query fallback, and Bearer refresh limits."""
        csrf_client = Client(enforce_csrf_checks=True)
        self.assertEqual(
            csrf_client.post(
                "/api/v1/detect/refresh", data=json.dumps({"ip": "8.8.8.8"}), content_type="application/json"
            ).status_code,
            401,
        )

        session = csrf_client.session
        session["wikimedia_user"] = {
            "isLoggedIn": True,
            "username": "AllowlistedAdmin",
            "role": "Local Administrator (sysop)",
            "hasAccess": True,
            "localGroups": ["sysop"],
            "globalGroups": [],
        }
        session.save()

        no_csrf = csrf_client.post(
            "/api/v1/detect/refresh", data=json.dumps({"ip": "8.8.8.8"}), content_type="application/json"
        )
        self.assertEqual(no_csrf.status_code, 403)
        self.assertEqual(no_csrf.json()["error"], "csrf_failed")

        user_resp = csrf_client.get("/api/v1/auth/user/")
        csrf_token = user_resp.cookies["csrftoken"].value
        self._patch_detect_providers()
        ok_session = csrf_client.post(
            "/api/v1/detect/refresh",
            data=json.dumps({"ip": "8.8.8.8"}),
            content_type="application/json",
            headers={"X-CSRFToken": csrf_token},
        )
        self.assertEqual(ok_session.status_code, 200)

        # Query-string ?ip= fallback must not be accepted on POST refresh.
        qs_only = csrf_client.post(
            "/api/v1/detect/refresh?ip=8.8.8.8",
            data="{}",
            content_type="application/json",
            headers={"X-CSRFToken": csrf_token},
        )
        self.assertEqual(qs_only.status_code, 400)

        with override_settings(ALLOWED_WIKI_USERS="AllowlistedAdmin"):
            bearer = views.issue_gadget_token("AllowlistedAdmin")
            bearer_resp = csrf_client.post(
                "/api/v1/detect/refresh",
                data=json.dumps({"ip": "8.8.4.4"}),
                content_type="application/json",
                headers={"Authorization": f"Bearer {bearer}"},
            )
            self.assertEqual(bearer_resp.status_code, 200)

            fake_redis = FakeAsyncRedis()
            with (
                patch("detector.cache.redis_backend.redis_client", fake_redis),
                override_settings(REFRESH_USER_RPM_LIMIT=1, REFRESH_USER_RPH_LIMIT=60, REFRESH_GLOBAL_RPM_LIMIT=30),
            ):
                first = csrf_client.post(
                    "/api/v1/detect/refresh",
                    data=json.dumps({"ip": "1.1.1.1"}),
                    content_type="application/json",
                    headers={"Authorization": f"Bearer {bearer}"},
                )
                second = csrf_client.post(
                    "/api/v1/detect/refresh",
                    data=json.dumps({"ip": "9.9.9.9"}),
                    content_type="application/json",
                    headers={"Authorization": f"Bearer {bearer}"},
                )
                self.assertEqual(first.status_code, 200)
                self.assertEqual(second.status_code, 429)

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test-client-id",
        WIKIMEDIA_CLIENT_SECRET="test-client-secret",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/oauth/callback",
    )
    def test_oauth_login_and_callback_state_and_session_cycle_key(self):
        """Rotates session keys via cycle_key on login and prevents OAuth state replay."""
        login_resp = self.client.get("/api/v1/auth/login/?ip=2001:0db8:0:0::0001")
        self.assertEqual(login_resp.status_code, 302)
        state = parse_qs(urlparse(login_resp["Location"]).query)["state"][0]
        session_key_before = self.client.session.session_key
        self.assertEqual(self.client.session.get("oauth_post_login_ip"), "2001:db8::1")

        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_response(200, {"access_token": "tok-1"})
        mock_client.get.return_value = _mock_response(
            200, {"username": "Patroller", "groups": ["sysop"], "rights": ["checkuser-temporary-account"]}
        )
        mock_client.__aenter__.return_value = mock_client

        with (
            patch("detector.core.http_client.httpx.AsyncClient", return_value=mock_client),
            patch(
                "detector.auth.oauth.fetch_user_rights_from_meta",
                AsyncMock(return_value={"global_groups": [], "global_rights": [], "merged_projects": []}),
            ),
        ):
            cb_resp = self.client.get(f"/api/v1/auth/callback/?code=auth-code&state={state}")
        self.assertEqual(cb_resp.status_code, 302)
        self.assertEqual(cb_resp["Location"], "/?ip=2001%3Adb8%3A%3A1")
        self.assertNotEqual(self.client.session.session_key, session_key_before)
        self.assertTrue(self.client.session["wikimedia_user"]["hasAccess"])

        # Replaying a consumed OAuth state from a fresh client must not exchange tokens or create a session.
        replay_client = Client()
        replay_resp = replay_client.get(f"/api/v1/auth/callback/?code=auth-code&state={state}")
        self.assertEqual(replay_resp.status_code, 302)
        self.assertNotIn("wikimedia_user", replay_client.session)
        self.assertEqual(mock_client.post.call_count, 1)

        # Upstream Meta-Wiki failure must not persist an unprivileged session.
        fail_client = Client()
        fail_client.get("/api/v1/auth/login/")
        next_state = fail_client.session["oauth_state"]
        mock_client.get.return_value = _mock_response(200, {"username": "Patroller", "groups": ["user"]})
        with (
            patch("detector.core.http_client.httpx.AsyncClient", return_value=mock_client),
            patch(
                "detector.auth.oauth.fetch_user_rights_from_meta",
                AsyncMock(side_effect=MetaWikiRightsFetchError("down")),
            ),
        ):
            fail_client.get(f"/api/v1/auth/callback/?code=auth-code&state={next_state}")
        self.assertNotIn("wikimedia_user", fail_client.session)

    def test_logout_requires_post_with_csrf_and_always_deletes_cookie(self):
        """Enforces POST+CSRF logout, no-store headers, CSRF seeding, and auth-gated memoryMb."""
        csrf_client = Client(enforce_csrf_checks=True)
        spa_resp = csrf_client.get("/")
        self.assertIn("csrftoken", spa_resp.cookies)

        anon_user = csrf_client.get("/api/v1/auth/user/")
        self.assertEqual(anon_user.status_code, 200)
        self.assertEqual(anon_user.headers.get("Cache-Control"), "no-store")
        self.assertIn("csrftoken", anon_user.cookies)
        self.assertNotIn("memoryMb", anon_user.json())

        get_logout = csrf_client.get("/api/v1/auth/logout/")
        self.assertEqual(get_logout.status_code, 405)
        self.assertEqual(get_logout.headers.get("Cache-Control"), "no-store")

        no_csrf_logout = csrf_client.post("/api/v1/auth/logout/")
        self.assertEqual(no_csrf_logout.status_code, 403)

        csrf_token = anon_user.cookies["csrftoken"].value
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

        authed_user = csrf_client.get("/api/v1/auth/user/")
        self.assertIn("memoryMb", authed_user.json())

        ok_logout = csrf_client.post("/api/v1/auth/logout/", headers={"X-CSRFToken": csrf_token})
        self.assertEqual(ok_logout.status_code, 200)
        self.assertEqual(ok_logout.headers.get("Cache-Control"), "no-store")
        self.assertIn("memoryMb", ok_logout.json())
        self.assertEqual(ok_logout.cookies[settings.SESSION_COOKIE_NAME].value, "")

        anon_logout = csrf_client.post("/api/v1/auth/logout/", headers={"X-CSRFToken": csrf_token})
        self.assertEqual(anon_logout.status_code, 200)
        self.assertNotIn("memoryMb", anon_logout.json())

    def test_switch_test_role_and_oauth_fallback_enforce_dual_guard(self):
        """Blocks test auth role switching unless both DEBUG and ENABLE_TEST_AUTH are enabled."""
        for debug_flag, test_auth_flag, expected_status in (
            (False, False, 403),
            (True, False, 403),
            (False, True, 403),
            (True, True, 200),
        ):
            with (
                self.subTest(debug=debug_flag, test_auth=test_auth_flag),
                override_settings(
                    DEBUG=debug_flag, ENABLE_TEST_AUTH=test_auth_flag, WIKIMEDIA_CLIENT_ID="", WIKIMEDIA_REDIRECT_URI=""
                ),
            ):
                resp = self.client.post(
                    "/api/v1/auth/switch-role/", data=json.dumps({"role": "steward"}), content_type="application/json"
                )
                self.assertEqual(resp.status_code, expected_status)
                login_resp = self.client.get("/api/v1/auth/login/")
                self.assertEqual(login_resp.status_code, 302 if expected_status == 200 else 503)

    def test_system_status_and_admin_dashboard_require_allowlisted_session(self):
        """Restricts system status and provider dashboard to allowlisted administrator sessions."""
        for path in ("/api/v1/status/", "/api/v1/admin/provider-dashboard/"):
            with self.subTest(path=path):
                self.client.logout()
                self.assertEqual(self.client.get(path).status_code, 401)
                _login_authorised(self)
                with override_settings(ALLOWED_WIKI_USERS="OtherAdmin"):
                    self.assertEqual(self.client.get(path).status_code, 403)
                with override_settings(ALLOWED_WIKI_USERS="SysopUser"):
                    bearer = views.issue_gadget_token("SysopUser")
                    self.assertEqual(self.client.get(path, HTTP_AUTHORIZATION=f"Bearer {bearer}").status_code, 403)
                    ok_resp = self.client.get(path)
                    self.assertEqual(ok_resp.status_code, 200)
                    self.assertEqual(ok_resp.headers.get("Cache-Control"), "no-store")
