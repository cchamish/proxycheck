"""Tests for detection endpoints, OAuth login and callback, RBAC, and SPA routing."""

import asyncio
import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import dns.exception
import dns.name
import dns.resolver
import dns.reversename
import httpx
from django.test import SimpleTestCase, TestCase, override_settings

from detector import cache_backends, detection_service, providers, views
from detector.adapters import (
    adapt_dshield,
    adapt_stopforumspam,
    adapt_tor_onionoo,
)
from detector.oauth import (
    MetaWikiRightsFetchError,
    extract_wikimedia_domain_from_project,
    fetch_project_user_rights,
    fetch_user_rights_from_meta,
    is_session_rights_expired,
)

from .helpers import (
    MAXMIND_STUB,
    _login_authorised,
    _mock_response,
    start_non_dnsbl_provider_stubs,
)


class DetectorAuthTests(TestCase):
    """Tests for IP detection access control, test role guards, and OAuth state validation."""

    def setUp(self):
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)

    # Verify detect_ip authentication and role-based access control
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

    @patch("detector.cache_backends.redis_client", None)
    def test_detect_ip_enforces_authentication_and_rbac(self):
        unauth_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")
        self.assertEqual(unauth_resp.status_code, 401)
        self.assertIn("error", unauth_resp.json())

        session = self.client.session
        session["wikimedia_user"] = {
            "isLoggedIn": True,
            "username": "StandardEditor",
            "role": "Standard User (Unauthorised)",
            "hasAccess": False,
            "localGroups": ["autoreview"],
            "globalGroups": [],
        }
        session.save()

        forbidden_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")
        self.assertEqual(forbidden_resp.status_code, 403)
        self.assertIn("error", forbidden_resp.json())

        self._patch_detect_providers()
        _login_authorised(self)

        response = self.client.get("/api/v1/detect?ip=8.8.8.8")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["ip"], "8.8.8.8")
        self.assertEqual(len(payload["results"]), 17)
        result_providers = {row["provider"] for row in payload["results"]}
        self.assertNotIn("Tor Onionoo", result_providers)
        self.assertIn("StopForumSpam", result_providers)
        self.assertIn("DShield", result_providers)

    def test_switch_test_role_enforces_dual_guard(self):
        for debug_flag, test_auth_flag, expected_status in (
            (False, False, 403),
            (True, False, 403),
            (False, True, 403),
            (True, True, 200),
        ):
            with (
                self.subTest(debug=debug_flag, enable_test_auth=test_auth_flag),
                override_settings(DEBUG=debug_flag, ENABLE_TEST_AUTH=test_auth_flag),
            ):
                self.client.session.flush()
                response = self.client.post(
                    "/api/v1/auth/switch-role/",
                    data=json.dumps({"role": "steward"}),
                    content_type="application/json",
                )
                self.assertEqual(response.status_code, expected_status)
                if expected_status == 200:
                    data = response.json()
                    self.assertEqual(data["role"], "Steward")
                    self.assertTrue(data["hasAccess"])
                    self.assertEqual(self.client.session["wikimedia_user"]["role"], "Steward")
                else:
                    self.assertIsNone(self.client.session.get("wikimedia_user"))

    def test_oauth_login_without_credentials_enforces_dual_guard(self):
        for debug_flag, test_auth_flag, expected_status in (
            (False, False, 503),
            (True, False, 503),
            (True, True, 302),
        ):
            with (
                self.subTest(debug=debug_flag, enable_test_auth=test_auth_flag),
                override_settings(
                    DEBUG=debug_flag,
                    ENABLE_TEST_AUTH=test_auth_flag,
                    WIKIMEDIA_CLIENT_ID="",
                    WIKIMEDIA_REDIRECT_URI="",
                ),
            ):
                self.client.session.flush()
                response = self.client.get("/api/v1/auth/login/")
                self.assertEqual(response.status_code, expected_status)
                if expected_status == 302:
                    self.assertEqual(response["Location"], "/")
                    self.assertTrue(self.client.session["wikimedia_user"]["hasAccess"])
                else:
                    self.assertIsNone(self.client.session.get("wikimedia_user"))

        with override_settings(
            DEBUG=True,
            ENABLE_TEST_AUTH=True,
            WIKIMEDIA_CLIENT_ID="",
            WIKIMEDIA_REDIRECT_URI="",
        ):
            valid_resp = self.client.get("/api/v1/auth/login/?ip=2001:0db8::01")
            self.assertEqual(valid_resp.status_code, 302)
            self.assertEqual(valid_resp["Location"], "/?ip=2001%3Adb8%3A%3A1")
            self.assertIsNone(self.client.session.get("oauth_post_login_ip"))

            invalid_resp = self.client.get("/api/v1/auth/login/?ip=bad")
            self.assertEqual(invalid_resp.status_code, 302)
            self.assertEqual(invalid_resp["Location"], "/")
            self.assertIsNone(self.client.session.get("oauth_post_login_ip"))

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/api/v1/auth/callback",
        WIKIMEDIA_OAUTH_URL="https://meta.wikimedia.org/w/rest.php/oauth2",
    )
    def test_oauth_login_generates_state_and_persists_canonical_ip_only(self):
        response = self.client.get("/api/v1/auth/login/?ip=2001:0db8::01")
        self.assertEqual(response.status_code, 302)
        parsed = urlparse(response["Location"])
        params = parse_qs(parsed.query)
        self.assertEqual(params["client_id"], ["test_client_id"])
        self.assertEqual(params["redirect_uri"], ["https://proxycheck.toolforge.org/api/v1/auth/callback"])
        session_state = self.client.session.get("oauth_state")
        self.assertTrue(session_state)
        self.assertEqual(params["state"], [session_state])
        self.assertEqual(self.client.session.get("oauth_post_login_ip"), "2001:db8::1")

        # Starting a plain login clears any abandoned post-login IP, and invalid targets are ignored
        for path in ("/api/v1/auth/login/", "/api/v1/auth/login/?ip=https://evil.example"):
            with self.subTest(path=path):
                follow_up = self.client.get(path)
                self.assertEqual(follow_up.status_code, 302)
                self.assertIsNone(self.client.session.get("oauth_post_login_ip"))

    # Verify oauth_callback state validation and error handling

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="test_client_secret",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/api/v1/auth/callback",
    )
    @patch("detector.oauth.fetch_user_rights_from_meta", new_callable=AsyncMock)
    @patch("detector.http_client.httpx.AsyncClient")
    def test_oauth_callback_valid_state_authenticates_and_prevents_replay(self, mock_async_client_cls, mock_fetch_meta):
        mock_client = AsyncMock()
        mock_async_client_cls.return_value.__aenter__.return_value = mock_client

        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = {"access_token": "valid_access_token"}
        mock_client.post.return_value = token_resp

        profile_resp = MagicMock()
        profile_resp.status_code = 200
        profile_resp.json.return_value = {
            "username": "WikiAdmin",
            "groups": ["sysop"],
            "rights": ["read", "edit"],
        }
        mock_client.get.return_value = profile_resp
        mock_fetch_meta.return_value = {
            "global_groups": ["steward"],
            "global_rights": ["checkuser-temporary-account-no-preference"],
            "merged_projects": [],
        }

        session = self.client.session
        session["oauth_state"] = "valid_random_state_token_123"
        session.save()

        # First callback with matching state succeeds
        response = self.client.get("/api/v1/auth/callback/?code=auth_code_1&state=valid_random_state_token_123")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")
        self.assertIsNone(self.client.session.get("oauth_state"))
        user_session = self.client.session.get("wikimedia_user")
        self.assertIsNotNone(user_session)
        self.assertEqual(user_session["username"], "WikiAdmin")
        self.assertTrue(user_session["hasAccess"])
        self.assertEqual(mock_client.post.call_count, 1)

        # Replay with the same state must be rejected because oauth_state was popped
        session = self.client.session
        session.pop("wikimedia_user", None)
        session.save()

        replay_resp = self.client.get("/api/v1/auth/callback/?code=auth_code_1&state=valid_random_state_token_123")
        self.assertEqual(replay_resp.status_code, 302)
        self.assertIsNone(self.client.session.get("wikimedia_user"))
        self.assertEqual(mock_client.post.call_count, 1)

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="test_client_secret",
    )
    @patch("detector.http_client.httpx.AsyncClient")
    def test_oauth_callback_invalid_or_mismatched_state_clears_session(self, mock_async_client_cls):
        for label, expected_state, received_state in (
            ("mismatch", "expected_state_abc", "wrong_state_xyz"),
            ("non_ascii", "expected_ascii_state", "测试状态"),
        ):
            with self.subTest(case=label):
                session = self.client.session
                session["oauth_state"] = expected_state
                session["oauth_post_login_ip"] = "8.8.8.8"
                session.save()

                response = self.client.get("/api/v1/auth/callback/", {"code": "auth_code_1", "state": received_state})
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response["Location"], "/")
                self.assertIsNone(self.client.session.get("oauth_state"))
                self.assertIsNone(self.client.session.get("oauth_post_login_ip"))
                self.assertIsNone(self.client.session.get("wikimedia_user"))
        mock_async_client_cls.assert_not_called()

    def _configure_oauth_callback_mocks(
        self,
        mock_async_client_cls,
        mock_fetch_meta,
        *,
        username: str = "WikiAdmin",
        groups: list[str] | None = None,
        global_rights: list[str] | None = None,
    ) -> None:
        """Configure HTTPX and Meta API mocks for OAuth callback redirect tests."""
        mock_client = AsyncMock()
        mock_async_client_cls.return_value.__aenter__.return_value = mock_client

        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = {"access_token": "valid_access_token"}
        mock_client.post.return_value = token_resp

        profile_resp = MagicMock()
        profile_resp.status_code = 200
        profile_resp.json.return_value = {
            "username": username,
            "groups": ["sysop"] if groups is None else groups,
            "rights": ["read", "edit"],
        }
        mock_client.get.return_value = profile_resp
        mock_fetch_meta.return_value = {
            "global_groups": [],
            "global_rights": ["checkuser-temporary-account"] if global_rights is None else global_rights,
            "merged_projects": [],
        }

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="test_client_secret",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/api/v1/auth/callback",
    )
    @patch("detector.oauth.fetch_user_rights_from_meta", new_callable=AsyncMock)
    @patch("detector.http_client.httpx.AsyncClient")
    def test_oauth_callback_post_login_ip_redirect_and_sanitisation(self, mock_async_client_cls, mock_fetch_meta):
        cases = (
            (
                "valid_authorised",
                "WikiAdmin",
                ["sysop"],
                ["checkuser-temporary-account"],
                "2001:db8::1",
                "/?ip=2001%3Adb8%3A%3A1",
                True,
            ),
            ("unauthorised_drops_ip", "RegularUser", ["autoconfirmed"], [], "8.8.8.8", "/", False),
            (
                "invalid_session_ip",
                "WikiAdmin",
                ["sysop"],
                ["checkuser-temporary-account"],
                "https://evil.example",
                "/",
                True,
            ),
        )
        for label, username, groups, rights, session_ip, expected_location, expected_access in cases:
            with self.subTest(case=label):
                self._configure_oauth_callback_mocks(
                    mock_async_client_cls,
                    mock_fetch_meta,
                    username=username,
                    groups=groups,
                    global_rights=rights,
                )
                session = self.client.session
                session["oauth_state"] = f"state_{label}"
                session["oauth_post_login_ip"] = session_ip
                session.save()

                response = self.client.get(f"/api/v1/auth/callback/?code=auth_code_1&state=state_{label}")
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response["Location"], expected_location)
                self.assertIsNone(self.client.session.get("oauth_post_login_ip"))
                self.assertEqual(self.client.session["wikimedia_user"]["hasAccess"], expected_access)

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="test_client_secret",
    )
    @patch("detector.http_client.httpx.AsyncClient")
    def test_oauth_callback_error_parameter_cleans_state_without_raw_log_leak(self, mock_async_client_cls):
        session = self.client.session
        session["oauth_state"] = "state_to_be_cleaned"
        session.save()

        with self.assertLogs("detector.views", level="WARNING") as captured:
            response = self.client.get("/api/v1/auth/callback/?error=access_denied&state=state_to_be_cleaned")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")
        self.assertIsNone(self.client.session.get("oauth_state"))
        self.assertIsNone(self.client.session.get("wikimedia_user"))
        self.assertTrue(any("access_denied" in msg for msg in captured.output))

        session = self.client.session
        session["oauth_state"] = "state_to_be_cleaned"
        session.save()
        raw_secret_like_value = "leaked_client_secret_999\nforged_entry"
        with self.assertLogs("detector.views", level="WARNING") as raw_captured:
            raw_response = self.client.get(
                "/api/v1/auth/callback/",
                {"error": raw_secret_like_value, "state": "state_to_be_cleaned"},
            )
        self.assertEqual(raw_response.status_code, 302)
        self.assertIsNone(self.client.session.get("oauth_state"))
        log_output = "\n".join(raw_captured.output)
        self.assertNotIn("leaked_client_secret_999", log_output)
        self.assertNotIn("forged_entry", log_output)
        mock_async_client_cls.assert_not_called()


class MetaWikiRightsAndSessionTtlTests(TestCase):
    """Tests distinction between Meta-Wiki API failures and empty user rights, plus session TTL expiry."""

    def test_fetch_user_rights_returns_empty_lists_for_normal_unprivileged_user(self):
        client = AsyncMock()
        client.get.return_value = _mock_response(
            status_code=200,
            json_value={
                "batchcomplete": "",
                "query": {
                    "globaluserinfo": {
                        "id": 999,
                        "name": "RegularUser",
                        "groups": [],
                        "rights": [],
                        "merged": [{"wiki": "enwiki", "groups": ["*", "user"]}],
                    }
                },
            },
        )
        rights = asyncio.run(fetch_user_rights_from_meta(client, "RegularUser"))
        self.assertEqual(rights["global_groups"], [])
        self.assertEqual(rights["global_rights"], [])
        self.assertEqual(len(rights["merged_projects"]), 1)

        client.get.return_value = _mock_response(
            status_code=200,
            json_value={
                "batchcomplete": "",
                "query": {
                    "globaluserinfo": {
                        "id": 1001,
                        "name": "GlobalRightUser",
                        "groups": ["global-temporary-account-viewer"],
                        "rights": ["read", "checkuser-temporary-account"],
                        "merged": [],
                    }
                },
            },
        )
        global_rights = asyncio.run(fetch_user_rights_from_meta(client, "GlobalRightUser"))
        self.assertEqual(global_rights["global_rights"], ["read", "checkuser-temporary-account"])

        self.assertEqual(
            extract_wikimedia_domain_from_project({"url": "https://ja.wikipedia.org/"}),
            "ja.wikipedia.org",
        )
        self.assertIsNone(extract_wikimedia_domain_from_project({"url": "https://evil.example.com"}))
        self.assertIsNone(extract_wikimedia_domain_from_project({"url": "https://zh.wikipedia.org:8443"}))
        self.assertIsNone(extract_wikimedia_domain_from_project({"url": "https://user@zh.wikipedia.org"}))

        client.get.return_value = _mock_response(
            status_code=200,
            json_value={
                "query": {"users": [{"name": "LocalRightUser", "rights": ["read", "checkuser-temporary-account"]}]}
            },
        )
        project_rights = asyncio.run(fetch_project_user_rights(client, "LocalRightUser", "zh.wikipedia.org"))
        self.assertEqual(project_rights, ["read", "checkuser-temporary-account"])

        client.get.reset_mock()
        self.assertEqual(asyncio.run(fetch_project_user_rights(client, "LocalRightUser", "evil.example.com")), [])
        client.get.assert_not_called()

        client.get.return_value = _mock_response(status_code=503, json_value={})
        self.assertEqual(asyncio.run(fetch_project_user_rights(client, "LocalRightUser", "zh.wikipedia.org")), [])

    def test_fetch_user_rights_raises_on_network_or_http_or_payload_errors(self):
        error_cases = (
            ("timeout", AsyncMock(side_effect=httpx.ConnectTimeout("timed out"))),
            ("http 503", AsyncMock(return_value=_mock_response(status_code=503, text="Service Unavailable"))),
            (
                "invalid json",
                AsyncMock(return_value=_mock_response(status_code=200, json_error=ValueError("bad json"))),
            ),
            (
                "api error payload",
                AsyncMock(return_value=_mock_response(status_code=200, json_value={"error": {"code": "failed"}})),
            ),
            (
                "missing user",
                AsyncMock(
                    return_value=_mock_response(
                        status_code=200, json_value={"query": {"globaluserinfo": {"missing": ""}}}
                    )
                ),
            ),
        )
        for label, get_mock in error_cases:
            with self.subTest(case=label):
                client = AsyncMock()
                client.get = get_mock
                with self.assertRaises(MetaWikiRightsFetchError):
                    asyncio.run(fetch_user_rights_from_meta(client, "SomeUser"))

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="test_client_secret",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/api/v1/auth/callback",
    )
    @patch("detector.oauth.fetch_user_rights_from_meta", new_callable=AsyncMock)
    @patch("detector.http_client.httpx.AsyncClient")
    def test_oauth_callback_does_not_persist_false_unauthorised_session_on_meta_failure(
        self, mock_async_client_cls, mock_fetch_meta
    ):
        mock_client = AsyncMock()
        mock_async_client_cls.return_value.__aenter__.return_value = mock_client

        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = {"access_token": "valid_token"}
        mock_client.post.return_value = token_resp

        profile_resp = MagicMock()
        profile_resp.status_code = 200
        profile_resp.json.return_value = {"username": "GlobalSysopUser", "groups": ["*"]}
        mock_client.get.return_value = profile_resp

        mock_fetch_meta.side_effect = MetaWikiRightsFetchError("Meta-Wiki HTTP 503")

        session = self.client.session
        session["oauth_state"] = "state_meta_fail"
        session.save()

        response = self.client.get("/api/v1/auth/callback/?code=code123&state=state_meta_fail")
        self.assertEqual(response.status_code, 302)
        self.assertIsNone(self.client.session.get("wikimedia_user"))

    @override_settings(SESSION_RIGHTS_TTL_SECONDS=60)
    def test_session_rights_ttl_expiration_evicts_stale_privileges(self):
        now = time.time()
        self.assertFalse(is_session_rights_expired({"rights_updated_at": now - 10}, ttl_seconds=60, now=now))
        self.assertTrue(is_session_rights_expired({"rights_updated_at": now - 120}, ttl_seconds=60, now=now))

        session = self.client.session
        session["wikimedia_user"] = {
            "isLoggedIn": True,
            "username": "FormerSysop",
            "role": "Local Administrator (sysop)",
            "hasAccess": True,
            "localGroups": ["sysop"],
            "globalGroups": [],
            "rights_updated_at": now - 120,
        }
        session.save()

        detect_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")
        self.assertEqual(detect_resp.status_code, 401)
        self.assertIsNone(self.client.session.get("wikimedia_user"))

        user_resp = self.client.get("/api/v1/auth/user/")
        self.assertEqual(user_resp.status_code, 200)
        self.assertFalse(user_resp.json()["isLoggedIn"])


class IpCanonicalizationAndSecurityBaselineTests(TestCase):
    """Tests IPv4 and IPv6 address canonicalisation for cache consistency and production security settings."""

    def setUp(self):
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)

        session = self.client.session
        session["wikimedia_user"] = {
            "isLoggedIn": True,
            "username": "TestSysop",
            "role": "Local Administrator (sysop)",
            "hasAccess": True,
            "localGroups": ["sysop"],
            "globalGroups": [],
        }
        session.save()

    def test_canonicalize_ip_normalizes_ipv6_variants_and_rejects_invalid_inputs(self):
        self.assertEqual(views.canonicalize_ip("2001:0db8:0:0::0001"), "2001:db8::1")
        self.assertEqual(views.canonicalize_ip("2001:DB8:0000:0000:0000:0000:0000:0001"), "2001:db8::1")
        self.assertEqual(views.canonicalize_ip("  2001:db8::1  "), "2001:db8::1")
        self.assertEqual(views.canonicalize_ip("8.8.8.8"), "8.8.8.8")
        self.assertIsNone(views.canonicalize_ip(""))
        self.assertIsNone(views.canonicalize_ip("not-an-ip"))
        self.assertIsNone(views.canonicalize_ip("999.999.999.999"))

    def test_detect_ip_variants_hit_identical_canonical_cache_key(self):
        def _ok_provider(name):
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

        start_non_dnsbl_provider_stubs(
            self,
            overrides={"maxmind": dict(MAXMIND_STUB)},
            row_builder=_ok_provider,
        )

        cache_store = {}

        async def _fake_get(key):
            return cache_store.get(key)

        async def _fake_set(key, val, ex=None, nx=False):
            if nx and key in cache_store:
                return False
            cache_store[key] = val
            return True

        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(side_effect=_fake_get)
        mock_redis.set = AsyncMock(side_effect=_fake_set)
        mock_redis.delete = AsyncMock(
            side_effect=lambda *keys: sum(1 for k in keys if cache_store.pop(k, None) is not None)
        )

        with patch("detector.cache_backends.redis_client", mock_redis):
            first_resp = self.client.get("/api/v1/detect?ip=2001:0486:4860:0:0::8888")
            second_resp = self.client.get("/api/v1/detect?ip=2001:0486:4860:0000:0000:0000:0000:8888")
            third_resp = self.client.get("/api/v1/detect?ip=2001:486:4860::8888")

        self.assertEqual(first_resp.status_code, 200)
        self.assertEqual(second_resp.status_code, 200)
        self.assertEqual(third_resp.status_code, 200)

        first_payload = first_resp.json()
        second_payload = second_resp.json()
        third_payload = third_resp.json()

        canonical_v6 = "2001:486:4860::8888"
        self.assertEqual(first_payload["ip"], canonical_v6)
        self.assertFalse(first_payload["isCached"])
        self.assertEqual(second_payload["ip"], canonical_v6)
        self.assertTrue(second_payload["isCached"])
        self.assertEqual(second_payload["cacheMeta"]["status"], "hit")
        self.assertEqual(second_payload["cacheMeta"]["layer"], "L1")
        self.assertEqual(third_payload["ip"], canonical_v6)
        self.assertTrue(third_payload["isCached"])
        self.assertIn(cache_backends.snapshot_cache_key(canonical_v6, mode="full"), cache_store)
        for pkey in ("proxycheck", "tor_onionoo", "stopforumspam", "dshield", "ptr"):
            self.assertIn(cache_backends.provider_cache_key(pkey, canonical_v6), cache_store)


class DetectEndpointValidationTests(TestCase):
    """Tests for IP parameter validation on the detect endpoint."""

    def setUp(self):
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)
        _login_authorised(self)

    def test_detect_ip_rejects_missing_and_invalid_ip_with_400(self):
        cases = (
            "/api/v1/detect",
            "/api/v1/detect?ip=",
            "/api/v1/detect?ip=   ",
            "/api/v1/detect/?ip=",
            "/api/v1/detect?ip=not-an-ip",
            "/api/v1/detect?ip=999.999.999.999",
            "/api/v1/detect?ip=1.2.3",
            "/api/v1/detect?ip=2001:xyz::1",
            "/api/v1/detect?ip=1.1.1.1/24",
            "/api/v1/detect?ip=localhost",
        )
        for url in cases:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"], "invalid_ip")


class SettingsAndHardeningTests(TestCase):
    """Tests for Allowed Hosts wildcard parsing."""

    def test_allowed_hosts_parser_normalizes_wildcard_prefixes(self):
        from proxycheck.settings import _parse_allowed_hosts

        parsed = _parse_allowed_hosts("localhost, 127.0.0.1, *.toolforge.org, .wmcloud.org")
        self.assertEqual(parsed, ["localhost", "127.0.0.1", ".toolforge.org", ".wmcloud.org"])
        self.assertEqual(_parse_allowed_hosts("  , "), ["127.0.0.1", "localhost"])


class SpaRoutingTests(SimpleTestCase):
    """Tests for SPA entrypoint serving, fallback HTML, and API or asset exclusions."""

    def test_spa_index_serves_dist_or_fallback_html(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir)
            with override_settings(BASE_DIR=base_dir):
                fallback_resp = self.client.get("/")
            self.assertEqual(fallback_resp.status_code, 200)
            self.assertEqual(fallback_resp["Content-Type"], "text/html; charset=utf-8")
            self.assertIn('<div id="app">Loading Proxy Detector...</div>', fallback_resp.content.decode("utf-8"))

            dist_dir = base_dir / "dist"
            dist_dir.mkdir(parents=True, exist_ok=True)
            (dist_dir / "index.html").write_text(
                "<!doctype html><html><body><div id='app'>Compiled Bundle</div></body></html>",
                encoding="utf-8",
            )

            with override_settings(BASE_DIR=base_dir):
                root_resp = self.client.get("/")
                subroute_resp = self.client.get("/lookup/8.8.8.8")

            self.assertEqual(root_resp.status_code, 200)
            self.assertEqual(root_resp["Content-Type"], "text/html; charset=utf-8")
            self.assertIn("Compiled Bundle", root_resp.content.decode("utf-8"))
            self.assertEqual(subroute_resp.status_code, 200)
            self.assertIn("Compiled Bundle", subroute_resp.content.decode("utf-8"))

    def test_spa_catch_all_excludes_api_oauth_assets_and_favicon_routes(self):
        api_miss = self.client.get("/api/nonexistent/")
        oauth_miss = self.client.get("/oauth/unknown-step/")
        asset_miss = self.client.get("/assets/missing-bundle.js")
        auth_user = self.client.get("/api/v1/auth/user/")
        toolforge_svg = self.client.get("/Proxycheck.svg")
        favicon_svg = self.client.get("/favicon.svg")
        favicon_ico = self.client.get("/favicon.ico")

        self.assertEqual(api_miss.status_code, 404)
        self.assertEqual(oauth_miss.status_code, 404)
        self.assertEqual(asset_miss.status_code, 404)
        self.assertEqual(auth_user.status_code, 200)
        self.assertEqual(auth_user["Content-Type"], "application/json")
        for icon_resp in (toolforge_svg, favicon_svg, favicon_ico):
            self.assertEqual(icon_resp.status_code, 200)
            self.assertIn("image/svg+xml", icon_resp["Content-Type"])


class OfflineDatabaseStatusEndpointTests(TestCase):
    """Tests inventory reporting, stale detection, and system status endpoint exposure."""

    def test_collect_offline_databases_status_reports_healthy_stale_and_missing(self):
        from datetime import datetime, timezone

        from detector import offline_dbs

        now_dt = datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            data_dir = root / "data"
            data_dir.mkdir()
            sfs_toxic = data_dir / "toxic_ip_cidr.txt"
            sfs_90 = data_dir / "listed_ip_90_ipv46_all.zip"
            mm_asn = data_dir / "GeoLite2-ASN.mmdb"

            sfs_toxic.write_text("192.0.2.0/24\n", encoding="utf-8")
            sfs_90.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
            mm_asn.write_bytes(b"mmdb-stub")

            fresh_ts = now_dt.timestamp() - 3600
            stale_ts = now_dt.timestamp() - (10 * 86400)
            os.utime(sfs_toxic, (fresh_ts, fresh_ts))
            os.utime(sfs_90, (stale_ts, stale_ts))
            os.utime(mm_asn, (fresh_ts, fresh_ts))

            with override_settings(
                TOOL_DATA_DIR=tmp_dir,
                OFFLINE_DB_SFS_90_STALE_SECONDS=86400,
            ):
                entries = offline_dbs.collect_offline_databases_status(now_dt=now_dt)

        by_key = {entry["key"]: entry for entry in entries}
        self.assertEqual(by_key["stopforumspam_toxic_cidr"]["status"], "healthy")
        self.assertEqual(by_key["stopforumspam_toxic_cidr"]["ageSeconds"], 3600)
        self.assertTrue(by_key["stopforumspam_toxic_cidr"]["lastModifiedIso"].startswith("2026-11-16T11:00:00"))
        self.assertEqual(by_key["stopforumspam_listed_90"]["status"], "stale")
        self.assertEqual(by_key["maxmind_asn"]["status"], "healthy")
        self.assertEqual(by_key["maxmind_city"]["status"], "missing")
        self.assertFalse(by_key["maxmind_city"]["exists"])
        self.assertEqual(by_key["cloud_cidrs"]["statusLabel"], "Built-in (Optional)")
        self.assertEqual(by_key["hosting_asn_rules"]["statusLabel"], "Built-in (Optional)")

    def test_system_status_endpoint_requires_admin_session_and_detect_omits_inventory(self):
        unauth_resp = self.client.get("/api/v1/status")
        self.assertEqual(unauth_resp.status_code, 401)

        _login_authorised(self)
        with (
            override_settings(ALLOWED_WIKI_USERS="AllowlistedAdmin"),
            patch.dict(os.environ, {"ALLOWED_WIKI_USERS": "AllowlistedAdmin"}),
        ):
            non_admin_resp = self.client.get("/api/v1/status")
            self.assertEqual(non_admin_resp.status_code, 403)

            gadget_token = views.issue_gadget_token("AllowlistedAdmin")
            gadget_resp = self.client.get("/api/v1/status", HTTP_AUTHORIZATION=f"Bearer {gadget_token}")
            self.assertEqual(gadget_resp.status_code, 403)

        admin_session = self.client.session
        admin_session["wikimedia_user"] = {
            "isLoggedIn": True,
            "username": "AllowlistedAdmin",
            "role": "Allowlisted Wikimedia User",
            "hasAccess": True,
            "localGroups": [],
            "globalGroups": [],
        }
        admin_session.save()
        with (
            override_settings(ALLOWED_WIKI_USERS="AllowlistedAdmin"),
            patch.dict(os.environ, {"ALLOWED_WIKI_USERS": "AllowlistedAdmin"}),
        ):
            ok_resp = self.client.get("/api/v1/status")
            self.assertEqual(ok_resp.status_code, 200)
            self.assertEqual(ok_resp["Cache-Control"], "no-store")
            payload = ok_resp.json()
            self.assertIn("generatedAt", payload)
            self.assertIsInstance(payload.get("offlineDatabases"), list)
            keys = {item["key"] for item in payload["offlineDatabases"]}
            self.assertIn("maxmind_city", keys)
            self.assertIn("stopforumspam_listed_90", keys)

            post_resp = self.client.post("/api/v1/status")
            self.assertEqual(post_resp.status_code, 405)

            detect_resp = asyncio.run(
                detection_service._execute_detection_with_cache(
                    "8.8.8.8",
                    initial_cache=(
                        {
                            provider_key: ({"provider": name, "status": "200 OK", "statusCode": 200}, None)
                            for provider_key, name, _, _, _ in providers._PROVIDER_SPECS
                        },
                        ("dns.google", None),
                    ),
                )
            )
            self.assertNotIn("offlineDatabases", detect_resp)
