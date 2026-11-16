"""Tests for detection endpoints, OAuth login and callback, RBAC, and SPA routing."""

import asyncio
import json
import os
import sys
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

from detector import views
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
    def test_detect_ip_unauthenticated_returns_401(self):
        response = self.client.get("/api/v1/detect?ip=8.8.8.8")
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertIn("error", data)

    def test_detect_ip_unauthorised_role_returns_403(self):
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

        response = self.client.get("/api/v1/detect?ip=8.8.8.8")
        self.assertEqual(response.status_code, 403)
        data = response.json()
        self.assertIn("error", data)

    @patch("detector.views.redis_client", None)
    @patch("detector.views.query_dshield", new_callable=AsyncMock)
    @patch("detector.views.query_stopforumspam", new_callable=AsyncMock)
    @patch("detector.views.query_tor_onionoo", new_callable=AsyncMock)
    @patch("detector.views.query_maxmind", new_callable=AsyncMock)
    @patch("detector.views.query_iphunter", new_callable=AsyncMock)
    @patch("detector.views.query_iphub", new_callable=AsyncMock)
    @patch("detector.views.query_proxycheck", new_callable=AsyncMock)
    @patch("detector.views.query_getipintel", new_callable=AsyncMock)
    @patch("detector.views.query_ip2location", new_callable=AsyncMock)
    @patch("detector.views.query_ipregistry", new_callable=AsyncMock)
    @patch("detector.views.query_ipdata", new_callable=AsyncMock)
    @patch("detector.views.query_abuseipdb", new_callable=AsyncMock)
    @patch("detector.views.query_cloudflare_radar", new_callable=AsyncMock)
    def test_detect_ip_authorised_user_returns_200(
        self,
        mock_cf,
        mock_abuse,
        mock_ipdata,
        mock_ipreg,
        mock_ip2loc,
        mock_gii,
        mock_pc,
        mock_iphub,
        mock_iphunter,
        mock_mm,
        mock_tor,
        mock_sfs,
        mock_dshield,
    ):
        def _stub_provider(name):
            return {
                "provider": name,
                "status": "No API Key",
                "statusCode": None,
                "asn": "-",
                "isp": "-",
                "organisation": "-",
                "location": "-",
                "usageType": "-",
                "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
                "rawJson": {"status": "error", "message": "API key not configured"},
            }

        mock_cf.return_value = _stub_provider("Cloudflare Radar")
        mock_abuse.return_value = _stub_provider("AbuseIPDB")
        mock_ipdata.return_value = _stub_provider("IPData")
        mock_ipreg.return_value = _stub_provider("IPRegistry")
        mock_ip2loc.return_value = _stub_provider("IP2Location")
        mock_gii.return_value = _stub_provider("GetIPIntel")
        mock_pc.return_value = _stub_provider("Proxycheck")
        mock_iphub.return_value = _stub_provider("IPHub")
        mock_iphunter.return_value = _stub_provider("IPHunter")
        mock_mm.return_value = _stub_provider("MaxMind")
        mock_tor.return_value = adapt_tor_onionoo({"relays": []}, 200, "8.8.8.8")
        mock_sfs.return_value = adapt_stopforumspam(
            {"success": 1, "ip": {"appears": 0, "frequency": 0, "confidence": 0.0}}, 200
        )
        mock_dshield.return_value = adapt_dshield({"ip": {"attacks": 0, "count": 0}}, 200)

        session = self.client.session
        session["wikimedia_user"] = {
            "isLoggedIn": True,
            "username": "SysopUser",
            "role": "Local Administrator (sysop)",
            "hasAccess": True,
            "localGroups": ["sysop"],
            "globalGroups": [],
        }
        session.save()

        response = self.client.get("/api/v1/detect?ip=8.8.8.8")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["ip"], "8.8.8.8")
        self.assertEqual(len(payload["results"]), 14)
        result_providers = {row["provider"] for row in payload["results"]}
        self.assertNotIn("Tor Onionoo", result_providers)
        self.assertIn("StopForumSpam", result_providers)
        self.assertIn("DShield", result_providers)

    # Verify switch_test_role dual guard behaviour

    @override_settings(DEBUG=False, ENABLE_TEST_AUTH=False)
    def test_switch_test_role_blocked_in_production(self):
        response = self.client.post(
            "/api/v1/auth/switch-role/",
            data=json.dumps({"role": "steward"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        self.assertIsNone(self.client.session.get("wikimedia_user"))

    @override_settings(DEBUG=True, ENABLE_TEST_AUTH=False)
    def test_switch_test_role_blocked_when_only_debug_true(self):
        response = self.client.post(
            "/api/v1/auth/switch-role/",
            data=json.dumps({"role": "steward"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        self.assertIsNone(self.client.session.get("wikimedia_user"))

    @override_settings(DEBUG=False, ENABLE_TEST_AUTH=True)
    def test_switch_test_role_blocked_when_only_enable_test_auth_true(self):
        response = self.client.post(
            "/api/v1/auth/switch-role/",
            data=json.dumps({"role": "steward"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        self.assertIsNone(self.client.session.get("wikimedia_user"))

    @override_settings(DEBUG=True, ENABLE_TEST_AUTH=True)
    def test_switch_test_role_succeeds_when_both_guards_enabled(self):
        response = self.client.post(
            "/api/v1/auth/switch-role/",
            data=json.dumps({"role": "steward"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["role"], "Steward")
        self.assertTrue(data["hasAccess"])
        self.assertEqual(self.client.session["wikimedia_user"]["role"], "Steward")

    # Verify oauth_login fallback behaviour and state generation

    @override_settings(
        DEBUG=False,
        ENABLE_TEST_AUTH=False,
        WIKIMEDIA_CLIENT_ID="",
        WIKIMEDIA_REDIRECT_URI="",
    )
    def test_oauth_login_fail_closed_in_production_without_credentials(self):
        response = self.client.get("/api/v1/auth/login/")
        self.assertEqual(response.status_code, 503)
        self.assertIsNone(self.client.session.get("wikimedia_user"))

    @override_settings(
        DEBUG=True,
        ENABLE_TEST_AUTH=False,
        WIKIMEDIA_CLIENT_ID="",
        WIKIMEDIA_REDIRECT_URI="",
    )
    def test_oauth_login_fail_closed_when_only_debug_true_without_credentials(self):
        response = self.client.get("/api/v1/auth/login/")
        self.assertEqual(response.status_code, 503)
        self.assertIsNone(self.client.session.get("wikimedia_user"))

    @override_settings(
        DEBUG=True,
        ENABLE_TEST_AUTH=True,
        WIKIMEDIA_CLIENT_ID="",
        WIKIMEDIA_REDIRECT_URI="",
    )
    def test_oauth_login_fallback_admin_when_dual_guards_enabled(self):
        response = self.client.get("/api/v1/auth/login/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")
        self.assertTrue(self.client.session["wikimedia_user"]["hasAccess"])

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/api/v1/auth/callback",
        WIKIMEDIA_OAUTH_URL="https://meta.wikimedia.org/w/rest.php/oauth2",
    )
    def test_oauth_login_generates_state_and_urlencodes_redirect(self):
        response = self.client.get("/api/v1/auth/login/")
        self.assertEqual(response.status_code, 302)
        parsed = urlparse(response["Location"])
        params = parse_qs(parsed.query)
        self.assertEqual(params["client_id"], ["test_client_id"])
        self.assertEqual(params["redirect_uri"], ["https://proxycheck.toolforge.org/api/v1/auth/callback"])
        self.assertIn("state", params)
        session_state = self.client.session.get("oauth_state")
        self.assertTrue(session_state)
        self.assertEqual(params["state"], [session_state])

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/api/v1/auth/callback",
        WIKIMEDIA_OAUTH_URL="https://meta.wikimedia.org/w/rest.php/oauth2",
    )
    def test_oauth_login_persists_canonical_ip_and_clears_stale_ip(self):
        response = self.client.get("/api/v1/auth/login/?ip=2001:0db8::01")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session.get("oauth_post_login_ip"), "2001:db8::1")

        # Starting a plain login clears any abandoned post-login IP from the session
        second_response = self.client.get("/api/v1/auth/login/")
        self.assertEqual(second_response.status_code, 302)
        self.assertIsNone(self.client.session.get("oauth_post_login_ip"))

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/api/v1/auth/callback",
        WIKIMEDIA_OAUTH_URL="https://meta.wikimedia.org/w/rest.php/oauth2",
    )
    def test_oauth_login_ignores_invalid_or_redirect_ip_parameter(self):
        response = self.client.get("/api/v1/auth/login/?ip=https://evil.example")
        self.assertEqual(response.status_code, 302)
        self.assertIsNone(self.client.session.get("oauth_post_login_ip"))

    @override_settings(
        DEBUG=True,
        ENABLE_TEST_AUTH=True,
        WIKIMEDIA_CLIENT_ID="",
        WIKIMEDIA_REDIRECT_URI="",
    )
    def test_oauth_login_fallback_admin_preserves_valid_ip_only(self):
        valid_resp = self.client.get("/api/v1/auth/login/?ip=2001:0db8::01")
        self.assertEqual(valid_resp.status_code, 302)
        self.assertEqual(valid_resp["Location"], "/?ip=2001%3Adb8%3A%3A1")
        self.assertIsNone(self.client.session.get("oauth_post_login_ip"))

        invalid_resp = self.client.get("/api/v1/auth/login/?ip=bad")
        self.assertEqual(invalid_resp.status_code, 302)
        self.assertEqual(invalid_resp["Location"], "/")
        self.assertIsNone(self.client.session.get("oauth_post_login_ip"))

    # Verify oauth_callback state validation and error handling

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="test_client_secret",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/api/v1/auth/callback",
    )
    @patch("detector.views.fetch_user_rights_from_meta", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
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
    @patch("detector.views.httpx.AsyncClient")
    def test_oauth_callback_mismatched_state_is_rejected_and_destroys_state(self, mock_async_client_cls):
        session = self.client.session
        session["oauth_state"] = "expected_state_abc"
        session.save()

        response = self.client.get("/api/v1/auth/callback/?code=auth_code_1&state=wrong_state_xyz")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")
        self.assertIsNone(self.client.session.get("oauth_state"))
        self.assertIsNone(self.client.session.get("wikimedia_user"))
        mock_async_client_cls.assert_not_called()

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="test_client_secret",
    )
    @patch("detector.views.httpx.AsyncClient")
    def test_oauth_callback_non_ascii_state_does_not_crash(self, mock_async_client_cls):
        session = self.client.session
        session["oauth_state"] = "expected_ascii_state"
        session.save()

        response = self.client.get("/api/v1/auth/callback/?code=auth_code_1&state=test")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")
        self.assertIsNone(self.client.session.get("oauth_state"))
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
    @patch("detector.views.fetch_user_rights_from_meta", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
    def test_oauth_callback_redirects_to_preserved_ip_and_pops_session_key(
        self, mock_async_client_cls, mock_fetch_meta
    ):
        self._configure_oauth_callback_mocks(mock_async_client_cls, mock_fetch_meta)

        session = self.client.session
        session["oauth_state"] = "state_preserve_ip"
        session["oauth_post_login_ip"] = "2001:db8::1"
        session.save()

        response = self.client.get("/api/v1/auth/callback/?code=auth_code_1&state=state_preserve_ip")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/?ip=2001%3Adb8%3A%3A1")
        self.assertIsNone(self.client.session.get("oauth_post_login_ip"))
        self.assertTrue(self.client.session["wikimedia_user"]["hasAccess"])

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="test_client_secret",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/api/v1/auth/callback",
    )
    @patch("detector.views.fetch_user_rights_from_meta", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
    def test_oauth_callback_without_access_ignores_and_pops_preserved_ip(self, mock_async_client_cls, mock_fetch_meta):
        self._configure_oauth_callback_mocks(
            mock_async_client_cls,
            mock_fetch_meta,
            username="RegularUser",
            groups=["autoconfirmed"],
            global_rights=[],
        )

        session = self.client.session
        session["oauth_state"] = "state_unauthorised"
        session["oauth_post_login_ip"] = "8.8.8.8"
        session.save()

        response = self.client.get("/api/v1/auth/callback/?code=auth_code_1&state=state_unauthorised")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")
        self.assertIsNone(self.client.session.get("oauth_post_login_ip"))
        self.assertFalse(self.client.session["wikimedia_user"]["hasAccess"])

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="test_client_secret",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/api/v1/auth/callback",
    )
    @patch("detector.views.fetch_user_rights_from_meta", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
    def test_oauth_callback_ignores_invalid_session_ip_value(self, mock_async_client_cls, mock_fetch_meta):
        self._configure_oauth_callback_mocks(mock_async_client_cls, mock_fetch_meta)

        session = self.client.session
        session["oauth_state"] = "state_bad_session_ip"
        session["oauth_post_login_ip"] = "https://evil.example"
        session.save()

        response = self.client.get("/api/v1/auth/callback/?code=auth_code_1&state=state_bad_session_ip")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")
        self.assertIsNone(self.client.session.get("oauth_post_login_ip"))

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="test_client_secret",
    )
    @patch("detector.views.httpx.AsyncClient")
    def test_oauth_callback_mismatched_state_clears_preserved_ip(self, mock_async_client_cls):
        session = self.client.session
        session["oauth_state"] = "expected_state"
        session["oauth_post_login_ip"] = "8.8.8.8"
        session.save()

        response = self.client.get("/api/v1/auth/callback/?code=auth_code_1&state=wrong_state")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")
        self.assertIsNone(self.client.session.get("oauth_state"))
        self.assertIsNone(self.client.session.get("oauth_post_login_ip"))
        mock_async_client_cls.assert_not_called()

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="test_client_secret",
    )
    @patch("detector.views.httpx.AsyncClient")
    def test_oauth_callback_error_parameter_cleans_state_and_redirects(self, mock_async_client_cls):
        session = self.client.session
        session["oauth_state"] = "state_to_be_cleaned"
        session.save()

        with self.assertLogs("detector.views", level="WARNING") as captured:
            response = self.client.get("/api/v1/auth/callback/?error=access_denied&state=state_to_be_cleaned")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")
        self.assertIsNone(self.client.session.get("oauth_state"))
        self.assertIsNone(self.client.session.get("wikimedia_user"))
        mock_async_client_cls.assert_not_called()
        self.assertTrue(any("access_denied" in msg for msg in captured.output))

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="test_client_secret",
    )
    @patch("detector.views.httpx.AsyncClient")
    def test_oauth_callback_unrecognized_error_does_not_log_raw_query_value(self, mock_async_client_cls):
        session = self.client.session
        session["oauth_state"] = "state_to_be_cleaned"
        session.save()

        raw_secret_like_value = "leaked_client_secret_999\nforged_entry"
        with self.assertLogs("detector.views", level="WARNING") as captured:
            response = self.client.get(
                "/api/v1/auth/callback/",
                {"error": raw_secret_like_value, "state": "state_to_be_cleaned"},
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")
        self.assertIsNone(self.client.session.get("oauth_state"))
        mock_async_client_cls.assert_not_called()
        log_output = "\n".join(captured.output)
        self.assertIn("unrecognized error code", log_output)
        self.assertNotIn("leaked_client_secret_999", log_output)
        self.assertNotIn("forged_entry", log_output)

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
    @patch("detector.views.fetch_user_rights_from_meta", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
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

    @patch("detector.views.query_dshield", new_callable=AsyncMock)
    @patch("detector.views.query_stopforumspam", new_callable=AsyncMock)
    @patch("detector.views.query_tor_onionoo", new_callable=AsyncMock)
    @patch("detector.views.query_maxmind", new_callable=AsyncMock)
    @patch("detector.views.query_iphunter", new_callable=AsyncMock)
    @patch("detector.views.query_iphub", new_callable=AsyncMock)
    @patch("detector.views.query_proxycheck", new_callable=AsyncMock)
    @patch("detector.views.query_getipintel", new_callable=AsyncMock)
    @patch("detector.views.query_ip2location", new_callable=AsyncMock)
    @patch("detector.views.query_ipregistry", new_callable=AsyncMock)
    @patch("detector.views.query_ipdata", new_callable=AsyncMock)
    @patch("detector.views.query_abuseipdb", new_callable=AsyncMock)
    @patch("detector.views.query_cloudflare_radar", new_callable=AsyncMock)
    def test_detect_ip_variants_hit_identical_canonical_cache_key(
        self,
        mock_cf,
        mock_abuse,
        mock_ipdata,
        mock_ipreg,
        mock_ip2loc,
        mock_gii,
        mock_pc,
        mock_iphub,
        mock_iphunter,
        mock_mm,
        mock_tor,
        mock_sfs,
        mock_dshield,
    ):
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

        for m, name in (
            (mock_cf, "Cloudflare Radar"),
            (mock_abuse, "AbuseIPDB"),
            (mock_ipdata, "IPData"),
            (mock_ipreg, "IPRegistry"),
            (mock_ip2loc, "IP2Location"),
            (mock_gii, "GetIPIntel"),
            (mock_pc, "Proxycheck"),
            (mock_iphub, "IPHub"),
            (mock_iphunter, "IPHunter"),
            (mock_tor, "Tor Onionoo"),
            (mock_sfs, "StopForumSpam"),
            (mock_dshield, "DShield"),
        ):
            m.return_value = _ok_provider(name)
        mock_mm.return_value = dict(MAXMIND_STUB)

        cache_store = {}

        async def _fake_get(key):
            return cache_store.get(key)

        async def _fake_set(key, val, ex=None):
            cache_store[key] = val

        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(side_effect=_fake_get)
        mock_redis.set = AsyncMock(side_effect=_fake_set)

        with patch("detector.views.redis_client", mock_redis):
            first_resp = self.client.get("/api/v1/detect?ip=2001:0486:4860:0:0::8888")
            second_resp = self.client.get("/api/v1/detect?ip=2001:0486:4860:0000:0000:0000:0000:8888")
            third_resp = self.client.get("/api/v1/detect?ip=2001:486:4860::8888")

        self.assertEqual(first_resp.status_code, 200)
        self.assertEqual(second_resp.status_code, 200)
        self.assertEqual(third_resp.status_code, 200)

        first_payload = first_resp.json()
        second_payload = second_resp.json()
        third_payload = third_resp.json()

        self.assertEqual(first_payload["ip"], "2001:486:4860::8888")
        self.assertFalse(first_payload["isCached"])
        self.assertEqual(second_payload["ip"], "2001:486:4860::8888")
        self.assertTrue(second_payload["isCached"])
        self.assertEqual(second_payload["cacheMeta"]["status"], "hit")
        self.assertEqual(third_payload["ip"], "2001:486:4860::8888")
        self.assertTrue(third_payload["isCached"])
        self.assertEqual(mock_redis.set.call_count, 13)
        self.assertIn("proxycheck:v1:prov:proxycheck:2001:486:4860::8888", cache_store)
        self.assertIn("proxycheck:v1:prov:tor_onionoo:2001:486:4860::8888", cache_store)
        self.assertIn("proxycheck:v1:prov:stopforumspam:2001:486:4860::8888", cache_store)
        self.assertIn("proxycheck:v1:prov:dshield:2001:486:4860::8888", cache_store)
        self.assertIn("proxycheck:v1:prov:ptr:2001:486:4860::8888", cache_store)

    def test_session_and_security_baseline_settings(self):
        from django.conf import settings as django_settings

        self.assertFalse(django_settings.SESSION_SAVE_EVERY_REQUEST)
        self.assertTrue(django_settings.SESSION_COOKIE_HTTPONLY)
        self.assertEqual(django_settings.SESSION_COOKIE_SAMESITE, "Lax")

        logout_resp = self.client.get("/api/v1/auth/logout/")
        self.assertEqual(logout_resp.status_code, 200)
        user_resp = self.client.get("/api/v1/auth/user/")
        self.assertFalse(user_resp.json()["isLoggedIn"])

class DetectEndpointRoutingAndValidationTests(TestCase):
    """Tests for URL routing normalisation and IP parameter validation on the detect endpoint."""

    def setUp(self):
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)
        _login_authorised(self)

    @patch("detector.views.redis_client", None)
    @patch("detector.views.query_dshield", new_callable=AsyncMock)
    @patch("detector.views.query_stopforumspam", new_callable=AsyncMock)
    @patch("detector.views.query_tor_onionoo", new_callable=AsyncMock)
    @patch("detector.views.query_maxmind", new_callable=AsyncMock)
    @patch("detector.views.query_iphunter", new_callable=AsyncMock)
    @patch("detector.views.query_iphub", new_callable=AsyncMock)
    @patch("detector.views.query_proxycheck", new_callable=AsyncMock)
    @patch("detector.views.query_getipintel", new_callable=AsyncMock)
    @patch("detector.views.query_ip2location", new_callable=AsyncMock)
    @patch("detector.views.query_ipregistry", new_callable=AsyncMock)
    @patch("detector.views.query_ipdata", new_callable=AsyncMock)
    @patch("detector.views.query_abuseipdb", new_callable=AsyncMock)
    @patch("detector.views.query_cloudflare_radar", new_callable=AsyncMock)
    def test_trailing_and_non_trailing_slash_return_identical_results(
        self,
        mock_cf,
        mock_abuse,
        mock_ipdata,
        mock_ipreg,
        mock_ip2loc,
        mock_gii,
        mock_pc,
        mock_iphub,
        mock_iphunter,
        mock_mm,
        mock_tor,
        mock_sfs,
        mock_dshield,
    ):
        def _stub_provider(name):
            return {
                "provider": name,
                "status": "No API Key",
                "statusCode": None,
                "asn": "-",
                "isp": "-",
                "organisation": "-",
                "location": "-",
                "usageType": "-",
                "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
                "rawJson": {"status": "error", "message": "API key not configured"},
            }

        for m, name in (
            (mock_cf, "Cloudflare Radar"),
            (mock_abuse, "AbuseIPDB"),
            (mock_ipdata, "IPData"),
            (mock_ipreg, "IPRegistry"),
            (mock_ip2loc, "IP2Location"),
            (mock_gii, "GetIPIntel"),
            (mock_pc, "Proxycheck"),
            (mock_iphub, "IPHub"),
            (mock_iphunter, "IPHunter"),
            (mock_tor, "Tor Onionoo"),
            (mock_sfs, "StopForumSpam"),
            (mock_dshield, "DShield"),
        ):
            m.return_value = _stub_provider(name)
        mock_mm.return_value = dict(MAXMIND_STUB)

        response_canonical = self.client.get("/api/v1/detect?ip=8.8.8.8")
        response_legacy = self.client.get("/api/v1/detect/?ip=8.8.8.8")

        self.assertEqual(response_canonical.status_code, 200)
        self.assertEqual(response_legacy.status_code, 200)

        data_canonical = response_canonical.json()
        data_legacy = response_legacy.json()

        self.assertEqual(data_canonical["ip"], data_legacy["ip"])
        self.assertEqual(data_canonical["arbitrationVerdict"], data_legacy["arbitrationVerdict"])
        self.assertEqual(data_canonical["recommendedCidr"], data_legacy["recommendedCidr"])
        self.assertEqual(len(data_canonical["results"]), len(data_legacy["results"]))

    @patch("detector.views.redis_client", None)
    @patch("detector.views.query_dshield", new_callable=AsyncMock)
    @patch("detector.views.query_stopforumspam", new_callable=AsyncMock)
    @patch("detector.views.query_tor_onionoo", new_callable=AsyncMock)
    @patch("detector.views.query_maxmind", new_callable=AsyncMock)
    @patch("detector.views.query_iphunter", new_callable=AsyncMock)
    @patch("detector.views.query_iphub", new_callable=AsyncMock)
    @patch("detector.views.query_proxycheck", new_callable=AsyncMock)
    @patch("detector.views.query_getipintel", new_callable=AsyncMock)
    @patch("detector.views.query_ip2location", new_callable=AsyncMock)
    @patch("detector.views.query_ipregistry", new_callable=AsyncMock)
    @patch("detector.views.query_ipdata", new_callable=AsyncMock)
    @patch("detector.views.query_abuseipdb", new_callable=AsyncMock)
    @patch("detector.views.query_cloudflare_radar", new_callable=AsyncMock)
    def test_valid_ipv4_and_ipv6_normalization(
        self,
        mock_cf,
        mock_abuse,
        mock_ipdata,
        mock_ipreg,
        mock_ip2loc,
        mock_gii,
        mock_pc,
        mock_iphub,
        mock_iphunter,
        mock_mm,
        mock_tor,
        mock_sfs,
        mock_dshield,
    ):
        def _stub_provider(name):
            return {
                "provider": name,
                "status": "No API Key",
                "statusCode": None,
                "asn": "-",
                "isp": "-",
                "organisation": "-",
                "location": "-",
                "usageType": "-",
                "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
                "rawJson": {"status": "error", "message": "API key not configured"},
            }

        for m, name in (
            (mock_cf, "Cloudflare Radar"),
            (mock_abuse, "AbuseIPDB"),
            (mock_ipdata, "IPData"),
            (mock_ipreg, "IPRegistry"),
            (mock_ip2loc, "IP2Location"),
            (mock_gii, "GetIPIntel"),
            (mock_pc, "Proxycheck"),
            (mock_iphub, "IPHub"),
            (mock_iphunter, "IPHunter"),
            (mock_tor, "Tor Onionoo"),
            (mock_sfs, "StopForumSpam"),
            (mock_dshield, "DShield"),
        ):
            m.return_value = _stub_provider(name)
        mock_mm.return_value = dict(MAXMIND_STUB)

        response_ipv4 = self.client.get("/api/v1/detect?ip=  1.1.1.1  ")
        self.assertEqual(response_ipv4.status_code, 200)
        self.assertEqual(response_ipv4.json()["ip"], "1.1.1.1")
        self.assertEqual(response_ipv4.json()["recommendedCidr"], "1.1.1.0/24")

        response_ipv6 = self.client.get("/api/v1/detect?ip=  2001:0486:4860:0000:0000:0000:0000:8888  ")
        self.assertEqual(response_ipv6.status_code, 200)
        self.assertEqual(response_ipv6.json()["ip"], "2001:486:4860::8888")
        self.assertEqual(response_ipv6.json()["recommendedCidr"], "2001:486:4860::/64")

    def test_missing_ip_parameter_returns_400(self):
        cases = (
            "/api/v1/detect",
            "/api/v1/detect?ip=",
            "/api/v1/detect?ip=   ",
            "/api/v1/detect/?ip=",
        )
        for url in cases:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 400)
                payload = response.json()
                self.assertEqual(payload["error"], "invalid_ip")
                self.assertIn("Missing required ip query parameter", payload["message"])

    def test_invalid_ip_format_returns_400(self):
        invalid_ips = (
            "not-an-ip",
            "999.999.999.999",
            "1.2.3",
            "2001:xyz::1",
            "1.1.1.1/24",
            "localhost",
        )
        for raw_val in invalid_ips:
            with self.subTest(ip=raw_val):
                response = self.client.get(f"/api/v1/detect?ip={raw_val}")
                self.assertEqual(response.status_code, 400)
                payload = response.json()
                self.assertEqual(payload["error"], "invalid_ip")
                self.assertIn("Invalid IP address format", payload["message"])

    def test_toolforge_favicon_endpoints_return_200(self):
        for path in ("/Proxycheck.svg", "/favicon.svg", "/favicon.ico"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn("image/svg+xml", response.headers.get("Content-Type", ""))

class SettingsAndHardeningTests(TestCase):
    """Tests for production settings baselines, Redis key prefixes, and graceful memory diagnostics."""

    def test_production_secret_key_absence_raises_improperly_configured(self):
        from django.core.exceptions import ImproperlyConfigured

        with (
            patch.dict(os.environ, {"DJANGO_SECRET_KEY": "", "DJANGO_DEBUG": "False"}),
            patch.object(sys, "argv", ["gunicorn"]),
            self.assertRaises(ImproperlyConfigured),
        ):
            secret = os.environ.get("DJANGO_SECRET_KEY")
            debug = os.environ.get("DJANGO_DEBUG", "False").lower() in ("true", "1", "yes")
            if not secret and not debug and "test" not in sys.argv:
                raise ImproperlyConfigured("DJANGO_SECRET_KEY environment variable is required in production.")

    def test_allowed_hosts_fallback_to_local_defaults(self):
        with patch.dict(os.environ, {"DJANGO_ALLOWED_HOSTS": ""}):
            raw = os.environ.get("DJANGO_ALLOWED_HOSTS", "").strip()
            hosts = [h.strip() for h in raw.split(",") if h.strip()] if raw else ["127.0.0.1", "localhost"]
            self.assertEqual(hosts, ["127.0.0.1", "localhost"])

    def test_allowed_hosts_parser_normalizes_wildcard_prefixes(self):
        from proxycheck.settings import _parse_allowed_hosts

        parsed = _parse_allowed_hosts("localhost, 127.0.0.1, *.toolforge.org, .wmcloud.org")
        self.assertEqual(parsed, ["localhost", "127.0.0.1", ".toolforge.org", ".wmcloud.org"])
        self.assertEqual(_parse_allowed_hosts("  , "), ["127.0.0.1", "localhost"])

    def test_redis_cache_key_prefix_configured_from_env(self):
        from django.conf import settings

        self.assertIn("KEY_PREFIX", settings.CACHES["default"])
        prefix = settings.CACHES["default"]["KEY_PREFIX"]
        self.assertTrue(prefix.startswith("proxycheck_") or prefix.startswith("proxy_detector"))

    def test_process_memory_mb_degrades_to_none_on_error(self):
        with (
            patch.object(views, "_read_proc_rss_mb", return_value=None),
            patch.dict(sys.modules, {"resource": None}),
        ):
            mem = views.get_process_memory_mb()
            self.assertIsNone(mem)

    def test_auth_user_and_logout_include_request_diagnostics(self):
        with patch("detector.views.get_process_memory_mb", return_value=71.4):
            unauth_resp = self.client.get("/api/v1/auth/user/")
            self.assertEqual(unauth_resp.status_code, 200)
            unauth_payload = unauth_resp.json()
            self.assertFalse(unauth_payload["isLoggedIn"])
            self.assertIsInstance(unauth_payload["durationSeconds"], (int, float))
            self.assertGreaterEqual(unauth_payload["durationSeconds"], 0)
            self.assertEqual(unauth_payload["memoryMb"], 71.4)

            session = self.client.session
            session["wikimedia_user"] = {
                "isLoggedIn": True,
                "username": "SysopTester",
                "role": "Local Administrator (sysop)",
                "hasAccess": True,
                "localGroups": ["sysop"],
                "globalGroups": [],
            }
            session.save()

            auth_resp = self.client.get("/api/v1/auth/user/")
            self.assertEqual(auth_resp.status_code, 200)
            auth_payload = auth_resp.json()
            self.assertTrue(auth_payload["isLoggedIn"])
            self.assertEqual(auth_payload["username"], "SysopTester")
            self.assertIsInstance(auth_payload["durationSeconds"], (int, float))
            self.assertGreaterEqual(auth_payload["durationSeconds"], 0)
            self.assertEqual(auth_payload["memoryMb"], 71.4)

            stored_user = self.client.session.get("wikimedia_user", {})
            self.assertNotIn("durationSeconds", stored_user)
            self.assertNotIn("memoryMb", stored_user)

        with patch("detector.views.get_process_memory_mb", return_value=None):
            logout_resp = self.client.get("/api/v1/auth/logout/")
            self.assertEqual(logout_resp.status_code, 200)
            logout_payload = logout_resp.json()
            self.assertEqual(logout_payload["status"], "logged_out")
            self.assertIsInstance(logout_payload["durationSeconds"], (int, float))
            self.assertGreaterEqual(logout_payload["durationSeconds"], 0)
            self.assertIsNone(logout_payload["memoryMb"])

class SpaRoutingTests(SimpleTestCase):
    """Tests for SPA entrypoint serving, fallback HTML, and API or asset exclusions."""

    def test_spa_index_serves_compiled_dist_html_for_client_routes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir)
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

    def test_spa_index_returns_fallback_html_when_dist_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with override_settings(BASE_DIR=Path(tmpdir)):
                resp = self.client.get("/")

            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp["Content-Type"], "text/html; charset=utf-8")
            self.assertIn('<div id="app">Loading Proxy Detector...</div>', resp.content.decode("utf-8"))

    def test_spa_catch_all_excludes_api_oauth_assets_and_favicon_routes(self):
        api_miss = self.client.get("/api/nonexistent/")
        oauth_miss = self.client.get("/oauth/unknown-step/")
        asset_miss = self.client.get("/assets/missing-bundle.js")
        auth_user = self.client.get("/api/v1/auth/user/")
        toolforge_svg = self.client.get("/Proxycheck.svg")
        favicon_svg = self.client.get("/favicon.svg")

        self.assertEqual(api_miss.status_code, 404)
        self.assertEqual(oauth_miss.status_code, 404)
        self.assertEqual(asset_miss.status_code, 404)
        self.assertEqual(auth_user.status_code, 200)
        self.assertEqual(auth_user["Content-Type"], "application/json")
        self.assertEqual(toolforge_svg.status_code, 200)
        self.assertIn("image/svg+xml", toolforge_svg["Content-Type"])
        self.assertEqual(favicon_svg.status_code, 200)
        self.assertIn("image/svg+xml", favicon_svg["Content-Type"])

class OfflineDatabaseStatusEndpointTests(TestCase):
    """Tests inventory reporting, stale detection, and /api/v1/status endpoint exposure."""

    def test_collect_offline_databases_status_reports_healthy_stale_and_missing(self):
        from datetime import datetime, timezone

        from detector import offline_dbs

        now_dt = datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sfs_toxic = root / "toxic_ip_cidr.txt"
            sfs_90 = root / "listed_ip_90_ipv46_all.zip"
            mm_asn = root / "GeoLite2-ASN.mmdb"

            sfs_toxic.write_text("192.0.2.0/24\n", encoding="utf-8")
            sfs_90.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
            mm_asn.write_bytes(b"mmdb-stub")

            fresh_ts = now_dt.timestamp() - 3600
            stale_ts = now_dt.timestamp() - (10 * 86400)
            os.utime(sfs_toxic, (fresh_ts, fresh_ts))
            os.utime(sfs_90, (stale_ts, stale_ts))
            os.utime(mm_asn, (fresh_ts, fresh_ts))

            with override_settings(
                STOPFORUMSPAM_DB_DIR=tmp_dir,
                MAXMIND_DB_DIR=tmp_dir,
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
                views._execute_detection_with_cache(
                    "8.8.8.8",
                    initial_cache=(
                        {
                            provider_key: ({"provider": name, "status": "200 OK", "statusCode": 200}, None)
                            for provider_key, name, _, _, _ in views._PROVIDER_SPECS
                        },
                        ("dns.google", None),
                    ),
                )
            )
            self.assertNotIn("offlineDatabases", detect_resp)
