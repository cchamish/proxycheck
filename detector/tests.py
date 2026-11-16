"""
Tests for detector authentication, role guards, OAuth state handling, credential redaction
and upstream payload validation.
"""

import asyncio
import contextlib
import copy
import json
import os
import socket
import sys
import tempfile
import threading
import time
import warnings
from pathlib import Path
from types import SimpleNamespace
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import dns.exception
import dns.name
import dns.resolver
import dns.reversename
import httpx
import redis.exceptions
import uvicorn
from asgiref.sync import SyncToAsync, iscoroutinefunction
from django.contrib.sessions.backends.base import UpdateError
from django.contrib.sessions.middleware import SessionInterrupted
from django.core import signing
from django.core.asgi import get_asgi_application
from django.http import HttpResponse
from django.test import AsyncRequestFactory, RequestFactory, SimpleTestCase, TestCase, override_settings

from detector import views
from detector.adapters import (
    _safe_int,
    adapt_abuseipdb,
    adapt_cloudflare_radar,
    adapt_dshield,
    adapt_getipintel,
    adapt_ip2location,
    adapt_ipdata,
    adapt_iphub,
    adapt_iphunter,
    adapt_ipregistry,
    adapt_maxmind,
    adapt_proxycheck,
    adapt_stopforumspam,
    adapt_tor_onionoo,
    classify_rdns_hostname,
    clear_offline_intelligence_caches,
    compute_cidr_attribution,
    match_cloud_cidr,
    match_hosting_asn_or_org,
)
from detector.middleware import AsyncWhiteNoiseMiddleware, ResilientSessionMiddleware
from detector.oauth import (
    CentralAuthVerificationError,
    InvalidCentralAuthTokenError,
    MetaWikiRightsFetchError,
    _clear_client_cookies,
    evaluate_wikimedia_rights,
    extract_wikimedia_domain_from_project,
    fetch_project_user_rights,
    fetch_user_rights_from_meta,
    is_session_rights_expired,
    normalize_and_validate_wikimedia_domain,
    verify_centralauth_userinfo,
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

    # Verify switch_test_role dual guard behavior

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

    # Verify oauth_login fallback behavior and state generation

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


TEST_UPSTREAM_SECRETS = {
    "CLOUDFLARE_RADAR_TOKEN": "cf-radar-token-7a1c",
    "ABUSEIPDB_API_KEY": "abuseipdb-key-55d2",
    "IPDATA_API_KEY": "ipdata-key-90bb",
    "IPREGISTRY_API_KEY": "ipregistry-key-3f4e",
    "IP2LOCATION_API_KEY": "ip2location-key-c0de",
    "GETIPINTEL_CONTACT_EMAIL": "ops-contact@example.org",
    "PROXYCHECK_API_KEY": "secret123",
    "IPHUB_API_KEY": "iphub-key-81fa",
    "IPHUNTER_API_KEY": "iphunter-key-6e09",
}

EMPTY_UPSTREAM_SECRETS = {name: "" for name in TEST_UPSTREAM_SECRETS}

MAXMIND_STUB = {
    "provider": "MaxMind",
    "status": "Database Missing",
    "statusCode": None,
    "asn": "-",
    "isp": "-",
    "organisation": "-",
    "location": "-",
    "usageType": "-",
    "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
    "rawJson": {"status": "error", "message": "Local MMDB files not found"},
}

ALL_ADAPTERS = (
    ("Cloudflare Radar", lambda raw, code: adapt_cloudflare_radar(raw, True, code)),
    ("AbuseIPDB", lambda raw, code: adapt_abuseipdb(raw, True, code)),
    ("IPData", lambda raw, code: adapt_ipdata(raw, True, code)),
    ("IPRegistry", lambda raw, code: adapt_ipregistry(raw, True, code)),
    ("IP2Location", lambda raw, code: adapt_ip2location(raw, True, code)),
    ("MaxMind", lambda raw, code: adapt_maxmind(raw, True, code)),
    ("GetIPIntel", lambda raw, code: adapt_getipintel(raw, True, code)),
    ("Proxycheck", lambda raw, code: adapt_proxycheck(raw, True, code, "8.8.8.8")),
    ("IPHub", lambda raw, code: adapt_iphub(raw, True, code)),
    ("IPHunter", lambda raw, code: adapt_iphunter(raw, True, code)),
    ("Tor Onionoo", lambda raw, code: adapt_tor_onionoo(raw, code, "8.8.8.8")),
    ("StopForumSpam", lambda raw, code: adapt_stopforumspam(raw, code)),
    ("DShield", lambda raw, code: adapt_dshield(raw, code)),
)


HTTP_PROVIDERS = tuple(name for name, _ in ALL_ADAPTERS if name not in ("MaxMind", "Tor Onionoo", "StopForumSpam"))


def _mock_ptr_answer(*hostnames):
    return [SimpleNamespace(target=dns.name.from_text(host)) for host in hostnames]


def _mock_a_answer(*ipv4_codes):
    return [SimpleNamespace(address=code) for code in ipv4_codes]


def _ptr_or_clean_dns_side_effect(ptr_hostname=None, ptr_timeout=False):
    async def _impl(_self_or_qname, rdtype="A", *_args, **_kwargs):
        if str(rdtype).upper() == "PTR":
            if ptr_timeout:
                raise dns.exception.Timeout("DNS timed out")
            if ptr_hostname:
                return _mock_ptr_answer(ptr_hostname)
        raise dns.resolver.NXDOMAIN()

    return _impl


def _mock_response(status_code=200, json_value=None, json_error=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if json_error is not None:
        resp.json.side_effect = json_error
    else:
        resp.json.return_value = json_value
    return resp


def _login_authorised(test_case):
    session = test_case.client.session
    session["wikimedia_user"] = {
        "isLoggedIn": True,
        "username": "SysopUser",
        "role": "Local Administrator (sysop)",
        "hasAccess": True,
        "localGroups": ["sysop"],
        "globalGroups": [],
    }
    session.save()


def _patch_async_client(mock_async_client_cls, get_side_effect):
    views._http_client_instance = None
    mock_client = AsyncMock()
    mock_client.get.side_effect = get_side_effect
    mock_client.__aenter__.return_value = mock_client
    mock_async_client_cls.return_value = mock_client
    return mock_client


class CredentialRedactionTests(TestCase):
    """Tests that upstream credentials never reach logs, API responses or the Redis cache."""

    def setUp(self):
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)

    @override_settings(**EMPTY_UPSTREAM_SECRETS)
    def test_sanitize_redacts_sensitive_query_parameters(self):
        with patch.dict(os.environ, EMPTY_UPSTREAM_SECRETS):
            message = (
                "ReadTimeout for https://proxycheck.io/v3/1.1.1.1?key=secret123&ip=1.1.1.1 "
                "and https://api.ipdata.co/1.1.1.1?api-key=abc999 "
                "and https://check.getipintel.net/check.php?ip=1.1.1.1&contact=me@example.org&format=json "
                "and token=tok-777 secret=s3cr3t password=hunter2 access_token='bearer-xyz'"
            )
            cleaned = views._sanitize_error_message(message)

        for leaked in ("secret123", "abc999", "me@example.org", "tok-777", "s3cr3t", "hunter2", "bearer-xyz"):
            self.assertNotIn(leaked, cleaned)
        self.assertIn("key=***REDACTED***&ip=1.1.1.1", cleaned)
        self.assertIn("api-key=***REDACTED***", cleaned)
        self.assertIn("contact=***REDACTED***&format=json", cleaned)
        self.assertIn("ip=1.1.1.1", cleaned)

    def test_sanitize_redacts_configured_keys_outside_query_strings(self):
        with override_settings(**TEST_UPSTREAM_SECRETS), patch.dict(os.environ, TEST_UPSTREAM_SECRETS):
            cleaned = views._sanitize_error_message(
                "Header X-Key iphub-key-81fa rejected, contact ops-contact%40example.org"
            )
        self.assertNotIn("iphub-key-81fa", cleaned)
        self.assertNotIn("ops-contact", cleaned)
        self.assertEqual(cleaned.count("***REDACTED***"), 2)

    @override_settings(**EMPTY_UPSTREAM_SECRETS)
    def test_sanitize_error_message_detects_dynamic_override_settings_key_changes(self):
        with patch.dict(os.environ, EMPTY_UPSTREAM_SECRETS):
            with override_settings(IPDATA_API_KEY="first-dynamic-key-1001"):
                first_cached = views._configured_secret_values()
                second_cached = views._configured_secret_values()
                self.assertIs(first_cached, second_cached)
                first_cleaned = views._sanitize_error_message(
                    "Upstream rejected key first-dynamic-key-1001 with Bearer tok-abc123"
                )
                self.assertNotIn("first-dynamic-key-1001", first_cleaned)
                self.assertNotIn("tok-abc123", first_cleaned)
                self.assertIn("Bearer ***REDACTED***", first_cleaned)

            with override_settings(IPDATA_API_KEY="rotated-dynamic-key-2002"):
                rotated_cached = views._configured_secret_values()
                self.assertIsNot(first_cached, rotated_cached)
                rotated_cleaned = views._sanitize_error_message("Upstream rejected key rotated-dynamic-key-2002")
                self.assertNotIn("rotated-dynamic-key-2002", rotated_cleaned)
                self.assertIn("***REDACTED***", rotated_cleaned)

    @override_settings(**EMPTY_UPSTREAM_SECRETS)
    def test_sanitize_ignores_empty_settings_and_handles_non_strings(self):
        with patch.dict(os.environ, EMPTY_UPSTREAM_SECRETS):
            self.assertEqual(views._sanitize_error_message("plain upstream failure"), "plain upstream failure")
            self.assertEqual(views._sanitize_error_message(""), "")
            self.assertEqual(views._sanitize_error_message(None), "")

    def test_getipintel_and_proxycheck_use_https(self):
        captured_urls = []

        async def _record(url, **kwargs):
            captured_urls.append(url)
            return _mock_response(json_value={"status": "ok"})

        client = AsyncMock()
        client.get.side_effect = _record
        with override_settings(**TEST_UPSTREAM_SECRETS), patch.dict(os.environ, TEST_UPSTREAM_SECRETS):
            asyncio.run(views.query_getipintel(client, "8.8.8.8"))
            asyncio.run(views.query_proxycheck(client, "8.8.8.8"))

        self.assertEqual(len(captured_urls), 2)
        for url in captured_urls:
            self.assertTrue(url.startswith("https://"), url)

    @patch("detector.views.query_maxmind", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
    def test_upstream_timeouts_are_redacted_in_response_logs_and_cache(self, mock_async_client_cls, mock_mm):
        mock_mm.return_value = dict(MAXMIND_STUB)

        async def _timeout(url, **kwargs):
            # Header based keys are echoed too, so only the configured-key pass can catch them
            raise httpx.ConnectTimeout(f"timed out fetching {url} with headers {kwargs.get('headers')}")

        _patch_async_client(mock_async_client_cls, _timeout)
        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.set = AsyncMock()
        _login_authorised(self)

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.views.redis_client", mock_redis),
            self.assertLogs("detector.views", level="ERROR") as captured_logs,
        ):
            response = self.client.get("/api/v1/detect?ip=8.8.8.8")

        self.assertEqual(response.status_code, 200)
        body = response.content.decode("utf-8")
        cached_body = mock_redis.set.call_args.args[1] if mock_redis.set.call_args else ""
        log_text = "\n".join(captured_logs.output)

        for secret_value in TEST_UPSTREAM_SECRETS.values():
            self.assertNotIn(secret_value, body)
            self.assertNotIn(secret_value, cached_body)
            self.assertNotIn(secret_value, log_text)
        self.assertNotIn("ops-contact%40example.org", body)
        self.assertIn("***REDACTED***", body)

        rows = {row["provider"]: row for row in response.json()["results"]}
        self.assertEqual(rows["Proxycheck"]["status"], "502 Error")
        self.assertIn("key=***REDACTED***", rows["Proxycheck"]["rawJson"]["message"])

    @patch("detector.views.query_maxmind", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
    def test_upstream_body_echoing_key_is_redacted(self, mock_async_client_cls, mock_mm):
        mock_mm.return_value = dict(MAXMIND_STUB)

        async def _echo(url, **kwargs):
            return _mock_response(
                status_code=403,
                json_value={"status": "denied", "message": f"Key secret123 is invalid for {url}"},
            )

        _patch_async_client(mock_async_client_cls, _echo)
        _login_authorised(self)

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.views.redis_client", None),
        ):
            response = self.client.get("/api/v1/detect?ip=8.8.8.8")

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("secret123", response.content.decode("utf-8"))


class UpstreamPayloadDefenceTests(TestCase):
    """Tests that malformed upstream bodies degrade to error rows instead of crashing adapters."""

    def setUp(self):
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)

    def test_safe_int_handles_null_nan_and_garbage(self):
        self.assertEqual(_safe_int(1), 1)
        self.assertEqual(_safe_int("2"), 2)
        self.assertEqual(_safe_int(1.0), 1)
        self.assertEqual(_safe_int(None), 0)
        self.assertEqual(_safe_int("invalid"), 0)
        self.assertEqual(_safe_int("NaN"), 0)
        self.assertEqual(_safe_int(float("inf")), 0)
        self.assertEqual(_safe_int([1]), 0)
        self.assertEqual(_safe_int(True), 0)
        self.assertIsNone(_safe_int(None, default=None))

    def test_all_adapters_reject_non_dict_payloads(self):
        for payload in ([], [{"block": 1}], "502 Bad Gateway", 42):
            for name, adapter in ALL_ADAPTERS:
                with self.subTest(provider=name, payload=payload):
                    result = adapter(payload, 200)
                    self.assertEqual(result["provider"], name)
                    self.assertEqual(result["status"], "502 Error")
                    self.assertEqual(result["statusCode"], 502)
                    self.assertIsInstance(result["rawJson"], dict)

    def test_non_dict_payload_keeps_upstream_error_status(self):
        result = adapt_iphub([], True, 429)
        self.assertEqual(result["status"], "429 Rate Limited")

    def test_iphub_null_and_invalid_block_degrade_to_format_error(self):
        for block in (None, "invalid", "NaN", [], {}):
            with self.subTest(block=block):
                result = adapt_iphub({"ip": "8.8.8.8", "block": block}, True, 200)
                self.assertEqual(result["status"], "502 Error")
                self.assertIsNone(result["block"])

    def test_iphub_numeric_string_block_is_classified(self):
        result = adapt_iphub({"ip": "8.8.8.8", "block": "1", "countryCode": "US"}, True, 200)
        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(result["block"], 1)
        self.assertTrue(any(flag["isHighRisk"] for flag in result["securityFlags"]))

    def test_iphunter_null_and_invalid_block_degrade_to_format_error(self):
        for payload in ({"block": None}, {"block": "invalid"}, {"data": {"block": "NaN"}}):
            with self.subTest(payload=payload):
                result = adapt_iphunter(payload, True, 200)
                self.assertEqual(result["status"], "502 Error")
                self.assertIsNone(result["block"])

    def test_iphunter_missing_block_keeps_residential_default(self):
        result = adapt_iphunter({"data": {"ip": "8.8.8.8", "country_code": "us"}}, True, 200)
        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(result["block"], 0)
        self.assertEqual(result["countryCode"], "US")

    def test_getipintel_nan_result_is_rejected(self):
        result = adapt_getipintel({"status": "success", "result": "NaN"}, True, 200)
        self.assertEqual(result["status"], "400 Error")

    def test_cloudflare_null_result_does_not_crash(self):
        unconfigured = adapt_cloudflare_radar(None, False)
        self.assertEqual(unconfigured["organisation"], "-")

        errored = adapt_cloudflare_radar({"success": False}, True, 429)
        self.assertEqual(errored["organisation"], "-")

        result = adapt_cloudflare_radar({"success": True, "result": None}, True, 200)
        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(result["asn"], "-")

    def test_abuseipdb_non_dict_data_degrades(self):
        result = adapt_abuseipdb({"data": None}, True, 200)
        self.assertEqual(result["status"], "200 Error")

    def test_html_gateway_page_maps_to_format_error(self):
        client = AsyncMock()
        client.get.return_value = _mock_response(
            status_code=200,
            json_error=ValueError("Expecting value: line 1 column 1"),
            text="<html><body><h1>502 Bad Gateway</h1></body></html>",
        )
        with override_settings(**TEST_UPSTREAM_SECRETS), patch.dict(os.environ, TEST_UPSTREAM_SECRETS):
            result = asyncio.run(views.query_iphub(client, "8.8.8.8"))
        self.assertEqual(result["status"], "502 Error")
        self.assertIn("502 Bad Gateway", result["rawJson"]["message"])

    @patch("detector.views.query_maxmind", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
    def test_detect_ip_survives_malformed_upstream_bodies(self, mock_async_client_cls, mock_mm):
        cases = (
            ("null block", {"json_value": {"block": None}}, ("IPHub", "IPHunter")),
            ("invalid block", {"json_value": {"block": "invalid"}}, ("IPHub", "IPHunter")),
            ("json array", {"json_value": []}, HTTP_PROVIDERS),
            (
                "html gateway page",
                {"json_error": ValueError("Expecting value"), "text": "<html>502 Bad Gateway</html>"},
                HTTP_PROVIDERS,
            ),
            ("json null", {"json_value": None}, ()),
        )
        _login_authorised(self)

        for label, response_kwargs, expected_format_errors in cases:
            with self.subTest(case=label):
                mock_mm.return_value = dict(MAXMIND_STUB)

                async def _respond(url, expected_kwargs=response_kwargs, **kwargs):
                    return _mock_response(status_code=200, **expected_kwargs)

                _patch_async_client(mock_async_client_cls, _respond)

                with (
                    override_settings(**TEST_UPSTREAM_SECRETS),
                    patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
                    patch("detector.views.redis_client", None),
                    self.assertNoLogs("detector.views", level="ERROR"),
                ):
                    response = self.client.get("/api/v1/detect?ip=8.8.8.8")

                self.assertEqual(response.status_code, 200)
                rows = {row["provider"]: row for row in response.json()["results"]}
                self.assertEqual(len(rows), 14)
                self.assertNotIn("Tor Onionoo", rows)
                for provider in expected_format_errors:
                    self.assertEqual(rows[provider]["status"], "502 Error", provider)


class MaxMindUsageTypeTests(TestCase):
    """Tests that GeoLite2 records without traits.user_type are not reported as hosting."""

    GEOLITE2_RECORD = {
        "autonomous_system_number": 1221,
        "autonomous_system_organization": "Telstra Corporation Ltd",
        "country": {"iso_code": "AU", "names": {"en": "Australia"}},
        "location": {"latitude": -33.494, "longitude": 143.2104},
    }

    def test_geolite2_without_user_type_is_not_hosting(self):
        result = adapt_maxmind(dict(self.GEOLITE2_RECORD), True, 200)
        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(result["usageType"], "unknown")
        self.assertEqual(result["securityFlags"], [{"label": "No Flags", "isHighRisk": False}])

    def test_geoip2_hosting_user_type_is_still_flagged(self):
        record = dict(self.GEOLITE2_RECORD, traits={"user_type": "hosting"})
        result = adapt_maxmind(record, True, 200)
        self.assertEqual(result["usageType"], "hosting")
        self.assertIn({"label": "Hosting", "isHighRisk": True}, result["securityFlags"])

    def test_geoip2_residential_user_type_is_preserved(self):
        record = dict(self.GEOLITE2_RECORD, traits={"user_type": "residential"})
        result = adapt_maxmind(record, True, 200)
        self.assertEqual(result["usageType"], "residential")

    def test_non_dict_traits_do_not_crash(self):
        record = dict(self.GEOLITE2_RECORD, traits="corrupted")
        result = adapt_maxmind(record, True, 200)
        self.assertEqual(result["usageType"], "unknown")

    def test_geolite2_row_does_not_raise_aggregate_score(self):
        maxmind_row = adapt_maxmind(dict(self.GEOLITE2_RECORD), True, 200)
        aggregated = views.aggregate_intelligence_metrics("1.2.3.4", [maxmind_row])
        self.assertFalse(aggregated["isMajorityProxyVpn"])
        self.assertEqual(aggregated["arbitrationTier"], "neutral")
        self.assertNotIn("Hosting", aggregated["arbitrationVerdict"])


class AggregationAndCacheIntegrityTests(TestCase):
    """Tests pure aggregation semantics and protection against caching transient upstream failures."""

    def setUp(self):
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)

    def test_aggregate_intelligence_metrics_does_not_mutate_input_dicts(self):
        input_rows = [
            {
                "provider": "IPData",
                "status": "200 OK",
                "statusCode": 200,
                "asn": "AS13335",
                "isp": "Cloudflare",
                "organisation": "Cloudflare",
                "location": "United States",
                "usageType": "hosting",
                "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
                "countryCode": "US",
                "rawJson": {"ip": "1.1.1.1"},
            },
            {
                "provider": "IPRegistry",
                "status": "200 OK",
                "statusCode": 200,
                "asn": "AS13335",
                "isp": "Cloudflare",
                "organisation": "Cloudflare",
                "location": "United States",
                "usageType": "isp",
                "securityFlags": [{"label": "Proxy", "isHighRisk": True}],
                "countryCode": "US",
                "rawJson": {"ip": "1.1.1.1"},
            },
        ]
        snapshot = copy.deepcopy(input_rows)

        aggregated = views.aggregate_intelligence_metrics("1.1.1.1", input_rows)

        # Verify caller input structures were not modified in place
        self.assertEqual(input_rows, snapshot)
        self.assertEqual(input_rows[0]["securityFlags"], [{"label": "No Flags", "isHighRisk": False}])

        # Verify returned copy normalizes hosting flags without mutating inputs
        out_rows = {row["provider"]: row for row in aggregated["results"]}
        self.assertEqual(out_rows["IPData"]["securityFlags"], [{"label": "Hosting", "isHighRisk": True}])
        self.assertEqual(out_rows["IPRegistry"]["securityFlags"], [{"label": "Proxy", "isHighRisk": True}])

        # Mutating returned securityFlags must not pollute the caller input list or flag dictionaries
        out_rows["IPRegistry"]["securityFlags"][0]["label"] = "Mutated"
        out_rows["IPRegistry"]["securityFlags"].append({"label": "Extra", "isHighRisk": False})
        self.assertEqual(input_rows[1]["securityFlags"], [{"label": "Proxy", "isHighRisk": True}])
        self.assertIs(out_rows["IPData"]["rawJson"], input_rows[0]["rawJson"])

    def test_sanitized_cache_entry_skips_redundant_payload_sanitization_on_hit(self):
        sanitized_entry = json.dumps(
            {
                "row": {
                    "provider": "IPData",
                    "status": "200 OK",
                    "statusCode": 200,
                    "rawJson": {"ip": "8.8.8.8"},
                },
                "cachedAt": "2026-11-15T08:00:00+00:00",
                "sanitized": True,
            }
        )
        legacy_entry = json.dumps(
            {
                "row": {
                    "provider": "IPData",
                    "status": "200 OK",
                    "statusCode": 200,
                    "rawJson": {"detail": "url?key=secret123"},
                },
                "cachedAt": "2026-11-15T08:00:00+00:00",
            }
        )
        with patch("detector.views._sanitize_payload", wraps=views._sanitize_payload) as spy_sanitize:
            decoded_sanitized = views._decode_cached_provider_entry(sanitized_entry)
            self.assertIsNotNone(decoded_sanitized)
            self.assertEqual(spy_sanitize.call_count, 0)

            decoded_legacy = views._decode_cached_provider_entry(legacy_entry)
            self.assertIsNotNone(decoded_legacy)
            self.assertGreater(spy_sanitize.call_count, 0)
            self.assertIn("key=***REDACTED***", decoded_legacy[0]["rawJson"]["detail"])

    @patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock)
    @patch("detector.views.query_maxmind", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
    def test_cache_hit_returns_payload_without_recomputing_aggregation(
        self, mock_async_client_cls, mock_mm, mock_dns_resolve
    ):
        provider_map = {
            "cloudflare_radar": "Cloudflare Radar",
            "abuseipdb": "AbuseIPDB",
            "ipdata": "IPData",
            "ipregistry": "IPRegistry",
            "ip2location": "IP2Location",
            "getipintel": "GetIPIntel",
            "proxycheck": "Proxycheck",
            "iphub": "IPHub",
            "iphunter": "IPHunter",
            "maxmind": "MaxMind",
            "spamhaus_zen": "Spamhaus ZEN",
            "spamcop": "SpamCop",
            "tor_onionoo": "Tor Onionoo",
            "stopforumspam": "StopForumSpam",
            "dshield": "DShield",
        }
        cache_store = {}
        for provider_key, provider_name in provider_map.items():
            cache_store[f"proxycheck:v1:prov:{provider_key}:8.8.8.8"] = json.dumps(
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
                }
            )
        cache_store["proxycheck:v1:prov:ptr:8.8.8.8"] = json.dumps(
            {
                "hostname": "dns.google",
                "status": "ok",
                "cachedAt": "2026-11-13T08:30:00+00:00",
            }
        )

        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(side_effect=lambda k: cache_store.get(k))
        mock_redis.set = AsyncMock()
        _login_authorised(self)

        with patch("detector.views.redis_client", mock_redis):
            response = self.client.get("/api/v1/detect?ip=8.8.8.8")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["isCached"])
        self.assertEqual(payload["cacheMeta"]["status"], "hit")
        self.assertFalse(payload["cacheMeta"]["isPartial"])
        self.assertEqual(payload["cacheMeta"]["hitCount"], 16)
        self.assertEqual(payload["cacheMeta"]["cachedAt"], "2026-11-13T08:00:00+00:00")
        self.assertEqual(payload["ptrHostname"], "dns.google")
        self.assertEqual(payload["arbitrationTier"], "success")
        mock_async_client_cls.assert_not_called()
        mock_dns_resolve.assert_not_called()
        mock_mm.assert_not_called()

    @patch(
        "dns.asyncresolver.Resolver.resolve",
        new_callable=AsyncMock,
        side_effect=dns.exception.Timeout("DNS timed out"),
    )
    @patch("detector.views.query_maxmind", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
    def test_transient_429_and_5xx_errors_do_not_pollute_redis_cache(self, mock_async_client_cls, mock_mm, _mock_dns):
        mock_mm.return_value = dict(MAXMIND_STUB)
        _login_authorised(self)

        for error_status in (429, 500, 502, 503):
            with self.subTest(status_code=error_status):

                async def _fail_upstream(url, status=error_status, **kwargs):
                    return _mock_response(status_code=status, json_value={"status": "error"})

                _patch_async_client(mock_async_client_cls, _fail_upstream)
                mock_redis = MagicMock()
                mock_redis.get = AsyncMock(return_value=None)
                mock_redis.set = AsyncMock()

                with (
                    override_settings(**TEST_UPSTREAM_SECRETS),
                    patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
                    patch("detector.views.redis_client", mock_redis),
                ):
                    response = self.client.get("/api/v1/detect?ip=8.8.8.8")

                self.assertEqual(response.status_code, 200)
                written_keys = [c.args[0] for c in mock_redis.set.call_args_list]
                self.assertFalse(any(k.startswith("proxycheck:v1:prov:") for k in written_keys))
                cooldown_calls = [
                    c for c in mock_redis.set.call_args_list if c.args[0].startswith("proxycheck:v1:cooldown:")
                ]
                self.assertEqual(len(cooldown_calls), 13)
                for call_obj in cooldown_calls:
                    self.assertEqual(call_obj.kwargs.get("ex"), 120)

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
    def test_clean_200_responses_are_written_to_redis_cache(
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

        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.set = AsyncMock()
        _login_authorised(self)

        with patch("detector.views.redis_client", mock_redis):
            response = self.client.get("/api/v1/detect?ip=8.8.8.8")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertFalse(payload["isCached"])
        self.assertEqual(payload["cacheMeta"]["status"], "miss")
        self.assertEqual(mock_redis.set.await_count, 15)
        ttls_by_key = {c.args[0]: c.kwargs.get("ex") for c in mock_redis.set.call_args_list}
        for provider_key in (
            "cloudflare_radar",
            "abuseipdb",
            "ipdata",
            "ipregistry",
            "ip2location",
            "getipintel",
            "proxycheck",
            "iphub",
            "iphunter",
        ):
            self.assertEqual(ttls_by_key.get(f"proxycheck:v1:prov:{provider_key}:8.8.8.8"), 86400)
        for dynamic_key in ("ptr", "spamhaus_zen", "spamcop", "tor_onionoo", "stopforumspam", "dshield"):
            self.assertEqual(ttls_by_key.get(f"proxycheck:v1:prov:{dynamic_key}:8.8.8.8"), 7200)
        self.assertNotIn("proxycheck:v1:prov:maxmind:8.8.8.8", ttls_by_key)

    @patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock)
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
    def test_partial_cache_hit_annotates_only_cached_rows_with_timestamps(
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
        mock_dns_resolve,
    ):
        def _ok_row(name):
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
            m.return_value = _ok_row(name)
        mock_mm.return_value = dict(MAXMIND_STUB)
        mock_dns_resolve.side_effect = dns.resolver.NXDOMAIN()

        cached_iso = "2026-11-14T06:15:00+00:00"
        cache_store = {
            "proxycheck:v1:prov:cloudflare_radar:8.8.8.8": json.dumps(
                {"row": _ok_row("Cloudflare Radar"), "cachedAt": cached_iso}
            )
        }
        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(side_effect=lambda k: cache_store.get(k))
        mock_redis.set = AsyncMock()
        _login_authorised(self)

        with patch("detector.views.redis_client", mock_redis):
            response = self.client.get("/api/v1/detect?ip=8.8.8.8")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertFalse(payload["isCached"])
        self.assertTrue(payload["cacheMeta"]["isPartial"])
        rows_by_provider = {row["provider"]: row for row in payload["results"]}
        self.assertTrue(rows_by_provider["Cloudflare Radar"].get("isCached"))
        self.assertEqual(rows_by_provider["Cloudflare Radar"].get("cachedAt"), cached_iso)
        self.assertNotIn("isCached", rows_by_provider["AbuseIPDB"])
        self.assertNotIn("cachedAt", rows_by_provider["AbuseIPDB"])
        mock_cf.assert_not_called()
        mock_abuse.assert_called_once()


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
            first = await views._get_shared_http_client()
            second = await views._get_shared_http_client()
            self.assertIs(first, second)
            return first

        with patch("detector.views.httpx.AsyncClient", wraps=httpx.AsyncClient) as spy_cls:
            client_loop_one = asyncio.run(_acquire_twice())
            self.assertEqual(spy_cls.call_count, 1)

            # Running in a new event loop after the previous one closed must rebuild the client cleanly
            client_loop_two = asyncio.run(_acquire_twice())
            self.assertEqual(spy_cls.call_count, 2)
            self.assertIsNot(client_loop_one, client_loop_two)

    @patch("detector.views.query_maxmind", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
    def test_sequential_async_requests_do_not_raise_closed_event_loop_error(self, mock_async_client_cls, mock_mm):
        mock_mm.return_value = dict(MAXMIND_STUB)

        async def _ok_response(url, **kwargs):
            return _mock_response(status_code=200, json_value={"status": "ok", "block": 0})

        _patch_async_client(mock_async_client_cls, _ok_response)
        _login_authorised(self)

        with (
            override_settings(**EMPTY_UPSTREAM_SECRETS),
            patch.dict(os.environ, EMPTY_UPSTREAM_SECRETS),
            patch("detector.views.redis_client", None),
        ):
            first_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")
            second_resp = self.client.get("/api/v1/detect?ip=1.1.1.1")

        self.assertEqual(first_resp.status_code, 200)
        self.assertEqual(second_resp.status_code, 200)

    def test_maxmind_reader_reused_across_calls_and_gracefully_degrades_when_missing(self):
        views._maxmind_readers.clear()

        mock_country_reader = MagicMock()
        mock_country_reader.get.return_value = {"country": {"iso_code": "US", "names": {"en": "United States"}}}
        mock_city_reader = MagicMock()
        mock_city_reader.get.return_value = {
            "country": {"iso_code": "US", "names": {"en": "United States"}},
            "subdivisions": [{"iso_code": "CA", "names": {"en": "California"}}],
            "city": {"names": {"en": "Mountain View"}},
            "location": {"latitude": 37.386, "longitude": -122.0838},
        }
        mock_asn_reader = MagicMock()
        mock_asn_reader.get.return_value = {
            "autonomous_system_number": 13335,
            "autonomous_system_organization": "Cloudflare",
        }

        def _fake_open(path):
            lowered = str(path).lower()
            if "country" in lowered:
                return mock_country_reader
            if "city" in lowered:
                return mock_city_reader
            return mock_asn_reader

        mock_maxmind_module = MagicMock()
        mock_maxmind_module.open_database.side_effect = _fake_open

        with (
            patch("detector.views.os.path.exists", return_value=True),
            patch.dict("sys.modules", {"maxminddb": mock_maxmind_module}),
        ):
            res_one = views._read_maxmind_sync("1.1.1.1")
            res_two = views._read_maxmind_sync("8.8.8.8")

        self.assertEqual(res_one["status"], "200 OK")
        self.assertEqual(res_one["location"], "Mountain View, California, United States (37.386, -122.0838)")
        self.assertEqual(res_one["countryCode"], "US")
        self.assertEqual(res_two["status"], "200 OK")
        self.assertEqual(mock_maxmind_module.open_database.call_count, 3)
        self.assertEqual(mock_country_reader.get.call_count, 2)
        self.assertEqual(mock_city_reader.get.call_count, 2)
        self.assertEqual(mock_asn_reader.get.call_count, 2)

        # Verify graceful fallback when local MMDB files are absent
        with patch("detector.views.os.path.exists", return_value=False):
            missing_res = views._read_maxmind_sync("1.1.1.1")
        self.assertEqual(missing_res["status"], "Database Missing")
        self.assertEqual(len(views._maxmind_readers), 0)


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
    """Tests IPv4 and IPv6 address canonicalization for cache consistency and production security settings."""

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


class ReverseDnsAndCidrAttributionTests(TestCase):
    """Tests reverse DNS PTR resolution, hostname classification, CIDR range attribution, and cache guards."""

    def setUp(self):
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)
        _login_authorised(self)

    def test_ptr_normal_resolution_and_hostname_classification(self):
        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            return_value=_mock_ptr_answer("EC2-54-239-28-85.compute-1.amazonaws.com."),
        ) as mock_dns:
            hostname = asyncio.run(views.query_rdns_ptr("54.239.28.85"))
            mock_dns.assert_awaited_once_with(
                dns.reversename.from_address("54.239.28.85"),
                "PTR",
            )

        self.assertEqual(hostname, "ec2-54-239-28-85.compute-1.amazonaws.com")
        hosting_info = classify_rdns_hostname(hostname)
        self.assertEqual(hosting_info["ptrCategory"], "hosting_or_gateway")
        self.assertEqual(hosting_info["ptrLabel"], "Cloud or Hosting Gateway")
        self.assertTrue(hosting_info["isHighRisk"])

        residential_info = classify_rdns_hostname("p5489a1b2.dip0.t-ipconnect.de.")
        self.assertEqual(residential_info["ptrHostname"], "p5489a1b2.dip0.t-ipconnect.de")
        self.assertEqual(residential_info["ptrCategory"], "dynamic_residential")
        self.assertEqual(residential_info["ptrLabel"], "Dynamic Residential")
        self.assertFalse(residential_info["isHighRisk"])

        standard_info = classify_rdns_hostname("dns.google")
        self.assertEqual(standard_info["ptrCategory"], "unclassified")
        self.assertFalse(standard_info["isHighRisk"])

        none_info = classify_rdns_hostname(None)
        self.assertIsNone(none_info["ptrHostname"])
        self.assertEqual(none_info["ptrCategory"], "none")
        self.assertFalse(none_info["isHighRisk"])

    def test_ptr_timeout_degrades_silently_to_none(self):
        state = {"status": "ok"}
        token = views._rdns_context_state.set(state)
        try:
            with patch(
                "dns.asyncresolver.Resolver.resolve",
                new_callable=AsyncMock,
                side_effect=dns.exception.Timeout("DNS timed out"),
            ):
                resolver = views._create_async_resolver()
                self.assertEqual(resolver.timeout, 2.0)
                self.assertEqual(resolver.lifetime, 2.0)
                result = asyncio.run(views.query_rdns_ptr("8.8.8.8"))
        finally:
            views._rdns_context_state.reset(token)

        self.assertIsNone(result)
        self.assertEqual(state["status"], "timeout")

    def test_ptr_resolution_exceptions_degrade_silently_to_none(self):
        error_cases = (
            ("nxdomain", dns.resolver.NXDOMAIN(), "nxdomain"),
            ("noanswer", dns.resolver.NoAnswer(), "nxdomain"),
            ("nonameservers", dns.resolver.NoNameservers(), "error"),
            ("timeout", dns.exception.Timeout("DNS timed out"), "timeout"),
        )
        for label, exc, expected_status in error_cases:
            with self.subTest(case=label):
                state = {"status": "ok"}
                token = views._rdns_context_state.set(state)
                try:
                    with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock, side_effect=exc):
                        result = asyncio.run(views.query_rdns_ptr("1.2.3.4"))
                finally:
                    views._rdns_context_state.reset(token)

                self.assertIsNone(result)
                self.assertEqual(state["status"], expected_status)

    def test_cidr_attribution_defaults_and_mmdb_prefix_selection(self):
        # Verify IPv4 default prefix 24 and IPv6 default prefix 64 when no MMDB prefix is present
        v4_default = compute_cidr_attribution("203.0.113.45", None)
        self.assertEqual(v4_default["recommendedCidr"], "203.0.113.0/24")
        self.assertEqual(v4_default["defaultCidr"], "203.0.113.0/24")
        self.assertIsNone(v4_default["mmdbCidr"])

        v6_default = compute_cidr_attribution("2001:db8:abcd:1234:5678::1", None)
        self.assertEqual(v6_default["recommendedCidr"], "2001:db8:abcd:1234::/64")
        self.assertEqual(v6_default["defaultCidr"], "2001:db8:abcd:1234::/64")
        self.assertIsNone(v6_default["mmdbCidr"])

        # Verify narrower MMDB prefix is selected over the default granularity
        v4_narrow = compute_cidr_attribution("203.0.113.45", 28)
        self.assertEqual(v4_narrow["recommendedCidr"], "203.0.113.32/28")
        self.assertEqual(v4_narrow["defaultCidr"], "203.0.113.0/24")
        self.assertEqual(v4_narrow["mmdbCidr"], "203.0.113.32/28")

        v6_narrow = compute_cidr_attribution("2001:db8:abcd:1234:5678::1", 80)
        self.assertEqual(v6_narrow["recommendedCidr"], "2001:db8:abcd:1234:5678::/80")
        self.assertEqual(v6_narrow["defaultCidr"], "2001:db8:abcd:1234::/64")
        self.assertEqual(v6_narrow["mmdbCidr"], "2001:db8:abcd:1234:5678::/80")

        # Verify wider MMDB prefix is capped at default granularity while preserving mmdbCidr
        v4_wide = compute_cidr_attribution("203.0.113.45", 16)
        self.assertEqual(v4_wide["recommendedCidr"], "203.0.113.0/24")
        self.assertEqual(v4_wide["defaultCidr"], "203.0.113.0/24")
        self.assertEqual(v4_wide["mmdbCidr"], "203.0.0.0/16")

        v6_wide = compute_cidr_attribution("2001:db8:abcd:1234:5678::1", 48)
        self.assertEqual(v6_wide["recommendedCidr"], "2001:db8:abcd:1234::/64")
        self.assertEqual(v6_wide["defaultCidr"], "2001:db8:abcd:1234::/64")
        self.assertEqual(v6_wide["mmdbCidr"], "2001:db8:abcd::/48")

    def test_maxmind_sync_extracts_prefix_length_for_aggregation(self):
        views._maxmind_readers.clear()
        mock_asn_reader = MagicMock()
        mock_asn_reader.get.return_value = {
            "autonomous_system_number": 16509,
            "autonomous_system_organization": "Amazon.com, Inc.",
        }
        mock_asn_reader.get_with_prefix_len.return_value = (
            mock_asn_reader.get.return_value,
            26,
        )
        mock_maxmind_module = MagicMock()
        mock_maxmind_module.open_database.return_value = mock_asn_reader

        with (
            patch("detector.views.os.path.exists", side_effect=lambda p: "asn" in str(p).lower()),
            patch.dict("sys.modules", {"maxminddb": mock_maxmind_module}),
        ):
            mm_row = views._read_maxmind_sync("54.239.28.85")

        self.assertEqual(mm_row["status"], "200 OK")
        self.assertEqual(mm_row["prefixLength"], 26)
        self.assertNotIn("_mmdb_prefix_len", mm_row["rawJson"])

        aggregated = views.aggregate_intelligence_metrics(
            "54.239.28.85",
            [mm_row],
            ptr_hostname="ec2-54-239-28-85.compute-1.amazonaws.com",
        )
        self.assertEqual(aggregated["recommendedCidr"], "54.239.28.64/26")
        self.assertEqual(aggregated["defaultCidr"], "54.239.28.0/24")
        self.assertEqual(aggregated["mmdbCidr"], "54.239.28.64/26")
        self.assertEqual(aggregated["ptrCategory"], "hosting_or_gateway")

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
    def test_cache_conditions_preserved_across_rdns_and_upstream_states(
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
        written_ttls = {}

        async def _fake_get(key):
            return cache_store.get(key)

        async def _fake_set(key, val, ex=None):
            cache_store[key] = val
            written_ttls[key] = ex

        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(side_effect=_fake_get)
        mock_redis.set = AsyncMock(side_effect=_fake_set)

        # Transient DNS timeout skips caching PTR while healthy HTTP providers still cache
        with (
            patch("detector.views.redis_client", mock_redis),
            patch(
                "dns.asyncresolver.Resolver.resolve",
                new_callable=AsyncMock,
                side_effect=_ptr_or_clean_dns_side_effect(ptr_timeout=True),
            ),
        ):
            timeout_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")

        self.assertEqual(timeout_resp.status_code, 200)
        timeout_data = timeout_resp.json()
        self.assertIsNone(timeout_data["ptrHostname"])
        self.assertEqual(timeout_data["recommendedCidr"], "8.8.8.0/24")
        self.assertNotIn("proxycheck:v1:prov:ptr:8.8.8.8", cache_store)
        self.assertNotIn("proxycheck:v1:cooldown:ptr", cache_store)
        self.assertEqual(written_ttls.get("proxycheck:v1:prov:cloudflare_radar:8.8.8.8"), 86400)
        self.assertEqual(mock_cf.call_count, 1)

        # Subsequent lookup recovers PTR using cached providers without re-querying HTTP APIs
        with (
            patch("detector.views.redis_client", mock_redis),
            patch(
                "dns.asyncresolver.Resolver.resolve",
                new_callable=AsyncMock,
                side_effect=_ptr_or_clean_dns_side_effect(ptr_hostname="dns.google."),
            ),
        ):
            ok_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")

        self.assertEqual(ok_resp.status_code, 200)
        ok_data = ok_resp.json()
        self.assertEqual(ok_data["ptrHostname"], "dns.google")
        self.assertEqual(ok_data["recommendedCidr"], "8.8.8.0/24")
        self.assertFalse(ok_data["isCached"])
        self.assertTrue(ok_data["cacheMeta"]["isPartial"])
        self.assertEqual(ok_data["cacheMeta"]["status"], "partial")
        self.assertEqual(written_ttls.get("proxycheck:v1:prov:ptr:8.8.8.8"), 7200)
        self.assertEqual(mock_cf.call_count, 1)


class DetectEndpointRoutingAndValidationTests(TestCase):
    """Tests for URL routing normalization and IP parameter validation on the detect endpoint."""

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
        for path in ("/Toolforge.svg", "/favicon.svg", "/favicon.ico"):
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
        ):
            with self.assertRaises(ImproperlyConfigured):
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


class GadgetTokenAndCorsAuthTests(TestCase):
    """Tests for CentralAuth token exchange, Bearer verification, unified RBAC, and Wikimedia CORS."""

    def setUp(self):
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)
        views._http_client_instance = None
        views._http_client_loop = None
        self.addCleanup(self._reset_http_client)

    @staticmethod
    def _reset_http_client():
        views._http_client_instance = None
        views._http_client_loop = None

    @staticmethod
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

    def _patch_all_providers(self):
        patchers = []
        provider_map = (
            ("detector.views.query_cloudflare_radar", "Cloudflare Radar"),
            ("detector.views.query_abuseipdb", "AbuseIPDB"),
            ("detector.views.query_ipdata", "IPData"),
            ("detector.views.query_ipregistry", "IPRegistry"),
            ("detector.views.query_ip2location", "IP2Location"),
            ("detector.views.query_getipintel", "GetIPIntel"),
            ("detector.views.query_proxycheck", "Proxycheck"),
            ("detector.views.query_iphub", "IPHub"),
            ("detector.views.query_iphunter", "IPHunter"),
            ("detector.views.query_maxmind", "MaxMind"),
            ("detector.views.query_tor_onionoo", "Tor Onionoo"),
            ("detector.views.query_stopforumspam", "StopForumSpam"),
            ("detector.views.query_dshield", "DShield"),
        )
        for target, name in provider_map:
            p = patch(target, new_callable=AsyncMock, return_value=self._stub_provider(name))
            p.start()
            self.addCleanup(p.stop)
            patchers.append(p)
        return patchers

    def test_options_preflight_allows_wikimedia_origins_and_bearer_header(self):
        allowed_origins = (
            "https://zh.wikipedia.org",
            "https://zh.wiktionary.org",
            "https://meta.wikimedia.org",
            "https://www.wikidata.org",
            "https://zh.wikipedia.beta.wmcloud.org",
        )
        endpoints = (
            ("/api/v1/detect", "GET"),
            ("/api/v1/auth/gadget-token", "POST"),
            ("/api/v1/auth/gadget-token/", "POST"),
        )
        for origin in allowed_origins:
            for endpoint, expected_method in endpoints:
                with self.subTest(origin=origin, endpoint=endpoint):
                    response = self.client.options(endpoint, HTTP_ORIGIN=origin)
                    self.assertEqual(response.status_code, 204)
                    self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), origin)
                    allow_headers = response.headers.get("Access-Control-Allow-Headers", "")
                    self.assertIn("Authorization", allow_headers)
                    self.assertIn("Content-Type", allow_headers)
                    self.assertNotIn("X-Wiki-User", allow_headers)
                    self.assertIn(expected_method, response.headers.get("Access-Control-Allow-Methods", ""))
                    self.assertEqual(response.headers.get("Vary"), "Origin")

        for endpoint, _ in endpoints:
            with self.subTest(disallowed_endpoint=endpoint):
                disallowed_response = self.client.options(
                    endpoint,
                    HTTP_ORIGIN="https://evil.example.com",
                )
                self.assertEqual(disallowed_response.status_code, 204)
                self.assertNotIn("Access-Control-Allow-Origin", disallowed_response.headers)

    def test_bare_x_wiki_user_header_is_always_rejected_with_401(self):
        self._patch_all_providers()
        with (
            override_settings(ALLOWED_WIKI_USERS="AllowlistedUser"),
            patch("detector.views.fetch_user_rights_from_meta", new_callable=AsyncMock) as mock_fetch,
        ):
            for spoofed_user in ("GlobalSteward", "AllowlistedUser"):
                with self.subTest(spoofed_user=spoofed_user):
                    response = self.client.get(
                        "/api/v1/detect?ip=8.8.8.8",
                        HTTP_ORIGIN="https://zh.wikipedia.org",
                        HTTP_X_WIKI_USER=spoofed_user,
                    )
                    self.assertEqual(response.status_code, 401)
                    self.assertEqual(
                        response.headers.get("Access-Control-Allow-Origin"),
                        "https://zh.wikipedia.org",
                    )
        mock_fetch.assert_not_called()

    def test_verify_centralauth_token_handles_valid_rejected_and_transient_responses(self):
        def _build_client(response=None, side_effect=None):
            client = MagicMock()
            client.cookies = httpx.Cookies({"GeoIP": "US", "centralauth_Session": "stale-cookie"})
            if side_effect is not None:
                client.get = AsyncMock(side_effect=side_effect)
            else:
                client.get = AsyncMock(return_value=response)
            return client

        async def _run_cases():
            ok_resp = MagicMock(status_code=200)
            ok_resp.json.return_value = {
                "query": {
                    "userinfo": {
                        "id": 42,
                        "name": "  StewardUser  ",
                        "groups": ["*", "user", "sysop"],
                        "rights": ["read", "edit", "block"],
                        "centralids": {"CentralAuth": 1001, "local": 42},
                    }
                },
            }
            ok_client = _build_client(response=ok_resp)
            long_jwt_token = "eyJhbGciOiJSUzI1NiJ9." + ("a" * 400) + "." + ("b" * 400)
            userinfo = await verify_centralauth_userinfo(
                ok_client,
                long_jwt_token,
                wiki_domain="zh.wikipedia.org",
            )
            self.assertEqual(userinfo["username"], "StewardUser")
            self.assertEqual(userinfo["local_groups"], ["*", "user", "sysop"])
            self.assertEqual(userinfo["domain"], "zh.wikipedia.org")
            self.assertEqual(len(ok_client.cookies), 0)

            call_args = ok_client.get.await_args.args
            call_kwargs = ok_client.get.await_args.kwargs
            self.assertEqual(call_args[0], "https://zh.wikipedia.org/w/api.php")
            self.assertEqual(call_kwargs["params"]["centralauthtoken"], long_jwt_token)
            self.assertEqual(call_kwargs["params"]["meta"], "userinfo")
            self.assertEqual(call_kwargs["params"]["uiprop"], "groups|rights|centralids")
            self.assertEqual(
                call_kwargs["headers"]["User-Agent"],
                "ProxyCheck/1.0 (https://proxycheck.toolforge.org; tools.proxycheck@toolforge.org)",
            )

            invalid_payloads = (
                ({"error": {"code": "badtoken", "info": "Invalid token"}}, "badtoken"),
                ({"query": {"userinfo": {"id": 0, "anon": ""}}}, "anon"),
                ({"query": {"userinfo": {"id": 99, "name": "~2025-1234", "temp": ""}}}, "temp"),
                ({"query": {"userinfo": {"id": 99, "name": "~2025-1234"}}}, "temp"),
                ({"query": {"userinfo": {"id": 99, "name": "   "}}}, "missing_username"),
            )
            for payload, expected_code in invalid_payloads:
                bad_resp = MagicMock(status_code=200)
                bad_resp.json.return_value = payload
                with self.assertRaises(InvalidCentralAuthTokenError) as exc_ctx:
                    await verify_centralauth_userinfo(_build_client(response=bad_resp), "bad-token")
                self.assertIsInstance(exc_ctx.exception.mw_error, dict)
                self.assertEqual(exc_ctx.exception.mw_error.get("code"), expected_code)

            transient_resp = MagicMock(status_code=200)
            transient_resp.json.return_value = {
                "error": {"code": "internal_api_error_DBConnectionError", "info": "db down"},
            }
            with self.assertRaises(CentralAuthVerificationError):
                await verify_centralauth_userinfo(_build_client(response=transient_resp), "transient-token")

            http_err_resp = MagicMock(status_code=503)
            with self.assertRaises(CentralAuthVerificationError):
                await verify_centralauth_userinfo(_build_client(response=http_err_resp), "http-err")

            json_err_resp = MagicMock(status_code=200)
            json_err_resp.json.side_effect = ValueError("Invalid JSON")
            with self.assertRaises(CentralAuthVerificationError):
                await verify_centralauth_userinfo(_build_client(response=json_err_resp), "json-err")

            with self.assertRaises(CentralAuthVerificationError):
                await verify_centralauth_userinfo(
                    _build_client(side_effect=httpx.ConnectError("network failure")),
                    "net-err",
                )

        asyncio.run(_run_cases())

    def test_wikimedia_domain_validation_and_token_exchange_body_parsing(self):
        valid_domains = (
            "zh.wikipedia.org",
            "en.wikipedia.org",
            "meta.wikimedia.org",
            "en.wiktionary.org",
            "fr.wikisource.org",
            "www.wikidata.org",
            "de.wikibooks.org",
            "en.wikinews.org",
            "es.wikiquote.org",
            "en.wikiversity.org",
            "en.wikivoyage.org",
            "www.mediawiki.org",
            "zh.wikipedia.beta.wmcloud.org",
        )
        for domain in valid_domains:
            with self.subTest(valid_domain=domain):
                self.assertEqual(normalize_and_validate_wikimedia_domain(domain), domain)

        invalid_domains = (
            "",
            None,
            123,
            "evil.example.com",
            "wikipedia.org.evil.com",
            "https://zh.wikipedia.org",
            "zh.wikipedia.org:8080",
            "zh.wikipedia.org/w/api.php",
            "-bad.wikipedia.org",
            "zh..wikipedia.org",
        )
        for domain in invalid_domains:
            with self.subTest(invalid_domain=domain):
                self.assertIsNone(normalize_and_validate_wikimedia_domain(domain))

        get_resp = self.client.get(
            "/api/v1/auth/gadget-token",
            HTTP_ORIGIN="https://zh.wikipedia.org",
        )
        self.assertEqual(get_resp.status_code, 405)
        self.assertEqual(get_resp.headers.get("Access-Control-Allow-Origin"), "https://zh.wikipedia.org")

        invalid_bodies = (
            "{not-json",
            "[]",
            "{}",
            json.dumps({"centralauthtoken": 12345, "domain": "zh.wikipedia.org"}),
            json.dumps({"centralauthtoken": "   ", "domain": "zh.wikipedia.org"}),
            json.dumps({"centralauthtoken": "has space", "domain": "zh.wikipedia.org"}),
            json.dumps({"centralauthtoken": "has\nnewline", "domain": "zh.wikipedia.org"}),
            json.dumps({"centralauthtoken": "x" * 4097, "domain": "zh.wikipedia.org"}),
            json.dumps({"centralauthtoken": "valid-cat"}),
            json.dumps({"centralauthtoken": "valid-cat", "domain": "evil.example.com"}),
            json.dumps({"centralauthtoken": "valid-cat", "domain": "https://zh.wikipedia.org"}),
        )
        with patch("detector.views.verify_centralauth_userinfo", new_callable=AsyncMock) as mock_verify:
            for body in invalid_bodies:
                with self.subTest(body=body[:50]):
                    resp = self.client.post(
                        "/api/v1/auth/gadget-token",
                        data=body,
                        content_type="application/json",
                        HTTP_ORIGIN="https://zh.wikipedia.org",
                    )
                    self.assertEqual(resp.status_code, 400)
                    self.assertTrue(resp.json().get("error"))
                    self.assertEqual(
                        resp.headers.get("Access-Control-Allow-Origin"),
                        "https://zh.wikipedia.org",
                    )
        mock_verify.assert_not_called()

        long_jwt_token = "header." + ("a" * 500) + "." + ("b" * 500)
        with (
            patch(
                "detector.views.verify_centralauth_userinfo",
                new_callable=AsyncMock,
                return_value={
                    "username": "ZhWikiSysop",
                    "local_groups": ["*", "user", "sysop"],
                    "rights": ["read", "edit", "checkuser-temporary-account"],
                    "centralids": {"CentralAuth": 77},
                    "domain": "zh.wikipedia.org",
                },
            ) as mock_verify,
            patch(
                "detector.views.fetch_user_rights_from_meta",
                new_callable=AsyncMock,
                return_value={"global_groups": [], "global_rights": [], "merged_projects": []},
            ),
        ):
            text_plain_resp = self.client.post(
                "/api/v1/auth/gadget-token",
                data=json.dumps({"centralauthtoken": long_jwt_token, "domain": "zh.wikipedia.org"}),
                content_type="text/plain",
                HTTP_ORIGIN="https://zh.wikipedia.org",
            )
        self.assertEqual(text_plain_resp.status_code, 200)
        self.assertEqual(text_plain_resp.json()["username"], "ZhWikiSysop")
        self.assertEqual(mock_verify.await_args.kwargs["wiki_domain"], "zh.wikipedia.org")

    def test_exchange_gadget_token_error_mapping_and_subwiki_local_groups(self):
        with (
            patch(
                "detector.views.verify_centralauth_userinfo",
                new_callable=AsyncMock,
                side_effect=InvalidCentralAuthTokenError(
                    "MediaWiki rejected CentralAuth token (badtoken: Invalid token).",
                    mw_error={"code": "badtoken", "info": "Invalid token"},
                ),
            ),
            self.assertLogs("detector.views", level="WARNING") as invalid_logs,
        ):
            invalid_resp = self.client.post(
                "/api/v1/auth/gadget-token",
                data=json.dumps({"centralauthtoken": "expired-cat", "domain": "zh.wikipedia.org"}),
                content_type="application/json",
                HTTP_ORIGIN="https://zh.wikipedia.org",
            )
        self.assertEqual(invalid_resp.status_code, 401)
        invalid_payload = invalid_resp.json()
        self.assertEqual(invalid_payload, {"error": "Invalid CentralAuth token."})
        self.assertNotIn("mw_error", invalid_payload)
        self.assertTrue(any("badtoken" in entry for entry in invalid_logs.output))
        self.assertEqual(invalid_resp.headers.get("Access-Control-Allow-Origin"), "https://zh.wikipedia.org")

        with (
            patch(
                "detector.views.verify_centralauth_userinfo",
                new_callable=AsyncMock,
                side_effect=CentralAuthVerificationError(
                    "zh.wikipedia.org returned HTTP 503.",
                    mw_error={"code": "http_error", "status": 503},
                ),
            ),
            self.assertLogs("detector.views", level="WARNING") as transient_logs,
        ):
            transient_resp = self.client.post(
                "/api/v1/auth/gadget-token",
                data=json.dumps({"centralauthtoken": "cat-503", "domain": "zh.wikipedia.org"}),
                content_type="application/json",
                HTTP_ORIGIN="https://zh.wikipedia.org",
            )
        self.assertEqual(transient_resp.status_code, 503)
        transient_payload = transient_resp.json()
        self.assertEqual(
            transient_payload,
            {"error": "Unable to verify CentralAuth credentials at this time."},
        )
        self.assertNotIn("mw_error", transient_payload)
        self.assertTrue(any("http_error" in entry and "503" in entry for entry in transient_logs.output))
        self.assertEqual(transient_resp.headers.get("Access-Control-Allow-Origin"), "https://zh.wikipedia.org")

        with (
            patch(
                "detector.views.verify_centralauth_userinfo",
                new_callable=AsyncMock,
                return_value={
                    "username": "RegularUser",
                    "local_groups": ["*", "user"],
                    "rights": [],
                    "centralids": {},
                    "domain": "zh.wikipedia.org",
                },
            ),
            patch(
                "detector.views.fetch_user_rights_from_meta",
                new_callable=AsyncMock,
                return_value={"global_groups": [], "merged_projects": [{"wiki": "enwiki", "groups": ["*", "user"]}]},
            ),
        ):
            unpriv_resp = self.client.post(
                "/api/v1/auth/gadget-token",
                data=json.dumps({"centralauthtoken": "cat-unpriv", "domain": "zh.wikipedia.org"}),
                content_type="application/json",
                HTTP_ORIGIN="https://zh.wikipedia.org",
            )
        self.assertEqual(unpriv_resp.status_code, 403)
        self.assertEqual(unpriv_resp.headers.get("Access-Control-Allow-Origin"), "https://zh.wikipedia.org")

        with (
            patch(
                "detector.views.verify_centralauth_userinfo",
                new_callable=AsyncMock,
                return_value={
                    "username": "MissingUser",
                    "local_groups": ["*"],
                    "rights": [],
                    "centralids": {},
                    "domain": "zh.wikipedia.org",
                },
            ),
            patch(
                "detector.views.fetch_user_rights_from_meta",
                new_callable=AsyncMock,
                side_effect=MetaWikiRightsFetchError("Meta-Wiki globaluserinfo missing from response"),
            ),
        ):
            missing_resp = self.client.post(
                "/api/v1/auth/gadget-token",
                data=json.dumps({"centralauthtoken": "cat-missing", "domain": "zh.wikipedia.org"}),
                content_type="application/json",
                HTTP_ORIGIN="https://zh.wikipedia.org",
            )
        self.assertEqual(missing_resp.status_code, 403)

        with (
            patch(
                "detector.views.verify_centralauth_userinfo",
                new_callable=AsyncMock,
                return_value={
                    "username": "TransientUser",
                    "local_groups": ["*", "user"],
                    "rights": [],
                    "centralids": {},
                    "domain": "zh.wikipedia.org",
                },
            ),
            patch(
                "detector.views.fetch_user_rights_from_meta",
                new_callable=AsyncMock,
                side_effect=MetaWikiRightsFetchError("Meta-Wiki returned HTTP 503"),
            ),
        ):
            rights_err_resp = self.client.post(
                "/api/v1/auth/gadget-token",
                data=json.dumps({"centralauthtoken": "cat-rights-503", "domain": "zh.wikipedia.org"}),
                content_type="application/json",
                HTTP_ORIGIN="https://zh.wikipedia.org",
            )
        self.assertEqual(rights_err_resp.status_code, 503)

        # Verify local sub-wiki privileges still grant access even if globaluserinfo lookup degrades
        with (
            patch(
                "detector.views.verify_centralauth_userinfo",
                new_callable=AsyncMock,
                return_value={
                    "username": "LocalZhCheckUser",
                    "local_groups": ["*", "user", "checkuser"],
                    "rights": ["checkuser-temporary-account"],
                    "centralids": {},
                    "domain": "zh.wikipedia.org",
                },
            ),
            patch(
                "detector.views.fetch_user_rights_from_meta",
                new_callable=AsyncMock,
                side_effect=MetaWikiRightsFetchError("Meta-Wiki returned HTTP 503"),
            ),
        ):
            local_ok_resp = self.client.post(
                "/api/v1/auth/gadget-token",
                data=json.dumps({"centralauthtoken": "cat-local-cu", "domain": "zh.wikipedia.org"}),
                content_type="application/json",
                HTTP_ORIGIN="https://zh.wikipedia.org",
            )
        self.assertEqual(local_ok_resp.status_code, 200)
        self.assertEqual(local_ok_resp.json()["username"], "LocalZhCheckUser")

    def test_exchange_gadget_token_issues_signed_token_across_rbac_groups_and_allowlist(self):
        authorized_right_cases = (
            (
                "GlobalTaViewer",
                ["read"],
                {"global_groups": [], "global_rights": ["checkuser-temporary-account"], "merged_projects": []},
                [],
            ),
            (
                "GlobalNoPrefUser",
                ["read"],
                {
                    "global_groups": [],
                    "global_rights": ["checkuser-temporary-account-no-preference"],
                    "merged_projects": [],
                },
                [],
            ),
            (
                "LocalTaRightUser",
                ["read", "checkuser-temporary-account"],
                {"global_groups": [], "global_rights": [], "merged_projects": []},
                [],
            ),
            (
                "LocalNoPrefRightUser",
                ["read", "checkuser-temporary-account-no-preference"],
                {"global_groups": [], "global_rights": [], "merged_projects": []},
                [],
            ),
            (
                "PrepopulatedProjectRightUser",
                ["read"],
                {
                    "global_groups": [],
                    "global_rights": [],
                    "merged_projects": [{"wiki": "enwiki", "rights": ["checkuser-temporary-account"]}],
                },
                [],
            ),
            (
                "FetchedProjectTaRightUser",
                ["read"],
                {
                    "global_groups": [],
                    "global_rights": [],
                    "merged_projects": [{"wiki": "jawiki", "url": "https://ja.wikipedia.org", "groups": ["sysop"]}],
                },
                ["read", "checkuser-temporary-account"],
            ),
            (
                "FetchedProjectNoPrefRightUser",
                ["read"],
                {
                    "global_groups": [],
                    "global_rights": [],
                    "merged_projects": [{"wiki": "enwiki", "url": "https://en.wikipedia.org", "groups": ["checkuser"]}],
                },
                ["read", "checkuser-temporary-account-no-preference"],
            ),
        )

        with override_settings(GADGET_TOKEN_TTL_SECONDS=3600):
            for username, local_rights, rights_payload, project_rights in authorized_right_cases:
                with self.subTest(username=username):
                    userinfo_stub = {
                        "username": username,
                        "local_groups": ["*", "user"],
                        "rights": local_rights,
                        "centralids": {},
                        "domain": "zh.wiktionary.org",
                    }
                    with (
                        patch(
                            "detector.views.verify_centralauth_userinfo",
                            new_callable=AsyncMock,
                            return_value=userinfo_stub,
                        ),
                        patch(
                            "detector.views.fetch_user_rights_from_meta",
                            new_callable=AsyncMock,
                            return_value=rights_payload,
                        ),
                        patch(
                            "detector.views.fetch_project_user_rights",
                            new_callable=AsyncMock,
                            return_value=project_rights,
                        ),
                    ):
                        resp = self.client.post(
                            "/api/v1/auth/gadget-token",
                            data=json.dumps({"centralauthtoken": "valid-cat", "domain": "zh.wiktionary.org"}),
                            content_type="application/json",
                            HTTP_ORIGIN="https://zh.wiktionary.org",
                        )
                    self.assertEqual(resp.status_code, 200)
                    self.assertEqual(resp.headers.get("Access-Control-Allow-Origin"), "https://zh.wiktionary.org")
                    data = resp.json()
                    self.assertEqual(data["username"], username)
                    self.assertEqual(data["expires_in"], 3600)
                    decoded = signing.loads(data["token"], salt=views.GADGET_TOKEN_SALT, max_age=3600)
                    self.assertEqual(decoded, {"u": username, "scope": "gadget"})

            group_only_denied_cases = (
                (
                    "GroupOnlySteward",
                    ["user"],
                    ["read", "delete"],
                    {"global_groups": ["steward"], "global_rights": ["read"], "merged_projects": []},
                ),
                (
                    "GroupOnlyLocalSysop",
                    ["sysop", "temporary-account-viewer"],
                    ["read", "block"],
                    {
                        "global_groups": [],
                        "global_rights": [],
                        "merged_projects": [{"wiki": "enwiki", "url": "https://en.wikipedia.org", "groups": ["sysop"]}],
                    },
                ),
            )
            for username, local_groups, local_rights, rights_payload in group_only_denied_cases:
                with self.subTest(denied_username=username):
                    userinfo_stub = {
                        "username": username,
                        "local_groups": local_groups,
                        "rights": local_rights,
                        "centralids": {},
                        "domain": "zh.wiktionary.org",
                    }
                    with (
                        patch(
                            "detector.views.verify_centralauth_userinfo",
                            new_callable=AsyncMock,
                            return_value=userinfo_stub,
                        ),
                        patch(
                            "detector.views.fetch_user_rights_from_meta",
                            new_callable=AsyncMock,
                            return_value=rights_payload,
                        ),
                        patch(
                            "detector.views.fetch_project_user_rights",
                            new_callable=AsyncMock,
                            return_value=["read", "block"],
                        ),
                    ):
                        denied_resp = self.client.post(
                            "/api/v1/auth/gadget-token",
                            data=json.dumps({"centralauthtoken": "valid-cat", "domain": "zh.wiktionary.org"}),
                            content_type="application/json",
                            HTTP_ORIGIN="https://zh.wiktionary.org",
                        )
                    self.assertEqual(denied_resp.status_code, 403)

        allowlisted_userinfo = {
            "username": "allowlisted Tester",
            "local_groups": ["*", "user"],
            "rights": [],
            "centralids": {},
            "domain": "zh.wikipedia.org",
        }
        with (
            override_settings(ALLOWED_WIKI_USERS="Allowlisted_Tester"),
            patch(
                "detector.views.verify_centralauth_userinfo", new_callable=AsyncMock, return_value=allowlisted_userinfo
            ),
            patch("detector.views.fetch_user_rights_from_meta", new_callable=AsyncMock) as mock_fetch,
        ):
            allow_resp = self.client.post(
                "/api/v1/auth/gadget-token",
                data=json.dumps({"centralauthtoken": "valid-cat", "domain": "zh.wikipedia.org"}),
                content_type="application/json",
                HTTP_ORIGIN="https://zh.wikipedia.org",
            )
        self.assertEqual(allow_resp.status_code, 200)
        mock_fetch.assert_not_called()
        self.assertEqual(allow_resp.json()["username"], "allowlisted Tester")

    def test_merged_project_rights_lookup_prioritises_sysop_and_edit_count(self):
        merged_projects = [
            {"wiki": "enwiki", "url": "https://en.wikipedia.org", "editcount": 9000, "groups": []},
            {"wiki": "frwiki", "url": "https://fr.wikipedia.org", "editcount": 500, "groups": ["user"]},
            {"wiki": "dewiki", "url": "https://de.wikipedia.org", "editcount": 10, "groups": ["sysop"]},
            {"wiki": "eswiki", "url": "https://es.wikipedia.org", "editcount": 100, "groups": ["sysop"]},
            {"wiki": "itwiki", "url": "https://it.wikipedia.org", "editcount": 1000, "groups": ["user"]},
            {"wiki": "jawiki", "url": "https://ja.wikipedia.org", "editcount": 9999},
        ]
        queried_domains = []

        async def record_lookup(_client, _username, domain):
            queried_domains.append(domain)
            return []

        with patch("detector.views.fetch_project_user_rights", side_effect=record_lookup):
            enriched = asyncio.run(
                views._populate_merged_project_rights(
                    MagicMock(),
                    "ExampleUser",
                    merged_projects,
                    checked_domains=set(),
                )
            )

        self.assertEqual(
            queried_domains,
            [
                "es.wikipedia.org",
                "de.wikipedia.org",
                "it.wikipedia.org",
                "fr.wikipedia.org",
            ],
        )
        self.assertNotIn("en.wikipedia.org", queried_domains)
        self.assertNotIn("ja.wikipedia.org", queried_domains)
        self.assertEqual(len(enriched), len(merged_projects))

    def test_detect_ip_bearer_token_authentication_and_tamper_resistance(self):
        self._patch_all_providers()
        with patch("detector.views.redis_client", None):
            steward_userinfo = {
                "username": "Steward",
                "local_groups": ["*", "user"],
                "rights": [],
                "centralids": {},
                "domain": "zh.wikipedia.org",
            }
            with (
                patch(
                    "detector.views.verify_centralauth_userinfo", new_callable=AsyncMock, return_value=steward_userinfo
                ),
                patch(
                    "detector.views.fetch_user_rights_from_meta",
                    new_callable=AsyncMock,
                    return_value={
                        "global_groups": ["steward"],
                        "global_rights": ["checkuser-temporary-account-no-preference"],
                        "merged_projects": [],
                    },
                ),
            ):
                exchange_resp = self.client.post(
                    "/api/v1/auth/gadget-token",
                    data=json.dumps({"centralauthtoken": "exchange-cat", "domain": "zh.wikipedia.org"}),
                    content_type="application/json",
                    HTTP_ORIGIN="https://zh.wikipedia.org",
                )
            self.assertEqual(exchange_resp.status_code, 200)
            bearer_token = exchange_resp.json()["token"]

            detect_resp = self.client.get(
                "/api/v1/detect?ip=8.8.8.8",
                HTTP_ORIGIN="https://zh.wikipedia.org",
                HTTP_AUTHORIZATION=f"Bearer {bearer_token}",
            )
            self.assertEqual(detect_resp.status_code, 200)
            self.assertEqual(detect_resp.headers.get("Access-Control-Allow-Origin"), "https://zh.wikipedia.org")
            self.assertEqual(detect_resp.json()["ip"], "8.8.8.8")

            tampered_token = f"{bearer_token[:-1]}{'A' if bearer_token[-1] != 'A' else 'B'}"
            wrong_scope_token = signing.dumps({"u": "GlobalSteward", "scope": "web"}, salt=views.GADGET_TOKEN_SALT)
            wrong_salt_token = signing.dumps({"u": "GlobalSteward", "scope": "gadget"}, salt="different.salt")
            missing_user_token = signing.dumps({"u": "   ", "scope": "gadget"}, salt=views.GADGET_TOKEN_SALT)

            invalid_headers = (
                "Basic dXNlcjpwYXNz",
                "Bearer ",
                "Bearer not-a-signed-token",
                f"Bearer {tampered_token}",
                f"Bearer {wrong_scope_token}",
                f"Bearer {wrong_salt_token}",
                f"Bearer {missing_user_token}",
            )
            for auth_value in invalid_headers:
                with self.subTest(auth_header=auth_value[:32]):
                    bad_resp = self.client.get(
                        "/api/v1/detect?ip=8.8.8.8",
                        HTTP_ORIGIN="https://zh.wikipedia.org",
                        HTTP_AUTHORIZATION=auth_value,
                    )
                    self.assertEqual(bad_resp.status_code, 401)
                    self.assertEqual(
                        bad_resp.headers.get("Access-Control-Allow-Origin"),
                        "https://zh.wikipedia.org",
                    )

            with (
                override_settings(GADGET_TOKEN_TTL_SECONDS=10),
                patch("detector.views.signing.loads", side_effect=signing.SignatureExpired("Signature expired")),
            ):
                expired_resp = self.client.get(
                    "/api/v1/detect?ip=8.8.8.8",
                    HTTP_ORIGIN="https://zh.wikipedia.org",
                    HTTP_AUTHORIZATION=f"Bearer {bearer_token}",
                )
            self.assertEqual(expired_resp.status_code, 401)
            self.assertIn("expired", expired_resp.json()["error"].lower())

    def test_gadget_bearer_token_rejects_temporary_accounts_and_enforces_restricted_allowlist(self):
        self._patch_all_providers()
        self.assertEqual(views.DEFAULT_GADGET_TOKEN_TTL_SECONDS, 3600)

        with patch("detector.views.redis_client", None):
            for temp_username in ("~2026-12345", " ~2026-99999 "):
                temp_token = views.issue_gadget_token(temp_username)
                verified_user, verified_err = views._verify_gadget_bearer_token(f"Bearer {temp_token}")
                self.assertIsNone(verified_user)
                self.assertEqual(verified_err, "Invalid authentication token.")

                with override_settings(
                    RESTRICT_TO_ALLOWED_WIKI_USERS=True,
                    ALLOWED_WIKI_USERS="~2026-12345, ~2026-99999",
                ):
                    temp_resp = self.client.get(
                        "/api/v1/detect?ip=8.8.8.8",
                        HTTP_ORIGIN="https://zh.wikipedia.org",
                        HTTP_AUTHORIZATION=f"Bearer {temp_token}",
                    )
                self.assertEqual(temp_resp.status_code, 401)

            steward_userinfo = {
                "username": "StewardOperator",
                "local_groups": ["*", "user"],
                "rights": [],
                "centralids": {},
                "domain": "zh.wikipedia.org",
            }
            with (
                patch(
                    "detector.views.verify_centralauth_userinfo",
                    new_callable=AsyncMock,
                    return_value=steward_userinfo,
                ),
                patch(
                    "detector.views.fetch_user_rights_from_meta",
                    new_callable=AsyncMock,
                    return_value={
                        "global_groups": ["steward"],
                        "global_rights": ["checkuser-temporary-account"],
                        "merged_projects": [],
                    },
                ),
            ):
                exchange_resp = self.client.post(
                    "/api/v1/auth/gadget-token",
                    data=json.dumps({"centralauthtoken": "valid-cat", "domain": "zh.wikipedia.org"}),
                    content_type="application/json",
                    HTTP_ORIGIN="https://zh.wikipedia.org",
                )
            self.assertEqual(exchange_resp.status_code, 200)
            steward_token = exchange_resp.json()["token"]
            self.assertEqual(exchange_resp.json()["expires_in"], 3600)

            with (
                override_settings(
                    RESTRICT_TO_ALLOWED_WIKI_USERS=True,
                    ALLOWED_WIKI_USERS="Allowlisted_Operator",
                ),
                patch.dict(os.environ, {"ALLOWED_WIKI_USERS": "Allowlisted_Operator"}),
            ):
                denied_detect = self.client.get(
                    "/api/v1/detect?ip=8.8.8.8",
                    HTTP_ORIGIN="https://zh.wikipedia.org",
                    HTTP_AUTHORIZATION=f"Bearer {steward_token}",
                )
                self.assertEqual(denied_detect.status_code, 403)
                self.assertEqual(
                    denied_detect.json(),
                    {"error": "Access denied. Insufficient Wikimedia user rights."},
                )
                self.assertEqual(
                    denied_detect.headers.get("Access-Control-Allow-Origin"),
                    "https://zh.wikipedia.org",
                )

                denied_batch = self.client.post(
                    "/api/v1/detect/batch",
                    data=json.dumps({"ips": ["8.8.8.8"]}),
                    content_type="application/json",
                    HTTP_ORIGIN="https://zh.wikipedia.org",
                    HTTP_AUTHORIZATION=f"Bearer {steward_token}",
                )
                self.assertEqual(denied_batch.status_code, 403)
                self.assertEqual(
                    denied_batch.json(),
                    {"error": "Access denied. Insufficient Wikimedia user rights."},
                )

                allowlisted_token = views.issue_gadget_token("allowlisted_Operator")
                allowed_detect = self.client.get(
                    "/api/v1/detect?ip=8.8.8.8",
                    HTTP_ORIGIN="https://zh.wikipedia.org",
                    HTTP_AUTHORIZATION=f"Bearer {allowlisted_token}",
                )
                self.assertEqual(allowed_detect.status_code, 200)
                self.assertEqual(allowed_detect.json()["ip"], "8.8.8.8")

    def test_unified_rbac_evaluator_and_oauth_callback_parity(self):
        required_rights = (
            "checkuser-temporary-account",
            "checkuser-temporary-account-no-preference",
        )
        for right in required_rights:
            has_global, global_label, _, _ = evaluate_wikimedia_rights({"global_rights": [right]})
            self.assertTrue(has_global, msg=f"Expected access for global right {right}")
            self.assertIn(right, global_label)

            has_local, local_label, _, _ = evaluate_wikimedia_rights({"local_rights": [f"  {right.upper()}  "]})
            self.assertTrue(has_local, msg=f"Expected access for local right {right}")
            self.assertIn(right, local_label)

            has_legacy_key, _, _, _ = evaluate_wikimedia_rights({"rights": [right]})
            self.assertTrue(has_legacy_key, msg=f"Expected access for rights key {right}")

            has_project, project_label, _, _ = evaluate_wikimedia_rights(
                {"merged_projects": [{"wiki": "jawiki", "rights": [right]}]}
            )
            self.assertTrue(has_project, msg=f"Expected access for project right {right}")
            self.assertIn("jawiki", project_label)

        for group in (
            "steward",
            "global-sysop",
            "global-rollbacker",
            "global-temporary-account-viewer",
            "ombuds",
            "staff",
        ):
            has_access, _, _, _ = evaluate_wikimedia_rights({"global_groups": [group]})
            self.assertFalse(has_access, msg=f"Group {group} alone must not grant access without required rights")

        for local_group in (
            "sysop",
            "administrator",
            "checkuser",
            "arbcom",
            "oversight",
            "suppress",
            "temporary-account-viewer",
            "checkuser-temporary-account-viewer",
        ):
            has_access, _, _, _ = evaluate_wikimedia_rights({"local_groups": [local_group]})
            self.assertFalse(has_access, msg=f"Local group {local_group} alone must not grant access")

            has_merged_group, _, _, _ = evaluate_wikimedia_rights(
                {"merged_projects": [{"wiki": "zhwiki", "groups": [local_group]}]}
            )
            self.assertFalse(
                has_merged_group,
                msg=f"Merged project group {local_group} alone must not grant access without required rights",
            )

        denied, _, _, _ = evaluate_wikimedia_rights({"username": "PlainUser", "local_groups": ["*", "user"]})
        self.assertFalse(denied)

        with override_settings(ALLOWED_WIKI_USERS="~2026-12345"):
            temp_denied, _, _, _ = evaluate_wikimedia_rights(
                {
                    "username": "~2026-12345",
                    "local_rights": ["checkuser-temporary-account"],
                }
            )
            self.assertFalse(temp_denied)

        with override_settings(ALLOWED_WIKI_USERS="Allowlisted_Operator"):
            allowed, role_label, _, _ = evaluate_wikimedia_rights({"username": "allowlisted Operator"})
            self.assertTrue(allowed)
            self.assertEqual(role_label, "Allowlisted Wikimedia User")

        session = self.client.session
        session["oauth_state"] = "state-allowlist"
        session.save()

        token_resp = MagicMock(status_code=200)
        token_resp.json.return_value = {"access_token": "oauth-access-token"}
        profile_resp = MagicMock(status_code=200)
        profile_resp.json.return_value = {"username": "allowlisted Operator", "groups": ["user"]}

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=token_resp)
        mock_client.get = AsyncMock(return_value=profile_resp)

        with (
            override_settings(
                WIKIMEDIA_CLIENT_ID="test-id",
                WIKIMEDIA_CLIENT_SECRET="test-secret",
                ALLOWED_WIKI_USERS="Allowlisted_Operator",
            ),
            patch("detector.views.httpx.AsyncClient", return_value=mock_client),
            patch("detector.views.fetch_user_rights_from_meta", new_callable=AsyncMock) as mock_meta_fetch,
        ):
            callback_resp = self.client.get("/api/v1/auth/callback?code=abc&state=state-allowlist")

        self.assertEqual(callback_resp.status_code, 302)
        mock_meta_fetch.assert_not_called()
        user_session = self.client.session.get("wikimedia_user")
        self.assertIsInstance(user_session, dict)
        self.assertTrue(user_session["hasAccess"])
        self.assertEqual(user_session["role"], "Allowlisted Wikimedia User")

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test-id",
        WIKIMEDIA_CLIENT_SECRET="test-secret",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/oauth/callback",
    )
    def test_oauth_callback_and_gadget_parity_for_cross_wiki_sysop_taiv_and_temp_accounts(self):
        cross_wiki_cases = (
            (
                "CrossWikiTaAccess",
                "jawiki",
                "https://ja.wikipedia.org",
                "checkuser-temporary-account",
                "Temporary Account Access (jawiki: checkuser-temporary-account)",
            ),
            (
                "CrossWikiNoPrefAccess",
                "frwikisource",
                "https://fr.wikisource.org",
                "checkuser-temporary-account-no-preference",
                "Temporary Account Access (frwikisource: checkuser-temporary-account-no-preference)",
            ),
        )

        for username, project_wiki, project_url, granted_right, expected_role in cross_wiki_cases:
            with self.subTest(username=username, right=granted_right):
                session = self.client.session
                session["oauth_state"] = f"state-{username}"
                session.pop("wikimedia_user", None)
                session.save()

                token_resp = MagicMock(status_code=200)
                token_resp.json.return_value = {"access_token": f"token-{username}"}
                profile_resp = MagicMock(status_code=200)
                profile_resp.json.return_value = {"username": username, "groups": ["*", "user"], "rights": ["read"]}

                project_users_resp = MagicMock(status_code=200)
                project_users_resp.json.return_value = {
                    "query": {"users": [{"name": username, "rights": ["read", granted_right]}]}
                }

                async def _mock_get(
                    url, *_args, target_profile=profile_resp, target_users=project_users_resp, **_kwargs
                ):
                    if "/oauth2/resource/profile" in url:
                        return target_profile
                    return target_users

                mock_client = MagicMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock(return_value=token_resp)
                mock_client.get = AsyncMock(side_effect=_mock_get)

                meta_rights = {
                    "global_groups": [],
                    "global_rights": [],
                    "merged_projects": [{"wiki": project_wiki, "url": project_url, "groups": ["sysop"]}],
                }

                with (
                    patch("detector.views.httpx.AsyncClient", return_value=mock_client),
                    patch(
                        "detector.views.fetch_user_rights_from_meta", new_callable=AsyncMock, return_value=meta_rights
                    ),
                ):
                    oauth_resp = self.client.get(f"/api/v1/auth/callback?code=code1&state=state-{username}")

                self.assertEqual(oauth_resp.status_code, 302)
                user_session = self.client.session.get("wikimedia_user")
                self.assertIsInstance(user_session, dict)
                self.assertTrue(user_session["hasAccess"])
                self.assertEqual(user_session["role"], expected_role)

                userinfo_stub = {
                    "username": username,
                    "local_groups": ["*", "user"],
                    "rights": ["read"],
                    "centralids": {},
                    "domain": "commons.wikimedia.org",
                }
                with (
                    patch(
                        "detector.views.verify_centralauth_userinfo", new_callable=AsyncMock, return_value=userinfo_stub
                    ),
                    patch(
                        "detector.views.fetch_user_rights_from_meta", new_callable=AsyncMock, return_value=meta_rights
                    ),
                    patch(
                        "detector.views.fetch_project_user_rights",
                        new_callable=AsyncMock,
                        return_value=["read", granted_right],
                    ),
                ):
                    gadget_resp = self.client.post(
                        "/api/v1/auth/gadget-token",
                        data=json.dumps({"centralauthtoken": "valid-cat", "domain": "commons.wikimedia.org"}),
                        content_type="application/json",
                        HTTP_ORIGIN="https://commons.wikimedia.org",
                    )

                self.assertEqual(gadget_resp.status_code, 200)
                self.assertEqual(gadget_resp.json()["username"], username)

        # Verify Meta-Wiki local right fallback on transient globaluserinfo error matches gadget behavior
        session = self.client.session
        session["oauth_state"] = "state-local-fallback"
        session.pop("wikimedia_user", None)
        session.save()

        token_resp = MagicMock(status_code=200)
        token_resp.json.return_value = {"access_token": "token-local"}
        profile_resp = MagicMock(status_code=200)
        profile_resp.json.return_value = {
            "username": "MetaTaivUser",
            "groups": ["*"],
            "rights": ["read", "checkuser-temporary-account"],
        }
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=token_resp)
        mock_client.get = AsyncMock(return_value=profile_resp)

        with (
            patch("detector.views.httpx.AsyncClient", return_value=mock_client),
            patch(
                "detector.views.fetch_user_rights_from_meta",
                new_callable=AsyncMock,
                side_effect=MetaWikiRightsFetchError("Meta-Wiki HTTP 503"),
            ),
        ):
            fallback_resp = self.client.get("/api/v1/auth/callback?code=code2&state=state-local-fallback")

        self.assertEqual(fallback_resp.status_code, 302)
        fallback_session = self.client.session.get("wikimedia_user")
        self.assertIsInstance(fallback_session, dict)
        self.assertTrue(fallback_session["hasAccess"])
        self.assertEqual(fallback_session["role"], "Temporary Account Access (local: checkuser-temporary-account)")

        # Verify group-only members without the required rights are denied on both OAuth and gadget
        session = self.client.session
        session["oauth_state"] = "state-group-only-denied"
        session.pop("wikimedia_user", None)
        session.save()

        denied_profile_resp = MagicMock(status_code=200)
        denied_profile_resp.json.return_value = {
            "username": "GroupOnlySysop",
            "groups": ["sysop", "temporary-account-viewer"],
            "rights": ["read", "delete"],
        }
        mock_client.get = AsyncMock(return_value=denied_profile_resp)
        denied_meta_rights = {
            "global_groups": ["steward", "global-sysop"],
            "global_rights": ["read", "block"],
            "merged_projects": [{"wiki": "zhwiki", "url": "https://zh.wikipedia.org", "groups": ["sysop"]}],
        }
        with (
            patch("detector.views.httpx.AsyncClient", return_value=mock_client),
            patch(
                "detector.views.fetch_user_rights_from_meta", new_callable=AsyncMock, return_value=denied_meta_rights
            ),
            patch("detector.views.fetch_project_user_rights", new_callable=AsyncMock, return_value=["read", "delete"]),
        ):
            denied_oauth_resp = self.client.get("/api/v1/auth/callback?code=code2b&state=state-group-only-denied")

        self.assertEqual(denied_oauth_resp.status_code, 302)
        denied_session = self.client.session.get("wikimedia_user")
        self.assertIsInstance(denied_session, dict)
        self.assertFalse(denied_session["hasAccess"])

        denied_userinfo = {
            "username": "GroupOnlySysop",
            "local_groups": ["sysop", "temporary-account-viewer"],
            "rights": ["read", "delete"],
            "centralids": {},
            "domain": "zh.wikipedia.org",
        }
        with (
            patch("detector.views.verify_centralauth_userinfo", new_callable=AsyncMock, return_value=denied_userinfo),
            patch(
                "detector.views.fetch_user_rights_from_meta", new_callable=AsyncMock, return_value=denied_meta_rights
            ),
            patch("detector.views.fetch_project_user_rights", new_callable=AsyncMock, return_value=["read", "delete"]),
        ):
            denied_gadget_resp = self.client.post(
                "/api/v1/auth/gadget-token",
                data=json.dumps({"centralauthtoken": "valid-cat", "domain": "zh.wikipedia.org"}),
                content_type="application/json",
                HTTP_ORIGIN="https://zh.wikipedia.org",
            )
        self.assertEqual(denied_gadget_resp.status_code, 403)

        # Verify temporary accounts are rejected via OAuth even if allowlisted
        session = self.client.session
        session["oauth_state"] = "state-temp-acct"
        session.pop("wikimedia_user", None)
        session.save()

        temp_profile_resp = MagicMock(status_code=200)
        temp_profile_resp.json.return_value = {"username": "~2026-12345", "groups": ["*"]}
        mock_client.get = AsyncMock(return_value=temp_profile_resp)

        with (
            override_settings(ALLOWED_WIKI_USERS="~2026-12345"),
            patch("detector.views.httpx.AsyncClient", return_value=mock_client),
            patch("detector.views.fetch_user_rights_from_meta", new_callable=AsyncMock) as mock_temp_meta,
        ):
            temp_resp = self.client.get("/api/v1/auth/callback?code=code3&state=state-temp-acct")

        self.assertEqual(temp_resp.status_code, 302)
        mock_temp_meta.assert_not_called()
        self.assertIsNone(self.client.session.get("wikimedia_user"))

    def test_post_method_returns_405_with_cors_headers(self):
        resp = self.client.post(
            "/api/v1/detect?ip=8.8.8.8",
            HTTP_ORIGIN="https://zh.wikipedia.org",
        )
        self.assertEqual(resp.status_code, 405)
        self.assertEqual(resp.headers.get("Access-Control-Allow-Origin"), "https://zh.wikipedia.org")


class NonPublicIpInterceptionTests(TestCase):
    """Tests early 200 OK interception for loopback, private, link-local, multicast and reserved IPs."""

    def setUp(self):
        _login_authorised(self)

    def test_canonicalize_ip_strips_valid_ipv6_zone_ids_and_rejects_malformed_zones(self):
        self.assertEqual(views.canonicalize_ip("fe80::1%eth0"), "fe80::1")
        self.assertEqual(views.canonicalize_ip("  FE80:0:0:0:0:0:0:0001%ens33  "), "fe80::1")
        self.assertEqual(views.canonicalize_ip("fe80::1%enp0s3"), "fe80::1")

        for malformed in ("fe80::1%", "fe80::1%eth 0", "fe80::1%eth0%eth1", "127.0.0.1%eth0", "fe80::1%eth/0"):
            with self.subTest(malformed=malformed):
                self.assertIsNone(views.canonicalize_ip(malformed))

    @patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock)
    @patch("detector.views.query_maxmind", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
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

        with patch("detector.views.redis_client", mock_redis):
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
        for bad_ip in ("fe80::1%25", "fe80::1%", "127.0.0.1%eth0"):
            with self.subTest(bad_ip=bad_ip):
                resp = self.client.get(f"/api/v1/detect?ip={bad_ip}")
                self.assertEqual(resp.status_code, 400)
                self.assertEqual(resp.json()["error"], "invalid_ip")


class SingleflightCoalescingTests(TestCase):
    """Tests singleflight coalescing of concurrent uncached IP detection requests."""

    def tearDown(self):
        views._ip_detect_inflight.clear()
        views._http_client_instance = None
        views._http_client_loop = None

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

        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.set = AsyncMock()
        auth_headers = {"Authorization": f"Bearer {views.issue_gadget_token('SysopUser')}"}
        factory = AsyncRequestFactory()
        requests = [factory.get("/api/v1/detect?ip=8.8.4.4", headers=auth_headers) for _ in range(5)]

        with (
            patch("detector.views.redis_client", mock_redis),
            patch("detector.views.query_maxmind", AsyncMock(return_value=dict(MAXMIND_STUB))),
            patch("detector.views.query_rdns_ptr", side_effect=_fake_dns),
            patch("detector.views.query_cloudflare_radar", side_effect=_make_slow_ok("Cloudflare Radar")),
            patch("detector.views.query_abuseipdb", side_effect=_make_slow_ok("AbuseIPDB")),
            patch("detector.views.query_ipdata", side_effect=_make_slow_ok("IPData")),
            patch("detector.views.query_ipregistry", side_effect=_make_slow_ok("IPRegistry")),
            patch("detector.views.query_ip2location", side_effect=_make_slow_ok("IP2Location")),
            patch("detector.views.query_getipintel", side_effect=_make_slow_ok("GetIPIntel")),
            patch("detector.views.query_proxycheck", side_effect=_make_slow_ok("Proxycheck")),
            patch("detector.views.query_iphub", side_effect=_make_slow_ok("IPHub")),
            patch("detector.views.query_iphunter", side_effect=_make_slow_ok("IPHunter")),
            patch("detector.views.query_tor_onionoo", side_effect=_make_slow_ok("Tor Onionoo")),
            patch("detector.views.query_stopforumspam", side_effect=_make_slow_ok("StopForumSpam")),
            patch("detector.views.query_dshield", side_effect=_make_slow_ok("DShield")),
        ):
            mock_client = AsyncMock()
            mock_client.is_closed = False
            with patch("detector.views._get_shared_http_client", AsyncMock(return_value=mock_client)):
                responses = await asyncio.gather(*(views.detect_ip(req) for req in requests))

        self.assertEqual(len(responses), 5)
        for resp in responses:
            self.assertEqual(resp.status_code, 200)
            payload = json.loads(resp.content)
            self.assertEqual(payload["ip"], "8.8.4.4")
            self.assertEqual(payload["ptrHostname"], "dns.google")

        self.assertEqual(provider_calls["count"], 1)
        self.assertEqual(dns_calls["count"], 1)
        self.assertEqual(len(views._ip_detect_inflight), 0)

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
            patch("detector.views.redis_client", None),
            patch("detector.views._get_shared_http_client", AsyncMock(return_value=mock_client)),
            patch("detector.views.query_maxmind", AsyncMock(return_value=dict(MAXMIND_STUB))),
            patch("detector.views.query_rdns_ptr", AsyncMock(return_value=None)),
            patch("detector.views.query_cloudflare_radar", side_effect=_make_gated_provider("Cloudflare Radar")),
            patch("detector.views.query_abuseipdb", side_effect=_make_gated_provider("AbuseIPDB")),
            patch("detector.views.query_ipdata", side_effect=_make_gated_provider("IPData")),
            patch("detector.views.query_ipregistry", side_effect=_make_gated_provider("IPRegistry")),
            patch("detector.views.query_ip2location", side_effect=_make_gated_provider("IP2Location")),
            patch("detector.views.query_getipintel", side_effect=_make_gated_provider("GetIPIntel")),
            patch("detector.views.query_proxycheck", side_effect=_make_gated_provider("Proxycheck")),
            patch("detector.views.query_iphub", side_effect=_make_gated_provider("IPHub")),
            patch("detector.views.query_iphunter", side_effect=_make_gated_provider("IPHunter")),
            patch("detector.views.query_tor_onionoo", side_effect=_make_gated_provider("Tor Onionoo")),
            patch("detector.views.query_stopforumspam", side_effect=_make_gated_provider("StopForumSpam")),
            patch("detector.views.query_dshield", side_effect=_make_gated_provider("DShield")),
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
        self.assertEqual(len(views._ip_detect_inflight), 0)

    async def test_inflight_map_cleaned_up_on_unexpected_exception(self):
        auth_headers = {"Authorization": f"Bearer {views.issue_gadget_token('SysopUser')}"}

        with (
            patch("detector.views.redis_client", None),
            patch("detector.views._execute_detection_with_cache", AsyncMock(side_effect=RuntimeError("boom"))),
        ):
            with self.assertRaises(RuntimeError):
                await self.async_client.get("/api/v1/detect?ip=8.8.4.4", headers=auth_headers)

        self.assertEqual(len(views._ip_detect_inflight), 0)

    async def test_five_concurrent_requests_read_provider_caches_once(self):
        cache_reads = {"count": 0}
        detection_runs = {"count": 0}

        async def _slow_cache_read(ip):
            cache_reads["count"] += 1
            # Yield long enough for every other request to reach the singleflight check
            await asyncio.sleep(0.03)
            return {}, ("dns.google", "2026-01-01T00:00:00+00:00")

        async def _fake_detection(ip, *, initial_cache=None, query_mode="full"):
            detection_runs["count"] += 1
            self.assertEqual(initial_cache, ({}, ("dns.google", "2026-01-01T00:00:00+00:00")))
            return {
                "ip": ip,
                "ptrHostname": "dns.google",
                "queryMode": query_mode,
                "results": [],
                "cacheMeta": {"status": "hit"},
            }

        auth_headers = {"Authorization": f"Bearer {views.issue_gadget_token('SysopUser')}"}
        factory = AsyncRequestFactory()
        requests = [factory.get("/api/v1/detect?ip=8.8.4.4", headers=auth_headers) for _ in range(5)]

        with (
            patch("detector.views._read_provider_caches", side_effect=_slow_cache_read),
            patch("detector.views._execute_detection_with_cache", side_effect=_fake_detection),
            patch("detector.views.record_global_request_telemetry", AsyncMock()),
        ):
            responses = await asyncio.gather(*(views.detect_ip(req) for req in requests))

        self.assertEqual(cache_reads["count"], 1)
        self.assertEqual(detection_runs["count"], 1)
        for resp in responses:
            self.assertEqual(resp.status_code, 200)
            payload = json.loads(resp.content)
            self.assertEqual(payload["ip"], "8.8.4.4")
            self.assertIn("durationSeconds", payload)
        self.assertEqual(len(views._ip_detect_inflight), 0)

    async def test_concurrent_waiters_receive_independent_payload_copies(self):
        shared_payload = {"ip": "8.8.4.4", "results": [], "cacheMeta": {"status": "miss"}}

        async def _slow_cache_read(ip):
            await asyncio.sleep(0.02)
            return {}, None

        with (
            patch("detector.views._read_provider_caches", side_effect=_slow_cache_read),
            patch("detector.views._execute_detection_with_cache", AsyncMock(return_value=shared_payload)),
            patch("detector.views.record_global_request_telemetry", AsyncMock()),
        ):
            payloads = await asyncio.gather(
                *(views._detect_single_canonical_ip("8.8.4.4", "gadget", time.perf_counter()) for _ in range(5))
            )

        self.assertEqual(len({id(payload) for payload in payloads}), 5)
        for payload in payloads:
            self.assertIsNot(payload, shared_payload)
            self.assertIn("durationSeconds", payload)
        self.assertNotIn("durationSeconds", shared_payload)
        self.assertEqual(len(views._ip_detect_inflight), 0)


class PerProviderCacheAndCircuitBreakerTests(TestCase):
    """Tests per-provider tiered TTL caching and HTTP 429 or 5xx cooldown circuit breaking."""

    def setUp(self):
        _login_authorised(self)

    def tearDown(self):
        views._http_client_instance = None
        views._http_client_loop = None

    def test_retry_after_header_parsed_and_clamped_within_cooldown_bounds(self):
        self.assertEqual(views._parse_retry_after_seconds("15"), 60)
        self.assertEqual(views._parse_retry_after_seconds("180"), 180)
        self.assertEqual(views._parse_retry_after_seconds("999"), 300)
        self.assertEqual(views._parse_retry_after_seconds("Wed, 21 Oct 2015 07:28:00 GMT"), 120)
        self.assertEqual(views._parse_retry_after_seconds(None), 120)

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
    @patch("detector.views.query_maxmind", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
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
        cache_store = {
            "proxycheck:v1:prov:proxycheck:1.1.1.1": historical_proxycheck_1111,
        }
        written_ttls = {}
        requested_urls = []

        async def _fake_get(key):
            return cache_store.get(key)

        async def _fake_set(key, val, ex=None):
            cache_store[key] = val
            written_ttls[key] = ex

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
            patch("detector.views.redis_client", mock_redis),
        ):
            first_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")

        self.assertEqual(first_resp.status_code, 200)
        first_payload = first_resp.json()
        first_rows = {row["provider"]: row for row in first_payload["results"]}
        self.assertEqual(first_rows["Proxycheck"]["statusCode"], 429)
        self.assertIn("proxycheck:v1:cooldown:proxycheck", cache_store)
        self.assertEqual(written_ttls["proxycheck:v1:cooldown:proxycheck"], 180)
        self.assertNotIn("proxycheck:v1:prov:proxycheck:8.8.8.8", cache_store)
        self.assertEqual(cache_store["proxycheck:v1:prov:proxycheck:1.1.1.1"], historical_proxycheck_1111)

        for healthy_key in (
            "cloudflare_radar",
            "abuseipdb",
            "ipdata",
            "ipregistry",
            "ip2location",
            "iphub",
            "iphunter",
        ):
            self.assertIn(f"proxycheck:v1:prov:{healthy_key}:8.8.8.8", cache_store)
            self.assertEqual(written_ttls[f"proxycheck:v1:prov:{healthy_key}:8.8.8.8"], 86400)
        self.assertIn("proxycheck:v1:prov:getipintel:8.8.8.8", cache_store)
        self.assertEqual(written_ttls["proxycheck:v1:prov:getipintel:8.8.8.8"], 259200)
        self.assertEqual(written_ttls["proxycheck:v1:prov:ptr:8.8.8.8"], 7200)

        requested_urls.clear()
        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.views.redis_client", mock_redis),
        ):
            second_resp = self.client.get("/api/v1/detect?ip=9.9.9.9")

        self.assertEqual(second_resp.status_code, 200)
        self.assertFalse(any("proxycheck.io" in u for u in requested_urls))
        second_rows = {row["provider"]: row for row in second_resp.json()["results"]}
        self.assertTrue(second_rows["Proxycheck"].get("isCooldown"))
        self.assertIn("429 Cooldown", second_rows["Proxycheck"]["status"])
        self.assertIn("proxycheck:v1:prov:cloudflare_radar:9.9.9.9", cache_store)

        requested_urls.clear()
        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.views.redis_client", mock_redis),
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
    @patch("detector.views.query_maxmind", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
    def test_timeout_triggers_default_cooldown_and_respects_ttl_settings(
        self, mock_async_client_cls, mock_mm, _mock_dns
    ):
        mock_mm.return_value = dict(MAXMIND_STUB)
        cache_store = {}
        written_ttls = {}

        async def _fake_get(key):
            return cache_store.get(key)

        async def _fake_set(key, val, ex=None):
            cache_store[key] = val
            written_ttls[key] = ex

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
            patch("detector.views.redis_client", mock_redis),
        ):
            resp = self.client.get("/api/v1/detect?ip=8.8.8.8")
            self.assertEqual(views._get_provider_cache_ttl("dnsbl"), 1800)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(written_ttls.get("proxycheck:v1:cooldown:proxycheck"), 120)
        self.assertNotIn("proxycheck:v1:prov:proxycheck:8.8.8.8", cache_store)
        self.assertEqual(written_ttls.get("proxycheck:v1:prov:ptr:8.8.8.8"), 1800)
        self.assertEqual(written_ttls.get("proxycheck:v1:prov:cloudflare_radar:8.8.8.8"), 43200)

    def test_getipintel_stable_scores_extend_cache_ttl(self):
        stable_low_row = views.adapt_getipintel({"status": "success", "result": "0.05"}, True, 200)
        stable_high_row = views.adapt_getipintel({"status": "success", "result": "0.95"}, True, 200)
        uncertain_row = views.adapt_getipintel({"status": "success", "result": "0.50"}, True, 200)

        self.assertEqual(views._get_provider_cache_ttl("getipintel", stable_low_row), 259200)
        self.assertEqual(views._get_provider_cache_ttl("getipintel", stable_high_row), 259200)
        self.assertEqual(views._get_provider_cache_ttl("getipintel", uncertain_row), 86400)
        self.assertEqual(views._get_provider_cache_ttl("getipintel"), 86400)

        with override_settings(PROVIDER_STATIC_CACHE_TTL_SECONDS=86400, GETIPINTEL_STABLE_CACHE_TTL_SECONDS=604800):
            self.assertEqual(views._get_provider_cache_ttl("getipintel", stable_low_row), 604800)
            self.assertEqual(views._get_provider_cache_ttl("getipintel", uncertain_row), 86400)


class HttpClientLifecycleTests(TestCase):
    """Tests shared httpx.AsyncClient connection pool limits and safe cleanup across loops."""

    def tearDown(self):
        views._http_client_instance = None
        views._http_client_loop = None

    async def test_shared_http_client_configures_explicit_connection_limits(self):
        views._http_client_instance = None
        views._http_client_loop = None
        client = await views._get_shared_http_client()
        try:
            self.assertEqual(views._DEFAULT_HTTP_LIMITS.max_connections, 100)
            self.assertEqual(views._DEFAULT_HTTP_LIMITS.max_keepalive_connections, 20)
            pool_limits = client._transport._pool
            self.assertEqual(pool_limits._max_connections, 100)
            self.assertEqual(pool_limits._max_keepalive_connections, 20)
        finally:
            await views._close_http_client_safely(client)

    async def test_rebuilding_shared_client_safely_closes_stale_instance_when_aclose_raises(self):
        stale_client = MagicMock()
        stale_client.is_closed = False
        stale_client.aclose = AsyncMock(side_effect=RuntimeError("Event loop is closed"))
        views._http_client_instance = stale_client
        views._http_client_loop = object()

        fresh_client = await views._get_shared_http_client()
        try:
            stale_client.aclose.assert_awaited_once()
            self.assertIsNot(fresh_client, stale_client)
            self.assertIsInstance(fresh_client, httpx.AsyncClient)
            self.assertFalse(fresh_client.is_closed)
        finally:
            await views._close_http_client_safely(fresh_client)

    async def test_cookieless_http_client_enforces_empty_cookie_policy_and_strips_request_cookies(self):
        captured_cookie_headers = []

        def _handler(request: httpx.Request) -> httpx.Response:
            captured_cookie_headers.append(request.headers.get("cookie"))
            return httpx.Response(
                200,
                headers=[("Set-Cookie", "centralauth_Session=leak; Domain=.wikipedia.org; Path=/")],
                json={"ok": True},
            )

        client = views._build_cookieless_http_client()
        try:
            self.assertEqual(client.cookies.jar._policy.allowed_domains(), ())
            client._transport = httpx.MockTransport(_handler)

            await client.get("https://zh.wikipedia.org/w/api.php", headers={"Cookie": "injected=1"})
            await client.get("https://meta.wikimedia.org/w/api.php")

            self.assertEqual(len(client.cookies), 0)
            self.assertEqual(captured_cookie_headers, [None, None])
        finally:
            await views._close_http_client_safely(client)

    def test_clear_client_cookies_skips_empty_cookies_and_supports_mocks(self):
        empty_client = SimpleNamespace(cookies=httpx.Cookies())
        with patch.object(empty_client.cookies.jar, "clear", wraps=empty_client.cookies.jar.clear) as spy_jar_clear:
            _clear_client_cookies(empty_client)
            spy_jar_clear.assert_not_called()

        populated_client = SimpleNamespace(cookies=httpx.Cookies({"GeoIP": "US"}))
        _clear_client_cookies(populated_client)
        self.assertEqual(len(populated_client.cookies), 0)

        mock_method_client = SimpleNamespace(cookies=httpx.Cookies())
        with patch.object(mock_method_client.cookies, "clear") as mock_clear:
            _clear_client_cookies(mock_method_client)
            mock_clear.assert_called_once()

        magic_client = MagicMock()
        _clear_client_cookies(magic_client)
        magic_client.cookies.clear.assert_called_once()

        with warnings.catch_warnings(record=True) as recorded_warnings:
            warnings.simplefilter("always")
            _clear_client_cookies(None)
            _clear_client_cookies(SimpleNamespace(cookies=None))
            _clear_client_cookies(AsyncMock())

        runtime_warnings = [w for w in recorded_warnings if issubclass(w.category, RuntimeWarning)]
        self.assertEqual(runtime_warnings, [])

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

        client = views._build_cookieless_http_client()
        try:
            client._transport = httpx.MockTransport(_handler)
            with patch.object(client.cookies.jar, "clear", wraps=client.cookies.jar.clear) as spy_jar_clear:
                userinfo, meta_rights, project_rights = await asyncio.gather(
                    verify_centralauth_userinfo(client, "valid-token", wiki_domain="zh.wikipedia.org"),
                    fetch_user_rights_from_meta(client, "StewardUser"),
                    fetch_project_user_rights(client, "StewardUser", "zh.wikipedia.org"),
                )

            spy_jar_clear.assert_not_called()
            self.assertEqual(len(client.cookies), 0)
            self.assertEqual(userinfo["username"], "StewardUser")
            self.assertEqual(meta_rights["global_groups"], ["steward"])
            self.assertEqual(project_rights, ["checkuser-temporary-account"])
            self.assertEqual(len(captured_requests), 3)
            for _url, cookie_hdr, ua_hdr in captured_requests:
                self.assertIsNone(cookie_hdr)
                self.assertIn("ProxyCheck/1.0", ua_hdr or "")
        finally:
            await views._close_http_client_safely(client)


class AsyncDnsAndDnsblTests(TestCase):
    """Tests asynchronous PTR lookups and IPv4-only DNSBL integrations via dnspython."""

    def setUp(self):
        _login_authorised(self)

    def tearDown(self):
        views._http_client_instance = None
        views._http_client_loop = None

    async def test_async_ptr_success_nxdomain_and_resolver_timeouts(self):
        with override_settings(DNS_QUERY_TIMEOUT_SECONDS=1.5, DNS_QUERY_LIFETIME_SECONDS=3.0):
            resolver = views._create_async_resolver()
            self.assertEqual(resolver.timeout, 1.5)
            self.assertEqual(resolver.lifetime, 3.0)

        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            return_value=_mock_ptr_answer("DNS.GOOGLE."),
        ) as mock_resolve:
            state = {"status": "ok"}
            token = views._rdns_context_state.set(state)
            try:
                v4_host = await views.query_rdns_ptr("8.8.8.8")
                v6_host = await views.query_rdns_ptr("2001:4860:4860::8888")
            finally:
                views._rdns_context_state.reset(token)

        self.assertEqual(v4_host, "dns.google")
        self.assertEqual(v6_host, "dns.google")
        self.assertEqual(state["status"], "ok")
        self.assertEqual(mock_resolve.await_count, 2)
        self.assertEqual(
            mock_resolve.await_args_list[0].args,
            (dns.reversename.from_address("8.8.8.8"), "PTR"),
        )
        self.assertEqual(
            mock_resolve.await_args_list[1].args,
            (dns.reversename.from_address("2001:4860:4860::8888"), "PTR"),
        )

        for label, exc, expected_status in (
            ("nxdomain", dns.resolver.NXDOMAIN(), "nxdomain"),
            ("noanswer", dns.resolver.NoAnswer(), "nxdomain"),
            ("timeout", dns.exception.Timeout("DNS timed out"), "timeout"),
            ("nonameservers", dns.resolver.NoNameservers(), "error"),
        ):
            with self.subTest(case=label):
                err_state = {"status": "ok"}
                token = views._rdns_context_state.set(err_state)
                try:
                    with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock, side_effect=exc):
                        res = await views.query_rdns_ptr("1.2.3.4")
                finally:
                    views._rdns_context_state.reset(token)
                self.assertIsNone(res)
                self.assertEqual(err_state["status"], expected_status)

    async def test_spamhaus_zen_sbl_css_xbl_pbl_nxdomain_and_query_blocked(self):
        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            return_value=_mock_a_answer("127.0.0.2"),
        ) as mock_resolve:
            sbl_row = await views.query_spamhaus_zen("1.2.3.4")

        mock_resolve.assert_awaited_once_with("4.3.2.1.zen.spamhaus.org", "A")
        self.assertEqual(sbl_row["status"], "200 OK")
        self.assertTrue(sbl_row["isListed"])
        self.assertIn("SBL", sbl_row["usageType"])
        self.assertTrue(any(flag["isHighRisk"] and "SBL" in flag["label"] for flag in sbl_row["securityFlags"]))

        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            return_value=_mock_a_answer("127.0.0.3", "127.0.0.4"),
        ):
            combo_row = await views.query_spamhaus_zen("1.2.3.4")
        self.assertEqual(combo_row["status"], "200 OK")
        self.assertTrue(combo_row["isListed"])
        self.assertIn("CSS", combo_row["usageType"])
        self.assertIn("XBL/CBL", combo_row["usageType"])
        self.assertTrue(any(flag["isHighRisk"] and "CSS" in flag["label"] for flag in combo_row["securityFlags"]))
        self.assertTrue(any(flag["isHighRisk"] and "XBL" in flag["label"] for flag in combo_row["securityFlags"]))

        for pbl_code in ("127.0.0.10", "127.0.0.11"):
            with self.subTest(pbl_code=pbl_code):
                with patch(
                    "dns.asyncresolver.Resolver.resolve",
                    new_callable=AsyncMock,
                    return_value=_mock_a_answer(pbl_code),
                ):
                    pbl_row = await views.query_spamhaus_zen("1.2.3.4")
                self.assertEqual(pbl_row["status"], "200 OK")
                self.assertTrue(pbl_row["isPolicyRange"])
                self.assertIn("Policy/Dynamic ISP Range", pbl_row["usageType"])
                self.assertFalse(any(flag["isHighRisk"] for flag in pbl_row["securityFlags"]))

        for restricted_code in ("127.255.255.254", "127.255.255.255"):
            with self.subTest(restricted_code=restricted_code):
                with patch(
                    "dns.asyncresolver.Resolver.resolve",
                    new_callable=AsyncMock,
                    return_value=_mock_a_answer(restricted_code),
                ):
                    blocked_row = await views.query_spamhaus_zen("1.2.3.4")
                self.assertFalse(blocked_row["isListed"])
                self.assertTrue(blocked_row.get("isQueryRestricted"))
                self.assertEqual(blocked_row["statusCode"], 429)
                self.assertEqual(blocked_row["status"], "429 Query Blocked")
                self.assertIn(restricted_code, blocked_row["usageType"])
                self.assertFalse(any(flag["isHighRisk"] for flag in blocked_row["securityFlags"]))

        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        ):
            clean_row = await views.query_spamhaus_zen("1.2.3.4")
        self.assertEqual(clean_row["status"], "200 OK")
        self.assertFalse(clean_row["isListed"])
        self.assertEqual(clean_row["usageType"], "Clean (Not Listed)")

    async def test_spamcop_listed_and_nxdomain_clean(self):
        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            return_value=_mock_a_answer("127.0.0.2"),
        ) as mock_resolve:
            listed_row = await views.query_spamcop("192.0.2.55")

        mock_resolve.assert_awaited_once_with("55.2.0.192.bl.spamcop.net", "A")
        self.assertEqual(listed_row["status"], "200 OK")
        self.assertTrue(listed_row["isListed"])
        self.assertEqual(listed_row["listedCodes"], ["127.0.0.2"])
        self.assertTrue(any(flag["isHighRisk"] for flag in listed_row["securityFlags"]))

        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        ):
            clean_row = await views.query_spamcop("192.0.2.55")
        self.assertEqual(clean_row["status"], "200 OK")
        self.assertFalse(clean_row["isListed"])
        self.assertEqual(clean_row["usageType"], "Clean (Not Listed)")

    def test_ipv6_target_skips_dnsbl_queries_without_dns_requests(self):
        dns_queries = []

        async def _record_dns(qname, rdtype="A", *_args, **_kwargs):
            dns_queries.append((str(qname), str(rdtype)))
            raise dns.resolver.NXDOMAIN()

        with (
            patch("detector.views.redis_client", None),
            patch("detector.views.query_maxmind", AsyncMock(return_value=dict(MAXMIND_STUB))),
            patch("detector.views.httpx.AsyncClient") as mock_async_client_cls,
            patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock, side_effect=_record_dns),
        ):
            _patch_async_client(
                mock_async_client_cls,
                AsyncMock(return_value=_mock_response(status_code=200, json_value={"status": "ok"})),
            )
            with override_settings(**EMPTY_UPSTREAM_SECRETS), patch.dict(os.environ, EMPTY_UPSTREAM_SECRETS):
                resp = self.client.get("/api/v1/detect?ip=2001:4860:4860::8888")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(dns_queries), 1)
        self.assertEqual(dns_queries[0][1], "PTR")
        self.assertTrue(dns_queries[0][0].endswith("ip6.arpa."))

        rows_by_provider = {row["provider"]: row for row in resp.json()["results"]}
        for dnsbl_name in ("Spamhaus ZEN", "SpamCop"):
            self.assertEqual(rows_by_provider[dnsbl_name]["status"], "Skipped (IPv6)")
            self.assertIsNone(rows_by_provider[dnsbl_name]["statusCode"])
            self.assertTrue(rows_by_provider[dnsbl_name].get("isSkippedIpv6"))
            self.assertIn("IPv6", rows_by_provider[dnsbl_name]["usageType"])

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
    def test_detect_endpoint_preserves_commercial_arbitration_and_handles_spamhaus_block(
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
        def _clean_commercial(name):
            return {
                "provider": name,
                "status": "200 OK",
                "statusCode": 200,
                "asn": "AS15169",
                "isp": "Example Residential ISP",
                "organisation": "Example Residential ISP",
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
        ):
            m.return_value = _clean_commercial(name)
        mock_tor.return_value = adapt_tor_onionoo({"relays": []}, 200, "1.2.3.4")
        mock_sfs.return_value = adapt_stopforumspam(
            {"success": 1, "ip": {"appears": 0, "frequency": 0, "confidence": 0.0}}, 200
        )
        mock_dshield.return_value = adapt_dshield({"ip": {"attacks": 0, "count": 0}}, 200)
        mock_mm.return_value = dict(MAXMIND_STUB)

        cache_store = {}
        written_ttls = {}

        async def _fake_get(key):
            return cache_store.get(key)

        async def _fake_set(key, val, ex=None):
            cache_store[key] = val
            written_ttls[key] = ex

        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(side_effect=_fake_get)
        mock_redis.set = AsyncMock(side_effect=_fake_set)

        async def _listed_dns_side_effect(qname, rdtype="A", *_args, **_kwargs):
            qtext = str(qname)
            if str(rdtype).upper() == "PTR":
                raise dns.resolver.NXDOMAIN()
            if qtext == "4.3.2.1.zen.spamhaus.org":
                return _mock_a_answer("127.0.0.2")
            if qtext == "4.3.2.1.bl.spamcop.net":
                return _mock_a_answer("127.0.0.2")
            raise dns.resolver.NXDOMAIN()

        with (
            patch("detector.views.redis_client", mock_redis),
            patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock, side_effect=_listed_dns_side_effect),
        ):
            resp = self.client.get("/api/v1/detect?ip=1.2.3.4")

        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["arbitrationVerdict"], "Clean Residential / Direct (0/8 Sources)")
        self.assertEqual(payload["arbitrationTier"], "success")

        rows = {row["provider"]: row for row in payload["results"]}
        self.assertTrue(rows["Spamhaus ZEN"]["isListed"])
        self.assertIn("SBL (127.0.0.2)", rows["Spamhaus ZEN"]["usageType"])
        self.assertTrue(rows["SpamCop"]["isListed"])

        self.assertEqual(written_ttls.get("proxycheck:v1:prov:spamhaus_zen:1.2.3.4"), 7200)
        self.assertEqual(written_ttls.get("proxycheck:v1:prov:spamcop:1.2.3.4"), 7200)

        cache_store.clear()
        written_ttls.clear()

        async def _blocked_spamhaus_side_effect(qname, rdtype="A", *_args, **_kwargs):
            qtext = str(qname)
            if str(rdtype).upper() == "PTR":
                raise dns.resolver.NXDOMAIN()
            if qtext == "5.6.7.8.zen.spamhaus.org":
                return _mock_a_answer("127.255.255.254")
            raise dns.resolver.NXDOMAIN()

        with (
            patch("detector.views.redis_client", mock_redis),
            patch(
                "dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock, side_effect=_blocked_spamhaus_side_effect
            ),
        ):
            blocked_resp = self.client.get("/api/v1/detect?ip=8.7.6.5")

        self.assertEqual(blocked_resp.status_code, 200)
        blocked_rows = {row["provider"]: row for row in blocked_resp.json()["results"]}
        self.assertEqual(blocked_rows["Spamhaus ZEN"]["status"], "429 Query Blocked")
        self.assertFalse(blocked_rows["Spamhaus ZEN"]["isListed"])
        self.assertNotIn("proxycheck:v1:prov:spamhaus_zen:8.7.6.5", cache_store)
        self.assertEqual(written_ttls.get("proxycheck:v1:cooldown:spamhaus_zen"), 120)
        self.assertEqual(written_ttls.get("proxycheck:v1:prov:spamcop:8.7.6.5"), 7200)


class OsintFeedsAndProxycheckExtensionsTests(TestCase):
    """Tests for Proxycheck extended parameters, Tor Onionoo, StopForumSpam, and DShield feeds."""

    def setUp(self):
        views._http_client_instance = None
        views._http_client_loop = None
        _login_authorised(self)

    def tearDown(self):
        views._http_client_instance = None
        views._http_client_loop = None

    def test_query_proxycheck_attaches_extended_flags_and_extracts_port_and_last_seen(self):
        captured = {}

        async def _get(url, **kwargs):
            captured["url"] = url
            return _mock_response(
                status_code=200,
                json_value={
                    "status": "ok",
                    "198.51.100.20": {
                        "network": {"asn": "14061", "provider": "DigitalOcean", "type": "Hosting"},
                        "location": {"country_name": "United States", "country_code": "US"},
                        "detections": {"proxy": True, "vpn": False, "tor": False, "hosting": True, "risk": 82},
                        "port": 1080,
                        "last_seen_human": "2 hours ago",
                    },
                },
            )

        client = AsyncMock()
        client.get.side_effect = _get

        with override_settings(**TEST_UPSTREAM_SECRETS), patch.dict(os.environ, TEST_UPSTREAM_SECRETS):
            result = asyncio.run(views.query_proxycheck(client, "198.51.100.20"))

        parsed = urlparse(captured["url"])
        qs = parse_qs(parsed.query)
        self.assertEqual(qs.get("vpn"), ["1"])
        self.assertEqual(qs.get("port"), ["1"])
        self.assertEqual(qs.get("seen"), ["1"])
        self.assertEqual(qs.get("risk"), ["1"])
        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(result["port"], 1080)
        self.assertEqual(result["lastSeen"], "2 hours ago")
        self.assertEqual(result["riskScore"], 82)

        unix_adapted = adapt_proxycheck(
            {
                "status": "ok",
                "198.51.100.21": {
                    "type": "Proxy",
                    "proxy": "yes",
                    "detections": {"port": "9050"},
                    "seen": 1700000000,
                },
            },
            True,
            200,
            "198.51.100.21",
        )
        self.assertEqual(unix_adapted["port"], 9050)
        self.assertEqual(unix_adapted["lastSeen"], "2023-11-14T22:13:20+00:00")

    def test_tor_onionoo_adapter_verifies_exact_ip_and_role_flags(self):
        exit_res = adapt_tor_onionoo(
            {
                "relays": [
                    {
                        "a": ["185.220.101.4", "[2a0b:f4c2:2::4]:9001"],
                        "exit_addresses": ["185.220.101.4"],
                        "r": True,
                        "flags": ["Exit", "Fast", "Running", "Valid"],
                    }
                ]
            },
            status_code=200,
            ip="185.220.101.4",
        )
        self.assertTrue(exit_res["isTor"])
        self.assertTrue(exit_res["torIsExit"])
        self.assertTrue(exit_res["torRunning"])
        self.assertEqual(exit_res["torLabel"], "Tor Exit")
        self.assertTrue(any(flag["isHighRisk"] for flag in exit_res["securityFlags"]))
        self.assertIn("Exit", exit_res["torFlags"])

        guard_v6 = adapt_tor_onionoo(
            {
                "relays": [
                    {
                        "or_addresses": ["[2a0b:f4c2:0002::4]:9001"],
                        "running": True,
                        "flags": ["Guard", "Running"],
                    }
                ]
            },
            status_code=200,
            ip="2a0b:f4c2:2::4",
        )
        self.assertTrue(guard_v6["isTor"])
        self.assertFalse(guard_v6["torIsExit"])
        self.assertTrue(guard_v6["torRunning"])
        self.assertEqual(guard_v6["torLabel"], "Tor Guard")

        prefix_miss = adapt_tor_onionoo(
            {
                "relays": [
                    {"a": ["185.220.101.99"], "r": True, "flags": ["Exit"]},
                ]
            },
            status_code=200,
            ip="185.220.101.4",
        )
        self.assertFalse(prefix_miss["isTor"])

        offline_relay = adapt_tor_onionoo(
            {
                "relays": [
                    {"a": ["185.220.101.4"], "r": False, "flags": ["Exit", "Stable"]},
                ]
            },
            status_code=200,
            ip="185.220.101.4",
        )
        self.assertFalse(offline_relay["isTor"])
        self.assertFalse(offline_relay["torRunning"])

        inferred_offline = adapt_tor_onionoo(
            {
                "relays": [
                    {"a": ["185.220.101.4"], "flags": ["Exit", "Stable"]},
                ]
            },
            status_code=200,
            ip="185.220.101.4",
        )
        self.assertFalse(inferred_offline["isTor"])
        self.assertFalse(inferred_offline["torRunning"])

        inferred_running = adapt_tor_onionoo(
            {
                "relays": [
                    {"a": ["185.220.101.4"], "flags": ["Exit", "Running"]},
                ]
            },
            status_code=200,
            ip="185.220.101.4",
        )
        self.assertTrue(inferred_running["isTor"])
        self.assertTrue(inferred_running["torRunning"])

        empty_relays = adapt_tor_onionoo({"relays": []}, status_code=200, ip="8.8.8.8")
        self.assertFalse(empty_relays["isTor"])
        self.assertEqual(empty_relays["usageType"], "Not a Tor Node")

        captured = {}

        async def _get(url, **kwargs):
            captured["url"] = url
            return _mock_response(status_code=200, json_value={"relays": []})

        client = AsyncMock()
        client.get.side_effect = _get
        queried = asyncio.run(views.query_tor_onionoo(client, "8.8.8.8"))
        self.assertEqual(captured["url"], "https://onionoo.torproject.org/summary?search=8.8.8.8")
        self.assertFalse(queried["isTor"])

    def test_stopforumspam_adapter_and_query_extract_reputation_metrics(self):
        listed = adapt_stopforumspam(
            {
                "success": 1,
                "ip": {
                    "appears": 1,
                    "frequency": 14,
                    "confidence": 92.4,
                    "lastseen": "2026-11-10 12:00:00",
                },
            },
            status_code=200,
        )
        self.assertEqual(listed["status"], "200 OK")
        self.assertTrue(listed["appears"])
        self.assertEqual(listed["frequency"], 14)
        self.assertEqual(listed["confidence"], 92.4)
        self.assertEqual(listed["lastSeen"], "2026-11-10 12:00:00")
        self.assertIsNone(listed.get("countryCode"))

        clean = adapt_stopforumspam(
            {"success": 1, "ip": {"appears": 0, "frequency": 0, "confidence": 0.0}},
            status_code=200,
        )
        self.assertFalse(clean["appears"])
        self.assertEqual(clean["frequency"], 0)

        api_err = adapt_stopforumspam({"success": 0, "error": "rate limit"}, status_code=200)
        self.assertEqual(api_err["status"], "400 Error")

        from detector import offline_dbs

        with tempfile.TemporaryDirectory() as tmp_dir:
            toxic_file = Path(tmp_dir) / "toxic_ip_cidr.txt"
            toxic_file.write_text("198.51.100.0/24\n", encoding="utf-8")
            offline_dbs.clear_stopforumspam_caches()
            with override_settings(STOPFORUMSPAM_DB_DIR=tmp_dir):
                hit_row = asyncio.run(views.query_stopforumspam(None, "198.51.100.5"))
                clean_row = asyncio.run(views.query_stopforumspam(None, "203.0.113.5"))
            offline_dbs.clear_stopforumspam_caches()

        self.assertEqual(hit_row["status"], "200 OK")
        self.assertTrue(hit_row["blacklisted"])
        self.assertTrue(hit_row["appears"])
        self.assertEqual(hit_row["toxicCidr"], "198.51.100.0/24")
        self.assertEqual(clean_row["status"], "200 OK")
        self.assertFalse(clean_row["appears"])

        with tempfile.TemporaryDirectory() as empty_dir:
            offline_dbs.clear_stopforumspam_caches()
            with override_settings(STOPFORUMSPAM_DB_DIR=empty_dir):
                missing_row = asyncio.run(views.query_stopforumspam(None, "198.51.100.5"))
            offline_dbs.clear_stopforumspam_caches()
        self.assertEqual(missing_row["status"], "Offline DB Missing")
        self.assertIsNone(missing_row["statusCode"])

    def test_dshield_adapter_and_query_extract_attack_and_threatfeed_metrics(self):
        listed = adapt_dshield(
            {
                "ip": {
                    "attacks": 42,
                    "count": 7,
                    "maxdate": "2026-11-11",
                    "threatfeeds": {"scanner": {"lastseen": "2026-11-12"}, "sshbruteforce": {}},
                    "as": 14061,
                    "asname": "DigitalOcean",
                    "ascountry": "US",
                }
            },
            status_code=200,
        )
        self.assertEqual(listed["status"], "200 OK")
        self.assertEqual(listed["attacks"], 42)
        self.assertEqual(listed["count"], 7)
        self.assertEqual(listed["maxDate"], "2026-11-11")
        self.assertEqual(listed["lastSeen"], "2026-11-11")
        self.assertIn("scanner", listed["threatfeeds"])
        self.assertIn("sshbruteforce", listed["threatfeeds"])
        self.assertEqual(listed["asn"], "AS14061")
        self.assertIsNone(listed.get("countryCode"))

        clean = adapt_dshield({"ip": {"attacks": 0, "count": 0, "threatfeeds": []}}, status_code=200)
        self.assertEqual(clean["usageType"], "Clean (No Activity)")

        null_metrics = adapt_dshield(
            {"ip": {"number": "198.51.100.5", "count": None, "attacks": None, "maxrisk": None}},
            status_code=200,
        )
        self.assertEqual(null_metrics["status"], "200 OK")
        self.assertEqual(null_metrics["attacks"], 0)
        self.assertEqual(null_metrics["count"], 0)
        self.assertEqual(null_metrics["usageType"], "Clean (No Activity)")

        captured = {}

        async def _get(url, **kwargs):
            captured["url"] = url
            captured["headers"] = kwargs.get("headers") or {}
            captured["follow_redirects"] = kwargs.get("follow_redirects")
            captured["timeout"] = kwargs.get("timeout")
            return _mock_response(status_code=200, json_value={"ip": {"attacks": 0, "count": 0}})

        client = AsyncMock()
        client.get.side_effect = _get
        asyncio.run(views.query_dshield(client, "198.51.100.5"))
        self.assertEqual(captured["url"], "https://isc.sans.edu/api/ip/198.51.100.5?json")
        self.assertIn("ProxyCheck", captured["headers"].get("User-Agent", ""))
        self.assertTrue(captured["follow_redirects"])
        self.assertEqual(captured["timeout"], 10.0)

    def test_dshield_retries_fallback_and_isolates_follow_redirects(self):
        # Verify the shared HTTP client and unrelated providers keep redirects disabled by default
        shared_client = asyncio.run(views._get_shared_http_client())
        self.assertFalse(shared_client.follow_redirects)

        default_capture = {}

        async def _default_get(url, **kwargs):
            default_capture["follow_redirects"] = kwargs.get("follow_redirects")
            default_capture["has_timeout_kwarg"] = "timeout" in kwargs
            default_capture["timeout"] = kwargs.get("timeout")
            return _mock_response(status_code=200, json_value={"relays": []})

        default_client = AsyncMock()
        default_client.get.side_effect = _default_get
        asyncio.run(views.query_tor_onionoo(default_client, "198.51.100.5"))
        self.assertFalse(default_capture["follow_redirects"])
        self.assertTrue(default_capture["has_timeout_kwarg"])
        self.assertEqual(default_capture["timeout"], 5.0)

        # Calling _fetch_upstream_json without timeout lets the client default timeout apply
        asyncio.run(
            views._fetch_upstream_json(
                default_client,
                "dshield",
                "DShield",
                "https://isc.sans.edu/api/ip/198.51.100.5?json",
            )
        )
        self.assertFalse(default_capture["has_timeout_kwarg"])

        # Passing an explicit httpx.Timeout overrides the client default timeout
        custom_timeout = httpx.Timeout(12.0)
        asyncio.run(
            views._fetch_upstream_json(
                default_client,
                "dshield",
                "DShield",
                "https://isc.sans.edu/api/ip/198.51.100.5?json",
                timeout=custom_timeout,
            )
        )
        self.assertTrue(default_capture["has_timeout_kwarg"])
        self.assertIs(default_capture["timeout"], custom_timeout)

        failure_modes = (
            ("network_error", httpx.ConnectError("connection reset")),
            ("http_503", _mock_response(status_code=503, text="<html>Service Unavailable</html>")),
            ("http_504", _mock_response(status_code=504, text="<html>Gateway Timeout</html>")),
            (
                "non_json_200",
                _mock_response(
                    status_code=200,
                    json_error=json.JSONDecodeError("Expecting value", "<html>proxy error</html>", 0),
                    text="<html>proxy error</html>",
                ),
            ),
        )
        for label, primary_outcome in failure_modes:
            with self.subTest(case=label):
                if not isinstance(primary_outcome, Exception):
                    primary_outcome.headers = {"Content-Type": "text/html"}
                attempted = []
                upstream_events = {}
                token = views._provider_upstream_events.set(upstream_events)

                async def _fallback_get(url, outcome=primary_outcome, captured_urls=attempted, **kwargs):
                    captured_urls.append((url, kwargs.get("follow_redirects"), kwargs.get("timeout")))
                    if "isc.sans.edu" in url:
                        if isinstance(outcome, Exception):
                            raise outcome
                        return outcome
                    return _mock_response(status_code=200, json_value={"ip": {"attacks": 3, "count": 1}})

                fallback_client = AsyncMock()
                fallback_client.get.side_effect = _fallback_get
                try:
                    with self.assertLogs("detector.views", level="WARNING") as captured_logs:
                        result = asyncio.run(views.query_dshield(fallback_client, "198.51.100.5"))
                finally:
                    views._provider_upstream_events.reset(token)

                self.assertEqual(result["status"], "200 OK")
                self.assertEqual(result["attacks"], 3)
                self.assertEqual(
                    attempted,
                    [
                        ("https://isc.sans.edu/api/ip/198.51.100.5?json", True, 10.0),
                        ("https://www.dshield.org/api/ip/198.51.100.5?json", True, 10.0),
                    ],
                )
                self.assertFalse(upstream_events["dshield"]["trigger"])
                self.assertTrue(any("retrying fallback endpoint" in line for line in captured_logs.output))

        # When both endpoints fail with gateway errors, DShield still degrades cleanly to 502 Error
        both_bad_client = AsyncMock()

        async def _both_bad(url, **kwargs):
            resp = _mock_response(
                status_code=200,
                json_error=json.JSONDecodeError("Expecting value", "<xml/>", 0),
                text="<xml>error</xml>",
            )
            resp.headers = {"Content-Type": "application/xml"}
            return resp

        both_bad_client.get.side_effect = _both_bad
        with self.assertLogs("detector.views", level="WARNING"):
            failed_result = asyncio.run(views.query_dshield(both_bad_client, "198.51.100.5"))
        self.assertEqual(failed_result["status"], "502 Error")

    def test_dshield_skips_fallback_on_timeout_slow_failure_or_non_gateway_status(self):
        # ReadTimeout on the primary endpoint must return immediately without hitting the fallback host
        timeout_urls = []
        upstream_events = {}
        token = views._provider_upstream_events.set(upstream_events)

        async def _timeout_get(url, **kwargs):
            timeout_urls.append((url, kwargs.get("timeout")))
            raise httpx.ReadTimeout("timed out after 10s")

        timeout_client = AsyncMock()
        timeout_client.get.side_effect = _timeout_get
        try:
            with self.assertLogs("detector.views", level="ERROR"):
                timeout_result = asyncio.run(views.query_dshield(timeout_client, "198.51.100.5"))
        finally:
            views._provider_upstream_events.reset(token)

        self.assertEqual(timeout_result["status"], "502 Error")
        self.assertEqual(timeout_urls, [("https://isc.sans.edu/api/ip/198.51.100.5?json", 10.0)])
        self.assertTrue(upstream_events["dshield"]["isTimeout"])

        # A primary error arriving after 5 seconds must also skip fallback to avoid doubling latency
        slow_error_urls = []

        async def _slow_error_get(url, **kwargs):
            slow_error_urls.append((url, kwargs.get("timeout")))
            return _mock_response(status_code=503, text="Slow gateway error")

        slow_error_client = AsyncMock()
        slow_error_client.get.side_effect = _slow_error_get
        with (
            patch.object(views, "time", SimpleNamespace(monotonic=MagicMock(side_effect=[100.0, 105.31]))),
            self.assertLogs("detector.views", level="WARNING"),
        ):
            slow_error_result = asyncio.run(views.query_dshield(slow_error_client, "198.51.100.5"))

        self.assertEqual(slow_error_result["status"], "503 Error")
        self.assertEqual(slow_error_urls, [("https://isc.sans.edu/api/ip/198.51.100.5?json", 10.0)])

        # A primary 200 response arriving after 5.31 seconds succeeds cleanly under the 10s budget
        slow_ok_urls = []

        async def _slow_ok_get(url, **kwargs):
            slow_ok_urls.append((url, kwargs.get("timeout")))
            return _mock_response(status_code=200, json_value={"ip": {"attacks": 0, "count": 0}})

        slow_ok_client = AsyncMock()
        slow_ok_client.get.side_effect = _slow_ok_get
        with patch.object(views, "time", SimpleNamespace(monotonic=MagicMock(side_effect=[200.0, 205.31]))):
            slow_ok_result = asyncio.run(views.query_dshield(slow_ok_client, "198.51.100.5"))

        self.assertEqual(slow_ok_result["status"], "200 OK")
        self.assertEqual(slow_ok_urls, [("https://isc.sans.edu/api/ip/198.51.100.5?json", 10.0)])

        # Non-gateway statuses such as HTTP 500 or HTTP 429 do not trigger fallback
        for status in (500, 429):
            with self.subTest(status=status):
                attempted = []

                async def _status_get(url, code=status, seen=attempted, **kwargs):
                    seen.append(url)
                    return _mock_response(status_code=code, text="error")

                status_client = AsyncMock()
                status_client.get.side_effect = _status_get
                with self.assertLogs("detector.views", level="WARNING"):
                    res = asyncio.run(views.query_dshield(status_client, "198.51.100.5"))
                self.assertEqual(len(attempted), 1)
                self.assertEqual(res["statusCode"], status)

    @patch(
        "dns.asyncresolver.Resolver.resolve",
        new_callable=AsyncMock,
        side_effect=dns.resolver.NXDOMAIN(),
    )
    @patch("detector.views.query_maxmind", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
    def test_detect_endpoint_excludes_tor_from_comparison_and_preserves_commercial_verdict_over_osint_hits(
        self, mock_async_client_cls, mock_mm, _mock_dns
    ):
        mock_mm.return_value = dict(MAXMIND_STUB)
        tor_active_mode = {"enabled": False}

        async def _respond(url, **kwargs):
            if "onionoo.torproject.org" in url:
                if tor_active_mode["enabled"]:
                    return _mock_response(
                        status_code=200,
                        json_value={
                            "relays": [
                                {
                                    "a": ["185.220.101.9"],
                                    "exit_addresses": ["185.220.101.9"],
                                    "r": True,
                                    "flags": ["Exit", "Fast", "Running"],
                                }
                            ]
                        },
                    )
                return _mock_response(status_code=200, json_value={"relays": []})
            if "stopforumspam.org" in url:
                return _mock_response(
                    status_code=200,
                    json_value={
                        "success": 1,
                        "ip": {"appears": 1, "frequency": 25, "confidence": 96.5, "lastseen": "2026-11-12 09:00:00"},
                    },
                )
            if "sans.edu" in url or "dshield" in url:
                return _mock_response(
                    status_code=200,
                    json_value={
                        "ip": {
                            "attacks": 80,
                            "count": 12,
                            "maxdate": "2026-11-12",
                            "threatfeeds": ["scanner"],
                            "ascountry": "DE",
                        }
                    },
                )
            if "proxycheck.io" in url:
                ip_part = urlparse(url).path.rsplit("/", 1)[-1]
                return _mock_response(
                    status_code=200,
                    json_value={
                        "status": "ok",
                        ip_part: {
                            "asn": "AS3320",
                            "provider": "Example Residential ISP",
                            "country": "United States",
                            "isocode": "US",
                            "type": "Residential",
                            "port": 9050,
                            "last_seen_human": "1 hour ago",
                        },
                    },
                )
            if "ipregistry.co" in url:
                return _mock_response(
                    status_code=200,
                    json_value={
                        "company": {"name": "Example Residential ISP"},
                        "connection": {"asn": 3320, "type": "isp"},
                        "location": {"country": {"name": "United States", "code": "US"}},
                        "security": {},
                    },
                )
            if "ip2location.io" in url:
                return _mock_response(
                    status_code=200,
                    json_value={
                        "asn": "3320",
                        "as": "Example Residential ISP",
                        "country_name": "United States",
                        "country_code": "US",
                    },
                )
            if "ipdata.co" in url:
                return _mock_response(
                    status_code=200,
                    json_value={
                        "asn": {"asn": "AS3320", "name": "Example Residential ISP", "type": "isp"},
                        "country_name": "United States",
                        "country_code": "US",
                        "threat": {},
                    },
                )
            if "abuseipdb.com" in url:
                return _mock_response(
                    status_code=200,
                    json_value={
                        "data": {"isp": "Example Residential ISP", "countryCode": "US", "abuseConfidenceScore": 0}
                    },
                )
            if "getipintel.net" in url:
                return _mock_response(status_code=200, json_value={"status": "success", "result": "0.0"})
            if "iphub.info" in url:
                return _mock_response(
                    status_code=200,
                    json_value={
                        "asn": 3320,
                        "isp": "Example Residential ISP",
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
                        "data": {
                            "isp": "Example Residential ISP",
                            "country_name": "United States",
                            "country_code": "US",
                            "block": 0,
                        },
                    },
                )
            return _mock_response(
                status_code=200,
                json_value={
                    "success": True,
                    "result": {
                        "location": {"countryName": "United States", "countryCode": "US"},
                        "asn": {"asn": 3320, "name": "Example Residential ISP"},
                    },
                },
            )

        _patch_async_client(mock_async_client_cls, _respond)

        cache_store = {}
        written_ttls = {}

        async def _fake_get(key):
            return cache_store.get(key)

        async def _fake_set(key, val, ex=None):
            cache_store[key] = val
            written_ttls[key] = ex

        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(side_effect=_fake_get)
        mock_redis.set = AsyncMock(side_effect=_fake_set)

        from detector import offline_dbs

        with tempfile.TemporaryDirectory() as sfs_tmp_dir:
            (Path(sfs_tmp_dir) / "listed_ip_90_ipv46_all.txt").write_text(
                '"185.220.101.4","25","2026-11-12 09:00:00"\n',
                encoding="utf-8",
            )
            offline_dbs.clear_stopforumspam_caches()

            with (
                override_settings(**{**TEST_UPSTREAM_SECRETS, "STOPFORUMSPAM_DB_DIR": sfs_tmp_dir}),
                patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
                patch("detector.views.redis_client", mock_redis),
            ):
                resp = self.client.get("/api/v1/detect?ip=185.220.101.4")

            self.assertEqual(resp.status_code, 200)
            payload = resp.json()
            self.assertFalse(payload["isTor"])
            self.assertFalse(payload["is_broadcast_ip"])
            self.assertFalse(payload["isMajorityProxyVpn"])
            self.assertEqual(payload["arbitrationVerdict"], "Clean Residential / Direct (0/8 Sources)")
            self.assertEqual(payload["arbitrationTier"], "success")

            rows = {row["provider"]: row for row in payload["results"]}
            self.assertNotIn("Tor Onionoo", rows)
            self.assertEqual(rows["Proxycheck"]["port"], 9050)
            self.assertEqual(rows["Proxycheck"]["lastSeen"], "1 hour ago")
            self.assertEqual(rows["StopForumSpam"]["frequency"], 25)
            self.assertEqual(rows["StopForumSpam"]["lastSeen"], "2026-11-12 09:00:00")
            self.assertEqual(rows["DShield"]["attacks"], 80)
            self.assertEqual(rows["DShield"]["threatfeeds"], ["scanner"])
            self.assertEqual(written_ttls.get("proxycheck:v1:prov:tor_onionoo:185.220.101.4"), 7200)
            self.assertEqual(written_ttls.get("proxycheck:v1:prov:stopforumspam:185.220.101.4"), 7200)
            self.assertEqual(written_ttls.get("proxycheck:v1:prov:dshield:185.220.101.4"), 7200)

            tor_active_mode["enabled"] = True
            with (
                override_settings(**{**TEST_UPSTREAM_SECRETS, "STOPFORUMSPAM_DB_DIR": sfs_tmp_dir}),
                patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
                patch("detector.views.redis_client", mock_redis),
            ):
                tor_resp = self.client.get("/api/v1/detect?ip=185.220.101.9")
            offline_dbs.clear_stopforumspam_caches()

        self.assertEqual(tor_resp.status_code, 200)
        tor_payload = tor_resp.json()
        self.assertTrue(tor_payload["isTor"])
        self.assertTrue(tor_payload["torIsExit"])
        self.assertTrue(tor_payload["torRunning"])
        self.assertEqual(tor_payload["torLabel"], "Tor Exit")
        self.assertIn("Exit", tor_payload["torFlags"])
        self.assertEqual(tor_payload["arbitrationTier"], "destructive")
        self.assertIn("Tor Exit", tor_payload["arbitrationVerdict"])
        self.assertNotIn("Tor Onionoo", {row["provider"] for row in tor_payload["results"]})


class LoopIsolationAndSessionSettingsTests(TestCase):
    """Tests per-loop Redis and HTTP client isolation, empty error logging, and Redis sessions."""

    def tearDown(self):
        views._http_client_instance = None
        views._http_client_loop = None
        with views._http_client_lock:
            views._http_clients_by_loop.clear()
        with views._redis_client_lock:
            views._redis_clients_by_loop.clear()
        views.reset_redis_circuit_breaker()

    def test_redis_client_reused_within_loop_and_isolated_across_closed_loops(self):
        created_clients = []

        def _make_fake_redis(*args, **kwargs):
            client = MagicMock(name=f"redis-{len(created_clients)}")
            created_clients.append((args, kwargs, client))
            return client

        async def _acquire_twice():
            first = views._get_redis_client()
            second = views._get_redis_client()
            self.assertIs(first, second)
            return first

        with patch.object(views.aioredis, "from_url", side_effect=_make_fake_redis):
            client_one = asyncio.run(_acquire_twice())
            client_two = asyncio.run(_acquire_twice())

        self.assertIsNot(client_one, client_two)
        self.assertEqual(len(created_clients), 2)

    def test_concurrent_open_loops_in_separate_threads_keep_distinct_clients(self):
        import concurrent.futures
        import threading

        barrier = threading.Barrier(2)
        results = []

        def _worker():
            async def _inner():
                redis_first = views._get_redis_client()
                http_first = await views._get_shared_http_client()
                barrier.wait(timeout=5)
                redis_second = views._get_redis_client()
                http_second = await views._get_shared_http_client()
                self.assertIs(redis_first, redis_second)
                self.assertIs(http_first, http_second)
                self.assertFalse(http_first.is_closed)
                await views._close_http_client_safely(http_first)
                return redis_first, http_first

            return asyncio.run(_inner())

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(_worker)
            f2 = pool.submit(_worker)
            results.append(f1.result(timeout=10))
            results.append(f2.result(timeout=10))

        self.assertIsNot(results[0][0], results[1][0])
        self.assertIsNot(results[0][1], results[1][1])

    async def test_fetch_upstream_json_logs_type_when_exception_message_is_empty(self):
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ReadTimeout("")

        with self.assertLogs("detector.views", level="ERROR") as captured_logs:
            payload, status_code = await views._fetch_upstream_json(
                mock_client,
                "dshield",
                "DShield",
                "https://www.dshield.org/api/ip/8.8.8.8?json",
            )

        self.assertEqual(status_code, 502)
        self.assertEqual(payload["status"], "error")
        self.assertIn("ReadTimeout", payload["message"])
        self.assertTrue(any("ReadTimeout" in line for line in captured_logs.output))

    async def test_fetch_upstream_json_warns_with_sanitized_preview_on_non_json_and_non_200(self):
        long_html = "<html><body>upstream failure key=secret_token_999 " + ("x" * 180) + "</body></html>"
        non_json_resp = _mock_response(
            status_code=200,
            json_error=json.JSONDecodeError("Expecting value", long_html, 0),
            text=long_html,
        )
        non_json_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        mock_client = AsyncMock()
        mock_client.get.return_value = non_json_resp

        with self.assertLogs("detector.views", level="WARNING") as warning_logs:
            payload, status_code = await views._fetch_upstream_json(
                mock_client,
                "dshield",
                "DShield",
                "https://isc.sans.edu/api/ip/8.8.8.8?json",
            )

        self.assertEqual(status_code, 502)
        self.assertEqual(payload["status"], "error")
        self.assertTrue(all(record.levelname == "WARNING" for record in warning_logs.records))
        warning_text = "\n".join(warning_logs.output)
        self.assertIn("JSONDecodeError", warning_text)
        self.assertIn("502", warning_text)
        self.assertIn("text/html; charset=utf-8", warning_text)
        self.assertIn("key=***REDACTED***", warning_text)
        self.assertNotIn("secret_token_999", warning_text)
        body_fragment = warning_logs.records[0].getMessage().split("body: ", 1)[1][:-1]
        self.assertLessEqual(len(body_fragment), 120)

        denied_resp = _mock_response(status_code=403, text="Forbidden by edge WAF")
        denied_resp.headers = {"Content-Type": "text/plain"}
        mock_client.get.return_value = denied_resp

        with self.assertLogs("detector.views", level="WARNING") as status_logs:
            _, denied_status = await views._fetch_upstream_json(
                mock_client,
                "dshield",
                "DShield",
                "https://isc.sans.edu/api/ip/8.8.8.8?json",
            )

        self.assertEqual(denied_status, 403)
        status_text = "\n".join(status_logs.output)
        self.assertIn("HTTP 403", status_text)
        self.assertIn("text/plain", status_text)
        self.assertIn("Forbidden by edge WAF", status_text)

    def test_session_engine_uses_cache_and_production_cache_uses_redis(self):
        from django.conf import settings as django_settings

        from proxycheck.settings import _build_default_cache_config

        self.assertEqual(django_settings.SESSION_ENGINE, "django.contrib.sessions.backends.cache")
        self.assertEqual(django_settings.SESSION_CACHE_ALIAS, "default")

        prod_cache = _build_default_cache_config(
            "redis://redis.svc.tools.eqiad1.wikimedia.cloud:6379/0",
            "proxycheck_prod_",
            is_test_run=False,
        )
        self.assertEqual(prod_cache["BACKEND"], "django.core.cache.backends.redis.RedisCache")
        self.assertEqual(prod_cache["LOCATION"], "redis://redis.svc.tools.eqiad1.wikimedia.cloud:6379/0")
        self.assertEqual(prod_cache["KEY_PREFIX"], "proxycheck_prod_")

    def test_collectstatic_does_not_require_secret_key(self):
        import subprocess

        env = {k: v for k, v in os.environ.items() if k != "DJANGO_SECRET_KEY"}
        env["DJANGO_DEBUG"] = "False"
        proc = subprocess.run(
            [sys.executable, "manage.py", "collectstatic", "--dry-run", "--noinput"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)

    def test_dotenv_and_mmdb_resolvers_support_tool_data_dir(self):
        import tempfile
        from pathlib import Path

        from proxycheck.settings import _resolve_dotenv_path

        with tempfile.TemporaryDirectory() as tmpdir:
            tool_root = Path(tmpdir) / "tool"
            python_dir = tool_root / "www" / "python"
            data_dir = python_dir / "data"
            data_dir.mkdir(parents=True)

            env_file = python_dir / ".env"
            env_file.write_text("DJANGO_DEBUG=False\n", encoding="utf-8")
            mmdb_file = data_dir / "GeoLite2-Country.mmdb"
            mmdb_file.write_bytes(b"")
            city_mmdb_file = data_dir / "GeoLite2-City.mmdb"
            city_mmdb_file.write_bytes(b"")

            resolved_env = _resolve_dotenv_path(Path(tmpdir) / "workspace", str(tool_root))
            self.assertEqual(resolved_env, env_file)

            with patch.dict(os.environ, {"TOOL_DATA_DIR": str(tool_root)}):
                resolved_db = views._resolve_db_file("", "GeoLite2-Country.mmdb", Path(tmpdir) / "workspace")
                resolved_city_db = views._resolve_db_file("", "GeoLite2-City.mmdb", Path(tmpdir) / "workspace")
            self.assertEqual(resolved_db, str(mmdb_file))
            self.assertEqual(resolved_city_db, str(city_mmdb_file))
            self.assertEqual(
                views._resolve_db_file(str(data_dir), "GeoLite2-Country.mmdb", Path(tmpdir) / "workspace"),
                str(mmdb_file),
            )
            self.assertEqual(
                views._resolve_db_file(str(data_dir), "GeoLite2-City.mmdb", Path(tmpdir) / "workspace"),
                str(city_mmdb_file),
            )
            self.assertEqual(
                views._resolve_db_file(str(data_dir), "GeoLite2-ASN.mmdb", Path(tmpdir) / "workspace"),
                str(data_dir / "GeoLite2-ASN.mmdb"),
            )
            missing_custom_dir = Path(tmpdir) / "absent_mmdb_dir"
            with patch.dict(os.environ, {"TOOL_DATA_DIR": str(tool_root)}):
                self.assertEqual(
                    views._resolve_db_file(
                        str(missing_custom_dir), "GeoLite2-Country.mmdb", Path(tmpdir) / "workspace"
                    ),
                    str(missing_custom_dir / "GeoLite2-Country.mmdb"),
                )

    def test_procfile_starts_asgi_gunicorn_without_runtime_collectstatic(self):
        from django.conf import settings as django_settings

        procfile_content = (django_settings.BASE_DIR / "Procfile").read_text(encoding="utf-8")
        self.assertIn("proxycheck.asgi:application", procfile_content)
        self.assertIn("uvicorn_worker.UvicornWorker", procfile_content)
        self.assertNotIn("collectstatic", procfile_content)
        self.assertTrue(getattr(django_settings, "WHITENOISE_USE_FINDERS", False))


class RedisDegradationAndOAuthFallbackTests(TestCase):
    """Tests Redis cache fault tolerance, OAuth upstream error handling, and callback route aliases."""

    def tearDown(self):
        views._ip_detect_inflight.clear()
        with views._redis_client_lock:
            views._redis_clients_by_loop.clear()
        views.reset_redis_circuit_breaker()

    async def test_safe_redis_helpers_degrade_on_connection_and_timeout_errors(self):
        failures = (
            ("connection_error", redis.exceptions.ConnectionError("Connection refused")),
            ("timeout_error", redis.exceptions.TimeoutError("Socket read timed out")),
        )
        for label, exc in failures:
            with self.subTest(failure=label):
                mock_redis = MagicMock()
                mock_redis.get = AsyncMock(side_effect=exc)
                mock_redis.set = AsyncMock(side_effect=exc)

                with (
                    patch("detector.views.redis_client", mock_redis),
                    self.assertLogs("detector.views", level="WARNING") as captured_logs,
                ):
                    cached_value = await views._safe_redis_get("proxycheck:v1:prov:proxycheck:8.8.8.8")
                    await views._safe_redis_set("proxycheck:v1:prov:proxycheck:8.8.8.8", "{}", ex=60)

                self.assertIsNone(cached_value)
                log_output = "\n".join(captured_logs.output)
                self.assertIn("Redis cache read bypassed", log_output)
                self.assertIn("Redis cache write bypassed", log_output)

    @patch(
        "dns.asyncresolver.Resolver.resolve",
        new_callable=AsyncMock,
        side_effect=_ptr_or_clean_dns_side_effect(ptr_hostname="dns.google."),
    )
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
    def test_detect_ip_returns_200_when_redis_raises_connection_or_timeout_errors(
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
        _mock_dns,
    ):
        for mock_fn, name in (
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
            mock_fn.return_value = {
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
        mock_mm.return_value = dict(MAXMIND_STUB)

        _login_authorised(self)
        bearer_token = views.issue_gadget_token("SysopUser")
        failures = (
            ("connection_error", redis.exceptions.ConnectionError("Redis unreachable")),
            ("timeout_error", redis.exceptions.TimeoutError("Redis read timed out")),
        )
        for label, exc in failures:
            for auth_mode, headers in (
                ("session", {}),
                ("bearer", {"HTTP_AUTHORIZATION": f"Bearer {bearer_token}"}),
            ):
                with self.subTest(failure=label, auth_mode=auth_mode):
                    mock_redis = MagicMock()
                    mock_redis.get = AsyncMock(side_effect=exc)
                    mock_redis.set = AsyncMock(side_effect=exc)

                    with (
                        patch("detector.views.redis_client", mock_redis),
                        self.assertLogs("detector.views", level="WARNING") as captured_logs,
                    ):
                        resp = self.client.get("/api/v1/detect?ip=8.8.8.8", **headers)

                    self.assertEqual(resp.status_code, 200)
                    payload = resp.json()
                    self.assertEqual(payload["ip"], "8.8.8.8")
                    self.assertFalse(payload["isCached"])
                    self.assertEqual(payload["cacheMeta"]["status"], "miss")
                    self.assertTrue(any("Redis cache" in line for line in captured_logs.output))

    @override_settings(REDIS_CIRCUIT_BREAKER_SECONDS=5.0)
    async def test_redis_circuit_breaker_opens_on_timeout_and_recovers_after_cooldown(self):
        from detector import quota_telemetry

        monotonic_clock = [100.0]
        loop_client = MagicMock(name="default-loop-redis")
        loop_client.get = AsyncMock(side_effect=[redis.exceptions.TimeoutError("Timed out"), "cached-ok"])
        loop_client.set = AsyncMock(return_value=True)

        views.reset_redis_circuit_breaker()
        with (
            patch.object(views.aioredis, "from_url", return_value=loop_client),
            patch("detector.views.time.monotonic", side_effect=lambda: monotonic_clock[0]),
        ):
            self.assertFalse(views.is_redis_circuit_open())
            self.assertIs(views._get_redis_client(), loop_client)

            # Non-connection exceptions must not trip the circuit breaker
            views.mark_redis_failure(ValueError("unexpected serialization error"))
            self.assertFalse(views.is_redis_circuit_open())

            with self.assertLogs("detector.views", level="WARNING") as captured_logs:
                first_read = await views._safe_redis_get("proxycheck:v1:prov:proxycheck:8.8.8.8")

            self.assertIsNone(first_read)
            self.assertTrue(views.is_redis_circuit_open())
            self.assertTrue(any("circuit breaker opened" in line for line in captured_logs.output))
            self.assertEqual(loop_client.get.await_count, 1)

            # Within the cooldown window, client acquisition fails open immediately without calling Redis
            monotonic_clock[0] = 104.9
            self.assertIsNone(views._get_redis_client())
            self.assertIsNone(quota_telemetry._get_redis_client())
            self.assertIsNone(await views._safe_redis_get("proxycheck:v1:prov:proxycheck:8.8.8.8"))
            await views._safe_redis_set("proxycheck:v1:prov:proxycheck:8.8.8.8", "{}", ex=60)
            self.assertEqual(loop_client.get.await_count, 1)
            self.assertEqual(loop_client.set.await_count, 0)

            # Once the cooldown elapses, the default client resumes automatically
            monotonic_clock[0] = 105.0
            self.assertFalse(views.is_redis_circuit_open())
            self.assertIs(views._get_redis_client(), loop_client)
            recovered_read = await views._safe_redis_get("proxycheck:v1:prov:proxycheck:8.8.8.8")
            self.assertEqual(recovered_read, "cached-ok")
            self.assertEqual(loop_client.get.await_count, 2)

            # Write errors also trip the breaker and explicit reset closes it immediately
            loop_client.set = AsyncMock(side_effect=ConnectionError("Connection reset by peer"))
            await views._safe_redis_set("proxycheck:v1:prov:proxycheck:8.8.8.8", "{}", ex=60)
            self.assertTrue(views.is_redis_circuit_open())
            self.assertIsNone(views._get_redis_client())
            views.reset_redis_circuit_breaker()
            self.assertFalse(views.is_redis_circuit_open())
            self.assertIs(views._get_redis_client(), loop_client)

    @override_settings(REDIS_CIRCUIT_BREAKER_SECONDS=5.0)
    @patch(
        "dns.asyncresolver.Resolver.resolve",
        new_callable=AsyncMock,
        side_effect=_ptr_or_clean_dns_side_effect(ptr_hostname="dns.google."),
    )
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
    async def test_redis_circuit_breaker_short_circuits_multistage_detect_request(
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
        _mock_dns,
    ):
        from django.test import AsyncClient

        for mock_fn, name in (
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
            mock_fn.return_value = {
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
        mock_mm.return_value = dict(MAXMIND_STUB)

        loop_client = MagicMock(name="hanging-default-loop-redis")
        loop_client.mget = AsyncMock(side_effect=redis.exceptions.TimeoutError("Socket read timed out"))
        loop_client.get = AsyncMock(side_effect=redis.exceptions.TimeoutError("Unexpected get call"))
        loop_client.set = AsyncMock(side_effect=redis.exceptions.TimeoutError("Unexpected set call"))
        loop_client.eval = AsyncMock(side_effect=redis.exceptions.TimeoutError("Unexpected eval call"))
        loop_client.pipeline = MagicMock(side_effect=AssertionError("Pipeline should be skipped once circuit is open"))

        bearer_token = views.issue_gadget_token("SysopUser")
        asgi_client = AsyncClient()
        views.reset_redis_circuit_breaker()

        with (
            patch.object(views.aioredis, "from_url", return_value=loop_client),
            patch("detector.views.time.monotonic", return_value=200.0),
        ):
            resp = await asgi_client.get(
                "/api/v1/detect?ip=8.8.8.8",
                headers={"Authorization": f"Bearer {bearer_token}"},
            )
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(views.is_redis_circuit_open())
            # Only the first cache-read stage contacts Redis; cooldown, quota, cache write, and telemetry fail open cleanly
            self.assertEqual(loop_client.mget.await_count, 1)
            self.assertEqual(loop_client.get.await_count, 0)
            self.assertEqual(loop_client.set.await_count, 0)
            self.assertEqual(loop_client.eval.await_count, 0)
            self.assertEqual(loop_client.pipeline.call_count, 0)

    @override_settings(REDIS_CIRCUIT_BREAKER_SECONDS=5.0)
    async def test_redis_circuit_breaker_isolates_custom_mock_client_patches(self):
        from detector import quota_telemetry

        mock_redis = MagicMock(name="patched-mock-redis")
        mock_redis.get = AsyncMock(side_effect=redis.exceptions.ConnectionError("Simulated mock outage"))
        mock_redis.eval = AsyncMock(side_effect=redis.exceptions.ConnectionError("Simulated Lua outage"))
        failing_pipe = MagicMock()
        failing_pipe.execute = AsyncMock(side_effect=redis.exceptions.TimeoutError("Simulated pipe outage"))
        mock_redis.pipeline = MagicMock(return_value=failing_pipe)

        views.reset_redis_circuit_breaker()
        with patch("detector.views.redis_client", mock_redis):
            self.assertIsNone(await views._safe_redis_get("proxycheck:v1:prov:proxycheck:8.8.8.8"))
            quota_res = await quota_telemetry.check_and_consume_quota("ipdata")
            self.assertTrue(quota_res.allowed)
            self.assertFalse(views.is_redis_circuit_open())
            self.assertIs(views._get_redis_client(), mock_redis)

        # Restoring the default client leaves the circuit closed
        self.assertFalse(views.is_redis_circuit_open())

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="super_secret_oauth_value_999",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/oauth/callback",
    )
    @patch("detector.views.httpx.AsyncClient")
    def test_oauth_callback_upstream_failures_log_without_leaks_and_redirect_home(self, mock_async_client_cls):
        failure_cases = (
            (
                "token_http_500",
                _mock_response(status_code=500, text="token error super_secret_oauth_value_999"),
                None,
                "token exchange failed",
            ),
            (
                "token_missing_access_token",
                _mock_response(status_code=200, json_value={"token_type": "Bearer"}),
                None,
                "contained no access_token",
            ),
            (
                "profile_http_502",
                _mock_response(status_code=200, json_value={"access_token": "tok_runtime_secret_888"}),
                _mock_response(
                    status_code=502,
                    text="profile bad gateway Bearer tok_runtime_secret_888 super_secret_oauth_value_999",
                ),
                "profile fetch failed",
            ),
            (
                "network_timeout",
                httpx.ReadTimeout("request timed out super_secret_oauth_value_999"),
                None,
                "callback processing error",
            ),
            (
                "profile_exception_with_token",
                _mock_response(status_code=200, json_value={"access_token": "tok_runtime_secret_888"}),
                RuntimeError("unexpected crash with tok_runtime_secret_888 and super_secret_oauth_value_999"),
                "callback processing error",
            ),
            (
                "invalid_json",
                _mock_response(status_code=200, json_error=ValueError("Invalid JSON payload")),
                None,
                "callback processing error",
            ),
        )

        for label, token_outcome, profile_outcome, expected_log_fragment in failure_cases:
            with self.subTest(case=label):
                mock_client = AsyncMock()
                mock_async_client_cls.return_value.__aenter__.return_value = mock_client
                if isinstance(token_outcome, Exception):
                    mock_client.post.side_effect = token_outcome
                else:
                    mock_client.post.return_value = token_outcome
                if isinstance(profile_outcome, Exception):
                    mock_client.get.side_effect = profile_outcome
                elif profile_outcome is not None:
                    mock_client.get.return_value = profile_outcome

                session = self.client.session
                session["oauth_state"] = f"state_{label}"
                session.pop("wikimedia_user", None)
                session.save()

                with self.assertLogs("detector.views", level="ERROR") as captured_logs:
                    resp = self.client.get(f"/api/v1/auth/callback/?code=code_{label}&state=state_{label}")

                self.assertEqual(resp.status_code, 302)
                self.assertEqual(resp["Location"], "/")
                self.assertIsNone(self.client.session.get("oauth_state"))
                self.assertIsNone(self.client.session.get("wikimedia_user"))
                log_output = "\n".join(captured_logs.output)
                self.assertIn(expected_log_fragment, log_output)
                self.assertNotIn("super_secret_oauth_value_999", log_output)
                self.assertNotIn("tok_runtime_secret_888", log_output)
                self.assertNotIn("Traceback (most recent call last):", log_output)

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="test_client_secret",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/oauth/callback",
    )
    @patch("detector.views.fetch_user_rights_from_meta", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
    def test_oauth_callback_alias_routes_authenticate_and_consume_state(self, mock_async_client_cls, mock_fetch_meta):
        mock_fetch_meta.return_value = {
            "global_groups": ["steward"],
            "global_rights": ["checkuser-temporary-account-no-preference"],
            "merged_projects": [],
        }
        alias_paths = ("/oauth/callback", "/oauth/callback/", "/api/oauth/callback")

        for index, route in enumerate(alias_paths):
            with self.subTest(route=route):
                mock_client = AsyncMock()
                mock_async_client_cls.return_value.__aenter__.return_value = mock_client
                mock_client.post.return_value = _mock_response(
                    status_code=200,
                    json_value={"access_token": f"token_{index}"},
                )
                mock_client.get.return_value = _mock_response(
                    status_code=200,
                    json_value={"username": f"AliasSteward_{index}", "groups": ["user"]},
                )

                state_val = f"alias_state_{index}"
                session = self.client.session
                session["oauth_state"] = state_val
                session.pop("wikimedia_user", None)
                session.save()

                resp = self.client.get(f"{route}?code=alias_code_{index}&state={state_val}")

                self.assertEqual(resp.status_code, 302)
                self.assertEqual(resp["Location"], "/")
                self.assertIsNone(self.client.session.get("oauth_state"))
                user_session = self.client.session.get("wikimedia_user")
                self.assertIsNotNone(user_session)
                self.assertEqual(user_session["username"], f"AliasSteward_{index}")
                self.assertTrue(user_session["hasAccess"])

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="super_secret_oauth_value_999",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/oauth/callback",
    )
    def test_oauth_login_returns_503_without_leaks_when_session_backend_fails(self):
        failures = (
            ("redis_conn", redis.exceptions.ConnectionError("redis://secret@127.0.0.1:6379 down")),
            ("redis_timeout", redis.exceptions.TimeoutError("socket timeout")),
            ("os_error", OSError("network unreachable")),
        )
        for label, exc in failures:
            with self.subTest(failure=label):
                with (
                    patch(
                        "django.contrib.sessions.backends.cache.SessionStore.save",
                        side_effect=exc,
                    ),
                    self.assertLogs("detector.views", level="WARNING") as captured_logs,
                ):
                    resp = self.client.get("/api/v1/auth/login/")

                self.assertEqual(resp.status_code, 503)
                self.assertIn("unavailable", resp.json()["error"].lower())
                log_output = "\n".join(captured_logs.output)
                self.assertNotIn("super_secret_oauth_value_999", log_output)
                self.assertNotIn("redis://secret", log_output)

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="super_secret_oauth_value_999",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/oauth/callback",
    )
    @patch("detector.views.fetch_user_rights_from_meta", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
    def test_oauth_callback_returns_503_when_session_save_fails_at_state_or_login(
        self, mock_async_client_cls, mock_fetch_meta
    ):
        with (
            patch(
                "django.contrib.sessions.backends.cache.SessionStore.save",
                side_effect=redis.exceptions.ConnectionError("Redis write refused"),
            ),
            self.assertLogs("detector.views", level="WARNING"),
        ):
            state_fail_resp = self.client.get("/api/v1/auth/callback/?code=abc&state=xyz")

        self.assertEqual(state_fail_resp.status_code, 503)
        self.assertIn("unavailable", state_fail_resp.json()["error"].lower())
        mock_async_client_cls.assert_not_called()

        session = self.client.session
        session["oauth_state"] = "state_persist_fail"
        session.save()

        mock_client = AsyncMock()
        mock_async_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.post.return_value = _mock_response(
            status_code=200,
            json_value={"access_token": "secret_oauth_access_tok_555"},
        )
        mock_client.get.return_value = _mock_response(
            status_code=200,
            json_value={"username": "StewardUser", "groups": ["user"]},
        )
        mock_fetch_meta.return_value = {
            "global_groups": ["steward"],
            "global_rights": ["checkuser-temporary-account-no-preference"],
            "merged_projects": [],
        }

        original_save = __import__(
            "django.contrib.sessions.backends.cache",
            fromlist=["SessionStore"],
        ).SessionStore.save
        save_calls = {"count": 0}

        def _fail_second_save(store_self, *args, **kwargs):
            save_calls["count"] += 1
            if save_calls["count"] == 1:
                return original_save(store_self, *args, **kwargs)
            raise redis.exceptions.TimeoutError("Timed out persisting session secret_oauth_access_tok_555")

        with (
            patch(
                "django.contrib.sessions.backends.cache.SessionStore.save",
                autospec=True,
                side_effect=_fail_second_save,
            ),
            self.assertLogs("detector.views", level="WARNING") as captured_logs,
        ):
            persist_fail_resp = self.client.get("/api/v1/auth/callback/?code=abc&state=state_persist_fail")

        self.assertEqual(persist_fail_resp.status_code, 503)
        self.assertIn("unavailable", persist_fail_resp.json()["error"].lower())
        self.assertIsNone(self.client.session.get("wikimedia_user"))
        log_output = "\n".join(captured_logs.output)
        self.assertNotIn("secret_oauth_access_tok_555", log_output)
        self.assertNotIn("super_secret_oauth_value_999", log_output)

    @override_settings(SESSION_RIGHTS_TTL_SECONDS=60)
    def test_auth_user_detect_and_logout_degrade_safely_when_redis_session_fails(self):
        with patch(
            "django.contrib.sessions.backends.cache.SessionStore.load",
            side_effect=redis.exceptions.ConnectionError("load fallback"),
        ):
            unauth_user_resp = self.client.get("/api/v1/auth/user/")
            self.assertEqual(unauth_user_resp.status_code, 200)
            self.assertFalse(unauth_user_resp.json()["isLoggedIn"])

            unauth_detect_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")
            self.assertEqual(unauth_detect_resp.status_code, 401)

        expired_user = {
            "isLoggedIn": True,
            "username": "ExpiredSysop",
            "role": "Local Administrator (sysop)",
            "hasAccess": True,
            "localGroups": ["sysop"],
            "globalGroups": [],
            "rights_updated_at": time.time() - 120,
        }
        session = self.client.session
        session["wikimedia_user"] = expired_user
        session.save()

        with (
            patch(
                "django.contrib.sessions.backends.cache.SessionStore.save",
                side_effect=redis.exceptions.ConnectionError("Redis save refused"),
            ),
            self.assertLogs("detector.views", level="WARNING"),
        ):
            user_resp = self.client.get("/api/v1/auth/user/")
            detect_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")

        self.assertEqual(user_resp.status_code, 200)
        self.assertFalse(user_resp.json()["isLoggedIn"])
        self.assertEqual(detect_resp.status_code, 401)

        session = self.client.session
        session["wikimedia_user"] = {
            **expired_user,
            "rights_updated_at": time.time(),
        }
        session.save()
        session_cookie_value = self.client.cookies["proxycheck_sessionid"].value

        with (
            patch(
                "django.contrib.sessions.backends.cache.SessionStore.delete",
                side_effect=redis.exceptions.ConnectionError("Redis delete refused"),
            ),
            self.assertLogs("detector.views", level="WARNING") as captured_logs,
        ):
            logout_resp = self.client.get("/api/v1/auth/logout/")

        self.assertEqual(logout_resp.status_code, 200)
        self.assertEqual(logout_resp.json()["status"], "logged_out")
        log_output = "\n".join(captured_logs.output)
        self.assertNotIn(session_cookie_value, log_output)

        with (
            override_settings(DEBUG=True, ENABLE_TEST_AUTH=True),
            patch(
                "django.contrib.sessions.backends.cache.SessionStore.delete",
                side_effect=redis.exceptions.ConnectionError("Redis delete refused"),
            ),
            self.assertLogs("detector.views", level="WARNING"),
        ):
            switch_flush_resp = self.client.post(
                "/api/v1/auth/switch-role/",
                data=json.dumps({"role": "unauthenticated"}),
                content_type="application/json",
            )
        self.assertEqual(switch_flush_resp.status_code, 200)
        self.assertFalse(switch_flush_resp.json()["isLoggedIn"])

    def test_resilient_session_middleware_guards_backend_outage_without_hiding_update_error(self):
        from detector.middleware import ResilientSessionMiddleware

        rf = RequestFactory()
        middleware = ResilientSessionMiddleware(lambda req: HttpResponse("ok"))

        req_outage = rf.get("/")
        req_outage.session = MagicMock()
        req_outage.session.accessed = True
        req_outage.session.modified = True
        req_outage.session.is_empty.return_value = False
        req_outage.session.get_expire_at_browser_close.return_value = False
        req_outage.session.get_expiry_age.return_value = 3600
        req_outage.session.save.side_effect = redis.exceptions.ConnectionError("Redis unreachable")

        with self.assertLogs("detector.middleware", level="WARNING"):
            res = middleware.process_response(req_outage, HttpResponse("ok"))

        self.assertEqual(res.status_code, 200)
        self.assertFalse(req_outage.session.modified)
        self.assertIn("Cookie", res.headers.get("Vary", ""))
        self.assertNotIn("proxycheck_sessionid", res.cookies)

        req_conflict = rf.get("/")
        req_conflict.session = MagicMock()
        req_conflict.session.accessed = True
        req_conflict.session.modified = True
        req_conflict.session.is_empty.return_value = False
        req_conflict.session.get_expire_at_browser_close.return_value = False
        req_conflict.session.get_expiry_age.return_value = 3600
        req_conflict.session.save.side_effect = UpdateError("concurrent logout")

        with self.assertRaises(SessionInterrupted):
            middleware.process_response(req_conflict, HttpResponse("ok"))


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
        toolforge_svg = self.client.get("/Toolforge.svg")
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


@contextlib.contextmanager
def _run_uvicorn_smoke_server(asgi_app):
    """Starts an ephemeral local Uvicorn server and guarantees shutdown on exit."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    finally:
        sock.close()

    config = uvicorn.Config(
        asgi_app,
        host="127.0.0.1",
        port=port,
        log_level="error",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5.0
        while not server.started:
            if not thread.is_alive() or time.monotonic() >= deadline:
                raise RuntimeError("Uvicorn test server failed to become ready within timeout.")
            time.sleep(0.02)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)


class AsgiSmokeTests(SimpleTestCase):
    """End-to-end ASGI smoke tests covering middleware headers, concurrency, and WhiteNoise."""

    def test_asgi_application_middleware_forwarded_proto_and_concurrent_requests(self):
        from proxycheck.asgi import application

        self.assertTrue(iscoroutinefunction(application._middleware_chain))
        self.assertNotIsInstance(application._middleware_chain, SyncToAsync)

        async def _send_concurrent_requests(base_url: str):
            async with httpx.AsyncClient(base_url=base_url, timeout=5.0) as client:
                return await asyncio.gather(
                    client.get("/", headers={"X-Forwarded-Proto": "https"}),
                    client.get("/"),
                    client.get("/api/v1/auth/user/", headers={"X-Forwarded-Proto": "https"}),
                    client.get("/api/v1/auth/user/", headers={"X-Forwarded-Proto": "https"}),
                    client.get("/api/v1/detect?ip=8.8.8.8", headers={"X-Forwarded-Proto": "https"}),
                    client.get("/Toolforge.svg", headers={"X-Forwarded-Proto": "https"}),
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

    def test_asgi_whitenoise_serves_static_asset_over_real_http(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir)
            static_root = base_dir / "staticfiles"
            static_root.mkdir(parents=True, exist_ok=True)
            (static_root / "smoke-test.css").write_text("body { color: #3366cc; }\n", encoding="utf-8")

            with (
                override_settings(BASE_DIR=base_dir, STATIC_ROOT=static_root, STATICFILES_DIRS=[]),
                warnings.catch_warnings(record=True) as captured_warnings,
            ):
                warnings.simplefilter("always")
                asgi_app = get_asgi_application()
                self.assertTrue(iscoroutinefunction(asgi_app._middleware_chain))
                self.assertNotIsInstance(asgi_app._middleware_chain, SyncToAsync)
                with _run_uvicorn_smoke_server(asgi_app) as base_url:
                    resp = httpx.get(
                        f"{base_url}/assets/smoke-test.css",
                        headers={"X-Forwarded-Proto": "https"},
                        timeout=5.0,
                    )
                    head_resp = httpx.head(
                        f"{base_url}/assets/smoke-test.css",
                        headers={"X-Forwarded-Proto": "https"},
                        timeout=5.0,
                    )
                    not_modified_resp = httpx.get(
                        f"{base_url}/assets/smoke-test.css",
                        headers={
                            "X-Forwarded-Proto": "https",
                            "If-None-Match": resp.headers["etag"],
                        },
                        timeout=5.0,
                    )

            self.assertEqual(resp.status_code, 200)
            self.assertIn("text/css", resp.headers.get("content-type", ""))
            self.assertIn("#3366cc", resp.text)
            self.assertIn("max-age=", resp.headers.get("cache-control", ""))
            self.assertEqual(head_resp.status_code, 200)
            self.assertEqual(head_resp.content, b"")
            self.assertEqual(not_modified_resp.status_code, 304)
            sync_iterator_warnings = [
                str(warning.message)
                for warning in captured_warnings
                if "StreamingHttpResponse must consume synchronous iterators" in str(warning.message)
            ]
            self.assertEqual(sync_iterator_warnings, [])

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

    def test_resilient_session_middleware_skips_sync_bridging_for_stateless_api_requests(self):
        import django.utils.deprecation as django_deprecation

        sync_factory = RequestFactory()
        sync_middleware = ResilientSessionMiddleware(lambda req: HttpResponse("sync-ok"))
        self.assertFalse(sync_middleware.async_mode)
        self.assertFalse(iscoroutinefunction(sync_middleware))
        sync_resp = sync_middleware(sync_factory.get("/api/v1/detect?ip=8.8.8.8"))
        self.assertEqual(sync_resp.content, b"sync-ok")

        observed_requests = []

        async def async_next(request):
            observed_requests.append(
                {
                    "path": request.path,
                    "has_session": hasattr(request, "session"),
                    "session_key": request.session.session_key,
                    "accessed": request.session.accessed,
                    "modified": request.session.modified,
                }
            )
            return HttpResponse("async-ok")

        async_middleware = ResilientSessionMiddleware(async_next)
        self.assertTrue(async_middleware.async_mode)
        self.assertTrue(iscoroutinefunction(async_middleware))

        async_factory = AsyncRequestFactory()
        real_sync_to_async = django_deprecation.sync_to_async
        bridged_calls = []

        def spy_sync_to_async(func, *args, **kwargs):
            bridged_calls.append(getattr(func, "__qualname__", repr(func)))
            return real_sync_to_async(func, *args, **kwargs)

        async def _exercise_stateless_requests():
            stateless_requests = [
                async_factory.options("/api/v1/detect"),
                async_factory.options("/api/v1/auth/gadget-token/"),
                async_factory.post("/api/v1/auth/gadget-token"),
                async_factory.post("/api/v1/auth/gadget-token/"),
                async_factory.get(
                    "/api/v1/detect?ip=8.8.8.8",
                    headers={
                        "Authorization": "Bearer signed-gadget-token",
                        "Cookie": "proxycheck_sessionid=existing-session-key",
                    },
                ),
                async_factory.post(
                    "/api/v1/detect/batch",
                    data="{}",
                    content_type="application/json",
                    headers={"Authorization": "bearer lower-scheme-token"},
                ),
            ]
            for req in stateless_requests:
                resp = await async_middleware(req)
                self.assertEqual(resp.status_code, 200)

        with (
            patch("django.utils.deprecation.sync_to_async", side_effect=spy_sync_to_async),
            patch(
                "django.contrib.sessions.backends.cache.SessionStore.load",
                side_effect=AssertionError("Session backend load should not be called"),
            ),
            patch(
                "django.contrib.sessions.backends.cache.SessionStore.save",
                side_effect=AssertionError("Session backend save should not be called"),
            ),
        ):
            asyncio.run(_exercise_stateless_requests())

        self.assertEqual(bridged_calls, [])
        self.assertEqual(len(observed_requests), 6)
        for item in observed_requests:
            self.assertTrue(item["has_session"])
            self.assertIsNone(item["session_key"])
            self.assertFalse(item["accessed"])
            self.assertFalse(item["modified"])

        observed_requests.clear()
        bridged_calls.clear()

        async def _exercise_session_requests():
            no_auth_req = async_factory.get(
                "/api/v1/detect?ip=8.8.8.8",
                headers={"Cookie": "proxycheck_sessionid=web-session-key"},
            )
            basic_auth_req = async_factory.get(
                "/api/v1/detect?ip=8.8.8.8",
                headers={
                    "Authorization": "Basic dXNlcjpwYXNz",
                    "Cookie": "proxycheck_sessionid=web-session-key-2",
                },
            )
            blank_auth_req = async_factory.get(
                "/api/v1/detect?ip=8.8.8.8",
                headers={
                    "Authorization": "   ",
                    "Cookie": "proxycheck_sessionid=web-session-key-3",
                },
            )
            for req in (no_auth_req, basic_auth_req, blank_auth_req):
                resp = await async_middleware(req)
                self.assertEqual(resp.status_code, 200)

        with patch("django.utils.deprecation.sync_to_async", side_effect=spy_sync_to_async):
            asyncio.run(_exercise_session_requests())

        self.assertEqual(
            [item["session_key"] for item in observed_requests],
            ["web-session-key", "web-session-key-2", "web-session-key-3"],
        )
        self.assertEqual(
            bridged_calls,
            [
                "SessionMiddleware.process_request",
                "ResilientSessionMiddleware.process_response",
                "SessionMiddleware.process_request",
                "ResilientSessionMiddleware.process_response",
                "SessionMiddleware.process_request",
                "ResilientSessionMiddleware.process_response",
            ],
        )

        async def async_mutating_next(request):
            request.session["oauth_state"] = "state_value"
            return HttpResponse("mutated")

        mutating_middleware = ResilientSessionMiddleware(async_mutating_next)
        outage_req = async_factory.get("/api/v1/auth/login/")
        with (
            patch(
                "django.contrib.sessions.backends.cache.SessionStore.save",
                side_effect=redis.exceptions.ConnectionError("Redis offline"),
            ),
            self.assertLogs("detector.middleware", level="WARNING"),
        ):
            outage_resp = asyncio.run(mutating_middleware(outage_req))

        self.assertEqual(outage_resp.status_code, 200)
        self.assertFalse(outage_req.session.modified)
        self.assertIn("Cookie", outage_resp.headers.get("Vary", ""))
        self.assertNotIn("proxycheck_sessionid", outage_resp.cookies)

        conflict_req = async_factory.get("/api/v1/auth/login/")
        with patch(
            "django.contrib.sessions.backends.cache.SessionStore.save",
            side_effect=UpdateError("concurrent logout"),
        ):
            with self.assertRaises(SessionInterrupted):
                asyncio.run(mutating_middleware(conflict_req))

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


class CommercialProviderMetadataAdapterTests(SimpleTestCase):
    """Tests for extracted metadata and security signals across commercial adapters."""

    def test_ipdata_extracts_icloud_relay_and_carrier(self):
        relay_row = adapt_ipdata(
            {
                "ip": "172.224.224.1",
                "threat": {"is_icloud_relay": True},
                "carrier": {"name": "T-Mobile USA"},
                "country_name": "United States",
                "country_code": "US",
            },
            has_api_key=True,
        )
        self.assertEqual(relay_row["carrier"], "T-Mobile USA")
        self.assertEqual(relay_row["usageType"], "mobile")
        self.assertEqual(relay_row["isp"], "T-Mobile USA")
        self.assertIn({"label": "iCloud Private Relay", "isHighRisk": True}, relay_row["securityFlags"])

        # Explicit company type takes precedence over carrier fallback and ignores malformed nested objects
        company_row = adapt_ipdata(
            {
                "ip": "198.51.100.2",
                "threat": "invalid-threat-payload",
                "company": {"type": "isp", "name": "Example Mobile ISP"},
                "carrier": "  Orange France  ",
            },
            has_api_key=True,
        )
        self.assertEqual(company_row["carrier"], "Orange France")
        self.assertEqual(company_row["usageType"], "isp")
        self.assertEqual(company_row["isp"], "Example Mobile ISP")

    def test_ipregistry_extracts_mobile_relay_and_abuser(self):
        mobile_row = adapt_ipregistry(
            {
                "connection": {"type": "mobile", "asn": 7018, "organization": "AT&T Mobility"},
                "security": {"is_relay": True, "is_abuser": True},
                "location": {"country": {"name": "United States", "code": "US"}},
            },
            has_api_key=True,
        )
        self.assertTrue(mobile_row["isMobile"])
        self.assertEqual(mobile_row["usageType"], "mobile")
        self.assertIn({"label": "Relay", "isHighRisk": True}, mobile_row["securityFlags"])
        self.assertIn({"label": "Known Abuser", "isHighRisk": True}, mobile_row["securityFlags"])

        hosting_row = adapt_ipregistry(
            {
                "connection": {"type": "hosting", "asn": 14061, "organization": "DigitalOcean"},
                "security": {"is_proxy": True, "is_tor": True, "is_relay": True, "is_abuser": True},
            },
            has_api_key=True,
        )
        self.assertFalse(hosting_row["isMobile"])
        self.assertIn({"label": "Relay", "isHighRisk": True}, hosting_row["securityFlags"])
        self.assertIn({"label": "Known Abuser", "isHighRisk": True}, hosting_row["securityFlags"])

    def test_ip2location_extracts_mobile_brand_and_ignores_dash(self):
        mobile_row = adapt_ip2location(
            {
                "asn": "21928",
                "mobile_brand": "  T-Mobile  ",
                "usage_type": "-",
                "country_name": "United States",
                "country_code": "US",
            },
            has_api_key=True,
        )
        self.assertEqual(mobile_row["mobileBrand"], "T-Mobile")
        self.assertEqual(mobile_row["usageType"], "mobile")
        self.assertEqual(mobile_row["isp"], "T-Mobile")

        dash_row = adapt_ip2location(
            {
                "asn": "1221",
                "as": "Telstra Corporation Ltd",
                "mobile_brand": "-",
                "usage_type": "ISP",
            },
            has_api_key=True,
        )
        self.assertIsNone(dash_row["mobileBrand"])
        self.assertEqual(dash_row["usageType"], "ISP")
        self.assertEqual(dash_row["isp"], "Telstra Corporation Ltd")

    def test_abuseipdb_extracts_report_counts_and_last_reported_at(self):
        row = adapt_abuseipdb(
            {
                "data": {
                    "abuseConfidenceScore": 85,
                    "totalReports": 42,
                    "numDistinctUsers": 17,
                    "lastReportedAt": "2026-10-01T12:30:00+00:00",
                    "isp": "Hetzner Online GmbH",
                    "countryName": "Germany",
                    "countryCode": "DE",
                    "usageType": "Data Center/Web Hosting/Transit",
                }
            },
            has_api_key=True,
        )
        self.assertEqual(row["totalReports"], 42)
        self.assertEqual(row["numDistinctUsers"], 17)
        self.assertEqual(row["lastSeen"], "2026-10-01T12:30:00+00:00")

        clamped_row = adapt_abuseipdb(
            {
                "data": {
                    "abuseConfidenceScore": 0,
                    "totalReports": -5,
                    "numDistinctUsers": "invalid",
                    "lastReportedAt": "   ",
                }
            },
            has_api_key=True,
        )
        self.assertEqual(clamped_row["totalReports"], 0)
        self.assertIsNone(clamped_row["numDistinctUsers"])
        self.assertIsNone(clamped_row["lastSeen"])

        err_row = adapt_abuseipdb(None, has_api_key=True, status_code=429)
        self.assertIsNone(err_row["totalReports"])
        self.assertIsNone(err_row["numDistinctUsers"])
        self.assertIsNone(err_row["lastSeen"])


class OfflineHostingAndCloudIntelligenceTests(SimpleTestCase):
    """Tests for offline hosting ASN rules, cloud CIDR matching, and GeoLite2 enrichment."""

    def setUp(self):
        clear_offline_intelligence_caches()
        self.addCleanup(clear_offline_intelligence_caches)

    def test_builtin_hosting_asn_fallback_and_non_hosting_exclusions(self):
        with override_settings(
            HOSTING_ASN_RULES_PATH="",
            HOSTING_ASNS=(),
            HOSTING_ORG_KEYWORDS=(),
        ):
            for asn in (14061, "AS24940", 16276, 20473, 63949):
                hit = match_hosting_asn_or_org(asn, "Some Organization")
                self.assertIsNotNone(hit)
                self.assertEqual(hit["matchedBy"], "asn")

            kw_hit = match_hosting_asn_or_org(None, "Hetzner Online GmbH")
            self.assertIsNotNone(kw_hit)
            self.assertEqual(kw_hit["matchedBy"], "keyword")

            # Non-hosting ISPs and CDN names without hosting keywords should remain unflagged
            self.assertIsNone(match_hosting_asn_or_org(1221, "Telstra Corporation Ltd"))
            self.assertIsNone(match_hosting_asn_or_org(13335, "Cloudflare, Inc."))

    def test_custom_hosting_asn_rules_json_and_settings_override(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_file = Path(tmpdir) / "hosting_asn_rules.json"
            rules_file.write_text(
                json.dumps(
                    {
                        "hosts": [
                            {"name": "Example Cloud Host", "asn": 64510, "keywords": ["ExampleHost"]},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with override_settings(
                HOSTING_ASN_RULES_PATH=str(rules_file),
                HOSTING_ASNS=("64512",),
                HOSTING_ORG_KEYWORDS=("CustomRack",),
            ):
                json_hit = match_hosting_asn_or_org("AS64510", "Unlisted")
                self.assertEqual(json_hit, {"provider": "Example Cloud Host", "matchedBy": "asn"})

                env_asn_hit = match_hosting_asn_or_org(64512, "Unlisted")
                self.assertEqual(env_asn_hit, {"provider": "AS64512", "matchedBy": "asn"})

                env_kw_hit = match_hosting_asn_or_org(None, "CustomRack Infrastructure LLC")
                self.assertEqual(env_kw_hit, {"provider": "CustomRack", "matchedBy": "keyword"})

                # Word boundaries prevent partial substring false positives
                self.assertIsNone(match_hosting_asn_or_org(None, "MyExampleHostCompany"))

    def test_cloud_cidr_matching_formats_narrowest_prefix_and_ipv6(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            computehosts_file = Path(tmpdir) / "computehosts.json"
            computehosts_file.write_text(
                json.dumps(
                    [
                        {"range": "52.94.236.0/24", "provider": "aws"},
                        {"range": "52.94.236.64/26", "provider": "Amazon AWS"},
                        {"range": "2600:1f18:2000::/48", "provider": "aws"},
                    ]
                ),
                encoding="utf-8",
            )
            with override_settings(CLOUD_CIDR_DB_PATH=str(computehosts_file)):
                narrow_hit = match_cloud_cidr("52.94.236.70")
                self.assertEqual(
                    narrow_hit,
                    {"cidr": "52.94.236.64/26", "prefixLength": 26, "provider": "Amazon AWS"},
                )
                v6_hit = match_cloud_cidr("2600:1f18:2000:1::1")
                self.assertEqual(
                    v6_hit,
                    {"cidr": "2600:1f18:2000::/48", "prefixLength": 48, "provider": "Amazon AWS"},
                )
                mapped_v4_hit = match_cloud_cidr("::ffff:52.94.236.70")
                self.assertEqual(
                    mapped_v4_hit,
                    {"cidr": "52.94.236.64/26", "prefixLength": 26, "provider": "Amazon AWS"},
                )
                self.assertIsNone(match_cloud_cidr("8.8.8.8"))

            clear_offline_intelligence_caches()
            aws_file = Path(tmpdir) / "ip-ranges.json"
            aws_file.write_text(
                json.dumps(
                    {
                        "prefixes": [{"ip_prefix": "3.5.140.0/22", "service": "AMAZON"}],
                        "ipv6_prefixes": [{"ipv6_prefix": "2a05:d014::/40", "service": "EC2"}],
                    }
                ),
                encoding="utf-8",
            )
            with override_settings(CLOUD_CIDR_DB_PATH=str(aws_file)):
                self.assertEqual(match_cloud_cidr("3.5.140.5")["provider"], "Amazon AWS")
                self.assertEqual(match_cloud_cidr("2a05:d014:1::5")["cidr"], "2a05:d014::/40")

            clear_offline_intelligence_caches()
            provider_dict_file = Path(tmpdir) / "provider_cidrs.json"
            provider_dict_file.write_text(
                json.dumps({"gcp": ["34.64.0.0/16"], "azure": ["20.48.0.0/16"]}),
                encoding="utf-8",
            )
            with override_settings(CLOUD_CIDR_DB_PATH=str(provider_dict_file)):
                self.assertEqual(match_cloud_cidr("34.64.1.2")["provider"], "Google Cloud")
                self.assertEqual(match_cloud_cidr("20.48.1.2")["provider"], "Microsoft Azure")

            clear_offline_intelligence_caches()
            broken_file = Path(tmpdir) / "broken.json"
            broken_file.write_text("{not-valid-json", encoding="utf-8")
            with override_settings(CLOUD_CIDR_DB_PATH=str(broken_file)):
                self.assertIsNone(match_cloud_cidr("34.64.1.2"))

            with override_settings(CLOUD_CIDR_DB_PATH=str(Path(tmpdir) / "missing.json")):
                self.assertIsNone(match_cloud_cidr("34.64.1.2"))

    def test_cloud_cidr_cache_reloads_when_file_mtime_changes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cidr_file = Path(tmpdir) / "cloud_cidrs.json"
            cidr_file.write_text(json.dumps({"gcp": ["34.64.0.0/16"]}), encoding="utf-8")
            with override_settings(CLOUD_CIDR_DB_PATH=str(cidr_file)):
                self.assertIsNone(match_cloud_cidr("20.48.1.2"))

                cidr_file.write_text(json.dumps({"azure": ["20.48.0.0/16"]}), encoding="utf-8")
                stat = cidr_file.stat()
                os.utime(cidr_file, ns=(stat.st_atime_ns, stat.st_mtime_ns + 2_000_000_000))

                reloaded = match_cloud_cidr("20.48.1.2")
                self.assertIsNotNone(reloaded)
                self.assertEqual(reloaded["provider"], "Microsoft Azure")

    def test_maxmind_geolite2_enrichment_preserves_explicit_geoip2_user_type(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cidr_file = Path(tmpdir) / "cloud_cidrs.json"
            cidr_file.write_text(
                json.dumps([{"range": "54.239.28.64/26", "provider": "Amazon AWS"}]),
                encoding="utf-8",
            )
            with override_settings(
                CLOUD_CIDR_DB_PATH=str(cidr_file),
                HOSTING_ASN_RULES_PATH="",
                HOSTING_ASNS=(),
                HOSTING_ORG_KEYWORDS=(),
            ):
                cloud_enriched = adapt_maxmind(
                    {
                        "autonomous_system_number": 16509,
                        "autonomous_system_organization": "Amazon.com, Inc.",
                        "country": {"names": {"en": "United States"}, "iso_code": "US"},
                        "_mmdb_prefix_len": 24,
                        "_ip": "54.239.28.85",
                    },
                    has_db=True,
                    ip="54.239.28.85",
                )
                self.assertEqual(cloud_enriched["usageType"], "hosting")
                self.assertEqual(cloud_enriched["cloudProvider"], "Amazon AWS")
                self.assertEqual(cloud_enriched["cloudCidr"], "54.239.28.64/26")
                self.assertEqual(cloud_enriched["cloudPrefixLength"], 26)
                self.assertEqual(cloud_enriched["hostingProvider"], "Amazon AWS")
                self.assertIn({"label": "Hosting", "isHighRisk": True}, cloud_enriched["securityFlags"])
                self.assertNotIn("_ip", cloud_enriched["rawJson"])
                self.assertNotIn("_mmdb_prefix_len", cloud_enriched["rawJson"])

                # Paid GeoIP2 user_type takes priority over offline hosting fallback
                explicit_geoip2 = adapt_maxmind(
                    {
                        "autonomous_system_number": 14061,
                        "autonomous_system_organization": "DigitalOcean, LLC",
                        "traits": {"user_type": "residential"},
                    },
                    has_db=True,
                    ip="159.89.10.1",
                )
                self.assertEqual(explicit_geoip2["usageType"], "residential")
                self.assertEqual(explicit_geoip2["securityFlags"], [{"label": "No Flags", "isHighRisk": False}])

    def test_compute_cidr_attribution_uses_cloud_prefix_rules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cidr_file = Path(tmpdir) / "cloud_cidrs.json"
            cidr_file.write_text(
                json.dumps(
                    {
                        "Amazon AWS": ["54.239.28.64/26", "2600:1f18:2000::/80"],
                        "Google Cloud": ["34.64.0.0/16"],
                    }
                ),
                encoding="utf-8",
            )
            with override_settings(CLOUD_CIDR_DB_PATH=str(cidr_file)):
                narrow_v4 = compute_cidr_attribution("54.239.28.85")
                self.assertEqual(narrow_v4["recommendedCidr"], "54.239.28.64/26")
                self.assertEqual(narrow_v4["defaultCidr"], "54.239.28.0/24")
                self.assertEqual(narrow_v4["cloudCidr"], "54.239.28.64/26")
                self.assertEqual(narrow_v4["cloudProvider"], "Amazon AWS")

                narrow_v6 = compute_cidr_attribution("2600:1f18:2000::5")
                self.assertEqual(narrow_v6["recommendedCidr"], "2600:1f18:2000::/80")
                self.assertEqual(narrow_v6["defaultCidr"], "2600:1f18:2000::/64")
                self.assertEqual(narrow_v6["cloudCidr"], "2600:1f18:2000::/80")

                wide_v4 = compute_cidr_attribution("34.64.12.34")
                self.assertEqual(wide_v4["recommendedCidr"], "34.64.12.0/24")
                self.assertEqual(wide_v4["cloudCidr"], "34.64.0.0/16")
                self.assertEqual(wide_v4["cloudProvider"], "Google Cloud")

                mmdb_wins = compute_cidr_attribution("54.239.28.85", mmdb_prefix_len=27)
                self.assertEqual(mmdb_wins["recommendedCidr"], "54.239.28.64/27")
                self.assertEqual(mmdb_wins["cloudCidr"], "54.239.28.64/26")

    def test_views_read_maxmind_sync_and_aggregate_intelligence_integration(self):
        views._maxmind_readers.clear()
        self.addCleanup(views._maxmind_readers.clear)
        with tempfile.TemporaryDirectory() as tmpdir:
            cidr_file = Path(tmpdir) / "cloud_cidrs.json"
            cidr_file.write_text(
                json.dumps([{"range": "54.239.28.64/26", "provider": "Amazon AWS"}]),
                encoding="utf-8",
            )
            country_db = Path(tmpdir) / "GeoLite2-Country.mmdb"
            asn_db = Path(tmpdir) / "GeoLite2-ASN.mmdb"
            country_db.write_bytes(b"stub")
            asn_db.write_bytes(b"stub")

            country_rec = {"country": {"names": {"en": "United States"}, "iso_code": "US"}}
            asn_rec = {
                "autonomous_system_number": 16509,
                "autonomous_system_organization": "Amazon.com, Inc.",
            }
            fake_country_reader = MagicMock()
            fake_country_reader.get.return_value = country_rec
            fake_country_reader.get_with_prefix_len.return_value = (country_rec, 16)

            fake_asn_reader = MagicMock()
            fake_asn_reader.get.return_value = asn_rec
            fake_asn_reader.get_with_prefix_len.return_value = (asn_rec, 24)

            fake_maxmind_module = MagicMock()
            fake_maxmind_module.open_database.side_effect = lambda db_path: (
                fake_country_reader if "country" in str(db_path).lower() else fake_asn_reader
            )

            with (
                override_settings(
                    MAXMIND_DB_DIR=str(tmpdir),
                    CLOUD_CIDR_DB_PATH=str(cidr_file),
                    HOSTING_ASN_RULES_PATH="",
                    HOSTING_ASNS=(),
                    HOSTING_ORG_KEYWORDS=(),
                ),
                patch.dict("sys.modules", {"maxminddb": fake_maxmind_module}),
            ):
                maxmind_row = views._read_maxmind_sync("54.239.28.85")
                self.assertEqual(maxmind_row["usageType"], "hosting")
                self.assertEqual(maxmind_row["cloudCidr"], "54.239.28.64/26")
                self.assertEqual(maxmind_row["cloudProvider"], "Amazon AWS")

                relay_row = adapt_ipregistry(
                    {
                        "connection": {"type": "hosting", "asn": 16509, "organization": "Amazon.com, Inc."},
                        "security": {"is_relay": True},
                    },
                    has_api_key=True,
                )
                aggregated = views.aggregate_intelligence_metrics("54.239.28.85", [maxmind_row, relay_row])
                self.assertEqual(aggregated["recommendedCidr"], "54.239.28.64/26")
                self.assertEqual(aggregated["cloudCidr"], "54.239.28.64/26")
                self.assertEqual(aggregated["cloudProvider"], "Amazon AWS")
                self.assertIn("Amazon AWS cloud prefix /26", aggregated["cidrNote"])
                self.assertEqual(aggregated["arbitrationVerdict"], "Confirmed Proxy / VPN (1/1 Sources)")
                self.assertEqual(aggregated["arbitrationTier"], "destructive")

        non_public = views._build_non_public_response_payload("127.0.0.1", "loopback", "Loopback IP", time.monotonic())
        self.assertIsNone(non_public["cloudCidr"])
        self.assertIsNone(non_public["cloudProvider"])

    def _query_mmdb_dir(
        self,
        ip: str,
        db_records: dict[str, tuple[dict, int | None]],
        *,
        cidr_path: str = "",
    ) -> dict:
        """Creates stub MMDB files in one directory and runs _read_maxmind_sync against fake readers."""
        views._maxmind_readers.clear()
        self.addCleanup(views._maxmind_readers.clear)
        filename_map = {
            "country": "GeoLite2-Country.mmdb",
            "city": "GeoLite2-City.mmdb",
            "asn": "GeoLite2-ASN.mmdb",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            readers_by_path: dict[str, MagicMock] = {}
            for role, (rec, prefix_len) in db_records.items():
                db_path = Path(tmpdir) / filename_map[role]
                db_path.write_bytes(b"stub")
                reader = MagicMock()
                reader.get.return_value = rec
                if prefix_len is not None:
                    reader.get_with_prefix_len.return_value = (rec, prefix_len)
                readers_by_path[str(db_path)] = reader

            fake_maxmind_module = MagicMock()
            fake_maxmind_module.open_database.side_effect = lambda path: readers_by_path[str(path)]

            with (
                override_settings(
                    MAXMIND_DB_DIR=str(tmpdir),
                    CLOUD_CIDR_DB_PATH=cidr_path,
                    HOSTING_ASN_RULES_PATH="",
                    HOSTING_ASNS=(),
                    HOSTING_ORG_KEYWORDS=(),
                ),
                patch.dict("sys.modules", {"maxminddb": fake_maxmind_module}),
            ):
                return views._read_maxmind_sync(ip)

    def test_adapt_maxmind_city_subdivision_coordinates_and_deduplication(self):
        us_row = adapt_maxmind(
            {
                "country": {"names": {"en": "United States"}, "iso_code": "US"},
                "subdivisions": [{"names": {"en": "California"}, "iso_code": "CA"}],
                "city": {"names": {"en": "Mountain View"}},
                "location": {"latitude": 37.386, "longitude": -122.0838},
                "autonomous_system_number": 15169,
                "autonomous_system_organization": "Google LLC",
            },
            has_db=True,
        )
        self.assertEqual(us_row["location"], "Mountain View, California, United States (37.386, -122.0838)")
        self.assertEqual(us_row["coordinates"], "37.386, -122.0838")
        self.assertEqual(us_row["countryCode"], "US")

        # Duplicate city and subdivision names should collapse cleanly
        tokyo_row = adapt_maxmind(
            {
                "country": {"names": {"en": "Japan"}, "iso_code": "JP"},
                "subdivisions": [{"names": {"en": "Tokyo"}, "iso_code": "13"}],
                "city": {"names": {"en": "Tokyo"}},
                "location": {"latitude": 35.6895, "longitude": 139.6917},
            },
            has_db=True,
        )
        self.assertEqual(tokyo_row["location"], "Tokyo, Japan (35.6895, 139.6917)")

        # Corrupted subdivisions or missing names still preserve valid country output
        fallback_row = adapt_maxmind(
            {
                "country": {"names": {"en": "Singapore"}, "iso_code": "SG"},
                "subdivisions": "corrupted",
                "city": {"names": {"en": "Singapore"}},
            },
            has_db=True,
        )
        self.assertEqual(fallback_row["location"], "Singapore")

    def test_three_mmdb_collaboration_preserves_country_iso_and_city_fallback_coords(self):
        # Country DB remains authoritative on iso_code even when City DB omits or differs on country
        maxmind_row = self._query_mmdb_dir(
            "8.8.8.8",
            {
                "country": ({"country": {"names": {"en": "United States"}, "iso_code": "US"}}, 16),
                "city": (
                    {
                        "country": {"names": {"en": "United States"}, "iso_code": "CA"},
                        "subdivisions": [{"names": {"en": "Virginia"}, "iso_code": "VA"}],
                        "city": {"names": {"en": "Ashburn"}},
                        "location": {"latitude": 39.0438, "longitude": -77.4874},
                    },
                    27,
                ),
                "asn": (
                    {
                        "autonomous_system_number": 15169,
                        "autonomous_system_organization": "Google LLC",
                    },
                    24,
                ),
            },
        )
        self.assertEqual(maxmind_row["countryCode"], "US")
        self.assertEqual(maxmind_row["location"], "Ashburn, Virginia, United States (39.0438, -77.4874)")
        self.assertEqual(maxmind_row["coordinates"], "39.0438, -77.4874")
        # ASN routing prefix takes precedence over City and Country prefixes
        self.assertEqual(maxmind_row["prefixLength"], 24)

        consistent_ipdata = adapt_ipdata(
            {"country_code": "US", "country_name": "United States", "city": "Ashburn", "region": "Virginia"},
            has_api_key=True,
        )
        consistent_agg = views.aggregate_intelligence_metrics("8.8.8.8", [consistent_ipdata, maxmind_row])
        self.assertFalse(consistent_agg["is_broadcast_ip"])
        self.assertEqual(consistent_agg["primaryCoordinates"], "39.0438, -77.4874")

        conflicting_abuseipdb = adapt_abuseipdb(
            {"data": {"countryName": "Germany", "countryCode": "DE", "abuseConfidenceScore": 0}},
            has_api_key=True,
        )
        broadcast_agg = views.aggregate_intelligence_metrics("8.8.8.8", [conflicting_abuseipdb, maxmind_row])
        self.assertTrue(broadcast_agg["is_broadcast_ip"])
        self.assertEqual(broadcast_agg["primaryCoordinates"], "39.0438, -77.4874")

    def test_maxmind_db_dir_partial_databases_and_explicit_missing_dir(self):
        # City and ASN without Country DB still supply country, city, subdivision, and coordinates
        city_only_country_row = self._query_mmdb_dir(
            "1.1.1.1",
            {
                "city": (
                    {
                        "country": {"names": {"en": "Australia"}, "iso_code": "AU"},
                        "subdivisions": [{"names": {"en": "New South Wales"}, "iso_code": "NSW"}],
                        "city": {"names": {"en": "Sydney"}},
                        "location": {"latitude": -33.8688, "longitude": 151.2093},
                    },
                    25,
                ),
                "asn": (
                    {
                        "autonomous_system_number": 13335,
                        "autonomous_system_organization": "Cloudflare, Inc.",
                    },
                    None,
                ),
            },
        )
        self.assertEqual(city_only_country_row["countryCode"], "AU")
        self.assertEqual(city_only_country_row["location"], "Sydney, New South Wales, Australia (-33.8688, 151.2093)")
        self.assertEqual(city_only_country_row["prefixLength"], 25)

        # Explicit empty MAXMIND_DB_DIR does not fall back to unrelated data directories
        with tempfile.TemporaryDirectory() as tmpdir:
            tool_root = Path(tmpdir) / "tool"
            fallback_data = tool_root / "www" / "python" / "data"
            fallback_data.mkdir(parents=True)
            (fallback_data / "GeoLite2-Country.mmdb").write_bytes(b"stub")
            empty_dir = Path(tmpdir) / "empty_mmdb"
            empty_dir.mkdir()

            with (
                override_settings(MAXMIND_DB_DIR=str(empty_dir)),
                patch.dict(os.environ, {"TOOL_DATA_DIR": str(tool_root)}),
            ):
                missing_row = views._read_maxmind_sync("1.1.1.1")
            self.assertEqual(missing_row["status"], "Database Missing")

    def test_adapt_maxmind_falls_back_to_non_english_localized_names(self):
        localized_row = adapt_maxmind(
            {
                "country": {"names": {"zh-CN": "中国"}, "iso_code": "CN"},
                "subdivisions": [{"names": {"zh-CN": "北京"}, "iso_code": "BJ"}],
                "city": {"names": {"zh-CN": "北京"}},
                "location": {"latitude": 39.9075, "longitude": 116.3971},
            },
            has_db=True,
        )
        self.assertEqual(localized_row["location"], "北京, 中国 (39.9075, 116.3971)")
        self.assertEqual(localized_row["coordinates"], "39.9075, 116.3971")
        self.assertEqual(localized_row["countryCode"], "CN")

    def test_maxmind_resolver_expands_env_nested_subdirs_and_reloads_updated_file(self):
        from proxycheck.settings import resolve_mmdb_file

        views._maxmind_readers.clear()
        views._maxmind_reader_stats.clear()
        self.addCleanup(views._maxmind_readers.clear)
        self.addCleanup(views._maxmind_reader_stats.clear)

        with tempfile.TemporaryDirectory() as tmpdir:
            tool_root = Path(tmpdir) / "tool"
            flat_data_dir = tool_root / "data"
            nested_city_dir = flat_data_dir / "GeoLite2-City_20261114"
            nested_city_dir.mkdir(parents=True)
            country_file = flat_data_dir / "GeoLite2-Country.mmdb"
            city_file = nested_city_dir / "GeoLite2-City.mmdb"
            country_file.write_bytes(b"country-v1")
            city_file.write_bytes(b"city-v1")

            with patch.dict(os.environ, {"TOOL_DATA_DIR": str(tool_root)}):
                self.assertEqual(
                    resolve_mmdb_file("$TOOL_DATA_DIR/data", "GeoLite2-City.mmdb", tmpdir),
                    str(city_file),
                )
                self.assertEqual(
                    resolve_mmdb_file("", "GeoLite2-Country.mmdb", tmpdir),
                    str(country_file),
                )
                self.assertEqual(
                    resolve_mmdb_file("", "GeoLite2-City.mmdb", tmpdir),
                    str(city_file),
                )

            country_reader = MagicMock()
            country_reader.get.return_value = {
                "country": {"names": {"en": "China"}, "iso_code": "CN"},
            }
            city_v1_reader = MagicMock()
            city_v1_reader.get.return_value = {
                "country": {"names": {"en": "China"}, "iso_code": "CN"},
            }
            city_v2_reader = MagicMock()
            city_v2_reader.get.return_value = {
                "country": {"names": {"en": "China"}, "iso_code": "CN"},
                "subdivisions": [{"names": {"en": "Beijing"}, "iso_code": "BJ"}],
                "city": {"names": {"en": "Beijing"}},
                "location": {"latitude": 39.9075, "longitude": 116.3971},
            }
            country_open_paths = []
            city_open_paths = []

            def _open_sequence(path):
                path_str = str(path)
                if "city" in Path(path_str).name.lower():
                    reader = city_v1_reader if not city_open_paths else city_v2_reader
                    city_open_paths.append(path_str)
                    return reader
                country_open_paths.append(path_str)
                return country_reader

            fake_maxmind_module = MagicMock()
            fake_maxmind_module.open_database.side_effect = _open_sequence

            with (
                override_settings(
                    MAXMIND_DB_DIR=str(flat_data_dir),
                    CLOUD_CIDR_DB_PATH="",
                    HOSTING_ASN_RULES_PATH="",
                ),
                patch.dict("sys.modules", {"maxminddb": fake_maxmind_module}),
            ):
                row_before_update = views._read_maxmind_sync("1.2.3.4")
                self.assertEqual(row_before_update["location"], "China")

                # Replace the file on disk with a different size so the cached reader reopens cleanly
                city_file.write_bytes(b"city-v2-updated-bytes")
                row_after_update = views._read_maxmind_sync("1.2.3.4")
                self.assertEqual(row_after_update["location"], "Beijing, China (39.9075, 116.3971)")
                self.assertEqual(row_after_update["coordinates"], "39.9075, 116.3971")
                self.assertEqual(len(country_open_paths), 1)
                self.assertEqual(len(city_open_paths), 2)
                city_v1_reader.close.assert_called_once()

    @patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
    def test_stale_pre_city_maxmind_cache_refreshes_when_city_db_exists(self, mock_async_client_cls, mock_dns_resolve):
        views._maxmind_readers.clear()
        views._maxmind_reader_stats.clear()
        self.addCleanup(views._maxmind_readers.clear)
        self.addCleanup(views._maxmind_reader_stats.clear)

        target_ip = "1.2.3.4"
        cache_store = {}
        for provider_key, provider_name, _uses_http, _cooldown, _fn in views._PROVIDER_SPECS:
            row_payload = {
                "provider": provider_name,
                "status": "200 OK",
                "statusCode": 200,
                "asn": "AS137718",
                "isp": "Beijing Volcano Engine",
                "organisation": "Beijing Volcano Engine",
                "location": "China",
                "usageType": "isp",
                "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
                "countryCode": "CN",
                "rawJson": {"country": {"iso_code": "CN"}},
            }
            cache_store[f"proxycheck:v1:prov:{provider_key}:{target_ip}"] = json.dumps(
                {"row": row_payload, "cachedAt": "2026-11-14T08:00:00+00:00"}
            )
        cache_store[f"proxycheck:v1:prov:ptr:{target_ip}"] = json.dumps(
            {"hostname": "example.net", "status": "ok", "cachedAt": "2026-11-14T08:00:00+00:00"}
        )

        async def _fake_redis_set(key, value, ex=None):
            cache_store[key] = value

        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(side_effect=lambda k: cache_store.get(k))
        mock_redis.set = AsyncMock(side_effect=_fake_redis_set)
        _login_authorised(self)

        with tempfile.TemporaryDirectory() as tmpdir:
            mmdb_dir = Path(tmpdir)
            for fname in ("GeoLite2-Country.mmdb", "GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb"):
                (mmdb_dir / fname).write_bytes(b"stub")

            readers_by_path = {}
            country_reader = MagicMock()
            country_reader.get.return_value = {"country": {"names": {"en": "China"}, "iso_code": "CN"}}
            city_reader = MagicMock()
            city_reader.get.return_value = {
                "country": {"names": {"en": "China"}, "iso_code": "CN"},
                "subdivisions": [{"names": {"en": "Beijing"}, "iso_code": "BJ"}],
                "city": {"names": {"en": "Beijing"}},
                "location": {"latitude": 39.9075, "longitude": 116.3971},
            }
            asn_reader = MagicMock()
            asn_reader.get.return_value = {
                "autonomous_system_number": 137718,
                "autonomous_system_organization": "Beijing Volcano Engine",
            }
            readers_by_path[str(mmdb_dir / "GeoLite2-Country.mmdb")] = country_reader
            readers_by_path[str(mmdb_dir / "GeoLite2-City.mmdb")] = city_reader
            readers_by_path[str(mmdb_dir / "GeoLite2-ASN.mmdb")] = asn_reader

            fake_maxmind_module = MagicMock()
            fake_maxmind_module.open_database.side_effect = lambda p: readers_by_path[str(p)]

            with (
                override_settings(
                    MAXMIND_DB_DIR=str(mmdb_dir),
                    CLOUD_CIDR_DB_PATH="",
                    HOSTING_ASN_RULES_PATH="",
                ),
                patch.dict("sys.modules", {"maxminddb": fake_maxmind_module}),
                patch("detector.views.redis_client", mock_redis),
            ):
                first_resp = self.client.get(f"/api/v1/detect?ip={target_ip}")
                second_resp = self.client.get(f"/api/v1/detect?ip={target_ip}")

        self.assertEqual(first_resp.status_code, 200)
        first_payload = first_resp.json()
        first_mm = next(r for r in first_payload["results"] if r["provider"] == "MaxMind")
        self.assertEqual(first_mm["location"], "Beijing, China (39.9075, 116.3971)")
        self.assertEqual(first_mm["coordinates"], "39.9075, 116.3971")
        self.assertEqual(first_payload["cacheMeta"]["hitCount"], 15)

        cached_mm_wrapper = json.loads(cache_store[f"proxycheck:v1:prov:maxmind:{target_ip}"])
        self.assertTrue(cached_mm_wrapper["cityDbLoaded"])

        self.assertEqual(second_resp.status_code, 200)
        second_payload = second_resp.json()
        second_mm = next(r for r in second_payload["results"] if r["provider"] == "MaxMind")
        self.assertEqual(second_mm["location"], "Beijing, China (39.9075, 116.3971)")
        self.assertEqual(second_payload["cacheMeta"]["hitCount"], 16)
        self.assertEqual(city_reader.get.call_count, 1)
        mock_async_client_cls.assert_not_called()
        mock_dns_resolve.assert_not_called()

    def test_read_maxmind_sync_combines_get_with_prefix_len_without_duplicate_get(self):
        views._maxmind_readers.clear()
        views._maxmind_reader_stats.clear()
        self.addCleanup(views._maxmind_readers.clear)
        self.addCleanup(views._maxmind_reader_stats.clear)

        with tempfile.TemporaryDirectory() as tmpdir:
            country_db = Path(tmpdir) / "GeoLite2-Country.mmdb"
            country_db.write_bytes(b"stub")

            reader = MagicMock()
            reader.get_with_prefix_len.return_value = ({"country": {"iso_code": "US"}}, 24)
            fake_maxmind_module = MagicMock()
            fake_maxmind_module.open_database.return_value = reader

            with (
                override_settings(
                    MAXMIND_DB_DIR=str(tmpdir),
                    CLOUD_CIDR_DB_PATH="",
                    HOSTING_ASN_RULES_PATH="",
                    HOSTING_ASNS=(),
                    HOSTING_ORG_KEYWORDS=(),
                ),
                patch.dict("sys.modules", {"maxminddb": fake_maxmind_module}),
            ):
                row = views._read_maxmind_sync("198.51.100.42")

        reader.get_with_prefix_len.assert_called_once_with("198.51.100.42")
        reader.get.assert_not_called()
        self.assertEqual(row["status"], "200 OK")
        self.assertEqual(row["countryCode"], "US")
        self.assertEqual(row["prefixLength"], 24)
        self.assertEqual(views._extract_mmdb_prefix_len(reader, "198.51.100.42"), 24)

        # Unmapped record with routing prefix still avoids redundant reader.get
        null_rec_reader = MagicMock()
        null_rec_reader.get_with_prefix_len.return_value = (None, 20)
        rec, prefix_len = views._lookup_mmdb_record_and_prefix(null_rec_reader, "198.51.100.42")
        self.assertIsNone(rec)
        self.assertEqual(prefix_len, 20)
        null_rec_reader.get.assert_not_called()

        # Distinct reader.get mock return value remains respected when configured separately
        custom_get_reader = MagicMock()
        custom_get_reader.get.return_value = {"country": {"iso_code": "CA"}}
        custom_get_reader.get_with_prefix_len.return_value = ({"country": {"iso_code": "US"}}, 25)
        rec_custom, prefix_custom = views._lookup_mmdb_record_and_prefix(custom_get_reader, "198.51.100.42")
        self.assertEqual(rec_custom, {"country": {"iso_code": "CA"}})
        self.assertEqual(prefix_custom, 25)
        custom_get_reader.get.assert_called_once_with("198.51.100.42")

    def test_read_maxmind_sync_warms_offline_caches_when_mmdb_missing(self):
        from detector import adapters as detector_adapters

        clear_offline_intelligence_caches()
        self.assertFalse(detector_adapters.are_offline_intelligence_caches_warm())

        with tempfile.TemporaryDirectory() as tmpdir:
            empty_mmdb_dir = Path(tmpdir) / "empty_mmdb"
            empty_mmdb_dir.mkdir()
            cidr_file = Path(tmpdir) / "cloud_cidrs.json"
            cidr_file.write_text(json.dumps([{"range": "54.239.28.64/26", "provider": "Amazon AWS"}]), encoding="utf-8")
            rules_file = Path(tmpdir) / "hosting_asn_rules.json"
            rules_file.write_text(
                json.dumps({"hosts": [{"name": "Example Cloud", "asn": 64510}]}),
                encoding="utf-8",
            )

            with override_settings(
                MAXMIND_DB_DIR=str(empty_mmdb_dir),
                CLOUD_CIDR_DB_PATH=str(cidr_file),
                HOSTING_ASN_RULES_PATH=str(rules_file),
                HOSTING_ASNS=(),
                HOSTING_ORG_KEYWORDS=(),
            ):
                missing_row = views._read_maxmind_sync("54.239.28.85")

        self.assertEqual(missing_row["status"], "Database Missing")
        self.assertTrue(detector_adapters.are_offline_intelligence_caches_warm())

    def test_execute_detection_with_cache_warms_offline_rules_off_event_loop(self):
        from detector import adapters as detector_adapters

        clear_offline_intelligence_caches()
        target_ip = "54.239.28.85"
        is_ipv4 = True
        cached_providers = {}
        for provider_key, provider_name, _uses_http, _cooldown, _fn in views._PROVIDER_SPECS:
            if not views._is_provider_cache_expected(provider_key, is_ipv4):
                continue
            cached_providers[provider_key] = (
                {
                    "provider": provider_name,
                    "status": "200 OK",
                    "statusCode": 200,
                    "asn": "AS16509",
                    "isp": "Amazon.com, Inc.",
                    "organisation": "Amazon.com, Inc.",
                    "location": "United States",
                    "usageType": "hosting",
                    "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
                    "countryCode": "US",
                    "rawJson": {},
                },
                "2026-11-16T00:00:00+00:00",
            )
        initial_cache = (cached_providers, (None, "2026-11-16T00:00:00+00:00"))

        with tempfile.TemporaryDirectory() as tmpdir:
            cidr_file = Path(tmpdir) / "cloud_cidrs.json"
            cidr_file.write_text(json.dumps([{"range": "54.239.28.64/26", "provider": "Amazon AWS"}]), encoding="utf-8")
            rules_file = Path(tmpdir) / "hosting_asn_rules.json"
            rules_file.write_text(json.dumps({"hosts": []}), encoding="utf-8")

            original_warm = detector_adapters.warm_offline_intelligence_caches
            warm_threads = []
            event_loop_thread_id = None

            def _tracked_warm():
                warm_threads.append(threading.get_ident())
                return original_warm()

            async def _run():
                nonlocal event_loop_thread_id
                event_loop_thread_id = threading.get_ident()
                first_payload = await views._execute_detection_with_cache(
                    target_ip,
                    initial_cache=initial_cache,
                )
                second_payload = await views._execute_detection_with_cache(
                    target_ip,
                    initial_cache=initial_cache,
                )
                return first_payload, second_payload

            with (
                override_settings(
                    CLOUD_CIDR_DB_PATH=str(cidr_file),
                    HOSTING_ASN_RULES_PATH=str(rules_file),
                    HOSTING_ASNS=(),
                    HOSTING_ORG_KEYWORDS=(),
                ),
                patch("detector.views.redis_client", None),
                patch("detector.views.warm_offline_intelligence_caches", side_effect=_tracked_warm),
            ):
                first_payload, second_payload = asyncio.run(_run())

        self.assertEqual(len(warm_threads), 1)
        self.assertNotEqual(warm_threads[0], event_loop_thread_id)
        self.assertTrue(detector_adapters.are_offline_intelligence_caches_warm())
        self.assertEqual(first_payload["cloudCidr"], "54.239.28.64/26")
        self.assertEqual(first_payload["cloudProvider"], "Amazon AWS")
        self.assertEqual(second_payload["cloudCidr"], "54.239.28.64/26")

    def test_should_refresh_cached_maxmind_entry_respects_city_db_loaded_flag(self):
        views._maxmind_city_db_cache = None
        self.addCleanup(setattr, views, "_maxmind_city_db_cache", None)

        base_row = {
            "provider": "MaxMind",
            "status": "200 OK",
            "statusCode": 200,
            "asn": "AS137718",
            "isp": "Beijing Volcano Engine",
            "organisation": "Beijing Volcano Engine",
            "location": "China",
            "usageType": "isp",
            "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
            "countryCode": "CN",
            "rawJson": {"country": {"iso_code": "CN"}},
        }
        raw_loaded_true = json.dumps(
            {
                "row": base_row,
                "cachedAt": "2026-11-16T00:00:00+00:00",
                "sanitized": True,
                "cityDbLoaded": True,
            }
        )
        raw_loaded_false = json.dumps(
            {
                "row": base_row,
                "cachedAt": "2026-11-16T00:00:00+00:00",
                "sanitized": True,
                "cityDbLoaded": False,
            }
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            city_db = Path(tmpdir) / "GeoLite2-City.mmdb"
            city_db.write_bytes(b"stub")

            with override_settings(MAXMIND_DB_DIR=str(tmpdir)):
                with patch("detector.views.json.loads", wraps=json.loads) as spy_loads:
                    decoded_true = views._decode_cached_provider_entry(raw_loaded_true)
                    self.assertIsNotNone(decoded_true)
                    self.assertEqual(set(decoded_true[0].keys()), set(base_row.keys()))
                    should_refresh_true = views._should_refresh_cached_maxmind_entry(
                        raw_loaded_true,
                        decoded_true[0],
                    )
                    self.assertFalse(should_refresh_true)
                    self.assertEqual(spy_loads.call_count, 1)

                with patch("detector.views.json.loads", wraps=json.loads) as spy_loads:
                    decoded_false = views._decode_cached_provider_entry(raw_loaded_false)
                    self.assertIsNotNone(decoded_false)
                    self.assertEqual(set(decoded_false[0].keys()), set(base_row.keys()))
                    should_refresh_false = views._should_refresh_cached_maxmind_entry(
                        raw_loaded_false,
                        decoded_false[0],
                    )
                    self.assertTrue(should_refresh_false)
                    self.assertEqual(spy_loads.call_count, 1)

                # Direct calls with a plain dictionary preserve original fallback decoding
                self.assertFalse(views._should_refresh_cached_maxmind_entry(raw_loaded_true, dict(base_row)))
                self.assertTrue(views._should_refresh_cached_maxmind_entry(raw_loaded_false, dict(base_row)))

                # Repeated checks within the TTL window reuse the cached city DB presence result
                views._maxmind_city_db_cache = None
                with patch("detector.views._resolve_db_file", wraps=views._resolve_db_file) as spy_resolve:
                    self.assertTrue(views._has_local_maxmind_city_db())
                    self.assertTrue(views._has_local_maxmind_city_db())
                    self.assertEqual(spy_resolve.call_count, 1)

        with patch("detector.views.os.path.exists", return_value=False):
            self.assertFalse(views._has_local_maxmind_city_db())
            self.assertFalse(views._should_refresh_cached_maxmind_entry(raw_loaded_false, dict(base_row)))

    def test_async_resolver_and_proc_rss_hot_path_caches(self):
        from unittest.mock import mock_open

        views._cached_async_resolvers.clear()
        self.addCleanup(views._cached_async_resolvers.clear)

        with override_settings(DNS_QUERY_TIMEOUT_SECONDS=2.0, DNS_QUERY_LIFETIME_SECONDS=2.0):
            first_resolver = views._create_async_resolver()
            second_resolver = views._create_async_resolver()
            self.assertIs(first_resolver, second_resolver)

        with override_settings(DNS_QUERY_TIMEOUT_SECONDS=1.5, DNS_QUERY_LIFETIME_SECONDS=3.0):
            custom_resolver = views._create_async_resolver()
            self.assertEqual(custom_resolver.timeout, 1.5)
            self.assertEqual(custom_resolver.lifetime, 3.0)
            self.assertIs(custom_resolver, views._create_async_resolver())

        views._proc_rss_cache = None
        self.addCleanup(setattr, views, "_proc_rss_cache", None)

        with (
            patch("builtins.open", mock_open(read_data="4096 2048 0 0 0 0 0\n")),
            patch.object(views.os, "sysconf", return_value=4096, create=True),
        ):
            sampled_rss = views._read_proc_rss_mb()
        self.assertEqual(sampled_rss, 8.0)

        # Unmocked call within one second returns the cached RSS sample without opening procfs
        self.assertEqual(views._read_proc_rss_mb(), 8.0)

        # Mocking builtins.open bypasses the cached sample immediately
        with patch("builtins.open", side_effect=OSError("procfs unavailable")):
            self.assertIsNone(views._read_proc_rss_mb())


class FlagBasedArbitrationTests(SimpleTestCase):
    """Tests for flag and Proxycheck risk arbitrage."""

    @staticmethod
    def _clean_row(provider: str) -> dict:
        return {
            "provider": provider,
            "status": "200 OK",
            "statusCode": 200,
            "asn": "AS7922",
            "isp": "Comcast",
            "organisation": "Comcast",
            "location": "United States",
            "usageType": "isp",
            "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
            "countryCode": "US",
            "rawJson": {},
        }

    def test_arbitration_uses_flags_and_proxycheck_risk_score(self):
        clean_sources = [
            self._clean_row("IPHunter"),
            self._clean_row("AbuseIPDB"),
            self._clean_row("IPData"),
            self._clean_row("IPRegistry"),
            self._clean_row("IP2Location"),
        ]

        # A single hosting tag with no behavioral signal is dismissed as a minor attribute dispute
        isolated_hosting = self._clean_row("IPHub")
        isolated_hosting["usageType"] = "hosting"
        isolated_hosting["securityFlags"] = [{"label": "Hosting", "isHighRisk": True}]
        outlier_result = views.aggregate_intelligence_metrics("8.8.8.8", [*clean_sources, isolated_hosting])
        self.assertEqual(outlier_result["arbitrationTier"], "success")
        self.assertEqual(outlier_result["arbitrationVerdict"], "Clean Residential (1 Minor Attribute Dispute)")
        self.assertFalse(outlier_result["isMajorityProxyVpn"])

        # Proxycheck riskScore counts as a behavioral signal and prevents outlier dismissal
        risky_hosting = self._clean_row("Proxycheck")
        risky_hosting["usageType"] = "hosting"
        risky_hosting["securityFlags"] = [{"label": "Hosting", "isHighRisk": True}]
        risky_hosting["riskScore"] = 82
        disputed_result = views.aggregate_intelligence_metrics("8.8.8.8", [*clean_sources, risky_hosting])
        self.assertEqual(disputed_result["arbitrationTier"], "warning")
        self.assertIn("(1/6 Sources)", disputed_result["arbitrationVerdict"])
        self.assertNotIn("Clean Residential", disputed_result["arbitrationVerdict"])

        # Majority high-risk anonymizer flags trigger the destructive confirmed verdict
        proxy_rows = [
            {
                **self._clean_row(name),
                "securityFlags": [{"label": "Proxy", "isHighRisk": True}],
            }
            for name in ("IPData", "IPRegistry", "Proxycheck")
        ]
        confirmed_result = views.aggregate_intelligence_metrics("8.8.8.8", [self._clean_row("IPHub"), *proxy_rows])
        self.assertTrue(confirmed_result["isMajorityProxyVpn"])
        self.assertEqual(confirmed_result["arbitrationTier"], "destructive")
        self.assertIn("Confirmed Proxy", confirmed_result["arbitrationVerdict"])


class _FakeRedisPipeline:
    """Queued command pipeline mirroring redis.asyncio pipeline execution."""

    def __init__(self, store):
        self._store = store
        self._ops = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def _queue(self, name, *args, **kwargs):
        self._ops.append((name, args, kwargs))
        return self

    def get(self, *args, **kwargs):
        return self._queue("get", *args, **kwargs)

    def set(self, *args, **kwargs):
        return self._queue("set", *args, **kwargs)

    def ttl(self, *args, **kwargs):
        return self._queue("ttl", *args, **kwargs)

    def incr(self, *args, **kwargs):
        return self._queue("incr", *args, **kwargs)

    def decr(self, *args, **kwargs):
        return self._queue("decr", *args, **kwargs)

    def expire(self, *args, **kwargs):
        return self._queue("expire", *args, **kwargs)

    def hincrby(self, *args, **kwargs):
        return self._queue("hincrby", *args, **kwargs)

    def hset(self, *args, **kwargs):
        return self._queue("hset", *args, **kwargs)

    def hgetall(self, *args, **kwargs):
        return self._queue("hgetall", *args, **kwargs)

    async def execute(self):
        results = []
        for name, args, kwargs in self._ops:
            results.append(await getattr(self._store, name)(*args, **kwargs))
        self._ops.clear()
        return results


class FakeAsyncRedis:
    """In-memory async Redis double supporting quota buckets, hashes, TTLs, and pipelines."""

    def __init__(self):
        self.strings = {}
        self.hashes = {}
        self.ttls = {}

    async def get(self, key):
        return self.strings.get(key)

    async def set(self, key, value, ex=None):
        self.strings[key] = str(value)
        if ex is not None:
            self.ttls[key] = int(ex)
        return True

    async def ttl(self, key):
        if key not in self.strings and key not in self.hashes:
            return -2
        return self.ttls.get(key, -1)

    async def incr(self, key, amount=1):
        current = int(self.strings.get(key, "0"))
        updated = current + int(amount)
        self.strings[key] = str(updated)
        return updated

    async def decr(self, key, amount=1):
        current = int(self.strings.get(key, "0"))
        updated = current - int(amount)
        self.strings[key] = str(updated)
        return updated

    async def expire(self, key, seconds):
        if key not in self.strings and key not in self.hashes:
            return 0
        self.ttls[key] = int(seconds)
        return 1

    async def hincrby(self, key, field, amount=1):
        bucket = self.hashes.setdefault(key, {})
        updated = int(bucket.get(field, "0")) + int(amount)
        bucket[field] = str(updated)
        return updated

    async def hset(self, key, mapping=None, **kwargs):
        bucket = self.hashes.setdefault(key, {})
        merged = {}
        if mapping:
            merged.update(mapping)
        merged.update(kwargs)
        for field, val in merged.items():
            bucket[str(field)] = str(val)
        return len(merged)

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def pipeline(self, transaction=True):
        return _FakeRedisPipeline(self)


class ProactiveQuotaAndTelemetryTests(TestCase):
    """Tests for multi-window proactive quota protection, anonymised telemetry, and admin dashboard access."""

    def setUp(self):
        views._http_client_instance = None
        views._http_client_loop = None

    def tearDown(self):
        views._http_client_instance = None
        views._http_client_loop = None

    @staticmethod
    def _build_provider_http_response(url, ip="8.8.8.8"):
        if "cloudflare.com" in url:
            return _mock_response(
                status_code=200,
                json_value={
                    "success": True,
                    "result": {"ip": {"asn": "15169", "asnName": "Google LLC", "asnLocation": "US"}},
                },
            )
        if "abuseipdb.com" in url:
            resp = _mock_response(
                status_code=200,
                json_value={
                    "data": {
                        "isp": "Google LLC",
                        "countryCode": "US",
                        "usageType": "Data Center",
                        "abuseConfidenceScore": 0,
                    }
                },
            )
            resp.headers = {"X-RateLimit-Remaining": "982", "X-RateLimit-Limit": "1000"}
            return resp
        if "ipdata.co" in url:
            return _mock_response(
                status_code=200,
                json_value={
                    "asn": {"asn": "AS15169", "name": "Google LLC"},
                    "country_name": "United States",
                    "country_code": "US",
                    "threat": {},
                    "count": "142",
                },
            )
        if "ipregistry.co" in url:
            resp = _mock_response(
                status_code=200,
                json_value={
                    "company": {"name": "Google LLC"},
                    "connection": {"asn": 15169, "type": "isp"},
                    "location": {"country": {"name": "United States", "code": "US"}},
                    "security": {},
                },
            )
            resp.headers = {"RateLimit-Remaining": "4950"}
            return resp
        if "ip2location.io" in url:
            return _mock_response(
                status_code=200,
                json_value={
                    "asn": "15169",
                    "as": "Google LLC",
                    "country_name": "United States",
                    "country_code": "US",
                    "usage_type": "DCH",
                    "is_proxy": False,
                },
            )
        if "getipintel.net" in url:
            return _mock_response(status_code=200, json_value={"status": "success", "result": "0.02"})
        if "proxycheck.io" in url:
            return _mock_response(
                status_code=200,
                json_value={
                    "status": "ok",
                    ip: {
                        "asn": "AS15169",
                        "provider": "Google LLC",
                        "country": "United States",
                        "isocode": "US",
                        "proxy": "no",
                    },
                },
            )
        if "iphub.info" in url:
            return _mock_response(
                status_code=200,
                json_value={
                    "asn": 15169,
                    "isp": "Google LLC",
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
                    "data": {"isp": "Google LLC", "country_name": "United States", "country_code": "US", "block": 0},
                },
            )
        if "onionoo.torproject.org" in url:
            return _mock_response(status_code=200, json_value={"relays": []})
        if "stopforumspam.org" in url:
            return _mock_response(
                status_code=200, json_value={"success": 1, "ip": {"appears": 0, "frequency": 0, "confidence": 0.0}}
            )
        if "sans.edu" in url or "dshield" in url:
            return _mock_response(
                status_code=200,
                json_value={"ip": {"count": 0, "attacks": 0, "as": "15169", "asname": "Google LLC", "ascountry": "US"}},
            )
        return _mock_response(status_code=404, json_value={})

    @staticmethod
    def _clean_dns_side_effect(qname, rdtype):
        if rdtype == "PTR":
            answer = MagicMock()
            answer.__str__ = lambda self: "dns.google."
            return [answer]
        raise views.dns.resolver.NXDOMAIN()

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

    def test_refund_consumed_quota_clamps_at_zero_and_fails_open_on_redis_error(self):
        from datetime import datetime, timezone

        from asgiref.sync import async_to_sync

        from detector import quota_telemetry

        fake_redis = FakeAsyncRedis()
        sample_dt = datetime(2026, 11, 16, 5, 30, tzinfo=timezone.utc)
        min_key = quota_telemetry._quota_minute_key("getipintel", sample_dt)
        day_key = quota_telemetry._quota_daily_key("getipintel", sample_dt)

        with patch("detector.views.redis_client", fake_redis):
            quota_res = async_to_sync(quota_telemetry.check_and_consume_quota)("getipintel", now_dt=sample_dt)
            self.assertTrue(quota_res.allowed)
            self.assertEqual(fake_redis.strings[min_key], "1")
            self.assertEqual(fake_redis.strings[day_key], "1")

            # First refund decrements counters from 1 to 0
            async_to_sync(quota_telemetry.refund_consumed_quota)("getipintel", now_dt=sample_dt)
            self.assertEqual(fake_redis.strings[min_key], "0")
            self.assertEqual(fake_redis.strings[day_key], "0")

            # Repeated refund on zeroed counters must clamp back to 0 rather than going negative
            async_to_sync(quota_telemetry.refund_consumed_quota)("getipintel", now_dt=sample_dt)
            self.assertEqual(fake_redis.strings[min_key], "0")
            self.assertEqual(fake_redis.strings[day_key], "0")

            # Unknown provider keys are ignored without writing Redis keys
            async_to_sync(quota_telemetry.refund_consumed_quota)("unknown_provider", now_dt=sample_dt)
            self.assertFalse(any("unknown_provider" in k for k in fake_redis.strings))

        failing_client = MagicMock()
        failing_client.pipeline = MagicMock(side_effect=ConnectionError("redis offline"))
        with patch("detector.views.redis_client", failing_client):
            async_to_sync(quota_telemetry.refund_consumed_quota)("getipintel", now_dt=sample_dt)


class _BatchingFakeRedis(FakeAsyncRedis):
    """In-memory Redis double that records single reads, batch reads and pipeline flushes."""

    def __init__(self):
        super().__init__()
        self.get_calls = []
        self.mget_calls = []
        self.pipeline_calls = []

    async def get(self, key):
        self.get_calls.append(key)
        return await super().get(key)

    async def mget(self, keys):
        self.mget_calls.append(list(keys))
        return [self.strings.get(key) for key in keys]

    def pipeline(self, transaction=True):
        self.pipeline_calls.append(transaction)
        return super().pipeline(transaction=transaction)


class RedisBatchingAndCacheCompletenessTests(TestCase):
    """Tests for batched Redis reads and writes and for the full cache hit check on partial source sets."""

    IPV6_TARGET = "2001:4860:4860::8888"

    def setUp(self):
        views._http_client_instance = None
        views._http_client_loop = None

    def tearDown(self):
        views._http_client_instance = None
        views._http_client_loop = None

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

    async def test_mget_reads_all_keys_in_one_round_trip(self):
        fake_redis = _BatchingFakeRedis()
        fake_redis.strings["proxycheck:v1:prov:ipdata:8.8.8.8"] = "cached-ipdata"
        fake_redis.strings["proxycheck:v1:prov:ptr:8.8.8.8"] = b"cached-ptr"
        keys = [
            "proxycheck:v1:prov:ipdata:8.8.8.8",
            "proxycheck:v1:prov:iphub:8.8.8.8",
            "proxycheck:v1:prov:ptr:8.8.8.8",
        ]

        with patch("detector.views.redis_client", fake_redis):
            values = await views._safe_redis_mget(keys)

        self.assertEqual(values, ["cached-ipdata", None, "cached-ptr"])
        self.assertEqual(fake_redis.mget_calls, [keys])
        self.assertEqual(fake_redis.get_calls, [])

    async def test_mget_falls_back_to_single_reads_for_get_only_mocks(self):
        cache_store = {"proxycheck:v1:prov:ipdata:8.8.8.8": "cached-ipdata"}
        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(side_effect=lambda key: cache_store.get(key))
        keys = ["proxycheck:v1:prov:ipdata:8.8.8.8", "proxycheck:v1:prov:iphub:8.8.8.8"]

        with patch("detector.views.redis_client", mock_redis):
            values = await views._safe_redis_mget(keys)

        self.assertEqual(values, ["cached-ipdata", None])
        self.assertEqual(sorted(call.args[0] for call in mock_redis.get.await_args_list), sorted(keys))

    async def test_mget_falls_back_when_client_has_no_mget(self):
        fake_redis = FakeAsyncRedis()
        fake_redis.strings["proxycheck:v1:prov:ipdata:8.8.8.8"] = "cached-ipdata"

        with patch("detector.views.redis_client", fake_redis):
            values = await views._safe_redis_mget(
                ["proxycheck:v1:prov:ipdata:8.8.8.8", "proxycheck:v1:prov:iphub:8.8.8.8"]
            )

        self.assertEqual(values, ["cached-ipdata", None])

    async def test_mget_degrades_to_empty_values_on_connection_errors(self):
        mock_redis = MagicMock()
        mock_redis.mget = AsyncMock(side_effect=redis.exceptions.ConnectionError("redis offline"))
        mock_redis.get = AsyncMock(return_value="should-not-be-read")
        keys = ["proxycheck:v1:prov:ipdata:8.8.8.8", "proxycheck:v1:prov:iphub:8.8.8.8"]

        with (
            patch("detector.views.redis_client", mock_redis),
            self.assertLogs("detector.views", level="WARNING") as logs,
        ):
            values = await views._safe_redis_mget(keys)

        self.assertEqual(values, [None, None])
        mock_redis.get.assert_not_awaited()
        self.assertTrue(any("redis offline" in line for line in logs.output))

    async def test_mget_without_client_or_keys_returns_empty_values(self):
        with patch("detector.views.redis_client", None):
            self.assertEqual(await views._safe_redis_mget(["a", "b"]), [None, None])
        with patch("detector.views.redis_client", _BatchingFakeRedis()):
            self.assertEqual(await views._safe_redis_mget([]), [])

    async def test_set_many_flushes_entries_through_one_pipeline(self):
        fake_redis = _BatchingFakeRedis()
        entries = [
            ("proxycheck:v1:prov:ipdata:8.8.8.8", "row-a", 3600),
            ("proxycheck:v1:cooldown:iphub", "cooldown-b", 120),
        ]

        with patch("detector.views.redis_client", fake_redis):
            await views._safe_redis_set_many(entries)

        self.assertEqual(fake_redis.pipeline_calls, [False])
        self.assertEqual(fake_redis.strings["proxycheck:v1:prov:ipdata:8.8.8.8"], "row-a")
        self.assertEqual(fake_redis.strings["proxycheck:v1:cooldown:iphub"], "cooldown-b")
        self.assertEqual(fake_redis.ttls["proxycheck:v1:prov:ipdata:8.8.8.8"], 3600)
        self.assertEqual(fake_redis.ttls["proxycheck:v1:cooldown:iphub"], 120)

    async def test_set_many_falls_back_to_single_writes_for_set_only_mocks(self):
        mock_redis = MagicMock()
        mock_redis.set = AsyncMock()
        entries = [
            ("proxycheck:v1:prov:ipdata:8.8.8.8", "row-a", 3600),
            ("proxycheck:v1:prov:ptr:8.8.8.8", "row-b", 900),
        ]

        with patch("detector.views.redis_client", mock_redis):
            await views._safe_redis_set_many(entries)

        written = {call.args[0]: (call.args[1], call.kwargs["ex"]) for call in mock_redis.set.await_args_list}
        self.assertEqual(
            written,
            {
                "proxycheck:v1:prov:ipdata:8.8.8.8": ("row-a", 3600),
                "proxycheck:v1:prov:ptr:8.8.8.8": ("row-b", 900),
            },
        )

    async def test_set_many_logs_and_skips_writes_when_pipeline_fails(self):
        failing_pipe = MagicMock()
        failing_pipe.execute = AsyncMock(side_effect=redis.exceptions.TimeoutError("redis timed out"))
        mock_redis = MagicMock()
        mock_redis.pipeline = MagicMock(return_value=failing_pipe)
        mock_redis.set = AsyncMock()

        with (
            patch("detector.views.redis_client", mock_redis),
            self.assertLogs("detector.views", level="WARNING") as logs,
        ):
            await views._safe_redis_set_many([("proxycheck:v1:prov:ipdata:8.8.8.8", "row-a", 3600)])

        mock_redis.set.assert_not_awaited()
        self.assertTrue(any("redis timed out" in line for line in logs.output))

    async def test_read_provider_caches_uses_single_mget(self):
        fake_redis = _BatchingFakeRedis()
        fake_redis.strings["proxycheck:v1:prov:ipdata:8.8.8.8"] = self._cached_row_entry("IPData")

        with patch("detector.views.redis_client", fake_redis):
            cached_providers, cached_ptr = await views._read_provider_caches("8.8.8.8")

        self.assertEqual(list(cached_providers), ["ipdata"])
        self.assertIsNone(cached_ptr)
        self.assertEqual(len(fake_redis.mget_calls), 1)
        self.assertEqual(len(fake_redis.mget_calls[0]), len(views._PROVIDER_SPECS) + 1)
        self.assertEqual(fake_redis.get_calls, [])

    @override_settings(**{**TEST_UPSTREAM_SECRETS, "IPHUNTER_API_KEY": ""})
    def test_provider_cache_expectation_skips_dnsbl_on_ipv6_and_unconfigured_sources(self):
        with patch("detector.views._has_any_local_maxmind_db", return_value=True):
            self.assertTrue(views._is_provider_cache_expected("spamhaus_zen", True))
            self.assertFalse(views._is_provider_cache_expected("spamhaus_zen", False))
            self.assertFalse(views._is_provider_cache_expected("spamcop", False))
            self.assertFalse(views._is_provider_cache_expected("iphunter", True))
            self.assertTrue(views._is_provider_cache_expected("ipdata", False))
            self.assertTrue(views._is_provider_cache_expected("tor_onionoo", False))
            self.assertTrue(views._is_provider_cache_expected("maxmind", False))
        with patch("detector.views._has_any_local_maxmind_db", return_value=False):
            self.assertFalse(views._is_provider_cache_expected("maxmind", True))

    @override_settings(**{**TEST_UPSTREAM_SECRETS, "IPHUNTER_API_KEY": ""})
    @patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock)
    def test_ipv6_with_all_expected_sources_cached_takes_full_hit_fast_path(self, mock_dns_resolve):
        target_ip = views.canonicalize_ip(self.IPV6_TARGET)
        uncached_keys = {"spamhaus_zen", "spamcop", "iphunter", "maxmind"}
        cache_store = {}
        for provider_key, provider_name, _, _, _ in views._PROVIDER_SPECS:
            if provider_key not in uncached_keys:
                cache_store[views._provider_cache_key(provider_key, target_ip)] = self._cached_row_entry(provider_name)
        cache_store[views._provider_cache_key("ptr", target_ip)] = json.dumps(
            {"hostname": "dns.google", "status": "ok", "cachedAt": "2026-11-13T08:30:00+00:00"}
        )

        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(side_effect=lambda key: cache_store.get(key))
        mock_redis.set = AsyncMock()
        shared_client = AsyncMock()
        _login_authorised(self)

        with (
            patch("detector.views.redis_client", mock_redis),
            patch("detector.views._has_any_local_maxmind_db", return_value=False),
            patch("detector.views._has_any_local_stopforumspam_db", return_value=True),
            patch("detector.views.query_maxmind", AsyncMock(return_value=dict(MAXMIND_STUB))),
            patch("detector.views._get_shared_http_client", shared_client),
            patch("detector.views._release_inflight_task", wraps=views._release_inflight_task) as release_spy,
        ):
            response = self.client.get(f"/api/v1/detect?ip={self.IPV6_TARGET}")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["isCached"])
        self.assertEqual(payload["cacheMeta"]["status"], "hit")
        self.assertFalse(payload["cacheMeta"]["isPartial"])
        self.assertEqual(payload["cacheMeta"]["missCount"], 0)
        self.assertEqual(payload["cacheMeta"]["cooldownCount"], 0)
        expected_hits = len(views._PROVIDER_SPECS) - len(uncached_keys) + 1
        self.assertEqual(payload["cacheMeta"]["hitCount"], expected_hits)
        self.assertEqual(payload["ptrHostname"], "dns.google")

        # The fast path runs through exactly one coalesced task, which is released by both its finally block
        # and its done callback, and it never builds the HTTP client or reads cooldowns
        released_calls = [call.args for call in release_spy.call_args_list]
        self.assertEqual(len(released_calls), 2)
        self.assertEqual({task_key for task_key, _ in released_calls}, {(target_ip, "full")})
        self.assertEqual(len({released_task for _, released_task in released_calls}), 1)
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


class BatchDetectionEndpointTests(TestCase):
    """Tests for the batch IP detection endpoint covering authentication, validation, CORS, and mixed IP lookups."""

    def setUp(self):
        views._ip_detect_inflight.clear()
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)

    def tearDown(self):
        views._ip_detect_inflight.clear()

    @staticmethod
    def _stub_provider(name: str) -> dict:
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

    def _patch_all_providers(self):
        provider_map = (
            ("detector.views.query_cloudflare_radar", "Cloudflare Radar"),
            ("detector.views.query_abuseipdb", "AbuseIPDB"),
            ("detector.views.query_ipdata", "IPData"),
            ("detector.views.query_ipregistry", "IPRegistry"),
            ("detector.views.query_ip2location", "IP2Location"),
            ("detector.views.query_getipintel", "GetIPIntel"),
            ("detector.views.query_proxycheck", "Proxycheck"),
            ("detector.views.query_iphub", "IPHub"),
            ("detector.views.query_iphunter", "IPHunter"),
            ("detector.views.query_maxmind", "MaxMind"),
            ("detector.views.query_tor_onionoo", "Tor Onionoo"),
            ("detector.views.query_stopforumspam", "StopForumSpam"),
            ("detector.views.query_dshield", "DShield"),
        )
        for target, name in provider_map:
            patcher = patch(target, new_callable=AsyncMock, return_value=self._stub_provider(name))
            patcher.start()
            self.addCleanup(patcher.stop)

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

    @patch("detector.views.redis_client", None)
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
        self.assertEqual(len(public_v4["results"]), 14)

        public_v6 = payload["results"]["2001:4860:4860::8888"]
        self.assertEqual(public_v6["ip"], "2001:4860:4860::8888")
        self.assertFalse(public_v6.get("isNonPublic", False))
        self.assertEqual(len(public_v6["results"]), 14)

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
        views._ip_detect_inflight.clear()
        views._http_client_instance = None
        views._http_client_loop = None
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)

    def tearDown(self):
        views._ip_detect_inflight.clear()
        views._http_client_instance = None
        views._http_client_loop = None

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

    def _patch_all_providers(self):
        provider_map = (
            ("detector.views.query_cloudflare_radar", "Cloudflare Radar"),
            ("detector.views.query_abuseipdb", "AbuseIPDB"),
            ("detector.views.query_ipdata", "IPData"),
            ("detector.views.query_ipregistry", "IPRegistry"),
            ("detector.views.query_ip2location", "IP2Location"),
            ("detector.views.query_getipintel", "GetIPIntel"),
            ("detector.views.query_proxycheck", "Proxycheck"),
            ("detector.views.query_iphub", "IPHub"),
            ("detector.views.query_iphunter", "IPHunter"),
            ("detector.views.query_maxmind", "MaxMind"),
            ("detector.views.query_tor_onionoo", "Tor Onionoo"),
            ("detector.views.query_stopforumspam", "StopForumSpam"),
            ("detector.views.query_dshield", "DShield"),
        )
        for target, name in provider_map:
            patcher = patch(target, new_callable=AsyncMock, return_value=self._stub_provider(name))
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_strip_raw_json_from_payload_helper_does_not_mutate_input(self):
        original_row = {"provider": "IPData", "status": "200 OK", "rawJson": {"count": "5"}}
        original_payload = {"ip": "8.8.8.8", "results": [original_row, "non-dict-row"]}

        stripped = views._strip_raw_json_from_payload(original_payload)

        self.assertIsNot(stripped, original_payload)
        self.assertIsNot(stripped["results"], original_payload["results"])
        self.assertIsNot(stripped["results"][0], original_row)
        self.assertNotIn("rawJson", stripped["results"][0])
        self.assertEqual(stripped["results"][0]["provider"], "IPData")
        self.assertEqual(stripped["results"][1], "non-dict-row")
        self.assertIn("rawJson", original_row)

        no_results_payload = {"ip": "8.8.8.8"}
        self.assertEqual(views._strip_raw_json_from_payload(no_results_payload), no_results_payload)

    @patch("detector.views.redis_client", None)
    def test_detect_ip_compact_strips_raw_json_and_sets_cache_control_header(self):
        self._patch_all_providers()
        _login_authorised(self)

        for query_suffix in ("&compact=1", "&compact=true", "&compact=TRUE", "&compact=yes"):
            with self.subTest(query_suffix=query_suffix):
                resp = self.client.get(f"/api/v1/detect?ip=8.8.8.8{query_suffix}")
                self.assertEqual(resp.status_code, 200)
                self.assertEqual(resp.headers.get("Cache-Control"), "private, max-age=300")
                payload = resp.json()
                self.assertEqual(len(payload["results"]), 14)
                for row in payload["results"]:
                    self.assertNotIn("rawJson", row)

        for query_suffix in ("", "&compact=0", "&compact=false"):
            with self.subTest(query_suffix=query_suffix or "default"):
                resp = self.client.get(f"/api/v1/detect?ip=8.8.8.8{query_suffix}")
                self.assertEqual(resp.status_code, 200)
                self.assertEqual(resp.headers.get("Cache-Control"), "private, max-age=300")
                payload = resp.json()
                self.assertEqual(len(payload["results"]), 14)
                for row in payload["results"]:
                    self.assertIn("rawJson", row)

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
            patch("detector.views.redis_client", None),
            patch("detector.views._get_shared_http_client", AsyncMock(return_value=mock_client)),
            patch("detector.views.query_maxmind", AsyncMock(return_value=dict(MAXMIND_STUB))),
            patch("detector.views.query_rdns_ptr", AsyncMock(return_value="dns.google")),
            patch("detector.views.query_cloudflare_radar", side_effect=_make_slow_ok("Cloudflare Radar")),
            patch("detector.views.query_abuseipdb", side_effect=_make_slow_ok("AbuseIPDB")),
            patch("detector.views.query_ipdata", side_effect=_make_slow_ok("IPData")),
            patch("detector.views.query_ipregistry", side_effect=_make_slow_ok("IPRegistry")),
            patch("detector.views.query_ip2location", side_effect=_make_slow_ok("IP2Location")),
            patch("detector.views.query_getipintel", side_effect=_make_slow_ok("GetIPIntel")),
            patch("detector.views.query_proxycheck", side_effect=_make_slow_ok("Proxycheck")),
            patch("detector.views.query_iphub", side_effect=_make_slow_ok("IPHub")),
            patch("detector.views.query_iphunter", side_effect=_make_slow_ok("IPHunter")),
            patch("detector.views.query_tor_onionoo", side_effect=_make_slow_ok("Tor Onionoo")),
            patch("detector.views.query_stopforumspam", side_effect=_make_slow_ok("StopForumSpam")),
            patch("detector.views.query_dshield", side_effect=_make_slow_ok("DShield")),
        ):
            compact_resp, full_resp = await asyncio.gather(
                views.detect_ip(compact_req),
                views.detect_ip(full_req),
            )

        self.assertEqual(provider_calls["count"], 1)
        self.assertEqual(compact_resp.status_code, 200)
        self.assertEqual(full_resp.status_code, 200)
        self.assertEqual(compact_resp.headers.get("Cache-Control"), "private, max-age=300")
        self.assertEqual(full_resp.headers.get("Cache-Control"), "private, max-age=300")

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
            return ProactiveQuotaAndTelemetryTests._build_provider_http_response(url, ip="8.8.8.8")

        fake_resolver = MagicMock()
        fake_resolver.resolve = AsyncMock(side_effect=ProactiveQuotaAndTelemetryTests._clean_dns_side_effect)

        with (
            patch("detector.views.redis_client", fake_redis),
            patch("detector.views.httpx.AsyncClient") as mock_client_cls,
            patch("detector.views.dns.asyncresolver.Resolver", return_value=fake_resolver),
            patch("detector.views.query_maxmind", new_callable=AsyncMock, return_value=dict(MAXMIND_STUB)),
        ):
            _patch_async_client(mock_client_cls, fake_get)
            compact_resp = self.client.get("/api/v1/detect?ip=8.8.8.8&compact=1")
            full_cached_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")
            compact_cached_resp = self.client.get("/api/v1/detect?ip=8.8.8.8&compact=true")

        self.assertEqual(compact_resp.status_code, 200)
        self.assertEqual(compact_resp.headers.get("Cache-Control"), "private, max-age=300")
        for row in compact_resp.json()["results"]:
            self.assertNotIn("rawJson", row)

        # Ensure IPData usage count was still extracted from rawJson before stripping the response
        ipdata_key = next(key for key in fake_redis.hashes if key.startswith("proxycheck:v1:telemetry:ipdata:day:"))
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

    @patch("detector.views.redis_client", None)
    def test_batch_detect_compact_strips_raw_json_when_requested(self):
        self._patch_all_providers()
        bearer_token = views.issue_gadget_token("SysopUser")
        headers = {"HTTP_AUTHORIZATION": f"Bearer {bearer_token}"}

        query_compact_resp = self.client.post(
            "/api/v1/detect/batch?compact=1",
            data=json.dumps({"ips": ["1.1.1.1"]}),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(query_compact_resp.status_code, 200)
        for row in query_compact_resp.json()["results"]["1.1.1.1"]["results"]:
            self.assertNotIn("rawJson", row)

        body_compact_resp = self.client.post(
            "/api/v1/detect/batch",
            data=json.dumps({"ips": ["1.1.1.1"], "compact": True}),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(body_compact_resp.status_code, 200)
        for row in body_compact_resp.json()["results"]["1.1.1.1"]["results"]:
            self.assertNotIn("rawJson", row)

        default_resp = self.client.post(
            "/api/v1/detect/batch",
            data=json.dumps({"ips": ["1.1.1.1"]}),
            content_type="application/json",
            **headers,
        )
        self.assertEqual(default_resp.status_code, 200)
        for row in default_resp.json()["results"]["1.1.1.1"]["results"]:
            self.assertIn("rawJson", row)


class TwoTierQueryModeTests(TestCase):
    """Tests for light and full two-tier detection modes across single, batch, and singleflight paths."""

    def setUp(self):
        views._ip_detect_inflight.clear()
        views._http_client_instance = None
        views._http_client_loop = None

    def tearDown(self):
        views._ip_detect_inflight.clear()
        views._http_client_instance = None
        views._http_client_loop = None

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
        provider_targets = (
            ("cloudflare_radar", "detector.views.query_cloudflare_radar", "Cloudflare Radar", None),
            ("abuseipdb", "detector.views.query_abuseipdb", "AbuseIPDB", None),
            ("ipdata", "detector.views.query_ipdata", "IPData", None),
            ("ipregistry", "detector.views.query_ipregistry", "IPRegistry", None),
            ("ip2location", "detector.views.query_ip2location", "IP2Location", None),
            ("getipintel", "detector.views.query_getipintel", "GetIPIntel", 0.985),
            ("proxycheck", "detector.views.query_proxycheck", "Proxycheck", None),
            ("iphub", "detector.views.query_iphub", "IPHub", None),
            ("iphunter", "detector.views.query_iphunter", "IPHunter", None),
            ("maxmind", "detector.views.query_maxmind", "MaxMind", None),
            ("spamhaus_zen", "detector.views.query_spamhaus_zen", "Spamhaus ZEN", None),
            ("spamcop", "detector.views.query_spamcop", "SpamCop", None),
            ("tor_onionoo", "detector.views.query_tor_onionoo", "Tor Onionoo", None),
            ("stopforumspam", "detector.views.query_stopforumspam", "StopForumSpam", None),
            ("dshield", "detector.views.query_dshield", "DShield", None),
        )
        for key, target, name, chance in provider_targets:
            mock_fn = AsyncMock(return_value=self._build_ok_row(name, chance=chance))
            patcher = patch(target, mock_fn)
            patcher.start()
            self.addCleanup(patcher.stop)
            mocks[key] = mock_fn

        ptr_patcher = patch("detector.views.query_rdns_ptr", AsyncMock(return_value="dns.google"))
        ptr_patcher.start()
        self.addCleanup(ptr_patcher.stop)

        http_client = AsyncMock()
        http_client.is_closed = False
        client_patcher = patch("detector.views._get_shared_http_client", AsyncMock(return_value=http_client))
        client_patcher.start()
        self.addCleanup(client_patcher.stop)

        mm_db_patcher = patch("detector.views._has_any_local_maxmind_db", return_value=True)
        mm_db_patcher.start()
        self.addCleanup(mm_db_patcher.stop)

        sfs_db_patcher = patch("detector.views._has_any_local_stopforumspam_db", return_value=True)
        sfs_db_patcher.start()
        self.addCleanup(sfs_db_patcher.stop)
        return mocks

    def test_light_mode_skips_uncached_commercial_sources_and_quota(self):
        fake_redis = _BatchingFakeRedis()
        mocks = self._patch_provider_suite()
        _login_authorised(self)

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.views.redis_client", fake_redis),
            patch("detector.views.check_and_consume_quota", wraps=views.check_and_consume_quota) as quota_spy,
        ):
            response = self.client.get("/api/v1/detect?ip=8.8.8.8&mode=light")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["queryMode"], "light")
        self.assertTrue(payload["isPartialMode"])
        self.assertIsNone(payload["getipintel_chance"])

        for deferred_key in (
            "abuseipdb",
            "ipdata",
            "ipregistry",
            "ip2location",
            "getipintel",
            "proxycheck",
            "iphub",
            "iphunter",
        ):
            mocks[deferred_key].assert_not_awaited()
            self.assertNotIn(f"proxycheck:v1:prov:{deferred_key}:8.8.8.8", fake_redis.strings)

        for active_key in (
            "cloudflare_radar",
            "maxmind",
            "stopforumspam",
            "spamhaus_zen",
            "spamcop",
            "tor_onionoo",
            "dshield",
        ):
            mocks[active_key].assert_awaited_once()
            self.assertIn(f"proxycheck:v1:prov:{active_key}:8.8.8.8", fake_redis.strings)

        consumed_providers = {call.args[0] for call in quota_spy.await_args_list}
        self.assertNotIn("getipintel", consumed_providers)
        self.assertNotIn("proxycheck", consumed_providers)
        self.assertFalse(any(key.startswith("proxycheck:v1:quota:getipintel:") for key in fake_redis.strings))

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
        fake_redis.strings["proxycheck:v1:prov:getipintel:8.8.8.8"] = cached_getipintel

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.views.redis_client", fake_redis),
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
        for provider_key, provider_name, _, _, _ in views._PROVIDER_SPECS:
            cache_key = f"proxycheck:v1:prov:{provider_key}:8.8.8.8"
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
            patch("detector.views.redis_client", fake_redis),
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
            patch("detector.views.redis_client", fake_redis),
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

        self.assertIn("proxycheck:v1:prov:getipintel:8.8.8.8", fake_redis.strings)
        self.assertTrue(any(key.startswith("proxycheck:v1:quota:getipintel:") for key in fake_redis.strings))

    def test_default_invalid_and_non_public_modes_preserve_backward_compatibility(self):
        fake_redis = _BatchingFakeRedis()
        mocks = self._patch_provider_suite()
        _login_authorised(self)

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.views.redis_client", fake_redis),
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

    def test_batch_detect_supports_light_mode_from_body_and_query_parameter(self):
        fake_redis = _BatchingFakeRedis()
        mocks = self._patch_provider_suite()
        bearer_token = views.issue_gadget_token("SysopUser")
        headers = {"HTTP_AUTHORIZATION": f"Bearer {bearer_token}"}

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.views.redis_client", fake_redis),
        ):
            body_resp = self.client.post(
                "/api/v1/detect/batch?compact=1",
                data=json.dumps({"ips": ["8.8.8.8"], "mode": "light"}),
                content_type="application/json",
                **headers,
            )

        self.assertEqual(body_resp.status_code, 200)
        body_payload = body_resp.json()
        self.assertEqual(body_payload["queryMode"], "light")
        ip_payload = body_payload["results"]["8.8.8.8"]
        self.assertEqual(ip_payload["queryMode"], "light")
        self.assertTrue(ip_payload["isPartialMode"])
        mocks["getipintel"].assert_not_awaited()
        for row in ip_payload["results"]:
            self.assertNotIn("rawJson", row)

    def test_batch_detect_defaults_to_light_mode_and_honours_explicit_full_mode(self):
        fake_redis = _BatchingFakeRedis()
        mocks = self._patch_provider_suite()
        bearer_token = views.issue_gadget_token("SysopUser")
        headers = {"HTTP_AUTHORIZATION": f"Bearer {bearer_token}"}

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.views.redis_client", fake_redis),
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

        self.assertEqual(default_resp.status_code, 200)
        default_payload = default_resp.json()
        self.assertEqual(default_payload["queryMode"], "light")
        self.assertTrue(default_payload["results"]["8.8.8.8"]["isPartialMode"])
        self.assertEqual(default_payload["results"]["8.8.8.8"]["queryMode"], "light")

        self.assertEqual(invalid_resp.status_code, 200)
        invalid_payload = invalid_resp.json()
        self.assertEqual(invalid_payload["queryMode"], "light")
        self.assertTrue(invalid_payload["results"]["1.1.1.1"]["isPartialMode"])

        mocks["getipintel"].assert_not_awaited()
        self.assertFalse(any(key.startswith("proxycheck:v1:quota:getipintel:") for key in fake_redis.strings))

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.views.redis_client", fake_redis),
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
            patch("detector.views.redis_client", None),
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
        self.assertEqual(len(views._ip_detect_inflight), 0)


class OfflineStopForumSpamEngineTests(TestCase):
    """Tests local StopForumSpam lookups, mtime hot-reloading, and graceful degradation."""

    def setUp(self):
        super().setUp()
        from detector import offline_dbs

        offline_dbs.clear_stopforumspam_caches()

    def tearDown(self):
        from detector import offline_dbs

        offline_dbs.clear_stopforumspam_caches()
        super().tearDown()

    def test_toxic_cidr_and_zip_gz_listed_ips_query_without_http(self):
        import gzip
        import zipfile

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "toxic_ip_cidr.txt").write_text(
                "# Comment line\n192.0.2.0/24\n2001:db8:dead::/48\n",
                encoding="utf-8",
            )
            zip_90_path = root / "listed_ip_90_ipv46_all.zip"
            with zipfile.ZipFile(zip_90_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(
                    "listed_ip_90_ipv46_all.txt",
                    '"198.51.100.42","12","2026-11-10 08:30:00"\n"192.0.2.77","3","2026-11-09 02:00:00"\n',
                )

            gz_1_path = root / "listed_ip_1_ipv46_all.txt.gz"
            with gzip.open(gz_1_path, "wt", encoding="utf-8") as gz_handle:
                gz_handle.write('"198.51.100.42","18","2026-11-16 05:15:00"\n')
                gz_handle.write('"2001:0db8:cafe:0000:0000:0000:0000:0001","9","2026-11-16 04:00:00"\n')

            with (
                override_settings(STOPFORUMSPAM_DB_DIR=tmp_dir),
                patch("detector.views.httpx.AsyncClient") as mock_client,
            ):
                toxic_row = asyncio.run(views.query_stopforumspam("192.0.2.77"))
                toxic_v6_row = asyncio.run(views.query_stopforumspam("2001:db8:dead::5"))
                merged_row = asyncio.run(views.query_stopforumspam("198.51.100.42"))
                canonical_v6_row = asyncio.run(views.query_stopforumspam("2001:db8:cafe::1"))
                clean_row = asyncio.run(views.query_stopforumspam("203.0.113.99"))

            mock_client.assert_not_called()

        self.assertEqual(toxic_row["status"], "200 OK")
        self.assertTrue(toxic_row["blacklisted"])
        self.assertTrue(toxic_row["appears"])
        self.assertEqual(toxic_row["toxicCidr"], "192.0.2.0/24")
        self.assertEqual(toxic_row["frequency"], 3)
        self.assertTrue(toxic_row.get("offlineDbUpdatedAt"))

        self.assertTrue(toxic_v6_row["blacklisted"])
        self.assertEqual(toxic_v6_row["toxicCidr"], "2001:db8:dead::/48")

        self.assertFalse(merged_row["blacklisted"])
        self.assertTrue(merged_row["appears"])
        self.assertEqual(merged_row["frequency"], 18)
        self.assertEqual(merged_row["lastSeen"], "2026-11-16 05:15:00")
        self.assertEqual(merged_row["rawJson"]["ip"]["sources"], ["listed_ip_90", "listed_ip_1"])

        self.assertTrue(canonical_v6_row["appears"])
        self.assertEqual(canonical_v6_row["frequency"], 9)

        self.assertFalse(clean_row["appears"])
        self.assertFalse(clean_row["blacklisted"])
        self.assertEqual(clean_row["usageType"], "Clean (Not Listed)")

    def test_hot_reloads_when_files_change_mtime_and_invalidates_redis_cache(self):
        from detector import offline_dbs

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            toxic_path = root / "toxic_ip_cidr.txt"
            listed_path = root / "listed_ip_90_ipv46_all.txt"

            toxic_path.write_text("192.0.2.0/24\n", encoding="utf-8")
            listed_path.write_text('"198.51.100.7","5","2026-11-10 00:00:00"\n', encoding="utf-8")

            cache_store = {}

            async def _fake_get(key):
                return cache_store.get(key)

            async def _fake_set(key, val, ex=None):
                cache_store[key] = val

            mock_redis = MagicMock()
            mock_redis.get = AsyncMock(side_effect=_fake_get)
            mock_redis.set = AsyncMock(side_effect=_fake_set)

            with (
                override_settings(STOPFORUMSPAM_DB_DIR=tmp_dir),
                patch("detector.views.redis_client", mock_redis),
            ):
                initial_lookup = offline_dbs.query_stopforumspam_offline("198.51.100.88")
                self.assertFalse(initial_lookup["appears"])

                first_row = asyncio.run(views.query_stopforumspam("198.51.100.88"))
                cache_key = views._provider_cache_key("stopforumspam", "198.51.100.88")
                cache_store[cache_key] = json.dumps(
                    {
                        "row": first_row,
                        "cachedAt": "2026-11-16T00:00:00+00:00",
                        "sanitized": True,
                        "dbVersion": offline_dbs.get_stopforumspam_db_version(),
                    }
                )

                cached_hit, _ = asyncio.run(views._read_provider_caches("198.51.100.88"))
                self.assertIn("stopforumspam", cached_hit)

                # Advance timestamps beyond integer second boundaries so file mtime visibly changes
                listed_path.write_text(
                    '"198.51.100.7","5","2026-11-10 00:00:00"\n"198.51.100.88","42","2026-11-16 12:00:00"\n',
                    encoding="utf-8",
                )
                future_ts = time.time() + 10.0
                os.utime(listed_path, (future_ts, future_ts))

                reloaded_lookup = offline_dbs.query_stopforumspam_offline("198.51.100.88")
                cached_after_update, _ = asyncio.run(views._read_provider_caches("198.51.100.88"))

            self.assertTrue(reloaded_lookup["appears"])
            self.assertEqual(reloaded_lookup["frequency"], 42)
            self.assertNotIn("stopforumspam", cached_after_update)

    def test_zero_quota_limits_for_stopforumspam(self):
        from detector import quota_telemetry

        rpm, daily = quota_telemetry.get_provider_quota_limits("stopforumspam")
        self.assertEqual((rpm, daily), (0, 0))


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


class UpdateOfflineDbsCommandTests(TestCase):
    """Tests rate-limit mtime guards, checksum validation, and atomic replacements."""

    def test_respects_mtime_cooldown_and_allows_force_and_validates_md5(self):
        import hashlib
        import io
        import tarfile
        import zipfile

        from django.core.management import call_command
        from django.core.management.base import CommandError

        from detector import offline_dbs
        from detector.management.commands import update_offline_dbs as update_cmd

        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("listed_ip_90_ipv46_all.txt", '"198.51.100.12","7","2026-11-16 01:00:00"\n')
        good_zip_bytes = zip_buf.getvalue()
        good_zip_md5 = hashlib.md5(good_zip_bytes, usedforsecurity=False).hexdigest()

        zip_1_buf = io.BytesIO()
        with zipfile.ZipFile(zip_1_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("listed_ip_1_ipv46_all.txt", '"198.51.100.13","3","2026-11-16 02:00:00"\n')
        good_zip_1_bytes = zip_1_buf.getvalue()
        good_zip_1_md5 = hashlib.md5(good_zip_1_bytes, usedforsecurity=False).hexdigest()

        toxic_bytes = b"192.0.2.0/24\n"

        tar_buf = io.BytesIO()
        mmdb_bytes = b"MMDB-VALID-HEADER-STUB"
        with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
            info = tarfile.TarInfo(name="GeoLite2-Country_20261116/GeoLite2-Country.mmdb")
            info.size = len(mmdb_bytes)
            tf.addfile(info, io.BytesIO(mmdb_bytes))
        good_tar_bytes = tar_buf.getvalue()
        good_tar_sha = hashlib.sha256(good_tar_bytes).hexdigest()

        class _FakeStreamResp:
            def __init__(self, content: bytes, status_code: int = 200):
                self._content = content
                self.status_code = status_code

            def raise_for_status(self):
                if self.status_code >= 400:
                    raise httpx.HTTPStatusError("err", request=MagicMock(), response=MagicMock())

            def iter_bytes(self, chunk_size=65536):
                yield self._content

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class _FakeTextResp:
            def __init__(self, text: str, status_code: int = 200):
                self.text = text
                self.status_code = status_code

            def raise_for_status(self):
                if self.status_code >= 400:
                    raise httpx.HTTPStatusError("err", request=MagicMock(), response=MagicMock())

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sfs_dir = root / "sfs"
            mm_dir = root / "mm"
            sfs_dir.mkdir()
            mm_dir.mkdir()

            old_zip_buf = io.BytesIO()
            with zipfile.ZipFile(old_zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("listed_ip_90_ipv46_all.txt", '"198.51.100.1","1","2026-11-01 00:00:00"\n')
            old_zip_bytes = old_zip_buf.getvalue()

            existing_90 = sfs_dir / "listed_ip_90_ipv46_all.zip"
            existing_90.write_bytes(old_zip_bytes)

            downloads_seen = []

            def _build_client(corrupt_md5: bool = False):
                fake_client = MagicMock()

                def _get(url, **kwargs):
                    downloads_seen.append(("GET", url))
                    if url.endswith("listed_ip_90_ipv46_all.zip.md5"):
                        return _FakeTextResp("0" * 32 if corrupt_md5 else good_zip_md5)
                    if url.endswith("listed_ip_1_ipv46_all.zip.md5"):
                        return _FakeTextResp(good_zip_1_md5)
                    if "GeoLite2-Country" in url and url.endswith(".sha256"):
                        return _FakeTextResp(f"{good_tar_sha}  GeoLite2-Country.tar.gz\n")
                    if "GeoLite2-City" in url and url.endswith(".sha256"):
                        return _FakeTextResp(f"{good_tar_sha}  GeoLite2-City.tar.gz\n")
                    if "GeoLite2-ASN" in url and url.endswith(".sha256"):
                        return _FakeTextResp(f"{good_tar_sha}  GeoLite2-ASN.tar.gz\n")
                    return _FakeTextResp("")

                def _stream(method, url, **kwargs):
                    downloads_seen.append(("STREAM", url))
                    if url.endswith("toxic_ip_cidr.txt"):
                        return _FakeStreamResp(toxic_bytes)
                    if url.endswith("listed_ip_90_ipv46_all.zip"):
                        return _FakeStreamResp(good_zip_bytes)
                    if url.endswith("listed_ip_1_ipv46_all.zip"):
                        return _FakeStreamResp(good_zip_1_bytes)
                    return _FakeStreamResp(good_tar_bytes)

                fake_client.get.side_effect = _get
                fake_client.stream.side_effect = _stream
                cm = MagicMock()
                cm.__enter__.return_value = fake_client
                cm.__exit__.return_value = False
                return cm

            # Recent mtime blocks SFS 90d download when --force is omitted
            with patch.object(update_cmd.httpx, "Client", return_value=_build_client()):
                call_command("update_offline_dbs", sources=["stopforumspam"], sfs_dir=str(sfs_dir), skip_listed_1=True)

            self.assertFalse(any("listed_ip_90_ipv46_all.zip" in u for _, u in downloads_seen))
            self.assertEqual(existing_90.read_bytes(), old_zip_bytes)

            # MD5 mismatch must fail without corrupting existing archive on disk
            downloads_seen.clear()
            with (
                patch.object(update_cmd.httpx, "Client", return_value=_build_client(corrupt_md5=True)),
                self.assertRaises(CommandError),
            ):
                call_command(
                    "update_offline_dbs",
                    sources=["stopforumspam"],
                    sfs_dir=str(sfs_dir),
                    force=True,
                    skip_listed_1=True,
                )
            self.assertEqual(existing_90.read_bytes(), old_zip_bytes)

            # Force full valid SFS + MaxMind update with mocked maxminddb reader validation
            downloads_seen.clear()
            fake_mm_reader = MagicMock()
            with (
                override_settings(
                    MAXMIND_ACCOUNT_ID="123456",
                    MAXMIND_LICENSE_KEY="secret-mm-key",
                    STOPFORUMSPAM_DB_DIR=str(sfs_dir),
                ),
                patch.object(update_cmd.httpx, "Client", return_value=_build_client(corrupt_md5=False)),
                patch.object(update_cmd.maxminddb, "open_database", return_value=fake_mm_reader),
                patch.object(update_cmd, "MAXMIND_EDITION_SPECS", (("GeoLite2-Country", "GeoLite2-Country.mmdb"),)),
            ):
                call_command(
                    "update_offline_dbs",
                    sources=["all"],
                    sfs_dir=str(sfs_dir),
                    maxmind_dir=str(mm_dir),
                    force=True,
                )

            self.assertEqual(existing_90.read_bytes(), good_zip_bytes)
            self.assertEqual((mm_dir / "GeoLite2-Country.mmdb").read_bytes(), mmdb_bytes)
            self.assertTrue((sfs_dir / "stopforumspam.sqlite3").is_file())
            with override_settings(STOPFORUMSPAM_DB_DIR=str(sfs_dir)):
                offline_dbs.clear_stopforumspam_caches()
                hit = offline_dbs.query_stopforumspam_offline("198.51.100.12")
                self.assertTrue(hit["appears"])
                self.assertEqual(hit["frequency"], 7)
            offline_dbs.clear_stopforumspam_caches()


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
                "- name: update-offline-dbs\n"
                "  command: python manage.py update_offline_dbs\n"
                "  image: tool-proxycheck/tool-proxycheck:latest\n"
                '  schedule: "0 * * * *"\n'
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
                if cmd[1:] == ["jobs", "list"]:
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
                "- name: update-offline-dbs\n"
                "  command: python manage.py update_offline_dbs\n"
                "  image: tool-proxycheck/tool-proxycheck:latest\n"
                '  schedule: "0 * * * *"\n'
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
            self.assertIn("update-offline-dbs: OK", output)
            self.assertIn("Toolforge scheduled jobs match jobs.yaml.", output)

    def test_manage_py_check_setup_starts_without_secret_key(self):
        import subprocess

        manage_py = Path(__file__).resolve().parent.parent / "manage.py"
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
                if cmd[1:] == ["jobs", "list"]:
                    return subprocess.CompletedProcess(
                        cmd,
                        0,
                        stdout=(
                            "Job name:              Job type:              Status:\n"
                            "---------------------- ---------------------- -------------------\n"
                            "update-offline-dbs     scheduled: 0 * * * *   Running\n"
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
                            "Mount: none\n"
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
