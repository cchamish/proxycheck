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
    compute_cidr_attribution,
)
from detector.middleware import AsyncWhiteNoiseMiddleware
from detector.oauth import (
    CentralAuthVerificationError,
    InvalidCentralAuthTokenError,
    MetaWikiRightsFetchError,
    evaluate_wikimedia_rights,
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
                "threatScore": None,
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
        self.assertIn("comprehensiveScore", payload)
        self.assertEqual(len(payload["results"]), 15)
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
        }
        mock_client.get.return_value = profile_resp
        mock_fetch_meta.return_value = {"global_groups": ["steward"], "merged_projects": []}

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
    "threatScore": None,
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


HTTP_PROVIDERS = tuple(name for name, _ in ALL_ADAPTERS if name not in ("MaxMind", "Tor Onionoo"))


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
                self.assertIsNone(result["threatScore"])

    def test_iphub_numeric_string_block_is_classified(self):
        result = adapt_iphub({"ip": "8.8.8.8", "block": "1", "countryCode": "US"}, True, 200)
        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(result["block"], 1)
        self.assertEqual(result["threatScore"], 85)

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
        self.assertIsNone(result["threatScore"])

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
                self.assertEqual(len(rows), 15)
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
        self.assertEqual(result["threatScore"], 0)
        self.assertEqual(result["securityFlags"], [{"label": "No Flags", "isHighRisk": False}])

    def test_geoip2_hosting_user_type_is_still_flagged(self):
        record = dict(self.GEOLITE2_RECORD, traits={"user_type": "hosting"})
        result = adapt_maxmind(record, True, 200)
        self.assertEqual(result["usageType"], "hosting")
        self.assertIn({"label": "Hosting", "isHighRisk": True}, result["securityFlags"])
        self.assertEqual(result["threatScore"], 50)

    def test_geoip2_residential_user_type_is_preserved(self):
        record = dict(self.GEOLITE2_RECORD, traits={"user_type": "residential"})
        result = adapt_maxmind(record, True, 200)
        self.assertEqual(result["usageType"], "residential")
        self.assertEqual(result["threatScore"], 0)

    def test_non_dict_traits_do_not_crash(self):
        record = dict(self.GEOLITE2_RECORD, traits="corrupted")
        result = adapt_maxmind(record, True, 200)
        self.assertEqual(result["usageType"], "unknown")

    def test_geolite2_row_does_not_raise_aggregate_score(self):
        maxmind_row = adapt_maxmind(dict(self.GEOLITE2_RECORD), True, 200)
        aggregated = views.aggregate_intelligence_metrics("1.2.3.4", [maxmind_row])
        self.assertEqual(aggregated["comprehensiveScore"], 0)
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
                "threatScore": 10,
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
                "threatScore": 30,
                "countryCode": "US",
                "rawJson": {"ip": "1.1.1.1"},
            },
        ]
        snapshot = copy.deepcopy(input_rows)

        aggregated = views.aggregate_intelligence_metrics("1.1.1.1", input_rows)

        # Verify caller input structures were not modified in place
        self.assertEqual(input_rows, snapshot)
        self.assertEqual(input_rows[0]["securityFlags"], [{"label": "No Flags", "isHighRisk": False}])
        self.assertEqual(input_rows[0]["threatScore"], 10)
        self.assertEqual(input_rows[1]["threatScore"], 30)

        # Verify returned copy carries the normalized scores and flags
        out_rows = {row["provider"]: row for row in aggregated["results"]}
        self.assertEqual(out_rows["IPData"]["securityFlags"], [{"label": "Hosting", "isHighRisk": True}])
        self.assertEqual(out_rows["IPData"]["threatScore"], 50)
        self.assertEqual(out_rows["IPRegistry"]["threatScore"], 80)

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
            "sorbs": "SORBS",
            "tor_onionoo": "Tor Onionoo",
            "stopforumspam": "StopForumSpam",
            "dshield": "DShield",
        }
        cache_store = {}
        for provider_key, provider_name in provider_map.items():
            cache_store[f"ipcheck:v2:prov:{provider_key}:8.8.8.8"] = json.dumps(
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
                        "threatScore": 0,
                        "countryCode": "US",
                        "rawJson": {},
                    },
                    "cachedAt": "2026-11-13T08:00:00+00:00",
                }
            )
        cache_store["ipcheck:v2:prov:ptr:8.8.8.8"] = json.dumps(
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
        self.assertEqual(payload["cacheMeta"]["hitCount"], 17)
        self.assertEqual(payload["cacheMeta"]["cachedAt"], "2026-11-13T08:00:00+00:00")
        self.assertEqual(payload["ptrHostname"], "dns.google")
        self.assertEqual(payload["comprehensiveScore"], 0)
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
                self.assertFalse(any(k.startswith("ipcheck:v2:prov:") for k in written_keys))
                cooldown_calls = [
                    c for c in mock_redis.set.call_args_list if c.args[0].startswith("ipcheck:v2:cooldown:")
                ]
                self.assertEqual(len(cooldown_calls), 15)
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
                "threatScore": 0,
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
        self.assertEqual(mock_redis.set.await_count, 16)
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
            self.assertEqual(ttls_by_key.get(f"ipcheck:v2:prov:{provider_key}:8.8.8.8"), 86400)
        for dynamic_key in ("ptr", "spamhaus_zen", "spamcop", "sorbs", "tor_onionoo", "stopforumspam", "dshield"):
            self.assertEqual(ttls_by_key.get(f"ipcheck:v2:prov:{dynamic_key}:8.8.8.8"), 7200)
        self.assertNotIn("ipcheck:v2:prov:maxmind:8.8.8.8", ttls_by_key)


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
        mock_asn_reader = MagicMock()
        mock_asn_reader.get.return_value = {
            "autonomous_system_number": 13335,
            "autonomous_system_organization": "Cloudflare",
        }

        def _fake_open(path):
            if "country" in str(path).lower():
                return mock_country_reader
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
        self.assertEqual(res_two["status"], "200 OK")
        self.assertEqual(mock_maxmind_module.open_database.call_count, 2)
        self.assertEqual(mock_country_reader.get.call_count, 2)
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
                        "merged": [{"wiki": "enwiki", "groups": ["*", "user"]}],
                    }
                },
            },
        )
        rights = asyncio.run(fetch_user_rights_from_meta(client, "RegularUser"))
        self.assertEqual(rights["global_groups"], [])
        self.assertEqual(len(rights["merged_projects"]), 1)

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
                "threatScore": 0,
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
        self.assertIn("ipcheck:v2:prov:proxycheck:2001:486:4860::8888", cache_store)
        self.assertIn("ipcheck:v2:prov:tor_onionoo:2001:486:4860::8888", cache_store)
        self.assertIn("ipcheck:v2:prov:stopforumspam:2001:486:4860::8888", cache_store)
        self.assertIn("ipcheck:v2:prov:dshield:2001:486:4860::8888", cache_store)
        self.assertIn("ipcheck:v2:prov:ptr:2001:486:4860::8888", cache_store)

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
                "threatScore": 0,
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
        self.assertNotIn("ipcheck:v2:prov:ptr:8.8.8.8", cache_store)
        self.assertNotIn("ipcheck:v2:cooldown:ptr", cache_store)
        self.assertEqual(written_ttls.get("ipcheck:v2:prov:cloudflare_radar:8.8.8.8"), 86400)
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
        self.assertEqual(written_ttls.get("ipcheck:v2:prov:ptr:8.8.8.8"), 7200)
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
                "threatScore": None,
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
        self.assertEqual(data_canonical["comprehensiveScore"], data_legacy["comprehensiveScore"])
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
                "threatScore": None,
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
        with patch.dict(sys.modules, {"resource": None}):
            mem = views.get_process_memory_mb()
            self.assertIsNone(mem)


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
            "threatScore": None,
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
                    "rights": ["read", "edit"],
                    "centralids": {"CentralAuth": 77},
                    "domain": "zh.wikipedia.org",
                },
            ) as mock_verify,
            patch(
                "detector.views.fetch_user_rights_from_meta",
                new_callable=AsyncMock,
                return_value={"global_groups": [], "merged_projects": []},
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
        group_cases = (
            ("GlobalSteward", {"global_groups": ["steward"], "merged_projects": []}),
            ("GlobalSysop", {"global_groups": ["global-sysop"], "merged_projects": []}),
            ("GlobalRollback", {"global_groups": ["global-rollbacker"], "merged_projects": []}),
            ("GlobalTempViewer", {"global_groups": ["global-temporary-account-viewer"], "merged_projects": []}),
            ("OmbudsUser", {"global_groups": ["ombuds"], "merged_projects": []}),
            ("StaffUser", {"global_groups": ["staff"], "merged_projects": []}),
            ("LocalSysop", {"global_groups": [], "merged_projects": [{"wiki": "enwiki", "groups": ["sysop"]}]}),
            ("LocalAdmin", {"global_groups": [], "merged_projects": [{"wiki": "enwiki", "groups": ["administrator"]}]}),
            ("LocalCheckUser", {"global_groups": [], "merged_projects": [{"wiki": "enwiki", "groups": ["checkuser"]}]}),
            ("LocalArbCom", {"global_groups": [], "merged_projects": [{"wiki": "enwiki", "groups": ["arbcom"]}]}),
            ("LocalOversight", {"global_groups": [], "merged_projects": [{"wiki": "enwiki", "groups": ["oversight"]}]}),
            ("LocalSuppress", {"global_groups": [], "merged_projects": [{"wiki": "enwiki", "groups": ["suppress"]}]}),
            (
                "LocalTempViewer",
                {"global_groups": [], "merged_projects": [{"wiki": "enwiki", "groups": ["temporary-account-viewer"]}]},
            ),
        )

        with override_settings(GADGET_TOKEN_TTL_SECONDS=3600):
            for username, rights_payload in group_cases:
                with self.subTest(username=username):
                    userinfo_stub = {
                        "username": username,
                        "local_groups": ["*", "user"],
                        "rights": [],
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
                    return_value={"global_groups": ["steward"], "merged_projects": []},
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

    def test_unified_rbac_evaluator_and_oauth_callback_parity(self):
        for group in (
            "steward",
            "global-sysop",
            "global-rollbacker",
            "global-temporary-account-viewer",
            "ombuds",
            "staff",
        ):
            has_access, label, _, _ = evaluate_wikimedia_rights({"global_groups": [group]})
            self.assertTrue(has_access, msg=f"Expected access for global group {group}")
            self.assertTrue(label)

        for local_group in (
            "sysop",
            "administrator",
            "checkuser",
            "arbcom",
            "oversight",
            "suppress",
            "temporary-account-viewer",
        ):
            has_access, label, _, _ = evaluate_wikimedia_rights({"local_groups": [local_group]})
            self.assertTrue(has_access, msg=f"Expected access for local group {local_group}")
            self.assertTrue(label)

        denied, _, _, _ = evaluate_wikimedia_rights({"username": "PlainUser", "local_groups": ["*", "user"]})
        self.assertFalse(denied)

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
                    "threatScore": 0,
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
                    "threatScore": 0,
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
        if "dshield.org" in url:
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
                    "threatScore": 0,
                    "countryCode": "US",
                    "rawJson": {},
                },
                "cachedAt": "2026-11-13T07:00:00+00:00",
            }
        )
        cache_store = {
            "ipcheck:v2:prov:proxycheck:1.1.1.1": historical_proxycheck_1111,
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
        self.assertIn("ipcheck:v2:cooldown:proxycheck", cache_store)
        self.assertEqual(written_ttls["ipcheck:v2:cooldown:proxycheck"], 180)
        self.assertNotIn("ipcheck:v2:prov:proxycheck:8.8.8.8", cache_store)
        self.assertEqual(cache_store["ipcheck:v2:prov:proxycheck:1.1.1.1"], historical_proxycheck_1111)

        for healthy_key in (
            "cloudflare_radar",
            "abuseipdb",
            "ipdata",
            "ipregistry",
            "ip2location",
            "getipintel",
            "iphub",
            "iphunter",
        ):
            self.assertIn(f"ipcheck:v2:prov:{healthy_key}:8.8.8.8", cache_store)
            self.assertEqual(written_ttls[f"ipcheck:v2:prov:{healthy_key}:8.8.8.8"], 86400)
        self.assertEqual(written_ttls["ipcheck:v2:prov:ptr:8.8.8.8"], 7200)

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
        self.assertIn("ipcheck:v2:prov:cloudflare_radar:9.9.9.9", cache_store)

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
        self.assertEqual(written_ttls.get("ipcheck:v2:cooldown:proxycheck"), 120)
        self.assertNotIn("ipcheck:v2:prov:proxycheck:8.8.8.8", cache_store)
        self.assertEqual(written_ttls.get("ipcheck:v2:prov:ptr:8.8.8.8"), 1800)
        self.assertEqual(written_ttls.get("ipcheck:v2:prov:cloudflare_radar:8.8.8.8"), 43200)


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
        self.assertGreaterEqual(sbl_row["threatScore"], 75)
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
        self.assertEqual(combo_row["threatScore"], 85)

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
                self.assertEqual(pbl_row["threatScore"], 0)
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
                self.assertIsNone(blocked_row["threatScore"])
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
        self.assertEqual(clean_row["threatScore"], 0)

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

    async def test_sorbs_reverses_ipv4_octets_and_decodes_codes(self):
        code_expectations = (
            ("127.0.0.2", "HTTP Proxy", True),
            ("127.0.0.3", "SOCKS Proxy", True),
            ("127.0.0.4", "MISC Proxy", True),
            ("127.0.0.5", "Open Relay", True),
            ("127.0.0.6", "Spam Source", True),
            ("127.0.0.9", "Zombie / Hijacked", True),
            ("127.0.0.10", "Dynamic IP (DUHL)", False),
            ("127.0.0.14", "Non-Mail Server", False),
        )
        for code, expected_label, expected_high_risk in code_expectations:
            with self.subTest(code=code):
                with patch(
                    "dns.asyncresolver.Resolver.resolve",
                    new_callable=AsyncMock,
                    return_value=_mock_a_answer(code),
                ) as mock_resolve:
                    row = await views.query_sorbs("198.51.100.42")
                mock_resolve.assert_awaited_once_with("42.100.51.198.dnsbl.sorbs.net", "A")
                self.assertEqual(row["status"], "200 OK")
                self.assertTrue(row["isListed"])
                self.assertIn(expected_label, row["usageType"])
                self.assertEqual(any(flag["isHighRisk"] for flag in row["securityFlags"]), expected_high_risk)

        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        ):
            clean_row = await views.query_sorbs("198.51.100.42")
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
        for dnsbl_name in ("Spamhaus ZEN", "SpamCop", "SORBS"):
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
                "threatScore": 0,
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
            if qtext == "4.3.2.1.dnsbl.sorbs.net":
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
        self.assertEqual(payload["comprehensiveScore"], 0)

        rows = {row["provider"]: row for row in payload["results"]}
        self.assertTrue(rows["Spamhaus ZEN"]["isListed"])
        self.assertIn("SBL (127.0.0.2)", rows["Spamhaus ZEN"]["usageType"])
        self.assertTrue(rows["SpamCop"]["isListed"])
        self.assertTrue(rows["SORBS"]["isListed"])
        self.assertIn("HTTP Proxy (127.0.0.2)", rows["SORBS"]["usageType"])

        self.assertEqual(written_ttls.get("ipcheck:v2:prov:spamhaus_zen:1.2.3.4"), 7200)
        self.assertEqual(written_ttls.get("ipcheck:v2:prov:spamcop:1.2.3.4"), 7200)
        self.assertEqual(written_ttls.get("ipcheck:v2:prov:sorbs:1.2.3.4"), 7200)

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
        self.assertNotIn("ipcheck:v2:prov:spamhaus_zen:8.7.6.5", cache_store)
        self.assertEqual(written_ttls.get("ipcheck:v2:cooldown:spamhaus_zen"), 120)
        self.assertEqual(written_ttls.get("ipcheck:v2:prov:spamcop:8.7.6.5"), 7200)
        self.assertEqual(written_ttls.get("ipcheck:v2:prov:sorbs:8.7.6.5"), 7200)


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
        self.assertEqual(result["threatScore"], 82)

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
        self.assertEqual(exit_res["threatScore"], 90)
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
        self.assertEqual(prefix_miss["threatScore"], 0)

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
        self.assertEqual(clean["threatScore"], 0)

        api_err = adapt_stopforumspam({"success": 0, "error": "rate limit"}, status_code=200)
        self.assertEqual(api_err["status"], "400 Error")

        captured = {}

        async def _get(url, **kwargs):
            captured["url"] = url
            return _mock_response(
                status_code=200, json_value={"success": 1, "ip": {"appears": 0, "frequency": 0, "confidence": 0}}
            )

        client = AsyncMock()
        client.get.side_effect = _get
        asyncio.run(views.query_stopforumspam(client, "198.51.100.5"))
        self.assertEqual(captured["url"], "https://api.stopforumspam.org/api?ip=198.51.100.5&json")

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
        self.assertEqual(clean["threatScore"], 0)
        self.assertEqual(clean["usageType"], "Clean (No Activity)")

        captured = {}

        async def _get(url, **kwargs):
            captured["url"] = url
            captured["headers"] = kwargs.get("headers") or {}
            return _mock_response(status_code=200, json_value={"ip": {"attacks": 0, "count": 0}})

        client = AsyncMock()
        client.get.side_effect = _get
        asyncio.run(views.query_dshield(client, "198.51.100.5"))
        self.assertEqual(captured["url"], "https://www.dshield.org/api/ip/198.51.100.5?json")
        self.assertIn("ProxyCheck", captured["headers"].get("User-Agent", ""))

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
            if "dshield.org" in url:
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

        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
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
        self.assertEqual(payload["comprehensiveScore"], 0)

        rows = {row["provider"]: row for row in payload["results"]}
        self.assertNotIn("Tor Onionoo", rows)
        self.assertEqual(rows["Proxycheck"]["port"], 9050)
        self.assertEqual(rows["Proxycheck"]["lastSeen"], "1 hour ago")
        self.assertEqual(rows["StopForumSpam"]["frequency"], 25)
        self.assertEqual(rows["StopForumSpam"]["lastSeen"], "2026-11-12 09:00:00")
        self.assertEqual(rows["DShield"]["attacks"], 80)
        self.assertEqual(rows["DShield"]["threatfeeds"], ["scanner"])
        self.assertEqual(written_ttls.get("ipcheck:v2:prov:tor_onionoo:185.220.101.4"), 7200)
        self.assertEqual(written_ttls.get("ipcheck:v2:prov:stopforumspam:185.220.101.4"), 7200)
        self.assertEqual(written_ttls.get("ipcheck:v2:prov:dshield:185.220.101.4"), 7200)

        tor_active_mode["enabled"] = True
        with (
            override_settings(**TEST_UPSTREAM_SECRETS),
            patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
            patch("detector.views.redis_client", mock_redis),
        ):
            tor_resp = self.client.get("/api/v1/detect?ip=185.220.101.9")

        self.assertEqual(tor_resp.status_code, 200)
        tor_payload = tor_resp.json()
        self.assertTrue(tor_payload["isTor"])
        self.assertTrue(tor_payload["torIsExit"])
        self.assertTrue(tor_payload["torRunning"])
        self.assertEqual(tor_payload["torLabel"], "Tor Exit")
        self.assertIn("Exit", tor_payload["torFlags"])
        self.assertGreaterEqual(tor_payload["comprehensiveScore"], 90)
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

            resolved_env = _resolve_dotenv_path(Path(tmpdir) / "workspace", str(tool_root))
            self.assertEqual(resolved_env, env_file)

            with patch.dict(os.environ, {"TOOL_DATA_DIR": str(tool_root)}):
                resolved_db = views._resolve_db_file("", "GeoLite2-Country.mmdb", Path(tmpdir) / "workspace")
            self.assertEqual(resolved_db, str(mmdb_file))

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
                    cached_value = await views._safe_redis_get("ipcheck:v2:prov:proxycheck:8.8.8.8")
                    await views._safe_redis_set("ipcheck:v2:prov:proxycheck:8.8.8.8", "{}", ex=60)

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
                "threatScore": 0,
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
        mock_fetch_meta.return_value = {"global_groups": ["steward"], "merged_projects": []}
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
        mock_fetch_meta.return_value = {"global_groups": ["steward"], "merged_projects": []}

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
