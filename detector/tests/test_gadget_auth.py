"""Core P0 tests for Wikimedia gadget Bearer authentication, Beta origin blocking, and RBAC."""

import asyncio
import json
from unittest.mock import AsyncMock, patch

import dns.resolver
from django.core import signing
from django.test import TestCase, override_settings

from detector import views
from detector.auth import oauth
from detector.auth.oauth import (
    evaluate_wikimedia_rights,
    fetch_user_rights_from_meta,
    normalize_and_validate_wikimedia_domain,
)
from detector.auth.session import GADGET_TOKEN_SALT, get_gadget_token_ttl_seconds
from detector.cache import redis_backend as cache_backends

from .helpers import _mock_response, start_non_dnsbl_provider_stubs


class GadgetAuthSecurityTests(TestCase):
    """P0 tests for Beta Cluster auth hardening, CentralAuth exchange, Bearer verification, and RBAC."""

    def setUp(self):
        cache_backends.reset_redis_circuit_breaker()
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock, side_effect=dns.resolver.NXDOMAIN()
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)

    def test_beta_origins_and_domains_blocked_by_default_and_gated_by_env(self):
        """Rejects Beta Cluster origins and domains by default and pins global rights queries to Meta-Wiki."""
        self.assertEqual(normalize_and_validate_wikimedia_domain("en.wikipedia.org"), "en.wikipedia.org")
        self.assertIsNone(normalize_and_validate_wikimedia_domain("en.wikipedia.beta.wmcloud.org"))
        self.assertIsNone(normalize_and_validate_wikimedia_domain("en.wikipedia.beta.wmflabs.org"))

        default_preflight = self.client.options(
            "/api/v1/detect?ip=127.0.0.1", HTTP_ORIGIN="https://en.wikipedia.beta.wmcloud.org"
        )
        self.assertEqual(default_preflight.status_code, 204)
        self.assertNotIn("Access-Control-Allow-Origin", default_preflight.headers)

        with override_settings(ALLOW_WIKIMEDIA_BETA_ORIGINS=True):
            self.assertEqual(
                normalize_and_validate_wikimedia_domain("en.wikipedia.beta.wmcloud.org"),
                "en.wikipedia.beta.wmcloud.org",
            )
            beta_preflight = self.client.options(
                "/api/v1/detect?ip=127.0.0.1", HTTP_ORIGIN="https://en.wikipedia.beta.wmcloud.org"
            )
            self.assertEqual(
                beta_preflight.headers.get("Access-Control-Allow-Origin"), "https://en.wikipedia.beta.wmcloud.org"
            )

        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            200, {"query": {"globaluserinfo": {"groups": [], "rights": [], "merged": []}}}
        )
        asyncio.run(
            fetch_user_rights_from_meta(mock_client, "ExampleUser", wiki_domain="en.wikipedia.beta.wmcloud.org")
        )
        self.assertEqual(mock_client.get.call_args.args[0], oauth.MEDIAWIKI_API_URL)

    def test_exchange_gadget_token_centralauth_validation_and_no_store(self):
        """Verifies CentralAuth token exchange, 900s default TTL, and no-store cache control."""
        self.assertEqual(get_gadget_token_ttl_seconds(), 900)

        cases = [
            (
                {"query": {"userinfo": {"id": 10, "name": "~2026-1", "temp": "", "groups": []}}},
                401,
            ),
            (
                {"query": {"userinfo": {"id": 12, "name": "NormalUser", "groups": ["user"], "rights": []}}},
                403,
            ),
            (
                {
                    "query": {
                        "userinfo": {
                            "id": 15,
                            "name": "SysopUser",
                            "groups": ["sysop"],
                            "rights": ["checkuser-temporary-account"],
                        }
                    }
                },
                200,
            ),
        ]
        for userinfo_payload, expected_status in cases:
            with self.subTest(expected_status=expected_status):
                mock_client = AsyncMock()
                mock_client.get.side_effect = [
                    _mock_response(200, userinfo_payload),
                    _mock_response(200, {"query": {"globaluserinfo": {"groups": [], "rights": [], "merged": []}}}),
                ]
                with patch("detector.core.http_client.get_shared_http_client", AsyncMock(return_value=mock_client)):
                    resp = self.client.post(
                        "/api/v1/auth/gadget-token",
                        data=json.dumps({"centralauthtoken": "cat-secret", "domain": "en.wikipedia.org"}),
                        content_type="application/json",
                        HTTP_ORIGIN="https://en.wikipedia.org",
                    )
                self.assertEqual(resp.status_code, expected_status)
                if expected_status == 200:
                    body = resp.json()
                    self.assertEqual(body["username"], "SysopUser")
                    self.assertEqual(body["expires_in"], 900)
                    self.assertEqual(resp.headers.get("Cache-Control"), "no-store")

    def test_detect_ip_bearer_token_signature_expiry_and_temp_account_rejection(self):
        """Accepts valid gadget Bearer tokens and rejects tampered, expired, temp, or bare-header requests."""
        start_non_dnsbl_provider_stubs(self)
        valid_token = views.issue_gadget_token("SysopUser")
        self.assertEqual(
            self.client.get("/api/v1/detect?ip=127.0.0.1", HTTP_AUTHORIZATION=f"Bearer {valid_token}").status_code,
            200,
        )

        tampered = f"{valid_token}x"
        wrong_scope = signing.dumps({"u": "SysopUser", "scope": "other"}, salt=GADGET_TOKEN_SALT)
        temp_token = signing.dumps({"u": "~2026-999", "scope": "gadget"}, salt=GADGET_TOKEN_SALT)
        for headers in (
            {"HTTP_X_WIKI_USER": "SysopUser"},
            {"HTTP_AUTHORIZATION": f"Bearer {tampered}"},
            {"HTTP_AUTHORIZATION": f"Bearer {wrong_scope}"},
            {"HTTP_AUTHORIZATION": f"Bearer {temp_token}"},
        ):
            with self.subTest(headers=headers):
                self.assertEqual(self.client.get("/api/v1/detect?ip=127.0.0.1", **headers).status_code, 401)

        with (
            override_settings(GADGET_TOKEN_TTL_SECONDS=60),
            patch("django.core.signing.time.time", return_value=1000.0),
        ):
            old_token = views.issue_gadget_token("SysopUser")
        with (
            override_settings(GADGET_TOKEN_TTL_SECONDS=60),
            patch("django.core.signing.time.time", return_value=1120.0),
        ):
            expired_resp = self.client.get("/api/v1/detect?ip=127.0.0.1", HTTP_AUTHORIZATION=f"Bearer {old_token}")
            self.assertEqual(expired_resp.status_code, 401)

    def test_unified_rbac_evaluator_handles_local_global_and_allowlist_rights(self):
        """Evaluates temporary-account IP reveal rights across local, global, merged, and allowlist rules."""
        with override_settings(ALLOWED_WIKI_USERS="AllowUser"):
            self.assertTrue(
                evaluate_wikimedia_rights(
                    {"username": "StewardUser", "global_rights": ["checkuser-temporary-account-no-preference"]}
                )[0]
            )
            self.assertTrue(
                evaluate_wikimedia_rights({"username": "SysopUser", "local_rights": ["checkuser-temporary-account"]})[0]
            )
            self.assertTrue(evaluate_wikimedia_rights({"username": "AllowUser"})[0])
            self.assertFalse(
                evaluate_wikimedia_rights({"username": "~2026-1", "global_rights": ["checkuser-temporary-account"]})[0]
            )
            self.assertFalse(evaluate_wikimedia_rights({"username": "UnprivUser", "local_groups": ["sysop"]})[0])
