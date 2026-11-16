"""Tests for Wikimedia gadget Bearer token exchange, verification, and CORS handling."""

import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.name
import dns.resolver
import dns.reversename
import httpx
from django.core import signing
from django.test import TestCase, override_settings

from detector import views
from detector.oauth import (
    CentralAuthVerificationError,
    InvalidCentralAuthTokenError,
    MetaWikiRightsFetchError,
    evaluate_wikimedia_rights,
    normalize_and_validate_wikimedia_domain,
    verify_centralauth_userinfo,
)


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

        with override_settings(
            ALLOWED_WIKI_USERS="Allowlisted_Operator",
            RESTRICT_TO_ALLOWED_WIKI_USERS=True,
        ):
            allowed, role_label, _, _ = evaluate_wikimedia_rights(
                {
                    "username": "Allowlisted_Operator",
                    "global_rights": ["checkuser-temporary-account"],
                }
            )
            self.assertTrue(allowed)
            self.assertEqual(role_label, "Allowlisted Wikimedia User")

            denied, role_label, _, _ = evaluate_wikimedia_rights(
                {
                    "username": "Other_Operator",
                    "global_rights": ["checkuser-temporary-account"],
                }
            )
            self.assertFalse(denied)
            self.assertEqual(role_label, "Access Denied (restricted user allowlist)")

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

        # Verify Meta-Wiki local right fallback on transient globaluserinfo error matches gadget behaviour
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
