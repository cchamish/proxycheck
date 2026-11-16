"""Tests for provider adapters, secret redaction, rDNS/CIDR attribution, and arbitration."""

import asyncio
import copy
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.name
import dns.resolver
import dns.reversename
import httpx
from django.test import SimpleTestCase, TestCase, override_settings

from detector import views
from detector.adapters import (
    _safe_int,
    adapt_abuseipdb,
    adapt_cloudflare_radar,
    adapt_getipintel,
    adapt_ip2location,
    adapt_ipdata,
    adapt_iphub,
    adapt_iphunter,
    adapt_ipregistry,
    adapt_maxmind,
    classify_rdns_hostname,
    compute_cidr_attribution,
)

from .helpers import (
    ALL_ADAPTERS,
    EMPTY_UPSTREAM_SECRETS,
    HTTP_PROVIDERS,
    MAXMIND_STUB,
    TEST_UPSTREAM_SECRETS,
    _login_authorised,
    _mock_ptr_answer,
    _mock_response,
    _patch_async_client,
    _ptr_or_clean_dns_side_effect,
)


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

        # Verify returned copy normalises hosting flags without mutating inputs
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

        # A single hosting tag with no behavioural signal is dismissed as a minor attribute dispute
        isolated_hosting = self._clean_row("IPHub")
        isolated_hosting["usageType"] = "hosting"
        isolated_hosting["securityFlags"] = [{"label": "Hosting", "isHighRisk": True}]
        outlier_result = views.aggregate_intelligence_metrics("8.8.8.8", [*clean_sources, isolated_hosting])
        self.assertEqual(outlier_result["arbitrationTier"], "success")
        self.assertEqual(outlier_result["arbitrationVerdict"], "Clean Residential (1 Minor Attribute Dispute)")
        self.assertFalse(outlier_result["isMajorityProxyVpn"])

        # Proxycheck riskScore counts as a behavioural signal and prevents outlier dismissal
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
