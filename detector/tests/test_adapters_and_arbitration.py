"""Tests for provider adapters, secret redaction, reverse DNS and CIDR attribution, and arbitration."""

import asyncio
import copy
import json
import os
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.name
import dns.resolver
import dns.reversename
import httpx
from django.test import SimpleTestCase, TestCase, override_settings

from detector import cache_backends, dns_providers, providers, sanitization, views
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
from detector.provider_registry import (
    COMMERCIAL_ARBITRATION_PROVIDERS,
    DEFAULT_QUOTA_LIMITS,
    PROVIDER_REGISTRY,
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
    start_non_dnsbl_provider_stubs,
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
            cleaned = sanitization.sanitize_error_message(message)

        for leaked in ("secret123", "abc999", "me@example.org", "tok-777", "s3cr3t", "hunter2", "bearer-xyz"):
            self.assertNotIn(leaked, cleaned)
        self.assertIn("key=***REDACTED***&ip=1.1.1.1", cleaned)
        self.assertIn("api-key=***REDACTED***", cleaned)
        self.assertIn("contact=***REDACTED***&format=json", cleaned)
        self.assertIn("ip=1.1.1.1", cleaned)

    def test_sanitize_redacts_configured_and_dynamic_keys_and_handles_edge_inputs(self):
        with override_settings(**TEST_UPSTREAM_SECRETS), patch.dict(os.environ, TEST_UPSTREAM_SECRETS):
            cleaned = sanitization.sanitize_error_message(
                "Header X-Key iphub-key-81fa rejected, contact ops-contact%40example.org"
            )
        self.assertNotIn("iphub-key-81fa", cleaned)
        self.assertNotIn("ops-contact", cleaned)
        self.assertEqual(cleaned.count("***REDACTED***"), 2)

        with override_settings(**EMPTY_UPSTREAM_SECRETS), patch.dict(os.environ, EMPTY_UPSTREAM_SECRETS):
            self.assertEqual(sanitization.sanitize_error_message("plain upstream failure"), "plain upstream failure")
            self.assertEqual(sanitization.sanitize_error_message(""), "")
            self.assertEqual(sanitization.sanitize_error_message(None), "")

            with override_settings(IPDATA_API_KEY="first-dynamic-key-1001"):
                first_cached = sanitization.configured_secret_values()
                self.assertIs(first_cached, sanitization.configured_secret_values())
                first_cleaned = sanitization.sanitize_error_message(
                    "Upstream rejected key first-dynamic-key-1001 with Bearer tok-abc123"
                )
                self.assertNotIn("first-dynamic-key-1001", first_cleaned)
                self.assertNotIn("tok-abc123", first_cleaned)
                self.assertIn("Bearer ***REDACTED***", first_cleaned)

            with override_settings(IPDATA_API_KEY="rotated-dynamic-key-2002"):
                rotated_cached = sanitization.configured_secret_values()
                self.assertIsNot(first_cached, rotated_cached)
                rotated_cleaned = sanitization.sanitize_error_message("Upstream rejected key rotated-dynamic-key-2002")
                self.assertNotIn("rotated-dynamic-key-2002", rotated_cleaned)
                self.assertIn("***REDACTED***", rotated_cleaned)

    @patch("detector.dns_providers.query_maxmind", new_callable=AsyncMock)
    @patch("detector.http_client.httpx.AsyncClient")
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
            patch("detector.cache_backends.redis_client", mock_redis),
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

    @patch("detector.dns_providers.query_maxmind", new_callable=AsyncMock)
    @patch("detector.http_client.httpx.AsyncClient")
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
            patch("detector.cache_backends.redis_client", None),
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

        rate_limited = adapt_iphub([], True, 429)
        self.assertEqual(rate_limited["status"], "429 Rate Limited")

    def test_adapters_degrade_or_normalise_edge_field_payloads(self):
        for block in (None, "invalid", "NaN", [], {}):
            with self.subTest(provider="IPHub", block=block):
                result = adapt_iphub({"ip": "8.8.8.8", "block": block}, True, 200)
                self.assertEqual(result["status"], "502 Error")
                self.assertIsNone(result["block"])

        iphub_str = adapt_iphub({"ip": "8.8.8.8", "block": "1", "countryCode": "US"}, True, 200)
        self.assertEqual(iphub_str["status"], "200 OK")
        self.assertEqual(iphub_str["block"], 1)
        self.assertTrue(any(flag["isHighRisk"] for flag in iphub_str["securityFlags"]))

        for payload in ({"block": None}, {"block": "invalid"}, {"data": {"block": "NaN"}}):
            with self.subTest(provider="IPHunter", payload=payload):
                result = adapt_iphunter(payload, True, 200)
                self.assertEqual(result["status"], "502 Error")
                self.assertIsNone(result["block"])

        iphunter_default = adapt_iphunter({"data": {"ip": "8.8.8.8", "country_code": "us"}}, True, 200)
        self.assertEqual(iphunter_default["status"], "200 OK")
        self.assertEqual(iphunter_default["block"], 0)
        self.assertEqual(iphunter_default["countryCode"], "US")

        self.assertEqual(adapt_getipintel({"status": "success", "result": "NaN"}, True, 200)["status"], "400 Error")
        self.assertEqual(adapt_cloudflare_radar(None, False)["organisation"], "-")
        self.assertEqual(adapt_cloudflare_radar({"success": False}, True, 429)["organisation"], "-")
        cf_null = adapt_cloudflare_radar({"success": True, "result": None}, True, 200)
        self.assertEqual(cf_null["status"], "200 OK")
        self.assertEqual(cf_null["asn"], "-")
        self.assertEqual(adapt_abuseipdb({"data": None}, True, 200)["status"], "200 Error")

    @patch("detector.dns_providers.query_maxmind", new_callable=AsyncMock)
    @patch("detector.http_client.httpx.AsyncClient")
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
                    patch("detector.cache_backends.redis_client", None),
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

    def test_maxmind_user_type_classification_and_arbitration_impact(self):
        cases = (
            ("geolite2_missing_user_type", {}, "unknown", [{"label": "No Flags", "isHighRisk": False}]),
            (
                "geoip2_hosting",
                {"traits": {"user_type": "hosting"}},
                "hosting",
                [{"label": "Hosting", "isHighRisk": True}],
            ),
            (
                "geoip2_residential",
                {"traits": {"user_type": "residential"}},
                "residential",
                [{"label": "No Flags", "isHighRisk": False}],
            ),
            ("corrupted_traits", {"traits": "corrupted"}, "unknown", [{"label": "No Flags", "isHighRisk": False}]),
        )
        for label, extra, expected_usage, expected_flags in cases:
            with self.subTest(case=label):
                result = adapt_maxmind({**self.GEOLITE2_RECORD, **extra}, True, 200)
                self.assertEqual(result["status"], "200 OK")
                self.assertEqual(result["usageType"], expected_usage)
                self.assertEqual(result["securityFlags"], expected_flags)

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
        with patch("detector.sanitization.sanitize_payload", wraps=sanitization.sanitize_payload) as spy_sanitize:
            decoded_sanitized = cache_backends._decode_cached_provider_entry(sanitized_entry)
            self.assertIsNotNone(decoded_sanitized)
            self.assertEqual(spy_sanitize.call_count, 0)

            decoded_legacy = cache_backends._decode_cached_provider_entry(legacy_entry)
            self.assertIsNotNone(decoded_legacy)
            self.assertGreater(spy_sanitize.call_count, 0)
            self.assertIn("key=***REDACTED***", decoded_legacy[0]["rawJson"]["detail"])

    @patch(
        "dns.asyncresolver.Resolver.resolve",
        new_callable=AsyncMock,
        side_effect=dns.exception.Timeout("DNS timed out"),
    )
    @patch("detector.dns_providers.query_maxmind", new_callable=AsyncMock)
    @patch("detector.http_client.httpx.AsyncClient")
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
                    patch("detector.cache_backends.redis_client", mock_redis),
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
            hostname = asyncio.run(dns_providers.query_rdns_ptr("54.239.28.85"))
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

    def test_cidr_attribution_defaults_and_mmdb_prefix_selection(self):
        cases = (
            ("v4_default", "203.0.113.45", None, "203.0.113.0/24", "203.0.113.0/24", None),
            (
                "v6_default",
                "2001:db8:abcd:1234:5678::1",
                None,
                "2001:db8:abcd:1234::/64",
                "2001:db8:abcd:1234::/64",
                None,
            ),
            ("v4_narrow", "203.0.113.45", 28, "203.0.113.32/28", "203.0.113.0/24", "203.0.113.32/28"),
            (
                "v6_narrow",
                "2001:db8:abcd:1234:5678::1",
                80,
                "2001:db8:abcd:1234:5678::/80",
                "2001:db8:abcd:1234::/64",
                "2001:db8:abcd:1234:5678::/80",
            ),
            ("v4_wide", "203.0.113.45", 16, "203.0.113.0/24", "203.0.113.0/24", "203.0.0.0/16"),
            (
                "v6_wide",
                "2001:db8:abcd:1234:5678::1",
                48,
                "2001:db8:abcd:1234::/64",
                "2001:db8:abcd:1234::/64",
                "2001:db8:abcd::/48",
            ),
        )
        for label, ip, prefix_len, expected_rec, expected_def, expected_mmdb in cases:
            with self.subTest(case=label):
                attribution = compute_cidr_attribution(ip, prefix_len)
                self.assertEqual(attribution["recommendedCidr"], expected_rec)
                self.assertEqual(attribution["defaultCidr"], expected_def)
                self.assertEqual(attribution["mmdbCidr"], expected_mmdb)

    def test_maxmind_sync_extracts_prefix_length_for_aggregation(self):
        cache_backends._maxmind_readers.clear()
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
            patch("detector.dns_providers.os.path.exists", side_effect=lambda p: "asn" in str(p).lower()),
            patch.dict("sys.modules", {"maxminddb": mock_maxmind_module}),
        ):
            mm_row = dns_providers._read_maxmind_sync("54.239.28.85")

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

    def test_cache_conditions_preserved_across_rdns_and_upstream_states(self):
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

        mocks = start_non_dnsbl_provider_stubs(
            self,
            overrides={"maxmind": dict(MAXMIND_STUB)},
            row_builder=_ok_provider,
        )
        mock_cf = mocks["cloudflare_radar"]

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
            patch("detector.cache_backends.redis_client", mock_redis),
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
            patch("detector.cache_backends.redis_client", mock_redis),
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

    def test_commercial_adapters_extract_risk_carrier_and_report_metadata(self):
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

        ip2loc_mobile = adapt_ip2location(
            {"asn": "21928", "mobile_brand": "  T-Mobile  ", "usage_type": "-", "country_code": "US"},
            has_api_key=True,
        )
        self.assertEqual(ip2loc_mobile["mobileBrand"], "T-Mobile")
        self.assertEqual(ip2loc_mobile["usageType"], "mobile")
        self.assertEqual(ip2loc_mobile["isp"], "T-Mobile")

        ip2loc_dash = adapt_ip2location(
            {"asn": "1221", "as": "Telstra Corporation Ltd", "mobile_brand": "-", "usage_type": "ISP"},
            has_api_key=True,
        )
        self.assertIsNone(ip2loc_dash["mobileBrand"])
        self.assertEqual(ip2loc_dash["usageType"], "ISP")

        abuse_row = adapt_abuseipdb(
            {
                "data": {
                    "abuseConfidenceScore": 85,
                    "totalReports": 42,
                    "numDistinctUsers": 17,
                    "lastReportedAt": "2026-10-01T12:30:00+00:00",
                    "isp": "Hetzner Online GmbH",
                    "countryCode": "DE",
                }
            },
            has_api_key=True,
        )
        self.assertEqual(abuse_row["totalReports"], 42)
        self.assertEqual(abuse_row["numDistinctUsers"], 17)
        self.assertEqual(abuse_row["lastSeen"], "2026-10-01T12:30:00+00:00")

        clamped_row = adapt_abuseipdb(
            {"data": {"abuseConfidenceScore": 0, "totalReports": -5, "numDistinctUsers": "bad", "lastReportedAt": " "}},
            has_api_key=True,
        )
        self.assertEqual(clamped_row["totalReports"], 0)
        self.assertIsNone(clamped_row["numDistinctUsers"])
        self.assertIsNone(clamped_row["lastSeen"])
        self.assertIsNone(adapt_abuseipdb(None, has_api_key=True, status_code=429)["totalReports"])


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


class CrossStackProviderContractTests(SimpleTestCase):
    """Tests provider registry alignment across backend, TypeScript helpers, and MediaWiki gadget."""

    def test_provider_registry_aligns_with_frontend_and_userscript_contracts(self):
        repo_root = Path(__file__).resolve().parent.parent.parent
        ts_source = (repo_root / "src" / "utils" / "ip-detector-logic.ts").read_text(encoding="utf-8")
        gadget_source = (repo_root / "scripts" / "user-gadget.js").read_text(encoding="utf-8")

        expected_labels = [meta.label for meta in PROVIDER_REGISTRY]
        spec_labels = [spec.label for spec in providers.PROVIDER_SPECS]
        self.assertEqual(spec_labels, expected_labels)
        self.assertEqual(DEFAULT_QUOTA_LIMITS["getipintel"], (15, 500))

        ts_provider_block = re.search(r"export const PROVIDER_NAMES\s*=\s*\[(.*?)\]\s*as const;", ts_source, re.S)
        self.assertIsNotNone(ts_provider_block)
        ts_providers = re.findall(r"'([^']+)'", ts_provider_block.group(1))
        self.assertEqual(ts_providers, expected_labels)

        ts_comm_block = re.search(
            r"export const COMMERCIAL_ARBITRATION_PROVIDERS\s*=\s*\[(.*?)\]\s*as const;",
            ts_source,
            re.S,
        )
        self.assertIsNotNone(ts_comm_block)
        ts_commercial = set(re.findall(r"'([^']+)'", ts_comm_block.group(1)))
        self.assertEqual(ts_commercial, set(COMMERCIAL_ARBITRATION_PROVIDERS))

        gadget_comm_block = re.search(r"var COMMERCIAL_PROVIDERS\s*=\s*\{(.*?)\};", gadget_source, re.S)
        self.assertIsNotNone(gadget_comm_block)
        gadget_commercial = set(re.findall(r"'([^']+)'\s*:\s*true", gadget_comm_block.group(1)))
        self.assertEqual(gadget_commercial, set(COMMERCIAL_ARBITRATION_PROVIDERS))

        palette_block = re.search(r"var PROVIDER_BADGE_PALETTES\s*=\s*\{(.*?)\n    \};", gadget_source, re.S)
        self.assertIsNotNone(palette_block)
        palette_keys = set(re.findall(r"'([^']+)'\s*:\s*\{", palette_block.group(1)))
        self.assertTrue(set(expected_labels).issubset(palette_keys))

        self.assertNotIn(".html(", gadget_source)
        self.assertNotIn("innerHTML", gadget_source)
