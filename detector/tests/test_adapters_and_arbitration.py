"""Core P0 tests for secret redaction, DNS log safety, malformed upstream defence, and arbitration."""

import asyncio
from unittest.mock import AsyncMock, patch

import dns.exception
from django.test import SimpleTestCase, TestCase, override_settings

from detector.core import sanitization
from detector.detection.arbitration import aggregate_intelligence_metrics
from detector.providers import adapt_proxycheck
from detector.providers import dns_local as dns_providers

from .helpers import ALL_ADAPTERS, MAXMIND_STUB, TEST_UPSTREAM_SECRETS


class AdaptersAndArbitrationTests(TestCase):
    """P0 tests for secret redaction, malformed upstream survival, and arbitration invariants."""

    def setUp(self):
        sanitization.clear_secret_values_cache()
        self.addCleanup(sanitization.clear_secret_values_cache)

    def test_credential_redaction_strips_secrets_from_errors_payloads_and_dns_logs(self):
        """Redacts configured API keys from errors/payloads and omits query targets from DNSBL warnings."""
        with override_settings(**TEST_UPSTREAM_SECRETS):
            sanitization.clear_secret_values_cache()
            raw_err = f"https://api.example.org/check?key={TEST_UPSTREAM_SECRETS['PROXYCHECK_API_KEY']}&token={TEST_UPSTREAM_SECRETS['IPDATA_API_KEY']}"
            redacted = sanitization.sanitize_error_message(raw_err)
            self.assertNotIn(TEST_UPSTREAM_SECRETS["PROXYCHECK_API_KEY"], redacted)
            self.assertNotIn(TEST_UPSTREAM_SECRETS["IPDATA_API_KEY"], redacted)
            nested = sanitization.sanitize_payload(
                {"error": raw_err, "items": [TEST_UPSTREAM_SECRETS["ABUSEIPDB_API_KEY"]]}
            )
            self.assertNotIn(TEST_UPSTREAM_SECRETS["ABUSEIPDB_API_KEY"], str(nested))

        with (
            patch("detector.providers.dns_local._create_async_resolver") as mock_resolver_cls,
            patch("detector.providers.dns_local.record_upstream_event"),
            self.assertLogs("detector.views", level="WARNING") as captured,
        ):
            mock_resolver = AsyncMock()
            mock_resolver.resolve.side_effect = dns.exception.Timeout("timed out")
            mock_resolver_cls.return_value = mock_resolver
            asyncio.run(dns_providers.query_spamhaus_zen("8.8.4.4"))

        joined_logs = "\n".join(captured.output)
        self.assertIn("Spamhaus ZEN DNS query timed out", joined_logs)
        self.assertNotIn("4.4.8.8", joined_logs)
        self.assertNotIn("zen.spamhaus.org", joined_logs)

    def test_all_adapters_handle_malformed_and_non_dict_payloads(self):
        """Ensures every adapter degrades gracefully on non-dict or malformed upstream JSON."""
        for name, adapter_fn in ALL_ADAPTERS:
            for bad_input in (None, [], "invalid", {"unexpected": 1}):
                with self.subTest(provider=name, bad_input=type(bad_input).__name__):
                    row = adapter_fn(bad_input, 200)
                    self.assertEqual(row["provider"], name)
                    self.assertIn("status", row)

    def test_arbitration_computes_verdict_and_does_not_mutate_inputs(self):
        """Computes consensus arbitration verdict without mutating input provider rows."""
        proxy_row = {
            "provider": "AbuseIPDB",
            "status": "200 OK",
            "statusCode": 200,
            "asn": "AS14061",
            "isp": "DigitalOcean",
            "organisation": "DigitalOcean",
            "location": "United States",
            "usageType": "Data Center/Web Hosting/Transit",
            "securityFlags": [{"label": "Abuse Score: 90%", "isHighRisk": True}],
            "rawJson": {},
        }
        snapshot_copy = dict(proxy_row)
        metrics = aggregate_intelligence_metrics("198.51.100.10", [dict(MAXMIND_STUB), proxy_row], None)
        self.assertEqual(proxy_row, snapshot_copy)
        self.assertIn("arbitrationVerdict", metrics)
        self.assertEqual(metrics["primaryAsn"], "AS14061")

    def test_adapt_proxycheck_parses_flat_v3_payload(self):
        """Preserves detections, risk score, location, and network metadata for flat v3 payloads."""
        flat_payload = {
            "status": "ok",
            "network": {"asn": "AS15169", "provider": "Google LLC", "type": "ISP"},
            "location": {"city": "Mountain View", "country_name": "United States", "country_code": "US"},
            "detections": {
                "proxy": True,
                "vpn": True,
                "tor": False,
                "hosting": False,
                "risk": 99,
                "port": 443,
                "last_seen": "2026-11-20T12:00:00Z",
            },
        }
        for ip_arg in ("8.8.8.8", ""):
            with self.subTest(ip=ip_arg):
                row = adapt_proxycheck(flat_payload, has_api_key=True, status_code=200, ip=ip_arg)
                self.assertEqual(row["status"], "200 OK")
                self.assertEqual(row["asn"], "AS15169")
                self.assertEqual(row["isp"], "Google LLC")
                self.assertEqual(row["location"], "Mountain View, United States")
                self.assertEqual(row["countryCode"], "US")
                self.assertEqual(row["usageType"], "isp")
                self.assertEqual(row["riskScore"], 99)
                self.assertEqual(row["port"], 443)
                self.assertEqual(row["lastSeen"], "2026-11-20T12:00:00Z")
                self.assertEqual(
                    row["securityFlags"],
                    [
                        {"label": "Proxy", "isHighRisk": True},
                        {"label": "VPN", "isHighRisk": True},
                    ],
                )

    def test_adapt_proxycheck_parses_ip_keyed_v2_and_v3_payloads(self):
        """Still extracts records keyed by IP for v2, v3, omitted ip, and non-canonical IPv6 keys."""
        v3_ip_keyed = {
            "status": "ok",
            "2001:0db8::1": {
                "network": {"asn": "AS64496", "provider": "Example Hosting", "type": "Hosting"},
                "location": {"city": "London", "country_name": "United Kingdom", "country_code": "GB"},
                "detections": {"proxy": False, "vpn": False, "tor": True, "hosting": True, "risk": 88},
            },
            "query_time": "5ms",
        }
        for ip_arg in ("2001:0db8::1", "2001:db8::1", ""):
            with self.subTest(case="v3_ip_keyed", ip=ip_arg):
                row = adapt_proxycheck(v3_ip_keyed, has_api_key=True, status_code=200, ip=ip_arg)
                self.assertEqual(row["asn"], "AS64496")
                self.assertEqual(row["isp"], "Example Hosting")
                self.assertEqual(row["location"], "London, United Kingdom")
                self.assertEqual(row["countryCode"], "GB")
                self.assertEqual(row["usageType"], "hosting")
                self.assertEqual(row["riskScore"], 88)
                self.assertEqual(
                    row["securityFlags"],
                    [
                        {"label": "Tor", "isHighRisk": True},
                        {"label": "Hosting", "isHighRisk": True},
                    ],
                )

        v2_ip_keyed = {
            "status": "ok",
            "198.51.100.1": {
                "asn": "AS14061",
                "provider": "DigitalOcean",
                "country": "United States",
                "isocode": "US",
                "city": "New York",
                "proxy": "yes",
                "type": "VPN",
                "risk": 66,
            },
        }
        row = adapt_proxycheck(v2_ip_keyed, has_api_key=True, status_code=200, ip="198.51.100.1")
        self.assertEqual(row["asn"], "AS14061")
        self.assertEqual(row["isp"], "DigitalOcean")
        self.assertEqual(row["location"], "New York, United States")
        self.assertEqual(row["countryCode"], "US")
        self.assertEqual(row["riskScore"], 66)
        self.assertEqual(
            row["securityFlags"],
            [
                {"label": "Proxy", "isHighRisk": True},
                {"label": "VPN", "isHighRisk": True},
            ],
        )


class NonMutationSanityTests(SimpleTestCase):
    """Lightweight sanity test confirming adapter registry integrity."""

    def test_adapter_registry_covers_all_providers(self):
        self.assertGreaterEqual(len(ALL_ADAPTERS), 16)
