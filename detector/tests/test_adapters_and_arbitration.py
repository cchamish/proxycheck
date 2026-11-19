"""Core P0 tests for secret redaction, DNS log safety, malformed upstream defence, and arbitration."""

import asyncio
from unittest.mock import AsyncMock, patch

import dns.exception
from django.test import SimpleTestCase, TestCase, override_settings

from detector import dns_providers, sanitization
from detector.intelligence import aggregate_intelligence_metrics

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
            patch("detector.dns_providers._create_async_resolver") as mock_resolver_cls,
            patch("detector.dns_providers.record_upstream_event"),
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


class NonMutationSanityTests(SimpleTestCase):
    """Lightweight sanity test confirming adapter registry integrity."""

    def test_adapter_registry_covers_all_providers(self):
        self.assertGreaterEqual(len(ALL_ADAPTERS), 16)
