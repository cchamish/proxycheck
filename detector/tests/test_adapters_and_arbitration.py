"""Core P0 tests for secret redaction, DNS log safety, malformed upstream defence, and arbitration."""

import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import dns.exception
from django.test import SimpleTestCase, TestCase, override_settings

from detector.core import sanitization
from detector.detection.arbitration import aggregate_intelligence_metrics
from detector.offline import feeds as offline_feeds
from detector.providers import dns as dns_providers
from detector.providers.local import adapt_oxylabs

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
            patch("detector.providers.dns._create_async_resolver") as mock_resolver_cls,
            patch("detector.providers.dns.record_upstream_event"),
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

    def test_oxylabs_offline_lookup_deduplicates_by_updated_at_throttles_scans_and_locks_cidr(self):
        """Loads Oxylabs JSONL datasets with updated_at precedence, scan throttling, and single-IP CIDR locking."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            data_dir = Path(tmp_dir)
            (data_dir / "a.jsonl").write_text(
                "\n".join(
                    [
                        "not-json",
                        json.dumps(
                            {
                                "ip": "198.51.100.42",
                                "asn": 64500,
                                "org_name": "Old ISP",
                                "updated_at": "2026-10-01T00:00:00Z",
                            }
                        ),
                        json.dumps(
                            {
                                "ip": "2001:0db8::0001",
                                "asn": "AS64501",
                                "org_name": "V6 ISP",
                                "updated_at": "2026-11-01T00:00:00Z",
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (data_dir / "b.jsonl").write_text(
                json.dumps(
                    {
                        "ip": "198.51.100.42",
                        "asn": 64512,
                        "org_name": "Newer ISP",
                        "updated_at": "2026-11-15T00:00:00Z",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            offline_feeds.clear_offline_feed_caches()
            self.addCleanup(offline_feeds.clear_offline_feed_caches)

            with (
                override_settings(OXYLABS_DATA_DIR=str(data_dir)),
                patch.object(Path, "glob", autospec=True, wraps=Path.glob) as spy_glob,
            ):
                v4_hit = offline_feeds.query_oxylabs_offline("198.51.100.42")
                mapped_hit = offline_feeds.query_oxylabs_offline("::ffff:198.51.100.42")
                v6_hit = offline_feeds.query_oxylabs_offline("2001:db8::1")
                clean_hit = offline_feeds.query_oxylabs_offline("198.51.100.99")
                self.assertEqual(spy_glob.call_count, 1)

            self.assertTrue(v4_hit["has_db"] and v4_hit["isListed"])
            self.assertEqual((v4_hit["asn"], v4_hit["orgName"], v4_hit["sourceFile"]), (64512, "Newer ISP", "b.jsonl"))
            self.assertTrue(mapped_hit["isListed"])
            self.assertTrue(v6_hit["isListed"])
            self.assertEqual(v6_hit["asn"], 64501)
            self.assertTrue(clean_hit["has_db"] and not clean_hit["isListed"])

            for target_ip, raw_lookup, expected_cidr in (
                ("198.51.100.42", v4_hit, "198.51.100.42/32"),
                ("2001:db8::1", v6_hit, "2001:db8::1/128"),
            ):
                with self.subTest(ip=target_ip):
                    row = adapt_oxylabs(raw_lookup, status_code=200, has_db=True)
                    metrics = aggregate_intelligence_metrics(target_ip, [row], None)
                    self.assertTrue(metrics["confirmedResidentialProxy"])
                    self.assertEqual(metrics["confirmedResidentialProxyProvider"], "Oxylabs")
                    self.assertEqual(metrics["arbitrationTier"], "destructive")
                    self.assertEqual(metrics["recommendedCidr"], expected_cidr)
                    self.assertIsNone(metrics["escalationCidr"])

            missing_row = adapt_oxylabs(None, has_db=False)
            self.assertEqual(missing_row["status"], "Offline DB Missing")


class NonMutationSanityTests(SimpleTestCase):
    """Lightweight sanity test confirming adapter registry integrity."""

    def test_adapter_registry_covers_all_providers(self):
        self.assertGreaterEqual(len(ALL_ADAPTERS), 16)
