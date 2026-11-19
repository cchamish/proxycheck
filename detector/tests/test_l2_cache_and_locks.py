"""Core P0 tests for Redis namespace/JSON serializer hardening, L2 compliance, and ToolsDB degradation."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from django.db import OperationalError
from django.test import TestCase

from detector import l2_cache
from detector.provider_registry import JsonRedisSerializer, build_redis_namespace, hash_ip_for_redis
from proxycheck.settings import _build_default_cache_config


class L2CacheAndRedisHardeningTests(TestCase):
    """P0 tests for Redis JSON session serialisation, L2 compliance stripping, and DB failure fallback."""

    def test_redis_hmac_namespace_and_json_session_serializer(self):
        """Verifies HMAC Redis key prefixes and Pickle-free JSON session serialisation."""
        cfg = _build_default_cache_config(
            "redis://127.0.0.1:6379/0", "proxycheck_prod", is_test_run=False, key_secret="s3cr3t"
        )
        self.assertEqual(cfg["BACKEND"], "django.core.cache.backends.redis.RedisCache")
        self.assertEqual(cfg["KEY_PREFIX"], build_redis_namespace("proxycheck_prod", "s3cr3t"))
        self.assertEqual(cfg["OPTIONS"]["serializer"], "detector.provider_registry.JsonRedisSerializer")
        self.assertNotEqual(
            build_redis_namespace("proxycheck_prod", "secret-a"),
            build_redis_namespace("proxycheck_prod", "secret-b"),
        )
        self.assertNotIn("8.8.8.8", hash_ip_for_redis("8.8.8.8", "s3cr3t"))

        serializer = JsonRedisSerializer()
        self.assertEqual(serializer.dumps(42), 42)
        encoded = serializer.dumps({"wikimedia_user": {"username": "Patroller", "hasAccess": True}})
        self.assertIsInstance(encoded, bytes)
        self.assertEqual(serializer.loads(encoded)["wikimedia_user"]["username"], "Patroller")
        self.assertEqual(serializer.loads(b"42"), 42)
        with self.assertRaises(ValueError):
            serializer.loads(b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00")

    def test_l2_compliance_sanitisation_and_thirty_day_ip2location_filter(self):
        """Strips forbidden keys/offline/L1 providers from L2 and enforces 30-day IP2Location retention."""
        raw_snapshot = {
            "ip": "203.0.113.9",
            "queryMode": "full",
            "memoryMb": 128.5,
            "username": "LeakyUser",
            "results": [
                {
                    "provider": "IP2Location",
                    "status": "200 OK",
                    "statusCode": 200,
                    "asn": "AS64500",
                    "rawJson": {"secret": "k"},
                },
                {"provider": "AbuseIPDB", "status": "200 OK", "statusCode": 200, "asn": "AS64500", "rawJson": {"x": 1}},
                {
                    "provider": "Shodan InternetDB",
                    "status": "200 OK",
                    "statusCode": 200,
                    "tags": ["vpn", "CVE-2024-0001"],
                    "vulns": ["CVE-1"],
                },
                {"provider": "MaxMind", "status": "200 OK", "statusCode": 200},
                {"provider": "IPHub", "status": "200 OK", "statusCode": 200},
            ],
        }
        sanitised = l2_cache.sanitize_snapshot_for_l2(raw_snapshot)
        self.assertNotIn("memoryMb", sanitised)
        self.assertNotIn("username", sanitised)
        providers_kept = {row["provider"]: row for row in sanitised["results"]}
        self.assertEqual(set(providers_kept), {"IP2Location", "AbuseIPDB", "Shodan InternetDB"})
        self.assertNotIn("rawJson", providers_kept["IP2Location"])
        self.assertEqual(providers_kept["Shodan InternetDB"]["tags"], ["vpn"])
        self.assertNotIn("vulns", providers_kept["Shodan InternetDB"])

        old_dt = datetime.now(timezone.utc) - timedelta(days=31)
        merged = l2_cache.merge_and_upsert_l2_snapshot("203.0.113.9", raw_snapshot, query_mode="full", now_dt=old_dt)
        self.assertTrue(merged.saved)

        loaded = l2_cache.get_ip_snapshot("203.0.113.9", mode="full", now_dt=datetime.now(timezone.utc))
        self.assertIsNotNone(loaded)
        loaded_providers = {row["provider"] for row in loaded["results"]}
        self.assertNotIn("IP2Location", loaded_providers)
        self.assertIn("AbuseIPDB", loaded_providers)

    def test_l2_toolsdb_failure_degrades_cleanly_to_upstream(self):
        """Returns None and unsaved fallback without crashing when ToolsDB raises OperationalError."""
        with patch("detector.l2_cache.IpIntelligenceCache.objects.filter", side_effect=OperationalError("db down")):
            self.assertIsNone(l2_cache.get_ip_snapshot("8.8.8.8", mode="full"))
            merge_res = l2_cache.merge_and_upsert_l2_snapshot("8.8.8.8", {"ip": "8.8.8.8", "results": []})
            self.assertFalse(merge_res.saved)
