"""Core P0 tests for provider quota guards, daily salted volatile endpoint rate limits, and telemetry."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import patch

from django.test import TestCase, override_settings

from detector import cache_backends, quota_telemetry

from .helpers import FakeAsyncRedis


class QuotaAndRateLimitTests(TestCase):
    """P0 tests for proactive provider quotas, endpoint rate limits, and anonymised telemetry."""

    def setUp(self):
        cache_backends.reset_redis_circuit_breaker()
        quota_telemetry._DAILY_RL_SALT_CACHE.clear()

    def test_proactive_provider_quota_blocks_excess_and_fails_open_on_redis_error(self):
        """Blocks calls past configured provider RPM limit and fails open on Redis transport errors."""
        fake_redis = FakeAsyncRedis()
        with (
            patch("detector.cache_backends.redis_client", fake_redis),
            override_settings(ABUSEIPDB_RPM_LIMIT=1, ABUSEIPDB_DAILY_LIMIT=100),
        ):
            first = asyncio.run(quota_telemetry.check_and_consume_quota("abuseipdb"))
            second = asyncio.run(quota_telemetry.check_and_consume_quota("abuseipdb"))
        self.assertTrue(first.allowed)
        self.assertFalse(second.allowed)
        self.assertEqual(second.window, "rpm")

        broken_redis = FakeAsyncRedis()

        async def _raise_conn(*_args, **_kwargs):
            raise ConnectionError("redis unreachable")

        broken_redis.pipeline = lambda *a, **kw: (_ for _ in ()).throw(ConnectionError("redis unreachable"))
        broken_redis.eval = _raise_conn
        with patch("detector.cache_backends.redis_client", broken_redis):
            degraded = asyncio.run(quota_telemetry.check_and_consume_quota("abuseipdb"))
        self.assertTrue(degraded.allowed)

    def test_volatile_endpoint_rate_limits_and_daily_salted_user_digest(self):
        """Enforces detect/batch/gadget-token limits using daily rotating salted username digests."""
        fake_redis = FakeAsyncRedis()
        fixed_dt = datetime(2026, 11, 20, 12, 0, 10, tzinfo=timezone.utc)
        with (
            patch("detector.cache_backends.redis_client", fake_redis),
            override_settings(
                DETECT_USER_RPM_LIMIT=1,
                DETECT_GLOBAL_RPM_LIMIT=600,
                DETECT_BATCH_USER_RPM_LIMIT=1,
                DETECT_BATCH_GLOBAL_RPM_LIMIT=100,
                GADGET_TOKEN_GLOBAL_RPM_LIMIT=1,
            ),
        ):
            d1 = asyncio.run(
                quota_telemetry.check_and_consume_endpoint_rate_limit("detect", "AlicePatroller", now_dt=fixed_dt)
            )
            d2 = asyncio.run(
                quota_telemetry.check_and_consume_endpoint_rate_limit("detect", "AlicePatroller", now_dt=fixed_dt)
            )
            b1 = asyncio.run(
                quota_telemetry.check_and_consume_endpoint_rate_limit("detect_batch", "AlicePatroller", now_dt=fixed_dt)
            )
            b2 = asyncio.run(
                quota_telemetry.check_and_consume_endpoint_rate_limit("detect_batch", "AlicePatroller", now_dt=fixed_dt)
            )
            g1 = asyncio.run(quota_telemetry.check_and_consume_endpoint_rate_limit("gadget_token", now_dt=fixed_dt))
            g2 = asyncio.run(quota_telemetry.check_and_consume_endpoint_rate_limit("gadget_token", now_dt=fixed_dt))

        self.assertTrue(d1.allowed and not d2.allowed and d2.reason == "detect_user_rpm")
        self.assertTrue(b1.allowed and not b2.allowed and b2.reason == "detect_batch_user_rpm")
        self.assertTrue(g1.allowed and not g2.allowed and g2.reason == "gadget_token_global_rpm")
        joined_keys = " ".join(fake_redis.strings.keys())
        self.assertIn(":rl_salt:day:20261120", joined_keys)
        self.assertNotIn("AlicePatroller", joined_keys)

    def test_telemetry_anonymisation_never_stores_ip_or_username(self):
        """Stores aggregated daily counters in Redis without recording plaintext IPs or usernames."""
        fake_redis = FakeAsyncRedis()
        fixed_dt = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
        with patch("detector.cache_backends.redis_client", fake_redis):
            asyncio.run(
                quota_telemetry.record_global_request_telemetry(
                    "hit", "gadget", cache_layer_event="l1_hit", now_dt=fixed_dt
                )
            )
            asyncio.run(
                quota_telemetry.record_provider_outcomes_batch(
                    [{"provider_key": "abuseipdb", "outcome": "ok"}],
                    now_dt=fixed_dt,
                )
            )
        serialised = repr(fake_redis.hashes) + repr(fake_redis.strings)
        self.assertIn("l1_hit", serialised)
        self.assertNotIn("8.8.8.8", serialised)
        self.assertNotIn("SysopUser", serialised)
