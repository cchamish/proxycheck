"""Tests for ToolsDB L2 persistent caching, Redis HMAC namespace isolation, and singleflight locks."""

from __future__ import annotations

import asyncio
import builtins
import hashlib
import hmac
import io
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import OperationalError
from django.test import SimpleTestCase, TestCase, override_settings

import proxycheck
from detector import cache_backends, l2_cache
from detector.management.commands import check_setup
from detector.models import IpIntelligenceCache
from detector.provider_registry import (
    DEFAULT_PROVIDER_L2_MAX_RETENTION_DAYS,
    EXTRA_SECRET_SETTING_NAMES,
    L1_ONLY_PROVIDERS,
    OFFLINE_REHYDRATE_PROVIDERS,
    PROVIDER_BY_KEY,
    PROVIDER_BY_LABEL,
    build_redis_namespace,
    hash_ip_for_redis,
)
from proxycheck.settings import (
    CACHE_SWR_STALE_DAYS,
    CACHE_SWR_STALE_SECONDS,
    ENABLE_L2_TOOLSDB_CACHE,
    PROVIDER_L2_MAX_RETENTION_DAYS,
    build_databases_config,
)

from .helpers import FakeAsyncRedis, _BatchingFakeRedis


def _make_provider_row(
    provider_label: str,
    *,
    status: str = "200 OK",
    status_code: Optional[int] = 200,
    is_high_risk: bool = False,
    flag_label: str = "Clean",
    raw_json: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "provider": provider_label,
        "status": status,
        "statusCode": status_code,
        "asn": "AS15169",
        "isp": "Example Transit",
        "organisation": "Example Org",
        "location": "London, United Kingdom",
        "usageType": "isp",
        "countryCode": "GB",
        "securityFlags": [{"label": flag_label, "isHighRisk": is_high_risk}],
        "rawJson": raw_json if raw_json is not None else {"secretEcho": "key=raw-token-999", "ok": True},
    }
    if extra:
        row.update(extra)
    return row


def _make_snapshot(
    ip: str = "203.0.113.42",
    *,
    rows: Optional[List[Dict[str, Any]]] = None,
    query_mode: str = "full",
    ptr_hostname: Optional[str] = "host.example.net",
    fetched_at: Optional[str] = None,
    provider_fetched_map: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    default_rows = [
        _make_provider_row("AbuseIPDB"),
        _make_provider_row("IPData"),
        _make_provider_row("Proxycheck", is_high_risk=True, flag_label="VPN"),
        _make_provider_row("IPRegistry"),
        _make_provider_row("Cloudflare Radar"),
        _make_provider_row(
            "Tor Onionoo",
            extra={"isTor": True, "torIsExit": True, "torRunning": True, "torFlags": ["Exit", "Fast"]},
        ),
    ]
    payload: Dict[str, Any] = {
        "ip": ip,
        "queryMode": query_mode,
        "ptrHostname": ptr_hostname,
        "results": rows if rows is not None else default_rows,
    }
    if fetched_at is not None:
        payload["fetchedAt"] = fetched_at
    if provider_fetched_map is not None:
        payload["providerFetchedMap"] = provider_fetched_map
    return payload


class _AtomicLockFakeRedis(FakeAsyncRedis):
    """Redis test double supporting NX lock semantics, DELETE, and atomic Lua lock release."""

    def __init__(self) -> None:
        super().__init__()
        self.eval_calls: List[tuple[Any, ...]] = []

    async def set(self, key: str, value: Any, ex: Optional[int] = None, nx: bool = False) -> bool:
        if nx and key in self.strings:
            return False
        return await super().set(key, value, ex=ex)

    async def delete(self, key: str) -> int:
        existed = key in self.strings
        self.strings.pop(key, None)
        self.ttls.pop(key, None)
        return 1 if existed else 0

    async def eval(self, script: str, numkeys: int, *keys_and_args: Any) -> int:
        self.eval_calls.append((script, numkeys, *keys_and_args))
        key = str(keys_and_args[0])
        expected_token = str(keys_and_args[1])
        if self.strings.get(key) == expected_token:
            await self.delete(key)
            return 1
        return 0


class DatabaseConfigAndRegistryTests(SimpleTestCase):
    """Tests PyMySQL bootstrap resilience, ToolsDB credential precedence, and registry metadata."""

    def test_pymysql_shim_handles_present_and_absent_driver(self) -> None:
        fake_pymysql = MagicMock()
        with patch.dict(sys.modules, {"pymysql": fake_pymysql}):
            exec(compile(Path(proxycheck.__file__).read_text(encoding="utf-8"), proxycheck.__file__, "exec"), {})  # noqa: S102
        fake_pymysql.install_as_MySQLdb.assert_called_once()

        real_import = builtins.__import__

        def _missing_pymysql(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "pymysql":
                raise ImportError("No module named pymysql")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_missing_pymysql):
            exec(compile(Path(proxycheck.__file__).read_text(encoding="utf-8"), proxycheck.__file__, "exec"), {})  # noqa: S102

    def test_toolsdb_credential_autodiscovery_precedence_and_sqlite_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            tool_dir = root / "tool_home"
            user_home = root / "user_home"
            tool_dir.mkdir()
            user_home.mkdir()

            (tool_dir / "replica.my.cnf").write_text(
                "[client]\nuser = 's51111'\npassword = \"cnf%pass%tool\"\n",
                encoding="utf-8",
            )
            (user_home / "replica.my.cnf").write_text(
                "[client]\nuser = s52222\npassword = cnf_pass_home\n",
                encoding="utf-8",
            )

            cases = (
                (
                    "explicit_toolsdb_env_wins_all",
                    {
                        "TOOLSDB_USER": "s50001",
                        "TOOLSDB_PASSWORD": "explicit-secret",
                        "TOOLSDB_NAME": "s50001__proxycheck_cache",
                        "TOOL_TOOLSDB_USER": "s50002",
                        "TOOL_TOOLSDB_PASSWORD": "injected-secret",
                        "TOOL_DATA_DIR": str(tool_dir),
                    },
                    "django.db.backends.mysql",
                    "s50001",
                    "explicit-secret",
                    "tools.db.svc.wikimedia.cloud",
                    3306,
                ),
                (
                    "custom_host_and_port_honoured",
                    {
                        "TOOLSDB_USER": "s50001",
                        "TOOLSDB_PASSWORD": "explicit-secret",
                        "TOOLSDB_NAME": "s50001__proxycheck_cache",
                        "TOOLSDB_HOST": "127.0.0.1",
                        "TOOLSDB_PORT": "3307",
                    },
                    "django.db.backends.mysql",
                    "s50001",
                    "explicit-secret",
                    "127.0.0.1",
                    3307,
                ),
                (
                    "buildpack_tool_toolsdb_wins_over_cnf",
                    {
                        "TOOL_TOOLSDB_USER": "s50002",
                        "TOOL_TOOLSDB_PASSWORD": "injected-secret",
                        "TOOL_TOOLSDB_NAME": "s50002__proxycheck_dev_cache",
                        "TOOL_DATA_DIR": str(tool_dir),
                    },
                    "django.db.backends.mysql",
                    "s50002",
                    "injected-secret",
                    "tools.db.svc.wikimedia.cloud",
                    3306,
                ),
                (
                    "tool_data_dir_replica_cnf_wins_over_home_cnf",
                    {
                        "TOOLSDB_NAME": "s51111__proxycheck_cache",
                        "TOOL_DATA_DIR": str(tool_dir),
                    },
                    "django.db.backends.mysql",
                    "s51111",
                    "cnf%pass%tool",
                    "tools.db.svc.wikimedia.cloud",
                    3306,
                ),
                (
                    "home_replica_cnf_used_when_tool_data_dir_unset",
                    {
                        "TOOLSDB_NAME": "s52222__proxycheck_cache",
                    },
                    "django.db.backends.mysql",
                    "s52222",
                    "cnf_pass_home",
                    "tools.db.svc.wikimedia.cloud",
                    3306,
                ),
            )

            for label, env_map, expected_engine, exp_user, exp_pass, exp_host, exp_port in cases:
                with self.subTest(case=label):
                    cfg = build_databases_config(env=env_map, base_dir=root, home_dir=user_home)["default"]
                    self.assertEqual(cfg["ENGINE"], expected_engine)
                    self.assertEqual(cfg["USER"], exp_user)
                    self.assertEqual(cfg["PASSWORD"], exp_pass)
                    self.assertEqual(cfg["HOST"], exp_host)
                    self.assertEqual(cfg["PORT"], exp_port)
                    self.assertEqual(cfg["CONN_MAX_AGE"], 0)
                    self.assertEqual(
                        cfg["OPTIONS"],
                        {"connect_timeout": 3, "read_timeout": 5, "write_timeout": 5, "charset": "utf8mb4"},
                    )

            fallback_cases = (
                ("empty_env_without_db_name", {}, root / "db.sqlite3", False),
                (
                    "credentials_without_db_name",
                    {"TOOLSDB_USER": "s50001", "TOOLSDB_PASSWORD": "secret"},
                    root / "db.sqlite3",
                    False,
                ),
                ("db_name_without_credentials", {"TOOLSDB_NAME": "s50001__cache"}, root / "db.sqlite3", False),
                ("test_run_uses_memory_sqlite", {"TOOLSDB_NAME": "s52222__cache"}, ":memory:", True),
            )
            empty_home = root / "empty_home"
            empty_home.mkdir()
            for label, env_map, expected_name, is_test in fallback_cases:
                with self.subTest(fallback=label):
                    cfg = build_databases_config(
                        env=env_map,
                        base_dir=root,
                        is_test_run=is_test,
                        home_dir=empty_home,
                    )["default"]
                    self.assertEqual(cfg["ENGINE"], "django.db.backends.sqlite3")
                    self.assertEqual(cfg["NAME"], expected_name)
                    self.assertEqual(cfg["CONN_MAX_AGE"], 0)

    def test_provider_registry_and_cache_settings_baseline(self) -> None:
        self.assertTrue(ENABLE_L2_TOOLSDB_CACHE)
        self.assertEqual(CACHE_SWR_STALE_DAYS, 90)
        self.assertEqual(CACHE_SWR_STALE_SECONDS, 7_776_000)
        self.assertEqual(PROVIDER_L2_MAX_RETENTION_DAYS, {"ip2location": 30})
        self.assertEqual(DEFAULT_PROVIDER_L2_MAX_RETENTION_DAYS, {"ip2location": 30})
        self.assertEqual(
            OFFLINE_REHYDRATE_PROVIDERS,
            frozenset({"maxmind", "stopforumspam", "ipsum_drop", "x4bnet_vpn"}),
        )
        self.assertEqual(L1_ONLY_PROVIDERS, frozenset({"iphub", "spamhaus_zen", "spamcop"}))

        for secret_name in ("REDIS_KEY_SECRET", "TOOLSDB_PASSWORD", "TOOL_TOOLSDB_PASSWORD"):
            self.assertIn(secret_name, EXTRA_SECRET_SETTING_NAMES)

        expected_new = (
            ("ipsum_drop", "IPsum / DROP", False, False, True, True, False, 0),
            ("x4bnet_vpn", "X4BNet VPN", False, False, True, True, False, 0),
            ("shodan_internetdb", "Shodan InternetDB", True, True, False, False, True, 120),
        )
        for key, label, uses_http, cooldown, light_mode, is_offline, has_quota, rpm in expected_new:
            with self.subTest(provider=key):
                meta = PROVIDER_BY_KEY[key]
                self.assertIs(PROVIDER_BY_LABEL[label], meta)
                self.assertEqual(meta.uses_http, uses_http)
                self.assertEqual(meta.supports_cooldown, cooldown)
                self.assertEqual(meta.active_in_light_mode, light_mode)
                self.assertEqual(meta.is_offline, is_offline)
                self.assertEqual(meta.has_quota_env_vars, has_quota)
                self.assertEqual(meta.default_rpm_limit, rpm)
                self.assertFalse(meta.is_commercial_arbitration)


class RedisIsolationAndSingleflightLockTests(TestCase):
    """Tests HMAC Redis key isolation, L1 snapshot persistence, and distributed singleflight locks."""

    def test_redis_namespace_isolation_and_ip_hmac_hashing(self) -> None:
        prod_ns = build_redis_namespace("proxycheck_prod_", "prod-secret-alpha")
        dev_ns = build_redis_namespace("proxycheck_dev_", "prod-secret-alpha")
        other_secret_ns = build_redis_namespace("proxycheck_prod_", "prod-secret-beta")

        self.assertTrue(prod_ns.endswith(":v2"))
        self.assertNotEqual(prod_ns, dev_ns)
        self.assertNotEqual(prod_ns, other_secret_ns)
        self.assertNotIn("prod-secret-alpha", prod_ns)

        sample_ips = ("203.0.113.42", "2001:db8:85a3::8a2e:370:7334")
        with override_settings(REDIS_KEY_PREFIX="proxycheck_prod_", REDIS_KEY_SECRET=" dedicated-hmac-key-01 "):
            expected_secret = "dedicated-hmac-key-01"
            for ip in sample_ips:
                with self.subTest(ip=ip):
                    expected_digest = hmac.new(
                        expected_secret.encode("utf-8"),
                        ip.encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest()[:24]
                    self.assertEqual(hash_ip_for_redis(ip, expected_secret), expected_digest)
                    self.assertEqual(len(expected_digest), 24)

                    generated_keys = (
                        cache_backends.provider_cache_key("abuseipdb", ip),
                        cache_backends.snapshot_cache_key(ip, mode="full"),
                        cache_backends.snapshot_cache_key(ip, mode="light"),
                        cache_backends.updating_lock_key(ip),
                        cache_backends.refresh_cooldown_key(ip),
                        cache_backends.swr_backoff_key(ip),
                    )
                    for key_str in generated_keys:
                        self.assertNotIn(ip, key_str)
                        self.assertNotIn("proxycheck:v1", key_str)
                        self.assertTrue(key_str.endswith(expected_digest))

        with override_settings(
            REDIS_KEY_PREFIX="proxycheck_dev_",
            REDIS_KEY_SECRET="",
            SECRET_KEY="fallback-django-secret-key",
        ):
            fallback_digest = cache_backends.get_redis_ip_digest("198.51.100.9")
            self.assertEqual(fallback_digest, hash_ip_for_redis("198.51.100.9", "fallback-django-secret-key"))

    @override_settings(
        REDIS_KEY_PREFIX="proxycheck_test_",
        REDIS_KEY_SECRET="snapshot-hmac-secret",
        ABUSEIPDB_API_KEY="leak-secret-val",
    )
    async def test_l1_snapshot_preserves_historical_fetched_at_and_batches_mget(self) -> None:
        fake_redis = _BatchingFakeRedis()
        historical_iso = "2026-07-15T09:12:30.104500+00:00"
        snap_one = _make_snapshot(
            "203.0.113.10",
            fetched_at=historical_iso,
            rows=[_make_provider_row("AbuseIPDB", raw_json={"echo": "key=leak-secret-val"})],
        )
        snap_two = _make_snapshot("2001:db8::20", fetched_at="2026-08-01T00:00:00+00:00")

        with patch("detector.cache_backends.redis_client", fake_redis):
            await cache_backends.set_cached_ip_snapshot("203.0.113.10", snap_one, mode="full", ttl_seconds=86400)
            await cache_backends.set_cached_ip_snapshot("2001:db8::20", snap_two, mode="full", ttl_seconds=86400)

            self.assertIsNone(await cache_backends.get_cached_ip_snapshot("203.0.113.10", mode="light"))
            loaded_one = await cache_backends.get_cached_ip_snapshot("203.0.113.10", mode="full")
            self.assertIsNotNone(loaded_one)
            assert loaded_one is not None
            self.assertEqual(loaded_one["fetchedAt"], historical_iso)
            self.assertNotIn("leak-secret-val", str(loaded_one["results"][0]["rawJson"]))

            bulk = await cache_backends.get_cached_ip_snapshots_bulk(
                ["203.0.113.10", "2001:db8::20", "198.51.100.99", "203.0.113.10"],
                mode="full",
            )
            self.assertEqual(set(bulk.keys()), {"203.0.113.10", "2001:db8::20"})
            self.assertEqual(bulk["203.0.113.10"]["fetchedAt"], historical_iso)
            self.assertEqual(len(fake_redis.mget_calls), 1)
            self.assertEqual(len(fake_redis.mget_calls[0]), 3)

            self.assertFalse(await cache_backends.is_refresh_on_cooldown("203.0.113.10"))
            await cache_backends.set_refresh_cooldown("203.0.113.10", ttl_seconds=60)
            self.assertTrue(await cache_backends.is_refresh_on_cooldown("203.0.113.10"))

            self.assertFalse(await cache_backends.is_swr_backed_off("203.0.113.10"))
            await cache_backends.set_swr_backoff("203.0.113.10", ttl_seconds=1800)
            self.assertTrue(await cache_backends.is_swr_backed_off("203.0.113.10"))

    @override_settings(REDIS_KEY_PREFIX="proxycheck_test_", REDIS_KEY_SECRET="lock-hmac-secret")
    async def test_singleflight_lock_lua_token_verification_and_simple_double_fallback(self) -> None:
        atomic_redis = _AtomicLockFakeRedis()
        target_ip = "203.0.113.77"

        with patch("detector.cache_backends.redis_client", atomic_redis):
            self.assertFalse(await cache_backends.is_ip_updating_locked(target_ip))
            token = await cache_backends.acquire_ip_updating_lock(target_ip, ttl_seconds=25)
            self.assertIsNotNone(token)
            assert token is not None
            self.assertTrue(await cache_backends.is_ip_updating_locked(target_ip))
            self.assertIsNone(await cache_backends.acquire_ip_updating_lock(target_ip, ttl_seconds=25))

            self.assertFalse(await cache_backends.release_ip_updating_lock(target_ip, "wrong-owner-token"))
            self.assertTrue(await cache_backends.is_ip_updating_locked(target_ip))

            self.assertTrue(await cache_backends.release_ip_updating_lock(target_ip, token))
            self.assertFalse(await cache_backends.is_ip_updating_locked(target_ip))
            self.assertEqual(len(atomic_redis.eval_calls), 2)

        simple_redis = FakeAsyncRedis()
        with patch("detector.cache_backends.redis_client", simple_redis):
            simple_token = await cache_backends.acquire_ip_updating_lock(target_ip, ttl_seconds=20)
            self.assertIsNotNone(simple_token)
            assert simple_token is not None
            self.assertIsNone(await cache_backends.acquire_ip_updating_lock(target_ip, ttl_seconds=20))
            self.assertFalse(await cache_backends.release_ip_updating_lock(target_ip, "forged-token"))
            self.assertTrue(await cache_backends.release_ip_updating_lock(target_ip, simple_token))
            self.assertFalse(await cache_backends.is_ip_updating_locked(target_ip))

        broken_redis = MagicMock()
        broken_redis.set = MagicMock(side_effect=ConnectionError("redis unreachable"))
        broken_redis.eval = MagicMock(side_effect=ConnectionError("redis unreachable"))
        with patch("detector.cache_backends.redis_client", broken_redis):
            self.assertIsNone(await cache_backends.acquire_ip_updating_lock(target_ip))
            self.assertFalse(await cache_backends.release_ip_updating_lock(target_ip, "any-token"))


class ToolsDbL2CacheRepositoryTests(TestCase):
    """Tests BINARY(16) CRUD, compliance stripping, retention expiry, non-degrading merge, and fail-open."""

    def tearDown(self) -> None:
        l2_cache.clear_l2_db_semaphores()

    def test_binary16_ip_packing_and_bulk_where_in_queries(self) -> None:
        ip_cases = (
            ("203.0.113.1", 4, "203.0.113.1"),
            ("8.8.8.8", 4, "8.8.8.8"),
            ("2001:0db8:0000:0000:0000:0000:0000:0001", 6, "2001:db8::1"),
            ("2606:4700:4700::1111", 6, "2606:4700:4700::1111"),
        )
        t0 = datetime(2026, 9, 10, 14, 25, 30, 123456, tzinfo=timezone.utc)

        for raw_ip, expected_ver, expected_canon in ip_cases:
            with self.subTest(ip=raw_ip):
                packed, ver, canon = l2_cache.pack_ip_binary(raw_ip)
                self.assertEqual(len(packed), 16)
                self.assertEqual(ver, expected_ver)
                self.assertEqual(canon, expected_canon)
                self.assertEqual(l2_cache.unpack_ip_binary(packed), expected_canon)

                res = l2_cache.merge_and_upsert_l2_snapshot(raw_ip, _make_snapshot(canon), now_dt=t0)
                self.assertTrue(res.saved)
                self.assertFalse(res.degraded_fallback)
                self.assertEqual(res.fetched_at, t0.isoformat())

        row_v4 = IpIntelligenceCache.objects.get(canonical_ip="203.0.113.1")
        self.assertEqual(len(bytes(row_v4.ip_bin)), 16)
        self.assertEqual(row_v4.ip_version, 4)

        single = l2_cache.get_ip_snapshot("2001:db8::1", now_dt=t0 + timedelta(days=5))
        self.assertIsNotNone(single)
        assert single is not None
        self.assertEqual(single["fetchedAt"], t0.isoformat())
        self.assertEqual(single["ptrHostname"], "host.example.net")

        with self.assertNumQueries(1):
            bulk = l2_cache.get_ip_snapshots_bulk(
                ["203.0.113.1", "2001:db8::1", "198.51.100.250", "8.8.8.8"],
                now_dt=t0 + timedelta(days=5),
            )
        self.assertEqual(set(bulk.keys()), {"203.0.113.1", "2001:db8::1", "8.8.8.8"})
        self.assertEqual(bulk["8.8.8.8"]["fetchedAt"], t0.isoformat())

        light_ip = "203.0.113.19"
        light_rows = [_make_provider_row("Cloudflare Radar"), _make_provider_row("Tor Onionoo")]
        l2_cache.merge_and_upsert_l2_snapshot(
            light_ip,
            _make_snapshot(light_ip, rows=light_rows, query_mode="light"),
            query_mode="light",
            now_dt=t0,
        )
        self.assertIsNotNone(l2_cache.get_ip_snapshot(light_ip, mode="light", now_dt=t0))
        self.assertIsNone(l2_cache.get_ip_snapshot(light_ip, mode="full", now_dt=t0))

        thirty_ips = [f"198.51.100.{idx}" for idx in range(1, 31)]
        for ip_addr in thirty_ips:
            l2_cache.merge_and_upsert_l2_snapshot(ip_addr, _make_snapshot(ip_addr), now_dt=t0)
        capped_bulk = l2_cache.get_ip_snapshots_bulk(thirty_ips, now_dt=t0)
        self.assertEqual(len(capped_bulk), 25)

    def test_four_tier_compliance_sanitisation_before_l2_write(self) -> None:
        mixed_rows = [
            _make_provider_row("AbuseIPDB", raw_json={"secret": "strip-me"}),
            _make_provider_row(
                "Shodan InternetDB",
                extra={
                    "openProxyPorts": [1080, 3128],
                    "tags": ["proxy", "compromised", "CVE-2024-9999"],
                    "hostnames": ["proxy-node.example"],
                    "latencyMs": 38,
                    "vulns": ["CVE-2024-9999", "CVE-2023-1111"],
                    "cpes": ["cpe:2.3:a:squid:squid:5.0"],
                    "ports": [22, 80, 1080, 3128, 3306],
                },
            ),
            _make_provider_row(
                "Tor Onionoo",
                extra={"isTor": True, "torIsExit": True, "torSummary": "Exit relay"},
            ),
            _make_provider_row("IP2Location"),
            _make_provider_row("MaxMind"),
            _make_provider_row("StopForumSpam"),
            _make_provider_row("IPsum / DROP"),
            _make_provider_row("X4BNet VPN"),
            _make_provider_row("IPHub"),
            _make_provider_row("Spamhaus ZEN"),
            _make_provider_row("SpamCop"),
        ]
        now_dt = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
        snap = _make_snapshot("198.51.100.12", rows=mixed_rows)
        snap["username"] = "ForbiddenUserField"
        snap["temporaryAccount"] = "~2026-99999"

        outcome = l2_cache.merge_and_upsert_l2_snapshot("198.51.100.12", snap, now_dt=now_dt)
        self.assertTrue(outcome.saved)

        db_row = IpIntelligenceCache.objects.get(canonical_ip="198.51.100.12")
        raw_decompressed = l2_cache.decompress_l2_payload(db_row.payload_compressed)
        self.assertIsNotNone(raw_decompressed)
        assert raw_decompressed is not None
        self.assertNotIn("username", raw_decompressed)
        self.assertNotIn("temporaryAccount", raw_decompressed)

        by_label = {item["provider"]: item for item in raw_decompressed["results"]}
        self.assertEqual(
            set(by_label.keys()),
            {"AbuseIPDB", "Shodan InternetDB", "Tor Onionoo", "IP2Location"},
        )
        for persisted_row in by_label.values():
            self.assertNotIn("rawJson", persisted_row)

        shodan_row = by_label["Shodan InternetDB"]
        self.assertNotIn("vulns", shodan_row)
        self.assertNotIn("cpes", shodan_row)
        self.assertNotIn("ports", shodan_row)
        self.assertEqual(shodan_row["openProxyPorts"], [1080, 3128])
        self.assertEqual(shodan_row["tags"], ["proxy", "compromised"])
        self.assertEqual(shodan_row["hostnames"], ["proxy-node.example"])
        self.assertEqual(shodan_row["latencyMs"], 38)

        tor_row = by_label["Tor Onionoo"]
        self.assertTrue(tor_row["isTor"])
        self.assertTrue(tor_row["torIsExit"])

        for stripped_key in (*OFFLINE_REHYDRATE_PROVIDERS, *L1_ONLY_PROVIDERS):
            self.assertNotIn(stripped_key, db_row.provider_fetched_map)

    def test_thirty_day_ip2location_read_filtering_and_purge_command(self) -> None:
        base_dt = datetime(2026, 8, 1, 8, 0, tzinfo=timezone.utc)
        rows = [
            _make_provider_row("AbuseIPDB"),
            _make_provider_row("IPData"),
            _make_provider_row("IP2Location"),
            _make_provider_row("Cloudflare Radar"),
        ]
        l2_cache.merge_and_upsert_l2_snapshot("203.0.113.50", _make_snapshot("203.0.113.50", rows=rows), now_dt=base_dt)
        l2_cache.merge_and_upsert_l2_snapshot("203.0.113.51", _make_snapshot("203.0.113.51", rows=rows), now_dt=base_dt)
        fresh_dt = base_dt + timedelta(days=20)
        l2_cache.merge_and_upsert_l2_snapshot(
            "203.0.113.52", _make_snapshot("203.0.113.52", rows=rows), now_dt=fresh_dt
        )

        within_30d = l2_cache.get_ip_snapshot("203.0.113.50", now_dt=base_dt + timedelta(days=29))
        assert within_30d is not None
        self.assertIn("IP2Location", {r["provider"] for r in within_30d["results"]})

        past_30d_now = base_dt + timedelta(days=31)
        expired_read = l2_cache.get_ip_snapshot("203.0.113.50", now_dt=past_30d_now)
        assert expired_read is not None
        self.assertNotIn("IP2Location", {r["provider"] for r in expired_read["results"]})
        self.assertNotIn("ip2location", expired_read["providerFetchedMap"])
        self.assertEqual(expired_read["fetchedAt"], base_dt.isoformat())
        self.assertEqual(expired_read["validCommercialCount"], 2)

        bulk_after_30d = l2_cache.get_ip_snapshots_bulk(["203.0.113.50", "203.0.113.52"], now_dt=past_30d_now)
        self.assertNotIn("IP2Location", {r["provider"] for r in bulk_after_30d["203.0.113.50"]["results"]})
        self.assertIn("IP2Location", {r["provider"] for r in bulk_after_30d["203.0.113.52"]["results"]})

        dry_out = io.StringIO()
        with patch(
            "detector.l2_cache._ensure_utc",
            side_effect=lambda dt=None: past_30d_now if dt is None else dt.astimezone(timezone.utc),
        ):
            call_command("purge_l2_cache", batch_size=1, dry_run=True, stdout=dry_out)
        self.assertIn("2 rows require cleanup", dry_out.getvalue())
        self.assertIn("ip2location", IpIntelligenceCache.objects.get(canonical_ip="203.0.113.50").provider_fetched_map)

        live_out = io.StringIO()
        with patch(
            "detector.l2_cache._ensure_utc",
            side_effect=lambda dt=None: past_30d_now if dt is None else dt.astimezone(timezone.utc),
        ):
            call_command("purge_l2_cache", batch_size=1, stdout=live_out)
        self.assertIn("Purged 2 expired provider entries across 2 rows", live_out.getvalue())

        purged_row = IpIntelligenceCache.objects.get(canonical_ip="203.0.113.50")
        self.assertNotIn("ip2location", purged_row.provider_fetched_map)
        self.assertEqual(purged_row.fetched_at, base_dt)
        self.assertEqual(purged_row.valid_commercial_count, 2)
        purged_payload = l2_cache.decompress_l2_payload(purged_row.payload_compressed)
        assert purged_payload is not None
        self.assertNotIn("IP2Location", {r["provider"] for r in purged_payload["results"]})

        kept_row = IpIntelligenceCache.objects.get(canonical_ip="203.0.113.52")
        self.assertIn("ip2location", kept_row.provider_fetched_map)

        recent_refresh_dt = base_dt + timedelta(days=28)
        l2_cache.merge_and_upsert_l2_snapshot(
            "203.0.113.53",
            _make_snapshot(
                "203.0.113.53",
                rows=rows,
                provider_fetched_map={"ip2location": int(base_dt.timestamp())},
            ),
            now_dt=recent_refresh_dt,
        )
        with patch(
            "detector.l2_cache._ensure_utc",
            side_effect=lambda dt=None: past_30d_now if dt is None else dt.astimezone(timezone.utc),
        ):
            call_command("purge_l2_cache", batch_size=2, stdout=io.StringIO())
        self.assertNotIn(
            "ip2location", IpIntelligenceCache.objects.get(canonical_ip="203.0.113.53").provider_fetched_map
        )

        with self.assertRaises(CommandError):
            call_command("purge_l2_cache", batch_size=0, stdout=io.StringIO())

    def test_non_degrading_merge_retains_historical_rows_and_blocks_severe_degradation(self) -> None:
        t_initial = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)
        initial_rows = [
            _make_provider_row("AbuseIPDB", extra={"abuseScore": 10}),
            _make_provider_row("IPData"),
            _make_provider_row("Proxycheck"),
            _make_provider_row("IPRegistry"),
        ]
        target_ip = "203.0.113.88"
        first = l2_cache.merge_and_upsert_l2_snapshot(
            target_ip, _make_snapshot(target_ip, rows=initial_rows), now_dt=t_initial
        )
        self.assertTrue(first.saved)
        self.assertEqual(first.valid_commercial_count, 4)

        t_partial = t_initial + timedelta(days=10)
        partial_rows = [
            _make_provider_row("AbuseIPDB", extra={"abuseScore": 85}),
            _make_provider_row("IPData"),
            _make_provider_row(
                "Proxycheck",
                status="Local Quota Guard (1000/1000 req/day)",
                status_code=429,
                extra={"isQuotaGuard": True},
            ),
            _make_provider_row("IPRegistry", status="504 Gateway Timeout", status_code=504),
        ]
        merged = l2_cache.merge_and_upsert_l2_snapshot(
            target_ip, _make_snapshot(target_ip, rows=partial_rows), now_dt=t_partial
        )
        self.assertTrue(merged.saved)
        self.assertFalse(merged.degraded_fallback)
        self.assertTrue(merged.has_degraded_sources)
        self.assertEqual(set(merged.retained_historical_providers), {"proxycheck", "ipregistry"})
        self.assertEqual(merged.fetched_at, t_partial.isoformat())

        reloaded = l2_cache.get_ip_snapshot(target_ip, now_dt=t_partial)
        assert reloaded is not None
        rows_by_name = {r["provider"]: r for r in reloaded["results"]}
        self.assertEqual(rows_by_name["AbuseIPDB"]["abuseScore"], 85)
        self.assertNotIn("isHistoricalFallback", rows_by_name["AbuseIPDB"])
        self.assertTrue(rows_by_name["Proxycheck"]["isHistoricalFallback"])
        self.assertTrue(rows_by_name["IPRegistry"]["isHistoricalFallback"])
        self.assertEqual(reloaded["providerFetchedMap"]["abuseipdb"], int(t_partial.timestamp()))
        self.assertEqual(reloaded["providerFetchedMap"]["proxycheck"], int(t_initial.timestamp()))

        degraded_cases = (
            (
                "below_half_commercial_threshold",
                [
                    _make_provider_row("AbuseIPDB"),
                    _make_provider_row("IPData", status="504 Gateway Timeout", status_code=504),
                    _make_provider_row("Proxycheck", status="429 Rate Limited", status_code=429),
                    _make_provider_row("IPRegistry", status="503 Cooldown", status_code=503),
                ],
            ),
            (
                "zero_commercial_sources_succeeded",
                [
                    _make_provider_row("AbuseIPDB", status="504 Gateway Timeout", status_code=504),
                    _make_provider_row("IPData", status="429 Rate Limited", status_code=429),
                    _make_provider_row("Proxycheck", status="429 Rate Limited", status_code=429),
                    _make_provider_row("IPRegistry", status="503 Cooldown", status_code=503),
                ],
            ),
        )
        t_outage = t_partial + timedelta(days=2)
        for case_name, bad_rows in degraded_cases:
            with self.subTest(case=case_name):
                aborted = l2_cache.merge_and_upsert_l2_snapshot(
                    target_ip,
                    _make_snapshot(target_ip, rows=bad_rows),
                    now_dt=t_outage,
                )
                self.assertFalse(aborted.saved)
                self.assertTrue(aborted.degraded_fallback)
                self.assertTrue(aborted["degraded_fallback"])
                self.assertEqual(aborted.fetched_at, t_partial.isoformat())
                self.assertEqual(
                    IpIntelligenceCache.objects.get(canonical_ip=target_ip).fetched_at,
                    t_partial,
                )

    async def test_async_semaphore_limit_and_database_error_fail_open(self) -> None:
        t0 = datetime(2026, 10, 5, 9, 0, tzinfo=timezone.utc)
        await l2_cache.amerge_and_upsert_l2_snapshot("203.0.113.200", _make_snapshot("203.0.113.200"), now_dt=t0)
        loaded = await l2_cache.aget_ip_snapshot("203.0.113.200", now_dt=t0)
        self.assertIsNotNone(loaded)

        active = 0
        peak = 0

        async def _slow_sync_bridge(*_args: Any, **_kwargs: Any) -> Optional[Dict[str, Any]]:
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.02)
            active -= 1
            return loaded

        with patch("detector.l2_cache.sync_to_async", return_value=_slow_sync_bridge):
            await asyncio.gather(*(l2_cache.aget_ip_snapshot("203.0.113.200") for _ in range(8)))
        self.assertLessEqual(peak, l2_cache.L2_DB_CONCURRENCY_LIMIT)
        self.assertEqual(l2_cache.L2_DB_CONCURRENCY_LIMIT, 3)

        with override_settings(ENABLE_L2_TOOLSDB_CACHE=False):
            self.assertIsNone(l2_cache.get_ip_snapshot("203.0.113.200"))
            self.assertEqual(l2_cache.get_ip_snapshots_bulk(["203.0.113.200"]), {})
            self.assertFalse(l2_cache.merge_and_upsert_l2_snapshot("203.0.113.200", _make_snapshot()).saved)

        with patch.object(IpIntelligenceCache.objects, "filter", side_effect=OperationalError("MariaDB offline")):
            with patch("detector.l2_cache.close_old_connections") as close_spy:
                self.assertIsNone(l2_cache.get_ip_snapshot("203.0.113.200"))
                self.assertGreaterEqual(close_spy.call_count, 2)
            self.assertEqual(l2_cache.get_ip_snapshots_bulk(["203.0.113.200"]), {})
            failed_upsert = l2_cache.merge_and_upsert_l2_snapshot("203.0.113.200", _make_snapshot())
            self.assertFalse(failed_upsert.saved)
            self.assertFalse(failed_upsert.degraded_fallback)
            purge_res = l2_cache.purge_expired_provider_fields()
            self.assertTrue(purge_res["failed"])

        async_bulk = await l2_cache.aget_ip_snapshots_bulk(["203.0.113.200"], now_dt=t0)
        self.assertIn("203.0.113.200", async_bulk)

        with patch.object(
            l2_cache.settings,
            "DATABASES",
            {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": "s51234__bad_p"}},
        ):
            self.assertIsNone(l2_cache.get_ip_snapshot("203.0.113.200"))
            self.assertFalse(l2_cache.merge_and_upsert_l2_snapshot("203.0.113.200", _make_snapshot()).saved)


class CheckSetupToolsDbAndSecretValidationTests(SimpleTestCase):
    """Tests check_setup validation of _p database hazards, MariaDB grants, and REDIS_KEY_SECRET."""

    def test_public_schema_suffix_and_grant_auditing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            conn_spy = MagicMock()

            for public_name in ("s51234__proxycheck_p", "s51234__cache_P"):
                with self.subTest(public_name=public_name):
                    res = check_setup.check_toolsdb_status(
                        base,
                        {"TOOLSDB_NAME": public_name, "TOOLSDB_USER": "s51234", "TOOLSDB_PASSWORD": "secret"},
                        connection_factory=conn_spy,
                    )
                    self.assertEqual(res.status, "error")
                    self.assertTrue(res.is_public_name_hazard)
                    self.assertIn("_p", res.message)
            conn_spy.assert_not_called()

            grant_cases = (
                (
                    "safe_private_tool_grants",
                    [
                        ("GRANT USAGE ON *.* TO 's51234'@'%'",),
                        ("GRANT ALL PRIVILEGES ON `s51234__proxycheck_cache`.* TO 's51234'@'%'",),
                        ("GRANT ALL PRIVILEGES ON `s51234\\_\\%`.* TO 's51234'@'%'",),
                    ],
                    0,
                ),
                (
                    "wildcard_grantee_user",
                    [("GRANT SELECT ON `s51234__proxycheck_cache`.* TO '%'@'%'",)],
                    1,
                ),
                (
                    "anonymous_grantee_user",
                    [("GRANT SELECT ON `s51234__proxycheck_cache`.* TO ''@'%'",)],
                    1,
                ),
                (
                    "public_role_grant",
                    [("GRANT SELECT ON `s51234__proxycheck_cache`.* TO PUBLIC",)],
                    1,
                ),
                (
                    "cross_tenant_user_grant",
                    [("GRANT SELECT ON `s51234__proxycheck_cache`.* TO 's59999'@'%'",)],
                    1,
                ),
                (
                    "public_suffix_schema_in_grant",
                    [("GRANT SELECT ON `s51234__proxycheck_p`.* TO 's51234'@'%'",)],
                    1,
                ),
                (
                    "global_select_on_star",
                    [("GRANT SELECT ON *.* TO 's51234'@'%'",)],
                    1,
                ),
            )
            for label, rows, expected_unsafe_count in grant_cases:
                with self.subTest(grant_case=label):
                    flagged = check_setup.find_unsafe_grant_statements(
                        rows,
                        expected_user="s51234",
                        db_name="s51234__proxycheck_cache",
                    )
                    self.assertEqual(len(flagged), expected_unsafe_count)

    def test_toolsdb_live_probe_and_check_setup_strict_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            project_root = root / "proxycheck"
            project_root.mkdir()
            data_dir = root / "data"
            data_dir.mkdir()

            fake_cursor = MagicMock()
            fake_cursor.fetchone.return_value = (1,)
            fake_cursor.fetchall.return_value = [
                ("GRANT USAGE ON *.* TO 's51234'@'%'",),
                ("GRANT ALL PRIVILEGES ON `s51234__proxycheck_cache`.* TO 's51234'@'%'",),
            ]
            fake_conn = MagicMock()
            fake_conn.cursor.return_value.__enter__.return_value = fake_cursor

            ok_probe = check_setup.check_toolsdb_status(
                project_root,
                {
                    "TOOLSDB_NAME": "s51234__proxycheck_cache",
                    "TOOLSDB_USER": "s51234",
                    "TOOLSDB_PASSWORD": "db-password-1234",
                },
                connection_factory=lambda _cfg: fake_conn,
            )
            self.assertEqual(ok_probe.status, "ok")
            fake_conn.close.assert_called_once()

            err_probe = check_setup.check_toolsdb_status(
                project_root,
                {
                    "TOOLSDB_NAME": "s51234__proxycheck_cache",
                    "TOOLSDB_USER": "s51234",
                    "TOOLSDB_PASSWORD": "db-password-1234",
                },
                connection_factory=MagicMock(side_effect=OSError("connection timed out")),
            )
            self.assertEqual(err_probe.status, "error")
            self.assertIn("connection timed out", err_probe.message)

            secret_cases = (
                ({}, "warning"),
                ({"REDIS_KEY_SECRET": "changeme-placeholder-secret"}, "error"),
                ({"REDIS_KEY_SECRET": "a" * 48}, "ok"),
            )
            for env_map, expected_status in secret_cases:
                with self.subTest(secret_env=env_map):
                    status, _ = check_setup.check_redis_key_secret_status(env_map)
                    self.assertEqual(status, expected_status)

            (project_root / ".env").write_text(
                "DJANGO_SECRET_KEY='a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2'\n"
                "WIKIMEDIA_CLIENT_ID='client-id'\n"
                "WIKIMEDIA_CLIENT_SECRET='client-secret-value-1234'\n"
                "TOOLSDB_NAME='s51234__proxycheck_p'\n",
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with (
                override_settings(BASE_DIR=project_root),
                patch.dict("os.environ", {}, clear=True),
                patch("pathlib.Path.home", return_value=root / "home"),
            ):
                call_command("check_setup", no_input=True, env_mode="local", stdout=stdout, stderr=io.StringIO())
                self.assertIn("ends with '_p'", stdout.getvalue())
                with self.assertRaises(CommandError):
                    call_command(
                        "check_setup",
                        no_input=True,
                        env_mode="local",
                        strict=True,
                        stdout=io.StringIO(),
                        stderr=io.StringIO(),
                    )
