"""Tests for the memory-mapped binary prefix index, offline threat feeds, and CIDR attribution."""

from __future__ import annotations

import concurrent.futures
import contextlib
import gzip
import io
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Tuple
from unittest.mock import MagicMock, patch

import httpx
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase, override_settings

from detector import cidr_attribution, offline_dbs
from detector.adapters import adapt_tor_onionoo
from detector.binary_prefix_index import (
    BinaryPrefixFormatError,
    BinaryPrefixIndexReader,
    compile_binary_prefix_index,
    sync_file_to_ephemeral_cache,
)
from detector.cidr_attribution import (
    classify_rdns_hostname,
    clear_offline_intelligence_caches,
    compute_cidr_attribution,
)
from detector.management.commands import update_offline_dbs as update_cmd
from detector.offline_dbs import (
    build_stopforumspam_sqlite_index,
    is_mobile_asn_offline,
    lookup_bgp_tools_offline,
    lookup_privacy_relay_offline,
    lookup_tor_onionoo_offline,
    query_ipsum_drop_offline,
    query_stopforumspam_offline,
    query_x4bnet_vpn_offline,
    resolve_local_ephemeral_cache_dir,
    warm_stopforumspam_caches,
)


class _MockFeedResponse:
    """Lightweight HTTP response test double supporting status codes, headers, and gzipped bytes."""

    def __init__(
        self,
        body: str | bytes = "",
        *,
        status_code: int = 200,
        headers: Optional[Mapping[str, str]] = None,
    ) -> None:
        self.status_code = status_code
        self.headers = dict(headers or {})
        if isinstance(body, bytes):
            self.content = body
            self.text = ""
        else:
            self.text = body
            self.content = body.encode("utf-8")

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("HTTP error", request=MagicMock(), response=MagicMock())

    def json(self) -> Any:
        return json.loads(self.content.decode("utf-8"))


def _build_all_feeds_payloads() -> Dict[str, Tuple[str | bytes, Dict[str, str]]]:
    onionoo_doc = {
        "relays_published": "2026-11-18 04:00:00",
        "relays": [
            {
                "n": "ExitRelayOne",
                "a": ["198.51.100.77", "[2001:db8:cafe::77]"],
                "exit_addresses": ["198.51.100.77"],
                "r": True,
                "flags": ["Exit", "Fast", "Running", "Valid"],
            },
            {
                "n": "DormantGuard",
                "a": ["198.51.100.78"],
                "r": False,
                "flags": ["Guard"],
            },
        ],
    }
    onionoo_gzip = gzip.compress(json.dumps(onionoo_doc).encode("utf-8"))

    drop_v4_ndjson = "\n".join(
        [
            json.dumps({"cidr": "192.0.2.0/24", "sblid": "SBL100001", "rir": "arin"}),
            json.dumps({"type": "metadata", "timestamp": 1763424000}),
        ]
    )
    drop_v6_ndjson = "\n".join(
        [
            json.dumps({"cidr": "2001:db8:dead::/48", "sblid": "SBL600009", "rir": "ripencc"}),
            json.dumps({"type": "metadata", "timestamp": 1763424000}),
        ]
    )
    peeringdb_json = json.dumps(
        {
            "data": [
                {"asn": 21928, "name": "T-Mobile USA", "info_types": ["Mobile"]},
                {"asn": 7018, "name": "AT&T Mobility", "info_type": "Mobile", "info_types": []},
                {"asn": 15169, "name": "Google LLC", "info_types": ["Content"]},
            ]
        }
    )

    return {
        "mask-api.icloud.com/egress-ip-ranges.csv": (
            "# Apple Private Relay\n"
            "172.224.226.0/27,US,US-CA,San Francisco,\n"
            "2a02:26f7:b400::/48,GB,GB-LND,London,\n",
            {"ETag": '"apple-v1"', "Last-Modified": "Wed, 18 Nov 2026 01:00:00 GMT"},
        ),
        "api.cloudflare.com/local-ip-ranges.csv": (
            "104.28.16.0/20,US,US-NY,New York,\n"
            "172.64.0.0/16,US,US-CA,San Jose,\n"
            "173.245.48.128/25,US,US-CA,Los Angeles,\n"
            "2a09:bac0::/29,DE,DE-HE,Frankfurt,\n",
            {"ETag": '"cf-local-v1"', "Last-Modified": "Wed, 18 Nov 2026 01:00:00 GMT"},
        ),
        "cloudflare.com/ips-v4": (
            "173.245.48.0/20\n"
            "172.64.0.0/16\n"
            "104.28.20.0/24\n",
            {"ETag": '"cf-v4-v1"', "Last-Modified": "Wed, 18 Nov 2026 01:00:00 GMT"},
        ),
        "cloudflare.com/ips-v6": (
            "2606:4700::/32\n",
            {"ETag": '"cf-v6-v1"', "Last-Modified": "Wed, 18 Nov 2026 01:00:00 GMT"},
        ),
        "stamparm/ipsum": (
            "# ipsum feed\n"
            "198.51.100.10\t1\n"
            "198.51.100.11\t2\n"
            "198.51.100.12\t5\n"
            "192.0.2.55\t4\n",
            {"ETag": '"ipsum-v1"', "Last-Modified": "Wed, 18 Nov 2026 02:00:00 GMT"},
        ),
        "spamhaus.org/drop/drop_v4.json": (
            drop_v4_ndjson,
            {"ETag": '"drop4-v1"', "Last-Modified": "Wed, 18 Nov 2026 02:00:00 GMT"},
        ),
        "spamhaus.org/drop/drop_v6.json": (
            drop_v6_ndjson,
            {"ETag": '"drop6-v1"', "Last-Modified": "Wed, 18 Nov 2026 02:00:00 GMT"},
        ),
        "onionoo.torproject.org/summary": (
            onionoo_gzip,
            {"ETag": '"tor-v1"', "Last-Modified": "Wed, 18 Nov 2026 03:00:00 GMT"},
        ),
        "bgp.tools/table.txt": (
            "203.0.113.0/24 64501\n"
            "203.0.113.128/25 64502\n"
            "2001:db8:1234::/48 64503\n"
            "2001:db8:abcd::/32 64504\n"
            "198.51.100.0/24 64555\n",
            {"ETag": '"bgp-table-v1"', "Last-Modified": "Wed, 18 Nov 2026 03:00:00 GMT"},
        ),
        "bgp.tools/tags.txt": (
            "mobile,2\nvpn,1\n",
            {"ETag": '"bgp-tags-v1"', "Last-Modified": "Wed, 18 Nov 2026 03:00:00 GMT"},
        ),
        "bgp.tools/tags/mobile.csv": (
            "AS64555,Example Cellular Operator\n",
            {"ETag": '"bgp-mob-v1"', "Last-Modified": "Wed, 18 Nov 2026 03:00:00 GMT"},
        ),
        "bgp.tools/tags/vpn.csv": (
            "AS64502,Example VPN Network\n",
            {"ETag": '"bgp-vpn-v1"', "Last-Modified": "Wed, 18 Nov 2026 03:00:00 GMT"},
        ),
        "X4BNet/lists_vpn/main/output/vpn/ipv4.txt": (
            "185.159.157.0/24\n",
            {"ETag": '"x4b-vpn4-v1"'},
        ),
        "X4BNet/lists_vpn/main/output/vpn/ipv6.txt": (
            "2a0d:5600:10::/48\n",
            {"ETag": '"x4b-vpn6-v1"'},
        ),
        "X4BNet/lists_vpn/main/output/datacenter/ipv4.txt": (
            "185.159.157.0/24\n198.51.100.192/26\n",
            {"ETag": '"x4b-dc4-v1"'},
        ),
        "X4BNet/lists_vpn/main/output/datacenter/ipv6.txt": (
            "2a01:4f8:c010::/48\n",
            {"ETag": '"x4b-dc6-v1"'},
        ),
        "ipapi-is/ip_to_hosting": (
            "startIp,endIp,datacenter\n203.0.113.64,203.0.113.95,ExampleHost\n",
            {"ETag": '"ipapi-v1"'},
        ),
        "peeringdb.com/api/net": (
            peeringdb_json,
            {"ETag": '"pdb-v1"', "Last-Modified": "Wed, 18 Nov 2026 03:30:00 GMT"},
        ),
    }


def _make_conditional_client_cm(
    routes: Mapping[str, Tuple[str | bytes, Dict[str, str]]],
    seen_requests: List[Tuple[str, Dict[str, str]]],
):
    def _get(url: str, **kwargs: Any) -> _MockFeedResponse:
        req_headers = {str(k): str(v) for k, v in (kwargs.get("headers") or {}).items()}
        seen_requests.append((url, req_headers))
        for fragment, (payload, resp_headers) in routes.items():
            if fragment in url:
                etag = resp_headers.get("ETag")
                last_mod = resp_headers.get("Last-Modified")
                if etag and req_headers.get("If-None-Match") == etag:
                    return _MockFeedResponse(b"", status_code=304, headers=resp_headers)
                if last_mod and req_headers.get("If-Modified-Since") == last_mod:
                    return _MockFeedResponse(b"", status_code=304, headers=resp_headers)
                return _MockFeedResponse(payload, status_code=200, headers=resp_headers)
        return _MockFeedResponse("not found", status_code=404)

    fake_client = MagicMock()
    fake_client.get.side_effect = _get
    cm = MagicMock()
    cm.__enter__.return_value = fake_client
    cm.__exit__.return_value = False
    return cm


@contextlib.contextmanager
def _isolated_offline_dirs() -> Iterator[Tuple[Path, Path, Path]]:
    """Provides temporary tool data and ephemeral cache directories, closing handles before cleanup."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        tool_root = root / "tool"
        data_dir = tool_root / "data"
        ephemeral_dir = root / "ephemeral"
        data_dir.mkdir(parents=True)
        try:
            yield tool_root, data_dir, ephemeral_dir
        finally:
            clear_offline_intelligence_caches()


class BinaryPrefixIndexTests(SimpleTestCase):
    """Tests compilation, longest prefix matching, memory mapping, and corrupt header guards."""

    def setUp(self) -> None:
        clear_offline_intelligence_caches()
        self.addCleanup(clear_offline_intelligence_caches)

    def test_ipv4_and_ipv6_longest_prefix_matching_and_payload_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            bin_path = Path(tmp_dir) / "prefixes.bin"
            ephemeral_dir = Path(tmp_dir) / "ephemeral"
            entries = [
                ("10.0.0.0/8", "broad_v4"),
                ("10.20.0.0/16", 64500),
                ("10.20.30.0/24", {"asn": 64501, "tags": ["vpn"]}),
                ("10.20.30.99/32", "host_override"),
                ("255.255.255.0/24", "upper_edge_v4"),
                ("2001:db8::/32", "broad_v6"),
                ("2001:db8:1234::/48", "mid_v6"),
                ("2001:db8:1234:5678::/64", {"asn": 64502}),
                ("ffff:ffff:ffff:ffff::/64", "upper_edge_v6"),
            ]
            count = compile_binary_prefix_index(entries, bin_path)
            self.assertEqual(count, len(entries))

            with BinaryPrefixIndexReader.open_from_source(bin_path, ephemeral_dir) as reader:
                cases = (
                    ("10.1.2.3", ("10.0.0.0/8", "broad_v4")),
                    ("10.20.1.5", ("10.20.0.0/16", 64500)),
                    ("10.20.30.5", ("10.20.30.0/24", {"asn": 64501, "tags": ["vpn"]})),
                    ("10.20.30.99", ("10.20.30.99/32", "host_override")),
                    ("10.20.30.100", ("10.20.30.0/24", {"asn": 64501, "tags": ["vpn"]})),
                    ("10.20.31.1", ("10.20.0.0/16", 64500)),
                    ("255.255.255.255", ("255.255.255.0/24", "upper_edge_v4")),
                    ("::ffff:10.20.30.99", ("10.20.30.99/32", "host_override")),
                    ("2001:db8:9999::1", ("2001:db8::/32", "broad_v6")),
                    ("2001:db8:1234:abcd::1", ("2001:db8:1234::/48", "mid_v6")),
                    ("2001:db8:1234:5678::9", ("2001:db8:1234:5678::/64", {"asn": 64502})),
                    ("ffff:ffff:ffff:ffff::1", ("ffff:ffff:ffff:ffff::/64", "upper_edge_v6")),
                    ("11.0.0.1", None),
                    ("0.0.0.0", None),
                    ("2606:4700::1", None),
                    ("not-an-ip", None),
                    ("", None),
                )
                for ip_str, expected in cases:
                    with self.subTest(ip=ip_str):
                        self.assertEqual(reader.lookup(ip_str), expected)

                first_json_hit = reader.lookup("10.20.30.5")
                assert first_json_hit is not None
                first_json_hit[1]["tags"].append("mutated")
                second_json_hit = reader.lookup("10.20.30.5")
                assert second_json_hit is not None
                self.assertEqual(second_json_hit[1], {"asn": 64501, "tags": ["vpn"]})

    def test_large_table_lookup_latency_and_ephemeral_platform_defaults(self) -> None:
        with patch.object(offline_dbs.os, "name", "posix"):
            posix_dir = resolve_local_ephemeral_cache_dir(env_overrides={"LOCAL_EPHEMERAL_CACHE_DIR": ""})
            self.assertEqual(posix_dir.as_posix(), "/tmp/proxycheck-local")  # noqa: S108

        with patch.object(offline_dbs.os, "name", "nt"):
            win_dir = resolve_local_ephemeral_cache_dir(env_overrides={"LOCAL_EPHEMERAL_CACHE_DIR": ""})
            self.assertEqual(win_dir, Path(tempfile.gettempdir()) / "proxycheck-local")

        with tempfile.TemporaryDirectory() as tmp_dir:
            bin_path = Path(tmp_dir) / "large.bin"
            entries = [(f"100.{(idx >> 8) & 255}.{idx & 255}.0/24", idx % 500) for idx in range(25000)]
            entries.extend((f"2001:db8:{idx:x}::/48", idx % 500) for idx in range(5000))
            compile_binary_prefix_index(entries, bin_path)

            with BinaryPrefixIndexReader(bin_path) as reader:
                reader.lookup("100.40.12.9")
                t0 = time.perf_counter()
                for _ in range(500):
                    hit_v4 = reader.lookup("100.40.12.9")
                    hit_v6 = reader.lookup("2001:db8:12a::1")
                elapsed_ms_per_lookup = ((time.perf_counter() - t0) * 1000.0) / 1000.0
                self.assertIsNotNone(hit_v4)
                self.assertIsNotNone(hit_v6)
                self.assertLess(elapsed_ms_per_lookup, 0.1)

    def test_corrupt_or_empty_binary_index_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            empty_idx = root / "empty_valid.bin"
            self.assertEqual(compile_binary_prefix_index((), empty_idx), 0)
            with BinaryPrefixIndexReader(empty_idx) as empty_reader:
                self.assertIsNone(empty_reader.lookup("8.8.8.8"))
                self.assertIsNone(empty_reader.lookup("2001:db8::1"))

            bad_magic = root / "bad_magic.bin"
            bad_magic.write_bytes(b"NOTVALID" + b"\x00" * 120)
            with self.assertRaises(BinaryPrefixFormatError):
                BinaryPrefixIndexReader(bad_magic)

            truncated = root / "truncated.bin"
            truncated.write_bytes(b"PCBI")
            with self.assertRaises(BinaryPrefixFormatError):
                BinaryPrefixIndexReader(truncated)


class NfsStatThrottleAndLocalSqliteTests(SimpleTestCase):
    """Tests 30-second monotonic stat caching, local SQLite copying, and Web rebuild prevention."""

    def setUp(self) -> None:
        clear_offline_intelligence_caches()
        self.addCleanup(clear_offline_intelligence_caches)

    def test_stat_checks_are_throttled_for_thirty_seconds_and_reset_on_clear(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample = Path(tmp_dir) / "sample.dat"
            sample.write_bytes(b"initial")
            clock = [500.0]
            real_stat = os.stat
            stat_calls = 0

            def _counting_stat(target: Any, *args: Any, **kwargs: Any):
                nonlocal stat_calls
                if os.fspath(target) == os.fspath(sample):
                    stat_calls += 1
                return real_stat(target, *args, **kwargs)

            with (
                patch("detector.offline_dbs.time.monotonic", side_effect=lambda: clock[0]),
                patch("detector.offline_dbs.os.stat", side_effect=_counting_stat),
            ):
                first_sig = offline_dbs.get_file_stat_signature(sample)
                clock[0] += 10.0
                second_sig = offline_dbs.get_file_stat_signature(sample)
                clock[0] += 19.5
                third_sig = offline_dbs.get_file_stat_signature(sample)
                self.assertEqual(first_sig, second_sig)
                self.assertEqual(second_sig, third_sig)
                self.assertEqual(stat_calls, 1)

                clock[0] += 1.0
                offline_dbs.get_file_stat_signature(sample)
                self.assertEqual(stat_calls, 2)

                clear_offline_intelligence_caches()
                offline_dbs.get_file_stat_signature(sample)
                self.assertEqual(stat_calls, 3)

    def test_sfs_copies_sqlite_to_ephemeral_reuses_thread_conn_and_forbids_web_rebuild(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tool_root = Path(tmp_dir) / "tool"
            data_dir = tool_root / "data"
            ephemeral_dir = Path(tmp_dir) / "local_ephemeral"
            data_dir.mkdir(parents=True)

            raw_listed = data_dir / "listed_ip_90_ipv46_all.txt"
            raw_listed.write_text('"198.51.100.21","11","2026-11-17 09:00:00"\n', encoding="utf-8")

            with override_settings(
                TOOL_DATA_DIR=str(tool_root),
                LOCAL_EPHEMERAL_CACHE_DIR=str(ephemeral_dir),
            ):
                warm_stopforumspam_caches()
                unbuilt_res = query_stopforumspam_offline("198.51.100.21")
                self.assertFalse(unbuilt_res["has_db"])
                self.assertFalse((data_dir / "stopforumspam.sqlite3").exists())

                clear_offline_intelligence_caches()
                sqlite_target = data_dir / "stopforumspam.sqlite3"
                build_stopforumspam_sqlite_index(sqlite_target, raw_listed, None)

                real_connect = offline_dbs.sqlite3.connect
                connect_uris: List[str] = []

                def _spy_connect(database: Any, *args: Any, **kwargs: Any):
                    connect_uris.append(str(database))
                    return real_connect(database, *args, **kwargs)

                with patch("detector.offline_dbs.sqlite3.connect", side_effect=_spy_connect):
                    first = query_stopforumspam_offline("198.51.100.21")
                    second = query_stopforumspam_offline("198.51.100.21")
                    miss = query_stopforumspam_offline("198.51.100.99")

                self.assertTrue(first["appears"])
                self.assertEqual(first["frequency"], 11)
                self.assertEqual(second["frequency"], 11)
                self.assertFalse(miss["appears"])
                self.assertEqual(len(connect_uris), 1)
                self.assertIn(ephemeral_dir.resolve().as_posix(), connect_uris[0])

                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    worker_hit = pool.submit(query_stopforumspam_offline, "198.51.100.21").result()
                self.assertTrue(worker_hit["appears"])

                # Closing caches must release both main-thread and worker-thread handles cleanly on Windows
                clear_offline_intelligence_caches()
                sync_copy = sync_file_to_ephemeral_cache(sqlite_target, ephemeral_dir)
                self.assertTrue(sync_copy.is_file())


class OfflineFeedsUpdaterAndLookupTests(TestCase):
    """Tests update_offline_dbs conditional syncs and sub-millisecond lookup helpers for all feeds."""

    def setUp(self) -> None:
        clear_offline_intelligence_caches()
        self.addCleanup(clear_offline_intelligence_caches)

    def test_all_six_new_feeds_sync_conditional_304_headers_and_fast_lookups(self) -> None:
        with _isolated_offline_dirs() as (tool_root, data_dir, ephemeral_dir):
            routes = _build_all_feeds_payloads()
            seen_requests: List[Tuple[str, Dict[str, str]]] = []

            with (
                override_settings(
                    TOOL_DATA_DIR=str(tool_root),
                    LOCAL_EPHEMERAL_CACHE_DIR=str(ephemeral_dir),
                ),
                patch.object(
                    update_cmd.httpx,
                    "Client",
                    side_effect=lambda **_kw: _make_conditional_client_cm(routes, seen_requests),
                ),
            ):
                self.assertIsNone(lookup_tor_onionoo_offline("198.51.100.77"))

                call_command(
                    "update_offline_dbs",
                    sources=[
                        "privacy_relays,ipsum_drop",
                        "tor_onionoo",
                        "bgp_tools,x4bnet_vpn",
                        "peeringdb_mobile",
                    ],
                    force=True,
                    stdout=io.StringIO(),
                )

                bgp_reqs = [hdrs for url, hdrs in seen_requests if "bgp.tools" in url]
                self.assertGreaterEqual(len(bgp_reqs), 2)
                for hdrs in bgp_reqs:
                    self.assertEqual(
                        hdrs.get("User-Agent"),
                        "ProxyCheck/1.0 bgp.tools - tools.proxycheck@toolforge.org",
                    )

                tor_reqs = [hdrs for url, hdrs in seen_requests if "onionoo.torproject.org" in url]
                self.assertEqual(len(tor_reqs), 1)
                self.assertEqual(tor_reqs[0].get("Accept-Encoding"), "gzip")

                privacy_cases = (
                    ("172.224.226.5", "icloud_private_relay"),
                    ("2a02:26f7:b400::1", "icloud_private_relay"),
                    ("104.28.16.42", "cloudflare_warp"),
                    ("2a09:bac0::99", "cloudflare_warp"),
                    # Exact CIDR match with CDN ips-v4 must NOT classify as WARP
                    ("172.64.10.1", None),
                    # Narrower CDN 24-bit subnet inside broader WARP 20-bit prefix excludes CDN edge
                    ("104.28.20.9", None),
                    # Narrower WARP 25-bit subnet inside broader CDN 20-bit prefix overrides to WARP
                    ("173.245.48.200", "cloudflare_warp"),
                    ("173.245.48.10", None),
                    ("2606:4700::1", None),
                    ("8.8.8.8", None),
                )
                for ip_addr, expected_relay in privacy_cases:
                    with self.subTest(privacy_ip=ip_addr):
                        self.assertEqual(lookup_privacy_relay_offline(ip_addr), expected_relay)

                ipsum_cases = (
                    ("198.51.100.10", False, 0, False, None),
                    ("198.51.100.11", True, 2, False, None),
                    ("198.51.100.12", True, 5, False, None),
                    ("192.0.2.99", True, 0, True, "SBL100001"),
                    ("192.0.2.55", True, 4, True, "SBL100001"),
                    ("2001:db8:dead::7", True, 0, True, "SBL600009"),
                    ("203.0.113.1", False, 0, False, None),
                )
                for ip_addr, listed, score, in_drop, sbl_id in ipsum_cases:
                    with self.subTest(ipsum_ip=ip_addr):
                        res = query_ipsum_drop_offline(ip_addr)
                        self.assertTrue(res["hasDb"])
                        self.assertEqual(res["isListed"], listed)
                        self.assertEqual(res["ipsumScore"], score)
                        self.assertEqual(res["isIpsumListed"], score >= 2)
                        self.assertEqual(res["inSpamhausDrop"], in_drop)
                        self.assertEqual(res["dropSblId"], sbl_id)

                tor_hit_v4 = lookup_tor_onionoo_offline("198.51.100.77")
                self.assertIsNotNone(tor_hit_v4)
                assert tor_hit_v4 is not None
                self.assertEqual(len(tor_hit_v4["relays"]), 1)
                adapted_tor = adapt_tor_onionoo(tor_hit_v4, 200, ip="198.51.100.77")
                self.assertTrue(adapted_tor["isTor"])
                self.assertTrue(adapted_tor["torIsExit"])

                tor_hit_v6 = lookup_tor_onionoo_offline("2001:db8:cafe::77")
                assert tor_hit_v6 is not None
                self.assertEqual(len(tor_hit_v6["relays"]), 1)

                tor_clean = lookup_tor_onionoo_offline("203.0.113.50")
                self.assertEqual(tor_clean, {"relays": [], "bridges": []})

                bgp_cases = (
                    ("203.0.113.5", {"bgpPrefix": "203.0.113.0/24", "asn": 64501, "tags": []}),
                    ("203.0.113.200", {"bgpPrefix": "203.0.113.128/25", "asn": 64502, "tags": ["vpn"]}),
                    ("2001:db8:1234:5::1", {"bgpPrefix": "2001:db8:1234::/48", "asn": 64503, "tags": []}),
                    ("198.51.100.2", {"bgpPrefix": "198.51.100.0/24", "asn": 64555, "tags": ["mobile"]}),
                    ("9.9.9.9", None),
                )
                for ip_addr, expected_bgp in bgp_cases:
                    with self.subTest(bgp_ip=ip_addr):
                        self.assertEqual(lookup_bgp_tools_offline(ip_addr), expected_bgp)

                x4b_cases = (
                    ("185.159.157.9", True, True, True, "vpn"),
                    ("2a0d:5600:10::1", True, False, False, "vpn"),
                    ("198.51.100.200", False, True, True, "datacenter"),
                    ("2a01:4f8:c010::5", False, True, True, "datacenter"),
                    ("203.0.113.70", False, False, True, "hosting"),
                    ("8.8.4.4", False, False, False, None),
                )
                for ip_addr, is_vpn, is_dc, is_host, category in x4b_cases:
                    with self.subTest(x4b_ip=ip_addr):
                        x4b_res = query_x4bnet_vpn_offline(ip_addr)
                        self.assertEqual(x4b_res["isVpn"], is_vpn)
                        self.assertEqual(x4b_res["isDatacenter"], is_dc)
                        self.assertEqual(x4b_res["isHosting"], is_host)
                        self.assertEqual(x4b_res["category"], category)

                for mobile_asn in (21928, 7018, 64555):
                    self.assertTrue(is_mobile_asn_offline(mobile_asn))
                self.assertFalse(is_mobile_asn_offline(15169))
                self.assertFalse(is_mobile_asn_offline(None))

                # Second sync sends ETag and If-Modified-Since headers and preserves files on HTTP 304
                seen_requests.clear()
                mtime_before = (data_dir / "privacy_relays.bin").stat().st_mtime_ns
                out_304 = io.StringIO()
                call_command(
                    "update_offline_dbs",
                    sources=[
                        "privacy_relays",
                        "ipsum_drop",
                        "tor_onionoo",
                        "bgp_tools",
                        "x4bnet_vpn",
                        "peeringdb_mobile",
                    ],
                    force=True,
                    stdout=out_304,
                )
                self.assertEqual((data_dir / "privacy_relays.bin").stat().st_mtime_ns, mtime_before)
                self.assertIn("304 Not Modified", out_304.getvalue())
                tor_second = [hdrs for url, hdrs in seen_requests if "onionoo.torproject.org" in url][0]
                self.assertEqual(tor_second.get("If-Modified-Since"), "Wed, 18 Nov 2026 03:00:00 GMT")
                self.assertEqual(tor_second.get("If-None-Match"), '"tor-v1"')
                self.assertEqual(tor_second.get("Accept-Encoding"), "gzip")

            with self.assertRaises(CommandError):
                call_command("update_offline_dbs", sources=["unknown_feed"], dry_run=True)

    def test_missing_or_corrupt_feed_files_degrade_safely_and_report_status(self) -> None:
        with (
            _isolated_offline_dirs() as (tool_root, data_dir, ephemeral_dir),
            override_settings(
                TOOL_DATA_DIR=str(tool_root),
                LOCAL_EPHEMERAL_CACHE_DIR=str(ephemeral_dir),
            ),
        ):
            self.assertIsNone(lookup_privacy_relay_offline("172.224.226.5"))
            self.assertFalse(query_ipsum_drop_offline("192.0.2.1")["hasDb"])
            self.assertIsNone(lookup_tor_onionoo_offline("198.51.100.77"))
            self.assertIsNone(lookup_bgp_tools_offline("203.0.113.5"))
            self.assertFalse(query_x4bnet_vpn_offline("185.159.157.9")["hasDb"])
            self.assertFalse(is_mobile_asn_offline(21928))

            for fname in ("privacy_relays.bin", "ipsum_drop.bin", "bgp_tools.bin", "x4bnet_vpn.bin"):
                (data_dir / fname).write_bytes(b"CORRUPT-BIN-DATA")
            (data_dir / "tor_onionoo_summary.json").write_text("{corrupt-json", encoding="utf-8")
            clear_offline_intelligence_caches()

            self.assertIsNone(lookup_privacy_relay_offline("172.224.226.5"))
            self.assertFalse(query_ipsum_drop_offline("192.0.2.1")["isListed"])
            self.assertIsNone(lookup_tor_onionoo_offline("198.51.100.77"))
            self.assertIsNone(lookup_bgp_tools_offline("203.0.113.5"))
            self.assertFalse(query_x4bnet_vpn_offline("185.159.157.9")["isListed"])

            status_by_key = {e["key"]: e for e in offline_dbs.collect_offline_databases_status()}
            for expected_key in (
                "privacy_relays",
                "ipsum_drop",
                "tor_onionoo",
                "bgp_tools",
                "x4bnet_vpn",
                "peeringdb_mobile",
            ):
                self.assertIn(expected_key, status_by_key)


class MobileCgnatAndIpv6EscalationCidrTests(SimpleTestCase):
    """Tests cellular and CGNAT PTR separation, host mask locks, and IPv6 escalation CIDR rules."""

    def setUp(self) -> None:
        clear_offline_intelligence_caches()
        self.addCleanup(clear_offline_intelligence_caches)

    def test_rdns_separates_cellular_and_cgnat_tokens_from_dynamic_residential(self) -> None:
        mobile_hosts = (
            "sub-10-20.mobile.carrier.example",
            "pool.cellular.isp.example",
            "lte04.vodafone.de",
            "node-5g.telecom.example",
            "nr.ran.carrier.example",
            "epc01.core.carrier.example",
            "ggsn2.wireless.example",
            "pgw-west.carrier.example",
            "cgn-pool-12.isp.example",
            "cgnat01.telekom.de",
            "nat444-edge.isp.example",
            "gprs-gateway.carrier.example",
        )
        for host in mobile_hosts:
            with self.subTest(mobile_host=host):
                classified = classify_rdns_hostname(host)
                self.assertEqual(classified["ptrCategory"], "mobile_or_cgnat")
                self.assertFalse(classified["isHighRisk"])

        residential_hosts = (
            "p5489a1b2.dip0.t-ipconnect.de",
            "cust-88.pppoe.isp.example",
            "ftth-subscriber.broadband.example",
            "cable-docsis.comcast.net",
        )
        for host in residential_hosts:
            with self.subTest(residential_host=host):
                self.assertEqual(classify_rdns_hostname(host)["ptrCategory"], "dynamic_residential")

    def test_mobile_cgnat_locks_ipv4_32_and_ipv6_64_and_ipv6_escalation_rules(self) -> None:
        with _isolated_offline_dirs() as (tool_root, data_dir, ephemeral_dir):
            (data_dir / "mobile_asns.json").write_text(
                json.dumps({"mobile_asns": [21928]}),
                encoding="utf-8",
            )
            (data_dir / "bgp_tags.json").write_text(
                json.dumps({"asn_tags": {"64555": ["mobile"], "24940": ["hosting"]}}),
                encoding="utf-8",
            )
            compile_binary_prefix_index(
                [
                    ("198.51.100.0/24", 64555),
                    ("2001:db8:1234::/48", 7922),
                    ("2001:db8:5555::/32", 21928),
                    ("2a01:4f8::/32", 24940),
                ],
                data_dir / "bgp_tools.bin",
            )
            compile_binary_prefix_index(
                [
                    ("172.224.226.0/27", "icloud_private_relay"),
                    ("104.28.16.0/20", "cloudflare_warp"),
                    ("173.245.48.0/20", "cloudflare_cdn"),
                ],
                data_dir / "privacy_relays.bin",
            )

            with override_settings(
                TOOL_DATA_DIR=str(tool_root),
                LOCAL_EPHEMERAL_CACHE_DIR=str(ephemeral_dir),
            ):
                mobile_cases = (
                    (
                        "ptr_mobile_v4",
                        "203.0.113.45",
                        {"ptr_hostname": "cgnat-pool.isp.example"},
                        "203.0.113.45/32",
                    ),
                    (
                        "bgp_mobile_tag_v4",
                        "198.51.100.9",
                        {},
                        "198.51.100.9/32",
                    ),
                    (
                        "peeringdb_mobile_v6",
                        "2001:db8:5555:9999::1",
                        {},
                        "2001:db8:5555:9999::/64",
                    ),
                    (
                        "provider_row_carrier_v4",
                        "203.0.113.88",
                        {"provider_rows": [{"status": "200 OK", "carrier": "T-Mobile"}]},
                        "203.0.113.88/32",
                    ),
                    (
                        "provider_row_mobile_brand_v6",
                        "2001:db8:1234:5678::9",
                        {"provider_rows": [{"status": "200 OK", "mobileBrand": "Vodafone"}]},
                        "2001:db8:1234:5678::/64",
                    ),
                )
                for label, ip_str, kwargs, expected_rec in mobile_cases:
                    with self.subTest(mobile_case=label):
                        res = compute_cidr_attribution(ip_str, **kwargs)
                        self.assertTrue(res["isMobileOrCgnat"])
                        self.assertEqual(res["recommendedCidr"], expected_rec)
                        self.assertIsNone(res["escalationCidr"])

                # Residential IPv6 with BGP 48-bit prefix sets escalationCidr to normalised 56-bit range
                res_v6 = compute_cidr_attribution("2001:db8:1234:5678::1")
                self.assertFalse(res_v6["isMobileOrCgnat"])
                self.assertEqual(res_v6["bgpPrefix"], "2001:db8:1234::/48")
                self.assertEqual(res_v6["recommendedCidr"], "2001:db8:1234:5678::/64")
                self.assertEqual(res_v6["escalationCidr"], "2001:db8:1234:5600::/56")

                # Residential IPv6 with narrower BGP 56-bit prefix does not escalate
                res_narrow_bgp = compute_cidr_attribution(
                    "2001:db8:7777:5678::1",
                    bgp_prefix="2001:db8:7777:5600::/56",
                )
                self.assertEqual(res_narrow_bgp["recommendedCidr"], "2001:db8:7777:5678::/64")
                self.assertIsNone(res_narrow_bgp["escalationCidr"])

                # Cloud and VPS IPv6 clamps escalationCidr strictly to [48, 64]
                hosting_cases = (
                    ("wide_bgp_32", "2a01:4f8:1234:5678::1", {}, "2a01:4f8:1234:5678::/64", "2a01:4f8:1234::/48"),
                    (
                        "cloud_52",
                        "2600:1f18:2000:abcd::5",
                        {"cloud_cidr": "2600:1f18:2000:a000::/52", "cloud_provider": "Amazon AWS"},
                        "2600:1f18:2000:abcd::/64",
                        "2600:1f18:2000:a000::/52",
                    ),
                    (
                        "cloud_narrow_80",
                        "2600:1f18:2000:abcd::5",
                        {"cloud_cidr": "2600:1f18:2000:abcd::/80", "cloud_provider": "Amazon AWS"},
                        "2600:1f18:2000:abcd::/80",
                        "2600:1f18:2000:abcd::/64",
                    ),
                )
                for label, ip_str, kwargs, expected_rec, expected_esc in hosting_cases:
                    with self.subTest(hosting_case=label):
                        host_res = compute_cidr_attribution(ip_str, **kwargs)
                        self.assertEqual(host_res["recommendedCidr"], expected_rec)
                        self.assertEqual(host_res["escalationCidr"], expected_esc)

                # Shared privacy egress populates cleanly while excluding Cloudflare CDN edge
                icloud_attr = compute_cidr_attribution("172.224.226.9")
                self.assertEqual(icloud_attr["sharedPrivacyEgress"], "icloud_private_relay")
                warp_attr = compute_cidr_attribution("104.28.16.9")
                self.assertEqual(warp_attr["sharedPrivacyEgress"], "cloudflare_warp")
                cdn_attr = compute_cidr_attribution("173.245.48.9")
                self.assertIsNone(cdn_attr["sharedPrivacyEgress"])

                # MediaWiki minimum prefix clamp helper guard
                self.assertEqual(cidr_attribution._clamp_mediawiki_prefix_len(4, 8), 16)
                self.assertEqual(cidr_attribution._clamp_mediawiki_prefix_len(6, 12), 19)
