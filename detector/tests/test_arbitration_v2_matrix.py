"""Table-driven regression matrices for offline prefix indexes, CIDR masks, arbitration, and Redis isolation."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Set, Tuple
from unittest.mock import AsyncMock, patch

import dns.resolver
from django.test import TestCase, override_settings

from detector import (
    cache_backends,
    cidr_attribution,
    detection_service,
    offline_dbs,
    providers,
    quota_telemetry,
    views,
)
from detector.adapters import (
    adapt_abuseipdb,
    adapt_dshield,
    adapt_getipintel,
    adapt_ipdata,
    adapt_ipregistry,
    adapt_ipsum_drop,
    adapt_shodan_internetdb,
    adapt_spamhaus_zen,
    adapt_stopforumspam,
    adapt_tor_onionoo,
    adapt_x4bnet_vpn,
)
from detector.binary_prefix_index import BinaryPrefixIndexReader, compile_binary_prefix_index

from .helpers import (
    MAXMIND_STUB,
    TEST_UPSTREAM_SECRETS,
    _BatchingFakeRedis,
    _mock_response,
    start_non_dnsbl_provider_stubs,
)


def _clean_commercial_row(provider: str, *, usage: str = "isp", asn: str = "AS7922") -> Dict[str, Any]:
    return {
        "provider": provider,
        "status": "200 OK",
        "statusCode": 200,
        "asn": asn,
        "isp": "Example Residential Broadband",
        "organisation": "Example Residential Broadband",
        "location": "United States",
        "usageType": usage,
        "countryCode": "US",
        "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
        "rawJson": {"provider": provider},
    }


def _high_risk_commercial_row(provider: str, flag_label: str = "VPN", usage: str = "isp") -> Dict[str, Any]:
    row = _clean_commercial_row(provider, usage=usage)
    row["securityFlags"] = [{"label": flag_label, "isHighRisk": True}]
    return row


class BinaryPrefixAndOfflineFeedMatrixTests(TestCase):
    """Table-driven checks for memory-mapped LPM indexes, privacy relays, Onionoo mirror, and Cymru BGP."""

    def setUp(self) -> None:
        detection_service._ip_detect_inflight.clear()
        cidr_attribution.clear_offline_intelligence_caches()
        self.addCleanup(cidr_attribution.clear_offline_intelligence_caches)
        self.addCleanup(detection_service._ip_detect_inflight.clear)

    def test_binary_prefix_index_overlapping_lpm_merge_callback_and_mmap_lookup_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            bin_path = root / "overlapping_lpm.bin"
            ephemeral_dir = root / "ephemeral"

            rules: List[Tuple[str, Any]] = [
                ("0.0.0.0/0", "default_v4"),
                ("198.51.0.0/16", "supernet_16"),
                ("198.51.100.0/24", 1),
                ("198.51.100.0/24", 2),
                ("198.51.100.128/25", "subnet_25"),
                ("198.51.100.200/32", {"role": "host_32"}),
                ("::/0", "default_v6"),
                ("2001:db8::/32", "v6_32"),
                ("2001:db8:abcd::/48", 4),
                ("2001:db8:abcd::/48", 1),
                ("2001:db8:abcd:1200::/56", "v6_56"),
                ("2001:db8:abcd:1234::1/128", "v6_host_128"),
            ]

            def _merge_bits(left: Any, right: Any) -> Any:
                if isinstance(left, int) and isinstance(right, int):
                    return left | right
                return right

            compiled_count = compile_binary_prefix_index(rules, bin_path, merge_payloads=_merge_bits)
            self.assertEqual(compiled_count, 10)

            with BinaryPrefixIndexReader.open_from_source(bin_path, ephemeral_dir) as reader:
                self.assertIsNotNone(reader._mmap)
                self.assertFalse(reader.closed)

                lookup_cases = (
                    ("8.8.8.8", ("0.0.0.0/0", 0, "default_v4")),
                    ("198.51.99.255", ("198.51.0.0/16", 16, "supernet_16")),
                    ("198.51.100.1", ("198.51.100.0/24", 24, 3)),
                    ("198.51.100.127", ("198.51.100.0/24", 24, 3)),
                    ("198.51.100.128", ("198.51.100.128/25", 25, "subnet_25")),
                    ("198.51.100.200", ("198.51.100.200/32", 32, {"role": "host_32"})),
                    ("198.51.100.201", ("198.51.100.128/25", 25, "subnet_25")),
                    ("198.51.101.0", ("198.51.0.0/16", 16, "supernet_16")),
                    ("2606:4700::1111", ("::/0", 0, "default_v6")),
                    ("2001:db8:9999::1", ("2001:db8::/32", 32, "v6_32")),
                    ("2001:db8:abcd:0099::1", ("2001:db8:abcd::/48", 48, 5)),
                    ("2001:db8:abcd:12ff::9", ("2001:db8:abcd:1200::/56", 56, "v6_56")),
                    ("2001:db8:abcd:1234::1%eth0", ("2001:db8:abcd:1234::1/128", 128, "v6_host_128")),
                )
                for raw_ip, expected_hit in lookup_cases:
                    with self.subTest(ip=raw_ip):
                        self.assertEqual(reader.lookup_with_prefix_len(raw_ip), expected_hit)
                        self.assertEqual(reader.lookup(raw_ip), (expected_hit[0], expected_hit[2]))

    def test_privacy_relay_cdn_exclusion_ipsum_drop_x4bnet_and_shodan_port_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tool_root = Path(tmp_dir) / "tool"
            data_dir = tool_root / "data"
            ephemeral_dir = Path(tmp_dir) / "ephemeral"
            data_dir.mkdir(parents=True)

            compile_binary_prefix_index(
                [
                    ("172.224.226.0/27", "icloud_private_relay"),
                    ("2a02:26f7:b400::/48", "icloud_private_relay"),
                    ("104.28.0.0/14", "cloudflare_warp"),
                    ("104.28.20.0/24", "cloudflare_cdn"),
                    ("173.245.48.0/20", "cloudflare_cdn"),
                    ("173.245.48.128/25", "cloudflare_warp"),
                    ("2a09:bac0::/29", "cloudflare_warp"),
                    ("2606:4700::/32", "cloudflare_cdn"),
                ],
                data_dir / "privacy_relays.bin",
            )
            compile_binary_prefix_index(
                [
                    ("198.51.100.10/32", 1),
                    ("198.51.100.11/32", 2),
                    ("198.51.100.12/32", 3),
                    ("192.0.2.0/24", {"drop": True, "sblid": "SBL44001", "drop_cidr": "192.0.2.0/24"}),
                    ("2001:db8:dead::/48", {"drop": True, "sblid": "SBL66002", "drop_cidr": "2001:db8:dead::/48"}),
                ],
                data_dir / "ipsum_drop.bin",
            )
            compile_binary_prefix_index(
                [
                    ("185.159.157.0/24", offline_dbs.X4BNET_MASK_VPN),
                    ("198.51.100.192/26", offline_dbs.X4BNET_MASK_DATACENTER),
                    ("203.0.113.64/27", offline_dbs.X4BNET_MASK_HOSTING),
                ],
                data_dir / "x4bnet_vpn.bin",
            )

            try:
                with override_settings(
                    TOOL_DATA_DIR=str(tool_root),
                    LOCAL_EPHEMERAL_CACHE_DIR=str(ephemeral_dir),
                ):
                    relay_cases = (
                        ("apple_v4", "172.224.226.12", "icloud_private_relay"),
                        ("apple_v6", "2a02:26f7:b400::7", "icloud_private_relay"),
                        ("warp_v4", "104.28.12.9", "cloudflare_warp"),
                        ("warp_v6", "2a09:bac1::1", "cloudflare_warp"),
                        ("warp_subnet_inside_cdn", "173.245.48.200", "cloudflare_warp"),
                        ("cdn_subnet_inside_warp_excluded", "104.28.20.44", None),
                        ("cdn_edge_v4_excluded", "173.245.48.10", None),
                        ("cdn_edge_v6_excluded", "2606:4700:4700::1111", None),
                    )
                    for label, ip_addr, expected_egress in relay_cases:
                        with self.subTest(privacy_case=label):
                            self.assertEqual(offline_dbs.lookup_privacy_relay_offline(ip_addr), expected_egress)

                    ipsum_cases = (
                        ("score_1_ignored", "198.51.100.10", False, 0, False, False, 0),
                        ("score_2_moderate_zero_votes", "198.51.100.11", True, 2, False, False, 0),
                        ("score_3_high_risk_votes", "198.51.100.12", True, 3, False, True, 1),
                        ("drop_v4_high_risk_votes", "192.0.2.77", True, 0, True, True, 1),
                        ("drop_v6_high_risk_votes", "2001:db8:dead::99", True, 0, True, True, 1),
                    )
                    base_clean = [_clean_commercial_row(n) for n in ("IPHub", "IPData", "Proxycheck", "IPHunter")]
                    for label, ip_addr, exp_listed, exp_score, exp_drop, exp_high_risk, exp_vote_delta in ipsum_cases:
                        with self.subTest(ipsum_case=label):
                            lookup = offline_dbs.query_ipsum_drop_offline(ip_addr)
                            row = adapt_ipsum_drop(lookup, status_code=200, has_db=True)
                            self.assertEqual(row["isListed"], exp_listed)
                            self.assertEqual(row["ipsumScore"], exp_score)
                            self.assertEqual(row["inSpamhausDrop"], exp_drop)
                            self.assertEqual(any(f["isHighRisk"] for f in row["securityFlags"]), exp_high_risk)
                            agg = views.aggregate_intelligence_metrics("8.8.8.8", [*base_clean, row])
                            if exp_vote_delta == 0:
                                self.assertEqual(agg["arbitrationVerdict"], "Clean Residential / Direct (0/4 Sources)")
                            else:
                                self.assertEqual(agg["arbitrationVerdict"], "Disputed Proxy / VPN (1/5 Sources)")

                    x4b_cases = (
                        ("vpn_casts_vote", "185.159.157.5", "vpn", True, "Disputed Proxy / VPN (1/5 Sources)"),
                        (
                            "datacenter_auxiliary_only",
                            "198.51.100.200",
                            "datacenter",
                            False,
                            "Clean Residential / Direct (0/4 Sources)",
                        ),
                        (
                            "hosting_auxiliary_only",
                            "203.0.113.70",
                            "hosting",
                            False,
                            "Clean Residential / Direct (0/4 Sources)",
                        ),
                    )
                    for label, ip_addr, exp_cat, exp_high_risk, exp_verdict in x4b_cases:
                        with self.subTest(x4b_case=label):
                            x4b_lookup = offline_dbs.query_x4bnet_vpn_offline(ip_addr)
                            x4b_row = adapt_x4bnet_vpn(x4b_lookup, status_code=200, has_db=True)
                            self.assertEqual(x4b_row["category"], exp_cat)
                            self.assertEqual(any(f["isHighRisk"] for f in x4b_row["securityFlags"]), exp_high_risk)
                            agg = views.aggregate_intelligence_metrics("8.8.8.8", [*base_clean, x4b_row])
                            self.assertEqual(agg["arbitrationVerdict"], exp_verdict)
            finally:
                cidr_attribution.clear_offline_intelligence_caches()

        shodan_cases = (
            ("http_404_clean_empty", {"detail": "No information available"}, 404, [], [], False),
            (
                "all_canonical_proxy_ports_and_cve_strip",
                {
                    "ports": [22, 443, 1080, 3128, 8080, 9050],
                    "tags": ["proxy", "CVE-2024-1234", "cloud"],
                    "hostnames": ["node.example.org."],
                },
                200,
                [1080, 3128, 8080, 9050],
                ["proxy", "cloud"],
                True,
            ),
        )
        for label, raw_payload, code, exp_proxy_ports, exp_tags, exp_high_risk in shodan_cases:
            with self.subTest(shodan_case=label):
                s_row = adapt_shodan_internetdb(raw_payload, status_code=code)
                self.assertEqual(s_row["status"], "200 OK")
                self.assertEqual(s_row["statusCode"], 200)
                self.assertEqual(s_row["openProxyPorts"], exp_proxy_ports)
                self.assertEqual(s_row["tags"], exp_tags)
                self.assertEqual(any(f["isHighRisk"] for f in s_row["securityFlags"]), exp_high_risk)

    async def test_tor_onionoo_local_mirror_hit_clean_miss_and_missing_file_http_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tool_root = Path(tmp_dir) / "tool"
            data_dir = tool_root / "data"
            data_dir.mkdir(parents=True)
            mirror_file = data_dir / "tor_onionoo_summary.json"
            mirror_file.write_text(
                json.dumps(
                    {
                        "relays": [
                            {
                                "n": "FastExit",
                                "a": ["185.220.101.10", "[2001:db8:cafe::10]"],
                                "exit_addresses": ["185.220.101.10"],
                                "r": True,
                                "flags": ["Exit", "Fast", "Running"],
                            },
                            {
                                "n": "GuardOnly",
                                "a": ["185.220.101.11"],
                                "r": True,
                                "flags": ["Guard", "Running"],
                            },
                            {
                                "n": "OfflineRelay",
                                "a": ["185.220.101.12"],
                                "r": False,
                                "flags": ["Exit"],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            http_mock = AsyncMock()
            with override_settings(TOOL_DATA_DIR=str(tool_root)):
                offline_dbs.lookup_tor_onionoo_offline("8.8.8.8")
                t_start = time.perf_counter()
                for _ in range(200):
                    offline_dbs.lookup_tor_onionoo_offline("185.220.101.10")
                    offline_dbs.lookup_tor_onionoo_offline("8.8.8.8")
                per_lookup_ms = ((time.perf_counter() - t_start) * 1000.0) / 400.0
                self.assertLess(per_lookup_ms, 0.1)

                mirror_cases = (
                    ("active_exit_v4", "185.220.101.10", True, True, "Tor Exit"),
                    ("active_relay_v6", "2001:db8:cafe::10", True, True, "Tor Exit"),
                    ("active_guard_v4", "185.220.101.11", True, False, "Tor Guard"),
                    ("dormant_relay_v4", "185.220.101.12", False, False, None),
                    ("clean_miss_relays_empty", "203.0.113.250", False, False, None),
                )
                for label, ip_addr, exp_is_tor, exp_is_exit, exp_label in mirror_cases:
                    with self.subTest(mirror_case=label):
                        row = await providers.query_tor_onionoo(http_mock, ip_addr)
                        self.assertEqual(row["status"], "200 OK")
                        self.assertEqual(row["isTor"], exp_is_tor)
                        self.assertEqual(row["torIsExit"], exp_is_exit)
                        self.assertEqual(row["torLabel"], exp_label)
                http_mock.get.assert_not_awaited()

                mirror_file.unlink()
                cidr_attribution.clear_offline_intelligence_caches()
                http_mock.get.return_value = _mock_response(
                    status_code=200,
                    json_value={"relays": [{"a": ["185.220.101.99"], "r": True, "flags": ["Exit", "Running"]}]},
                )
                fallback_row = await providers.query_tor_onionoo(http_mock, "185.220.101.99")
                self.assertTrue(fallback_row["isTor"])
                self.assertTrue(fallback_row["torIsExit"])
                http_mock.get.assert_awaited_once()

    async def test_team_cymru_dns_txt_end_to_end_fallback_populates_bgp_prefix_and_ipv6_escalation(self) -> None:
        fake_redis = _BatchingFakeRedis()
        start_non_dnsbl_provider_stubs(
            self,
            overrides={"maxmind": dict(MAXMIND_STUB)},
            row_builder=lambda label: _clean_commercial_row(label),
        )
        patch(
            "detector.dns_providers.query_spamhaus_zen",
            new_callable=AsyncMock,
            return_value=_clean_commercial_row("Spamhaus ZEN"),
        ).start()
        patch(
            "detector.dns_providers.query_spamcop",
            new_callable=AsyncMock,
            return_value=_clean_commercial_row("SpamCop"),
        ).start()
        self.addCleanup(patch.stopall)

        cymru_queries: List[Tuple[str, str]] = []

        async def _cymru_or_ptr_resolver(qname: Any, rdtype: str = "A", *_args: Any, **_kwargs: Any) -> Any:
            q_str = str(qname)
            cymru_queries.append((q_str, rdtype))
            if rdtype == "TXT" and q_str.endswith(".origin.asn.cymru.com"):
                return [SimpleNamespace(strings=(b"7922 | 94.140.12.0/22 | US | arin | 2020-01-01",))]
            if rdtype == "TXT" and q_str.endswith(".origin6.asn.cymru.com"):
                return [SimpleNamespace(strings=(b"7922 | 2606:4700::/32 | US | arin | 2020-01-01",))]
            raise dns.resolver.NXDOMAIN()

        with (
            patch("detector.dns_providers.lookup_bgp_tools_offline", return_value=None),
            patch("detector.detection_service.lookup_bgp_tools_offline", return_value=None),
            patch("detector.cidr_attribution.lookup_bgp_tools_offline", return_value=None),
            patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock, side_effect=_cymru_or_ptr_resolver),
            patch("detector.cache_backends.redis_client", fake_redis),
        ):
            v4_payload = await detection_service.detect_single_canonical_ip("94.140.14.14", "session", 0.0)
            v6_payload = await detection_service.detect_single_canonical_ip("2606:4700:1234:5678::1", "session", 0.0)

        self.assertEqual(v4_payload["bgpPrefix"], "94.140.12.0/22")
        self.assertEqual(v4_payload["recommendedCidr"], "94.140.14.0/24")
        self.assertEqual(v6_payload["bgpPrefix"], "2606:4700::/32")
        self.assertEqual(v6_payload["recommendedCidr"], "2606:4700:1234:5678::/64")
        self.assertEqual(v6_payload["escalationCidr"], "2606:4700:1234:5600::/56")
        txt_queries = [q for q, rtype in cymru_queries if rtype == "TXT"]
        self.assertEqual(len(txt_queries), 2)


class CidrMaskParadoxAndArbitrationBoundaryMatrixTests(TestCase):
    """Table-driven checks for CGNAT and IPv6 masks, MediaWiki clamps, signal paradox, and arbitration v2."""

    def setUp(self) -> None:
        cidr_attribution.clear_offline_intelligence_caches()
        self.addCleanup(cidr_attribution.clear_offline_intelligence_caches)

    def test_mobile_cgnat_locks_ipv6_escalation_and_mediawiki_cidr_clamp_matrix(self) -> None:
        clamp_cases = (
            (4, "203.0.113.9", 8, "203.0.0.0/16"),
            (4, "203.0.113.9", 15, "203.0.0.0/16"),
            (4, "203.0.113.9", 16, "203.0.0.0/16"),
            (4, "203.0.113.9", 24, "203.0.113.0/24"),
            (4, "203.0.113.9", 32, "203.0.113.9/32"),
            (6, "2001:db8:abcd:1234::1", 8, "2001::/19"),
            (6, "2001:db8:abcd:1234::1", 18, "2001::/19"),
            (6, "2001:db8:abcd:1234::1", 19, "2001::/19"),
            (6, "2001:db8:abcd:1234::1", 48, "2001:db8:abcd::/48"),
            (6, "2001:db8:abcd:1234::1", 128, "2001:db8:abcd:1234::1/128"),
        )
        for _ver, raw_ip, prefix_len, expected_clamped in clamp_cases:
            with self.subTest(clamp_ip=raw_ip, prefix=prefix_len):
                import ipaddress

                formatted = cidr_attribution._format_clamped_cidr(ipaddress.ip_address(raw_ip), prefix_len)
                self.assertEqual(formatted, expected_clamped)

        attribution_cases = (
            (
                "rfc6598_cgnat_v4_locked_32",
                "100.64.42.9",
                {"mmdb_prefix_len": 28},
                True,
                "100.64.42.9/32",
                None,
            ),
            (
                "is_mobile_provider_v4_locked_32",
                "203.0.113.42",
                {"mmdb_prefix_len": 26, "provider_rows": [{"status": "200 OK", "isMobile": True}]},
                True,
                "203.0.113.42/32",
                None,
            ),
            (
                "mobile_v6_locked_64_no_escalation",
                "2001:db8:1234:5678::1",
                {"bgp_prefix": "2001:db8::/32", "ptr_hostname": "lte-gw.carrier.example"},
                True,
                "2001:db8:1234:5678::/64",
                None,
            ),
            (
                "residential_v6_bgp_32_escalates_56",
                "2001:db8:1234:5678::1",
                {"bgp_prefix": "2001:db8::/32"},
                False,
                "2001:db8:1234:5678::/64",
                "2001:db8:1234:5600::/56",
            ),
            (
                "residential_v6_bgp_48_escalates_56",
                "2001:db8:1234:5678::1",
                {"bgp_prefix": "2001:db8:1234::/48"},
                False,
                "2001:db8:1234:5678::/64",
                "2001:db8:1234:5600::/56",
            ),
            (
                "residential_v6_bgp_49_no_escalation",
                "2001:db8:1234:5678::1",
                {"bgp_prefix": "2001:db8:1234::/49"},
                False,
                "2001:db8:1234:5678::/64",
                None,
            ),
            (
                "cloud_v6_wide_28_clamped_to_48_escalation",
                "2600:1f18:2000:abcd::5",
                {"cloud_cidr": "2600:1f10::/28", "cloud_provider": "Amazon AWS"},
                False,
                "2600:1f18:2000:abcd::/64",
                "2600:1f18:2000::/48",
            ),
            (
                "cloud_v6_56_preserved_in_bounds",
                "2600:1f18:2000:abcd::5",
                {"cloud_cidr": "2600:1f18:2000:ab00::/56", "cloud_provider": "Amazon AWS"},
                False,
                "2600:1f18:2000:abcd::/64",
                "2600:1f18:2000:ab00::/56",
            ),
            (
                "cloud_v6_narrow_96_clamps_escalation_to_64",
                "2600:1f18:2000:abcd::5",
                {"cloud_cidr": "2600:1f18:2000:abcd::/96", "cloud_provider": "Amazon AWS"},
                False,
                "2600:1f18:2000:abcd::/96",
                "2600:1f18:2000:abcd::/64",
            ),
        )
        for label, ip_str, kwargs, exp_mobile, exp_rec, exp_esc in attribution_cases:
            with self.subTest(cidr_case=label):
                out = cidr_attribution.compute_cidr_attribution(ip_str, **kwargs)
                self.assertEqual(out["isMobileOrCgnat"], exp_mobile)
                self.assertEqual(out["recommendedCidr"], exp_rec)
                self.assertEqual(out["escalationCidr"], exp_esc)

    def test_residential_signal_paradox_and_seven_day_recheck_boundary_matrix(self) -> None:
        now_dt = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
        recent_iso = (now_dt - timedelta(days=3)).isoformat()
        res_pair = [_clean_commercial_row("IPHub", usage="residential"), _clean_commercial_row("IPData", usage="isp")]
        shodan_9050 = adapt_shodan_internetdb({"ports": [9050]}, status_code=200)
        ipsum_high = adapt_ipsum_drop({"ipsumScore": 4, "isIpsumListed": True})
        sfs_recent = adapt_stopforumspam(
            {"success": 1, "ip": {"appears": 1, "frequency": 5, "lastseen": recent_iso}},
            status_code=200,
        )

        recheck_cases = (
            ("paradox_fresh_0s", [*res_pair, shodan_9050], 0, True, False),
            ("paradox_exact_7d_boundary", [*res_pair, shodan_9050], 7 * 86400, True, False),
            ("paradox_over_7d_by_1s", [*res_pair, shodan_9050], 7 * 86400 + 1, True, True),
            ("paradox_ipsum_sfs_at_15d", [*res_pair, ipsum_high, sfs_recent], 15 * 86400, True, True),
            ("clean_residential_at_30d", list(res_pair), 30 * 86400, False, False),
        )
        for label, rows, age_secs, exp_paradox, exp_recheck in recheck_cases:
            with self.subTest(recheck_case=label):
                fetched_iso = (now_dt - timedelta(seconds=age_secs)).isoformat()
                assembled = detection_service._assemble_detection_payload(
                    "94.140.14.14",
                    rows,
                    "cpe-42.dynamic.isp.example",
                    hit_count=len(rows) + 1,
                    miss_count=0,
                    cooldown_count=0,
                    cached_at_timestamps=[fetched_iso],
                    layer="L2" if age_secs > 0 else "upstream",
                    fetched_at_override=fetched_iso,
                    all_from_snapshot=age_secs > 0,
                    now_dt=now_dt,
                )
                self.assertEqual(assembled["suspectedResidentialProxy"], exp_paradox)
                self.assertEqual(assembled["cacheMeta"]["recommendFreshRecheck"], exp_recheck)

    def test_arbitration_weighted_voting_spamhaus_pbl_exclusion_and_shared_privacy_matrix(self) -> None:
        three_clean = [_clean_commercial_row(n) for n in ("IPHub", "IPData", "Proxycheck")]
        two_clean = [_clean_commercial_row(n) for n in ("IPHub", "IPData")]
        one_clean = [_clean_commercial_row("IPHub")]
        one_proxy = [_high_risk_commercial_row("Proxycheck", "Proxy")]
        two_proxy = [_high_risk_commercial_row("Proxycheck", "Proxy"), _high_risk_commercial_row("IPHunter", "VPN")]

        gii_cases = (
            (
                "gii_74_9_zero_weight",
                "0.749",
                three_clean,
                "Clean Residential / Direct (0/4 Sources)",
                "success",
                False,
            ),
            (
                "gii_75_0_half_weight_disputed",
                "0.750",
                three_clean,
                "Disputed Proxy / VPN (0.5/4 Sources)",
                "warning",
                False,
            ),
            (
                "gii_89_9_half_weight_disputed",
                "0.899",
                three_clean,
                "Disputed Proxy / VPN (0.5/4 Sources)",
                "warning",
                False,
            ),
            (
                "gii_half_plus_one_exact_50pct_not_majority",
                "0.80",
                [*one_clean, *one_proxy],
                "Disputed Proxy / VPN (1.5/3 Sources)",
                "warning",
                False,
            ),
            (
                "gii_half_breaks_two_of_four_tie",
                "0.80",
                [*one_clean, *two_proxy],
                "Confirmed Proxy / VPN (2.5/4 Sources)",
                "destructive",
                True,
            ),
            (
                "gii_90_0_full_weight_disputed",
                "0.900",
                three_clean,
                "Disputed Proxy / VPN (1/4 Sources)",
                "warning",
                False,
            ),
            (
                "gii_95_0_full_weight_confirmed",
                "0.950",
                [*one_clean, *two_proxy],
                "Confirmed Proxy / VPN (3/4 Sources)",
                "destructive",
                True,
            ),
        )
        for label, raw_prob, peer_rows, exp_verdict, exp_tier, exp_majority in gii_cases:
            with self.subTest(gii_case=label):
                gii_row = adapt_getipintel({"status": "success", "result": raw_prob}, True, 200)
                agg = views.aggregate_intelligence_metrics("8.8.8.8", [*peer_rows, gii_row])
                self.assertEqual(agg["arbitrationVerdict"], exp_verdict)
                self.assertEqual(agg["arbitrationTier"], exp_tier)
                self.assertEqual(agg["isMajorityProxyVpn"], exp_majority)

        zen_cases = (
            (
                "pbl_10_excluded",
                ["127.0.0.10"],
                three_clean,
                "Clean Residential / Direct (0/3 Sources)",
                "success",
                False,
            ),
            (
                "pbl_11_excluded",
                ["127.0.0.11"],
                three_clean,
                "Clean Residential / Direct (0/3 Sources)",
                "success",
                False,
            ),
            (
                "pbl_both_10_and_11_excluded",
                ["127.0.0.10", "127.0.0.11"],
                three_clean,
                "Clean Residential / Direct (0/3 Sources)",
                "success",
                False,
            ),
            ("sbl_2_corroborates", ["127.0.0.2"], three_clean, "Disputed Proxy / VPN (1/4 Sources)", "warning", False),
            ("css_3_corroborates", ["127.0.0.3"], three_clean, "Disputed Proxy / VPN (1/4 Sources)", "warning", False),
            ("xbl_4_corroborates", ["127.0.0.4"], three_clean, "Disputed Proxy / VPN (1/4 Sources)", "warning", False),
            ("drop_9_corroborates", ["127.0.0.9"], three_clean, "Disputed Proxy / VPN (1/4 Sources)", "warning", False),
            (
                "mixed_xbl_4_and_pbl_10_corroborates_majority",
                ["127.0.0.4", "127.0.0.10"],
                [*two_clean, *two_proxy],
                "Confirmed Proxy / VPN (3/5 Sources)",
                "destructive",
                True,
            ),
        )
        for label, codes, peer_rows, exp_verdict, exp_tier, exp_majority in zen_cases:
            with self.subTest(spamhaus_case=label):
                zen_row = adapt_spamhaus_zen({"status": "listed", "codes": codes}, 200)
                agg = views.aggregate_intelligence_metrics("8.8.8.8", [*peer_rows, zen_row])
                self.assertEqual(agg["arbitrationVerdict"], exp_verdict)
                self.assertEqual(agg["arbitrationTier"], exp_tier)
                self.assertEqual(agg["isMajorityProxyVpn"], exp_majority)

        recent_iso = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        relay_commercial = [
            adapt_ipregistry(
                {"connection": {"type": "hosting", "asn": 13335}, "security": {"is_vpn": True, "is_relay": True}},
                has_api_key=True,
            ),
            adapt_ipdata({"ip": "104.28.1.1", "threat": {"is_icloud_relay": True}}, has_api_key=True),
        ]
        privacy_attack_cases = (
            ("clean_icloud_soft_block", "icloud_private_relay", [], True),
            ("clean_warp_soft_block", "cloudflare_warp", [], True),
            (
                "attacked_by_abuseipdb_25",
                "icloud_private_relay",
                [adapt_abuseipdb({"data": {"abuseConfidenceScore": 25}}, has_api_key=True)],
                False,
            ),
            (
                "attacked_by_spamhaus_sbl",
                "cloudflare_warp",
                [adapt_spamhaus_zen({"status": "listed", "codes": ["127.0.0.2"]}, 200)],
                False,
            ),
            (
                "attacked_by_ipsum_3",
                "icloud_private_relay",
                [adapt_ipsum_drop({"ipsumScore": 3, "isIpsumListed": True})],
                False,
            ),
            (
                "attacked_by_recent_sfs",
                "cloudflare_warp",
                [
                    adapt_stopforumspam(
                        {"success": 1, "ip": {"appears": 1, "frequency": 4, "lastseen": recent_iso}}, 200
                    )
                ],
                False,
            ),
            (
                "attacked_by_recent_dshield",
                "icloud_private_relay",
                [adapt_dshield({"ip": {"attacks": 9, "count": 2, "maxdate": recent_iso[:10]}}, 200)],
                False,
            ),
            (
                "active_tor_overrides_soft_block",
                "cloudflare_warp",
                [
                    adapt_tor_onionoo(
                        {"relays": [{"a": ["104.28.1.1"], "r": True, "flags": ["Exit"]}]}, 200, "104.28.1.1"
                    )
                ],
                False,
            ),
        )
        for label, egress_kind, attack_rows, expect_soft_verdict in privacy_attack_cases:
            with (
                self.subTest(privacy_verdict_case=label),
                patch("detector.cidr_attribution.lookup_privacy_relay_offline", return_value=egress_kind),
            ):
                agg = views.aggregate_intelligence_metrics("104.28.1.1", [*relay_commercial, *attack_rows])
                if expect_soft_verdict:
                    self.assertEqual(
                        agg["arbitrationVerdict"],
                        "Shared Privacy Egress (iCloud Relay / WARP — Soft Block Recommended)",
                    )
                    self.assertEqual(agg["arbitrationTier"], "warning")
                    self.assertFalse(agg["isMajorityProxyVpn"])
                else:
                    self.assertNotEqual(
                        agg["arbitrationVerdict"],
                        "Shared Privacy Egress (iCloud Relay / WARP — Soft Block Recommended)",
                    )

    async def test_admin_dashboard_snapshot_reports_healthy_ipsum_drop_and_x4bnet_binary_indexes(self) -> None:
        fake_redis = _BatchingFakeRedis()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tool_root = Path(tmp_dir) / "tool"
            data_dir = tool_root / "data"
            data_dir.mkdir(parents=True)

            with (
                override_settings(TOOL_DATA_DIR=str(tool_root)),
                patch("detector.cache_backends.redis_client", fake_redis),
            ):
                missing_snap = await quota_telemetry.build_dashboard_snapshot()
                by_key_missing = {p["key"]: p for p in missing_snap["providers"]}
                self.assertEqual(by_key_missing["ipsum_drop"]["statusKey"], "db_missing")
                self.assertEqual(by_key_missing["x4bnet_vpn"]["statusKey"], "db_missing")

                compile_binary_prefix_index([("192.0.2.0/24", 3)], data_dir / "ipsum_drop.bin")
                compile_binary_prefix_index([("185.159.157.0/24", 1)], data_dir / "x4bnet_vpn.bin")
                cidr_attribution.clear_offline_intelligence_caches()

                healthy_snap = await quota_telemetry.build_dashboard_snapshot()
                by_key_healthy = {p["key"]: p for p in healthy_snap["providers"]}
                self.assertEqual(by_key_healthy["ipsum_drop"]["statusKey"], "healthy")
                self.assertEqual(by_key_healthy["ipsum_drop"]["status"], "Healthy")
                self.assertEqual(by_key_healthy["x4bnet_vpn"]["statusKey"], "healthy")
                self.assertEqual(by_key_healthy["x4bnet_vpn"]["status"], "Healthy")


class SharedRedisMultiTenantHmacIsolationMatrixTests(TestCase):
    """Table-driven verification of shared Redis tenant isolation and zero plaintext IP or secret leakage."""

    def setUp(self) -> None:
        detection_service._ip_detect_inflight.clear()
        dns_patcher = patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        )
        dns_patcher.start()
        self.addCleanup(dns_patcher.stop)
        self.addCleanup(detection_service._ip_detect_inflight.clear)

    def test_multi_tenant_redis_prefixes_and_secrets_isolate_all_keys_and_never_leak_plaintext_ips(self) -> None:
        shared_redis = _BatchingFakeRedis()
        stubs = start_non_dnsbl_provider_stubs(
            self,
            overrides={"maxmind": dict(MAXMIND_STUB)},
            row_builder=lambda label: _clean_commercial_row(label),
        )
        patch(
            "detector.dns_providers.query_spamhaus_zen",
            new_callable=AsyncMock,
            return_value=_clean_commercial_row("Spamhaus ZEN"),
        ).start()
        patch(
            "detector.dns_providers.query_spamcop",
            new_callable=AsyncMock,
            return_value=_clean_commercial_row("SpamCop"),
        ).start()
        self.addCleanup(patch.stopall)

        sensitive_ips = (
            "203.0.113.42",
            "94.140.14.14",
            "2606:4700:4700::1111",
            "2606:4700:4700:0000:0000:0000:0000:1111",
        )
        tenants = (
            ("prod_alpha", "proxycheck_prod_", "hmac-secret-alpha-9001", "FallbackKeyOne", "SysopSensitiveOne"),
            ("dev_alpha", "proxycheck_dev_", "hmac-secret-alpha-9001", "FallbackKeyOne", "SysopSensitiveTwo"),
            ("prod_beta", "proxycheck_prod_", "hmac-secret-beta-9002", "FallbackKeyOne", "SysopSensitiveThree"),
            ("stage_fallback", "proxycheck_stage_", "", "FallbackDjangoSecretKey99", "SysopSensitiveFour"),
        )

        keys_by_tenant: Dict[str, Set[str]] = {}
        seen_keys: Set[str] = set()

        for tenant_name, prefix, redis_secret, django_secret, wiki_user in tenants:
            with (
                self.subTest(tenant=tenant_name),
                override_settings(
                    **TEST_UPSTREAM_SECRETS,
                    ENABLE_L2_TOOLSDB_CACHE=False,
                    REDIS_KEY_PREFIX=prefix,
                    REDIS_KEY_SECRET=redis_secret,
                    SECRET_KEY=django_secret,
                ),
                patch.dict(
                    os.environ, {**TEST_UPSTREAM_SECRETS, "REDIS_KEY_PREFIX": prefix, "REDIS_KEY_SECRET": redis_secret}
                ),
                patch("detector.cache_backends.redis_client", shared_redis),
            ):
                token = views.issue_gadget_token(wiki_user)
                headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"}

                before_upstream = stubs["ipdata"].await_count
                v4_miss = self.client.get("/api/v1/detect?ip=94.140.14.14", **headers)
                self.assertEqual(v4_miss.status_code, 200)
                self.assertEqual(v4_miss.json()["cacheMeta"]["layer"], "upstream")
                self.assertEqual(stubs["ipdata"].await_count, before_upstream + 1)

                v4_hit = self.client.get("/api/v1/detect?ip=94.140.14.14", **headers)
                self.assertEqual(v4_hit.json()["cacheMeta"]["layer"], "L1")
                self.assertEqual(stubs["ipdata"].await_count, before_upstream + 1)

                v6_refresh = self.client.post(
                    "/api/v1/detect/refresh",
                    data=json.dumps({"ip": "2606:4700:4700:0000:0000:0000:0000:1111"}),
                    content_type="application/json",
                    **headers,
                )
                self.assertEqual(v6_refresh.status_code, 200)

                lock_tok = asyncio.run(cache_backends.acquire_ip_updating_lock("203.0.113.42"))
                self.assertIsNotNone(lock_tok)
                asyncio.run(cache_backends.set_swr_backoff("203.0.113.42"))

                all_current_keys = set(shared_redis.strings.keys()) | set(shared_redis.hashes.keys())
                tenant_new_keys = all_current_keys - seen_keys
                self.assertGreater(len(tenant_new_keys), 10)
                for prior_tenant, prior_keys in keys_by_tenant.items():
                    self.assertTrue(
                        tenant_new_keys.isdisjoint(prior_keys),
                        f"Tenant {tenant_name} collided with {prior_tenant}",
                    )
                keys_by_tenant[tenant_name] = tenant_new_keys
                seen_keys |= tenant_new_keys

        forbidden_substrings = (
            *sensitive_ips,
            "94.140.14",
            "203.0.113",
            "2606:4700",
            "hmac-secret-alpha-9001",
            "hmac-secret-beta-9002",
            "FallbackDjangoSecretKey99",
            "SysopSensitiveOne",
            "SysopSensitiveTwo",
            "SysopSensitiveThree",
            "SysopSensitiveFour",
            "proxycheck:v1",
        )
        all_redis_keys = (
            set(shared_redis.strings.keys()) | set(shared_redis.hashes.keys()) | set(shared_redis.ttls.keys())
        )
        for redis_key in all_redis_keys:
            for forbidden in forbidden_substrings:
                self.assertNotIn(forbidden, redis_key)
