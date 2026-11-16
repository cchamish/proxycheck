"""Tests for async DNS/DNSBL resolution, OSINT feeds, and Proxycheck extensions."""

import asyncio
import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import dns.exception
import dns.name
import dns.resolver
import dns.reversename
import httpx
from django.test import TestCase, override_settings

from detector import views
from detector.adapters import (
    adapt_dshield,
    adapt_proxycheck,
    adapt_stopforumspam,
    adapt_tor_onionoo,
)

from .helpers import (
    EMPTY_UPSTREAM_SECRETS,
    MAXMIND_STUB,
    TEST_UPSTREAM_SECRETS,
    _login_authorised,
    _mock_a_answer,
    _mock_ptr_answer,
    _mock_response,
    _patch_async_client,
)


class AsyncDnsAndDnsblTests(TestCase):
    """Tests asynchronous PTR lookups and IPv4-only DNSBL integrations via dnspython."""

    def setUp(self):
        _login_authorised(self)

    async def test_async_ptr_success_nxdomain_and_resolver_timeouts(self):
        with override_settings(DNS_QUERY_TIMEOUT_SECONDS=1.5, DNS_QUERY_LIFETIME_SECONDS=3.0):
            resolver = views._create_async_resolver()
            self.assertEqual(resolver.timeout, 1.5)
            self.assertEqual(resolver.lifetime, 3.0)

        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            return_value=_mock_ptr_answer("DNS.GOOGLE."),
        ) as mock_resolve:
            state = {"status": "ok"}
            token = views._rdns_context_state.set(state)
            try:
                v4_host = await views.query_rdns_ptr("8.8.8.8")
                v6_host = await views.query_rdns_ptr("2001:4860:4860::8888")
            finally:
                views._rdns_context_state.reset(token)

        self.assertEqual(v4_host, "dns.google")
        self.assertEqual(v6_host, "dns.google")
        self.assertEqual(state["status"], "ok")
        self.assertEqual(mock_resolve.await_count, 2)
        self.assertEqual(
            mock_resolve.await_args_list[0].args,
            (dns.reversename.from_address("8.8.8.8"), "PTR"),
        )
        self.assertEqual(
            mock_resolve.await_args_list[1].args,
            (dns.reversename.from_address("2001:4860:4860::8888"), "PTR"),
        )

        for label, exc, expected_status in (
            ("nxdomain", dns.resolver.NXDOMAIN(), "nxdomain"),
            ("noanswer", dns.resolver.NoAnswer(), "nxdomain"),
            ("timeout", dns.exception.Timeout("DNS timed out"), "timeout"),
            ("nonameservers", dns.resolver.NoNameservers(), "error"),
        ):
            with self.subTest(case=label):
                err_state = {"status": "ok"}
                token = views._rdns_context_state.set(err_state)
                try:
                    with patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock, side_effect=exc):
                        res = await views.query_rdns_ptr("1.2.3.4")
                finally:
                    views._rdns_context_state.reset(token)
                self.assertIsNone(res)
                self.assertEqual(err_state["status"], expected_status)

    async def test_spamhaus_zen_sbl_css_xbl_pbl_nxdomain_and_query_blocked(self):
        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            return_value=_mock_a_answer("127.0.0.2"),
        ) as mock_resolve:
            sbl_row = await views.query_spamhaus_zen("1.2.3.4")

        mock_resolve.assert_awaited_once_with("4.3.2.1.zen.spamhaus.org", "A")
        self.assertEqual(sbl_row["status"], "200 OK")
        self.assertTrue(sbl_row["isListed"])
        self.assertIn("SBL", sbl_row["usageType"])
        self.assertTrue(any(flag["isHighRisk"] and "SBL" in flag["label"] for flag in sbl_row["securityFlags"]))

        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            return_value=_mock_a_answer("127.0.0.3", "127.0.0.4"),
        ):
            combo_row = await views.query_spamhaus_zen("1.2.3.4")
        self.assertEqual(combo_row["status"], "200 OK")
        self.assertTrue(combo_row["isListed"])
        self.assertIn("CSS", combo_row["usageType"])
        self.assertIn("XBL/CBL", combo_row["usageType"])
        self.assertTrue(any(flag["isHighRisk"] and "CSS" in flag["label"] for flag in combo_row["securityFlags"]))
        self.assertTrue(any(flag["isHighRisk"] and "XBL" in flag["label"] for flag in combo_row["securityFlags"]))

        for pbl_code in ("127.0.0.10", "127.0.0.11"):
            with self.subTest(pbl_code=pbl_code):
                with patch(
                    "dns.asyncresolver.Resolver.resolve",
                    new_callable=AsyncMock,
                    return_value=_mock_a_answer(pbl_code),
                ):
                    pbl_row = await views.query_spamhaus_zen("1.2.3.4")
                self.assertEqual(pbl_row["status"], "200 OK")
                self.assertTrue(pbl_row["isPolicyRange"])
                self.assertIn("Policy/Dynamic ISP Range", pbl_row["usageType"])
                self.assertFalse(any(flag["isHighRisk"] for flag in pbl_row["securityFlags"]))

        for restricted_code in ("127.255.255.254", "127.255.255.255"):
            with self.subTest(restricted_code=restricted_code):
                with patch(
                    "dns.asyncresolver.Resolver.resolve",
                    new_callable=AsyncMock,
                    return_value=_mock_a_answer(restricted_code),
                ):
                    blocked_row = await views.query_spamhaus_zen("1.2.3.4")
                self.assertFalse(blocked_row["isListed"])
                self.assertTrue(blocked_row.get("isQueryRestricted"))
                self.assertEqual(blocked_row["statusCode"], 429)
                self.assertEqual(blocked_row["status"], "429 Query Blocked")
                self.assertIn(restricted_code, blocked_row["usageType"])
                self.assertFalse(any(flag["isHighRisk"] for flag in blocked_row["securityFlags"]))

        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        ):
            clean_row = await views.query_spamhaus_zen("1.2.3.4")
        self.assertEqual(clean_row["status"], "200 OK")
        self.assertFalse(clean_row["isListed"])
        self.assertEqual(clean_row["usageType"], "Clean (Not Listed)")

    async def test_spamcop_listed_and_nxdomain_clean(self):
        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            return_value=_mock_a_answer("127.0.0.2"),
        ) as mock_resolve:
            listed_row = await views.query_spamcop("192.0.2.55")

        mock_resolve.assert_awaited_once_with("55.2.0.192.bl.spamcop.net", "A")
        self.assertEqual(listed_row["status"], "200 OK")
        self.assertTrue(listed_row["isListed"])
        self.assertEqual(listed_row["listedCodes"], ["127.0.0.2"])
        self.assertTrue(any(flag["isHighRisk"] for flag in listed_row["securityFlags"]))

        with patch(
            "dns.asyncresolver.Resolver.resolve",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        ):
            clean_row = await views.query_spamcop("192.0.2.55")
        self.assertEqual(clean_row["status"], "200 OK")
        self.assertFalse(clean_row["isListed"])
        self.assertEqual(clean_row["usageType"], "Clean (Not Listed)")

    def test_ipv6_target_skips_dnsbl_queries_without_dns_requests(self):
        dns_queries = []

        async def _record_dns(qname, rdtype="A", *_args, **_kwargs):
            dns_queries.append((str(qname), str(rdtype)))
            raise dns.resolver.NXDOMAIN()

        with (
            patch("detector.views.redis_client", None),
            patch("detector.views.query_maxmind", AsyncMock(return_value=dict(MAXMIND_STUB))),
            patch("detector.views.httpx.AsyncClient") as mock_async_client_cls,
            patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock, side_effect=_record_dns),
        ):
            _patch_async_client(
                mock_async_client_cls,
                AsyncMock(return_value=_mock_response(status_code=200, json_value={"status": "ok"})),
            )
            with override_settings(**EMPTY_UPSTREAM_SECRETS), patch.dict(os.environ, EMPTY_UPSTREAM_SECRETS):
                resp = self.client.get("/api/v1/detect?ip=2001:4860:4860::8888")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(dns_queries), 1)
        self.assertEqual(dns_queries[0][1], "PTR")
        self.assertTrue(dns_queries[0][0].endswith("ip6.arpa."))

        rows_by_provider = {row["provider"]: row for row in resp.json()["results"]}
        for dnsbl_name in ("Spamhaus ZEN", "SpamCop"):
            self.assertEqual(rows_by_provider[dnsbl_name]["status"], "Skipped (IPv6)")
            self.assertIsNone(rows_by_provider[dnsbl_name]["statusCode"])
            self.assertTrue(rows_by_provider[dnsbl_name].get("isSkippedIpv6"))
            self.assertIn("IPv6", rows_by_provider[dnsbl_name]["usageType"])

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
    def test_detect_endpoint_preserves_commercial_arbitration_and_handles_spamhaus_block(
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
        def _clean_commercial(name):
            return {
                "provider": name,
                "status": "200 OK",
                "statusCode": 200,
                "asn": "AS15169",
                "isp": "Example Residential ISP",
                "organisation": "Example Residential ISP",
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
        ):
            m.return_value = _clean_commercial(name)
        mock_tor.return_value = adapt_tor_onionoo({"relays": []}, 200, "1.2.3.4")
        mock_sfs.return_value = adapt_stopforumspam(
            {"success": 1, "ip": {"appears": 0, "frequency": 0, "confidence": 0.0}}, 200
        )
        mock_dshield.return_value = adapt_dshield({"ip": {"attacks": 0, "count": 0}}, 200)
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

        async def _listed_dns_side_effect(qname, rdtype="A", *_args, **_kwargs):
            qtext = str(qname)
            if str(rdtype).upper() == "PTR":
                raise dns.resolver.NXDOMAIN()
            if qtext == "4.3.2.1.zen.spamhaus.org":
                return _mock_a_answer("127.0.0.2")
            if qtext == "4.3.2.1.bl.spamcop.net":
                return _mock_a_answer("127.0.0.2")
            raise dns.resolver.NXDOMAIN()

        with (
            patch("detector.views.redis_client", mock_redis),
            patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock, side_effect=_listed_dns_side_effect),
        ):
            resp = self.client.get("/api/v1/detect?ip=1.2.3.4")

        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["arbitrationVerdict"], "Clean Residential / Direct (0/8 Sources)")
        self.assertEqual(payload["arbitrationTier"], "success")

        rows = {row["provider"]: row for row in payload["results"]}
        self.assertTrue(rows["Spamhaus ZEN"]["isListed"])
        self.assertIn("SBL (127.0.0.2)", rows["Spamhaus ZEN"]["usageType"])
        self.assertTrue(rows["SpamCop"]["isListed"])

        self.assertEqual(written_ttls.get("proxycheck:v1:prov:spamhaus_zen:1.2.3.4"), 7200)
        self.assertEqual(written_ttls.get("proxycheck:v1:prov:spamcop:1.2.3.4"), 7200)

        cache_store.clear()
        written_ttls.clear()

        async def _blocked_spamhaus_side_effect(qname, rdtype="A", *_args, **_kwargs):
            qtext = str(qname)
            if str(rdtype).upper() == "PTR":
                raise dns.resolver.NXDOMAIN()
            if qtext == "5.6.7.8.zen.spamhaus.org":
                return _mock_a_answer("127.255.255.254")
            raise dns.resolver.NXDOMAIN()

        with (
            patch("detector.views.redis_client", mock_redis),
            patch(
                "dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock, side_effect=_blocked_spamhaus_side_effect
            ),
        ):
            blocked_resp = self.client.get("/api/v1/detect?ip=8.7.6.5")

        self.assertEqual(blocked_resp.status_code, 200)
        blocked_rows = {row["provider"]: row for row in blocked_resp.json()["results"]}
        self.assertEqual(blocked_rows["Spamhaus ZEN"]["status"], "429 Query Blocked")
        self.assertFalse(blocked_rows["Spamhaus ZEN"]["isListed"])
        self.assertNotIn("proxycheck:v1:prov:spamhaus_zen:8.7.6.5", cache_store)
        self.assertEqual(written_ttls.get("proxycheck:v1:cooldown:spamhaus_zen"), 120)
        self.assertEqual(written_ttls.get("proxycheck:v1:prov:spamcop:8.7.6.5"), 7200)

_MIXED_OSINT_STATIC_RESPONSES = (
    (
        "stopforumspam.org",
        {
            "success": 1,
            "ip": {"appears": 1, "frequency": 25, "confidence": 96.5, "lastseen": "2026-11-12 09:00:00"},
        },
    ),
    (
        "sans.edu",
        {
            "ip": {
                "attacks": 80,
                "count": 12,
                "maxdate": "2026-11-12",
                "threatfeeds": ["scanner"],
                "ascountry": "DE",
            }
        },
    ),
    (
        "dshield",
        {
            "ip": {
                "attacks": 80,
                "count": 12,
                "maxdate": "2026-11-12",
                "threatfeeds": ["scanner"],
                "ascountry": "DE",
            }
        },
    ),
    (
        "ipregistry.co",
        {
            "company": {"name": "Example Residential ISP"},
            "connection": {"asn": 3320, "type": "isp"},
            "location": {"country": {"name": "United States", "code": "US"}},
            "security": {},
        },
    ),
    (
        "ip2location.io",
        {
            "asn": "3320",
            "as": "Example Residential ISP",
            "country_name": "United States",
            "country_code": "US",
        },
    ),
    (
        "ipdata.co",
        {
            "asn": {"asn": "AS3320", "name": "Example Residential ISP", "type": "isp"},
            "country_name": "United States",
            "country_code": "US",
            "threat": {},
        },
    ),
    (
        "abuseipdb.com",
        {"data": {"isp": "Example Residential ISP", "countryCode": "US", "abuseConfidenceScore": 0}},
    ),
    ("getipintel.net", {"status": "success", "result": "0.0"}),
    (
        "iphub.info",
        {"asn": 3320, "isp": "Example Residential ISP", "countryName": "United States", "countryCode": "US", "block": 0},
    ),
    (
        "iphunter.info",
        {
            "status": "success",
            "data": {
                "isp": "Example Residential ISP",
                "country_name": "United States",
                "country_code": "US",
                "block": 0,
            },
        },
    ),
)


def _build_mixed_osint_responder(tor_active_mode):
    async def _respond(url, **kwargs):
        if "onionoo.torproject.org" in url:
            if tor_active_mode["enabled"]:
                return _mock_response(
                    status_code=200,
                    json_value={
                        "relays": [
                            {
                                "a": ["185.220.101.9"],
                                "exit_addresses": ["185.220.101.9"],
                                "r": True,
                                "flags": ["Exit", "Fast", "Running"],
                            }
                        ]
                    },
                )
            return _mock_response(status_code=200, json_value={"relays": []})
        if "proxycheck.io" in url:
            ip_part = urlparse(url).path.rsplit("/", 1)[-1]
            return _mock_response(
                status_code=200,
                json_value={
                    "status": "ok",
                    ip_part: {
                        "asn": "AS3320",
                        "provider": "Example Residential ISP",
                        "country": "United States",
                        "isocode": "US",
                        "type": "Residential",
                        "port": 9050,
                        "last_seen_human": "1 hour ago",
                    },
                },
            )
        for fragment, payload in _MIXED_OSINT_STATIC_RESPONSES:
            if fragment in url:
                return _mock_response(status_code=200, json_value=payload)
        return _mock_response(
            status_code=200,
            json_value={
                "success": True,
                "result": {
                    "location": {"countryName": "United States", "countryCode": "US"},
                    "asn": {"asn": 3320, "name": "Example Residential ISP"},
                },
            },
        )

    return _respond


class OsintFeedsAndProxycheckExtensionsTests(TestCase):
    """Tests for Proxycheck extended parameters, Tor Onionoo, StopForumSpam, and DShield feeds."""

    def setUp(self):
        _login_authorised(self)

    def test_query_proxycheck_attaches_extended_flags_and_extracts_port_and_last_seen(self):
        captured = {}

        async def _get(url, **kwargs):
            captured["url"] = url
            return _mock_response(
                status_code=200,
                json_value={
                    "status": "ok",
                    "198.51.100.20": {
                        "network": {"asn": "14061", "provider": "DigitalOcean", "type": "Hosting"},
                        "location": {"country_name": "United States", "country_code": "US"},
                        "detections": {"proxy": True, "vpn": False, "tor": False, "hosting": True, "risk": 82},
                        "port": 1080,
                        "last_seen_human": "2 hours ago",
                    },
                },
            )

        client = AsyncMock()
        client.get.side_effect = _get

        with override_settings(**TEST_UPSTREAM_SECRETS), patch.dict(os.environ, TEST_UPSTREAM_SECRETS):
            result = asyncio.run(views.query_proxycheck(client, "198.51.100.20"))

        parsed = urlparse(captured["url"])
        qs = parse_qs(parsed.query)
        self.assertEqual(qs.get("vpn"), ["1"])
        self.assertEqual(qs.get("port"), ["1"])
        self.assertEqual(qs.get("seen"), ["1"])
        self.assertEqual(qs.get("risk"), ["1"])
        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(result["port"], 1080)
        self.assertEqual(result["lastSeen"], "2 hours ago")
        self.assertEqual(result["riskScore"], 82)

        unix_adapted = adapt_proxycheck(
            {
                "status": "ok",
                "198.51.100.21": {
                    "type": "Proxy",
                    "proxy": "yes",
                    "detections": {"port": "9050"},
                    "seen": 1700000000,
                },
            },
            True,
            200,
            "198.51.100.21",
        )
        self.assertEqual(unix_adapted["port"], 9050)
        self.assertEqual(unix_adapted["lastSeen"], "2023-11-14T22:13:20+00:00")

    def test_tor_onionoo_adapter_verifies_exact_ip_and_role_flags(self):
        exit_res = adapt_tor_onionoo(
            {
                "relays": [
                    {
                        "a": ["185.220.101.4", "[2a0b:f4c2:2::4]:9001"],
                        "exit_addresses": ["185.220.101.4"],
                        "r": True,
                        "flags": ["Exit", "Fast", "Running", "Valid"],
                    }
                ]
            },
            status_code=200,
            ip="185.220.101.4",
        )
        self.assertTrue(exit_res["isTor"])
        self.assertTrue(exit_res["torIsExit"])
        self.assertTrue(exit_res["torRunning"])
        self.assertEqual(exit_res["torLabel"], "Tor Exit")
        self.assertTrue(any(flag["isHighRisk"] for flag in exit_res["securityFlags"]))
        self.assertIn("Exit", exit_res["torFlags"])

        guard_v6 = adapt_tor_onionoo(
            {
                "relays": [
                    {
                        "or_addresses": ["[2a0b:f4c2:0002::4]:9001"],
                        "running": True,
                        "flags": ["Guard", "Running"],
                    }
                ]
            },
            status_code=200,
            ip="2a0b:f4c2:2::4",
        )
        self.assertTrue(guard_v6["isTor"])
        self.assertFalse(guard_v6["torIsExit"])
        self.assertTrue(guard_v6["torRunning"])
        self.assertEqual(guard_v6["torLabel"], "Tor Guard")

        prefix_miss = adapt_tor_onionoo(
            {
                "relays": [
                    {"a": ["185.220.101.99"], "r": True, "flags": ["Exit"]},
                ]
            },
            status_code=200,
            ip="185.220.101.4",
        )
        self.assertFalse(prefix_miss["isTor"])

        offline_relay = adapt_tor_onionoo(
            {
                "relays": [
                    {"a": ["185.220.101.4"], "r": False, "flags": ["Exit", "Stable"]},
                ]
            },
            status_code=200,
            ip="185.220.101.4",
        )
        self.assertFalse(offline_relay["isTor"])
        self.assertFalse(offline_relay["torRunning"])

        inferred_offline = adapt_tor_onionoo(
            {
                "relays": [
                    {"a": ["185.220.101.4"], "flags": ["Exit", "Stable"]},
                ]
            },
            status_code=200,
            ip="185.220.101.4",
        )
        self.assertFalse(inferred_offline["isTor"])
        self.assertFalse(inferred_offline["torRunning"])

        inferred_running = adapt_tor_onionoo(
            {
                "relays": [
                    {"a": ["185.220.101.4"], "flags": ["Exit", "Running"]},
                ]
            },
            status_code=200,
            ip="185.220.101.4",
        )
        self.assertTrue(inferred_running["isTor"])
        self.assertTrue(inferred_running["torRunning"])

        empty_relays = adapt_tor_onionoo({"relays": []}, status_code=200, ip="8.8.8.8")
        self.assertFalse(empty_relays["isTor"])
        self.assertEqual(empty_relays["usageType"], "Not a Tor Node")

        captured = {}

        async def _get(url, **kwargs):
            captured["url"] = url
            return _mock_response(status_code=200, json_value={"relays": []})

        client = AsyncMock()
        client.get.side_effect = _get
        queried = asyncio.run(views.query_tor_onionoo(client, "8.8.8.8"))
        self.assertEqual(captured["url"], "https://onionoo.torproject.org/summary?search=8.8.8.8")
        self.assertFalse(queried["isTor"])

    def test_stopforumspam_adapter_and_query_extract_reputation_metrics(self):
        listed = adapt_stopforumspam(
            {
                "success": 1,
                "ip": {
                    "appears": 1,
                    "frequency": 14,
                    "confidence": 92.4,
                    "lastseen": "2026-11-10 12:00:00",
                },
            },
            status_code=200,
        )
        self.assertEqual(listed["status"], "200 OK")
        self.assertTrue(listed["appears"])
        self.assertEqual(listed["frequency"], 14)
        self.assertEqual(listed["confidence"], 92.4)
        self.assertEqual(listed["lastSeen"], "2026-11-10 12:00:00")
        self.assertIsNone(listed.get("countryCode"))

        clean = adapt_stopforumspam(
            {"success": 1, "ip": {"appears": 0, "frequency": 0, "confidence": 0.0}},
            status_code=200,
        )
        self.assertFalse(clean["appears"])
        self.assertEqual(clean["frequency"], 0)

        api_err = adapt_stopforumspam({"success": 0, "error": "rate limit"}, status_code=200)
        self.assertEqual(api_err["status"], "400 Error")

        from detector import offline_dbs

        with tempfile.TemporaryDirectory() as tmp_dir:
            toxic_file = Path(tmp_dir) / "toxic_ip_cidr.txt"
            toxic_file.write_text("198.51.100.0/24\n", encoding="utf-8")
            offline_dbs.clear_stopforumspam_caches()
            with override_settings(STOPFORUMSPAM_DB_DIR=tmp_dir):
                hit_row = asyncio.run(views.query_stopforumspam(None, "198.51.100.5"))
                clean_row = asyncio.run(views.query_stopforumspam(None, "203.0.113.5"))
            offline_dbs.clear_stopforumspam_caches()

        self.assertEqual(hit_row["status"], "200 OK")
        self.assertTrue(hit_row["blacklisted"])
        self.assertTrue(hit_row["appears"])
        self.assertEqual(hit_row["toxicCidr"], "198.51.100.0/24")
        self.assertEqual(clean_row["status"], "200 OK")
        self.assertFalse(clean_row["appears"])

        with tempfile.TemporaryDirectory() as empty_dir:
            offline_dbs.clear_stopforumspam_caches()
            with override_settings(STOPFORUMSPAM_DB_DIR=empty_dir):
                missing_row = asyncio.run(views.query_stopforumspam(None, "198.51.100.5"))
            offline_dbs.clear_stopforumspam_caches()
        self.assertEqual(missing_row["status"], "Offline DB Missing")
        self.assertIsNone(missing_row["statusCode"])

    def test_dshield_adapter_and_query_extract_attack_and_threatfeed_metrics(self):
        listed = adapt_dshield(
            {
                "ip": {
                    "attacks": 42,
                    "count": 7,
                    "maxdate": "2026-11-11",
                    "threatfeeds": {"scanner": {"lastseen": "2026-11-12"}, "sshbruteforce": {}},
                    "as": 14061,
                    "asname": "DigitalOcean",
                    "ascountry": "US",
                }
            },
            status_code=200,
        )
        self.assertEqual(listed["status"], "200 OK")
        self.assertEqual(listed["attacks"], 42)
        self.assertEqual(listed["count"], 7)
        self.assertEqual(listed["maxDate"], "2026-11-11")
        self.assertEqual(listed["lastSeen"], "2026-11-11")
        self.assertIn("scanner", listed["threatfeeds"])
        self.assertIn("sshbruteforce", listed["threatfeeds"])
        self.assertEqual(listed["asn"], "AS14061")
        self.assertIsNone(listed.get("countryCode"))

        clean = adapt_dshield({"ip": {"attacks": 0, "count": 0, "threatfeeds": []}}, status_code=200)
        self.assertEqual(clean["usageType"], "Clean (No Activity)")

        null_metrics = adapt_dshield(
            {"ip": {"number": "198.51.100.5", "count": None, "attacks": None, "maxrisk": None}},
            status_code=200,
        )
        self.assertEqual(null_metrics["status"], "200 OK")
        self.assertEqual(null_metrics["attacks"], 0)
        self.assertEqual(null_metrics["count"], 0)
        self.assertEqual(null_metrics["usageType"], "Clean (No Activity)")

        captured = {}

        async def _get(url, **kwargs):
            captured["url"] = url
            captured["headers"] = kwargs.get("headers") or {}
            captured["follow_redirects"] = kwargs.get("follow_redirects")
            captured["timeout"] = kwargs.get("timeout")
            return _mock_response(status_code=200, json_value={"ip": {"attacks": 0, "count": 0}})

        client = AsyncMock()
        client.get.side_effect = _get
        asyncio.run(views.query_dshield(client, "198.51.100.5"))
        self.assertEqual(captured["url"], "https://isc.sans.edu/api/ip/198.51.100.5?json")
        self.assertIn("ProxyCheck", captured["headers"].get("User-Agent", ""))
        self.assertTrue(captured["follow_redirects"])
        self.assertEqual(captured["timeout"], 10.0)

    def test_dshield_retries_fallback_and_isolates_follow_redirects(self):
        # Verify the shared HTTP client and unrelated providers keep redirects disabled by default
        shared_client = asyncio.run(views._get_shared_http_client())
        self.assertFalse(shared_client.follow_redirects)

        default_capture = {}

        async def _default_get(url, **kwargs):
            default_capture["follow_redirects"] = kwargs.get("follow_redirects")
            default_capture["has_timeout_kwarg"] = "timeout" in kwargs
            default_capture["timeout"] = kwargs.get("timeout")
            return _mock_response(status_code=200, json_value={"relays": []})

        default_client = AsyncMock()
        default_client.get.side_effect = _default_get
        asyncio.run(views.query_tor_onionoo(default_client, "198.51.100.5"))
        self.assertFalse(default_capture["follow_redirects"])
        self.assertTrue(default_capture["has_timeout_kwarg"])
        self.assertEqual(default_capture["timeout"], 5.0)

        # Calling _fetch_upstream_json without timeout lets the client default timeout apply
        asyncio.run(
            views._fetch_upstream_json(
                default_client,
                "dshield",
                "DShield",
                "https://isc.sans.edu/api/ip/198.51.100.5?json",
            )
        )
        self.assertFalse(default_capture["has_timeout_kwarg"])

        # Passing an explicit httpx.Timeout overrides the client default timeout
        custom_timeout = httpx.Timeout(12.0)
        asyncio.run(
            views._fetch_upstream_json(
                default_client,
                "dshield",
                "DShield",
                "https://isc.sans.edu/api/ip/198.51.100.5?json",
                timeout=custom_timeout,
            )
        )
        self.assertTrue(default_capture["has_timeout_kwarg"])
        self.assertIs(default_capture["timeout"], custom_timeout)

        failure_modes = (
            ("network_error", httpx.ConnectError("connection reset")),
            ("http_503", _mock_response(status_code=503, text="<html>Service Unavailable</html>")),
            ("http_504", _mock_response(status_code=504, text="<html>Gateway Timeout</html>")),
            (
                "non_json_200",
                _mock_response(
                    status_code=200,
                    json_error=json.JSONDecodeError("Expecting value", "<html>proxy error</html>", 0),
                    text="<html>proxy error</html>",
                ),
            ),
        )
        for label, primary_outcome in failure_modes:
            with self.subTest(case=label):
                if not isinstance(primary_outcome, Exception):
                    primary_outcome.headers = {"Content-Type": "text/html"}
                attempted = []
                upstream_events = {}
                token = views._provider_upstream_events.set(upstream_events)

                async def _fallback_get(url, outcome=primary_outcome, captured_urls=attempted, **kwargs):
                    captured_urls.append((url, kwargs.get("follow_redirects"), kwargs.get("timeout")))
                    if "isc.sans.edu" in url:
                        if isinstance(outcome, Exception):
                            raise outcome
                        return outcome
                    return _mock_response(status_code=200, json_value={"ip": {"attacks": 3, "count": 1}})

                fallback_client = AsyncMock()
                fallback_client.get.side_effect = _fallback_get
                try:
                    with self.assertLogs("detector.views", level="WARNING") as captured_logs:
                        result = asyncio.run(views.query_dshield(fallback_client, "198.51.100.5"))
                finally:
                    views._provider_upstream_events.reset(token)

                self.assertEqual(result["status"], "200 OK")
                self.assertEqual(result["attacks"], 3)
                self.assertEqual(
                    attempted,
                    [
                        ("https://isc.sans.edu/api/ip/198.51.100.5?json", True, 10.0),
                        ("https://www.dshield.org/api/ip/198.51.100.5?json", True, 10.0),
                    ],
                )
                self.assertFalse(upstream_events["dshield"]["trigger"])
                self.assertTrue(any("retrying fallback endpoint" in line for line in captured_logs.output))

        # When both endpoints fail with gateway errors, DShield still degrades cleanly to 502 Error
        both_bad_client = AsyncMock()

        async def _both_bad(url, **kwargs):
            resp = _mock_response(
                status_code=200,
                json_error=json.JSONDecodeError("Expecting value", "<xml/>", 0),
                text="<xml>error</xml>",
            )
            resp.headers = {"Content-Type": "application/xml"}
            return resp

        both_bad_client.get.side_effect = _both_bad
        with self.assertLogs("detector.views", level="WARNING"):
            failed_result = asyncio.run(views.query_dshield(both_bad_client, "198.51.100.5"))
        self.assertEqual(failed_result["status"], "502 Error")

    def test_dshield_skips_fallback_on_timeout_slow_failure_or_non_gateway_status(self):
        # ReadTimeout on the primary endpoint must return immediately without hitting the fallback host
        timeout_urls = []
        upstream_events = {}
        token = views._provider_upstream_events.set(upstream_events)

        async def _timeout_get(url, **kwargs):
            timeout_urls.append((url, kwargs.get("timeout")))
            raise httpx.ReadTimeout("timed out after 10s")

        timeout_client = AsyncMock()
        timeout_client.get.side_effect = _timeout_get
        try:
            with self.assertLogs("detector.views", level="ERROR"):
                timeout_result = asyncio.run(views.query_dshield(timeout_client, "198.51.100.5"))
        finally:
            views._provider_upstream_events.reset(token)

        self.assertEqual(timeout_result["status"], "502 Error")
        self.assertEqual(timeout_urls, [("https://isc.sans.edu/api/ip/198.51.100.5?json", 10.0)])
        self.assertTrue(upstream_events["dshield"]["isTimeout"])

        # A primary error arriving after 5 seconds must also skip fallback to avoid doubling latency
        slow_error_urls = []

        async def _slow_error_get(url, **kwargs):
            slow_error_urls.append((url, kwargs.get("timeout")))
            return _mock_response(status_code=503, text="Slow gateway error")

        slow_error_client = AsyncMock()
        slow_error_client.get.side_effect = _slow_error_get
        with (
            patch.object(views, "time", SimpleNamespace(monotonic=MagicMock(side_effect=[100.0, 105.31]))),
            self.assertLogs("detector.views", level="WARNING"),
        ):
            slow_error_result = asyncio.run(views.query_dshield(slow_error_client, "198.51.100.5"))

        self.assertEqual(slow_error_result["status"], "503 Error")
        self.assertEqual(slow_error_urls, [("https://isc.sans.edu/api/ip/198.51.100.5?json", 10.0)])

        # A primary 200 response arriving after 5.31 seconds succeeds cleanly under the 10s budget
        slow_ok_urls = []

        async def _slow_ok_get(url, **kwargs):
            slow_ok_urls.append((url, kwargs.get("timeout")))
            return _mock_response(status_code=200, json_value={"ip": {"attacks": 0, "count": 0}})

        slow_ok_client = AsyncMock()
        slow_ok_client.get.side_effect = _slow_ok_get
        with patch.object(views, "time", SimpleNamespace(monotonic=MagicMock(side_effect=[200.0, 205.31]))):
            slow_ok_result = asyncio.run(views.query_dshield(slow_ok_client, "198.51.100.5"))

        self.assertEqual(slow_ok_result["status"], "200 OK")
        self.assertEqual(slow_ok_urls, [("https://isc.sans.edu/api/ip/198.51.100.5?json", 10.0)])

        # Non-gateway statuses such as HTTP 500 or HTTP 429 do not trigger fallback
        for status in (500, 429):
            with self.subTest(status=status):
                attempted = []

                async def _status_get(url, code=status, seen=attempted, **kwargs):
                    seen.append(url)
                    return _mock_response(status_code=code, text="error")

                status_client = AsyncMock()
                status_client.get.side_effect = _status_get
                with self.assertLogs("detector.views", level="WARNING"):
                    res = asyncio.run(views.query_dshield(status_client, "198.51.100.5"))
                self.assertEqual(len(attempted), 1)
                self.assertEqual(res["statusCode"], status)

    @patch(
        "dns.asyncresolver.Resolver.resolve",
        new_callable=AsyncMock,
        side_effect=dns.resolver.NXDOMAIN(),
    )
    @patch("detector.views.query_maxmind", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
    def test_detect_endpoint_excludes_tor_from_comparison_and_preserves_commercial_verdict_over_osint_hits(
        self, mock_async_client_cls, mock_mm, _mock_dns
    ):
        mock_mm.return_value = dict(MAXMIND_STUB)
        tor_active_mode = {"enabled": False}

        _patch_async_client(mock_async_client_cls, _build_mixed_osint_responder(tor_active_mode))

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

        from detector import offline_dbs

        with tempfile.TemporaryDirectory() as sfs_tmp_dir:
            (Path(sfs_tmp_dir) / "listed_ip_90_ipv46_all.txt").write_text(
                '"185.220.101.4","25","2026-11-12 09:00:00"\n',
                encoding="utf-8",
            )
            offline_dbs.clear_stopforumspam_caches()

            with (
                override_settings(**{**TEST_UPSTREAM_SECRETS, "STOPFORUMSPAM_DB_DIR": sfs_tmp_dir}),
                patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
                patch("detector.views.redis_client", mock_redis),
            ):
                resp = self.client.get("/api/v1/detect?ip=185.220.101.4")

            self.assertEqual(resp.status_code, 200)
            payload = resp.json()
            self.assertFalse(payload["isTor"])
            self.assertFalse(payload["is_broadcast_ip"])
            self.assertFalse(payload["isMajorityProxyVpn"])
            self.assertEqual(payload["arbitrationVerdict"], "Clean Residential / Direct (0/8 Sources)")
            self.assertEqual(payload["arbitrationTier"], "success")

            rows = {row["provider"]: row for row in payload["results"]}
            self.assertNotIn("Tor Onionoo", rows)
            self.assertEqual(rows["Proxycheck"]["port"], 9050)
            self.assertEqual(rows["Proxycheck"]["lastSeen"], "1 hour ago")
            self.assertEqual(rows["StopForumSpam"]["frequency"], 25)
            self.assertEqual(rows["StopForumSpam"]["lastSeen"], "2026-11-12 09:00:00")
            self.assertEqual(rows["DShield"]["attacks"], 80)
            self.assertEqual(rows["DShield"]["threatfeeds"], ["scanner"])
            self.assertEqual(written_ttls.get("proxycheck:v1:prov:tor_onionoo:185.220.101.4"), 7200)
            self.assertEqual(written_ttls.get("proxycheck:v1:prov:stopforumspam:185.220.101.4"), 7200)
            self.assertEqual(written_ttls.get("proxycheck:v1:prov:dshield:185.220.101.4"), 7200)

            tor_active_mode["enabled"] = True
            with (
                override_settings(**{**TEST_UPSTREAM_SECRETS, "STOPFORUMSPAM_DB_DIR": sfs_tmp_dir}),
                patch.dict(os.environ, TEST_UPSTREAM_SECRETS),
                patch("detector.views.redis_client", mock_redis),
            ):
                tor_resp = self.client.get("/api/v1/detect?ip=185.220.101.9")
            offline_dbs.clear_stopforumspam_caches()

        self.assertEqual(tor_resp.status_code, 200)
        tor_payload = tor_resp.json()
        self.assertTrue(tor_payload["isTor"])
        self.assertTrue(tor_payload["torIsExit"])
        self.assertTrue(tor_payload["torRunning"])
        self.assertEqual(tor_payload["torLabel"], "Tor Exit")
        self.assertIn("Exit", tor_payload["torFlags"])
        self.assertEqual(tor_payload["arbitrationTier"], "destructive")
        self.assertIn("Tor Exit", tor_payload["arbitrationVerdict"])
        self.assertNotIn("Tor Onionoo", {row["provider"] for row in tor_payload["results"]})
