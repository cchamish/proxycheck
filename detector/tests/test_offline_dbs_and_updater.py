"""Tests for offline MaxMind/StopForumSpam engines, cloud CIDR matching, and DB updates."""

import asyncio
import json
import os
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from django.test import SimpleTestCase, TestCase, override_settings

from detector import views
from detector.adapters import (
    adapt_abuseipdb,
    adapt_ipdata,
    adapt_ipregistry,
    adapt_maxmind,
    clear_offline_intelligence_caches,
    compute_cidr_attribution,
    match_cloud_cidr,
    match_hosting_asn_or_org,
)

from .helpers import (
    _login_authorised,
)


class OfflineHostingAndCloudIntelligenceTests(SimpleTestCase):
    """Tests for offline hosting ASN rules, cloud CIDR matching, and GeoLite2 enrichment."""

    def setUp(self):
        clear_offline_intelligence_caches()
        self.addCleanup(clear_offline_intelligence_caches)

    def test_builtin_hosting_asn_fallback_and_non_hosting_exclusions(self):
        with override_settings(
            HOSTING_ASN_RULES_PATH="",
            HOSTING_ASNS=(),
            HOSTING_ORG_KEYWORDS=(),
        ):
            for asn in (14061, "AS24940", 16276, 20473, 63949):
                hit = match_hosting_asn_or_org(asn, "Some Organization")
                self.assertIsNotNone(hit)
                self.assertEqual(hit["matchedBy"], "asn")

            kw_hit = match_hosting_asn_or_org(None, "Hetzner Online GmbH")
            self.assertIsNotNone(kw_hit)
            self.assertEqual(kw_hit["matchedBy"], "keyword")

            # Non-hosting ISPs and CDN names without hosting keywords should remain unflagged
            self.assertIsNone(match_hosting_asn_or_org(1221, "Telstra Corporation Ltd"))
            self.assertIsNone(match_hosting_asn_or_org(13335, "Cloudflare, Inc."))

    def test_custom_hosting_asn_rules_json_and_settings_override(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_file = Path(tmpdir) / "hosting_asn_rules.json"
            rules_file.write_text(
                json.dumps(
                    {
                        "hosts": [
                            {"name": "Example Cloud Host", "asn": 64510, "keywords": ["ExampleHost"]},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with override_settings(
                HOSTING_ASN_RULES_PATH=str(rules_file),
                HOSTING_ASNS=("64512",),
                HOSTING_ORG_KEYWORDS=("CustomRack",),
            ):
                json_hit = match_hosting_asn_or_org("AS64510", "Unlisted")
                self.assertEqual(json_hit, {"provider": "Example Cloud Host", "matchedBy": "asn"})

                env_asn_hit = match_hosting_asn_or_org(64512, "Unlisted")
                self.assertEqual(env_asn_hit, {"provider": "AS64512", "matchedBy": "asn"})

                env_kw_hit = match_hosting_asn_or_org(None, "CustomRack Infrastructure LLC")
                self.assertEqual(env_kw_hit, {"provider": "CustomRack", "matchedBy": "keyword"})

                # Word boundaries prevent partial substring false positives
                self.assertIsNone(match_hosting_asn_or_org(None, "MyExampleHostCompany"))

    def test_cloud_cidr_matching_formats_narrowest_prefix_and_ipv6(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            list_tool = root / "list_tool"
            (list_tool / "data").mkdir(parents=True)
            (list_tool / "data" / "computehosts.json").write_text(
                json.dumps(
                    [
                        {"range": "52.94.236.0/24", "provider": "aws"},
                        {"range": "52.94.236.64/26", "provider": "Amazon AWS"},
                        {"range": "2600:1f18:2000::/48", "provider": "aws"},
                    ]
                ),
                encoding="utf-8",
            )
            with override_settings(TOOL_DATA_DIR=str(list_tool)):
                narrow_hit = match_cloud_cidr("52.94.236.70")
                self.assertEqual(
                    narrow_hit,
                    {"cidr": "52.94.236.64/26", "prefixLength": 26, "provider": "Amazon AWS"},
                )
                v6_hit = match_cloud_cidr("2600:1f18:2000:1::1")
                self.assertEqual(
                    v6_hit,
                    {"cidr": "2600:1f18:2000::/48", "prefixLength": 48, "provider": "Amazon AWS"},
                )
                mapped_v4_hit = match_cloud_cidr("::ffff:52.94.236.70")
                self.assertEqual(
                    mapped_v4_hit,
                    {"cidr": "52.94.236.64/26", "prefixLength": 26, "provider": "Amazon AWS"},
                )
                self.assertIsNone(match_cloud_cidr("8.8.8.8"))

            clear_offline_intelligence_caches()
            aws_tool = root / "aws_tool"
            (aws_tool / "data").mkdir(parents=True)
            (aws_tool / "data" / "cloud_cidrs.json").write_text(
                json.dumps(
                    {
                        "prefixes": [{"ip_prefix": "3.5.140.0/22", "service": "AMAZON"}],
                        "ipv6_prefixes": [{"ipv6_prefix": "2a05:d014::/40", "service": "EC2"}],
                    }
                ),
                encoding="utf-8",
            )
            with override_settings(TOOL_DATA_DIR=str(aws_tool)):
                self.assertEqual(match_cloud_cidr("3.5.140.5")["provider"], "Amazon AWS")
                self.assertEqual(match_cloud_cidr("2a05:d014:1::5")["cidr"], "2a05:d014::/40")

            clear_offline_intelligence_caches()
            dict_tool = root / "dict_tool"
            (dict_tool / "data").mkdir(parents=True)
            (dict_tool / "data" / "cloud_cidrs.json").write_text(
                json.dumps({"gcp": ["34.64.0.0/16"], "azure": ["20.48.0.0/16"]}),
                encoding="utf-8",
            )
            with override_settings(TOOL_DATA_DIR=str(dict_tool)):
                self.assertEqual(match_cloud_cidr("34.64.1.2")["provider"], "Google Cloud")
                self.assertEqual(match_cloud_cidr("20.48.1.2")["provider"], "Microsoft Azure")

            clear_offline_intelligence_caches()
            broken_tool = root / "broken_tool"
            (broken_tool / "data").mkdir(parents=True)
            (broken_tool / "data" / "cloud_cidrs.json").write_text("{not-valid-json", encoding="utf-8")
            with override_settings(TOOL_DATA_DIR=str(broken_tool)):
                self.assertIsNone(match_cloud_cidr("34.64.1.2"))

            missing_tool = root / "missing_tool"
            missing_tool.mkdir()
            with override_settings(TOOL_DATA_DIR=str(missing_tool)):
                self.assertIsNone(match_cloud_cidr("34.64.1.2"))

    def test_cloud_cidr_cache_reloads_when_file_mtime_changes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir) / "data"
            data_dir.mkdir()
            cidr_file = data_dir / "cloud_cidrs.json"
            cidr_file.write_text(json.dumps({"gcp": ["34.64.0.0/16"]}), encoding="utf-8")
            with override_settings(TOOL_DATA_DIR=tmpdir):
                self.assertIsNone(match_cloud_cidr("20.48.1.2"))

                cidr_file.write_text(json.dumps({"azure": ["20.48.0.0/16"]}), encoding="utf-8")
                stat = cidr_file.stat()
                os.utime(cidr_file, ns=(stat.st_atime_ns, stat.st_mtime_ns + 2_000_000_000))

                reloaded = match_cloud_cidr("20.48.1.2")
                self.assertIsNotNone(reloaded)
                self.assertEqual(reloaded["provider"], "Microsoft Azure")

    def test_maxmind_geolite2_enrichment_preserves_explicit_geoip2_user_type(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir) / "data"
            data_dir.mkdir()
            cidr_file = data_dir / "cloud_cidrs.json"
            cidr_file.write_text(
                json.dumps([{"range": "54.239.28.64/26", "provider": "Amazon AWS"}]),
                encoding="utf-8",
            )
            with override_settings(
                TOOL_DATA_DIR=tmpdir,
                HOSTING_ASN_RULES_PATH="",
                HOSTING_ASNS=(),
                HOSTING_ORG_KEYWORDS=(),
            ):
                cloud_enriched = adapt_maxmind(
                    {
                        "autonomous_system_number": 16509,
                        "autonomous_system_organization": "Amazon.com, Inc.",
                        "country": {"names": {"en": "United States"}, "iso_code": "US"},
                        "_mmdb_prefix_len": 24,
                        "_ip": "54.239.28.85",
                    },
                    has_db=True,
                    ip="54.239.28.85",
                )
                self.assertEqual(cloud_enriched["usageType"], "hosting")
                self.assertEqual(cloud_enriched["cloudProvider"], "Amazon AWS")
                self.assertEqual(cloud_enriched["cloudCidr"], "54.239.28.64/26")
                self.assertEqual(cloud_enriched["cloudPrefixLength"], 26)
                self.assertEqual(cloud_enriched["hostingProvider"], "Amazon AWS")
                self.assertIn({"label": "Hosting", "isHighRisk": True}, cloud_enriched["securityFlags"])
                self.assertNotIn("_ip", cloud_enriched["rawJson"])
                self.assertNotIn("_mmdb_prefix_len", cloud_enriched["rawJson"])

                # Paid GeoIP2 user_type takes priority over offline hosting fallback
                explicit_geoip2 = adapt_maxmind(
                    {
                        "autonomous_system_number": 14061,
                        "autonomous_system_organization": "DigitalOcean, LLC",
                        "traits": {"user_type": "residential"},
                    },
                    has_db=True,
                    ip="159.89.10.1",
                )
                self.assertEqual(explicit_geoip2["usageType"], "residential")
                self.assertEqual(explicit_geoip2["securityFlags"], [{"label": "No Flags", "isHighRisk": False}])

    def test_compute_cidr_attribution_uses_cloud_prefix_rules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir) / "data"
            data_dir.mkdir()
            cidr_file = data_dir / "cloud_cidrs.json"
            cidr_file.write_text(
                json.dumps(
                    {
                        "Amazon AWS": ["54.239.28.64/26", "2600:1f18:2000::/80"],
                        "Google Cloud": ["34.64.0.0/16"],
                    }
                ),
                encoding="utf-8",
            )
            with override_settings(TOOL_DATA_DIR=tmpdir):
                narrow_v4 = compute_cidr_attribution("54.239.28.85")
                self.assertEqual(narrow_v4["recommendedCidr"], "54.239.28.64/26")
                self.assertEqual(narrow_v4["defaultCidr"], "54.239.28.0/24")
                self.assertEqual(narrow_v4["cloudCidr"], "54.239.28.64/26")
                self.assertEqual(narrow_v4["cloudProvider"], "Amazon AWS")

                narrow_v6 = compute_cidr_attribution("2600:1f18:2000::5")
                self.assertEqual(narrow_v6["recommendedCidr"], "2600:1f18:2000::/80")
                self.assertEqual(narrow_v6["defaultCidr"], "2600:1f18:2000::/64")
                self.assertEqual(narrow_v6["cloudCidr"], "2600:1f18:2000::/80")

                wide_v4 = compute_cidr_attribution("34.64.12.34")
                self.assertEqual(wide_v4["recommendedCidr"], "34.64.12.0/24")
                self.assertEqual(wide_v4["cloudCidr"], "34.64.0.0/16")
                self.assertEqual(wide_v4["cloudProvider"], "Google Cloud")

                mmdb_wins = compute_cidr_attribution("54.239.28.85", mmdb_prefix_len=27)
                self.assertEqual(mmdb_wins["recommendedCidr"], "54.239.28.64/27")
                self.assertEqual(mmdb_wins["cloudCidr"], "54.239.28.64/26")

    def test_views_read_maxmind_sync_and_aggregate_intelligence_integration(self):
        views._maxmind_readers.clear()
        self.addCleanup(views._maxmind_readers.clear)
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir) / "data"
            data_dir.mkdir()
            cidr_file = data_dir / "cloud_cidrs.json"
            cidr_file.write_text(
                json.dumps([{"range": "54.239.28.64/26", "provider": "Amazon AWS"}]),
                encoding="utf-8",
            )
            country_db = data_dir / "GeoLite2-Country.mmdb"
            asn_db = data_dir / "GeoLite2-ASN.mmdb"
            country_db.write_bytes(b"stub")
            asn_db.write_bytes(b"stub")

            country_rec = {"country": {"names": {"en": "United States"}, "iso_code": "US"}}
            asn_rec = {
                "autonomous_system_number": 16509,
                "autonomous_system_organization": "Amazon.com, Inc.",
            }
            fake_country_reader = MagicMock()
            fake_country_reader.get.return_value = country_rec
            fake_country_reader.get_with_prefix_len.return_value = (country_rec, 16)

            fake_asn_reader = MagicMock()
            fake_asn_reader.get.return_value = asn_rec
            fake_asn_reader.get_with_prefix_len.return_value = (asn_rec, 24)

            fake_maxmind_module = MagicMock()
            fake_maxmind_module.open_database.side_effect = lambda db_path: (
                fake_country_reader if "country" in str(db_path).lower() else fake_asn_reader
            )

            with (
                override_settings(
                    TOOL_DATA_DIR=str(tmpdir),
                    HOSTING_ASN_RULES_PATH="",
                    HOSTING_ASNS=(),
                    HOSTING_ORG_KEYWORDS=(),
                ),
                patch.dict("sys.modules", {"maxminddb": fake_maxmind_module}),
            ):
                maxmind_row = views._read_maxmind_sync("54.239.28.85")
                self.assertEqual(maxmind_row["usageType"], "hosting")
                self.assertEqual(maxmind_row["cloudCidr"], "54.239.28.64/26")
                self.assertEqual(maxmind_row["cloudProvider"], "Amazon AWS")

                relay_row = adapt_ipregistry(
                    {
                        "connection": {"type": "hosting", "asn": 16509, "organization": "Amazon.com, Inc."},
                        "security": {"is_relay": True},
                    },
                    has_api_key=True,
                )
                aggregated = views.aggregate_intelligence_metrics("54.239.28.85", [maxmind_row, relay_row])
                self.assertEqual(aggregated["recommendedCidr"], "54.239.28.64/26")
                self.assertEqual(aggregated["cloudCidr"], "54.239.28.64/26")
                self.assertEqual(aggregated["cloudProvider"], "Amazon AWS")
                self.assertIn("Amazon AWS cloud prefix /26", aggregated["cidrNote"])
                self.assertEqual(aggregated["arbitrationVerdict"], "Confirmed Proxy / VPN (1/1 Sources)")
                self.assertEqual(aggregated["arbitrationTier"], "destructive")

        non_public = views._build_non_public_response_payload("127.0.0.1", "loopback", "Loopback IP", time.monotonic())
        self.assertIsNone(non_public["cloudCidr"])
        self.assertIsNone(non_public["cloudProvider"])

    def _query_mmdb_dir(
        self,
        ip: str,
        db_records: dict[str, tuple[dict, int | None]],
    ) -> dict:
        """Creates stub MMDB files in one TOOL_DATA_DIR/data directory and runs _read_maxmind_sync."""
        views._maxmind_readers.clear()
        self.addCleanup(views._maxmind_readers.clear)
        filename_map = {
            "country": "GeoLite2-Country.mmdb",
            "city": "GeoLite2-City.mmdb",
            "asn": "GeoLite2-ASN.mmdb",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir) / "data"
            data_dir.mkdir()
            readers_by_path: dict[str, MagicMock] = {}
            for role, (rec, prefix_len) in db_records.items():
                db_path = data_dir / filename_map[role]
                db_path.write_bytes(b"stub")
                reader = MagicMock()
                reader.get.return_value = rec
                if prefix_len is not None:
                    reader.get_with_prefix_len.return_value = (rec, prefix_len)
                readers_by_path[str(db_path)] = reader

            fake_maxmind_module = MagicMock()
            fake_maxmind_module.open_database.side_effect = lambda path: readers_by_path[str(path)]

            with (
                override_settings(
                    TOOL_DATA_DIR=str(tmpdir),
                    HOSTING_ASN_RULES_PATH="",
                    HOSTING_ASNS=(),
                    HOSTING_ORG_KEYWORDS=(),
                ),
                patch.dict("sys.modules", {"maxminddb": fake_maxmind_module}),
            ):
                return views._read_maxmind_sync(ip)

    def test_adapt_maxmind_city_subdivision_coordinates_and_deduplication(self):
        us_row = adapt_maxmind(
            {
                "country": {"names": {"en": "United States"}, "iso_code": "US"},
                "subdivisions": [{"names": {"en": "California"}, "iso_code": "CA"}],
                "city": {"names": {"en": "Mountain View"}},
                "location": {"latitude": 37.386, "longitude": -122.0838},
                "autonomous_system_number": 15169,
                "autonomous_system_organization": "Google LLC",
            },
            has_db=True,
        )
        self.assertEqual(us_row["location"], "Mountain View, California, United States (37.386, -122.0838)")
        self.assertEqual(us_row["coordinates"], "37.386, -122.0838")
        self.assertEqual(us_row["countryCode"], "US")

        # Duplicate city and subdivision names should collapse cleanly
        tokyo_row = adapt_maxmind(
            {
                "country": {"names": {"en": "Japan"}, "iso_code": "JP"},
                "subdivisions": [{"names": {"en": "Tokyo"}, "iso_code": "13"}],
                "city": {"names": {"en": "Tokyo"}},
                "location": {"latitude": 35.6895, "longitude": 139.6917},
            },
            has_db=True,
        )
        self.assertEqual(tokyo_row["location"], "Tokyo, Japan (35.6895, 139.6917)")

        # Corrupted subdivisions or missing names still preserve valid country output
        fallback_row = adapt_maxmind(
            {
                "country": {"names": {"en": "Singapore"}, "iso_code": "SG"},
                "subdivisions": "corrupted",
                "city": {"names": {"en": "Singapore"}},
            },
            has_db=True,
        )
        self.assertEqual(fallback_row["location"], "Singapore")

        localized_row = adapt_maxmind(
            {
                "country": {"names": {"zh-CN": "中国"}, "iso_code": "CN"},
                "subdivisions": [{"names": {"zh-CN": "北京"}, "iso_code": "BJ"}],
                "city": {"names": {"zh-CN": "北京"}},
                "location": {"latitude": 39.9075, "longitude": 116.3971},
            },
            has_db=True,
        )
        self.assertEqual(localized_row["location"], "北京, 中国 (39.9075, 116.3971)")
        self.assertEqual(localized_row["coordinates"], "39.9075, 116.3971")
        self.assertEqual(localized_row["countryCode"], "CN")

    def test_three_mmdb_collaboration_preserves_country_iso_and_city_fallback_coords(self):
        # Country DB remains authoritative on iso_code even when City DB omits or differs on country
        maxmind_row = self._query_mmdb_dir(
            "8.8.8.8",
            {
                "country": ({"country": {"names": {"en": "United States"}, "iso_code": "US"}}, 16),
                "city": (
                    {
                        "country": {"names": {"en": "United States"}, "iso_code": "CA"},
                        "subdivisions": [{"names": {"en": "Virginia"}, "iso_code": "VA"}],
                        "city": {"names": {"en": "Ashburn"}},
                        "location": {"latitude": 39.0438, "longitude": -77.4874},
                    },
                    27,
                ),
                "asn": (
                    {
                        "autonomous_system_number": 15169,
                        "autonomous_system_organization": "Google LLC",
                    },
                    24,
                ),
            },
        )
        self.assertEqual(maxmind_row["countryCode"], "US")
        self.assertEqual(maxmind_row["location"], "Ashburn, Virginia, United States (39.0438, -77.4874)")
        self.assertEqual(maxmind_row["coordinates"], "39.0438, -77.4874")
        # ASN routing prefix takes precedence over City and Country prefixes
        self.assertEqual(maxmind_row["prefixLength"], 24)

        consistent_ipdata = adapt_ipdata(
            {"country_code": "US", "country_name": "United States", "city": "Ashburn", "region": "Virginia"},
            has_api_key=True,
        )
        consistent_agg = views.aggregate_intelligence_metrics("8.8.8.8", [consistent_ipdata, maxmind_row])
        self.assertFalse(consistent_agg["is_broadcast_ip"])
        self.assertEqual(consistent_agg["primaryCoordinates"], "39.0438, -77.4874")

        conflicting_abuseipdb = adapt_abuseipdb(
            {"data": {"countryName": "Germany", "countryCode": "DE", "abuseConfidenceScore": 0}},
            has_api_key=True,
        )
        broadcast_agg = views.aggregate_intelligence_metrics("8.8.8.8", [conflicting_abuseipdb, maxmind_row])
        self.assertTrue(broadcast_agg["is_broadcast_ip"])
        self.assertEqual(broadcast_agg["primaryCoordinates"], "39.0438, -77.4874")

    def test_maxmind_db_dir_partial_databases_and_explicit_missing_dir(self):
        # City and ASN without Country DB still supply country, city, subdivision, and coordinates
        city_only_country_row = self._query_mmdb_dir(
            "1.1.1.1",
            {
                "city": (
                    {
                        "country": {"names": {"en": "Australia"}, "iso_code": "AU"},
                        "subdivisions": [{"names": {"en": "New South Wales"}, "iso_code": "NSW"}],
                        "city": {"names": {"en": "Sydney"}},
                        "location": {"latitude": -33.8688, "longitude": 151.2093},
                    },
                    25,
                ),
                "asn": (
                    {
                        "autonomous_system_number": 13335,
                        "autonomous_system_organization": "Cloudflare, Inc.",
                    },
                    None,
                ),
            },
        )
        self.assertEqual(city_only_country_row["countryCode"], "AU")
        self.assertEqual(city_only_country_row["location"], "Sydney, New South Wales, Australia (-33.8688, 151.2093)")
        self.assertEqual(city_only_country_row["prefixLength"], 25)

        # Explicit TOOL_DATA_DIR does not fall back to unrelated data directories
        with tempfile.TemporaryDirectory() as tmpdir:
            unrelated_home = Path(tmpdir) / "home"
            fallback_data = unrelated_home / "data"
            fallback_data.mkdir(parents=True)
            (fallback_data / "GeoLite2-Country.mmdb").write_bytes(b"stub")
            empty_tool = Path(tmpdir) / "empty_tool"
            (empty_tool / "data").mkdir(parents=True)

            with (
                override_settings(TOOL_DATA_DIR=str(empty_tool)),
                patch("pathlib.Path.home", return_value=unrelated_home),
            ):
                missing_row = views._read_maxmind_sync("1.1.1.1")
            self.assertEqual(missing_row["status"], "Database Missing")

    def test_maxmind_resolver_expands_env_nested_subdirs_and_reloads_updated_file(self):
        from proxycheck.settings import resolve_mmdb_file

        views._maxmind_readers.clear()
        views._maxmind_reader_stats.clear()
        self.addCleanup(views._maxmind_readers.clear)
        self.addCleanup(views._maxmind_reader_stats.clear)

        with tempfile.TemporaryDirectory() as tmpdir:
            tool_root = Path(tmpdir) / "tool"
            flat_data_dir = tool_root / "data"
            nested_city_dir = flat_data_dir / "GeoLite2-City_20261114"
            nested_city_dir.mkdir(parents=True)
            country_file = flat_data_dir / "GeoLite2-Country.mmdb"
            city_file = nested_city_dir / "GeoLite2-City.mmdb"
            country_file.write_bytes(b"country-v1")
            city_file.write_bytes(b"city-v1")

            with patch.dict(os.environ, {"TOOL_DATA_DIR": str(tool_root)}):
                self.assertEqual(
                    resolve_mmdb_file("$TOOL_DATA_DIR/data", "GeoLite2-City.mmdb", tmpdir),
                    str(city_file),
                )
                self.assertEqual(
                    resolve_mmdb_file("", "GeoLite2-Country.mmdb", tmpdir),
                    str(country_file),
                )
                self.assertEqual(
                    resolve_mmdb_file("", "GeoLite2-City.mmdb", tmpdir),
                    str(city_file),
                )

            country_reader = MagicMock()
            country_reader.get.return_value = {
                "country": {"names": {"en": "China"}, "iso_code": "CN"},
            }
            city_v1_reader = MagicMock()
            city_v1_reader.get.return_value = {
                "country": {"names": {"en": "China"}, "iso_code": "CN"},
            }
            city_v2_reader = MagicMock()
            city_v2_reader.get.return_value = {
                "country": {"names": {"en": "China"}, "iso_code": "CN"},
                "subdivisions": [{"names": {"en": "Beijing"}, "iso_code": "BJ"}],
                "city": {"names": {"en": "Beijing"}},
                "location": {"latitude": 39.9075, "longitude": 116.3971},
            }
            country_open_paths = []
            city_open_paths = []

            def _open_sequence(path):
                path_str = str(path)
                if "city" in Path(path_str).name.lower():
                    reader = city_v1_reader if not city_open_paths else city_v2_reader
                    city_open_paths.append(path_str)
                    return reader
                country_open_paths.append(path_str)
                return country_reader

            fake_maxmind_module = MagicMock()
            fake_maxmind_module.open_database.side_effect = _open_sequence

            with (
                override_settings(
                    TOOL_DATA_DIR=str(tool_root),
                    HOSTING_ASN_RULES_PATH="",
                ),
                patch.dict("sys.modules", {"maxminddb": fake_maxmind_module}),
            ):
                row_before_update = views._read_maxmind_sync("1.2.3.4")
                self.assertEqual(row_before_update["location"], "China")

                # Replace the file on disk with a different size so the cached reader reopens cleanly
                city_file.write_bytes(b"city-v2-updated-bytes")
                row_after_update = views._read_maxmind_sync("1.2.3.4")
                self.assertEqual(row_after_update["location"], "Beijing, China (39.9075, 116.3971)")
                self.assertEqual(row_after_update["coordinates"], "39.9075, 116.3971")
                self.assertEqual(len(country_open_paths), 1)
                self.assertEqual(len(city_open_paths), 2)
                city_v1_reader.close.assert_called_once()

    @patch("dns.asyncresolver.Resolver.resolve", new_callable=AsyncMock)
    @patch("detector.views.httpx.AsyncClient")
    def test_stale_pre_city_maxmind_cache_refreshes_when_city_db_exists(self, mock_async_client_cls, mock_dns_resolve):
        views._maxmind_readers.clear()
        views._maxmind_reader_stats.clear()
        self.addCleanup(views._maxmind_readers.clear)
        self.addCleanup(views._maxmind_reader_stats.clear)

        target_ip = "1.2.3.4"
        cache_store = {}
        for provider_key, provider_name, _uses_http, _cooldown, _fn in views._PROVIDER_SPECS:
            row_payload = {
                "provider": provider_name,
                "status": "200 OK",
                "statusCode": 200,
                "asn": "AS137718",
                "isp": "Beijing Volcano Engine",
                "organisation": "Beijing Volcano Engine",
                "location": "China",
                "usageType": "isp",
                "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
                "countryCode": "CN",
                "rawJson": {"country": {"iso_code": "CN"}},
            }
            cache_store[f"proxycheck:v1:prov:{provider_key}:{target_ip}"] = json.dumps(
                {"row": row_payload, "cachedAt": "2026-11-14T08:00:00+00:00"}
            )
        cache_store[f"proxycheck:v1:prov:ptr:{target_ip}"] = json.dumps(
            {"hostname": "example.net", "status": "ok", "cachedAt": "2026-11-14T08:00:00+00:00"}
        )

        async def _fake_redis_set(key, value, ex=None):
            cache_store[key] = value

        mock_redis = MagicMock()
        mock_redis.get = AsyncMock(side_effect=lambda k: cache_store.get(k))
        mock_redis.set = AsyncMock(side_effect=_fake_redis_set)
        _login_authorised(self)

        with tempfile.TemporaryDirectory() as tmpdir:
            mmdb_dir = Path(tmpdir) / "data"
            mmdb_dir.mkdir()
            for fname in ("GeoLite2-Country.mmdb", "GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb"):
                (mmdb_dir / fname).write_bytes(b"stub")

            readers_by_path = {}
            country_reader = MagicMock()
            country_reader.get.return_value = {"country": {"names": {"en": "China"}, "iso_code": "CN"}}
            city_reader = MagicMock()
            city_reader.get.return_value = {
                "country": {"names": {"en": "China"}, "iso_code": "CN"},
                "subdivisions": [{"names": {"en": "Beijing"}, "iso_code": "BJ"}],
                "city": {"names": {"en": "Beijing"}},
                "location": {"latitude": 39.9075, "longitude": 116.3971},
            }
            asn_reader = MagicMock()
            asn_reader.get.return_value = {
                "autonomous_system_number": 137718,
                "autonomous_system_organization": "Beijing Volcano Engine",
            }
            readers_by_path[str(mmdb_dir / "GeoLite2-Country.mmdb")] = country_reader
            readers_by_path[str(mmdb_dir / "GeoLite2-City.mmdb")] = city_reader
            readers_by_path[str(mmdb_dir / "GeoLite2-ASN.mmdb")] = asn_reader

            fake_maxmind_module = MagicMock()
            fake_maxmind_module.open_database.side_effect = lambda p: readers_by_path[str(p)]

            with (
                override_settings(
                    TOOL_DATA_DIR=str(tmpdir),
                    HOSTING_ASN_RULES_PATH="",
                ),
                patch.dict("sys.modules", {"maxminddb": fake_maxmind_module}),
                patch("detector.views.redis_client", mock_redis),
            ):
                first_resp = self.client.get(f"/api/v1/detect?ip={target_ip}")
                second_resp = self.client.get(f"/api/v1/detect?ip={target_ip}")

        self.assertEqual(first_resp.status_code, 200)
        first_payload = first_resp.json()
        first_mm = next(r for r in first_payload["results"] if r["provider"] == "MaxMind")
        self.assertEqual(first_mm["location"], "Beijing, China (39.9075, 116.3971)")
        self.assertEqual(first_mm["coordinates"], "39.9075, 116.3971")
        self.assertEqual(first_payload["cacheMeta"]["hitCount"], 15)

        cached_mm_wrapper = json.loads(cache_store[f"proxycheck:v1:prov:maxmind:{target_ip}"])
        self.assertTrue(cached_mm_wrapper["cityDbLoaded"])

        self.assertEqual(second_resp.status_code, 200)
        second_payload = second_resp.json()
        second_mm = next(r for r in second_payload["results"] if r["provider"] == "MaxMind")
        self.assertEqual(second_mm["location"], "Beijing, China (39.9075, 116.3971)")
        self.assertEqual(second_payload["cacheMeta"]["hitCount"], 16)
        self.assertEqual(city_reader.get.call_count, 1)
        mock_async_client_cls.assert_not_called()
        mock_dns_resolve.assert_not_called()

    def test_execute_detection_with_cache_warms_offline_rules_off_event_loop(self):
        from detector import adapters as detector_adapters

        clear_offline_intelligence_caches()
        target_ip = "54.239.28.85"
        is_ipv4 = True
        cached_providers = {}
        for provider_key, provider_name, _uses_http, _cooldown, _fn in views._PROVIDER_SPECS:
            if not views._is_provider_cache_expected(provider_key, is_ipv4):
                continue
            cached_providers[provider_key] = (
                {
                    "provider": provider_name,
                    "status": "200 OK",
                    "statusCode": 200,
                    "asn": "AS16509",
                    "isp": "Amazon.com, Inc.",
                    "organisation": "Amazon.com, Inc.",
                    "location": "United States",
                    "usageType": "hosting",
                    "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
                    "countryCode": "US",
                    "rawJson": {},
                },
                "2026-11-16T00:00:00+00:00",
            )
        initial_cache = (cached_providers, (None, "2026-11-16T00:00:00+00:00"))

        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir) / "data"
            data_dir.mkdir()
            cidr_file = data_dir / "cloud_cidrs.json"
            cidr_file.write_text(json.dumps([{"range": "54.239.28.64/26", "provider": "Amazon AWS"}]), encoding="utf-8")
            rules_file = data_dir / "hosting_asn_rules.json"
            rules_file.write_text(json.dumps({"hosts": []}), encoding="utf-8")

            original_warm = detector_adapters.warm_offline_intelligence_caches
            warm_threads = []
            event_loop_thread_id = None

            def _tracked_warm():
                warm_threads.append(threading.get_ident())
                return original_warm()

            async def _run():
                nonlocal event_loop_thread_id
                event_loop_thread_id = threading.get_ident()
                first_payload = await views._execute_detection_with_cache(
                    target_ip,
                    initial_cache=initial_cache,
                )
                second_payload = await views._execute_detection_with_cache(
                    target_ip,
                    initial_cache=initial_cache,
                )
                return first_payload, second_payload

            with (
                override_settings(
                    TOOL_DATA_DIR=str(tmpdir),
                    HOSTING_ASN_RULES_PATH=str(rules_file),
                    HOSTING_ASNS=(),
                    HOSTING_ORG_KEYWORDS=(),
                ),
                patch("detector.views.redis_client", None),
                patch("detector.views.warm_offline_intelligence_caches", side_effect=_tracked_warm),
            ):
                first_payload, second_payload = asyncio.run(_run())

        self.assertEqual(len(warm_threads), 1)
        self.assertNotEqual(warm_threads[0], event_loop_thread_id)
        self.assertTrue(detector_adapters.are_offline_intelligence_caches_warm())
        self.assertEqual(first_payload["cloudCidr"], "54.239.28.64/26")
        self.assertEqual(first_payload["cloudProvider"], "Amazon AWS")
        self.assertEqual(second_payload["cloudCidr"], "54.239.28.64/26")


class OfflineStopForumSpamEngineTests(TestCase):
    """Tests local StopForumSpam lookups, mtime hot-reloading, and graceful degradation."""

    def setUp(self):
        super().setUp()
        from detector import offline_dbs

        offline_dbs.clear_stopforumspam_caches()

    def tearDown(self):
        from detector import offline_dbs

        offline_dbs.clear_stopforumspam_caches()
        super().tearDown()

    def test_toxic_cidr_and_zip_gz_listed_ips_query_without_http(self):
        import gzip
        import zipfile

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "data"
            root.mkdir()
            (root / "toxic_ip_cidr.txt").write_text(
                "# Comment line\n192.0.2.0/24\n2001:db8:dead::/48\n",
                encoding="utf-8",
            )
            zip_90_path = root / "listed_ip_90_ipv46_all.zip"
            with zipfile.ZipFile(zip_90_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(
                    "listed_ip_90_ipv46_all.txt",
                    '"198.51.100.42","12","2026-11-10 08:30:00"\n"192.0.2.77","3","2026-11-09 02:00:00"\n',
                )

            gz_1_path = root / "listed_ip_1_ipv46_all.txt.gz"
            with gzip.open(gz_1_path, "wt", encoding="utf-8") as gz_handle:
                gz_handle.write('"198.51.100.42","18","2026-11-16 05:15:00"\n')
                gz_handle.write('"2001:0db8:cafe:0000:0000:0000:0000:0001","9","2026-11-16 04:00:00"\n')

            with (
                override_settings(TOOL_DATA_DIR=tmp_dir),
                patch("detector.views.httpx.AsyncClient") as mock_client,
            ):
                toxic_row = asyncio.run(views.query_stopforumspam("192.0.2.77"))
                toxic_v6_row = asyncio.run(views.query_stopforumspam("2001:db8:dead::5"))
                merged_row = asyncio.run(views.query_stopforumspam("198.51.100.42"))
                canonical_v6_row = asyncio.run(views.query_stopforumspam("2001:db8:cafe::1"))
                clean_row = asyncio.run(views.query_stopforumspam("203.0.113.99"))

            mock_client.assert_not_called()

        self.assertEqual(toxic_row["status"], "200 OK")
        self.assertTrue(toxic_row["blacklisted"])
        self.assertTrue(toxic_row["appears"])
        self.assertEqual(toxic_row["toxicCidr"], "192.0.2.0/24")
        self.assertEqual(toxic_row["frequency"], 3)
        self.assertTrue(toxic_row.get("offlineDbUpdatedAt"))

        self.assertTrue(toxic_v6_row["blacklisted"])
        self.assertEqual(toxic_v6_row["toxicCidr"], "2001:db8:dead::/48")

        self.assertFalse(merged_row["blacklisted"])
        self.assertTrue(merged_row["appears"])
        self.assertEqual(merged_row["frequency"], 18)
        self.assertEqual(merged_row["lastSeen"], "2026-11-16 05:15:00")
        self.assertEqual(merged_row["rawJson"]["ip"]["sources"], ["listed_ip_90", "listed_ip_1"])

        self.assertTrue(canonical_v6_row["appears"])
        self.assertEqual(canonical_v6_row["frequency"], 9)

        self.assertFalse(clean_row["appears"])
        self.assertFalse(clean_row["blacklisted"])
        self.assertEqual(clean_row["usageType"], "Clean (Not Listed)")

    def test_hot_reloads_when_files_change_mtime_and_invalidates_redis_cache(self):
        from detector import offline_dbs

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "data"
            root.mkdir()
            toxic_path = root / "toxic_ip_cidr.txt"
            listed_path = root / "listed_ip_90_ipv46_all.txt"

            toxic_path.write_text("192.0.2.0/24\n", encoding="utf-8")
            listed_path.write_text('"198.51.100.7","5","2026-11-10 00:00:00"\n', encoding="utf-8")

            cache_store = {}

            async def _fake_get(key):
                return cache_store.get(key)

            async def _fake_set(key, val, ex=None):
                cache_store[key] = val

            mock_redis = MagicMock()
            mock_redis.get = AsyncMock(side_effect=_fake_get)
            mock_redis.set = AsyncMock(side_effect=_fake_set)

            with (
                override_settings(TOOL_DATA_DIR=tmp_dir),
                patch("detector.views.redis_client", mock_redis),
            ):
                initial_lookup = offline_dbs.query_stopforumspam_offline("198.51.100.88")
                self.assertFalse(initial_lookup["appears"])

                first_row = asyncio.run(views.query_stopforumspam("198.51.100.88"))
                cache_key = views._provider_cache_key("stopforumspam", "198.51.100.88")
                cache_store[cache_key] = json.dumps(
                    {
                        "row": first_row,
                        "cachedAt": "2026-11-16T00:00:00+00:00",
                        "sanitized": True,
                        "dbVersion": offline_dbs.get_stopforumspam_db_version(),
                    }
                )

                cached_hit, _ = asyncio.run(views._read_provider_caches("198.51.100.88"))
                self.assertIn("stopforumspam", cached_hit)

                # Advance timestamps beyond integer second boundaries so file mtime visibly changes
                listed_path.write_text(
                    '"198.51.100.7","5","2026-11-10 00:00:00"\n"198.51.100.88","42","2026-11-16 12:00:00"\n',
                    encoding="utf-8",
                )
                future_ts = time.time() + 10.0
                os.utime(listed_path, (future_ts, future_ts))

                reloaded_lookup = offline_dbs.query_stopforumspam_offline("198.51.100.88")
                cached_after_update, _ = asyncio.run(views._read_provider_caches("198.51.100.88"))

            self.assertTrue(reloaded_lookup["appears"])
            self.assertEqual(reloaded_lookup["frequency"], 42)
            self.assertNotIn("stopforumspam", cached_after_update)


class _FakeStreamResp:
    def __init__(self, content: bytes, status_code: int = 200):
        self._content = content
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=MagicMock(), response=MagicMock())

    def iter_bytes(self, chunk_size=65536):
        yield self._content

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakeTextResp:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=MagicMock(), response=MagicMock())


def _build_update_test_archives():
    import hashlib
    import io
    import tarfile
    import zipfile

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("listed_ip_90_ipv46_all.txt", '"198.51.100.12","7","2026-11-16 01:00:00"\n')
    good_zip_bytes = zip_buf.getvalue()

    zip_1_buf = io.BytesIO()
    with zipfile.ZipFile(zip_1_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("listed_ip_1_ipv46_all.txt", '"198.51.100.13","3","2026-11-16 02:00:00"\n')
    good_zip_1_bytes = zip_1_buf.getvalue()

    old_zip_buf = io.BytesIO()
    with zipfile.ZipFile(old_zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("listed_ip_90_ipv46_all.txt", '"198.51.100.1","1","2026-11-01 00:00:00"\n')

    tar_buf = io.BytesIO()
    mmdb_bytes = b"MMDB-VALID-HEADER-STUB"
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="GeoLite2-Country_20261116/GeoLite2-Country.mmdb")
        info.size = len(mmdb_bytes)
        tf.addfile(info, io.BytesIO(mmdb_bytes))
    good_tar_bytes = tar_buf.getvalue()

    return {
        "good_zip_bytes": good_zip_bytes,
        "good_zip_md5": hashlib.md5(good_zip_bytes, usedforsecurity=False).hexdigest(),
        "good_zip_1_bytes": good_zip_1_bytes,
        "good_zip_1_md5": hashlib.md5(good_zip_1_bytes, usedforsecurity=False).hexdigest(),
        "old_zip_bytes": old_zip_buf.getvalue(),
        "toxic_bytes": b"192.0.2.0/24\n",
        "mmdb_bytes": mmdb_bytes,
        "good_tar_bytes": good_tar_bytes,
        "good_tar_sha": hashlib.sha256(good_tar_bytes).hexdigest(),
    }


def _build_fake_update_http_client(archives, downloads_seen, *, corrupt_md5: bool = False):
    text_routes = (
        ("listed_ip_90_ipv46_all.zip.md5", "0" * 32 if corrupt_md5 else archives["good_zip_md5"]),
        ("listed_ip_1_ipv46_all.zip.md5", archives["good_zip_1_md5"]),
        ("GeoLite2-Country", f"{archives['good_tar_sha']}  GeoLite2-Country.tar.gz\n"),
        ("GeoLite2-City", f"{archives['good_tar_sha']}  GeoLite2-City.tar.gz\n"),
        ("GeoLite2-ASN", f"{archives['good_tar_sha']}  GeoLite2-ASN.tar.gz\n"),
    )
    stream_routes = (
        ("toxic_ip_cidr.txt", archives["toxic_bytes"]),
        ("listed_ip_90_ipv46_all.zip", archives["good_zip_bytes"]),
        ("listed_ip_1_ipv46_all.zip", archives["good_zip_1_bytes"]),
    )

    def _get(url, **kwargs):
        downloads_seen.append(("GET", url))
        for suffix, text in text_routes:
            if suffix in url and (not suffix.startswith("GeoLite2") or url.endswith(".sha256")):
                return _FakeTextResp(text)
        return _FakeTextResp("")

    def _stream(method, url, **kwargs):
        downloads_seen.append(("STREAM", url))
        for suffix, payload in stream_routes:
            if url.endswith(suffix):
                return _FakeStreamResp(payload)
        return _FakeStreamResp(archives["good_tar_bytes"])

    fake_client = MagicMock()
    fake_client.get.side_effect = _get
    fake_client.stream.side_effect = _stream
    cm = MagicMock()
    cm.__enter__.return_value = fake_client
    cm.__exit__.return_value = False
    return cm


class UpdateOfflineDbsCommandTests(TestCase):
    """Tests rate-limit mtime guards, checksum validation, and atomic replacements."""

    def test_respects_mtime_cooldown_and_allows_force_and_validates_md5(self):
        from django.core.management import call_command
        from django.core.management.base import CommandError

        from detector import offline_dbs
        from detector.management.commands import update_offline_dbs as update_cmd

        archives = _build_update_test_archives()

        with tempfile.TemporaryDirectory() as tmp_dir:
            tool_root = Path(tmp_dir) / "tool"
            data_dir = tool_root / "data"
            data_dir.mkdir(parents=True)

            existing_90 = data_dir / "listed_ip_90_ipv46_all.zip"
            existing_90.write_bytes(archives["old_zip_bytes"])
            downloads_seen = []

            # Recent mtime blocks SFS 90d download when --force is omitted
            with patch.object(
                update_cmd.httpx, "Client", return_value=_build_fake_update_http_client(archives, downloads_seen)
            ):
                call_command(
                    "update_offline_dbs", sources=["stopforumspam"], data_dir=str(data_dir), skip_listed_1=True
                )

            self.assertFalse(any("listed_ip_90_ipv46_all.zip" in u for _, u in downloads_seen))
            self.assertEqual(existing_90.read_bytes(), archives["old_zip_bytes"])

            # MD5 mismatch must fail without corrupting existing archive on disk
            downloads_seen.clear()
            with (
                patch.object(
                    update_cmd.httpx,
                    "Client",
                    return_value=_build_fake_update_http_client(archives, downloads_seen, corrupt_md5=True),
                ),
                self.assertRaises(CommandError),
            ):
                call_command(
                    "update_offline_dbs",
                    sources=["stopforumspam"],
                    data_dir=str(data_dir),
                    force=True,
                    skip_listed_1=True,
                )
            self.assertEqual(existing_90.read_bytes(), archives["old_zip_bytes"])

            # Force full valid SFS + MaxMind update into unified TOOL_DATA_DIR with mocked maxminddb reader
            downloads_seen.clear()
            fake_mm_reader = MagicMock()
            with (
                override_settings(
                    MAXMIND_ACCOUNT_ID="123456",
                    MAXMIND_LICENSE_KEY="secret-mm-key",
                    TOOL_DATA_DIR=str(tool_root),
                ),
                patch.object(
                    update_cmd.httpx,
                    "Client",
                    return_value=_build_fake_update_http_client(archives, downloads_seen, corrupt_md5=False),
                ),
                patch.object(update_cmd.maxminddb, "open_database", return_value=fake_mm_reader),
                patch.object(update_cmd, "MAXMIND_EDITION_SPECS", (("GeoLite2-Country", "GeoLite2-Country.mmdb"),)),
            ):
                call_command(
                    "update_offline_dbs",
                    sources=["stopforumspam", "maxmind"],
                    force=True,
                )

            self.assertEqual(existing_90.read_bytes(), archives["good_zip_bytes"])
            self.assertEqual((data_dir / "GeoLite2-Country.mmdb").read_bytes(), archives["mmdb_bytes"])
            self.assertTrue((data_dir / "stopforumspam.sqlite3").is_file())
            with override_settings(TOOL_DATA_DIR=str(tool_root)):
                offline_dbs.clear_stopforumspam_caches()
                hit = offline_dbs.query_stopforumspam_offline("198.51.100.12")
                self.assertTrue(hit["appears"])
                self.assertEqual(hit["frequency"], 7)
            offline_dbs.clear_stopforumspam_caches()

    def _build_cloud_cidr_mock_client(self, *, fail_providers=()):
        azure_json_url = "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20261117.json"
        payload_by_url = {
            "ip-ranges.amazonaws.com": json.dumps(
                {
                    "prefixes": [{"ip_prefix": "3.5.140.0/22"}, {"ip_prefix": "invalid-cidr"}],
                    "ipv6_prefixes": [{"ipv6_prefix": "2a05:d014::/40"}],
                }
            ),
            "gstatic.com": json.dumps({"prefixes": [{"ipv4Prefix": "34.64.0.0/10"}, {"ipv6Prefix": "2600:1900::/28"}]}),
            "docs.oracle.com": json.dumps(
                {"regions": [{"region": "us-ashburn-1", "cidrs": [{"cidr": "129.146.0.0/16"}]}]}
            ),
            "details.aspx?id=56519": f'<html><a href="{azure_json_url}">Download</a></html>',
            "ServiceTags_Public_": json.dumps(
                {"values": [{"name": "AzureCloud", "properties": {"addressPrefixes": ["20.48.0.0/12"]}}]}
            ),
        }

        def _get(url, **kwargs):
            for provider_key, url_part in (
                ("aws", "ip-ranges.amazonaws.com"),
                ("gcp", "gstatic.com"),
                ("oci", "docs.oracle.com"),
                ("azure", "details.aspx?id=56519"),
                ("azure", "ServiceTags_Public_"),
            ):
                if url_part in url and provider_key in fail_providers:
                    raise httpx.ConnectTimeout("Upstream timed out")
            for fragment, body in payload_by_url.items():
                if fragment in url:
                    return _FakeTextResp(body)
            return _FakeTextResp("{}", status_code=404)

        fake_client = MagicMock()
        fake_client.get.side_effect = _get
        cm = MagicMock()
        cm.__enter__.return_value = fake_client
        cm.__exit__.return_value = False
        return cm

    def test_cloud_cidrs_update_parses_all_providers_degrades_gracefully_and_hot_reloads(self):
        from django.core.management import call_command

        from detector import offline_dbs
        from detector.management.commands import update_offline_dbs as update_cmd

        with tempfile.TemporaryDirectory() as tmp_dir:
            target_file = Path(tmp_dir) / "data" / "cloud_cidrs.json"
            clear_offline_intelligence_caches()

            with (
                override_settings(TOOL_DATA_DIR=str(tmp_dir)),
                patch.object(update_cmd.httpx, "Client", return_value=self._build_cloud_cidr_mock_client()),
            ):
                call_command("update_offline_dbs", sources=["cloud_cidrs"], force=True)

            written = json.loads(target_file.read_text(encoding="utf-8"))
            self.assertEqual(written["Amazon AWS"], ["2a05:d014::/40", "3.5.140.0/22"])
            self.assertEqual(written["Google Cloud"], ["2600:1900::/28", "34.64.0.0/10"])
            self.assertEqual(written["Oracle Cloud"], ["129.146.0.0/16"])
            self.assertEqual(written["Microsoft Azure"], ["20.48.0.0/12"])

            with override_settings(TOOL_DATA_DIR=str(tmp_dir)):
                self.assertEqual(match_cloud_cidr("129.146.10.5")["provider"], "Oracle Cloud")
                self.assertEqual(match_cloud_cidr("20.48.10.5")["provider"], "Microsoft Azure")

                # Partial failure: OCI and Azure fail, so their historical CIDRs must be preserved
                target_file.write_text(
                    json.dumps(
                        {
                            "Amazon AWS": ["3.5.140.0/22"],
                            "Oracle Cloud": ["129.146.0.0/16", "130.35.0.0/16"],
                            "Microsoft Azure": ["20.48.0.0/12"],
                        }
                    ),
                    encoding="utf-8",
                )
                # Ensure hot-reload detects both mtime and size changes
                self.assertEqual(match_cloud_cidr("130.35.1.1")["provider"], "Oracle Cloud")

                with patch.object(
                    update_cmd.httpx,
                    "Client",
                    return_value=self._build_cloud_cidr_mock_client(fail_providers=("oci", "azure")),
                ):
                    call_command("update_offline_dbs", sources=["cloud_cidrs"], force=True)

                degraded = json.loads(target_file.read_text(encoding="utf-8"))
                self.assertEqual(degraded["Oracle Cloud"], ["129.146.0.0/16", "130.35.0.0/16"])
                self.assertEqual(degraded["Microsoft Azure"], ["20.48.0.0/12"])
                self.assertEqual(match_cloud_cidr("34.64.5.5")["provider"], "Google Cloud")

                # Verify 7-day staleness threshold in offline_dbs status monitoring
                stale_ts = time.time() - (8 * 86400)
                os.utime(target_file, (stale_ts, stale_ts))
                status_entries = {e["key"]: e for e in offline_dbs.collect_offline_databases_status()}
                self.assertEqual(status_entries["cloud_cidrs"]["status"], "stale")
            clear_offline_intelligence_caches()

    def test_unset_tool_data_dir_fallback_and_invalid_directory_validation(self):
        import io

        from django.core.management import call_command
        from django.core.management.base import CommandError

        with tempfile.TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            project_root = workspace / "proxycheck"
            project_root.mkdir()
            expected_default = workspace / "data"

            stdout = io.StringIO()
            clean_env = {key: val for key, val in os.environ.items() if key != "TOOL_DATA_DIR"}
            with (
                override_settings(BASE_DIR=project_root, TOOL_DATA_DIR=""),
                patch.dict(os.environ, clean_env, clear=True),
            ):
                call_command(
                    "update_offline_dbs",
                    sources=["stopforumspam"],
                    dry_run=True,
                    stdout=stdout,
                )

            output = stdout.getvalue()
            self.assertIn("TOOL_DATA_DIR is not set", output)
            self.assertIn(str(expected_default), output)

            # Reject a non-directory path configured via TOOL_DATA_DIR or --data-dir
            blocking_file = workspace / "not_a_dir"
            blocking_file.write_text("occupied", encoding="utf-8")
            with self.assertRaises(CommandError) as file_exc:
                call_command(
                    "update_offline_dbs",
                    sources=["stopforumspam"],
                    data_dir=str(blocking_file),
                    dry_run=True,
                )
            self.assertIn("not a directory", str(file_exc.exception))

            with (
                override_settings(TOOL_DATA_DIR=str(blocking_file)),
                self.assertRaises(CommandError) as tool_exc,
            ):
                call_command(
                    "update_offline_dbs",
                    sources=["stopforumspam"],
                )
            self.assertIn("not writable", str(tool_exc.exception))
