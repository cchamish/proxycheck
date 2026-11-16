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
            computehosts_file = Path(tmpdir) / "computehosts.json"
            computehosts_file.write_text(
                json.dumps(
                    [
                        {"range": "52.94.236.0/24", "provider": "aws"},
                        {"range": "52.94.236.64/26", "provider": "Amazon AWS"},
                        {"range": "2600:1f18:2000::/48", "provider": "aws"},
                    ]
                ),
                encoding="utf-8",
            )
            with override_settings(CLOUD_CIDR_DB_PATH=str(computehosts_file)):
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
            aws_file = Path(tmpdir) / "ip-ranges.json"
            aws_file.write_text(
                json.dumps(
                    {
                        "prefixes": [{"ip_prefix": "3.5.140.0/22", "service": "AMAZON"}],
                        "ipv6_prefixes": [{"ipv6_prefix": "2a05:d014::/40", "service": "EC2"}],
                    }
                ),
                encoding="utf-8",
            )
            with override_settings(CLOUD_CIDR_DB_PATH=str(aws_file)):
                self.assertEqual(match_cloud_cidr("3.5.140.5")["provider"], "Amazon AWS")
                self.assertEqual(match_cloud_cidr("2a05:d014:1::5")["cidr"], "2a05:d014::/40")

            clear_offline_intelligence_caches()
            provider_dict_file = Path(tmpdir) / "provider_cidrs.json"
            provider_dict_file.write_text(
                json.dumps({"gcp": ["34.64.0.0/16"], "azure": ["20.48.0.0/16"]}),
                encoding="utf-8",
            )
            with override_settings(CLOUD_CIDR_DB_PATH=str(provider_dict_file)):
                self.assertEqual(match_cloud_cidr("34.64.1.2")["provider"], "Google Cloud")
                self.assertEqual(match_cloud_cidr("20.48.1.2")["provider"], "Microsoft Azure")

            clear_offline_intelligence_caches()
            broken_file = Path(tmpdir) / "broken.json"
            broken_file.write_text("{not-valid-json", encoding="utf-8")
            with override_settings(CLOUD_CIDR_DB_PATH=str(broken_file)):
                self.assertIsNone(match_cloud_cidr("34.64.1.2"))

            with override_settings(CLOUD_CIDR_DB_PATH=str(Path(tmpdir) / "missing.json")):
                self.assertIsNone(match_cloud_cidr("34.64.1.2"))

    def test_cloud_cidr_cache_reloads_when_file_mtime_changes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cidr_file = Path(tmpdir) / "cloud_cidrs.json"
            cidr_file.write_text(json.dumps({"gcp": ["34.64.0.0/16"]}), encoding="utf-8")
            with override_settings(CLOUD_CIDR_DB_PATH=str(cidr_file)):
                self.assertIsNone(match_cloud_cidr("20.48.1.2"))

                cidr_file.write_text(json.dumps({"azure": ["20.48.0.0/16"]}), encoding="utf-8")
                stat = cidr_file.stat()
                os.utime(cidr_file, ns=(stat.st_atime_ns, stat.st_mtime_ns + 2_000_000_000))

                reloaded = match_cloud_cidr("20.48.1.2")
                self.assertIsNotNone(reloaded)
                self.assertEqual(reloaded["provider"], "Microsoft Azure")

    def test_maxmind_geolite2_enrichment_preserves_explicit_geoip2_user_type(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cidr_file = Path(tmpdir) / "cloud_cidrs.json"
            cidr_file.write_text(
                json.dumps([{"range": "54.239.28.64/26", "provider": "Amazon AWS"}]),
                encoding="utf-8",
            )
            with override_settings(
                CLOUD_CIDR_DB_PATH=str(cidr_file),
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
            cidr_file = Path(tmpdir) / "cloud_cidrs.json"
            cidr_file.write_text(
                json.dumps(
                    {
                        "Amazon AWS": ["54.239.28.64/26", "2600:1f18:2000::/80"],
                        "Google Cloud": ["34.64.0.0/16"],
                    }
                ),
                encoding="utf-8",
            )
            with override_settings(CLOUD_CIDR_DB_PATH=str(cidr_file)):
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
            cidr_file = Path(tmpdir) / "cloud_cidrs.json"
            cidr_file.write_text(
                json.dumps([{"range": "54.239.28.64/26", "provider": "Amazon AWS"}]),
                encoding="utf-8",
            )
            country_db = Path(tmpdir) / "GeoLite2-Country.mmdb"
            asn_db = Path(tmpdir) / "GeoLite2-ASN.mmdb"
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
                    MAXMIND_DB_DIR=str(tmpdir),
                    CLOUD_CIDR_DB_PATH=str(cidr_file),
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
        *,
        cidr_path: str = "",
    ) -> dict:
        """Creates stub MMDB files in one directory and runs _read_maxmind_sync against fake readers."""
        views._maxmind_readers.clear()
        self.addCleanup(views._maxmind_readers.clear)
        filename_map = {
            "country": "GeoLite2-Country.mmdb",
            "city": "GeoLite2-City.mmdb",
            "asn": "GeoLite2-ASN.mmdb",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            readers_by_path: dict[str, MagicMock] = {}
            for role, (rec, prefix_len) in db_records.items():
                db_path = Path(tmpdir) / filename_map[role]
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
                    MAXMIND_DB_DIR=str(tmpdir),
                    CLOUD_CIDR_DB_PATH=cidr_path,
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

        # Explicit empty MAXMIND_DB_DIR does not fall back to unrelated data directories
        with tempfile.TemporaryDirectory() as tmpdir:
            tool_root = Path(tmpdir) / "tool"
            fallback_data = tool_root / "www" / "python" / "data"
            fallback_data.mkdir(parents=True)
            (fallback_data / "GeoLite2-Country.mmdb").write_bytes(b"stub")
            empty_dir = Path(tmpdir) / "empty_mmdb"
            empty_dir.mkdir()

            with (
                override_settings(MAXMIND_DB_DIR=str(empty_dir)),
                patch.dict(os.environ, {"TOOL_DATA_DIR": str(tool_root)}),
            ):
                missing_row = views._read_maxmind_sync("1.1.1.1")
            self.assertEqual(missing_row["status"], "Database Missing")

    def test_adapt_maxmind_falls_back_to_non_english_localized_names(self):
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
                    MAXMIND_DB_DIR=str(flat_data_dir),
                    CLOUD_CIDR_DB_PATH="",
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
            mmdb_dir = Path(tmpdir)
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
                    MAXMIND_DB_DIR=str(mmdb_dir),
                    CLOUD_CIDR_DB_PATH="",
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

    def test_read_maxmind_sync_combines_get_with_prefix_len_without_duplicate_get(self):
        views._maxmind_readers.clear()
        views._maxmind_reader_stats.clear()
        self.addCleanup(views._maxmind_readers.clear)
        self.addCleanup(views._maxmind_reader_stats.clear)

        with tempfile.TemporaryDirectory() as tmpdir:
            country_db = Path(tmpdir) / "GeoLite2-Country.mmdb"
            country_db.write_bytes(b"stub")

            reader = MagicMock()
            reader.get_with_prefix_len.return_value = ({"country": {"iso_code": "US"}}, 24)
            fake_maxmind_module = MagicMock()
            fake_maxmind_module.open_database.return_value = reader

            with (
                override_settings(
                    MAXMIND_DB_DIR=str(tmpdir),
                    CLOUD_CIDR_DB_PATH="",
                    HOSTING_ASN_RULES_PATH="",
                    HOSTING_ASNS=(),
                    HOSTING_ORG_KEYWORDS=(),
                ),
                patch.dict("sys.modules", {"maxminddb": fake_maxmind_module}),
            ):
                row = views._read_maxmind_sync("198.51.100.42")

        reader.get_with_prefix_len.assert_called_once_with("198.51.100.42")
        reader.get.assert_not_called()
        self.assertEqual(row["status"], "200 OK")
        self.assertEqual(row["countryCode"], "US")
        self.assertEqual(row["prefixLength"], 24)

        # Unmapped record with routing prefix still avoids redundant reader.get
        null_rec_reader = MagicMock()
        null_rec_reader.get_with_prefix_len.return_value = (None, 20)
        rec, prefix_len = views._lookup_mmdb_record_and_prefix(null_rec_reader, "198.51.100.42")
        self.assertIsNone(rec)
        self.assertEqual(prefix_len, 20)
        null_rec_reader.get.assert_not_called()

        # Distinct reader.get mock return value remains respected when configured separately
        custom_get_reader = MagicMock()
        custom_get_reader.get.return_value = {"country": {"iso_code": "CA"}}
        custom_get_reader.get_with_prefix_len.return_value = ({"country": {"iso_code": "US"}}, 25)
        rec_custom, prefix_custom = views._lookup_mmdb_record_and_prefix(custom_get_reader, "198.51.100.42")
        self.assertEqual(rec_custom, {"country": {"iso_code": "CA"}})
        self.assertEqual(prefix_custom, 25)
        custom_get_reader.get.assert_called_once_with("198.51.100.42")

    def test_read_maxmind_sync_warms_offline_caches_when_mmdb_missing(self):
        from detector import adapters as detector_adapters

        clear_offline_intelligence_caches()
        self.assertFalse(detector_adapters.are_offline_intelligence_caches_warm())

        with tempfile.TemporaryDirectory() as tmpdir:
            empty_mmdb_dir = Path(tmpdir) / "empty_mmdb"
            empty_mmdb_dir.mkdir()
            cidr_file = Path(tmpdir) / "cloud_cidrs.json"
            cidr_file.write_text(json.dumps([{"range": "54.239.28.64/26", "provider": "Amazon AWS"}]), encoding="utf-8")
            rules_file = Path(tmpdir) / "hosting_asn_rules.json"
            rules_file.write_text(
                json.dumps({"hosts": [{"name": "Example Cloud", "asn": 64510}]}),
                encoding="utf-8",
            )

            with override_settings(
                MAXMIND_DB_DIR=str(empty_mmdb_dir),
                CLOUD_CIDR_DB_PATH=str(cidr_file),
                HOSTING_ASN_RULES_PATH=str(rules_file),
                HOSTING_ASNS=(),
                HOSTING_ORG_KEYWORDS=(),
            ):
                missing_row = views._read_maxmind_sync("54.239.28.85")

        self.assertEqual(missing_row["status"], "Database Missing")
        self.assertTrue(detector_adapters.are_offline_intelligence_caches_warm())

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
            cidr_file = Path(tmpdir) / "cloud_cidrs.json"
            cidr_file.write_text(json.dumps([{"range": "54.239.28.64/26", "provider": "Amazon AWS"}]), encoding="utf-8")
            rules_file = Path(tmpdir) / "hosting_asn_rules.json"
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
                    CLOUD_CIDR_DB_PATH=str(cidr_file),
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

    def test_should_refresh_cached_maxmind_entry_respects_city_db_loaded_flag(self):
        views._maxmind_city_db_cache = None
        self.addCleanup(setattr, views, "_maxmind_city_db_cache", None)

        base_row = {
            "provider": "MaxMind",
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
        raw_loaded_true = json.dumps(
            {
                "row": base_row,
                "cachedAt": "2026-11-16T00:00:00+00:00",
                "sanitized": True,
                "cityDbLoaded": True,
            }
        )
        raw_loaded_false = json.dumps(
            {
                "row": base_row,
                "cachedAt": "2026-11-16T00:00:00+00:00",
                "sanitized": True,
                "cityDbLoaded": False,
            }
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            city_db = Path(tmpdir) / "GeoLite2-City.mmdb"
            city_db.write_bytes(b"stub")

            with override_settings(MAXMIND_DB_DIR=str(tmpdir)):
                with patch("detector.views.json.loads", wraps=json.loads) as spy_loads:
                    decoded_true = views._decode_cached_provider_entry(raw_loaded_true)
                    self.assertIsNotNone(decoded_true)
                    self.assertEqual(set(decoded_true[0].keys()), set(base_row.keys()))
                    should_refresh_true = views._should_refresh_cached_maxmind_entry(
                        raw_loaded_true,
                        decoded_true[0],
                    )
                    self.assertFalse(should_refresh_true)
                    self.assertEqual(spy_loads.call_count, 1)

                with patch("detector.views.json.loads", wraps=json.loads) as spy_loads:
                    decoded_false = views._decode_cached_provider_entry(raw_loaded_false)
                    self.assertIsNotNone(decoded_false)
                    self.assertEqual(set(decoded_false[0].keys()), set(base_row.keys()))
                    should_refresh_false = views._should_refresh_cached_maxmind_entry(
                        raw_loaded_false,
                        decoded_false[0],
                    )
                    self.assertTrue(should_refresh_false)
                    self.assertEqual(spy_loads.call_count, 1)

                # Direct calls with a plain dictionary preserve original fallback decoding
                self.assertFalse(views._should_refresh_cached_maxmind_entry(raw_loaded_true, dict(base_row)))
                self.assertTrue(views._should_refresh_cached_maxmind_entry(raw_loaded_false, dict(base_row)))

                # Repeated checks within the TTL window reuse the cached city DB presence result
                views._maxmind_city_db_cache = None
                with patch("detector.views._resolve_db_file", wraps=views._resolve_db_file) as spy_resolve:
                    self.assertTrue(views._has_local_maxmind_city_db())
                    self.assertTrue(views._has_local_maxmind_city_db())
                    self.assertEqual(spy_resolve.call_count, 1)

        with patch("detector.views.os.path.exists", return_value=False):
            self.assertFalse(views._has_local_maxmind_city_db())
            self.assertFalse(views._should_refresh_cached_maxmind_entry(raw_loaded_false, dict(base_row)))

    def test_async_resolver_and_proc_rss_hot_path_caches(self):
        from unittest.mock import mock_open

        views._cached_async_resolvers.clear()
        self.addCleanup(views._cached_async_resolvers.clear)

        with override_settings(DNS_QUERY_TIMEOUT_SECONDS=2.0, DNS_QUERY_LIFETIME_SECONDS=2.0):
            first_resolver = views._create_async_resolver()
            second_resolver = views._create_async_resolver()
            self.assertIs(first_resolver, second_resolver)

        with override_settings(DNS_QUERY_TIMEOUT_SECONDS=1.5, DNS_QUERY_LIFETIME_SECONDS=3.0):
            custom_resolver = views._create_async_resolver()
            self.assertEqual(custom_resolver.timeout, 1.5)
            self.assertEqual(custom_resolver.lifetime, 3.0)
            self.assertIs(custom_resolver, views._create_async_resolver())

        views._proc_rss_cache = None
        self.addCleanup(setattr, views, "_proc_rss_cache", None)

        with (
            patch("builtins.open", mock_open(read_data="4096 2048 0 0 0 0 0\n")),
            patch.object(views.os, "sysconf", return_value=4096, create=True),
        ):
            sampled_rss = views._read_proc_rss_mb()
        self.assertEqual(sampled_rss, 8.0)

        # Unmocked call within one second returns the cached RSS sample without opening procfs
        self.assertEqual(views._read_proc_rss_mb(), 8.0)

        # Mocking builtins.open bypasses the cached sample immediately
        with patch("builtins.open", side_effect=OSError("procfs unavailable")):
            self.assertIsNone(views._read_proc_rss_mb())

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
            root = Path(tmp_dir)
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
                override_settings(STOPFORUMSPAM_DB_DIR=tmp_dir),
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
            root = Path(tmp_dir)
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
                override_settings(STOPFORUMSPAM_DB_DIR=tmp_dir),
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

    def test_zero_quota_limits_for_stopforumspam(self):
        from detector import quota_telemetry

        rpm, daily = quota_telemetry.get_provider_quota_limits("stopforumspam")
        self.assertEqual((rpm, daily), (0, 0))

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
            root = Path(tmp_dir)
            sfs_dir = root / "sfs"
            mm_dir = root / "mm"
            sfs_dir.mkdir()
            mm_dir.mkdir()

            existing_90 = sfs_dir / "listed_ip_90_ipv46_all.zip"
            existing_90.write_bytes(archives["old_zip_bytes"])
            downloads_seen = []

            # Recent mtime blocks SFS 90d download when --force is omitted
            with patch.object(
                update_cmd.httpx, "Client", return_value=_build_fake_update_http_client(archives, downloads_seen)
            ):
                call_command("update_offline_dbs", sources=["stopforumspam"], sfs_dir=str(sfs_dir), skip_listed_1=True)

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
                    sfs_dir=str(sfs_dir),
                    force=True,
                    skip_listed_1=True,
                )
            self.assertEqual(existing_90.read_bytes(), archives["old_zip_bytes"])

            # Force full valid SFS + MaxMind update with mocked maxminddb reader validation
            downloads_seen.clear()
            fake_mm_reader = MagicMock()
            with (
                override_settings(
                    MAXMIND_ACCOUNT_ID="123456",
                    MAXMIND_LICENSE_KEY="secret-mm-key",
                    STOPFORUMSPAM_DB_DIR=str(sfs_dir),
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
                    sources=["all"],
                    sfs_dir=str(sfs_dir),
                    maxmind_dir=str(mm_dir),
                    force=True,
                )

            self.assertEqual(existing_90.read_bytes(), archives["good_zip_bytes"])
            self.assertEqual((mm_dir / "GeoLite2-Country.mmdb").read_bytes(), archives["mmdb_bytes"])
            self.assertTrue((sfs_dir / "stopforumspam.sqlite3").is_file())
            with override_settings(STOPFORUMSPAM_DB_DIR=str(sfs_dir)):
                offline_dbs.clear_stopforumspam_caches()
                hit = offline_dbs.query_stopforumspam_offline("198.51.100.12")
                self.assertTrue(hit["appears"])
                self.assertEqual(hit["frequency"], 7)
            offline_dbs.clear_stopforumspam_caches()
