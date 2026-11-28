"""P0 tests for offline database updaters: streaming compilation, 304 mtime refresh, and empty-feed protection."""

from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict

import httpx
from django.core.management.color import no_style
from django.test import SimpleTestCase

from detector.offline.prefix_index import BinaryPrefixIndexReader
from detector.offline.store import (
    BGP_TAGS_JSON_FILENAME,
    BGP_TOOLS_BIN_FILENAME,
    MOBILE_ASNS_JSON_FILENAME,
    OPENASN_MMDB_FILENAME,
)
from detector.offline.updaters import (
    BGP_TOOLS_TABLE_URL,
    BGP_TOOLS_TAGS_URL,
    MOBILE_CARRIERS_URL,
    OPENASN_MANIFEST_URL,
    OfflineDbUpdater,
    _url_cache_path,
)


def _mock_client(routes: Dict[str, httpx.Response]) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(lambda req: routes[str(req.url)]))


class OfflineDbUpdaterTests(SimpleTestCase):
    """Verifies BGP Tools streaming compilation, mobile carrier parsing, 304 mtime refresh, and empty-feed safety."""

    def _make_updater(self) -> tuple[OfflineDbUpdater, io.StringIO, io.StringIO]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        return OfflineDbUpdater(stdout=stdout, stderr=stderr, style=no_style()), stdout, stderr

    def test_bgp_tools_streams_compiles_refreshes_304_mtime_and_rejects_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            data_dir = Path(tmp_dir)
            bin_path = data_dir / BGP_TOOLS_BIN_FILENAME
            tags_path = data_dir / BGP_TAGS_JSON_FILENAME
            meta_map: Dict[str, Dict[str, str]] = {}
            updater, _out, _err = self._make_updater()

            with _mock_client(
                {
                    BGP_TOOLS_TAGS_URL: httpx.Response(200, text="AS64512 mobile\n", headers={"ETag": '"tags-v1"'}),
                    BGP_TOOLS_TABLE_URL: httpx.Response(
                        200,
                        text="198.51.100.0/24 64512\n2001:db8::/32 64513\n",
                        headers={"ETag": '"table-v1"'},
                    ),
                }
            ) as client:
                errors = updater._update_bgp_tools(
                    client, data_dir=data_dir, meta_map=meta_map, force=True, dry_run=False
                )
            self.assertEqual(errors, 0)
            self.assertTrue(bin_path.is_file())
            self.assertTrue(tags_path.is_file())
            self.assertFalse(_url_cache_path(data_dir, BGP_TOOLS_TABLE_URL).exists())

            reader = BinaryPrefixIndexReader(bin_path)
            try:
                self.assertEqual(reader.lookup("198.51.100.42"), ("198.51.100.0/24", 64512))
                self.assertEqual(reader.lookup("2001:db8::1"), ("2001:db8::/32", 64513))
            finally:
                reader.close()

            original_bin_bytes = bin_path.read_bytes()
            stale_ts = time.time() - 8 * 86400
            os.utime(bin_path, (stale_ts, stale_ts))
            os.utime(tags_path, (stale_ts, stale_ts))

            with _mock_client(
                {
                    BGP_TOOLS_TAGS_URL: httpx.Response(304),
                    BGP_TOOLS_TABLE_URL: httpx.Response(304),
                }
            ) as client:
                errors_304 = updater._update_bgp_tools(
                    client, data_dir=data_dir, meta_map=meta_map, force=True, dry_run=False
                )
            self.assertEqual(errors_304, 0)
            self.assertGreater(bin_path.stat().st_mtime, stale_ts + 3600)
            self.assertGreater(tags_path.stat().st_mtime, stale_ts + 3600)

            with _mock_client(
                {
                    BGP_TOOLS_TAGS_URL: httpx.Response(304),
                    BGP_TOOLS_TABLE_URL: httpx.Response(200, text="# comment only\n"),
                }
            ) as client:
                errors_empty = updater._update_bgp_tools(
                    client, data_dir=data_dir, meta_map=meta_map, force=True, dry_run=False
                )
            self.assertEqual(errors_empty, 1)
            self.assertEqual(bin_path.read_bytes(), original_bin_bytes)

    def test_mobile_carriers_parses_mobile_role_refreshes_304_mtime_and_rejects_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            data_dir = Path(tmp_dir)
            target_path = data_dir / MOBILE_ASNS_JSON_FILENAME
            meta_map: Dict[str, Dict[str, str]] = {}
            updater, _out, _err = self._make_updater()

            sample_payload: Dict[str, Any] = {
                "name": "PROXIES.SX Carrier & ASN Registry",
                "rows": [
                    {"carrier": "Djezzy", "asn": 327931, "asn_role": "mobile"},
                    {"carrier": "Mobilis Fixed", "asn": 36947, "asn_role": "fixed"},
                    {"carrier": "Corp", "asn": 64500, "asn_role": "enterprise"},
                    {"carrier": "StrCarrier", "asn": "AS327712", "asn_role": "mobile"},
                    {"carrier": "Unknown", "asn": None, "asn_role": "mobile"},
                ],
            }
            with _mock_client(
                {
                    MOBILE_CARRIERS_URL: httpx.Response(
                        200, text=json.dumps(sample_payload), headers={"ETag": '"carriers-v1"'}
                    )
                }
            ) as client:
                errors = updater._update_mobile_carriers(
                    client, data_dir=data_dir, meta_map=meta_map, force=True, dry_run=False
                )
            self.assertEqual(errors, 0)
            written = json.loads(target_path.read_text(encoding="utf-8"))
            self.assertEqual(written["mobile_asns"], [327712, 327931])
            self.assertEqual(written["networks"], {"327712": "StrCarrier", "327931": "Djezzy"})

            original_text = target_path.read_text(encoding="utf-8")
            stale_ts = time.time() - 8 * 86400
            os.utime(target_path, (stale_ts, stale_ts))

            with _mock_client({MOBILE_CARRIERS_URL: httpx.Response(304)}) as client:
                errors_304 = updater._update_mobile_carriers(
                    client, data_dir=data_dir, meta_map=meta_map, force=True, dry_run=False
                )
            self.assertEqual(errors_304, 0)
            self.assertGreater(target_path.stat().st_mtime, stale_ts + 3600)

            empty_payload = {"rows": [{"carrier": "FixedOnly", "asn": 36947, "asn_role": "fixed"}]}
            with _mock_client({MOBILE_CARRIERS_URL: httpx.Response(200, text=json.dumps(empty_payload))}) as client:
                errors_empty = updater._update_mobile_carriers(
                    client, data_dir=data_dir, meta_map=meta_map, force=True, dry_run=False
                )
            self.assertEqual(errors_empty, 1)
            self.assertEqual(target_path.read_text(encoding="utf-8"), original_text)

    def test_openasn_refreshes_mtime_when_manifest_matches_local_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            data_dir = Path(tmp_dir)
            target_path = data_dir / OPENASN_MMDB_FILENAME
            raw_mmdb = b"fake-openasn-mmdb-bytes"
            target_path.write_bytes(raw_mmdb)
            stale_ts = time.time() - 8 * 86400
            os.utime(target_path, (stale_ts, stale_ts))

            manifest = {
                "files": [
                    {
                        "name": OPENASN_MMDB_FILENAME,
                        "sha256": hashlib.sha256(raw_mmdb).hexdigest(),
                        "bytes": len(raw_mmdb),
                        "export": {
                            "format": "mmdb",
                            "content_encoding": "identity",
                            "schema_version": 1,
                            "classification_profile": "core-v1",
                            "lookup_policy_version": 1,
                        },
                    }
                ]
            }
            updater, _out, _err = self._make_updater()
            with _mock_client({OPENASN_MANIFEST_URL: httpx.Response(200, text=json.dumps(manifest))}) as client:
                errors = updater._update_openasn(client, data_dir=data_dir, force=False, dry_run=False)
            self.assertEqual(errors, 0)
            self.assertGreater(target_path.stat().st_mtime, stale_ts + 3600)
