"""Management command to safely download and atomically replace offline intelligence databases."""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

import httpx
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from detector.binary_prefix_index import compile_binary_prefix_index, parse_cidr_to_int_prefix
from detector.cache_backends import clear_maxmind_readers
from detector.cidr_attribution import clear_offline_intelligence_caches
from detector.offline_dbs import (
    BGP_TAGS_JSON_FILENAME,
    BGP_TOOLS_BIN_FILENAME,
    HTTP_FEED_METADATA_FILENAME,
    IPSUM_DROP_BIN_FILENAME,
    MAXMIND_EDITION_SPECS,
    MOBILE_ASNS_JSON_FILENAME,
    MOBILE_BGP_TAG_TOKENS,
    OPENASN_MMDB_FILENAME,
    PRIVACY_RELAYS_BIN_FILENAME,
    REZMOSS_EXCLUDED_PROVIDERS,
    SFS_LISTED_1_ZIP_NAME,
    SFS_LISTED_90_ZIP_NAME,
    SFS_SQLITE_FILENAME,
    SFS_TOXIC_CIDR_FILENAME,
    SHARED_CIDRS_BIN_FILENAME,
    TOR_ONIONOO_SUMMARY_FILENAME,
    PrefixCidrIndex,
    atomic_temp_path,
    build_stopforumspam_sqlite_index,
    classify_rezmoss_provider,
    clear_stopforumspam_caches,
    replace_temp_file_atomically,
    resolve_configured_data_dir,
    resolve_writable_data_dir,
)
from detector.provider_registry import USER_AGENT_HEADER
from detector.sanitization import sanitize_error_message

try:
    import maxminddb
except ImportError:
    maxminddb = None

SFS_BASE_URL = "https://www.stopforumspam.com/downloads"
SFS_TOXIC_CIDR_URL = f"{SFS_BASE_URL}/{SFS_TOXIC_CIDR_FILENAME}"
SFS_LISTED_90_ZIP_URL = f"{SFS_BASE_URL}/{SFS_LISTED_90_ZIP_NAME}"
SFS_LISTED_90_MD5_URL = f"{SFS_LISTED_90_ZIP_URL}.md5"
SFS_LISTED_1_ZIP_URL = f"{SFS_BASE_URL}/{SFS_LISTED_1_ZIP_NAME}"
SFS_LISTED_1_MD5_URL = f"{SFS_LISTED_1_ZIP_URL}.md5"

# Guard windows stay comfortably below upstream daily or hourly download limits
# whilst accommodating minor cron or timer drift.
SFS_TOXIC_MIN_INTERVAL_SECONDS = 12 * 3600 - 300
SFS_90_MIN_INTERVAL_SECONDS = 12 * 3600 - 300
SFS_1_MIN_INTERVAL_SECONDS = 3600 - 120
MAXMIND_MIN_INTERVAL_SECONDS = 24 * 3600 - 300
TOR_ONIONOO_MIN_INTERVAL_SECONDS = 3600 - 120
DAILY_FEED_MIN_INTERVAL_SECONDS = 24 * 3600 - 300

REZMOSS_BASE_URL = "https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main"
REZMOSS_SUMMARY_URL = f"{REZMOSS_BASE_URL}/summary.json"
_SHARED_CATEGORY_PRIORITY: Dict[str, int] = {
    "vpn": 6,
    "enterprise_gateway": 5,
    "bot": 4,
    "saas": 3,
    "cdn": 2,
    "cloud": 1,
}

APPLE_PRIVATE_RELAY_URL = "https://mask-api.icloud.com/egress-ip-ranges.csv"
CLOUDFLARE_LOCAL_GEOFEED_URL = "https://api.cloudflare.com/local-ip-ranges.csv"
CLOUDFLARE_IPS_V4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_IPS_V6_URL = "https://www.cloudflare.com/ips-v6"

IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
SPAMHAUS_DROP_V4_URL = "https://www.spamhaus.org/drop/drop_v4.json"
SPAMHAUS_DROP_V6_URL = "https://www.spamhaus.org/drop/drop_v6.json"

TOR_ONIONOO_SUMMARY_URL = "https://onionoo.torproject.org/summary?type=relay"

BGP_TOOLS_USER_AGENT = "ProxyCheck/1.0 bgp.tools - tools.proxycheck@toolforge.org"
BGP_TOOLS_TABLE_URL = "https://bgp.tools/table.txt"
BGP_TOOLS_TAGS_URL = "https://bgp.tools/tags.txt"
BGP_TOOLS_MOBILE_TAG_CSV_URL = "https://bgp.tools/tags/mobile.csv"
BGP_TOOLS_VPN_TAG_CSV_URL = "https://bgp.tools/tags/vpn.csv"

# Always the tag-addressed "latest" release: the GitHub "Latest" badge can point at stale dated snapshots.
OPENASN_MANIFEST_URL = "https://github.com/openasn/openasn/releases/download/latest/manifest.json"
OPENASN_MMDB_URL = "https://github.com/openasn/openasn/releases/download/latest/openasn.mmdb"
OPENASN_MANIFEST_MAX_BYTES = 2 * 1024 * 1024
OPENASN_MAX_ATTEMPTS = 3
OPENASN_RETRY_BACKOFF_SECONDS = (2, 5)
OPENASN_DATABASE_TYPE = "OpenASN-Core-v1"
_OPENASN_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_OPENASN_EXPORT_CONTRACT: Dict[str, Any] = {
    "format": "mmdb",
    "content_encoding": "identity",
    "schema_version": 1,
    "classification_profile": "core-v1",
    "lookup_policy_version": 1,
}

PEERINGDB_NET_URL = "https://www.peeringdb.com/api/net"

_SOURCE_ALIASES: Dict[str, str] = {
    "stopforumspam": "stopforumspam",
    "sfs": "stopforumspam",
    "maxmind": "maxmind",
    "shared_cidrs": "shared_cidrs",
    "shared-cidrs": "shared_cidrs",
    "rezmoss": "shared_cidrs",
    "privacy_relays": "privacy_relays",
    "privacy-relays": "privacy_relays",
    "ipsum_drop": "ipsum_drop",
    "ipsum-drop": "ipsum_drop",
    "tor_onionoo": "tor_onionoo",
    "tor-onionoo": "tor_onionoo",
    "bgp_tools": "bgp_tools",
    "bgp-tools": "bgp_tools",
    "openasn": "openasn",
    "open-asn": "openasn",
    "peeringdb_mobile": "peeringdb_mobile",
    "peeringdb-mobile": "peeringdb_mobile",
}
_ALL_CANONICAL_SOURCES: Tuple[str, ...] = (
    "stopforumspam",
    "maxmind",
    "shared_cidrs",
    "privacy_relays",
    "ipsum_drop",
    "tor_onionoo",
    "bgp_tools",
    "openasn",
    "peeringdb_mobile",
)

MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
_HEX_32_RE = re.compile(r"\b([0-9a-fA-F]{32})\b")
_HEX_64_RE = re.compile(r"\b([0-9a-fA-F]{64})\b")
_DOWNLOAD_UPDATE_ERRORS = (httpx.HTTPError, CommandError, OSError, ValueError, tarfile.TarError, zipfile.BadZipFile)


def _file_digest_hex(file_path: Path, hasher: Any) -> str:
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def _file_md5_hex(file_path: Path) -> str:
    return _file_digest_hex(file_path, hashlib.md5(usedforsecurity=False))


def _file_sha256_hex(file_path: Path) -> str:
    return _file_digest_hex(file_path, hashlib.sha256())


def _check_mtime_cooldown(target_path: Path, min_interval_seconds: int, *, force: bool) -> Optional[int]:
    """Returns remaining wait seconds when mtime is newer than the allowed interval."""
    if force or min_interval_seconds <= 0 or not target_path.is_file():
        return None
    try:
        age = time.time() - target_path.stat().st_mtime
    except OSError:
        return None
    if age < 0:
        return min_interval_seconds
    if age < min_interval_seconds:
        return max(1, int(min_interval_seconds - age))
    return None


def _parse_hex_digest(raw_text: str, pattern: re.Pattern[str]) -> Optional[str]:
    match = pattern.search(raw_text or "")
    return match.group(1).lower() if match else None


def _redact_update_error(message: str, secrets_to_hide: Iterable[str] = ()) -> str:
    cleaned = sanitize_error_message(message)
    for secret in secrets_to_hide:
        if secret:
            cleaned = cleaned.replace(secret, "[REDACTED]")
    return cleaned


def _load_http_feed_metadata(data_dir: Path) -> Dict[str, Dict[str, str]]:
    meta_path = data_dir / HTTP_FEED_METADATA_FILENAME
    if not meta_path.is_file():
        return {}
    try:
        raw = json.loads(meta_path.read_text(encoding="utf-8"))
    except OSError, ValueError:
        return {}
    if not isinstance(raw, dict):
        return {}
    cleaned: Dict[str, Dict[str, str]] = {}
    for url, entry in raw.items():
        if isinstance(url, str) and isinstance(entry, dict):
            cleaned[url] = {str(k): str(v) for k, v in entry.items() if isinstance(v, str) and v}
    return cleaned


def _save_http_feed_metadata(data_dir: Path, metadata: Mapping[str, Mapping[str, str]]) -> None:
    meta_path = data_dir / HTTP_FEED_METADATA_FILENAME
    serialisable = {str(k): dict(v) for k, v in sorted(metadata.items())}
    with atomic_temp_path(meta_path) as tmp_path:
        tmp_path.write_text(json.dumps(serialisable, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _get_header_ci(headers: Any, target_name: str) -> str:
    if headers is None:
        return ""
    getter = getattr(headers, "get", None)
    if callable(getter):
        direct = getter(target_name) or getter(target_name.lower()) or getter(target_name.title())
        if isinstance(direct, str) and direct.strip():
            return direct.strip()
    if isinstance(headers, Mapping):
        lowered = target_name.lower()
        for k, v in headers.items():
            if str(k).lower() == lowered and isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def _url_cache_path(data_dir: Path, url: str) -> Path:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:20]
    return data_dir / ".feed_cache" / f"{digest}.txt"


def _extract_response_text(resp: Any, url: str) -> str:
    raw_content = getattr(resp, "content", None)
    if isinstance(raw_content, (bytes, bytearray)):
        raw_bytes = bytes(raw_content)
        if len(raw_bytes) > MAX_ARCHIVE_BYTES:
            raise CommandError(f"Download exceeded size limit for {url}")
        if raw_bytes[:2] == b"\x1f\x8b":
            raw_bytes = gzip.decompress(raw_bytes)
        text = raw_bytes.decode("utf-8", errors="replace")
    else:
        text = str(getattr(resp, "text", "") or "")
        if len(text.encode("utf-8", errors="replace")) > MAX_ARCHIVE_BYTES:
            raise CommandError(f"Download exceeded size limit for {url}")
    if not text.strip():
        raise CommandError(f"Downloaded empty response from {url}")
    return text


def _fetch_conditional_text(
    client: httpx.Client,
    url: str,
    *,
    data_dir: Path,
    meta_map: Dict[str, Dict[str, str]],
    target_exists: bool,
    cache_raw: bool = False,
    extra_headers: Optional[Mapping[str, str]] = None,
) -> Tuple[Optional[str], bool]:
    """
    Fetches an upstream text or JSON feed using stored ETag and Last-Modified headers.
    Returns (text_or_none, was_modified) where was_modified is False on HTTP 304 responses.
    """
    cache_file = _url_cache_path(data_dir, url)
    can_send_conditional = target_exists and (not cache_raw or cache_file.is_file())
    prior_meta = meta_map.get(url) if can_send_conditional else None

    req_headers: Dict[str, str] = dict(extra_headers or {})
    if isinstance(prior_meta, dict):
        if prior_meta.get("etag"):
            req_headers["If-None-Match"] = prior_meta["etag"]
        if prior_meta.get("last_modified"):
            req_headers["If-Modified-Since"] = prior_meta["last_modified"]

    resp = client.get(url, headers=req_headers) if req_headers else client.get(url)
    status_code = getattr(resp, "status_code", 200)
    if status_code == 304:
        if cache_raw and cache_file.is_file():
            return cache_file.read_text(encoding="utf-8"), False
        return None, False

    resp.raise_for_status()
    text = _extract_response_text(resp, url)

    resp_headers = getattr(resp, "headers", None)
    etag = _get_header_ci(resp_headers, "ETag")
    last_modified = _get_header_ci(resp_headers, "Last-Modified")
    if etag or last_modified:
        entry: Dict[str, str] = {}
        if etag:
            entry["etag"] = etag
        if last_modified:
            entry["last_modified"] = last_modified
        meta_map[url] = entry

    if cache_raw:
        with atomic_temp_path(cache_file) as tmp_cache:
            tmp_cache.write_text(text, encoding="utf-8")

    return text, True


def _reject_html_payload(raw_text: str, label: str) -> None:
    first_non_empty = next((ln.strip() for ln in raw_text.splitlines() if ln.strip()), "")
    if first_non_empty.lower().startswith(("<!doctype", "<html")):
        raise CommandError(f"{label} download returned HTML instead of feed data.")


def _stream_download_to_temp(
    client: httpx.Client,
    url: str,
    target_dir: Path,
    prefix: str,
    *,
    auth: Optional[Tuple[str, str]] = None,
) -> Path:
    """Streams an HTTP response body into a temporary file inside target_dir for atomic replacement."""
    target_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=prefix, dir=str(target_dir))
    os.close(fd)
    tmp_path = Path(tmp_name)
    total_bytes = 0
    try:
        request_kwargs: Dict[str, object] = {"auth": auth} if auth is not None else {}
        with client.stream("GET", url, **request_kwargs) as response:
            response.raise_for_status()
            with tmp_path.open("wb") as out_handle:
                for chunk in response.iter_bytes(chunk_size=65536):
                    if not chunk:
                        continue
                    total_bytes += len(chunk)
                    if total_bytes > MAX_ARCHIVE_BYTES:
                        raise CommandError(f"Download exceeded size limit for {url}")
                    out_handle.write(chunk)
        if total_bytes <= 0:
            raise CommandError(f"Downloaded empty response from {url}")
        return tmp_path
    except Exception:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise


def _validate_toxic_cidr_file(file_path: Path) -> int:
    valid_networks = 0
    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        for idx, line in enumerate(handle):
            stripped = line.strip()
            if idx == 0 and stripped.lower().startswith(("<!doctype", "<html")):
                raise CommandError("Toxic CIDR download returned HTML instead of CIDR data.")
            if not stripped or stripped.startswith(("#", ";")):
                continue
            try:
                ipaddress.ip_network(stripped.split()[0], strict=False)
                valid_networks += 1
            except ValueError:
                continue
    if valid_networks <= 0:
        raise CommandError("Toxic CIDR download contained no valid IP networks.")
    return valid_networks


def _validate_sfs_zip_sample_rows(zf: zipfile.ZipFile, primary_member: zipfile.ZipInfo) -> int:
    sample_ips = 0
    with zf.open(primary_member, "r") as raw_member:
        for idx in range(25):
            raw_line = raw_member.readline()
            if not raw_line:
                break
            decoded = raw_line.decode("utf-8", errors="replace").strip()
            if idx == 0 and decoded.lower().startswith(("<!doctype", "<html")):
                raise CommandError("StopForumSpam archive contained HTML instead of CSV data.")
            first_col = decoded.split(",", 1)[0].strip().strip('"')
            if not first_col or first_col.startswith("#"):
                continue
            try:
                ipaddress.ip_address(first_col)
                sample_ips += 1
            except ValueError:
                continue
    return sample_ips


def _validate_sfs_zip_file(zip_path: Path, expected_md5: Optional[str]) -> int:
    if expected_md5 is not None:
        actual_md5 = _file_md5_hex(zip_path)
        if actual_md5 != expected_md5:
            raise CommandError(f"MD5 mismatch for {zip_path.name}: expected {expected_md5}, got {actual_md5}.")
    if not zipfile.is_zipfile(zip_path):
        raise CommandError(f"Downloaded file {zip_path.name} is not a valid zip archive.")
    with zipfile.ZipFile(zip_path, "r") as zf:
        corrupt_member = zf.testzip()
        if corrupt_member is not None:
            raise CommandError(f"Corrupt member '{corrupt_member}' inside zip archive.")
        data_members = [
            info for info in zf.infolist() if not info.is_dir() and info.filename.lower().endswith((".txt", ".csv"))
        ]
        if not data_members:
            raise CommandError("StopForumSpam zip archive contains no text or CSV data member.")
        primary_member = max(data_members, key=lambda info: info.file_size)
        if primary_member.file_size <= 0:
            raise CommandError("StopForumSpam zip archive data member is empty.")
        sample_ips = _validate_sfs_zip_sample_rows(zf, primary_member)
    if sample_ips <= 0:
        raise CommandError("StopForumSpam zip archive did not contain recognisable IP records.")
    return sample_ips


def _extract_mmdb_into_file(tar_path: Path, edition_name: str, destination_path: Path) -> None:
    expected_basename = f"{edition_name}.mmdb"
    with tarfile.open(tar_path, "r:gz") as archive:
        target_member = next(
            (m for m in archive.getmembers() if m.isfile() and Path(m.name).name == expected_basename),
            None,
        )
        if target_member is None:
            raise CommandError(f"Could not find {expected_basename} inside MaxMind archive.")
        extracted = archive.extractfile(target_member)
        if extracted is None:
            raise CommandError(f"Failed to read {expected_basename} from MaxMind archive.")
        written = 0
        with extracted, destination_path.open("wb") as out_handle:
            for chunk in iter(lambda: extracted.read(65536), b""):
                written += len(chunk)
                if written > MAX_ARCHIVE_BYTES:
                    raise CommandError(f"Extracted {expected_basename} exceeded safety size limit.")
                out_handle.write(chunk)
        if written <= 0:
            raise CommandError(f"Extracted {expected_basename} is empty.")

    if maxminddb is not None:
        reader = maxminddb.open_database(str(destination_path))
        try:
            _ = reader.metadata()
        finally:
            reader.close()


def _write_json_atomically(payload: Any, target_path: Path) -> None:
    with atomic_temp_path(target_path) as tmp_path:
        tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _merge_shared_cidr_payloads(existing: Any, new: Any) -> Dict[str, str]:
    existing_map = existing if isinstance(existing, Mapping) else {}
    new_map = new if isinstance(new, Mapping) else {}
    existing_cat = str(existing_map.get("c") or "cloud").lower()
    new_cat = str(new_map.get("c") or "cloud").lower()
    if _SHARED_CATEGORY_PRIORITY.get(new_cat, 0) > _SHARED_CATEGORY_PRIORITY.get(existing_cat, 0):
        return {"p": str(new_map.get("p") or ""), "c": new_cat}
    return {"p": str(existing_map.get("p") or ""), "c": existing_cat}


def _parse_rezmoss_summary_slugs(raw_text: str) -> List[str]:
    _reject_html_payload(raw_text, "Rezmoss summary.json")
    try:
        payload = json.loads(raw_text)
    except ValueError as exc:
        raise CommandError(f"Rezmoss summary.json was not valid JSON: {exc}") from exc
    providers = payload.get("providers") if isinstance(payload, dict) else None
    if not isinstance(providers, dict) or not providers:
        raise CommandError("Rezmoss summary.json is missing a non-empty providers object.")
    slugs = sorted(
        str(raw_slug).strip().lower()
        for raw_slug in providers
        if isinstance(raw_slug, str)
        and str(raw_slug).strip()
        and str(raw_slug).strip().lower() not in REZMOSS_EXCLUDED_PROVIDERS
    )
    if not slugs:
        raise CommandError("Rezmoss summary.json contained no eligible provider slugs.")
    return slugs


def _parse_geofeed_csv_cidrs(raw_text: str, label: str) -> List[str]:
    _reject_html_payload(raw_text, label)
    cidrs: List[str] = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        first_col = stripped.split(",", 1)[0].strip().strip('"')
        if parse_cidr_to_int_prefix(first_col) is not None:
            cidrs.append(first_col)
    return cidrs


def _parse_plaintext_cidrs(raw_text: str, label: str) -> List[str]:
    _reject_html_payload(raw_text, label)
    cidrs: List[str] = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        first_col = stripped.split()[0].strip()
        if parse_cidr_to_int_prefix(first_col) is not None:
            cidrs.append(first_col)
    return cidrs


def _merge_privacy_relay_tags(existing_tag: Any, new_tag: Any) -> str:
    tags = {str(existing_tag), str(new_tag)}
    if "icloud_private_relay" in tags:
        return "icloud_private_relay"
    if "cloudflare_cdn" in tags:
        return "cloudflare_cdn"
    return str(new_tag)


def _parse_ipsum_entries(raw_text: str) -> List[Tuple[str, int]]:
    _reject_html_payload(raw_text, "IPsum")
    entries: List[Tuple[str, int]] = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        try:
            score = int(parts[1])
        except ValueError:
            continue
        if score >= 2 and parse_cidr_to_int_prefix(parts[0]) is not None:
            entries.append((parts[0], score))
    return entries


def _extract_drop_record(obj: Any) -> Optional[Tuple[str, Optional[str]]]:
    if not isinstance(obj, dict) or obj.get("type") == "metadata":
        return None
    raw_cidr = obj.get("cidr")
    if not isinstance(raw_cidr, str) or not raw_cidr.strip():
        return None
    try:
        net = ipaddress.ip_network(raw_cidr.strip(), strict=False)
    except ValueError:
        return None
    sbl_raw = obj.get("sblid") or obj.get("sblId")
    sbl_id = str(sbl_raw).strip() if isinstance(sbl_raw, str) and str(sbl_raw).strip() else None
    return str(net), sbl_id


def _parse_spamhaus_drop_entries(raw_text: str, label: str) -> List[Tuple[str, Optional[str]]]:
    _reject_html_payload(raw_text, label)
    entries: List[Tuple[str, Optional[str]]] = []
    stripped_body = raw_text.strip()
    if not stripped_body:
        return entries

    try:
        whole = json.loads(stripped_body)
    except ValueError:
        whole = None

    if whole is not None:
        items: Iterable[Any]
        if isinstance(whole, list):
            items = whole
        elif isinstance(whole, dict):
            items = [whole] if "cidr" in whole else next((v for v in whole.values() if isinstance(v, list)), ())
        else:
            items = ()
        for item in items:
            rec = _extract_drop_record(item)
            if rec is not None:
                entries.append(rec)
        return entries

    for line in stripped_body.splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith(("#", ";")):
            continue
        try:
            line_obj = json.loads(cleaned)
        except ValueError:
            continue
        rec = _extract_drop_record(line_obj)
        if rec is not None:
            entries.append(rec)
    return entries


def _normalise_ipsum_drop_payload(val: Any) -> Dict[str, Any]:
    if isinstance(val, int) and not isinstance(val, bool):
        return {"score": val, "drop": False, "sblid": None, "drop_cidr": None}
    if isinstance(val, dict):
        return {
            "score": int(val.get("score") or 0),
            "drop": bool(val.get("drop")),
            "sblid": val.get("sblid"),
            "drop_cidr": val.get("drop_cidr"),
        }
    return {"score": 0, "drop": False, "sblid": None, "drop_cidr": None}


def _merge_ipsum_drop_payloads(existing_val: Any, new_val: Any) -> Any:
    left = _normalise_ipsum_drop_payload(existing_val)
    right = _normalise_ipsum_drop_payload(new_val)
    merged_score = max(left["score"], right["score"])
    merged_drop = left["drop"] or right["drop"]
    if not merged_drop:
        return merged_score
    return {
        "score": merged_score,
        "drop": True,
        "sblid": right["sblid"] or left["sblid"],
        "drop_cidr": right["drop_cidr"] or left["drop_cidr"],
    }


def _build_ipsum_drop_compile_entries(
    ipsum_rows: List[Tuple[str, int]],
    drop_rows: List[Tuple[str, Optional[str]]],
) -> List[Tuple[str, Any]]:
    drop_index = PrefixCidrIndex([(cidr, (cidr, sbl_id)) for cidr, sbl_id in drop_rows])
    compiled: List[Tuple[str, Any]] = [
        (cidr, {"score": 0, "drop": True, "sblid": sbl_id, "drop_cidr": cidr}) for cidr, sbl_id in drop_rows
    ]
    for raw_ip_or_cidr, score in ipsum_rows:
        lookup_probe = raw_ip_or_cidr.split("/", 1)[0].strip()
        drop_hit = drop_index.lookup(lookup_probe)
        if drop_hit is not None:
            compiled.append(
                (
                    raw_ip_or_cidr,
                    {
                        "score": score,
                        "drop": True,
                        "sblid": drop_hit[2][1],
                        "drop_cidr": drop_hit[2][0],
                    },
                )
            )
        else:
            compiled.append((raw_ip_or_cidr, score))
    return compiled


def _parse_asn_token(raw_val: str) -> Optional[int]:
    cleaned = raw_val.strip().upper()
    if cleaned.startswith("AS"):
        cleaned = cleaned[2:].strip()
    if cleaned.isdigit():
        parsed = int(cleaned)
        return parsed if parsed > 0 else None
    return None


def _parse_bgp_table_entries(raw_text: str) -> List[Tuple[str, int]]:
    _reject_html_payload(raw_text, "bgp.tools table")
    entries: List[Tuple[str, int]] = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        asn_num = _parse_asn_token(parts[1])
        if asn_num is not None and parse_cidr_to_int_prefix(parts[0]) is not None:
            entries.append((parts[0], asn_num))
    return entries


def _ingest_bgp_tag_row(
    tokens: List[str],
    asn_tags: Dict[int, List[str]],
    tag_counts: Dict[str, int],
) -> None:
    first = tokens[0].strip()
    first_asn = _parse_asn_token(first)
    if first_asn is not None:
        bucket = asn_tags.setdefault(first_asn, [])
        for raw_tag in tokens[1:]:
            cleaned_tag = raw_tag.strip().lower()
            if cleaned_tag and not cleaned_tag.isdigit() and cleaned_tag not in bucket:
                bucket.append(cleaned_tag)
        return

    tag_label = first.lower()
    if not tag_label:
        return
    if len(tokens) == 2 and tokens[1].strip().isdigit() and not tokens[1].strip().upper().startswith("AS"):
        tag_counts[tag_label] = int(tokens[1].strip())
        return

    for candidate in tokens[1:]:
        member_asn = _parse_asn_token(candidate)
        if member_asn is not None:
            bucket = asn_tags.setdefault(member_asn, [])
            if tag_label not in bucket:
                bucket.append(tag_label)


def _parse_bgp_tags_text(raw_text: str) -> Tuple[Dict[int, List[str]], Dict[str, int]]:
    _reject_html_payload(raw_text, "bgp.tools tags")
    asn_tags: Dict[int, List[str]] = {}
    tag_counts: Dict[str, int] = {}

    stripped_all = raw_text.strip()
    if stripped_all.startswith("{"):
        try:
            obj = json.loads(stripped_all)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            source_map = obj.get("asn_tags") if isinstance(obj.get("asn_tags"), dict) else obj
            for k, vals in source_map.items():
                asn_num = _parse_asn_token(str(k))
                if asn_num is not None and isinstance(vals, list):
                    asn_tags[asn_num] = [str(v).strip().lower() for v in vals if str(v).strip()]
            return asn_tags, tag_counts

    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        delimiter_parts = [p.strip() for p in re.split(r"[,\t]+", stripped) if p.strip()]
        tokens = delimiter_parts if len(delimiter_parts) >= 2 else stripped.split()
        if len(tokens) >= 2:
            _ingest_bgp_tag_row(tokens, asn_tags, tag_counts)

    return asn_tags, tag_counts


def _ingest_bgp_tag_category_csv(raw_text: str, category_tag: str, asn_tags: Dict[int, List[str]]) -> None:
    tag_clean = category_tag.strip().lower()
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";", "<")):
            continue
        first_col = stripped.split(",", 1)[0].strip().strip('"')
        asn_num = _parse_asn_token(first_col)
        if asn_num is not None:
            bucket = asn_tags.setdefault(asn_num, [])
            if tag_clean not in bucket:
                bucket.append(tag_clean)


def _is_peeringdb_mobile_entry(entry: Mapping[str, Any]) -> bool:
    info_types = entry.get("info_types")
    if isinstance(info_types, list) and any(str(item).strip().lower() == "mobile" for item in info_types):
        return True
    info_type = entry.get("info_type")
    return isinstance(info_type, str) and info_type.strip().lower() == "mobile"


def _parse_peeringdb_mobile_payload(raw_text: str) -> Dict[str, Any]:
    _reject_html_payload(raw_text, "PeeringDB")
    payload = json.loads(raw_text)
    rows: Iterable[Any]
    if isinstance(payload, dict) and isinstance(payload.get("data"), list):
        rows = payload["data"]
    elif isinstance(payload, list):
        rows = payload
    else:
        raise CommandError("PeeringDB payload did not contain a network data list.")

    mobile_asns: Set[int] = set()
    networks: Dict[str, str] = {}
    for entry in rows:
        if not isinstance(entry, Mapping) or not _is_peeringdb_mobile_entry(entry):
            continue
        raw_asn = entry.get("asn")
        asn_num = raw_asn if isinstance(raw_asn, int) and not isinstance(raw_asn, bool) and raw_asn > 0 else None
        if asn_num is None and isinstance(raw_asn, str):
            asn_num = _parse_asn_token(raw_asn)
        if asn_num is not None:
            mobile_asns.add(asn_num)
            name = str(entry.get("name") or "").strip()
            if name:
                networks[str(asn_num)] = name

    return {
        "mobile_asns": sorted(mobile_asns),
        "networks": networks,
    }


class _OpenAsnUnsupportedError(CommandError):
    """Raised when the OpenASN manifest declares a contract this updater does not understand."""


def _is_transient_openasn_error(exc: Exception) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 404 or status >= 500
    return isinstance(exc, (httpx.TransportError, CommandError, OSError))


def _select_openasn_manifest_entry(manifest: Any) -> Dict[str, Any]:
    """Validates the manifest files entry for openasn.mmdb against the v1 export contract."""
    files = manifest.get("files") if isinstance(manifest, dict) else None
    entry = next(
        (item for item in files or [] if isinstance(item, dict) and item.get("name") == OPENASN_MMDB_FILENAME),
        None,
    )
    if entry is None:
        raise CommandError("OpenASN manifest.json does not list openasn.mmdb.")

    sha256 = entry.get("sha256")
    size = entry.get("bytes")
    if not isinstance(sha256, str) or not _OPENASN_SHA256_RE.fullmatch(sha256):
        raise CommandError("OpenASN manifest entry has an invalid sha256.")
    if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_ARCHIVE_BYTES:
        raise CommandError("OpenASN manifest entry has an invalid byte length.")

    export_meta = entry.get("export")
    if not isinstance(export_meta, dict):
        raise _OpenAsnUnsupportedError("OpenASN manifest entry is missing its export metadata.")
    for key, expected in _OPENASN_EXPORT_CONTRACT.items():
        if export_meta.get(key) != expected:
            raise _OpenAsnUnsupportedError(
                f"Unsupported OpenASN export {key}: {export_meta.get(key)!r} (expected {expected!r})."
            )
    return {"sha256": sha256, "bytes": size}


def _verify_openasn_database_type(candidate: Path) -> None:
    if maxminddb is None:
        raise _OpenAsnUnsupportedError("maxminddb is not installed; cannot verify the OpenASN database.")
    try:
        reader = maxminddb.open_database(str(candidate))
        try:
            database_type = reader.metadata().database_type
        finally:
            reader.close()
    except RuntimeError as exc:
        raise _OpenAsnUnsupportedError(f"OpenASN database is invalid or unreadable: {exc}") from exc
    if database_type != OPENASN_DATABASE_TYPE:
        raise _OpenAsnUnsupportedError(f"Unexpected OpenASN database type: {database_type!r}.")


class Command(BaseCommand):
    help = "Downloads and atomically replaces local offline threat intelligence databases and prefix indexes."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--sources",
            nargs="+",
            default=["all"],
            help=(
                "Sources to update: all, stopforumspam, maxmind, shared_cidrs, privacy_relays, "
                "ipsum_drop, tor_onionoo, bgp_tools, openasn, peeringdb_mobile (space or comma separated)."
            ),
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Bypass local file modification time cooldown checks (still uses conditional requests).",
        )
        parser.add_argument(
            "--skip-listed-1",
            action="store_true",
            help="Skip StopForumSpam 1-day hourly incremental feed and only update toxic CIDR plus 90-day feed.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Check local file ages and report planned actions without downloading or writing files.",
        )
        parser.add_argument(
            "--timeout",
            type=float,
            default=60.0,
            help="HTTP read timeout in seconds for archive downloads (default: 60).",
        )
        parser.add_argument(
            "--data-dir",
            default="",
            help="Override destination directory for offline databases (defaults to TOOL_DATA_DIR/data).",
        )

    def _parse_sources(self, raw_sources: Iterable[str]) -> Set[str]:
        tokens: List[str] = []
        for entry in raw_sources:
            tokens.extend(part.strip().lower() for part in str(entry).split(",") if part.strip())
        if not tokens or "all" in tokens:
            return set(_ALL_CANONICAL_SOURCES)
        unknown = [tok for tok in tokens if tok not in _SOURCE_ALIASES]
        if unknown:
            raise CommandError(f"Unknown --sources value: {', '.join(unknown)}")
        return {_SOURCE_ALIASES[tok] for tok in tokens}

    def _download_sfs_zip(
        self,
        client: httpx.Client,
        *,
        label: str,
        zip_url: str,
        md5_url: str,
        target_path: Path,
        min_interval_seconds: int,
        force: bool,
        dry_run: bool,
    ) -> bool:
        remaining = _check_mtime_cooldown(target_path, min_interval_seconds, force=force)
        if remaining is not None:
            self.stdout.write(
                f"Skipped {label} ({target_path.name}): updated recently, next check allowed in {remaining}s."
            )
            return False

        if dry_run:
            self.stdout.write(f"[dry-run] Would check MD5 and download {label} -> {target_path}")
            return False

        md5_resp = client.get(md5_url)
        md5_resp.raise_for_status()
        expected_md5 = _parse_hex_digest(md5_resp.text, _HEX_32_RE)
        if expected_md5 is None:
            raise CommandError(f"Invalid MD5 checksum payload returned by {md5_url}")

        if not force and target_path.is_file():
            with contextlib.suppress(OSError):
                if _file_md5_hex(target_path) == expected_md5:
                    self.stdout.write(
                        f"Skipped {label} ({target_path.name}): local archive already matches remote MD5."
                    )
                    return False

        tmp_zip = _stream_download_to_temp(client, zip_url, target_path.parent, f".{target_path.name}.tmp.")
        try:
            _validate_sfs_zip_file(tmp_zip, expected_md5)
            replace_temp_file_atomically(tmp_zip, target_path)
        finally:
            if tmp_zip.exists():
                with contextlib.suppress(OSError):
                    tmp_zip.unlink()

        self.stdout.write(self.style.SUCCESS(f"Updated {label} ({target_path.name}, md5={expected_md5})."))
        return True

    def _update_toxic_cidr(self, client: httpx.Client, toxic_target: Path, *, force: bool, dry_run: bool) -> int:
        toxic_wait = _check_mtime_cooldown(toxic_target, SFS_TOXIC_MIN_INTERVAL_SECONDS, force=force)
        if toxic_wait is not None:
            self.stdout.write(
                f"Skipped StopForumSpam Toxic CIDR ({toxic_target.name}): updated recently, wait {toxic_wait}s."
            )
            return 0
        if dry_run:
            self.stdout.write(f"[dry-run] Would download StopForumSpam Toxic CIDR -> {toxic_target}")
            return 0

        try:
            tmp_toxic = _stream_download_to_temp(
                client, SFS_TOXIC_CIDR_URL, toxic_target.parent, f".{toxic_target.name}.tmp."
            )
            try:
                network_count = _validate_toxic_cidr_file(tmp_toxic)
                replace_temp_file_atomically(tmp_toxic, toxic_target)
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Updated StopForumSpam Toxic CIDR ({toxic_target.name}, {network_count} CIDRs)."
                    )
                )
            finally:
                if tmp_toxic.exists():
                    with contextlib.suppress(OSError):
                        tmp_toxic.unlink()
        except _DOWNLOAD_UPDATE_ERRORS as exc:
            self.stderr.write(self.style.ERROR(_redact_update_error(f"Failed StopForumSpam Toxic CIDR update: {exc}")))
            return 1
        return 0

    def _update_stopforumspam(
        self,
        client: httpx.Client,
        *,
        sfs_dir: Path,
        force: bool,
        dry_run: bool,
        skip_listed_1: bool,
    ) -> int:
        toxic_target = sfs_dir / SFS_TOXIC_CIDR_FILENAME
        listed_90_target = sfs_dir / SFS_LISTED_90_ZIP_NAME
        listed_1_target = sfs_dir / SFS_LISTED_1_ZIP_NAME
        sqlite_target = sfs_dir / SFS_SQLITE_FILENAME

        errors = self._update_toxic_cidr(client, toxic_target, force=force, dry_run=dry_run)
        updated_listed = False

        sfs_feeds = [
            (
                "StopForumSpam Listed IPs (90d)",
                SFS_LISTED_90_ZIP_URL,
                SFS_LISTED_90_MD5_URL,
                listed_90_target,
                SFS_90_MIN_INTERVAL_SECONDS,
                "90d",
            )
        ]
        if not skip_listed_1:
            sfs_feeds.append(
                (
                    "StopForumSpam Listed IPs (1d)",
                    SFS_LISTED_1_ZIP_URL,
                    SFS_LISTED_1_MD5_URL,
                    listed_1_target,
                    SFS_1_MIN_INTERVAL_SECONDS,
                    "1d",
                )
            )

        for label, zip_url, md5_url, target_path, min_interval, short_tag in sfs_feeds:
            try:
                if self._download_sfs_zip(
                    client,
                    label=label,
                    zip_url=zip_url,
                    md5_url=md5_url,
                    target_path=target_path,
                    min_interval_seconds=min_interval,
                    force=force,
                    dry_run=dry_run,
                ):
                    updated_listed = True
            except _DOWNLOAD_UPDATE_ERRORS as exc:
                errors += 1
                self.stderr.write(
                    self.style.ERROR(_redact_update_error(f"Failed StopForumSpam {short_tag} update: {exc}"))
                )

        has_any_listed = listed_90_target.is_file() or listed_1_target.is_file()
        if not dry_run and has_any_listed and (updated_listed or not sqlite_target.is_file()):
            try:
                row_count = build_stopforumspam_sqlite_index(
                    sqlite_target,
                    listed_90_target if listed_90_target.is_file() else None,
                    listed_1_target if listed_1_target.is_file() else None,
                )
                clear_stopforumspam_caches()
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Rebuilt StopForumSpam SQLite index ({sqlite_target.name}, {row_count} entries)."
                    )
                )
            except (OSError, sqlite3.Error, ValueError, zipfile.BadZipFile) as exc:
                errors += 1
                self.stderr.write(self.style.ERROR(f"Failed rebuilding StopForumSpam SQLite index: {exc}"))
        return errors

    def _update_maxmind(
        self,
        client: httpx.Client,
        *,
        maxmind_dir: Path,
        force: bool,
        dry_run: bool,
    ) -> int:
        account_id = (os.environ.get("MAXMIND_ACCOUNT_ID") or getattr(settings, "MAXMIND_ACCOUNT_ID", "") or "").strip()
        license_key = (
            os.environ.get("MAXMIND_LICENSE_KEY") or getattr(settings, "MAXMIND_LICENSE_KEY", "") or ""
        ).strip()
        if not account_id or not license_key:
            self.stdout.write(
                self.style.WARNING(
                    "Skipped MaxMind updates: MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY are not configured."
                )
            )
            return 0

        secrets_to_hide = (account_id, license_key)
        errors = 0

        for edition, filename in MAXMIND_EDITION_SPECS:
            target_path = maxmind_dir / filename
            wait_seconds = _check_mtime_cooldown(target_path, MAXMIND_MIN_INTERVAL_SECONDS, force=force)
            if wait_seconds is not None:
                self.stdout.write(
                    f"Skipped {edition} ({filename}): updated recently, next check allowed in {wait_seconds}s."
                )
                continue

            if dry_run:
                self.stdout.write(f"[dry-run] Would check and update {edition} -> {target_path}")
                continue

            tar_url = f"https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz"
            sha_url = f"{tar_url}.sha256"
            tmp_tar: Optional[Path] = None
            try:
                sha_resp = client.get(sha_url, auth=(account_id, license_key))
                sha_resp.raise_for_status()
                expected_sha = _parse_hex_digest(sha_resp.text, _HEX_64_RE)
                if expected_sha is None:
                    raise CommandError(f"Invalid SHA-256 payload returned for {edition}.")

                tmp_tar = _stream_download_to_temp(
                    client,
                    tar_url,
                    maxmind_dir,
                    f".{edition}.tar.gz.tmp.",
                    auth=(account_id, license_key),
                )
                actual_sha = _file_sha256_hex(tmp_tar)
                if actual_sha != expected_sha:
                    raise CommandError(f"SHA-256 mismatch for {edition}: expected {expected_sha}, got {actual_sha}.")
                with atomic_temp_path(target_path, prefix=f".{edition}.mmdb.tmp.") as tmp_mmdb:
                    _extract_mmdb_into_file(tmp_tar, edition, tmp_mmdb)
                self.stdout.write(self.style.SUCCESS(f"Updated {edition} ({filename}, sha256={expected_sha[:12]}...)."))
            except _DOWNLOAD_UPDATE_ERRORS as exc:
                errors += 1
                self.stderr.write(
                    self.style.ERROR(_redact_update_error(f"Failed {edition} update: {exc}", secrets_to_hide))
                )
            finally:
                if tmp_tar is not None and tmp_tar.exists():
                    with contextlib.suppress(OSError):
                        tmp_tar.unlink()

        return errors

    def _fetch_rezmoss_provider_cidrs(
        self,
        client: httpx.Client,
        slug: str,
        *,
        data_dir: Path,
        meta_map: Dict[str, Dict[str, str]],
        target_exists: bool,
    ) -> Tuple[List[str], bool]:
        provider_url = f"{REZMOSS_BASE_URL}/{slug}/{slug}_ips_merged.txt"
        modified = False
        try:
            body, modified = _fetch_conditional_text(
                client,
                provider_url,
                data_dir=data_dir,
                meta_map=meta_map,
                target_exists=target_exists,
                cache_raw=True,
            )
        except _DOWNLOAD_UPDATE_ERRORS as exc:
            cache_file = _url_cache_path(data_dir, provider_url)
            if not cache_file.is_file():
                self.stderr.write(
                    self.style.WARNING(_redact_update_error(f"Failed Rezmoss {slug} fetch ({exc}); skipping."))
                )
                return [], False
            body = cache_file.read_text(encoding="utf-8")
            self.stderr.write(
                self.style.WARNING(_redact_update_error(f"Failed Rezmoss {slug} fetch ({exc}); using cached list."))
            )

        if body is None:
            return [], modified
        try:
            return _parse_plaintext_cidrs(body, f"Rezmoss {slug}"), modified
        except CommandError as exc:
            self.stderr.write(self.style.WARNING(_redact_update_error(f"Invalid Rezmoss {slug} payload: {exc}")))
            return [], modified

    def _update_shared_cidrs(
        self,
        client: httpx.Client,
        *,
        data_dir: Path,
        meta_map: Dict[str, Dict[str, str]],
        force: bool,
        dry_run: bool,
    ) -> int:
        target_path = data_dir / SHARED_CIDRS_BIN_FILENAME
        wait_seconds = _check_mtime_cooldown(target_path, DAILY_FEED_MIN_INTERVAL_SECONDS, force=force)
        if wait_seconds is not None:
            self.stdout.write(f"Skipped Shared CIDRs ({target_path.name}): wait {wait_seconds}s.")
            return 0
        if dry_run:
            self.stdout.write(f"[dry-run] Would compile Rezmoss shared CIDRs index into {target_path}")
            return 0

        target_exists = target_path.is_file()
        try:
            summary_body, summary_modified = _fetch_conditional_text(
                client,
                REZMOSS_SUMMARY_URL,
                data_dir=data_dir,
                meta_map=meta_map,
                target_exists=target_exists,
                cache_raw=True,
            )
            if not summary_modified and target_exists:
                self.stdout.write(f"Skipped Shared CIDRs ({target_path.name}): summary.json returned 304 Not Modified.")
                return 0
            if summary_body is None:
                raise CommandError("Rezmoss summary.json returned no content.")
            slugs = _parse_rezmoss_summary_slugs(summary_body)
        except _DOWNLOAD_UPDATE_ERRORS as exc:
            self.stderr.write(self.style.ERROR(_redact_update_error(f"Failed Shared CIDRs summary fetch: {exc}")))
            return 1

        entries: List[Tuple[str, Dict[str, str]]] = []
        any_modified = summary_modified
        provider_count = 0

        for slug in slugs:
            classified = classify_rezmoss_provider(slug)
            if classified is None:
                continue
            display_label, category = classified
            cidrs, modified = self._fetch_rezmoss_provider_cidrs(
                client,
                slug,
                data_dir=data_dir,
                meta_map=meta_map,
                target_exists=target_exists,
            )
            any_modified = any_modified or modified
            if cidrs:
                payload = {"p": display_label, "c": category}
                provider_count += 1
                entries.extend((cidr, payload) for cidr in cidrs)

        if not any_modified and target_exists:
            self.stdout.write(f"Skipped Shared CIDRs ({target_path.name}): upstream returned 304 Not Modified.")
            return 0
        if not entries:
            self.stderr.write(self.style.ERROR("Failed Shared CIDRs update: no valid CIDR entries collected."))
            return 1

        try:
            rule_count = compile_binary_prefix_index(
                entries,
                target_path,
                merge_payloads=_merge_shared_cidr_payloads,
            )
            clear_offline_intelligence_caches()
            self.stdout.write(
                self.style.SUCCESS(
                    f"Updated Shared CIDRs ({target_path.name}, {rule_count} CIDRs across {provider_count} providers)."
                )
            )
            return 0
        except _DOWNLOAD_UPDATE_ERRORS as exc:
            self.stderr.write(self.style.ERROR(_redact_update_error(f"Failed Shared CIDRs compilation: {exc}")))
            return 1

    def _update_privacy_relays(
        self,
        client: httpx.Client,
        *,
        data_dir: Path,
        meta_map: Dict[str, Dict[str, str]],
        force: bool,
        dry_run: bool,
    ) -> int:
        target_path = data_dir / PRIVACY_RELAYS_BIN_FILENAME
        wait_seconds = _check_mtime_cooldown(target_path, DAILY_FEED_MIN_INTERVAL_SECONDS, force=force)
        if wait_seconds is not None:
            self.stdout.write(f"Skipped Privacy Relays ({target_path.name}): wait {wait_seconds}s.")
            return 0
        if dry_run:
            self.stdout.write(f"[dry-run] Would compile Privacy Relays index into {target_path}")
            return 0

        target_exists = target_path.is_file()
        sub_feeds = (
            ("Apple Private Relay", APPLE_PRIVATE_RELAY_URL, "icloud_private_relay", _parse_geofeed_csv_cidrs),
            ("Cloudflare Local Geofeed", CLOUDFLARE_LOCAL_GEOFEED_URL, "cloudflare_warp", _parse_geofeed_csv_cidrs),
            ("Cloudflare CDN IPv4", CLOUDFLARE_IPS_V4_URL, "cloudflare_cdn", _parse_plaintext_cidrs),
            ("Cloudflare CDN IPv6", CLOUDFLARE_IPS_V6_URL, "cloudflare_cdn", _parse_plaintext_cidrs),
        )
        try:
            any_modified = False
            entries: List[Tuple[str, str]] = []
            for label, url, tag, parser_fn in sub_feeds:
                body, modified = _fetch_conditional_text(
                    client,
                    url,
                    data_dir=data_dir,
                    meta_map=meta_map,
                    target_exists=target_exists,
                    cache_raw=True,
                )
                any_modified = any_modified or modified
                if body is not None:
                    entries.extend((cidr, tag) for cidr in parser_fn(body, label))

            if not any_modified and target_exists:
                self.stdout.write(f"Skipped Privacy Relays ({target_path.name}): upstream returned 304 Not Modified.")
                return 0
            if not entries:
                raise CommandError("Privacy Relays feeds contained no valid IP prefixes.")

            rule_count = compile_binary_prefix_index(
                entries,
                target_path,
                merge_payloads=_merge_privacy_relay_tags,
            )
            clear_offline_intelligence_caches()
            self.stdout.write(self.style.SUCCESS(f"Updated Privacy Relays ({target_path.name}, {rule_count} CIDRs)."))
            return 0
        except _DOWNLOAD_UPDATE_ERRORS as exc:
            self.stderr.write(self.style.ERROR(_redact_update_error(f"Failed Privacy Relays update: {exc}")))
            return 1

    def _update_ipsum_drop(
        self,
        client: httpx.Client,
        *,
        data_dir: Path,
        meta_map: Dict[str, Dict[str, str]],
        force: bool,
        dry_run: bool,
    ) -> int:
        target_path = data_dir / IPSUM_DROP_BIN_FILENAME
        wait_seconds = _check_mtime_cooldown(target_path, DAILY_FEED_MIN_INTERVAL_SECONDS, force=force)
        if wait_seconds is not None:
            self.stdout.write(f"Skipped IPsum and DROP ({target_path.name}): wait {wait_seconds}s.")
            return 0
        if dry_run:
            self.stdout.write(f"[dry-run] Would compile IPsum and Spamhaus DROP index into {target_path}")
            return 0

        target_exists = target_path.is_file()
        try:
            ipsum_body, mod_ipsum = _fetch_conditional_text(
                client,
                IPSUM_URL,
                data_dir=data_dir,
                meta_map=meta_map,
                target_exists=target_exists,
                cache_raw=True,
            )
            drop4_body, mod_drop4 = _fetch_conditional_text(
                client,
                SPAMHAUS_DROP_V4_URL,
                data_dir=data_dir,
                meta_map=meta_map,
                target_exists=target_exists,
                cache_raw=True,
            )
            drop6_body, mod_drop6 = _fetch_conditional_text(
                client,
                SPAMHAUS_DROP_V6_URL,
                data_dir=data_dir,
                meta_map=meta_map,
                target_exists=target_exists,
                cache_raw=True,
            )
            if not (mod_ipsum or mod_drop4 or mod_drop6) and target_exists:
                self.stdout.write(f"Skipped IPsum and DROP ({target_path.name}): upstream returned 304 Not Modified.")
                return 0

            ipsum_rows = _parse_ipsum_entries(ipsum_body or "")
            drop_rows = _parse_spamhaus_drop_entries(drop4_body or "", "Spamhaus DROP v4")
            drop_rows.extend(_parse_spamhaus_drop_entries(drop6_body or "", "Spamhaus DROP v6"))

            compile_entries = _build_ipsum_drop_compile_entries(ipsum_rows, drop_rows)
            if not compile_entries:
                raise CommandError("IPsum and Spamhaus DROP feeds contained no qualifying prefixes.")

            rule_count = compile_binary_prefix_index(
                compile_entries,
                target_path,
                merge_payloads=_merge_ipsum_drop_payloads,
            )
            clear_offline_intelligence_caches()
            self.stdout.write(self.style.SUCCESS(f"Updated IPsum and DROP ({target_path.name}, {rule_count} rules)."))
            return 0
        except _DOWNLOAD_UPDATE_ERRORS as exc:
            self.stderr.write(self.style.ERROR(_redact_update_error(f"Failed IPsum and DROP update: {exc}")))
            return 1

    def _update_tor_onionoo(
        self,
        client: httpx.Client,
        *,
        data_dir: Path,
        meta_map: Dict[str, Dict[str, str]],
        force: bool,
        dry_run: bool,
    ) -> int:
        target_path = data_dir / TOR_ONIONOO_SUMMARY_FILENAME
        wait_seconds = _check_mtime_cooldown(target_path, TOR_ONIONOO_MIN_INTERVAL_SECONDS, force=force)
        if wait_seconds is not None:
            self.stdout.write(f"Skipped Tor Onionoo ({target_path.name}): wait {wait_seconds}s.")
            return 0
        if dry_run:
            self.stdout.write(f"[dry-run] Would sync Tor Onionoo summary mirror into {target_path}")
            return 0

        try:
            body, modified = _fetch_conditional_text(
                client,
                TOR_ONIONOO_SUMMARY_URL,
                data_dir=data_dir,
                meta_map=meta_map,
                target_exists=target_path.is_file(),
                cache_raw=False,
                extra_headers={"Accept-Encoding": "gzip"},
            )
            if not modified or body is None:
                self.stdout.write(f"Skipped Tor Onionoo ({target_path.name}): upstream returned 304 Not Modified.")
                return 0

            _reject_html_payload(body, "Tor Onionoo")
            parsed = json.loads(body)
            if not isinstance(parsed, dict) or not isinstance(parsed.get("relays"), list):
                raise CommandError("Tor Onionoo summary payload missing relays array.")

            _write_json_atomically(parsed, target_path)
            clear_offline_intelligence_caches()
            self.stdout.write(
                self.style.SUCCESS(f"Updated Tor Onionoo ({target_path.name}, {len(parsed['relays'])} relays).")
            )
            return 0
        except _DOWNLOAD_UPDATE_ERRORS as exc:
            self.stderr.write(self.style.ERROR(_redact_update_error(f"Failed Tor Onionoo update: {exc}")))
            return 1

    def _enrich_bgp_category_tags(
        self,
        client: httpx.Client,
        *,
        data_dir: Path,
        meta_map: Dict[str, Dict[str, str]],
        target_exists: bool,
        bgp_headers: Mapping[str, str],
        tag_counts: Mapping[str, int],
        asn_tags: Dict[int, List[str]],
    ) -> bool:
        modified_any = False
        category_urls = (
            ("mobile", BGP_TOOLS_MOBILE_TAG_CSV_URL),
            ("vpn", BGP_TOOLS_VPN_TAG_CSV_URL),
        )
        for category_name, csv_url in category_urls:
            if tag_counts and category_name not in tag_counts:
                continue
            with contextlib.suppress(*_DOWNLOAD_UPDATE_ERRORS):
                csv_body, csv_mod = _fetch_conditional_text(
                    client,
                    csv_url,
                    data_dir=data_dir,
                    meta_map=meta_map,
                    target_exists=target_exists,
                    cache_raw=True,
                    extra_headers=bgp_headers,
                )
                modified_any = modified_any or csv_mod
                if csv_body:
                    _ingest_bgp_tag_category_csv(csv_body, category_name, asn_tags)
        return modified_any

    def _update_bgp_tools(
        self,
        client: httpx.Client,
        *,
        data_dir: Path,
        meta_map: Dict[str, Dict[str, str]],
        force: bool,
        dry_run: bool,
    ) -> int:
        bin_target = data_dir / BGP_TOOLS_BIN_FILENAME
        tags_target = data_dir / BGP_TAGS_JSON_FILENAME
        wait_seconds = _check_mtime_cooldown(bin_target, DAILY_FEED_MIN_INTERVAL_SECONDS, force=force)
        if wait_seconds is not None and tags_target.is_file():
            self.stdout.write(f"Skipped BGP Tools ({bin_target.name}): wait {wait_seconds}s.")
            return 0
        if dry_run:
            self.stdout.write(f"[dry-run] Would compile bgp.tools routing table into {bin_target}")
            return 0

        both_exist = bin_target.is_file() and tags_target.is_file()
        bgp_headers = {"User-Agent": BGP_TOOLS_USER_AGENT}
        try:
            table_body, mod_table = _fetch_conditional_text(
                client,
                BGP_TOOLS_TABLE_URL,
                data_dir=data_dir,
                meta_map=meta_map,
                target_exists=both_exist,
                cache_raw=True,
                extra_headers=bgp_headers,
            )
            tags_body, mod_tags = _fetch_conditional_text(
                client,
                BGP_TOOLS_TAGS_URL,
                data_dir=data_dir,
                meta_map=meta_map,
                target_exists=both_exist,
                cache_raw=True,
                extra_headers=bgp_headers,
            )
            asn_tags, tag_counts = _parse_bgp_tags_text(tags_body or "")
            mod_extra = False
            if tag_counts and not asn_tags:
                mod_extra = self._enrich_bgp_category_tags(
                    client,
                    data_dir=data_dir,
                    meta_map=meta_map,
                    target_exists=both_exist,
                    bgp_headers=bgp_headers,
                    tag_counts=tag_counts,
                    asn_tags=asn_tags,
                )

            if not (mod_table or mod_tags or mod_extra) and both_exist:
                self.stdout.write(f"Skipped BGP Tools ({bin_target.name}): upstream returned 304 Not Modified.")
                return 0

            table_entries = _parse_bgp_table_entries(table_body or "")
            if not table_entries:
                raise CommandError("bgp.tools table feed contained no valid prefix announcements.")

            rule_count = compile_binary_prefix_index(table_entries, bin_target)
            mobile_asns = sorted(
                asn_num for asn_num, tags in asn_tags.items() if any(tag in MOBILE_BGP_TAG_TOKENS for tag in tags)
            )
            tags_payload = {
                "asn_tags": {str(k): v for k, v in sorted(asn_tags.items())},
                "mobile_asns": mobile_asns,
                "tag_counts": tag_counts,
            }
            _write_json_atomically(tags_payload, tags_target)
            clear_offline_intelligence_caches()
            self.stdout.write(self.style.SUCCESS(f"Updated BGP Tools ({bin_target.name}, {rule_count} prefixes)."))
            return 0
        except _DOWNLOAD_UPDATE_ERRORS as exc:
            self.stderr.write(self.style.ERROR(_redact_update_error(f"Failed BGP Tools update: {exc}")))
            return 1

    def _fetch_openasn_manifest_entry(self, client: httpx.Client) -> Dict[str, Any]:
        resp = client.get(OPENASN_MANIFEST_URL)
        resp.raise_for_status()
        raw_bytes = resp.content
        if not isinstance(raw_bytes, (bytes, bytearray)) or not raw_bytes:
            raise CommandError("OpenASN manifest.json was empty.")
        if len(raw_bytes) > OPENASN_MANIFEST_MAX_BYTES:
            raise _OpenAsnUnsupportedError("OpenASN manifest.json exceeded the size limit.")
        try:
            manifest = json.loads(bytes(raw_bytes).decode("utf-8"))
        except ValueError as exc:
            raise CommandError(f"OpenASN manifest.json was not valid JSON: {exc}") from exc
        return _select_openasn_manifest_entry(manifest)

    def _install_openasn_once(
        self,
        client: httpx.Client,
        *,
        target_path: Path,
        force: bool,
    ) -> bool:
        """Runs one verified OpenASN download attempt, returning False when the local file is already current."""
        entry = self._fetch_openasn_manifest_entry(client)
        expected_sha = entry["sha256"]
        expected_bytes = entry["bytes"]

        if not force and target_path.is_file():
            with contextlib.suppress(OSError):
                if _file_sha256_hex(target_path) == expected_sha:
                    self.stdout.write(f"Skipped OpenASN ({target_path.name}): local file already matches manifest.")
                    return False

        tmp_path = _stream_download_to_temp(client, OPENASN_MMDB_URL, target_path.parent, f".{target_path.name}.tmp.")
        try:
            actual_bytes = tmp_path.stat().st_size
            if actual_bytes != expected_bytes:
                raise CommandError(f"OpenASN size mismatch: expected {expected_bytes} bytes, got {actual_bytes}.")
            actual_sha = _file_sha256_hex(tmp_path)
            if actual_sha != expected_sha:
                raise CommandError(f"OpenASN SHA-256 mismatch: expected {expected_sha}, got {actual_sha}.")
            _verify_openasn_database_type(tmp_path)
            replace_temp_file_atomically(tmp_path, target_path)
        finally:
            if tmp_path.exists():
                with contextlib.suppress(OSError):
                    tmp_path.unlink()
        return True

    def _update_openasn(
        self,
        client: httpx.Client,
        *,
        data_dir: Path,
        meta_map: Dict[str, Dict[str, str]],
        force: bool,
        dry_run: bool,
    ) -> int:
        target_path = data_dir / OPENASN_MMDB_FILENAME
        wait_seconds = _check_mtime_cooldown(target_path, DAILY_FEED_MIN_INTERVAL_SECONDS, force=force)
        if wait_seconds is not None:
            self.stdout.write(f"Skipped OpenASN ({target_path.name}): wait {wait_seconds}s.")
            return 0
        if dry_run:
            self.stdout.write(f"[dry-run] Would verify manifest and download OpenASN into {target_path}")
            return 0

        last_error: Optional[Exception] = None
        for attempt in range(OPENASN_MAX_ATTEMPTS):
            try:
                installed = self._install_openasn_once(client, target_path=target_path, force=force)
            except _OpenAsnUnsupportedError as exc:
                last_error = exc
                break
            except _DOWNLOAD_UPDATE_ERRORS as exc:
                last_error = exc
                if not _is_transient_openasn_error(exc):
                    break
                if attempt + 1 < OPENASN_MAX_ATTEMPTS:
                    time.sleep(OPENASN_RETRY_BACKOFF_SECONDS[attempt])
                continue
            if installed:
                clear_maxmind_readers()
                clear_offline_intelligence_caches()
                self.stdout.write(self.style.SUCCESS(f"Updated OpenASN ({target_path.name})."))
            return 0

        self.stderr.write(self.style.ERROR(_redact_update_error(f"Failed OpenASN update: {last_error}")))
        return 1

    def _update_peeringdb_mobile(
        self,
        client: httpx.Client,
        *,
        data_dir: Path,
        meta_map: Dict[str, Dict[str, str]],
        force: bool,
        dry_run: bool,
    ) -> int:
        target_path = data_dir / MOBILE_ASNS_JSON_FILENAME
        wait_seconds = _check_mtime_cooldown(target_path, DAILY_FEED_MIN_INTERVAL_SECONDS, force=force)
        if wait_seconds is not None:
            self.stdout.write(f"Skipped PeeringDB Mobile ({target_path.name}): wait {wait_seconds}s.")
            return 0
        if dry_run:
            self.stdout.write(f"[dry-run] Would fetch PeeringDB mobile ASNs into {target_path}")
            return 0

        try:
            body, modified = _fetch_conditional_text(
                client,
                PEERINGDB_NET_URL,
                data_dir=data_dir,
                meta_map=meta_map,
                target_exists=target_path.is_file(),
                cache_raw=False,
            )
            if not modified or body is None:
                self.stdout.write(f"Skipped PeeringDB Mobile ({target_path.name}): upstream returned 304 Not Modified.")
                return 0

            parsed = _parse_peeringdb_mobile_payload(body)
            _write_json_atomically(parsed, target_path)
            clear_offline_intelligence_caches()
            self.stdout.write(
                self.style.SUCCESS(
                    f"Updated PeeringDB Mobile ({target_path.name}, {len(parsed['mobile_asns'])} mobile ASNs)."
                )
            )
            return 0
        except _DOWNLOAD_UPDATE_ERRORS as exc:
            self.stderr.write(self.style.ERROR(_redact_update_error(f"Failed PeeringDB Mobile update: {exc}")))
            return 1

    def _resolve_and_validate_data_dir(self, explicit_data_dir: str, *, dry_run: bool) -> Path:
        cleaned_explicit = explicit_data_dir.strip()
        configured_data_dir = resolve_configured_data_dir()
        data_dir = resolve_writable_data_dir(cleaned_explicit)

        if not cleaned_explicit and not configured_data_dir:
            self.stdout.write(f"TOOL_DATA_DIR is not set; using default offline data directory: {data_dir}")

        if data_dir.exists() and not data_dir.is_dir():
            raise CommandError(f"Offline database target path is not a directory: {data_dir}")

        if not dry_run:
            try:
                data_dir.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(dir=data_dir, prefix=".write_probe_", delete=True):
                    pass
            except OSError as exc:
                raise CommandError(f"Offline database directory is not writable ({data_dir}): {exc}") from exc

        return data_dir

    def _dispatch_selected_sources(
        self,
        client: httpx.Client,
        selected: Set[str],
        *,
        data_dir: Path,
        meta_map: Dict[str, Dict[str, str]],
        force: bool,
        dry_run: bool,
        skip_listed_1: bool,
    ) -> int:
        total_errors = 0
        if "stopforumspam" in selected:
            total_errors += self._update_stopforumspam(
                client,
                sfs_dir=data_dir,
                force=force,
                dry_run=dry_run,
                skip_listed_1=skip_listed_1,
            )
        if "maxmind" in selected:
            total_errors += self._update_maxmind(client, maxmind_dir=data_dir, force=force, dry_run=dry_run)

        conditional_handlers = (
            ("shared_cidrs", self._update_shared_cidrs),
            ("privacy_relays", self._update_privacy_relays),
            ("ipsum_drop", self._update_ipsum_drop),
            ("tor_onionoo", self._update_tor_onionoo),
            ("bgp_tools", self._update_bgp_tools),
            ("openasn", self._update_openasn),
            ("peeringdb_mobile", self._update_peeringdb_mobile),
        )
        for key, handler in conditional_handlers:
            if key in selected:
                total_errors += handler(client, data_dir=data_dir, meta_map=meta_map, force=force, dry_run=dry_run)
        return total_errors

    def handle(self, *args, **options) -> None:
        selected = self._parse_sources(options.get("sources") or ["all"])
        force = bool(options.get("force"))
        dry_run = bool(options.get("dry_run"))
        skip_listed_1 = bool(options.get("skip_listed_1"))
        timeout = float(options.get("timeout") or 60.0)
        if timeout <= 0:
            raise CommandError("--timeout must be greater than zero.")

        data_dir = self._resolve_and_validate_data_dir(str(options.get("data_dir") or ""), dry_run=dry_run)
        meta_map = _load_http_feed_metadata(data_dir)
        initial_meta = json.dumps(meta_map, sort_keys=True)

        with httpx.Client(
            timeout=httpx.Timeout(timeout, connect=10.0),
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT_HEADER},
        ) as client:
            total_errors = self._dispatch_selected_sources(
                client,
                selected,
                data_dir=data_dir,
                meta_map=meta_map,
                force=force,
                dry_run=dry_run,
                skip_listed_1=skip_listed_1,
            )

        if not dry_run and json.dumps(meta_map, sort_keys=True) != initial_meta:
            _save_http_feed_metadata(data_dir, meta_map)

        if total_errors > 0:
            raise CommandError(f"Offline database update finished with {total_errors} error(s).")
