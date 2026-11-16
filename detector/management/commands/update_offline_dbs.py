"""Management command to safely download and atomically replace offline intelligence databases."""

from __future__ import annotations

import contextlib
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
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import httpx
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from detector.adapters import _parse_cloud_cidr_payload, clear_offline_intelligence_caches
from detector.offline_dbs import (
    SFS_SQLITE_FILENAME,
    SFS_TOXIC_CIDR_FILENAME,
    build_stopforumspam_sqlite_index,
    clear_stopforumspam_caches,
    resolve_configured_data_dir,
    resolve_writable_data_dir,
)
from detector.offline_dbs import (
    atomic_replace_with_retry as _atomic_replace,
)
from detector.views import USER_AGENT_HEADER
from proxycheck.settings import (
    MAXMIND_ASN_DB_FILENAME,
    MAXMIND_CITY_DB_FILENAME,
    MAXMIND_COUNTRY_DB_FILENAME,
)

try:
    import maxminddb
except ImportError:
    maxminddb = None

SFS_BASE_URL = "https://www.stopforumspam.com/downloads"
SFS_TOXIC_CIDR_URL = f"{SFS_BASE_URL}/{SFS_TOXIC_CIDR_FILENAME}"
SFS_LISTED_90_ZIP_NAME = "listed_ip_90_ipv46_all.zip"
SFS_LISTED_90_ZIP_URL = f"{SFS_BASE_URL}/{SFS_LISTED_90_ZIP_NAME}"
SFS_LISTED_90_MD5_URL = f"{SFS_LISTED_90_ZIP_URL}.md5"
SFS_LISTED_1_ZIP_NAME = "listed_ip_1_ipv46_all.zip"
SFS_LISTED_1_ZIP_URL = f"{SFS_BASE_URL}/{SFS_LISTED_1_ZIP_NAME}"
SFS_LISTED_1_MD5_URL = f"{SFS_LISTED_1_ZIP_URL}.md5"

# Guard windows stay comfortably below StopForumSpam daily caps of 2 per day for 90d and 24 per day for 1d
# whilst accommodating minor cron or systemd timer drift.
SFS_TOXIC_MIN_INTERVAL_SECONDS = 12 * 3600 - 300
SFS_90_MIN_INTERVAL_SECONDS = 12 * 3600 - 300
SFS_1_MIN_INTERVAL_SECONDS = 3600 - 120
MAXMIND_MIN_INTERVAL_SECONDS = 24 * 3600 - 300
CLOUD_CIDRS_MIN_INTERVAL_SECONDS = 24 * 3600 - 300

CLOUD_CIDRS_FILENAME = "cloud_cidrs.json"
AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_IP_RANGES_URL = "https://www.gstatic.com/ipranges/cloud.json"
OCI_IP_RANGES_URL = "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"
AZURE_DOWNLOAD_PAGE_URL = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
_AZURE_SERVICETAGS_URL_RE = re.compile(
    r"https://download\.microsoft\.com/download/[^\"'\s<>]+/ServiceTags_Public_\d+\.json"
)

MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
_HEX_32_RE = re.compile(r"\b([0-9a-fA-F]{32})\b")
_HEX_64_RE = re.compile(r"\b([0-9a-fA-F]{64})\b")

MAXMIND_EDITION_SPECS: Tuple[Tuple[str, str], ...] = (
    ("GeoLite2-Country", MAXMIND_COUNTRY_DB_FILENAME),
    ("GeoLite2-City", MAXMIND_CITY_DB_FILENAME),
    ("GeoLite2-ASN", MAXMIND_ASN_DB_FILENAME),
)
_DOWNLOAD_UPDATE_ERRORS = (httpx.HTTPError, CommandError, OSError, ValueError, tarfile.TarError, zipfile.BadZipFile)


def _file_md5_hex(file_path: Path) -> str:
    hasher = hashlib.md5(usedforsecurity=False)
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def _file_sha256_hex(file_path: Path) -> str:
    hasher = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


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


def _redact_text(message: str, secrets_to_hide: Iterable[str]) -> str:
    cleaned = message
    for secret in secrets_to_hide:
        if secret:
            cleaned = cleaned.replace(secret, "[REDACTED]")
    return cleaned


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
        request_kwargs: Dict[str, object] = {}
        if auth is not None:
            request_kwargs["auth"] = auth
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
            token = stripped.split()[0]
            try:
                ipaddress.ip_network(token, strict=False)
                valid_networks += 1
            except ValueError:
                continue
    if valid_networks <= 0:
        raise CommandError("Toxic CIDR download contained no valid IP networks.")
    return valid_networks


def _validate_sfs_zip_file(zip_path: Path, expected_md5: Optional[str]) -> int:
    if expected_md5 is not None:
        actual_md5 = _file_md5_hex(zip_path)
        if actual_md5 != expected_md5:
            raise CommandError(f"MD5 mismatch for {zip_path.name}: expected {expected_md5}, got {actual_md5}.")
    if not zipfile.is_zipfile(zip_path):
        raise CommandError(f"Downloaded file {zip_path.name} is not a valid zip archive.")
    sample_ips = 0
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
    if sample_ips <= 0:
        raise CommandError("StopForumSpam zip archive did not contain recognisable IP records.")
    return sample_ips


def _extract_mmdb_from_tar_gz(tar_path: Path, edition_name: str, target_dir: Path) -> Path:
    expected_basename = f"{edition_name}.mmdb"
    fd, tmp_mmdb_name = tempfile.mkstemp(prefix=f".{expected_basename}.tmp.", dir=str(target_dir))
    os.close(fd)
    tmp_mmdb_path = Path(tmp_mmdb_name)
    try:
        with tarfile.open(tar_path, "r:gz") as archive:
            target_member = None
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                if Path(member.name).name == expected_basename:
                    target_member = member
                    break
            if target_member is None:
                raise CommandError(f"Could not find {expected_basename} inside MaxMind archive.")
            extracted = archive.extractfile(target_member)
            if extracted is None:
                raise CommandError(f"Failed to read {expected_basename} from MaxMind archive.")
            written = 0
            with extracted, tmp_mmdb_path.open("wb") as out_handle:
                for chunk in iter(lambda: extracted.read(65536), b""):
                    written += len(chunk)
                    if written > MAX_ARCHIVE_BYTES:
                        raise CommandError(f"Extracted {expected_basename} exceeded safety size limit.")
                    out_handle.write(chunk)
            if written <= 0:
                raise CommandError(f"Extracted {expected_basename} is empty.")

        if maxminddb is not None:
            reader = maxminddb.open_database(str(tmp_mmdb_path))
            try:
                _ = reader.metadata()
            finally:
                reader.close()
        return tmp_mmdb_path
    except Exception:
        with contextlib.suppress(OSError):
            tmp_mmdb_path.unlink()
        raise


def _normalize_cidr_list(raw_cidrs: Iterable[Any]) -> List[str]:
    """Validates, normalises, and deduplicates raw CIDR strings in deterministic order."""
    seen: set[str] = set()
    for raw in raw_cidrs:
        if not isinstance(raw, str):
            continue
        cleaned = raw.strip()
        if not cleaned:
            continue
        try:
            net = ipaddress.ip_network(cleaned, strict=False)
        except ValueError:
            continue
        seen.add(str(net))
    return sorted(seen)


def _parse_aws_cloud_cidrs(payload: Any) -> List[str]:
    if not isinstance(payload, dict):
        raise CommandError("AWS IP ranges payload was not a JSON object.")
    raw: List[Any] = []
    for key, field in (("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")):
        items = payload.get(key)
        if isinstance(items, list):
            raw.extend(entry.get(field) for entry in items if isinstance(entry, dict))
    return _normalize_cidr_list(raw)


def _parse_gcp_cloud_cidrs(payload: Any) -> List[str]:
    if not isinstance(payload, dict):
        raise CommandError("GCP IP ranges payload was not a JSON object.")
    prefixes = payload.get("prefixes")
    if not isinstance(prefixes, list):
        raise CommandError("GCP IP ranges payload missing prefixes list.")
    raw: List[Any] = []
    for entry in prefixes:
        if isinstance(entry, dict):
            raw.append(entry.get("ipv4Prefix"))
            raw.append(entry.get("ipv6Prefix"))
    return _normalize_cidr_list(raw)


def _parse_oci_cloud_cidrs(payload: Any) -> List[str]:
    if not isinstance(payload, dict):
        raise CommandError("OCI IP ranges payload was not a JSON object.")
    regions = payload.get("regions")
    if not isinstance(regions, list):
        raise CommandError("OCI IP ranges payload missing regions list.")
    raw: List[Any] = []
    for region in regions:
        if not isinstance(region, dict):
            continue
        cidrs = region.get("cidrs")
        if isinstance(cidrs, list):
            raw.extend(item.get("cidr") for item in cidrs if isinstance(item, dict))
    return _normalize_cidr_list(raw)


def _extract_azure_servicetags_url(html_text: str) -> str:
    match = _AZURE_SERVICETAGS_URL_RE.search(html_text or "")
    if match is None:
        raise CommandError("Could not locate ServiceTags_Public JSON download URL on Microsoft download page.")
    return match.group(0)


def _parse_azure_cloud_cidrs(payload: Any) -> List[str]:
    if not isinstance(payload, dict):
        raise CommandError("Azure ServiceTags payload was not a JSON object.")
    values = payload.get("values")
    if not isinstance(values, list):
        raise CommandError("Azure ServiceTags payload missing values list.")
    raw: List[Any] = []
    for entry in values:
        if not isinstance(entry, dict):
            continue
        props = entry.get("properties")
        if isinstance(props, dict) and isinstance(props.get("addressPrefixes"), list):
            raw.extend(props["addressPrefixes"])
    return _normalize_cidr_list(raw)


def _fetch_json_payload(client: httpx.Client, url: str) -> Any:
    resp = client.get(url)
    resp.raise_for_status()
    json_fn = getattr(resp, "json", None)
    if callable(json_fn):
        return json_fn()
    return json.loads(resp.text)


def _fetch_azure_cloud_cidrs(client: httpx.Client) -> List[str]:
    page_resp = client.get(AZURE_DOWNLOAD_PAGE_URL)
    page_resp.raise_for_status()
    json_url = _extract_azure_servicetags_url(page_resp.text)
    return _parse_azure_cloud_cidrs(_fetch_json_payload(client, json_url))


_CLOUD_CIDR_SOURCES: Tuple[Tuple[str, Callable[[httpx.Client], List[str]]], ...] = (
    ("Amazon AWS", lambda client: _parse_aws_cloud_cidrs(_fetch_json_payload(client, AWS_IP_RANGES_URL))),
    ("Google Cloud", lambda client: _parse_gcp_cloud_cidrs(_fetch_json_payload(client, GCP_IP_RANGES_URL))),
    ("Oracle Cloud", lambda client: _parse_oci_cloud_cidrs(_fetch_json_payload(client, OCI_IP_RANGES_URL))),
    ("Microsoft Azure", _fetch_azure_cloud_cidrs),
)


def _load_existing_cloud_cidrs_by_provider(target_path: Path) -> Dict[str, List[str]]:
    if not target_path.is_file():
        return {}
    try:
        payload = json.loads(target_path.read_text(encoding="utf-8"))
    except OSError, ValueError:
        return {}
    grouped: Dict[str, List[str]] = {}
    for raw_cidr, provider_name in _parse_cloud_cidr_payload(payload):
        grouped.setdefault(provider_name, []).append(raw_cidr)
    return {provider: _normalize_cidr_list(cidrs) for provider, cidrs in grouped.items()}


def _write_json_atomically(payload: Dict[str, List[str]], target_path: Path) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target_path.name}.tmp.", dir=str(target_path.parent))
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        with contextlib.suppress(OSError):
            os.chmod(tmp_path, 0o644)
        _atomic_replace(tmp_path, target_path)
    finally:
        if tmp_path.exists():
            with contextlib.suppress(OSError):
                tmp_path.unlink()


class Command(BaseCommand):
    help = "Downloads and atomically replaces local StopForumSpam, MaxMind, and cloud CIDR offline databases."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--sources",
            nargs="+",
            default=["all"],
            help="Sources to update: all, stopforumspam, maxmind, cloud_cidrs (space or comma separated).",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Bypass local file modification time cooldown checks (still verifies checksums).",
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

    def _parse_sources(self, raw_sources: Iterable[str]) -> Tuple[bool, bool, bool]:
        tokens: List[str] = []
        for entry in raw_sources:
            for part in str(entry).split(","):
                cleaned = part.strip().lower()
                if cleaned:
                    tokens.append(cleaned)
        if not tokens or "all" in tokens:
            return True, True, True
        valid_tokens = {"stopforumspam", "sfs", "maxmind", "cloud_cidrs", "cloud-cidrs", "cloud", "all"}
        unknown = [tok for tok in tokens if tok not in valid_tokens]
        if unknown:
            raise CommandError(f"Unknown --sources value: {', '.join(unknown)}")
        return (
            "stopforumspam" in tokens or "sfs" in tokens,
            "maxmind" in tokens,
            any(tok in tokens for tok in ("cloud_cidrs", "cloud-cidrs", "cloud")),
        )

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
            with contextlib.suppress(OSError):
                os.chmod(tmp_zip, 0o644)
            _atomic_replace(tmp_zip, target_path)
        finally:
            if tmp_zip.exists():
                with contextlib.suppress(OSError):
                    tmp_zip.unlink()

        self.stdout.write(self.style.SUCCESS(f"Updated {label} ({target_path.name}, md5={expected_md5})."))
        return True

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

        errors = 0
        updated_listed = False

        toxic_wait = _check_mtime_cooldown(toxic_target, SFS_TOXIC_MIN_INTERVAL_SECONDS, force=force)
        if toxic_wait is not None:
            self.stdout.write(
                f"Skipped StopForumSpam Toxic CIDR ({toxic_target.name}): updated recently, wait {toxic_wait}s."
            )
        elif dry_run:
            self.stdout.write(f"[dry-run] Would download StopForumSpam Toxic CIDR -> {toxic_target}")
        else:
            try:
                tmp_toxic = _stream_download_to_temp(client, SFS_TOXIC_CIDR_URL, sfs_dir, f".{toxic_target.name}.tmp.")
                try:
                    network_count = _validate_toxic_cidr_file(tmp_toxic)
                    with contextlib.suppress(OSError):
                        os.chmod(tmp_toxic, 0o644)
                    _atomic_replace(tmp_toxic, toxic_target)
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
                errors += 1
                self.stderr.write(self.style.ERROR(f"Failed StopForumSpam Toxic CIDR update: {exc}"))

        try:
            if self._download_sfs_zip(
                client,
                label="StopForumSpam Listed IPs (90d)",
                zip_url=SFS_LISTED_90_ZIP_URL,
                md5_url=SFS_LISTED_90_MD5_URL,
                target_path=listed_90_target,
                min_interval_seconds=SFS_90_MIN_INTERVAL_SECONDS,
                force=force,
                dry_run=dry_run,
            ):
                updated_listed = True
        except _DOWNLOAD_UPDATE_ERRORS as exc:
            errors += 1
            self.stderr.write(self.style.ERROR(f"Failed StopForumSpam 90d update: {exc}"))

        if not skip_listed_1:
            try:
                if self._download_sfs_zip(
                    client,
                    label="StopForumSpam Listed IPs (1d)",
                    zip_url=SFS_LISTED_1_ZIP_URL,
                    md5_url=SFS_LISTED_1_MD5_URL,
                    target_path=listed_1_target,
                    min_interval_seconds=SFS_1_MIN_INTERVAL_SECONDS,
                    force=force,
                    dry_run=dry_run,
                ):
                    updated_listed = True
            except _DOWNLOAD_UPDATE_ERRORS as exc:
                errors += 1
                self.stderr.write(self.style.ERROR(f"Failed StopForumSpam 1d update: {exc}"))

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
            tmp_mmdb: Optional[Path] = None
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
                tmp_mmdb = _extract_mmdb_from_tar_gz(tmp_tar, edition, maxmind_dir)
                with contextlib.suppress(OSError):
                    os.chmod(tmp_mmdb, 0o644)
                _atomic_replace(tmp_mmdb, target_path)
                self.stdout.write(self.style.SUCCESS(f"Updated {edition} ({filename}, sha256={expected_sha[:12]}...)."))
            except _DOWNLOAD_UPDATE_ERRORS as exc:
                errors += 1
                self.stderr.write(self.style.ERROR(_redact_text(f"Failed {edition} update: {exc}", secrets_to_hide)))
            finally:
                for leftover in (tmp_tar, tmp_mmdb):
                    if leftover is not None and leftover.exists():
                        with contextlib.suppress(OSError):
                            leftover.unlink()

        return errors

    def _update_cloud_cidrs(
        self,
        client: httpx.Client,
        *,
        data_dir: Path,
        force: bool,
        dry_run: bool,
    ) -> int:
        target_path = data_dir / CLOUD_CIDRS_FILENAME
        wait_seconds = _check_mtime_cooldown(target_path, CLOUD_CIDRS_MIN_INTERVAL_SECONDS, force=force)
        if wait_seconds is not None:
            self.stdout.write(
                f"Skipped Cloud CIDRs ({target_path.name}): updated recently, next check allowed in {wait_seconds}s."
            )
            return 0
        if dry_run:
            self.stdout.write(f"[dry-run] Would fetch AWS/GCP/OCI/Azure IP ranges -> {target_path}")
            return 0

        existing_by_provider = _load_existing_cloud_cidrs_by_provider(target_path)
        merged: Dict[str, List[str]] = {}
        fetched_count = 0

        for provider_name, fetcher in _CLOUD_CIDR_SOURCES:
            try:
                cidrs = fetcher(client)
                if not cidrs:
                    raise CommandError(f"{provider_name} returned no valid IP networks.")
                merged[provider_name] = cidrs
                fetched_count += 1
            except (*_DOWNLOAD_UPDATE_ERRORS, KeyError, TypeError) as exc:
                historical = existing_by_provider.get(provider_name, [])
                if historical:
                    merged[provider_name] = historical
                    self.stderr.write(
                        self.style.WARNING(
                            f"Failed {provider_name} CIDR fetch ({exc}); retaining {len(historical)} historical CIDRs."
                        )
                    )
                else:
                    self.stderr.write(
                        self.style.WARNING(f"Failed {provider_name} CIDR fetch ({exc}); no fallback data.")
                    )

        total_cidrs = sum(len(v) for v in merged.values())
        if fetched_count == 0 and total_cidrs == 0:
            self.stderr.write(self.style.ERROR("Failed Cloud CIDRs update: all providers failed with no fallback."))
            return 1

        _write_json_atomically(merged, target_path)
        clear_offline_intelligence_caches()
        self.stdout.write(
            self.style.SUCCESS(
                f"Updated Cloud CIDRs ({target_path.name}, {total_cidrs} CIDRs across {len(merged)} providers)."
            )
        )
        return 0

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

    def handle(self, *args, **options) -> None:
        update_sfs, update_maxmind, update_cloud_cidrs = self._parse_sources(options.get("sources") or ["all"])
        force = bool(options.get("force"))
        dry_run = bool(options.get("dry_run"))
        skip_listed_1 = bool(options.get("skip_listed_1"))
        timeout = float(options.get("timeout") or 60.0)
        if timeout <= 0:
            raise CommandError("--timeout must be greater than zero.")

        data_dir = self._resolve_and_validate_data_dir(str(options.get("data_dir") or ""), dry_run=dry_run)

        total_errors = 0
        with httpx.Client(
            timeout=httpx.Timeout(timeout, connect=10.0),
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT_HEADER},
        ) as client:
            if update_sfs:
                total_errors += self._update_stopforumspam(
                    client,
                    sfs_dir=data_dir,
                    force=force,
                    dry_run=dry_run,
                    skip_listed_1=skip_listed_1,
                )
            if update_maxmind:
                total_errors += self._update_maxmind(
                    client,
                    maxmind_dir=data_dir,
                    force=force,
                    dry_run=dry_run,
                )
            if update_cloud_cidrs:
                total_errors += self._update_cloud_cidrs(
                    client,
                    data_dir=data_dir,
                    force=force,
                    dry_run=dry_run,
                )

        if total_errors > 0:
            raise CommandError(f"Offline database update finished with {total_errors} error(s).")
