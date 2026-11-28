"""Environment variable specifications, job schemas, and redaction helpers for setup diagnostics."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from django.db import Error as DjangoDbError

from ..offline.feeds import OFFLINE_DATASET_SPECS
from ..provider_registry import PROVIDER_REGISTRY

try:
    import pymysql
    from pymysql.err import MySQLError as _PyMySqlError
except ImportError:
    pymysql = None
    _PyMySqlError = None

ENV_MODES = ("auto", "bastion", "local")
DEFAULT_PRODUCTION_REDIRECT_URI = "https://proxycheck.toolforge.org/oauth/callback"
DEFAULT_TOOLFORGE_ALLOWED_HOSTS = "localhost,127.0.0.1,.toolforge.org,.wmcloud.org"
DEFAULT_TOOLFORGE_REDIS_URL = "redis://redis.svc.tools.eqiad1.wikimedia.cloud:6379/0"
INSECURE_DEV_SECRET_KEY = "django-insecure-dev-key"  # noqa: S105
_SECRET_KEY_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^&*(-_=+)"  # noqa: S105
_PLACEHOLDER_SECRET_PREFIXES = (
    "your-",
    "your_",
    "changeme",
    "replace-",
    "placeholder",
    "example-",
    "django-insecure-",
)
_FAILED_JOB_STATUS_TOKENS = ("failed", "error", "crash", "backoff", "oom", "evicted", "killed")

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SEPARATOR_LINE_RE = re.compile(r"^[-=+|:\s]+$")
_GRANT_STMT_RE = re.compile(r"^\s*GRANT\s+(.+?)\s+ON\s+(.+?)\s+TO\s+(.+?)\s*;?\s*$", re.IGNORECASE)
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_WIKI_REPLICA_READONLY_PRIVS = frozenset({"SELECT", "SHOW VIEW"})
_MYSQL_PROBE_ERRORS: Tuple[type[BaseException], ...] = (
    (ImportError, OSError, RuntimeError, ValueError, DjangoDbError, _PyMySqlError)
    if _PyMySqlError is not None
    else (ImportError, OSError, RuntimeError, ValueError, DjangoDbError)
)
DEFAULT_TOOLFORGE_IMAGE = "tool-proxycheck/tool-proxycheck:latest"


@dataclass(frozen=True)
class EnvVarSpec:
    name: str
    tier: str
    category: str
    sensitive: bool = False
    default_display: str = "(unset)"
    description: str = ""


@dataclass
class EnvLoadResult:
    values: Dict[str, str]
    sources: Dict[str, str]
    hidden_keys: frozenset[str]
    dotenv_path: Path
    warnings: Tuple[str, ...] = ()


@dataclass(frozen=True)
class DirectoryStatus:
    label: str
    path: Path
    required: bool
    persistent: bool
    exists: bool
    is_dir: bool
    readable: bool
    writable: bool
    mount_summary: str
    is_ephemeral_mount: bool
    error: str = ""


@dataclass(frozen=True)
class JobSpec:
    name: str
    command: str
    image: str
    schedule: str
    mount: str


@dataclass(frozen=True)
class RegisteredJob:
    name: str
    command: str = ""
    job_type: str = ""
    image: str = ""
    mount: str = ""
    status: str = ""


@dataclass(frozen=True)
class BastionJobCheck:
    expected: JobSpec
    registered: bool
    job_type: str
    status: str
    warnings: Tuple[str, ...]
    adapted_image: str
    covered_by: str = ""


@dataclass(frozen=True)
class ToolsDbCheckResult:
    status: str
    db_name: str = ""
    host: str = ""
    port: int = 3306
    user: str = ""
    is_public_name_hazard: bool = False
    unsafe_grants: Tuple[str, ...] = ()
    message: str = ""


def _build_env_specs() -> Tuple[EnvVarSpec, ...]:
    specs: List[EnvVarSpec] = [
        EnvVarSpec(
            "DJANGO_SECRET_KEY",
            "required",
            "Core & OAuth",
            True,
            "(none in production)",
            "Django cryptographic signing key and gadget Bearer token secret",
        ),
        EnvVarSpec(
            "WIKIMEDIA_CLIENT_ID",
            "required",
            "Core & OAuth",
            False,
            "(unset)",
            "Wikimedia OAuth 2.0 application client ID",
        ),
        EnvVarSpec(
            "WIKIMEDIA_CLIENT_SECRET",
            "required",
            "Core & OAuth",
            True,
            "(unset)",
            "Wikimedia OAuth 2.0 application client secret",
        ),
        EnvVarSpec(
            "DJANGO_ALLOWED_HOSTS",
            "recommended",
            "Production / Toolforge Recommended",
            False,
            "127.0.0.1,localhost",
            "Comma-separated allowed hostnames (include .toolforge.org,.wmcloud.org in production)",
        ),
        EnvVarSpec(
            "WIKIMEDIA_REDIRECT_URI",
            "recommended",
            "Production / Toolforge Recommended",
            False,
            DEFAULT_PRODUCTION_REDIRECT_URI,
            "OAuth 2.0 callback URL matching the deployed tool domain",
        ),
        EnvVarSpec(
            "REDIS_URL",
            "recommended",
            "Production / Toolforge Recommended",
            False,
            "redis://127.0.0.1:6379/0",
            "Redis connection URL for sessions, IP caches, quota guard, and telemetry",
        ),
        EnvVarSpec(
            "TOOL_DATA_DIR",
            "recommended",
            "Production / Toolforge Recommended",
            False,
            "(unset)",
            "Toolforge tool home or persistent data root for .env and offline databases (for example /data/project/<tool>)",
        ),
        EnvVarSpec(
            "MAXMIND_ACCOUNT_ID",
            "recommended",
            "Production / Toolforge Recommended",
            True,
            "(unset)",
            "MaxMind account ID required by update_offline_dbs to fetch GeoLite2 MMDBs",
        ),
        EnvVarSpec(
            "MAXMIND_LICENSE_KEY",
            "recommended",
            "Production / Toolforge Recommended",
            True,
            "(unset)",
            "MaxMind licence key paired with MAXMIND_ACCOUNT_ID",
        ),
        EnvVarSpec(
            "ALLOWED_WIKI_USERS",
            "recommended",
            "Production / Toolforge Recommended",
            False,
            "(unset)",
            "Comma-separated Wikimedia usernames granted admin dashboard and status access",
        ),
    ]

    for meta in PROVIDER_REGISTRY:
        if meta.credential_setting is not None:
            specs.append(
                EnvVarSpec(
                    name=meta.credential_setting,
                    tier="provider",
                    category="Upstream IP Intelligence Providers",
                    sensitive=True,
                    description=meta.credential_description or f"{meta.label} API credential",
                )
            )

    runtime_defs = (
        ("DJANGO_DEBUG", "False", "Enable Django debug mode (local development only)", False),
        ("DJANGO_SECURE_HSTS_SECONDS", "31536000", "HSTS max-age in seconds when DJANGO_DEBUG is False", False),
        ("PORT", "8000", "Gunicorn HTTP bind port", False),
        ("WEB_CONCURRENCY", "2", "Gunicorn UvicornWorker worker count", False),
        ("REDIS_KEY_PREFIX", "proxycheck_dev_", "Django cache key prefix in Redis", False),
        (
            "REDIS_KEY_SECRET",
            "(fallback to DJANGO_SECRET_KEY)",
            "Secret key isolating Shared Redis namespaces and hashing IP suffixes",
            True,
        ),
        ("ENABLE_L2_TOOLSDB_CACHE", "True", "Enable persistent ToolsDB L2 cache storage", False),
        ("TOOLSDB_NAME", "(unset; SQLite fallback)", "Private ToolsDB database name without a _p suffix", False),
        ("TOOL_TOOLSDB_NAME", "(unset)", "Buildpack-injected ToolsDB database name override", False),
        ("TOOLSDB_HOST", "tools.db.svc.wikimedia.cloud", "ToolsDB MariaDB hostname", False),
        ("TOOLSDB_PORT", "3306", "ToolsDB MariaDB TCP port", False),
        ("TOOLSDB_USER", "(auto)", "Explicit ToolsDB MariaDB username override", False),
        ("TOOLSDB_PASSWORD", "(auto)", "Explicit ToolsDB MariaDB password override", True),
        ("TOOL_TOOLSDB_USER", "(auto)", "Toolforge-injected ToolsDB username", False),
        ("TOOL_TOOLSDB_PASSWORD", "(auto)", "Toolforge-injected ToolsDB password", True),
        ("CACHE_SWR_STALE_DAYS", "90", "Age threshold in days before L2 snapshots trigger background refresh", False),
        ("ENABLE_TEST_AUTH", "(disabled)", "Set to 1 alongside DJANGO_DEBUG=True to enable test role switching", False),
        (
            "WIKIMEDIA_OAUTH_URL",
            "https://meta.wikimedia.org/w/rest.php/oauth2",
            "Wikimedia OAuth 2.0 base endpoint",
            False,
        ),
        ("GADGET_TOKEN_TTL_SECONDS", "900", "Signed userscript gadget token lifetime in seconds", False),
        (
            "RESTRICT_TO_ALLOWED_WIKI_USERS",
            "False",
            "Restrict access exclusively to usernames listed in ALLOWED_WIKI_USERS",
            False,
        ),
        ("HOSTING_ASNS", "(built-in)", "Extra comma-separated hosting ASNs", False),
        ("HOSTING_ORG_KEYWORDS", "(built-in)", "Extra comma-separated hosting organisation keywords", False),
        ("VITE_GITHUB_REPO", "(unset)", "Build-time GitHub repository slug shown in the UI footer", False),
        ("VITE_COMMIT_HASH", "(git HEAD)", "Build-time commit hash override for the frontend bundle", False),
        (
            "VITE_COMMIT_TIMESTAMP",
            "(git commit time)",
            "Build-time UTC commit timestamp override for the frontend bundle",
            False,
        ),
    )
    specs.extend(
        EnvVarSpec(
            name=name,
            tier="optional",
            category="Runtime, Paths & Build Metadata",
            sensitive=sensitive,
            default_display=default_display,
            description=description,
        )
        for name, default_display, description, sensitive in runtime_defs
    )

    seen_override_settings: set[str] = set()
    for dataset in OFFLINE_DATASET_SPECS:
        if dataset.override_setting and dataset.override_setting not in seen_override_settings:
            seen_override_settings.add(dataset.override_setting)
            specs.append(
                EnvVarSpec(
                    name=dataset.override_setting,
                    tier="optional",
                    category="Runtime, Paths & Build Metadata",
                    sensitive=False,
                    default_display="(auto)",
                    description=dataset.override_description or f"Override path for {dataset.filename}",
                )
            )

    tuning_defs = (
        ("PROVIDER_STATIC_CACHE_TTL_SECONDS", "86400", "Cache TTL for static commercial intelligence providers"),
        ("PROVIDER_DYNAMIC_CACHE_TTL_SECONDS", "7200", "Cache TTL for dynamic threat feeds"),
        ("PROVIDER_COOLDOWN_DEFAULT_SECONDS", "120", "Default reactive cooldown circuit-breaker duration"),
        ("PROVIDER_COOLDOWN_MIN_SECONDS", "60", "Minimum clamped Retry-After cooldown duration"),
        ("PROVIDER_COOLDOWN_MAX_SECONDS", "300", "Maximum clamped Retry-After cooldown duration"),
        ("DNS_QUERY_TIMEOUT_SECONDS", "2.0", "Per-attempt DNS resolver timeout"),
        ("DNS_QUERY_LIFETIME_SECONDS", "2.0", "Total DNS resolver query lifetime"),
    )
    specs.extend(
        EnvVarSpec(
            name=name,
            tier="tuning",
            category="Tuning & Quota Limits",
            default_display=default_display,
            description=description,
        )
        for name, default_display, description in tuning_defs
    )

    seen_stale_settings: set[str] = set()
    for dataset in OFFLINE_DATASET_SPECS:
        if dataset.stale_setting not in seen_stale_settings:
            seen_stale_settings.add(dataset.stale_setting)
            specs.append(
                EnvVarSpec(
                    name=dataset.stale_setting,
                    tier="tuning",
                    category="Tuning & Quota Limits",
                    default_display=str(dataset.default_stale_seconds),
                    description=dataset.stale_description,
                )
            )

    for meta in PROVIDER_REGISTRY:
        if not meta.has_quota_env_vars:
            continue
        specs.append(
            EnvVarSpec(
                name=meta.rpm_setting,
                tier="tuning",
                category="Tuning & Quota Limits",
                default_display=str(meta.default_rpm_limit),
                description=f"Soft requests-per-minute quota guard for {meta.key}",
            )
        )
        specs.append(
            EnvVarSpec(
                name=meta.daily_setting,
                tier="tuning",
                category="Tuning & Quota Limits",
                default_display=str(meta.default_daily_limit),
                description=f"Soft daily quota guard for {meta.key}",
            )
        )
    return tuple(specs)


ENV_SPECS: Tuple[EnvVarSpec, ...] = _build_env_specs()
ENV_SPEC_BY_NAME: Dict[str, EnvVarSpec] = {spec.name: spec for spec in ENV_SPECS}


def mask_secret(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        return ""
    length = len(cleaned)
    if length > 10:
        return f"{cleaned[:4]}...{cleaned[-4:]}"
    if length >= 9:
        return f"{cleaned[:2]}...{cleaned[-2:]}"
    if length >= 5:
        return f"{cleaned[0]}{'*' * (length - 2)}{cleaned[-1]}"
    return "*" * length


def format_display_value(spec: EnvVarSpec, value: str) -> str:
    if spec.sensitive:
        return mask_secret(value)
    if spec.name == "REDIS_URL":
        cleaned = value.strip()
        if not cleaned:
            return ""
        try:
            parsed = urlsplit(cleaned)
        except ValueError:
            return mask_secret(cleaned)
        if parsed.password is None:
            return cleaned
        host_part = parsed.hostname or ""
        if ":" in host_part and not host_part.startswith("["):
            host_part = f"[{host_part}]"
        if parsed.port is not None:
            host_part = f"{host_part}:{parsed.port}"
        user_part = parsed.username or ""
        netloc = f"{user_part}:***@{host_part}" if user_part else f":***@{host_part}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
    return value


def _is_weak_secret_key(value: str) -> Tuple[bool, Optional[str]]:
    cleaned = value.strip()
    if any(cleaned.lower().startswith(prefix) for prefix in _PLACEHOLDER_SECRET_PREFIXES):
        return True, "appears to be a placeholder secret"
    if len(cleaned) < 32:
        return False, f"short secret ({len(cleaned)} chars; 50+ recommended)"
    return False, None


def is_public_toolsdb_name(db_name: str) -> bool:
    cleaned = str(db_name or "").strip().strip("`'\"")
    return bool(cleaned) and cleaned.lower().endswith("_p")
