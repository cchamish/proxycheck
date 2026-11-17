"""Interactive environment diagnostic and initialisation command for Proxy Detector."""

from __future__ import annotations

import contextlib
import getpass
import json
import os
import re
import shlex
import shutil
import subprocess  # noqa: S404
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils.crypto import get_random_string
from dotenv import dotenv_values, set_key

from detector.offline_dbs import (
    DEFAULT_STALE_CLOUD_CIDRS_SECONDS,
    DEFAULT_STALE_MAXMIND_SECONDS,
    DEFAULT_STALE_RULES_SECONDS,
    DEFAULT_STALE_SFS_1_SECONDS,
    DEFAULT_STALE_SFS_90_SECONDS,
    DEFAULT_STALE_SFS_TOXIC_SECONDS,
    collect_offline_databases_status,
)
from detector.provider_registry import PROVIDER_REGISTRY
from proxycheck.settings import expand_configured_path, resolve_dotenv_path, resolve_tool_data_subdir

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
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass(frozen=True)
class EnvVarSpec:
    """Metadata describing an environment variable used by Proxy Detector."""

    name: str
    tier: str
    category: str
    sensitive: bool = False
    default_display: str = "(unset)"
    description: str = ""


@dataclass(frozen=True)
class EnvLoadResult:
    """Loaded environment values alongside their resolved source labels."""

    values: Dict[str, str]
    sources: Dict[str, str]
    hidden_keys: frozenset[str]
    dotenv_path: Path
    warnings: Tuple[str, ...] = ()


@dataclass(frozen=True)
class DirectoryStatus:
    """Filesystem permission and mount status for a checked directory."""

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
    """Expected Toolforge scheduled job definition parsed from jobs.yaml or defaults."""

    name: str
    command: str
    image: str
    schedule: str
    mount: str


@dataclass(frozen=True)
class RegisteredJob:
    """Active Toolforge job metadata parsed from toolforge jobs list or jobs show."""

    name: str
    command: str = ""
    job_type: str = ""
    image: str = ""
    mount: str = ""
    status: str = ""


@dataclass(frozen=True)
class BastionJobCheck:
    """Comparison outcome between jobs.yaml and active Toolforge jobs."""

    expected: JobSpec
    registered: bool
    job_type: str
    status: str
    warnings: Tuple[str, ...]
    adapted_image: str
    covered_by: str = ""


def _build_core_and_oauth_env_specs() -> Tuple[EnvVarSpec, ...]:
    """Returns required core and Toolforge OAuth environment variable specs."""
    core_defs = (
        (
            "DJANGO_SECRET_KEY",
            "required",
            "Core & OAuth",
            True,
            "(none in production)",
            "Django cryptographic signing key and gadget Bearer token secret",
        ),
        (
            "WIKIMEDIA_CLIENT_ID",
            "required",
            "Core & OAuth",
            False,
            "(unset)",
            "Wikimedia OAuth 2.0 application client ID",
        ),
        (
            "WIKIMEDIA_CLIENT_SECRET",
            "required",
            "Core & OAuth",
            True,
            "(unset)",
            "Wikimedia OAuth 2.0 application client secret",
        ),
        (
            "DJANGO_ALLOWED_HOSTS",
            "recommended",
            "Production / Toolforge Recommended",
            False,
            "127.0.0.1,localhost",
            "Comma-separated allowed hostnames (include .toolforge.org,.wmcloud.org in production)",
        ),
        (
            "WIKIMEDIA_REDIRECT_URI",
            "recommended",
            "Production / Toolforge Recommended",
            False,
            DEFAULT_PRODUCTION_REDIRECT_URI,
            "OAuth 2.0 callback URL matching the deployed tool domain",
        ),
        (
            "REDIS_URL",
            "recommended",
            "Production / Toolforge Recommended",
            False,
            "redis://127.0.0.1:6379/0",
            "Redis connection URL for sessions, IP caches, quota guard, and telemetry",
        ),
        (
            "TOOL_DATA_DIR",
            "recommended",
            "Production / Toolforge Recommended",
            False,
            "(unset)",
            "Toolforge tool home or persistent data root for .env and offline databases (for example /data/project/<tool>)",
        ),
        (
            "MAXMIND_ACCOUNT_ID",
            "recommended",
            "Production / Toolforge Recommended",
            True,
            "(unset)",
            "MaxMind account ID required by update_offline_dbs to fetch GeoLite2 MMDBs",
        ),
        (
            "MAXMIND_LICENSE_KEY",
            "recommended",
            "Production / Toolforge Recommended",
            True,
            "(unset)",
            "MaxMind license key paired with MAXMIND_ACCOUNT_ID",
        ),
        (
            "ALLOWED_WIKI_USERS",
            "recommended",
            "Production / Toolforge Recommended",
            False,
            "(unset)",
            "Comma-separated Wikimedia usernames granted admin dashboard and status access",
        ),
    )
    return tuple(
        EnvVarSpec(
            name=name,
            tier=tier,
            category=category,
            sensitive=sensitive,
            default_display=default_display,
            description=description,
        )
        for name, tier, category, sensitive, default_display, description in core_defs
    )


def _build_provider_api_env_specs() -> Tuple[EnvVarSpec, ...]:
    """Returns commercial IP intelligence provider credential variable specs from the shared registry."""
    return tuple(
        EnvVarSpec(
            name=meta.credential_setting,
            tier="provider",
            category="Upstream IP Intelligence Providers",
            sensitive=True,
            description=meta.credential_description or f"{meta.label} API credential",
        )
        for meta in PROVIDER_REGISTRY
        if meta.credential_setting is not None
    )


def _build_runtime_and_path_env_specs() -> Tuple[EnvVarSpec, ...]:
    """Returns optional runtime, offline database path, and frontend build metadata specs."""
    runtime_defs = (
        ("DJANGO_DEBUG", "False", "Enable Django debug mode (local development only)"),
        ("DJANGO_SECURE_HSTS_SECONDS", "31536000", "HSTS max-age in seconds when DJANGO_DEBUG is False"),
        ("PORT", "8000", "Gunicorn HTTP bind port"),
        ("WEB_CONCURRENCY", "2", "Gunicorn UvicornWorker worker count"),
        ("REDIS_KEY_PREFIX", "proxycheck_dev_", "Django cache key prefix in Redis"),
        ("ENABLE_TEST_AUTH", "(disabled)", "Set to 1 alongside DJANGO_DEBUG=True to enable test role switching"),
        ("WIKIMEDIA_OAUTH_URL", "https://meta.wikimedia.org/w/rest.php/oauth2", "Wikimedia OAuth 2.0 base endpoint"),
        ("GADGET_TOKEN_TTL_SECONDS", "3600", "Signed userscript gadget token lifetime in seconds"),
        (
            "RESTRICT_TO_ALLOWED_WIKI_USERS",
            "False",
            "Restrict access exclusively to usernames listed in ALLOWED_WIKI_USERS",
        ),
        ("STOPFORUMSPAM_TOXIC_CIDR_PATH", "(auto)", "Override file or directory path for toxic_ip_cidr.txt"),
        ("STOPFORUMSPAM_LISTED_90_PATH", "(auto)", "Override path for StopForumSpam 90-day listed IP archive"),
        ("STOPFORUMSPAM_LISTED_1_PATH", "(auto)", "Override path for StopForumSpam 1-day listed IP archive"),
        ("STOPFORUMSPAM_SQLITE_PATH", "(auto)", "Override path for stopforumspam.sqlite3 index"),
        ("HOSTING_ASN_RULES_PATH", "(auto)", "Override path for hosting_asn_rules.json"),
        ("HOSTING_ASNS", "(built-in)", "Extra comma-separated hosting ASNs"),
        ("HOSTING_ORG_KEYWORDS", "(built-in)", "Extra comma-separated hosting organisation keywords"),
        ("VITE_GITHUB_REPO", "(unset)", "Build-time GitHub repository slug shown in the UI footer"),
        ("VITE_COMMIT_HASH", "(git HEAD)", "Build-time commit hash override for the frontend bundle"),
        (
            "VITE_COMMIT_TIMESTAMP",
            "(git commit time)",
            "Build-time UTC commit timestamp override for the frontend bundle",
        ),
    )
    return tuple(
        EnvVarSpec(
            name=name,
            tier="optional",
            category="Runtime, Paths & Build Metadata",
            default_display=default_display,
            description=description,
        )
        for name, default_display, description in runtime_defs
    )


def _build_tuning_and_quota_env_specs() -> Tuple[EnvVarSpec, ...]:
    """Returns cache, resolver, staleness threshold, and per-provider quota tuning specs."""
    tuning_defs = (
        ("PROVIDER_STATIC_CACHE_TTL_SECONDS", "86400", "Cache TTL for static commercial intelligence providers"),
        ("PROVIDER_DYNAMIC_CACHE_TTL_SECONDS", "7200", "Cache TTL for dynamic threat feeds"),
        ("PROVIDER_COOLDOWN_DEFAULT_SECONDS", "120", "Default reactive cooldown circuit-breaker duration"),
        ("PROVIDER_COOLDOWN_MIN_SECONDS", "60", "Minimum clamped Retry-After cooldown duration"),
        ("PROVIDER_COOLDOWN_MAX_SECONDS", "300", "Maximum clamped Retry-After cooldown duration"),
        ("DNS_QUERY_TIMEOUT_SECONDS", "2.0", "Per-attempt DNS resolver timeout"),
        ("DNS_QUERY_LIFETIME_SECONDS", "2.0", "Total DNS resolver query lifetime"),
        (
            "OFFLINE_DB_MAXMIND_STALE_SECONDS",
            str(DEFAULT_STALE_MAXMIND_SECONDS),
            "MaxMind MMDB staleness warning threshold",
        ),
        (
            "OFFLINE_DB_SFS_TOXIC_STALE_SECONDS",
            str(DEFAULT_STALE_SFS_TOXIC_SECONDS),
            "StopForumSpam toxic_ip_cidr.txt staleness threshold",
        ),
        (
            "OFFLINE_DB_SFS_90_STALE_SECONDS",
            str(DEFAULT_STALE_SFS_90_SECONDS),
            "StopForumSpam 90-day dump staleness threshold",
        ),
        (
            "OFFLINE_DB_SFS_1_STALE_SECONDS",
            str(DEFAULT_STALE_SFS_1_SECONDS),
            "StopForumSpam 1-day dump staleness threshold",
        ),
        (
            "OFFLINE_DB_CLOUD_CIDRS_STALE_SECONDS",
            str(DEFAULT_STALE_CLOUD_CIDRS_SECONDS),
            "Cloud provider CIDRs staleness threshold",
        ),
        ("OFFLINE_DB_RULES_STALE_SECONDS", str(DEFAULT_STALE_RULES_SECONDS), "Hosting ASN rules staleness threshold"),
    )
    specs = [
        EnvVarSpec(
            name=name,
            tier="tuning",
            category="Tuning & Quota Limits",
            default_display=default_display,
            description=description,
        )
        for name, default_display, description in tuning_defs
    ]
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


def _build_env_specs() -> Tuple[EnvVarSpec, ...]:
    """Returns all scanned environment variable definitions in display order."""
    return (
        *_build_core_and_oauth_env_specs(),
        *_build_provider_api_env_specs(),
        *_build_runtime_and_path_env_specs(),
        *_build_tuning_and_quota_env_specs(),
    )


ENV_SPECS: Tuple[EnvVarSpec, ...] = _build_env_specs()
ENV_SPEC_BY_NAME: Dict[str, EnvVarSpec] = {spec.name: spec for spec in ENV_SPECS}

DEFAULT_JOB_SPECS: Tuple[JobSpec, ...] = (
    JobSpec(
        name="update-sfs-db",
        command="python manage.py update_offline_dbs --sources stopforumspam",
        image="tool-proxycheck/tool-proxycheck:latest",
        schedule="@hourly",
        mount="all",
    ),
    JobSpec(
        name="update-maxmind-db",
        command="python manage.py update_offline_dbs --sources maxmind",
        image="tool-proxycheck/tool-proxycheck:latest",
        schedule="@daily",
        mount="all",
    ),
    JobSpec(
        name="update-cloud-cidrs-db",
        command="python manage.py update_offline_dbs --sources cloud_cidrs",
        image="tool-proxycheck/tool-proxycheck:latest",
        schedule="0 3 * * *",
        mount="all",
    ),
)
DEFAULT_JOB_SPEC = DEFAULT_JOB_SPECS[0]


def mask_secret(value: str) -> str:
    """Masks sensitive credentials while retaining safe prefix and suffix characters."""
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


def redact_url_credentials(raw_url: str) -> str:
    """Redacts password components inside connection URLs such as REDIS_URL."""
    cleaned = raw_url.strip()
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


def format_display_value(spec: EnvVarSpec, value: str) -> str:
    """Formats an environment variable value for terminal display."""
    if spec.sensitive:
        return mask_secret(value)
    if spec.name == "REDIS_URL":
        return redact_url_credentials(value)
    return value


def generate_secret_key(length: int = 50) -> str:
    """Generates a cryptographically random Django secret key."""
    return get_random_string(length, _SECRET_KEY_CHARS)


def detect_toolforge_account(
    *,
    environ: Optional[Mapping[str, str]] = None,
    home_dir: Optional[Path] = None,
) -> Optional[str]:
    """Extracts the active Toolforge tool name from USER, TOOL_DATA_DIR, or HOME."""
    env = os.environ if environ is None else environ
    for user_var in ("USER", "LOGNAME"):
        raw_user = str(env.get(user_var) or "").strip()
        for prefix in ("tools.", "toolsbeta."):
            if raw_user.startswith(prefix) and len(raw_user) > len(prefix):
                return raw_user[len(prefix) :]

    candidates = [str(env.get(k) or "") for k in ("TOOL_DATA_DIR", "HOME") if env.get(k)]
    if home_dir is not None:
        candidates.append(str(home_dir))

    for candidate in candidates:
        match = re.match(r"^/data/project/([^/]+)(?:/|$)", candidate.strip())
        if match:
            return match.group(1)
    return None


def detect_runtime_environment(
    requested_mode: str = "auto",
    *,
    environ: Optional[Mapping[str, str]] = None,
    which_fn: Optional[Callable[[str], Optional[str]]] = None,
    wmcs_project_path: Path = Path("/etc/wmcs-project"),
    home_dir: Optional[Path] = None,
) -> Tuple[str, Optional[str], Optional[str]]:
    """Detects whether execution targets Toolforge Bastion or a local or container environment."""
    normalized_mode = requested_mode.strip().lower()
    if normalized_mode not in ENV_MODES:
        raise CommandError(f"Unsupported --env mode '{requested_mode}'. Choose from: {', '.join(ENV_MODES)}.")

    env = os.environ if environ is None else environ
    lookup_bin = shutil.which if which_fn is None else which_fn
    toolforge_bin = lookup_bin("toolforge")
    tool_account = detect_toolforge_account(environ=env, home_dir=home_dir)

    if normalized_mode == "bastion":
        if not toolforge_bin:
            raise CommandError("Cannot run in bastion mode: 'toolforge' CLI was not found on PATH.")
        return "bastion", toolforge_bin, tool_account

    if normalized_mode == "local":
        return "local", toolforge_bin, tool_account

    # Auto mode requires both the toolforge CLI and a WMCS host marker outside buildpack containers.
    raw_user = str(env.get("USER") or env.get("LOGNAME") or "").strip()
    raw_home = str(env.get("HOME") or (home_dir or "")).strip()
    is_container = bool(env.get("CNB_STACK_ID") or env.get("TOOL_TOOLFORGE_API_URL") or Path("/.dockerenv").exists())
    has_bastion_marker = (
        wmcs_project_path.exists()
        or raw_user.startswith(("tools.", "toolsbeta."))
        or raw_home.startswith("/data/project/")
    )
    if toolforge_bin and has_bastion_marker and not is_container:
        return "bastion", toolforge_bin, tool_account
    return "local", toolforge_bin, tool_account


def _run_toolforge_command(
    toolforge_bin: str,
    args: Sequence[str],
    *,
    input_text: Optional[str] = None,
    timeout: float = 30.0,
) -> Tuple[int, str, str]:
    """Executes the Toolforge CLI safely without shell interpolation."""
    try:
        completed = subprocess.run(  # noqa: S603
            [toolforge_bin, *args],
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except OSError as exc:
        return 1, "", f"Failed to execute toolforge CLI: {exc}"
    except subprocess.TimeoutExpired:
        return 1, "", f"Timed out executing: toolforge {' '.join(args)}"
    return completed.returncode, completed.stdout or "", completed.stderr or ""


def _parse_envvars_json(stripped: str) -> Optional[Tuple[Dict[str, str], set[str]]]:
    try:
        payload = json.loads(stripped)
    except ValueError:
        return None
    if isinstance(payload, dict):
        values = {str(k): str(v) for k, v in payload.items() if _ENV_NAME_RE.match(str(k))}
        return values, set(values.keys())
    if isinstance(payload, list):
        values: Dict[str, str] = {}
        names: set[str] = set()
        for entry in payload:
            if isinstance(entry, dict) and entry.get("name"):
                key = str(entry["name"]).strip()
                names.add(key)
                if entry.get("value") is not None:
                    values[key] = str(entry["value"])
            elif isinstance(entry, str) and _ENV_NAME_RE.match(entry.strip()):
                names.add(entry.strip())
        return values, names
    return None


def _parse_envvars_list_output(raw_output: str, *, with_values: bool) -> Tuple[Dict[str, str], set[str]]:
    """Parses tabular or JSON output from toolforge envvars list."""
    stripped = raw_output.strip()
    if not stripped:
        return {}, set()

    if stripped.startswith(("{", "[")):
        parsed_json = _parse_envvars_json(stripped)
        if parsed_json is not None:
            return parsed_json

    values_out: Dict[str, str] = {}
    names_out: set[str] = set()
    for line in raw_output.splitlines():
        candidate = line.strip()
        if not candidate or _SEPARATOR_LINE_RE.match(candidate):
            continue
        first_token = candidate.split(None, 1)[0]
        parts = [part.strip() for part in candidate.split("=", 1)] if "=" in first_token else candidate.split(None, 1)
        head = parts[0].strip().rstrip(":")
        if head.lower() in ("name", "key", "envvar", "variable") and (
            len(parts) == 1 or parts[1].strip().lower() in ("value", "values")
        ):
            continue
        if not _ENV_NAME_RE.match(head):
            continue
        names_out.add(head)
        if with_values and len(parts) == 2:
            values_out[head] = parts[1].strip()
    return values_out, names_out


def _parse_envvar_show_output(name: str, raw_output: str) -> Optional[str]:
    """Parses output from toolforge envvars show, returning None when masked or unreadable."""
    filtered = [
        line.rstrip("\r\n")
        for line in raw_output.splitlines()
        if line.strip() and not _SEPARATOR_LINE_RE.match(line.strip())
    ]
    if not filtered:
        return None
    for line in filtered:
        stripped = line.strip()
        parts = stripped.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in ("name", "key") and parts[1].strip().lower() == "value":
            continue
        if len(parts) == 2 and parts[0] == name:
            val = parts[1].strip()
            return None if set(val) == {"*"} else val
        if stripped.startswith((f"{name}:", f"{name}=")):
            val = stripped[len(name) + 1 :].strip()
            return None if set(val) == {"*"} else val
    if len(filtered) == 1:
        single = filtered[0].strip()
        if single != name and set(single) != {"*"}:
            return single
    return None


def load_bastion_envvars(toolforge_bin: str, base_dir: Path) -> EnvLoadResult:
    """Reads configured environment variables via toolforge envvars list and show."""
    values: Dict[str, str] = {}
    sources: Dict[str, str] = {}
    hidden_keys: set[str] = set()

    rc, stdout, stderr = _run_toolforge_command(toolforge_bin, ("envvars", "list", "--show-values"))
    if rc == 0:
        parsed_vals, parsed_names = _parse_envvars_list_output(stdout, with_values=True)
        for key in parsed_names:
            val = parsed_vals.get(key, "")
            if val:
                values[key] = val
                sources[key] = "toolforge envvars"
        return EnvLoadResult(values=values, sources=sources, hidden_keys=frozenset(), dotenv_path=base_dir / ".env")

    rc_list, stdout_list, stderr_list = _run_toolforge_command(toolforge_bin, ("envvars", "list"))
    if rc_list != 0:
        err_detail = (stderr_list or stderr or stdout_list or stdout).strip()
        raise CommandError(f"Failed to query Toolforge envvars: {err_detail or f'exit code {rc_list}'}")

    _, listed_names = _parse_envvars_list_output(stdout_list, with_values=False)
    for key in sorted(listed_names):
        if key not in ENV_SPEC_BY_NAME:
            continue
        rc_show, stdout_show, _ = _run_toolforge_command(toolforge_bin, ("envvars", "show", key))
        shown_val = _parse_envvar_show_output(key, stdout_show) if rc_show == 0 else None
        values[key] = shown_val or ""
        sources[key] = "toolforge envvars"
        if not shown_val:
            hidden_keys.add(key)

    return EnvLoadResult(
        values=values,
        sources=sources,
        hidden_keys=frozenset(hidden_keys),
        dotenv_path=base_dir / ".env",
    )


def load_local_envvars(base_dir: Path, *, environ: Optional[Mapping[str, str]] = None) -> EnvLoadResult:
    """Loads environment variables from process environment and local .env files."""
    env = os.environ if environ is None else environ
    warnings: List[str] = []

    raw_tool_dir = str(env.get("TOOL_DATA_DIR") or "").strip()
    resolved_dotenv = resolve_dotenv_path(base_dir, raw_tool_dir)
    read_dotenv_path = resolved_dotenv if resolved_dotenv is not None else (base_dir / ".env")
    write_dotenv_path = base_dir / ".env"
    dotenv_label = read_dotenv_path.name if read_dotenv_path == write_dotenv_path else str(read_dotenv_path)

    dotenv_map: Dict[str, str] = {}
    if read_dotenv_path.is_file():
        try:
            raw_dotenv = dotenv_values(read_dotenv_path, encoding="utf-8-sig")
            dotenv_map = {str(k): ("" if v is None else str(v)) for k, v in raw_dotenv.items() if k}
        except (OSError, UnicodeDecodeError) as exc:
            warnings.append(f"Unable to read {read_dotenv_path}: {exc}")

    values: Dict[str, str] = {}
    sources: Dict[str, str] = {}
    for spec in ENV_SPECS:
        name = spec.name
        env_val = env.get(name)
        dotenv_val = dotenv_map.get(name)
        if env_val is not None and env_val.strip():
            values[name] = env_val.strip()
            sources[name] = (
                dotenv_label if (dotenv_val is not None and dotenv_val.strip() == env_val.strip()) else "process env"
            )
        elif dotenv_val is not None and dotenv_val.strip():
            values[name] = dotenv_val.strip()
            sources[name] = dotenv_label

    return EnvLoadResult(
        values=values,
        sources=sources,
        hidden_keys=frozenset(),
        dotenv_path=write_dotenv_path,
        warnings=tuple(warnings),
    )


def ensure_env_in_gitignore(base_dir: Path) -> Tuple[bool, str]:
    """Ensures .env is ignored by Git before writing secrets to the project root."""
    gitignore_path = base_dir / ".gitignore"
    if gitignore_path.is_file():
        existing = gitignore_path.read_text(encoding="utf-8")
        for line in existing.splitlines():
            if line.split("#", 1)[0].strip() in (".env", "/.env", "*.env"):
                return False, "already ignored"
        prefix = "\n" if existing and not existing.endswith("\n") else ""
        gitignore_path.write_text(f"{existing}{prefix}.env\n", encoding="utf-8")
        return True, f"appended '.env' to {gitignore_path}"

    gitignore_path.write_text(".env\n", encoding="utf-8")
    return True, f"created {gitignore_path} with '.env'"


def save_envvar_bastion(toolforge_bin: str, key: str, value: str) -> None:
    """Writes an environment variable to Toolforge via stdin so secrets stay off process argv."""
    rc, stdout, stderr = _run_toolforge_command(toolforge_bin, ("envvars", "create", key), input_text=value)
    if rc != 0:
        detail = (stderr or stdout).strip()
        raise CommandError(f"Failed to set Toolforge envvar {key}: {detail or f'exit code {rc}'}")


def save_envvar_local(base_dir: Path, dotenv_path: Path, key: str, value: str) -> Optional[str]:
    """Persists an environment variable to .env while guaranteeing .gitignore coverage."""
    _, gitignore_note = ensure_env_in_gitignore(base_dir)
    created_new = not dotenv_path.exists()
    dotenv_path.parent.mkdir(parents=True, exist_ok=True)
    set_key(dotenv_path, key, value, quote_mode="always", encoding="utf-8")
    if created_new:
        with contextlib.suppress(OSError):
            os.chmod(dotenv_path, 0o600)
    os.environ[key] = value
    return gitignore_note if gitignore_note != "already ignored" else None


def _is_weak_secret_key(value: str) -> Tuple[bool, Optional[str]]:
    cleaned = value.strip()
    if any(cleaned.lower().startswith(prefix) for prefix in _PLACEHOLDER_SECRET_PREFIXES):
        return True, "appears to be a placeholder secret"
    if len(cleaned) < 32:
        return False, f"short secret ({len(cleaned)} chars; 50+ recommended)"
    return False, None


def _is_recommended_local_fallback(
    spec: EnvVarSpec,
    value: str,
    *,
    mode: str,
    tool_account: Optional[str],
) -> Optional[str]:
    cleaned = value.strip()
    if not cleaned:
        return None
    if spec.name == "DJANGO_ALLOWED_HOSTS" and mode == "bastion":
        hosts = [entry.strip().lower() for entry in cleaned.split(",") if entry.strip()]
        if hosts and all(host in _LOCAL_HOSTS for host in hosts):
            return "contains only local hosts for a Toolforge environment"
    if (
        spec.name == "REDIS_URL"
        and mode == "bastion"
        and ("127.0.0.1" in cleaned.lower() or "localhost" in cleaned.lower())
    ):
        return "points to localhost Redis inside Toolforge"
    if (
        spec.name == "WIKIMEDIA_REDIRECT_URI"
        and tool_account == "proxycheck-dev"
        and "proxycheck.toolforge.org" in cleaned
        and "proxycheck-dev.toolforge.org" not in cleaned
    ):
        return "points to production callback URL while active tool is proxycheck-dev"
    return None


def _suggested_value_hint(spec: EnvVarSpec, *, mode: str, tool_account: Optional[str]) -> str:
    if spec.name == "DJANGO_ALLOWED_HOSTS" and mode == "bastion":
        return DEFAULT_TOOLFORGE_ALLOWED_HOSTS
    if spec.name == "WIKIMEDIA_REDIRECT_URI":
        if tool_account:
            return f"https://{tool_account}.toolforge.org/oauth/callback"
        return "http://127.0.0.1:8000/oauth/callback" if mode == "local" else DEFAULT_PRODUCTION_REDIRECT_URI
    if spec.name == "REDIS_URL" and mode == "bastion":
        return DEFAULT_TOOLFORGE_REDIS_URL
    if spec.name == "TOOL_DATA_DIR" and mode == "bastion" and tool_account:
        return f"/data/project/{tool_account}"
    return ""


def _parse_mounts_table(mounts_path: Path = Path("/proc/mounts")) -> List[Tuple[str, str, str]]:
    """Reads Linux mount points as (mount_point, fs_type, options) tuples."""
    if not mounts_path.is_file():
        return []
    try:
        raw_lines = mounts_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    entries: List[Tuple[str, str, str]] = []
    for line in raw_lines:
        parts = line.split()
        if len(parts) >= 4:
            entries.append((parts[1].replace("\\040", " "), parts[2], parts[3]))
    return entries


def _detect_mount_info(target_path: Path, *, mounts: Sequence[Tuple[str, str, str]]) -> Tuple[str, bool]:
    """Determines the filesystem type and persistence status for a target path."""
    if not mounts:
        return "local filesystem", False
    try:
        probe = target_path.resolve()
    except OSError:
        probe = target_path

    probe_str = probe.as_posix()
    best_match: Optional[Tuple[str, str, str]] = None
    for mount_point, fs_type, options in mounts:
        normalized_mp = mount_point.rstrip("/") or "/"
        is_match = normalized_mp == "/" or probe_str == normalized_mp or probe_str.startswith(f"{normalized_mp}/")
        if is_match and (best_match is None or len(normalized_mp) > len(best_match[0].rstrip("/") or "/")):
            best_match = (mount_point, fs_type, options)

    if best_match is None:
        return "local filesystem", False

    mount_point, fs_type, options = best_match
    rw_flag = "ro" if "ro" in options.split(",") else "rw"
    kind = "NFS" if fs_type.startswith("nfs") else fs_type
    return f"{kind} ({fs_type}, {rw_flag}) at {mount_point}", fs_type in ("overlay", "tmpfs", "ramfs")


def _collect_target_directories(
    base_dir: Path,
    env_values: Mapping[str, str],
    *,
    mode: str,
) -> List[Tuple[str, Path, bool, bool]]:
    entries: List[List[Any]] = []
    index_by_resolved: Dict[Path, int] = {}

    def _add(source_tag: str, fallback_label: str, raw_path: Path, *, required: bool, persistent: bool) -> None:
        try:
            normalized = raw_path.resolve()
        except OSError:
            normalized = raw_path
        existing_idx = index_by_resolved.get(normalized)
        if existing_idx is not None:
            existing = entries[existing_idx]
            if source_tag and source_tag not in existing[0]:
                existing[0].append(source_tag)
            existing[3] = existing[3] or required
            existing[4] = existing[4] or persistent
            return
        index_by_resolved[normalized] = len(entries)
        entries.append([[source_tag] if source_tag else [], fallback_label, raw_path, required, persistent])

    tool_data_dir = expand_configured_path(env_values.get("TOOL_DATA_DIR", ""))
    if tool_data_dir:
        _add(
            "TOOL_DATA_DIR",
            "Persistent data directory",
            resolve_tool_data_subdir(tool_data_dir),
            required=True,
            persistent=True,
        )
    elif mode == "bastion" or base_dir.parent == Path(base_dir.anchor):
        _add("~/data", "Persistent data directory", Path.home() / "data", required=True, persistent=True)
    else:
        local_candidates = (base_dir.parent / "data", base_dir / "data", Path.home() / "data")
        chosen_local = next((cand for cand in local_candidates if cand.is_dir()), base_dir.parent / "data")
        _add("", "Default offline data directory", chosen_local, required=True, persistent=True)

    _add("", "Frontend build assets (dist/assets)", base_dir / "dist" / "assets", required=False, persistent=False)
    _add("", "Collected static directory (staticfiles)", base_dir / "staticfiles", required=False, persistent=False)

    targets: List[Tuple[str, Path, bool, bool]] = []
    for source_tags, fallback_label, raw_path, required, persistent in entries:
        if len(source_tags) > 1:
            label = f"Offline data directory ({', '.join(source_tags)})"
        elif len(source_tags) == 1:
            label = f"{fallback_label} ({source_tags[0]})"
        else:
            label = fallback_label
        targets.append((label, raw_path, required, persistent))
    return targets


def _inspect_directory(
    label: str,
    path: Path,
    *,
    required: bool,
    persistent: bool,
    mounts: Sequence[Tuple[str, str, str]],
) -> DirectoryStatus:
    mount_summary, is_ephemeral = _detect_mount_info(path, mounts=mounts)
    if not path.exists():
        return DirectoryStatus(
            label=label,
            path=path,
            required=required,
            persistent=persistent,
            exists=False,
            is_dir=False,
            readable=False,
            writable=False,
            mount_summary=mount_summary,
            is_ephemeral_mount=is_ephemeral,
        )

    if not path.is_dir():
        return DirectoryStatus(
            label=label,
            path=path,
            required=required,
            persistent=persistent,
            exists=True,
            is_dir=False,
            readable=False,
            writable=False,
            mount_summary=mount_summary,
            is_ephemeral_mount=is_ephemeral,
            error="path exists but is not a directory",
        )

    readable = os.access(path, os.R_OK | os.X_OK)
    read_err = ""
    if readable:
        try:
            with os.scandir(path):
                pass
        except OSError as exc:
            readable = False
            read_err = str(exc)
    else:
        read_err = "read permission denied"

    writable = False
    write_err = ""
    if persistent:
        try:
            with tempfile.NamedTemporaryFile(dir=path, prefix=".check_setup_", delete=True):
                writable = True
        except OSError as exc:
            write_err = str(exc)
    else:
        writable = os.access(path, os.W_OK)

    return DirectoryStatus(
        label=label,
        path=path,
        required=required,
        persistent=persistent,
        exists=True,
        is_dir=True,
        readable=readable,
        writable=writable,
        mount_summary=mount_summary,
        is_ephemeral_mount=is_ephemeral,
        error="; ".join(msg for msg in (read_err, write_err) if msg),
    )


def collect_offline_status_for_env(
    base_dir: Path,
    env_values: Mapping[str, str],
    *,
    now_dt: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """Inventories offline database and rule files against a resolved environment mapping."""
    return collect_offline_databases_status(
        now_dt=now_dt,
        env_overrides=env_values,
        base_dir=base_dir,
        include_resolved_path=True,
    )


def _strip_yaml_quotes(raw_val: str) -> str:
    cleaned = raw_val.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ("'", '"'):
        return cleaned[1:-1]
    return cleaned


def parse_jobs_yaml(jobs_path: Path) -> List[JobSpec]:
    """Parses simple Toolforge jobs.yaml entries without requiring PyYAML."""
    if not jobs_path.is_file():
        return list(DEFAULT_JOB_SPECS)

    raw_items: List[Dict[str, str]] = []
    current: Optional[Dict[str, str]] = None
    for raw_line in jobs_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line == "---":
            continue
        if line.startswith("- "):
            if current:
                raw_items.append(current)
            current = {}
            line = line[2:].strip()
        if current is None or ":" not in line:
            continue
        key, val = line.split(":", 1)
        current[key.strip()] = _strip_yaml_quotes(val)
    if current:
        raw_items.append(current)

    parsed = [
        JobSpec(
            name=item["name"].strip(),
            command=item.get("command", DEFAULT_JOB_SPEC.command).strip(),
            image=item.get("image", DEFAULT_JOB_SPEC.image).strip(),
            schedule=item.get("schedule", DEFAULT_JOB_SPEC.schedule).strip(),
            mount=item.get("mount", DEFAULT_JOB_SPEC.mount).strip(),
        )
        for item in raw_items
        if item.get("name", "").strip()
    ]
    return parsed or list(DEFAULT_JOB_SPECS)


def _split_bordered_row(line: str, plus_positions: Optional[List[int]]) -> List[str]:
    if plus_positions and len(plus_positions) >= 2 and len(line) >= plus_positions[-1] + 1:
        return [
            line[plus_positions[idx] + 1 : plus_positions[idx + 1]].strip() for idx in range(len(plus_positions) - 1)
        ]
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _parse_bordered_jobs_table(raw_output: str) -> Dict[str, RegisteredJob]:
    """Parses prettytable grid output from toolforge jobs list --output long."""
    plus_positions: Optional[List[int]] = None
    headers: Optional[List[str]] = None
    jobs: Dict[str, RegisteredJob] = {}

    for line in (ln.rstrip("\r\n") for ln in raw_output.splitlines() if ln.strip()):
        stripped = line.strip()
        if stripped.startswith("+") and "+" in stripped[1:] and set(stripped) <= {"+", "-", "="}:
            candidate_positions = [idx for idx, ch in enumerate(line) if ch == "+"]
            if len(candidate_positions) >= 2:
                plus_positions = candidate_positions
            continue
        if not (stripped.startswith("|") and stripped.endswith("|")):
            continue

        cells = _split_bordered_row(line, plus_positions)
        if headers is None:
            headers = [cell.rstrip(":").strip().lower() for cell in cells]
            continue

        row_map = {header: cells[idx] for idx, header in enumerate(headers) if idx < len(cells)}
        name = row_map.get("job name") or row_map.get("name") or ""
        if name:
            jobs[name] = RegisteredJob(
                name=name,
                command=row_map.get("command", ""),
                job_type=row_map.get("job type") or row_map.get("type") or "",
                image=row_map.get("image", ""),
                mount=row_map.get("mounts") or row_map.get("mount") or "",
                status=row_map.get("status", ""),
            )
    return jobs


def _parse_toolforge_jobs_json(stripped: str) -> Optional[Dict[str, RegisteredJob]]:
    try:
        payload = json.loads(stripped)
    except ValueError:
        return None
    if not isinstance(payload, list):
        return None
    return {
        str(entry["name"]).strip(): RegisteredJob(
            name=str(entry["name"]).strip(),
            command=str(entry.get("command") or ""),
            job_type=str(entry.get("type") or entry.get("job_type") or ""),
            image=str(entry.get("image") or ""),
            mount=str(entry.get("mount") or entry.get("mounts") or ""),
            status=str(entry.get("status") or ""),
        )
        for entry in payload
        if isinstance(entry, dict) and entry.get("name")
    }


def _parse_toolforge_jobs_list(raw_output: str) -> Dict[str, RegisteredJob]:
    """Parses toolforge jobs list output across long, compact, and JSON formats."""
    stripped = raw_output.strip()
    if not stripped or "no jobs found" in stripped.lower():
        return {}

    if stripped.startswith(("{", "[")):
        parsed_json = _parse_toolforge_jobs_json(stripped)
        if parsed_json is not None:
            return parsed_json

    if any(line.strip().startswith("|") and line.strip().endswith("|") for line in raw_output.splitlines()):
        bordered = _parse_bordered_jobs_table(raw_output)
        if bordered:
            return bordered

    jobs: Dict[str, RegisteredJob] = {}
    col_bounds: Optional[List[Tuple[int, int]]] = None
    for line in (ln.rstrip("\r\n") for ln in raw_output.splitlines() if ln.strip()):
        if line.strip().lower().startswith("job name"):
            continue
        if _SEPARATOR_LINE_RE.match(line.strip()):
            spans = [m.span() for m in re.finditer(r"-+", line)]
            if len(spans) >= 2:
                col_bounds = spans
            continue

        if col_bounds and len(col_bounds) >= 3:
            name = line[col_bounds[0][0] : col_bounds[1][0]].strip()
            job_type = line[col_bounds[1][0] : col_bounds[2][0]].strip()
            status = line[col_bounds[2][0] :].strip()
        else:
            parts = line.split(None, 2)
            if not parts:
                continue
            name = parts[0].strip()
            job_type = parts[1].strip() if len(parts) > 1 else ""
            status = parts[2].strip() if len(parts) > 2 else ""

        if name and not name.endswith(":"):
            jobs[name] = RegisteredJob(name=name, job_type=job_type, status=status)
    return jobs


def _parse_toolforge_job_show(raw_output: str) -> Dict[str, str]:
    details: Dict[str, str] = {}
    for line in raw_output.splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            cleaned_key = key.strip().lower()
            if cleaned_key:
                details[cleaned_key] = val.strip()
    return details


def _extract_update_offline_sources(command: str) -> set[str]:
    if not command or "update_offline_dbs" not in command:
        return set()
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    if len(tokens) >= 3 and Path(tokens[0]).name in ("sh", "bash") and tokens[1] in ("-c", "-lc"):
        try:
            tokens = shlex.split(tokens[2])
        except ValueError:
            tokens = tokens[2].split()

    cmd_idx = next((idx for idx, tok in enumerate(tokens) if tok == "update_offline_dbs"), None)
    if cmd_idx is None:
        return set()

    source_tokens: List[str] = []
    idx = cmd_idx + 1
    while idx < len(tokens):
        tok = tokens[idx]
        if tok == "--sources":
            idx += 1
            while idx < len(tokens) and not tokens[idx].startswith("-"):
                source_tokens.extend(part.strip().lower() for part in tokens[idx].split(",") if part.strip())
                idx += 1
            continue
        if tok.startswith("--sources="):
            raw_val = tok.split("=", 1)[1]
            source_tokens.extend(part.strip().lower() for part in raw_val.split(",") if part.strip())
        idx += 1

    if not source_tokens or "all" in source_tokens:
        return {"stopforumspam", "maxmind", "cloud_cidrs"}

    alias_map = {
        "stopforumspam": "stopforumspam",
        "sfs": "stopforumspam",
        "maxmind": "maxmind",
        "cloud_cidrs": "cloud_cidrs",
        "cloud-cidrs": "cloud_cidrs",
        "cloud": "cloud_cidrs",
    }
    return {alias_map[tok] for tok in source_tokens if tok in alias_map}


def _schedule_matches_expected(expected_schedule: str, actual_job_type: str) -> bool:
    lowered_type = actual_job_type.strip().lower()
    if "scheduled" not in lowered_type:
        return False
    actual_cron = " ".join((lowered_type.split(":", 1)[1] if ":" in lowered_type else lowered_type).split())
    norm_expected = " ".join(expected_schedule.strip().lower().split())
    if not norm_expected or norm_expected == actual_cron:
        return True
    hourly_re = r"\d{1,2}\s+\*\s+\*\s+\*\s+\*"
    daily_re = r"\d{1,2}\s+\d{1,2}\s+\*\s+\*\s+\*"
    if norm_expected == "@hourly":
        return bool(re.fullmatch(hourly_re, actual_cron))
    if actual_cron == "@hourly":
        return bool(re.fullmatch(hourly_re, norm_expected))
    if norm_expected == "@daily":
        return bool(re.fullmatch(daily_re, actual_cron))
    if actual_cron == "@daily":
        return bool(re.fullmatch(daily_re, norm_expected))
    return False


def _validate_registered_job(
    spec: JobSpec,
    reg: RegisteredJob,
    *,
    adapted_image: str,
    tool_account: Optional[str],
    covered_by: str = "",
) -> BastionJobCheck:
    job_warnings: List[str] = []
    covered_sources = _extract_update_offline_sources(reg.command)
    is_combined_coverage = bool(covered_by) and len(covered_sources) > 1
    schedule_ok = _schedule_matches_expected(spec.schedule, reg.job_type)
    if not schedule_ok and is_combined_coverage and spec.schedule.strip().lower() == "@daily":
        schedule_ok = _schedule_matches_expected("@hourly", reg.job_type)
    if spec.schedule and not schedule_ok:
        job_warnings.append(f"schedule mismatch (expected '{spec.schedule}', got '{reg.job_type or 'unknown'}')")

    if reg.mount.strip() and spec.mount.lower() not in reg.mount.strip().lower():
        job_warnings.append(f"mount is '{reg.mount}' (expected '{spec.mount}')")
    if tool_account and reg.image and reg.image != adapted_image:
        job_warnings.append(f"image is '{reg.image}' (expected '{adapted_image}')")
    if reg.command and not covered_by and "update_offline_dbs" not in reg.command:
        job_warnings.append(f"command is '{reg.command}' (expected '{spec.command}')")
    if any(token in reg.status.lower() for token in _FAILED_JOB_STATUS_TOKENS):
        job_warnings.append(f"unhealthy job status '{reg.status}'")

    return BastionJobCheck(
        expected=spec,
        registered=True,
        job_type=reg.job_type,
        status=reg.status or "Registered",
        warnings=tuple(job_warnings),
        adapted_image=adapted_image,
        covered_by=covered_by,
    )


def _hydrate_missing_job_details(
    toolforge_bin: str,
    active_jobs: Dict[str, RegisteredJob],
    expected_names: set[str],
) -> None:
    for job_name, reg in list(active_jobs.items()):
        if job_name not in expected_names and "update" not in job_name and "db" not in job_name:
            continue
        if reg.command and reg.image and reg.mount:
            continue
        rc_show, show_stdout, _ = _run_toolforge_command(toolforge_bin, ("jobs", "show", job_name))
        if rc_show == 0:
            details = _parse_toolforge_job_show(show_stdout)
            active_jobs[job_name] = RegisteredJob(
                name=job_name,
                command=details.get("command", reg.command),
                job_type=reg.job_type or details.get("job type") or details.get("type") or "",
                image=details.get("image", reg.image),
                mount=details.get("mounts") or details.get("mount") or reg.mount,
                status=reg.status or details.get("status", ""),
            )


def _check_bastion_jobs(
    toolforge_bin: str,
    base_dir: Path,
    tool_account: Optional[str],
) -> Tuple[List[BastionJobCheck], Optional[str]]:
    expected_jobs = parse_jobs_yaml(base_dir / "jobs.yaml")
    used_long_output = True
    rc, stdout, stderr = _run_toolforge_command(toolforge_bin, ("jobs", "list", "--output", "long"))
    if rc != 0:
        used_long_output = False
        rc, stdout, stderr = _run_toolforge_command(toolforge_bin, ("jobs", "list"))
    if rc != 0:
        detail = (stderr or stdout).strip()
        return [], f"Unable to query toolforge jobs list: {detail or f'exit code {rc}'}"

    active_jobs = _parse_toolforge_jobs_list(stdout)
    if not used_long_output:
        _hydrate_missing_job_details(toolforge_bin, active_jobs, {spec.name for spec in expected_jobs})

    results: List[BastionJobCheck] = []
    for spec in expected_jobs:
        adapted_image = f"tool-{tool_account}/tool-{tool_account}:latest" if tool_account else spec.image
        if spec.name in active_jobs:
            results.append(
                _validate_registered_job(
                    spec,
                    active_jobs[spec.name],
                    adapted_image=adapted_image,
                    tool_account=tool_account,
                )
            )
            continue

        needed_sources = _extract_update_offline_sources(spec.command)
        candidates = (
            [reg for reg in active_jobs.values() if needed_sources <= _extract_update_offline_sources(reg.command)]
            if needed_sources
            else []
        )
        if candidates:
            covering_job = next((cand for cand in candidates if "scheduled" in cand.job_type.lower()), candidates[0])
            results.append(
                _validate_registered_job(
                    spec,
                    covering_job,
                    adapted_image=adapted_image,
                    tool_account=tool_account,
                    covered_by=covering_job.name,
                )
            )
            continue

        warnings = (
            (
                f"jobs.yaml specifies template image '{spec.image}', whereas active account '{tool_account}' "
                f"requires '{adapted_image}'",
            )
            if (tool_account and spec.image != adapted_image)
            else ()
        )
        results.append(
            BastionJobCheck(
                expected=spec,
                registered=False,
                job_type="",
                status="Missing",
                warnings=warnings,
                adapted_image=adapted_image,
            )
        )
    return results, None


def _format_age(age_seconds: Optional[int]) -> str:
    if age_seconds is None:
        return "-"
    if age_seconds < 60:
        return f"{age_seconds}s"
    if age_seconds < 3600:
        return f"{age_seconds // 60}m"
    if age_seconds < 86400:
        return f"{age_seconds // 3600}h"
    return f"{age_seconds // 86400}d"


def _format_bytes(size_bytes: Optional[int]) -> str:
    if size_bytes is None:
        return "-"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KiB"
    return f"{size_bytes / (1024 * 1024):.1f} MiB"


class Command(BaseCommand):
    help = "Audits and interactively initialises Proxy Detector environment configuration."
    requires_system_checks = []
    requires_migrations_checks = False

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--no-input",
            "--noinput",
            action="store_true",
            dest="no_input",
            help="Run in non-interactive mode without prompting for missing settings or directories.",
        )
        parser.add_argument(
            "--env",
            choices=ENV_MODES,
            default="auto",
            dest="env_mode",
            help="Target runtime environment mode: auto, bastion, or local (default: auto).",
        )
        parser.add_argument(
            "--all-options",
            action="store_true",
            dest="all_options",
            help="Display all low-level tuning and quota limit variables and include them in interactive prompts.",
        )
        parser.add_argument(
            "--strict",
            action="store_true",
            help="Exit with non-zero status if any required variable, directory, offline database, or job is missing.",
        )

    def _prompt_text(self, prompt: str, *, sensitive: bool = False) -> Optional[str]:
        try:
            raw = getpass.getpass(prompt) if sensitive else input(prompt)
        except EOFError, KeyboardInterrupt:
            self.stdout.write("")
            return None
        return raw.strip()

    def _prompt_yes_no(self, prompt: str) -> bool:
        response = self._prompt_text(prompt, sensitive=False)
        return bool(response and response.lower() in ("y", "yes"))

    def _save_env_value(
        self,
        *,
        mode: str,
        toolforge_bin: Optional[str],
        base_dir: Path,
        env_result: EnvLoadResult,
        key: str,
        value: str,
    ) -> None:
        if mode == "bastion":
            if not toolforge_bin:
                raise CommandError("Cannot write Toolforge envvars without 'toolforge' CLI.")
            save_envvar_bastion(toolforge_bin, key, value)
            env_result.values[key] = value
            env_result.sources[key] = "toolforge envvars"
            return

        gitignore_note = save_envvar_local(base_dir, env_result.dotenv_path, key, value)
        if gitignore_note:
            self.stdout.write(self.style.WARNING(f"  Git safety: {gitignore_note}"))
        env_result.values[key] = value
        env_result.sources[key] = env_result.dotenv_path.name

    def _report_missing_env_spec(
        self,
        spec: EnvVarSpec,
        *,
        tag: str,
        missing_required: List[EnvVarSpec],
        attention_recommended: List[EnvVarSpec],
        missing_providers: List[EnvVarSpec],
        missing_optional_all: List[EnvVarSpec],
    ) -> None:
        if spec.tier == "required":
            missing_required.append(spec)
            self.stdout.write(self.style.ERROR(f"  - {tag} {spec.name}: MISSING ({spec.description})"))
        elif spec.tier == "recommended":
            attention_recommended.append(spec)
            self.stdout.write(self.style.WARNING(f"  - {tag} {spec.name}: MISSING (default: {spec.default_display})"))
        elif spec.tier == "provider":
            missing_providers.append(spec)
            self.stdout.write(f"  - {tag} {spec.name}: MISSING (provider skipped)")
        else:
            missing_optional_all.append(spec)
            self.stdout.write(f"  - {tag} {spec.name}: USING DEFAULT ({spec.default_display})")

    def _report_configured_env_spec(
        self,
        spec: EnvVarSpec,
        val: str,
        *,
        tag: str,
        source_label: str,
        mode: str,
        tool_account: Optional[str],
        missing_required: List[EnvVarSpec],
        attention_recommended: List[EnvVarSpec],
    ) -> None:
        if spec.name == "DJANGO_SECRET_KEY" and val == INSECURE_DEV_SECRET_KEY:
            missing_required.append(spec)
            self.stdout.write(self.style.ERROR(f"  - {tag} {spec.name}: INSECURE DEFAULT ({source_label})"))
            return

        if spec.name == "DJANGO_SECRET_KEY":
            is_placeholder, weak_reason = _is_weak_secret_key(val)
            if weak_reason:
                shown_val = format_display_value(spec, val)
                if is_placeholder:
                    missing_required.append(spec)
                self.stdout.write(
                    self.style.WARNING(
                        f"  - {tag} {spec.name}: WEAK / PLACEHOLDER = {shown_val} ({weak_reason}; {source_label})"
                    )
                )
                return

        review_reason = (
            _is_recommended_local_fallback(spec, val, mode=mode, tool_account=tool_account)
            if spec.tier == "recommended"
            else None
        )
        shown_val = format_display_value(spec, val)
        if review_reason:
            attention_recommended.append(spec)
            self.stdout.write(
                self.style.WARNING(
                    f"  - {tag} {spec.name}: NEEDS REVIEW = {shown_val} ({review_reason}; {source_label})"
                )
            )
        else:
            self.stdout.write(self.style.SUCCESS(f"  - {tag} {spec.name}: CONFIGURED = {shown_val} ({source_label})"))

    def _print_tuning_env_section(
        self,
        values: Dict[str, str],
        sources: Dict[str, str],
        *,
        show_all_options: bool,
        missing_optional_all: List[EnvVarSpec],
    ) -> None:
        tuning_specs = [spec for spec in ENV_SPECS if spec.tier == "tuning"]
        custom_tuning = [spec for spec in tuning_specs if values.get(spec.name, "")]
        if show_all_options:
            self.stdout.write("\n  Tuning & Quota Limits (Optional):")
            for spec in tuning_specs:
                val = values.get(spec.name, "")
                if val:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"  - [OPTIONAL] {spec.name}: CUSTOMISED = {val} ({sources.get(spec.name, '')})"
                        )
                    )
                else:
                    missing_optional_all.append(spec)
                    self.stdout.write(f"  - [OPTIONAL] {spec.name}: USING DEFAULT ({spec.default_display})")
            return

        self.stdout.write(f"\n  Tuning & Quota Limits ({len(tuning_specs)} optional vars):")
        if custom_tuning:
            custom_summary = ", ".join(f"{spec.name}={values[spec.name]}" for spec in custom_tuning)
            self.stdout.write(f"  - Customised ({len(custom_tuning)}): {custom_summary}")
        self.stdout.write(
            f"  - Using built-in defaults ({len(tuning_specs) - len(custom_tuning)} vars); "
            "pass --all-options to inspect or edit individually."
        )

    def _print_env_section(
        self,
        env_result: EnvLoadResult,
        *,
        mode: str,
        tool_account: Optional[str],
        show_all_options: bool,
    ) -> Tuple[List[EnvVarSpec], List[EnvVarSpec], List[EnvVarSpec], List[EnvVarSpec]]:
        self.stdout.write("\n[1/4] Environment Variables")
        values, sources, hidden_keys = env_result.values, env_result.sources, env_result.hidden_keys

        missing_required: List[EnvVarSpec] = []
        attention_recommended: List[EnvVarSpec] = []
        missing_providers: List[EnvVarSpec] = []
        missing_optional_all: List[EnvVarSpec] = []

        sections = (
            ("required", "Required Configuration", "[REQUIRED]"),
            ("recommended", "Production / Toolforge Recommended", "[RECOMMENDED]"),
            ("provider", "Upstream IP Intelligence Providers (Optional)", "[OPTIONAL]"),
            ("optional", "Runtime, Paths & Build Metadata (Optional)", "[OPTIONAL]"),
        )
        for tier, heading, tag in sections:
            self.stdout.write(f"\n  {heading}:")
            for spec in (s for s in ENV_SPECS if s.tier == tier):
                if spec.name in hidden_keys:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"  - {tag} {spec.name}: CONFIGURED (hidden by CLI, {sources.get(spec.name, '')})"
                        )
                    )
                    continue
                val = values.get(spec.name, "")
                if not val:
                    self._report_missing_env_spec(
                        spec,
                        tag=tag,
                        missing_required=missing_required,
                        attention_recommended=attention_recommended,
                        missing_providers=missing_providers,
                        missing_optional_all=missing_optional_all,
                    )
                else:
                    self._report_configured_env_spec(
                        spec,
                        val,
                        tag=tag,
                        source_label=sources.get(spec.name, "configured"),
                        mode=mode,
                        tool_account=tool_account,
                        missing_required=missing_required,
                        attention_recommended=attention_recommended,
                    )

        if values.get("ENABLE_TEST_AUTH") == "1" and (
            mode == "bastion" or values.get("DJANGO_DEBUG", "").lower() not in ("1", "true", "yes")
        ):
            self.stdout.write(
                self.style.WARNING(
                    "  ! Security notice: ENABLE_TEST_AUTH=1 should only be enabled alongside DJANGO_DEBUG=True locally."
                )
            )

        self._print_tuning_env_section(
            values,
            sources,
            show_all_options=show_all_options,
            missing_optional_all=missing_optional_all,
        )
        return missing_required, attention_recommended, missing_providers, missing_optional_all

    def _run_interactive_env_prompts(
        self,
        *,
        mode: str,
        toolforge_bin: Optional[str],
        tool_account: Optional[str],
        base_dir: Path,
        env_result: EnvLoadResult,
        missing_required: List[EnvVarSpec],
        attention_recommended: List[EnvVarSpec],
        missing_providers: List[EnvVarSpec],
        missing_optional_all: List[EnvVarSpec],
        show_all_options: bool,
    ) -> int:
        updated_count = 0

        def _prompt_and_store(spec: EnvVarSpec, *, hint: str = "") -> None:
            nonlocal updated_count
            if spec.name == "DJANGO_SECRET_KEY":
                prompt = (
                    f"  Enter {spec.name} (hidden; type 'gen' to auto-generate a 50-char secret, "
                    "or press Enter to skip): "
                )
            else:
                hidden_note = " (hidden)" if spec.sensitive else ""
                hint_note = f" [suggested: {hint}]" if hint else ""
                prompt = f"  Enter {spec.name}{hidden_note}{hint_note} (press Enter to skip): "

            entered = self._prompt_text(prompt, sensitive=spec.sensitive)
            if not entered:
                return

            final_val = (
                generate_secret_key() if spec.name == "DJANGO_SECRET_KEY" and entered.lower() == "gen" else entered
            )
            self._save_env_value(
                mode=mode,
                toolforge_bin=toolforge_bin,
                base_dir=base_dir,
                env_result=env_result,
                key=spec.name,
                value=final_val,
            )
            updated_count += 1
            self.stdout.write(self.style.SUCCESS(f"    Saved {spec.name} = {format_display_value(spec, final_val)}"))

        if missing_required:
            self.stdout.write("\n  Interactive Setup: Required Variables")
            for spec in missing_required:
                _prompt_and_store(spec)

        if attention_recommended:
            self.stdout.write("\n  Interactive Setup: Recommended Variables")
            for spec in attention_recommended:
                _prompt_and_store(spec, hint=_suggested_value_hint(spec, mode=mode, tool_account=tool_account))

        if missing_providers:
            self.stdout.write("")
            if self._prompt_yes_no(
                f"  Configure {len(missing_providers)} missing third-party IP intelligence API keys now? [y/N]: "
            ):
                for spec in missing_providers:
                    _prompt_and_store(spec)

        if show_all_options and missing_optional_all:
            self.stdout.write("")
            if self._prompt_yes_no(
                f"  Configure {len(missing_optional_all)} optional runtime and tuning variables now? [y/N]: "
            ):
                for spec in missing_optional_all:
                    _prompt_and_store(spec, hint=spec.default_display)

        return updated_count

    def _print_directory_section(
        self,
        *,
        base_dir: Path,
        env_values: Mapping[str, str],
        mode: str,
        no_input: bool,
    ) -> Tuple[List[DirectoryStatus], List[Path]]:
        self.stdout.write("\n[2/4] Persistent Directories & Mount Status")
        mounts = _parse_mounts_table()
        targets = _collect_target_directories(base_dir, env_values, mode=mode)
        statuses: List[DirectoryStatus] = []
        created_dirs: List[Path] = []

        for label, path, required, persistent in targets:
            status = _inspect_directory(label, path, required=required, persistent=persistent, mounts=mounts)
            tag = "[REQUIRED]" if required else "[OPTIONAL]"
            if not status.exists:
                if not persistent and mode == "bastion":
                    self.stdout.write(
                        f"  - [INFO] {label}: NOT ON BASTION NFS "
                        "(built inside Toolforge Build Service image during 'toolforge build start')"
                    )
                    statuses.append(status)
                    continue
                msg = f"  - {tag} {label}: MISSING -> {path} ({status.mount_summary})"
                self.stdout.write(self.style.ERROR(msg) if required else self.style.WARNING(msg))
                if persistent and not no_input and self._prompt_yes_no(f"    Create directory '{path}'? [y/N]: "):
                    try:
                        path.mkdir(parents=True, exist_ok=True)
                        created_dirs.append(path)
                        status = _inspect_directory(
                            label, path, required=required, persistent=persistent, mounts=mounts
                        )
                        self.stdout.write(self.style.SUCCESS(f"    Created {path}"))
                    except OSError as exc:
                        status = DirectoryStatus(
                            label=label,
                            path=path,
                            required=required,
                            persistent=persistent,
                            exists=False,
                            is_dir=False,
                            readable=False,
                            writable=False,
                            mount_summary=status.mount_summary,
                            is_ephemeral_mount=status.is_ephemeral_mount,
                            error=str(exc),
                        )
                        self.stdout.write(self.style.ERROR(f"    Failed to create {path}: {exc}"))
            elif not status.is_dir or not status.readable or (persistent and not status.writable):
                self.stdout.write(
                    self.style.ERROR(
                        f"  - {tag} {label}: PERMISSION / PATH ERROR -> {path} ({status.error}; {status.mount_summary})"
                    )
                )
            else:
                perm_label = "read/write" if status.writable else "read-only"
                line = f"  - {tag} {label}: OK ({perm_label}; {status.mount_summary}) -> {path}"
                if persistent and status.is_ephemeral_mount:
                    self.stdout.write(
                        self.style.WARNING(f"{line} [WARNING: ephemeral mount; ensure --mount=all on Toolforge]")
                    )
                else:
                    self.stdout.write(self.style.SUCCESS(line))
            statuses.append(status)

        return statuses, created_dirs

    def _print_offline_db_section(
        self,
        *,
        base_dir: Path,
        env_values: Mapping[str, str],
    ) -> List[Dict[str, Any]]:
        self.stdout.write("\n[3/4] Offline Databases & Rule Files")
        entries = collect_offline_status_for_env(base_dir, env_values)

        for entry in entries:
            tag = "[OPTIONAL]" if entry["optional"] else "[REQUIRED]"
            name, filename, status, resolved_path = (
                entry["name"],
                entry["filename"],
                entry["status"],
                entry["resolvedPath"],
            )
            if status in ("healthy", "stale"):
                meta = f"{_format_bytes(entry['sizeBytes'])}, age {_format_age(entry['ageSeconds'])}"
                style_fn = self.style.SUCCESS if status == "healthy" else self.style.WARNING
                self.stdout.write(
                    style_fn(f"  - {tag} {name} ({filename}): {status.upper()} ({meta}) -> {resolved_path}")
                )
            elif entry["optional"] and entry["key"] in ("cloud_cidrs", "hosting_asn_rules"):
                self.stdout.write(f"  - {tag} {name} ({filename}): BUILT-IN FALLBACK (no override file found)")
            elif entry["optional"]:
                self.stdout.write(f"  - {tag} {name} ({filename}): MISSING (optional)")
            else:
                self.stdout.write(self.style.ERROR(f"  - {tag} {name} ({filename}): MISSING"))
        return entries

    def _print_jobs_section(
        self,
        *,
        mode: str,
        toolforge_bin: Optional[str],
        tool_account: Optional[str],
        base_dir: Path,
    ) -> Tuple[List[BastionJobCheck], Optional[str]]:
        self.stdout.write("\n[4/4] Toolforge Scheduled Jobs")
        if mode != "bastion":
            self.stdout.write("  - [SKIPPED] Toolforge jobs check only runs in Toolforge Bastion mode.")
            return [], None

        if not toolforge_bin:
            err = "toolforge CLI unavailable"
            self.stdout.write(self.style.ERROR(f"  - [ERROR] {err}"))
            return [], err

        checks, err = _check_bastion_jobs(toolforge_bin, base_dir, tool_account)
        if err:
            self.stdout.write(self.style.ERROR(f"  - [ERROR] {err}"))
            return [], err

        for check in checks:
            spec = check.expected
            coverage_note = f", covered by '{check.covered_by}'" if check.covered_by else ""
            if not check.registered:
                self.stdout.write(
                    self.style.ERROR(
                        f"  - [REQUIRED] {spec.name}: MISSING (expected schedule '{spec.schedule}', command '{spec.command}')"
                    )
                )
                for warning in check.warnings:
                    self.stdout.write(self.style.WARNING(f"    Note: {warning}"))
            elif check.warnings:
                detail = "; ".join(check.warnings)
                self.stdout.write(
                    self.style.WARNING(
                        f"  - [REQUIRED] {spec.name}: REGISTERED WITH WARNINGS ({check.status}{coverage_note}; {detail})"
                    )
                )
            else:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"  - [REQUIRED] {spec.name}: OK ({check.job_type or spec.schedule}; {check.status}{coverage_note})"
                    )
                )
        return checks, None

    def _collect_db_update_commands(
        self,
        *,
        mode: str,
        tool_account: Optional[str],
        values: Dict[str, str],
        hidden: frozenset[str],
        missing_or_stale_core_dbs: Sequence[Dict[str, Any]],
    ) -> List[str]:
        if not missing_or_stale_core_dbs:
            return []
        missing_sfs_dbs = [e for e in missing_or_stale_core_dbs if e["source"] == "StopForumSpam"]
        missing_maxmind_dbs = [e for e in missing_or_stale_core_dbs if e["source"] == "MaxMind"]
        has_maxmind_creds = bool(
            (values.get("MAXMIND_ACCOUNT_ID") or "MAXMIND_ACCOUNT_ID" in hidden)
            and (values.get("MAXMIND_LICENSE_KEY") or "MAXMIND_LICENSE_KEY" in hidden)
        )
        if mode == "bastion":
            target_image = f"tool-{tool_account}/tool-{tool_account}:latest" if tool_account else DEFAULT_JOB_SPEC.image
            if missing_maxmind_dbs and not has_maxmind_creds:
                self.stdout.write(
                    self.style.WARNING(
                        "  - MaxMind credentials (MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY) are not configured; "
                        "configure them first or upload GeoLite2-*.mmdb manually into ~/data."
                    )
                )
            return [
                f"toolforge jobs run update-offline-dbs-init --image {target_image} "
                '--mount=all --wait --command "python manage.py update_offline_dbs"'
            ]

        if missing_sfs_dbs and not missing_maxmind_dbs:
            return ["python manage.py update_offline_dbs --sources stopforumspam"]
        commands: List[str] = []
        if missing_maxmind_dbs and not has_maxmind_creds:
            self.stdout.write(
                self.style.WARNING(
                    "  - MaxMind credentials (MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY) are not configured; "
                    "StopForumSpam can still update via '--sources stopforumspam'."
                )
            )
            if missing_sfs_dbs:
                commands.append("python manage.py update_offline_dbs --sources stopforumspam")
        commands.append("python manage.py update_offline_dbs")
        return commands

    def _collect_job_remediation_commands(self, missing_or_warn_jobs: Sequence[BastionJobCheck]) -> List[str]:
        if not missing_or_warn_jobs:
            return []
        commands = [
            f'toolforge jobs run {job.covered_by or job.expected.name} --command "{job.expected.command}" '
            f'--image {job.adapted_image} --schedule "{job.expected.schedule}" --mount={job.expected.mount}'
            for job in missing_or_warn_jobs
        ]
        if any(job.expected.image != job.adapted_image for job in missing_or_warn_jobs):
            template_img = missing_or_warn_jobs[0].expected.image
            adapted_img = missing_or_warn_jobs[0].adapted_image
            commands.append(
                f"tmp_jobs=$(mktemp) && sed 's|{template_img}|{adapted_img}|g' jobs.yaml > \"$tmp_jobs\" "
                '&& toolforge jobs load "$tmp_jobs" && rm -f "$tmp_jobs"'
            )
        else:
            commands.append("toolforge jobs load jobs.yaml")
        return commands

    def _print_remediation_and_summary(
        self,
        *,
        mode: str,
        tool_account: Optional[str],
        env_result: EnvLoadResult,
        dir_statuses: Sequence[DirectoryStatus],
        offline_entries: Sequence[Dict[str, Any]],
        job_checks: Sequence[BastionJobCheck],
        jobs_error: Optional[str],
        updated_env_count: int,
        strict: bool,
    ) -> None:
        self.stdout.write("\nSummary & Next Steps")

        values, hidden = env_result.values, env_result.hidden_keys
        unresolved_required_env = [
            spec.name
            for spec in ENV_SPECS
            if spec.tier == "required"
            and spec.name not in hidden
            and (
                not values.get(spec.name)
                or (
                    spec.name == "DJANGO_SECRET_KEY"
                    and (values[spec.name] == INSECURE_DEV_SECRET_KEY or _is_weak_secret_key(values[spec.name])[0])
                )
            )
        ]
        missing_dirs = [d for d in dir_statuses if d.required and not d.exists]
        broken_dirs = [
            d
            for d in dir_statuses
            if d.required and d.exists and (not d.is_dir or not d.readable or (d.persistent and not d.writable))
        ]
        missing_or_stale_core_dbs = [e for e in offline_entries if not e["optional"] and e["status"] != "healthy"]
        missing_or_warn_jobs = [j for j in job_checks if not j.registered or j.warnings]

        commands_to_run: List[str] = []
        if mode == "bastion" and updated_env_count > 0:
            commands_to_run.append("toolforge webservice buildservice restart --mount=all")
        commands_to_run.extend(f"mkdir -p {d.path}" for d in missing_dirs)
        commands_to_run.extend(
            self._collect_db_update_commands(
                mode=mode,
                tool_account=tool_account,
                values=values,
                hidden=hidden,
                missing_or_stale_core_dbs=missing_or_stale_core_dbs,
            )
        )
        commands_to_run.extend(self._collect_job_remediation_commands(missing_or_warn_jobs))

        if unresolved_required_env:
            self.stdout.write(
                self.style.ERROR(f"  - Required envvars still missing/invalid: {', '.join(unresolved_required_env)}")
            )
        else:
            self.stdout.write(self.style.SUCCESS("  - All required environment variables are configured."))

        if broken_dirs:
            self.stdout.write(
                self.style.ERROR("  - Directory permission/path issues: " + ", ".join(str(d.path) for d in broken_dirs))
            )
        if missing_dirs:
            self.stdout.write(
                self.style.WARNING("  - Missing required directories: " + ", ".join(str(d.path) for d in missing_dirs))
            )
        if not missing_dirs and not broken_dirs:
            self.stdout.write(self.style.SUCCESS("  - All required persistent directories are ready."))

        if missing_or_stale_core_dbs:
            self.stdout.write(
                self.style.WARNING(
                    f"  - Core offline databases needing attention: {len(missing_or_stale_core_dbs)} "
                    f"({', '.join(e['filename'] for e in missing_or_stale_core_dbs)})"
                )
            )
        else:
            self.stdout.write(self.style.SUCCESS("  - All core offline databases are present and up to date."))

        if mode == "bastion":
            if jobs_error:
                self.stdout.write(self.style.ERROR(f"  - Scheduled jobs check error: {jobs_error}"))
            elif missing_or_warn_jobs:
                self.stdout.write(
                    self.style.WARNING(
                        "  - Scheduled jobs needing setup/review: "
                        + ", ".join(j.expected.name for j in missing_or_warn_jobs)
                    )
                )
            else:
                self.stdout.write(self.style.SUCCESS("  - Toolforge scheduled jobs match jobs.yaml."))

        if commands_to_run:
            self.stdout.write("\n  Recommended commands:")
            for cmd in commands_to_run:
                self.stdout.write(f"    {cmd}")

        has_required_failures = bool(
            unresolved_required_env
            or missing_dirs
            or broken_dirs
            or missing_or_stale_core_dbs
            or jobs_error
            or (mode == "bastion" and any(not j.registered for j in job_checks))
        )
        if strict and has_required_failures:
            raise CommandError("Setup check failed under --strict because required items are missing or unhealthy.")

    def handle(self, *args, **options) -> None:
        base_dir = Path(str(getattr(settings, "BASE_DIR", Path(__file__).resolve().parent.parent.parent.parent)))
        requested_mode = str(options.get("env_mode") or "auto")
        no_input = bool(options.get("no_input"))
        show_all_options = bool(options.get("all_options"))
        strict = bool(options.get("strict"))

        mode, toolforge_bin, tool_account = detect_runtime_environment(requested_mode)
        mode_desc = (
            f"Toolforge Bastion (account: {tool_account})"
            if mode == "bastion" and tool_account
            else ("Toolforge Bastion (account undetected)" if mode == "bastion" else "Local / Buildpack Container")
        )
        self.stdout.write(f"Proxy Detector Environment Check ({mode_desc})")
        if mode == "bastion" and not tool_account:
            self.stdout.write(
                self.style.WARNING(
                    "  Warning: Could not detect a 'tools.<name>' account. Run 'become proxycheck' or "
                    "'become proxycheck-dev' before managing toolforge envvars or jobs."
                )
            )

        env_result = (
            load_bastion_envvars(toolforge_bin, base_dir)
            if mode == "bastion" and toolforge_bin
            else load_local_envvars(base_dir)
        )
        for warning in env_result.warnings:
            self.stdout.write(self.style.WARNING(f"  Warning: {warning}"))

        missing_required, attention_recommended, missing_providers, missing_optional_all = self._print_env_section(
            env_result,
            mode=mode,
            tool_account=tool_account,
            show_all_options=show_all_options,
        )

        updated_env_count = 0
        if not no_input:
            updated_env_count = self._run_interactive_env_prompts(
                mode=mode,
                toolforge_bin=toolforge_bin,
                tool_account=tool_account,
                base_dir=base_dir,
                env_result=env_result,
                missing_required=missing_required,
                attention_recommended=attention_recommended,
                missing_providers=missing_providers,
                missing_optional_all=missing_optional_all,
                show_all_options=show_all_options,
            )

        dir_statuses, _ = self._print_directory_section(
            base_dir=base_dir,
            env_values=env_result.values,
            mode=mode,
            no_input=no_input,
        )
        offline_entries = self._print_offline_db_section(base_dir=base_dir, env_values=env_result.values)
        job_checks, jobs_error = self._print_jobs_section(
            mode=mode,
            toolforge_bin=toolforge_bin,
            tool_account=tool_account,
            base_dir=base_dir,
        )

        self._print_remediation_and_summary(
            mode=mode,
            tool_account=tool_account,
            env_result=env_result,
            dir_statuses=dir_statuses,
            offline_entries=offline_entries,
            job_checks=job_checks,
            jobs_error=jobs_error,
            updated_env_count=updated_env_count,
            strict=strict,
        )
