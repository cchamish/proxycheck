"""Django configuration for Proxycheck on Wikimedia Toolforge."""

import configparser
import math
import os
import sys
from pathlib import Path
from typing import Any, Mapping, Optional, Tuple

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

from detector.provider_registry import (
    DEFAULT_PROVIDER_L2_MAX_RETENTION_DAYS,
    PROVIDER_REGISTRY,
    build_redis_namespace,
)

BASE_DIR = Path(__file__).resolve().parent.parent


def resolve_dotenv_path(base_dir: Path, tool_data_dir: str = "") -> Optional[Path]:
    """Locates an environment file from local project roots or Toolforge mounted storage."""
    candidates = [
        base_dir / ".env",
        base_dir.parent / ".env",
    ]
    if tool_data_dir:
        tool_root = Path(tool_data_dir)
        candidates.extend(
            [
                tool_root / "www" / "python" / "src" / ".env",
                tool_root / "www" / "python" / ".env",
                tool_root / ".env",
            ]
        )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


_TOOL_DATA_DIR = os.environ.get("TOOL_DATA_DIR", "").strip()
_dotenv_path = resolve_dotenv_path(BASE_DIR, _TOOL_DATA_DIR)
if _dotenv_path is not None:
    load_dotenv(dotenv_path=_dotenv_path)
else:
    load_dotenv()


def _parse_bool_env(name: str, default: bool = False) -> bool:
    value = os.environ.get(name, "").strip().lower()
    if not value:
        return default
    return value in ("1", "true", "yes", "on")


def _parse_int_env(
    name: str,
    default: int,
    *,
    min_value: int = 1,
    mapping: Optional[Mapping[str, str]] = None,
) -> int:
    source = os.environ if mapping is None else mapping
    raw_value = str(source.get(name) or "").strip()
    if not raw_value:
        return default
    try:
        parsed = int(raw_value)
        return parsed if parsed >= min_value else default
    except ValueError:
        return default


def _parse_positive_float_env(name: str, default: float) -> float:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = float(raw_value)
        return parsed if math.isfinite(parsed) and parsed > 0 else default
    except ValueError:
        return default


def _parse_csv_env(name: str) -> tuple[str, ...]:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return ()
    return tuple(item.strip() for item in raw_value.split(",") if item.strip())


DEBUG = os.environ.get("DJANGO_DEBUG", "False").lower() in ("true", "1", "yes")
ENABLE_TEST_AUTH = os.environ.get("ENABLE_TEST_AUTH") == "1"
RESTRICT_TO_ALLOWED_WIKI_USERS = _parse_bool_env("RESTRICT_TO_ALLOWED_WIKI_USERS")

_IS_TEST_RUN = "test" in sys.argv or "pytest" in sys.modules
_IS_SETUP_CHECK = "check_setup" in sys.argv[1:]
_IS_MIGRATION_CHECK = "makemigrations" in sys.argv[1:]

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")
if not SECRET_KEY:
    if (
        not DEBUG
        and not _IS_TEST_RUN
        and not _IS_SETUP_CHECK
        and not _IS_MIGRATION_CHECK
        and "collectstatic" not in sys.argv
    ):
        raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set in production.")
    SECRET_KEY = "django-insecure-dev-key"  # noqa: S105

# Convert leading *. wildcards to Django dot syntax.
ALLOWED_HOSTS = [
    host[1:] if host.startswith("*.") and len(host) > 2 else host
    for entry in os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",")
    if (host := entry.strip())
] or ["127.0.0.1", "localhost"]

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "whitenoise.runserver_nostatic",
    "django.contrib.staticfiles",
    "detector",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "detector.middleware.AsyncWhiteNoiseMiddleware",
    "detector.middleware.ResilientSessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# Toolforge Kubernetes Ingress passes HTTPS termination via X-Forwarded-Proto.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"
SESSION_COOKIE_NAME = "proxycheck_sessionid"
SESSION_COOKIE_AGE = 86400 * 7
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_SAVE_EVERY_REQUEST = False

if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = int(os.environ.get("DJANGO_SECURE_HSTS_SECONDS", "31536000"))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
else:
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SECURE_HSTS_SECONDS = 0

# Toolforge Kubernetes Ingress terminates HTTPS externally, so container-level SSL redirects break internal
# HTTP traffic and HSTS preload is omitted to avoid irreversible domain-wide commitments on shared hosts.
SILENCED_SYSTEM_CHECKS = ["security.W008", "security.W021"]

ROOT_URLCONF = "proxycheck.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

ASGI_APPLICATION = "proxycheck.asgi.application"

DEFAULT_TOOLSDB_HOST = "tools.db.svc.wikimedia.cloud"
DEFAULT_TOOLSDB_PORT = 3306
_MANAGEMENT_COMMAND_DB_TIMEOUT_COMMANDS = frozenset(
    {
        "sync_world_block",
        "purge_l2_cache",
        "migrate",
        "makemigrations",
        "sqlmigrate",
        "showmigrations",
        "dbshell",
        "flush",
        "loaddata",
        "dumpdata",
        "check_setup",
    }
)


def _parse_port_value(raw_value: str, default: int = DEFAULT_TOOLSDB_PORT) -> int:
    cleaned = str(raw_value or "").strip()
    if not cleaned:
        return default
    try:
        parsed = int(cleaned)
        return parsed if 0 < parsed <= 65535 else default
    except ValueError:
        return default


def _read_replica_my_cnf(cnf_path: Path) -> Optional[Tuple[str, str, str, Optional[int], str]]:
    """Reads client credentials from a MariaDB replica.my.cnf file without value interpolation."""
    if not cnf_path.is_file():
        return None
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with cnf_path.open(encoding="utf-8") as handle:
            parser.read_file(handle)
    except OSError, UnicodeDecodeError, configparser.Error:
        return None
    if not parser.has_section("client"):
        return None

    def get_clean(option: str) -> str:
        cleaned = str(parser.get("client", option, fallback="") or "").strip()
        if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ("'", '"'):
            return cleaned[1:-1]
        return cleaned

    user = get_clean("user")
    password = get_clean("password")
    if not user or not password:
        return None
    host = get_clean("host")
    port = _parse_port_value(get_clean("port"), 0) or None
    database = get_clean("database")
    return user, password, host, port, database


def _replica_cnf_candidates(active_env: Mapping[str, str], home_dir: Optional[Path | str] = None) -> list[Path]:
    candidates: list[Path] = []
    tool_data_raw = str(active_env.get("TOOL_DATA_DIR") or "").strip()
    if tool_data_raw:
        candidates.append(Path(os.path.expanduser(os.path.expandvars(tool_data_raw))) / "replica.my.cnf")
    if home_dir is not None:
        resolved_home = Path(home_dir)
    elif str(active_env.get("HOME") or "").strip():
        resolved_home = Path(str(active_env["HOME"]).strip())
    else:
        resolved_home = Path.home()
    home_cnf = resolved_home / "replica.my.cnf"
    if home_cnf not in candidates:
        candidates.append(home_cnf)
    return candidates


def discover_wiki_replica_credentials(
    env: Optional[Mapping[str, str]] = None,
    *,
    home_dir: Optional[Path | str] = None,
) -> Optional[Tuple[str, str]]:
    """Discovers Wiki Replicas client credentials from environment variables or replica.my.cnf."""
    active_env = os.environ if env is None else env
    explicit_user = str(active_env.get("TOOL_REPLICA_USER") or "").strip()
    explicit_pass = str(active_env.get("TOOL_REPLICA_PASSWORD") or "").strip()
    if explicit_user and explicit_pass:
        return explicit_user, explicit_pass

    for cnf_path in _replica_cnf_candidates(active_env, home_dir=home_dir):
        parsed_cnf = _read_replica_my_cnf(cnf_path)
        if parsed_cnf is not None:
            cnf_user, cnf_pass, _, _, _ = parsed_cnf
            return cnf_user, cnf_pass
    return None


def build_databases_config(
    env: Optional[Mapping[str, str]] = None,
    base_dir: Path | str = BASE_DIR,
    *,
    is_test_run: bool = False,
    home_dir: Optional[Path | str] = None,
    is_management_command: Optional[bool] = None,
) -> dict[str, dict[str, Any]]:
    """Builds the Django DATABASES dictionary using ToolsDB credential discovery or SQLite fallback."""
    resolved_base = Path(base_dir)
    if is_test_run:
        return {
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
                "CONN_MAX_AGE": 0,
            }
        }

    active_env = os.environ if env is None else env
    env_host = str(active_env.get("TOOLSDB_HOST") or active_env.get("TOOL_TOOLSDB_HOST") or "").strip()
    env_port_raw = str(active_env.get("TOOLSDB_PORT") or active_env.get("TOOL_TOOLSDB_PORT") or "").strip()
    env_db_name = str(active_env.get("TOOLSDB_NAME") or active_env.get("TOOL_TOOLSDB_NAME") or "").strip()

    discovered: Optional[Tuple[str, str, str, int, str]] = None
    explicit_user = str(active_env.get("TOOLSDB_USER") or "").strip()
    explicit_pass = str(active_env.get("TOOLSDB_PASSWORD") or "").strip()
    tool_user = str(active_env.get("TOOL_TOOLSDB_USER") or "").strip()
    tool_pass = str(active_env.get("TOOL_TOOLSDB_PASSWORD") or "").strip()

    if explicit_user and explicit_pass:
        discovered = (
            explicit_user,
            explicit_pass,
            env_host or DEFAULT_TOOLSDB_HOST,
            _parse_port_value(env_port_raw, DEFAULT_TOOLSDB_PORT),
            env_db_name,
        )
    elif tool_user and tool_pass:
        discovered = (
            tool_user,
            tool_pass,
            env_host or DEFAULT_TOOLSDB_HOST,
            _parse_port_value(env_port_raw, DEFAULT_TOOLSDB_PORT),
            env_db_name,
        )
    else:
        for cnf_path in _replica_cnf_candidates(active_env, home_dir=home_dir):
            parsed_cnf = _read_replica_my_cnf(cnf_path)
            if parsed_cnf is not None:
                cnf_user, cnf_pass, cnf_host, cnf_port, cnf_db = parsed_cnf
                discovered = (
                    cnf_user,
                    cnf_pass,
                    env_host or cnf_host or DEFAULT_TOOLSDB_HOST,
                    _parse_port_value(env_port_raw, cnf_port or DEFAULT_TOOLSDB_PORT),
                    env_db_name or cnf_db,
                )
                break

    if discovered is not None:
        db_user, db_password, db_host, db_port, db_name = discovered
        if db_name:
            if is_management_command is None:
                subcommand = str(sys.argv[1]).strip().lower() if len(sys.argv) >= 2 else ""
                script_name = Path(str(sys.argv[0])).name.lower() if sys.argv else ""
                use_management_timeouts = subcommand in _MANAGEMENT_COMMAND_DB_TIMEOUT_COMMANDS or (
                    script_name == "manage.py" and bool(subcommand) and subcommand not in {"runserver", "test"}
                )
            else:
                use_management_timeouts = bool(is_management_command)

            return {
                "default": {
                    "ENGINE": "django.db.backends.mysql",
                    "NAME": db_name,
                    "USER": db_user,
                    "PASSWORD": db_password,
                    "HOST": db_host,
                    "PORT": db_port,
                    "CONN_MAX_AGE": 0,
                    "OPTIONS": {
                        "connect_timeout": _parse_int_env(
                            "TOOLSDB_CONNECT_TIMEOUT",
                            10 if use_management_timeouts else 3,
                            mapping=active_env,
                        ),
                        "read_timeout": _parse_int_env(
                            "TOOLSDB_READ_TIMEOUT",
                            120 if use_management_timeouts else 5,
                            mapping=active_env,
                        ),
                        "write_timeout": _parse_int_env(
                            "TOOLSDB_WRITE_TIMEOUT",
                            30 if use_management_timeouts else 5,
                            mapping=active_env,
                        ),
                        "charset": "utf8mb4",
                    },
                }
            }

    return {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": resolved_base / "db.sqlite3",
            "CONN_MAX_AGE": 0,
        }
    }


DATABASES = build_databases_config(os.environ, BASE_DIR, is_test_run=_IS_TEST_RUN)

REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
REDIS_KEY_PREFIX = os.environ.get("REDIS_KEY_PREFIX", "proxycheck_dev_")
REDIS_KEY_SECRET = os.environ.get("REDIS_KEY_SECRET", "").strip()
TOOLSDB_PASSWORD = os.environ.get("TOOLSDB_PASSWORD", "")
TOOL_TOOLSDB_PASSWORD = os.environ.get("TOOL_TOOLSDB_PASSWORD", "")
TOOL_REPLICA_PASSWORD = os.environ.get("TOOL_REPLICA_PASSWORD", "")
RANGEBLOCK_REALTIME_WIKIS = os.environ.get("RANGEBLOCK_REALTIME_WIKIS", "enwiki")


def _build_default_cache_config(
    redis_url: str,
    key_prefix: str,
    *,
    is_test_run: bool,
    key_secret: str = "",
) -> dict:
    effective_secret = str(key_secret or "").strip() or str(SECRET_KEY or "")
    isolated_prefix = build_redis_namespace(key_prefix, effective_secret)
    if is_test_run:
        return {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "proxycheck-test-cache",
            "TIMEOUT": 86400,
            "KEY_PREFIX": isolated_prefix,
        }
    return {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": redis_url,
        "TIMEOUT": 86400,
        "KEY_PREFIX": isolated_prefix,
        "OPTIONS": {
            "serializer": "detector.provider_registry.JsonRedisSerializer",
        },
    }


CACHES = {
    "default": _build_default_cache_config(
        REDIS_URL,
        REDIS_KEY_PREFIX,
        is_test_run=_IS_TEST_RUN,
        key_secret=REDIS_KEY_SECRET or SECRET_KEY,
    )
}

AUTH_PASSWORD_VALIDATORS = []

LANGUAGE_CODE = "en-gb"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# Match Vite assets directory output so WhiteNoise serves static assets directly on port 8000.
STATIC_URL = "/assets/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "dist" / "assets"] if (BASE_DIR / "dist" / "assets").exists() else []

WHITENOISE_USE_FINDERS = True
WHITENOISE_AUTOREFRESH = DEBUG

STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedStaticFilesStorage",
    },
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

WIKIMEDIA_OAUTH_URL = os.environ.get("WIKIMEDIA_OAUTH_URL", "https://meta.wikimedia.org/w/rest.php/oauth2").strip()
WIKIMEDIA_CLIENT_ID = os.environ.get("WIKIMEDIA_CLIENT_ID", "").strip()
WIKIMEDIA_CLIENT_SECRET = os.environ.get("WIKIMEDIA_CLIENT_SECRET", "").strip()
WIKIMEDIA_REDIRECT_URI = os.environ.get(
    "WIKIMEDIA_REDIRECT_URI", "https://proxycheck.toolforge.org/oauth/callback"
).strip()
GADGET_TOKEN_TTL_SECONDS = _parse_int_env("GADGET_TOKEN_TTL_SECONDS", 900)
DETECT_USER_RPM_LIMIT = _parse_int_env("DETECT_USER_RPM_LIMIT", 120, min_value=0)
DETECT_GLOBAL_RPM_LIMIT = _parse_int_env("DETECT_GLOBAL_RPM_LIMIT", 600, min_value=0)
DETECT_BATCH_USER_RPM_LIMIT = _parse_int_env("DETECT_BATCH_USER_RPM_LIMIT", 20, min_value=0)
DETECT_BATCH_GLOBAL_RPM_LIMIT = _parse_int_env("DETECT_BATCH_GLOBAL_RPM_LIMIT", 100, min_value=0)
RANGEBLOCK_USER_RPM_LIMIT = _parse_int_env("RANGEBLOCK_USER_RPM_LIMIT", 120, min_value=0)
RANGEBLOCK_GLOBAL_RPM_LIMIT = _parse_int_env("RANGEBLOCK_GLOBAL_RPM_LIMIT", 600, min_value=0)
GADGET_TOKEN_USER_RPM_LIMIT = _parse_int_env("GADGET_TOKEN_USER_RPM_LIMIT", 15, min_value=0)
GADGET_TOKEN_GLOBAL_RPM_LIMIT = _parse_int_env("GADGET_TOKEN_GLOBAL_RPM_LIMIT", 240, min_value=0)
REFRESH_USER_RPM_LIMIT = _parse_int_env("REFRESH_USER_RPM_LIMIT", 6, min_value=0)
REFRESH_USER_RPH_LIMIT = _parse_int_env("REFRESH_USER_RPH_LIMIT", 60, min_value=0)
REFRESH_GLOBAL_RPM_LIMIT = _parse_int_env("REFRESH_GLOBAL_RPM_LIMIT", 30, min_value=0)
ALLOWED_WIKI_USERS = os.environ.get("ALLOWED_WIKI_USERS", "")

PROVIDER_STATIC_CACHE_TTL_SECONDS = _parse_int_env("PROVIDER_STATIC_CACHE_TTL_SECONDS", 86400)
PROVIDER_DYNAMIC_CACHE_TTL_SECONDS = _parse_int_env("PROVIDER_DYNAMIC_CACHE_TTL_SECONDS", 7200)
GETIPINTEL_STABLE_CACHE_TTL_SECONDS = _parse_int_env("GETIPINTEL_STABLE_CACHE_TTL_SECONDS", 259200)
PROVIDER_COOLDOWN_DEFAULT_SECONDS = _parse_int_env("PROVIDER_COOLDOWN_DEFAULT_SECONDS", 120)
PROVIDER_COOLDOWN_MIN_SECONDS = _parse_int_env("PROVIDER_COOLDOWN_MIN_SECONDS", 60)
PROVIDER_COOLDOWN_MAX_SECONDS = _parse_int_env("PROVIDER_COOLDOWN_MAX_SECONDS", 300)
DNS_QUERY_TIMEOUT_SECONDS = _parse_positive_float_env("DNS_QUERY_TIMEOUT_SECONDS", 2.0)
DNS_QUERY_LIFETIME_SECONDS = _parse_positive_float_env("DNS_QUERY_LIFETIME_SECONDS", 2.0)

ENABLE_L2_TOOLSDB_CACHE = _parse_bool_env("ENABLE_L2_TOOLSDB_CACHE", default=True)
CACHE_SWR_STALE_DAYS = _parse_int_env("CACHE_SWR_STALE_DAYS", 90)
PROVIDER_L2_MAX_RETENTION_DAYS = dict(DEFAULT_PROVIDER_L2_MAX_RETENTION_DAYS)

for _provider_meta in PROVIDER_REGISTRY:
    if _provider_meta.credential_setting is not None:
        globals()[_provider_meta.credential_setting] = os.environ.get(_provider_meta.credential_setting, "")
    if _provider_meta.has_quota_env_vars:
        _rpm_limit = _parse_int_env(_provider_meta.rpm_setting, _provider_meta.default_rpm_limit, min_value=0)
        _daily_limit = _parse_int_env(_provider_meta.daily_setting, _provider_meta.default_daily_limit, min_value=0)
    else:
        _rpm_limit = 0
        _daily_limit = 0
    globals()[_provider_meta.rpm_setting] = _rpm_limit
    globals()[_provider_meta.daily_setting] = _daily_limit

PROVIDER_QUOTA_LIMITS = {
    meta.key: {
        "rpm": globals()[meta.rpm_setting],
        "daily": globals()[meta.daily_setting],
    }
    for meta in PROVIDER_REGISTRY
}
del _provider_meta, _rpm_limit, _daily_limit


def expand_configured_path(raw_path: str) -> str:
    """Expands environment variables and user home shortcuts in configured paths."""
    cleaned = str(raw_path or "").strip()
    if not cleaned:
        return ""
    return os.path.expanduser(os.path.expandvars(cleaned))


def _configured_tool_data_dir(explicit_tool_data_dir: Optional[str] = None) -> str:
    if explicit_tool_data_dir is not None:
        return expand_configured_path(explicit_tool_data_dir)
    try:
        from django.conf import settings as django_settings

        if django_settings.configured:
            setting_val = getattr(django_settings, "TOOL_DATA_DIR", "")
            if isinstance(setting_val, str) and setting_val.strip():
                return expand_configured_path(setting_val)
    except ImportError, RuntimeError:
        pass
    return expand_configured_path(os.environ.get("TOOL_DATA_DIR", ""))


def resolve_tool_data_subdir(tool_data_dir: str) -> Path:
    """Resolves the persistent offline data subdirectory beneath a configured TOOL_DATA_DIR root."""
    tool_root = Path(expand_configured_path(tool_data_dir))
    legacy_www_data = tool_root / "www" / "python" / "data"
    if legacy_www_data.is_dir():
        return legacy_www_data
    return tool_root / "data"


def standard_data_directories(base_dir: Path | str, *, tool_data_dir: Optional[str] = None) -> list[Path]:
    """Returns local workspace and Toolforge data directories in lookup priority order."""
    resolved_tool_dir = _configured_tool_data_dir(tool_data_dir)
    if resolved_tool_dir:
        expanded_tool_dir = Path(resolved_tool_dir)
        return [
            expanded_tool_dir / "www" / "python" / "data",
            expanded_tool_dir / "data",
        ]

    base_path = Path(str(base_dir))
    home_dir = Path.home()
    return [
        base_path.parent / "data",
        base_path.parent,
        base_path / "data",
        base_path,
        home_dir / "www" / "python" / "data",
        home_dir / "data",
    ]


def find_mmdb_in_directory(directory: Path, filename: str) -> Optional[Path]:
    """Finds an MMDB file directly inside directory or one extracted archive subdirectory."""
    direct = directory / filename
    if direct.exists():
        return direct
    if directory.is_dir():
        nested_matches = sorted(match for match in directory.glob(f"*/{filename}") if match.is_file())
        if nested_matches:
            return nested_matches[0]
    return None


def resolve_data_file(
    configured_path: str,
    filename: str,
    base_dir: Path | str,
    *,
    default_missing: Optional[str] = None,
) -> str:
    """Finds a local intelligence data file across configured, workspace, and Toolforge data paths."""
    expanded_configured = expand_configured_path(configured_path)
    if expanded_configured:
        configured = Path(expanded_configured)
        if configured.is_file():
            return str(configured)
        if configured.is_dir():
            return str(configured / filename)

    for directory in standard_data_directories(base_dir):
        candidate = directory / filename
        if candidate.exists():
            return str(candidate)

    return expanded_configured if default_missing is None else default_missing


def resolve_mmdb_file(
    configured_path: str,
    filename: str,
    base_dir: Path | str,
    *,
    default_missing: Optional[str] = None,
) -> str:
    """Resolves an MMDB file from a configured directory or standard data locations."""
    expanded_configured = expand_configured_path(configured_path)
    if expanded_configured:
        configured = Path(expanded_configured)
        if configured.is_file():
            return str(configured)
        matched = find_mmdb_in_directory(configured, filename)
        if matched is not None:
            return str(matched)
        return str(configured / filename)

    resolved_tool_dir = _configured_tool_data_dir()
    default_dir = (
        resolve_tool_data_subdir(resolved_tool_dir) if resolved_tool_dir else (Path(str(base_dir)).parent / "data")
    )
    fallback = default_missing if default_missing is not None else str(default_dir / filename)
    resolved_direct = resolve_data_file("", filename, base_dir, default_missing="")
    if resolved_direct:
        return resolved_direct

    for directory in standard_data_directories(base_dir):
        matched = find_mmdb_in_directory(directory, filename)
        if matched is not None:
            return str(matched)

    return fallback


TOOL_DATA_DIR = os.environ.get("TOOL_DATA_DIR", "").strip()
MAXMIND_COUNTRY_DB_FILENAME = "GeoLite2-Country.mmdb"
MAXMIND_CITY_DB_FILENAME = "GeoLite2-City.mmdb"
MAXMIND_ASN_DB_FILENAME = "GeoLite2-ASN.mmdb"
MAXMIND_ACCOUNT_ID = os.environ.get("MAXMIND_ACCOUNT_ID", "").strip()
MAXMIND_LICENSE_KEY = os.environ.get("MAXMIND_LICENSE_KEY", "").strip()
HOSTING_ASN_RULES_PATH = (
    os.environ.get("HOSTING_ASN_RULES_PATH", "").strip()
    or resolve_data_file("", "hosting_asn_rules.json", BASE_DIR, default_missing="")
    or str(BASE_DIR.parent / "data" / "hosting_asn_rules.json")
)
HOSTING_ASNS = _parse_csv_env("HOSTING_ASNS")
HOSTING_ORG_KEYWORDS = _parse_csv_env("HOSTING_ORG_KEYWORDS")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "detector": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "httpx": {
            "level": "WARNING",
        },
        "httpcore": {
            "level": "WARNING",
        },
    },
}
