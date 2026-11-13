"""
Django configuration for Proxy Detector on Wikimedia Toolforge.
"""

import math
import os
import sys
from pathlib import Path
from typing import Optional

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent


def _resolve_dotenv_path(base_dir: Path, tool_data_dir: str = "") -> Optional[Path]:
    """Locate an environment file from local project roots or Toolforge mounted storage."""
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
_dotenv_path = _resolve_dotenv_path(BASE_DIR, _TOOL_DATA_DIR)
if _dotenv_path is not None:
    load_dotenv(dotenv_path=_dotenv_path)
else:
    load_dotenv()

DEBUG = os.environ.get("DJANGO_DEBUG", "False").lower() in ("true", "1", "yes")
ENABLE_TEST_AUTH = os.environ.get("ENABLE_TEST_AUTH") == "1"

_IS_TEST_RUN = "test" in sys.argv or "pytest" in sys.modules

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")
if not SECRET_KEY:
    if not DEBUG and not _IS_TEST_RUN and "collectstatic" not in sys.argv:
        raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set in production.")
    SECRET_KEY = "django-insecure-dev-key"  # noqa: S105


def _parse_allowed_hosts(raw_value: str) -> list[str]:
    """Parses comma-separated hosts and converts leading *. wildcards to Django dot syntax."""
    hosts: list[str] = []
    for entry in raw_value.split(","):
        host = entry.strip()
        if not host:
            continue
        if host.startswith("*.") and len(host) > 2:
            host = host[1:]
        hosts.append(host)
    return hosts or ["127.0.0.1", "localhost"]


ALLOWED_HOSTS = _parse_allowed_hosts(os.environ.get("DJANGO_ALLOWED_HOSTS", ""))

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

# Toolforge Kubernetes Ingress passes HTTPS termination via X-Forwarded-Proto
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Session cookie and production security baseline configuration for Toolforge
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

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
REDIS_KEY_PREFIX = os.environ.get("REDIS_KEY_PREFIX", "proxycheck_dev_")


def _build_default_cache_config(redis_url: str, key_prefix: str, *, is_test_run: bool) -> dict:
    if is_test_run:
        return {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "proxycheck-test-cache",
            "TIMEOUT": 86400,
            "KEY_PREFIX": key_prefix,
        }
    return {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": redis_url,
        "TIMEOUT": 86400,
        "KEY_PREFIX": key_prefix,
    }


CACHES = {
    "default": _build_default_cache_config(
        REDIS_URL,
        REDIS_KEY_PREFIX,
        is_test_run=_IS_TEST_RUN,
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
STATICFILES_DIRS = (
    [
        BASE_DIR / "dist" / "assets",
    ]
    if (BASE_DIR / "dist" / "assets").exists()
    else []
)

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


def _parse_positive_int_env(name: str, default: int) -> int:
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        parsed = int(raw_value)
        return parsed if parsed > 0 else default
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


WIKIMEDIA_OAUTH_URL = os.environ.get("WIKIMEDIA_OAUTH_URL", "https://meta.wikimedia.org/w/rest.php/oauth2").strip()
WIKIMEDIA_CLIENT_ID = os.environ.get("WIKIMEDIA_CLIENT_ID", "").strip()
WIKIMEDIA_CLIENT_SECRET = os.environ.get("WIKIMEDIA_CLIENT_SECRET", "").strip()
WIKIMEDIA_REDIRECT_URI = os.environ.get(
    "WIKIMEDIA_REDIRECT_URI", "https://proxycheck.toolforge.org/oauth/callback"
).strip()
GADGET_TOKEN_TTL_SECONDS = _parse_positive_int_env("GADGET_TOKEN_TTL_SECONDS", 604800)
ALLOWED_WIKI_USERS = os.environ.get("ALLOWED_WIKI_USERS", "")

PROVIDER_STATIC_CACHE_TTL_SECONDS = _parse_positive_int_env("PROVIDER_STATIC_CACHE_TTL_SECONDS", 86400)
PROVIDER_DYNAMIC_CACHE_TTL_SECONDS = _parse_positive_int_env("PROVIDER_DYNAMIC_CACHE_TTL_SECONDS", 7200)
PROVIDER_COOLDOWN_DEFAULT_SECONDS = _parse_positive_int_env("PROVIDER_COOLDOWN_DEFAULT_SECONDS", 120)
PROVIDER_COOLDOWN_MIN_SECONDS = _parse_positive_int_env("PROVIDER_COOLDOWN_MIN_SECONDS", 60)
PROVIDER_COOLDOWN_MAX_SECONDS = _parse_positive_int_env("PROVIDER_COOLDOWN_MAX_SECONDS", 300)
DNS_QUERY_TIMEOUT_SECONDS = _parse_positive_float_env("DNS_QUERY_TIMEOUT_SECONDS", 2.0)
DNS_QUERY_LIFETIME_SECONDS = _parse_positive_float_env("DNS_QUERY_LIFETIME_SECONDS", 2.0)

CLOUDFLARE_RADAR_TOKEN = os.environ.get("CLOUDFLARE_RADAR_TOKEN", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
IPDATA_API_KEY = os.environ.get("IPDATA_API_KEY", "")
IPREGISTRY_API_KEY = os.environ.get("IPREGISTRY_API_KEY", "")
IP2LOCATION_API_KEY = os.environ.get("IP2LOCATION_API_KEY", "")
GETIPINTEL_CONTACT_EMAIL = os.environ.get("GETIPINTEL_CONTACT_EMAIL", "")
PROXYCHECK_API_KEY = os.environ.get("PROXYCHECK_API_KEY", "")
IPHUB_API_KEY = os.environ.get("IPHUB_API_KEY", "")
IPHUNTER_API_KEY = os.environ.get("IPHUNTER_API_KEY", "")


def resolve_mmdb_file(
    configured_path: str,
    filename: str,
    base_dir: Path | str,
    *,
    default_missing: Optional[str] = None,
) -> str:
    """Finds an MMDB file across configured, workspace, and Toolforge data paths."""
    if configured_path:
        configured = Path(configured_path)
        if configured.is_file():
            return str(configured)
        if configured.is_dir():
            return str(configured / filename)

    base_path = Path(str(base_dir))
    # Check local workspace directories and Toolforge mounted data paths in order.
    candidates = [
        base_path.parent / "data" / filename,
        base_path.parent / filename,
        base_path / "data" / filename,
        base_path / filename,
    ]
    tool_data_dir = os.environ.get("TOOL_DATA_DIR", "").strip()
    if tool_data_dir:
        candidates.append(Path(tool_data_dir) / "www" / "python" / "data" / filename)
    candidates.append(Path.home() / "www" / "python" / "data" / filename)
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    return configured_path if default_missing is None else default_missing


def _resolve_mmdb_path(env_var_name: str, filename: str) -> str:
    custom_path = os.environ.get(env_var_name, "").strip()
    if custom_path:
        return custom_path
    return resolve_mmdb_file(
        "",
        filename,
        BASE_DIR,
        default_missing=str(BASE_DIR.parent / "data" / filename),
    )


MAXMIND_COUNTRY_DB_PATH = _resolve_mmdb_path("MAXMIND_COUNTRY_DB_PATH", "GeoLite2-Country.mmdb")
MAXMIND_ASN_DB_PATH = _resolve_mmdb_path("MAXMIND_ASN_DB_PATH", "GeoLite2-ASN.mmdb")
