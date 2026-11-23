"""
Immutable registry of upstream IP intelligence providers, default quota specifications,
and shared infrastructure constants with zero Django dependencies.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Optional, Tuple

try:
    from redis.exceptions import RedisError as _RedisError
except ImportError:
    _RedisError = None

USER_AGENT_HEADER = "ProxyCheck/1.0 (https://proxycheck.toolforge.org; tools.proxycheck@toolforge.org)"


def build_redis_namespace(prefix: str, secret: str) -> str:
    """Builds an isolated Redis key namespace combining environment prefix and a keyed secret digest."""
    cleaned_prefix = str(prefix or "").strip().strip(":_") or "proxycheck"
    secret_bytes = str(secret or "").encode("utf-8")
    digest = hmac.new(secret_bytes, f"ns:{cleaned_prefix}".encode("utf-8"), hashlib.sha256).hexdigest()[:12]
    return f"{cleaned_prefix}:{digest}:v2"


def hash_ip_for_redis(canonical_ip: str, secret: str) -> str:
    """Computes a truncated HMAC-SHA256 digest so plaintext IP addresses never appear in Redis keys."""
    secret_bytes = str(secret or "").encode("utf-8")
    ip_bytes = str(canonical_ip or "").strip().encode("utf-8")
    return hmac.new(secret_bytes, ip_bytes, hashlib.sha256).hexdigest()[:24]


class JsonRedisSerializer:
    """JSON-based Redis cache serialiser replacing Pickle to prevent unsafe deserialisation."""

    def dumps(self, obj: Any) -> bytes | int:
        if type(obj) is int:
            return obj
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def loads(self, data: bytes | bytearray | str) -> Any:
        if isinstance(data, (bytes, bytearray)):
            text = bytes(data).decode("utf-8")
        elif isinstance(data, str):
            text = data
        else:
            raise ValueError(f"Unsupported Redis payload type: {type(data).__name__}")
        return json.loads(text)


REDIS_TRANSPORT_ERRORS: Tuple[type[BaseException], ...] = (
    (ConnectionError, TimeoutError, OSError, _RedisError)
    if _RedisError is not None
    else (ConnectionError, TimeoutError, OSError)
)


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    """Static configuration, classification flags, and default soft quota limits for a provider."""

    key: str
    label: str
    uses_http: bool
    supports_cooldown: bool
    active_in_light_mode: bool = False
    is_commercial_arbitration: bool = False
    is_dnsbl: bool = False
    is_offline: bool = False
    credential_setting: Optional[str] = None
    credential_description: Optional[str] = None
    default_rpm_limit: int = 0
    default_daily_limit: int = 0
    has_quota_env_vars: bool = True

    @property
    def rpm_setting(self) -> str:
        return f"{self.key.upper()}_RPM_LIMIT"

    @property
    def daily_setting(self) -> str:
        return f"{self.key.upper()}_DAILY_LIMIT"


PROVIDER_REGISTRY: Tuple[ProviderMetadata, ...] = (
    ProviderMetadata(
        key="cloudflare_radar",
        label="Cloudflare Radar",
        uses_http=True,
        supports_cooldown=True,
        active_in_light_mode=True,
        is_commercial_arbitration=False,
        credential_setting="CLOUDFLARE_RADAR_TOKEN",
        credential_description="Cloudflare Radar API Bearer token",
        default_rpm_limit=240,
        default_daily_limit=0,
    ),
    ProviderMetadata(
        key="abuseipdb",
        label="AbuseIPDB",
        uses_http=True,
        supports_cooldown=True,
        is_commercial_arbitration=True,
        credential_setting="ABUSEIPDB_API_KEY",
        credential_description="AbuseIPDB v2 API key",
        default_rpm_limit=0,
        default_daily_limit=1000,
    ),
    ProviderMetadata(
        key="ipdata",
        label="IPData",
        uses_http=True,
        supports_cooldown=True,
        is_commercial_arbitration=True,
        credential_setting="IPDATA_API_KEY",
        credential_description="IPData API key",
        default_rpm_limit=0,
        default_daily_limit=1000,
    ),
    ProviderMetadata(
        key="ipregistry",
        label="IPRegistry",
        uses_http=True,
        supports_cooldown=True,
        is_commercial_arbitration=True,
        credential_setting="IPREGISTRY_API_KEY",
        credential_description="IPRegistry API key",
        default_rpm_limit=50,
        default_daily_limit=0,
    ),
    ProviderMetadata(
        key="ip2location",
        label="IP2Location",
        uses_http=True,
        supports_cooldown=True,
        is_commercial_arbitration=True,
        credential_setting="IP2LOCATION_API_KEY",
        credential_description="IP2Location.io API key",
        default_rpm_limit=0,
        default_daily_limit=1000,
    ),
    ProviderMetadata(
        key="getipintel",
        label="GetIPIntel",
        uses_http=True,
        supports_cooldown=True,
        is_commercial_arbitration=True,
        credential_setting="GETIPINTEL_CONTACT_EMAIL",
        credential_description="Contact email address required by GetIPIntel API",
        default_rpm_limit=15,
        default_daily_limit=500,
    ),
    ProviderMetadata(
        key="proxycheck",
        label="Proxycheck",
        uses_http=True,
        supports_cooldown=True,
        is_commercial_arbitration=True,
        credential_setting="PROXYCHECK_API_KEY",
        credential_description="Proxycheck.io API key",
        default_rpm_limit=0,
        default_daily_limit=1000,
    ),
    ProviderMetadata(
        key="iphub",
        label="IPHub",
        uses_http=True,
        supports_cooldown=True,
        is_commercial_arbitration=True,
        credential_setting="IPHUB_API_KEY",
        credential_description="IPHub API key",
        default_rpm_limit=0,
        default_daily_limit=1000,
    ),
    ProviderMetadata(
        key="iphunter",
        label="IPHunter",
        uses_http=True,
        supports_cooldown=True,
        is_commercial_arbitration=True,
        credential_setting="IPHUNTER_API_KEY",
        credential_description="IPHunter API key",
        default_rpm_limit=0,
        default_daily_limit=1000,
    ),
    ProviderMetadata(
        key="maxmind",
        label="MaxMind",
        uses_http=False,
        supports_cooldown=False,
        active_in_light_mode=True,
        is_offline=True,
        has_quota_env_vars=False,
    ),
    ProviderMetadata(
        key="spamhaus_zen",
        label="Spamhaus ZEN",
        uses_http=False,
        supports_cooldown=True,
        active_in_light_mode=True,
        is_dnsbl=True,
        default_rpm_limit=1000,
        default_daily_limit=0,
    ),
    ProviderMetadata(
        key="spamcop",
        label="SpamCop",
        uses_http=False,
        supports_cooldown=True,
        active_in_light_mode=True,
        is_dnsbl=True,
        default_rpm_limit=0,
        default_daily_limit=0,
    ),
    ProviderMetadata(
        key="tor_onionoo",
        label="Tor Onionoo",
        uses_http=True,
        supports_cooldown=True,
        active_in_light_mode=True,
        default_rpm_limit=0,
        default_daily_limit=0,
    ),
    ProviderMetadata(
        key="stopforumspam",
        label="StopForumSpam",
        uses_http=False,
        supports_cooldown=False,
        active_in_light_mode=True,
        is_offline=True,
        has_quota_env_vars=False,
    ),
    ProviderMetadata(
        key="dshield",
        label="DShield",
        uses_http=True,
        supports_cooldown=True,
        active_in_light_mode=True,
        default_rpm_limit=1000,
        default_daily_limit=0,
    ),
    ProviderMetadata(
        key="ipsum_drop",
        label="IPsum / DROP",
        uses_http=False,
        supports_cooldown=False,
        active_in_light_mode=True,
        is_offline=True,
        has_quota_env_vars=False,
    ),
    ProviderMetadata(
        key="openasn",
        label="OpenASN",
        uses_http=False,
        supports_cooldown=False,
        active_in_light_mode=True,
        is_offline=True,
        has_quota_env_vars=False,
    ),
    ProviderMetadata(
        key="shodan_internetdb",
        label="Shodan InternetDB",
        uses_http=True,
        supports_cooldown=True,
        active_in_light_mode=False,
        is_commercial_arbitration=False,
        default_rpm_limit=120,
        default_daily_limit=0,
    ),
)

PROVIDER_BY_KEY: Dict[str, ProviderMetadata] = {meta.key: meta for meta in PROVIDER_REGISTRY}

PROVIDER_BY_LABEL: Dict[str, ProviderMetadata] = {meta.label: meta for meta in PROVIDER_REGISTRY}

PROVIDER_CREDENTIAL_SETTINGS: Dict[str, str] = {
    meta.key: meta.credential_setting for meta in PROVIDER_REGISTRY if meta.credential_setting is not None
}

DEFAULT_QUOTA_LIMITS: Dict[str, Tuple[int, int]] = {
    meta.key: (meta.default_rpm_limit, meta.default_daily_limit) for meta in PROVIDER_REGISTRY
}

COMMERCIAL_ARBITRATION_PROVIDERS: FrozenSet[str] = frozenset(
    meta.label for meta in PROVIDER_REGISTRY if meta.is_commercial_arbitration
)

LIGHT_MODE_ACTIVE_PROVIDER_KEYS: FrozenSet[str] = frozenset(
    meta.key for meta in PROVIDER_REGISTRY if meta.active_in_light_mode
)

DNSBL_PROVIDER_KEYS: FrozenSet[str] = frozenset(meta.key for meta in PROVIDER_REGISTRY if meta.is_dnsbl)

OFFLINE_PROVIDER_KEYS: FrozenSet[str] = frozenset(meta.key for meta in PROVIDER_REGISTRY if meta.is_offline)

OFFLINE_REHYDRATE_PROVIDERS: FrozenSet[str] = OFFLINE_PROVIDER_KEYS

# Local mmap lookups cost microseconds, so these providers never touch Redis or the L1/L2 snapshots.
NO_REDIS_CACHE_PROVIDER_KEYS: FrozenSet[str] = frozenset({"openasn"})

L1_ONLY_PROVIDERS: FrozenSet[str] = frozenset({"iphub", "spamhaus_zen", "spamcop"})

DEFAULT_PROVIDER_L2_MAX_RETENTION_DAYS: Dict[str, int] = {"ip2location": 30}

EXTRA_SECRET_SETTING_NAMES: Tuple[str, ...] = (
    "MAXMIND_ACCOUNT_ID",
    "MAXMIND_LICENSE_KEY",
    "WIKIMEDIA_CLIENT_SECRET",
    "REDIS_KEY_SECRET",
    "TOOLSDB_PASSWORD",
    "TOOL_TOOLSDB_PASSWORD",
    "TOOL_REPLICA_PASSWORD",
)

SECRET_SETTING_NAMES: Tuple[str, ...] = (
    *(meta.credential_setting for meta in PROVIDER_REGISTRY if meta.credential_setting is not None),
    *EXTRA_SECRET_SETTING_NAMES,
)
