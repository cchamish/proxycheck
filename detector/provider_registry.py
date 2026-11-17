"""
Immutable registry of upstream IP intelligence providers, default quota specifications,
and shared infrastructure constants with zero Django dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Optional, Tuple

try:
    from redis.exceptions import RedisError as _RedisError
except ImportError:
    _RedisError = None

USER_AGENT_HEADER = "ProxyCheck/1.0 (https://proxycheck.toolforge.org; tools.proxycheck@toolforge.org)"
REDIS_KEY_NAMESPACE = "proxycheck:v1"

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
    def env_prefix(self) -> str:
        return self.key.upper()

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
)

PROVIDER_BY_KEY: Dict[str, ProviderMetadata] = {meta.key: meta for meta in PROVIDER_REGISTRY}

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

EXTRA_SECRET_SETTING_NAMES: Tuple[str, ...] = (
    "MAXMIND_ACCOUNT_ID",
    "MAXMIND_LICENSE_KEY",
    "WIKIMEDIA_CLIENT_SECRET",
)

SECRET_SETTING_NAMES: Tuple[str, ...] = (
    *(meta.credential_setting for meta in PROVIDER_REGISTRY if meta.credential_setting is not None),
    *EXTRA_SECRET_SETTING_NAMES,
)
