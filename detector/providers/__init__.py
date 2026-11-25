"""External HTTP, DNS/DNSBL, and local provider execution and response adapters."""

from __future__ import annotations

from .adapters_http import (
    adapt_abuseipdb,
    adapt_cloudflare_radar,
    adapt_dshield,
    adapt_getipintel,
    adapt_ip2location,
    adapt_ipdata,
    adapt_iphub,
    adapt_iphunter,
    adapt_ipregistry,
    adapt_proxycheck,
    adapt_shodan_internetdb,
    adapt_tor_onionoo,
)
from .adapters_local import (
    adapt_ipsum_drop,
    adapt_maxmind,
    adapt_openasn,
    adapt_stopforumspam,
)
from .http import (
    PROVIDER_SPECS,
    ProviderSpec,
    build_cooldown_provider_row,
    build_deferred_provider_row,
    build_unhandled_provider_error_row,
    is_provider_result_cacheable,
    is_unconfigured_provider_row,
)

__all__ = [
    "PROVIDER_SPECS",
    "ProviderSpec",
    "adapt_abuseipdb",
    "adapt_cloudflare_radar",
    "adapt_dshield",
    "adapt_getipintel",
    "adapt_ip2location",
    "adapt_ipdata",
    "adapt_iphub",
    "adapt_iphunter",
    "adapt_ipregistry",
    "adapt_ipsum_drop",
    "adapt_maxmind",
    "adapt_openasn",
    "adapt_proxycheck",
    "adapt_shodan_internetdb",
    "adapt_stopforumspam",
    "adapt_tor_onionoo",
    "build_cooldown_provider_row",
    "build_deferred_provider_row",
    "build_unhandled_provider_error_row",
    "is_provider_result_cacheable",
    "is_unconfigured_provider_row",
]
