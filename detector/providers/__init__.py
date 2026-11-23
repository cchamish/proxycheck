"""External HTTP, DNS/DNSBL, and local provider execution and response adapters."""

from __future__ import annotations

from typing import Any, Dict

from .adapters_http import (
    SHODAN_HIGH_RISK_PROXY_PORTS,
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
    adapt_spamcop,
    adapt_spamhaus_zen,
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

ADAPTER_DISPATCH_TABLE: Dict[str, Any] = {
    "cloudflare_radar": adapt_cloudflare_radar,
    "abuseipdb": adapt_abuseipdb,
    "ipdata": adapt_ipdata,
    "ipregistry": adapt_ipregistry,
    "ip2location": adapt_ip2location,
    "maxmind": adapt_maxmind,
    "getipintel": adapt_getipintel,
    "proxycheck": adapt_proxycheck,
    "iphub": adapt_iphub,
    "iphunter": adapt_iphunter,
    "spamhaus_zen": adapt_spamhaus_zen,
    "spamcop": adapt_spamcop,
    "tor_onionoo": adapt_tor_onionoo,
    "stopforumspam": adapt_stopforumspam,
    "dshield": adapt_dshield,
    "ipsum_drop": adapt_ipsum_drop,
    "openasn": adapt_openasn,
    "shodan_internetdb": adapt_shodan_internetdb,
}

__all__ = [
    "ADAPTER_DISPATCH_TABLE",
    "PROVIDER_SPECS",
    "SHODAN_HIGH_RISK_PROXY_PORTS",
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
    "adapt_spamcop",
    "adapt_spamhaus_zen",
    "adapt_stopforumspam",
    "adapt_tor_onionoo",
    "build_cooldown_provider_row",
    "build_deferred_provider_row",
    "build_unhandled_provider_error_row",
    "is_provider_result_cacheable",
    "is_unconfigured_provider_row",
]
