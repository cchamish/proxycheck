"""
Upstream HTTP IP intelligence provider queries and shared provider specification registry.
"""

import asyncio
import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterator, Optional, Tuple, Union

import httpx
from django.conf import settings

from . import adapters, dns_providers, offline_dbs, sanitization
from .adapters import (
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
from .cache_backends import get_cooldown_bounds
from .dns_providers import (
    provider_upstream_events,
    record_upstream_event,
)
from .provider_registry import PROVIDER_REGISTRY, USER_AGENT_HEADER
from .quota_telemetry import extract_upstream_rate_limit
from .sanitization import (
    extract_response_log_details,
    parse_upstream_json_with_error,
    sanitize_error_message,
)

logger = logging.getLogger("detector.views")


def _extract_retry_after_header(resp: Any) -> Optional[str]:
    headers = getattr(resp, "headers", None)
    if headers is None:
        return None
    getter = getattr(headers, "get", None)
    if not callable(getter):
        return None
    for header_name in ("Retry-After", "retry-after"):
        val = getter(header_name)
        if isinstance(val, str):
            return val
    return None


def parse_retry_after_seconds(raw_header: Optional[str]) -> int:
    """Parses an integer Retry-After delay and clamps it within configured cooldown bounds."""
    default_s, low, high = get_cooldown_bounds()
    if not isinstance(raw_header, str):
        return default_s
    cleaned = raw_header.strip()
    if not re.fullmatch(r"\d+", cleaned):
        return default_s
    return max(low, min(high, int(cleaned)))


_parse_retry_after_seconds = parse_retry_after_seconds


def _record_http_status_event(
    resp: Any,
    provider_key: str,
    raw_status: Any,
    parsed_status: int,
    payload: Any,
    default_cooldown: int,
) -> None:
    upstream_remaining, upstream_limit, upstream_used = extract_upstream_rate_limit(
        resp,
        payload if raw_status == 200 and parsed_status == 200 else None,
        provider_key,
    )
    if raw_status == 429:
        cooldown_secs = parse_retry_after_seconds(_extract_retry_after_header(resp))
        record_upstream_event(
            provider_key,
            trigger_cooldown=True,
            status_code=429,
            reason="429 Rate Limited",
            cooldown_seconds=cooldown_secs,
            upstream_remaining=upstream_remaining,
            upstream_limit=upstream_limit,
        )
    elif isinstance(raw_status, int) and raw_status >= 500:
        record_upstream_event(
            provider_key,
            trigger_cooldown=True,
            status_code=raw_status,
            reason=f"HTTP {raw_status}",
            cooldown_seconds=default_cooldown,
            upstream_remaining=upstream_remaining,
            upstream_limit=upstream_limit,
        )
    elif parsed_status >= 500 and raw_status == 200:
        record_upstream_event(
            provider_key,
            trigger_cooldown=True,
            status_code=parsed_status,
            reason="Malformed Gateway Body",
            cooldown_seconds=default_cooldown,
        )
    else:
        record_upstream_event(
            provider_key,
            trigger_cooldown=False,
            status_code=parsed_status,
            upstream_remaining=upstream_remaining,
            upstream_limit=upstream_limit,
            upstream_used=upstream_used,
        )


async def _fetch_upstream_json(
    client: httpx.AsyncClient,
    provider_key: str,
    provider_label: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[Union[float, httpx.Timeout]] = None,
    follow_redirects: bool = False,
    treat_404_as_ok: bool = False,
) -> Tuple[Any, int]:
    """
    Executes an upstream GET request, parses JSON safely, redacts leaked secrets on error,
    and records HTTP 429, 5xx, or timeout signals for per-provider circuit breaking.
    """
    default_cooldown, _, _ = get_cooldown_bounds()
    request_kwargs: Dict[str, Any] = {"follow_redirects": follow_redirects}
    if headers is not None:
        request_kwargs["headers"] = headers
    if timeout is not None:
        request_kwargs["timeout"] = timeout
    try:
        resp = await client.get(url, **request_kwargs)
    except (httpx.HTTPError, asyncio.TimeoutError, TimeoutError, OSError) as exc:
        is_timeout = isinstance(exc, (httpx.TimeoutException, asyncio.TimeoutError, TimeoutError))
        reason = "Upstream Timeout" if is_timeout else f"Upstream Exception ({type(exc).__name__})"
        raw_message = str(exc).strip()
        if raw_message:
            safe_message = sanitize_error_message(raw_message)
        elif is_timeout:
            safe_message = f"{type(exc).__name__}: upstream request timed out"
        else:
            safe_message = type(exc).__name__
        logger.error(f"{provider_label} request exception: {safe_message}")
        record_upstream_event(
            provider_key,
            trigger_cooldown=True,
            status_code=502,
            reason=reason,
            cooldown_seconds=default_cooldown,
            is_timeout=is_timeout,
            is_transport_error=True,
        )
        return {"status": "error", "message": safe_message}, 502

    raw_status = getattr(resp, "status_code", 502)
    payload, parsed_status, parse_error = parse_upstream_json_with_error(resp)
    if treat_404_as_ok and raw_status == 404:
        clean_404_payload = (
            payload
            if parse_error is None and isinstance(payload, dict)
            else {"detail": "No information available"}
        )
        _record_http_status_event(resp, provider_key, 200, 200, clean_404_payload, default_cooldown)
        return clean_404_payload, 404

    if isinstance(raw_status, int) and raw_status != 200:
        content_type, body_preview = extract_response_log_details(resp)
        logger.warning(
            f"{provider_label} returned HTTP {raw_status} (Content-Type: {content_type}; body: {body_preview})"
        )
    elif parse_error is not None:
        content_type, body_preview = extract_response_log_details(resp)
        logger.warning(
            f"{provider_label} returned non-JSON HTTP {raw_status} body ({parse_error} -> {parsed_status}; "
            f"Content-Type: {content_type}; body: {body_preview})"
        )
    _record_http_status_event(resp, provider_key, raw_status, parsed_status, payload, default_cooldown)
    return payload, parsed_status


def _get_provider_secret(setting_name: str) -> str:
    return os.environ.get(setting_name) or getattr(settings, setting_name, "")


async def query_cloudflare_radar(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    token = _get_provider_secret("CLOUDFLARE_RADAR_TOKEN")
    if not token:
        return adapt_cloudflare_radar(None, False)

    url = f"https://api.cloudflare.com/client/v4/radar/entities/asns/ip?ip={ip}"
    headers = {"Authorization": f"Bearer {token}"}
    payload, status_code = await _fetch_upstream_json(
        client, "cloudflare_radar", "Cloudflare Radar", url, headers=headers, timeout=8.0
    )
    return adapt_cloudflare_radar(payload, True, status_code)


async def query_abuseipdb(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = _get_provider_secret("ABUSEIPDB_API_KEY")
    if not api_key:
        return adapt_abuseipdb(None, False)

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": api_key, "Accept": "application/json"}
    payload, status_code = await _fetch_upstream_json(
        client, "abuseipdb", "AbuseIPDB", url, headers=headers, timeout=8.0
    )
    return adapt_abuseipdb(payload, True, status_code)


async def query_ipdata(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = _get_provider_secret("IPDATA_API_KEY")
    if not api_key:
        return adapt_ipdata(None, False)

    url = f"https://api.ipdata.co/{ip}?api-key={api_key}"
    payload, status_code = await _fetch_upstream_json(client, "ipdata", "IPData", url, timeout=8.0)
    return adapt_ipdata(payload, True, status_code)


async def query_ipregistry(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = _get_provider_secret("IPREGISTRY_API_KEY")
    if not api_key:
        return adapt_ipregistry(None, False)

    url = f"https://api.ipregistry.co/{ip}?key={api_key}"
    payload, status_code = await _fetch_upstream_json(client, "ipregistry", "IPRegistry", url, timeout=8.0)
    return adapt_ipregistry(payload, True, status_code)


async def query_ip2location(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = _get_provider_secret("IP2LOCATION_API_KEY")
    if not api_key:
        return adapt_ip2location(None, False)

    url = f"https://api.ip2location.io/?key={api_key}&ip={ip}"
    payload, status_code = await _fetch_upstream_json(client, "ip2location", "IP2Location", url, timeout=5.0)
    return adapt_ip2location(payload, True, status_code)


async def query_getipintel(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    """GetIPIntel requires a valid contact email in the query string instead of an API key."""
    contact_email = _get_provider_secret("GETIPINTEL_CONTACT_EMAIL")
    if not contact_email:
        return adapt_getipintel(None, False)

    url = f"https://check.getipintel.net/check.php?ip={ip}&contact={contact_email}&flags=f&format=json"
    payload, status_code = await _fetch_upstream_json(client, "getipintel", "GetIPIntel", url, timeout=5.0)
    return adapters.adapt_getipintel(payload, True, status_code)


async def query_proxycheck(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = _get_provider_secret("PROXYCHECK_API_KEY")
    if not api_key:
        return adapt_proxycheck(None, False, 200, ip)

    url = f"https://proxycheck.io/v3/{ip}?key={api_key}&vpn=1&port=1&seen=1&risk=1"
    payload, status_code = await _fetch_upstream_json(client, "proxycheck", "Proxycheck", url, timeout=5.0)
    return adapt_proxycheck(payload, True, status_code, ip)


async def query_iphub(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = _get_provider_secret("IPHUB_API_KEY")
    if not api_key:
        return adapt_iphub(None, False)

    url = f"https://v2.api.iphub.info/ip/{ip}"
    headers = {"X-Key": api_key, "Accept-Version": "2.2"}
    payload, status_code = await _fetch_upstream_json(client, "iphub", "IPHub", url, headers=headers, timeout=5.0)
    return adapt_iphub(payload, True, status_code)


async def query_iphunter(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = _get_provider_secret("IPHUNTER_API_KEY")
    if not api_key:
        return adapt_iphunter(None, False)

    url = f"https://www.iphunter.info:8082/v1/ip/{ip}"
    headers = {"X-Key": api_key}
    payload, status_code = await _fetch_upstream_json(client, "iphunter", "IPHunter", url, headers=headers, timeout=5.0)
    return adapt_iphunter(payload, True, status_code)


async def query_tor_onionoo(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    offline_payload = offline_dbs.lookup_tor_onionoo_offline(ip)
    if isinstance(offline_payload, dict):
        return adapt_tor_onionoo(offline_payload, status_code=200, ip=ip)

    url = f"https://onionoo.torproject.org/summary?search={ip}"
    payload, status_code = await _fetch_upstream_json(client, "tor_onionoo", "Tor Onionoo", url, timeout=5.0)
    return adapt_tor_onionoo(payload, status_code=status_code, ip=ip)


async def query_shodan_internetdb(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    """Queries Shodan InternetDB for IPv4 open ports and tags, treating HTTP 404 as clean."""
    if dns_providers.reverse_ipv4_octets(ip) is None:
        return adapt_shodan_internetdb({"status": "skipped_ipv6"}, status_code=200)

    url = f"https://internetdb.shodan.io/{ip}"
    payload, status_code = await _fetch_upstream_json(
        client,
        "shodan_internetdb",
        "Shodan InternetDB",
        url,
        timeout=5.0,
        treat_404_as_ok=True,
    )
    return adapt_shodan_internetdb(payload, status_code=status_code)


async def query_dshield(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    endpoints = (
        ("isc.sans.edu", f"https://isc.sans.edu/api/ip/{ip}?json"),
        ("www.dshield.org", f"https://www.dshield.org/api/ip/{ip}?json"),
    )
    headers = {"User-Agent": USER_AGENT_HEADER, "Accept": "application/json"}
    owned_events_token = None
    events = provider_upstream_events.get()
    if not isinstance(events, dict):
        events = {}
        owned_events_token = provider_upstream_events.set(events)

    payload: Any = None
    status_code = 502
    try:
        for idx, (host, url) in enumerate(endpoints):
            started_at = time.monotonic()
            payload, status_code = await _fetch_upstream_json(
                client,
                "dshield",
                "DShield",
                url,
                headers=headers,
                timeout=10.0,
                follow_redirects=True,
            )
            elapsed = time.monotonic() - started_at
            is_timeout = bool((events.get("dshield") or {}).get("isTimeout"))
            if is_timeout or elapsed > 5.0 or status_code not in (502, 503, 504) or idx == len(endpoints) - 1:
                break
            logger.warning(f"DShield primary endpoint {host} returned {status_code}; retrying fallback endpoint")
    finally:
        if owned_events_token is not None:
            provider_upstream_events.reset(owned_events_token)
    return adapt_dshield(payload, status_code=status_code)


def is_unconfigured_provider_row(row: Dict[str, Any]) -> bool:
    return (
        isinstance(row, dict)
        and row.get("status") in ("No API Key", "Database Missing", "Offline DB Missing", "Skipped (IPv6)")
        and row.get("statusCode") is None
    )


def is_provider_result_cacheable(row: Any) -> bool:
    return isinstance(row, dict) and row.get("statusCode") == 200 and row.get("status") == "200 OK"


def build_cooldown_provider_row(provider_name: str, cooldown_info: Dict[str, Any]) -> Dict[str, Any]:
    raw_status = cooldown_info.get("statusCode")
    status_code = raw_status if isinstance(raw_status, int) and not isinstance(raw_status, bool) else 503
    reason = str(cooldown_info.get("reason") or "Upstream rate limited or degraded")
    custom_label = cooldown_info.get("statusLabel")
    is_quota_guard = bool(cooldown_info.get("isQuotaGuard") or cooldown_info.get("isQuotaGuarded"))
    if isinstance(custom_label, str) and custom_label.strip():
        status_label = custom_label.strip()
    else:
        status_label = "429 Cooldown (Rate Limited)" if status_code == 429 else f"{status_code} Cooldown (Circuit Open)"

    flag_label = "Local Quota Guard" if is_quota_guard else "Provider Cooldown"
    raw_payload: Dict[str, Any] = {
        "status": "quota_guarded" if is_quota_guard else "cooldown",
        "message": reason,
        "retryAfterSeconds": cooldown_info.get("cooldownSeconds"),
        "cooldownUntil": cooldown_info.get("until"),
    }
    if is_quota_guard:
        raw_payload["window"] = cooldown_info.get("window")
        raw_payload["used"] = cooldown_info.get("used")
        raw_payload["limit"] = cooldown_info.get("limit")

    sanitize_fn = sanitization.sanitize_payload
    row: Dict[str, Any] = {
        "provider": provider_name,
        "status": status_label,
        "statusCode": status_code,
        "asn": "-",
        "isp": "-",
        "organisation": "-",
        "location": "-",
        "usageType": "-",
        "securityFlags": [{"label": flag_label, "isHighRisk": False}],
        "isCooldown": True,
        "rawJson": sanitize_fn(raw_payload),
    }
    if is_quota_guard:
        row["isQuotaGuarded"] = True
        row["isQuotaGuard"] = True
    return row


_build_cooldown_provider_row = build_cooldown_provider_row


def build_unhandled_provider_error_row(provider_name: str, safe_message: str) -> Dict[str, Any]:
    return {
        "provider": provider_name,
        "status": "500 Internal Error",
        "statusCode": 500,
        "asn": "-",
        "isp": "-",
        "organisation": "-",
        "location": "-",
        "usageType": "-",
        "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
        "rawJson": {"status": "error", "message": safe_message},
    }


def build_deferred_provider_row(provider_name: str) -> Dict[str, Any]:
    """Builds a placeholder row when an uncached commercial source is skipped in light mode."""
    return {
        "provider": provider_name,
        "status": "Deferred (Light Mode)",
        "statusCode": None,
        "asn": "-",
        "isp": "-",
        "organisation": "-",
        "location": "-",
        "usageType": "-",
        "securityFlags": [{"label": "Deferred (Light Mode)", "isHighRisk": False}],
        "isDeferred": True,
        "rawJson": {"status": "deferred", "mode": "light"},
    }


@dataclass(frozen=True)
class ProviderSpec:
    """Declarative execution specification resolving provider query callables dynamically at dispatch time."""

    key: str
    label: str
    uses_http_client: bool
    supports_cooldown: bool
    target_module: Any
    func_name: str
    passes_client: bool = True

    async def invoke(self, client: Optional[httpx.AsyncClient], ip: str) -> Dict[str, Any]:
        query_fn = getattr(self.target_module, self.func_name)
        if self.passes_client:
            return await query_fn(client, ip)
        return await query_fn(ip)

    def __iter__(self) -> Iterator[Any]:
        yield self.key
        yield self.label
        yield self.uses_http_client
        yield self.supports_cooldown
        yield self.invoke

    def __getitem__(self, index: int) -> Any:
        return (self.key, self.label, self.uses_http_client, self.supports_cooldown, self.invoke)[index]


_CURRENT_MODULE = sys.modules[__name__]
_IP_ONLY_DNS_PROVIDER_KEYS = frozenset({"maxmind", "spamhaus_zen", "spamcop"})

PROVIDER_SPECS: Tuple[ProviderSpec, ...] = tuple(
    ProviderSpec(
        key=meta.key,
        label=meta.label,
        uses_http_client=not (meta.is_offline or meta.is_dnsbl),
        supports_cooldown=not meta.is_offline,
        target_module=dns_providers if (meta.is_offline or meta.is_dnsbl) else _CURRENT_MODULE,
        func_name=f"query_{meta.key}",
        passes_client=meta.key not in _IP_ONLY_DNS_PROVIDER_KEYS,
    )
    for meta in PROVIDER_REGISTRY
)
_PROVIDER_SPECS = PROVIDER_SPECS
