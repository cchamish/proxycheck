"""Upstream HTTP IP intelligence provider queries."""

import asyncio
import logging
import os
import re
import time
from typing import Any, Dict, Optional, Tuple, Union

import httpx
from django.conf import settings

from ..cache.quota_telemetry import extract_upstream_rate_limit
from ..cache.redis_backend import get_cooldown_bounds
from ..core.context import provider_upstream_events, record_upstream_event
from ..core.sanitization import sanitize_error_message
from ..offline import feeds as offline_feeds
from ..provider_registry import USER_AGENT_HEADER
from . import dns as dns_providers
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

logger = logging.getLogger("detector.views")


def parse_retry_after_seconds(raw_header: Optional[str]) -> int:
    """Parses an integer Retry-After delay and clamps it within configured cooldown bounds."""
    default_s, low, high = get_cooldown_bounds()
    if not isinstance(raw_header, str):
        return default_s
    cleaned = raw_header.strip()
    if not re.fullmatch(r"\d+", cleaned):
        return default_s
    return max(low, min(high, int(cleaned)))


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
        logger.error("%s request exception: %s", provider_label, safe_message)
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
    try:
        payload: Any = resp.json()
        parsed_status = raw_status
        parse_error: Optional[str] = None
    except ValueError as exc:
        parsed_status = 502 if raw_status == 200 else raw_status
        payload = {"status": "error", "message": sanitize_error_message(getattr(resp, "text", "") or "")}
        parse_error = type(exc).__name__

    if treat_404_as_ok and raw_status == 404:
        clean_404_payload = (
            payload if parse_error is None and isinstance(payload, dict) else {"detail": "No information available"}
        )
        upstream_remaining, upstream_limit, upstream_used = extract_upstream_rate_limit(
            resp, clean_404_payload, provider_key
        )
        record_upstream_event(
            provider_key,
            trigger_cooldown=False,
            status_code=200,
            upstream_remaining=upstream_remaining,
            upstream_limit=upstream_limit,
            upstream_used=upstream_used,
        )
        return clean_404_payload, 404

    if (isinstance(raw_status, int) and raw_status != 200) or parse_error is not None:
        content_type = "unknown"
        resp_headers = getattr(resp, "headers", None)
        getter = getattr(resp_headers, "get", None) if resp_headers is not None else None
        if callable(getter):
            for header_name in ("Content-Type", "content-type"):
                candidate = getter(header_name)
                if isinstance(candidate, str) and candidate.strip():
                    cleaned_ct = " ".join(sanitize_error_message(candidate).split())
                    content_type = cleaned_ct[:64] or "unknown"
                    break

        raw_text = getattr(resp, "text", "")
        if not isinstance(raw_text, str) or not raw_text.strip():
            body_preview = "<empty>"
        else:
            sanitised_text = " ".join(sanitize_error_message(raw_text).split())
            body_preview = f"{sanitised_text[:117]}..." if len(sanitised_text) > 120 else sanitised_text

        if isinstance(raw_status, int) and raw_status != 200:
            logger.warning(
                "%s returned HTTP %s (Content-Type: %s; body: %s)",
                provider_label,
                raw_status,
                content_type,
                body_preview,
            )
        else:
            logger.warning(
                "%s returned non-JSON HTTP %s body (%s -> %s; Content-Type: %s; body: %s)",
                provider_label,
                raw_status,
                parse_error,
                parsed_status,
                content_type,
                body_preview,
            )

    upstream_remaining, upstream_limit, upstream_used = extract_upstream_rate_limit(
        resp,
        payload if raw_status == 200 and parsed_status == 200 else None,
        provider_key,
    )
    if raw_status == 429:
        retry_after: Optional[str] = None
        resp_headers = getattr(resp, "headers", None)
        getter = getattr(resp_headers, "get", None) if resp_headers is not None else None
        if callable(getter):
            for header_name in ("Retry-After", "retry-after"):
                val = getter(header_name)
                if isinstance(val, str):
                    retry_after = val
                    break
        record_upstream_event(
            provider_key,
            trigger_cooldown=True,
            status_code=429,
            reason="429 Rate Limited",
            cooldown_seconds=parse_retry_after_seconds(retry_after),
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
        client,
        "cloudflare_radar",
        "Cloudflare Radar",
        url,
        headers=headers,
        timeout=httpx.Timeout(connect=4.0, read=12.0, write=5.0, pool=5.0),
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

    url = f"https://check.getipintel.net/check.php?ip={ip}&contact={contact_email}&flags=f&oflags=r&format=json"
    payload, status_code = await _fetch_upstream_json(client, "getipintel", "GetIPIntel", url, timeout=5.0)
    return adapt_getipintel(payload, True, status_code)


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
    if dns_providers.reverse_ipv4_octets(ip) is None:
        return adapt_iphunter({"status": "skipped_ipv6"}, True, status_code=200)

    url = f"https://www.iphunter.info:8082/v1/ip/{ip}"
    headers = {"X-Key": api_key}
    payload, status_code = await _fetch_upstream_json(client, "iphunter", "IPHunter", url, headers=headers, timeout=5.0)
    return adapt_iphunter(payload, True, status_code)


async def query_tor_onionoo(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    offline_payload = offline_feeds.lookup_tor_onionoo_offline(ip)
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
            logger.warning("DShield primary endpoint %s returned %s; retrying fallback endpoint", host, status_code)
    finally:
        if owned_events_token is not None:
            provider_upstream_events.reset(owned_events_token)
    return adapt_dshield(payload, status_code=status_code)
