"""
Upstream HTTP IP intelligence provider queries and shared provider specification registry.
"""

import asyncio
import logging
import os
import re
import time
from typing import Any, Callable, Dict, Optional, Tuple, Union

import httpx
from django.conf import settings

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
    adapt_tor_onionoo,
)
from .cache_backends import _get_cooldown_bounds, _views_attr
from .dns_providers import (
    _provider_upstream_events,
    _record_upstream_event,
    query_maxmind,
    query_spamcop,
    query_spamhaus_zen,
    query_stopforumspam,
)
from .quota_telemetry import extract_upstream_rate_limit
from .sanitization import (
    _extract_response_log_details,
    _parse_upstream_json_with_error,
    _sanitize_error_message,
    _sanitize_payload,
)

logger = logging.getLogger("detector.views")

USER_AGENT_HEADER = "ProxyCheck/1.0 (https://proxycheck.toolforge.org; tools.proxycheck@toolforge.org)"


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


def _parse_retry_after_seconds(raw_header: Optional[str]) -> int:
    """Parses an integer Retry-After delay and clamps it within configured cooldown bounds."""
    default_s, low, high = _get_cooldown_bounds()
    if not isinstance(raw_header, str):
        return default_s
    cleaned = raw_header.strip()
    if not re.fullmatch(r"\d+", cleaned):
        return default_s
    return max(low, min(high, int(cleaned)))


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
        cooldown_secs = _parse_retry_after_seconds(_extract_retry_after_header(resp))
        _record_upstream_event(
            provider_key,
            trigger_cooldown=True,
            status_code=429,
            reason="429 Rate Limited",
            cooldown_seconds=cooldown_secs,
            upstream_remaining=upstream_remaining,
            upstream_limit=upstream_limit,
        )
    elif isinstance(raw_status, int) and raw_status >= 500:
        _record_upstream_event(
            provider_key,
            trigger_cooldown=True,
            status_code=raw_status,
            reason=f"HTTP {raw_status}",
            cooldown_seconds=default_cooldown,
            upstream_remaining=upstream_remaining,
            upstream_limit=upstream_limit,
        )
    elif parsed_status >= 500 and raw_status == 200:
        _record_upstream_event(
            provider_key,
            trigger_cooldown=True,
            status_code=parsed_status,
            reason="Malformed Gateway Body",
            cooldown_seconds=default_cooldown,
        )
    else:
        _record_upstream_event(
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
) -> Tuple[Any, int]:
    """
    Executes an upstream GET request, parses JSON safely, redacts leaked secrets on error,
    and records HTTP 429, 5xx, or timeout signals for per-provider circuit breaking.
    """
    default_cooldown, _, _ = _get_cooldown_bounds()
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
            safe_message = _sanitize_error_message(raw_message)
        elif is_timeout:
            safe_message = f"{type(exc).__name__}: upstream request timed out"
        else:
            safe_message = type(exc).__name__
        logger.error(f"{provider_label} request exception: {safe_message}")
        _record_upstream_event(
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
    payload, parsed_status, parse_error = _parse_upstream_json_with_error(resp)
    if isinstance(raw_status, int) and raw_status != 200:
        content_type, body_preview = _extract_response_log_details(resp)
        logger.warning(
            f"{provider_label} returned HTTP {raw_status} (Content-Type: {content_type}; body: {body_preview})"
        )
    elif parse_error is not None:
        content_type, body_preview = _extract_response_log_details(resp)
        logger.warning(
            f"{provider_label} returned non-JSON HTTP {raw_status} body ({parse_error} -> {parsed_status}; "
            f"Content-Type: {content_type}; body: {body_preview})"
        )
    _record_http_status_event(resp, provider_key, raw_status, parsed_status, payload, default_cooldown)
    return payload, parsed_status


async def query_cloudflare_radar(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    token = os.environ.get("CLOUDFLARE_RADAR_TOKEN") or getattr(settings, "CLOUDFLARE_RADAR_TOKEN", "")
    if not token:
        return adapt_cloudflare_radar(None, False)

    url = f"https://api.cloudflare.com/client/v4/radar/entities/asns/ip?ip={ip}"
    headers = {"Authorization": f"Bearer {token}"}
    payload, status_code = await _fetch_upstream_json(
        client, "cloudflare_radar", "Cloudflare Radar", url, headers=headers, timeout=8.0
    )
    return adapt_cloudflare_radar(payload, True, status_code)


async def query_abuseipdb(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = os.environ.get("ABUSEIPDB_API_KEY") or getattr(settings, "ABUSEIPDB_API_KEY", "")
    if not api_key:
        return adapt_abuseipdb(None, False)

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": api_key, "Accept": "application/json"}
    payload, status_code = await _fetch_upstream_json(
        client, "abuseipdb", "AbuseIPDB", url, headers=headers, timeout=8.0
    )
    return adapt_abuseipdb(payload, True, status_code)


async def query_ipdata(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = os.environ.get("IPDATA_API_KEY") or getattr(settings, "IPDATA_API_KEY", "")
    if not api_key:
        return adapt_ipdata(None, False)

    url = f"https://api.ipdata.co/{ip}?api-key={api_key}"
    payload, status_code = await _fetch_upstream_json(client, "ipdata", "IPData", url, timeout=8.0)
    return adapt_ipdata(payload, True, status_code)


async def query_ipregistry(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = os.environ.get("IPREGISTRY_API_KEY") or getattr(settings, "IPREGISTRY_API_KEY", "")
    if not api_key:
        return adapt_ipregistry(None, False)

    url = f"https://api.ipregistry.co/{ip}?key={api_key}"
    payload, status_code = await _fetch_upstream_json(client, "ipregistry", "IPRegistry", url, timeout=8.0)
    return adapt_ipregistry(payload, True, status_code)


async def query_ip2location(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = os.environ.get("IP2LOCATION_API_KEY") or getattr(settings, "IP2LOCATION_API_KEY", "")
    if not api_key:
        return adapt_ip2location(None, False)

    url = f"https://api.ip2location.io/?key={api_key}&ip={ip}"
    payload, status_code = await _fetch_upstream_json(client, "ip2location", "IP2Location", url, timeout=5.0)
    return adapt_ip2location(payload, True, status_code)


async def query_getipintel(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    """GetIPIntel requires a valid contact email in the query string instead of an API key."""
    contact_email = os.environ.get("GETIPINTEL_CONTACT_EMAIL") or getattr(settings, "GETIPINTEL_CONTACT_EMAIL", "")
    if not contact_email:
        return adapt_getipintel(None, False)

    url = f"https://check.getipintel.net/check.php?ip={ip}&contact={contact_email}&flags=f&format=json"
    payload, status_code = await _fetch_upstream_json(client, "getipintel", "GetIPIntel", url, timeout=5.0)
    return _views_attr("adapt_getipintel", adapt_getipintel)(payload, True, status_code)


async def query_proxycheck(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = os.environ.get("PROXYCHECK_API_KEY") or getattr(settings, "PROXYCHECK_API_KEY", "")
    if not api_key:
        return adapt_proxycheck(None, False, 200, ip)

    url = f"https://proxycheck.io/v3/{ip}?key={api_key}&vpn=1&port=1&seen=1&risk=1"
    payload, status_code = await _fetch_upstream_json(client, "proxycheck", "Proxycheck", url, timeout=5.0)
    return adapt_proxycheck(payload, True, status_code, ip)


async def query_iphub(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = os.environ.get("IPHUB_API_KEY") or getattr(settings, "IPHUB_API_KEY", "")
    if not api_key:
        return adapt_iphub(None, False)

    url = f"https://v2.api.iphub.info/ip/{ip}"
    headers = {"X-Key": api_key, "Accept-Version": "2.2"}
    payload, status_code = await _fetch_upstream_json(client, "iphub", "IPHub", url, headers=headers, timeout=5.0)
    return adapt_iphub(payload, True, status_code)


async def query_iphunter(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    api_key = os.environ.get("IPHUNTER_API_KEY") or getattr(settings, "IPHUNTER_API_KEY", "")
    if not api_key:
        return adapt_iphunter(None, False)

    url = f"https://www.iphunter.info:8082/v1/ip/{ip}"
    headers = {"X-Key": api_key}
    payload, status_code = await _fetch_upstream_json(
        client, "iphunter", "IPHunter", url, headers=headers, timeout=5.0
    )
    return adapt_iphunter(payload, True, status_code)


async def query_tor_onionoo(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    url = f"https://onionoo.torproject.org/summary?search={ip}"
    payload, status_code = await _fetch_upstream_json(client, "tor_onionoo", "Tor Onionoo", url, timeout=5.0)
    return adapt_tor_onionoo(payload, status_code=status_code, ip=ip)


async def query_dshield(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    endpoints = (
        ("isc.sans.edu", f"https://isc.sans.edu/api/ip/{ip}?json"),
        ("www.dshield.org", f"https://www.dshield.org/api/ip/{ip}?json"),
    )
    headers = {"User-Agent": USER_AGENT_HEADER, "Accept": "application/json"}
    owned_events_token = None
    events = _provider_upstream_events.get()
    if not isinstance(events, dict):
        events = {}
        owned_events_token = _provider_upstream_events.set(events)

    payload: Any = None
    status_code = 502
    time_mod = _views_attr("time", time)
    try:
        for idx, (host, url) in enumerate(endpoints):
            started_at = time_mod.monotonic()
            payload, status_code = await _fetch_upstream_json(
                client,
                "dshield",
                "DShield",
                url,
                headers=headers,
                timeout=10.0,
                follow_redirects=True,
            )
            elapsed = time_mod.monotonic() - started_at
            is_timeout = bool((events.get("dshield") or {}).get("isTimeout"))
            if is_timeout or elapsed > 5.0 or status_code not in (502, 503, 504) or idx == len(endpoints) - 1:
                break
            logger.warning(f"DShield primary endpoint {host} returned {status_code}; retrying fallback endpoint")
    finally:
        if owned_events_token is not None:
            _provider_upstream_events.reset(owned_events_token)
    return adapt_dshield(payload, status_code=status_code)


def _is_unconfigured_provider_row(row: Dict[str, Any]) -> bool:
    return (
        isinstance(row, dict)
        and row.get("status") in ("No API Key", "Database Missing", "Offline DB Missing", "Skipped (IPv6)")
        and row.get("statusCode") is None
    )


def _is_provider_result_cacheable(row: Any) -> bool:
    return isinstance(row, dict) and row.get("statusCode") == 200 and row.get("status") == "200 OK"


def _build_cooldown_provider_row(provider_name: str, cooldown_info: Dict[str, Any]) -> Dict[str, Any]:
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

    sanitize_fn = _views_attr("_sanitize_payload", _sanitize_payload)
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


def _build_unhandled_provider_error_row(provider_name: str, safe_message: str) -> Dict[str, Any]:
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


def _build_deferred_provider_row(provider_name: str) -> Dict[str, Any]:
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


_PROVIDER_SPECS: Tuple[Tuple[str, str, bool, bool, Callable[[Any, str], Any]], ...] = (
    (
        "cloudflare_radar",
        "Cloudflare Radar",
        True,
        True,
        lambda client, ip: _views_attr("query_cloudflare_radar", query_cloudflare_radar)(client, ip),
    ),
    ("abuseipdb", "AbuseIPDB", True, True, lambda client, ip: _views_attr("query_abuseipdb", query_abuseipdb)(client, ip)),
    ("ipdata", "IPData", True, True, lambda client, ip: _views_attr("query_ipdata", query_ipdata)(client, ip)),
    (
        "ipregistry",
        "IPRegistry",
        True,
        True,
        lambda client, ip: _views_attr("query_ipregistry", query_ipregistry)(client, ip),
    ),
    (
        "ip2location",
        "IP2Location",
        True,
        True,
        lambda client, ip: _views_attr("query_ip2location", query_ip2location)(client, ip),
    ),
    (
        "getipintel",
        "GetIPIntel",
        True,
        True,
        lambda client, ip: _views_attr("query_getipintel", query_getipintel)(client, ip),
    ),
    (
        "proxycheck",
        "Proxycheck",
        True,
        True,
        lambda client, ip: _views_attr("query_proxycheck", query_proxycheck)(client, ip),
    ),
    ("iphub", "IPHub", True, True, lambda client, ip: _views_attr("query_iphub", query_iphub)(client, ip)),
    ("iphunter", "IPHunter", True, True, lambda client, ip: _views_attr("query_iphunter", query_iphunter)(client, ip)),
    ("maxmind", "MaxMind", False, False, lambda _client, ip: _views_attr("query_maxmind", query_maxmind)(ip)),
    (
        "spamhaus_zen",
        "Spamhaus ZEN",
        False,
        True,
        lambda _client, ip: _views_attr("query_spamhaus_zen", query_spamhaus_zen)(ip),
    ),
    ("spamcop", "SpamCop", False, True, lambda _client, ip: _views_attr("query_spamcop", query_spamcop)(ip)),
    (
        "tor_onionoo",
        "Tor Onionoo",
        True,
        True,
        lambda client, ip: _views_attr("query_tor_onionoo", query_tor_onionoo)(client, ip),
    ),
    (
        "stopforumspam",
        "StopForumSpam",
        False,
        False,
        lambda client, ip: _views_attr("query_stopforumspam", query_stopforumspam)(client, ip),
    ),
    ("dshield", "DShield", True, True, lambda client, ip: _views_attr("query_dshield", query_dshield)(client, ip)),
)
