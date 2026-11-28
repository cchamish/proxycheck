"""Asynchronous DNS, reverse PTR, Team Cymru BGP, and DNSBL provider queries and adapters."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import threading
from typing import Any, Dict, List, Optional, Tuple

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename
from django.conf import settings

from ..cache.redis_backend import get_cooldown_bounds
from ..core.context import (
    rdns_context_state,
    record_upstream_event,
)
from ..core.sanitization import sanitize_error_message
from ..offline.feeds import lookup_bgp_tools_offline
from .common import (
    _build_error_row,
    _build_ok_row,
    _guard_payload,
)

logger = logging.getLogger("detector.views")

DEFAULT_DNS_TIMEOUT_SECONDS = 2.0
_DEFAULT_ASYNC_RESOLVER_CLS = dns.asyncresolver.Resolver
_async_resolver_lock = threading.Lock()
_cached_base_nameservers: Optional[List[Any]] = None
_cached_async_resolvers: Dict[Tuple[float, float], dns.asyncresolver.Resolver] = {}

_SPAMHAUS_CODE_MAP: Dict[str, Tuple[str, str, bool]] = {
    "127.0.0.2": ("SBL", "Spamhaus SBL", True),
    "127.0.0.3": ("CSS", "Spamhaus CSS", True),
    "127.0.0.4": ("XBL/CBL", "Spamhaus XBL/CBL", True),
    "127.0.0.5": ("XBL/CBL", "Spamhaus XBL/CBL", True),
    "127.0.0.6": ("XBL/CBL", "Spamhaus XBL/CBL", True),
    "127.0.0.7": ("XBL/CBL", "Spamhaus XBL/CBL", True),
    "127.0.0.9": ("SBL DROP/EDROP", "Spamhaus DROP/EDROP", True),
    "127.0.0.10": ("Policy/Dynamic ISP Range (PBL)", "Policy/Dynamic ISP Range (PBL)", False),
    "127.0.0.11": ("Policy/Dynamic ISP Range (PBL)", "Policy/Dynamic ISP Range (PBL)", False),
}


def _extract_dnsbl_codes(raw_data: Dict[str, Any]) -> List[str]:
    raw_codes = raw_data.get("codes")
    if not isinstance(raw_codes, list):
        return []
    seen = set()
    cleaned: List[str] = []
    for item in raw_codes:
        if isinstance(item, str):
            val = item.strip()
            if val and val not in seen:
                seen.add(val)
                cleaned.append(val)
    return cleaned


def _adapt_dnsbl_precheck(
    provider_name: str,
    raw_data: Optional[Dict[str, Any]],
    status_code: int,
) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    guarded, effective_status = _guard_payload(raw_data, status_code)
    payload = guarded if isinstance(guarded, dict) else {}
    state = str(payload.get("status") or "").strip().lower()

    if state == "skipped_ipv6":
        return (
            _build_error_row(
                provider_name,
                None,
                payload,
                status="Skipped (IPv6)",
                usage_type="IPv4 Only (Skipped for IPv6)",
                extra={"isListed": False, "isSkippedIpv6": True, "listedCodes": [], "listedCategories": []},
            ),
            payload,
        )

    if effective_status != 200 or state in ("timeout", "error") or not raw_data:
        if state == "timeout" or effective_status == 504:
            status_text, out_code = "504 Timeout", 504
        elif effective_status == 429:
            status_text, out_code = "429 Rate Limited", 429
        else:
            out_code = effective_status if effective_status != 200 else 502
            status_text = f"{out_code} DNS Error"
        return (
            _build_error_row(
                provider_name,
                out_code,
                payload or None,
                status=status_text,
                raw_message=status_text,
                extra={"isListed": False, "listedCodes": [], "listedCategories": []},
            ),
            payload,
        )

    return None, payload


def _build_clean_dnsbl_row(provider_name: str, raw_data: Dict[str, Any]) -> Dict[str, Any]:
    return _build_ok_row(
        provider_name,
        raw_data,
        usage_type="Clean (Not Listed)",
        extra={"isListed": False, "listedCodes": [], "listedCategories": []},
    )


def adapt_spamhaus_zen(raw_data: Optional[Dict[str, Any]], status_code: int = 200) -> Dict[str, Any]:
    """Normalises Spamhaus ZEN DNSBL A-record responses including SBL, CSS, XBL, PBL, and policy blocks."""
    early_row, payload = _adapt_dnsbl_precheck("Spamhaus ZEN", raw_data, status_code)
    if early_row is not None:
        return early_row

    codes = _extract_dnsbl_codes(payload)
    blocked_codes = [code for code in codes if code.startswith("127.255.255.")]
    if blocked_codes:
        reason_detail = (
            "Public DNS Refused or Rate Limited"
            if any(c in ("127.255.255.254", "127.255.255.255") for c in blocked_codes)
            else "Query Format Error"
        )
        return _build_error_row(
            "Spamhaus ZEN",
            429,
            payload,
            status="429 Query Blocked",
            usage_type=f"Query Restricted ({', '.join(blocked_codes)}: {reason_detail})",
            security_flags=[{"label": "Query Restricted (Unapplied)", "isHighRisk": False}],
            extra={"isListed": False, "isQueryRestricted": True, "listedCodes": [], "listedCategories": []},
        )

    if not codes:
        return _build_clean_dnsbl_row("Spamhaus ZEN", payload)

    flags: List[Dict[str, Any]] = []
    usage_parts: List[str] = []
    categories: List[str] = []
    seen_labels = set()

    for code in codes:
        category, flag_label, is_high_risk = _SPAMHAUS_CODE_MAP.get(
            code,
            (f"Spamhaus Code {code}", f"Spamhaus Listed ({code})", True),
        )
        if category not in categories:
            categories.append(category)
        if code in ("127.0.0.10", "127.0.0.11"):
            usage_parts.append(f"Policy/Dynamic ISP Range (PBL: {code})")
            full_label = flag_label
        else:
            usage_parts.append(f"{category} ({code})")
            full_label = f"{flag_label} ({code})"

        if full_label not in seen_labels:
            seen_labels.add(full_label)
            flags.append({"label": full_label, "isHighRisk": is_high_risk})

    is_only_pbl = all(code in ("127.0.0.10", "127.0.0.11") for code in codes)
    usage_text = ", ".join(usage_parts) if is_only_pbl else f"Listed: {', '.join(usage_parts)}"

    return _build_ok_row(
        "Spamhaus ZEN",
        payload,
        usage_type=usage_text,
        security_flags=flags,
        extra={
            "isListed": True,
            "isPolicyRange": is_only_pbl,
            "listedCodes": codes,
            "listedCategories": categories,
        },
    )


def adapt_spamcop(raw_data: Optional[Dict[str, Any]], status_code: int = 200) -> Dict[str, Any]:
    """Normalises SpamCop DNSBL A-record responses."""
    early_row, payload = _adapt_dnsbl_precheck("SpamCop", raw_data, status_code)
    if early_row is not None:
        return early_row

    codes = _extract_dnsbl_codes(payload)
    if not codes:
        return _build_clean_dnsbl_row("SpamCop", payload)

    return _build_ok_row(
        "SpamCop",
        payload,
        usage_type=f"Listed: Spam Source ({', '.join(codes)})",
        security_flags=[{"label": f"SpamCop Listed ({code})", "isHighRisk": True} for code in codes],
        extra={
            "isListed": True,
            "listedCodes": codes,
            "listedCategories": ["Spam Source"],
        },
    )


def _get_positive_float_setting(name: str, default: float) -> float:
    configured = getattr(settings, name, default)
    if (
        isinstance(configured, bool)
        or not isinstance(configured, (int, float))
        or not math.isfinite(float(configured))
        or float(configured) <= 0
    ):
        return default
    return float(configured)


def _create_async_resolver() -> dns.asyncresolver.Resolver:
    global _cached_base_nameservers

    timeout_s = _get_positive_float_setting("DNS_QUERY_TIMEOUT_SECONDS", DEFAULT_DNS_TIMEOUT_SECONDS)
    lifetime_s = _get_positive_float_setting("DNS_QUERY_LIFETIME_SECONDS", timeout_s)
    resolver_cls = dns.asyncresolver.Resolver
    if resolver_cls is not _DEFAULT_ASYNC_RESOLVER_CLS:
        try:
            resolver = resolver_cls()
        except dns.resolver.NoResolverConfiguration:
            resolver = resolver_cls(configure=False)
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = timeout_s
        resolver.lifetime = lifetime_s
        return resolver

    cache_key = (timeout_s, lifetime_s)
    with _async_resolver_lock:
        cached = _cached_async_resolvers.get(cache_key)
        if (
            cached is not None
            and cached.timeout == timeout_s
            and cached.lifetime == lifetime_s
            and bool(cached.nameservers)
        ):
            return cached

        if _cached_base_nameservers is None:
            try:
                base_resolver = resolver_cls()
                resolved_nameservers = (
                    list(base_resolver.nameservers) if base_resolver.nameservers else ["8.8.8.8", "1.1.1.1"]
                )
            except dns.resolver.NoResolverConfiguration:
                base_resolver = resolver_cls(configure=False)
                resolved_nameservers = ["8.8.8.8", "1.1.1.1"]
            _cached_base_nameservers = resolved_nameservers
            base_resolver.nameservers = list(resolved_nameservers)
            base_resolver.timeout = timeout_s
            base_resolver.lifetime = lifetime_s
            _cached_async_resolvers[cache_key] = base_resolver
            return base_resolver

        resolver = resolver_cls(configure=False)
        resolver.nameservers = list(_cached_base_nameservers)
        resolver.timeout = timeout_s
        resolver.lifetime = lifetime_s
        if len(_cached_async_resolvers) >= 16:
            _cached_async_resolvers.clear()
        _cached_async_resolvers[cache_key] = resolver
        return resolver


async def query_rdns_ptr(ip: str) -> Optional[str]:
    """
    Resolves the reverse DNS PTR hostname asynchronously via dnspython without
    blocking threads, distinguishing normal NXDOMAIN or NoAnswer from timeouts or errors.
    """
    state = rdns_context_state.get()
    try:
        qname = dns.reversename.from_address(ip)
    except ValueError, dns.exception.DNSException:
        if isinstance(state, dict):
            state["status"] = "error"
        return None

    try:
        resolver = _create_async_resolver()
        answer = await resolver.resolve(qname, "PTR")
        raw_host: Optional[str] = None
        if isinstance(answer, str):
            raw_host = answer
        elif answer is not None:
            for rdata in answer:
                target = getattr(rdata, "target", None)
                if target is not None:
                    to_text = getattr(target, "to_text", None)
                    cand = to_text() if callable(to_text) else str(target)
                    if isinstance(cand, str) and cand.strip():
                        raw_host = cand
                        break
                to_text = getattr(rdata, "to_text", None)
                cand = to_text() if callable(to_text) else str(rdata)
                if isinstance(cand, str) and cand.strip():
                    raw_host = cand
                    break

        cleaned = sanitize_error_message(raw_host.strip().rstrip(".").lower()) if isinstance(raw_host, str) else ""
        if not cleaned:
            if isinstance(state, dict):
                state["status"] = "nxdomain"
            return None
        if isinstance(state, dict):
            state["status"] = "ok"
        return cleaned
    except dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.YXDOMAIN:
        if isinstance(state, dict):
            state["status"] = "nxdomain"
        return None
    except dns.exception.Timeout, dns.resolver.LifetimeTimeout, asyncio.TimeoutError, TimeoutError:
        if isinstance(state, dict):
            state["status"] = "timeout"
        return None
    except dns.resolver.NoNameservers, dns.exception.DNSException, OSError:
        if isinstance(state, dict):
            state["status"] = "error"
        return None


def reverse_ipv4_octets(ip: str) -> Optional[str]:
    """Reverses IPv4 dotted octets for DNSBL lookups and returns None for non-IPv4 addresses."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    if addr.version != 4:
        return None
    return ".".join(reversed(addr.exploded.split(".")))


async def _query_dnsbl_zone(
    ip: str,
    zone: str,
    provider_key: str,
    provider_label: str,
) -> Tuple[Dict[str, Any], int]:
    """Queries an IPv4 DNSBL zone asynchronously, skipping IPv6 targets and recording timeouts."""
    reversed_ip = reverse_ipv4_octets(ip)
    if reversed_ip is None:
        return {"status": "skipped_ipv6", "query": None, "reversedIp": None, "codes": []}, 200

    qname = f"{reversed_ip}.{zone}"
    default_cooldown, _, _ = get_cooldown_bounds()
    try:
        resolver = _create_async_resolver()
        answer = await resolver.resolve(qname, "A")
        codes: List[str] = []
        if answer is not None:
            for rdata in answer:
                raw_addr = getattr(rdata, "address", None)
                if isinstance(raw_addr, str):
                    candidate = raw_addr.strip()
                else:
                    to_text = getattr(rdata, "to_text", None)
                    txt = to_text() if callable(to_text) else None
                    candidate = txt.strip() if isinstance(txt, str) else str(rdata).strip()
                if not candidate:
                    continue
                try:
                    normalised = str(ipaddress.IPv4Address(candidate))
                except ValueError:
                    continue
                if normalised not in codes:
                    codes.append(normalised)
        return {
            "status": "listed" if codes else "clean",
            "query": qname,
            "reversedIp": reversed_ip,
            "codes": codes,
        }, 200
    except dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.YXDOMAIN:
        return {"status": "clean", "query": qname, "reversedIp": reversed_ip, "codes": []}, 200
    except (dns.exception.Timeout, dns.resolver.LifetimeTimeout, asyncio.TimeoutError, TimeoutError) as exc:
        safe_message = sanitize_error_message(str(exc) or "DNS timeout")
        logger.warning("%s DNS query timed out: %s", provider_label, safe_message)
        record_upstream_event(
            provider_key,
            trigger_cooldown=True,
            status_code=504,
            reason="DNS Timeout",
            cooldown_seconds=default_cooldown,
            is_timeout=True,
        )
        return {"status": "timeout", "query": qname, "reversedIp": reversed_ip, "codes": [], "error": safe_message}, 504
    except (dns.resolver.NoNameservers, dns.exception.DNSException, OSError) as exc:
        safe_message = sanitize_error_message(str(exc) or "DNS resolution failed")
        logger.warning("%s DNS query failed: %s", provider_label, safe_message)
        record_upstream_event(
            provider_key,
            trigger_cooldown=True,
            status_code=502,
            reason=f"DNS Error ({type(exc).__name__})",
            cooldown_seconds=default_cooldown,
        )
        return {"status": "error", "query": qname, "reversedIp": reversed_ip, "codes": [], "error": safe_message}, 502


async def query_spamhaus_zen(ip: str) -> Dict[str, Any]:
    raw_data, status_code = await _query_dnsbl_zone(ip, "zen.spamhaus.org", "spamhaus_zen", "Spamhaus ZEN")
    row = adapt_spamhaus_zen(raw_data, status_code)
    if row.get("isQueryRestricted"):
        default_cooldown, _, _ = get_cooldown_bounds()
        record_upstream_event(
            "spamhaus_zen",
            trigger_cooldown=True,
            status_code=429,
            reason=str(row.get("usageType") or "Spamhaus Query Restricted"),
            cooldown_seconds=default_cooldown,
        )
    return row


async def query_spamcop(ip: str) -> Dict[str, Any]:
    raw_data, status_code = await _query_dnsbl_zone(ip, "bl.spamcop.net", "spamcop", "SpamCop")
    return adapt_spamcop(raw_data, status_code)


async def query_cymru_bgp_prefix(ip: str) -> Optional[Dict[str, Any]]:
    """
    Resolves the BGP origin prefix and ASN via Team Cymru DNS TXT records when the local
    offline bgp.tools index is absent or misses.
    """
    if not isinstance(ip, str) or not ip.strip():
        return None
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None

    offline_hit = lookup_bgp_tools_offline(addr.compressed)
    if isinstance(offline_hit, dict) and offline_hit.get("bgpPrefix"):
        return {
            "bgpPrefix": str(offline_hit["bgpPrefix"]),
            "asn": offline_hit.get("asn"),
        }

    if addr.version == 4:
        reversed_v4 = reverse_ipv4_octets(addr.compressed)
        if reversed_v4 is None:
            return None
        qname = f"{reversed_v4}.origin.asn.cymru.com"
    else:
        nibble_reversed_v6 = ".".join(reversed(addr.exploded.replace(":", "")))
        qname = f"{nibble_reversed_v6}.origin6.asn.cymru.com"

    try:
        resolver = _create_async_resolver()
        answer = await asyncio.wait_for(
            resolver.resolve(qname, "TXT"),
            timeout=DEFAULT_DNS_TIMEOUT_SECONDS,
        )
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.YXDOMAIN,
        dns.exception.Timeout,
        dns.resolver.LifetimeTimeout,
        dns.resolver.NoNameservers,
        dns.exception.DNSException,
        asyncio.TimeoutError,
        TimeoutError,
        OSError,
    ):
        return None

    records: List[str] = []
    if isinstance(answer, str):
        if answer.strip():
            records.append(answer.strip().strip('"'))
    elif answer is not None:
        for rdata in answer:
            if isinstance(rdata, str):
                cleaned = rdata.strip().strip('"')
                if cleaned:
                    records.append(cleaned)
                continue
            raw_strings = getattr(rdata, "strings", None)
            if isinstance(raw_strings, (list, tuple)) and raw_strings:
                joined = "".join(
                    chunk.decode("utf-8", errors="ignore") if isinstance(chunk, (bytes, bytearray)) else str(chunk)
                    for chunk in raw_strings
                ).strip()
                if joined:
                    records.append(joined)
                    continue
            to_text = getattr(rdata, "to_text", None)
            raw_text = to_text() if callable(to_text) else str(rdata)
            if isinstance(raw_text, str) and raw_text.strip():
                records.append(raw_text.strip().strip('"'))

    best_prefix: Optional[ipaddress.IPv4Network | ipaddress.IPv6Network] = None
    best_asn: Optional[int] = None
    for record in records:
        parts = [part.strip() for part in record.split("|")]
        if len(parts) < 2 or not parts[1]:
            continue
        try:
            net = ipaddress.ip_network(parts[1], strict=False)
        except ValueError:
            continue
        if net.version != addr.version or addr not in net or not (0 < net.prefixlen <= addr.max_prefixlen):
            continue

        asn_num: Optional[int] = None
        raw_asn_tokens = parts[0].split()
        if raw_asn_tokens:
            first_token = raw_asn_tokens[0].upper().removeprefix("AS")
            if first_token.isdigit() and int(first_token) > 0:
                asn_num = int(first_token)

        if best_prefix is None or net.prefixlen > best_prefix.prefixlen:
            best_prefix = net
            best_asn = asn_num

    if best_prefix is None:
        return None
    return {"bgpPrefix": str(best_prefix), "asn": best_asn}
