"""
Local MaxMind MMDB, StopForumSpam SQLite, and asynchronous DNS and DNSBL provider queries.
"""

import asyncio
import contextvars
import ipaddress
import logging
import math
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename
from django.conf import settings

from . import cache_backends, cidr_attribution
from .adapters import (
    adapt_ipsum_drop,
    adapt_maxmind,
    adapt_openasn,
    adapt_spamcop,
    adapt_spamhaus_zen,
    adapt_stopforumspam,
)
from .cache_backends import (
    MAXMIND_DB_SPECS,
    evict_maxmind_reader,
    evict_missing_maxmind_readers,
    get_cooldown_bounds,
    get_maxmind_reader,
    record_city_db_presence,
)
from .offline_dbs import (
    get_maxmind_newest_mtime_iso,
    lookup_bgp_tools_offline,
    query_ipsum_drop_offline,
    query_openasn_offline,
    query_stopforumspam_offline,
)
from .sanitization import sanitize_error_message

logger = logging.getLogger("detector.views")

provider_upstream_events: contextvars.ContextVar[Optional[Dict[str, Dict[str, Any]]]] = contextvars.ContextVar(
    "provider_upstream_events", default=None
)
_provider_upstream_events = provider_upstream_events
rdns_context_state: contextvars.ContextVar[Optional[Dict[str, str]]] = contextvars.ContextVar(
    "rdns_context_state", default=None
)
_rdns_context_state = rdns_context_state

DEFAULT_DNS_TIMEOUT_SECONDS = 2.0
_DEFAULT_ASYNC_RESOLVER_CLS = dns.asyncresolver.Resolver
_async_resolver_lock = threading.Lock()
_cached_base_nameservers: Optional[List[Any]] = None
_cached_async_resolvers: Dict[Tuple[float, float], dns.asyncresolver.Resolver] = {}


def clear_dns_resolver_cache() -> None:
    """Clears cached async DNS resolvers and base nameserver discovery state."""
    global _cached_base_nameservers
    with _async_resolver_lock:
        _cached_base_nameservers = None
        _cached_async_resolvers.clear()


def record_upstream_event(
    provider_key: str,
    *,
    trigger_cooldown: bool,
    status_code: int,
    reason: str = "",
    cooldown_seconds: Optional[int] = None,
    is_timeout: bool = False,
    is_transport_error: bool = False,
    upstream_remaining: Optional[int] = None,
    upstream_limit: Optional[int] = None,
    upstream_used: Optional[int] = None,
) -> None:
    events = provider_upstream_events.get()
    if isinstance(events, dict):
        events[provider_key] = {
            "trigger": trigger_cooldown,
            "statusCode": status_code,
            "reason": reason,
            "cooldownSeconds": cooldown_seconds,
            "isTimeout": is_timeout,
            "isTransportError": is_transport_error,
            "upstreamRemaining": upstream_remaining,
            "upstreamLimit": upstream_limit,
            "upstreamUsed": upstream_used,
        }


def _is_valid_mmdb_prefix_tuple(result: Any) -> bool:
    """Returns True when a prefix lookup returned a (record_or_none, prefix_len) tuple."""
    return (
        isinstance(result, tuple)
        and len(result) == 2
        and (result[0] is None or isinstance(result[0], dict))
        and not isinstance(result[1], bool)
        and isinstance(result[1], int)
    )


def _lookup_mmdb_record_and_prefix(reader: Any, ip: str) -> Tuple[Optional[Dict[str, Any]], Optional[int]]:
    """
    Retrieves the MMDB record and routing prefix length in one lookup via get_with_prefix_len
    when supported, falling back to reader.get otherwise.
    """
    getter = getattr(reader, "get_with_prefix_len", None)
    if callable(getter):
        try:
            result = getter(ip)
        except AttributeError, NotImplementedError:
            result = None
        if _is_valid_mmdb_prefix_tuple(result):
            raw_rec, prefix_len = result
            return (raw_rec if isinstance(raw_rec, dict) else None, prefix_len)

    rec = reader.get(ip)
    return (rec if isinstance(rec, dict) else None, None)


def _merge_maxmind_dict_field(combined: Dict[str, Any], key: str, value: Any) -> None:
    """Deep-merges nested MaxMind dictionaries while keeping Country iso_code authoritative."""
    existing = combined.get(key)
    if isinstance(existing, dict) and isinstance(value, dict):
        merged = dict(existing)
        for sub_key, sub_val in value.items():
            if sub_key == "names" and isinstance(merged.get("names"), dict) and isinstance(sub_val, dict):
                merged["names"] = {**merged["names"], **sub_val}
            elif sub_val is not None:
                merged[sub_key] = sub_val
        combined[key] = merged
    elif value is not None:
        combined[key] = value


def _merge_maxmind_records(
    country_rec: Optional[Dict[str, Any]],
    city_rec: Optional[Dict[str, Any]],
    asn_rec: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Combines Country, City, and ASN MMDB lookups while preserving iso_code consistency."""
    combined: Dict[str, Any] = {}
    if isinstance(city_rec, dict):
        for key, value in city_rec.items():
            if value is not None:
                combined[key] = value
    if isinstance(country_rec, dict):
        for key, value in country_rec.items():
            if key in ("country", "registered_country", "represented_country", "continent", "traits"):
                _merge_maxmind_dict_field(combined, key, value)
            elif key not in combined and value is not None:
                combined[key] = value
    if isinstance(asn_rec, dict):
        for key, value in asn_rec.items():
            if value is not None:
                combined[key] = value
    return combined


def _read_maxmind_sync(ip: str) -> Dict[str, Any]:
    """
    Reads local GeoLite2 and GeoIP2 Country, City, and ASN MMDB files synchronously.
    Offloaded via `asyncio.to_thread` to avoid blocking the ASGI event loop on disk reads.
    """
    if not cidr_attribution.are_offline_intelligence_caches_warm():
        cidr_attribution.warm_offline_intelligence_caches()

    db_paths = cache_backends._resolve_maxmind_db_paths()
    available_paths = {key: path for key, path in db_paths.items() if os.path.exists(path)}

    for key, filename in MAXMIND_DB_SPECS:
        if key not in available_paths:
            evict_missing_maxmind_readers(filename, db_paths[key])

    if not available_paths:
        return adapt_maxmind(None, has_db=False)

    city_path = db_paths["city"]
    if record_city_db_presence(city_path, is_present="city" in available_paths):
        logger.warning(
            "GeoLite2-City.mmdb was not found at %s; MaxMind lookups will omit city",
            city_path,
        )

    try:
        import maxminddb
    except ImportError:
        logger.warning("maxminddb package not installed; returning Database Missing fallback")
        return adapt_maxmind(None, has_db=False)

    try:
        records: Dict[str, Optional[Dict[str, Any]]] = {}
        prefix_lens: Dict[str, Optional[int]] = {}
        for key, path in available_paths.items():
            reader = get_maxmind_reader(path, maxminddb)
            rec, prefix_len = _lookup_mmdb_record_and_prefix(reader, ip)
            records[key] = rec
            prefix_lens[key] = prefix_len

        combined_record = _merge_maxmind_records(records.get("country"), records.get("city"), records.get("asn"))
        resolved_prefix_len = next(
            (prefix_lens.get(key) for key in ("asn", "country", "city") if prefix_lens.get(key) is not None),
            None,
        )
        if resolved_prefix_len is not None:
            combined_record["_mmdb_prefix_len"] = resolved_prefix_len
        offline_updated_at = get_maxmind_newest_mtime_iso()
        if offline_updated_at:
            combined_record["_offline_db_updated_at"] = offline_updated_at

        return adapt_maxmind(combined_record, has_db=True, status_code=200, ip=ip)
    except (OSError, ValueError, RuntimeError) as exc:
        for path in db_paths.values():
            evict_maxmind_reader(path)
        safe_message = sanitize_error_message(str(exc))
        logger.error(f"Error querying MaxMind local database: {safe_message}")
        return adapt_maxmind({"error": safe_message}, has_db=True, status_code=500)


async def query_maxmind(ip: str) -> Dict[str, Any]:
    return await asyncio.to_thread(_read_maxmind_sync, ip)


def _read_stopforumspam_sync(ip: str) -> Dict[str, Any]:
    try:
        lookup = query_stopforumspam_offline(ip)
    except (OSError, sqlite3.Error, ValueError) as exc:
        safe_message = sanitize_error_message(str(exc))
        logger.error("Error querying StopForumSpam offline database: %s", safe_message)
        return adapt_stopforumspam({"success": 0, "error": safe_message}, status_code=500, has_db=True)

    if not lookup.get("has_db"):
        return adapt_stopforumspam(None, has_db=False)

    payload: Dict[str, Any] = {
        "success": 1,
        "ip": {
            "ip": ip,
            "appears": 1 if lookup.get("appears") else 0,
            "frequency": int(lookup.get("frequency") or 0),
            "lastseen": lookup.get("last_seen"),
            "blacklisted": bool(lookup.get("blacklisted")),
            "toxicCidr": lookup.get("toxic_cidr"),
            "sources": lookup.get("sources") or [],
        },
    }
    if lookup.get("offline_db_updated_at"):
        payload["offlineDbUpdatedAt"] = lookup["offline_db_updated_at"]
    return adapt_stopforumspam(payload, status_code=200, has_db=True)


async def query_stopforumspam(ip_or_client: Any, ip: Optional[str] = None) -> Dict[str, Any]:
    target_ip = ip if isinstance(ip, str) and ip.strip() else str(ip_or_client)
    return await asyncio.to_thread(_read_stopforumspam_sync, target_ip)


def _read_ipsum_drop_sync(ip: str) -> Dict[str, Any]:
    try:
        lookup = query_ipsum_drop_offline(ip)
    except (OSError, ValueError, RuntimeError) as exc:
        safe_message = sanitize_error_message(str(exc))
        logger.error("Error querying IPsum and Spamhaus DROP offline index: %s", safe_message)
        return adapt_ipsum_drop({"status": "error", "error": safe_message}, status_code=500, has_db=True)

    if not lookup.get("has_db"):
        return adapt_ipsum_drop(None, has_db=False)
    return adapt_ipsum_drop(lookup, status_code=200, has_db=True)


async def query_ipsum_drop(ip_or_client: Any, ip: Optional[str] = None) -> Dict[str, Any]:
    target_ip = ip if isinstance(ip, str) and ip.strip() else str(ip_or_client)
    return await asyncio.to_thread(_read_ipsum_drop_sync, target_ip)


def _read_openasn_sync(ip: str) -> Dict[str, Any]:
    try:
        lookup = query_openasn_offline(ip)
    except (OSError, ValueError, RuntimeError) as exc:
        safe_message = sanitize_error_message(str(exc))
        logger.error("Error querying OpenASN offline database: %s", safe_message)
        return adapt_openasn({"status": "error", "error": safe_message}, status_code=500, has_db=True)

    if not lookup.get("has_db"):
        return adapt_openasn(None, has_db=False)
    return adapt_openasn(lookup, status_code=200, has_db=True)


async def query_openasn(ip_or_client: Any, ip: Optional[str] = None) -> Dict[str, Any]:
    target_ip = ip if isinstance(ip, str) and ip.strip() else str(ip_or_client)
    return await asyncio.to_thread(_read_openasn_sync, target_ip)


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


def _get_dns_timeouts() -> Tuple[float, float]:
    timeout_s = _get_positive_float_setting("DNS_QUERY_TIMEOUT_SECONDS", DEFAULT_DNS_TIMEOUT_SECONDS)
    lifetime_s = _get_positive_float_setting("DNS_QUERY_LIFETIME_SECONDS", timeout_s)
    return timeout_s, lifetime_s


def _create_async_resolver() -> dns.asyncresolver.Resolver:
    global _cached_base_nameservers

    timeout_s, lifetime_s = _get_dns_timeouts()
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


def _extract_ptr_hostname(answer: Any) -> Optional[str]:
    if answer is None:
        return None
    if isinstance(answer, str):
        return answer
    for rdata in answer:
        target = getattr(rdata, "target", None)
        if target is not None:
            to_text = getattr(target, "to_text", None)
            raw = to_text() if callable(to_text) else str(target)
            if isinstance(raw, str) and raw.strip():
                return raw
        to_text = getattr(rdata, "to_text", None)
        if callable(to_text):
            raw = to_text()
            if isinstance(raw, str) and raw.strip():
                return raw
        raw = str(rdata)
        if raw.strip():
            return raw
    return None


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
        raw_host = _extract_ptr_hostname(answer)
        if not isinstance(raw_host, str):
            if isinstance(state, dict):
                state["status"] = "nxdomain"
            return None
        cleaned = sanitize_error_message(raw_host.strip().rstrip(".").lower())
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


def _extract_dnsbl_a_records(answer: Any) -> List[str]:
    if answer is None:
        return []
    codes: List[str] = []
    for rdata in answer:
        candidate: Optional[str] = None
        raw_addr = getattr(rdata, "address", None)
        if isinstance(raw_addr, str):
            candidate = raw_addr.strip()
        else:
            to_text = getattr(rdata, "to_text", None)
            if callable(to_text):
                txt = to_text()
                if isinstance(txt, str):
                    candidate = txt.strip()
            if candidate is None:
                candidate = str(rdata).strip()
        if not candidate:
            continue
        try:
            normalized = str(ipaddress.IPv4Address(candidate))
        except ValueError:
            continue
        if normalized not in codes:
            codes.append(normalized)
    return codes


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
        codes = _extract_dnsbl_a_records(answer)
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
        logger.warning(f"{provider_label} DNS query timed out: {safe_message}")
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
        logger.warning(f"{provider_label} DNS query failed: {safe_message}")
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


def _extract_txt_record_strings(answer: Any) -> List[str]:
    if answer is None:
        return []
    if isinstance(answer, str):
        return [answer.strip().strip('"')] if answer.strip() else []
    records: List[str] = []
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
    return records


def _parse_cymru_txt_origin(
    records: List[str],
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> Optional[Dict[str, Any]]:
    best_prefix: Optional[ipaddress.IPv4Network | ipaddress.IPv6Network] = None
    best_asn: Optional[int] = None
    for record in records:
        parts = [part.strip() for part in record.split("|")]
        if len(parts) < 2:
            continue
        raw_asn_tokens = parts[0].split()
        raw_prefix = parts[1]
        if not raw_prefix:
            continue
        try:
            net = ipaddress.ip_network(raw_prefix, strict=False)
        except ValueError:
            continue
        if net.version != addr.version or addr not in net or not (0 < net.prefixlen <= addr.max_prefixlen):
            continue

        asn_num: Optional[int] = None
        if raw_asn_tokens:
            first_token = raw_asn_tokens[0].upper()
            if first_token.startswith("AS"):
                first_token = first_token[2:]
            if first_token.isdigit() and int(first_token) > 0:
                asn_num = int(first_token)

        if best_prefix is None or net.prefixlen > best_prefix.prefixlen:
            best_prefix = net
            best_asn = asn_num

    if best_prefix is None:
        return None
    return {"bgpPrefix": str(best_prefix), "asn": best_asn}


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

    return _parse_cymru_txt_origin(_extract_txt_record_strings(answer), addr)
