"""Shared test doubles, mock builders, and fixtures for the detector test suite."""

import contextlib
import socket
import threading
import time
from types import SimpleNamespace
from typing import Any, Callable, Dict, Optional, Tuple
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.name
import dns.resolver
import dns.reversename
import uvicorn

from detector import (
    cache_backends,
    cidr_attribution,
    detection_service,
    dns_providers,
    http_client,
    intelligence,
)
from detector.adapters import (
    adapt_abuseipdb,
    adapt_cloudflare_radar,
    adapt_dshield,
    adapt_getipintel,
    adapt_ip2location,
    adapt_ipdata,
    adapt_iphub,
    adapt_iphunter,
    adapt_ipregistry,
    adapt_maxmind,
    adapt_proxycheck,
    adapt_stopforumspam,
    adapt_tor_onionoo,
)
from detector.provider_registry import PROVIDER_REGISTRY

TEST_UPSTREAM_SECRETS = {
    "CLOUDFLARE_RADAR_TOKEN": "cf-radar-token-7a1c",
    "ABUSEIPDB_API_KEY": "abuseipdb-key-55d2",
    "IPDATA_API_KEY": "ipdata-key-90bb",
    "IPREGISTRY_API_KEY": "ipregistry-key-3f4e",
    "IP2LOCATION_API_KEY": "ip2location-key-c0de",
    "GETIPINTEL_CONTACT_EMAIL": "ops-contact@example.org",
    "PROXYCHECK_API_KEY": "secret123",
    "IPHUB_API_KEY": "iphub-key-81fa",
    "IPHUNTER_API_KEY": "iphunter-key-6e09",
}

EMPTY_UPSTREAM_SECRETS = {name: "" for name in TEST_UPSTREAM_SECRETS}

MAXMIND_STUB = {
    "provider": "MaxMind",
    "status": "Database Missing",
    "statusCode": None,
    "asn": "-",
    "isp": "-",
    "organisation": "-",
    "location": "-",
    "usageType": "-",
    "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
    "rawJson": {"status": "error", "message": "Local MMDB files not found"},
}

ALL_ADAPTERS = (
    ("Cloudflare Radar", lambda raw, code: adapt_cloudflare_radar(raw, True, code)),
    ("AbuseIPDB", lambda raw, code: adapt_abuseipdb(raw, True, code)),
    ("IPData", lambda raw, code: adapt_ipdata(raw, True, code)),
    ("IPRegistry", lambda raw, code: adapt_ipregistry(raw, True, code)),
    ("IP2Location", lambda raw, code: adapt_ip2location(raw, True, code)),
    ("MaxMind", lambda raw, code: adapt_maxmind(raw, True, code)),
    ("GetIPIntel", lambda raw, code: adapt_getipintel(raw, True, code)),
    ("Proxycheck", lambda raw, code: adapt_proxycheck(raw, True, code, "8.8.8.8")),
    ("IPHub", lambda raw, code: adapt_iphub(raw, True, code)),
    ("IPHunter", lambda raw, code: adapt_iphunter(raw, True, code)),
    ("Tor Onionoo", lambda raw, code: adapt_tor_onionoo(raw, code, "8.8.8.8")),
    ("StopForumSpam", lambda raw, code: adapt_stopforumspam(raw, code)),
    ("DShield", lambda raw, code: adapt_dshield(raw, code)),
)


HTTP_PROVIDERS = tuple(name for name, _ in ALL_ADAPTERS if name not in ("MaxMind", "Tor Onionoo", "StopForumSpam"))


def _mock_ptr_answer(*hostnames):
    return [SimpleNamespace(target=dns.name.from_text(host)) for host in hostnames]


def _mock_a_answer(*ipv4_codes):
    return [SimpleNamespace(address=code) for code in ipv4_codes]


def _ptr_or_clean_dns_side_effect(ptr_hostname=None, ptr_timeout=False):
    async def _impl(_self_or_qname, rdtype="A", *_args, **_kwargs):
        if str(rdtype).upper() == "PTR":
            if ptr_timeout:
                raise dns.exception.Timeout("DNS timed out")
            if ptr_hostname:
                return _mock_ptr_answer(ptr_hostname)
        raise dns.resolver.NXDOMAIN()

    return _impl


def _mock_response(status_code=200, json_value=None, json_error=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if json_error is not None:
        resp.json.side_effect = json_error
    else:
        resp.json.return_value = json_value
    return resp


def _login_authorised(test_case):
    session = test_case.client.session
    session["wikimedia_user"] = {
        "isLoggedIn": True,
        "username": "SysopUser",
        "role": "Local Administrator (sysop)",
        "hasAccess": True,
        "localGroups": ["sysop"],
        "globalGroups": [],
    }
    session.save()


def _patch_async_client(mock_async_client_cls, get_side_effect):
    mock_client = AsyncMock()
    mock_client.get.side_effect = get_side_effect
    mock_client.__aenter__.return_value = mock_client
    mock_async_client_cls.return_value = mock_client
    return mock_client


@contextlib.contextmanager
def _run_uvicorn_smoke_server(asgi_app):
    """Starts an ephemeral local Uvicorn server and guarantees shutdown on exit."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    finally:
        sock.close()

    config = uvicorn.Config(
        asgi_app,
        host="127.0.0.1",
        port=port,
        log_level="error",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5.0
        while not server.started:
            if not thread.is_alive() or time.monotonic() >= deadline:
                raise RuntimeError("Uvicorn test server failed to become ready within timeout.")
            time.sleep(0.02)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)


class _FakeRedisPipeline:
    """Queued command pipeline mirroring redis.asyncio pipeline execution."""

    def __init__(self, store):
        self._store = store
        self._ops = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def _queue(self, name, *args, **kwargs):
        self._ops.append((name, args, kwargs))
        return self

    def get(self, *args, **kwargs):
        return self._queue("get", *args, **kwargs)

    def set(self, *args, **kwargs):
        return self._queue("set", *args, **kwargs)

    def ttl(self, *args, **kwargs):
        return self._queue("ttl", *args, **kwargs)

    def incr(self, *args, **kwargs):
        return self._queue("incr", *args, **kwargs)

    def decr(self, *args, **kwargs):
        return self._queue("decr", *args, **kwargs)

    def expire(self, *args, **kwargs):
        return self._queue("expire", *args, **kwargs)

    def hincrby(self, *args, **kwargs):
        return self._queue("hincrby", *args, **kwargs)

    def hset(self, *args, **kwargs):
        return self._queue("hset", *args, **kwargs)

    def hgetall(self, *args, **kwargs):
        return self._queue("hgetall", *args, **kwargs)

    async def execute(self):
        results = []
        for name, args, kwargs in self._ops:
            results.append(await getattr(self._store, name)(*args, **kwargs))
        self._ops.clear()
        return results


class FakeAsyncRedis:
    """In-memory async Redis double supporting quota buckets, hashes, TTLs, and pipelines."""

    def __init__(self):
        self.strings = {}
        self.hashes = {}
        self.ttls = {}

    async def get(self, key):
        return self.strings.get(key)

    async def set(self, key, value, ex=None):
        self.strings[key] = str(value)
        if ex is not None:
            self.ttls[key] = int(ex)
        return True

    async def ttl(self, key):
        if key not in self.strings and key not in self.hashes:
            return -2
        return self.ttls.get(key, -1)

    async def incr(self, key, amount=1):
        current = int(self.strings.get(key, "0"))
        updated = current + int(amount)
        self.strings[key] = str(updated)
        return updated

    async def decr(self, key, amount=1):
        current = int(self.strings.get(key, "0"))
        updated = current - int(amount)
        self.strings[key] = str(updated)
        return updated

    async def expire(self, key, seconds):
        if key not in self.strings and key not in self.hashes:
            return 0
        self.ttls[key] = int(seconds)
        return 1

    async def hincrby(self, key, field, amount=1):
        bucket = self.hashes.setdefault(key, {})
        updated = int(bucket.get(field, "0")) + int(amount)
        bucket[field] = str(updated)
        return updated

    async def hset(self, key, mapping=None, **kwargs):
        bucket = self.hashes.setdefault(key, {})
        merged = {}
        if mapping:
            merged.update(mapping)
        merged.update(kwargs)
        for field, val in merged.items():
            bucket[str(field)] = str(val)
        return len(merged)

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def pipeline(self, transaction=True):
        return _FakeRedisPipeline(self)


class _BatchingFakeRedis(FakeAsyncRedis):
    """In-memory Redis double that records single reads, batch reads and pipeline flushes."""

    def __init__(self):
        super().__init__()
        self.get_calls = []
        self.mget_calls = []
        self.pipeline_calls = []

    async def get(self, key):
        self.get_calls.append(key)
        return await super().get(key)

    async def mget(self, keys):
        self.mget_calls.append(list(keys))
        return [self.strings.get(key) for key in keys]

    def pipeline(self, transaction=True):
        self.pipeline_calls.append(transaction)
        return super().pipeline(transaction=transaction)


def build_provider_http_response(url, ip="8.8.8.8"):
    static_payloads = (
        (
            "cloudflare.com",
            {"success": True, "result": {"ip": {"asn": "15169", "asnName": "Google LLC", "asnLocation": "US"}}},
            None,
        ),
        (
            "abuseipdb.com",
            {"data": {"isp": "Google LLC", "countryCode": "US", "usageType": "Data Center", "abuseConfidenceScore": 0}},
            {"X-RateLimit-Remaining": "982", "X-RateLimit-Limit": "1000"},
        ),
        (
            "ipdata.co",
            {
                "asn": {"asn": "AS15169", "name": "Google LLC"},
                "country_name": "United States",
                "country_code": "US",
                "threat": {},
                "count": "142",
            },
            None,
        ),
        (
            "ipregistry.co",
            {
                "company": {"name": "Google LLC"},
                "connection": {"asn": 15169, "type": "isp"},
                "location": {"country": {"name": "United States", "code": "US"}},
                "security": {},
            },
            {"RateLimit-Remaining": "4950"},
        ),
        (
            "ip2location.io",
            {
                "asn": "15169",
                "as": "Google LLC",
                "country_name": "United States",
                "country_code": "US",
                "usage_type": "DCH",
                "is_proxy": False,
            },
            None,
        ),
        ("getipintel.net", {"status": "success", "result": "0.02"}, None),
        (
            "proxycheck.io",
            {
                "status": "ok",
                ip: {
                    "asn": "AS15169",
                    "provider": "Google LLC",
                    "country": "United States",
                    "isocode": "US",
                    "proxy": "no",
                },
            },
            None,
        ),
        (
            "iphub.info",
            {"asn": 15169, "isp": "Google LLC", "countryName": "United States", "countryCode": "US", "block": 0},
            None,
        ),
        (
            "iphunter.info",
            {
                "status": "success",
                "data": {"isp": "Google LLC", "country_name": "United States", "country_code": "US", "block": 0},
            },
            None,
        ),
        ("onionoo.torproject.org", {"relays": []}, None),
        ("stopforumspam.org", {"success": 1, "ip": {"appears": 0, "frequency": 0, "confidence": 0.0}}, None),
        (
            "sans.edu",
            {"ip": {"count": 0, "attacks": 0, "as": "15169", "asname": "Google LLC", "ascountry": "US"}},
            None,
        ),
        ("dshield", {"ip": {"count": 0, "attacks": 0, "as": "15169", "asname": "Google LLC", "ascountry": "US"}}, None),
    )
    for fragment, payload, headers in static_payloads:
        if fragment in url:
            resp = _mock_response(status_code=200, json_value=payload)
            if headers is not None:
                resp.headers = headers
            return resp
    return _mock_response(status_code=404, json_value={})


def clean_dns_side_effect(qname, rdtype):
    if rdtype == "PTR":
        answer = MagicMock()
        answer.__str__ = lambda self: "dns.google."
        return [answer]
    raise dns.resolver.NXDOMAIN()


_DNS_PROVIDER_KEYS = frozenset({"maxmind", "spamhaus_zen", "spamcop", "stopforumspam"})

CANONICAL_PROVIDER_PATCH_TARGETS: Dict[str, str] = {
    meta.key: (
        f"detector.dns_providers.query_{meta.key}"
        if meta.key in _DNS_PROVIDER_KEYS
        else f"detector.providers.query_{meta.key}"
    )
    for meta in PROVIDER_REGISTRY
}

NON_DNSBL_PROVIDER_PATCH_SPECS: Tuple[Tuple[str, str, str], ...] = tuple(
    (meta.key, CANONICAL_PROVIDER_PATCH_TARGETS[meta.key], meta.label)
    for meta in PROVIDER_REGISTRY
    if not meta.is_dnsbl
)


def stub_unconfigured_provider_row(name: str) -> Dict[str, Any]:
    """Builds a clean unconfigured stub row for a named upstream provider."""
    return {
        "provider": name,
        "status": "No API Key",
        "statusCode": None,
        "asn": "-",
        "isp": "-",
        "organisation": "-",
        "location": "-",
        "usageType": "-",
        "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
        "rawJson": {"status": "error", "message": "API key not configured"},
    }


def start_non_dnsbl_provider_stubs(
    test_case,
    *,
    overrides: Optional[Dict[str, Any]] = None,
    row_builder: Callable[[str], Dict[str, Any]] = stub_unconfigured_provider_row,
) -> Dict[str, AsyncMock]:
    """Starts canonical AsyncMock patches for all 13 non-DNSBL providers and registers cleanup."""
    mocks: Dict[str, AsyncMock] = {}
    custom = overrides or {}
    for key, target_path, label in NON_DNSBL_PROVIDER_PATCH_SPECS:
        return_row = custom[key] if key in custom else row_builder(label)
        patcher = patch(target_path, new_callable=AsyncMock, return_value=return_row)
        mocks[key] = patcher.start()
        test_case.addCleanup(patcher.stop)
    return mocks


@contextlib.contextmanager
def patch_non_dnsbl_providers(
    side_effect_builder: Callable[[str], Any],
    *,
    overrides: Optional[Dict[str, Any]] = None,
):
    """Context manager patching all non-DNSBL providers with a per-label side effect or override mock."""
    custom = overrides or {}
    with contextlib.ExitStack() as stack:
        mocks: Dict[str, Any] = {}
        for key, target_path, label in NON_DNSBL_PROVIDER_PATCH_SPECS:
            if key in custom:
                mocks[key] = stack.enter_context(patch(target_path, custom[key]))
            else:
                mocks[key] = stack.enter_context(patch(target_path, side_effect=side_effect_builder(label)))
        yield mocks


def reset_detector_caches() -> None:
    """Resets shared HTTP, Redis, MaxMind, DNS, offline, and singleflight caches between tests."""
    with http_client.http_client_lock:
        http_client.http_clients_by_loop.clear()
    cache_backends.clear_redis_clients()
    cache_backends.clear_maxmind_readers()
    cache_backends.clear_maxmind_probe_cache()
    dns_providers.clear_dns_resolver_cache()
    intelligence.clear_proc_rss_cache()
    detection_service._ip_detect_inflight.clear()
    cidr_attribution.clear_offline_intelligence_caches()
