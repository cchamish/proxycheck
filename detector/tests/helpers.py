"""Shared test doubles and provider mock helpers for the detector P0 test suite."""

import contextlib
from typing import Any, Callable, Dict, Optional, Tuple
from unittest.mock import AsyncMock, MagicMock, patch

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
    adapt_ipsum_drop,
    adapt_maxmind,
    adapt_proxycheck,
    adapt_shodan_internetdb,
    adapt_stopforumspam,
    adapt_tor_onionoo,
    adapt_x4bnet_vpn,
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
    ("IPsum / DROP", lambda raw, code: adapt_ipsum_drop(raw, code)),
    ("X4BNet VPN", lambda raw, code: adapt_x4bnet_vpn(raw, code)),
    ("Shodan InternetDB", lambda raw, code: adapt_shodan_internetdb(raw, code)),
)


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
        results = [await getattr(self._store, name)(*args, **kwargs) for name, args, kwargs in self._ops]
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

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.strings:
            return False
        self.strings[key] = str(value)
        if ex is not None:
            self.ttls[key] = int(ex)
        return True

    async def delete(self, *keys):
        removed = 0
        for key in keys:
            if self.strings.pop(key, None) is not None or self.hashes.pop(key, None) is not None:
                removed += 1
                self.ttls.pop(key, None)
        return removed

    async def ttl(self, key):
        if key not in self.strings and key not in self.hashes:
            return -2
        return self.ttls.get(key, -1)

    async def incr(self, key, amount=1):
        updated = int(self.strings.get(key, "0")) + int(amount)
        self.strings[key] = str(updated)
        return updated

    async def decr(self, key, amount=1):
        updated = int(self.strings.get(key, "0")) - int(amount)
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
        merged = {**(mapping or {}), **kwargs}
        for field, val in merged.items():
            bucket[str(field)] = str(val)
        return len(merged)

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def pipeline(self, transaction=True):
        return _FakeRedisPipeline(self)


class _BatchingFakeRedis(FakeAsyncRedis):
    """In-memory Redis double that records single reads, batch reads, and pipeline flushes."""

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


_DNS_PROVIDER_KEYS = frozenset({"maxmind", "spamhaus_zen", "spamcop", "stopforumspam", "ipsum_drop", "x4bnet_vpn"})

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
