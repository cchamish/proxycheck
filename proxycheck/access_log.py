"""Privacy-preserving HTTP access logging at the ASGI boundary."""

import ipaddress
import logging
import re
import unicodedata
from urllib.parse import unquote

logger = logging.getLogger("proxycheck.access")
_REDACTED = "<redacted>"
_IPV4 = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
_IPV6 = re.compile(r"[0-9a-fA-F:.]*:[0-9a-fA-F:.]*(?:%[\w.-]+)?")
_PRIVATE_PARAMS = {"ip", "ips", "code", "state", "token"}


def _safe_field(value):
    return "".join(char for char in value if not unicodedata.category(char).startswith("C") and char not in '"\\')


def _redact_ip(match):
    value = match.group()
    try:
        ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return value
    return _REDACTED


def _decode(value):
    while True:
        decoded = unquote(value)
        if decoded == value:
            return value
        value = decoded


def redact_target(path, query):
    target = _decode(path)
    if query:
        parts = []
        for part in query.decode("latin1").split("&"):
            raw_key, equals, value = part.partition("=")
            key = _decode(raw_key)
            part = key + "=" + _REDACTED if key.lower() in _PRIVATE_PARAMS else key + equals + _decode(value)
            parts.append(part)
        target += "?" + "&".join(parts)
    target = _IPV6.sub(_redact_ip, target)
    return _safe_field(_IPV4.sub(_redact_ip, target))


class AccessLogMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        status = 500

        async def track_status(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, track_status)
        except BaseException:
            status = 500
            raise
        finally:
            ua = next((value for key, value in scope.get("headers", []) if key.lower() == b"user-agent"), b"")
            ua = _safe_field(ua.decode("latin1"))[:256] or "-"
            logger.info(
                'ua="%s" "%s %s HTTP/%s" %s',
                ua,
                _safe_field(scope.get("method", "-")),
                redact_target(scope.get("path", "/"), scope.get("query_string", b"")),
                _safe_field(scope.get("http_version", "-")),
                status,
            )
