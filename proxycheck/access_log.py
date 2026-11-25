"""Privacy-preserving HTTP access logging and bot User-Agent blocking at the ASGI boundary."""

import asyncio
import ipaddress
import logging
import os
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

logger = logging.getLogger("proxycheck.access")
_REDACTED = "<redacted>"
_IPV4 = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
_IPV6 = re.compile(r"[0-9a-fA-F:.]*:[0-9a-fA-F:.]*(?:%[\w.-]+)?")
_PRIVATE_PARAMS = {"ip", "ips", "code", "state", "token"}
_DEFAULT_BLOCKED_USER_AGENTS = (
    "lightpanda",
    "bytespider",
    "gptbot",
    "claudebot",
    "ccbot",
    "amazonbot",
    "anthropic-ai",
    "petalbot",
    "semrushbot",
    "ahrefsbot",
    "dotbot",
    "mj12bot",
)
_BLOCK_RESPONSE_HEADERS = [
    (b"content-type", b"text/plain; charset=utf-8"),
    (b"retry-after", b"3600"),
    (b"cache-control", b"no-store"),
]
_BLOCK_RESPONSE_BODY = b"Too Many Requests\n"


def _safe_field(value):
    return "".join(char for char in value if not unicodedata.category(char).startswith("C") and char not in '"\\')


def _redact_ip(match):
    value = match.group()
    try:
        ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return value
    return _REDACTED


def _decode_bytes(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.decode("latin1")


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
        for part in _decode_bytes(query).split("&"):
            raw_key, equals, value = part.partition("=")
            key = _decode(raw_key)
            part = key + "=" + _REDACTED if key.lower() in _PRIVATE_PARAMS else key + equals + _decode(value)
            parts.append(part)
        target += "?" + "&".join(parts)
    target = _IPV6.sub(_redact_ip, target)
    return _safe_field(_IPV4.sub(_redact_ip, target))


def _resolve_block_log_dir(block_log_dir=None) -> Path:
    explicit = block_log_dir or os.environ.get("BLOCK_LOG_DIR", "").strip()
    if explicit:
        return Path(os.path.expanduser(os.path.expandvars(str(explicit))))
    tool_data_dir = os.environ.get("TOOL_DATA_DIR", "").strip()
    if tool_data_dir:
        return Path(os.path.expanduser(os.path.expandvars(tool_data_dir))) / "logs" / "block"
    return Path.home() / "logs" / "block"


class AccessLogMiddleware:
    def __init__(self, app, *, blocked_user_agents=None, block_log_dir=None):
        self.app = app
        if blocked_user_agents is not None:
            self._blocked_uas = tuple(token.strip().lower() for token in blocked_user_agents if token.strip())
        else:
            extra = (token.strip().lower() for token in os.environ.get("BLOCKED_USER_AGENTS", "").split(","))
            self._blocked_uas = _DEFAULT_BLOCKED_USER_AGENTS + tuple(token for token in extra if token)
        self._block_log_dir = _resolve_block_log_dir(block_log_dir)

    def _is_blocked_ua(self, ua: str) -> bool:
        if not ua:
            return True
        lower = ua.lower()
        return any(token in lower for token in self._blocked_uas)

    def _write_block_log(self, line: str) -> None:
        now = datetime.now(timezone.utc)
        log_path = self._block_log_dir / f"{now:%Y-%m-%d}.log"
        try:
            self._block_log_dir.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(f"{now:%Y-%m-%dT%H:%M:%SZ} {line}\n")
        except OSError as exc:
            logger.warning("Failed to write block log to %s: %s", log_path, exc)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        raw_ua = next((value for key, value in scope.get("headers", []) if key.lower() == b"user-agent"), b"")
        ua = _safe_field(_decode_bytes(raw_ua))[:256]
        path = scope.get("path", "/")
        method = _safe_field(scope.get("method", "-"))
        target = redact_target(path, scope.get("query_string", b""))
        http_version = _safe_field(scope.get("http_version", "-"))

        if path != "/robots.txt" and self._is_blocked_ua(ua):
            await send({"type": "http.response.start", "status": 429, "headers": _BLOCK_RESPONSE_HEADERS})
            await send({"type": "http.response.body", "body": _BLOCK_RESPONSE_BODY})
            await asyncio.to_thread(
                self._write_block_log,
                f'ua="{ua or "-"}" "{method} {target} HTTP/{http_version}" 429',
            )
            return

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
            logger.info('ua="%s" "%s %s HTTP/%s" %s', ua or "-", method, target, http_version, status)
