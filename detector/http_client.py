"""Shared event-loop-scoped cookieless HTTP client pool and lifecycle helpers."""

from __future__ import annotations

import asyncio
import http.cookiejar
import inspect
import logging
import threading
import weakref
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("detector.views")

http_client_lock = threading.Lock()
http_clients_by_loop: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, Any] = weakref.WeakKeyDictionary()

DEFAULT_HTTP_LIMITS = httpx.Limits(max_connections=100, max_keepalive_connections=20)


def clear_client_cookies(client: Any) -> None:
    """Clears stored cookies on an HTTP client when a non-empty synchronous jar is attached."""
    cookies = getattr(client, "cookies", None)
    if cookies is None:
        return
    clear_fn = getattr(cookies, "clear", None)
    if not callable(clear_fn) or inspect.iscoroutinefunction(clear_fn):
        return
    try:
        has_entries = len(cookies) > 0 if hasattr(cookies, "__len__") else False
    except TypeError:
        has_entries = False
    if has_entries:
        clear_fn()


async def close_http_client_safely(client: Any) -> None:
    """Closes a superseded httpx.AsyncClient instance without propagating loop-state errors."""
    if client is None or getattr(client, "is_closed", False) is True:
        return
    aclose_fn = getattr(client, "aclose", None)
    if not callable(aclose_fn):
        return
    try:
        maybe_coro = aclose_fn()
        if inspect.isawaitable(maybe_coro):
            await maybe_coro
    except (httpx.HTTPError, RuntimeError, OSError) as exc:
        logger.debug("Ignoring error whilst closing superseded HTTP client: %s", exc)


def build_cookieless_http_client(*, headers: Optional[Dict[str, str]] = None) -> httpx.AsyncClient:
    """Constructs a pooled httpx.AsyncClient that rejects cookies on both storage and request paths."""

    async def strip_request_cookie(request: httpx.Request) -> None:
        request.headers.pop("cookie", None)

    # Pass the CookieJar directly because httpx.AsyncClient copies httpx.Cookies into a new default jar.
    cookie_jar = http.cookiejar.CookieJar(
        policy=http.cookiejar.DefaultCookiePolicy(allowed_domains=[]),
    )
    client_kwargs: Dict[str, Any] = {
        "timeout": 10.0,
        "limits": DEFAULT_HTTP_LIMITS,
        "cookies": cookie_jar,
        "event_hooks": {"request": [strip_request_cookie]},
    }
    if headers is not None:
        client_kwargs["headers"] = headers
    return httpx.AsyncClient(**client_kwargs)


async def get_shared_http_client() -> httpx.AsyncClient:
    """Returns a reusable cookieless httpx.AsyncClient bound to the currently running event loop."""
    current_loop = asyncio.get_running_loop()
    stale_clients: List[Any] = []

    with http_client_lock:
        for loop in list(http_clients_by_loop.keys()):
            if loop.is_closed() or getattr(http_clients_by_loop.get(loop), "is_closed", False) is True:
                dead_client = http_clients_by_loop.pop(loop, None)
                if dead_client is not None:
                    stale_clients.append(dead_client)

        selected_client = http_clients_by_loop.get(current_loop)
        if selected_client is None or getattr(selected_client, "is_closed", False) is True:
            selected_client = build_cookieless_http_client()
            http_clients_by_loop[current_loop] = selected_client

    for stale_client in stale_clients:
        await close_http_client_safely(stale_client)

    return selected_client


async def clear_shared_http_clients() -> None:
    """Removes and safely closes all cached HTTP clients across event loops."""
    with http_client_lock:
        clients = list(http_clients_by_loop.values())
        http_clients_by_loop.clear()
    for client in clients:
        await close_http_client_safely(client)
