"""Request-scoped context variables for provider upstream events and reverse DNS state."""

from __future__ import annotations

import contextvars
from typing import Any, Dict, Optional

provider_upstream_events: contextvars.ContextVar[Optional[Dict[str, Dict[str, Any]]]] = contextvars.ContextVar(
    "provider_upstream_events", default=None
)
rdns_context_state: contextvars.ContextVar[Optional[Dict[str, str]]] = contextvars.ContextVar(
    "rdns_context_state", default=None
)


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
