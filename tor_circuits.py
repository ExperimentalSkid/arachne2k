"""Bounded Tor stream isolation and optional circuit renewal for passive fetches.

Onion services do not use a normal Tor exit relay.  The useful OPSEC control here
is separating crawler streams so consecutive sites are not deliberately attached
to one long-lived SOCKS circuit.  Optional NEWNYM signaling is rate-limited and
never required for the crawler to keep working.
"""
from __future__ import annotations

import logging
import secrets
import threading
import time
from urllib.parse import quote

from config_loader import get_bool, get_int, get_str


LOGGER = logging.getLogger("tor_circuits")
_LOCK = threading.Lock()
_REQUEST_COUNT = 0
_LAST_NEWNYM_AT = 0.0
_SOCKS_IDENTITY_STARTED_AT = 0.0
_SOCKS_IDENTITY: tuple[str, str] | None = None


def _new_isolation_credentials() -> tuple[str, str]:
    token = secrets.token_hex(12)
    return f"arachne-{token}", secrets.token_hex(12)


def _isolation_credentials() -> tuple[str | None, str | None]:
    """Return the identity selected at the most recent safe fetch boundary."""
    global _SOCKS_IDENTITY_STARTED_AT, _SOCKS_IDENTITY
    if not get_bool("TOR_SOCKS_ISOLATION", True):
        return None, None
    with _LOCK:
        if _SOCKS_IDENTITY is None:
            _SOCKS_IDENTITY = _new_isolation_credentials()
            _SOCKS_IDENTITY_STARTED_AT = time.monotonic()
        return _SOCKS_IDENTITY


def requests_proxy_url() -> str:
    """Return the SOCKS proxy URL for the current bounded identity window."""
    host = get_str("TOR_SOCKS_HOST", "127.0.0.1") or "127.0.0.1"
    port = get_int("TOR_SOCKS_PORT", 9050)
    username, password = _isolation_credentials()
    if username and password:
        return f"socks5h://{quote(username)}:{quote(password)}@{host}:{port}"
    return f"socks5h://{host}:{port}"


def playwright_proxy() -> dict[str, str]:
    """Return Playwright proxy settings using the same stream-isolation policy."""
    host = get_str("TOR_SOCKS_HOST", "127.0.0.1") or "127.0.0.1"
    port = get_int("TOR_SOCKS_PORT", 9050)
    username, password = _isolation_credentials()
    proxy = {"server": f"socks5://{host}:{port}"}
    if username and password:
        proxy.update(username=username, password=password)
    return proxy


def _signal_newnym() -> bool:
    try:
        from stem import Signal
        from stem.control import Controller

        host = get_str("TOR_CONTROL_HOST", "127.0.0.1") or "127.0.0.1"
        port = get_int("TOR_CONTROL_PORT", 9051)
        password = get_str("TOR_CONTROL_PASSWORD")
        with Controller.from_port(address=host, port=port) as controller:
            controller.authenticate(password=password or None)
            if hasattr(controller, "is_newnym_available") and not controller.is_newnym_available():
                return False
            controller.signal(Signal.NEWNYM)
        return True
    except Exception as exc:
        LOGGER.warning("Optional Tor circuit renewal unavailable: %s", type(exc).__name__)
        return False


def prepare_fetch_circuit(now: float | None = None) -> dict[str, object]:
    """Apply due rotation only at the safe boundary before the next URL fetch."""
    global _REQUEST_COUNT, _LAST_NEWNYM_AT, _SOCKS_IDENTITY_STARTED_AT, _SOCKS_IDENTITY
    current = time.monotonic() if now is None else float(now)
    with _LOCK:
        _REQUEST_COUNT += 1
        request_number = _REQUEST_COUNT
        identity_interval = max(60, get_int("TOR_SOCKS_IDENTITY_INTERVAL_SECONDS", 900))
        identity_due = (_SOCKS_IDENTITY is None or current < _SOCKS_IDENTITY_STARTED_AT
                        or current - _SOCKS_IDENTITY_STARTED_AT >= identity_interval)
        identity_rotated = False
        if get_bool("TOR_SOCKS_ISOLATION", True) and identity_due:
            _SOCKS_IDENTITY = _new_isolation_credentials()
            _SOCKS_IDENTITY_STARTED_AT = current
            identity_rotated = True
        enabled = get_bool("TOR_NEWNYM_ENABLED", False)
        every = max(0, get_int("TOR_NEWNYM_EVERY_REQUESTS", 0))
        renewal_interval = max(600, get_int("TOR_NEWNYM_INTERVAL_SECONDS", 900))
        minimum_interval = max(60, get_int("TOR_NEWNYM_MIN_INTERVAL_SECONDS", 600))
        if enabled and (_LAST_NEWNYM_AT == 0.0 or current < _LAST_NEWNYM_AT):
            # Establish a baseline instead of needlessly renewing on process startup.
            _LAST_NEWNYM_AT = current
        elapsed = current - _LAST_NEWNYM_AT
        due_by_time = elapsed >= renewal_interval
        due_by_count = every > 0 and request_number % every == 0
        due = enabled and (due_by_time or due_by_count) and elapsed >= minimum_interval
        if due:
            _LAST_NEWNYM_AT = current
    renewed = _signal_newnym() if due else False
    return {
        "request_number": request_number,
        "socks_isolation": get_bool("TOR_SOCKS_ISOLATION", True),
        "socks_identity_rotated": identity_rotated,
        "newnym_requested": due,
        "newnym_succeeded": renewed,
    }


def reset_rotation_state_for_tests() -> None:
    global _REQUEST_COUNT, _LAST_NEWNYM_AT, _SOCKS_IDENTITY_STARTED_AT, _SOCKS_IDENTITY
    with _LOCK:
        _REQUEST_COUNT = 0
        _LAST_NEWNYM_AT = 0.0
        _SOCKS_IDENTITY_STARTED_AT = 0.0
        _SOCKS_IDENTITY = None


def circuit_policy_status() -> dict[str, object]:
    return {
        "socks_isolation": get_bool("TOR_SOCKS_ISOLATION", True),
        "socks_identity_interval_seconds": max(60, get_int("TOR_SOCKS_IDENTITY_INTERVAL_SECONDS", 900)),
        "newnym_enabled": get_bool("TOR_NEWNYM_ENABLED", False),
        "newnym_interval_seconds": max(600, get_int("TOR_NEWNYM_INTERVAL_SECONDS", 900)),
        "newnym_every_requests": max(0, get_int("TOR_NEWNYM_EVERY_REQUESTS", 0)),
        "newnym_min_interval_seconds": max(60, get_int("TOR_NEWNYM_MIN_INTERVAL_SECONDS", 600)),
    }
