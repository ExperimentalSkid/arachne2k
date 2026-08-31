"""Approved, fail-closed transports for onion and bounded provider GETs."""
from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import requests

from config_loader import get_bool, get_int
from safety_policy import is_onion_url
from tor_circuits import prepare_fetch_circuit, requests_proxy_url


NEUTRAL_HEADERS = {
    "User-Agent": "Mozilla/5.0 PassiveOSINTResearchBot/1.0",
    "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9",
    "Accept-Language": "en",
    "DNT": "1",
}

PROVIDER_HEADERS = {
    "User-Agent": "Arachne-Passive-Public-Provider/1.0",
    "Accept": "application/json",
    "Accept-Language": "en",
    "DNT": "1",
}
_PROVIDER_NAMES = {
    "openpgp_exact",
    "rdap_exact_domain",
    "certificate_transparency_exact",
}
_PUBLIC_HOST_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_PGP_FINGERPRINT_RE = re.compile(r"(?:[A-F0-9]{40}|[A-F0-9]{64})\Z")
_DOMAIN_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


def _public_hostname(host: str) -> bool:
    host = str(host or "").casefold().rstrip(".")
    if (
        not host
        or not _PUBLIC_HOST_RE.fullmatch(host)
        or host == "localhost"
        or host.endswith((".localhost", ".local", ".internal", ".onion", ".invalid", ".test"))
    ):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True


def _exact_public_domain(value: str) -> bool:
    domain = str(value or "").casefold().rstrip(".")
    return bool(
        _DOMAIN_RE.fullmatch(domain)
        and not domain.endswith((".onion", ".local", ".internal", ".invalid", ".test"))
    )


def _validate_provider_request(request: Any) -> None:
    """Reject every provider request outside the reviewed exact-lookup surface."""
    provider = str(getattr(request, "provider", "") or "")
    url = str(getattr(request, "url", "") or "")
    if provider not in _PROVIDER_NAMES:
        raise ValueError("OPSEC: unapproved public provider")
    try:
        target = urlsplit(url)
        port = target.port
    except ValueError as exc:
        raise ValueError("OPSEC: invalid provider URL") from exc
    host = (target.hostname or "").casefold().rstrip(".")
    if (
        target.scheme.casefold() != "https"
        or target.username is not None
        or target.password is not None
        or target.fragment
        or port not in {None, 443}
        or not _public_hostname(host)
    ):
        raise ValueError("OPSEC: provider URL must be public HTTPS")

    if provider == "openpgp_exact":
        fingerprint = unquote(target.path.removeprefix("/vks/v1/by-fingerprint/"))
        if (
            host != "keys.openpgp.org"
            or target.query
            or not target.path.startswith("/vks/v1/by-fingerprint/")
            or not _PGP_FINGERPRINT_RE.fullmatch(fingerprint)
        ):
            raise ValueError("OPSEC: invalid exact OpenPGP request")
        return

    if provider == "certificate_transparency_exact":
        query = parse_qs(target.query, keep_blank_values=True)
        if (
            host != "api.certspotter.com"
            or target.path.rstrip("/") != "/v1/issuances"
            or set(query) != {"domain", "include_subdomains", "match_wildcards", "expand"}
            or len(query["domain"]) != 1
            or not _exact_public_domain(query["domain"][0])
            or query["include_subdomains"] != ["false"]
            or query["match_wildcards"] != ["false"]
            or query["expand"] != ["dns_names"]
        ):
            raise ValueError("OPSEC: invalid exact Certificate Transparency request")
        return

    # The RDAP adapter may request the static IANA bootstrap document or one
    # authoritative HTTPS service selected from that document. No generic
    # search, entity endpoint, query string, redirect, or non-domain route is
    # allowed through this transport.
    if host == "data.iana.org":
        if target.path != "/rdap/dns.json" or target.query:
            raise ValueError("OPSEC: invalid IANA RDAP bootstrap request")
        return
    marker = "/domain/"
    if target.query or marker not in target.path.casefold():
        raise ValueError("OPSEC: RDAP transport accepts exact domain lookups only")
    domain = unquote(target.path[target.path.casefold().rfind(marker) + len(marker):])
    if "/" in domain or not _exact_public_domain(domain):
        raise ValueError("OPSEC: invalid exact RDAP domain")


def create_onion_session(*, proxy_url: str | None = None, prepare: bool = True) -> requests.Session:
    """Create a fresh GET-only, environment-independent Tor session."""
    if prepare:
        prepare_fetch_circuit()
    proxy = proxy_url or requests_proxy_url()
    if not proxy.casefold().startswith("socks5h://"):
        raise RuntimeError("OPSEC: onion proxy must use socks5h")
    session = requests.Session()
    session.trust_env = False
    session.proxies = {"http": proxy, "https": proxy}
    session.headers.clear()
    session.headers.update(NEUTRAL_HEADERS)
    session.cookies.clear()
    return session


def create_public_provider_session(
    *,
    proxy_url: str | None = None,
    prepare: bool = True,
) -> requests.Session:
    """Create a fresh Tor-isolated session for approved clear-web providers."""
    if prepare:
        prepare_fetch_circuit()
    proxy = proxy_url or requests_proxy_url()
    if not proxy.casefold().startswith("socks5h://"):
        raise RuntimeError("OPSEC: provider proxy must use socks5h")
    session = requests.Session()
    session.trust_env = False
    session.proxies = {"http": proxy, "https": proxy}
    session.headers.clear()
    session.headers.update(PROVIDER_HEADERS)
    session.cookies.clear()
    return session


def fetch_public_provider(
    request: Any,
    *,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Perform one reviewed provider GET through Tor and retain bounded bytes only."""
    if not (
        get_bool("DEEP_DISCOVERY_NETWORK_ENABLED", False)
        and get_bool("ALLOW_CLEARNET_FETCH", False)
    ):
        raise RuntimeError("OPSEC: public provider network is disabled")
    _validate_provider_request(request)
    if bool(getattr(request, "allow_redirects", False)):
        raise ValueError("OPSEC: provider redirects are forbidden")
    connect_timeout = max(1.0, min(float(getattr(request, "connect_timeout", 3.0)), 5.0))
    read_timeout = max(1.0, min(float(getattr(request, "read_timeout", 7.0)), 15.0))
    max_bytes = max(1024, min(int(getattr(request, "max_response_bytes", 0)), 512 * 1024))
    requested_headers = getattr(request, "headers", {}) or {}
    headers = {
        key: str(value)
        for key, value in dict(requested_headers).items()
        if str(key).casefold() == "accept"
    }
    owned = session is None
    current = session or create_public_provider_session()
    response = None
    try:
        response = current.get(
            str(getattr(request, "url")),
            headers=headers,
            timeout=(connect_timeout, read_timeout),
            stream=True,
            allow_redirects=False,
            cookies={},
        )
        body = bytearray()
        for chunk in response.iter_content(chunk_size=16 * 1024):
            if not chunk:
                continue
            body.extend(chunk)
            if len(body) > max_bytes:
                raise ValueError("OPSEC: provider response exceeded byte limit")
        safe_headers = {}
        for name in ("Content-Type", "Retry-After"):
            value = response.headers.get(name)
            if value is not None:
                safe_headers[name] = str(value)[:160]
        return {
            "status_code": int(response.status_code),
            "headers": safe_headers,
            "body": bytes(body),
        }
    finally:
        if response is not None:
            response.close()
        if owned:
            current.close()


def fetch_onion(url: str, *, session: requests.Session | None = None,
                timeout: int | tuple[int, int] | None = None) -> requests.Response:
    """Perform one bounded passive onion GET without redirects or downloads."""
    if not is_onion_url(url):
        raise ValueError("OPSEC: safe transport accepts onion URLs only")
    current = session or create_onion_session()
    return current.get(
        url,
        timeout=timeout or (get_int("ONION_CONNECT_TIMEOUT_SECONDS", 15),
                            get_int("ONION_READ_TIMEOUT_SECONDS", 30)),
        stream=True,
        allow_redirects=False,
        cookies={},
    )
