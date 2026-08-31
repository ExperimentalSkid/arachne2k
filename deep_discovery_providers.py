"""Bounded, proposal-only provider adapters for Deep Discovery.

The adapters in this module never perform HTTP directly.  Callers must inject
an approved transport implementing the small ``fetch(ProviderRequest)``
contract.  Provider results are evidence proposals only: they never update
identity, policy, cards, alerts, classification, Spain, urgency, or analyst
state.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from typing import Any, Callable, Mapping
from urllib.parse import quote, urlencode, urlsplit

import config_loader
import deep_discovery


LOCAL_PROVIDER_NAME = "local_arachne"
OPENPGP_PROVIDER_NAME = "openpgp_exact"
RDAP_PROVIDER_NAME = "rdap_exact_domain"
CT_PROVIDER_NAME = "certificate_transparency_exact"
PROVIDER_ENABLE_FLAGS = {
    OPENPGP_PROVIDER_NAME: "DEEP_DISCOVERY_OPENPGP_ENABLED",
    RDAP_PROVIDER_NAME: "DEEP_DISCOVERY_RDAP_ENABLED",
    CT_PROVIDER_NAME: "DEEP_DISCOVERY_CT_ENABLED",
}

OPENPGP_ENDPOINT = "https://keys.openpgp.org/vks/v1/by-fingerprint/"
IANA_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
CERTSPOTTER_ENDPOINT = "https://api.certspotter.com/v1/issuances"

CONNECT_TIMEOUT_SECONDS = 3.0
READ_TIMEOUT_SECONDS = 7.0
OPENPGP_MAX_BYTES = 256 * 1024
JSON_MAX_BYTES = 512 * 1024
CT_MAX_RESULTS = 20

OPENPGP_CACHE_TTL_SECONDS = 24 * 60 * 60
RDAP_BOOTSTRAP_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
RDAP_CACHE_TTL_SECONDS = 24 * 60 * 60
CT_CACHE_TTL_SECONDS = 6 * 60 * 60

_CACHE_SCHEMA = "arachne.deep_discovery.provider_cache.v1"
_PGP_FINGERPRINT_RE = re.compile(r"(?:[0-9A-F]{40}|[0-9A-F]{64})\Z")
_DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_BLOCKED_DOMAIN_SUFFIXES = (
    ".onion", ".local", ".localhost", ".internal", ".invalid", ".test",
)
_SAFE_RESULT_KEYS = frozenset({
    "schema", "provider", "network_used", "status", "error_code",
    "query_hash", "result_count", "results", "decision_mode",
    "analyst_review_required", "cached",
})


@dataclass(frozen=True)
class ProviderRequest:
    """Transport-neutral bounded GET request."""

    provider: str
    url: str
    headers: Mapping[str, str]
    connect_timeout: float = CONNECT_TIMEOUT_SECONDS
    read_timeout: float = READ_TIMEOUT_SECONDS
    max_response_bytes: int = JSON_MAX_BYTES
    allow_redirects: bool = False


@dataclass(frozen=True)
class ProviderResponse:
    """Small response shape returned by an approved injected transport."""

    status_code: int
    headers: Mapping[str, str]
    body: bytes = b""
    json_body: object | None = None


ProviderFetch = Callable[[ProviderRequest], ProviderResponse | Mapping[str, object]]
CacheGet = Callable[[str], Mapping[str, object] | None]
CachePut = Callable[[str, Mapping[str, object], int], None]


def _hash_identifier(provider: str, value: str) -> str:
    return hashlib.sha256(f"{provider}:{value}".encode("utf-8")).hexdigest()[:24]


def _base_result(provider: str, query_hash: str, *, network_used: bool) -> dict[str, Any]:
    return {
        "schema": "arachne.deep_discovery.provider_result.v1",
        "provider": provider,
        "network_used": bool(network_used),
        "status": "complete",
        "error_code": None,
        "query_hash": query_hash,
        "result_count": 0,
        "results": [],
        "decision_mode": "proposal_only",
        "analyst_review_required": True,
        "cached": False,
    }


def _failure(provider: str, query_hash: str, status: str, error_code: str,
             *, network_used: bool) -> dict[str, Any]:
    result = _base_result(provider, query_hash, network_used=network_used)
    result.update(status=status, error_code=error_code)
    return result


def _safe_exception_code(exc: Exception) -> str:
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, OSError):
        return "network_error"
    return "provider_error"


def _response(value: ProviderResponse | Mapping[str, object]) -> ProviderResponse:
    if isinstance(value, ProviderResponse):
        return value
    if not isinstance(value, Mapping):
        raise TypeError("invalid provider response")
    status = value.get("status_code", value.get("status", 0))
    try:
        status_code = int(status)
    except (TypeError, ValueError) as exc:
        raise TypeError("invalid provider status") from exc
    body = value.get("body", b"")
    if isinstance(body, str):
        body = body.encode("utf-8", "replace")
    if not isinstance(body, bytes):
        body = b""
    headers = value.get("headers")
    return ProviderResponse(
        status_code=status_code,
        headers=dict(headers) if isinstance(headers, Mapping) else {},
        body=body,
        json_body=value.get("json_body"),
    )


def _header(response: ProviderResponse, name: str) -> str:
    target = name.casefold()
    for key, value in response.headers.items():
        if str(key).casefold() == target:
            return str(value)
    return ""


def _json_response(response: ProviderResponse, maximum: int) -> object:
    if response.json_body is not None:
        # Bound injected JSON by its serialized representation too.
        encoded = json.dumps(
            response.json_body, ensure_ascii=True, separators=(",", ":")
        ).encode("ascii")
        if len(encoded) > maximum:
            raise ValueError("response_too_large")
        return response.json_body
    if len(response.body) > maximum:
        raise ValueError("response_too_large")
    return json.loads(response.body.decode("utf-8"))


def _cache_key(provider: str, query_hash: str) -> str:
    return f"deep-discovery:{provider}:{query_hash}:v1"


def _cache_read(cache_get: CacheGet | None, key: str, provider: str,
                query_hash: str) -> dict[str, Any] | None:
    if cache_get is None:
        return None
    try:
        value = cache_get(key)
    except Exception:
        return None
    if not isinstance(value, Mapping):
        return None
    if value.get("_cache_schema") != _CACHE_SCHEMA:
        return None
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        return None
    if payload.get("provider") != provider or payload.get("query_hash") != query_hash:
        return None
    # Refuse cache extensions so an untrusted cache cannot inject raw material.
    if not set(payload).issubset(_SAFE_RESULT_KEYS):
        return None
    result = json.loads(json.dumps(dict(payload), ensure_ascii=True))
    result.update(network_used=False, cached=True)
    return result


def _cache_write(cache_put: CachePut | None, key: str, result: dict[str, Any],
                 ttl_seconds: int) -> None:
    if cache_put is None or result.get("status") not in {"complete", "not_found"}:
        return
    payload = {key: value for key, value in result.items() if key in _SAFE_RESULT_KEYS}
    try:
        cache_put(
            key,
            {"_cache_schema": _CACHE_SCHEMA, "payload": payload},
            int(ttl_seconds),
        )
    except Exception:
        # Cache availability must never change provider semantics.
        return


def _fetch_safely(fetch: ProviderFetch, request: ProviderRequest,
                  query_hash: str) -> tuple[ProviderResponse | None, dict[str, Any] | None]:
    try:
        response = _response(fetch(request))
    except Exception as exc:
        return None, _failure(
            request.provider, query_hash, "provider_error",
            _safe_exception_code(exc), network_used=True)
    if len(response.body) > request.max_response_bytes:
        return None, _failure(
            request.provider, query_hash, "provider_error",
            "response_too_large", network_used=True)
    return response, None


def normalize_openpgp_fingerprint(value: object) -> str | None:
    """Accept only a complete v4/v5 hexadecimal fingerprint.

    Short key IDs, ``0x`` prefixes, spaces, and partial values are rejected.
    """
    text = str(value or "").strip()
    upper = text.upper()
    return upper if text == upper and _PGP_FINGERPRINT_RE.fullmatch(upper) else None


def normalize_public_domain(value: object) -> str | None:
    """Return a strict lower-case IDNA domain or ``None``."""
    text = str(value or "").strip().rstrip(".")
    if not text or "://" in text or any(char in text for char in "/*@?#\\"):
        return None
    try:
        domain = text.encode("idna").decode("ascii").casefold()
    except (UnicodeError, ValueError):
        return None
    if len(domain) > 253 or "." not in domain or domain.endswith(_BLOCKED_DOMAIN_SUFFIXES):
        return None
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass
    labels = domain.split(".")
    if len(labels) < 2 or any(not _DNS_LABEL_RE.fullmatch(label) for label in labels):
        return None
    return domain


def lookup_openpgp_fingerprint(
    fingerprint: object,
    *,
    fetch: ProviderFetch,
    cache_get: CacheGet | None = None,
    cache_put: CachePut | None = None,
) -> dict[str, Any]:
    """Perform one exact, bounded VKS fingerprint lookup."""
    normalized = normalize_openpgp_fingerprint(fingerprint)
    query_hash = _hash_identifier(OPENPGP_PROVIDER_NAME, normalized or "invalid")
    if normalized is None:
        return _failure(
            OPENPGP_PROVIDER_NAME, query_hash, "invalid_identifier",
            "exact_fingerprint_required", network_used=False)
    key = _cache_key(OPENPGP_PROVIDER_NAME, query_hash)
    cached = _cache_read(cache_get, key, OPENPGP_PROVIDER_NAME, query_hash)
    if cached:
        return cached
    request = ProviderRequest(
        provider=OPENPGP_PROVIDER_NAME,
        url=OPENPGP_ENDPOINT + quote(normalized, safe=""),
        headers={"Accept": "application/pgp-keys"},
        max_response_bytes=OPENPGP_MAX_BYTES,
    )
    response, failure = _fetch_safely(fetch, request, query_hash)
    if failure:
        return failure
    assert response is not None
    if response.status_code == 404:
        result = _failure(
            OPENPGP_PROVIDER_NAME, query_hash, "not_found",
            "exact_fingerprint_not_found", network_used=True)
        _cache_write(cache_put, key, result, 60 * 60)
        return result
    if response.status_code == 429:
        return _failure(
            OPENPGP_PROVIDER_NAME, query_hash, "rate_limited",
            "provider_rate_limited", network_used=True)
    if response.status_code != 200:
        return _failure(
            OPENPGP_PROVIDER_NAME, query_hash, "provider_error",
            "unexpected_status", network_used=True)
    content_type = _header(response, "Content-Type").split(";", 1)[0].strip().casefold()
    if content_type != "application/pgp-keys":
        return _failure(
            OPENPGP_PROVIDER_NAME, query_hash, "provider_error",
            "unexpected_content_type", network_used=True)
    if not response.body.lstrip().startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"):
        return _failure(
            OPENPGP_PROVIDER_NAME, query_hash, "provider_error",
            "invalid_public_key_response", network_used=True)
    result = _base_result(OPENPGP_PROVIDER_NAME, query_hash, network_used=True)
    result.update(result_count=1, results=[{
        "candidate_id": f"pgp:{query_hash}",
        "display_name": "Exact OpenPGP fingerprint",
        "provider": OPENPGP_PROVIDER_NAME,
        "matching_pivots": ["pgp_fingerprint"],
        "supporting": [{
            "type": "exact_openpgp_fingerprint",
            "label": "Exact public-key lookup returned a public key",
        }],
        "contradicting": [],
        "exact_lookup": True,
        "decision_mode": "proposal_only",
    }])
    _cache_write(cache_put, key, result, OPENPGP_CACHE_TTL_SECONDS)
    return result


def iana_rdap_bootstrap_request() -> ProviderRequest:
    return ProviderRequest(
        provider=RDAP_PROVIDER_NAME,
        url=IANA_RDAP_BOOTSTRAP_URL,
        headers={"Accept": "application/json"},
        max_response_bytes=JSON_MAX_BYTES,
    )


def _safe_https_base(value: object) -> str | None:
    try:
        parsed = urlsplit(str(value or ""))
    except ValueError:
        return None
    host = (parsed.hostname or "").casefold()
    if (
        parsed.scheme.casefold() != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or host == "localhost"
        or host.endswith((".localhost", ".local", ".onion"))
    ):
        return None
    try:
        address = ipaddress.ip_address(host)
        if not address.is_global:
            return None
    except ValueError:
        pass
    path = parsed.path.rstrip("/") + "/"
    return f"https://{parsed.netloc}{path}"


def resolve_rdap_base(domain: object, bootstrap: object) -> str | None:
    """Resolve the exact TLD through the IANA DNS bootstrap document."""
    normalized = normalize_public_domain(domain)
    if normalized is None or not isinstance(bootstrap, Mapping):
        return None
    services = bootstrap.get("services")
    if not isinstance(services, list):
        return None
    tld = normalized.rsplit(".", 1)[-1]
    for entry in services:
        if not isinstance(entry, list) or len(entry) != 2:
            continue
        zones, bases = entry
        if not isinstance(zones, list) or not isinstance(bases, list):
            continue
        normalized_zones = {
            str(zone).strip().strip(".").casefold() for zone in zones
        }
        if tld not in normalized_zones:
            continue
        for base in bases:
            safe = _safe_https_base(base)
            if safe:
                return safe
    return None


def _rdap_query_request(domain: str, base: str) -> ProviderRequest:
    return ProviderRequest(
        provider=RDAP_PROVIDER_NAME,
        url=base + "domain/" + quote(domain, safe=".-"),
        headers={"Accept": "application/rdap+json, application/json;q=0.9"},
        max_response_bytes=JSON_MAX_BYTES,
    )


def _fetch_iana_bootstrap(
    fetch: ProviderFetch,
    *,
    cache_get: CacheGet | None,
    cache_put: CachePut | None,
) -> tuple[object | None, str | None]:
    cache_key = "deep-discovery:iana-rdap-dns-bootstrap:v1"
    if cache_get is not None:
        try:
            cached = cache_get(cache_key)
        except Exception:
            cached = None
        if (
            isinstance(cached, Mapping)
            and cached.get("_cache_schema") == _CACHE_SCHEMA
            and isinstance(cached.get("bootstrap"), Mapping)
        ):
            return cached["bootstrap"], None
    request = iana_rdap_bootstrap_request()
    try:
        response = _response(fetch(request))
    except Exception as exc:
        return None, _safe_exception_code(exc)
    if response.status_code != 200:
        return None, (
            "provider_rate_limited" if response.status_code == 429
            else "bootstrap_unavailable"
        )
    try:
        document = _json_response(response, request.max_response_bytes)
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        return None, "invalid_bootstrap_response"
    if not isinstance(document, Mapping) or not isinstance(document.get("services"), list):
        return None, "invalid_bootstrap_response"
    if cache_put is not None:
        try:
            cache_put(
                cache_key,
                {"_cache_schema": _CACHE_SCHEMA, "bootstrap": dict(document)},
                RDAP_BOOTSTRAP_CACHE_TTL_SECONDS,
            )
        except Exception:
            pass
    return document, None


def lookup_domain_rdap(
    domain: object,
    *,
    fetch: ProviderFetch,
    cache_get: CacheGet | None = None,
    cache_put: CachePut | None = None,
) -> dict[str, Any]:
    """Perform one exact RDAP domain lookup using the IANA bootstrap registry."""
    normalized = normalize_public_domain(domain)
    query_hash = _hash_identifier(RDAP_PROVIDER_NAME, normalized or "invalid")
    if normalized is None:
        return _failure(
            RDAP_PROVIDER_NAME, query_hash, "invalid_identifier",
            "exact_public_domain_required", network_used=False)
    key = _cache_key(RDAP_PROVIDER_NAME, query_hash)
    cached = _cache_read(cache_get, key, RDAP_PROVIDER_NAME, query_hash)
    if cached:
        return cached
    bootstrap, bootstrap_error = _fetch_iana_bootstrap(
        fetch, cache_get=cache_get, cache_put=cache_put)
    if bootstrap_error:
        return _failure(
            RDAP_PROVIDER_NAME, query_hash, "provider_error",
            bootstrap_error, network_used=True)
    base = resolve_rdap_base(normalized, bootstrap)
    if base is None:
        return _failure(
            RDAP_PROVIDER_NAME, query_hash, "not_supported",
            "no_authoritative_rdap_service", network_used=True)
    request = _rdap_query_request(normalized, base)
    response, failure = _fetch_safely(fetch, request, query_hash)
    if failure:
        return failure
    assert response is not None
    if response.status_code == 404:
        result = _failure(
            RDAP_PROVIDER_NAME, query_hash, "not_found",
            "exact_domain_not_found", network_used=True)
        _cache_write(cache_put, key, result, 60 * 60)
        return result
    if response.status_code == 429:
        return _failure(
            RDAP_PROVIDER_NAME, query_hash, "rate_limited",
            "provider_rate_limited", network_used=True)
    if response.status_code != 200:
        return _failure(
            RDAP_PROVIDER_NAME, query_hash, "provider_error",
            "unexpected_status", network_used=True)
    try:
        document = _json_response(response, request.max_response_bytes)
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        return _failure(
            RDAP_PROVIDER_NAME, query_hash, "provider_error",
            "invalid_json_response", network_used=True)
    if not isinstance(document, Mapping) or document.get("objectClassName") != "domain":
        return _failure(
            RDAP_PROVIDER_NAME, query_hash, "provider_error",
            "invalid_rdap_domain_response", network_used=True)
    response_domain = normalize_public_domain(
        document.get("ldhName") or document.get("unicodeName"))
    if response_domain != normalized:
        return _failure(
            RDAP_PROVIDER_NAME, query_hash, "provider_error",
            "exact_identifier_mismatch", network_used=True)
    statuses = sorted({
        str(value).strip().casefold()[:48]
        for value in (document.get("status") or [])
        if isinstance(value, str) and value.strip()
    })[:10]
    event_actions = sorted({
        str(value.get("eventAction") or "").strip().casefold()[:48]
        for value in (document.get("events") or [])
        if isinstance(value, Mapping) and value.get("eventAction")
    })[:10]
    nameserver_count = min(
        50,
        sum(
            1 for value in (document.get("nameservers") or [])
            if isinstance(value, Mapping)
            and normalize_public_domain(value.get("ldhName")) is not None
        ),
    )
    secure_dns = document.get("secureDNS")
    delegation_signed = (
        bool(secure_dns.get("delegationSigned"))
        if isinstance(secure_dns, Mapping)
        else None
    )
    result = _base_result(RDAP_PROVIDER_NAME, query_hash, network_used=True)
    result.update(result_count=1, results=[{
        "candidate_id": f"rdap:{query_hash}",
        "display_name": normalized,
        "domain": normalized,
        "provider": RDAP_PROVIDER_NAME,
        "matching_pivots": ["domain"],
        "supporting": [{
            "type": "exact_domain_rdap",
            "label": "Authoritative RDAP returned the exact domain object",
        }],
        "contradicting": [],
        "exact_lookup": True,
        "status_codes": statuses,
        "event_actions": event_actions,
        "nameserver_count": nameserver_count,
        "delegation_signed": delegation_signed,
        "decision_mode": "proposal_only",
    }])
    _cache_write(cache_put, key, result, RDAP_CACHE_TTL_SECONDS)
    return result


def certspotter_request(domain: object) -> ProviderRequest | None:
    normalized = normalize_public_domain(domain)
    if normalized is None:
        return None
    query = urlencode([
        ("domain", normalized),
        ("include_subdomains", "false"),
        ("match_wildcards", "false"),
        ("expand", "dns_names"),
    ])
    return ProviderRequest(
        provider=CT_PROVIDER_NAME,
        url=f"{CERTSPOTTER_ENDPOINT}?{query}",
        headers={"Accept": "application/json"},
        max_response_bytes=JSON_MAX_BYTES,
    )


def lookup_certificate_transparency(
    domain: object,
    *,
    fetch: ProviderFetch,
    cache_get: CacheGet | None = None,
    cache_put: CachePut | None = None,
) -> dict[str, Any]:
    """Query one bounded CT page for an exact public domain."""
    normalized = normalize_public_domain(domain)
    query_hash = _hash_identifier(CT_PROVIDER_NAME, normalized or "invalid")
    if normalized is None:
        return _failure(
            CT_PROVIDER_NAME, query_hash, "invalid_identifier",
            "exact_public_domain_required", network_used=False)
    key = _cache_key(CT_PROVIDER_NAME, query_hash)
    cached = _cache_read(cache_get, key, CT_PROVIDER_NAME, query_hash)
    if cached:
        return cached
    request = certspotter_request(normalized)
    assert request is not None
    response, failure = _fetch_safely(fetch, request, query_hash)
    if failure:
        return failure
    assert response is not None
    if response.status_code == 429:
        return _failure(
            CT_PROVIDER_NAME, query_hash, "rate_limited",
            "provider_rate_limited", network_used=True)
    if response.status_code != 200:
        return _failure(
            CT_PROVIDER_NAME, query_hash, "provider_error",
            "unexpected_status", network_used=True)
    try:
        document = _json_response(response, request.max_response_bytes)
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        return _failure(
            CT_PROVIDER_NAME, query_hash, "provider_error",
            "invalid_json_response", network_used=True)
    if not isinstance(document, list):
        return _failure(
            CT_PROVIDER_NAME, query_hash, "provider_error",
            "invalid_ct_response", network_used=True)
    issuances = []
    for item in document[:CT_MAX_RESULTS]:
        if not isinstance(item, Mapping):
            continue
        exact_names = {
            normalize_public_domain(value)
            for value in (item.get("dns_names") or [])
            if isinstance(value, str)
        }
        if normalized not in exact_names:
            continue
        opaque = str(
            item.get("tbs_sha256")
            or item.get("cert_sha256")
            or item.get("id")
            or ""
        )
        issuance_hash = hashlib.sha256(
            f"{normalized}:{opaque}".encode("utf-8", "replace")
        ).hexdigest()[:24]
        issuances.append({
            "issuance_hash": issuance_hash,
            "not_before": str(item.get("not_before") or "")[:32] or None,
            "not_after": str(item.get("not_after") or "")[:32] or None,
            "revoked": (
                bool(item.get("revoked"))
                if item.get("revoked") is not None
                else None
            ),
        })
    result = _base_result(CT_PROVIDER_NAME, query_hash, network_used=True)
    if issuances:
        result.update(result_count=1, results=[{
            "candidate_id": f"ct:{query_hash}",
            "display_name": normalized,
            "domain": normalized,
            "provider": CT_PROVIDER_NAME,
            "matching_pivots": ["domain"],
            "supporting": [{
                "type": "exact_domain_certificate_transparency",
                "label": "Certificate Transparency returned the exact domain",
            }],
            "contradicting": [],
            "exact_lookup": True,
            "issuance_count": len(issuances),
            "issuances": issuances,
            "result_truncated": len(document) > CT_MAX_RESULTS,
            "decision_mode": "proposal_only",
        }])
    else:
        result["status"] = "not_found"
        result["error_code"] = "exact_domain_not_present"
    _cache_write(cache_put, key, result, CT_CACHE_TTL_SECONDS)
    return result


def run_local_provider(actor_detail: dict | None) -> dict[str, Any]:
    """Return explainable local candidates without any network access."""
    results = deep_discovery.local_first_candidates(actor_detail)
    return {
        "provider": LOCAL_PROVIDER_NAME,
        "network_used": False,
        "status": "complete",
        "results": results,
    }


def provider_status() -> dict[str, Any]:
    """Truthful provider availability for worker/UI status."""
    network_enabled = bool(
        config_loader.get_bool("DEEP_DISCOVERY_NETWORK_ENABLED", False)
        and config_loader.get_bool("ALLOW_CLEARNET_FETCH", False)
    )
    adapters = [
        OPENPGP_PROVIDER_NAME, RDAP_PROVIDER_NAME, CT_PROVIDER_NAME,
    ]
    enabled_adapters = [
        provider for provider in adapters
        if config_loader.get_bool(PROVIDER_ENABLE_FLAGS[provider], True)
    ] if network_enabled else []
    return {
        "network_enabled": network_enabled,
        "transport": "tor_socks5h_exact_get_only",
        "enabled_providers": [LOCAL_PROVIDER_NAME, *enabled_adapters],
        "disabled_providers": [
            provider for provider in adapters if provider not in enabled_adapters
        ],
        "available_adapters": adapters,
        "reason": (
            "exact_provider_transport_enabled"
            if network_enabled
            else "network_disabled_fail_closed"
        ),
    }


__all__ = [
    "CERTSPOTTER_ENDPOINT",
    "CT_MAX_RESULTS",
    "CT_PROVIDER_NAME",
    "IANA_RDAP_BOOTSTRAP_URL",
    "LOCAL_PROVIDER_NAME",
    "OPENPGP_ENDPOINT",
    "OPENPGP_PROVIDER_NAME",
    "ProviderRequest",
    "ProviderResponse",
    "RDAP_PROVIDER_NAME",
    "certspotter_request",
    "iana_rdap_bootstrap_request",
    "lookup_certificate_transparency",
    "lookup_domain_rdap",
    "lookup_openpgp_fingerprint",
    "normalize_openpgp_fingerprint",
    "normalize_public_domain",
    "provider_status",
    "resolve_rdap_base",
    "run_local_provider",
]
