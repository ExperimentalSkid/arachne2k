from __future__ import annotations

import inspect
import json
from urllib.parse import parse_qs, urlsplit

import deep_discovery_providers as providers
import safe_transport


FINGERPRINT = "0123456789ABCDEF0123456789ABCDEF01234567"


def _json_response(value, status=200):
    return providers.ProviderResponse(
        status_code=status,
        headers={"Content-Type": "application/json"},
        body=json.dumps(value).encode("utf-8"),
    )


def test_openpgp_requires_exact_uppercase_full_fingerprint_without_network():
    calls = []

    def fetch(request):
        calls.append(request)
        raise AssertionError("invalid identifiers must not reach transport")

    for value in (
        "0123456789ABCDEF",
        "0x" + FINGERPRINT,
        FINGERPRINT.lower(),
        "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567",
        FINGERPRINT + "00",
    ):
        result = providers.lookup_openpgp_fingerprint(value, fetch=fetch)
        assert result["status"] == "invalid_identifier"
        assert result["network_used"] is False
        assert result["results"] == []
    assert calls == []


def test_openpgp_exact_lookup_is_bounded_and_discards_armored_key_material():
    seen = []
    armored = (
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
        b"private-looking-public-key-material\n"
        b"-----END PGP PUBLIC KEY BLOCK-----\n"
    )

    def fetch(request):
        seen.append(request)
        return providers.ProviderResponse(
            200, {"Content-Type": "application/pgp-keys"}, armored)

    result = providers.lookup_openpgp_fingerprint(FINGERPRINT, fetch=fetch)
    assert result["status"] == "complete"
    assert result["result_count"] == 1
    assert result["results"][0]["matching_pivots"] == ["pgp_fingerprint"]
    assert result["decision_mode"] == "proposal_only"
    assert seen[0].url.endswith("/" + FINGERPRINT)
    assert seen[0].allow_redirects is False
    assert seen[0].connect_timeout <= 3
    assert seen[0].read_timeout <= 7
    assert seen[0].max_response_bytes == providers.OPENPGP_MAX_BYTES
    assert "private-looking-public-key-material" not in json.dumps(result)
    assert FINGERPRINT not in json.dumps(result)


def test_provider_errors_are_reason_coded_without_exception_text():
    secret = "secret-onion-or-token-value"

    def fetch(_request):
        raise RuntimeError(secret)

    result = providers.lookup_openpgp_fingerprint(FINGERPRINT, fetch=fetch)
    rendered = json.dumps(result)
    assert result["status"] == "provider_error"
    assert result["error_code"] == "provider_error"
    assert secret not in rendered


def test_cache_hooks_are_bounded_and_skip_network_on_valid_hit():
    stored = {}
    calls = []

    def cache_put(key, value, ttl):
        stored[key] = (value, ttl)

    def fetch(request):
        calls.append(request)
        return providers.ProviderResponse(
            200,
            {"Content-Type": "application/pgp-keys"},
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nX\n",
        )

    first = providers.lookup_openpgp_fingerprint(
        FINGERPRINT, fetch=fetch, cache_put=cache_put)
    assert first["cached"] is False
    assert list(stored.values())[0][1] == providers.OPENPGP_CACHE_TTL_SECONDS

    second = providers.lookup_openpgp_fingerprint(
        FINGERPRINT,
        fetch=lambda _request: (_ for _ in ()).throw(
            AssertionError("network must not run")),
        cache_get=lambda key: stored[key][0],
    )
    assert len(calls) == 1
    assert second["cached"] is True
    assert second["network_used"] is False


def test_public_domain_gate_rejects_onion_urls_wildcards_ips_and_single_labels():
    assert providers.normalize_public_domain("Example.COM.") == "example.com"
    assert providers.normalize_public_domain("münich.example") == "xn--mnich-kva.example"
    for value in (
        "example", "*.example.com", "https://example.com", "example.com/path",
        "127.0.0.1", "localhost", "example.onion", "name@example.com",
    ):
        assert providers.normalize_public_domain(value) is None


def test_rdap_uses_iana_bootstrap_and_requires_exact_domain_object():
    requests = []
    bootstrap = {
        "services": [
            [["com"], ["http://unsafe.invalid/rdap/", "https://rdap.example/"]],
        ],
    }
    rdap = {
        "objectClassName": "domain",
        "ldhName": "EXAMPLE.COM",
        "status": ["active"],
        "events": [{"eventAction": "registration", "eventDate": "2020-01-01"}],
        "nameservers": [{"objectClassName": "nameserver", "ldhName": "ns1.example.com"}],
        "entities": [{
            "vcardArray": ["vcard", [["email", {}, "text", "private@example.com"]]],
        }],
        "secureDNS": {"delegationSigned": True},
    }

    def fetch(request):
        requests.append(request)
        return _json_response(bootstrap if len(requests) == 1 else rdap)

    result = providers.lookup_domain_rdap("example.com", fetch=fetch)
    assert result["status"] == "complete"
    assert len(requests) == 2
    assert requests[0].url == providers.IANA_RDAP_BOOTSTRAP_URL
    assert requests[1].url == "https://rdap.example/domain/example.com"
    assert requests[1].allow_redirects is False
    candidate = result["results"][0]
    assert candidate["domain"] == "example.com"
    assert candidate["matching_pivots"] == ["domain"]
    assert candidate["nameserver_count"] == 1
    assert candidate["delegation_signed"] is True
    rendered = json.dumps(result)
    assert "private@example.com" not in rendered
    assert "vcard" not in rendered


def test_rdap_rejects_nonexact_response_and_unsafe_bootstrap_base():
    unsafe = {"services": [[["com"], ["https://127.0.0.1/rdap/"]]]}
    assert providers.resolve_rdap_base("example.com", unsafe) is None

    responses = iter([
        _json_response({"services": [[["com"], ["https://rdap.example/"]]]}),
        _json_response({"objectClassName": "domain", "ldhName": "other.com"}),
    ])
    result = providers.lookup_domain_rdap(
        "example.com", fetch=lambda _request: next(responses))
    assert result["status"] == "provider_error"
    assert result["error_code"] == "exact_identifier_mismatch"
    assert result["results"] == []


def test_certificate_transparency_is_exact_single_page_and_bounded():
    requests = []
    rows = [
        {
            "id": str(index),
            "tbs_sha256": f"{index:064x}",
            "dns_names": ["example.com", f"other-{index}.example.net"],
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2026-04-01T00:00:00Z",
            "revoked": False,
            "cert_der": "must-not-be-retained",
        }
        for index in range(25)
    ]

    def fetch(request):
        requests.append(request)
        return _json_response(rows)

    result = providers.lookup_certificate_transparency(
        "example.com", fetch=fetch)
    assert len(requests) == 1
    request = requests[0]
    query = parse_qs(urlsplit(request.url).query)
    assert query == {
        "domain": ["example.com"],
        "include_subdomains": ["false"],
        "match_wildcards": ["false"],
        "expand": ["dns_names"],
    }
    candidate = result["results"][0]
    assert candidate["issuance_count"] == providers.CT_MAX_RESULTS
    assert candidate["result_truncated"] is True
    rendered = json.dumps(result)
    assert "must-not-be-retained" not in rendered
    assert "other-0.example.net" not in rendered
    assert "cert_der" not in rendered


def test_certificate_transparency_discards_nonexact_san_results():
    result = providers.lookup_certificate_transparency(
        "example.com",
        fetch=lambda _request: _json_response([
            {"id": "1", "dns_names": ["www.example.com", "*.example.com"]},
        ]),
    )
    assert result["status"] == "not_found"
    assert result["results"] == []


def test_provider_module_has_no_direct_network_or_production_mutators():
    source = inspect.getsource(providers)
    forbidden = (
        "import requests",
        "import httpx",
        "import aiohttp",
        "urllib.request",
        "requests.get(",
        "urlopen(",
        "apply_onion_policy(",
        "apply_manual_category(",
        "queue_spain_alert(",
        "update_site_card_rollups(",
        "merge_site_cards(",
    )
    assert all(token not in source for token in forbidden)
    status = providers.provider_status()
    assert status["network_enabled"] is False
    assert status["enabled_providers"] == ["local_arachne"]
    assert set(status["available_adapters"]) == {
        "openpgp_exact", "rdap_exact_domain",
        "certificate_transparency_exact",
    }


class _TransportResponse:
    def __init__(self, body=b"{}", status=200, content_type="application/json"):
        self.status_code = status
        self.headers = {"Content-Type": content_type, "Unsafe": "discard-me"}
        self._body = body
        self.closed = False

    def iter_content(self, chunk_size=1):
        del chunk_size
        yield self._body

    def close(self):
        self.closed = True


class _TransportSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


def test_approved_provider_transport_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(safe_transport, "get_bool", lambda _key, default=False: default)
    request = providers.ProviderRequest(
        provider=providers.OPENPGP_PROVIDER_NAME,
        url=providers.OPENPGP_ENDPOINT + FINGERPRINT,
        headers={"Accept": "application/pgp-keys"},
    )

    try:
        safe_transport.fetch_public_provider(
            request, session=_TransportSession(_TransportResponse()))
    except RuntimeError as exc:
        assert "network is disabled" in str(exc)
    else:
        raise AssertionError("disabled provider transport must fail closed")


def test_approved_provider_transport_rejects_non_exact_targets(monkeypatch):
    monkeypatch.setattr(safe_transport, "get_bool", lambda _key, default=False: True)
    session = _TransportSession(_TransportResponse())
    request = providers.ProviderRequest(
        provider=providers.RDAP_PROVIDER_NAME,
        url="https://rdap.example/entity/private@example.com",
        headers={"Accept": "application/json"},
    )

    try:
        safe_transport.fetch_public_provider(request, session=session)
    except ValueError as exc:
        assert "exact domain lookups only" in str(exc)
    else:
        raise AssertionError("non-domain RDAP request must fail closed")
    assert session.calls == []


def test_approved_provider_transport_returns_only_bounded_safe_response(monkeypatch):
    monkeypatch.setattr(safe_transport, "get_bool", lambda _key, default=False: True)
    response = _TransportResponse(
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nX\n",
        content_type="application/pgp-keys",
    )
    session = _TransportSession(response)
    request = providers.ProviderRequest(
        provider=providers.OPENPGP_PROVIDER_NAME,
        url=providers.OPENPGP_ENDPOINT + FINGERPRINT,
        headers={"Accept": "application/pgp-keys", "Authorization": "must-not-pass"},
        max_response_bytes=1024,
    )

    result = safe_transport.fetch_public_provider(request, session=session)

    assert result["status_code"] == 200
    assert result["headers"] == {"Content-Type": "application/pgp-keys"}
    assert response.closed is True
    assert session.calls[0][1]["headers"] == {"Accept": "application/pgp-keys"}
    assert session.calls[0][1]["allow_redirects"] is False
    assert session.calls[0][1]["stream"] is True
