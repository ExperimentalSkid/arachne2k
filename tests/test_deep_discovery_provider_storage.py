from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

import actor_intelligence
from classification_schema import DESTINATION_HTML_EVIDENCE_VERSION
from entity_extractor import extract_indicators
import onion_worker
import storage


FINGERPRINT = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
HOST = "a" * 56 + ".onion"
SOURCE_URL = f"http://{HOST}/profile/example"


def _actor_with_safe_page() -> tuple[int, int]:
    now = storage.utc_now_iso()
    with storage.get_db() as db:
        db.execute("""INSERT INTO onion_urls
          (url,onion_domain,status,active,first_seen,verification_state,
           destination_html_evidence_version,storage_policy,queue_policy,
           primary_category,safety_state)
          VALUES(?,?,?,1,?,?,?,?,?,?,?)""",
          (SOURCE_URL, HOST, "crawled", now, "verified",
           DESTINATION_HTML_EVIDENCE_VERSION, "safe_summary", "normal",
           "forum_social", "safe"))
        db.execute("""INSERT INTO actors
          (normalized_alias,display_alias,onion_host,first_seen,last_seen,
           observation_count,confidence_score,confidence_label,identity_key)
          VALUES(?,?,?,?,?,?,?,?,?)""",
          ("exampleactor", "ExampleActor", HOST, now, now, 1, 0.98, "high",
           f"test:exampleactor:{HOST}"))
        actor_id = int(db.execute("SELECT last_insert_rowid()").fetchone()[0])
        db.execute("""INSERT INTO actor_observations
          (actor_id,url,onion_host,observed_at,last_seen,page_type,
           primary_category,risk_level,evidence_type,evidence_confidence,
           safe_context_label,source_scope)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
          (actor_id, SOURCE_URL, HOST, now, now, "profile_page",
           "forum_social", "low", "profile_page_identity", 0.98,
           "Exact public profile container", "actor"))
        observation_id = int(db.execute("SELECT last_insert_rowid()").fetchone()[0])
    return actor_id, observation_id


def _bind_exact_identifier(
    actor_id: int,
    observation_id: int,
    indicator_type: str,
    normalized_value: str,
    *,
    association_confidence: float = 0.98,
    indicator_confidence: float = 0.98,
    linked: bool = True,
) -> None:
    now = storage.utc_now_iso()
    local_digest = hashlib.sha256(
        f"{indicator_type}:{normalized_value}".encode()).hexdigest()
    local_value = f"local_sha256:{local_digest}"
    value_hash = hashlib.sha256(
        f"{indicator_type}:{local_value}".encode()).hexdigest()
    with storage.get_db() as db:
        db.execute("""INSERT INTO actor_identifiers
          (actor_id,indicator_type,value_hash,safe_value_label,
           association_confidence,first_seen,last_seen,observation_id,
           binding_method,source_scope)
          VALUES(?,?,?,?,?,?,?,?,?,?)""",
          (actor_id, indicator_type, value_hash, "Exact public identifier",
           association_confidence, now, now, observation_id,
           "same_structural_container", "actor"))
        actor_identifier_id = int(
            db.execute("SELECT last_insert_rowid()").fetchone()[0])
        db.execute("""INSERT INTO actor_identifier_observations
          (actor_identifier_id,observation_id,first_seen,last_seen)
          VALUES(?,?,?,?)""",
          (actor_identifier_id, observation_id, now, now))
        db.execute("""INSERT INTO indicators
          (indicator_type,value,normalized_value,first_seen,last_seen,
           source_type,source_ref,confidence,risk_flags)
          VALUES(?,?,?,?,?,?,?,?,?)""",
          (indicator_type, normalized_value, normalized_value, now, now,
           "onion_page", SOURCE_URL, indicator_confidence, "[]"))
        indicator_id = int(db.execute("SELECT last_insert_rowid()").fetchone()[0])
        if linked:
            db.execute("""INSERT INTO indicator_links
              (indicator_id,source_type,source_ref,context_snippet,first_seen)
              VALUES(?,?,?,?,?)""",
              (indicator_id, "onion_page", SOURCE_URL,
               "[REDACTED EXACT IDENTIFIER]", now))


def test_provider_schema_is_additive_and_indexed(isolated_db):
    with storage.get_db() as db:
        tables = {row["name"] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        indexes = {row["name"] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='index'")}

    assert {
        "deep_discovery_provider_runs",
        "deep_discovery_provider_evidence",
        "deep_discovery_provider_cache",
    } <= tables
    assert {
        "idx_deep_provider_runs_job",
        "idx_deep_provider_runs_parent",
        "idx_deep_provider_evidence_run",
        "idx_deep_provider_cache_expiry",
    } <= indexes


def test_provider_run_is_idempotent_and_never_persists_raw_query(isolated_db):
    first = storage.record_deep_discovery_provider_run(
        "openpgp_exact", "pgp_fingerprint", FINGERPRINT,
        status="running", idempotency_key="private-invocation-scope",
        safe_metadata={
            "record_type": "pgp_lookup",
            "raw_http_body": "SECRET BODY",
            "credential": "bot-token-secret",
            "source_url": f"http://{HOST}/private",
        },
    )
    second = storage.record_deep_discovery_provider_run(
        "openpgp_exact", "pgp_fingerprint", FINGERPRINT,
        status="complete", idempotency_key="private-invocation-scope",
        result_count=1,
        safe_metadata={"record_type": "pgp_lookup"},
    )

    assert second == first
    rows = storage.get_deep_discovery_provider_runs(provider_name="openpgp_exact")
    assert len(rows) == 1
    assert rows[0]["status"] == "complete"
    assert rows[0]["result_count"] == 1
    stored = json.dumps(rows, sort_keys=True)
    assert FINGERPRINT not in stored
    assert "private-invocation-scope" not in stored
    assert "SECRET BODY" not in stored
    assert "bot-token-secret" not in stored
    assert ".onion" not in stored
    assert json.loads(rows[0]["safe_metadata_json"]) == {
        "record_type": "pgp_lookup"
    }


def test_provider_evidence_is_normalized_bounded_and_idempotent(isolated_db):
    run_id = storage.record_deep_discovery_provider_run(
        "rdap_exact_domain", "clearnet_domain", "Example.COM",
        status="complete", idempotency_key="evidence-test")
    evidence = [{
        "identifier_type": "clearnet_domain",
        "identifier_value": "WWW.Example.COM",
        "evidence_type": "rdap_domain_record",
        "provenance_type": "rdap",
        "provenance_ref": "https://rdap.example.test/domain/example.com?token=secret",
        "confidence": 0.93,
        "support_codes": ["exact-domain", "registry-match"],
        "contradiction_codes": ["registrant-country-differs"],
        "safe_metadata": {
            "record_type": "domain",
            "country_code": "ES",
            "record_count": 2,
            "domains": ["www.example.com", f"http://{HOST}/not-public"],
            "raw_http_body": "DO NOT STORE",
            "registrant_email": "person@example.com",
        },
    }]

    assert storage.upsert_deep_discovery_provider_evidence(run_id, evidence) == 1
    assert storage.upsert_deep_discovery_provider_evidence(run_id, evidence) == 1
    rows = storage.get_deep_discovery_provider_evidence(run_id)
    assert len(rows) == 1
    assert rows[0]["public_identifier"] == "www.example.com"
    assert json.loads(rows[0]["support_codes_json"]) == [
        "exact-domain", "registry-match"
    ]
    assert json.loads(rows[0]["contradiction_codes_json"]) == [
        "registrant-country-differs"
    ]
    metadata = json.loads(rows[0]["safe_metadata_json"])
    assert metadata == {
        "country_code": "es",
        "domains": ["www.example.com"],
        "record_count": 2,
        "record_type": "domain",
    }
    serialized = json.dumps(rows, sort_keys=True)
    assert "token=secret" not in serialized
    assert "DO NOT STORE" not in serialized
    assert "person@example.com" not in serialized
    assert ".onion" not in serialized


@pytest.mark.parametrize(
    ("query_type", "query_value"),
    [
        ("clearnet_domain", f"{HOST}"),
        ("clearnet_domain", "https://example.com/path"),
        ("clearnet_domain", "127.0.0.1"),
        ("pgp_fingerprint", "ABCD1234"),
        ("email", "person@example.com"),
    ],
)
def test_provider_queries_require_exact_allowed_public_identifiers(
    isolated_db, query_type, query_value
):
    with pytest.raises(ValueError):
        storage.record_deep_discovery_provider_run(
            "test_provider", query_type, query_value,
            idempotency_key="invalid-query")


def test_provider_cache_has_bounded_ttl_redaction_and_expiry(isolated_db):
    cache_key = storage.put_deep_discovery_provider_cache(
        "rdap_exact_domain", "clearnet_domain", "example.com",
        [{
            "identifier_type": "clearnet_domain",
            "identifier_value": "example.net",
            "evidence_type": "related_public_domain",
            "provenance_type": "rdap",
            "provenance_ref": "https://rdap.test/secret-source",
            "confidence": 0.8,
            "safe_metadata": {
                "record_type": "domain",
                "raw_http_body": "SECRET RESPONSE",
            },
        }],
        ttl_seconds=99_999_999,
    )
    cached = storage.get_deep_discovery_provider_cache(
        "rdap_exact_domain", "clearnet_domain", "EXAMPLE.COM")
    assert cached is not None
    assert cached["cache_key"] == cache_key
    assert cached["normalized_results"][0]["public_identifier"] == "example.net"
    assert "SECRET RESPONSE" not in json.dumps(cached, sort_keys=True)
    assert "secret-source" not in json.dumps(cached, sort_keys=True)
    expires = datetime.fromisoformat(cached["expires_at"].replace("Z", "+00:00"))
    stored = datetime.fromisoformat(cached["stored_at"].replace("Z", "+00:00"))
    assert timedelta(days=6, hours=23) < expires - stored <= timedelta(days=7)

    expired = "2000-01-01T00:00:00Z"
    with storage.get_db() as db:
        db.execute(
            "UPDATE deep_discovery_provider_cache SET expires_at=? WHERE cache_key=?",
            (expired, cache_key),
        )
    assert storage.get_deep_discovery_provider_cache(
        "rdap_exact_domain", "clearnet_domain", "example.com") is None
    assert storage.purge_expired_deep_discovery_provider_cache(limit=1) == 1


def test_exact_structurally_bound_pivots_are_resolved_in_process_only(isolated_db):
    actor_id, observation_id = _actor_with_safe_page()
    _bind_exact_identifier(
        actor_id, observation_id, "pgp_fingerprint", FINGERPRINT)
    _bind_exact_identifier(
        actor_id, observation_id, "clearnet_url",
        "https://Public.Example.org/profile/example")
    # Key-block digests remain local-correlation-only and never become public
    # OpenPGP queries.
    _bind_exact_identifier(
        actor_id, observation_id, "pgp_key_block",
        "PGP_BLOCK_SHA256:0011223344556677")

    pivots = storage.get_deep_discovery_provider_pivots(actor_id)

    assert [(row["query_type"], row["query_value"]) for row in pivots] == [
        ("pgp_fingerprint", FINGERPRINT),
        ("clearnet_domain", "public.example.org"),
    ]
    assert all(row["confidence"] >= 0.9 for row in pivots)
    assert all(row["source_hash"].startswith("sha256:") for row in pivots)
    assert all(".onion" not in row["source_hash"] for row in pivots)


def test_page_wide_weak_or_restricted_identifiers_never_become_pivots(isolated_db):
    actor_id, observation_id = _actor_with_safe_page()
    _bind_exact_identifier(
        actor_id, observation_id, "pgp_fingerprint", FINGERPRINT,
        association_confidence=0.89)
    _bind_exact_identifier(
        actor_id, observation_id, "clearnet_url", "https://example.org/",
        linked=False)
    assert storage.get_deep_discovery_provider_pivots(actor_id) == []

    # A later exact binding is still suppressed when the source page crosses
    # the restricted/storage boundary.
    _bind_exact_identifier(
        actor_id, observation_id, "clearnet_url",
        "https://public.example.net/profile")
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET storage_policy='metadata_only',
          queue_policy='blocked',primary_category='adult_restricted',
          safety_state='metadata_only' WHERE url=?""", (SOURCE_URL,))
    assert storage.get_deep_discovery_provider_pivots(actor_id) == []


def test_provider_persistence_never_mutates_actor_or_page_policy(isolated_db):
    actor_id, _observation_id = _actor_with_safe_page()
    with storage.get_db() as db:
        before_actor = dict(db.execute(
            "SELECT * FROM actors WHERE id=?", (actor_id,)).fetchone())
        before_page = dict(db.execute(
            "SELECT * FROM onion_urls WHERE url=?", (SOURCE_URL,)).fetchone())

    run_id = storage.record_deep_discovery_provider_run(
        "openpgp_exact", "pgp_fingerprint", FINGERPRINT,
        status="complete", idempotency_key="no-state-mutation")
    storage.upsert_deep_discovery_provider_evidence(run_id, [{
        "identifier_type": "pgp_fingerprint",
        "identifier_value": FINGERPRINT,
        "evidence_type": "exact_key_record",
        "provenance_type": "openpgp",
        "confidence": 1.0,
        "support_codes": ["exact-fingerprint"],
    }])

    with storage.get_db() as db:
        after_actor = dict(db.execute(
            "SELECT * FROM actors WHERE id=?", (actor_id,)).fetchone())
        after_page = dict(db.execute(
            "SELECT * FROM onion_urls WHERE url=?", (SOURCE_URL,)).fetchone())
    assert after_actor == before_actor
    assert after_page == before_page


def test_real_page_ingestion_emits_only_same_container_exact_provider_pivots(
    isolated_db,
):
    """The parser/indicator/actor path must preserve the structural boundary."""
    url = f"http://{HOST}/viewtopic.php?t=77"
    inside_domain = "identity.example.org"
    outside_domain = "unrelated.example.net"
    html = f"""
    <html><head><title>Public forum thread</title></head><body>
      <div class="post has-profile">
        <dl class="postprofile">
          <dt>
            <a class="username"
               href="/memberlist.php?mode=viewprofile&amp;u=77">ExactPivot77</a>
          </dt>
          <dd>PGP fingerprint: {FINGERPRINT}</dd>
          <dd>Official website:
            <a href="https://{inside_domain}/profile/exactpivot77">public profile</a>
          </dd>
        </dl>
        <div class="postbody">A normal public discussion post.</div>
      </div>
      <footer>
        Resources: <a href="https://{outside_domain}/directory">unrelated directory</a>
      </footer>
    </body></html>
    """
    _title, _meta, visible_text, link_records, page_structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    actor_evidence = page_structure["actor_evidence"]
    assert len(actor_evidence) == 1
    assert actor_evidence[0]["normalized_alias"] == "exactpivot77"
    assert {item["type"] for item in actor_evidence[0]["bound_identifiers"]} == {
        "pgp_fingerprint", "clearnet_url"
    }

    policy = {
        "primary_category": "forum_social",
        "content_category": "forum_social",
        "page_type": "thread_page",
        "site_type": "forum",
        "storage_policy": "safe_summary",
        "queue_policy": "normal",
        "safety_state": "safe",
        "risk_level": "low",
        "review_status": "monitor",
        "spain_priority": False,
        "destination_html_evidence_version": DESTINATION_HTML_EVIDENCE_VERSION,
        "classification_evidence_source": "destination_html",
    }
    storage.insert_or_update_onion_url(
        url, HOST, status="classification_pending")
    storage.apply_onion_policy(
        url, policy, 200, checked=True, page_structure=page_structure)

    links = [str(record["url"]) for record in link_records]
    indicators = extract_indicators(visible_text, links)
    for indicator in indicators:
        indicator_id = storage.upsert_indicator(
            indicator["type"], indicator["value"],
            indicator["normalized_value"], "onion_page", url,
            float(indicator["confidence"]), [])
        storage.link_indicator(
            indicator_id, "onion_page", url, indicator.get("context"))

    outcome = actor_intelligence.process_page_actor_intelligence(
        url, visible_text=visible_text, links=links,
        link_records=link_records, policy=policy,
        page_structure=page_structure)
    assert outcome["actors"] == 1
    actor = next(
        item for item in storage.get_public_actors()
        if item["normalized_alias"] == "exactpivot77")

    # The unrelated URL was genuinely observed by the normal page-level
    # indicator path, so its exclusion below proves actor-container scoping.
    with storage.get_db() as db:
        page_domains = {
            row["normalized_value"] for row in db.execute(
                """SELECT normalized_value FROM indicators
                   WHERE indicator_type='clearnet_url'""")
        }
    assert f"https://{inside_domain}/profile/exactpivot77" in page_domains
    assert f"https://{outside_domain}/directory" in page_domains

    pivots = storage.get_deep_discovery_provider_pivots(actor["id"])
    assert {(item["query_type"], item["query_value"]) for item in pivots} == {
        ("pgp_fingerprint", FINGERPRINT),
        ("clearnet_domain", inside_domain),
    }
    assert outside_domain not in json.dumps(pivots, sort_keys=True)
