from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import sqlite3
import threading
import uuid

import deep_discovery
import deep_discovery_worker
import storage


def _actor(alias: str = "BoundedExample") -> int:
    now = storage.utc_now_iso()
    normalized = alias.casefold()
    token = uuid.uuid4().hex
    host = (token + token)[:56] + ".onion"
    with storage.get_db() as db:
        db.execute("""INSERT INTO actors
          (normalized_alias,display_alias,onion_host,first_seen,last_seen,
           observation_count,confidence_score,confidence_label,identity_key)
          VALUES(?,?,?,?,?,?,?,?,?)""",
          (normalized, alias, host, now, now, 1, 0.95, "high",
           f"test:{normalized}:{host}"))
        return int(db.execute("SELECT last_insert_rowid()").fetchone()[0])


def _job(actor_id: int, marker: str = "v1") -> int:
    return int(storage.create_deep_discovery_job(
        actor_id, 0, 0.95, "test anchor",
        {"schema": "arachne.deep_discovery.anchor.v1", "actor_id": actor_id,
         "site_card_id": 0, "marker": marker},
    ))


def test_parallel_workers_cannot_claim_the_same_discovery_job(isolated_db):
    job_id = _job(_actor())
    barrier = threading.Barrier(2)

    def claim(worker_id):
        barrier.wait(timeout=5)
        return storage.claim_next_deep_discovery_job(worker_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        rows = list(pool.map(claim, ("deep:a", "deep:b")))

    claimed = [row for row in rows if row]
    assert len(claimed) == 1
    assert int(claimed[0]["id"]) == job_id


def test_parallel_creators_get_one_discovery_job(isolated_db):
    actor_id = _actor()
    barrier = threading.Barrier(2)

    def create(_worker):
        barrier.wait(timeout=5)
        return _job(actor_id, "same-anchor")

    with ThreadPoolExecutor(max_workers=2) as pool:
        ids = list(pool.map(create, ("a", "b")))

    assert ids[0] == ids[1]
    assert len(storage.get_deep_discovery_jobs(actor_id=actor_id)) == 1


def test_stale_discovery_claim_is_recovered_after_timeout(isolated_db):
    job_id = _job(_actor())
    first = storage.claim_next_deep_discovery_job("deep:old")
    assert int(first["id"]) == job_id
    stale = (datetime.now(timezone.utc) - timedelta(minutes=60)).isoformat().replace("+00:00", "Z")
    with storage.get_db() as db:
        db.execute("UPDATE deep_discovery_jobs SET claimed_at=? WHERE id=?", (stale, job_id))

    recovered = storage.claim_next_deep_discovery_job(
        "deep:new", claim_timeout_minutes=5)
    assert int(recovered["id"]) == job_id
    assert recovered["claimed_by"] == "deep:new"


def test_local_worker_persists_run_without_network_provider(isolated_db):
    actor_id = _actor()
    job_id = _job(actor_id)

    assert deep_discovery_worker.process_one("deep:test") is True

    job = storage.get_deep_discovery_jobs(actor_id=actor_id)[0]
    assert job["status"] == "done"
    runs = storage.get_deep_discovery_runs(job_id=job_id)
    assert len(runs) == 1
    assert runs[0]["run_status"] == "local_complete"
    local = json.loads(runs[0]["local_results_json"])
    providers = json.loads(runs[0]["provider_status_json"])
    assert local["network_used"] is False
    assert providers["network_enabled"] is False
    assert providers["enabled_providers"] == ["local_arachne"]


def test_strict_actor_gate_runs_exact_provider_and_persists_advisory_evidence(
    isolated_db, monkeypatch
):
    actor_id = _actor()
    job_id = _job(actor_id)
    fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
    eligibility = deep_discovery.DeepDiscoveryEligibility(
        actor_id=actor_id, site_card_id=0, score=0.95, auto_queue=True,
        confirmed_profile=True, strong_pivots=["pgp_fingerprint"],
        weak_pivots=[], reasons=["confirmed_profile", "strong_public_pivot"],
        blockers=[],
    )
    monkeypatch.setattr(
        deep_discovery_worker.deep_discovery, "score_actor_detail",
        lambda _detail: eligibility,
    )
    monkeypatch.setattr(
        deep_discovery_worker.deep_discovery_providers, "provider_status",
        lambda: {
            "network_enabled": True,
            "enabled_providers": ["local_arachne", "openpgp_exact"],
            "disabled_providers": [
                "rdap_exact_domain", "certificate_transparency_exact"],
            "transport": "tor_socks5h_exact_get_only",
        },
    )
    monkeypatch.setattr(
        deep_discovery_worker.storage, "get_deep_discovery_provider_pivots",
        lambda _actor_id, limit=8: [{
            "query_type": "pgp_fingerprint",
            "query_value": fingerprint,
            "identifier_type": "pgp_fingerprint",
            "confidence": 0.98,
            "source_hash": "sha256:" + "1" * 64,
            "binding_method": "same_structural_container",
        }],
    )
    monkeypatch.setattr(
        deep_discovery_worker.deep_discovery_providers,
        "lookup_openpgp_fingerprint",
        lambda *_args, **_kwargs: {
            "provider": "openpgp_exact",
            "status": "complete",
            "result_count": 1,
            "results": [{
                "candidate_id": "pgp:exact-test",
                "display_name": "Exact OpenPGP fingerprint",
                "provider": "openpgp_exact",
                "matching_pivots": ["pgp_fingerprint"],
                "supporting": [{
                    "type": "exact_openpgp_fingerprint",
                    "label": "Exact public-key lookup returned a public key",
                }],
                "contradicting": [],
            }],
            "cached": False,
            "network_used": True,
            "error_code": None,
        },
    )

    assert deep_discovery_worker.process_one("deep:provider-test") is True

    runs = storage.get_deep_discovery_runs(job_id=job_id)
    assert runs[0]["run_status"] == "provider_complete"
    provider_runs = storage.get_deep_discovery_provider_runs(job_id=job_id)
    assert len(provider_runs) == 1
    assert fingerprint not in json.dumps(provider_runs)
    evidence = storage.get_deep_discovery_provider_evidence(provider_runs[0]["id"])
    assert evidence[0]["identifier_type"] == "pgp_fingerprint"
    assert evidence[0]["public_identifier"] == fingerprint


def test_network_provider_never_runs_below_strict_actor_gate(
    isolated_db, monkeypatch
):
    actor_id = _actor()
    job_id = _job(actor_id)
    ineligible = deep_discovery.DeepDiscoveryEligibility(
        actor_id=actor_id, site_card_id=0, score=0.89, auto_queue=False,
        confirmed_profile=True, strong_pivots=["pgp_fingerprint"],
        weak_pivots=[], reasons=[], blockers=["below_threshold"],
    )
    monkeypatch.setattr(
        deep_discovery_worker.deep_discovery, "score_actor_detail",
        lambda _detail: ineligible,
    )
    monkeypatch.setattr(
        deep_discovery_worker.deep_discovery_providers, "provider_status",
        lambda: {
            "network_enabled": True,
            "enabled_providers": ["local_arachne", "openpgp_exact"],
            "disabled_providers": [],
        },
    )
    monkeypatch.setattr(
        deep_discovery_worker, "_run_public_providers",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("provider network must remain gated")),
    )

    assert deep_discovery_worker.process_one("deep:below-gate") is True
    runs = storage.get_deep_discovery_runs(job_id=job_id)
    assert runs[0]["run_status"] == "local_complete"
    state = json.loads(runs[0]["provider_status_json"])
    assert state["reason"] == "actor_below_strict_network_gate"


def test_unchanged_anchor_does_not_requeue_but_changed_anchor_does(isolated_db):
    actor_id = _actor()
    job_id = _job(actor_id, "v1")
    assert deep_discovery_worker.process_one("deep:test") is True

    assert _job(actor_id, "v1") == job_id
    assert storage.get_deep_discovery_jobs(actor_id=actor_id)[0]["status"] == "done"

    assert _job(actor_id, "v2") == job_id
    changed = storage.get_deep_discovery_jobs(actor_id=actor_id)[0]
    assert changed["status"] == "queued"
    assert int(changed["anchor_revision"]) == 2


def test_changed_anchor_during_claim_is_promoted_after_success(isolated_db):
    actor_id = _actor()
    job_id = _job(actor_id, "v1")
    assert storage.claim_next_deep_discovery_job("deep:v1")["id"] == job_id
    assert _job(actor_id, "v2") == job_id

    assert storage.finish_deep_discovery_job(job_id, "deep:v1") is not None
    job = storage.get_deep_discovery_jobs(actor_id=actor_id)[0]
    assert job["status"] == "queued"
    assert json.loads(job["anchor_snapshot_json"])["marker"] == "v2"
    assert int(job["anchor_revision"]) == 2


def test_changed_anchor_is_not_stranded_when_old_revision_dead_letters(isolated_db):
    actor_id = _actor()
    job_id = _job(actor_id, "v1")
    assert storage.claim_next_deep_discovery_job("deep:old")["id"] == job_id
    _job(actor_id, "v2")

    assert storage.fail_deep_discovery_job(
        job_id, "deep:old", "ValueError", retry=True)
    with storage.get_db() as db:
        db.execute(
            "UPDATE deep_discovery_jobs SET next_retry_at=? WHERE id=?",
            ("2000-01-01T00:00:00Z", job_id),
        )
    assert storage.claim_next_deep_discovery_job("deep:old-2")["id"] == job_id
    assert storage.fail_deep_discovery_job(
        job_id, "deep:old-2", "ValueError", retry=True)

    job = storage.get_deep_discovery_jobs(actor_id=actor_id)[0]
    assert job["status"] == "queued"
    assert int(job["anchor_revision"]) == 2
    assert json.loads(job["anchor_snapshot_json"])["marker"] == "v2"
    runs = storage.get_deep_discovery_runs(job_id=job_id)
    assert runs[0]["run_status"] == "dead_letter"


def test_local_alias_candidates_are_exact_not_substring_matches(isolated_db):
    anchor_id = _actor("ExactAlias")
    exact_id = _actor("ExactAlias")
    _actor("ExactAliasMarket")
    detail = storage.get_actor_detail(anchor_id)

    local = deep_discovery.local_first_candidates(detail)

    assert [int(item["actor_id"]) for item in local["same_alias_candidates"]] == [exact_id]


def test_rejected_actor_connection_never_strengthens_candidate(isolated_db):
    actor_id = _actor("AnchorAlias")
    other_id = _actor("OtherAlias")
    now = storage.utc_now_iso()
    with storage.get_db() as db:
        db.execute("""INSERT INTO actor_connections
          (source_actor_id,target_actor_id,confidence_score,
           confidence_label,evidence_json,analyst_decision,first_seen,last_seen)
          VALUES(?,?,?,?,?,?,?,?)""",
          (actor_id, other_id, 0.9, "high", "{}",
           "not_same", now, now))

    local = deep_discovery.local_first_candidates(storage.get_actor_detail(actor_id))
    assert local["connections"] == []
    clusters = deep_discovery.build_candidate_clusters(
        {"actor_id": actor_id}, local,
        [{"candidate_id": "candidate", "matching_pivots": ["handle"]}],
    )
    assert clusters[0]["score"] == 0.38


def test_explicit_site_card_is_identical_in_job_and_anchor(monkeypatch):
    detail = {"actor": {"id": 7, "display_alias": "Example"},
              "observations": [], "identifiers": []}
    eligibility = deep_discovery.DeepDiscoveryEligibility(
        actor_id=7, site_card_id=11, score=0.95, auto_queue=True,
        confirmed_profile=True, strong_pivots=["pgp"], weak_pivots=[],
        reasons=["test"], blockers=[])
    captured = {}
    monkeypatch.setattr(deep_discovery.storage, "get_actor_detail", lambda _actor_id: detail)
    monkeypatch.setattr(deep_discovery, "score_actor_detail", lambda _detail: eligibility)

    def create(actor_id, site_card_id, score, reason, anchor, **_kwargs):
        captured.update(actor_id=actor_id, site_card_id=site_card_id, anchor=anchor)
        return 123

    monkeypatch.setattr(deep_discovery.storage, "create_deep_discovery_job", create)
    result = deep_discovery.maybe_queue_actor(7, site_card_id=99)

    assert result["queued_job_id"] == 123
    assert captured["site_card_id"] == 99
    assert captured["anchor"]["site_card_id"] == 99


def test_worker_loop_recovers_preclaim_database_error(monkeypatch):
    events = []
    monkeypatch.setattr(
        deep_discovery_worker, "process_one",
        lambda _worker_id: (_ for _ in ()).throw(sqlite3.OperationalError("busy")),
    )
    monkeypatch.setattr(
        deep_discovery_worker.storage, "heartbeat_worker_instance",
        lambda *_args, **kwargs: events.append(kwargs.get("last_error") or "heartbeat"),
    )
    monkeypatch.setattr(deep_discovery_worker, "STOP_REQUESTED", False)

    deep_discovery_worker._worker_loop(1, once=True)

    assert "OperationalError" in events
