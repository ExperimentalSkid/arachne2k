from __future__ import annotations

import json

import onion_worker
import storage


HOST = "x" * 56 + ".onion"
OTHER_HOST = "y" * 56 + ".onion"
PARENT = f"http://{HOST}/"
CHILD = f"http://{HOST}/about"


def _verified_parent() -> int:
    url_id = storage.insert_or_update_onion_url(PARENT, HOST, status="crawled")
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET verification_state='verified',
          verification_reason='page_fetched_and_classified',
          classification_evidence_source='destination_html',
          destination_html_evidence_version=1,storage_policy='safe_summary',
          queue_policy='normal',review_status='monitor',active=1,depth=2 WHERE id=?""",
          (url_id,))
    return url_id


def _proposal_plan() -> dict:
    return {
        "proposal_only": True, "network_performed": False,
        "caps": {"per_host": 10, "per_resource": 1},
        "proposals": [{
            "url": CHILD, "role": "about",
            "resource_identity": f"route:{HOST}:about",
            "reason_code": "PUBLIC_ABOUT_ROUTE",
        }],
    }


def _stored_proposal() -> int:
    _verified_parent()
    ids = storage.persist_entity_expansion_plan(
        PARENT, _proposal_plan(), parent_evidence_type="verified_public_page")
    assert len(ids) == 1
    assert storage.get_onion_url_by_url(CHILD) is None
    return ids[0]


def test_explicit_approval_revalidates_and_binds_proposal_to_frontier_row(isolated_db):
    proposal_id = _stored_proposal()

    assert storage.decide_entity_expansion_proposal(
        proposal_id, "approve", analyst_id="reviewer", reason="public about route")

    child = storage.get_onion_url_by_url(CHILD)
    assert child is not None
    assert child["status"] == "queued"
    assert child["source_type"] == "entity_expansion_analyst"
    assert child["depth"] == 3
    with storage.get_db() as db:
        proposal = dict(db.execute("""SELECT status,decision_mode,result_code,
          enqueued_onion_url_id FROM entity_expansion_proposals WHERE id=?""",
          (proposal_id,)).fetchone())
    assert proposal == {
        "status": "enqueued", "decision_mode": "analyst",
        "result_code": "QUEUED_AFTER_ANALYST_APPROVAL",
        "enqueued_onion_url_id": child["id"],
    }


def test_approval_fails_closed_when_verified_parent_policy_changed(isolated_db):
    proposal_id = _stored_proposal()
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET storage_policy='discard',queue_policy='blocked',
          review_status='filtered',active=0 WHERE url=?""", (PARENT,))

    assert storage.decide_entity_expansion_proposal(proposal_id, "approve")

    assert storage.get_onion_url_by_url(CHILD) is None
    with storage.get_db() as db:
        proposal = dict(db.execute("""SELECT status,result_code,result_safe_metadata_json,
          completed_at FROM entity_expansion_proposals WHERE id=?""",
          (proposal_id,)).fetchone())
    assert proposal["status"] == "completed"
    assert proposal["result_code"] == "APPROVAL_SAFETY_BLOCKED"
    assert json.loads(proposal["result_safe_metadata_json"])["reason_code"] == "SOURCE_POLICY_BLOCKED"
    assert proposal["completed_at"]


def test_terminal_outcome_is_idempotent_and_never_persists_raw_content(isolated_db):
    proposal_id = _stored_proposal()
    assert storage.decide_entity_expansion_proposal(proposal_id, "approve")
    child = storage.get_onion_url_by_url(CHILD)

    changed = storage.complete_entity_expansion_for_url(
        child["id"], "DESTINATION_USEFUL_VERIFIED",
        safe_metadata={
            "verified": True, "card_ready": True, "indicator_count": 2,
            "page_type": "about_page", "raw_page_text": "must-not-persist",
            "identifier": "must-not-persist",
        })
    assert changed == 1
    assert storage.complete_entity_expansion_for_url(
        child["id"], "DESTINATION_USEFUL_VERIFIED") == 0

    with storage.get_db() as db:
        proposal = dict(db.execute("""SELECT status,result_code,result_safe_metadata_json,
          completed_at FROM entity_expansion_proposals WHERE id=?""",
          (proposal_id,)).fetchone())
    assert proposal["status"] == "completed"
    assert proposal["result_code"] == "DESTINATION_USEFUL_VERIFIED"
    metadata = json.loads(proposal["result_safe_metadata_json"])
    assert metadata == {
        "card_ready": True, "indicator_count": 2,
        "page_type": "about_page", "verified": True,
    }
    assert "must-not-persist" not in proposal["result_safe_metadata_json"]
    assert proposal["completed_at"]

    metrics = storage.get_entity_expansion_metrics()
    assert metrics["accepted"] == 1
    assert metrics["completed"] == 1
    assert metrics["useful"] == 1
    assert metrics["no_yield"] == 0
    assert metrics["completion_rate"] == 1.0
    assert metrics["useful_rate"] == 1.0


def test_duplicate_destination_is_reason_coded_without_raw_fingerprint(isolated_db):
    proposal_id = _stored_proposal()
    assert storage.decide_entity_expansion_proposal(proposal_id, "approve")
    child = storage.get_onion_url_by_url(CHILD)
    content_hash = "a" * 64
    other_url = f"http://{OTHER_HOST}/"
    other_id = storage.insert_or_update_onion_url(other_url, OTHER_HOST, status="crawled")
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET content_hash=?,verification_state='verified'
          WHERE id IN (?,?)""", (content_hash, other_id, child["id"]))

    assert storage.complete_entity_expansion_for_url(
        child["id"], "DESTINATION_VERIFIED_NO_YIELD",
        safe_metadata={"verified": True}, content_hash=content_hash) == 1

    with storage.get_db() as db:
        row = dict(db.execute("""SELECT result_code,result_safe_metadata_json
          FROM entity_expansion_proposals WHERE id=?""", (proposal_id,)).fetchone())
    assert row["result_code"] == "DESTINATION_VERIFIED_DUPLICATE"
    assert json.loads(row["result_safe_metadata_json"]) == {
        "duplicate": True, "verified": True,
    }
    assert content_hash not in row["result_safe_metadata_json"]
    metrics = storage.get_entity_expansion_metrics()
    assert metrics["duplicate"] == 1
    assert metrics["useful"] == 0


def test_rejected_proposal_never_enters_frontier_or_accepted_metrics(isolated_db):
    proposal_id = _stored_proposal()
    assert storage.decide_entity_expansion_proposal(proposal_id, "reject", reason="not useful")
    assert storage.decide_entity_expansion_proposal(proposal_id, "approve") is False
    assert storage.get_onion_url_by_url(CHILD) is None
    metrics = storage.get_entity_expansion_metrics()
    assert metrics["statuses"]["rejected"] == 1
    assert metrics["accepted"] == 0
    assert metrics["completed"] == 0


def test_legacy_approved_proposal_is_revalidated_and_cannot_remain_stranded(isolated_db):
    proposal_id = _stored_proposal()
    with storage.get_db() as db:
        db.execute("""UPDATE entity_expansion_proposals SET status='approved',
          decision_mode='analyst',decided_at=? WHERE id=?""",
          (storage.utc_now_iso(), proposal_id))

    assert storage.decide_entity_expansion_proposal(proposal_id, "approve")
    child = storage.get_onion_url_by_url(CHILD)
    assert child is not None
    with storage.get_db() as db:
        proposal = dict(db.execute("""SELECT status,enqueued_onion_url_id
          FROM entity_expansion_proposals WHERE id=?""", (proposal_id,)).fetchone())
    assert proposal == {"status": "enqueued", "enqueued_onion_url_id": child["id"]}


def _prepare_no_yield_verification(monkeypatch, actor_handler=None) -> tuple[int, int]:
    proposal_id = _stored_proposal()
    assert storage.decide_entity_expansion_proposal(proposal_id, "approve")
    child = storage.get_onion_url_by_url(CHILD)
    html = b"<html><head><title>About</title></head><body><p>Ordinary public information.</p></body></html>"
    title, meta, visible, links, structure = onion_worker._parse(html, "text/html", CHILD)
    snapshot_id = storage.store_fetched_page_snapshot(
        child["id"], CHILD, worker_id="fetch-test", response_status=200,
        content_type="text/html", headers={"Content-Type": "text/html"},
        title=title, meta_text=meta, visible_text=visible, link_records=links,
        page_structure=structure, pre_policy={})
    policy = {
        "primary_category": "unknown", "category": "unknown",
        "content_category": "unknown", "tags": [], "risk_level": "low",
        "confidence": "low", "risk_flags": [], "storage_policy": "safe_summary",
        "review_status": "monitor", "safety_reason": "page_verified_no_yield",
        "priority_score": 0, "screenshot_policy": "blocked", "queue_policy": "normal",
        "active": 1, "spain_priority": False, "card_ready": 0,
        "page_type": "homepage",
    }
    monkeypatch.setattr(onion_worker, "_classify_fetched_page", lambda *a, **k: dict(policy))
    monkeypatch.setattr(onion_worker, "_mixed_link_directory", lambda *a, **k: False)
    monkeypatch.setattr(onion_worker, "classify_outbound_records", lambda *a, **k: (
        {"total": 0, "adult": 0, "severe": 0, "restricted": 0, "blocked": 0}, []))
    monkeypatch.setattr(onion_worker, "extract_page_identity", lambda *a, **k: {
        "display_name": "About", "detected_title": "About"})
    monkeypatch.setattr(onion_worker, "fingerprint_page_type", lambda *a, **k: {
        "page_type": "homepage", "page_type_confidence": "high", "evidence": []})
    monkeypatch.setattr(onion_worker, "calibrate_classification", lambda p, **k: p)
    monkeypatch.setattr(onion_worker, "finalize_page_policy", lambda _url, p, **k: p)
    monkeypatch.setattr(onion_worker, "assess_content_liveness", lambda *a, **k: {
        "fetch_status": "live", "liveness_status": "live",
        "content_quality": "meaningful", "reason": "ok"})
    monkeypatch.setattr(onion_worker, "apply_classification_contract", lambda p, *a, **k: p)
    monkeypatch.setattr(onion_worker, "compute_card_readiness", lambda *a, **k: {
        "card_ready": 0, "card_readiness_reason": "no_entity_yield"})
    monkeypatch.setattr(onion_worker, "classify_risk_flags", lambda *a, **k: [])
    monkeypatch.setattr(onion_worker, "extract_indicators", lambda *a, **k: [])
    monkeypatch.setattr(onion_worker, "extract_passive_exposures", lambda *a, **k: [])
    monkeypatch.setattr(onion_worker, "extract_page_topics", lambda *a, **k: {
        "topics": [], "keywords": []})
    monkeypatch.setattr(
        onion_worker, "process_page_actor_intelligence",
        actor_handler or (lambda *a, **k: {"actors": 0, "candidates": 0}),
    )
    return proposal_id, int(snapshot_id)


def test_verify_stage_closes_enqueued_proposal_as_no_yield(isolated_db, monkeypatch):
    proposal_id, _snapshot_id = _prepare_no_yield_verification(monkeypatch)

    assert onion_worker.verify_one("verify-expansion") is True

    with storage.get_db() as db:
        proposal = dict(db.execute("""SELECT status,result_code,result_safe_metadata_json
          FROM entity_expansion_proposals WHERE id=?""", (proposal_id,)).fetchone())
    assert proposal["status"] == "completed"
    assert proposal["result_code"] == "DESTINATION_VERIFIED_NO_YIELD"
    assert json.loads(proposal["result_safe_metadata_json"])["verified"] is True


def test_verify_stage_retries_when_required_downstream_work_fails_then_recovers(
        isolated_db, monkeypatch):
    def fail_actor_stage(*_args, **_kwargs):
        raise RuntimeError("actor_stage_failed")

    proposal_id, snapshot_id = _prepare_no_yield_verification(
        monkeypatch, actor_handler=fail_actor_stage)

    assert onion_worker.verify_one("verify-failure") is True

    with storage.get_db() as db:
        snapshot = dict(db.execute(
            "SELECT classification_status,attempts,claimed_by FROM fetched_pages WHERE id=?",
            (snapshot_id,),
        ).fetchone())
        proposal = dict(db.execute(
            "SELECT status,result_code FROM entity_expansion_proposals WHERE id=?",
            (proposal_id,),
        ).fetchone())
        db.execute(
            "UPDATE fetched_pages SET next_retry_at=NULL WHERE id=?",
            (snapshot_id,),
        )
    assert snapshot == {
        "classification_status": "retry",
        "attempts": 1,
        "claimed_by": None,
    }
    assert proposal["status"] == "enqueued"

    monkeypatch.setattr(
        onion_worker, "process_page_actor_intelligence",
        lambda *_args, **_kwargs: {"actors": 0, "candidates": 0},
    )
    assert onion_worker.verify_one("verify-recovery") is True

    with storage.get_db() as db:
        snapshot = dict(db.execute(
            "SELECT classification_status,attempts,claimed_by FROM fetched_pages WHERE id=?",
            (snapshot_id,),
        ).fetchone())
        proposal = dict(db.execute(
            "SELECT status,result_code FROM entity_expansion_proposals WHERE id=?",
            (proposal_id,),
        ).fetchone())
    assert snapshot == {
        "classification_status": "done",
        "attempts": 1,
        "claimed_by": None,
    }
    assert proposal == {
        "status": "completed",
        "result_code": "DESTINATION_VERIFIED_NO_YIELD",
    }
