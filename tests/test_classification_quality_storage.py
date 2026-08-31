import json

import pytest

import storage


HOST = "q" * 56 + ".onion"
URL = f"http://{HOST}/"


def _decision(isolated_db) -> tuple[int, int]:
    url_id = storage.insert_or_update_onion_url(URL, HOST, status="crawled")
    decision_id = storage.record_classification_decision(
        URL,
        {
            "primary_category": "forum_social",
            "suggested_category": "forum_social",
            "category_confidence": "high",
            "classification_confidence_score": 0.91,
            "classification_decision": "accepted",
            "classifier_version": "rules-page-v7",
            "category_reason": "Corroborated forum structure",
            "evidence_families": ["forum_structure", "http://do-not-store.onion/"],
        },
        stage="page",
        safe_metadata={
            "classification_evidence_source": "destination_html",
            "destination_evidence_trusted": True,
            "content_category": "forum_social",
            "page_type": "forum_index",
            "site_type": "forum",
            "risk_category": "unknown",
            "safety_state": "safe",
            "evidence_bucket_counts": {"heading": 2, "link_pattern": 3, "bogus": 99},
            "support_codes": ["forum markup", "http://do-not-store.onion/"],
            "contradiction_codes": ["generic text only"],
            "spain_evidence_score": 0,
            "urgent_score": 0,
            "urgent_flag": False,
            "raw_text": "never persist this",
        },
    )
    return url_id, decision_id


def test_quality_schema_and_indexes_are_additive_and_idempotent(isolated_db):
    storage.init_db()
    storage.init_db()
    with storage.get_db() as db:
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        indexes = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        )}
    assert {
        "classification_feedback_events",
        "classification_shadow_evaluations",
        "classification_quality_daily",
    } <= tables
    assert {
        "idx_classification_decisions_stage_ts",
        "idx_classification_feedback_created",
        "idx_classification_feedback_scope_action",
        "idx_classification_shadow_created",
        "idx_classification_shadow_version",
        "idx_classification_quality_daily_generated",
    } <= indexes


def test_decision_snapshot_metadata_is_capped_and_never_keeps_raw_evidence(isolated_db):
    _url_id, decision_id = _decision(isolated_db)
    snapshots = storage.get_classification_decision_snapshots()
    assert snapshots[0]["id"] == decision_id
    assert "url" not in snapshots[0]
    encoded = json.dumps(snapshots[0])
    assert URL not in encoded
    assert "do-not-store.onion" not in encoded
    assert "never persist this" not in encoded
    metadata = json.loads(snapshots[0]["safe_metadata_json"])
    assert metadata["classification_evidence_source"] == "destination_html"
    assert metadata["destination_evidence_trusted"] is True
    assert metadata["evidence_bucket_counts"] == {"heading": 2, "link_pattern": 3}
    assert metadata["support_codes"] == ["forum_markup"]
    assert metadata["contradiction_codes"] == ["generic_text_only"]
    assert json.loads(snapshots[0]["evidence_families_json"]) == ["forum_structure"]


def test_feedback_is_append_only_hashed_and_foreign_keys_set_null(isolated_db):
    url_id, decision_id = _decision(isolated_db)
    first = storage.record_classification_feedback(
        subject=URL,
        feedback_scope="category",
        feedback_action="category_corrected",
        reason_code="analyst_category_correction",
        decision_id=decision_id,
        previous_category="forum_social",
        final_category="directory_index",
        safe_metadata={"source_stage": "page", "url_count": 1, "raw_text": URL},
    )
    second = storage.record_classification_feedback(
        subject=URL,
        feedback_scope="category",
        feedback_action="category_confirmed",
        reason_code="analyst_confirmation",
        decision_id=decision_id,
        previous_category="forum_social",
        final_category="forum_social",
    )
    events = storage.get_classification_feedback_events()
    assert {row["id"] for row in events} == {first, second}
    assert len({row["subject_hash"] for row in events}) == 1
    assert all(URL not in json.dumps(row) for row in events)
    assert json.loads(next(row for row in events if row["id"] == first)["safe_metadata_json"]) == {
        "source_stage": "page", "url_count": 1,
    }

    with storage.get_db() as db:
        db.execute("DELETE FROM classification_decisions WHERE id=?", (decision_id,))
        assert db.execute(
            "SELECT COUNT(*) FROM classification_feedback_events WHERE decision_id IS NULL"
        ).fetchone()[0] == 2
        db.execute("DELETE FROM onion_url_sources WHERE onion_url_id=?", (url_id,))
        db.execute("DELETE FROM onion_urls WHERE id=?", (url_id,))
        assert db.execute(
            "SELECT COUNT(*) FROM classification_feedback_events WHERE onion_url_id IS NULL"
        ).fetchone()[0] == 2


def test_feedback_rejects_unknown_actions_and_per_item_severe_history(isolated_db):
    _url_id, decision_id = _decision(isolated_db)
    with pytest.raises(ValueError):
        storage.record_classification_feedback(
            subject=URL, feedback_scope="category", feedback_action="invented",
            reason_code="invalid", decision_id=decision_id,
        )
    with pytest.raises(ValueError):
        storage.record_classification_feedback(
            subject=URL, feedback_scope="category",
            feedback_action="category_corrected", reason_code="analyst_correction",
            decision_id=decision_id, final_category="severe_abuse_risk",
        )


def test_shadow_evaluations_are_bounded_idempotent_and_advisory(isolated_db):
    _url_id, decision_id = _decision(isolated_db)
    assert storage.upsert_classification_shadow_evaluations([{
        "decision_id": decision_id,
        "subject": URL,
        "proposed_category": "directory_index",
        "confidence_score": 0.72,
        "decision_code": "would_correct",
        "reason_codes": ["link pattern", URL],
        "would_change": True,
    }], "shadow-rules-v1") == 1
    assert storage.upsert_classification_shadow_evaluations([{
        "decision_id": decision_id,
        "subject": URL,
        "proposed_category": "forum_social",
        "confidence_score": 0.95,
        "decision_code": "would_confirm",
        "reason_codes": ["forum structure"],
        "would_change": False,
    }], "shadow-rules-v1") == 1
    rows = storage.get_classification_shadow_evaluations(
        evaluator_version="shadow-rules-v1")
    assert len(rows) == 1
    assert rows[0]["proposed_category"] == "forum_social"
    assert rows[0]["would_change"] == 0
    assert json.loads(rows[0]["reason_codes_json"]) == ["forum_structure"]
    assert URL not in json.dumps(rows[0])
    with storage.get_db() as db:
        persisted = db.execute(
            "SELECT primary_category FROM onion_urls WHERE id=(SELECT onion_url_id "
            "FROM classification_decisions WHERE id=?)", (decision_id,)
        ).fetchone()[0]
    assert persisted in {None, "unknown"}


def test_shadow_rejects_missing_decision_and_severe_proposal(isolated_db):
    with pytest.raises(ValueError):
        storage.upsert_classification_shadow_evaluations([{
            "decision_id": 999999, "proposed_category": "forum_social",
            "decision_code": "would_confirm",
        }], "shadow-rules-v1")
    _url_id, decision_id = _decision(isolated_db)
    with pytest.raises(ValueError):
        storage.upsert_classification_shadow_evaluations([{
            "decision_id": decision_id, "proposed_category": "severe_abuse_risk",
            "decision_code": "would_change",
        }], "shadow-rules-v1")


def test_daily_quality_snapshots_are_sanitized_and_upserted(isolated_db):
    storage.store_classification_quality_daily(
        "2026-07-26", "rules-page-v7",
        {
            "verified_pages": 12,
            "unknown_rate": 0.25,
            "confusion": {"forum_social": {"directory_index": 2}},
            "top_reason_codes": ["weak_text_signal"],
        },
    )
    storage.store_classification_quality_daily(
        "2026-07-26", "rules-page-v7",
        {"verified_pages": 13, "unknown_rate": 0.2},
    )
    rows = storage.get_classification_quality_daily()
    assert len(rows) == 1
    assert json.loads(rows[0]["metrics_json"]) == {
        "unknown_rate": 0.2, "verified_pages": 13,
    }
    with pytest.raises(ValueError):
        storage.store_classification_quality_daily(
            "2026-07-26", "rules-page-v7",
            {"unsafe": URL},
        )
