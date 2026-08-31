from __future__ import annotations

import json

import onion_worker
import storage
from scripts import classification_quality_audit


HOST = "r" * 56 + ".onion"
URL = f"http://{HOST}/"


def test_decision_time_quality_metadata_contains_counts_not_evidence_text():
    metadata = onion_worker._classification_decision_metadata({
        "page_type": "forum_thread",
        "page_type_confidence": "high",
        "content_category": "forum_social",
        "safety_state": "safe",
        "category_evidence": {
            "heading": ["PRIVATE_MATCHED_HEADING"],
            "link_pattern": ["forum_markup", "thread_markup"],
        },
        "classification_evidence_source": "destination_html",
        "urgent_score": 12,
    }, "meaningful")
    encoded = json.dumps(metadata)
    assert "PRIVATE_MATCHED_HEADING" not in encoded
    assert metadata["destination_evidence_trusted"] is True
    assert metadata["evidence_bucket_counts"] == {"heading": 1, "link_pattern": 2}


def _record(url: str, *, stage: str = "page", final: str = "directory_index",
            decision: str = "accepted") -> tuple[int, int]:
    url_id = storage.insert_or_update_onion_url(url, HOST, status="crawled")
    decision_id = storage.record_classification_decision(
        url,
        {
            "primary_category": final,
            "suggested_category": final,
            "category_confidence": "high",
            "classification_confidence_score": 0.9,
            "classification_decision": decision,
            "classifier_version": "rules-page-report-test",
            "evidence_families": ["safe_structure"],
        },
        stage=stage,
        safe_metadata={
            "classification_evidence_source": (
                "destination_html" if stage == "page" else "unverified"
            ),
            "destination_evidence_trusted": stage == "page",
            "page_type": "directory_index_page",
            "content_quality": "meaningful",
            "evidence_bucket_counts": {"heading": 1, "link_pattern": 2},
        },
    )
    return url_id, decision_id


def test_quality_report_uses_latest_page_snapshot_and_explicit_feedback(isolated_db):
    url_id, first = _record(URL, final="marketplace", decision="accepted")
    _url_id, latest = _record(URL, final="unknown", decision="abstained")
    _record(URL, stage="prefetch", final="marketplace", decision="accepted")
    storage.record_classification_feedback(
        subject=f"site-card:none:url:{url_id}",
        feedback_scope="category", feedback_action="category_corrected",
        reason_code="analyst_category_correction",
        decision_id=latest, onion_url_id=url_id,
        previous_category="unknown", final_category="directory_index",
    )

    report = storage.get_classification_quality_report(days=30)

    assert first != latest
    assert report["page_decisions"] == 2
    assert report["unique_pages"] == 1
    assert report["accepted"] == 0
    assert report["unsure"] == 1
    assert report["unknown_rate"] == 1.0
    assert report["reviewed_count"] == 1
    assert report["category_corrections"] == 1
    assert report["correction_rate"] == 1.0
    assert report["correction_pairs"] == [{
        "previous_category": "unknown",
        "final_category": "directory_index",
        "count": 1,
    }]
    assert report["decision_mode"] == "advisory_only"
    assert URL not in json.dumps(report)


def test_quality_dimensions_use_honest_review_denominators(isolated_db):
    _url_id, decision_id = _record(URL)
    events = [
        ("spain", "spain_confirmed"),
        ("spain", "spain_removed"),
        ("urgency", "urgent_dismissed"),
        ("safety", "adult_false_positive"),
        ("mirror", "mirror_confirmed"),
        ("mirror", "mirror_not_same"),
        ("mirror", "mirror_ignored"),
    ]
    for index, (scope, action) in enumerate(events):
        storage.record_classification_feedback(
            subject=f"feedback:{index}",
            feedback_scope=scope, feedback_action=action,
            reason_code="analyst_review",
            decision_id=decision_id,
            previous_category="directory_index",
            final_category=(
                "adult_filtered" if scope == "safety" else "directory_index"
            ),
        )

    dimensions = storage.get_classification_quality_report()["feedback_by_dimension"]

    assert dimensions["spain"]["reviewed_count"] == 2
    assert dimensions["spain"]["confirmed"] == 1
    assert dimensions["spain"]["corrected"] == 1
    assert dimensions["urgency"]["reviewed_count"] == 1
    assert dimensions["restriction"]["corrected"] == 1
    assert dimensions["dedupe"]["reviewed_count"] == 2
    assert dimensions["dedupe"]["excluded"] == 1


def test_quality_report_is_read_only_for_operational_tables(isolated_db):
    _record(URL)
    protected = (
        "onion_urls", "site_cards", "site_card_jobs", "fetched_pages",
        "spain_hits", "spain_alert_queue", "page_preview_jobs",
        "possible_site_card_matches", "site_card_events",
    )
    with storage.get_db() as db:
        before = {table: int(db.execute(
            f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in protected}

    first = storage.get_classification_quality_report()
    second = storage.get_classification_quality_report()

    with storage.get_db() as db:
        after = {table: int(db.execute(
            f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in protected}
    assert before == after
    assert first == second


def test_quality_audit_cli_emits_only_sanitized_aggregate_json(isolated_db, capsys):
    _record(URL)
    assert classification_quality_audit.main(["--days", "30"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["decision_mode"] == "advisory_only"
    assert payload["unique_pages"] == 1
    assert URL not in json.dumps(payload)
