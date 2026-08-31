from __future__ import annotations

import inspect
import json

import classification_quality as quality


def _row(
    row_id: int,
    *,
    ts: str | None = None,
    stage: str = "page",
    url_id: int | None = 1,
    card_id: int | None = 10,
    proposed: str = "directory_index",
    final: str = "directory_index",
    decision: str = "accepted",
    analyst: bool = False,
    source: str | None = "destination_html",
    confidence: float = 0.88,
    metadata: dict | None = None,
    evidence: list | None = None,
    previous: str | None = None,
    **extra,
):
    value = {
        "id": row_id,
        "ts": ts or f"2026-07-26T00:00:{row_id:02d}+00:00",
        "url": f"http://{'a' * 56}.onion/private/{row_id}",
        "onion_url_id": url_id,
        "site_card_id": card_id,
        "stage": stage,
        "proposed_category": proposed,
        "final_category": final,
        "confidence_label": "high",
        "confidence_score": confidence,
        "decision": decision,
        "evidence_families_json": json.dumps(
            ["safe_structure"] if evidence is None else evidence),
        "reason": "raw page text and credentials must never be emitted",
        "classifier_version": "rules-page-test",
        "analyst_corrected": int(analyst),
        "previous_category": previous,
        "safe_metadata_json": json.dumps(metadata or {}),
    }
    if source is not None:
        value["classification_evidence_source"] = source
    value.update(extra)
    return value


def test_normalization_drops_raw_urls_text_and_identifiers():
    normalized = quality.normalize_ledger_row(_row(
        1,
        metadata={
            "page_type": "forum_thread",
            "content_quality": "meaningful",
            "trusted_destination_html": True,
            "evidence_bucket_counts": {"title": 1, "negative_contradicting": 2},
        },
        password="not-for-output",
        body="private body",
        title="private title",
    ))

    rendered = json.dumps(normalized, sort_keys=True)
    assert ".onion" not in rendered
    assert "private body" not in rendered
    assert "private title" not in rendered
    assert "not-for-output" not in rendered
    assert "raw page text" not in rendered
    assert "onion_url_id" not in normalized
    assert "site_card_id" not in normalized
    assert normalized["trusted_destination_html"] is True
    assert normalized["evidence_bucket_counts"]["title"] == 1
    assert normalized["evidence_bucket_counts"]["negative_contradicting"] == 2


def test_only_trusted_page_destination_html_decisions_are_predictions():
    rows = [
        _row(1),
        _row(2, stage="prefetch", source="unverified", decision="abstained"),
        _row(3, stage="outbound", source="unverified"),
        _row(4, stage="page", source="url_hint"),
        _row(5, stage="page", metadata={"trusted_destination_html": False}),
        _row(7, stage="page", metadata={"destination_evidence_trusted": False}),
        _row(6, stage="analyst", analyst=True, decision="analyst_confirmed"),
    ]

    selected = quality.select_page_predictions(rows)
    assert len(selected) == 1
    assert selected[0]["final_category"] == "directory_index"
    assert selected[0]["stage"] == "page"


def test_pairing_uses_nearest_preceding_url_prediction():
    rows = [
        _row(1, ts="2026-07-26T00:00:01Z", final="forum_social"),
        _row(2, ts="2026-07-26T00:00:02Z", final="directory_index"),
        _row(
            3,
            ts="2026-07-26T00:00:03Z",
            stage="analyst",
            analyst=True,
            decision="analyst_confirmed",
            final="hosting_services",
            previous="directory_index",
            source="analyst",
        ),
    ]

    pairs = quality.pair_analyst_corrections(rows)
    assert len(pairs) == 1
    assert pairs[0]["baseline_category"] == "directory_index"
    assert pairs[0]["analyst_category"] == "hosting_services"
    assert pairs[0]["changed"] is True


def test_card_fallback_is_used_only_when_correction_has_no_url_id():
    rows = [
        _row(1, url_id=1, card_id=50, final="forum_social"),
        _row(
            2,
            url_id=999,
            card_id=50,
            stage="analyst",
            analyst=True,
            decision="analyst_confirmed",
            final="directory_index",
            source="analyst",
        ),
        _row(
            3,
            url_id=None,
            card_id=50,
            stage="analyst",
            analyst=True,
            decision="analyst_confirmed",
            final="directory_index",
            source="analyst",
        ),
    ]

    pairs = quality.pair_analyst_corrections(rows)
    assert len(pairs) == 1
    assert pairs[0]["baseline_category"] == "forum_social"


def test_aggregate_rates_use_honest_denominators_and_group_unknown_reasons():
    rows = [
        _row(1, url_id=1, final="directory_index", decision="accepted"),
        _row(
            2,
            url_id=2,
            proposed="marketplace_fraud",
            final="unknown",
            decision="abstained",
            evidence=[],
            metadata={"content_quality": "thin"},
        ),
        _row(
            3,
            url_id=1,
            stage="analyst",
            analyst=True,
            source="analyst",
            decision="analyst_confirmed",
            previous="directory_index",
            final="forum_social",
        ),
        # These workflow events must not enter the prediction denominator.
        _row(4, stage="prefetch", source="unverified", decision="abstained"),
        _row(5, stage="outbound", source="unverified", decision="accepted"),
    ]

    report = quality.analyze_classification_quality(rows)
    assert report["prediction_event_count"] == 2
    assert report["prediction_count"] == 2
    assert report["reviewed_prediction_count"] == 1
    assert report["changed_after_review_count"] == 1
    assert report["accepted_rate"] == 0.5
    assert report["uncertain_rate"] == 0.5
    assert report["unknown_rate"] == 0.5
    assert report["observed_review_disagreement_rate"] == 1.0
    assert report["unknown_reason_groups"] == {"content_thin": 1}
    assert report["correction_pairs"] == [{
        "baseline_category": "directory_index",
        "analyst_category": "forum_social",
        "count": 1,
    }]


def test_repeated_crawls_count_as_events_but_latest_url_state_drives_snapshot_rates():
    rows = [
        _row(
            1,
            ts="2026-07-26T00:00:01Z",
            url_id=77,
            proposed="directory_index",
            final="directory_index",
            decision="accepted",
        ),
        _row(
            2,
            ts="2026-07-26T00:00:02Z",
            url_id=77,
            proposed="marketplace",
            final="unknown",
            decision="abstained",
        ),
        _row(
            3,
            ts="2026-07-26T00:00:03Z",
            url_id=77,
            stage="analyst",
            analyst=True,
            source="analyst",
            decision="analyst_confirmed",
            previous="unknown",
            final="hosting_services",
        ),
    ]

    report = quality.analyze_classification_quality(rows)
    assert report["prediction_event_count"] == 2
    assert report["prediction_count"] == 1
    assert report["decision_counts"] == {"abstained": 1}
    assert report["category_counts"] == {"unknown": 1}
    assert report["accepted_rate"] == 0.0
    assert report["uncertain_rate"] == 1.0
    assert report["unknown_rate"] == 1.0
    # Pairing intentionally remains event-based and chooses the nearest
    # preceding page decision rather than the first crawl.
    assert report["correction_pairs"] == [{
        "baseline_category": "unknown",
        "analyst_category": "hosting_services",
        "count": 1,
    }]


def test_shadow_observations_require_at_least_ten_repeated_samples():
    def correction_rows(count: int):
        result = []
        for index in range(1, count + 1):
            result.extend([
                _row(index * 2 - 1, url_id=index, final="marketplace"),
                _row(
                    index * 2,
                    url_id=index,
                    stage="analyst",
                    analyst=True,
                    source="analyst",
                    decision="analyst_confirmed",
                    previous="marketplace",
                    final="directory_index",
                ),
            ])
        return result

    assert quality.build_shadow_observations(
        correction_rows(9), minimum_sample=1) == []
    observations = quality.build_shadow_observations(
        correction_rows(10), minimum_sample=1)
    assert len(observations) == 1
    observation = observations[0]
    assert observation["observation_type"] == "repeated_correction_pattern"
    assert observation["sample_size"] == 10
    assert observation["baseline_category"] == "marketplace"
    assert observation["advisory_category"] == "directory_index"
    assert observation["decision_mode"] == "advisory_only"
    assert set(quality.LOCKED_PRODUCTION_DIMENSIONS) == set(
        observation["locked_dimensions"])


def test_repeated_unknown_pattern_is_advisory_and_has_no_category_proposal():
    rows = [
        _row(
            index,
            url_id=index,
            proposed="unknown",
            final="unknown",
            decision="abstained",
            evidence=[],
        )
        for index in range(1, 11)
    ]

    observations = quality.build_shadow_observations(rows)
    assert observations == [{
        "observation_type": "repeated_unknown_pattern",
        "baseline_category": "unknown",
        "advisory_category": None,
        "sample_size": 10,
        "reviewed_baseline_count": 0,
        "observed_share": 0.0,
        "confidence": "low",
        "reason_codes": ["insufficient_evidence", "more_evidence_needed"],
        "decision_mode": "advisory_only",
        "locked_dimensions": list(quality.LOCKED_PRODUCTION_DIMENSIONS),
    }]


def test_safety_categories_are_aggregate_only_and_never_create_observations():
    rows = []
    for index in range(1, 11):
        rows.extend([
            _row(
                index * 2 - 1,
                url_id=index,
                proposed="severe_abuse_risk",
                final="severe_abuse_risk",
                decision="restricted",
            ),
            _row(
                index * 2,
                url_id=index,
                stage="analyst",
                analyst=True,
                source="analyst",
                decision="analyst_confirmed",
                previous="severe_abuse_risk",
                final="unknown",
            ),
        ])

    report = quality.analyze_classification_quality(rows)
    rendered = json.dumps(report, sort_keys=True)
    assert report["prediction_count"] == 0
    assert report["safety_excluded_count"] == 10
    assert report["shadow_observations"] == []
    assert ".onion" not in rendered
    assert "safe_structure" not in rendered


def test_invalid_json_and_unknown_category_fail_closed():
    row = _row(
        1,
        proposed="DROP TABLE onion_urls",
        final="made_up_category",
        evidence=[],
    )
    row["safe_metadata_json"] = "{broken"
    row["evidence_families_json"] = "not-json"
    normalized = quality.normalize_ledger_row(row)
    assert normalized["proposed_category"] == "unknown"
    assert normalized["final_category"] == "unknown"
    assert normalized["evidence_family_count"] == 0
    assert sum(normalized["evidence_bucket_counts"].values()) == 0


def test_advisory_module_has_no_production_mutator_dependencies():
    source = inspect.getsource(quality)
    forbidden = (
        "import storage",
        "import site_dedupe",
        "import universal_classifier",
        "import onion_worker",
        "apply_onion_policy(",
        "apply_manual_category(",
        "update_site_card_rollups(",
        "queue_spain_alert(",
        "merge_site_cards(",
    )
    assert all(token not in source for token in forbidden)
