"""Deterministic hostile-input coverage for Entity Intelligence.

This fixture is a regression corpus, not a statistical validation dataset.
"""
from __future__ import annotations

import json
from pathlib import Path

import entity_expansion
from entity_quality import evaluate_candidate, quality_summary


CORPUS = Path(__file__).with_name("fixtures") / "entity_intelligence_hostile_corpus.json"
HOST = "a" * 56 + ".onion"


def _load() -> dict:
    return json.loads(CORPUS.read_text(encoding="utf-8"))


def test_hostile_alias_corpus_has_fixed_explainable_outcomes():
    corpus = _load()
    results = []
    for case in corpus["alias_cases"]:
        result = evaluate_candidate(case["candidate"])
        results.append(result)
        assert result["state"] == case["expected_state"], case["id"]
        assert case["expected_reason"] in result["reason_codes"], case["id"]
        assert result["automatic_merge_allowed"] is False

    summary = quality_summary(results)
    assert summary["total"] == 12
    assert summary["states"] == {
        "accepted_observation": 2,
        "analyst_review_candidate": 2,
        "rejected_noise": 8,
    }
    assert "aliases" not in summary


def test_hostile_expansion_corpus_is_bounded_deduplicated_and_policy_safe():
    corpus = _load()
    source = {
        "url": f"http://{HOST}/",
        "verification_state": "verified",
        "classification_evidence_source": "destination_html",
        "destination_html_evidence_version": 1,
        "storage_policy": "safe_summary",
        "queue_policy": "allowed",
        "active": 1,
    }
    plan = entity_expansion.plan_entity_expansion(
        source, corpus["expansion_records"])
    expected = corpus["expected_expansion"]

    assert [item["role"] for item in plan["proposals"]] == expected["proposed_roles"]
    assert plan["rejections"] == {
        "CHILD_POLICY_BLOCKED": expected["child_policy_blocked"],
        "CROSS_HOST": expected["cross_host"],
        "DUPLICATE_RESOURCE": expected["duplicate_resources"],
        "FETCH_POLICY_BLOCKED": expected["fetch_policy_blocked"],
        "NON_GET_ROUTE": expected["non_get"],
        "ROUTE_BLOCKED": expected["blocked_routes"],
        "SESSION_OR_TRACKING_BLOCKED": expected["tracking_variants"],
    }
    assert plan["proposed"] <= plan["caps"]["per_host"] <= 10
    assert plan["proposal_only"] is True
    assert plan["network_performed"] is False
    assert plan["enqueued"] is False
