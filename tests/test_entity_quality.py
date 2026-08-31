import json

import pytest

from entity_quality import (
    CANDIDATE_STATES,
    REASON_CODES,
    RuleConfigError,
    evaluate_candidate,
    evaluate_candidates,
    load_noise_rules,
    normalize_alias,
    quality_summary,
    review_only_similarity,
)


def _strong_candidate(alias="NightFox77", **updates):
    candidate = {
        "accepted": True,
        "evidence_version": 2,
        "alias": alias,
        "role": "forum_member",
        "evidence_type": "phpbb_post_author",
        "confidence": 0.97,
        "evidence_strength": "strong",
        "source_scope": "post_author",
        "evidence_signals": ["profile_link", "anchor_slug_match"],
        "profile_identity": "query:u:17",
        "bound_identifiers": [{"type": "pgp_key_block"}],
    }
    candidate.update(updates)
    return candidate


def test_ruleset_is_versioned_and_supports_bounded_match_types():
    rules = load_noise_rules()

    assert rules["schema_version"] == 1
    assert rules["ruleset_version"] == "2026-07-16.1"
    assert {rule["match"] for rule in rules["rules"]} == {"exact", "prefix", "suffix"}
    assert all(rule["reason_code"] in REASON_CODES for rule in rules["rules"])


def test_current_structural_candidate_is_accepted_without_enabling_merge():
    result = evaluate_candidate(_strong_candidate())

    assert result["state"] == "accepted_observation"
    assert result["reason_codes"] == ["accepted_strong_structural"]
    assert result["profile_route_agreement"] == "matched"
    assert result["bound_identifier_types"] == ["pgp_key_block"]
    assert result["automatic_merge_allowed"] is False


def test_medium_structural_candidate_remains_review_only():
    result = evaluate_candidate(
        _strong_candidate(confidence=0.86, evidence_strength="medium")
    )

    assert result["state"] == "analyst_review_candidate"
    assert result["reason_codes"] == ["review_weak_evidence"]


def test_corroborated_flat_candidate_can_be_accepted_but_not_merged():
    result = evaluate_candidate({
        "alias": "NightFox77",
        "auto_store_eligible": True,
        "confidence": 0.93,
        "evidence_type": "cryptographically_corroborated_alias",
    })

    assert result["state"] == "accepted_observation"
    assert result["reason_codes"] == ["accepted_corroborated_flat"]
    assert result["automatic_merge_allowed"] is False


@pytest.mark.parametrize(
    ("candidate", "reason"),
    [
        ({"alias": "admin"}, "rejected_generic_role"),
        ({"alias": "gmail"}, "rejected_provider_word"),
        ({"alias": "payload.sql"}, "rejected_filename_like"),
        ({"alias": "417"}, "rejected_numeric_identifier"),
        ({"alias": "2026-07-16"}, "rejected_timestamp_like"),
        ({"alias": "user_123456"}, "rejected_generated_label"),
        ({"alias": "0123456789abcdef0123456789abcdef"}, "rejected_generated_label"),
        ({"alias": "NightFox77", "source_scope": "quoted_post"}, "rejected_blocked_context"),
        (
            {"alias": "NightFox77", "profile_url": "/u/17", "profile_route_agreement": False},
            "rejected_profile_route_mismatch",
        ),
        (
            {"alias": "NightFox77", "unrelated_host_count": 4, "template_repetition_count": 8},
            "rejected_template_boilerplate",
        ),
    ],
)
def test_hostile_noise_corpus_is_rejected(candidate, reason):
    result = evaluate_candidate(candidate)

    assert result["state"] == "rejected_noise"
    assert reason in result["reason_codes"]
    assert result["automatic_merge_allowed"] is False


def test_configured_generated_prefix_routes_to_review_not_acceptance():
    result = evaluate_candidate(_strong_candidate(alias="user_nightfox"))

    assert result["state"] == "analyst_review_candidate"
    assert "review_generated_prefix" in result["reason_codes"]


def test_mixed_script_confusable_is_review_only_and_never_an_identity_key():
    suspicious = "N\u0456ghtFox"
    result = evaluate_candidate(_strong_candidate(alias=suspicious))
    comparison = review_only_similarity(suspicious, "NightFox")

    assert normalize_alias(suspicious) != normalize_alias("NightFox")
    assert result["state"] == "analyst_review_candidate"
    assert {"review_mixed_script", "review_confusable_skeleton"}.issubset(result["reason_codes"])
    assert result["script_profile"]["mixed_script"] is True
    assert comparison["skeleton_match"] is True
    assert comparison["review_only"] is True
    assert comparison["merge_allowed"] is False
    assert comparison["method"] in {"rapidfuzz_optional", "stdlib_sequence_matcher"}


@pytest.mark.parametrize(
    ("decision", "state", "reason"),
    [
        ("confirmed", "analyst_confirmed_identity_evidence", "analyst_confirmed"),
        ("rejected", "analyst_rejected_identity_evidence", "analyst_rejected"),
        ("contradicted", "superseded_or_contradicted_observation", "contradicted_observation"),
        ("superseded", "superseded_or_contradicted_observation", "superseded_observation"),
    ],
)
def test_analyst_decisions_map_to_fixed_states(decision, state, reason):
    result = evaluate_candidate(_strong_candidate(analyst_decision=decision))

    assert result["state"] == state
    assert reason in result["reason_codes"]
    assert result["state"] in CANDIDATE_STATES


def test_custom_exact_prefix_suffix_rules_are_applied_locally(tmp_path):
    path = tmp_path / "entity-rules.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "ruleset_version": "test.1",
        "rules": [
            {
                "id": "custom-exact",
                "match": "exact",
                "action": "reject",
                "reason_code": "rejected_navigation_template",
                "patterns": ["customblock"],
            },
            {
                "id": "custom-prefix",
                "match": "prefix",
                "action": "review",
                "reason_code": "review_generated_prefix",
                "patterns": ["reviewme_"],
            },
            {
                "id": "custom-suffix",
                "match": "suffix",
                "action": "reject",
                "reason_code": "rejected_filename_like",
                "patterns": ["_noise"],
            },
        ],
    }), encoding="utf-8")

    exact = evaluate_candidate(_strong_candidate(alias="customblock"), rules_path=path)
    prefix = evaluate_candidate(_strong_candidate(alias="reviewme_alias"), rules_path=path)
    suffix = evaluate_candidate(_strong_candidate(alias="useful_noise"), rules_path=path)

    assert exact["state"] == "rejected_noise"
    assert "rejected_navigation_template" in exact["reason_codes"]
    assert prefix["state"] == "analyst_review_candidate"
    assert "review_generated_prefix" in prefix["reason_codes"]
    assert suffix["state"] == "rejected_noise"
    assert "rejected_filename_like" in suffix["reason_codes"]


def test_invalid_local_rule_reason_fails_closed(tmp_path):
    path = tmp_path / "invalid-rules.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "ruleset_version": "test.invalid",
        "rules": [{
            "id": "bad-reason",
            "match": "exact",
            "action": "reject",
            "reason_code": "invented_reason",
            "patterns": ["noise"],
        }],
    }), encoding="utf-8")

    with pytest.raises(RuleConfigError):
        load_noise_rules(path)


def test_runtime_rule_scope_is_context_bound_and_unknown_scope_fails_closed():
    rule = {
        "id": 9,
        "enabled": 1,
        "rule_type": "exact",
        "normalized_pattern": "nightfox77",
        "scope": "source_scope:navigation",
        "action": "reject",
        "reason_code": "rejected_navigation_template",
    }

    author = evaluate_candidate(
        _strong_candidate(source_scope="post_author"), extra_rules=[rule])
    navigation = evaluate_candidate(
        _strong_candidate(source_scope="navigation"), extra_rules=[rule])
    legacy_unknown = evaluate_candidate(
        _strong_candidate(source_scope="post_author"),
        extra_rules=[{**rule, "scope": "legacy-wide-scope"}],
    )

    assert author["state"] == "accepted_observation"
    assert navigation["state"] == "rejected_noise"
    assert legacy_unknown["state"] == "accepted_observation"


def test_batch_and_summary_are_deterministic_and_do_not_disclose_aliases():
    candidates = [_strong_candidate(), {"alias": "admin"}, {"alias": "user_nightfox"}]

    first = evaluate_candidates(candidates)
    second = evaluate_candidates(candidates)
    summary = quality_summary(first)

    assert first == second
    assert summary["total"] == 3
    assert summary["states"] == {
        "accepted_observation": 1,
        "analyst_review_candidate": 1,
        "rejected_noise": 1,
    }
    rendered = json.dumps(summary)
    assert "NightFox77" not in rendered
    assert "user_nightfox" not in rendered
