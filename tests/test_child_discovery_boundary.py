"""Focused regression tests for discovery-hint versus destination-truth scope."""
from __future__ import annotations

import crawler_decide_rules
import onion_worker
import storage


PARENT_HOST = "a" * 56 + ".onion"
PARENT_URL = f"http://{PARENT_HOST}/"
EXPLICIT_HOST = "childporn" + ("b" * (56 - len("childporn"))) + ".onion"
EXPLICIT_URL = f"http://{EXPLICIT_HOST}/childporn"


def _directory_policy() -> dict:
    return {
        "primary_category": "directory_index",
        "category": "directory_index",
        "content_category": "directory_index",
        "page_type": "link_repository",
        "storage_policy": "safe_summary",
        "review_status": "monitor",
        "queue_policy": "expand",
        "screenshot_policy": "allowed",
        "active": 1,
        "spain_priority": False,
    }


def test_explicit_looking_child_from_link_list_is_queued_unknown(isolated_db):
    source_id = storage.insert_or_update_onion_url(
        PARENT_URL, PARENT_HOST, status="crawled", policy=_directory_policy())

    result = onion_worker._store_discovered_links(
        {"id": source_id, "url": PARENT_URL, "depth": 0},
        [{
            "url": EXPLICIT_URL,
            "anchor_text": "childporn files",
            "section_context": "restricted links section",
        }],
        _directory_policy(),
    )

    child = storage.get_onion_url_by_url(EXPLICIT_URL)
    assert result["safe_queued"] == 1
    assert result["unknown_queued"] == 1
    assert child["status"] == "queued"
    assert child["active"] == 1
    assert child["primary_category"] == "unknown"
    assert child["content_category"] == "unknown"
    assert child["classification_evidence_source"] == "unverified"
    assert child["destination_html_evidence_version"] == 0
    assert child["site_card_id"] is None


def test_prefetch_classifier_cannot_leak_a_content_category(monkeypatch, isolated_db):
    """Defense in depth holds even if a future prefetch helper regresses."""
    monkeypatch.setattr(
        crawler_decide_rules,
        "classify_url_prefetch",
        lambda *_args, **_kwargs: {
            "primary_category": "severe_abuse_risk",
            "category": "severe_abuse_risk",
            "content_category": "severe_abuse_risk",
            "storage_policy": "metadata_only",
            "review_status": "restricted",
            "queue_policy": "blocked",
            "decision": "restrict",
            "active": 0,
            "url_hint_present": True,
            "classification_decision": "unverified_restricted_candidate",
        },
    )

    decision = crawler_decide_rules.decide_url(
        EXPLICIT_URL,
        source_url=PARENT_URL,
        anchor_text="childporn",
        source_context="restricted links section",
        classification_scope="outbound",
    )

    assert decision["decision"] in {"accept", "monitor"}
    assert decision["primary_category"] == "unknown"
    assert decision["content_category"] == "unknown"
    assert decision["storage_policy"] == "safe_summary"
    assert decision["active"] == 1
    assert decision["classification_decision"] == "unverified_hint"


def test_fetch_prefilter_cannot_block_from_a_regressed_url_classifier(monkeypatch, isolated_db):
    monkeypatch.setattr(
        onion_worker,
        "classify_url_prefetch",
        lambda *_args, **_kwargs: {
            "primary_category": "adult_filtered",
            "category": "adult_filtered",
            "content_category": "adult_filtered",
            "storage_policy": "discard",
            "review_status": "filtered",
            "queue_policy": "blocked",
            "decision": "reject",
            "active": 0,
            "url_hint_present": True,
            "classification_decision": "unverified_restricted_candidate",
        },
    )

    policy = onion_worker._prefilter_url(
        EXPLICIT_URL, PARENT_URL, "childporn", "restricted links section")

    assert policy["primary_category"] == "unknown"
    assert policy["content_category"] == "unknown"
    assert policy["decision"] == "monitor"
    assert policy["active"] == 1
    assert policy["classification_evidence_source"] == "unverified"


def test_interaction_looking_path_is_a_route_hint_not_a_terminal_page_type(isolated_db):
    url = f"http://{'c' * 56}.onion/login"
    decision = onion_worker._blocked_interaction_child_policy(
        url, crawler_decide_rules.decide_url(url))
    provisional = onion_worker._provisional_safe_child_policy(decision)

    assert provisional["interaction_route_hint"] is True
    assert provisional["interaction_route_hint_verified"] is False
    assert provisional["primary_category"] == "unknown"
    assert provisional["page_type"] == "unknown"
    assert provisional["decision"] in {"accept", "monitor"}
    assert provisional["active"] == 1

    context = onion_worker.classify_link_context(
        url, anchor_text="Login", section_context="Account",
        source_page_type="marketplace_front", same_host=True)
    assert context["relation_hint"] == "contact_login_cart"
    assert context["relation_verified"] is False
    assert context["evidence_source"] == "discovery_metadata"


def test_unverified_terminal_content_policy_is_neutralized():
    provisional = onion_worker._provisional_safe_child_policy({
        "primary_category": "adult_filtered",
        "category": "adult_filtered",
        "content_category": "adult_filtered",
        "storage_policy": "discard",
        "review_status": "filtered",
        "queue_policy": "blocked",
        "decision": "reject",
        "active": 0,
        "safety_reason": "adult_content_filtered",
        "classification_decision": "unverified_restricted_candidate",
    })

    assert provisional["primary_category"] == "unknown"
    assert provisional["content_category"] == "unknown"
    assert provisional["storage_policy"] == "safe_summary"
    assert provisional["queue_policy"] == "normal"
    assert provisional["decision"] == "monitor"
    assert provisional["active"] == 1


def test_file_policy_remains_terminal_without_assigning_content():
    url = f"http://{'d' * 56}.onion/archive.zip"
    provisional = onion_worker._provisional_safe_child_policy(
        crawler_decide_rules.decide_url(url))

    assert provisional["decision"] == "reject"
    assert provisional["active"] == 0
    assert provisional["safety_reason"] == "blocked_extension"
    assert provisional["primary_category"] == "unknown"
    assert provisional["content_category"] == "unknown"
