from __future__ import annotations

import copy
import hashlib
import random

import entity_expansion


HOST = f"{'a' * 56}.onion"
OTHER_HOST = f"{'b' * 56}.onion"
ROOT = f"http://{HOST}/"


def _source(**overrides):
    source = {
        "url": ROOT,
        "verification_state": "verified",
        "classification_evidence_source": "destination_html",
        "destination_html_evidence_version": 1,
        "storage_policy": "safe_summary",
        "queue_policy": "allowed",
        "active": 1,
    }
    source.update(overrides)
    return source


def _records(*paths):
    return [{"url": path} for path in paths]


def test_source_must_be_current_verified_destination_html():
    for change in (
        {"verification_state": "provisional"},
        {"classification_evidence_source": "url_hint"},
        {"destination_html_evidence_version": 0},
    ):
        result = entity_expansion.plan_entity_expansion(
            _source(**change), _records("/about"))
        assert result["stop_code"] == "SOURCE_NOT_VERIFIED"
        assert result["proposals"] == []
        assert result["proposal_only"] is True
        assert result["network_performed"] is False
        assert result["enqueued"] is False


def test_source_and_child_restricted_policies_fail_closed():
    for change in (
        {"storage_policy": "discard"},
        {"storage_policy": "metadata_only"},
        {"primary_category": "adult_filtered"},
        {"safety_state": "restricted"},
        {"queue_policy": "blocked"},
    ):
        result = entity_expansion.plan_entity_expansion(
            _source(**change), _records("/about"))
        assert result["stop_code"] == "SOURCE_POLICY_BLOCKED"
        assert result["proposed"] == 0

    result = entity_expansion.plan_entity_expansion(_source(), [
        {"url": "/about", "policy": {"storage_policy": "metadata_only"}},
        {"url": "/contact"},
    ])
    assert [proposal["role"] for proposal in result["proposals"]] == ["contact"]
    assert result["rejections"]["CHILD_POLICY_BLOCKED"] == 1


def test_only_same_host_public_get_routes_are_proposed():
    result = entity_expansion.plan_entity_expansion(_source(), [
        {"url": "/about"},
        {"url": f"http://{OTHER_HOST}/about"},
        {"url": "ftp://example.invalid/about"},
        {"url": "/contact", "method": "POST"},
        {"url": "/unrelated"},
    ])
    assert result["stop_code"] == "PLAN_READY"
    assert len(result["proposals"]) == 1
    assert result["proposals"][0]["role"] == "about"
    assert result["proposals"][0]["method"] == "GET"
    assert result["proposals"][0]["same_host"] is True
    assert result["rejections"] == {
        "CROSS_HOST": 1,
        "NON_GET_ROUTE": 1,
        "NON_PUBLIC_SCHEME": 1,
        "UNSUPPORTED_ROLE": 1,
    }


def test_interactive_tracking_trap_and_download_routes_are_hard_blocked():
    long_url = "/about?" + "&".join(f"k{i}=v" for i in range(9))
    result = entity_expansion.plan_entity_expansion(_source(), [
        {"url": "/login"},
        {"url": "/cart"},
        {"url": "/search.php?q=anything"},
        {"url": "/viewtopic.php?t=7&sid=secret"},
        {"url": "/about?utm_source=news"},
        {"url": "/tag/topic"},
        {"url": "/calendar?month=12"},
        {"url": "/form/submit"},
        {"url": "/about/about/about/about"},
        {"url": "/archive.zip"},
        {"url": "/a/b/c/d/e/f/g/h/i/j/k/l/about"},
        {"url": "/%2e%2e/about"},
        {"url": long_url},
        {"url": f"http://user:pass@{HOST}/about"},
        {"url": f"http://{HOST}:8080/about"},
        {"url": f"http://{HOST}:bad/about"},
        # Exact-token matching must not confuse a normal forum route with a form.
        {"url": "/forum/42"},
    ])
    assert result["proposals"] and result["proposals"][0]["role"] == "section"
    assert result["rejections"]["ROUTE_BLOCKED"] == 6
    assert result["rejections"]["SESSION_OR_TRACKING_BLOCKED"] == 2
    assert result["rejections"]["TRAP_BLOCKED"] == 4
    assert result["rejections"]["FETCH_POLICY_BLOCKED"] == 1
    assert result["rejections"]["CREDENTIALS_BLOCKED"] == 1
    assert result["rejections"]["PORT_BLOCKED"] == 1
    assert result["rejections"]["INVALID_URL"] == 1


def test_forum_thread_page_variants_share_one_resource_and_root_wins():
    result = entity_expansion.plan_entity_expansion(_source(), [
        {"url": "/viewtopic.php?t=7&start=20"},
        {"url": "/viewtopic.php?t=8"},
        {"url": "/viewtopic.php?t=7&p=99#p99"},
        {"url": "/viewtopic.php?t=7"},
    ])
    assert result["proposed"] == 2
    thread_seven = next(
        item for item in result["proposals"]
        if item["resource_identity"].endswith(":thread:7")
    )
    assert thread_seven["role"] == "thread"
    assert thread_seven["url"].endswith("/viewtopic.php?t=7")
    assert result["rejections"]["DUPLICATE_RESOURCE"] == 2
    assert all(len(item["resource_hash"]) == 64 for item in result["proposals"])


def test_profile_variants_dedupe_on_stable_profile_identity():
    result = entity_expansion.plan_entity_expansion(_source(), [
        {"url": "/memberlist.php?u=17&mode=viewprofile"},
        {"url": "/memberlist.php?mode=viewprofile&u=17"},
        {"url": "/memberlist.php?mode=viewprofile&u=18"},
        # Generic id= is not enough to call an unrelated route a profile.
        {"url": "/article.php?id=17"},
    ])
    profiles = [item for item in result["proposals"] if item["role"] == "profile"]
    assert len(profiles) == 2
    assert len({item["resource_hash"] for item in profiles}) == 2
    assert result["rejections"]["DUPLICATE_RESOURCE"] == 1
    assert result["rejections"]["UNSUPPORTED_ROLE"] == 1


def test_public_routes_use_conservative_path_or_exact_anchor_hints():
    result = entity_expansion.plan_entity_expansion(_source(), [
        {"url": "/about/"},
        {"url": "/about"},
        {"url": "/index.php?page=2", "anchor_text": "Contact us"},
        {"url": "/pgp"},
        {"url": "/mirrors"},
        {"url": "/faq"},
        {"url": "/rules"},
        {"url": "/news", "anchor_text": "about this article"},
    ])
    assert {item["role"] for item in result["proposals"]} == {
        "about", "contact", "pgp", "mirrors", "faq", "rules",
    }
    assert result["rejections"]["DUPLICATE_RESOURCE"] == 1
    assert result["rejections"]["UNSUPPORTED_ROLE"] == 1


def test_caps_are_strict_and_cannot_be_raised_above_module_limits():
    records = [
        {"url": f"/users/person{name}"}
        for name in ("alpha", "bravo", "charlie", "delta", "echo")
    ] + _records("/about", "/contact", "/pgp", "/mirrors", "/faq", "/rules")
    result = entity_expansion.plan_entity_expansion(
        _source(), records, max_proposals=999, max_per_role=999)
    assert result["caps"] == {"per_host": 10, "per_role": 3, "per_resource": 1}
    assert result["proposed"] <= 10
    assert sum(item["role"] == "profile" for item in result["proposals"]) == 3
    assert result["rejections"]["ROLE_CAP_REACHED"] == 2

    tight = entity_expansion.plan_entity_expansion(
        _source(), records, max_proposals=2, max_per_role=1)
    assert tight["proposed"] == 2
    assert tight["caps"]["per_host"] == 2
    assert tight["caps"]["per_role"] == 1
    assert tight["rejections"]["HOST_CAP_REACHED"] >= 1


def test_plan_is_deterministic_across_input_order():
    records = [
        {"url": "/viewtopic.php?t=7&start=20"},
        {"url": "/contact"},
        {"url": "/viewtopic.php?t=7"},
        {"url": "/users/alice"},
        {"url": "/about"},
        {"url": "/faq"},
    ]
    first = entity_expansion.plan_entity_expansion(_source(), records)
    shuffled = copy.deepcopy(records)
    random.Random(47).shuffle(shuffled)
    second = entity_expansion.plan_entity_expansion(_source(), shuffled)
    assert first == second


def test_hostile_records_never_raise_and_have_fixed_reason_codes():
    hostile = [
        None, "not-a-record", {}, {"url": 7}, {"url": ""},
        {"url": "http://[broken/about"}, {"url": "javascript:alert(1)"},
        {"url": "/about", "policy": {"primary_category": "severe_abuse_risk"}},
    ]
    result = entity_expansion.plan_entity_expansion(_source(), hostile)
    assert result["stop_code"] == "NO_ELIGIBLE_CANDIDATES"
    assert set(result["rejections"]).issubset(entity_expansion.REJECTION_CODES)
    assert result["rejections"]["INVALID_RECORD"] == 2
    assert result["rejections"]["CHILD_POLICY_BLOCKED"] == 1
    assert result["considered"] == len(hostile)


def test_resource_hashes_are_stable_and_planner_has_no_side_effect_contract():
    result = entity_expansion.build_entity_expansion_plan(
        _source(), [{"url": "/users/alice"}])
    proposal = result["proposals"][0]
    assert proposal["resource_hash"] == hashlib.sha256(
        proposal["resource_identity"].encode("utf-8")).hexdigest()
    assert proposal["reason_code"] == "VERIFIED_PROFILE_ROUTE"
    assert result["proposal_only"] is True
    assert result["network_performed"] is False
    assert result["enqueued"] is False


def test_approval_revalidation_rechecks_source_route_and_verified_destination_policy():
    proposal = {
        "proposed_url": ROOT + "about", "route_role": "about",
        "resource_identity": f"route:{HOST}:about",
        "safety_state": "policy_allowed_unverified_destination",
    }
    allowed = entity_expansion.revalidate_entity_expansion_proposal(_source(), proposal)
    assert allowed["allowed"] is True
    assert allowed["reason_code"] == "APPROVAL_POLICY_ALLOWED"
    assert allowed["network_performed"] is False

    source_blocked = entity_expansion.revalidate_entity_expansion_proposal(
        _source(storage_policy="discard"), proposal)
    assert source_blocked == {"allowed": False, "reason_code": "SOURCE_POLICY_BLOCKED"}

    destination_blocked = entity_expansion.revalidate_entity_expansion_proposal(
        _source(), proposal, destination_page=_source(
            url=proposal["proposed_url"], primary_category="adult_filtered",
            storage_policy="discard", queue_policy="blocked", active=0))
    assert destination_blocked == {
        "allowed": False, "reason_code": "DESTINATION_POLICY_BLOCKED"}


def test_approval_revalidation_does_not_promote_unverified_destination_hint_to_block():
    proposal = {
        "proposed_url": ROOT + "about", "route_role": "about",
        "resource_identity": f"route:{HOST}:about",
        "safety_state": "policy_allowed_unverified_destination",
    }
    unverified_hint = {
        "url": proposal["proposed_url"], "verification_state": "provisional",
        "classification_evidence_source": "unverified",
        "destination_html_evidence_version": 0,
        "primary_category": "adult_filtered", "storage_policy": "discard",
        "queue_policy": "blocked", "active": 0,
    }
    decision = entity_expansion.revalidate_entity_expansion_proposal(
        _source(), proposal, destination_page=unverified_hint)
    assert decision["allowed"] is True


def test_approval_revalidation_rejects_tampered_or_interactive_proposals():
    base = {
        "proposed_url": ROOT + "about", "route_role": "about",
        "resource_identity": f"route:{HOST}:about",
        "safety_state": "policy_allowed_unverified_destination",
    }
    cases = (
        ({**base, "proposed_url": ROOT + "login"}, "ROUTE_BLOCKED"),
        ({**base, "proposed_url": f"http://{OTHER_HOST}/about"}, "CROSS_HOST"),
        ({**base, "method": "POST"}, "NON_GET_ROUTE"),
        ({**base, "resource_identity": "route:wrong.onion:about"}, "INVALID_PROPOSAL"),
    )
    for proposal, reason in cases:
        result = entity_expansion.revalidate_entity_expansion_proposal(_source(), proposal)
        assert result == {"allowed": False, "reason_code": reason}
