import json
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

import identity_registry
import site_dedupe
import storage
import structured_intelligence


ROOT = Path(__file__).parents[1]
HOST = "r" * 56 + ".onion"


@pytest.fixture
def synthetic_registry(tmp_path, monkeypatch):
    """Provide analyst references without relying on bundled or demo data."""
    path = tmp_path / "identity_registry.json"
    registry = {
        "schema_version": 1,
        "entities": [
            {
                "id": "reference-person-contextual",
                "entity_type": "person",
                "canonical_name": "Synthetic Contextual Reference",
                "attribution_status": "unresolved",
                "handles": [{
                    "value": "Distinctive Context Handle",
                    "policy": "contextual_only",
                    "contexts": ["Example Forum"],
                }],
                "sources": [{"label": "Analyst fixture", "url": "https://example.invalid/context"}],
            },
            {
                "id": "reference-person-exact",
                "entity_type": "person",
                "canonical_name": "Synthetic Exact Reference",
                "attribution_status": "unresolved",
                "handles": [{
                    "value": "RareOperatorHandle",
                    "policy": "exact_safe",
                    "contexts": ["Example Market"],
                }],
                "sources": [{"label": "Analyst fixture", "url": "https://example.invalid/exact"}],
            },
            {
                "id": "reference-operation-context",
                "entity_type": "ransomware_operation",
                "canonical_name": "Synthetic Operation Reference",
                "attribution_status": "unresolved",
                "handles": [{
                    "value": "OperationLabel",
                    "policy": "disabled_global",
                    "contexts": ["operation"],
                }],
                "sources": [{"label": "Analyst fixture", "url": "https://example.invalid/operation"}],
            },
        ],
    }
    path.write_text(json.dumps(registry), encoding="utf-8")
    monkeypatch.setattr(identity_registry, "REGISTRY_PATH", path)
    identity_registry.load_registry.cache_clear()
    yield registry
    identity_registry.load_registry.cache_clear()


def _actor_policy():
    return {
        "primary_category": "forum_social",
        "page_type": "profile_page",
        "storage_policy": "safe_summary",
        "risk_level": "medium",
        "spain_priority": False,
    }


def _card_policy():
    return {
        "primary_category": "forum_social",
        "category": "forum_social",
        "content_category": "forum_social",
        "analyst_category": "forum_social",
        "classification_evidence_source": "analyst",
        "destination_html_evidence_version": 0,
        "tags": ["forum_social"],
        "risk_level": "medium",
        "confidence": "high",
        "risk_flags": [],
        "storage_policy": "safe_summary",
        "review_status": "pending",
        "safety_reason": "test",
        "priority_score": 20,
        "screenshot_policy": "allowed",
        "queue_policy": "expand",
        "active": 1,
        "page_type": "profile_page",
        "card_ready": 1,
    }


def _store_live_profile(alias="RareOperatorHandle"):
    url = f"http://{HOST}/u/{alias}"
    url_id = storage.insert_or_update_onion_url(url, HOST, status="crawled", policy=_card_policy())
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET analyst_category='forum_social',
          primary_category='forum_social',category='forum_social',content_category='forum_social',
          classification_evidence_source='analyst',destination_html_evidence_version=0
          WHERE id=?""", (url_id,))
    card_id = site_dedupe.ensure_url_site_card(
        url_id,
        _card_policy(),
        title="Observed forum profile",
        visible_text=f"{alias} Example Market profile",
    )
    aliases = [{
        "accepted": True,
        "evidence_version": 2,
        "alias": alias,
        "normalized_alias": alias.casefold(),
        "role": "profile_owner",
        "evidence_type": "profile_page_identity_match",
        "confidence": 0.96,
        "safe_context_label": f"{alias} Example Market profile",
    }]
    storage.store_actor_observations(url, aliases, [], _card_policy())
    return card_id, url


def test_bundled_registry_is_empty_and_contains_no_demo_records():
    identity_registry.load_registry.cache_clear()

    assert identity_registry.reference_entities() == []
    bundled = json.loads(identity_registry.REGISTRY_PATH.read_text(encoding="utf-8"))
    assert bundled.get("entities") == []
    assert "demo" not in identity_registry.REGISTRY_PATH.read_text(encoding="utf-8").casefold()


def test_temporary_analyst_registry_loads_reference_profiles(synthetic_registry):
    entities = identity_registry.reference_entities()

    assert {item["id"] for item in entities} == {
        "reference-person-contextual",
        "reference-person-exact",
        "reference-operation-context",
    }
    assert all(item.get("sources") for item in entities)
    assert all("demo_record" not in item for item in entities)


def test_disabled_and_generic_handles_do_not_identify_people(synthetic_registry):
    admin = identity_registry.match_observed_alias(
        "Admin", context_text="Example Market profile", observed_field="profile_username")
    assert admin == []

    free = identity_registry.match_observed_alias(
        "Free", context_text="normal forum body text", observed_field="body_text")
    assert free == []

    operation = identity_registry.match_observed_alias(
        "OperationLabel", context_text="operation status page", observed_field="body_text")
    assert operation and operation[0]["entity_type"] == "ransomware_operation"
    assert operation[0]["decision"] == "context_only"
    assert not any(item["entity_type"] == "person" for item in operation)


def test_contextual_and_exact_safe_matching_remain_conservative(synthetic_registry):
    contextual_without_context = identity_registry.match_observed_alias(
        "Distinctive Context Handle",
        context_text="unrelated profile",
        observed_field="profile_username",
    )
    assert contextual_without_context[0]["decision"] == "insufficient_context"

    contextual_with_context = identity_registry.match_observed_alias(
        "Distinctive Context Handle",
        context_text="Example Forum member profile",
        observed_field="profile_username",
    )
    assert contextual_with_context[0]["decision"] == "needs_review"
    assert contextual_with_context[0]["canonical_name"] == "Synthetic Contextual Reference"

    exact = identity_registry.match_observed_alias(
        "RareOperatorHandle",
        context_text="Example Market operator profile",
        observed_field="profile_username",
    )
    assert exact[0]["decision"] == "strong_candidate"
    assert exact[0]["canonical_name"] == "Synthetic Exact Reference"
    assert exact[0]["reference_record"] is True


def test_observed_identity_candidates_use_live_actor_rows(
        isolated_db, synthetic_registry):
    _store_live_profile()

    candidates = identity_registry.observed_identity_candidates()

    match = next(item for item in candidates
                 if item["entity_id"] == "reference-person-exact")
    assert match["canonical_name"] == "Synthetic Exact Reference"
    assert match["decision"] == "strong_candidate"
    assert match["onion_host"] == HOST


def test_live_structured_card_uses_observations_and_lists_observed_pages(
        isolated_db, synthetic_registry):
    card_id, url = _store_live_profile()

    live = structured_intelligence.build_live_structured_card(card_id)

    assert live and live["data_origin"] == "crawler"
    assert "is_demo" not in live
    assert live["coverage"]["profiles"] == 1
    assert live["profiles"][0]["handle"] == "RareOperatorHandle"
    assert any(page["path"] == url for page in live["observed_pages"])
    assert any(
        candidate["candidate_entity_id"] == "reference-person-exact"
        for candidate in live["candidate_attributions"]
    )


def test_identity_signals_page_is_live_only_and_has_no_demo_ui(
        isolated_db, synthetic_registry):
    _store_live_profile()

    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value("Identity Signals").run()

    assert not app.exception
    visible_text = " ".join(
        " ".join((str(getattr(item, "value", "")), str(getattr(item, "label", ""))))
        for collection in (app.markdown, app.caption, app.info, app.metric, app.tabs)
        for item in collection
    )
    assert "Identity signals" in visible_text
    assert "Live Site Cards" in visible_text
    assert "Observed aliases" in visible_text
    assert "Analyst references" in visible_text
    assert "demo" not in visible_text.casefold()


def test_identity_workspace_separates_live_classification_from_advisory_quality(
        isolated_db, synthetic_registry):
    _store_live_profile()

    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value("Identity Signals").run()

    assert not app.exception
    visible_text = " ".join(
        " ".join((str(getattr(item, "value", "")), str(getattr(item, "label", ""))))
        for collection in (
            app.markdown, app.caption, app.info, app.warning, app.metric, app.tabs,
            app.expander,
        )
        for item in collection
    )
    assert "Live classification" in visible_text
    assert "Content category" in visible_text
    assert "Page type" in visible_text
    assert "Safety state" in visible_text
    assert "Advisory quality" in visible_text
    assert "Technical provenance" in visible_text
    assert "Supporting evidence" in visible_text
    assert "Contradicting evidence" in visible_text
    assert all("apply" not in str(button.label).casefold() for button in app.button)
