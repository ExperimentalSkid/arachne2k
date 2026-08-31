import json
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

import site_dedupe
import storage
import onion_worker
from cti_export import build_stix_bundle, write_stix_bundle
from dashboard_pages.quality_center import _dimension_label
from dashboard_services.i18n import tr
from ui_components import mask_onion_address
from universal_classifier import classify


ROOT = Path(__file__).parents[1]
HOST = "q" * 56 + ".onion"


def test_review_feedback_dimension_is_bilingual():
    assert _dimension_label("review", "en") == "Review"
    assert _dimension_label("review", "es") == "Revisión"


def test_weak_page_signal_abstains_with_safe_suggestion():
    policy = classify(f"http://{HOST}/thread/topic", visible_text="malware discussion",
                      classification_scope="page")
    assert policy["primary_category"] == "unknown"
    assert policy["suggested_category"] == "malware_hacking"
    assert policy["classification_decision"] == "abstained"
    assert policy["classification_confidence_score"] < 0.5


def test_decision_ledger_is_metadata_safe(isolated_db):
    url = f"http://{HOST}/"
    policy = classify(url, visible_text="plain community page", classification_scope="page")
    storage.insert_or_update_onion_url(url, status="crawled", policy=policy)
    storage.record_classification_decision(
        url, policy, stage="page", safe_metadata={"page_type": "homepage", "raw_text": "DO NOT STORE"}
    )
    with storage.get_db() as db:
        row = dict(db.execute("SELECT * FROM classification_decisions").fetchone())
    assert row["stage"] == "page"
    assert "DO NOT STORE" not in json.dumps(row)
    assert json.loads(row["safe_metadata_json"]) == {"page_type": "homepage"}


def test_change_intelligence_uses_hashes_without_page_text(isolated_db):
    url = f"http://{HOST}/news"
    policy = classify(url, visible_text="community updates", classification_scope="page")
    storage.insert_or_update_onion_url(url, status="crawled", policy=policy)
    storage.mark_onion_crawled(url, 200, "Safe", "old-hash", "fuzzy", 0, 0, "low", [], [],
                               "crawled", None)
    assert storage.record_page_change(url, "new-hash", "forum_social") is True
    changes = storage.get_meaningful_changes()
    assert changes[0]["change_type"] == "category_and_content"
    with storage.get_db() as db:
        payload = db.execute("SELECT safe_summary_json FROM page_change_events").fetchone()[0]
    assert json.loads(payload) == {"hash_changed": True, "category_changed": True}


def test_coverage_counts_checked_waiting_and_blocked(isolated_db):
    checked = f"http://{HOST}/checked"
    waiting = f"http://{HOST}/waiting"
    blocked = f"http://{HOST}/blocked"
    for url in (checked, waiting, blocked):
        storage.insert_or_update_onion_url(url, HOST, status="queued")
    storage.mark_onion_crawled(checked, 200, "Safe", "hash", "fuzzy", 0, 0, "low", [], [],
                               "crawled", None)
    html = b"<html><title>Restricted material</title><body>child sexual abuse material files download exchange</body></html>"
    title, meta, visible, _links, structure = onion_worker._parse(html, "text/html", blocked)
    policy = onion_worker._classify_fetched_page(
        blocked, title=title, meta=meta, visible_text=visible,
        source_url=None, source_context=None, page_structure=structure,
    )
    policy = onion_worker.finalize_page_policy(
        blocked, policy, title=title, page_structure=structure,
    )
    storage.apply_onion_policy(blocked, policy, checked=True, page_structure=structure)
    storage.refresh_crawl_coverage()
    rows = storage.get_crawl_coverage()
    row = next(item for item in rows if item["onion_host"] == HOST)
    assert row["discovered_count"] == 3
    assert row["checked_count"] >= 2
    assert row["queued_count"] == 1
    assert row["restricted_count"] == 1


def test_coverage_reader_does_not_rebuild_during_dashboard_render(isolated_db, monkeypatch):
    monkeypatch.setattr(
        storage, "refresh_crawl_coverage",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("normal coverage reads must not write")),
    )
    assert storage.get_crawl_coverage() == []


def test_stix_export_contains_safe_metadata_and_rejects_adult(isolated_db, tmp_path):
    url = f"http://{HOST}/forum"
    policy = classify(url, visible_text="discussion forum community forum", classification_scope="page")
    policy.update(
        analyst_category=policy["primary_category"],
        classification_evidence_source="analyst",
    )
    url_id = storage.insert_or_update_onion_url(url, HOST, status="crawled")
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET analyst_category=? WHERE id=?",
                   (policy["analyst_category"], url_id))
    storage.apply_onion_policy(url, policy)
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Safe forum")
    bundle = build_stix_bundle(card_id)
    encoded = json.dumps(bundle)
    assert bundle["type"] == "bundle"
    assert url in encoded
    assert "snippet" not in encoded.casefold()
    path = write_stix_bundle(card_id, tmp_path)
    assert path.is_file()
    graph = storage.get_site_evidence_graph(card_id)
    assert any(node["kind"] == "site_card" for node in graph["nodes"])
    assert any(node["label"] == url for node in graph["nodes"])

    with storage.get_db() as db:
        now = storage.utc_now_iso()
        cur = db.execute("""INSERT INTO site_cards
          (canonical_site_id,primary_category,storage_policy,first_seen,created_at,updated_at)
          VALUES(?,?,?,?,?,?)""", ("adult-card", "adult_filtered", "discard", now, now, now))
        adult_card = int(cur.lastrowid)
    with pytest.raises(ValueError):
        build_stix_bundle(adult_card)


def test_quality_center_renders_from_intelligence_menu(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    intelligence = next(value for value in app.sidebar.radio[1].options if "Results" in value)
    app.sidebar.radio[1].set_value(intelligence).run()
    quality = next(value for value in app.sidebar.radio[2].options if "Quality" in value)
    app.sidebar.radio[2].set_value(quality).run()
    assert not app.exception
    rendered = "\n".join(str(item.value) for item in app.markdown)
    assert rendered.count('class="rt-hero-title">Quality center</div>') == 1
    assert "Classification Quality Center" not in rendered
    assert any(tab.label == "Crawl coverage" for tab in app.tabs)


def _quality_text(app) -> str:
    values = []
    for name in ("markdown", "caption", "info", "success", "warning"):
        values.extend(str(item.value) for item in getattr(app, name, []))
    values.extend(str(item.label) for item in app.expander)
    return "\n".join(values)


def _feedback_report(**overrides):
    report = {
        "page_decisions": 40,
        "unique_pages": 32,
        "accepted": 24,
        "unsure": 8,
        "unknown_rate": 0.25,
        "reviewed_count": 10,
        "category_corrections": 3,
        "correction_rate": 0.3,
        "feedback_by_dimension": {
            "spain": {"reviewed_count": 5, "confirmed": 4, "corrected": 1},
            "dedupe": {"reviewed_count": 3, "confirmed": 2, "rejected": 1},
        },
        "correction_pairs": [{
            "previous_category": "unknown", "final_category": "forum_social", "count": 3,
        }],
        "unknown_reasons": [{"reason_code": "insufficient_evidence", "count": 8}],
        "shadow_candidates": [],
        "safety_excluded": 0,
    }
    report.update(overrides)
    return report


def test_quality_feedback_uses_30_day_default_and_honest_sample_copy(isolated_db, monkeypatch):
    monkeypatch.setattr(
        storage, "get_classification_quality_report",
        lambda days=30: _feedback_report(), raising=False,
    )
    monkeypatch.setattr(storage, "get_uncertain_classifications", lambda limit=100: [])
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "quality"
    app.run()

    assert not app.exception
    selector = next(item for item in app.selectbox if item.label == "Quality window")
    assert selector.options == ["Last 7 days", "Last 30 days", "Last 90 days"]
    assert selector.value == 30
    text = _quality_text(app)
    assert "Advisory only" in text
    assert "40 page-decision events across 32 unique pages" in text
    assert "10 analyst-reviewed outcomes" in text
    assert "What needs improvement" in text
    assert "Insufficient evidence affected 8 pages" in text


def test_uncertain_pages_are_grouped_by_card_and_raw_onions_are_masked(
        isolated_db, monkeypatch):
    host = "u" * 56 + ".onion"
    raw_url = f"http://{host}/thread/one"
    uncertain = [
        {
            "url": raw_url,
            "site_card_id": 41,
            "primary_category": "unknown",
            "suggested_category": "forum_social",
            "classification_confidence_score": 0.48,
            "category_reason": "Forum structure needs corroboration",
        },
        {
            "url": f"http://{host}/thread/two",
            "site_card_id": 41,
            "primary_category": "unknown",
            "suggested_category": "forum_social",
            "classification_confidence_score": 0.44,
            "category_reason": "Forum structure needs corroboration",
        },
        {
            "url": "http://" + "r" * 56 + ".onion/restricted",
            "site_card_id": None,
            "primary_category": "adult_filtered",
            "suggested_category": None,
            "classification_confidence_score": 0.99,
            "category_reason": "restricted",
        },
    ]
    monkeypatch.setattr(
        storage, "get_classification_quality_report",
        lambda days=30: _feedback_report(), raising=False,
    )
    monkeypatch.setattr(
        storage, "get_uncertain_classifications", lambda limit=100: uncertain,
    )
    monkeypatch.setattr(
        storage, "get_meaningful_changes",
        lambda limit=100: [{
            "url": "http://" + "s" * 56 + ".onion/unsafe",
            "change_type": "category",
            "previous_category": "unknown",
            "current_category": "severe_abuse_risk",
            "detected_at": "2026-07-01T00:00:00Z",
        }],
    )
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "quality"
    app.run()

    assert not app.exception
    text = _quality_text(app)
    assert "Site Card #41" in text
    assert "2 uncertain pages" in text
    assert host not in text
    assert mask_onion_address(raw_url) in text
    assert ("r" * 56 + ".onion") not in text
    assert ("s" * 56 + ".onion") not in text
    assert len([item for item in app.expander if "uncertain pages" in str(item.label)]) == 1


def test_shadow_observations_are_advisory_and_have_no_apply_control(
        isolated_db, monkeypatch):
    monkeypatch.setattr(
        storage, "get_classification_quality_report",
        lambda days=30: _feedback_report(shadow_candidates=[{
            "candidate_ruleset": "candidate-v2",
            "sample_size": 20,
            "changed_count": 4,
            "safety_excluded": 2,
            "current_category": "unknown",
            "candidate_category": "forum_social",
        }]),
        raising=False,
    )
    monkeypatch.setattr(storage, "get_uncertain_classifications", lambda limit=100: [])
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "quality"
    app.run()

    assert not app.exception
    text = _quality_text(app)
    assert "candidate-v2" in text
    assert "Observation only" in text
    assert "4 would differ" in text
    assert all("apply" not in str(button.label).casefold() for button in app.button)


def test_quality_feedback_copy_is_available_in_english_and_spanish():
    keys = (
        "quality_window", "quality_advisory", "quality_improvement_title",
        "quality_feedback_title", "quality_tab_shadow", "quality_shadow_advisory",
    )
    for key in keys:
        assert tr(key, "en") != key
        assert tr(key, "es") != key
