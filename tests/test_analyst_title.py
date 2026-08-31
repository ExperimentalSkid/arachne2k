from pathlib import Path

import report_builder
import site_dedupe
import storage
from dashboard_pages.site_directory import _name
from dashboard_services.i18n import category_description, category_family, category_label
from ui_components import category_badge, importance_badge, risk_badge


HOST = "c" * 56 + ".onion"


def _policy():
    return {
        "primary_category": "directory_index", "category": "directory_index",
        "content_category": "directory_index", "analyst_category": "directory_index",
        "classification_evidence_source": "analyst",
        "tags": ["directory_index"], "risk_level": "medium", "confidence": "high",
        "risk_flags": [], "storage_policy": "safe_summary", "review_status": "pending",
        "safety_reason": "directory_index", "priority_score": 10,
        "screenshot_policy": "allowed", "queue_policy": "expand", "active": 1,
        "safe_display_name": "Detected Directory",
        "spain_priority": True, "spain_confidence": "high",
        "spain_match_reason": "Spain-specific reference",
    }


def _insert_analyst_url(url, host, policy, **kwargs):
    url_id = storage.insert_or_update_onion_url(url, host, **kwargs)
    with storage.get_db() as db:
        stored_url = db.execute("SELECT url FROM onion_urls WHERE id=?", (url_id,)).fetchone()[0]
        db.execute("UPDATE onion_urls SET analyst_category=? WHERE id=?",
                   (policy["analyst_category"], url_id))
    storage.apply_onion_policy(stored_url, policy)
    return url_id


def _card(isolated_db):
    url = f"http://{HOST}/"
    policy = _policy()
    url_id = _insert_analyst_url(url, HOST, policy)
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Detected Directory")
    return url, card_id


def test_analyst_title_persists_and_clear_restores_detected_name(isolated_db):
    _, card_id = _card(isolated_db)
    site_dedupe.apply_manual_title(card_id, "  Clean   Review Name  ")
    card = site_dedupe.get_site_card(card_id)
    assert card["analyst_title"] == "Clean Review Name"
    assert card["display_name"] == "Detected Directory"
    assert _name(card, "en") == "Clean Review Name"

    site_dedupe.apply_manual_title(card_id, "")
    card = site_dedupe.get_site_card(card_id)
    assert card["analyst_title"] is None
    assert _name(card, "en") == "Detected Directory"


def test_title_change_does_not_mutate_policy_or_evidence_state(isolated_db):
    url, card_id = _card(isolated_db)
    with storage.get_db() as db:
        before_card = dict(db.execute("""SELECT canonical_site_id,primary_category,risk_level,
          importance_level,spain_priority,storage_policy FROM site_cards WHERE id=?""", (card_id,)).fetchone())
        before_url = dict(db.execute("SELECT url,primary_category,risk_level,spain_priority,storage_policy FROM onion_urls WHERE url=?", (url,)).fetchone())
    site_dedupe.apply_manual_title(card_id, "Analyst label")
    with storage.get_db() as db:
        after_card = dict(db.execute("""SELECT canonical_site_id,primary_category,risk_level,
          importance_level,spain_priority,storage_policy FROM site_cards WHERE id=?""", (card_id,)).fetchone())
        after_url = dict(db.execute("SELECT url,primary_category,risk_level,spain_priority,storage_policy FROM onion_urls WHERE url=?", (url,)).fetchone())
    assert after_card == before_card
    assert after_url == before_url


def test_report_uses_analyst_heading_and_detected_metadata(isolated_db, monkeypatch, tmp_path):
    _, card_id = _card(isolated_db)
    site_dedupe.apply_manual_title(card_id, "Clean Demo Name")
    monkeypatch.setattr(report_builder, "REPORTS_DIR", tmp_path)
    output = Path(report_builder.build_site_card_report(card_id))
    body = output.read_text(encoding="utf-8")
    assert body.startswith("# Clean Demo Name")
    assert "Analyst title: Clean Demo Name" in body
    assert "Detected/generated title: Detected Directory" in body
    assert f"Source host: {HOST}" in body


def test_human_category_helpers_and_badge_semantics():
    assert category_label("directory_index") == "Directory / Link list"
    assert category_family("hosting_services") == "Technical / Infrastructure"
    assert "directory or link list" in category_description("directory_index")
    assert "badge-category" in category_badge("directory_index")
    assert "badge-risk" in risk_badge("high")
    assert "badge-importance" in importance_badge("high")
