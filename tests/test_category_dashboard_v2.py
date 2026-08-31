from pathlib import Path

from streamlit.testing.v1 import AppTest

import report_builder
import site_dedupe
import storage
from universal_classifier import classify


BASE = "http://" + "a" * 56 + ".onion/"


def test_marketplace_taxonomy_respects_page_structure_and_safety_precedence():
    cases = {
        "onion directory index of markets": ("directory_index", "safe_summary"),
        "drug market": ("marketplace_drugs", "metadata_limited"),
        "weapon shop": ("marketplace_weapons", "metadata_limited"),
        "credential shop": ("marketplace_credentials", "metadata_limited"),
        "leak shop": ("marketplace_leaks", "metadata_limited"),
        "discussion forum about marketplaces": ("forum_social", "safe_summary"),
    }
    for text, (category, policy) in cases.items():
        result = classify(BASE, visible_text=text)
        assert result["primary_category"] == category
        assert result["storage_policy"] == policy
        assert result["category_confidence"] in {"medium", "high", "critical"}
        assert result["category_reason"]
        assert result["category_safe_label"]
    directory = classify(BASE, visible_text="onion directory index of markets")
    forum = classify(BASE, visible_text="discussion forum about marketplaces")
    assert "marketplace" in directory["tags"]
    assert "marketplace" in forum["tags"]

    explicit_url_with_other_html = classify(BASE + "porn", visible_text="weapon marketplace")
    adult = classify(BASE, title="Adult content",
                     visible_text="Pornography and explicit sexual adult content")
    severe = classify(
        BASE,
        visible_text="child sexual abuse material video files for download and exchange",
    )
    assert explicit_url_with_other_html["primary_category"] == "marketplace_weapons"
    assert adult["primary_category"] == "adult_filtered" and adult["ui_hidden_default"] == 1
    assert severe["primary_category"] == "severe_abuse_risk" and severe["storage_policy"] == "metadata_only"


def _add_card(letter: str, text: str):
    host = letter * 56 + ".onion"
    url = f"http://{host}/"
    policy = classify(url, visible_text=text)
    policy.update(
        analyst_category=policy["primary_category"],
        classification_evidence_source="analyst",
    )
    url_id = storage.insert_or_update_onion_url(url, host)
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET analyst_category=? WHERE id=?",
                   (policy["analyst_category"], url_id))
    storage.apply_onion_policy(url, policy)
    site_dedupe.ensure_url_site_card(url_id, policy, title="Safe category title", visible_text=text)
    return policy


def _site_cards_app():
    app = AppTest.from_file(str(Path(__file__).parents[1] / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value("Site Cards").run()
    assert not app.exception
    return app


def test_compact_table_card_modes_filters_and_marketplace_warning(isolated_db):
    _add_card("b", "drug market")
    _add_card("c", "discussion forum about marketplaces")
    app = _site_cards_app()
    display = next(item for item in app.radio if item.label == "Display")
    assert display.value == "Compact list"
    rendered = " ".join(str(item.value) for item in [*app.markdown, *app.caption])
    assert "Marketplace: Drugs" in rendered

    display.set_value("Table view").run()
    assert not app.exception and app.dataframe
    categories = set(app.dataframe[-1].value["Category"])
    assert "Marketplace: Drugs" in categories and "Forum / Community" in categories

    display = next(item for item in app.radio if item.label == "Display")
    display.set_value("Card view").run()
    assert any("Marketplace: Drugs" in str(item.label) for item in app.button)
    assert not any("Metadata limited" in str(item.label) for item in app.button)

    app = _site_cards_app()
    market_filter = next(button for button in app.button if button.label.startswith("Marketplace: Drugs"))
    market_filter.click().run()
    assert not app.exception
    assert any("Marketplace: Drugs" in str(item.label) for item in app.button)
    assert not any("Forum / social" in str(item.value) for item in app.markdown)


def test_directory_card_opens_read_only_dialog_then_edit_mode(isolated_db):
    _add_card("d", "discussion forum about marketplaces")
    app = _site_cards_app()
    search = next(item for item in app.text_input if item.label == "Search sites")
    search.set_value("forum").run()
    card = next(item for item in app.button if str(item.key).startswith("compact-review-False-"))
    card.click().run()

    assert not app.exception
    assert any(item.label == "Edit review fields" for item in app.button)
    assert any("d" * 56 + ".onion" in str(item.value) for item in app.code)
    assert not any(item.label == "Save changes" for item in app.button)
    modal_text = " ".join(str(item.value) for item in app.markdown)
    assert "Final content category" in modal_text
    assert "Final page type" in modal_text
    assert "Supporting signals" in modal_text
    assert "Contradicting signals" in modal_text
    assert "Site Card category update" in modal_text

    next(item for item in app.button if item.label == "Edit review fields").click().run()
    assert not app.exception
    assert any(item.label == "Review importance" for item in app.selectbox)
    assert any(item.label == "Review status" for item in app.selectbox)
    assert any(item.label == "Save changes" for item in app.button)
    assert any(item.label == "Cancel edit" for item in app.button)

    importance = next(item for item in app.selectbox if item.label == "Review importance")
    importance.set_value("high").run()
    next(item for item in app.button if item.label == "Cancel edit").click().run()
    with storage.get_db() as db:
        assert db.execute("SELECT analyst_importance FROM site_cards").fetchone()[0] is None

    next(item for item in app.button if item.label == "Edit review fields").click().run()
    importance = next(item for item in app.selectbox if item.label == "Review importance")
    assert importance.value != "high"
    importance.set_value("high").run()
    next(item for item in app.button if item.label == "Save changes").click().run()
    assert not app.exception
    with storage.get_db() as db:
        assert db.execute("SELECT analyst_importance FROM site_cards").fetchone()[0] == "high"


def test_site_card_modal_can_create_safe_report(isolated_db, monkeypatch, tmp_path):
    _add_card("e", "discussion forum about marketplaces")
    monkeypatch.setattr(report_builder, "REPORTS_DIR", tmp_path)
    app = _site_cards_app()
    card = next(item for item in app.button if str(item.key).startswith("compact-review-False-"))
    card.click().run()

    create = next(item for item in app.button if item.label == "Create report")
    create.click().run()

    assert not app.exception
    assert any("Report created" in str(item.value) for item in app.success)
    assert list(tmp_path.glob("report_site_card_*.md"))
    with storage.get_db() as db:
        row = db.execute("SELECT report_status,review_status FROM site_cards").fetchone()
    assert tuple(row) == ("generated", "reported")
