from pathlib import Path

from streamlit.testing.v1 import AppTest

import site_dedupe
import storage
from ui_components import mask_onion_address


HOST = "d" * 56 + ".onion"


def _policy(spain=False):
    return {
        "primary_category": "directory_index", "category": "directory_index",
        "content_category": "directory_index", "analyst_category": "directory_index",
        "classification_evidence_source": "analyst",
        "tags": ["directory_index", "spain_priority"] if spain else ["directory_index"],
        "risk_level": "low", "confidence": "high", "risk_flags": ["spain_priority"] if spain else [],
        "storage_policy": "safe_summary", "review_status": "pending", "safety_reason": "directory_index",
        "priority_score": 40 if spain else 10, "screenshot_policy": "allowed", "queue_policy": "expand",
        "active": 1, "spain_priority": spain, "spain_confidence": "high" if spain else None,
        "spain_match_language": "ES" if spain else None,
        "spain_match_reason": "Strong Spanish institution reference" if spain else None,
    }


def _insert_analyst_url(url, policy, status="crawled"):
    url_id = storage.insert_or_update_onion_url(url, HOST, status=status)
    with storage.get_db() as db:
        stored_url = db.execute("SELECT url FROM onion_urls WHERE id=?", (url_id,)).fetchone()[0]
        db.execute("UPDATE onion_urls SET analyst_category=? WHERE id=?",
                   (policy["analyst_category"], url_id))
    storage.apply_onion_policy(stored_url, policy)
    return url_id


def _app(page):
    app = AppTest.from_file(str(Path(__file__).parents[1] / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value(page).run()
    assert not app.exception
    return app


def test_site_cards_and_spain_pages_render_one_grouped_card(isolated_db):
    policy = _policy(True)
    for path in ("/", "/index.php", "/home"):
        url = f"http://{HOST}{path}"
        url_id = _insert_analyst_url(url, policy)
        # The production verifier persists identity evidence before the card
        # rollup.  Mirror that boundary instead of relying on the legacy
        # ``title=`` argument to become stored evidence implicitly.
        with storage.get_db() as db:
            db.execute("""UPDATE onion_urls
              SET safe_display_name=?,detected_title=?
              WHERE id=?""", ("Spain Directory", "Spain Directory", url_id))
        site_dedupe.ensure_url_site_card(url_id, policy, title="Spain Directory", visible_text="safe directory text")
    assert len(site_dedupe.get_site_cards()) == 1
    cards_app = _app("Site Cards")
    compact_text = " ".join(
        [str(item.value) for item in cards_app.markdown] +
        [str(item.label) for item in cards_app.button]
    )
    assert "Spain Directory" in compact_text
    assert "URLs 1" not in compact_text
    assert mask_onion_address(HOST) in compact_text
    assert HOST not in compact_text
    assert "🇪🇸" in compact_text
    next(item for item in cards_app.radio if item.label == "Display").set_value("Card view").run()
    spain_card = next(item for item in cards_app.button
                      if str(item.key).startswith("directory-card-spain-"))
    assert "SPAIN FLAG" not in str(spain_card.label)
    assert "SPAIN PRIORITY" not in str(spain_card.label)
    assert "🇪🇸" in str(spain_card.label)
    spain_app = _app("Spain Priority")
    spain_text = " ".join(str(item.value) for item in spain_app.markdown)
    assert "Pages to check" in spain_text
    assert "Spain Priority Site Cards" not in spain_text


def test_opening_site_card_pins_cards_navigation_query(isolated_db):
    policy = _policy(False)
    url = f"http://{HOST}/"
    url_id = _insert_analyst_url(url, policy)
    site_dedupe.ensure_url_site_card(url_id, policy, title="Openable Card", visible_text="safe directory text")

    app = AppTest.from_file(str(Path(__file__).parents[1] / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "cards"
    app.run()
    assert not app.exception
    button = next(item for item in app.button if str(item.key).startswith("compact-review-False-"))
    button.click().run()

    assert not app.exception
    nav = app.query_params.get("nav")
    assert (nav[0] if isinstance(nav, list) else nav) == "cards"
    text = " ".join(str(item.label) for item in app.button)
    assert "Edit review fields" in text
    assert "Close" in text
    assert any("Source trail" in str(item.value) for item in app.markdown)


def test_selected_site_card_dialog_renders_from_any_workspace_page(isolated_db):
    policy = _policy(False)
    url = f"http://{HOST}/"
    url_id = _insert_analyst_url(url, policy)
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Global Dialog Card",
                                               visible_text="safe directory text")

    app = AppTest.from_file(str(Path(__file__).parents[1] / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "home"
    app.session_state["directory_selected_card"] = card_id
    app.run()

    assert not app.exception
    text = " ".join(str(item.label) for item in app.button)
    assert "Edit review fields" in text
    assert "Close" in text
    assert any("Source trail" in str(item.value) for item in app.markdown)


def test_spain_priority_open_card_preserves_spain_navigation_and_back_context(isolated_db):
    policy = _policy(True)
    url = f"http://{HOST}/spain"
    url_id = _insert_analyst_url(url, policy)
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Spain Open Test",
                                               visible_text="safe Spain directory text")
    storage.persist_spain_priority(url, policy, None, card_id)

    app = AppTest.from_file(str(Path(__file__).parents[1] / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "spain"
    app.run()
    button = next(item for item in app.button if str(item.key).startswith("spain-open-card-"))
    button.click().run()

    assert not app.exception
    nav = app.query_params.get("nav")
    assert (nav[0] if isinstance(nav, list) else nav) == "spain"
    assert app.session_state["nav_page"] == "Spain Priority"
    assert app.session_state["directory_origin_page"] == "Spain Priority"
    assert app.session_state["directory_selected_card"] == card_id
    back = next(item for item in app.button if str(item.key).startswith("card-page-back-"))
    assert "Spain" in str(back.label)
    back.click().run()
    assert not app.exception
    assert app.session_state["nav_page"] == "Spain Priority"
    assert "directory_selected_card" not in app.session_state


def test_advanced_possible_mirror_and_merge_split_views_render(isolated_db):
    app = _app("Advanced")
    app.selectbox[0].set_value("Possible Mirrors").run()
    assert not app.exception
    app.selectbox[0].set_value("Manual Merge / Split").run()
    assert not app.exception
