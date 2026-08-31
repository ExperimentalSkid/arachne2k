from pathlib import Path

from streamlit.testing.v1 import AppTest

import site_dedupe
import storage
from dashboard_pages import site_directory
from ui_components import mask_onion_address


HOST = "p" * 56 + ".onion"


class _FakeStreamlit:
    def __init__(self):
        self.session_state = {}
        self.buttons = []

    def button(self, label, **kwargs):
        self.buttons.append((label, kwargs))
        return False


def _summary_card(**updates):
    card = {
        "id": 17,
        "analyst_title": "Analyst *label* [reference](https://example.invalid)",
        "display_name": "Detected title",
        "representative_host": HOST,
        "representative_url": f"http://{HOST}/vendor/example?view=full",
        "primary_category": "forum_social",
        "risk_level": "high",
        "review_status": "needs_review",
        "storage_policy": "safe_summary",
        "live_url_count": 2,
        "dead_url_count": 1,
        "seen_count": 7,
        "last_checked_at": "2026-07-12T11:52:26Z",
        "card_completeness_label": "usable",
        "safe_summary": "A concise [external-looking](https://example.invalid) summary for review.",
        "spain_priority": True,
    }
    card.update(updates)
    return card


def test_card_face_is_compact_host_first_escaped_and_keeps_callback_contract():
    st = _FakeStreamlit()
    site_directory.render_card(st, _summary_card())

    assert len(st.buttons) == 1
    label, options = st.buttons[0]
    assert r"Analyst \*label\* \[reference\]\(https://example\.invalid\)" in label
    assert f"`{mask_onion_address(HOST)}`" in label
    assert HOST not in label
    assert f"http://{HOST}/vendor" not in label
    assert "Forum / Community" in label
    assert "Risk High · Review Needs Review" in label
    assert "Live · Current" in label
    assert "Seen 7" not in label and "URLs 3" not in label
    assert "2026" not in label and "Completeness" not in label
    assert r"A concise \[external\-looking\]\(https://example\.invalid\) summary for review\." in label
    assert "No report" not in label
    assert "🇪🇸" in label
    assert "SPAIN FLAG" not in label and "SPAIN PRIORITY" not in label
    assert options["key"] == "directory-card-spain-high-False-17"
    assert options["on_click"] is site_directory.open_card
    assert options["args"] == (17, False)


def test_card_key_prefix_supports_home_without_changing_directory_default():
    default_st = _FakeStreamlit()
    home_st = _FakeStreamlit()
    card = _summary_card()

    site_directory.render_card(default_st, card)
    site_directory.render_card(home_st, card, key_prefix="home-card")

    assert default_st.buttons[0][1]["key"] == "directory-card-spain-high-False-17"
    assert home_st.buttons[0][1]["key"] == "home-card-spain-high-False-17"
    assert home_st.buttons[0][1]["on_click"] is site_directory.open_card
    assert home_st.buttons[0][1]["args"] == (17, False)


def test_visible_timestamps_are_compact_while_invalid_values_remain_readable():
    assert site_directory._display_timestamp("2026-07-12T11:52:26Z") == "2026-07-12 11:52 UTC"
    assert site_directory._display_timestamp("2026-07-12T13:52:26+02:00") == "2026-07-12 11:52 UTC"
    assert site_directory._display_timestamp(None) == "—"
    assert site_directory._display_timestamp("legacy-value") == "legacy-value"


def test_expanded_card_face_allows_a_longer_summary_without_readding_clutter():
    summary = " ".join(["representative safe description"] * 8)
    compact = _FakeStreamlit()
    expanded = _FakeStreamlit()
    expanded.session_state["compact_site_cards"] = False
    site_directory.render_card(compact, _summary_card(safe_summary=summary))
    site_directory.render_card(expanded, _summary_card(safe_summary=summary))

    compact_label, _ = compact.buttons[0]
    expanded_label, _ = expanded.buttons[0]
    assert len(expanded_label) > len(compact_label)
    assert "Seen 7" not in expanded_label and "URLs 3" not in expanded_label
    assert "Completeness" not in expanded_label
    assert "🇪🇸" in expanded_label


def test_card_face_keeps_report_and_safety_details_for_the_detail_page():
    st = _FakeStreamlit()
    site_directory.render_card(st, _summary_card(
        report_status="generated",
        report_generated_at="2026-07-12T12:00:00Z",
        updated_at="2026-07-12T11:59:00Z",
        storage_policy="metadata_limited",
        restricted_outbound_count=4,
    ))

    label, _options = st.buttons[0]
    assert "Report" not in label
    assert "Metadata limited" not in label
    assert "restricted child" not in label
    assert "Open details" in label


def _policy():
    return {
        "primary_category": "directory_index", "category": "directory_index",
        "content_category": "directory_index", "analyst_category": "directory_index",
        "classification_evidence_source": "analyst",
        "tags": ["directory_index"], "risk_level": "low", "confidence": "high",
        "risk_flags": [], "storage_policy": "safe_summary", "review_status": "pending",
        "safety_reason": "directory_index", "priority_score": 10,
        "screenshot_policy": "allowed", "queue_policy": "expand", "active": 1,
        "page_type": "homepage", "card_ready": True,
    }


def _insert_analyst_url(url, policy):
    url_id = storage.insert_or_update_onion_url(url, HOST, status="crawled")
    with storage.get_db() as db:
        stored_url = db.execute("SELECT url FROM onion_urls WHERE id=?", (url_id,)).fetchone()[0]
        db.execute("UPDATE onion_urls SET analyst_category=? WHERE id=?",
                   (policy["analyst_category"], url_id))
    storage.apply_onion_policy(stored_url, policy)
    return url_id


def test_live_dialog_uses_canonical_main_url(isolated_db):
    about = f"http://{HOST}/about"
    root = f"http://{HOST}/"
    about_id = _insert_analyst_url(about, _policy())
    card_id = site_dedupe.ensure_url_site_card(about_id, _policy(), title="Presentation test")
    root_id = _insert_analyst_url(root, _policy())
    assert site_dedupe.ensure_url_site_card(root_id, _policy(), title="Presentation test") == card_id
    with storage.get_db() as db:
        db.execute("UPDATE site_card_urls SET url_role='path' WHERE site_card_id=?", (card_id,))
        db.execute("UPDATE site_card_urls SET url_role='canonical' WHERE site_card_id=? AND onion_url_id=?",
                   (card_id, root_id))

    app = AppTest.from_file(str(Path(__file__).parents[1] / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "cards"
    app.run()
    next(item for item in app.button if str(item.key).startswith("compact-review-False-")).click().run()

    assert not app.exception
    assert app.code[0].value == root
