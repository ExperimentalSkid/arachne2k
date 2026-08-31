from pathlib import Path

from streamlit.testing.v1 import AppTest

import dashboard
import report_builder
import site_dedupe
import storage


HOSTS = {letter: letter * 56 + ".onion" for letter in "fghij"}


def _policy(category="unknown", risk="low", storage_policy="safe_summary", flags=None):
    return {
        "primary_category": category, "category": category, "tags": [] if category == "unknown" else [category],
        "content_category": category, "analyst_category": category,
        "classification_evidence_source": "analyst",
        "risk_level": risk, "confidence": "low", "risk_flags": flags or [],
        "storage_policy": storage_policy,
        "review_status": "restricted" if storage_policy == "metadata_only" else "pending",
        "safety_reason": category if category != "unknown" else None, "priority_score": 10,
        "screenshot_policy": "blocked", "queue_policy": "blocked" if storage_policy == "metadata_only" else "normal",
        "active": 0 if storage_policy == "metadata_only" else 1, "spain_priority": False,
    }


def _add(host_key, item_policy, path="/", title=None):
    url = f"http://{HOSTS[host_key]}{path}"
    url_id = storage.insert_or_update_onion_url(
        url, HOSTS[host_key], status="blocked" if not item_policy["active"] else "queued"
    )
    with storage.get_db() as db:
        stored_url = db.execute("SELECT url FROM onion_urls WHERE id=?", (url_id,)).fetchone()[0]
        db.execute("UPDATE onion_urls SET analyst_category=? WHERE id=?",
                   (item_policy["analyst_category"], url_id))
    storage.apply_onion_policy(stored_url, item_policy)
    card_id = site_dedupe.ensure_url_site_card(url_id, item_policy, title=title, visible_text="safe ordinary words")
    if title and card_id:
        with storage.get_db() as db:
            db.execute("UPDATE onion_urls SET title=? WHERE id=?", (title, url_id))
        site_dedupe.update_site_card_rollups(card_id)
    return url_id, card_id


def _app(page):
    app = AppTest.from_file(str(Path(__file__).parents[1] / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value(page).run()
    assert not app.exception
    return app


def _all_text(app):
    values = []
    for collection in (app.markdown, app.caption, app.error, app.warning, app.info):
        values.extend(str(item.value) for item in collection)
    values.extend(str(item.label) for item in app.button)
    return "\n".join(values)


def test_adult_hidden_by_default_and_advanced_metadata_toggle(isolated_db):
    adult = _policy("adult_restricted", "critical", "metadata_only", ["adult_extreme_caution"])
    _add("f", adult, title="UNSAFE_ADULT_TITLE")
    app = _app("Site Cards")
    assert "Restricted adult-risk page" not in _all_text(app)
    advanced = _app("Advanced")
    advanced.selectbox[0].set_value("Restricted Metadata").run()
    adult_toggle = next(item for item in advanced.checkbox if item.label == "Show filtered adult metadata")
    adult_toggle.set_value(True).run()
    text = _all_text(advanced)
    frame = advanced.dataframe[0].value
    assert any(HOSTS["f"] in value for value in frame["url"])
    assert set(frame["safety_reason"]) == {"adult_content_filtered"}
    assert "UNSAFE_ADULT_TITLE" not in text
    assert "No preview available" not in text


def test_severe_blackhole_does_not_appear_even_in_advanced_card_views(isolated_db):
    severe = _policy("severe_abuse_risk", "critical", "metadata_only", ["restricted_content"])
    _add("g", severe, title="FORBIDDEN_SEVERE_RAW_TITLE")
    normal = _app("Site Cards")
    assert "Restricted content. Metadata only retained" not in _all_text(normal)
    advanced = _app("Advanced")
    advanced.selectbox[0].set_value("Restricted Metadata").run()
    severe_toggle = next(item for item in advanced.checkbox if item.label == "Show severe restricted metadata")
    severe_toggle.set_value(True).run()
    text = _all_text(advanced)
    assert "Restricted content. Metadata only retained" not in text
    assert "FORBIDDEN_SEVERE_RAW_TITLE" not in text
    assert "No preview available" not in text


def test_compact_card_omits_empty_sections_and_preview_box(isolated_db):
    plain = _policy("directory_index")
    plain["tags"] = []
    _add("h", plain, title="Plain safe site")
    app = _app("Site Cards")
    text = _all_text(app)
    assert "Plain safe site" in text
    assert "Spain reason" not in text
    assert "**Indicators**" not in text
    assert "No preview available" not in text


def test_dead_warning_and_simplified_review_actions_render(isolated_db):
    dead_url_id, _ = _add("i", _policy("weapons_arms", "high", "metadata_limited"), title="Unavailable site")
    url = f"http://{HOSTS['i']}/"
    storage.mark_onion_dead(url, 404, "http_404")
    site_dedupe.ensure_url_site_card(dead_url_id, _policy("weapons_arms", "high", "metadata_limited"))
    dead_app = _app("Site Cards")
    assert "Unavailable" in _all_text(dead_app)

    actionable = _policy("leaks_data", "high", "metadata_limited")
    actionable["review_status"] = "needs_report"
    _add("j", actionable, title="Actionable site")
    review = _app("Review Findings")
    next(item for item in review.button if str(item.key).startswith("compact-review-True-")).click().run()
    labels = {button.label for button in review.button}
    assert {"Edit review fields", "Re-check", "Close"} <= labels
    next(item for item in review.button if item.label == "Edit review fields").click().run()
    review_status = next(item for item in review.selectbox if item.label == "Review status")
    option_text = " ".join(str(value).casefold() for value in review_status.options)
    assert all(value in option_text for value in ("relevant", "false", "report", "blocked"))


def test_honest_review_and_restricted_counts(isolated_db):
    _add("f", _policy("adult_restricted", "critical", "metadata_only", ["adult_extreme_caution"]))
    _add("g", _policy("severe_abuse_risk", "critical", "metadata_only", ["restricted_content"]))
    _add("h", _policy("forum_social", "low"), title="Monitor forum")
    dead_id, _ = _add("i", _policy("leaks_data", "high", "metadata_limited"), title="Dead finding")
    dead_url = f"http://{HOSTS['i']}/"
    storage.mark_onion_dead(dead_url, 404, "http_404")
    site_dedupe.ensure_url_site_card(dead_id, _policy("leaks_data", "high", "metadata_limited"))
    needs_review = _policy("leaks_data", "high", "metadata_limited")
    needs_review["review_status"] = "needs_report"
    _add("j", needs_review, title="Needs review")
    assert dashboard._need_review_count() == 1
    # Severe rows are tombstones, not hidden Site Cards.
    assert dashboard._restricted_hidden_count() == 0
    assert dashboard._scalar("SELECT COUNT(*) FROM onion_urls WHERE primary_category='adult_filtered'") == 1


def test_adult_report_cannot_be_created(isolated_db, tmp_path, monkeypatch):
    import pytest
    monkeypatch.setattr(report_builder, "REPORTS_DIR", tmp_path)
    _, card_id = _add("f", _policy("adult_restricted", "critical", "metadata_only", ["adult_extreme_caution"]))
    assert card_id == 0
    with pytest.raises(ValueError):
        report_builder.build_site_card_report(card_id, "pytest")
    assert dashboard._scalar("SELECT COUNT(*) FROM evidence_reports") == 0
