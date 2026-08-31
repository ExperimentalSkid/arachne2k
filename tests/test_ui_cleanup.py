from pathlib import Path
import re

from streamlit.testing.v1 import AppTest

import site_dedupe
import storage
from ui_components import data_row, empty_state, page_lead
from ui_styles import DASHBOARD_CSS
from universal_classifier import classify


ROOT = Path(__file__).parents[1]
UI_SOURCES = [ROOT / "dashboard.py", ROOT / "ui_components.py", ROOT / "ui_styles.py"]
UI_SOURCES += list((ROOT / "dashboard_pages").glob("*.py"))
MOJIBAKE = ("\u00c3", "\u00c2", "\u00e2\u20ac", "\ufffd", "\u00f0\u0178")


def _add(index: int, text: str = "discussion forum") -> int:
    host = ("a" * 52 + f"{index:04d}") + ".onion"
    url = f"http://{host}/"
    page_text = f"{text} unique section {index}"
    policy = classify(url, title=f"Directory entry {index}", visible_text=page_text,
                      classification_scope="page")
    policy.update(
        analyst_category=policy["primary_category"],
        classification_evidence_source="analyst",
    )
    url_id = storage.insert_or_update_onion_url(url, host, status="crawled")
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET analyst_category=? WHERE id=?",
                   (policy["analyst_category"], url_id))
    storage.apply_onion_policy(url, policy)
    return site_dedupe.ensure_url_site_card(url_id, policy, title=f"Directory entry {index}",
                                            visible_text=page_text)


def _app():
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=30).run()
    app.sidebar.radio[0].set_value("Site Cards").run()
    assert not app.exception
    return app


def test_ui_sources_do_not_contain_common_mojibake():
    failures = []
    for path in UI_SOURCES:
        text = path.read_text(encoding="utf-8")
        for marker in MOJIBAKE:
            if marker in text:
                failures.append(f"{path.name}: {marker!r}")
    assert failures == []


def test_related_site_display_name_is_escaped_before_unsafe_html_render():
    source = (ROOT / "dashboard_pages" / "workspace.py").read_text(encoding="utf-8")
    assert "html.escape(str(site['name']))" in source
    assert 'f"**{site[\'name\']}**' not in source


def test_shared_flat_primitives_escape_external_values():
    marker = '<img src=x onerror="alert(1)">'
    rendered = "".join((
        page_lead(marker, marker, eyebrow=marker, aside=marker),
        empty_state(marker, marker),
        data_row(marker, marker, state="critical"),
    ))
    assert marker not in rendered
    assert rendered.count("&lt;img") == 8
    assert 'class="rt-page-lead"' in rendered
    assert 'class="rt-empty-state"' in rendered
    assert 'rt-data-row-critical' in rendered


def test_shared_css_has_semantic_timer_and_flat_card_contract():
    assert ".rt-session-timer" in DASHBOARD_CSS
    assert ".rt-page-lead" in DASHBOARD_CSS
    assert ".rt-empty-state" in DASHBOARD_CSS
    assert 'st-key-home-card-' in DASHBOARD_CSS
    height = re.search(r'st-key-home-card-.*?min-height:(\d+)px!important', DASHBOARD_CSS, re.DOTALL)
    assert height and int(height.group(1)) <= 160
    assert "box-shadow:none!important" in DASHBOARD_CSS


def test_table_view_can_open_the_same_detail_dialog(isolated_db):
    _add(1)
    app = _app()
    next(item for item in app.radio if item.label == "Display").set_value("Table view").run()
    assert any(item.label == "Select a result to open" for item in app.selectbox)
    next(item for item in app.button if item.label == "Open selected Site Card").click().run()
    assert not app.exception
    assert any(item.label == "Edit review fields" for item in app.button)
    assert any(item.label == "Re-check" for item in app.button)
    assert any(item.label == "Close" for item in app.button)


def test_empty_state_distinguishes_true_empty_from_filtered(isolated_db):
    app = _app()
    assert any("true empty result" in str(item.value) for item in app.info)

    _add(2)
    app = _app()
    search = next(item for item in app.text_input if item.label == "Search sites")
    search.set_value("definitely-no-match").run()
    assert any("current filters" in str(item.value) and "still exist" in str(item.value)
               for item in app.warning)


def test_search_change_resets_stale_pagination(isolated_db):
    for index in range(52):
        _add(index, "discussion forum")
    app = _app()
    size = next(item for item in app.selectbox if item.label == "Page size")
    size.set_value(25).run()
    page = next(item for item in app.number_input if item.label == "Page number")
    page.set_value(2).run()
    assert next(item for item in app.number_input if item.label == "Page number").value == 2
    search = next(item for item in app.text_input if item.label == "Search sites")
    search.set_value("Directory entry 0").run()
    assert app.session_state["card-page-False"] == 1
    assert not any(item.label == "Page number" for item in app.number_input)
