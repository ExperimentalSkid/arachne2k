from pathlib import Path
import re
import sys

from streamlit.testing.v1 import AppTest

import dashboard_auth
import storage
from dashboard_pages import workspace
from ui_components import category_badge, mask_onion_address, safe_display_title
from ui_styles import ARACHNE_LIGHT_CSS, DASHBOARD_CSS


ROOT = Path(__file__).parents[1]


def _without_media_blocks(css: str) -> str:
    """Return the desktop cascade without viewport-specific overrides."""
    result = css
    while True:
        start = result.find("@media")
        if start < 0:
            return result
        opening = result.find("{", start)
        assert opening >= 0, "malformed media rule"
        depth = 1
        cursor = opening + 1
        while depth and cursor < len(result):
            if result[cursor] == "{":
                depth += 1
            elif result[cursor] == "}":
                depth -= 1
            cursor += 1
        assert depth == 0, "unterminated media rule"
        result = result[:start] + result[cursor:]


def _effective_declarations(css: str, selector: str) -> dict[str, str]:
    """Resolve the final desktop declarations for one exact selector."""
    desktop = _without_media_blocks(re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL))
    declarations: dict[str, str] = {}
    for selector_block, body in re.findall(r"([^{}]+)\{([^{}]*)\}", desktop):
        selectors = {item.strip() for item in selector_block.split(",")}
        if selector not in selectors:
            continue
        for declaration in body.split(";"):
            if ":" not in declaration:
                continue
            name, value = declaration.split(":", 1)
            declarations[name.strip()] = value.strip()
    return declarations


def _desktop_rule_count(css: str, selector: str) -> int:
    desktop = _without_media_blocks(re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL))
    return sum(
        selector in {item.strip() for item in selector_block.split(",")}
        for selector_block, _body in re.findall(r"([^{}]+)\{([^{}]*)\}", desktop)
    )


class _FakeStreamlit:
    def __init__(self):
        self.session_state = {}
        self.query_params = {}


def test_dark_is_the_session_fallback_without_overriding_saved_preferences(monkeypatch):
    monkeypatch.setattr(workspace, "get_str", lambda _key, default=None: default)
    fresh = _FakeStreamlit()
    assert workspace._resolve_ui_theme(fresh) == "dark"
    assert fresh.session_state["ui_dark_mode"] is True

    saved = _FakeStreamlit()
    saved.session_state["ui_theme"] = "light"
    assert workspace._resolve_ui_theme(saved) == "light"


def test_visible_navigation_has_eight_plain_primary_destinations(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    assert not app.exception
    primary_keys = {f"nav_btn_{workspace.PAGE_SLUGS[page]}" for page in workspace.PRIMARY_NAV_PAGES}
    primary = [button for button in app.sidebar.button if str(button.key) in primary_keys]
    assert len(primary) == 8
    labels = " ".join(str(button.label) for button in primary)
    assert all(code not in labels for code in ("HOME", "REVIEW", "SITES", "ENTITY", "QUEUE", "CTRL", "DOC"))
    assert "Overview" in labels and "Review Inbox" in labels and "Sites" in labels
    assert "Spain" in labels and "Collection" in labels and "Operations" in labels


def test_primary_navigation_inventory_and_renderer_map_are_complete():
    assert workspace.PRIMARY_NAV_PAGES == (
        "Home", "Review Findings", "Spain Priority", "Site Cards",
        "Entity Intelligence", "Crawl Queue", "Control Center", "Reports",
    )
    assert set(workspace.PAGE_SLUGS) == set(workspace.SIMPLE_PAGES)
    assert len(set(workspace.PAGE_SLUGS.values())) == len(workspace.SIMPLE_PAGES)

    source = (ROOT / "dashboard_pages" / "workspace.py").read_text(encoding="utf-8")
    renderer_pages = set(re.findall(r'^\s{12}"([^"]+)":\s+lambda:', source, re.MULTILINE))
    assert renderer_pages == set(workspace.SIMPLE_PAGES)


def test_every_primary_workspace_still_renders_after_visual_refinement(isolated_db):
    for page in workspace.PRIMARY_NAV_PAGES:
        app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
        app.query_params["nav"] = workspace.PAGE_SLUGS[page]
        app.run()

        assert not app.exception, page
        assert app.session_state["nav_page"] == page
        primary_keys = {
            f"nav_btn_{workspace.PAGE_SLUGS[item]}"
            for item in workspace.PRIMARY_NAV_PAGES
        }
        assert primary_keys.issubset({str(button.key) for button in app.sidebar.button})


def test_sidebar_starts_expanded_and_always_keeps_a_reopen_control():
    dashboard_source = (ROOT / "dashboard.py").read_text(encoding="utf-8")
    workspace_source = (ROOT / "dashboard_pages" / "workspace.py").read_text(encoding="utf-8")
    assert 'initial_sidebar_state="expanded"' in dashboard_source
    assert 'initial_sidebar_state="expanded"' in workspace_source
    assert '[data-testid="stSidebarCollapsedControl"] {display:flex!important;visibility:visible!important;}' in DASHBOARD_CSS
    assert '[data-testid="stToolbar"]' not in DASHBOARD_CSS


def test_explicit_navigation_leaves_a_full_page_site_detail(monkeypatch):
    fake = _FakeStreamlit()
    fake.session_state.update({
        "directory_selected_card": 17,
        "directory_selected_review_only": True,
        "directory_dialog_edit": True,
    })
    monkeypatch.setitem(sys.modules, "streamlit", fake)
    workspace._open_workspace_page("Reports")
    assert fake.session_state["nav_page"] == "Reports"
    assert "directory_selected_card" not in fake.session_state
    assert "directory_selected_review_only" not in fake.session_state
    assert "directory_dialog_edit" not in fake.session_state


def test_navigation_preserves_theme_session_and_unrelated_query_parameters(monkeypatch):
    fake = _FakeStreamlit()
    fake.session_state["dashboard_session_token"] = "opaque-session-token"
    fake.query_params.update({"theme": "light", "keep": "unchanged", "nav": "home"})
    monkeypatch.setitem(sys.modules, "streamlit", fake)

    workspace._open_workspace_page("Quality Center")

    assert fake.session_state["nav_page"] == "Quality Center"
    assert fake.query_params == {
        "theme": "light",
        "keep": "unchanged",
        "nav": "quality",
        "rt_session": "opaque-session-token",
    }


def test_direct_navigation_slug_opens_the_requested_page_and_keeps_query_context(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params.update({"nav": "quality", "theme": "light", "keep": "unchanged"})
    app.run()

    assert not app.exception
    assert app.session_state["nav_page"] == "Quality Center"
    scalar = lambda value: value[0] if isinstance(value, list) else value
    assert scalar(app.query_params["nav"]) == "quality"
    assert scalar(app.query_params["theme"]) == "light"
    assert scalar(app.query_params["keep"]) == "unchanged"
    rendered = " ".join(str(item.value) for item in app.markdown)
    assert "quality center" in rendered.casefold()


def test_url_navigation_overrides_stale_hidden_navigation_state(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "cards"
    app.run()
    assert app.session_state["nav_page"] == "Site Cards"

    # Simulate a browser back/direct URL change after the hidden compatibility
    # radios have already been instantiated with the Sites route.
    app.query_params["nav"] = "quality"
    app.run()
    assert not app.exception
    assert app.session_state["nav_page"] == "Quality Center"

    app.query_params["nav"] = "home"
    app.run()
    assert not app.exception
    assert app.session_state["nav_page"] == "Home"


def test_sites_default_to_compact_rows_and_collapsed_filters(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "cards"
    app.run()
    assert not app.exception
    display = next(item for item in app.radio if item.label == "Display")
    assert display.value == "Compact list"
    assert any(str(item.label).startswith("Filters") for item in app.expander)
    source = (ROOT / "dashboard_pages" / "workspace.py").read_text(encoding="utf-8")
    assert "with st.expander(filter_label, expanded=False):" in source


def test_crawl_queue_uses_a_bounded_plain_language_list(isolated_db):
    host = "q" * 56 + ".onion"
    for index in range(30):
        storage.insert_or_update_onion_url(
            f"http://{host}/page-{index}", host, status="queued",
        )
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "queue"
    app.run()
    assert not app.exception
    rows = [item for item in app.markdown if '<div class="rt-queue-row ' in str(item.value)]
    assert len(rows) == 25
    next_button = next(item for item in app.button if item.key == "queue-page-next")
    next_button.click().run()
    assert not app.exception
    rows = [item for item in app.markdown if '<div class="rt-queue-row ' in str(item.value)]
    assert len(rows) == 5


def test_onion_mask_is_stable_and_does_not_expose_the_raw_host():
    host = "a" * 56 + ".onion"
    masked = mask_onion_address(host)
    assert host not in masked
    assert masked == "aaaaaaaa…aa.onion"
    assert mask_onion_address("abcdefghijklmnop.onion") == "abcdefgh…op.onion"
    assert mask_onion_address("example.org") == "example.org"
    assert safe_display_title(host, fallback="Unnamed site") == "Unnamed site"
    assert safe_display_title("Named source", host) == "Named source"


def test_category_colours_are_stable_across_canonical_and_legacy_names():
    assert "badge-blue" in category_badge("forum_social")
    assert "badge-blue" in category_badge("forum_home")
    assert "badge-green" in category_badge("wiki_knowledge")
    assert "badge-cyan" in category_badge("link_list")
    assert "badge-amber" in category_badge("marketplace_mixed")
    assert "badge-red" in category_badge("financial_fraud")


def test_shared_design_system_is_responsive_restrained_and_script_free():
    combined = DASHBOARD_CSS + ARACHNE_LIGHT_CSS
    assert "@media (max-width:1100px)" in combined
    assert "@media (max-width:700px)" in combined
    assert "prefers-reduced-motion" in combined
    assert "radial-gradient" not in combined
    assert "@keyframes" not in combined
    assert "<script" not in combined.casefold()
    assert "--rt-space-1" in combined and "--rt-accent" in combined


def test_visual_system_uses_flat_hierarchy_without_hiding_controls():
    # Evaluate the winning desktop cascade. A substring elsewhere in the file
    # cannot satisfy this contract if a later rule silently re-boxes the UI.
    flat_selectors = (
        '[data-testid="stVerticalBlockBorderWrapper"]',
        '[data-testid="stForm"]',
        'div[data-testid="stExpander"]',
        '[data-testid="stDataFrame"]',
        '.rt-kpi-strip',
        '.rt-kpi',
        '[class*="st-key-rt-home-workbench"]',
    )
    for selector in flat_selectors:
        declarations = _effective_declarations(DASHBOARD_CSS, selector)
        assert declarations, selector
        assert declarations["border-radius"].startswith("0"), selector
        assert declarations["box-shadow"].startswith("none"), selector
    for selector in flat_selectors[:3] + flat_selectors[4:]:
        assert _effective_declarations(
            DASHBOARD_CSS, selector,
        )["background"].startswith("transparent"), selector

    # Grouping selectors have one desktop authority rather than a flatten /
    # re-box sequence. Dialogs are the deliberate elevation exception.
    assert _desktop_rule_count(DASHBOARD_CSS, '[data-testid="stForm"]') == 1
    assert _desktop_rule_count(DASHBOARD_CSS, 'div[data-testid="stExpander"]') == 1
    assert _desktop_rule_count(DASHBOARD_CSS, '.rt-kpi-strip') == 1
    dialog = _effective_declarations(DASHBOARD_CSS, 'div[role="dialog"]')
    assert dialog["box-shadow"] == "var(--rt-shadow-dialog)!important"

    # Dense controls and review lanes have explicit responsive contracts.
    assert 'st-key-card-sort-' in DASHBOARD_CSS
    assert 'st-key-card-display-' in DASHBOARD_CSS
    assert 'st-key-home-review-lane-' in DASHBOARD_CSS
    assert "flex-wrap:wrap!important" in DASHBOARD_CSS

    # Primary and secondary actions remain visually distinct and every native
    # widget stays present. The refinement layer must not hide button/control
    # families to achieve a cleaner screenshot.
    assert '.stButton > button:not([kind="primary"])' in DASHBOARD_CSS
    assert ".stButton {display:none" not in DASHBOARD_CSS
    assert ".stButton > button {display:none" not in DASHBOARD_CSS
    assert '[data-testid="stForm"] {display:none' not in DASHBOARD_CSS
    assert 'input {visibility:hidden' not in DASHBOARD_CSS

    # Theme switching changes semantic colours only; it cannot fork geometry
    # or reintroduce a second navigation/control design.
    assert '[data-testid="stForm"]' not in ARACHNE_LIGHT_CSS
    assert 'st-key-nav_btn_' not in ARACHNE_LIGHT_CSS
    assert '.rt-kpi' not in ARACHNE_LIGHT_CSS


def test_main_content_stays_inside_streamlit_sidebar_layout():
    declarations = _effective_declarations(
        DASHBOARD_CSS, 'section[data-testid="stMain"]',
    )
    assert declarations["position"] == "relative!important"
    assert declarations["inset"] == "auto!important"
    assert declarations["width"] == "100%!important"
    assert declarations["min-width"] == "0!important"
    assert _desktop_rule_count(
        DASHBOARD_CSS, 'section[data-testid="stMain"]',
    ) == 1


def test_primary_action_text_keeps_contrast_in_both_themes():
    assert '.stButton > button[kind="primary"] *' in DASHBOARD_CSS
    assert "-webkit-text-fill-color:#fff!important" in DASHBOARD_CSS
    assert 'button[kind="primary"] *' not in ARACHNE_LIGHT_CSS


def test_card_tabs_and_dialogs_have_dense_responsive_contracts():
    assert "min-height:132px!important" in DASHBOARD_CSS
    assert "border-bottom:1px solid var(--rt-line)!important" in DASHBOARD_CSS
    assert "[data-baseweb=\"tab-list\"]" in DASHBOARD_CSS
    assert "overflow-x:auto" in DASHBOARD_CSS
    assert 'div[role="dialog"] {' in DASHBOARD_CSS
    assert "max-height:92vh" in DASHBOARD_CSS


def test_anonymous_screen_is_generic_but_existing_activation_still_unlocks_input(isolated_db):
    dashboard_auth.set_dashboard_lock_enabled(True, "pytest")
    waiting = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    waiting_text = " ".join(str(item.value) for item in waiting.markdown)
    assert waiting.text_input[0].disabled is True
    assert "Workspace access" in waiting_text and "No active code" in waiting_text
    assert "Waiting for an active code" in waiting_text
    sensitive_terms = ("Arachne", "Telegram", "intelligence", "onion", "Tor", "crawler", "bot")
    assert all(not re.search(rf"\b{re.escape(term)}\b", waiting_text, re.IGNORECASE)
               for term in sensitive_terms)

    dashboard_auth.generate_dashboard_code(900, 123)
    active = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    active_text = " ".join(str(item.value) for item in active.markdown)
    assert active.text_input[0].disabled is False
    assert "Code available" in active_text and "Code is active" in active_text
    assert active_text != waiting_text
    assert all(not re.search(rf"\b{re.escape(term)}\b", active_text, re.IGNORECASE)
               for term in sensitive_terms)
