from pathlib import Path

from streamlit.testing.v1 import AppTest

import storage
from dashboard_pages.workspace import PAGE_SLUGS, PRIMARY_NAV_PAGES


ROOT = Path(__file__).parents[1]


def test_control_center_renders_health_and_safe_actions(isolated_db):
    storage.start_worker()
    storage.set_worker_paused(False)
    storage.heartbeat_worker_instance("fetch-test", "fetch", state="idle", processed_increment=2)

    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    assert not app.exception

    app.sidebar.radio[0].set_value("Control Center").run()
    assert not app.exception

    text = "\n".join(str(item.value) for item in [*app.markdown, *app.caption])
    assert "operations" in text.casefold()
    assert "Queue pressure" in text
    assert "Worker instances" in text
    assert "Access, backups and privacy" in text
    assert "Access codes are created outside the web interface" in text
    assert not any("Generate code" in str(button.label) for button in app.button)


def test_visual_sidebar_uses_in_place_buttons_not_raw_links(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    assert not app.exception

    rendered = "\n".join(str(item.value) for item in app.markdown)
    assert "<a class=\"rt-nav-item" not in rendered
    assert "href=\"?nav=" not in rendered
    assert "page=Control Center" not in rendered
    operations = next(item for item in app.button if str(item.key) == "nav_btn_control")
    assert str(operations.label) == "⚙  Operations"


def test_visual_sidebar_buttons_navigate_without_falling_home(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    assert not app.exception

    visual_keys = {
        page: ("sidebar-add-source" if page == "Add Onion" else f"nav_btn_{slug}")
        for page, slug in PAGE_SLUGS.items()
    }
    for page in ("Add Onion", *PRIMARY_NAV_PAGES[1:], "Connections", "Timeline", "Actors",
                 "Identity Signals", "Quality Center", "Watchlist", "Daily Activity",
                 "Advanced", "Settings", "FAQ"):
        button = next(item for item in app.button if str(item.key) == visual_keys[page])
        button.click().run()
        assert not app.exception
        nav = app.query_params.get("nav")
        assert (nav[0] if isinstance(nav, list) else nav) == PAGE_SLUGS[page]
        assert app.session_state["nav_page"] == page
