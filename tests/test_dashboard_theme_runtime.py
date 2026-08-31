from pathlib import Path

import config_loader
from streamlit.testing.v1 import AppTest

from dashboard_pages import workspace


ROOT = Path(__file__).parents[1]


class _FakeStreamlit:
    def __init__(self, *, session=None, query=None):
        self.session_state = dict(session or {})
        self.query_params = dict(query or {})


def _query_scalar(value):
    return value[0] if isinstance(value, list) else value


def test_sidebar_keeps_language_then_theme_toggle_order(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()

    assert not app.exception
    assert len(app.sidebar.toggle) >= 2
    assert app.sidebar.toggle[0].key == "ui_spanish"
    assert app.sidebar.toggle[1].key == "ui_dark_mode"


def test_theme_resolution_prefers_query_then_session_then_runtime(monkeypatch):
    monkeypatch.setattr(workspace, "get_str", lambda key, default=None: "light")
    query = _FakeStreamlit(session={"ui_theme": "light"}, query={"theme": "dark"})

    assert workspace._resolve_ui_theme(query) == "dark"
    assert query.session_state["ui_theme"] == "dark"
    assert query.session_state["ui_dark_mode"] is True

    session = _FakeStreamlit(session={"ui_theme": "light"})
    monkeypatch.setattr(workspace, "get_str", lambda key, default=None: "dark")
    assert workspace._resolve_ui_theme(session) == "light"
    assert session.session_state["ui_dark_mode"] is False

    runtime = _FakeStreamlit()
    monkeypatch.setattr(workspace, "get_str", lambda key, default=None: "light")
    assert workspace._resolve_ui_theme(runtime) == "light"
    assert runtime.session_state["ui_dark_mode"] is False


def test_theme_normalization_supports_legacy_graphite_without_exposing_it():
    assert workspace._normalize_ui_theme("graphite") == "dark"
    assert workspace._normalize_ui_theme(" GRAPHITE ") == "dark"
    assert workspace._normalize_ui_theme("dark") == "dark"
    assert workspace._normalize_ui_theme("LIGHT") == "light"
    assert workspace._normalize_ui_theme("system") is None
    assert workspace._normalize_ui_theme(None) is None


def test_theme_persistence_preserves_other_query_parameters(monkeypatch):
    saved = []
    monkeypatch.setattr(workspace, "save_runtime_settings", lambda updates: saved.append(updates) or updates)
    st = _FakeStreamlit(
        session={"ui_dark_mode": False, "ui_theme": "dark"},
        query={"theme": "dark", "nav": "cards", "rt_session": "opaque-session"},
    )

    workspace._persist_ui_theme(st)

    assert st.session_state["ui_theme"] == "light"
    assert st.session_state["_ui_theme_query"] == "light"
    assert st.query_params == {
        "theme": "light",
        "nav": "cards",
        "rt_session": "opaque-session",
    }
    assert saved == [{"UI_THEME": "light"}]


def test_app_theme_query_and_toggle_persist_without_moving_language_toggle(
        isolated_db, tmp_path, monkeypatch):
    runtime_path = tmp_path / "runtime_settings.json"
    monkeypatch.setattr(config_loader, "RUNTIME_CONFIG_PATH", runtime_path)
    config_loader.get_config.cache_clear()
    config_loader.save_runtime_settings({"UI_THEME": "dark"})

    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params["theme"] = "light"
    app.query_params["nav"] = "home"
    app.query_params["keep"] = "unchanged"
    app.run()

    assert not app.exception
    assert app.sidebar.toggle[0].key == "ui_spanish"
    assert app.sidebar.toggle[1].key == "ui_dark_mode"
    assert app.sidebar.toggle[1].value is False
    assert any('data-theme="light"' in str(item.value) for item in app.markdown)

    app.sidebar.toggle[1].set_value(True).run()

    assert not app.exception
    assert app.sidebar.toggle[0].key == "ui_spanish"
    assert app.sidebar.toggle[1].value is True
    assert _query_scalar(app.query_params["theme"]) == "dark"
    assert _query_scalar(app.query_params["nav"]) == "home"
    assert _query_scalar(app.query_params["keep"]) == "unchanged"
    assert config_loader.get_runtime_settings()["UI_THEME"] == "dark"
    assert any('data-theme="dark"' in str(item.value) for item in app.markdown)
