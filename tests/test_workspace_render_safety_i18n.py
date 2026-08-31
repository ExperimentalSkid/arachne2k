from pathlib import Path
from types import SimpleNamespace

from streamlit.testing.v1 import AppTest

import consistency
from dashboard_pages import workspace
from dashboard_services.i18n import spain_reason_label


ROOT = Path(__file__).parents[1]


def _empty_consistency_audit() -> dict:
    counts = {
        "active_blocked_conflicts": 0,
        "queued_inactive_conflicts": 0,
        "blocked_normal_queue_conflicts": 0,
        "crawled_awaiting_classification": 0,
        "unknown_high_edge_pages": 0,
        "alert_queue_without_url_flag": 0,
        "url_flag_without_site_card_flag": 0,
        "site_card_flag_without_url_support": 0,
    }
    return {"counts": counts, "details": [], "samples": [], "total_conflicts": 0}


def test_advanced_consistency_audit_runs_only_after_explicit_click(
        isolated_db, monkeypatch):
    calls = []

    def _audit():
        calls.append("run")
        return _empty_consistency_audit()

    monkeypatch.setattr(consistency, "audit_consistency", _audit)
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "advanced"
    app.run()

    assert not app.exception
    assert calls == []
    rendered = " ".join(str(item.value) for item in app.markdown)
    assert "Consistency audit not run" in rendered

    run_button = next(
        item for item in app.button
        if str(item.key) == "advanced-run-consistency-audit"
    )
    run_button.click().run()

    assert not app.exception
    assert calls == ["run"]
    assert any("Last run in this session:" in str(item.value) for item in app.caption)

    app.run()
    assert not app.exception
    assert calls == ["run"]


def test_spanish_operations_copy_is_localized_and_has_no_raw_none_state(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "control"
    app.run()
    app.sidebar.toggle[0].set_value(True).run()

    assert not app.exception
    rendered = " ".join(
        str(item.value) for item in [*app.markdown, *app.caption]
    )
    labels = " ".join(
        str(item.label) for item in [*app.metric, *app.checkbox, *app.button]
    )
    assert "Procesos activos" in rendered
    assert "Recopilación · Verificación · Fichas" in rendered
    assert "Procesos de trabajo" in rendered
    assert "Reintentos o fallos de verificación" in labels
    assert "Reintentos o fallos de fichas" in labels
    assert "trabajos fallidos de verificación o fichas" in labels
    assert "Workers de proceso" not in rendered
    assert "Fetch · Verify" not in rendered
    pause_caption = next(
        str(item.value) for item in app.caption
        if "Estado pausa legado:" in str(item.value)
    )
    assert "none" not in pause_caption.casefold()
    assert "ninguno registrado" in pause_caption.casefold()


def _rendered_text(app) -> str:
    values = []
    for collection_name in (
        "markdown", "caption", "info", "success", "warning", "error", "metric", "expander"
    ):
        for item in getattr(app, collection_name, []):
            values.append(str(getattr(item, "value", "")))
            values.append(str(getattr(item, "label", "")))
    for collection_name in (
        "button", "checkbox", "toggle", "text_input", "selectbox", "multiselect"
    ):
        values.extend(str(item.label) for item in getattr(app, collection_name, []))
    return " ".join(values)


def test_spanish_advanced_default_and_option_labels_are_localized(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "advanced"
    app.run()
    app.sidebar.toggle[0].set_value(True).run()

    assert not app.exception
    selector = next(item for item in app.selectbox if item.key == "advanced_tool")
    assert selector.label == "Herramienta avanzada"
    assert selector.value == "Centro de consistencia"
    assert "Centro de consistencia" in selector.options
    assert "Estado OPSEC" in selector.options
    assert "Grupos de sitios relacionados" in selector.options
    assert "Seguridad y configuración" in selector.options
    rendered = _rendered_text(app)
    assert "Centro de consistencia" in rendered
    assert "Auditoría de consistencia sin ejecutar" in rendered
    assert "Ejecutar auditoría de consistencia" in rendered
    assert "Consistency audit not run" not in rendered


def test_spanish_settings_shared_opsec_panel_is_localized(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "settings"
    app.run()
    app.sidebar.toggle[0].set_value(True).run()

    assert not app.exception
    labels = [str(item.label) for item in app.metric]
    assert "Enrutamiento socks5h" in labels
    assert "Aislamiento SOCKS" in labels
    assert "Inicio estricto" in labels
    rendered = _rendered_text(app)
    assert "Seguridad de vistas previas" in rendered
    assert "Última auditoría en vivo" in rendered
    assert "Direct-fetch scan" not in rendered


def test_spanish_advanced_related_sites_and_setup_render_translated_choices(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "advanced"
    app.run()
    app.sidebar.toggle[0].set_value(True).run()

    selector = next(item for item in app.selectbox if item.key == "advanced_tool")
    selector.set_value("Grupos de sitios relacionados").run()
    assert not app.exception
    rendered = _rendered_text(app)
    assert "Sitios relacionados" in rendered
    assert "Todavía no se han encontrado grupos de sitios relacionados" in rendered

    selector = next(item for item in app.selectbox if item.key == "advanced_tool")
    selector.set_value("Seguridad y configuración").run()
    assert not app.exception
    rendered = _rendered_text(app)
    assert "Configuración y seguridad" in rendered
    assert "Servicios de procesamiento" in rendered
    assert "Configuración del servidor" in rendered
    assert "Garantías de seguridad" in rendered
    assert "Setup and safety" not in rendered


def test_spanish_home_health_uses_product_language_not_worker_jargon(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "home"
    app.run()
    app.sidebar.toggle[0].set_value(True).run()

    assert not app.exception
    rendered = " ".join(
        str(item.value) for item in [*app.markdown, *app.caption]
    )
    assert "Procesos de recopilación" in rendered
    assert "Procesos de verificación" in rendered
    assert "Procesos de fichas" in rendered
    assert "flujo por etapas" in rendered
    assert "Workers de" not in rendered
    assert "Workers activos" not in rendered
    assert "Workers por etapas" not in rendered
    assert "worker por etapas" not in rendered
    assert "pipeline por etapas" not in rendered


def test_spain_reason_display_is_bilingual_without_changing_stored_value():
    stored = "Spain reference paired with seller, actor, or market context"
    assert spain_reason_label(stored, "en") == stored
    assert spain_reason_label(stored, "es") == (
        "Referencia a España junto con contexto de vendedor, actor o mercado"
    )
    assert spain_reason_label(None, "es") == "Contexto de prioridad España"


def test_spanish_collapsed_add_onion_label_and_entity_subtitle_are_accessible(
        isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "add"
    app.run()
    app.sidebar.toggle[0].set_value(True).run()

    assert not app.exception
    onion_input = next(
        item for item in app.text_input
        if str(item.key) == "dedicated-add-onion"
    )
    assert onion_input.label == "Nueva dirección onion"

    fake = SimpleNamespace(session_state={"ui_spanish": True})
    assert workspace._page_subtitle(fake, "Entity Intelligence") == (
        "Revisar alias públicos, evidencia, relaciones y expansión limitada"
    )
