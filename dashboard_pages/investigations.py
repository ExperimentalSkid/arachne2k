"""Saved, reusable Site Card filter scopes."""
from __future__ import annotations

import html
import json

import storage
import dashboard_auth
from dashboard_services.i18n import category_label, current_language, value_label
from ui_components import empty_state, page_lead, section_header


_BUILTIN_WATCHLIST_ES = {
    "Spain · Needs review": (
        "España · Pendiente de revisión",
        "Resultados vinculados a España pendientes de revisión",
    ),
    "Spain · Weapons": (
        "España · Armas",
        "Contexto de armas vinculado a España",
    ),
    "High risk · Unreviewed": (
        "Riesgo alto · Sin revisar",
        "Resultados de riesgo alto o crítico pendientes de revisión",
    ),
    "Fraud and carding": (
        "Fraude financiero y carding",
        "Mercados y páginas relacionados con fraude",
    ),
    "Leaks and credentials": (
        "Filtraciones y credenciales",
        "Posibles resultados con datos expuestos y credenciales",
    ),
    "New discoveries": (
        "Nuevos descubrimientos",
        "Fichas de sitio más recientes",
    ),
}


def _watchlist_display_text(row: dict, language: str) -> tuple[str, str]:
    """Return localized built-in labels without changing canonical stored data."""
    name = str(row.get("name") or "")
    description = str(row.get("description") or "")
    if language == "es" and bool(row.get("builtin")):
        localized = _BUILTIN_WATCHLIST_ES.get(name)
        if localized is not None:
            return localized
    return name, description


def _apply(filters: dict) -> None:
    import streamlit as st
    from dashboard_pages.workspace import _open_workspace_page
    _open_workspace_page("Site Cards")
    mapping = {
        "category": "category-filter-False", "priority": "priority-filter-False",
        "risk": "risk-filter-False", "importance": "importance-filter-False",
        "review": "review-filter-False", "operational": "operational-filter-False",
        "sort": "card-sort-False", "search": "card-search-False",
    }
    defaults = {"category": "All", "priority": "All", "risk": "All", "importance": "All",
                "review": "All", "operational": "All", "sort": "Needs review first", "search": ""}
    for key, widget in mapping.items():
        st.session_state[widget] = filters.get(key, defaults[key])
    if str(filters.get("priority") or "").startswith("Spain"):
        st.session_state["show-results-spain-tools"] = True
    st.session_state["card-page-False"] = 1


def _filter_summary(filters: dict, language: str) -> str:
    """Render readable chips while keeping the exact filter data available."""
    labels = {
        "category": ("Category", "Categoría"),
        "priority": ("Focus", "Enfoque"),
        "risk": ("Risk", "Riesgo"),
        "importance": ("Importance", "Importancia"),
        "review": ("Review", "Revisión"),
        "operational": ("Status", "Estado"),
        "sort": ("Order", "Orden"),
        "search": ("Search", "Búsqueda"),
    }
    chips: list[str] = []
    for key, value in filters.items():
        if value in (None, "", "All"):
            continue
        english, spanish = labels.get(str(key), (str(key).replace("_", " ").title(),) * 2)
        label = spanish if language == "es" else english
        shown = category_label(value, language) if key == "category" else value_label(value, language)
        chips.append(
            f'<span class="rt-filter-chip"><b>{html.escape(label)}</b>'
            f'{html.escape(str(shown))}</span>'
        )
    if chips:
        return '<div class="rt-filter-summary">' + "".join(chips) + "</div>"
    return (
        '<div class="rt-filter-summary"><span class="rt-filter-chip"><b>'
        + ("Vista" if language == "es" else "View")
        + "</b>"
        + ("Todos los resultados" if language == "es" else "All results")
        + "</span></div>"
    )


def render(st, query) -> None:
    from dashboard_pages.workspace import _authorize_action, _can

    language = current_language(st)
    es = language == "es"
    can_manage = _can(st, dashboard_auth.CAPABILITY_WATCHLIST_MANAGE)
    st.markdown(
        page_lead(
            "Lista de seguimiento" if es else "Watchlist",
            "Abre ámbitos frecuentes con un clic. No modifica datos ni inicia rastreos."
            if es else
            "Open common review scopes in one click. This never changes data or starts a crawl.",
            eyebrow="Ámbitos guardados" if es else "Saved scopes",
            aside="Solo filtros" if es else "Filters only",
            show_title=False,
        ),
        unsafe_allow_html=True,
    )
    rows = storage.get_saved_investigations()
    st.markdown(
        section_header(
            "Vistas guardadas" if es else "Saved views",
            "Abre un conjunto de filtros sin cambiar los resultados almacenados."
            if es else
            "Open a filter set without changing stored results.",
            count=len(rows),
        ),
        unsafe_allow_html=True,
    )
    if not rows:
        st.markdown(
            empty_state(
                "No hay vistas guardadas" if es else "No saved views",
                "Crea una vista para reutilizar una combinación de filtros."
                if es else
                "Create a view to reuse a filter combination.",
            ),
            unsafe_allow_html=True,
        )
    for row in rows:
        try:
            filters = json.loads(row.get("filters_json") or "{}")
        except (TypeError, ValueError):
            filters = {}
        display_name, display_description = _watchlist_display_text(row, language)
        with st.container(border=True):
            left, action = st.columns([5, 1])
            left.markdown(f"#### {display_name}")
            left.caption(display_description or ("Vista guardada" if es else "Saved view"))
            left.markdown(_filter_summary(filters, language), unsafe_allow_html=True)
            with left.expander("Detalles técnicos del filtro" if es else "Technical filter details"):
                st.code(" · ".join(f"{key}: {value}" for key, value in filters.items()) or "All results", language=None)
            action.button("Abrir" if es else "Open", key=f"open-investigation-{row['id']}",
                          on_click=_apply, args=(filters,), width="stretch")
            if not row.get("builtin"):
                if action.button("Eliminar" if es else "Delete", key=f"delete-investigation-{row['id']}",
                                 width="stretch", disabled=not can_manage) and _authorize_action(
                                     st, dashboard_auth.CAPABILITY_WATCHLIST_MANAGE):
                    storage.delete_investigation(int(row["id"])); st.rerun()
    with st.expander("Crear vista guardada" if es else "Create a watchlist view"):
        with st.form("create-investigation"):
            name = st.text_input("Nombre" if es else "Name")
            description = st.text_input("Descripción" if es else "Description")
            category = st.selectbox("Categoría" if es else "Category",
                                    ["All", "weapons_arms", "fraud_financial", "drugs", "leaks_data",
                                     "credentials", "malware_hacking", "marketplace", "forum_social",
                                     "directory_index", "hosting_services"])
            priority = st.selectbox("Enfoque" if es else "Focus",
                                    ["All", "Spain Priority", "Spain + weapons", "Spain + drugs",
                                     "Spain + carding/fraud", "High risk", "Needs review",
                                     "Weapons / drugs", "Leaks / credentials", "Marketplaces"])
            risk = st.selectbox("Riesgo" if es else "Risk", ["All", "low", "medium", "high", "critical"])
            review = st.selectbox("Revisión" if es else "Review", ["All", "pending", "needs_review",
                                                                            "needs_report", "reported"])
            submitted = st.form_submit_button(
                "Guardar" if es else "Save",
                width="stretch",
                disabled=not can_manage,
            )
        if submitted and _authorize_action(st, dashboard_auth.CAPABILITY_WATCHLIST_MANAGE):
            storage.save_investigation(name, description, {"category": category, "priority": priority,
                                                            "risk": risk, "review": review})
            st.rerun()
