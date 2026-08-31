"""Unified metadata-safe monitoring timeline."""
from __future__ import annotations

import html
import json

import storage
from dashboard_pages import site_directory
from dashboard_services.i18n import category_label, current_language, value_label
from ui_components import empty_state, page_lead, section_header


def _t(language: str, english: str, spanish: str) -> str:
    return spanish if language == "es" else english


def _safe_meta(raw: str | None) -> list[str]:
    try:
        data = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    keys = (
        "url", "url_count", "reason", "spain_flow", "marketplace_category",
        "previous_category", "current_category", "confidence",
    )
    return [
        f"{key.replace('_', ' ')}: {data[key]}"
        for key in keys
        if data.get(key) not in (None, "")
    ][:5]


def render(st, query) -> None:
    language = current_language(st)
    st.markdown(
        page_lead(
            _t(
                language,
                "Follow what changed, what connected, and what was reviewed",
                "Sigue qué cambió, qué se conectó y qué fue revisado",
            ),
            _t(
                language,
                "Chronology is built from stored metadata and audit events only.",
                "La cronología se crea solo con metadatos y eventos de auditoría guardados.",
            ),
            eyebrow=_t(language, "Activity timeline", "Cronología de actividad"),
            aside=_t(language, "Audit events", "Eventos de auditoría"),
            show_title=False,
        ),
        unsafe_allow_html=True,
    )
    events = storage.get_intelligence_timeline(300)
    if not events:
        st.markdown(
            empty_state(
                _t(language, "No timeline events yet", "Todavía no hay eventos"),
                _t(
                    language,
                    "Site, entity, review, and change events will appear here in time order.",
                    "Los eventos de sitios, entidades, revisiones y cambios aparecerán aquí por fecha.",
                ),
            ),
            unsafe_allow_html=True,
        )
        return

    families = sorted({str(event.get("event_family") or "unknown") for event in events})
    selected = st.selectbox(
        _t(language, "Event type", "Tipo de evento"),
        ["All"] + families,
        key="timeline-family",
        format_func=lambda value: (
            "All" if value == "All" and language == "en"
            else "Todo" if value == "All"
            else value.replace("_", " ").title()
        ),
    )
    if selected != "All":
        events = [event for event in events if str(event.get("event_family") or "unknown") == selected]

    cols = st.columns(4)
    cols[0].metric(_t(language, "Events shown", "Eventos visibles"), len(events))
    cols[1].metric(_t(language, "Site events", "Eventos de sitios"),
                   sum(1 for event in events if event.get("event_family") == "site_card"))
    cols[2].metric(_t(language, "Alias events", "Eventos de alias"),
                   sum(1 for event in events if event.get("event_family") == "actor"))
    cols[3].metric(_t(language, "Changes", "Cambios"),
                   sum(1 for event in events if event.get("event_family") == "page_change"))

    st.markdown(
        section_header(
            _t(language, "Event stream", "Flujo de eventos"),
            _t(
                language,
                "Newest policy-visible audit events appear first.",
                "Los eventos de auditoría visibles más recientes aparecen primero.",
            ),
            count=len(events),
        ),
        unsafe_allow_html=True,
    )
    st.markdown('<div class="rt-timeline">', unsafe_allow_html=True)
    for index, event in enumerate(events[:200]):
        family = str(event.get("event_family") or "unknown")
        summary = str(event.get("summary") or event.get("event_type") or family)
        title = summary
        if event.get("analyst_title") or event.get("display_name"):
            title = f"{event.get('analyst_title') or event.get('display_name')} · {summary}"
        meta = _safe_meta(event.get("safe_metadata_json"))
        badges = [family.replace("_", " ").title(),
                  str(event.get("event_type") or "").replace("_", " ").title()]
        if event.get("primary_category"):
            badges.append(category_label(event.get("primary_category"), language))
        if event.get("risk_level"):
            badges.append(value_label(event.get("risk_level"), language))
        if event.get("spain_priority"):
            badges.append("Spain")
        st.markdown(
            f'<div class="rt-timeline-item"><div class="rt-timeline-dot"></div>'
            f'<div class="rt-timeline-time">{html.escape(str(event.get("ts") or "unknown"))}</div>'
            f'<div class="rt-timeline-title">{html.escape(title)}</div>'
            f'<div class="rt-timeline-meta">{html.escape(" · ".join(filter(None, badges)))}</div>'
            + (f'<div class="rt-timeline-note">{html.escape(" · ".join(meta))}</div>' if meta else "")
            + '</div>',
            unsafe_allow_html=True,
        )
        if event.get("site_card_id"):
            if st.button(_t(language, "Open Site Card", "Abrir ficha"),
                         key=f"timeline-open-{index}-{event['site_card_id']}"):
                site_directory.open_card(int(event["site_card_id"]), False)
                st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)
