"""Daily crawler activity and digest page."""
from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

import daily_activity
import storage
from dashboard_services.i18n import current_language
from ui_components import empty_state, page_lead, section_header


def render(st, query) -> None:
    language = current_language(st)
    es = language == "es"
    st.markdown(
        page_lead(
            "Actividad diaria" if es else "Daily activity",
            "Un resumen sencillo de lo que procesó el sistema y lo que queda pendiente."
            if es else
            "A plain-language summary of what the system processed and what remains.",
            eyebrow="Resumen operativo" if es else "Operations summary",
            aside="Europe/Madrid",
            show_title=False,
        ),
        unsafe_allow_html=True,
    )
    day = st.date_input("Día" if es else "Day", value=datetime.now(ZoneInfo("Europe/Madrid")).date())
    digest = daily_activity.build_daily_digest(day)
    labels = [
        ("Páginas completadas" if es else "Pages completed", "pages_completed"),
        ("Nuevas URLs" if es else "New URLs", "new_urls"),
        ("Nuevas fichas" if es else "New Site Cards", "new_site_cards"),
        ("Cambios importantes" if es else "Meaningful changes", "meaningful_changes"),
        ("Alertas España" if es else "Spain alerts", "spain_alerts"),
        ("Errores" if es else "Fetch errors", "fetch_errors"),
    ]
    for start in (0, 3):
        for col, (label, key) in zip(st.columns(3), labels[start:start + 3], strict=False):
            col.metric(label, int(digest.get(key) or 0))
    st.info((f"Cola restante: {digest['queue_remaining']} · Bloqueadas de forma segura: {digest['blocked_before_fetch']}"
             if es else f"Queue remaining: {digest['queue_remaining']} · Safely blocked: {digest['blocked_before_fetch']}"))
    st.markdown(
        section_header(
            "Actividad reciente" if es else "Recent activity",
            "Acciones registradas para el día seleccionado."
            if es else "Recorded actions for the selected day.",
            count=len(digest["recent_actions"]),
        ),
        unsafe_allow_html=True,
    )
    if not digest["recent_actions"]:
        st.markdown(
            empty_state(
                "No hay actividad para este día" if es else "No activity for this day",
                "Selecciona otra fecha o vuelve cuando los workers hayan procesado trabajos."
                if es else
                "Choose another date or return after workers have processed jobs.",
            ),
            unsafe_allow_html=True,
        )
    else:
        st.dataframe(digest["recent_actions"], width="stretch", hide_index=True)
    with st.expander("Historial de resúmenes" if es else "Saved digest history"):
        rows = storage.get_daily_digests(14)
        if rows:
            st.dataframe([{"date": row["digest_date"], "telegram": row["telegram_status"],
                           **{k: v for k, v in daily_activity.payload_from_row(row).items()
                              if k in {"pages_completed", "new_urls", "new_site_cards", "meaningful_changes", "spain_alerts"}}}
                          for row in rows], width="stretch", hide_index=True)
        else:
            st.markdown(
                empty_state(
                    "No hay resúmenes guardados" if es else "No saved summaries",
                    "Los resúmenes aparecerán después del primer ciclo diario."
                    if es else "Summaries will appear after the first daily cycle.",
                ),
                unsafe_allow_html=True,
            )
