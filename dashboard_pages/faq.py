"""Plain-language FAQ for the workspace."""
from __future__ import annotations

import html

from config_loader import get_bool, runtime_setting_source
from dashboard_services.i18n import current_language
from screenshot_service import screenshot_support_status
from ui_components import section_header


def _card(st, title: str, body: str, *, tone: str = "plain") -> None:
    st.markdown(
        f"""
        <div class="faq-card faq-card-{html.escape(tone)}">
          <div class="faq-card-title">{html.escape(title)}</div>
          <div class="faq-card-body">{html.escape(body)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _section(st, title: str, intro: str) -> None:
    st.markdown(section_header(title, intro), unsafe_allow_html=True)


def render(st) -> None:
    es = current_language(st) == "es"
    st.markdown(
        f"""
        <div class="faq-hero">
          <p>{html.escape(
            "Ayuda rápida para saber qué mirar, qué significa cada estado y dónde cambiar cosas sin tocar el servidor."
            if es else
            "Quick help for what to check, what each state means, and where to change things without digging through the server."
          )}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    from dashboard_pages.workspace import _open_workspace_page
    st.button("Volver a Ajustes" if es else "Back to Settings",
              on_click=_open_workspace_page, args=("Settings",), key="faq-back-settings")

    available, preview_reason = screenshot_support_status()
    preview_on = get_bool("ENABLE_PAGE_SCREENSHOTS", False)
    preview_source = runtime_setting_source("ENABLE_PAGE_SCREENSHOTS")
    preview_status = (
        f"{'Disponible' if available else 'Desactivado'}; valor efectivo "
        f"{'ACTIVO' if preview_on else 'DESACTIVADO'} desde {preview_source}."
        if es else
        f"{'Available' if available else 'Off'}; effective value "
        f"{'ON' if preview_on else 'OFF'} from {preview_source}. Support check: {preview_reason}."
    )

    sections = [
        (
            "Empieza aquí" if es else "Start here",
            "Las tres ideas que hacen que el panel sea más fácil." if es else "The three ideas that make the console easier to use.",
            [
                (
                    "¿Qué es una ficha?" if es else "What is a Site Card?",
                    "Agrupa un sitio onion, sus rutas, espejos y señales públicas seguras en un solo elemento. Revisa la ficha; entra en técnico solo cuando necesites detalle."
                    if es else
                    "It groups one onion site, its paths, mirrors and safe public signals into one review item. Review the card first; open technical details only when needed.",
                    "work",
                ),
                (
                    "¿Dónde trabajo normalmente?" if es else "Where should I work most of the time?",
                    "Resumen para la vista general, Bandeja de revisión para decisiones pendientes, Sitios para fichas, Prioridad España para elementos marcados, Colección para el progreso y Centro de calidad para clasificaciones dudosas."
                    if es else
                    "Overview for the summary, Review Inbox for pending decisions, Sites for Site Cards, Spain Priority for marked Spain-linked items, Collection for progress, and Quality Center for uncertain classification.",
                    "work",
                ),
                (
                    "¿Riesgo o importancia?" if es else "Risk or importance?",
                    "Riesgo lo decide la política. Importancia es tu prioridad manual. Cambiar importancia no cambia la evidencia ni la categoría."
                    if es else
                    "Risk is policy-driven. Importance is your manual priority. Changing importance does not change signals or category.",
                    "safe",
                ),
            ],
        ),
        (
            "Rastreo y proceso" if es else "Crawling and processing",
            "Cómo pasa una página desde la cola hasta una ficha." if es else "How a page moves from the queue into a Site Card.",
            [
                (
                    "¿Cómo se procesa una página?" if es else "How is a page processed?",
                    "Primero se recoge la página permitida, después se clasifica y, por último, sus señales se agrupan en una ficha. Las vistas solo se crean cuando la política lo permite."
                    if es else
                    "First the allowed page is collected, then it is classified, and finally its signals are grouped into a Site Card. Previews are created only when policy allows.",
                    "work",
                ),
                (
                    "¿Un link list se termina en una página?" if es else "Does a link list stop at one page?",
                    "No debería. Directorios y link lists útiles pasan enlaces onion como semillas superficiales, con límites y filtros de seguridad."
                    if es else
                    "It should not. Useful directories and link lists pass onion links forward as shallow seeds, within limits and safety filters.",
                    "work",
                ),
                (
                    "¿La rotación Tor cancela un rastreo?" if es else "Does Tor rotation cancel an active crawl?",
                    "No. La rotación se comprueba entre páginas. La página activa termina y se guarda antes de cambiar circuito."
                    if es else
                    "No. Rotation is checked between pages. The active page finishes and is stored before circuit rotation.",
                    "safe",
                ),
            ],
        ),
        (
            "Clasificación y revisión" if es else "Classification and review",
            "Cómo evitar pelearte con falsos positivos todo el día." if es else "How to avoid fighting false positives all day.",
            [
                (
                    "¿Por qué una ficha dice desconocido?" if es else "Why does a card say unknown?",
                    "El sistema prefiere desconocido antes que inventar una categoría con señales débiles. Usa Calidad para ver evidencia y contradicciones."
                    if es else
                    "The system prefers unknown over inventing a category from weak signals. Use Quality Center to see signals and contradictions.",
                    "warn",
                ),
                (
                    "¿Cómo corrijo una ficha?" if es else "How do I correct a Site Card?",
                    "Abre los detalles en Sitios. Puedes cambiar título, categoría, importancia, estado, crear un informe, volver a comprobar o silenciar duplicados."
                    if es else
                    "Open details in Sites. You can change title, category, importance, review state, create a report, re-check, or suppress duplicate alerts.",
                    "work",
                ),
                (
                    "¿El título manual cambia las señales?" if es else "Does a manual title change signals?",
                    "No. Solo cambia la etiqueta del panel. URL, categoría, riesgo, prioridad España y evidencia quedan intactos."
                    if es else
                    "No. It only changes the dashboard label. URL, category, risk, Spain Priority and signals stay unchanged.",
                    "safe",
                ),
            ],
        ),
        (
            "España, alertas y urgencia" if es else "Spain, alerts and urgency",
            "Cuándo algo debe saltar de verdad." if es else "When something should really stand out.",
            [
                (
                    "¿/es/ significa Prioridad España?" if es else "Does /es/ mean Spain Priority?",
                    "No. /es/ solo indica idioma. Prioridad España exige contexto real: país, ciudad, objetivo, alias, vendedor, envío o institución española."
                    if es else
                    "No. /es/ only means language. Spain Priority needs real context: country, city, target, alias, seller, shipping or Spanish institution signal.",
                    "safe",
                ),
                (
                    "¿Cómo paro una avalancha de alertas?" if es else "How do I stop an alert burst?",
                    "Usa el control del bot para pausar alertas España. La cola se conserva y el bot sigue disponible para códigos."
                    if es else
                    "Use the bot control to pause Spain alerts. The queue is retained and the bot stays available for access codes.",
                    "hot",
                ),
                (
                    "¿Por qué una alerta desaparece al abrirla?" if es else "Why does an alert disappear after opening it?",
                    "Abrir manualmente una ficha confirma que ya la viste. La evidencia queda guardada; solo baja el ruido del panel."
                    if es else
                    "Opening a card manually marks it as seen. Signals remain stored; only dashboard noise is reduced.",
                    "safe",
                ),
            ],
        ),
        (
            "Seguridad y contenido restringido" if es else "Safety and restricted content",
            "Qué se oculta y por qué." if es else "What is hidden and why.",
            [
                (
                    "¿Un enlace adulto bloquea todo el directorio?" if es else "Does one adult link block an entire directory?",
                    "No. Padre e hijos se clasifican por separado. El hijo restringido se bloquea; los enlaces seguros del directorio siguen."
                    if es else
                    "No. Parent and children are classified separately. The restricted child is blocked; safe directory links continue.",
                    "safe",
                ),
                (
                    "¿Dónde veo falsos positivos adultos?" if es else "Where do I review adult false positives?",
                    "Resumen tiene el botón para revisar o corregir filtros de adultos. Avanzado puede mostrar solo metadatos mínimos: URL, fechas, fuente y razón."
                    if es else
                    "Overview has the button to review or correct adult filters. Advanced can show only minimal metadata: URL, dates, source and reason.",
                    "warn",
                ),
                (
                    "¿Qué pasa con vistas previas?" if es else "What about previews?",
                    preview_status + (" No se crean previews para contenido restringido, login, carrito, descargas o páginas no elegibles."
                                      if es else
                                      " Previews are never created for restricted content, login, cart, downloads or ineligible pages."),
                    "safe",
                ),
            ],
        ),
        (
            "Servidor y despliegue" if es else "Server and deployment",
            "Qué hacer cuando algo huele raro en producción." if es else "What to do when production smells weird.",
            [
                (
                    "¿Qué hago después de subir archivos?" if es else "What do I run after uploading files?",
                    "En el servidor: cd /root/arachne && bash RUN_AFTER_UPLOAD.sh safe-update. Para solo reiniciar: bash RUN_AFTER_UPLOAD.sh restart."
                    if es else
                    "On the server: cd /root/arachne && bash RUN_AFTER_UPLOAD.sh safe-update. To only restart: bash RUN_AFTER_UPLOAD.sh restart.",
                    "work",
                ),
                (
                    "¿SQLite muestra disk I/O error?" if es else "SQLite shows disk I/O error?",
                    "Ejecuta bash RUN_AFTER_UPLOAD.sh repair-db-io. Hace backup, limpia WAL/SHM stale, arregla permisos y reinicia servicios."
                    if es else
                    "Run bash RUN_AFTER_UPLOAD.sh repair-db-io. It backs up, clears stale WAL/SHM files, fixes permissions and restarts services.",
                    "hot",
                ),
                (
                    "¿Por qué no uso python a secas?" if es else "Why not use plain python?",
                    "En Ubuntu usa .venv/bin/python dentro del proyecto. El sistema puede no tener el alias python instalado."
                    if es else
                    "On Ubuntu use .venv/bin/python inside the project. The system may not have the python alias installed.",
                    "warn",
                ),
            ],
        ),
    ]

    for section_title, intro, cards in sections:
        _section(st, section_title, intro)
        columns = st.columns(3)
        for index, (title, body, tone) in enumerate(cards):
            with columns[index % 3]:
                _card(st, title, body, tone=tone)
