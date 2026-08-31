"""Small, dependency-free English/Spanish UI copy catalogue."""
from __future__ import annotations


COPY = {
    "language": {"en": "ES · Español", "es": "ES · Español activado"},
    "menu_title": {"en": "Workspace", "es": "Espacio de trabajo"},
    "menu_home": {"en": "Home", "es": "Inicio"},
    "menu_crawl": {"en": "Crawl", "es": "Rastreo"},
    "menu_spain": {"en": "Spain Priority", "es": "Prioridad España"},
    "menu_reports": {"en": "Reports", "es": "Informes"},
    "menu_settings": {"en": "Settings", "es": "Ajustes"},
    "page_home": {"en": "Overview", "es": "Resumen"},
    "page_add": {"en": "Add onion", "es": "Añadir onion"},
    "page_queue": {"en": "Collection", "es": "Colección"},
    "page_cards": {"en": "Sites", "es": "Sitios"},
    "page_entities": {"en": "Intelligence", "es": "Inteligencia"},
    "page_connections": {"en": "Connections", "es": "Conexiones"},
    "page_timeline": {"en": "Timeline", "es": "Cronología"},
    "page_actors": {"en": "Public aliases", "es": "Alias públicos"},
    "page_identity": {"en": "Identity signals", "es": "Señales de identidad"},
    "page_spain": {"en": "Spain Priority", "es": "Prioridad España"},
    "page_reports": {"en": "Reports", "es": "Informes"},
    "page_advanced": {"en": "Advanced tools", "es": "Herramientas avanzadas"},
    "page_control": {"en": "Operations", "es": "Operaciones"},
    "page_settings": {"en": "Settings", "es": "Ajustes"},
    "page_faq": {"en": "FAQ", "es": "Preguntas frecuentes"},
    "view_options": {"en": "Display options", "es": "Opciones de visualización"},
    "compact_cards": {"en": "Compact cards", "es": "Fichas compactas"},
    "show_low_info": {"en": "Show empty / low-information cards", "es": "Mostrar fichas vacías o con poca información"},
    "show_monitor": {"en": "Show monitor-only pages", "es": "Mostrar páginas solo monitorizadas"},
    "guided_note": {"en": "Start with what needs attention. Technical details stay folded away until you need them.",
                    "es": "Empieza por lo que necesita atención. Los detalles técnicos permanecen ocultos hasta que los necesites."},
    "hero_title": {"en": "CONSOLE", "es": "CONSOLA"},
    "status_worker": {"en": "Worker", "es": "Trabajador"},
    "status_queue": {"en": "URL queue", "es": "Cola URL"},
    "status_spain": {"en": "ES priority", "es": "Prioridad ES"},
    "status_online": {"en": "online", "es": "activo"},
    "status_offline": {"en": "offline", "es": "inactivo"},
    "environment": {"en": "Environment", "es": "Entorno"},
    "updated": {"en": "Updated", "es": "Actualizado"},
    "current_view": {"en": "View", "es": "Vista"},
    "home_title": {"en": "Start here", "es": "Empieza aquí"},
    "home_services": {"en": "System health", "es": "Estado del sistema"},
    "home_categories": {"en": "What was found", "es": "Qué se encontró"},
    "home_automatic": {"en": "What happens automatically?", "es": "¿Qué ocurre automáticamente?"},
    "home_actions": {"en": "Quick actions", "es": "Acciones rápidas"},
    "home_recent": {"en": "Recently discovered sites", "es": "Sitios descubiertos recientemente"},
    "add_title": {"en": "Add an onion site", "es": "Añadir un sitio onion"},
    "add_address": {"en": "Onion address", "es": "Dirección onion"},
    "add_button": {"en": "Add to crawl queue", "es": "Añadir a la cola de rastreo"},
    "queue_title": {"en": "Crawl queue", "es": "Cola de rastreo"},
    "cards_title": {"en": "Site cards", "es": "Fichas de sitios"},
    "reports_title": {"en": "Reports", "es": "Informes"},
    "advanced_title": {"en": "Advanced tools", "es": "Herramientas avanzadas"},
    "settings_title": {"en": "Settings", "es": "Ajustes"},
    "search_sites": {"en": "Search sites", "es": "Buscar sitios"},
    "sort": {"en": "Sort", "es": "Ordenar"},
    "display": {"en": "Display", "es": "Vista"},
    "page_size": {"en": "Page size", "es": "Tamaño de página"},
    "categories": {"en": "Categories", "es": "Categorías"},
    "priority": {"en": "Priority", "es": "Prioridad"},
    "operational": {"en": "Operational", "es": "Operativo"},
    "previous": {"en": "Previous", "es": "Anterior"},
    "next": {"en": "Next", "es": "Siguiente"},
    "review": {"en": "Review", "es": "Revisar"},
    "show_details": {"en": "Show details", "es": "Mostrar detalles"},
    "actions": {"en": "Actions", "es": "Acciones"},
    "review_domain": {"en": "Review this domain", "es": "Revisar este dominio"},
    "apply_domain": {"en": "Apply to domain tree", "es": "Aplicar al árbol del dominio"},
    "domain_updated": {"en": "Domain review status updated.", "es": "Estado de revisión del dominio actualizado."},
    "page_quality": {"en": "Quality center", "es": "Centro de calidad"},
    "page_activity": {"en": "Daily activity", "es": "Actividad diaria"},
    "page_investigations": {"en": "Watchlist", "es": "Lista de seguimiento"},
    "quality_title": {"en": "Classification Quality Center", "es": "Centro de calidad de clasificación"},
    "quality_intro": {"en": "See what the crawler decided, where it was unsure, how much of each site it covered, and what changed.", "es": "Consulta qué decidió Arachne, dónde tuvo dudas, cuánto cubrió de cada sitio y qué cambió."},
    "quality_accepted": {"en": "Confident decisions", "es": "Decisiones fiables"},
    "quality_accepted_help": {"en": "Classifications supported strongly enough to use automatically.", "es": "Clasificaciones con pruebas suficientes para usarlas automáticamente."},
    "quality_unsure": {"en": "Needs a human", "es": "Necesita revisión"},
    "quality_unsure_help": {"en": "The crawler kept a suggestion but refused to guess.", "es": "Arachne guardó una sugerencia, pero se negó a adivinar."},
    "quality_corrections": {"en": "Corrections made", "es": "Correcciones hechas"},
    "quality_tab_decisions": {"en": "Classification", "es": "Clasificación"},
    "quality_tab_coverage": {"en": "Crawl coverage", "es": "Cobertura"},
    "quality_tab_changes": {"en": "What changed", "es": "Qué cambió"},
    "quality_tab_connections": {"en": "Connections", "es": "Conexiones"},
    "quality_tab_operations": {"en": "Health & export", "es": "Estado y exportación"},
    "quality_review_queue": {"en": "Decisions that need your attention", "es": "Decisiones que necesitan tu atención"},
    "quality_none_uncertain": {"en": "No uncertain classifications are waiting.", "es": "No hay clasificaciones dudosas pendientes."},
    "quality_no_suggestion": {"en": "No safe suggestion", "es": "Sin sugerencia segura"},
    "quality_suggested": {"en": "Suggested category: {category}", "es": "Categoría sugerida: {category}"},
    "quality_open_card": {"en": "Open Site Card to classify", "es": "Abrir ficha para clasificar"},
    "quality_category_summary": {"en": "Decision totals by category", "es": "Decisiones por categoría"},
    "coverage_title": {"en": "How thoroughly each onion was explored", "es": "Cuánto se exploró cada onion"},
    "coverage_help": {"en": "Checked means the worker visited it. Waiting means it is still in the queue. Hidden means safety policy blocked the content.", "es": "Comprobada significa visitada. En espera sigue en cola. Oculta significa bloqueada por seguridad."},
    "coverage_empty": {"en": "Coverage will appear after URLs enter the crawl queue.", "es": "La cobertura aparecerá cuando haya URLs en la cola."},
    "coverage_host": {"en": "Onion site", "es": "Sitio onion"},
    "coverage_progress": {"en": "Checked", "es": "Comprobado"},
    "coverage_checked": {"en": "Pages visited", "es": "Páginas visitadas"},
    "coverage_found": {"en": "Pages found", "es": "Páginas encontradas"},
    "coverage_waiting": {"en": "Waiting", "es": "En espera"},
    "coverage_hidden": {"en": "Safety-hidden", "es": "Ocultas por seguridad"},
    "coverage_stop": {"en": "Current state", "es": "Estado actual"},
    "changes_title": {"en": "Meaningful page changes", "es": "Cambios importantes"},
    "changes_help": {"en": "Only content-hash or category changes are shown; raw page text is never copied here.", "es": "Solo se muestran cambios de huella o categoría; nunca se copia aquí el texto de la página."},
    "changes_empty": {"en": "No meaningful changes have been detected yet.", "es": "Todavía no se detectaron cambios importantes."},
    "connections_card": {"en": "Site Card to map", "es": "Ficha que representar"},
    "connections_empty": {"en": "No safe Site Cards are ready to map.", "es": "No hay fichas seguras listas para representar."},
    "operations_title": {"en": "Worker health and safe sharing", "es": "Estado del trabajador y uso compartido seguro"},
    "operations_help": {"en": "A quick operational check, plus a metadata-only JSON export for other tools.", "es": "Comprobación operativa y exportación JSON solo con metadatos."},
    "operations_worker": {"en": "Worker", "es": "Trabajador"},
    "operations_waiting": {"en": "Waiting", "es": "En espera"},
    "operations_retrying": {"en": "Retrying", "es": "Reintentando"},
    "operations_errors": {"en": "Recorded errors", "es": "Errores registrados"},
    "operations_export_help": {"en": "Export includes onion URLs and aggregate category labels—never snippets, screenshots, or page text.", "es": "La exportación incluye URLs onion y categorías agregadas; nunca fragmentos, capturas ni texto."},
    "operations_export_card": {"en": "Site Card to export", "es": "Ficha que exportar"},
    "operations_export_button": {"en": "Prepare safe JSON export", "es": "Preparar exportación JSON segura"},
    "operations_export_ready": {"en": "Safe JSON export is ready.", "es": "La exportación JSON segura está lista."},
    "operations_download": {"en": "Download JSON", "es": "Descargar JSON"},
    "operations_no_cards": {"en": "No safe Site Cards are ready to export.", "es": "No hay fichas seguras listas para exportar."},
    "brand_subtitle": {"en": "web mapping · review queues · source monitoring",
                       "es": "mapeo web · colas de revisión · seguimiento de fuentes"},
    "menu_intelligence": {"en": "Results", "es": "Resultados"},
    "page_review": {"en": "Review Inbox", "es": "Bandeja de revisión"},
    "review_title": {"en": "Pages to check", "es": "Páginas para revisar"},
    "quality_reviews": {"en": "Manual reviews", "es": "Revisiones manuales"},
    "quality_reviews_help": {"en": "Manual category choices saved in the change history.",
                             "es": "Opciones manuales de categoría guardadas en el historial de cambios."},
    "quality_corrections_help": {"en": "Manual reviews that changed the original category.",
                                 "es": "Revisiones manuales que cambiaron la categoría original."},
    "quality_review_queue_help": {"en": "These pages were not forced into a category. Check only the uncertain items.",
                                  "es": "Estas páginas no se forzaron a una categoría. Revisa solo los elementos dudosos."},
    "quality_needs_evidence": {"en": "More page details are needed.", "es": "Se necesitan más detalles de la página."},
    "quality_window": {"en": "Quality window", "es": "Periodo de calidad"},
    "quality_window_days": {"en": "Last {days} days", "es": "Últimos {days} días"},
    "quality_window_help": {
        "en": "Changes only the quality samples and trends shown on this page.",
        "es": "Solo cambia las muestras y tendencias de calidad que aparecen en esta página.",
    },
    "quality_advisory": {
        "en": "Advisory only. This page observes reviewed samples and rule behaviour; it never changes live classifications, safety filters, Spain Priority, urgency, or crawl decisions.",
        "es": "Solo informativo. Esta página observa muestras revisadas y el comportamiento de las reglas; nunca cambia clasificaciones activas, filtros de seguridad, Prioridad España, urgencia ni decisiones de rastreo.",
    },
    "quality_sample_pages": {
        "en": "Based on {count} unique pages.",
        "es": "Basado en {count} páginas únicas.",
    },
    "quality_unknown_sample": {
        "en": "{percent}% of a {count}-page sample.",
        "es": "{percent}% de una muestra de {count} páginas.",
    },
    "quality_review_sample": {
        "en": "{count} analyst-reviewed outcomes; unreviewed items are excluded.",
        "es": "{count} resultados revisados por un analista; se excluyen los no revisados.",
    },
    "quality_no_review_sample": {
        "en": "No reviewed outcomes in this window; no rate is inferred.",
        "es": "No hay resultados revisados en este periodo; no se calcula ninguna tasa.",
    },
    "quality_correction_sample": {
        "en": "{percent}% across {count} reviewed outcomes.",
        "es": "{percent}% entre {count} resultados revisados.",
    },
    "quality_decision_event_sample": {
        "en": "{decisions} page-decision events across {pages} unique pages in this window.",
        "es": "{decisions} eventos de decisión en {pages} páginas únicas durante este periodo.",
    },
    "quality_improvement_title": {
        "en": "What needs improvement",
        "es": "Qué necesita mejorar",
    },
    "quality_improvement_help": {
        "en": "The strongest recurring signals in the selected window, not a new review queue.",
        "es": "Las señales recurrentes más claras del periodo seleccionado, no una nueva cola de revisión.",
    },
    "quality_improvement_unknown": {
        "en": "Main uncertainty reason",
        "es": "Principal motivo de duda",
    },
    "quality_improvement_unknown_value": {
        "en": "{reason} affected {count} pages.",
        "es": "{reason} afectó a {count} páginas.",
    },
    "quality_improvement_correction": {
        "en": "Most common correction",
        "es": "Corrección más frecuente",
    },
    "quality_improvement_correction_value": {
        "en": "{previous} to {current}, {count} times.",
        "es": "De {previous} a {current}, {count} veces.",
    },
    "quality_improvement_feedback": {
        "en": "Largest reviewed disagreement",
        "es": "Mayor desacuerdo revisado",
    },
    "quality_improvement_feedback_value": {
        "en": "{dimension}: {count} changed outcomes in a reviewed sample of {sample}.",
        "es": "{dimension}: {count} resultados cambiados en una muestra revisada de {sample}.",
    },
    "quality_improvement_empty": {
        "en": "No recurring quality problem is visible yet",
        "es": "Aún no se observa un problema de calidad recurrente",
    },
    "quality_improvement_empty_help": {
        "en": "More reviewed outcomes are needed before a pattern can be shown honestly.",
        "es": "Se necesitan más resultados revisados para mostrar un patrón de forma fiable.",
    },
    "quality_feedback_title": {
        "en": "Reviewed signal outcomes",
        "es": "Resultados de señales revisadas",
    },
    "quality_feedback_help": {
        "en": "Only explicit analyst outcomes are counted. Pending items are excluded, and every rate uses its reviewed sample.",
        "es": "Solo se cuentan resultados explícitos del analista. Las muestras pendientes o sin decisión nunca mejoran la tasa.",
    },
    "quality_feedback_empty": {
        "en": "Reviewed Spain, urgency, restriction, and duplicate samples will appear here.",
        "es": "Aquí aparecerán las muestras revisadas de España, urgencia, restricciones y duplicados.",
    },
    "quality_feedback_sample": {
        "en": "{count} reviewed",
        "es": "{count} revisados",
    },
    "quality_feedback_outcomes": {
        "en": "{confirmed} confirmed; {changed} corrected or rejected.",
        "es": "{confirmed} confirmados; {changed} corregidos o rechazados.",
    },
    "quality_dimension_category": {"en": "Category", "es": "Categoría"},
    "quality_dimension_spain": {"en": "Spain Priority", "es": "Prioridad España"},
    "quality_dimension_urgency": {"en": "Urgency", "es": "Urgencia"},
    "quality_dimension_restriction": {"en": "Safety filter", "es": "Filtro de seguridad"},
    "quality_dimension_dedupe": {"en": "Duplicate grouping", "es": "Agrupación de duplicados"},
    "quality_site_card_identity": {
        "en": "Site Card #{card_id}",
        "es": "Ficha #{card_id}",
    },
    "quality_unassigned_identity": {
        "en": "Not grouped yet",
        "es": "Aún sin agrupar",
    },
    "quality_uncertain_page_count": {
        "en": "{count} uncertain pages",
        "es": "{count} páginas dudosas",
    },
    "quality_confidence_sample": {
        "en": "Strongest suggestion: {confidence}% across {count} grouped pages.",
        "es": "Sugerencia más sólida: {confidence}% entre {count} páginas agrupadas.",
    },
    "quality_page_status": {
        "en": "Page {page} of {pages}",
        "es": "Página {page} de {pages}",
    },
    "quality_correction_patterns": {
        "en": "Common category corrections",
        "es": "Correcciones de categoría frecuentes",
    },
    "quality_correction_count": {
        "en": "{count} reviewed corrections",
        "es": "{count} correcciones revisadas",
    },
    "quality_technical_totals_help": {
        "en": "Legacy event totals are retained for technical comparison and may include repeated decisions.",
        "es": "Los totales históricos se conservan para comparación técnica y pueden incluir decisiones repetidas.",
    },
    "quality_discovered": {"en": "Discovered", "es": "Descubiertas"},
    "quality_discovered_help": {
        "en": "Starting addresses not yet visited.",
        "es": "Direcciones iniciales aún no visitadas.",
    },
    "quality_provisional": {"en": "Provisional", "es": "Provisionales"},
    "quality_provisional_help": {
        "en": "Links found on a page but not visited yet.",
        "es": "Enlaces encontrados en una página, pero aún no visitados.",
    },
    "quality_verified": {"en": "Verified", "es": "Verificadas"},
    "quality_verified_help": {
        "en": "Pages fetched and classified from their own content.",
        "es": "Páginas visitadas y clasificadas a partir de su propio contenido.",
    },
    "quality_tab_shadow": {
        "en": "Shadow observations",
        "es": "Observaciones en sombra",
    },
    "quality_shadow_advisory": {
        "en": "Observation only. Candidate rules are compared with live decisions, but cannot be applied from this page and never alter safety policy.",
        "es": "Solo observación. Las reglas candidatas se comparan con decisiones activas, pero no pueden aplicarse desde esta página ni alterar la política de seguridad.",
    },
    "quality_shadow_empty": {
        "en": "No shadow ruleset is being observed",
        "es": "No se está observando un conjunto de reglas en sombra",
    },
    "quality_shadow_empty_help": {
        "en": "A candidate will appear only after it has produced safe, non-authoritative observations.",
        "es": "Una regla candidata solo aparecerá después de producir observaciones seguras y no autoritativas.",
    },
    "quality_shadow_candidate": {
        "en": "Candidate ruleset",
        "es": "Reglas candidatas",
    },
    "quality_shadow_summary": {
        "en": "{sample} observations; {changed} would differ; {excluded} protected by safety invariants.",
        "es": "{sample} observaciones; {changed} serían distintas; {excluded} protegidas por invariantes de seguridad.",
    },
    "quality_shadow_category_delta": {
        "en": "Live: {current}. Candidate: {candidate}.",
        "es": "Activa: {current}. Candidata: {candidate}.",
    },
    "connections_title": {"en": "Why these pages are grouped", "es": "Por qué se agrupan estas páginas"},
    "connections_help": {"en": "A simple map from the Site Card to onion URLs and shared public signal types. Page content is omitted.",
                         "es": "Mapa sencillo de la ficha a URLs onion y tipos de señales públicas compartidas. Se omite el contenido."},
    "spain_tree_title": {"en": "Spain Priority", "es": "Prioridad España"},
    "spain_tree_help": {"en": "Review Spain-linked sites, public aliases and marketplace sellers from exact pages.",
                        "es": "Revisa sitios, alias públicos y vendedores vinculados con España desde páginas exactas."},
    "show_hits": {"en": "Show pages", "es": "Mostrar páginas"},
    "safe_metadata": {"en": "Spain-linked pages and safe details", "es": "Páginas vinculadas con España y detalles seguros"},
}


# Identity review copy stays in the shared catalogue so the complete workspace
# changes language together. These labels describe evidence and advisory state
# without exposing raw identifiers.
COPY.update({
    "identity_advisory_quality": {"en": "Advisory quality", "es": "Calidad orientativa"},
    "identity_advisory_quality_help": {
        "en": "These signals explain confidence and readiness. They do not replace the live classification.",
        "es": "Estas señales explican la confianza y la preparación. No sustituyen la clasificación activa.",
    },
    "identity_alias_summary": {
        "en": "Observed on {host} · {count} supporting page(s) · {confidence} confidence",
        "es": "Observado en {host} · {count} página(s) de apoyo · confianza {confidence}",
    },
    "identity_aliases_empty": {"en": "No reliable public aliases yet", "es": "Aún no hay alias públicos fiables"},
    "identity_aliases_empty_help": {
        "en": "Generic words and low-confidence fragments are deliberately excluded.",
        "es": "Las palabras genéricas y los fragmentos de baja confianza se excluyen deliberadamente.",
    },
    "identity_analyst_references": {"en": "Analyst references", "es": "Referencias del analista"},
    "identity_blockers": {"en": "Blockers", "es": "Bloqueos"},
    "identity_candidate_summary": {
        "en": "{score}% match · {decision}",
        "es": "{score}% de coincidencia · {decision}",
    },
    "identity_candidates_advisory": {
        "en": "Candidates are comparison aids, not identity conclusions.",
        "es": "Los candidatos ayudan a comparar; no son conclusiones de identidad.",
    },
    "identity_candidates_empty": {"en": "No reference candidates", "es": "No hay candidatos de referencia"},
    "identity_candidates_empty_help": {
        "en": "No safe reference record has enough supporting evidence for this profile.",
        "es": "Ninguna referencia segura tiene pruebas suficientes para este perfil.",
    },
    "identity_card_load_error": {"en": "This Site Card could not be loaded.", "es": "No se pudo cargar esta ficha de sitio."},
    "identity_card_missing": {"en": "The selected Site Card no longer exists.", "es": "La ficha de sitio seleccionada ya no existe."},
    "identity_card_readiness": {"en": "Card readiness", "es": "Preparación de la ficha"},
    "identity_cards_empty": {"en": "No identity-ready Site Cards", "es": "No hay fichas preparadas para identidad"},
    "identity_cards_empty_help": {
        "en": "Cards appear here after safe profile or relationship signals are recorded.",
        "es": "Las fichas aparecen aquí cuando se registran señales seguras de perfil o relación.",
    },
    "identity_classification_restricted": {
        "en": "Classification details are hidden by the active safety policy.",
        "es": "Los detalles de clasificación están ocultos por la política de seguridad activa.",
    },
    "identity_classification_unavailable": {
        "en": "Live classification details are temporarily unavailable.",
        "es": "Los detalles de clasificación activa no están disponibles temporalmente.",
    },
    "identity_confidence": {"en": "Category confidence", "es": "Confianza de categoría"},
    "identity_content_category": {"en": "Content category", "es": "Categoría de contenido"},
    "identity_contradictions": {"en": "Contradicting evidence", "es": "Pruebas contradictorias"},
    "identity_decision": {"en": "Classification decision", "es": "Decisión de clasificación"},
    "identity_discovery_advisory": {
        "en": "Deep Discovery is bounded and advisory. Optional exact public checks are Tor-routed, and nothing shown here changes live cards automatically.",
        "es": "Deep Discovery es limitado y orientativo. Las consultas públicas exactas opcionales usan Tor y nada de lo mostrado cambia fichas activas automáticamente.",
    },
    "identity_discovery_candidate_summary": {
        "en": "{score}% match · {decision} · provider: {provider}",
        "es": "{score}% de coincidencia · {decision} · proveedor: {provider}",
    },
    "identity_discovery_candidates": {"en": "Candidate clusters", "es": "Grupos candidatos"},
    "identity_discovery_candidates_empty": {"en": "No candidate clusters", "es": "No hay grupos candidatos"},
    "identity_discovery_candidates_empty_help": {
        "en": "The completed discovery run did not find a sufficiently supported candidate.",
        "es": "La ejecución de descubrimiento terminada no encontró ningún candidato con apoyo suficiente.",
    },
    "identity_discovery_candidates_help": {
        "en": "Compare support, contradictions and provenance before making any analyst decision.",
        "es": "Compara apoyo, contradicciones y procedencia antes de tomar una decisión.",
    },
    "identity_discovery_complete": {"en": "Discovery complete", "es": "Descubrimiento terminado"},
    "identity_discovery_partial": {
        "en": "Discovery completed with one or more provider limits",
        "es": "El descubrimiento terminó con uno o más límites del proveedor",
    },
    "identity_discovery_empty": {"en": "No discovery record", "es": "No hay registro de descubrimiento"},
    "identity_discovery_empty_help": {
        "en": "No Deep Discovery job has been recorded for this profile.",
        "es": "No se ha registrado ningún trabajo de Deep Discovery para este perfil.",
    },
    "identity_discovery_failed": {"en": "Discovery failed safely", "es": "El descubrimiento falló de forma segura"},
    "identity_discovery_not_started": {"en": "Not started", "es": "Sin iniciar"},
    "identity_discovery_running": {"en": "Discovery running", "es": "Descubrimiento en curso"},
    "identity_discovery_unavailable": {"en": "Discovery status is unavailable.", "es": "El estado del descubrimiento no está disponible."},
    "identity_discovery_waiting": {"en": "Waiting in the local queue", "es": "Esperando en la cola local"},
    "identity_eligibility_evidence": {"en": "Eligibility evidence", "es": "Pruebas de elegibilidad"},
    "identity_eligibility_summary": {
        "en": "Eligibility {score}% · {state}",
        "es": "Elegibilidad {score}% · {state}",
    },
    "identity_evidence_details": {"en": "Evidence details", "es": "Detalles de las pruebas"},
    "identity_evidence_version": {
        "en": "Destination-HTML evidence version: {version}",
        "es": "Versión de pruebas del HTML de destino: {version}",
    },
    "identity_history_empty": {"en": "No recorded history", "es": "No hay historial registrado"},
    "identity_history_empty_help": {
        "en": "Profile and relationship changes will appear here when evidence changes.",
        "es": "Los cambios de perfil y relación aparecerán aquí cuando cambien las pruebas.",
    },
    "identity_identifier_summary": {
        "en": "{count} safe occurrence(s) · last seen {seen}",
        "es": "{count} aparición(es) segura(s) · última observación {seen}",
    },
    "identity_identifiers": {"en": "Identifier signals", "es": "Señales identificadoras"},
    "identity_identifiers_empty": {"en": "No safe identifier signals", "es": "No hay señales identificadoras seguras"},
    "identity_identifiers_empty_help": {
        "en": "Only validated, metadata-safe signal types are summarized here.",
        "es": "Aquí solo se resumen tipos de señal validados y seguros para metadatos.",
    },
    "identity_identifiers_redacted": {
        "en": "Values are redacted; only type, count and recency are shown.",
        "es": "Los valores están ocultos; solo se muestran tipo, cantidad y antigüedad.",
    },
    "identity_identity_confidence": {"en": "Identity confidence", "es": "Confianza de identidad"},
    "identity_intro": {
        "en": "Review public profile signals, relationships and local candidate matches without exposing raw identifiers.",
        "es": "Revisa señales de perfiles públicos, relaciones y coincidencias locales sin exponer identificadores.",
    },
    "identity_limitations": {"en": "Limitations", "es": "Limitaciones"},
    "identity_live_classification": {"en": "Live classification", "es": "Clasificación activa"},
    "identity_live_classification_help": {
        "en": "The current page-derived category, structure and safety state used by the Site Card.",
        "es": "La categoría, estructura y estado de seguridad actuales derivados de la página.",
    },
    "identity_live_origin": {"en": "Live observed data", "es": "Datos observados activos"},
    "identity_live_site_cards": {"en": "Live Site Cards", "es": "Fichas de sitios activas"},
    "identity_local_exact_candidates": {"en": "Local exact-handle candidates", "es": "Candidatos locales de alias exacto"},
    "identity_local_exact_candidates_help": {
        "en": "Hosts are masked and exact handle matches remain advisory.",
        "es": "Los hosts están ocultos y las coincidencias exactas de alias siguen siendo orientativas.",
    },
    "identity_matching_rules": {"en": "Matching rules", "es": "Reglas de coincidencia"},
    "identity_matching_rules_advisory": {
        "en": "A shared handle alone never proves identity. Strong matches require independent corroborating signal types and contradictions remain visible.",
        "es": "Un alias compartido nunca prueba una identidad. Las coincidencias fuertes exigen señales independientes y mantienen visibles las contradicciones.",
    },
    "identity_rule_exact": {
        "en": "An exact, distinctive handle can become a candidate only when its source field is reliable; independent evidence is still required.",
        "es": "Un alias exacto y distintivo solo puede ser candidato si su campo de origen es fiable; aun así se exigen pruebas independientes.",
    },
    "identity_rule_contextual": {
        "en": "Context-bound names are compared only inside their recorded site or role context.",
        "es": "Los nombres ligados al contexto solo se comparan dentro del sitio o rol registrado.",
    },
    "identity_rule_disabled": {
        "en": "Generic roles and globally disabled terms never create identity candidates.",
        "es": "Los roles genéricos y términos desactivados globalmente nunca crean candidatos de identidad.",
    },
    "identity_no_contradictions": {"en": "No contradictions recorded.", "es": "No hay contradicciones registradas."},
    "identity_no_eligibility_detail": {"en": "No eligibility details recorded.", "es": "No hay detalles de elegibilidad registrados."},
    "identity_no_recorded_limitations": {"en": "No limitations recorded.", "es": "No hay limitaciones registradas."},
    "identity_no_supporting_evidence": {"en": "No supporting evidence recorded.", "es": "No hay pruebas de apoyo registradas."},
    "identity_not_dated": {"en": "date unavailable", "es": "fecha no disponible"},
    "identity_not_ready": {"en": "Not ready", "es": "No preparada"},
    "identity_observed_alias": {"en": "Observed alias", "es": "Alias observado"},
    "identity_observed_aliases": {"en": "Observed aliases", "es": "Alias observados"},
    "identity_observed_pages": {"en": "Observed on {count} page(s)", "es": "Observado en {count} página(s)"},
    "identity_observed_profile": {"en": "Observed profile", "es": "Perfil observado"},
    "identity_page_confidence": {"en": "Page-type confidence", "es": "Confianza del tipo de página"},
    "identity_page_type": {"en": "Page type", "es": "Tipo de página"},
    "identity_pages": {"en": "Observed pages", "es": "Páginas observadas"},
    "identity_pages_empty": {"en": "No safe page references", "es": "No hay referencias de página seguras"},
    "identity_profile_summary": {
        "en": "{role} · {confidence} confidence · last observed {seen}",
        "es": "{role} · confianza {confidence} · última observación {seen}",
    },
    "identity_profiles": {"en": "Profiles", "es": "Perfiles"},
    "identity_profiles_empty": {"en": "No validated profiles", "es": "No hay perfiles validados"},
    "identity_profiles_empty_help": {
        "en": "Low-information words and incidental mentions are not promoted to profiles.",
        "es": "Las palabras con poca información y menciones incidentales no se convierten en perfiles.",
    },
    "identity_provenance": {"en": "Technical provenance", "es": "Procedencia técnica"},
    "identity_provenance_reason": {"en": "Classification reason: {reason}", "es": "Motivo de clasificación: {reason}"},
    "identity_provenance_source": {"en": "Evidence source: {source}", "es": "Fuente de pruebas: {source}"},
    "identity_provider_disabled": {"en": "Provider access disabled", "es": "Acceso a proveedores desactivado"},
    "identity_provider_disabled_list": {"en": "Disabled: {providers}", "es": "Desactivados: {providers}"},
    "identity_provider_enabled": {"en": "Provider access enabled", "es": "Acceso a proveedores activado"},
    "identity_provider_enabled_list": {"en": "Enabled: {providers}", "es": "Activados: {providers}"},
    "identity_provider_local": {"en": "Local-only", "es": "Solo local"},
    "identity_provider_mode": {"en": "Provider mode", "es": "Modo de proveedor"},
    "identity_provider_network": {"en": "Network-enabled", "es": "Con red"},
    "identity_provider_reason": {"en": "Provider note: {reason}", "es": "Nota del proveedor: {reason}"},
    "identity_provider_unknown": {"en": "Not recorded", "es": "No registrado"},
    "identity_public_alias": {"en": "Public alias", "es": "Alias público"},
    "identity_readiness_reason": {"en": "Readiness reason: {reason}", "es": "Motivo de preparación: {reason}"},
    "identity_ready": {"en": "Ready", "es": "Preparada"},
    "identity_reference": {"en": "Reference", "es": "Referencia"},
    "identity_reference_candidate": {"en": "Reference candidate", "es": "Candidato de referencia"},
    "identity_reference_matches": {"en": "Reference matches", "es": "Coincidencias de referencia"},
    "identity_reference_policies": {"en": "Policies: {policies}", "es": "Políticas: {policies}"},
    "identity_reference_summary": {
        "en": "{entity_type} · {status} · {handles} handle(s) · {sources} source(s)",
        "es": "{entity_type} · {status} · {handles} alias · {sources} fuente(s)",
    },
    "identity_references_advisory": {
        "en": "Analyst references are comparison records and never overwrite live evidence.",
        "es": "Las referencias del analista son registros comparativos y nunca sustituyen las pruebas activas.",
    },
    "identity_references_empty": {"en": "No analyst references", "es": "No hay referencias del analista"},
    "identity_references_empty_help": {
        "en": "Reference records are optional and remain separate from observed profiles.",
        "es": "Las referencias son opcionales y permanecen separadas de los perfiles observados.",
    },
    "identity_related_profile": {"en": "Related profile", "es": "Perfil relacionado"},
    "identity_relationship_summary": {
        "en": "{confidence} confidence · {count} evidence item(s) · {decision}",
        "es": "Confianza {confidence} · {count} prueba(s) · {decision}",
    },
    "identity_relationships": {"en": "Relationships", "es": "Relaciones"},
    "identity_relationships_advisory": {
        "en": "Relationships express recorded evidence, not attribution or guilt.",
        "es": "Las relaciones expresan pruebas registradas, no atribución ni culpabilidad.",
    },
    "identity_relationships_empty": {"en": "No supported relationships", "es": "No hay relaciones respaldadas"},
    "identity_relationships_empty_help": {
        "en": "A relationship appears only after corroborating evidence is stored.",
        "es": "Una relación aparece solo cuando se guardan pruebas que la respaldan.",
    },
    "identity_safety_state": {"en": "Safety state", "es": "Estado de seguridad"},
    "identity_search_aliases": {"en": "Search observed aliases", "es": "Buscar alias observados"},
    "identity_signal_types": {"en": "Signal types", "es": "Tipos de señal"},
    "identity_site_card": {"en": "Site Card", "es": "Ficha de sitio"},
    "identity_strong_pivots": {"en": "Strong local pivots", "es": "Pivotes locales fuertes"},
    "identity_structured_cards": {"en": "Structured Site Cards", "es": "Fichas de sitio estructuradas"},
    "identity_supporting_evidence": {"en": "Supporting evidence", "es": "Pruebas de apoyo"},
    "identity_tab_discovery": {"en": "Deep Discovery", "es": "Deep Discovery"},
    "identity_tab_history": {"en": "History", "es": "Historial"},
    "identity_tab_identifiers": {"en": "Identifiers", "es": "Identificadores"},
    "identity_tab_profiles": {"en": "Profiles", "es": "Perfiles"},
    "identity_tab_reference_matches": {"en": "Reference matches", "es": "Coincidencias de referencia"},
    "identity_tab_relationships": {"en": "Relationships", "es": "Relaciones"},
    "identity_unknown_time": {"en": "time unavailable", "es": "hora no disponible"},
    "identity_update": {"en": "Recorded update", "es": "Actualización registrada"},
    "identity_update_reason": {"en": "Update reason: {reason}", "es": "Motivo de actualización: {reason}"},
    "identity_watched_aliases": {"en": "Watched aliases", "es": "Alias seguidos"},
    "identity_workspace_unavailable": {
        "en": "Identity data is temporarily unavailable.",
        "es": "Los datos de identidad no están disponibles temporalmente.",
    },
})


CATEGORY_LABELS = {
    "adult_filtered": ("Filtered adult content", "Contenido adulto filtrado"),
    "adult_restricted": ("Adult content — restricted", "Contenido adulto — restringido"),
    "severe_abuse_risk": ("Restricted content — metadata only", "Contenido restringido — solo metadatos"),
    "weapons_arms": ("Weapons / arms context", "Contexto de armas"),
    "drugs": ("Drugs context", "Contexto de drogas"),
    "leaks_data": ("Leaks / exposed data", "Filtraciones / datos expuestos"),
    "credentials": ("Credentials", "Credenciales"),
    "malware_hacking": ("Malware / hacking", "Malware / intrusión"),
    "extremist_recruitment": ("Extremist / recruitment", "Extremismo / reclutamiento"),
    "fraud_financial": ("Financial fraud", "Fraude financiero"),
    "marketplace": ("Marketplace context", "Contexto de mercado"),
    "marketplace_drugs": ("Marketplace: Drugs", "Mercado: drogas"),
    "marketplace_weapons": ("Marketplace: Weapons", "Mercado: armas"),
    "marketplace_fraud": ("Marketplace: Fraud", "Mercado: fraude"),
    "marketplace_credentials": ("Marketplace: Credentials", "Mercado: credenciales"),
    "marketplace_leaks": ("Marketplace: Leaks", "Mercado: filtraciones"),
    "marketplace_counterfeit": ("Marketplace: Counterfeit", "Mercado: falsificaciones"),
    "marketplace_services": ("Marketplace: Services", "Mercado: servicios"),
    "forum_social": ("Forum / Community", "Foro / Comunidad"),
    "directory_index": ("Directory / Link list", "Directorio / Lista de enlaces"),
    "search_engine": ("Search engine", "Buscador"),
    "hosting_services": ("Hosting / services", "Alojamiento / servicios"),
    "contact_infrastructure": ("Contact / infrastructure", "Contacto / infraestructura"),
    "infosec_research": ("Information security / research", "Seguridad informática / investigación"),
    "privacy_anonymity": ("Privacy / anonymity", "Privacidad / anonimato"),
    "news_media": ("News / journalism", "Noticias / periodismo"),
    "religion_spirituality": ("Religion / spirituality", "Religión / espiritualidad"),
    "education_reference": ("Education / reference", "Educación / consulta"),
    "technology_software": ("Technology / software", "Tecnología / software"),
    "finance_cryptocurrency": ("Finance / cryptocurrency", "Finanzas / criptomonedas"),
    "activism_civil_society": ("Activism / civil society", "Activismo / sociedad civil"),
    "personal_blog": ("Personal blog / writing", "Blog personal / escritos"),
    "communication_services": ("Email / messaging", "Correo / mensajería"),
    "file_storage_sharing": ("File sharing / storage", "Archivos / almacenamiento"),
    "arts_culture": ("Arts / culture", "Arte / cultura"),
    "health_wellness": ("Health / wellbeing", "Salud / bienestar"),
    "spam_noise": ("Spam / noise", "Spam / ruido"),
    "dead_softdead": ("Dead / unavailable", "Caído / no disponible"),
    "general_other": ("General / other", "General / otros"),
    "unknown": ("Unknown / Needs review", "Desconocido / Necesita revisión"),
}

CATEGORY_FAMILIES = {
    "unknown": "Needs review", "general_other": "Needs review",
    "directory_index": "Safe / Discovery", "search_engine": "Safe / Discovery",
    "forum_social": "Forums / Community", "personal_blog": "Forums / Community",
    "hosting_services": "Technical / Infrastructure", "contact_infrastructure": "Technical / Infrastructure",
    "infosec_research": "Technical / Infrastructure", "privacy_anonymity": "Technical / Infrastructure",
    "technology_software": "Technical / Infrastructure", "communication_services": "Technical / Infrastructure",
    "file_storage_sharing": "Technical / Infrastructure",
    "marketplace": "Marketplaces", "marketplace_drugs": "Marketplaces", "marketplace_weapons": "Marketplaces",
    "marketplace_fraud": "Marketplaces", "marketplace_credentials": "Marketplaces",
    "marketplace_leaks": "Marketplaces", "marketplace_counterfeit": "Marketplaces",
    "marketplace_services": "Marketplaces",
    "weapons_arms": "Risk context", "drugs": "Risk context", "leaks_data": "Risk context",
    "credentials": "Risk context", "malware_hacking": "Risk context", "fraud_financial": "Risk context",
    "extremist_recruitment": "Risk context",
}

CATEGORY_DESCRIPTIONS = {
    "unknown": "The system does not yet have enough detail for a reliable category.",
    "directory_index": "A directory or link list that can lead to other onion pages.",
    "forum_social": "A discussion forum, community, thread index or social space.",
    "hosting_services": "Hosting, infrastructure or site-operation services.",
    "marketplace": "A mixed or general marketplace; interaction remains prohibited.",
    "marketplace_fraud": "A marketplace with strong financial-fraud context; metadata remains limited.",
    "fraud_financial": "Financial-fraud context outside a confirmed marketplace structure.",
    "weapons_arms": "Weapons-related context identified from the page itself.",
}

VALUE_LABELS_ES = {
    "unknown": "Desconocido", "unavailable": "No disponible", "none": "Ninguno",
    "low": "Bajo", "medium": "Medio", "high": "Alto", "critical": "Crítico",
    "filtered": "Filtrado", "pending": "Pendiente", "monitor": "Monitorizar",
    "needs_review": "Necesita revisión", "relevant": "Relevante",
    "false_positive": "Falso positivo", "needs_report": "Necesita informe",
    "reported": "Informado", "blocked": "Bloqueado", "restricted": "Restringido",
    "accepted": "Aceptado", "analyst_confirmed": "Confirmado manualmente",
    "unreviewed": "Sin revisar", "keep": "Conservar", "ignored": "Ignorado",
    "abstained": "Sin clasificación", "monitor_only": "Solo monitorizar",
    "queued": "En cola", "new": "Nuevo", "crawled": "Rastreado", "active": "Activo",
    "dead": "Caído", "soft_dead": "No disponible", "error": "Error", "retry": "Reintentar",
    "offline": "Desconectado", "live": "Activo", "allowed": "Permitido",
    "safe_summary": "Resumen seguro", "metadata_limited": "Metadatos limitados",
    "metadata_only": "Solo metadatos", "discard": "Descartar", "normal": "Normal",
    "online": "Conectado", "stale": "Sin actividad reciente", "ready": "Lista",
    "not reachable": "No accesible", "stopped": "Detenido", "paused": "Pausado", "idle": "En espera",
    "homepage": "Portada", "forum_home": "Portada del foro", "thread_page": "Hilo",
    "post_page": "Mensaje", "category_page": "Página de categoría", "directory_page": "Directorio",
    "search_page": "Página de búsqueda", "article_page": "Artículo", "login_gate": "Acceso restringido",
    "profile_page": "Perfil", "vendor_page": "Vendedor", "product_page": "Producto",
    "listing_page": "Listado", "paste_page": "Página de texto", "marketplace_home": "Portada del mercado",
    "marketplace": "Mercado", "arms": "Armas", "drugs": "Drogas", "leaks": "Filtraciones",
    "credentials": "Credenciales", "hacking": "Intrusión", "malware": "Malware",
    "recruitment": "Reclutamiento", "extremist": "Extremismo", "fraud": "Fraude",
    "forum": "Foro", "directory": "Directorio", "privacy": "Privacidad",
    "education": "Educación", "technology": "Tecnología", "cryptocurrency": "Criptomonedas",
    "civil_society": "Sociedad civil", "personal_blog": "Blog personal",
    "communication": "Comunicación", "communications": "Comunicaciones",
    "file_sharing": "Archivos compartidos", "file_storage": "Almacenamiento de archivos",
    "arts": "Arte", "culture": "Cultura", "health": "Salud", "wellbeing": "Bienestar",
    "spain_priority": "Prioridad España", "restricted_child_present": "Enlace restringido presente",
    "spain": "España", "spain_confirmed": "España confirmada",
    "adult_link_present": "Enlace adulto oculto", "marketplace_context": "Contexto de mercado",
}

SPAIN_REASON_LABELS = {
    "spain_priority_context": ("Spain priority context", "Contexto de prioridad España"),
    "spain_country_reference": ("Spain-specific country reference", "Referencia específica a España"),
    "spanish_city_reference": ("Spanish city or province reference", "Referencia a una ciudad o provincia española"),
    "spanish_financial_target": ("Spanish financial target", "Objetivo financiero español"),
    "spanish_actor_or_seller": ("Spain-linked actor or seller", "Actor o vendedor vinculado con España"),
    "spanish_market_targeting": ("Spanish market targeting", "Orientación al mercado español"),
    "spanish_language_only_not_priority": (
        "Spanish language only; not Spain priority",
        "Solo idioma español; no es prioridad España",
    ),
    "Visible delivery or sending references both to and from Spain": (
        "Visible delivery or sending references both to and from Spain",
        "Referencias visibles de envíos hacia y desde España",
    ),
    "Visible delivery or sending reference to Spain": (
        "Visible delivery or sending reference to Spain",
        "Referencia visible de envío hacia España",
    ),
    "Visible delivery or sending reference from Spain": (
        "Visible delivery or sending reference from Spain",
        "Referencia visible de envío desde España",
    ),
    "Strong Spanish institution or official-domain reference": (
        "Strong Spanish institution or official-domain reference",
        "Referencia clara a una institución o dominio oficial español",
    ),
    "Spain reference with Russian or geopolitical threat context": (
        "Spain reference with Russian or geopolitical threat context",
        "Referencia a España con contexto ruso o geopolítico de riesgo",
    ),
    "Spanish city or province paired with relevant context": (
        "Spanish city or province paired with relevant context",
        "Ciudad o provincia española junto con contexto relevante",
    ),
    "Spain reference paired with seller, actor, or market context": (
        "Spain reference paired with seller, actor, or market context",
        "Referencia a España junto con contexto de vendedor, actor o mercado",
    ),
    "Spain reference paired with threat-related context": (
        "Spain reference paired with threat-related context",
        "Referencia a España junto con contexto de riesgo",
    ),
}

CATEGORY_REASON_ES = {
    "Adult safety filter matched": "Coincidencia con el filtro de seguridad para contenido adulto",
    "Critical restricted safety policy matched": "Coincidencia con una regla crítica de contenido restringido",
    "Direct marketplace or listing structure detected": "Se detectó una estructura directa de mercado o anuncios",
    "Discovery or community page structure detected": "Se detectó una estructura de descubrimiento o comunidad",
    "Neutral informational topic detected": "Se detectó un tema informativo neutral",
    "Threat-related context detected": "Se detectó contexto de riesgo",
    "No stronger category structure detected": "No se detectó una categoría más específica",
    "A possible category signal needs corroboration": "Una posible categoría necesita más pruebas",
    "Threat signal was not corroborated strongly enough": "La señal de riesgo no tuvo apoyo suficiente",
    "Analyst category correction": "Categoría corregida manualmente",
    "Existing category preserved during taxonomy migration": "Categoría existente conservada durante la actualización",
}


def category_label(category: str | None, language: str = "en") -> str:
    key = str(category or "unknown")
    labels = CATEGORY_LABELS.get(key)
    if labels:
        return labels[1 if language == "es" else 0]
    return key.replace("_", " ").title()


def category_family(category: str | None, language: str = "en") -> str:
    family = CATEGORY_FAMILIES.get(str(category or "unknown"), "Neutral / Reference")
    translations = {
        "Needs review": "Necesita revisión", "Safe / Discovery": "Seguro / Descubrimiento",
        "Forums / Community": "Foros / Comunidad", "Technical / Infrastructure": "Técnico / Infraestructura",
        "Marketplaces": "Mercados", "Risk context": "Contexto de riesgo", "Neutral / Reference": "Neutral / Referencia",
    }
    return translations.get(family, family) if language == "es" else family


def category_description(category: str | None, language: str = "en") -> str:
    text = CATEGORY_DESCRIPTIONS.get(str(category or "unknown"),
        "A human-readable reviewer label. It does not replace policy risk or crawler signals.")
    if language != "es":
        return text
    translations = {
        CATEGORY_DESCRIPTIONS["unknown"]: "El sistema todavía no tiene pruebas suficientes para una categoría fiable.",
        CATEGORY_DESCRIPTIONS["directory_index"]: "Un directorio o lista de enlaces que puede llevar a otras páginas onion.",
        CATEGORY_DESCRIPTIONS["forum_social"]: "Un foro, comunidad, índice de hilos o espacio social.",
        CATEGORY_DESCRIPTIONS["hosting_services"]: "Servicios de alojamiento, infraestructura u operación de sitios.",
    }
    return translations.get(text, "Una etiqueta legible para el analista. No sustituye el riesgo ni las pruebas de Arachne.")


def value_label(value: str | None, language: str = "en") -> str:
    key = str(value or "unknown").casefold()
    if key in CATEGORY_LABELS:
        return category_label(key, language)
    if language == "es" and key in VALUE_LABELS_ES:
        return VALUE_LABELS_ES[key]
    return key.replace("_", " ").title()


def spain_reason_label(reason: str | None, language: str = "en") -> str:
    """Return a stable display label without changing stored Spain evidence."""
    key = str(reason or "spain_priority_context").strip()
    labels = SPAIN_REASON_LABELS.get(key)
    if labels:
        return labels[1 if language == "es" else 0]
    if language == "es" and "_" in key and " " not in key:
        return value_label(key, language)
    return key


def category_reason_label(reason: str | None, language: str = "en") -> str:
    text = str(reason or "")
    if language != "es":
        return text
    if text in CATEGORY_REASON_ES:
        return CATEGORY_REASON_ES[text]
    if text.startswith("Fetched page structure matched "):
        category = text.removeprefix("Fetched page structure matched ").replace(" ", "_")
        return f"La estructura de la página coincide con {category_label(category, language).casefold()}"
    if text.startswith("neutral_"):
        return "Contenido informativo neutral"
    return value_label(text, language)


def tr(key: str, language: str = "en", **values) -> str:
    language = "es" if language == "es" else "en"
    text = COPY.get(key, {}).get(language) or COPY.get(key, {}).get("en") or key
    return text.format(**values) if values else text


def current_language(st) -> str:
    return "es" if st.session_state.get("ui_spanish") else "en"
