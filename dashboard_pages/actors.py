"""General public-alias monitoring page."""
from __future__ import annotations

import html
import json

import actor_intelligence
import dashboard_auth
import storage
from dashboard_services.i18n import category_label, current_language, value_label
from ui_components import empty_state, page_lead, section_header


def _t(language: str, english: str, spanish: str) -> str:
    """Return bounded page copy in the active dashboard language."""
    return spanish if language == "es" else english


def _can(st, capability: str) -> bool:
    from dashboard_pages.workspace import _can as workspace_can

    return workspace_can(st, capability)


def _authorize(st, capability: str) -> bool:
    from dashboard_pages.workspace import _authorize_action

    return _authorize_action(st, capability)


def _short(value: str | None, *, left: int = 16, right: int = 14,
           fallback: str = "unknown") -> str:
    text = value or fallback
    return text if len(text) <= left + right + 3 else f"{text[:left]}...{text[-right:]}"


def _event_metadata(raw: str | None, language: str = "en") -> str:
    try:
        data = json.loads(raw or "{}")
    except (TypeError, ValueError):
        data = {}
    if not isinstance(data, dict):
        return ""
    parts = []
    labels = {
        "url": ("URL", "URL"),
        "spain_flow": ("Spain flow", "Flujo de España"),
        "marketplace_category": ("Marketplace category", "Categoría del mercado"),
        "reason": ("Reason", "Motivo"),
    }
    for key in ("url", "spain_flow", "marketplace_category", "reason"):
        if data.get(key):
            label = _t(language, *labels[key])
            value = data[key] if key == "url" else value_label(data[key], language)
            parts.append(f"{label}: {value}")
    return " · ".join(parts)


def _page_items(st, items: list[dict], *, key: str, page_size: int,
                item_name: str = "items", item_name_es: str = "elementos",
                language: str = "en") -> list[dict]:
    """Return one bounded UI page without changing the underlying query."""
    rows = list(items or [])
    page_count = max(1, (len(rows) + page_size - 1) // page_size)
    page_key = f"{key}-page"
    stored_page = int(st.session_state.get(page_key, 1) or 1)
    selected_page = min(max(stored_page, 1), page_count)
    if stored_page != selected_page:
        st.session_state[page_key] = selected_page
    if page_count > 1:
        selected_page = int(st.selectbox(
            _t(language, f"{item_name.title()} page", f"Página de {item_name_es}"),
            list(range(1, page_count + 1)),
            index=selected_page - 1,
            format_func=lambda value: _t(
                language, f"Page {value} of {page_count}", f"Página {value} de {page_count}"
            ),
            key=page_key,
        ))
    start = (selected_page - 1) * page_size
    visible = rows[start:start + page_size]
    if rows:
        st.caption(_t(
            language,
            f"Showing {start + 1}-{start + len(visible)} of {len(rows)} {item_name}.",
            f"Mostrando {start + 1}-{start + len(visible)} de {len(rows)} {item_name_es}.",
        ))
    return visible


def _render_alias_quality_tools(st, query, language: str = "en") -> None:
    """Expose conservative alias-noise cleanup without requiring terminal access."""
    can_manage_quality = _can(st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE)
    scan_key = "alias-quality-scan-result"
    with st.expander(
        _t(language, "Alias quality tools", "Herramientas de calidad de alias"),
        expanded=False,
    ):
        st.caption(
            _t(
                language,
                "Use this when generic words such as mail providers, navigation labels, or vague "
                "adjectives slip into the alias list. The scan is conservative and only targets "
                "obvious noise.",
                "Úsalo cuando palabras genéricas, como proveedores de correo, etiquetas de "
                "navegación o adjetivos vagos, aparezcan en la lista. El análisis es conservador "
                "y solo busca ruido evidente.",
            )
        )
        session_state = getattr(st, "session_state", {})
        dry = session_state.get(scan_key)
        scan_label = _t(
            language,
            "Refresh conservative scan" if isinstance(dry, dict) else "Run conservative scan",
            "Actualizar análisis conservador" if isinstance(dry, dict) else "Ejecutar análisis conservador",
        )
        if st.button(scan_label, key="alias-quality-scan"):
            dry = actor_intelligence.cleanup_public_alias_noise(dry_run=True)
            session_state[scan_key] = dry
        if not isinstance(dry, dict):
            st.info(_t(
                language,
                "Run the scan to count obvious alias noise. Nothing is removed automatically.",
                "Ejecuta el análisis para contar el ruido evidente. No se elimina nada automáticamente.",
            ))
            return

        cols = st.columns(3)
        cols[0].metric(
            _t(language, "Noisy aliases found", "Alias con ruido"),
            int(dry.get("noisy_aliases") or 0),
        )
        cols[1].metric(
            _t(language, "Checked aliases", "Alias comprobados"),
            int(dry.get("checked") or 0),
        )
        cols[2].metric(
            _t(language, "Would remove", "Se eliminarían"),
            int(dry.get("noisy_aliases") or 0),
        )
        sample = [str(item) for item in dry.get("sample") or [] if item]
        if sample:
            st.caption(
                _t(language, "Sample: ", "Muestra: ")
                + ", ".join(html.escape(item) for item in sample[:12])
            )
        else:
            st.success(_t(
                language,
                "No obvious alias noise found.",
                "No se encontró ruido evidente en los alias.",
            ))
        confirm = st.toggle(
            _t(
                language,
                "I want to remove the obvious noisy aliases shown by this scan",
                "Quiero eliminar los alias con ruido evidente que muestra este análisis",
            ),
            value=False,
            key="alias-quality-remove-confirm",
            disabled=not can_manage_quality,
        )
        if not can_manage_quality:
            st.caption(_t(
                language,
                "Read-only: only an administrator can run alias cleanup.",
                "Solo lectura: únicamente un administrador puede limpiar los alias.",
            ))
        if st.button(
            _t(language, "Remove noisy aliases", "Eliminar alias con ruido"),
            disabled=not can_manage_quality or not confirm or not dry.get("noisy_aliases"),
            key="alias-quality-remove",
            type="primary",
        ) and _authorize(st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE):
            result = actor_intelligence.cleanup_public_alias_noise(dry_run=False)
            st.success(_t(
                language,
                f"Removed {int(result.get('removed') or 0)} noisy aliases.",
                f"Se eliminaron {int(result.get('removed') or 0)} alias con ruido.",
            ))
            st.session_state.pop(scan_key, None)
            query.clear()
            st.rerun()


def render(st, query) -> None:
    language = current_language(st)
    st.markdown(
        page_lead(
            _t(language, "Public username profiles", "Perfiles de alias públicos"),
            _t(
                language,
                "One evidence-backed card per public username/profile, with verified page sightings "
                "and locally bound signal types kept together. It does not claim real-world identity.",
                "Una ficha respaldada por pruebas por cada alias o perfil público, con sus páginas "
                "verificadas y tipos de señales vinculadas localmente. No atribuye una identidad real.",
            ),
            eyebrow=_t(language, "Observed identities", "Identidades observadas"),
            aside=_t(language, "Evidence-bound", "Basado en pruebas"),
            show_title=False,
        ),
        unsafe_allow_html=True,
    )
    filters = st.columns([2, 1, 1])
    search = filters[0].text_input(
        _t(language, "Search usernames", "Buscar nombres de usuario"),
        placeholder=_t(
            language, "Username, onion host, category", "Nombre de usuario, host onion o categoría"
        ),
        key="actors-search",
    )
    watched_only = filters[1].checkbox(
        _t(language, "Watched only", "Solo en seguimiento"), key="actors-watched-only"
    )
    limit = filters[2].selectbox(
        _t(language, "Limit", "Límite"), [100, 300, 500], index=1, key="actors-limit"
    )
    actors = storage.get_public_actors(watched_only=watched_only, search=search, limit=int(limit))
    all_actors = storage.get_public_actors(limit=1000)
    metric_cols = st.columns(4)
    metric_cols[0].metric(_t(language, "Username cards", "Fichas de alias"), len(all_actors))
    metric_cols[1].metric(
        _t(language, "Watched", "En seguimiento"),
        sum(int(item.get("watched") or 0) for item in all_actors),
    )
    metric_cols[2].metric(
        _t(language, "Spain-linked aliases", "Alias vinculados con España"),
        sum(1 for item in all_actors if int(item.get("spain_observation_count") or 0)),
    )
    metric_cols[3].metric(
        _t(language, "Possible matches", "Coincidencias posibles"),
        sum(int(item.get("connection_count") or 0) for item in all_actors),
    )
    _render_alias_quality_tools(st, query, language)
    if not actors:
        st.markdown(
            empty_state(
                _t(
                    language,
                    "No public usernames match this view",
                    "Ningún alias público coincide con esta vista",
                ),
                _t(
                    language,
                    "Eligible, evidence-backed profile observations will appear after verification.",
                    "Las observaciones de perfiles válidas y respaldadas por pruebas aparecerán "
                    "después de la verificación.",
                ),
            ),
            unsafe_allow_html=True,
        )
        return

    visible_actors = _page_items(
        st,
        actors,
        key="public-actors",
        page_size=20,
        item_name="username cards",
        item_name_es="fichas de alias",
        language=language,
    )
    selected = st.session_state.get("selected_public_actor")
    valid = {int(item["id"]) for item in visible_actors}
    if not selected or int(selected) not in valid:
        selected = int(visible_actors[0]["id"])
        st.session_state["selected_public_actor"] = selected

    list_col, detail_col = st.columns([0.9, 2.1], gap="large")
    with list_col:
        st.markdown(
            section_header(
                _t(language, "Usernames", "Alias públicos"),
                _t(
                    language,
                    "Choose one profile to review its observations and connections.",
                    "Elige un perfil para revisar sus observaciones y conexiones.",
                ),
                count=len(actors),
            ),
            unsafe_allow_html=True,
        )
        for actor in visible_actors:
            actor_id = int(actor["id"])
            active = actor_id == int(selected)
            with st.container(border=True):
                st.markdown(
                    f"**{html.escape(actor.get('display_alias') or _t(language, 'Public alias', 'Alias público'))}**"
                )
                st.caption(
                    f"{html.escape(_short(
                        actor.get('onion_host'),
                        fallback=_t(language, 'unknown', 'desconocido'),
                    ))} · "
                    + _t(
                        language,
                        f"{int(actor.get('observation_count') or 0)} pages · "
                        f"{int(actor.get('connection_count') or 0)} matches",
                        f"{int(actor.get('observation_count') or 0)} páginas · "
                        f"{int(actor.get('connection_count') or 0)} coincidencias",
                    )
                )
                if actor.get("canonical_profile_identity"):
                    st.caption(
                        _t(language, "Profile: ", "Perfil: ")
                        + html.escape(_short(actor.get("canonical_profile_identity")))
                    )
                badges = []
                if actor.get("watched"):
                    badges.append(_t(language, "watched", "en seguimiento"))
                if int(actor.get("spain_observation_count") or 0):
                    badges.append(_t(language, "Spain", "España"))
                if int(actor.get("seller_page_count") or 0):
                    badges.append(_t(language, "seller", "vendedor"))
                if badges:
                    st.caption(" · ".join(badges))
                if st.button(
                    _t(language, "Selected", "Seleccionado")
                    if active else _t(language, "Open", "Abrir"),
                    key=f"actor-open-{actor_id}",
                             disabled=active, width="stretch"):
                    st.session_state["selected_public_actor"] = actor_id
                    query.clear()
                    st.rerun()

    detail = storage.get_actor_detail(int(selected))
    if not detail:
        with detail_col:
            st.markdown(
                empty_state(
                    _t(language, "Profile unavailable", "Perfil no disponible"),
                    _t(
                        language,
                        "The selected public username is no longer available in this view.",
                        "El alias público seleccionado ya no está disponible en esta vista.",
                    ),
                ),
                unsafe_allow_html=True,
            )
        return
    actor = detail["actor"]
    with detail_col:
        can_watch = _can(st, dashboard_auth.CAPABILITY_WATCHLIST_MANAGE)
        can_review = _can(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE)
        st.markdown(
            section_header(
                actor.get("display_alias") or _t(language, "Public alias", "Alias público"),
                f"{actor.get('onion_host') or _t(language, 'unknown', 'desconocido')} · "
                f"{category_label(actor.get('primary_category'), language)} · "
                + _t(
                    language,
                    f"{int(actor.get('observation_count') or 0)} page sighting(s)",
                    f"{int(actor.get('observation_count') or 0)} observaciones de página",
                ),
            ),
            unsafe_allow_html=True,
        )
        watch_col, note_col = st.columns([1, 2])
        with note_col:
            watch_reason = st.text_input(
                _t(language, "Watch note", "Nota de seguimiento"),
                value=actor.get("watch_reason") or "",
                placeholder=_t(
                    language, "Why this username matters", "Por qué importa este alias"
                ),
                key=f"public-actor-watch-note-{selected}",
                disabled=not can_watch,
            )
        with watch_col:
            if actor.get("watched"):
                if st.button(
                    _t(language, "Stop watching", "Dejar de seguir"),
                    key=f"public-actor-unwatch-{selected}", width="stretch",
                    disabled=not can_watch,
                ) and _authorize(st, dashboard_auth.CAPABILITY_WATCHLIST_MANAGE):
                    storage.set_actor_watch(int(selected), False)
                    query.clear()
                    st.rerun()
            else:
                if st.button(
                    _t(language, "Watch username", "Seguir alias"),
                    key=f"public-actor-watch-{selected}",
                             type="primary", width="stretch", disabled=not can_watch
                             ) and _authorize(
                                 st, dashboard_auth.CAPABILITY_WATCHLIST_MANAGE):
                    storage.set_actor_watch(int(selected), True, watch_reason)
                    query.clear()
                    st.rerun()

        profile_tab, timeline_tab, matches_tab, signals_tab, events_tab = st.tabs(
            [
                _t(language, "Profile & aliases", "Perfil y alias"),
                _t(language, "Page sightings", "Páginas observadas"),
                _t(language, "Possible matches", "Coincidencias posibles"),
                _t(language, "Public signal types", "Tipos de señales públicas"),
                _t(language, "Timeline events", "Eventos cronológicos"),
            ]
        )
        if not can_watch or not can_review:
            st.caption(_t(
                language,
                "Read-only controls are disabled for this session; viewing evidence remains available.",
                "Los controles de edición están desactivados en esta sesión; las pruebas siguen visibles.",
            ))
        with profile_tab:
            st.caption(_t(
                language,
                "Stable profile identity keeps repeated sightings together without merging unrelated "
                "same-name profiles.",
                "La identidad estable del perfil agrupa las observaciones repetidas sin unir perfiles "
                "no relacionados que tengan el mismo nombre.",
            ))
            if actor.get("canonical_profile_url"):
                st.code(actor["canonical_profile_url"], language=None)
            if detail.get("aliases"):
                alias_rows = []
                alias_labels = [
                    ("display_alias", "Alias", "Alias"),
                    ("normalized_alias", "Normalized alias", "Alias normalizado"),
                    ("alias_skeleton", "Comparison form", "Forma de comparación"),
                    ("first_seen", "First seen", "Primera detección"),
                    ("last_seen", "Last seen", "Última detección"),
                    ("observation_count", "Sightings", "Observaciones"),
                ]
                for row in detail["aliases"]:
                    alias_rows.append({
                        _t(language, english, spanish): row.get(key)
                        for key, english, spanish in alias_labels
                    })
                st.dataframe(alias_rows, use_container_width=True, hide_index=True)
            else:
                st.markdown(
                    empty_state(
                        _t(
                            language,
                            "No alternate public spelling",
                            "No hay otra forma pública del alias",
                        ),
                        _t(
                            language,
                            "Only the current profile spelling has been observed.",
                            "Solo se ha observado la forma actual del perfil.",
                        ),
                    ),
                    unsafe_allow_html=True,
                )
        with timeline_tab:
            visible_observations = _page_items(
                st, detail["observations"], key=f"public-actor-{selected}-observations",
                page_size=12, item_name="page sightings", item_name_es="páginas observadas",
                language=language)
            for observation in visible_observations:
                with st.container(border=True):
                    header = (
                        f"**{html.escape(category_label(observation.get('primary_category'), language))}** · "
                        f"{html.escape(value_label(observation.get('page_type') or 'page', language))}"
                    )
                    if observation.get("spain_priority"):
                        header += " · " + _t(language, "Spain", "España")
                    st.markdown(header)
                    st.code(observation["url"], language=None)
                    context_label = observation.get("safe_context_label")
                    st.caption(
                        f"{value_label(context_label, language) if context_label else _t(language, 'Public alias', 'Alias público')} · "
                        + _t(
                            language,
                            f"last seen {observation.get('last_seen') or 'unknown'}",
                            f"última detección {observation.get('last_seen') or 'desconocida'}",
                        )
                    )
                    confirm = st.toggle(
                        _t(
                            language,
                            "Confirm removal from this alias",
                            "Confirmar que se desvincule esta página del alias",
                        ),
                        value=False,
                        key=f"public-actor-remove-confirm-{observation['id']}",
                        disabled=not can_review,
                    )
                    if st.button(
                        _t(
                            language,
                            "Remove this page from alias",
                            "Desvincular esta página del alias",
                        ),
                        key=f"public-actor-remove-{observation['id']}",
                                 disabled=not can_review or not confirm) and _authorize(
                                     st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
                        storage.exclude_actor_observation(int(observation["id"]))
                        query.clear()
                        st.rerun()
        with matches_tab:
            visible = [item for item in detail["connections"] if item.get("analyst_decision") != "not_same"]
            if not visible:
                st.markdown(
                    empty_state(
                        _t(
                            language,
                            "No unresolved possible matches",
                            "No hay coincidencias posibles pendientes",
                        ),
                        _t(
                            language,
                            "Evidence-backed candidates will appear here without being auto-confirmed.",
                            "Los candidatos respaldados por pruebas aparecerán aquí sin confirmarse "
                            "automáticamente.",
                        ),
                    ),
                    unsafe_allow_html=True,
                )
            visible_connections = _page_items(
                st, visible, key=f"public-actor-{selected}-connections",
                page_size=10, item_name="possible matches",
                item_name_es="coincidencias posibles", language=language)
            for connection in visible_connections:
                with st.container(border=True):
                    st.markdown(
                        f"**{html.escape(connection.get('other_alias') or _t(language, 'Unknown alias', 'Alias desconocido'))}** · "
                        f"`{html.escape(_short(
                            connection.get('other_onion_host'),
                            fallback=_t(language, 'unknown', 'desconocido'),
                        ))}`"
                    )
                    st.caption(
                        _t(language, "Confidence", "Confianza")
                        + f" {int(float(connection.get('confidence_score') or 0))}% · "
                        + value_label(connection.get("confidence_label") or "low", language)
                        + " · "
                        + value_label(connection.get("analyst_decision") or "unreviewed", language)
                    )
                    try:
                        evidence = json.loads(connection.get("evidence_json") or "[]")
                    except (TypeError, ValueError):
                        evidence = []
                    for item in evidence:
                        evidence_label = item.get("label") or _t(
                            language, "Public signal", "Señal pública"
                        )
                        st.markdown(f"- {html.escape(value_label(evidence_label, language))}")
                    a, b, c = st.columns(3)
                    if a.button(
                        _t(language, "Confirm", "Confirmar"),
                        key=f"public-connection-confirm-{connection['id']}",
                        disabled=not can_review,
                    ) and _authorize(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
                        storage.set_actor_connection_decision(int(connection["id"]), "confirmed_same")
                        query.clear(); st.rerun()
                    if b.button(
                        _t(language, "Not same", "No es el mismo"),
                        key=f"public-connection-reject-{connection['id']}",
                        disabled=not can_review,
                    ) and _authorize(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
                        storage.set_actor_connection_decision(int(connection["id"]), "not_same")
                        query.clear(); st.rerun()
                    if c.button(
                        _t(language, "Reset", "Restablecer"),
                        key=f"public-connection-reset-{connection['id']}",
                        disabled=not can_review,
                    ) and _authorize(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
                        storage.set_actor_connection_decision(int(connection["id"]), "unreviewed")
                        query.clear(); st.rerun()
        with signals_tab:
            st.caption(_t(
                language,
                "Values are hashed in storage. This page shows only signal types and safe labels.",
                "Los valores se guardan como hashes. Esta página solo muestra tipos de señales "
                "y etiquetas seguras.",
            ))
            if detail["identifiers"]:
                identifier_rows = []
                identifier_labels = [
                    ("indicator_type", "Signal type", "Tipo de señal"),
                    ("safe_value_label", "Safe label", "Etiqueta segura"),
                    ("binding_method", "Binding", "Vinculación"),
                    ("source_scope", "Scope", "Ámbito"),
                    ("count", "Sightings", "Observaciones"),
                    ("last_seen", "Last seen", "Última detección"),
                ]
                for row in detail["identifiers"]:
                    display_row = {}
                    for key, english, spanish in identifier_labels:
                        value = row.get(key)
                        if key in {"indicator_type", "binding_method", "source_scope"}:
                            value = value_label(value, language)
                        display_row[_t(language, english, spanish)] = value
                    identifier_rows.append(display_row)
                st.dataframe(identifier_rows, use_container_width=True, hide_index=True)
            else:
                st.markdown(
                    empty_state(
                        _t(
                            language,
                            "No independent public signal types",
                            "No hay tipos de señales públicas independientes",
                        ),
                        _t(
                            language,
                            "Only validated, safely stored signal types appear here.",
                            "Aquí solo aparecen tipos de señales validados y almacenados de forma segura.",
                        ),
                    ),
                    unsafe_allow_html=True,
                )
        with events_tab:
            if not detail["events"]:
                st.markdown(
                    empty_state(
                        _t(
                            language,
                            "No username events yet",
                            "Todavía no hay eventos del alias",
                        ),
                        _t(
                            language,
                            "Review and observation changes will appear here in time order.",
                            "Los cambios de revisión y observación aparecerán aquí en orden cronológico.",
                        ),
                    ),
                    unsafe_allow_html=True,
                )
            visible_events = _page_items(
                st, detail["events"], key=f"public-actor-{selected}-events",
                page_size=20, item_name="timeline events",
                item_name_es="eventos cronológicos", language=language)
            for event in visible_events:
                st.markdown(f"**{html.escape(value_label(event['event_type'], language))}**")
                meta = _event_metadata(event.get("safe_metadata_json"), language)
                st.caption(f"{event.get('created_at') or ''}{' · ' + meta if meta else ''}")
