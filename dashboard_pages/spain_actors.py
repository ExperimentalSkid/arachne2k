"""Public-alias watchlist for exact Spain-linked evidence pages."""
from __future__ import annotations

import html
import json

import dashboard_auth
import storage
from dashboard_services.i18n import spain_reason_label
from ui_components import (
    category_badge,
    data_row,
    risk_badge,
    section_header,
    spain_flag_badge,
)
from universal_classifier import safe_category_label


def _can(st, capability: str) -> bool:
    from dashboard_pages.workspace import _can as workspace_can

    return workspace_can(st, capability)


def _authorize(st, capability: str) -> bool:
    from dashboard_pages.workspace import _authorize_action

    return _authorize_action(st, capability)


def _text(language: str, english: str, spanish: str) -> str:
    return spanish if language == "es" else english


def _short_host(host: str | None) -> str:
    value = host or "Unknown onion domain"
    return value if len(value) <= 34 else f"{value[:14]}…{value[-16:]}"


def _render_summary(st, items: list[tuple[str, object, str]]) -> None:
    """Present the existing alias totals without another row of metric cards."""
    columns = st.columns(len(items))
    for column, (label, value, state) in zip(columns, items):
        column.markdown(data_row(label, value, state=state), unsafe_allow_html=True)


def _queue_actor(actor: dict, language: str) -> str:
    confidence = str(actor.get("confidence_label") or "low")
    watched = bool(actor.get("watched"))
    state = "warn" if watched or confidence.casefold() == "high" else "ok"
    return (
        f'<div class="rt-queue-row rt-queue-{state}"><div class="rt-queue-main">'
        f'<strong>{spain_flag_badge(_text(language, "Spain-linked alias", "Alias vinculado con España"))} '
        f'{html.escape(actor.get("display_alias") or "Public alias")}</strong>'
        f'<code>{html.escape(_short_host(actor.get("onion_host")))}</code></div>'
        f'<div class="rt-queue-meta">'
        f'<span><b>{int(actor.get("spain_observation_count") or 0)}</b> '
        f'{html.escape(_text(language, "pages", "páginas"))}</span>'
        f'<span><b>{int(actor.get("connection_count") or 0)}</b> '
        f'{html.escape(_text(language, "matches", "coincidencias"))}</span>'
        f'<span>{html.escape(("★ " if watched else "") + confidence)}</span>'
        '</div></div>'
    )


def _page_items(st, items: list[dict], *, key: str, page_size: int, language: str,
                english_name: str, spanish_name: str) -> list[dict]:
    """Keep action-heavy alias views bounded without changing their data."""
    rows = list(items or [])
    page_count = max(1, (len(rows) + page_size - 1) // page_size)
    page_key = f"{key}-page"
    stored_page = int(st.session_state.get(page_key, 1) or 1)
    selected_page = min(max(stored_page, 1), page_count)
    if stored_page != selected_page:
        st.session_state[page_key] = selected_page
    if page_count > 1:
        selected_page = int(st.selectbox(
            _text(language, f"{english_name.title()} page", f"Pagina de {spanish_name}"),
            list(range(1, page_count + 1)),
            index=selected_page - 1,
            format_func=lambda value: _text(
                language, f"Page {value} of {page_count}", f"Pagina {value} de {page_count}"),
            key=page_key,
        ))
    start = (selected_page - 1) * page_size
    visible = rows[start:start + page_size]
    if rows:
        st.caption(_text(
            language,
            f"Showing {start + 1}-{start + len(visible)} of {len(rows)} {english_name}.",
            f"Mostrando {start + 1}-{start + len(visible)} de {len(rows)} {spanish_name}.",
        ))
    return visible


def _select_actor(st, actor_id: int) -> None:
    st.session_state["selected_spain_actor"] = int(actor_id)


def _render_observation(st, observation: dict, language: str, query) -> None:
    can_review = _can(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE)
    st.markdown(
        '<div class="rt-spain-hit">'
        f'<span class="rt-spain-hit-kind">{spain_flag_badge(_text(language, "Spain-linked page", "Página vinculada con España"))} '
        f'{html.escape(str(observation.get("page_type") or "page").replace("_", " ").title())}</span>'
        f'{category_badge(str(observation.get("primary_category") or "unknown"), safe_category_label(observation.get("primary_category")))}'
        f'{risk_badge(str(observation.get("risk_level") or "unknown"), str(observation.get("risk_level") or "unknown").title())}'
        '</div>',
        unsafe_allow_html=True,
    )
    st.code(observation["url"], language=None)
    st.link_button(_text(language, "Open exact public page", "Abrir página pública exacta"),
                   observation["url"], type="secondary")
    st.caption(
        f"{_text(language, 'Observed as', 'Observado como')}: "
        f"{observation.get('safe_context_label') or 'Public alias'} · "
        f"{_text(language, 'Last seen', 'Última vez visto')}: {observation.get('last_seen') or 'unknown'}"
    )
    if observation.get("spain_priority"):
        st.info(
            f"{_text(language, 'Why Spain matched', 'Motivo de coincidencia')}: "
            f"{spain_reason_label(observation.get('spain_reason'), language)}"
        )
    with st.expander(_text(language, "Wrong alias match?", "¿Alias incorrecto?")):
        st.caption(_text(
            language,
            "Use this when this exact page was attached to the wrong public alias. The page and its normal history remain stored.",
            "Úsalo si esta página exacta se vinculó al alias público incorrecto. La página y su historial normal se conservan.",
        ))
        confirmed = st.toggle(
            _text(language, "Slide to confirm timeline removal", "Desliza para confirmar la eliminación"),
            value=False, key=f"actor-observation-confirm-{observation['id']}",
            disabled=not can_review,
        )
        if st.button(
            _text(language, "Remove page from this alias", "Quitar página de este alias"),
            key=f"actor-observation-remove-{observation['id']}",
            disabled=not can_review or not confirmed,
        ) and _authorize(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
            if storage.exclude_actor_observation(int(observation["id"])):
                query.clear()
                st.success(_text(language, "The page was removed from this alias timeline.",
                                 "La página se eliminó de la cronología de este alias."))
                st.rerun()


def _render_connection(st, connection: dict, language: str, query) -> None:
    can_review = _can(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE)
    decision = connection.get("analyst_decision") or "unreviewed"
    score = int(float(connection.get("confidence_score") or 0))
    st.markdown(
        '<div class="rt-entity-row">'
        f'<strong>{html.escape(connection.get("other_alias") or "Unknown alias")}</strong>'
        f'<div><code>{html.escape(_short_host(connection.get("other_onion_host")))}</code></div>'
        '</div>',
        unsafe_allow_html=True,
    )
    st.caption(
        f"{_text(language, 'Possible-match confidence', 'Confianza de posible coincidencia')}: "
        f"{score}% ({connection.get('confidence_label') or 'low'}) · "
        f"{_text(language, 'Saved choice', 'Opción guardada')}: {decision.replace('_', ' ')}"
    )
    try:
        evidence = json.loads(connection.get("evidence_json") or "[]")
    except (TypeError, ValueError):
        evidence = []
    for item in evidence:
        st.markdown(f"- {html.escape(str(item.get('label') or 'Public correlation signal'))}")
    st.warning(_text(
        language,
        "These public aliases share signals. Review the linked pages before grouping them.",
        "Estos alias públicos comparten señales. Revisa las páginas vinculadas antes de agruparlos.",
    ))
    action_a, action_b, action_c = st.columns(3)
    if action_a.button(_text(language, "Confirm match", "Confirmar coincidencia"),
                       key=f"actor-connection-confirm-{connection['id']}",
                       disabled=not can_review) and _authorize(
                           st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
        storage.set_actor_connection_decision(int(connection["id"]), "confirmed_same")
        query.clear(); st.rerun()
    if action_b.button(_text(language, "Not a match", "No coinciden"),
                       key=f"actor-connection-reject-{connection['id']}",
                       disabled=not can_review) and _authorize(
                           st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
        storage.set_actor_connection_decision(int(connection["id"]), "not_same")
        query.clear(); st.rerun()
    if action_c.button(_text(language, "Reset decision", "Restablecer decisión"),
                       key=f"actor-connection-reset-{connection['id']}",
                       disabled=not can_review) and _authorize(
                           st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
        storage.set_actor_connection_decision(int(connection["id"]), "unreviewed")
        query.clear(); st.rerun()


def render(st, query, language: str) -> None:
    can_review = _can(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE)
    can_watch = _can(st, dashboard_auth.CAPABILITY_WATCHLIST_MANAGE)
    st.markdown(
        '<div class="rt-section-head"><div>'
        f'<h3>{spain_flag_badge(_text(language, "Spain alias watchlist", "Seguimiento de alias de España"))} '
        f'{html.escape(_text(language, "Spain alias watchlist", "Seguimiento de alias de España"))}</h3>'
        f'<p>{html.escape(_text(language, "Public aliases with exact Spain-linked source pages. Suggested matches remain reviewable.", "Alias públicos con páginas fuente exactas vinculadas con España. Las coincidencias sugeridas siguen siendo revisables."))}</p>'
        '</div></div>',
        unsafe_allow_html=True,
    )
    if not can_watch or not can_review:
        st.caption(_text(
            language,
            "Read-only controls are disabled for this session; evidence remains available.",
            "Los controles de edición están desactivados para esta sesión; la evidencia sigue disponible.",
        ))
    filters = st.columns([2, 1])
    search = filters[0].text_input(
        _text(language, "Search aliases", "Buscar alias"),
        placeholder=_text(language, "Alias, onion site or category", "Alias, sitio onion o categoría"),
        key="spain-actor-search",
    )
    watched_only = filters[1].checkbox(_text(language, "Watched only", "Solo vigilados"),
                                       key="spain-actors-watched-only")
    actors = storage.get_spain_actors(watched_only=watched_only, search=search)
    all_actors = storage.get_spain_actors(limit=1000)
    watch_alerts = storage.get_actor_watch_alerts()
    watched_count = sum(int(actor.get("watched") or 0) for actor in all_actors)
    spain_page_count = sum(int(actor.get("spain_observation_count") or 0) for actor in all_actors)
    _render_summary(st, [
        (_text(language, "Public aliases", "Alias públicos"), len(all_actors), ""),
        (_text(language, "Watched", "Vigilados"), watched_count,
         "warn" if watched_count else "muted"),
        (_text(language, "Spain-linked pages", "Páginas vinculadas con España"), spain_page_count, ""),
        (_text(language, "New watch updates", "Nuevas actualizaciones"), len(watch_alerts),
         "critical" if watch_alerts else "muted"),
    ])
    if watch_alerts:
        st.markdown(section_header(
            _text(language, "New watch updates", "Nuevas actualizaciones vigiladas"),
            _text(language, "Each exact page appears once; acknowledge it after review.",
                  "Cada página exacta aparece una vez; márcala revisada después de revisarla."),
            count=len(watch_alerts),
        ), unsafe_allow_html=True)
        visible_alerts = _page_items(
            st, watch_alerts, key="spain-actor-watch-alerts", page_size=10,
            language=language, english_name="watch updates",
            spanish_name="actualizaciones vigiladas")
        for alert in visible_alerts:
            with st.container(border=False):
                related = (f" → {alert.get('related_alias')}" if alert.get("related_alias") else "")
                st.markdown(
                    '<div class="rt-spain-hit">'
                    f'<span class="rt-spain-hit-kind">{spain_flag_badge(_text(language, "Spain-linked update", "Actualización vinculada con España"))} '
                    f'{html.escape(str(alert.get("alert_type") or "").replace("_", " ").title())}</span>'
                    f'<strong>{html.escape(alert.get("display_alias") or "Public alias")}{html.escape(related)}</strong>'
                    '</div>',
                    unsafe_allow_html=True,
                )
                st.code(alert["url"], language=None)
                st.caption(alert.get("safe_reason") or _text(language, "Watched alias update", "Actualización de alias vigilado"))
                action_a, action_b = st.columns([1, 1])
                action_a.link_button(_text(language, "Open exact page", "Abrir página exacta"), alert["url"])
                if action_b.button(_text(language, "Mark reviewed", "Marcar revisado"),
                                   key=f"actor-alert-ack-{alert['id']}",
                                   disabled=not can_review) and _authorize(
                                       st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
                    storage.acknowledge_actor_watch_alert(int(alert["id"]))
                    query.clear(); st.rerun()
    if not actors:
        st.info(_text(
            language,
            "No public aliases have appeared on Spain-linked pages yet. They will be added automatically as eligible pages are checked.",
            "Todavía no aparecieron alias públicos en páginas vinculadas con España. Se añadirán automáticamente al revisar páginas válidas.",
        ))
        return

    visible_actors = _page_items(
        st, actors, key="spain-actors", page_size=15, language=language,
        english_name="aliases", spanish_name="alias")
    valid_ids = {int(actor["id"]) for actor in visible_actors}
    selected_id = int(st.session_state.get("selected_spain_actor") or 0)
    if selected_id not in valid_ids:
        selected_id = int(visible_actors[0]["id"])
        st.session_state["selected_spain_actor"] = selected_id
    queue_col, detail_col = st.columns([0.85, 2.15], gap="large")
    with queue_col:
        st.markdown(section_header(
            _text(language, "Alias queue", "Cola de alias"),
            _text(language, "Choose an alias to inspect its exact-page timeline.",
                  "Elige un alias para revisar su cronología de páginas exactas."),
            count=len(actors),
        ), unsafe_allow_html=True)
        for actor in visible_actors:
            selected = int(actor["id"]) == selected_id
            st.markdown(_queue_actor(actor, language), unsafe_allow_html=True)
            st.button(
                _text(language, "Selected alias" if selected else "Open alias",
                      "Alias seleccionado" if selected else "Abrir alias"),
                key=f"spain-actor-open-{actor['id']}", disabled=selected, width="stretch",
                on_click=_select_actor, args=(st, int(actor["id"])),
            )

    detail = storage.get_actor_detail(selected_id)
    if not detail:
        return
    actor = detail["actor"]
    with detail_col:
        st.markdown(
            '<div class="rt-spain-case">'
            f'<span class="rt-spain-case-label">{spain_flag_badge(_text(language, "Spain-linked alias", "Alias vinculado con España"))} '
            f'{html.escape(_text(language, "PUBLIC ALIAS", "ALIAS PÚBLICO"))}</span>'
            f'<h3>{html.escape(actor["display_alias"])}</h3>'
            f'<div>{category_badge(str(actor.get("primary_category") or "unknown"), safe_category_label(actor.get("primary_category")))}</div>'
            '</div>', unsafe_allow_html=True,
        )
        actor_summary = st.columns(2)
        actor_summary[0].markdown(
            data_row(_text(language, "Source host", "Dominio fuente"), _short_host(actor.get("onion_host"))),
            unsafe_allow_html=True,
        )
        actor_summary[1].markdown(
            data_row(
                _text(language, "Spain-linked pages", "Páginas vinculadas con España"),
                int(actor.get("spain_observation_count") or 0),
            ),
            unsafe_allow_html=True,
        )
        watch_reason = st.text_input(
            _text(language, "Why are you watching this alias?", "¿Por qué vigilas este alias?"),
            value=actor.get("watch_reason") or "", key=f"actor-watch-reason-{selected_id}",
            placeholder=_text(language, "Short note", "Nota breve"),
            disabled=not can_watch,
        )
        if actor.get("watched"):
            if st.button(
                _text(language, "Stop watching", "Dejar de vigilar"),
                key=f"actor-unwatch-{selected_id}", disabled=not can_watch,
            ) and _authorize(st, dashboard_auth.CAPABILITY_WATCHLIST_MANAGE):
                storage.set_actor_watch(selected_id, False)
                query.clear(); st.rerun()
        else:
            if st.button(_text(language, "Watch this alias", "Vigilar este alias"),
                         key=f"actor-watch-{selected_id}", type="primary",
                         disabled=not can_watch) and _authorize(
                             st, dashboard_auth.CAPABILITY_WATCHLIST_MANAGE):
                storage.set_actor_watch(selected_id, True, watch_reason)
                query.clear(); st.rerun()

        timeline_tab, connections_tab, identifiers_tab = st.tabs([
            _text(language, "Page timeline", "Cronología de páginas"),
            _text(language, "Possible matches", "Posibles coincidencias"),
            _text(language, "Shared public signals", "Señales públicas compartidas"),
        ])
        with timeline_tab:
            if not detail["observations"]:
                st.info(_text(language, "No active pages remain for this alias.",
                              "No quedan páginas activas para este alias."))
            visible_observations = _page_items(
                st, detail["observations"], key=f"spain-actor-{selected_id}-observations",
                page_size=12, language=language, english_name="page sightings",
                spanish_name="observaciones de pagina")
            for observation in visible_observations:
                with st.container(border=False):
                    _render_observation(st, observation, language, query)
        with connections_tab:
            visible = [item for item in detail["connections"] if item.get("analyst_decision") != "not_same"]
            if not visible:
                st.info(_text(language, "No unresolved cross-site correspondences are available.",
                              "No hay correspondencias entre sitios pendientes."))
            visible_connections = _page_items(
                st, visible, key=f"spain-actor-{selected_id}-connections",
                page_size=10, language=language, english_name="possible matches",
                spanish_name="posibles coincidencias")
            for connection in visible_connections:
                with st.container(border=False):
                    _render_connection(st, connection, language, query)
            rejected = [item for item in detail["connections"] if item.get("analyst_decision") == "not_same"]
            if rejected:
                with st.expander(_text(language, f"Rejected suggestions ({len(rejected)})",
                                       f"Sugerencias rechazadas ({len(rejected)})")):
                    visible_rejected = _page_items(
                        st, rejected, key=f"spain-actor-{selected_id}-rejected",
                        page_size=10, language=language, english_name="rejected suggestions",
                        spanish_name="sugerencias rechazadas")
                    for connection in visible_rejected:
                        _render_connection(st, connection, language, query)
        with identifiers_tab:
            st.caption(_text(
                language,
                "Only the types of shared public signals are shown here. Contact values are not repeated on this page.",
                "Aquí solo se muestran los tipos de señales públicas compartidas. Los valores de contacto no se repiten en esta página.",
            ))
            if detail["identifiers"]:
                st.dataframe(detail["identifiers"], use_container_width=True, hide_index=True)
            else:
                st.info(_text(language, "No independent public identifier has been attached yet.",
                              "Todavía no se adjuntó ningún identificador público independiente."))
