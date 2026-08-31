"""Spain-linked public marketplace seller workspace."""
from __future__ import annotations

import html
import json

import dashboard_auth
import storage
from dashboard_services.i18n import spain_reason_label
from ui_components import category_badge, data_row, section_header, spain_flag_badge


def _text(language: str, english: str, spanish: str) -> str:
    return spanish if language == "es" else english


_CATEGORY_LABELS = {
    "weapons_arms": ("Weapons", "Armas"),
    "drugs": ("Drugs", "Drogas"),
    "carding": ("Carding / payment fraud", "Carding / fraude de pagos"),
    "fraud_financial": ("Financial fraud", "Fraude financiero"),
    "marketplace_fraud": ("Carding / payment fraud", "Carding / fraude de pagos"),
    "leaks_data": ("Leaks / data", "Filtraciones / datos"),
    "credentials": ("Credentials", "Credenciales"),
    "malware_hacking": ("Malware / hacking", "Malware / hacking"),
    "marketplace": ("Mixed marketplace", "Mercado mixto"),
    "unknown": ("Other / unclassified", "Otro / sin clasificar"),
}

_FLOW_LABELS = {
    "from_spain": ("Ships from Spain", "Envía desde España"),
    "to_spain": ("Ships to Spain", "Envía a España"),
    "both": ("Ships from and to Spain", "Envía desde y hacia España"),
    "spain_context": ("Spain context; direction unclear", "Contexto España; dirección sin confirmar"),
    "none": ("No shipping direction", "Sin dirección de envío"),
}


def _can(st, capability: str) -> bool:
    from dashboard_pages.workspace import _can as workspace_can

    return workspace_can(st, capability)


def _authorize(st, capability: str) -> bool:
    from dashboard_pages.workspace import _authorize_action

    return _authorize_action(st, capability)


def _category_label(value: str | None, language: str) -> str:
    labels = _CATEGORY_LABELS.get(value or "unknown")
    return labels[1 if language == "es" else 0] if labels else str(value or "unknown").replace("_", " ").title()


def _flow_label(value: str | None, language: str) -> str:
    labels = _FLOW_LABELS.get(value or "none", _FLOW_LABELS["none"])
    return labels[1 if language == "es" else 0]


def _short_host(host: str | None) -> str:
    value = host or "unknown onion"
    return value if len(value) <= 32 else f"{value[:13]}…{value[-15:]}"


def _render_summary(st, items: list[tuple[str, object, str]]) -> None:
    """Render the current seller totals as a single compact information strip."""
    columns = st.columns(len(items))
    for column, (label, value, state) in zip(columns, items):
        column.markdown(data_row(label, value, state=state), unsafe_allow_html=True)


def _queue_seller(seller: dict, language: str) -> str:
    weapons_focus = int(seller.get("weapons_page_count") or 0) > 0
    warnings = int(seller.get("warning_count") or 0)
    migrations = int(seller.get("migration_count") or 0)
    state = "danger" if weapons_focus or warnings else "warn" if migrations else "ok"
    category_value = str(seller.get("latest_marketplace_category") or "unknown")
    category_name = _category_label(category_value, language)
    return (
        f'<div class="rt-queue-row rt-queue-{state}"><div class="rt-queue-main">'
        f'<strong>{spain_flag_badge(_text(language, "Spain-linked seller", "Vendedor vinculado con España"))} '
        f'{html.escape(seller.get("display_alias") or "Public seller")}</strong>'
        f'<code>{html.escape(_short_host(seller.get("onion_host")))}</code></div>'
        f'<div class="rt-queue-meta">'
        f'{category_badge(category_value, category_name)}'
        f'<span>{html.escape(_flow_label(seller.get("latest_spain_flow"), language))}</span>'
        f'<span><b>{int(seller.get("seller_page_count") or 0)}</b> '
        f'{html.escape(_text(language, "pages", "páginas"))}</span>'
        f'{"<span><b>" + html.escape(_text(language, "WEAPONS FOCUS", "FOCO ARMAS")) + "</b></span>" if weapons_focus else ""}'
        '</div></div>'
    )


def _page_items(st, items: list[dict], *, key: str, page_size: int, language: str,
                english_name: str, spanish_name: str) -> list[dict]:
    """Keep seller queues and detail activity bounded for reliable rendering."""
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


def _select_seller(st, actor_id: int) -> None:
    st.session_state["selected_spain_seller"] = int(actor_id)


def _event_metadata(event: dict) -> dict:
    try:
        value = json.loads(event.get("safe_metadata_json") or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def _render_connection(st, connection: dict, language: str, query) -> None:
    can_review = _can(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE)
    warning = connection.get("warning_type")
    migration = bool(connection.get("migration_candidate"))
    title = f"{connection.get('other_alias') or 'Public alias'} · {_short_host(connection.get('other_onion_host'))}"
    st.markdown(
        '<div class="rt-entity-row">'
        f'<strong>{html.escape(title)}</strong>'
        f'<div>{html.escape(_text(language, "Public-signal comparison", "Comparación de señales públicas"))}</div>'
        '</div>',
        unsafe_allow_html=True,
    )
    if warning:
        st.warning(_text(
            language,
            connection.get("warning_reason") or "Possible copycat: public identifiers conflict.",
            "Posible suplantación: los identificadores públicos no coinciden.",
        ))
    elif migration:
        st.info(_text(
            language,
            "Possible market move: the alias appeared on another market with shared public signals.",
            "Posible cambio de mercado: el alias apareció en otro mercado con señales públicas compartidas.",
        ))
    else:
        st.caption(_text(language, "Reviewable public-signal match", "Coincidencia revisable por señales públicas"))
    st.caption(
        f"{_text(language, 'Match confidence', 'Confianza')}: "
        f"{int(float(connection.get('confidence_score') or 0))}% · "
        f"{_text(language, 'Saved choice', 'Decisión guardada')}: "
        f"{str(connection.get('analyst_decision') or 'unreviewed').replace('_', ' ')}"
    )
    first, second = st.columns(2)
    if first.button(_text(language, "Confirm same public identity", "Confirmar misma identidad pública"),
                    key=f"seller-match-confirm-{connection['id']}",
                    disabled=not can_review) and _authorize(
                        st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
        storage.set_actor_connection_decision(int(connection["id"]), "confirmed_same")
        query.clear(); st.rerun()
    if second.button(_text(language, "Mark as different", "Marcar como diferentes"),
                     key=f"seller-match-reject-{connection['id']}",
                     disabled=not can_review) and _authorize(
                         st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
        storage.set_actor_connection_decision(int(connection["id"]), "not_same")
        query.clear(); st.rerun()


def render(st, query, language: str) -> None:
    can_review = _can(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE)
    can_watch = _can(st, dashboard_auth.CAPABILITY_WATCHLIST_MANAGE)
    st.markdown(
        '<div class="rt-section-head"><div>'
        f'<h3>{spain_flag_badge(_text(language, "Spain Seller Monitor", "Monitor de vendedores España"))} '
        f'{html.escape(_text(language, "Spain Seller Monitor", "Monitor de vendedores España"))}</h3>'
        f'<p>{html.escape(_text(language, "Public marketplace pages with exact Spain shipping evidence. Weapons remain prioritised.", "Páginas públicas de mercados con evidencia exacta de envíos vinculados con España. Las armas siguen teniendo prioridad."))}</p>'
        '</div></div>',
        unsafe_allow_html=True,
    )

    all_sellers = storage.get_spain_sellers(limit=1000)
    category_counts = {row.get("marketplace_category") or "unknown": int(row.get("count") or 0)
                       for row in storage.get_spain_seller_categories()}
    weapons_count = sum(
        1 for row in all_sellers if int(row.get("weapons_page_count") or 0) > 0
    )
    from_spain_count = sum(
        1 for row in all_sellers if int(row.get("from_spain_count") or 0) > 0
    )
    to_spain_count = sum(
        1 for row in all_sellers if int(row.get("to_spain_count") or 0) > 0
    )
    watched_count = sum(int(row.get("watched") or 0) for row in all_sellers)
    _render_summary(st, [
        (_text(language, "Public sellers", "Vendedores públicos"), len(all_sellers), ""),
        (_text(language, "Weapons focus", "Foco armas"), weapons_count,
         "critical" if weapons_count else "muted"),
        (_text(language, "From Spain", "Desde España"), from_spain_count, ""),
        (_text(language, "To Spain", "Hacia España"), to_spain_count, ""),
        (_text(language, "Watched", "En seguimiento"), watched_count,
         "warn" if watched_count else "muted"),
    ])

    if category_counts:
        st.markdown(section_header(
            _text(language, "Category overview", "Resumen de categorías"),
            _text(language, "A compact breakdown of the current seller queue.",
                  "Un desglose compacto de la cola actual de vendedores."),
            count=sum(category_counts.values()),
        ), unsafe_allow_html=True)
        ordered = sorted(category_counts, key=lambda item: (
            {"weapons_arms": 0, "drugs": 1, "carding": 2}.get(item, 3), -category_counts[item]
        ))
        category_cards = st.columns(min(4, len(ordered)))
        for index, category_name in enumerate(ordered[:8]):
            category_cards[index % len(category_cards)].markdown(
                data_row(_category_label(category_name, language), category_counts[category_name]),
                unsafe_allow_html=True,
            )

    filters = st.columns([2, 1.25, 1.25, 0.8])
    search = filters[0].text_input(
        _text(language, "Search sellers", "Buscar vendedores"),
        placeholder=_text(language, "Alias, market or category", "Alias, mercado o categoría"),
        key="spain-seller-search",
    )
    category_options = ["all"] + sorted(category_counts, key=lambda item: (
        {"weapons_arms": 0, "drugs": 1, "carding": 2}.get(item, 3), item
    ))
    category = filters[1].selectbox(
        _text(language, "Category", "Categoría"), category_options,
        format_func=lambda value: _text(language, "All categories", "Todas las categorías")
        if value == "all" else _category_label(value, language),
        key="spain-seller-category",
    )
    flow_options = ["all", "from_or_both", "to_or_both", "both", "spain_context"]
    flow = filters[2].selectbox(
        _text(language, "Spain direction", "Dirección España"), flow_options,
        format_func=lambda value: {
            "all": _text(language, "Any direction", "Cualquier dirección"),
            "from_or_both": _text(language, "From Spain", "Desde España"),
            "to_or_both": _text(language, "To Spain", "Hacia España"),
            "both": _text(language, "Both", "Ambas"),
            "spain_context": _text(language, "Direction unclear", "Dirección sin confirmar"),
        }[value], key="spain-seller-flow",
    )
    watched_only = filters[3].checkbox(_text(language, "Watched", "En seguimiento"),
                                       key="spain-seller-watched")
    sellers = storage.get_spain_sellers(
        watched_only=watched_only, search=search, spain_flow=flow, category=category
    )
    if not sellers:
        st.info(_text(
            language,
            "No public seller page matches these filters yet. Eligible market pages are added automatically while crawling.",
            "Todavía no hay páginas públicas de vendedor con estos filtros. Se añaden automáticamente durante el rastreo.",
        ))
        return

    visible_sellers = _page_items(
        st, sellers, key="spain-sellers", page_size=15, language=language,
        english_name="seller pages", spanish_name="paginas de vendedor")
    valid_ids = {int(row["id"]) for row in visible_sellers}
    selected_id = int(st.session_state.get("selected_spain_seller") or 0)
    if selected_id not in valid_ids:
        selected_id = int(visible_sellers[0]["id"])
        st.session_state["selected_spain_seller"] = selected_id
    queue_col, detail_col = st.columns([0.9, 2.1], gap="large")
    with queue_col:
        st.markdown(section_header(
            _text(language, "Seller queue", "Cola de vendedores"),
            _text(language, "Select a seller to review exact source pages.",
                  "Selecciona un vendedor para revisar las páginas fuente exactas."),
            count=len(sellers),
        ), unsafe_allow_html=True)
        for seller in visible_sellers:
            selected = int(seller["id"]) == selected_id
            st.markdown(_queue_seller(seller, language), unsafe_allow_html=True)
            if seller.get("warning_count"):
                st.caption(_text(language, "Possible copycat warning", "Aviso de posible suplantación"))
            elif seller.get("migration_count"):
                st.caption(_text(language, "Possible market move", "Posible cambio de mercado"))
            st.button(
                _text(language, "Selected seller" if selected else "Open seller",
                      "Vendedor seleccionado" if selected else "Abrir vendedor"),
                key=f"spain-seller-open-{seller['id']}", disabled=selected, width="stretch",
                on_click=_select_seller, args=(st, int(seller["id"])),
            )

    detail = storage.get_actor_detail(selected_id)
    if not detail:
        return
    actor = detail["actor"]
    seller_observations = [row for row in detail["observations"]
                           if row.get("seller_observation") and row.get("spain_priority")]
    with detail_col:
        st.markdown(
            '<div class="rt-spain-case">'
            f'<span class="rt-spain-case-label">{spain_flag_badge(_text(language, "Spain-linked seller", "Vendedor vinculado con España"))} '
            f'{html.escape(_text(language, "PUBLIC SELLER", "VENDEDOR PÚBLICO"))}</span>'
            f'<h3>{html.escape(actor.get("display_alias") or "Public seller")}</h3>'
            f'<div>{html.escape(_text(language, "Public marketplace observations only", "Solo observaciones públicas del mercado"))}</div>'
            '</div>',
            unsafe_allow_html=True,
        )
        seller_summary = st.columns(2)
        seller_summary[0].markdown(
            data_row(_text(language, "Source host", "Dominio fuente"), _short_host(actor.get("onion_host"))),
            unsafe_allow_html=True,
        )
        seller_summary[1].markdown(
            data_row(_text(language, "Exact Spain pages", "Páginas exactas España"), len(seller_observations)),
            unsafe_allow_html=True,
        )
        watch_reason = st.text_input(
            _text(language, "Watch note", "Nota de seguimiento"), value=actor.get("watch_reason") or "",
            placeholder=_text(language, "Why this public seller matters", "Por qué interesa este vendedor público"),
            key=f"seller-watch-reason-{selected_id}",
            disabled=not can_watch,
        )
        if not can_watch or not can_review:
            st.caption(_text(
                language,
                "Read-only controls are disabled for this session; evidence remains available.",
                "Los controles de edición están desactivados para esta sesión; la evidencia sigue disponible.",
            ))
        if actor.get("watched"):
            if st.button(_text(language, "Stop watching seller", "Dejar de seguir vendedor"),
                         key=f"seller-unwatch-{selected_id}",
                         disabled=not can_watch) and _authorize(
                             st, dashboard_auth.CAPABILITY_WATCHLIST_MANAGE):
                storage.set_actor_watch(selected_id, False)
                query.clear(); st.rerun()
        elif st.button(_text(language, "Watch seller", "Seguir vendedor"),
                       key=f"seller-watch-{selected_id}", type="primary",
                       disabled=not can_watch) and _authorize(
                           st, dashboard_auth.CAPABILITY_WATCHLIST_MANAGE):
            storage.set_actor_watch(selected_id, True, watch_reason)
            query.clear(); st.rerun()

        pages_tab, changes_tab, matches_tab = st.tabs([
            _text(language, "Exact pages", "Páginas exactas"),
            _text(language, "Changes", "Cambios"),
            _text(language, "Cross-market matches", "Coincidencias entre mercados"),
        ])
        with pages_tab:
            if not seller_observations:
                st.info(_text(language, "No exact seller pages are available.",
                              "No hay paginas exactas de vendedor disponibles."))
            visible_observations = _page_items(
                st, seller_observations, key=f"spain-seller-{selected_id}-pages",
                page_size=12, language=language, english_name="exact pages",
                spanish_name="paginas exactas")
            for observation in visible_observations:
                with st.container(border=False):
                    st.markdown(
                        '<div class="rt-spain-hit">'
                        f'<span class="rt-spain-hit-kind">{spain_flag_badge(_text(language, "Spain-linked page", "Página vinculada con España"))} '
                        f'{html.escape(_flow_label(observation.get("spain_flow"), language))}</span>'
                        f'{category_badge(str(observation.get("marketplace_category") or "unknown"), _category_label(observation.get("marketplace_category"), language))}'
                        '</div>',
                        unsafe_allow_html=True,
                    )
                    st.code(observation["url"], language=None)
                    st.link_button(_text(language, "Open exact public page", "Abrir página pública exacta"),
                                   observation["url"])
                    st.caption(f"{_text(language, 'Last seen', 'Última vez')}: {observation.get('last_seen')} · "
                               f"{spain_reason_label(observation.get('spain_reason'), language)}")
        with changes_tab:
            seller_events = [event for event in detail["events"] if event.get("event_type") in {
                "seller_first_seen", "seller_new_page", "shipping_changed", "seller_category_changed",
                "market_migration_detected", "possible_copycat_detected",
            }]
            if not seller_events:
                st.info(_text(language, "No seller changes recorded yet.", "Todavía no hay cambios registrados."))
            visible_events = _page_items(
                st, seller_events, key=f"spain-seller-{selected_id}-changes",
                page_size=15, language=language, english_name="changes",
                spanish_name="cambios")
            for event in visible_events:
                metadata = _event_metadata(event)
                with st.container(border=False):
                    st.markdown(
                        '<div class="rt-timeline-item">'
                        f'<strong>{html.escape(str(event.get("event_type") or "").replace("_", " ").title())}</strong>'
                        f'<div class="rt-timeline-time">{html.escape(str(event.get("created_at") or ""))}</div>'
                        '</div>',
                        unsafe_allow_html=True,
                    )
                    if metadata.get("spain_flow"):
                        st.write(_flow_label(metadata["spain_flow"], language))
                    if metadata.get("marketplace_category"):
                        st.write(_category_label(metadata["marketplace_category"], language))
                    if metadata.get("reason"):
                        st.info(metadata["reason"])
                    if metadata.get("url"):
                        st.code(metadata["url"], language=None)
        with matches_tab:
            visible_connections = [row for row in detail["connections"]
                                   if row.get("analyst_decision") != "not_same"]
            if not visible_connections:
                st.info(_text(language, "No cross-market matches yet.", "Todavía no hay coincidencias entre mercados."))
            paged_connections = _page_items(
                st, visible_connections, key=f"spain-seller-{selected_id}-matches",
                page_size=10, language=language, english_name="cross-market matches",
                spanish_name="coincidencias entre mercados")
            for connection in paged_connections:
                with st.container(border=False):
                    _render_connection(st, connection, language, query)
