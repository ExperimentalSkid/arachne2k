"""Focused, metadata-safe workspace for Spain Priority case review."""
from __future__ import annotations

import html

import site_dedupe
import storage
import dashboard_auth
from safety_policy import is_onion_url
from dashboard_pages import spain_actors, spain_sellers
from dashboard_services.i18n import (category_label, current_language, spain_reason_label,
                                     tr, value_label)
from ui_components import (
    category_badge,
    data_row,
    metric_strip,
    review_badge,
    risk_badge,
    section_header,
    spain_flag_badge,
)


REVIEW_ACTIONS = ["unreviewed", "keep", "needs_report", "reported", "ignored", "blocked"]
HIT_FILTERS = ["All hits", "Direct thread/post hits", "Search hits", "Forum sections",
               "Author search hits", "New since last review", "High risk only"]


def _can(st, capability: str) -> bool:
    from dashboard_pages.workspace import _can as workspace_can

    return workspace_can(st, capability)


def _authorize(st, capability: str) -> bool:
    from dashboard_pages.workspace import _authorize_action

    return _authorize_action(st, capability)


def _text(language: str, english: str, spanish: str) -> str:
    return spanish if language == "es" else english


def _risk_label(rank: int) -> str:
    return {4: "critical", 3: "high", 2: "medium"}.get(int(rank or 0), "low")


def _short_host(host: str | None) -> str:
    value = host or "Unknown onion domain"
    if len(value) <= 34:
        return value
    return f"{value[:14]}…{value[-16:]}"


def _render_summary(st, language: str, items: list[tuple[str, object, str]]) -> None:
    """Render the existing case totals as one quiet, scan-friendly strip."""
    st.markdown(
        metric_strip((label, value, None, state or "muted") for label, value, state in items),
        unsafe_allow_html=True,
    )


def _queue_case(tree: dict, language: str) -> str:
    """Return a compact, escaped queue row without changing case semantics."""
    risk = _risk_label(tree.get("risk_rank"))
    direct = int(tree.get("direct_thread_hits") or 0) + int(tree.get("direct_post_hits") or 0)
    total = int(tree.get("total_spain_hits") or 0)
    state = "danger" if risk in {"high", "critical"} else "warn"
    return (
        f'<div class="rt-queue-row rt-queue-{state}"><div class="rt-queue-main">'
        f'<strong>{spain_flag_badge(_text(language, "Spain-linked site", "Sitio vinculado con España"))} '
        f'{html.escape(category_label(tree.get("primary_category"), language))}</strong>'
        f'<code>{html.escape(_short_host(tree.get("onion_host")))}</code></div>'
        f'<div class="rt-queue-meta">'
        f'<span><b>{total}</b> {html.escape(_text(language, "pages", "páginas"))}</span>'
        f'<span><b>{direct}</b> {html.escape(_text(language, "direct", "directas"))}</span>'
        f'{risk_badge(risk, value_label(risk, language))}'
        f'{review_badge(str(tree.get("review_status") or "unreviewed"), value_label(tree.get("review_status") or "unreviewed", language))}'
        '</div></div>'
    )


def _page_items(st, items: list[dict], *, key: str, page_size: int, language: str,
                english_name: str, spanish_name: str) -> list[dict]:
    """Render only one bounded page while retaining the complete filtered result."""
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


def _select_case(st, site_tree_id: str) -> None:
    st.session_state["selected_spain_tree"] = site_tree_id


def _open_site_card(st, site_card_id: int) -> None:
    from dashboard_pages.site_directory import open_card
    open_card(int(site_card_id), False)


def _category_editor(st, query, site_card_id: int | None, current_category: str,
                     language: str, key_prefix: str) -> None:
    can_edit = _can(st, dashboard_auth.CAPABILITY_SITE_CARDS_EDIT)
    st.markdown("#### " + _text(language, "Correct the classification", "Corregir la clasificación"))
    st.caption(_text(
        language,
        "If the automatic category is wrong, choose the correct one. This changes the whole Site Card and records an audit event.",
        "Si la categoría automática es incorrecta, elige la correcta. El cambio se aplica a toda la ficha y queda registrado.",
    ))
    if not site_card_id:
        st.info(_text(language, "This site is not attached to a Site Card yet.",
                      "Este sitio todavía no está vinculado a una ficha."))
        return
    if current_category in {"adult_filtered", "adult_restricted", "severe_abuse_risk"}:
        st.warning(_text(
            language,
            "Safety-restricted categories are reviewed from Advanced → Restricted Metadata so content cannot be exposed here.",
            "Las categorías restringidas se revisan en Avanzado → Metadatos restringidos para no exponer contenido aquí.",
        ))
        return
    options = site_dedupe.ANALYST_CATEGORY_OPTIONS
    index = options.index(current_category) if current_category in options else 0
    selected = st.selectbox(
        _text(language, "Correct category", "Categoría correcta"),
        options,
        index=index,
        format_func=lambda value: category_label(value, language),
        key=f"{key_prefix}-category-{site_card_id}",
        help=_text(language, "This manual correction is kept in the change history.",
                   "Esta corrección manual se conserva en el historial de cambios."),
        disabled=not can_edit,
    )
    if st.button(_text(language, "Save category correction", "Guardar corrección"),
                 key=f"{key_prefix}-save-category-{site_card_id}", type="primary",
                 disabled=not can_edit) and _authorize(
                     st, dashboard_auth.CAPABILITY_SITE_CARDS_EDIT):
        try:
            site_dedupe.apply_manual_category(site_card_id, selected)
        except ValueError as exc:
            st.error(str(exc))
        else:
            query.clear()
            st.success(_text(language, "Category corrected and change saved.",
                             "Categoría corregida y cambio guardado."))
            st.rerun()


def _review_editor(st, query, tree: dict, language: str) -> None:
    can_review = _can(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE)
    st.markdown("#### " + _text(language, "Site review", "Revisión del sitio"))
    st.caption(_text(
        language,
        "This choice applies to every Spain-linked page grouped under this onion domain.",
        "Esta opción se aplica a todas las páginas vinculadas con España agrupadas en este dominio onion.",
    ))
    current = tree.get("review_status") or "unreviewed"
    index = REVIEW_ACTIONS.index(current) if current in REVIEW_ACTIONS else 0
    labels_es = {"unreviewed": "Sin revisar", "keep": "Conservar", "needs_report": "Necesita informe",
                 "reported": "Informado", "ignored": "Ignorar", "blocked": "Bloqueado"}
    action = st.selectbox(
        _text(language, "Review decision", "Decisión de revisión"),
        REVIEW_ACTIONS,
        index=index,
        format_func=lambda value: labels_es.get(value, value) if language == "es" else value.replace("_", " ").title(),
        key=f"spain-tree-action-{tree['site_tree_id']}",
        disabled=not can_review,
    )
    if st.button(_text(language, "Apply choice to this site", "Aplicar opción a este sitio"),
                 key=f"spain-tree-save-{tree['site_tree_id']}",
                 disabled=not can_review) and _authorize(
                     st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
        storage.set_spain_tree_review(tree["site_tree_id"], action)
        query.clear()
        st.success(tr("domain_updated", language))
        st.rerun()


def _render_hit(st, hit: dict, language: str, query) -> None:
    can_review = _can(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE)
    hit_type = str(hit.get("hit_type") or "unknown").replace("_", " ").title()
    restricted = bool(hit.get("metadata_only"))
    st.markdown(
        '<div class="rt-spain-hit">'
        f'<span class="rt-spain-hit-kind">{html.escape(hit_type)}</span>'
        f'<strong>{html.escape(category_label(hit.get("primary_category"), language))}</strong>'
        f'<span>{html.escape(value_label(hit.get("risk_level"), language))}</span>'
        f'<span>{html.escape(_text(language, "Metadata only" if restricted else "Safe metadata", "Solo metadatos" if restricted else "Metadatos seguros"))}</span>'
        '</div>',
        unsafe_allow_html=True,
    )
    st.code(hit.get("canonical_url") or _text(language, "URL unavailable", "URL no disponible"), language=None)
    if hit.get("canonical_url") and is_onion_url(hit["canonical_url"]):
        st.link_button(_text(language, "Open flagged location", "Abrir ubicación marcada"),
                       hit["canonical_url"], type="secondary")
    st.caption(
        f"{_text(language, 'Why this is Spain-linked', 'Por qué está vinculado con España')}: "
        f"{spain_reason_label(hit.get('spain_reason'), language)} · "
        f"{_text(language, 'Last seen', 'Última vez visto')}: {hit.get('last_seen') or 'unknown'}"
    )
    with st.expander(_text(language, "Spain classification controls", "Controles de clasificación España")):
        st.caption(_text(
            language,
            "This removes only this page from Spain Priority. The page, its normal category and its crawl history remain stored.",
            "Esto solo elimina esta página de Prioridad España. La página, su categoría normal y su historial de rastreo se conservan.",
        ))
        confirmed = st.toggle(
            _text(language, "Slide to confirm removal", "Desliza para confirmar la eliminación"),
            value=False,
            key=f"spain-remove-confirm-{hit['id']}",
            disabled=not can_review,
        )
        if st.button(
            _text(language, "Remove this page from Spain Priority", "Eliminar esta página de Prioridad España"),
            key=f"spain-remove-{hit['id']}",
            disabled=not confirmed or not can_review,
            type="primary",
        ) and _authorize(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
            if storage.suppress_spain_hit(int(hit["id"])):
                query.clear()
                st.success(_text(language, "Page removed from Spain Priority.",
                                 "Página eliminada de Prioridad España."))
                st.rerun()
            else:
                st.error(_text(language, "The Spain finding no longer exists.",
                               "El hallazgo de España ya no existe."))


def render(st, query) -> None:
    language = current_language(st)
    st.markdown(
        '<div class="rt-spain-hero"><div>'
        f'<span>{spain_flag_badge(_text(language, "Spain Priority", "Prioridad España"))} '
        f'{html.escape(_text(language, "Spain Priority", "Prioridad España"))}</span>'
        f'<p>{html.escape(tr("spain_tree_help", language))}</p></div></div>',
        unsafe_allow_html=True,
    )
    workspace = st.radio(
        _text(language, "Spain workspace", "Espacio de España"), ["Cases", "Actors", "Sellers"],
        horizontal=True, key="spain-workspace-mode",
        format_func=lambda value: ({"Cases": "Sitios", "Actors": "Alias", "Sellers": "Vendedores"}.get(value, value)
                                   if language == "es" else {"Cases": "Sites", "Actors": "Aliases",
                                                              "Sellers": "Sellers"}.get(value, value)),
        help=_text(language,
                   "Sites group pages by onion domain. Aliases follow public names. Sellers organise public market pages by category and Spain shipping direction.",
                   "Sitios agrupa páginas por dominio onion. Alias sigue nombres públicos. Vendedores organiza mercados públicos por categoría y dirección de envío."),
    )
    if workspace == "Actors":
        spain_actors.render(st, query, language)
        return
    if workspace == "Sellers":
        spain_sellers.render(st, query, language)
        return
    trees = storage.get_spain_domain_trees()
    legacy_cards = query("""SELECT sc.id,sc.analyst_title,sc.display_name,sc.primary_category,sc.risk_level,
      sc.spain_match_reason,sc.spain_confidence,sc.last_seen,
      (SELECT onion_host FROM site_card_urls WHERE site_card_id=sc.id ORDER BY id LIMIT 1) AS onion_host
      FROM site_cards sc WHERE sc.spain_priority=1
      AND COALESCE(sc.ui_hidden_default,0)=0
      AND NOT EXISTS(SELECT 1 FROM spain_hits sh WHERE sh.site_card_id=sc.id)
      AND sc.primary_category NOT IN ('adult_filtered','adult_restricted','severe_abuse_risk')
      AND EXISTS(SELECT 1 FROM onion_urls ou WHERE ou.site_card_id=sc.id
        AND ou.spain_priority=1 AND COALESCE(ou.spain_analyst_suppressed,0)=0
        AND COALESCE(ou.spain_review_status,'unreviewed')='unreviewed')
      ORDER BY sc.review_score DESC,sc.last_seen DESC LIMIT 100""")

    direct_hits = sum(int(tree.get("direct_thread_hits") or 0) + int(tree.get("direct_post_hits") or 0)
                      for tree in trees)
    unreviewed_count = sum(
        1 for tree in trees if (tree.get("review_status") or "unreviewed") == "unreviewed"
    ) + len(legacy_cards)
    high_risk_count = (
        sum(1 for tree in trees if int(tree.get("risk_rank") or 0) >= 3)
        + sum(1 for card in legacy_cards
              if str(card.get("risk_level") or "").casefold() in {"high", "critical", "alto", "critico"})
    )
    _render_summary(st, language, [
        (_text(language, "Spain leads", "Señales de España"), len(trees) + len(legacy_cards), ""),
        (_text(language, "Unreviewed", "Sin revisar"), unreviewed_count,
         "warn" if unreviewed_count else "muted"),
        (_text(language, "Exact pages", "Páginas exactas"), direct_hits, ""),
        (_text(language, "High / critical", "Riesgo alto / crítico"), high_risk_count,
         "critical" if high_risk_count else "muted"),
    ])

    st.markdown(section_header(
        _text(language, "Pages to check", "Páginas para revisar"),
        _text(
            language,
            "Cases with a stored page-level reason. Filter the queue, select a site, then review the exact match.",
            "Casos con un motivo guardado a nivel de página. Filtra la cola, selecciona un sitio y revisa la coincidencia exacta.",
        ),
        count=len(trees),
    ), unsafe_allow_html=True)
    with st.container(key="rt-spain-filters"):
        filter_a, filter_b, filter_c = st.columns([2, 1, 1])
        search = filter_a.text_input(_text(language, "Search sites", "Buscar sitios"),
                                     placeholder=_text(language, "Onion domain, category or reason",
                                                       "Dominio onion, categoría o motivo"))
        status_options = ["All"] + REVIEW_ACTIONS
        status_es = {"All": "Todos", "unreviewed": "Sin revisar", "keep": "Conservar",
                     "needs_report": "Necesita informe", "reported": "Informado",
                     "ignored": "Ignorar", "blocked": "Bloqueado"}
        status_filter = filter_b.selectbox(
            _text(language, "Site status", "Estado del sitio"), status_options,
            format_func=lambda value: status_es.get(value, value) if language == "es" else value.replace("_", " ").title(),
        )
        hit_es = {"All hits": "Todos", "Direct thread/post hits": "Hilos y mensajes",
                  "Search hits": "Búsquedas", "Forum sections": "Secciones",
                  "Author search hits": "Búsqueda por autor", "New since last review": "Nuevos",
                  "High risk only": "Solo riesgo alto"}
        hit_en = {"All hits": "All pages", "Direct thread/post hits": "Direct threads / posts",
                  "Search hits": "Search pages", "Forum sections": "Forum sections",
                  "Author search hits": "Author search pages", "New since last review": "New since last review",
                  "High risk only": "High risk only"}
        hit_filter = filter_c.selectbox(
            _text(language, "Pages shown", "Páginas visibles"), HIT_FILTERS,
            format_func=lambda value: hit_es.get(value, value) if language == "es" else hit_en.get(value, value),
        )

    needle = search.casefold().strip()
    visible_trees = []
    for tree in trees:
        haystack = " ".join(str(tree.get(key) or "") for key in
                            ("onion_host", "primary_category", "spain_reason", "review_status")).casefold()
        if needle and needle not in haystack:
            continue
        if status_filter != "All" and (tree.get("review_status") or "unreviewed") != status_filter:
            continue
        visible_trees.append(tree)
    visible_trees.sort(
        key=lambda tree: (
            (tree.get("review_status") or "unreviewed") == "unreviewed",
            int(tree.get("direct_thread_hits") or 0) + int(tree.get("direct_post_hits") or 0),
            int(tree.get("risk_rank") or 0),
            str(tree.get("last_seen") or ""),
        ),
        reverse=True,
    )

    if not trees and not legacy_cards:
        st.info(_text(language, "No Spain Priority sites are currently stored.",
                      "No hay sitios de Prioridad España guardados."))
        return
    if not visible_trees:
        if legacy_cards:
            st.info(_text(
                language,
                f"No exact-page cases match these filters. {len(legacy_cards)} card-level lead(s) still need review below.",
                f"No hay casos de página exacta que coincidan. Quedan {len(legacy_cards)} señal(es) a nivel de ficha para revisar abajo.",
            ))
        else:
            st.info(_text(language, "No onion sites match these filters.",
                          "Ningún sitio onion coincide con estos filtros."))
    else:
        visible_tree_page = _page_items(
            st, visible_trees, key="spain-sites", page_size=15, language=language,
            english_name="sites", spanish_name="sitios")
        valid_ids = {tree["site_tree_id"] for tree in visible_tree_page}
        selected_id = st.session_state.get("selected_spain_tree")
        if selected_id not in valid_ids:
            selected_id = visible_tree_page[0]["site_tree_id"]
            st.session_state["selected_spain_tree"] = selected_id
        selected_tree = next(tree for tree in visible_tree_page if tree["site_tree_id"] == selected_id)

        queue_col, detail_col = st.columns([0.85, 2.15], gap="large")
        with queue_col:
            st.markdown(section_header(
                _text(language, "Site queue", "Cola de sitios"),
                _text(language, "Direct matches are listed first.",
                      "Las coincidencias directas aparecen primero."),
                count=len(visible_trees),
            ), unsafe_allow_html=True)
            for tree in visible_tree_page:
                selected = tree["site_tree_id"] == selected_id
                with st.container(key=f"rt-spain-queue-{tree['site_tree_id']}"):
                    st.markdown(_queue_case(tree, language), unsafe_allow_html=True)
                    st.button(
                        _text(language, "Selected site" if selected else "Open site",
                              "Sitio seleccionado" if selected else "Abrir sitio"),
                        key=f"spain-open-{tree['site_tree_id']}",
                        disabled=selected,
                        width="stretch",
                        on_click=_select_case,
                        args=(st, tree["site_tree_id"]),
                    )

        with detail_col:
            st.markdown('<span class="rt-spain-detail-marker" aria-hidden="true"></span>',
                        unsafe_allow_html=True)
            host = selected_tree.get("onion_host") or "Unknown onion domain"
            risk = _risk_label(selected_tree.get("risk_rank"))
            direct = int(selected_tree.get("direct_thread_hits") or 0) + int(selected_tree.get("direct_post_hits") or 0)
            st.markdown(
                '<div class="rt-spain-case">'
                f'<span class="rt-spain-case-label">{spain_flag_badge(_text(language, "Spain-linked site", "Sitio vinculado con España"))} '
                f'{html.escape(_text(language, "SELECTED SITE", "SITIO SELECCIONADO"))}</span>'
                f'<h3>{html.escape(host)}</h3>'
                f'<div>{category_badge(str(selected_tree.get("primary_category") or "unknown"), category_label(selected_tree.get("primary_category"), language))}'
                f'{risk_badge(risk, value_label(risk, language))}'
                f'{review_badge(str(selected_tree.get("review_status") or "unreviewed"), value_label(selected_tree.get("review_status") or "unreviewed", language))}</div>'
                '</div>',
                unsafe_allow_html=True,
            )
            detail_stats = st.columns(2)
            detail_stats[0].markdown(
                data_row(_text(language, "Direct pages", "Páginas directas"), direct),
                unsafe_allow_html=True,
            )
            detail_stats[1].markdown(
                data_row(
                    _text(language, "Matching pages", "Páginas coincidentes"),
                    int(selected_tree.get("total_spain_hits") or 0),
                ),
                unsafe_allow_html=True,
            )
            st.markdown(section_header(
                _text(language, "Why this site is shown", "Por qué aparece este sitio"),
                _text(language, "The stored Spain-specific reason for this case.",
                      "El motivo específico de España guardado para este caso."),
            ), unsafe_allow_html=True)
            st.write(spain_reason_label(selected_tree.get("spain_reason"), language))
            st.caption(f"{_text(language, 'First seen', 'Primera vez visto')}: {selected_tree.get('first_seen') or 'unknown'} · "
                       f"{_text(language, 'Last seen', 'Última vez visto')}: {selected_tree.get('last_seen') or 'unknown'}")

            hits = storage.get_spain_tree_hits(
                selected_tree["site_tree_id"], None if hit_filter == "All hits" else hit_filter,
            )
            exact_hit = next((hit for hit in hits if hit.get("canonical_url") and
                              is_onion_url(hit["canonical_url"])), None)
            if selected_tree.get("site_card_id"):
                st.button(
                    _text(language, "Open dashboard Site Card and clear alert",
                          "Abrir ficha del panel y quitar alerta"),
                    key=f"spain-open-card-{selected_tree['site_tree_id']}",
                    type="primary",
                    width="stretch",
                    on_click=_open_site_card,
                    args=(st, int(selected_tree["site_card_id"])),
                )
            if exact_hit:
                st.link_button(
                    _text(language, "Open the exact page that triggered Spain Priority",
                          "Abrir la página exacta que activó Prioridad España"),
                    exact_hit["canonical_url"], type="primary", width="stretch",
                )
            st.markdown(section_header(
                _text(language, "Matching pages", "Páginas coincidentes"),
                _text(language, "Review the exact page and its stored reason.",
                      "Revisa la página exacta y su motivo guardado."),
                count=len(hits),
            ), unsafe_allow_html=True)
            if not hits:
                st.info(_text(language, "No pages match the selected filter.",
                              "No hay páginas que coincidan con el filtro seleccionado."))
            visible_hits = _page_items(
                st, hits, key=f"spain-hits-{selected_tree['site_tree_id']}-{hit_filter}",
                page_size=12, language=language, english_name="matching pages",
                spanish_name="paginas coincidentes")
            for hit in visible_hits:
                _render_hit(st, hit, language, query)

            control_a, control_b = st.columns(2, gap="large")
            with control_a:
                _review_editor(st, query, selected_tree, language)
            with control_b:
                _category_editor(st, query, selected_tree.get("site_card_id"),
                                 selected_tree.get("primary_category") or "unknown",
                                 language, "spain")

    if legacy_cards:
        st.markdown(section_header(
            _text(language, "Card-level leads", "Señales a nivel de ficha"),
            _text(
                language,
                "Spain-relevant Site Cards that do not yet have a stored exact-page case. Review the card without inventing a source location.",
                "Fichas relevantes para España que todavía no tienen un caso con página exacta. Revisa la ficha sin inventar una ubicación de origen.",
            ),
            count=len(legacy_cards),
        ), unsafe_allow_html=True)
        visible_legacy_cards = _page_items(
            st, legacy_cards, key="spain-legacy-cards", page_size=15,
            language=language, english_name="card-level leads",
            spanish_name="señales a nivel de ficha")
        for card in visible_legacy_cards:
            with st.container(key=f"rt-spain-card-lead-{card['id']}"):
                row = st.columns([2.2, 1.15, .72], gap="small")
                title = (
                    card.get("analyst_title")
                    or card.get("display_name")
                    or card.get("onion_host")
                    or _text(language, "Unnamed site", "Sitio sin nombre")
                )
                row[0].markdown(
                    f"**{html.escape(str(title))}**  \n"
                    f"`{html.escape(_short_host(card.get('onion_host')))}`"
                )
                row[1].markdown(
                    f"{category_badge(str(card.get('primary_category') or 'unknown'), category_label(card.get('primary_category'), language))}"
                    f"{risk_badge(str(card.get('risk_level') or 'low'), value_label(card.get('risk_level'), language))}",
                    unsafe_allow_html=True,
                )
                row[2].button(
                    _text(language, "Open card", "Abrir ficha"),
                    key=f"spain-open-legacy-card-{card['id']}",
                    on_click=_open_site_card,
                    args=(st, int(card["id"])),
                    width="stretch",
                )
                st.caption(
                    spain_reason_label(card.get("spain_match_reason"), language)
                )

    orphans = query("""SELECT url,primary_category,risk_level,spain_confidence,spain_match_language,
      spain_match_reason,first_seen,last_seen,spain_review_status FROM onion_urls
      WHERE spain_priority=1 AND COALESCE(spain_analyst_suppressed,0)=0 AND site_card_id IS NULL
      AND COALESCE(ui_hidden_default,0)=0
      AND primary_category NOT IN ('adult_filtered','adult_restricted','severe_abuse_risk')
      ORDER BY last_seen DESC LIMIT 100""")
    if orphans:
        with st.expander(_text(language,
                               f"Advanced: unattached Spain URLs ({len(orphans)})",
                               f"Avanzado: URLs de España sin ficha ({len(orphans)})")):
            st.caption(_text(language, "These URLs are waiting to be attached to a Site Card.",
                             "Estas URLs esperan ser vinculadas a una ficha de sitio."))
            visible_orphans = _page_items(
                st, orphans, key="spain-orphan-urls", page_size=15,
                language=language, english_name="unattached URLs",
                spanish_name="URLs sin ficha")
            for item in visible_orphans:
                st.markdown(f"**{html.escape(category_label(item.get('primary_category'), language))}** · "
                            f"{html.escape(value_label(item.get('risk_level'), language))}")
                st.code(item["url"], language=None)
                st.caption(spain_reason_label(item.get("spain_match_reason"), language))
