"""Relationship workbench for metadata-safe Site Card connections."""
from __future__ import annotations

import html

import storage
from dashboard_pages import site_directory
from dashboard_services.i18n import category_label, current_language, value_label
from ui_components import empty_state, page_lead, section_header


def _t(language: str, english: str, spanish: str) -> str:
    return spanish if language == "es" else english


def _card_name(card: dict) -> str:
    return (card.get("analyst_title") or card.get("display_name")
            or card.get("representative_host") or f"Site #{card.get('id')}")


def _graphviz(graph: dict) -> str:
    lines = [
        "digraph Signals {",
        "rankdir=LR;",
        'graph [pad="0.35", nodesep="0.45", ranksep="0.7"];',
        'node [shape=box,style="rounded,filled",fontname="Arial",fontsize=10,color="#d7dde5"];',
        'edge [fontname="Arial",fontsize=8,color="#7b8794",fontcolor="#667085"];',
    ]
    colors = {
        "site_card": "#dbeafe",
        "onion_url": "#ecfdf5",
        "actor": "#f3e8ff",
        "indicator_type": "#fef3c7",
    }
    for node in graph.get("nodes", []):
        label = str(node.get("label") or node.get("id")).replace("\\", "\\\\").replace('"', '\\"')
        fill = colors.get(node.get("kind"), "#f8fafc")
        lines.append(f'"{node["id"]}" [label="{label}",fillcolor="{fill}"];')
    for edge in graph.get("edges", []):
        label = str(edge.get("label") or "").replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'"{edge["source"]}" -> "{edge["target"]}" [label="{label}"];')
    lines.append("}")
    return "\n".join(lines)


def render(st, query) -> None:
    language = current_language(st)
    st.markdown(
        page_lead(
            _t(
                language,
                "See how sites, URLs, aliases and indicators connect",
                "Ve cómo se conectan sitios, URLs, alias e indicadores",
            ),
            _t(
                language,
                "This view uses stored safe metadata only. It does not contact onion sites.",
                "Esta vista usa solo metadatos seguros guardados. No contacta sitios onion.",
            ),
            eyebrow=_t(language, "Relationship workbench", "Espacio de relaciones"),
            aside=_t(language, "Stored evidence", "Evidencia guardada"),
            show_title=False,
        ),
        unsafe_allow_html=True,
    )
    cards = storage.get_connection_workbench(250)
    if not cards:
        st.markdown(
            empty_state(
                _t(language, "No connection-ready Site Cards", "No hay fichas con conexiones"),
                _t(
                    language,
                    "Relationship maps appear after safe public signals link eligible Site Cards.",
                    "Los mapas aparecen cuando señales públicas seguras vinculan fichas aptas.",
                ),
            ),
            unsafe_allow_html=True,
        )
        return

    metrics = st.columns(4)
    metrics[0].metric(_t(language, "Sites", "Sitios"), len(cards))
    metrics[1].metric(_t(language, "Alias links", "Enlaces de alias"),
                      sum(int(card.get("actor_count") or 0) for card in cards))
    metrics[2].metric(_t(language, "Indicator links", "Indicadores"),
                      sum(int(card.get("indicator_count") or 0) for card in cards))
    metrics[3].metric(_t(language, "Spain-linked", "Vinculados ES"),
                      sum(1 for card in cards if card.get("spain_priority")))

    search = st.text_input(
        _t(language, "Filter graph candidates", "Filtrar candidatos de grafo"),
        placeholder=_t(language, "Name, host, category", "Nombre, host, categoría"),
        key="connections-search",
    )
    needle = search.casefold().strip()
    if needle:
        cards = [
            card for card in cards
            if needle in " ".join(str(card.get(key) or "") for key in (
                "analyst_title", "display_name", "representative_host", "primary_category"
            )).casefold()
        ]
    if not cards:
        st.markdown(
            empty_state(
                _t(language, "No cards match that filter", "Ninguna ficha coincide"),
                _t(
                    language,
                    "Clear or broaden the filter to return to the recorded relationship candidates.",
                    "Borra o amplía el filtro para volver a las relaciones candidatas registradas.",
                ),
            ),
            unsafe_allow_html=True,
        )
        return

    selected_id = st.session_state.get("connections-selected-card")
    valid_ids = {int(card["id"]) for card in cards}
    if not selected_id or int(selected_id) not in valid_ids:
        selected_id = int(cards[0]["id"])
        st.session_state["connections-selected-card"] = selected_id

    left, right = st.columns([0.95, 2.2], gap="large")
    with left:
        st.markdown(
            section_header(
                _t(language, "Connected sites", "Sitios conectados"),
                _t(language, "Choose a Site Card to inspect its evidence map.",
                   "Elige una ficha para inspeccionar su mapa de evidencia."),
                count=len(cards),
            ),
            unsafe_allow_html=True,
        )
        for card in cards[:80]:
            active = int(card["id"]) == int(selected_id)
            score = (int(card.get("actor_count") or 0)
                     + int(card.get("indicator_count") or 0)
                     + int(card.get("mirror_count") or 0))
            st.markdown(
                f'<div class="rt-entity-row {"active" if active else ""}">'
                f'<b>{html.escape(_card_name(card))}</b><br>'
                f'<span>{html.escape(str(card.get("representative_host") or "unknown"))}</span><br>'
                f'<small>{html.escape(category_label(card.get("primary_category"), language))} · '
                f'{score} links</small></div>',
                unsafe_allow_html=True,
            )
            if st.button(
                _t(language, "Selected" if active else "Open graph",
                   "Seleccionado" if active else "Abrir grafo"),
                key=f"connections-open-{card['id']}",
                disabled=active,
                width="stretch",
            ):
                st.session_state["connections-selected-card"] = int(card["id"])
                st.rerun()

    selected = next(card for card in cards if int(card["id"]) == int(selected_id))
    with right:
        st.markdown(
            section_header(
                _card_name(selected),
                f"{selected.get('representative_host') or 'unknown'} · "
                f"{category_label(selected.get('primary_category'), language)} · "
                f"{value_label(selected.get('risk_level'), language)}",
            ),
            unsafe_allow_html=True,
        )
        if st.button(_t(language, "Open full Site Card", "Abrir ficha completa"),
                     key=f"connections-card-{selected_id}", type="primary"):
            site_directory.open_card(int(selected_id), False)
            st.rerun()
        try:
            graph = storage.get_site_evidence_graph(int(selected_id))
        except ValueError as exc:
            st.warning(str(exc))
            return
        if len(graph.get("nodes", [])) <= 1:
            st.markdown(
                empty_state(
                    _t(language, "No visible relationship graph", "No hay grafo visible"),
                    _t(
                        language,
                        "The Site Card exists, but no policy-visible relationship edges are recorded yet.",
                        "La ficha existe, pero todavía no tiene relaciones visibles por política.",
                    ),
                ),
                unsafe_allow_html=True,
            )
        else:
            st.graphviz_chart(_graphviz(graph), use_container_width=True)
            st.caption(_t(language, f"{len(graph['nodes'])} nodes · {len(graph['edges'])} edges",
                          f"{len(graph['nodes'])} nodos · {len(graph['edges'])} enlaces"))
