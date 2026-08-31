"""Consolidated, metadata-safe entity intelligence workspace.

The page deliberately relies on storage's public/safe query boundary.  It does
not inspect page bodies, fetch URLs, or expose restricted content.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import dashboard_auth
import storage
from dashboard_services.i18n import current_language
from ui_components import empty_state, page_lead, section_header


_VIEWS = (
    "Review Inbox",
    "Entities",
    "Evidence",
    "Connections",
    "Expansion",
    "History",
)

_ALL_CANDIDATE_STATES = (
    "accepted_observation",
    "rejected_noise",
    "analyst_review_candidate",
    "analyst_confirmed_identity_evidence",
    "analyst_rejected_identity_evidence",
    "superseded_or_contradicted_observation",
)


def _can(st, capability: str) -> bool:
    from dashboard_pages.workspace import _can as workspace_can

    return workspace_can(st, capability)


def _authorize(st, capability: str) -> bool:
    from dashboard_pages.workspace import _authorize_action

    return _authorize_action(st, capability)


def _l(language: str, english: str, spanish: str) -> str:
    return spanish if language == "es" else english


def _section(st, title: str, detail: str | None = None, *, count: int | None = None) -> None:
    """Render one shared, presentation-only workspace section heading."""
    st.markdown(section_header(title, detail, count=count), unsafe_allow_html=True)


def _empty(st, title: str, detail: str | None = None) -> None:
    """Render one shared empty state without changing control flow."""
    st.markdown(empty_state(title, detail), unsafe_allow_html=True)


def _human(value: Any, fallback: str = "Unknown") -> str:
    text = str(value or "").strip()
    return text.replace("_", " ").strip().title() if text else fallback


def _bounded_text(value: Any, limit: int = 160) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: max(1, limit - 1)] + "…"


def _json_labels(value: Any, *, limit: int = 8) -> list[str]:
    """Decode only short scalar labels; never display arbitrary JSON blobs."""
    decoded = value
    if isinstance(value, str):
        try:
            decoded = json.loads(value or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            decoded = []
    if isinstance(decoded, dict):
        decoded = list(decoded.keys())
    if not isinstance(decoded, (list, tuple, set)):
        return []
    labels: list[str] = []
    for item in decoded:
        if isinstance(item, dict):
            # Connection evidence is stored as structured safe labels.  Keep
            # the allow-list narrow so arbitrary metadata never reaches UI.
            item = next((item.get(key) for key in ("label", "reason_code", "type")
                         if item.get(key)), None)
        if isinstance(item, (str, int, float, bool)):
            label = _bounded_text(item, 80)
            if label:
                labels.append(label)
        if len(labels) >= limit:
            break
    return labels


def _clear_and_rerun(st, query) -> None:
    clear = getattr(query, "clear", None)
    if callable(clear):
        clear()
    st.rerun()


def _page_items(st, items: list[dict], *, key: str, page_size: int, language: str,
                english_name: str, spanish_name: str) -> list[dict]:
    """Bound interactive record rendering while preserving the full filtered set."""
    rows = list(items or [])
    page_count = max(1, (len(rows) + page_size - 1) // page_size)
    page_key = f"{key}-page"
    stored_page = int(st.session_state.get(page_key, 1) or 1)
    selected_page = min(max(stored_page, 1), page_count)
    if stored_page != selected_page:
        st.session_state[page_key] = selected_page
    name = _l(language, english_name, spanish_name)
    if page_count > 1:
        selected_page = int(st.selectbox(
            _l(language, f"{english_name.title()} page", f"Pagina de {spanish_name}"),
            list(range(1, page_count + 1)),
            index=selected_page - 1,
            format_func=lambda value: _l(
                language, f"Page {value} of {page_count}", f"Pagina {value} de {page_count}"),
            key=page_key,
        ))
    start = (selected_page - 1) * page_size
    visible = rows[start:start + page_size]
    if rows:
        st.caption(_l(
            language,
            f"Showing {start + 1}-{start + len(visible)} of {len(rows)} {name}.",
            f"Mostrando {start + 1}-{start + len(visible)} de {len(rows)} {name}.",
        ))
    return visible


def _safe_search(st, language: str) -> tuple[str, dict[str, list[dict]]]:
    search = st.text_input(
        _l(language, "Search entity intelligence", "Buscar inteligencia de entidades"),
        placeholder=_l(
            language,
            "Username, safe site label, host, or profile identity",
            "Usuario, etiqueta segura, host o identidad de perfil",
        ),
        key="entity-intelligence-search",
    ).strip()
    results = {"actors": [], "site_cards": [], "candidates": []}
    if search:
        results = storage.search_entity_intelligence(search, limit=50)
        totals = sum(len(results.get(key) or []) for key in results)
        st.caption(
            _l(language, f"{totals} safe matches across entities, sites, and evidence.",
               f"{totals} coincidencias seguras entre entidades, sitios y evidencias.")
        )
        with st.expander(_l(language, "Search matches", "Coincidencias"), expanded=False):
            for actor in results.get("actors") or []:
                st.write(
                    _l(language, "Entity", "Entidad"),
                    _bounded_text(actor.get("display_alias") or actor.get("normalized_alias") or "Unknown"),
                    "·", _bounded_text(actor.get("onion_host") or "unknown"),
                )
            for card in results.get("site_cards") or []:
                st.write(
                    _l(language, "Site", "Sitio"),
                    _bounded_text(card.get("display_name") or "Unknown"),
                    "·", _human(card.get("primary_category")),
                )
            for candidate in results.get("candidates") or []:
                st.write(
                    _l(language, "Evidence", "Evidencia"),
                    _bounded_text(candidate.get("display_alias") or candidate.get("normalized_alias") or "Unknown"),
                    "·", _human(candidate.get("effective_state")),
                )
            if totals == 0:
                _empty(
                    st,
                    _l(language, "No safe matches", "No hay coincidencias seguras"),
                    _l(
                        language,
                        "Try a different public username, site label, host, or profile identity.",
                        "Prueba otro usuario público, etiqueta de sitio, host o identidad de perfil.",
                    ),
                )
    return search, results


def _metrics(st, language: str) -> None:
    candidates = storage.get_actor_candidate_review_queue(limit=1000)
    actors = storage.get_public_actors(limit=1000)
    audit = storage.get_alias_quality_audit(limit=5000)
    expansion = storage.get_entity_expansion_metrics()
    states = audit.get("states") or {}
    confirmed = int(states.get("accepted_observation") or 0) + int(
        states.get("analyst_confirmed_identity_evidence") or 0
    )
    columns = st.columns(4)
    columns[0].metric(_l(language, "Awaiting review", "Pendientes"), len(candidates))
    columns[1].metric(_l(language, "Entities", "Entidades"), len(actors))
    columns[2].metric(_l(language, "Confirmed evidence", "Evidencia confirmada"), confirmed)
    columns[3].metric(_l(language, "Expansion proposals", "Propuestas de expansión"),
                      int(expansion.get("proposed") or 0))


def _candidate_summary(st, candidate: dict, language: str) -> None:
    st.write(candidate.get("display_alias") or candidate.get("normalized_alias") or
             _l(language, "Unnamed candidate", "Candidato sin nombre"))
    st.caption(
        f"{_bounded_text(candidate.get('onion_host') or 'unknown')} · "
        f"{_human(candidate.get('effective_state'))} · "
        f"{float(candidate.get('evidence_confidence') or 0):.0%}"
    )
    facts = [
        _human(candidate.get("evidence_type"), "Unspecified evidence"),
        _human(candidate.get("structural_role") or candidate.get("structural_container"),
               "Unspecified structure"),
        _human(candidate.get("extraction_method"), "Unspecified method"),
    ]
    st.write(" · ".join(facts))
    reasons = _json_labels(candidate.get("reason_codes_json"))
    if reasons:
        st.caption(_l(language, "Reason codes: ", "Códigos: ") +
                   ", ".join(_human(reason) for reason in reasons))


def _render_review(st, query, language: str, search: str, _: dict) -> None:
    can_review = _can(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE)
    _section(
        st,
        _l(language, "Review Inbox", "Bandeja de revisión"),
        _l(
            language,
            "Only evidence that needs an analyst decision appears here.",
            "Aquí solo aparece evidencia que necesita una decisión del analista.",
        ),
    )
    candidates = storage.get_actor_candidate_review_queue(search=search or None, limit=200)
    if not candidates:
        _empty(
            st,
            _l(language, "Nothing is waiting for review", "No hay revisiones pendientes"),
            _l(
                language,
                "Candidate evidence will appear here only when a decision is required.",
                "La evidencia candidata aparecerá aquí solo cuando necesite una decisión.",
            ),
        )
        return
    if not can_review:
        st.caption(_l(
            language,
            "Read-only: this session can inspect evidence but cannot save review decisions.",
            "Solo lectura: esta sesión puede revisar la evidencia, pero no guardar decisiones.",
        ))
    visible_candidates = _page_items(
        st, candidates, key="entity-review", page_size=12, language=language,
        english_name="review items", spanish_name="elementos de revision")
    for candidate in visible_candidates:
        candidate_id = int(candidate["id"])
        _candidate_summary(st, candidate, language)
        actions = st.columns(3)
        decisions = (
            ("confirm", _l(language, "Confirm evidence", "Confirmar evidencia"), "primary"),
            ("reject", _l(language, "Reject noise", "Rechazar ruido"), "secondary"),
            ("contradict", _l(language, "Mark contradicted", "Marcar contradicha"), "secondary"),
        )
        for column, (decision, label, button_type) in zip(actions, decisions):
            if column.button(
                label, key=f"entity-candidate-{decision}-{candidate_id}",
                type=button_type, use_container_width=True, disabled=not can_review,
            ) and _authorize(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
                storage.record_actor_candidate_decision(
                    candidate_id, decision, reason_code="entity_intelligence_review")
                st.success(_l(language, "Decision saved.", "Decisión guardada."))
                _clear_and_rerun(st, query)
        st.divider()


def _actor_choices(actors: list[dict]) -> tuple[list[int], dict[int, str]]:
    ids: list[int] = []
    labels: dict[int, str] = {}
    for actor in actors:
        actor_id = int(actor["id"])
        ids.append(actor_id)
        name = actor.get("display_alias") or actor.get("normalized_alias") or f"Entity {actor_id}"
        labels[actor_id] = f"{_bounded_text(name, 60)} · {_bounded_text(actor.get('onion_host') or 'unknown', 50)}"
    return ids, labels


def _entity_detail(st, detail: dict, language: str) -> None:
    actor = detail.get("actor") or {}
    actor_id = int(actor.get("id") or 0)
    _section(
        st,
        _bounded_text(actor.get("display_alias") or actor.get("normalized_alias") or
                      _l(language, "Public entity", "Entidad pública")),
        f"{_bounded_text(actor.get('onion_host') or 'unknown')} · "
        f"{_human(actor.get('primary_category'))} · "
        f"{_human(actor.get('confidence_label'), 'Unrated')}",
    )
    summary = st.columns(4)
    summary[0].metric(_l(language, "Sightings", "Observaciones"),
                      int(actor.get("observation_count") or len(detail.get("observations") or [])))
    summary[1].metric(_l(language, "Aliases", "Alias"), len(detail.get("aliases") or []))
    summary[2].metric(_l(language, "Connections", "Conexiones"), len(detail.get("connections") or []))
    summary[3].metric(_l(language, "Signal types", "Tipos de señal"), len(detail.get("identifiers") or []))

    with st.expander(_l(language, "Aliases", "Alias"), expanded=True):
        aliases = detail.get("aliases") or []
        if not aliases:
            _empty(
                st,
                _l(language, "No alternate aliases", "No hay alias alternativos"),
                _l(
                    language,
                    "Only the current public profile name is recorded.",
                    "Solo está registrado el nombre del perfil público actual.",
                ),
            )
        visible_aliases = _page_items(
            st, aliases, key=f"entity-{actor_id}-aliases", page_size=15,
            language=language, english_name="aliases", spanish_name="alias")
        for alias in visible_aliases:
            st.write(_bounded_text(alias.get("display_alias") or alias.get("normalized_alias") or "Unknown"))
            st.caption(_l(language, "Seen", "Visto") +
                       f" {int(alias.get('observation_count') or 0)} · " +
                       _bounded_text(alias.get("last_seen") or "unknown"))

    with st.expander(_l(language, "Identifiers", "Identificadores"), expanded=False):
        identifiers = detail.get("identifiers") or []
        if not identifiers:
            _empty(
                st,
                _l(language, "No safely bound identifiers", "No hay identificadores seguros"),
                _l(
                    language,
                    "Independent public signal types will appear after they are safely linked.",
                    "Los tipos de señal pública independientes aparecerán cuando se vinculen de forma segura.",
                ),
            )
        visible_identifiers = _page_items(
            st, identifiers, key=f"entity-{actor_id}-identifiers", page_size=15,
            language=language, english_name="signal types", spanish_name="tipos de senal")
        for identifier in visible_identifiers:
            st.write(_human(identifier.get("indicator_type")))
            st.caption(
                f"{_bounded_text(identifier.get('safe_value_label') or 'Safe value hidden')} · "
                f"{_human(identifier.get('binding_method'))} · "
                f"{int(identifier.get('count') or 0)}"
            )

    with st.expander(_l(language, "Page sightings", "Observaciones en páginas"), expanded=False):
        observations = detail.get("observations") or []
        if not observations:
            _empty(
                st,
                _l(language, "No eligible page sightings", "No hay observaciones de página aptas"),
                _l(
                    language,
                    "Only policy-visible, evidence-backed sightings are shown here.",
                    "Aquí solo se muestran observaciones visibles por política y respaldadas por evidencia.",
                ),
            )
        visible_observations = _page_items(
            st, observations, key=f"entity-{actor_id}-observations", page_size=12,
            language=language, english_name="page sightings",
            spanish_name="observaciones en paginas")
        for observation in visible_observations:
            st.write(_bounded_text(observation.get("safe_context_label") or
                                   observation.get("evidence_type") or "Public page sighting"))
            st.caption(
                f"{_human(observation.get('page_type'))} · "
                f"{float(observation.get('evidence_confidence') or 0):.0%} · "
                f"{_bounded_text(observation.get('last_seen') or 'unknown')}"
            )
            if observation.get("url"):
                st.code(_bounded_text(observation.get("url"), 260), language=None)


def _render_entities(st, _query, language: str, search: str, results: dict) -> None:
    _section(
        st,
        _l(language, "Entities", "Entidades"),
        _l(
            language,
            "Choose a public entity to review its aliases, signal types, and page sightings.",
            "Elige una entidad pública para revisar sus alias, tipos de señal y observaciones.",
        ),
    )
    actors = list(results.get("actors") or []) if search else storage.get_public_actors(limit=200)
    if not actors:
        _empty(
            st,
            _l(language, "No entities match this view", "No hay entidades en esta vista"),
            _l(
                language,
                "Verified public profile observations will appear here.",
                "Las observaciones verificadas de perfiles públicos aparecerán aquí.",
            ),
        )
        return
    ids, labels = _actor_choices(actors)
    selected = st.selectbox(
        _l(language, "Choose an entity", "Elegir una entidad"),
        ids,
        format_func=lambda actor_id: labels[actor_id],
        key="entity-intelligence-actor",
    )
    detail = storage.get_actor_detail(int(selected))
    if detail:
        _entity_detail(st, detail, language)
    else:
        st.warning(_l(language, "This entity is no longer available.",
                      "Esta entidad ya no está disponible."))


def _render_evidence(st, _query, language: str, search: str, _results: dict) -> None:
    _section(
        st,
        _l(language, "Evidence", "Evidencia"),
        _l(
            language,
            "Accepted, rejected, pending, and contradicted evidence remain distinct and auditable.",
            "La evidencia aceptada, rechazada, pendiente y contradicha permanece separada y auditable.",
        ),
    )
    rows = storage.get_actor_candidate_review_queue(
        search=search or None, states=_ALL_CANDIDATE_STATES, limit=300)
    if not rows:
        _empty(
            st,
            _l(language, "No evidence matches this view", "No hay evidencia en esta vista"),
            _l(
                language,
                "Change the search or return after more eligible pages are verified.",
                "Cambia la búsqueda o vuelve cuando se hayan verificado más páginas aptas.",
            ),
        )
        return
    state_filter = st.selectbox(
        _l(language, "Evidence state", "Estado de evidencia"),
        ("all",) + _ALL_CANDIDATE_STATES,
        format_func=lambda value: _l(language, "All states", "Todos los estados")
        if value == "all" else _human(value),
        key="entity-evidence-state",
    )
    if state_filter != "all":
        rows = [row for row in rows if row.get("effective_state") == state_filter]
    if not rows:
        _empty(
            st,
            _l(language, "No evidence in this state", "No hay evidencia en este estado"),
            _l(
                language,
                "Choose another evidence state to continue.",
                "Elige otro estado de evidencia para continuar.",
            ),
        )
        return
    visible_rows = _page_items(
        st, rows, key=f"entity-evidence-{state_filter}", page_size=20,
        language=language, english_name="evidence records",
        spanish_name="registros de evidencia")
    for row in visible_rows:
        _candidate_summary(st, row, language)
        if row.get("site_card_name"):
            st.caption(_l(language, "Site: ", "Sitio: ") +
                       _bounded_text(row.get("site_card_name")))
        st.divider()


def _render_connections(st, _query, language: str, search: str, results: dict) -> None:
    _section(
        st,
        _l(language, "Connections", "Conexiones"),
        _l(
            language,
            "Connections are evidence-backed candidates, not automatic identity claims.",
            "Las conexiones son candidatas respaldadas por evidencia, no afirmaciones automáticas de identidad.",
        ),
    )
    actors = list(results.get("actors") or []) if search else storage.get_public_actors(limit=200)
    if not actors:
        _empty(
            st,
            _l(language, "No connected entities match", "No hay entidades conectadas"),
            _l(
                language,
                "Connection candidates appear only after independent signal types are linked.",
                "Las conexiones candidatas solo aparecen después de vincular tipos de señal independientes.",
            ),
        )
        return
    ids, labels = _actor_choices(actors)
    selected = st.selectbox(
        _l(language, "Choose an entity", "Elegir una entidad"), ids,
        format_func=lambda actor_id: labels[actor_id], key="entity-connections-actor")
    detail = storage.get_actor_detail(int(selected)) or {}
    connections = detail.get("connections") or []
    if not connections:
        _empty(
            st,
            _l(language, "No connection evidence", "No hay evidencia de conexión"),
            _l(
                language,
                "This entity has no evidence-backed connection candidates yet.",
                "Esta entidad todavía no tiene conexiones candidatas respaldadas por evidencia.",
            ),
        )
        return
    evidence_families = sorted({
        _human(item)
        for connection in connections
        for item in _json_labels(connection.get("evidence_json"))
    })
    with st.expander(_l(language, "Filter connections", "Filtrar conexiones"), expanded=False):
        confidence_filter = st.selectbox(
            _l(language, "Confidence band", "Nivel de confianza"),
            ("all", "high", "medium", "low"),
            format_func=lambda value: _l(language, "All", "Todos")
            if value == "all" else _human(value), key="entity-connections-confidence")
        analyst_filter = st.selectbox(
            _l(language, "Analyst state", "Estado del analista"),
            ("all",) + tuple(sorted({str(row.get("analyst_decision") or "unreviewed")
                                     for row in connections})),
            format_func=lambda value: _l(language, "All", "Todos")
            if value == "all" else _human(value), key="entity-connections-analyst")
        evidence_filter = st.selectbox(
            _l(language, "Evidence family", "Familia de evidencia"),
            ("all",) + tuple(evidence_families),
            format_func=lambda value: _l(language, "All", "Todas")
            if value == "all" else value, key="entity-connections-evidence")
        relevance_filter = st.selectbox(
            _l(language, "Operational focus", "Enfoque operativo"),
            ("all", "contradicted", "watched", "spain"),
            format_func=lambda value: _l(language, "All", "Todos")
            if value == "all" else _human(value), key="entity-connections-focus")
        time_filter = st.selectbox(
            _l(language, "Last seen", "Última observación"),
            ("all", "7", "30", "90"),
            format_func=lambda value: _l(language, "Any time", "Cualquier fecha")
            if value == "all" else _l(language, f"Last {value} days", f"Últimos {value} días"),
            key="entity-connections-time")

    def _connection_visible(connection: dict) -> bool:
        score = float(connection.get("confidence_score") or 0)
        if confidence_filter == "high" and score < 75:
            return False
        if confidence_filter == "medium" and not 40 <= score < 75:
            return False
        if confidence_filter == "low" and score >= 40:
            return False
        if analyst_filter != "all" and str(connection.get("analyst_decision") or "unreviewed") != analyst_filter:
            return False
        families = {_human(item) for item in _json_labels(connection.get("evidence_json"))}
        if evidence_filter != "all" and evidence_filter not in families:
            return False
        if relevance_filter == "contradicted" and not connection.get("warning_type"):
            return False
        if relevance_filter == "watched" and not bool(connection.get("other_watched")):
            return False
        if relevance_filter == "spain" and int(connection.get("other_spain_observation_count") or 0) <= 0:
            return False
        if time_filter != "all":
            try:
                seen = datetime.fromisoformat(str(connection.get("last_seen") or "").replace("Z", "+00:00"))
                cutoff = datetime.now(timezone.utc) - timedelta(days=int(time_filter))
                if seen.tzinfo is None:
                    seen = seen.replace(tzinfo=timezone.utc)
                if seen < cutoff:
                    return False
            except (TypeError, ValueError):
                return False
        return True

    connections = [row for row in connections if _connection_visible(row)]
    if not connections:
        _empty(
            st,
            _l(language, "No connections match these filters", "Ninguna conexión coincide"),
            _l(
                language,
                "Broaden one or more filters to see the recorded candidates.",
                "Amplía uno o más filtros para ver las candidatas registradas.",
            ),
        )
        return
    visible_connections = _page_items(
        st, connections, key=f"entity-connections-{selected}", page_size=15,
        language=language, english_name="connections", spanish_name="conexiones")
    for connection in visible_connections:
        st.write(_bounded_text(connection.get("other_alias") or
                               _l(language, "Unknown entity", "Entidad desconocida")))
        st.caption(
            f"{_bounded_text(connection.get('other_onion_host') or 'unknown')} · "
            f"{float(connection.get('confidence_score') or 0):.0f}% · "
            f"{_human(connection.get('analyst_decision'), 'Unreviewed')}"
        )
        evidence = _json_labels(connection.get("evidence_json"))
        if evidence:
            st.write(_l(language, "Evidence: ", "Evidencia: ") +
                     ", ".join(_human(item) for item in evidence))
        st.divider()


def _render_expansion(st, query, language: str, search: str, _results: dict) -> None:
    can_review = _can(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE)
    can_queue = _can(st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE)
    _section(
        st,
        _l(language, "Expansion", "Expansión"),
        _l(
            language,
            "These are bounded, same-host public-route proposals. Nothing is queued without approval.",
            "Son propuestas limitadas de rutas públicas del mismo host. Nada se encola sin aprobación.",
        ),
    )
    statuses = ("all", "proposed", "approved", "enqueued", "rejected", "completed")
    status = st.selectbox(
        _l(language, "Proposal state", "Estado de propuesta"), statuses,
        format_func=lambda value: _l(language, "All states", "Todos los estados")
        if value == "all" else _human(value), key="entity-expansion-status")
    proposals = storage.get_entity_expansion_proposals(
        status=status, search=search or None, limit=300)
    if not proposals:
        _empty(
            st,
            _l(language, "No expansion proposals", "No hay propuestas de expansión"),
            _l(
                language,
                "Approved public-route proposals will remain separate from automatic crawling.",
                "Las propuestas de rutas públicas aprobables permanecen separadas del rastreo automático.",
            ),
        )
        return
    if not can_review:
        st.caption(_l(
            language,
            "Read-only: this session can inspect proposals but cannot approve or reject them.",
            "Solo lectura: esta sesión puede revisar propuestas, pero no aprobarlas ni rechazarlas.",
        ))
    elif not can_queue:
        st.caption(_l(
            language,
            "Queue approval is administrator-only. Analysts may still reject unsuitable proposals.",
            "La aprobación para encolar es solo para administradores. Los analistas aún pueden rechazar propuestas inadecuadas.",
        ))
    visible_proposals = _page_items(
        st, proposals, key=f"entity-expansion-{status}", page_size=12,
        language=language, english_name="proposals", spanish_name="propuestas")
    for proposal in visible_proposals:
        proposal_id = int(proposal["id"])
        st.write(proposal.get("actor_alias") or proposal.get("site_card_name") or
                 _l(language, "Unassigned proposal", "Propuesta sin asignar"))
        st.caption(
            f"{_human(proposal.get('route_role'))} · {_human(proposal.get('status'))} · "
            f"{_human(proposal.get('reason_code'))} · "
            f"{float(proposal.get('expected_value') or 0):.0%}"
        )
        st.caption(_l(language, "Budget", "Presupuesto") +
                   f": host {int(proposal.get('host_budget') or 0)} · " +
                   f"resource {int(proposal.get('resource_budget') or 0)}")
        if proposal.get("result_code"):
            st.caption(_l(language, "Result", "Resultado") +
                       f": {_human(proposal.get('result_code'))}")
        st.code(_bounded_text(proposal.get("proposed_url") or "", 300), language=None)
        if proposal.get("status") == "proposed":
            reason = st.text_input(
                _l(language, "Decision note (optional)", "Nota de decisión (opcional)"),
                key=f"entity-expansion-reason-{proposal_id}", max_chars=240,
                disabled=not can_review)
            confirm = st.checkbox(
                _l(language, "I confirm this public route may be queued",
                   "Confirmo que esta ruta pública puede encolarse"),
                key=f"entity-expansion-confirm-{proposal_id}",
                disabled=not can_queue)
            approve, reject = st.columns(2)
            if approve.button(
                _l(language, "Approve and queue", "Aprobar y encolar"),
                key=f"entity-expansion-approve-{proposal_id}",
                disabled=not can_queue or not confirm,
                type="primary", use_container_width=True,
            ) and _authorize(st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
                storage.decide_entity_expansion_proposal(
                    proposal_id, "approve", reason=reason or None)
                st.success(_l(language, "Proposal approved and queued.",
                              "Propuesta aprobada y encolada."))
                _clear_and_rerun(st, query)
            if reject.button(
                _l(language, "Reject proposal", "Rechazar propuesta"),
                key=f"entity-expansion-reject-{proposal_id}", use_container_width=True,
                disabled=not can_review,
            ) and _authorize(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
                storage.decide_entity_expansion_proposal(
                    proposal_id, "reject", reason=reason or None)
                st.success(_l(language, "Proposal rejected.", "Propuesta rechazada."))
                _clear_and_rerun(st, query)
        st.divider()


def _event_summary(event: dict, language: str) -> str:
    family = str(event.get("event_family") or "event")
    if family == "page_change":
        return _l(language, "Page change recorded", "Cambio de página registrado")
    if family == "daily_digest":
        return _l(language, "Daily summary", "Resumen diario") + ": " + _bounded_text(event.get("summary"))
    if family == "actor":
        return _bounded_text(event.get("display_alias") or event.get("summary") or
                             _l(language, "Public entity event", "Evento de entidad pública"))
    return _bounded_text(event.get("analyst_title") or event.get("display_name") or
                         event.get("summary") or _l(language, "Site event", "Evento de sitio"))


def _render_history(st, _query, language: str, search: str, _results: dict) -> None:
    _section(
        st,
        _l(language, "History", "Historial"),
        _l(
            language,
            "A safe activity trail. Technical metadata remains hidden from this overview.",
            "Un historial de actividad seguro. Los metadatos técnicos permanecen ocultos aquí.",
        ),
    )
    events = storage.get_intelligence_timeline(limit=200)
    if search:
        needle = search.casefold()
        events = [event for event in events if needle in " ".join((
            _event_summary(event, language),
            _human(event.get("event_family")),
            _human(event.get("event_type")),
        )).casefold()]
    if not events:
        _empty(
            st,
            _l(language, "No history matches this view", "No hay historial en esta vista"),
            _l(
                language,
                "Auditable entity and Site Card events will appear here.",
                "Los eventos auditables de entidades y fichas aparecerán aquí.",
            ),
        )
        return
    visible_events = _page_items(
        st, events, key="entity-history", page_size=20, language=language,
        english_name="history events", spanish_name="eventos del historial")
    for event in visible_events:
        st.write(_event_summary(event, language))
        st.caption(
            f"{_bounded_text(event.get('ts') or 'unknown')} · "
            f"{_human(event.get('event_family'))} · {_human(event.get('event_type'))}"
        )
        st.divider()


def render(st, query) -> None:
    """Render one non-eager entity-intelligence view."""
    language = current_language(st)
    st.markdown(page_lead(
        _l(language, "Public identity workspace", "Espacio de identidades públicas"),
        _l(
            language,
            "Review identities, evidence, connections, and bounded expansion without leaving this workspace.",
            "Revisa identidades, evidencia, conexiones y expansión limitada sin salir de este espacio.",
        ),
        eyebrow=_l(language, "Entity intelligence", "Inteligencia de entidades"),
        aside=_l(language, "Evidence first", "Evidencia primero"),
        show_title=False,
    ), unsafe_allow_html=True)
    search, results = _safe_search(st, language)
    _metrics(st, language)

    localized = {
        "Review Inbox": _l(language, "Review Inbox", "Bandeja de revisión"),
        "Entities": _l(language, "Entities", "Entidades"),
        "Evidence": _l(language, "Evidence", "Evidencia"),
        "Connections": _l(language, "Connections", "Conexiones"),
        "Expansion": _l(language, "Expansion", "Expansión"),
        "History": _l(language, "History", "Historial"),
    }
    view = st.radio(
        _l(language, "Workspace view", "Vista del espacio"),
        _VIEWS,
        format_func=lambda value: localized[value],
        horizontal=True,
        key="entity-intelligence-view",
        label_visibility="collapsed",
    )
    renderers: dict[str, Callable[[Any, Any, str, str, dict], None]] = {
        "Review Inbox": _render_review,
        "Entities": _render_entities,
        "Evidence": _render_evidence,
        "Connections": _render_connections,
        "Expansion": _render_expansion,
        "History": _render_history,
    }
    renderers[view](st, query, language, search, results)
