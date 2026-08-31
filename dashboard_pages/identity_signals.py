"""Analyst-facing, metadata-safe identity and Deep Discovery review workspace."""
from __future__ import annotations

import html
import json
import math
import re
import sqlite3
from collections import Counter

import deep_discovery
import identity_registry
import site_dedupe
import storage
import structured_intelligence
from dashboard_services.i18n import category_label, current_language, tr, value_label
from ui_components import empty_state, mask_onion_address, page_lead, section_header


_RESTRICTED_CATEGORIES = {
    "adult_filtered", "adult_restricted", "adult_extreme_caution", "severe_abuse_risk",
}
_IDENTIFIER_PATTERN = re.compile(
    r"(?:https?://|\.onion\b|-----BEGIN|[A-Fa-f0-9]{24,}|[13][a-km-zA-HJ-NP-Z1-9]{25,}|"
    r"0x[A-Fa-f0-9]{20,}|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|"
    r"\b(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b|"
    r"\b(?:[A-Fa-f0-9]{4}[\s:-]){3,}[A-Fa-f0-9]{4}\b|"
    r"\+?\d[\d\s().-]{7,}\d)"
)


def _short(value: object, length: int = 90) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= length else text[: length - 1] + "…"


def _json_value(value, default):
    if isinstance(value, type(default)):
        return value
    try:
        loaded = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return loaded if isinstance(loaded, type(default)) else default


def _safe_code(value: object) -> str | None:
    """Return a human-readable evidence label without exposing identifier values."""
    if isinstance(value, dict):
        code = value.get("type") or value.get("reason_code") or value.get("evidence_type")
        label = value.get("label")
        candidate = code or label
    else:
        candidate = value
    text = " ".join(str(candidate or "").split()).strip()
    if not text:
        return None
    # Reject raw artifacts before shortening colon-delimited reason text. This
    # prevents a URL such as ``https://...`` from degrading into a misleading
    # but apparently safe ``https`` label.
    if _IDENTIFIER_PATTERN.search(text):
        return None
    if ":" in text:
        prefix = text.split(":", 1)[0].strip()
        if prefix and len(prefix) <= 50 and not _IDENTIFIER_PATTERN.search(prefix):
            text = prefix
    return _short(text.replace("_", " ").replace("-", " ").title(), 90)


def _safe_name(value: object, fallback: str) -> str:
    """Return a short public label, never a raw network/personal identifier."""
    text = " ".join(str(value or "").split()).strip()
    if not text or _IDENTIFIER_PATTERN.search(text):
        return fallback
    return _short(text, 120)


def _safe_codes(values, *, limit: int = 12) -> list[str]:
    if isinstance(values, str):
        parsed = _json_value(values, [])
        values = parsed if parsed else [values]
    if isinstance(values, dict):
        expanded = []
        for bucket, entries in values.items():
            if isinstance(entries, list) and entries:
                expanded.extend({"type": f"{bucket}: {entry}"} for entry in entries)
            elif entries:
                expanded.append({"type": bucket})
        values = expanded
    if not isinstance(values, list):
        return []
    safe = []
    for value in values:
        label = _safe_code(value)
        if label and label not in safe:
            safe.append(label)
        if len(safe) >= limit:
            break
    return safe


def _score_value(value) -> float:
    try:
        score = float(value or 0)
    except (TypeError, ValueError):
        return 0.0
    return score if math.isfinite(score) else 0.0


def _confidence_percent(value) -> int:
    score = _score_value(value)
    if score <= 1:
        score *= 100
    return max(0, min(100, round(score)))


def _classification_detail(site_card_id: int) -> tuple[dict | None, str | None]:
    try:
        detail = site_dedupe.get_site_card_detail(
            int(site_card_id), url_limit=1, event_limit=0,
            include_dead=False, include_restricted=False,
        )
    except (ValueError, sqlite3.Error):
        return None, "unavailable"
    if not detail:
        return None, "missing"
    if (
        detail.get("primary_category") in _RESTRICTED_CATEGORIES
        or detail.get("storage_policy") == "discard"
    ):
        return None, "restricted"
    return detail, None


def _render_live_classification(st, site_card_id: int, language: str) -> None:
    detail, error = _classification_detail(site_card_id)
    st.markdown(
        section_header(
            tr("identity_live_classification", language),
            tr("identity_live_classification_help", language),
        ),
        unsafe_allow_html=True,
    )
    if error == "restricted":
        st.warning(tr("identity_classification_restricted", language))
        return
    if error:
        st.warning(tr("identity_classification_unavailable", language))
        return

    columns = st.columns(4)
    columns[0].metric(
        tr("identity_content_category", language),
        category_label(detail.get("content_category") or detail.get("primary_category"), language),
    )
    columns[1].metric(
        tr("identity_page_type", language),
        value_label(detail.get("page_type") or "unknown", language),
    )
    columns[2].metric(
        tr("identity_safety_state", language),
        value_label(detail.get("safety_state") or "safe", language),
    )
    columns[3].metric(
        tr("identity_confidence", language),
        value_label(detail.get("category_confidence") or detail.get("confidence") or "unknown", language),
    )

    st.markdown(
        section_header(
            tr("identity_advisory_quality", language),
            tr("identity_advisory_quality_help", language),
        ),
        unsafe_allow_html=True,
    )
    advisory = st.columns(4)
    advisory[0].metric(
        tr("identity_decision", language),
        value_label(detail.get("classification_decision") or "unclassified", language),
    )
    advisory[1].metric(
        tr("identity_page_confidence", language),
        value_label(detail.get("page_type_confidence") or "unknown", language),
    )
    advisory[2].metric(
        tr("identity_card_readiness", language),
        tr("identity_ready", language) if detail.get("card_ready") else tr("identity_not_ready", language),
    )
    advisory[3].metric(
        tr("identity_identity_confidence", language),
        value_label(detail.get("identity_confidence") or "unknown", language),
    )

    supporting = _safe_codes(detail.get("category_supporting_evidence"))
    contradicting = _safe_codes(detail.get("category_contradicting_evidence"))
    bucketed = _safe_codes(detail.get("category_evidence_json"))
    evidence_left, evidence_right = st.columns(2)
    with evidence_left:
        st.markdown(f"**{tr('identity_supporting_evidence', language)}**")
        if supporting or bucketed:
            for label in (supporting + [item for item in bucketed if item not in supporting])[:10]:
                st.markdown(f"- {html.escape(label)}")
        else:
            st.caption(tr("identity_no_supporting_evidence", language))
    with evidence_right:
        st.markdown(f"**{tr('identity_contradictions', language)}**")
        if contradicting:
            for label in contradicting[:10]:
                st.markdown(f"- {html.escape(label)}")
        else:
            st.caption(tr("identity_no_contradictions", language))

    with st.expander(tr("identity_provenance", language), expanded=False):
        source = value_label(detail.get("classification_evidence_source") or "unknown", language)
        st.caption(tr("identity_provenance_source", language, source=source))
        reason = _safe_code(detail.get("category_reason"))
        if reason:
            st.caption(tr("identity_provenance_reason", language, reason=reason))
        update_reason = _safe_code(detail.get("category_update_reason"))
        if update_reason:
            st.caption(tr("identity_update_reason", language, reason=update_reason))
        readiness = _safe_code(detail.get("card_readiness_reason"))
        if readiness:
            st.caption(tr("identity_readiness_reason", language, reason=readiness))
        st.caption(
            tr(
                "identity_evidence_version", language,
                version=int(detail.get("destination_html_evidence_version") or 0),
            )
        )


def _profile_name_map(card: dict) -> dict[str, str]:
    return {
        str(profile.get("id")): _safe_name(
            profile.get("handle"), tr("identity_observed_profile", "en")
        )
        for profile in card.get("profiles") or []
        if profile.get("id")
    }


def _render_profiles(st, card: dict, language: str) -> None:
    profiles = card.get("profiles") or []
    if not profiles:
        st.markdown(
            empty_state(
                tr("identity_profiles_empty", language),
                tr("identity_profiles_empty_help", language),
            ),
            unsafe_allow_html=True,
        )
        return
    for profile in profiles[:100]:
        display_handle = _safe_name(
            profile.get("handle"), tr("identity_observed_profile", language)
        )
        st.markdown(f"**{html.escape(display_handle)}**")
        st.caption(
            tr(
                "identity_profile_summary", language,
                role=profile.get("role_display") or tr("identity_public_alias", language),
                confidence=value_label(profile.get("confidence") or "unknown", language),
                seen=profile.get("last_observed") or tr("identity_not_dated", language),
            )
        )
        signals = _safe_codes(profile.get("evidence_types"), limit=8)
        if signals:
            st.caption(
                tr("identity_signal_types", language) + ": " + " · ".join(map(html.escape, signals))
            )
        pages = profile.get("source_pages") or []
        if pages:
            with st.expander(
                tr("identity_observed_pages", language, count=len(pages)),
                expanded=False,
            ):
                for page in pages[:10]:
                    st.caption(mask_onion_address(page))
        st.divider()


def _render_relationships(st, card: dict, language: str) -> None:
    relationships = card.get("relationships") or []
    if not relationships:
        st.markdown(
            empty_state(
                tr("identity_relationships_empty", language),
                tr("identity_relationships_empty_help", language),
            ),
            unsafe_allow_html=True,
        )
        return
    names = _profile_name_map(card)
    for relationship in relationships[:100]:
        source = names.get(
            str(relationship.get("source")),
            tr("identity_observed_profile", language),
        )
        raw_target = str(relationship.get("target") or "")
        target = names.get(raw_target, tr("identity_related_profile", language))
        relation = value_label(relationship.get("type") or "possible_correspondence", language)
        st.markdown(
            f"**{html.escape(source)}** - {html.escape(relation)} - **{html.escape(target)}**"
        )
        st.caption(
            tr(
                "identity_relationship_summary", language,
                confidence=value_label(relationship.get("confidence") or "unknown", language),
                count=int(relationship.get("evidence_count") or 0),
                decision=value_label(relationship.get("analyst_decision") or "unreviewed", language),
            )
        )
        evidence = _safe_codes(relationship.get("evidence"), limit=6)
        if evidence:
            with st.expander(tr("identity_evidence_details", language), expanded=False):
                for label in evidence:
                    st.caption(label)
        st.divider()
    st.caption(tr("identity_relationships_advisory", language))


def _render_identifiers(st, card: dict, language: str) -> None:
    identifiers = card.get("identifiers") or []
    if not identifiers:
        st.markdown(
            empty_state(
                tr("identity_identifiers_empty", language),
                tr("identity_identifiers_empty_help", language),
            ),
            unsafe_allow_html=True,
        )
        return
    grouped: dict[str, dict] = {}
    for item in identifiers:
        kind = str(item.get("type") or "unknown")
        row = grouped.setdefault(kind, {"count": 0, "last_seen": ""})
        row["count"] += max(1, int(item.get("count") or 0))
        row["last_seen"] = max(str(row["last_seen"] or ""), str(item.get("last_seen") or ""))
    st.info(tr("identity_identifiers_redacted", language))
    for kind, row in sorted(grouped.items()):
        st.markdown(f"**{html.escape(value_label(kind, language))}**")
        st.caption(
            tr(
                "identity_identifier_summary", language,
                count=row["count"], seen=row["last_seen"] or tr("identity_not_dated", language),
            )
        )


def _render_reference_candidates(st, card: dict, language: str) -> None:
    candidates = sorted(
        card.get("candidate_attributions") or [],
        key=lambda item: _score_value(item.get("score")),
        reverse=True,
    )
    st.info(tr("identity_candidates_advisory", language))
    if not candidates:
        st.markdown(
            empty_state(
                tr("identity_candidates_empty", language),
                tr("identity_candidates_empty_help", language),
            ),
            unsafe_allow_html=True,
        )
        return
    names = _profile_name_map(card)
    for candidate in candidates[:50]:
        observed = names.get(
            str(candidate.get("observed_profile")),
            tr("identity_observed_profile", language),
        )
        candidate_name = _safe_name((
            candidate.get("candidate_name") or candidate.get("candidate_entity_id")
            or tr("identity_reference_candidate", language)
        ), tr("identity_reference_candidate", language))
        score = _confidence_percent(candidate.get("score"))
        st.markdown(
            f"**{html.escape(str(observed))}** -> **{html.escape(str(candidate_name))}**"
        )
        st.caption(
            tr(
                "identity_candidate_summary", language,
                score=score,
                decision=value_label(candidate.get("decision") or "needs_review", language),
            )
        )
        supporting = _safe_codes(candidate.get("supporting"), limit=8)
        missing = _safe_codes(candidate.get("missing"), limit=8)
        left, right = st.columns(2)
        with left:
            st.markdown(f"**{tr('identity_supporting_evidence', language)}**")
            if supporting:
                for label in supporting:
                    st.caption(label)
            else:
                st.caption(tr("identity_no_supporting_evidence", language))
        with right:
            st.markdown(f"**{tr('identity_limitations', language)}**")
            if missing:
                for label in missing:
                    st.caption(label)
            else:
                st.caption(tr("identity_no_recorded_limitations", language))
        st.divider()


def _provider_state(run: dict | None) -> dict:
    if not run:
        return {}
    return _json_value(run.get("provider_status_json"), {})


def _candidate_clusters(run: dict | None) -> list[dict]:
    if not run:
        return []
    return _json_value(run.get("candidate_clusters_json"), [])


def _local_results(run: dict | None) -> dict:
    if not run:
        return {}
    return _json_value(run.get("local_results_json"), {})


def _render_provider_state(st, job: dict | None, run: dict | None, language: str) -> None:
    provider = _provider_state(run)
    status = str((run or {}).get("run_status") or (job or {}).get("status") or "not_started")
    if status in {"queued", "retry", "pending"}:
        st.info(tr("identity_discovery_waiting", language))
    elif status in {"claimed", "running"}:
        st.info(tr("identity_discovery_running", language))
    elif status in {"failed", "dead_letter"}:
        st.error(tr("identity_discovery_failed", language))
    elif status in {
        "done", "complete", "completed", "succeeded",
        "local_complete", "provider_complete",
    }:
        st.success(tr("identity_discovery_complete", language))
    elif status == "provider_empty":
        st.info(tr("identity_discovery_complete", language))
    elif status == "provider_partial":
        st.warning(tr("identity_discovery_partial", language))
    elif run:
        st.warning(tr("identity_discovery_unavailable", language))
    else:
        st.caption(tr("identity_discovery_not_started", language))

    enabled = _safe_codes(provider.get("enabled_providers"), limit=10)
    disabled = _safe_codes(provider.get("disabled_providers"), limit=10)
    network_enabled = bool(provider.get("network_enabled"))
    state_columns = st.columns(3)
    state_columns[0].metric(
        tr("identity_provider_mode", language),
        tr("identity_provider_network", language) if network_enabled else tr("identity_provider_local", language),
    )
    state_columns[1].metric(tr("identity_provider_enabled", language), len(enabled))
    state_columns[2].metric(tr("identity_provider_disabled", language), len(disabled))
    if enabled:
        st.caption(tr("identity_provider_enabled_list", language, providers=", ".join(enabled)))
    if disabled:
        st.caption(tr("identity_provider_disabled_list", language, providers=", ".join(disabled)))
    reason = _safe_code(provider.get("reason"))
    if reason:
        st.caption(tr("identity_provider_reason", language, reason=reason))


def _render_discovery_candidates(st, run: dict | None, language: str) -> None:
    clusters = sorted(
        _candidate_clusters(run),
        key=lambda item: _score_value(item.get("score")),
        reverse=True,
    )
    if not clusters:
        st.markdown(
            empty_state(
                tr("identity_discovery_candidates_empty", language),
                tr("identity_discovery_candidates_empty_help", language),
            ),
            unsafe_allow_html=True,
        )
        return
    st.markdown(
        section_header(
            tr("identity_discovery_candidates", language),
            tr("identity_discovery_candidates_help", language),
            count=len(clusters),
        ),
        unsafe_allow_html=True,
    )
    for candidate in clusters[:50]:
        name = _safe_name((
            candidate.get("display_name") or candidate.get("candidate_id")
            or tr("identity_reference_candidate", language)
        ), tr("identity_reference_candidate", language))
        score = _confidence_percent(candidate.get("score"))
        provider = _safe_code(candidate.get("provider")) or tr("identity_provider_unknown", language)
        st.markdown(f"**{html.escape(str(name))}**")
        st.caption(
            tr(
                "identity_discovery_candidate_summary", language,
                score=score,
                decision=value_label(candidate.get("decision") or "needs_review", language),
                provider=provider,
            )
        )
        supporting = _safe_codes(candidate.get("supporting_evidence"), limit=8)
        contradicting = _safe_codes(candidate.get("contradicting_evidence"), limit=8)
        left, right = st.columns(2)
        with left:
            st.markdown(f"**{tr('identity_supporting_evidence', language)}**")
            if supporting:
                for label in supporting:
                    st.caption(label)
            else:
                st.caption(tr("identity_no_supporting_evidence", language))
        with right:
            st.markdown(f"**{tr('identity_contradictions', language)}**")
            if contradicting:
                for label in contradicting:
                    st.caption(label)
            else:
                st.caption(tr("identity_no_contradictions", language))
        provenance = _safe_codes(candidate.get("evidence_chain"), limit=8)
        if provenance:
            with st.expander(tr("identity_provenance", language), expanded=False):
                for step, label in enumerate(provenance, start=1):
                    st.caption(f"{step}. {label}")
        st.divider()


def _render_local_candidates(st, run: dict | None, language: str) -> None:
    local = _local_results(run)
    candidates = local.get("same_alias_candidates") or []
    if not candidates:
        return
    with st.expander(tr("identity_local_exact_candidates", language), expanded=False):
        st.caption(tr("identity_local_exact_candidates_help", language))
        for candidate in candidates[:20]:
            alias = _safe_name(
                candidate.get("display_alias"),
                tr("identity_observed_profile", language),
            )
            st.markdown(f"**{html.escape(str(alias))}**")
            st.caption(
                f"{mask_onion_address(candidate.get('onion_host'))} · "
                f"{value_label(candidate.get('confidence') or 'unknown', language)}"
            )


def _render_deep_discovery(st, site_card_id: int, language: str) -> None:
    st.info(tr("identity_discovery_advisory", language))
    try:
        discovery = deep_discovery.summary_for_site_card(site_card_id)
        jobs = storage.get_deep_discovery_jobs(site_card_id=site_card_id, limit=500)
        runs = storage.get_deep_discovery_runs(site_card_id=site_card_id, limit=500)
    except (ValueError, sqlite3.Error, TypeError):
        st.error(tr("identity_discovery_unavailable", language))
        return
    jobs_by_actor = {int(job.get("actor_id") or 0): job for job in jobs}
    latest_run_by_job: dict[int, dict] = {}
    for run in runs:
        latest_run_by_job.setdefault(int(run.get("job_id") or 0), run)
    if not discovery:
        st.markdown(
            empty_state(
                tr("identity_discovery_empty", language),
                tr("identity_discovery_empty_help", language),
            ),
            unsafe_allow_html=True,
        )
        return
    for item in discovery[:100]:
        profile = item.get("profile") or {}
        eligibility = item.get("eligibility") or {}
        actor_id = int(profile.get("actor_id") or 0)
        job = jobs_by_actor.get(actor_id)
        run = latest_run_by_job.get(int((job or {}).get("id") or 0))
        profile_name = _safe_name(
            profile.get("display_alias"),
            tr("identity_observed_profile", language),
        )
        st.markdown(
            section_header(
                profile_name,
                tr(
                    "identity_eligibility_summary", language,
                    score=_confidence_percent(eligibility.get("score")),
                    state=value_label((job or {}).get("status") or "not_started", language),
                ),
            ),
            unsafe_allow_html=True,
        )
        _render_provider_state(st, job, run, language)
        reasons = _safe_codes(eligibility.get("reasons"), limit=8)
        blockers = _safe_codes(eligibility.get("blockers"), limit=8)
        pivots = _safe_codes(eligibility.get("strong_pivots"), limit=8)
        with st.expander(tr("identity_eligibility_evidence", language), expanded=False):
            if pivots:
                st.caption(tr("identity_strong_pivots", language) + ": " + " · ".join(pivots))
            if reasons:
                st.caption(tr("identity_supporting_evidence", language) + ": " + " · ".join(reasons))
            if blockers:
                st.caption(tr("identity_blockers", language) + ": " + " · ".join(blockers))
            if not (pivots or reasons or blockers):
                st.caption(tr("identity_no_eligibility_detail", language))
        _render_discovery_candidates(st, run, language)
        _render_local_candidates(st, run, language)


def _render_history(st, card: dict, language: str) -> None:
    timeline = card.get("timeline") or []
    if not timeline:
        st.markdown(
            empty_state(
                tr("identity_history_empty", language),
                tr("identity_history_empty_help", language),
            ),
            unsafe_allow_html=True,
        )
    for event in timeline[:30]:
        st.markdown(
            f"**{html.escape(str(event.get('ts') or tr('identity_unknown_time', language)))}** - "
            f"{html.escape(str(event.get('label') or tr('identity_update', language)))}"
        )
    pages = card.get("observed_pages") or []
    with st.expander(tr("identity_observed_pages", language, count=len(pages)), expanded=False):
        if not pages:
            st.caption(tr("identity_pages_empty", language))
        for page in pages[:80]:
            st.caption(
                f"{mask_onion_address(page.get('path'))} · "
                f"{value_label(page.get('page_type') or 'page', language)} · "
                f"{value_label(page.get('purpose') or 'observed', language)}"
            )


def _render_live_cards(st, cards: list[dict], language: str) -> None:
    if not cards:
        st.markdown(
            empty_state(
                tr("identity_cards_empty", language),
                tr("identity_cards_empty_help", language),
            ),
            unsafe_allow_html=True,
        )
        return
    labels = {}
    for card in cards:
        card_id = int(card["id"])
        display_name = _safe_name(
            card.get("analyst_title") or card.get("display_name"),
            f"{tr('identity_site_card', language)} #{card_id}",
        )
        labels[f"#{card_id} - {display_name}"] = card_id
    selected = st.selectbox(tr("identity_site_card", language), list(labels), key="identity-live-card")
    site_card_id = labels[selected]
    try:
        card = structured_intelligence.build_live_structured_card(site_card_id)
    except (ValueError, sqlite3.Error, TypeError):
        st.error(tr("identity_card_load_error", language))
        return
    if not card:
        st.warning(tr("identity_card_missing", language))
        return

    card_name = _safe_name(
        card.get("name"),
        f"{tr('identity_site_card', language)} #{site_card_id}",
    )
    st.markdown(
        section_header(card_name, tr("identity_live_origin", language)),
        unsafe_allow_html=True,
    )
    if card.get("summary"):
        st.write(card["summary"])
    _render_live_classification(st, site_card_id, language)

    coverage = card.get("coverage") or {}
    metrics = st.columns(5)
    metrics[0].metric(tr("identity_pages", language), coverage.get("pages", 0))
    metrics[1].metric(tr("identity_profiles", language), coverage.get("profiles", 0))
    metrics[2].metric(tr("identity_identifiers", language), coverage.get("identifiers", 0))
    metrics[3].metric(tr("identity_relationships", language), coverage.get("relationships", 0))
    metrics[4].metric(
        tr("identity_reference_matches", language),
        coverage.get("candidate_attributions", 0),
    )

    p_tab, r_tab, i_tab, c_tab, d_tab, t_tab = st.tabs([
        tr("identity_tab_profiles", language),
        tr("identity_tab_relationships", language),
        tr("identity_tab_identifiers", language),
        tr("identity_tab_reference_matches", language),
        tr("identity_tab_discovery", language),
        tr("identity_tab_history", language),
    ])
    with p_tab:
        _render_profiles(st, card, language)
    with r_tab:
        _render_relationships(st, card, language)
    with i_tab:
        _render_identifiers(st, card, language)
    with c_tab:
        _render_reference_candidates(st, card, language)
    with d_tab:
        _render_deep_discovery(st, site_card_id, language)
    with t_tab:
        _render_history(st, card, language)


def _render_alias_directory(st, actors: list[dict], language: str) -> None:
    search = st.text_input(tr("identity_search_aliases", language), key="identity-alias-search")
    needle = search.casefold().strip()
    visible = [
        actor for actor in actors
        if not needle or needle in str(actor.get("display_alias") or "").casefold()
        or needle in str(actor.get("onion_host") or "").casefold()
    ]
    if not visible:
        st.markdown(
            empty_state(
                tr("identity_aliases_empty", language),
                tr("identity_aliases_empty_help", language),
            ),
            unsafe_allow_html=True,
        )
        return
    for actor in visible[:100]:
        display_alias = _safe_name(
            actor.get("display_alias"),
            tr("identity_observed_alias", language),
        )
        st.markdown(
            f"**{html.escape(display_alias)}**"
        )
        st.caption(
            tr(
                "identity_alias_summary", language,
                host=mask_onion_address(actor.get("onion_host")),
                count=actor.get("observation_count") or 0,
                confidence=value_label(actor.get("confidence_label") or "low", language),
            )
        )
        st.divider()


def _render_references(st, references: list[dict], language: str) -> None:
    st.info(tr("identity_references_advisory", language))
    if not references:
        st.markdown(
            empty_state(
                tr("identity_references_empty", language),
                tr("identity_references_empty_help", language),
            ),
            unsafe_allow_html=True,
        )
        return
    for entity in references[:100]:
        st.markdown(
            f"**{html.escape(entity.get('canonical_name') or tr('identity_reference', language))}**"
        )
        st.caption(
            tr(
                "identity_reference_summary", language,
                entity_type=value_label(entity.get("entity_type") or "unknown", language),
                status=value_label(entity.get("attribution_status") or "unresolved", language),
                handles=len(entity.get("handles") or []),
                sources=len(entity.get("sources") or []),
            )
        )
        policies = Counter(str(item.get("policy") or "contextual_only") for item in entity.get("handles") or [])
        if policies:
            st.caption(
                tr(
                    "identity_reference_policies", language,
                    policies=", ".join(
                        f"{value_label(policy, language)} ({count})"
                        for policy, count in sorted(policies.items())
                    ),
                )
            )
        st.divider()


def _render_matching_rules(st, language: str) -> None:
    st.markdown(
        section_header(tr("identity_matching_rules", language)),
        unsafe_allow_html=True,
    )
    st.info(tr("identity_matching_rules_advisory", language))
    rules = (
        ("exact_safe", "identity_rule_exact"),
        ("contextual_only", "identity_rule_contextual"),
        ("disabled_global", "identity_rule_disabled"),
    )
    for code, copy_key in rules:
        st.markdown(f"**{html.escape(code)}**")
        st.caption(tr(copy_key, language))


def render(st, query) -> None:
    language = current_language(st)
    st.markdown(
        page_lead(
            "Señales de identidad" if language == "es" else "Identity signals",
            tr("identity_intro", language),
            eyebrow="Identidad pública" if language == "es" else "Public identity",
            aside="Metadatos seguros" if language == "es" else "Safe metadata",
            show_title=False,
        ),
        unsafe_allow_html=True,
    )
    try:
        cards = storage.get_connection_workbench(limit=200)
        actors = storage.get_public_actors(limit=500)
        references = identity_registry.reference_entities()
    except (ValueError, sqlite3.Error, TypeError):
        st.error(tr("identity_workspace_unavailable", language))
        return
    metrics = st.columns(4)
    metrics[0].metric(tr("identity_structured_cards", language), len(cards))
    metrics[1].metric(tr("identity_observed_aliases", language), len(actors))
    metrics[2].metric(
        tr("identity_watched_aliases", language),
        sum(1 for actor in actors if actor.get("watched")),
    )
    metrics[3].metric(tr("identity_analyst_references", language), len(references))

    live_tab, aliases_tab, references_tab, rules_tab = st.tabs([
        tr("identity_live_site_cards", language),
        tr("identity_observed_aliases", language),
        tr("identity_analyst_references", language),
        tr("identity_matching_rules", language),
    ])
    with live_tab:
        _render_live_cards(st, cards, language)
    with aliases_tab:
        _render_alias_directory(st, actors, language)
    with references_tab:
        _render_references(st, references, language)
    with rules_tab:
        _render_matching_rules(st, language)
