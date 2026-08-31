"""Plain-language classification quality, coverage, and operations workspace."""
from __future__ import annotations

import html
from collections import Counter

import storage
from dashboard_services.i18n import category_label, current_language, tr
from ui_components import empty_state, mask_onion_address, page_lead, section_header


_RESTRICTED_CATEGORIES = {
    "adult_filtered", "adult_restricted", "adult_extreme_caution", "severe_abuse_risk",
}
_QUALITY_WINDOWS = (7, 30, 90)
_UNCERTAIN_PAGE_SIZE = 15


def _integer(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _percentage(value) -> int:
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        return 0
    if 0 <= number <= 1:
        number *= 100
    return max(0, min(100, round(number)))


def _metric(st, label: str, value, help_text: str, sample_text: str) -> None:
    st.metric(label, value, help=help_text)
    st.caption(sample_text)


def _legacy_report() -> dict:
    """Build a conservative fallback while older databases are being upgraded."""
    quality = storage.get_classification_quality_summary()
    decisions = quality.get("decisions", {})
    total = _integer(quality.get("total"))
    unsure = _integer(decisions.get("abstained")) + _integer(decisions.get("needs_review"))
    return {
        "page_decisions": total,
        "unique_pages": total,
        "accepted": _integer(decisions.get("accepted")),
        "unsure": unsure,
        "unknown_rate": (unsure / total) if total else 0,
        "reviewed_count": _integer(quality.get("analyst_reviews")),
        "category_corrections": _integer(quality.get("corrections")),
        "correction_rate": float(quality.get("correction_rate") or 0),
        "feedback_by_dimension": {},
        "correction_pairs": [],
        "unknown_reasons": [],
        "shadow_candidates": [],
        "safety_excluded": 0,
    }


def _empty_report() -> dict:
    return {
        "page_decisions": 0,
        "unique_pages": 0,
        "accepted": 0,
        "unsure": 0,
        "unknown_rate": 0,
        "reviewed_count": 0,
        "category_corrections": 0,
        "correction_rate": 0,
        "feedback_by_dimension": {},
        "correction_pairs": [],
        "unknown_reasons": [],
        "shadow_candidates": [],
        "safety_excluded": 0,
    }


def _quality_report(days: int) -> dict:
    """Use the richer report API when available without breaking rolling upgrades."""
    report_reader = getattr(storage, "get_classification_quality_report", None)
    if not callable(report_reader):
        return _legacy_report()
    try:
        report = report_reader(days=days)
    except TypeError:
        report = report_reader(days)
    if not isinstance(report, dict):
        return _legacy_report()
    normalized = _empty_report()
    normalized.update(report)
    return normalized


def _count_rows(value, *, label_keys: tuple[str, ...]) -> list[dict]:
    if isinstance(value, dict):
        rows = []
        for label, payload in value.items():
            if isinstance(payload, dict):
                row = dict(payload)
                row.setdefault("label", label)
            else:
                row = {"label": label, "count": payload}
            rows.append(row)
    elif isinstance(value, list):
        rows = [dict(item) for item in value if isinstance(item, dict)]
    else:
        rows = []
    for row in rows:
        if not row.get("label"):
            row["label"] = next((row.get(key) for key in label_keys if row.get(key)), "unknown")
        row["count"] = _integer(
            row.get("count", row.get("decision_count", row.get("total", row.get("pages", 0))))
        )
    return sorted(rows, key=lambda row: (-row["count"], str(row.get("label") or "")))


def _unknown_rows(report: dict) -> list[dict]:
    return _count_rows(
        report.get("unknown_reasons"),
        label_keys=("reason_code", "reason", "category_reason", "verification_reason"),
    )


def _correction_rows(report: dict) -> list[dict]:
    rows = _count_rows(
        report.get("correction_pairs"),
        label_keys=("pair", "transition", "previous_category"),
    )
    for row in rows:
        row["previous_category"] = (
            row.get("previous_category") or row.get("from_category") or row.get("from") or "unknown"
        )
        row["final_category"] = (
            row.get("final_category") or row.get("new_category") or row.get("to_category")
            or row.get("to") or "unknown"
        )
    return rows


def _human_reason(value: object) -> str:
    return " ".join(str(value or "unknown").replace("-", "_").split("_")).strip().capitalize()


def _dimension_label(value: object, language: str) -> str:
    key = str(value or "unknown").casefold()
    if key == "review":
        return "Revisión" if language == "es" else "Review"
    translation_key = {
        "category": "quality_dimension_category",
        "spain": "quality_dimension_spain",
        "urgency": "quality_dimension_urgency",
        "restriction": "quality_dimension_restriction",
        "dedupe": "quality_dimension_dedupe",
    }.get(key)
    return tr(translation_key, language) if translation_key else _human_reason(value)


def _feedback_rows(report: dict) -> list[dict]:
    value = report.get("feedback_by_dimension")
    if not isinstance(value, dict):
        return []
    rows = []
    for dimension, payload in value.items():
        data = dict(payload) if isinstance(payload, dict) else {"reviewed_count": payload}
        reviewed = _integer(
            data.get("reviewed_count", data.get("reviewed", data.get("sample_size", data.get("total"))))
        )
        confirmed = _integer(
            data.get("confirmed", data.get("accepted", data.get("kept", data.get("positive"))))
        )
        changed = _integer(
            data.get(
                "corrected",
                data.get(
                    "rejected",
                    data.get(
                        "false_positive",
                        data.get("ignored", data.get("too_high", data.get("negative"))),
                    ),
                ),
            )
        )
        rows.append({
            "dimension": str(dimension),
            "reviewed": reviewed,
            "confirmed": confirmed,
            "changed": changed,
        })
    preferred = {"category": 0, "spain": 1, "urgency": 2, "restriction": 3, "dedupe": 4}
    return sorted(rows, key=lambda row: (preferred.get(row["dimension"], 99), row["dimension"]))


def _render_improvement_summary(st, report: dict, language: str) -> None:
    st.markdown(
        section_header(
            tr("quality_improvement_title", language),
            tr("quality_improvement_help", language),
        ),
        unsafe_allow_html=True,
    )
    unknown = _unknown_rows(report)
    corrections = _correction_rows(report)
    feedback = sorted(_feedback_rows(report), key=lambda row: (-row["changed"], row["dimension"]))
    items: list[tuple[str, str]] = []
    if unknown and unknown[0]["count"]:
        items.append((
            tr("quality_improvement_unknown", language),
            tr(
                "quality_improvement_unknown_value", language,
                reason=_human_reason(unknown[0]["label"]), count=unknown[0]["count"],
            ),
        ))
    if corrections and corrections[0]["count"]:
        items.append((
            tr("quality_improvement_correction", language),
            tr(
                "quality_improvement_correction_value", language,
                previous=category_label(corrections[0]["previous_category"], language),
                current=category_label(corrections[0]["final_category"], language),
                count=corrections[0]["count"],
            ),
        ))
    if feedback and feedback[0]["changed"]:
        items.append((
            tr("quality_improvement_feedback", language),
            tr(
                "quality_improvement_feedback_value", language,
                dimension=_dimension_label(feedback[0]["dimension"], language),
                count=feedback[0]["changed"], sample=feedback[0]["reviewed"],
            ),
        ))
    if not items:
        st.markdown(
            empty_state(
                tr("quality_improvement_empty", language),
                tr("quality_improvement_empty_help", language),
            ),
            unsafe_allow_html=True,
        )
        return
    columns = st.columns(len(items))
    for column, (label, detail) in zip(columns, items, strict=False):
        with column:
            st.markdown(f"**{html.escape(label)}**")
            st.caption(detail)


def _group_uncertain(rows: list[dict]) -> list[dict]:
    groups: dict[str, dict] = {}
    for row in rows:
        category = str(row.get("primary_category") or "unknown")
        if category in _RESTRICTED_CATEGORIES:
            continue
        card_id = _integer(row.get("site_card_id"))
        masked_host = mask_onion_address(row.get("url"))
        group_key = f"card:{card_id}" if card_id else f"host:{masked_host}"
        group = groups.setdefault(group_key, {
            "site_card_id": card_id or None,
            "masked_host": masked_host,
            "rows": [],
            "suggestions": Counter(),
            "reasons": Counter(),
            "confidence": 0.0,
        })
        group["rows"].append(row)
        if row.get("suggested_category"):
            group["suggestions"][str(row["suggested_category"])] += 1
        if row.get("category_reason"):
            group["reasons"][str(row["category_reason"])[:240]] += 1
        try:
            group["confidence"] = max(
                group["confidence"], float(row.get("classification_confidence_score") or 0)
            )
        except (TypeError, ValueError):
            pass
    return sorted(
        groups.values(),
        key=lambda group: (-len(group["rows"]), -group["confidence"], group["masked_host"]),
    )


def _render_uncertain(st, language: str) -> None:
    uncertain = storage.get_uncertain_classifications(500)
    groups = _group_uncertain(uncertain)
    if not groups:
        st.markdown(
            empty_state(
                tr("quality_none_uncertain", language),
                tr("quality_review_queue_help", language),
            ),
            unsafe_allow_html=True,
        )
        return
    page_count = max(1, (len(groups) + _UNCERTAIN_PAGE_SIZE - 1) // _UNCERTAIN_PAGE_SIZE)
    page_key = "quality_uncertain_page"
    page = min(max(_integer(st.session_state.get(page_key)) or 1, 1), page_count)
    st.session_state[page_key] = page
    start = (page - 1) * _UNCERTAIN_PAGE_SIZE
    for index, group in enumerate(groups[start:start + _UNCERTAIN_PAGE_SIZE], start=start):
        suggested_code = group["suggestions"].most_common(1)[0][0] if group["suggestions"] else None
        suggested = (
            category_label(suggested_code, language)
            if suggested_code else tr("quality_no_suggestion", language)
        )
        identity = (
            tr("quality_site_card_identity", language, card_id=group["site_card_id"])
            if group["site_card_id"] else tr("quality_unassigned_identity", language)
        )
        page_total = len(group["rows"])
        label = (
            f"{identity} - {group['masked_host']} - "
            f"{tr('quality_uncertain_page_count', language, count=page_total)}"
        )
        with st.expander(label):
            st.write(tr("quality_suggested", language, category=suggested))
            st.caption(
                group["reasons"].most_common(1)[0][0]
                if group["reasons"] else tr("quality_needs_evidence", language)
            )
            st.caption(
                tr(
                    "quality_confidence_sample", language,
                    confidence=round(max(0, min(1, group["confidence"])) * 100),
                    count=page_total,
                )
            )
            if group["site_card_id"]:
                if st.button(
                    tr("quality_open_card", language),
                    key=f"quality_card_{index}_{group['site_card_id']}",
                ):
                    from dashboard_pages.site_directory import open_card
                    open_card(int(group["site_card_id"]), False)
                    st.rerun()
    if page_count > 1:
        previous, status, following = st.columns([1, 3, 1])
        if previous.button(
            tr("previous", language), key="quality-uncertain-previous",
            disabled=page <= 1, use_container_width=True,
        ):
            st.session_state[page_key] = page - 1
            st.rerun()
        status.caption(tr("quality_page_status", language, page=page, pages=page_count))
        if following.button(
            tr("next", language), key="quality-uncertain-next",
            disabled=page >= page_count, use_container_width=True,
        ):
            st.session_state[page_key] = page + 1
            st.rerun()


def _render_feedback(st, report: dict, language: str) -> None:
    rows = _feedback_rows(report)
    if not rows:
        st.caption(tr("quality_feedback_empty", language))
        return
    st.markdown(
        section_header(
            tr("quality_feedback_title", language),
            tr("quality_feedback_help", language),
        ),
        unsafe_allow_html=True,
    )
    for row in rows:
        st.markdown(
            f"**{html.escape(_dimension_label(row['dimension'], language))}** - "
            f"{tr('quality_feedback_sample', language, count=row['reviewed'])}"
        )
        st.caption(
            tr(
                "quality_feedback_outcomes", language,
                confirmed=row["confirmed"], changed=row["changed"],
            )
        )


def _shadow_rows(value) -> list[dict]:
    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        rows = []
        for name, payload in value.items():
            row = dict(payload) if isinstance(payload, dict) else {"changed_count": payload}
            row.setdefault("candidate_ruleset", name)
            rows.append(row)
        return rows
    return []


def _render_shadow(st, report: dict, language: str) -> None:
    st.info(tr("quality_shadow_advisory", language))
    candidates = _shadow_rows(report.get("shadow_candidates"))
    if not candidates:
        st.markdown(
            empty_state(
                tr("quality_shadow_empty", language),
                tr("quality_shadow_empty_help", language),
            ),
            unsafe_allow_html=True,
        )
        return
    for row in candidates:
        ruleset = str(
            row.get("candidate_ruleset") or row.get("ruleset_version")
            or row.get("candidate_version") or row.get("classifier_version")
            or tr("quality_shadow_candidate", language)
        )[:100]
        sample = _integer(
            row.get(
                "sample_size",
                row.get("observations", row.get("evaluated", row.get("decision_count", row.get("total")))),
            )
        )
        changed = _integer(
            row.get(
                "changed_count",
                row.get("differences", row.get("changed", row.get("different_count"))),
            )
        )
        excluded = _integer(
            row.get("safety_excluded", row.get("safety_invariant_blocked"))
        )
        if not excluded and len(candidates) == 1:
            excluded = _integer(report.get("safety_excluded"))
        st.markdown(f"**{html.escape(ruleset)}**")
        st.caption(
            tr(
                "quality_shadow_summary", language,
                sample=sample, changed=changed, excluded=excluded,
            )
        )
        current = row.get("current_category")
        candidate = row.get("candidate_category")
        if current or candidate:
            st.caption(
                tr(
                    "quality_shadow_category_delta", language,
                    current=category_label(current or "unknown", language),
                    candidate=category_label(candidate or "unknown", language),
                )
            )


def _safe_graph_label(value: object) -> str:
    label = str(value or "")
    if ".onion" in label.casefold():
        return mask_onion_address(label)
    return label


def render(st, query) -> None:
    language = current_language(st)
    st.markdown(
        page_lead(
            tr("page_quality", language),
            tr("quality_intro", language),
            eyebrow=tr("page_quality", language),
            show_title=False,
        ),
        unsafe_allow_html=True,
    )
    window = st.selectbox(
        tr("quality_window", language),
        _QUALITY_WINDOWS,
        index=1,
        format_func=lambda days: tr("quality_window_days", language, days=days),
        key="quality_window_days",
        help=tr("quality_window_help", language),
    )
    report = _quality_report(int(window))
    st.info(tr("quality_advisory", language))

    unique_pages = _integer(report.get("unique_pages"))
    page_decisions = _integer(report.get("page_decisions"))
    accepted = _integer(report.get("accepted"))
    unsure = _integer(report.get("unsure"))
    reviewed = _integer(report.get("reviewed_count"))
    corrections = _integer(report.get("category_corrections"))
    columns = st.columns(4)
    with columns[0]:
        _metric(
            st, tr("quality_accepted", language), accepted,
            tr("quality_accepted_help", language),
            tr("quality_sample_pages", language, count=unique_pages),
        )
    with columns[1]:
        _metric(
            st, tr("quality_unsure", language), unsure,
            tr("quality_unsure_help", language),
            tr(
                "quality_unknown_sample", language,
                percent=_percentage(report.get("unknown_rate")), count=unique_pages,
            ),
        )
    with columns[2]:
        _metric(
            st, tr("quality_reviews", language), reviewed,
            tr("quality_reviews_help", language),
            (
                tr("quality_review_sample", language, count=reviewed)
                if reviewed else tr("quality_no_review_sample", language)
            ),
        )
    with columns[3]:
        _metric(
            st, tr("quality_corrections", language), corrections,
            tr("quality_corrections_help", language),
            (
                tr(
                    "quality_correction_sample", language,
                    count=reviewed, percent=_percentage(report.get("correction_rate")),
                )
                if reviewed else tr("quality_no_review_sample", language)
            ),
        )
    st.caption(
        tr(
            "quality_decision_event_sample", language,
            decisions=page_decisions, pages=unique_pages,
        )
    )
    _render_improvement_summary(st, report, language)
    _render_feedback(st, report, language)

    decision_tab, coverage_tab, changes_tab, connections_tab, operations_tab, shadow_tab = st.tabs([
        tr("quality_tab_decisions", language), tr("quality_tab_coverage", language),
        tr("quality_tab_changes", language), tr("quality_tab_connections", language),
        tr("quality_tab_operations", language), tr("quality_tab_shadow", language),
    ])
    with decision_tab:
        st.markdown(
            section_header(
                tr("quality_review_queue", language),
                tr("quality_review_queue_help", language),
            ),
            unsafe_allow_html=True,
        )
        _render_uncertain(st, language)
        corrections_rows = _correction_rows(report)
        if corrections_rows:
            st.markdown(
                section_header(tr("quality_correction_patterns", language)),
                unsafe_allow_html=True,
            )
            for row in corrections_rows[:8]:
                st.markdown(
                    f"**{html.escape(category_label(row['previous_category'], language))}** "
                    f"-> **{html.escape(category_label(row['final_category'], language))}**"
                )
                st.caption(tr("quality_correction_count", language, count=row["count"]))
        legacy_quality = storage.get_classification_quality_summary()
        visible_categories = [
            row for row in legacy_quality.get("categories", [])
            if row.get("final_category") not in _RESTRICTED_CATEGORIES
        ]
        if visible_categories:
            with st.expander(tr("quality_category_summary", language), expanded=False):
                st.caption(tr("quality_technical_totals_help", language))
                st.dataframe(visible_categories, use_container_width=True, hide_index=True)

    with coverage_tab:
        st.markdown(
            section_header(tr("coverage_title", language), tr("coverage_help", language)),
            unsafe_allow_html=True,
        )
        with storage.get_db() as db:
            verification = {row[0]: int(row[1]) for row in db.execute(
                "SELECT COALESCE(verification_state,'discovered'),COUNT(*) FROM onion_urls GROUP BY verification_state")}
        state_cols = st.columns(3)
        state_cols[0].metric(
            tr("quality_discovered", language), verification.get("discovered", 0),
            help=tr("quality_discovered_help", language),
        )
        state_cols[1].metric(
            tr("quality_provisional", language), verification.get("provisional", 0),
            help=tr("quality_provisional_help", language),
        )
        state_cols[2].metric(
            tr("quality_verified", language), verification.get("verified", 0),
            help=tr("quality_verified_help", language),
        )
        coverage = storage.get_crawl_coverage(200)
        if not coverage:
            st.markdown(empty_state(tr("coverage_empty", language)), unsafe_allow_html=True)
        else:
            display = [{
                tr("coverage_host", language): mask_onion_address(row["onion_host"]),
                tr("coverage_progress", language): f"{round(float(row['coverage_ratio'] or 0) * 100)}%",
                tr("coverage_checked", language): int(row["checked_count"] or 0),
                tr("coverage_found", language): int(row["discovered_count"] or 0),
                tr("coverage_waiting", language): int(row["queued_count"] or 0),
                tr("coverage_hidden", language): int(row["restricted_count"] or 0),
                tr("coverage_stop", language): row["stopping_reason"],
            } for row in coverage]
            st.dataframe(display, use_container_width=True, hide_index=True)

    with changes_tab:
        st.markdown(
            section_header(tr("changes_title", language), tr("changes_help", language)),
            unsafe_allow_html=True,
        )
        changes = [
            row for row in storage.get_meaningful_changes(100)
            if row.get("previous_category") not in _RESTRICTED_CATEGORIES
            and row.get("current_category") not in _RESTRICTED_CATEGORIES
        ]
        if not changes:
            st.markdown(empty_state(tr("changes_empty", language)), unsafe_allow_html=True)
        for row in changes:
            old = category_label(row.get("previous_category"), language)
            new = category_label(row.get("current_category"), language)
            masked = mask_onion_address(row.get("url"))
            st.markdown(
                f"**{html.escape(str(row['change_type']).replace('_', ' ').title())}** "
                f"- `{html.escape(masked)}`"
            )
            st.caption(f"{row['detected_at']} - {old} -> {new}")

    with connections_tab:
        st.markdown(
            section_header(tr("connections_title", language), tr("connections_help", language)),
            unsafe_allow_html=True,
        )
        with storage.get_db() as db:
            graph_cards = [dict(row) for row in db.execute("""SELECT id,display_name,primary_category FROM site_cards
              WHERE primary_category NOT IN ('adult_filtered','adult_restricted','severe_abuse_risk')
              AND storage_policy!='discard' ORDER BY updated_at DESC LIMIT 200""")]
        if graph_cards:
            graph_labels = {
                f"#{row['id']} - {row.get('display_name') or category_label(row.get('primary_category'), language)}": row["id"]
                for row in graph_cards
            }
            graph_selected = st.selectbox(
                tr("connections_card", language), list(graph_labels), key="quality_graph_card",
            )
            graph = storage.get_site_evidence_graph(int(graph_labels[graph_selected]))
            lines = [
                "digraph Signals {", "rankdir=LR;",
                'node [shape=box,style="rounded,filled",fontname="Arial"];',
            ]
            for node in graph["nodes"]:
                color = (
                    "#dbeafe" if node["kind"] == "site_card" else
                    "#ecfdf5" if node["kind"] == "onion_url" else
                    "#f3e8ff" if node["kind"] == "actor" else "#fef3c7"
                )
                label = _safe_graph_label(node["label"]).replace("\\", "\\\\").replace('"', '\\"')
                lines.append(f'"{node["id"]}" [label="{label}",fillcolor="{color}"];')
            for edge in graph["edges"]:
                label = str(edge["label"]).replace('"', '\\"')
                lines.append(f'"{edge["source"]}" -> "{edge["target"]}" [label="{label}"];')
            lines.append("}")
            st.graphviz_chart("\n".join(lines), use_container_width=True)
        else:
            st.markdown(empty_state(tr("connections_empty", language)), unsafe_allow_html=True)

    with operations_tab:
        st.markdown(
            section_header(tr("operations_title", language), tr("operations_help", language)),
            unsafe_allow_html=True,
        )
        health = storage.get_operational_health()
        worker = health.get("worker", {})
        cols = st.columns(4)
        cols[0].metric(tr("operations_worker", language), worker.get("state") or "not started")
        cols[1].metric(tr("operations_waiting", language), int(health.get("queued") or 0))
        cols[2].metric(tr("operations_retrying", language), int(health.get("retrying") or 0))
        cols[3].metric(tr("operations_errors", language), int(health.get("errors") or 0))
        st.caption(tr("operations_export_help", language))
        with storage.get_db() as db:
            cards = [dict(row) for row in db.execute("""SELECT id,display_name,primary_category FROM site_cards
              WHERE primary_category NOT IN ('adult_filtered','adult_restricted','severe_abuse_risk')
              AND storage_policy!='discard' ORDER BY updated_at DESC LIMIT 200""")]
        if cards:
            labels = {
                f"#{row['id']} - {row.get('display_name') or category_label(row.get('primary_category'), language)}": row["id"]
                for row in cards
            }
            selected = st.selectbox(tr("operations_export_card", language), list(labels))
            if st.button(tr("operations_export_button", language), type="primary"):
                from cti_export import write_stix_bundle
                path = write_stix_bundle(int(labels[selected]))
                st.success(tr("operations_export_ready", language))
                st.download_button(
                    tr("operations_download", language), data=path.read_bytes(),
                    file_name=path.name, mime="application/json",
                )
        else:
            st.markdown(empty_state(tr("operations_no_cards", language)), unsafe_allow_html=True)

    with shadow_tab:
        _render_shadow(st, report, language)
