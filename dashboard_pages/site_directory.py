"""Compact Site summaries and read-only-first full-page details."""
from __future__ import annotations

import html
import re
import sqlite3
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import site_dedupe
import storage
import dashboard_auth
from log_redaction import redact_for_log
from report_builder import build_site_card_report, neutralize_report_embeds
from paths import REPORTS_DIR
from screenshot_service import screenshot_support_status
from dashboard_services.i18n import (category_description, category_family, category_label,
                                     category_reason_label, current_language, spain_reason_label,
                                     value_label)
from ui_components import (category_badge, data_row, importance_badge,
                           mask_onion_address, page_lead, parse_json, review_badge,
                           risk_badge, safe_display_title, safe_preview_path,
                           section_header, spain_flag_badge, status_badge)


RESTRICTED = {"adult_filtered", "adult_restricted", "severe_abuse_risk"}
_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]<>()#+\-.!|])")


def _can(st, capability: str) -> bool:
    from dashboard_pages.workspace import _can as workspace_can

    return workspace_can(st, capability)


def _authorize(st, capability: str) -> bool:
    from dashboard_pages.workspace import _authorize_action

    return _authorize_action(st, capability)


def _l(language: str, english: str, spanish: str) -> str:
    return spanish if language == "es" else english


def _markdown_text(value: object) -> str:
    """Return one-line external text that cannot alter a button's Markdown."""
    compact = " ".join(str(value or "").split())
    return _MARKDOWN_SPECIAL.sub(r"\\\1", compact)


def _markdown_code(value: object) -> str:
    """Keep normalized host-like values inside a single inline-code span."""
    return " ".join(str(value or "").split()).replace("`", "'")


def _concise_summary(value: object, fallback: str, width: int = 132) -> str:
    compact = " ".join(str(value or fallback).split())
    return textwrap.shorten(compact, width=max(40, width), placeholder="…")


def _display_timestamp(value: object) -> str:
    """Return a compact visible timestamp without changing stored evidence."""
    raw = str(value or "").strip()
    if not raw:
        return "—"
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return raw
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc)
        return parsed.strftime("%Y-%m-%d %H:%M UTC")
    return parsed.strftime("%Y-%m-%d %H:%M")


def _card_summary(card: dict, language: str) -> str:
    raw = str(card.get("safe_summary") or card.get("category_reason")
              or card.get("importance_reason") or "").strip()
    common = {
        "source_or_directory_value": (
            "Useful discovery or directory source.",
            "Fuente útil de descubrimiento o directorio.",
        ),
        "routine_monitoring": (
            "General site monitored for relevant changes.",
            "Sitio general monitorizado para detectar cambios relevantes.",
        ),
        "policy_risk_review": (
            "Risk context retained for controlled review.",
            "Contexto de riesgo conservado para revisión controlada.",
        ),
        "direct_fraud_page": (
            "Direct financial-fraud page structure detected.",
            "Se detectó una estructura directa de fraude financiero.",
        ),
    }
    if raw in common:
        raw = common[raw][1 if language == "es" else 0]
    elif raw:
        raw = category_reason_label(raw, language)
    return _concise_summary(
        raw,
        _l(language, "Passively classified site profile", "Perfil clasificado de forma pasiva"),
    )


def _name(card: dict, language: str) -> str:
    return safe_display_title(
        card.get("analyst_title"), card.get("display_name"),
        fallback=_l(language, "Unnamed site", "Sitio sin nombre"),
    )


def _host(card: dict, detail: dict | None = None) -> str:
    if card.get("representative_host"):
        return str(card["representative_host"])
    for value in (card.get("representative_url"), card.get("canonical_root")):
        try:
            host = urlsplit(str(value or "")).hostname
        except ValueError:
            host = None
        if host:
            return host
    for item in (detail or {}).get("urls", []):
        for value in (item.get("onion_host"), item.get("url"), item.get("canonical_url")):
            if str(value or "").endswith(".onion") and "://" not in str(value):
                return str(value)
            try:
                host = urlsplit(str(value or "")).hostname
            except ValueError:
                host = None
            if host:
                return host
    return str(card.get("canonical_site_id") or "Unknown onion host")


def _safe_evidence_codes(value) -> list[str]:
    parsed = parse_json(value)
    if isinstance(parsed, dict):
        parsed = [item for values in parsed.values() for item in (values or [])]
    return [str(item).replace("_", " ").title() for item in (parsed or [])][:30]


def open_card(card_id: int, review_only: bool) -> None:
    import streamlit as st
    from dashboard_pages.workspace import _open_workspace_page

    origin_page = str(st.session_state.get("nav_page") or "")
    if origin_page not in {
        "Home", "Add Onion", "Crawl Queue", "Site Cards", "Entity Intelligence",
        "Connections", "Timeline", "Actors", "Identity Signals", "Quality Center",
        "Watchlist", "Daily Activity", "Review Findings", "Reports",
        "Spain Priority", "Advanced", "Control Center", "Settings", "FAQ",
    }:
        origin_page = "Review Findings" if review_only else "Site Cards"
    if _can(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
        storage.acknowledge_spain_card_open(int(card_id))
    _open_workspace_page(origin_page)
    st.session_state["directory_origin_page"] = origin_page
    st.session_state["directory_selected_card"] = int(card_id)
    st.session_state["directory_selected_review_only"] = bool(review_only)
    st.session_state["directory_dialog_edit"] = False


def _close() -> None:
    import streamlit as st
    from dashboard_pages.workspace import _open_workspace_page

    origin_page = str(st.session_state.get("directory_origin_page") or "Site Cards")
    st.session_state.pop("directory_selected_card", None)
    st.session_state.pop("directory_selected_review_only", None)
    st.session_state.pop("directory_dialog_edit", None)
    st.session_state.pop("directory_origin_page", None)
    _open_workspace_page(origin_page)


def _report_label(state: str, language: str) -> str:
    labels = {
        "no_report": ("No report", "Sin informe"),
        "report_ready": ("Report ready", "Informe listo"),
        "report_stale": ("Report needs update", "Informe por actualizar"),
        "report_failed": ("Report failed", "Error de informe"),
    }
    pair = labels.get(state, labels["no_report"])
    return pair[1 if language == "es" else 0]


def _main_url(card: dict, urls: list[dict]) -> str:
    ranked = sorted(urls, key=lambda item: (
        0 if item.get("url_role") == "canonical" else 1,
        0 if str(item.get("path") or "/") == "/" else 1,
        str(item.get("first_seen") or ""),
    ))
    return str((ranked[0].get("url") if ranked else None) or card.get("representative_url") or
               _host(card, card))


def _safe_event_parts(raw: str | None) -> dict:
    data = parse_json(raw, {})
    return data if isinstance(data, dict) else {}


def _creation_reason(card: dict, urls: list[dict], language: str) -> str:
    reason = str(card.get("card_readiness_reason") or card.get("category_update_reason") or "").strip()
    if reason:
        return value_label(reason, language)
    hosts = {str(item.get("onion_host") or "") for item in urls if item.get("onion_host")}
    if len(hosts) <= 1:
        return _l(language, "Same onion host grouped into one Site Card.",
                  "Mismo host onion agrupado en una ficha.")
    return _l(language, "Multiple onion hosts are grouped by safe mirror signals.",
              "Varios hosts onion agrupados por senales seguras de espejo.")


def _render_source_trail(st, card: dict, urls: list[dict], language: str) -> None:
    st.markdown(section_header(
        _l(language, "Source trail", "Rastro de origen"),
        _l(
            language,
            "Plain-language view of why this card exists and what updated it. It uses stored metadata only.",
            "Vista simple de por que existe esta ficha y que la actualizo. Usa solo metadatos guardados.",
        ),
    ), unsafe_allow_html=True)
    source_count = int(card.get("source_count") or len(card.get("sources") or []))
    trail_cols = st.columns(3)
    trail_cols[0].markdown(data_row(
        _l(language, "Grouped because", "Agrupada por"),
        _creation_reason(card, urls, language),
    ), unsafe_allow_html=True)
    trail_cols[1].markdown(data_row(
        _l(language, "Discovery sources", "Origenes"),
        source_count,
    ), unsafe_allow_html=True)
    trail_cols[2].markdown(data_row(
        _l(language, "Activity entries", "Entradas"),
        len(card.get("events") or []),
    ), unsafe_allow_html=True)

    if card.get("spain_priority"):
        exact_spain_hit = next((hit for hit in card.get("spain_hits", [])
                                if hit.get("canonical_url")), None)
        st.info(_l(language, "Spain marker is attached to an exact stored page.",
                   "La marca de Espana esta ligada a una pagina exacta guardada."))
        if exact_spain_hit:
            st.link_button(_l(language, "Open exact marked page", "Abrir pagina marcada"),
                           exact_spain_hit["canonical_url"])

    sources = card.get("sources") or []
    events = card.get("events") or []
    if sources:
        with st.expander(_l(language, "Discovery path", "Ruta de descubrimiento"), expanded=True):
            for source in sources[:8]:
                st.code(source.get("source_url") or "", language=None)
                st.caption(
                    f"{value_label(source.get('source_type') or 'unknown', language)} · "
                    f"{_l(language, 'Seen', 'Visto')} {int(source.get('seen_count') or 0)} · "
                    f"{source.get('last_seen') or '—'}"
                )
    if events:
        with st.expander(_l(language, "Recent changes", "Cambios recientes"), expanded=True):
            for event in events[:8]:
                meta = _safe_event_parts(event.get("safe_metadata_json"))
                detail = meta.get("reason") or meta.get("url_role") or meta.get("classification") or ""
                st.markdown(f"**{html.escape(str(event.get('event_summary') or event.get('event_type') or 'Update'))}**")
                st.caption(f"{event.get('created_at') or '—'}{(' · ' + html.escape(str(detail))) if detail else ''}")
    if not sources and not events:
        st.info(_l(language, "No source trail entries are stored yet.",
                   "Aun no hay entradas de rastro de origen guardadas."))


def _safe_report_path(value: str | None) -> Path | None:
    try:
        path = Path(str(value or "")).resolve()
        root = Path(REPORTS_DIR).resolve()
        return path if path.is_file() and path.is_relative_to(root) else None
    except (OSError, ValueError):
        return None


def _cancel_edit(card: dict) -> None:
    """Reset the draft in a widget callback before the dialog reruns."""
    import streamlit as st
    card_id = int(card["id"])
    st.session_state[f"dialog-title-{card_id}"] = str(card.get("analyst_title") or "")
    st.session_state[f"dialog-category-{card_id}"] = card.get("primary_category") or "unknown"
    st.session_state[f"dialog-importance-{card_id}"] = (
        card.get("analyst_importance") or card.get("importance_level") or "normal")
    st.session_state[f"dialog-review-{card_id}"] = card.get("review_status") or "pending"
    st.session_state[f"dialog-notes-{card_id}"] = str(card.get("analyst_notes") or "")
    st.session_state[f"dialog-alerts-{card_id}"] = bool(card.get("analyst_suppressed_alerts"))
    st.session_state["directory_dialog_edit"] = False


def render_card(st, card: dict, *, review_only: bool = False,
                key_prefix: str = "directory-card") -> None:
    """Render a calm, scannable Site Card face as one reliable click target.

    Operational counts, timestamps, report state and policy explanations live
    on the detail page.  Keeping them off the face makes the directory useful
    at a glance without discarding any stored data.
    """
    language = current_language(st)
    name = _name(card, language)
    is_forum_case = str(card.get("card_kind") or "") == "forum_thread_case"
    host = _host(card)
    category = category_label(card.get("primary_category"), language)
    risk = value_label(card.get("risk_level") or "unknown", language)
    review = value_label(card.get("review_status") or "pending", language)
    live = bool(card.get("live_url_count"))
    status = value_label("live" if live else "dead", language)
    current = (_l(language, "Current", "Actual") if card.get("last_checked_at") else
               _l(language, "Awaiting first check", "Pendiente de primera comprobación"))
    summary_width = 104 if bool(st.session_state.get("compact_site_cards", True)) else 156
    reason = _concise_summary(
        _card_summary(card, language),
        _l(language, "Passively classified site profile", "Perfil clasificado de forma pasiva"),
        width=summary_width,
    )
    case_prefix = f"{_l(language, 'FORUM THREAD', 'HILO DE FORO')} · " if is_forum_case else ""
    spain_flag = "🇪🇸 " if card.get("spain_priority") else ""
    label = (
        f"{case_prefix}{spain_flag}**{_markdown_text(name)}**\n\n"
        f"`{_markdown_code(mask_onion_address(host))}`\n\n"
        f"{_markdown_text(category)} · {_l(language, 'Risk', 'Riesgo')} {risk} · "
        f"{_l(language, 'Review', 'Revisión')} {review}\n\n"
        f"{_markdown_text(reason)}\n\n"
        f"{status} · {current}\n\n"
        f"**{_l(language, 'Open details →', 'Abrir detalles →')}**"
    )
    risk_key = str(card.get("risk_level") or "unknown").casefold()
    spain_key = "spain-" if card.get("spain_priority") else ""
    case_key = "forum-case-" if is_forum_case else ""
    st.button(label, key=f"{key_prefix}-{case_key}{spain_key}{risk_key}-{review_only}-{card['id']}",
              on_click=open_card, args=(int(card["id"]), review_only), width="stretch",
              help=_l(
                  language,
                  "Open the complete Site Card" + (" · Spain-linked" if card.get("spain_priority") else ""),
                  "Abrir la ficha completa" + (" · Vinculada con España" if card.get("spain_priority") else ""),
              ))


def _safe_urls(card: dict) -> list[dict]:
    if card.get("primary_category") in RESTRICTED:
        return []
    return [item for item in card.get("urls", []) if item.get("primary_category") not in RESTRICTED]


def _badges(card: dict, language: str) -> str:
    live = any(item.get("active") and item.get("status") not in {"dead", "soft_dead"}
               for item in card.get("urls", []))
    result = (
        category_badge(str(card.get("primary_category") or "unknown"),
                       _l(language, "Category", "Categoría") + ": " + category_label(card.get("primary_category"), language)) + " " +
        risk_badge(card.get("risk_level"), _l(language, "Policy risk", "Riesgo de política") + ": " + value_label(card.get("risk_level"), language)) + " " +
        importance_badge(card.get("importance_level"),
                         _l(language, "Importance", "Importancia") + ": " +
                         value_label(card.get("importance_level") or "normal", language)) + " " +
        review_badge(card.get("review_status"), value_label(card.get("review_status"), language)) + " " +
        status_badge("live" if live else "dead", value_label("live" if live else "dead", language))
    )
    if card.get("spain_priority"):
        result += f' {spain_flag_badge(_l(language, "Spain-linked", "Vinculado con España"))}'
        result += ' <span class="badge badge-red">SPAIN PRIORITY</span>'
    return result


def _save_edit(st, card: dict, query) -> None:
    language = current_language(st)
    if not _authorize(st, dashboard_auth.CAPABILITY_SITE_CARDS_EDIT):
        return
    card_id = int(card["id"])
    analyst_title = st.session_state.get(f"dialog-title-{card_id}", card.get("analyst_title") or "")
    category = st.session_state.get(f"dialog-category-{card_id}", card.get("primary_category"))
    importance = st.session_state.get(f"dialog-importance-{card_id}", card.get("importance_level") or "normal")
    review = st.session_state.get(f"dialog-review-{card_id}", card.get("review_status"))
    notes = st.session_state.get(f"dialog-notes-{card_id}", card.get("analyst_notes") or "")
    suppressed = bool(st.session_state.get(f"dialog-alerts-{card_id}", card.get("analyst_suppressed_alerts")))
    try:
        if " ".join(str(analyst_title).split()).strip() != str(card.get("analyst_title") or ""):
            site_dedupe.apply_manual_title(card_id, analyst_title)
        if category != card.get("primary_category"):
            site_dedupe.apply_manual_category(card_id, category)
        review_action = {"relevant": "keep", "false_positive": "ignored", "needs_report": "needs_report",
                         "reported": "reported", "blocked": "blocked"}.get(review)
        if review != card.get("review_status") and review_action:
            site_dedupe.apply_card_review(card_id, review_action)
        site_dedupe.apply_manual_importance(card_id, importance, notes)
        if suppressed != bool(card.get("analyst_suppressed_alerts")):
            site_dedupe.set_card_alert_suppressed(card_id, suppressed)
    except sqlite3.OperationalError as exc:
        if "locked" in str(exc).casefold() or "busy" in str(exc).casefold():
            st.warning(_l(
                language,
                "Database is busy because the worker is writing. Wait a few seconds or pause the worker, then save again.",
                "La base de datos está ocupada porque el worker está escribiendo. Espera unos segundos o pausa el worker y vuelve a guardar.",
            ))
        else:
            st.error(_l(language, "Changes could not be saved: ", "No se pudieron guardar los cambios: ") +
                     redact_for_log(exc))
        return
    except ValueError as exc:
        st.error(str(exc))
        return
    query.clear()
    st.session_state["directory_dialog_edit"] = False
    st.toast(_l(language, "Site Card changes saved", "Cambios de la ficha guardados"))
    st.rerun()


def _create_report(st, card_id: int, query, language: str) -> None:
    """Generate the existing metadata-safe report from the open Site Card."""
    if not _authorize(st, dashboard_auth.CAPABILITY_REPORTS_CREATE):
        return
    try:
        build_site_card_report(card_id, generated_by="dashboard_analyst")
    except (OSError, ValueError, sqlite3.Error) as exc:
        try:
            storage.mark_site_card_report_failed(card_id, exc)
        except sqlite3.Error:
            pass
        st.error(_l(language, "Report could not be created: ", "No se pudo crear el informe: ") +
                 redact_for_log(exc))
        return
    query.clear()
    st.session_state["directory_report_notice"] = _l(
        language,
        "Report created. Open Reports to view the saved metadata-safe report.",
        "Informe creado. Abre Informes para ver el informe seguro guardado.",
    )
    st.rerun()


def _mark_adult_filtered(st, card_id: int, query, language: str) -> None:
    if not _authorize(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
        return
    try:
        removed = site_dedupe.mark_site_card_adult_filtered(card_id)
    except (sqlite3.Error, ValueError) as exc:
        st.error(_l(language, "Could not apply adult block: ", "No se pudo aplicar el bloqueo adulto: ") +
                 redact_for_log(exc))
        return
    query.clear()
    st.session_state.pop("directory_selected_card", None)
    st.session_state.pop("directory_selected_review_only", None)
    st.session_state.pop("directory_dialog_edit", None)
    st.toast(_l(language,
                f"Adult filter applied. {removed} URL(s) retained only as blocked metadata.",
                f"Filtro adulto aplicado. {removed} URL(s) retenidas solo como metadatos bloqueados."))
    st.rerun()


def _adult_block_control(st, card: dict, query, language: str, *, key_prefix: str) -> None:
    if card.get("primary_category") in RESTRICTED or card.get("storage_policy") == "discard":
        return
    card_id = int(card["id"])
    can_review = _can(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE)
    with st.expander(_l(language, "Block confirmed adult content",
                        "Bloquear contenido adulto confirmado"),
                     expanded=False):
        st.warning(_l(language,
            "Use this only when this card itself is adult content that passed the automatic filter. It hides the card, removes previews/reports/alerts, and keeps only blocked anti-retry metadata.",
            "Usa esto solo cuando esta ficha sea contenido adulto que haya superado el filtro automático. Oculta la ficha, elimina vistas/informes/alertas y conserva solo metadatos bloqueados."))
        confirm = st.slider(
            _l(language, "Slide to confirm adult block", "Desliza para confirmar bloqueo adulto"),
            min_value=0, max_value=100, value=0, step=25,
            key=f"{key_prefix}-adult-confirm-{card_id}",
            help=_l(language, "The button unlocks only at 100.",
                    "El boton solo se desbloquea en 100."),
            disabled=not can_review,
        )
        st.button(
            _l(language, "Move to adult block list", "Mover a lista de bloqueo adulto"),
            key=f"{key_prefix}-adult-block-{card_id}", type="primary", width="stretch",
            disabled=confirm < 100 or not can_review,
            on_click=_mark_adult_filtered, args=(st, card_id, query, language),
        )


def _render_analyst_fields(st, card: dict, query, language: str) -> None:
    card_id = int(card["id"])
    editing = bool(st.session_state.get("directory_dialog_edit"))
    can_edit = _can(st, dashboard_auth.CAPABILITY_SITE_CARDS_EDIT)
    st.markdown(section_header(
        _l(language, "Your review fields", "Tus campos de revisión"),
        _l(
            language,
            "These fields improve your workspace label and review order. They never change crawler signals or policy risk.",
            "Estos campos mejoran la etiqueta y el orden de revisión. Nunca cambian las señales ni el riesgo.",
        ),
    ), unsafe_allow_html=True)
    if not editing:
        st.write("**" + _l(language, "Reviewer title", "Título de revisión") + ":** " +
                 str(card.get("analyst_title") or _l(language, "Using generated title", "Usando título generado")))
        st.write("**" + _l(language, "Review importance", "Importancia de revisión") + ":** " +
                 value_label(card.get("importance_level") or "normal", language))
        st.write("**" + _l(language, "Review status", "Estado de revisión") + ":** " +
                 value_label(card.get("review_status") or "pending", language))
        st.write(card.get("analyst_notes") or _l(language, "No reviewer notes.", "Sin notas de revisión."))
        if st.button(_l(language, "Edit review fields", "Editar campos de revisión"),
                     key=f"card-tab-edit-{card_id}", type="primary",
                     disabled=not can_edit):
            st.session_state["directory_dialog_edit"] = True; st.rerun()
        return

    restricted = card.get("primary_category") in RESTRICTED
    categories = site_dedupe.ANALYST_CATEGORY_OPTIONS
    current_category = card.get("primary_category") or "unknown"
    st.text_input(_l(language, "Reviewer title", "Título de revisión"),
                  value=str(card.get("analyst_title") or ""), max_chars=180,
                  key=f"dialog-title-{card_id}", placeholder=str(card.get("display_name") or ""),
                  disabled=not can_edit)
    if card.get("analyst_title") and st.button(_l(language, "Reset to generated name", "Restaurar nombre generado"),
                                               key=f"card-reset-title-{card_id}",
                                               disabled=not can_edit) and _authorize(
                                                   st, dashboard_auth.CAPABILITY_SITE_CARDS_EDIT):
        site_dedupe.apply_manual_title(card_id, ""); st.rerun()
    selected_category = st.selectbox(_l(language, "Manual category override", "Categoría corregida"), categories,
        index=categories.index(current_category) if current_category in categories else 0,
        disabled=restricted or not can_edit, key=f"dialog-category-{card_id}",
        format_func=lambda value: f"{category_family(value, language)} — {category_label(value, language)}")
    st.caption(category_description(selected_category, language))
    importance_values = ["low", "normal", "elevated", "high", "critical"]
    current_importance = card.get("analyst_importance") or card.get("importance_level") or "normal"
    st.selectbox(_l(language, "Review importance", "Importancia de revisión"), importance_values,
                 index=importance_values.index(current_importance), key=f"dialog-importance-{card_id}",
                 format_func=lambda value: value_label(value, language), disabled=not can_edit)
    review_values = list(dict.fromkeys([card.get("review_status") or "pending", "relevant",
                                        "false_positive", "needs_report", "reported", "blocked"]))
    st.selectbox(_l(language, "Review status", "Estado de revisión"), review_values,
                 index=0, key=f"dialog-review-{card_id}", format_func=lambda value: value_label(value, language),
                 disabled=not can_edit)
    st.text_area(_l(language, "Reviewer notes", "Notas de revisión"), value=str(card.get("analyst_notes") or ""),
                 key=f"dialog-notes-{card_id}", disabled=not can_edit)
    st.checkbox(_l(language, "Suppress duplicate alerts", "Silenciar alertas duplicadas"),
                value=bool(card.get("analyst_suppressed_alerts")), key=f"dialog-alerts-{card_id}",
                disabled=not can_edit)
    save, cancel = st.columns(2)
    if save.button(_l(language, "Save changes", "Guardar cambios"), type="primary",
                   key=f"card-save-fields-{card_id}", width="stretch", disabled=not can_edit):
        _save_edit(st, card, query)
    cancel.button(_l(language, "Cancel edit", "Cancelar edición"),
                  key=f"card-cancel-fields-{card_id}", width="stretch",
                  on_click=_cancel_edit, args=(card,))


def render_selected_page(st, query) -> None:
    """Render a full-width Site Card workspace."""
    card_id = st.session_state.get("directory_selected_card")
    if not card_id:
        return
    if _can(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
        storage.acknowledge_spain_card_open(int(card_id))
    card = site_dedupe.get_site_card_detail(int(card_id), url_limit=300, event_limit=75,
                                            include_dead=True, include_restricted=False)
    if not card:
        _close(); st.rerun(); return
    language = current_language(st)
    can_edit = _can(st, dashboard_auth.CAPABILITY_SITE_CARDS_EDIT)
    can_recheck = _can(st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE)
    can_report = _can(st, dashboard_auth.CAPABILITY_REPORTS_CREATE)
    urls = _safe_urls(card)
    main_url = _main_url(card, urls)
    title = _name(card, language)
    generated_title = str(card.get("display_name") or _l(language, "Not available", "No disponible"))
    summary = card.get("safe_summary") or card.get("category_reason") or _l(
        language, "Grouped site profile built from safely stored metadata.",
        "Perfil agrupado del sitio creado con metadatos guardados de forma segura.")
    report_state = str(card.get("report_state") or "no_report")
    report_notice = st.session_state.pop("directory_report_notice", None)
    if report_notice:
        st.success(report_notice)

    origin_page = str(st.session_state.get("directory_origin_page") or "Site Cards")
    origin_labels = {
        "Spain Priority": ("Spain", "España"),
        "Review Findings": ("Review Inbox", "Bandeja de revisión"),
        "Quality Center": ("Quality Center", "Centro de calidad"),
        "Connections": ("Connections", "Conexiones"),
        "Timeline": ("Timeline", "Cronología"),
        "Home": ("Overview", "Resumen"),
    }
    origin_pair = origin_labels.get(origin_page, ("Sites", "Sitios"))
    back_label = f"← {_l(language, 'Back to ' + origin_pair[0], 'Volver a ' + origin_pair[1])}"
    with st.container(key=f"rt-dossier-head-{card_id}"):
        top = st.columns([1.15, 5], gap="medium")
        top[0].button(back_label,
                      key=f"card-page-back-{card_id}", width="stretch", on_click=_close)
        with top[1]:
            st.markdown(page_lead(
                title,
                _concise_summary(
                    summary,
                    _l(language, "Grouped site profile built from safely stored metadata.",
                       "Perfil agrupado del sitio creado con metadatos guardados de forma segura."),
                    width=180,
                ),
                eyebrow=_l(language, "Site dossier", "Ficha del sitio"),
                aside=mask_onion_address(_host(card, card)),
            ), unsafe_allow_html=True)
            if str(card.get("card_kind") or "") == "forum_thread_case":
                parent = card.get("parent_site_card_id")
                parent_text = f" · Parent forum card #{int(parent)}" if parent else ""
                st.caption(_l(language, "Forum thread", "Hilo de foro") + parent_text)
            if card.get("analyst_title"):
                st.caption(_l(language, "Generated title: ", "Título generado: ") + generated_title)
            else:
                st.caption(_l(language, "System-generated site name", "Nombre de sitio generado por el sistema"))
        st.markdown(_badges(card, language) +
                    f' <span class="badge badge-blue">{html.escape(_report_label(report_state, language))}</span>',
                    unsafe_allow_html=True)

        address, dossier_state = st.columns([3.4, 1.35], gap="large")
        with address:
            st.caption(_l(language, "Primary onion address", "Dirección onion principal"))
            st.code(main_url, language=None)
        with dossier_state:
            st.markdown(data_row(
                _l(language, "Completeness", "Completitud"),
                value_label(card.get("card_completeness_label") or "weak", language),
            ), unsafe_allow_html=True)
            st.markdown(data_row(
                _l(language, "Report", "Informe"),
                _report_label(report_state, language),
            ), unsafe_allow_html=True)

    with st.container(key=f"rt-dossier-actions-{card_id}"):
        st.markdown(section_header(
            _l(language, "Card actions", "Acciones de la ficha"),
            _l(
                language,
                "Review the record, request a fresh check, or build a report from stored metadata.",
                "Revisa el registro, solicita una nueva comprobación o crea un informe con metadatos guardados.",
            ),
        ), unsafe_allow_html=True)
        actions = st.columns([1.45, 1, 1.15, .75], gap="small")
        if actions[0].button(_l(language, "Edit review fields", "Editar campos de revisión"), type="primary",
                             key=f"card-page-edit-{card_id}", width="stretch",
                             disabled=not can_edit):
            st.session_state["directory_dialog_edit"] = True
            st.rerun()
        can_recheck_card = any(item.get("queue_policy") != "blocked" and item.get("storage_policy") != "metadata_only"
                               for item in urls)
        if actions[1].button(_l(language, "Re-check", "Volver a comprobar"),
                             key=f"card-page-recheck-{card_id}",
                             disabled=not can_recheck_card or not can_recheck,
                             width="stretch") and _authorize(
                                 st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
            site_dedupe.apply_card_review(int(card_id), "live_check")
            query.clear(); st.toast(_l(language, "Site queued for re-check", "Sitio añadido para comprobar"))
        report_action = "Create report" if report_state == "no_report" else "Rebuild report"
        report_action_es = "Crear informe" if report_state == "no_report" else "Actualizar informe"
        if actions[2].button(_l(language, report_action, report_action_es),
                             key=f"card-page-report-{card_id}", width="stretch",
                             disabled=not can_report):
            _create_report(st, int(card_id), query, language)
        actions[3].button(_l(language, "Close", "Cerrar"),
                          key=f"card-page-close-{card_id}", width="stretch", on_click=_close)

    if st.session_state.get("directory_dialog_edit"):
        with st.container(border=True):
            _render_analyst_fields(st, card, query, language)

    overview, pages_tab, review_tab, discovery_tab, technical = st.tabs([
        _l(language, "Overview", "Resumen"),
        _l(language, "Pages & previews", "Páginas y vistas"),
        _l(language, "Review & classification", "Revisión y clasificación"),
        _l(language, "Discovery & reports", "Descubrimiento e informes"),
        _l(language, "Activity & technical", "Actividad y técnico"),
    ])
    # Several sections intentionally share a tab.  Keeping the aliases makes
    # each section small and testable while presenting a five-part workspace.
    preview_tab = links_tab = pages_tab
    analyst = classification = review_tab
    sources_tab = reports_tab = discovery_tab

    with overview:
        st.markdown(section_header(
            _l(language, "Dossier overview", "Resumen de la ficha"),
            _l(
                language,
                "Identity, classification, availability, and review state at a glance.",
                "Identidad, clasificación, disponibilidad y estado de revisión de un vistazo.",
            ),
        ), unsafe_allow_html=True)
        snapshot = st.columns(4)
        snapshot_values = [
            (_l(language, "First seen", "Primera vez"), _display_timestamp(card.get("first_seen"))),
            (_l(language, "Last checked", "Última revisión"), _display_timestamp(card.get("last_checked_at"))),
            (_l(language, "Known pages", "Páginas conocidas"), len(urls)),
            (_l(language, "Discovery sources", "Fuentes de descubrimiento"),
             int(card.get("source_count") or len(card.get("sources") or []))),
        ]
        for column, (label, value) in zip(snapshot, snapshot_values, strict=False):
            column.markdown(data_row(label, value), unsafe_allow_html=True)
        left, right = st.columns([1.65, 1], gap="large")
        with left:
            st.markdown(section_header(
                _l(language, "What this site is", "Qué es este sitio"),
                _l(
                    language,
                    "The best current interpretation from safely stored evidence.",
                    "La mejor interpretación actual a partir de evidencia guardada de forma segura.",
                ),
            ), unsafe_allow_html=True)
            st.write(summary)
            st.markdown(data_row(
                _l(language, "Category", "Categoría"),
                category_label(card.get("primary_category"), language),
            ), unsafe_allow_html=True)
            st.markdown(data_row(
                _l(language, "Page structure", "Estructura"),
                value_label(card.get("page_type"), language),
            ), unsafe_allow_html=True)
            st.markdown(data_row(
                _l(language, "Review status", "Estado de revisión"),
                value_label(card.get("review_status"), language),
            ), unsafe_allow_html=True)
            if card.get("spain_priority"):
                st.warning(spain_reason_label(card.get("spain_match_reason"), language))
                exact_spain_hit = next((hit for hit in card.get("spain_hits", [])
                                        if hit.get("canonical_url")), None)
                if exact_spain_hit:
                    st.link_button(_l(language, "Open exact Spain-flagged page",
                                      "Abrir página exacta marcada para España"),
                                   exact_spain_hit["canonical_url"], type="primary")
        with right:
            st.markdown(section_header(
                _l(language, "Stored safely", "Guardado de forma segura"),
                _l(
                    language,
                    "Opening this dossier does not contact the onion site.",
                    "Abrir esta ficha no contacta con el sitio onion.",
                ),
            ), unsafe_allow_html=True)
            st.write(_l(language,
                "This view uses stored metadata only. Opening it does not contact the onion site.",
                "Esta vista usa solo metadatos guardados. Abrirla no contacta con el sitio onion."))
            st.markdown(data_row(
                _l(language, "Live pages", "Páginas activas"),
                int(card.get("live_url_count") or 0),
                state="ok" if int(card.get("live_url_count") or 0) else "muted",
            ), unsafe_allow_html=True)
            st.markdown(data_row(
                _l(language, "Unavailable pages", "Páginas no disponibles"),
                int(card.get("dead_url_count") or 0),
                state="warn" if int(card.get("dead_url_count") or 0) else "muted",
            ), unsafe_allow_html=True)
            restricted_count = int(card.get("restricted_outbound_count") or 0)
            if restricted_count:
                st.info(_l(language, f"Restricted child links hidden: {restricted_count}",
                           f"Enlaces secundarios restringidos ocultos: {restricted_count}"))
                st.caption(_l(language,
                    "Parent directory preserved; unsafe child links were filtered individually.",
                    "El directorio principal se conservó; los enlaces secundarios no seguros se filtraron individualmente."))
    with preview_tab:
        st.markdown(section_header(
            _l(language, "Stored front-page preview", "Vista guardada de la portada"),
            _l(
                language,
                "A small representative gallery is shown here; page-by-page controls are below.",
                "Aquí se muestra una pequeña galería representativa; los controles por página están debajo.",
            ),
        ), unsafe_allow_html=True)
        if card.get("storage_policy") in {"metadata_only", "discard"}:
            st.warning(_l(language, "Preview blocked by the safety policy.",
                          "La política de seguridad bloquea esta vista previa."))
        else:
            preview_records = []
            blocked_reasons = []
            ordered_for_preview = sorted(
                urls,
                key=lambda row: (0 if row.get("url") == main_url else 1,
                                 0 if row.get("url_role") == "canonical" else 1,
                                 str(row.get("path") or "/")),
            )
            for item in ordered_for_preview[:24]:
                preview = storage.get_page_preview(item.get("url") or "")
                path = safe_preview_path(preview.get("preview_path") if preview else None)
                if path:
                    preview_records.append((item, preview or {}, path))
                    if len(preview_records) >= 4:
                        break
                elif item.get("screenshot_blocked_reason"):
                    blocked_reasons.append(str(item.get("screenshot_blocked_reason")))
            if preview_records:
                gallery = st.columns(2)
                for index, (item, preview, path) in enumerate(preview_records):
                    with gallery[index % 2]:
                        role = (_l(language, "Representative front page", "Portada representativa")
                                if item.get("url") == main_url else
                                value_label(item.get("url_role") or "page", language))
                        st.markdown(f"**{html.escape(role)}**")
                        preview_url = str(item.get("url") or "")
                        try:
                            path_label = urlsplit(preview_url).path or "/"
                        except ValueError:
                            path_label = "/"
                        caption = f"{mask_onion_address(_host(card, card))}{path_label}"
                        if preview.get("status") == "available_ocr_unchecked":
                            st.warning(_l(
                                language,
                                "OCR was unavailable or not checked for this stored preview.",
                                "El OCR no estaba disponible o no se verificó para esta vista guardada.",
                            ))
                            if st.checkbox(
                                _l(language, "Reveal this unchecked preview", "Mostrar esta vista sin verificar"),
                                key=f"reveal-ocr-unchecked-{item.get('id')}",
                            ):
                                st.image(str(path), caption=caption, width="stretch")
                        else:
                            st.image(str(path), caption=caption, width="stretch")
                if len(preview_records) == 4:
                    st.caption(_l(
                        language,
                        "Showing up to four representative stored previews.",
                        "Se muestran hasta cuatro vistas guardadas representativas.",
                    ))
            else:
                available, reason = screenshot_support_status()
                if blocked_reasons:
                    st.warning(_l(language, "No preview is allowed for this page: ",
                                  "No se permite vista previa para esta página: ") + blocked_reasons[0])
                elif available:
                    states = [storage.get_page_preview_state(item.get("url") or "") for item in urls[:5]]
                    active_states = [state for state in states if state]
                    state_labels = [state.get("job_status") or state.get("preview_status") for state in active_states
                                    if state.get("job_status") or state.get("preview_status")]
                    if state_labels:
                        st.info(_l(language,
                            f"Preview state: {', '.join(dict.fromkeys(state_labels))}. The worker will create or retry it.",
                            f"Estado de vista previa: {', '.join(dict.fromkeys(state_labels))}. El worker la creará o reintentará."))
                    else:
                        st.info(_l(language, "Preview not captured yet. Capture preview now.",
                                   "Vista previa no capturada. Captúrala ahora."))
                    if st.button(_l(language, "Capture preview now", "Capturar vista previa ahora"),
                                 key=f"detail-capture-preview-{card_id}",
                                 disabled=not can_recheck) and _authorize(
                                     st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
                        result = storage.queue_preview_for_site_card(int(card_id), force=False)
                        st.success(_l(language, f"Preview request: {result.get('status')}",
                                      f"Solicitud de vista previa: {result.get('status')}"))
                        st.rerun()
                    if any((state.get("preview_status") in {"failed", "missing_file"}
                            or state.get("job_status") in {"failed", "retry"})
                           for state in active_states):
                        if st.button(_l(language, "Force recapture", "Forzar nueva captura"),
                                     key=f"detail-force-preview-{card_id}",
                                     disabled=not can_recheck) and _authorize(
                                         st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
                            result = storage.queue_preview_for_site_card(int(card_id), force=True)
                            st.success(_l(language, f"Preview request: {result.get('status')}",
                                          f"Solicitud de vista previa: {result.get('status')}"))
                            st.rerun()
                else:
                    st.info(_l(language, "Preview service unavailable: ", "Servicio de vistas no disponible: ") + reason)

    with analyst:
        if not st.session_state.get("directory_dialog_edit"):
            _render_analyst_fields(st, card, query, language)
        _adult_block_control(st, card, query, language, key_prefix="card-page")

    with links_tab:
        st.markdown(section_header(
            _l(language, "Pages grouped into this site", "Páginas agrupadas en este sitio"),
            _l(
                language,
                "The primary onion is shown first. Restricted child URLs remain hidden.",
                "La onion principal aparece primero. Las URLs secundarias restringidas permanecen ocultas.",
            ),
            count=len(urls),
        ), unsafe_allow_html=True)
        if not urls:
            st.info(_l(language, "No policy-visible URLs are available.", "No hay URLs visibles según la política."))
        ordered_urls = sorted(urls, key=lambda row: (0 if row.get("url") == main_url else 1,
                                                     str(row.get("path") or "/")))
        page_size = 15
        page_count = max(1, (len(ordered_urls) + page_size - 1) // page_size)
        page_key = f"detail-url-page-{card_id}"
        selected_page = int(st.session_state.get(page_key, 1) or 1)
        selected_page = min(max(selected_page, 1), page_count)
        if page_count > 1:
            selected_page = st.selectbox(
                _l(language, "Page group", "Grupo de páginas"),
                list(range(1, page_count + 1)),
                index=selected_page - 1,
                format_func=lambda value: _l(
                    language, f"Page {value} of {page_count}", f"Página {value} de {page_count}"),
                key=page_key,
            )
        start = (selected_page - 1) * page_size
        visible_urls = ordered_urls[start:start + page_size]
        if ordered_urls:
            st.caption(_l(
                language,
                f"Showing {start + 1}–{start + len(visible_urls)} of {len(ordered_urls)} policy-visible pages.",
                f"Mostrando {start + 1}–{start + len(visible_urls)} de {len(ordered_urls)} páginas visibles.",
            ))
        for index, item in enumerate(visible_urls):
            row = st.columns([5, 1.4])
            with row[0]:
                label = (_l(language, "Primary onion", "Onion principal")
                         if item.get("url") == main_url else
                         value_label(item.get("url_role") or "path", language))
                st.markdown(
                    f"**{html.escape(label)}** · "
                    f"{html.escape(value_label(item.get('status') or 'unknown', language))} · "
                    f"{html.escape(value_label(item.get('page_type') or 'unknown', language))}"
                )
                st.code(item.get("url") or "", language=None)
                st.caption(
                    f"{_l(language, 'First seen', 'Primera vez')}: {_display_timestamp(item.get('first_seen'))} · "
                    f"{_l(language, 'Last checked', 'Última revisión')}: {_display_timestamp(item.get('last_checked_at'))}"
                )
            with row[1]:
                if item.get("status") == "crawled" and item.get("screenshot_policy") == "allowed":
                    if st.button(
                        _l(language, "Queue preview", "Encolar vista"),
                        key=f"detail-url-preview-{item.get('id')}",
                        width="stretch",
                        disabled=not can_recheck,
                    ) and _authorize(st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
                        job_id = storage.create_page_preview_job(
                            item.get("url") or "", onion_url_id=item.get("id"), site_card_id=int(card_id),
                            force=True, priority="manual", requested_by="dashboard",
                            request_reason="manual_url_preview")
                        st.success(_l(language, f"Preview job queued: {job_id}",
                                      f"Trabajo de vista previa encolado: {job_id}"))
                        st.rerun()
                else:
                    st.caption(_l(language, "Preview unavailable", "Vista no disponible"))
            if index < len(visible_urls) - 1:
                st.divider()

    with sources_tab:
        _render_source_trail(st, card, urls, language)
        st.divider()
        st.markdown(section_header(
            _l(language, "How this site was found", "Cómo se encontró este sitio"),
            _l(
                language,
                "Stored discovery sources are shown separately from classification evidence.",
                "Las fuentes de descubrimiento guardadas se muestran separadas de la evidencia de clasificación.",
            ),
            count=len(card.get("sources") or []),
        ), unsafe_allow_html=True)
        sources = card.get("sources") or []
        if not sources:
            st.info(_l(language, "No separate discovery source was stored.", "No se guardó un origen de descubrimiento separado."))
        source_size = 12
        source_page_count = max(1, (len(sources) + source_size - 1) // source_size)
        source_key = f"detail-source-page-{card_id}"
        source_page = min(max(int(st.session_state.get(source_key, 1) or 1), 1), source_page_count)
        if source_page_count > 1:
            source_page = st.selectbox(
                _l(language, "Discovery source group", "Grupo de fuentes"),
                list(range(1, source_page_count + 1)),
                index=source_page - 1,
                format_func=lambda value: _l(
                    language,
                    f"Sources {value} of {source_page_count}",
                    f"Fuentes {value} de {source_page_count}",
                ),
                key=source_key,
            )
        source_start = (source_page - 1) * source_size
        visible_sources = sources[source_start:source_start + source_size]
        for index, source in enumerate(visible_sources):
            st.code(source.get("source_url") or "", language=None)
            st.caption(f"{value_label(source.get('source_type') or 'unknown', language)} · "
                       f"{_l(language, 'Seen', 'Visto')} {int(source.get('seen_count') or 0)} · "
                       f"{_display_timestamp(source.get('last_seen'))}")
            if index < len(visible_sources) - 1:
                st.divider()

    with classification:
        st.divider()
        st.markdown(section_header(
            _l(language, "Classification explained", "Clasificación explicada"),
            _l(
                language,
                "Final labels, confidence, and the evidence that did or did not support the rollup.",
                "Etiquetas finales, confianza y evidencia que respaldó o contradijo la agrupación.",
            ),
        ), unsafe_allow_html=True)
        fields = [
            (_l(language, "Final content category", "Categoría final de contenido"), category_label(card.get("primary_category"), language)),
            (_l(language, "Generated category", "Categoría generada"), category_label(card.get("suggested_category") or card.get("primary_category"), language)),
            (_l(language, "Final page type", "Tipo final de página"), value_label(card.get("page_type"), language)),
            (_l(language, "Confidence", "Confianza"), value_label(card.get("category_confidence") or card.get("confidence"), language)),
            (_l(language, "Policy risk", "Riesgo"), value_label(card.get("risk_level"), language)),
            (_l(language, "Safety state", "Estado de seguridad"), value_label(card.get("safety_state"), language)),
            (_l(language, "Why a card was created", "Por qué se creó la ficha"), value_label(card.get("card_readiness_reason"), language)),
        ]
        for label, value in fields:
            st.markdown(data_row(label, value or "—"), unsafe_allow_html=True)
        supporting = _safe_evidence_codes(card.get("category_supporting_evidence_json"))
        contradicting = _safe_evidence_codes(card.get("category_contradicting_evidence_json"))
        with st.expander(_l(language, "Why the classifier chose this", "Por qué eligió esto el clasificador")):
            evidence_columns = st.columns(2, gap="large")
            evidence_columns[0].markdown(data_row(
                _l(language, "Supporting signals", "Señales favorables"),
                " · ".join(supporting) if supporting else "—",
                state="ok" if supporting else "muted",
            ), unsafe_allow_html=True)
            evidence_columns[1].markdown(data_row(
                _l(language, "Contradicting signals", "Señales contradictorias"),
                " · ".join(contradicting) if contradicting else "—",
                state="warn" if contradicting else "muted",
            ), unsafe_allow_html=True)
            st.markdown(data_row(
                _l(language, "Site Card category update", "Actualización de categoría de la ficha"),
                (_l(language, "Allowed", "Permitida") if card.get("category_update_allowed")
                 else _l(language, "Not allowed", "No permitida")),
                state="ok" if card.get("category_update_allowed") else "muted",
            ), unsafe_allow_html=True)
            st.caption(value_label(card.get("category_update_reason") or "legacy_unknown", language))
        identity_items = [
            (_l(language, "Domain", "Dominio"), card.get("identity_domain")),
            (_l(language, "Brand", "Marca"), card.get("identity_brand")),
            (_l(language, "Country", "País"), card.get("identity_country")),
            (_l(language, "Language", "Idioma"), card.get("identity_language")),
            (_l(language, "Matched from", "Coincidencia por"), card.get("identity_matched_from")),
            (_l(language, "Identity confidence", "Confianza de identidad"),
             f"{float(card.get('identity_confidence_score') or 0):.0%}"
             if card.get("identity_confidence_score") is not None else None),
        ]
        if any(value not in (None, "") for _label, value in identity_items):
            with st.expander(_l(language, "Site identity evidence", "Evidencia de identidad del sitio")):
                for label, value in identity_items:
                    if value not in (None, ""):
                        st.markdown(data_row(label, value), unsafe_allow_html=True)
                if card.get("identity_ambiguous"):
                    st.warning(card.get("identity_ambiguity_reason") or _l(
                        language, "Identity evidence is ambiguous.", "La evidencia de identidad es ambigua."))
                missing = parse_json(card.get("identity_missing_fields_json"), [])
                if missing:
                    st.caption(_l(language, "Still missing: ", "Aún falta: ") +
                               ", ".join(str(item) for item in missing))

    with reports_tab:
        st.divider()
        st.markdown(section_header(
            _l(language, "Metadata-safe reports", "Informes seguros de metadatos"),
            _l(
                language,
                "Create and review reports from facts already stored in this dossier.",
                "Crea y revisa informes con datos ya guardados en esta ficha.",
            ),
            count=len(card.get("reports") or []),
        ), unsafe_allow_html=True)
        st.info(_l(language, _report_label(report_state, language), _report_label(report_state, language)))
        st.caption(_l(language,
            "Reports use already stored safe facts. They do not fetch the onion site and never include restricted content.",
            "Los informes usan datos seguros ya guardados. No contactan con el sitio onion ni incluyen contenido restringido."))
        if report_state in {"no_report", "report_stale", "report_failed"}:
            label = _l(language, "Create report" if report_state == "no_report" else "Rebuild report",
                       "Crear informe" if report_state == "no_report" else "Actualizar informe")
            if st.button(label, key=f"report-tab-build-{card_id}", type="primary",
                         disabled=not can_report):
                _create_report(st, int(card_id), query, language)
        report_rows = card.get("reports") or []
        if report_rows:
            latest = report_rows[0]
            report_path = _safe_report_path(latest.get("output_path"))
            st.write(f"**{_l(language, 'Latest report', 'Último informe')}:** "
                     f"{_display_timestamp(latest.get('ts'))}")
            if report_path:
                st.download_button(_l(language, "Download latest report", "Descargar Último informe"),
                                   data=report_path.read_bytes(), file_name=report_path.name,
                                   mime="text/markdown", key=f"report-download-{card_id}")
                with st.expander(_l(language, "Read report here (optional)", "Leer informe aqué (opcional)")):
                    st.markdown(neutralize_report_embeds(
                        report_path.read_text(encoding="utf-8", errors="replace")))
            with st.expander(_l(language, "Previous report versions", "Versiones anteriores")):
                for report in report_rows:
                    st.caption(f"{_display_timestamp(report.get('ts'))} · "
                               f"{Path(str(report.get('output_path') or '')).name} · "
                               f"{report.get('status') or 'generated'}")

    with technical:
        st.markdown(section_header(
            _l(language, "Activity and technical data", "Actividad y datos técnicos"),
            _l(
                language,
                "Optional debugging information for advanced review.",
                "Información de depuración opcional para revisiones avanzadas.",
            ),
        ), unsafe_allow_html=True)
        with st.expander(_l(language, "Identity and classifier data", "Identidad y clasificador")):
            st.json({
                "site_card_id": card.get("id"), "canonical_site_id": card.get("canonical_site_id"),
                "generated_title": card.get("display_name"), "analyst_title": card.get("analyst_title"),
                "title_source": card.get("title_source"),
                "identity_confidence": card.get("identity_confidence"),
                "identity": {
                    "site_id": card.get("identity_site_id"),
                    "domain": card.get("identity_domain"),
                    "canonical_domain": card.get("identity_canonical_domain"),
                    "brand": card.get("identity_brand"),
                    "country": card.get("identity_country"),
                    "language": card.get("identity_language"),
                    "source_type": card.get("identity_source_type"),
                    "matched_from": card.get("identity_matched_from"),
                    "confidence": card.get("identity_confidence_score"),
                    "evidence": parse_json(card.get("identity_evidence_json"), []),
                    "ambiguous": bool(card.get("identity_ambiguous")),
                    "ambiguity_reason": card.get("identity_ambiguity_reason"),
                },
                "content_category": card.get("content_category"),
                "page_type": card.get("page_type"),
                "page_type_confidence": card.get("page_type_confidence"),
                "safety_state": card.get("safety_state"),
                "category_confidence": card.get("category_confidence"),
                "category_update_allowed": card.get("category_update_allowed"),
                "category_update_reason": card.get("category_update_reason"),
                "category_evidence": parse_json(card.get("category_evidence_json"), {}),
                "card_readiness_reason": card.get("card_readiness_reason"),
                "link_repository_score": card.get("link_repository_score"),
                "outbound_onion_count": card.get("outbound_onion_count"),
                "internal_link_count": card.get("internal_link_count"),
                "external_onion_count": card.get("external_onion_count"),
                "storage_policy": card.get("storage_policy"),
                "classification_decision": card.get("classification_decision"),
                "duplicate_candidates": card.get("duplicate_candidate_count"),
                "child_adult_link_count": card.get("child_adult_link_count"),
                "child_restricted_link_count": card.get("child_restricted_link_count"),
                "child_blocked_link_count": card.get("child_blocked_link_count"),
                "parent_evidence": parse_json(card.get("parent_evidence_json"), {}),
                "child_link_evidence": parse_json(card.get("child_link_evidence_json"), {}),
                "marketplace_type": card.get("marketplace_type"),
                "mirror_count": card.get("mirror_count"),
                "source_count": card.get("source_count"),
                "last_seen": card.get("last_seen"),
                "last_checked_at": card.get("last_checked_at"),
            })
        with st.expander(_l(language, "Safe fingerprints", "Huellas seguras")):
            st.json(card.get("fingerprints") or [])
        with st.expander(_l(language, "Activity log", "Registro de actividad")):
            events = card.get("events") or []
            event_size = 20
            event_page_count = max(1, (len(events) + event_size - 1) // event_size)
            event_key = f"detail-event-page-{card_id}"
            event_page = min(max(int(st.session_state.get(event_key, 1) or 1), 1), event_page_count)
            if event_page_count > 1:
                event_page = st.selectbox(
                    _l(language, "Activity group", "Grupo de actividad"),
                    list(range(1, event_page_count + 1)),
                    index=event_page - 1,
                    format_func=lambda value: _l(
                        language,
                        f"Activity {value} of {event_page_count}",
                        f"Actividad {value} de {event_page_count}",
                    ),
                    key=event_key,
                )
            event_start = (event_page - 1) * event_size
            for event in events[event_start:event_start + event_size]:
                st.caption(f"{event.get('created_at') or ''} · {event.get('event_summary') or ''}")
