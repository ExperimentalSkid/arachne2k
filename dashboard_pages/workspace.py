"""Self-explanatory Streamlit cockpit for passive OSINT review.

Importing this module performs no GUI, crawler, or network activity.
"""
from __future__ import annotations

import html
import base64
import json
import logging
import os
import shutil
import socket
import sqlite3
import subprocess
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import storage
import site_dedupe
import backup_service
import dashboard_auth
from config_loader import (effective_config_value, get_bool, get_int, get_str, runtime_setting_source,
                           save_runtime_settings)
from passive_attribution import build_attribution_profile
from paths import BASE_DIR, REPORTS_DIR
from log_redaction import redact_for_log
from report_builder import build_cluster_report, build_site_card_report, build_url_report
from safety_policy import is_fetch_allowed, is_onion_url, normalize_url, redact_sensitive
from screenshot_service import screenshot_support_status
from tor_circuits import circuit_policy_status
from profile_builder import refresh_site_profiles
from universal_classifier import (classify_url_prefetch, restricted_placeholder,
                                  safe_category_label)
from ui_components import (category_badge, confidence_badge, empty_state, explain_flag, importance_badge, indicator_summary,
                           mask_onion_address, metric_strip, parse_json, review_badge, risk_badge,
                           safe_preview_path, safe_display_title, section_header, spain_flag_badge,
                           stage_strip, severity_badge, status_badge, suggested_action,
                           workbench_header)
from ui_styles import ARACHNE_LIGHT_CSS, DASHBOARD_CSS
from dashboard_pages.router import render_page
from dashboard_pages import (activity, actors, add_onion, advanced, connections, control_center, crawl_queue, entity_intelligence, faq, home,
                             identity_signals, investigations, quality_center, reports, review, settings as settings_page, site_cards, timeline,
                             site_directory, spain_priority)
from dashboard_services.queries import QueryMetrics
from dashboard_services.i18n import (category_label, category_reason_label, current_language,
                                     spain_reason_label, tr, value_label)

LOGGER = logging.getLogger("dashboard")

PAGES = ["Overview", "Onion URL Frontier", "Onion Hits", "Mirror Clusters",
         "Indicator Explorer", "Public Signal Map", "Passive Exposures",
         "Saved Reports", "Settings / Safety"]
REVIEW_STATES = ["pending", "relevant", "false_positive", "needs_report", "reported", "blocked"]
RISK_ORDER = {"NULO": 0, "BAJO": 1, "MEDIO": 2, "ALTO": 3, "CRITICO": 4}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
SIMPLE_PAGES = ["Home", "Add Onion", "Crawl Queue", "Site Cards", "Entity Intelligence", "Connections", "Timeline", "Actors", "Identity Signals", "Quality Center", "Watchlist",
                "Spain Priority", "Daily Activity", "Review Findings", "Reports", "Advanced",
                "Control Center", "Settings", "FAQ"]
NAV_AREAS = {
    "Home": ["Home"],
    "Crawl": ["Add Onion", "Crawl Queue"],
    "Intelligence": ["Site Cards", "Entity Intelligence", "Timeline", "Watchlist", "Connections", "Actors", "Identity Signals", "Review Findings", "Quality Center"],
    "Spain": ["Spain Priority"],
    "Reports": ["Daily Activity", "Reports", "Advanced"],
    "Settings": ["Control Center", "Settings", "FAQ"],
}
PAGE_TO_AREA = {page: area for area, pages in NAV_AREAS.items() for page in pages}
PAGE_COPY_KEYS = {
    "Home": "page_home", "Add Onion": "page_add", "Crawl Queue": "page_queue",
    "Site Cards": "page_cards", "Entity Intelligence": "page_entities", "Connections": "page_connections", "Timeline": "page_timeline",
    "Actors": "page_actors", "Identity Signals": "page_identity", "Review Findings": "page_review",
    "Quality Center": "page_quality", "Watchlist": "page_investigations",
    "Daily Activity": "page_activity",
    "Spain Priority": "page_spain", "Reports": "page_reports", "Advanced": "page_advanced",
    "Control Center": "page_control", "Settings": "page_settings",
    "FAQ": "page_faq",
}
PAGE_SLUGS = {
    "Home": "home",
    "Add Onion": "add",
    "Crawl Queue": "queue",
    "Site Cards": "cards",
    "Entity Intelligence": "entities",
    "Connections": "connections",
    "Timeline": "timeline",
    "Actors": "actors",
    "Identity Signals": "identity",
    "Quality Center": "quality",
    "Watchlist": "investigations",
    "Spain Priority": "spain",
    "Daily Activity": "activity",
    "Review Findings": "review",
    "Reports": "reports",
    "Advanced": "advanced",
    "Control Center": "control",
    "Settings": "settings",
    "FAQ": "faq",
}
SLUG_TO_PAGE = {slug: page for page, slug in PAGE_SLUGS.items()}
PRIMARY_NAV_PAGES = (
    "Home", "Review Findings", "Spain Priority", "Site Cards",
    "Entity Intelligence", "Crawl Queue", "Control Center", "Reports",
)
ADULT_CATEGORY = "adult_restricted"
SEVERE_CATEGORY = "severe_abuse_risk"
NEUTRAL_CATEGORIES = {"infosec_research", "privacy_anonymity", "news_media",
                      "religion_spirituality", "education_reference", "technology_software",
                      "finance_cryptocurrency", "activism_civil_society", "personal_blog",
                      "communication_services", "file_storage_sharing", "arts_culture", "health_wellness"}
MONITOR_ONLY_CATEGORIES = ({"forum_social", "directory_index", "search_engine", "hosting_services",
                            "contact_infrastructure"} | NEUTRAL_CATEGORIES)
MARKETPLACE_CATEGORIES = {"marketplace", "marketplace_drugs", "marketplace_weapons", "marketplace_fraud",
                          "marketplace_credentials", "marketplace_leaks", "marketplace_counterfeit",
                          "marketplace_services"}
CATEGORY_GROUPS = {
    "Discovery": ["directory_index", "search_engine", "forum_social", "hosting_services", "contact_infrastructure"],
    "Neutral / informational": ["infosec_research", "privacy_anonymity", "news_media",
                                "religion_spirituality", "education_reference", "technology_software",
                                "finance_cryptocurrency", "activism_civil_society", "personal_blog",
                                "communication_services", "file_storage_sharing", "arts_culture", "health_wellness"],
    "Marketplaces": ["marketplace", "marketplace_drugs", "marketplace_weapons", "marketplace_fraud",
                     "marketplace_credentials", "marketplace_leaks", "marketplace_services", "marketplace_counterfeit"],
    "Risk topics": ["leaks_data", "credentials", "malware_hacking", "weapons_arms", "drugs",
                "fraud_financial", "extremist_recruitment"],
}


def _dashboard_principal(st) -> dict:
    """Return the principal established by dashboard.py, failing closed."""
    principal = st.session_state.get("dashboard_principal")
    if isinstance(principal, dict) and dashboard_auth.normalize_role(principal.get("role")):
        return principal
    if not dashboard_auth.dashboard_lock_enabled():
        return {
            "role": dashboard_auth.ROLE_ADMIN,
            "capabilities": list(
                dashboard_auth.capabilities_for_role(dashboard_auth.ROLE_ADMIN)
            ),
            "lock_enabled": False,
        }
    return {
        "role": dashboard_auth.ROLE_DEMO_READONLY,
        "capabilities": list(
            dashboard_auth.capabilities_for_role(dashboard_auth.ROLE_DEMO_READONLY)
        ),
        "lock_enabled": True,
    }


def _can(st, capability: str) -> bool:
    return dashboard_auth.has_capability(_dashboard_principal(st), capability)


def _authorize_action(st, capability: str) -> bool:
    """Enforce authorization again when a mutating event reaches the server."""
    if _can(st, capability):
        return True
    st.error(_l(
        st,
        "This session is read-only for that action.",
        "Esta sesión es de solo lectura para esa acción.",
    ))
    return False


def _rows(query: str, params=()) -> list[dict]:
    with storage.get_db() as db:
        return [dict(row) for row in db.execute(query, params)]


def _scalar(query: str, params=(), default=0):
    with storage.get_db() as db:
        row = db.execute(query, params).fetchone()
        return row[0] if row else default


def _fmt(value) -> str:
    return str(value or "Unavailable")


def _is_adult_item(item: dict) -> bool:
    return (item.get("primary_category") in {ADULT_CATEGORY, "adult_filtered"}
            or item.get("storage_policy") == "discard"
            or "adult_extreme_caution" in parse_json(item.get("risk_flags")))


def _is_severe_item(item: dict) -> bool:
    return item.get("primary_category") == SEVERE_CATEGORY


def _is_monitor_only(item: dict) -> bool:
    return (item.get("primary_category") in MONITOR_ONLY_CATEGORIES
            and str(item.get("risk_level") or "low").casefold() in {"low", "bajo", "nulo"}
            and not item.get("spain_priority"))


def _is_low_info(item: dict) -> bool:
    return (item.get("primary_category") in {None, "", "unknown"}
            and not item.get("spain_priority") and not item.get("mirror_count")
            and not item.get("source_count"))


def _normal_card_visible(item: dict, show_adult: bool, show_low_info: bool = True,
                         show_monitor: bool = True) -> bool:
    if _is_severe_item(item):
        return False
    if _is_adult_item(item) and not show_adult:
        return False
    if not show_low_info and _is_low_info(item):
        return False
    if not show_monitor and _is_monitor_only(item):
        return False
    return True


def _need_review_count() -> int:
    return int(_scalar("""SELECT COUNT(*) FROM site_cards WHERE review_status IN ('pending','needs_review','needs_report')
      AND primary_category NOT IN ('adult_restricted','severe_abuse_risk')
      AND COALESCE(ui_hidden_default,0)=0 AND live_url_count>0 AND NOT (primary_category IN ('forum_social','directory_index','search_engine','hosting_services','contact_infrastructure','infosec_research','privacy_anonymity','news_media','religion_spirituality','education_reference','technology_software','finance_cryptocurrency','activism_civil_society','personal_blog','communication_services','file_storage_sharing','arts_culture','health_wellness')
      AND lower(COALESCE(risk_level,'low')) IN ('low','bajo','nulo') AND spain_priority=0)"""))


def _restricted_hidden_count() -> int:
    return int(_scalar("""SELECT COUNT(*) FROM site_cards WHERE storage_policy='metadata_only'
      AND primary_category!='severe_abuse_risk'"""))


def _show_page_topics(st, topics_value, keywords_value) -> None:
    topics = parse_json(topics_value)
    keywords = parse_json(keywords_value)
    if topics:
        topic_html = " ".join(f'<span class="badge badge-purple">{html.escape(str(topic))}</span>' for topic in topics)
        st.markdown(f"**Topics found in visible text:** {topic_html}", unsafe_allow_html=True)
    else:
        st.caption("Topics found in visible text: none confidently recognized yet.")
    if keywords:
        st.caption("Page keywords: " + ", ".join(html.escape(str(word)) for word in keywords[:15]))
    st.caption("These are automatic text hints for sorting and review—not proof that a page is accurately described by the label.")


def _environment_label() -> str:
    configured = get_str("APP_ENV")
    if configured:
        return configured.upper()
    return "SERVER" if str(BASE_DIR).startswith("/root/") else "LOCAL"


def _normalize_ui_theme(value: object) -> str | None:
    """Return the two supported presentation themes without leaking legacy names."""
    normalized = str(value or "").strip().casefold()
    if normalized == "graphite":
        return "dark"
    return normalized if normalized in {"dark", "light"} else None


def _query_param_value(st, key: str) -> str | None:
    try:
        value = st.query_params.get(key)
    except (AttributeError, RuntimeError, TypeError):
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    return str(value).strip() if value is not None else None


def _resolve_ui_theme(st) -> str:
    """Resolve query, session, then server preference in that order.

    The query parameter keeps refreshes and navigation stable for the current
    browser.  ``runtime_settings.json`` provides the durable server default.
    No database state or analyst data is involved.
    """
    query_theme = _normalize_ui_theme(_query_param_value(st, "theme"))
    session_theme = _normalize_ui_theme(st.session_state.get("ui_theme"))
    configured_theme = _normalize_ui_theme(get_str("UI_THEME", "dark")) or "dark"
    theme = query_theme or session_theme or configured_theme
    previous_query = st.session_state.get("_ui_theme_query")
    if "ui_dark_mode" not in st.session_state or (query_theme and previous_query != query_theme):
        st.session_state["ui_dark_mode"] = theme == "dark"
    st.session_state["_ui_theme_query"] = query_theme
    st.session_state["ui_theme"] = theme
    return theme


def _persist_ui_theme(st) -> None:
    """Persist the visible theme toggle without disturbing other query keys."""
    theme = "dark" if bool(st.session_state.get("ui_dark_mode")) else "light"
    st.session_state["ui_theme"] = theme
    st.session_state["_ui_theme_query"] = theme
    try:
        st.query_params["theme"] = theme
    except (AttributeError, RuntimeError, TypeError):
        pass
    try:
        save_runtime_settings({"UI_THEME": theme})
    except (OSError, ValueError) as exc:
        # The browser/session preference still works when the settings folder
        # is temporarily read-only.  Do not make presentation block the app.
        LOGGER.warning("Could not persist UI theme: %s", redact_for_log(str(exc)))


def _page_subtitle(st, page: str) -> str:
    copy = {
        "Entity Intelligence": ("Review public aliases, evidence, relationships and bounded expansion",
                                "Revisar alias públicos, evidencia, relaciones y expansión limitada"),
        "Home": ("Web mapping · Review queues · Source monitoring", "Mapeo web · Colas de revisión · Seguimiento de fuentes"),
        "Add Onion": ("Add a passive crawl starting point", "Añadir un punto inicial de rastreo pasivo"),
        "Crawl Queue": ("Worker progress, queues and crawl health", "Progreso, colas y estado del rastreo"),
        "Site Cards": ("Browse deduplicated sites and their safe profiles", "Explorar sitios agrupados y sus perfiles seguros"),
        "Connections": ("Relationships between sites, aliases and signals", "Relaciones entre sitios, alias y señales"),
        "Timeline": ("Recent changes across monitored sources", "Cambios recientes en las fuentes monitorizadas"),
        "Actors": ("Public aliases and evidence-linked observations", "Alias públicos y observaciones con evidencia"),
        "Identity Signals": ("Structured identifiers and correspondence evidence", "Identificadores estructurados y evidencia de coincidencia"),
        "Quality Center": ("Classification confidence and consistency checks", "Confianza de clasificación y controles de consistencia"),
        "Watchlist": ("Saved scopes for repeat review", "Ámbitos guardados para revisión recurrente"),
        "Spain Priority": ("Exact Spain-linked pages awaiting review", "Páginas vinculadas con España pendientes de revisión"),
        "Daily Activity": ("What the system processed and changed", "Qué procesó y cambió el sistema"),
        "Review Findings": ("Small, actionable review queue", "Cola de revisión pequeña y accionable"),
        "Reports": ("Metadata-safe reports and exports", "Informes y exportaciones de metadatos seguros"),
        "Advanced": ("Restricted metadata and maintenance tools", "Metadatos restringidos y mantenimiento"),
        "Control Center": (
            "Workers, access and service health",
            "Procesos, acceso y estado de servicios",
        ),
        "Settings": ("Safe runtime configuration", "Configuración segura en ejecución"),
        "FAQ": ("Plain-language product and workflow help", "Ayuda sencilla sobre el producto y el flujo"),
    }
    english, spanish = copy.get(page, ("Operational workspace", "Espacio operativo"))
    return _l(st, english, spanish)


def _arachne_logo_data_uri() -> str:
    logo_path = BASE_DIR / "assets" / "brand" / "arachne_mark.svg"
    try:
        payload = base64.b64encode(logo_path.read_bytes()).decode("ascii")
    except OSError:
        return ""
    return f"data:image/svg+xml;base64,{payload}"


def _render_visual_sidebar_nav(st, current_page: str, language: str, spain_count: int) -> None:
    """Render eight analyst-facing destinations and retain every legacy route."""
    if st.sidebar.button(
        _l(st, "＋  Add starting onion", "＋  Añadir onion inicial"),
        key="sidebar-add-source",
        type="primary",
        use_container_width=True,
        help=_l(st, "Open the focused page for starting or extending a crawl.",
                "Abre la página dedicada a iniciar o ampliar un rastreo."),
    ):
        _open_workspace_page("Add Onion")
        st.rerun()
    nav_sections = [
        (_l(st, "Review", "Revisión"), [
            ("Home", "⌂", _l(st, "Overview", "Resumen"), ""),
            ("Review Findings", "✓", _l(st, "Review Inbox", "Bandeja de revisión"), ""),
            ("Spain Priority", "🇪🇸", _l(st, "Spain", "España"), str(spain_count) if spain_count else ""),
        ]),
        (_l(st, "Explore", "Explorar"), [
            ("Site Cards", "▦", _l(st, "Sites", "Sitios"), ""),
            ("Entity Intelligence", "◇", _l(st, "Intelligence", "Inteligencia"), ""),
        ]),
        (_l(st, "Operate", "Operar"), [
            ("Crawl Queue", "↻", _l(st, "Collection", "Colección"), ""),
            ("Control Center", "⚙", _l(st, "Operations", "Operaciones"), ""),
            ("Reports", "▤", _l(st, "Reports", "Informes"), ""),
        ]),
    ]
    for section, items in nav_sections:
        st.sidebar.markdown(f'<div class="rt-nav-label">{html.escape(section)}</div>', unsafe_allow_html=True)
        for page_name, icon, display_label, count in items:
            count_label = f" [{count}]" if count else ""
            if st.sidebar.button(
                f"{icon}  {display_label}{count_label}", key=f"nav_btn_{PAGE_SLUGS[page_name]}",
                type="primary" if page_name == current_page else "secondary", use_container_width=True,
            ):
                _open_workspace_page(page_name)
                st.rerun()
    secondary_items = [
        ("Connections", "↔"), ("Timeline", "◷"),
        ("Actors", "@"), ("Identity Signals", "ID"), ("Quality Center", "Q"),
        ("Watchlist", "☆"), ("Daily Activity", "↓"), ("Advanced", "…"),
    ]
    with st.sidebar.expander(
        _l(st, "More tools", "Más herramientas"),
        expanded=current_page in {page for page, _icon in secondary_items},
    ):
        for page_name, icon in secondary_items:
            if st.button(
                f"{icon}  {tr(PAGE_COPY_KEYS[page_name], language)}",
                key=f"nav_btn_{PAGE_SLUGS[page_name]}",
                type="primary" if page_name == current_page else "secondary", use_container_width=True,
            ):
                _open_workspace_page(page_name)
                st.rerun()
    st.sidebar.markdown(f'<div class="rt-nav-label">{html.escape(_l(st, "Utility", "Utilidad"))}</div>', unsafe_allow_html=True)
    for page_name, icon in (("Settings", "⚙"), ("FAQ", "?")):
        if st.sidebar.button(
            f"{icon}  {tr(PAGE_COPY_KEYS[page_name], language)}", key=f"nav_btn_{PAGE_SLUGS[page_name]}",
            type="primary" if page_name == current_page else "secondary", use_container_width=True,
        ):
            _open_workspace_page(page_name)
            st.rerun()
    return


def _note(st, text: str) -> None:
    st.markdown(f'<div class="section-note">{html.escape(text)}</div>', unsafe_allow_html=True)


def _l(st, english: str, spanish: str) -> str:
    return spanish if current_language(st) == "es" else english


def _preview(st, path_value: str | None, caption: str = "Safe local page preview") -> None:
    path = safe_preview_path(path_value)
    if path:
        st.image(str(path), caption=caption, width="stretch")
        with st.expander("Open larger preview"):
            st.image(str(path), width="stretch")
    else:
        st.markdown('<div class="empty-preview">No preview available</div>', unsafe_allow_html=True)


def _policy_preview(st, item: dict, caption: str = "Safe local page preview") -> None:
    category = item.get("primary_category") or "unknown"
    restricted = item.get("storage_policy") == "metadata_only" or item.get("review_status") == "restricted"
    blocked = restricted or item.get("screenshot_policy") == "blocked"
    if blocked:
        line1, line2, line3 = restricted_placeholder(category)
        st.markdown(
            f'<div class="restricted-preview"><b>{html.escape(line1)}</b><br>'
            f'<span>{html.escape(line2)}</span><br><small>{html.escape(line3)}</small></div>',
            unsafe_allow_html=True,
        )
        return
    _preview(st, item.get("preview_path"), caption)


def _spain_unreviewed_count() -> int:
    cards = int(_scalar("""SELECT COUNT(*) FROM site_cards WHERE spain_priority=1
      AND COALESCE(ui_hidden_default,0)=0
      AND COALESCE(classification_decision,'unclassified') NOT IN ('accepted','analyst_confirmed')
      AND primary_category NOT IN ('adult_filtered','adult_restricted','severe_abuse_risk')
      AND EXISTS(SELECT 1 FROM onion_urls ou WHERE ou.site_card_id=site_cards.id
        AND ou.spain_priority=1 AND COALESCE(ou.spain_analyst_suppressed,0)=0
        AND COALESCE(ou.spain_review_status,'unreviewed')='unreviewed')"""))
    orphans = int(_scalar("""SELECT COUNT(*) FROM onion_urls WHERE spain_priority=1 AND site_card_id IS NULL
      AND COALESCE(ui_hidden_default,0)=0 AND COALESCE(spain_analyst_suppressed,0)=0
      AND COALESCE(spain_review_status,'unreviewed')='unreviewed'
      AND COALESCE(classification_decision,'unclassified') NOT IN ('accepted','analyst_confirmed')
      AND primary_category NOT IN ('adult_filtered','adult_restricted','severe_abuse_risk')"""))
    actor_updates = int(_scalar("SELECT COUNT(*) FROM actor_watch_alerts WHERE status='new'"))
    return cards + orphans + actor_updates


def _sync_workspace_navigation(st, page: str, language: str | None = None) -> str:
    """Make every compatibility widget reflect one authoritative page."""
    if page not in SIMPLE_PAGES:
        page = "Home"
    language = language or current_language(st)
    area = PAGE_TO_AREA[page]
    area_icons = {"Home": "⌂", "Crawl": "◎", "Intelligence": "◇", "Spain": "🇪🇸", "Reports": "▤",
                  "Settings": "⚙"}
    area_copy = {"Home": "menu_home", "Crawl": "menu_crawl", "Intelligence": "menu_intelligence",
                 "Spain": "menu_spain", "Reports": "menu_reports", "Settings": "menu_settings"}
    st.session_state["nav_page"] = page
    st.session_state["_compat_page"] = page
    st.session_state[f"_nav_area_display_{language}"] = f"{area_icons[area]}  {tr(area_copy[area], language)}"
    if len(NAV_AREAS[area]) > 1:
        st.session_state[f"_nav_subpage_display_{language}_{area}"] = tr(PAGE_COPY_KEYS[page], language)
    return page


def _open_workspace_page(page: str) -> None:
    """Move to a visible workspace while keeping URL and widgets in sync."""
    import streamlit as st
    page = _sync_workspace_navigation(st, page)
    # A selected Site Card is a full-page drill-down.  Explicit navigation is
    # the user's request to leave that drill-down, including when they click
    # Sites to return to the list.
    st.session_state.pop("directory_selected_card", None)
    st.session_state.pop("directory_selected_review_only", None)
    st.session_state.pop("directory_dialog_edit", None)
    st.session_state.pop("directory_origin_page", None)
    try:
        st.query_params["nav"] = PAGE_SLUGS[page]
        session_token = str(st.session_state.get("dashboard_session_token") or "").strip()
        if session_token:
            st.query_params["rt_session"] = session_token
    except Exception:
        pass


def _open_results_scope(scope: str = "All") -> None:
    import streamlit as st
    _open_workspace_page("Site Cards")
    st.session_state["category-filter-False"] = "All"
    st.session_state["priority-filter-False"] = scope
    st.session_state["operational-filter-False"] = "All"
    st.session_state["results-spain-filter"] = "All results"
    st.session_state["card-page-False"] = 1


def _clear_results_scope() -> None:
    _open_results_scope("All")


def _pipeline_status() -> dict:
    with storage.get_db() as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        fetched_pending = card_pending = 0
        frontier_pending = 0
        fetched_today = verified_today = card_jobs_done_today = 0
        fetched_status = {}
        card_job_status = {}
        onion_status = {}
        workers = []
        processed_today = 0
        today = storage.utc_now_iso()[:10]
        if "onion_urls" in tables:
            frontier_pending = int(db.execute("""SELECT COUNT(*) FROM onion_urls
              WHERE active=1 AND status IN ('new','queued','retry','claimed')""").fetchone()[0])
            onion_status = {str(row[0] or "unknown"): int(row[1]) for row in db.execute(
                "SELECT COALESCE(status,'unknown'),COUNT(*) FROM onion_urls GROUP BY COALESCE(status,'unknown')")}
        if "fetched_pages" in tables:
            fetched_pending = int(db.execute("""SELECT COUNT(*) FROM fetched_pages
              WHERE classification_status IN ('pending','retry','claimed')""").fetchone()[0])
            fetched_today = int(db.execute("""SELECT COUNT(*) FROM fetched_pages
              WHERE fetched_at LIKE ?""", (today + "%",)).fetchone()[0])
            verified_today = int(db.execute("""SELECT COUNT(*) FROM fetched_pages
              WHERE classification_status IN ('done','verified') AND COALESCE(verified_at,fetched_at) LIKE ?""",
              (today + "%",)).fetchone()[0])
            fetched_status = {str(row[0] or "unknown"): int(row[1]) for row in db.execute(
                "SELECT COALESCE(classification_status,'unknown'),COUNT(*) FROM fetched_pages GROUP BY COALESCE(classification_status,'unknown')")}
        if "site_card_jobs" in tables:
            card_pending = int(db.execute("""SELECT COUNT(*) FROM site_card_jobs
              WHERE status IN ('queued','retry','claimed')""").fetchone()[0])
            card_jobs_done_today = int(db.execute("""SELECT COUNT(*) FROM site_card_jobs
              WHERE status='done' AND updated_at LIKE ?""", (today + "%",)).fetchone()[0])
            card_job_status = {f"{row[0] or 'job'}:{row[1] or 'unknown'}": int(row[2])
                               for row in db.execute("""SELECT COALESCE(job_type,'job'),COALESCE(status,'unknown'),COUNT(*)
                                 FROM site_card_jobs GROUP BY COALESCE(job_type,'job'),COALESCE(status,'unknown')""")}
        if "worker_instances" in tables:
            workers = [dict(row) for row in db.execute("""SELECT worker_type,state,last_heartbeat_at,processed_total
              FROM worker_instances ORDER BY last_heartbeat_at DESC,worker_type,worker_id""")]
    active_workers = [
        worker for worker in workers
        if str(worker.get("state") or "").casefold() != "stopped" and _worker_is_online(worker)
    ]
    by_type = defaultdict(list)
    for worker in active_workers:
        by_type[str(worker.get("worker_type") or "worker")].append(worker)
    processed_today = fetched_today + verified_today + card_jobs_done_today
    newest_worker = max(workers, key=lambda item: str(item.get("last_heartbeat_at") or ""), default={})
    return {
        "frontier_pending": frontier_pending,
        "fetched_pending": fetched_pending,
        "card_pending": card_pending,
        "fetch_workers": len(by_type.get("fetch", [])),
        "verify_workers": len(by_type.get("verify", [])),
        "card_workers": len(by_type.get("card", [])),
        "preview_workers": len(by_type.get("preview", [])),
        "processed_today": processed_today,
        "fetched_today": fetched_today,
        "verified_today": verified_today,
        "card_jobs_done_today": card_jobs_done_today,
        "processed_total": sum(int(worker.get("processed_total") or 0) for worker in workers),
        "worker_states": dict(by_type),
        "newest_worker_type": newest_worker.get("worker_type"),
        "newest_worker_state": newest_worker.get("state"),
        "newest_worker_at": newest_worker.get("last_heartbeat_at"),
        "onion_status": onion_status,
        "fetched_status": fetched_status,
        "card_job_status": card_job_status,
    }


def _open_new_results() -> None:
    import streamlit as st
    _open_results_scope("All")
    st.session_state["card-sort-False"] = "Newest first"


def _open_urgent_results() -> None:
    import streamlit as st
    _open_results_scope("Urgent")
    st.session_state["card-sort-False"] = "Urgent first"


def _open_classification_queue() -> None:
    _open_workspace_page("Quality Center")


def _reset_card_results(review_only: bool) -> None:
    """Keep changed result controls from leaving the user on an empty stale page."""
    import streamlit as st
    st.session_state[f"card-page-{review_only}"] = 1
    st.session_state.pop(f"card-page-picker-{review_only}", None)
    st.session_state.pop("directory_selected_card", None)
    st.session_state.pop("directory_selected_review_only", None)
    st.session_state.pop("directory_dialog_edit", None)


def _open_spain_page() -> None:
    _open_workspace_page("Spain Priority")


def _open_spain_actors() -> None:
    import streamlit as st
    _open_spain_page()
    st.session_state["spain-workspace-mode"] = "Actors"


def _open_restricted_metadata() -> None:
    import streamlit as st
    # Use the canonical navigator first so refreshes/deep links retain Advanced.
    _open_workspace_page("Advanced")
    language = current_language(st)
    st.session_state["nav_page"] = "Advanced"
    st.session_state["_compat_page"] = "Advanced"
    st.session_state[f"_nav_area_display_{language}"] = f"▤  {tr('menu_reports', language)}"
    st.session_state[f"_nav_subpage_display_{language}_Reports"] = tr("page_advanced", language)
    st.session_state["advanced_tool"] = "Restricted Metadata"
    st.session_state["show_filtered_adult_metadata"] = True


def _global_spain_banner(st, query) -> None:
    count = _spain_unreviewed_count()
    if not count:
        return
    actor_updates = len(storage.get_actor_watch_alerts(limit=1000))
    if actor_updates:
        language = current_language(st)
        st.warning((f"ACTUALIZACIONES DE ALIAS VIGILADOS — {actor_updates} nueva(s)" if language == "es" else
                    f"WATCHED ALIAS UPDATES — {actor_updates} new exact page(s) or correspondence(s)"))
        st.button("ABRIR ACTUALIZACIONES DE ALIAS" if language == "es" else "OPEN WATCHED ALIAS UPDATES",
                  on_click=_open_spain_actors, key="global-actor-open")
        if count == actor_updates:
            return
        count -= actor_updates
    newest = query("""SELECT primary_category,risk_level,spain_match_reason,mirror_count FROM site_cards
        WHERE spain_priority=1
        AND COALESCE(ui_hidden_default,0)=0
        AND COALESCE(classification_decision,'unclassified') NOT IN ('accepted','analyst_confirmed')
        AND primary_category NOT IN ('adult_filtered','adult_restricted','severe_abuse_risk')
        AND EXISTS(SELECT 1 FROM onion_urls ou WHERE ou.site_card_id=site_cards.id
          AND ou.spain_priority=1 AND COALESCE(ou.spain_analyst_suppressed,0)=0
          AND COALESCE(ou.spain_review_status,'unreviewed')='unreviewed')
        ORDER BY priority_score DESC,first_seen DESC LIMIT 1""")
    detail = newest[0] if newest else {}
    language = current_language(st)
    alert_text = (f"ESPAÑA · REVISAR AHORA — {count} página(s) necesitan atención" if language == "es" else
                  f"SPAIN · REVIEW NOW — {count} page(s) need attention")
    st.markdown(f'<div class="spain-review-pulse">🚨 {html.escape(alert_text)}</div>', unsafe_allow_html=True)
    st.caption(("Caso principal: " if language == "es" else "Highest current card: ") +
               f"{category_label(detail.get('primary_category'), language)} · {value_label(detail.get('risk_level'), language)} · " +
               ("Espejos " if language == "es" else "Mirrors ") +
               f"{detail.get('mirror_count') or 0} · "
               f"{spain_reason_label(detail.get('spain_match_reason'), language)}")
    st.button("ABRIR REVISIÓN PRIORIDAD ESPAÑA" if language == "es" else "OPEN SPAIN PRIORITY REVIEW",
              type="primary", on_click=_open_spain_page, key="global-spain-open")


def _compact_hit(st, hit: dict) -> None:
    category = safe_category_label(hit.get("primary_category") or "unknown")
    st.markdown(
        f'<div class="analyst-card"><h3>#{hit.get("id")} {html.escape(_fmt(hit.get("title") or "Untitled page"))}</h3>'
        f'{category_badge(category)} {risk_badge(hit.get("risk_level"))} {review_badge(hit.get("review_status"))}'
        f'<div class="card-meta">Score {hit.get("score", 0)} · Cluster {hit.get("cluster_id") or "Unassigned"} · {_fmt(hit.get("ts"))}</div></div>',
        unsafe_allow_html=True,
    )


def _simple_home(st, query) -> None:
    language = current_language(st)
    pipeline = _pipeline_status()
    urgent = int(_scalar("""SELECT COUNT(*) FROM site_cards WHERE COALESCE(ui_hidden_default,0)=0
      AND COALESCE(urgent_flag,0)=1
      AND primary_category!='severe_abuse_risk'
      AND review_status IN ('needs_review','needs_report','restricted')"""))
    new_today = int(_scalar("""SELECT COUNT(*) FROM site_cards
      WHERE COALESCE(ui_hidden_default,0)=0 AND primary_category!='severe_abuse_risk'
      AND created_at>=datetime('now','-24 hours')"""))
    needs_classification = int(_scalar("""SELECT COUNT(*) FROM onion_urls
      WHERE verification_state='verified' AND classification_decision IN ('abstained','needs_review')
      AND primary_category NOT IN ('adult_filtered','adult_restricted','severe_abuse_risk')"""))
    spain_leads = int(_spain_unreviewed_count())
    weak_cards = int(_scalar("""SELECT COUNT(*) FROM site_cards
      WHERE COALESCE(ui_hidden_default,0)=0
      AND primary_category!='severe_abuse_risk'
      AND COALESCE(card_completeness_label,'weak')='weak'"""))
    active_workers = (pipeline["fetch_workers"] + pipeline["verify_workers"]
                      + pipeline["card_workers"] + pipeline["preview_workers"])
    recent = query("SELECT * FROM site_cards ORDER BY first_seen DESC LIMIT 40")
    recent = [item for item in recent if _normal_card_visible(
        item, bool(st.session_state.get("show_adult_restricted_metadata", False)),
        bool(st.session_state.get("show_low_info_cards", False)),
        bool(st.session_state.get("show_monitor_only_cards", True)))][:5]
    lane_data = [
        ("🚨", _l(st, "Urgent", "Urgente"), urgent,
         _l(st, "Spain Priority or high-risk cards awaiting action.", "Prioridad España o fichas de alto riesgo pendientes."),
         _open_urgent_results, ()),
        ("✦", _l(st, "New", "Nuevo"), new_today,
         _l(st, "Site Cards created during the last 24 hours.", "Fichas creadas durante las últimas 24 horas."),
         _open_new_results, ()),
        ("?", _l(st, "Needs classification", "Necesita clasificación"), needs_classification,
         _l(st, "Fetched pages where the classifier deliberately remained unsure.", "Páginas comprobadas donde el clasificador mantuvo la duda."),
         _open_classification_queue, ()),
        ("⌁", _l(st, "Active crawls", "Rastreos activos"), active_workers,
         _l(st, "Staged workers currently reporting a live heartbeat.", "Procesos por etapas que están informando actividad."),
         _open_workspace_page, ("Crawl Queue",)),
    ]
    lane_data[0] = (lane_data[0][0], lane_data[0][1], lane_data[0][2],
                    _l(st, "Evidence-based urgent cards awaiting action.",
                       "Fichas urgentes basadas en evidencia pendientes."),
                    lane_data[0][4], lane_data[0][5])
    lane_data[3] = (lane_data[3][0], _l(st, "Active workers", "Procesos activos"),
                    lane_data[3][2], lane_data[3][3], lane_data[3][4], lane_data[3][5])
    with st.container(key="rt-home-intro"):
        intro_copy, intro_actions = st.columns([2.55, 1.45], gap="large")
        intro_copy.markdown(
            f'<div class="rt-home-kicker">{html.escape(_l(st, "Operations overview", "Resumen operativo"))}</div>'
            f'<h1 class="rt-home-heading">{html.escape(_l(st, "What needs attention?", "¿Qué necesita atención?"))}</h1>'
            f'<p class="rt-home-summary">{html.escape(_l(st, "Start here: see the work that matters now, confirm system health, and move directly to the next useful action.", "Empieza aquí: consulta el trabajo importante, confirma el estado del sistema y abre directamente la siguiente acción útil."))}</p>',
            unsafe_allow_html=True,
        )
        with intro_actions:
            action_columns = st.columns(2, gap="small")
            action_columns[0].button(
                _l(st, "Add onion", "Añadir onion"), key="home-intro-add",
                type="primary", on_click=_open_workspace_page, args=("Add Onion",),
                width="stretch",
            )
            action_columns[1].button(
                _l(st, "Operations", "Operaciones"), key="home-intro-operations",
                on_click=_open_workspace_page, args=("Control Center",), width="stretch",
            )

    st.markdown(metric_strip([
        (_l(st, "Urgent", "Urgente"), urgent,
         _l(st, "Direct evidence awaiting action", "Evidencia directa pendiente"),
         "critical" if urgent else "muted"),
        (_l(st, "Spain leads", "Señales de España"), spain_leads,
         _l(st, "Country-specific review", "Revisión específica del país"),
         "critical" if spain_leads else "muted"),
        (_l(st, "Needs classification", "Necesita clasificación"), needs_classification,
         _l(st, "Grouped uncertain pages", "Páginas inciertas agrupadas"),
         "warn" if needs_classification else "muted"),
        (_l(st, "Weak cards", "Fichas débiles"), weak_cards,
         _l(st, "Identity evidence can improve", "La evidencia de identidad puede mejorar"),
         "info" if weak_cards else "ok"),
    ]), unsafe_allow_html=True)

    with st.container(key="rt-home-workbench"):
        review_column, health_column = st.columns(2, gap="large")
        with review_column:
            with st.container(key="rt-home-review-panel"):
                st.markdown(workbench_header(
                    _l(st, "Review lanes", "Colas de revisión"),
                    _l(st, "Grouped, deduplicated, and routed for a clear decision.",
                       "Agrupadas, deduplicadas y dirigidas para una decisión clara."),
                    aside=str(urgent + spain_leads + needs_classification),
                ), unsafe_allow_html=True)
                for index, (icon, title, value, explanation, callback, args) in enumerate(lane_data[:3]):
                    with st.container(key=f"rt-home-lane-{index}"):
                        row = st.columns([.18, 2.5, .64], gap="small")
                        row[0].markdown(
                            f'<span class="rt-lane-icon">{html.escape(icon)}</span>',
                            unsafe_allow_html=True,
                        )
                        row[1].markdown(
                            f'<div class="rt-lane-copy"><strong>{html.escape(title)}</strong>'
                            f'<b>{int(value or 0)}</b><small>{html.escape(explanation)}</small></div>',
                            unsafe_allow_html=True,
                        )
                        row[2].button(
                            _l(st, "Open", "Abrir"), key=f"home-review-lane-{index}",
                            on_click=callback, args=args, disabled=value <= 0, width="stretch",
                        )
        with health_column:
            with st.container(key="rt-home-health-panel"):
                health_label = _l(st, "Healthy", "Correcto") if active_workers else _l(st, "Attention", "Atención")
                st.markdown(workbench_header(
                    _l(st, "System health", "Estado del sistema"),
                    _l(st, "Background services and the work currently waiting in the staged pipeline.",
                       "Servicios en segundo plano y trabajo pendiente en el flujo por etapas."),
                    aside=health_label,
                ), unsafe_allow_html=True)
                health_rows = [
                    (_l(st, "Fetch workers", "Procesos de recopilación"), pipeline["fetch_workers"],
                     pipeline["frontier_pending"]),
                    (_l(st, "Verify workers", "Procesos de verificación"), pipeline["verify_workers"],
                     pipeline["fetched_pending"]),
                    (_l(st, "Card workers", "Procesos de fichas"), pipeline["card_workers"],
                     pipeline["card_pending"]),
                    (_l(st, "Processed today", "Procesadas hoy"), pipeline["processed_today"], 0),
                ]
                for label, value, waiting in health_rows:
                    waiting_text = (
                        _l(st, f"{int(waiting)} waiting", f"{int(waiting)} en espera")
                        if waiting else _l(st, "No backlog", "Sin cola")
                    )
                    st.markdown(
                        f'<div class="rt-health-row"><div><strong>{html.escape(label)}</strong>'
                        f'<small>{html.escape(waiting_text)}</small></div>'
                        f'<span>{int(value or 0)}</span></div>',
                        unsafe_allow_html=True,
                    )
                st.button(
                    _l(st, "Open operations", "Abrir operaciones"),
                    key="home-health-open", on_click=_open_workspace_page,
                    args=("Control Center",), width="stretch",
                )

    with st.container(key="rt-home-recent-panel"):
        st.markdown(workbench_header(
            _l(st, "Recently mapped", "Mapeados recientemente"),
            _l(st, "Newest policy-visible sites, grouped into stable Site Cards.",
               "Los sitios visibles más recientes, agrupados en fichas estables."),
            eyebrow=_l(st, "Site directory", "Directorio de sitios"),
            aside=str(len(recent)),
        ), unsafe_allow_html=True)
        if not recent:
            st.markdown(empty_state(
                _l(st, "No sites mapped yet", "Todavía no hay sitios"),
                _l(st, "Add a lawful starting address to begin the collection pipeline.",
                   "Añade una dirección inicial legítima para comenzar."),
            ), unsafe_allow_html=True)
        else:
            for item in recent:
                with st.container(key=f"rt-home-recent-{item['id']}"):
                    row = st.columns([.18, 2.8, 1.65, .68], gap="small")
                    live_marker = (
                        '<span class="rt-live-dot rt-live-dot-on"></span>'
                        if item.get("live_url_count")
                        else '<span class="rt-live-dot"></span>'
                    )
                    row[0].markdown(live_marker, unsafe_allow_html=True)
                    name = safe_display_title(
                        item.get("analyst_title"), item.get("display_name"),
                        fallback=_l(st, "Unnamed site", "Sitio sin nombre"),
                    )
                    host = (item.get("representative_host") or
                            item.get("representative_url") or item.get("canonical_site_id"))
                    row[1].markdown(
                        f'<div class="rt-record-identity"><strong>{html.escape(str(name))}</strong>'
                        f'<code>{html.escape(mask_onion_address(host))}</code></div>',
                        unsafe_allow_html=True,
                    )
                    spain_marker = (
                        '<span class="rt-inline-flag" aria-label="Spain-linked">🇪🇸</span>'
                        if item.get("spain_priority") else ""
                    )
                    row[2].markdown(
                        f'<div class="rt-record-classification">{spain_marker}'
                        f'<strong>{html.escape(category_label(item.get("primary_category"), language))}</strong>'
                        f'<small>{html.escape(_l(st, "Risk", "Riesgo"))}: '
                        f'{html.escape(value_label(item.get("risk_level"), language))}</small></div>',
                        unsafe_allow_html=True,
                    )
                    row[3].button(
                        _l(st, "Open", "Abrir"), key=f"home-recent-open-{item['id']}",
                        on_click=site_directory.open_card, args=(int(item["id"]), False),
                        width="stretch",
                    )

    if not active_workers:
        st.error(_l(st, "No staged workers are reporting a current heartbeat. Open Operations to inspect services.",
                       "Ningún proceso por etapas informa actividad. Abre Operaciones para revisar los servicios."))

    # Category shortcuts remain available for experienced reviewers without
    # duplicating the primary navigation and system-health controls above.
    with st.expander(_l(st, "Browse by focus", "Explorar por tema")):
        focus_items = [
            (_l(st, "Marketplaces", "Mercados"),
             _scalar("SELECT COUNT(*) FROM site_cards WHERE primary_category LIKE 'marketplace%' AND ui_hidden_default=0"),
             "Marketplaces"),
            (_l(st, "Leaks / Credentials", "Filtraciones / Credenciales"),
             _scalar("SELECT COUNT(*) FROM site_cards WHERE primary_category IN ('leaks_data','credentials','marketplace_leaks','marketplace_credentials') AND ui_hidden_default=0"),
             "Leaks / credentials"),
            (_l(st, "Weapons / Drugs", "Armas / Drogas"),
             _scalar("SELECT COUNT(*) FROM site_cards WHERE primary_category IN ('weapons_arms','drugs','marketplace_weapons','marketplace_drugs') AND ui_hidden_default=0"),
             "Weapons / drugs"),
            (_l(st, "Forums / Directories", "Foros / Directorios"),
             _scalar("SELECT COUNT(*) FROM site_cards WHERE primary_category IN ('forum_social','directory_index','search_engine') AND ui_hidden_default=0"),
             "Forums / directories"),
            (_l(st, "High risk", "Riesgo alto"),
             _scalar("SELECT COUNT(*) FROM site_cards WHERE lower(COALESCE(risk_level,'low')) IN ('high','critical','alto','critico') AND ui_hidden_default=0 AND primary_category!='severe_abuse_risk'"),
             "High risk"),
            (_l(st, "Dead / unavailable", "Caídos / no disponibles"),
             _scalar("SELECT COUNT(*) FROM site_cards WHERE (live_url_count=0 OR dead_url_count>0) AND ui_hidden_default=0 AND primary_category!='severe_abuse_risk'"),
             "Dead / unavailable"),
        ]
        for batch_start in (0, 3):
            focus_columns = st.columns(3, gap="small")
            for offset, (column, (label, value, scope)) in enumerate(
                    zip(focus_columns, focus_items[batch_start:batch_start + 3], strict=False)):
                with column:
                    st.caption(f"{label} · {int(value or 0)}")
                    st.button(_l(st, "Open results", "Abrir resultados"),
                              key=f"home-category-action-{batch_start + offset}",
                              on_click=_open_results_scope, args=(scope,),
                              disabled=int(value or 0) <= 0, width="stretch")
        st.divider()
        st.caption(_l(st,
            "Correct a false adult classification from the restricted metadata view.",
            "Corrige una clasificación adulta falsa desde la vista de metadatos restringidos."))
        st.button(_l(st, "Show / fix adult filters", "Mostrar / corregir filtros adultos"),
                  key="home-review-adult-filters", on_click=_open_restricted_metadata,
                  width="stretch")

    return


def _worker_is_online(worker: dict | None) -> bool:
    heartbeat_value = (worker or {}).get("last_heartbeat_at") or (worker or {}).get("last_heartbeat")
    if not heartbeat_value:
        return False
    try:
        heartbeat = datetime.fromisoformat(heartbeat_value.replace("Z", "+00:00"))
        max_age = max(60, get_int("ONION_CRAWL_DELAY_SECONDS", 10) * 3)
        return (datetime.now(timezone.utc) - heartbeat).total_seconds() <= max_age
    except (TypeError, ValueError):
        return False


def _worker_status_label(worker: dict | None) -> str:
    if worker and worker.get("state") == "stopped":
        return "Stopped"
    if worker and worker.get("is_paused"):
        return "Paused"
    if _worker_is_online(worker):
        return "Running"
    if worker and (worker.get("last_heartbeat_at") or worker.get("last_heartbeat")):
        return "Stale"
    return "Never started"


def _systemd_service_state(service: str) -> str:
    if os.name == "nt":
        return "Unknown"
    try:
        result = subprocess.run(["systemctl", "is-active", service], capture_output=True,
                                text=True, timeout=1, check=False)
        return "Running" if result.stdout.strip() == "active" else "Stopped"
    except (OSError, subprocess.SubprocessError):
        return "Unknown"


def _tor_status() -> str:
    try:
        with socket.create_connection((get_str("TOR_SOCKS_HOST", "127.0.0.1"),
                                       get_int("TOR_SOCKS_PORT", 9050)), timeout=0.15):
            return "Ready"
    except OSError:
        return "Not reachable"


def _add_onion_page(st, query) -> None:
    language = current_language(st)
    can_manage_collection = _can(st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE)
    _note(st, _l(st,
        "Paste one lawful v3 onion address. This validates and queues it; the page is not opened in your browser.",
        "Pega una dirección onion v3 legítima. Aquí solo se valida y se añade a la cola; no se abre en tu navegador."))
    st.markdown(f"### {tr('add_address', language)}")
    seed_value = st.text_input(
        _l(st, "New onion address", "Nueva dirección onion"),
        placeholder="http://abcdefghijklmnopqrstuvwxyz...onion/",
        label_visibility="collapsed",
        key="dedicated-add-onion",
    )
    st.caption(_l(st, "A modern onion address has 56 letters/numbers before `.onion`. Include `http://` or `https://`.",
                  "Una dirección onion moderna tiene 56 letras/números antes de `.onion`. Incluye `http://` o `https://`."))
    if not can_manage_collection:
        st.info(_l(
            st,
            "This session can inspect collection state but cannot add crawl targets.",
            "Esta sesión puede consultar el rastreo, pero no añadir objetivos.",
        ))
    if st.button(
        tr("add_button", language),
        type="primary",
        width="stretch",
        disabled=not can_manage_collection,
    ) and _authorize_action(st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
        normalized = normalize_url(seed_value)
        allowed, reason = is_fetch_allowed(normalized or "", False)
        if not normalized or not is_onion_url(normalized) or not allowed:
            st.error(_l(st,
                f"This address cannot be added. Check that it is a complete 56-character v3 onion URL and not a blocked file link ({reason}).",
                f"No se puede añadir esta dirección. Comprueba que sea una URL onion v3 completa de 56 caracteres y no un archivo bloqueado ({reason})."))
        else:
            policy = classify_url_prefetch(normalized, source_context="manual_seed")
            status = "queued" if policy.get("active") else "blocked"
            seed_id = storage.insert_or_update_onion_url(
                normalized, urlsplit(normalized).hostname, source_type="manual_seed", depth=0,
                status=status, policy=policy,
            )
            adult_filtered = policy.get("primary_category") == "adult_filtered" or policy.get("storage_policy") == "discard"
            if not adult_filtered:
                site_dedupe.ensure_url_site_card(seed_id, policy, source_context="manual_seed")
                storage.queue_spain_alert(normalized, policy)
            queued = storage.queue_existing_onion_url(normalized) if policy.get("active") and not adult_filtered else False
            refresh_site_profiles(); query.clear()
            if adult_filtered:
                st.info(_l(st, "Address filtered by safety policy and retained only as blocked anti-retry metadata.",
                              "Dirección filtrada por seguridad y conservada solo como metadato para evitar reintentos."))
            elif policy.get("storage_policy") == "metadata_only":
                st.warning(_l(st, "Added as a restricted metadata-only item. It will not be fetched, previewed, screenshotted, or expanded.",
                              "Añadida como elemento restringido de solo metadatos. No se abrirá, previsualizará, capturará ni expandirá."))
            elif queued:
                st.success(_l(st, "Added successfully. It is now waiting for the crawler worker.",
                              "Añadido correctamente. Ahora está esperando al trabajador de rastreo."))
                st.info(_l(st, "Next: open Crawl queue to follow its status.",
                           "Siguiente paso: abre Cola de rastreo para seguir su estado."))
            else:
                st.error(_l(st, "This known URL is blocked by the safety policy and was not re-queued.",
                               "Esta URL conocida está bloqueada por seguridad y no volvió a la cola."))

    st.markdown("### " + _l(st, "Recently added starting addresses", "Direcciones iniciales añadidas recientemente"))
    recent = query("""SELECT url,status,first_seen,last_crawled,error_count FROM onion_urls
        WHERE source_type='manual_seed' AND primary_category NOT IN
        ('severe_abuse_risk','adult_restricted','adult_filtered') ORDER BY first_seen DESC LIMIT 10""")
    if not recent:
        st.info(_l(st, "No starting onion addresses have been added yet.",
                      "Todavía no se han añadido direcciones onion iniciales."))
    for item in recent:
        st.markdown(status_badge(item.get("status"), value_label(item.get("status"), language)), unsafe_allow_html=True)
        st.code(item["url"], language=None)
        st.caption(f"{_l(st, 'Added', 'Añadida')} {item.get('first_seen') or _l(st, 'at an unknown time', 'en un momento desconocido')} · "
                   f"{_l(st, 'Last checked', 'Última comprobación')} {item.get('last_crawled') or _l(st, 'not yet', 'todavía no')} · "
                   f"{_l(st, 'Errors', 'Errores')} {item.get('error_count') or 0}")


def _crawl_manager(st, query, pd) -> None:
    language = current_language(st)
    can_manage_collection = _can(st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE)
    _note(st, _l(st,
        "Manage added and discovered sites here. Use Add onion for a new starting address; the background worker performs the Tor requests.",
        "Gestiona aquí los sitios añadidos y descubiertos. Usa Añadir onion para una dirección nueva; el trabajador en segundo plano realiza las peticiones Tor."))

    worker = storage.get_worker_state() or {}
    pipeline = _pipeline_status()
    staged_online = (pipeline["fetch_workers"] + pipeline["verify_workers"] + pipeline["card_workers"]) > 0
    online = staged_online or _worker_is_online(worker)
    display_state = (pipeline.get("newest_worker_state") if staged_online else worker.get("state")) or "idle"
    display_heartbeat = (
        (pipeline.get("newest_worker_at") if staged_online else None)
        or worker.get("last_heartbeat_at")
        or worker.get("last_heartbeat")
        or _l(st, "unknown", "desconocida")
    )
    status_col, action_col, pause_col = st.columns([3, 1, 1])
    with status_col:
        if online:
            st.success(f"{_l(st, 'Worker online', 'Trabajador activo')} · "
                       f"{value_label(display_state, language)} · "
                       f"{_l(st, 'Last update', 'Última actualización')} {display_heartbeat}")
            if worker.get("last_action"):
                st.caption(f"{_l(st, 'Latest activity', 'Última actividad')}: {worker['last_action']}")
        else:
            st.error(_l(st, "The worker appears offline. The queue can be prepared, but nothing will be checked yet.",
                        "El trabajador parece inactivo. Puedes preparar la cola, pero todavía no se comprobará nada."))
            st.caption(_l(
                st,
                "Open Operations for service status and use the server control launcher if a restart is required.",
                "Abre Operaciones para ver los servicios y usa el control del servidor si hace falta reiniciarlos.",
            ))
    if action_col.button(_l(st, "Refresh status", "Actualizar estado"), width="stretch"):
        query.clear(); st.rerun()
    st.markdown(stage_strip([
        (_l(st, "Fetch", "Recopilar"), pipeline["fetch_workers"],
         "active" if pipeline["fetch_workers"] else "muted"),
        (_l(st, "Verify", "Clasificar"), pipeline["verify_workers"],
         "active" if pipeline["verify_workers"] else "muted"),
        (_l(st, "Cards", "Fichas"), pipeline["card_workers"],
         "active" if pipeline["card_workers"] else "muted"),
        (_l(st, "URL queue", "Cola URL"), pipeline["frontier_pending"],
         "warn" if pipeline["frontier_pending"] else "ok"),
        (_l(st, "Verify queue", "Cola de clasificación"), pipeline["fetched_pending"],
         "warn" if pipeline["fetched_pending"] else "ok"),
        (_l(st, "Card jobs", "Trabajos de fichas"), pipeline["card_pending"],
         "warn" if pipeline["card_pending"] else "ok"),
    ]), unsafe_allow_html=True)
    paused = bool((worker or {}).get("is_paused"))
    if pause_col.button(_l(st, "Resume worker" if paused else "Pause worker",
                           "Reanudar trabajador" if paused else "Pausar trabajador"), width="stretch",
                           disabled=not can_manage_collection) and _authorize_action(
                               st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
        storage.set_worker_paused(not paused); query.clear(); st.rerun()
    if worker:
        st.caption(f"{_l(st, 'Service state', 'Estado del servicio')}: {value_label(_worker_status_label(worker), language)} · "
                   f"{_l(st, 'Current stage', 'Etapa actual')}: {worker.get('current_stage') or worker.get('state') or 'unknown'} · "
                   f"RSS: {float(worker.get('rss_mb') or 0):.1f} MB · "
                   f"{_l(st, 'Processed today', 'Procesadas hoy')}: {int(pipeline.get('processed_today') or worker.get('processed_today') or 0)} · "
                   f"{_l(st, 'Total', 'Total')}: {int(worker.get('processed_total') or 0)} · "
                   f"{_l(st, 'Last URL', 'Última URL')}: {worker.get('last_url') or _l(st, 'none yet', 'ninguna')}")
    tor_policy = circuit_policy_status()
    if tor_policy["socks_isolation"]:
        identity_minutes = max(1, int(tor_policy["socks_identity_interval_seconds"]) // 60)
        renewal_minutes = max(1, int(tor_policy["newnym_interval_seconds"]) // 60)
        rotation_text = (_l(st, f"scheduled circuit renewal every {renewal_minutes} minutes is ON",
                                f"la renovación programada cada {renewal_minutes} minutos está ACTIVA")
                         if tor_policy["newnym_enabled"] else
                         _l(st, "scheduled circuit renewal needs server ControlPort setup",
                                "la renovación programada necesita configurar ControlPort en el servidor"))
        st.success(_l(st, f"Tor isolation is ON — the crawler changes its isolated SOCKS identity about every {identity_minutes} minutes; ",
                         f"El aislamiento de Tor está ACTIVO — el arachne cambia su identidad SOCKS aislada aproximadamente cada {identity_minutes} minutos; ") + rotation_text + ".")
        st.caption(_l(st, "Rotation is applied only between queued pages. An active fetch is allowed to finish normally.",
                          "La rotación solo se aplica entre páginas de la cola. Una descarga activa termina con normalidad."))
    else:
        st.warning(_l(st, "Tor stream isolation is OFF. Enable TOR_SOCKS_ISOLATION=true.",
                          "El aislamiento de Tor está DESACTIVADO. Activa TOR_SOCKS_ISOLATION=true."))

    st.markdown("### " + _l(st, "1 · Waiting list and crawl health", "1 · Lista de espera y estado del rastreo"))
    counts = {
        "Waiting": _scalar("SELECT COUNT(*) FROM onion_urls WHERE status IN ('new','queued','retry')"),
        "Being checked": _scalar("SELECT COUNT(*) FROM onion_urls WHERE status='claimed'"),
        "Finished": _scalar("SELECT COUNT(*) FROM onion_urls WHERE status='crawled'"),
        "Blocked safely": _scalar("SELECT COUNT(*) FROM onion_urls WHERE status='blocked' AND primary_category!='adult_filtered'"),
        "Failed repeatedly": _scalar("SELECT COUNT(*) FROM onion_urls WHERE status='dead'"),
    }
    count_help = {
        "Waiting":"Known URLs the worker has not finished yet.",
        "Being checked":"A URL the worker is opening right now.",
        "Finished":"URLs successfully checked and attached to Site Cards where eligible.",
        "Blocked safely":"URLs the safety rules refused to fetch.",
        "Failed repeatedly":"URLs that stayed unavailable after several safe attempts.",
    }
    count_items = list(counts.items())
    count_labels_es = {"Waiting": "En espera", "Being checked": "Comprobándose", "Finished": "Finalizadas",
                       "Blocked safely": "Bloqueadas con seguridad", "Failed repeatedly": "Fallos repetidos"}
    count_help_es = {"Waiting": "URL conocidas que el trabajador aún no terminó.",
                     "Being checked": "URL que el trabajador está abriendo ahora.",
                     "Finished": "URL comprobadas y vinculadas a fichas cuando corresponde.",
                     "Blocked safely": "URL que las reglas de seguridad no permitieron abrir.",
                     "Failed repeatedly": "URL que siguieron sin estar disponibles tras varios intentos seguros."}
    crawl_metric_items = []
    for label, value in count_items:
        state = (
            "critical" if label == "Failed repeatedly" and value
            else "warn" if label in {"Waiting", "Blocked safely"} and value
            else "ok" if label == "Finished" and value
            else "info" if label == "Being checked" and value
            else "muted"
        )
        crawl_metric_items.append((
            count_labels_es.get(label, label) if language == "es" else label,
            value,
            count_help_es.get(label, count_help[label]) if language == "es" else count_help[label],
            state,
        ))
    st.markdown(metric_strip(crawl_metric_items), unsafe_allow_html=True)
    with st.expander(_l(st, "Detailed category and safety counts", "Recuentos detallados de categorías y seguridad")):
        detailed=[
            (_l(st, "Discovered seeds", "Direcciones iniciales"),_scalar("SELECT COUNT(*) FROM onion_urls WHERE verification_state='discovered'")),
            (_l(st, "Provisional links", "Enlaces provisionales"),_scalar("SELECT COUNT(*) FROM onion_urls WHERE verification_state='provisional'")),
            (_l(st, "Verified pages", "Páginas verificadas"),_scalar("SELECT COUNT(*) FROM onion_urls WHERE verification_state='verified'")),
            (_l(st, "Verified weapons", "Armas verificadas"),_scalar("""SELECT COUNT(*) FROM onion_urls WHERE verification_state='verified'
              AND primary_category IN ('weapons_arms','marketplace_weapons')""")),
            (_l(st, "Retry", "Reintentos"),_scalar("SELECT COUNT(*) FROM onion_urls WHERE status='retry'")),
            (_l(st, "Restricted hidden", "Restringido oculto"),_restricted_hidden_count()),
            (_l(st, "Weapons", "Armas"),_scalar("SELECT COUNT(*) FROM onion_urls WHERE primary_category='weapons_arms'")),
            (_l(st, "Drugs", "Drogas"),_scalar("SELECT COUNT(*) FROM onion_urls WHERE primary_category='drugs'")),
            (_l(st, "Leaks", "Filtraciones"),_scalar("SELECT COUNT(*) FROM onion_urls WHERE primary_category='leaks_data'")),
            (_l(st, "Credentials", "Credenciales"),_scalar("SELECT COUNT(*) FROM onion_urls WHERE primary_category='credentials'")),
            ("Malware",_scalar("SELECT COUNT(*) FROM onion_urls WHERE primary_category='malware_hacking'")),
            (_l(st, "Recruitment", "Reclutamiento"),_scalar("SELECT COUNT(*) FROM onion_urls WHERE primary_category='extremist_recruitment'")),
            (_l(st, "Spain priority", "Prioridad España"),_scalar("SELECT COUNT(*) FROM onion_urls WHERE spain_priority=1")),
            ("Urgent", _scalar("SELECT COUNT(*) FROM site_cards WHERE triage_level='urgent'")),
            ("Alerts", _scalar("SELECT COUNT(*) FROM site_cards WHERE triage_level='alert'")),
            ("Needs check", _scalar("SELECT COUNT(*) FROM site_cards WHERE triage_level='needs_check'")),
            ("Monitor", _scalar("SELECT COUNT(*) FROM site_cards WHERE triage_level='monitor'")),
            (_l(st, "Screenshots blocked", "Capturas bloqueadas"),_scalar("SELECT COUNT(*) FROM onion_urls WHERE screenshot_policy='blocked' AND primary_category!='adult_filtered'")),
            (_l(st, "Discovered today", "Descubiertas hoy"),_scalar("SELECT COUNT(*) FROM onion_urls WHERE date(first_seen)=date('now')")),
        ]
        for batch_start in range(0,len(detailed),4):
            batch=detailed[batch_start:batch_start+4]; metric_cols=st.columns(len(batch))
            for col,(label,value) in zip(metric_cols,batch, strict=False): col.metric(label,value)

    st.markdown("### " + _l(st, "2 · Queue actions", "2 · Acciones de la cola"))
    st.caption(_l(
        st,
        "Use these only when a queue needs help. Normal staged workers continue automatically.",
        "Usa estas acciones solo cuando una cola necesite ayuda. Los procesos continúan automáticamente.",
    ))
    q1, q2, q3 = st.columns(3)
    if q1.button(_l(st, "Queue discovered links again", "Volver a encolar enlaces descubiertos"),
                 width="stretch", disabled=not can_manage_collection) and _authorize_action(
                     st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
        count = storage.queue_discovered_urls(50); query.clear(); st.success(_l(st, f"Queued {count} discovered link(s).", f"{count} enlace(s) descubierto(s) añadido(s) a la cola."))
    if q2.button(_l(st, "Retry failed sites", "Reintentar sitios fallidos"),
                 width="stretch", disabled=not can_manage_collection) and _authorize_action(
                     st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
        count = storage.queue_retryable_urls(50); query.clear(); st.success(_l(st, f"Queued {count} failed site(s) for another try.", f"{count} sitio(s) fallido(s) añadido(s) para reintentar."))
    if q3.button(_l(st, "Recheck uncertain pages", "Revisar páginas inciertas"),
                 width="stretch", disabled=not can_manage_collection) and _authorize_action(
                     st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
        count = storage.queue_uncertain_urls(50); query.clear(); st.success(_l(st, f"Queued {count} uncertain page(s) for deeper page understanding.", f"{count} página(s) incierta(s) añadida(s) para un análisis más profundo."))
    screenshot_enabled = get_bool("ENABLE_PAGE_SCREENSHOTS", False)
    with st.expander(_l(st, "Occasional maintenance actions", "Acciones de mantenimiento ocasionales")):
        q4, q5 = st.columns(2)
        if q4.button(_l(st, "Find missing text topics", "Detectar temas de texto pendientes"),
                     width="stretch", disabled=not can_manage_collection) and _authorize_action(
                         st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
            count = storage.queue_missing_topics(50); query.clear(); st.success(_l(st, f"Queued {count} checked site(s) that still need topic keywords.", f"{count} sitio(s) añadido(s) para detectar temas."))
        if q5.button(_l(st, "Queue missing previews", "Encolar vistas previas pendientes"),
                     width="stretch", disabled=not screenshot_enabled or not can_manage_collection) and _authorize_action(
                         st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
            count = storage.queue_missing_previews(20); query.clear(); st.success(_l(st, f"Queued {count} site(s) that need a front-page preview.", f"{count} sitio(s) añadido(s) para crear vista previa."))
        if not screenshot_enabled:
            st.caption(_l(st, "Preview generation is disabled in the production profile.",
                          "La generación de vistas previas está desactivada en el perfil de producción."))

    st.markdown("### " + _l(st, "3 · Known URLs", "3 · URL conocidas"))
    show_adult = bool(st.session_state.get("show_adult_restricted_metadata", False))
    visibility_where = ["ou.primary_category!='severe_abuse_risk'"]
    if not show_adult:
        visibility_where.extend([
            "ou.primary_category NOT IN ('adult_restricted','adult_filtered')",
            "COALESCE(ou.storage_policy,'safe_summary')!='discard'",
            "COALESCE(ou.risk_flags,'[]') NOT LIKE '%adult_extreme_caution%'",
        ])
    visibility_sql = " AND ".join(visibility_where)

    def _reset_queue_page() -> None:
        st.session_state["queue-page"] = 1
        st.session_state.pop("queue-selected-url-id", None)

    status_options = [
        row["value"] for row in query(
            f"""SELECT DISTINCT ou.status AS value FROM onion_urls ou
                WHERE {visibility_sql} AND trim(COALESCE(ou.status,''))!=''
                ORDER BY ou.status"""
        )
    ]
    category_options = [
        row["value"] for row in query(
            f"""SELECT DISTINCT COALESCE(ou.primary_category,'unknown') AS value
                FROM onion_urls ou WHERE {visibility_sql}
                ORDER BY COALESCE(ou.primary_category,'unknown')"""
        )
    ]
    status_filter = category_filter = risk_filter = language_filter = verification_filter = []
    spain_only = restricted_only = dead_only = False
    queue_search = ""
    with st.expander(_l(st, "Filter known URLs", "Filtrar URL conocidas"), expanded=False):
        queue_search = st.text_input(
            _l(st, "Find a URL or site", "Buscar una URL o sitio"),
            placeholder=_l(
                st,
                "Site name, masked host, category or exact stored URL",
                "Nombre, dominio, categoría o URL guardada exacta",
            ),
            key="queue-url-search",
            on_change=_reset_queue_page,
        )
        f1, f2, f3 = st.columns(3)
        status_filter = f1.multiselect(
            _l(st, "Status", "Estado"), status_options,
            format_func=lambda value: value_label(value, language),
            key="queue-status-filter", on_change=_reset_queue_page,
        )
        category_filter = f2.multiselect(
            _l(st, "Category", "Categoría"), category_options,
            format_func=lambda value: category_label(value, language),
            key="queue-category-filter", on_change=_reset_queue_page,
        )
        risk_filter = f3.multiselect(
            _l(st, "Risk", "Riesgo"), ["low", "medium", "high", "critical"],
            format_func=lambda value: value_label(value, language),
            key="queue-risk-filter", on_change=_reset_queue_page,
        )
        f4, f5 = st.columns(2)
        language_filter = f4.multiselect(
            _l(st, "Language", "Idioma"), ["EN", "ES", "RU", "MIXED"],
            key="queue-language-filter", on_change=_reset_queue_page,
        )
        verification_filter = f5.multiselect(
            _l(st, "Verification status", "Estado de verificación"),
            ["discovered", "provisional", "verified"],
            format_func=lambda value: (
                {"discovered": "Dirección inicial", "provisional": "Enlace encontrado — no visitado",
                 "verified": "Visitado y verificado"}[value]
                if language == "es" else
                {"discovered": "Discovered seed", "provisional": "Found link — not visited",
                 "verified": "Visited and verified"}[value]
            ),
            key="queue-verification-filter", on_change=_reset_queue_page,
        )
        x1, x2, x3 = st.columns(3)
        spain_only = x1.checkbox(
            _l(st, "Spain Priority only", "Solo Prioridad España"),
            key="queue-spain", on_change=_reset_queue_page,
        )
        restricted_only = x2.checkbox(
            _l(st, "Restricted only", "Solo restringidas"),
            key="queue-restricted", on_change=_reset_queue_page,
        )
        dead_only = x3.checkbox(
            _l(st, "Dead only", "Solo caídas"),
            key="queue-dead", on_change=_reset_queue_page,
        )

    queue_where = list(visibility_where)
    queue_params: list[object] = []
    if queue_search:
        needle = f"%{queue_search.casefold()[:240]}%"
        queue_where.append(
            "(lower(COALESCE(ou.url,'')) LIKE ? OR "
            "lower(COALESCE(ou.title,'')) LIKE ? OR "
            "lower(COALESCE(ou.safe_display_name,'')) LIKE ? OR "
            "lower(COALESCE(sp.display_name,'')) LIKE ? OR "
            "lower(COALESCE(sc.analyst_title,'')) LIKE ? OR "
            "lower(COALESCE(sc.display_name,'')) LIKE ? OR "
            "lower(COALESCE(ou.onion_domain,'')) LIKE ?)"
        )
        queue_params.extend([needle] * 7)

    def _append_in_filter(column: str, values: list[str]) -> None:
        if not values:
            return
        queue_where.append(f"{column} IN ({','.join('?' for _ in values)})")
        queue_params.extend(values)

    _append_in_filter("ou.status", status_filter)
    if category_filter:
        category_values = [None if value == "unknown" else value for value in category_filter]
        ordinary_categories = [value for value in category_values if value is not None]
        category_parts = []
        if ordinary_categories:
            category_parts.append(
                f"ou.primary_category IN ({','.join('?' for _ in ordinary_categories)})"
            )
            queue_params.extend(ordinary_categories)
        if None in category_values:
            category_parts.append("trim(COALESCE(ou.primary_category,''))=''")
        queue_where.append("(" + " OR ".join(category_parts) + ")")
    _append_in_filter("lower(COALESCE(ou.risk_level,'low'))", risk_filter)
    _append_in_filter("ou.spain_match_language", language_filter)
    _append_in_filter("ou.verification_state", verification_filter)
    if spain_only:
        queue_where.append("COALESCE(ou.spain_priority,0)=1")
    if restricted_only:
        queue_where.append("ou.storage_policy='metadata_only'")
    if dead_only:
        queue_where.append("ou.status='dead'")
    queue_where_sql = " AND ".join(queue_where)

    friendly_status = {"new":"Waiting","queued":"Waiting","retry":"Waiting to retry","crawled":"Finished",
                       "blocked":"Blocked safely","dead":"Failed repeatedly","error":"Error"}
    queue_page_size = st.selectbox(
        _l(st, "URLs per page", "URL por página"), [25, 50, 100],
        index=0, key="queue-page-size", on_change=_reset_queue_page,
    )
    queue_total = int(query(
        f"""SELECT COUNT(*) AS value
            FROM onion_urls ou
            LEFT JOIN site_profiles sp ON sp.url=ou.url
            LEFT JOIN site_cards sc ON sc.id=ou.site_card_id
            WHERE {queue_where_sql}""",
        tuple(queue_params),
    )[0]["value"])
    queue_page_count = max(1, (queue_total + queue_page_size - 1) // queue_page_size)
    if int(st.session_state.get("queue-page", 1) or 1) > queue_page_count:
        st.session_state["queue-page"] = queue_page_count
    queue_nav = st.columns([1, 3, 1])

    def _move_queue_page(delta: int) -> None:
        current = int(st.session_state.get("queue-page", 1) or 1)
        st.session_state["queue-page"] = max(1, min(queue_page_count, current + delta))

    queue_nav[0].button(
        _l(st, "Previous", "Anterior"), key="queue-page-prev",
        disabled=int(st.session_state.get("queue-page", 1) or 1) <= 1,
        width="stretch", on_click=_move_queue_page, args=(-1,),
    )
    queue_page = queue_nav[1].number_input(
        _l(st, "Page", "Página"), min_value=1, max_value=queue_page_count,
        step=1, key="queue-page", label_visibility="collapsed",
    )
    queue_nav[2].button(
        _l(st, "Next", "Siguiente"), key="queue-page-next",
        disabled=int(queue_page) >= queue_page_count, width="stretch",
        on_click=_move_queue_page, args=(1,),
    )
    queue_start = (int(queue_page) - 1) * queue_page_size
    page_rows = query(
        f"""SELECT ou.*,sp.display_name,pt.topics_json,sc.canonical_site_id,
                   sc.analyst_title AS card_analyst_title,sc.display_name AS card_name
            FROM onion_urls ou
            LEFT JOIN site_profiles sp ON sp.url=ou.url
            LEFT JOIN page_topics pt ON pt.url=ou.url
            LEFT JOIN site_cards sc ON sc.id=ou.site_card_id
            WHERE {queue_where_sql}
            ORDER BY ou.spain_priority DESC,ou.priority_score DESC,
              CASE ou.status WHEN 'queued' THEN 0 WHEN 'retry' THEN 1
                WHEN 'new' THEN 2 WHEN 'claimed' THEN 3 ELSE 4 END,
              ou.first_seen DESC,ou.id DESC
            LIMIT ? OFFSET ?""",
        tuple(queue_params + [int(queue_page_size), int(queue_start)]),
    )
    st.caption(_l(
        st,
        f"Showing {queue_start + 1 if queue_total else 0}–{min(queue_start + len(page_rows), queue_total)} of {queue_total} matching URLs.",
        f"Mostrando {queue_start + 1 if queue_total else 0}–{min(queue_start + len(page_rows), queue_total)} de {queue_total} URL.",
    ))

    for row in page_rows:
        display_name = (
            category_label(row.get("primary_category"), language)
            if row.get("storage_policy") == "metadata_only"
            else (
                row.get("card_analyst_title")
                or row.get("card_name")
                or row.get("display_name")
                or row.get("safe_display_name")
                or row.get("title")
                or _l(st, "Unnamed site", "Sitio sin nombre")
            )
        )
        status_text = (
            value_label(row.get("status"), language)
            if language == "es"
            else friendly_status.get(row.get("status"), row.get("status") or "Unknown")
        )
        status_class = (
            "rt-queue-danger" if row.get("status") in {"dead", "error"}
            else "rt-queue-warn" if row.get("status") in {"retry", "blocked"}
            else "rt-queue-ok" if row.get("status") == "crawled"
            else ""
        )
        spain_mark = " 🇪🇸" if row.get("spain_priority") else ""
        with st.container(key=f"rt-queue-item-{row['id']}"):
            queue_record, queue_action = st.columns([6, 1], gap="small")
            queue_record.markdown(
                f'<div class="rt-queue-row {status_class}">'
                f'<div class="rt-queue-main"><strong>{html.escape(str(display_name))}{spain_mark}</strong>'
                f'<code>{html.escape(mask_onion_address(row.get("url")))}</code></div>'
                f'<div class="rt-queue-meta"><span>{html.escape(category_label(row.get("primary_category"), language))}</span>'
                f'<span>{html.escape(value_label(row.get("risk_level") or "low", language))}</span>'
                f'<b>{html.escape(str(status_text))}</b></div></div>',
                unsafe_allow_html=True,
            )
            if queue_action.button(
                _l(st, "Inspect", "Revisar"), key=f"queue-inspect-{row['id']}",
                width="stretch",
            ):
                st.session_state["queue-selected-url-id"] = int(row["id"])
                st.rerun()

    table_labels = {"card": _l(st, "Site Card", "Ficha"), "name": _l(st, "Name", "Nombre"),
                    "url": _l(st, "Onion address", "Dirección onion"), "category": _l(st, "Category", "Categoría"),
                    "risk": _l(st, "Risk", "Riesgo"), "spain": _l(st, "Spain", "España"),
                    "storage": _l(st, "Storage", "Conservación"), "topics": _l(st, "Topics", "Temas"),
                    "evidence": _l(st, "Verification status", "Verificación"), "weapons": _l(st, "Weapons score", "Puntuación de armas"),
                    "status": _l(st, "Status", "Estado"), "checked": _l(st, "Last checked", "Última comprobación"),
                    "next": _l(st, "Next check", "Próxima comprobación"), "errors": _l(st, "Errors", "Errores"),
                    "source": _l(st, "Found from", "Encontrado desde")}
    evidence_es = {"discovered":"Dirección inicial", "provisional":"Enlace encontrado — no visitado",
                   "verified":"Visitado y verificado"}
    table = [{table_labels["card"]:r.get("card_name") or r.get("canonical_site_id") or _l(st, "Pending assignment", "Asignación pendiente"),
              table_labels["name"]:category_label(r.get("primary_category"), language) if r.get("storage_policy")=="metadata_only" else (
                  r.get("card_analyst_title") or r.get("card_name") or r.get("display_name")
                  or r.get("safe_display_name") or r.get("title")
                  or _l(st, "Unnamed site", "Sitio sin nombre")),
              table_labels["url"]:r["url"], table_labels["category"]:category_label(r.get("primary_category"), language),
              table_labels["risk"]:value_label(r.get("risk_level"), language),
              table_labels["spain"]:_l(st, "Yes", "Sí") if r.get("spain_priority") else "No",
              table_labels["storage"]:value_label(r.get("storage_policy"), language),
              table_labels["topics"]:", ".join(value_label(topic, language) for topic in parse_json(r.get("topics_json"))) or _l(st, "Not classified", "Sin clasificar"),
              table_labels["evidence"]:(evidence_es.get(r.get("verification_state"), "Descubierta") if language == "es" else
                                        {"discovered":"Discovered seed", "provisional":"Found link — not visited",
                                         "verified":"Visited and verified"}.get(r.get("verification_state"), "Discovered")),
              table_labels["weapons"]:int(r.get("weapons_evidence_score") or 0),
              table_labels["status"]:(value_label(r.get("status"), language) if language == "es" else friendly_status.get(r.get("status"),r.get("status"))),
              table_labels["checked"]:r.get("last_crawled"), table_labels["next"]:r.get("next_crawl_at"),
              table_labels["errors"]:r.get("error_count",0), table_labels["source"]:r.get("source_url") or _l(st, "Manual", "Manual")}
             for r in page_rows]
    with st.expander(_l(st, "Technical table for this page", "Tabla técnica de esta página")):
        st.caption(_l(st,
            "This view contains operational detail for the URLs shown above.",
            "Esta vista contiene detalles operativos de las URL mostradas arriba."))
        st.dataframe(pd.DataFrame(table), width="stretch", hide_index=True, height=360)
    selected_id = st.session_state.get("queue-selected-url-id")
    selected = next((row for row in page_rows if int(row["id"]) == int(selected_id or 0)), None)
    if selected:
        with st.container(border=True, key=f"rt-queue-detail-{selected['id']}"):
            detail_header, detail_close = st.columns([5, 1])
            detail_header.markdown(
                section_header(
                    _l(st, "Selected URL", "URL seleccionada"),
                    _l(
                        st,
                        "Operational detail and the one safe action available for this record.",
                        "Detalle operativo y la única acción segura disponible para este registro.",
                    ),
                ),
                unsafe_allow_html=True,
            )
            if detail_close.button(
                _l(st, "Close", "Cerrar"), key=f"queue-detail-close-{selected['id']}",
                width="stretch",
            ):
                st.session_state.pop("queue-selected-url-id", None)
                st.rerun()
            st.code(selected["url"], language=None)
            detail = st.columns(4)
            detail[0].metric(_l(st, "Status", "Estado"), value_label(selected.get("status"), language))
            detail[1].metric(_l(st, "Errors", "Errores"), int(selected.get("error_count") or 0))
            detail[2].metric(
                _l(st, "Verification", "Verificación"),
                value_label(selected.get("verification_state") or "discovered", language),
            )
            detail[3].metric(
                _l(st, "Last checked", "Última revisión"),
                selected.get("last_crawled") or _l(st, "Not yet", "Todavía no"),
            )
            if not selected.get("active") or selected.get("queue_policy") == "blocked":
                st.error(_l(
                    st,
                    "This URL is inactive under safety/dead-link policy and cannot be queued here.",
                    "Esta URL está inactiva por seguridad o disponibilidad y no puede añadirse a la cola.",
                ))
            elif st.button(
                _l(st, "Queue a policy-safe re-check", "Encolar una revisión segura"),
                key=f"queue-live-check-{selected['id']}", type="primary",
                disabled=not can_manage_collection,
            ) and _authorize_action(st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
                storage.queue_live_check(selected["url"])
                query.clear()
                st.success(_l(
                    st,
                    "Queued for the next full-policy worker cycle.",
                    "Añadida para el próximo ciclo completo del trabajador.",
                ))
            if selected.get("last_error"):
                st.warning(
                    f"{_l(st, 'Last problem', 'Último problema')}: {selected['last_error']}"
                )
    elif not page_rows:
        st.info(_l(st, "The queue is empty. Open Add Onion to enter a starting address.",
                      "La cola está vacía. Abre Añadir onion para introducir una dirección inicial."))


def _site_profiles(st, query) -> None:
    st.markdown("## Site Profiles")
    _note(st, "Safe pages show a normal profile. Restricted pages show metadata and a policy placeholder only—never a real title, snippet, preview, screenshot, or content excerpt.")
    rows = query("""SELECT sp.display_name,sp.explanation,sp.source_summary,ou.*,mu.cluster_id,
        pp.preview_path,pp.status AS preview_status,pt.topics_json,pt.keywords_json
        FROM onion_urls ou LEFT JOIN site_profiles sp ON sp.url=ou.url
        LEFT JOIN mirror_urls mu ON mu.url=ou.url LEFT JOIN page_previews pp ON pp.url=ou.url
        LEFT JOIN page_topics pt ON pt.url=ou.url
        WHERE COALESCE(ou.ui_hidden_default,0)=0 AND ou.primary_category NOT IN ('unknown','general_other')
        ORDER BY priority_score DESC,first_seen DESC LIMIT 1000""")
    c1,c2,c3,c4 = st.columns([2,1,1,1])
    search = c1.text_input("Search", placeholder="Name, category, or onion address")
    categories = c2.multiselect("Category", sorted({r.get("primary_category") or "unknown" for r in rows}), format_func=safe_category_label)
    risks = c3.multiselect("Risk level", ["low","medium","high","critical"])
    language = c4.multiselect("Language", ["EN","ES","RU","MIXED"])
    f1,f2,f3,f4 = st.columns(4)
    spain_only=f1.checkbox("Spain Priority only"); restricted_only=f2.checkbox("Restricted only")
    dead_only=f3.checkbox("Dead only"); needs_review=f4.checkbox("Needs review")
    screenshot_blocked=st.checkbox("Screenshot blocked only")
    filtered=[]
    for row in rows:
        haystack=" ".join([str(row.get("display_name") or ""),str(row.get("url") or ""),str(row.get("primary_category") or "")]).casefold()
        if categories and row.get("primary_category") not in categories: continue
        if risks and row.get("risk_level") not in risks: continue
        if language and row.get("spain_match_language") not in language: continue
        if spain_only and not row.get("spain_priority"): continue
        if restricted_only and row.get("storage_policy") != "metadata_only": continue
        if dead_only and row.get("status") != "dead": continue
        if needs_review and row.get("review_status") not in {"pending","needs_review"}: continue
        if screenshot_blocked and row.get("screenshot_policy") != "blocked": continue
        if search and search.casefold() not in haystack: continue
        filtered.append(row)
    st.caption(f"Showing {min(len(filtered),100)} of {len(filtered)} matching profiles.")
    if not filtered: st.info("No site profiles match these filters."); return
    for item in filtered[:100]:
        restricted=item.get("storage_policy")=="metadata_only"
        name=safe_category_label(item.get("primary_category")) if restricted else (item.get("display_name") or item.get("title") or "Unnamed site")
        badges=f'{category_badge(safe_category_label(item.get("primary_category")))} {risk_badge(item.get("risk_level"))} {status_badge(item.get("status"))}'
        if item.get("spain_priority"): badges += ' <span class="badge badge-red">🇪🇸 SPAIN PRIORITY</span>'
        st.markdown(f'<div class="analyst-card"><h3>{html.escape(name)}</h3>{badges}'
                    f'<div class="card-meta">{html.escape(item.get("explanation") or "Safe metadata profile")}</div></div>', unsafe_allow_html=True)
        left,right=st.columns([1,2])
        with left: _policy_preview(st,item,name)
        with right:
            if restricted:
                warning = "Restricted adult-risk page. Metadata only retained. No preview, snippet, screenshot, or content text is shown." if item.get("primary_category")=="adult_restricted" else "Restricted content. Metadata only retained. No preview, snippet, screenshot, title, or content text is shown."
                st.error(warning)
            else:
                _show_page_topics(st,item.get("topics_json"),item.get("keywords_json"))
            st.markdown("**Onion URL**"); st.code(item["url"],language=None)
            st.write("**Why classified this way:**",item.get("safety_reason") or "No strong category signal")
            st.write("**Found from:**",item.get("source_url") or item.get("source_summary") or "Manual seed")
            a,b,c=st.columns(3)
            a.metric("First seen",item.get("first_seen") or "Unknown")
            b.metric("Last checked",item.get("last_checked_at") or item.get("last_crawled") or "Not yet")
            c.metric("Priority",item.get("priority_score") or 0)
            if item.get("active") and item.get("queue_policy")!="blocked":
                if st.button("Live Check",key=f"live-profile-{item['id']}"):
                    storage.queue_live_check(item["url"]); query.clear(); st.success("Queued for an immediate full-policy check.")
            else: st.caption("Live Check is disabled because safety or dead-link policy makes this item inactive.")
        st.divider()


def _card_preview_item(card: dict) -> dict:
    item = dict(card)
    item["preview_path"] = None
    if card.get("storage_policy") == "metadata_only":
        return item
    for url_item in card.get("urls", []):
        preview = storage.get_page_preview(url_item["url"])
        if preview and preview.get("status") == "available":
            item["preview_path"] = preview.get("preview_path")
            item["screenshot_policy"] = "allowed"
            break
    return item


def _render_card_actions(st, card: dict, query, key_prefix: str) -> None:
    language = current_language(st)
    can_review = _can(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE)
    can_report = _can(st, dashboard_auth.CAPABILITY_REPORTS_CREATE)
    can_edit = _can(st, dashboard_auth.CAPABILITY_SITE_CARDS_EDIT)
    can_requeue = _can(st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE)
    if not any((can_review, can_report, can_edit, can_requeue)):
        st.info(_l(
            st,
            "Read-only session: evidence and history are available, but changes are disabled.",
            "Sesión de solo lectura: la evidencia y el historial están disponibles, pero los cambios están desactivados.",
        ))
    urls = card.get("urls", [])
    if card.get("primary_category") not in {"adult_filtered", "adult_restricted", "severe_abuse_risk"}:
        urls = [item for item in urls if item.get("primary_category") not in {
            "adult_filtered", "adult_restricted", "severe_abuse_risk"}]
    scope_url = st.checkbox(
        _l(st, "Advanced: apply action to one URL only", "Avanzado: aplicar la acción solo a una URL"),
        key=f"{key_prefix}-scope-{card['id']}",
    )
    selected_url_id = None
    if scope_url and urls:
        choices = {item["url"]: item["onion_url_id"] for item in urls}
        selected_url_id = choices[st.selectbox(
            _l(st, "Choose the one URL", "Elige una URL"), list(choices),
            key=f"{key_prefix}-url-{card['id']}"
        )]
    decisions = [
        (_l(st, "Relevant — keep monitoring", "Relevante — seguir monitorizando"), "keep"),
        (_l(st, "Not important — hide from review", "No importante — ocultar de revisión"), "ignored"),
        (_l(st, "Make report", "Crear informe"), "needs_report"),
        (_l(st, "Block / restrict", "Bloquear / restringir"), "blocked"),
    ]
    cols = st.columns(4)
    for col, (label, action) in zip(cols, decisions, strict=False):
        capability = (
            dashboard_auth.CAPABILITY_REPORTS_CREATE
            if action == "needs_report"
            else dashboard_auth.CAPABILITY_REVIEWS_MANAGE
        )
        if col.button(
            label,
            key=f"{key_prefix}-{card['id']}-{action}",
            width="stretch",
            disabled=not _can(st, capability),
        ) and _authorize_action(st, capability):
            if action == "needs_report" and not selected_url_id:
                site_dedupe.apply_card_review(card["id"], action)
                st.success(_l(st, "Site Card report created: ", "Informe de ficha creado: ") +
                           str(build_site_card_report(card['id'])))
            elif action == "needs_report" and selected_url_id:
                selected = next(item for item in urls if item["onion_url_id"] == selected_url_id)
                st.success(_l(st, "URL-only report created: ", "Informe de URL creado: ") +
                           str(build_url_report(selected['url'])))
            else:
                site_dedupe.apply_card_review(card["id"], action, selected_url_id)
                query.clear(); st.rerun()
    can_recheck = any(item.get("queue_policy") != "blocked" and item.get("storage_policy") != "metadata_only" for item in urls)
    if st.button(_l(st, "Recheck now", "Volver a comprobar"),
                 key=f"{key_prefix}-{card['id']}-live_check",
                 disabled=not can_recheck or not can_requeue) and _authorize_action(
                     st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
        site_dedupe.apply_card_review(card["id"], "live_check", selected_url_id)
        query.clear(); st.success(_l(st, "Queued for a full-policy recheck.",
                                     "Añadido a la cola para una comprobación completa."))
    st.markdown("#### " + ("Corregir la clasificación" if language == "es" else "Correct the classification"))
    st.caption(("Si la categoría automática es incorrecta, elige la correcta. El cambio se aplica a toda la ficha y queda registrado."
                if language == "es" else
                "If the automatic category is wrong, choose the correct one. The change applies to the whole Site Card and is saved in its change history."))
    current_category = card.get("primary_category") or "unknown"
    if current_category in {"adult_filtered", "adult_restricted", "severe_abuse_risk"}:
        st.warning(("Las categorías restringidas se revisan en Avanzado → Metadatos restringidos."
                    if language == "es" else
                    "Safety-restricted categories are reviewed from Advanced → Restricted Metadata."))
    else:
        options = site_dedupe.ANALYST_CATEGORY_OPTIONS
        selected_category = st.selectbox(
            "Categoría correcta" if language == "es" else "Correct category",
            options,
            index=options.index(current_category) if current_category in options else 0,
            format_func=lambda value: category_label(value, language),
            key=f"{key_prefix}-{card['id']}-manual-category",
            disabled=not can_edit,
        )
        if st.button("Guardar corrección" if language == "es" else "Save category correction",
                     key=f"{key_prefix}-{card['id']}-save-category",
                     disabled=not can_edit) and _authorize_action(
                         st, dashboard_auth.CAPABILITY_SITE_CARDS_EDIT):
            try:
                site_dedupe.apply_manual_category(card["id"], selected_category)
            except ValueError as exc:
                st.error(str(exc))
            else:
                query.clear()
                st.success("Categoría corregida." if language == "es" else "Category corrected and saved to the change history.")
                st.rerun()

    st.markdown("#### " + _l(st, "Set review importance", "Definir importancia de revisión"))
    st.caption(_l(st,
        "Importance controls how urgently this card is surfaced. It does not change the policy-driven risk level.",
        "La importancia controla con qué urgencia se muestra la ficha. No cambia el nivel de riesgo definido por la política."))
    importance_options = ["low", "normal", "elevated", "high", "critical"]
    current_importance = card.get("analyst_importance") or card.get("importance_level") or "normal"
    importance_choice = st.selectbox(
        _l(st, "Importance", "Importancia"), importance_options,
        index=importance_options.index(current_importance) if current_importance in importance_options else 1,
        format_func=lambda value: value_label(value, language),
        key=f"{key_prefix}-{card['id']}-importance",
        disabled=not can_edit,
    )
    analyst_note = st.text_input(
        _l(st, "Optional reviewer note", "Nota opcional de revisión"),
        value=str(card.get("analyst_notes") or ""), key=f"{key_prefix}-{card['id']}-importance-note",
        disabled=not can_edit,
    )
    importance_col, alert_col = st.columns(2)
    if importance_col.button(_l(st, "Save importance", "Guardar importancia"),
                             key=f"{key_prefix}-{card['id']}-save-importance",
                             width="stretch", disabled=not can_edit) and _authorize_action(
                                 st, dashboard_auth.CAPABILITY_SITE_CARDS_EDIT):
        site_dedupe.apply_manual_importance(card["id"], importance_choice, analyst_note)
        query.clear(); st.rerun()
    alerts_suppressed = bool(card.get("analyst_suppressed_alerts"))
    if alert_col.button(
        _l(st, "Resume card alerts" if alerts_suppressed else "Suppress duplicate card alerts",
           "Reanudar alertas" if alerts_suppressed else "Silenciar alertas duplicadas"),
        key=f"{key_prefix}-{card['id']}-toggle-alerts", width="stretch",
        disabled=not can_review,
    ) and _authorize_action(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
        site_dedupe.set_card_alert_suppressed(card["id"], not alerts_suppressed)
        query.clear(); st.rerun()


def _render_site_card(st, summary: dict, query, key_prefix: str = "card", actions: bool = False) -> None:
    language = current_language(st)
    restricted_summary = (_is_adult_item(summary) or _is_severe_item(summary))
    card = site_dedupe.get_site_card_detail(
        int(summary["id"]), url_limit=50, event_limit=10,
        include_dead=False, include_restricted=restricted_summary,
    ) or summary
    restricted = card.get("storage_policy") == "metadata_only"
    adult = _is_adult_item(card)
    severe = _is_severe_item(card)
    marketplace = card.get("primary_category") in MARKETPLACE_CATEGORIES
    tags = [tag for tag in parse_json(card.get("tags")) if tag and tag != "unknown"]
    urls = card.get("urls", [])
    if not adult and not severe:
        urls = [item for item in urls if item.get("primary_category") not in {
            "adult_filtered", "adult_restricted", "severe_abuse_risk"}]
    live_urls = [item for item in urls if item.get("status") not in {"dead","soft_dead"} and not item.get("dead_reason")]
    dead_urls = [item for item in urls if item.get("status") in {"dead","soft_dead"} or item.get("dead_reason")]
    sources = list(dict.fromkeys(item.get("source_url") for item in urls if item.get("source_url")))
    indicators = [] if restricted or marketplace else query("""SELECT DISTINCT i.indicator_type,i.value FROM indicators i
      JOIN indicator_links il ON il.indicator_id=i.id JOIN site_card_urls scu ON scu.url=il.source_ref
      WHERE scu.site_card_id=? LIMIT 100""", (card["id"],))
    preview_item = _card_preview_item(card)
    has_preview = bool(preview_item.get("preview_path"))
    title = (category_label(card.get("primary_category"), language) if (adult or severe or restricted)
             else (card.get("display_name") or (urls[0].get("onion_host") if urls else None)
                   or _l(st, "Unnamed onion site", "Sitio onion sin nombre")))
    crawl_state = "crawled" if live_urls else "dead"
    badges = (f'{category_badge(safe_category_label(card.get("primary_category")), category_label(card.get("primary_category"), language))} '
              f'{risk_badge(card.get("risk_level"), value_label(card.get("risk_level"), language))} '
              f'{importance_badge(card.get("importance_level"), _l(st, "Importance", "Importancia") + ": " + value_label(card.get("importance_level") or "normal", language))} '
              f'{review_badge(card.get("review_status"), value_label(card.get("review_status"), language))} '
              f'{status_badge(crawl_state, value_label(crawl_state, language))}')
    if card.get("spain_priority"):
        badges += f' <span class="badge badge-red">🇪🇸 {html.escape(_l(st, "SPAIN PRIORITY", "PRIORIDAD ESPAÑA"))}</span>'
    host = next((item.get("onion_host") for item in urls if item.get("onion_host")),
                card.get("canonical_site_id") or _l(st, "Unknown host", "Dominio desconocido"))
    summary_bits = [host]
    if len(urls) > 1: summary_bits.append(f"URLs {len(urls)}")
    if int(card.get("source_count") or 0) > 1:
        summary_bits.append(f"{_l(st, 'Sources', 'Fuentes')} {card['source_count']}")
    if card.get("last_checked_at"):
        summary_bits.append(f"{_l(st, 'Last checked', 'Última comprobación')} {card['last_checked_at']}")
    st.markdown(f'<div class="analyst-card"><h3>{html.escape(title)}</h3>{badges}'
                f'<div class="card-meta">{html.escape(" · ".join(summary_bits))}</div></div>', unsafe_allow_html=True)

    if adult:
        st.error(_l(st, "Restricted adult-risk page. Metadata only retained. No preview, snippet, screenshot, or content text is shown.",
                    "Página adulta restringida. Solo se conservan metadatos; no se muestran vista previa, fragmento, captura ni texto."))
        _policy_preview(st, preview_item, title)
    elif severe:
        st.error(_l(st, "Restricted content. Metadata only retained. No preview, snippet, screenshot, title, or content text is shown.",
                    "Contenido restringido. Solo se conservan metadatos; no se muestran vista previa, fragmento, captura, título ni texto."))
        _policy_preview(st, preview_item, title)
    elif restricted:
        st.error(_l(st, "Restricted by safety policy.", "Restringido por la política de seguridad."))
        _policy_preview(st, preview_item, title)
    elif any(item.get("status") == "blocked" or item.get("review_status") == "restricted" for item in urls):
        st.error(_l(st, "Restricted by safety policy.", "Restringido por la política de seguridad."))
    if dead_urls:
        st.warning(_l(st, "Dead or unavailable page — removed from active queue.",
                      "Página caída o no disponible — eliminada de la cola activa."))
    if marketplace:
        st.warning(_l(st,
            "Marketplace-related page. Passive metadata only. No interaction, login, forms, purchases, contact, downloads, or transaction details.",
            "Página relacionada con un mercado. Solo metadatos pasivos; sin interacción, acceso, formularios, compras, contacto, descargas ni transacciones."))
    if marketplace and card.get("adult_category_present"):
        st.warning(_l(st, "Contains restricted marketplace category: hidden metadata only",
                      "Contiene una categoría restringida del mercado: solo metadatos ocultos"))
    elif int(card.get("restricted_outbound_count") or 0):
        count = int(card.get("restricted_outbound_count") or 0)
        st.warning(_l(st, f"Contains restricted outbound links: {count} hidden",
                      f"Contiene enlaces restringidos: {count} ocultos"))

    compact = bool(st.session_state.get("compact_site_cards", True))
    with st.expander(tr("show_details", language), expanded=not compact):
        if has_preview and not restricted:
            _preview(st, preview_item.get("preview_path"), title)
        elif not restricted and card.get("screenshot_blocked_reason"):
            st.caption(_l(st, "Preview blocked: ", "Vista previa bloqueada: ") +
                       value_label(card["screenshot_blocked_reason"], language))
        if tags:
            st.write(_l(st, "**Tags:**", "**Etiquetas:**"),
                     ", ".join(value_label(str(tag), language) for tag in tags))
        if card.get("page_type") and card.get("page_type") != "unknown":
            st.write(_l(st, "**Page type:**", "**Tipo de página:**"),
                     value_label(card["page_type"], language))
        if marketplace and card.get("marketplace_type"):
            st.write(_l(st, "**Marketplace type:**", "**Tipo de mercado:**"),
                     value_label(card["marketplace_type"], language))
        if card.get("category_reason"):
            st.write(_l(st, "**Why this category:**", "**Motivo de la categoría:**"),
                     category_reason_label(card["category_reason"], language))
        if card.get("spain_match_language") and card.get("spain_match_language") != "UNKNOWN":
            st.write(_l(st, "**Language:**", "**Idioma:**"), card["spain_match_language"])
        if card.get("spain_priority") and card.get("spain_match_reason"):
            st.write(_l(st, "**Spain reason:**", "**Motivo de España:**"),
                     spain_reason_label(card["spain_match_reason"], language))
        if card.get("locale_paths_seen"):
            locales = parse_json(card.get("locale_paths_seen"))
            if locales:
                st.write(_l(st, "**Language variants seen:**", "**Variantes de idioma vistas:**"),
                         ", ".join(str(value).upper() for value in locales))
        if card.get("importance_reason"):
            st.write(_l(st, "**Importance reason:**", "**Motivo de importancia:**"),
                     value_label(card.get("importance_reason"), language))
        if card.get("page_type") in {"link_repository", "mixed_directory", "directory_page"}:
            st.write(_l(st, "**Safe links queued:**", "**Enlaces seguros en cola:**"),
                     sum(int(item.get("outbound_safe_queued") or 0) for item in urls))
            st.write(_l(st, "**Restricted links blocked:**", "**Enlaces restringidos bloqueados:**"),
                     int(card.get("restricted_outbound_count") or 0))
            st.write(_l(st, "**External onion seeds added:**", "**Semillas onion externas añadidas:**"),
                     sum(int(item.get("outbound_external_seeded") or 0) for item in urls))
        if int(card.get("spain_hit_count") or 0):
            st.write(_l(st, "**Spain hits:**", "**Coincidencias de España:**"), int(card["spain_hit_count"]))
            for hit in card.get("spain_hits", []):
                st.caption(f"{str(hit.get('hit_type') or 'unknown').replace('_',' ')} · "
                           f"{spain_reason_label(hit.get('spain_reason'), language)}")
        if int(card.get("mirror_count") or 0) > 0:
            st.markdown(_l(st, "**Shared mirror signals**", "**Señales de espejos compartidas**"))
            for item in live_urls:
                if item.get("url_role") in {"canonical","mirror","restricted"}:
                    st.code(item["url"], language=None)
                    if item.get("mirror_confidence") not in {None,"","unknown"}:
                        st.caption(_l(st, "Mirror confidence: ", "Confianza del espejo: ") +
                                   value_label(item["mirror_confidence"], language))
        meaningful_paths = [item for item in urls if item.get("path") not in {None,"","/"}]
        if meaningful_paths:
            st.markdown(_l(st, "**Discovered paths**", "**Rutas descubiertas**"))
            for item in meaningful_paths:
                st.write(f"`{item.get('path')}` — {category_label(item.get('primary_category'), language)}")
        if sources:
            st.markdown(_l(st, "**Source chain**", "**Cadena de origen**"))
            for source in sources: st.code(source, language=None)
        if indicators:
            st.markdown(_l(st, "**Indicators**", "**Indicadores**"))
            for indicator in indicators:
                st.write(f"**{indicator['indicator_type'].replace('_',' ').title()}:** {redact_sensitive(indicator['value'])}")
        if dead_urls:
            st.markdown(_l(st, "**Dead mirrors / inactive URLs**", "**Espejos caídos / URLs inactivas**"))
            for item in dead_urls:
                st.code(item["url"], language=None)
                st.caption(
                    f"{_l(st, 'Last checked', 'Última comprobación')}: {item.get('last_checked_at') or value_label('unknown', language)} · "
                    f"{_l(st, 'Reason', 'Motivo')}: {value_label(item.get('dead_reason') or 'unavailable', language)}"
                )
        if card.get("report_status") not in {None,"","not_prepared"}:
            st.write(_l(st, "**Report status:**", "**Estado del informe:**"),
                     value_label(card["report_status"], language))
        events = [event for event in card.get("events", []) if event.get("event_summary")]
        if events:
            st.markdown(_l(st, "**Recent audit activity**", "**Actividad reciente**"))
            for event in events[:5]: st.caption(f"{event.get('created_at')} — {event.get('event_summary')}")
        if not has_preview and not restricted:
            st.caption(_l(st, "No preview created", "No se creó vista previa"))

    if actions:
        _render_card_actions(st, card, query, key_prefix)
    else:
        with st.expander(tr("actions", language)):
            _render_card_actions(st, card, query, key_prefix)
    st.divider()


def _site_cards_page(st, query, review_only: bool = False) -> None:
    language = current_language(st)
    if review_only:
        _note(st, _l(
            st,
            "Make one decision at a time. This inbox contains only live, policy-visible Site Cards that still need an analyst action.",
            "Toma una decisión cada vez. Esta bandeja contiene solo fichas activas y visibles que aún necesitan una acción.",
        ))
    else:
        _note(st, _l(
            st,
            "Browse one deduplicated card per site. Open a card to inspect its full profile without losing your filters.",
            "Explora una ficha sin duplicados por sitio. Abre una ficha para revisar su perfil sin perder los filtros.",
        ))

    visible_scope = (
        "COALESCE(ui_hidden_default,0)=0 "
        "AND primary_category NOT IN ('severe_abuse_risk','adult_restricted','adult_filtered')"
    )
    review_scope_sql = (
        visible_scope
        + " AND live_url_count>0 "
          "AND review_status IN ('needs_review','needs_report','restricted')"
    )
    if review_only:
        review_total = _scalar(f"SELECT COUNT(*) FROM site_cards WHERE {review_scope_sql}")
        review_urgent = _scalar(
            f"SELECT COUNT(*) FROM site_cards WHERE {review_scope_sql} "
            "AND COALESCE(urgent_flag,0)=1"
        )
        review_report = _scalar(
            f"SELECT COUNT(*) FROM site_cards WHERE {review_scope_sql} "
            "AND review_status='needs_report'"
        )
        review_high_risk = _scalar(
            f"SELECT COUNT(*) FROM site_cards WHERE {review_scope_sql} "
            "AND lower(COALESCE(risk_level,'low')) IN ('high','critical','alto','critico')"
        )
        st.markdown(metric_strip([
            (_l(st, "Actionable", "Accionables"), review_total,
             _l(st, "Deduplicated cards", "Fichas deduplicadas"), "info"),
            (_l(st, "Urgent", "Urgentes"), review_urgent,
             _l(st, "Direct evidence first", "Evidencia directa primero"),
             "critical" if review_urgent else "muted"),
            (_l(st, "Report needed", "Necesitan informe"), review_report,
             _l(st, "Ready for reporting", "Preparadas para informe"),
             "warn" if review_report else "muted"),
            (_l(st, "High risk", "Riesgo alto"), review_high_risk,
             _l(st, "Risk is not importance", "Riesgo no es importancia"),
             "critical" if review_high_risk else "muted"),
        ]), unsafe_allow_html=True)
    else:
        directory_total = _scalar(
            f"SELECT COUNT(*) FROM site_cards WHERE {visible_scope}"
        )
        directory_active = _scalar(
            f"SELECT COUNT(*) FROM site_cards WHERE {visible_scope} AND live_url_count>0"
        )
        directory_high_risk = _scalar(
            f"SELECT COUNT(*) FROM site_cards WHERE {visible_scope} "
            "AND lower(COALESCE(risk_level,'low')) IN ('high','critical','alto','critico')"
        )
        directory_review = _scalar(
            f"SELECT COUNT(*) FROM site_cards WHERE {visible_scope} "
            "AND review_status IN ('needs_review','needs_report','restricted')"
        )
        st.markdown(metric_strip([
            (_l(st, "Total sites", "Sitios totales"), directory_total,
             _l(st, "Policy-visible", "Visibles por política"), "info"),
            (_l(st, "Active", "Activos"), directory_active,
             _l(st, "At least one live page", "Al menos una página activa"),
             "ok" if directory_active else "muted"),
            (_l(st, "High risk", "Riesgo alto"), directory_high_risk,
             _l(st, "High or critical", "Alto o crítico"),
             "critical" if directory_high_risk else "muted"),
            (_l(st, "Needs review", "Necesitan revisión"), directory_review,
             _l(st, "Actionable records", "Registros accionables"),
             "warn" if directory_review else "muted"),
        ]), unsafe_allow_html=True)
    spain_results_filter = "All results"
    spain_es = {}
    show_spain_tools = (not review_only and st.toggle(
        _l(st, "Show Spain filters and counters", "Mostrar filtros y contadores de España"),
        value=False, key="show-results-spain-tools",
        help=_l(st, "Open only when you need the Spain-specific result views.",
                "Abre esta sección solo cuando necesites vistas específicas de España."),
    ))
    if show_spain_tools:
        st.markdown("### " + _l(st, "Spain results", "Resultados de España"))
        spain_metrics = st.columns(4)
        spain_metrics[0].metric(_l(st, "All Spain-linked", "Todos vinculados"),
                                _scalar("SELECT COUNT(*) FROM site_cards WHERE spain_priority=1 AND ui_hidden_default=0 AND primary_category!='severe_abuse_risk'"))
        spain_metrics[1].metric(_l(st, "Sending from Spain", "Envíos desde España"),
                                _scalar("""SELECT COUNT(*) FROM site_cards WHERE spain_priority=1
                                  AND spain_context_tags LIKE '%trade_flow_from_spain%' AND ui_hidden_default=0
                                  AND primary_category!='severe_abuse_risk'"""))
        spain_metrics[2].metric(_l(st, "Sending to Spain", "Envíos hacia España"),
                                _scalar("""SELECT COUNT(*) FROM site_cards WHERE spain_priority=1
                                  AND spain_context_tags LIKE '%trade_flow_to_spain%' AND ui_hidden_default=0
                                  AND primary_category!='severe_abuse_risk'"""))
        spain_metrics[3].metric(_l(st, "Spain + weapons", "España + armas"),
                                _scalar("""SELECT COUNT(*) FROM site_cards WHERE spain_priority=1
                                  AND primary_category IN ('weapons_arms','marketplace_weapons') AND ui_hidden_default=0"""))
        spain_options = ["All results", "All Spain-linked", "Sending from Spain", "Sending to Spain",
                         "Spain + weapons", "Spain + drugs", "Spain + carding/fraud"]
        spain_es = {"All results": "Todos los resultados", "All Spain-linked": "Todos vinculados con España",
                    "Sending from Spain": "Envíos desde España", "Sending to Spain": "Envíos hacia España",
                    "Spain + weapons": "España + armas", "Spain + drugs": "España + drogas",
                    "Spain + carding/fraud": "España + carding/fraude"}
        spain_results_filter = st.selectbox(
            _l(st, "Filter Spain results", "Filtrar resultados de España"), spain_options,
            format_func=lambda value: spain_es.get(value, value) if language == "es" else value,
            key="results-spain-filter",
            on_change=_reset_card_results, args=(review_only,),
            help=_l(st, "Classified Spain results remain here after the temporary alert disappears.",
                    "Los resultados clasificados de España permanecen aquí cuando desaparece la alerta temporal."),
        )
    review_focus = "All actionable"
    if review_only:
        review_focus_options = ["All actionable", "Urgent", "Decision needed", "Report needed"]
        review_focus_es = {
            "All actionable": "Todo lo accionable",
            "Urgent": "Urgente",
            "Decision needed": "Decisión pendiente",
            "Report needed": "Informe pendiente",
        }
        review_focus = st.radio(
            _l(st, "Review focus", "Enfoque de revisión"),
            review_focus_options,
            horizontal=True,
            format_func=lambda value: review_focus_es.get(value, value) if language == "es" else value,
            key="review-inbox-focus",
            on_change=_reset_card_results,
            args=(review_only,),
            help=_l(
                st,
                "Choose the decision lane first; secondary filters remain available below.",
                "Elige primero la cola de decisión; los filtros secundarios quedan debajo.",
            ),
        )
    with st.container(key="rt-directory-command"):
        search = st.text_input(
            tr("search_sites", language),
            placeholder=_l(st, "Host, category, tag, Spain reason, source or review status",
                           "Dominio, categoría, etiqueta, motivo de España, origen o estado"),
            key=f"card-search-{review_only}",
            on_change=_reset_card_results, args=(review_only,))
        controls = st.columns([1.45, 2, .75])
        sort_options = ["Urgent first","Needs review first","Spain first","Highest risk","Highest importance","Newest first",
                        "Category","Most seen","Most sources","Recently checked"]
        sort_es = {"Urgent first":"Urgentes primero", "Needs review first":"Revisión primero",
                   "Spain first":"España primero", "Highest risk":"Mayor riesgo",
                   "Highest importance":"Mayor importancia", "Newest first":"Más recientes",
                   "Category":"Categoría", "Most seen":"Más vistos", "Most sources":"Más fuentes",
                   "Recently checked":"Revisados recientemente"}
        sort_mode = controls[0].selectbox(tr("sort", language), sort_options,
            format_func=lambda value: sort_es.get(value, value) if language == "es" else value,
            index=1 if review_only else 0,
            key=f"card-sort-{review_only}", on_change=_reset_card_results, args=(review_only,))
        # Every result-shaping control resets pagination before the next render.
        display_options = ["Compact list","Card view","Table view"]
        display_en = {"Compact list":"Compact", "Card view":"Cards", "Table view":"Table"}
        display_es = {"Compact list":"Lista compacta", "Card view":"Vista de fichas", "Table view":"Vista de tabla"}
        display_mode = controls[1].radio(tr("display", language), display_options, horizontal=True, index=0,
            format_func=lambda value: display_es.get(value, value) if language == "es" else display_en.get(value, value),
            key=f"card-display-{review_only}", on_change=_reset_card_results, args=(review_only,))
        page_size = controls[2].selectbox(tr("page_size", language), [25,50,100], index=1,
            key=f"card-page-size-{review_only}", on_change=_reset_card_results, args=(review_only,))
        load_large_table = False
        if display_mode == "Table view":
            load_large_table = st.checkbox(
                _l(st, "Load up to 500 summary rows on this table page", "Cargar hasta 500 filas resumidas en esta página"),
                value=False,
                key=f"card-large-table-{review_only}",
                help="This loads summaries only. URL history, events, and indicators remain unloaded.",
            )

    filter_key = f"category-filter-{review_only}"
    selected_category = st.session_state.get(filter_key, "All")
    category_counts = site_dedupe.get_site_card_category_counts(review_only=review_only)
    total_for_counts = sum(category_counts.values())
    active_filter_count = sum((
        selected_category != "All",
        st.session_state.get(f"priority-filter-{review_only}", "All") != "All",
        st.session_state.get(f"operational-filter-{review_only}", "All") != "All",
        st.session_state.get(f"risk-filter-{review_only}", "All") != "All",
        st.session_state.get(f"importance-filter-{review_only}", "All") != "All",
        st.session_state.get(f"review-filter-{review_only}", "All") != "All",
        st.session_state.get(f"report-filter-{review_only}", "All") != "All",
        st.session_state.get(f"title-filter-{review_only}", "All") != "All",
        st.session_state.get(f"age-filter-{review_only}", "All") != "All",
        bool(st.session_state.get(f"duplicates-filter-{review_only}", False)),
    ))
    filter_label = _l(st, "Filters", "Filtros") + (
        f" · {active_filter_count} {_l(st, 'active', 'activos')}" if active_filter_count else ""
    )
    with st.expander(filter_label, expanded=False):
        priority_options = (
            ["All", "Urgent", "High risk", "Spain Priority"]
            if review_only else
            ["All", "Urgent", "Marketplaces", "Leaks / credentials", "Weapons / drugs",
             "Forums / directories", "High risk", "High importance", "Elevated importance",
             "Dead / unavailable", "Needs review", "Spain Priority", "Spain + Russian context"]
        )
        option_es = {"All":"Todo", "Spain Priority":"Prioridad España", "Spain + Russian context":"España + contexto ruso",
                     "Marketplaces":"Mercados", "Leaks / credentials":"Filtraciones / credenciales",
                      "Weapons / drugs":"Armas / drogas", "Forums / directories":"Foros / directorios",
                      "High risk":"Riesgo alto", "Dead / unavailable":"Caídos / no disponibles",
                      "Needs review":"Necesita revisión", "Urgent": "Urgente"}
        operational_options = (
            ["All", "Live"] if review_only
            else ["All","Queued","Crawled","Retry","Live","Dead","Soft dead","Monitor only"]
        )
        operational_es = {"All":"Todo", "Queued":"En cola", "Crawled":"Rastreado", "Retry":"Reintentar",
                          "Live":"Activo", "Dead":"Caído", "Soft dead":"Probablemente caído", "Monitor only":"Solo monitorizar"}
        filter_controls = st.columns(3, gap="small")
        priority_filter = filter_controls[0].selectbox(
            _l(st, "Priority filter", "Filtro de prioridad"), priority_options,
            format_func=lambda value: option_es.get(value, value) if language == "es" else value,
            key=f"priority-filter-{review_only}", on_change=_reset_card_results, args=(review_only,))
        operational = filter_controls[1].selectbox(
            _l(st, "Operational filter", "Filtro operativo"), operational_options,
            format_func=lambda value: operational_es.get(value, value) if language == "es" else value,
            key=f"operational-filter-{review_only}", on_change=_reset_card_results, args=(review_only,))
        risk_filter = filter_controls[2].selectbox(_l(st, "Policy risk", "Riesgo"),
            ["All", "low", "medium", "high", "critical"], key=f"risk-filter-{review_only}",
            format_func=lambda value, lang=language: ("Todo" if lang == "es" else "All") if value == "All" else value_label(value, lang),
            on_change=_reset_card_results, args=(review_only,))
        importance_filter = review_filter = report_filter = title_filter = age_filter = "All"
        duplicates_only = False
        detail_controls = st.columns(3, gap="small")
        importance_filter = detail_controls[0].selectbox(_l(st, "Importance", "Importancia"),
            ["All", "low", "normal", "elevated", "high", "critical"], key=f"importance-filter-{review_only}",
            format_func=lambda value, lang=language: ("Todo" if lang == "es" else "All") if value == "All" else value_label(value, lang),
            on_change=_reset_card_results, args=(review_only,))
        review_filter = detail_controls[1].selectbox(_l(st, "Review status", "Estado de revisión"),
            ["All", "pending", "needs_review", "relevant", "needs_report", "reported", "false_positive", "blocked"],
            key=f"review-filter-{review_only}",
            format_func=lambda value, lang=language: ("Todo" if lang == "es" else "All") if value == "All" else value_label(value, lang),
            on_change=_reset_card_results, args=(review_only,))
        report_filter = detail_controls[2].selectbox(_l(st, "Report", "Informe"),
            ["All", "No report", "Ready", "Needs update", "Failed"], key=f"report-filter-{review_only}",
            on_change=_reset_card_results, args=(review_only,))
        final_controls = st.columns(2, gap="small")
        if review_only:
            age_filter = final_controls[0].selectbox(
                _l(st, "Age", "Antigüedad"),
                ["All", "New 24h", "Last 7 days", "Older than 7 days"],
                key=f"age-filter-{review_only}",
                format_func=lambda value: ({
                    "All": "Todo", "New 24h": "Nuevas · 24 h",
                    "Last 7 days": "Últimos 7 días", "Older than 7 days": "Más de 7 días",
                }.get(value, value) if language == "es" else value),
                on_change=_reset_card_results, args=(review_only,),
            )
            review_categories = ["All"] + sorted(category_counts)
            if selected_category not in review_categories:
                st.session_state[filter_key] = "All"
            selected_category = final_controls[1].selectbox(
                _l(st, "Content category", "Categoría de contenido"),
                review_categories,
                key=filter_key,
                format_func=lambda value: (
                    _l(st, "All categories", "Todas las categorías")
                    if value == "All"
                    else f"{category_label(value, language)} ({category_counts[value]})"
                ),
                on_change=_reset_card_results, args=(review_only,),
            )
            st.caption(_l(
                st,
                "Risk describes content policy. Analyst importance describes review priority; they remain separate.",
                "Riesgo describe la política de contenido. Importancia indica prioridad; se mantienen separados.",
            ))
        else:
            title_filter = final_controls[0].selectbox(_l(st, "Site name", "Nombre del sitio"),
                ["All", "Reviewer title", "Generated only"], key=f"title-filter-{review_only}",
                on_change=_reset_card_results, args=(review_only,))
            duplicates_only = final_controls[1].checkbox(
                _l(st, "Only possible duplicates", "Solo posibles duplicados"),
                key=f"duplicates-filter-{review_only}", on_change=_reset_card_results,
                args=(review_only,))

        if not review_only:
            selected_label = (_l(st, "All", "Todo") if selected_category == "All"
                              else category_label(selected_category, language))
            st.markdown(f"**{tr('categories', language)} · {selected_label}**")
            with st.container():
                if st.button(f"{_l(st, 'All', 'Todo')} ({total_for_counts})",
                             key=f"all-categories-{review_only}", width="stretch"):
                    st.session_state[filter_key] = "All"; _reset_card_results(review_only); st.rerun()
                group_es = {"Discovery": "Descubrimiento", "Neutral / informational": "Neutral / informativo",
                            "Marketplaces": "Mercados", "Risk topics": "Temas de riesgo"}
                shown_category_groups = 0
                for group, categories in CATEGORY_GROUPS.items():
                    available_categories = [(category, category_counts.get(category, 0))
                                            for category in categories if category_counts.get(category, 0)]
                    if not available_categories:
                        continue
                    shown_category_groups += 1
                    st.caption(group_es.get(group, group) if language == "es" else group)
                    category_columns = st.columns(min(4, len(available_categories)), gap="small")
                    for index, (category, count) in enumerate(available_categories):
                        if category_columns[index % len(category_columns)].button(
                                f"{category_label(category, language)} ({count})",
                                key=f"filter-{review_only}-{category}", width="stretch"):
                            st.session_state[filter_key] = category; _reset_card_results(review_only); st.rerun()
                if not shown_category_groups:
                    st.caption(_l(st, "Categories appear after the first sites are classified.",
                                  "Las categorías aparecerán cuando se clasifiquen los primeros sitios."))
                adult_hidden = _scalar("SELECT COUNT(*) FROM onion_urls WHERE primary_category='adult_filtered'")
                severe_hidden = _scalar("SELECT COUNT(*) FROM site_cards WHERE primary_category='severe_abuse_risk'")
                if adult_hidden or severe_hidden:
                    st.caption(f"{_l(st, 'Policy-hidden', 'Ocultos por política')}: "
                               f"{_l(st, 'adult', 'adulto')} {adult_hidden} · "
                               f"{_l(st, 'severe', 'grave')} {severe_hidden}")

        if spain_results_filter != "All results":
            priority_filter = spain_results_filter
        if review_focus == "Urgent":
            priority_filter = "Urgent"
        elif review_focus == "Decision needed":
            review_filter = "needs_review"
        elif review_focus == "Report needed":
            review_filter = "needs_report"
        if priority_filter != "All":
            active_label = option_es.get(priority_filter, spain_es.get(priority_filter, priority_filter)) if language == "es" else priority_filter
            active_scope, clear_scope = st.columns([4, 1])
            active_scope.info(_l(st, "Showing only: ", "Mostrando solo: ") + active_label)
            clear_scope.button(_l(st, "Clear", "Quitar"), key=f"clear-results-filter-{review_only}",
                               on_click=_clear_results_scope, width="stretch")
        st.caption(_l(st, "Duplicate URL rows and restricted child pages stay grouped inside Site Cards.",
                      "Las URLs duplicadas y páginas hijas restringidas quedan agrupadas dentro de las fichas."))
    results = st.container()
    sort_key = {"Urgent first":"urgent","Needs review first":"needs_review","Spain first":"spain","Highest risk":"risk",
        "Highest importance":"importance",
        "Newest first":"newest","Category":"category","Most seen":"seen","Most sources":"sources",
        "Recently checked":"checked"}[sort_mode]
    page_key = f"card-page-{review_only}"
    page_number = max(1, int(st.session_state.get(page_key, 1)))
    query_limit = 500 if (display_mode == "Table view" and load_large_table) else page_size
    visible = site_dedupe.get_site_card_summaries(
        review_only=review_only, category=None if selected_category == "All" else selected_category,
        priority_filter=None if priority_filter == "All" else priority_filter,
        operational_filter=None if operational == "All" else operational, search=search or None,
        risk_filter=risk_filter, importance_filter=importance_filter, review_filter=review_filter,
        report_filter=report_filter, title_filter=title_filter, age_filter=age_filter,
        duplicates_only=duplicates_only,
        sort=sort_key, limit=query_limit, offset=(page_number - 1) * query_limit,
        include_monitor=bool(st.session_state.get("show_monitor_only_cards", True)) and not review_only,
    )
    st.session_state["_perf_cards_fetched"] = len(visible)
    st.session_state["_perf_render_mode"] = display_mode
    total = int(visible[0].get("total_count") or 0) if visible else 0
    total_pages = max(1, (total + query_limit - 1) // query_limit)
    if page_number > total_pages:
        st.session_state[page_key] = total_pages
        st.session_state.pop(f"card-page-picker-{review_only}", None)
        st.rerun()

    with results:
        st.caption(_l(
            st,
            f"Showing {len(visible)} of {total} matching Site Card(s) · Page {page_number} of {total_pages}. Restricted and duplicate child rows stay hidden.",
            f"Mostrando {len(visible)} de {total} fichas · Página {page_number} de {total_pages}. Las URLs restringidas y duplicadas permanecen ocultas.",
        ))
        if total_pages > 1:
            nav = st.columns([.75, 1.35, .75, 5], gap="small")
            if nav[0].button(tr("previous", language), disabled=page_number <= 1, key=f"cards-prev-{review_only}"):
                st.session_state[page_key] = page_number - 1; st.rerun()
            selected_page = nav[1].number_input(
                _l(st, "Page number", "Número de página"), min_value=1, max_value=total_pages, value=page_number,
                step=1, key=f"card-page-picker-{review_only}",
            )
            if int(selected_page) != page_number:
                st.session_state[page_key] = int(selected_page); st.rerun()
            if nav[2].button(tr("next", language), disabled=page_number >= total_pages, key=f"cards-next-{review_only}"):
                st.session_state[page_key] = page_number + 1; st.rerun()
        if not visible:
            if total_for_counts:
                if review_only:
                    st.success(_l(
                        st,
                        "No actionable Site Cards match this review lane. Try another lane or clear the secondary filters.",
                        "Ninguna ficha accionable coincide con esta cola. Prueba otra cola o quita los filtros secundarios.",
                    ))
                else:
                    st.warning(_l(st,
                        f"No cards match the current filters. {total_for_counts} policy-visible card(s) still exist. Clear the filters, enable monitor-only cards, or choose the relevant dead/soft-dead status.",
                        f"Ninguna ficha coincide con los filtros actuales. Aún existen {total_for_counts} fichas visibles por política. Quita filtros, activa las fichas en monitorización o elige el estado caído correspondiente."))
            else:
                st.info(_l(st,
                    "No Site Cards have been created yet. This is a true empty result, not a hidden filter page.",
                    "Todavía no se ha creado ninguna ficha. Es un resultado realmente vacío, no una página ocultada por filtros."))
            return
        if display_mode == "Table view":
            import pandas as pd
            columns = {"status": _l(st, "Status", "Estado"), "name": _l(st, "Site", "Sitio"),
                       "host": _l(st, "Onion host", "Dominio onion"),
                       "category": _l(st, "Category", "Categoría"), "risk": _l(st, "Risk", "Riesgo"),
                       "importance": _l(st, "Importance", "Importancia"),
                       "spain": _l(st, "Spain", "España"), "review": _l(st, "Review", "Revisión")}
            table = [{columns["status"]: value_label("live" if card.get("live_url_count") else "dead", language),
                columns["name"]: card.get("analyst_title") or card.get("display_name") or category_label(card.get("primary_category"), language),
                columns["host"]: mask_onion_address(card.get("representative_host") or card.get("canonical_site_id")),
                columns["category"]: category_label(card.get("primary_category"), language),
                columns["risk"]: value_label(card.get("risk_level"), language),
                columns["importance"]: value_label(card.get("importance_level") or "normal", language),
                columns["spain"]: bool(card.get("spain_priority")),
                columns["review"]: value_label(card.get("review_status"), language)} for card in visible[:500]]
            st.dataframe(pd.DataFrame(table), width="stretch", hide_index=True, height=560)
            table_choices = {
                f"{safe_display_title(card.get('analyst_title'), card.get('display_name'), fallback=_l(st, 'Unnamed site', 'Sitio sin nombre'))} · "
                f"{mask_onion_address(card.get('representative_host') or card.get('canonical_site_id'))} · "
                f"{category_label(card.get('primary_category'), language)}": int(card["id"])
                for card in visible[:500]
            }
            selected_table_label = st.selectbox(
                _l(st, "Select a result to open", "Selecciona un resultado para abrir"),
                list(table_choices), key=f"table-card-selection-{review_only}",
            )
            st.button(_l(st, "Open selected Site Card", "Abrir la ficha seleccionada"),
                      key=f"table-open-card-{review_only}", type="primary", width="stretch",
                      on_click=site_directory.open_card,
                      args=(table_choices[selected_table_label], review_only))
        elif display_mode == "Card view":
            grid = st.columns(3, gap="small")
            for index, card in enumerate(visible):
                with grid[index % 3]:
                    site_directory.render_card(st, card, review_only=review_only)
        else:
            for card in visible[:100]:
                host = card.get("representative_host") or card.get("representative_url") or card.get("canonical_site_id")
                name = safe_display_title(
                    card.get("analyst_title"), card.get("display_name"),
                    fallback=_l(st, "Unnamed site", "Sitio sin nombre"),
                )
                with st.container(key=f"rt-site-row-{card['id']}"):
                    cols = st.columns([3.2, 2, 2, .75], gap="small")
                    cols[0].markdown(
                        f'<div class="rt-record-identity"><strong>{html.escape(str(name))}</strong>'
                        f'<code>{html.escape(mask_onion_address(host))}</code></div>',
                        unsafe_allow_html=True,
                    )
                    cols[1].markdown(
                        category_badge(
                            safe_category_label(card.get("primary_category")),
                            category_label(card.get("primary_category"), language),
                        ),
                        unsafe_allow_html=True,
                    )
                    cols[1].caption(value_label(card.get("review_status") or "pending", language))
                    cols[2].markdown(
                        (spain_flag_badge(_l(st, "Spain-linked", "Vinculado con España")) + " "
                         if card.get("spain_priority") else "") +
                        risk_badge(card.get("risk_level"),
                                   value_label(card.get("risk_level"), language)) + " " +
                        importance_badge(card.get("importance_level"),
                                         value_label(card.get("importance_level") or "normal", language)),
                        unsafe_allow_html=True,
                    )
                    cols[2].caption(
                        _l(st, "Live", "Activo") if card.get("live_url_count")
                        else _l(st, "Unavailable", "No disponible")
                    )
                    cols[3].button(
                        _l(st, "Open", "Abrir"), key=f"compact-review-{review_only}-{card['id']}",
                        on_click=site_directory.open_card, args=(int(card["id"]), review_only),
                    )
        # Selected cards are rendered once as a full-page drill-down after the
        # active list. Cards opened from Results, Spain, Quality Center, and
        # Home therefore share the same state and back-navigation behavior.


def _simple_review(st, query) -> None:
    st.markdown("## Review Findings")
    _note(st, "Review safe metadata and choose one action. Restricted cards never reveal their title, page text, snippet, or screenshot.")
    rows = query("""SELECT ou.*,sp.display_name,sp.explanation,pp.preview_path,pt.topics_json,pt.keywords_json,
        h.id AS hit_id,h.snippet,h.indicators_json,h.passive_exposures_json
        FROM onion_urls ou LEFT JOIN site_profiles sp ON sp.url=ou.url
        LEFT JOIN page_previews pp ON pp.url=ou.url LEFT JOIN page_topics pt ON pt.url=ou.url
        LEFT JOIN onion_hits h ON h.id=(SELECT id FROM onion_hits WHERE url=ou.url ORDER BY ts DESC LIMIT 1)
        WHERE ou.review_status IN ('pending','needs_review','restricted','needs_report')
        ORDER BY ou.priority_score DESC,ou.first_seen DESC LIMIT 200""")
    if not rows:
        st.success("Nothing currently needs your review.")
        return
    for item in rows:
        restricted=item.get("storage_policy")=="metadata_only"
        name=safe_category_label(item.get("primary_category")) if restricted else (item.get("display_name") or item.get("title") or "Unnamed site")
        badges=f'{category_badge(safe_category_label(item.get("primary_category")))} {risk_badge(item.get("risk_level"))}'
        if item.get("spain_priority"): badges+=' <span class="badge badge-red">🇪🇸 SPAIN PRIORITY</span>'
        st.markdown(f'<div class="analyst-card"><h3>{html.escape(name)}</h3>{badges}'
                    f'<div class="card-meta">{html.escape(item.get("explanation") or "Policy-classified finding")}</div></div>',unsafe_allow_html=True)
        left, right = st.columns([3, 1])
        with left:
            st.write("**Category:**",safe_category_label(item.get("primary_category")))
            st.write("**Why it matters:**",item.get("safety_reason") or "Needs human review")
            st.write("**Source:**",item.get("source_url") or "Manual seed")
            st.code(item["url"],language=None)
            if restricted:
                st.error("Restricted metadata-only item. No preview, snippet, screenshot, unsafe title, or content text is shown.")
            else:
                _show_page_topics(st,item.get("topics_json"),item.get("keywords_json"))
                st.info(redact_sensitive((item.get("snippet") or "No safe excerpt was saved.")[:700]))
        with right: _policy_preview(st,item,name)
        cols = st.columns(5)
        actions = [("Keep", "relevant", "keep"), ("Ignore", "false_positive", "ignored"),
                   ("Prepare report", "needs_report", "needs_report"), ("Block", "blocked", "blocked")]
        for col, (label, status, spain_status) in zip(cols, actions, strict=False):
            if col.button(label, key=f"simple-review-{item['id']}-{status}", width="stretch"):
                storage.set_review_status("onion_url", item["id"], status)
                if item.get("spain_priority"): storage.set_spain_review_status(item["url"], spain_status)
                if status == "needs_report":
                    st.success(f"Safe report created: {build_url_report(item['url'])}")
                else:
                    query.clear(); st.rerun()
        if item.get("active") and item.get("queue_policy")!="blocked":
            if cols[4].button("Live Check",key=f"review-live-{item['id']}",width="stretch"):
                storage.queue_live_check(item["url"]); query.clear(); st.success("Queued for full-policy Live Check.")
        st.divider()


def _simple_related_sites(st, query) -> None:
    language = current_language(st)
    st.markdown(_l(st, "## Related sites", "## Sitios relacionados"))
    _note(st, _l(
        st,
        "The system puts sites in the same group when they share visible clues such as the same "
        "wording, address, contact name, or page fingerprint. A group is a lead to review—not proof "
        "of who runs the sites.",
        "El sistema agrupa sitios cuando comparten pistas visibles, como el mismo texto, dirección, "
        "nombre de contacto o huella de página. Un grupo es una pista para revisar; no demuestra "
        "quién gestiona los sitios.",
    ))
    clusters = query("""SELECT mc.*,COUNT(mu.id) AS site_count FROM mirror_clusters mc
        LEFT JOIN mirror_urls mu ON mu.cluster_id=mc.id GROUP BY mc.id ORDER BY mc.last_seen DESC LIMIT 200""")
    if not clusters:
        st.info(_l(
            st,
            "No related-site groups have been found yet. Groups appear after more than one checked "
            "site shares useful clues.",
            "Todavía no se han encontrado grupos de sitios relacionados. Aparecerán cuando varios "
            "sitios comprobados compartan pistas útiles.",
        ))
        return
    type_names = {
        "leak": ("Leak-related pages", "Páginas relacionadas con filtraciones"),
        "recruitment": ("Recruitment-related pages", "Páginas relacionadas con reclutamiento"),
        "cyber": ("Cyber-related pages", "Páginas relacionadas con ciberseguridad"),
        "propaganda": ("Propaganda-related pages", "Páginas relacionadas con propaganda"),
        "weapons_trafficking_context": (
            "Weapons-trafficking context", "Contexto de tráfico de armas"
        ),
        "unknown": ("Unclear relationship", "Relación no determinada"),
    }
    for cluster in clusters:
        profile = parse_json(cluster.get("attribution_profile_json"), {})
        confidence = profile.get("confidence_level", "LOW")
        shared = parse_json(cluster.get("shared_indicators_json"))
        type_pair = type_names.get(cluster.get("cluster_type"), type_names["unknown"])
        group_title = _l(st, "Related group", "Grupo relacionado")
        site_count_label = _l(st, "sites", "sitios")
        clue_count_label = _l(st, "shared clues", "pistas compartidas")
        changed_label = _l(st, "Last changed", "Último cambio")
        st.markdown(
            f'<div class="analyst-card"><h3>{group_title} #{cluster["id"]} · '
            f'{html.escape(type_pair[1 if language == "es" else 0])}</h3>'
            f'{risk_badge(
                cluster.get("risk_level"),
                value_label(cluster.get("risk_level"), language) if language == "es" else None,
            )} '
            f'{confidence_badge(
                confidence, value_label(confidence, language) if language == "es" else None
            )}'
            f'<div class="card-meta">{cluster.get("site_count",0)} {site_count_label} · '
            f'{len(shared)} {clue_count_label} · {changed_label} '
            f'{_fmt(cluster.get("last_seen"))}</div></div>',
            unsafe_allow_html=True,
        )
        st.caption(_l(
            st,
            "Related group = pages sharing visible clues · Match strength = how many clues repeat · "
            "It does not identify the owner or server location.",
            "Grupo relacionado = páginas que comparten pistas visibles · Fuerza de la coincidencia = "
            "cuántas pistas se repiten · No identifica al propietario ni la ubicación del servidor.",
        ))
        st.write(cluster.get("summary") or _l(
            st,
            "These sites were grouped because the collector found repeated passive clues.",
            "Estos sitios se agruparon porque el recopilador encontró pistas pasivas repetidas.",
        ))
        match_texts = {
            "LOW": (
                "A weak possible relationship. Monitor for more repeated clues.",
                "Una posible relación débil. Conviene esperar más pistas repetidas.",
            ),
            "MEDIUM": (
                "Several clues repeat across the sites. This deserves human review.",
                "Varias pistas se repiten entre los sitios. Merece una revisión manual.",
            ),
            "HIGH": (
                "Many strong clues repeat, but this still does not prove ownership or identity.",
                "Se repiten muchas pistas sólidas, pero no demuestran propiedad ni identidad.",
            ),
        }
        match_pair = match_texts.get(
            str(confidence).upper(),
            ("Not enough information yet.", "Todavía no hay información suficiente."),
        )
        st.info(
            f"**{_l(st, 'How strong is the match?', '¿Qué solidez tiene la coincidencia?')}** "
            f"{match_pair[1 if language == 'es' else 0]}"
        )
        with st.expander(_l(st, "Show sites and shared clues", "Mostrar sitios y pistas compartidas")):
            sites = query("""SELECT mu.url,COALESCE(sp.display_name,mu.title,'Unnamed site') AS name,
                COALESCE(sp.category,'Unknown / Miscellaneous') AS category,pp.preview_path,pt.topics_json,pt.keywords_json
                FROM mirror_urls mu LEFT JOIN site_profiles sp ON sp.url=mu.url
                LEFT JOIN page_previews pp ON pp.url=mu.url LEFT JOIN page_topics pt ON pt.url=mu.url
                WHERE mu.cluster_id=? ORDER BY mu.last_seen DESC""", (cluster["id"],))
            for site in sites:
                preview_col, text_col = st.columns([1, 3])
                with preview_col: _preview(st, site.get("preview_path"), site["name"])
                with text_col:
                    site_name = site["name"]
                    if site_name == "Unnamed site":
                        site_name = _l(st, "Unnamed site", "Sitio sin nombre")
                    category = category_label(site["category"], language)
                    escaped_site_name = (
                        html.escape(str(site_name))
                        if language == "es"
                        else html.escape(str(site['name']))
                    )
                    st.markdown(
                        f"**{escaped_site_name}** "
                        f"{category_badge(
                            site['category'], category if language == 'es' else None
                        )}",
                        unsafe_allow_html=True,
                    )
                    st.code(site["url"], language=None)
                    _show_page_topics(st, site.get("topics_json"), site.get("keywords_json"))
            st.markdown(_l(st, "**Shared clues**", "**Pistas compartidas**"))
            for clue in shared[:30]: st.text(redact_sensitive(str(clue).replace("_", " ")))
        if st.button(
            _l(st, "Create a report for this group", "Crear un informe de este grupo"),
            key=f"simple-report-cluster-{cluster['id']}",
        ):
            st.success(_l(
                st,
                f"Report created: {build_cluster_report(cluster['id'])}",
                f"Informe creado: {build_cluster_report(cluster['id'])}",
            ))
        st.divider()


CLUE_NAMES = {"telegram_handle":"Telegram name","onion_url":"Onion link","onion_domain":"Onion domain",
    "clearnet_url":"Regular website link","email":"Email address","wallet_btc":"Bitcoin wallet",
    "wallet_eth":"Ethereum wallet","pgp_key_block":"PGP identity marker","tox_id":"Tox contact marker",
    "session_id":"Session contact marker","matrix_id":"Matrix contact","jabber_id":"Jabber contact",
    "username":"Repeated username","victim_or_org_name":"Organization name","file_name":"Visible filename",
    "mirror_phrase":"Mirror wording"}
CLUE_NAMES_ES = {
    "telegram_handle": "Nombre de Telegram", "onion_url": "Enlace onion",
    "onion_domain": "Dominio onion", "clearnet_url": "Enlace web público",
    "email": "Dirección de correo", "wallet_btc": "Cartera Bitcoin",
    "wallet_eth": "Cartera Ethereum", "pgp_key_block": "Marcador de identidad PGP",
    "tox_id": "Marcador de contacto Tox", "session_id": "Marcador de contacto Session",
    "matrix_id": "Contacto Matrix", "jabber_id": "Contacto Jabber",
    "username": "Nombre de usuario repetido", "victim_or_org_name": "Nombre de organización",
    "file_name": "Nombre de archivo visible", "mirror_phrase": "Texto de espejo",
}


def _simple_clues(st, query) -> None:
    language = current_language(st)
    st.markdown(_l(st, "## Repeated clues", "## Pistas repetidas"))
    _note(st, _l(
        st,
        "A clue is a public detail seen on one or more pages—for example an onion address, contact "
        "name, wallet, email, filename, or repeated phrase. Clues help connect pages; they are not "
        "instructions to contact anyone.",
        "Una pista es un dato público visto en una o varias páginas, por ejemplo una dirección onion, "
        "un nombre de contacto, una cartera, un correo, un archivo o una frase repetida. Las pistas "
        "ayudan a relacionar páginas; no son instrucciones para contactar con nadie.",
    ))
    rows = query("""SELECT i.id,i.indicator_type,i.value,i.confidence,i.first_seen,i.last_seen,
        COUNT(DISTINCT l.source_ref) AS site_count,COUNT(DISTINCT mu.cluster_id) AS group_count
        FROM indicators i LEFT JOIN indicator_links l ON l.indicator_id=i.id
        LEFT JOIN mirror_urls mu ON mu.url=l.source_ref GROUP BY i.id ORDER BY site_count DESC,i.last_seen DESC LIMIT 1000""")
    c1, c2 = st.columns([2, 1])
    search = c1.text_input(
        _l(st, "Search clues", "Buscar pistas"),
        placeholder=_l(
            st,
            "Part of an address, name, email, or phrase",
            "Parte de una dirección, nombre, correo o frase",
        ),
    )
    choices = sorted({r["indicator_type"] for r in rows})
    clue_type = c2.selectbox(
        _l(st, "Kind of clue", "Tipo de pista"),
        ["All"] + choices,
        format_func=lambda value: (
            _l(st, "All kinds", "Todos los tipos")
            if value == "All"
            else (
                CLUE_NAMES_ES.get(value, value_label(value, language))
                if language == "es"
                else CLUE_NAMES.get(value, value.replace("_", " ").title())
            )
        ),
    )
    filtered = [r for r in rows if (clue_type == "All" or r["indicator_type"] == clue_type)
        and (not search or search.casefold() in str(r.get("value", "")).casefold())]
    if not filtered:
        st.info(_l(st, "No clues match this search.", "Ninguna pista coincide con esta búsqueda."))
        return
    for clue in filtered[:100]:
        name = (
            CLUE_NAMES_ES.get(clue["indicator_type"], value_label(clue["indicator_type"], language))
            if language == "es"
            else CLUE_NAMES.get(
                clue["indicator_type"], clue["indicator_type"].replace("_", " ").title()
            )
        )
        confidence = (
            "HIGH" if clue.get("confidence", 0) >= .8
            else "MEDIUM" if clue.get("confidence", 0) >= .5
            else "LOW"
        )
        st.markdown(f'<div class="analyst-card"><h3>{html.escape(name)}</h3>'
                    f'{confidence_badge(
                        confidence, value_label(confidence, language) if language == "es" else None
                    )}'
                    f'<div class="card-meta">'
                    f'{_l(st, "Seen on", "Vista en")} {clue.get("site_count",0)} '
                    f'{_l(st, "site(s) and", "sitio(s) y")} {clue.get("group_count",0)} '
                    f'{_l(st, "related group(s)", "grupo(s) relacionado(s)")}</div></div>',
                    unsafe_allow_html=True)
        st.caption(_l(
            st,
            "Why this matters: a clue becomes more useful when the same value appears on different "
            "pages or in different related-site groups.",
            "Por qué importa: una pista resulta más útil cuando el mismo valor aparece en páginas "
            "distintas o en varios grupos relacionados.",
        ))
        st.code(
            redact_sensitive(clue.get("value") or _l(st, "Unavailable", "No disponible")),
            language=None,
        )
        with st.expander(_l(st, "Where was this seen?", "¿Dónde se observó?")):
            sources = query("""SELECT l.source_ref,l.context_snippet,l.first_seen,mu.cluster_id
                FROM indicator_links l LEFT JOIN mirror_urls mu ON mu.url=l.source_ref
                WHERE l.indicator_id=? ORDER BY l.first_seen DESC""", (clue["id"],))
            for source in sources:
                st.code(
                    source.get("source_ref") or _l(st, "Unknown source", "Fuente desconocida"),
                    language=None,
                )
                st.caption(
                    f"{_l(st, 'Related group', 'Grupo relacionado')}: "
                    f"{source.get('cluster_id') or _l(st, 'None', 'Ninguno')} · "
                    f"{redact_sensitive(source.get('context_snippet') or _l(
                        st, 'No short context saved', 'No se guardó contexto breve'
                    ))}"
                )


DISCLOSURE_NAMES = {"server_header":"Server name visible","directory_listing_visible":"Directory listing visible",
    "debug_message_visible":"Debug message visible","clearnet_link_visible":"Regular website link visible",
    "stack_trace":"Technical error trace visible","absolute_path_disclosure":"Server file path visible",
    "powered_by_header":"Software name visible","onion_link_visible":"Another onion link visible",
    "framework_disclosure":"Website framework visible","version_disclosure":"Software version visible",
    "default_error_page":"Default error page visible","server_error":"Server error visible",
    "mirror_list_visible":"List of mirrors visible","contact_visible":"Contact detail visible",
    "timestamp_visible":"Timestamp visible","file_name_visible":"Filename visible"}
DISCLOSURE_NAMES_ES = {
    "server_header": "Nombre del servidor visible",
    "directory_listing_visible": "Listado de directorio visible",
    "debug_message_visible": "Mensaje de depuración visible",
    "clearnet_link_visible": "Enlace web público visible",
    "stack_trace": "Traza de error técnica visible",
    "absolute_path_disclosure": "Ruta de archivo del servidor visible",
    "powered_by_header": "Nombre del software visible",
    "onion_link_visible": "Otro enlace onion visible",
    "framework_disclosure": "Framework web visible",
    "version_disclosure": "Versión de software visible",
    "default_error_page": "Página de error predeterminada visible",
    "server_error": "Error del servidor visible",
    "mirror_list_visible": "Lista de espejos visible",
    "contact_visible": "Dato de contacto visible",
    "timestamp_visible": "Marca temporal visible",
    "file_name_visible": "Nombre de archivo visible",
}
EXPOSURE_EXPLANATIONS_ES = {
    "server_header": "La respuesta normal mostró información del software del servidor.",
    "directory_listing_visible": "La página mostró un índice de directorio visible.",
    "debug_message_visible": "La página devuelta ya contenía un mensaje de depuración.",
    "clearnet_link_visible": "La página enlazó visiblemente una dirección web pública; no se visitó por defecto.",
    "stack_trace": "Había una traza de error visible y solo se conservó un fragmento breve y depurado.",
    "absolute_path_disclosure": "La respuesta normal mostró una ruta con apariencia local.",
    "powered_by_header": "La respuesta mostró una cabecera de framework o entorno de ejecución.",
    "onion_link_visible": "La respuesta de la página contenía otro enlace onion visible.",
}


def _simple_disclosures(st, query) -> None:
    language = current_language(st)
    st.markdown(_l(st, "## Things pages revealed", "## Datos visibles en las páginas"))
    _note(st, _l(
        st,
        "These are details the page showed by itself during a normal check. The system did not cause "
        "an error, test hidden paths, or probe the server.",
        "Son datos que la propia página mostró durante una comprobación normal. El sistema no provocó "
        "errores, no probó rutas ocultas ni sondeó el servidor.",
    ))
    rows = query("""SELECT pe.*,COALESCE(sp.display_name,'Unnamed site') AS site_name,mu.cluster_id
        FROM passive_exposures pe LEFT JOIN site_profiles sp ON sp.url=pe.url
        LEFT JOIN mirror_urls mu ON mu.url=pe.url ORDER BY pe.ts DESC LIMIT 1000""")
    c1, c2 = st.columns(2)
    severity_labels = {
        "info": ("For information", "Informativo"),
        "low": ("Low", "Baja"),
        "medium": ("Medium", "Media"),
        "high": ("High", "Alta"),
    }
    severities = c1.multiselect(
        _l(st, "Importance", "Importancia"),
        ["info", "low", "medium", "high"],
        format_func=lambda value: severity_labels[value][1 if language == "es" else 0],
    )
    search = c2.text_input(
        _l(st, "Find a site or disclosure", "Buscar un sitio o dato visible")
    )
    filtered = [r for r in rows if (not severities or r["severity"] in severities)
        and (not search or search.casefold() in " ".join([r.get("site_name",""),r.get("url",""),r.get("exposure_type","")]).casefold())]
    if not filtered:
        st.info(_l(
            st,
            "No page disclosures match this view.",
            "Ningún dato visible de página coincide con esta vista.",
        ))
        return
    for item in filtered[:150]:
        title = (
            DISCLOSURE_NAMES_ES.get(
                item["exposure_type"], value_label(item["exposure_type"], language)
            )
            if language == "es"
            else DISCLOSURE_NAMES.get(
                item["exposure_type"], item["exposure_type"].replace("_", " ").title()
            )
        )
        site_name = item["site_name"]
        if site_name == "Unnamed site":
            site_name = _l(st, "Unnamed site", "Sitio sin nombre")
        group_value = item.get("cluster_id") or _l(st, "None", "Ninguno")
        st.markdown(
            f'<div class="analyst-card"><h3>{html.escape(title)}</h3>'
            f'{severity_badge(
                item["severity"],
                severity_labels[item["severity"]][1] if language == "es" else None,
            )}'
            f'<div class="card-meta">{html.escape(site_name)} · '
            f'{_l(st, "Related group", "Grupo relacionado")} {group_value}</div></div>',
            unsafe_allow_html=True,
        )
        st.caption(_l(
            st,
            "Importance describes how useful this visible detail may be for review; it is not a claim "
            "that the site is vulnerable.",
            "La importancia describe la utilidad de este dato visible para la revisión; no afirma "
            "que el sitio sea vulnerable.",
        ))
        if language == "es":
            explanation = EXPOSURE_EXPLANATIONS_ES.get(
                item["exposure_type"],
                "La página mostró este dato durante la respuesta normal de su portada.",
            )
        else:
            explanation = EXPOSURE_EXPLANATIONS.get(
                item["exposure_type"],
                "The page displayed this detail during its normal front-page response.",
            )
        st.write(explanation)
        st.code(item["url"], language=None)
        st.caption(redact_sensitive(
            item.get("context") or item.get("value")
            or _l(st, "No additional context saved", "No se guardó contexto adicional")
        ))


def _simple_reports(st, query) -> None:
    language = current_language(st)
    _note(st, _l(st,
        "Reports collect the safe facts already shown in this workspace: site names, categories, repeated clues, page disclosures, timestamps, hashes, and short cleaned excerpts.",
        "Los informes reúnen los datos seguros ya mostrados: nombres, categorías, pistas repetidas, detalles visibles, fechas, huellas y fragmentos depurados."))
    reports = query("""SELECT er.*,sc.primary_category,sc.storage_policy,sc.analyst_title,
      sc.display_name AS site_name,sc.representative_url FROM evidence_reports er
      LEFT JOIN site_cards sc ON sc.id=er.site_card_id
      WHERE sc.primary_category IS NULL OR (sc.primary_category!='severe_abuse_risk'
      AND sc.primary_category NOT IN ('adult_restricted','adult_filtered')
      AND COALESCE(sc.storage_policy,'safe_summary')!='discard') ORDER BY er.ts DESC LIMIT 500""")
    if not reports:
        st.markdown(
            empty_state(
                _l(st, "No reports yet", "Todavía no hay informes"),
                _l(
                    st,
                    "Create a report from the actions inside a Site Card. It will appear here with its source and status.",
                    "Crea un informe desde las acciones de una ficha. Aparecerá aquí con su fuente y estado.",
                ),
            ),
            unsafe_allow_html=True,
        )
        return
    report_page_size = 20
    report_pages = max(1, (len(reports) + report_page_size - 1) // report_page_size)
    if int(st.session_state.get("reports-page", 1) or 1) > report_pages:
        st.session_state["reports-page"] = report_pages
    report_page = st.number_input(
        _l(st, "Report page", "Página de informes"), min_value=1, max_value=report_pages,
        step=1, key="reports-page",
    )
    report_start = (int(report_page) - 1) * report_page_size
    visible_reports = reports[report_start:report_start + report_page_size]
    st.caption(_l(
        st,
        f"Showing {report_start + 1}–{min(report_start + report_page_size, len(reports))} of {len(reports)} reports.",
        f"Mostrando {report_start + 1}–{min(report_start + report_page_size, len(reports))} de {len(reports)} informes.",
    ))
    for report in visible_reports:
        site_title = safe_display_title(
            report.get("analyst_title") or report.get("site_name"),
            report.get("representative_url"),
            fallback=_l(st, "Site report", "Informe del sitio"),
        )
        st.markdown(f'<div class="analyst-card"><h3>{html.escape(site_title)}</h3>'
                    f'{status_badge(report.get("status"), value_label(report.get("status"), language))}'
                    f'<div class="card-meta">{html.escape(_l(st, "Report", "Informe"))} #{report["id"]} · '
                    f'{html.escape(_l(st, "Related group", "Grupo relacionado"))} {report.get("cluster_id") or value_label("none", language)} · '
                    f'{html.escape(_l(st, "Created", "Creado"))} {report.get("ts")} · '
                    f'{html.escape(_l(st, "By", "Por"))} {html.escape(report.get("generated_by") or value_label("unknown", language))}</div></div>', unsafe_allow_html=True)
        path = Path(report.get("output_path") or "")
        try:
            safe_path = path.resolve()
            allowed = (
                safe_path.is_relative_to(REPORTS_DIR.resolve())
                and safe_path.is_file()
                and safe_path.suffix.lower() == ".md"
            )
            report_text = safe_path.read_text(encoding="utf-8")[:50000] if allowed else ""
        except (OSError, ValueError):
            allowed = False
            report_text = ""
        actions = st.columns(2)
        if report.get("site_card_id"):
            actions[0].button(
                _l(st, "Open Site Card", "Abrir ficha"), key=f"report-open-card-{report['id']}",
                on_click=site_directory.open_card, args=(int(report["site_card_id"]), False),
                width="stretch",
            )
        if allowed:
            actions[1].download_button(
                _l(st, "Download report", "Descargar informe"), data=report_text,
                file_name=f"arachne-report-{int(report['id'])}.md", mime="text/markdown",
                key=f"report-download-{report['id']}", width="stretch",
            )
        with st.expander(_l(st, "Read report", "Leer informe")):
            if allowed:
                st.markdown(report_text)
            else: st.warning(_l(st, "This report file is not available at its saved location.",
                                  "El archivo del informe no está disponible en la ubicación guardada."))


def _spain_priority_page(st, query) -> None:
    st.markdown("## 🇪🇸 Spain Priority")
    _note(st, "Spain-related pages are placed here for fast review. A city alone is not a high alert; strong institutions/domains or Spain paired with risk context are prioritized. Safety restrictions always win.")
    items=storage.get_spain_priority_items(False,300)
    unreviewed=sum(1 for item in items if item.get("spain_review_status")=="unreviewed")
    c1,c2,c3=st.columns(3)
    c1.metric("Unreviewed",unreviewed); c2.metric("Total Spain items",len(items)); c3.metric("High/Critical",sum(1 for i in items if i.get("risk_level") in {"high","critical"}))
    review_filter=st.selectbox("Review status",["All","unreviewed","keep","ignored","needs_report","reported","blocked"])
    visible=[item for item in items if review_filter=="All" or item.get("spain_review_status")==review_filter]
    if not visible: st.info("No Spain-priority items match this view."); return
    context_labels={"weapons_arms":"SPAIN + WEAPONS","leaks_data":"SPAIN + LEAKS","credentials":"SPAIN + CREDENTIALS",
        "malware_hacking":"SPAIN + MALWARE","extremist_recruitment":"SPAIN + RECRUITMENT",
        "adult_restricted":"SPAIN + RESTRICTED CONTENT","severe_abuse_risk":"SPAIN + RESTRICTED CONTENT"}
    for item in visible:
        label=context_labels.get(item.get("primary_category"),"SPAIN PRIORITY")
        spain_contexts=parse_json(item.get("spain_context_tags"))
        if "russian_geopolitical_context" in spain_contexts: label="SPAIN + RUSSIAN CONTEXT"
        if "trade_flow_to_spain" in spain_contexts: label="SENDING / DELIVERY TO SPAIN"
        if "trade_flow_from_spain" in spain_contexts: label="SENDING / DELIVERY FROM SPAIN"
        st.markdown(f'<div class="analyst-card"><h3>🇪🇸 {html.escape(label)}</h3>'
                    f'{category_badge(safe_category_label(item.get("primary_category")))} {risk_badge(item.get("risk_level"))} '
                    f'{review_badge(item.get("spain_review_status"))}'
                    f'<div class="card-meta">Language {item.get("spain_match_language") or "UNKNOWN"} · Confidence {item.get("spain_confidence") or "unknown"}</div></div>',unsafe_allow_html=True)
        left,right=st.columns([3,1])
        with left:
            st.write(_l(st, "**Why Spain matched:**", "**Motivo de la coincidencia con España:**"),
                     spain_reason_label(item.get("spain_match_reason"), current_language(st)))
            st.write("**Why it matters:**",safe_category_label(item.get("primary_category")))
            st.write("**Source:**",item.get("source_url") or "Manual seed")
            st.write("**First seen:**",item.get("first_seen") or "Unknown"," · **Last checked:**",item.get("last_checked_at") or "Not yet")
            st.write("**Crawler status:**",item.get("status")," · **Review:**",item.get("spain_review_status"))
            st.code(item["url"],language=None)
            if item.get("storage_policy")=="metadata_only":
                st.error("Restricted metadata-only item. No preview, snippet, screenshot, unsafe title, or content text is shown.")
        with right: _policy_preview(st,item,safe_category_label(item.get("primary_category")))
        cols=st.columns(5)
        actions=[("Keep","keep","relevant"),("Ignore","ignored","false_positive"),("Prepare report","needs_report","needs_report"),("Block","blocked","blocked")]
        for col,(label_text,spain_status,review_status) in zip(cols,actions, strict=False):
            if col.button(label_text,key=f"spain-{item['id']}-{spain_status}",width="stretch"):
                storage.set_spain_review_status(item["url"],spain_status)
                storage.set_review_status("onion_url",item["id"],review_status)
                if spain_status == "needs_report":
                    st.success(f"Safe Spain-priority report created: {build_url_report(item['url'])}")
                else:
                    query.clear(); st.rerun()
        if item.get("active") and item.get("queue_policy")!="blocked":
            if cols[4].button("Live Check",key=f"spain-live-{item['id']}",width="stretch"):
                storage.queue_live_check(item["url"]); query.clear(); st.success("Queued for a full-policy Live Check.")
        else: cols[4].caption("Live Check blocked by safety/dead-link policy")
        st.divider()


def _spain_site_cards_page(st, query) -> None:
    st.markdown("## 🇪🇸 Spain Priority Site Cards")
    _note(st, "Each deduplicated site appears once here even when many mirrors or paths mention Spain. New mirrors update the existing card and do not create duplicate main alerts.")
    cards = [card for card in site_dedupe.get_site_cards(spain_only=True, limit=500)
             if _normal_card_visible(card, bool(st.session_state.get("show_adult_restricted_metadata", False)),
                                     bool(st.session_state.get("show_low_info_cards", False)), True)]
    unreviewed = [card for card in cards if card.get("review_status") in {"pending","needs_review","restricted","needs_report"}]
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Unreviewed cards", len(unreviewed))
    c2.metric("Spain Site Cards", len(cards))
    c3.metric("Total mirrors", sum(int(card.get("mirror_count") or 0) for card in cards))
    c4.metric("High / critical", sum(1 for card in cards if card.get("risk_level") in {"high","critical"}))
    status_filter = st.selectbox("Review status", ["All","pending","restricted","relevant","false_positive","needs_report","reported","blocked"])
    visible = [card for card in cards if status_filter == "All" or card.get("review_status") == status_filter]
    if not visible:
        st.info("No Spain-priority Site Cards match this review status.")
        return
    for card in visible:
        _render_site_card(st, card, query, "spain-card", actions=True)


def _opsec_status_panel(st, compact: bool = False) -> None:
    """Render safe status flags only; never expose configuration values or secrets."""
    from opsec_preflight import opsec_status_snapshot, run_opsec_audit
    language = current_language(st)
    audit = opsec_status_snapshot()
    if not compact:
        st.markdown(_l(st, "### OPSEC Status", "### Estado OPSEC"))
        st.info(_l(
            st,
            "Read-only checks for Tor routing, preview isolation and accidental direct-fetch paths. "
            "No tokens or raw configuration values are shown.",
            "Comprobaciones de solo lectura sobre el enrutamiento Tor, el aislamiento de vistas "
            "previas y posibles accesos directos accidentales. No se muestran tokens ni valores "
            "de configuración.",
        ))
    top = st.columns(2)
    bottom = st.columns(2)
    tor_value = audit.get("tor_socks_reachable")
    tor_status = (
        _l(st, "Reachable", "Accesible")
        if tor_value is True else
        _l(st, "Unavailable", "No disponible")
        if tor_value is False else
        _l(st, "Not audited", "Sin auditar")
    )
    isolation_value = str(audit["socks_isolation"] or "unknown").casefold()
    isolation_labels = {
        "enforced": ("Enforced", "Aplicado"),
        "enabled": ("Enabled", "Activado"),
        "disabled": ("Disabled", "Desactivado"),
        "failed": ("Failed", "Fallido"),
        "unknown": ("Unknown", "Desconocido"),
        "not audited": ("Not audited", "Sin auditar"),
        "not_audited": ("Not audited", "Sin auditar"),
    }
    isolation_pair = isolation_labels.get(
        isolation_value, (isolation_value.replace("_", " ").title(), value_label(isolation_value, language))
    )
    top[0].metric("Tor SOCKS", tor_status)
    top[1].metric(
        _l(st, "socks5h routing", "Enrutamiento socks5h"),
        _l(st, "Enforced", "Aplicado") if audit["socks5h_enforced"]
        else _l(st, "Failed", "Fallido"),
    )
    bottom[0].metric(
        _l(st, "SOCKS isolation", "Aislamiento SOCKS"),
        isolation_pair[1 if language == "es" else 0],
    )
    bottom[1].metric(
        _l(st, "Strict startup", "Inicio estricto"),
        _l(st, "On", "Activado") if audit["strict_mode"] else _l(st, "Off", "Desactivado"),
    )
    preview_safe = all(audit["preview_policy"].values()) and audit["preview_proxy_ok"]
    direct_value = audit["direct_fetch_scan"].get("pass")
    direct_label = (
        _l(st, "PASS", "CORRECTO") if direct_value is True
        else _l(st, "FAIL", "FALLO") if direct_value is False
        else _l(st, "NOT AUDITED", "SIN AUDITAR")
    )
    release_value = audit.get("release_hygiene")
    release_label = (
        _l(st, "PASS", "CORRECTO") if release_value is True
        else _l(st, "FAIL", "FALLO") if release_value is False
        else _l(st, "NOT AUDITED", "SIN AUDITAR")
    )
    preview_label = _l(st, "PASS", "CORRECTO") if preview_safe else _l(st, "FAIL", "FALLO")
    last_audit = audit.get("timestamp") or _l(st, "never", "nunca")
    st.caption(
        f"{_l(st, 'Preview safety', 'Seguridad de vistas previas')}: {preview_label} · "
        f"{_l(st, 'Direct-fetch scan', 'Análisis de accesos directos')}: {direct_label} · "
        f"{_l(st, 'Release hygiene', 'Higiene de la versión')}: {release_label} · "
        f"{_l(st, 'Last live audit', 'Última auditoría en vivo')}: {last_audit}"
    )
    if audit["status"] == "PASS":
        st.success(_l(
            st,
            "The last live OPSEC audit passed.",
            "La última auditoría OPSEC en vivo terminó correctamente.",
        ))
    elif tor_value is False and not audit["strict_mode"]:
        st.warning(_l(
            st,
            "Tor SOCKS is not reachable from this dashboard process. Strict mode is off; verify the "
            "server service before enabling it.",
            "Este proceso del panel no puede acceder a Tor SOCKS. El modo estricto está desactivado; "
            "comprueba el servicio del servidor antes de activarlo.",
        ))
    else:
        st.info(_l(
            st,
            "No passing live audit is cached. Run `python onion_worker.py --opsec-audit` on the server.",
            "No hay una auditoría en vivo correcta en caché. Ejecuta "
            "`python onion_worker.py --opsec-audit` en el servidor.",
        ))
    can_manage_settings = _can(st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE)
    if not compact and st.button(
        _l(st, "Run live OPSEC audit", "Ejecutar auditoría OPSEC en vivo"),
        key="advanced-run-live-opsec-audit",
        disabled=not can_manage_settings,
    ) and _authorize_action(st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE):
        with st.spinner(_l(
            st, "Running bounded live checks…", "Ejecutando comprobaciones limitadas en vivo…"
        )):
            audit = run_opsec_audit(persist=True)
        st.success(_l(
            st,
            "Live audit finished. Review the refreshed status below.",
            "La auditoría en vivo ha terminado. Revisa el estado actualizado.",
        ))
        st.rerun()


def _advanced_page(st,query,pd) -> None:
    language = current_language(st)
    can_manage_settings = _can(st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE)
    can_review = _can(st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE)
    can_edit = _can(st, dashboard_auth.CAPABILITY_SITE_CARDS_EDIT)
    can_manage_collection = _can(st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE)
    _note(st, _l(
        st,
        "Detailed correlations and maintenance tools live here so the normal workflow stays uncluttered.",
        "Las correlaciones detalladas y las herramientas de mantenimiento están aquí para que el "
        "flujo habitual siga siendo claro.",
    ))
    advanced_options = [
        "Consistency Center", "OPSEC Status", "Restricted Metadata", "Possible Mirrors",
        "Manual Merge / Split", "Raw URL Table", "Related Site Groups", "Repeated Clues",
        "Page Disclosures", "Safety & Setup", "Maintenance Tools", "Clean Dead Links",
    ]
    advanced_labels_es = {
        "Consistency Center": "Centro de consistencia",
        "OPSEC Status": "Estado OPSEC",
        "Restricted Metadata": "Metadatos restringidos",
        "Possible Mirrors": "Posibles espejos",
        "Manual Merge / Split": "Unir o separar manualmente",
        "Raw URL Table": "Tabla técnica de URL",
        "Related Site Groups": "Grupos de sitios relacionados",
        "Repeated Clues": "Pistas repetidas",
        "Page Disclosures": "Datos visibles en páginas",
        "Safety & Setup": "Seguridad y configuración",
        "Maintenance Tools": "Herramientas de mantenimiento",
        "Clean Dead Links": "Limpiar enlaces caídos",
    }
    displayed_options = (
        [advanced_labels_es[value] for value in advanced_options]
        if language == "es" else advanced_options
    )
    displayed_choice = st.selectbox(
        _l(st, "Advanced tool", "Herramienta avanzada"),
        displayed_options,
        key="advanced_tool",
    )
    choice = (
        {label: value for value, label in advanced_labels_es.items()}[displayed_choice]
        if language == "es" else displayed_choice
    )
    if choice=="Consistency Center":
        from consistency import (audit_consistency, repair_consistency,
                                 repair_link_list_frontier, repair_site_cards)
        st.markdown(_l(st, "### Consistency Center", "### Centro de consistencia"))
        st.info(_l(
            st,
            "Safe counts only. Diagnostics never display page text, restricted titles, snippets, "
            "OCR, products, credentials, or secrets.",
            "Solo se muestran recuentos seguros. El diagnóstico nunca muestra texto de páginas, "
            "títulos restringidos, fragmentos, OCR, productos, credenciales ni secretos.",
        ))
        audit_state_key = "advanced_consistency_audit"
        audit = st.session_state.get(audit_state_key)
        run_label = (
            _l(st, "Run audit again", "Repetir auditoría")
            if isinstance(audit, dict)
            else _l(st, "Run consistency audit", "Ejecutar auditoría de consistencia")
        )
        if st.button(
            run_label,
            key="advanced-run-consistency-audit",
            width="stretch",
            disabled=not can_manage_settings,
        ) and _authorize_action(st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE):
            with st.spinner(_l(
                st,
                "Running bounded consistency checks…",
                "Ejecutando comprobaciones limitadas de consistencia…",
            )):
                audit = audit_consistency()
            audit = dict(audit)
            audit["_dashboard_checked_at"] = storage.utc_now_iso()
            st.session_state[audit_state_key] = audit
            query.clear()

        if not isinstance(audit, dict):
            st.markdown(
                empty_state(
                    _l(
                        st,
                        "Consistency audit not run",
                        "Auditoría de consistencia sin ejecutar",
                    ),
                    _l(
                        st,
                        "No audit has been run in this dashboard session. Start it explicitly when "
                        "diagnostics are needed.",
                        "No se ha ejecutado ninguna auditoría en esta sesión. Iníciala expresamente "
                        "cuando necesites el diagnóstico.",
                    ),
                ),
                unsafe_allow_html=True,
            )
        else:
            st.caption(
                f"{_l(st, 'Last run in this session', 'Última ejecución en esta sesión')}: "
                f"{audit.get('_dashboard_checked_at') or _l(st, 'time unavailable', 'hora no disponible')}"
            )
            counts = audit["counts"]
            metrics = st.columns(4)
            metrics[0].metric(
                _l(st, "State conflicts", "Conflictos de estado"),
                counts["active_blocked_conflicts"] + counts["queued_inactive_conflicts"]
                + counts["blocked_normal_queue_conflicts"],
            )
            metrics[1].metric(
                _l(st, "Awaiting finalization", "Pendientes de finalización"),
                counts["crawled_awaiting_classification"],
            )
            metrics[2].metric(
                _l(st, "Unknown high-edge pages", "Páginas desconocidas con muchos enlaces"),
                counts["unknown_high_edge_pages"],
            )
            metrics[3].metric(
                _l(st, "Spain mismatches", "Desajustes de España"),
                counts["alert_queue_without_url_flag"] + counts["url_flag_without_site_card_flag"]
                + counts["site_card_flag_without_url_support"],
            )
            detail_rows = audit.get("details") or [
                {"category": key, "count": value, "severity": "none", "safe_auto_repair": False,
                 "affects_analyst_data": False, "scope": "none"}
                for key, value in counts.items() if value
            ]
            if detail_rows:
                st.dataframe(pd.DataFrame(detail_rows),
                             width="stretch", hide_index=True)
            else:
                st.markdown(
                    empty_state(
                        _l(
                            st,
                            "No consistency conflicts",
                            "No hay conflictos de consistencia",
                        ),
                        _l(
                            st,
                            "The current audit found no state, finalization, frontier, or Spain "
                            "rollup mismatch.",
                            "La auditoría no encontró desajustes de estado, finalización, cola ni "
                            "agrupación de España.",
                        ),
                    ),
                    unsafe_allow_html=True,
                )
            if audit["samples"]:
                st.caption(_l(
                    st,
                    "Safe samples: ID, onion host, state and reason only",
                    "Muestras seguras: solo ID, host onion, estado y motivo",
                ))
                st.dataframe(pd.DataFrame(audit["samples"]), width="stretch", hide_index=True)
        dry_cols = st.columns(3)
        if dry_cols[0].button(
            _l(st, "Preview consistency repair", "Previsualizar reparación de consistencia"),
            width="stretch",
        ):
            st.json(repair_consistency(True))
        if dry_cols[1].button(
            _l(st, "Preview link-list repair", "Previsualizar reparación de listas"),
            width="stretch",
        ):
            st.json(repair_link_list_frontier(True))
        if dry_cols[2].button(
            _l(st, "Preview Site Card rebuild", "Previsualizar reconstrucción de fichas"),
            width="stretch",
        ):
            st.json(repair_site_cards(True))
        confirm = st.checkbox(
            _l(
                st,
                "I understand: apply only the safe mechanical repairs shown above",
                "Entiendo: aplicar solo las reparaciones mecánicas seguras mostradas arriba",
            ),
            disabled=not can_manage_settings,
        )
        repair_cols = st.columns(3)
        if repair_cols[0].button(
            _l(st, "Repair consistency", "Reparar consistencia"),
            disabled=not confirm or not can_manage_settings,
            width="stretch",
        ) and _authorize_action(st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE):
            st.json(repair_consistency(False)); query.clear()
        if repair_cols[1].button(
            _l(st, "Repair link-list frontier", "Reparar cola de listas de enlaces"),
            disabled=not confirm or not can_manage_settings,
            width="stretch",
        ) and _authorize_action(st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE):
            st.json(repair_link_list_frontier(False)); query.clear()
        if repair_cols[2].button(
            _l(st, "Rebuild Site Cards", "Reconstruir fichas de sitios"),
            disabled=not confirm or not can_manage_settings,
            width="stretch",
        ) and _authorize_action(st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE):
            st.json(repair_site_cards(False)); query.clear()
    elif choice=="OPSEC Status":
        _opsec_status_panel(st)
    elif choice=="Restricted Metadata":
        st.markdown(_l(st, "### Restricted metadata", "### Metadatos restringidos"))
        st.warning(_l(
            st,
            "Restricted records remain metadata only. This view never shows unsafe titles, raw "
            "terms, snippets, screenshots, previews, or page text.",
            "Los registros restringidos conservan solo metadatos. Esta vista nunca muestra títulos "
            "no seguros, términos sin depurar, fragmentos, capturas, vistas previas ni texto.",
        ))
        adult_count=_scalar("SELECT COUNT(*) FROM onion_urls WHERE primary_category='adult_filtered' OR storage_policy='discard'")
        severe_count=_scalar("SELECT COUNT(*) FROM onion_urls WHERE primary_category='severe_abuse_risk'")
        c1,c2=st.columns(2)
        c1.metric(_l(st, "Filtered adult URLs", "URL adultas filtradas"), adult_count)
        c2.metric(
            _l(st, "Critical restricted metadata", "Metadatos restringidos críticos"),
            severe_count,
        )
        show_adult=st.checkbox(
            _l(st, "Show filtered adult metadata", "Mostrar metadatos adultos filtrados"),
            value=False,key="show_filtered_adult_metadata",
            help=_l(
                st,
                "Shows only URL, timestamps, source URL, and the fixed filter reason. No result card "
                "or content fields exist.",
                "Muestra solo la URL, fechas, URL de origen y el motivo fijo del filtro. No existen "
                "fichas de resultado ni campos de contenido.",
            ),
        )
        show_severe=st.checkbox(
            _l(st, "Show severe restricted metadata", "Mostrar metadatos restringidos graves"),
            value=False,key="show_severe_restricted_metadata",
            help=_l(
                st,
                "Advanced-only metadata view. Raw severe-abuse terms, titles, snippets, and "
                "screenshots remain unavailable.",
                "Vista de metadatos solo avanzada. Los términos graves sin depurar, títulos, "
                "fragmentos y capturas siguen sin estar disponibles.",
            ),
        )
        if show_adult:
            adult_rows=query("""SELECT afm.id,ou.url,afm.confidence,afm.safe_rule_id,
              'adult_content_filtered' AS safety_reason,afm.matched_safe_label,afm.match_scope,
              afm.false_positive_guard_applied,afm.first_seen,
              afm.last_seen,afm.match_count,afm.analyst_decision FROM adult_filter_memory afm
              LEFT JOIN onion_urls ou ON ou.id=afm.onion_url_id ORDER BY afm.last_seen DESC LIMIT 1000""")
            if adult_rows:
                st.dataframe(pd.DataFrame(adult_rows),width="stretch",hide_index=True,height=400)
                choices = {
                    f"#{row['id']} · {row.get('url') or row.get('safe_rule_id')} · "
                    f"{value_label(row.get('analyst_decision'), language)}": row
                    for row in adult_rows
                }
                selected=choices[st.selectbox(
                    _l(st, "Filter-memory entry to review", "Entrada del filtro que revisar"),
                    list(choices),
                )]
                a,b=st.columns(2)
                if a.button(_l(st, "Mark as false positive", "Marcar como falso positivo"), width="stretch",
                            disabled=not can_review) and _authorize_action(
                                st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
                    storage.review_adult_memory(selected["id"],"false_positive"); query.clear()
                    st.success(_l(
                        st,
                        "Removed from automatic blocking memory and returned for a safe re-check.",
                        "Se eliminó de la memoria de bloqueo automático y volvió a una comprobación segura.",
                    )); st.rerun()
                if b.button(_l(st, "Keep blocked", "Mantener bloqueado"), width="stretch",
                            disabled=not can_review) and _authorize_action(
                                st, dashboard_auth.CAPABILITY_REVIEWS_MANAGE):
                    storage.review_adult_memory(selected["id"],"blocked"); query.clear()
                    st.success(_l(
                        st,
                        "Kept in private adult-filter memory.",
                        "Se mantuvo en la memoria privada del filtro de adultos.",
                    )); st.rerun()
            else:
                st.info(_l(
                    st,
                    "No filtered adult URL metadata is stored.",
                    "No hay metadatos guardados de URL adultas filtradas.",
                ))
        if show_severe:
            severe_rows=query("""SELECT url,first_seen,last_seen,last_checked_at,source_url,safety_reason,
              review_status FROM onion_urls WHERE primary_category='severe_abuse_risk'
              ORDER BY first_seen DESC LIMIT 1000""")
            if severe_rows:
                st.dataframe(pd.DataFrame(severe_rows),width="stretch",hide_index=True,height=400)
            else:
                st.info(_l(
                    st,
                    "No severe restricted metadata is stored.",
                    "No hay metadatos restringidos graves guardados.",
                ))
            severe_cards=[card for card in site_dedupe.get_site_cards(limit=1000) if _is_severe_item(card)]
            for card in severe_cards: _render_site_card(st,card,query,"restricted-card",actions=False)
        if not show_adult and not show_severe:
            st.info(_l(
                st,
                "No restricted metadata is intentionally unlocked in this view.",
                "No se ha desbloqueado expresamente ningún metadato restringido en esta vista.",
            ))
    elif choice=="Possible Mirrors":
        st.markdown(_l(st, "### Possible mirror review", "### Revisión de posibles espejos"))
        st.info(_l(
            st,
            "These pairs share a weak safe signal, such as a title. They stay separate until you "
            "confirm them.",
            "Estas parejas comparten una señal segura débil, como un título. Permanecen separadas "
            "hasta que las confirmes.",
        ))
        matches=query("""SELECT pm.*,ou.url,ou.site_card_id AS current_card_id,
          current.display_name AS current_name,candidate.display_name AS candidate_name
          FROM possible_site_card_matches pm JOIN onion_urls ou ON ou.id=pm.onion_url_id
          LEFT JOIN site_cards current ON current.id=ou.site_card_id
          JOIN site_cards candidate ON candidate.id=pm.candidate_site_card_id
          WHERE pm.status='pending' ORDER BY pm.created_at DESC""")
        if not matches:
            st.success(_l(
                st,
                "No possible mirrors are waiting for review.",
                "No hay posibles espejos pendientes de revisión.",
            ))
        for match in matches:
            current_name = match.get("current_name") or _l(st, "New card", "Ficha nueva")
            candidate_name = match.get("candidate_name") or _l(
                st, "Existing card", "Ficha existente"
            )
            st.markdown(
                f"**{html.escape(current_name)}** "
                f"{_l(st, 'may match', 'puede coincidir con')} "
                f"**{html.escape(candidate_name)}**"
            )
            st.code(match["url"],language=None)
            st.caption(match.get("reason") or _l(
                st, "Weak safe similarity", "Similitud segura débil"
            ))
            cols=st.columns(3)
            mirror_actions = [
                (_l(st, "Confirm mirror", "Confirmar espejo"), "confirm"),
                (_l(st, "Not same site", "No es el mismo sitio"), "not_same"),
                (_l(st, "Ignore", "Ignorar"), "ignore"),
            ]
            for col,(label,decision) in zip(cols, mirror_actions, strict=False):
                if col.button(
                    label,
                    key=f"possible-{match['id']}-{decision}",
                    width="stretch",
                    disabled=not can_edit,
                ) and _authorize_action(st, dashboard_auth.CAPABILITY_SITE_CARDS_EDIT):
                    site_dedupe.review_possible_match(match["id"],decision); query.clear(); st.rerun()
            st.divider()
    elif choice=="Manual Merge / Split":
        st.markdown(_l(st, "### Manual merge", "### Unión manual"))
        cards=site_dedupe.get_site_cards(limit=1000)
        choices={f"#{card['id']} · {card.get('analyst_title') or card.get('display_name') or card['canonical_site_id']}":card["id"] for card in cards}
        if len(choices)>=2:
            a,b=st.columns(2)
            source_label=a.selectbox(
                _l(st, "Card to merge", "Ficha que unir"), list(choices), key="merge-source"
            )
            target_options=[label for label in choices if label!=source_label]
            target_label=b.selectbox(
                _l(st, "Card to keep", "Ficha que conservar"),
                target_options,key="merge-target",
            )
            merge_confirm = st.toggle(
                _l(
                    st,
                    "Confirm that these two cards represent the same site",
                    "Confirmar que estas dos fichas representan el mismo sitio",
                ),
                value=False, key="merge-confirm",
                help=_l(
                    st,
                    "The kept card preserves analyst fields; the other card's URLs and audit history "
                    "are moved underneath it.",
                    "La ficha conservada mantiene los campos manuales; las URL y el historial de "
                    "auditoría de la otra ficha se trasladan a ella.",
                ),
                disabled=not can_edit,
            )
            if st.button(
                _l(st, "Merge selected Site Cards", "Unir las fichas seleccionadas"),
                type="primary",
                disabled=not merge_confirm or not can_edit,
            ) and _authorize_action(st, dashboard_auth.CAPABILITY_SITE_CARDS_EDIT):
                site_dedupe.merge_site_cards(choices[source_label],choices[target_label])
                query.clear()
                st.success(_l(
                    st,
                    "Cards merged; all URLs and audit events were preserved.",
                    "Fichas unidas; se conservaron todas las URL y los eventos de auditoría.",
                ))
                st.rerun()
        else:
            st.info(_l(
                st,
                "At least two Site Cards are needed for manual merge.",
                "Se necesitan al menos dos fichas para realizar una unión manual.",
            ))
        st.markdown(_l(st, "### Manual split", "### Separación manual"))
        rows=query("""SELECT ou.id,ou.url,sc.display_name FROM onion_urls ou JOIN site_cards sc ON sc.id=ou.site_card_id
          ORDER BY sc.display_name,ou.url""")
        if rows:
            url_choices={f"{row['display_name']} · {row['url']}":row["id"] for row in rows}
            selected=st.selectbox(
                _l(
                    st,
                    "URL/path to move into a new Site Card",
                    "URL o ruta que trasladar a una ficha nueva",
                ),
                list(url_choices),
            )
            split_confirm = st.toggle(
                _l(
                    st,
                    "Confirm that this URL belongs on a separate Site Card",
                    "Confirmar que esta URL pertenece a una ficha separada",
                ),
                value=False, key="split-confirm",
                disabled=not can_edit,
            )
            if st.button(
                _l(st, "Split selected URL", "Separar la URL seleccionada"),
                disabled=not split_confirm or not can_edit,
            ) and _authorize_action(st, dashboard_auth.CAPABILITY_SITE_CARDS_EDIT):
                site_dedupe.split_url_from_site_card(url_choices[selected])
                query.clear()
                st.success(_l(
                    st,
                    "URL moved into a new Site Card with its source history preserved.",
                    "La URL se trasladó a una ficha nueva y se conservó su historial de origen.",
                ))
                st.rerun()
    elif choice=="Raw URL Table":
        st.markdown(_l(st, "### Raw URL table", "### Tabla técnica de URL"))
        st.info(_l(
            st,
            "This is the URL-level maintenance view. Normal review should happen from Site Cards.",
            "Esta es la vista de mantenimiento por URL. La revisión habitual debe hacerse desde las fichas.",
        ))
        show_severe=st.checkbox(
            _l(st, "Show severe restricted metadata", "Mostrar metadatos restringidos graves"),
            value=False,key="raw_show_severe_restricted_metadata",
            help=_l(
                st,
                "Advanced-only metadata. Unsafe content fields remain unavailable.",
                "Metadatos solo avanzados. Los campos de contenido no seguro siguen sin estar disponibles.",
            ),
        )
        rows=query("""SELECT ou.id,ou.url,ou.status,ou.active,ou.primary_category,ou.risk_level,
          ou.http_status,ou.dead_reason,ou.last_checked_at,ou.source_url,sc.canonical_site_id,sc.display_name
          FROM onion_urls ou LEFT JOIN site_cards sc ON sc.id=ou.site_card_id
          WHERE ou.primary_category NOT IN ('adult_restricted','adult_filtered') AND ou.storage_policy!='discard'
          AND (?=1 OR ou.primary_category!='severe_abuse_risk')
          ORDER BY ou.last_seen DESC LIMIT 2000""",(int(show_severe),))
        st.dataframe(pd.DataFrame(rows),width="stretch",hide_index=True,height=520)
        dead=[row for row in rows if row.get("status")=="dead"]
        if dead:
            dead_choices={f"{row['display_name'] or row['canonical_site_id']} · {row['url']}":row for row in dead}
            selected=dead_choices[st.selectbox(
                _l(st, "Dead mirror to recheck", "Espejo caído que volver a comprobar"),
                list(dead_choices),
            )]
            if st.button(
                _l(st, "Recheck dead mirror", "Volver a comprobar el espejo caído"),
                disabled=not can_manage_collection,
            ) and _authorize_action(st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
                with storage.get_db() as db:
                    db.execute("UPDATE onion_urls SET active=1,status='queued',dead_reason=NULL,next_crawl_at=? WHERE id=? AND queue_policy!='blocked'",(storage.utc_now_iso(),selected["id"]))
                query.clear()
                st.success(_l(
                    st,
                    "Dead mirror queued for one full-policy recheck.",
                    "El espejo caído se puso en cola para una comprobación completa.",
                ))
    elif choice=="Related Site Groups": _simple_related_sites(st,query)
    elif choice=="Repeated Clues": _simple_clues(st,query)
    elif choice=="Page Disclosures": _simple_disclosures(st,query)
    elif choice=="Safety & Setup": _simple_setup(st)
    elif choice=="Maintenance Tools":
        st.markdown(_l(
            st, "### Safe database maintenance", "### Mantenimiento seguro de la base de datos"
        ))
        st.info(_l(
            st,
            "These actions rebuild stored indexes only. They do not visit sites or perform new "
            "network requests.",
            "Estas acciones solo reconstruyen índices guardados. No visitan sitios ni realizan "
            "nuevas solicitudes de red.",
        ))
        if st.button(
            _l(st, "Refresh changed Site Cards", "Actualizar fichas modificadas"),
            disabled=not can_manage_settings,
        ) and _authorize_action(
                st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE):
            result=site_dedupe.refresh_dirty_site_cards()
            query.clear()
            st.success(_l(
                st,
                f"Refreshed {result['refreshed']} changed Site Card(s).",
                f"Se actualizaron {result['refreshed']} fichas modificadas.",
            ))
        if st.button(
            _l(st, "Rebuild Site Cards", "Reconstruir fichas de sitios"),
            disabled=not can_manage_settings,
        ) and _authorize_action(
                st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE):
            result=site_dedupe.backfill_existing_urls()
            query.clear()
            st.success(_l(
                st,
                f"Processed {result['processed']} URL rows; {result['cards']} Site Cards are available.",
                f"Se procesaron {result['processed']} filas de URL; hay {result['cards']} fichas disponibles.",
            ))
        if st.button(
            _l(st, "Rebuild Dedupe Index", "Reconstruir índice de duplicados"),
            disabled=not can_manage_settings,
        ) and _authorize_action(
                st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE):
            result=site_dedupe.backfill_existing_urls()
            query.clear()
            st.success(_l(
                st,
                f"Dedupe index refreshed across {result['processed']} URL rows.",
                f"Índice de duplicados actualizado en {result['processed']} filas de URL.",
            ))
        if st.button(
            _l(st, "Rebuild Mirror Clusters", "Reconstruir grupos de espejos"),
            disabled=not can_manage_settings,
        ) and _authorize_action(
                st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE):
            count=storage.rebuild_mirror_clusters_from_metadata()
            query.clear()
            st.success(_l(
                st,
                f"Re-indexed {count} stored URL fingerprints into mirror clusters.",
                f"Se reindexaron {count} huellas de URL guardadas en grupos de espejos.",
            ))
    else:
        st.markdown(_l(st, "### Clean Dead Links", "### Limpiar enlaces caídos"))
        st.info(_l(
            st,
            "This removes confirmed 404/410 and repeatedly failing URLs from the active queue. "
            "Their database rows and source-chain history are preserved for audit.",
            "Esto retira de la cola activa las URL con 404/410 confirmados o fallos repetidos. "
            "Sus filas y el historial de origen se conservan para auditoría.",
        ))
        dead=_scalar("SELECT COUNT(*) FROM onion_urls WHERE status='dead' OR http_status IN (404,410) OR error_count>=4")
        st.metric(_l(st, "Dead or exhausted URLs", "URL caídas o agotadas"),dead)
        if st.button(
            _l(st, "Clean Dead Links", "Limpiar enlaces caídos"),
            type="primary",
            disabled=not can_manage_collection,
        ) and _authorize_action(st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
            count=storage.clean_dead_links()
            query.clear()
            st.success(_l(
                st,
                f"Removed {count} URL(s) from the active queue; audit rows were preserved.",
                f"Se retiraron {count} URL de la cola activa; se conservaron las filas de auditoría.",
            ))


def _simple_setup(st) -> None:
    language = current_language(st)
    st.markdown(_l(st, "## Setup and safety", "## Configuración y seguridad"))
    _note(st, _l(
        st,
        "This page checks the staged services: Tor access plus fetch/verify/card workers. Visual "
        "previews are disabled by default for safer production use.",
        "Esta página comprueba los servicios por etapas: acceso Tor y procesos de recopilación, "
        "verificación y fichas. Las vistas previas visuales están desactivadas por defecto para un "
        "uso más seguro en producción.",
    ))
    pipeline = _pipeline_status()
    online = (pipeline["fetch_workers"] + pipeline["verify_workers"] + pipeline["card_workers"]) > 0
    preview_available, preview_message = screenshot_support_status()
    cols = st.columns(4)
    cols[0].metric(
        _l(st, "Worker pipeline", "Servicios de procesamiento"),
        _l(st, "Online", "Activos") if online else _l(st, "Offline", "Inactivos"),
    )
    cols[1].metric(
        _l(st, "Crawler enabled", "Arachne activado"),
        _l(st, "Yes", "Sí") if get_bool("ONION_CRAWLER_ENABLED", False)
        else _l(st, "No", "No"),
    )
    cols[2].metric(
        _l(st, "Visual previews", "Vistas previas visuales"),
        _l(st, "On", "Activadas") if get_bool("ENABLE_PAGE_SCREENSHOTS", False)
        else _l(st, "Off", "Desactivadas"),
    )
    cols[3].metric(
        _l(st, "Source storage", "Almacenamiento del código fuente"),
        _l(st, "Minimized", "Minimizado"),
    )
    st.markdown(_l(st, "### Server setup", "### Configuración del servidor"))
    st.code("cd /root/arachne\n.venv/bin/python -m pip install -r requirements.txt", language="bash")
    st.write(_l(st, "Add these lines to `.env`:", "Añade estas líneas a `.env`:"))
    st.code("ONION_CRAWLER_ENABLED=true\nENABLE_PAGE_SCREENSHOTS=false\nSTORE_RAW_HTML=false\nSTORE_FULL_VISIBLE_TEXT=false", language=None)
    st.write(_l(
        st,
        "Then restart the dashboard plus fetch, verify and card worker services.",
        "Después reinicia el panel y los servicios de recopilación, verificación y fichas.",
    ))
    st.code("systemctl disable --now arachne-preview-worker 2>/dev/null || true\nsystemctl restart arachne-dashboard arachne-fetch-worker arachne-verify-worker arachne-card-worker", language="bash")
    preview_messages_es = {
        "Disabled by process environment": "Desactivadas por el entorno del proceso",
        "Disabled by dashboard runtime setting": "Desactivadas desde los ajustes del panel",
        "Disabled by server .env": "Desactivadas en el archivo .env del servidor",
        "Disabled by config.json": "Desactivadas en config.json",
        "Disabled by default": "Desactivadas por defecto",
        "Disabled by configuration": "Desactivadas por configuración",
        "Playwright is not installed; previews remain safely disabled":
            "Playwright no está instalado; las vistas previas siguen desactivadas de forma segura",
        "Playwright is installed, but Chromium is not installed; run: python -m playwright install chromium":
            "Playwright está instalado, pero Chromium no; ejecuta: python -m playwright install chromium",
        "Tor SOCKS proxy is not configured correctly for preview capture":
            "El proxy Tor SOCKS no está configurado correctamente para las vistas previas",
        "Available (Tor proxy, JavaScript disabled, subresources blocked)":
            "Disponibles (proxy Tor, JavaScript desactivado y subrecursos bloqueados)",
    }
    preview_status = (
        preview_messages_es.get(preview_message, value_label(preview_message, language))
        if language == "es" else preview_message
    )
    st.caption(
        f"{_l(st, 'Preview status', 'Estado de vistas previas')}: {preview_status}"
    )
    st.markdown(_l(st, "### Safety promises", "### Garantías de seguridad"))
    safe_note = _l(
        st,
        """<div class="safe-note">✓ Only known or visibly discovered links are queued<br>
        ✓ No guessed directories, port scanning, brute forcing, login, CAPTCHA handling, or forms<br>
        ✓ Blocked files stay blocked<br>✓ Raw HTML/source archiving stays off by default<br>
        ✓ Related-site matches are clues, not claims about identity or physical server location</div>""",
        """<div class="safe-note">✓ Solo se ponen en cola enlaces conocidos o descubiertos de forma visible<br>
        ✓ No se adivinan directorios ni se realizan escaneos de puertos, fuerza bruta, inicios de sesión, CAPTCHA o formularios<br>
        ✓ Los archivos bloqueados siguen bloqueados<br>✓ El archivado de HTML o código fuente sin depurar permanece desactivado por defecto<br>
        ✓ Las coincidencias entre sitios son pistas, no afirmaciones sobre identidad ni ubicación física del servidor</div>""",
    )
    st.markdown(safe_note, unsafe_allow_html=True)


def _overview(st, query) -> None:
    _note(st, "Operational snapshot of the passive collection queue, review workload, recent matches, and crawler health.")
    metrics = [
        ("Total onion URLs", _scalar("SELECT COUNT(*) FROM onion_urls")),
        ("Queued URLs", _scalar("SELECT COUNT(*) FROM onion_urls WHERE status IN ('new','queued','retry')")),
        ("Crawled URLs", _scalar("SELECT COUNT(*) FROM onion_urls WHERE status='crawled'")),
        ("Blocked URLs", _scalar("SELECT COUNT(*) FROM onion_urls WHERE status='blocked'")),
        ("Dead URLs", _scalar("SELECT COUNT(*) FROM onion_urls WHERE status='dead'")),
        ("Pending hits", _scalar("SELECT COUNT(*) FROM onion_hits WHERE review_status='pending'")),
        ("Mirror clusters", _scalar("SELECT COUNT(*) FROM mirror_clusters")),
        ("Indicators", _scalar("SELECT COUNT(*) FROM indicators")),
        ("Passive exposures", _scalar("SELECT COUNT(*) FROM passive_exposures")),
        ("High-risk items", _scalar("SELECT COUNT(*) FROM onion_urls WHERE risk_level IN ('ALTO','CRITICO')")),
    ]
    cols = st.columns(5)
    for idx, (label, value) in enumerate(metrics):
        cols[idx % 5].metric(label, value)

    st.subheader("Needs Attention")
    st.caption("Prioritized records that are pending, high risk, or explicitly marked for reporting.")
    attention = query("""SELECT h.*,ou.primary_category,mu.cluster_id,mc.cluster_type FROM onion_hits h
        LEFT JOIN onion_urls ou ON ou.url=h.url
        LEFT JOIN mirror_urls mu ON mu.url=h.url LEFT JOIN mirror_clusters mc ON mc.id=mu.cluster_id
        WHERE h.review_status IN ('pending','needs_report') OR h.risk_level IN ('ALTO','CRITICO')
        ORDER BY CASE h.review_status WHEN 'needs_report' THEN 0 ELSE 1 END, h.score DESC, h.ts DESC LIMIT 6""")
    if attention:
        for item in attention: _compact_hit(st, item)
    else:
        st.success("No records currently require prioritized attention.")

    left, right = st.columns(2)
    with left:
        st.subheader("Recent Onion Hits")
        st.caption("Latest pages retained because of scoring, indicators, or visible passive disclosures.")
        hits = query("""SELECT h.*,ou.primary_category,mu.cluster_id,mc.cluster_type FROM onion_hits h
            LEFT JOIN onion_urls ou ON ou.url=h.url
            LEFT JOIN mirror_urls mu ON mu.url=h.url LEFT JOIN mirror_clusters mc ON mc.id=mu.cluster_id
            ORDER BY h.ts DESC LIMIT 6""")
        for item in hits: _compact_hit(st, item)
        if not hits: st.info("No onion hits collected yet.")
    with right:
        st.subheader("Active Mirror Clusters")
        st.caption("Related URLs grouped only through shared public indicators, hashes, titles, and link structure.")
        clusters = query("""SELECT c.*,COUNT(u.id) AS url_count FROM mirror_clusters c
            LEFT JOIN mirror_urls u ON u.cluster_id=c.id WHERE c.status='active'
            GROUP BY c.id ORDER BY c.last_seen DESC,c.relevance_score DESC LIMIT 6""")
        for cluster in clusters:
            profile = parse_json(cluster.get("attribution_profile_json"), {})
            st.markdown(f'<div class="analyst-card"><h3>Cluster #{cluster["id"]} · {html.escape(_fmt(cluster.get("cluster_type")))}</h3>'
                        f'{risk_badge(cluster.get("risk_level"))} {review_badge(cluster.get("review_status"))} '
                        f'{confidence_badge(profile.get("confidence_level", "LOW"))}'
                        f'<div class="card-meta">{cluster.get("url_count",0)} URLs · Last seen {_fmt(cluster.get("last_seen"))}</div></div>', unsafe_allow_html=True)
        if not clusters: st.info("No active mirror clusters yet.")

    st.subheader("Recent Passive Exposures")
    st.caption("Technical details already visible in normal responses; no errors were induced and no extra paths were requested.")
    exposures = query("SELECT * FROM passive_exposures ORDER BY ts DESC LIMIT 8")
    if exposures:
        cols = st.columns(2)
        for idx, exposure in enumerate(exposures):
            with cols[idx % 2]:
                st.markdown(f'{severity_badge(exposure.get("severity"))} **{html.escape(exposure.get("exposure_type", "unknown").replace("_"," ").title())}**')
                st.caption(f"{exposure.get('url')} · {exposure.get('ts')}")
    else: st.info("No passive exposures recorded.")

    st.subheader("Crawler Health")
    latest = _scalar("SELECT MAX(last_crawled) FROM onion_urls", default=None)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Queue", metrics[1][1]); c2.metric("Crawled", metrics[2][1]); c3.metric("Blocked", metrics[3][1]); c4.metric("Dead", metrics[4][1])
    c5.metric("Latest activity", latest or "None")


def _onion_hits(st, query) -> None:
    _note(st, "Pages on this screen matched configured sorting rules or contained useful public details. Review status is a manual choice, not an automatic conclusion.")
    rows = query("""SELECT h.*,ou.first_seen,ou.risk_flags,ou.primary_category,
        mu.cluster_id,mc.cluster_type,pp.preview_path
        FROM onion_hits h LEFT JOIN onion_urls ou ON ou.url=h.url
        LEFT JOIN mirror_urls mu ON mu.url=h.url LEFT JOIN mirror_clusters mc ON mc.id=mu.cluster_id
        LEFT JOIN page_previews pp ON pp.url=h.url ORDER BY h.ts DESC LIMIT 250""")
    prepared = []
    for row in rows:
        row["_reasons"] = parse_json(row.get("reasons")); row["_indicators"] = parse_json(row.get("indicators_json"))
        row["_exposures"] = parse_json(row.get("passive_exposures_json"))
        row["_category"] = safe_category_label(row.get("primary_category") or "unknown")
        prepared.append(row)
    c1, c2, c3, c4, c5 = st.columns(5)
    review = c1.multiselect("Review", REVIEW_STATES)
    risks = c2.multiselect("Risk", ["NULO","BAJO","MEDIO","ALTO","CRITICO"])
    categories = c3.multiselect("Category", sorted({r["_category"] for r in prepared}))
    cluster_values = sorted({str(r["cluster_id"]) for r in prepared if r.get("cluster_id")})
    clusters = c4.multiselect("Cluster", cluster_values)
    search = c5.text_input("Search", placeholder="Title, URL, snippet")
    filtered = [r for r in prepared if (not review or r.get("review_status") in review)
        and (not risks or r.get("risk_level") in risks) and (not categories or r["_category"] in categories)
        and (not clusters or str(r.get("cluster_id")) in clusters)
        and (not search or search.casefold() in " ".join([_fmt(r.get("title")),_fmt(r.get("url")),_fmt(r.get("snippet"))]).casefold())]
    st.caption(f"Showing {min(len(filtered), 30)} of {len(filtered)} matching hits. Narrow filters for faster triage.")
    for row in filtered[:30]:
        title = html.escape(_fmt(row.get("title") or "Untitled page"))
        st.markdown(f'<div class="analyst-card"><h3>Hit #{row["id"]} · {title}</h3>'
                    f'{category_badge(row["_category"])} {risk_badge(row.get("risk_level"))} {review_badge(row.get("review_status"))}'
                    f'<div class="card-meta">Score {row.get("score",0)} · Cluster {row.get("cluster_id") or "Unassigned"} · First seen {_fmt(row.get("first_seen") or row.get("ts"))}</div></div>', unsafe_allow_html=True)
        meta, preview_col = st.columns([3, 1])
        with meta:
            st.caption("Exact page URL")
            st.code(row.get("url", "Unavailable"), language=None)
            st.markdown("**Why this was flagged**")
            st.markdown(f'<div class="reason-box">{html.escape(explain_flag(row["_reasons"],row["_indicators"],row["_exposures"],row.get("cluster_id")))}</div>', unsafe_allow_html=True)
            reason_labels = [str(x).replace("_"," ") for x in row["_reasons"] if not str(x).startswith("lang:")]
            st.write("Matched reasons:", ", ".join(reason_labels) or "No scoring reason retained")
            summary, values = indicator_summary(row["_indicators"])
            st.markdown(f"**Indicators — {summary}**")
            for value in values: st.text(redact_sensitive(value))
            exposures = row["_exposures"]
            if exposures:
                highest = max((e.get("severity","info") for e in exposures), key=lambda x: SEVERITY_ORDER.get(x,0))
                st.markdown(f"**Passive exposures — {len(exposures)} observed, highest severity:** {highest.upper()}")
                st.write(", ".join(sorted({e.get("type","unknown").replace("_"," ") for e in exposures})))
            else: st.caption("No passive exposures recorded for this hit.")
            st.markdown("**Safe snippet**")
            st.info(redact_sensitive((row.get("snippet") or "No snippet available")[:700]))
        with preview_col: _preview(st, row.get("preview_path"))
        with st.expander("Technical detail (redacted JSON)"):
            st.code(json.dumps({"reasons":row["_reasons"],"indicators":row["_indicators"],"passive_exposures":row["_exposures"],"risk_flags":parse_json(row.get("risk_flags"))}, ensure_ascii=False, indent=2), language="json")
        st.markdown("**Review action**")
        action_cols = st.columns(5)
        actions = [("Relevant","relevant"),("False positive","false_positive"),("Needs report","needs_report"),("Reported","reported"),("Blocked","blocked")]
        for col, (label, status) in zip(action_cols, actions, strict=False):
            if col.button(label, key=f"hit-{row['id']}-{status}", width="stretch"):
                storage.set_review_status("onion_hit", row["id"], status); query.clear(); st.rerun()
        st.divider()
    if not filtered: st.info("No hits match the selected filters.")


def _frontier(st, query, pd) -> None:
    _note(st, "The frontier is the passive crawler's URL work queue. Queued items await a normal GET; crawled items were processed; blocked items violated safety/content rules; dead items exceeded retry limits.")
    rows = query("""SELECT ou.*,mu.cluster_id,mc.cluster_type,pp.preview_path FROM onion_urls ou
        LEFT JOIN mirror_urls mu ON mu.url=ou.url LEFT JOIN mirror_clusters mc ON mc.id=mu.cluster_id
        LEFT JOIN page_previews pp ON pp.url=ou.url ORDER BY ou.first_seen DESC LIMIT 1000""")
    for row in rows:
        row["category"] = safe_category_label(row.get("primary_category") or "unknown")
    c1,c2,c3,c4,c5,c6 = st.columns(6)
    statuses=c1.multiselect("Status",sorted({r.get("status") for r in rows if r.get("status")})); risks=c2.multiselect("Risk",sorted({r.get("risk_level") for r in rows if r.get("risk_level")},key=lambda x:RISK_ORDER.get(x,0)))
    categories=c3.multiselect("Category",sorted({r["category"] for r in rows})); domains=c4.multiselect("Domain",sorted({r.get("onion_domain") for r in rows if r.get("onion_domain")}))
    clusters=c5.multiselect("Cluster",sorted({str(r.get("cluster_id")) for r in rows if r.get("cluster_id")})); reviews=c6.multiselect("Review",sorted({r.get("review_status") for r in rows if r.get("review_status")}))
    search=st.text_input("Search frontier",placeholder="URL, title, or domain")
    filtered=[r for r in rows if (not statuses or r.get("status") in statuses) and (not risks or r.get("risk_level") in risks)
        and (not categories or r["category"] in categories) and (not domains or r.get("onion_domain") in domains)
        and (not clusters or str(r.get("cluster_id")) in clusters) and (not reviews or r.get("review_status") in reviews)
        and (not search or search.casefold() in " ".join([_fmt(r.get("url")),_fmt(r.get("title")),_fmt(r.get("onion_domain"))]).casefold())]
    table=[{"URL":r.get("url"),"Title":r.get("title"),"Category":r["category"],"Status":r.get("status"),"Risk":r.get("risk_level"),
            "Relevance":r.get("relevance_score"),"First seen":r.get("first_seen"),"Last crawled":r.get("last_crawled"),"Next crawl":r.get("next_crawl_at"),
            "Errors":r.get("error_count"),"Cluster":r.get("cluster_id"),"Preview":"Yes" if r.get("preview_path") else "No"} for r in filtered]
    st.dataframe(pd.DataFrame(table),width="stretch",hide_index=True,height=420)
    if not filtered: return
    options={f"{r.get('title') or 'Untitled'} · {r.get('url')}":r for r in filtered[:300]}
    selected=options[st.selectbox("URL drill-down",list(options))]
    st.markdown(f'### {html.escape(_fmt(selected.get("title") or "Untitled page"))} {category_badge(selected["category"])} {status_badge(selected.get("status"))} {risk_badge(selected.get("risk_level"))}',unsafe_allow_html=True)
    left,right=st.columns([3,1])
    with left:
        st.code(selected.get("url",""),language=None)
        a,b,c,d=st.columns(4); a.metric("Relevance",selected.get("relevance_score",0)); b.metric("Errors",selected.get("error_count",0)); c.metric("Cluster",selected.get("cluster_id") or "None"); d.metric("HTTP",selected.get("http_status") or "Unknown")
        st.write("**Crawl timing:**",selected.get("last_crawled") or "Never crawled","→ next",selected.get("next_crawl_at") or "Not scheduled")
        st.write("**Discovery source:**",selected.get("source_type") or "Unknown",selected.get("source_url") or "")
        hit=query("SELECT snippet FROM onion_hits WHERE url=? ORDER BY ts DESC LIMIT 1",(selected["url"],))
        st.info(redact_sensitive(hit[0]["snippet"]) if hit and hit[0].get("snippet") else "No safe snippet available.")
        indicators=query("""SELECT i.indicator_type,i.value,l.context_snippet FROM indicators i JOIN indicator_links l ON l.indicator_id=i.id WHERE l.source_ref=? ORDER BY i.indicator_type""",(selected["url"],))
        exposures=query("SELECT exposure_type,severity,value,context FROM passive_exposures WHERE url=? ORDER BY ts DESC",(selected["url"],))
        with st.expander(f"Related indicators ({len(indicators)})"):
            for item in indicators: st.write(f"**{item['indicator_type'].replace('_',' ').title()}** — {redact_sensitive(item.get('value') or '')}")
        with st.expander(f"Passive exposures ({len(exposures)})"):
            for item in exposures: st.markdown(f'{severity_badge(item["severity"])} **{item["exposure_type"].replace("_"," ").title()}** — {html.escape(redact_sensitive(item.get("value") or ""))}',unsafe_allow_html=True)
    with right: _preview(st,selected.get("preview_path"))


def _clusters(st, query, pd) -> None:
    _note(st, "A mirror cluster groups URLs that appear related through passive signals such as shared hashes, titles, public handles, wallets, phrases, or link structure. It is not an origin-server claim.")
    clusters=query("""SELECT c.*,COUNT(u.id) AS url_count FROM mirror_clusters c LEFT JOIN mirror_urls u ON u.cluster_id=c.id GROUP BY c.id ORDER BY c.last_seen DESC LIMIT 300""")
    summary=[]
    for c in clusters:
        p=parse_json(c.get("attribution_profile_json"),{})
        summary.append({"Cluster":c["id"],"Type":c.get("cluster_type"),"Risk":c.get("risk_level"),"Review":c.get("review_status"),"URLs":c.get("url_count",0),"First seen":c.get("first_seen"),"Last seen":c.get("last_seen"),"Confidence":p.get("confidence_level","LOW"),"Summary":c.get("summary")})
    st.dataframe(pd.DataFrame(summary),width="stretch",hide_index=True)
    if not clusters: st.info("No mirror clusters available."); return
    labels={f"Cluster #{c['id']} · {c.get('cluster_type') or 'unknown'} · {c.get('url_count',0)} URLs":c for c in clusters}
    selected=labels[st.selectbox("Cluster drill-down",list(labels))]; cid=selected["id"]
    st.markdown(f'## Cluster #{cid} {risk_badge(selected.get("risk_level"))} {review_badge(selected.get("review_status"))} {status_badge(selected.get("status"))}',unsafe_allow_html=True)
    st.subheader("Cluster Summary")
    st.write(selected.get("summary") or "No summary has been recorded.")
    shared=parse_json(selected.get("shared_indicators_json")); st.info(f"Grouped because collected URLs share {len(shared)} public indicator, hash, or title signal(s). Similarity is passive and needs review.")
    st.markdown(f'**Suggested next step:** {suggested_action(selected.get("risk_level"),selected.get("review_status"))}')
    review_col, save_col = st.columns([2, 1])
    new_review = review_col.selectbox("Cluster review status", REVIEW_STATES,
        index=REVIEW_STATES.index(selected.get("review_status")) if selected.get("review_status") in REVIEW_STATES else 0,
        key=f"cluster-review-{cid}")
    if save_col.button("Save cluster review", key=f"save-cluster-{cid}", width="stretch"):
        storage.set_review_status("cluster", cid, new_review); query.clear(); st.rerun()
    related=query("""SELECT mu.*,ou.risk_level,ou.status AS crawl_status,pp.preview_path FROM mirror_urls mu LEFT JOIN onion_urls ou ON ou.url=mu.url LEFT JOIN page_previews pp ON pp.url=mu.url WHERE mu.cluster_id=? ORDER BY mu.last_seen DESC""",(cid,))
    st.subheader("Related URLs")
    st.dataframe(pd.DataFrame([{"URL":u.get("url"),"Title":u.get("title"),"Risk":u.get("risk_level") or "NULO","Status":u.get("crawl_status") or u.get("status"),"Preview":"Yes" if u.get("preview_path") else "No"} for u in related]),width="stretch",hide_index=True)
    previews=[u for u in related if safe_preview_path(u.get("preview_path"))][:3]
    if previews:
        cols=st.columns(len(previews))
        for col,item in zip(cols,previews, strict=False):
            with col: _preview(st,item.get("preview_path"),item.get("title") or "Related URL preview")
    st.subheader("Shared Indicators")
    grouped=defaultdict(list)
    for item in shared:
        kind,value=(str(item).split(":",1)+[""])[:2] if ":" in str(item) else ("other",str(item))
        grouped[kind].append(value)
    if grouped:
        cols=st.columns(min(3,len(grouped)))
        for idx,(kind,values) in enumerate(grouped.items()):
            with cols[idx%len(cols)]:
                st.markdown(f"**{kind.replace('_',' ').title()}**")
                for value in values[:8]: st.text(redact_sensitive(value))
    else: st.caption("No shared indicators retained.")
    st.subheader("Public Connections")
    try: profile=build_attribution_profile(cid)
    except ValueError: profile={}
    c1,c2=st.columns([1,3])
    with c1:
        st.metric("Confidence score",f"{profile.get('confidence_score',0)}/100")
        st.markdown(confidence_badge(profile.get("confidence_level","LOW")),unsafe_allow_html=True)
        st.progress(int(profile.get("confidence_score",0))/100)
    with c2:
        st.write(profile.get("explanation") or "No connection explanation is available.")
        st.warning(profile.get("limitations") or "Passive correlation does not identify a server or operator.")
    st.subheader("Passive Exposures")
    exposures=query("""SELECT pe.* FROM passive_exposures pe JOIN mirror_urls mu ON mu.url=pe.url WHERE mu.cluster_id=? ORDER BY pe.ts DESC""",(cid,))
    for item in exposures[:20]: st.markdown(f'{severity_badge(item["severity"])} **{item["exposure_type"].replace("_"," ").title()}** · {html.escape(item["url"])}',unsafe_allow_html=True)
    if not exposures: st.caption("No passive exposures across this cluster.")
    st.subheader("Report Actions")
    reports=query("SELECT * FROM evidence_reports WHERE cluster_id=? ORDER BY ts DESC",(cid,))
    if st.button("Build safe Markdown report",type="primary"):
        output=build_cluster_report(cid); query.clear(); st.success(f"Report generated: {output}")
    for report in reports[:5]: st.caption(f"#{report['id']} · {report['ts']} · {report['output_path']}")


def _indicators(st, query) -> None:
    _note(st, "Search public indicators and see where each value appeared across collected sources. Context is short and redacted; this view does not encourage contact or interaction.")
    c1,c2,c3=st.columns([2,1,1]); value=c1.text_input("Indicator value",placeholder="Exact or partial value"); exact=c2.checkbox("Exact match"); types=[r["indicator_type"] for r in query("SELECT DISTINCT indicator_type FROM indicators ORDER BY indicator_type")]; kind=c3.selectbox("Type",["All"]+types)
    if not value and kind=="All": st.info("Enter a value or choose an indicator type to begin entity lookup."); return
    operator="=" if exact else "LIKE"; needle=value.casefold() if exact else f"%{value.casefold()}%"
    sql=f"""SELECT i.*,COUNT(DISTINCT l.id) AS linked_sources,COUNT(DISTINCT mu.cluster_id) AS related_clusters
        FROM indicators i LEFT JOIN indicator_links l ON l.indicator_id=i.id LEFT JOIN mirror_urls mu ON mu.url=l.source_ref
        WHERE lower(i.normalized_value) {operator} ?"""
    params=[needle]
    if kind!="All": sql+=" AND i.indicator_type=?"; params.append(kind)
    sql+=" GROUP BY i.id ORDER BY i.last_seen DESC LIMIT 200"
    results=query(sql,tuple(params))
    if not results: st.info("No matching indicators."); return
    for item in results:
        st.markdown(f'<div class="analyst-card"><h3>{html.escape(item["indicator_type"].replace("_"," ").title())}</h3>'
                    f'{confidence_badge("HIGH" if item.get("confidence",0)>=.8 else "MEDIUM" if item.get("confidence",0)>=.5 else "LOW")}'
                    f'<div class="card-meta">{html.escape(redact_sensitive(item.get("value") or ""))} · {item.get("linked_sources",0)} linked sources · {item.get("related_clusters",0)} clusters</div></div>',unsafe_allow_html=True)
        with st.expander("Occurrence and relationship details"):
            a,b,c=st.columns(3); a.metric("Confidence",f"{float(item.get('confidence',0)):.0%}"); b.metric("First seen",item.get("first_seen") or "Unknown"); c.metric("Last seen",item.get("last_seen") or "Unknown")
            st.write("**Normalized value:**",redact_sensitive(item.get("normalized_value") or ""))
            links=query("""SELECT l.source_type,l.source_ref,l.context_snippet,l.first_seen,mu.cluster_id FROM indicator_links l LEFT JOIN mirror_urls mu ON mu.url=l.source_ref WHERE l.indicator_id=? ORDER BY l.first_seen DESC""",(item["id"],))
            for link in links:
                st.markdown(f"**{link.get('source_type') or 'Unknown source'}** · Cluster {link.get('cluster_id') or 'Unassigned'}")
                st.code(link.get("source_ref") or "Unavailable",language=None)
                st.caption(redact_sensitive(link.get("context_snippet") or "No context retained"))


def _attribution(st, query) -> None:
    _note(st, "Public Connections compares repeated public signals across collected pages. It does not identify a person, physical host, or hidden origin server.")
    clusters=query("SELECT id,cluster_type,risk_level FROM mirror_clusters ORDER BY last_seen DESC")
    if not clusters: st.info("No related groups are available for comparison."); return
    labels={f"#{c['id']} · {c.get('cluster_type') or 'unknown'} · {c.get('risk_level') or 'NULO'}":c["id"] for c in clusters}; cid=labels[st.selectbox("Cluster",list(labels))]
    profile=build_attribution_profile(cid)
    c1,c2=st.columns([1,3])
    with c1:
        st.metric("Confidence",f"{profile['confidence_score']}/100")
        st.markdown(confidence_badge(profile["confidence_level"]),unsafe_allow_html=True); st.progress(profile["confidence_score"]/100)
    with c2:
        st.subheader(f"Why confidence is {profile['confidence_level'].lower()}")
        st.write(profile["explanation"]); st.warning(profile["limitations"])
    st.subheader("Shared factors")
    factors=[("Shared handles",profile["shared_handles"]),("Shared wallets",profile["shared_wallets"]),("Shared emails",profile["shared_emails"]),("Shared content hashes",profile["shared_content_hashes"]),("Shared fuzzy hashes",profile["shared_fuzzy_hashes"]),("Shared domains",profile["shared_onion_domains"]+profile["shared_clearnet_domains"]),("Shared titles",profile["shared_titles"]),("Shared phrases",profile["shared_phrases"])]
    cols=st.columns(2)
    for idx,(label,values) in enumerate(factors):
        with cols[idx%2]:
            st.markdown(f"**{label} ({len(values)})**")
            if values:
                for value in values[:10]: st.text(redact_sensitive(str(value)))
            else: st.caption("No repeated factor observed.")
    st.info("A higher score means more repeated public signals. It does not establish identity or ownership.")


EXPOSURE_EXPLANATIONS={"server_header":"The normal response disclosed server software information.","directory_listing_visible":"The page visibly presented a directory index.","debug_message_visible":"A debug message was already visible in the returned page.","clearnet_link_visible":"The page visibly linked to a clearnet address; it was not fetched by default.","stack_trace":"A stack trace was visible and retained only as a short redacted snippet.","absolute_path_disclosure":"A local-looking path was visible in the normal response.","powered_by_header":"The response disclosed a framework/runtime header.","onion_link_visible":"Another onion link was visible in the page response."}


def _exposures(st, query) -> None:
    _note(st, "Passive exposures are technical disclosures already visible during a normal allowed fetch. The system does not induce errors, probe services, or request additional paths.")
    rows=query("""SELECT pe.*,mu.cluster_id FROM passive_exposures pe LEFT JOIN mirror_urls mu ON mu.url=pe.url ORDER BY pe.ts DESC LIMIT 1000""")
    c1,c2,c3,c4=st.columns(4); severities=c1.multiselect("Severity",["info","low","medium","high"]); kinds=c2.multiselect("Type",sorted({r["exposure_type"] for r in rows})); url=c3.text_input("URL contains"); clusters=c4.multiselect("Cluster",sorted({str(r["cluster_id"]) for r in rows if r.get("cluster_id")}))
    filtered=[r for r in rows if (not severities or r["severity"] in severities) and (not kinds or r["exposure_type"] in kinds) and (not url or url.casefold() in r["url"].casefold()) and (not clusters or str(r.get("cluster_id")) in clusters)]
    for item in filtered[:100]:
        st.markdown(f'<div class="analyst-card"><h3>{html.escape(item["exposure_type"].replace("_"," ").title())}</h3>{severity_badge(item["severity"])} '
                    f'<span class="card-meta">Cluster {item.get("cluster_id") or "Unassigned"} · {_fmt(item.get("ts"))}</span></div>',unsafe_allow_html=True)
        st.code(item["url"],language=None)
        st.write(EXPOSURE_EXPLANATIONS.get(item["exposure_type"],"A technical detail was visible in the normal response and retained for review."))
        st.caption("Value: "+redact_sensitive(item.get("value") or "Unavailable")); st.info(redact_sensitive(item.get("context") or "No context retained"))
    if not filtered: st.info("No passive exposures match the selected filters.")


def _reports(st, query, pd) -> None:
    _note(st, "Saved reports are metadata-based Markdown files containing hashes, public matches, technical summaries, preview references, and short safe snippets only.")
    reports=query("SELECT * FROM evidence_reports ORDER BY ts DESC LIMIT 500")
    st.dataframe(pd.DataFrame([{"Report ID":r["id"],"Type":r.get("report_type"),"Cluster":r.get("cluster_id"),"Generated":r.get("ts"),"Generated by":r.get("generated_by"),"Path":r.get("output_path"),"Status":r.get("status")} for r in reports]),width="stretch",hide_index=True)
    if not reports: st.info("No saved reports have been generated."); return
    labels={f"#{r['id']} · Cluster {r.get('cluster_id') or 'N/A'} · {r.get('ts')}":r for r in reports}; selected=labels[st.selectbox("Report preview",list(labels))]
    path=Path(selected.get("output_path") or "")
    st.code(str(path),language=None)
    with st.expander("Preview safe Markdown report",expanded=True):
        try:
            safe_path = path.resolve()
            is_safe = safe_path.is_relative_to(REPORTS_DIR.resolve()) and safe_path.is_file() and safe_path.suffix.lower()==".md"
        except (OSError, ValueError):
            is_safe = False
        if is_safe: st.markdown(safe_path.read_text(encoding="utf-8")[:50000])
        else: st.warning("Report file is unavailable or outside the approved reports directory.")


def _safe_service_state(service_name: str) -> str:
    """Best-effort read-only systemd status with a tiny timeout."""
    if not shutil.which("systemctl"):
        return "unavailable"
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service_name],
            capture_output=True, text=True, timeout=0.45, check=False,
        )
        value = (result.stdout or result.stderr or "").strip().splitlines()
        return value[0] if value else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _control_queue_counts() -> dict:
    with storage.get_db() as db:
        tables = {row["name"] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        counts = {
            "url_waiting": db.execute("""SELECT COUNT(*) FROM onion_urls
              WHERE active=1 AND status IN ('new','queued','retry')""").fetchone()[0],
            "url_claimed": db.execute("SELECT COUNT(*) FROM onion_urls WHERE status='claimed'").fetchone()[0],
            "url_dead": db.execute("SELECT COUNT(*) FROM onion_urls WHERE status='dead'").fetchone()[0],
        }
        if "fetched_pages" in tables:
            counts["verify_waiting"] = db.execute("""SELECT COUNT(*) FROM fetched_pages
              WHERE classification_status IN ('pending','retry')""").fetchone()[0]
            counts["verify_claimed"] = db.execute("""SELECT COUNT(*) FROM fetched_pages
              WHERE classification_status='claimed'""").fetchone()[0]
        else:
            counts["verify_waiting"] = counts["verify_claimed"] = 0
        if "site_card_jobs" in tables:
            counts["card_waiting"] = db.execute("""SELECT COUNT(*) FROM site_card_jobs
              WHERE status IN ('queued','retry')""").fetchone()[0]
            counts["card_claimed"] = db.execute("SELECT COUNT(*) FROM site_card_jobs WHERE status='claimed'").fetchone()[0]
        else:
            counts["card_waiting"] = counts["card_claimed"] = 0
        if "page_preview_jobs" in tables:
            counts["preview_waiting"] = db.execute("""SELECT COUNT(*) FROM page_preview_jobs
              WHERE status IN ('queued','retry')""").fetchone()[0]
            counts["preview_claimed"] = db.execute("SELECT COUNT(*) FROM page_preview_jobs WHERE status='claimed'").fetchone()[0]
        else:
            counts["preview_waiting"] = counts["preview_claimed"] = 0
    return {key: int(value or 0) for key, value in counts.items()}


def _control_worker_rows() -> list[dict]:
    with storage.get_db() as db:
        tables = {row["name"] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "worker_instances" not in tables:
            return []
        return [dict(row) for row in db.execute("""SELECT worker_id,worker_type,pid,state,current_url_id,
          current_job_id,last_heartbeat_at,processed_total,last_error
          FROM worker_instances ORDER BY worker_type,worker_id LIMIT 100""")]


def _control_center(st, query, pd) -> None:
    language = current_language(st)
    can_manage_collection = _can(st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE)
    can_manage_settings = _can(st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE)
    _note(st, _l(st,
        "One place to check whether Arachne is online, what is waiting, and which safe operator actions are available.",
        "Un solo lugar para comprobar si Arachne está activo, qué está esperando y qué acciones seguras están disponibles."))

    pipeline = _pipeline_status()
    worker = storage.get_worker_state() or {}
    access = dashboard_auth.dashboard_access_status()
    queues = _control_queue_counts()
    failures = storage.worker_failures_summary()
    backups = backup_service.list_backups()
    tor_policy = circuit_policy_status()
    bot_state = _safe_service_state("arachne-bot.service")
    dashboard_state = _safe_service_state("arachne-dashboard.service")

    st.markdown(section_header(
        _l(st, "System status", "Estado del sistema"),
        _l(st, "Service health at the last available check.", "Estado de los servicios en la última comprobación."),
    ), unsafe_allow_html=True)
    active_workers = int(pipeline["fetch_workers"] + pipeline["verify_workers"] + pipeline["card_workers"])
    tor_state = _tor_status()
    st.markdown(metric_strip([
        (_l(st, "Processing workers", "Procesos activos"), active_workers,
         _l(st, "Fetch · Verify · Cards", "Recopilación · Verificación · Fichas"),
         "ok" if active_workers else "critical"),
        (_l(st, "Telegram bot", "Bot Telegram"), value_label(bot_state, language),
         _l(st, "Access and notifications", "Acceso y avisos"),
         "ok" if bot_state == "active" else "warn"),
        (_l(st, "Dashboard", "Panel"), value_label(dashboard_state, language),
         _l(st, "Web workspace", "Espacio web"),
         "ok" if dashboard_state == "active" else "warn"),
        (_l(st, "Access lock", "Bloqueo"),
         _l(st, "On", "Activo") if access["enabled"] else _l(st, "Off", "Desactivado"),
         _l(st, "Temporary-code gate", "Acceso por código temporal"),
         "ok" if access["enabled"] else "warn"),
        (_l(st, "Tor connection", "Conexión Tor"), value_label(tor_state, language),
         _l(st, "Configured SOCKS endpoint", "Punto SOCKS configurado"),
         "ok" if tor_state == "online" else "warn"),
    ]), unsafe_allow_html=True)

    if bot_state not in {"active", "unavailable"}:
        st.warning(_l(st,
            "Telegram bot is not active according to systemd. On the server run: bash RUN_AFTER_UPLOAD.sh bot-start",
            "El bot de Telegram no aparece activo en systemd. En el servidor ejecuta: bash RUN_AFTER_UPLOAD.sh bot-start"))

    st.markdown("### " + _l(st, "Quick actions", "Acciones rápidas"))
    action_cols = st.columns(3)
    paused = bool((worker or {}).get("is_paused"))
    if action_cols[0].button(_l(st, "Resume crawler" if paused else "Pause crawler",
                                "Reanudar arachne" if paused else "Pausar arachne"),
                             width="stretch", disabled=not can_manage_collection) and _authorize_action(
                                 st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
        storage.set_worker_paused(not paused)
        query.clear()
        st.success(_l(st, "Crawler state updated.", "Estado del arachne actualizado."))
        st.rerun()

    if action_cols[1].button(_l(st, "Create backup now", "Crear copia ahora"),
                             width="stretch", disabled=not can_manage_settings) and _authorize_action(
                                 st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE):
        try:
            result = backup_service.create_daily_backup(keep_days=7, force=True)
            st.success(_l(st, "Backup created and verified: ", "Copia creada y verificada: ") + Path(result["path"]).name)
        except (OSError, ValueError, sqlite3.DatabaseError) as exc:
            st.error(_l(st, "Backup failed safely: ", "La copia falló de forma segura: ") + type(exc).__name__)

    if action_cols[2].button(_l(st, "Open settings", "Abrir ajustes"), width="stretch"):
        _open_workspace_page("Settings")
        st.rerun()
    st.caption(_l(
        st,
        "Access codes are created outside the web interface from the secure messaging menu or the server control command.",
        "Los códigos de acceso se crean fuera de la interfaz web desde el menú de mensajería segura o el control del servidor.",
    ))

    st.markdown("### " + _l(st, "Queue pressure", "Carga de colas"))
    queue_table = [
        {"Stage": _l(st, "Collect pages", "Recopilar páginas"),
         "Waiting": queues["url_waiting"], "Claimed": queues["url_claimed"],
         "Meaning": _l(st, "Known onion pages waiting to be checked.",
                       "Páginas onion conocidas pendientes de comprobación.")},
        {"Stage": _l(st, "Classify pages", "Clasificar páginas"),
         "Waiting": queues["verify_waiting"], "Claimed": queues["verify_claimed"],
         "Meaning": _l(st, "Collected pages waiting for classification.",
                       "Páginas recopiladas pendientes de clasificación.")},
        {"Stage": _l(st, "Update Site Cards", "Actualizar fichas"),
         "Waiting": queues["card_waiting"], "Claimed": queues["card_claimed"],
         "Meaning": _l(st, "Profiles, duplicates and mirrors waiting to be grouped.",
                       "Perfiles, duplicados y espejos pendientes de agrupación.")},
        {"Stage": _l(st, "Create previews", "Crear vistas"),
         "Waiting": queues["preview_waiting"], "Claimed": queues["preview_claimed"],
         "Meaning": _l(st, "Optional safe previews when policy allows.",
                       "Vistas seguras opcionales cuando la política lo permite.")},
    ]
    st.markdown(stage_strip([
        (_l(st, "Fetch", "Recopilar"), f"{queues['url_waiting']} / {queues['url_claimed']}",
         "active" if queues["url_claimed"] else ("warn" if queues["url_waiting"] else "ok")),
        (_l(st, "Verify", "Clasificar"), f"{queues['verify_waiting']} / {queues['verify_claimed']}",
         "active" if queues["verify_claimed"] else ("warn" if queues["verify_waiting"] else "ok")),
        (_l(st, "Cards", "Fichas"), f"{queues['card_waiting']} / {queues['card_claimed']}",
         "active" if queues["card_claimed"] else ("warn" if queues["card_waiting"] else "ok")),
        (_l(st, "Preview", "Vista previa"), f"{queues['preview_waiting']} / {queues['preview_claimed']}",
         "active" if queues["preview_claimed"] else ("warn" if queues["preview_waiting"] else "ok")),
    ]), unsafe_allow_html=True)
    queue_header = st.columns([1.3, .65, .65, 3])
    for column, label in zip(queue_header, (
        _l(st, "Stage", "Etapa"), _l(st, "Waiting", "En espera"),
        _l(st, "Active", "Activas"), _l(st, "What it means", "Qué significa"),
    ), strict=False):
        column.caption(label)
    for item in queue_table:
        queue_row = st.columns([1.3, .65, .65, 3])
        queue_row[0].markdown(f"**{html.escape(str(item['Stage']))}**")
        queue_row[1].write(int(item["Waiting"] or 0))
        queue_row[2].write(int(item["Claimed"] or 0))
        queue_row[3].caption(item["Meaning"])

    st.markdown("### " + _l(st, "Worker instances", "Procesos de trabajo"))
    workers = _control_worker_rows()
    if workers:
        worker_page_size = 12
        worker_page_count = max(1, (len(workers) + worker_page_size - 1) // worker_page_size)
        worker_page = 1
        if worker_page_count > 1:
            worker_page = st.selectbox(
                _l(st, "Worker page", "Página de procesos"), list(range(1, worker_page_count + 1)),
                format_func=lambda value: _l(
                    st, f"Page {value} of {worker_page_count}", f"Página {value} de {worker_page_count}"),
                key="control-worker-page",
            )
        worker_start = (int(worker_page) - 1) * worker_page_size
        visible_workers = workers[worker_start:worker_start + worker_page_size]
        worker_header = st.columns([2, 1, 1, 1.5])
        for column, label in zip(worker_header, (
            _l(st, "Worker", "Proceso"), _l(st, "State", "Estado"),
            _l(st, "Processed", "Procesadas"), _l(st, "Last heartbeat", "Último latido"),
        ), strict=False):
            column.caption(label)
        for item in visible_workers:
            worker_row = st.columns([2, 1, 1, 1.5])
            worker_row[0].markdown(f"**{html.escape(str(item.get('worker_type') or 'worker'))}**  \n"
                                   f"`{html.escape(str(item.get('worker_id') or 'unknown'))}`")
            worker_row[1].write(value_label(item.get("state") or "unknown", language))
            worker_row[2].write(int(item.get("processed_total") or 0))
            worker_row[3].caption(str(item.get("last_heartbeat_at") or "—"))
            if item.get("last_error"):
                st.caption(_l(st, "Last error: ", "Último error: ") +
                           html.escape(str(item.get("last_error"))))
    else:
        st.info(_l(st, "No staged worker heartbeat rows are stored yet.",
                      "Aún no hay actividad almacenada de los procesos por etapas."))
    newest_heartbeat = (
        str(pipeline.get("newest_worker_at"))
        if pipeline.get("newest_worker_at")
        else _l(st, "none recorded", "ninguno registrado")
    )
    st.caption(_l(st, "Legacy pause state: ", "Estado pausa legado: ") +
               (_l(st, "paused", "pausado") if paused else _l(st, "running", "activo")) +
               f" · {_l(st, 'Newest heartbeat', 'Último latido')}: {newest_heartbeat}")

    st.markdown("### " + _l(st, "Failures and repair queue", "Fallos y cola de reparación"))
    fail_cols = st.columns(3)
    fail_cols[0].metric(_l(st, "Verification retries / failures", "Reintentos o fallos de verificación"),
                        sum(int(failures["fetched_pages"].get(key, 0)) for key in ("retry", "failed", "dead_letter")))
    fail_cols[1].metric(_l(st, "Site Card retries / failures", "Reintentos o fallos de fichas"),
                        sum(int(failures["site_card_jobs"].get(key, 0)) for key in ("retry", "failed", "dead_letter")))
    fail_cols[2].metric(_l(st, "Dead URLs", "URLs muertas"), queues["url_dead"])
    if failures["common_error_types"]:
        with st.expander(_l(st, "Most common failure types", "Tipos de fallo más frecuentes")):
            for item in failures["common_error_types"][:12]:
                label = item.get("error_type") or item.get("type") or _l(st, "Unknown", "Desconocido")
                count = item.get("count") or item.get("total") or 0
                st.markdown(f"**{html.escape(str(label))}** · {int(count or 0)}")
    confirm_requeue = st.checkbox(_l(st, "I want to requeue failed verification/Site Card jobs",
                                     "Quiero reencolar los trabajos fallidos de verificación o fichas"),
                                  key="control-confirm-requeue",
                                  disabled=not can_manage_collection)
    repair_cols = st.columns(2)
    if repair_cols[0].button(_l(st, "Requeue verification failures", "Reencolar fallos de verificación"),
                             disabled=not confirm_requeue or not can_manage_collection,
                             width="stretch") and _authorize_action(
                                 st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
        st.json(storage.requeue_failed_verifications(dry_run=False))
        query.clear()
    if repair_cols[1].button(_l(st, "Requeue card failures", "Reencolar fallos de fichas"),
                             disabled=not confirm_requeue or not can_manage_collection,
                             width="stretch") and _authorize_action(
                                 st, dashboard_auth.CAPABILITY_CRAWLER_MANAGE):
        st.json(storage.requeue_failed_card_jobs(dry_run=False))
        query.clear()

    st.markdown("### " + _l(st, "Access, backups and privacy", "Acceso, copias y privacidad"))
    info_cols = st.columns(4)
    info_cols[0].metric(_l(st, "Active sessions", "Sesiones activas"), int(access["active_sessions"]))
    info_cols[1].metric(_l(st, "Unused code", "Código sin usar"), _l(st, "Yes", "Sí") if access["active_code"] else _l(st, "No", "No"))
    info_cols[2].metric(_l(st, "Backups retained", "Copias conservadas"), len(backups))
    info_cols[3].metric(_l(st, "Tor circuit window", "Ventana circuito"),
                        f"{max(1, int(tor_policy['socks_identity_interval_seconds']) // 60)} min")
    code_expiry = (
        str(access.get("active_code_expires_at"))
        if access.get("active_code_expires_at")
        else value_label("none", language)
    )
    st.caption(_l(st, "Active code expires: ", "Código activo expira: ") + code_expiry)
    if backups:
        with st.expander(_l(st, "Recent backups", "Copias recientes")):
            for backup in backups[:7]:
                name = Path(str(backup.get("path") or backup.get("name") or "backup")).name
                created = backup.get("created_at") or backup.get("timestamp") or "—"
                size = backup.get("size_bytes") or backup.get("size")
                size_label = f" · {int(size) / (1024 * 1024):.1f} MB" if isinstance(size, (int, float)) else ""
                st.markdown(f"**{html.escape(name)}**")
                st.caption(f"{created}{size_label}")


def _settings(st) -> None:
    language = current_language(st)
    can_manage_settings = _can(st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE)
    if not can_manage_settings:
        st.info(_l(
            st,
            "Settings are shown read-only for this session.",
            "Los ajustes se muestran en modo de solo lectura para esta sesión.",
        ))
    st.button(_l(st, "Open plain-language FAQ", "Abrir preguntas frecuentes"),
              on_click=_open_workspace_page, args=("FAQ",), key="settings-open-faq")
    if st.session_state.pop("settings_saved_notice", False):
        st.success(_l(st, "Settings saved. The worker will use them before the next queued page.",
                          "Ajustes guardados. El trabajador los usará antes de la siguiente página."))
    _note(st, _l(st,
        "Use simple, bounded controls for crawler privacy and workload. Changes apply before the next queued page and never cancel the page currently being processed.",
        "Usa controles sencillos y limitados para la privacidad y la carga del arachne. Los cambios se aplican antes de la siguiente página y nunca cancelan la página en curso."))

    with st.expander(_l(st, "OPSEC status", "Estado OPSEC"), expanded=False):
        _opsec_status_panel(st, compact=True)

    with st.expander(
        _l(st, "Deep Discovery public checks", "Consultas públicas de Deep Discovery"),
        expanded=False,
    ):
        import deep_discovery_providers

        provider_state = deep_discovery_providers.provider_status()
        provider_enabled = bool(provider_state.get("network_enabled"))
        provider_columns = st.columns(3)
        provider_columns[0].metric(
            _l(st, "Provider mode", "Modo de proveedores"),
            _l(st, "Tor-routed and enabled", "Activo mediante Tor")
            if provider_enabled else _l(st, "Off by default", "Desactivado por defecto"),
        )
        provider_columns[1].metric(
            _l(st, "Eligibility gate", "Umbral de acceso"),
            "90%",
        )
        provider_columns[2].metric(
            _l(st, "Result handling", "Tratamiento del resultado"),
            _l(st, "Review proposal", "Propuesta para revisión"),
        )
        st.caption(_l(
            st,
            "These optional checks use only an exact, structurally bound public PGP fingerprint or domain. "
            "They run through the separate Tor-only allowlist and cannot change a Site Card, category, risk, "
            "Spain Priority, urgency, or crawl policy.",
            "Estas consultas opcionales usan únicamente una huella PGP pública o un dominio exactos y vinculados "
            "estructuralmente. Usan una lista permitida separada y exclusiva de Tor, y no pueden cambiar una ficha, "
            "categoría, riesgo, Prioridad España, urgencia ni política de rastreo.",
        ))

    tor_host = get_str("TOR_SOCKS_HOST", "127.0.0.1") or "127.0.0.1"
    tor_port = get_int("TOR_SOCKS_PORT", 9050)
    control_host = get_str("TOR_CONTROL_HOST", "127.0.0.1") or "127.0.0.1"
    control_port = get_int("TOR_CONTROL_PORT", 9051)

    def port_status(host: str, port: int) -> str:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return _l(st, "Ready", "Disponible")
        except OSError:
            return _l(st, "Not reachable", "No disponible")

    tor_policy = circuit_policy_status()
    identity_minutes_now = max(1, int(tor_policy["socks_identity_interval_seconds"]) // 60)
    renewal_minutes_now = max(1, int(tor_policy["newnym_interval_seconds"]) // 60)
    st.markdown("### " + _l(st, "1 · Tor privacy", "1 · Privacidad de Tor"))
    summary = [
        (_l(st, "Tor connection", "Conexión Tor"), port_status(tor_host, tor_port),
         _l(st, "The local SOCKS connection used for onion requests.", "La conexión SOCKS local usada para peticiones onion.")),
        (_l(st, "Stream isolation", "Aislamiento de flujos"),
         _l(st, "Locked on", "Bloqueado y activo") if tor_policy["socks_isolation"] else _l(st, "Needs server setup", "Necesita configuración"),
         _l(st, "Keeps crawler traffic in a separate Tor circuit group.", "Mantiene el tráfico del arachne en un grupo de circuitos separado.")),
        (_l(st, "Circuit window", "Ventana de circuito"), f"{identity_minutes_now} min",
         _l(st, "The current page finishes before a due rotation is applied.", "La página actual termina antes de aplicar una rotación pendiente.")),
        (_l(st, "Scheduled renewal", "Renovación programada"),
         (_l(st, "On", "Activa") if tor_policy["newnym_enabled"] else _l(st, "Off", "Desactivada")),
         _l(st, "Optional ControlPort-assisted circuit renewal.", "Renovación opcional mediante ControlPort.")),
    ]
    for column, (label, value, explanation) in zip(st.columns(4), summary, strict=False):
        column.metric(label, value, help=explanation)

    with st.expander(_l(st, "What Tor rotation does—and does not do", "Qué hace —y qué no hace— la rotación de Tor")):
        st.markdown(_l(st,
            """- A circuit is the temporary path Tor uses for a connection.
- Arachne changes its isolated circuit group at a moderate interval.
- If the interval expires during a crawl, that crawl finishes first.
- Onion services do not use a normal exit relay.
- Tor may intentionally reuse an entry guard. Forcing guard changes would expose traffic to more relays and can reduce anonymity.
- Rotation reduces linkability; it cannot promise protection from every possible global traffic-correlation observer.""",
            """- Un circuito es la ruta temporal que Tor usa para una conexión.
- Arachne cambia su grupo de circuitos aislado con un intervalo moderado.
- Si el intervalo vence durante un rastreo, ese rastreo termina primero.
- Los servicios onion no utilizan un relé de salida normal.
- Tor puede reutilizar intencionadamente un nodo de entrada. Forzar su cambio expondría el tráfico a más relés y puede reducir el anonimato.
- La rotación reduce la vinculación; no puede garantizar protección frente a cualquier observador global de correlación de tráfico."""))

    interval_options = [10, 15, 30, 60]
    delay_options = [5, 10, 15, 20, 30, 45, 60, 90, 120]
    timeout_options = [15, 30, 45, 60, 90, 120]

    def closest_index(options: list[int], current: int) -> int:
        return min(range(len(options)), key=lambda index: abs(options[index] - current))

    st.markdown("### " + _l(st, "2 · Change crawler settings", "2 · Cambiar ajustes del arachne"))
    with st.form("safe-runtime-settings"):
        privacy_left, privacy_right = st.columns(2)
        with privacy_left:
            identity_minutes = st.selectbox(
                _l(st, "Change circuit group about every", "Cambiar el grupo de circuitos aproximadamente cada"),
                interval_options, index=closest_index(interval_options, identity_minutes_now),
                format_func=lambda value: f"{value} " + _l(st, "minutes", "minutos"),
                help=_l(st, "15 minutes is the balanced choice. Rotation waits for the current page to finish.",
                        "15 minutos es la opción equilibrada. La rotación espera a que termine la página actual."),
            )
            scheduled_renewal = st.toggle(
                _l(st, "Use scheduled Tor circuit renewal", "Usar renovación programada de circuitos Tor"),
                value=bool(tor_policy["newnym_enabled"]),
                help=_l(st, "Requires Tor ControlPort. It does not terminate existing connections.",
                        "Necesita ControlPort de Tor. No termina las conexiones existentes."),
            )
            renewal_minutes = st.selectbox(
                _l(st, "Scheduled renewal interval", "Intervalo de renovación programada"),
                interval_options, index=closest_index(interval_options, renewal_minutes_now),
                format_func=lambda value: f"{value} " + _l(st, "minutes", "minutos"),
                disabled=not scheduled_renewal,
            )
        with privacy_right:
            crawl_delay = st.selectbox(
                _l(st, "Pause between completed pages", "Pausa entre páginas terminadas"), delay_options,
                index=closest_index(delay_options, get_int("ONION_CRAWL_DELAY_SECONDS", 10)),
                format_func=lambda value: f"{value} " + _l(st, "seconds", "segundos"),
                help=_l(st, "A small pause reduces load and creates less bursty traffic.",
                        "Una pequeña pausa reduce la carga y evita tráfico en ráfagas."),
            )
            request_timeout = st.selectbox(
                _l(st, "Give each page up to", "Dar a cada página hasta"), timeout_options,
                index=closest_index(timeout_options, get_int("ONION_REQUEST_TIMEOUT_SECONDS", 30)),
                format_func=lambda value: f"{value} " + _l(st, "seconds", "segundos"),
                help=_l(st, "Slow onion pages may need longer; a timeout moves the URL to safe retry handling.",
                        "Las páginas onion lentas pueden necesitar más tiempo; al vencer pasa a reintento seguro."),
            )
            max_depth = st.selectbox(
                _l(st, "External discovery depth", "Profundidad de descubrimiento externo"), list(range(1, 7)),
                index=max(0, min(5, get_int("ONION_MAX_DEPTH", 3) - 1)),
                help=_l(st, "How many discovered-link generations may be followed away from the starting page.",
                        "Cuántas generaciones de enlaces descubiertos pueden seguirse desde la página inicial."),
            )
            internal_depth = st.selectbox(
                _l(st, "Pages within the same onion site", "Páginas dentro del mismo sitio onion"), list(range(2, 13)),
                index=max(0, min(10, get_int("ONION_INTERNAL_MAX_DEPTH", 8) - 2)),
                help=_l(st, "Allows directories, forum sections and threads on the chosen onion site to be explored.",
                        "Permite explorar directorios, secciones y temas dentro del sitio onion elegido."),
            )

        available, preview_status = screenshot_support_status()
        screenshots_enabled = False
        screenshot_limit = get_int("SCREENSHOT_MAX_PER_RUN", 5)
        screenshot_timeout = get_int("SCREENSHOT_TIMEOUT_SECONDS", 20)
        st.info(_l(st,
            "Visual screenshots/previews are disabled for the production profile. Source/body archiving also stays disabled; the system keeps safe metadata, classification signals and reviewer notes instead.",
            "Las capturas/vistas visuales están desactivadas para el perfil de producción. El archivado de código fuente/cuerpo también queda desactivado; el sistema conserva metadatos seguros, evidencia de clasificación y notas."))
        st.caption(_l(st, f"Preview status: {preview_status}", f"Estado de vistas previas: {preview_status}"))

        submitted = st.form_submit_button(
            _l(st, "Save settings", "Guardar ajustes"),
            width="stretch",
            disabled=not can_manage_settings,
        )

    if submitted and _authorize_action(st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE):
        try:
            save_runtime_settings({
                "TOR_SOCKS_IDENTITY_INTERVAL_SECONDS": int(identity_minutes) * 60,
                "TOR_NEWNYM_ENABLED": bool(scheduled_renewal),
                "TOR_NEWNYM_INTERVAL_SECONDS": int(renewal_minutes) * 60,
                "TOR_NEWNYM_EVERY_REQUESTS": 0,
                "TOR_NEWNYM_MIN_INTERVAL_SECONDS": min(int(renewal_minutes) * 60, 600),
                "ONION_CRAWL_DELAY_SECONDS": int(crawl_delay),
                "ONION_REQUEST_TIMEOUT_SECONDS": int(request_timeout),
                "ONION_MAX_DEPTH": int(max_depth),
                "ONION_INTERNAL_MAX_DEPTH": max(int(max_depth), int(internal_depth)),
                "ENABLE_PAGE_SCREENSHOTS": bool(screenshots_enabled),
                "SCREENSHOT_MAX_PER_RUN": int(screenshot_limit),
                "SCREENSHOT_TIMEOUT_SECONDS": int(screenshot_timeout),
            })
            st.session_state["settings_saved_notice"] = True
            st.rerun()
        except (OSError, ValueError) as exc:
            st.error(_l(st, "Settings could not be saved: ", "No se pudieron guardar los ajustes: ") + redact_for_log(exc))

    st.caption(_l(st, "Saved dashboard overrides contain no tokens, passwords, onion URLs or crawl results.",
                      "Los ajustes guardados no contienen tokens, contraseñas, URLs onion ni resultados del rastreo."))
    source = runtime_setting_source("TOR_SOCKS_IDENTITY_INTERVAL_SECONDS")
    source_label = {
        "runtime_settings.json": _l(st, "dashboard runtime setting", "ajuste del panel"),
        "environment": _l(st, "process environment", "entorno del proceso"),
        ".env": _l(st, "server .env", ".env del servidor"),
        "config.json": "config.json",
        "default": _l(st, "built-in default", "valor predeterminado"),
    }.get(source, source)
    st.caption(_l(st, "Current circuit interval source: ", "Origen del intervalo actual: ") + source_label)
    preview_source = runtime_setting_source("ENABLE_PAGE_SCREENSHOTS")
    if get_bool("ENABLE_PAGE_SCREENSHOTS", False):
        st.success(_l(st, f"Front-page previews are ON. Effective source: {preview_source}.",
                          f"Las vistas previas están ACTIVAS. Origen efectivo: {preview_source}."))
    else:
        st.warning(_l(st,
            f"Front-page previews are currently OFF on this server. Effective source: {preview_source}. This is the recommended production setting.",
            f"Las vistas previas están DESACTIVADAS en este servidor. Origen efectivo: {preview_source}. Este es el ajuste recomendado para producción."))

    st.markdown("### " + _l(st, "3 · Notifications", "3 · Notificaciones"))
    preferences = storage.notification_preferences()
    with st.form("notification-preferences"):
        immediate_spain = st.toggle(
            _l(st, "Immediate Spain Priority alerts", "Alertas inmediatas de Prioridad España"),
            value=bool(preferences.get("immediate_spain_alerts", 1)),
            help=_l(st, "Spain remains the red review-now alert. Opening its Site Card acknowledges it.",
                    "España mantiene la alerta roja de revisión inmediata. Abrir su ficha la reconoce."))
        digest_telegram = st.toggle(
            _l(st, "Send the completed daily digest to Telegram", "Enviar el resumen diario completado a Telegram"),
            value=bool(preferences.get("daily_digest_telegram", 0)),
            help=_l(st, "Lower-priority activity stays in the daily summary instead of producing immediate noise.",
                    "La actividad de menor prioridad permanece en el resumen diario sin crear ruido inmediato."))
        if st.form_submit_button(
            _l(st, "Save notification choices", "Guardar notificaciones"),
            width="stretch",
            disabled=not can_manage_settings,
        ) and _authorize_action(st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE):
            storage.set_notification_preferences(immediate_spain=immediate_spain,
                                                 daily_digest_telegram=digest_telegram)
            st.success(_l(st, "Notification choices saved.", "Notificaciones guardadas."))
    st.caption(_l(st, "Immediate: Spain Priority. Daily digest: crawler work, discoveries, changes, errors and ordinary categories.",
                      "Inmediato: Prioridad España. Resumen diario: trabajo del arachne, descubrimientos, cambios, errores y categorías normales."))

    st.markdown("### " + _l(st, "4 · Rolling backups", "4 · Copias de seguridad rotativas"))
    st.caption(_l(st, "One integrity-checked backup per Madrid day is retained for seven days. Reports are included; regenerable screenshots are excluded.",
                      "Se conserva una copia verificada por día de Madrid durante siete días. Incluye informes y excluye capturas regenerables."))
    backup_left, backup_right = st.columns(2)
    if backup_left.button(_l(st, "Create today's backup now", "Crear la copia de hoy ahora"),
                          key="settings-create-backup", width="stretch",
                          disabled=not can_manage_settings) and _authorize_action(
                              st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE):
        try:
            result = backup_service.create_daily_backup(keep_days=7, force=True)
            st.success(_l(st, "Backup created and verified: ", "Copia creada y verificada: ") + Path(result["path"]).name)
        except (OSError, ValueError, sqlite3.DatabaseError) as exc:
            st.error(_l(st, "Backup failed safely: ", "La copia falló de forma segura: ") + type(exc).__name__)
    backups = backup_service.list_backups()
    backup_right.metric(_l(st, "Daily backups retained", "Copias diarias conservadas"), len(backups))
    if backups:
        st.dataframe(backups, width="stretch", hide_index=True)
        with st.expander(_l(st, "Prepare a restore", "Preparar una restauración")):
            selected_backup = st.selectbox(_l(st, "Verified backup", "Copia verificada"),
                                           [item["name"] for item in backups])
            confirm_restore = st.toggle(_l(st, "I understand this prepares a server restore",
                                                 "Entiendo que esto prepara una restauración del servidor"),
                                        value=False, key="confirm-restore-stage",
                                        disabled=not can_manage_settings)
            if st.button(_l(st, "Prepare verified restore", "Preparar restauración verificada"),
                         disabled=not confirm_restore or not can_manage_settings,
                         key="prepare-restore", width="stretch") and _authorize_action(
                             st, dashboard_auth.CAPABILITY_SETTINGS_MANAGE):
                try:
                    restored = backup_service.prepare_restore(selected_backup)
                    st.success(_l(st, "Restore staged safely. Stop the services before replacing the live database: ",
                                      "Restauración preparada. Detén los servicios antes de reemplazar la base activa: ") +
                               restored["staging_dir"])
                except (OSError, ValueError, sqlite3.DatabaseError) as exc:
                    st.error(_l(st, "Restore validation failed: ", "Falló la validación: ") + type(exc).__name__)

    with st.expander(_l(st, "Effective settings and where they come from", "Ajustes efectivos y su origen")):
        setting_keys = [
            "ENABLE_PAGE_SCREENSHOTS", "SCREENSHOT_MAX_PER_RUN", "SCREENSHOT_TIMEOUT_SECONDS",
            "ONION_MAX_DEPTH", "ONION_INTERNAL_MAX_DEPTH", "ONION_CRAWL_DELAY_SECONDS",
            "ONION_REQUEST_TIMEOUT_SECONDS", "TOR_NEWNYM_ENABLED",
            "TOR_SOCKS_IDENTITY_INTERVAL_SECONDS",
        ]
        st.dataframe([{
            _l(st, "Setting", "Ajuste"): key,
            _l(st, "Effective value", "Valor efectivo"): effective_config_value(key),
            _l(st, "Source", "Origen"): runtime_setting_source(key),
            _l(st, "Editable here", "Editable aquí"): "Yes" if key in {
                "ENABLE_PAGE_SCREENSHOTS", "SCREENSHOT_MAX_PER_RUN", "SCREENSHOT_TIMEOUT_SECONDS",
                "ONION_MAX_DEPTH", "ONION_INTERNAL_MAX_DEPTH", "ONION_CRAWL_DELAY_SECONDS",
                "ONION_REQUEST_TIMEOUT_SECONDS", "TOR_NEWNYM_ENABLED",
                "TOR_SOCKS_IDENTITY_INTERVAL_SECONDS",
            } else "No",
        } for key in setting_keys], width="stretch", hide_index=True)

    st.markdown("### " + _l(st, "5 · One-time server check", "5 · Comprobación única del servidor"))
    control_ready = port_status(control_host, control_port)
    check_left, check_right = st.columns(2)
    check_left.metric(_l(st, "Tor SOCKS port", "Puerto SOCKS de Tor"), f"{tor_host}:{tor_port} · {port_status(tor_host, tor_port)}")
    check_right.metric(_l(st, "Tor ControlPort", "ControlPort de Tor"), f"{control_host}:{control_port} · {control_ready}")
    st.info(_l(st,
        "The dashboard can save intervals, but only the server can enable Tor's isolation and ControlPort. This is a one-time setup.",
        "El panel puede guardar intervalos, pero solo el servidor puede activar el aislamiento y ControlPort de Tor. Se configura una sola vez."))
    st.code("SocksPort 9050 IsolateSOCKSAuth\nControlPort 9051\nCookieAuthentication 1", language=None)
    st.code(
        "systemctl restart tor\n"
        "systemctl restart arachne-fetch-worker arachne-verify-worker arachne-card-worker",
        language="bash",
    )
    if scheduled_renewal and _l(st, "Not reachable", "No disponible") == control_ready:
        st.warning(_l(st, "Scheduled renewal is selected but ControlPort is not reachable yet. Normal isolated crawling continues.",
                          "La renovación está seleccionada, pero ControlPort aún no está disponible. El rastreo aislado normal continúa."))

    st.markdown("### " + _l(st, "6 · Safety rules that settings cannot weaken", "6 · Reglas de seguridad que los ajustes no pueden debilitar"))
    st.markdown(_l(st, """<div class="safe-note"><b>Always enforced</b><br>
    ✓ Crawler page fetching remains onion-only; optional exact public identity checks use a separate Tor-only allowlist<br>✓ Adult and severe-abuse content remains filtered<br>
    ✓ No login, CAPTCHA handling, form submission or purchasing<br>✓ No archive, executable, video or document downloads<br>
    ✓ Restricted pages never receive screenshots, snippets or outbound expansion</div>""",
    """<div class="safe-note"><b>Siempre activo</b><br>
    ✓ El arachne solo obtiene páginas onion; las consultas públicas exactas opcionales usan una lista separada exclusiva de Tor<br>✓ El contenido adulto y de abuso grave permanece filtrado<br>
    ✓ Sin inicios de sesión, CAPTCHA, formularios ni compras<br>✓ Sin descargas de archivos, ejecutables, vídeos o documentos<br>
    ✓ Las páginas restringidas nunca generan capturas, fragmentos ni expansión de enlaces</div>"""), unsafe_allow_html=True)
    if not available:
        preview_status_es = {
            "Disabled by configuration": "Desactivadas en los ajustes",
            "Disabled by dashboard runtime setting": "Desactivadas en el panel",
            "Disabled by server .env": "Desactivadas en el .env del servidor",
            "Disabled by process environment": "Desactivadas en el entorno del proceso",
            "Disabled by config.json": "Desactivadas en config.json",
            "Disabled by default": "Desactivadas de forma predeterminada",
            "Playwright is not installed; previews remain safely disabled":
                "Playwright no está instalado; las vistas previas permanecen desactivadas de forma segura",
        }.get(preview_status, preview_status)
        st.caption(_l(st, f"Preview status: {preview_status}", f"Estado de vistas previas: {preview_status_es}"))


def main() -> None:
    import pandas as pd
    import streamlit as st

    render_started = time.perf_counter()
    metrics = QueryMetrics()
    storage.ensure_db_initialized()
    st.session_state["_perf_cards_fetched"] = 0
    st.session_state["_perf_detail_cards"] = 0
    st.session_state["_perf_render_mode"] = "n/a"
    try:
        st.set_page_config(page_title="Arachne Console", page_icon="A", layout="wide",
                           initial_sidebar_state="expanded")
    except Exception:
        # dashboard.py sets page config before the access gate. Keep this as a
        # harmless fallback when this
        # workspace module is rendered directly in tests/tools.
        pass
    theme = _resolve_ui_theme(st)
    st.markdown(DASHBOARD_CSS, unsafe_allow_html=True)
    if theme == "light":
        st.markdown(ARACHNE_LIGHT_CSS, unsafe_allow_html=True)
    st.markdown(
        f'<span class="rt-theme-marker" data-theme="{theme}" aria-hidden="true"></span>',
        unsafe_allow_html=True,
    )

    @st.cache_data(ttl=15,show_spinner=False)
    def _cached_query(sql: str, params=(), db_signature: str = ""):
        return metrics.run(_rows,sql,params)

    def query(sql: str, params=()):
        # Including the database path prevents stale result cards when tests,
        # deployments, or maintenance tools switch to another database file.
        return _cached_query(sql, params, str(storage.DB_PATH))

    query.clear = _cached_query.clear

    language = current_language(st)
    logo_uri = _arachne_logo_data_uri()
    logo_html = (f'<img src="{logo_uri}" alt="Arachne logo" />' if logo_uri else "A")
    st.sidebar.markdown(
        f'<div class="rt-brand"><div class="rt-brand-badge">{logo_html}</div><div>'
        f'<div class="rt-brand-mark">Arachne</div>'
        f'<div class="rt-brand-copy">{html.escape(tr("brand_subtitle", language))}</div></div></div>',
        unsafe_allow_html=True,
    )
    try:
        deep_links = {"spain": "Spain Priority", "activity": "Daily Activity",
                      "investigations": "Watchlist", "quality": "Quality Center"}
        deep_page = deep_links.get(str(st.query_params.get("view") or "").casefold())
        if deep_page and not st.session_state.get("_deep_link_applied"):
            _sync_workspace_navigation(st, deep_page, language)
            st.session_state["_deep_link_applied"] = True
        query_nav = str(st.query_params.get("nav") or "").strip().casefold()
        query_page = str(st.query_params.get("page") or "").strip()
        selected_query_page = SLUG_TO_PAGE.get(query_nav) or (query_page if query_page in SIMPLE_PAGES else "")
        if selected_query_page:
            previous_page = st.session_state.get("nav_page")
            query_page = _sync_workspace_navigation(st, selected_query_page, language)
            if previous_page in SIMPLE_PAGES and previous_page != query_page:
                st.session_state.pop("directory_selected_card", None)
                st.session_state.pop("directory_selected_review_only", None)
                st.session_state.pop("directory_dialog_edit", None)
                st.session_state.pop("directory_origin_page", None)
    except (AttributeError, TypeError):
        pass
    if st.session_state.get("nav_page") not in SIMPLE_PAGES:
        _sync_workspace_navigation(st, "Home", language)
    elif st.session_state.get("_compat_page") not in SIMPLE_PAGES:
        _sync_workspace_navigation(st, st.session_state["nav_page"], language)
    area_labels = {"Home":"menu_home", "Crawl":"menu_crawl", "Intelligence":"menu_intelligence",
                   "Spain":"menu_spain", "Reports":"menu_reports", "Settings":"menu_settings"}
    area_icons = {"Home":"⌂", "Crawl":"◎", "Intelligence":"◇", "Spain":"🇪🇸", "Reports":"▤",
                  "Settings":"⚙"}
    def _compat_changed():
        selected = st.session_state.get("_compat_page", "Home")
        _open_workspace_page(selected)

    # Global presentation controls stay near the brand. On shorter screens the
    # route list scrolls, so placing them last made both controls look missing.
    st.sidebar.markdown(f'<div class="rt-nav-label">{html.escape(_l(st, "Preferences", "Preferencias"))}</div>', unsafe_allow_html=True)
    st.sidebar.toggle(
        tr("language", language), value=bool(st.session_state.get("ui_spanish")), key="ui_spanish",
        help=("Changes menus, filters, cards, statuses and explanations across the whole workspace."
              if language == "en" else
              "Cambia menús, filtros, fichas, estados y explicaciones en todo el espacio de trabajo."),
    )
    language = current_language(st)
    st.sidebar.toggle(
        _l(st, "Dark mode", "Modo oscuro"), key="ui_dark_mode",
        on_change=_persist_ui_theme, args=(st,),
        help=_l(st, "Switch between the light workspace and the dark workspace. Your choice is saved.",
                "Cambia entre el espacio claro y el espacio oscuro. Tu elección queda guardada."),
    )

    language = current_language(st)
    spain_count=_spain_unreviewed_count()
    _render_visual_sidebar_nav(st, st.session_state["nav_page"], language, spain_count)

    # Kept for automated/deep-link compatibility; hidden visually by the theme.
    st.sidebar.radio("Compatibility page router", SIMPLE_PAGES, key="_compat_page",
                     on_change=_compat_changed, label_visibility="collapsed")
    # These radios are hidden compatibility controls used by old deep links and
    # automated checks.  They update navigation only from their on-change
    # callbacks; their stale return values must never override a URL route.
    current_area = PAGE_TO_AREA[st.session_state["nav_page"]]
    display_to_area = {f"{area_icons[value]}  {tr(area_labels[value], language)}": value for value in NAV_AREAS}
    area_options = list(display_to_area)
    area_state_key = f"_nav_area_display_{language}"
    if area_state_key not in st.session_state:
        st.session_state[area_state_key] = area_options[list(NAV_AREAS).index(current_area)]

    def _area_changed():
        selected_area = display_to_area.get(st.session_state.get(area_state_key), "Home")
        _open_workspace_page(NAV_AREAS[selected_area][0])

    st.sidebar.radio(
        "Main workspace", area_options, key=area_state_key,
        label_visibility="collapsed", on_change=_area_changed)
    area = current_area
    if len(NAV_AREAS[area]) > 1:
        current_page = st.session_state["nav_page"] if st.session_state["nav_page"] in NAV_AREAS[area] else NAV_AREAS[area][0]
        display_to_page = {tr(PAGE_COPY_KEYS[value], language): value for value in NAV_AREAS[area]}
        subpage_state_key = f"_nav_subpage_display_{language}_{area}"
        if subpage_state_key not in st.session_state:
            st.session_state[subpage_state_key] = tr(PAGE_COPY_KEYS[current_page], language)

        def _subpage_changed():
            selected_page = display_to_page.get(st.session_state.get(subpage_state_key), current_page)
            _open_workspace_page(selected_page)

        st.sidebar.radio(
            "Workspace section", list(display_to_page), key=subpage_state_key,
            label_visibility="collapsed", on_change=_subpage_changed)
    page = st.session_state["nav_page"]
    if page == "Site Cards":
        with st.sidebar.expander(tr("view_options", language)):
            st.checkbox(tr("compact_cards", language), value=True, key="compact_site_cards")
            st.checkbox(tr("show_low_info", language), value=False, key="show_low_info_cards")
            st.checkbox(tr("show_monitor", language), value=True, key="show_monitor_only_cards")
    pipeline = _pipeline_status()
    sidebar_workers = (pipeline["fetch_workers"] + pipeline["verify_workers"]
                       + pipeline["card_workers"] + pipeline["preview_workers"])
    sidebar_waiting = pipeline["frontier_pending"] + pipeline["fetched_pending"] + pipeline["card_pending"]
    sidebar_state = _l(st, "Healthy", "Correcto") if sidebar_workers else _l(st, "Attention", "Atención")
    st.sidebar.markdown(
        f'<div class="rt-sidebar-note"><strong>{html.escape(sidebar_state)}</strong><br>'
        f'{sidebar_workers} {html.escape(_l(st, "workers online", "procesos activos"))} · '
        f'{sidebar_waiting} {html.escape(_l(st, "core pipeline jobs waiting", "tareas principales en espera"))}<br>'
        f'{int(pipeline.get("processed_today") or 0)} {html.escape(_l(st, "processed today", "procesadas hoy"))}</div>',
        unsafe_allow_html=True,
    )
    worker_online = (pipeline["fetch_workers"] + pipeline["verify_workers"]
                     + pipeline["card_workers"]) > 0
    queued = int(_scalar("SELECT COUNT(*) FROM onion_urls WHERE active=1 AND status IN ('new','queued','retry')"))
    page_label = tr(PAGE_COPY_KEYS[page], language)
    st.markdown(
        f'<div class="rt-hero"><div class="rt-hero-copy">'
        f'<div class="rt-hero-title">{html.escape(page_label)}</div>'
        f'<div class="rt-hero-subtitle">{html.escape(_page_subtitle(st, page))}</div>'
        f'</div>'
        f'<div class="rt-status-rail">'
        f'<span class="rt-status-chip {"rt-chip-ok" if worker_online else "rt-chip-crit"}"><i></i>'
        f'{html.escape(tr("status_worker", language))} {html.escape(tr("status_online" if worker_online else "status_offline", language))}</span>'
        f'<span class="rt-status-chip rt-chip-info"><i></i>{html.escape(tr("status_queue", language))} {queued}</span>'
        f'<span class="rt-status-chip rt-chip-spain"><i></i>{html.escape(tr("status_spain", language))} {spain_count}</span>'
        f'</div></div>', unsafe_allow_html=True)
    updated=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
    st.markdown(f'<div class="rt-context-line">{html.escape(tr("environment", language))}: '
                f'<b>{html.escape(_environment_label())}</b> · {html.escape(tr("updated", language))}: {updated} · '
                f'{html.escape(tr("current_view", language))}: {html.escape(page_label)}</div>',unsafe_allow_html=True)
    principal = _dashboard_principal(st)
    if principal.get("role") == dashboard_auth.ROLE_DEMO_READONLY:
        st.info(_l(
            st,
            "Read-only session · You can inspect records and safe reports; edits, queue changes, and settings are disabled.",
            "Sesión de solo lectura · Puedes consultar registros e informes; las ediciones, colas y ajustes están desactivados.",
        ))
    if page == "Home":
        _global_spain_banner(st, query)

    if st.session_state.get("directory_selected_card"):
        # Complex records use the full content width.  The selected-card state
        # remains the same one used by every list, Spain result, and review row.
        site_directory.render_selected_page(st, query)
    else:
        render_page(page, {
            "Home": lambda: home.render(st, query),
            "Add Onion": lambda: add_onion.render(st, query),
            "Crawl Queue": lambda: crawl_queue.render(st, query, pd),
            "Site Cards": lambda: site_cards.render(st, query),
            "Entity Intelligence": lambda: entity_intelligence.render(st, query),
            "Connections": lambda: connections.render(st, query),
            "Timeline": lambda: timeline.render(st, query),
            "Actors": lambda: actors.render(st, query),
            "Identity Signals": lambda: identity_signals.render(st, query),
            "Review Findings": lambda: review.render(st, query),
            "Quality Center": lambda: quality_center.render(st, query),
            "Watchlist": lambda: investigations.render(st, query),
            "Daily Activity": lambda: activity.render(st, query),
            "Reports": lambda: reports.render(st, query),
            "Spain Priority": lambda: spain_priority.render(st, query),
            "Advanced": lambda: advanced.render(st, query, pd),
            "Control Center": lambda: control_center.render(st, query, pd),
            "Settings": lambda: settings_page.render(st),
            "FAQ": lambda: faq.render(st),
        })
    if get_bool("DASHBOARD_PERF_LOG", False):
        LOGGER.info("page=%s queries=%d db_ms=%.1f cards=%d details=%d mode=%s render_ms=%.1f",
                    page, metrics.count, metrics.seconds * 1000,
                    int(st.session_state.get("_perf_cards_fetched", 0)),
                    int(st.session_state.get("_perf_detail_cards", 0)),
                    st.session_state.get("_perf_render_mode", "n/a"),
                    (time.perf_counter() - render_started) * 1000)


if __name__=="__main__":
    # The deployable entry point owns authentication. Running this module
    # directly must not create an alternate route around the access gate.
    from dashboard import main as dashboard_main

    dashboard_main()
