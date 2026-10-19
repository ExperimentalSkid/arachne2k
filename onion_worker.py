"""Separate passive Tor/onion worker with universal early safety policy.

GET-only. No JavaScript, forms, authentication, interaction, probing, media, or file downloads.
"""
from __future__ import annotations

import argparse
import codecs
import hashlib
import json
import logging
import os
import re
import signal
import threading
import time
from contextlib import contextmanager
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

import storage
import site_dedupe
from actor_intelligence import process_page_actor_intelligence
from crawler_decide_rules import assess_content_liveness, decide_url, url_shape
from config_loader import get_bool, get_int, get_str
from entity_extractor import extract_actor_evidence, extract_indicators
from forum_url_identity import classify_forum_url
from classification_schema import (DESTINATION_HTML_EVIDENCE_VERSION,
                                   apply_classification_contract,
                                   destination_html_evidence_version,
                                   has_current_destination_html_evidence,
                                   normalize_page_type)
from mirror_logger import update_mirror_clusters
from passive_attribution import build_attribution_profile
from passive_exposure_extractor import extract_passive_exposures
from page_intelligence import (classify_link_context, compute_card_readiness,
                               extract_page_identity, fingerprint_page_type)
from safety_policy import (classify_risk_flags, is_content_type_allowed, is_fetch_allowed,
                           is_onion_url, is_severe_blackhole_policy,
                           make_safe_snippet, normalize_url)
from screenshot_service import capture_page_screenshot
from safe_transport import create_onion_session, fetch_onion
from tor_circuits import prepare_fetch_circuit, requests_proxy_url
from topic_classifier import extract_page_topics
from universal_classifier import (calibrate_classification, classify, classify_url_prefetch,
                                  classify_preview_ocr_text, safe_category_label)
from url_policy import derive_safe_display_name, normalize_policy_state

LOGGER = logging.getLogger("onion_worker")
REMOVED_TAGS = (
    "script", "style", "noscript", "svg", "canvas", "iframe", "object", "embed",
    "img", "picture", "video", "audio", "source", "track",
)
LIMITED_INDICATOR_TYPES = {"onion_url", "onion_domain", "clearnet_url", "victim_or_org_name", "pgp_key_block"}
STOP_REQUESTED = False
ENRICHMENT_PUBLIC_PATHS = ("/", "/about", "/contact", "/pgp", "/mirrors", "/mirror",
                           "/faq", "/rules", "/terms", "/index")
ENRICHMENT_ANCHOR_TERMS = ("about", "contact", "pgp", "mirror", "mirrors", "faq", "rules", "terms", "index")
ENRICHMENT_BLOCKED_MARKERS = (
    "/login", "/log-in", "/signin", "/sign-in", "/register", "/signup", "/sign-up",
    "/account", "/profile", "/cart", "/basket", "/checkout", "/order", "/orders",
    "/payment", "/pay", "/message", "/messages", "/inbox", "/upload", "/admin",
    "/logout", "/auth", "/captcha", "/submit", "/form",
)
ENRICHMENT_RESTRICTED_CATEGORIES = {"adult_filtered", "adult_restricted", "severe_abuse_risk"}
DECODING_META_SCAN_BYTES = 16_384
LINK_CONTEXT_VARIANT_LIMIT = 8
LINK_OCCURRENCE_COUNT_LIMIT = 65_535
_PASSIVE_HEADER_NAMES = {"server": "Server", "x-powered-by": "X-Powered-By"}
_PASSIVE_HEADER_VALUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()/+-]{0,159}\Z")
_PRIVATE_HEADER_MARKER_RE = re.compile(
    r"(?i)\b(?:auth|bearer|cookie|password|secret|session|token|api[-_]?key)\b|\.onion\b"
)

_HTTP_CHARSET_RE = re.compile(
    r"(?:^|;)\s*charset\s*=\s*(?:\"([^\"]{1,80})\"|'([^']{1,80})'|([^;\s]{1,80}))",
    re.IGNORECASE,
)
_META_TAG_RE = re.compile(r"<meta\b[^>]{0,1024}>", re.IGNORECASE)
_META_CHARSET_RE = re.compile(
    r"\bcharset\s*=\s*(?:\"([^\"]{1,80})\"|'([^']{1,80})'|([^\s\"'/>;]{1,80}))",
    re.IGNORECASE,
)

FORUM_TRIGGER_CATEGORIES = {
    "weapons_arms", "marketplace_weapons", "fraud_financial", "marketplace_fraud",
    "drugs", "marketplace_drugs", "leaks_data", "marketplace_leaks",
    "credentials", "marketplace_credentials", "malware_hacking",
}
FORUM_TRIGGER_TERMS = (
    "spain", "españa", "espana", "madrid", "barcelona", "sevilla", "valencia",
    "weapon", "weapons", "firearm", "pistol", "rifle", "ammunition", "arms",
    "carding", "fullz", "cvv", "fraud", "bank", "drug", "cocaine", "heroin",
    "leak", "database", "credential", "password", "malware", "ransomware",
)


def _adult_filtered(policy: dict) -> bool:
    return (policy.get("primary_category") in {"adult_filtered", "adult_restricted"}
            or policy.get("storage_policy") == "discard")


def _independent_prefetch_content_decision(policy: dict) -> bool:
    """Return true only for an exact prior destination/analyst decision."""
    return bool(policy.get("independent_destination_decision"))


def _is_forum_thread_url(url: str) -> bool:
    identity = classify_forum_url(url)
    return identity.role in {"thread", "pagination", "post_permalink"}


def _forum_anchor_trigger(record: dict) -> bool:
    for observation in _record_context_observations(record):
        context = " ".join((observation["anchor_text"], observation["section_context"])).casefold()
        if any(term in context for term in FORUM_TRIGGER_TERMS):
            return True
    return False


def _forum_route_hint(url: str) -> dict:
    """Return bounded, explicitly unverified routing metadata for a forum-like URL."""
    identity = classify_forum_url(url)
    recognized = identity.role != "unknown"
    canonical_hash = (hashlib.sha256(identity.canonical_url.encode("utf-8", "ignore")).hexdigest()
                      if recognized and identity.canonical_url else None)
    return {
        "role": identity.role,
        "engine": identity.engine,
        "confidence": identity.confidence,
        "stable_key": identity.case_identity or identity.thread_identity or identity.post_identity,
        "canonical_identity_hash": canonical_hash,
        "reason": identity.reason,
        "hint_verified": False,
        "evidence_source": "url_route",
    }


def _forum_relevance_trigger(url: str, policy: dict) -> tuple[bool, str]:
    _ = url
    if (normalize_page_type(policy.get("page_type")) != "forum_thread"
            or policy.get("classification_evidence_source") != "destination_html"
            or int(policy.get("destination_html_evidence_version") or 0)
                < DESTINATION_HTML_EVIDENCE_VERSION):
        return False, "not_forum_thread"
    if policy.get("spain_priority"):
        return True, str(policy.get("spain_priority_reason") or "spain_priority_thread")
    category = str(policy.get("primary_category") or "unknown")
    confidence = str(policy.get("category_confidence") or policy.get("confidence") or "low").casefold()
    if category in FORUM_TRIGGER_CATEGORIES and confidence in {"medium", "high", "critical"}:
        return True, f"relevant_thread_category:{category}"
    return False, "no_strong_relevance_trigger"


def _expand_relevant_forum_thread(url: str, policy: dict) -> dict:
    """Apply the bounded forum expansion side effect from every crawl path."""
    triggered, reason = _forum_relevance_trigger(url, policy)
    if not triggered:
        return {
            "triggered": False,
            "reason": reason,
            "expanded": 0,
            "duplicate_trigger": 0,
        }
    expansion = storage.expand_deferred_forum_threads(
        urlsplit(url).hostname or "", url, reason,
        batch_size=get_int("ONION_FORUM_TRIGGER_EXPANSION_BATCH", 25),
        max_limit=get_int("ONION_FORUM_MAX_THREAD_BUDGET", 100),
    )
    storage.insert_crawl_audit(
        url, "forum_budget", "expanded" if expansion["expanded"] else "budget_raised",
        f"{reason};permitted={expansion['permitted']};queued={expansion['expanded']}")
    return {"triggered": True, "reason": reason, **expansion}


def _adult_memory_policy() -> dict:
    return {
        "primary_category": "adult_filtered", "category": "adult_filtered",
        "content_category": "adult_filtered", "tags": ["adult_filtered"],
        "risk_level": "filtered", "confidence": "high", "risk_flags": ["adult_filtered"],
        "storage_policy": "discard", "review_status": "filtered",
        "safety_reason": "adult_content_filtered", "screenshot_policy": "blocked",
        "screenshot_blocked_reason": "adult_content_filtered", "queue_policy": "blocked",
        "active": 0, "priority_score": 0, "spain_priority": False,
        "classification_decision": "independently_verified_memory",
        "classification_evidence_source": "adult_filter_memory",
        "independent_destination_decision": True, "hint_verified": True,
    }


def _prefilter_url(url: str, source_url: str | None = None,
                   anchor_text: str | None = None, source_context: str | None = None) -> dict:
    decision = storage.get_adult_memory_decision(url)
    if decision == "blocked":
        # Only an exact, page-verified or analyst-confirmed memory decision is
        # terminal. URL wording itself never creates this state.
        return _adult_memory_policy()
    policy = _provisional_safe_child_policy(
        classify_url_prefetch(url, source_url, anchor_text, source_context))
    if decision == "false_positive":
        policy = dict(policy, tags=["analyst_false_positive"],
                      safety_reason="awaiting_page_classification",
                      classification_decision="analyst_url_filter_false_positive")
    return policy


def _classify_fetched_page(url: str, *, title: str | None, meta: str,
                           visible_text: str, source_url: str | None,
                           source_context: str | None, page_structure: dict | None = None) -> dict:
    policy = classify(url=url, title=title, meta=meta, visible_text=visible_text,
                      source_url=None, source_context=None, classification_scope="page",
                      page_structure=page_structure)
    if storage.get_adult_memory_decision(url) == "false_positive" and _adult_filtered(policy):
        policy = dict(policy, primary_category="unknown", category="unknown",
                      content_category="unknown", tags=["analyst_false_positive"],
                      risk_level="low", risk_flags=[], storage_policy="safe_summary",
                      review_status="monitor", safety_reason="analyst_false_positive",
                      queue_policy="normal", active=1, spain_priority=False,
                      classification_decision="analyst_confirmed")
    return policy


def _classification_decision_metadata(policy: dict,
                                      content_quality: str | None = None) -> dict:
    """Build a code/count-only snapshot for later quality review.

    Titles, URLs, snippets, matched terms, and raw evidence are intentionally
    excluded. Quality analysis only needs to know which evidence buckets were
    present when the decision was made.
    """
    evidence = policy.get("category_evidence")
    if not isinstance(evidence, dict):
        evidence = {}

    def _score(value: object) -> int:
        try:
            return max(0, min(100, int(float(value or 0))))
        except (TypeError, ValueError, OverflowError):
            return 0

    bucket_counts = {}
    for bucket in (
        "title", "heading", "url", "body_safe_snippet", "link_pattern",
        "form_checkout_login", "negative_contradicting",
    ):
        value = evidence.get(bucket)
        if isinstance(value, (list, tuple, set)):
            bucket_counts[bucket] = min(100, len(value))
        elif isinstance(value, (int, float)):
            bucket_counts[bucket] = _score(value)
    return {
        "page_type": policy.get("page_type"),
        "page_type_confidence": policy.get("page_type_confidence"),
        "content_category": policy.get("content_category"),
        "site_type": policy.get("site_type"),
        "risk_category": policy.get("risk_category"),
        "safety_state": policy.get("safety_state"),
        "content_quality": content_quality or policy.get("content_quality"),
        "classification_evidence_source": "destination_html",
        "destination_evidence_trusted": True,
        "evidence_bucket_counts": bucket_counts,
        "category_update_allowed": policy.get("category_update_allowed"),
        "category_update_reason": policy.get("category_update_reason"),
        "display_group": policy.get("display_group"),
        "card_ready": bool(policy.get("card_ready")),
        "spain_priority": bool(policy.get("spain_priority")),
        "spain_confidence": policy.get("spain_confidence"),
        "spain_evidence_score": _score(policy.get("spain_evidence_score")),
        "spain_evidence_type": policy.get("spain_evidence_type"),
        "spain_evidence_direction": policy.get("spain_evidence_direction"),
        "spain_actionable": bool(policy.get("spain_actionable")),
        "urgent_score": _score(policy.get("urgent_score")),
        "urgent_flag": bool(policy.get("urgent_flag")),
        "context_only": bool(policy.get("context_only")),
        "storage_policy": policy.get("storage_policy"),
        "review_status": policy.get("review_status"),
    }


def _provisional_safe_child_policy(policy: dict) -> dict:
    """Keep a discovered destination provisional until its own HTML is fetched.

    Parent/anchor/URL-derived policies may carry strong-looking labels, but
    those labels are discovery hints only.  The only content-terminal exception
    is an explicitly marked independent decision for this exact destination
    (currently verified adult-filter memory).  Non-content transport, file,
    trap, and exact liveness rules remain enforceable before a fetch.
    """
    independent_content = bool(policy.get("independent_destination_decision"))
    if independent_content:
        return dict(policy)

    terminal_rule = str(policy.get("rule_id") or "") in {
        "DECIDE-001-FILE", "DECIDE-002-MALFORMED", "DECIDE-005-TRAP",
        "DECIDE-006-DEAD", "DECIDE-008-FETCH",
    }
    terminal_reason = str(policy.get("safety_reason") or "") in {
        "blocked_extension", "blocked_file_type", "blocked_url_extension",
        "download_like_url", "crawler_trap", "known_dead_url", "invalid_url",
        "malformed_onion", "clearnet_disabled",
    }
    preserve_terminal = bool(terminal_rule or terminal_reason)
    terminal_fields = {
        key: policy.get(key) for key in (
            "decision", "rule_id", "safety_reason", "display_safe_reason",
            "storage_policy", "review_status", "queue_policy", "active",
            "frontier_priority", "fetch_allowed", "card_allowed", "alert_allowed",
        ) if key in policy
    }
    result = dict(policy)
    result.update(primary_category="unknown", category="unknown", tags=[], risk_level="low",
                  content_category="unknown", site_type="unknown", page_type="unknown",
                  risk_category="unknown", ui_hidden_default=0,
                  confidence="low", risk_flags=[], storage_policy="safe_summary",
                  review_status="monitor", safety_reason="awaiting_page_classification",
                  screenshot_policy="blocked", screenshot_blocked_reason="awaiting_page_classification",
                  queue_policy="normal", active=1, spain_priority=False, geo_priority=None,
                  spain_match_reason=None, spain_match_language=None, spain_confidence=None,
                  spain_context_tags=[], category_confidence="provisional",
                  category_reason="Queued from a visible link; page content not fetched yet",
                  category_safe_label="Awaiting page classification", display_group="Queued",
                  classification_stage="prefetch", classification_evidence_source="unverified",
                  destination_html_evidence_version=0, hint_verified=False,
                  card_allowed=False, alert_allowed=False, preview_allowed=False,
                  expand_allowed=False)
    if preserve_terminal:
        result.update(terminal_fields)
        if result.get("decision") in {"reject", "restrict"}:
            result.update(active=0, queue_policy="blocked", fetch_allowed=False,
                          card_allowed=False, alert_allowed=False,
                          preview_allowed=False, expand_allowed=False)
    elif result.get("decision") in {"reject", "restrict"}:
        result.update(
            decision="monitor", rule_id="DECIDE-009-UNVERIFIED-HINT",
            display_safe_reason="Unverified route/content hint; fetch destination HTML",
            classification_decision="unverified_hint",
        )
    return result


def _mixed_link_directory(title: str | None, meta: str, visible_text: str, records: list[dict]) -> bool:
    onion_links = {record.get("url") for record in records if is_onion_url(record.get("url", ""))}
    heading = " ".join((title or "", meta or "", visible_text[:1500])).casefold()
    directory_words = any(marker in heading for marker in (
        "link list", "links list", "onion links", "directory", "link directory", "index", "catalog", "wiki"
    ))
    return (len(onion_links) >= 5 or
            (len(onion_links) >= 3 and len(onion_links) / max(1, len(records)) >= 0.5) or
            (len(onion_links) >= 3 and directory_words))


def _quarantined_directory_policy() -> dict:
    return {
        "primary_category": "directory_index", "category": "directory_index", "tags": ["directory_index"],
        "risk_level": "low", "confidence": "medium", "risk_flags": [], "storage_policy": "discard",
        "review_status": "filtered", "safety_reason": "mixed_directory_quarantine",
        "screenshot_policy": "blocked", "queue_policy": "expand", "active": 1,
        "priority_score": 10, "spain_priority": False, "tag_summary": "mixed_directory_quarantine",
        "quarantined_source": True,
    }


def _safe_mixed_directory_policy() -> dict:
    return {
        "primary_category": "directory_index", "category": "directory_index",
        "secondary_categories": [], "tags": ["directory_index", "restricted_child_present"],
        "risk_level": "medium", "confidence": "medium", "category_confidence": "medium",
        "category_reason": "Mixed directory with restricted child links filtered individually",
        "category_safe_label": "Directory / index", "display_group": "Discovery",
        "risk_flags": [], "storage_policy": "safe_summary", "review_status": "monitor",
        "safety_reason": "page_structure_directory_index", "screenshot_policy": "allowed",
        "screenshot_blocked_reason": None, "queue_policy": "expand",
        "active": 1, "priority_score": 20, "review_score": 10, "ui_priority": 10,
        "ui_hidden_default": 0, "spain_priority": False, "page_type": "link_repository",
        "tag_summary": "mixed_directory", "importance_level": "normal",
        "importance_reason": "mixed_link_repository",
    }


def finalize_page_policy(url: str, policy: dict, *, title: str | None,
                         page_structure: dict | None = None) -> dict:
    """Finalize fetched-page truth before storage, rollups, alerts, or previews."""
    result = dict(policy)
    structure = page_structure or {}
    if (result.get("primary_category") == "unknown"
            and (int(structure.get("onion_link_count") or 0) >= 5
                 or int(structure.get("external_onion_host_count") or 0) >= 3)):
        result.update(
            primary_category="directory_index", category="directory_index",
            page_type="link_repository", queue_policy="expand", active=1,
            content_quality="meaningful", safety_reason="page_structure_directory_index",
            category_confidence="high" if int(structure.get("onion_link_count") or 0) >= 20 else "medium",
            category_reason="High-edge onion link repository structure",
            category_safe_label="Directory / index", display_group="Discovery",
            review_status="monitor", risk_level="low", importance_level="normal",
            importance_reason="source_or_directory_value", ui_hidden_default=0,
        )
        result = calibrate_classification(result, stage="page")
    result["url"] = url
    evidence_version = destination_html_evidence_version(structure)
    result["destination_html_evidence_version"] = evidence_version
    result["classification_evidence_source"] = (
        "destination_html" if evidence_version else "unverified"
    )
    result["safe_display_name"] = derive_safe_display_name(url, title, result)
    return normalize_policy_state(result, fetched=True, requested_status="crawled")


def _is_marketplace_policy(policy: dict) -> bool:
    return str(policy.get("primary_category") or "").startswith("marketplace")


def _marketplace_adult_child_policy(policy: dict) -> dict:
    result = dict(policy)
    result.update({
        "decision": "restrict", "rule_id": "DECIDE-003-ADULT-CATEGORY",
        "primary_category": "adult_restricted", "category": "adult_restricted",
        "storage_policy": "metadata_only", "review_status": "restricted",
        "queue_policy": "blocked", "active": 0, "risk_level": "filtered",
        "safety_reason": "adult_marketplace_category",
        "display_safe_reason": "Restricted adult marketplace category metadata only",
        "screenshot_policy": "blocked", "screenshot_blocked_reason": "adult_marketplace_category",
        "ui_hidden_default": 1, "frontier_priority": 0, "spain_priority": False,
    })
    return result


def _adult_dominant_marketplace_policy() -> dict:
    result = _marketplace_adult_child_policy({})
    result.update(safety_reason="adult_marketplace_dominant",
                  display_safe_reason="Adult-dominant marketplace restricted",
                  category_reason="Adult-dominant marketplace page",
                  page_type="homepage")
    return result


def _adult_dominance_threshold() -> float:
    try:
        return min(1.0, max(0.5, float(get_str("ONION_ADULT_DOMINANCE_THRESHOLD", "0.60") or "0.60")))
    except (TypeError, ValueError):
        return 0.60


def _marketplace_public_discovery(item: dict, classified: list[dict],
                                  page_policy: dict) -> tuple[dict, list[dict]]:
    """Keep public market navigation useful while excluding transactional workflows."""
    source_page_type = str(page_policy.get("page_type") or "unknown")
    source_page_type = normalize_page_type(source_page_type)
    if source_page_type in {"vendor_profile", "login_wall"}:
        return {"total": 0, "adult": 0, "severe": 0, "restricted": 0,
                "ratio": 0.0, "mixed_directory": False, "adult_category_present": False}, []
    selected = []
    blocked_markers = (
        "/cart", "/checkout", "/order", "/orders", "/escrow", "/deposit", "/withdraw",
        "/wallet", "/message", "/messages", "/inbox", "/dispute", "/login", "/logout",
        "/register", "/settings", "add-to-cart", "add_to_cart",
    )
    category_markers = ("/category", "/categories", "/cat/", "category=", "cat=")
    seller_markers = ("/vendor", "/vendors", "/seller", "/sellers", "/profile", "/member/",
                      "memberlist.php?mode=viewprofile")
    listing_markers = ("/product", "/listing", "/item/", "product=", "listing=", "item=")
    cap = max(1, get_int("ONION_MARKETPLACE_MAX_PUBLIC_LINKS_PER_PAGE", 75))
    for record in classified:
        if not record.get("is_onion") or not record.get("is_internal"):
            continue
        target = str(record.get("url") or "").casefold()
        if any(marker in target for marker in blocked_markers):
            continue
        context = " ".join((str(record.get("anchor_text") or ""),
                            str(record.get("section_context") or ""))).casefold()
        seller_link = any(marker in target for marker in seller_markers) or any(
            term in context for term in ("seller", "vendor", "public profile", "store profile"))
        category_link = any(marker in target for marker in category_markers) or "category" in context
        listing_link = any(marker in target for marker in listing_markers) or any(
            term in context for term in ("listing", "product", "item details"))
        pagination = any(term in target for term in ("page=", "start=", "offset="))
        if source_page_type == "marketplace_listing":
            allowed = seller_link
        else:
            allowed = (seller_link or category_link or listing_link or pagination
                       or source_page_type in {"homepage", "category_index", "directory_index_page", "unknown"})
        if allowed:
            selected.append(record)
        if len(selected) >= cap:
            break
    onion_records = [record for record in selected if record.get("is_onion")]
    adult = sum(1 for record in onion_records if _adult_filtered(record.get("policy") or {}))
    severe = sum(1 for record in onion_records
                 if (record.get("policy") or {}).get("primary_category") == "severe_abuse_risk")
    candidate = sum(1 for record in onion_records
                    if (record.get("policy") or {}).get("classification_decision")
                    == "unverified_restricted_candidate")
    total = len(onion_records)
    restricted = adult + severe + candidate
    summary = {"total": total, "adult": adult, "severe": severe, "restricted": restricted,
               "ratio": restricted / total if total else 0.0,
               "mixed_directory": bool(restricted and restricted < total),
               "adult_category_present": bool(adult),
               "unverified_restricted_candidates": candidate}
    return summary, selected


def _blocked_interaction_child_policy(link: str, policy: dict) -> dict:
    """Record an interaction-looking route as a hint without blocking its page.

    A passive text-only GET can establish whether the destination is actually a
    login/cart/form page.  Its URL path alone cannot establish that fact.
    """
    child = dict(policy)
    child_path = (urlsplit(link).path or "").casefold()
    if any(marker in child_path for marker in (
            "/login", "/log-in", "/signin", "/register", "/account", "/cart",
            "/checkout", "/order", "/payment", "/contact", "/support/form")):
        child["interaction_route_hint"] = True
        child["interaction_route_hint_verified"] = False
        child["hint_verified"] = False
        if child.get("classification_decision") in {None, "unclassified", "abstained"}:
            child["classification_decision"] = "unverified_hint"
    return child


def _child_safety_rank(policy: dict) -> int:
    """Rank one independently-scoped child result without comparing raw context."""
    category = str(policy.get("primary_category") or "")
    if category == "severe_abuse_risk" or is_severe_blackhole_policy(policy):
        return 400
    if category in {"adult_filtered", "adult_restricted"}:
        return 300
    blocked = (policy.get("decision") in {"reject", "restrict"}
               or not policy.get("active", True)
               or policy.get("queue_policy") == "blocked")
    if blocked:
        reason = str(policy.get("safety_reason") or "")
        interaction_or_file = any(marker in reason for marker in (
            "login", "account", "transaction", "cart", "checkout", "contact", "mail",
            "extension", "file_type", "download",
        ))
        return 210 if interaction_or_file else 200
    return 100


def classify_outbound_records(item: dict, records: list[dict], page_policy: dict) -> tuple[dict, list[dict]]:
    """Classify paired observations independently, then keep one strict child result per URL."""
    total = adult = severe = candidate = fraud = file_blocked = transaction_blocked = blocked_count = 0
    safe_queued = unknown_queued = existing_count = external_seeded = 0
    classified = []
    depth = int(item.get("depth") or 0)
    source_host = (urlsplit(item["url"]).hostname or "").casefold()
    external_max_depth = get_int("ONION_MAX_DEPTH", 3)
    internal_max_depth = max(external_max_depth, get_int("ONION_INTERNAL_MAX_DEPTH", 8))
    directory_source = (page_policy.get("primary_category") in {"directory_index", "search_engine"}
                        or page_policy.get("page_type") in {
                            "directory_index_page", "link_repository", "search_results"})
    record_limit = max(1, get_int("ONION_MAX_LINKS_PER_PAGE", 2000))
    unique_records = _aggregate_link_records(records[:record_limit])
    for record in unique_records:
        link = record.get("url") or ""
        observations = _record_context_observations(record)
        forum_anchor_trigger = _forum_anchor_trigger(record)
        if not is_onion_url(link):
            scoped = [(observation, _decide(
                link, source_url=item["url"], anchor_text=observation["anchor_text"],
                source_context=observation["section_context"], depth=depth + 1,
                classification_scope="outbound")) for observation in observations]
            selected_observation, decision = max(
                scoped, key=lambda item_policy: _child_safety_rank(item_policy[1]))
            reason = str(decision.get("safety_reason") or "")
            if reason in {"blocked_extension", "blocked_file_type", "blocked_url_extension", "download_like_url"}:
                file_blocked += 1
            if any(token in reason for token in ("login", "account", "transaction", "cart", "checkout", "contact", "mail")):
                transaction_blocked += 1
            if decision.get("decision") in {"reject", "restrict"} or not decision.get("active", True):
                blocked_count += 1
            link_context = classify_link_context(
                link, anchor_text=selected_observation["anchor_text"],
                section_context=selected_observation["section_context"],
                source_page_type=str(page_policy.get("page_type") or "unknown"), same_host=False,
                restricted=(decision.get("decision") in {"reject", "restrict"}),
                unverified_hint=(bool(decision.get("url_hint_present"))
                                 or bool(decision.get("link_text_hint_present"))),
                policy_reason=str(decision.get("safety_reason") or ""),
            )
            classified.append({**record, "policy": decision, "decision": decision.get("decision"),
                               "is_internal": False, "existing_id": None, "is_onion": False,
                               "link_context": link_context,
                               "forum_anchor_trigger": forum_anchor_trigger})
            continue
        internal = (urlsplit(link).hostname or "").casefold() == source_host
        child_depth = depth + 1 if internal else 1 if directory_source else depth + 1
        scoped = []
        for observation in observations:
            child_policy = _decide(
                link, source_url=item["url"], anchor_text=observation["anchor_text"],
                source_context=observation["section_context"], depth=child_depth,
                max_depth=internal_max_depth if internal else external_max_depth,
                classification_scope="outbound")
            child_policy = _blocked_interaction_child_policy(link, child_policy)
            scoped.append((observation, child_policy))
        selected_observation, child = max(
            scoped, key=lambda item_policy: _child_safety_rank(item_policy[1]))
        existing = storage.get_onion_url_by_url(link)
        total += 1
        if child.get("classification_decision") == "unverified_restricted_candidate": candidate += 1
        elif child.get("primary_category") == "severe_abuse_risk": severe += 1
        elif _adult_filtered(child): adult += 1
        elif child.get("primary_category") in {"marketplace_fraud", "fraud_financial"}: fraud += 1
        reason = str(child.get("safety_reason") or "")
        if reason in {"blocked_extension", "blocked_file_type", "blocked_url_extension", "download_like_url"}:
            file_blocked += 1
        if any(token in reason for token in ("login", "account", "transaction", "cart", "checkout", "contact", "mail")):
            transaction_blocked += 1
        if existing:
            existing_count += 1
        if child.get("decision") in {"accept", "monitor"} and child.get("active", True):
            safe_queued += 1
            if child.get("primary_category") == "unknown":
                unknown_queued += 1
        child_blocked = (child.get("decision") in {"reject", "restrict"}
                         or not child.get("active", True))
        if child_blocked:
            blocked_count += 1
        if (directory_source and not internal and child.get("decision") in {"accept", "monitor"}
                and child.get("active", True)):
            external_seeded += 1
        link_context = classify_link_context(
            link, anchor_text=selected_observation["anchor_text"],
            section_context=selected_observation["section_context"],
            source_page_type=str(page_policy.get("page_type") or "unknown"), same_host=internal,
            restricted=child_blocked,
            unverified_hint=(bool(child.get("url_hint_present"))
                             or bool(child.get("link_text_hint_present"))),
            policy_reason=str(child.get("safety_reason") or ""),
        )
        classified.append({**record, "policy": child, "decision": child.get("decision"),
                           "is_internal": internal, "existing_id": existing.get("id") if existing else None,
                           "is_onion": True, "child_depth": child_depth,
                           "external_seed": bool(directory_source and not internal),
                           "link_context": link_context,
                           "forum_anchor_trigger": forum_anchor_trigger})
    restricted = adult + severe + candidate
    summary = {"total": total, "adult": adult, "severe": severe, "restricted": restricted,
               "ratio": restricted / total if total else 0.0,
               "mixed_directory": bool(restricted and restricted < total),
               "adult_category_present": bool(adult and _is_marketplace_policy(page_policy)),
               "unverified_restricted_candidates": candidate,
               "fraud": fraud, "file_blocked": file_blocked,
               "transaction_blocked": transaction_blocked, "safe_queued": safe_queued,
               "unknown_queued": unknown_queued, "existing": existing_count,
               "external_seeded": external_seeded, "blocked": blocked_count}
    return summary, classified


def _preview_outbound_summary(item: dict, records: list[dict], page_policy: dict) -> dict:
    """Compatibility wrapper; worker processing uses classify_outbound_records directly."""
    return classify_outbound_records(item, records, page_policy)[0]


def _decision_limits(max_depth: int | None = None) -> dict:
    return {
        "max_path_segments": get_int("ONION_MAX_PATH_SEGMENTS", 12),
        "max_repeated_path_segment": get_int("ONION_MAX_REPEATED_PATH_SEGMENT", 3),
        "max_query_params": get_int("ONION_MAX_QUERY_PARAMS", 8),
        "max_query_variants_per_host_path": get_int("ONION_MAX_QUERY_VARIANTS_PER_FAMILY", 20),
        "max_pages_per_host": get_int("ONION_MAX_PAGES_PER_HOST", 2000),
        "max_depth_from_seed": max_depth if max_depth is not None else get_int("ONION_INTERNAL_MAX_DEPTH", 8),
        "trap_block_score": get_int("ONION_TRAP_BLOCK_SCORE", 7),
        # Gather mode always admits pages 1-9. Operators may raise these
        # thresholds, but lowering them would contradict the frontier contract.
        "defer_pagination_at": max(10, get_int("ONION_DEFER_PAGINATION_AT", 10)),
        "hard_defer_pagination_at": max(50, get_int("ONION_HARD_DEFER_PAGINATION_AT", 50)),
    }


def _decide(url: str, *, source_url: str | None = None, anchor_text: str | None = None,
            source_context: str | None = None, depth: int = 0, max_depth: int | None = None,
            classification_scope: str = "url") -> dict:
    shape = url_shape(url)
    stats = storage.get_url_decision_stats(url, shape.get("url_family"), source_url)
    return _provisional_safe_child_policy(decide_url(
        url, source_url=source_url, anchor_text=anchor_text, source_context=source_context,
        depth=depth, stats=stats, limits=_decision_limits(max_depth),
        adult_memory_decision=storage.get_adult_memory_decision(url),
        classification_scope=classification_scope,
    ))


def _future(hours: int = 0, days: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours, days=days)).isoformat().replace("+00:00", "Z")


def _next_crawl_for_policy(policy: dict, relevant: bool) -> str:
    category = str(policy.get("primary_category") or "unknown")
    weapons = category in {"weapons_arms", "marketplace_weapons"}
    page_type = str(policy.get("page_type") or "unknown")
    if weapons and policy.get("spain_priority"):
        return _future(hours=6)
    if weapons or (policy.get("spain_priority") and relevant):
        return _future(hours=12)
    if relevant and normalize_page_type(page_type) in {"forum_thread", "vendor_profile", "marketplace_listing"}:
        return _future(hours=12)
    return _future(hours=24) if relevant else _future(days=7)


def _enrichment_allowed_path(url: str) -> bool:
    parsed = urlsplit(url or "")
    path = (parsed.path or "/").casefold()
    target = f"{path}?{parsed.query or ''}".casefold()
    if parsed.scheme not in {"http", "https"} or not is_onion_url(url):
        return False
    if any(marker in target for marker in ENRICHMENT_BLOCKED_MARKERS):
        return False
    if parsed.query and any(marker in parsed.query.casefold() for marker in
                            ("submit", "token", "session", "login", "auth", "cart", "checkout", "payment")):
        return False
    return True


def _same_host_url(base_url: str, path: str) -> str | None:
    parsed = urlsplit(base_url or "")
    host = (parsed.hostname or "").casefold()
    if not host or not host.endswith(".onion"):
        return None
    return urlunsplit((parsed.scheme or "http", host, path or "/", "", ""))


def _enrichment_candidates(card_id: int, representative_url: str, host: str) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()
    for path in ENRICHMENT_PUBLIC_PATHS:
        url = _same_host_url(representative_url, path)
        if url and url not in seen:
            seen.add(url)
            candidates.append((url, f"public_path:{path}"))
    with storage.get_db() as db:
        edges = [dict(row) for row in db.execute("""SELECT oe.discovered_url,oe.safe_anchor_text
          FROM onion_edges oe JOIN site_card_urls scu ON scu.url=oe.source_url
          WHERE scu.site_card_id=? AND COALESCE(oe.discovered_url,'')!=''
          ORDER BY oe.first_seen LIMIT 250""", (card_id,))]
    for edge in edges:
        url = normalize_url(edge.get("discovered_url") or "")
        parsed = urlsplit(url or "")
        if (parsed.hostname or "").casefold() != host:
            continue
        anchor = str(edge.get("safe_anchor_text") or "").casefold()
        path = (parsed.path or "/").casefold()
        if not any(term in anchor or f"/{term}" in path for term in ENRICHMENT_ANCHOR_TERMS):
            continue
        if url and url not in seen:
            seen.add(url)
            candidates.append((url, "internal_nav_anchor"))
    return candidates


def plan_card_enrichment(site_card_id: int, *, worker_id: str | None = None) -> dict:
    """Queue bounded, same-host public identity pages for weak Site Cards only."""
    with storage.get_db() as db:
        card = db.execute("SELECT * FROM site_cards WHERE id=?", (site_card_id,)).fetchone()
        rows = [dict(row) for row in db.execute("""SELECT ou.*,scu.url AS card_url,
          scu.onion_host,scu.path AS card_path FROM site_card_urls scu
          JOIN onion_urls ou ON ou.id=scu.onion_url_id WHERE scu.site_card_id=?
          ORDER BY CASE WHEN scu.path IN ('','/') THEN 0 ELSE 1 END,ou.id""", (site_card_id,))]
        already_enriched = int(db.execute("""SELECT COUNT(*) FROM onion_urls
          WHERE source_type='card_enrichment' AND source_url=?""",
          (f"site_card:{site_card_id}",)).fetchone()[0])
    if not card or not rows:
        return {"queued": 0, "skipped": 0, "reason": "missing_card"}
    card = dict(card)
    if (card.get("primary_category") in ENRICHMENT_RESTRICTED_CATEGORIES
            or card.get("storage_policy") in {"discard", "metadata_only"}
            or int(card.get("ui_hidden_default") or 0)):
        return {"queued": 0, "skipped": 0, "reason": "restricted_card"}
    completeness = str(card.get("card_completeness_label") or "weak")
    if completeness == "strong":
        return {"queued": 0, "skipped": 0, "reason": "already_strong"}
    configured_max = get_int("ONION_CARD_ENRICHMENT_MAX_URLS", 5)
    default_cap = 10 if completeness == "weak" and not card.get("safe_site_name") else 5
    max_new = max(1, min(10, configured_max if configured_max != 5 else default_cap))
    remaining = max_new - already_enriched
    if remaining <= 0:
        return {"queued": 0, "skipped": 0, "reason": "card_cap_reached"}
    representative = next((row for row in rows if row.get("active") and row.get("storage_policy") != "metadata_only"), rows[0])
    representative_url = representative.get("url") or card.get("representative_url")
    host = (urlsplit(representative_url or "").hostname or representative.get("onion_domain") or "").casefold()
    if not host.endswith(".onion"):
        return {"queued": 0, "skipped": 0, "reason": "missing_host"}
    queued = 0
    skipped = 0
    planned: list[dict] = []
    for candidate, reason in _enrichment_candidates(site_card_id, representative_url, host):
        if queued >= remaining:
            break
        if not _enrichment_allowed_path(candidate):
            skipped += 1
            continue
        if storage.get_onion_url_by_url(candidate):
            skipped += 1
            continue
        decision = _decide(candidate, source_url=representative_url, anchor_text=reason,
                           source_context="card_enrichment", depth=int(representative.get("depth") or 0) + 1,
                           classification_scope="outbound")
        fetch_allowed, _fetch_reason = is_fetch_allowed(candidate, False)
        if (decision.get("decision") in {"reject", "restrict"}
                or decision.get("primary_category") in ENRICHMENT_RESTRICTED_CATEGORIES
                or decision.get("storage_policy") in {"discard", "metadata_only"}
                or not fetch_allowed):
            skipped += 1
            continue
        policy = _provisional_safe_child_policy(decision)
        url_id = storage.insert_or_update_onion_url(
            candidate, host, source_url=f"site_card:{site_card_id}", source_type="card_enrichment",
            depth=int(representative.get("depth") or 0) + 1, status="queued", policy=policy)
        storage.apply_crawl_decision(candidate, decision)
        storage.insert_crawl_audit(candidate, "card_enrichment", "queued", reason)
        planned.append({"url_id": url_id, "path": urlsplit(candidate).path or "/", "reason": reason})
        queued += 1
    with storage.get_db() as db:
        now = storage.utc_now_iso()
        db.execute("UPDATE site_cards SET last_enrichment_planned_at=? WHERE id=?", (now, site_card_id))
        db.execute("""INSERT INTO site_card_events(site_card_id,event_type,event_summary,
          safe_metadata_json,created_at) VALUES(?,?,?,?,?)""",
          (site_card_id, "card_enrichment_planned",
           f"Queued {queued} bounded public same-host page(s) for card completeness",
           json.dumps({"queued": queued, "skipped": skipped, "planned": planned}, ensure_ascii=False), now))
    return {"queued": queued, "skipped": skipped, "reason": "planned"}


def _session() -> requests.Session:
    prepare_fetch_circuit()
    return create_onion_session(proxy_url=requests_proxy_url(), prepare=False)


def _passive_response_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Keep only short product headers needed by passive exposure extraction."""
    safe: dict[str, str] = {}
    for raw_name, value in headers.items():
        name = _PASSIVE_HEADER_NAMES.get(str(raw_name).casefold())
        if name is None or value is None:
            continue
        text = str(value).strip()
        if (_PASSIVE_HEADER_VALUE_RE.fullmatch(text)
                and not _PRIVATE_HEADER_MARKER_RE.search(text)):
            safe[name] = text
    return safe


def _read_bounded(response: requests.Response, limit: int, deadline: float | None = None) -> bytes:
    expected = response.headers.get("Content-Length")
    if expected and expected.isdigit() and int(expected) > limit:
        raise ValueError("response_too_large")
    data = bytearray()
    for chunk in response.iter_content(chunk_size=16384):
        if deadline is not None and time.monotonic() > deadline:
            raise TimeoutError("total_fetch_timeout")
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError("response_too_large")
    return bytes(data)


@contextmanager
def _fetch_heartbeat(url: str, url_id: int, interval_seconds: int = 15):
    """Keep the durable heartbeat fresh while a bounded Tor GET is waiting."""
    stop = threading.Event()

    def beat() -> None:
        while not stop.wait(max(5, interval_seconds)):
            try:
                storage.update_worker_state(
                    "fetching", "Waiting for Tor response", url, last_url_id=url_id,
                    progress=False,
                )
            except Exception:
                LOGGER.debug("Fetch heartbeat update failed")

    thread = threading.Thread(target=beat, name="onion-fetch-heartbeat", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=1)


def _normalize_discovered_link(raw_url: object, base_url: str) -> str | None:
    """Normalize link targets while retaining file-like URLs for a blocked audit row."""
    normalized = normalize_url(raw_url, base_url) if isinstance(raw_url, str) else None
    if normalized:
        return normalized
    if not isinstance(raw_url, str) or not raw_url.strip():
        return None
    try:
        parsed = urlsplit(urljoin(base_url, raw_url.strip()))
        if (parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname
                or parsed.username or parsed.password):
            return None
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit((parsed.scheme.casefold(), parsed.hostname.casefold() + port,
                           parsed.path or "/", parsed.query, ""))
    except (ValueError, UnicodeError):
        return None


def _first_charset_group(match: re.Match[str] | None) -> str | None:
    if not match:
        return None
    return next((value for value in match.groups() if value), None)


def _text_codec_name(label: str | None) -> str | None:
    """Return a canonical Python text codec name for one bounded charset label."""
    candidate = str(label or "").strip().strip("\"'")
    if not re.fullmatch(r"[A-Za-z0-9._:+-]{1,40}", candidate):
        return None
    try:
        info = codecs.lookup(candidate)
        decoded = codecs.getincrementaldecoder(info.name)(errors="strict").decode(b"", final=True)
    except (LookupError, TypeError, ValueError, UnicodeError):
        return None
    return info.name if isinstance(decoded, str) else None


def _meta_charset_label(body: bytes) -> str | None:
    """Read only the bounded ASCII-compatible HTML prefix for a meta charset."""
    prefix = body[:DECODING_META_SCAN_BYTES].decode("latin-1", errors="strict")
    for tag_match in _META_TAG_RE.finditer(prefix):
        label = _first_charset_group(_META_CHARSET_RE.search(tag_match.group(0)))
        if label:
            return label
    return None


def _decode_page_body(body: bytes, content_type: str, *, html: bool) -> tuple[str, dict]:
    """Decode a bounded response deterministically without statistical guessing.

    Precedence is a valid and strictly decodable HTTP charset, a byte-order mark,
    a bounded HTML meta declaration, then fixed strict fallbacks.  The final
    ISO-8859-1 fallback is total, so arbitrary response bytes never make parsing
    depend on platform locale or replacement heuristics.
    """
    http_label = _first_charset_group(_HTTP_CHARSET_RE.search(str(content_type or "")[:500]))
    http_codec = _text_codec_name(http_label)
    bom_codec = None
    if body.startswith((codecs.BOM_UTF32_BE, codecs.BOM_UTF32_LE)):
        bom_codec = "utf-32"
    elif body.startswith(codecs.BOM_UTF8):
        bom_codec = "utf-8-sig"
    elif body.startswith((codecs.BOM_UTF16_BE, codecs.BOM_UTF16_LE)):
        bom_codec = "utf-16"
    meta_label = _meta_charset_label(body) if html else None
    meta_codec = _text_codec_name(meta_label)

    candidates: list[tuple[str, str, str]] = []
    if http_codec:
        candidates.append((http_codec, "http_header", "declared"))
    if bom_codec:
        candidates.append((bom_codec, "byte_order_mark", "high"))
    if meta_codec:
        candidates.append((meta_codec, "html_meta", "declared"))
    candidates.extend((
        ("utf-8", "fallback_utf8", "high"),
        ("cp1252", "fallback_windows_1252", "medium"),
        ("iso-8859-1", "fallback_latin1", "low"),
    ))

    attempted: set[str] = set()
    failed = 0
    for requested_codec, source, confidence in candidates:
        codec_name = _text_codec_name(requested_codec)
        if not codec_name or codec_name in attempted:
            continue
        attempted.add(codec_name)
        try:
            decoded = body.decode(codec_name, errors="strict")
        except (LookupError, UnicodeDecodeError):
            failed += 1
            continue
        return decoded, {
            "charset": codec_name,
            "source": source,
            "confidence": confidence,
            "fallback_used": source.startswith("fallback_"),
            "http_charset_declared": bool(http_label),
            "http_charset_valid": bool(http_codec),
            "bom_present": bool(bom_codec),
            "meta_charset_declared": bool(meta_label),
            "meta_charset_valid": bool(meta_codec),
            "failed_candidates": failed,
        }

    # ISO-8859-1 above is total for bytes. This is a defensive invariant only.
    return body.decode("iso-8859-1", errors="strict"), {
        "charset": "iso8859-1", "source": "fallback_latin1", "confidence": "low",
        "fallback_used": True, "http_charset_declared": bool(http_label),
        "http_charset_valid": bool(http_codec), "bom_present": bool(bom_codec),
        "meta_charset_declared": bool(meta_label), "meta_charset_valid": bool(meta_codec),
        "failed_candidates": failed,
    }


def _append_bounded_unique(values: list[str], value: str, limit: int) -> None:
    if value and value not in values and len(values) < limit:
        values.append(value)


def _record_context_observations(record: dict) -> list[dict[str, str]]:
    """Return paired, bounded link contexts; never zip unrelated context lists."""
    observations: list[dict[str, str]] = []
    raw_observations = record.get("context_observations")
    if isinstance(raw_observations, list):
        for raw in raw_observations[:LINK_CONTEXT_VARIANT_LIMIT]:
            if not isinstance(raw, dict):
                continue
            observation = {
                "anchor_text": str(raw.get("anchor_text") or "")[:300],
                "section_context": str(raw.get("section_context") or "")[:200],
            }
            if observation not in observations:
                observations.append(observation)
    if not observations:
        observations.append({
            "anchor_text": str(record.get("anchor_text") or "")[:300],
            "section_context": str(record.get("section_context") or "")[:200],
        })
    return observations


def _aggregate_link_records(records: list[dict]) -> list[dict]:
    """Keep legacy first context while retaining bounded repeated observations."""
    aggregated: dict[str, dict] = {}
    for record in records:
        url = str(record.get("url") or "")
        if not url:
            continue
        anchor_text = str(record.get("anchor_text") or "")[:300]
        section_context = str(record.get("section_context") or "")[:200]
        try:
            occurrences = max(1, int(record.get("occurrence_count") or 1))
        except (TypeError, ValueError):
            occurrences = 1
        observations = _record_context_observations(record)
        current = aggregated.get(url)
        if current is None:
            current = {
                "url": url,
                "anchor_text": anchor_text,
                "section_context": section_context,
                "occurrence_count": min(LINK_OCCURRENCE_COUNT_LIMIT, occurrences),
                "anchor_texts": [],
                "section_contexts": [],
                "context_observations": [],
            }
            aggregated[url] = current
        else:
            current["occurrence_count"] = min(
                LINK_OCCURRENCE_COUNT_LIMIT, int(current["occurrence_count"]) + occurrences)
        for observation in observations:
            _append_bounded_unique(
                current["anchor_texts"], observation["anchor_text"], LINK_CONTEXT_VARIANT_LIMIT)
            _append_bounded_unique(
                current["section_contexts"], observation["section_context"],
                LINK_CONTEXT_VARIANT_LIMIT)
            if (observation not in current["context_observations"]
                    and len(current["context_observations"]) < LINK_CONTEXT_VARIANT_LIMIT):
                current["context_observations"].append(observation)
    return list(aggregated.values())


def _parse(body: bytes, content_type: str, base_url: str) -> tuple[str | None, str, str, list[dict], dict]:
    from bs4 import BeautifulSoup
    media_type = content_type.split(";", 1)[0].strip().lower()
    decoded, decoding = _decode_page_body(
        body, content_type, html=media_type in {"text/html", "application/xhtml+xml"})
    forum_route_hint = _forum_route_hint(base_url)
    text_limit = max(10_000, get_int("ONION_MAX_CLASSIFICATION_TEXT_CHARS", 200_000))
    if media_type == "text/plain":
        identity = extract_page_identity(base_url)
        features = {"plain_text_page": True, "onion_link_count": 0,
                    "internal_link_count": 0, "external_onion_count": 0}
        page_type_info = fingerprint_page_type(base_url, features, allow_url_hints=False)
        # A text/plain response has no document title. Keep the host only in
        # display metadata; never feed it into final page classification.
        return None, "", decoded[:text_limit], [], {
            "content_boundary": {
                "version": DESTINATION_HTML_EVIDENCE_VERSION,
                "outbound_anchor_text_removed": True,
            },
            "signals": ["plain_text_page"], "scores": {}, "heading_text": "",
            "onion_link_count": 0, "internal_link_count": 0, "external_onion_count": 0,
            "identity": identity, "page_type_info": page_type_info,
            "decoding": decoding, "decoding_charset": decoding["charset"],
            "decoding_source": decoding["source"],
            "forum_route_hint": forum_route_hint, **features,
        }
    soup = BeautifulSoup(decoded, "lxml")
    html_title = soup.title.get_text(" ", strip=True) if soup.title else None
    meta_by_key = {}
    meta_values = []
    for meta in soup.find_all("meta"):
        key = str(meta.get("name", meta.get("property", ""))).casefold()
        if meta.get("content") and key in {
            "description", "keywords", "og:description", "og:title", "twitter:title"
        }:
            meta_by_key[key] = str(meta.get("content"))
            if key in {"description", "keywords", "og:description"}:
                meta_values.append(str(meta.get("content")))
    # The HTTP client never loads subresources. Remove their DOM containers as
    # well so fallback markup inside noscript/iframe/embed/media elements cannot
    # leak links or text into discovery and final page classification.
    for tag in soup.find_all(REMOVED_TAGS):
        tag.decompose()

    def text_outside_links(node) -> str:
        parts = []
        for value in node.find_all(string=True):
            if value.find_parent("a") is None:
                cleaned = str(value).strip()
                if cleaned:
                    parts.append(cleaned)
        return " ".join(parts)

    def page_level_h1_text(heading) -> str:
        """Keep only H1 text outside links; anchor targets/text are hints."""
        outside = text_outside_links(heading).strip()
        anchors = heading.find_all("a", href=True)
        wrapping_anchor = heading.find_parent("a", href=True)
        if wrapping_anchor is not None:
            anchors = [wrapping_anchor, *anchors]
        if not anchors:
            return heading.get_text(" ", strip=True)
        return outside

    records = []
    link_limit = max(50, get_int("ONION_MAX_EXTRACTED_LINKS", 2000))
    for anchor in soup.find_all("a", href=True, limit=link_limit):
        normalized = _normalize_discovered_link(anchor.get("href"), base_url)
        if normalized:
            # Only retain a heading contained in the same bounded DOM block.
            # A global find_previous() leaks one section's words into unrelated
            # sibling links and must never become target evidence.
            container = anchor.find_parent(["li", "tr", "article", "section", "nav"])
            heading = container.find(["h1", "h2", "h3", "h4", "h5", "h6"]) if container else None
            if heading is None:
                sibling = anchor.previous_sibling
                for _ in range(8):
                    if sibling is None:
                        break
                    name = str(getattr(sibling, "name", "") or "").casefold()
                    if name in {"h1", "h2", "h3", "h4", "h5", "h6"}:
                        heading = sibling
                        break
                    if name in {"section", "article", "nav", "ul", "ol", "table"}:
                        break
                    sibling = sibling.previous_sibling
            records.append({"url": normalized, "anchor_text": anchor.get_text(" ", strip=True)[:300],
                            "section_context": heading.get_text(" ", strip=True)[:200] if heading else ""})
    heading_nodes = soup.find_all(["h1", "h2", "h3", "h4"], limit=200)
    headings = [text_outside_links(heading) for heading in heading_nodes]
    headings = [heading for heading in headings if heading]
    identity_headings = []
    for heading in heading_nodes:
        if str(heading.name).casefold() != "h1":
            continue
        candidate = page_level_h1_text(heading)
        if candidate:
            identity_headings.append(candidate)
            break
    heading_text = " ".join(headings)[:4000]
    host = (urlsplit(base_url).hostname or "").casefold()
    onion_links = [record for record in records if is_onion_url(record.get("url") or "")]
    unique_onion_links = {record["url"] for record in onion_links}
    external_onion_hosts = {(urlsplit(record["url"]).hostname or "").casefold()
                            for record in onion_links
                            if (urlsplit(record["url"]).hostname or "").casefold() != host}
    link_density = len(unique_onion_links) / max(1, len(records))
    internal_links = [record for record in onion_links
                      if (urlsplit(record["url"]).hostname or "").casefold() == host]
    # Link destinations and their paths are crawl-routing data, not proof of
    # what this returned page is. Page-type evidence comes from markup, forms,
    # headings, and aggregate link structure below.
    forum_links = 0
    market_links = 0
    shell_tokens = []
    for tag in soup.find_all(True, limit=4000):
        if str(tag.name).casefold() in {"a", "img", "source", "track"}:
            continue
        token_values = [str(value) for value in (
            tag.get("id"), " ".join(tag.get("class") or [])) if value]
        if not token_values:
            continue
        descendant_anchors = tag.find_all("a", limit=2)
        if len(descendant_anchors) == 1 and not text_outside_links(tag).strip():
            # A class/id on one link or its link-only row describes that child,
            # not the fetched parent page shell.
            continue
        shell_tokens.extend(token_values)
    class_tokens = " ".join(shell_tokens).casefold()
    form_actions = " ".join(str(form.get("action") or "") for form in soup.find_all("form")).casefold()
    form_route_labels = []
    for label, tokens in (
            ("login_route", ("login", "signin", "authenticate")),
            ("cart_route", ("/cart", "/basket")),
            ("checkout_route", ("checkout", "/order", "/payment")),
            ("contact_route", ("/contact", "/support")),
            ("search_route", ("search", "/query"))):
        if any(token in form_actions for token in tokens):
            form_route_labels.append(label)
    visible_hint = " ".join((html_title or "", " ".join(meta_values), heading_text[:1200])).casefold()
    destination_visible_text = text_outside_links(soup.body or soup).casefold()[:8000]
    structural_text = " ".join((visible_hint, destination_visible_text))
    has_password = bool(soup.find("input", attrs={"type": "password"}))
    has_search = bool(soup.find("input", attrs={"type": "search"}) or
                      soup.find("input", attrs={"name": lambda value: value and str(value).casefold() in {"q", "query", "search"}}))
    signals, scores = [], {"forum": 0, "directory": 0, "marketplace": 0, "search": 0, "article": 0}
    if has_password:
        signals.append("password_form")
    if forum_links >= 2:
        signals.append("forum_link_structure"); scores["forum"] += 3
    if any(marker in class_tokens for marker in ("phpbb", "postbody", "topiclist", "forumlist", "postprofile")):
        signals.append("forum_markup"); scores["forum"] += 3
    if len(unique_onion_links) >= 20:
        signals.append("high_edge_link_repository"); scores["directory"] += 4
    elif len(unique_onion_links) >= 5:
        signals.append("link_index_density"); scores["directory"] += 3
    elif len(external_onion_hosts) >= 3 and link_density >= 0.35:
        signals.append("external_host_link_density"); scores["directory"] += 3
    if len(soup.find_all(["ul", "ol"])) >= 3 and len(onion_links) >= 5:
        signals.append("structured_link_lists"); scores["directory"] += 2
    if market_links >= 2:
        signals.append("market_link_structure"); scores["marketplace"] += 3
    if any(marker in class_tokens for marker in ("product-grid", "product-card", "vendor-list", "marketplace", "catalog")):
        signals.append("market_markup"); scores["marketplace"] += 4
    if has_search:
        signals.append("search_form"); scores["search"] += 3
    if soup.find("article") or soup.find("time"):
        signals.append("article_markup"); scores["article"] += 2
    if any(marker in class_tokens for marker in ("article", "byline", "post-date", "entry-content")):
        signals.append("article_or_post_markup"); scores["article"] += 2
    wiki_markup = any(marker in class_tokens or marker in visible_hint for marker in
                      ("mediawiki", "mw-content", "wiki-page", "documentation", "table of contents"))
    code_markup = any(marker in class_tokens or marker in visible_hint for marker in
                      ("repository", "commit-list", "source code", "git repository", "code browser"))
    nav_anchors = sum(1 for anchor in soup.find_all("a", href=True) if anchor.find_parent("nav"))
    repeated_link_rows = sum(1 for anchor in soup.find_all("a", href=True)
                             if anchor.find_parent(["li", "tr", "article"]) is not None)
    directory_markers = any(marker in visible_hint for marker in (
        "onion directory", "link directory", "link list", "onion index", "site index",
        "directory index", "hidden services", "service directory",
    ))
    forum_thread_markup = any(marker in class_tokens for marker in ("postbody", "postprofile"))
    forum_index_markup = any(marker in class_tokens for marker in ("topiclist", "forumlist", "phpbb"))
    features = {
        "onion_link_count": len(unique_onion_links), "internal_link_count": len(internal_links),
        "external_onion_count": len(external_onion_hosts), "link_density": link_density,
        "forum_link_count": forum_links, "market_link_count": market_links,
        "forum_markup": bool(forum_thread_markup or forum_index_markup),
        "forum_thread_markup": forum_thread_markup,
        "forum_index_markup": forum_index_markup,
        "market_markup": any(marker in class_tokens for marker in ("product-grid", "product-card", "vendor-list", "marketplace", "catalog")),
        "wiki_markup": wiki_markup, "code_markup": code_markup,
        "structured_lists": len(soup.find_all(["ul", "ol"])) >= 3,
        "article_markup": bool(soup.find("article") or soup.find("time")),
        "has_password_form": has_password, "has_search_form": has_search,
        "form_count": len(soup.find_all("form")), "navigation_link_count": nav_anchors,
        "repeated_link_row_count": repeated_link_rows, "directory_markers": directory_markers,
        "login_markers": any(term in structural_text for term in ("sign in", "log in", "login", "authenticate")),
        "cart_markers": any(term in structural_text for term in ("shopping cart", "basket")),
        "checkout_markers": any(term in structural_text for term in ("checkout", "place order", "payment form")),
        "contact_markers": any(term in structural_text for term in ("contact us", "support form")),
        "error_markers": any(term in visible_hint for term in ("404 not found", "410 gone", "service unavailable", "server error")),
        "placeholder_markers": any(term in visible_hint for term in ("domain parked", "site parked", "coming soon")),
        "mirror_markers": "mirror" in visible_hint,
    }
    identity = extract_page_identity(
        base_url, title=html_title, og_title=meta_by_key.get("og:title"),
        twitter_title=meta_by_key.get("twitter:title"), headings=identity_headings,
        meta_description=meta_by_key.get("og:description") or meta_by_key.get("description"),
    )
    actor_evidence = extract_actor_evidence(soup, base_url=base_url, page_identity=identity)
    page_type_info = fingerprint_page_type(base_url, features, allow_url_hints=False)
    # The onion host is a display fallback only. Feeding it back as a title
    # would turn URL wording into final destination content evidence.
    title = (identity["detected_title"]
             if identity.get("title_source") != "onion_host" else None)
    aggregated_records = _aggregate_link_records(records)
    structure = {
        "content_boundary": {
            "version": DESTINATION_HTML_EVIDENCE_VERSION,
            "outbound_anchor_text_removed": True,
        },
        "signals": list(dict.fromkeys(signals)), "scores": scores, "heading_text": heading_text,
        "onion_link_count": len(unique_onion_links), "internal_link_count": len(internal_links),
        "external_onion_host_count": len(external_onion_hosts), "external_onion_count": len(external_onion_hosts), "link_density": link_density,
        "form_count": len(soup.find_all("form")), "has_password_form": has_password,
        "has_search_form": has_search, "identity": identity, "page_type_info": page_type_info,
        "actor_evidence": actor_evidence,
        "decoding": decoding, "decoding_charset": decoding["charset"],
        "decoding_source": decoding["source"],
        "forum_route_hint": forum_route_hint,
        "form_route_hints": {
            "labels": form_route_labels,
            "hint_verified": False,
            "evidence_source": "form_action_route",
        },
        "link_observation_count": len(records), "unique_link_count": len(aggregated_records),
        "duplicate_link_observation_count": max(0, len(records) - len(aggregated_records)),
        "parent_evidence": list(dict.fromkeys(signals + list(page_type_info.get("evidence") or [])))[:20],
        **features,
    }
    # Outbound anchor labels are classified with their child URL. They are removed from
    # page-level text so one restricted child cannot poison its safe parent page.
    for anchor in soup.find_all("a"):
        anchor.decompose()
    for tag in soup.find_all(REMOVED_TAGS):
        tag.decompose()
    content_root = soup.body or soup
    return (title, " ".join(meta_values)[:20_000], content_root.get_text(" ", strip=True)[:text_limit],
            aggregated_records, structure)


def _store_discovered_links(item: dict, records: list[dict], page_policy: dict,
                            classified_records: list[dict] | None = None,
                            preclassified_summary: dict | None = None) -> dict:
    if not page_policy.get("active") or page_policy.get("queue_policy") == "blocked":
        return {"total": 0, "restricted": 0, "adult": 0, "severe": 0, "ratio": 0.0,
                "mixed_directory": False, "processed_total": 0, "queued_new": 0,
                "already_known": 0, "rejected": 0, "deferred": 0, "blocked": 0}
    count = 0
    new_count = 0
    known_count = 0
    rejected_count = 0
    deferred_count = 0
    blocked_count = 0
    batch_size = max(1, get_int("ONION_MAX_NEW_LINKS_PER_PAGE", 50))
    summary, prepared = ((preclassified_summary, classified_records)
                         if classified_records is not None and preclassified_summary is not None
                         else classify_outbound_records(item, records, page_policy))
    forum_source = (page_policy.get("primary_category") == "forum_social"
                    or normalize_page_type(page_policy.get("page_type")) in {"forum_index", "forum_thread"})
    if forum_source:
        prepared = sorted(prepared, key=lambda record: (
            int(_is_forum_thread_url(str(record.get("url") or "")) and _forum_anchor_trigger(record)),
            int(_is_forum_thread_url(str(record.get("url") or ""))),
        ), reverse=True)
    source_host = (urlsplit(item["url"]).hostname or "").casefold()
    forum_budget = (storage.get_forum_thread_budget(
        source_host, initial_limit=get_int("ONION_FORUM_INITIAL_THREAD_LIMIT", 25),
        max_limit=get_int("ONION_FORUM_MAX_THREAD_BUDGET", 100)) if forum_source else None)
    admitted_threads = int(forum_budget.get("admitted") or 0) if forum_budget else 0
    for record in prepared:
        link = record["url"]
        policy = _provisional_safe_child_policy(record["policy"])
        if not record.get("is_onion"):
            rejected = policy
            storage.insert_crawl_audit(link, "decide_rule", rejected["decision"], rejected.get("rule_id"))
            rejected_count += 1
            continue
        internal = bool(record.get("is_internal"))
        existing = record.get("existing_id")
        deferred = bool(policy.get("defer_requested"))
        status = ("deferred_deep_pagination" if deferred else
                  "queued" if policy.get("decision") in {"accept", "monitor"} else
                  "retry" if policy.get("decision") == "fetch_later" else "blocked")
        forum_thread_hint = bool(forum_source and internal and _is_forum_thread_url(link))
        over_forum_budget = bool(forum_thread_hint and existing is None and forum_budget
                                 and admitted_threads >= int(forum_budget["permitted"]))
        if over_forum_budget:
            status = "deferred_forum_budget"
        if status.startswith("deferred"):
            deferred_count += 1
        elif status == "blocked":
            blocked_count += 1
        link_id = storage.insert_or_update_onion_url(
            link, urlsplit(link).hostname, item["url"],
            "forum_thread_hint" if forum_thread_hint else
            "onion_internal" if internal else "directory_seed" if record.get("external_seed") else "onion_page",
            int(record.get("child_depth") if record.get("child_depth") is not None else int(item.get("depth") or 0) + 1),
            status=status, policy=policy
        )
        if (is_severe_blackhole_policy(policy)
                and _independent_prefetch_content_decision(policy)):
            storage.enforce_severe_blackhole(link, policy)
            count += 1
            continue
        storage.apply_crawl_decision(link, policy)
        if over_forum_budget:
            storage.defer_frontier_url(link, "forum_initial_thread_budget",
                                       deferred_status="deferred_forum_budget")
        elif deferred:
            storage.defer_frontier_url(link, policy.get("defer_reason") or "deep_pagination_default_defer")
        storage.insert_crawl_audit(link, "decide_rule", policy["decision"], policy.get("rule_id"))
        storage.record_classification_decision(
            link, policy, stage="outbound",
            safe_metadata={"source": "discovered_link", "scope": "child_url"},
        )
        count += 1
        if (_adult_filtered(policy)
                and _independent_prefetch_content_decision(policy)):
            continue
        if policy.get("decision") == "reject":
            rejected_count += 1
            continue
        if not page_policy.get("quarantined_source"):
            storage.insert_onion_edge(item["url"], link, record.get("link_context"))
        if existing is not None:
            known_count += 1
            if count % batch_size == 0:
                storage.update_worker_state("expanding_links", f"Checked {count} unique links from this page",
                                            item["url"], last_url_id=int(item["id"]))
            continue
        if forum_thread_hint and not over_forum_budget:
            admitted_threads += 1
        new_count += 1
        # Safe child URLs do not become result cards or alerts until their own content
        # has been fetched and classified. Restricted metadata remains non-fetchable.
        if (policy.get("storage_policy") == "metadata_only"
                and policy.get("card_allowed") is not False):
            site_dedupe.ensure_url_site_card(link_id, policy, source_context=item["url"])
            if policy.get("alert_allowed") is not False:
                storage.queue_spain_alert(link, policy, item["url"])
        if count % batch_size == 0:
            storage.update_worker_state("expanding_links", f"Checked {count} unique links from this page",
                                        item["url"], last_url_id=int(item["id"]))
    if count:
        LOGGER.info("Link list processed safely: total=%d new=%d already_known=%d", count, new_count, known_count)
    result = storage.update_outbound_restriction_summary(
        item["url"], summary["total"], summary["adult"], summary["severe"],
        adult_category_present=bool(summary.get("adult_category_present")),
        candidate=int(summary.get("unverified_restricted_candidates") or 0),
        safe_queued=int(summary.get("safe_queued") or 0),
        unknown_queued=int(summary.get("unknown_queued") or 0),
        fraud=int(summary.get("fraud") or 0), file_blocked=int(summary.get("file_blocked") or 0),
        transaction_blocked=int(summary.get("transaction_blocked") or 0),
        existing=int(summary.get("existing") or 0), external_seeded=int(summary.get("external_seeded") or 0),
        blocked=int(summary.get("blocked") or 0))
    result.update(
        processed_total=len(prepared), queued_new=new_count,
        already_known=known_count, rejected=rejected_count,
        deferred=deferred_count,
        blocked=max(blocked_count, int(result.get("blocked") or 0)),
    )
    return result


def _finish_restricted(item: dict, response_status: int, policy: dict,
                       page_structure: dict | None = None) -> None:
    url = item["url"]
    if is_severe_blackhole_policy(policy):
        # The central writer first validates the current destination parser
        # boundary and binds provenance to this exact severe category.  The
        # blackhole then runs from that trusted row; a caller-supplied policy
        # alone can never authorize destructive cleanup.
        storage.apply_onion_policy(
            url, policy, response_status, checked=True,
            page_structure=page_structure)
        return
    storage.mark_onion_crawled(
        url, response_status, None, None, None, policy["priority_score"], policy["priority_score"],
        policy["risk_level"], policy.get("tags", []), policy.get("risk_flags", []), "blocked", None,
    )
    storage.apply_onion_policy(
        url, policy, response_status, checked=True, page_structure=page_structure)
    site_dedupe.ensure_url_site_card(int(item["id"]), policy, source_context=item.get("source_url"))
    storage.queue_spain_alert(url, policy, item.get("source_url"))
    storage.block_page_preview(url, policy.get("safety_reason", "restricted_content"))
    storage.insert_crawl_audit(url, "content_policy", "metadata_only", policy.get("safety_reason"))


def fetch_one(worker_id: str | None = None) -> bool:
    """Stage 1: claim one frontier URL, fetch/parse it, and store a snapshot.

    This intentionally stops before page classification, Site Card rollups,
    profile refresh, mirror clustering, OCR, and other heavier post-fetch work.
    """
    storage.ensure_db_initialized()
    worker_id = worker_id or f"fetch:{os.getpid()}"
    storage.heartbeat_worker_instance(worker_id, "fetch", "checking_queue")
    item = storage.claim_next_onion_url(
        storage.utc_now_iso(), worker_id=worker_id,
        exploration=get_bool("ONION_EXPLORATION_MODE", True),
        claim_timeout_minutes=get_int("ONION_CLAIM_TIMEOUT_MINUTES", 45),
    )
    if not item:
        state = "paused" if storage.worker_claims_paused() else "idle"
        storage.heartbeat_worker_instance(worker_id, "fetch", state)
        return False
    url = item["url"]
    response = None
    session = None
    try:
        storage.heartbeat_worker_instance(worker_id, "fetch", "prefetch", current_url_id=int(item["id"]))
        pre_policy = _decide(
            url, source_url=item.get("source_url"), source_context=item.get("source_type"),
            depth=int(item.get("depth") or 0))
        storage.apply_prefetch_policy(url, pre_policy)
        if (is_severe_blackhole_policy(pre_policy)
                and _independent_prefetch_content_decision(pre_policy)):
            storage.enforce_severe_blackhole(url, pre_policy)
            storage.heartbeat_worker_instance(
                worker_id, "fetch", "filtered", current_url_id=int(item["id"]), processed_increment=1)
            return True
        storage.apply_crawl_decision(url, pre_policy)
        storage.record_classification_decision(
            url, pre_policy, stage="prefetch", previous_category=item.get("primary_category"),
            safe_metadata={"source": item.get("source_type"), "scope": "url"},
        )
        if pre_policy.get("defer_requested"):
            storage.defer_frontier_url(
                url, pre_policy.get("defer_reason") or "deep_pagination_default_defer")
        if (_adult_filtered(pre_policy)
                and _independent_prefetch_content_decision(pre_policy)):
            storage.release_url_claim(url, "blocked", worker_id)
            storage.insert_crawl_audit(url, "url_prefilter", "adult_filtered", "adult_content_filtered")
            storage.heartbeat_worker_instance(
                worker_id, "fetch", "filtered", current_url_id=int(item["id"]), processed_increment=1)
            return True
        if (pre_policy.get("decision") in {"reject", "restrict", "fetch_later"}
                or not pre_policy.get("active")):
            status = "retry" if pre_policy.get("decision") == "fetch_later" else "blocked"
            storage.release_url_claim(url, status, worker_id)
            storage.insert_crawl_audit(url, "fetch_policy", status, pre_policy.get("safety_reason"))
            storage.heartbeat_worker_instance(
                worker_id, "fetch", status, current_url_id=int(item["id"]), processed_increment=1)
            return True
        allowed, reason = is_fetch_allowed(url, get_bool("ALLOW_CLEARNET_FETCH", False))
        if not allowed:
            blocked = dict(
                pre_policy, active=0, queue_policy="blocked", storage_policy="metadata_only",
                review_status="restricted", safety_reason=reason, screenshot_policy="blocked",
                screenshot_blocked_reason=reason)
            storage.apply_onion_policy(url, blocked)
            storage.release_url_claim(url, "blocked", worker_id)
            storage.insert_crawl_audit(url, "fetch_policy", "blocked", reason)
            storage.heartbeat_worker_instance(
                worker_id, "fetch", "blocked", current_url_id=int(item["id"]), processed_increment=1)
            return True
        if not storage.mark_url_fetching(int(item["id"]), worker_id):
            raise storage.WorkerClaimLost(f"fetch_claim_lost:{item['id']}")
        storage.heartbeat_worker_instance(worker_id, "fetch", "fetching", current_url_id=int(item["id"]))
        fetch_started = time.monotonic()
        total_fetch_timeout = max(15, get_int("ONION_TOTAL_FETCH_TIMEOUT_SECONDS", 60))
        session = _session()
        with _fetch_heartbeat(url, int(item["id"])):
            response = fetch_onion(url, session=session,
                                   timeout=(get_int("ONION_CONNECT_TIMEOUT_SECONDS", 15),
                                            get_int("ONION_READ_TIMEOUT_SECONDS", 30)))
        if response.status_code in {404, 410}:
            storage.mark_onion_dead(
                url, response.status_code, f"http_{response.status_code}", worker_id=worker_id)
            storage.heartbeat_worker_instance(worker_id, "fetch", "dead", current_url_id=int(item["id"]),
                                              processed_increment=1)
            return True
        content_type = response.headers.get("Content-Type")
        if not is_content_type_allowed(content_type):
            blocked = dict(pre_policy, active=0, queue_policy="blocked", storage_policy="metadata_only",
                           review_status="restricted", safety_reason="blocked_content_type",
                           screenshot_policy="blocked", screenshot_blocked_reason="blocked_content_type")
            storage.apply_onion_policy(url, blocked, response.status_code, checked=True)
            storage.release_url_claim(url, "blocked", worker_id)
            storage.insert_crawl_audit(url, "content_type", "blocked", "blocked_content_type")
            storage.heartbeat_worker_instance(worker_id, "fetch", "blocked", current_url_id=int(item["id"]),
                                              processed_increment=1)
            return True
        body = _read_bounded(response, get_int("ONION_MAX_PAGE_BYTES", 1_000_000),
                             deadline=fetch_started + total_fetch_timeout)
        title, meta_text, visible_text, link_records, page_structure = _parse(body, content_type or "", url)
        headers = _passive_response_headers(response.headers)
        response_status = response.status_code
        storage.store_fetched_page_snapshot(
            int(item["id"]), url, worker_id=worker_id, response_status=response_status,
            content_type=content_type, headers=headers, title=title, meta_text=meta_text,
            visible_text=visible_text, link_records=link_records, page_structure=page_structure,
            pre_policy=pre_policy,
        )
        storage.insert_crawl_audit(url, "fetch", "classification_pending", "snapshot_stored")
        storage.heartbeat_worker_instance(worker_id, "fetch", "snapshot_stored",
                                          current_url_id=int(item["id"]), processed_increment=1)
        return True
    except Exception as exc:
        error_count = int(item.get("error_count") or 0) + 1
        dead = error_count >= 4
        updated = storage.mark_onion_error(
            url, type(exc).__name__,
            None if dead else (_future(days=3) if error_count >= 3 else _future(hours=6)),
            dead=dead, worker_id=worker_id,
        )
        if updated:
            storage.insert_crawl_audit(url, "fetch", "error", type(exc).__name__)
        storage.heartbeat_worker_instance(worker_id, "fetch", "error", current_url_id=int(item["id"]),
                                          last_error=type(exc).__name__, processed_increment=1,
                                          observe=False)
        LOGGER.warning("Staged fetch failed safely: %s", type(exc).__name__)
        return True
    finally:
        try:
            if response is not None:
                response.close()
        except Exception:
            pass
        try:
            if session is not None:
                session.close()
        except Exception:
            pass


def verify_one(worker_id: str | None = None) -> bool:
    """Stage 2: classify one fetched snapshot and enqueue card work when useful."""
    storage.ensure_db_initialized()
    worker_id = worker_id or f"verify:{os.getpid()}"
    storage.heartbeat_worker_instance(worker_id, "verify", "checking_queue")
    snapshot = storage.claim_next_fetched_page(worker_id, get_int("ONION_CLAIM_TIMEOUT_MINUTES", 45))
    if not snapshot:
        state = "paused" if storage.worker_claims_paused() else "idle"
        storage.heartbeat_worker_instance(worker_id, "verify", state)
        return False
    url = snapshot["url"]
    url_id = int(snapshot["onion_url_id"])
    try:
        storage.heartbeat_worker_instance(worker_id, "verify", "classifying", current_url_id=url_id,
                                          current_job_id=int(snapshot["id"]))
        title = snapshot.get("title")
        meta_text = snapshot.get("meta_text") or ""
        visible_text = snapshot.get("visible_text") or ""
        link_records = snapshot.get("link_records") or []
        page_structure = snapshot.get("page_structure") or {}
        if not has_current_destination_html_evidence(page_structure):
            storage.reject_unproven_fetched_page(
                int(snapshot["id"]), url_id, worker_id=worker_id)
            storage.insert_crawl_audit(
                url, "classification_boundary", "refetch_queued",
                "legacy_snapshot_without_content_boundary")
            storage.heartbeat_worker_instance(
                worker_id, "verify", "refetch_queued", current_url_id=url_id,
                current_job_id=int(snapshot["id"]), processed_increment=1)
            return True
        item = {
            "id": url_id, "url": url, "depth": int(snapshot.get("depth") or 0),
            "source_url": snapshot.get("source_url"), "source_type": snapshot.get("source_type"),
            "primary_category": snapshot.get("primary_category"),
            "analyst_category": snapshot.get("analyst_category"),
            "classification_decision": snapshot.get("classification_decision"),
            "site_card_id": snapshot.get("site_card_id"),
        }
        policy = _classify_fetched_page(
            url, title=title, meta=meta_text, visible_text=visible_text,
            source_url=item.get("source_url"), source_context=item.get("source_type"),
            page_structure=page_structure,
        )
        directory_theme = _mixed_link_directory(title, meta_text, visible_text, link_records)
        structural_type = dict(page_structure.get("page_type_info") or {})
        external_hosts = int(page_structure.get("external_onion_host_count") or 0)
        structural_directory = bool(
            directory_theme or page_structure.get("directory_markers")
            or external_hosts >= 3
            or structural_type.get("page_type") in {"link_repository", "directory_index_page"}
        )
        outbound_preview, classified_outbound = classify_outbound_records(item, link_records, policy)
        # Parent dominance is decided only from the fetched parent's own HTML.
        # Child URL/anchor counts are deliberately excluded from this decision.
        adult_parent_dominant = bool(
            int(policy.get("signal_count") or 0) >= 1
            and float(policy.get("dominance_score") or 0) >= 0.75)
        if structural_directory and _adult_filtered(policy) and not adult_parent_dominant:
            policy = _safe_mixed_directory_policy()
            policy.update(false_positive_guard_applied=True,
                          safe_signal_labels=["adult_child_links_scoped_to_directory"])
        if structural_directory and not _adult_filtered(policy):
            policy.setdefault("page_type", "link_repository")
            policy["queue_policy"] = "expand"
            policy["active"] = 1
            if policy.get("primary_category") in {"unknown", "general_other"}:
                policy.update(primary_category="directory_index", category="directory_index",
                              content_category="directory_index",
                              category_reason="Directory or link repository structure detected",
                              category_safe_label="Directory / index", display_group="Discovery",
                              review_status="monitor", safety_reason="page_structure_directory_index",
                              importance_level="normal", importance_reason="source_or_directory_value",
                              ui_hidden_default=0)
        restricted_children = bool(outbound_preview.get("restricted"))
        if restricted_children and not _adult_filtered(policy):
            policy["tags"] = list(dict.fromkeys(policy.get("tags", []) + ["restricted_child_present"]
                                                + (["adult_link_present"] if outbound_preview.get("adult") else [])))
        identity = dict(page_structure.get("identity") or extract_page_identity(url, title=title))
        if (_adult_filtered(policy) or policy.get("primary_category") == "severe_abuse_risk"
                or policy.get("storage_policy") in {"metadata_only", "discard"}):
            identity = extract_page_identity(
                url, restricted=True, safe_category_label=safe_category_label(policy.get("primary_category")))
        page_type_info = fingerprint_page_type(
            url, page_structure, current_type=str(policy.get("page_type") or "unknown"),
            allow_url_hints=False)
        if page_type_info["page_type_confidence"] in {"medium", "high"}:
            policy["page_type"] = page_type_info["page_type"]
        policy.update(
            child_adult_link_count=int(outbound_preview.get("adult") or 0),
            child_restricted_link_count=int(outbound_preview.get("restricted") or 0),
            child_blocked_link_count=int(outbound_preview.get("blocked") or 0),
            parent_evidence=list(page_structure.get("parent_evidence") or [])[:20],
            detected_title=identity.get("detected_title"), title_source=identity.get("title_source"),
            identity_confidence=identity.get("identity_confidence"),
            page_type_confidence=page_type_info.get("page_type_confidence"),
            page_type_evidence=page_type_info.get("evidence", []),
            outbound_onion_count=int(page_structure.get("onion_link_count") or 0),
            internal_link_count=int(page_structure.get("internal_link_count") or 0),
            external_onion_count=int(page_structure.get("external_onion_count") or 0),
        )
        policy = calibrate_classification(policy, stage="page")
        policy = finalize_page_policy(url, policy, title=title, page_structure=page_structure)
        liveness = assess_content_liveness(int(snapshot.get("response_status") or 0), title, visible_text)
        if (policy.get("page_type") in {"link_repository", "directory_index_page", "forum_index",
                                        "marketplace_front", "search_results", "mirror_index"}
                and outbound_preview.get("total") and liveness["content_quality"] in {"empty", "thin"}):
            liveness = dict(liveness, liveness_status="live", content_quality="meaningful",
                            reason="link_directory_content")
        policy = apply_classification_contract(
            policy, identity, page_type_info, dict(page_structure, url=url), liveness["content_quality"],
            previous_category=snapshot.get("primary_category"),
            previous_category_trusted=bool(
                snapshot.get("analyst_category")
                or (
                    snapshot.get("prior_verification_reason") == "page_fetched_and_classified"
                    and int(snapshot.get("prior_destination_html_evidence_version") or 0)
                        >= DESTINATION_HTML_EVIDENCE_VERSION
                    and snapshot.get("prior_classification_evidence_source") == "destination_html"
                )
            ),
        )
        policy.update(compute_card_readiness(
            policy, identity, page_type_info, page_structure, liveness["content_quality"],
            analyst_confirmed=bool(snapshot.get("analyst_category")
                                   or snapshot.get("classification_decision") == "analyst_confirmed"),
        ))
        storage.apply_onion_policy(
            url, policy, int(snapshot.get("response_status") or 0), checked=True,
            page_structure=page_structure)
        if is_severe_blackhole_policy(policy):
            storage.enforce_severe_blackhole(url, policy)
            storage.complete_entity_expansion_for_url(
                url_id, "DESTINATION_FILTERED",
                safe_metadata={"verified": True, "response_status": snapshot.get("response_status"),
                               "safety_state": "filtered"})
            if not storage.mark_fetched_page_verified(int(snapshot["id"]), worker_id):
                raise storage.WorkerClaimLost(f"verify_claim_lost:{snapshot['id']}")
            try:
                storage.heartbeat_worker_instance(
                    worker_id, "verify", "filtered", current_url_id=url_id,
                    current_job_id=int(snapshot["id"]), processed_increment=1)
            except Exception as exc:
                LOGGER.warning("Verification completed but heartbeat failed safely: %s",
                               type(exc).__name__)
            return True
        storage.record_classification_decision(
            url, policy, stage="page", previous_category=snapshot.get("primary_category"),
            safe_metadata=_classification_decision_metadata(
                policy, liveness.get("content_quality")),
        )
        if _adult_filtered(policy):
            storage.detach_restricted_url_from_site_card(url)
            storage.block_page_preview(url, policy.get("safety_reason", "adult_content_filtered"))
            storage.complete_entity_expansion_for_url(
                url_id, "DESTINATION_FILTERED",
                safe_metadata={"verified": True, "response_status": snapshot.get("response_status"),
                               "safety_state": "filtered"})
            storage.insert_crawl_audit(url, "verify", "adult_filtered", "adult_content_filtered")
            if not storage.mark_fetched_page_verified(int(snapshot["id"]), worker_id):
                raise storage.WorkerClaimLost(f"verify_claim_lost:{snapshot['id']}")
            try:
                storage.heartbeat_worker_instance(
                    worker_id, "verify", "filtered", current_url_id=url_id,
                    current_job_id=int(snapshot["id"]), processed_increment=1)
            except Exception as exc:
                LOGGER.warning("Verification completed but heartbeat failed safely: %s",
                               type(exc).__name__)
            return True
        storage.set_onion_liveness(url, liveness["fetch_status"], liveness["liveness_status"],
                                   liveness["content_quality"], policy.get("page_type"))
        if liveness["liveness_status"] == "soft_dead":
            storage.mark_onion_soft_dead(url, int(snapshot.get("response_status") or 0), liveness["reason"])
            storage.complete_entity_expansion_for_url(
                url_id, "DESTINATION_SOFT_DEAD",
                safe_metadata={"verified": True, "response_status": snapshot.get("response_status"),
                               "content_quality": liveness.get("content_quality")})
            storage.create_site_card_job(onion_url_id=url_id, url=url, site_card_id=item.get("site_card_id"),
                                         priority=policy.get("priority_score") or 0)
            if not storage.mark_fetched_page_verified(int(snapshot["id"]), worker_id):
                raise storage.WorkerClaimLost(f"verify_claim_lost:{snapshot['id']}")
            try:
                storage.heartbeat_worker_instance(
                    worker_id, "verify", "verified", current_url_id=url_id,
                    current_job_id=int(snapshot["id"]), processed_increment=1)
            except Exception as exc:
                LOGGER.warning("Verification completed but heartbeat failed safely: %s",
                               type(exc).__name__)
            return True
        normalized_text = " ".join(visible_text.split())
        content_hash = hashlib.sha256(normalized_text.encode("utf-8", "ignore")).hexdigest()
        fuzzy_hash = hashlib.sha256(f"{title or ''}\n{normalized_text[:2000]}".casefold().encode("utf-8", "ignore")).hexdigest()
        links = [record["url"] for record in link_records]
        limited = policy["storage_policy"] in {"metadata_limited", "metadata_only"}
        normalized_page_type = normalize_page_type(policy.get("page_type"))
        safe_limited_identity = bool(
            limited and policy.get("storage_policy") != "metadata_only"
            and identity.get("limited_title_safe")
            and normalized_page_type in {"homepage", "marketplace_front", "directory_index_page",
                                         "link_repository", "forum_index", "search_results", "mirror_index"}
        )
        display_title = (make_safe_snippet(identity.get("display_name") or title or "", max_chars=180)
                         if safe_limited_identity else
                         safe_category_label(policy["primary_category"]) if limited
                         else make_safe_snippet(identity.get("display_name") or title or "", max_chars=180))
        policy["safe_display_name"] = display_title
        policy["safe_site_name"] = display_title if safe_limited_identity else None
        policy["unsafe_title_hidden"] = bool(limited and not safe_limited_identity)
        policy["policy_label"] = safe_category_label(policy["primary_category"])
        flags = list(dict.fromkeys(policy.get("risk_flags", []) + classify_risk_flags(visible_text, links)))
        reasons = list(policy.get("tags", []))
        if limited:
            indicators = [entry for entry in extract_indicators("", links)
                          if entry.get("type") in LIMITED_INDICATOR_TYPES]
            exposures = extract_passive_exposures(url, int(snapshot.get("response_status") or 0),
                                                  snapshot.get("headers") or {}, None, "", [])
            snippet = f"{safe_category_label(policy['primary_category'])}. Content omitted under metadata-limited safety policy."
            page_topics = {"topics": [safe_category_label(policy["primary_category"])], "keywords": []}
        else:
            indicators = extract_indicators(visible_text, links)
            exposures = extract_passive_exposures(url, int(snapshot.get("response_status") or 0),
                                                  snapshot.get("headers") or {}, title, visible_text, links)
            snippet = make_safe_snippet(visible_text, reasons, max(50, min(get_int("MAX_SAFE_SNIPPET_CHARS", 500), 500)))
            page_topics = extract_page_topics(visible_text)
        storage.elevate_review_for_indicators(url, indicators)
        storage.upsert_page_topics(url, page_topics["topics"], page_topics["keywords"])
        for indicator in indicators:
            iid = storage.upsert_indicator(indicator["type"], indicator["value"],
                                           indicator["normalized_value"], "onion_page", url,
                                           float(indicator["confidence"]), flags)
            storage.link_indicator(iid, "onion_page", url, indicator.get("context"))
        storage.insert_passive_exposures(url, exposures)
        relevant = bool(policy.get("card_ready") and (
            (liveness["content_quality"] != "thin" and policy["primary_category"] != "unknown")
            or policy.get("spain_priority") or indicators or exposures))
        if relevant:
            hit_id = storage.insert_onion_hit(url, display_title, policy["priority_score"],
                                              policy["risk_level"], reasons, snippet, indicators,
                                              item.get("source_url"), exposures)
            storage.insert_alert_from_onion_hit(hit_id)
        next_crawl = _next_crawl_for_policy(policy, relevant)
        storage.record_page_change(url, content_hash, policy.get("primary_category"))
        storage.mark_onion_crawled(
            url, int(snapshot.get("response_status") or 0), display_title, content_hash, fuzzy_hash,
            policy["priority_score"], policy["priority_score"], policy["risk_level"], reasons,
            flags, "crawled", next_crawl)
        storage.apply_onion_policy(
            url, policy, int(snapshot.get("response_status") or 0), checked=True,
            page_structure=page_structure)
        _expand_relevant_forum_thread(url, policy)
        records_to_store = link_records
        classified_to_store = classified_outbound
        summary_to_store = outbound_preview
        if _is_marketplace_policy(policy):
            summary_to_store, classified_to_store = _marketplace_public_discovery(item, classified_outbound, policy)
            records_to_store = classified_to_store
        bounded_marketplace_links = bool(
            _is_marketplace_policy(policy) and classified_to_store
        )
        if ((policy.get("queue_policy") == "expand" or bounded_marketplace_links)
                and policy.get("page_type") != "login_wall"):
            discovery_outcome = _store_discovered_links(
                item, records_to_store, policy, classified_records=classified_to_store,
                preclassified_summary=summary_to_store)
            try:
                import operational_observability as operations
                operations.record_discovery_outcome(
                    worker_id, job_id=int(snapshot["id"]), target=url,
                    counts=discovery_outcome)
            except Exception:
                pass
        preview_eligible = (policy["screenshot_policy"] == "allowed"
                            and 200 <= int(snapshot.get("response_status") or 0) < 400
                            and (snapshot.get("content_type") or "").split(";", 1)[0].strip().lower()
                            in {"text/html", "application/xhtml+xml"})
        if preview_eligible and policy.get("storage_policy") == "safe_summary" and policy.get("review_status") not in {"restricted", "filtered"}:
            storage.create_page_preview_job(url, onion_url_id=url_id, site_card_id=item.get("site_card_id"))
        elif not preview_eligible:
            storage.block_page_preview(url, policy.get("screenshot_blocked_reason") or "category_policy")
        if policy.get("card_ready") or relevant:
            storage.create_site_card_job(onion_url_id=url_id, url=url, site_card_id=item.get("site_card_id"),
                                         priority=policy.get("priority_score") or 0)
        actor_outcome = process_page_actor_intelligence(
            url, visible_text=visible_text, links=links, link_records=link_records,
            policy=policy, page_structure=page_structure)
        useful_expansion_result = bool(
            relevant or indicators or exposures or policy.get("spain_priority")
            or int(actor_outcome.get("actors") or 0) > 0
            or int(actor_outcome.get("candidates") or 0) > 0)
        storage.complete_entity_expansion_for_url(
            url_id,
            "DESTINATION_USEFUL_VERIFIED" if useful_expansion_result
            else "DESTINATION_VERIFIED_NO_YIELD",
            safe_metadata={
                "verified": True, "response_status": snapshot.get("response_status"),
                "content_quality": liveness.get("content_quality"),
                "page_type": policy.get("page_type"), "card_ready": bool(policy.get("card_ready")),
                "relevant": relevant, "indicator_count": len(indicators),
                "exposure_count": len(exposures),
                "actor_count": int(actor_outcome.get("actors") or 0),
            },
            content_hash=content_hash)
        storage.insert_crawl_audit(url, "verify", "completed", policy.get("safety_reason"))
        if not storage.mark_fetched_page_verified(int(snapshot["id"]), worker_id):
            raise storage.WorkerClaimLost(f"verify_claim_lost:{snapshot['id']}")
        try:
            storage.heartbeat_worker_instance(
                worker_id, "verify", "verified", current_url_id=url_id,
                current_job_id=int(snapshot["id"]), processed_increment=1)
        except Exception as exc:
            LOGGER.warning("Verification completed but heartbeat failed safely: %s",
                           type(exc).__name__)
        return True
    except storage.WorkerClaimLost as exc:
        try:
            storage.heartbeat_worker_instance(
                worker_id, "verify", "claim_lost", current_url_id=url_id,
                current_job_id=int(snapshot["id"]), last_error=type(exc).__name__,
                observe=False)
        except Exception:
            pass
        LOGGER.warning("Staged verification claim was lost safely: %s", type(exc).__name__)
        return True
    except Exception as exc:
        storage.mark_fetched_page_error(
            int(snapshot["id"]), f"{type(exc).__name__}: {exc}", worker_id=worker_id)
        storage.heartbeat_worker_instance(worker_id, "verify", "error", current_url_id=url_id,
                                          current_job_id=int(snapshot["id"]), last_error=type(exc).__name__,
                                          processed_increment=1, observe=False)
        LOGGER.warning("Staged verification failed safely: %s", type(exc).__name__)
        return True


def process_card_job(worker_id: str | None = None) -> bool:
    """Stage 3: process one queued Site Card job with per-card exclusion."""
    storage.ensure_db_initialized()
    worker_id = worker_id or f"card:{os.getpid()}"
    storage.heartbeat_worker_instance(worker_id, "card", "checking_queue")
    job = storage.claim_next_site_card_job(worker_id, get_int("ONION_CLAIM_TIMEOUT_MINUTES", 45))
    if not job:
        state = "paused" if storage.worker_claims_paused() else "idle"
        storage.heartbeat_worker_instance(worker_id, "card", state)
        return False
    card_id = None
    url_row = None
    try:
        storage.heartbeat_worker_instance(worker_id, "card", "processing", current_job_id=int(job["id"]),
                                          current_url_id=job.get("onion_url_id"))
        if job.get("onion_url_id"):
            with storage.get_db() as db:
                url_row = db.execute("SELECT * FROM onion_urls WHERE id=?", (int(job["onion_url_id"]),)).fetchone()
            if not url_row:
                storage.finish_site_card_job(
                    int(job["id"]), success=True, site_card_id=None, worker_id=worker_id)
                storage.heartbeat_worker_instance(
                    worker_id, "card", "done", current_job_id=int(job["id"]),
                    current_url_id=job.get("onion_url_id"), processed_increment=1)
                return True
            policy = dict(url_row)
            if is_severe_blackhole_policy(policy):
                storage.enforce_severe_blackhole(str(url_row["url"]), policy)
                storage.finish_site_card_job(
                    int(job["id"]), success=True, site_card_id=None, worker_id=worker_id)
                storage.heartbeat_worker_instance(
                    worker_id, "card", "done", current_job_id=int(job["id"]),
                    current_url_id=job.get("onion_url_id"), processed_increment=1)
                return True
            card_id = site_dedupe.ensure_url_site_card(int(job["onion_url_id"]), policy,
                                                       title=policy.get("title") or job.get("onion_title"),
                                                       source_context=policy.get("source_url") or job.get("url"),
                                                       update_rollup=False)
        elif job.get("site_card_id"):
            card_id = int(job["site_card_id"])
        if not card_id:
            storage.finish_site_card_job(
                int(job["id"]), success=True, site_card_id=None, worker_id=worker_id)
            storage.heartbeat_worker_instance(
                worker_id, "card", "done", current_job_id=int(job["id"]),
                current_url_id=job.get("onion_url_id"), processed_increment=1)
            return True
        if not storage.acquire_site_card_processing(card_id, worker_id,
                                                    get_int("ONION_CLAIM_TIMEOUT_MINUTES", 45)):
            storage.defer_site_card_job(
                int(job["id"]), worker_id, reason="site_card_already_processing",
                delay_seconds=get_int("SITE_CARD_LOCK_RETRY_SECONDS", 30))
            storage.heartbeat_worker_instance(
                worker_id, "card", "retry", current_job_id=int(job["id"]),
                current_url_id=job.get("onion_url_id"),
                last_error="site_card_already_processing", processed_increment=1)
            return True
        try:
            if job.get("job_type") == "enrich_card":
                plan_card_enrichment(card_id, worker_id=worker_id)
            else:
                site_dedupe.update_site_card_rollups(card_id)
                try:
                    from profile_builder import refresh_site_profile
                    if job.get("url"):
                        refresh_site_profile(job["url"])
                except Exception as exc:
                    LOGGER.warning("Site profile refresh skipped in card worker: %s", type(exc).__name__)
            if url_row:
                storage.attach_actor_observations_to_site_card(str(url_row["url"]), card_id)
                with storage.get_db() as db:
                    refreshed = db.execute("SELECT * FROM onion_urls WHERE id=?",
                                           (int(url_row["id"]),)).fetchone()
                if refreshed and refreshed["spain_priority"]:
                    storage.queue_spain_alert(str(refreshed["url"]), dict(refreshed),
                                              refreshed["source_url"])
        finally:
            storage.release_site_card_processing(card_id, worker_id)
        storage.finish_site_card_job(
            int(job["id"]), success=True, site_card_id=card_id, worker_id=worker_id)
        storage.heartbeat_worker_instance(worker_id, "card", "done", current_job_id=int(job["id"]),
                                          current_url_id=job.get("onion_url_id"), processed_increment=1)
        return True
    except Exception as exc:
        if card_id:
            storage.release_site_card_processing(card_id, worker_id)
        storage.finish_site_card_job(int(job["id"]), success=False, error=f"{type(exc).__name__}: {exc}",
                                     site_card_id=card_id, worker_id=worker_id)
        storage.heartbeat_worker_instance(worker_id, "card", "error", current_job_id=int(job["id"]),
                                          current_url_id=job.get("onion_url_id"),
                                          last_error=type(exc).__name__, processed_increment=1,
                                          observe=False)
        LOGGER.warning("Card worker failed safely: %s", type(exc).__name__)
        return True


def _process_one_impl() -> bool:
    storage.init_db()
    storage.update_worker_state("checking_queue", "Looking for the next queued site")
    worker_state = storage.get_worker_state() or {}
    worker_id = str(worker_state.get("boot_id") or f"pid:{os.getpid()}")
    item = storage.claim_next_onion_url(
        storage.utc_now_iso(), worker_id=worker_id,
        exploration=get_bool("ONION_EXPLORATION_MODE", True),
        claim_timeout_minutes=get_int("ONION_CLAIM_TIMEOUT_MINUTES", 45),
    )
    if not item:
        storage.update_worker_state("idle", "Queue is empty")
        return False
    url = item["url"]
    storage.update_worker_state("checking", "Applying safety rules before fetch", url,
                                last_url_id=int(item["id"]))
    try:
        pre_policy = _decide(
            url, source_url=item.get("source_url"), source_context=item.get("source_type"),
            depth=int(item.get("depth") or 0))
        storage.apply_prefetch_policy(url, pre_policy)
        storage.apply_crawl_decision(url, pre_policy)
    except Exception as exc:
        storage.mark_onion_error(
            url, f"{type(exc).__name__}: prefetch_policy_failed", _future(hours=6),
            worker_id=worker_id)
        storage.insert_crawl_audit(url, "prefetch", "error", type(exc).__name__)
        storage.update_worker_state("idle", "A pre-fetch policy check failed safely", url,
                                    type(exc).__name__)
        return True
    if pre_policy.get("defer_requested"):
        storage.defer_frontier_url(url, pre_policy.get("defer_reason") or "deep_pagination_default_defer")
    storage.record_classification_decision(
        url, pre_policy, stage="prefetch", previous_category=item.get("primary_category"),
        safe_metadata={"source": item.get("source_type"), "scope": "url"},
    )
    if (is_severe_blackhole_policy(pre_policy)
            and _independent_prefetch_content_decision(pre_policy)):
        storage.enforce_severe_blackhole(url, pre_policy)
        storage.update_worker_state("idle", "Restricted prior destination decision", url,
                                    "severe_abuse_blackhole")
        return True
    if (pre_policy.get("decision") in {"reject", "restrict", "fetch_later"}
            and not (_adult_filtered(pre_policy)
                     and _independent_prefetch_content_decision(pre_policy))):
        if pre_policy.get("decision") == "restrict":
            site_dedupe.ensure_url_site_card(int(item["id"]), pre_policy, source_context=item.get("source_url"))
        storage.insert_crawl_audit(url, "decide_rule", pre_policy["decision"], pre_policy.get("rule_id"))
        storage.update_worker_state("idle", pre_policy.get("display_safe_reason"), url, pre_policy.get("rule_id"))
        return True
    if (_adult_filtered(pre_policy)
            and _independent_prefetch_content_decision(pre_policy)):
        storage.release_url_claim(url, "blocked", worker_id)
        storage.insert_crawl_audit(url, "url_prefilter", "adult_filtered", "adult_content_filtered")
        storage.update_worker_state("idle", "Filtered adult URL before fetch", url, "adult_content_filtered")
        return True
    if not pre_policy.get("active") or pre_policy.get("queue_policy") == "blocked":
        storage.release_url_claim(url, "blocked", worker_id)
        site_dedupe.ensure_url_site_card(int(item["id"]), pre_policy, source_context=item.get("source_url"))
        storage.queue_spain_alert(url, pre_policy, item.get("source_url"))
        storage.block_page_preview(url, pre_policy.get("safety_reason", "restricted_content"))
        storage.insert_crawl_audit(url, "url_prefilter", "blocked", pre_policy.get("safety_reason"))
        storage.update_worker_state("idle", "URL restricted before fetch", url, pre_policy.get("safety_reason"))
        return True

    allowed, reason = is_fetch_allowed(url, get_bool("ALLOW_CLEARNET_FETCH", False))
    if not allowed:
        blocked = dict(pre_policy, active=0, queue_policy="blocked", storage_policy="metadata_only",
                       review_status="restricted", safety_reason=reason, screenshot_policy="blocked",
                       screenshot_blocked_reason=reason)
        storage.apply_onion_policy(url, blocked)
        storage.release_url_claim(url, "blocked", worker_id)
        storage.insert_crawl_audit(url, "fetch_policy", "blocked", reason)
        storage.update_worker_state("idle", "Blocked by URL safety policy", url, reason)
        return True

    response = None
    session = None
    try:
        if not storage.mark_url_fetching(int(item["id"]), worker_id):
            raise storage.WorkerClaimLost(f"fetch_claim_lost:{item['id']}")
        storage.update_worker_state("fetching", "Checking a queued site", url, last_url_id=int(item["id"]))
        fetch_started = time.monotonic()
        total_fetch_timeout = max(15, get_int("ONION_TOTAL_FETCH_TIMEOUT_SECONDS", 60))
        session = _session()
        with _fetch_heartbeat(url, int(item["id"])):
            response = fetch_onion(url, session=session,
                                   timeout=(get_int("ONION_CONNECT_TIMEOUT_SECONDS", 15),
                                            get_int("ONION_READ_TIMEOUT_SECONDS", 30)))
        storage.update_worker_state("fetch_complete", "Tor response received", url,
                                    last_url_id=int(item["id"]))
        if response.status_code in {404, 410}:
            response.close()
            storage.mark_onion_dead(
                url, response.status_code, f"http_{response.status_code}", worker_id=worker_id)
            site_dedupe.ensure_url_site_card(int(item["id"]), pre_policy, source_context=item.get("source_url"))
            storage.update_worker_state("idle", "Site is gone", url, f"HTTP {response.status_code}")
            return True
        content_type = response.headers.get("Content-Type")
        if not is_content_type_allowed(content_type):
            response.close()
            blocked = dict(pre_policy, active=0, queue_policy="blocked", storage_policy="metadata_only",
                           review_status="restricted", safety_reason="blocked_content_type",
                           screenshot_policy="blocked", screenshot_blocked_reason="blocked_content_type")
            storage.apply_onion_policy(url, blocked, response.status_code, checked=True)
            storage.release_url_claim(url, "blocked", worker_id)
            site_dedupe.ensure_url_site_card(int(item["id"]), blocked, source_context=item.get("source_url"))
            storage.queue_spain_alert(url, blocked, item.get("source_url"))
            storage.insert_crawl_audit(url, "content_type", "blocked", "blocked_content_type")
            storage.update_worker_state("idle", "Blocked a non-HTML/text response", url, "Blocked content type")
            return True

        storage.update_worker_state("parsing", "Reading and parsing bounded response", url,
                                    last_url_id=int(item["id"]))
        body = _read_bounded(response, get_int("ONION_MAX_PAGE_BYTES", 1_000_000),
                             deadline=fetch_started + total_fetch_timeout)
        title, meta_text, visible_text, link_records, page_structure = _parse(body, content_type or "", url)
        headers = _passive_response_headers(response.headers)
        response_status = response.status_code
        response.close()
        storage.update_worker_state("classifying", "Classifying fetched page", url,
                                    last_url_id=int(item["id"]))

        policy = _classify_fetched_page(
            url, title=title, meta=meta_text, visible_text=visible_text,
            source_url=item.get("source_url"), source_context=item.get("source_type"),
            page_structure=page_structure,
        )
        storage.update_worker_state("classified", "Page classification complete", url,
                                    last_url_id=int(item["id"]))
        directory_theme = _mixed_link_directory(title, meta_text, visible_text, link_records)
        structural_type = dict(page_structure.get("page_type_info") or {})
        external_hosts = int(page_structure.get("external_onion_host_count") or 0)
        directory_identity = bool(page_structure.get("directory_markers")
                                  or external_hosts >= 3
                                  or policy.get("primary_category") in {"directory_index", "search_engine"})
        structural_directory = bool(
            (directory_theme and directory_identity)
            or policy.get("page_type") in {"link_repository", "directory_index_page"} or (
                structural_type.get("page_type") in {"link_repository", "directory_index_page"}
                and structural_type.get("page_type_confidence") in {"medium", "high"}
            )
        )
        if (_is_marketplace_policy(policy) and external_hosts < 3
                and not page_structure.get("directory_markers")):
            structural_directory = False
        parent_restricted = (_adult_filtered(policy)
                             or policy.get("primary_category") == "severe_abuse_risk"
                             or policy.get("storage_policy") == "discard")
        if structural_directory and not parent_restricted:
            policy["page_type"] = ("link_repository" if structural_type.get("page_type") == "link_repository"
                                   or len(link_records) >= 5 else "directory_index_page")
            policy["queue_policy"] = "expand"
            policy["active"] = 1
            if policy.get("primary_category") in {"unknown", "general_other"}:
                policy.update(
                    primary_category="directory_index", category="directory_index",
                    content_category="directory_index", category_confidence=(
                        structural_type.get("page_type_confidence") or "medium"),
                    category_reason="Directory or link repository structure detected",
                    category_safe_label="Directory / index", display_group="Discovery",
                    review_status="monitor", safety_reason="page_structure_directory_index",
                    importance_level="normal", importance_reason="source_or_directory_value",
                    ui_hidden_default=0,
                )
        outbound_preview, classified_outbound = classify_outbound_records(item, link_records, policy)
        adult_ratio = (float(outbound_preview.get("adult") or 0) /
                       max(1, int(outbound_preview.get("total") or 0)))
        adult_parent_dominant = bool(
            int(policy.get("signal_count") or 0) >= 1
            and float(policy.get("dominance_score") or 0) >= 0.75
        )
        # Page text is classified before outbound links are scoped. A structural
        # directory with non-dominant adult children must be rescued here so a
        # title/category label cannot blackhole the useful parent index.
        if structural_directory and _adult_filtered(policy) and not adult_parent_dominant:
            original_page_signals = {
                "adult_signal_count": int(policy.get("signal_count") or 0),
                "adult_dominance_score": float(policy.get("dominance_score") or 0),
                "adult_outbound_ratio": adult_ratio,
            }
            policy = _safe_mixed_directory_policy()
            policy.update(
                category_reason="Mixed link repository; restricted child links scoped individually",
                safe_signal_labels=["adult_child_links_scoped_to_directory"],
                false_positive_guard_applied=True,
                parent_evidence=list(page_structure.get("parent_evidence") or [])[:20],
                classification_debug=original_page_signals,
            )
        page_context = " ".join((title or "", meta_text or "", visible_text[:2000])).casefold()
        marketplace_theme = any(term in page_context for term in (
            "marketplace", "market place", "market homepage", "vendor market", "shop market"))
        if marketplace_theme and _adult_filtered(policy):
            policy = _adult_dominant_marketplace_policy()
        elif _is_marketplace_policy(policy) and outbound_preview["adult"]:
            policy["marketplace_type"] = "mixed"
            policy["tags"] = list(dict.fromkeys(policy.get("tags", []) + ["adult_category_present",
                                                                                 "restricted_child_present"]))
            policy["secondary_categories"] = list(dict.fromkeys(
                policy.get("secondary_categories", []) + ["adult_category_present"]))
        directory_navigation = structural_directory or policy.get("page_type") in {
            "directory_index_page", "link_repository"}
        if directory_navigation and policy.get("primary_category") == "unknown":
            policy = _safe_mixed_directory_policy()
            if not outbound_preview["restricted"]:
                policy["tags"] = ["directory_index"]
                policy["safety_reason"] = "directory_index"
                policy["category_reason"] = "Directory or index page structure detected"
                policy["screenshot_policy"] = "allowed"
                policy["screenshot_blocked_reason"] = None
        restricted_children = bool(outbound_preview["restricted"])
        if restricted_children and not _adult_filtered(policy):
            policy["tags"] = list(dict.fromkeys(policy.get("tags", []) + ["restricted_child_present"]
                                                + (["adult_link_present"] if outbound_preview["adult"] else [])))
        policy.update(
            child_adult_link_count=int(outbound_preview.get("adult") or 0),
            child_restricted_link_count=int(outbound_preview.get("restricted") or 0),
            child_blocked_link_count=int(outbound_preview.get("blocked") or 0),
            parent_evidence=list(page_structure.get("parent_evidence") or [])[:20],
            child_link_evidence={
                "adult_or_filtered": int(outbound_preview.get("adult") or 0),
                "severe_or_restricted": int(outbound_preview.get("severe") or 0),
                "file_or_download_blocked": int(outbound_preview.get("file_blocked") or 0),
                "login_cart_contact_blocked": int(outbound_preview.get("transaction_blocked") or 0),
                "safe_external_seeded": int(outbound_preview.get("external_seeded") or 0),
            },
        )
        identity = dict(page_structure.get("identity") or extract_page_identity(url, title=title))
        if (_adult_filtered(policy) or policy.get("primary_category") == "severe_abuse_risk"
                or policy.get("storage_policy") in {"metadata_only", "discard"}):
            identity = extract_page_identity(
                url, restricted=True, safe_category_label=safe_category_label(policy.get("primary_category")))
        page_type_info = fingerprint_page_type(
            url, page_structure, current_type=str(policy.get("page_type") or "unknown"),
            allow_url_hints=False)
        if (page_type_info["page_type_confidence"] in {"medium", "high"}
                or policy.get("page_type") in {None, "", "unknown", "homepage"}):
            policy["page_type"] = page_type_info["page_type"]
        policy.update(
            detected_title=identity.get("detected_title"), title_source=identity.get("title_source"),
            identity_confidence=identity.get("identity_confidence"),
            page_type_confidence=page_type_info.get("page_type_confidence"),
            page_type_evidence=page_type_info.get("evidence", []),
            link_repository_score=int(page_type_info.get("page_type_score") or 0)
                if page_type_info.get("page_type") == "link_repository" else 0,
            outbound_onion_count=int(page_structure.get("onion_link_count") or 0),
            internal_link_count=int(page_structure.get("internal_link_count") or 0),
            external_onion_count=int(page_structure.get("external_onion_count") or 0),
        )
        policy["evidence_families"] = list(dict.fromkeys(
            list(policy.get("evidence_families") or []) + list(page_type_info.get("evidence") or [])))[:20]
        policy = calibrate_classification(policy, stage="page")
        policy = finalize_page_policy(url, policy, title=title, page_structure=page_structure)
        preliminary = assess_content_liveness(response_status, title, visible_text)
        navigation_type = policy.get("page_type") in {
            "link_repository", "directory_index_page", "forum_index", "marketplace_front", "search_results", "mirror_index"}
        preliminary_quality = ("meaningful" if navigation_type and outbound_preview["total"]
                               and preliminary["content_quality"] in {"empty", "thin"}
                               else preliminary["content_quality"])
        policy = apply_classification_contract(
            policy, identity, page_type_info, dict(page_structure, url=url), preliminary_quality,
            previous_category=item.get("primary_category"),
            previous_category_trusted=bool(
                item.get("analyst_category")
                or (
                    item.get("verification_reason") == "page_fetched_and_classified"
                    and int(item.get("destination_html_evidence_version") or 0)
                        >= DESTINATION_HTML_EVIDENCE_VERSION
                    and item.get("classification_evidence_source") == "destination_html"
                )
            ),
        )
        readiness = compute_card_readiness(
            policy, identity, page_type_info, page_structure, preliminary_quality,
            analyst_confirmed=bool(item.get("analyst_category")
                                   or item.get("classification_decision") == "analyst_confirmed"),
        )
        policy.update(readiness)
        storage.apply_onion_policy(
            url, policy, response_status, checked=True, page_structure=page_structure)
        if is_severe_blackhole_policy(policy):
            storage.enforce_severe_blackhole(url, policy)
            storage.update_worker_state("idle", "Restricted page removed", url,
                                        "severe_abuse_blackhole")
            return True
        storage.record_classification_decision(
            url, policy, stage="page", previous_category=item.get("primary_category"),
            safe_metadata=_classification_decision_metadata(
                policy, preliminary_quality),
        )
        if _adult_filtered(policy):
            storage.detach_restricted_url_from_site_card(url)
            storage.insert_crawl_audit(url, "content_policy", "adult_filtered", "adult_content_filtered")
            storage.update_worker_state("idle", "Filtered adult content", url, "adult_content_filtered")
            return True
        if policy["storage_policy"] == "metadata_only":
            storage.set_onion_liveness(url, "success", "live", "restricted", policy.get("page_type"))
            _finish_restricted(item, response_status, policy, page_structure)
            storage.update_worker_state("idle", "Restricted content retained as metadata only", url, policy["safety_reason"])
            return True

        liveness = assess_content_liveness(response_status, title, visible_text)
        marketplace_navigation = (_is_marketplace_policy(policy)
                                  and policy.get("page_type") in {"homepage", "category_index", "directory_index_page", "unknown"})
        # A destination is a forum/navigation page only when its own fetched
        # HTML produced a confirmed category or structural page type. Child
        # routes and their anchor context remain scheduling hints only.
        forum_navigation = (
            policy.get("primary_category") == "forum_social"
            or normalize_page_type(policy.get("page_type")) in {"forum_index", "forum_thread"}
        )
        useful_link_index = (directory_navigation or forum_navigation or marketplace_navigation
                             or policy.get("primary_category") in {"directory_index", "search_engine"})
        if useful_link_index and outbound_preview["total"] and liveness["content_quality"] in {"empty", "thin"}:
            liveness = dict(liveness, liveness_status="live", content_quality="meaningful",
                            reason="link_directory_content")
        storage.set_onion_liveness(url, liveness["fetch_status"], liveness["liveness_status"],
                                   liveness["content_quality"], policy.get("page_type"))
        if liveness["liveness_status"] == "soft_dead":
            storage.mark_onion_soft_dead(url, response_status, liveness["reason"])
            if item.get("site_card_id"):
                site_dedupe.update_site_card_rollups(int(item["site_card_id"]))
            storage.update_worker_state("idle", "Page is unavailable despite an HTTP response", url, liveness["reason"])
            return True
        thin_content = liveness["content_quality"] in {"empty", "thin"}
        strong_review = bool(policy.get("spain_priority") and policy.get("spain_confidence") == "high") or (
            str(policy.get("risk_level") or "low").casefold() in {"high", "critical"}
            and policy.get("category_confidence") in {"medium", "high", "critical"})
        if thin_content and not strong_review:
            policy["review_status"] = "monitor"
            policy["review_score"] = 0
            storage.apply_onion_policy(
                url, policy, response_status, checked=True, page_structure=page_structure)

        policy = apply_classification_contract(
            policy, identity, page_type_info, dict(page_structure, url=url), liveness["content_quality"],
            previous_category=item.get("primary_category"),
            previous_category_trusted=bool(
                item.get("analyst_category")
                or (
                    item.get("verification_reason") == "page_fetched_and_classified"
                    and int(item.get("destination_html_evidence_version") or 0)
                        >= DESTINATION_HTML_EVIDENCE_VERSION
                    and item.get("classification_evidence_source") == "destination_html"
                )
            ),
        )
        readiness = compute_card_readiness(
            policy, identity, page_type_info, page_structure, liveness["content_quality"],
            analyst_confirmed=bool(item.get("analyst_category")
                                   or item.get("classification_decision") == "analyst_confirmed"),
        )
        policy.update(readiness)
        if not readiness["card_ready"] and not strong_review:
            policy["review_status"] = "monitor"
            policy["review_score"] = 0
        storage.apply_onion_policy(
            url, policy, response_status, checked=True, page_structure=page_structure)

        normalized_text = " ".join(visible_text.split())
        content_hash = hashlib.sha256(normalized_text.encode("utf-8", "ignore")).hexdigest()
        fuzzy_hash = hashlib.sha256(f"{title or ''}\n{normalized_text[:2000]}".casefold().encode("utf-8", "ignore")).hexdigest()
        links = [record["url"] for record in link_records]
        limited = policy["storage_policy"] in {"metadata_limited", "metadata_only"}
        safe_limited_identity = bool(
            limited and identity.get("limited_title_safe")
            and normalize_page_type(policy.get("page_type")) in {"homepage", "marketplace_front", "forum_index", "directory_index_page", "link_repository", "search_results", "mirror_index"}
        )
        display_title = (str(identity.get("display_name"))[:180] if safe_limited_identity
                         else safe_category_label(policy["primary_category"]) if limited
                         else make_safe_snippet(identity.get("display_name") or title or "", max_chars=180))
        policy["safe_display_name"] = display_title
        reasons = list(policy.get("tags", []))
        flags = list(dict.fromkeys(policy.get("risk_flags", []) + classify_risk_flags(visible_text, links)))

        if limited:
            indicators = [entry for entry in extract_indicators("", links) if entry.get("type") in LIMITED_INDICATOR_TYPES]
            exposures = extract_passive_exposures(url, response_status, headers, None, "", [])
            snippet = (f"{safe_category_label(policy['primary_category'])}. Content omitted under metadata-limited safety policy."
                       if get_bool("STORE_SAFE_SNIPPETS", True) else "")
            page_topics = {"topics": [safe_category_label(policy["primary_category"])], "keywords": []}
        else:
            indicators = extract_indicators(visible_text, links)
            exposures = extract_passive_exposures(url, response_status, headers, title, visible_text, links)
            snippet = (make_safe_snippet(visible_text, reasons,
                       max(50, min(get_int("MAX_SAFE_SNIPPET_CHARS", 500), 500)))
                       if get_bool("STORE_SAFE_SNIPPETS", True) else "")
            page_topics = extract_page_topics(visible_text)
        storage.elevate_review_for_indicators(url, indicators)
        storage.upsert_page_topics(url, page_topics["topics"], page_topics["keywords"])

        for indicator in indicators:
            iid = storage.upsert_indicator(
                indicator["type"], indicator["value"], indicator["normalized_value"],
                "onion_page", url, float(indicator["confidence"]), flags,
            )
            storage.link_indicator(iid, "onion_page", url, indicator.get("context"))
        storage.insert_passive_exposures(url, exposures)

        classified_for_results = bool(policy.get("card_ready"))
        relevant = bool(classified_for_results and (
            (not thin_content and policy["primary_category"] != "unknown")
            or policy.get("spain_priority") or indicators or exposures
        ))
        _expand_relevant_forum_thread(url, policy)
        if relevant and storage.is_onion_url_verified(url):
            hit_id = storage.insert_onion_hit(
                url, display_title, policy["priority_score"], policy["risk_level"], reasons,
                snippet, indicators, item.get("source_url"), exposures,
            )
            storage.insert_alert_from_onion_hit(hit_id)

        cluster_text = visible_text if not limited else safe_category_label(policy["primary_category"])
        cluster_id = update_mirror_clusters(
            url, display_title, cluster_text, content_hash, fuzzy_hash, indicators, "onion_page"
        )
        if cluster_id:
            build_attribution_profile(cluster_id)

        next_crawl = _next_crawl_for_policy(policy, relevant)
        storage.record_page_change(url, content_hash, policy.get("primary_category"))
        storage.mark_onion_crawled(
            url, response_status, display_title, content_hash, fuzzy_hash,
            policy["priority_score"], policy["priority_score"], policy["risk_level"],
            reasons, flags, "crawled", next_crawl,
        )
        storage.apply_onion_policy(
            url, policy, response_status, checked=True, page_structure=page_structure)
        storage.elevate_review_for_indicators(url, indicators)
        if classified_for_results:
            site_dedupe.ensure_url_site_card(
                int(item["id"]), policy, title=display_title,
                visible_text=None if limited else visible_text, indicators=indicators,
                source_context=item.get("source_url"),
            )
            storage.queue_spain_alert(url, policy, item.get("source_url"))
            process_page_actor_intelligence(
                url, visible_text=visible_text, links=links, link_records=link_records,
                policy=policy, page_structure=page_structure)
        records_to_store = link_records
        classified_to_store = classified_outbound
        summary_to_store = outbound_preview
        if _is_marketplace_policy(policy):
            summary_to_store, classified_to_store = _marketplace_public_discovery(
                item, classified_outbound, policy)
            records_to_store = classified_to_store
        bounded_marketplace_links = bool(
            _is_marketplace_policy(policy) and classified_to_store
        )
        if ((useful_link_index or not thin_content or bounded_marketplace_links)
                and policy.get("page_type") != "login_wall"
                and (not _is_marketplace_policy(policy) or bool(classified_to_store))):
            storage.update_worker_state("storing_links", "Storing bounded discovered-link batch", url,
                                        last_url_id=int(item["id"]))
            _store_discovered_links(item, records_to_store, policy, classified_records=classified_to_store,
                                    preclassified_summary=summary_to_store)
        preview_eligible = (policy["screenshot_policy"] == "allowed" and 200 <= response_status < 400
                            and (content_type or "").split(";", 1)[0].strip().lower() in {
                                "text/html", "application/xhtml+xml"})
        if preview_eligible and get_bool("ENABLE_PAGE_SCREENSHOTS", False):
            preview_path = capture_page_screenshot(url)
            if preview_path:
                try:
                    from image_ocr import extract_text
                    ocr_result = extract_text(preview_path)
                    ocr_policy = classify_preview_ocr_text(ocr_result.get("text") or "")
                except Exception:
                    ocr_policy = dict(policy, ocr_checked=False)
                ocr_restricted = (ocr_policy.get("primary_category") in {
                    "adult_filtered", "adult_restricted", "severe_abuse_risk", "marketplace_fraud"}
                    or ocr_policy.get("storage_policy") in {"metadata_only", "metadata_limited"})
                if ocr_restricted:
                    ocr_policy["ocr_deleted_due_to_policy"] = True
                    ocr_policy["screenshot_policy"] = "blocked"
                    try:
                        from pathlib import Path
                        Path(preview_path).unlink(missing_ok=True)
                    except (OSError, ValueError):
                        pass
                    storage.block_page_preview(
                        url, ocr_policy.get("safety_reason") or "ocr_preview_safety_only")
                else:
                    storage.upsert_page_preview(url, preview_path)
        elif not preview_eligible:
            storage.block_page_preview(url, policy.get("screenshot_blocked_reason") or "category_policy")

        if classified_for_results:
            try:
                from profile_builder import refresh_site_profile
                refresh_site_profile(url)
            except Exception as exc:
                LOGGER.warning("Site profile refresh skipped: %s", type(exc).__name__)
        storage.insert_crawl_audit(url, "fetch", "completed", policy.get("safety_reason"))
        storage.update_worker_state("idle", "Finished checking a site", url, safe_category_label(policy["primary_category"]))
        return True
    except Exception as exc:
        error_count = int(item.get("error_count") or 0) + 1
        dead = error_count >= 4
        storage.mark_onion_error(
            url, type(exc).__name__,
            None if dead else (_future(days=3) if error_count >= 3 else _future(hours=6)),
            dead=dead, worker_id=worker_id,
        )
        if dead:
            site_dedupe.ensure_url_site_card(int(item["id"]), pre_policy, source_context=item.get("source_url"))
        storage.insert_crawl_audit(url, "fetch", "error", type(exc).__name__)
        LOGGER.warning("Passive fetch failed for queued URL: %s", type(exc).__name__)
        storage.update_worker_state("idle", "A site check failed safely", url, type(exc).__name__)
        return True
    finally:
        response_close = getattr(response, "close", None)
        if callable(response_close):
            response_close()
        session_close = getattr(session, "close", None)
        if callable(session_close):
            session_close()


def process_one() -> bool:
    """Process at most one URL and update durable service counters."""
    processed = _process_one_impl()
    if processed:
        worker = storage.get_worker_state() or {}
        storage.record_worker_processed(worker.get("last_url_id"))
        if worker.get("last_url"):
            storage.refresh_crawl_coverage(worker["last_url"])
    return processed


def run_maintenance() -> dict:
    """Run small SQL/bounded batches; full cleanup and rebuilds are explicit CLI jobs."""
    task = "automatic_housekeeping"
    leader_id = f"maintenance:{os.getpid()}"
    if not storage.acquire_maintenance_leader(task, leader_id,
                                              lease_seconds=max(1800, get_int("ONION_MAINTENANCE_LEASE_SECONDS", 3600))):
        return {"skipped": 1, "reason": "maintenance_leader_active"}
    if not storage.maintenance_allowed(task):
        storage.release_maintenance_leader(task, leader_id)
        return {"skipped": 1, "reason": "maintenance_backoff"}
    started = time.monotonic()
    rss_before = storage.current_rss_mb()
    storage.record_maintenance_start(task, rss_before)
    try:
        import operational_observability as operations
        operations.worker_startup("maintenance", leader_id)
    except Exception:
        operations = None
    try:
        dead = storage.automatic_dead_cleanup()
        stale = storage.compact_stale_queue_state()
        cards = site_dedupe.refresh_site_card_stats(safety_batch=0, missing_limit=50, dirty_limit=100)
        from backup_service import create_daily_backup
        from daily_activity import snapshot_previous_day
        backup = create_daily_backup(keep_days=7)
        digest = snapshot_previous_day()
        storage.mark_worker_maintenance()
        storage.record_maintenance_result(task, success=True,
                                          duration_seconds=time.monotonic() - started)
        result = {"dead_cleaned": dead, "stale_compacted": stale,
                  "site_cards_refreshed": cards.get("refreshed", 0),
                  "site_cards_assigned": cards.get("assigned", 0),
                  "daily_backup_created": int(backup.get("created") or 0),
                  "digest_date": digest.get("date"),
                  "rss_before_mb": rss_before, "rss_after_mb": storage.current_rss_mb()}
        if operations is not None:
            try:
                operations.emit_event(
                    worker_type="maintenance", worker_id=leader_id,
                    event_code="maintenance", outcome_code="maintenance_complete",
                    reason_code="maintenance_complete",
                    latency_ms=(time.monotonic() - started) * 1000)
                operations.write_daily_summary()
                operations.maintain_logs()
            except Exception:
                pass
        return result
    except Exception as exc:
        storage.record_maintenance_result(task, success=False,
                                          duration_seconds=time.monotonic() - started,
                                          error=exc, backoff_hours=6)
        if operations is not None:
            try:
                operations.emit_event(
                    worker_type="maintenance", worker_id=leader_id,
                    event_code="maintenance", outcome_code="maintenance_failed",
                    reason_code="maintenance_failed",
                    latency_ms=(time.monotonic() - started) * 1000)
            except Exception:
                pass
        raise
    finally:
        try:
            storage.release_maintenance_leader(task, leader_id)
        finally:
            if operations is not None:
                try:
                    operations.worker_shutdown("maintenance", leader_id)
                except Exception:
                    pass


def _request_stop(_signum=None, _frame=None) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True


def _interruptible_sleep(seconds: int, sleep_fn=time.sleep) -> None:
    remaining = max(0, int(seconds))
    while remaining and not STOP_REQUESTED:
        step = min(1, remaining)
        sleep_fn(step)
        remaining -= step


def run_loop(max_iterations: int | None = None, sleep_fn=time.sleep) -> None:
    """Run continuously; URL failures are isolated and pause state is durable."""
    global STOP_REQUESTED
    STOP_REQUESTED = False
    storage.init_db()
    storage.start_worker()
    delay = max(1, get_int("ONION_CRAWL_DELAY_SECONDS", 10))
    empty_delay = max(1, get_int("ONION_EMPTY_QUEUE_DELAY_SECONDS", 30))
    maintenance_interval = max(3600, get_int("ONION_MAINTENANCE_INTERVAL_SECONDS", 21600))
    last_maintenance = time.monotonic()
    iterations = 0
    while not STOP_REQUESTED and (max_iterations is None or iterations < max_iterations):
        iterations += 1
        worker = storage.get_worker_state() or {}
        if worker.get("is_paused"):
            storage.update_worker_state("paused", "Crawling is paused; heartbeat is still healthy",
                                        progress=False)
            _interruptible_sleep(empty_delay, sleep_fn)
            continue
        now = time.monotonic()
        if now - last_maintenance >= maintenance_interval:
            try:
                storage.update_worker_state("maintenance", "Running automatic queue maintenance")
                run_maintenance()
            except Exception as exc:
                LOGGER.warning("Maintenance failed safely task=automatic_housekeeping error=%s duration=%.2fs rss_mb=%.1f",
                               type(exc).__name__, time.monotonic() - now, storage.current_rss_mb())
                storage.update_worker_state("idle", "Maintenance failed safely", message=type(exc).__name__,
                                            last_error=f"maintenance:{type(exc).__name__}")
            last_maintenance = now
        try:
            processed = process_one()
        except Exception as exc:
            LOGGER.warning("Worker iteration failed safely: %s", type(exc).__name__)
            storage.update_worker_state("idle", "Worker iteration failed safely", message=type(exc).__name__,
                                        last_error=f"iteration:{type(exc).__name__}")
            processed = False
        storage.update_worker_state("sleeping", "Waiting before the next queue check", progress=False)
        _interruptible_sleep(delay if processed else empty_delay, sleep_fn)
    storage.update_worker_state("stopped", "Worker stopped cleanly")


def add_seed(raw_url: str) -> int:
    storage.init_db()
    normalized = normalize_url(raw_url)
    if not normalized or not is_onion_url(normalized):
        raise ValueError("Seed must be a valid 56-character v3 .onion HTTP(S) URL")
    allowed, reason = is_fetch_allowed(normalized, False)
    if not allowed:
        raise ValueError(f"Seed rejected: {reason}")
    policy = _decide(normalized, source_context="manual_seed", depth=0)
    status = ("deferred_deep_pagination" if policy.get("defer_requested") else
              "queued" if policy.get("decision") in {"accept", "monitor"} else "blocked")
    seed_id = storage.insert_or_update_onion_url(
        normalized, urlsplit(normalized).hostname, source_type="manual_seed", depth=0,
        status=status, policy=policy,
    )
    storage.apply_crawl_decision(normalized, policy)
    if policy.get("defer_requested"):
        storage.defer_frontier_url(normalized, policy.get("defer_reason") or "deep_pagination_default_defer")
    if (_adult_filtered(policy)
            and _independent_prefetch_content_decision(policy)):
        storage.insert_crawl_audit(normalized, "manual_seed", "adult_filtered", "adult_content_filtered")
        return seed_id
    if (is_severe_blackhole_policy(policy)
            and _independent_prefetch_content_decision(policy)):
        storage.enforce_severe_blackhole(normalized, policy)
        return seed_id
    if policy.get("decision") == "restrict" or policy.get("storage_policy") == "metadata_only":
        site_dedupe.ensure_url_site_card(seed_id, policy, source_context="manual_seed")
    if policy.get("active"):
        storage.queue_existing_onion_url(normalized)
    storage.insert_crawl_audit(normalized, "manual_seed", status, policy.get("safety_reason"))
    return seed_id


def status_counts() -> dict[str, int]:
    storage.init_db()
    with storage.get_db() as db:
        counts = {name: db.execute("SELECT COUNT(*) FROM onion_urls WHERE status=?", (name,)).fetchone()[0]
                  for name in ("queued", "crawled", "blocked", "dead")}
        counts["restricted"] = db.execute("SELECT COUNT(*) FROM onion_urls WHERE storage_policy='metadata_only'").fetchone()[0]
        counts["adult_filtered"] = db.execute("SELECT COUNT(*) FROM onion_urls WHERE primary_category='adult_filtered'").fetchone()[0]
        counts["soft_dead"] = db.execute("SELECT COUNT(*) FROM onion_urls WHERE liveness_status='soft_dead'").fetchone()[0]
        counts["monitor"] = db.execute("SELECT COUNT(*) FROM onion_urls WHERE review_status='monitor'").fetchone()[0]
        counts["spain_unreviewed"] = db.execute("SELECT COUNT(*) FROM onion_urls WHERE spain_priority=1 AND spain_review_status='unreviewed'").fetchone()[0]
        counts["hits"] = db.execute("SELECT COUNT(*) FROM onion_hits").fetchone()[0]
        counts["clusters"] = db.execute("SELECT COUNT(*) FROM mirror_clusters").fetchone()[0]
        counts["site_cards"] = db.execute("SELECT COUNT(*) FROM site_cards").fetchone()[0]
        worker = storage.get_worker_state() or {}
        counts["processed_today"] = int(worker.get("processed_today") or 0)
        counts["processed_total"] = int(worker.get("processed_total") or 0)
        return counts


def repair_adult_false_positives(dry_run: bool = False) -> dict:
    """Re-evaluate legacy adult rows from destination HTML, never URL shape."""
    with storage.get_db() as db:
        rows = [dict(row) for row in db.execute("""SELECT ou.*,afm.id AS memory_id,
          fp.id AS fetched_page_id,fp.title AS fetched_title,fp.visible_text AS fetched_visible_text,
          fp.page_structure_json AS fetched_page_structure_json,
          fp.classification_status AS fetched_classification_status
          FROM onion_urls ou
          LEFT JOIN adult_filter_memory afm ON afm.onion_url_id=ou.id
          LEFT JOIN fetched_pages fp ON fp.onion_url_id=ou.id
          WHERE ou.primary_category IN ('adult_filtered','adult_restricted')""")]
    result = {"examined": len(rows), "restored": 0, "kept_restricted": 0, "dry_run": int(dry_run)}
    for row in rows:
        # A prior exact analyst/page-verified memory decision has destination
        # provenance and remains authoritative.  Legacy host/path-only rows do
        # not: they must be fetched and classified again.
        if storage.get_adult_memory_decision(row["url"]) == "blocked":
            result["kept_restricted"] += 1
            continue
        try:
            page_structure = json.loads(row.get("fetched_page_structure_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            page_structure = {}
        current_snapshot = bool(
            row.get("fetched_classification_status") == "done"
            and has_current_destination_html_evidence(page_structure)
        )
        title_source = str((page_structure.get("identity") or {}).get("title_source") or "")
        fetched_title = (row.get("fetched_title") if current_snapshot and title_source in {
            "html_title", "og_title", "twitter_title", "page_h1",
        } else None)
        if current_snapshot:
            candidate = classify(
                row["url"], title=fetched_title,
                visible_text=row.get("fetched_visible_text") or "",
                page_structure=page_structure,
            )
            candidate = finalize_page_policy(
                row["url"], candidate, title=fetched_title, page_structure=page_structure)
        else:
            candidate = classify_url_prefetch(row["url"])
        if candidate.get("primary_category") in {
                "adult_filtered", "adult_restricted", "severe_abuse_risk"}:
            result["kept_restricted"] += 1
            continue
        result["restored"] += 1
        if dry_run: continue
        candidate.update(
            false_positive_guard_applied=True,
            safe_signal_labels=["legacy_url_only_adult_label_removed"],
            active=1,
            queue_policy=(candidate.get("queue_policy") or "normal"),
            status="crawled" if current_snapshot else "queued",
        )
        with storage.get_db() as db:
            db.execute("""UPDATE onion_urls SET status=?,active=1,next_crawl_at=?,dedupe_status='unassigned'
              WHERE id=?""", (candidate["status"], storage.utc_now_iso(), row["id"]))
            if row.get("memory_id"):
                db.execute("""UPDATE adult_filter_memory SET analyst_decision='unverified',
                  false_positive_guard_applied=1,safe_rule_id='legacy_url_only_adult_label_removed',
                  reviewed_at=NULL WHERE id=?""", (row["memory_id"],))
        storage.apply_onion_policy(
            row["url"], candidate, checked=current_snapshot,
            page_structure=page_structure if current_snapshot else None)
        if current_snapshot and candidate.get("primary_category") != "unknown":
            site_dedupe.ensure_url_site_card(
                int(row["id"]), candidate, source_context="adult_false_positive_repair")
    return result


def repair_fraud_marketplace_classification(dry_run: bool = False) -> dict:
    safe_markers = ("payment_card_fraud_signal", "carding_marketplace_signal", "cloned_cards",
                    "payment_card_fraud", "digital_cc", "fullz_signal")
    with storage.get_db() as db:
        rows = [dict(row) for row in db.execute("""SELECT ou.*,
          fp.title AS fetched_title,fp.visible_text AS fetched_visible_text,
          fp.page_structure_json AS fetched_page_structure_json,
          fp.classification_status AS fetched_classification_status
          FROM onion_urls ou LEFT JOIN fetched_pages fp ON fp.onion_url_id=ou.id WHERE
          (ou.primary_category='unknown' OR lower(COALESCE(ou.risk_level,'low')) IN ('low','nulo'))""")]
    candidates = [row for row in rows if any(marker in " ".join(str(row.get(key) or "")
                  for key in ("tags", "risk_flags", "safe_signal_labels", "category_reason"))
                  for marker in safe_markers)]
    confirmed: list[tuple[dict, dict]] = []
    for row in candidates:
        try:
            structure = json.loads(row.get("fetched_page_structure_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            structure = {}
        if (row.get("fetched_classification_status") != "done"
                or not has_current_destination_html_evidence(structure)):
            continue
        title_source = str((structure.get("identity") or {}).get("title_source") or "")
        fetched_title = row.get("fetched_title") if title_source in {
            "html_title", "og_title", "twitter_title", "page_h1",
        } else None
        policy = classify(
            row["url"], title=fetched_title,
            visible_text=row.get("fetched_visible_text") or "",
            page_structure=structure,
        )
        policy = finalize_page_policy(
            row["url"], policy, title=fetched_title, page_structure=structure)
        if policy.get("primary_category") in {"marketplace_fraud", "fraud_financial"}:
            confirmed.append((row, policy, structure))
    result = {"examined": len(rows), "candidates": len(candidates),
              "updated": len(confirmed), "dry_run": int(dry_run)}
    if dry_run:
        return result
    for row, policy, structure in confirmed:
        storage.apply_onion_policy(
            row["url"], policy, checked=True, page_structure=structure)
        if row.get("site_card_id"):
            with storage.get_db() as db:
                db.execute("UPDATE site_cards SET rollup_dirty=1 WHERE id=?", (row["site_card_id"],))
    site_dedupe.refresh_dirty_site_cards()
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Passive Tor/onion OSINT worker")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--once", action="store_true")
    group.add_argument("--loop", action="store_true")
    group.add_argument("--add-seed")
    group.add_argument("--status", action="store_true")
    group.add_argument("--pause", action="store_true")
    group.add_argument("--resume", action="store_true")
    group.add_argument("--cleanup-dead", action="store_true")
    group.add_argument("--maintenance-once", action="store_true")
    group.add_argument("--rebuild-site-cards", action="store_true")
    group.add_argument("--refresh-dirty-site-cards", action="store_true")
    group.add_argument("--repair-spain-from-alert-queue", action="store_true")
    group.add_argument("--repair-adult-false-positives", action="store_true")
    group.add_argument("--repair-fraud-marketplace-classification", action="store_true")
    group.add_argument("--audit-consistency", action="store_true")
    group.add_argument("--repair-consistency", action="store_true")
    group.add_argument("--repair-link-list-frontier", action="store_true")
    group.add_argument("--repair-spain-priority", action="store_true")
    group.add_argument("--repair-site-cards", action="store_true")
    group.add_argument("--opsec-audit", action="store_true")
    group.add_argument("--purge-runtime-artifacts", action="store_true")
    group.add_argument("--worker-failures-summary", action="store_true")
    group.add_argument("--requeue-failed-verifications", action="store_true")
    group.add_argument("--requeue-failed-card-jobs", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json-output", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    # Auditing and artifact cleanup must not create a fresh crawler database
    # before they inspect or clean a source-only deployment.  Keeping these
    # paths ahead of init_db also makes their result truthful on first install.
    if args.opsec_audit:
        from opsec_preflight import format_opsec_audit, run_opsec_audit
        result = run_opsec_audit(persist=True)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True) if args.json_output
              else format_opsec_audit(result))
        if result.get("status") != "PASS":
            raise SystemExit(2)
        return
    if args.purge_runtime_artifacts:
        from artifact_hygiene import purge_runtime_artifacts
        print(json.dumps(purge_runtime_artifacts(dry_run=args.dry_run), ensure_ascii=True,
                         sort_keys=True))
        return
    storage.init_db()
    if args.status:
        values = status_counts()
        worker = storage.get_worker_state() or {}
        values.update(worker_state=worker.get("state", "never_started"),
                      paused=int(bool(worker.get("is_paused"))),
                      always_on=int(get_bool("ONION_ALWAYS_ON", False)),
                      exploration=int(get_bool("ONION_EXPLORATION_MODE", True)),
                      heartbeat=worker.get("last_heartbeat_at") or worker.get("last_heartbeat") or "never")
        print(" ".join(f"{key}={value}" for key, value in values.items()))
    elif args.add_seed:
        try:
            print(f"Seed accepted (id={add_seed(args.add_seed)}).")
        except ValueError as exc:
            raise SystemExit(str(exc)) from None
    elif args.once:
        from opsec_preflight import enforce_strict_mode
        enforce_strict_mode()
        print("processed=1" if process_one() else "processed=0 queue_empty=true")
    elif args.pause:
        storage.set_worker_paused(True); print("paused=true")
    elif args.resume:
        storage.set_worker_paused(False); print("paused=false")
    elif args.cleanup_dead:
        print(f"dead_cleaned={storage.automatic_dead_cleanup()}")
    elif args.maintenance_once:
        print(json.dumps(run_maintenance(), ensure_ascii=True, sort_keys=True))
    elif args.rebuild_site_cards:
        result = site_dedupe.backfill_existing_urls()
        print(" ".join(f"{key}={value}" for key, value in result.items()))
    elif args.refresh_dirty_site_cards:
        result = site_dedupe.refresh_dirty_site_cards()
        print(" ".join(f"{key}={value}" for key, value in result.items()))
    elif args.repair_spain_from_alert_queue:
        result = storage.repair_spain_from_alert_queue(args.dry_run)
        print(" ".join(f"{key}={value}" for key, value in result.items()))
    elif args.repair_adult_false_positives:
        result = repair_adult_false_positives(args.dry_run)
        print(" ".join(f"{key}={value}" for key, value in result.items()))
    elif args.repair_fraud_marketplace_classification:
        result = repair_fraud_marketplace_classification(args.dry_run)
        print(" ".join(f"{key}={value}" for key, value in result.items()))
    elif args.audit_consistency:
        from consistency import audit_consistency
        print(json.dumps(audit_consistency(), ensure_ascii=True, sort_keys=True))
    elif args.repair_consistency:
        from consistency import repair_consistency
        print(json.dumps(repair_consistency(args.dry_run), ensure_ascii=True, sort_keys=True))
    elif args.repair_link_list_frontier:
        from consistency import repair_link_list_frontier
        print(json.dumps(repair_link_list_frontier(args.dry_run), ensure_ascii=True, sort_keys=True))
    elif args.repair_spain_priority:
        result = storage.repair_spain_from_alert_queue(args.dry_run)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    elif args.repair_site_cards:
        from consistency import repair_site_cards
        print(json.dumps(repair_site_cards(args.dry_run), ensure_ascii=True, sort_keys=True))
    elif args.worker_failures_summary:
        print(json.dumps(storage.worker_failures_summary(), ensure_ascii=True, sort_keys=True))
    elif args.requeue_failed_verifications:
        print(json.dumps(storage.requeue_failed_verifications(dry_run=args.dry_run), ensure_ascii=True, sort_keys=True))
    elif args.requeue_failed_card_jobs:
        print(json.dumps(storage.requeue_failed_card_jobs(dry_run=args.dry_run), ensure_ascii=True, sort_keys=True))
    elif args.loop:
        if not get_bool("ONION_CRAWLER_ENABLED", False):
            raise SystemExit("Crawler loop disabled. Set ONION_CRAWLER_ENABLED=true to run it.")
        if not get_bool("ONION_ALWAYS_ON", False):
            LOGGER.warning("ONION_ALWAYS_ON is false; explicit --loop still runs until stopped")
        from opsec_preflight import enforce_strict_mode
        enforce_strict_mode()
        if get_bool("OPSEC_PURGE_ON_START", False):
            from artifact_hygiene import purge_runtime_artifacts
            purge_runtime_artifacts(dry_run=False)
        signal.signal(signal.SIGTERM, _request_stop)
        signal.signal(signal.SIGINT, _request_stop)
        run_loop()


if __name__ == "__main__":
    main()
