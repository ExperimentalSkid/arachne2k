"""Canonical, metadata-safe classification vocabulary and calibration helpers.

This module has no crawler or transport behavior.  It only normalizes already
collected passive facts and explains whether they are suitable for Site Card
rollup.
"""
from __future__ import annotations


DESTINATION_HTML_EVIDENCE_VERSION = 1


def destination_html_evidence_version(page_structure: dict | None) -> int:
    """Return trusted parser provenance for destination-owned HTML evidence.

    Older snapshots may contain outbound anchor labels in ``visible_text``.  A
    numeric version by itself is therefore insufficient: the parser must also
    attest that outbound anchor text was removed from the page-classification
    boundary.
    """
    structure = page_structure if isinstance(page_structure, dict) else {}
    boundary = structure.get("content_boundary")
    if not isinstance(boundary, dict):
        return 0
    try:
        version = int(boundary.get("version") or 0)
    except (TypeError, ValueError):
        return 0
    if version < DESTINATION_HTML_EVIDENCE_VERSION:
        return 0
    if boundary.get("outbound_anchor_text_removed") is not True:
        return 0
    return version


def has_current_destination_html_evidence(page_structure: dict | None) -> bool:
    return destination_html_evidence_version(page_structure) >= DESTINATION_HTML_EVIDENCE_VERSION



CONTENT_CATEGORIES = frozenset({
    "unknown", "general_other", "directory_index", "search_engine", "forum_social",
    "hosting_services", "contact_infrastructure", "infosec_research",
    "privacy_anonymity", "news_media", "religion_spirituality", "education_reference",
    "technology_software", "finance_cryptocurrency", "activism_civil_society",
    "personal_blog", "communication_services", "file_storage_sharing", "arts_culture",
    "health_wellness", "marketplace", "marketplace_drugs", "marketplace_weapons",
    "marketplace_fraud", "marketplace_credentials", "marketplace_leaks",
    "marketplace_counterfeit", "marketplace_services", "weapons_arms", "drugs",
    "leaks_data", "credentials", "malware_hacking", "fraud_financial",
    "extremist_recruitment", "adult_filtered", "adult_restricted",
    "severe_abuse_risk", "spam_noise", "dead_softdead",
})

CONTENT_CATEGORY_LABELS = {
    "adult_filtered": "Filtered adult content",
    "adult_restricted": "Adult / pornographic content — restricted",
    "severe_abuse_risk": "Restricted content — metadata only",
    "weapons_arms": "Weapons / arms context",
    "drugs": "Drugs context",
    "leaks_data": "Leaks / exposed data",
    "credentials": "Credentials",
    "malware_hacking": "Malware / hacking",
    "extremist_recruitment": "Extremist / recruitment",
    "fraud_financial": "Financial fraud",
    "marketplace": "Marketplace context",
    "forum_social": "Forum / social",
    "directory_index": "Directory / index",
    "hosting_services": "Hosting / services",
    "contact_infrastructure": "Contact / infrastructure",
    # Compatibility presentation label; Spain Priority is a separate signal,
    # never a canonical content category.
    "spain_priority": "Spain priority",
    "search_engine": "Search engine",
    "marketplace_drugs": "Marketplace: Drugs",
    "marketplace_weapons": "Marketplace: Weapons",
    "marketplace_fraud": "Marketplace: Fraud",
    "marketplace_credentials": "Marketplace: Credentials",
    "marketplace_leaks": "Marketplace: Leaks",
    "marketplace_counterfeit": "Marketplace: Counterfeit",
    "marketplace_services": "Marketplace: Services",
    "spam_noise": "Spam / noise",
    "infosec_research": "Information security / research",
    "privacy_anonymity": "Privacy / anonymity",
    "news_media": "News / journalism",
    "religion_spirituality": "Religion / spirituality",
    "education_reference": "Education / reference",
    "technology_software": "Technology / software",
    "finance_cryptocurrency": "Finance / cryptocurrency",
    "activism_civil_society": "Activism / civil society",
    "personal_blog": "Personal blog / writing",
    "communication_services": "Email / messaging",
    "file_storage_sharing": "File sharing / storage",
    "arts_culture": "Arts / culture",
    "health_wellness": "Health / wellbeing",
    "dead_softdead": "Dead / unavailable",
    "general_other": "General / other",
    "unknown": "Needs classification",
}

PAGE_TYPES = frozenset({
    "unknown", "homepage", "directory_index_page", "link_repository", "forum_index",
    "forum_thread", "marketplace_front", "marketplace_listing", "vendor_profile",
    "category_index", "login_wall", "contact_support", "cart_checkout", "wiki_docs",
    "code_repository", "paste_text", "mirror_index", "search_results", "article_page",
    "empty_placeholder", "error_page", "download_file",
})

SAFETY_STATES = frozenset({"safe", "metadata_limited", "metadata_only", "filtered", "discarded"})

SITE_TYPES = frozenset({
    "forum", "marketplace", "directory", "link_list", "market_review",
    "paste", "blog", "login_portal", "unknown",
})

CARD_READINESS_REASONS = frozenset({
    "analyst_confirmed", "policy_discard", "restricted_metadata_only",
    "interaction_flow_not_reviewable", "empty_error_or_placeholder",
    "high_confidence_spain_evidence", "meaningful_structural_page",
    "classified_meaningful_page", "insufficient_page_evidence", "legacy_unknown",
})

EVIDENCE_BUCKETS = (
    "title", "heading", "url", "body_safe_snippet", "link_pattern",
    "form_checkout_login", "negative_contradicting",
)

CONTENT_CATEGORY_ALIASES = {
    "forum": "forum_social", "forum_home": "forum_social", "forum_index": "forum_social",
    "directory": "directory_index", "directory_page": "directory_index",
    "link_repository": "directory_index", "market": "marketplace",
    "marketplace_home": "marketplace", "marketplace_front": "marketplace",
    "adult_extreme_caution": "adult_filtered", "porn": "adult_filtered",
    "login_gate": "unknown", "login_wall": "unknown", "error_page": "unknown",
    "parked_page": "unknown", "empty_placeholder": "unknown", "thin": "unknown",
}

PAGE_TYPE_ALIASES = {
    "directory_page": "directory_index_page", "directory_index": "directory_index_page",
    "forum_home": "forum_index", "forum_index": "forum_index",
    "thread_page": "forum_thread", "post_page": "forum_thread", "forum_thread": "forum_thread",
    "marketplace_home": "marketplace_front", "marketplace_front": "marketplace_front",
    "listing_page": "marketplace_listing", "product_page": "marketplace_listing",
    "marketplace_listing_index": "marketplace_listing",
    "vendor_page": "vendor_profile", "profile_page": "vendor_profile",
    "vendor_profile_like": "vendor_profile", "login_gate": "login_wall",
    "contact_page": "contact_support", "mail_page": "contact_support",
    "cart_page": "cart_checkout", "checkout_page": "cart_checkout",
    "transaction_page": "cart_checkout", "paste_page": "paste_text",
    "search_page": "search_results", "parked_page": "empty_placeholder",
    "empty_page": "empty_placeholder", "download_page": "download_file",
    "category_page": "category_index",
}

READINESS_REASON_ALIASES = {
    "not_ready": "insufficient_page_evidence", "unknown": "legacy_unknown",
    "error_or_placeholder": "empty_error_or_placeholder",
    "restricted": "restricted_metadata_only",
}

STATE_PAGE_TYPES = frozenset({
    "login_wall", "contact_support", "cart_checkout", "empty_placeholder",
    "error_page", "download_file",
})
CHILD_PAGE_TYPES = frozenset({"forum_thread", "marketplace_listing", "vendor_profile", "category_index"})
LANDING_PAGE_TYPES = frozenset({
    "homepage", "directory_index_page", "link_repository", "forum_index",
    "marketplace_front", "wiki_docs", "code_repository", "mirror_index", "search_results",
})

MARKETPLACE_CONTENT_CATEGORIES = frozenset(
    category for category in CONTENT_CATEGORIES
    if category == "marketplace" or category.startswith("marketplace_")
)
DISCOVERY_CONTENT_CATEGORIES = frozenset({
    "directory_index", "search_engine", "forum_social", "hosting_services",
    "contact_infrastructure",
})
NEUTRAL_CONTENT_CATEGORIES = frozenset({
    "infosec_research", "privacy_anonymity", "news_media",
    "religion_spirituality", "education_reference", "technology_software",
    "finance_cryptocurrency", "activism_civil_society", "personal_blog",
    "communication_services", "file_storage_sharing", "arts_culture",
    "health_wellness",
})
THREAT_CONTENT_CATEGORIES = frozenset({
    "leaks_data", "credentials", "malware_hacking", "weapons_arms", "drugs",
    "fraud_financial", "extremist_recruitment",
})


def normalize_content_category(value: object) -> str:
    key = str(value or "unknown").strip().casefold().replace("-", "_").replace(" ", "_")
    key = CONTENT_CATEGORY_ALIASES.get(key, key)
    return key if key in CONTENT_CATEGORIES else "unknown"


def normalize_page_type(value: object) -> str:
    key = str(value or "unknown").strip().casefold().replace("-", "_").replace(" ", "_")
    key = PAGE_TYPE_ALIASES.get(key, key)
    return key if key in PAGE_TYPES else "unknown"


def normalize_readiness_reason(value: object) -> str:
    key = str(value or "legacy_unknown").strip().casefold().replace("-", "_").replace(" ", "_")
    key = READINESS_REASON_ALIASES.get(key, key)
    return key if key in CARD_READINESS_REASONS else "legacy_unknown"


def content_category_label(value: object) -> str:
    return CONTENT_CATEGORY_LABELS.get(normalize_content_category(value), "Needs classification")


def content_category_display_group(value: object) -> str:
    category = normalize_content_category(value)
    if category in {"adult_filtered", "adult_restricted", "severe_abuse_risk"}:
        return "Safety Restricted"
    if category in MARKETPLACE_CONTENT_CATEGORIES:
        return "Marketplaces"
    if category in DISCOVERY_CONTENT_CATEGORIES:
        return "Discovery"
    if category in NEUTRAL_CONTENT_CATEGORIES:
        return "Neutral / informational"
    if category in THREAT_CONTENT_CATEGORIES:
        return "Threats"
    return "Other"


def site_type_for_dimensions(category: object, page_type: object) -> str:
    """Derive a neutral structural type without inspecting content or routing hints."""
    category = normalize_content_category(category)
    page_type = normalize_page_type(page_type)
    if page_type == "login_wall":
        return "login_portal"
    if category == "forum_social" or page_type in {"forum_index", "forum_thread"}:
        return "forum"
    if category in MARKETPLACE_CONTENT_CATEGORIES or page_type in {
        "marketplace_front", "marketplace_listing", "vendor_profile", "cart_checkout",
    }:
        return "marketplace"
    if page_type == "link_repository":
        return "link_list"
    if category in {"directory_index", "search_engine"} or page_type in {
        "directory_index_page", "search_results", "mirror_index",
    }:
        return "directory"
    if page_type == "paste_text":
        return "paste"
    if category == "personal_blog":
        return "blog"
    return "unknown"


def derive_safety_state(policy: dict) -> str:
    category = normalize_content_category(policy.get("primary_category"))
    storage = str(policy.get("storage_policy") or "safe_summary").casefold()
    if category in {"adult_filtered", "adult_restricted"} or storage == "discard":
        return "filtered" if category in {"adult_filtered", "adult_restricted"} else "discarded"
    if category == "severe_abuse_risk" or storage == "metadata_only":
        return "metadata_only"
    if storage == "metadata_limited":
        return "metadata_limited"
    return "safe"


def empty_evidence_buckets() -> dict[str, list[str]]:
    return {name: [] for name in EVIDENCE_BUCKETS}


def _add(bucket: dict[str, list[str]], name: str, value: str) -> None:
    if value and value not in bucket[name]:
        bucket[name].append(value)


def build_category_evidence(policy: dict, identity: dict, page_type_info: dict,
                            structure: dict, content_quality: str) -> dict[str, list[str]]:
    """Convert raw classifier output into capped, display-safe evidence codes."""
    buckets = empty_evidence_buckets()
    page_type = normalize_page_type(policy.get("page_type") or page_type_info.get("page_type"))
    scope = str(policy.get("match_scope") or "").casefold()
    if scope == "title":
        _add(buckets, "title", "classifier_title_signal")
        if identity.get("title_source") in {"heading", "page_h1"}:
            _add(buckets, "heading", "classifier_heading_signal")
    elif scope == "url":
        _add(buckets, "url", "unverified_url_hint_not_page_evidence")
    elif scope == "body":
        _add(buckets, "body_safe_snippet", "corroborated_safe_body_signal")
    # URL/path shape is deliberately omitted from supporting evidence. It may
    # be retained as a routing hint, but cannot raise page confidence.
    for value in list(policy.get("evidence_families") or []) + list(page_type_info.get("evidence") or []):
        code = str(value)[:80]
        if code in {"password_form", "login_structure", "cart_structure", "checkout_structure", "contact_form"}:
            _add(buckets, "form_checkout_login", code)
        elif any(token in code for token in ("link", "navigation", "index", "markup", "structure")):
            _add(buckets, "link_pattern", code)
        elif code.startswith("scope:"):
            target = {"scope:title": "title", "scope:url": "url", "scope:body": "body_safe_snippet"}.get(code)
            if target:
                _add(buckets, target, "classifier_" + code.replace(":", "_"))
        elif code and code not in {"classifier_page_type", "insufficient_structure"}:
            _add(buckets, "body_safe_snippet", code)
    if int(structure.get("external_onion_count") or 0) >= 2:
        _add(buckets, "link_pattern", "multiple_external_onion_links")
    if page_type in STATE_PAGE_TYPES:
        _add(buckets, "negative_contradicting", f"page_state_{page_type}")
    if content_quality in {"thin", "empty", "unavailable"}:
        _add(buckets, "negative_contradicting", f"content_quality_{content_quality}")
    if policy.get("restricted_child_present"):
        _add(buckets, "negative_contradicting", "restricted_child_excluded_from_parent_identity")
    return {key: values[:12] for key, values in buckets.items()}


def calibrate_category_confidence(category: str, page_type: str,
                                  evidence: dict[str, list[str]], existing: object = "low") -> str:
    category = normalize_content_category(category)
    page_type = normalize_page_type(page_type)
    if category == "unknown":
        return "low"
    if category in {"adult_filtered", "adult_restricted", "severe_abuse_risk"}:
        return "critical"
    positive = [name for name in (
        "title", "heading", "body_safe_snippet", "link_pattern", "form_checkout_login"
    ) if evidence.get(name)]
    structural = bool(evidence.get("link_pattern") or evidence.get("form_checkout_login"))
    aligned_strong = (
        (category == "directory_index" and page_type in {"link_repository", "directory_index_page"})
        or (category == "forum_social" and page_type == "forum_index")
        or (category.startswith("marketplace") and page_type == "marketplace_front")
        or (category in {"hosting_services", "technology_software"} and page_type == "code_repository")
    )
    if aligned_strong and structural:
        return "high"
    if len(positive) >= 2:
        return "high"
    if structural or str(existing).casefold() in {"medium", "high", "critical", "analyst"}:
        return "medium"
    return "low"


def apply_classification_contract(policy: dict, identity: dict, page_type_info: dict,
                                  structure: dict, content_quality: str,
                                  previous_category: object = None,
                                  previous_category_trusted: bool = False) -> dict:
    """Normalize dimensions, calibrate evidence, and guard category updates."""
    result = dict(policy)
    category = normalize_content_category(result.get("primary_category"))
    proposed_category = category
    page_type = normalize_page_type(result.get("page_type") or page_type_info.get("page_type"))
    previous = normalize_content_category(previous_category)
    local_structure = dict(structure, url=structure.get("url") or result.get("url"))
    evidence = build_category_evidence(result, identity, page_type_info, local_structure, content_quality)
    allowed, reason = True, "confidence_weighted_page_evidence"

    if page_type in STATE_PAGE_TYPES or content_quality in {"empty", "unavailable"}:
        allowed, reason = False, "page_state_cannot_replace_site_category"
        if previous_category_trusted and previous != "unknown" and category != previous:
            category = previous
        elif not previous_category_trusted:
            category = "unknown"
            reason = "page_state_has_no_trusted_html_category"
    elif (content_quality == "thin" and previous_category_trusted
          and previous != "unknown" and category != previous):
        allowed, reason, category = False, "thin_page_preserved_previous_category", previous
    elif page_type in {"directory_index_page", "link_repository"} and category.startswith("marketplace"):
        # Market links describe directory children unless the page itself has independent market evidence.
        independent = bool(evidence["title"] or evidence["heading"] or evidence["body_safe_snippet"])
        if not independent:
            category, allowed = "directory_index", True
            reason = "directory_structure_accepted_child_marketplace_rejected"
            _add(evidence, "negative_contradicting", "marketplace_child_links_only")

    category_changed = category != proposed_category
    if category_changed:
        # Category guards run after the classifier has already populated
        # category-adjacent display and structural fields. Realign only those
        # dimensions so a rejected marketplace inference cannot leave behind
        # a hybrid "directory + marketplace" record. Risk, urgency, storage,
        # queue, Spain, and safety policy remain untouched.
        result.update(
            category_safe_label=content_category_label(category),
            display_group=content_category_display_group(category),
            site_type=site_type_for_dimensions(category, page_type),
        )
        if reason == "directory_structure_accepted_child_marketplace_rejected":
            result.update(
                category_reason=(
                    "Directory structure accepted; marketplace child-link evidence "
                    "did not define the parent page"
                ),
                marketplace_type=None,
            )
            tags = result.get("tags")
            if isinstance(tags, (list, tuple, set)):
                result["tags"] = list(dict.fromkeys(
                    [tag for tag in tags
                     if normalize_content_category(tag) not in MARKETPLACE_CONTENT_CATEGORIES]
                    + ["directory_index"]
                ))
            secondary = result.get("secondary_categories")
            if isinstance(secondary, (list, tuple, set)):
                result["secondary_categories"] = [
                    value for value in secondary
                    if normalize_content_category(value) not in MARKETPLACE_CONTENT_CATEGORIES
                ]
        elif reason == "thin_page_preserved_previous_category":
            result["category_reason"] = "Thin page preserved the last trusted category"
        elif reason == "page_state_cannot_replace_site_category":
            result["category_reason"] = "Page state preserved the last trusted category"
        elif reason == "page_state_has_no_trusted_html_category":
            result["category_reason"] = "Page state has no trusted content category"

    confidence = calibrate_category_confidence(category, page_type, evidence,
                                               result.get("category_confidence"))
    # URL entries remain visible in a dedicated, explicitly unverified hint
    # bucket. They are never supporting evidence for a content category.
    supporting = [code for name in (
        "title", "heading", "body_safe_snippet", "link_pattern", "form_checkout_login",
    ) for code in evidence[name]]
    contradicting = list(evidence["negative_contradicting"])
    result.update(
        primary_category=category, category=category, content_category=category,
        page_type=page_type, safety_state=derive_safety_state(dict(result, primary_category=category)),
        category_confidence=confidence, category_evidence=evidence,
        category_supporting_evidence=supporting[:30],
        category_contradicting_evidence=contradicting[:20],
        category_update_allowed=bool(allowed), category_update_reason=reason,
    )
    return result


def normalize_policy_vocabulary(policy: dict) -> dict:
    result = dict(policy)
    content_value = result.get("content_category")
    if content_value in {None, "", "unknown"} and result.get("primary_category") not in {None, "", "unknown"}:
        content_value = result.get("primary_category")
    category = normalize_content_category(content_value)
    result.update(primary_category=category, category=category, content_category=category,
                  page_type=normalize_page_type(result.get("page_type")),
                  safety_state=derive_safety_state(dict(result, primary_category=category)))
    if result.get("card_readiness_reason") is not None:
        result["card_readiness_reason"] = normalize_readiness_reason(result.get("card_readiness_reason"))
    return result
