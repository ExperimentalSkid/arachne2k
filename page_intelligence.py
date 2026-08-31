"""Passive, metadata-safe page understanding helpers.

The helpers in this module never fetch, execute JavaScript, or persist raw page
content. They turn already-fetched structural facts into capped safe metadata.
"""
from __future__ import annotations

import html
import re
import unicodedata
from urllib.parse import urlsplit

from classification_schema import normalize_page_type, normalize_readiness_reason


TRANSACTION_TYPES = {"login_wall", "cart_checkout", "contact_support", "download_file"}
RESTRICTED_CATEGORIES = {"adult_filtered", "adult_restricted", "severe_abuse_risk"}
MEANINGFUL_TYPES = {"link_repository", "directory_index_page", "forum_index", "forum_thread",
                    "marketplace_front", "marketplace_listing", "vendor_profile", "wiki_docs",
                    "code_repository", "mirror_index", "search_results"}
_UNSAFE_LIMITED_TITLE = re.compile(
    r"(?i)(\b(?:buy|order|checkout|cart|cvv|fullz|dump|price|vendor|listing|product)\b|"
    r"(?:[$€£]|\b(?:usd|eur|btc|xmr)\b)\s*\d|@\w+|https?://)"
)


def clean_text(value: object, limit: int = 180) -> str:
    text = html.unescape(str(value or ""))
    if any(marker in text for marker in ("Ã", "Â", "â€", "â€”", "â†")):
        try:
            repaired = text.encode("latin-1").decode("utf-8")
            if repaired.count("�") <= text.count("�"):
                text = repaired
        except (UnicodeError, UnicodeEncodeError):
            pass
    text = unicodedata.normalize("NFKC", text).replace("�", "")
    text = " ".join(text.split()).strip(" |·-—:\t\r\n")
    return text[:max(0, limit)].rstrip()


def _title_quality(value: str) -> int:
    if not value:
        return -100
    words = value.split()
    score = 40 + min(len(words), 8) * 3
    if 2 <= len(words) <= 9:
        score += 18
    if len(value) > 100:
        score -= 25
    if value.count("|") + value.count("-") > 3:
        score -= 18
    if value.casefold() in {"home", "homepage", "index", "welcome", "untitled", "login"}:
        score -= 35
    if len(set(words)) < max(1, len(words) // 2):
        score -= 12
    return score


def extract_page_identity(url: str, *, title: str | None = None,
                          og_title: str | None = None, twitter_title: str | None = None,
                          headings: list[str] | None = None,
                          meta_description: str | None = None,
                          restricted: bool = False,
                          safe_category_label: str | None = None) -> dict:
    """Return a safe identity candidate with provenance and confidence."""
    host = (urlsplit(url or "").hostname or "unknown onion").casefold()
    host_label = clean_text(host, 90)
    if restricted:
        label = clean_text(safe_category_label or "Restricted metadata", 80)
        return {"detected_title": label, "display_name": label, "host_label": host_label,
                "title_source": "policy_label", "identity_confidence": "high",
                "safe_meta_description": "", "limited_title_safe": False}
    candidates: list[tuple[str, str]] = []
    for source, value in (("og_title", og_title), ("twitter_title", twitter_title),
                          ("html_title", title)):
        cleaned = clean_text(value, 180)
        if cleaned:
            candidates.append((source, cleaned))
    for heading in headings or []:
        cleaned = clean_text(heading, 180)
        if cleaned:
            candidates.append(("page_h1", cleaned))
            break
    source_bonus = {"og_title": 8, "twitter_title": 6, "html_title": 4, "page_h1": 2}
    if candidates:
        source, selected = max(candidates,
                               key=lambda item: _title_quality(item[1]) + source_bonus[item[0]])
        quality = _title_quality(selected) + source_bonus[source]
        confidence = "high" if quality >= 70 else "medium" if quality >= 45 else "low"
    else:
        source, selected, confidence = "onion_host", host_label, "low"
    description = clean_text(meta_description, 280)
    limited_safe = bool(confidence in {"medium", "high"} and len(selected) <= 90
                        and not _UNSAFE_LIMITED_TITLE.search(selected))
    return {"detected_title": selected, "display_name": selected, "host_label": host_label,
            "title_source": source, "identity_confidence": confidence,
            "safe_meta_description": description, "limited_title_safe": limited_safe}


def fingerprint_page_type(url: str, features: dict, *, current_type: str = "unknown",
                          allow_url_hints: bool = False) -> dict:
    """Infer a confirmed page type only from destination-owned page evidence.

    ``url`` and the legacy ``allow_url_hints`` switch are intentionally ignored.
    Route shape belongs in a separate unverified routing hint and must never be
    able to assign the fetched destination's page type.
    """
    _ = (url, allow_url_hints)
    scores: dict[str, int] = {}
    evidence: dict[str, list[str]] = {}

    def add(kind: str, points: int, reason: str) -> None:
        scores[kind] = scores.get(kind, 0) + points
        evidence.setdefault(kind, []).append(reason)

    if features.get("has_password_form"):
        add("login_wall", 8, "password_form")
    if features.get("login_markers"):
        add("login_wall", 4, "login_structure")
    if features.get("cart_markers"):
        add("cart_checkout", 8, "cart_structure")
    if features.get("checkout_markers"):
        add("cart_checkout", 9, "checkout_structure")
    if features.get("contact_markers") and features.get("form_count"):
        add("contact_support", 6, "contact_form")
    if features.get("error_markers"):
        add("error_page", 9, "error_response_content")
    if features.get("placeholder_markers"):
        add("empty_placeholder", 8, "placeholder_content")
    if features.get("forum_thread_markup"):
        add("forum_thread", 9, "forum_thread_markup")
    if features.get("forum_index_markup") or features.get("forum_markup"):
        add("forum_index", 7, "forum_markup")
    if features.get("wiki_markup"):
        add("wiki_docs", 8, "wiki_documentation_markup")
    if features.get("code_markup"):
        add("code_repository", 8, "code_repository_markup")
    if features.get("market_markup"):
        add("marketplace_front", 7, "marketplace_markup")
    onion_count = int(features.get("onion_link_count") or 0)
    external_count = int(features.get("external_onion_count") or 0)
    density = float(features.get("link_density") or 0)
    repository_score = 0
    repository_evidence = []
    if onion_count >= 5:
        repository_score += 3; repository_evidence.append("multiple_onion_destinations")
    if onion_count >= 12:
        repository_score += 2; repository_evidence.append("high_onion_link_count")
    if onion_count >= 20:
        repository_score += 2; repository_evidence.append("high_edge_onion_index")
    if external_count >= 3:
        repository_score += 2; repository_evidence.append("multiple_external_onion_hosts")
    if external_count >= 8:
        repository_score += 2; repository_evidence.append("high_external_host_count")
    if density >= 0.50 and onion_count >= 3:
        repository_score += 2; repository_evidence.append("high_onion_link_density")
    if features.get("structured_lists") or int(features.get("repeated_link_row_count") or 0) >= 3:
        repository_score += 2; repository_evidence.append("repeated_directory_rows")
    if features.get("directory_markers"):
        repository_score += 2; repository_evidence.append("directory_identity_markers")
    if features.get("article_markup") and density < 0.35:
        repository_score = max(0, repository_score - 2)
    if repository_score >= 8:
        for reason in repository_evidence:
            add("link_repository", repository_score if reason == repository_evidence[0] else 0, reason)
    elif repository_score >= 5:
        for reason in repository_evidence:
            add("directory_index_page", repository_score if reason == repository_evidence[0] else 0, reason)
    if features.get("mirror_markers") and onion_count >= 2:
        add("mirror_index", 7, "mirror_navigation")
    if features.get("has_search_form"):
        add("search_results", 5, "search_form")
    if features.get("plain_text_page"):
        add("paste_text", 5, "plain_text_content")
    if features.get("article_markup"):
        add("article_page", 4, "article_markup")
    if current_type and current_type != "unknown":
        add(normalize_page_type(current_type), 3, "classifier_page_type")
    if not scores:
        return {"page_type": "unknown", "page_type_confidence": "low",
                "page_type_score": 0, "evidence": ["insufficient_structure"]}
    kind, score = max(scores.items(), key=lambda item: (item[1], item[0]))
    confidence = "high" if score >= 8 else "medium" if score >= 5 else "low"
    return {"page_type": kind, "page_type_confidence": confidence,
            "page_type_score": score, "evidence": list(dict.fromkeys(evidence[kind]))[:8]}


def classify_link_context(url: str, *, anchor_text: str = "", section_context: str = "",
                          source_page_type: str = "unknown", same_host: bool = False,
                          restricted: bool = False, unverified_hint: bool = False,
                          policy_reason: str = "") -> dict:
    target = (url or "").casefold()
    context = clean_text(f"{anchor_text} {section_context}", 220).casefold()
    if restricted:
        safe_anchor = "Restricted child link hidden"
    elif unverified_hint:
        safe_anchor = "Unverified link label hidden"
    else:
        safe_anchor = clean_text(anchor_text, 120)
    source_page_type = normalize_page_type(source_page_type)
    if any(token in target for token in (".zip", ".7z", ".rar", ".exe", ".pdf", "/download")):
        relation = "file_or_download"
    elif any(token in target for token in ("/login", "/register", "/cart", "/checkout", "/contact")):
        relation = "contact_login_cart"
    elif "mirror" in context or "/mirror" in target:
        relation = "mirror"
    elif source_page_type in {"forum_index", "forum_thread"} or any(
            token in target for token in ("viewtopic.php", "viewforum.php", "/thread", "/topic")):
        relation = "forum_link"
    elif source_page_type in {"marketplace_front", "marketplace_listing", "vendor_profile"} or any(
            token in target for token in ("/vendor", "/seller", "/product", "/listing", "/category")):
        relation = "marketplace_link"
    elif source_page_type in {"wiki_docs", "code_repository"}:
        relation = "wiki_doc_link"
    elif same_host:
        relation = "navigation"
    elif source_page_type in {"link_repository", "directory_index_page", "search_results", "mirror_index"}:
        relation = "directory_entry"
    else:
        relation = "unknown"
    # This describes how the source page *presented* the link.  It is useful
    # for scheduling and UI context, but it says nothing confirmed about bytes
    # returned by the destination itself.
    return {"relation_type": relation, "relation_hint": relation,
            "relation_verified": False, "evidence_source": "discovery_metadata",
            "safe_anchor_text": safe_anchor,
            "source_page_type": source_page_type, "same_host": bool(same_host),
            "unverified_hint": bool(unverified_hint),
            "policy_reason": clean_text(policy_reason, 100)}


def build_safe_summary(policy: dict, identity: dict, page_type: str, link_stats: dict,
                       content_quality: str) -> str:
    category = str(policy.get("primary_category") or "unknown")
    if category in RESTRICTED_CATEGORIES or policy.get("storage_policy") in {"metadata_only", "discard"}:
        return "Restricted page retained as metadata only. Page content and previews are hidden."
    if category in {"marketplace_fraud", "fraud_financial"} or policy.get("storage_policy") == "metadata_limited":
        return "Metadata-limited marketplace or fraud context. Listing and transaction details are hidden."
    if policy.get("spain_priority") and policy.get("spain_confidence") == "high":
        return "Spain Priority signal detected from explicit Spain-specific evidence."
    external = int(link_stats.get("external_onion_count") or link_stats.get("external_onion_host_count") or 0)
    blocked_children = int(policy.get("child_blocked_link_count") or 0)
    restricted_children = int(policy.get("child_restricted_link_count") or 0)
    if page_type == "link_repository":
        if restricted_children:
            return (f"Directory preserved with {external} external onion destination"
                    f"{'s' if external != 1 else ''}; restricted child links were filtered individually.")
        if blocked_children:
            return (f"Link repository with {external} external onion destination"
                    f"{'s' if external != 1 else ''}; blocked child links are hidden.")
        return f"Directory-style onion index with {external} external onion destination{'s' if external != 1 else ''}."
    if page_type in {"directory_index_page", "mirror_index", "search_results"}:
        return "Directory or search-style page with structured onion navigation."
    if page_type in {"forum_index", "forum_thread"}:
        return "Forum or community page identified from thread and navigation structure."
    if page_type == "wiki_docs":
        return "Documentation or wiki-style onion page."
    if page_type == "code_repository":
        return "Code repository or software-development page."
    if page_type in {"error_page", "empty_placeholder"} or content_quality in {"empty", "unavailable"}:
        return "Placeholder or unavailable page; not ready for normal review."
    description = clean_text(identity.get("safe_meta_description"), 220)
    return description or "Passively classified onion page with limited safe metadata."


def compute_card_readiness(policy: dict, identity: dict, page_type_info: dict,
                           link_stats: dict, content_quality: str,
                           analyst_confirmed: bool = False) -> dict:
    category = str(policy.get("primary_category") or "unknown")
    page_type = normalize_page_type(page_type_info.get("page_type"))
    if analyst_confirmed:
        ready, reason, confidence = True, "analyst_confirmed", "high"
    elif category in {"adult_filtered", "adult_restricted"} or policy.get("storage_policy") == "discard":
        ready, reason, confidence = False, "policy_discard", "high"
    elif category == "severe_abuse_risk" or policy.get("storage_policy") == "metadata_only":
        ready, reason, confidence = False, "restricted_metadata_only", "high"
    elif page_type in TRANSACTION_TYPES:
        ready, reason, confidence = False, "interaction_flow_not_reviewable", "high"
    elif page_type in {"error_page", "empty_placeholder"} or content_quality in {"empty", "unavailable"}:
        ready, reason, confidence = False, "empty_error_or_placeholder", "high"
    elif policy.get("spain_priority") and policy.get("spain_confidence") == "high":
        ready, reason, confidence = True, "high_confidence_spain_evidence", "high"
    elif page_type in MEANINGFUL_TYPES and content_quality in {"meaningful", "thin"}:
        ready, reason = True, "meaningful_structural_page"
        confidence = str(page_type_info.get("page_type_confidence") or "medium")
    elif category not in {"unknown", "general_other", "spam_noise", "dead_softdead"} and content_quality == "meaningful":
        ready, reason = True, "classified_meaningful_page"
        confidence = str(policy.get("category_confidence") or "medium")
    else:
        ready, reason, confidence = False, "insufficient_page_evidence", "low"
    return {"card_ready": bool(ready), "card_readiness_reason": normalize_readiness_reason(reason),
            "card_readiness_confidence": confidence,
            "recommended_review_status": policy.get("review_status") if ready else "monitor",
            "recommended_importance": policy.get("analyst_importance") or policy.get("importance_level") or "normal",
            "safe_summary": build_safe_summary(policy, identity, page_type, link_stats, content_quality)}
