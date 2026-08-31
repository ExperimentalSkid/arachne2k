"""Canonical, metadata-safe URL policy normalization.

Every classifier/crawler path may contribute evidence, but this module owns the
final state invariants persisted for an onion URL.
"""
from __future__ import annotations

from urllib.parse import urlsplit
import re


RESTRICTED_CATEGORIES = {"adult_filtered", "adult_restricted", "severe_abuse_risk"}
FRAUD_CATEGORIES = {"fraud_financial", "marketplace_fraud"}
DISCOVERY_CATEGORIES = {"directory_index", "search_engine", "forum_social"}
TRANSACTION_PAGE_TYPES = {
    "login_gate", "register_page", "cart_page", "checkout_page", "transaction_page",
    "contact_page", "mail_page", "download_page",
}
IMPORTANCE_VALUES = {"low", "normal", "elevated", "high", "critical"}


def locale_path(url: str) -> str | None:
    first = next((part for part in (urlsplit(url or "").path or "").split("/") if part), "")
    value = first.casefold().replace("-", "_")
    aliases = {"es_es": "es", "en_us": "en", "en_gb": "en", "zh_cn": "zh_cn",
               "pt_br": "pt_br"}
    value = aliases.get(value, value)
    return value if value in {"es", "de", "fr", "it", "pt", "pt_br", "ru", "zh", "zh_cn", "en"} else None


def default_importance(policy: dict) -> tuple[str, str]:
    category = str(policy.get("primary_category") or "unknown")
    if policy.get("spain_priority") and category in FRAUD_CATEGORIES | {
        "weapons_arms", "marketplace_weapons", "drugs", "marketplace_drugs",
        "credentials", "marketplace_credentials", "leaks_data", "marketplace_leaks",
    }:
        return "high", "verified_spain_threat_context"
    if category in FRAUD_CATEGORIES:
        return "high", "direct_fraud_page"
    if category in {"weapons_arms", "marketplace_weapons", "severe_abuse_risk"}:
        return "high", "direct_high_risk_page"
    if category in DISCOVERY_CATEGORIES:
        return "normal", "source_or_directory_value"
    if str(policy.get("risk_level") or "low").casefold() in {"high", "critical", "alto", "critico"}:
        return "elevated", "policy_risk_review"
    return "normal", "routine_monitoring"


def normalize_policy_state(policy: dict, *, fetched: bool = False,
                           requested_status: str | None = None) -> dict:
    """Return one internally consistent policy without weakening restrictions."""
    result = dict(policy)
    category = str(result.get("primary_category") or "unknown")
    result["primary_category"] = result["category"] = category
    storage = str(result.get("storage_policy") or "safe_summary")
    page_type = str(result.get("page_type") or "unknown")
    restricted = category in RESTRICTED_CATEGORIES or storage in {"metadata_only", "discard"}
    fraud = category in FRAUD_CATEGORIES
    blocked_flow = page_type in TRANSACTION_PAGE_TYPES

    if category == "adult_filtered":
        result.update(storage_policy="discard", active=0, queue_policy="blocked",
                      review_status="filtered", screenshot_policy="blocked",
                      screenshot_blocked_reason="adult_content_filtered",
                      safety_reason="adult_content_filtered", spain_priority=False)
    elif category in {"adult_restricted", "severe_abuse_risk"}:
        reason = "adult_content_filtered" if category == "adult_restricted" else "severe_abuse_risk"
        result.update(storage_policy="metadata_only", active=0, queue_policy="blocked",
                      review_status="restricted", screenshot_policy="blocked",
                      screenshot_blocked_reason=reason, spain_priority=False)
    elif fraud:
        result.update(storage_policy="metadata_limited", queue_policy="reviewable",
                      review_status="needs_review", screenshot_policy="blocked",
                      screenshot_blocked_reason="fraud_marketplace_metadata_only", active=1)
    elif blocked_flow:
        result.update(active=0, queue_policy="blocked", screenshot_policy="blocked",
                      screenshot_blocked_reason=result.get("screenshot_blocked_reason") or "blocked_interaction_flow")
    elif category in {"directory_index", "search_engine"}:
        result.update(active=1, queue_policy="expand")

    restricted = (category in RESTRICTED_CATEGORIES
                  or result.get("storage_policy") in {"metadata_only", "discard"})
    if restricted or fraud or blocked_flow:
        result["screenshot_policy"] = "blocked"
        result["screenshot_blocked_reason"] = (result.get("screenshot_blocked_reason")
                                                or result.get("safety_reason") or "policy_blocked")

    status = requested_status or result.get("status")
    if restricted and not fraud:
        status = "blocked"
    if not result.get("active", True) or result.get("queue_policy") == "blocked":
        result["active"] = 0
        result["queue_policy"] = "blocked"
        if status in {None, "new", "queued", "retry"}:
            status = "blocked"
    elif status == "blocked":
        result["active"] = 0
        result["queue_policy"] = "blocked"
    elif status == "queued":
        result["active"] = 1

    if fetched and result.get("safety_reason") == "awaiting_page_classification":
        result["safety_reason"] = "unclassified"
        result["review_status"] = "needs_review"
    if fetched and category == "unknown" and not result.get("safety_reason"):
        result["safety_reason"] = "unclassified"
    if status:
        result["status"] = status

    importance, reason = default_importance(result)
    if result.get("importance_level") not in IMPORTANCE_VALUES:
        result["importance_level"] = importance
    result["importance_reason"] = result.get("importance_reason") or reason
    result["locale_path"] = result.get("locale_path") or locale_path(str(result.get("url") or ""))
    return result


def safe_generated_name(category: str | None) -> str:
    return {
        "marketplace_fraud": "Restricted fraud marketplace",
        "fraud_financial": "Restricted fraud service",
        "adult_filtered": "Restricted adult-risk site",
        "adult_restricted": "Restricted adult-risk site",
        "severe_abuse_risk": "Severe-risk metadata-only item",
        "directory_index": "Mixed onion link repository",
        "forum_social": "Forum index",
        "technology_software": "Code repository",
    }.get(str(category or "unknown"), "Unknown onion service")


def derive_safe_display_name(url: str, title: str | None, policy: dict) -> str:
    """Extract a short service/market identity without retaining listing content."""
    category = str(policy.get("primary_category") or "unknown")
    if category in RESTRICTED_CATEGORIES:
        return safe_generated_name(category)
    cleaned = re.sub(r"\s+", " ", str(title or "")).strip(" -|:·")[:120]
    # Keep only a brand-like first title segment. Reject likely product/transaction text.
    candidate = re.split(r"\s+[|—–:]\s+", cleaned, maxsplit=1)[0].strip()
    unsafe = re.search(
        r"(?:\$|€|btc|price|buy now|add to cart|checkout|vendor|seller|telegram|jabber|@|\b\d{3,}\b)",
        candidate, re.I,
    )
    words = candidate.split()
    brand_like = 1 <= len(words) <= 7 and len(candidate) <= 72 and not unsafe
    if category.startswith("marketplace") or category == "fraud_financial":
        return candidate if brand_like and any(term in candidate.casefold() for term in (
            "market", "mart", "bazaar", "shop", "exchange", "store"
        )) else safe_generated_name(category)
    if brand_like and category in {"directory_index", "forum_social", "hosting_services",
                                   "technology_software", "search_engine"}:
        return candidate
    host = (urlsplit(url or "").hostname or "").casefold()
    return candidate if brand_like and candidate else host or safe_generated_name(category)
