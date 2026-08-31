"""Ordered, passive-only URL decision rules for the onion frontier."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlsplit

from safety_policy import is_fetch_allowed, is_onion_url
from universal_classifier import NEUTRAL_CATEGORIES, classify_url_prefetch

SESSION_KEYS = {"sid", "session", "sessionid", "phpsessid", "token", "auth", "jsessionid"}
PAGING_KEYS = {"page", "p", "offset", "start", "sort", "order", "id", "item", "date", "year", "month", "day"}


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()


def url_shape(url: str) -> dict:
    parsed = urlsplit(url or "")
    segments = [part.casefold() for part in parsed.path.split("/") if part]
    normalized_segments = [re.sub(r"\d{2,}", "{n}", part) for part in segments]
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query_keys = sorted(key.casefold() for key, _value in query)
    path_shape = "/" + "/".join(normalized_segments)
    host = (parsed.hostname or "").casefold()
    return {
        "host": host,
        "path_segments": segments,
        "query_pairs": query,
        "path_signature": _hash(path_shape),
        "query_signature": _hash("&".join(query_keys)) if query_keys else None,
        "url_family": f"{host}{path_shape}?{'&'.join(query_keys)}",
    }


def trap_assessment(url: str, stats: dict | None = None, limits: dict | None = None) -> dict:
    stats = stats or {}
    limits = limits or {}
    shape = url_shape(url)
    segments = shape["path_segments"]
    query = shape["query_pairs"]
    score, reasons = 0, []
    max_segments = int(limits.get("max_path_segments", 12))
    max_repeat = int(limits.get("max_repeated_path_segment", 3))
    max_query = int(limits.get("max_query_params", 8))
    max_variants = int(limits.get("max_query_variants_per_host_path", 20))
    max_pages = int(limits.get("max_pages_per_host", 2000))
    if len(segments) > max_segments:
        score += 5; reasons.append("excessive_path_depth")
    if segments and max(segments.count(segment) for segment in set(segments)) > max_repeat:
        score += 7; reasons.append("repeated_path_loop")
    if len(query) > max_query:
        score += 5; reasons.append("excessive_query_parameters")
    if any(key.casefold() in SESSION_KEYS for key, _value in query):
        score += 8; reasons.append("session_like_parameter")
    if int(stats.get("query_variants", 0)) >= max_variants and query:
        score += 7; reasons.append("excessive_query_variants")
    if int(stats.get("pages_on_host", 0)) >= max_pages:
        score += 7; reasons.append("host_page_limit")
    calendar_parts = sum(bool(re.fullmatch(r"(?:19|20)\d{2}|(?:0?[1-9]|1[0-2])|(?:0?[1-9]|[12]\d|3[01])", part)) for part in segments)
    if calendar_parts >= 3 or sum(key.casefold() in {"year", "month", "day", "date"} for key, _ in query) >= 2:
        score += 6; reasons.append("calendar_url_pattern")
    if len(query) >= 3 and sum(key.casefold() in PAGING_KEYS for key, _ in query) >= 2:
        score += 3; reasons.append("variant_heavy_query")
    page_match = re.search(r"(?:^|/)page/(\d+)(?:/|$)", (urlsplit(url or "").path or "").casefold())
    pagination_page = int(page_match.group(1)) if page_match else 0
    root_path = (urlsplit(url or "").path or "/") in {"", "/", "/index.html", "/index.php"}
    novelty = (45 if root_path else 0) + (35 if not stats.get("known_host") else 0)
    novelty += min(20, int(stats.get("source_quality", 0)))
    novelty -= 15 if pagination_page >= 6 else 0
    novelty -= 25 if any(key.casefold() in {"sort", "order", "filter", "search"} for key, _ in query) else 0
    novelty -= 15 if any(part in {"profile", "user", "member", "members"} for part in segments) else 0
    return dict(shape, trap_score=score, trap_reason=",".join(reasons) or None,
                pagination_page=pagination_page, novelty_score=max(-100, min(100, novelty)))


def _result(policy: dict, decision: str, rule_id: str, reason: str, display_reason: str,
            trap: dict, frontier_priority: int = 0) -> dict:
    result = dict(policy)
    result.update({
        "decision": decision, "rule_id": rule_id, "safety_reason": reason,
        "display_safe_reason": display_reason, "frontier_priority": max(0, frontier_priority),
        "path_signature": trap.get("path_signature"), "query_signature": trap.get("query_signature"),
        "url_family": trap.get("url_family"), "trap_score": trap.get("trap_score", 0),
        "trap_reason": trap.get("trap_reason"), "pagination_page": trap.get("pagination_page", 0),
        "novelty_score": trap.get("novelty_score", 0), "defer_reason": trap.get("defer_reason"),
    })
    return result


def _unverified_prefetch_policy(policy: dict) -> dict:
    """Strip content conclusions from URL/link-derived prefetch metadata.

    ``classify_url_prefetch`` is intentionally already conservative, but this
    second boundary keeps a future classifier/configuration regression (or an
    old caller) from turning a hostname, path, anchor, or parent label into
    destination truth.  The lexical flags remain useful as unverified hints;
    they never change fetch eligibility or a confirmed content dimension.
    """
    result = dict(policy or {})
    hinted = bool(
        result.get("url_hint_present")
        or result.get("link_text_hint_present")
        or result.get("classification_decision") in {
            "unverified_hint", "unverified_restricted_candidate",
        }
    )
    result.update(
        primary_category="unknown", category="unknown", content_category="unknown",
        site_type="unknown", page_type="unknown", risk_category="unknown",
        tags=["unknown"], risk_level="low", confidence="low", risk_flags=[],
        storage_policy="safe_summary", review_status="monitor",
        queue_policy="normal", active=1, priority_score=0,
        spain_priority=False, geo_priority=None, ui_hidden_default=0,
        category_confidence="provisional", classification_stage="prefetch",
        classification_evidence_source="unverified",
        destination_html_evidence_version=0, hint_verified=False,
        classification_decision="unverified_hint" if hinted else "unclassified",
        safety_reason="awaiting_page_classification",
    )
    return result


def decide_url(url: str, *, source_url: str | None = None, anchor_text: str | None = None,
               source_context: str | None = None, depth: int = 0, stats: dict | None = None,
               limits: dict | None = None, adult_memory_decision: str | None = None,
               classification_scope: str = "url") -> dict:
    """Apply ordered rules. The first terminal rule wins; no network activity occurs."""
    limits = limits or {}
    blank = {"primary_category": "unknown", "risk_level": "low", "storage_policy": "safe_summary",
             "review_status": "monitor", "queue_policy": "normal", "active": 1,
             "spain_priority": False, "priority_score": 0}
    trap = trap_assessment(url, stats, limits)

    allowed, fetch_reason = is_fetch_allowed(url, False)
    if not allowed and fetch_reason in {"blocked_extension", "blocked_file_type", "blocked_url_extension", "download_like_url"}:
        return _result(blank, "reject", "DECIDE-001-FILE", fetch_reason,
                       "Blocked file, media, archive, or download URL", trap)
    if not is_onion_url(url):
        return _result(blank, "reject", "DECIDE-002-MALFORMED", "malformed_onion",
                       "Malformed or unsupported onion URL", trap)

    policy = _unverified_prefetch_policy(
        classify_url_prefetch(url, None, anchor_text, source_context)
        if classification_scope == "outbound" else classify_url_prefetch(url)
    )
    if adult_memory_decision == "false_positive":
        policy.update(
            analyst_false_positive=True,
            classification_decision="unverified_hint" if (
                policy.get("url_hint_present") or policy.get("link_text_hint_present")
            ) else "unclassified",
        )
    if adult_memory_decision == "blocked":
        # ``get_adult_memory_decision`` returns blocked only for this exact URL
        # after its own fetched HTML or an explicit analyst decision.  Mark the
        # provenance so child-policy normalization can distinguish that fact
        # from URL/anchor wording.
        policy.update(primary_category="adult_filtered", category="adult_filtered",
                      content_category="adult_filtered", risk_level="filtered",
                      storage_policy="discard", review_status="filtered", queue_policy="blocked", active=0,
                      spain_priority=False, priority_score=0,
                      classification_decision="independently_verified_memory",
                      classification_evidence_source="adult_filter_memory",
                      independent_destination_decision=True, hint_verified=True)
    # Never reinterpret content from host/path wording here. Exact analyst or
    # page-verified memory is handled above; every other lexical signal remains
    # fetchable and unverified until the destination HTML is classified.
    if (policy.get("independent_destination_decision")
            and policy.get("primary_category") in {"adult_filtered", "adult_restricted"}):
        return _result(policy, "reject", "DECIDE-003-ADULT", "adult_content_filtered",
                       "Filtered by adult-content safety policy", trap)
    if (policy.get("independent_destination_decision")
            and policy.get("primary_category") == "severe_abuse_risk"):
        return _result(policy, "restrict", "DECIDE-004-SEVERE", "severe_abuse_risk",
                       "Restricted critical metadata only", trap)

    pagination_page = int(trap.get("pagination_page") or 0)
    defer_threshold = int(limits.get("defer_pagination_at", 10))
    hard_threshold = int(limits.get("hard_defer_pagination_at", 50))
    if pagination_page >= defer_threshold:
        trap["defer_reason"] = ("deep_pagination_hard_defer" if pagination_page >= hard_threshold
                                else "deep_pagination_gather_defer")
        result = _result(policy, "fetch_later", "DECIDE-005-PAGINATION",
                         trap["defer_reason"], "Deferred repetitive deep pagination", trap,
                         max(0, 10 - pagination_page))
        result["defer_requested"] = True
        return result

    max_depth = int(limits.get("max_depth_from_seed", 8))
    if depth > max_depth:
        trap["trap_score"] = max(7, trap["trap_score"]); trap["trap_reason"] = "seed_depth_limit"
    if trap["trap_score"] >= int(limits.get("trap_block_score", 7)):
        policy.update(active=0, queue_policy="blocked", review_status="filtered", storage_policy="metadata_only")
        return _result(policy, "reject", "DECIDE-005-TRAP", "crawler_trap",
                       "Blocked likely crawler trap or infinite URL family", trap)

    if stats and stats.get("exact_hard_dead"):
        policy.update(active=0, queue_policy="blocked", review_status="filtered")
        return _result(policy, "reject", "DECIDE-006-DEAD", "known_dead_url",
                       "Known hard-dead URL", trap)
    if stats and int(stats.get("dead_paths_on_host", 0)) >= 5:
        return _result(policy, "fetch_later", "DECIDE-006-DEAD-HOST", "dead_host_backoff",
                       "Host has repeated dead paths; delayed for backoff", trap, 1)

    if not allowed:
        policy.update(active=0, queue_policy="blocked")
        return _result(policy, "reject", "DECIDE-008-FETCH", fetch_reason,
                       "Fetch denied by passive safety policy", trap)

    category = policy.get("primary_category", "unknown")
    threat = category in {"weapons_arms", "drugs", "leaks_data", "credentials", "malware_hacking",
                          "fraud_financial", "extremist_recruitment"} or category.startswith("marketplace_")
    priority = int(policy.get("priority_score") or 0)
    priority += 100 if policy.get("spain_priority") and threat else 70 if policy.get("spain_priority") else 50 if threat else 0
    weapons_focus = category in {"weapons_arms", "marketplace_weapons"}
    priority += 90 if weapons_focus and policy.get("spain_priority") else 50 if weapons_focus else 0
    priority += 30 if category in {"directory_index", "search_engine"} else 0
    priority += 20 if stats and not stats.get("known_host") else 0
    priority += min(20, int(stats.get("source_quality", 0))) if stats else 0
    priority -= min(40, int(stats.get("duplicate_sightings", 0)) * 2) if stats else 0
    priority -= min(50, trap["trap_score"] * 5)
    priority -= 15 if category == "forum_social" and not policy.get("spain_priority") else 0
    monitor_categories = {"directory_index", "search_engine", "forum_social", "hosting_services"} | NEUTRAL_CATEGORIES
    decision = "monitor" if category in monitor_categories and not policy.get("spain_priority") else "accept"
    rule = "DECIDE-009-PRIORITY"
    return _result(policy, decision, rule, policy.get("safety_reason", "accepted_safe_url"),
                   "Accepted by passive crawler policy", trap, priority)


def assess_content_liveness(http_status: int | None, title: str | None, visible_text: str | None) -> dict:
    """Classify response usefulness without treating every HTTP 200 as live."""
    status = int(http_status or 0)
    text = re.sub(r"\s+", " ", f"{title or ''} {visible_text or ''}").strip().casefold()
    if status in {404, 410}:
        return {"fetch_status": "success", "liveness_status": "hard_dead",
                "content_quality": "unavailable", "reason": f"http_{status}"}
    soft_markers = (
        "page not found", "site not found", "service unavailable", "onion site not found",
        "this site has been seized", "domain is parked", "site is parked", "account suspended",
        "temporarily unavailable", "no longer available", "coming soon",
    )
    if status == 200 and any(marker in text for marker in soft_markers) and len(text) < 3000:
        parked = any(marker in text for marker in ("parked", "coming soon"))
        return {"fetch_status": "success", "liveness_status": "soft_dead",
                "content_quality": "unavailable", "reason": "parked_page" if parked else "soft_dead_content"}
    visible = re.sub(r"\s+", " ", visible_text or "").strip()
    if not visible:
        return {"fetch_status": "success", "liveness_status": "live",
                "content_quality": "empty", "reason": "empty_page"}
    if len(visible) < 120:
        return {"fetch_status": "success", "liveness_status": "live",
                "content_quality": "thin", "reason": "thin_page"}
    return {"fetch_status": "success", "liveness_status": "live",
            "content_quality": "meaningful", "reason": "meaningful_content"}
