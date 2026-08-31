"""Bounded, proposal-only entity route expansion.

This module plans a small set of high-value same-host public GET routes from an
already verified destination page.  It deliberately has no storage, queue, or
transport dependencies: callers must make a separate policy decision before
persisting or fetching any proposal.

URL/anchor information is used only to prioritise a public route.  It never
confirms the destination's content category or safety state.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from typing import Any, Iterable
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit

from classification_schema import DESTINATION_HTML_EVIDENCE_VERSION
from entity_extractor import canonical_profile_identity
from forum_url_identity import ForumUrlIdentity, classify_forum_url
from safety_policy import is_fetch_allowed, is_onion_url, normalize_url
from url_identity import canonical_url


MAX_PROPOSALS_PER_HOST = 10
MAX_PROPOSALS_PER_ROLE = 3
MAX_VARIANTS_PER_RESOURCE = 1
MAX_URL_LENGTH = 2048
MAX_PATH_SEGMENTS = 12
MAX_QUERY_PAIRS = 8
MAX_REPEATED_PATH_SEGMENT = 3

SUPPORTED_ROLES = frozenset({
    "profile", "thread", "thread_page", "section", "about", "contact",
    "pgp", "mirrors", "faq", "rules",
})

REASON_CODES = {
    "profile": "VERIFIED_PROFILE_ROUTE",
    "thread": "FORUM_THREAD_ROUTE",
    "thread_page": "FORUM_THREAD_PAGE_ROUTE",
    "section": "FORUM_SECTION_ROUTE",
    "about": "PUBLIC_ABOUT_ROUTE",
    "contact": "PUBLIC_CONTACT_ROUTE",
    "pgp": "PUBLIC_PGP_ROUTE",
    "mirrors": "PUBLIC_MIRRORS_ROUTE",
    "faq": "PUBLIC_FAQ_ROUTE",
    "rules": "PUBLIC_RULES_ROUTE",
}

STOP_CODES = frozenset({
    "PLAN_READY", "SOURCE_NOT_VERIFIED", "SOURCE_POLICY_BLOCKED",
    "SOURCE_URL_INVALID", "NO_LINK_RECORDS", "NO_ELIGIBLE_CANDIDATES",
})

REJECTION_CODES = frozenset({
    "INVALID_RECORD", "INVALID_URL", "NON_PUBLIC_SCHEME", "CREDENTIALS_BLOCKED",
    "PORT_BLOCKED", "CROSS_HOST", "CHILD_POLICY_BLOCKED", "NON_GET_ROUTE",
    "ROUTE_BLOCKED", "SESSION_OR_TRACKING_BLOCKED", "TRAP_BLOCKED",
    "FETCH_POLICY_BLOCKED", "UNSUPPORTED_ROLE", "DUPLICATE_RESOURCE",
    "ROLE_CAP_REACHED", "HOST_CAP_REACHED",
})

APPROVAL_REVALIDATION_CODES = frozenset({
    "APPROVAL_POLICY_ALLOWED", "SOURCE_NOT_VERIFIED", "SOURCE_POLICY_BLOCKED",
    "SOURCE_URL_INVALID", "INVALID_PROPOSAL", "INVALID_URL", "NON_PUBLIC_SCHEME",
    "CREDENTIALS_BLOCKED", "PORT_BLOCKED", "CROSS_HOST", "NON_GET_ROUTE",
    "ROUTE_BLOCKED", "SESSION_OR_TRACKING_BLOCKED", "TRAP_BLOCKED",
    "FETCH_POLICY_BLOCKED", "UNSUPPORTED_ROLE", "CHILD_POLICY_BLOCKED",
    "DESTINATION_POLICY_BLOCKED",
})

_ROLE_PRIORITY = {
    "profile": 10, "about": 20, "contact": 30, "pgp": 40, "mirrors": 50,
    "faq": 60, "rules": 70, "section": 80, "thread": 90, "thread_page": 100,
}

_STATIC_ROUTE_ALIASES = {
    "about": frozenset({"about", "about-us", "aboutus"}),
    "contact": frozenset({"contact", "contact-us", "contactus"}),
    "pgp": frozenset({"pgp", "gpg", "public-key", "publickey"}),
    "mirrors": frozenset({"mirror", "mirrors", "mirror-list", "mirrorlist"}),
    "faq": frozenset({"faq", "faqs", "frequently-asked-questions"}),
    "rules": frozenset({"rule", "rules", "guidelines"}),
}
_STATIC_ANCHOR_ALIASES = {
    "about": frozenset({"about", "about us"}),
    "contact": frozenset({"contact", "contact us"}),
    "pgp": frozenset({"pgp", "gpg", "pgp key", "public key"}),
    "mirrors": frozenset({"mirror", "mirrors", "mirror list"}),
    "faq": frozenset({"faq", "faqs", "frequently asked questions"}),
    "rules": frozenset({"rule", "rules", "guidelines"}),
}
_PROFILE_PATH_TOKENS = frozenset({
    "profile", "profiles", "member", "members", "user", "users", "vendor",
    "vendors", "seller", "sellers", "merchant", "merchants",
})

_BLOCKED_PATH_TOKENS = frozenset({
    "auth", "authenticate", "login", "log-in", "signin", "sign-in", "register",
    "logout", "password", "reset-password", "cart", "basket", "checkout",
    "account", "accounts", "message", "messages", "inbox", "dm", "payment",
    "payments", "pay", "deposit", "upload", "uploads", "submit", "form",
    "forms", "search", "find", "calendar", "tag", "tags",
})
_SESSION_TRACKING_KEYS = frozenset({
    "sid", "session", "sessionid", "phpsessid", "jsessionid", "s", "token",
    "auth", "apikey", "api_key", "fbclid", "gclid", "mc_cid", "mc_eid",
    "ref", "ref_src", "source_tracking", "cache", "cb", "timestamp",
})
_SEARCH_QUERY_KEYS = frozenset({"q", "query", "search", "keyword", "keywords"})
_CALENDAR_TAG_QUERY_KEYS = frozenset({
    "calendar", "date", "year", "month", "day", "tag", "tags",
})
_BLOCKED_QUERY_VALUES = frozenset({
    "auth", "authenticate", "login", "signin", "register", "logout", "account",
    "cart", "checkout", "payment", "upload", "submit", "search", "calendar",
    "tag", "messages", "inbox",
})
_RESTRICTED_CATEGORIES = frozenset({
    "adult_filtered", "adult_restricted", "adult_extreme_caution",
    "severe_abuse_risk", "severe_content_filtered",
})
_BLOCKED_STORAGE_POLICIES = frozenset({"discard", "metadata_only"})
_BLOCKED_SAFETY_STATES = frozenset({"filtered", "discarded", "metadata_only", "restricted"})
_BLOCKED_REVIEW_STATES = frozenset({"filtered", "restricted", "blocked"})


def _bounded_int(value: Any, *, default: int, upper: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(1, min(parsed, upper))


def _value(source: dict[str, Any], key: str) -> Any:
    policy = source.get("policy")
    if isinstance(policy, dict) and policy.get(key) is not None:
        return policy.get(key)
    return source.get(key)


def _lower_value(source: dict[str, Any], key: str) -> str:
    return str(_value(source, key) or "").strip().casefold()


def _policy_blocked(source: dict[str, Any]) -> bool:
    if not isinstance(source, dict):
        return True
    categories = {
        _lower_value(source, key)
        for key in ("category", "content_category", "primary_category", "classification")
    }
    if categories.intersection(_RESTRICTED_CATEGORIES):
        return True
    if _lower_value(source, "storage_policy") in _BLOCKED_STORAGE_POLICIES:
        return True
    if _lower_value(source, "safety_state") in _BLOCKED_SAFETY_STATES:
        return True
    if _lower_value(source, "review_status") in _BLOCKED_REVIEW_STATES:
        return True
    if _lower_value(source, "queue_policy") == "blocked":
        return True
    if _value(source, "restricted") is True or _value(source, "ui_hidden_default") is True:
        return True
    active = _value(source, "active")
    if active is not None and active in {False, 0, "0"}:
        return True
    return False


def _verified_destination(source: dict[str, Any]) -> bool:
    if not isinstance(source, dict):
        return False
    if _lower_value(source, "verification_state") != "verified":
        return False
    if _lower_value(source, "classification_evidence_source") != "destination_html":
        return False
    try:
        version = int(_value(source, "destination_html_evidence_version") or 0)
    except (TypeError, ValueError):
        return False
    return version >= DESTINATION_HTML_EVIDENCE_VERSION


def _source_url(source: dict[str, Any]) -> str:
    for key in ("url", "source_url", "page_url", "final_url"):
        value = source.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _record_url(record: dict[str, Any]) -> str:
    for key in ("url", "normalized_url", "target_url", "href"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _safe_anchor(record: dict[str, Any]) -> str:
    value = record.get("anchor_text")
    if not isinstance(value, str):
        value = record.get("text") if isinstance(record.get("text"), str) else ""
    value = unquote(value).casefold().strip()
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", value)).strip()[:80]


def _path_tokens(path: str) -> list[str]:
    tokens: list[str] = []
    for segment in unquote(path or "/").casefold().split("/"):
        clean = segment.strip()
        if not clean:
            continue
        tokens.append(clean)
        stem = clean.rsplit(".", 1)[0]
        if stem != clean:
            tokens.append(stem)
    return tokens


def _hard_route_rejection(resolved_url: str) -> str | None:
    """Reject interactive, tracking, or trap-like routes before role inference."""
    if len(resolved_url) > MAX_URL_LENGTH:
        return "TRAP_BLOCKED"
    try:
        parsed = urlsplit(resolved_url)
        decoded_path = unquote(parsed.path or "/")
        pairs = parse_qsl((parsed.query or "").replace(";", "&"), keep_blank_values=True)
    except (TypeError, ValueError, UnicodeError):
        return "INVALID_URL"
    if parsed.scheme.casefold() not in {"http", "https"}:
        return "NON_PUBLIC_SCHEME"
    if parsed.username or parsed.password:
        return "CREDENTIALS_BLOCKED"
    try:
        port = parsed.port
    except ValueError:
        return "INVALID_URL"
    if port is not None and port not in {80, 443}:
        return "PORT_BLOCKED"
    if any(character in decoded_path for character in ("\\", "\x00", "\r", "\n")):
        return "TRAP_BLOCKED"
    segments = [part for part in decoded_path.split("/") if part]
    if (len(segments) > MAX_PATH_SEGMENTS or any(part in {".", ".."} for part in segments)
            or max(Counter(part.casefold() for part in segments).values(), default=0)
            > MAX_REPEATED_PATH_SEGMENT):
        return "TRAP_BLOCKED"
    if len(pairs) > MAX_QUERY_PAIRS:
        return "TRAP_BLOCKED"
    lowered_pairs = [(str(key).casefold(), str(value).casefold()) for key, value in pairs]
    if any(key.startswith("utm_") or key in _SESSION_TRACKING_KEYS for key, _ in lowered_pairs):
        return "SESSION_OR_TRACKING_BLOCKED"
    if any(key in _SEARCH_QUERY_KEYS or key in _CALENDAR_TAG_QUERY_KEYS for key, _ in lowered_pairs):
        return "ROUTE_BLOCKED"
    if any(value in _BLOCKED_QUERY_VALUES for _, value in lowered_pairs):
        return "ROUTE_BLOCKED"
    if set(_path_tokens(decoded_path)).intersection(_BLOCKED_PATH_TOKENS):
        return "ROUTE_BLOCKED"
    return None


def _looks_like_profile_route(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        tokens = set(_path_tokens(parsed.path))
        query = {key.casefold(): value.casefold() for key, value in
                 parse_qsl(parsed.query.replace(";", "&"), keep_blank_values=True)}
    except (TypeError, ValueError, UnicodeError):
        return False
    if tokens.intersection(_PROFILE_PATH_TOKENS):
        return True
    return query.get("mode") == "viewprofile" or query.get("action") == "profile"


def _static_role(url: str, anchor: str) -> str | None:
    try:
        segments = [segment.casefold() for segment in unquote(urlsplit(url).path).split("/") if segment]
        last = segments[-1].rsplit(".", 1)[0] if segments else ""
    except (TypeError, ValueError, UnicodeError):
        return None
    for role, aliases in _STATIC_ROUTE_ALIASES.items():
        if last in aliases:
            return role
    for role, aliases in _STATIC_ANCHOR_ALIASES.items():
        if anchor in aliases:
            return role
    return None


def _forum_candidate(identity: ForumUrlIdentity) -> tuple[str, str] | None:
    if identity.role == "section" and identity.section_id:
        resource = f"forum:{identity.host}:{identity.engine}:section:{identity.section_id}"
        return "section", resource
    if identity.role == "thread" and identity.case_identity:
        return "thread", identity.case_identity
    if identity.role in {"pagination", "post_permalink"}:
        resource = identity.thread_identity or identity.post_identity or identity.case_identity
        if resource:
            return "thread_page", resource
    return None


def _candidate(record: dict[str, Any], source_url: str, source_host: str) -> tuple[dict[str, Any] | None, str | None]:
    if _policy_blocked(record):
        return None, "CHILD_POLICY_BLOCKED"
    method = str(record.get("method") or "GET").strip().upper()
    if method != "GET":
        return None, "NON_GET_ROUTE"
    raw_url = _record_url(record)
    if not raw_url:
        return None, "INVALID_URL"
    try:
        resolved = urljoin(source_url, raw_url)
        parsed = urlsplit(resolved)
    except (TypeError, ValueError, UnicodeError):
        return None, "INVALID_URL"
    route_rejection = _hard_route_rejection(resolved)
    if route_rejection:
        return None, route_rejection
    if (parsed.hostname or "").casefold() != source_host:
        return None, "CROSS_HOST"
    normalized = normalize_url(resolved)
    if not normalized:
        allowed, _ = is_fetch_allowed(resolved, allow_clearnet=False)
        return None, "FETCH_POLICY_BLOCKED" if not allowed else "INVALID_URL"
    allowed, _ = is_fetch_allowed(normalized, allow_clearnet=False)
    if not allowed:
        return None, "FETCH_POLICY_BLOCKED"

    forum = classify_forum_url(resolved)
    forum_match = _forum_candidate(forum)
    if forum_match:
        role, resource_identity = forum_match
        canonical = forum.canonical_url
        variant_rank = 0 if role == "thread" else 1
    elif _looks_like_profile_route(resolved):
        profile_identity = canonical_profile_identity(resolved)
        if not profile_identity:
            return None, "UNSUPPORTED_ROLE"
        role = "profile"
        resource_identity = f"profile:{source_host}:{profile_identity}"
        canonical = canonical_url(normalized)
        variant_rank = 0
    else:
        role = _static_role(resolved, _safe_anchor(record))
        if not role:
            return None, "UNSUPPORTED_ROLE"
        resource_identity = f"route:{source_host}:{role}"
        canonical = canonical_url(normalized)
        variant_rank = 0

    if role not in SUPPORTED_ROLES:
        return None, "UNSUPPORTED_ROLE"
    resource_hash = hashlib.sha256(resource_identity.encode("utf-8")).hexdigest()
    return {
        "url": normalized,
        "canonical_url": canonical,
        "role": role,
        "resource_identity": resource_identity,
        "resource_hash": resource_hash,
        "reason_code": REASON_CODES[role],
        "method": "GET",
        "same_host": True,
        "proposal_only": True,
        "_variant_rank": variant_rank,
    }, None


def revalidate_entity_expansion_proposal(
    source_page: dict[str, Any],
    proposal: dict[str, Any],
    *,
    destination_page: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Reapply the current route and policy boundary immediately before enqueue.

    This is intentionally independent from planning.  It does not infer or
    confirm destination content from URL/anchor wording, does not enqueue, and
    performs no network work.  A previously verified destination may block an
    approval only from its own destination-HTML/analyst policy; an unverified
    URL hint is never promoted into a terminal content decision here.
    """
    if not _verified_destination(source_page):
        return {"allowed": False, "reason_code": "SOURCE_NOT_VERIFIED"}
    if _policy_blocked(source_page):
        return {"allowed": False, "reason_code": "SOURCE_POLICY_BLOCKED"}

    source_url = normalize_url(_source_url(source_page))
    if not source_url or not is_onion_url(source_url):
        return {"allowed": False, "reason_code": "SOURCE_URL_INVALID"}
    if not isinstance(proposal, dict):
        return {"allowed": False, "reason_code": "INVALID_PROPOSAL"}
    proposed_url = str(proposal.get("proposed_url") or proposal.get("url") or "").strip()
    role = str(proposal.get("route_role") or proposal.get("role") or "").strip().casefold()
    resource_identity = str(proposal.get("resource_identity") or "").strip()
    safety_state = str(proposal.get("safety_state") or "").strip().casefold()
    method = str(proposal.get("method") or "GET").strip().upper()
    if (not proposed_url or role not in SUPPORTED_ROLES or not resource_identity
            or safety_state not in {"", "policy_allowed_unverified_destination"}):
        return {"allowed": False, "reason_code": "INVALID_PROPOSAL"}
    if method != "GET":
        return {"allowed": False, "reason_code": "NON_GET_ROUTE"}

    try:
        source_host = (urlsplit(source_url).hostname or "").casefold()
        proposed_host = (urlsplit(proposed_url).hostname or "").casefold()
    except (TypeError, ValueError, UnicodeError):
        return {"allowed": False, "reason_code": "INVALID_URL"}
    if proposed_host != source_host:
        return {"allowed": False, "reason_code": "CROSS_HOST"}
    route_rejection = _hard_route_rejection(proposed_url)
    if route_rejection:
        return {"allowed": False, "reason_code": route_rejection}
    normalized = normalize_url(proposed_url)
    if not normalized:
        return {"allowed": False, "reason_code": "INVALID_URL"}
    allowed, _ = is_fetch_allowed(normalized, allow_clearnet=False)
    if not allowed:
        return {"allowed": False, "reason_code": "FETCH_POLICY_BLOCKED"}

    # Resource identity is a bounded planner invariant, not content evidence.
    if source_host not in resource_identity.casefold():
        return {"allowed": False, "reason_code": "INVALID_PROPOSAL"}

    if isinstance(destination_page, dict) and destination_page:
        verified_policy = _verified_destination(destination_page)
        analyst_policy = bool(destination_page.get("analyst_category"))
        terminal_transport = str(destination_page.get("safety_reason") or "").casefold() in {
            "blocked_extension", "blocked_file_type", "blocked_url_extension",
            "download_like_url", "crawler_trap", "known_dead_url", "invalid_url",
            "malformed_onion", "clearnet_disabled", "blocked_content_type",
        }
        if (verified_policy or analyst_policy or terminal_transport) and _policy_blocked(destination_page):
            return {"allowed": False, "reason_code": "DESTINATION_POLICY_BLOCKED"}

    return {
        "allowed": True,
        "reason_code": "APPROVAL_POLICY_ALLOWED",
        "normalized_url": normalized,
        "source_host_hash": hashlib.sha256(source_host.encode("utf-8")).hexdigest(),
        "network_performed": False,
    }


def _empty_plan(stop_code: str, *, source_host: str = "", considered: int = 0,
                rejections: Counter[str] | None = None, host_cap: int = MAX_PROPOSALS_PER_HOST,
                role_cap: int = MAX_PROPOSALS_PER_ROLE) -> dict[str, Any]:
    return {
        "proposal_only": True,
        "network_performed": False,
        "enqueued": False,
        "stop_code": stop_code,
        "source_host": source_host,
        "source_host_hash": hashlib.sha256(source_host.encode("utf-8")).hexdigest() if source_host else "",
        "considered": considered,
        "eligible_before_caps": 0,
        "proposed": 0,
        "proposals": [],
        "rejections": dict(sorted((rejections or Counter()).items())),
        "caps": {
            "per_host": host_cap,
            "per_role": role_cap,
            "per_resource": MAX_VARIANTS_PER_RESOURCE,
        },
    }


def plan_entity_expansion(
    source_page: dict[str, Any],
    link_records: Iterable[dict[str, Any]] | None,
    *,
    max_proposals: int = MAX_PROPOSALS_PER_HOST,
    max_per_role: int = MAX_PROPOSALS_PER_ROLE,
) -> dict[str, Any]:
    """Return deterministic, bounded expansion proposals without side effects.

    The caller supplies an already-verified destination page and its parsed
    link records.  No proposal is enqueued or fetched here.  A later stage must
    reapply current safety policy and independently classify fetched HTML.
    """
    host_cap = _bounded_int(max_proposals, default=MAX_PROPOSALS_PER_HOST,
                            upper=MAX_PROPOSALS_PER_HOST)
    role_cap = _bounded_int(max_per_role, default=MAX_PROPOSALS_PER_ROLE,
                            upper=MAX_PROPOSALS_PER_ROLE)
    if not _verified_destination(source_page):
        return _empty_plan("SOURCE_NOT_VERIFIED", host_cap=host_cap, role_cap=role_cap)
    if _policy_blocked(source_page):
        return _empty_plan("SOURCE_POLICY_BLOCKED", host_cap=host_cap, role_cap=role_cap)

    raw_source_url = _source_url(source_page)
    source_url = normalize_url(raw_source_url)
    if not source_url or not is_onion_url(source_url):
        return _empty_plan("SOURCE_URL_INVALID", host_cap=host_cap, role_cap=role_cap)
    source_host = (urlsplit(source_url).hostname or "").casefold()

    records = list(link_records) if link_records is not None else []
    if not records:
        return _empty_plan("NO_LINK_RECORDS", source_host=source_host,
                           host_cap=host_cap, role_cap=role_cap)

    rejections: Counter[str] = Counter()
    candidates: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            rejections["INVALID_RECORD"] += 1
            continue
        candidate, rejection = _candidate(record, source_url, source_host)
        if candidate:
            candidates.append(candidate)
        else:
            rejections[rejection or "INVALID_URL"] += 1

    if not candidates:
        return _empty_plan("NO_ELIGIBLE_CANDIDATES", source_host=source_host,
                           considered=len(records), rejections=rejections,
                           host_cap=host_cap, role_cap=role_cap)

    by_resource: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        by_resource[candidate["resource_hash"]].append(candidate)

    winners: list[dict[str, Any]] = []
    for resource_hash in sorted(by_resource):
        variants = sorted(
            by_resource[resource_hash],
            key=lambda item: (
                item["_variant_rank"], _ROLE_PRIORITY[item["role"]],
                item["canonical_url"], item["url"],
            ),
        )
        winners.append(variants[0])
        if len(variants) > MAX_VARIANTS_PER_RESOURCE:
            rejections["DUPLICATE_RESOURCE"] += len(variants) - MAX_VARIANTS_PER_RESOURCE

    winners.sort(key=lambda item: (
        _ROLE_PRIORITY[item["role"]], item["canonical_url"], item["resource_hash"],
    ))
    eligible_before_caps = len(winners)
    proposals: list[dict[str, Any]] = []
    role_counts: Counter[str] = Counter()
    for winner in winners:
        if role_counts[winner["role"]] >= role_cap:
            rejections["ROLE_CAP_REACHED"] += 1
            continue
        if len(proposals) >= host_cap:
            rejections["HOST_CAP_REACHED"] += 1
            continue
        role_counts[winner["role"]] += 1
        winner = {key: value for key, value in winner.items() if not key.startswith("_")}
        proposals.append(winner)

    stop_code = "PLAN_READY" if proposals else "NO_ELIGIBLE_CANDIDATES"
    return {
        "proposal_only": True,
        "network_performed": False,
        "enqueued": False,
        "stop_code": stop_code,
        "source_host": source_host,
        "source_host_hash": hashlib.sha256(source_host.encode("utf-8")).hexdigest(),
        "considered": len(records),
        "eligible_before_caps": eligible_before_caps,
        "proposed": len(proposals),
        "proposals": proposals,
        "rejections": dict(sorted(rejections.items())),
        "caps": {
            "per_host": host_cap,
            "per_role": role_cap,
            "per_resource": MAX_VARIANTS_PER_RESOURCE,
        },
    }


build_entity_expansion_plan = plan_entity_expansion


__all__ = [
    "MAX_PROPOSALS_PER_HOST", "MAX_PROPOSALS_PER_ROLE", "MAX_VARIANTS_PER_RESOURCE",
    "REASON_CODES", "REJECTION_CODES", "STOP_CODES", "SUPPORTED_ROLES",
    "APPROVAL_REVALIDATION_CODES", "build_entity_expansion_plan",
    "plan_entity_expansion", "revalidate_entity_expansion_proposal",
]
