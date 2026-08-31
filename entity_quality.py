"""Deterministic, network-free quality evaluation for public alias candidates.

This module is deliberately standalone.  It does not fetch, persist, log, merge,
or classify pages.  It turns an existing candidate dictionary into a fixed-schema
quality decision that can be recorded by a later integration pass.
"""
from __future__ import annotations

import json
import hashlib
import re
import unicodedata
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path
from typing import Iterable


SCHEMA_VERSION = 1
DEFAULT_RULES_PATH = Path(__file__).with_name("entity_noise_rules.json")

CANDIDATE_STATES = frozenset({
    "accepted_observation",
    "rejected_noise",
    "analyst_review_candidate",
    "analyst_confirmed_identity_evidence",
    "analyst_rejected_identity_evidence",
    "superseded_or_contradicted_observation",
})

REASON_CODES = frozenset({
    "accepted_strong_structural",
    "accepted_corroborated_flat",
    "analyst_confirmed",
    "analyst_rejected",
    "contradicted_observation",
    "rejected_blocked_context",
    "rejected_empty_alias",
    "rejected_filename_like",
    "rejected_generated_label",
    "rejected_generic_role",
    "rejected_invalid_characters",
    "rejected_navigation_template",
    "rejected_numeric_identifier",
    "rejected_profile_route_mismatch",
    "rejected_provider_word",
    "rejected_template_boilerplate",
    "rejected_timestamp_like",
    "rejected_too_long",
    "rejected_too_short",
    "review_confusable_skeleton",
    "review_generated_prefix",
    "review_missing_profile_agreement",
    "review_mixed_script",
    "review_similarity_only",
    "review_weak_evidence",
    "superseded_observation",
})

_RULE_MATCHES = frozenset({"exact", "prefix", "suffix"})
_RULE_ACTIONS = frozenset({"reject", "review"})
_BLOCKED_CONTEXTS = frozenset({
    "action", "actions", "breadcrumb", "breadcrumbs", "cart", "checkout",
    "citation", "docs", "documentation", "footer", "header", "login", "menu",
    "nav", "navigation", "pagination", "product_action", "product-actions",
    "quote", "quoted_post", "search", "template", "toolbar",
})
_STRUCTURAL_EVIDENCE_SUFFIXES = ("_post_author",)
_STRUCTURAL_EVIDENCE_TYPES = frozenset({
    "linked_seller_field", "linked_vendor_field", "marketplace_seller_card",
    "marketplace_vendor_card", "profile_page_identity_match",
    "seller_page_identity_match", "vendor_page_identity_match",
})
_ANALYST_CONFIRMED = frozenset({"accepted", "confirmed", "analyst_confirmed"})
_ANALYST_REJECTED = frozenset({"rejected", "not_identity", "analyst_rejected"})
_SUPERSEDED = frozenset({"superseded", "contradicted"})
_GENERATED_LABEL = re.compile(
    r"(?i)^(?:account|anon|guest|member|seller|user|vendor)[_.-]?(?:\d{3,}|[a-f0-9]{12,})$"
)
_UUID_OR_HASH = re.compile(
    r"(?i)^(?:[a-f0-9]{16,}|[a-f0-9]{8}-[a-f0-9]{4}-[1-5a-f0-9][a-f0-9]{3}-"
    r"[89ab0-9a-f][a-f0-9]{3}-[a-f0-9]{12})$"
)
_TIMESTAMP_SHAPES = (
    re.compile(r"^\d{4}[-_.]\d{1,2}[-_.]\d{1,2}(?:[t_.-]\d{1,2}(?:[:_.-]\d{2}){1,2})?$", re.I),
    re.compile(r"^\d{1,2}[-_.]\d{1,2}[-_.]\d{2,4}$"),
    re.compile(r"^(?:19|20)\d{8,11}$"),
)

# Review-only transliteration.  It is never an identity or merge key.
_CONFUSABLE_TRANSLATION = {
    ord("\u0430"): "a", ord("\u0435"): "e", ord("\u043e"): "o",
    ord("\u0440"): "p", ord("\u0441"): "c", ord("\u0445"): "x",
    ord("\u0443"): "y", ord("\u0456"): "i", ord("\u0458"): "j",
    ord("\u043a"): "k", ord("\u043c"): "m", ord("\u0442"): "t",
    ord("\u0432"): "b", ord("\u043d"): "h",
    ord("\u03b1"): "a", ord("\u03b5"): "e", ord("\u03bf"): "o",
    ord("\u03c1"): "p", ord("\u03c7"): "x", ord("\u03c5"): "y",
    ord("\u03b9"): "i", ord("\u03ba"): "k", ord("\u03bc"): "m",
    ord("\u03c4"): "t",
}


class RuleConfigError(ValueError):
    """Raised when the local deterministic ruleset is invalid."""


def normalize_alias(value: object) -> str:
    """Normalize an alias without turning visual similarity into identity."""
    text = unicodedata.normalize("NFKC", str(value or "")).strip().lstrip("@").casefold()
    return "".join(
        char for char in text
        if char in "_.-" or unicodedata.category(char)[:1] in {"L", "N", "M"}
    )[:128]


def confusable_skeleton(value: object) -> str:
    canonical = normalize_alias(value).translate(_CONFUSABLE_TRANSLATION)
    decomposed = unicodedata.normalize("NFKD", canonical)
    return "".join(char for char in decomposed if unicodedata.category(char) != "Mn")[:128]


def _script_name(char: str) -> str | None:
    if not unicodedata.category(char).startswith("L"):
        return None
    name = unicodedata.name(char, "")
    for script in ("LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW", "HANGUL"):
        if script in name:
            return script.casefold()
    if any(marker in name for marker in ("CJK", "IDEOGRAPH", "HIRAGANA", "KATAKANA")):
        return "cjk"
    return "other"


def script_profile(value: object) -> dict:
    """Return safe script characteristics, not the candidate's surrounding text."""
    normalized = normalize_alias(value)
    counts = Counter(filter(None, (_script_name(char) for char in normalized)))
    scripts = sorted(counts)
    confusable_count = sum(ord(char) in _CONFUSABLE_TRANSLATION for char in normalized)
    return {
        "scripts": scripts,
        "script_counts": {script: counts[script] for script in scripts},
        "mixed_script": len(scripts) > 1,
        "confusable_character_count": confusable_count,
        "review_only_skeleton": confusable_skeleton(normalized),
    }


def load_noise_rules(path: str | Path | None = None) -> dict:
    """Load and strictly validate a local exact/prefix/suffix ruleset."""
    source = Path(path or DEFAULT_RULES_PATH)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuleConfigError(f"alias rules unavailable or invalid: {source.name}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise RuleConfigError("unsupported alias rules schema")
    version = payload.get("ruleset_version")
    rules = payload.get("rules")
    if not isinstance(version, str) or not version.strip() or not isinstance(rules, list):
        raise RuleConfigError("alias rules require a version and rule list")
    clean_rules = []
    seen_ids = set()
    for raw in rules:
        if not isinstance(raw, dict):
            raise RuleConfigError("alias rule must be an object")
        rule_id = str(raw.get("id") or "").strip()
        match = str(raw.get("match") or "").strip()
        action = str(raw.get("action") or "").strip()
        reason = str(raw.get("reason_code") or "").strip()
        patterns = raw.get("patterns")
        if (not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", rule_id)
                or rule_id in seen_ids or match not in _RULE_MATCHES
                or action not in _RULE_ACTIONS or reason not in REASON_CODES
                or not isinstance(patterns, list) or not patterns):
            raise RuleConfigError(f"invalid alias rule: {rule_id or '<missing>'}")
        normalized_patterns = sorted({str(item).casefold().strip() for item in patterns if str(item).strip()})
        if not normalized_patterns:
            raise RuleConfigError(f"alias rule has no valid patterns: {rule_id}")
        seen_ids.add(rule_id)
        clean_rules.append({
            "id": rule_id, "match": match, "action": action,
            "reason_code": reason, "patterns": normalized_patterns,
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "ruleset_version": version.strip(),
        "rules": sorted(clean_rules, key=lambda item: item["id"]),
    }


def _matched_rules(normalized: str, ruleset: dict) -> list[dict]:
    matches = []
    for rule in ruleset["rules"]:
        if any(
            normalized == pattern if rule["match"] == "exact"
            else normalized.startswith(pattern) if rule["match"] == "prefix"
            else normalized.endswith(pattern)
            for pattern in rule["patterns"]
        ):
            matches.append({
                "rule_id": rule["id"],
                "action": rule["action"],
                "reason_code": rule["reason_code"],
            })
    return matches


def _runtime_rule_scope_matches(raw_scope: object, candidate: dict) -> bool:
    """Return whether a local rule is explicitly in scope for this candidate.

    Local rules are deliberately exact and context-bound.  A non-global rule is
    never treated as global merely because an older row used an unknown scope.
    Supported values are ``source_scope:<value>``, ``page_type:<value>`` and
    ``forum_role:<value>``.  This keeps an analyst's correction to a navigation
    label, forum role, or page type from suppressing the same handle elsewhere.
    """
    scope = str(raw_scope or "global").casefold().strip()
    if scope == "global":
        return True
    if ":" not in scope:
        return False
    dimension, expected = scope.split(":", 1)
    if not expected or dimension not in {"source_scope", "page_type", "forum_role"}:
        return False
    actual_by_dimension = {
        "source_scope": candidate.get("source_scope"),
        "page_type": candidate.get("page_type") or candidate.get("page_role"),
        "forum_role": candidate.get("forum_role"),
    }
    actual = actual_by_dimension[dimension]
    return str(actual or "").casefold().strip() == expected


def _runtime_rule_matches(normalized: str, rules: Iterable[dict],
                          candidate: dict) -> tuple[list[dict], str]:
    """Apply validated, scoped analyst rules without regex or executable policy."""
    clean: list[dict] = []
    for raw in rules or ():
        if (not isinstance(raw, dict) or raw.get("enabled") in {False, 0, "0"}
                or not _runtime_rule_scope_matches(raw.get("scope"), candidate)):
            continue
        match = str(raw.get("rule_type") or raw.get("match") or "").casefold().strip()
        pattern = str(raw.get("normalized_pattern") or raw.get("pattern") or "").casefold().strip()
        action = str(raw.get("action") or "").casefold().strip()
        reason = str(raw.get("reason_code") or "").strip()
        if match not in _RULE_MATCHES or action not in _RULE_ACTIONS or reason not in REASON_CODES:
            continue
        if not pattern or len(pattern) > 80:
            continue
        matched = (normalized == pattern if match == "exact"
                   else normalized.startswith(pattern) if match == "prefix"
                   else normalized.endswith(pattern))
        if matched:
            clean.append({
                "rule_id": f"analyst:{int(raw.get('id') or 0)}",
                "action": action, "reason_code": reason,
            })
    clean.sort(key=lambda item: (item["rule_id"], item["action"], item["reason_code"]))
    fingerprint = hashlib.sha256(json.dumps(clean, sort_keys=True).encode("utf-8")).hexdigest()[:12]
    return clean, fingerprint


def _tokens(value: object) -> set[str]:
    if isinstance(value, (list, tuple, set)):
        values = value
    else:
        values = [value]
    return {
        token
        for item in values
        for token in re.sub(r"[^a-z0-9_-]+", " ", str(item or "").casefold()).split()
        if token
    }


def _is_timestamp_like(value: str) -> bool:
    return any(pattern.fullmatch(value) for pattern in _TIMESTAMP_SHAPES)


def _profile_agreement(candidate: dict) -> str:
    explicit = candidate.get("profile_route_agreement")
    if explicit is False or str(explicit).casefold() in {"false", "mismatch", "conflict", "contradicted"}:
        return "mismatch"
    if explicit is True or str(explicit).casefold() in {"true", "match", "matched"}:
        return "matched"
    signals = _tokens(candidate.get("evidence_signals") or candidate.get("evidence_signals_json"))
    if "anchor_slug_match" in signals or "heading_or_title_match" in signals:
        return "matched"
    identity = str(candidate.get("profile_identity") or "")
    if identity and identity.rsplit(":", 1)[-1].isdigit():
        return "numeric_structural_only"
    if identity or candidate.get("profile_url"):
        return "unverified"
    return "missing"


def _structurally_accepted(candidate: dict) -> bool:
    evidence_type = str(candidate.get("evidence_type") or "")
    structural_type = (
        evidence_type in _STRUCTURAL_EVIDENCE_TYPES
        or evidence_type.endswith(_STRUCTURAL_EVIDENCE_SUFFIXES)
    )
    return bool(
        candidate.get("accepted")
        and int(candidate.get("evidence_version") or 0) >= 2
        and float(candidate.get("confidence") or 0) >= 0.90
        and str(candidate.get("evidence_strength") or "").casefold() == "strong"
        and structural_type
        and candidate.get("role")
    )


def _corroborated_flat(candidate: dict) -> bool:
    return bool(
        candidate.get("auto_store_eligible")
        and float(candidate.get("confidence") or 0) >= 0.90
        and str(candidate.get("evidence_type") or "") in {
            "corroborated_public_alias", "cryptographically_corroborated_alias",
        }
    )


def review_only_similarity(left: object, right: object) -> dict:
    """Return a comparison aid that is explicitly forbidden as a merge decision."""
    first = normalize_alias(left)
    second = normalize_alias(right)
    try:
        from rapidfuzz.fuzz import ratio  # type: ignore[import-not-found]
        score = float(ratio(first, second))
        method = "rapidfuzz_optional"
    except ImportError:
        score = SequenceMatcher(None, first, second, autojunk=False).ratio() * 100
        method = "stdlib_sequence_matcher"
    return {
        "score": round(score, 2),
        "method": method,
        "skeleton_match": bool(first and second and confusable_skeleton(first) == confusable_skeleton(second)),
        "review_only": True,
        "merge_allowed": False,
    }


def evaluate_candidate(candidate: dict, *, rules_path: str | Path | None = None,
                       compare_aliases: Iterable[object] = (),
                       extra_rules: Iterable[dict] = ()) -> dict:
    """Evaluate one current-format alias candidate without side effects."""
    if not isinstance(candidate, dict):
        raise TypeError("candidate must be a dictionary")
    ruleset = load_noise_rules(rules_path)
    alias = str(candidate.get("alias") or candidate.get("display_alias")
                or candidate.get("normalized_alias") or "").strip().lstrip("@")
    normalized = normalize_alias(alias)
    profile = script_profile(alias)
    reasons: list[str] = []
    blocking_signals = sorted(
        _tokens(candidate.get("blocking_signals"))
        | (_tokens(candidate.get("source_scope")) & _BLOCKED_CONTEXTS)
        | (_tokens(candidate.get("structural_container")) & _BLOCKED_CONTEXTS)
        | (_tokens(candidate.get("role")) & _BLOCKED_CONTEXTS)
    )
    confidence = max(0.0, min(float(candidate.get("confidence") or 0), 1.0))
    contributions = [{"reason_code": "candidate_input_confidence", "value": round(confidence, 3)}]
    rule_matches = _matched_rules(normalized, ruleset) if normalized else []
    runtime_matches, runtime_fingerprint = _runtime_rule_matches(
        normalized, extra_rules, candidate)
    rule_matches.extend(runtime_matches)

    if not normalized:
        reasons.append("rejected_empty_alias")
    elif len(normalized) < 3:
        reasons.append("rejected_too_short")
    elif len(normalized) > 32:
        reasons.append("rejected_too_long")
    if alias and any(
        char not in "_.-@" and unicodedata.category(char)[:1] not in {"L", "N", "M"}
        for char in alias
    ):
        reasons.append("rejected_invalid_characters")
    if normalized.isdecimal():
        reasons.append("rejected_numeric_identifier")
    if _is_timestamp_like(normalized):
        reasons.append("rejected_timestamp_like")
    if _GENERATED_LABEL.fullmatch(normalized) or _UUID_OR_HASH.fullmatch(normalized):
        reasons.append("rejected_generated_label")
    if candidate.get("generic_role"):
        reasons.append("rejected_generic_role")
    if blocking_signals:
        reasons.append("rejected_blocked_context")
    agreement = _profile_agreement(candidate)
    if agreement == "mismatch":
        reasons.append("rejected_profile_route_mismatch")
    unrelated_hosts = int(candidate.get("unrelated_host_count") or 0)
    template_repetitions = int(candidate.get("template_repetition_count") or 0)
    if unrelated_hosts >= 3 and template_repetitions >= 5:
        reasons.append("rejected_template_boilerplate")
    reasons.extend(match["reason_code"] for match in rule_matches if match["action"] == "reject")

    hard_reasons = [reason for reason in reasons if reason.startswith("rejected_")]
    review_reasons = [match["reason_code"] for match in rule_matches if match["action"] == "review"]
    if profile["mixed_script"]:
        review_reasons.append("review_mixed_script")
    if profile["confusable_character_count"]:
        review_reasons.append("review_confusable_skeleton")
    if agreement in {"missing", "unverified"} and candidate.get("profile_url"):
        review_reasons.append("review_missing_profile_agreement")

    structural = _structurally_accepted(candidate)
    corroborated = _corroborated_flat(candidate)
    analyst = str(candidate.get("analyst_decision") or "").casefold().strip()
    if analyst in _ANALYST_REJECTED:
        state = "analyst_rejected_identity_evidence"
        reasons.append("analyst_rejected")
    elif analyst in _SUPERSEDED:
        state = "superseded_or_contradicted_observation"
        reasons.append("contradicted_observation" if analyst == "contradicted" else "superseded_observation")
    elif hard_reasons:
        state = "rejected_noise"
    elif analyst in _ANALYST_CONFIRMED:
        state = "analyst_confirmed_identity_evidence"
        reasons.append("analyst_confirmed")
    elif review_reasons:
        state = "analyst_review_candidate"
        reasons.extend(review_reasons)
    elif structural:
        state = "accepted_observation"
        reasons.append("accepted_strong_structural")
    elif corroborated:
        state = "accepted_observation"
        reasons.append("accepted_corroborated_flat")
    else:
        state = "analyst_review_candidate"
        reasons.append("review_weak_evidence")

    comparisons = []
    for other in compare_aliases:
        other_normalized = normalize_alias(other)
        if not other_normalized or other_normalized == normalized:
            continue
        comparison = review_only_similarity(normalized, other_normalized)
        if comparison["score"] >= 80 or comparison["skeleton_match"]:
            comparisons.append({"comparison": comparison})
    comparisons.sort(key=lambda item: (-item["comparison"]["score"],
                                       not item["comparison"]["skeleton_match"]))

    unique_reasons = list(dict.fromkeys(reasons))
    return {
        "schema_version": SCHEMA_VERSION,
        "ruleset_version": f"{ruleset['ruleset_version']}+{runtime_fingerprint}",
        "state": state,
        "alias": alias[:64],
        "normalized_alias": normalized[:32],
        "alias_skeleton": profile["review_only_skeleton"][:32],
        "structural_role": str(candidate.get("role") or "unknown")[:40],
        "structural_container": str(candidate.get("source_scope")
                                     or candidate.get("structural_container") or "unknown")[:40],
        "extraction_method": str(candidate.get("evidence_type") or "unknown")[:80],
        "profile_route_agreement": agreement,
        "page_role": str(candidate.get("page_type") or candidate.get("page_role") or "unknown")[:40],
        "forum_role": str(candidate.get("forum_role") or "unknown")[:40],
        "evidence_strength": str(candidate.get("evidence_strength") or "unknown")[:20],
        "bound_identifier_types": sorted({
            str(item.get("type") or "")[:40]
            for item in candidate.get("bound_identifiers") or []
            if isinstance(item, dict) and item.get("type")
        }),
        "blocking_signals": blocking_signals,
        "script_profile": profile,
        "confidence_score": round(confidence, 3),
        "confidence_contributions": contributions,
        "reason_codes": unique_reasons,
        "matched_local_rules": rule_matches,
        "review_similarities": comparisons[:10],
        "automatic_merge_allowed": False,
    }


def evaluate_candidates(candidates: Iterable[dict], *, rules_path: str | Path | None = None,
                        extra_rules: Iterable[dict] = ()) -> list[dict]:
    """Evaluate a bounded iterable and return deterministic ordering."""
    runtime_rules = tuple(extra_rules or ())
    evaluated = [evaluate_candidate(item, rules_path=rules_path, extra_rules=runtime_rules)
                 for item in candidates]
    return sorted(evaluated, key=lambda item: (
        item["state"], item["normalized_alias"], item["extraction_method"],
        item["structural_container"],
    ))


def quality_summary(evaluated: Iterable[dict]) -> dict:
    """Summarize deterministic regression/audit results without logging aliases."""
    rows = list(evaluated)
    states = Counter(str(item.get("state") or "unknown") for item in rows)
    reasons = Counter(
        str(reason)
        for item in rows
        for reason in item.get("reason_codes") or []
    )
    return {
        "total": len(rows),
        "states": {key: states[key] for key in sorted(states)},
        "reason_codes": {key: reasons[key] for key in sorted(reasons)},
    }
