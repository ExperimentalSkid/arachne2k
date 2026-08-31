"""Strict, local-first Deep Discovery eligibility and job helpers.

Deep Discovery is intentionally gated harder than normal actor observation.
It should start only from an already confirmed public profile plus strong,
page-visible pivot evidence. A distinctive nickname alone is useful for manual
review, but not enough to auto-queue work.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

import config_loader
import storage

AUTO_THRESHOLD_DEFAULT = 0.90

STRUCTURAL_PROFILE_EVIDENCE = {
    "profile_page_identity_match",
    "vendor_page_identity_match",
    "seller_page_identity_match",
    "phpbb_post_author",
    "forum_post_author",
    "generic_profile_link",
    "linked_vendor_field",
    "linked_seller_field",
    "seller_label",
    "vendor_label",
}

STRONG_PIVOT_TYPES = {
    "pgp_key_block",
    "pgp_fingerprint",
    "clearnet_url",
    "email",
    "jabber_id",
    "matrix_id",
    "tox_id",
    "session_id",
    "wallet_btc",
    "wallet_eth",
}

WEAK_PIVOT_TYPES = {"username", "telegram_handle"}
GENERIC_DISABLED_ALIASES = {
    "admin", "administrator", "support", "seller", "vendor", "market", "marketplace",
    "moderator", "staff", "escrow", "contact", "service", "unknown", "anonymous",
}

@dataclass(frozen=True)
class DeepDiscoveryEligibility:
    actor_id: int
    site_card_id: int
    score: float
    auto_queue: bool
    confirmed_profile: bool
    strong_pivots: list[str]
    weak_pivots: list[str]
    reasons: list[str]
    blockers: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "site_card_id": self.site_card_id,
            "score": self.score,
            "auto_queue": self.auto_queue,
            "confirmed_profile": self.confirmed_profile,
            "strong_pivots": list(self.strong_pivots),
            "weak_pivots": list(self.weak_pivots),
            "reasons": list(self.reasons),
            "blockers": list(self.blockers),
        }


def _threshold() -> float:
    raw = config_loader.get_str("DEEP_DISCOVERY_AUTO_THRESHOLD", str(AUTO_THRESHOLD_DEFAULT))
    try:
        value = float(raw or AUTO_THRESHOLD_DEFAULT)
    except (TypeError, ValueError):
        value = AUTO_THRESHOLD_DEFAULT
    return max(0.90, min(value, 0.99))


def _auto_enabled() -> bool:
    return config_loader.get_bool("DEEP_DISCOVERY_AUTO_ENABLED", True)


def _safe_json(value: str | None) -> dict:
    try:
        loaded = json.loads(value or "{}")
        return loaded if isinstance(loaded, dict) else {}
    except (TypeError, ValueError):
        return {}


def _site_card_id_from_detail(detail: dict) -> int:
    observations = detail.get("observations") or []
    for observation in observations:
        try:
            card_id = int(observation.get("site_card_id") or 0)
        except (TypeError, ValueError):
            card_id = 0
        if card_id:
            return card_id
    return 0


def score_actor_detail(detail: dict | None) -> DeepDiscoveryEligibility:
    """Score one actor profile for auto Deep Discovery.

    The score is deliberately conservative. Below 0.90 is manual/review-only.
    """
    if not detail or not detail.get("actor"):
        return DeepDiscoveryEligibility(0, 0, 0.0, False, False, [], [], [], ["missing_actor_detail"])
    actor = detail["actor"]
    actor_id = int(actor.get("id") or 0)
    site_card_id = _site_card_id_from_detail(detail)
    alias = str(actor.get("normalized_alias") or "").casefold()
    observations = detail.get("observations") or []
    identifiers = detail.get("identifiers") or []
    reasons: list[str] = []
    blockers: list[str] = []

    if int(actor.get("generic_role") or 0) or alias in GENERIC_DISABLED_ALIASES:
        blockers.append("generic_or_role_alias")

    evidence_types = {str(item.get("evidence_type") or "") for item in observations}
    max_confidence = max([float(item.get("evidence_confidence") or 0) for item in observations] or [0.0])
    seller_pages = sum(1 for item in observations if int(item.get("seller_observation") or 0))
    confirmed_profile = bool(
        evidence_types.intersection(STRUCTURAL_PROFILE_EVIDENCE)
        and max_confidence >= 0.86
    ) or bool(seller_pages and max_confidence >= 0.82)
    if confirmed_profile:
        reasons.append("confirmed_structured_public_profile")
    else:
        blockers.append("profile_not_confirmed")

    identifier_types = {
        str(item.get("indicator_type") or "")
        for item in identifiers
        if int(item.get("count") or 0) > 0
    }
    strong_pivots = sorted(identifier_types.intersection(STRONG_PIVOT_TYPES))
    weak_pivots = sorted(identifier_types.intersection(WEAK_PIVOT_TYPES))
    if strong_pivots:
        reasons.append("strong_public_pivot")
    elif weak_pivots:
        blockers.append("only_weak_handle_or_username_pivot")
    else:
        blockers.append("no_strong_public_pivot")

    score = 0.0
    if confirmed_profile:
        score = 0.70 + min(0.10, max_confidence * 0.10)
    if strong_pivots:
        score += 0.12
    if seller_pages:
        score += min(0.04, seller_pages * 0.02)
        reasons.append("seller_or_vendor_context")
    if len(observations) >= 2:
        score += 0.02
        reasons.append("repeated_observation")
    if any(int(item.get("spain_priority") or 0) for item in observations):
        score += 0.02
        reasons.append("spain_relevant_context")
    if blockers and not (confirmed_profile and strong_pivots):
        score = min(score, 0.79)
    if int(actor.get("generic_role") or 0) or alias in GENERIC_DISABLED_ALIASES:
        score = 0.0
    score = round(min(score, 0.99), 3)
    auto_queue = bool(_auto_enabled() and score >= _threshold() and confirmed_profile and strong_pivots and not blockers[:1])
    if not auto_queue and score >= _threshold():
        blockers.append("auto_gate_failed")
    return DeepDiscoveryEligibility(
        actor_id=actor_id,
        site_card_id=site_card_id,
        score=score,
        auto_queue=auto_queue,
        confirmed_profile=confirmed_profile,
        strong_pivots=strong_pivots,
        weak_pivots=weak_pivots,
        reasons=reasons,
        blockers=blockers,
    )


def build_anchor_snapshot(detail: dict, eligibility: DeepDiscoveryEligibility) -> dict:
    actor = detail.get("actor") or {}
    observations = detail.get("observations") or []
    identifiers = detail.get("identifiers") or []
    return {
        "schema": "arachne.deep_discovery.anchor.v1",
        "actor_id": eligibility.actor_id,
        "site_card_id": eligibility.site_card_id,
        "display_alias": actor.get("display_alias"),
        "normalized_alias": actor.get("normalized_alias"),
        "onion_host": actor.get("onion_host"),
        "eligibility_score": eligibility.score,
        "reasons": eligibility.reasons,
        "strong_pivots": eligibility.strong_pivots,
        "identifier_types": sorted({item.get("indicator_type") for item in identifiers if item.get("indicator_type")}),
        "source_pages": sorted({item.get("url") for item in observations if item.get("url")})[:20],
        "evidence_types": sorted({item.get("evidence_type") for item in observations if item.get("evidence_type")}),
        "immutable_note": "Safe local anchor. No raw restricted content or secrets.",
    }


def maybe_queue_actor(actor_id: int, *, site_card_id: int | None = None) -> dict:
    """Evaluate and queue a Deep Discovery job only when the strict gate passes."""
    detail = storage.get_actor_detail(int(actor_id))
    eligibility = score_actor_detail(detail)
    queued_id = None
    if detail and eligibility.auto_queue:
        effective_card_id = int(
            eligibility.site_card_id if site_card_id is None else site_card_id
        )
        anchor = build_anchor_snapshot(detail, eligibility)
        anchor["site_card_id"] = effective_card_id
        queued_id = storage.create_deep_discovery_job(
            int(actor_id),
            effective_card_id,
            eligibility.score,
            ", ".join(eligibility.reasons[:4]),
            anchor,
            auto_queued=True,
        )
    result = eligibility.as_dict()
    result["queued_job_id"] = queued_id
    return result


def local_first_candidates(detail: dict | None) -> dict:
    """Return local-only candidate context for a confirmed actor anchor."""
    if not detail:
        return {"connections": [], "identifier_types": [], "same_alias_candidates": []}
    actor = detail.get("actor") or {}
    connections = [
        item for item in (detail.get("connections") or [])
        if str(item.get("analyst_decision") or "unreviewed") != "not_same"
    ]
    identifiers = detail.get("identifiers") or []
    same_alias = []
    alias = str(actor.get("normalized_alias") or "").strip()
    if alias:
        for candidate in storage.get_actor_candidates_by_exact_alias(
                alias, exclude_actor_id=int(actor.get("id") or 0), limit=50):
            same_alias.append({
                "actor_id": candidate.get("id"),
                "display_alias": candidate.get("display_alias"),
                "onion_host": candidate.get("onion_host"),
                "confidence": candidate.get("confidence_label"),
            })
    return {
        "connections": [{
            "other_actor_id": item.get("other_actor_id"),
            "other_alias": item.get("other_alias"),
            "other_onion_host": item.get("other_onion_host"),
            "confidence": item.get("confidence_label"),
            "warning_type": item.get("warning_type"),
            "analyst_decision": item.get("analyst_decision") or "unreviewed",
        } for item in connections],
        "identifier_types": sorted({item.get("indicator_type") for item in identifiers if item.get("indicator_type")}),
        "same_alias_candidates": same_alias[:20],
    }


def build_candidate_clusters(anchor: dict, local_results: dict, provider_results: list[dict]) -> list[dict]:
    """Build explainable candidate clusters from local and provider evidence."""
    clusters = []
    local_connections = local_results.get("connections") or []
    confirmed_connections = [
        item for item in local_connections
        if item.get("analyst_decision") == "confirmed_same"
    ]
    local_identifier_types = set(local_results.get("identifier_types") or [])
    for result in provider_results:
        supporting = list(result.get("supporting") or [])
        contradicting = list(result.get("contradicting") or [])
        matching = set(result.get("matching_pivots") or [])
        score = 0.30
        if (
            ("pgp_fingerprint" in matching and "pgp_fingerprint" in local_identifier_types)
            or ("pgp_key_block" in matching and "pgp_key_block" in local_identifier_types)
        ):
            score += 0.42
        if "domain" in matching:
            score += 0.12
        if "handle" in matching:
            score += 0.08
        if confirmed_connections:
            score += min(0.08, len(confirmed_connections) * 0.04)
        score -= min(0.30, len(contradicting) * 0.12)
        score = round(max(0.0, min(score, 0.98)), 3)
        decision = "strong_candidate" if score >= 0.90 else "needs_review" if score >= 0.70 else "quiet_false_or_weak_match"
        clusters.append({
            "candidate_id": result.get("candidate_id"),
            "display_name": result.get("display_name"),
            "score": score,
            "decision": decision,
            "url": result.get("url"),
            "domain": result.get("domain"),
            "provider": result.get("provider"),
            "supporting_evidence": supporting,
            "contradicting_evidence": contradicting,
            "local_evidence": {
                "identifier_types": sorted(local_identifier_types),
                "connections": local_connections,
                "same_alias_candidates": local_results.get("same_alias_candidates") or [],
            },
            "evidence_chain": [
                "confirmed dark-web profile",
                "immutable local anchor snapshot",
                "local Arachne pivot search",
                f"provider result: {result.get('provider')}",
                "analyst review required before any identity claim",
            ],
        })
    return sorted(clusters, key=lambda item: item["score"], reverse=True)


def summary_for_site_card(site_card_id: int) -> list[dict]:
    """Score all live profiles attached to a Site Card for the dashboard."""
    summaries = []
    for profile in storage.get_site_card_actor_profiles(int(site_card_id)):
        detail = storage.get_actor_detail(int(profile["actor_id"]))
        eligibility = score_actor_detail(detail)
        summaries.append({
            "profile": profile,
            "eligibility": eligibility.as_dict(),
            "local_first": local_first_candidates(detail),
        })
    return sorted(summaries, key=lambda item: item["eligibility"]["score"], reverse=True)
