"""Pure, advisory-only analysis for the classification decision ledger.

This module deliberately has no dependency on crawler, classifier, storage,
Site Card, Spain, urgency, alert, or merge code.  It accepts already-loaded
ledger-shaped rows and returns sanitized observations.  It cannot apply a
classification or change production state.

The rates produced here describe only observed, analyst-reviewed decisions.
They are not statistical model accuracy and must not be used as an automatic
learning or policy input.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Iterable, Mapping


MINIMUM_ADVISORY_SAMPLE = 10
DECISION_MODE = "advisory_only"

SAFETY_CATEGORIES = frozenset({
    "adult_filtered", "adult_restricted", "severe_abuse_risk",
})

CANONICAL_CATEGORIES = frozenset({
    "unknown", "general_other", "directory_index", "search_engine", "forum_social",
    "hosting_services", "contact_infrastructure", "infosec_research",
    "privacy_anonymity", "news_media", "religion_spirituality",
    "education_reference", "technology_software", "finance_cryptocurrency",
    "activism_civil_society", "personal_blog", "communication_services",
    "file_storage_sharing", "arts_culture", "health_wellness", "marketplace",
    "marketplace_drugs", "marketplace_weapons", "marketplace_fraud",
    "marketplace_credentials", "marketplace_leaks", "marketplace_counterfeit",
    "marketplace_services", "weapons_arms", "drugs", "leaks_data", "credentials",
    "malware_hacking", "fraud_financial", "extremist_recruitment",
    "adult_filtered", "adult_restricted", "severe_abuse_risk", "spam_noise",
    "dead_softdead",
})

EVIDENCE_BUCKETS = (
    "title", "heading", "url", "body_safe_snippet", "link_pattern",
    "form_checkout_login", "negative_contradicting", "other",
)

PAGE_STATE_TYPES = frozenset({
    "login_wall", "login_gate", "error_page", "empty_placeholder",
    "download_file", "parked_page",
})

SAFE_UPDATE_REASONS = frozenset({
    "awaiting_destination_html",
    "page_state_cannot_replace_site_category",
    "page_state_has_no_trusted_html_category",
    "thin_page_preserved_previous_category",
    "directory_links_do_not_define_parent_category",
    "confidence_weighted_page_evidence",
    "analyst_category_preserved",
    "no_safe_page_allowed_category_update",
})

LOCKED_PRODUCTION_DIMENSIONS = (
    "production_classification", "safety", "spain", "urgency",
    "storage_and_queue_policy", "alerts", "site_card_identity",
    "merge_decisions", "analyst_overrides",
)

_ANALYST_DECISIONS = frozenset({"analyst_confirmed", "analyst_corrected"})
_PREDICTION_DECISIONS = frozenset({
    "accepted", "abstained", "needs_review", "monitor_only", "restricted",
})
_CODE_RE = re.compile(r"[^a-z0-9_]+")


@dataclass(frozen=True)
class _Decision:
    decision_key: str
    order_id: int
    timestamp: datetime
    url_key: str | None
    card_key: str | None
    stage: str
    proposed_category: str
    final_category: str
    previous_category: str
    confidence_label: str
    confidence_score: float
    decision: str
    classifier_version: str
    analyst_corrected: bool
    trusted_destination_html: bool
    page_type: str
    page_type_confidence: str
    content_quality: str
    category_update_allowed: bool | None
    category_update_reason: str
    evidence_bucket_counts: dict[str, int]
    evidence_family_count: int

    @property
    def safety_locked(self) -> bool:
        return (
            self.final_category in SAFETY_CATEGORIES
            or self.proposed_category in SAFETY_CATEGORIES
            or self.previous_category in SAFETY_CATEGORIES
            or self.decision == "restricted"
        )


def _mapping(row: object) -> dict:
    if isinstance(row, Mapping):
        return dict(row)
    try:
        return dict(row)  # sqlite3.Row and similar row objects
    except (TypeError, ValueError):
        return {}


def _safe_json(value: object, expected_type: type, default):
    if isinstance(value, expected_type):
        return value
    if not isinstance(value, str) or not value:
        return default
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return parsed if isinstance(parsed, expected_type) else default


def _safe_code(value: object, *, default: str = "unknown", maximum: int = 80) -> str:
    text = str(value or "").strip().casefold().replace("-", "_").replace(" ", "_")
    text = _CODE_RE.sub("_", text).strip("_")[:maximum]
    return text or default


def _category(value: object) -> str:
    code = _safe_code(value)
    return code if code in CANONICAL_CATEGORIES else "unknown"


def _bounded_float(value: object) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number != number:  # NaN
        return 0.0
    return round(max(0.0, min(1.0, number)), 4)


def _bounded_int(value: object, *, minimum: int = 0, maximum: int = 1_000_000) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return minimum
    return max(minimum, min(maximum, number))


def _bool_or_none(value: object) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    code = str(value).strip().casefold()
    if code in {"true", "yes", "1", "allowed"}:
        return True
    if code in {"false", "no", "0", "blocked"}:
        return False
    return None


def _timestamp(value: object) -> datetime:
    text = str(value or "").strip()
    if not text:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _correlation_key(kind: str, value: object) -> str | None:
    if value in {None, ""}:
        return None
    material = f"classification-quality-v1:{kind}:{value}".encode("utf-8", "replace")
    return hashlib.sha256(material).hexdigest()[:24]


def _evidence_counts(row: dict, metadata: dict) -> tuple[dict[str, int], int]:
    counts = {bucket: 0 for bucket in EVIDENCE_BUCKETS}
    raw_buckets = (
        row.get("category_evidence_json")
        or metadata.get("category_evidence_counts")
        or metadata.get("evidence_bucket_counts")
    )
    buckets = _safe_json(raw_buckets, dict, {})
    for bucket in EVIDENCE_BUCKETS:
        value = buckets.get(bucket)
        if isinstance(value, (list, tuple, set)):
            counts[bucket] = min(100, len(value))
        else:
            counts[bucket] = _bounded_int(value, maximum=100)
    families = _safe_json(row.get("evidence_families_json"), list, [])
    family_count = min(100, len(families))
    if not sum(counts.values()) and family_count:
        counts["other"] = family_count
    return counts, family_count


def _normalize_internal(row: object) -> _Decision:
    source = _mapping(row)
    metadata = _safe_json(source.get("safe_metadata_json"), dict, {})
    stage = _safe_code(source.get("stage"), maximum=32)
    decision = _safe_code(source.get("decision"), default="unclassified", maximum=40)
    analyst_corrected = bool(_bounded_int(source.get("analyst_corrected"), maximum=1))
    evidence_source = _safe_code(
        source.get("classification_evidence_source")
        or metadata.get("classification_evidence_source"),
        default="",
        maximum=40,
    )
    explicit_trust = _bool_or_none(
        source.get("trusted_destination_html")
        if source.get("trusted_destination_html") is not None
        else (
            metadata.get("trusted_destination_html")
            if metadata.get("trusted_destination_html") is not None
            else metadata.get("destination_evidence_trusted")
        )
    )
    trusted_html = (
        stage == "page"
        and not analyst_corrected
        and decision not in _ANALYST_DECISIONS
        and evidence_source in {"", "destination_html"}
        and explicit_trust is not False
    )
    evidence_counts, family_count = _evidence_counts(source, metadata)
    order_id = _bounded_int(source.get("id"), maximum=2_147_483_647)
    return _Decision(
        decision_key=_correlation_key("decision", source.get("id") or (
            str(source.get("ts") or "") + ":" + str(source.get("stage") or "")
        )) or "0" * 24,
        order_id=order_id,
        timestamp=_timestamp(source.get("ts")),
        url_key=_correlation_key("url", source.get("onion_url_id")),
        card_key=_correlation_key("card", source.get("site_card_id")),
        stage=stage,
        proposed_category=_category(source.get("proposed_category")),
        final_category=_category(source.get("final_category")),
        previous_category=_category(source.get("previous_category")),
        confidence_label=_safe_code(source.get("confidence_label"), default="low", maximum=20),
        confidence_score=_bounded_float(source.get("confidence_score")),
        decision=decision,
        classifier_version=_safe_code(
            source.get("classifier_version"), default="unknown", maximum=80),
        analyst_corrected=analyst_corrected,
        trusted_destination_html=trusted_html,
        page_type=_safe_code(
            source.get("page_type") or metadata.get("page_type"), maximum=40),
        page_type_confidence=_safe_code(
            source.get("page_type_confidence") or metadata.get("page_type_confidence"),
            default="low",
            maximum=20,
        ),
        content_quality=_safe_code(
            source.get("content_quality") or metadata.get("content_quality"),
            maximum=32,
        ),
        category_update_allowed=_bool_or_none(
            source.get("category_update_allowed")
            if source.get("category_update_allowed") is not None
            else metadata.get("category_update_allowed")
        ),
        category_update_reason=_safe_code(
            source.get("category_update_reason") or metadata.get("category_update_reason"),
            default="unknown",
            maximum=80,
        ),
        evidence_bucket_counts=evidence_counts,
        evidence_family_count=family_count,
    )


def _public_decision(item: _Decision) -> dict:
    """Return only metadata-safe codes and one-way correlation keys."""
    return {
        "decision_key": item.decision_key,
        "stage": item.stage,
        "proposed_category": item.proposed_category,
        "final_category": item.final_category,
        "previous_category": item.previous_category,
        "confidence_label": item.confidence_label,
        "confidence_score": item.confidence_score,
        "decision": item.decision,
        "classifier_version": item.classifier_version,
        "analyst_corrected": item.analyst_corrected,
        "trusted_destination_html": item.trusted_destination_html,
        "page_type": item.page_type,
        "page_type_confidence": item.page_type_confidence,
        "content_quality": item.content_quality,
        "category_update_allowed": item.category_update_allowed,
        "category_update_reason": item.category_update_reason,
        "evidence_bucket_counts": dict(item.evidence_bucket_counts),
        "evidence_family_count": item.evidence_family_count,
        "safety_excluded": item.safety_locked,
    }


def normalize_ledger_row(row: object) -> dict:
    """Normalize one ledger row without retaining raw URLs, text, or identifiers."""
    return _public_decision(_normalize_internal(row))


def _is_page_prediction(item: _Decision) -> bool:
    return (
        item.stage == "page"
        and item.trusted_destination_html
        and not item.analyst_corrected
        and item.decision in _PREDICTION_DECISIONS
    )


def _latest_prediction_snapshot(items: Iterable[_Decision]) -> list[_Decision]:
    """Return the latest trusted prediction per URL without losing URL-less events."""
    latest: dict[str, _Decision] = {}
    for item in sorted(
        items, key=lambda value: (value.timestamp, value.order_id, value.decision_key)
    ):
        # A decision without an onion URL identity cannot be safely collapsed
        # with another event. Its one-way decision key is therefore its own
        # snapshot identity.
        latest[item.url_key or item.decision_key] = item
    return sorted(
        latest.values(),
        key=lambda value: (value.timestamp, value.order_id, value.decision_key),
    )


def select_page_predictions(rows: Iterable[object]) -> list[dict]:
    """Select only automatic page-stage destination-HTML decisions."""
    selected = sorted(
        (_normalize_internal(row) for row in rows),
        key=lambda item: (item.timestamp, item.order_id, item.decision_key),
    )
    return [_public_decision(item) for item in selected if _is_page_prediction(item)]


def _is_analyst_correction(item: _Decision) -> bool:
    return item.stage == "analyst" or item.analyst_corrected


def _unknown_reason(item: _Decision) -> str:
    if item.content_quality in {"empty", "thin", "unavailable"}:
        return f"content_{item.content_quality}"
    if item.page_type in PAGE_STATE_TYPES:
        return "page_state_not_classifiable"
    if (
        item.category_update_reason in SAFE_UPDATE_REASONS
        and item.category_update_reason != "confidence_weighted_page_evidence"
    ):
        return item.category_update_reason
    if item.evidence_bucket_counts.get("negative_contradicting"):
        return "contradicting_evidence"
    if item.proposed_category != "unknown":
        return "weak_uncorroborated_suggestion"
    if item.evidence_family_count == 0 and not sum(item.evidence_bucket_counts.values()):
        return "insufficient_evidence"
    return "low_confidence_evidence"


def _pair_rows(rows: Iterable[object]) -> list[tuple[_Decision, _Decision]]:
    ordered = sorted(
        (_normalize_internal(row) for row in rows),
        key=lambda item: (item.timestamp, item.order_id, item.decision_key),
    )
    by_url: dict[str, list[_Decision]] = defaultdict(list)
    by_card: dict[str, list[_Decision]] = defaultdict(list)
    pairs: list[tuple[_Decision, _Decision]] = []
    for item in ordered:
        if _is_page_prediction(item):
            if item.url_key:
                by_url[item.url_key].append(item)
            if item.card_key:
                by_card[item.card_key].append(item)
            continue
        if not _is_analyst_correction(item):
            continue
        candidates: list[_Decision] = []
        if item.url_key:
            candidates = by_url.get(item.url_key, [])
        elif item.card_key:
            # Card fallback is deliberately allowed only when the correction
            # itself has no URL identity.
            candidates = by_card.get(item.card_key, [])
        if candidates:
            pairs.append((candidates[-1], item))
    return pairs


def pair_analyst_corrections(rows: Iterable[object]) -> list[dict]:
    """Pair corrections with the nearest preceding trusted page prediction."""
    result = []
    for prediction, correction in _pair_rows(rows):
        safety_excluded = prediction.safety_locked or correction.safety_locked
        analyst_category = correction.final_category
        changed = prediction.final_category != analyst_category
        pair_key = hashlib.sha256(
            f"{prediction.decision_key}:{correction.decision_key}".encode("ascii")
        ).hexdigest()[:24]
        result.append({
            "pair_key": pair_key,
            "baseline_category": prediction.final_category,
            "analyst_category": analyst_category,
            "changed": bool(changed),
            "baseline_decision": prediction.decision,
            "baseline_confidence_score": prediction.confidence_score,
            "classifier_version": prediction.classifier_version,
            "unknown_reason": (
                _unknown_reason(prediction)
                if prediction.final_category == "unknown"
                else None
            ),
            "evidence_bucket_counts": dict(prediction.evidence_bucket_counts),
            "safety_excluded": bool(safety_excluded),
        })
    return result


def _confidence_label(sample_size: int, observed_share: float) -> str:
    if sample_size >= 30 and observed_share >= 0.60:
        return "medium"
    return "low"


def build_shadow_observations(
    rows: Iterable[object], *, minimum_sample: int = MINIMUM_ADVISORY_SAMPLE,
) -> list[dict]:
    """Build aggregate, proposal-only observations from repeated outcomes.

    No single decision can create an observation.  The caller cannot lower the
    minimum below ten.
    """
    material = list(rows)
    threshold = max(MINIMUM_ADVISORY_SAMPLE, _bounded_int(minimum_sample, maximum=100_000))
    pairs = [
        pair for pair in pair_analyst_corrections(material)
        if not pair["safety_excluded"]
    ]
    observations: list[dict] = []
    reviewed_by_baseline = Counter(pair["baseline_category"] for pair in pairs)
    transitions = Counter(
        (pair["baseline_category"], pair["analyst_category"])
        for pair in pairs if pair["changed"]
    )
    for (baseline, analyst), sample_size in sorted(transitions.items()):
        if sample_size < threshold:
            continue
        reviewed = reviewed_by_baseline[baseline]
        share = round(sample_size / reviewed, 4) if reviewed else 0.0
        observations.append({
            "observation_type": "repeated_correction_pattern",
            "baseline_category": baseline,
            "advisory_category": analyst,
            "sample_size": sample_size,
            "reviewed_baseline_count": reviewed,
            "observed_share": share,
            "confidence": _confidence_label(sample_size, share),
            "reason_codes": [
                "analyst_corrections_repeated",
                "correlation_not_automatic_rule",
            ],
            "decision_mode": DECISION_MODE,
            "locked_dimensions": list(LOCKED_PRODUCTION_DIMENSIONS),
        })

    prediction_events = [
        item for item in (_normalize_internal(row) for row in material)
        if _is_page_prediction(item) and not item.safety_locked
    ]
    predictions = _latest_prediction_snapshot(prediction_events)
    unknown_groups = Counter(
        _unknown_reason(item) for item in predictions if item.final_category == "unknown"
    )
    for reason_code, sample_size in sorted(unknown_groups.items()):
        if sample_size < threshold:
            continue
        observations.append({
            "observation_type": "repeated_unknown_pattern",
            "baseline_category": "unknown",
            "advisory_category": None,
            "sample_size": sample_size,
            "reviewed_baseline_count": 0,
            "observed_share": 0.0,
            "confidence": "low",
            "reason_codes": [reason_code, "more_evidence_needed"],
            "decision_mode": DECISION_MODE,
            "locked_dimensions": list(LOCKED_PRODUCTION_DIMENSIONS),
        })
    return observations


def analyze_classification_quality(
    rows: Iterable[object], *, minimum_sample: int = MINIMUM_ADVISORY_SAMPLE,
) -> dict:
    """Return honest aggregate rates and conservative shadow observations."""
    material = list(rows)
    prediction_events = [
        item for item in (_normalize_internal(row) for row in material)
        if _is_page_prediction(item)
    ]
    predictions_internal = _latest_prediction_snapshot(prediction_events)
    safety_predictions = [item for item in predictions_internal if item.safety_locked]
    predictions = [item for item in predictions_internal if not item.safety_locked]
    pairs = pair_analyst_corrections(material)
    comparable_pairs = [pair for pair in pairs if not pair["safety_excluded"]]
    changed_pairs = [pair for pair in comparable_pairs if pair["changed"]]

    decision_counts = Counter(item.decision for item in predictions)
    category_counts = Counter(item.final_category for item in predictions)
    unknown_reason_groups = Counter(
        _unknown_reason(item) for item in predictions if item.final_category == "unknown"
    )
    correction_pairs = Counter(
        (pair["baseline_category"], pair["analyst_category"])
        for pair in changed_pairs
    )
    total = len(predictions)
    reviewed = len(comparable_pairs)
    accepted = decision_counts.get("accepted", 0)
    uncertain = decision_counts.get("abstained", 0) + decision_counts.get("needs_review", 0)
    return {
        "scope": "page_stage_destination_html_only",
        "decision_mode": DECISION_MODE,
        "minimum_advisory_sample": max(
            MINIMUM_ADVISORY_SAMPLE,
            _bounded_int(minimum_sample, maximum=100_000),
        ),
        "prediction_event_count": len(prediction_events),
        "prediction_count": total,
        "safety_excluded_count": len(safety_predictions),
        "reviewed_prediction_count": reviewed,
        "changed_after_review_count": len(changed_pairs),
        "accepted_rate": round(accepted / total, 4) if total else 0.0,
        "uncertain_rate": round(uncertain / total, 4) if total else 0.0,
        "unknown_rate": round(category_counts.get("unknown", 0) / total, 4) if total else 0.0,
        "observed_review_disagreement_rate": (
            round(len(changed_pairs) / reviewed, 4) if reviewed else 0.0
        ),
        "decision_counts": dict(sorted(decision_counts.items())),
        "category_counts": dict(sorted(category_counts.items())),
        "unknown_reason_groups": dict(sorted(unknown_reason_groups.items())),
        "correction_pairs": [
            {
                "baseline_category": baseline,
                "analyst_category": analyst,
                "count": count,
            }
            for (baseline, analyst), count in sorted(correction_pairs.items())
        ],
        "shadow_observations": build_shadow_observations(
            material, minimum_sample=minimum_sample),
        "locked_dimensions": list(LOCKED_PRODUCTION_DIMENSIONS),
        "rate_note": (
            "Observed rates cover trusted page decisions only; disagreement uses "
            "only decisions that received a comparable analyst review."
        ),
    }


__all__ = [
    "DECISION_MODE",
    "LOCKED_PRODUCTION_DIMENSIONS",
    "MINIMUM_ADVISORY_SAMPLE",
    "SAFETY_CATEGORIES",
    "analyze_classification_quality",
    "build_shadow_observations",
    "normalize_ledger_row",
    "pair_analyst_corrections",
    "select_page_predictions",
]
