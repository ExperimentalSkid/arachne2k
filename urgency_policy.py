"""Operational triage policy.

This layer is intentionally separate from category/risk/safety.  A page can be
high policy-risk but still only monitor if it has no Spain/actionable evidence.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable, Mapping, Any

from classification_schema import normalize_page_type


@dataclass(frozen=True)
class TriageDecision:
    level: str
    reason: str
    score: int
    triggers: list[str]


def _loads(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    try:
        loaded = json.loads(value or "[]")
        return [str(item) for item in loaded if item] if isinstance(loaded, list) else []
    except (TypeError, ValueError):
        return []


def _text(row: Mapping[str, Any]) -> str:
    parts: list[str] = []
    for key in ("primary_category", "risk_category", "tags", "risk_flags", "category_reason",
                "spain_evidence_type", "spain_priority_reason", "urgent_reason", "review_reason"):
        value = row.get(key)
        if isinstance(value, str):
            parts.append(value)
        else:
            parts.extend(_loads(value))
    return " ".join(parts).casefold()


def _row_signals(row: Mapping[str, Any]) -> dict[str, bool]:
    """Return actionable signal families from one evidence row only."""
    text = _text(row)
    page_type = normalize_page_type(row.get("page_type"))
    evidence_type = str(row.get("spain_evidence_type") or "").casefold()
    leak = any(term in text for term in ("leak", "database", "breach", "credentials", "exposed_data"))
    fraud = any(term in text for term in ("fraud", "carding", "fullz", "bank logs", "dumps", "cashout"))
    weapons = "weapon" in text or "arms" in text
    marketplace_direct = page_type in {
        "marketplace_front", "marketplace_listing", "vendor_profile", "cart_checkout"
    } or any(term in text for term in (
        "marketplace_front", "marketplace_listing", "vendor_profile",
        "direct_marketplace_needs_check", "listing_page", "vendor_page",
    ))
    direct_spain_target = evidence_type in {
        "spanish_identity_data", "spanish_financial_target", "spanish_institution_target",
        "spanish_domain_threat_context",
    } or (
        evidence_type == "direct_seller_geo"
        and str(row.get("seller_geo_confidence") or "").casefold() == "high"
        and bool(int(row.get("spain_actionable") or 0))
    )
    return {
        "leak": leak,
        "fraud": fraud,
        "weapons": weapons,
        "marketplace_direct": marketplace_direct,
        "direct_spain_target": direct_spain_target,
    }


def _score_gate(row: Mapping[str, Any]) -> bool:
    value = row.get("spain_evidence_score")
    if value in {None, ""}:
        # Compatibility for reviewed legacy evidence created before scores were
        # persisted. New classifier rows always carry an explicit score.
        return True
    try:
        return int(value) >= 75
    except (TypeError, ValueError):
        return False


def _strong_spain_row(row: Mapping[str, Any]) -> bool:
    if not row.get("spain_priority") or int(row.get("spain_context_only") or 0):
        return False
    if not _score_gate(row):
        return False
    return (
        str(row.get("spain_relevance") or "").casefold() == "high"
        or str(row.get("seller_geo_confidence") or "").casefold() == "high"
        or bool(int(row.get("spain_actionable") or 0))
    )


def decide_triage(rows: Iterable[Mapping[str, Any]]) -> TriageDecision:
    rows = list(rows)
    if not rows:
        return TriageDecision("monitor", "No evidence rows available", 0, [])
    joined = " ".join(_text(row) for row in rows)
    severe = any(row.get("primary_category") == "severe_abuse_risk"
                 or row.get("storage_policy") == "metadata_only" and "severe" in _text(row)
                 for row in rows)
    if severe:
        return TriageDecision("urgent", "Restricted severe-safety metadata requires controlled handling", 100,
                              ["severe_safety"])
    spain_rows = [row for row in rows if row.get("spain_priority") and not int(row.get("spain_context_only") or 0)]
    strong_spain_rows = [row for row in spain_rows if _strong_spain_row(row)]
    strong_spain = bool(strong_spain_rows)
    leak = any(term in joined for term in ("leak", "database", "breach", "credentials", "exposed_data"))
    fraud = any(term in joined for term in ("fraud", "carding", "fullz", "bank", "dumps", "cashout"))
    weapons = "weapon" in joined or "arms" in joined
    row_signals = [_row_signals(row) for row in rows]
    marketplace_direct = any(signals["marketplace_direct"] for signals in row_signals)
    triggers: list[str] = []
    if spain_rows:
        triggers.append("spain_evidence")
    if leak:
        triggers.append("leak_evidence")
    if fraud:
        triggers.append("fraud_evidence")
    if weapons:
        triggers.append("weapons_evidence")
    if marketplace_direct:
        triggers.append("direct_marketplace_structure")
    # Spain and actionability must be supported by the same verified URL row.
    # A Spain-only homepage plus an unrelated risky child must never synthesize
    # a new urgent fact at card rollup time.
    coherent_rows = [row for row in strong_spain_rows if any(_row_signals(row).values())]
    if coherent_rows:
        coherent_signals = [_row_signals(row) for row in coherent_rows]
        coherent_triggers = ["spain_evidence"]
        for key, label in (
            ("leak", "leak_evidence"), ("fraud", "fraud_evidence"),
            ("weapons", "weapons_evidence"), ("marketplace_direct", "direct_marketplace_structure"),
            ("direct_spain_target", "direct_spain_target"),
        ):
            if any(signals[key] for signals in coherent_signals):
                coherent_triggers.append(label)
        return TriageDecision("urgent", "Strong Spain relevance with actionable threat evidence", 90,
                              coherent_triggers)
    if strong_spain:
        return TriageDecision("alert", "Strong Spain relevance found", 75, triggers)
    if spain_rows:
        return TriageDecision("needs_check", "Spain evidence found but actionability is not high", 55, triggers)
    if any(int(row.get("urgent_flag") or 0) for row in rows) and (leak or fraud or weapons):
        return TriageDecision("needs_check", "Non-Spain direct-risk evidence; monitor unless Spain evidence appears", 40,
                              triggers or ["direct_risk_non_spain"])
    if fraud or weapons or marketplace_direct:
        return TriageDecision("needs_check", "Non-Spain direct-risk evidence; monitor unless Spain evidence appears", 40,
                              triggers or ["direct_risk_non_spain"])
    return TriageDecision("monitor", "No strong Spain/actionable evidence", 10, triggers)
