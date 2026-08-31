"""Optional analyst-managed entity registry and conservative handle matching.

The registry is empty by default and remains separate from crawler observations.
Adding a reference never means Arachne discovered or confirmed an identity.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from entity_extractor import normalize_public_alias
from paths import BASE_DIR

REGISTRY_PATH = Path(BASE_DIR) / "identity_registry.json"
STRUCTURED_FIELDS = {
    "profile_username", "profile_title", "forum_author", "post_author",
    "vendor_profile", "seller_profile", "vendor_card", "handle_field",
}


@lru_cache(maxsize=1)
def load_registry() -> dict:
    try:
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema_version": 1, "entities": []}
    if not isinstance(data, dict):
        return {"schema_version": 1, "entities": []}
    entities = data.get("entities")
    if not isinstance(entities, list):
        data["entities"] = []
    return data


def reference_entities() -> list[dict]:
    """Return bounded analyst-managed references; the bundled registry is empty."""
    return [dict(item) for item in load_registry().get("entities", []) if isinstance(item, dict)]


def _context_hit(context_text: str, contexts: list[str] | None) -> tuple[bool, list[str]]:
    haystack = (context_text or "").casefold()
    hits = [str(item) for item in contexts or [] if str(item).casefold() in haystack]
    return bool(hits), hits[:5]


def _candidate(entity: dict, handle: dict, *, observed_alias: str, score: float,
               decision: str, evidence: list[dict], missing: list[str]) -> dict:
    return {
        "entity_id": entity.get("id"),
        "reference_record": True,
        "entity_type": entity.get("entity_type") or "unknown",
        "canonical_name": entity.get("canonical_name") or "Reference entity",
        "observed_alias": observed_alias,
        "matched_handle": handle.get("value"),
        "policy": handle.get("policy") or "contextual_only",
        "score": round(max(0.0, min(float(score), 1.0)), 3),
        "decision": decision,
        "attribution_status": entity.get("attribution_status") or "unresolved",
        "legal_status": entity.get("legal_status") or "unknown",
        "status_as_of": entity.get("status_as_of"),
        "roles": entity.get("roles") or [],
        "sources": entity.get("sources") or [],
        "evidence": evidence[:8],
        "missing": missing[:8],
    }


def match_observed_alias(observed_alias: str, *, context_text: str = "",
                         observed_field: str = "unknown",
                         extra_signals: list[str] | None = None) -> list[dict]:
    """Score one observed handle/profile value against optional analyst references."""
    normalized = normalize_public_alias(observed_alias)
    if not normalized:
        return []
    structured = observed_field in STRUCTURED_FIELDS
    signals = {str(item).casefold() for item in (extra_signals or [])}
    candidates: list[dict] = []
    for entity in reference_entities():
        for handle in entity.get("handles") or []:
            if normalize_public_alias(handle.get("value") or "") != normalized:
                continue
            policy = str(handle.get("policy") or "contextual_only")
            context_ok, context_hits = _context_hit(context_text, handle.get("contexts"))
            evidence = [{
                "type": "exact_handle",
                "value": handle.get("value"),
                "weight": 0.55,
                "location": observed_field,
            }]
            missing: list[str] = []
            if structured:
                evidence.append({"type": "structured_field", "value": observed_field,
                                 "weight": 0.18, "location": observed_field})
            else:
                missing.append("structured profile/author/vendor field")
            if context_ok:
                evidence.append({"type": "operation_context", "value": ", ".join(context_hits),
                                 "weight": 0.18, "location": "page_context"})
            elif handle.get("contexts"):
                missing.append("required context: " + ", ".join(handle.get("contexts") or []))
            if "pgp_match" in signals:
                evidence.append({"type": "pgp_match", "value": "matched public key fingerprint",
                                 "weight": 0.25, "location": "profile_identifier"})

            if policy == "disabled_global":
                if entity.get("entity_type") in {"group", "ransomware_operation", "darknet_market", "forum"}:
                    candidates.append(_candidate(
                        entity, handle, observed_alias=observed_alias, score=0.35,
                        decision="context_only", evidence=evidence[:1],
                        missing=["disabled as person identifier"],
                    ))
                continue
            if policy == "exact_safe":
                score = 0.55 + (0.2 if structured else 0.0) + (0.15 if context_ok else 0.0)
                decision = "needs_review" if score < 0.85 else "strong_candidate"
                candidates.append(_candidate(
                    entity, handle, observed_alias=observed_alias, score=score,
                    decision=decision, evidence=evidence, missing=missing,
                ))
            else:
                score = 0.35 + (0.2 if structured else 0.0) + (0.25 if context_ok else 0.0)
                decision = "needs_review" if context_ok and structured else "insufficient_context"
                candidates.append(_candidate(
                    entity, handle, observed_alias=observed_alias, score=score,
                    decision=decision, evidence=evidence, missing=missing,
                ))
    return sorted(candidates, key=lambda item: (-float(item["score"]), item["canonical_name"]))[:10]


def match_actor_row(actor: dict, detail: dict | None = None) -> list[dict]:
    context_parts = [
        actor.get("primary_category"), actor.get("onion_host"),
        actor.get("watch_reason"),
    ]
    detail = detail or {}
    observed_field = "unknown"
    for observation in detail.get("observations") or []:
        context_parts.extend([
            observation.get("primary_category"), observation.get("page_type"),
            observation.get("safe_context_label"), observation.get("url"),
        ])
        evidence_type = str(observation.get("evidence_type") or "")
        if "vendor" in evidence_type or "seller" in evidence_type:
            observed_field = "vendor_profile"
        elif "author" in evidence_type or "profile" in evidence_type:
            observed_field = "profile_username"
    return match_observed_alias(
        actor.get("display_alias") or actor.get("normalized_alias") or "",
        context_text=" ".join(str(item or "") for item in context_parts),
        observed_field=observed_field,
    )


def observed_identity_candidates(*, limit: int = 100) -> list[dict]:
    import storage

    rows = []
    for actor in storage.get_public_actors(limit=max(1, min(int(limit), 500))):
        detail = storage.get_actor_detail(int(actor["id"])) or {}
        for candidate in match_actor_row(actor, detail):
            item = dict(candidate)
            item["actor_id"] = actor["id"]
            item["display_alias"] = actor.get("display_alias")
            item["onion_host"] = actor.get("onion_host")
            rows.append(item)
    return sorted(rows, key=lambda item: (-float(item["score"]), str(item.get("display_alias") or "")))
