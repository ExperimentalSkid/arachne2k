"""Live structured Site Card views for the Identity Signals workspace."""
from __future__ import annotations

import json

import identity_registry


def relationship_edges(card: dict) -> list[dict]:
    profiles = {profile.get("id"): profile for profile in card.get("profiles") or []}
    edges = []
    for relation in card.get("relationships") or []:
        source = relation.get("source")
        target = relation.get("target")
        edges.append({
            "source": profiles.get(source, {}).get("handle") or source,
            "relationship": relation.get("type"),
            "target": target,
            "confidence": relation.get("confidence"),
            "evidence_count": int(relation.get("evidence_count") or 0),
        })
    return edges


def build_live_structured_card(site_card_id: int) -> dict | None:
    """Build a structured view exclusively from persisted crawler/analyst data."""
    import site_dedupe
    import storage
    from universal_classifier import safe_category_label

    detail = site_dedupe.get_site_card_detail(int(site_card_id), url_limit=120, event_limit=80,
                                              include_dead=True, include_restricted=False)
    if not detail:
        return None
    urls = detail.get("urls") or []
    profiles = []
    candidate_attributions = []
    relationships = []
    identifiers = []
    evidence_ledger = []
    expansion_history = []
    profile_by_actor: dict[int, str] = {}
    relationship_keys: set[tuple[str, str, str]] = set()
    connection_relationship_ids: set[int] = set()
    for actor in storage.get_site_card_actor_profiles(int(site_card_id)):
        actor_id = int(actor["actor_id"])
        evidence_types = [item for item in str(actor.get("evidence_types") or "").split(",") if item]
        source_urls = [item for item in str(actor.get("source_urls") or "").split(",") if item]
        role = "vendor" if int(actor.get("seller_observations") or 0) else "public_alias"
        profile_id = f"live-actor-{actor_id}"
        profile_by_actor[actor_id] = profile_id
        profiles.append({
            "id": profile_id,
            "actor_id": actor_id,
            "handle": actor.get("display_alias") or actor.get("normalized_alias"),
            "normalized_handle": actor.get("normalized_alias"),
            "role_display": "Seller/vendor observation" if role == "vendor" else "Public alias/profile observation",
            "role_normalized": role,
            "matching_policy": "live_observed",
            "confidence": actor.get("confidence_label") or "unknown",
            "source_page": source_urls[0] if source_urls else "",
            "source_pages": source_urls[:10],
            "evidence_types": evidence_types[:10],
            "first_observed": actor.get("first_observed"),
            "last_observed": actor.get("last_observed"),
            "identifier_count": int(actor.get("identifier_count") or 0),
        })
        observed_edge = (
            profile_id,
            "observed_on",
            detail.get("analyst_title") or detail.get("display_name") or detail.get("representative_host") or "Site Card",
        )
        relationship_keys.add(observed_edge)
        relationships.append({
            "source": profile_id,
            "type": "observed_on",
            "target": observed_edge[2],
            "confidence": actor.get("confidence_label") or "unknown",
            "evidence_count": int(actor.get("observation_count") or 0),
        })
        for identifier in actor.get("identifiers") or []:
            identifiers.append({
                "profile": profile_id,
                "type": identifier.get("indicator_type"),
                "value": identifier.get("safe_value_label"),
                "strength": "hashed_public_signal",
                "count": int(identifier.get("count") or 0),
                "last_seen": identifier.get("last_seen"),
            })
        detail_for_actor = storage.get_actor_detail(actor_id) or {}
        for observation in detail_for_actor.get("observations") or []:
            evidence_ledger.append({
                "kind": "observation", "actor_id": actor_id,
                "label": observation.get("safe_context_label") or "Public profile observation",
                "source": observation.get("url") or "", "ts": observation.get("last_seen"),
                "confidence": observation.get("evidence_confidence"),
            })
        for candidate in detail_for_actor.get("candidates") or []:
            state = candidate.get("effective_state") or "analyst_review_candidate"
            kind = ("rejected_evidence" if "rejected" in str(state)
                    else "analyst_decision" if candidate.get("analyst_state")
                    else "candidate_observation")
            evidence_ledger.append({
                "kind": kind, "actor_id": actor_id,
                "label": f"Alias candidate: {state.replace('_', ' ')}",
                "source": candidate.get("url") or "", "ts": candidate.get("last_seen"),
                "confidence": candidate.get("evidence_confidence"),
                "reason_codes": candidate.get("reason_codes_json") or "[]",
            })
        for event in detail_for_actor.get("events") or []:
            evidence_ledger.append({
                "kind": "analyst_decision" if str(event.get("event_type") or "").startswith("analyst_")
                or event.get("event_type") in {"observation_excluded", "connection_reviewed"}
                else "lifecycle_event",
                "actor_id": actor_id,
                "label": str(event.get("event_type") or "event").replace("_", " ").title(),
                "source": "", "ts": event.get("created_at"),
            })
        for proposal in detail_for_actor.get("expansion") or []:
            expansion_history.append({
                "id": proposal.get("id"), "actor_id": actor_id,
                "role": proposal.get("route_role"), "reason": proposal.get("reason_code"),
                "status": proposal.get("status"), "parent": proposal.get("parent_url"),
                "target": proposal.get("proposed_url"),
                "expected_value": proposal.get("expected_value"),
                "created_at": proposal.get("created_at"),
            })
        for connection in detail_for_actor.get("connections") or []:
            connection_id = int(connection.get("id") or 0)
            if connection_id and connection_id in connection_relationship_ids:
                continue
            if connection_id:
                connection_relationship_ids.add(connection_id)
            other_id = int(connection.get("other_actor_id") or 0)
            target = profile_by_actor.get(other_id) or (
                f"{connection.get('other_alias') or 'profile'}@{connection.get('other_onion_host') or 'site'}"
            )
            relation_type = (
                "possible_copycat" if connection.get("warning_type") == "conflicting_public_identifiers"
                else "possible_same_vendor" if int(connection.get("migration_candidate") or 0)
                else "possible_correspondence"
            )
            key = (profile_id, relation_type, str(target))
            reverse_key = (str(target), relation_type, profile_id)
            if key not in relationship_keys and reverse_key not in relationship_keys:
                relationship_keys.add(key)
                evidence = []
                try:
                    evidence = json.loads(connection.get("evidence_json") or "[]")
                except (TypeError, ValueError):
                    evidence = []
                relationships.append({
                    "source": profile_id,
                    "type": relation_type,
                    "target": target,
                    "confidence": connection.get("confidence_label") or "unknown",
                    "evidence_count": len(evidence),
                    "analyst_decision": connection.get("analyst_decision") or "unreviewed",
                    "warning": connection.get("warning_reason") or "",
                    "evidence": [item.get("label") or item.get("type") for item in evidence[:6]],
                })
        for candidate in identity_registry.match_actor_row(actor, detail_for_actor):
            candidate_attributions.append({
                "observed_profile": profile_id,
                "candidate_entity_id": candidate.get("entity_id"),
                "candidate_name": candidate.get("canonical_name"),
                "score": candidate.get("score"),
                "decision": candidate.get("decision"),
                "supporting": [f"{item.get('type')}: {item.get('value')}" for item in candidate.get("evidence") or []],
                "missing": candidate.get("missing") or [],
                "analyst_reference": bool(candidate.get("reference_record")),
            })
    timeline = [
        {"type": "site_first_seen", "label": "Site Card first observed", "ts": detail.get("first_seen")},
        {"type": "site_last_seen", "label": "Latest Site Card update", "ts": detail.get("last_seen") or detail.get("updated_at")},
    ]
    for event in detail.get("events") or []:
        timeline.append({"type": event.get("event_type"), "label": event.get("event_summary"), "ts": event.get("created_at")})
    return {
        "id": f"live-card-{site_card_id}",
        "site_card_id": int(site_card_id),
        "data_origin": "crawler",
        "name": detail.get("analyst_title") or detail.get("display_name") or detail.get("representative_host") or "Live Site Card",
        "entity_type": detail.get("card_kind") or "site_card",
        "status": "live_observed" if detail.get("live_url_count") else "observed",
        "category": safe_category_label(detail.get("primary_category")),
        "summary": detail.get("safe_summary") or detail.get("category_reason") or "Structured view built from crawler metadata.",
        "profiles": profiles,
        "identifiers": identifiers,
        "relationships": relationships,
        "timeline": [item for item in timeline if item.get("ts") or item.get("label")][:80],
        "observed_pages": [{
            "path": row.get("url"),
            "page_type": row.get("page_type") or row.get("url_role") or "page",
            "purpose": row.get("status") or "observed page",
        } for row in urls[:80]],
        "candidate_attributions": candidate_attributions[:50],
        "evidence_ledger": sorted(evidence_ledger, key=lambda item: str(item.get("ts") or ""),
                                  reverse=True)[:300],
        "expansion_history": sorted(expansion_history,
                                    key=lambda item: str(item.get("created_at") or ""),
                                    reverse=True)[:200],
        "coverage": {
            "pages": len(urls),
            "live_pages": int(detail.get("live_url_count") or 0),
            "dead_pages": int(detail.get("dead_url_count") or 0),
            "profiles": len(profiles),
            "identifiers": len(identifiers),
            "relationships": len(relationships),
            "candidate_attributions": len(candidate_attributions),
            "evidence_items": len(evidence_ledger),
            "expansion_items": len(expansion_history),
        },
    }
