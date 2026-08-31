"""Conservative public-alias intelligence helpers.

This module deliberately stays boring: it extracts only public, page-visible
aliases and public identifier *types*, stores correlation hashes through the
existing actor tables, and never expands crawling or claims real-world identity.
"""
from __future__ import annotations

import argparse
import json
import re
from urllib.parse import urlsplit

import storage
from classification_schema import (
    DESTINATION_HTML_EVIDENCE_VERSION,
    has_current_destination_html_evidence,
)
from entity_extractor import (ALIAS_PROVIDER_WORDS, ALIAS_STOPWORDS,
                              extract_public_alias_candidates, extract_public_aliases,
                              is_noisy_public_alias, normalize_public_alias)
from entity_quality import evaluate_candidate

RESTRICTED_CATEGORIES = {"adult_filtered", "adult_restricted", "severe_abuse_risk"}
SAFE_ACTOR_PAGE_TYPES = {
    "thread_page", "post_page", "vendor_page", "listing_page", "profile_page",
    "category_page", "forum_thread", "vendor_profile", "marketplace_listing",
}
SAFE_ACTOR_CATEGORIES = {
    "forum_social", "weapons_arms", "drugs", "leaks_data", "credentials",
    "malware_hacking", "fraud_financial", "marketplace", "marketplace_drugs",
    "marketplace_weapons", "marketplace_fraud", "marketplace_credentials",
    "marketplace_leaks", "marketplace_services", "marketplace_counterfeit",
}


def _accepted_structural_aliases(page_structure: dict | None) -> list[dict]:
    aliases = []
    for item in (page_structure or {}).get("actor_evidence") or []:
        if not isinstance(item, dict) or not item.get("accepted"):
            continue
        if int(item.get("evidence_version") or 0) < 2:
            continue
        if not item.get("normalized_alias") or not item.get("evidence_type") or not item.get("role"):
            continue
        if float(item.get("confidence") or 0) < 0.90:
            continue
        if str(item.get("evidence_strength") or "strong") != "strong":
            continue
        clean = dict(item)
        # page_structure is a persistence boundary. Accept only safe local hashes;
        # never forward raw identifier-looking values from malformed/legacy input.
        bound = []
        for identifier in item.get("bound_identifiers") or []:
            if not isinstance(identifier, dict):
                continue
            value_hash = str(identifier.get("value_hash") or "").casefold()
            indicator_type = str(identifier.get("type") or "")
            if not re.fullmatch(r"[a-f0-9]{64}", value_hash):
                continue
            if not re.fullmatch(r"[a-z0-9_]{2,40}", indicator_type):
                continue
            bound.append({
                "type": indicator_type,
                "value_hash": value_hash,
                "confidence": round(float(identifier.get("confidence") or 0.7), 3),
                "binding": "same_structural_container",
            })
        clean["bound_identifiers"] = bound[:20]
        aliases.append(clean)
    return aliases[:25]


def _alias_candidate_key(item: dict) -> tuple[str, str, str]:
    return (
        str(item.get("normalized_alias") or ""),
        str(item.get("evidence_type") or ""),
        str(item.get("profile_identity") or item.get("profile_url") or ""),
    )


def _selected_aliases(page_structure: dict | None, visible_text: str,
                      link_records: list[dict] | None) -> tuple[list[dict], list[dict]]:
    """Merge independently accepted structural and flat candidates.

    Structural evidence no longer suppresses unrelated corroborated aliases from
    the same page. Exact duplicate evidence is collapsed by alias, evidence type,
    and profile identity rather than by display text alone.
    """
    structural = _accepted_structural_aliases(page_structure)
    flat = extract_public_aliases(visible_text or "", link_records or [])
    independently_eligible_flat = [
        item for item in flat
        if item.get("auto_store_eligible") and float(item.get("confidence") or 0) >= 0.90
    ]
    selected: dict[tuple[str, str, str], dict] = {}
    for item in structural + independently_eligible_flat:
        key = _alias_candidate_key(item)
        if not all((key[0], key[1])):
            continue
        previous = selected.get(key)
        if not previous or float(previous.get("confidence") or 0) < float(item.get("confidence") or 0):
            selected[key] = dict(item)
    ordered = sorted(selected.values(), key=lambda item: (
        -float(item.get("confidence") or 0),
        str(item.get("normalized_alias") or ""),
        str(item.get("evidence_type") or ""),
        str(item.get("profile_url") or ""),
    ))
    return ordered[:10], flat


def _local_identity_evidence(alias: dict) -> list[dict]:
    """Translate safe local hashes into storage-compatible correlation inputs."""
    evidence = []
    for item in alias.get("bound_identifiers") or []:
        value_hash = str(item.get("value_hash") or "").casefold()
        indicator_type = str(item.get("type") or "")
        if not re.fullmatch(r"[a-f0-9]{64}", value_hash):
            continue
        if not re.fullmatch(r"[a-z0-9_]{2,40}", indicator_type):
            continue
        evidence.append({
            "type": indicator_type,
            # Only the stable local hash crosses the module boundary. storage's
            # normal at-rest hash remains defense in depth and deterministic.
            "normalized_value": f"local_sha256:{value_hash}",
            "confidence": round(float(item.get("confidence") or 0.7), 3),
            "context": "[LOCAL STRUCTURAL IDENTIFIER]",
        })
    return evidence[:20]


def _restricted(policy: dict) -> bool:
    return (
        policy.get("primary_category") in RESTRICTED_CATEGORIES
        or policy.get("storage_policy") == "discard"
    )


def _evaluate_page_candidates(page_structure: dict | None, visible_text: str,
                              link_records: list[dict] | None, policy: dict) -> list[dict]:
    """Build the explainable shadow lifecycle without widening actor acceptance."""
    structural = [dict(item) for item in (page_structure or {}).get("actor_evidence") or []
                  if isinstance(item, dict)]
    flat = extract_public_alias_candidates(visible_text or "", link_records or [])
    runtime_rules = storage.get_alias_noise_rules(enabled_only=True)
    candidates: dict[tuple[str, str, str], dict] = {}
    for source in (structural + flat)[:125]:
        source.setdefault("page_type", policy.get("page_type") or "unknown")
        source.setdefault("forum_role", (page_structure or {}).get("forum_role") or "unknown")
        evaluated = evaluate_candidate(source, extra_rules=runtime_rules)
        # The quality schema intentionally omits navigation/source fields that are
        # not needed for a pure decision. Persistence receives only the safe,
        # bounded identity fields already approved by the extractor.
        evaluated.update({
            "profile_identity": str(source.get("profile_identity") or "")[:160],
            "profile_url": str(source.get("profile_url") or "")[:500],
            "evidence_type": str(source.get("evidence_type") or "unknown")[:80],
            "evidence_strength": str(source.get("evidence_strength") or "unknown")[:20],
            "confidence": float(source.get("confidence") or 0),
        })
        key = (evaluated["normalized_alias"], evaluated["extraction_method"],
               evaluated.get("profile_identity") or "")
        previous = candidates.get(key)
        if not previous or float(previous.get("confidence_score") or 0) < float(evaluated.get("confidence_score") or 0):
            candidates[key] = evaluated
    return sorted(candidates.values(), key=lambda item: (
        item["state"], item["normalized_alias"], item["extraction_method"]))[:100]


def actor_intelligence_eligible(url: str, policy: dict) -> bool:
    """Return true when a page is safe and useful enough for public-alias storage."""
    host = (urlsplit(url or "").hostname or "").casefold()
    if not host.endswith(".onion") or _restricted(policy):
        return False
    page_type = str(policy.get("page_type") or "unknown")
    category = str(policy.get("primary_category") or "unknown")
    return (
        bool(policy.get("spain_priority"))
        or page_type in SAFE_ACTOR_PAGE_TYPES
        or category in SAFE_ACTOR_CATEGORIES
        or category.startswith("marketplace")
    )


def process_page_actor_intelligence(
    url: str,
    *,
    visible_text: str,
    links: list[str] | None,
    link_records: list[dict] | None,
    policy: dict,
    page_structure: dict | None = None,
) -> dict:
    """Extract and store public alias observations for one already-fetched page."""
    # Restricted pages are a hard persistence boundary.  Structural parser
    # output cannot make such a page eligible, even when a stale snapshot still
    # contains an author-like container.
    if _restricted(policy):
        storage.store_actor_observations(url, [], [], policy)
        return {"eligible": False, "aliases": 0, "actors": 0,
                "candidates": 0, "reason": "restricted_policy"}
    structural_aliases = _accepted_structural_aliases(page_structure)
    if not actor_intelligence_eligible(url, policy) and not structural_aliases:
        return {"eligible": False, "aliases": 0, "actors": 0, "reason": "not_actor_page"}
    aliases, _flat_candidates = _selected_aliases(page_structure, visible_text or "", link_records)
    evaluated_candidates = _evaluate_page_candidates(
        page_structure, visible_text or "", link_records, policy)
    candidate_ids = storage.upsert_actor_candidates(url, evaluated_candidates, policy)
    if not aliases:
        return {"eligible": True, "aliases": 0, "actors": 0,
                "candidates": len(candidate_ids), "reason": "no_confirmed_public_alias"}
    actor_ids: list[int] = []
    # Store one candidate at a time so an identifier hash can only bind to the
    # exact structural alias container that produced it. Flat candidates carry
    # no identifier evidence.
    for alias in aliases:
        actor_ids.extend(storage.store_actor_observations(
            url, [alias], _local_identity_evidence(alias), policy))
    storage.link_actor_candidates(url, actor_ids)
    deep_discovery_queued = 0
    if actor_ids:
        try:
            import deep_discovery
            for actor_id in sorted(set(actor_ids)):
                result = deep_discovery.maybe_queue_actor(int(actor_id))
                if result.get("queued_job_id"):
                    deep_discovery_queued += 1
        except Exception:
            # Actor extraction must never fail the crawler; Deep Discovery is a
            # conservative downstream queue and can be retried by maintenance.
            deep_discovery_queued = 0
    expansion_proposals = 0
    if actor_ids and link_records:
        try:
            from entity_expansion import plan_entity_expansion
            source_page = dict(policy)
            source_page["url"] = url
            plan = plan_entity_expansion(source_page, link_records)
            page_row = storage.get_onion_url_by_url(url) or {}
            proposal_ids = storage.persist_entity_expansion_plan(
                url, plan, actor_id=actor_ids[0] if len(set(actor_ids)) == 1 else None,
                site_card_id=page_row.get("site_card_id"),
                parent_evidence_type="verified_actor_page")
            expansion_proposals = len(proposal_ids)
        except Exception:
            # Proposal planning is downstream, local and optional. It may never
            # fail verification or silently enter the crawl frontier.
            expansion_proposals = 0
    return {
        "eligible": True,
        "aliases": len(aliases),
        "actors": len(set(actor_ids)),
        "deep_discovery_queued": deep_discovery_queued,
        "candidates": len(candidate_ids),
        "expansion_proposals": expansion_proposals,
        "reason": "stored" if actor_ids else "filtered",
    }


def backfill_actor_intelligence(*, batch_size: int = 250, dry_run: bool = True) -> dict:
    """Backfill from stored fetched snapshots only; performs no network requests."""
    storage.init_db()
    with storage.get_db() as db:
        rows = [dict(row) for row in db.execute("""SELECT fp.url,fp.visible_text,fp.link_records_json,fp.page_structure_json,
          ou.primary_category,ou.page_type,ou.storage_policy,ou.spain_priority,ou.spain_confidence,
          ou.spain_match_reason,ou.risk_level
          FROM fetched_pages fp JOIN onion_urls ou ON ou.id=fp.onion_url_id
          WHERE fp.classification_status='done'
          AND ou.verification_state='verified'
          AND ou.classification_evidence_source='destination_html'
          AND COALESCE(ou.destination_html_evidence_version,0)>=?
          AND COALESCE(fp.visible_text,'')!=''
          AND COALESCE(ou.primary_category,'unknown') NOT IN ('adult_filtered','adult_restricted','severe_abuse_risk')
          ORDER BY fp.verified_at DESC,fp.fetched_at DESC LIMIT ?""",
          (DESTINATION_HTML_EVIDENCE_VERSION, max(1, int(batch_size))))]
    scanned = eligible = alias_hits = actors = 0
    for row in rows:
        scanned += 1
        try:
            page_structure = json.loads(row.get("page_structure_json") or "{}")
            if not isinstance(page_structure, dict):
                page_structure = {}
        except (TypeError, ValueError):
            page_structure = {}
        # URL-row provenance alone is insufficient.  Legacy fetched snapshots
        # may have copied outbound anchor text into visible_text, so actor
        # extraction is allowed only when the snapshot itself carries the
        # current destination-owned HTML boundary marker.
        if not has_current_destination_html_evidence(page_structure):
            continue
        policy = {
            "primary_category": row.get("primary_category"),
            "page_type": row.get("page_type"),
            "storage_policy": row.get("storage_policy"),
            "spain_priority": row.get("spain_priority"),
            "spain_confidence": row.get("spain_confidence"),
            "spain_match_reason": row.get("spain_match_reason"),
            "risk_level": row.get("risk_level"),
        }
        if not actor_intelligence_eligible(row["url"], policy):
            continue
        eligible += 1
        try:
            link_records = json.loads(row.get("link_records_json") or "[]")
            if not isinstance(link_records, list):
                link_records = []
        except (TypeError, ValueError):
            link_records = []
        aliases, flat_candidates = _selected_aliases(
            page_structure, row.get("visible_text") or "", link_records)
        # Preserve the diagnostic meaning of the dry-run count: it reports all
        # structurally accepted or flat candidates seen, while mutation still
        # requires independent eligibility through ``aliases``.
        alias_hits += len(aliases) if aliases else len(flat_candidates)
        if dry_run or not aliases:
            continue
        links = [str(record.get("url") or "") for record in link_records if record.get("url")]
        result = process_page_actor_intelligence(
            row["url"], visible_text=row.get("visible_text") or "", links=links,
            link_records=link_records, policy=policy, page_structure=page_structure,
        )
        actors += int(result.get("actors") or 0)
    return {"scanned": scanned, "eligible": eligible, "aliases": alias_hits,
            "actors": actors, "dry_run": bool(dry_run)}


def cleanup_public_alias_noise(*, dry_run: bool = True, limit: int = 5000) -> dict:
    """Remove already-stored public aliases that are obvious UI/provider/generic noise."""
    storage.init_db()
    limit = max(1, min(int(limit or 5000), 50000))
    with storage.get_db() as db:
        rows = [dict(row) for row in db.execute("""SELECT a.id,a.display_alias,a.normalized_alias,
          CASE WHEN a.watched=1 OR COALESCE(a.analyst_status,'unreviewed')!='unreviewed'
            OR EXISTS (SELECT 1 FROM actor_connections c WHERE
              (c.source_actor_id=a.id OR c.target_actor_id=a.id)
              AND COALESCE(c.analyst_decision,'unreviewed')!='unreviewed')
            OR EXISTS (SELECT 1 FROM actor_events e WHERE e.actor_id=a.id AND
              (e.event_type LIKE 'analyst_%' OR e.event_type IN
               ('watch_enabled','watch_disabled','connection_reviewed','observation_excluded')))
            THEN 1 ELSE 0 END cleanup_protected
          FROM actors a ORDER BY a.id LIMIT ?""", (limit,))]
        noisy = [
            row for row in rows
            if is_noisy_public_alias(row.get("display_alias") or row.get("normalized_alias") or "")
        ]
        reason_counts: dict[str, int] = {}
        for row in noisy:
            normalized = normalize_public_alias(
                row.get("display_alias") or row.get("normalized_alias") or "")
            if len(normalized) < 3:
                reason = "noise_too_short"
            elif normalized.isdigit():
                reason = "noise_numeric_only"
            elif normalized in ALIAS_PROVIDER_WORDS:
                reason = "noise_provider_word"
            elif normalized in ALIAS_STOPWORDS:
                reason = "noise_generic_or_navigation"
            else:
                # Keep a stable aggregate bucket if the shared noise predicate
                # gains another rule. Never expose the value that matched it.
                reason = "noise_other_rule"
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        protected_ids = {int(row["id"]) for row in noisy if row.get("cleanup_protected")}
        actor_ids = [int(row["id"]) for row in noisy if int(row["id"]) not in protected_ids]
    removed = storage.delete_actor_ids_safely(actor_ids) if not dry_run else 0
    return {
        "scanned": len(rows),
        "noisy_aliases": len(noisy),
        "removable": len(actor_ids),
        "removed": removed,
        "protected": len(protected_ids),
        "dry_run": bool(dry_run),
        "reason_counts": {key: reason_counts[key] for key in sorted(reason_counts)},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill public-alias intelligence from stored safe snapshots")
    parser.add_argument("--batch-size", type=int, default=250)
    parser.add_argument("--cleanup-noise", action="store_true")
    parser.add_argument("--audit-quality", action="store_true",
                        help="Report candidate-quality metrics without changing data")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if args.audit_quality:
        result = storage.get_alias_quality_audit(limit=max(args.batch_size, 1))
    elif args.cleanup_noise:
        result = cleanup_public_alias_noise(dry_run=not args.apply or args.dry_run)
    else:
        result = backfill_actor_intelligence(batch_size=args.batch_size, dry_run=not args.apply or args.dry_run)
    # CLI output is intentionally aggregate-only. JSON keeps the operator
    # summary machine-readable without ever printing aliases, profile values,
    # identifiers, or onion hosts selected during cleanup.
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
