"""Safe consistency audit and mechanical repair helpers.

These functions never fetch URLs and never print page content, titles, snippets,
OCR text, indicators, or restricted terms.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

import storage
from classification_schema import (CARD_READINESS_REASONS, CONTENT_CATEGORIES,
                                   DESTINATION_HTML_EVIDENCE_VERSION, PAGE_TYPES,
                                   SAFETY_STATES, has_current_destination_html_evidence)
from paths import PREVIEWS_DIR


RESTRICTED_CATEGORIES = frozenset({
    "adult_filtered", "adult_restricted", "severe_abuse_risk",
    "marketplace_fraud", "fraud_financial",
})
HARD_RESTRICTED_CATEGORIES = frozenset({
    "adult_filtered", "adult_restricted", "severe_abuse_risk",
})
RESTRICTED_SQL = "('adult_filtered','adult_restricted','severe_abuse_risk','marketplace_fraud','fraud_financial')"


def _trusted_category_sql(alias: str, categories_sql: str = RESTRICTED_SQL) -> str:
    """Return the row-level half of the exact-category trust contract.

    The fetched-page content-boundary attestation is JSON and is deliberately
    checked in Python below.  This SQL predicate is still useful as a narrow
    pre-filter, but callers must not treat it as sufficient destination proof.
    """
    return f"""{alias}.primary_category IN {categories_sql} AND (
      (COALESCE({alias}.analyst_category,'')!=''
       AND {alias}.primary_category={alias}.analyst_category
       AND {alias}.classification_evidence_source='analyst'
       AND {alias}.verification_state='verified'
       AND {alias}.verification_reason='analyst_confirmed')
      OR
      ({alias}.classification_evidence_source='destination_html'
       AND COALESCE({alias}.destination_html_evidence_version,0)>={DESTINATION_HTML_EVIDENCE_VERSION}
       AND {alias}.verification_state='verified'
       AND {alias}.verification_reason='page_fetched_and_classified')
    )"""


TRUSTED_RESTRICTED_SQL = _trusted_category_sql("onion_urls")
def _sql_values(values) -> str:
    return "(" + ",".join("'" + str(value).replace("'", "''") + "'" for value in sorted(values)) + ")"


CONTENT_CATEGORY_SQL = _sql_values(CONTENT_CATEGORIES)
PAGE_TYPE_SQL = _sql_values(PAGE_TYPES)
SAFETY_STATE_SQL = _sql_values(SAFETY_STATES)
READINESS_REASON_SQL = _sql_values(CARD_READINESS_REASONS)
REPAIRABLE_URL_WHERE = """(
  (active=0 AND status IN ('new','queued','retry') AND queue_policy!='blocked'
   AND storage_policy NOT IN ('metadata_only','discard')) OR
  (status='blocked' AND queue_policy!='blocked') OR
  (active=1 AND queue_policy='blocked') OR
  (status='crawled' AND safety_reason='awaiting_page_classification') OR
  (screenshot_policy='allowed' AND storage_policy IN ('metadata_only','discard'))
)"""


def _loads_structure(value) -> dict:
    if isinstance(value, dict):
        return value
    try:
        loaded = json.loads(value or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _trusted_category_index(categories: set[str] | frozenset[str] | None = None) -> dict[int, str]:
    """Return exact trusted categories, including parser boundary validation.

    A provenance flag is never allowed to bless a different category.  An
    analyst decision is trusted only when the stored category is exactly the
    analyst category.  Automated destination classification additionally
    requires the current, completed fetched snapshot and its content-boundary
    attestation.  URL/host/path/anchor/parent/section fields are not read here.
    """
    requested = set(categories or CONTENT_CATEGORIES)
    if not requested:
        return {}
    marks = ",".join("?" for _ in requested)
    with storage.get_db() as db:
        rows = [dict(row) for row in db.execute(f"""SELECT
          ou.id,ou.primary_category,ou.analyst_category,
          ou.classification_evidence_source,ou.destination_html_evidence_version,
          ou.verification_state,ou.verification_reason,
          fp.classification_status AS fetched_classification_status,
          fp.page_structure_json
          FROM onion_urls ou LEFT JOIN fetched_pages fp ON fp.id=(
            SELECT MAX(current.id) FROM fetched_pages current
            WHERE current.onion_url_id=ou.id)
          WHERE ou.primary_category IN ({marks})""", tuple(sorted(requested)))]
    trusted: dict[int, str] = {}
    for row in rows:
        category = str(row.get("primary_category") or "unknown")
        analyst_category = str(row.get("analyst_category") or "").strip()
        analyst_exact = (
            analyst_category
            and analyst_category == category
            and row.get("classification_evidence_source") == "analyst"
            and row.get("verification_state") == "verified"
            and row.get("verification_reason") == "analyst_confirmed"
        )
        html_exact = (
            row.get("classification_evidence_source") == "destination_html"
            and int(row.get("destination_html_evidence_version") or 0)
                >= DESTINATION_HTML_EVIDENCE_VERSION
            and row.get("verification_state") == "verified"
            and row.get("verification_reason") == "page_fetched_and_classified"
            and row.get("fetched_classification_status") == "done"
            and has_current_destination_html_evidence(
                _loads_structure(row.get("page_structure_json")))
        )
        if analyst_exact or html_exact:
            trusted[int(row["id"])] = category
    return trusted


def _trusted_category_ids(categories: set[str] | frozenset[str]) -> set[int]:
    return set(_trusted_category_index(categories))


def _trusted_restricted_conflict_counts() -> dict[str, int]:
    """Compute category-sensitive audit counts after full provenance checks."""
    trusted = _trusted_category_index(RESTRICTED_CATEGORIES)
    trusted_ids = set(trusted)
    trusted_hard_ids = {
        url_id for url_id, category in trusted.items()
        if category in HARD_RESTRICTED_CATEGORIES
    }
    trusted_adult_ids = {
        url_id for url_id, category in trusted.items()
        if category in {"adult_filtered", "adult_restricted"}
    }
    with storage.get_db() as db:
        urls = [dict(row) for row in db.execute("""SELECT id,source_url,page_type,
          screenshot_policy,storage_policy,active,queue_policy,
          restricted_outbound_count,match_scope FROM onion_urls""")]
        previews = [dict(row) for row in db.execute("""SELECT ou.id,pp.status,
          ou.screenshot_policy,ou.storage_policy FROM page_previews pp
          JOIN onion_urls ou ON ou.url=pp.url""")]
        edges = [dict(row) for row in db.execute("""SELECT child.id,e.safe_anchor_text
          FROM onion_edges e JOIN onion_urls child ON child.url=e.discovered_url""")]
    return {
        "screenshot_restricted_conflicts": sum(
            1 for row in urls if row["screenshot_policy"] == "allowed" and (
                row["storage_policy"] in {"metadata_only", "discard"}
                or int(row["id"]) in trusted_ids)),
        "preview_restricted_conflicts": sum(
            1 for row in previews if row["status"] == "available" and (
                row["screenshot_policy"] != "allowed"
                or row["storage_policy"] in {"metadata_only", "discard"}
                or int(row["id"]) in trusted_ids)),
        "link_repository_child_only_adult_conflicts": sum(
            1 for row in urls if int(row["id"]) in trusted_adult_ids
            and row["page_type"] == "link_repository"
            and int(row["restricted_outbound_count"] or 0) > 0
            and str(row["match_scope"] or "") == "anchor"),
        "restricted_child_queue_conflicts": sum(
            1 for row in urls if int(row["id"]) in trusted_hard_ids
            and row["source_url"] is not None
            and (int(row["active"] or 0) != 0 or row["queue_policy"] != "blocked"
                 or row["storage_policy"] not in {"metadata_only", "discard"})),
        "unsafe_restricted_anchor_storage": sum(
            1 for row in edges if int(row["id"]) in trusted_hard_ids
            and str(row["safe_anchor_text"] or "") not in {
                "", "Restricted child link hidden", "Unsafe anchor hidden"}),
    }

AUDIT_QUERIES = {
    "active_blocked_conflicts": "SELECT COUNT(*) FROM onion_urls WHERE active=1 AND (status='blocked' OR queue_policy='blocked')",
    "queued_inactive_conflicts": "SELECT COUNT(*) FROM onion_urls WHERE active=0 AND status IN ('new','queued','retry')",
    "blocked_normal_queue_conflicts": "SELECT COUNT(*) FROM onion_urls WHERE status='blocked' AND queue_policy!='blocked'",
    "crawled_awaiting_classification": "SELECT COUNT(*) FROM onion_urls WHERE status='crawled' AND safety_reason='awaiting_page_classification'",
    "screenshot_restricted_conflicts": f"""SELECT COUNT(*) FROM onion_urls WHERE
      screenshot_policy='allowed' AND (storage_policy IN ('metadata_only','discard')
      OR ({TRUSTED_RESTRICTED_SQL}))""",
    "preview_restricted_conflicts": f"""SELECT COUNT(*) FROM page_previews pp
      JOIN onion_urls ou ON ou.url=pp.url WHERE pp.status='available'
      AND (ou.screenshot_policy!='allowed' OR ou.storage_policy IN ('metadata_only','discard')
      OR ({_trusted_category_sql('ou')}))""",
    # Computed from the current parser-proven fetched snapshot in
    # audit_consistency(); historical edge rows are not content evidence.
    "unknown_high_edge_pages": "SELECT 0",
    "seed_depth_limit_total": "SELECT COUNT(*) FROM onion_urls WHERE trap_reason='seed_depth_limit'",
    "seed_depth_limit_from_high_edge_sources": "SELECT COUNT(*) FROM onion_urls child WHERE child.trap_reason='seed_depth_limit' AND (SELECT COUNT(*) FROM onion_edges e WHERE e.source_url=child.source_url)>=5",
    "excessive_query_variants_total": "SELECT COUNT(*) FROM onion_urls WHERE trap_reason LIKE '%excessive_query_variants%'",
    "alert_queue_without_url_flag": "SELECT COUNT(*) FROM spain_alert_queue q JOIN onion_urls ou ON ou.url=q.url WHERE ou.spain_priority=0 AND q.status IN ('pending','sent')",
    "url_flag_without_site_card_flag": "SELECT COUNT(*) FROM onion_urls ou LEFT JOIN site_cards sc ON sc.id=ou.site_card_id WHERE ou.spain_priority=1 AND (sc.id IS NULL OR sc.spain_priority=0)",
    "site_card_flag_without_url_support": "SELECT COUNT(*) FROM site_cards sc WHERE sc.spain_priority=1 AND NOT EXISTS(SELECT 1 FROM onion_urls ou WHERE ou.site_card_id=sc.id AND ou.spain_priority=1)",
    "card_ready_without_site_card": """SELECT COUNT(*) FROM onion_urls WHERE card_ready=1
      AND site_card_id IS NULL AND status='crawled' AND storage_policy NOT IN ('metadata_only','discard')""",
    "site_card_without_ready_url": """SELECT COUNT(*) FROM site_cards sc WHERE sc.card_ready=1
      AND COALESCE(sc.card_readiness_reason,'') NOT IN ('','analyst_confirmed')
      AND NOT EXISTS(SELECT 1 FROM onion_urls ou WHERE ou.site_card_id=sc.id AND ou.card_ready=1)""",
    "link_repository_without_link_stats": """SELECT COUNT(*) FROM onion_urls
      WHERE page_type='link_repository' AND card_readiness_reason IS NOT NULL
      AND COALESCE(outbound_onion_count,0)+COALESCE(internal_link_count,0)+COALESCE(external_onion_count,0)=0""",
    "noncanonical_content_category": f"SELECT COUNT(*) FROM onion_urls WHERE COALESCE(content_category,'unknown') NOT IN {CONTENT_CATEGORY_SQL}",
    "noncanonical_page_type": f"SELECT COUNT(*) FROM onion_urls WHERE COALESCE(page_type,'unknown') NOT IN {PAGE_TYPE_SQL}",
    "noncanonical_safety_state": f"SELECT COUNT(*) FROM onion_urls WHERE COALESCE(safety_state,'safe') NOT IN {SAFETY_STATE_SQL}",
    "noncanonical_readiness_reason": f"SELECT COUNT(*) FROM onion_urls WHERE card_readiness_reason IS NOT NULL AND card_readiness_reason NOT IN {READINESS_REASON_SQL}",
    "category_dimension_conflicts": "SELECT COUNT(*) FROM onion_urls WHERE COALESCE(content_category,'unknown')!=COALESCE(primary_category,'unknown')",
    "link_repository_child_only_adult_conflicts": f"""SELECT COUNT(*) FROM onion_urls
      WHERE page_type='link_repository'
      AND ({_trusted_category_sql('onion_urls', "('adult_filtered','adult_restricted')")})
      AND restricted_outbound_count>0 AND COALESCE(match_scope,'')='anchor'""",
    "restricted_child_queue_conflicts": """SELECT COUNT(*) FROM onion_urls child
      WHERE child.source_url IS NOT NULL
      AND (""" + _trusted_category_sql(
          "child", "('adult_filtered','adult_restricted','severe_abuse_risk')") + """)
      AND (child.active!=0 OR child.queue_policy!='blocked'
           OR child.storage_policy NOT IN ('metadata_only','discard'))""",
    "unsafe_restricted_anchor_storage": """SELECT COUNT(*) FROM onion_edges e
      JOIN onion_urls child ON child.url=e.discovered_url
      WHERE (""" + _trusted_category_sql(
          "child", "('adult_filtered','adult_restricted','severe_abuse_risk')") + """)
      AND COALESCE(e.safe_anchor_text,'') NOT IN ('','Restricted child link hidden','Unsafe anchor hidden')""",
    "directory_child_counter_conflicts": """SELECT COUNT(*) FROM onion_urls
      WHERE child_blocked_link_count<child_restricted_link_count""",
}


def _current_link_repository_candidates(min_links: int = 5) -> list[int]:
    """Return unknown URLs whose own current HTML proves link-list structure.

    Historical ``onion_edges`` and discovered-link metadata are intentionally
    absent.  The only inputs are aggregate DOM/link facts written into the
    destination's current parser-attested snapshot.  Link labels, target names,
    URL text, parent tags, and section context cannot enter this decision.
    """
    with storage.get_db() as db:
        rows = [dict(row) for row in db.execute("""SELECT ou.id,fp.page_structure_json
          FROM onion_urls ou JOIN fetched_pages fp ON fp.id=(
            SELECT MAX(current.id) FROM fetched_pages current
            WHERE current.onion_url_id=ou.id)
          WHERE ou.primary_category='unknown' AND ou.status='crawled'
          AND ou.analyst_category IS NULL
          AND COALESCE(ou.classification_evidence_source,'unverified')!='analyst'
          AND ou.storage_policy='safe_summary'
          AND ou.classification_evidence_source='destination_html'
          AND COALESCE(ou.destination_html_evidence_version,0)>=?
          AND ou.verification_state='verified'
          AND ou.verification_reason='page_fetched_and_classified'
          AND fp.classification_status='done'""",
          (DESTINATION_HTML_EVIDENCE_VERSION,))]
    selected: list[int] = []
    for row in rows:
        try:
            structure = json.loads(row.get("page_structure_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not has_current_destination_html_evidence(structure):
            continue
        link_count = int(structure.get("onion_link_count") or 0)
        external_hosts = int(structure.get("external_onion_host_count") or 0)
        directory_score = int((structure.get("scores") or {}).get("directory") or 0)
        structured_lists = bool(structure.get("structured_lists"))
        repeated_rows = int(structure.get("repeated_link_row_count") or 0)
        structural_support = (
            directory_score >= 3
            or external_hosts >= 3
            or structured_lists
            or repeated_rows >= 3
            or link_count >= 20
        )
        if link_count >= max(1, int(min_links)) and structural_support:
            selected.append(int(row["id"]))
    return selected

MECHANICAL_REPAIRABLE = {
    "active_blocked_conflicts", "queued_inactive_conflicts", "blocked_normal_queue_conflicts",
    "crawled_awaiting_classification", "screenshot_restricted_conflicts",
    "preview_restricted_conflicts", "unknown_high_edge_pages",
    "restricted_child_queue_conflicts", "unsafe_restricted_anchor_storage",
}
ANALYST_AFFECTING = {
    "alert_queue_without_url_flag", "url_flag_without_site_card_flag",
    "site_card_flag_without_url_support", "card_ready_without_site_card",
    "site_card_without_ready_url",
}
HIGH_SEVERITY = {
    "screenshot_restricted_conflicts", "preview_restricted_conflicts",
    "restricted_child_queue_conflicts", "unsafe_restricted_anchor_storage",
    "alert_queue_without_url_flag", "site_card_flag_without_url_support",
}


def consistency_categories(counts: dict[str, int]) -> list[dict]:
    details = []
    for name, count in sorted(counts.items()):
        count = int(count or 0)
        if not count:
            continue
        severity = "high" if name in HIGH_SEVERITY else "medium" if name in ANALYST_AFFECTING else "low"
        repairable = name in MECHANICAL_REPAIRABLE
        analyst_data = name in ANALYST_AFFECTING
        details.append({
            "category": name,
            "count": count,
            "severity": severity,
            "safe_auto_repair": bool(repairable and not analyst_data),
            "affects_analyst_data": bool(analyst_data),
            "scope": "analyst_review_or_alert_state" if analyst_data else "mechanical_state",
        })
    return details


def audit_consistency(sample_limit: int = 5) -> dict:
    with storage.get_db() as db:
        counts = {name: int(db.execute(query).fetchone()[0]) for name, query in AUDIT_QUERIES.items()}
        rows = [dict(row) for row in db.execute(f"""SELECT id,url,status,primary_category,safety_reason,
          trap_reason,queue_policy,depth FROM onion_urls WHERE
          (active=1 AND (status='blocked' OR queue_policy='blocked')) OR
          (active=0 AND status IN ('new','queued','retry')) OR
          (status='crawled' AND safety_reason='awaiting_page_classification')
          ORDER BY id LIMIT ?""", (max(0, min(sample_limit, 20)),))]
    # Category-sensitive counts require the fetched snapshot's JSON boundary,
    # which is deliberately not approximated from URL rows or edge tables.
    counts.update(_trusted_restricted_conflict_counts())
    counts["unknown_high_edge_pages"] = len(_current_link_repository_candidates(20))
    samples = [{
        "id": row["id"], "host": (urlsplit(row.get("url") or "").hostname or "unknown").casefold(),
        "status": row.get("status"), "category": row.get("primary_category"),
        "safety_reason": row.get("safety_reason"), "trap_reason": row.get("trap_reason"),
        "queue_policy": row.get("queue_policy"), "depth": row.get("depth"),
    } for row in rows]
    return {"counts": counts, "samples": samples,
            "details": consistency_categories(counts),
            "total_conflicts": sum(counts.values())}


def _remove_preview(path_value: str | None) -> None:
    if not path_value:
        return
    try:
        path = Path(path_value).resolve()
        if path.is_relative_to(PREVIEWS_DIR.resolve()) and path.is_file():
            path.unlink()
    except (OSError, ValueError):
        pass


def _repair_candidates() -> tuple[list[int], list[int], list[str]]:
    """Return bounded metadata needed by dry-run and write repair paths."""
    trusted_restricted_ids = _trusted_category_ids(RESTRICTED_CATEGORIES)
    directory_ids = _current_link_repository_candidates(20)
    with storage.get_db() as db:
        rows = db.execute(f"SELECT id,site_card_id FROM onion_urls WHERE {REPAIRABLE_URL_WHERE}").fetchall()
        preview_rows = [dict(row) for row in db.execute("""SELECT pp.preview_path,ou.id,
          ou.screenshot_policy,ou.storage_policy
          FROM page_previews pp JOIN onion_urls ou ON ou.url=pp.url
          WHERE pp.status='available'""")]
        directory_card_rows = db.execute(
            "SELECT site_card_id FROM onion_urls WHERE id IN (" +
            (",".join("?" for _ in directory_ids) or "NULL") + ")",
            tuple(directory_ids),
        ).fetchall()
    preview_paths = [str(row["preview_path"]) for row in preview_rows
                     if row.get("preview_path") and (
                         row.get("screenshot_policy") != "allowed"
                         or row.get("storage_policy") in {"metadata_only", "discard"}
                         or int(row["id"]) in trusted_restricted_ids)]
    url_ids = list(dict.fromkeys([int(row[0]) for row in rows]
                                 + directory_ids))
    card_ids = sorted({int(row[1]) for row in rows if row[1] is not None}
                      | {int(row[0]) for row in directory_card_rows if row[0] is not None})
    return url_ids, card_ids, preview_paths


def repair_consistency(dry_run: bool = False) -> dict:
    before = audit_consistency(0)["counts"]
    candidate_url_ids, card_ids, preview_paths = _repair_candidates()
    trusted_restricted_ids = _trusted_category_ids(RESTRICTED_CATEGORIES)
    trusted_hard_ids = _trusted_category_ids(HARD_RESTRICTED_CATEGORIES)
    unsafe_anchor_edges = int(before.get("unsafe_restricted_anchor_storage") or 0)
    result = {"dry_run": int(dry_run), "before": before, "mechanical_changes": 0,
              "candidate_urls": len(candidate_url_ids),
              "previews_removed": 0, "cards_refreshed": 0,
              "unsafe_anchors_sanitized": unsafe_anchor_edges}
    if dry_run:
        result["would_change"] = len(candidate_url_ids) + len(preview_paths) + unsafe_anchor_edges
        return result
    with storage.get_db() as db:
        if trusted_hard_ids:
            marks = ",".join("?" for _ in trusted_hard_ids)
            result["mechanical_changes"] += db.execute(f"""UPDATE onion_edges
              SET safe_anchor_text='Restricted child link hidden'
              WHERE discovered_url IN (SELECT url FROM onion_urls WHERE id IN ({marks}))
              AND COALESCE(safe_anchor_text,'') NOT IN
                ('','Restricted child link hidden','Unsafe anchor hidden')""",
              tuple(sorted(trusted_hard_ids))).rowcount
            result["mechanical_changes"] += db.execute(f"""UPDATE onion_urls SET
              active=0,status='blocked',queue_policy='blocked',
              storage_policy=CASE WHEN primary_category='adult_filtered' THEN 'discard'
                                  ELSE 'metadata_only' END,
              screenshot_policy='blocked',
              screenshot_blocked_reason=CASE WHEN primary_category='severe_abuse_risk'
                THEN 'severe_abuse_risk' ELSE 'adult_content_filtered' END
              WHERE id IN ({marks}) AND source_url IS NOT NULL
              AND (active!=0 OR queue_policy!='blocked'
                   OR storage_policy NOT IN ('metadata_only','discard'))""",
              tuple(sorted(trusted_hard_ids))).rowcount
        trusted_marks = ",".join("?" for _ in trusted_restricted_ids)
        trusted_clause = (f"AND id NOT IN ({trusted_marks})" if trusted_marks else "")
        result["mechanical_changes"] += db.execute(f"""UPDATE onion_urls SET active=1
          WHERE active=0 AND status IN ('new','queued','retry') AND queue_policy!='blocked'
          AND storage_policy NOT IN ('metadata_only','discard') {trusted_clause}""",
          tuple(sorted(trusted_restricted_ids))).rowcount
        result["mechanical_changes"] += db.execute("""UPDATE onion_urls SET queue_policy='blocked',active=0
          WHERE status='blocked' AND queue_policy!='blocked'""").rowcount
        result["mechanical_changes"] += db.execute("""UPDATE onion_urls SET active=0,status='blocked'
          WHERE active=1 AND queue_policy='blocked'""").rowcount
        result["mechanical_changes"] += db.execute("""UPDATE onion_urls SET safety_reason='unclassified',
          review_status=CASE WHEN review_status='monitor' THEN 'needs_review' ELSE review_status END,
          screenshot_policy='blocked',screenshot_blocked_reason='unclassified'
          WHERE status='crawled' AND safety_reason='awaiting_page_classification'""").rowcount
        result["previews_removed"] = len(preview_paths)
        category_clause = (f"OR id IN ({trusted_marks})" if trusted_marks else "")
        category_params = tuple(sorted(trusted_restricted_ids))
        db.execute(f"""UPDATE onion_urls SET screenshot_policy='blocked',
          screenshot_blocked_reason=COALESCE(screenshot_blocked_reason,'policy_blocked')
          WHERE storage_policy IN ('metadata_only','discard') {category_clause}""",
          category_params)
        preview_category_clause = (f"OR id IN ({trusted_marks})" if trusted_marks else "")
        db.execute(f"""UPDATE page_previews SET status='blocked',preview_path='',updated_at=? WHERE url IN
          (SELECT url FROM onion_urls WHERE screenshot_policy!='allowed'
           OR storage_policy IN ('metadata_only','discard') {preview_category_clause})""",
          (storage.utc_now_iso(), *category_params))
        directory_ids = _current_link_repository_candidates(20)
        if directory_ids:
            marks = ",".join("?" for _ in directory_ids)
            result["mechanical_changes"] += db.execute(f"""UPDATE onion_urls SET
              primary_category='directory_index',category='directory_index',
              content_category='directory_index',page_type='link_repository',
              queue_policy='expand',active=1,content_quality='meaningful',
              safety_reason='page_structure_directory_index',review_status='monitor',
              importance_level=COALESCE(analyst_importance,'normal')
              WHERE id IN ({marks})""", tuple(directory_ids)).rowcount
    for value in preview_paths:
        _remove_preview(value)
    from site_dedupe import update_site_card_rollups
    for card_id in card_ids:
        update_site_card_rollups(card_id)
    result["cards_refreshed"] = len(card_ids)
    result["after"] = audit_consistency(0)["counts"]
    return result


def repair_link_list_frontier(dry_run: bool = False) -> dict:
    parent_ids = _current_link_repository_candidates(5)
    trusted_hard_ids = _trusted_category_ids(HARD_RESTRICTED_CATEGORIES)
    trusted_any = _trusted_category_index(CONTENT_CATEGORIES)
    with storage.get_db() as db:
        analyst_owned_ids = {int(row[0]) for row in db.execute("""SELECT id FROM onion_urls
          WHERE analyst_category IS NOT NULL AND trim(analyst_category)!=''""")}
        child_ids: list[int] = []
        if parent_ids:
            marks = ",".join("?" for _ in parent_ids)
            child_ids = [int(row[0]) for row in db.execute(f"""SELECT child.id
              FROM onion_urls child JOIN onion_urls parent ON parent.url=child.source_url
              WHERE parent.id IN ({marks}) AND child.trap_reason='seed_depth_limit'
              AND lower(COALESCE(child.onion_domain,''))!=lower(COALESCE(parent.onion_domain,''))""",
              tuple(parent_ids))]
            child_ids = [url_id for url_id in child_ids
                         if url_id not in trusted_hard_ids and url_id not in analyst_owned_ids]
    untrusted_child_ids = [url_id for url_id in child_ids
                           if url_id not in trusted_any and url_id not in analyst_owned_ids]
    result = {"dry_run": int(dry_run), "directory_parents": len(parent_ids),
              "external_children": len(child_ids), "changed": 0}
    if dry_run:
        return result
    with storage.get_db() as db:
        if parent_ids:
            marks = ",".join("?" for _ in parent_ids)
            result["changed"] += db.execute(f"""UPDATE onion_urls SET primary_category='directory_index',
              category='directory_index',content_category='directory_index',
              page_type='link_repository',queue_policy='expand',active=1,
              content_quality='meaningful',safety_reason='page_structure_directory_index',review_status='monitor'
              WHERE id IN ({marks})""", parent_ids).rowcount
        if child_ids:
            marks = ",".join("?" for _ in child_ids)
            result["changed"] += db.execute(f"""UPDATE onion_urls SET depth=1,status='queued',active=1,
              queue_policy='normal',trap_reason=NULL,trap_score=0,safety_reason='awaiting_page_classification',
              next_crawl_at=? WHERE id IN ({marks})""", [storage.utc_now_iso(), *child_ids]).rowcount
        if untrusted_child_ids:
            marks = ",".join("?" for _ in untrusted_child_ids)
            db.execute(f"""UPDATE onion_urls SET
              primary_category='unknown',category='unknown',content_category='unknown',
              category_confidence='low',category_reason='Awaiting destination HTML classification',
              category_safe_label='Needs classification',page_type='unknown',
              site_type='unknown',risk_category='unknown',risk_level='low',risk_flags='[]',tags='[]',
              classification_decision='unverified_hint',classification_stage='prefetch',
              classification_confidence_score=0,
              classification_evidence_source='unverified',
              destination_html_evidence_version=0,verification_state='provisional',
              verification_reason='awaiting_destination_html',verified_at=NULL,
              storage_policy='safe_summary',safety_state='safe',review_status='monitor',
              ui_hidden_default=0,ui_priority=0,review_score=0,
              urgent_flag=0,urgent_score=0,urgent_reason=NULL,context_only=0,
              screenshot_policy='blocked',
              screenshot_blocked_reason='awaiting_destination_html'
              WHERE id IN ({marks})""", tuple(untrusted_child_ids))
    return result


def repair_site_cards(dry_run: bool = False) -> dict:
    with storage.get_db() as db:
        ids = [int(row[0]) for row in db.execute("SELECT id FROM site_cards")]
    from site_dedupe import reconcile_duplicate_site_cards, update_site_card_rollups
    duplicates = reconcile_duplicate_site_cards(dry_run=True)
    if dry_run:
        return {"dry_run": 1, "cards_found": len(ids), "cards_refreshed": 0,
                "duplicate_groups": duplicates["groups"],
                "duplicate_cards_to_merge": duplicates["cards_to_merge"],
                "duplicate_proposals": duplicates["proposals"]}
    applied_duplicates = reconcile_duplicate_site_cards(dry_run=False)
    with storage.get_db() as db:
        ids = [int(row[0]) for row in db.execute("SELECT id FROM site_cards")]
    for card_id in ids:
        update_site_card_rollups(card_id)
    return {"dry_run": 0, "cards_found": len(ids), "cards_refreshed": len(ids),
            "duplicate_groups": applied_duplicates["groups"],
            "duplicate_cards_merged": applied_duplicates["merged"]}
