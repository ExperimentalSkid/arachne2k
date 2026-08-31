"""Build simple, persisted site profiles from existing passive collection data."""
from __future__ import annotations

import json
from urllib.parse import urlsplit

import storage
from universal_classifier import safe_category_label


PLAIN_CATEGORY_TEXT = {
    "Hidden Service Directory": "A page that lists or organizes other onion sites.",
    "Search / Index": "A search or index page used to find other hidden-service pages.",
    "Social / Forum": "A discussion, community, or forum-style page.",
    "Marketplace-related Context": "A page containing marketplace-related wording. This label is for review only.",
    "Leak / Extortion Context": "A page referring to leaks, exposed data, victims, or extortion claims.",
    "Recruitment Context": "A page containing recruitment or membership-related wording.",
    "Contact / Infrastructure": "A page mainly connected through public contact details, mirrors, or infrastructure clues.",
    "Hosting / Services": "A page describing hosting or other online services.",
    "Wiki / Knowledge": "A reference, documentation, or knowledge-style page.",
    "Unknown / Miscellaneous": "The system found this onion page but does not yet have enough information to describe it confidently.",
    "Needs classification": "The system found this onion page but does not yet have enough information to describe it confidently.",
}


def _reasons(value) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
        return parsed if isinstance(parsed, list) else []
    except (TypeError, ValueError):
        return []


def _load_rows(url: str | None = None) -> list[dict]:
    with storage.get_db() as db:
        sql = """SELECT ou.*,h.reasons AS hit_reasons,h.indicators_json,
            h.passive_exposures_json,mu.cluster_id,mc.cluster_type,pt.topics_json,pt.keywords_json
            FROM onion_urls ou LEFT JOIN onion_hits h ON h.id=(SELECT id FROM onion_hits WHERE url=ou.url ORDER BY ts DESC LIMIT 1)
            LEFT JOIN mirror_urls mu ON mu.url=ou.url LEFT JOIN mirror_clusters mc ON mc.id=mu.cluster_id
            LEFT JOIN page_topics pt ON pt.url=ou.url
        """
        params = ()
        if url:
            sql += " WHERE ou.url=?"
            params = (url,)
        sql += " ORDER BY ou.first_seen"
        return [dict(row) for row in db.execute(sql, params)]


def _save_profile(row: dict) -> None:
    if row.get("storage_policy") == "discard" or row.get("primary_category") == "adult_filtered":
        return
    category_code = row.get("primary_category") or "unknown"
    category = safe_category_label(category_code)
    # Unknown remains unknown until the destination's fetched HTML supplies
    # evidence. Legacy URL paths, parent reasons, and cluster labels are not a
    # substitute for destination-owned classification.
    host = urlsplit(row["url"]).hostname or "Unknown onion site"
    if row.get("storage_policy") == "metadata_only":
        name = category
        explanation = "Restricted page. Metadata only retained. No preview, snippet, screenshot, title, or content text is shown."
    elif row.get("storage_policy") == "metadata_limited":
        name = category
        explanation = f"{category}. Only limited safe metadata is retained; transaction, contact, secret, and content details are omitted."
    else:
        name = (row.get("title") or host).strip()[:160]
        legacy = {
            "Directory / index": "A page that lists or organizes other onion sites.",
            "Forum / social": "A discussion, community, or forum-style page.",
            "Hosting / services": "A page describing hosting or other online services.",
            "Contact / infrastructure": "A page connected through public mirrors or infrastructure clues.",
            "Unknown": "The system found this onion page but does not yet have enough safe information to describe it confidently."
        }
        explanation = PLAIN_CATEGORY_TEXT.get(category, legacy.get(category, f"Classified as {category} for analyst review."))
    try:
        topics = json.loads(row.get("topics_json") or "[]")
    except (TypeError, ValueError):
        topics = []
    if topics and row.get("storage_policy") != "metadata_only":
        explanation += " Visible front-page text suggests: " + ", ".join(topics[:4]) + "."
    if row.get("cluster_id"):
        explanation += f" It is also connected to related-site group #{row['cluster_id']} through shared passive clues."
    source = "Added manually" if row.get("source_type") == "manual_seed" else (
        f"Found as a link on {row.get('source_url')}" if row.get("source_url") else "Found during passive collection"
    )
    storage.upsert_site_profile(row["url"], name, category, explanation, source)


def refresh_site_profiles() -> int:
    rows = _load_rows()
    visible = [row for row in rows if row.get("storage_policy") != "discard" and row.get("primary_category") != "adult_filtered"]
    for row in visible:
        _save_profile(row)
    return len(visible)


def refresh_site_profile(url: str) -> bool:
    rows = _load_rows(url)
    if not rows:
        return False
    _save_profile(rows[0])
    return True
