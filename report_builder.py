"""Storage-policy-aware Markdown evidence reports."""
from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlsplit

import storage
from passive_attribution import build_attribution_profile
from paths import REPORTS_DIR
from safety_policy import is_severe_blackhole_policy, make_safe_snippet, redact_sensitive
from universal_classifier import safe_category_label

SAFETY_NOTE = ("This report contains safe metadata, hashes, passive correlations, policy-approved exposure "
               "summaries, and short approved snippets only. It contains no downloaded files, credentials, "
               "illegal media, transaction instructions, exploit material, or restricted page content.")
TOOL_NAME = "Arachne"


def _list(values) -> str:
    safe = [str(value) for value in values if value]
    return "\n".join(f"- {make_safe_snippet(redact_sensitive(value), max_chars=500)}" for value in safe) or "- None observed"


def build_site_card_report(site_card_id: int, generated_by: str = "local_operator",
                           analyst_notes: str | None = None) -> str:
    from site_dedupe import get_site_card
    with storage.get_db() as db:
        raw_card = db.execute("SELECT * FROM site_cards WHERE id=?", (site_card_id,)).fetchone()
        severe_child = db.execute("""SELECT 1 FROM onion_urls ou
          JOIN site_card_urls scu ON scu.onion_url_id=ou.id
          WHERE scu.site_card_id=? AND (
            ou.primary_category='severe_abuse_risk'
            OR ou.safety_reason IN ('severe_abuse_blackhole','severe_abuse_risk','severe_content_filtered')
          ) LIMIT 1""", (site_card_id,)).fetchone()
    if is_severe_blackhole_policy(raw_card) or severe_child:
        raise ValueError("Severe-blackhole Site Cards cannot generate reports")
    card = get_site_card(site_card_id)
    if not card:
        raise ValueError("Site Card not found")
    if card.get("primary_category") in {"adult_filtered", "adult_restricted"} or card.get("storage_policy") == "discard":
        raise ValueError("Adult-filtered Site Cards cannot generate reports")
    restricted = card.get("storage_policy") in {"metadata_only", "metadata_limited"}
    detected_name = (safe_category_label(card.get("primary_category")) if restricted
                     else (card.get("display_name") or "Unavailable"))
    analyst_title = make_safe_snippet(card.get("analyst_title") or "", max_chars=180)
    display_name = analyst_title or detected_name
    urls = card.get("urls", [])
    live = [f"{item['url']} ({item.get('mirror_confidence') or 'unknown'})" for item in urls
            if item.get("active") and item.get("status") != "dead"]
    dead = [f"{item['url']} | reason={item.get('dead_reason') or 'inactive'} | last checked={item.get('last_checked_at') or 'unknown'}"
            for item in urls if item.get("status") == "dead" or item.get("dead_reason")]
    paths = [f"{item.get('path') or '/'} — {item.get('primary_category') or 'unknown'}" for item in urls]
    sections = storage.get_site_card_sections(site_card_id)
    section_lines = [
        f"{section['path']} | category={section['category']} | Spain={section.get('spain_evidence') or 'none'} | "
        f"preview={section.get('preview_state') or 'missing'} | first={section.get('first_seen') or 'unknown'} | "
        f"last={section.get('last_seen') or section.get('last_checked_at') or 'unknown'}"
        for section in sections
    ]
    sources = list(dict.fromkeys(item.get("source_url") for item in urls if item.get("source_url")))
    indicators = []
    if not restricted:
        with storage.get_db() as db:
            indicators = [f"{row['indicator_type']}: {redact_sensitive(row['value'])}" for row in db.execute("""
              SELECT DISTINCT i.indicator_type,i.value FROM indicators i JOIN indicator_links il ON il.indicator_id=i.id
              JOIN site_card_urls scu ON scu.url=il.source_ref WHERE scu.site_card_id=? LIMIT 100""", (site_card_id,))]
    preview = "Restricted placeholder only" if restricted else "No approved preview"
    if not restricted:
        for item in urls:
            found = storage.get_page_preview(item["url"])
            if found and found.get("status") == "available":
                preview = f"Approved preview: {found.get('preview_path')}"
                break
    generated = datetime.now(timezone.utc)
    generated_iso = generated.isoformat().replace('+00:00','Z')
    source_host = next((item.get("onion_host") for item in urls if item.get("onion_host")), "Unavailable")
    recommended = ("Urgent Spain-focused analyst review" if card.get("triage_level") == "urgent" else
                   "Review Spain/actionability evidence" if card.get("triage_level") in {"alert", "needs_check"} else
                   "Monitor; no strong Spain/actionable evidence recorded")
    body = f"""# {display_name}

Operational Site Review Report

## Report control

- Generated UTC: {generated.isoformat().replace('+00:00','Z')}
- Tool/source: {TOOL_NAME}
- Canonical Site Card ID: {card['canonical_site_id']}
- Analyst title: {analyst_title or 'Not set'}
- Detected/generated title: {detected_name}
- Source host: {source_host}
- Onion root / canonical identity: {card.get('canonical_site_id') or source_host}
- Primary category: {safe_category_label(card.get('primary_category'))}
- Risk level: {card.get('risk_level') or 'unknown'}
- Urgency level: {card.get('triage_level') or ('urgent' if card.get('urgent_flag') else 'monitor')}
- Urgency reason: {card.get('triage_reason') or card.get('urgent_reason') or card.get('review_reason') or 'Not recorded'}
- Review status: {card.get('review_status') or 'pending'}
- Spain priority: {'Yes' if card.get('spain_priority') else 'No'}
- Spain relevance: {card.get('spain_relevance') or 'none'}
- Spain evidence type: {card.get('spain_evidence_type') or card.get('spain_priority_evidence_type') or 'Not applicable'}
- Spain reason: {card.get('spain_match_reason') or card.get('spain_priority_reason') or 'Not applicable'}
- Mirrors: {card.get('mirror_count', 0)}
- Live URLs: {card.get('live_url_count', 0)}
- Dead URLs: {card.get('dead_url_count', 0)}
- Recommended action: {recommended}

## Live mirrors and URLs

{_list(live)}

## Dead mirrors / inactive URLs

{_list(dead)}

## Discovered paths and categories

{_list(paths)}

## Relevant discovered sections

{_list(section_lines)}

## Source chain

{_list(sources)}

## Safe indicators

{_list(indicators) if not restricted else '- Omitted by metadata-only policy'}

## Preview policy

- {preview}
- Preview/OCR note: previews are referenced only when policy-approved. Unsafe screenshots are not embedded.

## Safety restrictions

{('Restricted or metadata-limited card. No snippets, unsafe titles, product descriptions, raw content, previews, screenshots, or content fingerprints are included.' if restricted else 'Only safe passive metadata and approved preview references are included.')}

## Analyst notes

{make_safe_snippet(redact_sensitive(analyst_notes or 'No analyst notes supplied.'), max_chars=1000)}

## Safety note

{SAFETY_NOTE}

## Chain-of-custody style crawl metadata

- First seen: {card.get('first_seen') or 'Unknown'}
- Last seen: {card.get('last_seen') or 'Unknown'}
- Last checked: {card.get('last_checked_at') or 'Unknown'}
- Report generated by: {generated_by}
- Safe metadata only: Yes
"""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    output = REPORTS_DIR / f"report_site_card_{card['canonical_site_id']}_{generated.strftime('%Y%m%d_%H%M%S')}.md"
    output.write_text(body, encoding="utf-8")
    storage.insert_evidence_report("site_card", str(output), generated_by, site_card_id=site_card_id)
    with storage.get_db() as db:
        db.execute("""UPDATE site_cards SET report_status='generated',report_generated_at=?,
          report_error=NULL,review_status='reported',updated_at=? WHERE id=?""",
                   (generated_iso, generated_iso, site_card_id))
        db.execute("UPDATE onion_urls SET review_status='reported',spain_review_status=CASE WHEN spain_priority=1 THEN 'reported' ELSE spain_review_status END WHERE site_card_id=?",
                   (site_card_id,))
    return str(output)


def build_url_report(url: str, generated_by: str = "local_operator") -> str:
    """Create a safe single-item report, including Spain overlay metadata."""
    with storage.get_db() as db:
        row = db.execute("SELECT * FROM onion_urls WHERE url=?", (url,)).fetchone()
    if not row:
        raise ValueError("Onion URL not found")
    item = dict(row)
    if is_severe_blackhole_policy(item):
        raise ValueError("Severe-blackhole URLs cannot generate reports")
    if item.get("primary_category") in {"adult_filtered", "adult_restricted"} or item.get("storage_policy") == "discard":
        raise ValueError("Adult-filtered URLs cannot generate reports")
    restricted = item.get("storage_policy") in {"metadata_only", "metadata_limited"}
    generated = datetime.now(timezone.utc)
    category = safe_category_label(item.get("primary_category"))
    safe_title = "Omitted by restricted-content policy" if restricted else make_safe_snippet(item.get("title") or "Unavailable", 200)
    body = f"""# Passive OSINT Item Report

- Generated timestamp UTC: {generated.isoformat().replace('+00:00','Z')}
- URL: {item['url']}
- Onion host: {item.get('onion_domain') or (urlsplit(item['url']).hostname or 'Unavailable')}
- Category: {category}
- Risk: {item.get('risk_level') or 'unknown'}
- Storage policy: {item.get('storage_policy') or 'safe_summary'}
- Review status: {item.get('review_status') or 'pending'}
- Safe title: {safe_title}
- First seen: {item.get('first_seen') or 'Unknown'}
- Last checked: {item.get('last_checked_at') or 'Not yet checked'}
- Source URL: {item.get('source_url') or 'Manual or unavailable'}

## Spain priority

- Spain priority: {'Yes' if item.get('spain_priority') else 'No'}
- Language: {item.get('spain_match_language') or 'UNKNOWN'}
- Match reason: {item.get('spain_match_reason') or 'Not applicable'}
- Confidence: {item.get('spain_confidence') or 'Not applicable'}
- Analyst decision: {item.get('spain_review_status') or item.get('review_status') or 'unreviewed'}

## Safety handling

{('Restricted or metadata-limited item. No title, product description, content excerpt, snippet, preview, screenshot, or content indicators are included.' if restricted else 'Only policy-approved safe metadata is included. No files, secrets, transaction instructions, or media are included.')}

## Safety note

{SAFETY_NOTE}
"""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(url.encode("utf-8", "ignore")).hexdigest()[:12]
    output = REPORTS_DIR / f"report_item_{digest}_{generated.strftime('%Y%m%d_%H%M%S')}.md"
    output.write_text(body, encoding="utf-8")
    storage.insert_evidence_report("onion_url", str(output), generated_by, site_card_id=item.get("site_card_id"))
    return str(output)


def build_cluster_report(cluster_id: int, generated_by: str = "local_operator") -> str:
    cluster = storage.get_mirror_cluster(cluster_id)
    if not cluster:
        raise ValueError("Cluster not found")
    urls = cluster.get("urls", [])
    if any(is_severe_blackhole_policy(item) for item in urls):
        raise ValueError("Clusters containing severe-blackhole URLs cannot generate reports")
    profile = build_attribution_profile(cluster_id)
    restricted_urls = {item["url"] for item in urls if item.get("storage_policy") in {"metadata_only", "metadata_limited"}}
    active = [item["url"] for item in urls if item.get("status") == "active"]
    offline = [item["url"] for item in urls if item.get("status") == "offline"]
    onion = [item["url"] for item in urls if (urlsplit(item["url"]).hostname or "").endswith(".onion")]
    clearnet = [item["url"] for item in urls if not (urlsplit(item["url"]).hostname or "").endswith(".onion")]

    indicators = json.loads(cluster.get("shared_indicators_json") or "[]") if not restricted_urls else []
    grouped: dict[str, list[str]] = {}
    for indicator in indicators:
        raw = str(indicator)
        kind, value = raw.split(":", 1) if ":" in raw else ("other", raw)
        grouped.setdefault(kind, []).append(value)
    indicator_lines = [f"**{kind.replace('_',' ').title()}**: {', '.join(values[:20])}" for kind, values in grouped.items()]

    exposures = [entry for entry in cluster.get("passive_exposures", []) if entry.get("url") not in restricted_urls]
    exposure_lines = [f"**{entry['exposure_type'].replace('_',' ').title()}** ({entry['severity']}) — "
                      f"{entry.get('value','Unavailable')}. Source: {entry.get('source','normal_fetch_response')}."
                      for entry in exposures]
    categorized = []
    for item in urls:
        label = safe_category_label(item.get("primary_category") or "unknown")
        categorized.append(f"{label}: {item['url']} | storage={item.get('storage_policy') or 'safe_summary'}")

    preview_lines = []
    for item in urls:
        preview = storage.get_page_preview(item["url"])
        if (preview and preview.get("status") == "available" and item.get("storage_policy") not in {"metadata_only", "metadata_limited"}
                and item.get("screenshot_policy") in {None, "allowed"}):
            preview_lines.append(f"{item['url']} — Preview available at `{preview['preview_path']}`")
    spain_lines = [f"{item['url']} | language={item.get('spain_match_language') or 'UNKNOWN'} | "
                   f"reason={item.get('spain_match_reason') or 'Spain priority context'}"
                   for item in urls if item.get("spain_priority")]
    summary = ("Cluster contains restricted metadata-only item(s); content summary omitted."
               if restricted_urls else make_safe_snippet(cluster.get("summary") or "", max_chars=1000))
    generated = datetime.now(timezone.utc)
    body = f"""# Passive OSINT Evidence Report — Cluster {cluster_id}

- Generated timestamp UTC: {generated.isoformat().replace('+00:00','Z')}
- Cluster ID: {cluster_id}
- Cluster type: {cluster.get('cluster_type') or 'unknown'}
- Risk level: {cluster.get('risk_level') or 'unknown'}
- First seen: {cluster.get('first_seen')}
- Last seen: {cluster.get('last_seen')}
- Review status: {cluster.get('review_status')}

## Summary

{summary}

These URLs were grouped through passive shared indicators and metadata. This is a review lead, not proof of ownership, identity, or physical server location.

## Passive attribution

- Confidence: {profile['confidence_level']} ({profile['confidence_score']}/100)
- Explanation: {profile['explanation']}
- Limitations: {profile['limitations']}

## Categories and storage policies

{_list(categorized)}

## Spain priority

{_list(spain_lines)}

## Active URLs

{_list(active)}

## Offline URLs

{_list(offline)}

## Onion URLs

{_list(onion)}

## Clearnet URLs (evidence only)

{_list(clearnet)}

## Source chain

{_list(item.get('source_ref') for item in urls)}

## Shared indicators

{_list(indicator_lines)}

## Passive exposures approved for reporting

{_list(exposure_lines)}

## Page previews approved by policy

{_list(preview_lines)}

Restricted and metadata-only items never include preview references or content excerpts.

## Content hashes

{_list(item.get('content_hash') for item in urls if item.get('storage_policy') not in {'metadata_only', 'metadata_limited'})}

## Safety note

{SAFETY_NOTE}
"""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    output = REPORTS_DIR / f"report_cluster_{cluster_id}_{generated.strftime('%Y%m%d_%H%M%S')}.md"
    output.write_text(body, encoding="utf-8")
    storage.insert_evidence_report("mirror_cluster", str(output), generated_by, cluster_id=cluster_id)
    return str(output)
