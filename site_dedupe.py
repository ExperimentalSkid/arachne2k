"""Passive-only canonical Site Card grouping and safe mirror fingerprinting."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import storage
from safety_policy import is_severe_blackhole_policy
from site_identifier import identify_site
from urgency_policy import decide_triage
from url_identity import canonicalize
from forum_url_identity import classify_forum_url
from classification_schema import (CHILD_PAGE_TYPES, DESTINATION_HTML_EVIDENCE_VERSION,
                                   LANDING_PAGE_TYPES, derive_safety_state,
                                   normalize_content_category, normalize_page_type)
from universal_classifier import (NEUTRAL_CATEGORIES, category_search_tags, classify_url_prefetch,
                                  normalize_text, safe_category_label)


RISK_ORDER = {"low": 1, "bajo": 1, "medium": 2, "medio": 2, "high": 3, "alto": 3,
              "critical": 4, "critico": 4}
CATEGORY_ORDER = {
    "severe_abuse_risk": 100, "adult_restricted": 95, "adult_filtered": 95,
    "marketplace_weapons": 92, "marketplace_credentials": 90, "marketplace_leaks": 89,
    "marketplace_drugs": 88, "marketplace_fraud": 87, "marketplace_counterfeit": 65,
    "marketplace_services": 60, "weapons_arms": 85,
    "drugs": 82, "credentials": 80, "malware_hacking": 78,
    "extremist_recruitment": 76, "leaks_data": 74, "fraud_financial": 70,
    "marketplace": 55, "contact_infrastructure": 40, "hosting_services": 30,
    "forum_social": 25, "search_engine": 22, "directory_index": 20,
    "infosec_research": 19, "privacy_anonymity": 18, "news_media": 17,
    "technology_software": 16, "finance_cryptocurrency": 15,
    "education_reference": 14, "activism_civil_society": 13,
    "religion_spirituality": 12, "personal_blog": 11,
    "communication_services": 15, "file_storage_sharing": 14,
    "arts_culture": 11, "health_wellness": 12,
    "spam_noise": 2, "dead_softdead": 1, "general_other": 0, "unknown": 0,
}
STRONG_TYPES = {"pgp_key_block", "wallet_btc", "wallet_eth", "telegram_handle", "email",
                "jabber_id", "matrix_id", "tox_id", "session_id", "username"}
INDEX_PATHS = {"", "/", "/index.php", "/index.html", "/index.htm", "/home", "/home/"}
ENRICHMENT_RESTRICTED_CATEGORIES = {"adult_filtered", "adult_restricted", "severe_abuse_risk"}
FORUM_CASE_CATEGORIES = {"weapons_arms", "fraud_financial", "credentials", "leaks_data",
                         "malware_hacking", "drugs", "marketplace_weapons",
                         "marketplace_fraud", "marketplace_credentials", "marketplace_leaks",
                         "marketplace_drugs"}
ANALYST_CATEGORY_OPTIONS = [
    "unknown", "general_other", "directory_index", "search_engine", "forum_social", "hosting_services",
    "contact_infrastructure", "infosec_research", "privacy_anonymity", "news_media",
    "religion_spirituality", "education_reference", "technology_software",
    "finance_cryptocurrency", "activism_civil_society", "personal_blog",
    "communication_services", "file_storage_sharing", "arts_culture", "health_wellness",
    "marketplace", "marketplace_drugs", "marketplace_weapons",
    "marketplace_fraud", "marketplace_credentials", "marketplace_leaks",
    "marketplace_counterfeit", "marketplace_services", "weapons_arms", "drugs",
    "leaks_data", "credentials", "malware_hacking", "fraud_financial",
    "extremist_recruitment",
]
_SEVERE_ROLLUP_GUARD: set[int] = set()


@dataclass
class CardCreationDecision:
    url_id: int
    url: str
    host: str
    canonical_root: str
    entity_identity: str
    normalized_path: str
    path_signature: str
    query_signature: str
    classification: dict
    restricted: bool
    existing_card_id: int | None = None
    matched_card_id: int | None = None
    possible_card_id: int | None = None
    match_confidence: str = "unknown"
    url_role: str = "canonical"
    decision_reason: str = "new_card"

    @property
    def target_card_id(self) -> int | None:
        return self.matched_card_id or self.existing_card_id

    def safe_metadata(self) -> dict:
        metadata = asdict(self)
        metadata.pop("classification", None)
        return metadata


def _trusted_content_category(policy: dict) -> str | None:
    """Return the exact trusted category value, never a provenance boolean.

    A manual value proves only itself; it must not bless a different generated
    category in the same row. Automated truth also needs the completed verifier
    state, not merely a caller-supplied evidence-version number.
    """
    analyst = str(policy.get("analyst_category") or "").strip()
    if analyst:
        return normalize_content_category(analyst)
    if (
        policy.get("verification_state") == "verified"
        and policy.get("verification_reason") == "page_fetched_and_classified"
        and policy.get("classification_evidence_source") == "destination_html"
        and int(policy.get("destination_html_evidence_version") or 0)
            >= DESTINATION_HTML_EVIDENCE_VERSION
    ):
        value = policy.get("content_category")
        if value in {None, "", "unknown"}:
            value = policy.get("primary_category")
        return normalize_content_category(value)
    return None


def _content_classification_trusted(policy: dict) -> bool:
    return _trusted_content_category(policy) is not None


def _trusted_row_policy(item: dict) -> dict | None:
    """Build card policy only from the authoritative persisted URL row."""
    category = _trusted_content_category(item)
    if category is None:
        return None
    result = dict(item)
    result["primary_category"] = result["category"] = result["content_category"] = category
    for key in (
        "tags", "risk_flags", "secondary_categories", "spain_context_tags",
        "category_supporting_evidence_json", "category_contradicting_evidence_json",
    ):
        if isinstance(result.get(key), str):
            result[key] = _loads(result.get(key), [])
    return result


def _adult_filtered(policy: dict) -> bool:
    return _trusted_content_category(policy) in {"adult_filtered", "adult_restricted"}


def _severe_blackhole(*policies: object) -> bool:
    """Return true for canonical and legacy severe blackhole rows.

    Severe content is intentionally not treated as an ordinary restricted
    category here: it must never participate in Site Card identity, mirror
    matching, fingerprints, reports, or dashboard rollups.
    """
    return any(
        isinstance(policy, dict)
        and _trusted_content_category(policy) == "severe_abuse_risk"
        for policy in policies if policy is not None
    )


def _enforce_severe_url(item: dict, policy: dict | None = None) -> None:
    """Delegate artifact removal to the canonical storage blackhole."""
    storage.enforce_severe_blackhole(str(item["url"]), policy or item)


def _is_forum_thread_case(classification: dict, item: dict | None = None) -> bool:
    """Promote only high-signal forum threads into their own case card.

    Ordinary forum pages/threads stay attached to the parent forum Site Card.
    This keeps the dashboard calm while letting Spain/direct-risk thread URLs
    appear as exact review targets.
    """
    if item is not None:
        combined = _trusted_row_policy(item)
    else:
        combined = dict(classification or {}) if _content_classification_trusted(classification or {}) else None
    if combined is None:
        return False
    if _adult_filtered(combined) or _severe_blackhole(combined):
        return False
    page_type = normalize_page_type(combined.get("page_type"))
    if page_type != "forum_thread":
        return False
    if int(combined.get("context_only") or 0):
        return False
    category = normalize_content_category(combined.get("primary_category"))
    risk = str(combined.get("risk_level") or "low").casefold()
    high_risk = risk in {"high", "critical", "alto", "critico"}
    spain_direct = bool(combined.get("spain_priority")) and (
        bool(combined.get("spain_actionable"))
        or str(combined.get("spain_relevance") or "").casefold() == "high"
        or category in FORUM_CASE_CATEGORIES
        or high_risk
    )
    direct_risk = category in FORUM_CASE_CATEGORIES and high_risk
    urgent_direct = bool(combined.get("urgent_flag")) and (
        category in FORUM_CASE_CATEGORIES or bool(combined.get("spain_priority")) or high_risk
    )
    return bool(spain_direct or direct_risk or urgent_direct or combined.get("report_required"))


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()


def _loads(value, default=None):
    try:
        parsed = json.loads(value or "")
        return parsed
    except (TypeError, ValueError):
        return [] if default is None else default


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _looks_like_placeholder_title(value: str | None, hosts: set[str]) -> bool:
    text = str(value or "").strip().casefold()
    if not text:
        return True
    if text in {"unnamed onion site", "unknown", "site", "homepage"}:
        return True
    if text in {str(host or "").casefold() for host in hosts}:
        return True
    return False


GENERIC_IDENTITY_LABELS = {
    "marketplace", "market", "marketplace context", "marketplace fraud", "marketplace drugs",
    "marketplace weapons", "marketplace credentials", "marketplace leaks", "marketplace services",
    "marketplace counterfeit", "forum", "community", "directory", "link list", "onion links",
    "hidden wiki", "index", "home", "homepage", "welcome", "login", "sign in", "register",
    "shop", "store", "vendor", "seller", "product", "listing", "category", "unknown",
    "needs classification", "restricted content", "filtered adult content",
    "insufficient page evidence", "malware hacking", "fraud financial", "drugs",
    "weapons arms context", "weapons arms", "direct marketplace or listing structure detected",
}


def _clean_identity_candidate(value: object, limit: int = 120) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip(" \t\r\n|·-—:")
    text = re.sub(r"^(?:open|visit|go to|click|enter|view)\s+", "", text, flags=re.I).strip()
    return text[:limit].rstrip(" \t\r\n|·-—:")


def _identity_key(value: object) -> str:
    text = normalize_text(_clean_identity_candidate(value))
    text = re.sub(r"[^a-z0-9]+", " ", text).strip()
    return text


def _is_generic_identity_label(value: object, hosts: set[str] | None = None) -> bool:
    cleaned = _clean_identity_candidate(value)
    key = _identity_key(cleaned)
    if not key:
        return True
    if hosts and key in {_identity_key(host) for host in hosts if host}:
        return True
    if key in GENERIC_IDENTITY_LABELS:
        return True
    words = key.split()
    generic_nouns = {
        "market", "marketplace", "forum", "directory", "links", "index", "shop",
        "store", "vendor", "seller",
    }
    generic_modifiers = {
        "drug", "drugs", "weapon", "weapons", "fraud", "carding", "hacking",
        "malware", "leak", "leaks", "credential", "credentials", "adult",
        "onion", "hidden",
    }
    if len(words) == 1 and words[0] in generic_nouns | generic_modifiers:
        return True
    if len(words) == 2 and words[0] in generic_modifiers and words[1] in generic_nouns:
        return True
    if any(marker in key for marker in ("http onion", ".onion")):
        return True
    return False


def _limited_title_safe(value: str) -> bool:
    key = _identity_key(value)
    if not key or len(value) > 90:
        return False
    return not re.search(
        r"\b(?:buy|order|checkout|cart|price|vendor profile|listing|product|"
        r"shipping|ships from|ships to|contact seller)\b|[$€£]\s*\d|@\w+|https?://",
        key,
    )


def _site_identity_candidates(db: sqlite3.Connection, rows: list[dict], hosts: set[str]) -> list[dict]:
    """Build safe, scored Site Card name candidates from page and directory evidence."""
    candidates: list[dict] = []
    confidence_weight = {"low": 0, "medium": 12, "high": 24, "analyst": 40}
    source_weight = {
        "safe_site_name": 36, "safe_display_name": 30, "detected_title": 22,
        "title": 18, "directory_anchor": 16,
    }
    for row in rows:
        if row.get("storage_policy") in {"metadata_only", "discard"}:
            continue
        page_type = normalize_page_type(row.get("page_type"))
        root_bonus = 22 if row.get("card_path") in {None, "", "/"} else 0
        landing_bonus = 10 if page_type in LANDING_PAGE_TYPES else 0
        child_penalty = 14 if page_type in CHILD_PAGE_TYPES else 0
        ready_bonus = 8 if row.get("card_ready") else 0
        confidence_bonus = confidence_weight.get(str(row.get("identity_confidence") or "low").casefold(), 0)
        for field in ("safe_site_name", "safe_display_name", "detected_title", "title"):
            name = _clean_identity_candidate(row.get(field))
            if _is_generic_identity_label(name, hosts):
                continue
            if field in {"safe_site_name", "safe_display_name"} and not _limited_title_safe(name):
                continue
            score = (source_weight[field] + root_bonus + landing_bonus + ready_bonus
                     + confidence_bonus - child_penalty)
            candidates.append({
                "name": name, "source": field, "score": score,
                "url": row.get("url"), "confidence": row.get("identity_confidence") or "low",
            })

    urls = [row.get("url") for row in rows if row.get("url")]
    if urls:
        marks = ",".join("?" for _ in urls)
        edge_rows = db.execute(f"""SELECT discovered_url,safe_anchor_text,relation_type,source_page_type
          FROM onion_edges WHERE discovered_url IN ({marks})
          AND COALESCE(safe_anchor_text,'')!=''""", urls).fetchall()
        grouped: dict[str, dict] = {}
        for edge in edge_rows:
            anchor = _clean_identity_candidate(edge["safe_anchor_text"], 100)
            if _is_generic_identity_label(anchor, hosts) or not _limited_title_safe(anchor):
                continue
            key = _identity_key(anchor)
            item = grouped.setdefault(key, {
                "name": anchor, "source": "directory_anchor", "score": 0,
                "url": edge["discovered_url"], "confidence": "medium", "count": 0,
            })
            item["count"] += 1
            relation_bonus = 8 if edge["relation_type"] in {"directory_entry", "marketplace_link"} else 0
            item["score"] = max(item["score"], source_weight["directory_anchor"] + relation_bonus)
        for item in grouped.values():
            item["score"] += min(18, int(item.pop("count", 0)) * 6)
            candidates.append(item)
    return candidates


def _choose_site_identity(db: sqlite3.Connection, representative_rows: list[dict],
                          hosts: set[str]) -> tuple[str | None, str, dict | None]:
    candidates = _site_identity_candidates(db, representative_rows, hosts)
    if not candidates:
        return None, "host_label", None
    selected = max(candidates, key=lambda item: (int(item.get("score") or 0), len(str(item.get("name") or ""))))
    source = str(selected.get("source") or "safe_front_page_identity")
    display_source = "directory_anchor_identity" if source == "directory_anchor" else "safe_front_page_identity"
    return str(selected["name"])[:180], display_source, selected


def _card_completeness(rows: list[dict], *, display: str, primary: str,
                       consensus_page_type: str, category_confidence: str | None,
                       page_type_confidence: str | None, hosts: set[str],
                       indicator_types: list[str], live: int,
                       last_checked_at: str | None) -> tuple[int, str, str]:
    score = 0
    reasons: list[str] = []
    if not _looks_like_placeholder_title(display, hosts):
        score += 15
        reasons.append("stable_title")
    if any(row.get("card_path") in {None, "", "/"} or normalize_page_type(row.get("page_type")) == "homepage"
           for row in rows):
        score += 15
        reasons.append("homepage_seen")
    if str(page_type_confidence or "").casefold() in {"high", "analyst"} or consensus_page_type in LANDING_PAGE_TYPES:
        score += 15
        reasons.append("page_type_high")
    elif str(page_type_confidence or "").casefold() == "medium":
        score += 10
        reasons.append("page_type_medium")
    if primary and primary != "unknown" and str(category_confidence or "").casefold() in {"high", "critical", "analyst"}:
        score += 15
        reasons.append("category_high")
    elif primary and primary != "unknown" and str(category_confidence or "").casefold() == "medium":
        score += 10
        reasons.append("category_medium")
    if len(hosts) > 1 or any(int(row.get("seen_count") or 0) > 1 for row in rows):
        score += 10
        reasons.append("duplicate_or_mirror_evidence")
    if any(kind in STRONG_TYPES for kind in indicator_types):
        score += 10
        reasons.append("safe_contact_or_crypto_indicator")
    if live >= 4:
        score += 15
        reasons.append("representative_pages")
    elif live >= 2:
        score += 10
        reasons.append("some_representative_pages")
    checked = _parse_iso(last_checked_at)
    if checked and checked >= datetime.now(timezone.utc) - timedelta(days=7):
        score += 10
        reasons.append("recent_success")
    score = max(0, min(100, score))
    label = "strong" if score >= 75 else "usable" if score >= 45 else "weak"
    missing = []
    if "stable_title" not in reasons:
        missing.append("needs_stable_title")
    if "homepage_seen" not in reasons:
        missing.append("needs_homepage")
    if not any(reason.startswith("category_") for reason in reasons):
        missing.append("needs_category_confidence")
    if not any(reason.startswith("page_type_") for reason in reasons):
        missing.append("needs_page_type_confidence")
    return score, label, ", ".join((reasons + missing)[:10])


def normalize_url_for_dedupe(url: str) -> dict:
    identity = canonicalize(url)
    path = identity.get("normalized_path") or "/"
    return {
        "url": identity.get("canonical_url") or storage.canonical_url_identity(url),
        "host": identity.get("onion_host") or "",
        "path": path,
        "canonical_path": path,
        "canonical_root": identity.get("canonical_root") or "",
        "entity_identity": identity.get("entity_identity") or "",
        "path_signature": identity.get("path_signature") or "",
        "query_signature": identity.get("query_signature") or "",
    }


def _simhash(text: str) -> str | None:
    tokens = re.findall(r"[\w@.-]{3,}", normalize_text(text))[:4000]
    if not tokens:
        return None
    vector = [0] * 64
    for token in set(tokens):
        bits = int(hashlib.blake2b(token.encode("utf-8"), digest_size=8).hexdigest(), 16)
        for index in range(64):
            vector[index] += 1 if bits & (1 << index) else -1
    value = sum((1 << index) for index, score in enumerate(vector) if score >= 0)
    return f"{value:016x}"


def _text_unique_token_count(text: str) -> int:
    return len(set(re.findall(r"[\w@.-]{3,}", normalize_text(text))[:4000]))


def _distance(left: str, right: str) -> int:
    try:
        return (int(left, 16) ^ int(right, 16)).bit_count()
    except (TypeError, ValueError):
        return 64


def extract_safe_fingerprints(url: str, title: str | None = None, visible_text: str | None = None,
                              indicators: list[dict] | None = None, source_context: str | None = None,
                              restricted: bool = False, *, severe_blackhole: bool = False) -> list[dict]:
    """Return hashes only. Restricted content never contributes title/text/contact fingerprints."""
    if severe_blackhole:
        return []
    meta = normalize_url_for_dedupe(url)
    values = [{"type": "url_host", "value": _hash(f"host:{meta['host']}"), "confidence": "high"}]
    if source_context:
        source_meta = normalize_url_for_dedupe(source_context)
        if source_meta["host"]:
            values.append({"type": "source_context", "value": _hash(source_meta["url"]), "confidence": "medium"})
    if restricted:
        return values
    normalized_title = normalize_text(title)
    if normalized_title:
        values.append({"type": "title", "value": _hash(normalized_title[:300]), "confidence": "medium"})
    text_hash = _simhash(visible_text or "")
    if text_hash:
        richness = _text_unique_token_count(visible_text or "")
        values.append({"type": "text_simhash", "value": text_hash,
                       "confidence": "rich" if richness >= 12 else "high"})
    for indicator in indicators or []:
        kind = str(indicator.get("type") or "")
        if kind not in STRONG_TYPES:
            continue
        raw = normalize_text(indicator.get("normalized_value") or indicator.get("value"))
        if not raw:
            continue
        fp_type = "pgp_hash" if kind == "pgp_key_block" else "wallet_hash" if kind.startswith("wallet_") else "contact_hash"
        values.append({"type": fp_type, "value": _hash(f"{kind}:{raw}"), "confidence": "high"})
    unique = {}
    for item in values:
        unique[(item["type"], item["value"])] = item
    return list(unique.values())


def find_matching_site_card(classification: dict, fingerprints: list[dict], url_metadata: dict,
                            exclude_card_id: int | None = None) -> dict:
    if _severe_blackhole(classification):
        return {"site_card_id": None, "confidence": "blocked",
                "reason": "severe blackhole cannot participate in card matching"}
    host = url_metadata.get("host") or normalize_url_for_dedupe(url_metadata.get("url", ""))["host"]
    restricted = classification.get("storage_policy") == "metadata_only" or classification.get("review_status") == "restricted"
    with storage.get_db() as db:
        params = [host]
        sql = """SELECT scu.site_card_id FROM site_card_urls scu
          JOIN site_cards sc ON sc.id=scu.site_card_id
          WHERE scu.onion_host=? AND sc.primary_category!='severe_abuse_risk'"""
        if exclude_card_id:
            sql += " AND site_card_id!=?"
            params.append(exclude_card_id)
        same = db.execute(sql + " ORDER BY scu.id LIMIT 1", tuple(params)).fetchone()
        if same:
            return {"site_card_id": int(same[0]), "confidence": "same_host", "reason": "same onion host"}

        if restricted:
            source_fp = next((fp["value"] for fp in fingerprints if fp["type"] == "source_context"), None)
            if source_fp:
                row = db.execute("""SELECT sf.site_card_id FROM site_fingerprints sf JOIN site_cards sc ON sc.id=sf.site_card_id
                  WHERE sf.fingerprint_type='source_context' AND sf.fingerprint_value=?
                  AND sc.primary_category=? AND (? IS NULL OR sf.site_card_id!=?) ORDER BY sf.id LIMIT 1""",
                  (source_fp, classification.get("primary_category"), exclude_card_id, exclude_card_id)).fetchone()
                if row:
                    return {"site_card_id": int(row[0]), "confidence": "probable_mirror",
                            "reason": "same safe source listing and restricted category"}

        if not restricted:
            for fp in fingerprints:
                if fp["type"] not in {"pgp_hash", "wallet_hash", "contact_hash"}:
                    continue
                row = db.execute("""SELECT sf.site_card_id FROM site_fingerprints sf
                  JOIN site_cards sc ON sc.id=sf.site_card_id
                  WHERE sf.fingerprint_type=? AND sf.fingerprint_value=?
                  AND sc.primary_category!='severe_abuse_risk'
                  AND (? IS NULL OR sf.site_card_id!=?) ORDER BY sf.id LIMIT 1""",
                  (fp["type"], fp["value"], exclude_card_id, exclude_card_id)).fetchone()
                if row:
                    return {"site_card_id": int(row[0]), "confidence": "confirmed_mirror",
                            "reason": f"shared {fp['type']}"}

            title_fp = next((fp["value"] for fp in fingerprints if fp["type"] == "title"), None)
            text_item = next((fp for fp in fingerprints if fp["type"] == "text_simhash"), None)
            text_fp = text_item["value"] if text_item else None
            root_like = url_metadata.get("canonical_path") in {None, "", "/"}
            if text_fp and root_like and text_item.get("confidence") == "rich":
                category = classification.get("primary_category") or "unknown"
                candidates = db.execute("""SELECT sf.site_card_id,sf.fingerprint_value FROM site_fingerprints sf
                  JOIN site_card_urls scu ON scu.site_card_id=sf.site_card_id
                  JOIN site_cards sc ON sc.id=sf.site_card_id
                  WHERE sf.fingerprint_type='text_simhash' AND sf.confidence='rich'
                  AND COALESCE(scu.path,'/') IN ('','/')
                  AND lower(COALESCE(scu.onion_host,''))!=lower(?)
                  AND (? IS NULL OR sf.site_card_id!=?)
                  AND sc.primary_category=?
                  AND sc.storage_policy NOT IN ('metadata_only','discard')
                  GROUP BY sf.site_card_id,sf.fingerprint_value LIMIT 50""",
                  (host, exclude_card_id, exclude_card_id, category)).fetchall()
                for candidate in candidates:
                    distance = _distance(text_fp, candidate["fingerprint_value"])
                    if distance <= 16:
                        return {"site_card_id": int(candidate["site_card_id"]),
                                "confidence": "confirmed_mirror" if distance <= 8 else "probable_mirror",
                                "reason": "similar safe homepage text fingerprint"}
            if title_fp:
                title_cards = db.execute("""SELECT DISTINCT sf.site_card_id FROM site_fingerprints sf
                  JOIN site_cards sc ON sc.id=sf.site_card_id
                  WHERE sf.fingerprint_type='title' AND sf.fingerprint_value=?
                  AND sc.primary_category!='severe_abuse_risk'
                  AND (? IS NULL OR sf.site_card_id!=?) LIMIT 20""",
                  (title_fp, exclude_card_id, exclude_card_id)).fetchall()
                for candidate in title_cards:
                    candidate_id = int(candidate[0])
                    if text_fp:
                        other = db.execute("""SELECT fingerprint_value FROM site_fingerprints
                          WHERE site_card_id=? AND fingerprint_type='text_simhash' ORDER BY id DESC LIMIT 1""",
                                           (candidate_id,)).fetchone()
                        if other and _distance(text_fp, other[0]) <= 8:
                            confidence = "confirmed_mirror" if _distance(text_fp, other[0]) <= 3 else "probable_mirror"
                            return {"site_card_id": candidate_id, "confidence": confidence,
                                    "reason": "matching safe title and text fingerprint"}
                    return {"site_card_id": None, "possible_card_id": candidate_id,
                            "confidence": "possible_mirror", "reason": "matching safe title only"}
    return {"site_card_id": None, "confidence": "unknown", "reason": "no safe high-confidence match"}


def _canonical_site_id_for_meta(meta: dict, fallback: str = "") -> str:
    host_identity = meta.get("entity_identity") or f"onion:{(meta.get('host') or fallback).casefold()}"
    return "site-" + _hash(host_identity)[:20]


def _forum_case_identity(url: str, meta: dict) -> str:
    forum_identity = classify_forum_url(url)
    if forum_identity.case_identity:
        return "forum-case:" + forum_identity.case_identity
    host = str(meta.get("host") or "").casefold()
    path_sig = meta.get("path_signature") or _hash(str(meta.get("path") or "/"))[:16]
    query_sig = meta.get("query_signature") or "q0"
    return f"forum-case:{host}:{path_sig}:{query_sig}"


def _parent_forum_card_id(host: str, *, exclude_card_id: int | None = None) -> int | None:
    if not host:
        return None
    with storage.get_db() as db:
        params: list[object] = [host]
        sql = """SELECT sc.id FROM site_cards sc
          JOIN site_card_urls scu ON scu.site_card_id=sc.id
          WHERE lower(scu.onion_host)=lower(?)
          AND COALESCE(sc.card_kind,'site')!='forum_thread_case'
          AND (sc.primary_category='forum_social' OR sc.page_type IN ('forum_index','forum_home'))"""
        if exclude_card_id:
            sql += " AND sc.id!=?"
            params.append(exclude_card_id)
        row = db.execute(sql + " ORDER BY sc.id LIMIT 1", tuple(params)).fetchone()
        return int(row["id"]) if row else None


def _card_kind(site_card_id: int | None) -> str:
    if not site_card_id:
        return ""
    with storage.get_db() as db:
        row = db.execute("SELECT card_kind FROM site_cards WHERE id=?", (site_card_id,)).fetchone()
    return str(row["card_kind"] or "site") if row else ""


def _card_has_analyst_category(site_card_id: int | None) -> bool:
    if not site_card_id:
        return False
    with storage.get_db() as db:
        row = db.execute("SELECT analyst_category FROM site_cards WHERE id=?", (site_card_id,)).fetchone()
    return bool(row and row["analyst_category"])


def _same_host_card_id(host: str, *, exclude_card_id: int | None = None) -> int | None:
    if not host:
        return None
    with storage.get_db() as db:
        params = [host]
        sql = """SELECT scu.site_card_id FROM site_card_urls scu
          JOIN site_cards sc ON sc.id=scu.site_card_id
          WHERE lower(scu.onion_host)=lower(?)
          AND sc.primary_category!='severe_abuse_risk'"""
        if exclude_card_id:
            sql += " AND site_card_id!=?"
            params.append(exclude_card_id)
        row = db.execute(sql + " ORDER BY scu.id LIMIT 1", tuple(params)).fetchone()
        if row:
            return int(row["site_card_id"])
        row = db.execute("""SELECT ou.site_card_id FROM onion_urls ou
          JOIN site_cards sc ON sc.id=ou.site_card_id
          WHERE lower(COALESCE(ou.onion_domain,''))=lower(?) AND ou.site_card_id IS NOT NULL
          AND sc.primary_category!='severe_abuse_risk' ORDER BY ou.id LIMIT 1""", (host,)).fetchone()
        return int(row["site_card_id"]) if row else None


def build_card_creation_decision(item: dict, classification: dict,
                                 fingerprints: list[dict]) -> CardCreationDecision:
    if _severe_blackhole(classification, item):
        raise ValueError("Severe-blackhole URLs cannot create or match Site Cards")
    meta = normalize_url_for_dedupe(item["url"])
    current_id = int(item["site_card_id"]) if item.get("site_card_id") else None
    restricted = classification.get("storage_policy") == "metadata_only" or classification.get("review_status") == "restricted"
    forum_case = _is_forum_thread_case(classification, item)
    same_host_manual_parent_id = _same_host_card_id(meta["host"], exclude_card_id=current_id) if forum_case else None
    current_has_manual_category = _card_has_analyst_category(current_id)
    same_host_has_manual_category = _card_has_analyst_category(same_host_manual_parent_id)
    if forum_case and (current_has_manual_category or same_host_has_manual_category):
        forum_case = False
    if forum_case and current_id and _card_kind(current_id) != "forum_thread_case" and not current_has_manual_category:
        current_id = None
    if forum_case and not (current_id and current_has_manual_category):
        meta["entity_identity"] = _forum_case_identity(item["url"], meta)
        same_host_id = None
        match = {"site_card_id": None, "confidence": "forum_thread_case",
                 "reason": "important forum thread promoted to case card"}
    else:
        same_host_id = _same_host_card_id(meta["host"], exclude_card_id=current_id)
        match = find_matching_site_card(classification, fingerprints, {**meta, "url": item["url"]},
                                        current_id or same_host_id)
    if current_id and match.get("site_card_id") and int(match["site_card_id"]) != current_id:
        target_id = int(match["site_card_id"])
        reason = match.get("reason") or "matched existing card"
        confidence = match.get("confidence") or "unknown"
    elif current_id:
        target_id = current_id
        reason = "url already assigned to Site Card"
        confidence = "existing_assignment"
    elif same_host_id:
        target_id = same_host_id
        reason = "same onion host"
        confidence = "same_host"
    elif match.get("site_card_id"):
        target_id = int(match["site_card_id"])
        reason = match.get("reason") or "matched existing card"
        confidence = match.get("confidence") or "unknown"
    else:
        target_id = None
        reason = match.get("reason") or ("important forum thread promoted to case card" if forum_case else "no safe high-confidence match")
        confidence = match.get("confidence") or ("forum_thread_case" if forum_case else "unknown")
    decision = CardCreationDecision(
        url_id=int(item["id"]),
        url=item["url"],
        host=meta["host"],
        canonical_root=meta.get("canonical_root") or "",
        entity_identity=meta.get("entity_identity") or "",
        normalized_path=meta.get("path") or "/",
        path_signature=meta.get("path_signature") or "",
        query_signature=meta.get("query_signature") or "",
        classification=classification,
        restricted=bool(restricted),
        existing_card_id=current_id,
        matched_card_id=target_id,
        possible_card_id=int(match["possible_card_id"]) if match.get("possible_card_id") else None,
        match_confidence=confidence,
        decision_reason=reason,
    )
    if target_id:
        decision.url_role = _url_role(item, target_id, decision.match_confidence)
    return decision


def _insert_new_site_card(item: dict, classification: dict, decision: CardCreationDecision) -> int:
    if not _content_classification_trusted(classification):
        raise ValueError("Unverified content classification cannot create a Site Card")
    if _severe_blackhole(classification, item, decision.classification):
        raise ValueError("Severe-blackhole URLs cannot create Site Cards")
    with storage.get_db() as db:
        now = storage.utc_now_iso()
        canonical_site_id = _canonical_site_id_for_meta({
            "entity_identity": decision.entity_identity, "host": decision.host,
        }, item.get("onion_domain") or item["url"])
        card_kind = "forum_thread_case" if _is_forum_thread_case(classification, item) else "site"
        parent_card_id = _parent_forum_card_id(decision.host) if card_kind == "forum_thread_case" else None
        existing = db.execute("SELECT id FROM site_cards WHERE canonical_site_id=?", (canonical_site_id,)).fetchone()
        if existing:
            if card_kind == "forum_thread_case":
                db.execute("""UPDATE site_cards SET card_kind='forum_thread_case',
                  parent_site_card_id=COALESCE(parent_site_card_id,?),updated_at=?
                  WHERE id=?""", (parent_card_id, now, int(existing["id"])))
            return int(existing["id"])
        display = (safe_category_label(classification.get("primary_category")) if decision.restricted
                   else (item.get("title") or item.get("onion_domain") or "Unnamed onion site"))
        try:
            cur = db.execute("""INSERT INTO site_cards(canonical_site_id,display_name,primary_category,tags,
              risk_level,confidence,risk_flags,storage_policy,review_status,spain_priority,spain_confidence,
              spain_match_language,spain_match_reason,priority_score,first_seen,last_seen,last_checked_at,
              restricted_cluster_confidence,created_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (canonical_site_id, display[:180], classification.get("primary_category", "unknown"),
               json.dumps(classification.get("tags", []), ensure_ascii=False), classification.get("risk_level", "low"),
               classification.get("confidence", "low"), json.dumps(classification.get("risk_flags", []), ensure_ascii=False),
               classification.get("storage_policy", "safe_summary"), classification.get("review_status", "pending"),
               int(bool(classification.get("spain_priority"))), classification.get("spain_confidence"),
               classification.get("spain_match_language"), classification.get("spain_match_reason"),
               int(classification.get("priority_score", 0)), item.get("first_seen") or now, item.get("last_seen") or now,
               item.get("last_checked_at"), "high" if decision.restricted else None, now, now))
        except sqlite3.IntegrityError:
            existing = db.execute("SELECT id FROM site_cards WHERE canonical_site_id=?", (canonical_site_id,)).fetchone()
            if existing:
                return int(existing["id"])
            raise
        card_id = int(cur.lastrowid)
        if parent_card_id == card_id:
            parent_card_id = None
        db.execute("""UPDATE site_cards SET secondary_categories=?,marketplace_type=?,page_type=?,
           category_confidence=?,category_reason=?,category_safe_label=?,display_group=?,ui_hidden_default=?,
          ui_priority=?,review_score=?,card_kind=?,parent_site_card_id=? WHERE id=?""",
          (json.dumps(classification.get("secondary_categories", []), ensure_ascii=False),
           classification.get("marketplace_type"), classification.get("page_type", "unknown"),
           classification.get("category_confidence", classification.get("confidence", "low")),
           classification.get("category_reason"), classification.get("category_safe_label"),
           classification.get("display_group", "Other"), int(bool(classification.get("ui_hidden_default"))),
           int(classification.get("ui_priority", 0)), int(classification.get("review_score", 0)),
           card_kind, parent_card_id, card_id))
        db.execute("UPDATE site_cards SET spain_context_tags=? WHERE id=?",
                   (json.dumps(classification.get("spain_context_tags", []), ensure_ascii=False), card_id))
        return card_id


def create_site_card_from_url(url_id: int, classification: dict, fingerprints: list[dict]) -> int:
    with storage.get_db() as db:
        row = db.execute("SELECT * FROM onion_urls WHERE id=?", (url_id,)).fetchone()
    if not row:
        raise ValueError("Onion URL not found")
    item = dict(row)
    trusted_policy = _trusted_row_policy(item)
    if trusted_policy is None:
        return 0
    if _adult_filtered(trusted_policy):
        raise ValueError("Adult-filtered URLs cannot create Site Cards")
    if _severe_blackhole(trusted_policy):
        _enforce_severe_url(item, trusted_policy)
        return 0
    decision = build_card_creation_decision(item, trusted_policy, fingerprints)
    if decision.target_card_id:
        return int(decision.target_card_id)
    return _insert_new_site_card(item, trusted_policy, decision)


def _url_role(item: dict, site_card_id: int, confidence: str) -> str:
    if item.get("status") == "dead" or not item.get("active", 1) and item.get("dead_reason"):
        return "dead_mirror"
    if item.get("storage_policy") == "metadata_only" or item.get("review_status") == "restricted":
        return "restricted"
    with storage.get_db() as db:
        rows = db.execute("SELECT onion_host,path FROM site_card_urls WHERE site_card_id=?", (site_card_id,)).fetchall()
    if not rows:
        return "canonical"
    host = item.get("onion_domain") or normalize_url_for_dedupe(item["url"])["host"]
    if any(row["onion_host"] == host for row in rows):
        return "path"
    return "mirror"


def _attach_url_to_card(item: dict, decision: CardCreationDecision,
                        fingerprints: list[dict]) -> tuple[bool, str | None]:
    if _severe_blackhole(item, decision.classification):
        raise ValueError("Severe-blackhole URLs cannot be attached to Site Cards")
    now = storage.utc_now_iso()
    inherited_category = None
    meta = {
        "host": decision.host,
        "path": decision.normalized_path,
    }
    with storage.get_db() as db:
        existing_link = db.execute("SELECT site_card_id,url_role FROM site_card_urls WHERE url=?", (item["url"],)).fetchone()
        if existing_link and int(existing_link["site_card_id"]) == int(decision.matched_card_id):
            decision.url_role = existing_link["url_role"] or decision.url_role
        assignment_changed = (not existing_link or int(existing_link["site_card_id"]) != int(decision.matched_card_id)
                              or existing_link["url_role"] != decision.url_role)
        db.execute("""INSERT INTO site_card_urls(site_card_id,onion_url_id,url,onion_host,path,url_role,
          mirror_confidence,status,active,http_status,dead_reason,first_seen,last_seen,last_checked_at,
          source_url,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(url) DO UPDATE SET site_card_id=excluded.site_card_id,onion_url_id=excluded.onion_url_id,
          onion_host=excluded.onion_host,path=excluded.path,url_role=excluded.url_role,
          mirror_confidence=CASE WHEN excluded.mirror_confidence='unknown' THEN site_card_urls.mirror_confidence ELSE excluded.mirror_confidence END,
          status=excluded.status,active=excluded.active,http_status=excluded.http_status,
          dead_reason=excluded.dead_reason,last_seen=excluded.last_seen,last_checked_at=excluded.last_checked_at,
          source_url=COALESCE(site_card_urls.source_url,excluded.source_url),updated_at=excluded.updated_at""",
          (decision.matched_card_id, decision.url_id, item["url"], meta["host"], meta["path"],
           decision.url_role, decision.match_confidence, item.get("status"),
           int(bool(item.get("active", 1))), item.get("http_status"), item.get("dead_reason"),
           item.get("first_seen") or now, item.get("last_seen") or now, item.get("last_checked_at"),
           item.get("source_url"), now, now))
        db.execute("""UPDATE onion_urls SET site_card_id=?,canonical_site_id=(SELECT canonical_site_id FROM site_cards WHERE id=?),
          dedupe_status='assigned',mirror_confidence=?,safe_title_fingerprint=?,content_fingerprint=? WHERE id=?""",
          (decision.matched_card_id, decision.matched_card_id, decision.match_confidence,
           next((fp["value"] for fp in fingerprints if fp["type"] == "title"), None),
           next((fp["value"] for fp in fingerprints if fp["type"] == "text_simhash"), None),
           decision.url_id))
        canonical = db.execute("""SELECT onion_url_id,url FROM site_card_urls WHERE site_card_id=?
          ORDER BY CASE url_role WHEN 'canonical' THEN 0 ELSE 1 END,first_seen,id LIMIT 1""",
          (decision.matched_card_id,)).fetchone()
        if canonical:
            duplicate_of = int(canonical["onion_url_id"]) if (decision.url_role == "mirror" and decision.match_confidence in {
                "confirmed_mirror", "probable_mirror"
            }) else None
            db.execute("""UPDATE onion_urls SET canonical_url=?,canonical_id=?,duplicate_of=? WHERE id=?""",
                       (storage.canonical_url_identity(canonical["url"]),
                        canonical["onion_url_id"], duplicate_of, decision.url_id))
        inherited = db.execute("SELECT review_status,analyst_category FROM site_cards WHERE id=?",
                               (decision.matched_card_id,)).fetchone()
        incoming_restricted = (decision.classification.get("primary_category") in {
            "adult_filtered", "adult_restricted", "severe_abuse_risk"}
            or decision.classification.get("storage_policy") in {"metadata_only", "discard"})
        if inherited and inherited["analyst_category"] and not incoming_restricted:
            inherited_category = inherited["analyst_category"]
            db.execute("""UPDATE onion_urls SET analyst_category=?,
              classification_evidence_source='analyst',destination_html_evidence_version=0
              WHERE id=?""", (inherited_category, decision.url_id))
        if inherited and inherited["review_status"] in {"relevant", "false_positive", "blocked", "reported", "needs_report"}:
            db.execute("UPDATE onion_urls SET review_status=? WHERE id=?", (inherited["review_status"], decision.url_id))
            if inherited["review_status"] == "false_positive":
                db.execute("UPDATE onion_urls SET spain_review_status='ignored' WHERE id=? AND spain_priority=1",
                           (decision.url_id,))
            elif inherited["review_status"] == "blocked":
                db.execute("""UPDATE onion_urls SET active=0,status='blocked',queue_policy='blocked',
                  spain_review_status=CASE WHEN spain_priority=1 THEN 'blocked' ELSE spain_review_status END
                  WHERE id=?""", (decision.url_id,))
        return assignment_changed, inherited_category


def _persist_card_fingerprints(decision: CardCreationDecision, fingerprints: list[dict]) -> None:
    if _severe_blackhole(decision.classification):
        with storage.get_db() as db:
            db.execute("DELETE FROM site_fingerprints WHERE onion_url_id=?", (decision.url_id,))
            db.execute("DELETE FROM possible_site_card_matches WHERE onion_url_id=?", (decision.url_id,))
        return
    now = storage.utc_now_iso()
    with storage.get_db() as db:
        for fp in fingerprints:
            db.execute("""INSERT INTO site_fingerprints(site_card_id,onion_url_id,fingerprint_type,
              fingerprint_value,confidence,created_at) VALUES(?,?,?,?,?,?)
              ON CONFLICT(onion_url_id,fingerprint_type,fingerprint_value) DO UPDATE SET
              site_card_id=excluded.site_card_id,confidence=excluded.confidence""",
              (decision.matched_card_id, decision.url_id, fp["type"], fp["value"],
               fp.get("confidence", "medium"), now))
        if decision.possible_card_id and int(decision.possible_card_id) != int(decision.matched_card_id or 0):
            db.execute("""INSERT INTO possible_site_card_matches(onion_url_id,candidate_site_card_id,reason,
              confidence,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(onion_url_id,candidate_site_card_id)
              DO UPDATE SET reason=excluded.reason,updated_at=excluded.updated_at""",
              (decision.url_id, int(decision.possible_card_id), decision.decision_reason,
               "possible_mirror", now, now))


def _record_url_assignment_event(decision: CardCreationDecision) -> None:
    if _severe_blackhole(decision.classification):
        return
    with storage.get_db() as db:
        db.execute("""INSERT INTO site_card_events(site_card_id,event_type,event_summary,safe_metadata_json,created_at)
          VALUES(?,?,?,?,?)""", (decision.matched_card_id, "url_assigned", "URL attached to Site Card",
          json.dumps(decision.safe_metadata(), ensure_ascii=False), storage.utc_now_iso()))


def assign_url_to_site_card(url_id: int, classification: dict, fingerprints: list[dict],
                            *, update_rollup: bool = True) -> int:
    with storage.get_db() as db:
        row = db.execute("SELECT * FROM onion_urls WHERE id=?", (url_id,)).fetchone()
    if not row:
        raise ValueError("Onion URL not found")
    item = dict(row)
    trusted_policy = _trusted_row_policy(item)
    if trusted_policy is None:
        return 0
    classification = trusted_policy
    if _severe_blackhole(classification):
        _enforce_severe_url(item, classification)
        return 0
    if _adult_filtered(classification) or _adult_filtered(item):
        storage.cleanup_adult_filtered_items(item["url"])
        return 0
    decision = build_card_creation_decision(item, classification, fingerprints)
    if (decision.existing_card_id and decision.matched_card_id
            and int(decision.existing_card_id) != int(decision.matched_card_id)):
        decision.matched_card_id = merge_site_cards(int(decision.existing_card_id), int(decision.matched_card_id))
        decision.match_confidence = decision.match_confidence or "merged"
        decision.decision_reason = "existing assignment merged into matched card"
    if not decision.matched_card_id:
        decision.matched_card_id = _insert_new_site_card(item, classification, decision)
        decision.match_confidence = "new_card"
        decision.decision_reason = "created deterministic host Site Card"
    decision.url_role = _url_role(item, int(decision.matched_card_id), decision.match_confidence)
    assignment_changed, inherited_category = _attach_url_to_card(item, decision, fingerprints)
    _persist_card_fingerprints(decision, fingerprints)
    if assignment_changed:
        _record_url_assignment_event(decision)
    if inherited_category:
        # Reapply through the central policy writer so the card-level analyst override
        # wins consistently without weakening adult/severe safety decisions.
        inherited_policy = dict(
            classification,
            analyst_category=inherited_category,
            primary_category=inherited_category,
            category=inherited_category,
            content_category=inherited_category,
            classification_evidence_source="analyst",
            destination_html_evidence_version=0,
        )
        storage.apply_onion_policy(item["url"], inherited_policy)
    if update_rollup:
        update_site_card_rollups(int(decision.matched_card_id))
    return int(decision.matched_card_id)


def ensure_url_site_card(url_or_id: str | int, classification: dict | None = None,
                         title: str | None = None, visible_text: str | None = None,
                         indicators: list[dict] | None = None, source_context: str | None = None,
                         update_rollup: bool = True) -> int:
    with storage.get_db() as db:
        row = db.execute("SELECT * FROM onion_urls WHERE id=?" if isinstance(url_or_id, int) else
                         "SELECT * FROM onion_urls WHERE url=?", (url_or_id,)).fetchone()
    if not row:
        raise ValueError("Onion URL not found")
    item = dict(row)
    policy = _trusted_row_policy(item)
    if policy is None:
        # Site Cards are result entities, not a place to promote discovery
        # hints.  The verify stage may call again after destination HTML has a
        # current parser boundary; analyst-owned categories are also allowed.
        return 0
    if policy.get("card_allowed") is False or policy.get("classification_decision") == "unverified_restricted_candidate":
        return 0
    if _severe_blackhole(policy, item):
        _enforce_severe_url(item, policy)
        return 0
    if _adult_filtered(policy) or _adult_filtered(item):
        storage.cleanup_adult_filtered_items(item["url"])
        return 0
    restricted = policy.get("storage_policy") == "metadata_only" or policy.get("review_status") == "restricted"
    fingerprints = extract_safe_fingerprints(
        item["url"], title, visible_text, indicators,
        source_context or item.get("source_url"), restricted,
        severe_blackhole=_severe_blackhole(policy, item))
    return assign_url_to_site_card(int(item["id"]), policy, fingerprints, update_rollup=update_rollup)


def _load_rollup_rows(db, site_card_id: int) -> list[dict]:
    return [dict(row) for row in db.execute("""SELECT ou.*,scu.url_role AS card_url_role,
      scu.path AS card_path FROM onion_urls ou
      JOIN site_card_urls scu ON scu.onion_url_id=ou.id WHERE scu.site_card_id=?""", (site_card_id,))]


def _normalize_rollup_rows(rows: list[dict]) -> None:
    for row in rows:
        trusted_category = _trusted_content_category(row)
        trusted = trusted_category is not None
        row["content_classification_trusted"] = trusted
        row["primary_category"] = trusted_category if trusted else "unknown"
        row["content_category"] = row["primary_category"]
        row["page_type"] = normalize_page_type(row.get("page_type")) if trusted else "unknown"
        if not trusted:
            row.update(
                category_confidence="low", category_update_allowed=0,
                category_update_reason="awaiting_destination_html",
                risk_level="low", risk_category="unknown", site_type="unknown",
                urgent_score=0, urgent_flag=0, tags="[]", risk_flags="[]",
                urgent_reason=None, context_only=0,
                storage_policy="safe_summary", review_status="monitor",
                safety_state="safe", safety_reason="awaiting_destination_html",
                screenshot_policy="blocked",
                screenshot_blocked_reason="awaiting_destination_html",
                queue_policy="normal", secondary_categories="[]",
                marketplace_type=None, ui_hidden_default=0, ui_priority=0,
                review_score=0, display_group="Other",
                category_safe_label="Needs classification",
                card_ready=0, card_readiness_reason="awaiting_page_classification",
                card_readiness_confidence="low",
                spain_priority=0, spain_relevance="none", spain_actionable=0,
                spain_context_only=0, spain_evidence_score=0,
            )


def _safe_rollup_rows(rows: list[dict]) -> list[dict]:
    return [row for row in rows if row.get("primary_category") not in {
        "adult_filtered", "adult_restricted", "severe_abuse_risk"} and row.get("storage_policy") != "discard"]


def _classification_rollup_rows(representative_rows: list[dict]) -> list[dict]:
    representative_rows = [
        row for row in representative_rows if row.get("content_classification_trusted")
    ]
    landing_rows = [
        row for row in representative_rows
        if row.get("page_type") in LANDING_PAGE_TYPES
        or row.get("card_path") in {None, "", "/"}
    ]
    preserved_reasons = {
        "page_state_cannot_replace_site_category",
        "thin_page_preserved_previous_category",
    }
    authoritative_landing_rows = [
        row for row in landing_rows
        if normalize_content_category(row.get("primary_category")) != "unknown"
        and (
            int(row.get("category_update_allowed")
                if row.get("category_update_allowed") is not None else 1)
            or row.get("category_update_reason") in preserved_reasons
        )
    ]
    # A trusted root/landing page defines the site identity. Thread, listing,
    # vendor, and category children remain useful secondary context but cannot
    # win merely because there are more of them.
    return authoritative_landing_rows or representative_rows


def _score_primary_category(classification_rows: list[dict]) -> tuple[str, dict[str, int]]:
    confidence_weight = {"low": 1, "medium": 3, "high": 6, "critical": 8, "analyst": 12}
    category_scores: dict[str, int] = {}
    preserved_rows = []
    for row in classification_rows:
        category = normalize_content_category(row.get("primary_category"))
        page_type = normalize_page_type(row.get("page_type"))
        if not int(row.get("category_update_allowed") if row.get("category_update_allowed") is not None else 1):
            if (category != "unknown"
                    and row.get("category_update_reason") in {
                        "page_state_cannot_replace_site_category",
                        "thin_page_preserved_previous_category",
                    }):
                preserved_rows.append(row)
            continue
        score = confidence_weight.get(str(row.get("category_confidence") or "low").casefold(), 1)
        score += 5 if row.get("card_path") in {None, "", "/"} else 0
        score += 3 if page_type in LANDING_PAGE_TYPES else 0
        score += 2 if row.get("card_ready") else 0
        score -= 3 if page_type in CHILD_PAGE_TYPES else 0
        if row.get("content_quality") in {"empty", "unavailable"}:
            score = 0
        category_scores[category] = category_scores.get(category, 0) + max(0, score)
    if not category_scores:
        # A login/error/thin recrawl may preserve an already trusted category
        # while correctly forbidding the current page state from replacing it.
        # Use that preserved value only as a fallback; it never outvotes fresh
        # allowed destination-HTML evidence.
        for row in preserved_rows:
            category = normalize_content_category(row.get("primary_category"))
            score = confidence_weight.get(
                str(row.get("category_confidence") or "low").casefold(), 1)
            score += 5 if row.get("card_path") in {None, "", "/"} else 0
            category_scores[category] = category_scores.get(category, 0) + max(1, score)
    primary = (max(category_scores, key=lambda value: (category_scores[value], CATEGORY_ORDER.get(value, 0)))
               if category_scores else "unknown")
    return primary, category_scores


def _collect_rollup_tags_flags(representative_rows: list[dict], primary: str) -> tuple[list, list]:
    tags = []
    flags = []
    for row in representative_rows:
        tags.extend(_loads(row.get("tags")))
        if row.get("primary_category") and row.get("primary_category") != primary:
            tags.append(row["primary_category"])
        flags.extend(_loads(row.get("risk_flags")))
    return tags, flags


def _restricted_child_rollup(representative_rows: list[dict], tags: list) -> dict:
    restricted_outbound = sum(int(row.get("restricted_outbound_count") or 0) for row in representative_rows)
    adult_outbound = sum(int(row.get("adult_outbound_count") or 0) for row in representative_rows)
    severe_outbound = sum(int(row.get("severe_outbound_count") or 0) for row in representative_rows)
    child_adult = sum(int(row.get("child_adult_link_count") or 0) for row in representative_rows)
    child_restricted = sum(int(row.get("child_restricted_link_count") or 0) for row in representative_rows)
    child_blocked = sum(int(row.get("child_blocked_link_count") or 0) for row in representative_rows)
    adult_category_present = any(int(row.get("adult_category_present") or 0) for row in representative_rows)
    outbound_total = sum(max(int(row.get("restricted_outbound_count") or 0),
                             round(int(row.get("restricted_outbound_count") or 0) /
                                   float(row.get("restricted_outbound_ratio") or 1))) for row in representative_rows)
    if restricted_outbound:
        tags.append("restricted_child_present")
    if adult_outbound:
        tags.append("adult_link_present")
    if adult_category_present:
        tags.append("adult_category_present")
    return {
        "restricted_outbound": restricted_outbound,
        "adult_outbound": adult_outbound,
        "severe_outbound": severe_outbound,
        "child_adult": child_adult,
        "child_restricted": child_restricted,
        "child_blocked": child_blocked,
        "adult_category_present": adult_category_present,
        "outbound_total": outbound_total,
    }


def _rollup_storage_policy(representative_rows: list[dict]) -> tuple[bool, bool, str]:
    restricted = any(row.get("storage_policy") == "metadata_only" for row in representative_rows)
    limited = any(row.get("storage_policy") == "metadata_limited" for row in representative_rows)
    return restricted, limited, "metadata_only" if restricted else "metadata_limited" if limited else "safe_summary"


def _spain_rollup_rows(representative_rows: list[dict], tags: list) -> tuple[list[dict], list[dict]]:
    spain_signal_rows = [row for row in representative_rows
                         if row.get("spain_priority") or row.get("spain_relevance") not in {None, "", "none"}]
    spain_rows = [row for row in spain_signal_rows
                  if row.get("spain_priority") and not int(row.get("spain_context_only") or 0)]
    if spain_rows:
        tags.append("spain_priority")
        if any(row.get("classification_decision") in {"accepted", "analyst_confirmed"} for row in spain_rows):
            tags.extend(["spain", "spain_confirmed"])
    return spain_signal_rows, spain_rows


def _rollup_liveness_counts(rows: list[dict]) -> tuple[set[str], int, int, set[str]]:
    hosts = {row.get("onion_domain") or normalize_url_for_dedupe(row["url"])["host"] for row in rows}
    live = sum(1 for row in rows if row.get("active") and row.get("status") != "dead")
    dead = sum(1 for row in rows if row.get("status") == "dead" or row.get("dead_reason"))
    sources = {row.get("source_url") for row in rows if row.get("source_url")}
    return hosts, live, dead, sources


def _select_identity_row(representative_rows: list[dict]) -> dict:
    identity_rank = {"low": 1, "medium": 2, "high": 3}
    return max(
        representative_rows,
        key=lambda row: (
            3 if row.get("card_path") in {None, "", "/"} else 0,
            2 if row.get("card_ready") else 0,
            identity_rank.get(str(row.get("identity_confidence") or "low"), 0),
            1 if row.get("safe_display_name") else 0,
        ),
    )


def _best_spain_rows(spain_signal_rows: list[dict], spain_rows: list[dict]) -> tuple[dict, dict]:
    relevance_rank = {"none": 0, "low": 1, "medium": 2, "high": 3}
    best_spain = max(
        spain_signal_rows,
        key=lambda row: (
            relevance_rank.get(str(row.get("spain_relevance") or "none"), 0),
            relevance_rank.get(str(row.get("seller_geo_confidence") or row.get("spain_confidence") or "none"), 0),
            int(row.get("spain_actionable") or 0),
        ),
    ) if spain_signal_rows else {}
    best_actionable_spain = max(
        spain_rows,
        key=lambda row: (
            relevance_rank.get(str(row.get("spain_relevance") or "none"), 0),
            relevance_rank.get(str(row.get("seller_geo_confidence") or row.get("spain_confidence") or "none"), 0),
        ),
    ) if spain_rows else {}
    return best_spain, best_actionable_spain


def _current_card_state(db, site_card_id: int):
    return db.execute(
        "SELECT review_status,report_status,analyst_importance,analyst_notes,analyst_suppressed_alerts,analyst_category,analyst_title "
        "FROM site_cards WHERE id=?", (site_card_id,)).fetchone()


def _purge_severe_urls_before_rollup(site_card_id: int) -> bool:
    """Remove stale severe children before any card aggregate is calculated.

    The storage blackhole refreshes surviving shared cards. A small re-entry
    guard prevents those callbacks from recursively rolling up a partially
    cleaned card while this bounded batch is still being purged.
    """
    if site_card_id in _SEVERE_ROLLUP_GUARD:
        return False
    with storage.get_db() as db:
        rows = [dict(row) for row in db.execute("""SELECT ou.* FROM onion_urls ou
          JOIN site_card_urls scu ON scu.onion_url_id=ou.id
          WHERE scu.site_card_id=? AND (
            ou.analyst_category='severe_abuse_risk'
            OR (ou.primary_category='severe_abuse_risk'
              AND ou.classification_evidence_source='destination_html'
              AND COALESCE(ou.destination_html_evidence_version,0)>=1
              AND ou.verification_state='verified'
              AND ou.verification_reason='page_fetched_and_classified')
          )""", (site_card_id,))]
    if not rows:
        return False
    _SEVERE_ROLLUP_GUARD.add(site_card_id)
    try:
        for row in rows:
            _enforce_severe_url(row, row)
    finally:
        _SEVERE_ROLLUP_GUARD.discard(site_card_id)
    return True


def update_site_card_rollups(site_card_id: int) -> None:
    if site_card_id in _SEVERE_ROLLUP_GUARD:
        return
    if _purge_severe_urls_before_rollup(site_card_id):
        # The all-severe case deleted the card; the mixed case now rolls up
        # only its surviving safe URLs.
        return update_site_card_rollups(site_card_id)
    with storage.get_db() as db:
        rows = _load_rollup_rows(db, site_card_id)
        if not rows:
            return
        _normalize_rollup_rows(rows)
        safe_rows = _safe_rollup_rows(rows)
        if not safe_rows:
            # Defensive fail-closed fallback. Canonical enforcement above
            # should already have removed every severe-only card.
            db.execute("""UPDATE site_cards SET ui_hidden_default=1,spain_priority=0,
              urgent_flag=0,alert_eligible=0,review_score=0,priority_score=0,
              rollup_dirty=0,updated_at=? WHERE id=?""", (storage.utc_now_iso(), site_card_id))
            return
        representative_rows = safe_rows
        classification_rows = _classification_rollup_rows(representative_rows)
        confidence_weight = {"low": 1, "medium": 3, "high": 6, "critical": 8, "analyst": 12}
        primary, _category_scores = _score_primary_category(classification_rows)
        risk = max((row.get("risk_level") or "low" for row in representative_rows), key=lambda value: RISK_ORDER.get(str(value).casefold(), 0))
        tags, flags = _collect_rollup_tags_flags(representative_rows, primary)
        child_rollup = _restricted_child_rollup(representative_rows, tags)
        restricted_outbound = child_rollup["restricted_outbound"]
        adult_outbound = child_rollup["adult_outbound"]
        severe_outbound = child_rollup["severe_outbound"]
        child_adult = child_rollup["child_adult"]
        child_restricted = child_rollup["child_restricted"]
        child_blocked = child_rollup["child_blocked"]
        adult_category_present = child_rollup["adult_category_present"]
        outbound_total = child_rollup["outbound_total"]
        restricted, limited, storage_policy = _rollup_storage_policy(representative_rows)
        spain_signal_rows, spain_rows = _spain_rollup_rows(representative_rows, tags)
        hosts, live, dead, sources = _rollup_liveness_counts(rows)
        identity_row = _select_identity_row(representative_rows)
        identity_name, display_source, _identity_candidate = _choose_site_identity(db, representative_rows, hosts)
        display = identity_name if identity_name else next(iter(hosts), "Unnamed onion site")
        now = storage.utc_now_iso()
        best_spain, best_actionable_spain = _best_spain_rows(spain_signal_rows, spain_rows)
        type_order = {"marketplace": 8, "forum": 7, "link_list": 6, "directory": 5, "market_review": 5,
                      "login_portal": 4, "paste": 3, "blog": 2, "unknown": 0}
        risk_order = {"mixed": 7, "financial_fraud": 6, "weapons": 5, "drugs": 4,
                      "cybercrime": 3, "adult": 2, "needs_review": 1, "unknown": 0}
        identity_classification_rows = classification_rows or representative_rows
        site_type = max((str(row.get("site_type") or "unknown")
                         for row in identity_classification_rows),
                        key=lambda value: type_order.get(value, 0))
        risk_category = max((str(row.get("risk_category") or "unknown") for row in representative_rows),
                            key=lambda value: risk_order.get(value, 0))
        urgent_row = max(representative_rows, key=lambda row: int(row.get("urgent_score") or 0))
        urgent_score = max(int(row.get("urgent_score") or 0) for row in representative_rows)
        raw_urgent_flag = any(int(row.get("urgent_flag") or 0) for row in representative_rows)
        context_only = all(int(row.get("context_only") or 0) for row in representative_rows)
        strong_actionable_spain = any(
            int(row.get("spain_priority") or 0)
            and not int(row.get("spain_context_only") or 0)
            and (
                int(row.get("spain_actionable") or 0)
                or str(row.get("spain_relevance") or "").casefold() == "high"
                or str(row.get("seller_geo_confidence") or row.get("spain_confidence") or "").casefold() == "high"
            )
            for row in representative_rows
        )
        report_required = any(row.get("review_status") == "needs_report" for row in representative_rows)
        current = _current_card_state(db, site_card_id)
        analyst_importance = str(current["analyst_importance"] or "").casefold() if current else ""
        analyst_high_importance = analyst_importance in {"high", "critical"}
        action_required = bool(
            report_required
            or analyst_high_importance
            or (strong_actionable_spain and raw_urgent_flag and urgent_score >= 75 and not context_only)
        )
        if current and current["analyst_category"]:
            primary = normalize_content_category(current["analyst_category"])
        if current and current["review_status"] not in {"pending", "restricted", "monitor"}:
            review = current["review_status"]
        elif restricted:
            review = "restricted"
        elif report_required:
            review = "needs_report"
        elif action_required:
            review = "needs_review"
        elif all(row.get("review_status") == "monitor" for row in representative_rows):
            review = "monitor"
        else:
            review = "monitor"
        generic_marketplace_monitor = bool(
            limited and not restricted
            and not spain_rows
            and not action_required
            and primary in {
                "marketplace", "marketplace_fraud", "marketplace_drugs", "marketplace_weapons",
                "marketplace_credentials", "marketplace_leaks", "marketplace_counterfeit",
                "marketplace_services", "fraud_financial", "drugs", "weapons_arms",
            }
        )
        if generic_marketplace_monitor and not (current and current["analyst_category"]):
            review = "monitor"
        db.execute("""UPDATE site_cards SET display_name=?,primary_category=?,tags=?,risk_level=?,confidence=?,
          risk_flags=?,storage_policy=?,review_status=?,spain_priority=?,spain_confidence=?,
          spain_match_language=?,spain_match_reason=?,priority_score=?,first_seen=?,last_seen=?,
          last_checked_at=?,mirror_count=?,live_url_count=?,dead_url_count=?,source_count=?,
          restricted_cluster_confidence=?,updated_at=? WHERE id=?""",
          (display[:180], primary, json.dumps(list(dict.fromkeys(tags)), ensure_ascii=False), risk,
           max((row.get("confidence") or "low" for row in representative_rows), key=lambda x: {"low":1,"medium":2,"high":3}.get(x,0)),
           json.dumps(list(dict.fromkeys(flags)), ensure_ascii=False), storage_policy, review,
           int(bool(spain_rows)), best_actionable_spain.get("spain_confidence"), best_actionable_spain.get("spain_match_language"),
           best_actionable_spain.get("spain_match_reason"), max(int(row.get("priority_score") or 0) for row in representative_rows),
           min(row.get("first_seen") or now for row in representative_rows), max(row.get("last_seen") or now for row in representative_rows),
           max((row.get("last_checked_at") or "" for row in representative_rows), default="") or None,
           max(0, len(hosts) - 1), live, dead, len(sources), "high" if restricted and len(hosts) == 1 else "medium" if restricted else None,
           now, site_card_id))
        db.execute("""UPDATE site_card_urls SET status=(SELECT status FROM onion_urls WHERE id=onion_url_id),
          active=(SELECT active FROM onion_urls WHERE id=onion_url_id),
          http_status=(SELECT http_status FROM onion_urls WHERE id=onion_url_id),
          dead_reason=(SELECT dead_reason FROM onion_urls WHERE id=onion_url_id),
          last_seen=(SELECT last_seen FROM onion_urls WHERE id=onion_url_id),
          last_checked_at=(SELECT last_checked_at FROM onion_urls WHERE id=onion_url_id),updated_at=?
          WHERE site_card_id=?""", (now, site_card_id))
        db.execute("""UPDATE site_card_urls SET url_role=CASE
          WHEN status='dead' OR dead_reason IS NOT NULL THEN 'dead_mirror'
          WHEN onion_url_id IN (SELECT id FROM onion_urls WHERE storage_policy='metadata_only') THEN 'restricted'
          ELSE url_role END WHERE site_card_id=?""", (site_card_id,))
        type_scores: dict[str, int] = {}
        for row in identity_classification_rows:
            page_type = normalize_page_type(row.get("page_type"))
            score = {"low": 1, "medium": 2, "high": 3}.get(
                str(row.get("page_type_confidence") or "low"), 1)
            score += 3 if row.get("card_path") in {None, "", "/"} else 0
            score += 2 if row.get("card_ready") else 0
            score += 2 if page_type in LANDING_PAGE_TYPES else 0
            score -= 2 if page_type in CHILD_PAGE_TYPES else 0
            if row.get("content_quality") in {"empty", "unavailable"}:
                score = 0
            type_scores[page_type] = type_scores.get(page_type, 0) + score
        consensus_page_type = max(type_scores, key=lambda key: (type_scores[key], key != "unknown"))
        taxonomy_candidates = [row for row in classification_rows
                               if normalize_content_category(row.get("primary_category")) == primary
                               and int(row.get("category_update_allowed")
                                       if row.get("category_update_allowed") is not None else 1)]
        taxonomy = max(taxonomy_candidates or classification_rows or [identity_row],
                       key=lambda row: (
                           confidence_weight.get(str(row.get("category_confidence") or "low").casefold(), 1),
                           3 if row.get("card_path") in {None, "", "/"} else 0,
                           2 if normalize_page_type(row.get("page_type")) in LANDING_PAGE_TYPES else 0,
                           int(row.get("review_score") or 0)))
        secondary = []
        for row in representative_rows:
            secondary.extend(_loads(row.get("secondary_categories")))
        db.execute("""UPDATE site_cards SET secondary_categories=?,marketplace_type=?,page_type=?,
          category_confidence=?,category_reason=?,category_safe_label=?,display_group=?,ui_hidden_default=?,
          ui_priority=?,review_score=? WHERE id=?""",
          (json.dumps(list(dict.fromkeys(secondary)), ensure_ascii=False), taxonomy.get("marketplace_type"),
           consensus_page_type, taxonomy.get("category_confidence") or "low",
           taxonomy.get("category_reason"), taxonomy.get("category_safe_label") or safe_category_label(primary),
           taxonomy.get("display_group") or "Other", max(int(row.get("ui_hidden_default") or 0) for row in representative_rows),
           max(int(row.get("ui_priority") or 0) for row in representative_rows),
           max(int(row.get("review_score") or 0) for row in representative_rows), site_card_id))
        db.execute("UPDATE site_cards SET seen_count=? WHERE id=?",
                   (sum(int(row.get("seen_count") or 1) for row in rows), site_card_id))
        db.execute("UPDATE site_cards SET spain_context_tags=? WHERE id=?",
                   (best_spain.get("spain_context_tags") if spain_signal_rows else taxonomy.get("spain_context_tags"), site_card_id))
        importance_order = {"low": 0, "normal": 1, "elevated": 2, "high": 3, "critical": 4}
        rolled_importance = max((str(row.get("importance_level") or "normal") for row in representative_rows),
                                key=lambda value: importance_order.get(value, 1))
        importance = (current["analyst_importance"] if current and current["analyst_importance"]
                      else rolled_importance)
        if generic_marketplace_monitor and not (current and current["analyst_importance"]):
            importance = "normal"
            for row in representative_rows:
                row["importance_reason"] = row.get("importance_reason") or "generic_metadata_limited_monitor"
        importance_row = max(representative_rows,
                             key=lambda row: importance_order.get(str(row.get("importance_level") or "normal"), 1))
        urgent_flag = action_required
        locales = sorted({str(row.get("locale_path")) for row in rows if row.get("locale_path")})
        representative = identity_row
        site_identity = identify_site({
            "id": representative.get("id"), "url": representative.get("url"),
            "detected_title": identity_name, "language": representative.get("language"),
            "source_type": representative.get("source_type"),
        })
        db.execute("""UPDATE site_cards SET importance_level=?,importance_reason=?,locale_paths_seen=?,
          language_variants_count=?,spain_priority_reason=?,spain_priority_evidence_type=?,
          representative_url=? WHERE id=?""",
          (importance, importance_row.get("importance_reason"), json.dumps(locales, ensure_ascii=False),
           len(locales), best_actionable_spain.get("spain_priority_reason"),
           best_actionable_spain.get("spain_priority_evidence_type"), representative.get("url"), site_card_id))
        db.execute("""UPDATE site_cards SET safe_site_name=?,display_name_source=?,
          unsafe_title_hidden=?,identity_pending=?,policy_label=? WHERE id=?""",
          (identity_name, display_source, int(bool(identity_row.get("unsafe_title_hidden"))),
           int(not bool(identity_name) and bool(limited)), safe_category_label(primary), site_card_id))
        db.execute("""UPDATE site_cards SET spain_relevance=?,spain_evidence_type=?,
          seller_geo_confidence=?,spain_evidence_snippets=?,spain_evidence_source_url=?,
          spain_evidence_source_path=?,spain_context_only=?,spain_actionable=? WHERE id=?""",
          (best_spain.get("spain_relevance") or "none",
           best_spain.get("spain_evidence_type"),
           best_spain.get("seller_geo_confidence") or best_spain.get("spain_confidence") or "none",
           best_spain.get("spain_evidence_snippets"),
           best_spain.get("spain_evidence_source_url") or best_spain.get("url"),
           best_spain.get("spain_evidence_source_path") or best_spain.get("card_path"),
           int(bool(spain_signal_rows) and not bool(spain_rows)),
           int(bool(spain_rows)), site_card_id))
        db.execute("""UPDATE site_cards SET site_type=?,risk_category=?,urgent_score=?,
          urgent_flag=?,urgent_reason=?,context_only=? WHERE id=?""",
          (site_type, risk_category, urgent_score, int(bool(urgent_flag)),
           urgent_row.get("urgent_reason"), int(bool(context_only)), site_card_id))
        escalation_triggers = []
        if spain_rows:
            escalation_triggers.append("spain_priority")
        if any(term in " ".join(flags).casefold() for term in ("watchlist", "credential", "leak", "weapons", "weapon")):
            escalation_triggers.append("indicator_or_watchlist")
        if urgent_flag:
            escalation_triggers.append("urgent_evidence")
        review_reason = ("Monitor: generic metadata-limited marketplace context"
                         if generic_marketplace_monitor else
                         "Needs Review: " + ", ".join(escalation_triggers)
                         if review in {"pending", "needs_review", "needs_report"} and escalation_triggers
                         else "Auto-classified")
        db.execute("""UPDATE site_cards SET policy_risk=?,alert_eligible=?,review_reason=?,
          alert_reason=?,escalation_score=?,escalation_triggers=?,triage_level=?,triage_reason=? WHERE id=?""",
          (lambda triage: (
              risk, int(triage.level in {"alert", "urgent"}), review_reason,
              ", ".join(escalation_triggers) if escalation_triggers else None,
              max(len(escalation_triggers) * 25, triage.score),
              json.dumps(list(dict.fromkeys(escalation_triggers + triage.triggers)), ensure_ascii=False),
              triage.level, triage.reason, site_card_id
          ))(decide_triage(representative_rows)))
        db.execute("""UPDATE site_cards SET restricted_outbound_count=?,adult_outbound_count=?,
          severe_outbound_count=?,restricted_outbound_ratio=?,mixed_directory=?,restricted_child_present=?,
          adult_category_present=? WHERE id=?""",
          (restricted_outbound, adult_outbound, severe_outbound,
           restricted_outbound / outbound_total if outbound_total else 0.0,
           int(bool(restricted_outbound and restricted_outbound < outbound_total)), int(bool(restricted_outbound)),
           int(adult_category_present),
           site_card_id))
        liveness = ("live" if any(row.get("liveness_status") == "live" and row.get("active") for row in rows)
                    else "soft_dead" if any(row.get("liveness_status") == "soft_dead" for row in rows)
                    else "hard_dead" if all(row.get("status") == "dead" for row in rows) else "unknown")
        quality_order = {"unknown": 0, "unavailable": 0, "empty": 1, "thin": 2, "restricted": 2, "meaningful": 3}
        content_quality = max((row.get("content_quality") or "unknown" for row in rows),
                              key=lambda value: quality_order.get(value, 0))
        db.execute("UPDATE site_cards SET liveness_status=?,content_quality=? WHERE id=?",
                   (liveness, content_quality, site_card_id))
        db.execute("""UPDATE site_cards SET identity_site_id=?,identity_domain=?,
          identity_canonical_domain=?,identity_brand=?,identity_country=?,identity_language=?,
          identity_source_type=?,identity_matched_from=?,identity_confidence_score=?,
          identity_evidence_json=?,identity_ambiguous=?,identity_ambiguity_reason=?,
          identity_missing_fields_json=? WHERE id=?""",
          (site_identity.site_id, site_identity.domain, site_identity.canonical_domain,
           site_identity.brand, site_identity.country, site_identity.language,
           site_identity.source_type, site_identity.matched_from, site_identity.confidence,
           json.dumps(site_identity.evidence, ensure_ascii=False), int(site_identity.is_ambiguous),
           site_identity.ambiguity_reason,
           json.dumps(site_identity.missing_fields, ensure_ascii=False), site_card_id))
        ready_rows = [row for row in representative_rows if row.get("card_ready")]
        identity_rank = {"low": 1, "medium": 2, "high": 3}
        understanding_row = max(
            ready_rows or representative_rows,
            key=lambda row: (
                3 if row.get("card_path") in {None, "", "/"} else 0,
                identity_rank.get(str(row.get("page_type_confidence") or "low"), 0),
                int(row.get("link_repository_score") or 0),
            ),
        )
        db.execute("""UPDATE site_cards SET detected_title=?,title_source=?,identity_confidence=?,
          page_type_confidence=?,page_type_evidence_json=?,card_ready=?,card_readiness_reason=?,
          card_readiness_confidence=?,safe_summary=?,link_repository_score=?,outbound_onion_count=?,
          internal_link_count=?,external_onion_count=? WHERE id=?""",
          (understanding_row.get("detected_title"), understanding_row.get("title_source"),
           understanding_row.get("identity_confidence"), understanding_row.get("page_type_confidence"),
           understanding_row.get("page_type_evidence_json"), int(bool(ready_rows)),
           understanding_row.get("card_readiness_reason"),
           understanding_row.get("card_readiness_confidence"), understanding_row.get("safe_summary"),
           max(int(row.get("link_repository_score") or 0) for row in representative_rows),
           sum(int(row.get("outbound_onion_count") or 0) for row in representative_rows),
           sum(int(row.get("internal_link_count") or 0) for row in representative_rows),
           sum(int(row.get("external_onion_count") or 0) for row in representative_rows),
           site_card_id))
        child_evidence = {
            "adult_or_filtered": child_adult,
            "restricted_total": child_restricted,
            "blocked_total": child_blocked,
        }
        db.execute("""UPDATE site_cards SET child_adult_link_count=?,child_restricted_link_count=?,
          child_blocked_link_count=?,parent_evidence_json=?,child_link_evidence_json=? WHERE id=?""",
          (child_adult, child_restricted, child_blocked,
           understanding_row.get("parent_evidence_json"),
           json.dumps(child_evidence, ensure_ascii=False), site_card_id))
        db.execute("""UPDATE site_cards SET suggested_category=?,classification_decision=?,
          classification_confidence_score=?,classifier_version=? WHERE id=?""",
          (taxonomy.get("suggested_category"), taxonomy.get("classification_decision") or "unclassified",
           float(taxonomy.get("classification_confidence_score") or 0), taxonomy.get("classifier_version"),
           site_card_id))
        evidence_rows = taxonomy_candidates or [taxonomy]
        evidence_buckets: dict[str, list[str]] = {}
        supporting, contradicting = [], []
        for row in evidence_rows:
            parsed = _loads(row.get("category_evidence_json"), {})
            if isinstance(parsed, dict):
                for bucket, values in parsed.items():
                    evidence_buckets.setdefault(str(bucket), []).extend(str(value) for value in (values or []))
            supporting.extend(_loads(row.get("category_supporting_evidence_json")))
            contradicting.extend(_loads(row.get("category_contradicting_evidence_json")))
        evidence_buckets = {key: list(dict.fromkeys(values))[:20] for key, values in evidence_buckets.items()}
        card_policy = {"primary_category": primary, "storage_policy": storage_policy}
        db.execute("""UPDATE site_cards SET content_category=?,safety_state=?,category_evidence_json=?,
          category_supporting_evidence_json=?,category_contradicting_evidence_json=?,
          category_update_allowed=?,category_update_reason=? WHERE id=?""",
          (primary, derive_safety_state(card_policy), json.dumps(evidence_buckets, ensure_ascii=False),
           json.dumps(list(dict.fromkeys(supporting))[:30], ensure_ascii=False),
           json.dumps(list(dict.fromkeys(contradicting))[:20], ensure_ascii=False),
           int(bool(taxonomy_candidates)),
           ("analyst_category_preserved" if current and current["analyst_category"] else
            "confidence_weighted_safe_page_consensus" if taxonomy_candidates else
            "no_safe_page_allowed_category_update"), site_card_id))
        source_hosts = sorted({(urlsplit(source).hostname or "").casefold() for source in sources})
        indicator_types = [str(row[0]) for row in db.execute("""SELECT DISTINCT i.indicator_type
          FROM indicators i JOIN indicator_links il ON il.indicator_id=i.id
          JOIN site_card_urls scu ON scu.url=il.source_ref WHERE scu.site_card_id=?""", (site_card_id,))]
        card_score, card_label, card_reason = _card_completeness(
            representative_rows,
            display=display,
            primary=primary,
            consensus_page_type=consensus_page_type,
            category_confidence=taxonomy.get("category_confidence"),
            page_type_confidence=understanding_row.get("page_type_confidence"),
            hosts=hosts,
            indicator_types=indicator_types,
            live=live,
            last_checked_at=max((row.get("last_checked_at") or "" for row in representative_rows), default="") or None,
        )
        db.execute("""UPDATE site_cards SET card_completeness_score=?,
          card_completeness_label=?,card_completeness_reason=? WHERE id=?""",
          (card_score, card_label, card_reason, site_card_id))
        if (card_label in {"weak", "usable"} and primary not in ENRICHMENT_RESTRICTED_CATEGORIES
                and storage_policy not in {"discard", "metadata_only"}):
            existing_job = db.execute("""SELECT id FROM site_card_jobs
              WHERE job_type='enrich_card' AND site_card_id=? LIMIT 1""",
              (site_card_id,)).fetchone()
            if not existing_job:
                now_job = storage.utc_now_iso()
                db.execute("""INSERT INTO site_card_jobs
                  (site_card_id,url,job_type,status,priority,created_at,updated_at)
                  VALUES(?,?,'enrich_card','queued',?,?,?)""",
                  (site_card_id, representative.get("url"), max(1, 100 - card_score), now_job, now_job))
                db.execute("UPDATE site_cards SET last_enrichment_planned_at=? WHERE id=?",
                           (now_job, site_card_id))
        safe_search = " ".join(str(value or "") for value in (
            display, primary, safe_category_label(primary), " ".join(dict.fromkeys(tags)),
            best_spain.get("spain_match_reason"), review, " ".join(sorted(hosts)), " ".join(source_hosts),
            " ".join(indicator_types), understanding_row.get("safe_summary"),
            site_type, risk_category, "urgent" if urgent_flag else "", urgent_row.get("urgent_reason"),
        )).casefold()[:8000]
        db.execute("UPDATE site_cards SET search_text=?,rollup_dirty=0 WHERE id=?", (safe_search, site_card_id))


def merge_site_cards(source_site_card_id: int, target_site_card_id: int) -> int:
    if source_site_card_id == target_site_card_id:
        return target_site_card_id
    now = storage.utc_now_iso()
    with storage.get_db() as db:
        source_card = db.execute("SELECT * FROM site_cards WHERE id=?", (source_site_card_id,)).fetchone()
        target_card = db.execute("SELECT * FROM site_cards WHERE id=?", (target_site_card_id,)).fetchone()
        if not source_card:
            raise ValueError("Source Site Card not found")
        if not target_card:
            raise ValueError("Target Site Card not found")
        if _severe_blackhole(source_card, target_card):
            raise ValueError("Severe-blackhole Site Cards cannot be merged")
        # Analyst work and report history survive an automatic identity merge.
        db.execute("""UPDATE site_cards SET
          analyst_title=COALESCE(analyst_title,?),analyst_notes=COALESCE(analyst_notes,?),
          analyst_importance=COALESCE(analyst_importance,?),
          report_status=CASE WHEN report_status IN ('not_prepared','requested') THEN ? ELSE report_status END,
          report_generated_at=COALESCE(report_generated_at,?),report_error=COALESCE(report_error,?),
          updated_at=? WHERE id=?""",
          (source_card["analyst_title"], source_card["analyst_notes"], source_card["analyst_importance"],
           source_card["report_status"], source_card["report_generated_at"], source_card["report_error"],
           now, target_site_card_id))
        db.execute("UPDATE site_card_urls SET site_card_id=?,updated_at=? WHERE site_card_id=?",
                   (target_site_card_id, now, source_site_card_id))
        db.execute("UPDATE site_fingerprints SET site_card_id=? WHERE site_card_id=?",
                   (target_site_card_id, source_site_card_id))
        db.execute("UPDATE site_card_events SET site_card_id=? WHERE site_card_id=?",
                   (target_site_card_id, source_site_card_id))
        db.execute("""DELETE FROM possible_site_card_matches WHERE candidate_site_card_id=? AND EXISTS(
          SELECT 1 FROM possible_site_card_matches other WHERE other.onion_url_id=possible_site_card_matches.onion_url_id
          AND other.candidate_site_card_id=?)""", (source_site_card_id, target_site_card_id))
        db.execute("UPDATE possible_site_card_matches SET candidate_site_card_id=?,updated_at=? WHERE candidate_site_card_id=?",
                   (target_site_card_id, now, source_site_card_id))
        db.execute("UPDATE onion_urls SET site_card_id=?,canonical_site_id=(SELECT canonical_site_id FROM site_cards WHERE id=?) WHERE site_card_id=?",
                   (target_site_card_id, target_site_card_id, source_site_card_id))
        db.execute("UPDATE evidence_reports SET site_card_id=? WHERE site_card_id=?", (target_site_card_id, source_site_card_id))
        db.execute("UPDATE spain_alert_queue SET site_card_id=?,canonical_site_id=(SELECT canonical_site_id FROM site_cards WHERE id=?) WHERE site_card_id=?",
                   (target_site_card_id, target_site_card_id, source_site_card_id))
        db.execute("DELETE FROM site_cards WHERE id=?", (source_site_card_id,))
        db.execute("""DELETE FROM possible_site_card_matches WHERE candidate_site_card_id=?
          AND onion_url_id IN (SELECT onion_url_id FROM site_card_urls WHERE site_card_id=?)""",
          (target_site_card_id, target_site_card_id))
        db.execute("""INSERT INTO site_card_events(site_card_id,event_type,event_summary,safe_metadata_json,created_at)
          VALUES(?,?,?,?,?)""", (target_site_card_id, "cards_merged", "Site Cards merged by passive evidence or analyst",
          json.dumps({"source_site_card_id": source_site_card_id}, ensure_ascii=False), now))
    update_site_card_rollups(target_site_card_id)
    return target_site_card_id


def duplicate_site_card_groups() -> list[dict]:
    """Return safe same-host duplicate groups without loading URL/content evidence."""
    with storage.get_db() as db:
        rows = db.execute("""SELECT lower(scu.onion_host) AS onion_host,
          group_concat(DISTINCT scu.site_card_id) AS card_ids,
          COUNT(DISTINCT scu.site_card_id) AS card_count
          FROM site_card_urls scu JOIN site_cards sc ON sc.id=scu.site_card_id
          WHERE COALESCE(scu.onion_host,'')!=''
          AND sc.primary_category NOT IN ('adult_filtered','adult_restricted','severe_abuse_risk')
          GROUP BY lower(scu.onion_host) HAVING COUNT(DISTINCT scu.site_card_id)>1
          ORDER BY card_count DESC,onion_host""").fetchall()
        url_rows = db.execute("""SELECT lower(COALESCE(ou.onion_domain,'')) AS onion_host,
          group_concat(DISTINCT ou.site_card_id) AS card_ids,
          COUNT(DISTINCT ou.site_card_id) AS card_count
          FROM onion_urls ou JOIN site_cards sc ON sc.id=ou.site_card_id
          WHERE COALESCE(ou.onion_domain,'')!='' AND ou.site_card_id IS NOT NULL
          AND sc.primary_category NOT IN ('adult_filtered','adult_restricted','severe_abuse_risk')
          GROUP BY lower(COALESCE(ou.onion_domain,'')) HAVING COUNT(DISTINCT ou.site_card_id)>1""").fetchall()
    groups: dict[str, set[int]] = {}
    for row in list(rows) + list(url_rows):
        host = str(row["onion_host"] or "").casefold()
        if not host:
            continue
        groups.setdefault(host, set()).update(
            int(value) for value in str(row["card_ids"] or "").split(",") if value
        )
    return [{"onion_host": host, "card_ids": sorted(card_ids), "card_count": len(card_ids)}
            for host, card_ids in sorted(groups.items()) if len(card_ids) > 1]


def reconcile_duplicate_site_cards(*, dry_run: bool = True) -> dict:
    """Merge only unambiguous visible same-host cards; dry-run is the default."""
    groups = duplicate_site_card_groups()
    proposals, merged = [], 0
    for group in groups:
        card_ids = group["card_ids"]
        with storage.get_db() as db:
            cards = [dict(row) for row in db.execute(
                f"SELECT * FROM site_cards WHERE id IN ({','.join('?' for _ in card_ids)}) ORDER BY first_seen,id",
                card_ids)]
        # Prefer the oldest card that already contains analyst work.
        cards.sort(key=lambda card: (0 if card.get("analyst_title") else 1,
                                     str(card.get("first_seen") or ""), int(card["id"])))
        target = int(cards[0]["id"])
        sources = [int(card["id"]) for card in cards[1:]]
        proposals.append({"onion_host": group["onion_host"], "target_card_id": target,
                          "source_card_ids": sources})
        if not dry_run:
            for source in sources:
                merge_site_cards(source, target)
                merged += 1
    return {"dry_run": int(dry_run), "groups": len(groups), "cards_to_merge": sum(
        len(item["source_card_ids"]) for item in proposals), "merged": merged, "proposals": proposals}


def get_or_create_site_card_for_url(url_or_id: str | int, classification: dict | None = None,
                                    **kwargs) -> int:
    """Public repository boundary for canonical Site Card assignment."""
    return ensure_url_site_card(url_or_id, classification, **kwargs)


def assign_url_to_card_safely(url_id: int, classification: dict,
                              fingerprints: list[dict]) -> int:
    return assign_url_to_site_card(url_id, classification, fingerprints)


def merge_duplicate_cards_safely(source_site_card_id: int, target_site_card_id: int) -> int:
    return merge_site_cards(source_site_card_id, target_site_card_id)


def find_duplicate_card_candidates() -> list[dict]:
    return duplicate_site_card_groups()


def explain_card_creation_decision(site_card_id: int) -> dict:
    card = get_site_card_detail(site_card_id, url_limit=1, event_limit=1,
                                include_dead=True, include_restricted=False)
    if not card:
        raise ValueError("Site Card not found")
    with storage.get_db() as db:
        event = db.execute("""SELECT safe_metadata_json FROM site_card_events
          WHERE site_card_id=? AND event_type='url_assigned'
          ORDER BY id DESC LIMIT 1""", (site_card_id,)).fetchone()
        url_row = db.execute("""SELECT onion_host,path,url_role,mirror_confidence,url
          FROM site_card_urls WHERE site_card_id=?
          ORDER BY CASE url_role WHEN 'canonical' THEN 0 ELSE 1 END,id LIMIT 1""",
          (site_card_id,)).fetchone()
    metadata = _loads(event["safe_metadata_json"], {}) if event else {}
    if not isinstance(metadata, dict):
        metadata = {}
    url_info = dict(url_row) if url_row else {}
    return {"site_card_id": site_card_id, "canonical_site_id": card.get("canonical_site_id"),
            "host": metadata.get("host") or url_info.get("onion_host"),
            "canonical_root": metadata.get("canonical_root"),
            "entity_identity": metadata.get("entity_identity"),
            "normalized_path": metadata.get("normalized_path") or url_info.get("path"),
            "path_signature": metadata.get("path_signature"),
            "query_signature": metadata.get("query_signature"),
            "url_role": metadata.get("url_role") or url_info.get("url_role"),
            "match_confidence": metadata.get("match_confidence") or url_info.get("mirror_confidence"),
            "decision_reason": metadata.get("decision_reason"),
            "card_ready": bool(card.get("card_ready")),
            "reason": card.get("card_readiness_reason") or card.get("category_reason"),
            "identity_confidence": card.get("identity_confidence"),
            "category_update_allowed": bool(card.get("category_update_allowed")),
            "category_update_reason": card.get("category_update_reason")}


def _latest_page_decision(*, onion_url_id: int | None = None,
                          site_card_id: int | None = None) -> dict | None:
    """Return the latest machine page decision for an explicit analyst action."""
    if onion_url_id is None and site_card_id is None:
        return None
    where, value = (
        ("onion_url_id=?", int(onion_url_id))
        if onion_url_id is not None
        else ("site_card_id=?", int(site_card_id))
    )
    with storage.get_db() as db:
        row = db.execute(f"""SELECT id,onion_url_id,site_card_id,final_category,
          classifier_version FROM classification_decisions
          WHERE stage='page' AND analyst_corrected=0 AND {where}
          ORDER BY ts DESC,id DESC LIMIT 1""", (value,)).fetchone()
        return dict(row) if row else None


def _record_feedback_safely(**kwargs) -> None:
    """Quality telemetry must never block the analyst action it observes."""
    try:
        storage.record_classification_feedback(**kwargs)
    except (TypeError, ValueError, sqlite3.Error):
        return


def split_url_from_site_card(url_id: int) -> int:
    baseline = _latest_page_decision(onion_url_id=url_id)
    with storage.get_db() as db:
        row = db.execute("SELECT * FROM onion_urls WHERE id=?", (url_id,)).fetchone()
        if not row:
            raise ValueError("URL not found")
    if _severe_blackhole(row):
        _enforce_severe_url(dict(row), dict(row))
        return 0
    with storage.get_db() as db:
        row = db.execute("SELECT * FROM onion_urls WHERE id=?", (url_id,)).fetchone()
        if not row:
            return 0
        old_id = row["site_card_id"]
        db.execute("DELETE FROM site_card_urls WHERE onion_url_id=?", (url_id,))
        db.execute("DELETE FROM site_fingerprints WHERE onion_url_id=?", (url_id,))
        db.execute("UPDATE onion_urls SET site_card_id=NULL,canonical_site_id=NULL,dedupe_status='unassigned' WHERE id=?", (url_id,))
    policy = dict(row)
    new_id = ensure_url_site_card(url_id, policy)
    if old_id:
        with storage.get_db() as db:
            remaining = db.execute("SELECT COUNT(*) FROM site_card_urls WHERE site_card_id=?", (old_id,)).fetchone()[0]
            if not remaining:
                db.execute("DELETE FROM site_cards WHERE id=?", (old_id,))
        if remaining:
            update_site_card_rollups(int(old_id))
    if old_id:
        _record_feedback_safely(
            subject=f"url:{url_id}:split:{old_id}:{new_id}",
            feedback_scope="mirror", feedback_action="split_after_merge",
            reason_code="analyst_split_url_from_site_card",
            decision_id=baseline.get("id") if baseline else None,
            onion_url_id=url_id, site_card_id=new_id,
            previous_category=baseline.get("final_category") if baseline else row["primary_category"],
            final_category=row["primary_category"],
            classifier_version=baseline.get("classifier_version") if baseline else None,
            safe_metadata={"scope": "url", "confirmed": True},
        )
    return new_id


def apply_card_review(site_card_id: int, action: str, url_id: int | None = None) -> None:
    if action not in {"keep", "ignored", "needs_report", "reported", "blocked", "live_check"}:
        raise ValueError("Invalid Site Card action")
    review_map = {"keep": "relevant", "ignored": "false_positive", "needs_report": "needs_report",
                  "reported": "reported", "blocked": "blocked"}
    baseline = _latest_page_decision(onion_url_id=url_id, site_card_id=None if url_id else site_card_id)
    reviewed_category = "unknown"
    urgent_before = False
    with storage.get_db() as db:
        state = db.execute(
            "SELECT primary_category,urgent_flag FROM site_cards WHERE id=?",
            (site_card_id,),
        ).fetchone()
        if state:
            reviewed_category = str(state["primary_category"] or "unknown")
            urgent_before = bool(state["urgent_flag"])
        ids = [url_id] if url_id else [row[0] for row in db.execute(
            "SELECT onion_url_id FROM site_card_urls WHERE site_card_id=?", (site_card_id,))]
        for current_id in ids:
            if action == "live_check":
                db.execute("""UPDATE onion_urls SET status='queued',active=1,next_crawl_at=?,priority_score=priority_score+1000
                  WHERE id=? AND queue_policy!='blocked'""", (storage.utc_now_iso(), current_id))
            else:
                db.execute("UPDATE onion_urls SET review_status=? WHERE id=?", (review_map[action], current_id))
                if action == "blocked":
                    db.execute("UPDATE onion_urls SET active=0,status='blocked',queue_policy='blocked' WHERE id=? AND status!='dead'", (current_id,))
        if not url_id and action != "live_check":
            db.execute("UPDATE site_cards SET review_status=?,report_status=CASE WHEN ?='needs_report' THEN 'requested' WHEN ?='reported' THEN 'generated' ELSE report_status END,updated_at=? WHERE id=?",
                       (review_map[action], action, action, storage.utc_now_iso(), site_card_id))
            if action in {"ignored", "blocked", "keep", "reported"}:
                spain_status = {"ignored":"ignored", "blocked":"blocked", "keep":"keep", "reported":"reported"}[action]
                db.execute("UPDATE onion_urls SET spain_review_status=? WHERE site_card_id=? AND spain_priority=1", (spain_status, site_card_id))
        db.execute("""INSERT INTO site_card_events(site_card_id,event_type,event_summary,safe_metadata_json,created_at)
          VALUES(?,?,?,?,?)""", (site_card_id, "review_action", f"Analyst action: {action}",
          json.dumps({"scope": "url" if url_id else "card", "url_id": url_id}, ensure_ascii=False), storage.utc_now_iso()))
    update_site_card_rollups(site_card_id)
    if action != "live_check" and reviewed_category != "severe_abuse_risk":
        feedback_actions = {
            "keep": "review_kept", "ignored": "review_ignored",
            "needs_report": "review_needs_report", "reported": "review_reported",
            "blocked": "review_blocked",
        }
        _record_feedback_safely(
            subject=f"{'url' if url_id else 'site-card'}:{url_id or site_card_id}:review",
            feedback_scope="review", feedback_action=feedback_actions[action],
            reason_code="analyst_review_disposition",
            decision_id=baseline.get("id") if baseline else None,
            onion_url_id=url_id, site_card_id=site_card_id,
            previous_category=reviewed_category, final_category=reviewed_category,
            classifier_version=baseline.get("classifier_version") if baseline else None,
            safe_metadata={
                "scope": "url" if url_id else "card",
                "review_status": review_map[action],
            },
        )
        urgency_action = (
            "urgent_dismissed" if action == "ignored"
            else "urgent_confirmed" if action in {"keep", "needs_report", "reported"}
            else None
        )
        if urgent_before and urgency_action:
            _record_feedback_safely(
                subject=f"{'url' if url_id else 'site-card'}:{url_id or site_card_id}:urgency",
                feedback_scope="urgency", feedback_action=urgency_action,
                reason_code="analyst_review_of_urgent_item",
                decision_id=baseline.get("id") if baseline else None,
                onion_url_id=url_id, site_card_id=site_card_id,
                previous_category=reviewed_category, final_category=reviewed_category,
                classifier_version=baseline.get("classifier_version") if baseline else None,
                safe_metadata={
                    "scope": "url" if url_id else "card",
                    "confirmed": urgency_action == "urgent_confirmed",
                },
            )


def apply_manual_category(site_card_id: int, category: str) -> None:
    """Apply an analyst category correction without weakening restricted-content policy."""
    if category not in ANALYST_CATEGORY_OPTIONS:
        raise ValueError("Invalid analyst category")
    now = storage.utc_now_iso()
    baseline = _latest_page_decision(site_card_id=site_card_id)
    previous_card_category = "unknown"
    threat_categories = {"weapons_arms", "drugs", "leaks_data", "credentials", "malware_hacking",
                         "fraud_financial", "extremist_recruitment"}
    limited_category = category in threat_categories or category.startswith("marketplace")
    neutral_category = category in NEUTRAL_CATEGORIES
    corrected_urls = []
    with storage.get_db() as db:
        card = db.execute("SELECT primary_category,storage_policy FROM site_cards WHERE id=?", (site_card_id,)).fetchone()
        if not card:
            raise ValueError("Site Card not found")
        previous_card_category = str(card["primary_category"] or "unknown")
        if card["primary_category"] in {"adult_filtered", "adult_restricted", "severe_abuse_risk"}:
            raise ValueError("Restricted safety categories require the dedicated false-positive review workflow")
        corrected_urls = [dict(row) for row in db.execute(
            """SELECT id,url,primary_category,tags,spain_priority,spain_analyst_suppressed
              FROM onion_urls WHERE site_card_id=?""", (site_card_id,))]
        discovery_category = category in {"directory_index", "search_engine", "forum_social"}
        db.execute("""UPDATE onion_urls SET primary_category=?,category=?,content_category=?,category_safe_label=?,analyst_category=?,
          category_confidence='analyst',category_reason='Analyst category correction',
          suggested_category=?,classification_decision='analyst_confirmed',
          classification_confidence_score=1.0,classifier_version='analyst-v1',classification_stage='analyst',
          classification_evidence_source='analyst',destination_html_evidence_version=0,
          storage_policy=CASE WHEN ? THEN 'metadata_limited' ELSE 'safe_summary' END,
          queue_policy=CASE WHEN ? THEN 'reviewable' WHEN ? THEN 'expand' ELSE 'normal' END,
          screenshot_policy=CASE WHEN ? THEN 'blocked'
            WHEN screenshot_blocked_reason='restricted_child_present' THEN screenshot_policy ELSE 'allowed' END,
          screenshot_blocked_reason=CASE WHEN ? THEN 'analyst_category_metadata_limited'
            WHEN screenshot_blocked_reason='restricted_child_present' THEN screenshot_blocked_reason ELSE NULL END,
          risk_level=CASE WHEN ? AND lower(COALESCE(risk_level,'low')) IN ('low','medium','nulo','bajo','medio')
                          THEN 'high' ELSE risk_level END,
          review_status=CASE WHEN ? THEN 'monitor'
            WHEN review_status IN ('monitor','pending') THEN 'needs_review' ELSE review_status END,
          review_score=MAX(COALESCE(review_score,0),CASE WHEN ? THEN 70 ELSE 20 END),
          ui_priority=MAX(COALESCE(ui_priority,0),CASE WHEN ? THEN 70 ELSE 20 END)
          WHERE site_card_id=? AND primary_category NOT IN ('adult_filtered','adult_restricted','severe_abuse_risk')""",
          (category, category, category, safe_category_label(category), category, category, int(limited_category),
           int(limited_category), int(discovery_category), int(limited_category), int(limited_category),
           int(limited_category), int(neutral_category), int(limited_category), int(limited_category), site_card_id))
        for item in corrected_urls:
            tags = _loads(item.get("tags"))
            tags.extend(category_search_tags(category))
            if item.get("spain_priority") and not item.get("spain_analyst_suppressed"):
                tags.extend(["spain", "spain_confirmed"])
            db.execute("UPDATE onion_urls SET tags=? WHERE id=?",
                       (json.dumps(list(dict.fromkeys(tags)), ensure_ascii=False), item["id"]))
        db.execute("UPDATE spain_hits SET primary_category=? WHERE site_card_id=?",
                   (category, site_card_id))
        db.execute("UPDATE spain_alert_queue SET status='classified' WHERE status='pending' AND site_card_id=?",
                   (site_card_id,))
        db.execute("""UPDATE site_cards SET primary_category=?,content_category=?,category_safe_label=?,analyst_category=?,
          category_confidence='analyst',category_reason='Analyst category correction',
          suggested_category=?,classification_decision='analyst_confirmed',
          classification_confidence_score=1.0,classifier_version='analyst-v1',rollup_dirty=1,
          updated_at=? WHERE id=?""", (category, category, safe_category_label(category), category, category, now, site_card_id))
        db.execute("""INSERT INTO site_card_events(site_card_id,event_type,event_summary,safe_metadata_json,created_at)
          VALUES(?,?,?,?,?)""", (site_card_id, "category_corrected", "Analyst corrected Site Card category",
          json.dumps({"previous_category": card["primary_category"], "new_category": category}, ensure_ascii=False), now))
    update_site_card_rollups(site_card_id)
    for item in corrected_urls:
        storage.record_classification_decision(
            item["url"], {
                "primary_category": category, "suggested_category": category,
                "category_confidence": "analyst", "classification_confidence_score": 1.0,
                "classification_decision": "analyst_confirmed", "classifier_version": "analyst-v1",
                "category_reason": "Analyst category correction", "evidence_families": ["analyst_review"],
            }, stage="analyst", previous_category=item.get("primary_category"), analyst_corrected=True,
            safe_metadata={"scope": "site_card"},
        )
    _record_feedback_safely(
        subject=f"site-card:{site_card_id}:category",
        feedback_scope="category",
        feedback_action=(
            "category_confirmed"
            if previous_card_category == category
            else "category_corrected"
        ),
        reason_code="analyst_category_correction",
        decision_id=baseline.get("id") if baseline else None,
        site_card_id=site_card_id,
        previous_category=previous_card_category,
        final_category=category,
        classifier_version=baseline.get("classifier_version") if baseline else None,
        safe_metadata={
            "scope": "site_card",
            "url_count": len(corrected_urls),
            "member_decision_count": len(corrected_urls),
        },
    )


def apply_manual_importance(site_card_id: int, importance: str, notes: str | None = None) -> None:
    """Override analyst importance without changing policy-driven risk."""
    if importance not in {"low", "normal", "elevated", "high", "critical"}:
        raise ValueError("Invalid importance")
    now = storage.utc_now_iso()
    with storage.get_db() as db:
        if not db.execute("SELECT 1 FROM site_cards WHERE id=?", (site_card_id,)).fetchone():
            raise ValueError("Site Card not found")
        db.execute("""UPDATE site_cards SET analyst_importance=?,importance_level=?,
          importance_reason='analyst_override',analyst_notes=COALESCE(?,analyst_notes),
          analyst_last_updated_at=?,updated_at=? WHERE id=?""",
          (importance, importance, notes.strip()[:1000] if notes and notes.strip() else None,
           now, now, site_card_id))
        db.execute("""INSERT INTO site_card_events(site_card_id,event_type,event_summary,
          safe_metadata_json,created_at) VALUES(?,?,?,?,?)""",
          (site_card_id, "importance_corrected", "Analyst changed Site Card importance",
           json.dumps({"importance": importance}, ensure_ascii=False), now))


def apply_manual_title(site_card_id: int, title: str | None) -> None:
    """Set a dashboard-only analyst title without changing crawler-derived state."""
    normalized = " ".join(str(title or "").split()).strip()
    if len(normalized) > 180:
        raise ValueError("Analyst title must be 180 characters or fewer")
    now = storage.utc_now_iso()
    with storage.get_db() as db:
        if not db.execute("SELECT 1 FROM site_cards WHERE id=?", (site_card_id,)).fetchone():
            raise ValueError("Site Card not found")
        db.execute("""UPDATE site_cards SET analyst_title=?,analyst_last_updated_at=?,updated_at=?
          WHERE id=?""", (normalized or None, now, now, site_card_id))
        db.execute("""INSERT INTO site_card_events(site_card_id,event_type,event_summary,
          safe_metadata_json,created_at) VALUES(?,?,?,?,?)""",
          (site_card_id, "analyst_title_changed",
           "Analyst title cleared" if not normalized else "Analyst title updated",
           json.dumps({"title_set": bool(normalized)}), now))


def mark_site_card_adult_filtered(site_card_id: int) -> int:
    """Analyst emergency action: blackhole a Site Card that contains adult content."""
    now = storage.utc_now_iso()
    baseline = _latest_page_decision(site_card_id=site_card_id)
    with storage.get_db() as db:
        urls = [str(row["url"]) for row in db.execute("""SELECT ou.url FROM onion_urls ou
          JOIN site_card_urls scu ON scu.onion_url_id=ou.id WHERE scu.site_card_id=?""",
          (site_card_id,))]
        if not urls:
            raise ValueError("Site Card has no URLs to filter")
        marks = ",".join("?" for _ in urls)
        db.execute(f"""UPDATE onion_urls SET primary_category='adult_filtered',
          category='adult_filtered', risk_level='filtered', confidence='high',
          risk_flags='["adult_filtered"]', storage_policy='discard',
          review_status='filtered', safety_reason='adult_content_filtered',
          screenshot_blocked_reason='adult_content_filtered', screenshot_policy='blocked',
          queue_policy='blocked', status='blocked', active=0, spain_priority=0,
          spain_review_status='ignored', priority_score=0, ui_hidden_default=1,
          title=NULL, safe_display_name=NULL, safe_summary=NULL,
          classification_evidence_source='analyst',destination_html_evidence_version=0,
          last_seen=COALESCE(last_seen,?)
          WHERE url IN ({marks})""", (now, *urls))
        for url in urls:
            host = (urlsplit(url).hostname or "").casefold()
            db.execute("""INSERT INTO adult_filter_memory
              (onion_url_id,url_hash,host_hash,classification,confidence,safe_rule_id,
               first_seen,last_seen,analyst_decision,reviewed_at,match_scope,confidence_reason)
              SELECT id,?,?,?,?,?,?,?,?,?,?,? FROM onion_urls WHERE url=?
              ON CONFLICT(url_hash) DO UPDATE SET onion_url_id=COALESCE(adult_filter_memory.onion_url_id,excluded.onion_url_id),
              analyst_decision='blocked',reviewed_at=excluded.reviewed_at,last_seen=excluded.last_seen,
              match_count=adult_filter_memory.match_count+1,match_scope='analyst_site_card',
              confidence_reason='manual_card_adult_filter'""",
              (_hash(url), _hash(host),
               "adult_filtered", "high", "adult_content_filtered", now, now, "blocked", now,
               "analyst_site_card", "manual_card_adult_filter", url))
        db.execute("""INSERT INTO site_card_events(site_card_id,event_type,event_summary,
          safe_metadata_json,created_at) VALUES(?,?,?,?,?)""",
          (site_card_id, "adult_filter_applied",
           "Analyst marked Site Card as adult filtered",
           json.dumps({"url_count": len(urls)}, ensure_ascii=False), now))
    _record_feedback_safely(
        subject=f"site-card:{site_card_id}:adult-filter",
        feedback_scope="safety", feedback_action="adult_block_confirmed",
        reason_code="analyst_site_card_adult_filter",
        decision_id=baseline.get("id") if baseline else None,
        site_card_id=site_card_id,
        previous_category=baseline.get("final_category") if baseline else None,
        final_category="adult_filtered",
        classifier_version=baseline.get("classifier_version") if baseline else None,
        safe_metadata={"scope": "site_card", "url_count": len(urls), "confirmed": True},
    )
    return storage.cleanup_adult_filtered_items()


def set_card_alert_suppressed(site_card_id: int, suppressed: bool) -> None:
    now = storage.utc_now_iso()
    with storage.get_db() as db:
        db.execute("""UPDATE site_cards SET analyst_suppressed_alerts=?,analyst_last_updated_at=?,
          updated_at=? WHERE id=?""", (int(suppressed), now, now, site_card_id))
        if suppressed:
            db.execute("UPDATE spain_alert_queue SET status='suppressed' WHERE site_card_id=? AND status='pending'",
                       (site_card_id,))
        db.execute("""INSERT INTO site_card_events(site_card_id,event_type,event_summary,
          safe_metadata_json,created_at) VALUES(?,?,?,?,?)""",
          (site_card_id, "alert_suppression_changed",
           "Analyst suppressed duplicate alerts" if suppressed else "Analyst resumed alerts",
           json.dumps({"suppressed": bool(suppressed)}), now))


def get_site_card_summaries(*, spain_only: bool = False, review_only: bool = False,
                            category: str | None = None, priority_filter: str | None = None,
                            operational_filter: str | None = None, search: str | None = None,
                            risk_filter: str | None = None, importance_filter: str | None = None,
                            review_filter: str | None = None, report_filter: str | None = None,
                            title_filter: str | None = None, age_filter: str | None = None,
                            duplicates_only: bool = False,
                            sort: str = "needs_review", limit: int = 100, offset: int = 0,
                            include_hidden: bool = False, include_monitor: bool = False) -> list[dict]:
    """Return bounded SQL-filtered card rows without URL/event/indicator detail payloads."""
    # Severe blackhole tombstones have no Site Card surface, even when a
    # caller asks to include ordinary hidden/adult metadata.
    where, params = ["sc.primary_category!='severe_abuse_risk'"], []
    if not include_hidden:
        where += ["COALESCE(sc.ui_hidden_default,0)=0",
                  "sc.primary_category NOT IN ('adult_filtered','adult_restricted')"]
    if not include_monitor and operational_filter != "Monitor only":
        where.append("sc.review_status!='monitor'")
    if spain_only:
        where.append("sc.spain_priority=1")
    if review_only:
        where += ["sc.review_status IN ('needs_review','needs_report','restricted')", "sc.live_url_count>0"]
    if category:
        where.append("sc.primary_category=?"); params.append(category)
    if risk_filter and risk_filter != "All":
        where.append("lower(COALESCE(sc.risk_level,'low'))=?"); params.append(risk_filter.casefold())
    if importance_filter and importance_filter != "All":
        where.append("lower(COALESCE(sc.importance_level,'normal'))=?"); params.append(importance_filter.casefold())
    if review_filter and review_filter != "All":
        where.append("lower(COALESCE(sc.review_status,'pending'))=?"); params.append(review_filter.casefold())
    if report_filter == "No report":
        where.append("NOT EXISTS(SELECT 1 FROM evidence_reports er WHERE er.site_card_id=sc.id)")
    elif report_filter == "Ready":
        where.append("EXISTS(SELECT 1 FROM evidence_reports er WHERE er.site_card_id=sc.id)")
        where.append("COALESCE(sc.report_status,'')!='failed'")
        where.append("COALESCE(sc.updated_at,'')<=COALESCE(sc.report_generated_at,(SELECT MAX(er.ts) FROM evidence_reports er WHERE er.site_card_id=sc.id))")
    elif report_filter == "Needs update":
        where.append("EXISTS(SELECT 1 FROM evidence_reports er WHERE er.site_card_id=sc.id)")
        where.append("COALESCE(sc.updated_at,'')>COALESCE(sc.report_generated_at,(SELECT MAX(er.ts) FROM evidence_reports er WHERE er.site_card_id=sc.id),'')")
    elif report_filter == "Failed":
        where.append("sc.report_status='failed'")
    if title_filter == "Analyst title":
        where.append("trim(COALESCE(sc.analyst_title,''))!=''")
    elif title_filter == "Generated only":
        where.append("trim(COALESCE(sc.analyst_title,''))=''")
    if age_filter == "New 24h":
        where.append("COALESCE(sc.updated_at,sc.first_seen,'')>=datetime('now','-1 day')")
    elif age_filter == "Last 7 days":
        where.append("COALESCE(sc.updated_at,sc.first_seen,'')>=datetime('now','-7 days')")
    elif age_filter == "Older than 7 days":
        where.append("COALESCE(sc.updated_at,sc.first_seen,'')<datetime('now','-7 days')")
    if duplicates_only:
        where.append("EXISTS(SELECT 1 FROM possible_site_card_matches pm WHERE pm.candidate_site_card_id=sc.id AND pm.status='pending')")
    priority_sql = {
        "Urgent": "COALESCE(sc.urgent_flag,0)=1 AND sc.review_status IN ('needs_review','needs_report','restricted')",
        "Spain Priority": "sc.spain_priority=1",
        "All Spain-linked": "sc.spain_priority=1",
        "Sending from Spain": "sc.spain_priority=1 AND sc.spain_context_tags LIKE '%trade_flow_from_spain%'",
        "Sending to Spain": "sc.spain_priority=1 AND sc.spain_context_tags LIKE '%trade_flow_to_spain%'",
        "Spain + weapons": "sc.spain_priority=1 AND sc.primary_category IN ('weapons_arms','marketplace_weapons')",
        "Spain + drugs": "sc.spain_priority=1 AND sc.primary_category IN ('drugs','marketplace_drugs')",
        "Spain + carding/fraud": "sc.spain_priority=1 AND sc.primary_category IN ('fraud_financial','marketplace_fraud')",
        "Spain + Russian context": "sc.spain_context_tags LIKE '%russian_geopolitical_context%'",
        "Marketplaces": "sc.primary_category LIKE 'marketplace%'",
        "Leaks / credentials": "sc.primary_category IN ('leaks_data','credentials','marketplace_leaks','marketplace_credentials')",
        "Weapons / drugs": "sc.primary_category IN ('weapons_arms','drugs','marketplace_weapons','marketplace_drugs')",
        "Forums / directories": "sc.primary_category IN ('forum_social','directory_index','search_engine')",
        "High risk": "lower(COALESCE(sc.risk_level,'low')) IN ('high','critical','alto','critico')",
        "High importance": "lower(COALESCE(sc.importance_level,'normal'))='high'",
        "Elevated importance": "lower(COALESCE(sc.importance_level,'normal')) IN ('elevated','high')",
        "Dead / unavailable": "(COALESCE(sc.live_url_count,0)=0 OR COALESCE(sc.dead_url_count,0)>0)",
        "Needs review": "sc.review_status IN ('needs_review','needs_report','restricted')",
    }
    if priority_filter in priority_sql:
        where.append(priority_sql[priority_filter])
    if operational_filter in {"Queued", "Crawled", "Retry"}:
        where.append("EXISTS(SELECT 1 FROM site_card_urls x WHERE x.site_card_id=sc.id AND x.status=?)")
        params.append(operational_filter.casefold())
    elif operational_filter == "Live": where.append("sc.live_url_count>0")
    elif operational_filter == "Dead": where.append("sc.liveness_status='hard_dead'")
    elif operational_filter == "Soft dead": where.append("sc.liveness_status='soft_dead'")
    elif operational_filter == "Monitor only": where.append("sc.review_status='monitor'")
    if search:
        where.append("(lower(COALESCE(sc.search_text,'')) LIKE ? OR lower(COALESCE(sc.analyst_title,'')) LIKE ?)")
        needle = f"%{search.casefold()[:200]}%"
        params.extend([needle, needle])
    order = {
        "urgent": "COALESCE(sc.urgent_flag,0) DESC,COALESCE(sc.urgent_score,0) DESC,sc.updated_at DESC",
        "needs_review": "sc.review_score DESC,sc.ui_priority DESC,sc.updated_at DESC",
        "spain": "sc.spain_priority DESC,sc.review_score DESC,sc.updated_at DESC",
        "risk": "CASE lower(sc.risk_level) WHEN 'critical' THEN 4 WHEN 'critico' THEN 4 WHEN 'high' THEN 3 WHEN 'alto' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC,sc.review_score DESC",
        "newest": "sc.first_seen DESC", "category": "sc.primary_category,sc.updated_at DESC",
        "seen": "sc.seen_count DESC", "sources": "sc.source_count DESC",
        "checked": "sc.last_checked_at DESC",
        "importance": "CASE lower(COALESCE(sc.importance_level,'normal')) WHEN 'high' THEN 3 WHEN 'elevated' THEN 2 ELSE 1 END DESC,sc.review_score DESC,sc.updated_at DESC",
    }.get(sort, "sc.review_score DESC,sc.ui_priority DESC,sc.updated_at DESC")
    where_sql = "WHERE " + " AND ".join(where) if where else ""
    limit = max(1, min(int(limit), 500)); offset = max(0, int(offset))
    with storage.get_db() as db:
        return [dict(row) for row in db.execute(f"""SELECT sc.*,
          (SELECT scu.onion_host FROM site_card_urls scu WHERE scu.site_card_id=sc.id
           AND scu.url_role!='restricted' ORDER BY CASE scu.url_role WHEN 'canonical' THEN 0 WHEN 'mirror' THEN 1 ELSE 2 END,
           scu.active DESC,scu.first_seen LIMIT 1) AS representative_host,
          (SELECT scu.url FROM site_card_urls scu WHERE scu.site_card_id=sc.id
           AND scu.url_role!='restricted' ORDER BY CASE scu.url_role WHEN 'canonical' THEN 0 WHEN 'mirror' THEN 1 ELSE 2 END,
           scu.active DESC,scu.first_seen LIMIT 1) AS representative_url,
          (SELECT COUNT(*) FROM spain_hits sh WHERE sh.site_card_id=sc.id
           AND sh.primary_category!='severe_abuse_risk') AS spain_hit_count,
          COUNT(*) OVER() AS total_count
          FROM site_cards sc {where_sql} ORDER BY {order} LIMIT ? OFFSET ?""", (*params, limit, offset))]


def get_site_card_category_counts(*, include_hidden: bool = False, review_only: bool = False) -> dict[str, int]:
    where = ["primary_category!='severe_abuse_risk'"]
    if not include_hidden:
        where += ["COALESCE(ui_hidden_default,0)=0",
                  "primary_category NOT IN ('adult_filtered','adult_restricted')"]
    if review_only:
        where += ["review_status IN ('needs_review','needs_report','restricted')", "live_url_count>0"]
    clause = "WHERE " + " AND ".join(where) if where else ""
    with storage.get_db() as db:
        return {str(row[0] or "unknown"): int(row[1]) for row in db.execute(
            f"SELECT primary_category,COUNT(*) FROM site_cards {clause} GROUP BY primary_category")}


def get_site_cards(spain_only: bool = False, limit: int = 500) -> list[dict]:
    conditions = ["primary_category!='severe_abuse_risk'"]
    if spain_only:
        conditions.append("spain_priority=1")
    where = "WHERE " + " AND ".join(conditions)
    with storage.get_db() as db:
        return [dict(row) for row in db.execute(f"""SELECT * FROM site_cards {where}
          ORDER BY spain_priority DESC,priority_score DESC,updated_at DESC LIMIT ?""", (limit,))]


def get_site_card_detail(site_card_id: int, url_limit: int = 50, event_limit: int = 10,
                         include_dead: bool = False, include_restricted: bool = False) -> dict | None:
    with storage.get_db() as db:
        row = db.execute("SELECT * FROM site_cards WHERE id=?", (site_card_id,)).fetchone()
        if not row:
            return None
        if is_severe_blackhole_policy(row):
            return None
        result = dict(row)
        result["reports"] = storage.get_site_card_reports(site_card_id, 20)
        generated_at = result.get("report_generated_at") or (
            result["reports"][0].get("ts") if result["reports"] else None)
        if result.get("report_status") == "failed":
            result["report_state"] = "report_failed"
        elif not result["reports"]:
            result["report_state"] = "no_report"
        elif generated_at and str(result.get("updated_at") or "") > str(generated_at):
            result["report_state"] = "report_stale"
        else:
            result["report_state"] = "report_ready"
        result["spain_hit_count"] = int(db.execute(
            "SELECT COUNT(*) FROM spain_hits WHERE site_card_id=? AND primary_category!='severe_abuse_risk'",
            (site_card_id,)).fetchone()[0])
        result["spain_hits"] = [dict(item) for item in db.execute("""SELECT hit_type,canonical_url,
          primary_category,risk_level,spain_reason,spain_confidence,first_seen,last_seen,metadata_only
          FROM spain_hits WHERE site_card_id=? AND primary_category!='severe_abuse_risk'
          ORDER BY CASE hit_type WHEN 'thread' THEN 1 WHEN 'post' THEN 2
          ELSE 3 END,last_seen DESC LIMIT 25""", (site_card_id,))]
        filters = ["scu.site_card_id=?"]
        params: list = [site_card_id]
        if not include_dead: filters.append("COALESCE(scu.status,'') NOT IN ('dead','soft_dead')")
        filters.append("ou.primary_category!='severe_abuse_risk'")
        if not include_restricted: filters.append("ou.primary_category NOT IN ('adult_filtered','adult_restricted')")
        result["urls"] = [dict(item) for item in db.execute(f"""SELECT scu.*,ou.primary_category,ou.tags,
          ou.risk_level,ou.storage_policy,ou.review_status,ou.spain_priority,ou.spain_match_reason,
          ou.safety_reason,ou.queue_policy,ou.screenshot_policy FROM site_card_urls scu
          JOIN onion_urls ou ON ou.id=scu.onion_url_id WHERE {' AND '.join(filters)}
          ORDER BY CASE scu.url_role WHEN 'canonical' THEN 0 WHEN 'mirror' THEN 1 WHEN 'path' THEN 2
          WHEN 'restricted' THEN 3 ELSE 4 END,scu.active DESC,scu.first_seen LIMIT ?""",
          (*params, max(1, min(url_limit, 500))))]
        result["events"] = [dict(item) for item in db.execute(
            "SELECT * FROM site_card_events WHERE site_card_id=? ORDER BY id DESC LIMIT ?",
            (site_card_id, max(0, min(event_limit, 100))))]
        result["sources"] = [dict(item) for item in db.execute("""SELECT s.source_url,s.source_type,
          MIN(s.first_seen) AS first_seen,MAX(s.last_seen) AS last_seen,SUM(s.seen_count) AS seen_count
          FROM onion_url_sources s JOIN onion_urls ou ON ou.id=s.onion_url_id
          WHERE ou.site_card_id=? AND trim(COALESCE(s.source_url,''))!=''
          GROUP BY s.source_url,s.source_type ORDER BY last_seen DESC LIMIT 100""", (site_card_id,))]
        result["fingerprints"] = [dict(item) for item in db.execute("""SELECT sf.fingerprint_type,
          sf.fingerprint_value,sf.confidence,sf.created_at FROM site_fingerprints sf
          JOIN onion_urls ou ON ou.id=sf.onion_url_id
          WHERE sf.site_card_id=? AND ou.primary_category!='severe_abuse_risk'
          ORDER BY sf.id DESC LIMIT 100""", (site_card_id,))]
        result["duplicate_candidate_count"] = int(db.execute("""SELECT COUNT(*)
          FROM possible_site_card_matches WHERE candidate_site_card_id=? AND status='pending'""",
          (site_card_id,)).fetchone()[0])
        return result


def get_site_card(site_card_id: int) -> dict | None:
    """Backward-compatible bounded detail accessor for maintenance/tests."""
    return get_site_card_detail(site_card_id, url_limit=100, event_limit=100,
                                include_dead=True, include_restricted=True)


def review_possible_match(match_id: int, decision: str) -> int | None:
    if decision not in {"confirm", "not_same", "ignore"}:
        raise ValueError("Invalid possible-mirror decision")
    baseline = None
    feedback_data = None
    with storage.get_db() as db:
        row = db.execute("SELECT * FROM possible_site_card_matches WHERE id=?", (match_id,)).fetchone()
        if not row:
            raise ValueError("Possible match not found")
        candidate = db.execute("SELECT * FROM site_cards WHERE id=?",
                               (row["candidate_site_card_id"],)).fetchone()
        source_policy = db.execute("SELECT * FROM onion_urls WHERE id=?",
                                   (row["onion_url_id"],)).fetchone()
        if _severe_blackhole(candidate, source_policy):
            db.execute("UPDATE possible_site_card_matches SET status='ignored',updated_at=? WHERE id=?",
                       (storage.utc_now_iso(), match_id))
            return None
        db.execute("UPDATE possible_site_card_matches SET status=?,updated_at=? WHERE id=?",
                   ({"confirm":"confirmed", "not_same":"not_same", "ignore":"ignored"}[decision], storage.utc_now_iso(), match_id))
        source = db.execute("SELECT site_card_id FROM onion_urls WHERE id=?", (row["onion_url_id"],)).fetchone()
        feedback_data = {
            "onion_url_id": int(row["onion_url_id"]),
            "candidate_site_card_id": int(row["candidate_site_card_id"]),
            "source_site_card_id": int(source[0]) if source and source[0] else None,
            "confidence": row["confidence"],
        }
    baseline = _latest_page_decision(onion_url_id=feedback_data["onion_url_id"])
    _record_feedback_safely(
        subject=f"possible-match:{match_id}",
        feedback_scope="mirror",
        feedback_action={
            "confirm": "mirror_confirmed",
            "not_same": "mirror_not_same",
            "ignore": "mirror_ignored",
        }[decision],
        reason_code="analyst_possible_match_review",
        decision_id=baseline.get("id") if baseline else None,
        onion_url_id=feedback_data["onion_url_id"],
        site_card_id=feedback_data["source_site_card_id"],
        previous_category=baseline.get("final_category") if baseline else None,
        final_category=baseline.get("final_category") if baseline else None,
        classifier_version=baseline.get("classifier_version") if baseline else None,
        safe_metadata={
            "scope": "possible_match",
            "match_confidence": feedback_data["confidence"],
            "confirmed": decision == "confirm",
        },
    )
    if decision == "confirm" and source and source[0] and int(source[0]) != int(row["candidate_site_card_id"]):
        return merge_site_cards(int(source[0]), int(row["candidate_site_card_id"]))
    return None


def backfill_existing_urls() -> dict:
    storage.init_db()
    with storage.get_db() as db:
        rows = [dict(row) for row in db.execute("SELECT * FROM onion_urls ORDER BY first_seen,id")]
    assigned = created_before = 0
    for row in rows:
        if _severe_blackhole(row):
            _enforce_severe_url(row, row)
            continue
        if _adult_filtered(row):
            storage.cleanup_adult_filtered_items(row["url"])
            continue
        if row.get("primary_category") in {"unknown", "general_other"} and not row.get("spain_priority"):
            continue
        if row.get("site_card_id"):
            created_before += 1
        policy = dict(row)
        policy.setdefault("tags", _loads(row.get("tags")))
        policy.setdefault("risk_flags", _loads(row.get("risk_flags")))
        ensure_url_site_card(int(row["id"]), policy, title=None if row.get("storage_policy") == "metadata_only" else row.get("title"),
                             source_context=row.get("source_url"))
        assigned += 1
    return {"processed": len(rows), "assigned": assigned, "already_assigned": created_before,
            "cards": len(get_site_cards(limit=100000))}


def refresh_site_card_stats(safety_batch: int = 10, missing_limit: int = 100,
                            dirty_limit: int = 250) -> dict:
    """Assign missing URLs and refresh only dirty cards plus a bounded safety batch."""
    storage.init_db()
    with storage.get_db() as db:
        missing = [dict(row) for row in db.execute("""SELECT * FROM onion_urls
          WHERE site_card_id IS NULL AND storage_policy!='discard' AND primary_category NOT IN
          ('adult_filtered','severe_abuse_risk','unknown','general_other') AND verification_state='verified'
          ORDER BY first_seen,id LIMIT ?""", (max(1, min(missing_limit, 500)),))]
        card_ids = []
    for row in missing:
        policy = dict(row)
        policy.setdefault("tags", _loads(row.get("tags")))
        policy.setdefault("risk_flags", _loads(row.get("risk_flags")))
        ensure_url_site_card(int(row["id"]), policy,
                             title=None if row.get("storage_policy") == "metadata_only" else row.get("title"),
                             source_context=row.get("source_url"))
    with storage.get_db() as db:
        dirty = [int(row[0]) for row in db.execute(
            "SELECT id FROM site_cards WHERE rollup_dirty=1 ORDER BY updated_at LIMIT ?",
            (max(1, min(dirty_limit, 1000)),))]
        safety = [int(row[0]) for row in db.execute(
            "SELECT id FROM site_cards WHERE rollup_dirty=0 ORDER BY updated_at LIMIT ?", (max(0, safety_batch),))]
        card_ids = list(dict.fromkeys(dirty + safety))
    for card_id in card_ids:
        update_site_card_rollups(card_id)
    return {"assigned": len(missing), "refreshed": len(card_ids), "dirty": len(dirty)}


def refresh_dirty_site_cards(limit: int = 1000) -> dict:
    storage.init_db()
    with storage.get_db() as db:
        card_ids = [int(row[0]) for row in db.execute(
            "SELECT id FROM site_cards WHERE rollup_dirty=1 ORDER BY updated_at LIMIT ?", (max(1, limit),))]
    for card_id in card_ids:
        update_site_card_rollups(card_id)
    return {"refreshed": len(card_ids)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Passive Site Card deduplication")
    parser.add_argument("--backfill", action="store_true", required=True)
    args = parser.parse_args()
    if args.backfill:
        print(json.dumps(backfill_existing_urls(), ensure_ascii=False))


if __name__ == "__main__":
    main()
