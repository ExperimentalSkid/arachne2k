import sqlite3

import onion_worker
import storage
from universal_classifier import classify


LEGACY_ONION_URLS = """
CREATE TABLE onion_urls (
 id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE, onion_domain TEXT,
 source_url TEXT, source_type TEXT, depth INTEGER DEFAULT 0, first_seen TEXT NOT NULL,
 last_seen TEXT, last_crawled TEXT, next_crawl_at TEXT, status TEXT DEFAULT 'new',
 http_status INTEGER, title TEXT, content_hash TEXT, fuzzy_hash TEXT,
 relevance_score INTEGER DEFAULT 0, risk_score INTEGER DEFAULT 0,
 risk_level TEXT DEFAULT 'NULO', reasons TEXT, risk_flags TEXT,
 review_status TEXT DEFAULT 'pending', error_count INTEGER DEFAULT 0, last_error TEXT
)
"""


def _persist_verified_spain(url):
    html = """<html><head><title>Weapons vendor shipping to Spain</title></head>
    <body><h1>Weapons vendor shipping to Spain</h1><p>Vendor order and weapons
    shipping to Spain via Correos and Bizum with DNI checks and Madrid delivery.</p></body></html>"""
    title, meta, visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = onion_worker._classify_fetched_page(
        url, title=title, meta=meta, visible_text=visible,
        source_url=None, source_context=None, page_structure=structure)
    policy.update(
        spain_priority=True, spain_confidence="high", spain_match_language="ES",
        spain_match_reason="Spain reference paired with threat-related context",
        spain_context_tags=["threat_context", "trade_flow_to_spain"],
        spain_actionable=True, spain_relevance="high", spain_evidence_score=95,
        spain_context_only=False,
    )
    policy = onion_worker.finalize_page_policy(
        url, policy, title=title, page_structure=structure)
    storage.insert_or_update_onion_url(url, status="crawled")
    storage.apply_onion_policy(
        url, policy, 200, checked=True, page_structure=structure)
    return policy


def test_legacy_schema_migrates_twice_without_losing_state(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as db:
        db.execute(LEGACY_ONION_URLS)
    monkeypatch.setattr(storage, "DB_PATH", db_path)
    storage.init_db()
    url = "http://" + "m" * 56 + ".onion/"
    _persist_verified_spain(url)
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET review_status='relevant' WHERE url=?", (url,))

    storage.init_db()
    storage.init_db()
    row = storage.get_onion_url_by_url(url)
    assert row["spain_priority"] == 1
    assert row["spain_confidence"] == "high"
    assert row["review_status"] == "relevant"
    with storage.get_db() as db:
        columns = {item[1] for item in db.execute("PRAGMA table_info(onion_urls)")}
    assert {"site_card_id", "spain_context_tags", "ocr_safe_signal_labels"}.issubset(columns)


def test_non_spain_reclassification_preserves_spain_and_analyst_review(isolated_db):
    url = "http://" + "n" * 56 + ".onion/"
    _persist_verified_spain(url)
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET review_status='reported' WHERE url=?", (url,))
    # An unverified later guess cannot erase destination-HTML evidence.
    storage.apply_onion_policy(url, classify(url, title="ordinary page"))
    row = storage.get_onion_url_by_url(url)
    assert row["spain_priority"] == 1
    assert row["review_status"] == "reported"

