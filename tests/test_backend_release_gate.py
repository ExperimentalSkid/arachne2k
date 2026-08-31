from datetime import datetime, timedelta, timezone

import onion_worker
import storage
from url_identity import canonicalize


HOST = "z" * 56 + ".onion"


def test_authoritative_identity_separates_root_page_and_query():
    root = canonicalize(f"https://{HOST}//#fragment")
    index = canonicalize(f"https://{HOST}/index.php?utm_source=x&ref=directory#top")
    page = canonicalize(f"http://{HOST}/forum//thread/?b=2&utm_source=x&a=1#post")
    assert root["canonical_url"] == root["canonical_root"] == f"http://{HOST}/"
    assert index["canonical_url"] == root["canonical_url"]
    assert page["canonical_root"] == root["canonical_root"]
    assert page["canonical_url"] == f"http://{HOST}/forum/thread?a=1&b=2"
    assert page["canonical_url"] != root["canonical_url"]
    assert page["onion_host"] == HOST
    assert page["path_signature"] and page["query_signature"] and page["entity_identity"]


def test_atomic_claim_prevents_second_worker_and_recovers_stale_claim(isolated_db):
    url = f"http://{HOST}/"
    storage.insert_or_update_onion_url(url, HOST, status="queued")
    first = storage.claim_next_onion_url(worker_id="boot-a")
    assert first and first["status"] == "claimed" and first["claimed_by"] == "boot-a"
    assert storage.claim_next_onion_url(worker_id="boot-b") is None
    stale = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET claimed_at=? WHERE id=?", (stale, first["id"]))
    recovered = storage.claim_next_onion_url(worker_id="boot-b", claim_timeout_minutes=45)
    assert recovered and recovered["id"] == first["id"] and recovered["claimed_by"] == "boot-b"


def test_error_releases_claim_and_persists_retry_backoff(isolated_db):
    url = f"http://{HOST}/retry"
    storage.insert_or_update_onion_url(url, HOST, status="queued")
    claimed = storage.claim_next_onion_url(worker_id="boot-a")
    storage.mark_url_fetching(claimed["id"], "boot-a")
    retry_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    storage.mark_onion_error(url, "timeout", retry_at)
    row = storage.get_onion_url_by_url(url)
    assert row["status"] == "retry" and row["retry_count"] == 1
    assert row["claimed_at"] is None and row["claimed_by"] is None
    assert row["next_retry_at"] == retry_at and row["last_fetch_status"] == "error"


def test_parser_caps_links_and_classification_text(monkeypatch):
    monkeypatch.setattr(onion_worker, "get_int", lambda name, default: {
        "ONION_MAX_EXTRACTED_LINKS": 50,
        "ONION_MAX_CLASSIFICATION_TEXT_CHARS": 10_000,
    }.get(name, default))
    links = "".join(f"<a href='/page/{index}'>link {index}</a>" for index in range(200))
    body = ("<html><title>Bounded</title><body>" + links + ("x" * 30_000) + "</body></html>").encode()
    _title, _meta, text, records, _structure = onion_worker._parse(body, "text/html", f"http://{HOST}/")
    assert len(records) <= 50
    assert len(text) <= 10_000
