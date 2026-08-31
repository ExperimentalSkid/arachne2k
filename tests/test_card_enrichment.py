import json

import onion_worker
import site_dedupe
import storage


HOST = "b" * 56 + ".onion"
ROOT = f"http://{HOST}/"


def _policy(category="directory_index"):
    return {
        "primary_category": category,
        "category": category,
        "content_category": category,
        "analyst_category": category,
        "classification_evidence_source": "analyst",
        "tags": [category],
        "risk_level": "low",
        "confidence": "medium",
        "risk_flags": [],
        "storage_policy": "safe_summary",
        "review_status": "monitor",
        "safety_reason": "test",
        "priority_score": 10,
        "screenshot_policy": "allowed",
        "queue_policy": "expand",
        "active": 1,
        "spain_priority": False,
        "card_ready": 1,
        "safe_display_name": "Weak Directory",
        "page_type": "homepage",
        "page_type_confidence": "medium",
        "category_confidence": "medium",
    }


def _insert_analyst_url(url, host, policy, **kwargs):
    url_id = storage.insert_or_update_onion_url(url, host, **kwargs)
    with storage.get_db() as db:
        stored_url = db.execute("SELECT url FROM onion_urls WHERE id=?", (url_id,)).fetchone()[0]
        db.execute("UPDATE onion_urls SET analyst_category=? WHERE id=?",
                   (policy["analyst_category"], url_id))
    storage.apply_onion_policy(stored_url, policy)
    return url_id


def _card(policy=None):
    policy = policy or _policy()
    url_id = _insert_analyst_url(ROOT, HOST, policy, status="crawled")
    return site_dedupe.ensure_url_site_card(url_id, policy, title="Weak Directory")


def _urls():
    with storage.get_db() as db:
        return [dict(row) for row in db.execute("SELECT url,source_type,source_url,status FROM onion_urls ORDER BY url")]


def test_card_enrichment_never_queues_login_cart_account_payment_paths(isolated_db):
    card_id = _card()
    for path, anchor in [
        ("/login/about", "about"),
        ("/cart/faq", "faq"),
        ("/account/contact", "contact"),
        ("/payment/terms", "terms"),
        ("/upload/pgp", "pgp"),
        ("/submit/rules", "rules"),
    ]:
        storage.insert_onion_edge(ROOT, f"http://{HOST}{path}",
                                  {"safe_anchor_text": anchor, "same_host": 1})

    result = onion_worker.plan_card_enrichment(card_id)

    assert result["queued"] > 0
    queued = [row["url"] for row in _urls() if row["source_type"] == "card_enrichment"]
    assert queued
    assert not any(marker in url for url in queued for marker in
                   ("/login", "/cart", "/account", "/payment", "/upload", "/submit"))


def test_card_enrichment_respects_restricted_card_policy(isolated_db):
    card_id = _card()
    with storage.get_db() as db:
        db.execute("""UPDATE site_cards SET primary_category='adult_filtered',
          storage_policy='discard',ui_hidden_default=1 WHERE id=?""", (card_id,))

    result = onion_worker.plan_card_enrichment(card_id)

    assert result == {"queued": 0, "skipped": 0, "reason": "restricted_card"}
    assert [row for row in _urls() if row["source_type"] == "card_enrichment"] == []


def test_card_enrichment_is_capped_per_card(isolated_db, monkeypatch):
    card_id = _card()
    monkeypatch.setattr(onion_worker, "get_int", lambda key, default=0: 3 if key == "ONION_CARD_ENRICHMENT_MAX_URLS" else default)

    result = onion_worker.plan_card_enrichment(card_id)

    assert result["queued"] == 3
    assert len([row for row in _urls() if row["source_type"] == "card_enrichment"]) == 3


def test_card_enrichment_does_not_duplicate_known_urls(isolated_db, monkeypatch):
    card_id = _card()
    about = f"http://{HOST}/about"
    storage.insert_or_update_onion_url(about, HOST, source_url=ROOT, source_type="manual",
                                       status="queued", policy=_policy())
    monkeypatch.setattr(onion_worker, "get_int", lambda key, default=0: 5 if key == "ONION_CARD_ENRICHMENT_MAX_URLS" else default)

    onion_worker.plan_card_enrichment(card_id)

    rows = _urls()
    assert sum(1 for row in rows if row["url"] == about) == 1
    assert not any(row["url"] == about and row["source_type"] == "card_enrichment" for row in rows)


def test_card_enrichment_records_evidence_without_resetting_analyst_state(isolated_db):
    card_id = _card()
    with storage.get_db() as db:
        db.execute("""UPDATE site_cards SET analyst_category='hosting_services',
          review_status='relevant',analyst_notes='keep this note',analyst_title='Clean title'
          WHERE id=?""", (card_id,))

    site_dedupe.update_site_card_rollups(card_id)
    onion_worker.plan_card_enrichment(card_id)

    with storage.get_db() as db:
        card = dict(db.execute("""SELECT analyst_category,review_status,analyst_notes,
          analyst_title,card_completeness_label FROM site_cards WHERE id=?""", (card_id,)).fetchone())
        event = db.execute("""SELECT safe_metadata_json FROM site_card_events
          WHERE site_card_id=? AND event_type='card_enrichment_planned'
          ORDER BY id DESC LIMIT 1""", (card_id,)).fetchone()
    assert card["analyst_category"] == "hosting_services"
    assert card["review_status"] == "relevant"
    assert card["analyst_notes"] == "keep this note"
    assert card["analyst_title"] == "Clean title"
    assert card["card_completeness_label"] in {"weak", "usable", "strong"}
    evidence = json.loads(event["safe_metadata_json"])
    assert evidence["queued"] >= 0
    assert all("path" in item and "reason" in item for item in evidence["planned"])
