import json

import onion_worker
import site_dedupe
import storage


HOST = "q" * 56 + ".onion"
URL = f"http://{HOST}/"


def _policy():
    return {
        "primary_category": "weapons_arms",
        "category": "weapons_arms",
        "risk_level": "high",
        "confidence": "high",
        "risk_flags": ["weapons"],
        "storage_policy": "metadata_limited",
        "review_status": "needs_report",
        "priority_score": 90,
        "active": 1,
        "spain_priority": True,
        "spain_confidence": "high",
        "spain_match_reason": "Spain evidence",
        "spain_actionable": True,
        "spain_relevance": "high",
        "seller_geo_confidence": "high",
        "urgent_flag": True,
        "urgent_score": 90,
        "urgent_reason": "manual test urgent evidence",
    }


def _persist_verified(policy):
    html = """<html><head><title>Spain weapons vendor</title></head><body>
    <h1>Spain weapons vendor</h1><p>Weapons order and shipping to Spain via
    Correos and Bizum with DNI checks and Madrid delivery.</p></body></html>"""
    title, _meta, _visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", URL)
    verified = onion_worker.finalize_page_policy(
        URL, dict(policy), title=title, page_structure=structure)
    url_id = storage.insert_or_update_onion_url(URL, HOST, status="crawled")
    storage.apply_onion_policy(
        URL, verified, 200, checked=True, page_structure=structure)
    return url_id, verified


def test_manual_spain_pull_works_while_push_alerts_paused(isolated_db):
    url_id, policy = _persist_verified(_policy())
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Spain test card")
    payload = {
        "url": URL,
        "site_card_id": card_id,
        "category": "weapons_arms",
        "risk_level": "high",
        "reason": "Spain evidence",
    }
    with storage.get_db() as db:
        db.execute("""INSERT INTO spain_alert_queue
          (url,fingerprint,payload_json,created_at,site_card_id,status)
          VALUES(?,?,?,?,?,'pending')""",
          (URL, "quiet-test", json.dumps(payload), storage.utc_now_iso(), card_id))

    storage.set_spain_alerts_paused(True, "pytest")

    assert storage.get_pending_spain_alerts() == []
    pulled = storage.get_spain_alerts_for_manual_pull()
    assert len(pulled) == 1
    assert pulled[0]["status"] == "pending"
    with storage.get_db() as db:
        assert db.execute("SELECT sent_at FROM spain_alert_queue WHERE fingerprint='quiet-test'").fetchone()[0] is None


def test_manual_urgent_pull_returns_safe_card_summary(isolated_db):
    url_id, policy = _persist_verified(_policy())
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Spain test card")

    cards = storage.get_urgent_cards_for_manual_pull()

    assert [card["id"] for card in cards] == [card_id]
    assert cards[0]["representative_url"] == URL
