import json

import onion_worker
import site_dedupe
import storage


def _url(letter, path="/"):
    return f"http://{letter * 56}.onion{path}"


def _spain_policy(url, *, page_type="homepage"):
    structural_html = {
        "search_page": "<form><label>Search</label><input name='q'><button>Search</button></form>",
        "thread_page": "<article class='post'><span class='username'>VendorOne</span><p>Public post</p></article>",
    }.get(page_type, "<nav><a href='/about'>About</a></nav>")
    html = f"""<html><head><title>Spain weapons delivery</title></head><body>
      <h1>Spain weapons delivery</h1>{structural_html}
      <p>{'weapons shipment to Spain entrega en Espana Correos Bizum DNI Madrid ' * 10}</p>
      </body></html>"""
    title, meta, visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = onion_worker._classify_fetched_page(
        url, title=title, meta=meta, visible_text=visible,
        source_url=None, source_context=None, page_structure=structure)
    policy.update({
        "primary_category": "weapons_arms", "category": "weapons_arms",
        "content_category": "weapons_arms",
        "risk_level": "high",
        "spain_priority": True,
        "spain_confidence": "high",
        "spain_match_reason": "shipping to Spain",
        "spain_context_tags": ["shipping_to_spain", "spanish_payment_context", "spanish_identity_data"],
        "spain_actionable": True,
        "seller_geo_confidence": "high",
        "spain_relevance": "high",
        "spain_evidence_score": 95,
        "spain_context_only": False,
        "page_type": page_type,
    })
    policy = onion_worker.finalize_page_policy(
        url, policy, title=title, page_structure=structure)
    return policy, structure


def _persist_spain(url, *, page_type="homepage"):
    policy, structure = _spain_policy(url, page_type=page_type)
    url_id = storage.insert_or_update_onion_url(url, status="crawled")
    storage.apply_onion_policy(
        url, policy, 200, checked=True, page_structure=structure)
    return url_id, policy


def test_spain_alert_stages_ignore_boring_mirror_increment(isolated_db):
    url = _url("s")
    url_id, policy = _persist_spain(url)
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Spain weapons delivery")

    assert storage.queue_spain_alert(url, policy)
    assert not storage.queue_spain_alert(url, policy)

    with storage.get_db() as db:
        db.execute("UPDATE site_cards SET mirror_count=mirror_count+1 WHERE id=?", (card_id,))
    assert not storage.queue_spain_alert(url, policy)


def test_spain_alert_updates_when_page_improves_to_thread(isolated_db):
    url = _url("t", "/search")
    url_id, policy = _persist_spain(url, page_type="search_page")
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Spain weapons search")
    with storage.get_db() as db:
        db.execute("UPDATE site_cards SET page_type='search_page' WHERE id=?", (card_id,))
    assert storage.queue_spain_alert(url, policy)

    _same_url_id, thread_policy = _persist_spain(url, page_type="thread_page")
    with storage.get_db() as db:
        db.execute("UPDATE site_cards SET page_type='thread_page' WHERE id=?", (card_id,))
    assert storage.queue_spain_alert(url, thread_policy)

    alerts = storage.get_pending_spain_alerts()
    assert len(alerts) == 2
    latest = json.loads(alerts[-1]["payload_json"])
    assert latest["alert_kind"] == "updated"
    assert latest["page_type"] == "thread_page"
