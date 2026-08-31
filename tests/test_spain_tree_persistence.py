import json
from pathlib import Path

from streamlit.testing.v1 import AppTest

import onion_worker
import site_dedupe
import storage
from universal_classifier import classify


HOST = "s" * 56 + ".onion"


def _url(path):
    return f"http://{HOST}{path}"


def _policy(url, page_type="search_page"):
    policy = classify(url, title="weapons delivery to Spain", visible_text="weapons delivery to Spain Correos Bizum DNI Madrid")
    policy.update(primary_category="weapons_arms", risk_level="high", spain_priority=True,
                  spain_confidence="high", spain_match_language="ES",
                  spain_match_reason="Spain reference paired with threat-related context",
                  spain_context_tags=["threat_context", "trade_flow_to_spain", "spanish_payment_context", "spanish_identity_data"],
                  spain_actionable=True, seller_geo_confidence="high", spain_relevance="high",
                  spain_evidence_score=95, spain_context_only=False, page_type=page_type)
    return policy


def _persist_verified(url, policy):
    page_type = policy.get("page_type") or "unknown"
    structural_html = (
        "<article class='post'><span class='username'>VendorOne</span><p>Public post</p></article>"
        if page_type == "thread_page" else
        "<form><label>Search</label><input name='q'><button>Search</button></form>"
        if page_type == "search_page" else
        "<nav><a href='/about'>About</a></nav>"
    )
    html = f"""<html><head><title>Weapons delivery to Spain</title></head><body>
      <h1>Weapons delivery to Spain</h1>{structural_html}
      <p>Weapons delivery to Spain Correos Bizum DNI Madrid vendor order shipping.</p>
      </body></html>"""
    title, _meta, _visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    verified = onion_worker.finalize_page_policy(
        url, dict(policy), title=title, page_structure=structure)
    url_id = storage.insert_or_update_onion_url(url, status="crawled")
    storage.apply_onion_policy(
        url, verified, 200, checked=True, page_structure=structure)
    return url_id, verified


def test_phpbb_sid_variants_share_stable_families():
    a = storage.canonicalize_spain_hit(_url("/viewtopic.php?f=18&t=18453&sid=AAA"))
    b = storage.canonicalize_spain_hit(_url("/viewtopic.php?t=18453&sid=BBB"))
    assert a["normalized_family"] == b["normalized_family"] == "thread:t=18453"
    assert a["canonical_url"] == b["canonical_url"]
    forum_a = storage.canonicalize_spain_hit(_url("/viewforum.php?f=18&sid=A"))
    forum_b = storage.canonicalize_spain_hit(_url("/viewforum.php?f=18&sid=B"))
    assert forum_a["normalized_family"] == forum_b["normalized_family"] == "forum:f=18"


def test_spain_queue_persists_url_card_and_domain_tree(isolated_db):
    url = _url("/search.php?author_id=28171&sr=posts&sid=A")
    policy = _policy(url)
    url_id, stored_policy = _persist_verified(url, dict(policy, spain_priority=False))
    policy = dict(stored_policy, spain_priority=True)
    card_id = site_dedupe.ensure_url_site_card(url_id, stored_policy, title="Safe forum")
    assert storage.queue_spain_alert(url, policy)
    row = storage.get_onion_url_by_url(url)
    with storage.get_db() as db:
        card = dict(db.execute("SELECT * FROM site_cards WHERE id=?", (card_id,)).fetchone())
    assert row["spain_priority"] == card["spain_priority"] == 1
    assert row["spain_match_reason"] == card["spain_match_reason"] == policy["spain_match_reason"]
    trees = storage.get_spain_domain_trees()
    assert len(trees) == 1 and trees[0]["total_spain_hits"] == 1


def test_spain_tree_alerts_direct_hit_but_not_sid_repeat(isolated_db):
    search = _url("/search.php?author_id=28171&sr=posts&sid=A")
    search_id, search_policy = _persist_verified(search, _policy(search, "search_page"))
    assert storage.queue_spain_alert(search, search_policy)
    repeat = _url("/search.php?author_id=28171&sr=posts&sid=B")
    repeat_id = storage.insert_or_update_onion_url(repeat, status="crawled")
    assert repeat_id == search_id
    assert not storage.queue_spain_alert(search, search_policy)
    thread = _url("/viewtopic.php?f=18&t=18453&sid=C")
    _thread_id, thread_policy = _persist_verified(thread, _policy(thread, "thread_page"))
    assert storage.queue_spain_alert(thread, thread_policy)
    assert len(storage.get_pending_spain_alerts()) == 2
    assert len(storage.get_spain_domain_trees()) == 1


def test_later_non_spain_policy_does_not_clear_persisted_overlay(isolated_db):
    url = _url("/viewtopic.php?t=9")
    _url_id, policy = _persist_verified(url, _policy(url, "thread_page"))
    storage.queue_spain_alert(url, policy)
    storage.apply_onion_policy(url, classify(url, title="ordinary forum page"))
    row = storage.get_onion_url_by_url(url)
    assert row["spain_priority"] == 1
    assert row["spain_match_reason"] == policy["spain_match_reason"]


def test_repair_spain_queue_supports_dry_run_and_write(isolated_db):
    url = _url("/viewforum.php?f=2")
    analyst_forum = classify(url, title="forum")
    analyst_forum.update(
        primary_category="forum_social", category="forum_social",
        content_category="forum_social", analyst_category="forum_social",
        classification_evidence_source="analyst",
    )
    storage.insert_or_update_onion_url(
        url, status="crawled", policy=analyst_forum)
    payload = {"url": url, "category": "weapons_arms", "risk_level": "high", "confidence": "high",
               "reason": "Spain reference paired with threat-related context", "language": "ES",
               "contexts": ["threat_context"], "page_type": "category_page"}
    with storage.get_db() as db:
        db.execute("INSERT INTO spain_alert_queue(url,fingerprint,payload_json,created_at) VALUES(?,?,?,?)",
                   (url, "legacy", json.dumps(payload), storage.utc_now_iso()))
    assert storage.repair_spain_from_alert_queue(True)["onion_urls_updated"] == 1
    assert storage.get_onion_url_by_url(url)["spain_priority"] == 0
    assert storage.repair_spain_from_alert_queue(False)["onion_urls_updated"] == 1
    assert storage.get_onion_url_by_url(url)["spain_priority"] == 1
    assert storage.repair_spain_from_alert_queue(False)["onion_urls_updated"] == 1
    assert storage.get_onion_url_by_url(url)["spain_priority"] == 1


def test_spain_dashboard_groups_domain_tree_and_orphan(isolated_db):
    url = _url("/viewtopic.php?t=44")
    _url_id, policy = _persist_verified(url, _policy(url, "thread_page"))
    storage.queue_spain_alert(url, policy)
    app = AppTest.from_file(str(Path(__file__).parents[1] / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value("Spain Priority").run()
    assert not app.exception
    assert HOST in " ".join(item.value for item in app.markdown)


def test_analyst_suppression_removes_one_page_and_survives_future_classification(isolated_db):
    url = _url("/viewtopic.php?t=88&sid=FIRST")
    url_id, policy = _persist_verified(url, _policy(url, "thread_page"))
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Spain thread")
    assert storage.queue_spain_alert(url, policy)
    hit = storage.get_spain_tree_hits(storage.get_spain_domain_trees()[0]["site_tree_id"])[0]

    assert storage.suppress_spain_hit(hit["id"])

    row = storage.get_onion_url_by_url(url)
    card = site_dedupe.get_site_card(card_id)
    assert row["spain_priority"] == 0 and row["spain_analyst_suppressed"] == 1
    assert card["spain_priority"] == 0
    assert storage.get_spain_domain_trees() == []
    with storage.get_db() as db:
        stored_hit = dict(db.execute("SELECT * FROM spain_hits WHERE id=?", (hit["id"],)).fetchone())
        alert = dict(db.execute("SELECT * FROM spain_alert_queue WHERE url=?", (url,)).fetchone())
        event = db.execute("SELECT 1 FROM site_card_events WHERE site_card_id=? AND event_type='spain_priority_removed'",
                           (card_id,)).fetchone()
        quality = dict(db.execute("""SELECT feedback_scope,feedback_action,safe_metadata_json
          FROM classification_feedback_events WHERE site_card_id=? AND feedback_scope='spain'
          ORDER BY id DESC LIMIT 1""", (card_id,)).fetchone())
    assert stored_hit["analyst_suppressed"] == 1 and alert["status"] == "suppressed" and event
    assert quality["feedback_action"] == "spain_removed"
    assert url not in quality["safe_metadata_json"]

    storage.apply_onion_policy(url, policy)
    assert storage.get_onion_url_by_url(url)["spain_priority"] == 0
    assert not storage.queue_spain_alert(url, policy)

    variant = _url("/viewtopic.php?t=88&sid=SECOND")
    variant_id = storage.insert_or_update_onion_url(variant, status="crawled")
    assert variant_id == url_id
    assert not storage.queue_spain_alert(url, policy)
    assert storage.get_onion_url_by_url(variant)["spain_analyst_suppressed"] == 1


def test_spain_dashboard_requires_confirmation_before_removing_page(isolated_db):
    url = _url("/viewtopic.php?t=99")
    url_id, policy = _persist_verified(url, _policy(url, "thread_page"))
    site_dedupe.ensure_url_site_card(url_id, policy, title="Spain thread")
    storage.queue_spain_alert(url, policy)

    app = AppTest.from_file(str(Path(__file__).parents[1] / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value("Spain Priority").run()
    confirm = next(item for item in app.toggle if item.label == "Slide to confirm removal")
    remove = next(item for item in app.button if item.label == "Remove this page from Spain Priority")
    assert remove.disabled

    confirm.set_value(True).run()
    remove = next(item for item in app.button if item.label == "Remove this page from Spain Priority")
    assert not remove.disabled
    remove.click().run()
    assert not app.exception
    assert storage.get_spain_domain_trees() == []
