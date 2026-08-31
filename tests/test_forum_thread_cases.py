from pathlib import Path

from streamlit.testing.v1 import AppTest

import onion_worker
from page_intelligence import fingerprint_page_type
import site_dedupe
import storage


ROOT = Path(__file__).parents[1]
HOST = "f" * 56 + ".onion"


def _destination_policy(url, *, title, body, markup):
    document = (
        f"<html><head><title>{title}</title></head>"
        f"<body class='{markup}'><h1>{title}</h1><div>{body}</div></body></html>"
    )
    parsed_title, meta, visible_text, _links, structure = onion_worker._parse(
        document.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = onion_worker._classify_fetched_page(
        url, title=parsed_title, meta=meta, visible_text=visible_text,
        source_url=None, source_context=None, page_structure=structure)
    page_type = fingerprint_page_type(
        url, structure, current_type=str(policy.get("page_type") or "unknown"),
        allow_url_hints=False)
    if page_type["page_type_confidence"] in {"medium", "high"}:
        policy["page_type"] = page_type["page_type"]
    policy.update(
        page_type_confidence=page_type["page_type_confidence"],
        page_type_evidence=page_type["evidence"], card_ready=1,
        card_readiness_reason="classified_meaningful_page",
        card_readiness_confidence="high")
    policy = onion_worker.finalize_page_policy(
        url, policy, title=parsed_title, page_structure=structure)
    return policy, parsed_title, visible_text, structure


def _store_destination(url, *, title, body, markup):
    policy, parsed_title, visible_text, structure = _destination_policy(
        url, title=title, body=body, markup=markup)
    url_id = storage.insert_or_update_onion_url(
        url, HOST, status="crawled")
    stored_url = storage.get_onion_url_by_url(url)["url"]
    storage.apply_onion_policy(
        stored_url, policy, 200, checked=True, page_structure=structure)
    card_id = site_dedupe.ensure_url_site_card(
        url_id, policy, title=parsed_title, visible_text=visible_text)
    return url_id, card_id, policy


def test_important_forum_thread_becomes_own_case_card_and_parent_stays_forum(isolated_db):
    parent_url = f"http://{HOST}/forum/"
    _parent_id, parent_card_id, _parent_policy = _store_destination(
        parent_url, title="Example Forum",
        body="General discussion forum board index with news and community topics.",
        markup="phpbb forumlist topiclist")

    thread_url = f"http://{HOST}/thread/123-spain-shipping"
    thread_id, thread_card_id, thread_policy = _store_destination(
        thread_url, title="Shipping to Spain thread",
        body=("Firearms and weapons for sale by vendor. Direct order and escrow. "
              "Shipping to Spain via Correos. Payment with Bizum. "
              "Delivery in Madrid and Sevilla. DNI required."),
        markup="phpbb postbody postprofile")

    assert thread_card_id != parent_card_id
    with storage.get_db() as db:
        parent = dict(db.execute("SELECT * FROM site_cards WHERE id=?", (parent_card_id,)).fetchone())
        case = dict(db.execute("SELECT * FROM site_cards WHERE id=?", (thread_card_id,)).fetchone())
        thread_row = dict(db.execute("SELECT site_card_id FROM onion_urls WHERE id=?", (thread_id,)).fetchone())

    assert parent["primary_category"] == "forum_social"
    assert parent["card_kind"] in {None, "site"}
    assert case["card_kind"] == "forum_thread_case"
    assert case["parent_site_card_id"] == parent_card_id
    assert case["page_type"] == "forum_thread"
    assert case["spain_priority"] == 1
    assert thread_row["site_card_id"] == thread_card_id


def test_generic_forum_thread_stays_on_parent_forum_card(isolated_db):
    parent_url = f"http://{HOST}/"
    _parent_id, parent_card_id, _parent_policy = _store_destination(
        parent_url, title="Calm Forum",
        body="General discussion forum board index with community topics and news.",
        markup="phpbb forumlist topiclist")

    thread_url = f"http://{HOST}/thread/normal-chat"
    _thread_id, thread_card_id, _policy = _store_destination(
        thread_url, title="Normal discussion",
        body="Community members discuss ordinary news, books, hobbies, and general topics.",
        markup="phpbb postbody postprofile")

    assert thread_card_id == parent_card_id


def test_forum_thread_case_dedupes_by_thread_url_identity(isolated_db):
    body = ("Firearms and weapons for sale by vendor. Direct order and escrow. "
            "Shipping to Spain with Correos and Bizum payment in Madrid and Sevilla. DNI required.")
    _first_id, first_card, _first_policy = _store_destination(
        f"http://{HOST}/thread/999?utm_source=x", title="Spain thread",
        body=body, markup="phpbb postbody postprofile")
    _second_id, second_card, _second_policy = _store_destination(
        f"http://{HOST}/thread/999", title="Spain thread",
        body=body, markup="phpbb postbody postprofile")

    assert first_card == second_card
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM site_cards WHERE card_kind='forum_thread_case'").fetchone()[0] == 1


def test_spain_forum_thread_case_visible_in_results_and_alert_queue(isolated_db):
    url = f"http://{HOST}/thread/777"
    _url_id, card_id, policy = _store_destination(
        url, title="Spain weapons forum thread",
        body=("Firearms and weapons for sale by vendor. Direct order and escrow. "
              "Shipping to Spain via Correos, paid with Bizum, delivery in Madrid and Sevilla. "
              "DNI required."),
        markup="phpbb postbody postprofile")
    assert storage.queue_spain_alert(url, policy)

    with storage.get_db() as db:
        alert = dict(db.execute("SELECT * FROM spain_alert_queue WHERE url=?", (url,)).fetchone())
    assert alert["site_card_id"] == card_id

    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value("Site Cards").run()
    assert not app.exception
    next(item for item in app.radio if item.label == "Display").set_value("Card view").run()
    labels = " ".join(str(button.label) for button in app.button)
    assert "FORUM THREAD" in labels
    assert "SPAIN FLAG" not in labels
    assert any(str(button.key).startswith("directory-card-forum-case-spain-")
               for button in app.button)
