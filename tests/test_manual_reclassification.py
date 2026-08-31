import json

import onion_worker
from page_intelligence import fingerprint_page_type
import site_dedupe
import storage
from dashboard_pages.workspace import _spain_unreviewed_count


HOST = "q" * 56 + ".onion"
URL = f"http://{HOST}/"


def _page_policy(url, *, title, body, markup="", overrides=None):
    document = (
        f"<html><head><title>{title}</title></head>"
        f"<body class='{markup}'><h1>{title}</h1>{body}</body></html>"
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
    if overrides:
        policy.update(overrides)
    return policy, parsed_title, visible_text, structure


def _store_page(url, *, title, body, markup="", overrides=None):
    policy, parsed_title, visible_text, structure = _page_policy(
        url, title=title, body=body, markup=markup, overrides=overrides)
    url_id = storage.insert_or_update_onion_url(url, HOST, status="crawled")
    storage.apply_onion_policy(
        url, policy, 200, checked=True, page_structure=structure)
    card_id = site_dedupe.ensure_url_site_card(
        url_id, policy, title=parsed_title, visible_text=visible_text)
    return url_id, card_id, policy, structure


def _directory_body():
    links = "".join(
        f"<li><a href='http://{letter * 56}.onion/'>Resource {letter}</a></li>"
        for letter in "abcdef")
    return f"<p>Onion directory index of independent resources.</p><ul>{links}</ul>"


def test_analyst_category_correction_is_audited_and_survives_reclassification(isolated_db):
    _url_id, card_id, _policy, _structure = _store_page(
        URL, title="Safe directory", body=_directory_body())

    site_dedupe.apply_manual_category(card_id, "fraud_financial")
    corrected = storage.get_onion_url_by_url(URL)
    assert corrected["primary_category"] == corrected["analyst_category"] == "fraud_financial"
    assert corrected["storage_policy"] == "metadata_limited"
    assert corrected["screenshot_policy"] == "blocked"

    replacement, _title, _text, replacement_structure = _page_policy(
        URL, title="Ordinary directory", body=_directory_body())
    storage.apply_onion_policy(
        URL, replacement, 200, checked=True, page_structure=replacement_structure)
    persisted = storage.get_onion_url_by_url(URL)
    assert persisted["primary_category"] == "fraud_financial"
    assert persisted["category_confidence"] == "analyst"
    with storage.get_db() as db:
        card = dict(db.execute("SELECT * FROM site_cards WHERE id=?", (card_id,)).fetchone())
        event = dict(db.execute("SELECT * FROM site_card_events WHERE site_card_id=? AND event_type='category_corrected'",
                                (card_id,)).fetchone())
        quality_events = [dict(row) for row in db.execute("""SELECT * FROM classification_feedback_events
          WHERE site_card_id=? AND feedback_scope='category'""", (card_id,))]
    assert card["analyst_category"] == "fraud_financial"
    assert event["event_summary"] == "Analyst corrected Site Card category"
    assert len(quality_events) == 1
    assert quality_events[0]["feedback_action"] == "category_corrected"


def test_analyst_can_correct_a_nonrestricted_card_back_to_directory(isolated_db):
    _url_id, card_id, _policy, _structure = _store_page(
        URL, title="Financial fraud",
        body="<p>Carding CVV fullz cashout offer with bank logs and stolen cards.</p>")

    site_dedupe.apply_manual_category(card_id, "directory_index")

    row = storage.get_onion_url_by_url(URL)
    card = site_dedupe.get_site_card(card_id)
    assert row["primary_category"] == card["primary_category"] == "directory_index"
    assert row["storage_policy"] == card["storage_policy"] == "safe_summary"
    assert row["queue_policy"] == "expand"


def test_new_page_on_corrected_site_card_inherits_analyst_category(isolated_db):
    _first_id, card_id, _first_policy, _first_structure = _store_page(
        URL, title="Directory", body=_directory_body())
    site_dedupe.apply_manual_category(card_id, "directory_index")

    child_url = f"http://{HOST}/thread/7"
    _child_id, inherited_card_id, _child_policy, _child_structure = _store_page(
        child_url, title="Thread 7",
        body="<p>Carding CVV fullz cashout and stolen cards discussion.</p>",
        markup="phpbb postbody postprofile")

    child = storage.get_onion_url_by_url(child_url)
    assert inherited_card_id == card_id
    assert child["primary_category"] == child["analyst_category"] == "directory_index"


def test_spain_banner_and_pending_alert_clear_after_manual_classification(isolated_db):
    _url_id, card_id, policy, _structure = _store_page(
        URL, title="Spain shipment",
        body=("<p>Firearms and weapons for sale by vendor. Direct order and escrow. "
              "Shipping to Spain via Correos, payment with Bizum, delivery in Madrid "
              "and Sevilla, with DNI required.</p>"),
        overrides={"classification_decision": "needs_review",
                   "classification_confidence_score": 0.82})
    assert storage.queue_spain_alert(URL, policy)
    assert _spain_unreviewed_count() == 1

    site_dedupe.apply_manual_category(card_id, "weapons_arms")

    assert _spain_unreviewed_count() == 0
    assert storage.get_pending_spain_alerts() == []
    row = storage.get_onion_url_by_url(URL)
    assert row["classification_decision"] == "analyst_confirmed"


def test_confirmed_spain_and_hosting_categories_gain_searchable_tags(isolated_db):
    overrides = {
        "spain_priority": True,
        "spain_confidence": "high",
        "spain_match_reason": "Spain service context",
        "spain_context_tags": ["spain_service"],
        "spain_actionable": True,
        "spain_relevance": "high",
        "spain_evidence_score": 95,
        "spain_context_only": False,
        "classification_decision": "needs_review",
        "ui_hidden_default": 0,
    }
    _url_id, card_id, _policy, _structure = _store_page(
        URL, title="Spanish hosting",
        body=("<p>Anonymous VPS web hosting service based in Spain and Madrid. "
              "Hosting service support for Spanish customers.</p>"),
        overrides=overrides)

    site_dedupe.apply_manual_category(card_id, "hosting_services")

    row = storage.get_onion_url_by_url(URL)
    tags = set(json.loads(row["tags"]))
    assert {"spain", "spain_confirmed", "hosting", "web_hosting", "infrastructure"} <= tags
    assert [item["id"] for item in site_dedupe.get_site_card_summaries(
        search="spain", include_monitor=True
    )] == [card_id]
    assert [item["id"] for item in site_dedupe.get_site_card_summaries(
        search="hosting", include_monitor=True
    )] == [card_id]
