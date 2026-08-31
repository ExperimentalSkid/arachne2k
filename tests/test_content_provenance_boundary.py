"""Regression tests for the destination-owned HTML classification boundary."""
from __future__ import annotations

import onion_worker
import site_dedupe
import storage


HOST = "p" * 56 + ".onion"


def _verified_html_policy(url: str, html: str) -> tuple[dict, dict]:
    title, meta, visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = onion_worker._classify_fetched_page(
        url, title=title, meta=meta, visible_text=visible,
        source_url=None, source_context=None, page_structure=structure)
    policy = onion_worker.finalize_page_policy(
        url, policy, title=title, page_structure=structure)
    return policy, structure


def _persist_verified_directory(url: str) -> dict:
    html = """<html><head><title>Public Onion Directory</title></head><body>
    <h1>Public Onion Directory</h1><p>Independent public service links.</p>
    <a href='http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/'>One</a>
    <a href='http://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion/'>Two</a>
    <a href='http://cccccccccccccccccccccccccccccccccccccccccccccccccccccccc.onion/'>Three</a>
    <a href='http://dddddddddddddddddddddddddddddddddddddddddddddddddddddddd.onion/'>Four</a>
    <a href='http://eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.onion/'>Five</a>
    </body></html>"""
    policy, structure = _verified_html_policy(url, html)
    storage.insert_or_update_onion_url(url)
    storage.apply_onion_policy(url, policy, 200, checked=True, page_structure=structure)
    return storage.get_onion_url_by_url(url)


def test_checked_flag_and_claimed_version_without_parser_structure_are_not_proof(isolated_db):
    url = f"http://{HOST}/childporn"
    storage.insert_or_update_onion_url(url)
    storage.apply_onion_policy(url, {
        "primary_category": "severe_abuse_risk",
        "category": "severe_abuse_risk",
        "content_category": "severe_abuse_risk",
        "classification_evidence_source": "destination_html",
        "destination_html_evidence_version": 1,
        "storage_policy": "metadata_only",
        "queue_policy": "blocked",
        "active": 0,
    }, checked=True, page_structure={})

    row = storage.get_onion_url_by_url(url)
    assert row["primary_category"] == "unknown"
    assert row["content_category"] == "unknown"
    assert row["classification_evidence_source"] == "unverified"
    assert row["destination_html_evidence_version"] == 0
    assert row["status"] == "queued"
    assert row["active"] == 1


def test_unverified_severe_policy_cannot_replace_or_erase_verified_safe_html(isolated_db):
    url = f"http://{HOST}/"
    before = _persist_verified_directory(url)
    assert before["primary_category"] == "directory_index"

    storage.apply_onion_policy(url, {
        "primary_category": "severe_abuse_risk",
        "category": "severe_abuse_risk",
        "content_category": "severe_abuse_risk",
        "classification_evidence_source": "url_hint",
        "destination_html_evidence_version": 1,
        "storage_policy": "metadata_only",
        "queue_policy": "blocked",
        "active": 0,
    }, checked=True, page_structure={})

    after = storage.get_onion_url_by_url(url)
    assert after["primary_category"] == "directory_index"
    assert after["content_category"] == "directory_index"
    assert after["classification_evidence_source"] == "destination_html"
    assert after["active"] == 1


def test_unverified_card_argument_cannot_override_persisted_destination_truth(isolated_db):
    url = f"http://{HOST}/index.html"
    row = _persist_verified_directory(url)

    card_id = site_dedupe.ensure_url_site_card(
        int(row["id"]),
        classification={
            "primary_category": "adult_filtered",
            "storage_policy": "discard",
            "classification_evidence_source": "url_hint",
        },
    )

    assert card_id
    with storage.get_db() as db:
        card = dict(db.execute(
            "SELECT primary_category,storage_policy FROM site_cards WHERE id=?",
            (card_id,),
        ).fetchone())
    assert card["primary_category"] == "directory_index"
    assert card["storage_policy"] != "discard"


def test_analyst_value_proves_only_that_exact_category(isolated_db):
    url = f"http://{HOST}/about"
    storage.insert_or_update_onion_url(url)
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET analyst_category='directory_index',
          primary_category='fraud_financial',category='fraud_financial',
          content_category='fraud_financial',classification_evidence_source='analyst',
          verification_state='verified',verification_reason='analyst_confirmed'
          WHERE url=?""", (url,))

    card_id = site_dedupe.ensure_url_site_card(url)
    assert card_id
    with storage.get_db() as db:
        card = db.execute(
            "SELECT primary_category FROM site_cards WHERE id=?", (card_id,)
        ).fetchone()
    assert card["primary_category"] == "directory_index"


def test_unverified_content_rejection_cannot_block_frontier(isolated_db):
    url = f"http://{HOST}/explicit-looking-name"
    storage.insert_or_update_onion_url(url)
    storage.apply_crawl_decision(url, {
        "decision": "reject", "rule_id": "legacy-url-filter",
        "primary_category": "adult_filtered",
        "safety_reason": "adult_content_filtered",
        "classification_evidence_source": "url_hint",
        "active": 0,
    })

    row = storage.get_onion_url_by_url(url)
    assert row["decision"] == "monitor"
    assert row["status"] == "queued"
    assert row["active"] == 1
    assert row["primary_category"] == "unknown"


def test_old_adult_memory_cannot_borrow_safe_html_provenance(isolated_db):
    url = f"http://{HOST}/ordinary"
    row = _persist_verified_directory(url)
    storage.remember_adult_url(url, diagnostics={"match_scope": "title"})

    assert row["primary_category"] == "directory_index"
    assert storage.get_adult_memory_decision(url) is None

