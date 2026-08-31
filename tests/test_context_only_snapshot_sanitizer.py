import json

import site_dedupe
import storage


HOST = "6" * 56 + ".onion"
PARENT_URL = f"http://{HOST}/links"


def _policy(category: str = "directory_index") -> dict:
    return {
        "primary_category": category, "category": category,
        "content_category": category, "page_type": "link_repository",
        "tags": [category], "risk_level": "low", "confidence": "high",
        "category_confidence": "high", "risk_flags": [],
        "storage_policy": "safe_summary", "review_status": "monitor",
        "safety_reason": "link_repository", "priority_score": 10,
        "screenshot_policy": "blocked", "queue_policy": "expand", "active": 1,
        "spain_priority": False, "card_ready": 1,
        "classification_evidence_source": "destination_html",
        "destination_html_evidence_version": 1,
    }


def _store_snapshot(url: str, marker: str, *, structure: dict | None = None) -> tuple[int, int]:
    structure = dict(structure or {"heading_text": marker, "actor_evidence": [{"alias": marker}]})
    structure["content_boundary"] = {
        "version": 1, "outbound_anchor_text_removed": True,
    }
    policy = _policy()
    url_id = storage.insert_or_update_onion_url(url, HOST, policy=policy)
    snapshot_id = storage.store_fetched_page_snapshot(
        url_id, url, worker_id=None, response_status=200,
        content_type="text/html; charset=windows-1252", headers={"Content-Type": "text/html"},
        title=f"raw title {marker}", meta_text=f"raw meta {marker}",
        visible_text=f"raw body {marker}",
        link_records=[{"url": f"http://{'a' * 56}.onion/", "anchor_text": marker}],
        page_structure=structure,
        pre_policy={"decision": "accept"},
    )
    storage.apply_onion_policy(url, policy, 200, checked=True, page_structure=structure)
    return url_id, snapshot_id


def test_context_only_repository_snapshot_keeps_only_allowlisted_structure(isolated_db):
    marker = "RAW_RESTRICTED_PAGE_MARKER_91Z"
    forum_key = f"forum:{HOST}:phpbb:thread:44"
    structure = {
        "heading_text": marker,
        "identity": {"detected_title": marker, "safe_meta_description": marker},
        "actor_evidence": [{"alias": marker, "profile_url": marker}],
        "signals": [marker], "scores": {marker: 99}, "parent_evidence": [marker],
        "arbitrary_nested": {"raw": marker},
        "onion_link_count": 77, "internal_link_count": 12,
        "external_onion_count": 33, "external_onion_host_count": 31,
        "link_observation_count": 101, "unique_link_count": 77,
        "duplicate_link_observation_count": 24, "link_density": 0.76,
        "forum_link_count": 9, "market_link_count": 3, "form_count": 1,
        "navigation_link_count": 8, "repeated_link_row_count": 70,
        "page_type_info": {
            "page_type": "link_repository", "page_type_confidence": "high",
            "page_type_score": 10, "evidence": [marker],
        },
        "decoding": {
            "charset": "cp1252", "source": "http_header", "confidence": "declared",
            "fallback_used": False, "http_charset_declared": True,
            "http_charset_valid": True, "bom_present": False,
            "meta_charset_declared": False, "meta_charset_valid": False,
            "failed_candidates": 0, "raw_probe": marker,
        },
        "decoding_charset": "cp1252", "decoding_source": "http_header",
        "forum_route_hint": {
            "role": "thread", "engine": "phpbb", "confidence": "high",
            "stable_key": forum_key, "canonical_identity_hash": "a" * 64,
            "reason": "phpbb_viewtopic_identity", "exact_url": marker,
        },
    }
    url_id, snapshot_id = _store_snapshot(PARENT_URL, marker, structure=structure)
    card_id = site_dedupe.ensure_url_site_card(url_id, _policy(), title="Safe link directory")
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET analyst_category='directory_index',classification_decision='analyst_confirmed' WHERE id=?",
                   (url_id,))
        db.execute("UPDATE site_cards SET analyst_title='My safe directory',analyst_category='directory_index',analyst_notes='keep' WHERE id=?",
                   (card_id,))
        before_url = dict(db.execute("SELECT * FROM onion_urls WHERE id=?", (url_id,)).fetchone())
        before_card = dict(db.execute("SELECT * FROM site_cards WHERE id=?", (card_id,)).fetchone())

    sanitized_records = [
        {"url_hash": "b" * 64, "policy": "restricted_child", "observation_count": 4},
        {"url_hash": "c" * 64, "policy": "safe_child", "observation_count": 1},
    ]
    assert storage.sanitize_context_only_restricted_link_repository_snapshot(
        snapshot_id, safe_title="Context-only link repository",
        sanitized_link_records=sanitized_records,
    )

    with storage.get_db() as db:
        row = dict(db.execute("SELECT * FROM fetched_pages WHERE id=?", (snapshot_id,)).fetchone())
        after_url = dict(db.execute("SELECT * FROM onion_urls WHERE id=?", (url_id,)).fetchone())
        after_card = dict(db.execute("SELECT * FROM site_cards WHERE id=?", (card_id,)).fetchone())
        dump = "\n".join(db.iterdump())

    assert row["title"] == "Context-only link repository"
    assert row["meta_text"] == row["visible_text"] == ""
    assert json.loads(row["link_records_json"]) == sanitized_records
    summary = json.loads(row["page_structure_json"])
    assert summary["onion_link_count"] == 77
    assert summary["external_onion_host_count"] == 31
    assert summary["duplicate_link_observation_count"] == 24
    assert summary["link_density"] == 0.76
    assert summary["page_type"] == "link_repository"
    assert summary["page_type_confidence"] == "high"
    assert summary["page_type_score"] == 10
    assert summary["decoding"]["charset"] == "cp1252"
    assert summary["forum_route_hint"]["stable_key"] == forum_key
    assert summary["forum_route_hint"]["hint_verified"] is False
    assert summary["forum_route_hint"]["evidence_source"] == "url_route"
    assert set(summary) == {
        "decoding", "decoding_charset", "decoding_source", "duplicate_link_observation_count",
        "external_onion_count", "external_onion_host_count", "form_count", "forum_link_count",
        "forum_route_hint", "internal_link_count", "link_density", "link_observation_count",
        "market_link_count", "navigation_link_count", "onion_link_count", "page_type",
        "page_type_confidence", "page_type_score", "repeated_link_row_count", "unique_link_count",
    }
    assert marker not in dump
    assert after_url == before_url
    assert after_card == before_card


def test_snapshot_sanitizer_is_idempotent_and_does_not_touch_other_snapshot_or_children(isolated_db):
    parent_marker = "RAW_PARENT_ONLY_82Q"
    other_marker = "RAW_UNRELATED_ROW_73P"
    _, snapshot_id = _store_snapshot(PARENT_URL, parent_marker, structure={
        "heading_text": parent_marker, "onion_link_count": 5,
        "page_type_info": {"page_type": "link_repository", "page_type_confidence": "medium", "page_type_score": 5},
    })
    _, unrelated_snapshot_id = _store_snapshot(f"http://{HOST}/other", other_marker)

    adult_url = f"http://{'d' * 56}.onion/restricted"
    severe_url = f"http://{'e' * 56}.onion/restricted"
    adult_id = storage.insert_or_update_onion_url(adult_url, status="blocked", policy={
        **_policy("adult_restricted"), "active": 0, "storage_policy": "metadata_only",
        "queue_policy": "blocked", "review_status": "restricted",
    })
    severe_id = storage.insert_or_update_onion_url(severe_url, status="blocked", policy={
        **_policy("severe_abuse_risk"), "active": 0, "storage_policy": "metadata_only",
        "queue_policy": "blocked", "review_status": "restricted",
    })
    with storage.get_db() as db:
        unrelated_before = dict(db.execute("SELECT * FROM fetched_pages WHERE id=?", (unrelated_snapshot_id,)).fetchone())
        adult_before = dict(db.execute("SELECT * FROM onion_urls WHERE id=?", (adult_id,)).fetchone())
        severe_before = dict(db.execute("SELECT * FROM onion_urls WHERE id=?", (severe_id,)).fetchone())

    records = [{"url_hash": "f" * 64, "policy": "restricted_child", "observation_count": 2}]
    assert storage.sanitize_context_only_restricted_link_repository_snapshot(
        snapshot_id, safe_title=None, sanitized_link_records=records)
    with storage.get_db() as db:
        after_first = dict(db.execute("SELECT * FROM fetched_pages WHERE id=?", (snapshot_id,)).fetchone())
    assert storage.sanitize_context_only_restricted_link_repository_snapshot(
        snapshot_id, safe_title=None, sanitized_link_records=records)
    with storage.get_db() as db:
        after_second = dict(db.execute("SELECT * FROM fetched_pages WHERE id=?", (snapshot_id,)).fetchone())
        unrelated_after = dict(db.execute("SELECT * FROM fetched_pages WHERE id=?", (unrelated_snapshot_id,)).fetchone())
        adult_after = dict(db.execute("SELECT * FROM onion_urls WHERE id=?", (adult_id,)).fetchone())
        severe_after = dict(db.execute("SELECT * FROM onion_urls WHERE id=?", (severe_id,)).fetchone())

    assert after_first == after_second
    assert after_second["title"] is None
    assert after_second["meta_text"] == after_second["visible_text"] == ""
    assert json.loads(after_second["page_structure_json"])["onion_link_count"] == 5
    assert unrelated_after == unrelated_before
    assert unrelated_after["visible_text"] == f"raw body {other_marker}"
    assert adult_after == adult_before
    assert severe_after == severe_before


def test_snapshot_sanitizer_rejects_invalid_records_and_missing_id_is_safe(isolated_db):
    assert storage.sanitize_context_only_restricted_link_repository_snapshot(
        999999, safe_title="Safe", sanitized_link_records=[]) is False
    try:
        storage.sanitize_context_only_restricted_link_repository_snapshot(
            999999, safe_title="Safe", sanitized_link_records=["not-a-record"])
    except ValueError as exc:
        assert "sanitized dictionaries" in str(exc)
    else:
        raise AssertionError("invalid link records must be rejected")
