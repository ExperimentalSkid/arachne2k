from __future__ import annotations

import pytest

import report_builder
import onion_worker
import site_dedupe
import storage
from safety_policy import severe_blackhole_policy
from universal_classifier import classify


SAFE_HOST = "m" * 56 + ".onion"
SEVERE_HOST = "n" * 56 + ".onion"
SAFE_ROOT = f"http://{SAFE_HOST}/"
SAFE_CHILD = f"http://{SAFE_HOST}/notice"
SEVERE_URL = f"http://{SEVERE_HOST}/"


def _safe_policy() -> dict:
    return {
        "primary_category": "directory_index", "category": "directory_index",
        "tags": ["directory_index"], "risk_level": "low", "confidence": "high",
        "risk_flags": [], "storage_policy": "safe_summary", "review_status": "monitor",
        "safety_reason": "directory_index", "screenshot_policy": "allowed",
        "queue_policy": "expand", "active": 1, "spain_priority": False,
        "page_type": "homepage", "card_ready": True,
    }


def _persist_html(url: str, host: str, html: str) -> tuple[int, dict, dict]:
    title, meta, visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = classify(
        url, title=title, meta=meta, visible_text=visible,
        classification_scope="page", page_structure=structure)
    policy = onion_worker.finalize_page_policy(
        url, policy, title=title, page_structure=structure)
    url_id = storage.insert_or_update_onion_url(url, host, status="queued")
    storage.apply_onion_policy(
        url, policy, 200, checked=True, page_structure=structure)
    return url_id, policy, structure


def _directory_html(title: str) -> str:
    links = "".join(
        f"<a href='http://{letter * 56}.onion/'>Public resource {letter}</a>"
        for letter in "abcde"
    )
    return (f"<html><head><title>{title}</title></head><body>"
            f"<h1>Public onion directory</h1>{links}</body></html>")


def test_severe_url_cannot_create_match_or_fingerprint(isolated_db):
    url_id, policy, _structure = _persist_html(
        SEVERE_URL, SEVERE_HOST,
        "<html><head><title>Restricted archive</title></head><body>"
        "Childporn video archive advertised for download and exchange."
        "</body></html>")

    assert site_dedupe.ensure_url_site_card(
        url_id, policy, title="restricted", visible_text="restricted") == 0
    assert site_dedupe.extract_safe_fingerprints(
        SEVERE_URL, "restricted", "restricted", severe_blackhole=True) == []
    assert site_dedupe.find_matching_site_card(
        policy, [{"type": "title", "value": "not-persisted"}],
        site_dedupe.normalize_url_for_dedupe(SEVERE_URL))["site_card_id"] is None

    with storage.get_db() as db:
        row = dict(db.execute("SELECT * FROM onion_urls WHERE id=?", (url_id,)).fetchone())
        assert row["site_card_id"] is None
        assert db.execute("SELECT COUNT(*) FROM site_cards").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM site_fingerprints").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM possible_site_card_matches").fetchone()[0] == 0
    with pytest.raises(ValueError, match="Severe-blackhole"):
        report_builder.build_url_report(SEVERE_URL)


def test_late_severe_child_is_removed_without_deleting_shared_safe_card(isolated_db):
    root_id, safe, _root_structure = _persist_html(
        SAFE_ROOT, SAFE_HOST, _directory_html("Safe directory"))
    card_id = site_dedupe.ensure_url_site_card(
        root_id, safe, title="Safe directory", visible_text="safe directory index")
    child_id, child_safe, _child_structure = _persist_html(
        SAFE_CHILD, SAFE_HOST, _directory_html("Notice directory"))
    assert site_dedupe.ensure_url_site_card(
        child_id, child_safe, title="Notice", visible_text="ordinary safe notice") == card_id

    _severe_id, _severe, _severe_structure = _persist_html(
        SAFE_CHILD, SAFE_HOST,
        "<html><head><title>Restricted archive</title></head><body>"
        "Childporn video archive advertised for download and exchange."
        "</body></html>")

    card = site_dedupe.get_site_card(card_id)
    assert card is not None
    assert [item["url"] for item in card["urls"]] == [SAFE_ROOT]
    with storage.get_db() as db:
        child = dict(db.execute("SELECT * FROM onion_urls WHERE id=?", (child_id,)).fetchone())
        assert child["site_card_id"] is None
        assert child["spain_priority"] == 0 and child["urgent_flag"] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM site_fingerprints WHERE onion_url_id=?", (child_id,)).fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM site_card_urls WHERE onion_url_id=?", (child_id,)).fetchone()[0] == 0


def test_legacy_severe_cards_are_hidden_from_all_normal_card_accessors_and_reports(
        isolated_db):
    now = storage.utc_now_iso()
    with storage.get_db() as db:
        card_id = int(db.execute("""INSERT INTO site_cards(
          canonical_site_id,display_name,primary_category,storage_policy,review_status,
          spain_priority,urgent_flag,alert_eligible,ui_hidden_default,first_seen,last_seen,
          created_at,updated_at) VALUES(?,?,?,?,?,1,1,1,0,?,?,?,?)""",
          ("legacy-severe", "Legacy restricted card", "severe_abuse_risk", "metadata_only",
           "restricted", now, now, now, now)).lastrowid)

    assert site_dedupe.get_site_cards() == []
    assert site_dedupe.get_site_card_summaries(
        include_hidden=True, include_monitor=True) == []
    assert "severe_abuse_risk" not in site_dedupe.get_site_card_category_counts(include_hidden=True)
    assert site_dedupe.get_site_card_detail(
        card_id, include_dead=True, include_restricted=True) is None
    with pytest.raises(ValueError, match="Severe-blackhole"):
        report_builder.build_site_card_report(card_id)


def test_legacy_mirror_cluster_with_severe_tombstone_cannot_generate_report(isolated_db):
    _persist_html(
        SEVERE_URL, SEVERE_HOST,
        "<html><head><title>Restricted archive</title></head><body>"
        "Childporn video archive advertised for download and exchange."
        "</body></html>")
    now = storage.utc_now_iso()
    with storage.get_db() as db:
        cluster_id = int(db.execute("""INSERT INTO mirror_clusters(
          cluster_type,first_seen,last_seen,risk_level,status,summary,shared_indicators_json)
          VALUES('unknown',?,?,'critical','active','restricted','[]')""", (now, now)).lastrowid)
        db.execute("""INSERT INTO mirror_urls(
          cluster_id,url,source_type,first_seen,last_seen,title)
          VALUES(?,?,'legacy',?,?,NULL)""", (cluster_id, SEVERE_URL, now, now))

    with pytest.raises(ValueError, match="severe-blackhole"):
        report_builder.build_cluster_report(cluster_id)
