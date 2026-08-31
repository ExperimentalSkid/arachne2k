import json

import storage
import onion_worker
from universal_classifier import classify, classify_preview_ocr_text


HOST = "g" * 56 + ".onion"


def _classify(path, title):
    return classify(f"http://{HOST}{path}", title=title)


def test_structural_pages_resist_weak_adult_false_positives():
    cases = [
        ("/help/user/account", "GitLab help page porn report", "hosting_services"),
        ("/-/commits/main", "Gitea project porn issue", "hosting_services"),
        ("/wiki/Special:Random", "MediaWiki porn article reference", "directory_index"),
        ("/wiki/Talk:Example", "MediaWiki talk porn reference", "directory_index"),
        ("/viewforum.php?f=2", "phpBB forum porn discussion", "forum_social"),
        ("/viewtopic.php?t=2", "phpBB topic porn discussion", "forum_social"),
        ("/vendor/name", "marketplace vendor page", "marketplace"),
        ("/cart", "marketplace cart", "marketplace"),
        ("/escrow", "marketplace escrow", "marketplace"),
    ]
    for path, title, expected in cases:
        policy = _classify(path, title)
        assert policy["primary_category"] == expected
        assert policy["primary_category"] != "adult_filtered"


def test_url_only_adult_child_is_provisional_but_dominant_page_is_restricted():
    child = _classify("/category/porn", "Marketplace category")
    assert child["primary_category"] == "marketplace"
    assert child["active"] == 1
    dominant = _classify("/", "porn adult content gallery")
    assert dominant["primary_category"] == "adult_filtered"


def test_synthetic_severe_context_overrides_adult_and_safety_context_does_not():
    severe = _classify("/", "loli porn video gallery exchange")
    assert severe["primary_category"] == "severe_abuse_risk"
    assert severe["storage_policy"] == "metadata_only"
    assert all("loli" not in label for label in severe["safe_signal_labels"])
    safe = _classify("/wiki/Safety", "loli legal guidance child safety")
    assert safe["primary_category"] != "severe_abuse_risk"


def test_adult_memory_stores_safe_diagnostics_only(isolated_db):
    url = f"http://{HOST}/porn"
    html = ("<html><head><title>Adult content gallery</title></head><body>"
            "Pornographic adult videos, erotic xxx gallery, and adult content."
            "</body></html>")
    title, meta, visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = classify(
        url, title=title, meta=meta, visible_text=visible,
        classification_scope="page", page_structure=structure)
    policy = onion_worker.finalize_page_policy(
        url, policy, title=title, page_structure=structure)
    storage.insert_or_update_onion_url(url)
    storage.apply_onion_policy(
        url, policy, 200, checked=True, page_structure=structure)
    with storage.get_db() as db:
        row = dict(db.execute("SELECT * FROM adult_filter_memory").fetchone())
    labels = json.loads(row["safe_signal_labels"])
    assert row["match_scope"] in {"url", "title", "body", "anchor"}
    assert labels and all(label in {"adult_dominant_page", "adult_child_url_only"} for label in labels)


def test_structural_adult_false_positive_repair_is_guarded(isolated_db):
    url = f"http://{HOST}/wiki/Special:Random"
    url_id = storage.insert_or_update_onion_url(url)
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET status='blocked',active=0,
          primary_category='adult_filtered',category='adult_filtered',
          content_category='adult_filtered',storage_policy='discard',
          review_status='filtered',queue_policy='blocked',verification_state='discovered',
          classification_evidence_source='unverified',destination_html_evidence_version=0
          WHERE id=?""", (url_id,))
    result = onion_worker.repair_adult_false_positives(False)
    row = storage.get_onion_url_by_url(url)
    assert result["restored"] == 1
    assert row["primary_category"] == "unknown" and row["active"] == 1
    assert onion_worker.repair_adult_false_positives(False)["restored"] == 0


def test_adult_false_positive_repair_does_not_trust_legacy_snapshot_without_boundary(
        isolated_db):
    url = f"http://{HOST}/wiki/Links"
    child_url = "http://" + "p" * 56 + ".onion/"
    marker = "pornographic adult videos erotic xxx gallery and adult content"
    url_id = storage.insert_or_update_onion_url(url, HOST, status="queued")
    storage.store_fetched_page_snapshot(
        url_id, url, worker_id=None, response_status=200, content_type="text/html",
        headers={}, title="Neutral public link directory", meta_text="",
        visible_text=f"Neutral public link directory {marker}",
        link_records=[{"url": child_url, "anchor_text": marker}],
        page_structure={
            "identity": {
                "detected_title": "Neutral public link directory",
                "title_source": "html_title",
            },
            "signals": ["high_edge_link_repository"],
            "scores": {"directory": 4},
        },
        pre_policy={"primary_category": "unknown", "storage_policy": "safe_summary"},
    )
    with storage.get_db() as db:
        db.execute("""UPDATE fetched_pages SET classification_status='done',verified_at=?
          WHERE onion_url_id=?""", (storage.utc_now_iso(), url_id))
        db.execute("""UPDATE onion_urls SET status='blocked',active=0,
          primary_category='adult_filtered',category='adult_filtered',
          content_category='adult_filtered',storage_policy='discard',
          review_status='filtered',queue_policy='blocked',verification_state='discovered'
          WHERE id=?""", (url_id,))

    result = onion_worker.repair_adult_false_positives(False)

    row = storage.get_onion_url_by_url(url)
    assert result["restored"] == 1 and result["kept_restricted"] == 0
    assert row["primary_category"] == "unknown"
    assert row["status"] == "queued" and row["active"] == 1
    assert row["verification_state"] != "verified"
    assert row["site_card_id"] is None


def test_restricted_ocr_is_preview_only_and_never_becomes_page_truth(isolated_db):
    url = f"http://{HOST}/ocr"
    raw_ocr = "cp porn video gallery exchange"
    policy = classify_preview_ocr_text(raw_ocr)
    assert policy["primary_category"] == "severe_abuse_risk"
    storage.insert_or_update_onion_url(url)
    storage.apply_onion_policy(url, policy)
    row = storage.get_onion_url_by_url(url)
    serialized = json.dumps(row, ensure_ascii=False)
    assert raw_ocr not in serialized
    assert row["primary_category"] == "unknown"
    assert row["classification_evidence_source"] == "unverified"
    assert row["ocr_checked"] == 1 and row["ocr_restricted_hit"] == 1
    assert row["screenshot_policy"] == "blocked"
