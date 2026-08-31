
import onion_worker
import site_dedupe
import storage
from universal_classifier import classify


SAFE_HOST = "k" * 56 + ".onion"
PORN_URL = f"http://{SAFE_HOST}/porn"


def _verified_adult_policy(extra_text: str = ""):
    return classify(
        PORN_URL,
        title="Adult video marketplace",
        visible_text=(
            "Pornographic adult videos, erotic xxx gallery, and adult content. "
            + extra_text
        ),
        classification_scope="page",
    )


def _verified_page(url: str, html: str) -> tuple[dict, dict]:
    title, meta, visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = classify(
        url, title=title, meta=meta, visible_text=visible,
        classification_scope="page", page_structure=structure)
    return onion_worker.finalize_page_policy(
        url, policy, title=title, page_structure=structure), structure


def _persist_verified_directory(url: str, host: str, title: str) -> tuple[int, dict]:
    links = "".join(
        f"<a href='http://{letter * 56}.onion/'>Public resource {letter}</a>"
        for letter in "abcde"
    )
    policy, structure = _verified_page(
        url, f"<html><head><title>{title}</title></head><body>"
        f"<h1>Public onion directory</h1>{links}</body></html>")
    url_id = storage.insert_or_update_onion_url(url, host, status="queued")
    storage.apply_onion_policy(
        url, policy, 200, checked=True, page_structure=structure)
    return url_id, policy


def _safe_policy():
    return {
        "primary_category": "directory_index", "category": "directory_index", "tags": ["directory_index"],
        "risk_level": "low", "confidence": "high", "risk_flags": [], "storage_policy": "safe_summary",
        "review_status": "pending", "safety_reason": "directory_index", "priority_score": 10,
        "screenshot_policy": "allowed", "queue_policy": "expand", "active": 1, "spain_priority": False,
    }


def test_adult_plus_spain_and_multilingual_context_is_still_blackholed():
    for text in ("España Guardia Civil", "Испания МВД Испании", "Spain leaked credentials"):
        policy = _verified_adult_policy(text)
        assert policy["primary_category"] == "adult_filtered"
        assert policy["storage_policy"] == "discard"
        assert policy["spain_priority"] is False
        assert policy["spain_match_reason"] is None


def test_adult_insert_keeps_only_anti_retry_row_and_no_result_objects(isolated_db):
    policy, structure = _verified_page(
        PORN_URL,
        "<html><head><title>Adult video marketplace</title></head><body>"
        "Pornographic adult videos, erotic xxx gallery, and adult content. "
        "Spain country context.</body></html>",
    )
    url_id = storage.insert_or_update_onion_url(PORN_URL)
    storage.apply_onion_policy(
        PORN_URL, policy, 200, checked=True, page_structure=structure)
    assert site_dedupe.ensure_url_site_card(url_id, policy) == 0
    assert storage.queue_spain_alert(PORN_URL, policy) is False
    with storage.get_db() as db:
        row = db.execute("SELECT * FROM onion_urls WHERE id=?", (url_id,)).fetchone()
        assert row["status"] == "blocked" and row["active"] == 0
        assert row["primary_category"] == row["category"] == "adult_filtered"
        assert row["risk_level"] == "filtered" and row["storage_policy"] == "discard"
        assert row["review_status"] == "filtered" and row["safety_reason"] == "adult_content_filtered"
        assert row["title"] is None and row["content_hash"] is None and row["spain_priority"] == 0
        for table in ("site_cards", "site_card_urls", "onion_hits", "page_previews", "spain_alert_queue", "evidence_reports"):
            assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_discovered_adult_label_stays_provisional_until_destination_html(isolated_db):
    parent = f"http://{SAFE_HOST}/"
    parent_id = storage.insert_or_update_onion_url(parent, SAFE_HOST, policy=_safe_policy())
    item = {"id": parent_id, "url": parent, "depth": 0}
    onion_worker._store_discovered_links(item, [{"url": PORN_URL, "anchor_text": "adult"}], _safe_policy())
    with storage.get_db() as db:
        adult = db.execute("SELECT * FROM onion_urls WHERE url=?", (PORN_URL,)).fetchone()
        assert adult and adult["primary_category"] == "unknown" and adult["active"] == 1
        assert adult["verification_state"] == "provisional" and adult["status"] == "queued"
        assert db.execute("SELECT COUNT(*) FROM onion_edges WHERE discovered_url=?", (PORN_URL,)).fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM site_card_urls WHERE url=?", (PORN_URL,)).fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM spain_alert_queue").fetchone()[0] == 0


def test_cleanup_removes_legacy_adult_artifacts_only(isolated_db, tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "PREVIEWS_DIR", tmp_path / "previews")
    monkeypatch.setattr(storage, "REPORTS_DIR", tmp_path / "reports")
    storage.PREVIEWS_DIR.mkdir(); storage.REPORTS_DIR.mkdir()
    adult_url = f"http://{SAFE_HOST}/adult"
    safe_url = "http://" + "m" * 56 + ".onion/"
    adult_id, adult_safe_policy = _persist_verified_directory(
        adult_url, SAFE_HOST, "Legacy title")
    card_id = site_dedupe.ensure_url_site_card(
        adult_id, adult_safe_policy, title="Legacy title", visible_text="legacy text")
    safe_id, safe_policy = _persist_verified_directory(
        safe_url, "m" * 56 + ".onion", "Safe site")
    site_dedupe.ensure_url_site_card(
        safe_id, safe_policy, title="Safe site", visible_text="safe text")
    preview = storage.PREVIEWS_DIR / "adult.png"; preview.write_bytes(b"not-an-image")
    report = storage.REPORTS_DIR / "adult.md"; report.write_text(adult_url, encoding="utf-8")
    storage.upsert_page_preview(adult_url, str(preview))
    hit_id = storage.insert_onion_hit(adult_url, "Legacy unsafe title", 1, "critical", [], "legacy snippet", [], None,
                                      allow_unverified_legacy=True)
    storage.insert_evidence_report("site_card", str(report), "pytest", site_card_id=card_id)
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET analyst_category='adult_filtered',
          primary_category='adult_filtered',category='adult_filtered',content_category='adult_filtered',
          classification_evidence_source='analyst',destination_html_evidence_version=0,
          verification_state='verified',verification_reason='analyst_confirmed',
          storage_policy='metadata_only',risk_flags='[\"adult_extreme_caution\"]',spain_priority=1,
          title='Legacy unsafe title',content_hash='legacy' WHERE id=?""", (adult_id,))
        db.execute("""INSERT INTO spain_alert_queue(url,fingerprint,payload_json,created_at,site_card_id)
          VALUES(?,?,?,?,?)""", (adult_url, "legacy-adult", '{"category":"adult_restricted"}', storage.utc_now_iso(), card_id))
    assert storage.cleanup_adult_filtered_items() == 1
    with storage.get_db() as db:
        adult = db.execute("SELECT * FROM onion_urls WHERE id=?", (adult_id,)).fetchone()
        safe = db.execute("SELECT * FROM onion_urls WHERE id=?", (safe_id,)).fetchone()
        assert adult["primary_category"] == "adult_filtered" and adult["site_card_id"] is None
        assert adult["title"] is None and adult["spain_priority"] == 0
        assert safe["primary_category"] == "directory_index" and safe["site_card_id"] is not None
        assert db.execute("SELECT COUNT(*) FROM onion_hits WHERE id=?", (hit_id,)).fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM page_previews WHERE url=?", (adult_url,)).fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM spain_alert_queue WHERE url=?", (adult_url,)).fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM evidence_reports WHERE site_card_id=?", (card_id,)).fetchone()[0] == 0
    assert not preview.exists() and not report.exists()


def test_cleanup_scrubs_adult_fetched_snapshot_and_preview_job(isolated_db):
    adult_url = f"http://{SAFE_HOST}/adult-snapshot"
    adult_id = storage.insert_or_update_onion_url(
        adult_url, SAFE_HOST, status="crawled", policy=_safe_policy())
    raw_marker = "adult-raw-marker-must-not-remain"
    storage.store_fetched_page_snapshot(
        adult_id, adult_url, worker_id=None, response_status=200,
        content_type="text/html", headers={"X-Test": raw_marker},
        title=raw_marker, meta_text=raw_marker, visible_text=raw_marker,
        link_records=[{"url": adult_url + "/child", "anchor_text": raw_marker}],
        page_structure={
            "identity": {"detected_title": raw_marker},
            "content_boundary": {"version": 1, "outbound_anchor_text_removed": True},
        },
        pre_policy=_safe_policy(),
    )
    now = storage.utc_now_iso()
    with storage.get_db() as db:
        db.execute("""UPDATE fetched_pages SET classification_status='done',verified_at=?
          WHERE onion_url_id=?""", (now, adult_id))
        db.execute("""INSERT INTO page_preview_jobs
          (url,onion_url_id,status,created_at,updated_at,last_error)
          VALUES(?,?,'queued',?,?,?)""",
          (adult_url, adult_id, now, now, raw_marker))
        db.execute("""UPDATE onion_urls SET analyst_category='adult_filtered',
          primary_category='adult_filtered',
          category='adult_filtered',content_category='adult_filtered',
          storage_policy='discard',risk_flags='["adult_filtered"]',
          verification_state='verified',verification_reason='analyst_confirmed',
          destination_html_evidence_version=0,
          classification_evidence_source='analyst' WHERE id=?""", (adult_id,))

    assert storage.cleanup_adult_filtered_items(adult_url) == 1

    with storage.get_db() as db:
        fetched_row = db.execute("""SELECT title,meta_text,visible_text,headers_json,
          link_records_json,page_structure_json FROM fetched_pages WHERE onion_url_id=?""",
          (adult_id,)).fetchone()
        preview_job_count = db.execute(
            "SELECT COUNT(*) FROM page_preview_jobs WHERE onion_url_id=? OR url=?",
            (adult_id, adult_url)).fetchone()[0]
        dump = "\n".join(db.iterdump()).casefold()
    if fetched_row is not None:
        fetched = dict(fetched_row)
        assert fetched == {
            "title": None, "meta_text": "", "visible_text": "", "headers_json": "{}",
            "link_records_json": "[]", "page_structure_json": "{}",
        }
    assert preview_job_count == 0
    assert raw_marker not in dump


def test_aggregate_adult_child_flag_does_not_blackhole_verified_directory(isolated_db):
    url = f"http://{SAFE_HOST}/directory"
    url_id = storage.insert_or_update_onion_url(
        url, SAFE_HOST, status="crawled", policy=_safe_policy())
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET status='crawled',active=1,
          analyst_category='directory_index',classification_evidence_source='analyst',
          verification_reason='analyst_confirmed',
          primary_category='directory_index',category='directory_index',
          content_category='directory_index',storage_policy='safe_summary',
          verification_state='verified',risk_flags='["adult_filtered_child_link_present"]',
          adult_outbound_count=1,restricted_outbound_count=1,restricted_child_present=1
          WHERE id=?""", (url_id,))

    assert storage.cleanup_adult_filtered_items(url) == 0

    with storage.get_db() as db:
        row = dict(db.execute("""SELECT primary_category,category,storage_policy,status,active,
          adult_outbound_count,restricted_child_present FROM onion_urls WHERE id=?""",
          (url_id,)).fetchone())
    assert row == {
        "primary_category": "directory_index", "category": "directory_index",
        "storage_policy": "safe_summary", "status": "crawled", "active": 1,
        "adult_outbound_count": 1, "restricted_child_present": 1,
    }


def test_non_adult_spain_priority_still_works():
    policy = classify(f"http://{SAFE_HOST}/", visible_text="España Guardia Civil data leak")
    assert policy["primary_category"] == "leaks_data"
    assert policy["spain_priority"] is True
