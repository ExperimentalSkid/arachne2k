import sys
import types
from urllib.parse import urlsplit

import onion_worker
import preview_worker
import screenshot_service
import site_dedupe
import storage


HOST = "p" * 56 + ".onion"
URL = f"http://{HOST}/"


def _policy(category="directory_index"):
    return {
        "primary_category": category, "category": category, "content_category": category,
        "tags": [category], "risk_level": "low", "confidence": "medium", "risk_flags": [],
        "storage_policy": "safe_summary", "review_status": "monitor", "safety_reason": "test",
        "priority_score": 10, "screenshot_policy": "allowed", "queue_policy": "expand",
        "active": 1, "spain_priority": False, "card_ready": 1, "page_type": "directory_index_page",
    }


def _insert_crawled(url=URL, policy=None):
    policy = policy or _policy()
    category = str(policy.get("primary_category") or "directory_index")
    if category == "severe_abuse_risk":
        html = ("<html><head><title>Restricted archive</title></head><body>"
                "Childporn video archive advertised for download and exchange."
                "</body></html>")
    else:
        links = "".join(
            f"<a href='http://{letter * 56}.onion/'>Public resource {letter}</a>"
            for letter in "abcde"
        )
        html = ("<html><head><title>Neutral Directory</title></head><body>"
                f"<h1>Public onion directory</h1>{links}</body></html>")
    title, meta, visible, _records, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    verified = onion_worker._classify_fetched_page(
        url, title=title, meta=meta, visible_text=visible,
        source_url=None, source_context=None, page_structure=structure)
    verified = onion_worker.finalize_page_policy(
        url, verified, title=title, page_structure=structure)
    host = urlsplit(url).hostname or HOST
    url_id = storage.insert_or_update_onion_url(url, host, status="queued")
    storage.apply_onion_policy(
        url, verified, 200, checked=True, page_structure=structure)
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET status=?,active=?,http_status=200,
          last_crawled=? WHERE id=?""",
          ("crawled" if verified.get("active", 1) else "blocked",
           int(verified.get("active", 1)), storage.utc_now_iso(), url_id))
    return url_id


def _attach_directory_card(url_id: int, url: str = URL) -> int:
    policy = dict(
        _policy(), detected_title="Neutral Directory", safe_display_name="Neutral Directory",
        title_source="html_title", identity_confidence="high")
    return site_dedupe.ensure_url_site_card(
        url_id, policy, title="Neutral Directory",
        visible_text="A neutral directory containing unrelated public resources.")


def test_staged_verify_enqueues_preview_job_for_allowed_html(isolated_db, monkeypatch):
    url_id = storage.insert_or_update_onion_url(URL, HOST, status="classification_pending")
    html = ("<html><head><title>Directory</title></head><body><h1>Public onion directory</h1>"
            + "".join(
                f"<a href='http://{letter * 56}.onion/'>Resource {letter}</a>"
                for letter in "abcde")
            + "</body></html>")
    title, meta, visible, links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", URL)
    storage.store_fetched_page_snapshot(
        url_id, URL, worker_id="fetch-a", response_status=200, content_type="text/html; charset=utf-8",
        headers={"Content-Type": "text/html"}, title=title, meta_text=meta,
        visible_text=visible, link_records=links, page_structure=structure, pre_policy=_policy(),
    )
    monkeypatch.setattr(onion_worker, "_classify_fetched_page", lambda *a, **k: dict(_policy()))
    monkeypatch.setattr(onion_worker, "_mixed_link_directory", lambda *a, **k: False)
    monkeypatch.setattr(onion_worker, "classify_outbound_records",
                        lambda *a, **k: ({"total": 0, "adult": 0, "severe": 0, "restricted": 0, "blocked": 0}, []))
    monkeypatch.setattr(onion_worker, "extract_page_identity", lambda *a, **k: {"display_name": "Directory", "detected_title": "Directory"})
    monkeypatch.setattr(onion_worker, "fingerprint_page_type", lambda *a, **k: {"page_type": "directory_index_page", "page_type_confidence": "high", "evidence": []})
    monkeypatch.setattr(onion_worker, "calibrate_classification", lambda p, **k: p)
    monkeypatch.setattr(onion_worker, "assess_content_liveness", lambda *a, **k: {"fetch_status": "live", "liveness_status": "live", "content_quality": "meaningful", "reason": "ok"})
    monkeypatch.setattr(onion_worker, "apply_classification_contract", lambda p, *a, **k: p)
    monkeypatch.setattr(onion_worker, "compute_card_readiness", lambda *a, **k: {"card_ready": 1, "card_readiness_reason": "test"})
    monkeypatch.setattr(onion_worker, "classify_risk_flags", lambda *a, **k: [])
    monkeypatch.setattr(onion_worker, "extract_indicators", lambda *a, **k: [])
    monkeypatch.setattr(onion_worker, "extract_passive_exposures", lambda *a, **k: [])
    monkeypatch.setattr(onion_worker, "extract_page_topics", lambda *a, **k: {"topics": [], "keywords": []})

    assert onion_worker.verify_one("verify-test") is True

    with storage.get_db() as db:
        job = db.execute("SELECT status,url FROM page_preview_jobs WHERE url=?", (URL,)).fetchone()
        row = db.execute("SELECT status FROM onion_urls WHERE url=?", (URL,)).fetchone()
    assert dict(job) == {"status": "queued", "url": URL}
    assert row["status"] == "crawled"


def test_metadata_restricted_pages_do_not_enqueue_preview_jobs(isolated_db):
    policy = _policy("severe_abuse_risk")
    policy.update(storage_policy="metadata_only", review_status="restricted",
                  screenshot_policy="blocked", queue_policy="blocked", active=0)
    _insert_crawled(policy=policy)
    assert storage.create_page_preview_job(URL) is None
    assert storage.queue_missing_previews(20) == 0


def test_queue_missing_previews_does_not_change_crawl_status(isolated_db):
    _insert_crawled()
    assert storage.queue_missing_previews(20) == 1
    with storage.get_db() as db:
        url_row = db.execute("SELECT status FROM onion_urls WHERE url=?", (URL,)).fetchone()
        job_row = db.execute("SELECT status FROM page_preview_jobs WHERE url=?", (URL,)).fetchone()
    assert url_row["status"] == "crawled"
    assert job_row["status"] == "queued"


def test_preview_worker_claims_job_and_creates_available_preview(isolated_db, tmp_path, monkeypatch):
    _insert_crawled()
    storage.create_page_preview_job(URL)
    output = tmp_path / "preview.png"
    output.write_bytes(b"png")
    monkeypatch.setattr(preview_worker, "screenshot_support_status", lambda: (True, "ready"))
    monkeypatch.setattr(preview_worker.storage, "preview_capture_limit_reached", lambda: False)
    monkeypatch.setattr(preview_worker, "capture_page_screenshot", lambda _url: str(output))
    monkeypatch.setattr(preview_worker, "_ocr_policy_blocks_preview", lambda *_a, **_k: (False, {"ocr_checked": False}))

    assert preview_worker.process_preview_job("preview-a") is True

    preview = storage.get_page_preview(URL)
    with storage.get_db() as db:
        job = db.execute("SELECT status,preview_path FROM page_preview_jobs WHERE url=?", (URL,)).fetchone()
    assert preview["status"] == "available"
    assert preview["preview_path"] == str(output)
    assert dict(job) == {"status": "available", "preview_path": str(output)}


def test_preview_worker_ocr_restricted_deletes_and_blocks_preview_only(isolated_db, tmp_path, monkeypatch):
    _insert_crawled()
    storage.create_page_preview_job(URL)
    output = tmp_path / "preview.png"
    output.write_bytes(b"png")
    restricted_policy = _policy("adult_filtered")
    restricted_policy.update(storage_policy="discard", screenshot_policy="blocked",
                             screenshot_blocked_reason="adult_content_filtered",
                             safety_reason="adult_content_filtered")
    monkeypatch.setattr(preview_worker, "screenshot_support_status", lambda: (True, "ready"))
    monkeypatch.setattr(preview_worker.storage, "preview_capture_limit_reached", lambda: False)
    monkeypatch.setattr(preview_worker, "capture_page_screenshot", lambda _url: str(output))
    monkeypatch.setattr(preview_worker, "_ocr_policy_blocks_preview", lambda *_a, **_k: (True, restricted_policy))

    assert preview_worker.process_preview_job("preview-a") is True

    assert not output.exists()
    preview = storage.get_page_preview(URL)
    assert preview is None or preview["status"] == "blocked"
    with storage.get_db() as db:
        row = db.execute("SELECT status,primary_category,screenshot_policy FROM onion_urls WHERE url=?", (URL,)).fetchone()
    assert dict(row) == {
        "status": "crawled", "primary_category": "directory_index",
        "screenshot_policy": "allowed",
    }


def test_preview_ocr_child_label_cannot_overwrite_verified_directory_or_card(
        isolated_db, tmp_path, monkeypatch):
    url_id = _insert_crawled()
    card_id = _attach_directory_card(url_id)
    storage.create_page_preview_job(URL)
    output = tmp_path / "preview.png"
    output.write_bytes(b"png")
    fake_ocr = types.ModuleType("image_ocr")
    fake_ocr.extract_text = lambda _path: {
        "text": "childporn video archive exchange files", "language": "eng"}
    monkeypatch.setitem(sys.modules, "image_ocr", fake_ocr)
    monkeypatch.setattr(preview_worker, "screenshot_support_status", lambda: (True, "ready"))
    monkeypatch.setattr(preview_worker.storage, "preview_capture_limit_reached", lambda: False)
    monkeypatch.setattr(preview_worker, "capture_page_screenshot", lambda _url: str(output))

    assert preview_worker.process_preview_job("preview-child-label") is True

    assert not output.exists(), "ambiguous restricted OCR must fail closed for the preview artifact"
    with storage.get_db() as db:
        row = dict(db.execute("""SELECT status,verification_state,primary_category,
          content_category,storage_policy,site_card_id FROM onion_urls WHERE id=?""",
          (url_id,)).fetchone())
        card = dict(db.execute("SELECT id,primary_category FROM site_cards WHERE id=?",
                               (card_id,)).fetchone())
        job = dict(db.execute("SELECT status FROM page_preview_jobs WHERE url=?", (URL,)).fetchone())
    assert row == {
        "status": "crawled", "verification_state": "verified",
        "primary_category": "directory_index", "content_category": "directory_index",
        "storage_policy": "safe_summary", "site_card_id": card_id,
    }
    assert card == {"id": card_id, "primary_category": "directory_index"}
    assert job["status"] == "blocked"


def test_safe_preview_ocr_never_resets_verified_category_or_card_to_unknown(
        isolated_db, tmp_path, monkeypatch):
    url_id = _insert_crawled()
    card_id = _attach_directory_card(url_id)
    storage.create_page_preview_job(URL)
    output = tmp_path / "preview.png"
    output.write_bytes(b"png")
    fake_ocr = types.ModuleType("image_ocr")
    fake_ocr.extract_text = lambda _path: {
        "text": "ordinary directory navigation and public resources", "language": "eng"}
    monkeypatch.setitem(sys.modules, "image_ocr", fake_ocr)
    monkeypatch.setattr(preview_worker, "screenshot_support_status", lambda: (True, "ready"))
    monkeypatch.setattr(preview_worker.storage, "preview_capture_limit_reached", lambda: False)
    monkeypatch.setattr(preview_worker, "capture_page_screenshot", lambda _url: str(output))

    assert preview_worker.process_preview_job("preview-safe-ocr") is True

    with storage.get_db() as db:
        row = dict(db.execute("""SELECT status,verification_state,primary_category,
          content_category,storage_policy,site_card_id FROM onion_urls WHERE id=?""",
          (url_id,)).fetchone())
        card = dict(db.execute("SELECT id,primary_category FROM site_cards WHERE id=?",
                               (card_id,)).fetchone())
    assert row == {
        "status": "crawled", "verification_state": "verified",
        "primary_category": "directory_index", "content_category": "directory_index",
        "storage_policy": "safe_summary", "site_card_id": card_id,
    }
    assert card == {"id": card_id, "primary_category": "directory_index"}


def test_ocr_unavailable_creates_explicit_unchecked_preview_state(isolated_db, tmp_path, monkeypatch):
    _insert_crawled()
    storage.create_page_preview_job(URL)
    output = tmp_path / "preview.png"
    output.write_bytes(b"png")
    fake_ocr = types.ModuleType("image_ocr")
    fake_ocr.extract_text = lambda _path: (_ for _ in ()).throw(RuntimeError("missing tesseract"))
    monkeypatch.setitem(sys.modules, "image_ocr", fake_ocr)
    monkeypatch.setattr(preview_worker, "screenshot_support_status", lambda: (True, "ready"))
    monkeypatch.setattr(preview_worker.storage, "preview_capture_limit_reached", lambda: False)
    monkeypatch.setattr(preview_worker, "capture_page_screenshot", lambda _url: str(output))
    monkeypatch.setenv("PREVIEW_REQUIRE_OCR", "false")
    from config_loader import get_config
    get_config.cache_clear()

    assert preview_worker.process_preview_job("preview-a") is True

    preview = storage.get_page_preview(URL)
    assert preview["status"] == "available_ocr_unchecked"
    assert preview["preview_path"] == str(output)


def test_ocr_required_blocks_when_ocr_unavailable(isolated_db, tmp_path, monkeypatch):
    _insert_crawled()
    storage.create_page_preview_job(URL)
    output = tmp_path / "preview.png"
    output.write_bytes(b"png")
    fake_ocr = types.ModuleType("image_ocr")
    fake_ocr.extract_text = lambda _path: (_ for _ in ()).throw(RuntimeError("missing tesseract"))
    monkeypatch.setitem(sys.modules, "image_ocr", fake_ocr)
    monkeypatch.setattr(preview_worker, "screenshot_support_status", lambda: (True, "ready"))
    monkeypatch.setattr(preview_worker.storage, "preview_capture_limit_reached", lambda: False)
    monkeypatch.setattr(preview_worker, "capture_page_screenshot", lambda _url: str(output))
    monkeypatch.setenv("PREVIEW_REQUIRE_OCR", "true")
    from config_loader import get_config
    get_config.cache_clear()

    assert preview_worker.process_preview_job("preview-a") is True

    assert not output.exists()
    preview = storage.get_page_preview(URL)
    assert preview is None or preview["status"] == "blocked"


def test_failed_preview_capture_keeps_claim_lifecycle_and_schedules_retry(isolated_db, monkeypatch):
    _insert_crawled()
    storage.create_page_preview_job(URL)
    monkeypatch.setattr(preview_worker, "screenshot_support_status", lambda: (True, "ready"))
    monkeypatch.setattr(preview_worker.storage, "preview_capture_limit_reached", lambda: False)
    monkeypatch.setattr(preview_worker, "capture_page_screenshot", lambda _url: None)

    assert preview_worker.process_preview_job("preview-a") is True

    with storage.get_db() as db:
        job = db.execute("SELECT status,last_error FROM page_preview_jobs WHERE url=?", (URL,)).fetchone()
        preview = db.execute("SELECT status FROM page_previews WHERE url=?", (URL,)).fetchone()
    assert job["status"] == "retry"
    assert job["last_error"] == "preview_capture_unavailable"
    assert preview["status"] == "failed"


def test_manual_preview_jobs_are_claimed_before_auto_jobs(isolated_db):
    host2 = "m" * 56 + ".onion"
    auto_url = URL
    manual_url = f"http://{host2}/"
    _insert_crawled(auto_url)
    _insert_crawled(manual_url)
    storage.create_page_preview_job(auto_url)
    storage.create_page_preview_job(manual_url, priority="manual", requested_by="dashboard")

    claimed = storage.claim_next_page_preview_job("preview-a")

    assert claimed["url"] == manual_url


def test_missing_chromium_is_reported_separately_from_disabled(monkeypatch):
    monkeypatch.setenv("ENABLE_PAGE_SCREENSHOTS", "true")
    from config_loader import get_config
    get_config.cache_clear()
    fake_sync = types.ModuleType("playwright.sync_api")
    fake_playwright = types.ModuleType("playwright")
    fake_playwright.__file__ = __file__
    fake_playwright.__path__ = []
    fake_playwright.sync_api = fake_sync
    monkeypatch.setitem(sys.modules, "playwright", fake_playwright)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_sync)
    monkeypatch.setattr(screenshot_service, "_playwright_chromium_installed", lambda: False)

    available, reason = screenshot_service.screenshot_support_status()

    assert available is False
    assert "Chromium" in reason


def test_exact_root_canonicalization_allows_same_document_root():
    assert screenshot_service._document_equivalent(f"http://{HOST}", f"http://{HOST}/")
    assert screenshot_service._document_equivalent(f"http://{HOST}/index.php", f"http://{HOST}/")
    assert not screenshot_service._document_equivalent(f"http://{HOST}/style.css", f"http://{HOST}/")
    assert not screenshot_service._document_equivalent(f"http://{'q' * 56}.onion/", f"http://{HOST}/")


def test_parallel_preview_workers_cannot_claim_same_job(isolated_db):
    _insert_crawled()
    job_id = storage.create_page_preview_job(URL)

    first = storage.claim_next_page_preview_job("preview-a")
    second = storage.claim_next_page_preview_job("preview-b")

    assert first and first["id"] == job_id
    assert second is None
    with storage.get_db() as db:
        row = db.execute("SELECT status,claimed_by FROM page_preview_jobs WHERE id=?", (job_id,)).fetchone()
    assert dict(row) == {"status": "claimed", "claimed_by": "preview-a"}


def test_stale_preview_claim_recovers_after_timeout(isolated_db):
    _insert_crawled()
    storage.create_page_preview_job(URL)
    assert storage.claim_next_page_preview_job("preview-a")
    with storage.get_db() as db:
        db.execute("UPDATE page_preview_jobs SET claimed_at='2000-01-01T00:00:00Z' WHERE url=?", (URL,))

    recovered = storage.claim_next_page_preview_job("preview-b", claim_timeout_minutes=45)

    assert recovered and recovered["url"] == URL
    with storage.get_db() as db:
        row = db.execute("SELECT status,claimed_by FROM page_preview_jobs WHERE url=?", (URL,)).fetchone()
    assert dict(row) == {"status": "claimed", "claimed_by": "preview-b"}


def test_stale_preview_owner_cannot_finish_reclaimed_job(isolated_db):
    _insert_crawled()
    job_id = storage.create_page_preview_job(URL)
    assert storage.claim_next_page_preview_job("preview-a")
    with storage.get_db() as db:
        db.execute("UPDATE page_preview_jobs SET claimed_at='2000-01-01T00:00:00Z' WHERE id=?", (job_id,))
    assert storage.claim_next_page_preview_job("preview-b")

    assert storage.finish_page_preview_job(
        job_id, success=True, preview_path="stale.png", worker_id="preview-a") is False
    with storage.get_db() as db:
        row = db.execute("SELECT status,claimed_by FROM page_preview_jobs WHERE id=?", (job_id,)).fetchone()
        preview = db.execute("SELECT 1 FROM page_previews WHERE url=?", (URL,)).fetchone()
    assert dict(row) == {"status": "claimed", "claimed_by": "preview-b"}
    assert preview is None

    assert storage.finish_page_preview_job(
        job_id, success=True, preview_path="current.png", worker_id="preview-b") is True
    assert storage.get_page_preview(URL)["preview_path"] == "current.png"


def test_preview_loop_disabled_configuration_does_not_exit_restart_loop(monkeypatch):
    calls = {}

    def fake_run(*, workers=1, once=False):
        calls["workers"] = workers
        calls["once"] = once

    monkeypatch.setenv("ONION_CRAWLER_ENABLED", "true")
    monkeypatch.setenv("ENABLE_PAGE_SCREENSHOTS", "false")
    monkeypatch.setattr(preview_worker, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["preview_worker.py", "--loop", "--workers", "2"])

    preview_worker.main()

    assert calls == {"workers": 2, "once": False}
