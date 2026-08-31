
import artifact_hygiene
import storage


def _policy():
    return {
        "primary_category": "directory_index", "category": "directory_index",
        "storage_policy": "safe_summary", "review_status": "monitor",
        "screenshot_policy": "allowed", "queue_policy": "expand", "active": 1,
        "risk_level": "low", "confidence": "medium", "tags": [],
    }


def test_workspace_hygiene_detects_runtime_artifacts(tmp_path):
    (tmp_path / "messages.db").write_text("db")
    (tmp_path / "bot_alert_session.session").write_text("session")
    (tmp_path / "user_scraper_session.session").write_text("session")
    (tmp_path / ".env").write_text("SECRET=x")
    (tmp_path / "reports").mkdir()
    (tmp_path / "__pycache__").mkdir()

    result = artifact_hygiene.scan_workspace_hygiene(tmp_path)

    assert not result["pass"]
    assert result["highest_severity"] == "critical"
    assert result["by_type"]["database"] == 1
    assert result["by_type"]["session"] == 2
    assert result["by_type"]["secret_env"] == 1
    assert result["by_type"]["generated_dir:reports"] == 1
    assert result["by_type"]["cache_dir:__pycache__"] == 1


def test_workspace_hygiene_reports_virtualenv_once_without_walking_contents(tmp_path):
    virtualenv = tmp_path / ".venv"
    package = virtualenv / "Lib" / "site-packages" / "example"
    package.mkdir(parents=True)
    (package / "module.py").write_text("value = 1\n", encoding="utf-8")
    (package / "module.pyc").write_bytes(b"cache")

    result = artifact_hygiene.scan_workspace_hygiene(tmp_path)

    assert not result["pass"]
    assert result["by_type"] == {"virtualenv_dir:.venv": 1}
    assert result["highest_severity"] == "high"
    assert result["findings"][0]["path"] == ".venv"


def test_safe_cleanup_removes_cache_but_not_sensitive_files(tmp_path):
    pycache = tmp_path / "__pycache__"
    pycache.mkdir()
    (pycache / "x.pyc").write_bytes(b"pyc")
    db = tmp_path / "messages.db"
    session = tmp_path / "bot_alert_session.session"
    db.write_text("db")
    session.write_text("session")

    result = artifact_hygiene.clean_workspace_junk(tmp_path, dry_run=False)

    assert result["removed"] >= 1
    assert not pycache.exists()
    assert db.exists()
    assert session.exists()


def test_fetched_page_retry_backoff_and_dead_letter(isolated_db):
    host = "w" * 56 + ".onion"
    url = f"http://{host}/"
    url_id = storage.insert_or_update_onion_url(url, host, status="classification_pending", policy=_policy())
    snapshot_id = storage.store_fetched_page_snapshot(
        url_id, url, worker_id="fetch", response_status=200, content_type="text/html",
        headers={}, title="Test", meta_text="", visible_text="safe",
        link_records=[], page_structure={}, pre_policy=_policy(),
    )

    storage.mark_fetched_page_error(snapshot_id, "TimeoutError: temporary tor timeout")
    assert storage.claim_next_fetched_page("verify-now") is None
    with storage.get_db() as db:
        db.execute("UPDATE fetched_pages SET next_retry_at='2000-01-01T00:00:00Z' WHERE id=?", (snapshot_id,))
    assert storage.claim_next_fetched_page("verify-later")

    storage.mark_fetched_page_error(snapshot_id, "KeyError: category contract")
    storage.mark_fetched_page_error(snapshot_id, "KeyError: category contract")
    with storage.get_db() as db:
        row = db.execute("SELECT classification_status,dead_letter_reason FROM fetched_pages WHERE id=?",
                         (snapshot_id,)).fetchone()
    assert row["classification_status"] == "dead_letter"
    assert row["dead_letter_reason"]


def test_card_job_retry_backoff_and_dead_letter(isolated_db):
    host = "c" * 56 + ".onion"
    url = f"http://{host}/"
    url_id = storage.insert_or_update_onion_url(url, host, status="crawled", policy=_policy())
    job_id = storage.create_site_card_job(onion_url_id=url_id, url=url, priority=1)
    assert storage.claim_next_site_card_job("card-a")

    storage.finish_site_card_job(job_id, success=False, error="TimeoutError: temporary db busy")
    assert storage.claim_next_site_card_job("card-now") is None
    with storage.get_db() as db:
        db.execute("UPDATE site_card_jobs SET next_retry_at='2000-01-01T00:00:00Z' WHERE id=?", (job_id,))
    assert storage.claim_next_site_card_job("card-later")

    storage.finish_site_card_job(job_id, success=False, error="ValueError: invariant broken")
    storage.finish_site_card_job(job_id, success=False, error="ValueError: invariant broken")
    with storage.get_db() as db:
        row = db.execute("SELECT status,dead_letter_reason FROM site_card_jobs WHERE id=?", (job_id,)).fetchone()
    assert row["status"] == "dead_letter"
    assert row["dead_letter_reason"]
