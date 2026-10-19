from datetime import datetime
import json
from pathlib import Path
import zipfile

import pytest

import backup_service
import daily_activity
import site_dedupe
import storage


HOST = "w" * 56 + ".onion"
URL = f"http://{HOST}/thread/1"


def _spain_policy():
    return {
        "primary_category": "weapons_arms", "category": "weapons_arms",
        "content_category": "weapons_arms", "page_type": "forum_thread",
        "analyst_category": "weapons_arms", "classification_evidence_source": "analyst",
        "tags": ["weapons_arms", "spain_priority"], "risk_level": "high",
        "confidence": "high", "category_confidence": "high", "risk_flags": [],
        "storage_policy": "safe_summary", "review_status": "needs_review",
        "screenshot_policy": "allowed", "queue_policy": "expand", "active": 1,
        "priority_score": 90, "spain_priority": True, "spain_confidence": "high",
        "spain_match_reason": "shipping to Spain", "spain_priority_reason": "spanish_market_targeting",
        "spain_priority_evidence_type": "spanish_market_targeting",
        "classification_decision": "needs_review", "ui_hidden_default": 0,
    }


def _insert_analyst_url(url, policy):
    url_id = storage.insert_or_update_onion_url(url, HOST, status="crawled")
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET analyst_category=? WHERE id=?",
                   (policy["analyst_category"], url_id))
    storage.apply_onion_policy(url, policy)
    return url_id


def test_opening_spain_card_acknowledges_alert_without_removing_classification(isolated_db):
    policy = _spain_policy()
    url_id = _insert_analyst_url(URL, policy)
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Spain thread")
    storage.queue_spain_alert(URL, policy)
    assert storage.acknowledge_spain_card_open(card_id) == 1
    assert storage.acknowledge_spain_card_open(card_id) == 0
    row = storage.get_onion_url_by_url(URL)
    assert row["spain_review_status"] == "opened"
    assert row["spain_priority"] == 1
    assert row["classification_decision"] == "needs_review"
    assert storage.get_pending_spain_alerts() == []


def test_saved_investigations_are_seeded_and_custom_filters_persist(isolated_db):
    builtins = storage.get_saved_investigations()
    assert any(row["name"] == "Spain · Weapons" and row["builtin"] for row in builtins)
    item_id = storage.save_investigation("My review", "Focused review", {
        "priority": "High risk", "risk": "high", "unsafe": "ignored"})
    row = next(row for row in storage.get_saved_investigations() if row["id"] == item_id)
    assert json.loads(row["filters_json"]) == {"priority": "High risk", "risk": "high"}
    assert storage.delete_investigation(item_id)


def test_daily_digest_records_safe_operational_counts(isolated_db):
    today = datetime.now(daily_activity.MADRID).date()
    storage.insert_crawl_audit(URL, "fetch", "classification_pending", "snapshot_stored")
    storage.insert_crawl_audit(URL, "verify", "completed", "safe")
    # A legacy completion row for the same URL must not double count it.
    storage.insert_crawl_audit(URL, "fetch", "completed", "safe")
    storage.insert_or_update_onion_url(URL, HOST, status="crawled", policy=_spain_policy())
    digest = daily_activity.build_daily_digest(today)
    assert digest["pages_completed"] == 1
    assert digest["new_urls"] == 1
    assert "queue_remaining" in digest and "recent_actions" in digest
    assert digest["classification_quality"]["window_days"] == 30
    assert "unknown_rate" in digest["classification_quality"]
    assert daily_activity.format_digest(digest).startswith("ARACHNE DAILY ACTIVITY")
    storage.store_daily_digest(today.isoformat(), digest, telegram_pending=True)
    assert storage.get_pending_daily_digests()[0]["digest_date"] == today.isoformat()
    storage.mark_daily_digest_sent(today.isoformat())
    assert storage.get_pending_daily_digests() == []


def test_notification_preferences_control_immediate_spain_and_digest(isolated_db):
    storage.set_notification_preferences(immediate_spain=False, daily_digest_telegram=True)
    prefs = storage.notification_preferences()
    assert prefs["spain_alerts_paused"] == 1
    assert prefs["immediate_spain_alerts"] == 0
    assert prefs["daily_digest_telegram"] == 1


def test_daily_backup_is_integrity_checked_and_retains_seven(isolated_db, tmp_path, monkeypatch):
    backups = tmp_path / "backups"
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "summary.md").write_text("safe report", encoding="utf-8")
    preview = reports / "previews"
    preview.mkdir()
    (preview / "ignored.png").write_bytes(b"not included")
    monkeypatch.setattr(backup_service, "DB_PATH", isolated_db)
    monkeypatch.setattr(backup_service, "BACKUPS_DIR", backups)
    monkeypatch.setattr(backup_service, "REPORTS_DIR", reports)
    for day in range(1, 9):
        backups.mkdir(exist_ok=True)
        with zipfile.ZipFile(backups / f"arachne-daily-2020-01-{day:02d}.zip", "w") as archive:
            archive.writestr("old", "x")
    result = backup_service.create_daily_backup(keep_days=7, force=True)
    assert result["created"] == 1 and len(backup_service.list_backups()) == 7
    with zipfile.ZipFile(result["path"]) as archive:
        assert "messages.db" in archive.namelist()
        assert "reports/summary.md" in archive.namelist()
        assert not any("previews" in name for name in archive.namelist())
    staged = backup_service.prepare_restore(Path(result["path"]).name)
    assert staged["prepared"] == 1


def test_corrupt_daily_archive_is_rebuilt_instead_of_reused(isolated_db, tmp_path, monkeypatch):
    monkeypatch.setattr(backup_service, "DB_PATH", isolated_db)
    monkeypatch.setattr(backup_service, "BACKUPS_DIR", tmp_path / "backups")
    monkeypatch.setattr(backup_service, "REPORTS_DIR", tmp_path / "no-reports")
    first = backup_service.create_daily_backup()
    Path(first["path"]).write_bytes(b"truncated archive")

    repaired = backup_service.create_daily_backup()
    assert repaired["created"] == 1
    assert repaired["repaired"] == 1
    with zipfile.ZipFile(repaired["path"]) as archive:
        assert archive.testzip() is None
        assert "messages.db" in archive.namelist()


def test_daily_backup_does_not_create_an_empty_missing_database(tmp_path, monkeypatch):
    missing = tmp_path / "missing.db"
    monkeypatch.setattr(backup_service, "DB_PATH", missing)
    monkeypatch.setattr(backup_service, "BACKUPS_DIR", tmp_path / "backups")

    with pytest.raises(FileNotFoundError):
        backup_service.create_daily_backup(force=True)

    assert not missing.exists()


def test_previous_backup_prefix_is_supported_without_duplicate_patterns(tmp_path, monkeypatch):
    backups = tmp_path / "backups"
    backups.mkdir()
    current = backups / "arachne-daily-2026-08-31.zip"
    previous = backups / "previous-prefix-daily-2026-08-30.zip"
    current.write_bytes(b"current")
    previous.write_bytes(b"previous")
    monkeypatch.setattr(backup_service, "BACKUPS_DIR", backups)
    monkeypatch.setenv("ARACHNE_PREVIOUS_BACKUP_PREFIX", "previous-prefix")

    assert backup_service._backup_patterns() == (
        "arachne-daily-*.zip", "previous-prefix-daily-*.zip")
    assert {item["name"] for item in backup_service.list_backups()} == {
        current.name, previous.name}


def test_previous_backup_prefix_rejects_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_service, "BACKUPS_DIR", tmp_path)
    monkeypatch.setenv("ARACHNE_PREVIOUS_BACKUP_PREFIX", "../unsafe")

    with pytest.raises(ValueError, match="safe filename prefix"):
        backup_service.list_backups()
