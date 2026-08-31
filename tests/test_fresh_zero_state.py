import sqlite3

import dashboard_auth
import storage


def test_fresh_zero_state_bootstraps_complete_pipeline_and_access_storage(
        tmp_path, monkeypatch):
    main_db = tmp_path / "messages.db"
    access_db = tmp_path / "runtime" / "dashboard_access.db"
    monkeypatch.setattr(storage, "DB_PATH", main_db)
    monkeypatch.setattr(storage, "_ENSURE_DONE_FOR_PATH", None)
    monkeypatch.setattr(dashboard_auth, "AUTH_DB_PATH", access_db)
    monkeypatch.setattr(dashboard_auth, "_AUTH_SCHEMA_READY_PATH", None)
    monkeypatch.delenv("DASHBOARD_LOCK_ENABLED", raising=False)

    storage.init_db()
    access = dashboard_auth.dashboard_access_status()

    required_tables = {
        "onion_urls",
        "fetched_pages",
        "site_cards",
        "site_card_jobs",
        "page_preview_jobs",
        "worker_instances",
        "deep_discovery_jobs",
        "deep_discovery_runs",
    }
    with sqlite3.connect(main_db) as db:
        existing = {
            row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert required_tables <= existing
        assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        for table in (
            "onion_urls",
            "fetched_pages",
            "site_cards",
            "site_card_jobs",
            "page_preview_jobs",
            "deep_discovery_jobs",
            "deep_discovery_runs",
        ):
            assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0

    assert access.get("storage_error") is None
    assert access["enabled"] is True
    missing_session = dashboard_auth.validate_dashboard_session(None)
    assert missing_session["ok"] is False
    assert missing_session["reason"] == "missing"
    assert access_db.is_file()
    with sqlite3.connect(access_db) as db:
        assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        tables = {
            row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    assert {
        "dashboard_access_state",
        "dashboard_access_codes",
        "dashboard_sessions",
        "dashboard_access_events",
    } <= tables
