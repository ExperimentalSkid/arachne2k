import sqlite3

import dashboard_auth
import storage


def _tables(path):
    with sqlite3.connect(path) as db:
        return {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }


def test_fresh_and_legacy_main_database_receive_current_schema_version(
        tmp_path, monkeypatch):
    fresh = tmp_path / "fresh.db"
    monkeypatch.setattr(storage, "DB_PATH", fresh)
    storage.init_db()
    with sqlite3.connect(fresh) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == storage.MAIN_SCHEMA_VERSION

    legacy = tmp_path / "legacy.db"
    with sqlite3.connect(legacy) as db:
        db.execute(
            """
            CREATE TABLE onion_urls (
              id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE,
              onion_domain TEXT, source_url TEXT, source_type TEXT,
              depth INTEGER DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT,
              last_crawled TEXT, next_crawl_at TEXT, status TEXT DEFAULT 'new',
              http_status INTEGER, title TEXT, content_hash TEXT, fuzzy_hash TEXT,
              relevance_score INTEGER DEFAULT 0, risk_score INTEGER DEFAULT 0,
              risk_level TEXT DEFAULT 'NULO', reasons TEXT, risk_flags TEXT,
              review_status TEXT DEFAULT 'pending', error_count INTEGER DEFAULT 0,
              last_error TEXT
            )
            """
        )
        assert db.execute("PRAGMA user_version").fetchone()[0] == 0
    monkeypatch.setattr(storage, "DB_PATH", legacy)
    storage.init_db()
    with sqlite3.connect(legacy) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == storage.MAIN_SCHEMA_VERSION
        assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"


def test_main_database_from_newer_release_is_rejected_before_schema_writes(
        tmp_path, monkeypatch):
    future = tmp_path / "future.db"
    with sqlite3.connect(future) as db:
        db.execute("CREATE TABLE future_release_marker(id INTEGER PRIMARY KEY)")
        db.execute(f"PRAGMA user_version = {storage.MAIN_SCHEMA_VERSION + 1}")
    before = _tables(future)
    monkeypatch.setattr(storage, "DB_PATH", future)

    try:
        storage.init_db()
    except sqlite3.DatabaseError as exc:
        assert "main_database_schema_is_newer_than_this_release" in str(exc)
    else:
        raise AssertionError("newer main schema was accepted")

    assert _tables(future) == before
    with sqlite3.connect(future) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == storage.MAIN_SCHEMA_VERSION + 1


def test_access_database_versions_legacy_schema_and_preserves_role_upgrade(
        tmp_path, monkeypatch):
    access = tmp_path / "dashboard_access.db"
    with sqlite3.connect(access) as db:
        db.executescript(
            """
            CREATE TABLE dashboard_access_codes (
              id INTEGER PRIMARY KEY, code_hash TEXT NOT NULL, code_salt TEXT NOT NULL,
              created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT,
              used_at TEXT, created_by_telegram_id TEXT, duration_seconds INTEGER NOT NULL
            );
            CREATE TABLE dashboard_sessions (
              id INTEGER PRIMARY KEY, session_hash TEXT NOT NULL UNIQUE,
              created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT,
              source_code_id INTEGER, user_agent TEXT, ip_hint TEXT
            );
            """
        )
    monkeypatch.setattr(dashboard_auth, "AUTH_DB_PATH", access)
    monkeypatch.setattr(dashboard_auth, "_AUTH_SCHEMA_READY_PATH", None)

    ready, error = dashboard_auth._access_storage_ready()

    assert ready is True and error is None
    with sqlite3.connect(access) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == dashboard_auth.AUTH_SCHEMA_VERSION
        for table in ("dashboard_access_codes", "dashboard_sessions"):
            columns = {
                row[1] for row in db.execute(f"PRAGMA table_info({table})")
            }
            assert "role" in columns


def test_access_database_from_newer_release_fails_closed_without_schema_writes(
        tmp_path, monkeypatch):
    future = tmp_path / "future-access.db"
    with sqlite3.connect(future) as db:
        db.execute("CREATE TABLE future_access_marker(id INTEGER PRIMARY KEY)")
        db.execute(f"PRAGMA user_version = {dashboard_auth.AUTH_SCHEMA_VERSION + 1}")
    before = _tables(future)
    monkeypatch.setattr(dashboard_auth, "AUTH_DB_PATH", future)
    monkeypatch.setattr(dashboard_auth, "_AUTH_SCHEMA_READY_PATH", None)

    ready, error = dashboard_auth._access_storage_ready()

    assert ready is False
    assert isinstance(error, sqlite3.DatabaseError)
    assert "access_database_schema_is_newer_than_this_release" in str(error)
    assert _tables(future) == before
    with sqlite3.connect(future) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == dashboard_auth.AUTH_SCHEMA_VERSION + 1
