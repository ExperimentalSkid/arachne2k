from datetime import datetime, timedelta, timezone
from pathlib import Path
import asyncio
import re
import sqlite3
import threading

import pytest
from streamlit.testing.v1 import AppTest

import dashboard_auth
import storage


ROOT = Path(__file__).parents[1]


def test_dashboard_code_is_hashed_one_time_and_creates_session(isolated_db):
    result = dashboard_auth.generate_dashboard_code(900, 12345)
    code = result["code"]
    with dashboard_auth._auth_db() as db:
        row = dict(db.execute("SELECT * FROM dashboard_access_codes").fetchone())
    assert code.replace("-", "") not in row["code_hash"]
    assert row["code_salt"]

    login = dashboard_auth.consume_dashboard_code(code)
    assert login["ok"] is True
    assert dashboard_auth.validate_dashboard_session(login["session_token"])["ok"] is True
    assert dashboard_auth.consume_dashboard_code(code)["ok"] is False


def test_dashboard_code_defaults_to_admin_and_returns_capabilities(isolated_db):
    result = dashboard_auth.generate_dashboard_code(900, 12345)
    assert result["role"] == dashboard_auth.ROLE_ADMIN
    assert dashboard_auth.CAPABILITY_ACCESS_MANAGE in result["capabilities"]
    with dashboard_auth._auth_db() as db:
        assert db.execute(
            "SELECT role FROM dashboard_access_codes WHERE id=?",
            (result["id"],),
        ).fetchone()["role"] == dashboard_auth.ROLE_ADMIN

    login = dashboard_auth.consume_dashboard_code(result["code"])
    status = dashboard_auth.validate_dashboard_session(login["session_token"])
    assert login["role"] == dashboard_auth.ROLE_ADMIN
    assert status["role"] == dashboard_auth.ROLE_ADMIN
    assert dashboard_auth.has_capability(
        status, dashboard_auth.CAPABILITY_ACCESS_MANAGE)


def test_demo_readonly_session_cannot_authorize_mutations(isolated_db):
    result = dashboard_auth.generate_dashboard_code(
        900, 123, role=dashboard_auth.ROLE_DEMO_READONLY)
    login = dashboard_auth.consume_dashboard_code(result["code"])
    status = dashboard_auth.validate_dashboard_session(login["session_token"])

    assert status["role"] == dashboard_auth.ROLE_DEMO_READONLY
    assert status["capabilities"] == [dashboard_auth.CAPABILITY_DASHBOARD_VIEW]
    assert dashboard_auth.can_mutate(status) is False
    assert all(
        not dashboard_auth.has_capability(status, capability)
        for capability in dashboard_auth.MUTATING_CAPABILITIES
    )
    denied = dashboard_auth.authorize_dashboard_session(
        login["session_token"], dashboard_auth.CAPABILITY_SITE_CARDS_EDIT)
    assert denied["ok"] is False
    assert denied["reason"] == "forbidden"
    with pytest.raises(PermissionError, match="capability_denied"):
        dashboard_auth.require_capability(
            status, dashboard_auth.CAPABILITY_REVIEWS_MANAGE)

    rotated = dashboard_auth.rotate_dashboard_session(login["session_token"])
    assert rotated["role"] == dashboard_auth.ROLE_DEMO_READONLY
    assert dashboard_auth.validate_dashboard_session(
        rotated["session_token"])["role"] == dashboard_auth.ROLE_DEMO_READONLY


def test_analyst_role_is_bounded_and_unknown_roles_fail_closed(isolated_db):
    result = dashboard_auth.generate_dashboard_code(
        900, 123, role=dashboard_auth.ROLE_ANALYST)
    login = dashboard_auth.consume_dashboard_code(result["code"])
    status = dashboard_auth.validate_dashboard_session(login["session_token"])
    assert dashboard_auth.has_capability(
        status, dashboard_auth.CAPABILITY_SITE_CARDS_EDIT)
    assert dashboard_auth.has_capability(
        status, dashboard_auth.CAPABILITY_REPORTS_CREATE)
    assert not dashboard_auth.has_capability(
        status, dashboard_auth.CAPABILITY_ACCESS_MANAGE)
    assert not dashboard_auth.has_capability(
        status, dashboard_auth.CAPABILITY_CRAWLER_MANAGE)

    invalid = dashboard_auth.generate_dashboard_code(900, 123, role="superuser")
    assert invalid["ok"] is False
    assert invalid["reason"] == "invalid_role"
    assert "code" not in invalid
    assert dashboard_auth.capabilities_for_role("superuser") == ()

    with dashboard_auth._auth_db() as db:
        db.execute(
            "UPDATE dashboard_sessions SET role='superuser' WHERE session_hash=?",
            (dashboard_auth._session_hash(login["session_token"]),),
        )
    invalid_session = dashboard_auth.validate_dashboard_session(
        login["session_token"])
    assert invalid_session["ok"] is False
    assert invalid_session["reason"] == "invalid_role"
    assert invalid_session["capabilities"] == []


def test_legacy_access_database_migrates_codes_and_sessions_to_admin(
        tmp_path, monkeypatch):
    auth_db = tmp_path / "legacy-dashboard-access.db"
    with sqlite3.connect(auth_db) as db:
        db.executescript("""
        CREATE TABLE dashboard_access_codes (
          id INTEGER PRIMARY KEY AUTOINCREMENT, code_hash TEXT NOT NULL,
          code_salt TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
          revoked_at TEXT, used_at TEXT, created_by_telegram_id TEXT,
          duration_seconds INTEGER NOT NULL
        );
        CREATE TABLE dashboard_sessions (
          id INTEGER PRIMARY KEY AUTOINCREMENT, session_hash TEXT NOT NULL UNIQUE,
          created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT,
          source_code_id INTEGER, user_agent TEXT, ip_hint TEXT
        );
        INSERT INTO dashboard_access_codes
          (code_hash,code_salt,created_at,expires_at,created_by_telegram_id,duration_seconds)
          VALUES('hash','salt','2026-01-01T00:00:00Z','2099-01-01T00:00:00Z','1',900);
        INSERT INTO dashboard_sessions
          (session_hash,created_at,expires_at,source_code_id,user_agent,ip_hint)
          VALUES('session-hash','2026-01-01T00:00:00Z','2099-01-01T00:00:00Z',1,'u','i');
        """)
    monkeypatch.setattr(dashboard_auth, "AUTH_DB_PATH", auth_db)
    monkeypatch.setattr(dashboard_auth, "_AUTH_SCHEMA_READY_PATH", None)

    ready, error = dashboard_auth._access_storage_ready()
    assert ready is True
    assert error is None
    with dashboard_auth._auth_db() as db:
        code_columns = {
            row["name"] for row in db.execute(
                "PRAGMA table_info(dashboard_access_codes)")
        }
        session_columns = {
            row["name"] for row in db.execute(
                "PRAGMA table_info(dashboard_sessions)")
        }
        assert db.execute(
            "SELECT role FROM dashboard_access_codes WHERE id=1").fetchone()["role"] == "admin"
        assert db.execute(
            "SELECT role FROM dashboard_sessions WHERE id=1").fetchone()["role"] == "admin"
    assert "role" in code_columns
    assert "role" in session_columns


def test_dashboard_code_duration_accepts_custom_minutes():
    assert dashboard_auth.duration_seconds("7") == 7 * 60
    assert dashboard_auth.duration_seconds("37m") == 37 * 60
    assert dashboard_auth.duration_seconds("90 minutes") == 90 * 60
    assert dashboard_auth.duration_seconds("2h") == 2 * 3600


def test_expired_and_revoked_codes_fail(isolated_db):
    expired = dashboard_auth.generate_dashboard_code(60, 1)
    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
    with dashboard_auth._auth_db() as db:
        db.execute("UPDATE dashboard_access_codes SET expires_at=?", (past,))
    assert dashboard_auth.consume_dashboard_code(expired["code"])["ok"] is False

    active = dashboard_auth.generate_dashboard_code(900, 1)
    dashboard_auth.revoke_dashboard_codes()
    assert dashboard_auth.consume_dashboard_code(active["code"])["ok"] is False


def test_dashboard_lock_toggle_revokes_sessions(isolated_db):
    result = dashboard_auth.generate_dashboard_code(900, 123)
    login = dashboard_auth.consume_dashboard_code(result["code"])
    assert dashboard_auth.validate_dashboard_session(login["session_token"])["ok"] is True

    dashboard_auth.set_dashboard_lock_enabled(False, "pytest")

    status = dashboard_auth.dashboard_access_status()
    assert status["enabled"] is False
    assert status["active_sessions"] == 0


def test_dashboard_route_blocked_without_session_and_unlocks_with_code(isolated_db):
    result = dashboard_auth.generate_dashboard_code(900, 123)
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    assert not app.exception
    rendered = "\n".join(str(item.value) for item in app.markdown)
    assert "Workspace access" in rendered
    assert "Code available" in rendered
    assert "Code is active. The field is unlocked and ready." in rendered
    assert "Telegram" not in rendered
    assert not app.sidebar.radio
    assert app.text_input[0].disabled is False

    app.text_input[0].set_value(result["code"])
    app.button[0].click().run()

    assert not app.exception
    assert any("Session expires in" in str(item.value) for item in app.markdown)
    assert app.sidebar.radio


def test_secure_session_exit_renders_after_workspace_navigation_and_revokes(isolated_db):
    result = dashboard_auth.generate_dashboard_code(900, 123)
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    app.text_input[0].set_value(result["code"])
    app.button[0].click().run()

    assert not app.exception
    sidebar_buttons = list(app.sidebar.button)
    assert sidebar_buttons[0].key == "sidebar-add-source"
    exit_button = next(item for item in sidebar_buttons if item.key == "end-secure-session")
    assert sidebar_buttons[-1].key == "end-secure-session"

    exit_button.click().run()
    assert not app.exception
    rendered = "\n".join(str(item.value) for item in app.markdown)
    assert "Workspace access" in rendered
    assert dashboard_auth.dashboard_access_status()["active_sessions"] == 0


def test_dashboard_lock_field_is_disabled_until_code_exists(isolated_db):
    dashboard_auth.set_dashboard_lock_enabled(True, "pytest")
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    assert not app.exception
    rendered = "\n".join(str(item.value) for item in app.markdown)
    assert "No active code" in rendered
    assert "Telegram" not in rendered
    assert app.text_input[0].disabled is True
    assert app.button[0].disabled is True


def test_dashboard_session_survives_browser_refresh_via_query_token(isolated_db):
    result = dashboard_auth.generate_dashboard_code(900, 123)
    login = dashboard_auth.consume_dashboard_code(result["code"])
    assert login["ok"] is True

    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params["rt_session"] = login["session_token"]
    app.run()

    assert not app.exception
    assert any("Session expires in" in str(item.value) for item in app.markdown)
    assert app.sidebar.radio
    rotated = app.query_params["rt_session"]
    if isinstance(rotated, list):
        rotated = rotated[0]
    assert rotated != login["session_token"]
    assert dashboard_auth.validate_dashboard_session(login["session_token"])["ok"] is False
    assert dashboard_auth.validate_dashboard_session(rotated)["ok"] is True


def test_dashboard_code_is_consumed_atomically_under_concurrency(isolated_db):
    result = dashboard_auth.generate_dashboard_code(900, 123)
    start = threading.Barrier(2)
    consumed = []

    def consume():
        start.wait(timeout=5)
        consumed.append(dashboard_auth.consume_dashboard_code(result["code"]))

    threads = [threading.Thread(target=consume) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert sum(bool(item.get("ok")) for item in consumed) == 1
    with dashboard_auth._auth_db() as db:
        assert db.execute("SELECT COUNT(*) FROM dashboard_sessions").fetchone()[0] == 1


def test_dashboard_login_attempts_are_throttled_per_hashed_client(isolated_db, monkeypatch):
    monkeypatch.setattr(dashboard_auth, "LOGIN_ATTEMPT_LIMIT", 3)
    result = dashboard_auth.generate_dashboard_code(900, 123)

    for _ in range(2):
        failed = dashboard_auth.consume_dashboard_code(
            "WRONG-CODE", user_agent="Browser A", ip_hint="192.0.2.10",
        )
        assert failed.get("reason") == "invalid"
    blocked = dashboard_auth.consume_dashboard_code(
        "WRONG-CODE", user_agent="Browser A", ip_hint="192.0.2.10",
    )
    assert blocked.get("reason") == "rate_limited"
    assert dashboard_auth.consume_dashboard_code(
        result["code"], user_agent="Browser A", ip_hint="192.0.2.10",
    ).get("reason") == "rate_limited"

    # A distinct client can still use the valid one-time code.
    login = dashboard_auth.consume_dashboard_code(
        result["code"], user_agent="Browser B", ip_hint="192.0.2.11",
    )
    assert login["ok"] is True
    with dashboard_auth._auth_db() as db:
        session = db.execute("SELECT user_agent,ip_hint FROM dashboard_sessions").fetchone()
    assert session["user_agent"].startswith("sha256:")
    assert session["ip_hint"].startswith("sha256:")
    assert "Browser B" not in session["user_agent"]
    assert "192.0.2.11" not in session["ip_hint"]


def test_dashboard_auth_does_not_depend_on_main_crawler_db(isolated_db, monkeypatch):
    def broken_init_db():
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(storage, "ensure_db_initialized", broken_init_db)
    result = dashboard_auth.generate_dashboard_code(900, 123)
    assert result["code"]
    login = dashboard_auth.consume_dashboard_code(result["code"])
    assert login["ok"] is True
    assert dashboard_auth.validate_dashboard_session(login["session_token"])["ok"] is True

    access = dashboard_auth.dashboard_access_status()
    assert access["enabled"] is True
    assert "storage_error" not in access


def test_telegram_code_path_uses_dedicated_auth_db_when_main_db_is_broken(isolated_db, monkeypatch):
    import arachne

    def broken_init_db():
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(storage, "ensure_db_initialized", broken_init_db)

    result = arachne.dashboard_auth.generate_dashboard_code(900, 222)
    message = arachne._format_dashboard_code_message(result)
    login = dashboard_auth.consume_dashboard_code(result["code"])

    assert "Dashboard access code" in message
    assert login["ok"] is True
    assert dashboard_auth.validate_dashboard_session(login["session_token"])["ok"] is True


def test_telegram_code_formatter_handles_generation_error_without_crashing():
    import arachne

    message = arachne._format_dashboard_code_message({
        "ok": False,
        "reason": "auth_storage_unavailable",
        "error": "disk I/O error",
    })

    assert "could not be created" in message
    assert "disk I/O error" in message


def test_telegram_access_buttons_have_distinct_clear_and_disable_actions():
    import arachne

    buttons = [button for row in arachne.main_menu_buttons(123) for button in row]
    labels = {getattr(button, "text", ""): getattr(button, "data", b"") for button in buttons}

    assert labels["Create access code"] == b"dashboard_code_custom"
    assert labels["Clear unused codes"] == b"dashboard_clear_codes"
    assert labels["Enable access page"] == b"dashboard_lock_on"
    assert labels["Disable access page"] == b"dashboard_lock_off"
    assert "Dashboard revoke" not in labels


def test_telegram_status_text_explains_code_clear_vs_lock_disable():
    import arachne

    text = arachne._format_dashboard_access_status()

    assert "/dashboard_clear_codes - clear unused codes only" in text
    assert "/dashboard_lock_off - disable the access-code page for development" in text


def test_dashboard_auth_store_error_fails_closed_without_crashing(monkeypatch):
    class BrokenConnection:
        def __enter__(self):
            raise sqlite3.OperationalError("disk I/O error")

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(dashboard_auth, "_auth_db", lambda: BrokenConnection())

    assert dashboard_auth.dashboard_lock_enabled() is True
    status = dashboard_auth.validate_dashboard_session("anything")
    assert status["ok"] is False
    assert status["lock_enabled"] is True
    assert status["reason"] == "auth_storage_unavailable"
    access = dashboard_auth.dashboard_access_status()
    assert access["enabled"] is True
    assert access["active_code"] is False


def test_telegram_dashboard_admin_check_uses_admin_ids(monkeypatch):
    import arachne

    class Event:
        sender_id = 222
        chat_id = 333

    monkeypatch.setattr(arachne, "admin_chat_id", 111)
    monkeypatch.setattr(arachne, "_telegram_admin_ids", lambda: {111, 222})
    assert arachne._is_dashboard_admin(Event()) is True

    monkeypatch.setattr(arachne, "_telegram_admin_ids", lambda: {111})
    assert arachne._is_dashboard_admin(Event()) is False


def test_telegram_menu_and_callbacks_reject_non_admin(monkeypatch):
    import arachne

    class Event:
        sender_id = 999
        chat_id = 999
        data = b"toggle_spain_alerts"

        def __init__(self):
            self.responses = []

        async def answer(self):
            return None

        async def respond(self, *args, **kwargs):
            self.responses.append((args, kwargs))

    monkeypatch.setattr(arachne, "_telegram_admin_ids", lambda: {111})
    mutation_calls = []
    monkeypatch.setattr(arachne.osint_storage, "set_spain_alerts_paused",
                        lambda *args: mutation_calls.append(args))

    menu_event = Event()
    asyncio.run(arachne.menu_handler(menu_event))
    assert menu_event.responses == [(('Not authorized.',), {})]

    callback_event = Event()
    asyncio.run(arachne.callback_handler(callback_event))
    assert callback_event.responses == [(('Not authorized.',), {})]
    assert mutation_calls == []


def test_telegram_menu_keeps_access_controls_when_main_db_is_unavailable(monkeypatch):
    import arachne

    monkeypatch.setattr(arachne, "db", None)
    monkeypatch.setattr(
        arachne.osint_storage, "spain_alerts_paused",
        lambda: (_ for _ in ()).throw(sqlite3.OperationalError("disk I/O error")),
    )
    buttons = [button for row in arachne.main_menu_buttons(123) for button in row]
    labels = {getattr(button, "text", "") for button in buttons}
    assert "Create access code" in labels
    assert "Spain alert status unavailable" in labels


def test_pending_media_input_does_not_crash_or_consume_action(monkeypatch):
    import arachne

    class Message:
        text = None

    class Event:
        sender_id = 111
        chat_id = 111
        message = Message()

        def __init__(self):
            self.responses = []

        async def respond(self, *args, **kwargs):
            self.responses.append((args, kwargs))

    monkeypatch.setattr(arachne, "_telegram_admin_ids", lambda: {111})
    arachne.pending_action[111] = "search"
    event = Event()
    try:
        asyncio.run(arachne.text_input_handler(event))
        assert arachne.pending_action[111] == "search"
        assert "Send text" in event.responses[0][0][0]
    finally:
        arachne.pending_action.pop(111, None)


def test_custom_code_minutes_work_without_main_database(monkeypatch):
    import arachne

    class Message:
        text = "37"

    class Event:
        sender_id = 111
        chat_id = 111
        message = Message()

        def __init__(self):
            self.responses = []

        async def respond(self, *args, **kwargs):
            self.responses.append((args, kwargs))

    generated = []
    monkeypatch.setattr(arachne, "_telegram_admin_ids", lambda: {111})
    monkeypatch.setattr(
        arachne.dashboard_auth, "generate_dashboard_code",
        lambda seconds, uid: generated.append((seconds, uid)) or {
            "code": "ABCD-EFGH", "expires_at": "later", "duration_seconds": seconds,
        },
    )
    monkeypatch.setattr(
        arachne, "_require_telegram_data",
        lambda _event: (_ for _ in ()).throw(AssertionError("main DB must not be touched")),
    )
    arachne.pending_action[111] = "dashboard_code_minutes"
    event = Event()
    try:
        asyncio.run(arachne.text_input_handler(event))
    finally:
        arachne.pending_action.pop(111, None)

    assert generated == [(37 * 60, 111)]
    assert "ABCD-EFGH" in event.responses[0][0][0]


def test_telegram_code_command_accepts_explicit_role_and_defaults_remain_admin(
        monkeypatch):
    import arachne

    class Event:
        sender_id = 111

        def __init__(self, raw_text):
            self.raw_text = raw_text
            self.responses = []

        async def respond(self, *args, **kwargs):
            self.responses.append((args, kwargs))

    async def authorized(_event):
        return True

    generated = []

    def generate(seconds, uid, role=dashboard_auth.ROLE_ADMIN):
        generated.append((seconds, uid, role))
        return {
            "code": "ABCD-EFGH",
            "expires_at": "later",
            "duration_seconds": seconds,
            "role": role,
        }

    monkeypatch.setattr(arachne, "_require_dashboard_admin", authorized)
    monkeypatch.setattr(arachne.dashboard_auth, "generate_dashboard_code", generate)

    analyst_event = Event("/dashboard_code 45m analyst")
    asyncio.run(arachne.dashboard_code_command(analyst_event))
    admin_event = Event("/dashboard_code 30m")
    asyncio.run(arachne.dashboard_code_command(admin_event))

    assert generated == [
        (45 * 60, 111, dashboard_auth.ROLE_ANALYST),
        (30 * 60, 111, dashboard_auth.ROLE_ADMIN),
    ]
    assert "Role: analyst" in analyst_event.responses[0][0][0]
    assert "Role: admin" in admin_event.responses[0][0][0]


def test_telegram_short_lived_db_session_rolls_back_and_closes_on_error(monkeypatch):
    import arachne

    class Connection:
        def __init__(self):
            self.committed = False
            self.rolled_back = False
            self.closed = False

        def execute(self, *_args):
            return self

        def commit(self):
            self.committed = True

        def rollback(self):
            self.rolled_back = True

        def close(self):
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(arachne.sqlite3, "connect", lambda *_args, **_kwargs: connection)

    with pytest.raises(RuntimeError, match="boom"):
        with arachne._telegram_db_session():
            raise RuntimeError("boom")

    assert connection.rolled_back is True
    assert connection.committed is False
    assert connection.closed is True


def test_keyword_repetition_uses_configured_patterns_without_legacy_globals(monkeypatch):
    import arachne

    class Cursor:
        def fetchall(self):
            return [("boom",), ("boom",), ("boom",)]

    class FakeDb:
        def execute(self, *_args, **_kwargs):
            return Cursor()

    configured = {
        "EXPLOSIVES": {
            "compiled_en": re.compile(r"boom", re.I),
            "compiled_es": None,
            "compiled_ru": None,
        }
    }
    monkeypatch.setattr(arachne, "db", FakeDb())
    monkeypatch.setattr(arachne, "COMPILED_CATEGORIES", configured)

    boost, reasons = arachne.detect_keyword_repetition("demo", "boom")
    assert boost == 3
    assert reasons == ["explosives_x4"]
    assert hasattr(arachne, "ALLOWED_USERS")
    assert hasattr(arachne, "ALLOWED_CHATS")


def test_auth_storage_failure_is_explicit_for_revoke_and_status(monkeypatch):
    import arachne

    class BrokenConnection:
        def __enter__(self):
            raise sqlite3.OperationalError("disk I/O error")

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(dashboard_auth, "_auth_db", lambda: BrokenConnection())
    with pytest.raises(RuntimeError, match="storage is unavailable"):
        dashboard_auth.revoke_dashboard_codes()

    monkeypatch.setattr(arachne.dashboard_auth, "dashboard_access_status", lambda: {
        "enabled": True, "active_code": False, "active_code_expires_at": None,
        "active_sessions": 0, "storage_error": "disk I/O error",
    })
    assert "storage is unavailable" in arachne._format_dashboard_access_status()
