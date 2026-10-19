"""Temporary Telegram-controlled dashboard access lock.

This is intentionally app-level Streamlit gating.  It stores only hashes in
SQLite and never logs or persists plaintext access codes.  A reverse proxy can
later wrap the Streamlit process for true perimeter/session cookies.
"""
from __future__ import annotations

import hashlib
import hmac
import sqlite3
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone

from config_loader import get_bool
from paths import RUNTIME_DIR


CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
SESSION_BYTES = 32
AUTH_DB_PATH = RUNTIME_DIR / "dashboard_access.db"
LOGIN_ATTEMPT_WINDOW_SECONDS = 5 * 60
LOGIN_ATTEMPT_LIMIT = 8
LOGIN_BLOCK_SECONDS = 15 * 60
LOGIN_ATTEMPT_RETENTION_SECONDS = 24 * 60 * 60
_AUTH_SCHEMA_READY_PATH: str | None = None
_AUTH_SCHEMA_LOCK = threading.Lock()
AUTH_SCHEMA_VERSION = 1

ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_DEMO_READONLY = "demo_readonly"
VALID_ROLES = frozenset({ROLE_ADMIN, ROLE_ANALYST, ROLE_DEMO_READONLY})

CAPABILITY_DASHBOARD_VIEW = "dashboard.view"
CAPABILITY_SITE_CARDS_EDIT = "site_cards.edit"
CAPABILITY_REVIEWS_MANAGE = "reviews.manage"
CAPABILITY_REPORTS_CREATE = "reports.create"
CAPABILITY_WATCHLIST_MANAGE = "watchlist.manage"
CAPABILITY_CRAWLER_MANAGE = "crawler.manage"
CAPABILITY_SETTINGS_MANAGE = "settings.manage"
CAPABILITY_ACCESS_MANAGE = "access.manage"

ROLE_CAPABILITIES = {
    ROLE_ADMIN: frozenset({
        CAPABILITY_DASHBOARD_VIEW,
        CAPABILITY_SITE_CARDS_EDIT,
        CAPABILITY_REVIEWS_MANAGE,
        CAPABILITY_REPORTS_CREATE,
        CAPABILITY_WATCHLIST_MANAGE,
        CAPABILITY_CRAWLER_MANAGE,
        CAPABILITY_SETTINGS_MANAGE,
        CAPABILITY_ACCESS_MANAGE,
    }),
    ROLE_ANALYST: frozenset({
        CAPABILITY_DASHBOARD_VIEW,
        CAPABILITY_SITE_CARDS_EDIT,
        CAPABILITY_REVIEWS_MANAGE,
        CAPABILITY_REPORTS_CREATE,
        CAPABILITY_WATCHLIST_MANAGE,
    }),
    ROLE_DEMO_READONLY: frozenset({CAPABILITY_DASHBOARD_VIEW}),
}
MUTATING_CAPABILITIES = frozenset(
    capability
    for capability in set().union(*ROLE_CAPABILITIES.values())
    if capability != CAPABILITY_DASHBOARD_VIEW
)


class _ClosingConnection(sqlite3.Connection):
    """Preserve sqlite transaction semantics and always release the file handle."""
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


_AUTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS dashboard_access_state (
 id INTEGER PRIMARY KEY CHECK(id=1), lock_enabled INTEGER DEFAULT 1,
 updated_at TEXT, updated_by TEXT
);
CREATE TABLE IF NOT EXISTS dashboard_access_codes (
 id INTEGER PRIMARY KEY AUTOINCREMENT, code_hash TEXT NOT NULL, code_salt TEXT NOT NULL,
 created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT, used_at TEXT,
 created_by_telegram_id TEXT, duration_seconds INTEGER NOT NULL,
 role TEXT NOT NULL DEFAULT 'admin'
);
CREATE INDEX IF NOT EXISTS idx_dashboard_access_codes_active
 ON dashboard_access_codes(expires_at,revoked_at,used_at);
CREATE TABLE IF NOT EXISTS dashboard_sessions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, session_hash TEXT NOT NULL UNIQUE,
 created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT,
 source_code_id INTEGER, user_agent TEXT, ip_hint TEXT,
 role TEXT NOT NULL DEFAULT 'admin',
 FOREIGN KEY(source_code_id) REFERENCES dashboard_access_codes(id)
);
CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_active
 ON dashboard_sessions(expires_at,revoked_at);
CREATE TABLE IF NOT EXISTS dashboard_access_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL,
 safe_metadata_json TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dashboard_login_attempts (
 attempt_key TEXT PRIMARY KEY, window_started_at TEXT NOT NULL,
 attempt_count INTEGER NOT NULL DEFAULT 0, blocked_until TEXT, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dashboard_login_attempts_cleanup
 ON dashboard_login_attempts(updated_at,blocked_until);
"""


def normalize_role(role: object) -> str | None:
    value = str(role or "").strip().casefold()
    return value if value in VALID_ROLES else None


def capabilities_for_role(role: object) -> tuple[str, ...]:
    normalized = normalize_role(role)
    return tuple(sorted(ROLE_CAPABILITIES.get(normalized, frozenset())))


def has_capability(principal: object, capability: str) -> bool:
    role = principal.get("role") if isinstance(principal, dict) else principal
    normalized_capability = str(capability or "").strip()
    return normalized_capability in ROLE_CAPABILITIES.get(
        normalize_role(role), frozenset())


def can_mutate(principal: object) -> bool:
    return any(has_capability(principal, capability)
               for capability in MUTATING_CAPABILITIES)


def require_capability(principal: object, capability: str) -> None:
    if not has_capability(principal, capability):
        raise PermissionError(f"capability_denied:{str(capability or 'unknown')[:80]}")


def _role_result(role: object) -> dict:
    normalized = normalize_role(role)
    return {
        "role": normalized,
        "capabilities": list(capabilities_for_role(normalized)),
    }


def _storage_unavailable(exc: Exception) -> dict:
    return {
        "ok": False,
        "lock_enabled": True,
        "reason": "auth_storage_unavailable",
        "error": type(exc).__name__,
        "role": None,
        "capabilities": [],
    }


def _auth_db() -> sqlite3.Connection:
    # AUTH_DB_PATH is replaceable for tests/recovery and may be relocated in a
    # deployment.  Prepare its real parent rather than assuming paths.RUNTIME_DIR
    # is always the same directory.
    AUTH_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(AUTH_DB_PATH), timeout=10, factory=_ClosingConnection)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.execute("PRAGMA synchronous = NORMAL")
    return connection


def _migrate_auth_schema(db: sqlite3.Connection) -> None:
    """Add role columns to pre-role access databases without invalidating sessions."""
    for table in ("dashboard_access_codes", "dashboard_sessions"):
        columns = {
            str(row["name"])
            for row in db.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if "role" not in columns:
            db.execute(
                f"ALTER TABLE {table} ADD COLUMN role TEXT NOT NULL DEFAULT '{ROLE_ADMIN}'")
        db.execute(
            f"UPDATE {table} SET role=? WHERE role IS NULL OR trim(role)=''",
            (ROLE_ADMIN,),
        )


def _access_storage_ready() -> tuple[bool, Exception | None]:
    global _AUTH_SCHEMA_READY_PATH
    try:
        path_key = str(AUTH_DB_PATH.resolve())
    except OSError:
        path_key = str(AUTH_DB_PATH)
    if _AUTH_SCHEMA_READY_PATH == path_key and AUTH_DB_PATH.exists():
        return True, None
    with _AUTH_SCHEMA_LOCK:
        if _AUTH_SCHEMA_READY_PATH == path_key and AUTH_DB_PATH.exists():
            return True, None
        try:
            with _auth_db() as db:
                current_schema_version = int(
                    db.execute("PRAGMA user_version").fetchone()[0])
                if current_schema_version > AUTH_SCHEMA_VERSION:
                    raise sqlite3.DatabaseError(
                        "access_database_schema_is_newer_than_this_release:"
                        f"{current_schema_version}>{AUTH_SCHEMA_VERSION}"
                    )
                db.execute("PRAGMA journal_mode = WAL")
                db.executescript(_AUTH_SCHEMA)
                _migrate_auth_schema(db)
                # Version zero is the legacy access schema.  Keep migration
                # additive and rerunnable, and stamp only after role backfill and
                # all current schema objects have succeeded.
                db.execute(f"PRAGMA user_version = {AUTH_SCHEMA_VERSION}")
        except (OSError, sqlite3.Error) as exc:
            return False, exc
        _AUTH_SCHEMA_READY_PATH = path_key
    return True, None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _hash_secret(secret: str, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}:{secret.strip().upper()}".encode("utf-8")).hexdigest()
    return digest


def _session_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _client_hash(user_agent: str = "", ip_hint: str = "") -> str:
    """Hash the server-observed address for throttling, ignoring mutable UA text."""
    del user_agent
    material = str(ip_hint or "").strip() or "unknown-client"
    return hashlib.sha256(material.encode("utf-8", "ignore")).hexdigest()


def _attempt_blocked(db: sqlite3.Connection, attempt_key: str, now: datetime) -> bool:
    retention_before = _iso(now - timedelta(seconds=LOGIN_ATTEMPT_RETENTION_SECONDS))
    db.execute("DELETE FROM dashboard_login_attempts WHERE updated_at<?", (retention_before,))
    row = db.execute(
        "SELECT window_started_at,attempt_count,blocked_until FROM dashboard_login_attempts WHERE attempt_key=?",
        (attempt_key,),
    ).fetchone()
    if not row:
        return False
    blocked_until = _parse(row["blocked_until"])
    return bool(blocked_until and blocked_until > now)


def _record_failed_attempt(db: sqlite3.Connection, attempt_key: str, now: datetime) -> bool:
    row = db.execute(
        "SELECT window_started_at,attempt_count FROM dashboard_login_attempts WHERE attempt_key=?",
        (attempt_key,),
    ).fetchone()
    window_start = _parse(row["window_started_at"]) if row else None
    if not window_start or now - window_start >= timedelta(seconds=LOGIN_ATTEMPT_WINDOW_SECONDS):
        window_start = now
        count = 1
    else:
        count = int(row["attempt_count"] or 0) + 1
    blocked_until = (
        _iso(now + timedelta(seconds=LOGIN_BLOCK_SECONDS))
        if count >= LOGIN_ATTEMPT_LIMIT else None
    )
    db.execute(
        """INSERT INTO dashboard_login_attempts
          (attempt_key,window_started_at,attempt_count,blocked_until,updated_at)
          VALUES(?,?,?,?,?) ON CONFLICT(attempt_key) DO UPDATE SET
          window_started_at=excluded.window_started_at,attempt_count=excluded.attempt_count,
          blocked_until=excluded.blocked_until,updated_at=excluded.updated_at""",
        (attempt_key, _iso(window_start), count, blocked_until, _iso(now)),
    )
    return bool(blocked_until)


def normalize_code(code: str) -> str:
    return "".join(ch for ch in str(code or "").upper() if ch.isalnum())


def format_code(raw: str) -> str:
    raw = normalize_code(raw)
    return "-".join(raw[index:index + 4] for index in range(0, len(raw), 4))


def _new_code(length: int = 8) -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(length))


def dashboard_lock_enabled() -> bool:
    ready, exc = _access_storage_ready()
    if not ready:
        # Fail closed: never bypass the dashboard lock because SQLite/storage is
        # unhealthy.  Callers that need user-facing detail use
        # dashboard_access_status()/validate_dashboard_session().
        return True
    try:
        with _auth_db() as db:
            row = db.execute("SELECT lock_enabled FROM dashboard_access_state WHERE id=1").fetchone()
    except (OSError, sqlite3.Error):
        return True
    if row is None:
        return get_bool("DASHBOARD_LOCK_ENABLED", True)
    return bool(row["lock_enabled"])


def set_dashboard_lock_enabled(enabled: bool, updated_by: str = "telegram") -> None:
    ready, exc = _access_storage_ready()
    if not ready:
        raise RuntimeError(f"Dashboard access storage is unavailable: {exc}") from exc
    try:
        with _auth_db() as db:
            db.execute("""INSERT INTO dashboard_access_state(id,lock_enabled,updated_at,updated_by)
              VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET
              lock_enabled=excluded.lock_enabled,updated_at=excluded.updated_at,updated_by=excluded.updated_by""",
              (int(bool(enabled)), _iso(_now()), str(updated_by)[:80]))
            if not enabled:
                now = _iso(_now())
                db.execute("UPDATE dashboard_access_codes SET revoked_at=COALESCE(revoked_at,?) WHERE revoked_at IS NULL", (now,))
                db.execute("UPDATE dashboard_sessions SET revoked_at=COALESCE(revoked_at,?) WHERE revoked_at IS NULL", (now,))
    except (OSError, sqlite3.Error) as db_exc:
        raise RuntimeError(f"Dashboard access storage is unavailable: {db_exc}") from db_exc


def generate_dashboard_code(
        duration_seconds: int, created_by_telegram_id: int | str,
        role: str = ROLE_ADMIN) -> dict:
    normalized_role = normalize_role(role)
    if normalized_role is None:
        return {
            "ok": False,
            "reason": "invalid_role",
            "error": "Unknown dashboard role.",
            "role": None,
            "capabilities": [],
        }
    ready, exc = _access_storage_ready()
    if not ready:
        return _storage_unavailable(exc)
    duration = max(60, min(int(duration_seconds), 7 * 24 * 3600))
    raw_code = _new_code(8)
    salt = secrets.token_hex(16)
    now = _now()
    expires = now + timedelta(seconds=duration)
    try:
        with _auth_db() as db:
            db.execute("""INSERT INTO dashboard_access_state(id,lock_enabled,updated_at,updated_by)
              VALUES(1,1,?,?) ON CONFLICT(id) DO UPDATE SET
              lock_enabled=1,updated_at=excluded.updated_at,updated_by=excluded.updated_by""",
              (_iso(now), str(created_by_telegram_id)[:80]))
            db.execute("UPDATE dashboard_access_codes SET revoked_at=COALESCE(revoked_at,?) WHERE revoked_at IS NULL AND used_at IS NULL",
                       (_iso(now),))
            cur = db.execute("""INSERT INTO dashboard_access_codes
              (code_hash,code_salt,created_at,expires_at,created_by_telegram_id,
               duration_seconds,role)
              VALUES(?,?,?,?,?,?,?)""",
              (_hash_secret(raw_code, salt), salt, _iso(now), _iso(expires),
               str(created_by_telegram_id), duration, normalized_role))
    except (OSError, sqlite3.Error) as exc:
        return _storage_unavailable(exc)
    return {"id": cur.lastrowid, "code": format_code(raw_code), "expires_at": _iso(expires),
            "duration_seconds": duration, **_role_result(normalized_role)}


def revoke_dashboard_codes(*, revoke_sessions: bool = False, updated_by: str = "telegram") -> int:
    ready, exc = _access_storage_ready()
    if not ready:
        raise RuntimeError(f"Dashboard access storage is unavailable: {exc}") from exc
    now = _iso(_now())
    try:
        with _auth_db() as db:
            changed = db.execute("""UPDATE dashboard_access_codes SET revoked_at=COALESCE(revoked_at,?)
              WHERE revoked_at IS NULL AND used_at IS NULL""", (now,)).rowcount
            if revoke_sessions:
                db.execute("UPDATE dashboard_sessions SET revoked_at=COALESCE(revoked_at,?) WHERE revoked_at IS NULL", (now,))
            db.execute("""INSERT INTO dashboard_access_events(event_type,safe_metadata_json,created_at)
              VALUES('revoke',?,?)""", (f'{{"updated_by":"{str(updated_by)[:80]}","sessions":{int(revoke_sessions)}}}', now))
    except (OSError, sqlite3.Error) as db_exc:
        raise RuntimeError(f"Dashboard access storage is unavailable: {db_exc}") from db_exc
    return int(changed)


def consume_dashboard_code(code: str, *, user_agent: str = "", ip_hint: str = "") -> dict:
    """Consume a one-time code and create a session token."""
    ready, exc = _access_storage_ready()
    if not ready:
        result = _storage_unavailable(exc)
        result["error"] = "Access storage is temporarily unavailable. Check the server database/disk, then try again."
        return result
    entered = normalize_code(code)
    now = _now()
    attempt_key = _client_hash(user_agent, ip_hint)
    try:
        with _auth_db() as db:
            # Serialize the one-time claim.  Without BEGIN IMMEDIATE, concurrent
            # requests can both read used_at=NULL and create separate sessions.
            db.execute("BEGIN IMMEDIATE")
            if _attempt_blocked(db, attempt_key, now):
                db.execute("""INSERT INTO dashboard_access_events(event_type,safe_metadata_json,created_at)
                  VALUES('login_throttled','{"reason":"attempt_limit"}',?)""", (_iso(now),))
                return {"ok": False, "reason": "rate_limited",
                        "error": "Too many attempts. Try again later."}
            rows = [dict(row) for row in db.execute("""SELECT * FROM dashboard_access_codes
              WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at>? ORDER BY id DESC LIMIT 20""",
              (_iso(now),))]
            matched = None
            for row in rows:
                candidate = _hash_secret(entered, row["code_salt"])
                if hmac.compare_digest(candidate, row["code_hash"]):
                    matched = row
                    break
            if not matched:
                blocked = _record_failed_attempt(db, attempt_key, now)
                db.execute("""INSERT INTO dashboard_access_events(event_type,safe_metadata_json,created_at)
                  VALUES('login_failed',?,?)""", ('{"reason":"invalid_or_expired"}', _iso(now)))
                return {"ok": False, "reason": "rate_limited" if blocked else "invalid",
                        "error": ("Too many attempts. Try again later." if blocked
                                  else "Invalid or expired access code.")}
            matched_role = normalize_role(matched.get("role"))
            if matched_role is None:
                db.execute(
                    """UPDATE dashboard_access_codes
                      SET revoked_at=COALESCE(revoked_at,?) WHERE id=?""",
                    (_iso(now), matched["id"]),
                )
                db.execute("""INSERT INTO dashboard_access_events
                  (event_type,safe_metadata_json,created_at)
                  VALUES('login_failed','{"reason":"invalid_role"}',?)""", (_iso(now),))
                return {
                    "ok": False,
                    "reason": "invalid_role",
                    "error": "Invalid or expired access code.",
                    "role": None,
                    "capabilities": [],
                }
            token = secrets.token_urlsafe(SESSION_BYTES)
            token_hash = _session_hash(token)
            changed = db.execute("""UPDATE dashboard_access_codes SET used_at=?
              WHERE id=? AND used_at IS NULL AND revoked_at IS NULL AND expires_at>?""",
              (_iso(now), matched["id"], _iso(now))).rowcount
            if changed != 1:
                return {"ok": False, "error": "Invalid or expired access code."}
            db.execute("DELETE FROM dashboard_login_attempts WHERE attempt_key=?", (attempt_key,))
            db.execute("""INSERT INTO dashboard_sessions
              (session_hash,created_at,expires_at,source_code_id,user_agent,ip_hint,role)
              VALUES(?,?,?,?,?,?,?)""",
              (token_hash, _iso(now), matched["expires_at"], matched["id"],
               f"sha256:{attempt_key}", f"sha256:{attempt_key}", matched_role))
            db.execute("""INSERT INTO dashboard_access_events(event_type,safe_metadata_json,created_at)
              VALUES('login_success',?,?)""", (f'{{"code_id":{int(matched["id"])}}}', _iso(now)))
    except (OSError, sqlite3.Error) as exc:
        result = _storage_unavailable(exc)
        result["error"] = "Access storage is temporarily unavailable. Check the server database/disk, then try again."
        return result
    return {
        "ok": True,
        "session_token": token,
        "expires_at": matched["expires_at"],
        **_role_result(matched_role),
    }


def rotate_dashboard_session(token: str | None) -> dict:
    """Replace a URL-restored bearer token while preserving its expiry.

    Streamlit does not expose an HttpOnly session-cookie API. Rotating only when
    a session is restored from the query string preserves F5 continuity while
    invalidating older browser-history and proxy-log copies.
    """
    if not token:
        return {"ok": False, "reason": "missing"}
    ready, exc = _access_storage_ready()
    if not ready:
        return _storage_unavailable(exc)
    now = _now()
    try:
        with _auth_db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT * FROM dashboard_sessions
              WHERE session_hash=? AND revoked_at IS NULL AND expires_at>?""",
              (_session_hash(token), _iso(now))).fetchone()
            if not row:
                return {"ok": False, "reason": "invalid"}
            role = normalize_role(row["role"])
            if role is None:
                return {
                    "ok": False,
                    "reason": "invalid_role",
                    "role": None,
                    "capabilities": [],
                }
            replacement = secrets.token_urlsafe(SESSION_BYTES)
            changed = db.execute("""UPDATE dashboard_sessions SET revoked_at=?
              WHERE id=? AND revoked_at IS NULL""", (_iso(now), row["id"])).rowcount
            if changed != 1:
                return {"ok": False, "reason": "invalid"}
            db.execute("""INSERT INTO dashboard_sessions
              (session_hash,created_at,expires_at,source_code_id,user_agent,ip_hint,role)
              VALUES(?,?,?,?,?,?,?)""",
              (_session_hash(replacement), _iso(now), row["expires_at"], row["source_code_id"],
               row["user_agent"], row["ip_hint"], role))
            db.execute("""INSERT INTO dashboard_access_events(event_type,safe_metadata_json,created_at)
              VALUES('session_rotated','{}',?)""", (_iso(now),))
    except (OSError, sqlite3.Error) as exc:
        return _storage_unavailable(exc)
    return {
        "ok": True,
        "session_token": replacement,
        "expires_at": row["expires_at"],
        **_role_result(role),
    }


def validate_dashboard_session(token: str | None) -> dict:
    ready, exc = _access_storage_ready()
    if not ready:
        return _storage_unavailable(exc)
    try:
        with _auth_db() as db:
            row = db.execute("SELECT lock_enabled FROM dashboard_access_state WHERE id=1").fetchone()
        if row is None and not get_bool("DASHBOARD_LOCK_ENABLED", True):
            return {
                "ok": True,
                "lock_enabled": False,
                **_role_result(ROLE_ADMIN),
            }
        if row is not None and not bool(row["lock_enabled"]):
            return {
                "ok": True,
                "lock_enabled": False,
                **_role_result(ROLE_ADMIN),
            }
        if not token:
            return {"ok": False, "reason": "missing"}
        now = _now()
        with _auth_db() as db:
            row = db.execute("""SELECT * FROM dashboard_sessions
              WHERE session_hash=? AND revoked_at IS NULL AND expires_at>?""",
              (_session_hash(token), _iso(now))).fetchone()
    except (OSError, sqlite3.Error) as exc:
        return _storage_unavailable(exc)
    if not row:
        return {"ok": False, "reason": "invalid"}
    role = normalize_role(row["role"])
    if role is None:
        return {
            "ok": False,
            "lock_enabled": True,
            "reason": "invalid_role",
            "role": None,
            "capabilities": [],
        }
    expires = _parse(row["expires_at"])
    remaining = max(0, int((expires - now).total_seconds())) if expires else 0
    return {"ok": True, "lock_enabled": True, "expires_at": row["expires_at"],
            "remaining_seconds": remaining, **_role_result(role)}


def authorize_dashboard_session(token: str | None, capability: str) -> dict:
    """Validate a session and apply one centralized capability decision."""
    status = validate_dashboard_session(token)
    if not status.get("ok"):
        return status
    if not has_capability(status, capability):
        return {
            "ok": False,
            "lock_enabled": status.get("lock_enabled", True),
            "reason": "forbidden",
            "role": normalize_role(status.get("role")),
            "capabilities": list(capabilities_for_role(status.get("role"))),
        }
    return status


def revoke_dashboard_session(token: str | None) -> None:
    if not token:
        return
    ready, exc = _access_storage_ready()
    if not ready:
        raise RuntimeError("Dashboard access storage is unavailable") from exc
    try:
        with _auth_db() as db:
            db.execute("UPDATE dashboard_sessions SET revoked_at=COALESCE(revoked_at,?) WHERE session_hash=?",
                       (_iso(_now()), _session_hash(token)))
    except (OSError, sqlite3.Error) as db_exc:
        raise RuntimeError("Dashboard access storage is unavailable") from db_exc


def dashboard_access_status() -> dict:
    ready, exc = _access_storage_ready()
    if not ready:
        return {
            "enabled": True,
            "active_code": False,
            "active_code_expires_at": None,
            "active_sessions": 0,
            "storage_error": type(exc).__name__,
    }
    try:
        with _auth_db() as db:
            state = db.execute("SELECT lock_enabled FROM dashboard_access_state WHERE id=1").fetchone()
            enabled = bool(state["lock_enabled"]) if state is not None else get_bool(
                "DASHBOARD_LOCK_ENABLED", True)
            code = db.execute("""SELECT expires_at,created_at FROM dashboard_access_codes
              WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at>? ORDER BY id DESC LIMIT 1""",
              (_iso(_now()),)).fetchone()
            sessions = db.execute("""SELECT COUNT(*) FROM dashboard_sessions
              WHERE revoked_at IS NULL AND expires_at>?""", (_iso(_now()),)).fetchone()[0]
    except (OSError, sqlite3.Error) as exc:
        return {
            "enabled": True,
            "active_code": False,
            "active_code_expires_at": None,
            "active_sessions": 0,
            "storage_error": type(exc).__name__,
        }
    return {"enabled": enabled, "active_code": bool(code),
            "active_code_expires_at": code["expires_at"] if code else None,
            "active_sessions": int(sessions)}


def duration_seconds(label: str) -> int:
    value = str(label or "").strip().lower()
    mapping = {"15m": 900, "15min": 900, "1h": 3600, "4h": 14400, "24h": 86400}
    if value in mapping:
        return mapping[value]
    if value.isdigit():
        return max(1, int(value)) * 60
    match = re.fullmatch(r"(\d+)\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours)", value)
    if match:
        amount = max(1, int(match.group(1)))
        unit = match.group(2)
        return amount * 3600 if unit.startswith("h") else amount * 60
    return 3600
