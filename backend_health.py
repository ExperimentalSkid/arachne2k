"""Read-only backend health evaluation for CLI and deployment checks."""
from __future__ import annotations

import socket
import sqlite3
from datetime import datetime, timezone

import storage
from config_loader import get_int, get_str


def _age_seconds(value: str | None) -> float | None:
    if not value: return None
    try: return max(0.0, (datetime.now(timezone.utc) - datetime.fromisoformat(value.replace("Z", "+00:00"))).total_seconds())
    except (TypeError, ValueError): return None


def snapshot() -> dict:
    try:
        operational = storage.get_operational_health()
        worker = operational.get("worker") or {}
        frontier = storage.frontier_stats()
        with storage.get_db() as db:
            maintenance = [dict(row) for row in db.execute(
                "SELECT * FROM worker_maintenance_state ORDER BY COALESCE(last_failure_at,last_started_at) DESC LIMIT 20")]
        db_state = "ok"
    except sqlite3.Error as exc:
        return {"health": "db_locked" if "locked" in str(exc).casefold() else "database_error",
                "error": type(exc).__name__}
    heartbeat_age = _age_seconds(worker.get("last_heartbeat_at"))
    progress_age = None
    fetch_age = None
    pipeline_state = str(worker.get("state") or "offline")
    if pipeline_state == "paused":
        health = "paused"
    elif pipeline_state == "offline" or heartbeat_age is None or heartbeat_age > 1800:
        health = "offline_or_stale"
    elif pipeline_state == "degraded":
        health = "degraded"
    else:
        health = "healthy"
    tor_host, tor_port = get_str("TOR_SOCKS_HOST", "127.0.0.1"), get_int("TOR_SOCKS_PORT", 9050)
    try:
        with socket.create_connection((tor_host, tor_port), timeout=0.5): tor = "reachable"
    except OSError: tor = "unavailable"
    return {"health": health, "database": db_state, "tor": tor, "worker": worker,
            "heartbeat_age_seconds": heartbeat_age, "progress_age_seconds": progress_age,
            "fetch_age_seconds": fetch_age, "frontier": frontier,
            "queues": {key: operational.get(key, 0) for key in (
                "queued", "verify_waiting", "card_waiting", "preview_waiting")},
            "maintenance_backoff_active": any(row.get("next_allowed_at") and
                str(row["next_allowed_at"]) > storage.utc_now_iso() and row.get("last_failure_at") for row in maintenance),
            "maintenance": maintenance}
