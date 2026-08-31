"""Strict, bounded operational observability for Arachne workers.

Only fixed-schema operational metadata is accepted.  Raw URLs, page content,
classifications, identities, credentials, sessions, exception messages and
arbitrary payloads have no serialization path in this module.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import heapq
import hmac
import json
import logging
import math
import os
import re
import sqlite3
import stat
import threading
import time
import uuid
import zipfile
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from config_loader import get_bool, get_int
from paths import DB_PATH, LOGS_DIR, RUNTIME_DIR


SCHEMA_VERSION = "arachne.operations.v1"
WORKER_TYPES = {"fetch", "verify", "card", "preview", "deep_discovery", "maintenance"}
PROVIDER_NAMES = {"local_arachne", "openpgp_exact", "rdap_exact_domain"}
DB_OPERATION_CODES = {
    "init_db", "enqueue_deep_discovery",
    "claim_fetch", "finish_fetch", "claim_verify", "finish_verify", "fail_verify",
    "enqueue_card", "claim_card", "finish_card", "claim_maintenance",
    "claim_preview", "finish_preview", "claim_deep_discovery",
    "finish_deep_discovery", "fail_deep_discovery", "iteration",
    "other_db_operation",
}
EVENT_CODES = {
    "startup", "shutdown", "queue_snapshot", "queue_snapshot_unavailable",
    "claim", "finish", "retry", "dead_letter", "blocked", "idle", "paused",
    "state", "iteration", "worker_error", "db_operation_slow", "db_lock_delay",
    "tor_health", "provider_state", "discovery_outcome", "daily_summary", "maintenance",
}
REASON_CODES = {
    "worker_started", "worker_stopped", "queue_sample", "queue_empty",
    "queue_check", "claim_acquired", "fetch_started", "fetch_complete",
    "classification_started", "classification_complete", "classification_uncertain",
    "content_boundary_rejected", "card_processing", "card_complete",
    "preview_capture", "preview_available", "preview_reused", "provider_local_started",
    "provider_local_complete", "policy_restricted", "retry_scheduled", "dead_letter",
    "worker_failed", "worker_error", "database_locked", "database_slow",
    "intake_paused", "rate_limited", "feature_disabled", "claim_lost",
    "maintenance_complete", "maintenance_failed", "provider_disabled",
    "queue_snapshot_unavailable", "work_processed", "tor_health_snapshot",
    "provider_state_snapshot", "network_timeout", "connection_failed",
    "database_error", "response_error", "preview_unavailable",
    "actor_not_found", "invalid_anchor", "discovery_complete", "discovery_none",
    "pending_revision_promoted", "other_safe_reason",
}
STATE_MAP = {
    "checking_queue": ("state", "queue_check"),
    "idle": ("idle", "queue_empty"),
    "paused": ("paused", "intake_paused"),
    "prefetch": ("claim", "claim_acquired"),
    "fetching": ("state", "fetch_started"),
    "snapshot_stored": ("finish", "fetch_complete"),
    "classifying": ("claim", "classification_started"),
    "verified": ("finish", "classification_complete"),
    "refetch_queued": ("retry", "content_boundary_rejected"),
    "processing": ("claim", "card_processing"),
    "done": ("finish", "card_complete"),
    "capturing": ("claim", "preview_capture"),
    "available": ("finish", "preview_available"),
    "preview_reused_existing_file": ("finish", "preview_reused"),
    "local_correlation": ("claim", "provider_local_started"),
    "local_complete": ("finish", "provider_local_complete"),
    "filtered": ("blocked", "policy_restricted"),
    "blocked": ("blocked", "policy_restricted"),
    "retry": ("retry", "retry_scheduled"),
    "dead": ("dead_letter", "dead_letter"),
    "dead_letter": ("dead_letter", "dead_letter"),
    "rate_limited": ("state", "rate_limited"),
    "disabled": ("state", "feature_disabled"),
    "claim_lost": ("retry", "claim_lost"),
    "error": ("worker_error", "worker_error"),
    "failed": ("worker_error", "worker_failed"),
    "stopped": ("shutdown", "worker_stopped"),
}
QUEUE_KEYS = (
    "fetch_waiting", "verify_waiting", "card_waiting", "preview_waiting",
    "deep_discovery_waiting", "retry_total", "dead_letter_total",
    "database_bytes", "wal_bytes",
)
DISCOVERY_KEYS = (
    "processed_total", "queued_new", "already_known", "rejected",
    "restricted", "deferred", "blocked",
)
SENSITIVE_TEXT = re.compile(
    r"(?i)(https?://|\.onion|token|cookie|password|secret|session|authorization|"
    r"api[_-]?(?:id|key|hash)|chat[_-]?id|admin[_-]?id|wallet|email|alias|handle|"
    r"pgp|private|body|snippet|title|source[_-]?url|visible[_-]?text)"
)
SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SAFE_WORKER_ID = re.compile(
    r"^(?:fetch|verify|card|preview|deep_discovery|maintenance):[0-9]+(?::[0-9]+){0,3}$"
)
SAFE_RUN_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9]+-[0-9a-f]{8}$")
SAFE_TARGET_REF = re.compile(r"^h1_[0-9a-f]{24}$")
SAFE_EVENT_ID = re.compile(r"^[0-9a-f]{32}$")
SAFE_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)

LOG_ROOT = LOGS_DIR / "operations"
KEY_PATH = RUNTIME_DIR / "observability.key"
PROCESS_RUN_ID = (
    datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    + f"-{os.getpid()}-{uuid.uuid4().hex[:8]}"
)
LOGGER = logging.getLogger("arachne.operations")
_LOCK = threading.RLock()
_DIAGNOSTIC_BUILD_LOCK = threading.Lock()
_RUN_BY_WORKER: dict[str, str] = {}
_LAST_QUEUE_SAMPLE: dict[str, float] = {}
_MAX_EVENT_LINE_BYTES = 8192


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_worker_type(value: object) -> str:
    text = str(value or "").strip().casefold()
    return text if text in WORKER_TYPES else "maintenance"


def _safe_worker_id(value: object, worker_type: str) -> str:
    text = str(value or "")
    if SAFE_WORKER_ID.fullmatch(text):
        return text
    return f"{worker_type}:{os.getpid()}"


def _safe_run_id(value: object) -> str:
    text = str(value or "")
    return text if SAFE_RUN_ID.fullmatch(text) else PROCESS_RUN_ID


def _reason(value: object, fallback: str = "other_safe_reason") -> str:
    text = str(value or "").strip().casefold()
    if text in REASON_CODES:
        return text
    if SAFE_CODE.fullmatch(text) and not SENSITIVE_TEXT.search(text):
        # Exception class names and bounded internal codes remain useful, but
        # arbitrary strings never pass this path.
        if text.endswith("error") or text.endswith("timeout") or text in {
                "busy", "locked", "operationalerror", "connecttimeout"}:
            return "database_locked" if text in {"busy", "locked"} else fallback
    return fallback


def _error_reason(value: object, fallback: str) -> str:
    """Map known exception/state labels to non-sensitive operational causes."""
    text = str(value or "").strip().casefold().replace("-", "_")
    text = text.split(":", 1)[0].rsplit(".", 1)[-1]
    mapping = {
        "connecttimeout": "network_timeout", "readtimeout": "network_timeout",
        "timeouterror": "network_timeout", "timeout": "network_timeout",
        "connectionerror": "connection_failed", "proxyerror": "connection_failed",
        "operationalerror": "database_error", "databaseerror": "database_error",
        "workerclaimlost": "claim_lost", "preview_capture_unavailable": "preview_unavailable",
        "actor_not_found": "actor_not_found", "invalid_anchor_actor": "invalid_anchor",
        "httperror": "response_error",
    }
    return mapping.get(text, _reason(text, fallback))


def _event_code(value: object) -> str:
    text = str(value or "").strip().casefold()
    return text if text in EVENT_CODES else "state"


def _safe_int(value: object, *, minimum: int = 0, maximum: int = 10**15) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return max(minimum, min(number, maximum))


def _safe_ms(value: object) -> int | None:
    if value is None:
        return None
    try:
        return max(0, min(int(round(float(value))), 24 * 3600 * 1000))
    except (TypeError, ValueError, OverflowError):
        return None


def _key() -> bytes | None:
    try:
        KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not KEY_PATH.exists():
            generated = os.urandom(32)
            try:
                descriptor = os.open(
                    KEY_PATH,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    stat.S_IRUSR | stat.S_IWUSR,
                )
            except FileExistsError:
                descriptor = None
            if descriptor is not None:
                try:
                    offset = 0
                    while offset < len(generated):
                        offset += os.write(descriptor, generated[offset:])
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        try:
            KEY_PATH.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        # A second process can observe the exclusively-created file in the few
        # milliseconds before the creator finishes its 32-byte write.
        for attempt in range(5):
            data = KEY_PATH.read_bytes()
            if len(data) >= 32:
                return data
            if attempt < 4:
                time.sleep(0.01)
        return None
    except OSError:
        return None


def safe_target_ref(value: object) -> str | None:
    """Return an install-local HMAC reference without retaining source fragments."""
    if value is None:
        return None
    secret = _key()
    if secret is None:
        return None
    digest = hmac.new(secret, str(value).encode("utf-8", "ignore"), hashlib.sha256).hexdigest()
    return "h1_" + digest[:24]


def _safe_queue(value: dict | None) -> dict[str, int]:
    source = value if isinstance(value, dict) else {}
    result: dict[str, int] = {}
    for key in QUEUE_KEYS:
        number = _safe_int(source.get(key))
        if number is not None:
            result[key] = number
    return result


def _safe_discovery(value: dict | None) -> dict[str, int]:
    source = value if isinstance(value, dict) else {}
    result: dict[str, int] = {}
    for key in DISCOVERY_KEYS:
        number = _safe_int(source.get(key), maximum=10**7)
        if number is not None:
            result[key] = number
    return result


def _safe_provider_state(value: dict | None) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    enabled = [str(item) for item in source.get("enabled_providers", [])
               if str(item) in PROVIDER_NAMES]
    disabled = [str(item) for item in source.get("disabled_providers", [])
                if str(item) in PROVIDER_NAMES]
    return {
        "network_enabled": (source.get("network_enabled")
                            if isinstance(source.get("network_enabled"), bool) else False),
        "enabled_providers": sorted(set(enabled)),
        "disabled_providers": sorted(set(disabled)),
        "status": "enabled" if enabled else "disabled",
    }


def _safe_tor_state(value: dict | None) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    isolation = str(source.get("socks_isolation") or "unknown").casefold()
    if isolation not in {"configured", "missing", "unknown"}:
        isolation = "unknown"
    return {
        "status": str(source.get("status") or "NOT_AUDITED")
                  if str(source.get("status") or "") in {"PASS", "FAIL", "NOT_AUDITED"}
                  else "NOT_AUDITED",
        "tor_socks_reachable": source.get("tor_socks_reachable")
                               if isinstance(source.get("tor_socks_reachable"), bool) else None,
        "socks5h_enforced": (source.get("socks5h_enforced")
                             if isinstance(source.get("socks5h_enforced"), bool) else False),
        "socks_isolation": isolation,
        "strict_mode": (source.get("strict_mode")
                        if isinstance(source.get("strict_mode"), bool) else False),
        "live_checks_performed": (source.get("live_checks_performed")
                                  if isinstance(source.get("live_checks_performed"), bool) else False),
    }


def _event(*, worker_type: str, event_code: str, worker_id: str | None = None,
           run_id: str | None = None, job_id: int | None = None,
           target: object | None = None, outcome_code: str | None = None,
           reason_code: str | None = None, latency_ms: float | int | None = None,
           db_lock_wait_ms: float | int | None = None, retry_count: int | None = None,
           queue_depth: dict | None = None, provider_state: dict | None = None,
           tor_state: dict | None = None,
           operation_code: str | None = None,
           discovery_counts: dict | None = None) -> dict[str, Any]:
    kind = _safe_worker_type(worker_type)
    event: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": _utc_now(),
        "event_id": uuid.uuid4().hex,
        "event_code": _event_code(event_code),
        "run_id": _safe_run_id(run_id or _RUN_BY_WORKER.get(str(worker_id or ""))),
        "worker_type": kind,
        "worker_id": _safe_worker_id(worker_id, kind),
        "outcome_code": _reason(outcome_code, "other_safe_reason"),
        "reason_code": _reason(reason_code, "other_safe_reason"),
    }
    numeric_job = _safe_int(job_id)
    if numeric_job is not None:
        event["job_id"] = numeric_job
    target_ref = safe_target_ref(target)
    if target_ref:
        event["target_ref"] = target_ref
    duration = _safe_ms(latency_ms)
    if duration is not None:
        event["latency_ms"] = duration
    wait = _safe_ms(db_lock_wait_ms)
    if wait is not None:
        event["db_lock_wait_ms"] = wait
    retry = _safe_int(retry_count, maximum=1000)
    if retry is not None:
        event["retry_count"] = retry
    queue = _safe_queue(queue_depth)
    if queue:
        event["queue_depth"] = queue
    if provider_state is not None:
        event["provider_state"] = _safe_provider_state(provider_state)
    if tor_state is not None:
        event["tor_state"] = _safe_tor_state(tor_state)
    discovery = _safe_discovery(discovery_counts)
    if discovery:
        event["discovery_counts"] = discovery
    operation = str(operation_code or "").strip().casefold()
    if operation_code is not None:
        event["operation_code"] = (
            operation if operation in DB_OPERATION_CODES else "other_db_operation"
        )
    return event


def human_summary(event: dict[str, Any]) -> str:
    parts = [event["worker_type"], event["event_code"]]
    if "job_id" in event:
        parts.append(f"job={event['job_id']}")
    parts.extend((f"outcome={event['outcome_code']}", f"reason={event['reason_code']}"))
    if "latency_ms" in event:
        parts.append(f"latency_ms={event['latency_ms']}")
    if "operation_code" in event:
        parts.append(f"operation={event['operation_code']}")
    discovery = event.get("discovery_counts") or {}
    if discovery:
        parts.append(
            f"discovered={discovery.get('processed_total', 0)} "
            f"queued={discovery.get('queued_new', 0)}"
        )
    queue = event.get("queue_depth") or {}
    if queue:
        waiting = sum(queue.get(key, 0) for key in QUEUE_KEYS if key.endswith("_waiting"))
        parts.append(f"queue_waiting={waiting}")
    return " ".join(parts)


def _run_path(event: dict[str, Any]) -> Path:
    folder = LOG_ROOT / event["worker_type"]
    name = event["timestamp"][:10].replace("-", "") + "-" + event["run_id"] + ".jsonl"
    return folder / name


def _rotate(path: Path, incoming_bytes: int) -> None:
    max_bytes = max(16 * 1024, get_int("OPS_LOG_MAX_BYTES", 10 * 1024 * 1024))
    try:
        current = path.stat().st_size if path.exists() else 0
    except OSError:
        current = 0
    if current + incoming_bytes <= max_bytes:
        return
    backups = max(1, min(get_int("OPS_LOG_BACKUP_COUNT", 5), 20))
    oldest = path.with_name(path.name + f".{backups}.gz")
    oldest.unlink(missing_ok=True)
    for index in range(backups - 1, 0, -1):
        source = path.with_name(path.name + f".{index}.gz")
        target = path.with_name(path.name + f".{index + 1}.gz")
        if source.exists():
            source.replace(target)
    if path.exists():
        target = path.with_name(path.name + ".1.gz")
        with path.open("rb") as source, gzip.open(target, "wb", compresslevel=6) as output:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)
        path.unlink(missing_ok=True)


def emit_event(*, worker_type: str, event_code: str, worker_id: str | None = None,
               run_id: str | None = None, job_id: int | None = None,
               target: object | None = None, outcome_code: str | None = None,
               reason_code: str | None = None, latency_ms: float | int | None = None,
               db_lock_wait_ms: float | int | None = None, retry_count: int | None = None,
               queue_depth: dict | None = None, provider_state: dict | None = None,
               tor_state: dict | None = None,
               operation_code: str | None = None,
               discovery_counts: dict | None = None) -> dict[str, Any] | None:
    """Best-effort append of one strictly validated event."""
    try:
        event = _event(
            worker_type=worker_type, event_code=event_code, worker_id=worker_id,
            run_id=run_id, job_id=job_id, target=target, outcome_code=outcome_code,
            reason_code=reason_code, latency_ms=latency_ms,
            db_lock_wait_ms=db_lock_wait_ms, retry_count=retry_count,
            queue_depth=queue_depth, provider_state=provider_state, tor_state=tor_state,
            operation_code=operation_code, discovery_counts=discovery_counts,
        )
        encoded = (json.dumps(event, ensure_ascii=True, sort_keys=True,
                              separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > 8192:
            return None
        with _LOCK:
            path = _run_path(event)
            path.parent.mkdir(parents=True, exist_ok=True)
            _rotate(path, len(encoded))
            with path.open("ab") as handle:
                handle.write(encoded)
            try:
                path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
        LOGGER.info(human_summary(event))
        return event
    except Exception:
        # Observability must never change a worker outcome.
        return None


def _table_exists(db: sqlite3.Connection, table: str) -> bool:
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def queue_depth_snapshot() -> dict[str, int]:
    result = {key: 0 for key in QUEUE_KEYS}
    try:
        if not Path(DB_PATH).is_file():
            return result
        uri = Path(DB_PATH).resolve().as_uri() + "?mode=ro"
        db = sqlite3.connect(uri, uri=True, timeout=0.15)
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA busy_timeout=150")
            queries = {
                "fetch_waiting": ("onion_urls", "SELECT COUNT(*) FROM onion_urls WHERE status IN ('new','queued','retry','claimed','fetching')"),
                "verify_waiting": ("fetched_pages", "SELECT COUNT(*) FROM fetched_pages WHERE classification_status IN ('pending','retry','claimed')"),
                "card_waiting": ("site_card_jobs", "SELECT COUNT(*) FROM site_card_jobs WHERE status IN ('queued','retry','claimed')"),
                "preview_waiting": ("page_preview_jobs", "SELECT COUNT(*) FROM page_preview_jobs WHERE status IN ('queued','retry','claimed')"),
                "deep_discovery_waiting": ("deep_discovery_jobs", "SELECT COUNT(*) FROM deep_discovery_jobs WHERE status IN ('queued','retry','claimed')"),
            }
            for key, (table, query) in queries.items():
                if _table_exists(db, table):
                    result[key] = int(db.execute(query).fetchone()[0] or 0)
            retry_sources = (
                ("onion_urls", "status='retry'"),
                ("fetched_pages", "classification_status='retry'"),
                ("site_card_jobs", "status='retry'"),
                ("page_preview_jobs", "status='retry'"),
                ("deep_discovery_jobs", "status='retry'"),
            )
            dead_sources = (
                ("onion_urls", "status='dead'"),
                ("fetched_pages", "classification_status='dead_letter'"),
                ("site_card_jobs", "status='dead_letter'"),
                ("page_preview_jobs", "status='dead_letter'"),
                ("deep_discovery_jobs", "status='dead_letter'"),
            )
            result["retry_total"] = sum(
                int(db.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}").fetchone()[0] or 0)
                for table, where in retry_sources if _table_exists(db, table)
            )
            result["dead_letter_total"] = sum(
                int(db.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}").fetchone()[0] or 0)
                for table, where in dead_sources if _table_exists(db, table)
            )
        finally:
            db.close()
        result["database_bytes"] = Path(DB_PATH).stat().st_size
        wal = Path(str(DB_PATH) + "-wal")
        result["wal_bytes"] = wal.stat().st_size if wal.is_file() else 0
    except (OSError, sqlite3.Error):
        raise
    return result


def maybe_queue_snapshot(worker_type: str, worker_id: str, *, force: bool = False) -> dict | None:
    try:
        now = time.monotonic()
        interval = max(10, get_int("OPS_QUEUE_SAMPLE_SECONDS", 60))
        # Several instances of one stage commonly share a process.  Sampling
        # per instance made every thread perform the same COUNT queries during
        # startup and once per interval.  One sample per process/stage retains
        # the queue signal without multiplying read pressure.  ``force`` is a
        # first-startup hint, not permission for every sibling to resample.
        kind = _safe_worker_type(worker_type)
        sample_key = f"{PROCESS_RUN_ID}:{kind}"
        with _LOCK:
            previous = _LAST_QUEUE_SAMPLE.get(sample_key)
            if previous is not None and (force or now - previous < interval):
                return None
            _LAST_QUEUE_SAMPLE[sample_key] = now
        started = time.monotonic()
        queue = queue_depth_snapshot()
        event = emit_event(worker_type=kind, worker_id=worker_id,
                           event_code="queue_snapshot", outcome_code="queue_sample",
                           reason_code="queue_sample", queue_depth=queue,
                           latency_ms=(time.monotonic() - started) * 1000)
        return (event or {}).get("queue_depth")
    except Exception as exc:
        # Queue telemetry is advisory. A damaged, locked, missing or changing
        # database must never prevent a worker from starting or finishing work.
        try:
            elapsed = (time.monotonic() - started) * 1000
        except (NameError, UnboundLocalError):
            elapsed = 0
        locked = isinstance(exc, sqlite3.OperationalError) and any(
            marker in str(exc).casefold() for marker in ("locked", "busy")
        )
        emit_event(worker_type=worker_type, worker_id=worker_id,
                   event_code="queue_snapshot_unavailable", outcome_code="worker_error",
                   reason_code="database_locked" if locked else "queue_snapshot_unavailable",
                   latency_ms=elapsed, db_lock_wait_ms=elapsed if locked else None)
        return None


def worker_startup(worker_type: str, worker_id: str, *, tor_state: dict | None = None,
                   provider_state: dict | None = None) -> str:
    kind = _safe_worker_type(worker_type)
    safe_id = _safe_worker_id(worker_id, kind)
    _RUN_BY_WORKER[safe_id] = PROCESS_RUN_ID
    if tor_state is None:
        try:
            from opsec_preflight import opsec_status_snapshot
            tor_state = opsec_status_snapshot()
        except Exception:
            tor_state = {}
    emit_event(worker_type=kind, worker_id=safe_id, event_code="startup",
               outcome_code="worker_started", reason_code="worker_started")
    emit_event(worker_type=kind, worker_id=safe_id, event_code="tor_health",
               outcome_code="tor_health_snapshot", reason_code="tor_health_snapshot",
               tor_state=tor_state)
    if provider_state is not None:
        emit_event(worker_type=kind, worker_id=safe_id, event_code="provider_state",
                   outcome_code="provider_state_snapshot",
                   reason_code="provider_state_snapshot", provider_state=provider_state)
    maybe_queue_snapshot(kind, safe_id, force=True)
    return PROCESS_RUN_ID


def worker_shutdown(worker_type: str, worker_id: str) -> None:
    emit_event(worker_type=worker_type, worker_id=worker_id, event_code="shutdown",
               outcome_code="worker_stopped", reason_code="worker_stopped")


def record_iteration(worker_type: str, worker_id: str, *, processed: bool,
                     latency_ms: float | int, failure: object | None = None) -> None:
    """Record an iteration without turning exceptions into false idle signals.

    ``failure`` accepts an exception class/name for compatibility with worker
    call sites, but only the fixed reason mapping is serialized.
    """
    if failure is not None:
        reason = _error_reason(failure, "worker_error")
        emit_event(worker_type=worker_type, worker_id=worker_id,
                   event_code="worker_error", outcome_code=reason,
                   reason_code=reason, latency_ms=latency_ms)
    else:
        emit_event(worker_type=worker_type, worker_id=worker_id, event_code="iteration",
                   outcome_code="work_processed" if processed else "queue_empty",
                   reason_code="work_processed" if processed else "queue_empty",
                   latency_ms=latency_ms)
    maybe_queue_snapshot(worker_type, worker_id)


def record_job_transition(worker_type: str, worker_id: str, status: str, *,
                          job_id: int | None = None, target: object | None = None,
                          error_label: object | None = None,
                          retry_count: int | None = None,
                          latency_ms: float | int | None = None) -> None:
    """Record an authoritative persisted queue transition.

    The status is reduced to a fixed operational event and any error is reduced
    to a reason code.  Neither arbitrary status text nor exception messages can
    reach the log.
    """
    normalized = str(status or "").strip().casefold()
    mapping = {
        "claimed": ("claim", "claim_acquired"),
        "processing": ("claim", "claim_acquired"),
        "retry": ("retry", "retry_scheduled"),
        "queued": ("retry", "retry_scheduled"),
        "pending": ("retry", "retry_scheduled"),
        "blocked": ("blocked", "policy_restricted"),
        "filtered": ("blocked", "policy_restricted"),
        "dead": ("dead_letter", "dead_letter"),
        "dead_letter": ("dead_letter", "dead_letter"),
        "failed": ("dead_letter", "worker_failed"),
        "done": ("finish", "work_processed"),
        "complete": ("finish", "work_processed"),
        "completed": ("finish", "work_processed"),
        "verified": ("finish", "classification_complete"),
        "available": ("finish", "preview_available"),
    }
    event_code, fallback = mapping.get(normalized, ("state", "other_safe_reason"))
    reason = _error_reason(error_label, fallback) if error_label is not None else fallback
    emit_event(worker_type=worker_type, worker_id=worker_id,
               event_code=event_code, job_id=job_id, target=target,
               outcome_code=reason, reason_code=reason,
               retry_count=retry_count, latency_ms=latency_ms)


def record_discovery_outcome(worker_id: str, *, job_id: int | None = None,
                             target: object | None = None,
                             counts: dict | None = None) -> None:
    """Record one aggregate, content-free discovery result for a verified page."""
    safe_counts = _safe_discovery(counts)
    processed = safe_counts.get("processed_total", 0)
    reason = "discovery_complete" if processed > 0 else "discovery_none"
    emit_event(worker_type="verify", worker_id=worker_id,
               event_code="discovery_outcome", job_id=job_id, target=target,
               outcome_code=reason, reason_code=reason,
               discovery_counts=safe_counts)


def record_worker_state(worker_type: str, worker_id: str, state: str, *,
                        current_url_id: int | None = None, current_job_id: int | None = None,
                        last_error: str | None = None) -> None:
    event_code, reason = STATE_MAP.get(str(state or "").casefold(), ("state", "other_safe_reason"))
    actual_job = current_job_id if current_job_id is not None else current_url_id
    if last_error and event_code in {"worker_error", "retry", "dead_letter"}:
        reason = _error_reason(last_error, reason)
    emit_event(worker_type=worker_type, worker_id=worker_id, event_code=event_code,
               job_id=actual_job, outcome_code=reason, reason_code=reason)
    maybe_queue_snapshot(worker_type, worker_id)


def record_db_operation(worker_type: str, worker_id: str | None, operation: str,
                        latency_ms: float | int, error: BaseException | None = None) -> None:
    elapsed = _safe_ms(latency_ms) or 0
    threshold = max(25, get_int("OPS_DB_SLOW_MS", 250))
    locked = isinstance(error, sqlite3.OperationalError) and any(
        marker in str(error).casefold() for marker in ("locked", "busy")
    )
    if not locked and elapsed < threshold:
        return
    emit_event(worker_type=worker_type, worker_id=worker_id,
               event_code="db_lock_delay" if locked else "db_operation_slow",
               outcome_code="database_locked" if locked else "database_slow",
               reason_code="database_locked" if locked else "database_slow",
               db_lock_wait_ms=elapsed, operation_code=operation)


def record_db_operation_deferred(worker_type: str, worker_id: str | None,
                                 operation: str, latency_ms: float | int,
                                 error: BaseException | None = None) -> None:
    """Keep slow successful BEGIN telemetry off the SQLite critical path.

    Errors are emitted synchronously because a failed BEGIN owns no write lock.
    Successful operations below the configured threshold do nothing.  A rare
    slow success is written by a daemon thread, so log rotation/fsync cannot
    extend the caller's transaction hold time.
    """
    elapsed = _safe_ms(latency_ms) or 0
    threshold = max(25, get_int("OPS_DB_SLOW_MS", 250))
    if error is not None:
        record_db_operation(worker_type, worker_id, operation, elapsed, error)
        return
    if elapsed < threshold:
        return
    try:
        thread = threading.Thread(
            target=record_db_operation,
            args=(worker_type, worker_id, operation, elapsed),
            name="arachne-ops-db-log",
            daemon=True,
        )
        thread.start()
    except Exception:
        # Telemetry remains fail-open even if the runtime cannot create a
        # helper thread during shutdown or resource pressure.
        return


def _iter_log_events() -> Iterable[dict[str, Any]]:
    if not LOG_ROOT.is_dir():
        return []
    paths = sorted(set(
        LOG_ROOT.rglob("*.jsonl")
    ) | set(
        LOG_ROOT.rglob("*.jsonl.gz")
    ) | set(
        LOG_ROOT.rglob("*.jsonl.*.gz")
    ))
    events: list[dict[str, Any]] = []
    for path in paths:
        try:
            opener = gzip.open if path.suffix == ".gz" else open
            with opener(path, "rt", encoding="utf-8") as handle:
                for line in handle:
                    if len(line) > 8192:
                        continue
                    try:
                        loaded = json.loads(line)
                    except (json.JSONDecodeError, TypeError):
                        continue
                    safe = _revalidate_event(loaded)
                    if safe:
                        events.append(safe)
        except OSError:
            continue
    return events


def _revalidate_event(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        return None
    worker_type = str(value.get("worker_type") or "")
    run_id = str(value.get("run_id") or "")
    worker_id = str(value.get("worker_id") or "")
    timestamp = str(value.get("timestamp") or "")
    if (worker_type not in WORKER_TYPES or not SAFE_RUN_ID.fullmatch(run_id)
            or not SAFE_WORKER_ID.fullmatch(worker_id)
            or not SAFE_TIMESTAMP.fullmatch(timestamp)):
        return None
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if parsed_timestamp.utcoffset() != timedelta(0):
            return None
    except (OverflowError, ValueError):
        return None
    event = _event(
        worker_type=worker_type, event_code=value.get("event_code"), worker_id=worker_id,
        run_id=run_id, job_id=value.get("job_id"), outcome_code=value.get("outcome_code"),
        reason_code=value.get("reason_code"), latency_ms=value.get("latency_ms"),
        db_lock_wait_ms=value.get("db_lock_wait_ms"), retry_count=value.get("retry_count"),
        queue_depth=value.get("queue_depth"), provider_state=value.get("provider_state"),
        tor_state=value.get("tor_state"), operation_code=value.get("operation_code"),
        discovery_counts=value.get("discovery_counts"),
    )
    event["timestamp"] = timestamp
    event_id = str(value.get("event_id") or "")
    if SAFE_EVENT_ID.fullmatch(event_id):
        event["event_id"] = event_id
    target_ref = str(value.get("target_ref") or "")
    if SAFE_TARGET_REF.fullmatch(target_ref):
        event["target_ref"] = target_ref
    return event


def summarize_events(events: Iterable[dict[str, Any]], *, summary_date: str) -> dict[str, Any]:
    target_date = _safe_summary_date(summary_date)
    selected = []
    for value in events:
        event = _revalidate_event(value)
        if event and str(event.get("timestamp", ""))[:10] == target_date:
            selected.append(event)
    selected.sort(key=lambda item: str(item.get("timestamp", "")))
    transitions = Counter(event.get("event_code") for event in selected)
    throughput = Counter(event.get("worker_type") for event in selected
                         if event.get("event_code") == "finish")
    failures = sum(transitions[key] for key in ("worker_error", "retry", "dead_letter"))
    completed = sum(throughput.values())
    retry_causes = Counter(event.get("reason_code") for event in selected
                           if event.get("event_code") in {"retry", "dead_letter", "worker_error"})
    latencies: dict[str, list[int]] = defaultdict(list)
    for event in selected:
        if isinstance(event.get("latency_ms"), int):
            latencies[str(event.get("worker_type"))].append(int(event["latency_ms"]))
    latency_summary = {}
    for worker, values in latencies.items():
        ordered = sorted(values)
        latency_summary[worker] = {
            "average_ms": round(sum(ordered) / len(ordered)),
            "p95_ms": ordered[min(len(ordered) - 1, max(0, math.ceil(len(ordered) * 0.95) - 1))],
        }
    queue_events = [event.get("queue_depth") for event in selected if event.get("queue_depth")]
    queue_summary: dict[str, dict[str, int]] = {}
    for key in QUEUE_KEYS:
        values = [int(item.get(key, 0)) for item in queue_events]
        if values:
            queue_summary[key] = {
                "start": values[0], "end": values[-1], "max": max(values),
                "growth": values[-1] - values[0],
            }
    waiting = {key: data["end"] for key, data in queue_summary.items()
               if key.endswith("_waiting")}
    bottleneck = max(waiting, key=waiting.get) if waiting and max(waiting.values()) > 0 else "none"
    db_growth = queue_summary.get("database_bytes", {}).get("growth", 0)
    return {
        "schema_version": "arachne.operations.daily.v1",
        "date": target_date,
        "events": len(selected),
        "throughput_by_worker": dict(sorted(throughput.items())),
        "completed": completed,
        "failures": failures,
        "failure_rate": round(failures / max(1, completed + failures), 4),
        "retries": int(transitions["retry"]),
        "dead_letters": int(transitions["dead_letter"]),
        "retry_causes": dict(sorted(retry_causes.items())),
        "queue": queue_summary,
        "database_growth_bytes": int(db_growth),
        "latency": latency_summary,
        "bottleneck": bottleneck,
    }


def _safe_summary_date(value: object) -> str:
    text = str(value or "")
    try:
        parsed = date.fromisoformat(text)
    except ValueError:
        return datetime.now(timezone.utc).date().isoformat()
    return parsed.isoformat() if parsed.isoformat() == text else datetime.now(timezone.utc).date().isoformat()


def _safe_signed_int(value: object, *, maximum: int = 10**15) -> int:
    if value is None or isinstance(value, bool):
        return 0
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(-maximum, min(number, maximum))


def _safe_daily_summary(value: object) -> dict[str, Any] | None:
    """Rebuild a daily summary from an allowlist before it enters a bundle."""
    if not isinstance(value, dict) or value.get("schema_version") != "arachne.operations.daily.v1":
        return None
    raw_date = str(value.get("date") or "")
    if _safe_summary_date(raw_date) != raw_date:
        return None
    throughput_source = value.get("throughput_by_worker")
    throughput = {
        worker: _safe_int(count) or 0
        for worker, count in (throughput_source.items() if isinstance(throughput_source, dict) else ())
        if worker in WORKER_TYPES
    }
    retry_source = value.get("retry_causes")
    retry_causes = {
        reason: _safe_int(count) or 0
        for reason, count in (retry_source.items() if isinstance(retry_source, dict) else ())
        if reason in REASON_CODES
    }
    queue_source = value.get("queue")
    queue: dict[str, dict[str, int]] = {}
    for key, raw in (queue_source.items() if isinstance(queue_source, dict) else ()):
        if key not in QUEUE_KEYS or not isinstance(raw, dict):
            continue
        queue[key] = {
            "start": _safe_int(raw.get("start")) or 0,
            "end": _safe_int(raw.get("end")) or 0,
            "max": _safe_int(raw.get("max")) or 0,
            "growth": _safe_signed_int(raw.get("growth")),
        }
    latency_source = value.get("latency")
    latency: dict[str, dict[str, int]] = {}
    for worker, raw in (latency_source.items() if isinstance(latency_source, dict) else ()):
        if worker not in WORKER_TYPES or not isinstance(raw, dict):
            continue
        latency[worker] = {
            "average_ms": _safe_ms(raw.get("average_ms")) or 0,
            "p95_ms": _safe_ms(raw.get("p95_ms")) or 0,
        }
    try:
        failure_rate = float(value.get("failure_rate") or 0.0)
    except (TypeError, ValueError, OverflowError):
        failure_rate = 0.0
    if not math.isfinite(failure_rate):
        failure_rate = 0.0
    bottleneck = str(value.get("bottleneck") or "none")
    if bottleneck not in {*QUEUE_KEYS, "none"}:
        bottleneck = "none"
    return {
        "schema_version": "arachne.operations.daily.v1",
        "date": raw_date,
        "events": _safe_int(value.get("events")) or 0,
        "throughput_by_worker": dict(sorted(throughput.items())),
        "completed": _safe_int(value.get("completed")) or 0,
        "failures": _safe_int(value.get("failures")) or 0,
        "failure_rate": round(max(0.0, min(failure_rate, 1.0)), 4),
        "retries": _safe_int(value.get("retries")) or 0,
        "dead_letters": _safe_int(value.get("dead_letters")) or 0,
        "retry_causes": dict(sorted(retry_causes.items())),
        "queue": queue,
        "database_growth_bytes": _safe_signed_int(value.get("database_growth_bytes")),
        "latency": latency,
        "bottleneck": bottleneck,
    }


def write_daily_summary(day: str | None = None) -> dict[str, Any]:
    target = _safe_summary_date(day or datetime.now(timezone.utc).date().isoformat())
    summary = summarize_events(_iter_log_events(), summary_date=target)
    folder = LOG_ROOT / "daily"
    folder.mkdir(parents=True, exist_ok=True)
    json_path = folder / f"summary-{target}.json"
    text_path = folder / f"summary-{target}.txt"
    json_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    text_path.write_text(
        "\n".join((
            f"Arachne operational summary {target}",
            f"Completed: {summary['completed']}",
            f"Failures: {summary['failures']} ({summary['failure_rate']:.1%})",
            f"Retries: {summary['retries']}  Dead letters: {summary['dead_letters']}",
            f"Database growth: {summary['database_growth_bytes']} bytes",
            f"Bottleneck: {summary['bottleneck']}",
        )) + "\n",
        encoding="utf-8",
    )
    for path in (json_path, text_path):
        try:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    return summary


def maintain_logs(*, now: float | None = None) -> dict[str, int]:
    try:
        current = time.time() if now is None else float(now)
        if not math.isfinite(current):
            current = time.time()
    except (TypeError, ValueError, OverflowError):
        current = time.time()
    def safe_mtime(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return current

    detail_days = max(1, get_int("OPS_LOG_RETENTION_DAYS", 14))
    summary_days = max(detail_days, get_int("OPS_SUMMARY_RETENTION_DAYS", 30))
    removed = 0
    compressed = 0
    if not LOG_ROOT.is_dir():
        return {"compressed": 0, "removed": 0}
    for path in list(LOG_ROOT.rglob("*")):
        if not path.is_file():
            continue
        try:
            age = current - path.stat().st_mtime
        except OSError:
            continue
        is_summary = "daily" in path.parts
        retention = summary_days if is_summary else detail_days
        if age >= retention * 86400:
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
        elif not is_summary and path.suffix == ".jsonl" and age >= 86400:
            target = path.with_name(path.name + ".gz")
            try:
                with path.open("rb") as source, gzip.open(target, "wb", compresslevel=6) as output:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        output.write(chunk)
                path.unlink()
                compressed += 1
            except OSError:
                target.unlink(missing_ok=True)
    # Retention bounds time; this additional aggregate bound protects against a
    # restart storm creating many individually rotated run files inside that window.
    max_detail_bytes = max(
        16 * 1024 * 1024,
        get_int("OPS_LOG_TOTAL_MAX_BYTES", 512 * 1024 * 1024),
    )
    detail_paths = sorted(
        {
            path for pattern in ("*.jsonl", "*.jsonl.gz", "*.jsonl.*.gz")
            for path in LOG_ROOT.rglob(pattern)
            if path.is_file() and "daily" not in path.parts
        },
        key=safe_mtime,
    )
    sizes: dict[Path, int] = {}
    for path in detail_paths:
        try:
            sizes[path] = path.stat().st_size
        except OSError:
            continue
    total_detail_bytes = sum(sizes.values())
    for path in detail_paths:
        if total_detail_bytes <= max_detail_bytes:
            break
        try:
            age = current - path.stat().st_mtime
            # Never unlink a file a live process may still hold open. Rotated
            # gzip files are immutable and may be pruned immediately.
            if path.suffix == ".jsonl" and age < 3600:
                continue
            size = sizes.get(path, 0)
            path.unlink()
            total_detail_bytes = max(0, total_detail_bytes - size)
            removed += 1
        except OSError:
            continue
    diagnostic_limit = max(1, min(get_int("OPS_DIAGNOSTIC_RETENTION_COUNT", 10), 100))
    diagnostic_folder = LOG_ROOT / "diagnostics"
    if diagnostic_folder.is_dir():
        bundles = sorted(
            diagnostic_folder.glob("arachne-diagnostic-*.zip"),
            key=safe_mtime,
            reverse=True,
        )
        for path in bundles[diagnostic_limit:]:
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
    return {"compressed": compressed, "removed": removed}


def _diagnostic_log_paths() -> list[Path]:
    """Return detail logs newest first without exposing their names in output."""
    if not LOG_ROOT.is_dir():
        return []
    paths = {
        path for pattern in ("*.jsonl", "*.jsonl.gz", "*.jsonl.*.gz")
        for path in LOG_ROOT.rglob(pattern)
        if path.is_file() and "daily" not in path.parts
    }

    def mtime(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    return sorted(paths, key=mtime, reverse=True)


def _recent_safe_events(hours: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read a hard-bounded, revalidated tail of recent operational events.

    The byte limit applies to decompressed bytes, so a gzip file cannot turn a
    small on-disk input into unbounded diagnostic work.  A fixed line limit
    matches the writer's event limit and prevents a malformed local log from
    allocating an arbitrarily large JSON line.
    """
    try:
        bounded_hours = max(1, min(int(hours), 168))
    except (TypeError, ValueError, OverflowError):
        bounded_hours = 24
    event_limit = max(1, min(get_int("OPS_DIAGNOSTIC_MAX_EVENTS", 2500), 10000))
    byte_limit = max(
        _MAX_EVENT_LINE_BYTES,
        min(get_int("OPS_DIAGNOSTIC_SCAN_MAX_BYTES", 64 * 1024 * 1024),
            256 * 1024 * 1024),
    )
    cutoff = datetime.now(timezone.utc) - timedelta(hours=bounded_hours)
    # A min-heap retains only the newest bounded number of matching events,
    # independent of file ordering and without materializing the full corpus.
    retained: list[tuple[str, str, int, dict[str, Any]]] = []
    matched = 0
    scanned_bytes = 0
    files_scanned = 0
    scan_truncated = False
    paths = _diagnostic_log_paths()

    for path_index, path in enumerate(paths):
        if scanned_bytes >= byte_limit:
            scan_truncated = True
            break
        try:
            compressed = path.suffix == ".gz"
            opener = gzip.open if compressed else open
            with opener(path, "rb") as handle:
                files_scanned += 1
                # Plain current logs are seekable.  If one file alone exceeds
                # the remaining diagnostic budget, start at its bounded tail
                # so the bundle contains the newest operational events rather
                # than the oldest events from byte zero.  Gzip remains a
                # bounded best-effort forward read: seeking to its tail would
                # decompress the skipped prefix and defeat the work limit.
                if not compressed:
                    try:
                        file_size = path.stat().st_size
                    except OSError:
                        file_size = 0
                    remaining_budget = byte_limit - scanned_bytes
                    if file_size > remaining_budget > 0:
                        handle.seek(file_size - remaining_budget)
                        scan_truncated = True
                        # The seek point can be inside a JSON line.  Discard
                        # that fragment in bounded chunks so it can never be
                        # parsed as a standalone suffix.
                        while scanned_bytes < byte_limit:
                            remaining = byte_limit - scanned_bytes
                            fragment = handle.readline(min(_MAX_EVENT_LINE_BYTES, remaining))
                            if not fragment:
                                break
                            scanned_bytes += len(fragment)
                            if fragment.endswith(b"\n"):
                                break
                while scanned_bytes < byte_limit:
                    remaining = byte_limit - scanned_bytes
                    read_limit = min(_MAX_EVENT_LINE_BYTES + 1, remaining)
                    line = handle.readline(read_limit)
                    if not line:
                        break
                    scanned_bytes += len(line)
                    if len(line) > _MAX_EVENT_LINE_BYTES:
                        # Drain the rest of this malformed line in bounded
                        # chunks so no suffix can be mistaken for a JSON event.
                        while not line.endswith(b"\n") and scanned_bytes < byte_limit:
                            remaining = byte_limit - scanned_bytes
                            line = handle.readline(min(_MAX_EVENT_LINE_BYTES, remaining))
                            if not line:
                                break
                            scanned_bytes += len(line)
                        if scanned_bytes >= byte_limit and not line.endswith(b"\n"):
                            scan_truncated = True
                        continue
                    if not line.endswith(b"\n") and scanned_bytes >= byte_limit:
                        scan_truncated = True
                        break
                    try:
                        loaded = json.loads(line.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
                        continue
                    event = _revalidate_event(loaded)
                    if not event:
                        continue
                    try:
                        timestamp = datetime.fromisoformat(
                            str(event["timestamp"]).replace("Z", "+00:00")
                        )
                    except (KeyError, ValueError):
                        continue
                    if timestamp < cutoff:
                        continue
                    matched += 1
                    key = (str(event["timestamp"]), str(event["event_id"]))
                    # The sequence is a safe numeric tie-breaker for a valid
                    # event duplicated across a live and rotated log.  Without
                    # it heapq would eventually try to compare two dicts.
                    entry = (key[0], key[1], matched, event)
                    if len(retained) < event_limit:
                        heapq.heappush(retained, entry)
                    elif (key[0], key[1], matched) > retained[0][:3]:
                        heapq.heapreplace(retained, entry)
                if scanned_bytes >= byte_limit:
                    # There may be unread content in this file or later files.
                    scan_truncated = True
        except (OSError, EOFError):
            continue
        if scanned_bytes >= byte_limit:
            scan_truncated = True
            break
        if path_index + 1 < len(paths) and scanned_bytes >= byte_limit:
            scan_truncated = True
            break

    events = [entry[3] for entry in sorted(retained)]
    return events, {
        "files_scanned": files_scanned,
        "decompressed_bytes_scanned": scanned_bytes,
        "matching_events_seen": matched,
        "events_exported": len(events),
        "event_limit": event_limit,
        "decompressed_byte_limit": byte_limit,
        "events_truncated": matched > len(events),
        "scan_truncated": scan_truncated,
    }


def build_sanitized_diagnostic_bundle(*, hours: int = 24,
                                      output: Path | None = None) -> Path:
    with _DIAGNOSTIC_BUILD_LOCK:
        try:
            bounded_hours = max(1, min(int(hours), 168))
        except (TypeError, ValueError, OverflowError):
            bounded_hours = 24
        events, scan_stats = _recent_safe_events(bounded_hours)
        database_state = "missing"
        try:
            queue = queue_depth_snapshot()
            database_state = "available" if Path(DB_PATH).is_file() else "missing"
        except (OSError, sqlite3.Error):
            # A diagnostic bundle is most useful when storage itself is unhealthy.
            queue = {key: 0 for key in QUEUE_KEYS}
            try:
                database_state = "unavailable" if Path(DB_PATH).exists() else "missing"
            except OSError:
                database_state = "unavailable"
        try:
            from opsec_preflight import opsec_status_snapshot
            tor = _safe_tor_state(opsec_status_snapshot())
        except Exception:
            tor = _safe_tor_state({})
        try:
            from deep_discovery_providers import provider_status
            providers = _safe_provider_state(provider_status())
        except Exception:
            providers = _safe_provider_state({})
        daily = []
        daily_paths = (
            sorted((LOG_ROOT / "daily").glob("summary-*.json"))[-31:]
            if (LOG_ROOT / "daily").is_dir() else []
        )
        for path in daily_paths:
            try:
                # Daily summaries are generated from a small fixed schema.
                # Refuse an oversized/corrupt local file instead of allowing
                # it to defeat the diagnostic work bounds.
                with path.open("rb") as handle:
                    encoded_summary = handle.read(64 * 1024 + 1)
                if len(encoded_summary) > 64 * 1024:
                    continue
                value = json.loads(encoded_summary.decode("utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            safe_summary = _safe_daily_summary(value)
            if safe_summary:
                daily.append(safe_summary)
        database = {
            "database_bytes": queue.get("database_bytes", 0),
            "wal_bytes": queue.get("wal_bytes", 0),
            "state": database_state,
            "quick_check": "not_run_bounded_bundle",
        }
        health = {
            "crawler_enabled": get_bool("ONION_CRAWLER_ENABLED", False),
            "strict_mode": get_bool("OPSEC_STRICT_MODE", False),
            "preview_enabled": get_bool("ENABLE_PAGE_SCREENSHOTS", False),
            "discovery_network_enabled": get_bool("DEEP_DISCOVERY_NETWORK_ENABLED", False),
        }
        payloads = {
            "events.jsonl": "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            "queues.json": json.dumps(_safe_queue(queue), indent=2, sort_keys=True),
            "database.json": json.dumps(database, indent=2, sort_keys=True),
            "health.json": json.dumps(health, indent=2, sort_keys=True),
            "tor.json": json.dumps(tor, indent=2, sort_keys=True),
            "providers.json": json.dumps(providers, indent=2, sort_keys=True),
            "daily_summaries.json": json.dumps(daily[-31:], indent=2, sort_keys=True),
        }
        manifest = {
            "schema_version": "arachne.diagnostic.v1",
            "generated_at": _utc_now(),
            "hours": bounded_hours,
            "event_count": len(events),
            "scan": scan_stats,
            "members": sorted(["manifest.json", *payloads]),
            "checksums": {name: hashlib.sha256(value.encode("utf-8")).hexdigest()
                          for name, value in payloads.items()},
        }
        payloads["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True)
        folder = LOG_ROOT / "diagnostics"
        folder.mkdir(parents=True, exist_ok=True)
        destination = Path(output) if output is not None else folder / (
            "arachne-diagnostic-"
            + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            + f"-{os.getpid()}-{uuid.uuid4().hex[:8]}.zip"
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(
            f".{destination.name}.{os.getpid()}-{uuid.uuid4().hex}.tmp"
        )
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                stat.S_IRUSR | stat.S_IWUSR,
            )
            os.close(descriptor)
            descriptor = None
            with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name in sorted(payloads):
                    archive.writestr(name, payloads[name])
            os.replace(temporary, destination)
            try:
                destination.chmod(stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
            return destination
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Arachne sanitized operational observability")
    parser.add_argument("--daily-summary", action="store_true")
    parser.add_argument("--maintain", action="store_true")
    parser.add_argument("--diagnostic-bundle", action="store_true")
    parser.add_argument("--hours", type=int, default=24)
    args = parser.parse_args()
    if args.daily_summary:
        print(json.dumps(write_daily_summary(), sort_keys=True))
    if args.maintain:
        print(json.dumps(maintain_logs(), sort_keys=True))
    if args.diagnostic_bundle:
        path = build_sanitized_diagnostic_bundle(hours=args.hours)
        print(path.name)
    if not (args.daily_summary or args.maintain or args.diagnostic_bundle):
        parser.print_help()


if __name__ == "__main__":
    main()
