from __future__ import annotations

import asyncio
import gzip
import json
import os
import sqlite3
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import operational_observability as operations


@pytest.fixture
def isolated_operations(tmp_path, monkeypatch):
    values = {
        "OPS_LOG_MAX_BYTES": 16 * 1024,
        "OPS_LOG_BACKUP_COUNT": 2,
        "OPS_QUEUE_SAMPLE_SECONDS": 60,
        "OPS_DB_SLOW_MS": 25,
        "OPS_LOG_RETENTION_DAYS": 2,
        "OPS_SUMMARY_RETENTION_DAYS": 5,
    }
    monkeypatch.setattr(operations, "LOG_ROOT", tmp_path / "logs" / "operations")
    monkeypatch.setattr(operations, "KEY_PATH", tmp_path / "runtime" / "observability.key")
    monkeypatch.setattr(operations, "DB_PATH", tmp_path / "messages.db")
    monkeypatch.setattr(
        operations,
        "PROCESS_RUN_ID",
        "20260716T120000Z-123-abcdef12",
    )
    monkeypatch.setattr(operations, "get_int", lambda name, default=0: values.get(name, default))
    monkeypatch.setattr(operations, "get_bool", lambda _name, default=False: bool(default))
    operations._RUN_BY_WORKER.clear()
    operations._LAST_QUEUE_SAMPLE.clear()
    return {"root": operations.LOG_ROOT, "values": values, "tmp": tmp_path}


def _jsonl_events(root: Path) -> list[dict]:
    events = []
    paths = sorted(root.rglob("*.jsonl")) + sorted(root.rglob("*.jsonl.*.gz"))
    for path in paths:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8") as handle:
            events.extend(json.loads(line) for line in handle if line.strip())
    return events


def test_strict_event_schema_hashes_targets_and_drops_sensitive_text(isolated_operations):
    raw_target = (
        "http://sensitive-example.onion/private/path?token=fake-token-123&session=fake-session"
    )
    event = operations.emit_event(
        worker_type="fetch",
        worker_id="fetch:123:1:99",
        event_code="claim",
        job_id=42,
        target=raw_target,
        outcome_code=raw_target,
        reason_code="page_title_secret",
        latency_ms=12.4,
    )

    assert event is not None
    assert event["target_ref"].startswith("h1_")
    assert event["outcome_code"] == "other_safe_reason"
    assert event["reason_code"] == "other_safe_reason"
    assert set(event) <= {
        "schema_version", "timestamp", "event_id", "event_code", "run_id",
        "worker_type", "worker_id", "outcome_code", "reason_code", "job_id",
        "target_ref", "latency_ms", "db_lock_wait_ms", "retry_count",
        "queue_depth", "provider_state", "tor_state", "operation_code",
        "discovery_counts",
    }
    serialized = json.dumps(event, sort_keys=True)
    log_bytes = b"".join(path.read_bytes() for path in operations.LOG_ROOT.rglob("*.jsonl"))
    for secret in (raw_target, "sensitive-example", "private/path", "fake-token-123",
                   "fake-session", "page_title_secret"):
        assert secret not in serialized
        assert secret.encode() not in log_bytes
    assert operations.safe_target_ref(raw_target) == event["target_ref"]
    assert operations.safe_target_ref(raw_target + "x") != event["target_ref"]
    assert operations.KEY_PATH.read_bytes() not in log_bytes


def test_transition_tor_provider_and_db_lock_events_are_useful(isolated_operations):
    worker_id = "deep_discovery:123:1:99"
    operations.worker_startup(
        "deep_discovery",
        worker_id,
        tor_state={
            "status": "PASS", "tor_socks_reachable": True,
            "socks5h_enforced": True, "socks_isolation": "configured",
            "strict_mode": True, "live_checks_performed": False,
        },
        provider_state={
            "network_enabled": False,
            "enabled_providers": ["local_arachne"],
            "disabled_providers": ["rdap_exact_domain"],
        },
    )
    operations.record_worker_state(
        "deep_discovery", worker_id, "local_correlation", current_job_id=17
    )
    operations.record_worker_state(
        "deep_discovery", worker_id, "local_complete", current_job_id=17
    )
    operations.record_worker_state(
        "deep_discovery", worker_id, "retry", current_job_id=18,
        last_error="ConnectTimeout",
    )
    operations.record_worker_state(
        "deep_discovery", worker_id, "dead_letter", current_job_id=19
    )
    operations.record_db_operation(
        "deep_discovery", worker_id, "claim_deep_discovery", 75,
        sqlite3.OperationalError("database is locked"),
    )
    operations.worker_shutdown("deep_discovery", worker_id)

    events = _jsonl_events(operations.LOG_ROOT)
    codes = {event["event_code"] for event in events}
    assert {"startup", "tor_health", "provider_state", "claim", "finish", "retry",
            "dead_letter", "db_lock_delay", "shutdown"} <= codes
    assert all(event["run_id"] == operations.PROCESS_RUN_ID for event in events)
    assert {event.get("job_id") for event in events} >= {17, 18, 19, None}
    startup = next(event for event in events if event["event_code"] == "startup")
    assert "tor_state" not in startup
    assert "provider_state" not in startup
    tor_health = next(event for event in events if event["event_code"] == "tor_health")
    provider = next(event for event in events if event["event_code"] == "provider_state")
    assert tor_health["tor_state"]["status"] == "PASS"
    assert provider["provider_state"]["enabled_providers"] == ["local_arachne"]
    lock = next(event for event in events if event["event_code"] == "db_lock_delay")
    assert lock["reason_code"] == "database_locked"
    assert lock["db_lock_wait_ms"] == 75
    retry = next(event for event in events
                 if event["event_code"] == "retry" and event.get("job_id") == 18)
    assert retry["reason_code"] == "network_timeout"
    assert "database is locked" not in json.dumps(events)


def test_jsonl_logs_rotate_and_compress_without_losing_schema(isolated_operations):
    worker_id = "fetch:123:1:99"
    for index in range(180):
        operations.emit_event(
            worker_type="fetch", worker_id=worker_id, event_code="finish",
            job_id=index, target=f"http://rotation-{index}.onion/?password=fake",
            outcome_code="fetch_complete", reason_code="fetch_complete",
            latency_ms=index,
        )

    compressed = list(operations.LOG_ROOT.rglob("*.jsonl.*.gz"))
    assert compressed
    assert len(compressed) <= 2
    events = _jsonl_events(operations.LOG_ROOT)
    assert events
    assert all(event["schema_version"] == operations.SCHEMA_VERSION for event in events)
    all_text = "\n".join(json.dumps(event) for event in events)
    assert ".onion" not in all_text
    assert "password=fake" not in all_text


def test_daily_summary_reports_throughput_growth_failures_and_bottleneck(isolated_operations):
    day = "2026-07-16"

    def event(code, worker, timestamp, *, queue=None, reason="classification_complete"):
        value = operations._event(
            worker_type=worker, worker_id=f"{worker}:123:1:99",
            event_code=code, outcome_code=reason, reason_code=reason,
            queue_depth=queue, latency_ms=100,
        )
        value["timestamp"] = timestamp
        return value

    events = [
        event("queue_snapshot", "fetch", f"{day}T00:00:00Z", queue={
            "fetch_waiting": 2, "verify_waiting": 3, "database_bytes": 100,
        }, reason="queue_sample"),
        event("finish", "fetch", f"{day}T01:00:00Z"),
        event("finish", "verify", f"{day}T02:00:00Z"),
        event("retry", "verify", f"{day}T03:00:00Z", reason="retry_scheduled"),
        event("queue_snapshot", "fetch", f"{day}T23:00:00Z", queue={
            "fetch_waiting": 4, "verify_waiting": 9, "database_bytes": 170,
        }, reason="queue_sample"),
    ]
    summary = operations.summarize_events(events, summary_date=day)

    assert summary["completed"] == 2
    assert summary["throughput_by_worker"] == {"fetch": 1, "verify": 1}
    assert summary["failures"] == 1
    assert summary["failure_rate"] == pytest.approx(0.3333)
    assert summary["queue"]["verify_waiting"]["growth"] == 6
    assert summary["database_growth_bytes"] == 70
    assert summary["retry_causes"] == {"retry_scheduled": 1}
    assert summary["bottleneck"] == "verify_waiting"


def test_queue_snapshot_is_read_only_and_reports_all_stages(isolated_operations):
    db_path = operations.DB_PATH
    with sqlite3.connect(db_path) as db:
        db.executescript("""
        CREATE TABLE onion_urls(status TEXT);
        CREATE TABLE fetched_pages(classification_status TEXT);
        CREATE TABLE site_card_jobs(status TEXT);
        CREATE TABLE page_preview_jobs(status TEXT);
        CREATE TABLE deep_discovery_jobs(status TEXT);
        CREATE TABLE worker_instances(worker_id TEXT);
        INSERT INTO onion_urls VALUES ('queued'),('retry'),('done');
        INSERT INTO fetched_pages VALUES ('pending'),('retry'),('done');
        INSERT INTO site_card_jobs VALUES ('queued'),('dead_letter');
        INSERT INTO page_preview_jobs VALUES ('claimed'),('done');
        INSERT INTO deep_discovery_jobs VALUES ('retry'),('dead_letter');
        INSERT INTO worker_instances VALUES ('fetch:1');
        """)
    before = db_path.read_bytes()
    snapshot = operations.queue_depth_snapshot()

    assert snapshot["fetch_waiting"] == 2
    assert snapshot["verify_waiting"] == 2
    assert snapshot["card_waiting"] == 1
    assert snapshot["preview_waiting"] == 1
    assert snapshot["deep_discovery_waiting"] == 1
    assert snapshot["retry_total"] == 3
    assert snapshot["dead_letter_total"] == 2
    assert snapshot["database_bytes"] == db_path.stat().st_size
    assert db_path.read_bytes() == before


def test_iteration_failures_and_authoritative_transitions_are_reason_coded(
        isolated_operations):
    worker_id = "verify:123:1:99"
    secret_error = "ConnectTimeout: http://never-log-this.onion/?token=hidden"

    operations.record_iteration(
        "verify", worker_id, processed=False, latency_ms=321,
        failure=secret_error,
    )
    operations.record_job_transition(
        "verify", worker_id, "retry", job_id=77,
        error_label=secret_error, retry_count=2,
    )

    events = _jsonl_events(operations.LOG_ROOT)
    assert not any(event["outcome_code"] == "queue_empty" for event in events)
    assert any(event["event_code"] == "worker_error"
               and event["reason_code"] == "network_timeout" for event in events)
    retry = next(event for event in events if event["event_code"] == "retry")
    assert retry["job_id"] == 77
    assert retry["retry_count"] == 2
    assert retry["reason_code"] == "network_timeout"
    serialized = json.dumps(events, sort_keys=True)
    assert "never-log-this" not in serialized
    assert "token=hidden" not in serialized


def test_queue_sampling_is_once_per_process_and_worker_stage(
        isolated_operations, monkeypatch):
    calls = []

    def snapshot():
        calls.append(True)
        return {"fetch_waiting": 4}

    monkeypatch.setattr(operations, "queue_depth_snapshot", snapshot)
    first = operations.maybe_queue_snapshot("fetch", "fetch:123:1:10", force=True)
    second = operations.maybe_queue_snapshot("fetch", "fetch:123:2:11", force=True)

    assert first == {"fetch_waiting": 4}
    assert second is None
    assert calls == [True]


def test_discovery_outcome_is_aggregate_only_and_drops_arbitrary_fields(
        isolated_operations):
    raw = "http://do-not-log.onion/private"
    operations.record_discovery_outcome(
        "verify:123:1:99", job_id=88, target=raw,
        counts={
            "processed_total": 12, "queued_new": 5, "already_known": 4,
            "rejected": 3, "restricted": 1, "deferred": 2, "blocked": 1,
            "raw_url": raw, "category": "sensitive-category",
        },
    )

    event = next(event for event in _jsonl_events(operations.LOG_ROOT)
                 if event["event_code"] == "discovery_outcome")
    assert event["reason_code"] == "discovery_complete"
    assert event["discovery_counts"] == {
        "processed_total": 12, "queued_new": 5, "already_known": 4,
        "rejected": 3, "restricted": 1, "deferred": 2, "blocked": 1,
    }
    serialized = json.dumps(event, sort_keys=True)
    assert "raw_url" not in serialized
    assert "sensitive-category" not in serialized
    assert ".onion" not in serialized


def test_diagnostic_bundle_revalidates_logs_and_daily_summaries(isolated_operations):
    poison = "http://poisoned-example.onion/private?token=do-not-export"
    event = operations.emit_event(
        worker_type="verify", worker_id="verify:123:1:99", event_code="finish",
        job_id=7, target=poison, outcome_code="classification_complete",
        reason_code="classification_complete",
    )
    assert event
    log_path = next(operations.LOG_ROOT.rglob("*.jsonl"))
    injected = dict(event)
    injected.update({
        "raw_url": poison,
        "page_text": "raw page body",
        "credential": "123456789:FAKE_BOT_TOKEN",
        "personal_identifier": "person@example.test",
    })
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(injected) + "\n")
    daily_dir = operations.LOG_ROOT / "daily"
    daily_dir.mkdir(parents=True)
    (daily_dir / "summary-2026-07-16.json").write_text(json.dumps({
        "schema_version": "arachne.operations.daily.v1",
        "date": "2026-07-16",
        "events": 1,
        "raw_page": "raw page body",
        "secret": "123456789:FAKE_BOT_TOKEN",
    }), encoding="utf-8")

    bundle = operations.build_sanitized_diagnostic_bundle(
        hours=168, output=isolated_operations["tmp"] / "diagnostic.zip"
    )
    expected = {
        "manifest.json", "events.jsonl", "queues.json", "database.json",
        "health.json", "tor.json", "providers.json", "daily_summaries.json",
    }
    with zipfile.ZipFile(bundle) as archive:
        assert set(archive.namelist()) == expected
        exported = b"\n".join(archive.read(name) for name in archive.namelist())
        manifest = json.loads(archive.read("manifest.json"))
    for secret in (poison, b"raw page body".decode(), "FAKE_BOT_TOKEN",
                   "person@example.test", "poisoned-example"):
        assert secret.encode() not in exported
    assert manifest["members"] == sorted(expected)
    assert "messages.db" not in archive.namelist()
    assert operations.KEY_PATH.name not in archive.namelist()


def test_concurrent_diagnostic_builds_use_unique_atomic_archives(isolated_operations):
    operations.emit_event(
        worker_type="verify", worker_id="verify:123:1:99", event_code="finish",
        job_id=7, outcome_code="classification_complete",
        reason_code="classification_complete",
    )
    expected = {
        "manifest.json", "events.jsonl", "queues.json", "database.json",
        "health.json", "tor.json", "providers.json", "daily_summaries.json",
    }

    with ThreadPoolExecutor(max_workers=4) as executor:
        bundles = list(executor.map(
            lambda _index: operations.build_sanitized_diagnostic_bundle(hours=24),
            range(6),
        ))

    assert len({path.name for path in bundles}) == len(bundles)
    for path in bundles:
        assert path.is_file()
        with zipfile.ZipFile(path) as archive:
            assert archive.testzip() is None
            assert set(archive.namelist()) == expected
    assert not list((operations.LOG_ROOT / "diagnostics").glob(".*.tmp"))


def test_failed_diagnostic_write_preserves_existing_destination_and_cleans_temp(
        isolated_operations, monkeypatch):
    destination = isolated_operations["tmp"] / "existing-diagnostic.zip"
    original = b"previous-complete-artifact"
    destination.write_bytes(original)

    class ExplodingZip:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def writestr(self, *_args, **_kwargs):
            raise OSError("simulated archive failure")

    monkeypatch.setattr(operations.zipfile, "ZipFile", ExplodingZip)

    with pytest.raises(OSError, match="simulated archive failure"):
        operations.build_sanitized_diagnostic_bundle(hours=24, output=destination)

    assert destination.read_bytes() == original
    assert not list(destination.parent.glob(f".{destination.name}.*.tmp"))


def test_diagnostic_scan_has_hard_event_byte_and_line_bounds(
        isolated_operations):
    isolated_operations["values"]["OPS_DIAGNOSTIC_MAX_EVENTS"] = 3
    isolated_operations["values"]["OPS_DIAGNOSTIC_SCAN_MAX_BYTES"] = 8192
    log_path = operations.LOG_ROOT / "verify" / "bounded.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    events = []
    for job_id in range(12):
        events.append(operations._event(
            worker_type="verify", worker_id="verify:123:1:99",
            event_code="finish", job_id=job_id,
            outcome_code="classification_complete",
            reason_code="classification_complete",
        ))
    poison = "http://oversized-secret.onion/?token=never-export"
    with log_path.open("wb") as handle:
        handle.write((poison * 1000).encode("utf-8") + b"\n")
        for event in events:
            handle.write((json.dumps(event) + "\n").encode("utf-8"))

    bundle = operations.build_sanitized_diagnostic_bundle(
        hours=24, output=isolated_operations["tmp"] / "bounded.zip"
    )
    with zipfile.ZipFile(bundle) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        event_lines = [line for line in archive.read("events.jsonl").splitlines() if line]
        exported = b"\n".join(archive.read(name) for name in archive.namelist())

    scan = manifest["scan"]
    assert len(event_lines) == 3
    assert scan["events_exported"] == 3
    assert scan["event_limit"] == 3
    assert scan["events_truncated"] is True
    assert scan["decompressed_bytes_scanned"] <= 8192
    assert scan["decompressed_byte_limit"] == 8192
    assert scan["scan_truncated"] is True
    assert poison.encode() not in exported
    assert b"oversized-secret" not in exported


def test_diagnostic_scan_tails_newest_events_from_oversized_plain_current_log(
        isolated_operations):
    isolated_operations["values"]["OPS_DIAGNOSTIC_MAX_EVENTS"] = 5
    isolated_operations["values"]["OPS_DIAGNOSTIC_SCAN_MAX_BYTES"] = 8192
    log_path = operations.LOG_ROOT / "fetch" / "oversized-current.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    base = datetime.now(timezone.utc) - timedelta(minutes=3)
    with log_path.open("wb") as handle:
        for job_id in range(100):
            event = operations._event(
                worker_type="fetch", worker_id="fetch:123:1:99",
                event_code="finish", job_id=job_id,
                outcome_code="fetch_complete", reason_code="fetch_complete",
            )
            event["timestamp"] = (
                base + timedelta(seconds=job_id)
            ).isoformat().replace("+00:00", "Z")
            handle.write((json.dumps(event) + "\n").encode("utf-8"))
    assert log_path.stat().st_size > 8192

    bundle = operations.build_sanitized_diagnostic_bundle(
        hours=24, output=isolated_operations["tmp"] / "tail-current.zip"
    )
    with zipfile.ZipFile(bundle) as archive:
        exported = [json.loads(line) for line in archive.read("events.jsonl").splitlines()]
        manifest = json.loads(archive.read("manifest.json"))

    assert [event["job_id"] for event in exported] == [95, 96, 97, 98, 99]
    assert manifest["scan"]["events_exported"] == 5
    assert manifest["scan"]["events_truncated"] is True
    assert manifest["scan"]["scan_truncated"] is True
    assert manifest["scan"]["decompressed_bytes_scanned"] <= 8192


def test_retention_compresses_old_detail_and_never_touches_external_files(
        isolated_operations):
    now = time.time()
    old = operations.LOG_ROOT / "fetch" / "expired.jsonl"
    compressible = operations.LOG_ROOT / "verify" / "compress.jsonl"
    summary = operations.LOG_ROOT / "daily" / "summary-2026-07-14.json"
    for path in (old, compressible, summary):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")
    os.utime(old, (now - 3 * 86400, now - 3 * 86400))
    os.utime(compressible, (now - 36 * 3600, now - 36 * 3600))
    os.utime(summary, (now - 3 * 86400, now - 3 * 86400))
    external = isolated_operations["tmp"] / ".env"
    external.write_text("TELEGRAM_BOT_TOKEN=must-stay", encoding="utf-8")

    result = operations.maintain_logs(now=now)

    assert result == {"compressed": 1, "removed": 1}
    assert not old.exists()
    assert not compressible.exists()
    assert compressible.with_name(compressible.name + ".gz").exists()
    assert summary.exists()
    assert external.read_text(encoding="utf-8") == "TELEGRAM_BOT_TOKEN=must-stay"


def test_observability_failure_never_changes_worker_outcome(isolated_operations, monkeypatch):
    monkeypatch.setattr(
        operations, "_run_path",
        lambda _event: (_ for _ in ()).throw(OSError("read-only filesystem")),
    )
    assert operations.emit_event(
        worker_type="card", worker_id="card:123:1:99", event_code="finish",
        outcome_code="card_complete", reason_code="card_complete",
    ) is None


def test_worker_sources_use_native_observability_without_raw_payload_logging():
    root = Path(__file__).resolve().parents[1]
    for name in (
        "fetch_worker.py", "verify_worker.py", "card_worker.py",
        "preview_worker.py", "deep_discovery_worker.py",
    ):
        source = (root / name).read_text(encoding="utf-8")
        assert "import operational_observability as operations" in source
        assert "operations.worker_startup" in source
        assert "operations.worker_shutdown" in source
        assert "operations.record_iteration" in source
        assert "str(exc)" not in source
    storage_source = (root / "storage.py").read_text(encoding="utf-8")
    assert "def _begin_immediate" in storage_source
    assert "operations.record_db_operation" in storage_source
    assert "operations.record_db_operation_deferred" in storage_source


def test_telegram_admin_can_pull_only_the_sanitized_bundle(
        isolated_db, isolated_operations, monkeypatch):
    import arachne

    bundle = isolated_operations["tmp"] / "safe-diagnostics.zip"
    bundle.write_bytes(b"safe zip placeholder")
    builds = []

    def build_bundle(*, hours=24, output=None):
        builds.append(hours)
        return bundle

    sent = []

    class Bot:
        async def send_file(self, chat_id, path, **kwargs):
            sent.append((chat_id, Path(path), kwargs))

    class Event:
        sender_id = 222
        chat_id = 333
        raw_text = "/diagnostics 48"

        def __init__(self):
            self.responses = []

        async def respond(self, *args, **kwargs):
            self.responses.append((args, kwargs))

    monkeypatch.setattr(arachne, "_telegram_admin_ids", lambda: {222})
    monkeypatch.setattr(arachne.operations, "build_sanitized_diagnostic_bundle", build_bundle)
    monkeypatch.setattr(arachne, "bot", Bot())

    event = Event()
    asyncio.run(arachne.diagnostic_bundle_command(event))

    assert builds == [48]
    # Even when an admin invokes the command in a group, the file is delivered
    # only to that authenticated admin's private user ID.
    assert sent[0][0] == 222
    assert sent[0][1] == bundle
    assert "sanitized" in sent[0][2]["caption"].casefold()
    assert event.responses == []


def test_telegram_diagnostic_pull_rejects_non_admin_before_build(
        isolated_db, isolated_operations, monkeypatch):
    import arachne

    builds = []

    class Event:
        sender_id = 999
        chat_id = 999
        raw_text = "/diagnostics"

        def __init__(self):
            self.responses = []

        async def respond(self, *args, **kwargs):
            self.responses.append((args, kwargs))

    monkeypatch.setattr(arachne, "_telegram_admin_ids", lambda: {222})
    monkeypatch.setattr(
        arachne.operations, "build_sanitized_diagnostic_bundle",
        lambda **_kwargs: builds.append(True),
    )
    event = Event()
    asyncio.run(arachne.diagnostic_bundle_command(event))

    assert not builds
    assert event.responses == [(('Not authorized.',), {})]


def test_telegram_diagnostic_helper_rechecks_admin_and_refuses_oversized_bundle(
        isolated_db, isolated_operations, monkeypatch):
    import arachne

    bundle = isolated_operations["tmp"] / "too-large.zip"
    bundle.write_bytes(b"x" * (1024 * 1024 + 1))
    sent = []

    class Bot:
        async def send_file(self, *args, **kwargs):
            sent.append((args, kwargs))

    class Event:
        sender_id = 222
        chat_id = -100123

        def __init__(self):
            self.responses = []

        async def respond(self, *args, **kwargs):
            self.responses.append((args, kwargs))

    monkeypatch.setattr(arachne, "bot", Bot())
    monkeypatch.setattr(arachne, "_telegram_admin_ids", lambda: {111})
    unauthorized = Event()
    assert asyncio.run(arachne._send_sanitized_diagnostics(unauthorized)) is False
    assert unauthorized.responses == [(('Not authorized.',), {})]

    monkeypatch.setattr(arachne, "_telegram_admin_ids", lambda: {222})
    monkeypatch.setattr(
        arachne.operations, "build_sanitized_diagnostic_bundle",
        lambda **_kwargs: bundle,
    )
    monkeypatch.setattr(
        arachne, "get_int",
        lambda name, default=0: 1024 * 1024
        if name == "TELEGRAM_DIAGNOSTIC_MAX_BYTES" else default,
    )
    oversized = Event()
    assert asyncio.run(arachne._send_sanitized_diagnostics(oversized)) is False
    assert not sent
    assert "size limit" in oversized.responses[0][0][0]


def test_telegram_diagnostic_command_rejects_invalid_hour_window_before_build(
        isolated_db, isolated_operations, monkeypatch):
    import arachne

    builds = []

    class Event:
        sender_id = 222
        chat_id = 222
        raw_text = "/diagnostics 169"

        def __init__(self):
            self.responses = []

        async def respond(self, *args, **kwargs):
            self.responses.append((args, kwargs))

    monkeypatch.setattr(arachne, "_telegram_admin_ids", lambda: {222})
    monkeypatch.setattr(
        arachne.operations, "build_sanitized_diagnostic_bundle",
        lambda **_kwargs: builds.append(True),
    )
    event = Event()
    asyncio.run(arachne.diagnostic_bundle_command(event))
    assert not builds
    assert event.responses == [(('Usage: /diagnostics [hours], where hours is 1 to 168.',), {})]


def test_telegram_menu_exposes_sanitized_diagnostics(isolated_db):
    import arachne

    buttons = [button for row in arachne.main_menu_buttons(123) for button in row]
    labels = {getattr(button, "text", ""): getattr(button, "data", b"") for button in buttons}
    assert labels["Sanitized diagnostics"] == b"ops_diagnostics"


def test_telegram_diagnostic_button_stays_available_when_main_db_is_broken(
        isolated_db, isolated_operations, monkeypatch):
    import arachne

    calls = []

    class Event:
        sender_id = 222
        chat_id = 222
        is_private = True
        data = b"ops_diagnostics"

        async def answer(self):
            return None

        async def respond(self, *_args, **_kwargs):
            return None

    async def send_bundle(_event, hours=24):
        calls.append(("bundle", hours))
        return True

    async def forbidden_data_check(_event):
        calls.append(("main_db", None))
        return False

    monkeypatch.setattr(arachne, "_telegram_admin_ids", lambda: {222})
    monkeypatch.setattr(arachne, "_send_sanitized_diagnostics", send_bundle)
    monkeypatch.setattr(arachne, "_require_telegram_data", forbidden_data_check)

    asyncio.run(arachne.callback_handler(Event()))
    assert calls == [("bundle", 24)]
