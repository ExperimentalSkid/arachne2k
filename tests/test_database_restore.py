import hashlib
import os
import sqlite3
from pathlib import Path

import pytest

from scripts.backup_retention import prune_backup_artifacts
from scripts.restore_sqlite import RestoreError, inspect_database, restore_database


MAIN_TABLES = (
    "onion_urls", "site_cards", "fetched_pages", "site_card_jobs",
    "worker_instances",
)
ACCESS_TABLES = (
    "dashboard_access_state", "dashboard_access_codes", "dashboard_sessions",
)


def _database(path: Path, *, schema: str, marker: str) -> Path:
    tables = MAIN_TABLES if schema == "main" else ACCESS_TABLES
    db = sqlite3.connect(path)
    try:
        for table in tables:
            db.execute(f'CREATE TABLE "{table}" (id INTEGER PRIMARY KEY)')
        db.execute("CREATE TABLE restore_probe(value TEXT NOT NULL)")
        db.execute("INSERT INTO restore_probe(value) VALUES(?)", (marker,))
        db.commit()
    finally:
        db.close()
    return path


def _marker(path: Path) -> str:
    db = sqlite3.connect(path)
    try:
        return str(db.execute("SELECT value FROM restore_probe").fetchone()[0])
    finally:
        db.close()


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_restore_validates_candidate_preserves_current_and_publishes_atomically(tmp_path):
    live = _database(tmp_path / "messages.db", schema="main", marker="current")
    candidate = _database(tmp_path / "backup.db", schema="main", marker="backup")
    candidate_digest = _digest(candidate)

    result = restore_database(
        candidate, live, schema="main", rollback_root=tmp_path / "backups"
    )

    rollback = Path(result["rollback_path"])
    assert result["restored"] is True
    assert _marker(live) == "backup"
    assert rollback.is_file() and _marker(rollback) == "current"
    assert _digest(candidate) == candidate_digest
    assert inspect_database(live, "main")["schema"] == "main"


@pytest.mark.parametrize("candidate_kind", ["corrupt", "wrong_schema"])
def test_restore_rejects_bad_candidate_without_touching_live_database(
        tmp_path, candidate_kind):
    live = _database(tmp_path / "messages.db", schema="main", marker="current")
    original = _digest(live)
    candidate = tmp_path / "candidate.db"
    if candidate_kind == "corrupt":
        candidate.write_bytes(b"not sqlite")
    else:
        _database(candidate, schema="access", marker="wrong")

    with pytest.raises(RestoreError):
        restore_database(
            candidate, live, schema="main", rollback_root=tmp_path / "backups"
        )

    assert _digest(live) == original
    assert _marker(live) == "current"
    assert not (tmp_path / "backups").exists()


def test_restore_recovers_preserved_database_if_post_publish_validation_fails(tmp_path):
    live = _database(tmp_path / "messages.db", schema="main", marker="current")
    candidate = _database(tmp_path / "backup.db", schema="main", marker="backup")

    def fail_restored_target(path):
        assert _marker(path) == "backup"
        raise RestoreError("simulated post-publish application validation")

    with pytest.raises(RestoreError, match="simulated post-publish"):
        restore_database(
            candidate,
            live,
            schema="main",
            rollback_root=tmp_path / "backups",
            post_validate=fail_restored_target,
        )

    assert _marker(live) == "current"
    rollbacks = list((tmp_path / "backups").glob("rollback_*/*.db"))
    assert len(rollbacks) == 1 and _marker(rollbacks[0]) == "current"


def test_atomic_publish_failure_leaves_live_database_unchanged(tmp_path, monkeypatch):
    import scripts.restore_sqlite as module

    live = _database(tmp_path / "messages.db", schema="main", marker="current")
    candidate = _database(tmp_path / "backup.db", schema="main", marker="backup")
    original = _digest(live)

    def fail_replace(_source, _target):
        raise OSError("simulated atomic replace failure")

    monkeypatch.setattr(module, "_atomic_replace", fail_replace)
    with pytest.raises(OSError, match="simulated atomic"):
        module.restore_database(
            candidate, live, schema="main", rollback_root=tmp_path / "backups"
        )

    assert _digest(live) == original
    assert _marker(live) == "current"
    assert not list(tmp_path.glob(".*.restore.tmp"))


def test_sidecar_cleanup_failure_rolls_back_published_database(tmp_path, monkeypatch):
    import scripts.restore_sqlite as module

    live = _database(tmp_path / "messages.db", schema="main", marker="current")
    candidate = _database(tmp_path / "backup.db", schema="main", marker="backup")
    real_cleanup = module._remove_stopped_writer_sidecars
    calls = 0

    def fail_once(target):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("simulated sidecar cleanup failure")
        real_cleanup(target)

    monkeypatch.setattr(module, "_remove_stopped_writer_sidecars", fail_once)
    with pytest.raises(OSError, match="simulated sidecar"):
        module.restore_database(
            candidate, live, schema="main", rollback_root=tmp_path / "backups"
        )

    assert calls == 2
    assert _marker(live) == "current"


def test_restore_requires_existing_live_database_for_rollback_snapshot(tmp_path):
    candidate = _database(tmp_path / "backup.db", schema="main", marker="backup")

    with pytest.raises(RestoreError, match="initialize a fresh database"):
        restore_database(
            candidate,
            tmp_path / "missing.db",
            schema="main",
            rollback_root=tmp_path / "backups",
        )


def test_restore_keeps_access_database_schema_separate(tmp_path):
    live = _database(
        tmp_path / "dashboard_access.db", schema="access", marker="current"
    )
    candidate = _database(
        tmp_path / "access-backup.db", schema="access", marker="backup"
    )

    result = restore_database(
        candidate, live, schema="access", rollback_root=tmp_path / "backups"
    )

    assert result["schema"] == "access"
    assert _marker(live) == "backup"
    assert _marker(Path(result["rollback_path"])) == "current"


def test_backup_retention_is_bounded_and_never_removes_unknown_directories(tmp_path):
    root = tmp_path / "backups"
    root.mkdir()
    for index in range(6):
        path = root / f"rollback_2026010{index}"
        path.mkdir()
        (path / "messages.db").write_text(str(index), encoding="utf-8")
        os.utime(path, (index + 1, index + 1))
    unknown = root / "operator_archive"
    unknown.mkdir()

    preview = prune_backup_artifacts(
        root, kind="rollback", keeps={"rollback": 2}, dry_run=True
    )
    assert len(preview["candidates"]) == 4
    assert len(list(root.glob("rollback_*"))) == 6

    applied = prune_backup_artifacts(
        root, kind="rollback", keeps={"rollback": 2}, dry_run=False
    )
    assert len(applied["removed"]) == 4
    assert [path.name for path in sorted(root.glob("rollback_*"))] == [
        "rollback_20260104", "rollback_20260105",
    ]
    assert unknown.is_dir()
