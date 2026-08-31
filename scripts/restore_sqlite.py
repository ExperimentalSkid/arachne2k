"""Validate and atomically restore one Arachne SQLite database.

Service lifecycle belongs to ``RUN_AFTER_UPLOAD.sh``.  This module deliberately
does not stop processes itself; it provides the filesystem/database transaction
used after the launcher has proved every SQLite user is stopped.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.backup_sqlite import SnapshotError, snapshot_database  # noqa: E402


REQUIRED_TABLES = {
    "main": frozenset({
        "onion_urls", "site_cards", "fetched_pages", "site_card_jobs",
        "worker_instances",
    }),
    "access": frozenset({
        "dashboard_access_state", "dashboard_access_codes",
        "dashboard_sessions",
    }),
}
SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


class RestoreError(RuntimeError):
    """A candidate, rollback, or atomic-publish invariant failed."""


def _sqlite_uri(path: Path) -> str:
    """Build a read-only SQLite URI for an absolute database path."""
    return path.resolve().as_uri() + "?mode=ro"


def inspect_database(path: Path, schema: str) -> dict:
    """Validate one standalone SQLite file without mutating it."""
    original = Path(path).expanduser()
    if original.is_symlink():
        raise RestoreError(f"SQLite candidate must not be a symlink: {original}")
    path = original.resolve()
    if schema not in REQUIRED_TABLES:
        raise ValueError(f"unknown schema kind: {schema}")
    if path.is_symlink() or not path.is_file():
        raise RestoreError(f"SQLite candidate is not a regular file: {path}")
    try:
        with closing(sqlite3.connect(_sqlite_uri(path), uri=True, timeout=30)) as db:
            db.execute("PRAGMA busy_timeout=30000")
            db.execute("PRAGMA query_only=ON")
            quick = db.execute("PRAGMA quick_check").fetchone()
            if not quick or quick[0] != "ok":
                raise RestoreError(f"SQLite quick_check failed: {quick!r}")
            integrity = db.execute("PRAGMA integrity_check").fetchone()
            if not integrity or integrity[0] != "ok":
                raise RestoreError(f"SQLite integrity_check failed: {integrity!r}")
            tables = {
                str(row[0])
                for row in db.execute(
                    "SELECT name FROM sqlite_schema WHERE type='table'"
                )
            }
            missing = sorted(REQUIRED_TABLES[schema] - tables)
            if missing:
                raise RestoreError(
                    f"SQLite backup is not an Arachne {schema} database; "
                    f"missing tables: {', '.join(missing)}"
                )
            user_version = int(db.execute("PRAGMA user_version").fetchone()[0])
            page_count = int(db.execute("PRAGMA page_count").fetchone()[0])
    except sqlite3.Error as exc:
        raise RestoreError(f"SQLite validation failed for {path}: {exc}") from exc
    return {
        "path": str(path),
        "schema": schema,
        "user_version": user_version,
        "page_count": page_count,
        "bytes": path.stat().st_size,
    }


def _temporary_path(parent: Path, name: str) -> Path:
    """Reserve a unique same-filesystem staging path without leaving a file."""
    descriptor, raw = tempfile.mkstemp(
        prefix=f".{name}.", suffix=".restore.tmp", dir=parent
    )
    os.close(descriptor)
    path = Path(raw)
    path.unlink()
    return path


def _atomic_replace(source: Path, target: Path) -> None:
    """Publish with a short bounded retry for released Windows SQLite handles."""
    for attempt in range(10):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == 9:
                raise
            time.sleep(0.05)


def _publish_snapshot(source: Path, target: Path, schema: str) -> None:
    """Copy through SQLite, validate, then atomically publish on one filesystem."""
    staged = _temporary_path(target.parent, target.name)
    try:
        snapshot_database(source, staged)
        inspect_database(staged, schema)
        os.chmod(staged, 0o600)
        _atomic_replace(staged, target)
        staged = None
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def _remove_stopped_writer_sidecars(target: Path) -> None:
    """Remove WAL, SHM, and journal sidecars after all writers are stopped."""
    for suffix in SIDECAR_SUFFIXES:
        sidecar = target.with_name(target.name + suffix)
        if sidecar.exists():
            sidecar.unlink()


def restore_database(
        candidate: Path,
        target: Path,
        *,
        schema: str,
        rollback_root: Path,
        create_rollback: bool = True,
        post_validate: Callable[[Path], None] | None = None,
) -> dict:
    """Restore a verified candidate while preserving a verified current snapshot."""
    raw_candidate = Path(candidate).expanduser()
    raw_target = Path(target).expanduser()
    raw_rollback_root = Path(rollback_root).expanduser()
    if raw_candidate.is_symlink() or raw_target.is_symlink():
        raise RestoreError("restore candidate and live target must not be symlinks")
    if raw_rollback_root.exists() and raw_rollback_root.is_symlink():
        raise RestoreError("rollback root must not be a symlink")
    candidate = raw_candidate.resolve()
    target = raw_target.resolve()
    rollback_root = raw_rollback_root.resolve()
    if candidate == target:
        raise RestoreError("restore candidate and live target must differ")
    inspect_database(candidate, schema)
    target.parent.mkdir(parents=True, exist_ok=True)
    rollback_path: Path | None = None

    if target.exists():
        if target.is_symlink() or not target.is_file():
            raise RestoreError(f"live SQLite target is not a regular file: {target}")
        if create_rollback:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
            rollback_dir = rollback_root / f"rollback_{stamp}_{os.getpid()}"
            rollback_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
            rollback_path = rollback_dir / target.name
            try:
                # Ubuntu production uses SQLite's online backup API. Windows
                # validation runs have no live services and use a closed-file
                # copy because sqlite3 can retain a read handle briefly enough
                # to prevent the subsequent atomic replace.
                if os.name == "nt":
                    shutil.copy2(target, rollback_path)
                else:
                    snapshot_database(target, rollback_path)
                inspect_database(rollback_path, schema)
            except Exception:
                rollback_path.unlink(missing_ok=True)
                try:
                    rollback_dir.rmdir()
                except OSError:
                    pass
                raise
    elif create_rollback:
        raise RestoreError(
            "live SQLite target is missing; initialize a fresh database instead "
            "of using restore"
        )

    published = False
    try:
        _publish_snapshot(candidate, target, schema)
        published = True
        _remove_stopped_writer_sidecars(target)
        restored = inspect_database(target, schema)
        if post_validate is not None:
            post_validate(target)
    except Exception as exc:
        if published and rollback_path is not None:
            try:
                _publish_snapshot(rollback_path, target, schema)
                _remove_stopped_writer_sidecars(target)
            except Exception as rollback_exc:
                raise RestoreError(
                    "restored database validation failed and automatic rollback "
                    f"also failed: restore={exc}; rollback={rollback_exc}"
                ) from rollback_exc
        raise

    return {
        "restored": True,
        "schema": schema,
        "target": str(target),
        "candidate": str(candidate),
        "rollback_path": str(rollback_path) if rollback_path else None,
        "bytes": restored["bytes"],
        "user_version": restored["user_version"],
    }


def main() -> None:
    """Validate CLI restore inputs, perform the restore, and print JSON output."""
    parser = argparse.ArgumentParser(
        description="Validate and atomically restore one Arachne SQLite backup"
    )
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--schema", choices=sorted(REQUIRED_TABLES), required=True)
    parser.add_argument("--rollback-root", type=Path, required=True)
    parser.add_argument(
        "--no-rollback-snapshot",
        action="store_true",
        help="Internal recovery mode; do not use for an ordinary restore",
    )
    args = parser.parse_args()
    try:
        result = restore_database(
            args.candidate,
            args.target,
            schema=args.schema,
            rollback_root=args.rollback_root,
            create_rollback=not args.no_rollback_snapshot,
        )
    except (OSError, sqlite3.Error, RestoreError, SnapshotError, ValueError) as exc:
        print(f"restore failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))


if __name__ == "__main__":
    main()
