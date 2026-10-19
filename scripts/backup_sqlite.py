"""Create safe SQLite snapshots with retention.

Uses sqlite3.Connection.backup(), not a raw file copy, so it is safe while the
application database is open. By default it backs up the main Arachne DB.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import storage
from paths import BASE_DIR


MIN_FREE_RESERVE_BYTES = 64 * 1024 * 1024


class SnapshotError(RuntimeError):
    """A source- or destination-specific SQLite snapshot failure."""


def _required_snapshot_bytes(db_path: Path) -> int:
    """Estimate the peak target space without inspecting database content."""
    required = db_path.stat().st_size
    wal_path = db_path.with_name(db_path.name + "-wal")
    if wal_path.is_file():
        required += wal_path.stat().st_size
    return required + MIN_FREE_RESERVE_BYTES


def _fsync_path(path: Path) -> None:
    """Flush the completed snapshot before its atomic publish."""
    # Windows requires a writable descriptor for fsync; Linux accepts this too.
    with path.open("rb+") as handle:
        handle.flush()
        os.fsync(handle.fileno())


def snapshot_database(db_path: Path, target: Path) -> Path:
    """Create, verify, and atomically publish one consistent SQLite snapshot."""
    db_path = db_path.expanduser().resolve()
    target = target.expanduser().resolve()
    if not db_path.is_file():
        raise FileNotFoundError(db_path)
    if db_path == target:
        raise ValueError("SQLite snapshot target must differ from its source")
    target.parent.mkdir(parents=True, exist_ok=True)
    free_bytes = shutil.disk_usage(target.parent).free
    required_bytes = _required_snapshot_bytes(db_path)
    if free_bytes < required_bytes:
        raise SnapshotError(
            "snapshot destination has insufficient free space: "
            f"required={required_bytes} free={free_bytes} directory={target.parent}"
        )

    source_uri = db_path.as_uri() + "?mode=ro"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
                prefix=f".{target.name}.", suffix=".snapshot.tmp",
                dir=target.parent, delete=False) as handle:
            temporary = Path(handle.name)
        with closing(sqlite3.connect(source_uri, uri=True, timeout=30)) as source:
            source.execute("PRAGMA busy_timeout=30000")
            source.execute("PRAGMA query_only=ON")
            try:
                source.execute("SELECT COUNT(*) FROM sqlite_schema").fetchone()
            except sqlite3.Error as exc:
                raise SnapshotError(
                    f"snapshot source is not readable as SQLite: {db_path}: {exc}"
                ) from exc
            try:
                with closing(sqlite3.connect(str(temporary), timeout=30)) as dest:
                    dest.execute("PRAGMA busy_timeout=30000")
                    # The destination is a private temporary file. Journaling is
                    # unnecessary because it is published only after verification.
                    dest.execute("PRAGMA journal_mode=OFF")
                    dest.execute("PRAGMA synchronous=OFF")
                    source.backup(dest, pages=1024, sleep=0.05)
                    result = dest.execute("PRAGMA quick_check").fetchone()
                    if not result or result[0] != "ok":
                        raise sqlite3.DatabaseError(
                            f"backup quick_check failed: {result!r}")
                    dest.commit()
            except sqlite3.Error as exc:
                raise SnapshotError(
                    f"SQLite snapshot write failed: source={db_path} "
                    f"destination={target}: {exc}"
                ) from exc
        _fsync_path(temporary)
        os.replace(temporary, target)
        temporary = None
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    return target


def backup_database(db_path: Path, backup_dir: Path, *, keep: int = 14) -> Path:
    """Create a timestamped SQLite snapshot and prune older matching snapshots."""
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    descriptor, reserved = tempfile.mkstemp(
        prefix=f"{db_path.stem}_{timestamp}_", suffix=".db", dir=backup_dir)
    os.close(descriptor)
    target = Path(reserved)
    try:
        snapshot_database(db_path, target)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    backups = sorted(backup_dir.glob(f"{db_path.stem}_*.db"), key=lambda path: path.stat().st_mtime, reverse=True)
    for old in backups[max(1, int(keep)):]:
        old.unlink(missing_ok=True)
    return target


def main() -> None:
    """Create one requested SQLite snapshot and surface bounded CLI failures."""
    parser = argparse.ArgumentParser(description="Create a safe SQLite backup snapshot")
    parser.add_argument("--db", default=str(storage.DB_PATH), help="SQLite database path to back up")
    parser.add_argument("--backup-dir", default=str(BASE_DIR / "backups"), help="Directory for backup files")
    parser.add_argument("--output", help="Exact output path (disables timestamp/retention naming)")
    parser.add_argument("--keep", type=int, default=14, help="Number of backups to retain")
    args = parser.parse_args()
    try:
        target = (snapshot_database(Path(args.db), Path(args.output)) if args.output
                  else backup_database(Path(args.db), Path(args.backup_dir), keep=args.keep))
    except (FileNotFoundError, OSError, sqlite3.Error, SnapshotError, ValueError) as exc:
        print(f"backup failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    print(f"backup={target}")


if __name__ == "__main__":
    main()
