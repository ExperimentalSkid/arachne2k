"""Integrity-checked seven-day rolling backups and staged restore preparation."""
from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import zipfile
from zoneinfo import ZoneInfo

from paths import BACKUPS_DIR, DB_PATH, REPORTS_DIR


MADRID = ZoneInfo("Europe/Madrid")
RUNTIME_FILES = ("runtime_settings.json",)
BACKUP_PATTERNS = ("arachne-daily-*.zip", "arachne-daily-*.zip")


def _backup_paths() -> list[Path]:
    paths = {path for pattern in BACKUP_PATTERNS for path in BACKUPS_DIR.glob(pattern)}
    return sorted(paths, key=lambda path: path.stat().st_mtime, reverse=True)


def _integrity(path: Path) -> bool:
    db = None
    try:
        db = sqlite3.connect(str(path))
        return db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    except (OSError, sqlite3.Error):
        return False
    finally:
        if db is not None:
            db.close()


def create_daily_backup(*, keep_days: int = 7, force: bool = False) -> dict:
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(MADRID).date().isoformat()
    destination = BACKUPS_DIR / f"arachne-daily-{stamp}.zip"
    if destination.exists() and not force:
        return {"created": 0, "path": str(destination), "retained": len(_backup_paths())}
    if not DB_PATH.is_file():
        raise FileNotFoundError(f"Arachne database is missing: {DB_PATH}")
    with tempfile.TemporaryDirectory(dir=str(BACKUPS_DIR)) as temporary:
        temp = Path(temporary)
        snapshot = temp / "messages.db"
        source = sqlite3.connect(DB_PATH.resolve().as_uri() + "?mode=ro", uri=True, timeout=30)
        target = sqlite3.connect(str(snapshot))
        try:
            source.execute("PRAGMA busy_timeout=30000")
            source.backup(target)
        finally:
            target.close()
            source.close()
        if not _integrity(snapshot):
            raise sqlite3.DatabaseError("Backup snapshot failed integrity_check")
        manifest = {"created_at": datetime.now(MADRID).isoformat(), "timezone": "Europe/Madrid",
                    "product": "Arachne", "database": "messages.db",
                    "reports_exclude": ["previews", "screenshots"]}
        archive_temp = temp / destination.name
        with zipfile.ZipFile(archive_temp, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(snapshot, "messages.db")
            root = DB_PATH.parent
            for name in RUNTIME_FILES:
                path = root / name
                if path.is_file():
                    archive.write(path, name)
            if REPORTS_DIR.is_dir():
                for path in REPORTS_DIR.rglob("*"):
                    if (path.is_file() and not any(part.casefold() in {"previews", "screenshots"}
                                                   for part in path.relative_to(REPORTS_DIR).parts)):
                        archive.write(path, str(Path("reports") / path.relative_to(REPORTS_DIR)))
            archive.writestr("backup-manifest.json", json.dumps(manifest, indent=2))
        archive_temp.replace(destination)
    backups = _backup_paths()
    for old in backups[max(1, min(int(keep_days), 31)):]:
        old.unlink(missing_ok=True)
    return {"created": 1, "path": str(destination),
            "retained": len(_backup_paths())}


def list_backups() -> list[dict]:
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    return [{"name": path.name, "path": str(path), "size_mb": round(path.stat().st_size / 1048576, 2),
             "modified": datetime.fromtimestamp(path.stat().st_mtime, MADRID).isoformat()}
            for path in _backup_paths()]


def prepare_restore(backup_name: str) -> dict:
    """Validate and stage a restore; never replace the live database from Streamlit."""
    source = (BACKUPS_DIR / Path(backup_name).name).resolve()
    if source.parent != BACKUPS_DIR.resolve() or not source.is_file():
        raise ValueError("Unknown backup")
    staging = BACKUPS_DIR / "restore-ready"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    with zipfile.ZipFile(source) as archive:
        if "messages.db" not in archive.namelist():
            raise ValueError("Backup has no database snapshot")
        archive.extract("messages.db", staging)
        if "runtime_settings.json" in archive.namelist():
            archive.extract("runtime_settings.json", staging)
    database = staging / "messages.db"
    if not _integrity(database):
        shutil.rmtree(staging)
        raise sqlite3.DatabaseError("Staged database failed integrity_check")
    (staging / "RESTORE_INSTRUCTIONS.txt").write_text(
        "Stop the dashboard, bot, and all staged workers. Copy messages.db into the project root, "
        "then restart the Arachne services.\n",
        encoding="utf-8")
    return {"prepared": 1, "source": source.name, "staging_dir": str(staging),
            "database": str(database)}
