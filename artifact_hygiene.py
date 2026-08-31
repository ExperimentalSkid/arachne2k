"""Workspace and runtime artifact hygiene helpers.

Operational backups may contain live databases. Source handoff releases must not.
This module keeps those two ideas deliberately separate.
"""
from __future__ import annotations

import shutil
import time
from pathlib import Path

from config_loader import get_bool, get_int
from paths import BASE_DIR, LOGS_DIR, PREVIEWS_DIR, REPORTS_DIR


PROTECTED_SUFFIXES = (".db", ".db-wal", ".db-shm", ".session", ".session-journal")
GENERATED_DIR_NAMES = {"reports", "logs", "previews", "screenshots", "backups"}
CACHE_DIR_NAMES = {"__pycache__", ".pytest_cache"}
VIRTUAL_ENV_DIR_NAMES = {".venv", "venv"}
DATABASE_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm", ".db-journal")
SESSION_SUFFIXES = (".session", ".session-journal")
ARCHIVE_SUFFIXES = (".zip", ".7z", ".rar", ".tar", ".gz")


def _finding(path: Path, root: Path, kind: str, severity: str) -> dict:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        relative = path.as_posix()
    return {"path": relative, "type": kind, "severity": severity}


def scan_workspace_hygiene(root: Path = BASE_DIR) -> dict:
    """Report files/folders that make the active workspace unsafe for source handoff."""
    root = root.resolve()
    findings: list[dict] = []
    skip_descendants: set[Path] = set()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if not relative.parts:
            continue
        if any(parent in skip_descendants for parent in path.parents):
            continue
        name = path.name.casefold()
        suffix = path.suffix.casefold()
        parts = {part.casefold() for part in relative.parts}
        if ".git" in parts:
            continue
        if path.is_dir():
            if name in VIRTUAL_ENV_DIR_NAMES:
                findings.append(_finding(path, root, f"virtualenv_dir:{name}", "high"))
                skip_descendants.add(path)
            elif name in GENERATED_DIR_NAMES:
                findings.append(_finding(path, root, f"generated_dir:{name}", "high"))
                skip_descendants.add(path)
            elif name in CACHE_DIR_NAMES:
                findings.append(_finding(path, root, f"cache_dir:{name}", "medium"))
                skip_descendants.add(path)
            continue
        if name == ".env":
            findings.append(_finding(path, root, "secret_env", "critical"))
        elif name in {"runtime_settings.json", "runtime_settings.json.tmp"}:
            findings.append(_finding(path, root, "runtime_config", "critical"))
        elif name.endswith(DATABASE_SUFFIXES) or suffix in {".db", ".sqlite", ".sqlite3"}:
            findings.append(_finding(path, root, "database", "critical"))
        elif name.endswith(SESSION_SUFFIXES):
            findings.append(_finding(path, root, "session", "critical"))
        elif name.endswith(ARCHIVE_SUFFIXES) or suffix in ARCHIVE_SUFFIXES:
            findings.append(_finding(path, root, "generated_archive", "medium"))
        elif name.endswith(".pyc"):
            findings.append(_finding(path, root, "python_cache", "medium"))
        elif name.endswith(".log") or name.startswith("log_") and name.endswith(".txt"):
            findings.append(_finding(path, root, "generated_log", "high"))
        elif name.startswith("informe_") and (name.endswith(".json") or name.endswith(".txt")):
            findings.append(_finding(path, root, "generated_report", "high"))
        elif ".bak" in name or name.endswith(".tmp"):
            findings.append(_finding(path, root, "backup_temp", "low"))
    severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    by_type: dict[str, int] = {}
    for item in findings:
        by_type[item["type"]] = by_type.get(item["type"], 0) + 1
    highest = max((item["severity"] for item in findings),
                  key=lambda value: severity_order[value], default="none")
    return {
        "pass": not findings,
        "total_findings": len(findings),
        "findings": findings,
        "by_type": by_type,
        "highest_severity": highest,
        "recommended_command": "python scripts/make_clean_release.py --audit-workspace",
    }


def clean_workspace_junk(root: Path = BASE_DIR, *, include_archives: bool = False,
                         dry_run: bool = True) -> dict:
    """Remove only harmless caches by default; never delete DB/session/.env files."""
    root = root.resolve()
    candidates: list[Path] = []
    for cache in CACHE_DIR_NAMES:
        path = root / cache
        if path.exists():
            candidates.append(path)
    candidates.extend(
        path for path in root.rglob("__pycache__")
        if not VIRTUAL_ENV_DIR_NAMES.intersection(part.casefold() for part in path.parts)
    )
    candidates.extend(
        path for path in root.rglob("*.pyc")
        if not VIRTUAL_ENV_DIR_NAMES.intersection(part.casefold() for part in path.parts)
    )
    if include_archives:
        candidates.extend(path for path in root.glob("*.zip") if path.is_file())
    removed = 0
    for path in sorted(set(candidates), key=lambda item: item.as_posix()):
        if dry_run:
            continue
        try:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            removed += 1
        except OSError:
            continue
    return {"dry_run": int(dry_run), "candidates": len(set(candidates)), "removed": removed}


def _generated_candidates(now: float) -> list[tuple[Path, str, int]]:
    rules = [
        (PREVIEWS_DIR, "preview", max(1, get_int("PREVIEW_RETENTION_DAYS", 7))),
        (BASE_DIR / "screenshots", "screenshot", max(1, get_int("SCREENSHOT_RETENTION_DAYS", 7))),
        (LOGS_DIR, "log", max(1, get_int("LOG_RETENTION_DAYS", 14))),
    ]
    if get_bool("PURGE_GENERATED_REPORTS", False):
        rules.append((REPORTS_DIR, "report", max(1, get_int("REPORT_RETENTION_DAYS", 30))))
    result: list[tuple[Path, str, int]] = []
    for root, kind, days in rules:
        try:
            files = list(root.rglob("*"))
        except OSError:
            continue
        for path in files:
            if (not path.is_file() or path.name in {".env", "runtime_settings.json", "messages.db"}
                    or path.name.casefold().endswith(PROTECTED_SUFFIXES)):
                continue
            if kind == "report" and PREVIEWS_DIR in path.parents:
                continue
            try:
                if now - path.stat().st_mtime >= days * 86400:
                    result.append((path, kind, days))
            except OSError:
                continue
    return result


def purge_runtime_artifacts(*, dry_run: bool = True, now: float | None = None) -> dict:
    """Delete only expired generated previews/logs and optionally reports."""
    current = time.time() if now is None else float(now)
    candidates = _generated_candidates(current)
    removed = 0
    if not dry_run:
        for path, _, _ in candidates:
            try:
                path.unlink()
                removed += 1
            except OSError:
                continue
    counts: dict[str, int] = {}
    for _, kind, _ in candidates:
        counts[kind] = counts.get(kind, 0) + 1
    return {
        "dry_run": int(dry_run), "candidates": len(candidates), "removed": removed,
        "by_type": counts,
    }
