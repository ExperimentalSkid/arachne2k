"""Create safe handoff receipts and source manifests for direct-folder deploys.

The receipt is intentionally redacted: it proves configuration presence and
workspace hygiene without printing tokens, session data, onion results, or DB
content.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.make_clean_release import (  # noqa: E402
    MANIFEST_NAME,
    build_source_manifest,
    release_files,
    write_source_manifest,
)


RECEIPT_PATH = ROOT / "HANDOFF_RECEIPT.txt"
MANIFEST_PATH = ROOT / MANIFEST_NAME
RECEIPT_HISTORY_DIR = ROOT / "handoff_receipts"

FORBIDDEN_DIRS = {
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache",
    "runtime", "logs", "reports", "backups", "previews", "screenshots",
    "node_modules",
}
FORBIDDEN_SUFFIXES = (
    ".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm", ".db-journal",
    ".session", ".session-journal", ".pyc", ".pyo", ".log", ".zip", ".7z",
    ".bak", ".tmp",
)
REDACTED_ENV_KEYS = {
    "TELEGRAM_API_ID", "TELEGRAM_API_HASH", "TELEGRAM_BOT_TOKEN",
    "ADMIN_CHAT_ID", "TELEGRAM_ADMIN_IDS", "DASHBOARD_LOCK_ENABLED",
    "DASHBOARD_ACCESS_LOCK_ENABLED",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _env_map() -> dict[str, str]:
    env_path = ROOT / ".env"
    result: dict[str, str] = {}
    if not env_path.exists():
        return result
    for line in env_path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def _is_numeric(value: str | None) -> bool:
    return bool(str(value or "").strip().lstrip("-").isdigit())


def _runtime_findings() -> list[dict]:
    findings: list[dict] = []
    skip_descendants: set[Path] = set()
    for path in sorted(ROOT.rglob("*"), key=lambda item: item.as_posix()):
        try:
            rel = path.relative_to(ROOT)
        except ValueError:
            continue
        if not rel.parts:
            continue
        if any(parent in skip_descendants for parent in path.parents):
            continue
        parts = {part.casefold() for part in rel.parts}
        if ".git" in parts:
            continue
        rel_text = rel.as_posix()
        name = path.name.casefold()
        if path.is_dir():
            if name in FORBIDDEN_DIRS:
                findings.append({"path": rel_text, "type": f"runtime_dir:{name}"})
                if name in {".venv", "venv"}:
                    skip_descendants.add(path)
            continue
        if path.name == ".env":
            continue
        if (name.endswith(FORBIDDEN_SUFFIXES) or ".bak" in name
                or (name.startswith("log_") and name.endswith(".txt"))
                or (name.startswith("informe_") and name.endswith((".json", ".txt")))):
            findings.append({"path": rel_text, "type": "runtime_file"})
    return findings


def _source_files() -> list[Path]:
    """Compatibility wrapper around the authoritative release selector."""
    return release_files(ROOT)


def build_manifest() -> dict:
    return build_source_manifest(ROOT)


def write_manifest() -> dict:
    return write_source_manifest(ROOT, MANIFEST_PATH)


def build_receipt(*, write_manifest_file: bool = True, allow_runtime: bool = False) -> tuple[str, dict]:
    env = _env_map()
    findings = _runtime_findings()
    manifest = write_manifest() if write_manifest_file else build_manifest()
    required_files = [
        "RUN_AFTER_UPLOAD.sh", "dashboard.py", "arachne.py", "storage.py",
        "fetch_worker.py", "verify_worker.py", "card_worker.py", "preview_worker.py",
    ]
    required_status = {name: (ROOT / name).exists() for name in required_files}
    env_status = {
        key: {
            "present": bool(env.get(key)),
            "length": len(env.get(key, "")),
            "numeric": _is_numeric(env.get(key)),
        }
        for key in REDACTED_ENV_KEYS
    }
    pass_state = (
        (allow_runtime or not findings)
        and all(required_status.values())
        and env_status["TELEGRAM_API_ID"]["present"]
        and env_status["TELEGRAM_API_HASH"]["present"]
        and env_status["TELEGRAM_BOT_TOKEN"]["present"]
        and env_status["ADMIN_CHAT_ID"]["numeric"]
        and (ROOT / "RUN_AFTER_UPLOAD.sh").exists()
    )
    generated_at = _utc_now()
    lines = [
        "ARACHNE HANDOFF RECEIPT",
        f"Generated: {generated_at}",
        "Project: Arachne",
        f"Python: {platform.python_version()}",
        f"Platform: {platform.platform()}",
        "",
        "Direct-folder deployment readiness",
        f"Result: {'PASS' if pass_state else 'REVIEW NEEDED'}",
        f"Runtime mode: {'server/runtime allowed' if allow_runtime else 'strict direct-folder'}",
        f"Runtime junk excluding intended .env: {'none' if not findings else len(findings)}",
        f"Launcher present: {required_status['RUN_AFTER_UPLOAD.sh']}",
        f"Source manifest: {MANIFEST_PATH.name}",
        f"Source files: {manifest['file_count']}",
        f"Source tree sha256: {manifest['tree_sha256']}",
        "",
        "Required files",
    ]
    lines.extend(f"- {name}: {'yes' if ok else 'MISSING'}" for name, ok in required_status.items())
    lines.extend(["", "Configuration presence (redacted)"])
    for key in sorted(env_status):
        item = env_status[key]
        extra = " numeric" if item["numeric"] else ""
        lines.append(f"- {key}: {'present' if item['present'] else 'MISSING'} len={item['length']}{extra}")
    lines.extend([
        "",
        "Server commands",
        "- Start/repair bot: bash RUN_AFTER_UPLOAD.sh bot-start",
        "- Normal menu:      bash RUN_AFTER_UPLOAD.sh",
        "- Handoff check:    bash RUN_AFTER_UPLOAD.sh handoff-check",
        "- Verify handoff:   bash RUN_AFTER_UPLOAD.sh verify-handoff",
    ])
    if findings:
        lines.extend(["", "Runtime findings"])
        lines.extend(f"- {item['path']} ({item['type']})" for item in findings[:40])
        if len(findings) > 40:
            lines.append(f"- ... {len(findings) - 40} more")
    receipt = "\n".join(lines) + "\n"
    return receipt, {"pass": pass_state, "findings": findings, "manifest": manifest,
                     "env_status": env_status, "generated_at": generated_at}


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a safe Arachne handoff receipt.")
    parser.add_argument("--manifest", action="store_true", help="Write SOURCE_MANIFEST.json only.")
    parser.add_argument("--check", action="store_true", help="Exit non-zero when direct-folder handoff is not clean.")
    parser.add_argument("--no-write", action="store_true", help="Print receipt without writing HANDOFF_RECEIPT.txt.")
    parser.add_argument(
        "--allow-runtime",
        action="store_true",
        help="Allow server runtime files such as DBs/backups while still checking required source/config presence.",
    )
    args = parser.parse_args()

    if args.manifest:
        manifest = write_manifest()
        print(json.dumps({"manifest": str(MANIFEST_PATH), "file_count": manifest["file_count"],
                          "tree_sha256": manifest["tree_sha256"]}, sort_keys=True))
        return

    receipt, result = build_receipt(write_manifest_file=not args.no_write, allow_runtime=args.allow_runtime)
    print(receipt, end="")
    if not args.no_write:
        RECEIPT_PATH.write_text(receipt, encoding="utf-8")
        RECEIPT_HISTORY_DIR.mkdir(exist_ok=True)
        stamp = result["generated_at"].replace("-", "").replace(":", "").replace("T", "_").replace("Z", "")
        state = "PASS" if result["pass"] else "REVIEW"
        history_path = RECEIPT_HISTORY_DIR / f"{stamp}_{state}.txt"
        history_path.write_text(receipt, encoding="utf-8")
        print(f"receipt={RECEIPT_PATH}")
        print(f"receipt_history={history_path}")
    if args.check and not result["pass"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
