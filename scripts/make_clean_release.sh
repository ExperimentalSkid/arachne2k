#!/usr/bin/env bash
set -euo pipefail

# Source-only allowlist. The Python builder excludes at least:
# .env *.session *.session-journal messages.db *.db *.db-wal *.db-shm
# backups/ reports/ logs/ previews/ screenshots/ __pycache__/ .pytest_cache/
# *.pyc *.bak *.bak* *.zip *.7z *.log log_*.txt informe_*.json informe_*.txt
# arachne.db.empty*

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${1:-$ROOT/../arachne_release.zip}"
PYTHON_BIN="${PYTHON:-}"

if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then PYTHON_BIN=python3; else PYTHON_BIN=python; fi
fi

exec "$PYTHON_BIN" "$ROOT/scripts/make_clean_release.py" "$OUTPUT"
