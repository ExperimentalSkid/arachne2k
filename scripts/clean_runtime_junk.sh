#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Deliberately preserve .env, databases, sessions, reports/, and backups/.
find . -type d \( -name __pycache__ -o -name .pytest_cache \) \
  -not -path './backups/*' -not -path './reports/*' -prune -exec rm -rf -- {} +
find . -type f \( -name '*.pyc' -o -name '*.bak' -o -name '*.bak*' -o -name '*.log' \) \
  -not -path './backups/*' -not -path './reports/*' -delete
find . -maxdepth 1 -type f \( -name 'informe_*.json' -o -name 'informe_*.txt' \) -delete
find . -maxdepth 2 -type f \( -name '*.zip' -o -name '*.7z' \) -delete

echo "Runtime junk cleaned. Databases, .env, sessions, reports, and backups were preserved."
