#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Arachne server control script.
#
# Normal upload/update:
#   cd /root/arachne
#   bash RUN_AFTER_UPLOAD.sh
#
# Control menu:
#   bash RUN_AFTER_UPLOAD.sh menu
#
# Useful direct commands:
#   bash RUN_AFTER_UPLOAD.sh bootstrap
#   bash RUN_AFTER_UPLOAD.sh doctor
#   bash RUN_AFTER_UPLOAD.sh install
#   bash RUN_AFTER_UPLOAD.sh quick
#   bash RUN_AFTER_UPLOAD.sh configure-env
#   bash RUN_AFTER_UPLOAD.sh backup-db
#   bash RUN_AFTER_UPLOAD.sh wipe-db
#   bash RUN_AFTER_UPLOAD.sh deploy-onion
#   bash RUN_AFTER_UPLOAD.sh dashboard-code
#   bash RUN_AFTER_UPLOAD.sh logs
#   bash RUN_AFTER_UPLOAD.sh pause
#   bash RUN_AFTER_UPLOAD.sh resume
#   bash RUN_AFTER_UPLOAD.sh validate
#   bash RUN_AFTER_UPLOAD.sh restart
#   bash RUN_AFTER_UPLOAD.sh status

PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
cd "$PROJECT_DIR"

SERVICE_NAMES=(
  arachne-dashboard.service
  arachne-fetch-worker.service
  arachne-verify-worker.service
  arachne-card-worker.service
  arachne-deep-discovery-worker.service
  arachne-preview-worker.service
  arachne-bot.service
)

APP_SERVICE_NAMES=(
  arachne-dashboard.service
  arachne-fetch-worker.service
  arachne-verify-worker.service
  arachne-card-worker.service
  arachne-deep-discovery-worker.service
  arachne-preview-worker.service
)

WORKER_SERVICE_NAMES=(
  arachne-fetch-worker.service
  arachne-verify-worker.service
  arachne-card-worker.service
  arachne-deep-discovery-worker.service
  arachne-preview-worker.service
)

BOT_SERVICE_NAME=arachne-bot.service
MAINTENANCE_SERVICE_NAME=arachne-maintenance.service
MAINTENANCE_TIMER_NAME=arachne-maintenance.timer

DB_FILES=(messages.db arachne.db)
PREVIOUS_DB_FILE="${ARACHNE_PREVIOUS_DB_FILE:-}"
if [[ -n "$PREVIOUS_DB_FILE" ]]; then
  if [[ ! "$PREVIOUS_DB_FILE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.db$ ]]; then
    printf 'Invalid ARACHNE_PREVIOUS_DB_FILE: use a database basename ending in .db\n' >&2
    exit 2
  fi
  DB_FILES+=("$PREVIOUS_DB_FILE")
fi
AUTH_DB_FILES=(runtime/dashboard_access.db)
SOURCE_PREFLIGHT_COMPLETE=0

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
  BLUE=$'\033[1;34m'; GREEN=$'\033[1;32m'; YELLOW=$'\033[1;33m'
  RED=$'\033[1;31m'; CYAN=$'\033[1;36m'; GRAY=$'\033[90m'
else
  BOLD=""; DIM=""; RESET=""; BLUE=""; GREEN=""; YELLOW=""; RED=""; CYAN=""; GRAY=""
fi

# Print a visually distinct control-step heading.
log() { printf '\n%s==>%s %s\n' "$BLUE" "$RESET" "$*"; }
# Print a successful operation message.
ok() { printf '%sOK:%s %s\n' "$GREEN" "$RESET" "$*"; }
# Print a non-fatal warning to stderr.
warn() { printf '\n%sWARN:%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
# Print a fatal error and terminate the current command.
die() { printf '\n%sERROR:%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }
# Print a menu separator using the active color mode.
hr() { printf '%s\n' "${GRAY}------------------------------------------------------------${RESET}"; }
# Pause an interactive menu until the operator presses Enter.
pause_screen() { read -r -p "Press Enter to continue..." _; }

# Run one menu command without terminating the parent menu on failure.
run_menu_action() {
  local label="$1"
  shift
  if ! ("$@"); then
    warn "$label did not complete. The menu is still available; review the error above."
  fi
}

# Acquire the singleton lock that prevents overlapping control operations.
acquire_control_lock() {
  command -v flock >/dev/null 2>&1 || die "flock is required (normally provided by util-linux)."
  local lock_dir="/run/lock"
  [[ -d "$lock_dir" && -w "$lock_dir" ]] || lock_dir="${TMPDIR:-/tmp}"
  exec 9>"$lock_dir/arachne-server-control.lock"
  flock -n 9 || die "Another Arachne server-control process is already running. Wait for it to finish."
}

# Require root privileges before reading or changing systemd state.
require_root_for_systemd() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Run as root on the server so systemd services can be installed/restarted."
  fi
}

# Verify that the current directory contains a complete deployable source tree.
require_project() {
  [[ -f "requirements.txt" ]] || die "requirements.txt missing; are you in /root/arachne?"
  [[ -f "requirements-lock.txt" ]] || die "requirements-lock.txt missing; source release is incomplete."
  [[ -f "dashboard.py" ]] || die "dashboard.py missing; upload/extract looks incomplete."
  [[ -f "arachne.py" ]] || die "arachne.py missing; Telegram bot entrypoint is missing."
}

# Return the project virtual-environment Python path.
python_bin() {
  printf '%s\n' ".venv/bin/python"
}

# Select the supported system Python, preferring its versioned executable.
system_python_bin() {
  if command -v python3.12 >/dev/null 2>&1; then
    command -v python3.12
  elif command -v python3 >/dev/null 2>&1; then
    command -v python3
  else
    return 1
  fi
}

# Return success only when the selected interpreter is exactly Python 3.12.
python_312_ready() {
  local py="${1:-}"
  [[ -n "$py" && -x "$py" ]] || return 1
  "$py" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)'
}

# Require the production Python version before creating or replacing a virtualenv.
require_python_312() {
  local py actual
  py="$(system_python_bin 2>/dev/null || true)"
  if [[ -z "$py" ]]; then
    die "Python 3.12 is required. Install python3.12 and python3.12-venv, then rerun."
  fi
  if ! python_312_ready "$py"; then
    actual="$($py -c 'import sys; print(".".join(map(str, sys.version_info[:3])))' 2>/dev/null || printf 'unknown')"
    die "Python 3.12 is required; selected $py reports $actual. Install python3.12 and python3.12-venv, then rerun."
  fi
  printf '%s\n' "$py"
}

# Select a Python runtime suitable for standard-library-only safety helpers.
stdlib_python_bin() {
  if [[ -x ".venv/bin/python" ]]; then
    printf '%s\n' ".venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    command -v python3
  else
    die "python3 is required."
  fi
}

# Create one verified SQLite snapshot through the canonical Python helper.
sqlite_snapshot() {
  local source="$1" target="$2" py
  py="$(stdlib_python_bin)"
  "$py" "$PROJECT_DIR/scripts/backup_sqlite.py" --db "$source" --output "$target"
}

# Apply bounded retention to one recognized backup artifact category.
prune_backup_artifacts() {
  local kind="$1" py
  py="$(stdlib_python_bin)"
  if ! "$py" "$PROJECT_DIR/scripts/backup_retention.py" \
    --root "$PROJECT_DIR/backups" \
    --kind "$kind" \
    --keep-manual "${ARACHNE_KEEP_MANUAL_BACKUPS:-7}" \
    --keep-restore "${ARACHNE_KEEP_UPDATE_RESTORE_POINTS:-3}" \
    --keep-rollback "${ARACHNE_KEEP_DATABASE_ROLLBACKS:-5}" \
    --keep-config "${ARACHNE_KEEP_CONFIG_BACKUPS:-5}" \
    --keep-stale-source "${ARACHNE_KEEP_STALE_SOURCE_BACKUPS:-3}" \
    --apply; then
    warn "Backup retention for '$kind' could not complete. New verified artifacts were preserved; review disk usage."
  fi
  return 0
}

# Confirm that a target filesystem has enough room for the requested snapshots.
backup_space_preflight() {
  local target_dir="$1" py
  shift
  py="$(stdlib_python_bin)"
  "$py" - "$target_dir" "$@" <<'PY'
from pathlib import Path
import shutil
import sys

target = Path(sys.argv[1]).resolve()
sources = [Path(value) for value in sys.argv[2:] if Path(value).is_file()]
source_bytes = sum(path.stat().st_size for path in sources)
# SQLite backup needs the full destination plus bounded safety headroom.
required = source_bytes + max(64 * 1024 * 1024, source_bytes // 5)
free = shutil.disk_usage(target).free
print(f"backup preflight: source={source_bytes} required={required} free={free}")
if free < required:
    raise SystemExit("insufficient free disk space for verified SQLite snapshot")
PY
}

# Wait until a service has a live main PID for three consecutive checks.
wait_service_stable() {
  local service="$1" consecutive=0 state pid
  for _ in $(seq 1 12); do
    state="$(systemctl is-active "$service" 2>/dev/null || true)"
    pid="$(systemctl show -p MainPID --value "$service" 2>/dev/null || true)"
    if [[ "$state" == "active" && "${pid:-0}" =~ ^[0-9]+$ && "${pid:-0}" -gt 0 ]]; then
      consecutive=$((consecutive + 1))
      [[ "$consecutive" -ge 3 ]] && return 0
    else
      consecutive=0
    fi
    sleep 1
  done
  return 1
}

# Wait for a systemd timer to reach the active state.
wait_timer_active() {
  local timer="$1"
  for _ in $(seq 1 10); do
    systemctl is-active --quiet "$timer" && return 0
    sleep 1
  done
  return 1
}

# Restore the exact service and timer state captured before maintenance.
restore_active_service_snapshot() {
  local timer_was_active="$1"
  shift
  local services=("$@") service
  if [[ "${SKIP_RESTART:-0}" == "1" ]]; then
    warn "Service-state restoration skipped because SKIP_RESTART=1"
    return 0
  fi
  if (( ${#services[@]} )); then
    systemctl restart "${services[@]}"
    for service in "${services[@]}"; do
      wait_service_stable "$service" || {
        systemctl --no-pager --full status "$service" || true
        return 1
      }
    done
  fi
  if [[ "$timer_was_active" == "1" ]]; then
    systemctl start "$MAINTENANCE_TIMER_NAME"
    wait_timer_active "$MAINTENANCE_TIMER_NAME" || return 1
  fi
}

# Stop installed services and fail if any requested SQLite user remains active.
stop_services_checked() {
  local services=("$@") installed=() failed=0 service load_state
  for service in "${services[@]}"; do
    load_state="$(systemctl show -p LoadState --value "$service" 2>/dev/null || true)"
    [[ "$load_state" == "loaded" ]] && installed+=("$service")
  done
  [[ "${#installed[@]}" -eq 0 ]] || systemctl stop "${installed[@]}"
  for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
      warn "$service did not stop; refusing a destructive database action."
      failed=1
    fi
  done
  [[ "$failed" -eq 0 ]]
}

# Return a compact systemd load/active state for one service.
service_state() {
  local service="$1"
  if ! command -v systemctl >/dev/null 2>&1; then
    printf 'unknown'
    return 0
  fi
  local state load_state
  load_state="$(systemctl show -p LoadState --value "$service" 2>/dev/null || true)"
  if [[ "$load_state" != "loaded" ]]; then
    printf 'missing'
    return 0
  fi
  state="$(systemctl is-active "$service" 2>/dev/null || true)"
  printf '%s' "${state:-unknown}"
}

# Render a color-aware status badge for a service state.
state_badge() {
  case "$1" in
    active) printf '%sOK%s' "$GREEN" "$RESET" ;;
    activating) printf '%sSTARTING%s' "$YELLOW" "$RESET" ;;
    inactive|failed) printf '%s%s%s' "$RED" "$1" "$RESET" ;;
    missing) printf '%sMISSING%s' "$YELLOW" "$RESET" ;;
    *) printf '%s%s%s' "$YELLOW" "${1:-unknown}" "$RESET" ;;
  esac
}

# Report whether a named environment key has a non-empty private value.
env_value_present() {
  local key="$1"
  [[ -f ".env" ]] || { printf 'missing'; return 0; }
  if grep -Eq "^[[:space:]]*${key}[[:space:]]*=[[:space:]]*.+" .env; then
    printf 'set'
  else
    printf 'missing'
  fi
}

# Read the deployed dashboard onion hostname without exposing other Tor state.
onion_hostname() {
  local path="/var/lib/tor/arachne-dashboard/hostname"
  if [[ -s "$path" ]]; then
    tr -d '[:space:]' < "$path"
  else
    printf ''
  fi
}

# Print a compact list of recognized database files and sizes.
db_info_line() {
  local found=0
  for db in "${DB_FILES[@]}"; do
    if [[ -f "$db" ]]; then
      found=1
      printf '%s (%s) ' "$db" "$(du -h "$db" 2>/dev/null | awk '{print $1}')"
    fi
  done
  [[ "$found" -eq 1 ]] || printf 'none yet'
}

# Print a read-only queue and worker diagnostic without initializing storage.
pipeline_diagnostic() {
  # Status must remain observational.  In particular, do not import storage
  # here: importing the runtime database layer can initialize/migrate SQLite.
  local py
  if [[ -x ".venv/bin/python" ]]; then
    py=".venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    py="$(command -v python3)"
  else
    warn "Pipeline diagnostic unavailable: no Python runtime found."
    return 0
  fi

  if ! "$py" - <<'PY'
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import re
import sqlite3


def configured_value(key: str) -> str | None:
    """Read one diagnostic setting from process environment or the private file."""
    value = os.environ.get(key)
    if value is not None:
        return value.strip().strip("'\"")
    path = Path(".env")
    if not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8-sig", errors="ignore").splitlines()
    except OSError:
        return None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            continue
        current, raw = line.split("=", 1)
        if current.strip() == key:
            return raw.strip().strip("'\"")
    return None


def boolean_label(raw: str | None) -> str:
    """Render a configured boolean as a safe operator-facing status label."""
    if raw is None or not raw.strip():
        return "not configured"
    normalized = raw.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return "true"
    if normalized in {"0", "false", "no", "off"}:
        return "false (crawler loop disabled)"
    return "invalid value"


def table_exists(db: sqlite3.Connection, name: str) -> bool:
    """Return whether one diagnostic table exists without changing the schema."""
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def grouped_statuses(db: sqlite3.Connection, table: str, column: str,
                     ordered: tuple[str, ...], aliases: dict[str, str]) -> str:
    """Summarize bounded queue statuses using stable labels and aliases."""
    if not table_exists(db, table):
        return "unavailable (schema missing)"
    counts = Counter()
    for status, count in db.execute(
            f"SELECT lower(COALESCE({column},'')),COUNT(*) FROM {table} GROUP BY 1"):
        value = str(status or "")
        bucket = aliases.get(value, value if value in ordered else "other")
        counts[bucket] += int(count or 0)
    labels = [f"{name}={counts[name]}" for name in ordered]
    if counts["other"]:
        labels.append(f"other={counts['other']}")
    return " ".join(labels)


def safe_error_type(value: object) -> str:
    """Reduce an error value to a safe type label without leaking its message."""
    # Never print messages: they may contain URLs, tokens, page text, or paths.
    candidate = str(value or "").split(":", 1)[0].strip().rsplit(".", 1)[-1]
    if (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", candidate)
            and (candidate.endswith(("Error", "Exception", "Timeout", "Failure"))
                 or candidate in {"timeout", "database_locked", "worker_error"})):
        return candidate
    return "redacted_error"


print("Pipeline state (read-only)")
print("  ONION_CRAWLER_ENABLED: " + boolean_label(configured_value("ONION_CRAWLER_ENABLED")))

path = Path("messages.db")
if not path.is_file():
    print("  WARNING: pipeline database unavailable (messages.db missing)")
    raise SystemExit(0)

try:
    uri = path.resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=2) as db:
        db.execute("PRAGMA query_only=ON")
        if table_exists(db, "crawler_worker_state"):
            paused_row = db.execute(
                "SELECT COALESCE(is_paused,0) FROM crawler_worker_state WHERE id=1"
            ).fetchone()
            paused = bool(paused_row and int(paused_row[0] or 0))
            print("  Claim intake: " + ("PAUSED" if paused else "RUNNING"))
        else:
            print("  Claim intake: unavailable (schema missing)")

        onion_order = (
            "new", "queued", "retry", "claimed", "classification_pending",
            "deferred", "blocked", "crawled", "dead",
        )
        onion_aliases = {
            "fetching": "claimed", "deferred_forum_budget": "deferred",
            "deferred_deep_pagination": "deferred", "deferred": "deferred",
            "metadata_only": "blocked", "ignored": "blocked",
        }
        fetched_order = ("pending", "claimed", "retry", "failed", "done")
        fetched_aliases = {"dead_letter": "failed"}
        jobs_order = ("queued", "claimed", "retry", "failed", "dead_letter", "done")

        print("  onion_urls: " + grouped_statuses(
            db, "onion_urls", "status", onion_order, onion_aliases))
        print("  fetched_pages: " + grouped_statuses(
            db, "fetched_pages", "classification_status", fetched_order, fetched_aliases))
        print("  site_card_jobs: " + grouped_statuses(
            db, "site_card_jobs", "status", jobs_order, {}))
        if table_exists(db, "deep_discovery_jobs"):
            print("  deep_discovery_jobs: " + grouped_statuses(
                db, "deep_discovery_jobs", "status", jobs_order, {}))

        cutoff_seconds = 120
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=cutoff_seconds)).isoformat().replace(
            "+00:00", "Z")
        worker_counts = Counter()
        if table_exists(db, "worker_instances"):
            for worker_type, count in db.execute(
                    """SELECT lower(COALESCE(worker_type,'unknown')),COUNT(*)
                       FROM worker_instances
                       WHERE last_heartbeat_at>=? AND lower(COALESCE(state,''))!='stopped'
                       GROUP BY 1""", (cutoff,)):
                kind = str(worker_type or "unknown")
                if kind not in {"fetch", "verify", "card", "deep_discovery", "preview", "maintenance"}:
                    kind = "other"
                worker_counts[kind] += int(count or 0)
            worker_text = " ".join(
                f"{kind}={worker_counts[kind]}"
                for kind in ("fetch", "verify", "card", "deep_discovery", "preview", "maintenance")
            )
            if worker_counts["other"]:
                worker_text += f" other={worker_counts['other']}"
            print(f"  Active workers (heartbeat <= {cutoff_seconds}s): {worker_text}")

            errors = Counter(
                safe_error_type(row[0]) for row in db.execute(
                    """SELECT last_error FROM worker_instances
                       WHERE last_error IS NOT NULL AND trim(last_error)!=''
                       ORDER BY last_heartbeat_at DESC LIMIT 100"""))
            error_text = " ".join(f"{kind}={errors[kind]}" for kind in sorted(errors)) or "none"
            print("  Last worker error types: " + error_text)
        else:
            print("  Active workers: unavailable (schema missing)")
            print("  Last worker error types: unavailable (schema missing)")
except (OSError, sqlite3.Error) as exc:
    print(f"  WARNING: pipeline database unavailable ({type(exc).__name__})")
PY
  then
    printf '  WARNING: pipeline diagnostic unavailable (PythonError)\n'
  fi
  return 0
}

# Render the interactive server-control banner.
banner() {
  if [[ -t 1 ]]; then
    clear 2>/dev/null || true
  fi
  printf '%s\n' "${CYAN}+----------------------------------------------------------+${RESET}"
  printf '%s\n' "${CYAN}|${RESET} ${BOLD}ARACHNE SERVER CONTROL${RESET}                                  ${CYAN}|${RESET}"
  printf '%s\n' "${CYAN}|${RESET} install / update / access / database / workers        ${CYAN}|${RESET}"
  printf '%s\n' "${CYAN}+----------------------------------------------------------+${RESET}"
  printf '%sProject:%s %s\n' "$DIM" "$RESET" "$PROJECT_DIR"
}

# Display a concise, read-only overview for the main menu.
control_overview() {
  banner
  printf '\n%sQuick status%s\n' "$BOLD" "$RESET"
  hr
  printf 'Dashboard: %-10s  Bot: %-10s  Fetch: %s\n' \
    "$(state_badge "$(service_state arachne-dashboard.service)")" \
    "$(state_badge "$(service_state arachne-bot.service)")" \
    "$(state_badge "$(service_state arachne-fetch-worker.service)")"
  printf 'Verify:    %-10s  Card: %-10s  Preview: %s\n' \
    "$(state_badge "$(service_state arachne-verify-worker.service)")" \
    "$(state_badge "$(service_state arachne-card-worker.service)")" \
    "$(state_badge "$(service_state arachne-preview-worker.service)")"
  printf 'Discovery: %s\n' \
    "$(state_badge "$(service_state arachne-deep-discovery-worker.service)")"
  printf 'Maintenance timer: %s\n' \
    "$(state_badge "$(service_state "$MAINTENANCE_TIMER_NAME")")"
  printf 'DB:        %s\n' "$(db_info_line)"
  printf 'Telegram:  api_id=%s bot_token=%s admins=%s manual_pull=%s\n' \
    "$(env_value_present TELEGRAM_API_ID)" \
    "$(env_value_present TELEGRAM_BOT_TOKEN)" \
    "$(env_value_present TELEGRAM_ADMIN_IDS)" \
    "$(env_value_present TELEGRAM_MANUAL_PULL_ONLY)"
  local onion
  onion="$(onion_hostname)"
  if [[ -n "$onion" ]]; then
    printf 'Onion:     http://%s/\n' "$onion"
  else
    printf 'Onion:     not deployed\n'
  fi
  pipeline_diagnostic
  hr
}

# Create or refresh the project virtual environment from the pinned lock.
ensure_venv() {
  log "Preparing Python virtual environment"
  local system_py created=0
  system_py="$(require_python_312)"
  if [[ -d ".venv" && ! -x ".venv/bin/python" ]]; then
    warn "Existing .venv is incomplete; rebuilding only the disposable virtual environment."
    rm -rf -- ".venv"
  fi
  if [[ -x ".venv/bin/python" ]] && ! python_312_ready ".venv/bin/python"; then
    warn "Existing .venv does not use Python 3.12; rebuilding only the disposable virtual environment."
    rm -rf -- ".venv"
  fi
  if [[ ! -d ".venv" ]]; then
    if ! "$system_py" -m venv .venv; then
      rm -rf .venv
      if command -v apt-get >/dev/null 2>&1 && [[ "$(id -u)" == "0" ]]; then
        warn "Python 3.12 venv support is missing. Installing python3.12-venv, then retrying."
        apt-get update
        apt-get install -y python3.12-venv
        "$system_py" -m venv .venv || die "Could not create .venv after installing python3.12-venv."
      else
        die "Could not create .venv. Install python3.12-venv, then rerun."
      fi
    fi
    created=1
  fi
  local py requirements_hash installed_hash stamp
  py="$(python_bin)"
  [[ -x "$py" ]] || die ".venv/bin/python not found. Install python3-venv, then rerun."
  stamp=".venv/.arachne-requirements.sha256"
  requirements_hash="$("$py" - <<'PY'
from hashlib import sha256
from pathlib import Path
print(sha256(Path("requirements-lock.txt").read_bytes()).hexdigest())
PY
)"
  installed_hash="$(cat "$stamp" 2>/dev/null || true)"
  if [[ "$installed_hash" == "$requirements_hash" ]] && ! "$py" - <<'PY'
import importlib.util
import sys

required = (
    "telethon", "transformers", "requests", "stem", "bs4", "lxml", "dotenv",
    "streamlit", "pandas", "networkx", "dateutil", "pytest", "playwright",
    "PIL", "pytesseract", "psutil", "rapidfuzz",
)
missing = [name for name in required if importlib.util.find_spec(name) is None]
if missing:
    print("missing Python modules: " + ", ".join(missing))
    raise SystemExit(1)
PY
  then
    installed_hash=""
  fi
  if [[ "$created" -eq 1 || "$installed_hash" != "$requirements_hash" \
        || "${FORCE_DEPENDENCY_INSTALL:-0}" == "1" ]]; then
    log "Installing/updating Python dependencies"
    "$py" -m pip install -q --upgrade pip
    "$py" -m pip install -q -r requirements-lock.txt
    printf '%s\n' "$requirements_hash" > "$stamp"
  else
    ok "Python dependencies already match requirements-lock.txt."
  fi
  if [[ -f ".env" ]] && grep -Eqi '^[[:space:]]*ENABLE_PAGE_SCREENSHOTS[[:space:]]*=[[:space:]]*(1|true|yes|on)[[:space:]]*$' .env; then
    if ! "$py" - <<'PY'
from pathlib import Path
from playwright.sync_api import sync_playwright
with sync_playwright() as runtime:
    raise SystemExit(0 if Path(runtime.chromium.executable_path).is_file() else 1)
PY
    then
      log "Installing the Chromium preview runtime"
      "$py" -m playwright install --with-deps chromium
    fi
  fi
}

# Create private runtime directories and repair ownership without deleting data.
prepare_runtime_storage() {
  require_root_for_systemd
  local py path
  py="$(python_bin)"
  [[ -x "$py" ]] || die ".venv/bin/python is not ready; run install/update again."

  log "Preparing private writable runtime storage"
  install -d -m 0700 -o root -g root \
    "$PROJECT_DIR/runtime" \
    "$PROJECT_DIR/runtime/sessions"
  install -d -m 0750 -o root -g root \
    "$PROJECT_DIR/reports" \
    "$PROJECT_DIR/reports/previews" \
    "$PROJECT_DIR/logs" \
    "$PROJECT_DIR/backups"

  # FTP/SFTP uploads can recreate preserved state with an account owner that the
  # capability-restricted root services cannot override. Repair only known
  # writable/private artifacts; never delete or replace data or sessions here.
  for path in \
    "$PROJECT_DIR/.env" \
    "$PROJECT_DIR/messages.db" \
    "$PROJECT_DIR/messages.db-wal" \
    "$PROJECT_DIR/messages.db-shm" \
    "$PROJECT_DIR/messages.db-journal" \
    "$PROJECT_DIR/arachne.db" \
    "$PROJECT_DIR/arachne.db-wal" \
    "$PROJECT_DIR/arachne.db-shm" \
    "$PROJECT_DIR/arachne.db-journal" \
    "$PROJECT_DIR/runtime/dashboard_access.db" \
    "$PROJECT_DIR/runtime/dashboard_access.db-wal" \
    "$PROJECT_DIR/runtime/dashboard_access.db-shm" \
    "$PROJECT_DIR/runtime/dashboard_access.db-journal"; do
    [[ -L "$path" ]] && die "Private runtime file must not be a symbolic link: ${path##*/}"
    if [[ -e "$path" ]]; then
      chown root:root -- "$path"
      chmod 0600 -- "$path"
    fi
  done
  if [[ -n "$PREVIOUS_DB_FILE" ]]; then
    for path in \
      "$PROJECT_DIR/$PREVIOUS_DB_FILE" \
      "$PROJECT_DIR/$PREVIOUS_DB_FILE-wal" \
      "$PROJECT_DIR/$PREVIOUS_DB_FILE-shm" \
      "$PROJECT_DIR/$PREVIOUS_DB_FILE-journal"; do
      [[ -L "$path" ]] && die "Private runtime file must not be a symbolic link: ${path##*/}"
      if [[ -e "$path" ]]; then
        chown root:root -- "$path"
        chmod 0600 -- "$path"
      fi
    done
  fi

  local session_files=()
  shopt -s nullglob
  session_files=("$PROJECT_DIR"/runtime/sessions/*.session*)
  shopt -u nullglob
  if (( ${#session_files[@]} )); then
    for path in "${session_files[@]}"; do
      [[ -L "$path" ]] && die "Private runtime session must not be a symbolic link."
    done
    chown root:root -- "${session_files[@]}"
    chmod 0600 -- "${session_files[@]}"
  fi

  if ! "$py" - <<'PY'
import dashboard_auth

status = dashboard_auth.dashboard_access_status()
if status.get("storage_error"):
    raise SystemExit(
        "dashboard access storage preflight failed: "
        + str(status["storage_error"])
    )
print(
    "dashboard access storage: ok; lock="
    + ("enabled" if status.get("lock_enabled") else "disabled")
)
PY
  then
    die "Dashboard access storage is still unavailable. Run: bash RUN_AFTER_UPLOAD.sh repair-access"
  fi

  # The validation can create the DB/WAL files. Keep their final ownership and
  # private mode deterministic for both dashboard and Telegram bot services.
  for path in \
    "$PROJECT_DIR/runtime/dashboard_access.db" \
    "$PROJECT_DIR/runtime/dashboard_access.db-wal" \
    "$PROJECT_DIR/runtime/dashboard_access.db-shm" \
    "$PROJECT_DIR/runtime/dashboard_access.db-journal"; do
    if [[ -e "$path" ]]; then
      chown root:root -- "$path"
      chmod 0600 -- "$path"
    fi
  done
  ok "Runtime storage is writable; this preparation step removed no data or credentials."
}

# Install and start the required fail-closed Tor runtime when necessary.
ensure_tor_runtime() {
  require_root_for_systemd
  if ! command -v tor >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      log "Installing required Tor runtime"
      apt-get update
      apt-get install -y tor
    else
      die "Tor is required for fail-closed onion fetching. Install Tor, start its SOCKS service on 127.0.0.1:9050, then rerun."
    fi
  fi

  if ! systemctl is-active --quiet tor.service \
      && ! systemctl is-active --quiet tor@default.service; then
    log "Starting required Tor runtime"
    systemctl enable --now tor.service 2>/dev/null \
      || systemctl enable --now tor@default.service 2>/dev/null \
      || die "Tor could not be started. Run: systemctl status tor tor@default --no-pager"
  fi
}

# List every known unit name for an explicitly supplied prior namespace.
previous_service_units() {
  local prefix="$1" suffix
  for suffix in \
    dashboard.service fetch-worker.service verify-worker.service card-worker.service \
    deep-discovery-worker.service preview-worker.service bot.service \
    maintenance.service maintenance.timer onion-worker.service; do
    printf '%s-%s\n' "$prefix" "$suffix"
  done
}

# Stop, disable, and remove only the validated prior service namespace.
retire_previous_services() {
  local prefix="${ARACHNE_PREVIOUS_SERVICE_PREFIX:-}" unit unit_dir=/etc/systemd/system
  [[ -n "$prefix" ]] || die \
    "Set ARACHNE_PREVIOUS_SERVICE_PREFIX to the exact prior systemd prefix."
  [[ "$prefix" =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]{0,79}$ ]] || die \
    "ARACHNE_PREVIOUS_SERVICE_PREFIX contains unsupported characters."
  [[ "$prefix" != "arachne" ]] || die \
    "Refusing to retire the active Arachne service namespace."
  require_root_for_systemd
  log "Stopping and disabling the explicitly selected previous service namespace"
  while IFS= read -r unit; do
    systemctl disable --now "$unit" 2>/dev/null || true
    rm -f -- "$unit_dir/$unit"
    rm -rf -- "$unit_dir/$unit.d"
  done < <(previous_service_units "$prefix")
  systemctl daemon-reload
  ok "Previous service namespace retired: $prefix"
}

# Install canonical service definitions and retire explicitly requested old units.
install_services() {
  require_root_for_systemd
  log "Installing staged systemd services"
  if [[ -n "${ARACHNE_PREVIOUS_SERVICE_PREFIX:-}" ]]; then
    retire_previous_services
  fi
  systemctl disable --now arachne-onion-worker.service 2>/dev/null || true
  rm -f /etc/systemd/system/arachne-onion-worker.service
  rm -rf /etc/systemd/system/arachne-onion-worker.service.d
  write_systemd_units
  systemctl daemon-reload
  systemctl enable "${APP_SERVICE_NAMES[@]}"
  if telegram_config_ready; then
    systemctl enable "$BOT_SERVICE_NAME"
  else
    systemctl disable --now "$BOT_SERVICE_NAME" 2>/dev/null || true
    warn "Telegram is not configured; the optional bot service remains disabled."
  fi
  systemctl enable "$MAINTENANCE_TIMER_NAME"
}

# Write all canonical dashboard, worker, bot, and maintenance systemd units.
write_systemd_units() {
  local unit_dir="/etc/systemd/system"
  local py="$PROJECT_DIR/.venv/bin/python"

  cat > "$unit_dir/arachne-dashboard.service" <<EOF
[Unit]
Description=Arachne Streamlit dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
UMask=0077
WorkingDirectory=$PROJECT_DIR
Environment=DASHBOARD_BIND_ADDRESS=0.0.0.0
EnvironmentFile=-$PROJECT_DIR/.env
ExecStart=$py -m streamlit run dashboard.py --server.address \${DASHBOARD_BIND_ADDRESS} --server.port 8501
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$PROJECT_DIR
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
LockPersonality=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
EOF

  cat > "$unit_dir/arachne-fetch-worker.service" <<EOF
[Unit]
Description=Arachne staged fetch worker
After=network-online.target tor.service
Wants=network-online.target

[Service]
Type=simple
User=root
UMask=0077
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=-$PROJECT_DIR/.env
ExecStart=$py $PROJECT_DIR/fetch_worker.py --loop --workers 5
Restart=always
RestartSec=10
TimeoutStopSec=120
KillSignal=SIGTERM
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$PROJECT_DIR
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
LockPersonality=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
EOF

  cat > "$unit_dir/arachne-verify-worker.service" <<EOF
[Unit]
Description=Arachne staged verification worker
After=network-online.target tor.service arachne-fetch-worker.service
Wants=network-online.target

[Service]
Type=simple
User=root
UMask=0077
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=-$PROJECT_DIR/.env
ExecStart=$py $PROJECT_DIR/verify_worker.py --loop --workers 5
Restart=always
RestartSec=10
TimeoutStopSec=120
KillSignal=SIGTERM
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$PROJECT_DIR
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
LockPersonality=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
EOF

  cat > "$unit_dir/arachne-card-worker.service" <<EOF
[Unit]
Description=Arachne staged Site Card worker
After=network-online.target arachne-verify-worker.service
Wants=network-online.target

[Service]
Type=simple
User=root
UMask=0077
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=-$PROJECT_DIR/.env
ExecStart=$py $PROJECT_DIR/card_worker.py --loop --workers 2
Restart=always
RestartSec=10
TimeoutStopSec=120
KillSignal=SIGTERM
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$PROJECT_DIR
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
LockPersonality=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
EOF

  cat > "$unit_dir/arachne-preview-worker.service" <<EOF
[Unit]
Description=Arachne staged preview worker
After=network-online.target tor.service arachne-verify-worker.service
Wants=network-online.target

[Service]
Type=simple
User=root
UMask=0077
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=-$PROJECT_DIR/.env
ExecStart=$py $PROJECT_DIR/preview_worker.py --loop --workers 2
Restart=always
RestartSec=10
TimeoutStopSec=120
KillSignal=SIGTERM
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$PROJECT_DIR
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
LockPersonality=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
EOF

  cat > "$unit_dir/arachne-deep-discovery-worker.service" <<EOF
[Unit]
Description=Arachne local Deep Discovery worker
After=network-online.target arachne-card-worker.service
Wants=network-online.target

[Service]
Type=simple
User=root
UMask=0077
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=-$PROJECT_DIR/.env
ExecStart=$py $PROJECT_DIR/deep_discovery_worker.py --loop --workers 1
Restart=on-failure
RestartSec=10
TimeoutStopSec=120
KillSignal=SIGTERM
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$PROJECT_DIR
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=
LockPersonality=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
EOF

  cat > "$unit_dir/arachne-bot.service" <<EOF
[Unit]
Description=Arachne Telegram control bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
UMask=0077
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=-$PROJECT_DIR/.env
ExecStart=$py $PROJECT_DIR/arachne.py
Restart=on-failure
RestartSec=10
TimeoutStopSec=120
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$PROJECT_DIR
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
LockPersonality=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
EOF

  cat > "$unit_dir/arachne-maintenance.service" <<EOF
[Unit]
Description=Arachne bounded maintenance leader
After=arachne-card-worker.service arachne-deep-discovery-worker.service

[Service]
Type=oneshot
User=root
UMask=0077
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=-$PROJECT_DIR/.env
ExecStart=$py $PROJECT_DIR/onion_worker.py --maintenance-once
TimeoutStartSec=900
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$PROJECT_DIR
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=
LockPersonality=true
PrivateDevices=true
EOF

  cat > "$unit_dir/arachne-maintenance.timer" <<EOF
[Unit]
Description=Run bounded Arachne maintenance periodically

[Timer]
OnBootSec=15min
OnUnitActiveSec=6h
RandomizedDelaySec=10min
Persistent=true
Unit=arachne-maintenance.service

[Install]
WantedBy=timers.target
EOF

  chown root:root \
    "$unit_dir/arachne-dashboard.service" \
    "$unit_dir/arachne-fetch-worker.service" \
    "$unit_dir/arachne-verify-worker.service" \
    "$unit_dir/arachne-card-worker.service" \
    "$unit_dir/arachne-deep-discovery-worker.service" \
    "$unit_dir/arachne-preview-worker.service" \
    "$unit_dir/arachne-bot.service" \
    "$unit_dir/arachne-maintenance.service" \
    "$unit_dir/arachne-maintenance.timer"
  chmod 0644 \
    "$unit_dir/arachne-dashboard.service" \
    "$unit_dir/arachne-fetch-worker.service" \
    "$unit_dir/arachne-verify-worker.service" \
    "$unit_dir/arachne-card-worker.service" \
    "$unit_dir/arachne-deep-discovery-worker.service" \
    "$unit_dir/arachne-preview-worker.service" \
    "$unit_dir/arachne-bot.service" \
    "$unit_dir/arachne-maintenance.service" \
    "$unit_dir/arachne-maintenance.timer"
}

# Compile the deployment-critical Python modules without starting the application.
compile_check() {
  local py
  py="$(python_bin)"
  log "Compiling runtime modules"
  "$py" -m py_compile \
    dashboard.py onion_worker.py arachne.py storage.py \
    fetch_worker.py verify_worker.py card_worker.py preview_worker.py \
    deep_discovery.py deep_discovery_providers.py deep_discovery_worker.py \
    operational_observability.py \
    scripts/backup_sqlite.py scripts/restore_sqlite.py \
    scripts/backup_retention.py scripts/make_clean_release.py \
    actor_intelligence.py entity_extractor.py entity_quality.py \
    entity_expansion.py structured_intelligence.py \
    dashboard_pages/entity_intelligence.py \
    config_loader.py screenshot_service.py site_dedupe.py
}

# Run the fast deployment smoke-test subset.
run_tests() {
  local py
  py="$(python_bin)"
  if [[ "${SKIP_TESTS:-0}" == "1" ]]; then
    warn "Skipping pytest because SKIP_TESTS=1"
    return 0
  fi
  log "Running test suite"
  "$py" -m pytest -q
}

# Run the complete regression suite with bytecode generation disabled.
run_full_tests() {
  ensure_venv
  (
    unset SKIP_TESTS
    run_tests
  )
}

# Execute offline launch checks that are safe during installation.
deploy_smoke_checks() {
  local py
  py="$(python_bin)"
  if [[ "${SKIP_TESTS:-0}" == "1" ]]; then
    warn "Skipping deploy smoke pytest because SKIP_TESTS=1; compilation and source proof still run."
    return 0
  fi
  log "Running deploy-safe smoke checks"
  # Keep this list away from tests that import the live Telegram bot module or
  # touch the production SQLite DB. Full tests remain available through
  # `bash RUN_AFTER_UPLOAD.sh full-tests`.
  "$py" -m pytest -q \
    tests/test_deployment_readiness.py \
    tests/test_dashboard_access_lock.py::test_dashboard_code_is_hashed_one_time_and_creates_session \
    tests/test_dashboard_access_lock.py::test_expired_and_revoked_codes_fail \
    tests/test_dashboard_access_lock.py::test_telegram_code_path_uses_dedicated_auth_db_when_main_db_is_broken
}

# Return success when the main database already contains the canonical schema.
main_db_ready() {
  local py
  py="$(python_bin)"
  "$py" - <<'PY'
import storage
storage.init_db()
with storage.get_db() as db:
    db.execute("SELECT 1").fetchone()
print("ok")
PY
}

# Run read-only database and pipeline consistency diagnostics.
consistency_checks() {
  local py
  py="$(python_bin)"
  log "Running consistency checks"
  if ! main_db_ready; then
    warn "Main crawler DB is not writable/readable. Skipping DB-dependent consistency checks."
    warn "Run: bash RUN_AFTER_UPLOAD.sh db-doctor"
    warn "If you are okay wiping crawler data, run: bash RUN_AFTER_UPLOAD.sh wipe-db"
    return 2
  fi
  "$py" onion_worker.py --audit-consistency
  "$py" onion_worker.py --repair-consistency --dry-run
  "$py" onion_worker.py --repair-link-list-frontier --dry-run
}

# Refresh bounded Site Card statistics through the maintenance helper.
refresh_rollups() {
  local py
  py="$(python_bin)"
  log "Refreshing Site Card rollups"
  "$py" - <<'PY'
import storage
import site_dedupe

storage.init_db()
with storage.get_db() as db:
    ids = [int(row[0]) for row in db.execute("SELECT id FROM site_cards")]
for card_id in ids:
    site_dedupe.update_site_card_rollups(card_id)
print(f"refreshed {len(ids)} site cards")
PY
}

# Queue changed Site Cards for idempotent staged rollup processing.
queue_dirty_rollups() {
  local py
  py="$(python_bin)"
  log "Queueing changed Site Cards for staged rollup"
  "$py" - <<'PY'
import storage

storage.init_db()
queued = 0
with storage.get_db() as db:
    rows = [dict(row) for row in db.execute("""SELECT id,representative_url,ui_priority
      FROM site_cards WHERE COALESCE(rollup_dirty,0)=1 ORDER BY updated_at,id""")]
for row in rows:
    storage.create_site_card_job(
        site_card_id=int(row["id"]), url=row.get("representative_url"),
        job_type="rollup", priority=int(row.get("ui_priority") or 0),
    )
    queued += 1
print(f"queued {queued} changed Site Card rollup job(s)")
PY
}

# Print table counts and recognized database file sizes.
db_info() {
  log "Database summary"
  local py
  py="$(python_bin)"
  if [[ -x "$py" ]]; then
    "$py" - <<'PY'
from pathlib import Path
import os
import sqlite3

db_path = Path("messages.db")
if db_path.is_file():
    try:
        uri = db_path.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=5) as db:
            tables = {
                "site_cards": "SELECT COUNT(*) FROM site_cards",
                "onion_urls": "SELECT COUNT(*) FROM onion_urls",
                "fetched_pages": "SELECT COUNT(*) FROM fetched_pages",
                "site_card_jobs": "SELECT COUNT(*) FROM site_card_jobs",
                "workers": "SELECT COUNT(*) FROM worker_instances",
            }
            for label, sql in tables.items():
                try:
                    print(f"{label:16} {db.execute(sql).fetchone()[0]}")
                except sqlite3.Error:
                    print(f"{label:16} unavailable")
    except Exception as exc:
        print(f"database summary unavailable: {type(exc).__name__}")
else:
    print("database summary: no crawler DB yet")
names = ["messages.db", "arachne.db"]
previous = os.getenv("ARACHNE_PREVIOUS_DB_FILE", "").strip()
if previous:
    names.append(previous)
for name in dict.fromkeys(names):
    path = Path(name)
    if path.exists():
        print(f"{name:16} {path.stat().st_size / 1024 / 1024:.2f} MB")
PY
  else
    db_info_line; printf '\n'
  fi
}

# Diagnose disk, permissions, SQLite integrity, and dashboard access storage.
db_doctor() {
  log "Database doctor"
  printf 'Project: %s\n' "$PROJECT_DIR"
  printf '\nDisk space:\n'
  df -h "$PROJECT_DIR" /tmp 2>/dev/null || df -h "$PROJECT_DIR"
  printf '\nInodes:\n'
  df -i "$PROJECT_DIR" 2>/dev/null || true
  printf '\nDatabase files:\n'
  ls -lh messages.db* arachne.db* runtime/dashboard_access.db* 2>/dev/null || true
  if [[ -n "$PREVIOUS_DB_FILE" ]]; then
    ls -lh -- "$PREVIOUS_DB_FILE"* 2>/dev/null || true
  fi
  printf '\nDirectory permissions:\n'
  ls -ld "$PROJECT_DIR" . runtime runtime/sessions reports reports/previews logs backups 2>/dev/null || true

  local py
  py="$(python_bin)"
  if [[ -x "$py" ]]; then
    printf '\nSQLite checks:\n'
    "$py" - <<'PY'
from pathlib import Path
import os
import sqlite3

names = ["messages.db", "arachne.db", "runtime/dashboard_access.db"]
previous = os.getenv("ARACHNE_PREVIOUS_DB_FILE", "").strip()
if previous:
    names.append(previous)
for name in dict.fromkeys(names):
    path = Path(name)
    if not path.exists():
        print(f"{name}: missing")
        continue
    try:
        con = sqlite3.connect(str(path), timeout=5)
        try:
            print(f"{name}: quick_check={con.execute('PRAGMA quick_check').fetchone()[0]}")
            print(f"{name}: integrity_check={con.execute('PRAGMA integrity_check').fetchone()[0]}")
        finally:
            con.close()
    except Exception as exc:
        print(f"{name}: ERROR {type(exc).__name__}: {exc}")

try:
    import dashboard_auth
    status = dashboard_auth.dashboard_access_status()
    print(
        "access storage: "
        + ("ERROR " + str(status.get("storage_error"))
           if status.get("storage_error") else "ok")
    )
except Exception as exc:
    print(f"access storage: ERROR {type(exc).__name__}")
PY
  else
    warn "Virtualenv is not ready, skipping SQLite quick_check."
  fi
}

# Record one successful read-only doctor check.
doctor_ok() {
  printf '%sPASS%s  %s\n' "$GREEN" "$RESET" "$*"
}

# Record one non-blocking read-only doctor observation.
doctor_warning() {
  DOCTOR_WARNINGS=$((DOCTOR_WARNINGS + 1))
  printf '%sWARN%s  %s\n' "$YELLOW" "$RESET" "$*"
}

# Record one failed read-only doctor check without stopping later checks.
doctor_failure() {
  DOCTOR_FAILURES=$((DOCTOR_FAILURES + 1))
  printf '%sFAIL%s  %s\n' "$RED" "$RESET" "$*"
}

# Check existing SQLite files through read-only URI connections.
doctor_database_checks() {
  local py="$1"
  "$py" - <<'PY'
from pathlib import Path
import os
import sqlite3
import sys

names = ["messages.db", "arachne.db", "runtime/dashboard_access.db"]
previous = os.getenv("ARACHNE_PREVIOUS_DB_FILE", "").strip()
if previous:
    names.append(previous)
found = 0
failed = 0
for name in dict.fromkeys(names):
    path = Path(name)
    if not path.is_file():
        continue
    found += 1
    try:
        uri = path.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=5) as connection:
            result = connection.execute("PRAGMA quick_check").fetchone()[0]
        print(f"      {name}: {result}")
        if result != "ok":
            failed += 1
    except Exception as exc:
        print(f"      {name}: ERROR {type(exc).__name__}")
        failed += 1
if not found:
    print("      no database files yet")
raise SystemExit(1 if failed else 0)
PY
}

# Diagnose prerequisites and deployed state without writing files or changing services.
doctor() {
  log "Read-only installation doctor"
  printf 'No packages, files, databases, services, or settings will be changed.\n\n'
  DOCTOR_FAILURES=0
  DOCTOR_WARNINGS=0

  local required system_py actual mode owner available_kb installed_units=0 service
  for required in requirements.txt requirements-lock.txt dashboard.py arachne.py \
      RUN_AFTER_UPLOAD.sh SOURCE_MANIFEST.json; do
    if [[ -f "$required" ]]; then
      doctor_ok "Source file present: $required"
    else
      doctor_failure "Required source file missing: $required"
    fi
  done

  system_py="$(system_python_bin 2>/dev/null || true)"
  if [[ -n "$system_py" ]]; then
    actual="$($system_py -c 'import sys; print(".".join(map(str, sys.version_info[:3])))' 2>/dev/null || printf 'unknown')"
    if python_312_ready "$system_py"; then
      doctor_ok "System Python is supported: $system_py ($actual)"
    else
      doctor_failure "Python 3.12 required; $system_py reports $actual"
    fi
  else
    doctor_failure "Python 3.12 is not installed"
  fi

  if [[ -x ".venv/bin/python" ]]; then
    if python_312_ready ".venv/bin/python"; then
      doctor_ok "Virtual environment uses Python 3.12"
    else
      doctor_failure "Virtual environment uses the wrong Python version; bootstrap will rebuild it"
    fi
  else
    doctor_warning "Virtual environment is not installed yet"
  fi

  if [[ -f ".env" ]]; then
    mode="$(stat -c '%a' .env 2>/dev/null || printf 'unknown')"
    owner="$(stat -c '%U:%G' .env 2>/dev/null || printf 'unknown')"
    if [[ "$mode" == "600" && "$owner" == "root:root" ]]; then
      doctor_ok ".env is private (mode 600, owner $owner)"
    else
      doctor_failure ".env must use mode 600 and owner root:root; current mode is $mode (owner $owner)"
    fi
  else
    doctor_warning ".env is absent; bootstrap will create safe defaults"
  fi

  if [[ -n "$system_py" && -f "scripts/make_clean_release.py" ]]; then
    if PYTHONDONTWRITEBYTECODE=1 "$system_py" scripts/make_clean_release.py --verify-source >/dev/null 2>&1; then
      doctor_ok "Source manifest matches the selected deployment tree"
    else
      doctor_failure "Source manifest verification failed"
    fi
  else
    doctor_failure "Source manifest could not be verified"
  fi

  available_kb="$(df -Pk "$PROJECT_DIR" 2>/dev/null | awk 'NR==2 {print $4}')"
  if [[ "$available_kb" =~ ^[0-9]+$ ]]; then
    if (( available_kb >= 1048576 )); then
      doctor_ok "At least 1 GiB of project filesystem space is available"
    else
      doctor_warning "Less than 1 GiB of project filesystem space is available"
    fi
  else
    doctor_warning "Available project filesystem space could not be determined"
  fi

  if command -v systemctl >/dev/null 2>&1; then
    doctor_ok "systemd control is available"
    for service in "${SERVICE_NAMES[@]}" "$MAINTENANCE_TIMER_NAME"; do
      if systemctl cat "$service" >/dev/null 2>&1; then
        installed_units=$((installed_units + 1))
      fi
    done
    if (( installed_units > 0 )); then
      doctor_ok "$installed_units canonical service unit(s) are installed"
    else
      doctor_warning "Arachne service units are not installed yet"
    fi
  else
    doctor_failure "systemd is not available"
  fi

  if command -v tor >/dev/null 2>&1; then
    doctor_ok "Tor executable is installed"
    if command -v systemctl >/dev/null 2>&1 && \
        (systemctl is-active --quiet tor.service || systemctl is-active --quiet tor@default.service); then
      doctor_ok "Tor service is active"
    else
      doctor_warning "Tor is installed but its service is not currently active"
    fi
  else
    doctor_warning "Tor is not installed yet; bootstrap can install it on Ubuntu"
  fi

  if [[ -n "$system_py" ]]; then
    if doctor_database_checks "$system_py"; then
      doctor_ok "Existing SQLite files passed read-only quick checks"
    else
      doctor_failure "One or more SQLite files failed read-only quick checks"
    fi
  else
    doctor_warning "SQLite files were not checked because Python is unavailable"
  fi

  if [[ -x ".venv/bin/python" && -f ".env" ]]; then
    if PYTHONDONTWRITEBYTECODE=1 telegram_config_ready; then
      doctor_ok "Optional Telegram integration is completely configured"
    else
      doctor_warning "Telegram is incomplete; its bot service will remain disabled"
    fi
  fi

  printf '\nDoctor summary: %s failure(s), %s warning(s).\n' "$DOCTOR_FAILURES" "$DOCTOR_WARNINGS"
  if (( DOCTOR_FAILURES > 0 )); then
    printf 'Fix the failed prerequisites, then rerun: bash RUN_AFTER_UPLOAD.sh doctor\n'
    return 1
  fi
  printf 'No blocking prerequisite problems were found.\n'
}

# Generate one bounded one-time dashboard access code without prompting.
issue_dashboard_code() {
  local duration="${1:-1h}" source="${2:-server_control}"
  ensure_venv
  prepare_runtime_storage
  set_env_key DASHBOARD_LOCK_ENABLED "true"
  "$(python_bin)" - "$duration" "$source" <<'PY'
import sys
import re
import dashboard_auth

raw = (sys.argv[1] if len(sys.argv) > 1 else "1h").strip().lower()
source = (sys.argv[2] if len(sys.argv) > 2 else "server_control").strip() or "server_control"
match = re.fullmatch(r"(\d+)\s*([mhd]?)", raw)
if not match:
    raise SystemExit("Invalid duration. Use examples like 15m, 1h, 4h, 24h.")
number = int(match.group(1))
unit = match.group(2) or "m"
seconds = number * {"m": 60, "h": 3600, "d": 86400}[unit]
seconds = max(60, min(seconds, 7 * 24 * 3600))
dashboard_auth.set_dashboard_lock_enabled(True, source)
result = dashboard_auth.generate_dashboard_code(seconds, source)
if not result.get("code"):
    raise SystemExit(result.get("error") or result.get("reason") or "code generation failed")
print("")
print("Dashboard access lock: enabled")
print(f"One-time code: {result['code']}")
print(f"Expires at:    {result['expires_at']}")
print("")
PY
}

# Prompt for a duration and issue one bounded dashboard access code.
generate_dashboard_code() {
  local duration
  read -r -p "Code duration in minutes, or use 1h/4h/etc [60]: " duration
  issue_dashboard_code "${duration:-1h}" "server_control"
}

# Run the fail-closed Tor and crawler OPSEC checks without starting a crawl.
opsec_audit() {
  local py
  py="$(python_bin)"
  log "Running OPSEC audit"
  "$py" onion_worker.py --opsec-audit || die \
    "OPSEC audit failed. Confirm Tor SOCKS is reachable at the configured host/port; no crawler service was started."
}

# Restart the application plus the configured optional bot and maintenance timer.
restart_services() {
  require_root_for_systemd
  if [[ "${SKIP_RESTART:-0}" == "1" ]]; then
    warn "Skipping service restart because SKIP_RESTART=1"
    return 0
  fi
  prepare_runtime_storage
  local services=("${APP_SERVICE_NAMES[@]}") service
  if telegram_config_ready; then
    repair_telegram_env
    services+=("$BOT_SERVICE_NAME")
  else
    systemctl disable --now "$BOT_SERVICE_NAME" 2>/dev/null || true
    warn "Telegram is not configured; restarting Arachne without the optional bot."
  fi
  log "Restarting services"
  systemctl restart "${services[@]}"
  for service in "${services[@]}"; do
    wait_service_stable "$service" || {
      systemctl --no-pager --full status "$service" || true
      die "$service did not remain active after restart."
    }
  done
  systemctl enable --now "$MAINTENANCE_TIMER_NAME"
  wait_timer_active "$MAINTENANCE_TIMER_NAME" || die "$MAINTENANCE_TIMER_NAME is not active."
}

# Restart the dashboard and staged workers without restarting the bot.
restart_app_services() {
  require_root_for_systemd
  if [[ "${SKIP_RESTART:-0}" == "1" ]]; then
    warn "Skipping service restart because SKIP_RESTART=1"
    return 0
  fi
  prepare_runtime_storage
  log "Restarting dashboard and workers"
  systemctl restart "${APP_SERVICE_NAMES[@]}"
  local service
  for service in "${APP_SERVICE_NAMES[@]}"; do
    wait_service_stable "$service" || {
      systemctl --no-pager --full status "$service" || true
      die "$service did not remain active after restart."
    }
  done
  systemctl enable --now "$MAINTENANCE_TIMER_NAME"
  wait_timer_active "$MAINTENANCE_TIMER_NAME" || die "$MAINTENANCE_TIMER_NAME is not active."
}

# Restart only the staged crawler pipeline workers.
restart_worker_services() {
  require_root_for_systemd
  if [[ "${SKIP_RESTART:-0}" == "1" ]]; then
    warn "Skipping worker restart because SKIP_RESTART=1"
    return 0
  fi
  prepare_runtime_storage
  log "Restarting crawler pipeline workers"
  systemctl restart "${WORKER_SERVICE_NAMES[@]}"
  local service
  for service in "${WORKER_SERVICE_NAMES[@]}"; do
    wait_service_stable "$service" || {
      systemctl --no-pager --full status "$service" || true
      die "$service did not remain active after restart."
    }
  done
}

# Restart only the dashboard service after repairing its writable storage.
restart_dashboard_only() {
  require_root_for_systemd
  if [[ "${SKIP_RESTART:-0}" == "1" ]]; then
    warn "Skipping dashboard restart because SKIP_RESTART=1"
    return 0
  fi
  prepare_runtime_storage
  log "Restarting dashboard only"
  systemctl restart arachne-dashboard.service
  wait_service_stable arachne-dashboard.service || die "Dashboard did not remain active after restart."
}

# Return success only when the complete optional Telegram integration is configured.
telegram_config_ready() {
  local py
  py="$(python_bin)"
  "$py" - <<'PY'
import re

from config_loader import get_int, get_str


def valid_admin(value):
    """Return whether an administrator identifier has a safe Telegram shape."""
    return bool(re.fullmatch(r"-?\d{5,20}", value)) and value not in {
        "0", "12345", "6789", "67890"
    }


api_id = get_int("TELEGRAM_API_ID", 0)
api_hash = (get_str("TELEGRAM_API_HASH", "") or "").strip()
token = (get_str("TELEGRAM_BOT_TOKEN", "") or get_str("BOT_TOKEN", "") or "").strip()
raw_admins = " ".join(
    filter(None, [get_str("TELEGRAM_ADMIN_IDS", ""), get_str("ADMIN_CHAT_ID", "")])
)
admins = [part for part in re.split(r"[,; ]+", raw_admins) if valid_admin(part)]
raise SystemExit(0 if api_id > 0 and api_hash and token and admins else 1)
PY
}

# Validate Telegram credentials and normalize the authorized administrator keys.
repair_telegram_env() {
  local py
  py="$(python_bin)"
  log "Validating Telegram .env settings"
  "$py" - <<'PY'
from pathlib import Path
import os
import re
from scripts.private_env import read_private_env, write_private_env

env_path = Path(".env")
raw = read_private_env(env_path)
raw = raw.lstrip("\ufeff")
bad_ids = {"", "0", "12345", "6789", "67890"}

def valid_id(value):
    """Return whether a Telegram identifier has the accepted numeric shape."""
    return bool(re.fullmatch(r"-?\d{5,20}", str(value or "").strip()))

values = {}
for line in raw.splitlines():
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    values[key.strip()] = value.strip()

def env_value(key):
    """Read and unquote one Telegram setting from file or process environment."""
    if key in values:
        value = values[key]
    else:
        value = os.environ.get(key, "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return value.strip()

api_id = env_value("TELEGRAM_API_ID")
api_hash = env_value("TELEGRAM_API_HASH")
token = env_value("TELEGRAM_BOT_TOKEN") or env_value("BOT_TOKEN")
admin_ids = []
for key in ("TELEGRAM_ADMIN_IDS", "ADMIN_CHAT_ID"):
    for part in re.split(r"[,; ]+", env_value(key)):
        part = part.strip()
        if valid_id(part) and part not in bad_ids and part not in admin_ids:
            admin_ids.append(part)

missing = []
if not api_id.isdigit() or int(api_id or 0) <= 0:
    missing.append("TELEGRAM_API_ID")
if not api_hash:
    missing.append("TELEGRAM_API_HASH")
if not token:
    missing.append("TELEGRAM_BOT_TOKEN")
if not admin_ids:
    missing.append("TELEGRAM_ADMIN_IDS/ADMIN_CHAT_ID")
if missing:
    print("Missing or invalid Telegram configuration: " + ", ".join(missing))
    print("Run: bash RUN_AFTER_UPLOAD.sh configure-env")
    raise SystemExit(2)

forced = {
    "ADMIN_CHAT_ID": admin_ids[0],
    "TELEGRAM_ADMIN_IDS": ",".join(admin_ids),
    "TELEGRAM_BOT_TOKEN": token,
}

lines = []
seen = set()
for line in raw.splitlines():
    if "=" not in line or line.strip().startswith("#"):
        lines.append(line)
        continue
    key, _value = line.split("=", 1)
    key = key.strip()
    if key in forced:
        if key not in seen:
            lines.append(f"{key}={forced[key]}")
            seen.add(key)
        continue
    lines.append(line)
for key, value in forced.items():
    if key not in seen:
        lines.append(f"{key}={value}")

write_private_env("\n".join(lines).rstrip() + "\n", env_path)
print(f"Telegram configuration ok; authorized admins={len(admin_ids)}.")
PY
  chown root:root -- "$PROJECT_DIR/.env"
  chmod 0600 -- "$PROJECT_DIR/.env"
}

# Restart the optional bot when configured, or keep its unit stopped and disabled.
restart_bot_if_configured() {
  if telegram_config_ready; then
    restart_bot_service
  else
    systemctl disable --now "$BOT_SERVICE_NAME" 2>/dev/null || true
    warn "Telegram is not configured; the optional bot was not started."
  fi
}

# Start the bot only when it is absent or inactive, then prove stability.
ensure_bot_service_running() {
  require_root_for_systemd
  if [[ "${SKIP_RESTART:-0}" == "1" ]]; then
    warn "Skipping bot start check because SKIP_RESTART=1"
    return 0
  fi
  prepare_runtime_storage
  repair_telegram_env
  log "Checking Telegram bot service"
  systemctl enable "$BOT_SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl reset-failed "$BOT_SERVICE_NAME" >/dev/null 2>&1 || true
  if systemctl is-active --quiet "$BOT_SERVICE_NAME"; then
    wait_service_stable "$BOT_SERVICE_NAME" || die "Telegram bot did not remain active."
    ok "Telegram bot is already active and stable; not restarting it."
    return 0
  fi
  warn "Telegram bot is not running; starting it now."
  systemctl start "$BOT_SERVICE_NAME"
  if ! wait_service_stable "$BOT_SERVICE_NAME"; then
    systemctl --no-pager --full status "$BOT_SERVICE_NAME" || true
    die "Telegram bot did not become active. Check credentials and the bot service log."
  fi
  ok "Telegram bot start command completed and service is active."
}

# Validate configuration and deliberately restart the Telegram control bot.
restart_bot_service() {
  require_root_for_systemd
  if [[ "${SKIP_RESTART:-0}" == "1" ]]; then
    warn "Skipping bot restart because SKIP_RESTART=1"
    return 0
  fi
  prepare_runtime_storage
  repair_telegram_env
  log "Restarting Telegram control bot"
  systemctl enable "$BOT_SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl reset-failed "$BOT_SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl restart "$BOT_SERVICE_NAME"
  if ! wait_service_stable "$BOT_SERVICE_NAME"; then
    systemctl --no-pager --full status "$BOT_SERVICE_NAME" || true
    die "Telegram bot did not become active after restart. Check credentials and bot logs."
  fi
  ok "Telegram bot restarted with the uploaded code."
}

# Prepare an installation as needed and ensure the bot service is running.
start_bot_command() {
  require_project
  require_root_for_systemd
  ensure_venv
  prepare_runtime_storage
  if ! systemctl cat "$BOT_SERVICE_NAME" >/dev/null 2>&1; then
    warn "Arachne units are not installed yet; installing unit definitions first."
    install_services
  fi
  ensure_bot_service_running
}

# Stop the dashboard, workers, and maintenance units while leaving the bot alone.
stop_app_services() {
  require_root_for_systemd
  log "Stopping dashboard and workers only"
  stop_services_checked "$MAINTENANCE_TIMER_NAME" "$MAINTENANCE_SERVICE_NAME" \
    "${APP_SERVICE_NAMES[@]}" || die "Could not stop every app service safely."
}

# Restore the safest viable service state after an interrupted deploy operation.
recover_runtime_services_after_failure() {
  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi
  warn "A deploy/update step failed. Trying to keep the dashboard, workers, and Telegram bot online before exiting."
  systemctl reset-failed "${SERVICE_NAMES[@]}" >/dev/null 2>&1 || true
  if [[ "${SKIP_RESTART:-0}" != "1" ]]; then
    if main_db_ready; then
      systemctl restart "${APP_SERVICE_NAMES[@]}" >/dev/null 2>&1 || true
      systemctl enable --now "$MAINTENANCE_TIMER_NAME" >/dev/null 2>&1 || true
    else
      systemctl stop "$MAINTENANCE_TIMER_NAME" "$MAINTENANCE_SERVICE_NAME" \
        "${WORKER_SERVICE_NAMES[@]}" >/dev/null 2>&1 || true
      systemctl restart arachne-dashboard.service >/dev/null 2>&1 || true
    fi
    if telegram_config_ready; then
      systemctl enable "$BOT_SERVICE_NAME" >/dev/null 2>&1 || true
      systemctl start "$BOT_SERVICE_NAME" >/dev/null 2>&1 || true
    else
      systemctl disable --now "$BOT_SERVICE_NAME" >/dev/null 2>&1 || true
    fi
  fi
  systemctl --no-pager --full status "${SERVICE_NAMES[@]}" 2>/dev/null || true
}

# Stop every service and timer that can access Arachne runtime state.
stop_all_services() {
  require_root_for_systemd
  log "Stopping all Arachne services, including Telegram bot"
  stop_services_checked "$MAINTENANCE_TIMER_NAME" "$MAINTENANCE_SERVICE_NAME" \
    "${SERVICE_NAMES[@]}" || die "Could not stop every Arachne service safely."
}

# Snapshot databases, remove stopped-writer sidecars, and reinitialize storage.
repair_db_io() {
  require_root_for_systemd
  ensure_venv
  prepare_runtime_storage
  log "Repair DB I/O state"
  printf 'This briefly stops all services including Telegram, backs up DB files, removes stale WAL/SHM/JOURNAL files,\n'
  printf 'fixes ownership/permissions, and runs storage.init_db(). It does not delete messages.db.\n\n'
  local previously_active=() service timer_was_active=0
  for service in "${SERVICE_NAMES[@]}"; do
    systemctl is-active --quiet "$service" && previously_active+=("$service")
  done
  systemctl is-active --quiet "$MAINTENANCE_TIMER_NAME" && timer_was_active=1
  if ! stop_all_services; then
    die "DB repair cancelled because a database user is still running."
  fi
  if ! backup_db; then
    restore_active_service_snapshot "$timer_was_active" "${previously_active[@]}" || true
    die "DB repair cancelled because a verified SQLite backup could not be created."
  fi
  local repair_db sidecar
  for repair_db in "${DB_FILES[@]}"; do
    for sidecar in -wal -shm -journal; do
      rm -f -- "${repair_db}${sidecar}"
    done
  done
  if ! "$(python_bin)" - <<'PY'
import storage
storage.init_db()
print("storage.init_db completed")
PY
  then
    restore_active_service_snapshot "$timer_was_active" "${previously_active[@]}" || true
    die "DB I/O repair failed. Services were restarted; run db-doctor and check the output."
  fi
  restore_active_service_snapshot "$timer_was_active" "${previously_active[@]}" \
    || die "DB storage was repaired, but one previously active service did not recover."
  ok "DB I/O repair routine completed."
}

# Repair dashboard access storage permissions and refresh active consumers.
repair_access_storage() {
  require_project
  require_root_for_systemd
  ensure_venv
  prepare_runtime_storage

  if [[ "${SKIP_RESTART:-0}" == "1" ]]; then
    warn "Access storage is repaired; service restart skipped because SKIP_RESTART=1."
    return 0
  fi

  local service
  for service in arachne-dashboard.service "$BOT_SERVICE_NAME"; do
    if ! systemctl cat "$service" >/dev/null 2>&1; then
      warn "$service is not installed yet; option 1 will install it."
      continue
    fi
    if [[ "$service" == "$BOT_SERVICE_NAME" ]] && ! systemctl is-active --quiet "$service"; then
      warn "$service was already offline, so access repair did not start it. Run bot-start after checking credentials."
      continue
    fi
    systemctl reset-failed "$service" >/dev/null 2>&1 || true
    systemctl restart "$service"
    wait_service_stable "$service" || die "$service did not remain active after access-storage repair."
  done
  ok "Dashboard access storage repaired and active access services refreshed."
}

# Show full systemd status for every canonical service and timer.
show_status() {
  require_root_for_systemd
  log "Service status"
  systemctl --no-pager --full status "${SERVICE_NAMES[@]}" "$MAINTENANCE_TIMER_NAME" || true
}

# Show the concise overview followed by database table counts.
compact_status() {
  control_overview
  db_info
}

# Let the operator select and view bounded recent systemd logs.
show_logs() {
  require_root_for_systemd
  local service
  cat <<EOF
Choose logs:
1) Dashboard
2) Fetch worker
3) Verify worker
4) Card worker
5) Preview worker
6) Deep Discovery
7) Bot
8) Maintenance
9) All recent Arachne units
EOF
  read -r -p "Choose: " choice
  case "$choice" in
    1) service="arachne-dashboard.service" ;;
    2) service="arachne-fetch-worker.service" ;;
    3) service="arachne-verify-worker.service" ;;
    4) service="arachne-card-worker.service" ;;
    5) service="arachne-preview-worker.service" ;;
    6) service="arachne-deep-discovery-worker.service" ;;
    7) service="arachne-bot.service" ;;
    8) service="$MAINTENANCE_SERVICE_NAME" ;;
    9)
      journalctl --no-pager -n 120 \
        -u arachne-dashboard.service -u arachne-fetch-worker.service \
        -u arachne-verify-worker.service -u arachne-card-worker.service \
        -u arachne-deep-discovery-worker.service \
        -u arachne-preview-worker.service -u arachne-bot.service \
        -u "$MAINTENANCE_SERVICE_NAME"
      return 0
      ;;
    *) warn "Unknown choice."; return 1 ;;
  esac
  journalctl -u "$service" --no-pager -n "${LOG_LINES:-120}"
}

# Build a sanitized, bounded diagnostic archive for support review.
build_diagnostic_bundle() {
  require_project
  ensure_venv
  local hours="${DIAGNOSTIC_HOURS:-24}"
  if [[ ! "$hours" =~ ^[0-9]+$ ]] || (( hours < 1 || hours > 168 )); then
    die "DIAGNOSTIC_HOURS must be a whole number from 1 to 168."
  fi
  log "Building sanitized operational diagnostic bundle (${hours}h)"
  "$(python_bin)" operational_observability.py \
    --daily-summary --maintain --diagnostic-bundle --hours "$hours"
  ok "Sanitized bundle saved under logs/operations/diagnostics/."
  printf 'It excludes raw URLs, page content, credentials, cookies, sessions, databases, and personal identifiers.\n'
}

# Run the bounded read-only public-alias quality audit.
alias_quality_audit() {
  require_project
  ensure_venv
  local limit="${ALIAS_AUDIT_LIMIT:-5000}"
  if [[ ! "$limit" =~ ^[0-9]+$ ]] || (( limit < 1 || limit > 50000 )); then
    die "ALIAS_AUDIT_LIMIT must be a whole number from 1 to 50000."
  fi
  log "Running read-only public-alias quality audit"
  "$(python_bin)" actor_intelligence.py --audit-quality --batch-size "$limit"
  ok "Alias audit complete. No cleanup or analyst decision was applied."
}

# Present the database and maintenance submenu until the operator returns.
data_menu() {
  while true; do
    banner
    printf '\n%sData / maintenance%s\n' "$BOLD" "$RESET"
    hr
    cat <<EOF
1) Backup database
2) Wipe database (confirmation required)
3) Refresh Site Card rollups
4) DB info
5) DB doctor
6) Repair DB I/O state
7) Read-only alias quality audit
8) Restore database from verified snapshot (confirmation required)
0) Back
EOF
    read -r -p "Choose: " choice
    case "$choice" in
      1) run_menu_action "Database backup" backup_db ;;
      2) run_menu_action "Database reset" wipe_db ;;
      3) run_menu_action "Site Card rollup refresh" refresh_rollups ;;
      4) run_menu_action "Database summary" db_info ;;
      5) run_menu_action "Database doctor" db_doctor ;;
      6) run_menu_action "Database I/O repair" repair_db_io ;;
      7) run_menu_action "Alias quality audit" alias_quality_audit ;;
      8) run_menu_action "Database restore" restore_db ;;
      0) return 0 ;;
      *) warn "Unknown choice." ;;
    esac
    printf '\n'
    pause_screen
  done
}

# Present dashboard access-code and lock controls until the operator returns.
access_menu() {
  while true; do
    banner
    printf '\n%sAccess / network%s\n' "$BOLD" "$RESET"
    hr
    cat <<EOF
1) Configure .env credentials/settings
2) Generate dashboard access code
3) Deploy dashboard onion service
4) Show onion status
5) Repair access-code storage (keeps codes and sessions)
6) Validate configuration and start Telegram bot
0) Back
EOF
    read -r -p "Choose: " choice
    case "$choice" in
      1) run_menu_action "Configuration update" configure_env ;;
      2) run_menu_action "Dashboard code generation" generate_dashboard_code ;;
      3) run_menu_action "Onion deployment" deploy_onion ;;
      4) run_menu_action "Onion status" onion_status ;;
      5) run_menu_action "Access storage repair" repair_access_storage ;;
      6) run_menu_action "Telegram bot start" start_bot_command ;;
      0) return 0 ;;
      *) warn "Unknown choice." ;;
    esac
    printf '\n'
    pause_screen
  done
}

# Present worker lifecycle and maintenance controls until the operator returns.
worker_menu() {
  while true; do
    banner
    printf '\n%sWorkers / logs%s\n' "$BOLD" "$RESET"
    hr
    cat <<EOF
1) Restart services
2) Restart dashboard only
3) Restart crawler pipeline only
4) Restart Telegram bot only
5) Service status
6) Recent logs
7) Pause crawler
8) Resume crawler
9) Build sanitized diagnostic bundle
0) Back
EOF
    read -r -p "Choose: " choice
    case "$choice" in
      1) run_menu_action "Service restart" restart_services ;;
      2) run_menu_action "Dashboard restart" restart_dashboard_only ;;
      3) run_menu_action "Crawler worker restart" restart_worker_services ;;
      4) run_menu_action "Telegram bot restart" restart_bot_service ;;
      5) run_menu_action "Service status" show_status ;;
      6) run_menu_action "Log view" show_logs ;;
      7) run_menu_action "Crawler pause" pause_workers ;;
      8) run_menu_action "Crawler resume" resume_workers ;;
      9) run_menu_action "Sanitized diagnostics" build_diagnostic_bundle ;;
      0) return 0 ;;
      *) warn "Unknown choice." ;;
    esac
    printf '\n'
    pause_screen
  done
}

# Present deployment, manifest, validation, and evidence commands.
deploy_proof_menu() {
  while true; do
    banner
    printf '\n%sDeploy / proof%s\n' "$BOLD" "$RESET"
    hr
    cat <<EOF
1) Build clean verified handoff ZIP
2) Safe update (prove source + restore point + update)
3) Post-upload verification (prove source, update, dashboard code)
4) Strict handoff receipt for clean upload folder
5) Server handoff validation (no proof rewrite; may prepare venv)
6) Verify uploaded source manifest
7) Create restore point only
0) Back
EOF
    read -r -p "Choose: " choice
    case "$choice" in
      1) run_menu_action "Clean verified handoff ZIP" build_clean_release ;;
      2) run_menu_action "Safe update" safe_update ;;
      3) run_menu_action "Post-upload doctor" post_upload_doctor ;;
      4) run_menu_action "Handoff receipt" handoff_check ;;
      5) run_menu_action "Handoff verification" verify_handoff ;;
      6) run_menu_action "Manifest verification" verify_manifest ;;
      7) run_menu_action "Restore point" create_restore_point ;;
      0) return 0 ;;
      *) warn "Unknown choice." ;;
    esac
    printf '\n'
    pause_screen
  done
}

# Stop crawler workers and maintenance while keeping dashboard and bot available.
pause_workers() {
  ensure_venv
  log "Pausing crawler workers"
  "$(python_bin)" onion_worker.py --pause
}

# Start crawler workers and maintenance after an intentional pause.
resume_workers() {
  ensure_venv
  log "Resuming crawler workers"
  "$(python_bin)" onion_worker.py --resume
}

# Display the dashboard onion hostname and relevant Tor/systemd status.
onion_status() {
  log "Dashboard onion status"
  local onion
  onion="$(onion_hostname)"
  if [[ -n "$onion" ]]; then
    ok "Onion hostname:"
    printf 'http://%s/\n' "$onion"
  else
    warn "No dashboard onion hostname found. Run: bash RUN_AFTER_UPLOAD.sh deploy-onion"
  fi
  if [[ -f /etc/tor/torrc.d/arachne-dashboard.conf ]]; then
    printf '\nTor config:\n'
    sed 's/^/  /' /etc/tor/torrc.d/arachne-dashboard.conf
  fi
}

# Create verified snapshots of every existing recognized database.
backup_db() {
  local stamp backup_dir copied failed db
  stamp="$(date -u +%Y%m%d_%H%M%S)"
  backup_dir="${BACKUP_DIR:-$PROJECT_DIR/backups/manual_$stamp}"
  mkdir -p "$backup_dir"
  local existing=()
  for db in "${DB_FILES[@]}" "${AUTH_DB_FILES[@]}"; do
    [[ -f "$db" ]] && existing+=("$db")
  done
  if (( ${#existing[@]} )); then
    backup_space_preflight "$backup_dir" "${existing[@]}" || {
      warn "Database backup aborted before writing because disk-space preflight failed."
      return 1
    }
  fi
  copied=0
  failed=0
  for db in "${DB_FILES[@]}" "${AUTH_DB_FILES[@]}"; do
    if [[ -f "$db" ]]; then
      if sqlite_snapshot "$db" "$backup_dir/$db"; then
        copied=$((copied + 1))
      else
        warn "Verified SQLite snapshot failed for $db. No destructive action is authorized."
        failed=1
      fi
    fi
  done
  if [[ "$failed" -ne 0 ]]; then
    warn "Database backup is incomplete: $backup_dir"
    return 1
  fi
  if [[ "$copied" -eq 0 ]]; then
    warn "No known DB files found to back up."
  else
    ok "DB backup written to: $backup_dir"
    prune_backup_artifacts manual
  fi
}

# Capture a pre-update database, configuration, and control-script restore point.
create_restore_point() {
  local stamp restore_dir copied db
  stamp="$(date -u +%Y%m%d_%H%M%S)"
  restore_dir="${RESTORE_DIR:-$PROJECT_DIR/backups/restore_$stamp}"
  mkdir -p "$restore_dir"
  copied=0
  log "Creating restore point"
  local existing=()
  for db in "${DB_FILES[@]}" "${AUTH_DB_FILES[@]}"; do
    [[ -f "$db" ]] && existing+=("$db")
  done
  if (( ${#existing[@]} )); then
    backup_space_preflight "$restore_dir" "${existing[@]}" || {
      warn "Restore point aborted before writing because disk-space preflight failed."
      return 1
    }
  fi
  for db in "${DB_FILES[@]}" "${AUTH_DB_FILES[@]}"; do
    if [[ -f "$db" ]]; then
      sqlite_snapshot "$db" "$restore_dir/$db"
      copied=$((copied + 1))
    fi
  done
  for file in .env RUN_AFTER_UPLOAD.sh HANDOFF_RECEIPT.txt SOURCE_MANIFEST.json; do
    [[ -f "$file" ]] && cp -a "$file" "$restore_dir/$file"
  done
  cat > "$restore_dir/RESTORE_README.txt" <<EOF
Arachne restore point
Created UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Project: $PROJECT_DIR

This folder contains pre-update DB/config/control snapshots.
To restore manually: stop Arachne services, copy the needed files back into
$PROJECT_DIR, then restart services.
EOF
  ok "Restore point written to: $restore_dir"
  prune_backup_artifacts restore
  printf '%s\n' "$restore_dir"
}

# Validate and atomically restore one selected database with rollback protection.
restore_db() {
  require_project
  require_root_for_systemd
  ensure_venv
  local kind="${1:-${RESTORE_DB_KIND:-}}" candidate="${2:-${RESTORE_DB_SOURCE:-}}"
  local target confirmation restore_output rollback_path validation_ok=0

  if [[ -z "$kind" ]]; then
    printf 'Restore which database?\n'
    printf '1) Main crawler/analyst database (messages.db)\n'
    printf '2) Dashboard access-code/session database (runtime/dashboard_access.db)\n'
    read -r -p "Choose: " choice
    case "$choice" in
      1) kind="main" ;;
      2) kind="access" ;;
      *) die "Database restore cancelled." ;;
    esac
  fi
  case "$kind" in
    main) target="$PROJECT_DIR/messages.db" ;;
    access) target="$PROJECT_DIR/runtime/dashboard_access.db" ;;
    *) die "RESTORE_DB_KIND must be main or access." ;;
  esac
  if [[ -z "$candidate" ]]; then
    read -r -p "Verified SQLite backup file: " candidate
  fi
  [[ -n "$candidate" ]] || die "Database restore cancelled: no backup file was selected."
  [[ -f "$candidate" ]] || die "Database restore candidate does not exist: $candidate"
  [[ -f "$target" ]] || die \
    "Live database is missing: $target. Use fresh-install to initialize an empty database."

  printf '\nCandidate: %s\n' "$candidate"
  printf 'Target:    %s\n' "$target"
  printf 'Every dashboard, bot, worker, and maintenance SQLite user will stop briefly.\n'
  printf 'The current target is preserved as a verified rollback snapshot first.\n'
  if [[ "${CONFIRM_RESTORE_DB:-}" != "RESTORE ARACHNE DB" ]]; then
    printf 'Type exactly: RESTORE ARACHNE DB\n'
    read -r confirmation
    [[ "$confirmation" == "RESTORE ARACHNE DB" ]] || die "Database restore cancelled."
  fi

  local previously_active=() service timer_was_active=0
  for service in "${SERVICE_NAMES[@]}"; do
    systemctl is-active --quiet "$service" && previously_active+=("$service")
  done
  systemctl is-active --quiet "$MAINTENANCE_TIMER_NAME" && timer_was_active=1
  stop_services_checked "$MAINTENANCE_TIMER_NAME" "$MAINTENANCE_SERVICE_NAME" \
    "${SERVICE_NAMES[@]}" || die \
    "Database restore cancelled because a SQLite user is still running."
  trap 'restore_active_service_snapshot "$timer_was_active" "${previously_active[@]}" || true' ERR

  if ! restore_output="$("$(python_bin)" scripts/restore_sqlite.py \
      --candidate "$candidate" \
      --target "$target" \
      --schema "$kind" \
      --rollback-root "$PROJECT_DIR/backups")"; then
    restore_active_service_snapshot "$timer_was_active" "${previously_active[@]}" || true
    trap - ERR
    die "Database restore validation/publish failed. The live database was not replaced."
  fi
  printf '%s\n' "$restore_output"
  if ! rollback_path="$(RESTORE_RESULT="$restore_output" "$(python_bin)" - <<'PY'
import json
import os

print(json.loads(os.environ["RESTORE_RESULT"]).get("rollback_path") or "")
PY
  )"; then
    trap - ERR
    die "Restore result could not be verified. Services remain stopped; preserve the rollback directory and inspect it."
  fi
  if [[ -z "$rollback_path" || ! -f "$rollback_path" ]]; then
    trap - ERR
    die "Restore published without a usable rollback snapshot. Services remain stopped; preserve all database files."
  fi

  if [[ "$kind" == "main" ]]; then
    if main_db_ready && consistency_checks; then
      validation_ok=1
    fi
  elif "$(python_bin)" - <<'PY'
import dashboard_auth

status = dashboard_auth.dashboard_access_status()
if status.get("storage_error"):
    raise SystemExit(status["storage_error"])
print("dashboard access database validation: ok")
PY
  then
    validation_ok=1
  fi

  if [[ "$validation_ok" != "1" ]]; then
    warn "Post-restore application validation failed. Restoring the preserved pre-restore database."
    if ! "$(python_bin)" scripts/restore_sqlite.py \
        --candidate "$rollback_path" \
        --target "$target" \
        --schema "$kind" \
        --rollback-root "$PROJECT_DIR/backups" \
        --no-rollback-snapshot; then
      trap - ERR
      die "Automatic database rollback failed. Services remain stopped; preserve all files and inspect db-doctor output."
    fi
    prepare_runtime_storage
    restore_active_service_snapshot "$timer_was_active" "${previously_active[@]}" || true
    trap - ERR
    die "Candidate database was rejected after publish; the previous database was restored."
  fi

  prepare_runtime_storage
  restore_active_service_snapshot "$timer_was_active" "${previously_active[@]}" \
    || die "Database restore passed, but one previously active service did not recover."
  trap - ERR
  prune_backup_artifacts rollback
  ok "Database restore completed and the pre-restore rollback snapshot was retained."
}

# Perform an explicitly confirmed zero-state database reset with a prior backup.
wipe_db() {
  require_root_for_systemd
  ensure_venv
  log "Optional database wipe"
  local reset_access="${WIPE_ACCESS_DB:-0}"
  local wipe_targets=("${DB_FILES[@]}")
  if [[ "$reset_access" == "1" ]]; then
    wipe_targets+=("${AUTH_DB_FILES[@]}")
    printf 'This removes crawler results and dashboard access SQLite state in: %s\n' "$PROJECT_DIR"
    printf 'It does NOT remove code, .env, systemd units, backups, or Telegram session files.\n'
  else
    printf 'This removes local crawler SQLite DB files in: %s\n' "$PROJECT_DIR"
    printf 'It does NOT remove code, .env, systemd units, backups, or runtime/dashboard_access.db.\n'
  fi
  printf 'All DB users, including the bot, stop briefly so SQLite cannot keep a deleted file open.\n'
  printf 'Services that were running are started again after the fresh DB is initialized.\n'
  printf 'A backup is created first unless WIPE_DB_BACKUP=0.\n\n'

  if [[ "${CONFIRM_WIPE_DB:-}" != "WIPE ARACHNE DB" ]]; then
    printf 'Type exactly: WIPE ARACHNE DB\n'
    read -r confirmation
    [[ "$confirmation" == "WIPE ARACHNE DB" ]] || die "DB wipe cancelled."
  fi

  local previously_active=() service timer_was_active=0
  for service in "${SERVICE_NAMES[@]}"; do
    systemctl is-active --quiet "$service" && previously_active+=("$service")
  done
  systemctl is-active --quiet "$MAINTENANCE_TIMER_NAME" && timer_was_active=1
  stop_services_checked "$MAINTENANCE_TIMER_NAME" "$MAINTENANCE_SERVICE_NAME" \
    "${SERVICE_NAMES[@]}" || die "Could not stop every SQLite user; DB wipe cancelled."
  trap 'restore_active_service_snapshot "$timer_was_active" "${previously_active[@]}" || true' ERR

  if [[ "${WIPE_DB_BACKUP:-1}" != "0" ]]; then
    if ! backup_db; then
      restore_active_service_snapshot "$timer_was_active" "${previously_active[@]}" || true
      trap - ERR
      die "Crawler DB reset cancelled because the requested verified backup failed. Nothing was deleted. Use Fresh/First Install only when crawler data is intentionally disposable."
    fi
  else
    warn "Crawler DB backup intentionally skipped for this confirmed Fresh/First Install."
  fi

  local removed=0
  for db in "${wipe_targets[@]}"; do
    for path in "$db" "$db-wal" "$db-shm" "$db-journal"; do
      if [[ -e "$path" ]]; then
        rm -f -- "$path"
        removed=$((removed + 1))
      fi
    done
  done
  ok "Removed $removed selected SQLite file(s)."
  prepare_runtime_storage
  "$(python_bin)" - <<'PY'
import storage
storage.init_db()
print("fresh database initialized")
PY
  if [[ "${KEEP_SERVICES_STOPPED_AFTER_WIPE:-0}" == "1" ]]; then
    warn "Crawler DB reset is complete; services remain stopped for the immediately following install/update."
  else
    restore_active_service_snapshot "$timer_was_active" "${previously_active[@]}" \
      || die "Fresh DB was initialized, but one previously active service did not recover."
  fi
  trap - ERR
}

# Insert or replace one private environment key without exposing its value.
set_env_key() {
  local key="$1"
  local value="$2"
  ENV_KEY="$key" ENV_VALUE="$value" "$(python_bin)" - <<'PY'
import os
from pathlib import Path
from scripts.private_env import read_private_env, write_private_env

path = Path(".env")
key = os.environ["ENV_KEY"]
value = os.environ["ENV_VALUE"]
lines = read_private_env(path).splitlines()
out = []
seen = False
for line in lines:
    stripped = line.strip()
    if stripped and not stripped.startswith("#") and "=" in line:
        current = line.split("=", 1)[0].strip()
        if current == key:
            if not seen:
                out.append(f"{key}={value}")
            seen = True
            continue
    out.append(line)
if not seen:
    out.append(f"{key}={value}")
write_private_env("\n".join(out).rstrip() + "\n", path)
PY
}

# Interactively collect bounded server settings and write the private environment.
configure_env() {
  require_root_for_systemd
  ensure_venv
  log "Configure .env credentials/settings"
  ensure_bootstrap_env
  if [[ -s ".env" ]]; then
    local config_backup_dir
    config_backup_dir="$PROJECT_DIR/backups/config_$(date -u +%Y%m%d_%H%M%S)"
    install -d -m 0700 -o root -g root "$config_backup_dir"
    cp -- ".env" "$config_backup_dir/.env"
    chown root:root -- "$config_backup_dir/.env"
    chmod 0600 -- "$config_backup_dir/.env"
    ok "Existing configuration backed up privately before editing."
    prune_backup_artifacts config
  fi
  printf 'Leave a field blank to keep the current value.\n'

  local api_id api_hash bot_token admin_ids lock_enabled alerts_enabled manual_pull
  read -r -p "Telegram API ID: " api_id
  read -r -s -p "Telegram API hash: " api_hash; printf '\n'
  read -r -s -p "Telegram bot token: " bot_token; printf '\n'
  read -r -p "Telegram admin IDs / chat IDs (comma-separated): " admin_ids
  read -r -p "Dashboard access lock enabled? true/false (blank keeps current): " lock_enabled
  read -r -p "Telegram automatic alerts enabled? true/false (blank keeps current): " alerts_enabled
  read -r -p "Telegram manual-pull-only mode? true/false (blank keeps current): " manual_pull

  local setting
  for setting in "$lock_enabled" "$alerts_enabled" "$manual_pull"; do
    if [[ -n "$setting" && ! "${setting,,}" =~ ^(true|false|1|0|yes|no|on|off)$ ]]; then
      die "Boolean settings must be true/false (or 1/0, yes/no, on/off). No configuration was changed."
    fi
  done

  [[ -n "$api_id" ]] && set_env_key TELEGRAM_API_ID "$api_id"
  [[ -n "$api_hash" ]] && set_env_key TELEGRAM_API_HASH "$api_hash"
  [[ -n "$bot_token" ]] && set_env_key TELEGRAM_BOT_TOKEN "$bot_token"
  [[ -n "$admin_ids" ]] && {
    set_env_key TELEGRAM_ADMIN_IDS "$admin_ids"
    set_env_key ADMIN_CHAT_ID "${admin_ids%%,*}"
  }
  [[ -n "$lock_enabled" ]] && set_env_key DASHBOARD_LOCK_ENABLED "$lock_enabled"
  [[ -n "$alerts_enabled" ]] && set_env_key TELEGRAM_AUTO_ALERTS_ENABLED "$alerts_enabled"
  [[ -n "$manual_pull" ]] && set_env_key TELEGRAM_MANUAL_PULL_ONLY "$manual_pull"
  chown root:root -- "$PROJECT_DIR/.env"
  chmod 0600 -- "$PROJECT_DIR/.env"
  ok ".env updated. Secret values were not printed."
}

# Configure and validate the Tor hidden service for the local dashboard.
deploy_onion() {
  require_root_for_systemd
  ensure_venv
  prepare_runtime_storage
  log "Deploying dashboard as a Tor onion service"
  printf 'This publishes the dashboard through a local Tor onion service.\n'
  printf 'The dashboard access lock will be enabled automatically.\n\n'

  if ! command -v tor >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      log "Installing Tor"
      apt-get update
      apt-get install -y tor
    else
      die "tor is not installed and apt-get is unavailable. Install Tor, then rerun."
    fi
  fi

  systemctl cat arachne-dashboard.service >/dev/null 2>&1 \
    || die "Dashboard service is not installed. Run option 1 first, then deploy the onion service."

  set_env_key DASHBOARD_LOCK_ENABLED "true"
  set_env_key DASHBOARD_ACCESS_LOCK_ENABLED "true"
  set_env_key DASHBOARD_BIND_ADDRESS "127.0.0.1"

  local conf_dir conf_file torrc service hostname_file onion_host tor_user
  conf_dir="/etc/tor/torrc.d"
  conf_file="$conf_dir/arachne-dashboard.conf"
  torrc="/etc/tor/torrc"
  hostname_file="/var/lib/tor/arachne-dashboard/hostname"

  mkdir -p "$conf_dir"
  touch "$torrc"
  if ! grep -Eq '^[[:space:]]*%include[[:space:]]+/etc/tor/torrc\.d/\*\.conf' "$torrc"; then
    printf '\n%%include /etc/tor/torrc.d/*.conf\n' >> "$torrc"
  fi

  cat > "$conf_file" <<'EOF'
# Arachne dashboard onion service.
# Local-only backend: the onion maps to Streamlit on 127.0.0.1:8501.
HiddenServiceDir /var/lib/tor/arachne-dashboard/
HiddenServicePort 80 127.0.0.1:8501
EOF
  chmod 0644 "$conf_file"

  tor_user="debian-tor"
  if id tor >/dev/null 2>&1; then
    tor_user="tor"
  fi
  mkdir -p /var/lib/tor/arachne-dashboard
  chown -R "$tor_user:$tor_user" /var/lib/tor/arachne-dashboard 2>/dev/null || true
  chmod 0700 /var/lib/tor/arachne-dashboard

  tor --verify-config -f "$torrc" >/dev/null \
    || die "Tor configuration validation failed; Tor was not restarted."
  systemctl restart tor.service 2>/dev/null || systemctl restart tor@default.service
  systemctl restart arachne-dashboard.service
  wait_service_stable arachne-dashboard.service \
    || die "Dashboard did not remain active after switching to the local-only onion binding."

  for _ in $(seq 1 20); do
    [[ -s "$hostname_file" ]] && break
    sleep 1
  done

  if [[ -s "$hostname_file" ]]; then
    onion_host="$(tr -d '[:space:]' < "$hostname_file")"
    set_env_key DASHBOARD_URL "http://$onion_host"
    if systemctl is-active --quiet "$BOT_SERVICE_NAME"; then
      restart_bot_service
    else
      warn "Telegram bot is offline. The onion URL was saved and will load when the bot starts."
    fi
    ok "Dashboard onion service is ready:"
    printf 'http://%s/\n' "$onion_host"
    printf '\nUse the dashboard access-code lock before opening it from another browser.\n'
  else
    die "Tor did not create the hostname. Check: journalctl -u tor --no-pager -n 80"
  fi
}

# Run compilation, tests, consistency, and OPSEC checks as one launch gate.
validate() {
  require_project
  ensure_venv
  compile_check
  deploy_smoke_checks
  consistency_checks
  opsec_audit
}

# Generate a strict redacted direct-folder handoff receipt.
handoff_check() {
  require_project
  ensure_venv
  log "Creating handoff receipt"
  "$(python_bin)" scripts/handoff_receipt.py
}

# Verify source and handoff evidence before a server-side update.
verify_handoff() {
  require_project
  ensure_venv
  log "Verifying server handoff readiness"
  "$(python_bin)" scripts/handoff_receipt.py --check --allow-runtime --no-write
  compile_check
  deploy_smoke_checks
}

# Regenerate the authoritative source manifest through the handoff helper.
handoff_manifest() {
  require_project
  ensure_venv
  log "Writing source manifest"
  "$(python_bin)" scripts/handoff_receipt.py --manifest
}

# Verify that the live selected source exactly matches its committed manifest.
verify_manifest() {
  require_project
  command -v python3 >/dev/null 2>&1 || die "python3 is required to verify the uploaded source."
  log "Verifying uploaded source against its authoritative manifest"
  python3 scripts/make_clean_release.py --verify-source
}

# Quarantine stale selected source files left by a direct-folder upload.
reconcile_uploaded_source() {
  require_project
  command -v python3 >/dev/null 2>&1 || die "python3 is required to reconcile the uploaded source."
  log "Reconciling stale source left by direct folder upload"
  python3 scripts/make_clean_release.py --reconcile-source
}

# Prove the uploaded source and handoff state before any update mutation.
validated_update_preflight() {
  if [[ "$SOURCE_PREFLIGHT_COMPLETE" == "1" ]]; then
    ok "Uploaded source proof and deploy checks already passed in this control run."
    return 0
  fi
  # Direct folder uploads overwrite current files but cannot remove source
  # files retired by a newer release.  Reconciliation first proves every
  # expected file and hash, then quarantines only stale release-selected files.
  # Runtime data, configuration, databases, sessions, and logs are excluded.
  reconcile_uploaded_source
  # Exact proof still runs after reconciliation and before any dependency,
  # bytecode, service, database, or test mutation.
  verify_manifest
  verify_handoff
  prune_backup_artifacts stale-source
  SOURCE_PREFLIGHT_COMPLETE=1
}

# Build and verify a deterministic source-only ZIP outside the source tree.
build_clean_release() {
  require_project
  command -v python3 >/dev/null 2>&1 || die "python3 is required to build a clean handoff ZIP."
  local parent output timestamp
  parent="$(dirname "$PROJECT_DIR")"
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  output="${RELEASE_OUTPUT:-$parent/arachne-clean-release-${timestamp}-$$.zip}"
  output="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).expanduser().resolve())' "$output")"
  [[ "$output" != "$PROJECT_DIR"/* ]] || die "RELEASE_OUTPUT must be outside the live source folder."
  log "Building source-only handoff ZIP"
  python3 scripts/make_clean_release.py "$output"
  python3 scripts/make_clean_release.py --verify-archive "$output"
  chmod 0600 "$output"
  ok "Clean verified handoff ZIP: $output"
  printf 'Upload this ZIP contents. Do not upload the live project folder with .env, databases, sessions, logs, or backups.\n'
}

# Verify an upload, recover required services, and print operator next steps.
post_upload_doctor() {
  require_project
  require_root_for_systemd
  log "Post-upload doctor"
  validated_update_preflight
  trap 'recover_runtime_services_after_failure' ERR
  log "Stopping SQLite writers for a consistent pre-update restore point"
  stop_all_services
  create_restore_point >/dev/null
  install_or_update
  trap 'recover_runtime_services_after_failure' ERR
  prepare_runtime_storage
  "$(python_bin)" - <<'PY'
import dashboard_auth
dashboard_auth.set_dashboard_lock_enabled(True, "post_upload_doctor")
result = dashboard_auth.generate_dashboard_code(15 * 60, "post_upload_doctor")
if not result.get("code"):
    raise SystemExit(result.get("error") or result.get("reason") or "code generation failed")
print("")
print("Doctor dashboard test code:")
print(result["code"])
print("expires:", result["expires_at"])
PY
  systemctl is-active --quiet arachne-dashboard.service || systemctl restart arachne-dashboard.service
  wait_service_stable arachne-dashboard.service || die "Dashboard service is not stable after doctor."
  trap - ERR
  ok "Post-upload doctor completed."
}

# Return success when databases or canonical units indicate an existing deployment.
bootstrap_has_existing_state() {
  local path service
  for path in "${DB_FILES[@]}" "${AUTH_DB_FILES[@]}"; do
    [[ -e "$path" ]] && return 0
  done
  if command -v systemctl >/dev/null 2>&1; then
    for service in "${SERVICE_NAMES[@]}" "$MAINTENANCE_TIMER_NAME"; do
      systemctl cat "$service" >/dev/null 2>&1 && return 0
    done
  fi
  return 1
}

# Create or secure the private environment file while preserving existing values.
ensure_bootstrap_env() {
  [[ -L ".env" ]] && die ".env must be a private regular file, not a symbolic link."
  if [[ ! -e ".env" ]]; then
    [[ -f ".env.example" ]] || die ".env.example is missing; source release is incomplete."
    install -m 0600 -- ".env.example" ".env"
    ok "Created private .env with safe defaults; optional Telegram credentials remain blank."
  elif [[ ! -f ".env" ]]; then
    die ".env exists but is not a regular file."
  else
    ok "Preserving the existing private .env values."
  fi
  chown root:root -- "$PROJECT_DIR/.env"
  chmod 0600 -- "$PROJECT_DIR/.env"
}

# Install a true zero-state deployment without invoking a destructive reset path.
bootstrap_first_install() {
  log "First installation detected"
  printf 'No existing Arachne database or canonical service unit was found.\n'
  printf 'The normal initialization path will be used; no reset or wipe command will run.\n'
  trap 'recover_runtime_services_after_failure' ERR
  install_or_update
  trap 'recover_runtime_services_after_failure' ERR
  "$(python_bin)" scripts/handoff_receipt.py --allow-runtime >/dev/null
  trap - ERR
  issue_dashboard_code "1h" "bootstrap_first_install"
}

# Print concise post-bootstrap access and next-step information.
bootstrap_summary() {
  local onion
  onion="$(onion_hostname)"
  log "Bootstrap summary"
  if [[ -n "$onion" ]]; then
    printf 'Dashboard: http://%s/\n' "$onion"
  else
    printf 'Dashboard: port 8501 on this server (run deploy-onion for a private onion URL)\n'
  fi
  if telegram_config_ready; then
    printf 'Telegram:  configured; bot service is eligible to run\n'
  else
    printf 'Telegram:  not configured; bot service is stopped and disabled\n'
  fi
  printf 'Status:    bash RUN_AFTER_UPLOAD.sh status\n'
  printf 'Doctor:    bash RUN_AFTER_UPLOAD.sh doctor\n'
  printf 'Logs:      bash RUN_AFTER_UPLOAD.sh logs\n'
}

# Bootstrap a new host or safely update detected existing state with one command.
bootstrap() {
  require_project
  require_root_for_systemd
  local existing=0 answer=""
  if bootstrap_has_existing_state; then
    existing=1
  fi

  require_python_312 >/dev/null
  ensure_bootstrap_env
  validated_update_preflight

  if ! telegram_config_ready; then
    if [[ -t 0 ]]; then
      read -r -p "Configure optional Telegram integration now? [y/N]: " answer || answer=""
      case "${answer,,}" in
        y|yes) configure_env ;;
        *) warn "Telegram configuration skipped; only its bot service will remain disabled." ;;
      esac
    else
      warn "Non-interactive bootstrap: optional Telegram configuration was skipped."
    fi
  fi

  if [[ "$existing" -eq 1 ]]; then
    log "Existing deployment state detected; using the restore-point-protected update path"
    safe_update
  else
    bootstrap_first_install
  fi
  bootstrap_summary
  ok "Bootstrap completed."
}

# Create a restore point and perform the complete manifest-proven update path.
safe_update() {
  require_project
  require_root_for_systemd
  log "Safe update"
  validated_update_preflight
  trap 'recover_runtime_services_after_failure' ERR
  log "Stopping SQLite writers for a consistent pre-update restore point"
  stop_all_services
  create_restore_point >/dev/null
  install_or_update
  trap 'recover_runtime_services_after_failure' ERR
  "$(python_bin)" scripts/handoff_receipt.py --allow-runtime >/dev/null
  trap - ERR
  ok "Safe update complete. Latest receipt: $PROJECT_DIR/HANDOFF_RECEIPT.txt"
}

# Install dependencies, storage, units, checks, and services without wiping data.
install_or_update() {
  trap 'recover_runtime_services_after_failure' ERR
  log "Arachne install/update"
  printf 'Project: %s\n' "$PROJECT_DIR"
  require_project
  require_root_for_systemd
  ensure_venv
  [[ -f ".env" ]] || die ".env is missing. Run: bash RUN_AFTER_UPLOAD.sh configure-env, then rerun install."
  # Telegram is optional. Normalize complete credentials, but leave its unit
  # disabled when any required Telegram setting is absent.
  if telegram_config_ready; then
    repair_telegram_env
  else
    warn "Telegram credentials are incomplete; installing without the optional bot service."
  fi
  ensure_tor_runtime
  # Prevent a scheduled global maintenance job from starting halfway through
  # migrations/rollups. Recovery or the healthy restart re-enables the timer.
  systemctl stop "$MAINTENANCE_TIMER_NAME" "$MAINTENANCE_SERVICE_NAME" 2>/dev/null || true
  install_services
  compile_check
  deploy_smoke_checks
  opsec_audit
  log "Stopping SQLite writers for the bounded database update phase"
  stop_all_services
  prepare_runtime_storage
  if ! consistency_checks; then
    warn "Crawler DB checks failed. Stopping pipeline workers and maintenance to avoid crash loops."
    systemctl stop "$MAINTENANCE_TIMER_NAME" "$MAINTENANCE_SERVICE_NAME" \
      "${WORKER_SERVICE_NAMES[@]}" >/dev/null 2>&1 || true
    restart_dashboard_only
    restart_bot_if_configured
    show_status
    warn "Install/update completed code setup, but crawler DB is unhealthy so workers were not restarted."
    warn "Fix DB with db-doctor or wipe-db, then run install/update again."
    trap - ERR
    return 2
  fi
  if ! queue_dirty_rollups; then
    warn "Changed-card job queueing failed after services were stopped. Restarting services before exiting."
    restart_services || true
    die "Install/update aborted while queueing changed Site Cards. Services were restarted."
  fi
  restart_services
  show_status
  trap - ERR
  ok "Install/update complete."
}

# Offer guarded repair/reset choices after a failed normal installation.
recovery_menu() {
  while true; do
    cat <<EOF

${BOLD}Recovery / reset${RESET}
  1) Repair private runtime/access storage
     Fixes ownership and modes without deleting DBs, codes, credentials, or Telegram sessions.

  2) Diagnose all databases
     Shows disk, permissions, main DB checks, and access DB checks without deleting anything.

  3) Repair crawler DB I/O state
     Stops DB users briefly, backs up DBs, clears stale sidecars, and preserves stored data.

  4) Reset crawler database, then install/update
     Requires exact confirmation. Resets dashboard codes/sessions; keeps .env, Telegram sessions, and backups.

  0) Back
EOF
    read -r -p "Choose: " choice
    case "$choice" in
      1) run_menu_action "Runtime storage repair" repair_access_storage ;;
      2) run_menu_action "Database doctor" db_doctor ;;
      3) run_menu_action "Database I/O repair" repair_db_io ;;
      4)
        run_menu_action "Crawler database reset/install" fresh_first_install
        return 0
        ;;
      0) return 0 ;;
      *) warn "Unknown choice." ;;
    esac
    printf '\n'
    pause_screen
  done
}

# Run the standard non-destructive install/update path.
quick_update() {
  (
    export SKIP_TESTS=1
    safe_update
  )
}

# Enable the dashboard lock and issue an initial code after a fresh reset.
enable_dashboard_lock_after_fresh_reset() {
  log "Enabling the dashboard access page for the fresh installation"
  "$(python_bin)" - <<'PY'
import dashboard_auth

dashboard_auth.set_dashboard_lock_enabled(True, "fresh_first_install")
status = dashboard_auth.dashboard_access_status()
if status.get("storage_error") or not status.get("enabled"):
    raise SystemExit("Fresh installation aborted: dashboard access lock was not persisted.")
print("Dashboard access lock: enabled")
PY
}

# Perform a confirmed fresh database reset followed by installation.
install_or_update_with_wipe() {
  validated_update_preflight
  KEEP_SERVICES_STOPPED_AFTER_WIPE=1 wipe_db
  if [[ "${ENABLE_DASHBOARD_LOCK_AFTER_WIPE:-0}" == "1" ]]; then
    enable_dashboard_lock_after_fresh_reset
  fi
  install_or_update
}

# Repair DB I/O state and then retry the standard installation.
install_or_update_with_repair() {
  validated_update_preflight
  repair_db_io
  install_or_update
}

# Run the first-install workflow with explicit zero-state confirmation.
fresh_first_install() {
  log "Fresh/First Install: reset crawler data + install"
  printf 'This intentionally starts Arachne crawler results and access-code state from zero, then runs install/update.\n'
  printf 'The disposable SQLite state is NOT backed up on this explicit path.\n'
  printf 'It keeps code, .env, backups, Telegram credentials, and Telegram session files.\n\n'
  require_project
  require_root_for_systemd
  validated_update_preflight
  [[ -f ".env" ]] || die ".env is missing. Run: bash RUN_AFTER_UPLOAD.sh configure-env"
  ensure_tor_runtime
  ENABLE_DASHBOARD_LOCK_AFTER_WIPE=1 WIPE_ACCESS_DB=1 WIPE_DB_BACKUP=0 \
    install_or_update_with_wipe
}

# Print all supported commands and bounded environment flags.
print_usage() {
  cat <<'EOF'
Usage:
  bash RUN_AFTER_UPLOAD.sh [command]

Commands:
  menu                  Interactive control menu. Default if no command is given.
  bootstrap             First install or detected safe update with one guided command.
  doctor                Read-only prerequisites/source/database/service diagnostics.
  install, update       Prove uploaded source, create restore point, then install/update.
  install-wipe          Wipe crawler DB first, then install/update.
  install-repair        Repair DB I/O first, then install/update.
  fresh-install         Reset crawler and dashboard-access DBs; preserve Telegram config/sessions, then update.
  quick                 Install/update but skip pytest.
  full-tests            Run the complete pytest suite explicitly.
  configure-env         Add/update Telegram/dashboard .env settings.
  backup-db             Copy known SQLite DB files to backups/manual_TIMESTAMP.
  restore-db            Validate and restore one main/access SQLite snapshot.
  wipe-db               Optional DB wipe with exact confirmation and pre-backup.
  deploy-onion          Create/update a Tor onion service for the dashboard.
  onion-status          Show current dashboard onion address/config.
  dashboard-code        Generate a one-time dashboard access code.
  bot-start             Validate Telegram settings and start the bot.
  handoff-check         Write HANDOFF_RECEIPT.txt and SOURCE_MANIFEST.json.
  verify-handoff        Handoff receipt check plus compile and deploy smoke tests.
  handoff-manifest      Write SOURCE_MANIFEST.json only.
  verify-manifest       Verify the exact uploaded source set and hashes.
  build-release         Build and verify a source-only handoff ZIP outside the project.
  restore-point         Create backups/restore_TIMESTAMP with DB/config/control files.
  post-upload-doctor    Verify upload, safely update, check dashboard, print test code.
  safe-update           Source proof + handoff verify + restore point + install/update.
  retire-previous-services
                        Stop/remove a previous service namespace supplied explicitly.
  validate              Compile, smoke tests, consistency checks, OPSEC audit.
  restart               Restart dashboard/workers and the bot only when configured.
  restart-dashboard     Restart only the dashboard service.
  restart-workers       Restart only the staged crawler workers.
  restart-bot           Validate settings and restart only the Telegram bot.
  status                Show compact service/database/onion status.
  logs                  Show recent service logs.
  diagnostics           Build a sanitized operational diagnostic ZIP (default: last 24h).
  alias-audit           Report identity-candidate quality without changing data.
  db-info               Show safe DB counts/sizes.
  db-doctor             Diagnose SQLite/disk/permission issues.
  repair-db-io          Repair common SQLite I/O state without deleting DB.
  repair-access         Repair private runtime ownership without deleting data or sessions.
  refresh-rollups       Recalculate Site Card rollups.
  pause                 Pause crawler work.
  resume                Resume crawler work.
  help                  Show this help.

Environment flags:
  SKIP_TESTS=1          Skip pytest during install/update.
  SKIP_RESTART=1        Validate/install but do not restart services.
  DIAGNOSTIC_HOURS=24   Diagnostic bundle window (1 to 168 hours).
  ALIAS_AUDIT_LIMIT=5000 Candidate audit row limit (1 to 50000).
  RELEASE_OUTPUT=/path  Optional output path for build-release (must be outside source).
  ARACHNE_PREVIOUS_SERVICE_PREFIX=name  Prior systemd prefix to retire during migration.
  ARACHNE_PREVIOUS_DB_FILE=name.db       Prior compatibility DB included in snapshots/wipes.
  ARACHNE_PREVIOUS_BACKUP_PREFIX=name    Prior daily-backup prefix included in retention.
  CONFIRM_WIPE_DB="WIPE ARACHNE DB"     Non-interactive DB wipe confirmation.
  RESTORE_DB_KIND=main|access             Non-interactive restore target.
  RESTORE_DB_SOURCE=/path/to/snapshot.db  Non-interactive restore candidate.
  CONFIRM_RESTORE_DB="RESTORE ARACHNE DB" Non-interactive restore confirmation.
  ARACHNE_KEEP_MANUAL_BACKUPS=7           Manual database snapshot directories.
  ARACHNE_KEEP_UPDATE_RESTORE_POINTS=3    Pre-update restore-point directories.
  ARACHNE_KEEP_DATABASE_ROLLBACKS=5       Pre-restore rollback directories.
  ARACHNE_KEEP_CONFIG_BACKUPS=5           Private .env backup directories.
  ARACHNE_KEEP_STALE_SOURCE_BACKUPS=3     Reconciled stale-source directories.
EOF
}

# Run the top-level interactive server-control menu loop.
menu() {
  while true; do
    control_overview
    cat <<EOF
${BOLD}Main menu${RESET}
  1) Bootstrap / guided install or update (recommended)
  2) Safe update
  3) Read-only doctor
  4) Quick update (skip tests)
  5) Validate only
  6) Access / network
  7) Data / maintenance
  8) Services / workers / logs
  9) Deploy / proof
 10) Full pytest suite
 11) Recovery / reset

  0) Exit
EOF
    read -r -p "Choose: " choice
    case "$choice" in
      1) run_menu_action "Bootstrap" bootstrap ;;
      2) run_menu_action "Safe update" safe_update ;;
      3) run_menu_action "Read-only doctor" doctor ;;
      4) run_menu_action "Quick update" quick_update ;;
      5) run_menu_action "Validation" validate ;;
      6) access_menu; continue ;;
      7) data_menu; continue ;;
      8) worker_menu; continue ;;
      9) deploy_proof_menu; continue ;;
      10) run_menu_action "Full test suite" run_full_tests ;;
      11) recovery_menu; continue ;;
      0) exit 0 ;;
      *) warn "Unknown choice." ;;
    esac
    printf '\n'
    pause_screen
  done
}

if [[ "${ARACHNE_CONTROL_LIBRARY_ONLY:-0}" == "1" ]]; then
  return 0 2>/dev/null || exit 0
fi

cmd="${1:-menu}"
if [[ "$cmd" != "doctor" ]]; then
  acquire_control_lock
fi
case "$cmd" in
  bootstrap|setup) bootstrap ;;
  install|update) safe_update ;;
  install-wipe|update-wipe|wipe-install) install_or_update_with_wipe ;;
  install-repair|update-repair|repair-install) install_or_update_with_repair ;;
  fresh-install|first-install|fresh) fresh_first_install ;;
  quick) quick_update ;;
  full-tests|test|tests) run_full_tests ;;
  menu) menu ;;
  configure-env|config-env|env) configure_env ;;
  backup-db|backup) backup_db ;;
  restore-db|db-restore) restore_db "${2:-}" "${3:-}" ;;
  wipe-db|reset-db) wipe_db ;;
  deploy-onion|onion|darkweb) deploy_onion ;;
  onion-status) onion_status ;;
  dashboard-code|code) generate_dashboard_code ;;
  bot-start|start-bot|telegram-start) start_bot_command ;;
  handoff-check|receipt) handoff_check ;;
  verify-handoff|handoff-verify) verify_handoff ;;
  handoff-manifest|manifest) handoff_manifest ;;
  verify-manifest|manifest-verify) verify_manifest ;;
  build-release|clean-release|handoff-zip) build_clean_release ;;
  restore-point) create_restore_point ;;
  doctor) doctor ;;
  post-upload-doctor) post_upload_doctor ;;
  safe-update) safe_update ;;
  retire-previous-services) retire_previous_services ;;
  validate|check) validate ;;
  restart) restart_services ;;
  restart-dashboard) restart_dashboard_only ;;
  restart-workers) restart_worker_services ;;
  restart-bot|telegram-restart) restart_bot_service ;;
  status) compact_status ;;
  logs) show_logs ;;
  diagnostics|diagnostic-bundle|support-bundle) build_diagnostic_bundle ;;
  alias-audit|entity-audit|identity-audit) alias_quality_audit ;;
  db-info) db_info ;;
  db-doctor) db_doctor ;;
  repair-db-io|fix-db-io) repair_db_io ;;
  repair-access|fix-access) repair_access_storage ;;
  refresh-rollups|rollups) refresh_rollups ;;
  pause) pause_workers ;;
  resume) resume_workers ;;
  help|-h|--help) print_usage ;;
  *) print_usage; die "Unknown command: $cmd" ;;
esac
