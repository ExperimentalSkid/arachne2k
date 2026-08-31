"""Portable project paths. No module in this project should assume a host path."""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "messages.db"
CONFIG_PATH = BASE_DIR / "config.json"
KEYWORDS_CONFIG_PATH = BASE_DIR / "keywords_config.json"
SCORING_CONFIG_PATH = BASE_DIR / "scoring_config.json"
REPORTS_DIR = BASE_DIR / "reports"
PREVIEWS_DIR = REPORTS_DIR / "previews"
LOGS_DIR = BASE_DIR / "logs"
BACKUPS_DIR = BASE_DIR / "backups"
RUNTIME_DIR = BASE_DIR / "runtime"
SESSIONS_DIR = RUNTIME_DIR / "sessions"


def ensure_runtime_dirs() -> None:
    for path in (REPORTS_DIR, PREVIEWS_DIR, LOGS_DIR, BACKUPS_DIR, SESSIONS_DIR):
        path.mkdir(parents=True, exist_ok=True)
