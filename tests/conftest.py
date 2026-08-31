import os
import tempfile
from pathlib import Path

import pytest

# Test modules import the Telegram application during collection, before a
# per-test fixture can monkeypatch paths. Give Telethon disposable,
# process-local session names up front so a clean-release validation never
# creates or opens session databases inside deployable source or live runtime.
_TEST_SESSION_ROOT = Path(tempfile.gettempdir()) / f"arachne-pytest-{os.getpid()}"
os.environ["TELEGRAM_USER_SESSION_NAME"] = str(_TEST_SESSION_ROOT.with_name(
    _TEST_SESSION_ROOT.name + "-user"))
os.environ["TELEGRAM_BOT_SESSION_NAME"] = str(_TEST_SESSION_ROOT.with_name(
    _TEST_SESSION_ROOT.name + "-bot"))

import dashboard_auth
import storage


@pytest.fixture(autouse=True)
def stable_test_runtime(monkeypatch, tmp_path):
    """Keep every test away from the source tree's live DB/auth files by default."""
    monkeypatch.setenv("DASHBOARD_LOCK_ENABLED", "false")
    monkeypatch.setenv("DASHBOARD_ACCESS_LOCK_ENABLED", "false")
    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "ambient-test.db")
    monkeypatch.setattr(dashboard_auth, "AUTH_DB_PATH", tmp_path / "ambient-dashboard-access.db")


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard_auth, "AUTH_DB_PATH", tmp_path / "dashboard_access.db")
    storage.init_db()
    return storage.DB_PATH
