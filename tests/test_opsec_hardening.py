import os
import time
from pathlib import Path

import pytest

import artifact_hygiene
import opsec_preflight
import safe_transport
import storage
from log_redaction import redact_for_log


class _Session:
    def __init__(self):
        self.trust_env = True
        self.proxies = {}
        self.headers = {"Personal": "value"}
        self.cookies = _Cookies()


class _Cookies:
    def clear(self):
        self.cleared = True


def test_safe_transport_requires_socks5h_and_ignores_environment(monkeypatch):
    monkeypatch.setattr(safe_transport.requests, "Session", _Session)
    session = safe_transport.create_onion_session(proxy_url="socks5h://127.0.0.1:9050", prepare=False)
    assert session.trust_env is False
    assert session.proxies == {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
    assert "Personal" not in session.headers
    with pytest.raises(RuntimeError):
        safe_transport.create_onion_session(proxy_url="http://127.0.0.1:9050", prepare=False)


def test_direct_fetch_source_scan_passes_for_runtime_sources():
    result = opsec_preflight.scan_direct_fetch_paths()
    assert result == {"pass": True, "findings": []}


def test_direct_fetch_scan_ignores_virtualenv_but_checks_project_source(tmp_path):
    dependency = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages" / "requests"
    dependency.mkdir(parents=True)
    (dependency / "api.py").write_text("import requests\nrequests.get('https://dependency.invalid')\n", encoding="utf-8")
    (tmp_path / "onion_worker.py").write_text(
        "import requests\nrequests.get('http://example.onion')\n", encoding="utf-8")

    result = opsec_preflight.scan_direct_fetch_paths(tmp_path)

    assert result["pass"] is False
    assert len(result["findings"]) == 1
    assert result["findings"][0].startswith("onion_worker.py:")


@pytest.mark.parametrize("source", [
    "import requests as rq\nrq.get('https://example.invalid')\n",
    "from requests import get as fetch\nfetch('https://example.invalid')\n",
    "import requests\ns = requests.Session()\ns.get('https://example.invalid')\n",
    "import urllib.request as net\nnet.urlopen('https://example.invalid')\n",
    "from urllib.request import urlopen as open_url\nopen_url('https://example.invalid')\n",
    "from http.client import HTTPSConnection\nHTTPSConnection('example.invalid')\n",
])
def test_direct_fetch_scan_catches_import_alias_bypasses(tmp_path, source):
    (tmp_path / "crawler.py").write_text(source, encoding="utf-8")

    result = opsec_preflight.scan_direct_fetch_paths(tmp_path)

    assert result["pass"] is False
    assert result["findings"]


def test_ollama_urlopen_exception_requires_parsed_loopback_endpoint(tmp_path):
    classifier = tmp_path / "llm_classifier.py"
    classifier.write_text(
        "import urllib.request\n"
        "LLM_ENDPOINT='https://remote.invalid/api'\n"
        "NOTE='http://localhost:11434 is not actually used'\n"
        "urllib.request.urlopen(LLM_ENDPOINT)\n",
        encoding="utf-8",
    )

    result = opsec_preflight.scan_direct_fetch_paths(tmp_path)

    assert result["pass"] is False
    assert any("urlopen" in finding for finding in result["findings"])


def test_log_redaction_keeps_labels_and_removes_secrets():
    token = "123456789:" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
    value = redact_for_log(
        f"Normal label {token} http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345.onion/path?access_token=secret&view=1"
    )
    assert "Normal label" in value
    assert token not in value
    assert "secret" not in value
    assert "access_token=%5BREDACTED%5D" in value
    assert "..." in value


def test_log_redaction_removes_proxy_userinfo_api_hash_and_plain_onion_host():
    onion = f"{'a' * 56}.onion"
    value = redact_for_log(
        f"api_hash=0123456789abcdef0123456789abcdef "
        f"proxy=socks5h://isolation-user:isolation-pass@127.0.0.1:9050 "
        f"host={onion}"
    )

    assert "0123456789abcdef0123456789abcdef" not in value
    assert "isolation-user" not in value
    assert "isolation-pass" not in value
    assert onion not in value
    assert "[REDACTED]" in value


def test_strict_mode_blocks_critical_failure(monkeypatch):
    monkeypatch.setattr(opsec_preflight, "get_bool", lambda key, default=False: key == "OPSEC_STRICT_MODE")
    monkeypatch.setattr(opsec_preflight, "run_opsec_audit", lambda persist=False: {
        "status": "FAIL", "critical_checks": {"tor_socks_reachable": False, "socks5h_enforced": True}
    })
    with pytest.raises(RuntimeError, match="tor_socks_reachable"):
        opsec_preflight.enforce_strict_mode()


def test_artifact_purge_dry_run_preserves_everything(monkeypatch, tmp_path):
    previews = tmp_path / "reports" / "previews"
    logs = tmp_path / "logs"
    reports = tmp_path / "reports"
    previews.mkdir(parents=True)
    logs.mkdir()
    old_preview = previews / "old.png"
    old_log = logs / "worker.log"
    protected = logs / ".env"
    for path in (old_preview, old_log, protected):
        path.write_text("x", encoding="utf-8")
        os.utime(path, (time.time() - 30 * 86400,) * 2)
    monkeypatch.setattr(artifact_hygiene, "PREVIEWS_DIR", previews)
    monkeypatch.setattr(artifact_hygiene, "LOGS_DIR", logs)
    monkeypatch.setattr(artifact_hygiene, "REPORTS_DIR", reports)
    monkeypatch.setattr(artifact_hygiene, "get_int", lambda key, default: 7)
    monkeypatch.setattr(artifact_hygiene, "get_bool", lambda key, default=False: False)

    preview = artifact_hygiene.purge_runtime_artifacts(dry_run=True)
    assert preview["candidates"] == 2
    assert old_preview.exists() and old_log.exists() and protected.exists()

    result = artifact_hygiene.purge_runtime_artifacts(dry_run=False)
    assert result["removed"] == 2
    assert protected.exists()


def test_storage_schema_has_no_raw_html_or_full_visible_text(isolated_db):
    with storage.get_db() as db:
        columns = {str(row[1]).casefold() for table in (
            "onion_urls", "onion_hits", "site_cards", "classification_decisions"
        ) for row in db.execute(f"PRAGMA table_info({table})")}
    assert "raw_html" not in columns
    assert "full_visible_text" not in columns


def test_opsec_audit_and_artifact_purge_do_not_initialize_crawler_storage_first():
    source = (Path(__file__).resolve().parents[1] / "onion_worker.py").read_text(
        encoding="utf-8")
    main_source = source.split("def main() -> None:", 1)[1]

    init_position = main_source.index("storage.init_db()")
    assert main_source.index("if args.opsec_audit:") < init_position
    assert main_source.index("if args.purge_runtime_artifacts:") < init_position
