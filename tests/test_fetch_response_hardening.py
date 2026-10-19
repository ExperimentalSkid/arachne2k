"""Offline checks for passive fetch metadata and error persistence."""

import json

import pytest

import onion_worker
import storage


HOST = "a" * 56 + ".onion"
URL = f"http://{HOST}/"


class _Response:
    status_code = 200

    def __init__(self):
        self.headers = {
            "Content-Type": "text/html",
            "Server": "nginx/1.24.0",
            "X-Powered-By": "PHP/8.2",
            "Set-Cookie": "session=private-cookie",
            "Location": f"http://{HOST}/private?token=private-token",
        }

    def iter_content(self, chunk_size=16384):
        yield b"<html><title>Public note</title><body>Public note</body></html>"

    def close(self):
        pass


class _Session:
    def __init__(self, *, error=None):
        self.error = error

    def get(self, *_args, **_kwargs):
        if self.error:
            raise self.error
        return _Response()

    def close(self):
        pass


def test_staged_fetch_persists_only_bounded_passive_headers(isolated_db, monkeypatch):
    storage.insert_or_update_onion_url(URL, HOST, status="queued")
    monkeypatch.setattr(onion_worker, "_session", lambda: _Session())

    assert onion_worker.fetch_one("fetch-header-test")
    with storage.get_db() as db:
        row = db.execute("SELECT headers_json FROM fetched_pages WHERE url=?", (URL,)).fetchone()
    assert row is not None
    assert json.loads(row["headers_json"]) == {
        "Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2",
    }


def test_passive_header_filter_drops_secret_like_and_oversized_values():
    assert onion_worker._passive_response_headers({
        "Server": "session=private-cookie",
        "X-Powered-By": "X" * 161,
        "Set-Cookie": "private-cookie",
    }) == {}
    assert onion_worker._passive_response_headers({"server": "nginx/1.24.0"}) == {
        "Server": "nginx/1.24.0",
    }


@pytest.mark.parametrize("worker", ["fetch_one", "process_one"])
def test_fetch_error_persists_only_safe_exception_type(isolated_db, monkeypatch, worker):
    storage.insert_or_update_onion_url(URL, HOST, status="queued")
    secret_error = RuntimeError(
        f"request for http://{HOST}/private?token=private-token "
        "through socks5h://user:private-password@127.0.0.1:9050 failed"
    )
    monkeypatch.setattr(onion_worker, "_session", lambda: _Session(error=secret_error))

    assert getattr(onion_worker, worker)("fetch-error-test")
    with storage.get_db() as db:
        row = db.execute("SELECT last_error FROM onion_urls WHERE url=?", (URL,)).fetchone()
    assert row["last_error"] == "RuntimeError"
