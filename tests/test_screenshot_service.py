import sys
import types

import storage
import screenshot_service
from screenshot_service import capture_page_screenshot, has_screenshot, screenshot_path_for_url, screenshot_support_status
from universal_classifier import classify_url_prefetch


def test_screenshots_are_deterministic_and_disabled_by_default(monkeypatch):
    # An explicit process environment value wins over both .env and config.json.
    # This isolates the default-disabled behavior from a deployed server's live .env.
    monkeypatch.setenv("ENABLE_PAGE_SCREENSHOTS", "false")
    from config_loader import get_config
    get_config.cache_clear()
    url = "http://" + "a" * 56 + ".onion/"
    assert screenshot_path_for_url(url) == screenshot_path_for_url(url)
    assert not has_screenshot(url)
    available, reason = screenshot_support_status()
    assert available is False and "Disabled" in reason
    assert capture_page_screenshot(url) is None


def test_explicit_looking_url_is_unverified_and_preview_stays_blocked_until_html(isolated_db, monkeypatch):
    url = "http://" + "a" * 56 + ".onion/porn"
    storage.insert_or_update_onion_url(url, policy=classify_url_prefetch(url))
    monkeypatch.setattr(screenshot_service, "screenshot_support_status", lambda: (True, "test"))
    assert capture_page_screenshot(url) is None
    preview = storage.get_page_preview(url)
    preview_state = storage.get_page_preview_state(url)
    row = storage.get_onion_url_by_url(url)
    assert row["primary_category"] == "unknown"
    assert row["classification_evidence_source"] == "unverified"
    assert preview["status"] == "blocked"
    assert preview_state["blocked_reason"] == "universal_screenshot_policy"


def test_enabled_capture_disables_javascript_downloads_and_all_subresources(isolated_db, tmp_path, monkeypatch):
    url = "http://" + "s" * 56 + ".onion/"
    policy = classify_url_prefetch(url)
    policy.update(primary_category="news_media", category="news_media", active=1,
                  storage_policy="safe_summary", review_status="monitor",
                  screenshot_policy="allowed", queue_policy="expand")
    storage.insert_or_update_onion_url(url, status="crawled", policy=policy)
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET status='crawled',active=1,http_status=200,
          last_crawled=?,screenshot_policy='allowed' WHERE url=?""", (storage.utc_now_iso(), url))

    observed = {"routes": []}

    class Request:
        def __init__(self, request_url, resource_type, navigation=False):
            self.url, self.resource_type, self._navigation = request_url, resource_type, navigation
        def is_navigation_request(self):
            return self._navigation

    class Route:
        def __init__(self, request):
            self.request, self.action = request, None
        def continue_(self):
            self.action = "continue"
        def abort(self):
            self.action = "abort"

    class Page:
        def route(self, _pattern, handler):
            observed["handler"] = handler
        def goto(self, *_args, **_kwargs):
            return types.SimpleNamespace(ok=True)
        def screenshot(self, path, **_kwargs):
            from pathlib import Path
            Path(path).write_bytes(b"safe-test-png")

    class Context:
        def new_page(self):
            return Page()
        def close(self):
            pass

    class Browser:
        def new_context(self, **kwargs):
            observed["context"] = kwargs
            return Context()
        def close(self):
            pass

    class Runtime:
        chromium = types.SimpleNamespace(launch=lambda **_kwargs: Browser())

    class Manager:
        def __enter__(self):
            return Runtime()
        def __exit__(self, *_args):
            return False

    fake_sync = types.ModuleType("playwright.sync_api")
    fake_sync.sync_playwright = lambda: Manager()
    fake_playwright = types.ModuleType("playwright")
    fake_playwright.__path__ = []
    fake_playwright.sync_api = fake_sync
    monkeypatch.setitem(sys.modules, "playwright", fake_playwright)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_sync)
    monkeypatch.setattr(screenshot_service, "PREVIEWS_DIR", tmp_path)
    monkeypatch.setattr(screenshot_service, "screenshot_support_status", lambda: (True, "test"))
    monkeypatch.setattr(screenshot_service, "is_fetch_allowed", lambda *_args: (True, "allowed"))
    monkeypatch.setattr(screenshot_service, "playwright_proxy", lambda: None)
    monkeypatch.setattr(screenshot_service, "_captures_this_run", 0)
    monkeypatch.setattr(screenshot_service, "_capture_window_started", 0)

    assert capture_page_screenshot(url)
    assert observed["context"]["java_script_enabled"] is False
    assert observed["context"]["accept_downloads"] is False

    requests = [
        Route(Request(url, "document", True)),
        Route(Request(url + "style.css", "stylesheet")),
        Route(Request(url + "logo.png", "image")),
        Route(Request("http://" + "t" * 56 + ".onion/", "document", True)),
    ]
    for route in requests:
        observed["handler"](route)
    assert [route.action for route in requests] == ["continue", "abort", "abort", "abort"]


def test_capture_helper_does_not_release_preview_worker_claim(isolated_db, tmp_path, monkeypatch):
    url = "http://" + "r" * 56 + ".onion/"
    policy = classify_url_prefetch(url)
    policy.update(primary_category="news_media", category="news_media", active=1,
                  storage_policy="safe_summary", review_status="monitor",
                  screenshot_policy="allowed", queue_policy="expand")
    storage.insert_or_update_onion_url(url, status="crawled", policy=policy)
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET status='crawled',active=1,http_status=200,
          last_crawled=?,screenshot_policy='allowed' WHERE url=?""", (storage.utc_now_iso(), url))
    storage.create_page_preview_job(url)
    claimed = storage.claim_next_page_preview_job("preview-owner")
    assert claimed

    class Manager:
        def __enter__(self):
            raise RuntimeError("browser start failed")
        def __exit__(self, *_args):
            return False

    fake_sync = types.ModuleType("playwright.sync_api")
    fake_sync.sync_playwright = lambda: Manager()
    fake_playwright = types.ModuleType("playwright")
    fake_playwright.__path__ = []
    fake_playwright.sync_api = fake_sync
    monkeypatch.setitem(sys.modules, "playwright", fake_playwright)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_sync)
    monkeypatch.setattr(screenshot_service, "PREVIEWS_DIR", tmp_path)
    monkeypatch.setattr(screenshot_service, "screenshot_support_status", lambda: (True, "test"))
    monkeypatch.setattr(screenshot_service, "is_fetch_allowed", lambda *_args: (True, "allowed"))
    monkeypatch.setattr(screenshot_service, "_captures_this_run", 0)
    monkeypatch.setattr(screenshot_service, "_capture_window_started", 0)

    assert capture_page_screenshot(url) is None
    with storage.get_db() as db:
        row = dict(db.execute("SELECT status,claimed_by FROM page_preview_jobs WHERE id=?",
                              (claimed["id"],)).fetchone())
    assert row == {"status": "claimed", "claimed_by": "preview-owner"}
