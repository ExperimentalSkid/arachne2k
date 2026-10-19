"""Optional, fail-closed previews for HTML pages already fetched successfully.

Rendering is disabled by default. When explicitly enabled, JavaScript and all
subresource requests are blocked; the browser performs one GET navigation to the
exact URL already accepted and fetched by the worker. No clicks or form actions occur.
"""
from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from urllib.parse import urlsplit

from config_loader import get_bool, get_int, get_str, runtime_setting_source
from paths import PREVIEWS_DIR
from safety_policy import is_fetch_allowed, is_severe_blackhole_policy
from tor_circuits import playwright_proxy
import storage

LOGGER = logging.getLogger(__name__)
_captures_this_run = 0  # legacy test hook; durable rate limits live in page_preview_jobs
_capture_window_started = 0


def preview_safety_contract() -> dict[str, bool]:
    """Machine-readable contract used by tests and the OPSEC preflight."""
    return {
        "tor_proxy_required": True,
        "javascript_disabled": True,
        "downloads_disabled": True,
        "exact_document_only": True,
        "subresources_blocked": True,
    }


def screenshot_path_for_url(url: str) -> Path:
    digest = hashlib.sha256(url.encode("utf-8", "ignore")).hexdigest()
    return PREVIEWS_DIR / f"{digest}.png"


def has_screenshot(url: str) -> bool:
    return screenshot_path_for_url(url).is_file()


def _playwright_chromium_installed() -> bool:
    """Best-effort static browser check; never launches a browser during render/tests."""
    try:
        import playwright  # type: ignore
    except ImportError:
        return False
    candidates: list[Path] = []
    env_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if env_path and env_path != "0":
        candidates.append(Path(env_path))
    if env_path == "0":
        candidates.append(Path(playwright.__file__).resolve().parent / "driver" / "package" / ".local-browsers")
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            candidates.append(Path(local) / "ms-playwright")
    else:
        candidates.append(Path.home() / ".cache" / "ms-playwright")
    candidates.append(Path(playwright.__file__).resolve().parent / "driver" / "package" / ".local-browsers")
    for root in candidates:
        try:
            if root.exists() and any(child.name.startswith("chromium") for child in root.iterdir()):
                return True
        except OSError:
            continue
    return False


def screenshot_support_status() -> tuple[bool, str]:
    explicit = os.environ.get("ENABLE_PAGE_SCREENSHOTS")
    if explicit is not None and explicit.strip().casefold() in {"0", "false", "no", "off"}:
        return False, "Disabled by process environment"
    if not get_bool("ENABLE_PAGE_SCREENSHOTS", False):
        source = runtime_setting_source("ENABLE_PAGE_SCREENSHOTS")
        reason = {
            "runtime_settings.json": "Disabled by dashboard runtime setting",
            ".env": "Disabled by server .env",
            "environment": "Disabled by process environment",
            "config.json": "Disabled by config.json",
            "default": "Disabled by default",
        }.get(source, "Disabled by configuration")
        return False, reason
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        return False, "Playwright is not installed; previews remain safely disabled"
    if not _playwright_chromium_installed():
        return False, "Playwright is installed, but Chromium is not installed; run: python -m playwright install chromium"
    host = get_str("TOR_SOCKS_HOST", "127.0.0.1")
    port = get_int("TOR_SOCKS_PORT", 9050)
    if not host or port <= 0 or port > 65535:
        return False, "Tor SOCKS proxy is not configured correctly for preview capture"
    return True, "Available (Tor proxy, JavaScript disabled, subresources blocked)"


def _document_equivalent(candidate: str, expected: str) -> bool:
    """Allow only the same document, with an empty root path equal to ``/``."""
    def normalize(value: str) -> tuple[str, str, str, str]:
        parts = urlsplit(value)
        return parts.scheme.casefold(), parts.netloc.casefold(), parts.path or "/", parts.query
    return normalize(candidate) == normalize(expected)


def capture_page_screenshot(url: str) -> str | None:
    storage.init_db()
    output = screenshot_path_for_url(url)
    with storage.get_db() as db:
        fetched = db.execute("""SELECT status,http_status,last_crawled,primary_category,storage_policy,
            review_status,screenshot_policy,safety_reason,active FROM onion_urls WHERE url=?""", (url,)).fetchone()
    if fetched and is_severe_blackhole_policy(fetched):
        output.unlink(missing_ok=True)
        storage.enforce_severe_blackhole(url, dict(fetched))
        return None
    if fetched and (fetched["primary_category"] in {"adult_filtered", "adult_restricted"}
                    or fetched["storage_policy"] == "discard"):
        output.unlink(missing_ok=True)
        storage.cleanup_adult_filtered_items(url)
        return None
    available, reason = screenshot_support_status()
    if not available:
        LOGGER.info("Screenshot skipped: %s", reason)
        return None
    allowed, _ = is_fetch_allowed(url, get_bool("ALLOW_CLEARNET_FETCH", False))
    policy_allowed = bool(fetched and fetched["status"] == "crawled" and fetched["active"] == 1
        and fetched["http_status"] is not None and 200 <= fetched["http_status"] < 300
        and fetched["last_crawled"] and fetched["storage_policy"] == "safe_summary"
        and fetched["review_status"] not in {"restricted", "filtered"}
        and fetched["screenshot_policy"] == "allowed")
    if not allowed or not policy_allowed:
        if output.exists():
            output.unlink(missing_ok=True)
        storage.block_page_preview(url, "universal_screenshot_policy")
        return None
    if output.exists():
        return str(output)
    try:
        from playwright.sync_api import sync_playwright
        PREVIEWS_DIR.mkdir(parents=True, exist_ok=True)
        browser = context = page = None
        with sync_playwright() as runtime:
            browser = runtime.chromium.launch(headless=True, proxy=playwright_proxy())
            context = browser.new_context(
                viewport={"width": get_int("SCREENSHOT_WIDTH", 1280), "height": get_int("SCREENSHOT_HEIGHT", 900)},
                java_script_enabled=False, accept_downloads=False,
            )
            page = context.new_page()
            def handle_route(route):
                request = route.request
                exact_document = (
                    request.is_navigation_request()
                    and request.resource_type == "document"
                    and _document_equivalent(request.url, url)
                )
                route.continue_() if exact_document else route.abort()
            page.route("**/*", handle_route)
            response = page.goto(url, wait_until="domcontentloaded", timeout=get_int("SCREENSHOT_TIMEOUT_SECONDS", 20) * 1000)
            response_url = getattr(response, "url", url) if response else url
            if response and response.ok and _document_equivalent(response_url, url):
                page.screenshot(path=str(output), full_page=False)
        if output.exists():
            return str(output)
    except Exception as exc:
        LOGGER.warning("Screenshot unavailable for fetched page: %s", type(exc).__name__)
    finally:
        for resource in (page, context, browser):
            try:
                if resource:
                    resource.close()
            except Exception:
                pass
    return None
