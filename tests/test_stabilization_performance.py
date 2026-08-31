from pathlib import Path

from streamlit.testing.v1 import AppTest

import onion_worker
from page_intelligence import fingerprint_page_type
import profile_builder
import site_dedupe
import storage
from universal_classifier import classify


ROOT = Path(__file__).parents[1]


def _url(letter, path="/"):
    return f"http://{letter * 56}.onion{path}"


def _add(letter, text="weapons trafficking"):
    url = _url(letter)
    document = (
        f"<html><head><title>Safe title</title></head>"
        f"<body><article>{text}</article></body></html>"
    )
    title, meta, visible_text, _links, structure = onion_worker._parse(
        document.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = onion_worker._classify_fetched_page(
        url, title=title, meta=meta, visible_text=visible_text,
        source_url=None, source_context=None, page_structure=structure)
    page_type = fingerprint_page_type(
        url, structure, current_type=str(policy.get("page_type") or "unknown"),
        allow_url_hints=False)
    if page_type["page_type_confidence"] in {"medium", "high"}:
        policy["page_type"] = page_type["page_type"]
    policy.update(
        page_type_confidence=page_type["page_type_confidence"],
        page_type_evidence=page_type["evidence"], card_ready=1,
        card_readiness_reason="classified_meaningful_page",
        card_readiness_confidence="high")
    policy = onion_worker.finalize_page_policy(
        url, policy, title=title, page_structure=structure)
    url_id = storage.insert_or_update_onion_url(
        url, letter * 56 + ".onion", status="crawled")
    storage.apply_onion_policy(
        url, policy, 200, checked=True, page_structure=structure)
    return site_dedupe.ensure_url_site_card(
        url_id, policy, title=title, visible_text=visible_text)


def _app(page):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value(page).run()
    assert not app.exception
    return app


def test_dashboard_startup_never_runs_repairs(isolated_db, monkeypatch):
    monkeypatch.setattr(site_dedupe, "backfill_existing_urls",
                        lambda: (_ for _ in ()).throw(AssertionError("dashboard backfill")))
    monkeypatch.setattr(profile_builder, "refresh_site_profiles",
                        lambda: (_ for _ in ()).throw(AssertionError("dashboard profile refresh")))
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    assert not app.exception


def test_compact_and_search_do_not_load_card_details(isolated_db, monkeypatch):
    _add("b"); _add("c", "data leak"); _add("d", "discussion forum")
    monkeypatch.setattr(site_dedupe, "get_site_card",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("N+1 get_site_card")))
    monkeypatch.setattr(site_dedupe, "get_site_card_detail",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("compact detail load")))
    app = _app("Site Cards")
    search = next(item for item in app.text_input if item.label == "Search sites")
    search.set_value("weapons").run()
    assert not app.exception


def test_review_queue_loads_only_one_selected_detail(isolated_db, monkeypatch):
    _add("b"); _add("c", "data leak"); _add("d", "credential dump")
    original = site_dedupe.get_site_card_detail
    calls = []

    def counted(card_id, *args, **kwargs):
        calls.append(card_id)
        return original(card_id, *args, **kwargs)

    monkeypatch.setattr(site_dedupe, "get_site_card_detail", counted)
    app = _app("Review Findings")
    assert len(calls) == 0
    next(item for item in app.button if str(item.key).startswith("compact-review-True-")).click().run()
    assert len(calls) == 1


class _Response:
    status_code = 200
    headers = {"Content-Type": "text/html"}
    body = ("<html><title>Weapons vendor</title><body>" +
            "weapons trafficking firearms sale vendor shipping details " * 20 + "</body></html>").encode()
    def iter_content(self, chunk_size=16384): yield self.body
    def close(self): return None


class _Session:
    def get(self, *_args, **_kwargs): return _Response()


def test_successful_worker_assigns_site_card_once(isolated_db, monkeypatch):
    url = _url("e")
    storage.insert_or_update_onion_url(url, status="queued", policy=classify(url, visible_text="ordinary"))
    original = site_dedupe.ensure_url_site_card
    calls = []

    def counted(*args, **kwargs):
        calls.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(site_dedupe, "ensure_url_site_card", counted)
    monkeypatch.setattr(onion_worker, "_session", lambda: _Session())
    monkeypatch.setattr(onion_worker, "capture_page_screenshot", lambda *_args, **_kwargs: None)
    assert onion_worker.process_one()
    assert calls == [storage.get_onion_url_by_url(url)["id"]]


def test_outbound_records_are_classified_once(isolated_db, monkeypatch):
    parent = _url("f")
    parent_id = storage.insert_or_update_onion_url(parent, status="crawled",
                                                   policy=classify(parent, visible_text="onion directory"))
    records = [{"url": _url(letter), "anchor_text": "Safe directory", "section_context": "Directory"}
               for letter in "ghi"]
    original = onion_worker._decide
    calls = []

    def counted(url, **kwargs):
        calls.append(url)
        return original(url, **kwargs)

    monkeypatch.setattr(onion_worker, "_decide", counted)
    summary, classified = onion_worker.classify_outbound_records(
        {"id": parent_id, "url": parent, "depth": 0}, records,
        classify(parent, visible_text="onion directory"))
    onion_worker._store_discovered_links(
        {"id": parent_id, "url": parent, "depth": 0}, records,
        classify(parent, visible_text="onion directory"), classified, summary)
    assert calls == [record["url"] for record in records]


def test_dirty_refresh_only_updates_dirty_cards(isolated_db, monkeypatch):
    dirty_id = _add("j")
    clean_id = _add("k", "data leak")
    with storage.get_db() as db:
        db.execute("UPDATE site_cards SET rollup_dirty=CASE WHEN id=? THEN 1 ELSE 0 END", (dirty_id,))
    calls = []
    monkeypatch.setattr(site_dedupe, "update_site_card_rollups", lambda card_id: calls.append(card_id))
    result = site_dedupe.refresh_dirty_site_cards()
    assert result["refreshed"] == 1
    assert calls == [dirty_id] and clean_id not in calls


def test_production_config_and_clean_release_exclusions_exist():
    config = (ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8")
    release = (ROOT / "scripts" / "make_clean_release.sh").read_text(encoding="utf-8")
    assert 'fileWatcherType = "none"' in config and "runOnSave = false" in config
    for excluded in (".env", "*.session", "*.db", "backups/", "reports/", "__pycache__/", "*.bak", "*.zip"):
        assert excluded in release
