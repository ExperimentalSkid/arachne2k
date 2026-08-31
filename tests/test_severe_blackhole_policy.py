from __future__ import annotations

from pathlib import Path
from html import escape

import pytest

import preview_worker
import screenshot_service
import site_dedupe
import storage
import onion_worker
from universal_classifier import classify
from safety_policy import (
    SEVERE_BLACKHOLE_MARKER,
    assess_severe_abuse_signals,
    is_severe_blackhole_policy,
    severe_blackhole_policy,
)


HOST = "s" * 56 + ".onion"
URL = f"http://{HOST}/"


def _safe_policy() -> dict:
    return {
        "primary_category": "directory_index", "category": "directory_index",
        "risk_level": "low", "storage_policy": "safe_summary", "review_status": "monitor",
        "safety_reason": "directory_index", "screenshot_policy": "allowed",
        "queue_policy": "expand", "active": 1, "spain_priority": False,
    }


def _insert_url(policy: dict, url: str = URL, host: str = HOST) -> int:
    url_id = storage.insert_or_update_onion_url(url, host, status="crawled", policy=policy)
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET status='crawled',http_status=200,last_crawled=?,
          primary_category=?,category=?,storage_policy=?,review_status=?,safety_reason=?,
          screenshot_policy=?,queue_policy=?,active=? WHERE id=?""",
          (storage.utc_now_iso(), policy["primary_category"], policy["category"],
           policy["storage_policy"], policy["review_status"], policy["safety_reason"],
           policy["screenshot_policy"], policy["queue_policy"], policy["active"], url_id))
    return url_id


def _parser_owned_page(url: str, title: str, visible_text: str) -> tuple[str, str, str, dict]:
    html = (f"<html><head><title>{escape(title)}</title></head><body>"
            f"<main><p>{escape(visible_text)}</p></main></body></html>")
    parsed_title, meta, visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    return parsed_title or title, meta, visible, structure


def _insert_analyst_policy(policy: dict, url: str = URL, host: str = HOST) -> int:
    category = str(policy.get("primary_category") or "unknown")
    analyst_policy = dict(
        policy, analyst_category=category,
        classification_evidence_source="analyst",
        destination_html_evidence_version=0,
    )
    url_id = storage.insert_or_update_onion_url(url, host, status="queued")
    storage.apply_onion_policy(url, analyst_policy)
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET analyst_category=?,
          classification_evidence_source='analyst',verification_state='verified',
          verification_reason='analyst_confirmed' WHERE id=?""",
          (category, url_id))
    return url_id


def _store_historical_snapshot(url_id: int, url: str, *, title: str,
                               meta_text: str = "", visible_text: str = "Safe public directory.",
                               title_source: str = "html_title",
                               trusted_content_boundary: bool = False) -> None:
    structure = {
        "identity": {
            "detected_title": title,
            "display_name": title,
            "title_source": title_source,
            "identity_confidence": "low" if title_source == "onion_host" else "medium",
        }
    }
    if trusted_content_boundary:
        title, meta_text, visible_text, structure = _parser_owned_page(
            url, title, visible_text)
    storage.store_fetched_page_snapshot(
        url_id, url, worker_id=None, response_status=200, content_type="text/html",
        headers={}, title=title, meta_text=meta_text, visible_text=visible_text,
        link_records=[], page_structure=structure, pre_policy=_safe_policy())
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET status='crawled',verification_state='verified',
          primary_category='directory_index',category='directory_index',content_category='directory_index',
          title=?,detected_title=?,safe_display_name=?,title_source=?
          WHERE id=?""", (title, title, title, title_source, url_id))
        db.execute("""UPDATE fetched_pages SET classification_status='done',verified_at=?
          WHERE onion_url_id=?""", (storage.utc_now_iso(), url_id))


def test_obfuscated_and_unicode_normalized_explicit_signals_are_detected():
    for value in ("c.s.a.m exchange files", "c-s-a-m exchange files", "c s a m exchange files",
                  "ćšám exchange files", "ＣＳＡＭ exchange files"):
        result = assess_severe_abuse_signals(body_text=value)
        assert result["block"] is True
        assert "severe_explicit_signal" in result["safe_signal_labels"]
        assert result["raw_evidence_retention_allowed"] is False


def test_spanish_explicit_phrase_is_detected_without_retaining_raw_match():
    result = assess_severe_abuse_signals(body_text="material de abuso sexual infantil para intercambio")
    assert result["block"] is True
    assert result["scope"] == "body"
    assert set(result) >= {"safe_signal_labels", "independent_signal_families"}
    assert "material de abuso" not in repr(result).casefold()


def test_protective_context_and_ambiguous_word_do_not_blackhole():
    protected = assess_severe_abuse_signals(
        title_text="Child safety news report",
        body_text="Prevention and education report about c.s.a.m awareness.")
    ambiguous = assess_severe_abuse_signals(body_text="loli art discussion")
    unrelated = assess_severe_abuse_signals(body_text="minor account files for education")
    assert protected["block"] is False and protected["protected_context"] is True
    assert ambiguous["block"] is False
    assert unrelated["block"] is False


def test_configured_terms_are_all_context_bound():
    for term in ("cp", "loli", "pedo", "jailbait", "childporn"):
        assert assess_severe_abuse_signals(title_text=term)["block"] is False
    assert assess_severe_abuse_signals(title_text="cp porn video gallery")["block"] is True
    assert assess_severe_abuse_signals(title_text="loli porn preview")["block"] is True
    assert assess_severe_abuse_signals(title_text="childporn video archive")["block"] is True


def test_independent_families_must_share_a_bounded_context_window():
    separated = "minor " + ("ordinary text " * 80) + "sexual " + ("ordinary text " * 80) + "download files"
    together = "underage explicit sexual gallery files available for exchange"
    assert assess_severe_abuse_signals(body_text=separated)["block"] is False
    result = assess_severe_abuse_signals(body_text=together)
    assert result["block"] is True
    assert set(result["independent_signal_families"]) == {
        "minor_context", "sexual_context", "exchange_context"}


def test_page_scope_does_not_let_restricted_outbound_context_poison_parent():
    page = assess_severe_abuse_signals(
        title_text="General onion directory", body_text="A directory of many unrelated categories",
        context_text="c.s.a.m exchange files", classification_scope="page")
    child = assess_severe_abuse_signals(
        url_text=URL + "restricted", context_text="c.s.a.m exchange files",
        classification_scope="child")
    assert page["block"] is False
    assert child["block"] is False
    assert child["unverified_hint"] is True


def test_canonical_blackhole_contract_disables_every_downstream_action():
    policy = severe_blackhole_policy({"spain_priority": True, "urgent_flag": True})
    assert is_severe_blackhole_policy(policy) is True
    assert policy["blackhole_policy"] == SEVERE_BLACKHOLE_MARKER
    for field in (
        "fetch_allowed", "preview_allowed", "ocr_allowed", "screenshot_allowed",
        "expansion_allowed", "card_allowed", "actor_extraction_allowed", "alert_allowed",
        "report_allowed", "enrichment_allowed", "raw_content_allowed", "report_required",
        "spain_priority", "urgent_flag",
    ):
        assert policy[field] is False
    assert policy["active"] == 0 and policy["queue_policy"] == "blocked"
    assert policy["screenshot_policy"] == "blocked"
    assert is_severe_blackhole_policy({"primary_category": "adult_filtered"}) is False


def test_titles_seen_in_directory_leak_are_page_blackholes_not_visible_cards():
    titles = (
        "Board free preview pedo destination with nudism video",
        "Jailbait little pussy",
        "Preteen sexual video gallery files",
        "Underage boy porn video list",
        "High school girls hacked webcam sex video",
    )
    for title in (titles[0], *titles[2:]):
        policy = classify(URL, title=title, visible_text="", classification_scope="page")
        assert is_severe_blackhole_policy(policy)
        assert policy["card_allowed"] is False
    ambiguous = classify(URL, title=titles[1], visible_text="", classification_scope="page")
    assert ambiguous["primary_category"] != "severe_abuse_risk"


def test_historical_cleanup_ignores_non_destination_owned_severe_strings(isolated_db):
    marker = "loli porn preview gallery exchange"
    safe_title = "Neutral public directory"
    urls: list[str] = []

    # HTML metadata is a low-trust hint, not destination body evidence.
    meta_host = "m" * 56 + ".onion"
    meta_url = f"http://{meta_host}/"
    meta_id = _insert_url(_safe_policy(), meta_url, meta_host)
    _store_historical_snapshot(
        meta_id, meta_url, title=safe_title, meta_text=marker,
        visible_text="A neutral directory containing unrelated public resources.")
    urls.append(meta_url)

    # A section/child heading must not be promoted to proof about the whole page.
    heading_host = "h" * 56 + ".onion"
    heading_url = f"http://{heading_host}/"
    heading_id = _insert_url(_safe_policy(), heading_url, heading_host)
    _store_historical_snapshot(
        heading_id, heading_url, title=marker, title_source="heading",
        visible_text="A neutral directory containing unrelated public resources.")
    urls.append(heading_url)

    # The display-only host fallback is URL identity, not fetched-page title evidence.
    root_host = "n" * 56 + ".onion"
    host_url = f"http://loli-porn-preview.{root_host}/"
    host_id = _insert_url(_safe_policy(), host_url, f"loli-porn-preview.{root_host}")
    _store_historical_snapshot(
        host_id, host_url, title=f"loli-porn-preview.{root_host}",
        title_source="onion_host",
        visible_text="A neutral directory containing unrelated public resources.")
    urls.append(host_url)

    # Site Card rollups may summarize child pages and cannot become terminal page evidence.
    card_host = "r" * 56 + ".onion"
    card_url = f"http://{card_host}/"
    card_id_url = _insert_url(_safe_policy(), card_url, card_host)
    _store_historical_snapshot(
        card_id_url, card_url, title=safe_title,
        visible_text="A neutral directory containing unrelated public resources.")
    now = storage.utc_now_iso()
    with storage.get_db() as db:
        card_id = int(db.execute("""INSERT INTO site_cards(
          canonical_site_id,display_name,detected_title,primary_category,content_category,
          analyst_category,storage_policy,review_status,first_seen,last_seen,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
          ("historical-card-rollup", safe_title, safe_title, "directory_index",
           "directory_index", "directory_index", "safe_summary", "monitor",
           now, now, now, now)).lastrowid)
        db.execute("""INSERT INTO site_card_urls(
          site_card_id,onion_url_id,url,url_role,first_seen,last_seen,created_at,updated_at)
          VALUES(?,?,?,'homepage',?,?,?,?)""",
          (card_id, card_id_url, card_url, now, now, now, now))
        db.execute("UPDATE onion_urls SET site_card_id=? WHERE id=?", (card_id, card_id_url))
        db.execute("UPDATE site_cards SET display_name=?,detected_title=? WHERE id=?",
                   (marker, marker, card_id))
    urls.append(card_url)

    result = storage.cleanup_severe_blackhole_items(dry_run=False)

    assert result["matched"] == 0
    with storage.get_db() as db:
        rows = [dict(row) for row in db.execute(
            f"""SELECT url,primary_category,storage_policy,active FROM onion_urls
            WHERE url IN ({','.join('?' for _ in urls)}) ORDER BY url""", tuple(urls))]
        retained_card = db.execute("SELECT id FROM site_cards WHERE id=?", (card_id,)).fetchone()
    assert len(rows) == len(urls)
    assert all(row["primary_category"] == "directory_index" for row in rows)
    assert all(row["storage_policy"] == "safe_summary" and row["active"] == 1 for row in rows)
    assert retained_card is not None


def test_historical_cleanup_still_matches_corroborated_destination_visible_text(isolated_db):
    host = "v" * 56 + ".onion"
    url = f"http://{host}/"
    url_id = _insert_url(_safe_policy(), url, host)
    _store_historical_snapshot(
        url_id, url, title="Returned destination page",
        visible_text="Underage explicit sexual video files advertised for download and exchange.",
        trusted_content_boundary=True)

    result = storage.cleanup_severe_blackhole_items(dry_run=False)

    assert result["matched"] == 1 and result["scrubbed"] == 1
    with storage.get_db() as db:
        row = dict(db.execute("""SELECT primary_category,storage_policy,status,active
          FROM onion_urls WHERE id=?""", (url_id,)).fetchone())
    assert row == {
        "primary_category": "severe_abuse_risk", "storage_policy": "metadata_only",
        "status": "blocked", "active": 0,
    }


def test_historical_cleanup_does_not_trust_legacy_visible_text_without_content_boundary(
        isolated_db):
    host = "b" * 56 + ".onion"
    url = f"http://{host}/"
    child_url = "http://" + "c" * 56 + ".onion/"
    marker = "underage explicit sexual video files for download and exchange"
    url_id = _insert_url(_safe_policy(), url, host)

    # Older parser versions included outbound anchor labels in visible_text and
    # stored no boundary/provenance marker proving that those labels were removed.
    storage.store_fetched_page_snapshot(
        url_id, url, worker_id=None, response_status=200, content_type="text/html",
        headers={}, title="Neutral public directory", meta_text="",
        visible_text=f"Neutral public directory {marker}",
        link_records=[{"url": child_url, "anchor_text": marker}],
        page_structure={
            "identity": {
                "detected_title": "Neutral public directory",
                "title_source": "html_title",
            },
            "signals": ["high_edge_link_repository"],
            "scores": {"directory": 4},
        },
        pre_policy=_safe_policy(),
    )
    with storage.get_db() as db:
        db.execute("""UPDATE fetched_pages SET classification_status='done',verified_at=?
          WHERE onion_url_id=?""", (storage.utc_now_iso(), url_id))
        db.execute("""UPDATE onion_urls SET verification_state='verified',
          primary_category='directory_index',category='directory_index',
          content_category='directory_index',page_type='link_repository'
          WHERE id=?""", (url_id,))

    result = storage.cleanup_severe_blackhole_items(dry_run=False)

    assert result["matched"] == 0 and result["scrubbed"] == 0
    with storage.get_db() as db:
        row = dict(db.execute("""SELECT primary_category,storage_policy,status,active
          FROM onion_urls WHERE id=?""", (url_id,)).fetchone())
        fetched = dict(db.execute("""SELECT visible_text,link_records_json
          FROM fetched_pages WHERE onion_url_id=?""", (url_id,)).fetchone())
    assert row == {
        "primary_category": "directory_index", "storage_policy": "safe_summary",
        "status": "classification_pending", "active": 1,
    }
    assert marker in fetched["visible_text"]
    assert marker in fetched["link_records_json"]


@pytest.mark.parametrize("raw_title", (
    "Jailbait little pussy video gallery",
    "loli porn preview gallery",
    "childporn video archive",
    "cp porn video gallery exchange",
))
def test_historical_cleanup_removes_raw_snapshot_card_and_artifacts(
        isolated_db, tmp_path, monkeypatch, raw_title):
    monkeypatch.setattr(storage, "PREVIEWS_DIR", tmp_path)
    url_id = _insert_url(_safe_policy())
    parsed_title, parsed_meta, parsed_visible, structure = _parser_owned_page(
        URL, raw_title, raw_title)
    storage.store_fetched_page_snapshot(
        url_id, URL, worker_id=None, response_status=200, content_type="text/html",
        headers={"X-Test": "raw-marker"}, title=parsed_title, meta_text=parsed_meta,
        visible_text=parsed_visible, link_records=[],
        page_structure=structure, pre_policy=_safe_policy())
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET title=?,detected_title=?,status='crawled' WHERE id=?",
                   (raw_title, raw_title, url_id))
        db.execute("""UPDATE fetched_pages SET classification_status='done',verified_at=?
          WHERE onion_url_id=?""", (storage.utc_now_iso(), url_id))
        db.execute("""INSERT INTO page_topics(url,topics_json,keywords_json,updated_at)
          VALUES(?,?,?,?)""", (URL, '["raw-marker"]', '["raw-marker"]', storage.utc_now_iso()))
    stale = tmp_path / "stale.png"
    stale.write_bytes(b"raw-marker")
    storage.upsert_page_preview(URL, str(stale))

    result = storage.cleanup_severe_blackhole_items(dry_run=False)

    assert result["matched"] == 1 and result["scrubbed"] == 1
    assert not stale.exists()
    with storage.get_db() as db:
        row = dict(db.execute("""SELECT status,active,primary_category,site_card_id,title,
          detected_title,storage_policy,safety_reason,spain_priority,urgent_flag
          FROM onion_urls WHERE id=?""", (url_id,)).fetchone())
        fetched = dict(db.execute("""SELECT title,meta_text,visible_text,headers_json,
          link_records_json,page_structure_json,classification_status FROM fetched_pages WHERE onion_url_id=?""",
          (url_id,)).fetchone())
        dump = "\n".join(db.iterdump()).casefold()
    assert row == {
        "status": "blocked", "active": 0, "primary_category": "severe_abuse_risk",
        "site_card_id": None, "title": None, "detected_title": None,
        "storage_policy": "metadata_only", "safety_reason": "severe_abuse_blackhole",
        "spain_priority": 0, "urgent_flag": 0,
    }
    assert fetched == {
        "title": None, "meta_text": "", "visible_text": "", "headers_json": "{}",
        "link_records_json": "[]", "page_structure_json": "{}", "classification_status": "done",
    }
    assert raw_title.casefold() not in dump
    assert "raw-marker" not in dump


def test_context_v3_cleanup_runs_even_when_older_blackhole_migration_completed(isolated_db):
    url_id = _insert_url(_safe_policy())
    raw_title = "loli porn preview gallery"
    parsed_title, parsed_meta, parsed_visible, structure = _parser_owned_page(
        URL, raw_title, raw_title)
    storage.store_fetched_page_snapshot(
        url_id, URL, worker_id=None, response_status=200, content_type="text/html",
        headers={}, title=parsed_title, meta_text=parsed_meta, visible_text=parsed_visible,
        link_records=[], page_structure=structure, pre_policy=_safe_policy())
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET title=?,detected_title=? WHERE id=?",
                   (raw_title, raw_title, url_id))
        db.execute("""UPDATE fetched_pages SET classification_status='done',verified_at=?
          WHERE onion_url_id=?""", (storage.utc_now_iso(), url_id))
        db.execute("DELETE FROM data_migrations WHERE name='severe_blackhole_v3_context_20260713'")
        db.execute("""INSERT OR REPLACE INTO data_migrations
          (name,status,started_at,completed_at,safe_result_json)
          VALUES('severe_blackhole_v2_20260713','complete',?,?, '{}')""",
          (storage.utc_now_iso(), storage.utc_now_iso()))

    storage.init_db()

    with storage.get_db() as db:
        row = db.execute("SELECT primary_category,title FROM onion_urls WHERE id=?", (url_id,)).fetchone()
        fetched = db.execute(
            "SELECT visible_text,classification_status FROM fetched_pages WHERE onion_url_id=?",
            (url_id,)).fetchone()
        migration = db.execute("""SELECT status FROM data_migrations
          WHERE name='severe_blackhole_v3_context_20260713'""").fetchone()
    assert tuple(row) == ("severe_abuse_risk", None)
    assert tuple(fetched) == ("", "done")
    assert migration[0] == "complete"


def test_screenshot_entrypoint_fails_before_runtime_support_check(
        isolated_db, tmp_path, monkeypatch):
    _insert_analyst_policy(severe_blackhole_policy())
    monkeypatch.setattr(screenshot_service, "PREVIEWS_DIR", tmp_path)
    stale = screenshot_service.screenshot_path_for_url(URL)
    stale.write_bytes(b"stale")
    monkeypatch.setattr(
        screenshot_service, "screenshot_support_status",
        lambda: (_ for _ in ()).throw(AssertionError("runtime support check reached")))

    assert screenshot_service.capture_page_screenshot(URL) is None
    assert not stale.exists()
    assert storage.get_page_preview(URL) is None
    with storage.get_db() as db:
        row = db.execute("SELECT status,safety_reason FROM onion_urls WHERE url=?", (URL,)).fetchone()
    assert dict(row) == {"status": "blocked", "safety_reason": "severe_abuse_blackhole"}


def test_preview_claim_reclassified_severe_never_reuses_captures_or_runs_ocr(
        isolated_db, tmp_path, monkeypatch):
    url_id = _insert_url(_safe_policy())
    job_id = storage.create_page_preview_job(URL)
    with storage.get_db() as db:
        db.execute("""UPDATE page_preview_jobs SET status='claimed',claimed_by='preview-test',
          claimed_at=? WHERE id=?""", (storage.utc_now_iso(), job_id))
        db.execute("""UPDATE onion_urls SET primary_category='severe_abuse_risk',
          category='severe_abuse_risk',content_category='severe_abuse_risk',
          analyst_category='severe_abuse_risk',classification_evidence_source='analyst',
          verification_reason='analyst_confirmed',storage_policy='metadata_only',review_status='restricted',
          safety_reason='severe_abuse_risk',screenshot_policy='blocked',queue_policy='blocked',active=0
          WHERE id=?""", (url_id,))
    stale = tmp_path / "stale.png"
    stale.write_bytes(b"stale")
    storage.upsert_page_preview(URL, str(stale))
    with storage.get_db() as db:
        db.execute("""UPDATE page_preview_jobs SET status='claimed',claimed_by='preview-test',
          claimed_at=? WHERE id=?""", (storage.utc_now_iso(), job_id))
    job = {
        "id": job_id, "url": URL, "onion_url_id": url_id, "force": 0,
        "primary_category": "severe_abuse_risk", "safety_reason": "severe_abuse_risk",
    }
    monkeypatch.setattr(preview_worker, "screenshot_support_status", lambda: (True, "ready"))
    monkeypatch.setattr(preview_worker.storage, "preview_capture_limit_reached", lambda: False)
    monkeypatch.setattr(preview_worker.storage, "claim_next_page_preview_job", lambda *_a, **_k: job)
    monkeypatch.setattr(
        preview_worker, "capture_page_screenshot",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("capture reached")))
    monkeypatch.setattr(
        preview_worker, "_ocr_policy_blocks_preview",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("OCR reached")))

    assert preview_worker.process_preview_job("preview-test") is True
    assert not stale.exists()
    assert storage.get_page_preview(URL) is None
    with storage.get_db() as db:
        assert db.execute("SELECT 1 FROM page_preview_jobs WHERE url=?", (URL,)).fetchone() is None
