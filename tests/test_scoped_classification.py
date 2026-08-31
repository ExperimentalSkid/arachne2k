from pathlib import Path

from streamlit.testing.v1 import AppTest

import onion_worker
import site_dedupe
import storage
from universal_classifier import classify


HOST = "a" * 56 + ".onion"
PARENT = f"http://{HOST}/"
ADULT = "http://porn" + "b" * 52 + ".onion/"
SEVERE = PARENT + "csam"


class _Response:
    status_code = 200
    headers = {"Content-Type": "text/html"}

    def __init__(self, body: str):
        self.body = body.encode()

    def iter_content(self, chunk_size=16384):
        yield self.body

    def close(self):
        return None


class _Session:
    def __init__(self, body: str):
        self.response = _Response(body)

    def get(self, *_args, **_kwargs):
        return self.response


def _crawl(isolated_db, monkeypatch, body: str):
    storage.insert_or_update_onion_url(PARENT, HOST, status="queued")
    monkeypatch.setattr(onion_worker, "_session", lambda: _Session(body))
    monkeypatch.setattr(onion_worker, "capture_page_screenshot",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("screenshot attempted")))
    assert onion_worker.fetch_one("fetch-test")
    assert onion_worker.verify_one("verify-test")
    onion_worker.process_card_job("card-test")
    return storage.get_onion_url_by_url(PARENT)


def test_page_text_excludes_outbound_anchor_labels():
    _title, _meta, page_text, records, _structure = onion_worker._parse(
        f"<html><title>Safe Directory</title><body><h1>Useful index</h1>"
        f"<a href='{ADULT}'>Porn links</a></body></html>".encode(), "text/html", PARENT)
    assert "Porn links" not in page_text
    assert records[0]["anchor_text"] == "Porn links"


def test_fetched_forum_is_understood_from_its_html_structure():
    body = f"""<html><title>Community</title><body><ul class='topiclist'>
      <li><a href='http://{HOST}/viewtopic.php?t=1'>First topic</a></li>
      <li><a href='http://{HOST}/viewtopic.php?t=2'>Second topic</a></li>
      <li><a href='http://{HOST}/viewforum.php?f=3'>Section</a></li></ul></body></html>"""
    title, meta, text, _records, structure = onion_worker._parse(body.encode(), "text/html", PARENT)
    policy = classify(PARENT, title=title, meta=meta, visible_text=text,
                      classification_scope="page", page_structure=structure)
    assert policy["primary_category"] == "forum_social"
    assert policy["page_type"] == "forum_index"
    assert "forum_markup" in policy["evidence_families"]


def test_fetched_market_is_understood_from_vendor_and_listing_structure():
    body = f"""<html><title>Welcome</title><body><div class='product-grid'>
      <a href='http://{HOST}/vendor/alice'>Vendor Alice</a>
      <a href='http://{HOST}/product/1'>Listing one</a></div></body></html>"""
    title, meta, text, _records, structure = onion_worker._parse(body.encode(), "text/html", PARENT)
    policy = classify(PARENT, title=title, meta=meta, visible_text=text,
                      classification_scope="page", page_structure=structure)
    assert policy["primary_category"] == "marketplace"
    assert policy["storage_policy"] == "metadata_limited"
    assert policy["classification_decision"] == "accepted"


def test_meaningful_generic_article_becomes_hidden_general_monitor_not_unknown():
    body = """<html><title>Community bulletin</title><body><article>
      <h1>Weekly community update</h1><time>2026-07-02</time>
      <p>This is a long ordinary announcement about maintenance, schedules, and general community news.</p>
      </article></body></html>"""
    title, meta, text, _records, structure = onion_worker._parse(body.encode(), "text/html", PARENT)
    policy = classify(PARENT + "bulletin", title=title, meta=meta, visible_text=text,
                      classification_scope="page", page_structure=structure)
    assert policy["primary_category"] == "general_other"
    assert policy["classification_decision"] == "monitor_only"
    assert policy["ui_hidden_default"] == 1


def test_login_gate_stays_access_limited_instead_of_being_guessed():
    body = """<html><title>Sign in</title><body><form action='/login'>
      <input name='username'><input type='password' name='password'></form></body></html>"""
    title, meta, text, _records, structure = onion_worker._parse(body.encode(), "text/html", PARENT)
    policy = classify(PARENT + "login", title=title, meta=meta, visible_text=text,
                      classification_scope="page", page_structure=structure)
    assert policy["primary_category"] == "unknown"
    assert policy["page_type"] == "login_wall"
    assert policy["ui_hidden_default"] == 1


def test_low_signal_fetched_page_does_not_create_normal_result_card(isolated_db, monkeypatch):
    parent = _crawl(isolated_db, monkeypatch, """<html><title>Community bulletin</title><body><article>
      <h1>Weekly update</h1><p>This ordinary community announcement contains enough text to be meaningful
      and describes maintenance schedules, opening hours, and routine site news.</p></article></body></html>""")
    assert parent["primary_category"] == "general_other"
    assert parent["verification_state"] == "verified"
    assert parent["site_card_id"] is None
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM onion_hits WHERE url=?", (PARENT,)).fetchone()[0] == 0


def test_uncertain_verified_page_can_be_queued_for_deeper_understanding(isolated_db):
    url = PARENT + "unclear"
    html = ("<html><head><title>Welcome</title></head><body>"
            "<p>A short page with no reliable topic yet.</p></body></html>")
    title, meta, visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = classify(
        url, title=title, meta=meta, visible_text=visible,
        classification_scope="page", page_structure=structure)
    policy = onion_worker.finalize_page_policy(
        url, policy, title=title, page_structure=structure)
    storage.insert_or_update_onion_url(url, HOST)
    storage.apply_onion_policy(
        url, policy, 200, checked=True, page_structure=structure)
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET status='crawled' WHERE url=?", (url,))
    assert storage.queue_uncertain_urls() == 1
    row = storage.get_onion_url_by_url(url)
    assert row["status"] == "queued"
    assert row["verification_reason"] == "queued_for_deeper_page_understanding"


def test_one_adult_child_does_not_poison_directory_parent(isolated_db, monkeypatch):
    safe = "http://" + "d" * 56 + ".onion/"
    parent = _crawl(isolated_db, monkeypatch, f"""<html><title>Onion Directory</title><body>
      <h1>Useful Onion Directory</h1><a href='{ADULT}'>Porn links</a>
      <a href='{safe}'>Search engine</a></body></html>""")
    child = storage.get_onion_url_by_url(ADULT)
    assert parent["primary_category"] == "directory_index"
    assert parent["adult_outbound_count"] == 0 and parent["restricted_outbound_count"] == 0
    assert parent["restricted_child_present"] == 0 and parent["mixed_directory"] == 0
    assert "adult_link_present" not in (parent["tags"] or "")
    assert child["primary_category"] == "unknown" and child["active"] == 1
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM page_previews WHERE url=?", (ADULT,)).fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM onion_hits WHERE url=?", (ADULT,)).fetchone()[0] == 0


def test_minority_restricted_links_make_mixed_directory_and_safe_card(isolated_db, monkeypatch):
    safe_links = [f"http://{'defgh'[index] * 56}.onion/" for index in range(4)]
    anchors = "".join(f"<a href='{url}'>Safe directory {index}</a>" for index, url in enumerate(safe_links))
    parent = _crawl(isolated_db, monkeypatch, f"""<html><title>Onion Link Directory</title><body>
      <h1>Onion Link Directory</h1>{anchors}<a href='{ADULT}'>Porn links</a></body></html>""")
    assert parent["primary_category"] == "directory_index"
    assert parent["mixed_directory"] == 0
    assert parent["restricted_outbound_ratio"] == 0
    card = site_dedupe.get_site_cards()[0]
    assert card["primary_category"] == "directory_index"
    assert card["adult_outbound_count"] == 0 and card["restricted_child_present"] == 0
    assert card["storage_policy"] == "safe_summary" and card["ui_hidden_default"] == 0


def test_disabled_preview_feature_does_not_create_permanent_policy_block(isolated_db, monkeypatch):
    original_get_bool = onion_worker.get_bool
    monkeypatch.setattr(onion_worker, "get_bool",
                        lambda name, default=False: False if name == "ENABLE_PAGE_SCREENSHOTS"
                        else original_get_bool(name, default))
    safe = "http://" + "d" * 56 + ".onion/"
    _crawl(isolated_db, monkeypatch, f"""<html><title>Onion Directory</title><body>
      <h1>Useful Onion Directory</h1><a href='{safe}'>Safe index</a></body></html>""")
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM page_previews WHERE url=?", (PARENT,)).fetchone()[0] == 0


def test_adult_themed_majority_directory_is_filtered(isolated_db, monkeypatch):
    adult_links = [f"http://porn{'bcde'[index] * 52}.onion/" for index in range(4)]
    anchors = "".join(f"<a href='{url}'>Porn link {index}</a>" for index, url in enumerate(adult_links))
    safe = "http://" + "f" * 56 + ".onion/"
    parent = _crawl(isolated_db, monkeypatch, f"""<html><title>Porn Link Directory</title><body>
      <h1>Porn Link Directory</h1>{anchors}<a href='{safe}'>Other link</a></body></html>""")
    assert parent["primary_category"] == "adult_filtered" and parent["active"] == 0
    assert storage.get_onion_url_by_url(safe) is None


def test_severe_child_does_not_override_safe_parent_card(isolated_db, monkeypatch):
    safe = "http://" + "d" * 56 + ".onion/"
    parent = _crawl(isolated_db, monkeypatch, f"""<html><title>Onion Directory</title><body>
      <h1>Useful Onion Directory</h1><a href='{SEVERE}'>CSAM</a>
      <a href='{safe}'>Safe index</a></body></html>""")
    severe = storage.get_onion_url_by_url(SEVERE)
    assert parent["primary_category"] == "directory_index" and parent["severe_outbound_count"] == 0
    assert parent["restricted_outbound_count"] == 0
    assert severe["primary_category"] == "unknown" and severe["active"] == 1
    assert severe["classification_decision"] == "unverified_hint"
    card = site_dedupe.get_site_cards()[0]
    assert card["primary_category"] == "directory_index" and card["storage_policy"] == "safe_summary"


def test_parent_card_shows_only_safe_restricted_aggregate(isolated_db, monkeypatch):
    safe = "http://" + "d" * 56 + ".onion/"
    _crawl(isolated_db, monkeypatch, f"""<html><title>Onion Directory</title><body>
      <h1>Useful Onion Directory</h1><a href='{ADULT}'>Porn links</a>
      <a href='{safe}'>Safe index</a></body></html>""")
    app = AppTest.from_file(str(Path(__file__).parents[1] / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value("Site Cards").run()
    display = next(item for item in app.radio if item.label == "Display")
    display.set_value("Card view").run()
    assert not app.exception
    assert not any("restricted child link(s) hidden" in str(item.label) for item in app.button)
    assert not any(ADULT in str(item.value) for item in app.code)
