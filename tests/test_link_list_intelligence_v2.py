import json
from pathlib import Path

import onion_worker
import site_dedupe
import storage
from streamlit.testing.v1 import AppTest
from universal_classifier import classify


PARENT_HOST = "a" * 56 + ".onion"
PARENT = f"http://{PARENT_HOST}/deep/categories/list"


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


def _host(letter: str) -> str:
    return letter * 56 + ".onion"


def _crawl(monkeypatch, body: str, *, depth: int = 4):
    seed_policy = classify(PARENT, visible_text="ordinary page")
    storage.insert_or_update_onion_url(PARENT, PARENT_HOST, depth=depth,
                                       status="queued", policy=seed_policy)
    monkeypatch.setattr(onion_worker, "_session", lambda: _Session(body))
    monkeypatch.setattr(onion_worker, "capture_page_screenshot", lambda *_args, **_kwargs: None)
    assert onion_worker.process_one()
    return storage.get_onion_url_by_url(PARENT)


def test_structural_link_repository_is_promoted_before_frontier_depth_decision(isolated_db, monkeypatch):
    destinations = [f"http://{_host(letter)}/" for letter in "bcdefg"]
    rows = "".join(f"<li><a href='{url}'>Directory entry {index}</a></li>"
                   for index, url in enumerate(destinations))
    parent = _crawl(monkeypatch, f"""<html><title>Service Directory</title><body>
      <h1>Onion service index</h1><ul>{rows}</ul></body></html>""")

    assert parent["primary_category"] == "directory_index"
    assert parent["page_type"] == "link_repository"
    assert parent["page_type_confidence"] == "high"
    assert parent["card_ready"] == 1
    assert parent["card_readiness_reason"] == "meaningful_structural_page"
    assert parent["link_repository_score"] >= 8
    assert parent["outbound_external_seeded"] == len(destinations)
    for url in destinations:
        child = storage.get_onion_url_by_url(url)
        assert child["status"] == "queued"
        assert child["depth"] == 1
        assert child["source_type"] == "directory_seed"
    card = site_dedupe.get_site_card(parent["site_card_id"])
    assert card["primary_category"] == "directory_index"
    assert card["page_type"] == "link_repository"
    assert "Directory" in card["safe_summary"] or "repository" in card["safe_summary"]


def test_adult_child_majority_cannot_poison_safe_structural_directory(isolated_db, monkeypatch):
    safe = f"http://{_host('g')}/"
    adult_urls = ["http://" + letter * 56 + ".onion/porn" for letter in "bcde"]
    adult_rows = "".join(f"<li><a href='{url}'>Explicit unsafe anchor {index}</a></li>"
                         for index, url in enumerate(adult_urls))
    parent = _crawl(monkeypatch, f"""<html><title>Mixed Service Directory</title><body>
      <h1>Useful onion index</h1><p>Curated public service destinations.</p><ul>
      {adult_rows}<li><a href='{safe}'>Search service</a></li></ul></body></html>""")

    assert parent["primary_category"] == "directory_index"
    assert parent["page_type"] == "link_repository"
    assert parent["adult_outbound_count"] == 0
    assert parent["child_adult_link_count"] == 0
    assert parent["child_restricted_link_count"] == 0
    assert storage.get_onion_url_by_url(safe)["status"] == "queued"
    for url in adult_urls:
        child = storage.get_onion_url_by_url(url)
        assert child["primary_category"] == "unknown"
        assert child["active"] == 1
    with storage.get_db() as db:
        stored_anchors = [str(row[0] or "") for row in db.execute(
            "SELECT safe_anchor_text FROM onion_edges WHERE source_url=?", (PARENT,))]
    assert not any("explicit unsafe" in value.casefold() for value in stored_anchors)
    assert "Directory" in parent["safe_summary"] or "repository" in parent["safe_summary"]


def test_mixed_directory_blocks_file_but_keeps_interaction_route_as_hint(isolated_db, monkeypatch):
    safe_urls = [f"http://{_host(letter)}/" for letter in "bcd"]
    adult = "http://" + "e" * 56 + ".onion/porn"
    severe = f"http://{_host('f')}/csam"
    file_url = f"http://{_host('g')}/archive.zip"
    login_url = f"http://{_host('h')}/login"
    links = [(url, f"Safe entry {index}") for index, url in enumerate(safe_urls)] + [
        (adult, "Unsafe adult anchor"), (severe, "Unsafe restricted anchor"),
        (file_url, "Download archive"), (login_url, "Account login"),
    ]
    rows = "".join(f"<li><a href='{url}'>{label}</a></li>" for url, label in links)
    parent = _crawl(monkeypatch, f"""<html><title>Onion Link Directory</title><body>
      <h1>Service directory index</h1><ul>{rows}</ul></body></html>""")

    assert parent["primary_category"] == "directory_index"
    assert parent["page_type"] == "link_repository"
    assert parent["child_adult_link_count"] == 0
    assert parent["child_restricted_link_count"] == 0
    # A file extension is an enforceable transport/download rule.  A `/login`
    # path is only an unverified route hint; the destination's returned HTML is
    # required before assigning a page type or content policy.
    assert parent["child_blocked_link_count"] == 1
    assert parent["outbound_file_blocked"] == 1
    assert parent["outbound_login_transaction_blocked"] == 0
    assert parent["outbound_external_seeded"] == 6
    for url in (*safe_urls, adult, severe, login_url):
        assert storage.get_onion_url_by_url(url)["status"] == "queued"
    child = storage.get_onion_url_by_url(file_url)
    assert child["active"] == 0 and child["queue_policy"] == "blocked"
    login_child = storage.get_onion_url_by_url(login_url)
    assert login_child["primary_category"] == "unknown"
    assert login_child["page_type"] == "unknown"
    assert login_child["active"] == 1
    evidence = json.loads(parent["child_link_evidence_json"])
    assert evidence["file_or_download_blocked"] == 1
    assert evidence["login_cart_contact_blocked"] == 0
    card = site_dedupe.get_site_card(parent["site_card_id"])
    assert card["child_blocked_link_count"] == 1
    assert card["child_restricted_link_count"] == 0

    app = AppTest.from_file(str(Path(__file__).parents[1] / "dashboard.py"), default_timeout=25).run()
    app.sidebar.radio[0].set_value("Site Cards").run()
    next(item for item in app.button if str(item.key).startswith("compact-review-False-")).click().run()
    assert not app.exception
    assert not any("unsafe child links were filtered individually"
                   in str(item.value).casefold() for item in app.caption)
    technical = " ".join(str(item.value) for item in app.json)
    assert "child_blocked_link_count" in technical
    assert "child_restricted_link_count" in technical
    assert "parent_evidence" in technical and "child_link_evidence" in technical


def test_true_adult_parent_still_filters_before_expansion(isolated_db, monkeypatch):
    safe = f"http://{_host('b')}/"
    parent = _crawl(monkeypatch, f"""<html><title>Pornographic adult content</title><body>
      <h1>Explicit adult pornography</h1><p>Adult porn gallery and explicit content.</p>
      <a href='{safe}'>Other destination</a></body></html>""")
    assert parent["primary_category"] == "adult_filtered"
    assert parent["active"] == 0
    assert parent["screenshot_policy"] == "blocked"
    assert parent["card_ready"] == 0
    assert storage.get_onion_url_by_url(safe) is None
