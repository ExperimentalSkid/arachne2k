from pathlib import Path

from streamlit.testing.v1 import AppTest

import onion_worker
import site_dedupe
import storage
from universal_classifier import classify


HOST = "a" * 56 + ".onion"
MARKET = f"http://{HOST}/"
ADULT_CATEGORY = f"http://{HOST}/adult"


class _Response:
    status_code = 200
    headers = {"Content-Type": "text/html"}

    def __init__(self, body): self.body = body.encode()
    def iter_content(self, chunk_size=16384): yield self.body
    def close(self): return None


class _Session:
    def __init__(self, body): self.response = _Response(body)
    def get(self, *_args, **_kwargs): return self.response


def _crawl(isolated_db, monkeypatch, body):
    storage.insert_or_update_onion_url(MARKET, HOST, status="queued",
                                       policy=classify(MARKET, visible_text="ordinary homepage"))
    monkeypatch.setattr(onion_worker, "_session", lambda: _Session(body))
    monkeypatch.setattr(onion_worker, "capture_page_screenshot",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("screenshot attempted")))
    assert onion_worker.process_one()
    return storage.get_onion_url_by_url(MARKET)


def _mixed_market_html():
    return f"""<html><title>Example Marketplace</title><body><h1>Marketplace Categories</h1>
      <p>General marketplace navigation</p>
      <a href='{MARKET}drugs'>Drugs market</a>
      <a href='{MARKET}fraud'>Fraud market</a>
      <a href='{MARKET}services'>Services marketplace</a>
      <a href='{ADULT_CATEGORY}'>Adult category</a></body></html>"""


def test_marketplace_child_label_is_only_an_unverified_hint(isolated_db, monkeypatch):
    parent = _crawl(isolated_db, monkeypatch, _mixed_market_html())
    child = storage.get_onion_url_by_url(ADULT_CATEGORY)
    assert parent["primary_category"] == "marketplace"
    assert parent["marketplace_type"] == "general"
    assert parent["adult_category_present"] == 0
    assert parent["adult_outbound_count"] == 0 and parent["restricted_child_present"] == 0
    assert parent["storage_policy"] == "metadata_limited" and parent["ui_hidden_default"] == 0
    assert "adult_category_present" not in parent["secondary_categories"]
    assert child["primary_category"] == "unknown"
    assert child["storage_policy"] == "safe_summary" and child["active"] == 1
    assert child["screenshot_policy"] == "blocked" and child["queue_policy"] == "normal"
    assert child["status"] == "queued"

    card = next(card for card in site_dedupe.get_site_cards() if card["canonical_site_id"] == parent["canonical_site_id"])
    assert card["primary_category"] == "marketplace"
    assert card["marketplace_type"] == "general" and card["adult_category_present"] == 0
    assert card["ui_hidden_default"] == 0


def test_explicit_looking_child_majority_does_not_define_marketplace_parent(isolated_db, monkeypatch):
    adult_links = "".join(f"<a href='{MARKET}adult/{index}'>Adult category {index}</a>" for index in range(4))
    body = f"""<html><title>Example Marketplace</title><body><h1>Marketplace Categories</h1>
      {adult_links}<a href='{MARKET}services'>Services</a></body></html>"""
    parent = _crawl(isolated_db, monkeypatch, body)
    assert parent["primary_category"] == "marketplace"
    assert parent["marketplace_type"] == "general" and parent["active"] == 1
    assert parent["adult_category_present"] == 0
    assert parent["storage_policy"] == "metadata_limited"
    assert parent["site_card_id"] is not None


def test_marketplace_dashboard_does_not_present_unverified_child_as_restricted(isolated_db, monkeypatch):
    _crawl(isolated_db, monkeypatch, _mixed_market_html())
    app = AppTest.from_file(str(Path(__file__).parents[1] / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value("Site Cards").run()
    display = next(item for item in app.radio if item.label == "Display")
    display.set_value("Card view").run()
    assert not app.exception
    assert not any("Restricted marketplace category hidden" in str(item.label)
                   for item in app.button)
    assert not any(ADULT_CATEGORY in str(item.value) for item in app.code)
