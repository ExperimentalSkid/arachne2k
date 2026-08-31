from universal_classifier import classify
import onion_worker
import storage
import report_builder
import site_dedupe
from pathlib import Path


URL = "http://" + "f" * 56 + ".onion"


def _verified_html(url: str, html: str) -> tuple[dict, dict, tuple]:
    title, meta, visible, links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = classify(
        url, title=title, meta=meta, visible_text=visible,
        classification_scope="page", page_structure=structure)
    policy = onion_worker.finalize_page_policy(
        url, policy, title=title, page_structure=structure)
    return policy, structure, (title, meta, visible, links)


def test_payment_card_marketplace_is_high_priority_metadata_limited():
    policy = classify(URL + "/", title="Marketplace cloned cards digital CC fullz vendor cart checkout")
    assert policy["primary_category"] == "marketplace_fraud"
    assert policy["risk_level"] in {"high", "critical"}
    assert policy["storage_policy"] == "metadata_limited"
    assert policy["screenshot_policy"] == "blocked"
    assert policy["review_status"] == "monitor"
    assert policy["review_score"] >= 85 and policy["ui_priority"] >= 85
    assert {"carding", "cloned_cards", "fullz", "digital_cc", "payment_card_fraud"}.issubset(
        set(policy["secondary_categories"]))


def test_fraud_product_and_cashout_guide_are_not_unknown_low():
    product = classify(URL + "/product/4", title="digital CC fullz product listing")
    guide = classify(URL + "/guide", title="carding guide ATM cashout")
    assert product["primary_category"] == "marketplace_fraud" and product["risk_level"] != "low"
    assert guide["primary_category"] in {"fraud_financial", "marketplace_fraud"}
    assert guide["risk_level"] in {"high", "critical"}


def test_europe_alone_is_not_spain_priority_but_spain_delivery_is():
    europe = classify(URL + "/market", title="weapons marketplace delivery across Europe EU")
    spain = classify(URL + "/market", title="weapons marketplace delivery to Spain Correos Bizum Madrid")
    assert not europe["spain_priority"] and "europe_context" in europe["tags"]
    assert spain["spain_priority"]


def test_ocr_fraud_hint_does_not_become_confirmed_page_category():
    policy = classify(URL + "/shop", title="Marketplace", ocr_text="cloned cards fullz checkout")
    assert policy["primary_category"] == "marketplace"
    assert policy["primary_category"] != "marketplace_fraud"
    assert policy["screenshot_policy"] == "blocked"
    assert policy["ocr_checked"] is True


def test_fraud_repair_updates_safe_signal_row(isolated_db):
    url = URL + "/legacy"
    policy, structure, parsed = _verified_html(
        url, "<html><head><title>Carding market</title></head><body>"
        "Marketplace cloned cards digital CC fullz vendor cart checkout."
        "</body></html>")
    title, meta, visible, links = parsed
    url_id = storage.insert_or_update_onion_url(url)
    storage.store_fetched_page_snapshot(
        url_id, url, worker_id=None, response_status=200, content_type="text/html",
        headers={}, title=title, meta_text=meta, visible_text=visible,
        link_records=links, page_structure=structure,
        pre_policy={"primary_category": "unknown", "storage_policy": "safe_summary"})
    with storage.get_db() as db:
        db.execute("""UPDATE fetched_pages SET classification_status='done',verified_at=?
          WHERE onion_url_id=?""", (storage.utc_now_iso(), url_id))
        db.execute("""UPDATE onion_urls SET primary_category='unknown',category='unknown',
          content_category='unknown',risk_level='low',safe_signal_labels='["payment_card_fraud_signal"]',
          classification_evidence_source='unverified',destination_html_evidence_version=0
          WHERE id=?""", (url_id,))
    assert onion_worker.repair_fraud_marketplace_classification(True)["updated"] == 1
    assert storage.get_onion_url_by_url(url)["primary_category"] == "unknown"
    assert onion_worker.repair_fraud_marketplace_classification(False)["updated"] == 1
    row = storage.get_onion_url_by_url(url)
    assert row["primary_category"] == "marketplace_fraud"
    assert row["risk_level"] in {"high", "critical"}
    assert onion_worker.repair_fraud_marketplace_classification(False)["updated"] == 0


def test_fraud_marketplace_reports_omit_raw_titles_and_previews(isolated_db, tmp_path, monkeypatch):
    url = URL + "/product/7"
    raw_title = "RAW_UNSAFE_PRODUCT_DESCRIPTION"
    policy, structure, _parsed = _verified_html(
        url, "<html><head><title>Carding marketplace</title></head><body>"
        "Marketplace cloned cards digital CC fullz vendor product cart checkout."
        "</body></html>")
    url_id = storage.insert_or_update_onion_url(url)
    storage.apply_onion_policy(
        url, policy, 200, checked=True, page_structure=structure)
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET title=? WHERE id=?", (raw_title, url_id))
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title=raw_title)
    preview = tmp_path / "unsafe-preview.png"
    preview.write_bytes(b"not-an-image")
    storage.upsert_page_preview(url, str(preview))
    monkeypatch.setattr(report_builder, "REPORTS_DIR", tmp_path / "reports")
    url_report = Path(report_builder.build_url_report(url, "pytest")).read_text(encoding="utf-8")
    card_report = Path(report_builder.build_site_card_report(card_id, "pytest")).read_text(encoding="utf-8")
    for content in (url_report, card_report):
        assert raw_title not in content
        assert str(preview) not in content
        assert "metadata-limited" in content.casefold()
