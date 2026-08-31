import site_dedupe
import storage
import onion_worker
from universal_classifier import classify


HOST = "d" * 56 + ".onion"
URL = f"http://{HOST}/"


def _persist_html(url: str, html: str) -> tuple[int, dict]:
    title, meta, visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = classify(
        url, title=title, meta=meta, visible_text=visible,
        classification_scope="page", page_structure=structure)
    policy = onion_worker.finalize_page_policy(
        url, policy, title=title, page_structure=structure)
    url_id = storage.insert_or_update_onion_url(url, HOST)
    storage.apply_onion_policy(
        url, policy, 200, checked=True, page_structure=structure)
    return url_id, policy


def test_crypto_mention_alone_is_not_financial_fraud():
    policy = classify(URL, title="Crypto blog", visible_text="Bitcoin wallet crypto payment notes and money news.")

    assert policy["risk_category"] != "financial_fraud"
    assert policy["primary_category"] != "fraud_financial"
    assert policy["urgent_flag"] is False


def test_wallet_contact_page_alone_is_not_financial_fraud():
    policy = classify(URL + "contact", title="Contact", visible_text="Contact us by email. Donation wallet and PGP key.")

    assert policy["risk_category"] != "financial_fraud"
    assert policy["primary_category"] not in {"fraud_financial", "marketplace_fraud"}
    assert policy["urgent_flag"] is False


def test_forum_with_mixed_risk_links_is_forum_needs_review_not_fraud_certainty():
    policy = classify(URL + "forum", title="Community forum",
                      visible_text="Discussion forum with threads about privacy, markets, fraud links, and general chat.")

    assert policy["site_type"] == "forum"
    assert policy["risk_category"] in {"needs_review", "unknown", "mixed"}
    assert policy["primary_category"] != "fraud_financial"
    assert policy["urgent_flag"] is False


def test_directory_with_fraud_links_is_context_only_not_urgent():
    policy = classify(URL + "wiki", title="Hidden Wiki link directory",
                      visible_text="Onion directory link list with carding shops, fullz markets and many other outbound links.")

    assert policy["site_type"] in {"directory", "link_list"}
    assert policy["context_only"] is True
    assert policy["primary_category"] == "directory_index"
    assert policy["urgent_flag"] is False


def test_explicit_carding_fullz_cashout_becomes_financial_fraud():
    policy = classify(URL + "thread/1", title="Cashout method",
                      visible_text="Carding fullz cashout CVV dumps and bank logs direct offer.")

    assert policy["risk_category"] == "financial_fraud"
    assert policy["primary_category"] == "fraud_financial"
    assert policy["urgent_flag"] is False
    assert policy["urgent_score"] < 70


def test_metadata_limited_direct_marketplace_without_spain_is_not_urgent():
    policy = classify(URL + "market", title="Marketplace",
                      visible_text="Vendor product listing order cart checkout wallet deposit escrow global shipping.")

    assert policy["storage_policy"] == "metadata_limited"
    assert policy["site_type"] == "marketplace"
    assert policy["spain_priority"] is False
    assert policy["urgent_flag"] is False
    assert policy["review_status"] == "monitor"


def test_generic_marketplace_site_card_rolls_up_to_monitor_with_safe_name(isolated_db):
    url_id, policy = _persist_html(
        URL + "market", "<html><head><title>Best Financial Market</title></head><body>"
        "Vendor product listing order cart checkout wallet deposit escrow global shipping."
        "</body></html>")
    policy.update(safe_display_name="Best Financial Market", safe_site_name="Best Financial Market")
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Best Financial Market")
    site_dedupe.update_site_card_rollups(card_id)

    card = site_dedupe.get_site_card_detail(card_id)
    assert card["review_status"] == "monitor"
    assert card["triage_level"] == "needs_check"
    assert card["display_name"] == "Best Financial Market"


def test_metadata_limited_direct_marketplace_with_strong_spain_context_can_be_urgent():
    policy = classify(URL + "market", title="Marketplace",
                      visible_text="Vendor product listing order cart checkout wallet deposit escrow shipping to Spain Madrid.")

    assert policy["storage_policy"] == "metadata_limited"
    assert policy["screenshot_policy"] == "blocked"
    assert policy["site_type"] == "marketplace"
    assert policy["urgent_flag"] is False
    assert policy["spain_evidence_score"] < 75

    strong_policy = classify(URL + "market/spain", title="Marketplace",
                             visible_text="Vendor product listing order escrow shipping to Spain Correos Bizum Madrid.")
    assert strong_policy["spain_priority"] is True
    assert strong_policy["spain_evidence_score"] >= 75
    assert strong_policy["urgent_flag"] is True


def test_adult_context_directory_is_not_urgent():
    policy = classify(URL + "links", title="Onion directory",
                      visible_text="Link directory with adult outbound links and general categories.")

    assert policy["site_type"] in {"directory", "link_list"}
    assert policy["urgent_flag"] is False


def test_severe_safety_signal_is_blackholed_without_urgent_preview_or_enrichment():
    policy = classify(
        URL + "restricted", title="Restricted archive",
        visible_text="Childporn video archive advertised for download and exchange.")

    assert policy["primary_category"] == "severe_abuse_risk"
    assert policy["risk_level"] == "critical"
    assert policy["urgent_flag"] is False
    assert policy["alert_allowed"] is False
    assert policy["report_allowed"] is False
    assert policy["card_allowed"] is False
    assert policy["storage_policy"] == "metadata_only"
    assert policy["queue_policy"] == "blocked"
    assert policy["screenshot_policy"] == "blocked"


def test_enrichment_rollup_does_not_overwrite_manual_category_or_analyst_wins(isolated_db):
    url_id, base = _persist_html(
        URL, "<html><head><title>Crypto contact market</title></head><body>"
        "Vendor product listing order cart checkout wallet deposit escrow global shipping."
        "</body></html>")
    card_id = site_dedupe.ensure_url_site_card(url_id, base, title="Crypto contact")
    site_dedupe.apply_manual_category(card_id, "hosting_services")
    child_id, child = _persist_html(
        URL + "about", "<html><head><title>About</title></head><body>"
        "Carding fullz cashout CVV dumps and bank logs direct offer."
        "</body></html>")
    site_dedupe.ensure_url_site_card(child_id, child, title="About")

    site_dedupe.update_site_card_rollups(card_id)

    card = site_dedupe.get_site_card_detail(card_id)
    assert card["analyst_category"] == "hosting_services"
    assert card["primary_category"] == "hosting_services"
    assert card["risk_category"] == "financial_fraud"
