import html

import onion_worker
from page_intelligence import fingerprint_page_type
from universal_classifier import classify


HOST = "a" * 56 + ".onion"


def _classify_destination(path, visible_text, *, title="", body_class=""):
    """Exercise the automatic classifier with destination-owned HTML only."""
    url = f"http://{HOST}{path}"
    document = (
        f"<html><head><title>{html.escape(title)}</title></head>"
        f"<body class='{html.escape(body_class)}'><div>{html.escape(visible_text)}</div></body></html>"
    )
    parsed_title, meta, text, _links, structure = onion_worker._parse(
        document.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = classify(
        url, title=parsed_title, meta=meta, visible_text=text,
        classification_scope="page", page_structure=structure)
    page_type = fingerprint_page_type(
        url, structure, current_type=str(policy.get("page_type") or "unknown"),
        allow_url_hints=False)
    if page_type["page_type_confidence"] in {"medium", "high"}:
        policy["page_type"] = page_type["page_type"]
    policy["page_type_evidence"] = page_type["evidence"]
    return policy


def test_spanish_carding_recruitment_thread_prefers_fraud():
    policy = _classify_destination(
        "/thread/42",
        "Foro de carding CVV fullz y reclutamiento para el grupo de hacking",
        title="Tema de fraude", body_class="phpbb postbody postprofile")
    assert policy["primary_category"] == "fraud_financial"
    assert policy["page_type"] == "forum_thread"
    assert policy["risk_level"] == "high"
    assert "forum_thread_markup" in policy["page_type_evidence"]
    assert "extremist_recruitment" in policy["secondary_categories"]


def test_carding_marketplace_listing_is_marketplace_fraud():
    policy = _classify_destination(
        "/listing/cards", "Carding marketplace vendor listings CVV fullz",
        title="Vendor listing", body_class="marketplace product-grid product-card")
    assert policy["primary_category"] == "marketplace_fraud"
    assert policy["storage_policy"] == "metadata_limited"


def test_clear_malware_forum_remains_malware():
    policy = _classify_destination(
        "/thread/malware", "Discussion forum ransomware exploit kit malware botnet intrusion",
        title="Malware discussion", body_class="phpbb postbody postprofile")
    assert policy["primary_category"] == "malware_hacking"


def test_mixed_fraud_hacking_uses_stronger_evidence():
    fraud = _classify_destination(
        "/thread/fraud", "carding CVV fullz hacking exploit",
        body_class="phpbb postbody postprofile")
    malware = _classify_destination(
        "/thread/ransomware", "carding ransomware botnet exploit kit intrusion",
        body_class="phpbb postbody postprofile")
    assert fraud["primary_category"] == "fraud_financial"
    assert malware["primary_category"] == "malware_hacking"


def test_defensive_research_terms_do_not_become_financial_fraud():
    policy = _classify_destination(
        "/research/phishing",
        "Phishing awareness and carding prevention for defensive security research.",
        title="Security research")

    assert policy["primary_category"] not in {"fraud_financial", "marketplace_fraud"}
    assert policy["risk_category"] != "financial_fraud"
    assert policy["review_status"] == "monitor"
    assert "defensive_or_informational_fraud_context" in policy["category_contradicting_evidence"]


def test_news_report_about_fraud_victims_remains_informational():
    policy = _classify_destination(
        "/news/report", "Investigative journalism report on stolen cards and fullz victims.",
        title="Independent news report")

    assert policy["primary_category"] == "news_media"
    assert policy["risk_category"] != "financial_fraud"
    assert policy["urgent_flag"] is False


def test_actionable_fraud_offer_still_overrides_benign_vocabulary():
    policy = _classify_destination(
        "/listing/cards",
        "Carding prevention label. Fullz and CVV for sale from vendor, order with escrow.",
        title="Security research market", body_class="marketplace product-grid product-card")

    assert policy["primary_category"] == "marketplace_fraud"
    assert policy["risk_category"] == "financial_fraud"
