from __future__ import annotations

import onion_worker
import storage
from universal_classifier import classify
from urgency_policy import decide_triage

HOST = "a" * 56 + ".onion"


def url(path: str = "/") -> str:
    return f"http://{HOST}{path}"


def _classify_html(destination, html):
    title, meta, visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", destination)
    policy = onion_worker._classify_fetched_page(
        destination, title=title, meta=meta, visible_text=visible,
        source_url=None, source_context=None, page_structure=structure)
    return onion_worker.finalize_page_policy(
        destination, policy, title=title, page_structure=structure), structure


def test_spanish_language_only_is_not_spain_priority_or_urgent():
    policy = classify(url("/es/"), title="Noticias", visible_text="servicios privados informacion para usuarios")
    assert policy["spanish_language_detected"] is True
    assert policy["spain_relevance"] in {"none", "low"}
    assert policy["seller_geo_confidence"] == "none"
    assert policy["spain_priority"] is False
    assert policy["urgent_flag"] is False


def test_dot_es_without_threat_context_is_not_spain_priority():
    policy = classify("http://example.es/", title="Company page",
                      visible_text="empresa servicios noticias contacto usuarios")
    assert policy["spain_priority"] is False
    assert policy["spain_relevance"] in {"none", "low"}
    assert policy["urgent_flag"] is False


def test_spanish_city_without_threat_context_is_not_spain_priority():
    policy = classify(url("/info"), title="Travel info",
                      visible_text="Madrid Barcelona Sevilla tourism restaurants and local events")
    assert policy["spain_priority"] is False
    assert policy["urgent_flag"] is False


def test_dot_es_route_is_only_a_language_hint_below_priority_gate():
    policy = classify("http://example.es/leak", title="Database leak",
                      visible_text="Spanish company clientes database leak credentials breach")
    assert policy["spain_priority"] is False
    assert policy["spain_actionable"] is False
    assert policy["spain_evidence_type"] in {None, "language_only"}
    assert policy["spain_evidence_score"] < 75
    decision = decide_triage([policy])
    assert decision.level == "monitor"


def test_single_dni_database_context_is_evidence_but_below_priority_gate():
    policy = classify(url("/leak"), title="Database leak",
                      visible_text="DNI database leak clientes credentials breach")
    assert policy["spain_priority"] is False
    assert policy["spain_actionable"] is False
    assert policy["spain_evidence_type"] == "spanish_identity_data"
    assert policy["spain_evidence_score"] < 75
    assert policy["urgent_flag"] is False


def test_dni_passport_sale_leak_context_crosses_priority_gate():
    policy = classify(url("/sale"), title="Spanish documents",
                      visible_text="DNI pasaporte espanol database leak credentials for sale vendor")
    assert policy["spain_priority"] is True
    assert policy["spain_relevance"] == "high"
    assert policy["spain_actionable"] is True
    assert policy["spain_evidence_type"] == "spanish_identity_data"
    assert policy["spain_evidence_score"] >= 75
    assert policy["urgent_flag"] is True


def test_spanish_bank_fraud_context_becomes_urgent_spain_evidence():
    policy = classify(url("/fraud"), title="Fraud listing",
                      visible_text="Santander BBVA CaixaBank bank logs cvv fullz carding cashout")
    assert policy["spain_priority"] is True
    assert policy["spain_relevance"] == "high"
    assert policy["spain_evidence_type"] == "spanish_financial_target"
    assert policy["urgent_flag"] is True


def test_overlapping_bank_aliases_count_as_one_evidence_family():
    single = classify(url("/bank"), visible_text="Banco Santander customer records breached")
    repeated = classify(
        url("/bank-repeat"),
        visible_text="Banco Santander Santander Banco Santander customer records breached",
    )
    assert [family for family in repeated["spain_evidence_families"] if family.startswith("bank_")] == [
        "bank_santander"
    ]
    assert repeated["spain_evidence_score"] == single["spain_evidence_score"]


def test_distant_title_and_footer_signals_do_not_combine_into_priority():
    policy = classify(
        url("/news"),
        title="Banco Santander",
        visible_text=("general information and navigation " * 40) + "customer records breached",
    )
    assert policy["spain_priority"] is False
    assert policy["spain_actionable"] is False
    assert policy["spain_evidence_score"] < 75
    assert policy["spain_evidence_type"] is None


def test_spanish_institution_with_nearby_breach_is_high_confidence_not_seller_geo():
    policy = classify(
        url("/institution"),
        visible_text="Policia Nacional customer records breached and exfiltrated",
    )
    assert policy["spain_evidence_type"] == "spanish_institution_target"
    assert policy["spain_evidence_score"] >= 75
    assert policy["spain_priority"] is True
    assert policy["seller_geo_confidence"] == "none"


def test_spanish_bank_target_does_not_claim_seller_location():
    policy = classify(
        url("/bank-target"),
        visible_text="Banco Santander customer records leaked and offered for sale",
    )
    assert policy["spain_evidence_type"] == "spanish_financial_target"
    assert policy["spain_priority"] is True
    assert policy["seller_geo_confidence"] == "none"


def test_directory_with_spain_links_is_context_only_not_actionable():
    policy = classify(
        url("/wiki"),
        title="Hidden Wiki",
        visible_text="Onion directory link list. Spain market links, Spanish vendors, Madrid labels.",
    )
    assert policy["site_type"] in {"directory", "link_list"}
    assert policy["spain_context_only"] is True
    assert policy["spain_actionable"] is False
    assert policy["spain_priority"] is False
    assert policy["urgent_flag"] is False


def test_search_page_uses_canonical_context_role_before_spain_scoring(isolated_db):
    policy, _structure = _classify_html(
        url("/search"), """<html><head><title>Search</title></head><body>
        <form><label>Search</label><input name='q'><button>Search</button></form>
        <p>DNI pasaporte espanol database leak credentials for sale vendor</p>
        </body></html>""")
    assert policy["page_type"] == "search_results"
    assert policy["spain_context_only"] is True
    assert policy["spain_priority"] is False


def test_direct_spain_seller_page_becomes_actionable_priority_and_urgent():
    policy = classify(
        url("/vendor/123"),
        title="Vendor listing",
        visible_text="Vendor listing order escrow envio desde Espana Correos Bizum Madrid Sevilla shipping.",
    )
    assert policy["spain_relevance"] == "high"
    assert policy["seller_geo_confidence"] == "high"
    assert policy["spain_actionable"] is True
    assert policy["spain_priority"] is True
    assert policy["urgent_flag"] is True


def test_direct_fraud_page_with_spain_evidence_is_metadata_limited_priority():
    policy = classify(
        url("/listing/fullz"),
        title="Carding listing",
        visible_text="Direct offer fullz cvv dumps cashout order escrow Bizum IBAN ES Madrid pago nacional.",
    )
    assert policy["risk_category"] == "financial_fraud"
    assert policy["storage_policy"] == "metadata_limited"
    assert policy["screenshot_policy"] == "blocked"
    assert policy["spain_relevance"] in {"medium", "high"}
    assert policy["spain_priority"] is True
    assert policy["urgent_flag"] is True


def test_market_review_mentioning_spain_is_context_only_not_urgent():
    policy = classify(
        url("/review"),
        title="Market review",
        visible_text="Market review: some vendors ship to Spain and Madrid. This is a review only, no direct order.",
    )
    assert policy["site_type"] == "market_review"
    assert policy["spain_context_only"] is True
    assert policy["spain_actionable"] is False
    assert policy["spain_priority"] is False
    assert policy["urgent_flag"] is False


def test_metadata_limited_direct_marketplace_keeps_safe_spain_evidence():
    policy = classify(
        url("/market"),
        title="Marketplace",
        visible_text="Marketplace vendor product listing order escrow shipping from Spain Correos.",
    )
    assert policy["storage_policy"] == "metadata_limited"
    assert policy["spain_priority"] is True
    assert policy["spain_evidence_snippets"]
    assert policy["spain_evidence_source_path"] == "/market"


def test_severe_safety_wins_over_spain_signal():
    policy = classify(
        url("/thread"),
        visible_text="childporn video archive exchange gallery Spain Madrid",
    )
    assert policy["primary_category"] == "severe_abuse_risk"
    assert policy["storage_policy"] == "metadata_only"
    assert policy["queue_policy"] == "blocked"
    assert policy["spain_priority"] is False
    assert policy["spain_actionable"] is False


def test_context_only_spain_policy_does_not_queue_alert(isolated_db):
    destination = url("/wiki")
    policy, structure = _classify_html(
        destination, """<html><head><title>Hidden Wiki</title></head><body>
        <h1>Onion directory link list</h1><p>Spain market links, Spanish vendors,
        Madrid labels.</p></body></html>""")
    storage.insert_or_update_onion_url(destination, status="crawled")
    storage.apply_onion_policy(
        destination, policy, 200, checked=True, page_structure=structure)
    assert storage.queue_spain_alert(destination, policy) is False
