from pathlib import Path
import html

import pytest
from streamlit.testing.v1 import AppTest

import onion_worker
import site_dedupe
import storage
from universal_classifier import classify


BASE = "http://" + "n" * 56 + ".onion/"


def _classify_destination(text, *, title=None):
    page_title = title if title is not None else text
    document = (
        f"<html><head><title>{html.escape(page_title)}</title></head>"
        f"<body><article>{html.escape(text)}</article></body></html>"
    )
    parsed_title, meta, visible_text, _links, structure = onion_worker._parse(
        document.encode("utf-8"), "text/html; charset=utf-8", BASE)
    policy = classify(
        BASE, title=parsed_title, meta=meta, visible_text=visible_text,
        classification_scope="page", page_structure=structure)
    policy = onion_worker.finalize_page_policy(
        BASE, policy, title=parsed_title, page_structure=structure)
    return policy, structure, parsed_title, visible_text


@pytest.mark.parametrize(
    ("expected", "text"),
    [
        ("infosec_research", "Cybersecurity research and responsible disclosure of software vulnerabilities."),
        ("privacy_anonymity", "Digital privacy advocacy and anonymity tools with encryption guidance."),
        ("news_media", "Independent news publication focused on investigative journalism."),
        ("religion_spirituality", "Religious community with scripture study and spiritual teachings."),
        ("education_reference", "Educational resource with academic research and an online library."),
        ("technology_software", "Open source software development and developer documentation."),
        ("finance_cryptocurrency", "Bitcoin community with cryptocurrency education and blockchain research."),
        ("activism_civil_society", "Human rights organization supporting civil society and freedom of speech."),
        ("personal_blog", "Personal blog and personal journal with essays and my writing."),
        ("communication_services", "Private email service and secure messaging provider."),
        ("file_storage_sharing", "Encrypted file storage and private file sharing service."),
        ("arts_culture", "Independent arts and culture archive with literature and music reviews."),
        ("health_wellness", "Public health information and mental wellbeing resources."),
    ],
)
def test_neutral_topics_are_classified_instead_of_unknown(expected, text):
    policy, _structure, _title, _visible = _classify_destination(text)
    assert policy["primary_category"] == expected
    assert policy["classification_decision"] == "accepted"
    assert policy["storage_policy"] == "safe_summary"
    assert policy["risk_level"] == "low"
    assert policy["review_status"] == "monitor"
    assert policy["display_group"] == "Neutral / informational"


def test_hosting_service_is_classified_and_search_tagged():
    policy, _structure, _title, _visible = _classify_destination(
        "Anonymous web hosting service with VPS hosting and dedicated servers.",
        title="Anonymous web hosting")
    assert policy["primary_category"] == "hosting_services"
    assert policy["display_group"] == "Discovery"
    assert {"hosting", "web_hosting", "infrastructure"} <= set(policy["tags"])


def test_verified_threat_context_still_overrides_neutral_topic():
    religious_recruitment, *_ = _classify_destination(
        "Religious community promoting extremist recruitment and terror recruitment.")
    security_operation, *_ = _classify_destination(
        "Cybersecurity research describing a ransomware operation and malware infrastructure.")
    assert religious_recruitment["primary_category"] == "extremist_recruitment"
    assert security_operation["primary_category"] == "malware_hacking"


def test_neutral_categories_are_available_as_results_filters_and_manual_corrections(isolated_db):
    text = "Cybersecurity research and responsible disclosure with vulnerability advisories."
    policy, structure, parsed_title, visible_text = _classify_destination(
        text, title="Security research")
    policy.update(
        card_ready=1, card_readiness_reason="classified_meaningful_page",
        card_readiness_confidence="high")
    url_id = storage.insert_or_update_onion_url(
        BASE, "n" * 56 + ".onion", status="crawled")
    storage.apply_onion_policy(
        BASE, policy, 200, checked=True, page_structure=structure)
    site_dedupe.ensure_url_site_card(
        url_id, policy, title=parsed_title, visible_text=visible_text)

    assert "infosec_research" in site_dedupe.ANALYST_CATEGORY_OPTIONS
    app = AppTest.from_file(str(Path(__file__).parents[1] / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value("Site Cards").run()
    assert not app.exception
    assert any(button.label.startswith("Information security / research") for button in app.button)
