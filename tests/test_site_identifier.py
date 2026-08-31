import json

from site_identifier import extract_domains, identify_site, normalize_domain
import site_dedupe
import storage


ONION = "a" * 56 + ".onion"
SECOND = "b" * 56 + ".onion"


def registry(tmp_path):
    path = tmp_path / "sites.json"
    path.write_text(json.dumps({"sites": [
        {"site_id": "alpha", "display_name": "Alpha Market", "canonical_domain": ONION,
         "domains": ["shop.example.com"], "aliases": ["Alpha Bazaar"], "brand": "Alpha",
         "country": None, "language": "en", "active": True},
        {"site_id": "beta", "display_name": "Beta Forum", "canonical_domain": SECOND,
         "domains": ["beta.example.org"], "aliases": ["Beta Board"], "brand": "Beta",
         "country": "DE", "language": "de", "active": True},
    ]}), encoding="utf-8")
    return path


def test_normalizes_full_bare_www_query_subdomain_and_case():
    assert normalize_domain("HTTPS://WWW.Example.COM/path?q=1#x") == "example.com"
    assert normalize_domain("sub.Example.com/path") == "sub.example.com"
    assert extract_domains("Visit https://WWW.Example.COM/a?track=1") == ["example.com"]


def test_exact_canonical_and_known_subdomain_matches(tmp_path):
    path = registry(tmp_path)
    canonical = identify_site({"url": f"http://{ONION}/"}, registry_path=path)
    assert canonical.site_id == "alpha" and canonical.confidence == 1.0
    known = identify_site({"url": "https://checkout.shop.example.com/a"}, registry_path=path)
    assert known.site_id == "alpha" and known.confidence == .95
    assert known.canonical_domain == ONION


def test_alias_then_source_mapping_fallback(tmp_path):
    path = registry(tmp_path)
    alias = identify_site({"title": "Welcome to Alpha Bazaar"}, registry_path=path)
    assert alias.site_id == "alpha" and alias.matched_from == "exact_alias" and alias.confidence == .85
    source = identify_site({}, {"source_site_id": "beta"}, registry_path=path)
    assert source.site_id == "beta" and source.confidence == .75


def test_multiple_registered_domains_are_ambiguous(tmp_path):
    result = identify_site({"text": f"Mirrors http://{ONION}/ and http://{SECOND}/"},
                           registry_path=registry(tmp_path))
    assert result.is_ambiguous and set(result.candidates) == {"alpha", "beta"}
    assert result.ambiguity_reason


def test_unknown_explicit_domain_is_stable_and_does_not_invent_fields(tmp_path):
    result = identify_site({"url": "https://unknown.example.net/path", "detected_title": "Unknown News"},
                           registry_path=registry(tmp_path))
    assert result.site_id.startswith("domain:") and result.domain == "unknown.example.net"
    assert result.country is None and result.brand is None and result.confidence == .60
    assert {"brand", "country", "language"} <= set(result.missing_fields)


def test_empty_malformed_email_and_partial_string_do_not_match(tmp_path):
    path = registry(tmp_path)
    for item in ({}, {"url": "not a url"}, {"text": "mail user@shop.example.com"},
                 {"text": "notAlpha Bazaarish"}):
        result = identify_site(item, registry_path=path)
        assert result.site_id is None


def test_language_hint_cannot_override_explicit_domain(tmp_path):
    result = identify_site({"url": f"http://{ONION}/", "language": "de", "country": "DE"},
                           registry_path=registry(tmp_path))
    assert result.site_id == "alpha" and result.language == "en" and result.country is None


def test_site_card_receives_explainable_identity_without_overwriting_title(isolated_db):
    url = f"http://{ONION}/"
    policy = {
        "primary_category": "directory_index", "category": "directory_index",
        "content_category": "directory_index", "tags": ["directory_index"],
        "analyst_category": "directory_index",
        "classification_evidence_source": "analyst",
        "destination_html_evidence_version": 0,
        "risk_level": "low", "confidence": "high", "risk_flags": [],
        "storage_policy": "safe_summary", "review_status": "pending",
        "screenshot_policy": "allowed", "queue_policy": "expand", "active": 1,
        "spain_priority": False, "page_type": "directory_index_page",
    }
    url_id = storage.insert_or_update_onion_url(url, ONION, policy=policy, status="queued")
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET analyst_category='directory_index',
          primary_category='directory_index',category='directory_index',
          content_category='directory_index',classification_evidence_source='analyst',
          destination_html_evidence_version=0 WHERE id=?""", (url_id,))
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Useful Link Directory")
    with storage.get_db() as db:
        db.execute("UPDATE site_cards SET analyst_title='Analyst Directory' WHERE id=?", (card_id,))
    site_dedupe.update_site_card_rollups(card_id)
    card = site_dedupe.get_site_card_detail(card_id)
    assert card["identity_domain"] == ONION
    assert card["identity_matched_from"] == "explicit_unregistered_domain"
    assert card["identity_confidence_score"] == .60
    assert card["analyst_title"] == "Analyst Directory"
    assert "country" in json.loads(card["identity_missing_fields_json"])
