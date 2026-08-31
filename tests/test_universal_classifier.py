import json
from pathlib import Path

from universal_classifier import classify, classify_url_prefetch, normalize_text


ONION = "a" * 56 + ".onion"


def test_config_rules_have_safe_audit_metadata():
    config = json.loads(Path("safety_filter_config.json").read_text(encoding="utf-8"))
    required = {"rule_id", "language", "category", "weight", "match_target",
                "action_policy", "display_safe_label", "log_safe_label"}
    assert config["rules"]
    assert all(required <= set(rule) for rule in config["rules"])
    content_rules = [rule for rule in config["rules"] if rule["category"] != "spain_priority"]
    assert all(rule["match_target"] == "destination_title_body_html"
               for rule in content_rules)


def test_final_category_ignores_all_discovery_metadata_even_when_explicit():
    url = f"http://{ONION}/childporn/adult/porn/csam"
    policy = classify(
        url,
        title="General discussion board",
        visible_text="Welcome to this community forum and its public topic index.",
        anchor_text="child porn videos",
        source_url=f"http://{ONION}/adult-section",
        source_context="csam childporn loli jailbait explicit restricted section",
        classification_scope="combined",
    )
    assert policy["primary_category"] == "forum_social"
    assert policy["storage_policy"] == "safe_summary"
    assert policy["active"] == 1


def test_adult_url_wording_is_only_an_unverified_prefetch_hint():
    policy = classify_url_prefetch(f"http://{ONION}/porn")
    assert policy["primary_category"] == "unknown"
    assert policy["risk_level"] == "low"
    assert policy["storage_policy"] == "safe_summary"
    assert policy["review_status"] == "monitor"
    assert policy["screenshot_policy"] == "blocked"
    assert policy["queue_policy"] == "normal"
    assert policy["active"] == 1
    assert policy["url_hint_present"] is True
    assert policy["spain_priority"] is False
    # Policy output contains safe labels/reasons, never a raw matched-term field.
    assert "matched_text" not in json.dumps(policy)


def test_random_v3_hostname_prefix_is_opaque_not_adult_evidence():
    url = "http://pornikhjr6ikvrtbzbjw4puyusfi3yztvrxevxhrqxqiuuyfrdfqd.onion/"
    policy = classify_url_prefetch(url)
    assert policy["primary_category"] == "unknown"
    assert policy["active"] == 1
    assert policy["queue_policy"] != "blocked"


def test_valid_pornii_v3_hostname_is_opaque_not_adult_evidence():
    url = "http://porniikhjr6ivkvrtbzbjw4puyusfi3yzytxrvexwhrqxqjuuyfrdfqd.onion/"
    policy = classify_url_prefetch(url)
    assert policy["primary_category"] == "unknown"
    assert policy["storage_policy"] == "safe_summary"
    assert policy["active"] == 1


def test_high_risk_categories_use_limited_metadata():
    cases = {
        "weapons trafficking": "weapons_arms",
        "drug market": "marketplace_drugs",
        "credential dump": "credentials",
        "malware infrastructure": "malware_hacking",
        "extremist recruitment": "extremist_recruitment",
        "data leak": "leaks_data",
        "carding": "fraud_financial",
    }
    for text, expected in cases.items():
        policy = classify(f"http://{ONION}/", visible_text=text)
        assert policy["primary_category"] == expected
        assert policy["storage_policy"] == "metadata_limited"
        assert policy["screenshot_policy"] == "blocked"


def test_spain_accents_and_weak_city_context():
    for text in ("España", "Espana"):
        assert classify(f"http://{ONION}/", visible_text=text)["spain_priority"] is False
    for text in ("Policía Nacional", "Policia Nacional", "Guardia Civil"):
        policy = classify(f"http://{ONION}/", visible_text=text)
        assert policy["spain_priority"] is False
        assert policy["spain_relevance"] in {"low", "medium"}
    assert normalize_text("Málaga") == "malaga"
    assert normalize_text("Cádiz") == "cadiz"
    assert normalize_text("Córdoba") == "cordoba"
    assert classify(f"http://{ONION}/", visible_text="Sevilla tourism")["spain_priority"] is False
    leak = classify(f"http://{ONION}/", visible_text="Sevilla filtración de datos")
    assert leak["spain_priority"] is False
    assert leak["spain_relevance"] == "low"


def test_russian_and_mixed_language_spain_detection():
    assert classify(f"http://{ONION}/", visible_text="Испания")["spain_priority"] is False
    for text in (
        "испанская полиция",
        "Гражданская гвардия",
        "МВД Испании",
        "Мадрид утечка данных",
        "Испания НАТО вербовка",
        "новости Guardia Civil на русском",
    ):
        policy = classify(f"http://{ONION}/", visible_text=text)
        assert policy["spain_priority"] is False, text
        assert policy["spain_relevance"] in {"none", "low", "medium"}, text
        if policy["spain_relevance"] != "none":
            assert policy["spain_match_language"] in {"RU", "MIXED"}


def test_spain_trade_flow_is_high_confidence_and_keeps_intelligence_category():
    to_spain = classify(f"http://{ONION}/", visible_text="Weapons vendor shipping to Spain with Correos Bizum DNI Madrid")
    assert to_spain["primary_category"] == "weapons_arms"
    assert to_spain["storage_policy"] == "metadata_limited"
    assert to_spain["spain_priority"] is True
    assert to_spain["spain_confidence"] == "high"
    assert "trade_flow_to_spain" in to_spain["spain_context_tags"]

    from_spain = classify(f"http://{ONION}/", visible_text="Order dispatch from Spain with Correos Bizum DNI Madrid")
    assert from_spain["spain_priority"] is True
    assert from_spain["spain_confidence"] == "high"
    assert "trade_flow_from_spain" in from_spain["spain_context_tags"]

    adult_hint_only = classify(f"http://{ONION}/porn", visible_text="shipping to Spain")
    assert adult_hint_only["primary_category"] != "adult_filtered"
    assert adult_hint_only["spain_priority"] is False


def test_page_scope_requires_corroboration_for_generic_threat_words():
    generic = classify(
        f"http://{ONION}/article",
        title="Museum bulletin",
        visible_text="A historical exhibit uses the word weapons once in an educational caption.",
        classification_scope="page",
    )
    contextual = classify(
        f"http://{ONION}/thread/4",
        title="Shipping discussion",
        visible_text="Weapons vendor shipping and delivery to Spain.",
        classification_scope="page",
    )
    assert generic["primary_category"] != "weapons_arms"
    assert contextual["primary_category"] == "weapons_arms"


def test_weapons_requires_independent_commercial_or_actionable_evidence():
    harmless = [
        "A museum exhibit about historical weapons",
        "Airsoft guns in a video game guide",
        "News report about a weapons policy debate",
        "General discussion mentioning firearms once",
    ]
    for text in harmless:
        policy = classify(f"http://{ONION}/article", visible_text=text, classification_scope="page")
        assert policy["primary_category"] != "weapons_arms"
        assert policy["weapons_evidence_score"] < 60
    seller = classify(
        f"http://{ONION}/vendor/arms",
        visible_text="Firearms vendor listing. Rifles for sale with shipping and contact details.",
        classification_scope="page",
    )
    assert seller["primary_category"] in {"weapons_arms", "marketplace_weapons"}
    assert seller["weapons_evidence_score"] >= 60
    assert seller["weapons_commercial_context"] is True
    assert {"weapon_terminology", "commercial_context", "seller_or_listing_structure"} <= set(
        seller["weapons_evidence_families"]
    )
