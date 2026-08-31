import page_intelligence as intel
import storage


HOST = "a" * 56 + ".onion"
URL = f"http://{HOST}/"


def test_identity_uses_best_safe_title_with_provenance_and_host_fallback():
    identity = intel.extract_page_identity(
        URL, title="Home", og_title="Atlas Research Library",
        headings=["Atlas documentation"], meta_description="Public technical notes")
    assert identity["detected_title"] == "Atlas Research Library"
    assert identity["title_source"] == "og_title"
    assert identity["identity_confidence"] == "high"
    assert identity["limited_title_safe"] is True

    fallback = intel.extract_page_identity(URL)
    assert fallback["detected_title"] == HOST
    assert fallback["title_source"] == "onion_host"

    heading = intel.extract_page_identity(URL, headings=["Community Research Forum"])
    assert heading["detected_title"] == "Community Research Forum"
    assert heading["title_source"] == "page_h1"

    noisy = intel.extract_page_identity(URL, title="  Research   index  " + (" section" * 30))
    assert len(noisy["detected_title"]) <= 180
    assert "  " not in noisy["detected_title"]


def test_restricted_identity_never_exposes_page_text():
    identity = intel.extract_page_identity(
        URL, title="Sensitive listing title", headings=["Sensitive heading"],
        meta_description="Sensitive description", restricted=True,
        safe_category_label="Restricted metadata")
    assert identity["detected_title"] == "Restricted metadata"
    assert identity["safe_meta_description"] == ""
    assert identity["title_source"] == "policy_label"


def test_structural_page_type_has_safe_explainable_evidence():
    result = intel.fingerprint_page_type(URL, {
        "onion_link_count": 25, "external_onion_count": 18,
        "link_density": 0.55, "structured_lists": True,
    })
    assert result["page_type"] == "link_repository"
    assert result["page_type_confidence"] == "high"
    assert "high_edge_onion_index" in result["evidence"]
    assert "multiple_external_onion_hosts" in result["evidence"]

    login = intel.fingerprint_page_type(URL + "login", {
        "has_password_form": True, "login_markers": True,
    })
    assert login["page_type"] == "login_wall"
    assert "password_form" in login["evidence"]

    cases = [
        ({"forum_markup": True, "forum_link_count": 4}, "forum_index"),
        ({"wiki_markup": True}, "wiki_docs"),
        ({"code_markup": True}, "code_repository"),
        ({"market_markup": True, "market_link_count": 3}, "marketplace_front"),
        ({"error_markers": True}, "error_page"),
        ({"placeholder_markers": True}, "empty_placeholder"),
    ]
    for features, expected in cases:
        assert intel.fingerprint_page_type(URL, features)["page_type"] == expected


def test_legacy_url_hint_switch_cannot_assign_a_page_type():
    for path in ("viewtopic.php?t=7", "checkout", "vendor/alice", "product/42", "index.php"):
        result = intel.fingerprint_page_type(URL + path, {}, allow_url_hints=True)
        assert result["page_type"] == "unknown"
        assert not any("url" in value or "root_path" == value for value in result["evidence"])


def test_card_readiness_rejects_thin_unknown_and_accepts_meaningful_directory():
    base_policy = {"primary_category": "unknown", "storage_policy": "safe_summary",
                   "review_status": "pending", "spain_priority": False}
    identity = intel.extract_page_identity(URL, title="Index")
    unknown = intel.compute_card_readiness(
        base_policy, identity,
        {"page_type": "unknown", "page_type_confidence": "low"}, {}, "thin")
    assert unknown["card_ready"] is False
    assert unknown["card_readiness_reason"] == "insufficient_page_evidence"

    directory = intel.compute_card_readiness(
        base_policy, identity,
        {"page_type": "link_repository", "page_type_confidence": "high"},
        {"external_onion_count": 12}, "meaningful")
    assert directory["card_ready"] is True
    assert directory["card_readiness_reason"] == "meaningful_structural_page"
    assert "12 external onion destinations" in directory["safe_summary"]

    error = intel.compute_card_readiness(
        base_policy, identity,
        {"page_type": "error_page", "page_type_confidence": "high"}, {}, "empty")
    assert error["card_ready"] is False
    assert error["card_readiness_reason"] == "empty_error_or_placeholder"

    confirmed = intel.compute_card_readiness(
        base_policy, identity,
        {"page_type": "unknown", "page_type_confidence": "low"}, {}, "thin",
        analyst_confirmed=True)
    assert confirmed["card_ready"] is True
    assert confirmed["card_readiness_reason"] == "analyst_confirmed"

    spain_policy = dict(base_policy, spain_priority=True, spain_confidence="high")
    spain = intel.compute_card_readiness(
        spain_policy, identity,
        {"page_type": "unknown", "page_type_confidence": "low"}, {}, "thin")
    assert spain["card_ready"] is True
    assert "explicit Spain-specific evidence" in spain["safe_summary"]


def test_link_context_is_capped_and_restricted_anchor_is_hidden():
    context = intel.classify_link_context(
        URL + "thread/42", anchor_text="A" * 500,
        source_page_type="forum_home", same_host=True)
    assert context["relation_type"] == "forum_link"
    assert context["relation_verified"] is False
    assert context["evidence_source"] == "discovery_metadata"
    assert len(context["safe_anchor_text"]) == 120

    hidden = intel.classify_link_context(
        URL + "adult", anchor_text="unsafe child label", restricted=True,
        policy_reason="adult_content_filtered")
    assert hidden["safe_anchor_text"] == "Restricted child link hidden"
    assert "unsafe" not in hidden["safe_anchor_text"].casefold()


def test_edge_context_and_intelligence_columns_migrate_safely(isolated_db):
    storage.init_db()
    source = URL
    child = "http://" + "b" * 56 + ".onion/"
    storage.insert_onion_edge(source, child, {
        "relation_type": "directory_entry", "safe_anchor_text": "Research index",
        "source_page_type": "link_repository", "same_host": False,
        "policy_reason": "safe_link",
    })
    with storage.get_db() as db:
        url_columns = {row[1] for row in db.execute("PRAGMA table_info(onion_urls)")}
        edge = db.execute(
            "SELECT relation_type,safe_anchor_text,source_page_type,same_host,"
            "relation_verified,relation_evidence_source "
            "FROM onion_edges WHERE source_url=? AND discovered_url=?", (source, child)).fetchone()
    assert {"detected_title", "title_source", "page_type_confidence", "card_ready",
            "card_readiness_reason", "safe_summary", "outbound_onion_count"} <= url_columns
    assert tuple(edge) == ("directory_entry", "Research index", "link_repository", 0,
                           0, "discovery_metadata")
