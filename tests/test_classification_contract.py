
from classification_schema import (CONTENT_CATEGORIES, PAGE_TYPES, SAFETY_STATES,
                                   apply_classification_contract, normalize_content_category,
                                   normalize_page_type)
import site_dedupe
import storage


HOST = "a" * 56 + ".onion"
URL = f"http://{HOST}/"


def _contract(category, page_type, *, previous="unknown", quality="meaningful",
              evidence=None, scope=None, restricted_child=False,
              previous_trusted=None):
    policy = {
        "primary_category": category, "category": category, "storage_policy": "safe_summary",
        "category_confidence": "low", "evidence_families": evidence or [], "match_scope": scope,
        "restricted_child_present": restricted_child,
    }
    page = {"page_type": page_type, "page_type_confidence": "high", "evidence": evidence or []}
    return apply_classification_contract(
        policy, {"title_source": "html_title"}, page,
        {"url": URL, "external_onion_count": 8}, quality, previous_category=previous,
        previous_category_trusted=(previous != "unknown" if previous_trusted is None
                                   else previous_trusted))


def _policy(category, page_type, confidence="high", **extra):
    result = {
        "primary_category": category, "category": category, "content_category": category,
        "tags": [category], "page_type": page_type, "page_type_confidence": confidence,
        "category_confidence": confidence, "category_update_allowed": 1,
        "category_update_reason": "confidence_weighted_page_evidence",
        "risk_level": "low", "confidence": confidence, "risk_flags": [],
        "storage_policy": "safe_summary", "review_status": "pending",
        "safety_reason": category, "priority_score": 10, "screenshot_policy": "allowed",
        "queue_policy": "normal", "active": 1, "spain_priority": False,
        "card_ready": 1, "content_quality": "meaningful",
        "category_evidence": {"link_pattern": ["test_structure"]},
        "category_supporting_evidence": ["test_structure"],
        "category_contradicting_evidence": [], "safety_state": "safe",
        # These helpers create setup rows for rollup/identity tests; the
        # category is an explicit analyst fixture rather than a URL-derived
        # automatic classification.
        "analyst_category": category,
        "classification_evidence_source": "analyst",
    }
    result.update(extra)
    return result


def _insert_analyst_fixture(url, policy, *, status="crawled"):
    """Persist a setup-only analyst decision through the central writer."""
    onion_host = url.split("/", 3)[2]
    url_id = storage.insert_or_update_onion_url(url, onion_host, status=status)
    category = policy["analyst_category"]
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET analyst_category=?,primary_category=?,
          category=?,content_category=?,classification_evidence_source='analyst'
          WHERE id=?""", (category, category, category, category, url_id))
    storage.apply_onion_policy(url, policy)
    return url_id


def _add(url, policy, title="Detected title"):
    url_id = _insert_analyst_fixture(url, policy)
    return site_dedupe.ensure_url_site_card(url_id, policy, title=title, visible_text="safe structure")


def test_canonical_enums_and_legacy_names_normalize_safely():
    assert normalize_page_type("forum_home") == normalize_page_type("forum_index") == "forum_index"
    assert normalize_page_type("directory_page") == "directory_index_page"
    assert normalize_page_type("link_repository") == "link_repository"
    assert normalize_content_category("forum_home") == "forum_social"
    assert normalize_content_category("login_gate") == "unknown"
    assert {"unknown", "marketplace", "directory_index"} <= CONTENT_CATEGORIES
    assert {"forum_index", "marketplace_front", "error_page"} <= PAGE_TYPES
    assert {"safe", "metadata_limited", "metadata_only", "filtered"} <= SAFETY_STATES


def test_database_migration_normalizes_legacy_page_labels(isolated_db):
    item_id = _insert_analyst_fixture(URL, _policy("forum_social", "forum_index"))
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET page_type='forum_home',content_category='forum_home' WHERE id=?",
                   (item_id,))
    storage.init_db()
    with storage.get_db() as db:
        row = db.execute("SELECT primary_category,content_category,page_type FROM onion_urls WHERE id=?",
                         (item_id,)).fetchone()
    assert tuple(row) == ("forum_social", "forum_social", "forum_index")


def test_directory_marketplace_links_do_not_define_parent_category():
    policy = {
        "primary_category": "marketplace", "category": "marketplace",
        "content_category": "marketplace", "storage_policy": "metadata_limited",
        "category_confidence": "high", "evidence_families": ["high_edge_onion_index"],
        "site_type": "marketplace", "category_safe_label": "Marketplace context",
        "display_group": "Marketplaces", "marketplace_type": "general",
        "tags": ["marketplace"], "secondary_categories": ["marketplace"],
    }
    result = apply_classification_contract(
        policy, {"title_source": "html_title"},
        {"page_type": "link_repository", "page_type_confidence": "high",
         "evidence": ["high_edge_onion_index"]},
        {"url": URL, "external_onion_count": 8}, "meaningful",
    )
    assert result["content_category"] == "directory_index"
    assert result["category_update_allowed"] is True
    assert result["category_update_reason"] == "directory_structure_accepted_child_marketplace_rejected"
    assert "marketplace_child_links_only" in result["category_contradicting_evidence"]
    assert result["site_type"] == "link_list"
    assert result["category_safe_label"] == "Directory / index"
    assert result["display_group"] == "Discovery"
    assert result["marketplace_type"] is None
    assert result["tags"] == ["directory_index"]
    assert result["secondary_categories"] == []

    primary, scores = site_dedupe._score_primary_category([
        dict(result, card_path="/", card_ready=1, content_quality="meaningful")
    ])
    assert primary == "directory_index"
    assert scores["directory_index"] > 0


def test_login_thin_and_error_pages_preserve_known_category():
    login = _contract("marketplace", "login_gate", previous="hosting_services")
    assert login["content_category"] == "hosting_services"
    assert login["page_type"] == "login_wall"
    assert login["category_update_allowed"] is False
    assert login["site_type"] == "login_portal"
    assert login["category_safe_label"] == "Hosting / services"
    assert login["display_group"] == "Discovery"

    thin = _contract("weapons_arms", "article_page", previous="forum_social", quality="thin")
    assert thin["content_category"] == "forum_social"
    assert thin["category_update_reason"] == "thin_page_preserved_previous_category"
    assert thin["site_type"] == "forum"
    assert thin["category_safe_label"] == "Forum / social"
    assert thin["display_group"] == "Discovery"

    error = _contract("marketplace", "error_page", previous="directory_index", quality="empty")
    assert error["content_category"] == "directory_index"
    assert error["category_update_allowed"] is False
    assert error["site_type"] == "directory"
    assert error["category_safe_label"] == "Directory / index"
    assert error["display_group"] == "Discovery"


def test_page_state_does_not_preserve_an_untrusted_legacy_category():
    result = _contract(
        "marketplace", "error_page", previous="adult_filtered",
        quality="empty", previous_trusted=False,
    )
    assert result["content_category"] == "unknown"
    assert result["category_update_allowed"] is False
    assert result["category_update_reason"] == "page_state_has_no_trusted_html_category"
    assert result["site_type"] == "unknown"
    assert result["category_safe_label"] == "Needs classification"
    assert result["display_group"] == "Other"


def test_url_hint_is_a_debug_hint_never_supporting_category_evidence():
    result = apply_classification_contract(
        {
            "primary_category": "unknown", "category": "unknown",
            "storage_policy": "safe_summary", "match_scope": "url",
            "category_confidence": "low", "evidence_families": [],
        },
        {"title_source": "onion_host"},
        {"page_type": "article_page", "page_type_confidence": "low", "evidence": []},
        {}, "meaningful",
    )
    assert result["category_evidence"]["url"] == ["unverified_url_hint_not_page_evidence"]
    assert "unverified_url_hint_not_page_evidence" not in result["category_supporting_evidence"]
    assert result["content_category"] == "unknown"


def test_weak_unknown_abstains_and_structural_market_calibrates_high():
    unknown = _contract("unknown", "article_page", evidence=["weak_text_hint"])
    assert unknown["category_confidence"] == "low"
    assert unknown["content_category"] == "unknown"

    market = _contract("marketplace", "marketplace_home", evidence=["marketplace_markup", "market_navigation"])
    assert market["page_type"] == "marketplace_front"
    assert market["category_confidence"] == "high"


def test_homepage_and_forum_index_outweigh_listing_and_thread_children(isolated_db):
    market_card = _add(
        URL, _policy("marketplace", "marketplace_front", site_type="marketplace"),
        "Mixed market",
    )
    for index in range(4):
        _add(
            URL + f"product/{index}",
            _policy("marketplace_drugs", "marketplace_listing", site_type="marketplace"),
            "Listing",
        )
    market = site_dedupe.get_site_card(market_card)
    assert market["primary_category"] == "marketplace"
    assert market["page_type"] == "marketplace_front"
    assert market["site_type"] == "marketplace"

    forum_host = "b" * 56 + ".onion"
    forum_url = f"http://{forum_host}/"
    forum_id = _insert_analyst_fixture(
        forum_url, _policy("forum_social", "forum_index", site_type="forum"))
    forum_card = site_dedupe.ensure_url_site_card(forum_id, _policy(
        "forum_social", "forum_index", site_type="forum"),
                                                  title="Forum", visible_text="safe forum structure")
    for index in range(4):
        child = forum_url + f"thread/{index}"
        child_id = _insert_analyst_fixture(
            child, _policy("fraud_financial", "forum_thread", site_type="forum"))
        site_dedupe.ensure_url_site_card(
            child_id, _policy("fraud_financial", "forum_thread", site_type="forum"),
            title="Thread", visible_text="safe thread structure",
        )
    forum = site_dedupe.get_site_card(forum_card)
    assert forum["primary_category"] == "forum_social"
    assert forum["page_type"] == "forum_index"
    assert forum["site_type"] == "forum"


def test_directory_landing_site_type_is_not_overwritten_by_marketplace_child(isolated_db):
    card_id = _add(
        URL, _policy("directory_index", "link_repository", site_type="link_list"),
        "Useful directory",
    )
    _add(
        URL + "market/1",
        _policy("marketplace", "marketplace_listing", site_type="marketplace"),
        "Child market",
    )
    card = site_dedupe.get_site_card(card_id)
    assert card["primary_category"] == "directory_index"
    assert card["page_type"] == "link_repository"
    assert card["site_type"] == "link_list"


def test_preserved_trusted_category_is_rollup_fallback_after_page_state():
    primary, scores = site_dedupe._score_primary_category([{
        "primary_category": "forum_social",
        "page_type": "login_wall",
        "category_confidence": "medium",
        "category_update_allowed": 0,
        "category_update_reason": "page_state_cannot_replace_site_category",
        "card_path": "/",
        "card_ready": 0,
        "content_quality": "meaningful",
    }])
    assert primary == "forum_social"
    assert scores["forum_social"] > 0


def test_restricted_child_does_not_poison_parent_and_analyst_title_survives(isolated_db):
    card_id = _add(URL, _policy("directory_index", "link_repository"), "Useful directory")
    site_dedupe.apply_manual_title(card_id, "Analyst clean title")
    restricted = _policy("severe_abuse_risk", "marketplace_listing", storage_policy="metadata_only",
                         safety_state="metadata_only", category_update_allowed=0, active=0,
                         queue_policy="blocked", screenshot_policy="blocked", card_ready=0)
    child_id = _insert_analyst_fixture(URL + "restricted", restricted, status="blocked")
    # Severe children are blackholed as standalone tombstones and never attach
    # to the otherwise safe parent Site Card.
    assert site_dedupe.ensure_url_site_card(child_id, restricted, title="Hidden", visible_text="") == 0
    site_dedupe.update_site_card_rollups(card_id)
    card = site_dedupe.get_site_card(card_id)
    assert card["primary_category"] == "directory_index"
    assert card["analyst_title"] == "Analyst clean title"
    assert [item["url"] for item in card["urls"]] == [URL]


def test_wiki_and_code_repository_remain_distinct_page_types():
    wiki = _contract("education_reference", "wiki_docs", evidence=["wiki_documentation_markup"])
    code = _contract("technology_software", "code_repository", evidence=["code_repository_markup"])
    assert wiki["page_type"] == "wiki_docs"
    assert code["page_type"] == "code_repository"
    assert wiki["page_type"] != code["page_type"]
