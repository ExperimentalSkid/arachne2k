import onion_worker
import universal_classifier


HOST = "r" * 56 + ".onion"
ROOT = f"http://{HOST}/"


def test_url_routes_remain_hints_even_when_legacy_hint_switch_is_enabled():
    routes = (
        "viewtopic.php?t=42", "users/sign_in", "checkout", "vendor/alice",
        "product/7", "wiki/Something", "-/commits/main",
    )
    for route in routes:
        url = ROOT + route
        assert universal_classifier._detect_page_type(
            url, "ordinary destination", allow_url_hints=True) == "unknown"
        assert universal_classifier.structural_page_guard(url, "ordinary destination") is None

    weapons = universal_classifier._weapons_evidence(
        ROOT + "vendor/weapons/listing/7", "Rifles shipping", "")
    assert weapons["verified"] is False
    assert "seller_or_listing_structure" not in weapons["families"]


def test_form_action_routes_are_unverified_and_cannot_assign_page_type():
    html = b"""<html><head><title>Ordinary page</title></head><body>
      <form action='/login'></form><form action='/checkout'></form>
      <form action='/contact'></form><form action='/search'></form>
      <p>General information.</p></body></html>"""
    _title, _meta, _text, _links, structure = onion_worker._parse(
        html, "text/html; charset=utf-8", ROOT + "anything")

    assert structure["page_type_info"]["page_type"] == "unknown"
    assert structure["has_password_form"] is False
    assert structure["has_search_form"] is False
    assert set(structure["form_route_hints"]["labels"]) == {
        "login_route", "checkout_route", "contact_route", "search_route",
    }
    assert structure["form_route_hints"]["hint_verified"] is False
    assert structure["form_route_hints"]["evidence_source"] == "form_action_route"


def test_forum_route_is_hint_but_destination_markup_can_confirm_thread():
    generic = b"<html><body><p>General information.</p></body></html>"
    _title, _meta, _text, _links, generic_structure = onion_worker._parse(
        generic, "text/html", ROOT + "viewtopic.php?t=7")
    assert generic_structure["forum_route_hint"]["role"] == "thread"
    assert generic_structure["forum_route_hint"]["hint_verified"] is False
    assert generic_structure["page_type_info"]["page_type"] == "unknown"

    thread_html = b"""<html><head><title>Community discussion</title></head><body>
      <div class='postbody'>First post</div>
      <div class='postprofile'>Member profile</div>
      <div class='postbody'>Second post</div>
    </body></html>"""
    _title, _meta, _text, _links, thread_structure = onion_worker._parse(
        thread_html, "text/html", ROOT + "unrelated-route")
    assert thread_structure["page_type_info"]["page_type"] == "forum_thread"
    assert "forum_thread_markup" in thread_structure["page_type_info"]["evidence"]


def test_h1_anchor_text_cannot_become_destination_title_or_page_identity():
    html = b"""<html><body>
      <h1><a href='/'>Marketplace checkout forum thread</a></h1>
      <p>General information.</p>
    </body></html>"""
    title, _meta, visible_text, _links, structure = onion_worker._parse(
        html, "text/html", ROOT)

    assert title is None
    assert structure["identity"]["title_source"] == "onion_host"
    assert structure["page_type_info"]["page_type"] == "unknown"
    assert "marketplace checkout forum thread" not in visible_text.casefold()


def test_url_shaped_like_thread_cannot_trigger_forum_expansion_or_alert_logic():
    route_only = {
        "page_type": "unknown", "primary_category": "fraud_financial",
        "category_confidence": "high", "spain_priority": True,
    }
    assert onion_worker._forum_relevance_trigger(
        ROOT + "viewtopic.php?t=11", route_only) == (False, "not_forum_thread")

    confirmed = {
        **route_only,
        "page_type": "forum_thread",
        "classification_evidence_source": "destination_html",
        "destination_html_evidence_version": 1,
    }
    triggered, _reason = onion_worker._forum_relevance_trigger(ROOT + "ordinary", confirmed)
    assert triggered is True
