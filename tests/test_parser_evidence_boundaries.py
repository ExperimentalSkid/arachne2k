"""Parser regressions that keep child-link markup out of parent evidence."""
from __future__ import annotations

import pytest

import onion_worker


HOST = "a" * 56 + ".onion"
URL = f"http://{HOST}/"


@pytest.fixture(autouse=True)
def _initialized_test_database(isolated_db):
    """The fetched-page classifier consults exact analyst safety memory."""
    return isolated_db


def _parse_and_classify(html: str, url: str = URL):
    title, meta, visible_text, records, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = onion_worker._classify_fetched_page(
        url,
        title=title,
        meta=meta,
        visible_text=visible_text,
        source_url=None,
        source_context=None,
        page_structure=structure,
    )
    return title, visible_text, records, structure, policy


def _external_links() -> str:
    return "".join(
        f"<li><a href='http://{letter * 56}.onion/'>Service {index}</a></li>"
        for index, letter in enumerate("bcdefg")
    )


@pytest.mark.parametrize(
    "linked_heading",
    (
        "Pornographic adult xxx video gallery",
        "childporn video archive exchange",
        "carding fullz cashout stolen cards",
        "firearms weapons vendor for sale",
    ),
)
@pytest.mark.parametrize("heading_tag", ("h1", "h2"))
def test_anchor_wrapped_heading_cannot_title_or_classify_parent(
        linked_heading, heading_tag):
    html = (
        "<html><body><ul>"
        f"<li><a href='http://{'z' * 56}.onion/'>"
        f"<{heading_tag}>{linked_heading}</{heading_tag}></a></li>"
        f"{_external_links()}</ul></body></html>"
    )

    title, visible_text, records, structure, policy = _parse_and_classify(html)

    # The label is retained only on its own outbound record.
    assert any(linked_heading in record["anchor_text"] for record in records)
    assert linked_heading not in visible_text
    assert linked_heading not in structure["heading_text"]

    # With no genuine page title/heading, display identity falls back to the
    # host while the classifier-facing title remains empty.
    assert title is None
    assert structure["identity"]["detected_title"] == HOST
    assert structure["identity"]["title_source"] == "onion_host"
    assert policy["primary_category"] == "directory_index"
    assert policy["page_type"] == "link_repository"
    assert policy["classification_decision"] == "accepted"


def test_onion_host_fallback_is_display_only_not_classifier_title_evidence():
    opaque_host = "cardingfullzcashout" + ("b" * (56 - len("cardingfullzcashout")))
    url = f"http://{opaque_host}.onion/"
    html = """<html><body><article>
      <p>This ordinary community bulletin describes maintenance schedules,
      service availability, public updates, and general operating hours.</p>
      </article></body></html>"""

    title, _visible_text, _records, structure, policy = _parse_and_classify(html, url)

    assert title is None
    assert structure["identity"]["detected_title"] == f"{opaque_host}.onion"
    assert structure["identity"]["title_source"] == "onion_host"
    assert policy["primary_category"] == "general_other"
    assert policy["page_type"] == "article_page"
    assert policy["classification_decision"] == "monitor_only"
    assert policy.get("match_scope") != "title"


def test_text_plain_host_fallback_is_not_classifier_title_evidence():
    opaque_host = "childporn" + ("c" * (56 - len("childporn")))
    url = f"http://{opaque_host}.onion/"
    title, meta, visible_text, records, structure = onion_worker._parse(
        b"Ordinary public status bulletin and maintenance schedule.",
        "text/plain; charset=utf-8",
        url,
    )
    policy = onion_worker._classify_fetched_page(
        url, title=title, meta=meta, visible_text=visible_text,
        source_url=None, source_context=None, page_structure=structure,
    )

    assert title is None
    assert records == []
    assert structure["identity"]["title_source"] == "onion_host"
    assert policy["primary_category"] not in {
        "adult_filtered", "adult_restricted", "severe_abuse_risk",
    }
    assert policy.get("match_scope") != "title"


def test_subresource_fallback_markup_is_not_discovered_or_classified():
    hidden = f"http://{'d' * 56}.onion/childporn"
    html = f"""<html><title>Status page</title><body>
      <p>Ordinary maintenance information.</p>
      <noscript><h1><a href='{hidden}'>childporn video archive exchange</a></h1></noscript>
      <iframe><a href='{hidden}'>restricted child label</a></iframe>
      <video><source src='{hidden}'><track src='{hidden}'></video>
      </body></html>"""

    _title, visible_text, records, _structure, policy = _parse_and_classify(html)

    assert records == []
    assert "childporn" not in visible_text.casefold()
    assert policy["primary_category"] not in {
        "adult_filtered", "adult_restricted", "severe_abuse_risk",
    }


@pytest.mark.parametrize(
    ("attribute", "marker"),
    (
        ("class", "marketplace"),
        ("id", "topiclist"),
        ("class", "product-card"),
    ),
)
def test_anchor_class_or_id_cannot_define_parent_page_type(attribute, marker):
    html = f"""<html><title>Service bulletin</title><body><article>
      <p>This ordinary community maintenance bulletin describes service
      availability, opening hours, scheduled updates, and general news.</p>
      <a {attribute}='{marker}' href='/next'>Continue</a>
      </article></body></html>"""

    _title, _visible_text, _records, structure, policy = _parse_and_classify(html)

    assert "forum_markup" not in structure["signals"]
    assert "market_markup" not in structure["signals"]
    assert policy["primary_category"] == "general_other"
    assert policy["page_type"] == "article_page"


@pytest.mark.parametrize("shell_type", ("marketplace", "forum"))
def test_genuine_non_anchor_page_shell_markup_remains_structural_evidence(shell_type):
    if shell_type == "marketplace":
        html = f"""<html><title>Welcome</title><body>
          <main id='marketplace' class='product-grid'><section class='vendor-list'>
          <a href='http://{HOST}/vendor/alice'>Vendor Alice</a>
          <a href='http://{HOST}/product/1'>Product one</a>
          </section></main></body></html>"""
        expected = ("market_markup", "marketplace", "marketplace_front")
    else:
        html = f"""<html><title>Community</title><body><main id='phpbb'>
          <ul class='topiclist'>
          <li><a href='http://{HOST}/viewtopic.php?t=1'>Topic one</a></li>
          <li><a href='http://{HOST}/viewtopic.php?t=2'>Topic two</a></li>
          </ul></main></body></html>"""
        expected = ("forum_markup", "forum_social", "forum_index")

    _title, _visible_text, _records, structure, policy = _parse_and_classify(html)

    expected_signal, expected_category, expected_page_type = expected
    assert expected_signal in structure["signals"]
    assert policy["primary_category"] == expected_category
    assert policy["page_type"] == expected_page_type
    assert policy["classification_decision"] == "accepted"
