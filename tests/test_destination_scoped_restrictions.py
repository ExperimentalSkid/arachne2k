"""Regression coverage for destination-scoped restricted-content decisions.

URL labels, anchors, and source-page wording are discovery hints.  They are not
evidence about bytes returned by the destination.  This boundary is important
for link repositories: a restricted label on one entry must not classify the
parent, its sibling entries, or an opaque v3 onion hostname.
"""
from __future__ import annotations

import pytest

import onion_worker
import site_dedupe
import storage
from crawler_decide_rules import decide_url


PARENT_HOST = "a" * 56 + ".onion"
PARENT_URL = f"http://{PARENT_HOST}/"
OPAQUE_LABEL = "childporn" + ("b" * (56 - len("childporn")))
OPAQUE_URL = f"http://{OPAQUE_LABEL}.onion/ordinary"
SAFE_SIBLING = f"http://{'c' * 56}.onion/"


def _directory_policy() -> dict:
    return {
        "primary_category": "directory_index",
        "category": "directory_index",
        "content_category": "directory_index",
        "page_type": "link_repository",
        "classification_decision": "accepted",
        "classification_stage": "page",
        "safety_state": "safe",
        "storage_policy": "safe_summary",
        "review_status": "monitor",
        "queue_policy": "expand",
        "screenshot_policy": "allowed",
        "active": 1,
        "spain_priority": False,
        "priority_score": 0,
    }


def _classify_returned_html(url: str, html: str) -> dict:
    title, meta, visible_text, _records, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    return onion_worker._classify_fetched_page(
        url,
        title=title,
        meta=meta,
        visible_text=visible_text,
        source_url=PARENT_URL,
        source_context="directory_seed",
        page_structure=structure,
    )


def test_parent_link_list_wording_is_not_destination_evidence(isolated_db):
    decision = decide_url(
        SAFE_SIBLING,
        source_url=PARENT_URL,
        anchor_text="Ordinary destination",
        # This describes the source/index, not the destination being decided.
        source_context="childporn video archive links are listed in another section",
        classification_scope="outbound",
    )

    assert decision["decision"] in {"accept", "monitor"}
    assert decision["primary_category"] == "unknown"
    assert decision["classification_decision"] != "restricted"
    assert decision["active"] == 1


def test_url_and_anchor_words_are_hints_not_verified_page_classification(isolated_db):
    decision = decide_url(
        OPAQUE_URL,
        source_url=PARENT_URL,
        anchor_text="childporn video archive",
        source_context="directory entry label",
        classification_scope="outbound",
    )

    assert decision["decision"] in {"accept", "monitor"}
    assert decision["primary_category"] == "unknown"
    assert decision["content_category"] == "unknown"
    assert decision["classification_stage"] == "prefetch"
    assert decision["classification_decision"] not in {
        "restricted", "unverified_restricted_candidate"
    }
    assert decision["active"] == 1


def test_bare_ambiguous_path_word_remains_fetchable_until_html_decides(isolated_db):
    url = f"http://{'d' * 56}.onion/childporn"
    decision = decide_url(url)

    assert decision["decision"] in {"accept", "monitor"}
    assert decision["primary_category"] == "unknown"
    assert decision["url_hint_present"] is True
    assert decision["active"] == 1


def test_explicit_looking_url_is_still_only_a_fetchable_hint(isolated_db):
    url = f"http://{'e' * 56}.onion/csam"
    decision = decide_url(url)

    assert decision["decision"] in {"accept", "monitor"}
    assert decision["classification_decision"] == "unverified_hint"
    assert decision["primary_category"] == "unknown"
    assert decision["storage_policy"] == "safe_summary"
    assert decision["url_hint_present"] is True
    assert decision["active"] == 1

    verified = _classify_returned_html(
        url,
        "<html><title>Community Forum</title><body><h1>Community Forum</h1>"
        "<ul class='topiclist'><li>General discussion</li><li>Support</li></ul>"
        "</body></html>",
    )
    assert verified["primary_category"] == "forum_social"
    assert verified["active"] == 1
    assert verified["classification_stage"] == "page"


def test_two_exact_adult_memories_do_not_block_an_entire_host(isolated_db):
    host = "f" * 56 + ".onion"
    for path, scope in (("one", "body"), ("two", "title")):
        url = f"http://{host}/{path}"
        storage.insert_or_update_onion_url(url)
        html = (
            "<html><title>Adult pornography video archive</title><body>"
            "<h1>Adult pornography video archive</h1><p>Explicit adult sexual videos.</p>"
            "</body></html>"
            if scope == "title" else
            "<html><title>Video archive</title><body><h1>Video archive</h1>"
            "<p>Adult pornography and explicit sexual video archive.</p></body></html>"
        )
        title, meta, visible, _links, structure = onion_worker._parse(
            html.encode("utf-8"), "text/html; charset=utf-8", url)
        policy = onion_worker._classify_fetched_page(
            url, title=title, meta=meta, visible_text=visible,
            source_url=None, source_context=None, page_structure=structure)
        policy = onion_worker.finalize_page_policy(
            url, policy, title=title, page_structure=structure)
        assert policy["primary_category"] == "adult_filtered"
        storage.apply_onion_policy(
            url, policy, checked=True, page_structure=structure)

    assert storage.get_adult_memory_decision(f"http://{host}/one") == "blocked"
    assert storage.get_adult_memory_decision(f"http://{host}/") is None
    root = decide_url(f"http://{host}/")
    assert root["active"] == 1
    assert root["primary_category"] == "unknown"


def test_memory_scope_without_verified_destination_html_is_not_terminal(isolated_db):
    url = f"http://{'m' * 56}.onion/explicit-looking-name"
    storage.insert_or_update_onion_url(url)
    storage.remember_adult_url(url, diagnostics={"match_scope": "title"})
    assert storage.get_adult_memory_decision(url) is None
    assert decide_url(url)["active"] == 1


def test_rediscovery_hint_cannot_overwrite_verified_destination_truth(isolated_db):
    url = f"http://{'g' * 56}.onion/csam"
    verified = _directory_policy()
    verified["safety_reason"] = "page_structure_directory_index"
    storage.insert_or_update_onion_url(
        url, status="crawled", policy=verified,
    )

    hint = decide_url(
        url, source_url=PARENT_URL,
        anchor_text="childporn video archive exchange",
        source_context="link-list section label",
        classification_scope="outbound",
    )
    storage.insert_or_update_onion_url(
        url, source_url=PARENT_URL, source_type="directory_seed",
        status="queued", policy=hint,
    )
    storage.apply_crawl_decision(url, hint)

    row = storage.get_onion_url_by_url(url)
    assert row["verification_state"] == "provisional"
    # The legacy category has no fetched-page provenance, so it is not
    # preserved merely because it was already in the row.
    assert row["primary_category"] == "unknown"
    assert row["content_category"] == "unknown"
    assert row["storage_policy"] == "safe_summary"
    assert row["safety_reason"] == "awaiting_page_classification"


def test_taxonomy_backfill_does_not_reclassify_from_url_tags_or_legacy_title(isolated_db):
    url = f"http://{'h' * 56}.onion/childporn-csam"
    storage.insert_or_update_onion_url(url, status="crawled", policy=_directory_policy())
    with storage.get_db() as db:
        db.execute(
            "UPDATE onion_urls SET title=?,tags=? WHERE url=?",
            ("childporn video archive exchange", '["csam","adult"]', url),
        )

    storage.backfill_category_taxonomy()

    row = storage.get_onion_url_by_url(url)
    assert row["primary_category"] == "unknown"
    assert row["storage_policy"] == "safe_summary"
    assert row["active"] == 1


@pytest.mark.parametrize(
    ("html", "expected_category", "expected_page_type"),
    (
        (
            """<html><title>Public Onion Directory</title><body>
            <h1>Public link directory</h1><ul>
            <li><a href='http://dddddddddddddddddddddddddddddddddddddddddddddddddddddddd.onion/'>One</a></li>
            <li><a href='http://eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.onion/'>Two</a></li>
            <li><a href='http://ffffffffffffffffffffffffffffffffffffffffffffffffffffffff.onion/'>Three</a></li>
            <li><a href='http://gggggggggggggggggggggggggggggggggggggggggggggggggggggggg.onion/'>Four</a></li>
            <li><a href='http://hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh.onion/'>Five</a></li>
            <li><a href='http://iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii.onion/'>Six</a></li>
            </ul></body></html>""",
            "directory_index",
            "directory_index_page",
        ),
        (
            f"""<html><title>Community Board</title><body><ul class='topiclist'>
            <li><a href='http://{OPAQUE_LABEL}.onion/viewtopic.php?t=1'>Topic one</a></li>
            <li><a href='http://{OPAQUE_LABEL}.onion/viewtopic.php?t=2'>Topic two</a></li>
            <li><a href='http://{OPAQUE_LABEL}.onion/viewforum.php?f=3'>Section</a></li>
            </ul></body></html>""",
            "forum_social",
            "forum_index",
        ),
        (
            """<html><title>404 Not Found</title><body>
            <h1>404 Not Found</h1><p>This page is unavailable.</p>
            </body></html>""",
            "unknown",
            "error_page",
        ),
    ),
)
def test_opaque_v3_label_is_fetched_and_returned_html_decides(
        isolated_db, html, expected_category, expected_page_type):
    prefetch = decide_url(OPAQUE_URL)
    assert prefetch["decision"] in {"accept", "monitor"}
    assert prefetch["active"] == 1
    assert prefetch["primary_category"] == "unknown"

    verified = _classify_returned_html(OPAQUE_URL, html)

    assert verified["primary_category"] == expected_category
    assert verified["page_type"] == expected_page_type
    assert verified["classification_stage"] == "page"
    assert verified["classification_decision"] != "restricted"


def test_one_lexical_hint_does_not_poison_parent_or_safe_sibling(isolated_db):
    page_policy = _directory_policy()
    original_parent_policy = dict(page_policy)
    records = [
        {
            "url": OPAQUE_URL,
            "anchor_text": "childporn video archive",
            "section_context": "Directory entry label",
        },
        {
            "url": SAFE_SIBLING,
            "anchor_text": "Privacy discussion forum",
            "section_context": "Community links",
        },
    ]

    summary, classified = onion_worker.classify_outbound_records(
        {"url": PARENT_URL, "depth": 0}, records, page_policy)
    by_url = {record["url"]: record["policy"] for record in classified}

    assert page_policy == original_parent_policy
    assert by_url[OPAQUE_URL]["primary_category"] == "unknown"
    assert by_url[OPAQUE_URL]["active"] == 1
    assert by_url[SAFE_SIBLING]["primary_category"] == "unknown"
    assert by_url[SAFE_SIBLING]["active"] == 1
    assert summary["severe"] == 0
    assert summary["restricted"] == 0


def test_strong_destination_html_still_applies_severe_blackhole(isolated_db):
    verified = _classify_returned_html(
        OPAQUE_URL,
        """<html><title>Restricted destination</title><body>
        <h1>childporn video archive</h1>
        <p>Explicit sexual files advertised for download and exchange.</p>
        </body></html>""",
    )

    assert verified["primary_category"] == "severe_abuse_risk"
    assert verified["classification_decision"] == "restricted"
    assert verified["storage_policy"] == "metadata_only"
    assert verified["queue_policy"] == "blocked"
    assert verified["active"] == 0
    assert verified["fetch_allowed"] is False
    assert verified["card_allowed"] is False
    assert verified["alert_allowed"] is False
