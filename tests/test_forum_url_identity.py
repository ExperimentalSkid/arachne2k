from forum_url_identity import FORUM_URL_ROLES, classify_forum_url
import onion_worker
from page_intelligence import fingerprint_page_type
import site_dedupe
import storage


HOST = "7" * 56 + ".onion"
BASE = f"http://{HOST}"


def _important_thread_policy(url: str) -> tuple[dict, dict, str, str]:
    document = """<html><head><title>Important Spain forum thread</title></head>
      <body class="phpbb postbody postprofile">
        <h1>Weapons shipment to Spain</h1>
        <div>Firearms and weapons for sale by vendor. Direct order and escrow.
        Shipping to Spain via Correos. Payment with Bizum. Delivery in Madrid
        and Sevilla. DNI required.</div>
      </body></html>"""
    title, meta, visible_text, _links, structure = onion_worker._parse(
        document.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = onion_worker._classify_fetched_page(
        url, title=title, meta=meta, visible_text=visible_text,
        source_url=None, source_context=None, page_structure=structure)
    page_type = fingerprint_page_type(
        url, structure, current_type=str(policy.get("page_type") or "unknown"),
        allow_url_hints=False)
    if page_type["page_type_confidence"] in {"medium", "high"}:
        policy["page_type"] = page_type["page_type"]
    policy.update(
        page_type_confidence=page_type["page_type_confidence"],
        page_type_evidence=page_type["evidence"], card_ready=1,
        card_readiness_reason="classified_meaningful_page",
        card_readiness_confidence="high")
    policy = onion_worker.finalize_page_policy(
        url, policy, title=title, page_structure=structure)
    return policy, structure, title, visible_text


def _store_important_thread(url: str) -> int:
    policy, structure, title, visible_text = _important_thread_policy(url)
    url_id = storage.insert_or_update_onion_url(url, HOST, status="crawled")
    stored_url = storage.get_onion_url_by_url(url)["url"]
    storage.apply_onion_policy(
        stored_url, policy, 200, checked=True, page_structure=structure)
    return site_dedupe.ensure_url_site_card(
        url_id, policy, title=title, visible_text=visible_text)


def test_phpbb_thread_identity_ignores_only_navigation_noise_and_never_thread_id():
    exact = BASE + "/viewtopic.php?f=9&t=18453&sid=ABC&start=40&utm_source=x#top"
    paged = classify_forum_url(exact)
    root = classify_forum_url(BASE + "/viewtopic.php?t=18453")
    other = classify_forum_url(BASE + "/viewtopic.php?t=18454")

    assert paged.exact_url == exact
    assert paged.engine == "phpbb" and paged.role == "pagination"
    assert paged.thread_id == "18453"
    assert paged.case_identity == root.case_identity
    assert paged.case_identity != other.case_identity
    assert "sid=" not in paged.canonical_url and "start=" not in paged.canonical_url
    assert "utm_" not in paged.canonical_url
    assert "f=9" in paged.canonical_url and "t=18453" in paged.canonical_url


def test_phpbb_section_and_post_permalink_are_separate_stable_resources():
    section = classify_forum_url(BASE + "/viewforum.php?f=18&sid=x")
    post = classify_forum_url(BASE + "/viewtopic.php?p=812#p812")
    post_in_thread = classify_forum_url(BASE + "/viewtopic.php?t=44&p=812#p812")

    assert section.role == "section" and section.section_id == "18"
    assert section.case_identity is None
    assert post.role == "post_permalink" and post.post_id == "812"
    assert post.case_identity == post.post_identity
    assert post_in_thread.thread_id == "44" and post_in_thread.post_id == "812"
    assert post_in_thread.case_identity == post_in_thread.thread_identity


def test_vbulletin_classic_routes_have_stable_thread_post_and_section_identity():
    thread = classify_forum_url(BASE + "/showthread.php?t=90&page=3&sessionid=x")
    post = classify_forum_url(BASE + "/showpost.php?p=901#post901")
    section = classify_forum_url(BASE + "/forumdisplay.php?f=7")

    assert (thread.engine, thread.role, thread.thread_id) == ("vbulletin", "pagination", "90")
    assert (post.engine, post.role, post.post_id) == ("vbulletin", "post_permalink", "901")
    assert (section.engine, section.role, section.section_id) == ("vbulletin", "section", "7")


def test_smf_offsets_canonicalize_without_losing_topic_or_message_identity():
    paged = classify_forum_url(BASE + "/index.php?topic=123.40;session=abc")
    root = classify_forum_url(BASE + "/index.php?topic=123.0")
    post = classify_forum_url(BASE + "/index.php?topic=123.msg456#msg456")
    section = classify_forum_url(BASE + "/index.php?board=8.20")

    assert paged.engine == "smf" and paged.role == "pagination"
    assert paged.case_identity == root.case_identity
    assert "topic=123.0" in paged.canonical_url
    assert post.role == "post_permalink" and post.thread_id == "123" and post.post_id == "456"
    assert post.case_identity == root.case_identity
    assert "msg456" in post.canonical_url
    assert section.role == "pagination" and section.section_id == "8"


def test_login_attachment_index_and_unknown_routes_are_not_guessed_as_threads():
    login = classify_forum_url(BASE + "/ucp.php?mode=login&sid=x")
    attachment = classify_forum_url(BASE + "/download/file.php?id=9&sid=x")
    index = classify_forum_url(BASE + "/forum/?sid=x")
    unknown = classify_forum_url(BASE + "/news/123")

    assert login.role == "login" and login.case_identity is None
    assert attachment.role == "attachment" and attachment.case_identity is None
    assert index.role == "site_index" and index.case_identity is None
    assert unknown.role == "unknown" and unknown.case_identity is None
    assert {login.role, attachment.role, index.role, unknown.role} <= FORUM_URL_ROLES
    # Route identity is a crawl hint only. Even an explicit-looking forum URL
    # cannot assign the fetched page type without destination markup.
    assert fingerprint_page_type(
        BASE + "/viewtopic.php?t=99", {}, allow_url_hints=True
    )["page_type"] == "unknown"


def test_conservative_generic_thread_routes_keep_distinct_ids_and_strip_pages():
    first = classify_forum_url(BASE + "/threads/spain-shipping.321/page-4?ref=x")
    same = classify_forum_url(BASE + "/threads/321")
    other = classify_forum_url(BASE + "/threads/322")
    slug = classify_forum_url(BASE + "/thread/stable-topic-name")

    assert first.role == "pagination" and first.thread_id == "321"
    assert first.case_identity == same.case_identity
    assert first.case_identity != other.case_identity
    assert first.canonical_url.endswith("/threads/spain-shipping.321")
    assert slug.role == "thread" and slug.thread_id.startswith("slug-")
    assert "stable-topic-name" not in slug.case_identity


def test_forum_case_cards_reuse_stable_phpbb_thread_across_page_variants(isolated_db):
    urls = [
        BASE + "/viewtopic.php?f=4&t=700&sid=A&start=20",
        BASE + "/viewtopic.php?t=700&sid=B",
        BASE + "/viewtopic.php?t=700&p=701#p701",
    ]
    cards = [_store_important_thread(url) for url in urls]

    assert len(set(cards)) == 1
    with storage.get_db() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM site_cards WHERE card_kind='forum_thread_case'"
        ).fetchone()[0] == 1


def test_forum_case_cards_never_merge_distinct_thread_ids(isolated_db):
    cards = []
    for thread_id in ("801", "802"):
        url = BASE + f"/viewtopic.php?t={thread_id}&sid=noise"
        cards.append(_store_important_thread(url))

    assert cards[0] != cards[1]
    with storage.get_db() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM site_cards WHERE card_kind='forum_thread_case'"
        ).fetchone()[0] == 2
