import onion_worker
import storage


HOST = "f" * 56 + ".onion"
FORUM = f"http://{HOST}/forum/"


def _forum_policy():
    return {
        "primary_category": "forum_social", "category": "forum_social",
        "content_category": "forum_social", "page_type": "forum_index",
        "tags": ["forum_social"], "risk_level": "low", "confidence": "high",
        "category_confidence": "high", "risk_flags": [], "storage_policy": "safe_summary",
        "review_status": "monitor", "screenshot_policy": "allowed", "queue_policy": "expand",
        "active": 1, "priority_score": 10, "spain_priority": False,
    }


def _store_threads(count: int, *, trigger_last: bool = False):
    parent_id = storage.insert_or_update_onion_url(FORUM, HOST, status="crawled", policy=_forum_policy())
    records = []
    for index in range(count):
        records.append({
            "url": f"http://{HOST}/thread/{index}",
            "anchor_text": ("Weapons shipping to Madrid" if trigger_last and index == count - 1
                            else f"Ordinary discussion {index}"),
            "section_context": "Recent public threads",
        })
    onion_worker._store_discovered_links(
        {"id": parent_id, "url": FORUM, "depth": 0}, records, _forum_policy())


def test_forum_initial_pass_admits_25_and_retains_the_rest_deferred(isolated_db, monkeypatch):
    monkeypatch.setenv("ONION_FORUM_INITIAL_THREAD_LIMIT", "25")
    _store_threads(31)
    with storage.get_db() as db:
        queued = db.execute("SELECT COUNT(*) FROM onion_urls WHERE source_type='forum_thread_hint' AND status='queued'").fetchone()[0]
        deferred = db.execute("SELECT COUNT(*) FROM onion_urls WHERE source_type='forum_thread_hint' AND status='deferred_forum_budget'").fetchone()[0]
    assert queued == 25
    assert deferred == 6


def test_trigger_looking_thread_is_prioritized_inside_initial_25(isolated_db, monkeypatch):
    monkeypatch.setenv("ONION_FORUM_INITIAL_THREAD_LIMIT", "25")
    _store_threads(26, trigger_last=True)
    trigger = storage.get_onion_url_by_url(f"http://{HOST}/thread/25")
    assert trigger["status"] == "queued"
    assert trigger["source_type"] == "forum_thread_hint"


def test_repeat_discovery_does_not_consume_more_budget_or_requeue_threads(isolated_db):
    _store_threads(25)
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET status='crawled' WHERE source_type='forum_thread_hint'")
    _store_threads(30)
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM onion_urls WHERE source_type='forum_thread_hint'").fetchone()[0] == 30
        assert db.execute("SELECT COUNT(*) FROM onion_urls WHERE source_type='forum_thread_hint' AND status='crawled'").fetchone()[0] == 25
        assert db.execute("SELECT COUNT(*) FROM onion_urls WHERE status='deferred_forum_budget'").fetchone()[0] == 5


def test_relevant_thread_unlocks_next_25_once(isolated_db):
    _store_threads(60)
    first = storage.expand_deferred_forum_threads(
        HOST, f"http://{HOST}/thread/2", "relevant_thread_category:weapons_arms",
        batch_size=25, max_limit=100)
    duplicate = storage.expand_deferred_forum_threads(
        HOST, f"http://{HOST}/thread/2", "relevant_thread_category:weapons_arms",
        batch_size=25, max_limit=100)
    assert first == {"expanded": 25, "permitted": 50, "maximum": 100, "duplicate_trigger": 0}
    assert duplicate["expanded"] == 0 and duplicate["duplicate_trigger"] == 1
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM onion_urls WHERE source_type='forum_thread_hint' AND status='queued'").fetchone()[0] == 50
        assert db.execute("SELECT relevant_trigger_count FROM forum_crawl_state WHERE onion_host=?", (HOST,)).fetchone()[0] == 1


def test_logical_thread_url_variants_unlock_only_one_batch(isolated_db):
    _store_threads(80)
    first = storage.expand_deferred_forum_threads(
        HOST, f"http://{HOST}/viewtopic.php?t=2",
        "relevant_thread_category:weapons_arms", batch_size=25, max_limit=100)
    variant = storage.expand_deferred_forum_threads(
        HOST, f"http://{HOST}/viewtopic.php?t=2&start=25&sid=session-noise#p812",
        "relevant_thread_category:weapons_arms", batch_size=25, max_limit=100)
    distinct = storage.expand_deferred_forum_threads(
        HOST, f"http://{HOST}/viewtopic.php?t=3&start=25",
        "relevant_thread_category:weapons_arms", batch_size=25, max_limit=100)

    assert first["expanded"] == 25 and first["duplicate_trigger"] == 0
    assert variant["expanded"] == 0 and variant["duplicate_trigger"] == 1
    assert distinct["expanded"] == 25 and distinct["duplicate_trigger"] == 0
    with storage.get_db() as db:
        events = list(db.execute("""SELECT trigger_identity_hash FROM forum_expansion_events
          WHERE onion_host=? ORDER BY created_at""", (HOST,)))
        state = db.execute("""SELECT relevant_trigger_count,expansion_rounds,
          permitted_thread_budget FROM forum_crawl_state WHERE onion_host=?""", (HOST,)).fetchone()
    assert len(events) == 2
    assert len({row["trigger_identity_hash"] for row in events}) == 2
    assert tuple(state) == (2, 2, 75)


def test_only_strong_forum_page_results_expand_budget():
    provenance = {"classification_evidence_source": "destination_html",
                  "destination_html_evidence_version": 1}
    weak = {"page_type": "forum_thread", "primary_category": "forum_social",
            "category_confidence": "high", "spain_priority": False, **provenance}
    strong = {"page_type": "forum_thread", "primary_category": "fraud_financial",
              "category_confidence": "medium", "spain_priority": False, **provenance}
    homepage = {"page_type": "forum_index", "primary_category": "fraud_financial",
                "category_confidence": "high", "spain_priority": False, **provenance}
    assert onion_worker._forum_relevance_trigger(f"http://{HOST}/thread/1", weak)[0] is False
    assert onion_worker._forum_relevance_trigger(f"http://{HOST}/thread/2", strong)[0] is True
    assert onion_worker._forum_relevance_trigger(f"http://{HOST}/", homepage)[0] is False


def test_staged_verifier_expands_relevant_forum_budget_once(isolated_db, monkeypatch):
    _store_threads(60)
    url = f"http://{HOST}/thread/2"
    html = """<html><head><title>Relevant public forum thread</title></head><body>
    <article class="postbody"><p>Weapons vendor discussion and shipping details.</p></article>
    <aside class="postprofile">Public seller profile</aside>
    </body></html>"""
    title, meta, visible, links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = {
        **_forum_policy(),
        "primary_category": "weapons_arms",
        "category": "weapons_arms",
        "content_category": "weapons_arms",
        "page_type": "forum_thread",
        "category_confidence": "high",
        "card_ready": 1,
    }
    url_id = int(storage.get_onion_url_by_url(url)["id"])
    storage.store_fetched_page_snapshot(
        url_id, url, worker_id=None, response_status=200,
        content_type="text/html; charset=utf-8",
        headers={"Content-Type": "text/html; charset=utf-8"},
        title=title, meta_text=meta, visible_text=visible,
        link_records=links, page_structure=structure, pre_policy=policy,
    )
    monkeypatch.setattr(
        onion_worker, "_classify_fetched_page", lambda *_args, **_kwargs: dict(policy))

    assert onion_worker.verify_one("verify:forum-expansion") is True

    with storage.get_db() as db:
        admitted = db.execute("""SELECT COUNT(*) FROM onion_urls
          WHERE source_type='forum_thread_hint' AND status!='deferred_forum_budget'""").fetchone()[0]
        deferred = db.execute("""SELECT COUNT(*) FROM onion_urls
          WHERE source_type='forum_thread_hint' AND status='deferred_forum_budget'""").fetchone()[0]
        events = db.execute("""SELECT COUNT(*) FROM forum_expansion_events
          WHERE onion_host=?""", (HOST,)).fetchone()[0]
        permitted = db.execute("""SELECT permitted_thread_budget FROM forum_crawl_state
          WHERE onion_host=?""", (HOST,)).fetchone()[0]
    assert (admitted, deferred, events, permitted) == (50, 10, 1, 50)


def test_forum_sections_do_not_consume_thread_budget(isolated_db):
    parent_id = storage.insert_or_update_onion_url(FORUM, HOST, status="crawled", policy=_forum_policy())
    records = [{"url": f"http://{HOST}/viewforum.php?f={index}", "anchor_text": f"Section {index}"}
               for index in range(40)]
    onion_worker._store_discovered_links(
        {"id": parent_id, "url": FORUM, "depth": 0}, records, _forum_policy())
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM onion_urls WHERE source_type='forum_thread_hint'").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM onion_urls WHERE status='deferred_forum_budget'").fetchone()[0] == 0
