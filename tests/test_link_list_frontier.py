import onion_worker
import storage


HOST = "a" * 56 + ".onion"


def _policy():
    return {
        "primary_category": "directory_index", "category": "directory_index",
        "tags": ["directory_index"], "risk_level": "low", "confidence": "high",
        "risk_flags": [], "storage_policy": "safe_summary", "review_status": "pending",
        "safety_reason": "directory_index", "priority_score": 10,
        "screenshot_policy": "allowed", "queue_policy": "expand", "active": 1,
        "spain_priority": False,
    }


def _persist_verified_page(url: str, html: str) -> dict:
    title, meta, visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = onion_worker._classify_fetched_page(
        url, title=title, meta=meta, visible_text=visible,
        source_url=None, source_context=None, page_structure=structure)
    policy = onion_worker.finalize_page_policy(
        url, policy, title=title, page_structure=structure)
    storage.insert_or_update_onion_url(url, HOST, status="crawled")
    storage.apply_onion_policy(
        url, policy, 200, checked=True, page_structure=structure)
    return policy


def test_link_heavy_page_processes_every_unique_onion_link(isolated_db, monkeypatch):
    source = f"http://{HOST}/directory"
    source_id = storage.insert_or_update_onion_url(source, HOST, status="crawled", policy=_policy())
    records = [{"url": f"http://{HOST}/entry/{index}", "anchor_text": f"Entry {index}"}
               for index in range(125)]
    card_calls = []
    monkeypatch.setattr(onion_worker, "classify_url_prefetch", lambda *_args, **_kwargs: _policy())
    monkeypatch.setattr(onion_worker.site_dedupe, "ensure_url_site_card",
                        lambda url_id, *_args, **_kwargs: card_calls.append(url_id))
    monkeypatch.setattr(onion_worker.storage, "queue_spain_alert", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(onion_worker, "get_int",
                        lambda name, default: 2000 if name == "ONION_MAX_LINKS_PER_PAGE" else 10)

    onion_worker._store_discovered_links(
        {"id": source_id, "url": source, "depth": 0}, records, _policy()
    )

    with storage.get_db() as db:
        queued = db.execute("SELECT COUNT(*) FROM onion_urls WHERE status='queued'").fetchone()[0]
        edges = db.execute("SELECT COUNT(*) FROM onion_edges WHERE source_url=?", (source,)).fetchone()[0]
        internal = db.execute("SELECT COUNT(*) FROM onion_urls WHERE source_type='onion_internal'").fetchone()[0]
    assert queued == 125
    assert edges == 125
    assert internal == 125
    # Safe discovered children stay provisional until their own page is fetched.
    assert card_calls == []
    first = storage.get_onion_url_by_url(records[0]["url"])
    assert first["primary_category"] == "unknown" and first["site_card_id"] is None
    assert first["verification_state"] == "provisional" and first["verified_at"] is None


def test_internal_categories_continue_beyond_external_depth_limit(isolated_db, monkeypatch):
    source = f"http://{HOST}/categories/page/4"
    source_id = storage.insert_or_update_onion_url(source, HOST, depth=4, status="crawled", policy=_policy())
    internal = f"http://{HOST}/categories/page/5"
    external_host = "b" * 56 + ".onion"
    external = f"http://{external_host}/list"
    monkeypatch.setattr(onion_worker, "classify_url_prefetch", lambda *_args, **_kwargs: _policy())
    monkeypatch.setattr(onion_worker.site_dedupe, "ensure_url_site_card", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(onion_worker.storage, "queue_spain_alert", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(onion_worker, "get_int",
                        lambda name, default: 8 if name == "ONION_INTERNAL_MAX_DEPTH" else 3)

    onion_worker._store_discovered_links(
        {"id": source_id, "url": source, "depth": 4},
        [{"url": internal, "anchor_text": "Next category page"},
         {"url": external, "anchor_text": "External directory"}], _policy()
    )

    assert storage.get_onion_url_by_url(internal)["status"] == "queued"
    assert storage.get_onion_url_by_url(internal)["source_type"] == "onion_internal"
    external_row = storage.get_onion_url_by_url(external)
    # External onions found by a confirmed directory become fresh shallow seeds,
    # even when the directory itself was reached at a deep internal path.
    assert external_row["status"] == "queued"
    assert external_row["source_type"] == "directory_seed"
    assert external_row["depth"] == 1


def test_already_visited_link_updates_history_without_requeue_or_actions(isolated_db, monkeypatch):
    source = f"http://{HOST}/another-list"
    source_id = storage.insert_or_update_onion_url(source, HOST, status="crawled", policy=_policy())
    visited = f"http://{HOST}/already-checked"
    _persist_verified_page(
        visited,
        "<html><title>Reference page</title><body><h1>Reference page</h1>"
        "<p>General public documentation and information.</p></body></html>",
    )
    with storage.get_db() as db:
        db.execute(
            "UPDATE onion_urls SET source_url='first-source',source_type='onion_page' WHERE url=?",
            (visited,),
        )
    card_calls = []
    alert_calls = []
    monkeypatch.setattr(onion_worker, "classify_url_prefetch", lambda *_args, **_kwargs: _policy())
    monkeypatch.setattr(onion_worker.site_dedupe, "ensure_url_site_card",
                        lambda *_args, **_kwargs: card_calls.append(1))
    monkeypatch.setattr(onion_worker.storage, "queue_spain_alert",
                        lambda *_args, **_kwargs: alert_calls.append(1))

    onion_worker._store_discovered_links(
        {"id": source_id, "url": source, "depth": 0},
        [{"url": visited, "anchor_text": "Known"}], _policy()
    )

    row = storage.get_onion_url_by_url(visited)
    assert row["status"] == "crawled"
    assert row["seen_count"] == 2
    assert row["source_count"] == 2
    assert card_calls == []
    assert alert_calls == []
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM onion_edges WHERE source_url=? AND discovered_url=?",
                          (source, visited)).fetchone()[0] == 1


def test_mixed_directory_quarantine_keeps_unverified_labels_provisional(isolated_db):
    source = f"http://{HOST}/mixed-directory"
    source_id = storage.insert_or_update_onion_url(source, HOST, status="blocked", policy=_policy())
    safe = "http://" + "b" * 56 + ".onion/"
    adult = "http://porn" + "c" * 52 + ".onion/"
    records = [
        {"url": safe, "anchor_text": "Onion directory", "section_context": "Search Engines"},
        {"url": safe + "one", "anchor_text": "Search one", "section_context": "Search Engines"},
        {"url": safe + "two", "anchor_text": "Search two", "section_context": "Search Engines"},
        {"url": safe + "three", "anchor_text": "Search three", "section_context": "Search Engines"},
        {"url": adult, "anchor_text": "Porn links", "section_context": "Adult"},
    ]
    assert onion_worker._mixed_link_directory("Mixed onion link list", "", "directory index", records)
    onion_worker._store_discovered_links(
        {"id": source_id, "url": source, "depth": 0}, records,
        onion_worker._quarantined_directory_policy(),
    )
    safe_row = storage.get_onion_url_by_url(safe)
    adult_row = storage.get_onion_url_by_url(adult)
    assert safe_row["active"] == 1 and safe_row["status"] == "queued"
    assert adult_row["primary_category"] == "unknown" and adult_row["active"] == 1
    assert adult_row["verification_state"] == "provisional" and adult_row["status"] == "queued"
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM onion_edges WHERE source_url=?", (source,)).fetchone()[0] == 0


def test_adult_memory_can_release_false_positive_for_safe_content(isolated_db):
    # Memory is created by verified destination HTML, never by the path alone.
    url = "http://" + "d" * 56 + ".onion/porn"
    html = ("<html><title>Adult video marketplace</title><body>"
            "<h1>Adult video marketplace</h1><p>Pornographic adult videos, "
            "erotic xxx gallery, and adult content.</p></body></html>")
    title, meta, visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = onion_worker._classify_fetched_page(
        url, title=title, meta=meta, visible_text=visible,
        source_url=None, source_context=None, page_structure=structure)
    policy = onion_worker.finalize_page_policy(
        url, policy, title=title, page_structure=structure)
    assert policy["primary_category"] == "adult_filtered"
    storage.insert_or_update_onion_url(url, status="blocked")
    storage.apply_onion_policy(
        url, policy, checked=True, page_structure=structure)
    with storage.get_db() as db:
        memory_id = db.execute("SELECT id FROM adult_filter_memory").fetchone()[0]
    assert storage.get_adult_memory_decision(url) == "blocked"
    assert storage.review_adult_memory(memory_id, "false_positive")
    assert storage.get_adult_memory_decision(url) == "false_positive"
    with storage.get_db() as db:
        feedback = dict(db.execute("""SELECT feedback_scope,feedback_action,subject_hash
          FROM classification_feedback_events WHERE feedback_scope='safety'
          ORDER BY id DESC LIMIT 1""").fetchone())
    assert feedback["feedback_action"] == "adult_false_positive"
    assert url not in feedback["subject_hash"]
    assert onion_worker._prefilter_url(url)["active"] == 1
    content_policy = onion_worker._classify_fetched_page(
        url, title="Weapons intelligence", meta="", visible_text="weapons trafficking Spain",
        source_url=None, source_context=None,
    )
    assert content_policy["primary_category"] == "weapons_arms"
