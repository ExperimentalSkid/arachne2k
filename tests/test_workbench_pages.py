import site_dedupe
import storage


HOST = "w" * 56 + ".onion"


def _policy():
    return {
        "primary_category": "directory_index",
        "category": "directory_index",
        "content_category": "directory_index",
        "analyst_category": "directory_index",
        "classification_evidence_source": "analyst",
        "tags": ["directory_index"],
        "risk_level": "low",
        "confidence": "high",
        "risk_flags": [],
        "storage_policy": "safe_summary",
        "review_status": "pending",
        "safety_reason": "directory_index",
        "priority_score": 10,
        "screenshot_policy": "allowed",
        "queue_policy": "expand",
        "active": 1,
    }


def _insert_analyst_url(url, policy, status="crawled"):
    url_id = storage.insert_or_update_onion_url(url, HOST, status=status)
    with storage.get_db() as db:
        stored_url = db.execute("SELECT url FROM onion_urls WHERE id=?", (url_id,)).fetchone()[0]
        db.execute("UPDATE onion_urls SET analyst_category=? WHERE id=?",
                   (policy["analyst_category"], url_id))
    storage.apply_onion_policy(stored_url, policy)
    return url_id


def test_connection_workbench_returns_safe_cards_and_graph(isolated_db):
    url = f"http://{HOST}/"
    url_id = _insert_analyst_url(url, _policy())
    card_id = site_dedupe.ensure_url_site_card(
        url_id,
        _policy(),
        title="Workbench Directory",
        visible_text="safe directory index",
    )

    cards = storage.get_connection_workbench()
    assert any(int(card["id"]) == int(card_id) for card in cards)

    graph = storage.get_site_evidence_graph(card_id)
    assert any(node["kind"] == "site_card" for node in graph["nodes"])
    assert any(node["kind"] == "onion_url" and url in node["label"] for node in graph["nodes"])
    assert any(edge["label"] == "observed URL" for edge in graph["edges"])


def test_connection_workbench_hides_restricted_cards(isolated_db):
    url = f"http://{HOST}/adult"
    restricted_policy = {
        **_policy(),
        "primary_category": "adult_restricted",
        "category": "adult_restricted",
        "content_category": "adult_restricted",
        "analyst_category": "adult_restricted",
        "storage_policy": "metadata_only",
        "risk_level": "filtered",
        "active": 0,
    }
    url_id = _insert_analyst_url(url, restricted_policy, status="blocked")
    card_id = site_dedupe.ensure_url_site_card(
        url_id,
        {
            **_policy(),
            "primary_category": "adult_restricted",
            "category": "adult_restricted",
            "content_category": "adult_restricted",
            "analyst_category": "adult_restricted",
            "storage_policy": "metadata_only",
            "risk_level": "filtered",
            "active": 0,
        },
        title="Restricted Placeholder",
        visible_text="",
    )

    with storage.get_db() as db:
        db.execute(
            "UPDATE site_cards SET primary_category='adult_restricted', storage_policy='metadata_only', ui_hidden_default=1 WHERE id=?",
            (card_id,),
        )
        db.commit()

    cards = storage.get_connection_workbench()
    assert all(int(card["id"]) != int(card_id) for card in cards)


def test_intelligence_timeline_includes_safe_site_card_events(isolated_db):
    url = f"http://{HOST}/timeline"
    url_id = _insert_analyst_url(url, _policy())
    card_id = site_dedupe.ensure_url_site_card(
        url_id,
        _policy(),
        title="Timeline Directory",
        visible_text="safe directory index",
    )
    with storage.get_db() as db:
        db.execute(
            """INSERT INTO site_card_events(site_card_id,event_type,event_summary,safe_metadata_json,created_at)
               VALUES(?,?,?,?,?)""",
            (card_id, "card_updated", "Category evidence refreshed", '{"reason":"test"}',
             "2026-07-11T12:00:00Z"),
        )
        db.commit()

    events = storage.get_intelligence_timeline()
    assert any(
        event.get("event_family") == "site_card"
        and event.get("site_card_id") == card_id
        and event.get("summary") == "Category evidence refreshed"
        for event in events
    )
