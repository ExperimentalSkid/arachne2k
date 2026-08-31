import sqlite3

import storage


def test_migrations_and_idempotent_inserts(isolated_db):
    storage.init_db()
    storage.init_db()
    expected = {"onion_urls", "onion_edges", "onion_hits", "indicators", "indicator_links",
                "mirror_clusters", "mirror_urls", "passive_exposures", "evidence_reports", "page_previews", "site_profiles", "crawler_worker_state", "page_topics"}
    with storage.get_db() as db:
        actual = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        indexes = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        onion_columns = {row[1] for row in db.execute("PRAGMA table_info(onion_urls)")}
        edge_columns = {row[1] for row in db.execute("PRAGMA table_info(onion_edges)")}
        card_columns = {row[1] for row in db.execute("PRAGMA table_info(site_cards)")}
        actor_columns = {row[1] for row in db.execute("PRAGMA table_info(actors)")}
        observation_columns = {row[1] for row in db.execute("PRAGMA table_info(actor_observations)")}
    assert expected <= actual
    assert {"idx_onion_urls_source", "idx_onion_edges_discovered", "idx_site_cards_importance",
            "idx_spain_alert_tree", "idx_spain_alert_card"} <= indexes
    assert {"detected_title", "title_source", "identity_confidence", "page_type_confidence",
            "card_ready", "card_readiness_reason", "safe_summary", "content_category",
            "safety_state", "category_evidence_json", "category_update_reason",
            "child_adult_link_count", "child_restricted_link_count", "child_blocked_link_count",
            "parent_evidence_json", "child_link_evidence_json"} <= onion_columns
    assert {"relation_type", "safe_anchor_text", "source_page_type", "same_host",
            "policy_reason"} <= edge_columns
    assert {"identity_site_id", "identity_domain", "identity_canonical_domain",
            "identity_matched_from", "identity_confidence_score", "identity_evidence_json",
            "identity_ambiguous", "identity_missing_fields_json"} <= card_columns
    assert {"identity_key", "identity_kind", "canonical_profile_identity",
            "canonical_profile_url", "alias_skeleton", "identity_confidence"} <= actor_columns
    assert {"profile_identity", "profile_url", "source_scope", "evidence_signals_json",
            "bound_identifier_count"} <= observation_columns
    first = storage.insert_or_update_onion_url("http://" + "a" * 56 + ".onion/")
    second = storage.insert_or_update_onion_url("http://" + "a" * 56 + ".onion/")
    assert first == second
    i1 = storage.upsert_indicator("email", "A@EXAMPLE.COM", "a@example.com", "test", "x", .8)
    i2 = storage.upsert_indicator("email", "a@example.com", "a@example.com", "test", "y", .9)
    assert i1 == i2
    storage.insert_passive_exposures("u", [{"type":"server_header","severity":"info","value":"nginx","context":"header","source":"normal_fetch_response","confidence":.9}])
    assert storage.insert_evidence_report("test", "report.md", "pytest") > 0
    preview_id = storage.upsert_page_preview("http://" + "a" * 56 + ".onion/", "preview.png")
    assert preview_id > 0 and storage.get_page_preview("http://" + "a" * 56 + ".onion/")["preview_path"] == "preview.png"
    storage.update_worker_state("idle", "pytest heartbeat")
    assert storage.get_worker_state()["state"] == "idle"
    retry_url = "http://" + "b" * 56 + ".onion/"
    storage.insert_or_update_onion_url(retry_url, "b" * 56 + ".onion")
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET status='dead' WHERE url=?", (retry_url,))
    assert storage.queue_retryable_urls() == 1
    with storage.get_db() as db:
        assert db.execute("SELECT status FROM onion_urls WHERE url=?", (retry_url,)).fetchone()[0] == "queued"
    storage.upsert_page_topics(retry_url, ["Adult content"], ["porn"])
    assert "Adult content" in storage.get_page_topics(retry_url)["topics_json"]


def test_legacy_actor_unique_constraint_migrates_without_changing_ids_or_observations(
        tmp_path, monkeypatch):
    db_path = tmp_path / "legacy-actor.db"
    monkeypatch.setattr(storage, "DB_PATH", db_path)
    raw = sqlite3.connect(db_path)
    raw.executescript("""
      PRAGMA foreign_keys=ON;
      CREATE TABLE actors (
        id INTEGER PRIMARY KEY AUTOINCREMENT, normalized_alias TEXT NOT NULL,
        display_alias TEXT NOT NULL, onion_host TEXT NOT NULL, generic_role INTEGER DEFAULT 0,
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, observation_count INTEGER DEFAULT 0,
        spain_observation_count INTEGER DEFAULT 0, watched INTEGER DEFAULT 0, watch_reason TEXT,
        analyst_status TEXT DEFAULT 'unreviewed', confidence_score REAL DEFAULT 0,
        confidence_label TEXT DEFAULT 'low', latest_url TEXT, primary_category TEXT,
        risk_level TEXT, UNIQUE(normalized_alias,onion_host)
      );
      CREATE TABLE actor_observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER NOT NULL, url TEXT NOT NULL,
        onion_host TEXT NOT NULL, site_card_id INTEGER, spain_hit_id INTEGER,
        observed_at TEXT NOT NULL, last_seen TEXT NOT NULL, page_type TEXT,
        primary_category TEXT, risk_level TEXT, spain_priority INTEGER DEFAULT 0,
        spain_reason TEXT, evidence_type TEXT NOT NULL, evidence_confidence REAL DEFAULT 0,
        safe_context_label TEXT, analyst_excluded INTEGER DEFAULT 0,
        seller_observation INTEGER DEFAULT 0, spain_flow TEXT DEFAULT 'none',
        marketplace_category TEXT, UNIQUE(actor_id,url,evidence_type),
        FOREIGN KEY(actor_id) REFERENCES actors(id)
      );
    """)
    host = "a" * 56 + ".onion"
    raw.execute("""INSERT INTO actors(id,normalized_alias,display_alias,onion_host,
      first_seen,last_seen,watched,watch_reason) VALUES(7,'nightfox','NightFox',?,?,?,1,'keep')""",
                (host, "2026-01-01Z", "2026-01-02Z"))
    raw.execute("""INSERT INTO actor_observations(actor_id,url,onion_host,observed_at,last_seen,
      evidence_type,evidence_confidence) VALUES(7,?,?,?,?, 'profile_page_identity_match',0.96)""",
                (f"http://{host}/profile", host, "2026-01-01Z", "2026-01-02Z"))
    raw.commit()
    raw.close()

    storage.init_db()
    storage.init_db()

    with storage.get_db() as db:
        actor = dict(db.execute("SELECT * FROM actors WHERE id=7").fetchone())
        observation = dict(db.execute("SELECT actor_id,url FROM actor_observations").fetchone())
        table_sql = db.execute("SELECT sql FROM sqlite_master WHERE name='actors'").fetchone()[0]
        violations = list(db.execute("PRAGMA foreign_key_check"))
    assert actor["display_alias"] == "NightFox" and actor["watched"] == 1
    assert actor["identity_key"].startswith("actor:")
    assert observation["actor_id"] == 7
    assert "UNIQUE(normalized_alias,onion_host)" not in table_sql.replace(" ", "")
    assert violations == []


def test_legacy_forum_expansion_events_gain_logical_idempotence_without_data_loss(
        tmp_path, monkeypatch):
    db_path = tmp_path / "legacy-forum-expansion.db"
    host = "f" * 56 + ".onion"
    first = f"http://{host}/viewtopic.php?t=41"
    old_variant = f"http://{host}/viewtopic.php?t=41&start=25&sid=old"
    with sqlite3.connect(db_path) as raw:
        raw.executescript("""
          CREATE TABLE forum_expansion_events (
            trigger_url TEXT PRIMARY KEY, onion_host TEXT NOT NULL, reason TEXT NOT NULL,
            expanded_by INTEGER DEFAULT 0, created_at TEXT NOT NULL
          );
        """)
        raw.execute("INSERT INTO forum_expansion_events VALUES(?,?,?,?,?)",
                    (first, host, "legacy_first", 25, "2026-01-01T00:00:00Z"))
        raw.execute("INSERT INTO forum_expansion_events VALUES(?,?,?,?,?)",
                    (old_variant, host, "legacy_variant", 25, "2026-01-02T00:00:00Z"))
    monkeypatch.setattr(storage, "DB_PATH", db_path)

    storage.init_db()
    storage.init_db()

    with storage.get_db() as db:
        rows = list(db.execute("""SELECT trigger_url,trigger_identity_hash
          FROM forum_expansion_events ORDER BY created_at"""))
        indexes = {row[1]: row[2] for row in db.execute("PRAGMA index_list(forum_expansion_events)")}
    assert len(rows) == 2
    assert rows[0]["trigger_identity_hash"]
    assert rows[1]["trigger_identity_hash"] is None
    assert indexes["idx_forum_expansion_identity"] == 1

    repeated_variant = storage.expand_deferred_forum_threads(
        host, f"http://{host}/viewtopic.php?t=41&page=9&sid=new",
        "relevant_thread_category:weapons_arms")
    assert repeated_variant["duplicate_trigger"] == 1
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM forum_expansion_events").fetchone()[0] == 2
