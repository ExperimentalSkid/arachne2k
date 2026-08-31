import sqlite3
from pathlib import Path

from streamlit.testing.v1 import AppTest

import consistency
import site_dedupe
import storage
from dashboard_pages import workspace
from scripts.backup_sqlite import backup_database


HOST = "c" * 56 + ".onion"
URL = f"http://{HOST}/"


def _policy(category="directory_index"):
    policy = {
        "primary_category": category, "category": category, "tags": [category],
        "risk_level": "low", "confidence": "medium", "risk_flags": [],
        "storage_policy": "safe_summary", "review_status": "monitor",
        "safety_reason": "test", "priority_score": 10,
        "screenshot_policy": "allowed", "queue_policy": "expand", "active": 1,
        "spain_priority": False, "card_ready": 1, "safe_display_name": "Pipeline Test",
        "page_type": "homepage", "page_type_confidence": "medium",
        "category_confidence": "medium",
    }
    if category != "unknown":
        # Pipeline bookkeeping tests need a deterministic setup card. Mark the
        # fixture as an explicit analyst category instead of pretending that a
        # hand-built dict came from fetched destination HTML.
        policy.update(
            content_category=category, analyst_category=category,
            classification_evidence_source="analyst")
    return policy


def _insert_analyst_fixture(url, *, status="crawled", category="directory_index"):
    """Create setup-only card state as an explicit analyst decision."""
    policy = _policy(category)
    url_id = storage.insert_or_update_onion_url(url, HOST, status=status)
    if category != "unknown":
        with storage.get_db() as db:
            db.execute("""UPDATE onion_urls SET analyst_category=?,primary_category=?,
              category=?,content_category=?,classification_evidence_source='analyst'
              WHERE id=?""", (category, category, category, category, url_id))
        storage.apply_onion_policy(url, policy)
    return url_id, policy


def test_dashboard_pipeline_counters_read_staged_tables(isolated_db):
    url_id, policy = _insert_analyst_fixture(URL, status="queued")
    storage.heartbeat_worker_instance("fetch:test", "fetch", "idle", processed_increment=2)
    storage.heartbeat_worker_instance("verify:test", "verify", "idle", processed_increment=3)
    storage.heartbeat_worker_instance("card:test", "card", "idle", processed_increment=4)
    storage.store_fetched_page_snapshot(
        url_id, URL, worker_id="fetch:test", response_status=200,
        content_type="text/html", headers={}, title="Pipeline Test", meta_text="",
        visible_text="safe page", link_records=[], page_structure={}, pre_policy=policy)
    snapshot = storage.claim_next_fetched_page("verify:test")
    storage.mark_fetched_page_verified(int(snapshot["id"]))
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Pipeline Test")
    with storage.get_db() as db:
        db.execute("UPDATE site_card_jobs SET status='done' WHERE job_type='enrich_card'")
    job_id = storage.create_site_card_job(onion_url_id=url_id, site_card_id=card_id, url=URL)
    claimed = storage.claim_next_site_card_job("card:test")
    assert claimed and claimed["id"] == job_id
    storage.finish_site_card_job(job_id, success=True, site_card_id=card_id)

    status = workspace._pipeline_status()

    assert status["fetch_workers"] == 1
    assert status["verify_workers"] == 1
    assert status["card_workers"] == 1
    assert status["verified_today"] == 1
    assert status["card_jobs_done_today"] >= 1
    assert status["processed_today"] >= 2
    assert status["newest_worker_type"] in {"fetch", "verify", "card"}


def test_dashboard_does_not_count_stopped_or_stale_workers_as_online(isolated_db):
    storage.heartbeat_worker_instance("fetch:stopped", "fetch", "stopped")
    storage.heartbeat_worker_instance("verify:stale", "verify", "idle")
    with storage.get_db() as db:
        db.execute("""UPDATE worker_instances SET last_heartbeat_at='2000-01-01T00:00:00Z'
          WHERE worker_id='verify:stale'""")

    status = workspace._pipeline_status()

    assert status["fetch_workers"] == 0
    assert status["verify_workers"] == 0
    assert status["newest_worker_state"] in {"stopped", "idle"}


def test_operational_health_uses_fresh_staged_workers_not_legacy_state(isolated_db):
    storage.update_worker_state("running", "legacy row should not define staged health")
    storage.heartbeat_worker_instance("fetch:fresh", "fetch", "idle")
    storage.heartbeat_worker_instance("verify:stale", "verify", "idle")
    storage.heartbeat_worker_instance("card:stopped", "card", "stopped")
    with storage.get_db() as db:
        db.execute("""UPDATE worker_instances SET last_heartbeat_at='2000-01-01T00:00:00Z'
          WHERE worker_id='verify:stale'""")

    health = storage.get_operational_health()

    assert health["worker"]["state"] == "degraded"
    assert health["worker"]["active_instances"] == 1
    assert health["worker"]["worker_types"] == ["fetch"]
    assert health["worker_instances"][0]["worker_id"] == "fetch:fresh"


def test_crawl_queue_renders_when_legacy_worker_state_missing(isolated_db):
    with storage.get_db() as db:
        db.execute("DELETE FROM crawler_worker_state WHERE id=1")
    storage.heartbeat_worker_instance("fetch:test", "fetch", "idle", processed_increment=1)
    storage.heartbeat_worker_instance("verify:test", "verify", "idle", processed_increment=1)
    storage.heartbeat_worker_instance("card:test", "card", "idle", processed_increment=1)

    app = AppTest.from_file(str(Path(__file__).parents[1] / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value("Crawl Queue").run()

    assert not app.exception
    assert any("Worker online" in str(item.value) for item in app.success)


def test_rebuild_preserves_analyst_fields_and_pending_merge_candidates(isolated_db):
    url_id, policy = _insert_analyst_fixture(URL)
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Pipeline Test")
    weak_url = f"http://{HOST}/about"
    weak_id = storage.insert_or_update_onion_url(weak_url, HOST, status="crawled", policy=_policy("unknown"))
    with storage.get_db() as db:
        db.execute("""UPDATE site_cards SET analyst_title='Analyst title',
          analyst_notes='Do not erase',analyst_category='hosting_services',
          analyst_importance='high',review_status='relevant',report_status='ready',
          rollup_dirty=1 WHERE id=?""", (card_id,))
        db.execute("""INSERT INTO possible_site_card_matches(onion_url_id,candidate_site_card_id,
          reason,confidence,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)""",
          (weak_id, card_id, "test", "possible_mirror", "pending",
           storage.utc_now_iso(), storage.utc_now_iso()))

    result = site_dedupe.refresh_dirty_site_cards()

    with storage.get_db() as db:
        card = dict(db.execute("""SELECT analyst_title,analyst_notes,analyst_category,
          analyst_importance,review_status,report_status,rollup_dirty FROM site_cards WHERE id=?""",
          (card_id,)).fetchone())
        pending = db.execute("""SELECT COUNT(*) FROM possible_site_card_matches
          WHERE candidate_site_card_id=? AND status='pending'""", (card_id,)).fetchone()[0]
    assert result["refreshed"] == 1
    assert card["analyst_title"] == "Analyst title"
    assert card["analyst_notes"] == "Do not erase"
    assert card["analyst_category"] == "hosting_services"
    assert card["analyst_importance"] == "high"
    assert card["review_status"] == "relevant"
    assert card["report_status"] == "ready"
    assert card["rollup_dirty"] == 0
    assert pending == 1


def test_auto_merge_keeps_analyst_enriched_target_card(isolated_db):
    first_id, first_policy = _insert_analyst_fixture(URL)
    first_card = site_dedupe.ensure_url_site_card(first_id, first_policy, title="Plain")
    second_url = f"http://{HOST}/mirror"
    second_id, _second_policy = _insert_analyst_fixture(second_url)
    now = storage.utc_now_iso()
    with storage.get_db() as db:
        second_card = db.execute("""INSERT INTO site_cards
          (canonical_site_id,display_name,primary_category,storage_policy,first_seen,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?)""", ("manual-duplicate", "Analyst", "directory_index",
          "safe_summary", now, now, now)).lastrowid
        db.execute("""INSERT INTO site_card_urls(site_card_id,onion_url_id,url,onion_host,path,
          first_seen,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)""",
          (second_card, second_id, second_url, HOST, "/mirror", now, now, now))
        db.execute("UPDATE onion_urls SET site_card_id=? WHERE id=?", (second_card, second_id))
        db.execute("UPDATE site_cards SET analyst_title='Keep me' WHERE id=?", (second_card,))

    assert first_card != second_card
    result = site_dedupe.reconcile_duplicate_site_cards(dry_run=False)

    with storage.get_db() as db:
        cards = [dict(row) for row in db.execute("SELECT id,analyst_title FROM site_cards")]
    assert result["merged"] >= 1
    assert len(cards) == 1
    assert cards[0]["analyst_title"] == "Keep me"
    assert cards[0]["id"] == second_card


def test_consistency_audit_categorizes_conflicts(isolated_db):
    storage.insert_or_update_onion_url(URL, HOST, status="blocked", policy=_policy())
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET queue_policy='normal' WHERE url=?", (URL,))

    audit = consistency.audit_consistency()

    details = {item["category"]: item for item in audit["details"]}
    assert details["blocked_normal_queue_conflicts"]["severity"] == "low"
    assert details["blocked_normal_queue_conflicts"]["safe_auto_repair"] is True
    assert details["blocked_normal_queue_conflicts"]["affects_analyst_data"] is False


def test_sqlite_backup_uses_snapshot_and_retention(tmp_path):
    db_path = tmp_path / "messages.db"
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, value TEXT)")
        db.execute("INSERT INTO sample(value) VALUES('ok')")
    backup_dir = tmp_path / "backups"

    first = backup_database(db_path, backup_dir, keep=1)
    second = backup_database(db_path, backup_dir, keep=1)

    assert second.exists()
    assert len(list(backup_dir.glob("messages_*.db"))) == 1
    with sqlite3.connect(second) as db:
        assert db.execute("SELECT value FROM sample").fetchone()[0] == "ok"
    assert isinstance(first, Path)
