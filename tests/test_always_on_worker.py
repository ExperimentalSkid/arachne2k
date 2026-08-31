from pathlib import Path

from streamlit.testing.v1 import AppTest

import onion_worker
import storage


def _url(letter: str) -> str:
    return f"http://{letter * 56}.onion/"


def _policy(*, spain=False, risk="low", category="unknown", priority=0):
    return {
        "primary_category": category, "category": category, "tags": [],
        "risk_level": risk, "confidence": "high", "risk_flags": [],
        "storage_policy": "safe_summary", "review_status": "pending",
        "safety_reason": "test", "priority_score": priority,
        "screenshot_policy": "allowed", "queue_policy": "expand", "active": 1,
        "spain_priority": spain,
    }


def test_worker_state_counters_pause_and_duplicate_sources(isolated_db):
    url = _url("a")
    first = storage.insert_or_update_onion_url(url, source_url="seed-a", source_type="manual")
    second = storage.insert_or_update_onion_url(url, source_url="seed-b", source_type="page")
    assert first == second
    with storage.get_db() as db:
        row = dict(db.execute("SELECT * FROM onion_urls WHERE id=?", (first,)).fetchone())
    assert row["seen_count"] == 2
    assert row["source_count"] == 2
    assert row["canonical_url"] == url
    assert row["original_url"] == url

    storage.start_worker()
    storage.record_worker_processed(first)
    storage.set_worker_paused(True)
    worker = storage.get_worker_state()
    assert worker["worker_name"] == "onion_worker"
    assert worker["last_heartbeat_at"]
    assert worker["started_at"]
    assert worker["processed_total"] == 1
    assert worker["processed_today"] == 1
    assert worker["last_url_id"] == first
    assert worker["is_paused"] == 1


def test_queue_prefers_spain_then_risk_and_directory(isolated_db):
    directory = _policy(category="directory_index", priority=5)
    directory.update(analyst_category="directory_index",
                     classification_evidence_source="analyst")
    storage.insert_or_update_onion_url(_url("a"), policy=directory)
    high_risk = _policy(risk="high", category="weapons_arms", priority=50)
    high_risk.update(analyst_category="weapons_arms",
                     classification_evidence_source="analyst")
    storage.insert_or_update_onion_url(_url("b"), policy=high_risk)
    spain = _url("c")
    spain_policy = _policy(spain=True, category="weapons_arms", priority=1)
    spain_policy.update(analyst_category="weapons_arms",
                        classification_evidence_source="analyst")
    storage.insert_or_update_onion_url(spain, policy=spain_policy)
    assert storage.get_next_onion_url()["url"] == spain


def test_loop_survives_iteration_failure_and_stops_cleanly(isolated_db, monkeypatch):
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("one bad URL must not stop service")
        return True

    monkeypatch.setattr(onion_worker, "process_one", flaky)
    monkeypatch.setattr(onion_worker, "run_maintenance", lambda: {})
    monkeypatch.setattr(onion_worker, "get_int", lambda _name, default: 1)
    onion_worker.run_loop(max_iterations=3, sleep_fn=lambda _seconds: None)
    assert len(calls) == 3
    worker = storage.get_worker_state()
    assert worker["state"] == "stopped"
    assert worker["last_error"] == "iteration:RuntimeError"


def test_paused_loop_heartbeats_without_processing(isolated_db, monkeypatch):
    storage.set_worker_paused(True)
    monkeypatch.setattr(onion_worker, "process_one", lambda: (_ for _ in ()).throw(AssertionError("processed")))
    monkeypatch.setattr(onion_worker, "run_maintenance", lambda: {})
    monkeypatch.setattr(onion_worker, "get_int", lambda _name, default: 1)
    onion_worker.run_loop(max_iterations=1, sleep_fn=lambda _seconds: None)
    worker = storage.get_worker_state()
    assert worker["is_paused"] == 1
    assert worker["last_heartbeat_at"]


def test_search_seed_is_retired_after_two_failures_and_status_counts_it(isolated_db):
    url = _url("s")
    storage.insert_or_update_onion_url(url, source_type="search_seed")
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET error_count=2,status='retry',active=1 WHERE url=?", (url,))
    assert storage.automatic_dead_cleanup() == 1
    with storage.get_db() as db:
        row = dict(db.execute("SELECT status,active,dead_reason FROM onion_urls WHERE url=?", (url,)).fetchone())
    assert row == {"status": "dead", "active": 0, "dead_reason": "search_seed_timeout"}
    assert onion_worker.status_counts()["dead"] == 1


def test_dashboard_home_explains_service_health(isolated_db):
    storage.heartbeat_worker_instance(
        "fetch-home-test",
        "fetch",
        state="idle",
        processed_increment=1,
    )
    app = AppTest.from_file(str(Path(__file__).parents[1] / "dashboard.py"), default_timeout=20).run()
    assert not app.exception
    rendered = "\n".join(str(item.value) for item in app.markdown)
    assert "Background services" in rendered
    assert "<strong>Fetch workers</strong>" in rendered
    assert "Open operations" in {item.label for item in app.button}
