import storage
import onion_worker


HOST = "q" * 56 + ".onion"


def _url(path: str) -> str:
    return f"http://{HOST}{path}"


def test_deep_pagination_is_deferred_and_reversible(isolated_db):
    url = _url("/category/tools/page/10/")
    policy = onion_worker._decide(url, source_context="directory", depth=2)
    assert policy["decision"] == "fetch_later"
    assert policy["defer_requested"] is True
    item_id = storage.insert_or_update_onion_url(url, HOST, status="queued", policy=policy)
    storage.apply_crawl_decision(url, policy)
    assert storage.defer_frontier_url(url, policy["defer_reason"])
    row = storage.get_onion_url_by_url(url)
    assert row["id"] == item_id
    assert row["status"] == "deferred_deep_pagination"
    assert row["active"] == 0
    assert storage.get_next_onion_url() is None

    preview = storage.manage_deep_pagination(restore=True, apply=False)
    assert preview["matched"] == 1 and preview["changed"] == 0
    restored = storage.manage_deep_pagination(restore=True, apply=True)
    assert restored["changed"] == 1
    assert storage.get_onion_url_by_url(url)["status"] == "retry"


def test_pages_six_to_nine_are_low_priority_but_not_deferred(isolated_db):
    policy = onion_worker._decide(_url("/tag/tools/page/7/"), source_context="directory", depth=2)
    shallow = onion_worker._decide(_url("/tag/tools/page/1/"), source_context="directory", depth=2)
    assert policy["pagination_page"] == 7
    assert not policy.get("defer_requested")
    assert policy["novelty_score"] < shallow["novelty_score"]


def test_failed_maintenance_has_persistent_backoff(isolated_db):
    storage.record_maintenance_start("test_task", 100.0)
    storage.record_maintenance_result(
        "test_task", success=False, duration_seconds=1.5,
        error=RuntimeError("bounded failure"), backoff_hours=6,
    )
    assert storage.maintenance_allowed("test_task") is False
    with storage.get_db() as db:
        row = db.execute("SELECT * FROM worker_maintenance_state WHERE task_name='test_task'").fetchone()
    assert row["failure_type"] == "RuntimeError"
    assert row["failure_message"] == "bounded failure"
    assert row["duration_seconds"] == 1.5


def test_worker_state_exposes_stage_pid_rss_and_progress(isolated_db):
    storage.start_worker()
    storage.update_worker_state("fetching", "Waiting for Tor", _url("/"), last_url_id=17)
    state = storage.get_worker_state()
    assert state["worker_pid"]
    assert state["current_stage"] == "fetching"
    assert state["current_url_id"] == 17
    assert state["fetch_started_at"]
    assert state["last_progress_at"]
    assert state["rss_mb"] >= 0
