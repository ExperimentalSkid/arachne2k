from concurrent.futures import ThreadPoolExecutor
import json

import pytest

import onion_worker
import storage
import site_dedupe


HOST = "a" * 56 + ".onion"
URL = f"http://{HOST}/"
DIRECTORY_HTML = """<html><head><title>Public Directory</title></head><body>
<h1>Public Directory</h1><p>Independent public resources.</p>
<a href='http://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion/'>One</a>
<a href='http://cccccccccccccccccccccccccccccccccccccccccccccccccccccccc.onion/'>Two</a>
<a href='http://dddddddddddddddddddddddddddddddddddddddddddddddddddddddd.onion/'>Three</a>
<a href='http://eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.onion/'>Four</a>
<a href='http://ffffffffffffffffffffffffffffffffffffffffffffffffffffffff.onion/'>Five</a>
</body></html>"""


def _policy(category="directory_index"):
    return {
        "primary_category": category, "category": category, "tags": [category],
        "risk_level": "low", "confidence": "medium", "risk_flags": [],
        "storage_policy": "safe_summary", "review_status": "monitor",
        "safety_reason": "test", "priority_score": 10,
        "screenshot_policy": "allowed", "queue_policy": "expand", "active": 1,
        "spain_priority": False, "card_ready": 1,
    }


def _spain_policy():
    policy = _policy("weapons_arms")
    policy.update({
        "page_type": "thread_page",
        "risk_level": "high",
        "spain_priority": True,
        "spain_confidence": "high",
        "spain_relevance": "high",
        "spain_actionable": True,
        "spain_context_only": False,
        "spain_evidence_score": 92,
        "spain_match_language": "ES",
        "spain_match_reason": "Direct seller offers shipping to Spain",
        "spain_priority_reason": "spanish_market_targeting",
        "spain_priority_evidence_type": "shipping_to_spain",
        "spain_evidence_type": "shipping_to_spain",
        "spain_context_tags": ["trade_flow_to_spain", "market_or_actor_context"],
    })
    return policy


def _persist_verified(url, policy, *, html=DIRECTORY_HTML):
    title, _meta, _visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    verified = onion_worker.finalize_page_policy(
        url, dict(policy), title=title, page_structure=structure)
    url_id = storage.insert_or_update_onion_url(
        url, url.split("/")[2], status="crawled")
    storage.apply_onion_policy(
        url, verified, 200, checked=True, page_structure=structure)
    return url_id, verified


def test_parallel_fetch_workers_cannot_claim_same_onion_url(isolated_db):
    storage.insert_or_update_onion_url(URL, HOST, status="queued", policy=_policy())

    first = storage.claim_next_onion_url(worker_id="fetch-a")
    second = storage.claim_next_onion_url(worker_id="fetch-b")

    assert first and first["url"] == URL
    assert second is None
    with storage.get_db() as db:
        row = dict(db.execute("SELECT status,claimed_by FROM onion_urls WHERE url=?", (URL,)).fetchone())
    assert row == {"status": "claimed", "claimed_by": "fetch-a"}


def test_parallel_verify_workers_cannot_claim_same_fetched_snapshot(isolated_db):
    url_id = storage.insert_or_update_onion_url(URL, HOST, status="classification_pending", policy=_policy())
    storage.store_fetched_page_snapshot(
        url_id, URL, worker_id="fetch-a", response_status=200, content_type="text/html",
        headers={"Content-Type": "text/html"}, title="Directory", meta_text="",
        visible_text="safe directory text", link_records=[], page_structure={}, pre_policy=_policy(),
    )

    first = storage.claim_next_fetched_page("verify-a")
    second = storage.claim_next_fetched_page("verify-b")

    assert first and first["url"] == URL
    assert second is None
    with storage.get_db() as db:
        row = dict(db.execute("SELECT classification_status,claimed_by FROM fetched_pages WHERE url=?", (URL,)).fetchone())
    assert row == {"classification_status": "claimed", "claimed_by": "verify-a"}


def test_parallel_card_workers_cannot_claim_same_site_card_job(isolated_db):
    url_id = storage.insert_or_update_onion_url(URL, HOST, status="crawled", policy=_policy())
    job_id = storage.create_site_card_job(onion_url_id=url_id, url=URL, priority=10)

    first = storage.claim_next_site_card_job("card-a")
    second = storage.claim_next_site_card_job("card-b")

    assert first and first["id"] == job_id
    assert second is None
    with storage.get_db() as db:
        row = dict(db.execute("SELECT status,claimed_by FROM site_card_jobs WHERE id=?", (job_id,)).fetchone())
    assert row == {"status": "claimed", "claimed_by": "card-a"}


def test_card_worker_attaches_verify_stage_actor_observation_to_created_card(isolated_db):
    url = f"http://{HOST}/viewtopic.php?t=17"
    policy = _policy("forum_social")
    policy["page_type"] = "thread_page"
    thread_html = """<html><head><title>Public forum thread</title></head><body>
    <article class='post'><span class='username'>NightFox</span><p>Public discussion post.</p></article>
    </body></html>"""
    url_id, policy = _persist_verified(url, policy, html=thread_html)
    actor_ids = storage.store_actor_observations(url, [{
        "alias": "NightFox",
        "normalized_alias": "nightfox",
        "evidence_type": "phpbb_post_author",
        "confidence": 0.98,
        "profile_url": f"http://{HOST}/memberlist.php?mode=viewprofile&u=17",
        "source_scope": "post_author",
    }], [], policy)
    assert len(actor_ids) == 1
    with storage.get_db() as db:
        before = db.execute(
            "SELECT site_card_id FROM actor_observations WHERE actor_id=? AND url=?",
            (actor_ids[0], url),
        ).fetchone()
    assert before["site_card_id"] is None

    job_id = storage.create_site_card_job(onion_url_id=url_id, url=url, priority=10)
    assert onion_worker.process_card_job("card:actor-attachment") is True

    with storage.get_db() as db:
        url_row = db.execute("SELECT site_card_id FROM onion_urls WHERE id=?", (url_id,)).fetchone()
        observation = db.execute(
            "SELECT site_card_id FROM actor_observations WHERE actor_id=? AND url=?",
            (actor_ids[0], url),
        ).fetchone()
        job = db.execute("SELECT status,site_card_id FROM site_card_jobs WHERE id=?", (job_id,)).fetchone()
    assert url_row["site_card_id"] is not None
    assert observation["site_card_id"] == url_row["site_card_id"]
    assert dict(job) == {"status": "done", "site_card_id": url_row["site_card_id"]}


def test_card_worker_queues_spain_alert_from_exact_verified_url_and_dedupes(isolated_db):
    exact_url = f"http://{HOST}/viewtopic.php?t=42"
    misleading_job_url = f"http://{HOST}/directory-index"
    policy = _spain_policy()
    spain_html = """<html><head><title>Spain weapons seller thread</title></head><body>
    <article class='post'><span class='username'>VendorOne</span>
    <p>Weapons vendor order shipping to Spain via Correos and Bizum with DNI checks and Madrid delivery.</p>
    </article></body></html>"""
    url_id, policy = _persist_verified(exact_url, policy, html=spain_html)
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET source_url=? WHERE id=?", (misleading_job_url, url_id))
    job_id = storage.create_site_card_job(
        onion_url_id=url_id, url=misleading_job_url, priority=policy["priority_score"])

    assert onion_worker.process_card_job("card:spain-exact") is True
    with storage.get_db() as db:
        alerts = [dict(row) for row in db.execute(
            "SELECT url,payload_json FROM spain_alert_queue ORDER BY id")]
        hits = [dict(row) for row in db.execute(
            "SELECT canonical_url,onion_url_id FROM spain_hits ORDER BY id")]
        completed_job = db.execute(
            "SELECT site_card_id FROM site_card_jobs WHERE id=?", (job_id,)).fetchone()
    assert [row["url"] for row in alerts] == [exact_url]
    assert json.loads(alerts[0]["payload_json"])["url"] == exact_url
    assert len(hits) == 1
    assert hits[0]["canonical_url"] == exact_url
    assert hits[0]["onion_url_id"] == url_id

    # Re-queueing the idempotent card job must not emit another unchanged alert.
    assert storage.create_site_card_job(
        onion_url_id=url_id, site_card_id=completed_job["site_card_id"],
        url=misleading_job_url, priority=policy["priority_score"]) == job_id
    assert onion_worker.process_card_job("card:spain-repeat") is True
    with storage.get_db() as db:
        alert_count = db.execute("SELECT COUNT(*) FROM spain_alert_queue").fetchone()[0]
        hit_count = db.execute("SELECT COUNT(*) FROM spain_hits").fetchone()[0]
    assert alert_count == 1
    assert hit_count == 1


def test_card_processing_lock_prevents_same_card_rollup_in_parallel(isolated_db):
    url_id, policy = _persist_verified(URL, _policy())
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Directory")

    assert storage.acquire_site_card_processing(card_id, "card-a")
    assert not storage.acquire_site_card_processing(card_id, "card-b")
    storage.release_site_card_processing(card_id, "card-a")
    assert storage.acquire_site_card_processing(card_id, "card-b")


def test_card_lock_contention_defers_without_consuming_failure_attempt(isolated_db):
    url_id, policy = _persist_verified(URL, _policy())
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Directory")
    storage.create_site_card_job(onion_url_id=url_id, url=URL, site_card_id=card_id)
    claimed = storage.claim_next_site_card_job("card-a")
    assert claimed
    job_id = int(claimed["id"])

    assert storage.defer_site_card_job(job_id, "card-a", delay_seconds=10)

    with storage.get_db() as db:
        row = dict(db.execute("""SELECT status,claimed_by,attempts,error_type,next_retry_at
          FROM site_card_jobs WHERE id=?""", (job_id,)).fetchone())
    assert row["status"] == "retry"
    assert row["claimed_by"] is None
    assert row["attempts"] == 0
    assert row["error_type"] == "lock_contention"
    assert row["next_retry_at"]


def test_only_one_worker_holds_automatic_maintenance_leader_lock(isolated_db):
    assert storage.acquire_maintenance_leader("automatic_housekeeping", "worker-a", lease_seconds=300)
    assert not storage.acquire_maintenance_leader("automatic_housekeeping", "worker-b", lease_seconds=300)
    storage.release_maintenance_leader("automatic_housekeeping", "worker-a")
    assert storage.acquire_maintenance_leader("automatic_housekeeping", "worker-b", lease_seconds=300)


def test_worker_instance_success_heartbeat_clears_old_error(isolated_db):
    storage.heartbeat_worker_instance("fetch:instance", "fetch", "error", last_error="TimeoutError")
    storage.heartbeat_worker_instance("fetch:instance", "fetch", "idle")

    with storage.get_db() as db:
        row = dict(db.execute("SELECT state,last_error FROM worker_instances WHERE worker_id=?",
                              ("fetch:instance",)).fetchone())
    assert row == {"state": "idle", "last_error": None}


def test_stale_fetch_claim_recovers_after_timeout(isolated_db):
    storage.insert_or_update_onion_url(URL, HOST, status="queued", policy=_policy())
    first = storage.claim_next_onion_url(worker_id="fetch-a", claim_timeout_minutes=45)
    assert first
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET claimed_at='2000-01-01T00:00:00Z' WHERE url=?", (URL,))

    recovered = storage.claim_next_onion_url(worker_id="fetch-b", claim_timeout_minutes=45)

    assert recovered and recovered["url"] == URL
    with storage.get_db() as db:
        row = dict(db.execute("SELECT status,claimed_by FROM onion_urls WHERE url=?", (URL,)).fetchone())
    assert row == {"status": "claimed", "claimed_by": "fetch-b"}


def test_stale_verify_claim_recovers_after_timeout(isolated_db):
    url_id = storage.insert_or_update_onion_url(URL, HOST, status="classification_pending", policy=_policy())
    storage.store_fetched_page_snapshot(
        url_id, URL, worker_id="fetch-a", response_status=200, content_type="text/html",
        headers={}, title="Directory", meta_text="", visible_text="safe", link_records=[],
        page_structure={}, pre_policy=_policy(),
    )
    assert storage.claim_next_fetched_page("verify-a")
    with storage.get_db() as db:
        db.execute("UPDATE fetched_pages SET claimed_at='2000-01-01T00:00:00Z' WHERE url=?", (URL,))

    recovered = storage.claim_next_fetched_page("verify-b", claim_timeout_minutes=45)

    assert recovered and recovered["url"] == URL
    with storage.get_db() as db:
        row = dict(db.execute("SELECT classification_status,claimed_by FROM fetched_pages WHERE url=?", (URL,)).fetchone())
    assert row == {"classification_status": "claimed", "claimed_by": "verify-b"}


def test_stale_card_job_claim_recovers_after_timeout(isolated_db):
    url_id = storage.insert_or_update_onion_url(URL, HOST, status="crawled", policy=_policy())
    job_id = storage.create_site_card_job(onion_url_id=url_id, url=URL, priority=10)
    assert storage.claim_next_site_card_job("card-a")
    with storage.get_db() as db:
        db.execute("UPDATE site_card_jobs SET claimed_at='2000-01-01T00:00:00Z' WHERE id=?", (job_id,))

    recovered = storage.claim_next_site_card_job("card-b", claim_timeout_minutes=45)

    assert recovered and recovered["id"] == job_id
    with storage.get_db() as db:
        row = dict(db.execute("SELECT status,claimed_by FROM site_card_jobs WHERE id=?", (job_id,)).fetchone())
    assert row == {"status": "claimed", "claimed_by": "card-b"}


def test_site_card_job_creation_is_atomic_with_nullable_identity_fields(isolated_db):
    url_id = storage.insert_or_update_onion_url(URL, HOST, status="crawled", policy=_policy())

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(
            lambda _index: storage.create_site_card_job(
                onion_url_id=url_id, site_card_id=None, url=URL, job_type="rollup"),
            range(24),
        ))

    assert len(set(ids)) == 1
    with storage.get_db() as db:
        count = db.execute("""SELECT COUNT(*) FROM site_card_jobs
          WHERE job_type='rollup' AND onion_url_id=? AND site_card_id IS NULL""", (url_id,)).fetchone()[0]
    assert count == 1


def test_stale_verify_owner_cannot_finish_reclaimed_snapshot(isolated_db):
    url_id = storage.insert_or_update_onion_url(URL, HOST, status="classification_pending", policy=_policy())
    storage.store_fetched_page_snapshot(
        url_id, URL, worker_id="fetch-a", response_status=200, content_type="text/html",
        headers={}, title="Directory", meta_text="", visible_text="safe", link_records=[],
        page_structure={}, pre_policy=_policy())
    first = storage.claim_next_fetched_page("verify-a")
    with storage.get_db() as db:
        db.execute("UPDATE fetched_pages SET claimed_at='2000-01-01T00:00:00Z' WHERE id=?", (first["id"],))
    second = storage.claim_next_fetched_page("verify-b")

    assert second and second["id"] == first["id"]
    assert storage.mark_fetched_page_verified(int(first["id"]), "verify-a") is False
    with storage.get_db() as db:
        row = db.execute("SELECT classification_status,claimed_by FROM fetched_pages WHERE id=?",
                         (first["id"],)).fetchone()
    assert dict(row) == {"classification_status": "claimed", "claimed_by": "verify-b"}
    assert storage.mark_fetched_page_verified(int(first["id"]), "verify-b") is True


def test_stale_card_owner_cannot_finish_reclaimed_job(isolated_db):
    url_id = storage.insert_or_update_onion_url(URL, HOST, status="crawled", policy=_policy())
    job_id = storage.create_site_card_job(onion_url_id=url_id, url=URL)
    assert storage.claim_next_site_card_job("card-a")
    with storage.get_db() as db:
        db.execute("UPDATE site_card_jobs SET claimed_at='2000-01-01T00:00:00Z' WHERE id=?", (job_id,))
    assert storage.claim_next_site_card_job("card-b")

    assert storage.finish_site_card_job(job_id, worker_id="card-a") is False
    with storage.get_db() as db:
        row = db.execute("SELECT status,claimed_by FROM site_card_jobs WHERE id=?", (job_id,)).fetchone()
    assert dict(row) == {"status": "claimed", "claimed_by": "card-b"}
    assert storage.finish_site_card_job(job_id, worker_id="card-b") is True


def test_stale_fetch_owner_cannot_overwrite_reclaimed_url(isolated_db):
    storage.insert_or_update_onion_url(URL, HOST, status="queued", policy=_policy())
    first = storage.claim_next_onion_url(worker_id="fetch-a")
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET claimed_at='2000-01-01T00:00:00Z' WHERE id=?", (first["id"],))
    second = storage.claim_next_onion_url(worker_id="fetch-b")
    assert second and second["id"] == first["id"]

    with pytest.raises(storage.WorkerClaimLost):
        storage.store_fetched_page_snapshot(
            int(first["id"]), URL, worker_id="fetch-a", response_status=200,
            content_type="text/html", headers={}, title="stale", meta_text="",
            visible_text="stale", link_records=[], page_structure={}, pre_policy=_policy())
    with storage.get_db() as db:
        row = db.execute("SELECT status,claimed_by FROM onion_urls WHERE id=?", (first["id"],)).fetchone()
    assert dict(row) == {"status": "claimed", "claimed_by": "fetch-b"}


def test_pipeline_pause_prevents_new_claims_at_every_stage(isolated_db):
    fetch_url = f"http://{'f' * 56}.onion/"
    verify_url = f"http://{'v' * 56}.onion/"
    preview_url = f"http://{'p' * 56}.onion/"
    fetch_id = storage.insert_or_update_onion_url(
        fetch_url, "f" * 56 + ".onion", status="queued", policy=_policy())
    verify_id = storage.insert_or_update_onion_url(
        verify_url, "v" * 56 + ".onion", status="classification_pending", policy=_policy())
    storage.store_fetched_page_snapshot(
        verify_id, verify_url, worker_id="fixture", response_status=200, content_type="text/html",
        headers={}, title="Verify", meta_text="", visible_text="safe", link_records=[],
        page_structure={}, pre_policy=_policy())
    storage.create_site_card_job(onion_url_id=fetch_id, url=fetch_url)
    storage.insert_or_update_onion_url(
        preview_url, "p" * 56 + ".onion", status="crawled", policy=_policy())
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET active=1,status='crawled',http_status=200,
          storage_policy='safe_summary',review_status='monitor',screenshot_policy='allowed',
          queue_policy='normal' WHERE url=?""", (preview_url,))
    assert storage.create_page_preview_job(preview_url)

    storage.set_worker_paused(True)

    assert storage.claim_next_onion_url(worker_id="fetch-paused") is None
    assert storage.claim_next_fetched_page("verify-paused") is None
    assert storage.claim_next_site_card_job("card-paused") is None
    assert storage.claim_next_page_preview_job("preview-paused") is None
