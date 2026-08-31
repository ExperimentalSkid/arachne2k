import storage
import pytest
import onion_worker
from universal_classifier import classify


def _verified_policy(url: str, html: str) -> tuple[dict, dict]:
    title, meta, visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = classify(
        url, title=title, meta=meta, visible_text=visible,
        classification_scope="page", page_structure=structure)
    return onion_worker.finalize_page_policy(
        url, policy, title=title, page_structure=structure), structure


def test_policy_columns_migrate_and_verified_restricted_page_is_inactive(isolated_db):
    storage.init_db()
    with storage.get_db() as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(onion_urls)")}
    assert {"primary_category", "storage_policy", "spain_priority", "screenshot_policy", "active",
            "verification_state", "weapons_evidence_score"} <= columns

    url = "http://" + "a" * 56 + ".onion/porn"
    policy, structure = _verified_policy(
        url, "<html><head><title>Adult video marketplace</title></head><body>"
        "Pornographic adult videos, erotic xxx gallery, and adult content."
        "</body></html>")
    storage.insert_or_update_onion_url(url)
    storage.apply_onion_policy(
        url, policy, 200, checked=True, page_structure=structure)
    with storage.get_db() as db:
        row = db.execute("SELECT * FROM onion_urls WHERE url=?", (url,)).fetchone()
    assert row["active"] == 0
    assert row["primary_category"] == "adult_filtered"
    assert row["storage_policy"] == "discard"
    assert row["review_status"] == "filtered"
    assert row["screenshot_policy"] == "blocked"
    assert storage.get_next_onion_url() is None


def test_spain_alert_deduplication(isolated_db):
    url = "http://" + "b" * 56 + ".onion/"
    policy, structure = _verified_policy(
        url, "<html><head><title>Vendor shipping notice</title></head><body>"
        "Weapons vendor order shipping to Spain with Correos delivery."
        "</body></html>")
    storage.insert_or_update_onion_url(url)
    storage.apply_onion_policy(
        url, policy, 200, checked=True, page_structure=structure)
    assert storage.queue_spain_alert(url, policy) is True
    assert storage.queue_spain_alert(url, policy) is False


def test_unverified_spain_link_cannot_create_result_or_alert(isolated_db):
    source = "http://" + "c" * 56 + ".onion/"
    url = "http://" + "d" * 56 + ".onion/vendor/arms"
    policy = classify(url, visible_text="Weapons seller shipping to Spain")
    storage.insert_or_update_onion_url(url, source_url=source, source_type="onion_page",
                                       status="queued", policy=policy)
    assert storage.get_onion_url_by_url(url)["verification_state"] == "provisional"
    assert storage.queue_spain_alert(url, policy) is False
    with pytest.raises(ValueError, match="verified page"):
        storage.insert_onion_hit(url, "Unverified", 1, "high", [], "", [], source)
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM spain_hits WHERE canonical_url=?", (url,)).fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM spain_alert_queue WHERE url=?", (url,)).fetchone()[0] == 0


@pytest.mark.parametrize("legacy_status", ("crawled", "dead", "blocked"))
def test_init_does_not_promote_transport_status_to_content_verified(
        isolated_db, legacy_status):
    host = (legacy_status[0] * 56) + ".onion"
    url = f"http://{host}/{legacy_status}"
    url_id = storage.insert_or_update_onion_url(url, host, status="queued")
    now = storage.utc_now_iso()
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET status=?,last_checked_at=?,last_crawled=?,
          verification_state='discovered',verified_at=NULL,verification_reason='manual_seed',
          primary_category='marketplace_fraud',category='marketplace_fraud'
          WHERE id=?""", (legacy_status, now, now, url_id))
        assert db.execute(
            "SELECT COUNT(*) FROM fetched_pages WHERE onion_url_id=?", (url_id,)).fetchone()[0] == 0

    storage.init_db()

    with storage.get_db() as db:
        row = dict(db.execute("""SELECT verification_state,verified_at,verification_reason
          FROM onion_urls WHERE id=?""", (url_id,)).fetchone())
    assert row["verification_state"] != "verified"
    assert row["verified_at"] is None
    assert row["verification_reason"] == "manual_seed"

