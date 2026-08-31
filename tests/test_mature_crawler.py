from crawler_decide_rules import assess_content_liveness, decide_url
import onion_worker
import storage
from universal_classifier import classify
from datetime import datetime, timezone


HOST = "a" * 56 + ".onion"
BASE = f"http://{HOST}/"


def test_ordered_decide_rules_and_trap_signatures():
    file_decision = decide_url(BASE + "archive.zip")
    malformed = decide_url("http://not-an-onion.example/")
    adult = decide_url(BASE + "porn")
    severe = decide_url(BASE + "csam")
    trap = decide_url(BASE + "loop/loop/loop/loop/loop")
    variants = decide_url(BASE + "list?page=2&sort=new", stats={"query_variants": 20})
    assert file_decision["rule_id"] == "DECIDE-001-FILE"
    assert malformed["rule_id"] == "DECIDE-002-MALFORMED"
    # A path label is only a prefetch hint. Destination HTML must verify it.
    assert adult["rule_id"] == "DECIDE-009-PRIORITY" and adult["primary_category"] == "unknown"
    assert severe["rule_id"] == "DECIDE-009-PRIORITY" and severe["primary_category"] == "unknown"
    assert adult["active"] == severe["active"] == 1
    assert trap["rule_id"] == "DECIDE-005-TRAP" and trap["trap_reason"] == "repeated_path_loop"
    assert variants["rule_id"] == "DECIDE-005-TRAP"
    assert variants["path_signature"] and variants["query_signature"] and variants["url_family"]


def test_content_aware_liveness_does_not_equate_200_with_live():
    soft = assess_content_liveness(200, "Site not found", "This site is no longer available")
    empty = assess_content_liveness(200, "", "")
    thin = assess_content_liveness(200, "Hello", "short page")
    useful = assess_content_liveness(200, "Index", "Useful directory text " * 20)
    hard = assess_content_liveness(404, "", "")
    assert soft["liveness_status"] == "soft_dead"
    assert empty["content_quality"] == "empty"
    assert thin["content_quality"] == "thin"
    assert useful["content_quality"] == "meaningful"
    assert hard["liveness_status"] == "hard_dead"


class _Response:
    def __init__(self, status, body=b""):
        self.status_code = status
        self.headers = {"Content-Type": "text/html"}
        self._body = body

    def iter_content(self, chunk_size=16384):
        yield self._body

    def close(self):
        return None


class _Session:
    def __init__(self, response):
        self.response = response

    def get(self, *_args, **_kwargs):
        return self.response


def _queue(url):
    policy = classify(url, visible_text="ordinary safe page")
    return storage.insert_or_update_onion_url(url, status="queued", policy=policy)


def test_http_200_soft_dead_is_inactive_and_does_not_expand_links(isolated_db, monkeypatch):
    source = BASE
    child = "http://" + "b" * 56 + ".onion/"
    _queue(source)
    body = f"<html><title>Site not found</title><body>This site is no longer available<a href='{child}'>Next</a></body></html>".encode()
    monkeypatch.setattr(onion_worker, "_session", lambda: _Session(_Response(200, body)))
    assert onion_worker.process_one()
    row = storage.get_onion_url_by_url(source)
    assert row["liveness_status"] == "soft_dead" and row["active"] == 0 and row["status"] == "dead"
    assert storage.get_onion_url_by_url(child) is None


def test_http_404_does_not_extract_links(isolated_db, monkeypatch):
    source = BASE
    child = "http://" + "c" * 56 + ".onion/"
    _queue(source)
    monkeypatch.setattr(onion_worker, "_session", lambda: _Session(_Response(
        404, f"<a href='{child}'>child</a>".encode())))
    assert onion_worker.process_one()
    row = storage.get_onion_url_by_url(source)
    assert row["liveness_status"] == "hard_dead" and row["active"] == 0
    assert storage.get_onion_url_by_url(child) is None


def test_small_link_list_is_classified_and_expanded_from_fetched_content(isolated_db, monkeypatch):
    source = BASE + "links"
    children = ["http://" + letter * 56 + ".onion/" for letter in ("b", "c")]
    _queue(source)
    body = ("<html><title>Useful onion link list</title><body>"
            + "".join(f"<a href='{url}'>Service {index}</a>" for index, url in enumerate(children))
            + "</body></html>").encode()
    monkeypatch.setattr(onion_worker, "_session", lambda: _Session(_Response(200, body)))

    assert onion_worker.process_one()

    parent = storage.get_onion_url_by_url(source)
    assert parent["primary_category"] == "directory_index"
    for child in children:
        row = storage.get_onion_url_by_url(child)
        assert row["status"] == "queued"
        assert row["primary_category"] == "unknown"
        assert row["site_card_id"] is None


def test_forum_index_expands_then_thread_gets_its_own_spain_classification(isolated_db, monkeypatch):
    forum = BASE + "forum"
    thread = BASE + "viewtopic.php?t=44"
    _queue(forum)
    pages = {
        forum: _Response(200, (
            f"<html><title>Community discussion forum</title><body>"
            f"<ul class='topiclist'><li>Current discussion topics</li>"
            f"<li class='row'><a href='{thread}'>"
            f"Read thread 44</a></li></ul></body></html>"
        ).encode()),
        thread: _Response(200, (
            "<html><title>Thread 44</title><body>"
            "<div class='postbody'>Weapons vendor shipping to Spain with Correos, "
            "Bizum, DNI, and Madrid delivery details.</div>"
            "<div class='postprofile'>Public seller profile</div>"
            "</body></html>"
        ).encode()),
    }

    class _MappingSession:
        def get(self, url, **_kwargs):
            return pages[url]

    monkeypatch.setattr(onion_worker, "_session", lambda: _MappingSession())
    assert onion_worker.process_one()
    queued_thread = storage.get_onion_url_by_url(thread)
    assert queued_thread["status"] == "queued" and queued_thread["site_card_id"] is None

    assert onion_worker.process_one()
    checked_thread = storage.get_onion_url_by_url(thread)
    assert checked_thread["primary_category"] == "weapons_arms"
    assert checked_thread["spain_priority"] == 1 and checked_thread["site_card_id"] is not None
    assert checked_thread["verification_state"] == "verified" and checked_thread["verified_at"]
    assert checked_thread["weapons_evidence_score"] >= 60
    with storage.get_db() as db:
        hit = dict(db.execute("SELECT * FROM spain_hits WHERE canonical_url=?", (thread,)).fetchone())
    assert hit["hit_type"] == "thread"


def test_anchor_only_spain_hint_does_not_change_frontier_priority(isolated_db):
    forum = classify(BASE, visible_text="discussion forum about ordinary hobbies")
    assert forum["primary_category"] == "forum_social" and forum["review_status"] == "monitor"

    generic_url = BASE + "generic"
    spain_url = "http://" + "d" * 56 + ".onion/spain"
    generic = decide_url(generic_url, source_context="ordinary exploration")
    spain = decide_url(spain_url, anchor_text="Guardia Civil weapons trafficking",
                       classification_scope="outbound")
    for url, decision in ((generic_url, generic), (spain_url, spain)):
        storage.insert_or_update_onion_url(url, status="queued", policy=decision)
        storage.apply_crawl_decision(url, decision)
    assert spain["spain_priority"] is False
    assert spain["frontier_priority"] == generic["frontier_priority"]
    assert storage.get_next_onion_url()["url"] == generic_url


def test_verified_spain_weapons_pages_receive_short_revisit_window():
    policy = classify(BASE + "vendor/arms", visible_text="Weapons vendor shipping to Spain with Correos Bizum DNI Madrid",
                      classification_scope="page")
    revisit = datetime.fromisoformat(onion_worker._next_crawl_for_policy(policy, True).replace("Z", "+00:00"))
    hours = (revisit - datetime.now(timezone.utc)).total_seconds() / 3600
    assert 5.9 <= hours <= 6.1
