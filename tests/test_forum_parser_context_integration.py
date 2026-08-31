import onion_worker
import storage


HOST = "q" * 56 + ".onion"
FORUM = f"http://{HOST}/forum/"


def _forum_policy():
    return {
        "primary_category": "forum_social", "category": "forum_social",
        "content_category": "forum_social", "page_type": "forum_index",
        "storage_policy": "safe_summary", "review_status": "monitor",
        "screenshot_policy": "allowed", "queue_policy": "expand", "active": 1,
        "risk_level": "low", "priority_score": 10, "spain_priority": False,
    }


def _safe_child():
    return {
        "decision": "accept", "active": 1, "queue_policy": "normal",
        "primary_category": "unknown", "category": "unknown",
        "storage_policy": "safe_summary", "safety_reason": "safe_test_child",
        "spain_priority": False,
    }


def test_parser_exposes_safe_stable_unverified_forum_route_hint_only():
    first = f"http://{HOST}/viewtopic.php?f=4&t=77&start=20&sid=one"
    second = f"http://{HOST}/viewtopic.php?t=77&sid=two&f=4&start=40"

    _title, _meta, _text, _records, first_structure = onion_worker._parse(
        b"<html><body>Forum topic</body></html>", "text/html", first)
    _title, _meta, _text, _records, second_structure = onion_worker._parse(
        b"<html><body>Forum topic</body></html>", "text/html", second)

    hint = first_structure["forum_route_hint"]
    assert hint["role"] == "pagination"
    assert hint["engine"] == "phpbb"
    assert hint["confidence"] == "high"
    assert hint["stable_key"] == f"forum:{HOST}:phpbb:thread:77"
    assert len(hint["canonical_identity_hash"]) == 64
    assert hint["canonical_identity_hash"] == second_structure["forum_route_hint"]["canonical_identity_hash"]
    assert hint["hint_verified"] is False
    assert hint["evidence_source"] == "url_route"
    assert first_structure["page_type_info"]["page_type"] == "unknown"
    assert "exact_url" not in hint and "canonical_url" not in hint


def test_forum_thread_detection_reuses_conservative_route_identity():
    assert onion_worker._is_forum_thread_url(f"http://{HOST}/viewtopic.php?t=7")
    assert onion_worker._is_forum_thread_url(f"http://{HOST}/showthread.php?t=8&start=20")
    assert onion_worker._is_forum_thread_url(f"http://{HOST}/index.php?topic=9.20")
    assert onion_worker._is_forum_thread_url(f"http://{HOST}/posts/10")
    assert not onion_worker._is_forum_thread_url(f"http://{HOST}/viewforum.php?f=2")
    assert not onion_worker._is_forum_thread_url(f"http://{HOST}/login.php")
    assert not onion_worker._is_forum_thread_url(f"http://{HOST}/attachment.php?id=4")


def test_repeated_contexts_are_decided_independently_not_cross_concatenated(
        isolated_db, monkeypatch):
    calls = []

    def fake_decide(_url, **kwargs):
        pair = (kwargs.get("anchor_text") or "", kwargs.get("source_context") or "")
        calls.append(pair)
        policy = _safe_child()
        if "alpha" in pair[0] and "beta" in pair[1]:
            policy.update(
                decision="restrict", active=0, queue_policy="blocked",
                primary_category="severe_abuse_risk", category="severe_abuse_risk",
                storage_policy="discard", safety_reason="synthetic_combined_signal",
            )
        return policy

    monkeypatch.setattr(onion_worker, "_decide", fake_decide)
    child = f"http://{HOST}/thread/11"
    record = {
        "url": child, "anchor_text": "alpha", "section_context": "ordinary",
        "occurrence_count": 2,
        "context_observations": [
            {"anchor_text": "alpha", "section_context": "ordinary"},
            {"anchor_text": "ordinary", "section_context": "beta"},
        ],
    }

    summary, classified = onion_worker.classify_outbound_records(
        {"url": FORUM, "depth": 0}, [record], _forum_policy())

    assert calls == [("alpha", "ordinary"), ("ordinary", "beta")]
    assert classified[0]["policy"]["primary_category"] == "unknown"
    assert summary["total"] == 1 and summary["severe"] == 0


def test_strictest_child_policy_wins_once_per_unique_url(isolated_db, monkeypatch):
    def fake_decide(_url, **kwargs):
        marker = kwargs.get("anchor_text") or ""
        policy = _safe_child()
        if marker == "blocked":
            policy.update(decision="reject", active=0, queue_policy="blocked",
                          storage_policy="metadata_only", safety_reason="blocked_file_type")
        elif marker == "adult":
            policy.update(decision="restrict", active=0, queue_policy="blocked",
                          primary_category="adult_restricted", category="adult_restricted",
                          storage_policy="metadata_only", safety_reason="adult_content_filtered")
        elif marker == "severe":
            policy.update(decision="restrict", active=0, queue_policy="blocked",
                          primary_category="severe_abuse_risk", category="severe_abuse_risk",
                          storage_policy="discard", safety_reason="synthetic_severe_signal")
        return policy

    monkeypatch.setattr(onion_worker, "_decide", fake_decide)
    child = f"http://{HOST}/thread/12"
    records = [
        {"url": child, "anchor_text": "safe", "section_context": "one"},
        {"url": child, "anchor_text": "blocked", "section_context": "two"},
        {"url": child, "anchor_text": "adult", "section_context": "three"},
        {"url": child, "anchor_text": "severe", "section_context": "four"},
    ]

    summary, classified = onion_worker.classify_outbound_records(
        {"url": FORUM, "depth": 0}, records, _forum_policy())

    assert len(classified) == 1
    assert classified[0]["policy"]["primary_category"] == "severe_abuse_risk"
    assert classified[0]["occurrence_count"] == 4
    assert summary["total"] == 1
    assert summary["severe"] == 1 and summary["adult"] == 0
    assert summary["restricted"] == 1 and summary["blocked"] == 1


def test_later_strong_forum_observation_is_prioritized_within_existing_budget(
        isolated_db, monkeypatch):
    monkeypatch.setenv("ONION_FORUM_INITIAL_THREAD_LIMIT", "25")
    parent_id = storage.insert_or_update_onion_url(
        FORUM, HOST, status="crawled", policy=_forum_policy())
    records = [{
        "url": f"http://{HOST}/thread/{index}",
        "anchor_text": f"Ordinary discussion {index}",
        "section_context": "Recent public threads",
    } for index in range(26)]
    records[-1] = {
        "url": f"http://{HOST}/thread/25",
        "anchor_text": "Ordinary discussion 25",
        "section_context": "Recent public threads",
        "occurrence_count": 2,
        "context_observations": [
            {"anchor_text": "Ordinary discussion 25", "section_context": "Recent public threads"},
            {"anchor_text": "Weapons shipping to Madrid", "section_context": "Priority discussions"},
        ],
    }

    onion_worker._store_discovered_links(
        {"id": parent_id, "url": FORUM, "depth": 0}, records, _forum_policy())

    prioritized = storage.get_onion_url_by_url(f"http://{HOST}/thread/25")
    assert prioritized["status"] == "queued"
    with storage.get_db() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM onion_urls WHERE source_type='forum_thread_hint' AND status='queued'"
        ).fetchone()[0] == 25
