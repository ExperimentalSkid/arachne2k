from pathlib import Path
import json

import pytest
import report_builder
import site_dedupe
import storage
import onion_worker


HOST_A = "a" * 56 + ".onion"
HOST_B = "b" * 56 + ".onion"
HOST_C = "c" * 56 + ".onion"


def policy(category="directory_index", risk="low", storage_policy="safe_summary", **extra):
    result = {
        "primary_category": category, "category": category, "tags": [category],
        "risk_level": risk, "confidence": "high", "risk_flags": [],
        "storage_policy": storage_policy,
        "review_status": "restricted" if storage_policy == "metadata_only" else "pending",
        "safety_reason": category, "priority_score": 10,
        "screenshot_policy": "blocked" if storage_policy == "metadata_only" else "allowed",
        "queue_policy": "blocked" if storage_policy == "metadata_only" else "expand",
        "active": 0 if storage_policy == "metadata_only" else 1,
        "spain_priority": False,
    }
    result.update(extra)
    return result


def add(url, item_policy, title=None, text=None, indicators=None, source=None):
    item_policy = dict(item_policy)
    item_policy.update(
        # These tests exercise card identity/deduplication, not automatic page
        # classification.  Establish the setup category through the explicit
        # analyst boundary instead of pretending that a checked flag proves a
        # destination-HTML classification.
        analyst_category=item_policy["primary_category"],
        content_category=item_policy["primary_category"],
        destination_html_evidence_version=0,
        classification_evidence_source="analyst",
    )
    url_id = storage.insert_or_update_onion_url(
        url, url.split("/")[2], source_url=source,
        status="queued" if item_policy.get("active") else "blocked")
    with storage.get_db() as db:
        stored_url = db.execute("SELECT url FROM onion_urls WHERE id=?", (url_id,)).fetchone()[0]
    storage.apply_onion_policy(stored_url, item_policy)
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET analyst_category=?,primary_category=?,category=?,
          content_category=?,classification_evidence_source='analyst',
          destination_html_evidence_version=0 WHERE id=?""",
          (item_policy["primary_category"], item_policy["primary_category"],
           item_policy["primary_category"], item_policy["primary_category"], url_id))
    return url_id, site_dedupe.ensure_url_site_card(
        url_id, item_policy, title, text, indicators, source)


def test_same_host_paths_share_one_card_homepage_category_wins_but_highest_risk_remains(isolated_db):
    ids = []
    for path in ("/", "/index.php", "/home"):
        ids.append(add(f"http://{HOST_A}{path}", policy())[1])
    assert len(set(ids)) == 1
    _, card_id = add(f"http://{HOST_A}/weapons", policy("weapons_arms", "high", "metadata_limited"))
    card = site_dedupe.get_site_card(card_id)
    assert card["primary_category"] == "directory_index"
    assert card["risk_level"] == "high"
    assert card["live_url_count"] == 2
    assert {item["path"] for item in card["urls"]} >= {"/", "/weapons"}


def test_safe_fingerprints_group_mirrors_and_weak_title_only_is_possible(isolated_db):
    phrase = "unique research directory phrase alpha omega"
    _, first_card = add(f"http://{HOST_A}/", policy(), "Example Directory", phrase)
    _, second_card = add(f"http://{HOST_B}/index.php", policy(), "Example Directory", phrase)
    assert first_card == second_card
    card = site_dedupe.get_site_card(first_card)
    assert card["mirror_count"] == 1
    assert any(item["mirror_confidence"] in {"probable_mirror", "confirmed_mirror"} for item in card["urls"])

    weak_id, weak_card = add(f"http://{HOST_C}/", policy(), "Example Directory", "different unrelated words")
    assert weak_card != first_card
    with storage.get_db() as db:
        candidate = db.execute("SELECT * FROM possible_site_card_matches WHERE onion_url_id=?", (weak_id,)).fetchone()
    assert candidate and candidate["confidence"] == "possible_mirror"


def test_possible_match_review_records_one_advisory_feedback_event(isolated_db):
    _, first_card = add(
        f"http://{HOST_A}/", policy(), "Shared public title", "first unrelated page")
    weak_id, second_card = add(
        f"http://{HOST_C}/", policy(), "Shared public title", "second unrelated page")
    assert first_card != second_card
    with storage.get_db() as db:
        match_id = int(db.execute("""SELECT id FROM possible_site_card_matches
          WHERE onion_url_id=? AND candidate_site_card_id=?""",
          (weak_id, first_card)).fetchone()[0])

    assert site_dedupe.review_possible_match(match_id, "not_same") is None

    with storage.get_db() as db:
        event = dict(db.execute("""SELECT feedback_scope,feedback_action,subject_hash,
          safe_metadata_json FROM classification_feedback_events
          WHERE feedback_scope='mirror' ORDER BY id DESC LIMIT 1""").fetchone())
    assert event["feedback_action"] == "mirror_not_same"
    assert HOST_A not in json.dumps(event)
    assert HOST_C not in json.dumps(event)


def test_shared_pgp_fingerprint_confirms_mirror(isolated_db):
    indicator = [{"type": "pgp_key_block", "normalized_value": "ABCD1234", "value": "ABCD1234"}]
    _, first = add(f"http://{HOST_A}/", policy(), "One", "first page", indicator)
    _, second = add(f"http://{HOST_B}/", policy(), "Two", "second page", indicator)
    assert first == second
    card = site_dedupe.get_site_card(first)
    assert any(item["mirror_confidence"] == "confirmed_mirror" for item in card["urls"])


def test_safe_homepage_text_similarity_groups_probable_mirror_without_title(isolated_db):
    text = " ".join([
        "public directory homepage mirror proof",
        "stable navigation about contact rules mirrors pgp index",
        "safe informational content for researchers",
    ] * 8)
    _, first = add(f"http://{HOST_A}/", policy(), None, text)
    _, second = add(f"http://{HOST_B}/index.php?utm_source=list", policy(), None, text)
    assert first == second
    card = site_dedupe.get_site_card(first)
    assert card["mirror_count"] == 1
    assert any(item["mirror_confidence"] in {"probable_mirror", "confirmed_mirror"}
               for item in card["urls"])


def test_homepage_text_similarity_requires_compatible_category(isolated_db):
    text = " ".join(["same safe landing page text navigation contact rules"] * 10)
    _, first = add(f"http://{HOST_A}/", policy("directory_index"), None, text)
    _, second = add(f"http://{HOST_B}/", policy("forum_social"), None, text)
    assert first != second


def test_adult_filter_never_creates_site_card_or_fingerprint(isolated_db):
    restricted = policy("adult_restricted", "critical", "metadata_only")
    first_id, first = add(f"http://{HOST_A}/", restricted, "unsafe", "unsafe raw material")
    second_id, second = add(f"http://{HOST_A}/index.php", restricted, "unsafe", "other raw material")
    assert first == second == 0
    with storage.get_db() as db:
        types = {row[0] for row in db.execute(
            "SELECT fingerprint_type FROM site_fingerprints WHERE onion_url_id IN (?,?)", (first_id, second_id))}
    assert "title" not in types and "text_simhash" not in types and "contact_hash" not in types
    assert site_dedupe.get_site_card(first) is None
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM site_cards").fetchone()[0] == 0


def test_adult_filter_does_not_group_mirrors_by_source_listing(isolated_db):
    restricted = policy("adult_restricted", "critical", "metadata_only")
    source = f"http://{HOST_C}/mirror-list"
    _, first = add(f"http://{HOST_A}/", restricted, source=source)
    _, second = add(f"http://{HOST_B}/", restricted, source=source)
    assert first == second == 0
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM site_card_urls").fetchone()[0] == 0


def test_dead_mirror_remains_on_card_but_not_active(isolated_db):
    url = f"http://{HOST_A}/gone"
    url_id, card_id = add(url, policy())
    storage.mark_onion_dead(url, 404, "http_404")
    site_dedupe.ensure_url_site_card(url_id, policy())
    card = site_dedupe.get_site_card(card_id)
    dead = next(item for item in card["urls"] if item["url"] == url)
    assert dead["url_role"] == "dead_mirror"
    assert dead["active"] == 0
    assert dead["dead_reason"] == "http_404"
    assert storage.get_next_onion_url() is None


def test_card_review_and_url_only_scope(isolated_db):
    first_id, card_id = add(f"http://{HOST_A}/", policy())
    second_id, _ = add(f"http://{HOST_A}/forum", policy("forum_social"))
    with storage.get_db() as db:
        db.execute("UPDATE site_cards SET urgent_flag=1 WHERE id=?", (card_id,))
    site_dedupe.apply_card_review(card_id, "ignored")
    with storage.get_db() as db:
        statuses = {row[0] for row in db.execute("SELECT review_status FROM onion_urls WHERE site_card_id=?", (card_id,))}
        feedback = [tuple(row) for row in db.execute("""SELECT feedback_scope,feedback_action
          FROM classification_feedback_events WHERE site_card_id=? ORDER BY id""", (card_id,))]
    assert statuses == {"false_positive"}
    assert ("review", "review_ignored") in feedback
    assert ("urgency", "urgent_dismissed") in feedback
    site_dedupe.apply_card_review(card_id, "blocked", url_id=second_id)
    with storage.get_db() as db:
        first = db.execute("SELECT active FROM onion_urls WHERE id=?", (first_id,)).fetchone()[0]
        second = db.execute("SELECT active FROM onion_urls WHERE id=?", (second_id,)).fetchone()[0]
    assert first == 1 and second == 0


def test_new_mirror_inherits_ignored_card_status(isolated_db):
    shared = [{"type": "pgp_key_block", "normalized_value": "INHERIT", "value": "INHERIT"}]
    _, card_id = add(f"http://{HOST_A}/", policy(), "One", "safe", shared)
    site_dedupe.apply_card_review(card_id, "ignored")
    new_id, same_card = add(f"http://{HOST_B}/", policy(), "Two", "different", shared)
    assert same_card == card_id
    with storage.get_db() as db:
        row = db.execute("SELECT review_status FROM onion_urls WHERE id=?", (new_id,)).fetchone()
    assert row["review_status"] == "false_positive"


def test_spain_alerts_are_deduplicated_by_card(isolated_db):
    spain = policy("weapons_arms", "high", "metadata_limited", spain_priority=True,
                   spain_confidence="high", spain_match_language="ES",
                   spain_match_reason="Strong Spanish institution reference",
                   spain_context_tags=["strong_institution_or_domain"])
    shared = [{"type": "pgp_key_block", "normalized_value": "SHARED", "value": "SHARED"}]
    _, card_id = add(f"http://{HOST_A}/", spain, "Site One", "safe one", shared)
    storage.apply_onion_policy(f"http://{HOST_A}/", spain, checked=True)
    assert storage.queue_spain_alert(f"http://{HOST_A}/", spain) is True
    _, same_card = add(f"http://{HOST_B}/", spain, "Site Two", "safe two", shared)
    storage.apply_onion_policy(f"http://{HOST_B}/", spain, checked=True)
    assert same_card == card_id
    assert storage.queue_spain_alert(f"http://{HOST_B}/", spain) is False
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM spain_alert_queue").fetchone()[0] == 1


def test_site_card_report_includes_mirrors_and_severe_blackhole_has_no_card_or_report(
        isolated_db, tmp_path, monkeypatch):
    monkeypatch.setattr(report_builder, "REPORTS_DIR", tmp_path)
    _, card_id = add(f"http://{HOST_A}/", policy(), "Example", "same phrase")
    add(f"http://{HOST_B}/", policy(), "Example", "same phrase")
    content = Path(report_builder.build_site_card_report(card_id, "pytest")).read_text(encoding="utf-8")
    assert HOST_A in content and HOST_B in content
    assert "Canonical Site Card ID" in content

    restricted = policy("severe_abuse_risk", "critical", "metadata_only")
    rid, restricted_card = add(f"http://{HOST_C}/", restricted, "DANGEROUS_LABEL_X", "DANGEROUS_BODY_X")
    assert restricted_card == 0
    with pytest.raises(ValueError):
        report_builder.build_url_report(f"http://{HOST_C}/", "pytest")
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM site_cards").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM evidence_reports WHERE site_card_id IS NULL").fetchone()[0] == 0


def test_backfill_preserves_rows_and_groups_same_host(isolated_db):
    first = storage.insert_or_update_onion_url(f"http://{HOST_A}/")
    second = storage.insert_or_update_onion_url(f"http://{HOST_A}/home")
    result = site_dedupe.backfill_existing_urls()
    assert first == second
    assert result["processed"] == 1 and result["cards"] == 0
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM onion_urls").fetchone()[0] == 1
        cards = {row[0] for row in db.execute("SELECT site_card_id FROM onion_urls WHERE id IN (?,?)", (first, second))}
    assert cards == {None}


def test_add_seed_waits_for_page_visit_before_creating_site_card(isolated_db):
    host = "e" * 56 + ".onion"
    url_id = onion_worker.add_seed(f"http://{host}/")
    with storage.get_db() as db:
        row = db.execute("SELECT site_card_id,canonical_site_id FROM onion_urls WHERE id=?", (url_id,)).fetchone()
    assert row["site_card_id"] is None and row["canonical_site_id"] is None
    assert storage.get_onion_url_by_url(f"http://{host}/")["verification_state"] == "discovered"


def _attach_provisional_root_to_card(card_id: int, url: str, item_policy: dict) -> int:
    host = url.split("/")[2]
    url_id = storage.insert_or_update_onion_url(
        url, host, source_url=f"http://{HOST_A}/", source_type="directory_seed",
        status="queued", policy=item_policy)
    now = storage.utc_now_iso()
    with storage.get_db() as db:
        canonical_site_id = db.execute(
            "SELECT canonical_site_id FROM site_cards WHERE id=?", (card_id,)).fetchone()[0]
        db.execute("""UPDATE onion_urls SET site_card_id=?,canonical_site_id=?,
          dedupe_status='assigned',primary_category=?,category=?,content_category=?,
          category_confidence=?,classification_stage=?,category_update_allowed=?
          WHERE id=?""",
          (card_id, canonical_site_id, item_policy["primary_category"],
           item_policy["primary_category"], item_policy["primary_category"],
           item_policy.get("category_confidence") or "critical",
           item_policy.get("classification_stage") or "outbound",
           int(bool(item_policy.get("category_update_allowed", True))), url_id))
        db.execute("""INSERT INTO site_card_urls
          (site_card_id,onion_url_id,url,onion_host,path,url_role,mirror_confidence,status,
           active,first_seen,last_seen,source_url,created_at,updated_at)
          VALUES(?,?,?,?,?,'mirror','unknown','queued',1,?,?,?,?,?)""",
          (card_id, url_id, url, host, "/", now, now, f"http://{HOST_A}/", now, now))
    return url_id


def test_rollup_ignores_provisional_untrusted_url_category(isolated_db):
    trusted_id, card_id = add(
        f"http://{HOST_A}/",
        policy("directory_index", category_confidence="high", classification_stage="page"),
        "Trusted directory", "A neutral public directory with useful navigation.")
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET verification_state='verified',verified_at=?,
          classification_stage='page',category_update_allowed=1,category_confidence='high',
          primary_category='directory_index',category='directory_index',
          content_category='directory_index',destination_html_evidence_version=?,
          classification_evidence_source='destination_html'
          WHERE id=?""", (storage.utc_now_iso(), storage.DESTINATION_HTML_EVIDENCE_VERSION,
                           trusted_id))
    provisional_id = _attach_provisional_root_to_card(
        card_id, f"http://{HOST_B}/",
        policy("marketplace_fraud", "high", "metadata_limited",
               category_confidence="critical", classification_stage="outbound",
               category_update_allowed=True))
    assert storage.get_onion_url_by_url(f"http://{HOST_B}/")["verification_state"] == "provisional"

    site_dedupe.update_site_card_rollups(card_id)

    with storage.get_db() as db:
        card = dict(db.execute("""SELECT primary_category,content_category
          FROM site_cards WHERE id=?""", (card_id,)).fetchone())
        provisional = dict(db.execute("""SELECT primary_category,verification_state
          FROM onion_urls WHERE id=?""", (provisional_id,)).fetchone())
    assert card == {
        "primary_category": "directory_index", "content_category": "directory_index",
    }
    assert provisional == {
        "primary_category": "marketplace_fraud", "verification_state": "provisional",
    }


def test_rollup_preserves_explicit_analyst_category_over_provisional_rows(isolated_db):
    trusted_id, card_id = add(
        f"http://{HOST_A}/", policy("directory_index"),
        "Trusted directory", "A neutral public directory with useful navigation.")
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET verification_state='verified',verified_at=?,
          classification_stage='page',category_update_allowed=1,
          primary_category='directory_index',category='directory_index',
          content_category='directory_index',destination_html_evidence_version=?,
          classification_evidence_source='destination_html'
          WHERE id=?""",
          (storage.utc_now_iso(), storage.DESTINATION_HTML_EVIDENCE_VERSION, trusted_id))
    site_dedupe.apply_manual_category(card_id, "forum_social")
    _attach_provisional_root_to_card(
        card_id, f"http://{HOST_C}/",
        policy("marketplace_fraud", "high", "metadata_limited",
               category_confidence="critical", classification_stage="outbound",
               category_update_allowed=True))

    site_dedupe.update_site_card_rollups(card_id)

    with storage.get_db() as db:
        card = dict(db.execute("""SELECT primary_category,content_category,analyst_category,
          classification_decision FROM site_cards WHERE id=?""", (card_id,)).fetchone())
    assert card == {
        "primary_category": "forum_social", "content_category": "forum_social",
        "analyst_category": "forum_social", "classification_decision": "analyst_confirmed",
    }
