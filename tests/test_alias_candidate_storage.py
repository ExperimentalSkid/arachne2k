import hashlib
import json

import actor_intelligence
import storage
from entity_quality import evaluate_candidate


HOST_A = "a" * 56 + ".onion"
HOST_B = "b" * 56 + ".onion"


def _policy(**overrides):
    policy = {
        "primary_category": "forum_social",
        "page_type": "thread_page",
        "storage_policy": "safe_summary",
        "risk_level": "medium",
        "spain_priority": False,
    }
    policy.update(overrides)
    return policy


def _quality_candidate(alias="NightFox77", **overrides):
    source = {
        "accepted": True,
        "evidence_version": 2,
        "alias": alias,
        "normalized_alias": alias.casefold(),
        "role": "forum_member",
        "evidence_type": "phpbb_post_author",
        "confidence": 0.97,
        "evidence_strength": "strong",
        "source_scope": "post_author",
        "evidence_signals": ["profile_link", "anchor_slug_match"],
        "profile_identity": "query:u:17",
        "profile_url": f"http://{HOST_A}/memberlist.php?mode=viewprofile&u=17",
    }
    source.update(overrides)
    evaluated = evaluate_candidate(source)
    evaluated.update({
        "profile_identity": source.get("profile_identity"),
        "profile_url": source.get("profile_url"),
        "evidence_type": source.get("evidence_type"),
        "evidence_strength": source.get("evidence_strength"),
        "confidence": source.get("confidence"),
    })
    return evaluated


def _bound_evidence(*items):
    bound = []
    evidence = []
    for indicator_type, stable_material in items:
        digest = hashlib.sha256(stable_material.encode("utf-8")).hexdigest()
        bound.append({
            "type": indicator_type,
            "value_hash": digest,
            "confidence": 0.97,
        })
        evidence.append({
            "type": indicator_type,
            "normalized_value": f"local_sha256:{digest}",
            "confidence": 0.97,
        })
    return bound, evidence


def _store_actor(url, alias, *, bound_items=()):
    bound, evidence = _bound_evidence(*bound_items)
    actor_alias = {
        "accepted": True,
        "evidence_version": 2,
        "alias": alias,
        "normalized_alias": alias.casefold(),
        "role": "forum_member",
        "evidence_type": "phpbb_post_author",
        "confidence": 0.97,
        "evidence_strength": "strong",
        "source_scope": "post_author",
        "evidence_signals": ["profile_link", "anchor_slug_match"],
        "bound_identifiers": bound,
    }
    host = url.split("/", 3)[2]
    storage.insert_or_update_onion_url(url, host, status="crawled")
    return storage.store_actor_observations(url, [actor_alias], evidence, _policy())[0]


def _table_counts(*names):
    with storage.get_db() as db:
        return {name: int(db.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]) for name in names}


def test_candidate_schema_is_additive_and_init_is_idempotent(isolated_db):
    expected_tables = {
        "actors",
        "actor_candidates",
        "actor_candidate_events",
        "alias_noise_rules",
        "actor_identifier_observations",
        "entity_expansion_proposals",
    }
    expected_indexes = {
        "idx_actor_candidates_review",
        "idx_actor_candidates_alias",
        "idx_actor_candidates_actor",
        "idx_actor_candidate_events_candidate",
        "idx_alias_noise_rules_enabled",
        "idx_actor_identifier_obs_observation",
    }
    rule_id = storage.upsert_alias_noise_rule(
        "exact", "local-sentinel", action="review",
        reason_code="review_similarity_only", analyst_id="test",
    )

    storage.init_db()
    storage.init_db()

    with storage.get_db() as db:
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        indexes = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        retained = db.execute(
            "SELECT id,enabled FROM alias_noise_rules WHERE normalized_pattern='local-sentinel'"
        ).fetchone()
        assert list(db.execute("PRAGMA foreign_key_check")) == []

    assert expected_tables <= tables
    assert expected_indexes <= indexes
    assert dict(retained) == {"id": rule_id, "enabled": 1}


def test_candidate_upsert_is_idempotent_and_analyst_decision_survives_retry(isolated_db):
    url = f"http://{HOST_A}/viewtopic.php?t=17"
    storage.insert_or_update_onion_url(url, HOST_A, status="crawled")
    candidate = _quality_candidate()

    first = storage.upsert_actor_candidates(url, [candidate], _policy())
    second = storage.upsert_actor_candidates(url, [candidate], _policy())
    assert first == second and len(first) == 1
    candidate_id = first[0]
    assert storage.record_actor_candidate_decision(
        candidate_id, "confirm", reason_code="analyst_verified_profile", analyst_id="operator"
    )

    retry = dict(candidate)
    retry["state"] = "analyst_review_candidate"
    retry["reason_codes"] = ["review_weak_evidence"]
    assert storage.upsert_actor_candidates(url, [retry], _policy()) == [candidate_id]

    with storage.get_db() as db:
        row = dict(db.execute("SELECT * FROM actor_candidates WHERE id=?", (candidate_id,)).fetchone())
        event_types = [item[0] for item in db.execute(
            "SELECT event_type FROM actor_candidate_events WHERE candidate_id=? ORDER BY id",
            (candidate_id,),
        )]
    assert row["seen_count"] == 1
    assert row["automatic_state"] == "analyst_review_candidate"
    assert row["analyst_state"] == "analyst_confirmed_identity_evidence"
    assert row["effective_state"] == "analyst_confirmed_identity_evidence"
    assert event_types == ["automatic_evaluation", "analyst_decision"]


def test_reprocessing_same_observation_does_not_inflate_actor_alias_count(isolated_db):
    url = f"http://{HOST_A}/viewtopic.php?t=21"
    actor_id = _store_actor(url, "RetryFox")
    second_id = _store_actor(url, "RetryFox")

    with storage.get_db() as db:
        actor = dict(db.execute("SELECT observation_count FROM actors WHERE id=?", (actor_id,)).fetchone())
        alias = dict(db.execute(
            "SELECT observation_count FROM actor_aliases WHERE actor_id=?", (actor_id,)
        ).fetchone())
        observations = int(db.execute(
            "SELECT COUNT(*) FROM actor_observations WHERE actor_id=?", (actor_id,)
        ).fetchone()[0])

    assert second_id == actor_id
    assert actor["observation_count"] == 1
    assert alias["observation_count"] == 1
    assert observations == 1


def test_excluding_observation_removes_identifier_weight_and_recalculates_connections(isolated_db):
    shared = ("pgp_key_block", "shared-public-pgp")
    first = _store_actor(f"http://{HOST_A}/viewtopic.php?t=31", "NorthFox", bound_items=(shared,))
    second = _store_actor(f"http://{HOST_B}/viewtopic.php?t=32", "SouthFox", bound_items=(shared,))
    second_url = f"http://{HOST_B}/viewtopic.php?t=32"
    candidate_id = storage.upsert_actor_candidates(
        second_url, [_quality_candidate("SouthFox")], _policy())[0]
    assert storage.link_actor_candidates(second_url, [second]) == 1

    with storage.get_db() as db:
        before = dict(db.execute(
            "SELECT * FROM actor_connections WHERE source_actor_id=? AND target_actor_id=?",
            tuple(sorted((first, second))),
        ).fetchone())
        observation_id = int(db.execute(
            "SELECT id FROM actor_observations WHERE actor_id=?", (second,)
        ).fetchone()[0])
    assert before["confidence_score"] == 90
    assert before["migration_candidate"] == 1

    assert storage.exclude_actor_observation(observation_id)

    with storage.get_db() as db:
        excluded = dict(db.execute(
            "SELECT analyst_excluded,bound_identifier_count FROM actor_observations WHERE id=?",
            (observation_id,),
        ).fetchone())
        second_actor = dict(db.execute(
            "SELECT observation_count,confidence_score FROM actors WHERE id=?", (second,)
        ).fetchone())
        identifiers = int(db.execute(
            "SELECT COUNT(*) FROM actor_identifiers WHERE actor_id=?", (second,)
        ).fetchone()[0])
        links = int(db.execute(
            "SELECT COUNT(*) FROM actor_identifier_observations aio "
            "JOIN actor_identifiers ai ON ai.id=aio.actor_identifier_id WHERE ai.actor_id=?",
            (second,),
        ).fetchone()[0])
        connection = db.execute(
            "SELECT id FROM actor_connections WHERE source_actor_id=? AND target_actor_id=?",
            tuple(sorted((first, second))),
        ).fetchone()
        candidate = dict(db.execute(
            "SELECT analyst_state,effective_state FROM actor_candidates WHERE id=?",
            (candidate_id,),
        ).fetchone())

    assert excluded["analyst_excluded"] == 1
    assert second_actor == {"observation_count": 0, "confidence_score": 0.0}
    assert identifiers == 0
    assert links == 0
    assert connection is None
    assert candidate == {
        "analyst_state": "analyst_rejected_identity_evidence",
        "effective_state": "analyst_rejected_identity_evidence",
    }


def test_conflicting_strong_identifiers_cap_score_and_veto_migration(isolated_db):
    first = _store_actor(
        f"http://{HOST_A}/viewtopic.php?t=41",
        "MirrorFox",
        bound_items=(("pgp_key_block", "shared-pgp"), ("email", "first-contact")),
    )
    second = _store_actor(
        f"http://{HOST_B}/viewtopic.php?t=42",
        "MirrorFox",
        bound_items=(("pgp_key_block", "shared-pgp"), ("email", "second-contact")),
    )

    with storage.get_db() as db:
        connection = dict(db.execute(
            "SELECT * FROM actor_connections WHERE source_actor_id=? AND target_actor_id=?",
            tuple(sorted((first, second))),
        ).fetchone())
    evidence_types = {item["type"] for item in json.loads(connection["evidence_json"])}

    assert connection["confidence_score"] == 55
    assert connection["confidence_label"] == "low"
    assert connection["warning_type"] == "conflicting_public_identifiers"
    assert connection["migration_candidate"] == 0
    assert {"same_alias", "pgp_key_block", "contradictory_identifiers"} <= evidence_types


def test_watched_and_analyst_reviewed_actors_are_protected_from_cleanup(isolated_db):
    watched = _store_actor(f"http://{HOST_A}/viewtopic.php?t=51", "WatchedFox")
    reviewed = _store_actor(f"http://{HOST_A}/viewtopic.php?t=52", "ReviewedFox")
    assert storage.set_actor_watch(watched, True, "manual watch")
    with storage.get_db() as db:
        db.execute("UPDATE actors SET analyst_status='reviewed' WHERE id=?", (reviewed,))

    assert storage.actor_cleanup_protected(watched)
    assert storage.actor_cleanup_protected(reviewed)
    assert storage.delete_actor_ids_safely([watched, reviewed]) == 0

    with storage.get_db() as db:
        retained = {int(row[0]) for row in db.execute(
            "SELECT id FROM actors WHERE id IN (?,?)", (watched, reviewed)
        )}
    assert retained == {watched, reviewed}


def test_candidate_only_analyst_decision_protects_matching_actor_from_cleanup(isolated_db):
    url = f"http://{HOST_A}/viewtopic.php?t=53"
    actor_id = _store_actor(url, "CandidateFox")
    candidate = _quality_candidate(
        "CandidateFox", accepted=False, confidence=0.65,
        evidence_strength="medium", evidence_type="explicit_author_label",
        profile_identity="",
    )
    candidate_id = storage.upsert_actor_candidates(url, [candidate], _policy())[0]
    assert storage.record_actor_candidate_decision(candidate_id, "reject")

    assert storage.actor_cleanup_protected(actor_id)
    assert storage.delete_actor_ids_safely([actor_id]) == 0


def test_alias_noise_rule_rejects_invalid_or_unbounded_scope(isolated_db):
    for invalid_scope in ("host-wide", "source_scope:", "hostname:any", "page_type:has spaces"):
        try:
            storage.upsert_alias_noise_rule(
                "exact", "scopefox", action="reject",
                reason_code="rejected_navigation_template", scope=invalid_scope)
        except ValueError:
            continue
        raise AssertionError(f"invalid scope accepted: {invalid_scope}")


def test_restricted_policy_creates_no_actor_candidates(isolated_db):
    url = f"http://{HOST_A}/viewtopic.php?t=61"
    restricted = {
        "primary_category": "adult_filtered",
        "page_type": "thread_page",
        "storage_policy": "discard",
    }
    page_structure = {"actor_evidence": [{
        "accepted": True,
        "evidence_version": 2,
        "alias": "BlockedFox",
        "normalized_alias": "blockedfox",
        "role": "forum_member",
        "evidence_type": "phpbb_post_author",
        "confidence": 0.99,
        "evidence_strength": "strong",
    }]}

    result = actor_intelligence.process_page_actor_intelligence(
        url,
        visible_text="Author: BlockedFox",
        links=[],
        link_records=[],
        policy=restricted,
        page_structure=page_structure,
    )
    direct = storage.upsert_actor_candidates(url, [_quality_candidate("BlockedFox")], restricted)

    assert result["actors"] == 0
    assert result["candidates"] == 0
    assert result["eligible"] is False
    assert result["reason"] == "restricted_policy"
    assert direct == []
    assert _table_counts("actors", "actor_candidates", "actor_candidate_events") == {
        "actors": 0,
        "actor_candidates": 0,
        "actor_candidate_events": 0,
    }


def _seed_restricted_entity_material(url: str) -> tuple[int, int]:
    url_id = storage.insert_or_update_onion_url(url, HOST_A, status="crawled")
    candidate_id = storage.upsert_actor_candidates(
        url, [_quality_candidate("ScrubFox")], _policy())[0]
    child = f"http://{HOST_A}/about"
    proposal_id = storage.persist_entity_expansion_plan(url, {
        "proposal_only": True,
        "network_performed": False,
        "caps": {"per_host": 10, "per_resource": 1},
        "proposals": [{
            "url": child,
            "role": "about",
            "resource_identity": f"route:{HOST_A}:about",
            "reason_code": "PUBLIC_ABOUT_ROUTE",
        }],
    })[0]
    return url_id, candidate_id


def _assert_restricted_entity_material_scrubbed(url: str, candidate_id: int) -> None:
    with storage.get_db() as db:
        assert db.execute(
            "SELECT 1 FROM actor_candidates WHERE id=?", (candidate_id,)).fetchone() is None
        assert db.execute(
            "SELECT 1 FROM actor_candidate_events WHERE candidate_id=?", (candidate_id,)).fetchone() is None
        assert db.execute("""SELECT 1 FROM entity_expansion_proposals
          WHERE parent_url=? OR proposed_url=?""", (url, url)).fetchone() is None
    assert storage.get_actor_candidate_review_queue(search="scrubfox") == []
    assert storage.get_entity_expansion_proposals(search="scrubfox") == []


def test_adult_blackhole_scrubs_candidate_events_and_expansion_routes(isolated_db):
    url = f"http://{HOST_A}/restricted-adult"
    url_id, candidate_id = _seed_restricted_entity_material(url)
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET primary_category='adult_filtered',
          category='adult_filtered',classification_evidence_source='destination_html',
          destination_html_evidence_version=1,verification_state='verified',
          verification_reason='page_fetched_and_classified' WHERE id=?""", (url_id,))

    assert storage.cleanup_adult_filtered_items(url) == 1
    _assert_restricted_entity_material_scrubbed(url, candidate_id)


def test_severe_blackhole_scrubs_candidate_events_and_expansion_routes(isolated_db):
    url = f"http://{HOST_A}/restricted-severe"
    url_id, candidate_id = _seed_restricted_entity_material(url)
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET primary_category='severe_abuse_risk',
          classification_evidence_source='destination_html',destination_html_evidence_version=1,
          verification_state='verified',verification_reason='page_fetched_and_classified'
          WHERE id=?""", (url_id,))

    assert storage.enforce_severe_blackhole(url)
    _assert_restricted_entity_material_scrubbed(url, candidate_id)


def test_candidate_linking_keeps_same_alias_distinct_profiles_separate(isolated_db):
    url = f"http://{HOST_A}/viewtopic.php?t=71"
    storage.insert_or_update_onion_url(url, HOST_A, status="crawled")

    def store_profile(profile_id: int) -> int:
        profile_url = f"http://{HOST_A}/memberlist.php?mode=viewprofile&u={profile_id}"
        alias = {
            "accepted": True, "evidence_version": 2,
            "alias": "TwinFox", "normalized_alias": "twinfox",
            "role": "forum_member", "evidence_type": "phpbb_post_author",
            "confidence": 0.97, "evidence_strength": "strong",
            "source_scope": "post_author", "profile_url": profile_url,
        }
        return storage.store_actor_observations(url, [alias], [], _policy())[0]

    first_actor = store_profile(17)
    second_actor = store_profile(18)
    first_candidate, second_candidate = storage.upsert_actor_candidates(url, [
        _quality_candidate("TwinFox", profile_identity="query:u:17",
                           profile_url=f"http://{HOST_A}/memberlist.php?mode=viewprofile&u=17"),
        _quality_candidate("TwinFox", profile_identity="query:u:18",
                           profile_url=f"http://{HOST_A}/memberlist.php?mode=viewprofile&u=18"),
    ], _policy())

    assert storage.link_actor_candidates(url, [first_actor, second_actor]) == 2
    with storage.get_db() as db:
        linked = {int(row["id"]): int(row["actor_id"]) for row in db.execute(
            "SELECT id,actor_id FROM actor_candidates WHERE id IN (?,?)",
            (first_candidate, second_candidate))}
    assert linked == {first_candidate: first_actor, second_candidate: second_actor}


def test_runtime_noise_rule_changes_entity_quality_decision(isolated_db):
    rule_id = storage.upsert_alias_noise_rule(
        "exact",
        "runtimefox",
        action="reject",
        reason_code="rejected_navigation_template",
        analyst_id="operator",
        rule_version="analyst.2",
    )
    rules = storage.get_alias_noise_rules(enabled_only=True)
    result = evaluate_candidate({
        "accepted": True,
        "evidence_version": 2,
        "alias": "RuntimeFox",
        "role": "forum_member",
        "evidence_type": "phpbb_post_author",
        "confidence": 0.98,
        "evidence_strength": "strong",
    }, extra_rules=rules)

    assert any(rule["id"] == rule_id for rule in rules)
    assert result["state"] == "rejected_noise"
    assert "rejected_navigation_template" in result["reason_codes"]
    assert result["automatic_merge_allowed"] is False
    assert any(match["rule_id"] == f"analyst:{rule_id}" for match in result["matched_local_rules"])


def test_alias_quality_audit_is_dry_run_count_only_and_non_mutating(isolated_db):
    url = f"http://{HOST_A}/viewtopic.php?t=71"
    storage.insert_or_update_onion_url(url, HOST_A, status="crawled")
    candidate_id = storage.upsert_actor_candidates(
        url, [_quality_candidate("AuditFox")], _policy()
    )[0]
    tables = (
        "actors", "actor_candidates", "actor_candidate_events", "alias_noise_rules",
        "actor_observations", "actor_identifiers", "actor_connections",
    )
    before_counts = _table_counts(*tables)
    with storage.get_db() as db:
        before_candidate = dict(db.execute(
            "SELECT * FROM actor_candidates WHERE id=?", (candidate_id,)
        ).fetchone())

    first = storage.get_alias_quality_audit(limit=500)
    second = storage.get_alias_quality_audit(limit=500)

    after_counts = _table_counts(*tables)
    with storage.get_db() as db:
        after_candidate = dict(db.execute(
            "SELECT * FROM actor_candidates WHERE id=?", (candidate_id,)
        ).fetchone())
    serialized = json.dumps(first, sort_keys=True)

    assert first == second
    assert first["dry_run"] is True
    assert first["scanned"] == 1
    assert before_counts == after_counts
    assert before_candidate == after_candidate
    assert "AuditFox" not in serialized
    assert HOST_A not in serialized
    assert set(first) == {
        "dry_run", "scanned", "states", "top_rejection_reasons",
        "likely_stored_noise", "mixed_script_review", "confusable_review",
        "generic_role_leakage", "weak_single_observation_actors",
        "broadly_repeated_aliases", "proposed_cleanup_actions",
    }
