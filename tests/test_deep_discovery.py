import hashlib

import deep_discovery
import storage


HOST = "d" * 56 + ".onion"


def _policy(**overrides):
    data = {
        "primary_category": "marketplace_fraud",
        "category": "marketplace_fraud",
        "page_type": "vendor_page",
        "storage_policy": "metadata_limited",
        "risk_level": "high",
        "spain_priority": False,
    }
    data.update(overrides)
    return data


def _alias(name: str, *, confidence: float = 0.96, evidence_type: str = "profile_page_identity_match",
           generic: bool = False):
    return {
        "accepted": True,
        "evidence_version": 2,
        "alias": name,
        "normalized_alias": name.casefold(),
        "role": "profile_owner",
        "evidence_type": evidence_type,
        "confidence": confidence,
        "generic_role": generic,
        "safe_context_label": "Confirmed public profile field",
    }


def _evidence(kind: str = "pgp_key_block"):
    return [{
        "type": kind,
        "value": f"{kind}:synthetic-public-value",
        "normalized_value": f"{kind}:synthetic-public-value",
        "confidence": 0.92,
    }]


def _store_actor(name: str, *, aliases=None, evidence=None, policy=None):
    url = f"http://{HOST}/profile/{name}"
    storage.insert_or_update_onion_url(url, HOST, status="crawled", policy=policy or _policy())
    alias_rows = aliases if aliases is not None else [_alias(name)]
    bound, safe_evidence = [], []
    for item in evidence if evidence is not None else []:
        kind = str(item.get("type") or "")
        value = str(item.get("normalized_value") or item.get("value") or "")
        digest = hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()
        bound.append({"type": kind, "value_hash": digest,
                      "confidence": float(item.get("confidence") or 0.9)})
        safe_evidence.append({"type": kind, "normalized_value": f"local_sha256:{digest}",
                              "confidence": float(item.get("confidence") or 0.9)})
    if alias_rows and bound:
        alias_rows[0] = dict(alias_rows[0], bound_identifiers=bound)
    actor_ids = storage.store_actor_observations(
        url,
        alias_rows,
        safe_evidence,
        policy or _policy(),
    )
    assert actor_ids
    return actor_ids[0]


def test_confirmed_profile_with_strong_public_pivot_auto_queues_deep_discovery(isolated_db):
    actor_id = _store_actor("NordicExampleVendor", evidence=_evidence("pgp_key_block"))

    result = deep_discovery.maybe_queue_actor(actor_id)
    jobs = storage.get_deep_discovery_jobs()

    assert result["score"] >= 0.90
    assert result["auto_queue"] is True
    assert result["queued_job_id"]
    assert len(jobs) == 1
    assert jobs[0]["actor_id"] == actor_id
    assert "strong_public_pivot" in jobs[0]["trigger_reason"]


def test_distinctive_handle_without_strong_pivot_stays_quiet(isolated_db):
    actor_id = _store_actor("LockBitSupp", evidence=[])

    result = deep_discovery.maybe_queue_actor(actor_id)

    assert result["score"] < 0.90
    assert result["auto_queue"] is False
    assert result["queued_job_id"] is None
    assert storage.get_deep_discovery_jobs() == []


def test_generic_alias_never_auto_queues_even_with_identifier(isolated_db):
    url = f"http://{HOST}/profile/Admin"
    storage.insert_or_update_onion_url(url, HOST, status="crawled", policy=_policy())

    actor_ids = storage.store_actor_observations(
        url, [_alias("Admin", generic=True)], _evidence("email"), _policy())

    assert actor_ids == []
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM actors").fetchone()[0] == 0
    assert storage.get_deep_discovery_jobs() == []


def test_weak_username_pivot_does_not_reach_auto_threshold(isolated_db):
    actor_id = _store_actor("GoodHandle", evidence=_evidence("username"))

    result = deep_discovery.maybe_queue_actor(actor_id)

    assert result["score"] < 0.90
    assert result["auto_queue"] is False
    assert "only_weak_handle_or_username_pivot" in result["blockers"]


def test_duplicate_deep_discovery_job_is_not_flooded(isolated_db):
    actor_id = _store_actor("NordicExampleVendor", evidence=_evidence("pgp_key_block"))

    first = deep_discovery.maybe_queue_actor(actor_id)
    second = deep_discovery.maybe_queue_actor(actor_id)

    assert first["queued_job_id"] == second["queued_job_id"]
    assert len(storage.get_deep_discovery_jobs()) == 1


def test_candidate_clusters_use_caller_supplied_provider_evidence():
    anchor = {
        "schema": "arachne.deep_discovery.anchor.v1",
        "display_alias": "SyntheticAnchor",
    }
    local = {
        "connections": [{"other_actor_id": 2, "confidence": "high"}],
        "identifier_types": ["pgp_key_block", "email"],
        "same_alias_candidates": [],
    }
    providers = [{
        "candidate_id": "provider-row-1",
        "display_name": "Synthetic candidate",
        "url": "https://example.invalid/profile/synthetic",
        "domain": "example.invalid",
        "provider": "test_provider",
        "matching_pivots": ["pgp_key_block", "domain", "handle"],
        "supporting": [
            {"type": "pgp_key_block", "label": "Matching public PGP fingerprint"},
            {"type": "domain", "label": "Matching public domain"},
        ],
        "contradicting": [],
    }]

    clusters = deep_discovery.build_candidate_clusters(anchor, local, providers)

    assert len(clusters) == 1
    assert clusters[0]["candidate_id"] == "provider-row-1"
    assert clusters[0]["score"] >= 0.90
    assert clusters[0]["decision"] == "strong_candidate"
    assert clusters[0]["provider"] == "test_provider"
