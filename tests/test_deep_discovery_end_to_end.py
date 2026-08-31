import hashlib

import deep_discovery
import site_dedupe
import storage
import structured_intelligence


HOST_A = "e" * 56 + ".onion"
HOST_B = "f" * 56 + ".onion"


def _policy():
    return {
        "primary_category": "marketplace_fraud",
        "category": "marketplace_fraud",
        "content_category": "marketplace_fraud",
        "analyst_category": "marketplace_fraud",
        "classification_evidence_source": "analyst",
        "destination_html_evidence_version": 0,
        "page_type": "vendor_page",
        "storage_policy": "metadata_limited",
        "risk_level": "high",
        "review_status": "needs_review",
        "queue_policy": "reviewable",
        "active": 1,
        "spain_priority": False,
        "card_ready": True,
        "card_readiness_reason": "verified_public_profile",
    }


def _alias(name: str):
    return {
        "accepted": True,
        "evidence_version": 2,
        "alias": name,
        "normalized_alias": name.casefold(),
        "role": "profile_owner",
        "evidence_type": "profile_page_identity_match",
        "confidence": 0.96,
        "generic_role": False,
        "safe_context_label": "Confirmed synthetic profile field",
    }


def _identifier(kind: str, value: str):
    return {
        "type": kind,
        "value": value,
        "normalized_value": value.casefold(),
        "confidence": 0.94,
    }


def _store_profile(host: str, alias: str, evidence: list[dict]):
    policy = _policy()
    url = f"http://{host}/profile/{alias}"
    url_id = storage.insert_or_update_onion_url(url, host, status="crawled", policy=policy)
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET analyst_category='marketplace_fraud',
          primary_category='marketplace_fraud',category='marketplace_fraud',
          content_category='marketplace_fraud',classification_evidence_source='analyst',
          destination_html_evidence_version=0 WHERE id=?""", (url_id,))
    card_id = site_dedupe.ensure_url_site_card(
        url_id,
        policy,
        title=f"{alias} public profile",
        visible_text="Verified public profile structure",
    )
    bound, safe_evidence = [], []
    for item in evidence:
        kind = str(item.get("type") or "")
        value = str(item.get("normalized_value") or item.get("value") or "")
        digest = hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()
        bound.append({"type": kind, "value_hash": digest,
                      "confidence": float(item.get("confidence") or 0.9)})
        safe_evidence.append({"type": kind, "normalized_value": f"local_sha256:{digest}",
                              "confidence": float(item.get("confidence") or 0.9)})
    actor_ids = storage.store_actor_observations(
        url, [dict(_alias(alias), bound_identifiers=bound)], safe_evidence, policy)
    assert actor_ids
    return {"actor_id": actor_ids[0], "card_id": card_id, "url": url}


def _provider_rows():
    return [
        {
            "candidate_id": "strong-public-candidate",
            "display_name": "Atlas public profile",
            "url": "https://atlas.example.invalid/profile",
            "domain": "atlas.example.invalid",
            "provider": "synthetic_test_provider",
            "matching_pivots": ["pgp_key_block", "domain", "handle"],
            "supporting": [
                {"type": "pgp_key_block", "label": "Matching public PGP fingerprint"},
                {"type": "domain", "label": "Matching public domain"},
            ],
            "contradicting": [],
        },
        {
            "candidate_id": "conflicting-public-candidate",
            "display_name": "Conflicting public profile",
            "url": "https://conflict.example.invalid/profile",
            "domain": "conflict.example.invalid",
            "provider": "synthetic_test_provider",
            "matching_pivots": ["handle"],
            "supporting": [{"type": "handle", "label": "Same public handle"}],
            "contradicting": [
                {"type": "pgp_key_block", "label": "Different public PGP fingerprint"},
                {"type": "domain", "label": "Unrelated public domain"},
            ],
        },
        {
            "candidate_id": "handle-only-candidate",
            "display_name": "Handle-only profile",
            "url": "https://handle.example.invalid/profile",
            "domain": "handle.example.invalid",
            "provider": "synthetic_test_provider",
            "matching_pivots": ["handle"],
            "supporting": [{"type": "handle", "label": "Same public handle"}],
            "contradicting": [],
        },
    ]


def _ingest_synthetic_evidence_graph():
    shared_pgp = _identifier("pgp_key_block", "synthetic-shared-public-pgp-fingerprint")
    anchor = _store_profile(
        HOST_A,
        "AtlasVendor",
        [shared_pgp, _identifier("email", "atlas@example.invalid")],
    )
    peer = _store_profile(HOST_B, "HarborVendor", [shared_pgp])
    detail = storage.get_actor_detail(anchor["actor_id"])
    eligibility = deep_discovery.maybe_queue_actor(
        anchor["actor_id"], site_card_id=anchor["card_id"]
    )
    local = deep_discovery.local_first_candidates(detail)
    anchor_snapshot = deep_discovery.build_anchor_snapshot(
        detail, deep_discovery.score_actor_detail(detail)
    )
    clusters = deep_discovery.build_candidate_clusters(
        anchor_snapshot, local, _provider_rows()
    )
    return {
        "anchor_actor_id": anchor["actor_id"],
        "peer_actor_id": peer["actor_id"],
        "site_card_id": anchor["card_id"],
        "eligibility": eligibility,
        "jobs": storage.get_deep_discovery_jobs(),
        "local_pivots": local,
        "candidate_clusters": clusters,
    }


def test_synthetic_evidence_runs_through_real_pipeline_with_evidence_chain(isolated_db):
    result = _ingest_synthetic_evidence_graph()

    assert result["eligibility"]["score"] >= 0.90
    assert result["eligibility"]["auto_queue"] is True
    assert result["jobs"]
    assert result["local_pivots"]["connections"]

    clusters = result["candidate_clusters"]
    assert clusters[0]["score"] >= 0.90
    assert clusters[0]["decision"] == "strong_candidate"
    assert any(item["type"] == "pgp_key_block" for item in clusters[0]["supporting_evidence"])
    assert any(item["type"] == "domain" for item in clusters[0]["supporting_evidence"])
    assert any("analyst review" in step for step in clusters[0]["evidence_chain"])

    contradicted = next(
        item for item in clusters if item["candidate_id"] == "conflicting-public-candidate"
    )
    assert contradicted["score"] < 0.70
    assert contradicted["contradicting_evidence"]

    handle_only = next(item for item in clusters if item["candidate_id"] == "handle-only-candidate")
    assert handle_only["decision"] == "quiet_false_or_weak_match"


def test_synthetic_ingest_builds_live_structured_card_from_persisted_evidence(isolated_db):
    result = _ingest_synthetic_evidence_graph()
    card = structured_intelligence.build_live_structured_card(result["site_card_id"])

    assert card and card["data_origin"] == "crawler"
    assert card["coverage"]["profiles"] >= 1
    assert card["coverage"]["identifiers"] >= 2
    assert any(profile["handle"] == "AtlasVendor" for profile in card["profiles"])
    assert any(item["type"] == "pgp_key_block" for item in card["identifiers"])
    assert any(rel["type"] in {"possible_same_vendor", "possible_correspondence"}
               for rel in card["relationships"])

    relation_keys = [(rel["source"], rel["type"], rel["target"]) for rel in card["relationships"]]
    assert len(relation_keys) == len(set(relation_keys))


def test_empty_database_has_no_profiles_jobs_or_structured_cards(isolated_db):
    assert storage.get_public_actors() == []
    assert storage.get_deep_discovery_jobs() == []
    assert structured_intelligence.build_live_structured_card(999_999) is None


def test_analyst_connection_decision_survives_recalculation(isolated_db):
    result = _ingest_synthetic_evidence_graph()
    anchor_id = result["anchor_actor_id"]
    detail = storage.get_actor_detail(anchor_id)
    connection = next(item for item in detail["connections"] if item["confidence_label"] == "high")

    assert storage.set_actor_connection_decision(connection["id"], "confirmed_same")
    _ingest_synthetic_evidence_graph()

    refreshed = storage.get_actor_detail(anchor_id)
    same = next(item for item in refreshed["connections"] if item["id"] == connection["id"])
    assert same["analyst_decision"] == "confirmed_same"


def test_test_supplied_provider_rows_explain_conflicts_and_handle_only_matches(isolated_db):
    result = _ingest_synthetic_evidence_graph()

    assert len(result["candidate_clusters"]) == 3
    conflict = next(item for item in result["candidate_clusters"]
                    if item["candidate_id"] == "conflicting-public-candidate")
    assert conflict["contradicting_evidence"]
    handle_only = next(item for item in result["candidate_clusters"]
                       if item["candidate_id"] == "handle-only-candidate")
    assert handle_only["score"] < 0.70
