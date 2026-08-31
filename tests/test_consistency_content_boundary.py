import storage
from classification_schema import DESTINATION_HTML_EVIDENCE_VERSION
from consistency import audit_consistency, repair_consistency, repair_link_list_frontier


def _url(char: str, path: str = "/") -> str:
    return f"http://{char * 56}.onion{path}"


def _store_current_snapshot(url_id: int, url: str, structure: dict) -> int:
    snapshot_id = storage.store_fetched_page_snapshot(
        url_id, url, worker_id=None, response_status=200,
        content_type="text/html", headers={}, title="Index", meta_text="",
        visible_text="Index", link_records=[], page_structure=structure,
        pre_policy={},
    )
    assert storage.mark_fetched_page_verified(snapshot_id)
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET status='crawled',active=1,
          storage_policy='safe_summary',verification_state='verified',
          verification_reason='page_fetched_and_classified',
          classification_evidence_source='destination_html',
          destination_html_evidence_version=? WHERE id=?""",
          (DESTINATION_HTML_EVIDENCE_VERSION, url_id))
    return snapshot_id


def _directory_structure(link_count: int = 25) -> dict:
    return {
        "content_boundary": {
            "version": DESTINATION_HTML_EVIDENCE_VERSION,
            "outbound_anchor_text_removed": True,
        },
        "onion_link_count": link_count,
        "external_onion_host_count": link_count,
        "external_onion_count": link_count,
        "structured_lists": True,
        "repeated_link_row_count": link_count,
        "scores": {"directory": 4},
    }


def test_historical_edges_cannot_create_a_confirmed_directory(isolated_db):
    parent = _url("a", "/childporn-links")
    parent_id = storage.insert_or_update_onion_url(parent, status="crawled")
    for index in range(25):
        child = _url(chr(ord("b") + (index % 20)), f"/{index}")
        storage.insert_or_update_onion_url(child, source_url=parent, status="queued")
        storage.insert_onion_edge(parent, child, {
            "safe_anchor_text": "explicit-looking label",
            "relation_type": "directory_entry",
        })

    assert audit_consistency()["counts"]["unknown_high_edge_pages"] == 0
    result = repair_consistency(dry_run=False)

    with storage.get_db() as db:
        row = dict(db.execute("SELECT primary_category,page_type FROM onion_urls WHERE id=?",
                              (parent_id,)).fetchone())
    assert row == {"primary_category": "unknown", "page_type": "unknown"}
    assert result["after"]["unknown_high_edge_pages"] == 0


def test_current_destination_structure_can_mechanically_identify_link_repository(isolated_db):
    url = _url("v", "/anything-can-be-in-the-path")
    url_id = storage.insert_or_update_onion_url(url, status="queued")
    _store_current_snapshot(url_id, url, _directory_structure(25))

    assert audit_consistency()["counts"]["unknown_high_edge_pages"] == 1
    repair_consistency(dry_run=False)

    with storage.get_db() as db:
        row = dict(db.execute("""SELECT primary_category,category,content_category,
          page_type,classification_evidence_source,destination_html_evidence_version
          FROM onion_urls WHERE id=?""", (url_id,)).fetchone())
    assert row["primary_category"] == "directory_index"
    assert row["category"] == "directory_index"
    assert row["content_category"] == "directory_index"
    assert row["page_type"] == "link_repository"
    assert row["classification_evidence_source"] == "destination_html"
    assert row["destination_html_evidence_version"] == DESTINATION_HTML_EVIDENCE_VERSION


def test_route_or_parent_hints_inside_snapshot_cannot_create_directory(isolated_db):
    url = _url("w", "/directory-link-list-market")
    url_id = storage.insert_or_update_onion_url(url, status="queued")
    _store_current_snapshot(url_id, url, {
        "content_boundary": {
            "version": DESTINATION_HTML_EVIDENCE_VERSION,
            "outbound_anchor_text_removed": True,
        },
        "page_type_info": {
            "page_type": "link_repository",
            "page_type_confidence": "high",
            "evidence": ["url_route"],
        },
        "parent_evidence": ["directory", "restricted section"],
        "onion_link_count": 1,
        "external_onion_host_count": 1,
        "scores": {"directory": 0},
    })

    assert audit_consistency()["counts"]["unknown_high_edge_pages"] == 0
    assert repair_link_list_frontier(dry_run=False)["directory_parents"] == 0
    with storage.get_db() as db:
        row = dict(db.execute("SELECT primary_category,page_type FROM onion_urls WHERE id=?",
                              (url_id,)).fetchone())
    assert row == {"primary_category": "unknown", "page_type": "unknown"}


def test_forged_destination_flags_without_boundary_do_not_prove_restriction(isolated_db):
    parent = _url("c", "/")
    child = _url("d", "/childporn-name-only")
    storage.insert_or_update_onion_url(parent, status="crawled")
    child_id = storage.insert_or_update_onion_url(
        child, source_url=parent, status="queued")
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET primary_category='severe_abuse_risk',
          category='severe_abuse_risk',content_category='severe_abuse_risk',
          classification_evidence_source='destination_html',
          destination_html_evidence_version=?,verification_state='verified',
          verification_reason='page_fetched_and_classified',active=1,
          queue_policy='normal',storage_policy='safe_summary' WHERE id=?""",
          (DESTINATION_HTML_EVIDENCE_VERSION, child_id))
    storage.insert_onion_edge(parent, child, {
        "safe_anchor_text": "name-only hint", "relation_type": "directory_entry"})

    assert audit_consistency()["counts"]["restricted_child_queue_conflicts"] == 0
    assert audit_consistency()["counts"]["unsafe_restricted_anchor_storage"] == 0
    repair_consistency(dry_run=False)

    with storage.get_db() as db:
        edge = db.execute("SELECT safe_anchor_text FROM onion_edges WHERE discovered_url=?",
                          (child,)).fetchone()[0]
        row = dict(db.execute("SELECT active,queue_policy FROM onion_urls WHERE id=?",
                              (child_id,)).fetchone())
    assert edge == "name-only hint"
    assert row == {"active": 1, "queue_policy": "normal"}


def test_current_destination_restriction_is_eligible_for_safe_maintenance(isolated_db):
    parent = _url("g", "/")
    child = _url("h", "/neutral-path")
    storage.insert_or_update_onion_url(parent, status="crawled")
    child_id = storage.insert_or_update_onion_url(
        child, source_url=parent, status="queued")
    _store_current_snapshot(child_id, child, {
        "content_boundary": {
            "version": DESTINATION_HTML_EVIDENCE_VERSION,
            "outbound_anchor_text_removed": True,
        },
        "onion_link_count": 0,
        "scores": {},
    })
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET primary_category='adult_restricted',
          category='adult_restricted',content_category='adult_restricted',
          classification_evidence_source='destination_html',
          destination_html_evidence_version=?,verification_state='verified',
          verification_reason='page_fetched_and_classified',active=1,
          queue_policy='normal',storage_policy='safe_summary' WHERE id=?""",
          (DESTINATION_HTML_EVIDENCE_VERSION, child_id))
    storage.insert_onion_edge(parent, child, {
        "safe_anchor_text": "unsafe stored label", "relation_type": "directory_entry"})

    audit = audit_consistency()["counts"]
    assert audit["restricted_child_queue_conflicts"] == 1
    assert audit["unsafe_restricted_anchor_storage"] == 1
    repair_consistency(dry_run=False)

    with storage.get_db() as db:
        row = dict(db.execute("""SELECT status,active,queue_policy,storage_policy
          FROM onion_urls WHERE id=?""", (child_id,)).fetchone())
        edge = db.execute("SELECT safe_anchor_text FROM onion_edges WHERE discovered_url=?",
                          (child,)).fetchone()[0]
    assert row == {"status": "blocked", "active": 0,
                   "queue_policy": "blocked", "storage_policy": "metadata_only"}
    assert edge == "Restricted child link hidden"


def test_link_frontier_releases_unverified_explicit_looking_child(isolated_db):
    parent = _url("e", "/links")
    parent_id = storage.insert_or_update_onion_url(parent, status="queued")
    _store_current_snapshot(parent_id, parent, _directory_structure(8))

    child_host = "childporn" + ("f" * 47) + ".onion"
    child = f"http://{child_host}/"
    child_id = storage.insert_or_update_onion_url(
        child, child_host, source_url=parent, source_type="directory_seed",
        depth=4, status="blocked")
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET primary_category='adult_restricted',
          category='adult_restricted',content_category='adult_restricted',
          classification_evidence_source='unverified',
          destination_html_evidence_version=0,verification_state='provisional',
          verification_reason='url_hint',storage_policy='metadata_only',
          queue_policy='blocked',active=0,trap_reason='seed_depth_limit'
          WHERE id=?""", (child_id,))

    result = repair_link_list_frontier(dry_run=False)

    assert result["directory_parents"] == 1
    assert result["external_children"] == 1
    with storage.get_db() as db:
        child_row = dict(db.execute("""SELECT primary_category,category,content_category,
          status,active,queue_policy,storage_policy,verification_state,trap_reason
          FROM onion_urls WHERE id=?""", (child_id,)).fetchone())
    assert child_row["primary_category"] == "unknown"
    assert child_row["category"] == "unknown"
    assert child_row["content_category"] == "unknown"
    assert child_row["status"] == "queued"
    assert child_row["active"] == 1
    assert child_row["queue_policy"] == "normal"
    assert child_row["storage_policy"] == "safe_summary"
    assert child_row["verification_state"] == "provisional"
    assert child_row["trap_reason"] is None
