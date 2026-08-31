
import onion_worker
import site_dedupe
import storage
from consistency import audit_consistency, repair_consistency
from spain_alerts import format_spain_alert
from universal_classifier import classify


HOST = "q" * 56 + ".onion"
SPAIN_WEAPONS_HTML = """<html><head><title>Weapons delivery to Spain</title></head>
<body><h1>Weapons delivery to Spain</h1><p>Weapons shipment to Spain with Correos,
Bizum, DNI checks, Madrid delivery information, vendor order and shipping details.</p></body></html>"""


def _url(path="/"):
    return f"http://{HOST}{path}"


def _spain_weapon_policy(url, risk="high"):
    policy = classify(
        url,
        title="Weapons delivery to Spain",
        visible_text="Weapons shipment to Spain with Correos, Bizum, DNI checks, and Madrid delivery information " * 8,
        classification_scope="page",
    )
    policy.update({
        "primary_category": "weapons_arms", "category": "weapons_arms",
        "risk_level": risk, "spain_priority": True, "spain_confidence": "high",
        "spain_match_reason": "Spain destination context",
        "spain_priority_reason": "spanish_market_targeting",
        "spain_priority_evidence_type": "shipping_context",
        "spain_context_tags": ["trade_flow_to_spain", "spanish_payment_context", "spanish_identity_data"],
        "spain_actionable": True,
        "seller_geo_confidence": "high",
        "spain_relevance": "high",
        "spain_evidence_score": 95,
        "spain_context_only": False,
        "storage_policy": "safe_summary", "active": 1,
    })
    return policy


def _persist_verified(url, policy, *, html=SPAIN_WEAPONS_HTML):
    """Persist policy only after parsing this destination's own HTML."""
    title, _meta, _visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    policy = onion_worker.finalize_page_policy(
        url, dict(policy), title=title, page_structure=structure)
    url_id = storage.insert_or_update_onion_url(url, status="crawled")
    storage.apply_onion_policy(
        url, policy, 200, checked=True, page_structure=structure)
    return url_id, policy


def test_es_locale_and_spanish_language_are_not_spain_priority():
    locale = classify(_url("/es/"), title="Mercado", visible_text="servicios privados y noticias")
    language = classify(_url("/informacion"), title="Noticias", visible_text="informacion y servicios disponibles para usuarios")
    assert locale["locale_path"] == "es"
    assert locale["spanish_language_detected"] is True
    assert locale["spain_priority"] is False
    assert locale["spain_priority_reason"] == "spanish_language_only_not_priority"
    assert language["spain_priority"] is False


def test_true_spain_context_is_priority():
    policy = classify(
        _url("/delivery"),
        title="Delivery",
        visible_text="vendor order shipping to Spain using Correos and Bizum with Madrid Barcelona Sevilla delivery",
    )
    assert policy["spain_priority"] is True
    assert policy["spain_priority_reason"] in {"spanish_market_targeting", "spanish_city_reference", "spain_country_reference"}


def test_locale_variants_do_not_repeat_site_card_alert(isolated_db):
    first = _url("/market")
    first_id, policy = _persist_verified(first, _spain_weapon_policy(first))
    card_id = site_dedupe.ensure_url_site_card(first_id, policy, title="Market")
    assert storage.queue_spain_alert(first, policy)

    for path in ("/es/", "/de/", "/zh_cn/"):
        url = _url(path)
        variant = dict(policy, locale_path=path.strip("/"), language=path.strip("/").upper())
        url_id, variant = _persist_verified(url, variant)
        assert site_dedupe.ensure_url_site_card(url_id, variant, title="Market") == card_id
        assert storage.queue_spain_alert(url, variant) is False

    with storage.get_db() as db:
        card = dict(db.execute("SELECT * FROM site_cards WHERE id=?", (card_id,)).fetchone())
        alerts = db.execute("SELECT COUNT(*) FROM spain_alert_queue").fetchone()[0]
    assert alerts == 1
    assert card["language_variants_count"] >= 3


def test_risk_increase_creates_one_spain_update(isolated_db):
    url = _url("/risk")
    url_id, high = _persist_verified(url, _spain_weapon_policy(url, "high"))
    site_dedupe.ensure_url_site_card(url_id, high, title="Market")
    assert storage.queue_spain_alert(url, high)
    critical = dict(high, risk_level="critical")
    _url_id, critical = _persist_verified(url, critical)
    site_dedupe.ensure_url_site_card(url_id, critical, title="Market")
    assert storage.queue_spain_alert(url, critical)
    assert not storage.queue_spain_alert(url, critical)


def test_fraud_alert_format_is_always_metadata_only():
    message = format_spain_alert({"category": "marketplace_fraud", "risk_level": "critical"})
    assert "Restricted metadata-only item. No preview/snippet/screenshot stored." in message


def test_high_edge_unknown_finalizes_as_link_repository():
    policy = classify(_url("/links"), title="Resources", visible_text="welcome", classification_scope="page")
    finalized = onion_worker.finalize_page_policy(
        _url("/links"), policy, title="Resources",
        page_structure={"onion_link_count": 24, "external_onion_host_count": 20},
    )
    assert finalized["primary_category"] == "directory_index"
    assert finalized["page_type"] == "link_repository"
    assert finalized["queue_policy"] == "expand"
    assert finalized["safety_reason"] != "awaiting_page_classification"


def test_importance_override_does_not_change_risk(isolated_db):
    url = _url("/importance")
    url_id, policy = _persist_verified(url, _spain_weapon_policy(url))
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Market")
    site_dedupe.apply_manual_importance(card_id, "low", "Useful source, not urgent")
    with storage.get_db() as db:
        card = dict(db.execute("SELECT * FROM site_cards WHERE id=?", (card_id,)).fetchone())
    assert card["risk_level"] == "high"
    assert card["importance_level"] == "low"
    assert card["analyst_importance"] == "low"


def test_consistency_audit_and_safe_repair(isolated_db):
    url = _url("/conflict")
    storage.insert_or_update_onion_url(url, status="queued", policy=classify(url))
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET active=0,status='queued',queue_policy='normal' WHERE url=?", (url,))
    assert audit_consistency()["counts"]["queued_inactive_conflicts"] == 1
    preview = repair_consistency(dry_run=True)
    assert preview["would_change"] >= 1
    repair_consistency(dry_run=False)
    assert audit_consistency()["counts"]["queued_inactive_conflicts"] == 0


def test_clean_consistency_repair_does_not_rebuild_unaffected_cards(isolated_db, monkeypatch):
    url = _url("/already-clean")
    url_id, policy = _persist_verified(url, _spain_weapon_policy(url))
    site_dedupe.ensure_url_site_card(url_id, policy, title="Clean card")
    refreshed = []
    monkeypatch.setattr(site_dedupe, "update_site_card_rollups", lambda card_id: refreshed.append(card_id))

    preview = repair_consistency(dry_run=True)
    result = repair_consistency(dry_run=False)

    assert preview["would_change"] == 0
    assert preview["candidate_urls"] == 0
    assert result["mechanical_changes"] == 0
    assert result["cards_refreshed"] == 0
    assert refreshed == []


def test_consistency_repair_sanitizes_restricted_child_anchor_metadata(isolated_db):
    parent = _url("/directory")
    child = _url("/restricted-child")
    storage.insert_or_update_onion_url(parent, status="crawled", policy=classify(parent))
    restricted = classify(child)
    restricted.update(primary_category="severe_abuse_risk", category="severe_abuse_risk",
                      storage_policy="metadata_only", queue_policy="blocked", active=0)
    child_id = storage.insert_or_update_onion_url(
        child, source_url=parent, status="blocked", policy=restricted)
    # Maintenance may act on an exact analyst decision, but never on an
    # unverified category copied from URL/anchor/parent context.
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET primary_category='severe_abuse_risk',
          category='severe_abuse_risk',content_category='severe_abuse_risk',
          analyst_category='severe_abuse_risk',classification_evidence_source='analyst',
          destination_html_evidence_version=0,verification_state='verified',
          verification_reason='analyst_confirmed',storage_policy='metadata_only',
          queue_policy='blocked',active=0,status='blocked' WHERE id=?""", (child_id,))
    storage.insert_onion_edge(parent, child, {"safe_anchor_text": "unsafe child label",
                                              "relation_type": "directory_entry"})
    assert audit_consistency()["counts"]["unsafe_restricted_anchor_storage"] == 1
    preview = repair_consistency(dry_run=True)
    assert preview["unsafe_anchors_sanitized"] == 1
    repair_consistency(dry_run=False)
    with storage.get_db() as db:
        value = db.execute("SELECT safe_anchor_text FROM onion_edges WHERE source_url=?", (parent,)).fetchone()[0]
    assert value == "Restricted child link hidden"
    assert audit_consistency()["counts"]["unsafe_restricted_anchor_storage"] == 0


def test_spain_alert_pause_retains_pending_queue(isolated_db):
    url = _url("/pause")
    url_id, policy = _persist_verified(url, _spain_weapon_policy(url))
    site_dedupe.ensure_url_site_card(url_id, policy, title="Market")
    assert storage.queue_spain_alert(url, policy)
    storage.set_spain_alerts_paused(True, "test")
    assert storage.spain_alerts_paused() is True
    assert storage.get_pending_spain_alerts() == []
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM spain_alert_queue WHERE status='pending'").fetchone()[0] == 1
    storage.set_spain_alerts_paused(False, "test")
    assert len(storage.get_pending_spain_alerts()) == 1
