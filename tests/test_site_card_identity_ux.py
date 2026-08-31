import sqlite3
from pathlib import Path

import report_builder
import onion_worker
import site_dedupe
import storage
from consistency import repair_site_cards
from dashboard_pages import site_directory


HOST = "m" * 56 + ".onion"


def _policy(category="hosting_services"):
    return {
        "primary_category": category, "category": category,
        "content_category": category, "analyst_category": category,
        "classification_evidence_source": "analyst",
        "destination_html_evidence_version": 0, "tags": ["hosting"],
        "risk_level": "low", "confidence": "high", "risk_flags": [],
        "storage_policy": "safe_summary", "review_status": "needs_review",
        "safety_reason": "test", "priority_score": 20, "screenshot_policy": "allowed",
        "queue_policy": "normal", "active": 1, "spain_priority": False,
        "page_type": "homepage", "card_ready": True, "card_readiness_reason": "safe_homepage",
    }


def _insert_onion_url(url: str, onion_domain: str = HOST, **kwargs):
    policy = dict(kwargs.get("policy") or _policy())
    kwargs["policy"] = policy
    url_id = storage.insert_or_update_onion_url(url, onion_domain, **kwargs)
    category = str(policy["analyst_category"])
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET analyst_category=?,primary_category=?,category=?,
          content_category=?,classification_evidence_source='analyst',
          destination_html_evidence_version=0 WHERE id=?""",
          (category, category, category, category, url_id))
    return url_id


def _card(url: str):
    policy = _policy()
    url_id = _insert_onion_url(url, HOST, status="crawled", policy=policy)
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Example Hosting", visible_text="hosting service")
    return url_id, card_id


def test_canonical_url_variants_share_one_url_and_card(isolated_db):
    first_id, card_id = _card(f"https://{HOST}//#top")
    second_id = _insert_onion_url(
        f"http://{HOST}/?utm_source=index#other", HOST,
        source_url=f"http://{'s' * 56}.onion/one", source_type="directory", policy=_policy())
    third_id = _insert_onion_url(
        f"http://{HOST}", HOST,
        source_url=f"http://{'t' * 56}.onion/two", source_type="directory", policy=_policy())
    assert first_id == second_id == third_id
    site_dedupe.ensure_url_site_card(second_id, _policy(), title="Changed generated title", visible_text="hosting service")
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM onion_urls").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM site_cards").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM onion_url_sources WHERE onion_url_id=?", (first_id,)).fetchone()[0] == 3
        assert db.execute("SELECT site_card_id FROM onion_urls WHERE id=?", (first_id,)).fetchone()[0] == card_id


def test_duplicate_reconciliation_dry_run_and_apply_preserve_analyst_work(isolated_db):
    _url_id, target_id = _card(f"http://{HOST}/")
    now = storage.utc_now_iso()
    source_url_id = _insert_onion_url(f"http://{HOST}/about", HOST, status="crawled", policy=_policy())
    with storage.get_db() as db:
        source_id = db.execute("""INSERT INTO site_cards
          (canonical_site_id,display_name,analyst_title,primary_category,storage_policy,
           first_seen,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)""",
          ("duplicate-card", "Generated duplicate", "Analyst-kept name", "hosting_services",
           "safe_summary", now, now, now)).lastrowid
        db.execute("""INSERT INTO site_card_urls(site_card_id,onion_url_id,url,onion_host,path,
          first_seen,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)""",
          (source_id, source_url_id, f"http://{HOST}/about", HOST, "/about", now, now, now))
        db.execute("UPDATE onion_urls SET site_card_id=? WHERE id=?", (source_id, source_url_id))
    preview = site_dedupe.reconcile_duplicate_site_cards(dry_run=True)
    assert preview["groups"] == 1 and preview["cards_to_merge"] == 1 and preview["merged"] == 0
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM site_cards").fetchone()[0] == 2
    applied = site_dedupe.reconcile_duplicate_site_cards(dry_run=False)
    assert applied["merged"] == 1
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM site_cards").fetchone()[0] == 1
        card = db.execute("SELECT analyst_title FROM site_cards").fetchone()
        assert card["analyst_title"] == "Analyst-kept name"


def test_new_site_cards_use_deterministic_host_identity(isolated_db):
    first_id = _insert_onion_url(f"http://{HOST}/index.php?utm_source=x", HOST, status="crawled", policy=_policy())
    first_card = site_dedupe.ensure_url_site_card(first_id, _policy(), title="Root")
    second_id = _insert_onion_url(f"http://{HOST}/about?ref=directory", HOST, status="crawled", policy=_policy())
    second_card = site_dedupe.ensure_url_site_card(second_id, _policy(), title="About")
    with storage.get_db() as db:
        card = dict(db.execute("SELECT canonical_site_id FROM site_cards WHERE id=?", (first_card,)).fetchone())
        url_cards = {row[0] for row in db.execute("SELECT site_card_id FROM onion_urls WHERE id IN (?,?)", (first_id, second_id))}
    assert first_card == second_card
    assert url_cards == {first_card}
    assert card["canonical_site_id"] == "site-" + site_dedupe._hash(f"onion:{HOST}")[:20]


def test_directory_anchor_can_name_weak_market_card_without_category_title(isolated_db):
    source = f"http://{'d' * 56}.onion/"
    target = f"http://{HOST}/category/cards"
    policy = _policy("marketplace_fraud")
    policy.update(
        storage_policy="metadata_limited",
        review_status="monitor",
        safe_display_name="Marketplace: Fraud",
        detected_title="Marketplace: Fraud",
        title_source="classifier_label",
        identity_confidence="low",
        page_type="category_index",
        card_ready=True,
    )
    url_id = _insert_onion_url(target, HOST, source_url=source,
                               source_type="directory", status="crawled",
                               policy=policy)
    storage.insert_onion_edge(source, target, {
        "relation_type": "directory_entry",
        "safe_anchor_text": "Best Financial Market",
        "source_page_type": "link_repository",
        "same_host": 0,
    })

    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Marketplace: Fraud")

    card = site_dedupe.get_site_card(card_id)
    assert card["display_name"] == "Best Financial Market"
    assert card["display_name_source"] == "directory_anchor_identity"
    assert card["analyst_title"] in {None, ""}


def test_homepage_identity_beats_child_generic_market_label_and_manual_title_survives(isolated_db):
    child = f"http://{HOST}/vendor/example"
    child_policy = _policy("marketplace_drugs")
    child_policy.update(storage_policy="metadata_limited", review_status="monitor",
                        safe_display_name="Marketplace: Drugs", detected_title="Marketplace: Drugs",
                        identity_confidence="low", page_type="vendor_profile")
    child_id = _insert_onion_url(child, HOST, status="crawled", policy=child_policy)
    card_id = site_dedupe.ensure_url_site_card(child_id, child_policy, title="Marketplace: Drugs")
    site_dedupe.apply_manual_title(card_id, "Analyst clean market")

    root = f"http://{HOST}/"
    root_policy = _policy("marketplace")
    root_policy.update(storage_policy="metadata_limited", review_status="monitor",
                       safe_site_name="Best Financial Market", safe_display_name="Best Financial Market",
                       detected_title="Best Financial Market", title_source="heading",
                       identity_confidence="high", page_type="homepage",
                       page_type_confidence="high", category_confidence="high")
    root_id = _insert_onion_url(root, HOST, status="crawled", policy=root_policy)
    root_card_id = site_dedupe.ensure_url_site_card(root_id, root_policy, title="Best Financial Market")

    card = site_dedupe.get_site_card(root_card_id)
    assert root_card_id == card_id
    assert card["display_name"] == "Best Financial Market"
    assert card["analyst_title"] == "Analyst clean market"
    assert card["display_name"] != "Marketplace: Drugs"


def test_weak_child_card_plans_root_identity_enrichment(isolated_db):
    child = f"http://{HOST}/vendor/example"
    policy = _policy("marketplace")
    policy.update(storage_policy="metadata_limited", review_status="monitor",
                  safe_display_name="Marketplace", detected_title="Marketplace",
                  identity_confidence="low", page_type="vendor_profile",
                  page_type_confidence="low", category_confidence="low")
    url_id = _insert_onion_url(child, HOST, status="crawled", policy=policy)
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Marketplace")

    result = onion_worker.plan_card_enrichment(card_id)

    assert result["queued"] >= 1
    with storage.get_db() as db:
        queued = {row["url"] for row in db.execute(
            "SELECT url FROM onion_urls WHERE source_type='card_enrichment'")}
    assert f"http://{HOST}/" in queued


def test_first_about_then_root_reuses_one_host_card(isolated_db):
    about_id = _insert_onion_url(f"http://{HOST}/about", HOST, status="crawled", policy=_policy())
    about_card = site_dedupe.ensure_url_site_card(about_id, _policy(), title="About")
    root_id = _insert_onion_url(f"http://{HOST}/", HOST, status="crawled", policy=_policy())
    root_card = site_dedupe.ensure_url_site_card(root_id, _policy(), title="Root")
    assert about_card == root_card
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM site_cards").fetchone()[0] == 1
        roles = {row[0] for row in db.execute("SELECT url_role FROM site_card_urls WHERE site_card_id=?", (root_card,))}
    assert roles <= {"canonical", "path"}


def test_same_host_urls_processed_before_rollup_still_one_card(isolated_db):
    first_id = _insert_onion_url(f"http://{HOST}/rules", HOST, status="crawled", policy=_policy())
    second_id = _insert_onion_url(f"http://{HOST}/contact", HOST, status="crawled", policy=_policy())
    first_card = site_dedupe.ensure_url_site_card(first_id, _policy(), title="Rules", update_rollup=False)
    second_card = site_dedupe.ensure_url_site_card(second_id, _policy(), title="Contact", update_rollup=False)
    assert first_card == second_card
    site_dedupe.update_site_card_rollups(first_card)
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM site_cards").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM site_card_urls WHERE site_card_id=?", (first_card,)).fetchone()[0] == 2


def test_repeated_same_url_processing_does_not_duplicate_url_assigned_events(isolated_db):
    url = f"http://{HOST}/contact"
    url_id = _insert_onion_url(url, HOST, status="crawled", policy=_policy())
    card_id = site_dedupe.ensure_url_site_card(url_id, _policy(), title="Contact")
    site_dedupe.ensure_url_site_card(url_id, _policy(), title="Contact")
    with storage.get_db() as db:
        events = db.execute("""SELECT COUNT(*) FROM site_card_events
          WHERE site_card_id=? AND event_type='url_assigned'""", (card_id,)).fetchone()[0]
    assert events == 1


def test_explain_card_creation_decision_includes_identity_and_reason(isolated_db):
    url_id, card_id = _card(f"http://{HOST}/about")
    explanation = site_dedupe.explain_card_creation_decision(card_id)
    assert explanation["site_card_id"] == card_id
    assert explanation["host"] == HOST
    assert explanation["canonical_root"] == f"http://{HOST}/"
    assert explanation["entity_identity"] == f"onion:{HOST}"
    assert explanation["url_role"] in {"canonical", "path"}
    assert explanation["match_confidence"] in {"new_card", "unknown", "same_host"}
    assert explanation["decision_reason"]


def test_repair_site_cards_reports_and_applies_duplicate_merges(isolated_db):
    _url_id, target_id = _card(f"http://{HOST}/")
    now = storage.utc_now_iso()
    source_url_id = _insert_onion_url(f"http://{HOST}/rules", HOST, status="crawled", policy=_policy())
    with storage.get_db() as db:
        source_id = db.execute("""INSERT INTO site_cards
          (canonical_site_id,display_name,analyst_notes,primary_category,storage_policy,
           first_seen,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)""",
          ("legacy-duplicate-card", "Legacy duplicate", "keep these notes", "hosting_services",
           "safe_summary", now, now, now)).lastrowid
        db.execute("""INSERT INTO site_card_urls(site_card_id,onion_url_id,url,onion_host,path,
          first_seen,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)""",
          (source_id, source_url_id, f"http://{HOST}/rules", HOST, "/rules", now, now, now))
        db.execute("UPDATE onion_urls SET site_card_id=? WHERE id=?", (source_id, source_url_id))
    preview = repair_site_cards(dry_run=True)
    assert preview["duplicate_groups"] == 1
    assert preview["duplicate_cards_to_merge"] == 1
    applied = repair_site_cards(dry_run=False)
    assert applied["duplicate_cards_merged"] == 1
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM site_cards").fetchone()[0] == 1
        assert db.execute("SELECT analyst_notes FROM site_cards WHERE id=?", (target_id,)).fetchone()[0] == "keep these notes"


def test_report_state_becomes_stale_without_creating_a_new_card(isolated_db, tmp_path, monkeypatch):
    _url_id, card_id = _card(f"http://{HOST}/")
    monkeypatch.setattr(report_builder, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(site_directory, "REPORTS_DIR", tmp_path)
    first = Path(report_builder.build_site_card_report(card_id))
    assert first.exists()
    assert site_dedupe.get_site_card_detail(card_id)["report_state"] == "report_ready"
    site_dedupe.apply_manual_title(card_id, "Clean analyst name")
    assert site_dedupe.get_site_card_detail(card_id)["report_state"] == "report_stale"
    report_builder.build_site_card_report(card_id)
    detail = site_dedupe.get_site_card_detail(card_id)
    assert detail["report_state"] == "report_ready"
    assert len(detail["reports"]) == 2
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM site_cards").fetchone()[0] == 1


def test_dashboard_locked_save_uses_friendly_warning(isolated_db, monkeypatch):
    class FakeSt:
        session_state = {"dialog-title-1": "Changed"}
        warnings = []
        errors = []
        def warning(self, value): self.warnings.append(value)
        def error(self, value): self.errors.append(value)

    fake = FakeSt()
    monkeypatch.setattr(site_directory, "current_language", lambda _st: "en")
    monkeypatch.setattr(site_dedupe, "apply_manual_title",
                        lambda *_args: (_ for _ in ()).throw(sqlite3.OperationalError("database is locked")))
    site_directory._save_edit(fake, {"id": 1, "analyst_title": "", "primary_category": "unknown",
                                     "importance_level": "normal", "review_status": "pending"}, object())
    assert fake.warnings and "Database is busy" in fake.warnings[0]
    assert not fake.errors
