from pathlib import Path

import report_builder
import site_dedupe
import storage
from universal_classifier import classify
from urgency_policy import decide_triage


HOST = "z" * 56 + ".onion"
ROOT = f"http://{HOST}/"


def _analyst_policy(policy):
    """Give card-only fixtures an exact manual category provenance."""
    policy = dict(policy)
    policy.update(
        analyst_category=policy["primary_category"],
        classification_evidence_source="analyst",
    )
    return policy


def _insert_analyst_url(url, policy):
    url_id = storage.insert_or_update_onion_url(url, HOST, status="crawled")
    with storage.get_db() as db:
        stored_url = db.execute("SELECT url FROM onion_urls WHERE id=?", (url_id,)).fetchone()[0]
        db.execute("UPDATE onion_urls SET analyst_category=? WHERE id=?",
                   (policy["analyst_category"], url_id))
    storage.apply_onion_policy(stored_url, policy)
    return url_id


def test_spanish_language_only_is_monitor_triage():
    row = classify(ROOT + "es/", title="Noticias", visible_text="informacion servicios usuarios")
    decision = decide_triage([row])
    assert decision.level == "monitor"
    assert "No strong Spain" in decision.reason


def test_spain_leak_evidence_becomes_urgent_triage():
    row = classify(ROOT + "leak", title="Spain database leak",
                   visible_text="Spanish company database leak Madrid clientes exposed credentials breach")
    row.update(spain_priority=True, spain_relevance="high", spain_actionable=1, spain_evidence_score=90,
               spain_evidence_type="spanish_company_leak")
    decision = decide_triage([row])
    assert decision.level == "urgent"
    assert "spain_evidence" in decision.triggers
    assert "leak_evidence" in decision.triggers


def test_non_spain_direct_fraud_is_needs_check_not_urgent():
    row = classify(ROOT + "fraud", title="Fraud page",
                   visible_text="carding fullz cashout cvv dumps direct offer")
    decision = decide_triage([row])
    assert decision.level in {"needs_check", "monitor"}
    assert decision.level != "urgent"


def test_card_rollup_cannot_combine_spain_only_row_with_unrelated_risk_row():
    spain_only = {
        "primary_category": "general_other",
        "page_type": "homepage",
        "spain_priority": True,
        "spain_relevance": "high",
        "spain_actionable": 1,
        "spain_context_only": 0,
        "spain_evidence_score": 90,
        "spain_evidence_type": "location_mention",
    }
    unrelated_risk = {
        "primary_category": "leaks_data",
        "page_type": "article_page",
        "spain_priority": False,
        "risk_flags": ["breach", "credentials"],
    }
    decision = decide_triage([spain_only, unrelated_risk])
    assert decision.level == "alert"
    assert decision.level != "urgent"


def test_same_row_spain_and_direct_risk_remains_urgent():
    row = {
        "primary_category": "leaks_data",
        "page_type": "marketplace_listing",
        "spain_priority": True,
        "spain_relevance": "high",
        "spain_actionable": 1,
        "spain_context_only": 0,
        "spain_evidence_score": 90,
        "spain_evidence_type": "spanish_identity_data",
        "risk_flags": ["breach", "credentials"],
    }
    assert decide_triage([row]).level == "urgent"


def test_spain_row_below_evidence_gate_is_not_urgent_even_with_risk():
    row = {
        "primary_category": "leaks_data",
        "page_type": "marketplace_listing",
        "spain_priority": True,
        "spain_relevance": "high",
        "spain_actionable": 1,
        "spain_context_only": 0,
        "spain_evidence_score": 74,
        "spain_evidence_type": "spanish_identity_data",
        "risk_flags": ["breach", "credentials"],
    }
    assert decide_triage([row]).level != "urgent"


def test_same_root_sections_are_preserved_in_one_card(isolated_db):
    root_policy = _analyst_policy(classify(
        ROOT, title="Safe Directory", visible_text="onion directory index links"
    ))
    child_policy = _analyst_policy(classify(
        ROOT + "market", title="Market Section",
        visible_text="marketplace vendor product listing order escrow shipping from Spain Correos",
    ))
    root_id = _insert_analyst_url(ROOT, root_policy)
    child_id = _insert_analyst_url(ROOT + "market", child_policy)
    card_id = site_dedupe.ensure_url_site_card(root_id, root_policy, title="Safe Directory")
    child_card_id = site_dedupe.ensure_url_site_card(child_id, child_policy, title="Market Section")

    assert child_card_id == card_id
    sections = storage.get_site_card_sections(card_id)
    paths = {section["path"] for section in sections}
    assert "/" in paths
    assert "/market" in paths
    assert any(section.get("spain_evidence") for section in sections)


def test_operational_report_includes_safe_sections_and_recommendation(isolated_db, tmp_path, monkeypatch):
    policy = _analyst_policy(classify(
        ROOT, title="Spain Leak Watch",
        visible_text="Spanish company database leak Madrid exposed credentials",
    ))
    policy.update(spain_priority=True, spain_relevance="high", spain_actionable=1,
                  spain_evidence_type="spanish_company_leak", triage_level="urgent")
    url_id = _insert_analyst_url(ROOT, policy)
    card_id = site_dedupe.ensure_url_site_card(url_id, policy, title="Spain Leak Watch")
    site_dedupe.update_site_card_rollups(card_id)
    monkeypatch.setattr(report_builder, "REPORTS_DIR", tmp_path)

    output = Path(report_builder.build_site_card_report(card_id, "pytest"))
    text = output.read_text(encoding="utf-8")

    assert "Operational Site Review Report" in text
    assert "Police-Style" not in text
    assert "Arachne" in text
    assert "Relevant discovered sections" in text
    assert "Recommended action" in text
    assert "Safe metadata only: Yes" in text
