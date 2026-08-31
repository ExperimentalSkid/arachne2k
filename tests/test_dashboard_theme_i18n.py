from pathlib import Path
import ast
from collections import Counter

from streamlit.testing.v1 import AppTest

import site_dedupe
import storage
from universal_classifier import classify


ROOT = Path(__file__).parents[1]


def _analyst_policy(policy):
    """Mark synthetic UI setup as an explicit analyst classification."""
    policy = dict(policy)
    policy.update(
        analyst_category=policy["primary_category"],
        classification_evidence_source="analyst",
    )
    return policy


def _insert_analyst_url(url, policy):
    url_id = storage.insert_or_update_onion_url(url, status="crawled")
    with storage.get_db() as db:
        stored_url = db.execute("SELECT url FROM onion_urls WHERE id=?", (url_id,)).fetchone()[0]
        db.execute("UPDATE onion_urls SET analyst_category=? WHERE id=?",
                   (policy["analyst_category"], url_id))
    storage.apply_onion_policy(stored_url, policy)
    return url_id


def test_ui_copy_catalogue_has_no_silent_duplicate_keys():
    tree = ast.parse((ROOT / "dashboard_services" / "i18n.py").read_text(encoding="utf-8"))
    copy_node = next(
        node.value for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "COPY" for target in node.targets)
    )
    keys = [key.value for key in copy_node.keys if isinstance(key, ast.Constant)]
    assert [key for key, count in Counter(keys).items() if count > 1] == []


def test_six_area_menu_and_spanish_switch_render(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    assert not app.exception
    assert len(app.sidebar.radio[1].options) == 6
    assert any("Results" in value for value in app.sidebar.radio[1].options)
    assert any("Settings" in value for value in app.sidebar.radio[1].options)

    app.sidebar.toggle[0].set_value(True).run()
    assert not app.exception
    assert any("Resultados" in value for value in app.sidebar.radio[1].options)
    assert any("Ajustes" in value for value in app.sidebar.radio[1].options)
    assert any("Empieza aquí" in str(item.value) for item in app.markdown)


def test_settings_workspace_explains_safe_rotation_and_server_boundary(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value("Settings").run()
    assert not app.exception
    rendered = " ".join(str(item.value) for item in app.markdown) + " " + " ".join(str(item.label) for item in app.button)
    assert "Tor privacy" in rendered
    assert "never cancel" in rendered
    assert "Safety rules that settings cannot weaken" in rendered
    assert any(item.label == "Save settings" for item in app.button)


def test_spanish_switch_translates_result_cards_and_category_values(isolated_db):
    url = "http://" + "i" * 56 + ".onion/research"
    text = "Cybersecurity research and responsible disclosure with vulnerability advisories."
    policy = _analyst_policy(classify(
        url, title="Security research", visible_text=text, classification_scope="page"
    ))
    url_id = _insert_analyst_url(url, policy)
    site_dedupe.ensure_url_site_card(url_id, policy, title="Security research", visible_text=text)

    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    app.sidebar.toggle[0].set_value(True).run()
    results = next(value for value in app.sidebar.radio[1].options if "Resultados" in value)
    app.sidebar.radio[1].set_value(results).run()

    assert not app.exception
    rendered = " ".join(str(item.value) for item in [*app.markdown, *app.caption])
    rendered += " " + " ".join(str(item.label) for item in app.button)
    assert "Seguridad informática / investigación" in rendered
    assert "Comprobado" not in rendered
    assert "Visto" not in rendered
    assert any(button.label == "Abrir" for button in app.button)

    display = next(item for item in app.radio if item.label == "Vista")
    display.set_value("Card view").run()
    assert not app.exception
    rendered = " ".join(str(item.value) for item in [*app.markdown, *app.caption])
    rendered += " " + " ".join(str(item.label) for item in app.button)
    assert "Seguridad informática / investigación" in rendered
    assert "Bajo" in rendered
    assert "Monitorizar" in rendered


def test_grouped_crawl_navigation_opens_guided_add_page(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    crawl_option = next(value for value in app.sidebar.radio[1].options if "Crawl" in value)
    app.sidebar.radio[1].set_value(crawl_option).run()
    assert not app.exception
    assert any(item.label == "Add to crawl queue" for item in app.button)
    assert any("Add onion" in value for value in app.sidebar.radio[2].options)


def test_open_spain_priority_button_updates_grouped_menu_and_page(isolated_db):
    url = "http://" + "s" * 56 + ".onion/"
    policy = _analyst_policy(classify(
        url, visible_text="Firearms vendor listing with weapons for sale and shipping to Spain",
        classification_scope="page",
    ))
    policy.update(spain_priority=True, spain_confidence="high", spain_match_language="ES",
                  spain_match_reason="Spain reference paired with threat-related context",
                  spain_context_tags=["threat_context"], classification_decision="needs_review",
                  ui_hidden_default=0)
    url_id = _insert_analyst_url(url, policy)
    site_dedupe.ensure_url_site_card(url_id, policy, title="Safe Spain lead")

    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    button = next(item for item in app.button if item.label == "OPEN SPAIN PRIORITY REVIEW")
    button.click().run()
    assert not app.exception
    assert app.session_state["nav_page"] == "Spain Priority"
    rendered = " ".join(str(item.value) for item in app.markdown)
    assert "Spain Priority" in rendered and "Pages to check" in rendered
    assert any("Spain Priority" in value and app.sidebar.radio[1].value == value
               for value in app.sidebar.radio[1].options)


def test_classified_spain_result_uses_results_filter_without_persistent_alert(isolated_db):
    url = "http://" + "w" * 56 + ".onion/vendor/arms"
    policy = _analyst_policy(classify(
        url,
        visible_text="Firearms vendor listing and weapons sale with shipping to Spain Correos Bizum Madrid",
        classification_scope="page",
    ))
    assert policy["classification_decision"] == "accepted" and policy["spain_priority"]
    url_id = _insert_analyst_url(url, policy)
    site_dedupe.ensure_url_site_card(url_id, policy, title="Spain weapons result")

    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    assert not any(item.label == "OPEN SPAIN PRIORITY REVIEW" for item in app.button)

    results = next(value for value in app.sidebar.radio[1].options if "Results" in value)
    app.sidebar.radio[1].set_value(results).run()
    next(item for item in app.toggle if item.label == "Show Spain filters and counters").set_value(True).run()
    spain_filter = next(item for item in app.selectbox if item.label == "Filter Spain results")
    assert {"All Spain-linked", "Sending to Spain", "Spain + weapons"} <= set(spain_filter.options)
    spain_filter.set_value("Spain + weapons").run()
    assert not app.exception
    assert any("Spain weapons result" in str(item.label) or "Marketplace: Weapons" in str(item.label)
               or "Weapons / arms context" in str(item.label) for item in app.button)


def test_home_high_risk_box_opens_results_with_matching_filter(isolated_db):
    high_url = "http://" + "h" * 56 + ".onion/vendor/arms"
    high_text = "Firearms vendor listing with rifles for sale, shipping and contact details."
    high_policy = _analyst_policy(classify(
        high_url, visible_text=high_text, classification_scope="page"
    ))
    high_id = _insert_analyst_url(high_url, high_policy)
    site_dedupe.ensure_url_site_card(high_id, high_policy, title="High risk weapons result", visible_text=high_text)

    low_url = "http://" + "l" * 56 + ".onion/research"
    low_text = "Digital privacy advocacy and anonymity tools with encryption guidance."
    low_policy = _analyst_policy(classify(
        low_url, visible_text=low_text, classification_scope="page"
    ))
    low_id = _insert_analyst_url(low_url, low_policy)
    site_dedupe.ensure_url_site_card(low_id, low_policy, title="Low risk privacy result", visible_text=low_text)

    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    high_risk_button = next(item for item in app.button if item.key == "home-category-action-4")
    assert high_risk_button.disabled is False
    high_risk_button.click().run()

    assert not app.exception
    assert app.session_state["nav_page"] == "Site Cards"
    nav = app.query_params.get("nav")
    assert (nav[0] if isinstance(nav, list) else nav) == "cards"
    priority = next(item for item in app.selectbox if item.label == "Priority filter")
    assert priority.value == "High risk"
    rendered = " ".join(str(item.value) for item in app.markdown) + " " + " ".join(str(item.label) for item in app.button)
    assert "Weapons / arms context" in rendered or "Marketplace: Weapons" in rendered
    assert "Low risk privacy result" not in rendered


def test_home_adult_review_button_opens_safe_restricted_metadata(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    button = next(item for item in app.button if item.label == "Show / fix adult filters")
    button.click().run()

    assert not app.exception
    assert any("Advanced tools" in str(item.value) for item in app.markdown)
    adult_toggle = next(item for item in app.checkbox if item.label == "Show filtered adult metadata")
    assert adult_toggle.value is True


def test_faq_is_card_based_help_center(isolated_db):
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    settings = next(value for value in app.sidebar.radio[1].options if "Settings" in value)
    app.sidebar.radio[1].set_value(settings).run()
    faq = next(value for value in app.sidebar.radio[2].options if "FAQ" in value)
    app.sidebar.radio[2].set_value(faq).run()

    assert not app.exception
    rendered = " ".join(str(item.value) for item in app.markdown)
    assert "FAQ" in rendered
    assert "faq-card" in rendered
    assert "Crawling and processing" in rendered
    assert "Server and deployment" in rendered
    assert "Review Inbox for pending decisions" in rendered
    assert "Open details in Sites" in rendered
    assert "Results for Site Cards" not in rendered
    faq_heroes = [
        str(item.value) for item in app.markdown
        if "faq-hero" in str(item.value) and "<style>" not in str(item.value)
    ]
    assert len(faq_heroes) == 1
    assert "<h2>" not in faq_heroes[0]
    assert all(item.label != "What is a Site Card?" for item in app.expander)
