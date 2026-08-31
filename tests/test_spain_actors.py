import json
import hashlib
from pathlib import Path

from streamlit.testing.v1 import AppTest

import onion_worker
import storage
from entity_extractor import actor_identity_evidence, extract_indicators, extract_public_aliases
from universal_classifier import classify


ROOT = Path(__file__).parents[1]
HOST_A = "a" * 56 + ".onion"
HOST_B = "b" * 56 + ".onion"


class _Response:
    status_code = 200
    headers = {"Content-Type": "text/html"}

    def __init__(self, body):
        self.body = body.encode()

    def iter_content(self, chunk_size=16384):
        yield self.body

    def close(self):
        return None


class _Session:
    def __init__(self, body):
        self.response = _Response(body)

    def get(self, *_args, **_kwargs):
        return self.response


class _MappingSession:
    def __init__(self, pages):
        self.pages = pages

    def get(self, url, **_kwargs):
        return _Response(self.pages[url])


def _policy(spain=True):
    return {
        "primary_category": "weapons_arms", "category": "weapons_arms",
        "page_type": "thread_page", "risk_level": "high", "storage_policy": "metadata_limited",
        "review_status": "needs_review", "queue_policy": "reviewable", "active": 1,
        "spain_priority": spain, "spain_confidence": "high" if spain else None,
        "spain_match_reason": "Visible delivery reference to Spain" if spain else None,
        "spain_match_language": "EN", "spain_context_tags": ["trade_flow_to_spain"] if spain else [],
    }


def _persist_verified_policy(url, policy):
    category = str(policy.get("primary_category") or "unknown")
    category_text = {
        "weapons_arms": "weapons and firearms seller profile",
        "drugs": "controlled substances seller profile",
        "marketplace_fraud": "carding fullz cashout seller profile",
    }.get(category, "public forum profile")
    tags = set(policy.get("spain_context_tags") or [])
    flow_text = (
        "Shipping from Spain via Correos and Madrid pickup with Bizum."
        if "trade_flow_from_spain" in tags else
        "Shipping to Spain via Correos with Bizum and Madrid delivery."
        if "trade_flow_to_spain" in tags else
        "Spain-linked public profile context."
    )
    html = f"""<html><head><title>{category_text}</title></head><body>
      <h1>{category_text}</h1><article class='post'><span class='username'>PublicUser</span>
      <p>{flow_text} Public vendor listing and order information.</p></article></body></html>"""
    title, _meta, _visible, _links, structure = onion_worker._parse(
        html.encode("utf-8"), "text/html; charset=utf-8", url)
    verified = onion_worker.finalize_page_policy(
        url, dict(policy), title=title, page_structure=structure)
    storage.insert_or_update_onion_url(url, status="crawled")
    storage.apply_onion_policy(
        url, verified, 200, checked=True, page_structure=structure)
    return verified


def _store(url, alias, evidence=None, spain=True):
    policy = _persist_verified_policy(url, _policy(spain))
    if spain:
        storage.persist_spain_priority(url, policy)
    aliases = [{"alias": alias, "normalized_alias": alias.casefold(),
                "accepted": True, "evidence_version": 2, "role": "profile_owner",
                "evidence_type": "profile_page_identity_match",
                "confidence": 0.96, "safe_context_label": "Confirmed public profile identity",
                "generic_role": alias.casefold() in {"admin", "administrator", "moderator", "support", "staff", "root"}}]
    bound, safe_evidence = _locally_bound_evidence(evidence or [])
    aliases[0]["bound_identifiers"] = bound
    return storage.store_actor_observations(url, aliases, safe_evidence, policy)[0]


def _locally_bound_evidence(evidence):
    bound, safe = [], []
    for item in evidence:
        indicator_type = str(item.get("type") or "")
        normalized = str(item.get("normalized_value") or item.get("value") or "")
        if not indicator_type or not normalized:
            continue
        digest = hashlib.sha256(f"{indicator_type}:{normalized}".encode()).hexdigest()
        bound.append({"type": indicator_type, "value_hash": digest,
                      "confidence": float(item.get("confidence") or 0.9)})
        safe.append({"type": indicator_type, "normalized_value": f"local_sha256:{digest}",
                     "confidence": float(item.get("confidence") or 0.9)})
    return bound, safe


def _seller_policy(category="weapons_arms", flow="from_spain"):
    policy = _policy(True)
    policy["page_type"] = "vendor_page"
    policy["primary_category"] = category
    policy["category"] = category
    policy["spain_context_tags"] = {
        "from_spain": ["trade_flow_from_spain"],
        "to_spain": ["trade_flow_to_spain"],
        "both": ["trade_flow_from_spain", "trade_flow_to_spain"],
        "spain_context": [],
    }[flow]
    if category == "carding":
        policy["primary_category"] = policy["category"] = "marketplace_fraud"
        policy["secondary_categories"] = ["carding", "fullz"]
    return policy


def _store_seller(url, alias, category="weapons_arms", flow="from_spain", evidence=None):
    policy = _persist_verified_policy(url, _seller_policy(category, flow))
    storage.persist_spain_priority(url, policy)
    aliases = [{"alias": alias, "normalized_alias": alias.casefold(), "evidence_type": "seller_label",
                "confidence": 0.92, "safe_context_label": "Explicit public seller label",
                "generic_role": False}]
    bound, safe_evidence = _locally_bound_evidence(evidence or [])
    aliases[0]["bound_identifiers"] = bound
    return storage.store_actor_observations(url, aliases, safe_evidence, policy)[0]


def test_extracts_explicit_byline_handle_and_profile_aliases():
    url = f"http://{HOST_A}/member/Alice"
    aliases = extract_public_aliases(
        "Author: NightFox. Posted by SellerOne. Contact @PublicHandle user@example.org",
        [{"url": url, "anchor_text": "Alice", "section_context": "Members"}],
    )
    names = {item["normalized_alias"] for item in aliases}
    assert {"nightfox", "sellerone", "publichandle", "alice"} <= names
    assert "example" not in names


def test_same_alias_across_sites_is_low_confidence_without_corroboration(isolated_db):
    first = _store(f"http://{HOST_A}/thread/1", "NightFox")
    second = _store(f"http://{HOST_B}/thread/2", "NightFox")
    detail = storage.get_actor_detail(first)
    connection = next(item for item in detail["connections"] if item["other_actor_id"] == second)
    assert connection["confidence_score"] == 30
    assert connection["confidence_label"] == "low"
    assert json.loads(connection["evidence_json"])[0]["type"] == "same_alias"


def test_shared_public_pgp_raises_correspondence_confidence_without_storing_raw_key(isolated_db):
    raw = "-----BEGIN PGP PUBLIC KEY BLOCK----- SAMEPUBLICKEY -----END PGP PUBLIC KEY BLOCK-----"
    evidence = actor_identity_evidence(extract_indicators(raw))
    first = _store(f"http://{HOST_A}/thread/1", "NightFox", evidence)
    second = _store(f"http://{HOST_B}/thread/2", "OtherAlias", evidence)
    connection = next(item for item in storage.get_actor_detail(first)["connections"]
                      if item["other_actor_id"] == second)
    assert connection["confidence_score"] >= 90
    assert connection["confidence_label"] == "high"
    with storage.get_db() as db:
        stored = json.dumps([dict(row) for row in db.execute("SELECT * FROM actor_identifiers")])
    assert "SAMEPUBLICKEY" not in stored
    assert "Same public PGP fingerprint" in stored


def test_generic_role_alias_does_not_cross_link_by_name_alone(isolated_db):
    policy = _policy(True)
    for url in (f"http://{HOST_A}/thread/1", f"http://{HOST_B}/thread/2"):
        verified = _persist_verified_policy(url, policy)
        assert storage.store_actor_observations(url, [{
            "alias": "admin", "normalized_alias": "admin", "accepted": True,
            "evidence_version": 2, "role": "profile_owner",
            "evidence_type": "profile_page_identity_match", "confidence": 0.96,
            "generic_role": True,
        }], [], verified) == []
    assert storage.get_public_actors() == []


def test_watch_connection_review_and_observation_split_are_audited(isolated_db):
    first = _store(f"http://{HOST_A}/thread/1", "NightFox")
    _store(f"http://{HOST_B}/thread/2", "NightFox")
    detail = storage.get_actor_detail(first)
    assert storage.set_actor_watch(first, True, "Spain shipment monitoring")
    assert storage.set_actor_connection_decision(detail["connections"][0]["id"], "confirmed_same")
    assert storage.exclude_actor_observation(detail["observations"][0]["id"])
    with storage.get_db() as db:
        events = [row[0] for row in db.execute("SELECT event_type FROM actor_events ORDER BY id")]
    assert "watch_enabled" in events
    assert "connection_reviewed" in events


def test_watched_alias_gets_deduplicated_activity_and_correspondence_updates(isolated_db):
    first = _store(f"http://{HOST_A}/thread/1", "NightFox")
    storage.set_actor_watch(first, True, "Spain monitoring")
    _store(f"http://{HOST_A}/thread/2", "NightFox")
    _store(f"http://{HOST_B}/thread/3", "NightFox")
    alerts = storage.get_actor_watch_alerts()
    assert {item["alert_type"] for item in alerts} == {"new_activity", "possible_correspondence"}
    activity = next(item for item in alerts if item["alert_type"] == "new_activity")
    assert storage.acknowledge_actor_watch_alert(activity["id"])
    assert all(item["id"] != activity["id"] for item in storage.get_actor_watch_alerts())


def test_adult_policy_removes_alias_observation(isolated_db):
    url = f"http://{HOST_A}/thread/1"
    actor_id = _store(url, "NightFox")
    adult = {"primary_category": "adult_filtered", "storage_policy": "discard"}
    storage.store_actor_observations(url, [{"alias": "NightFox", "normalized_alias": "nightfox"}], [], adult)
    assert storage.get_actor_detail(actor_id) is None
    assert storage.get_spain_actors() == []


def test_worker_automatically_attaches_public_alias_to_exact_spain_page(isolated_db, monkeypatch):
    url = f"http://{HOST_A}/viewtopic.php?t=501"
    storage.insert_or_update_onion_url(url, HOST_A, status="queued", policy={"primary_category": "unknown"})
    body = """<html><title>Firearms vendor shipping to Spain</title><body>
      <h1>Weapons trafficking and firearms sale</h1>
      <p>Author: @NightFox. Shipping to Spain via Correos is available, Bizum accepted, Madrid delivery, DNI verification.</p></body></html>"""
    monkeypatch.setattr(onion_worker, "_session", lambda: _Session(body))
    monkeypatch.setattr(onion_worker, "capture_page_screenshot",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("screenshot attempted")))
    assert onion_worker.process_one()
    actors = storage.get_spain_actors()
    assert len(actors) == 1 and actors[0]["normalized_alias"] == "nightfox"
    observation = storage.get_actor_detail(actors[0]["id"])["observations"][0]
    assert observation["url"] == url
    assert observation["spain_priority"] == 1
    assert observation["spain_reason"]


def test_open_market_categories_reach_seller_shipping_from_spain_without_transaction_pages(isolated_db, monkeypatch):
    market = f"http://{HOST_A}/"
    category = f"http://{HOST_A}/category/general"
    vendor = f"http://{HOST_A}/vendor/IberiaFox"
    checkout = f"http://{HOST_A}/checkout"
    pages = {
        market: f"""<html><title>Example Marketplace</title><body><h1>Marketplace categories</h1>
          <a href='{category}'>General vendor listings</a><a href='{checkout}'>Checkout</a></body></html>""",
        category: f"""<html><title>Marketplace category</title><body><h1>Vendor listings</h1>
          <p>Public seller directory and product listings</p><a href='{vendor}'>Seller IberiaFox</a>
          <a href='{checkout}'>Checkout</a></body></html>""",
        vendor: """<html><title>IberiaFox weapons marketplace vendor</title><body><h1>IberiaFox seller profile</h1>
          <p>Seller: @IberiaFox</p><p>Weapons and firearms sale. Ships from Spain via Correos, Bizum accepted, Madrid pickup, DNI verification.</p></body></html>""",
    }
    storage.insert_or_update_onion_url(market, HOST_A, status="queued",
                                       policy=classify(market, visible_text="ordinary homepage"))
    monkeypatch.setattr(onion_worker, "_session", lambda: _MappingSession(pages))
    monkeypatch.setattr(onion_worker, "capture_page_screenshot",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("screenshot attempted")))
    assert onion_worker.process_one()
    assert storage.get_onion_url_by_url(category) is not None
    assert storage.get_onion_url_by_url(checkout) is None
    assert onion_worker.process_one()
    assert storage.get_onion_url_by_url(vendor) is not None
    assert storage.get_onion_url_by_url(checkout) is None
    assert onion_worker.process_one()
    actors = storage.get_spain_actors()
    seller = next(actor for actor in actors if actor["normalized_alias"] == "iberiafox")
    observation = storage.get_actor_detail(seller["id"])["observations"][0]
    assert observation["url"] == vendor
    assert observation["spain_priority"] == 1
    assert observation["spain_reason"]


def test_seller_shipping_direction_and_category_are_stored_per_exact_page(isolated_db):
    first = _store_seller(f"http://{HOST_A}/vendor/arms", "ArmsSeller", "weapons_arms", "from_spain")
    _store_seller(f"http://{HOST_A}/vendor/drugs", "DrugSeller", "drugs", "to_spain")
    _store_seller(f"http://{HOST_A}/vendor/cards", "CardSeller", "carding", "both")
    detail = storage.get_actor_detail(first)
    assert detail["observations"][0]["seller_observation"] == 1
    assert detail["observations"][0]["spain_flow"] == "from_spain"
    assert detail["observations"][0]["marketplace_category"] == "weapons_arms"
    categories = {row["marketplace_category"] for row in storage.get_spain_seller_categories()}
    assert {"weapons_arms", "drugs", "carding"} <= categories
    sellers = storage.get_spain_sellers()
    assert sellers[0]["normalized_alias"] == "armsseller"


def test_watched_seller_shipping_change_creates_event_and_alert(isolated_db):
    url = f"http://{HOST_A}/vendor/IberiaArms"
    actor_id = _store_seller(url, "IberiaArms", "weapons_arms", "from_spain")
    storage.set_actor_watch(actor_id, True, "Weapons shipping direction")
    policy = _persist_verified_policy(
        url, _seller_policy("weapons_arms", "to_spain"))
    aliases = [{"alias": "IberiaArms", "normalized_alias": "iberiaarms",
                "evidence_type": "seller_label", "confidence": 0.92,
                "safe_context_label": "Explicit public seller label", "generic_role": False}]
    storage.store_actor_observations(url, aliases, [], policy)
    detail = storage.get_actor_detail(actor_id)
    assert detail["observations"][0]["spain_flow"] == "to_spain"
    assert "shipping_changed" in {event["event_type"] for event in detail["events"]}
    assert "shipping_change" in {alert["alert_type"] for alert in storage.get_actor_watch_alerts()}


def test_same_alias_with_conflicting_public_pgp_is_copycat_warning_not_high_match(isolated_db):
    first_key = actor_identity_evidence(extract_indicators(
        "-----BEGIN PGP PUBLIC KEY BLOCK----- FIRSTPUBLICKEY -----END PGP PUBLIC KEY BLOCK-----"))
    second_key = actor_identity_evidence(extract_indicators(
        "-----BEGIN PGP PUBLIC KEY BLOCK----- SECONDPUBLICKEY -----END PGP PUBLIC KEY BLOCK-----"))
    first = _store_seller(f"http://{HOST_A}/vendor/NightFox", "NightFox", evidence=first_key)
    second = _store_seller(f"http://{HOST_B}/vendor/NightFox", "NightFox", evidence=second_key)
    connection = next(row for row in storage.get_actor_detail(first)["connections"]
                      if row["other_actor_id"] == second)
    assert connection["warning_type"] == "conflicting_public_identifiers"
    assert connection["migration_candidate"] == 0
    assert connection["confidence_label"] == "low"


def test_shared_public_signal_on_new_market_creates_migration_watch_update(isolated_db):
    raw = "-----BEGIN PGP PUBLIC KEY BLOCK----- MIGRATIONPUBLICKEY -----END PGP PUBLIC KEY BLOCK-----"
    evidence = actor_identity_evidence(extract_indicators(raw))
    first = _store_seller(f"http://{HOST_A}/vendor/IberiaArms", "IberiaArms", evidence=evidence)
    storage.set_actor_watch(first, True, "Watch public market moves")
    second = _store_seller(f"http://{HOST_B}/vendor/NewArmsAlias", "NewArmsAlias", evidence=evidence)
    connection = next(row for row in storage.get_actor_detail(first)["connections"]
                      if row["other_actor_id"] == second)
    assert connection["migration_candidate"] == 1
    assert connection["warning_type"] is None
    assert "market_migration" in {alert["alert_type"] for alert in storage.get_actor_watch_alerts()}


def test_adult_seller_is_not_added_to_seller_monitor(isolated_db):
    url = f"http://{HOST_A}/vendor/blocked"
    policy = _seller_policy("weapons_arms", "from_spain")
    policy.update({"primary_category": "adult_filtered", "storage_policy": "discard"})
    aliases = [{"alias": "BlockedSeller", "normalized_alias": "blockedseller",
                "evidence_type": "seller_label", "confidence": 0.9}]
    assert storage.store_actor_observations(url, aliases, [], policy) == []
    assert storage.get_spain_sellers() == []


def test_spain_actor_workspace_renders_watch_and_exact_evidence_controls(isolated_db):
    _store(f"http://{HOST_A}/viewtopic.php?t=44", "NightFox")
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value("Spain Priority").run()
    workspace = next(item for item in app.radio if item.label == "Spain workspace")
    workspace.set_value("Actors").run()
    assert not app.exception
    assert any("Spain alias watchlist" in str(item.value) for item in app.markdown)
    assert any("NightFox" in str(item.value) for item in app.markdown)
    assert any(item.label == "Watch this alias" for item in app.button)
    remove = next(item for item in app.button if item.label == "Remove page from this alias")
    assert remove.disabled


def test_spain_seller_workspace_renders_category_and_weapons_focus(isolated_db):
    _store_seller(f"http://{HOST_A}/vendor/IberiaArms", "IberiaArms", "weapons_arms", "from_spain")
    _store_seller(f"http://{HOST_A}/vendor/CardSeller", "CardSeller", "carding", "to_spain")
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value("Spain Priority").run()
    workspace = next(item for item in app.radio if item.label == "Spain workspace")
    workspace.set_value("Sellers").run()
    assert not app.exception
    assert any("Spain Seller Monitor" in str(item.value) for item in app.markdown)
    assert any("WEAPONS FOCUS" in str(item.value) for item in app.markdown)
    assert any(item.label == "Category" for item in app.selectbox)
    assert any(item.label == "Watch seller" for item in app.button)


def test_new_watch_update_appears_globally_and_opens_actor_workspace(isolated_db):
    actor_id = _store(f"http://{HOST_A}/thread/1", "NightFox")
    storage.set_actor_watch(actor_id, True, "Spain monitoring")
    _store(f"http://{HOST_A}/thread/2", "NightFox")
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    assert any("WATCHED ALIAS UPDATES" in str(item.value) for item in app.warning)
    button = next(item for item in app.button if item.label == "OPEN WATCHED ALIAS UPDATES")
    button.click().run()
    assert not app.exception
    workspace = next(item for item in app.radio if item.label == "Spain workspace")
    assert workspace.value == "Actors"
    assert any("Spain alias watchlist" in str(item.value) for item in app.markdown)
