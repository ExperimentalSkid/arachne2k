import json
from pathlib import Path

from streamlit.testing.v1 import AppTest

import actor_intelligence
import entity_extractor
import onion_worker
import storage


HOST_A = "a" * 56 + ".onion"
HOST_B = "b" * 56 + ".onion"
ROOT = Path(__file__).parents[1]


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


def test_actor_intelligence_stores_labelled_alias_without_duplicate_sightings(isolated_db):
    url = f"http://{HOST_A}/thread/1"
    storage.insert_or_update_onion_url(url, HOST_A, status="crawled", policy=_policy())
    text = "Author: @NightFox. Public discussion thread."
    first = actor_intelligence.process_page_actor_intelligence(
        url, visible_text=text, links=[], link_records=[], policy=_policy())
    second = actor_intelligence.process_page_actor_intelligence(
        url, visible_text=text, links=[], link_records=[], policy=_policy())
    assert first["actors"] == 1
    assert second["actors"] == 1
    actors = storage.get_public_actors()
    assert len(actors) == 1
    assert actors[0]["normalized_alias"] == "nightfox"
    detail = storage.get_actor_detail(actors[0]["id"])
    assert len(detail["observations"]) == 1


def test_single_flat_author_label_is_not_enough_to_create_actor(isolated_db):
    url = f"http://{HOST_A}/thread/weak"
    storage.insert_or_update_onion_url(url, HOST_A, status="crawled", policy=_policy())

    result = actor_intelligence.process_page_actor_intelligence(
        url, visible_text="Author: OrdinaryWord. Public discussion thread.",
        links=[], link_records=[], policy=_policy())

    assert result["actors"] == 0
    assert result["reason"] == "no_confirmed_public_alias"
    assert storage.get_public_actors() == []


def test_actor_intelligence_ignores_generic_unlabelled_text(isolated_db):
    url = f"http://{HOST_A}/about"
    storage.insert_or_update_onion_url(url, HOST_A, status="crawled", policy=_policy(page_type="homepage"))
    result = actor_intelligence.process_page_actor_intelligence(
        url, visible_text="Welcome to the forum. Contact and rules are public.",
        links=[], link_records=[], policy=_policy(page_type="homepage"))
    assert result["reason"] in {"not_actor_page", "no_public_alias", "no_confirmed_public_alias"}
    assert storage.get_public_actors() == []


def test_public_alias_extractor_rejects_navigation_provider_and_adjective_noise():
    text = """
    Seller: friendly
    Vendor: generated
    Author: supported
    Username: gmail
    Contact: protonmail
    Written by you
    """
    link_records = [
        {"url": "http://exampleaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/vendor/friendly",
         "anchor_text": "Friendly"},
        {"url": "http://exampleaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/profile/about",
         "anchor_text": "About"},
        {"url": "http://exampleaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/seller/agent",
         "anchor_text": "agent"},
        {"url": "http://exampleaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/member/AnonGun",
         "anchor_text": "AnonGun"},
        {"url": "http://exampleaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/vendor/trustcard",
         "anchor_text": "trustcard"},
    ]

    aliases = entity_extractor.extract_public_aliases(text, link_records)
    normalized = {item["normalized_alias"] for item in aliases}

    assert {"friendly", "generated", "supported", "gmail", "protonmail", "you",
            "about", "agent"} & normalized == set()
    assert {"anongun", "trustcard"} <= normalized


def test_public_alias_extractor_rejects_category_names_even_when_labelled():
    aliases = entity_extractor.extract_public_aliases(
        "Vendor: Weapons\nSeller: Drugs\nAuthor: Carding\nUsername: Credentials",
        [
            {"url": f"http://{HOST_A}/vendor/weapons", "anchor_text": "Weapons"},
            {"url": f"http://{HOST_A}/seller/drugs", "anchor_text": "Drugs"},
        ],
    )

    assert aliases == []
    assert entity_extractor.is_generic_public_alias("seller") is True
    assert entity_extractor.is_generic_public_alias("vendor") is True


def test_actor_intelligence_does_not_store_generic_seller_words(isolated_db):
    url = f"http://{HOST_A}/seller/noisy"
    policy = _policy(primary_category="marketplace_fraud", page_type="vendor_page")
    storage.insert_or_update_onion_url(url, HOST_A, status="crawled", policy=policy)
    result = actor_intelligence.process_page_actor_intelligence(
        url,
        visible_text="Seller: friendly\nVendor: generated\nUsername: proton\nAuthor: About",
        links=[],
        link_records=[
            {"url": f"http://{HOST_A}/vendor/friendly", "anchor_text": "friendly"},
            {"url": f"http://{HOST_A}/seller/gmail", "anchor_text": "gmail"},
        ],
        policy=policy,
    )
    assert result["aliases"] == 0
    assert storage.get_public_actors() == []


def test_structural_actor_evidence_rejects_marketplace_text_false_positives():
    base = f"http://{HOST_A}/"
    html = """
    <html><body>
      <h1>Cards market</h1>
      <p>Seller: Formulas</p>
      <p>Vendor: CREDITCARDCENTER. Since 2020 we operate safely.</p>
      <nav><a href="/vendor/charlie">BigBuyCardsFastPaypal</a></nav>
      <section class="docs">
        <a href="/profile/firewall">FirewallGlossaryTemplates</a>
      </section>
    </body></html>
    """
    _title, _meta, _text, _records, structure = onion_worker._parse(html.encode(), "text/html", base)

    assert structure["actor_evidence"] == []


def test_structural_actor_evidence_accepts_phpbb_author_and_vendor_card(isolated_db):
    forum_url = f"http://{HOST_A}/viewtopic.php?t=1"
    forum_html = """
    <html><body>
      <div class="post has-profile">
        <dl class="postprofile">
          <dt><a class="username" href="/memberlist.php?mode=viewprofile&u=17">Alice77</a></dt>
        </dl>
        <div class="postbody">hello</div>
      </div>
    </body></html>
    """
    _title, _meta, text, records, structure = onion_worker._parse(forum_html.encode(), "text/html", forum_url)
    evidence = structure["actor_evidence"]
    assert evidence and evidence[0]["normalized_alias"] == "alice77"
    assert evidence[0]["engine_hint"] == "phpbb"
    assert evidence[0]["seller_evidence"] is False

    policy = _policy(page_type="thread_page")
    storage.insert_or_update_onion_url(forum_url, HOST_A, status="crawled", policy=policy)
    result = actor_intelligence.process_page_actor_intelligence(
        forum_url, visible_text=text, links=[r["url"] for r in records],
        link_records=records, policy=policy, page_structure=structure)
    assert result["actors"] == 1
    actor = storage.get_public_actors()[0]
    detail = storage.get_actor_detail(actor["id"])
    assert detail["observations"][0]["seller_observation"] == 0

    vendor_url = f"http://{HOST_A}/vendors"
    vendor_html = """
    <html><body>
      <article class="vendor-card">
        <span>Vendor:</span> <a href="/vendor/apple_max">APPLE_MAX</a>
      </article>
      <article class="product-card">
        <a href="/vendor/charlie">BigBuyCardsFastPaypal</a>
      </article>
    </body></html>
    """
    _title, _meta, text, records, structure = onion_worker._parse(vendor_html.encode(), "text/html", vendor_url)
    accepted = {item["normalized_alias"]: item for item in structure["actor_evidence"]}
    assert "apple_max" in accepted
    assert accepted["apple_max"]["seller_evidence"] is True
    assert "bigbuycardsfastpaypal" not in accepted


def test_cleanup_public_alias_noise_removes_old_bad_aliases_only(isolated_db):
    now = "2026-07-11T12:00:00Z"
    with storage.get_db() as db:
        for alias in ("friendly", "gmail", "About", "AnonGun", "trustcard"):
            db.execute(
                """INSERT INTO actors(normalized_alias,display_alias,onion_host,first_seen,last_seen)
                   VALUES(?,?,?,?,?)""",
                (alias.casefold(), alias, HOST_A, now, now),
            )
        noisy_id = int(db.execute(
            "SELECT id FROM actors WHERE normalized_alias='gmail'").fetchone()[0])
        db.execute("""INSERT INTO actor_aliases
          (actor_id,normalized_alias,display_alias,first_seen,last_seen,observation_count)
          VALUES(?,?,?,?,?,1)""", (noisy_id, "gmail", "gmail", now, now))
        job_id = int(db.execute("""INSERT INTO deep_discovery_jobs
          (actor_id,site_card_id,status,anchor_snapshot_json,created_at,updated_at)
          VALUES(?,0,'done','{}',?,?) RETURNING id""", (noisy_id, now, now)).fetchone()[0])
        db.execute("""INSERT INTO deep_discovery_runs
          (job_id,actor_id,site_card_id,anchor_snapshot_json,created_at)
          VALUES(?,?,0,'{}',?)""", (job_id, noisy_id, now))
        db.commit()

    dry = actor_intelligence.cleanup_public_alias_noise(dry_run=True)
    assert dry["removed"] == 0
    assert dry["noisy_aliases"] == 3
    assert dry["removable"] == 3
    assert "sample" not in dry
    assert dry["reason_counts"] == {
        "noise_generic_or_navigation": 2,
        "noise_provider_word": 1,
    }

    applied = actor_intelligence.cleanup_public_alias_noise(dry_run=False)
    assert applied["removed"] == 3
    with storage.get_db() as db:
        aliases = {row["normalized_alias"] for row in db.execute("SELECT normalized_alias FROM actors")}
        assert db.execute("SELECT COUNT(*) FROM actor_aliases").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM deep_discovery_jobs").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM deep_discovery_runs").fetchone()[0] == 0
        assert list(db.execute("PRAGMA foreign_key_check")) == []
    assert aliases == {"anongun", "trustcard"}


def test_cleanup_cli_output_is_aggregate_only(isolated_db, monkeypatch, capsys):
    now = "2026-07-11T12:00:00Z"
    seeded_aliases = ("gmail", "profile")
    with storage.get_db() as db:
        for alias in seeded_aliases:
            db.execute(
                """INSERT INTO actors(normalized_alias,display_alias,onion_host,first_seen,last_seen)
                   VALUES(?,?,?,?,?)""",
                (alias.casefold(), alias, HOST_A, now, now),
            )
        db.commit()

    monkeypatch.setattr(
        "sys.argv", ["actor_intelligence.py", "--cleanup-noise", "--dry-run"])
    actor_intelligence.main()
    output = capsys.readouterr().out

    assert '"noisy_aliases": 2' in output
    assert '"reason_counts"' in output
    assert "gmail" not in output.casefold()
    assert "profile" not in output.casefold()
    assert HOST_A not in output


def test_public_alias_quality_tools_scan_only_after_explicit_action(
        isolated_db, monkeypatch):
    now = "2026-07-11T12:00:00Z"
    with storage.get_db() as db:
        for alias in ("friendly", "gmail", "AnonGun"):
            db.execute(
                """INSERT INTO actors(normalized_alias,display_alias,onion_host,first_seen,last_seen)
                   VALUES(?,?,?,?,?)""",
                (alias.casefold(), alias, HOST_A, now, now),
            )
        db.commit()

    real_cleanup = actor_intelligence.cleanup_public_alias_noise
    calls = []

    def tracked_cleanup(*, dry_run=True):
        calls.append(dry_run)
        return real_cleanup(dry_run=dry_run)

    monkeypatch.setattr(
        actor_intelligence, "cleanup_public_alias_noise", tracked_cleanup)
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20).run()
    app.sidebar.radio[0].set_value("Actors").run()

    assert not app.exception
    assert calls == []
    assert any("Alias quality tools" in str(item.label) for item in app.expander)
    assert not any("Noisy aliases found" in str(item.label) for item in app.metric)
    scan = next(item for item in app.button if item.key == "alias-quality-scan")
    scan.click().run()

    assert not app.exception
    assert calls == [True]
    assert any("Noisy aliases found" in str(item.label) for item in app.metric)
    assert any(item.label == "Remove noisy aliases" and item.disabled for item in app.button)


def test_public_alias_workspace_body_and_controls_are_spanish(isolated_db):
    now = "2026-07-11T12:00:00Z"
    with storage.get_db() as db:
        db.execute(
            """INSERT INTO actors(
                 normalized_alias,display_alias,onion_host,primary_category,watched,
                 observation_count,first_seen,last_seen
               ) VALUES(?,?,?,?,?,?,?,?)""",
            ("nightfox", "NightFox", HOST_A, "forum_social", 1, 1, now, now),
        )
        db.commit()

    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=20)
    app.query_params["nav"] = "actors"
    app.session_state["ui_spanish"] = True
    app.run()

    assert not app.exception
    body = " ".join(str(item.value) for item in [*app.markdown, *app.caption])
    labels = [str(item.label) for collection in (
        app.text_input, app.checkbox, app.selectbox, app.metric, app.expander, app.button
    ) for item in collection]
    assert "Perfiles de alias públicos" in body
    assert "Identidades observadas" in body
    assert "Buscar nombres de usuario" in labels
    assert "Solo en seguimiento" in labels
    assert "Fichas de alias" in labels
    assert "Herramientas de calidad de alias" in labels
    assert "Ejecutar análisis conservador" in labels
    assert [str(item.label) for item in app.tabs] == [
        "Perfil y alias",
        "Páginas observadas",
        "Coincidencias posibles",
        "Tipos de señales públicas",
        "Eventos cronológicos",
    ]


def test_page_global_pgp_does_not_promote_one_flat_alias(isolated_db):
    key = "-----BEGIN PGP PUBLIC KEY BLOCK----- SHAREDKEYMATERIAL -----END PGP PUBLIC KEY BLOCK-----"
    url = f"http://{HOST_A}/thread/1"
    storage.insert_or_update_onion_url(url, HOST_A, status="crawled", policy=_policy())

    result = actor_intelligence.process_page_actor_intelligence(
        url, visible_text=f"Author: NightFox. {key}", links=[], link_records=[], policy=_policy())

    assert result["aliases"] == 0
    assert storage.get_public_actors() == []


def test_shared_locally_bound_public_pgp_correlates_without_raw_value(isolated_db):
    key = "-----BEGIN PGP PUBLIC KEY BLOCK----- SHAREDKEYMATERIAL -----END PGP PUBLIC KEY BLOCK-----"
    first = f"http://{HOST_A}/viewtopic.php?t=1"
    second = f"http://{HOST_B}/viewtopic.php?t=2"
    for url, host, alias, member_id in [
        (first, HOST_A, "NightFox", 17),
        (second, HOST_B, "OtherFox", 28),
    ]:
        html = f"""
        <div class="post"><dl class="postprofile">
          <a href="/memberlist.php?mode=viewprofile&u={member_id}">{alias}</a>
          <pre>{key}</pre>
        </dl><div class="postbody">Public message</div></div>
        """
        _title, _meta, text, records, structure = onion_worker._parse(
            html.encode(), "text/html", url)
        assert "SHAREDKEYMATERIAL" not in json.dumps(structure)
        assert structure["actor_evidence"][0]["bound_identifiers"][0]["type"] == "pgp_key_block"
        storage.insert_or_update_onion_url(url, host, status="crawled", policy=_policy())
        actor_intelligence.process_page_actor_intelligence(
            url, visible_text=text, links=[record["url"] for record in records],
            link_records=records, policy=_policy(), page_structure=structure)
    actors = storage.get_public_actors()
    assert len(actors) == 2
    detail = storage.get_actor_detail(actors[0]["id"])
    assert detail["connections"][0]["confidence_label"] == "high"
    with storage.get_db() as db:
        stored = json.dumps([dict(row) for row in db.execute("SELECT * FROM actor_identifiers")])
    assert "SHAREDKEYMATERIAL" not in stored
    assert "Same public PGP fingerprint" in stored


def test_structural_digit_leading_handle_is_allowed_but_flat_is_not():
    url = f"http://{HOST_A}/thread/1"
    html = """
    <div class="post"><span component="post/username" data-username="4Runner"></span></div>
    <div class="post"><span component="post/username" data-username="MørkUlv"></span></div>
    """
    _title, _meta, _text, _records, structure = onion_worker._parse(
        html.encode(), "text/html", url)
    assert {item["normalized_alias"] for item in structure["actor_evidence"]} == {"4runner", "mørkulv"}

    flat = entity_extractor.extract_public_aliases("Author: 4Runner", [])
    assert flat == []


def test_structural_and_independently_eligible_flat_aliases_are_merged(isolated_db):
    url = f"http://{HOST_A}/viewtopic.php?t=7"
    html = """
    <div class="post"><dl class="postprofile">
      <a href="/memberlist.php?mode=viewprofile&u=17">Alice77</a>
    </dl><div class="postbody">Author: @Bob99</div></div>
    """
    _title, _meta, text, records, structure = onion_worker._parse(
        html.encode(), "text/html", url)
    storage.insert_or_update_onion_url(url, HOST_A, status="crawled", policy=_policy())

    result = actor_intelligence.process_page_actor_intelligence(
        url, visible_text=text, links=[record["url"] for record in records],
        link_records=records, policy=_policy(), page_structure=structure)

    assert result["actors"] == 2
    assert {row["normalized_alias"] for row in storage.get_public_actors()} == {"alice77", "bob99"}


def test_identifiers_bind_only_to_their_local_structural_actor(isolated_db):
    url = f"http://{HOST_A}/viewtopic.php?t=8"
    html = """
    <div class="post"><dl class="postprofile">
      <a href="/memberlist.php?mode=viewprofile&u=17">Alice77</a>
      <span>alice-contact@example.org</span>
    </dl></div>
    <div class="post"><dl class="postprofile">
      <a href="/memberlist.php?mode=viewprofile&u=28">Bob88</a>
      <span>bob-contact@example.org</span>
    </dl></div>
    <footer>global-contact@example.org</footer>
    """
    _title, _meta, text, records, structure = onion_worker._parse(
        html.encode(), "text/html", url)
    serialized = json.dumps(structure)
    assert "alice-contact" not in serialized
    assert "bob-contact" not in serialized
    assert "global-contact" not in serialized
    storage.insert_or_update_onion_url(url, HOST_A, status="crawled", policy=_policy())

    result = actor_intelligence.process_page_actor_intelligence(
        url, visible_text=text, links=[record["url"] for record in records],
        link_records=records, policy=_policy(), page_structure=structure)

    assert result["actors"] == 2
    with storage.get_db() as db:
        counts = {row["normalized_alias"]: row["identifier_count"] for row in db.execute("""
          SELECT a.normalized_alias,COUNT(ai.id) identifier_count
          FROM actors a LEFT JOIN actor_identifiers ai ON ai.actor_id=a.id
          GROUP BY a.id,a.normalized_alias
        """)}
        stored = json.dumps([dict(row) for row in db.execute("SELECT * FROM actor_identifiers")])
    assert counts == {"alice77": 1, "bob88": 1}
    assert "alice-contact" not in stored and "bob-contact" not in stored and "global-contact" not in stored


def test_same_username_distinct_numeric_profiles_create_distinct_cards(isolated_db):
    urls = (f"http://{HOST_A}/thread/17", f"http://{HOST_A}/thread/18")
    profile_urls = (f"http://{HOST_A}/memberlist.php?mode=viewprofile&u=17",
                    f"http://{HOST_A}/memberlist.php?mode=viewprofile&u=18")
    actor_ids = []
    for url, profile_url in zip(urls, profile_urls, strict=True):
        storage.insert_or_update_onion_url(url, HOST_A, status="crawled", policy=_policy())
        actor_ids.extend(storage.store_actor_observations(url, [{
            "alias": "NightFox", "normalized_alias": "nightfox", "role": "post_author",
            "evidence_type": "phpbb_post_author", "evidence_version": 2,
            "evidence_strength": "strong", "confidence": 0.98,
            "profile_url": profile_url, "source_scope": "post_author",
        }], [], _policy()))
    assert len(set(actor_ids)) == 2
    cards = storage.get_public_actors()
    assert len(cards) == 2
    assert {card["display_alias"] for card in cards} == {"NightFox"}
    assert len({card["identity_key"] for card in cards}) == 2


def test_one_profile_across_pages_stays_one_username_card(isolated_db):
    profile_url = f"http://{HOST_A}/memberlist.php?mode=viewprofile&u=17"
    actor_ids = []
    for suffix in ("first", "second", "third"):
        url = f"http://{HOST_A}/thread/{suffix}"
        storage.insert_or_update_onion_url(url, HOST_A, status="crawled", policy=_policy())
        actor_ids.extend(storage.store_actor_observations(url, [{
            "alias": "NightFox", "normalized_alias": "nightfox", "role": "post_author",
            "evidence_type": "phpbb_post_author", "evidence_version": 2,
            "evidence_strength": "strong", "confidence": 0.98,
            "profile_url": profile_url, "source_scope": "post_author",
        }], [], _policy()))
    assert len(set(actor_ids)) == 1
    detail = storage.get_actor_detail(actor_ids[0])
    assert len(detail["observations"]) == 3


def test_restricted_policy_removes_actor_observation(isolated_db):
    url = f"http://{HOST_A}/thread/1"
    storage.insert_or_update_onion_url(url, HOST_A, status="crawled", policy=_policy())
    actor_intelligence.process_page_actor_intelligence(
        url, visible_text="Author: @NightFox", links=[], link_records=[], policy=_policy())
    assert storage.get_public_actors()
    actor_intelligence.process_page_actor_intelligence(
        url, visible_text="Author: NightFox", links=[], link_records=[],
        policy=_policy(primary_category="adult_filtered", storage_policy="discard"))
    assert storage.get_public_actors() == []


def test_actor_backfill_dry_run_does_not_mutate(isolated_db):
    url = f"http://{HOST_A}/thread/1"
    url_id = storage.insert_or_update_onion_url(
        url, HOST_A, status="classification_pending", policy=_policy())
    snapshot_id = storage.store_fetched_page_snapshot(
        url_id, url, worker_id="test", response_status=200, content_type="text/html",
        headers={}, title="Thread", meta_text="", visible_text="Author: @NightFox",
        link_records=[], page_structure={
            "content_boundary": {
                "version": 1,
                "outbound_anchor_text_removed": True,
            },
        }, pre_policy={})
    storage.mark_fetched_page_verified(snapshot_id)
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET primary_category='forum_social',
          category='forum_social',page_type='forum_thread',verification_state='verified',
          classification_evidence_source='destination_html',
          destination_html_evidence_version=1 WHERE id=?""", (url_id,))
    result = actor_intelligence.backfill_actor_intelligence(batch_size=10, dry_run=True)
    assert result["aliases"] == 1
    assert storage.get_public_actors() == []


def test_actor_backfill_skips_untrusted_url_and_legacy_anchor_snapshot_without_mutation(
        isolated_db):
    accepted_alias = {
        "alias": "LegacyFox",
        "normalized_alias": "legacyfox",
        "accepted": True,
        "role": "post_author",
        "evidence_type": "phpbb_post_author",
        "evidence_version": 2,
        "evidence_strength": "strong",
        "confidence": 0.99,
    }
    current_structure = {
        "content_boundary": {
            "version": 1,
            "outbound_anchor_text_removed": True,
        },
        "actor_evidence": [accepted_alias],
    }
    legacy_structure = {"actor_evidence": [accepted_alias]}
    urls = [
        f"http://{HOST_A}/thread/untrusted-url",
        f"http://{HOST_A}/thread/legacy-snapshot",
    ]
    structures = [current_structure, legacy_structure]
    url_ids = []
    for url, structure in zip(urls, structures):
        url_id = storage.insert_or_update_onion_url(
            url, HOST_A, status="classification_pending", policy=_policy())
        snapshot_id = storage.store_fetched_page_snapshot(
            url_id, url, worker_id="test", response_status=200,
            content_type="text/html", headers={}, title="Legacy forum thread",
            meta_text="", visible_text="Author: @LegacyFox",
            link_records=[{
                "url": f"http://{HOST_B}/profile/legacyfox",
                "anchor_text": "Seller: @LegacyFox",
            }], page_structure=structure, pre_policy={})
        storage.mark_fetched_page_verified(snapshot_id)
        url_ids.append(url_id)

    # The first snapshot has the current parser boundary but no trusted URL-row
    # provenance.  The second has forged/current URL-row provenance but is a
    # legacy snapshot whose visible text and link record can contain anchors.
    with storage.get_db() as db:
        db.execute("""UPDATE onion_urls SET primary_category='forum_social',
          category='forum_social',verification_state='verified',
          classification_evidence_source='destination_html',
          destination_html_evidence_version=1 WHERE id=?""", (url_ids[1],))
        before = [tuple(row) for row in db.execute("""SELECT url,visible_text,
          link_records_json,page_structure_json,classification_status
          FROM fetched_pages ORDER BY onion_url_id""")]

    result = actor_intelligence.backfill_actor_intelligence(batch_size=10, dry_run=False)

    with storage.get_db() as db:
        after = [tuple(row) for row in db.execute("""SELECT url,visible_text,
          link_records_json,page_structure_json,classification_status
          FROM fetched_pages ORDER BY onion_url_id""")]
        assert db.execute("SELECT COUNT(*) FROM actor_observations").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM deep_discovery_jobs").fetchone()[0] == 0
    assert result == {"scanned": 1, "eligible": 0, "aliases": 0,
                      "actors": 0, "dry_run": False}
    assert after == before
    assert storage.get_public_actors() == []
