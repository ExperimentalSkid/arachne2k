import base64
import hashlib
from pathlib import Path

from streamlit.testing.v1 import AppTest

import site_dedupe
import storage
from dashboard_pages import workspace


ROOT = Path(__file__).parents[1]


def _insert_card(
    canonical_id: str,
    name: str,
    *,
    review_status: str = "needs_review",
    urgent: bool = False,
    spain: bool = False,
    updated_at: str = "2026-07-28T10:00:00Z",
) -> int:
    host = (
        base64.b32encode(hashlib.sha256(canonical_id.encode("utf-8")).digest())
        .decode("ascii")
        .lower()
        .rstrip("=")
        + "aaaa"
    )
    url = f"http://{host}.onion/"
    policy = {
        "primary_category": "directory_index",
        "category": "directory_index",
        "content_category": "directory_index",
        "analyst_category": "directory_index",
        "classification_evidence_source": "analyst",
        "tags": ["directory_index"],
        "risk_level": "high" if urgent else "low",
        "confidence": "high",
        "risk_flags": [],
        "storage_policy": "safe_summary",
        "review_status": review_status,
        "safety_reason": "directory_index",
        "priority_score": 80 if urgent else 20,
        "screenshot_policy": "allowed",
        "queue_policy": "expand",
        "active": 1,
        "spain_priority": spain,
        "spain_match_reason": "Spain-specific synthetic evidence" if spain else None,
    }
    url_id = storage.insert_or_update_onion_url(
        url,
        f"{host}.onion",
        status="crawled",
    )
    with storage.get_db() as db:
        db.execute(
            """UPDATE onion_urls
               SET analyst_category='directory_index',safe_display_name=?,
                   detected_title=?,review_status=?,verification_state='verified',
                   active=1,spain_priority=?,spain_review_status='unreviewed'
               WHERE id=?""",
            (name, name, review_status, int(spain), url_id),
        )
    storage.apply_onion_policy(url, policy)
    card_id = site_dedupe.ensure_url_site_card(
        url_id,
        policy,
        title=name,
        visible_text="safe directory structure",
    )
    with storage.get_db() as db:
        db.execute(
            """UPDATE site_cards
               SET display_name=?,review_status=?,report_status=?,
                   first_seen=?,created_at=?,updated_at=?,live_url_count=1,
                   ui_hidden_default=0,urgent_flag=?,urgent_score=?,
                   review_score=?,ui_priority=?,spain_priority=?,
                   spain_match_reason=?
               WHERE id=?""",
            (
                name,
                review_status,
                "requested" if review_status == "needs_report" else "not_prepared",
                updated_at,
                updated_at,
                updated_at,
                int(urgent),
                90 if urgent else 20,
                80 if urgent else 40,
                80 if urgent else 40,
                int(spain),
                "Spain-specific synthetic evidence" if spain else None,
                card_id,
            ),
        )
    return int(card_id)


def _dashboard(page: str) -> AppTest:
    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=30)
    app.query_params["nav"] = page
    app.run()
    assert not app.exception
    return app


def test_review_inbox_has_decision_lanes_and_filters_them(isolated_db):
    _insert_card("host:urgent", "Urgent evidence", urgent=True)
    _insert_card("host:report", "Report requested", review_status="needs_report")

    app = _dashboard("review")
    focus = next(item for item in app.radio if item.label == "Review focus")
    assert focus.options == ["All actionable", "Urgent", "Decision needed", "Report needed"]

    focus.set_value("Report needed").run()
    assert not app.exception
    rendered = " ".join(str(item.value) for item in app.markdown)
    assert "Report requested" in rendered
    assert "Urgent evidence" not in rendered


def test_review_age_filter_is_sql_backed(isolated_db):
    recent_id = _insert_card(
        "host:recent",
        "Recent card",
        updated_at=storage.utc_now_iso(),
    )
    old_id = _insert_card(
        "host:old",
        "Old card",
        updated_at="2020-01-01T00:00:00Z",
    )

    recent = site_dedupe.get_site_card_summaries(
        review_only=True,
        age_filter="New 24h",
    )
    old = site_dedupe.get_site_card_summaries(
        review_only=True,
        age_filter="Older than 7 days",
    )

    assert {row["id"] for row in recent} == {recent_id}
    assert {row["id"] for row in old} == {old_id}


def test_crawl_queue_counts_and_pages_beyond_one_thousand_rows(isolated_db):
    now = storage.utc_now_iso()
    host = "q" * 56 + ".onion"
    with storage.get_db() as db:
        db.executemany(
            """INSERT INTO onion_urls(
                 url,onion_domain,status,first_seen,
                 primary_category,storage_policy,risk_flags
               ) VALUES(?,?,?,?,?,?,?)""",
            [
                (
                    f"http://{host}/page-{index}",
                    host,
                    "queued",
                    now,
                    "unknown",
                    "safe_summary",
                    "[]",
                )
                for index in range(1005)
            ],
        )

    app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=30)
    app.query_params["nav"] = "queue"
    app.session_state["queue-page"] = 41
    app.run()

    assert not app.exception
    captions = " ".join(str(item.value) for item in app.caption)
    assert "1001–1005 of 1005 matching URLs" in captions
    rows = [item for item in app.markdown if '<div class="rt-queue-row ' in str(item.value)]
    assert len(rows) == 5


def test_crawl_queue_uses_the_attached_card_name_instead_of_unnamed(isolated_db):
    _insert_card("host:queue-name", "Atlas source directory")

    app = _dashboard("queue")
    rendered = " ".join(str(item.value) for item in app.markdown)

    assert "Atlas source directory" in rendered
    assert "Unnamed site" not in rendered


def test_spain_workspace_surfaces_card_level_leads_without_fake_exact_pages(isolated_db):
    _insert_card("host:spain-card-level", "Spain card lead", spain=True, urgent=True)

    app = _dashboard("spain")
    rendered = " ".join(str(item.value) for item in app.markdown)

    assert "Pages to check" in rendered
    assert "Card-level leads" in rendered
    assert "Spain card lead" in rendered
    assert "Older Spain Site Cards awaiting case migration" not in rendered
    assert any(item.label == "Open card" for item in app.button)


def test_every_workspace_route_renders_against_a_fresh_database(isolated_db):
    failures = {}
    for page, slug in workspace.PAGE_SLUGS.items():
        app = AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=30)
        app.query_params["nav"] = slug
        app.run()
        if app.exception:
            failures[page] = [str(item.value) for item in app.exception]

    assert failures == {}
