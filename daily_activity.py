"""Safe daily operational digest for the dashboard and optional Telegram delivery."""
from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
import json
from zoneinfo import ZoneInfo

import storage


MADRID = ZoneInfo("Europe/Madrid")


def _bounds(day: date) -> tuple[str, str]:
    start = datetime.combine(day, time.min, MADRID).astimezone(timezone.utc)
    end = (datetime.combine(day, time.min, MADRID) + timedelta(days=1)).astimezone(timezone.utc)
    return (start.isoformat().replace("+00:00", "Z"), end.isoformat().replace("+00:00", "Z"))


def build_daily_digest(day: date | None = None) -> dict:
    selected = day or datetime.now(MADRID).date()
    start, end = _bounds(selected)
    with storage.get_db() as db:
        scalar = lambda sql, params=(start, end): int(db.execute(sql, params).fetchone()[0])
        payload = {
            "date": selected.isoformat(), "timezone": "Europe/Madrid",
            # Staged workers finish a page at verification.  Keep the legacy
            # fetch/completed outcome for old rows, and de-duplicate URLs so a
            # deployment spanning both pipelines cannot count one page twice.
            "pages_completed": scalar("""SELECT COUNT(DISTINCT url) FROM crawl_audit_log
              WHERE ts>=? AND ts<? AND ((action='verify' AND outcome='completed')
                OR (action='fetch' AND outcome='completed'))"""),
            "new_urls": scalar("SELECT COUNT(*) FROM onion_urls WHERE first_seen>=? AND first_seen<?"),
            "new_site_cards": scalar("SELECT COUNT(*) FROM site_cards WHERE created_at>=? AND created_at<?"),
            "meaningful_changes": scalar("""SELECT COUNT(*) FROM page_change_events
              WHERE detected_at>=? AND detected_at<? AND meaningful=1"""),
            "spain_alerts": scalar("SELECT COUNT(*) FROM spain_alert_queue WHERE created_at>=? AND created_at<?"),
            "blocked_before_fetch": scalar("""SELECT COUNT(*) FROM crawl_audit_log
              WHERE ts>=? AND ts<? AND action='decide_rule' AND outcome IN ('reject','restrict')"""),
            "fetch_errors": scalar("""SELECT COUNT(*) FROM crawl_audit_log
              WHERE ts>=? AND ts<? AND action='fetch' AND outcome='error'"""),
            "reports_created": scalar("SELECT COUNT(*) FROM evidence_reports WHERE ts>=? AND ts<?"),
            "analyst_actions": scalar("SELECT COUNT(*) FROM site_card_events WHERE created_at>=? AND created_at<?"),
            "queue_remaining": scalar("""SELECT COUNT(*) FROM onion_urls
              WHERE active=1 AND status IN ('new','queued','retry')""", ()),
        }
        payload["recent_actions"] = [dict(row) for row in db.execute("""SELECT ts,action,outcome,safe_reason
          FROM crawl_audit_log WHERE ts>=? AND ts<? ORDER BY id DESC LIMIT 20""", (start, end))]
    quality = storage.get_classification_quality_report(days=30)
    payload["classification_quality"] = {
        "window_days": 30,
        "unique_pages": int(quality.get("unique_pages") or 0),
        "unknown_rate": float(quality.get("unknown_rate") or 0),
        "reviewed_count": int(quality.get("reviewed_count") or 0),
        "category_corrections": int(quality.get("category_corrections") or 0),
        "correction_rate": float(quality.get("correction_rate") or 0),
        "safety_excluded": int(quality.get("safety_excluded") or 0),
        "shadow_observations": len(quality.get("shadow_candidates") or []),
    }
    return payload


def snapshot_previous_day() -> dict:
    day = datetime.now(MADRID).date() - timedelta(days=1)
    payload = build_daily_digest(day)
    prefs = storage.notification_preferences()
    storage.store_daily_digest(day.isoformat(), payload,
                               telegram_pending=bool(prefs.get("daily_digest_telegram")))
    storage.store_classification_quality_daily(
        day.isoformat(), "all_classifiers",
        payload.get("classification_quality") or {},
    )
    return payload


def format_digest(payload: dict) -> str:
    quality = payload.get("classification_quality")
    if not isinstance(quality, dict):
        quality = {}
    return "\n".join([
        f"ARACHNE DAILY ACTIVITY · {payload.get('date')}",
        f"Pages completed: {int(payload.get('pages_completed') or 0)}",
        f"New URLs: {int(payload.get('new_urls') or 0)}",
        f"New Site Cards: {int(payload.get('new_site_cards') or 0)}",
        f"Meaningful changes: {int(payload.get('meaningful_changes') or 0)}",
        f"Spain alerts: {int(payload.get('spain_alerts') or 0)}",
        f"Blocked safely: {int(payload.get('blocked_before_fetch') or 0)}",
        f"Fetch errors: {int(payload.get('fetch_errors') or 0)}",
        f"Reports created: {int(payload.get('reports_created') or 0)}",
        f"Queue remaining: {int(payload.get('queue_remaining') or 0)}",
        f"Classification unknown (30d): {round(float(quality.get('unknown_rate') or 0) * 100)}%",
        f"Category corrections (30d): {int(quality.get('category_corrections') or 0)}"
        f" / {int(quality.get('reviewed_count') or 0)} reviewed",
        f"Advisory observations (30d): {int(quality.get('shadow_observations') or 0)}",
    ])


def payload_from_row(row: dict) -> dict:
    try:
        value = json.loads(row.get("payload_json") or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}
