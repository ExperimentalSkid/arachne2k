"""Safe Spain-priority Telegram alert formatting. Never includes page content."""
from __future__ import annotations

import json
import os

from universal_classifier import safe_category_label


def format_spain_alert(payload: dict) -> str:
    card_updated = payload.get("alert_kind") == "updated"
    lines = [
        "🇪🇸 SPAIN PRIORITY CARD UPDATED" if card_updated else "🇪🇸 SPAIN PRIORITY ALERT", "",
        f"Category: {safe_category_label(payload.get('category'))}",
        f"Risk: {str(payload.get('risk_level') or 'unknown').upper()}",
        f"Importance: {str(payload.get('importance_level') or 'normal').upper()}",
        f"Site Card: {payload.get('canonical_site_id') or 'Pending assignment'}",
        f"Mirrors: {payload.get('mirror_count', 0)}",
        f"Language: {payload.get('language') or 'UNKNOWN'}",
        f"Reason: {payload.get('reason') or 'Spain-related priority context'}",
        f"URL: {payload.get('url') or 'Unavailable'}",
        f"Source: {payload.get('source_url') or 'Manual or unavailable'}",
    ]
    if payload.get("restricted") or payload.get("category") in {"marketplace_fraud", "fraud_financial"}:
        lines.extend(["", "Restricted metadata-only item. No preview/snippet/screenshot stored."])
    dashboard_url = str(payload.get("dashboard_url") or os.getenv("DASHBOARD_URL") or "").strip().rstrip("/")
    if dashboard_url:
        separator = "&" if "?" in dashboard_url else "?"
        lines.extend(["", f"Open dashboard → Spain Priority: {dashboard_url}{separator}view=spain"])
    else:
        lines.extend(["", "Open dashboard → Spain Priority"])
    return "\n".join(lines)


def payload_from_queue_row(row: dict) -> dict:
    try:
        value = json.loads(row.get("payload_json") or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}
