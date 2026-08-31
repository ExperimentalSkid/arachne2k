"""Metadata-safe STIX 2.1 export for analyst-approved Site Cards."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import storage
from paths import REPORTS_DIR


RESTRICTED = {"adult_filtered", "adult_restricted", "severe_abuse_risk"}


def _stix_time(value: str | None = None) -> str:
    if value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        except ValueError:
            pass
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _id(kind: str, value: str) -> str:
    return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, value)}"


def build_stix_bundle(site_card_id: int) -> dict:
    """Build a STIX bundle containing URLs and safe aggregate labels only."""
    with storage.get_db() as db:
        card = db.execute("SELECT * FROM site_cards WHERE id=?", (site_card_id,)).fetchone()
        if not card:
            raise ValueError("Site Card not found")
        card = dict(card)
        if card.get("primary_category") in RESTRICTED or card.get("storage_policy") == "discard":
            raise ValueError("Restricted safety categories cannot be exported")
        urls = [dict(row) for row in db.execute("""SELECT url,first_seen,last_seen FROM site_card_urls
          WHERE site_card_id=? AND active=1 ORDER BY url""", (site_card_id,))]
    created = _stix_time()
    identity_id = _id("identity", "arachne-local-workspace")
    objects = [{
        "type": "identity", "spec_version": "2.1", "id": identity_id,
        "created": created, "modified": created, "name": "Arachne Metadata Export",
        "identity_class": "system",
    }]
    labels = [str(card.get("primary_category") or "unknown")]
    if card.get("spain_priority"):
        labels.append("spain-priority")
    for item in urls:
        value = str(item["url"]).replace("'", "\\'")
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": _id("indicator", item["url"]),
            "created": _stix_time(item.get("first_seen")), "modified": _stix_time(item.get("last_seen")),
            "created_by_ref": identity_id,
            "name": f"Onion URL — {card.get('category_safe_label') or card.get('primary_category')}",
            "description": "Metadata-safe passive intelligence indicator. Page content is intentionally omitted.",
            "indicator_types": ["unknown"], "pattern_type": "stix",
            "pattern": f"[url:value = '{value}']", "valid_from": _stix_time(item.get("first_seen")),
            "labels": labels,
        })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def write_stix_bundle(site_card_id: int, output_dir: Path | None = None) -> Path:
    bundle = build_stix_bundle(site_card_id)
    target_dir = output_dir or REPORTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / f"site_card_{site_card_id}_stix_2_1.json"
    path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
    storage.insert_evidence_report("stix_2_1", str(path), "dashboard", site_card_id=site_card_id)
    return path
