"""Safely backfill only Site Card identity columns.

Usage:
  python scripts/backfill_site_identity.py              # dry run
  python scripts/backfill_site_identity.py --apply
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import storage
from site_identifier import identify_site


def backfill(*, apply: bool = False, batch_size: int = 100) -> dict[str, int]:
    """Scan Site Cards and optionally persist newly derived identity fields."""
    storage.init_db()
    stats = {"scanned": 0, "changed": 0}
    offset = 0
    while True:
        with storage.get_db() as db:
            rows = [dict(row) for row in db.execute(
                """SELECT id,representative_url,display_name,detected_title,identity_site_id
                   FROM site_cards ORDER BY id LIMIT ? OFFSET ?""", (batch_size, offset))]
        if not rows:
            break
        for row in rows:
            stats["scanned"] += 1
            identity = identify_site({"id": row["id"], "url": row.get("representative_url"),
                                      "detected_title": row.get("detected_title") or row.get("display_name")})
            if identity.site_id == row.get("identity_site_id"):
                continue
            stats["changed"] += 1
            if apply:
                with storage.get_db() as db:
                    db.execute("""UPDATE site_cards SET identity_site_id=?,identity_domain=?,
                      identity_canonical_domain=?,identity_brand=?,identity_country=?,identity_language=?,
                      identity_source_type=?,identity_matched_from=?,identity_confidence_score=?,
                      identity_evidence_json=?,identity_ambiguous=?,identity_ambiguity_reason=?,
                      identity_missing_fields_json=? WHERE id=?""",
                      (identity.site_id, identity.domain, identity.canonical_domain, identity.brand,
                       identity.country, identity.language, identity.source_type, identity.matched_from,
                       identity.confidence, json.dumps(identity.evidence, ensure_ascii=False),
                       int(identity.is_ambiguous), identity.ambiguity_reason,
                       json.dumps(identity.missing_fields, ensure_ascii=False), row["id"]))
        offset += len(rows)
    return stats


def main() -> int:
    """Parse CLI options, run the bounded backfill, and print JSON statistics."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write identity-only changes")
    parser.add_argument("--batch-size", type=int, default=100)
    args = parser.parse_args()
    result = backfill(apply=args.apply, batch_size=max(1, min(args.batch_size, 1000)))
    print(json.dumps({**result, "mode": "apply" if args.apply else "dry-run"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
