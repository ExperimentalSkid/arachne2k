#!/usr/bin/env python3
"""Run expensive maintenance intentionally, never as an implicit worker startup job."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import consistency  # noqa: E402
import site_dedupe  # noqa: E402
import storage  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", required=True,
                        choices=("consistency", "site-card-rebuild", "taxonomy", "search-tags", "adult-cleanup",
                                 "frontier-repair", "dedupe-candidates"))
    parser.add_argument("--batch-size", type=int, default=500)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    storage.init_db()
    started = time.monotonic()
    rss_before = storage.current_rss_mb()
    if args.task == "consistency":
        result = consistency.audit_consistency() if args.dry_run else consistency.repair_consistency(dry_run=False)
    elif args.task == "frontier-repair":
        result = storage.recalculate_frontier_scores(dry_run=args.dry_run, limit=args.batch_size)
    elif args.task == "dedupe-candidates":
        result = site_dedupe.reconcile_duplicate_site_cards(dry_run=args.dry_run)
    elif args.dry_run:
        result = {"task": args.task, "dry_run": True,
                  "note": "No writes made. Run with --apply while the worker is paused."}
    elif args.task == "site-card-rebuild":
        result = site_dedupe.refresh_site_card_stats(safety_batch=0, missing_limit=args.batch_size,
                                                     dirty_limit=min(args.batch_size * 2, 2000))
    elif args.task == "taxonomy":
        result = {"updated": storage.backfill_category_taxonomy()}
    elif args.task == "search-tags":
        result = storage.backfill_searchable_category_tags()
    else:
        result = {"updated": storage.cleanup_adult_filtered_items()}
    print(json.dumps({"task": args.task, "duration_seconds": round(time.monotonic() - started, 3),
                      "rss_before_mb": rss_before, "rss_after_mb": storage.current_rss_mb(),
                      "result": result}, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
