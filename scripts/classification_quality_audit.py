"""Read-only classification-quality audit with an optional aggregate snapshot."""
from __future__ import annotations

import argparse
from datetime import date
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import storage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Summarize destination-HTML classification outcomes and explicit "
            "analyst feedback. This command never changes crawler policy."
        )
    )
    parser.add_argument("--days", type=int, default=30, choices=(7, 30, 90))
    parser.add_argument(
        "--store-daily",
        action="store_true",
        help="Store the sanitized aggregate report for today; operational state is untouched.",
    )
    parser.add_argument("--pretty", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = storage.get_classification_quality_report(days=args.days)
    if args.store_daily:
        snapshot = {
            key: report[key] for key in (
                "window_days", "page_decisions", "unique_pages", "accepted",
                "unsure", "unknown_rate", "reviewed_count",
                "category_corrections", "correction_rate", "safety_excluded",
            )
        }
        snapshot["shadow_observation_count"] = len(report.get("shadow_candidates") or [])
        storage.store_classification_quality_daily(
            date.today().isoformat(), "all_classifiers", snapshot)
    print(json.dumps(
        report, ensure_ascii=True, sort_keys=True,
        indent=2 if args.pretty else None,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
