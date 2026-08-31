#!/usr/bin/env python3
"""Preview, apply, or reverse bounded deep-pagination frontier deferrals."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import storage  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=int, default=10)
    parser.add_argument("--limit", type=int, default=1000)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--restore", action="store_true")
    args = parser.parse_args()
    storage.init_db()
    result = storage.manage_deep_pagination(
        threshold=args.threshold, limit=args.limit,
        apply=args.apply or args.restore, restore=args.restore,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
