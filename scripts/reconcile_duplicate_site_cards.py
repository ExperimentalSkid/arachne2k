#!/usr/bin/env python3
"""Preview or apply safe same-onion Site Card reconciliation."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import site_dedupe  # noqa: E402
import storage  # noqa: E402


def main() -> None:
    """Preview or apply bounded same-onion Site Card reconciliation."""
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    storage.init_db()
    result = site_dedupe.reconcile_duplicate_site_cards(dry_run=not args.apply)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
