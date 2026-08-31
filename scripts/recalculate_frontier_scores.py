#!/usr/bin/env python3
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import storage
p = argparse.ArgumentParser(); p.add_argument("--limit", type=int, default=1000)
g = p.add_mutually_exclusive_group(required=True); g.add_argument("--dry-run", action="store_true"); g.add_argument("--apply", action="store_true")
a = p.parse_args(); storage.init_db()
print(json.dumps(storage.recalculate_frontier_scores(dry_run=not a.apply, limit=a.limit), indent=2, sort_keys=True))
