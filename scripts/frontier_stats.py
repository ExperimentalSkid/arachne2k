#!/usr/bin/env python3
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import storage
storage.init_db()
print(json.dumps(storage.frontier_stats(), indent=2, sort_keys=True))
