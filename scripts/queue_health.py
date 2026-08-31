#!/usr/bin/env python3
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import storage
storage.init_db(); data=storage.frontier_stats(); data["health"]="low_value_dominated" if data["low_value_ratio"]>=0.6 else "healthy"; print(json.dumps(data, indent=2, sort_keys=True))
