#!/usr/bin/env python3
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backend_health, storage
storage.init_db(); print(json.dumps(backend_health.snapshot(), indent=2, sort_keys=True, default=str))
