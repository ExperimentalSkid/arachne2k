#!/usr/bin/env python3
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backend_health, storage
storage.init_db(); data=backend_health.snapshot(); print(json.dumps({k:data.get(k) for k in ("health","tor","worker","heartbeat_age_seconds","progress_age_seconds","fetch_age_seconds","maintenance_backoff_active")}, indent=2, sort_keys=True, default=str))
