"""Lightweight query timing without SQL parameter or URL logging."""
from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter


@dataclass
class QueryMetrics:
    count: int = 0
    seconds: float = 0.0

    def run(self, callback, *args, **kwargs):
        started = perf_counter()
        try:
            return callback(*args, **kwargs)
        finally:
            self.count += 1
            self.seconds += perf_counter() - started
