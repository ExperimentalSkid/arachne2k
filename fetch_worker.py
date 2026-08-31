"""Stage-1 onion fetch worker.

Claims frontier rows, applies prefetch policy, fetches allowed HTML/text pages,
parses bounded page metadata/links, and stores fetched snapshots for verification.
"""
from __future__ import annotations

import argparse
import logging
import os
import signal
import threading
import time

import onion_worker
import operational_observability as operations
import storage
from config_loader import get_bool, get_int

LOGGER = logging.getLogger("fetch_worker")
STOP_REQUESTED = False
MAX_WORKERS_PER_TASK = 5
STARTUP_TOR_STATE: dict = {}


def _request_stop(_signum=None, _frame=None) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True


def _worker_loop(index: int, *, once: bool = False) -> None:
    worker_id = f"fetch:{os.getpid()}:{index}:{threading.get_ident()}"
    delay = max(1, get_int("ONION_CRAWL_DELAY_SECONDS", 10))
    empty_delay = max(1, get_int("ONION_EMPTY_QUEUE_DELAY_SECONDS", 30))
    try:
        operations.worker_startup("fetch", worker_id, tor_state=STARTUP_TOR_STATE)
    except Exception:
        pass
    try:
        while not STOP_REQUESTED:
            started = time.monotonic()
            iteration_failure = None
            try:
                processed = onion_worker.fetch_one(worker_id)
            except Exception as exc:
                iteration_failure = exc
                LOGGER.warning("Fetch worker iteration failed safely: %s", type(exc).__name__)
                try:
                    operations.record_db_operation(
                        "fetch", worker_id, "iteration", (time.monotonic() - started) * 1000, exc)
                except Exception:
                    pass
                storage.heartbeat_worker_instance(
                    worker_id, "fetch", "error", last_error=type(exc).__name__, observe=False)
                processed = False
            try:
                operations.record_iteration(
                    "fetch", worker_id, processed=processed,
                    latency_ms=(time.monotonic() - started) * 1000,
                    failure=iteration_failure)
            except Exception:
                pass
            if once:
                break
            time.sleep(delay if processed else empty_delay)
    finally:
        try:
            storage.heartbeat_worker_instance(worker_id, "fetch", "stopped", observe=False)
        finally:
            try:
                operations.worker_shutdown("fetch", worker_id)
            except Exception:
                pass


def run(*, workers: int = 1, once: bool = False) -> None:
    storage.ensure_db_initialized()
    count = max(1, min(MAX_WORKERS_PER_TASK, int(workers or 1)))
    if count == 1:
        _worker_loop(1, once=once)
        return
    threads = [threading.Thread(target=_worker_loop, args=(idx,), kwargs={"once": once},
                                name=f"fetch-worker-{idx}", daemon=True)
               for idx in range(1, count + 1)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def main() -> None:
    global STARTUP_TOR_STATE
    parser = argparse.ArgumentParser(description="Arachne staged fetch worker")
    parser.add_argument("--once", action="store_true", help="Process at most one fetch job per worker")
    parser.add_argument("--loop", action="store_true", help="Run continuously")
    parser.add_argument("--workers", type=int, default=1, help="Parallel fetch workers, capped at 5")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.loop and not get_bool("ONION_CRAWLER_ENABLED", False):
        raise SystemExit("Crawler loop disabled. Set ONION_CRAWLER_ENABLED=true to run it.")
    from opsec_preflight import enforce_strict_mode
    STARTUP_TOR_STATE = enforce_strict_mode()
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    run(workers=args.workers, once=args.once or not args.loop)


if __name__ == "__main__":
    main()
