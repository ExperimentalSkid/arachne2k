"""Stage-3 Site Card worker.

Claims Site Card jobs and runs rollups/profile refresh/mirror reconciliation with
a per-card lock so multiple card workers do not process the same card together.
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

LOGGER = logging.getLogger("card_worker")
STOP_REQUESTED = False
MAX_WORKERS_PER_TASK = 5


def _request_stop(_signum=None, _frame=None) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True


def _worker_loop(index: int, *, once: bool = False) -> None:
    worker_id = f"card:{os.getpid()}:{index}:{threading.get_ident()}"
    delay = max(1, get_int("ONION_CARD_DELAY_SECONDS", get_int("ONION_CRAWL_DELAY_SECONDS", 10)))
    empty_delay = max(1, get_int("ONION_EMPTY_QUEUE_DELAY_SECONDS", 30))
    try:
        operations.worker_startup("card", worker_id)
    except Exception:
        pass
    try:
        while not STOP_REQUESTED:
            started = time.monotonic()
            iteration_failure = None
            try:
                processed = onion_worker.process_card_job(worker_id)
            except Exception as exc:
                iteration_failure = exc
                LOGGER.warning("Card worker iteration failed safely: %s", type(exc).__name__)
                try:
                    operations.record_db_operation(
                        "card", worker_id, "iteration", (time.monotonic() - started) * 1000, exc)
                except Exception:
                    pass
                storage.heartbeat_worker_instance(
                    worker_id, "card", "error", last_error=type(exc).__name__, observe=False)
                processed = False
            try:
                operations.record_iteration(
                    "card", worker_id, processed=processed,
                    latency_ms=(time.monotonic() - started) * 1000,
                    failure=iteration_failure)
            except Exception:
                pass
            if once:
                break
            time.sleep(delay if processed else empty_delay)
    finally:
        try:
            storage.heartbeat_worker_instance(worker_id, "card", "stopped", observe=False)
        finally:
            try:
                operations.worker_shutdown("card", worker_id)
            except Exception:
                pass


def run(*, workers: int = 1, once: bool = False) -> None:
    storage.ensure_db_initialized()
    count = max(1, min(MAX_WORKERS_PER_TASK, int(workers or 1)))
    if count == 1:
        _worker_loop(1, once=once)
        return
    threads = [threading.Thread(target=_worker_loop, args=(idx,), kwargs={"once": once},
                                name=f"card-worker-{idx}", daemon=True)
               for idx in range(1, count + 1)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def main() -> None:
    parser = argparse.ArgumentParser(description="Arachne staged Site Card worker")
    parser.add_argument("--once", action="store_true", help="Process at most one card job per worker")
    parser.add_argument("--loop", action="store_true", help="Run continuously")
    parser.add_argument("--workers", type=int, default=1, help="Parallel card workers, capped at 5")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.loop and not get_bool("ONION_CRAWLER_ENABLED", False):
        raise SystemExit("Crawler loop disabled. Set ONION_CRAWLER_ENABLED=true to run it.")
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    run(workers=args.workers, once=args.once or not args.loop)


if __name__ == "__main__":
    main()
