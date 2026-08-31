"""Stage-4 front-page preview worker.

Claims durable preview jobs and renders safe, policy-approved front pages with
Playwright through Tor. OCR is only a late preview-artifact safety check. It
may delete/block the rendered artifact, but it never replaces the canonical
classification derived from the destination's sanitized fetched HTML.
"""
from __future__ import annotations

import argparse
import logging
import os
import signal
import threading
import time
from pathlib import Path

import operational_observability as operations
import storage
from config_loader import get_bool, get_int
from safety_policy import is_severe_blackhole_policy
from screenshot_service import capture_page_screenshot, screenshot_support_status
from universal_classifier import classify_preview_ocr_text

LOGGER = logging.getLogger("preview_worker")
STOP_REQUESTED = False
MAX_WORKERS_PER_TASK = 5
_LAST_RECONCILE_AT = 0.0
RESTRICTED_PREVIEW_CATEGORIES = {
    "adult_filtered", "adult_restricted", "severe_abuse_risk",
}


def _request_stop(_signum=None, _frame=None) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True


def _ocr_policy_blocks_preview(url: str, preview_path: str) -> tuple[bool, dict]:
    try:
        from image_ocr import extract_text
        ocr_result = extract_text(preview_path)
        text = ocr_result.get("text") or ""
    except Exception as exc:
        LOGGER.info("Preview OCR unavailable for claimed page: %s", type(exc).__name__)
        if get_bool("PREVIEW_REQUIRE_OCR", False):
            return True, {
                "ocr_checked": False, "ocr_unavailable": True,
                "primary_category": "unknown", "storage_policy": "metadata_only",
                "screenshot_policy": "blocked", "screenshot_blocked_reason": "ocr_required_unavailable",
                "safety_reason": "ocr_required_unavailable",
            }
        return False, {"ocr_checked": False, "ocr_unavailable": True, "ocr_error": type(exc).__name__}
    if not text.strip():
        return False, {"ocr_checked": True, "ocr_empty": True}
    policy = classify_preview_ocr_text(text)
    blocked = (
        policy.get("primary_category") in RESTRICTED_PREVIEW_CATEGORIES
        or policy.get("primary_category") == "marketplace_fraud"
    )
    return blocked, policy


def process_preview_job(worker_id: str | None = None) -> bool:
    storage.ensure_db_initialized()
    worker_id = worker_id or f"preview:{os.getpid()}:{threading.get_ident()}"
    storage.heartbeat_worker_instance(worker_id, "preview", "checking_queue")
    if storage.preview_capture_limit_reached():
        storage.heartbeat_worker_instance(worker_id, "preview", "rate_limited")
        return False
    available, reason = screenshot_support_status()
    if not available:
        storage.heartbeat_worker_instance(worker_id, "preview", "disabled", last_error=reason[:300])
        return False
    job = storage.claim_next_page_preview_job(worker_id, get_int("ONION_CLAIM_TIMEOUT_MINUTES", 45))
    if not job:
        state = "paused" if storage.worker_claims_paused() else "idle"
        storage.heartbeat_worker_instance(worker_id, "preview", state)
        return False
    url = job["url"]
    try:
        existing = storage.get_page_preview(url)
        current_policy = storage.get_onion_url_by_url(url) or job
        if is_severe_blackhole_policy(current_policy):
            existing_path = str((existing or {}).get("preview_path") or "")
            if existing_path:
                try:
                    Path(existing_path).unlink(missing_ok=True)
                except (OSError, ValueError):
                    pass
            storage.enforce_severe_blackhole(url, dict(current_policy))
            storage.heartbeat_worker_instance(
                worker_id, "preview", "blocked",
                current_url_id=job.get("onion_url_id"), current_job_id=int(job["id"]),
                processed_increment=1)
            return True
        if (not int(job.get("force") or 0) and existing
                and existing.get("status") in {"available", "available_ocr_unchecked"}
                and existing.get("preview_path") and Path(existing["preview_path"]).is_file()):
            storage.finish_page_preview_job(int(job["id"]), success=True,
                                            preview_path=existing["preview_path"], worker_id=worker_id,
                                            preview_status=existing.get("status") or "available")
            storage.heartbeat_worker_instance(worker_id, "preview", "preview_reused_existing_file",
                                              current_url_id=job.get("onion_url_id"),
                                              current_job_id=int(job["id"]), processed_increment=1)
            return True
        if existing and existing.get("status") == "available" and existing.get("preview_path") and not Path(existing["preview_path"]).is_file():
            storage.reconcile_page_preview_artifacts(limit=100, dry_run=False)
        storage.heartbeat_worker_instance(worker_id, "preview", "capturing",
                                          current_url_id=job.get("onion_url_id"),
                                          current_job_id=int(job["id"]))
        preview_path = capture_page_screenshot(url)
        if not preview_path:
            storage.finish_page_preview_job(int(job["id"]), success=False,
                                            error="preview_capture_unavailable", retry=True,
                                            worker_id=worker_id)
            storage.heartbeat_worker_instance(worker_id, "preview", "retry",
                                              current_url_id=job.get("onion_url_id"),
                                              current_job_id=int(job["id"]),
                                              last_error="preview_capture_unavailable",
                                              processed_increment=1, observe=False)
            return True
        blocked, ocr_policy = _ocr_policy_blocks_preview(url, preview_path)
        if blocked:
            ocr_policy["ocr_deleted_due_to_policy"] = True
            ocr_policy["screenshot_policy"] = "blocked"
            ocr_policy["screenshot_blocked_reason"] = ocr_policy.get("safety_reason") or "ocr_policy_restricted"
            try:
                Path(preview_path).unlink(missing_ok=True)
            except (OSError, ValueError):
                pass
            storage.finish_page_preview_job(
                int(job["id"]), success=False,
                blocked_reason=ocr_policy["screenshot_blocked_reason"], worker_id=worker_id)
            storage.heartbeat_worker_instance(worker_id, "preview", "blocked",
                                              current_url_id=job.get("onion_url_id"),
                                              current_job_id=int(job["id"]),
                                              processed_increment=1)
            return True
        preview_status = "available_ocr_unchecked" if ocr_policy.get("ocr_unavailable") else "available"
        storage.finish_page_preview_job(
            int(job["id"]), success=True, preview_path=preview_path, worker_id=worker_id,
            preview_status=preview_status)
        storage.heartbeat_worker_instance(worker_id, "preview", "available",
                                          current_url_id=job.get("onion_url_id"),
                                          current_job_id=int(job["id"]),
                                          processed_increment=1)
        return True
    except Exception as exc:
        storage.finish_page_preview_job(int(job["id"]), success=False,
                                        error=f"{type(exc).__name__}: {exc}", retry=True,
                                        worker_id=worker_id)
        storage.heartbeat_worker_instance(worker_id, "preview", "error",
                                          current_url_id=job.get("onion_url_id"),
                                          current_job_id=int(job["id"]),
                                          last_error=type(exc).__name__,
                                          processed_increment=1, observe=False)
        LOGGER.warning("Preview worker failed safely: %s", type(exc).__name__)
        return True


def _worker_loop(index: int, *, once: bool = False) -> None:
    global _LAST_RECONCILE_AT
    worker_id = f"preview:{os.getpid()}:{index}:{threading.get_ident()}"
    delay = max(1, get_int("ONION_PREVIEW_DELAY_SECONDS", get_int("ONION_CRAWL_DELAY_SECONDS", 10)))
    empty_delay = max(1, get_int("ONION_EMPTY_QUEUE_DELAY_SECONDS", 30))
    try:
        operations.worker_startup("preview", worker_id)
    except Exception:
        pass
    try:
        while not STOP_REQUESTED:
            started = time.monotonic()
            iteration_failure = None
            try:
                interval = max(60, get_int("PREVIEW_RECONCILE_INTERVAL_SECONDS", 900))
                if index == 1 and time.monotonic() - _LAST_RECONCILE_AT >= interval:
                    storage.reconcile_page_preview_artifacts(limit=500, dry_run=False)
                    _LAST_RECONCILE_AT = time.monotonic()
                processed = process_preview_job(worker_id)
            except Exception as exc:
                iteration_failure = exc
                LOGGER.warning("Preview worker iteration failed safely: %s", type(exc).__name__)
                try:
                    operations.record_db_operation(
                        "preview", worker_id, "iteration",
                        (time.monotonic() - started) * 1000, exc)
                except Exception:
                    pass
                storage.heartbeat_worker_instance(
                    worker_id, "preview", "error", last_error=type(exc).__name__, observe=False)
                processed = False
            try:
                operations.record_iteration(
                    "preview", worker_id, processed=processed,
                    latency_ms=(time.monotonic() - started) * 1000,
                    failure=iteration_failure)
            except Exception:
                pass
            if once:
                break
            time.sleep(delay if processed else empty_delay)
    finally:
        try:
            storage.heartbeat_worker_instance(worker_id, "preview", "stopped", observe=False)
        finally:
            try:
                operations.worker_shutdown("preview", worker_id)
            except Exception:
                pass


def run(*, workers: int = 1, once: bool = False) -> None:
    storage.ensure_db_initialized()
    count = max(1, min(MAX_WORKERS_PER_TASK, int(workers or 1)))
    if count == 1:
        _worker_loop(1, once=once)
        return
    threads = [threading.Thread(target=_worker_loop, args=(idx,), kwargs={"once": once},
                                name=f"preview-worker-{idx}", daemon=True)
               for idx in range(1, count + 1)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def main() -> None:
    parser = argparse.ArgumentParser(description="Arachne staged preview worker")
    parser.add_argument("--once", action="store_true", help="Process at most one preview job per worker")
    parser.add_argument("--loop", action="store_true", help="Run continuously")
    parser.add_argument("--workers", type=int, default=1, help="Parallel preview workers, capped at 5")
    parser.add_argument("--reconcile-previews", action="store_true", help="Reconcile preview files and DB state")
    parser.add_argument("--dry-run", action="store_true", help="Preview reconciliation without writing")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.reconcile_previews:
        import json
        storage.ensure_db_initialized()
        print(json.dumps(storage.reconcile_page_preview_artifacts(dry_run=args.dry_run),
                         ensure_ascii=True, sort_keys=True))
        return
    if args.loop and not get_bool("ONION_CRAWLER_ENABLED", False):
        raise SystemExit("Crawler loop disabled. Set ONION_CRAWLER_ENABLED=true to run it.")
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    run(workers=args.workers, once=args.once or not args.loop)


if __name__ == "__main__":
    main()
