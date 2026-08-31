"""Bounded, advisory Deep Discovery assembly-line worker.

The worker atomically claims durable jobs, runs exact local correlation, and
stores immutable review evidence. Optional public-provider checks are disabled
by default, require the strict 90% eligibility gate, use exact structurally
bound identifiers through the approved Tor transport, and cannot mutate
crawler, classifier, Spain, risk, urgency, or Site Card policy.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import threading
import time

import deep_discovery
import deep_discovery_providers
import operational_observability as operations
import safe_transport
import storage
from config_loader import get_bool, get_int


LOGGER = logging.getLogger("deep_discovery_worker")
STOP_REQUESTED = False
MAX_WORKERS_PER_TASK = 2
_INFRA_CACHE_LOCK = threading.Lock()
_INFRA_CACHE: dict[str, tuple[float, dict]] = {}
_IANA_BOOTSTRAP_CACHE_KEY = "deep-discovery:iana-rdap-dns-bootstrap:v1"


def _infrastructure_cache_get(key: str) -> dict | None:
    """Read only the bounded process-local IANA bootstrap cache."""
    if key != _IANA_BOOTSTRAP_CACHE_KEY:
        return None
    with _INFRA_CACHE_LOCK:
        cached = _INFRA_CACHE.get(key)
        if not cached:
            return None
        expires_at, value = cached
        if expires_at <= time.monotonic():
            _INFRA_CACHE.pop(key, None)
            return None
        return json.loads(json.dumps(value, ensure_ascii=True))


def _infrastructure_cache_put(key: str, value: dict, ttl_seconds: int) -> None:
    """Cache the public IANA service map without weakening evidence storage."""
    if key != _IANA_BOOTSTRAP_CACHE_KEY or not isinstance(value, dict):
        return
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    if len(encoded.encode("ascii")) > deep_discovery_providers.JSON_MAX_BYTES:
        return
    ttl = max(300, min(int(ttl_seconds or 0), 7 * 24 * 60 * 60))
    with _INFRA_CACHE_LOCK:
        _INFRA_CACHE[key] = (
            time.monotonic() + ttl,
            json.loads(encoded),
        )


def _provider_storage_status(result: dict) -> str:
    status = str(result.get("status") or "provider_error")
    if status == "complete":
        return "complete"
    if status in {"not_found", "not_supported", "invalid_identifier"}:
        return "empty"
    if status == "rate_limited":
        return "rate_limited"
    if str(result.get("error_code") or "") == "timeout":
        return "timeout"
    return "error"


def _provider_evidence_rows(result: dict, pivot: dict) -> list[dict]:
    """Translate a proposal-only result into the strict storage evidence shape."""
    provider = str(result.get("provider") or "unknown")
    query_type = str(pivot.get("query_type") or "")
    query_value = str(pivot.get("query_value") or "")
    confidence_by_provider = {
        deep_discovery_providers.OPENPGP_PROVIDER_NAME: 0.98,
        deep_discovery_providers.RDAP_PROVIDER_NAME: 0.96,
        deep_discovery_providers.CT_PROVIDER_NAME: 0.92,
    }
    rows = []
    for candidate in (result.get("results") or [])[:20]:
        if not isinstance(candidate, dict):
            continue
        supporting = [
            str(item.get("type") or "") for item in (candidate.get("supporting") or [])
            if isinstance(item, dict) and item.get("type")
        ]
        contradicting = [
            str(item.get("type") or "") for item in (candidate.get("contradicting") or [])
            if isinstance(item, dict) and item.get("type")
        ]
        metadata: dict = {
            "candidate_type": provider,
            "match_type": "exact_public_identifier",
            "record_count": int(candidate.get("nameserver_count") or 0),
            "certificate_count": int(candidate.get("issuance_count") or 0),
        }
        if query_type == "clearnet_domain":
            metadata["domains"] = [query_value]
        elif query_type == "pgp_fingerprint":
            metadata["pgp_fingerprint"] = query_value
        if candidate.get("delegation_signed") is not None:
            metadata["dnssec"] = bool(candidate.get("delegation_signed"))
        issuances = [
            item for item in (candidate.get("issuances") or [])
            if isinstance(item, dict)
        ]
        if issuances:
            if issuances[0].get("not_before"):
                metadata["not_before"] = issuances[0]["not_before"]
            if issuances[0].get("not_after"):
                metadata["not_after"] = issuances[0]["not_after"]
            if issuances[0].get("revoked") is not None:
                metadata["revoked"] = bool(issuances[0]["revoked"])
        rows.append({
            "identifier_type": query_type,
            "identifier_value": query_value,
            "evidence_type": supporting[0] if supporting else "exact_public_record",
            "provenance_type": provider,
            "provenance_ref": str(candidate.get("candidate_id") or provider),
            "confidence": confidence_by_provider.get(provider, 0.90),
            "support_codes": supporting,
            "contradiction_codes": contradicting,
            "safe_metadata": metadata,
        })
    return rows


def _cached_provider_result(provider: str, pivot: dict) -> dict | None:
    cached = storage.get_deep_discovery_provider_cache(
        provider,
        str(pivot.get("query_type") or ""),
        str(pivot.get("query_value") or ""),
    )
    if not cached:
        return None
    results = []
    for row in (cached.get("normalized_results") or [])[:20]:
        if not isinstance(row, dict):
            continue
        evidence_type = str(row.get("evidence_type") or "exact_public_record")
        identifier_type = str(row.get("identifier_type") or "")
        public_identifier = str(row.get("public_identifier") or "")
        metadata = row.get("safe_metadata") if isinstance(row.get("safe_metadata"), dict) else {}
        candidate = {
            "candidate_id": "cache:" + str(row.get("identifier_hash") or "")[-24:],
            "display_name": (
                public_identifier if identifier_type == "clearnet_domain"
                else "Exact OpenPGP fingerprint"
            ),
            "provider": provider,
            "matching_pivots": [
                "domain" if identifier_type == "clearnet_domain" else "pgp_fingerprint"
            ],
            "supporting": [{
                "type": evidence_type,
                "label": evidence_type.replace("_", " ").title(),
            }],
            "contradicting": [{
                "type": code,
                "label": str(code).replace("_", " ").title(),
            } for code in (row.get("contradiction_codes") or [])],
            "exact_lookup": True,
            "decision_mode": "proposal_only",
        }
        if identifier_type == "clearnet_domain":
            candidate["domain"] = public_identifier
        candidate.update({
            key: value for key, value in metadata.items()
            if key in {
                "dnssec", "revoked", "record_count", "certificate_count",
                "not_before", "not_after",
            }
        })
        results.append(candidate)
    storage_status = str(cached.get("status") or "empty")
    return {
        "schema": "arachne.deep_discovery.provider_result.v1",
        "provider": provider,
        "network_used": False,
        "status": "complete" if storage_status == "complete" and results else "not_found",
        "error_code": None if results else "cached_empty",
        "query_hash": str(cached.get("query_hash") or ""),
        "result_count": len(results),
        "results": results,
        "decision_mode": "proposal_only",
        "analyst_review_required": True,
        "cached": True,
    }


def _store_provider_result(job_id: int, pivot: dict, result: dict) -> int:
    provider = str(result.get("provider") or "unknown")
    status = _provider_storage_status(result)
    evidence_rows = _provider_evidence_rows(result, pivot)
    run_id = storage.record_deep_discovery_provider_run(
        provider,
        str(pivot.get("query_type") or ""),
        str(pivot.get("query_value") or ""),
        job_id=job_id,
        status=status,
        cache_hit=bool(result.get("cached")),
        result_count=len(evidence_rows),
        error_code=str(result.get("error_code") or "") or None,
        safe_metadata={
            "result_state": status,
            "record_count": len(evidence_rows),
        },
    )
    if evidence_rows:
        storage.upsert_deep_discovery_provider_evidence(run_id, evidence_rows)
    if status in {"complete", "empty"}:
        ttl_by_provider = {
            deep_discovery_providers.OPENPGP_PROVIDER_NAME:
                deep_discovery_providers.OPENPGP_CACHE_TTL_SECONDS,
            deep_discovery_providers.RDAP_PROVIDER_NAME:
                deep_discovery_providers.RDAP_CACHE_TTL_SECONDS,
            deep_discovery_providers.CT_PROVIDER_NAME:
                deep_discovery_providers.CT_CACHE_TTL_SECONDS,
        }
        storage.put_deep_discovery_provider_cache(
            provider,
            str(pivot.get("query_type") or ""),
            str(pivot.get("query_value") or ""),
            evidence_rows,
            status=status,
            ttl_seconds=ttl_by_provider.get(provider, 60 * 60),
        )
    return run_id


def _run_public_providers(job_id: int, actor_id: int) -> tuple[list[dict], dict]:
    """Run at most one exact fingerprint and one exact domain provider chain."""
    state = deep_discovery_providers.provider_status()
    if not state.get("network_enabled"):
        return [], state
    enabled = set(state.get("enabled_providers") or [])
    pivots = storage.get_deep_discovery_provider_pivots(actor_id, limit=8)
    selected: dict[str, dict] = {}
    for pivot in pivots:
        query_type = str(pivot.get("query_type") or "")
        if query_type in {"pgp_fingerprint", "clearnet_domain"} and query_type not in selected:
            selected[query_type] = pivot
    max_requests = max(
        1, min(get_int("DEEP_DISCOVERY_MAX_PROVIDER_REQUESTS_PER_JOB", 5), 5))
    remaining = max_requests
    provider_results: list[dict] = []

    def run_one(provider: str, pivot: dict, cost: int, callback) -> None:
        nonlocal remaining
        if provider not in enabled:
            return
        cached = _cached_provider_result(provider, pivot)
        if cached is not None:
            result = cached
        elif remaining >= cost:
            remaining -= cost
            result = callback()
        else:
            return
        _store_provider_result(job_id, pivot, result)
        provider_results.append(result)

    pgp = selected.get("pgp_fingerprint")
    if pgp:
        run_one(
            deep_discovery_providers.OPENPGP_PROVIDER_NAME,
            pgp,
            1,
            lambda: deep_discovery_providers.lookup_openpgp_fingerprint(
                pgp["query_value"], fetch=safe_transport.fetch_public_provider),
        )
    domain = selected.get("clearnet_domain")
    if domain:
        run_one(
            deep_discovery_providers.RDAP_PROVIDER_NAME,
            domain,
            2,
            lambda: deep_discovery_providers.lookup_domain_rdap(
                domain["query_value"],
                fetch=safe_transport.fetch_public_provider,
                cache_get=_infrastructure_cache_get,
                cache_put=_infrastructure_cache_put,
            ),
        )
        run_one(
            deep_discovery_providers.CT_PROVIDER_NAME,
            domain,
            1,
            lambda: deep_discovery_providers.lookup_certificate_transparency(
                domain["query_value"], fetch=safe_transport.fetch_public_provider),
        )
    state = dict(state)
    state.update({
        "pivot_count": len(selected),
        "provider_runs": len(provider_results),
        "request_budget": max_requests,
        "request_budget_remaining": remaining,
    })
    return provider_results, state


def _request_stop(_signum=None, _frame=None) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True


def process_one(worker_id: str | None = None) -> bool:
    """Claim and process one job; return False only when the queue is empty."""
    storage.ensure_db_initialized()
    worker_id = worker_id or f"deep_discovery:{os.getpid()}:{threading.get_ident()}"
    storage.heartbeat_worker_instance(worker_id, "deep_discovery", "checking_queue")
    job = storage.claim_next_deep_discovery_job(
        worker_id, get_int("ONION_CLAIM_TIMEOUT_MINUTES", 45))
    if not job:
        state = "paused" if storage.worker_claims_paused() else "idle"
        storage.heartbeat_worker_instance(worker_id, "deep_discovery", state)
        return False

    job_id = int(job["id"])
    actor_id = int(job["actor_id"])
    try:
        storage.heartbeat_worker_instance(
            worker_id, "deep_discovery", "local_correlation",
            current_job_id=job_id)
        anchor = json.loads(job.get("anchor_snapshot_json") or "{}")
        if not isinstance(anchor, dict) or int(anchor.get("actor_id") or 0) != actor_id:
            raise ValueError("invalid_anchor_actor")
        detail = storage.get_actor_detail(actor_id)
        if not detail:
            storage.fail_deep_discovery_job(
                job_id, worker_id, "actor_not_found", retry=False)
            storage.heartbeat_worker_instance(
                worker_id, "deep_discovery", "failed", current_job_id=job_id,
                last_error="actor_not_found", processed_increment=1, observe=False)
            return True

        eligibility = deep_discovery.score_actor_detail(detail)
        local_provider = deep_discovery_providers.run_local_provider(detail)
        local_results = dict(local_provider["results"])
        local_results["eligibility_at_run"] = eligibility.as_dict()
        local_results["provider"] = local_provider["provider"]
        local_results["network_used"] = False
        if eligibility.auto_queue and eligibility.score >= 0.90:
            provider_results, provider_state = _run_public_providers(job_id, actor_id)
        else:
            provider_results = []
            provider_state = deep_discovery_providers.provider_status()
            provider_state = dict(provider_state)
            provider_state["reason"] = "actor_below_strict_network_gate"
        provider_candidates = [
            candidate
            for result in provider_results
            for candidate in (result.get("results") or [])
            if isinstance(candidate, dict)
        ]
        candidate_clusters = deep_discovery.build_candidate_clusters(
            anchor, local_results, provider_candidates)
        local_results["provider_summary"] = [{
            "provider": result.get("provider"),
            "status": result.get("status"),
            "result_count": int(result.get("result_count") or 0),
            "cached": bool(result.get("cached")),
            "error_code": result.get("error_code"),
        } for result in provider_results]
        provider_statuses = {
            str(result.get("status") or "provider_error")
            for result in provider_results
        }
        if not provider_results:
            run_status = "local_complete"
        elif provider_statuses == {"complete"}:
            run_status = "provider_complete"
        elif provider_statuses.issubset({"not_found", "not_supported"}):
            run_status = "provider_empty"
        else:
            run_status = "provider_partial"
        run_id = storage.finish_deep_discovery_job(
            job_id, worker_id,
            local_results=local_results,
            candidate_clusters=candidate_clusters,
            provider_status=provider_state,
            run_status=run_status,
        )
        if run_id is None:
            raise storage.WorkerClaimLost(f"deep_discovery_claim_lost:{job_id}")
        storage.heartbeat_worker_instance(
            worker_id, "deep_discovery", run_status,
            current_job_id=job_id, processed_increment=1)
        return True
    except storage.WorkerClaimLost:
        LOGGER.warning("Deep Discovery claim was lost before completion")
        storage.heartbeat_worker_instance(
            worker_id, "deep_discovery", "claim_lost", current_job_id=job_id,
            last_error="WorkerClaimLost", processed_increment=1)
        return True
    except Exception as exc:
        error_type = type(exc).__name__
        storage.fail_deep_discovery_job(job_id, worker_id, error_type, retry=True)
        storage.heartbeat_worker_instance(
            worker_id, "deep_discovery", "error", current_job_id=job_id,
            last_error=error_type, processed_increment=1, observe=False)
        LOGGER.warning("Deep Discovery job failed safely: %s", error_type)
        return True


def _worker_loop(index: int, *, once: bool = False) -> None:
    worker_id = f"deep_discovery:{os.getpid()}:{index}:{threading.get_ident()}"
    delay = max(1, get_int("DEEP_DISCOVERY_DELAY_SECONDS", 10))
    empty_delay = max(1, get_int("DEEP_DISCOVERY_EMPTY_QUEUE_DELAY_SECONDS", 30))
    try:
        provider_state = deep_discovery_providers.provider_status()
    except Exception:
        provider_state = {}
    try:
        operations.worker_startup(
            "deep_discovery", worker_id, provider_state=provider_state)
    except Exception:
        pass
    try:
        while not STOP_REQUESTED:
            started = time.monotonic()
            iteration_failure = None
            try:
                processed = process_one(worker_id)
            except Exception as exc:
                iteration_failure = exc
                # process_one handles failures after a claim. This outer boundary
                # keeps pre-claim DB/heartbeat errors from terminating the service.
                error_type = type(exc).__name__
                LOGGER.warning("Deep Discovery loop recovered safely: %s", error_type)
                try:
                    operations.record_db_operation(
                        "deep_discovery", worker_id, "iteration",
                        (time.monotonic() - started) * 1000, exc)
                except Exception:
                    pass
                try:
                    storage.heartbeat_worker_instance(
                        worker_id, "deep_discovery", "error",
                        last_error=error_type, observe=False)
                except Exception:
                    pass
                processed = False
            try:
                operations.record_iteration(
                    "deep_discovery", worker_id, processed=processed,
                    latency_ms=(time.monotonic() - started) * 1000,
                    failure=iteration_failure)
            except Exception:
                pass
            if once:
                break
            time.sleep(delay if processed else empty_delay)
    finally:
        try:
            storage.heartbeat_worker_instance(
                worker_id, "deep_discovery", "stopped", observe=False)
        finally:
            try:
                operations.worker_shutdown("deep_discovery", worker_id)
            except Exception:
                pass


def run(*, workers: int = 1, once: bool = False) -> None:
    storage.ensure_db_initialized()
    count = max(1, min(MAX_WORKERS_PER_TASK, int(workers or 1)))
    if count == 1:
        _worker_loop(1, once=once)
        return
    threads = [threading.Thread(
        target=_worker_loop, args=(index,), kwargs={"once": once},
        name=f"deep-discovery-worker-{index}", daemon=True)
        for index in range(1, count + 1)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def main() -> None:
    parser = argparse.ArgumentParser(description="Arachne local Deep Discovery worker")
    parser.add_argument("--once", action="store_true", help="Process at most one job per worker")
    parser.add_argument("--loop", action="store_true", help="Run continuously")
    parser.add_argument("--workers", type=int, default=1,
                        help="Parallel local workers, capped at 2")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.loop and not get_bool("DEEP_DISCOVERY_WORKER_ENABLED", True):
        LOGGER.info("Deep Discovery worker is disabled by configuration")
        return
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    run(workers=args.workers, once=args.once or not args.loop)


if __name__ == "__main__":
    main()
