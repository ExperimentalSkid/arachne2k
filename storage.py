"""Shared SQLite layer and idempotent passive-OSINT migrations."""
from __future__ import annotations

import json
import hashlib
import math
import os
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from paths import DB_PATH, PREVIEWS_DIR, REPORTS_DIR
from classification_schema import (DESTINATION_HTML_EVIDENCE_VERSION,
                                   has_current_destination_html_evidence)
from forum_url_identity import classify_forum_url
from url_policy import normalize_policy_state
from url_identity import canonical_url as _canonical_url, canonicalize as _canonicalize


MAIN_SCHEMA_VERSION = 1


class _ClosingConnection(sqlite3.Connection):
    """Commit/rollback like sqlite3's context manager, then always close."""
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class WorkerClaimLost(RuntimeError):
    """Raised when a stale worker tries to finish work it no longer owns."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _observe_db_operation(worker_id: str | None, operation: str,
                          elapsed_ms: float, error: BaseException | None = None) -> None:
    try:
        import operational_observability as operations
        prefix = str(worker_id or "").split(":", 1)[0]
        operation_workers = {
            "init_db": "maintenance",
            "enqueue_card": "verify",
            "enqueue_deep_discovery": "verify",
            "claim_fetch": "fetch", "finish_fetch": "fetch",
            "claim_verify": "verify", "finish_verify": "verify", "fail_verify": "verify",
            "claim_card": "card", "finish_card": "card",
            "claim_preview": "preview", "finish_preview": "preview",
            "claim_deep_discovery": "deep_discovery",
            "finish_deep_discovery": "deep_discovery",
            "fail_deep_discovery": "deep_discovery",
            "claim_maintenance": "maintenance",
        }
        worker_type = (
            prefix if prefix in operations.WORKER_TYPES
            else operation_workers.get(operation, "maintenance")
        )
        if error is None and hasattr(operations, "record_db_operation_deferred"):
            operations.record_db_operation_deferred(
                worker_type, worker_id, operation, elapsed_ms)
        else:
            operations.record_db_operation(worker_type, worker_id, operation, elapsed_ms, error)
    except Exception:
        pass


def _observe_job_transition(worker_type: str, worker_id: str | None, status: str,
                            *, job_id: int | None = None, target: str | None = None,
                            error_label: str | None = None,
                            retry_count: int | None = None) -> None:
    """Emit only the committed queue outcome; observability is always fail-open."""
    try:
        import operational_observability as operations
        operations.record_job_transition(
            worker_type, worker_id, status, job_id=job_id, target=target,
            error_label=error_label, retry_count=retry_count)
    except Exception:
        pass


def _begin_immediate(db: sqlite3.Connection, operation: str,
                     worker_id: str | None = None) -> None:
    started = time.monotonic()
    try:
        db.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError as exc:
        _observe_db_operation(worker_id, operation, (time.monotonic() - started) * 1000, exc)
        raise
    _observe_db_operation(worker_id, operation, (time.monotonic() - started) * 1000)


def canonical_url_identity(url: str) -> str:
    """Backward-compatible entrypoint for the authoritative identity module."""
    return _canonical_url(url)


def current_rss_mb() -> float:
    """Best-effort current RSS without introducing a mandatory dependency."""
    try:
        import psutil  # type: ignore
        return round(float(psutil.Process(os.getpid()).memory_info().rss) / 1048576, 1)
    except (ImportError, OSError, AttributeError):
        try:
            pages = int(Path("/proc/self/statm").read_text(encoding="ascii").split()[1])
            return round(pages * os.sysconf("SC_PAGE_SIZE") / 1048576, 1)
        except (OSError, ValueError, IndexError, AttributeError):
            return 0.0


def get_db() -> sqlite3.Connection:
    connection = sqlite3.connect(str(DB_PATH), timeout=30, factory=_ClosingConnection)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    connection.execute("PRAGMA synchronous = NORMAL")
    return connection


_SCHEMA = """
CREATE TABLE IF NOT EXISTS onion_urls (
 id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE, onion_domain TEXT,
 source_url TEXT, source_type TEXT, depth INTEGER DEFAULT 0, first_seen TEXT NOT NULL,
 last_seen TEXT, last_crawled TEXT, next_crawl_at TEXT, status TEXT DEFAULT 'new',
 http_status INTEGER, title TEXT, content_hash TEXT, fuzzy_hash TEXT,
 relevance_score INTEGER DEFAULT 0, risk_score INTEGER DEFAULT 0,
 risk_level TEXT DEFAULT 'NULO', reasons TEXT, risk_flags TEXT,
 review_status TEXT DEFAULT 'pending', error_count INTEGER DEFAULT 0, last_error TEXT,
 verification_state TEXT DEFAULT 'discovered', verified_at TEXT, verification_reason TEXT,
 weapons_evidence_score INTEGER DEFAULT 0, weapons_evidence_families TEXT,
 weapons_commercial_context INTEGER DEFAULT 0, weapons_context_type TEXT DEFAULT 'none'
);
CREATE INDEX IF NOT EXISTS idx_onion_urls_status ON onion_urls(status);
CREATE INDEX IF NOT EXISTS idx_onion_urls_next_crawl ON onion_urls(next_crawl_at);
CREATE INDEX IF NOT EXISTS idx_onion_urls_domain ON onion_urls(onion_domain);
CREATE INDEX IF NOT EXISTS idx_onion_urls_score ON onion_urls(relevance_score);
CREATE INDEX IF NOT EXISTS idx_onion_urls_hash ON onion_urls(content_hash);
CREATE TABLE IF NOT EXISTS onion_edges (
 id INTEGER PRIMARY KEY AUTOINCREMENT, source_url TEXT NOT NULL, discovered_url TEXT NOT NULL,
 first_seen TEXT NOT NULL, UNIQUE(source_url, discovered_url)
);
CREATE TABLE IF NOT EXISTS onion_hits (
 id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, url TEXT NOT NULL, title TEXT,
 score INTEGER, risk_level TEXT, reasons TEXT, snippet TEXT, indicators_json TEXT,
 source_chain TEXT, passive_exposures_json TEXT, review_status TEXT DEFAULT 'pending',
 alert_log_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_onion_hits_url ON onion_hits(url);
CREATE INDEX IF NOT EXISTS idx_onion_hits_ts ON onion_hits(ts);
CREATE INDEX IF NOT EXISTS idx_onion_hits_review ON onion_hits(review_status);
CREATE TABLE IF NOT EXISTS indicators (
 id INTEGER PRIMARY KEY AUTOINCREMENT, indicator_type TEXT NOT NULL, value TEXT NOT NULL,
 normalized_value TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
 source_type TEXT NOT NULL, source_ref TEXT, confidence REAL DEFAULT 0.5, risk_flags TEXT,
 UNIQUE(indicator_type, normalized_value)
);
CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(indicator_type);
CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(normalized_value);
CREATE TABLE IF NOT EXISTS indicator_links (
 id INTEGER PRIMARY KEY AUTOINCREMENT, indicator_id INTEGER NOT NULL, source_type TEXT NOT NULL,
 source_ref TEXT NOT NULL, context_snippet TEXT, first_seen TEXT NOT NULL,
 FOREIGN KEY(indicator_id) REFERENCES indicators(id)
);
CREATE TABLE IF NOT EXISTS mirror_clusters (
 id INTEGER PRIMARY KEY AUTOINCREMENT, cluster_type TEXT, first_seen TEXT NOT NULL,
 last_seen TEXT NOT NULL, relevance_score INTEGER DEFAULT 0, risk_score INTEGER DEFAULT 0,
 risk_level TEXT DEFAULT 'NULO', status TEXT DEFAULT 'active', summary TEXT,
 shared_indicators_json TEXT, attribution_profile_json TEXT, review_status TEXT DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS mirror_urls (
 id INTEGER PRIMARY KEY AUTOINCREMENT, cluster_id INTEGER, url TEXT NOT NULL UNIQUE,
 source_type TEXT, source_ref TEXT, first_seen TEXT NOT NULL, last_seen TEXT,
 last_checked TEXT, status TEXT DEFAULT 'active', http_status INTEGER, title TEXT,
 content_hash TEXT, fuzzy_hash TEXT, risk_flags TEXT, takedown_status TEXT DEFAULT 'not_sent',
 FOREIGN KEY(cluster_id) REFERENCES mirror_clusters(id)
);
CREATE TABLE IF NOT EXISTS passive_exposures (
 id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, url TEXT NOT NULL,
 exposure_type TEXT NOT NULL, severity TEXT NOT NULL, value TEXT, context TEXT,
 source TEXT DEFAULT 'normal_fetch_response', confidence REAL DEFAULT 0.5
);
CREATE INDEX IF NOT EXISTS idx_passive_exposures_url ON passive_exposures(url);
CREATE INDEX IF NOT EXISTS idx_passive_exposures_type ON passive_exposures(exposure_type);
CREATE INDEX IF NOT EXISTS idx_passive_exposures_severity ON passive_exposures(severity);
CREATE TABLE IF NOT EXISTS evidence_reports (
 id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, report_type TEXT NOT NULL,
 cluster_id INTEGER, alert_log_id INTEGER, output_path TEXT, generated_by TEXT,
 status TEXT DEFAULT 'generated'
);
CREATE TABLE IF NOT EXISTS page_previews (
 id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE, preview_path TEXT NOT NULL,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, status TEXT DEFAULT 'available'
);
CREATE INDEX IF NOT EXISTS idx_page_previews_status ON page_previews(status);
CREATE TABLE IF NOT EXISTS page_preview_jobs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE, onion_url_id INTEGER,
 site_card_id INTEGER, status TEXT NOT NULL DEFAULT 'queued',
 attempts INTEGER DEFAULT 0, claimed_at TEXT, claimed_by TEXT,
 last_error TEXT, blocked_reason TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 available_at TEXT, preview_path TEXT,
 priority TEXT DEFAULT 'auto', priority_score INTEGER DEFAULT 0,
 requested_by TEXT, requested_at TEXT, request_reason TEXT, force INTEGER DEFAULT 0,
 FOREIGN KEY(onion_url_id) REFERENCES onion_urls(id),
 FOREIGN KEY(site_card_id) REFERENCES site_cards(id)
);
CREATE INDEX IF NOT EXISTS idx_page_preview_jobs_status ON page_preview_jobs(status,priority_score,claimed_at,created_at);
CREATE TABLE IF NOT EXISTS site_profiles (
 url TEXT PRIMARY KEY, display_name TEXT NOT NULL, category TEXT NOT NULL,
 explanation TEXT NOT NULL, source_summary TEXT, updated_at TEXT NOT NULL,
 FOREIGN KEY(url) REFERENCES onion_urls(url)
);
CREATE INDEX IF NOT EXISTS idx_site_profiles_category ON site_profiles(category);
CREATE TABLE IF NOT EXISTS crawler_worker_state (
 id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL DEFAULT 'unknown',
 last_heartbeat TEXT NOT NULL, last_action TEXT, last_url TEXT, message TEXT
);
CREATE TABLE IF NOT EXISTS worker_maintenance_state (
 task_name TEXT PRIMARY KEY, last_started_at TEXT, last_success_at TEXT,
 last_failure_at TEXT, failure_type TEXT, failure_message TEXT,
 next_allowed_at TEXT, duration_seconds REAL, rss_before_mb REAL, rss_after_mb REAL
);
CREATE TABLE IF NOT EXISTS frontier_deferred_urls (
 url_id INTEGER PRIMARY KEY, url TEXT NOT NULL, old_status TEXT,
 deferred_status TEXT NOT NULL DEFAULT 'deferred_deep_pagination', reason TEXT NOT NULL,
 deferred_at TEXT NOT NULL, restored_at TEXT,
 FOREIGN KEY(url_id) REFERENCES onion_urls(id)
);
CREATE TABLE IF NOT EXISTS forum_crawl_state (
 onion_host TEXT PRIMARY KEY, permitted_thread_budget INTEGER NOT NULL DEFAULT 25,
 max_thread_budget INTEGER NOT NULL DEFAULT 100, relevant_trigger_count INTEGER DEFAULT 0,
 expansion_rounds INTEGER DEFAULT 0, last_trigger_url TEXT, last_trigger_reason TEXT,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS forum_expansion_events (
 trigger_url TEXT PRIMARY KEY, onion_host TEXT NOT NULL, trigger_identity_hash TEXT,
 reason TEXT NOT NULL,
 expanded_by INTEGER DEFAULT 0, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_forum_expansion_host ON forum_expansion_events(onion_host,created_at);
CREATE TABLE IF NOT EXISTS onion_url_sources (
 id INTEGER PRIMARY KEY AUTOINCREMENT, onion_url_id INTEGER NOT NULL, source_url TEXT NOT NULL DEFAULT '',
 source_type TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
 seen_count INTEGER DEFAULT 1, UNIQUE(onion_url_id,source_url,source_type),
 FOREIGN KEY(onion_url_id) REFERENCES onion_urls(id)
);
CREATE TABLE IF NOT EXISTS adult_filter_memory (
 id INTEGER PRIMARY KEY AUTOINCREMENT, onion_url_id INTEGER, url_hash TEXT NOT NULL UNIQUE,
 host_hash TEXT NOT NULL, classification TEXT NOT NULL DEFAULT 'adult_filtered',
 confidence TEXT DEFAULT 'high', safe_rule_id TEXT DEFAULT 'adult_content_filtered',
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, match_count INTEGER DEFAULT 1,
 analyst_decision TEXT DEFAULT 'blocked', reviewed_at TEXT,
 FOREIGN KEY(onion_url_id) REFERENCES onion_urls(id)
);
CREATE INDEX IF NOT EXISTS idx_adult_memory_host ON adult_filter_memory(host_hash,analyst_decision);
CREATE TABLE IF NOT EXISTS page_topics (
 url TEXT PRIMARY KEY, topics_json TEXT NOT NULL, keywords_json TEXT NOT NULL,
 updated_at TEXT NOT NULL, FOREIGN KEY(url) REFERENCES onion_urls(url)
);
CREATE TABLE IF NOT EXISTS onion_tags (
 id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, tag TEXT NOT NULL,
 confidence TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
 UNIQUE(url,tag), FOREIGN KEY(url) REFERENCES onion_urls(url)
);
CREATE TABLE IF NOT EXISTS safety_rule_matches (
 id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, url TEXT NOT NULL,
 rule_id TEXT NOT NULL, safe_label TEXT NOT NULL, match_target TEXT,
 UNIQUE(url,rule_id,match_target)
);
CREATE TABLE IF NOT EXISTS crawl_audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, url TEXT,
 action TEXT NOT NULL, outcome TEXT NOT NULL, safe_reason TEXT
);
CREATE TABLE IF NOT EXISTS restricted_items (
 id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE,
 category TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
 safety_reason TEXT, source_url TEXT, status TEXT DEFAULT 'restricted'
);
CREATE TABLE IF NOT EXISTS spain_alert_queue (
 id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, fingerprint TEXT NOT NULL UNIQUE,
 payload_json TEXT NOT NULL, created_at TEXT NOT NULL, sent_at TEXT, status TEXT DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS spain_hits (
 id INTEGER PRIMARY KEY AUTOINCREMENT, site_tree_id TEXT NOT NULL, site_card_id INTEGER,
 onion_url_id INTEGER, onion_host TEXT NOT NULL, canonical_url TEXT NOT NULL,
 normalized_family TEXT NOT NULL, hit_type TEXT NOT NULL, page_type TEXT,
 primary_category TEXT, risk_level TEXT, language TEXT, spain_reason TEXT,
 spain_confidence TEXT, source_url TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
 alert_state TEXT DEFAULT 'new', alert_count INTEGER DEFAULT 0, metadata_only INTEGER DEFAULT 0,
 safe_display_label TEXT, review_status TEXT DEFAULT 'unreviewed',
 evidence_score INTEGER DEFAULT 0, evidence_families_json TEXT,
 evidence_direction TEXT DEFAULT 'context_only', context_only INTEGER DEFAULT 0,
 actionable INTEGER DEFAULT 0, reason_code TEXT, evidence_type TEXT,
 UNIQUE(onion_host,normalized_family,hit_type)
);
CREATE INDEX IF NOT EXISTS idx_spain_hits_tree ON spain_hits(site_tree_id,hit_type,last_seen);
CREATE INDEX IF NOT EXISTS idx_spain_hits_review ON spain_hits(review_status,last_seen);
CREATE TABLE IF NOT EXISTS site_cards (
 id INTEGER PRIMARY KEY AUTOINCREMENT, canonical_site_id TEXT NOT NULL UNIQUE,
 display_name TEXT, primary_category TEXT DEFAULT 'unknown', tags TEXT,
 risk_level TEXT DEFAULT 'low', confidence TEXT DEFAULT 'low', risk_flags TEXT,
 storage_policy TEXT DEFAULT 'safe_summary', review_status TEXT DEFAULT 'pending',
 report_status TEXT DEFAULT 'not_prepared', spain_priority INTEGER DEFAULT 0,
 spain_confidence TEXT, spain_match_language TEXT, spain_match_reason TEXT,
 priority_score INTEGER DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT,
 last_checked_at TEXT, mirror_count INTEGER DEFAULT 0, live_url_count INTEGER DEFAULT 0,
 dead_url_count INTEGER DEFAULT 0, source_count INTEGER DEFAULT 0,
 restricted_cluster_confidence TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS site_card_urls (
 id INTEGER PRIMARY KEY AUTOINCREMENT, site_card_id INTEGER NOT NULL, onion_url_id INTEGER,
 url TEXT NOT NULL UNIQUE, onion_host TEXT, path TEXT, url_role TEXT DEFAULT 'canonical',
 mirror_confidence TEXT DEFAULT 'unknown', status TEXT, active INTEGER DEFAULT 1,
 http_status INTEGER, dead_reason TEXT, first_seen TEXT NOT NULL, last_seen TEXT,
 last_checked_at TEXT, source_url TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 FOREIGN KEY(site_card_id) REFERENCES site_cards(id), FOREIGN KEY(onion_url_id) REFERENCES onion_urls(id)
);
CREATE TABLE IF NOT EXISTS site_fingerprints (
 id INTEGER PRIMARY KEY AUTOINCREMENT, site_card_id INTEGER NOT NULL, onion_url_id INTEGER,
 fingerprint_type TEXT NOT NULL, fingerprint_value TEXT NOT NULL, confidence TEXT,
 created_at TEXT NOT NULL, UNIQUE(onion_url_id,fingerprint_type,fingerprint_value),
 FOREIGN KEY(site_card_id) REFERENCES site_cards(id), FOREIGN KEY(onion_url_id) REFERENCES onion_urls(id)
);
CREATE TABLE IF NOT EXISTS site_card_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, site_card_id INTEGER NOT NULL, event_type TEXT NOT NULL,
 event_summary TEXT NOT NULL, safe_metadata_json TEXT, created_at TEXT NOT NULL,
 FOREIGN KEY(site_card_id) REFERENCES site_cards(id)
);
CREATE TABLE IF NOT EXISTS possible_site_card_matches (
 id INTEGER PRIMARY KEY AUTOINCREMENT, onion_url_id INTEGER NOT NULL, candidate_site_card_id INTEGER NOT NULL,
 reason TEXT, confidence TEXT DEFAULT 'possible_mirror', status TEXT DEFAULT 'pending',
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(onion_url_id,candidate_site_card_id), FOREIGN KEY(onion_url_id) REFERENCES onion_urls(id),
 FOREIGN KEY(candidate_site_card_id) REFERENCES site_cards(id)
);
CREATE TABLE IF NOT EXISTS classification_decisions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, url TEXT NOT NULL,
 onion_url_id INTEGER, site_card_id INTEGER, stage TEXT NOT NULL,
 proposed_category TEXT, final_category TEXT, confidence_label TEXT,
 confidence_score REAL DEFAULT 0, decision TEXT NOT NULL,
 evidence_families_json TEXT, reason TEXT, classifier_version TEXT,
 analyst_corrected INTEGER DEFAULT 0, previous_category TEXT,
 safe_metadata_json TEXT,
 FOREIGN KEY(onion_url_id) REFERENCES onion_urls(id),
 FOREIGN KEY(site_card_id) REFERENCES site_cards(id)
);
CREATE TABLE IF NOT EXISTS classification_feedback_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
 feedback_scope TEXT NOT NULL, feedback_action TEXT NOT NULL,
 decision_id INTEGER, onion_url_id INTEGER, site_card_id INTEGER,
 subject_hash TEXT NOT NULL, previous_category TEXT, final_category TEXT,
 reason_code TEXT NOT NULL, classifier_version TEXT,
 safe_metadata_json TEXT NOT NULL DEFAULT '{}',
 FOREIGN KEY(decision_id) REFERENCES classification_decisions(id) ON DELETE SET NULL,
 FOREIGN KEY(onion_url_id) REFERENCES onion_urls(id) ON DELETE SET NULL,
 FOREIGN KEY(site_card_id) REFERENCES site_cards(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS classification_shadow_evaluations (
 id INTEGER PRIMARY KEY AUTOINCREMENT, decision_id INTEGER,
 subject_hash TEXT NOT NULL, evaluator_version TEXT NOT NULL,
 proposed_category TEXT, confidence_score REAL DEFAULT 0,
 decision_code TEXT NOT NULL, reason_codes_json TEXT NOT NULL DEFAULT '[]',
 would_change INTEGER DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(decision_id,evaluator_version),
 FOREIGN KEY(decision_id) REFERENCES classification_decisions(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS classification_quality_daily (
 day TEXT NOT NULL, classifier_version TEXT NOT NULL,
 metrics_json TEXT NOT NULL DEFAULT '{}', generated_at TEXT NOT NULL,
 PRIMARY KEY(day,classifier_version)
);
CREATE TABLE IF NOT EXISTS page_change_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, onion_url_id INTEGER,
 site_card_id INTEGER, detected_at TEXT NOT NULL, change_type TEXT NOT NULL,
 previous_content_hash TEXT, current_content_hash TEXT,
 previous_category TEXT, current_category TEXT,
 meaningful INTEGER DEFAULT 0, safe_summary_json TEXT,
 FOREIGN KEY(onion_url_id) REFERENCES onion_urls(id),
 FOREIGN KEY(site_card_id) REFERENCES site_cards(id)
);
CREATE TABLE IF NOT EXISTS crawl_coverage (
 onion_host TEXT PRIMARY KEY, site_card_id INTEGER, discovered_count INTEGER DEFAULT 0,
 checked_count INTEGER DEFAULT 0, queued_count INTEGER DEFAULT 0,
 blocked_count INTEGER DEFAULT 0, dead_count INTEGER DEFAULT 0,
 duplicate_count INTEGER DEFAULT 0, restricted_count INTEGER DEFAULT 0,
 coverage_ratio REAL DEFAULT 0, stopping_reason TEXT,
 first_seen TEXT, last_discovered_at TEXT, last_checked_at TEXT, updated_at TEXT NOT NULL,
 FOREIGN KEY(site_card_id) REFERENCES site_cards(id)
);
CREATE TABLE IF NOT EXISTS actors (
 id INTEGER PRIMARY KEY AUTOINCREMENT, normalized_alias TEXT NOT NULL,
 display_alias TEXT NOT NULL, onion_host TEXT NOT NULL, generic_role INTEGER DEFAULT 0,
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, observation_count INTEGER DEFAULT 0,
 spain_observation_count INTEGER DEFAULT 0, watched INTEGER DEFAULT 0, watch_reason TEXT,
 analyst_status TEXT DEFAULT 'unreviewed', confidence_score REAL DEFAULT 0,
 confidence_label TEXT DEFAULT 'low', latest_url TEXT, primary_category TEXT,
 risk_level TEXT, identity_key TEXT UNIQUE,
 identity_kind TEXT DEFAULT 'host_alias', canonical_profile_identity TEXT,
 canonical_profile_url TEXT, alias_skeleton TEXT, identity_confidence REAL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS actor_observations (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER NOT NULL, url TEXT NOT NULL,
 onion_host TEXT NOT NULL, site_card_id INTEGER, spain_hit_id INTEGER,
 observed_at TEXT NOT NULL, last_seen TEXT NOT NULL, page_type TEXT,
 primary_category TEXT, risk_level TEXT, spain_priority INTEGER DEFAULT 0,
 spain_reason TEXT, evidence_type TEXT NOT NULL, evidence_confidence REAL DEFAULT 0,
 safe_context_label TEXT, analyst_excluded INTEGER DEFAULT 0,
 seller_observation INTEGER DEFAULT 0, spain_flow TEXT DEFAULT 'none',
 marketplace_category TEXT, profile_identity TEXT, profile_url TEXT,
 source_scope TEXT, evidence_signals_json TEXT, bound_identifier_count INTEGER DEFAULT 0,
 UNIQUE(actor_id,url,evidence_type), FOREIGN KEY(actor_id) REFERENCES actors(id)
);
CREATE TABLE IF NOT EXISTS actor_aliases (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER NOT NULL,
 normalized_alias TEXT NOT NULL, display_alias TEXT NOT NULL, alias_skeleton TEXT,
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, observation_count INTEGER DEFAULT 1,
 UNIQUE(actor_id,normalized_alias,display_alias), FOREIGN KEY(actor_id) REFERENCES actors(id)
);
CREATE TABLE IF NOT EXISTS actor_identifiers (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER NOT NULL,
 indicator_type TEXT NOT NULL, value_hash TEXT NOT NULL, safe_value_label TEXT NOT NULL,
 association_confidence REAL DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
 observation_id INTEGER, binding_method TEXT DEFAULT 'legacy_unscoped', source_scope TEXT,
 UNIQUE(actor_id,indicator_type,value_hash), FOREIGN KEY(actor_id) REFERENCES actors(id)
);
CREATE TABLE IF NOT EXISTS actor_connections (
 id INTEGER PRIMARY KEY AUTOINCREMENT, source_actor_id INTEGER NOT NULL,
 target_actor_id INTEGER NOT NULL, confidence_score REAL DEFAULT 0,
 confidence_label TEXT DEFAULT 'low', evidence_json TEXT,
 analyst_decision TEXT DEFAULT 'unreviewed', first_seen TEXT NOT NULL,
 last_seen TEXT NOT NULL, warning_type TEXT, warning_reason TEXT,
 migration_candidate INTEGER DEFAULT 0, UNIQUE(source_actor_id,target_actor_id),
 FOREIGN KEY(source_actor_id) REFERENCES actors(id), FOREIGN KEY(target_actor_id) REFERENCES actors(id)
);
CREATE TABLE IF NOT EXISTS actor_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER, connection_id INTEGER,
 event_type TEXT NOT NULL, safe_metadata_json TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actor_candidates (
 id INTEGER PRIMARY KEY AUTOINCREMENT, candidate_key TEXT NOT NULL UNIQUE,
 url TEXT NOT NULL, onion_host TEXT NOT NULL, onion_url_id INTEGER, site_card_id INTEGER,
 actor_id INTEGER, display_alias TEXT NOT NULL, normalized_alias TEXT NOT NULL,
 alias_skeleton TEXT, automatic_state TEXT NOT NULL, analyst_state TEXT,
 effective_state TEXT NOT NULL, structural_container TEXT, structural_role TEXT,
 extraction_method TEXT, profile_route_agreement TEXT, profile_identity TEXT,
 profile_url TEXT, page_role TEXT, forum_role TEXT, evidence_type TEXT,
 evidence_strength TEXT, evidence_confidence REAL DEFAULT 0,
 reason_codes_json TEXT NOT NULL DEFAULT '[]', blocking_signals_json TEXT NOT NULL DEFAULT '[]',
 script_profile_json TEXT NOT NULL DEFAULT '{}', bound_identifier_types_json TEXT NOT NULL DEFAULT '[]',
 confidence_contributions_json TEXT NOT NULL DEFAULT '{}', ruleset_version TEXT NOT NULL,
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, seen_count INTEGER DEFAULT 1,
 FOREIGN KEY(onion_url_id) REFERENCES onion_urls(id),
 FOREIGN KEY(site_card_id) REFERENCES site_cards(id), FOREIGN KEY(actor_id) REFERENCES actors(id)
);
CREATE INDEX IF NOT EXISTS idx_actor_candidates_review ON actor_candidates(effective_state,last_seen);
CREATE INDEX IF NOT EXISTS idx_actor_candidates_alias ON actor_candidates(normalized_alias,onion_host);
CREATE INDEX IF NOT EXISTS idx_actor_candidates_actor ON actor_candidates(actor_id,last_seen);
CREATE TABLE IF NOT EXISTS actor_candidate_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, candidate_id INTEGER NOT NULL, actor_id INTEGER,
 event_type TEXT NOT NULL, old_state TEXT, new_state TEXT, reason_code TEXT,
 safe_metadata_json TEXT NOT NULL DEFAULT '{}', analyst_id TEXT, created_at TEXT NOT NULL,
 FOREIGN KEY(candidate_id) REFERENCES actor_candidates(id), FOREIGN KEY(actor_id) REFERENCES actors(id)
);
CREATE INDEX IF NOT EXISTS idx_actor_candidate_events_candidate ON actor_candidate_events(candidate_id,created_at);
CREATE TABLE IF NOT EXISTS alias_noise_rules (
 id INTEGER PRIMARY KEY AUTOINCREMENT, rule_version TEXT NOT NULL, rule_type TEXT NOT NULL,
 normalized_pattern TEXT NOT NULL, scope TEXT NOT NULL DEFAULT 'global',
 action TEXT NOT NULL DEFAULT 'reject', reason_code TEXT NOT NULL,
 enabled INTEGER DEFAULT 1, analyst_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(rule_type,normalized_pattern,scope)
);
CREATE INDEX IF NOT EXISTS idx_alias_noise_rules_enabled ON alias_noise_rules(enabled,scope,rule_type);
CREATE TABLE IF NOT EXISTS actor_identifier_observations (
 actor_identifier_id INTEGER NOT NULL, observation_id INTEGER NOT NULL,
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
 PRIMARY KEY(actor_identifier_id,observation_id),
 FOREIGN KEY(actor_identifier_id) REFERENCES actor_identifiers(id),
 FOREIGN KEY(observation_id) REFERENCES actor_observations(id)
);
CREATE INDEX IF NOT EXISTS idx_actor_identifier_obs_observation
 ON actor_identifier_observations(observation_id,actor_identifier_id);
CREATE TABLE IF NOT EXISTS actor_watch_alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER NOT NULL,
 related_actor_id INTEGER DEFAULT 0, url TEXT NOT NULL, alert_type TEXT NOT NULL,
 safe_reason TEXT NOT NULL, created_at TEXT NOT NULL, acknowledged_at TEXT,
 status TEXT DEFAULT 'new', UNIQUE(actor_id,related_actor_id,url,alert_type),
 FOREIGN KEY(actor_id) REFERENCES actors(id)
);
CREATE TABLE IF NOT EXISTS deep_discovery_jobs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER NOT NULL,
 site_card_id INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'queued',
 priority INTEGER DEFAULT 10, eligibility_score REAL DEFAULT 0,
 trigger_reason TEXT, anchor_snapshot_json TEXT NOT NULL,
 auto_queued INTEGER DEFAULT 1, attempts INTEGER DEFAULT 0, max_attempts INTEGER DEFAULT 3,
 claimed_by TEXT, claimed_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 completed_at TEXT, last_error TEXT, UNIQUE(actor_id,site_card_id),
 FOREIGN KEY(actor_id) REFERENCES actors(id)
);
CREATE TABLE IF NOT EXISTS deep_discovery_runs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER, actor_id INTEGER NOT NULL,
 site_card_id INTEGER NOT NULL DEFAULT 0, run_status TEXT NOT NULL DEFAULT 'local_only',
 anchor_snapshot_json TEXT NOT NULL, local_results_json TEXT,
 candidate_clusters_json TEXT, created_at TEXT NOT NULL, completed_at TEXT,
 FOREIGN KEY(job_id) REFERENCES deep_discovery_jobs(id),
 FOREIGN KEY(actor_id) REFERENCES actors(id)
);
CREATE TABLE IF NOT EXISTS deep_discovery_provider_runs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, run_key TEXT NOT NULL UNIQUE,
 deep_discovery_run_id INTEGER, job_id INTEGER,
 provider_name TEXT NOT NULL, provider_version TEXT NOT NULL,
 query_type TEXT NOT NULL, query_hash TEXT NOT NULL,
 status TEXT NOT NULL, cache_hit INTEGER NOT NULL DEFAULT 0,
 result_count INTEGER NOT NULL DEFAULT 0, error_code TEXT,
 safe_metadata_json TEXT NOT NULL DEFAULT '{}',
 started_at TEXT NOT NULL, completed_at TEXT, updated_at TEXT NOT NULL,
 FOREIGN KEY(deep_discovery_run_id) REFERENCES deep_discovery_runs(id) ON DELETE SET NULL,
 FOREIGN KEY(job_id) REFERENCES deep_discovery_jobs(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS deep_discovery_provider_evidence (
 id INTEGER PRIMARY KEY AUTOINCREMENT, provider_run_id INTEGER NOT NULL,
 evidence_key TEXT NOT NULL, identifier_type TEXT NOT NULL,
 identifier_hash TEXT NOT NULL, public_identifier TEXT,
 evidence_type TEXT NOT NULL, provenance_type TEXT NOT NULL,
 provenance_ref_hash TEXT, confidence REAL NOT NULL DEFAULT 0,
 support_codes_json TEXT NOT NULL DEFAULT '[]',
 contradiction_codes_json TEXT NOT NULL DEFAULT '[]',
 safe_metadata_json TEXT NOT NULL DEFAULT '{}',
 observed_at TEXT, retrieved_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(provider_run_id,evidence_key),
 FOREIGN KEY(provider_run_id) REFERENCES deep_discovery_provider_runs(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS deep_discovery_provider_cache (
 cache_key TEXT PRIMARY KEY, provider_name TEXT NOT NULL,
 provider_version TEXT NOT NULL, query_type TEXT NOT NULL,
 query_hash TEXT NOT NULL, status TEXT NOT NULL,
 result_count INTEGER NOT NULL DEFAULT 0,
 normalized_result_json TEXT NOT NULL DEFAULT '[]',
 stored_at TEXT NOT NULL, expires_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(provider_name,provider_version,query_type,query_hash)
);
CREATE TABLE IF NOT EXISTS entity_expansion_proposals (
 id INTEGER PRIMARY KEY AUTOINCREMENT, proposal_key TEXT NOT NULL UNIQUE,
 actor_id INTEGER, site_card_id INTEGER, parent_url TEXT NOT NULL,
 parent_evidence_type TEXT, onion_host TEXT NOT NULL, proposed_url TEXT NOT NULL,
 route_role TEXT NOT NULL, resource_family TEXT NOT NULL, resource_identity TEXT NOT NULL,
 reason_code TEXT NOT NULL, expected_value REAL DEFAULT 0, novelty_score REAL DEFAULT 0,
 host_budget INTEGER NOT NULL, resource_budget INTEGER NOT NULL,
 safety_state TEXT NOT NULL, decision_mode TEXT NOT NULL DEFAULT 'proposal_only',
 status TEXT NOT NULL DEFAULT 'proposed', analyst_id TEXT, analyst_reason TEXT,
 enqueued_onion_url_id INTEGER,
 result_code TEXT, result_safe_metadata_json TEXT NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, decided_at TEXT, completed_at TEXT,
 FOREIGN KEY(actor_id) REFERENCES actors(id), FOREIGN KEY(site_card_id) REFERENCES site_cards(id),
 FOREIGN KEY(enqueued_onion_url_id) REFERENCES onion_urls(id)
);
CREATE INDEX IF NOT EXISTS idx_entity_expansion_review
 ON entity_expansion_proposals(status,expected_value,created_at);
CREATE INDEX IF NOT EXISTS idx_entity_expansion_resource
 ON entity_expansion_proposals(onion_host,resource_family,resource_identity);
CREATE INDEX IF NOT EXISTS idx_deep_discovery_jobs_status ON deep_discovery_jobs(status,priority,created_at);
CREATE INDEX IF NOT EXISTS idx_deep_discovery_jobs_actor ON deep_discovery_jobs(actor_id,site_card_id);
CREATE INDEX IF NOT EXISTS idx_deep_provider_runs_job
 ON deep_discovery_provider_runs(job_id,provider_name,updated_at);
CREATE INDEX IF NOT EXISTS idx_deep_provider_runs_parent
 ON deep_discovery_provider_runs(deep_discovery_run_id,updated_at);
CREATE INDEX IF NOT EXISTS idx_deep_provider_evidence_run
 ON deep_discovery_provider_evidence(provider_run_id,confidence,retrieved_at);
CREATE INDEX IF NOT EXISTS idx_deep_provider_cache_expiry
 ON deep_discovery_provider_cache(expires_at);
CREATE TABLE IF NOT EXISTS maintenance_migrations (
 name TEXT PRIMARY KEY, completed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notification_control (
 id INTEGER PRIMARY KEY CHECK(id=1), spain_alerts_paused INTEGER DEFAULT 0,
 updated_at TEXT, updated_by TEXT
);
CREATE TABLE IF NOT EXISTS dashboard_access_state (
 id INTEGER PRIMARY KEY CHECK(id=1), lock_enabled INTEGER DEFAULT 0,
 updated_at TEXT, updated_by TEXT
);
CREATE TABLE IF NOT EXISTS dashboard_access_codes (
 id INTEGER PRIMARY KEY AUTOINCREMENT, code_hash TEXT NOT NULL, code_salt TEXT NOT NULL,
 created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT, used_at TEXT,
 created_by_telegram_id TEXT, duration_seconds INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dashboard_access_codes_active ON dashboard_access_codes(expires_at,revoked_at,used_at);
CREATE TABLE IF NOT EXISTS dashboard_sessions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, session_hash TEXT NOT NULL UNIQUE,
 created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT,
 source_code_id INTEGER, user_agent TEXT, ip_hint TEXT,
 FOREIGN KEY(source_code_id) REFERENCES dashboard_access_codes(id)
);
CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_active ON dashboard_sessions(expires_at,revoked_at);
CREATE TABLE IF NOT EXISTS dashboard_access_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL,
 safe_metadata_json TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS saved_investigations (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, description TEXT,
 filters_json TEXT NOT NULL, builtin INTEGER DEFAULT 0, created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS daily_digests (
 digest_date TEXT PRIMARY KEY, timezone TEXT NOT NULL DEFAULT 'Europe/Madrid',
 payload_json TEXT NOT NULL, generated_at TEXT NOT NULL,
 telegram_status TEXT DEFAULT 'dashboard_only', telegram_sent_at TEXT
);
CREATE TABLE IF NOT EXISTS fetched_pages (
 id INTEGER PRIMARY KEY AUTOINCREMENT, onion_url_id INTEGER NOT NULL UNIQUE,
 url TEXT NOT NULL UNIQUE, worker_id TEXT, classification_status TEXT NOT NULL DEFAULT 'pending',
 claimed_at TEXT, claimed_by TEXT, fetched_at TEXT NOT NULL, response_status INTEGER,
 content_type TEXT, headers_json TEXT, title TEXT, meta_text TEXT, visible_text TEXT,
 link_records_json TEXT, page_structure_json TEXT, pre_policy_json TEXT,
 error TEXT, verified_at TEXT,
 FOREIGN KEY(onion_url_id) REFERENCES onion_urls(id)
);
CREATE INDEX IF NOT EXISTS idx_fetched_pages_status ON fetched_pages(classification_status,claimed_at);
CREATE TABLE IF NOT EXISTS site_card_jobs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, onion_url_id INTEGER, site_card_id INTEGER,
 url TEXT, job_type TEXT NOT NULL DEFAULT 'rollup', status TEXT NOT NULL DEFAULT 'queued',
 priority INTEGER DEFAULT 0, claimed_at TEXT, claimed_by TEXT, created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL, attempts INTEGER DEFAULT 0, last_error TEXT,
 UNIQUE(job_type,onion_url_id,site_card_id)
);
CREATE INDEX IF NOT EXISTS idx_site_card_jobs_status ON site_card_jobs(status,priority,created_at);
CREATE TABLE IF NOT EXISTS worker_instances (
 worker_id TEXT PRIMARY KEY, worker_type TEXT NOT NULL, pid INTEGER, state TEXT NOT NULL,
 current_url_id INTEGER, current_job_id INTEGER, last_heartbeat_at TEXT NOT NULL,
 processed_total INTEGER DEFAULT 0, last_error TEXT, started_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_worker_instances_type ON worker_instances(worker_type,state,last_heartbeat_at);
CREATE TABLE IF NOT EXISTS maintenance_leases (
 task_name TEXT PRIMARY KEY, worker_id TEXT NOT NULL, acquired_at TEXT NOT NULL,
 expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS data_migrations (
 name TEXT PRIMARY KEY, status TEXT NOT NULL, started_at TEXT NOT NULL,
 completed_at TEXT, safe_result_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_onion_tags_url ON onion_tags(url);
CREATE INDEX IF NOT EXISTS idx_audit_url ON crawl_audit_log(url);
CREATE INDEX IF NOT EXISTS idx_spain_alert_status ON spain_alert_queue(status);
CREATE INDEX IF NOT EXISTS idx_site_cards_priority ON site_cards(spain_priority,priority_score,updated_at);
CREATE INDEX IF NOT EXISTS idx_site_cards_review ON site_cards(review_status);
CREATE INDEX IF NOT EXISTS idx_site_card_urls_card ON site_card_urls(site_card_id,status,active);
CREATE INDEX IF NOT EXISTS idx_site_card_urls_host ON site_card_urls(onion_host);
CREATE INDEX IF NOT EXISTS idx_site_fingerprints_value ON site_fingerprints(fingerprint_type,fingerprint_value);
CREATE INDEX IF NOT EXISTS idx_possible_matches_status ON possible_site_card_matches(status);
CREATE INDEX IF NOT EXISTS idx_classification_decisions_url ON classification_decisions(url,ts);
CREATE INDEX IF NOT EXISTS idx_classification_decisions_decision ON classification_decisions(decision,ts);
CREATE INDEX IF NOT EXISTS idx_classification_decisions_category ON classification_decisions(final_category,ts);
CREATE INDEX IF NOT EXISTS idx_classification_decisions_stage_ts
 ON classification_decisions(stage,ts,id);
CREATE INDEX IF NOT EXISTS idx_classification_feedback_created
 ON classification_feedback_events(created_at,id);
CREATE INDEX IF NOT EXISTS idx_classification_feedback_scope_action
 ON classification_feedback_events(feedback_scope,feedback_action,created_at);
CREATE INDEX IF NOT EXISTS idx_classification_feedback_decision
 ON classification_feedback_events(decision_id,created_at);
CREATE INDEX IF NOT EXISTS idx_classification_feedback_version
 ON classification_feedback_events(classifier_version,created_at);
CREATE INDEX IF NOT EXISTS idx_classification_shadow_created
 ON classification_shadow_evaluations(created_at,id);
CREATE INDEX IF NOT EXISTS idx_classification_shadow_version
 ON classification_shadow_evaluations(evaluator_version,created_at);
CREATE INDEX IF NOT EXISTS idx_classification_quality_daily_generated
 ON classification_quality_daily(generated_at,day);
CREATE INDEX IF NOT EXISTS idx_page_change_events_url ON page_change_events(url,detected_at);
CREATE INDEX IF NOT EXISTS idx_page_change_events_meaningful ON page_change_events(meaningful,detected_at);
CREATE INDEX IF NOT EXISTS idx_actors_spain_watch ON actors(spain_observation_count,watched,last_seen);
CREATE INDEX IF NOT EXISTS idx_actor_observations_actor ON actor_observations(actor_id,spain_priority,last_seen);
CREATE INDEX IF NOT EXISTS idx_actor_observations_url ON actor_observations(url);
CREATE INDEX IF NOT EXISTS idx_actor_aliases_actor ON actor_aliases(actor_id,last_seen);
CREATE INDEX IF NOT EXISTS idx_actor_identifiers_hash ON actor_identifiers(indicator_type,value_hash);
CREATE INDEX IF NOT EXISTS idx_actor_connections_source ON actor_connections(source_actor_id,target_actor_id);
CREATE INDEX IF NOT EXISTS idx_actor_watch_alerts_status ON actor_watch_alerts(status,created_at);
"""

_ENSURE_DONE_FOR_PATH: str | None = None
_ENSURE_INIT_LOCK = threading.RLock()


_ONION_POLICY_COLUMNS = {
    "primary_category": "TEXT DEFAULT 'unknown'", "category": "TEXT DEFAULT 'unknown'",
    "tags": "TEXT", "confidence": "TEXT DEFAULT 'low'", "geo_priority": "TEXT",
    "spain_priority": "INTEGER DEFAULT 0", "spain_match_reason": "TEXT",
    "spain_match_language": "TEXT", "spain_confidence": "TEXT", "spain_context_tags": "TEXT",
    "spain_alert_sent": "INTEGER DEFAULT 0", "spain_alert_sent_at": "TEXT",
    "spain_alert_level": "TEXT", "spain_review_status": "TEXT DEFAULT 'unreviewed'",
    "spain_analyst_suppressed": "INTEGER DEFAULT 0", "spain_suppressed_at": "TEXT",
    "storage_policy": "TEXT DEFAULT 'safe_summary'", "safety_reason": "TEXT",
    "screenshot_blocked_reason": "TEXT", "active": "INTEGER DEFAULT 1",
    "dead_reason": "TEXT", "last_checked_at": "TEXT", "priority_score": "INTEGER DEFAULT 0",
    "tag_summary": "TEXT", "tag_confidence": "TEXT", "queue_policy": "TEXT DEFAULT 'normal'",
    "screenshot_policy": "TEXT DEFAULT 'blocked'", "site_card_id": "INTEGER",
    "canonical_site_id": "TEXT", "dedupe_status": "TEXT DEFAULT 'unassigned'",
    "mirror_confidence": "TEXT DEFAULT 'unknown'", "content_fingerprint": "TEXT",
    "structure_fingerprint": "TEXT", "safe_title_fingerprint": "TEXT",
    "canonical_url": "TEXT", "original_url": "TEXT", "seen_count": "INTEGER DEFAULT 1",
    "canonical_root": "TEXT", "entity_identity": "TEXT",
    "source_count": "INTEGER DEFAULT 0", "duplicate_of": "INTEGER", "canonical_id": "INTEGER",
    "mirror_cluster_id": "INTEGER", "secondary_categories": "TEXT", "marketplace_type": "TEXT",
    "page_type": "TEXT DEFAULT 'unknown'", "category_confidence": "TEXT DEFAULT 'low'",
    "category_reason": "TEXT", "category_safe_label": "TEXT", "display_group": "TEXT DEFAULT 'Other'",
    "ui_hidden_default": "INTEGER DEFAULT 0", "ui_priority": "INTEGER DEFAULT 0",
    "review_score": "INTEGER DEFAULT 0"
    , "decision": "TEXT", "decision_rule_id": "TEXT", "display_safe_reason": "TEXT",
    "fetch_status": "TEXT DEFAULT 'not_fetched'", "liveness_status": "TEXT DEFAULT 'unknown'",
    "content_quality": "TEXT DEFAULT 'unknown'", "frontier_priority": "INTEGER DEFAULT 0",
    "path_signature": "TEXT", "query_signature": "TEXT", "url_family": "TEXT",
    "trap_score": "INTEGER DEFAULT 0", "trap_reason": "TEXT",
    "restricted_outbound_count": "INTEGER DEFAULT 0", "adult_outbound_count": "INTEGER DEFAULT 0",
    "severe_outbound_count": "INTEGER DEFAULT 0", "restricted_outbound_ratio": "REAL DEFAULT 0",
    "mixed_directory": "INTEGER DEFAULT 0", "restricted_child_present": "INTEGER DEFAULT 0",
    "adult_category_present": "INTEGER DEFAULT 0",
    "match_scope": "TEXT", "safe_signal_labels": "TEXT", "signal_count": "INTEGER DEFAULT 0",
    "signal_ratio": "REAL DEFAULT 0", "dominance_score": "REAL DEFAULT 0",
    "context_window_count": "INTEGER DEFAULT 0", "child_only": "INTEGER DEFAULT 0",
    "false_positive_guard_applied": "INTEGER DEFAULT 0", "ocr_checked": "INTEGER DEFAULT 0",
    "ocr_restricted_hit": "INTEGER DEFAULT 0", "ocr_safe_signal_labels": "TEXT",
    "ocr_deleted_due_to_policy": "INTEGER DEFAULT 0", "analyst_category": "TEXT",
    "suggested_category": "TEXT", "classification_decision": "TEXT DEFAULT 'unclassified'",
    "classification_confidence_score": "REAL DEFAULT 0", "classifier_version": "TEXT",
    "classification_stage": "TEXT",
    "verification_state": "TEXT DEFAULT 'discovered'", "verified_at": "TEXT",
    "verification_reason": "TEXT", "weapons_evidence_score": "INTEGER DEFAULT 0",
    "weapons_evidence_families": "TEXT", "weapons_commercial_context": "INTEGER DEFAULT 0",
    "weapons_context_type": "TEXT DEFAULT 'none'"
    , "language": "TEXT", "locale_path": "TEXT", "spanish_language_detected": "INTEGER DEFAULT 0",
    "spain_priority_reason": "TEXT", "spain_priority_evidence_type": "TEXT",
    "spain_relevance": "TEXT DEFAULT 'none'", "spain_evidence_type": "TEXT",
    "seller_geo_confidence": "TEXT DEFAULT 'none'", "spain_evidence_snippets": "TEXT",
    "spain_evidence_source_url": "TEXT", "spain_evidence_source_path": "TEXT",
    "spain_context_only": "INTEGER DEFAULT 0", "spain_actionable": "INTEGER DEFAULT 0",
    "spain_evidence_score": "INTEGER DEFAULT 0", "spain_evidence_families": "TEXT",
    "spain_evidence_direction": "TEXT DEFAULT 'context_only'",
    "importance_level": "TEXT DEFAULT 'normal'", "importance_reason": "TEXT",
    "analyst_importance": "TEXT", "safe_display_name": "TEXT",
    "outbound_total": "INTEGER DEFAULT 0", "outbound_safe_queued": "INTEGER DEFAULT 0",
    "outbound_unknown_queued": "INTEGER DEFAULT 0", "outbound_adult_restricted": "INTEGER DEFAULT 0",
    "outbound_severe_restricted": "INTEGER DEFAULT 0", "outbound_fraud_metadata_limited": "INTEGER DEFAULT 0",
    "outbound_file_blocked": "INTEGER DEFAULT 0", "outbound_login_transaction_blocked": "INTEGER DEFAULT 0",
    "outbound_existing": "INTEGER DEFAULT 0", "outbound_external_seeded": "INTEGER DEFAULT 0",
    "detected_title": "TEXT", "title_source": "TEXT", "identity_confidence": "TEXT",
    "safe_site_name": "TEXT", "policy_label": "TEXT", "unsafe_title_hidden": "INTEGER DEFAULT 0",
    "page_type_confidence": "TEXT", "page_type_evidence_json": "TEXT",
    "card_ready": "INTEGER DEFAULT 0", "card_readiness_reason": "TEXT",
    "card_readiness_confidence": "TEXT", "safe_summary": "TEXT",
    "link_repository_score": "INTEGER DEFAULT 0", "outbound_onion_count": "INTEGER DEFAULT 0",
    "internal_link_count": "INTEGER DEFAULT 0", "external_onion_count": "INTEGER DEFAULT 0"
    , "content_category": "TEXT DEFAULT 'unknown'", "safety_state": "TEXT DEFAULT 'safe'",
    "category_evidence_json": "TEXT", "category_supporting_evidence_json": "TEXT",
    "category_contradicting_evidence_json": "TEXT", "category_update_allowed": "INTEGER DEFAULT 1",
    "category_update_reason": "TEXT",
    "destination_html_evidence_version": "INTEGER DEFAULT 0",
    "classification_evidence_source": "TEXT DEFAULT 'unverified'"
    , "child_adult_link_count": "INTEGER DEFAULT 0",
    "child_restricted_link_count": "INTEGER DEFAULT 0", "child_blocked_link_count": "INTEGER DEFAULT 0",
    "parent_evidence_json": "TEXT", "child_link_evidence_json": "TEXT"
    , "pagination_page": "INTEGER DEFAULT 0", "novelty_score": "INTEGER DEFAULT 0",
    "defer_reason": "TEXT", "claimed_at": "TEXT", "claimed_by": "TEXT",
    "retry_count": "INTEGER DEFAULT 0", "next_retry_at": "TEXT",
    "last_fetch_status": "TEXT", "last_http_status": "INTEGER"
    , "site_type": "TEXT DEFAULT 'unknown'", "risk_category": "TEXT DEFAULT 'unknown'",
    "urgent_score": "INTEGER DEFAULT 0", "urgent_flag": "INTEGER DEFAULT 0",
    "urgent_reason": "TEXT", "context_only": "INTEGER DEFAULT 0",
    "policy_risk": "TEXT", "alert_eligible": "INTEGER DEFAULT 0",
    "review_reason": "TEXT", "alert_reason": "TEXT",
    "escalation_score": "INTEGER DEFAULT 0", "escalation_triggers": "TEXT",
    "triage_level": "TEXT DEFAULT 'monitor'", "triage_reason": "TEXT"
    , "restricted_signal_hash": "TEXT"
}

_SITE_CARD_TAXONOMY_COLUMNS = {
    "analyst_title": "TEXT",
    "secondary_categories": "TEXT", "marketplace_type": "TEXT",
    "page_type": "TEXT DEFAULT 'unknown'", "category_confidence": "TEXT DEFAULT 'low'",
    "category_reason": "TEXT", "category_safe_label": "TEXT", "display_group": "TEXT DEFAULT 'Other'",
    "ui_hidden_default": "INTEGER DEFAULT 0", "ui_priority": "INTEGER DEFAULT 0",
    "review_score": "INTEGER DEFAULT 0", "seen_count": "INTEGER DEFAULT 1",
    "spain_context_tags": "TEXT", "liveness_status": "TEXT DEFAULT 'unknown'",
    "content_quality": "TEXT DEFAULT 'unknown'", "restricted_outbound_count": "INTEGER DEFAULT 0",
    "adult_outbound_count": "INTEGER DEFAULT 0", "severe_outbound_count": "INTEGER DEFAULT 0",
    "restricted_outbound_ratio": "REAL DEFAULT 0", "mixed_directory": "INTEGER DEFAULT 0",
    "restricted_child_present": "INTEGER DEFAULT 0", "adult_category_present": "INTEGER DEFAULT 0",
    "search_text": "TEXT DEFAULT ''", "rollup_dirty": "INTEGER DEFAULT 0",
    "analyst_category": "TEXT", "suggested_category": "TEXT",
    "classification_decision": "TEXT DEFAULT 'unclassified'",
    "classification_confidence_score": "REAL DEFAULT 0", "classifier_version": "TEXT"
    , "importance_level": "TEXT DEFAULT 'normal'", "importance_reason": "TEXT",
    "analyst_importance": "TEXT", "analyst_notes": "TEXT",
    "analyst_suppressed_alerts": "INTEGER DEFAULT 0", "analyst_last_updated_at": "TEXT",
    "locale_paths_seen": "TEXT", "language_variants_count": "INTEGER DEFAULT 0",
    "spain_priority_reason": "TEXT", "spain_priority_evidence_type": "TEXT",
    "spain_relevance": "TEXT DEFAULT 'none'", "spain_evidence_type": "TEXT",
    "seller_geo_confidence": "TEXT DEFAULT 'none'", "spain_evidence_snippets": "TEXT",
    "spain_evidence_source_url": "TEXT", "spain_evidence_source_path": "TEXT",
    "spain_context_only": "INTEGER DEFAULT 0", "spain_actionable": "INTEGER DEFAULT 0",
    "spain_evidence_score": "INTEGER DEFAULT 0", "spain_evidence_families": "TEXT",
    "spain_evidence_direction": "TEXT DEFAULT 'context_only'",
    "representative_url": "TEXT", "detected_title": "TEXT", "title_source": "TEXT",
    "safe_site_name": "TEXT", "display_name_source": "TEXT", "unsafe_title_hidden": "INTEGER DEFAULT 0",
    "identity_pending": "INTEGER DEFAULT 0", "policy_label": "TEXT",
    "identity_confidence": "TEXT", "page_type_confidence": "TEXT",
    "page_type_evidence_json": "TEXT", "card_ready": "INTEGER DEFAULT 0",
    "card_readiness_reason": "TEXT", "card_readiness_confidence": "TEXT",
    "safe_summary": "TEXT", "link_repository_score": "INTEGER DEFAULT 0",
    "outbound_onion_count": "INTEGER DEFAULT 0", "internal_link_count": "INTEGER DEFAULT 0",
    "external_onion_count": "INTEGER DEFAULT 0"
    , "content_category": "TEXT DEFAULT 'unknown'", "safety_state": "TEXT DEFAULT 'safe'",
    "category_evidence_json": "TEXT", "category_supporting_evidence_json": "TEXT",
    "category_contradicting_evidence_json": "TEXT", "category_update_allowed": "INTEGER DEFAULT 1",
    "category_update_reason": "TEXT"
    , "child_adult_link_count": "INTEGER DEFAULT 0",
    "child_restricted_link_count": "INTEGER DEFAULT 0", "child_blocked_link_count": "INTEGER DEFAULT 0",
    "parent_evidence_json": "TEXT", "child_link_evidence_json": "TEXT",
    "report_generated_at": "TEXT", "report_error": "TEXT",
    "identity_site_id": "TEXT", "identity_domain": "TEXT", "identity_canonical_domain": "TEXT",
    "identity_brand": "TEXT", "identity_country": "TEXT", "identity_language": "TEXT",
    "identity_source_type": "TEXT", "identity_matched_from": "TEXT",
    "identity_confidence_score": "REAL DEFAULT 0", "identity_evidence_json": "TEXT",
    "identity_ambiguous": "INTEGER DEFAULT 0", "identity_ambiguity_reason": "TEXT",
    "identity_missing_fields_json": "TEXT",
    "rollup_claimed_by": "TEXT", "rollup_claimed_at": "TEXT"
    , "card_completeness_score": "INTEGER DEFAULT 0",
    "card_completeness_label": "TEXT DEFAULT 'weak'",
    "card_completeness_reason": "TEXT",
    "last_enrichment_planned_at": "TEXT"
    , "site_type": "TEXT DEFAULT 'unknown'", "risk_category": "TEXT DEFAULT 'unknown'",
    "urgent_score": "INTEGER DEFAULT 0", "urgent_flag": "INTEGER DEFAULT 0",
    "urgent_reason": "TEXT", "context_only": "INTEGER DEFAULT 0",
    "policy_risk": "TEXT", "alert_eligible": "INTEGER DEFAULT 0",
    "review_reason": "TEXT", "alert_reason": "TEXT",
    "escalation_score": "INTEGER DEFAULT 0", "escalation_triggers": "TEXT",
    "triage_level": "TEXT DEFAULT 'monitor'", "triage_reason": "TEXT",
    "card_kind": "TEXT DEFAULT 'site'", "parent_site_card_id": "INTEGER"
}

_ONION_EDGE_CONTEXT_COLUMNS = {
    "relation_type": "TEXT DEFAULT 'unknown'", "safe_anchor_text": "TEXT",
    "source_page_type": "TEXT", "same_host": "INTEGER DEFAULT 0", "policy_reason": "TEXT",
    "relation_verified": "INTEGER DEFAULT 0", "relation_evidence_source": "TEXT DEFAULT 'discovery_metadata'",
}

_WORKER_STATE_COLUMNS = {
    "worker_name": "TEXT DEFAULT 'onion_worker'", "last_heartbeat_at": "TEXT",
    "last_url_id": "INTEGER", "last_error": "TEXT", "processed_total": "INTEGER DEFAULT 0",
    "processed_today": "INTEGER DEFAULT 0", "processed_date": "TEXT", "started_at": "TEXT",
    "is_paused": "INTEGER DEFAULT 0", "last_maintenance_at": "TEXT",
    "worker_pid": "INTEGER", "rss_mb": "REAL DEFAULT 0", "current_stage": "TEXT",
    "current_url_id": "INTEGER", "fetch_started_at": "TEXT", "last_progress_at": "TEXT",
    "last_success_at": "TEXT", "last_failure_at": "TEXT", "boot_id": "TEXT"
}

_SPAIN_ALERT_CARD_COLUMNS = {
    "site_card_id": "INTEGER", "canonical_site_id": "TEXT", "alert_kind": "TEXT DEFAULT 'new'",
    "site_tree_id": "TEXT", "normalized_family": "TEXT", "hit_type": "TEXT"
}

_SPAIN_HIT_REVIEW_COLUMNS = {
    "analyst_suppressed": "INTEGER DEFAULT 0", "suppressed_at": "TEXT",
    "suppression_reason": "TEXT",
    "evidence_score": "INTEGER DEFAULT 0", "evidence_families_json": "TEXT",
    "evidence_direction": "TEXT DEFAULT 'context_only'", "context_only": "INTEGER DEFAULT 0",
    "actionable": "INTEGER DEFAULT 0", "reason_code": "TEXT", "evidence_type": "TEXT",
}

_NOTIFICATION_CONTROL_COLUMNS = {
    "daily_digest_telegram": "INTEGER DEFAULT 0",
    "immediate_spain_alerts": "INTEGER DEFAULT 1",
}

_ADULT_MEMORY_DIAGNOSTIC_COLUMNS = {
    "match_scope": "TEXT", "matched_safe_label": "TEXT", "confidence_reason": "TEXT",
    "parent_page_type": "TEXT", "parent_primary_category": "TEXT",
    "child_only": "INTEGER DEFAULT 0", "false_positive_guard_applied": "INTEGER DEFAULT 0",
    "safe_signal_labels": "TEXT", "signal_count": "INTEGER DEFAULT 0",
    "signal_ratio": "REAL DEFAULT 0", "dominance_score": "REAL DEFAULT 0",
    "context_window_count": "INTEGER DEFAULT 0", "ocr_checked": "INTEGER DEFAULT 0",
    "ocr_restricted_hit": "INTEGER DEFAULT 0"
}

_EVIDENCE_CARD_COLUMNS = {"site_card_id": "INTEGER"}

_ACTOR_OBSERVATION_COLUMNS = {
    "seller_observation": "INTEGER DEFAULT 0",
    "spain_flow": "TEXT DEFAULT 'none'",
    "marketplace_category": "TEXT",
    "profile_identity": "TEXT", "profile_url": "TEXT", "source_scope": "TEXT",
    "evidence_signals_json": "TEXT", "bound_identifier_count": "INTEGER DEFAULT 0",
}

_ACTOR_COLUMNS = {
    "identity_key": "TEXT", "identity_kind": "TEXT DEFAULT 'host_alias'",
    "canonical_profile_identity": "TEXT", "canonical_profile_url": "TEXT",
    "alias_skeleton": "TEXT", "identity_confidence": "REAL DEFAULT 0",
}

_ACTOR_IDENTIFIER_COLUMNS = {
    "observation_id": "INTEGER", "binding_method": "TEXT DEFAULT 'legacy_unscoped'",
    "source_scope": "TEXT",
}

_ACTOR_CONNECTION_COLUMNS = {
    "warning_type": "TEXT",
    "warning_reason": "TEXT",
    "migration_candidate": "INTEGER DEFAULT 0",
}

_DEEP_DISCOVERY_JOB_COLUMNS = {
    "next_retry_at": "TEXT",
    "error_type": "TEXT",
    "failed_at": "TEXT",
    "dead_letter_reason": "TEXT",
    "anchor_hash": "TEXT",
    "anchor_revision": "INTEGER DEFAULT 1",
    "pending_anchor_snapshot_json": "TEXT",
    "pending_anchor_hash": "TEXT",
}

_DEEP_DISCOVERY_RUN_COLUMNS = {
    "worker_id": "TEXT",
    "anchor_hash": "TEXT",
    "provider_status_json": "TEXT",
}

_ENTITY_EXPANSION_PROPOSAL_COLUMNS = {
    "enqueued_onion_url_id": "INTEGER",
}

_FETCHED_PAGE_LIFECYCLE_COLUMNS = {
    "attempts": "INTEGER DEFAULT 0",
    "max_attempts": "INTEGER DEFAULT 4",
    "next_retry_at": "TEXT",
    "last_error": "TEXT",
    "error_type": "TEXT",
    "failed_at": "TEXT",
    "dead_letter_reason": "TEXT",
}

_SITE_CARD_JOB_LIFECYCLE_COLUMNS = {
    "max_attempts": "INTEGER DEFAULT 4",
    "next_retry_at": "TEXT",
    "error_type": "TEXT",
    "failed_at": "TEXT",
    "dead_letter_reason": "TEXT",
}

_PAGE_PREVIEW_JOB_COLUMNS = {
    "priority": "TEXT DEFAULT 'auto'",
    "priority_score": "INTEGER DEFAULT 0",
    "requested_by": "TEXT",
    "requested_at": "TEXT",
    "request_reason": "TEXT",
    "force": "INTEGER DEFAULT 0",
    "max_attempts": "INTEGER DEFAULT 4",
    "next_retry_at": "TEXT",
    "error_type": "TEXT",
    "failed_at": "TEXT",
    "dead_letter_reason": "TEXT",
}

_FORUM_EXPANSION_EVENT_COLUMNS = {
    "trigger_identity_hash": "TEXT",
}


def _ensure_columns(db: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    existing = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
    for name, definition in columns.items():
        if name not in existing:
            try:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
                existing.add(name)
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc).casefold():
                    raise
                existing = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}


def _forum_trigger_identity_hash(onion_host: str, trigger_url: str) -> str:
    """Return a metadata-safe identity for one logical forum trigger resource.

    Known forum thread/post URL variants use the conservative identity parser.
    Unknown routes fall back to its canonical URL, which removes only established
    session, tracking, and pagination noise while retaining the resource path and
    all other query parameters.
    """
    host = str(onion_host or "").strip().casefold()
    exact = str(trigger_url or "").strip()
    identity = classify_forum_url(exact)
    if identity.case_identity and identity.host == host:
        identity_kind = "case"
        resource_identity = identity.case_identity
    else:
        identity_kind = "canonical"
        resource_identity = identity.canonical_url or _canonical_url(exact) or exact
    material = f"forum-expansion:v1\n{host}\n{identity_kind}\n{resource_identity}"
    return hashlib.sha256(material.encode("utf-8", "ignore")).hexdigest()


def _migrate_forum_expansion_identities(db: sqlite3.Connection) -> None:
    """Backfill durable logical identities without deleting legacy audit rows."""
    if db.execute("""SELECT 1 FROM sqlite_master
      WHERE type='index' AND name='idx_forum_expansion_identity'""").fetchone():
        return
    rows = list(db.execute("""SELECT rowid,trigger_url,onion_host,trigger_identity_hash
      FROM forum_expansion_events ORDER BY COALESCE(created_at,''),rowid"""))
    claimed: set[tuple[str, str]] = set()
    for row in rows:
        host = str(row["onion_host"] or "").strip().casefold()
        identity_hash = _forum_trigger_identity_hash(host, row["trigger_url"])
        key = (host, identity_hash)
        # Historical versions could already have expanded more than once for
        # URL variants.  Keep every event for audit, but only the first event
        # claims the logical identity used for all future idempotence checks.
        stored_hash = identity_hash if key not in claimed else None
        if row["trigger_identity_hash"] != stored_hash or row["onion_host"] != host:
            db.execute("""UPDATE forum_expansion_events
              SET onion_host=?,trigger_identity_hash=? WHERE rowid=?""",
                       (host, stored_hash, row["rowid"]))
        claimed.add(key)
    db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS idx_forum_expansion_identity
      ON forum_expansion_events(onion_host,trigger_identity_hash)
      WHERE trigger_identity_hash IS NOT NULL""")


def _actor_identity_key(onion_host: str, normalized_alias: str,
                        profile_identity: str | None = None) -> str:
    """Return a deterministic, non-sensitive identity key for one public profile."""
    host = str(onion_host or "").strip().casefold()
    alias = str(normalized_alias or "").strip().casefold()
    profile = str(profile_identity or "").strip().casefold()
    material = f"{host}\n{profile or 'alias:' + alias}"
    return "actor:" + hashlib.sha256(material.encode("utf-8", "ignore")).hexdigest()


def _migrate_actor_identity_model(db: sqlite3.Connection) -> None:
    """Replace legacy alias+host uniqueness while preserving actor IDs and data."""
    table = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='actors'").fetchone()
    if not table:
        return
    table_sql = "".join(str(table[0] or "").casefold().split())
    legacy_unique = "unique(normalized_alias,onion_host)" in table_sql
    if not legacy_unique:
        rows = list(db.execute("SELECT id,onion_host,normalized_alias,identity_key FROM actors"))
        for row in rows:
            if not row["identity_key"]:
                db.execute("""UPDATE actors SET identity_key=?,
                  identity_kind=COALESCE(identity_kind,'host_alias') WHERE id=?""",
                           (_actor_identity_key(row["onion_host"], row["normalized_alias"]), row["id"]))
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_actors_identity_key ON actors(identity_key)")
        return

    rows = [dict(row) for row in db.execute("SELECT * FROM actors ORDER BY id")]
    db.commit()
    db.execute("PRAGMA foreign_keys = OFF")
    try:
        _begin_immediate(db, "init_db", None)
        db.execute("DROP TABLE IF EXISTS actors_identity_v2")
        db.execute("""CREATE TABLE actors_identity_v2 (
          id INTEGER PRIMARY KEY AUTOINCREMENT, normalized_alias TEXT NOT NULL,
          display_alias TEXT NOT NULL, onion_host TEXT NOT NULL, generic_role INTEGER DEFAULT 0,
          first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, observation_count INTEGER DEFAULT 0,
          spain_observation_count INTEGER DEFAULT 0, watched INTEGER DEFAULT 0, watch_reason TEXT,
          analyst_status TEXT DEFAULT 'unreviewed', confidence_score REAL DEFAULT 0,
          confidence_label TEXT DEFAULT 'low', latest_url TEXT, primary_category TEXT,
          risk_level TEXT, identity_key TEXT UNIQUE,
          identity_kind TEXT DEFAULT 'host_alias', canonical_profile_identity TEXT,
          canonical_profile_url TEXT, alias_skeleton TEXT, identity_confidence REAL DEFAULT 0
        )""")
        columns = (
            "id", "normalized_alias", "display_alias", "onion_host", "generic_role",
            "first_seen", "last_seen", "observation_count", "spain_observation_count",
            "watched", "watch_reason", "analyst_status", "confidence_score",
            "confidence_label", "latest_url", "primary_category", "risk_level",
            "identity_key", "identity_kind", "canonical_profile_identity",
            "canonical_profile_url", "alias_skeleton", "identity_confidence",
        )
        marks = ",".join("?" for _ in columns)
        for row in rows:
            identity = row.get("identity_key") or _actor_identity_key(
                row.get("onion_host"), row.get("normalized_alias"),
                row.get("canonical_profile_identity"))
            values = tuple(
                identity if name == "identity_key"
                else row.get(name)
                if name in row
                else "host_alias" if name == "identity_kind"
                else 0 if name == "identity_confidence"
                else None
                for name in columns
            )
            db.execute(f"INSERT INTO actors_identity_v2({','.join(columns)}) VALUES({marks})", values)
        db.execute("DROP TABLE actors")
        db.execute("ALTER TABLE actors_identity_v2 RENAME TO actors")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_actors_identity_key ON actors(identity_key)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_actors_spain_watch ON actors(spain_observation_count,watched,last_seen)")
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.execute("PRAGMA foreign_keys = ON")
    if list(db.execute("PRAGMA foreign_key_check")):
        raise sqlite3.IntegrityError("actor_identity_migration_foreign_key_failure")


def _normalize_classification_vocabulary(db: sqlite3.Connection) -> None:
    """Mechanically migrate legacy labels without touching analyst decisions."""
    from classification_schema import (CONTENT_CATEGORY_ALIASES, PAGE_TYPE_ALIASES,
                                       derive_safety_state, normalize_content_category,
                                       normalize_page_type)
    for table in ("onion_urls", "site_cards"):
        legacy_types = tuple(PAGE_TYPE_ALIASES)
        legacy_categories = tuple(CONTENT_CATEGORY_ALIASES)
        type_marks = ",".join("?" for _ in legacy_types)
        category_marks = ",".join("?" for _ in legacy_categories)
        rows = db.execute(f"""SELECT id,primary_category,page_type,storage_policy FROM {table}
          WHERE content_category IS NULL OR content_category!=primary_category OR safety_state IS NULL
          OR page_type IN ({type_marks}) OR primary_category IN ({category_marks})
          OR (storage_policy='metadata_limited' AND safety_state!='metadata_limited')
          OR (storage_policy='metadata_only' AND safety_state!='metadata_only')
          OR (storage_policy='discard' AND safety_state NOT IN ('filtered','discarded'))""",
          (*legacy_types, *legacy_categories)).fetchall()
        for row in rows:
            old_category = str(row["primary_category"] or "unknown").casefold()
            old_type = str(row["page_type"] or "unknown").casefold()
            category = normalize_content_category(old_category)
            page_type = normalize_page_type(old_type)
            state = derive_safety_state({"primary_category": category,
                                         "storage_policy": row["storage_policy"]})
            db.execute(f"""UPDATE {table} SET primary_category=?,content_category=?,page_type=?,
              safety_state=? WHERE id=?""", (category, category, page_type, state, row["id"]))


def _seed_builtin_investigations(db: sqlite3.Connection) -> None:
    now = utc_now_iso()
    builtins = [
        ("Spain · Needs review", "Unacknowledged Spain-linked results", {"priority": "Spain Priority", "review": "needs_review"}),
        ("Spain · Weapons", "Spain-linked weapons context", {"priority": "Spain + weapons"}),
        ("High risk · Unreviewed", "High or critical results awaiting review", {"priority": "High risk", "review": "needs_review"}),
        ("Fraud and carding", "Fraud-related marketplaces and pages", {"category": "fraud_financial"}),
        ("Leaks and credentials", "Potential exposed data and credential results", {"priority": "Leaks / credentials"}),
        ("New discoveries", "Newest Site Cards", {"sort": "Newest first"}),
    ]
    for name, description, filters in builtins:
        db.execute("""INSERT INTO saved_investigations
          (name,description,filters_json,builtin,created_at,updated_at) VALUES(?,?,?,?,?,?)
          ON CONFLICT(name) DO UPDATE SET description=excluded.description,
          filters_json=excluded.filters_json,builtin=1,updated_at=excluded.updated_at""",
          (name, description, json.dumps(filters, ensure_ascii=False), 1, now, now))


def _cleanup_legacy_bundled_examples(db: sqlite3.Connection) -> int:
    """Remove the old opt-in synthetic identity fixture from upgraded databases.

    Matching is deliberately limited to the exact historical safety marker and
    fixed synthetic hosts. Normal crawler, analyst, Watchlist, and seed data is
    never selected by this migration.
    """
    rows = list(db.execute("""SELECT id,url,site_card_id FROM onion_urls
      WHERE safety_reason='fictional_demo'"""))
    if not rows:
        return 0
    url_ids = [int(row["id"]) for row in rows]
    urls = [str(row["url"]) for row in rows]
    card_ids = {int(row["site_card_id"]) for row in rows if row["site_card_id"]}
    card_ids.update(int(row[0]) for row in db.execute(
        f"SELECT DISTINCT site_card_id FROM site_card_urls WHERE onion_url_id IN ({','.join('?' for _ in url_ids)})",
        tuple(url_ids)) if row[0])
    actor_ids = {int(row[0]) for row in db.execute(
        f"SELECT DISTINCT actor_id FROM actor_observations WHERE url IN ({','.join('?' for _ in urls)})",
        tuple(urls))}

    url_marks = ",".join("?" for _ in urls)
    id_marks = ",".join("?" for _ in url_ids)
    cards = sorted(card_ids)
    actors = sorted(actor_ids)
    actor_marks = ",".join("?" for _ in actors)

    url_candidate_ids = [int(row[0]) for row in db.execute(
        f"SELECT id FROM actor_candidates WHERE url IN ({url_marks})", tuple(urls))]
    if url_candidate_ids:
        candidate_marks = ",".join("?" for _ in url_candidate_ids)
        db.execute(f"DELETE FROM actor_candidate_events WHERE candidate_id IN ({candidate_marks})",
                   tuple(url_candidate_ids))

    if actors:
        job_ids = [int(row[0]) for row in db.execute(
            f"SELECT id FROM deep_discovery_jobs WHERE actor_id IN ({actor_marks})", tuple(actors))]
        if job_ids:
            job_marks = ",".join("?" for _ in job_ids)
            db.execute(f"DELETE FROM deep_discovery_runs WHERE job_id IN ({job_marks})", tuple(job_ids))
        db.execute(f"DELETE FROM deep_discovery_runs WHERE actor_id IN ({actor_marks})", tuple(actors))
        db.execute(f"DELETE FROM deep_discovery_jobs WHERE actor_id IN ({actor_marks})", tuple(actors))
        connection_ids = [int(row[0]) for row in db.execute(
            f"SELECT id FROM actor_connections WHERE source_actor_id IN ({actor_marks}) OR target_actor_id IN ({actor_marks})",
            tuple(actors) + tuple(actors))]
        db.execute(f"DELETE FROM actor_events WHERE actor_id IN ({actor_marks})", tuple(actors))
        if connection_ids:
            connection_marks = ",".join("?" for _ in connection_ids)
            db.execute(f"DELETE FROM actor_events WHERE connection_id IN ({connection_marks})", tuple(connection_ids))
        db.execute(f"DELETE FROM actor_watch_alerts WHERE actor_id IN ({actor_marks}) OR related_actor_id IN ({actor_marks})",
                   tuple(actors) + tuple(actors))
        db.execute(f"DELETE FROM actor_connections WHERE source_actor_id IN ({actor_marks}) OR target_actor_id IN ({actor_marks})",
                   tuple(actors) + tuple(actors))
        db.execute(f"DELETE FROM actor_candidate_events WHERE actor_id IN ({actor_marks})", tuple(actors))
        db.execute(f"DELETE FROM entity_expansion_proposals WHERE actor_id IN ({actor_marks})", tuple(actors))
        candidate_ids = [int(row[0]) for row in db.execute(
            f"SELECT id FROM actor_candidates WHERE actor_id IN ({actor_marks})", tuple(actors))]
        if candidate_ids:
            candidate_marks = ",".join("?" for _ in candidate_ids)
            db.execute(f"DELETE FROM actor_candidate_events WHERE candidate_id IN ({candidate_marks})",
                       tuple(candidate_ids))
        db.execute(f"DELETE FROM actor_candidates WHERE actor_id IN ({actor_marks})", tuple(actors))
        identifier_ids = [int(row[0]) for row in db.execute(
            f"SELECT id FROM actor_identifiers WHERE actor_id IN ({actor_marks})", tuple(actors))]
        if identifier_ids:
            identifier_marks = ",".join("?" for _ in identifier_ids)
            db.execute(f"DELETE FROM actor_identifier_observations WHERE actor_identifier_id IN ({identifier_marks})",
                       tuple(identifier_ids))
        db.execute(f"DELETE FROM actor_identifiers WHERE actor_id IN ({actor_marks})", tuple(actors))
        db.execute(f"DELETE FROM actor_aliases WHERE actor_id IN ({actor_marks})", tuple(actors))
        db.execute(f"DELETE FROM actor_observations WHERE actor_id IN ({actor_marks})", tuple(actors))
        db.execute(f"DELETE FROM actors WHERE id IN ({actor_marks})", tuple(actors))

    for table, column in (
        ("fetched_pages", "onion_url_id"), ("frontier_deferred_urls", "url_id"),
        ("onion_url_sources", "onion_url_id"), ("adult_filter_memory", "onion_url_id"),
        ("classification_decisions", "onion_url_id"), ("page_change_events", "onion_url_id"),
        ("page_preview_jobs", "onion_url_id"), ("possible_site_card_matches", "onion_url_id"),
        ("site_fingerprints", "onion_url_id"), ("site_card_jobs", "onion_url_id"),
        ("spain_hits", "onion_url_id"),
        ("site_card_urls", "onion_url_id"),
        ("actor_candidates", "onion_url_id"),
    ):
        db.execute(f"DELETE FROM {table} WHERE {column} IN ({id_marks})", tuple(url_ids))
    for table, column in (
        ("onion_hits", "url"), ("page_previews", "url"), ("site_profiles", "url"),
        ("page_topics", "url"), ("onion_tags", "url"), ("safety_rule_matches", "url"),
        ("crawl_audit_log", "url"), ("restricted_items", "url"),
        ("passive_exposures", "url"), ("indicator_links", "source_ref"),
        ("mirror_urls", "url"), ("page_preview_jobs", "url"), ("site_card_jobs", "url"),
        ("spain_alert_queue", "url"),
        ("actor_candidates", "url"),
        ("entity_expansion_proposals", "parent_url"),
        ("entity_expansion_proposals", "proposed_url"),
    ):
        db.execute(f"DELETE FROM {table} WHERE {column} IN ({url_marks})", tuple(urls))
    db.execute(f"DELETE FROM onion_edges WHERE source_url IN ({url_marks}) OR discovered_url IN ({url_marks})",
               tuple(urls) + tuple(urls))
    db.execute(f"DELETE FROM restricted_items WHERE source_url IN ({url_marks})", tuple(urls))
    db.execute(f"DELETE FROM onion_urls WHERE id IN ({id_marks})", tuple(url_ids))

    if cards:
        orphan_cards = [card_id for card_id in cards if not db.execute(
            "SELECT 1 FROM site_card_urls WHERE site_card_id=? LIMIT 1", (card_id,)).fetchone()]
        retained_cards = sorted(set(cards) - set(orphan_cards))
        if retained_cards:
            retained_marks = ",".join("?" for _ in retained_cards)
            db.execute(f"UPDATE site_cards SET rollup_dirty=1 WHERE id IN ({retained_marks})",
                       tuple(retained_cards))
        if orphan_cards:
            orphan_marks = ",".join("?" for _ in orphan_cards)
            for table in ("deep_discovery_runs", "deep_discovery_jobs", "page_preview_jobs",
                          "site_card_jobs", "evidence_reports", "spain_hits",
                          "classification_decisions", "page_change_events", "crawl_coverage",
                          "site_card_events", "site_fingerprints"):
                db.execute(f"DELETE FROM {table} WHERE site_card_id IN ({orphan_marks})",
                           tuple(orphan_cards))
            db.execute(f"DELETE FROM possible_site_card_matches WHERE candidate_site_card_id IN ({orphan_marks})",
                       tuple(orphan_cards))
            db.execute(f"DELETE FROM site_cards WHERE id IN ({orphan_marks})", tuple(orphan_cards))
    db.execute("DELETE FROM indicators WHERE id NOT IN (SELECT DISTINCT indicator_id FROM indicator_links)")
    db.execute("DELETE FROM mirror_clusters WHERE id NOT IN (SELECT DISTINCT cluster_id FROM mirror_urls WHERE cluster_id IS NOT NULL)")
    return len(rows)


def init_db() -> None:
    severe_cleanup_needed = False
    with get_db() as db:
        current_schema_version = int(db.execute("PRAGMA user_version").fetchone()[0])
        if current_schema_version > MAIN_SCHEMA_VERSION:
            raise sqlite3.DatabaseError(
                "main_database_schema_is_newer_than_this_release:"
                f"{current_schema_version}>{MAIN_SCHEMA_VERSION}"
            )
        # WAL lets the dashboard read while the worker writes. This is applied
        # before migrations and no transaction is held across network work.
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript(_SCHEMA)
        _ensure_columns(db, "onion_urls", _ONION_POLICY_COLUMNS)
        _ensure_columns(db, "crawler_worker_state", _WORKER_STATE_COLUMNS)
        _ensure_columns(db, "site_cards", _SITE_CARD_TAXONOMY_COLUMNS)
        _ensure_columns(db, "onion_edges", _ONION_EDGE_CONTEXT_COLUMNS)
        _ensure_columns(db, "spain_alert_queue", _SPAIN_ALERT_CARD_COLUMNS)
        _ensure_columns(db, "spain_hits", _SPAIN_HIT_REVIEW_COLUMNS)
        _ensure_columns(db, "notification_control", _NOTIFICATION_CONTROL_COLUMNS)
        _ensure_columns(db, "adult_filter_memory", _ADULT_MEMORY_DIAGNOSTIC_COLUMNS)
        _ensure_columns(db, "evidence_reports", _EVIDENCE_CARD_COLUMNS)
        _ensure_columns(db, "actors", _ACTOR_COLUMNS)
        _ensure_columns(db, "actor_observations", _ACTOR_OBSERVATION_COLUMNS)
        _ensure_columns(db, "actor_identifiers", _ACTOR_IDENTIFIER_COLUMNS)
        _ensure_columns(db, "actor_connections", _ACTOR_CONNECTION_COLUMNS)
        _ensure_columns(db, "deep_discovery_jobs", _DEEP_DISCOVERY_JOB_COLUMNS)
        _ensure_columns(db, "deep_discovery_runs", _DEEP_DISCOVERY_RUN_COLUMNS)
        _ensure_columns(db, "entity_expansion_proposals", _ENTITY_EXPANSION_PROPOSAL_COLUMNS)
        db.execute("""CREATE INDEX IF NOT EXISTS idx_entity_expansion_destination
          ON entity_expansion_proposals(enqueued_onion_url_id,status)""")
        _ensure_columns(db, "fetched_pages", _FETCHED_PAGE_LIFECYCLE_COLUMNS)
        _ensure_columns(db, "site_card_jobs", _SITE_CARD_JOB_LIFECYCLE_COLUMNS)
        _ensure_columns(db, "page_preview_jobs", _PAGE_PREVIEW_JOB_COLUMNS)
        _ensure_columns(db, "forum_expansion_events", _FORUM_EXPANSION_EVENT_COLUMNS)
        _migrate_forum_expansion_identities(db)
        _migrate_actor_identity_model(db)
        _cleanup_legacy_bundled_examples(db)
        _normalize_classification_vocabulary(db)
        db.execute("INSERT OR IGNORE INTO notification_control(id,spain_alerts_paused,updated_at) VALUES(1,0,?)",
                   (utc_now_iso(),))
        _seed_builtin_investigations(db)
        # Transport state is not content evidence.  Historical ``crawled``,
        # ``dead``, and ``blocked`` rows were once promoted to verified merely
        # because a request had completed.  Demote only those unproven rows;
        # current parser-proven and explicit analyst decisions remain durable.
        db.execute("""UPDATE onion_urls SET verification_state='discovered',
          verified_at=NULL,
          verification_reason=CASE
            WHEN verification_reason='page_fetched_and_classified'
              THEN 'legacy_page_without_content_boundary'
            ELSE verification_reason END
          WHERE COALESCE(destination_html_evidence_version,0)<?
          AND analyst_category IS NULL
          AND COALESCE(verification_state,'discovered')='verified'""",
          (DESTINATION_HTML_EVIDENCE_VERSION,))
        db.execute("""UPDATE onion_urls SET
          suggested_category=CASE WHEN COALESCE(primary_category,'unknown')!='unknown'
            THEN primary_category ELSE suggested_category END,
          primary_category='unknown',category='unknown',content_category='unknown',
          category_confidence='low',category_reason='Awaiting destination HTML classification',
          category_safe_label='Needs classification',display_group='Other',
          classification_decision='unverified_hint',classification_stage='prefetch',
          classification_confidence_score=0,tags='[]',risk_flags='[]',risk_level='low',
          site_type='unknown',risk_category='unknown',urgent_flag=0,urgent_score=0,
          urgent_reason=NULL,context_only=0,
          storage_policy=CASE WHEN primary_category IN
            ('adult_filtered','adult_restricted','severe_abuse_risk') THEN 'safe_summary'
            ELSE storage_policy END,
          review_status=CASE WHEN primary_category IN
            ('adult_filtered','adult_restricted','severe_abuse_risk') THEN 'monitor'
            ELSE review_status END,
          safety_reason=CASE WHEN primary_category IN
            ('adult_filtered','adult_restricted','severe_abuse_risk') THEN 'awaiting_destination_html'
            ELSE safety_reason END,
          queue_policy=CASE WHEN primary_category IN
            ('adult_filtered','adult_restricted','severe_abuse_risk') THEN 'normal'
            ELSE queue_policy END,
          active=CASE WHEN primary_category IN
            ('adult_filtered','adult_restricted','severe_abuse_risk') THEN 1 ELSE active END,
          status=CASE WHEN primary_category IN
            ('adult_filtered','adult_restricted','severe_abuse_risk') THEN 'queued' ELSE status END,
          next_crawl_at=CASE WHEN primary_category IN
            ('adult_filtered','adult_restricted','severe_abuse_risk') THEN COALESCE(next_crawl_at,?)
            ELSE next_crawl_at END,
          screenshot_policy=CASE WHEN primary_category IN
            ('adult_filtered','adult_restricted','severe_abuse_risk') THEN 'blocked'
            ELSE screenshot_policy END,
          screenshot_blocked_reason=CASE WHEN primary_category IN
            ('adult_filtered','adult_restricted','severe_abuse_risk') THEN 'awaiting_destination_html'
            ELSE screenshot_blocked_reason END
          WHERE COALESCE(destination_html_evidence_version,0)<?
          AND analyst_category IS NULL
          AND COALESCE(primary_category,'unknown')!='unknown'
          AND NOT EXISTS (SELECT 1 FROM adult_filter_memory afm
            WHERE afm.onion_url_id=onion_urls.id AND afm.analyst_decision='blocked'
            AND afm.reviewed_at IS NOT NULL)""",
          (utc_now_iso(), DESTINATION_HTML_EVIDENCE_VERSION))
        db.execute("""UPDATE site_cards SET rollup_dirty=1 WHERE id IN (
          SELECT DISTINCT site_card_id FROM onion_urls
          WHERE site_card_id IS NOT NULL
           AND COALESCE(destination_html_evidence_version,0)<?
           AND analyst_category IS NULL)""", (DESTINATION_HTML_EVIDENCE_VERSION,))
        db.execute("""UPDATE site_cards SET primary_category='unknown',content_category='unknown',
          category_confidence='low',category_reason='Awaiting destination HTML classification',
          category_safe_label='Needs classification',display_group='Other',risk_level='low',
          risk_flags='[]',site_type='unknown',risk_category='unknown',
          urgent_flag=0,urgent_score=0,urgent_reason=NULL,context_only=0,
          storage_policy='safe_summary',review_status='monitor',safety_state='safe',
          page_type='unknown',secondary_categories='[]',marketplace_type=NULL,
          ui_hidden_default=0,ui_priority=0,review_score=0,
          alert_eligible=0,rollup_dirty=1
          WHERE analyst_category IS NULL AND NOT EXISTS (
            SELECT 1 FROM site_card_urls scu JOIN onion_urls ou ON ou.id=scu.onion_url_id
             WHERE scu.site_card_id=site_cards.id AND (
               (ou.analyst_category IS NOT NULL
                 AND trim(ou.analyst_category)!=''
                 AND ou.primary_category=ou.analyst_category)
               OR (ou.classification_evidence_source='destination_html'
                 AND COALESCE(ou.destination_html_evidence_version,0)>=?
                 AND ou.verification_state='verified'
                 AND ou.verification_reason='page_fetched_and_classified')
             ))""", (DESTINATION_HTML_EVIDENCE_VERSION,))
        db.execute("""UPDATE onion_urls SET ui_hidden_default=1,
          review_status=CASE WHEN review_status IN ('relevant','false_positive','needs_report','reported','blocked')
            THEN review_status WHEN suggested_category IS NOT NULL THEN 'needs_review' ELSE 'monitor' END,
          category_safe_label=CASE WHEN suggested_category IS NOT NULL THEN 'Needs classification'
            ELSE 'Insufficient page evidence' END
           WHERE primary_category='unknown' AND verification_state='verified'""")
        db.execute("""UPDATE onion_urls SET status='queued',active=1,queue_policy='normal',
          storage_policy='safe_summary',review_status='monitor',next_crawl_at=COALESCE(next_crawl_at,?),
          safety_reason='awaiting_destination_html',screenshot_policy='blocked',
          screenshot_blocked_reason='awaiting_destination_html'
           WHERE primary_category='unknown' AND analyst_category IS NULL
          AND NOT (classification_evidence_source='destination_html'
            AND COALESCE(destination_html_evidence_version,0)>=?
            AND verification_state='verified')
          AND status='blocked' AND COALESCE(safety_reason,'') IN (
            'adult_content_filtered','adult_restricted','adult_marketplace_category',
            'adult_marketplace_dominant','severe_abuse_risk','severe_abuse_blackhole',
            'severe_content_filtered','awaiting_destination_html')""",
          (utc_now_iso(), DESTINATION_HTML_EVIDENCE_VERSION))
        db.execute("""UPDATE site_cards SET ui_hidden_default=1,rollup_dirty=1
          WHERE primary_category='unknown'""")
        db.execute("UPDATE onion_urls SET active=0 WHERE status IN ('blocked','dead')")
        db.execute("""UPDATE onion_urls SET classification_decision='analyst_confirmed',
          classification_confidence_score=1.0,classifier_version='analyst-v1',classification_stage='analyst',
          suggested_category=COALESCE(suggested_category,analyst_category),
          primary_category=analyst_category,category=analyst_category,
          content_category=analyst_category,classification_evidence_source='analyst',
          destination_html_evidence_version=0,verification_state='verified',
          verification_reason='analyst_confirmed',verified_at=COALESCE(verified_at,?)
          WHERE analyst_category IS NOT NULL AND trim(analyst_category)!=''
          AND (COALESCE(classification_decision,'unclassified')!='analyst_confirmed'
            OR primary_category!=analyst_category OR classification_evidence_source!='analyst')""",
          (utc_now_iso(),))
        db.execute("""UPDATE site_cards SET classification_decision='analyst_confirmed',
          classification_confidence_score=1.0,classifier_version='analyst-v1',
          suggested_category=COALESCE(suggested_category,analyst_category),
          primary_category=analyst_category,content_category=analyst_category,rollup_dirty=1
          WHERE analyst_category IS NOT NULL AND trim(analyst_category)!=''
          AND (COALESCE(classification_decision,'unclassified')!='analyst_confirmed'
            OR primary_category!=analyst_category)""")
        db.execute("""UPDATE spain_alert_queue SET status='classified'
          WHERE status='pending' AND site_card_id IN
          (SELECT id FROM site_cards WHERE classification_decision IN ('accepted','analyst_confirmed'))""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_onion_urls_active_priority ON onion_urls(active,priority_score,status)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_onion_urls_spain ON onion_urls(spain_priority,spain_review_status)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_onion_urls_site_card ON onion_urls(site_card_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_onion_urls_frontier_priority ON onion_urls(active,status,frontier_priority)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_onion_urls_family ON onion_urls(url_family)")
        db.execute("""CREATE INDEX IF NOT EXISTS idx_site_cards_dashboard_filter ON site_cards
          (ui_hidden_default,spain_priority,review_status,primary_category,risk_level,updated_at)""")
        db.execute("""CREATE INDEX IF NOT EXISTS idx_site_cards_review_queue ON site_cards
          (review_status,ui_hidden_default,live_url_count,review_score,ui_priority)""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_site_cards_liveness ON site_cards(liveness_status,live_url_count,dead_url_count)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_site_cards_category ON site_cards(primary_category,updated_at)")
        db.execute("""CREATE INDEX IF NOT EXISTS idx_site_card_urls_card_status ON site_card_urls
          (site_card_id,status,active,url_role)""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_site_card_urls_card_seen ON site_card_urls(site_card_id,last_seen)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_site_card_urls_host_path ON site_card_urls(onion_host,path)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_onion_urls_site_review ON onion_urls(site_card_id,review_status,spain_priority)")
        db.execute("""CREATE INDEX IF NOT EXISTS idx_onion_urls_frontier_pick ON onion_urls
          (active,status,next_crawl_at,frontier_priority,priority_score)""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_onion_urls_family_stats ON onion_urls(url_family,status,active)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_onion_urls_canonical_url ON onion_urls(canonical_url)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_onion_urls_canonical_root ON onion_urls(canonical_root,site_card_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_onion_urls_entity_identity ON onion_urls(entity_identity,site_card_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_onion_urls_host_status ON onion_urls(onion_domain,status,active)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_actors_identity_key ON actors(identity_key)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_actor_observations_profile ON actor_observations(actor_id,profile_identity,last_seen)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_actor_identifiers_observation ON actor_identifiers(observation_id,binding_method)")
        db.execute("""CREATE INDEX IF NOT EXISTS idx_onion_urls_claim_queue ON onion_urls
          (active,status,next_retry_at,next_crawl_at,frontier_priority,novelty_score,priority_score)""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_onion_urls_source ON onion_urls(source_url)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_onion_edges_discovered ON onion_edges(discovered_url)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_site_cards_importance ON site_cards(importance_level,updated_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_spain_alert_tree ON spain_alert_queue(site_tree_id,id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_spain_alert_card ON spain_alert_queue(site_card_id,id)")
        migration_name = "severe_blackhole_v3_context_20260713"
        migration = db.execute("SELECT status,started_at FROM data_migrations WHERE name=?", (migration_name,)).fetchone()
        stale_running = False
        if migration and migration["status"] == "running":
            try:
                started = datetime.fromisoformat(str(migration["started_at"]).replace("Z", "+00:00"))
                stale_running = started < datetime.now(timezone.utc) - timedelta(minutes=10)
            except (TypeError, ValueError):
                stale_running = True
        severe_cleanup_needed = (not migration or migration["status"] == "failed" or stale_running)
        if severe_cleanup_needed:
            db.execute("""INSERT INTO data_migrations(name,status,started_at,completed_at,safe_result_json)
              VALUES(?,'running',?,NULL,NULL) ON CONFLICT(name) DO UPDATE SET
              status='running',started_at=excluded.started_at,completed_at=NULL""",
              (migration_name, utc_now_iso()))
        # Version zero represents every legacy database produced before explicit
        # schema versioning.  The additive migration path above remains the sole
        # upgrade path and is deliberately rerunnable; stamp only after all schema
        # and normalization work in this transaction has succeeded.
        db.execute(f"PRAGMA user_version = {MAIN_SCHEMA_VERSION}")
        # Full-table cleanup, taxonomy, tag, ANALYZE, and card rebuild jobs are
        # intentionally explicit maintenance commands.  Schema initialization is
        # cheap and deterministic so worker restarts cannot trigger an OOM loop.
    if severe_cleanup_needed:
        try:
            result = cleanup_severe_blackhole_items(dry_run=False)
        except Exception as exc:
            with get_db() as db:
                db.execute("""UPDATE data_migrations SET status='failed',completed_at=?,safe_result_json=?
                  WHERE name=?""",
                  (utc_now_iso(), json.dumps({"error_type": type(exc).__name__}, sort_keys=True),
                   migration_name))
            raise
        else:
            with get_db() as db:
                db.execute("""UPDATE data_migrations SET status='complete',completed_at=?,safe_result_json=?
                  WHERE name=?""",
                  (utc_now_iso(), json.dumps(result, ensure_ascii=True, sort_keys=True), migration_name))


def ensure_db_initialized() -> None:
    """Initialize the current DB path once per process for render-time callers.

    Tests, maintenance commands, and migrations should keep calling init_db()
    directly when they intentionally need idempotent normalization to rerun.
    """
    global _ENSURE_DONE_FOR_PATH
    db_path_key = str(DB_PATH.resolve() if hasattr(DB_PATH, "resolve") else DB_PATH)
    with _ENSURE_INIT_LOCK:
        if _ENSURE_DONE_FOR_PATH == db_path_key and Path(DB_PATH).exists():
            return
        init_db()
        _ENSURE_DONE_FOR_PATH = db_path_key


def _dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row else None


def backfill_searchable_category_tags() -> dict[str, int]:
    """Add safe category aliases and confirmed-Spain tags to existing rows."""
    from universal_classifier import category_search_tags

    counts = {"urls": 0, "cards": 0}
    restricted = {"adult_filtered", "adult_restricted", "severe_abuse_risk"}
    with get_db() as db:
        urls = [dict(row) for row in db.execute("""SELECT id,primary_category,tags,spain_priority,
          spain_analyst_suppressed,classification_decision FROM onion_urls""")]
        cards = [dict(row) for row in db.execute("""SELECT id,primary_category,tags,spain_priority,
          classification_decision,search_text FROM site_cards""")]
        for row in urls:
            category = row.get("primary_category") or "unknown"
            if category in restricted:
                continue
            try:
                tags = json.loads(row.get("tags") or "[]")
                if not isinstance(tags, list): tags = []
            except (TypeError, ValueError):
                tags = []
            tags.extend(category_search_tags(category))
            if (row.get("spain_priority") and not row.get("spain_analyst_suppressed")
                    and row.get("classification_decision") in {"accepted", "analyst_confirmed"}):
                tags.extend(["spain", "spain_confirmed"])
            db.execute("UPDATE onion_urls SET tags=? WHERE id=?",
                       (json.dumps(list(dict.fromkeys(tags)), ensure_ascii=False), row["id"]))
            counts["urls"] += 1
        for row in cards:
            category = row.get("primary_category") or "unknown"
            if category in restricted:
                continue
            try:
                tags = json.loads(row.get("tags") or "[]")
                if not isinstance(tags, list): tags = []
            except (TypeError, ValueError):
                tags = []
            tags.extend(category_search_tags(category))
            if (row.get("spain_priority")
                    and row.get("classification_decision") in {"accepted", "analyst_confirmed"}):
                tags.extend(["spain", "spain_confirmed"])
            tags = list(dict.fromkeys(tags))
            safe_search = (str(row.get("search_text") or "") + " " + " ".join(tags)).casefold()[:8000]
            db.execute("UPDATE site_cards SET tags=?,search_text=? WHERE id=?",
                       (json.dumps(tags, ensure_ascii=False), safe_search, row["id"]))
            counts["cards"] += 1
    return counts


def backfill_category_taxonomy() -> int:
    """Backfill taxonomy without turning legacy URL/tag/parent text into evidence."""
    from universal_classifier import NEUTRAL_CATEGORIES, classify, safe_category_label
    with get_db() as db:
        rows = [dict(row) for row in db.execute("""SELECT ou.*,
          fp.title AS fetched_title,fp.visible_text AS fetched_visible_text,
          fp.page_structure_json AS fetched_page_structure_json,
          fp.classification_status AS fetched_classification_status
          FROM onion_urls ou LEFT JOIN fetched_pages fp ON fp.onion_url_id=ou.id
          ORDER BY ou.id""")]
    updated = 0
    for row in rows:
        primary = row.get("primary_category") or "unknown"
        try:
            page_structure = json.loads(row.get("fetched_page_structure_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            page_structure = {}
        current_snapshot = bool(
            row.get("fetched_classification_status") == "done"
            and has_current_destination_html_evidence(page_structure)
        )
        analyst_category = str(row.get("analyst_category") or "").strip()
        trusted_prior_category = (
            analyst_category if analyst_category else primary if (
                row.get("classification_evidence_source") == "destination_html"
                and str(row.get("verification_reason") or "") == "page_fetched_and_classified"
                and row.get("verification_state") == "verified"
                and current_snapshot
                and int(row.get("destination_html_evidence_version") or 0)
                    >= DESTINATION_HTML_EVIDENCE_VERSION
            ) else None
        )
        if trusted_prior_category in {"adult_filtered", "adult_restricted"}:
            with get_db() as db:
                db.execute("""UPDATE onion_urls SET category_confidence='critical',category_reason='Adult safety filter matched',
                  category_safe_label='Filtered adult content',display_group='Safety Restricted',ui_hidden_default=1,
                  ui_priority=0,review_score=0 WHERE id=?""", (row["id"],))
            updated += 1
            continue
        if trusted_prior_category == "severe_abuse_risk":
            with get_db() as db:
                db.execute("""UPDATE onion_urls SET category_confidence='critical',
                  category_reason='Critical restricted safety policy matched',
                  category_safe_label='Restricted content — metadata only',display_group='Safety Restricted',
                  ui_hidden_default=1,ui_priority=90,review_score=90 WHERE id=?""", (row["id"],))
            updated += 1
            continue
        title_source = str((page_structure.get("identity") or {}).get("title_source") or "")
        fetched_title = (row.get("fetched_title") if current_snapshot and title_source in {
            "html_title", "og_title", "twitter_title", "page_h1",
        } else None)
        policy = classify(
            row["url"], title=fetched_title,
            visible_text=(row.get("fetched_visible_text") or "") if current_snapshot else "",
            page_structure=page_structure if current_snapshot else {},
        )
        if current_snapshot:
            policy.update(
                destination_html_evidence_version=DESTINATION_HTML_EVIDENCE_VERSION,
                classification_evidence_source="destination_html",
            )
        if (policy.get("primary_category") == "unknown"
                and trusted_prior_category not in {None, "unknown"}):
            policy["primary_category"] = policy["category"] = trusted_prior_category
            policy["content_category"] = trusted_prior_category
            policy["category_safe_label"] = safe_category_label(trusted_prior_category)
            policy["risk_level"] = row.get("risk_level") or "low"
            policy["storage_policy"] = row.get("storage_policy") or "safe_summary"
            policy["review_status"] = row.get("review_status") or "pending"
            policy["queue_policy"] = row.get("queue_policy") or "normal"
            policy["screenshot_policy"] = row.get("screenshot_policy") or "blocked"
            policy["active"] = int(bool(row.get("active", 1)))
            policy["display_group"] = ("Threats" if primary in {"leaks_data","credentials","malware_hacking",
                "weapons_arms","drugs","fraud_financial","extremist_recruitment"} else "Discovery" if primary in {
                "directory_index","search_engine","forum_social","hosting_services","contact_infrastructure"}
                else "Neutral / informational" if primary in NEUTRAL_CATEGORIES else "Other")
            policy["category_reason"] = "Existing category preserved during taxonomy migration"
        apply_onion_policy(
            row["url"], policy, checked=current_snapshot,
            page_structure=page_structure if current_snapshot else None)
        updated += 1
    with get_db() as db:
        card_ids = [int(item[0]) for item in db.execute(
            "SELECT id FROM site_cards ORDER BY id")]
        db.execute("UPDATE site_cards SET rollup_dirty=1")
    if card_ids:
        from site_dedupe import update_site_card_rollups
        for card_id in card_ids:
            update_site_card_rollups(card_id)
    return updated


def _remove_local_artifact(path_value: str | None, approved_root: Path) -> None:
    if not path_value:
        return
    try:
        path = Path(path_value).resolve()
        root = approved_root.resolve()
        if path.is_relative_to(root) and path.is_file():
            path.unlink(missing_ok=True)
    except (OSError, ValueError):
        pass


def _refresh_actor_stats_db(db: sqlite3.Connection, actor_id: int) -> None:
    row = db.execute("""SELECT COUNT(*) observations,
      SUM(CASE WHEN spain_priority=1 THEN 1 ELSE 0 END) spain_observations,
      MAX(last_seen) last_seen,MAX(evidence_confidence) evidence_confidence
      FROM actor_observations WHERE actor_id=? AND analyst_excluded=0""", (actor_id,)).fetchone()
    observations = int(row["observations"] or 0)
    if not observations:
        retained = db.execute("SELECT COUNT(*) FROM actor_observations WHERE actor_id=?", (actor_id,)).fetchone()[0]
        if retained:
            identifier_ids = [int(item[0]) for item in db.execute(
                "SELECT id FROM actor_identifiers WHERE actor_id=?", (actor_id,))]
            if identifier_ids:
                marks = ",".join("?" for _ in identifier_ids)
                db.execute(f"DELETE FROM actor_identifier_observations WHERE actor_identifier_id IN ({marks})",
                           tuple(identifier_ids))
            db.execute("DELETE FROM actor_identifiers WHERE actor_id=?", (actor_id,))
            db.execute("DELETE FROM actor_connections WHERE source_actor_id=? OR target_actor_id=?", (actor_id, actor_id))
            db.execute("""UPDATE actors SET observation_count=0,spain_observation_count=0,
              confidence_score=0,confidence_label='low' WHERE id=?""", (actor_id,))
        else:
            _delete_actor_dependents_db(db, actor_id)
        return
    latest = db.execute("""SELECT url,primary_category,risk_level FROM actor_observations
      WHERE actor_id=? AND analyst_excluded=0 ORDER BY last_seen DESC,id DESC LIMIT 1""", (actor_id,)).fetchone()
    score = round(float(row["evidence_confidence"] or 0) * 100)
    label = "high" if score >= 85 else "medium" if score >= 70 else "low"
    db.execute("""UPDATE actors SET observation_count=?,spain_observation_count=?,last_seen=?,
      confidence_score=?,confidence_label=?,latest_url=?,primary_category=?,risk_level=? WHERE id=?""",
      (observations, int(row["spain_observations"] or 0), row["last_seen"], score, label,
       latest["url"], latest["primary_category"], latest["risk_level"], actor_id))


def _delete_actor_dependents_db(db: sqlite3.Connection, actor_id: int) -> None:
    """Delete one derived actor in foreign-key-safe order."""
    job_ids = [int(row[0]) for row in db.execute(
        "SELECT id FROM deep_discovery_jobs WHERE actor_id=?", (actor_id,))]
    if job_ids:
        marks = ",".join("?" for _ in job_ids)
        db.execute(f"DELETE FROM deep_discovery_runs WHERE job_id IN ({marks})", tuple(job_ids))
    db.execute("DELETE FROM deep_discovery_runs WHERE actor_id=?", (actor_id,))
    db.execute("DELETE FROM deep_discovery_jobs WHERE actor_id=?", (actor_id,))
    connection_ids = [int(row[0]) for row in db.execute(
        "SELECT id FROM actor_connections WHERE source_actor_id=? OR target_actor_id=?",
        (actor_id, actor_id))]
    if connection_ids:
        marks = ",".join("?" for _ in connection_ids)
        db.execute(f"DELETE FROM actor_events WHERE connection_id IN ({marks})", tuple(connection_ids))
    db.execute("DELETE FROM actor_events WHERE actor_id=?", (actor_id,))
    db.execute("DELETE FROM actor_watch_alerts WHERE actor_id=? OR related_actor_id=?", (actor_id, actor_id))
    db.execute("DELETE FROM actor_connections WHERE source_actor_id=? OR target_actor_id=?", (actor_id, actor_id))
    candidate_ids = [int(row[0]) for row in db.execute(
        "SELECT id FROM actor_candidates WHERE actor_id=?", (actor_id,))]
    if candidate_ids:
        marks = ",".join("?" for _ in candidate_ids)
        db.execute(f"DELETE FROM actor_candidate_events WHERE candidate_id IN ({marks})", tuple(candidate_ids))
    db.execute("DELETE FROM actor_candidate_events WHERE actor_id=?", (actor_id,))
    db.execute("DELETE FROM entity_expansion_proposals WHERE actor_id=?", (actor_id,))
    db.execute("DELETE FROM actor_candidates WHERE actor_id=?", (actor_id,))
    identifier_ids = [int(row[0]) for row in db.execute(
        "SELECT id FROM actor_identifiers WHERE actor_id=?", (actor_id,))]
    if identifier_ids:
        marks = ",".join("?" for _ in identifier_ids)
        db.execute(f"DELETE FROM actor_identifier_observations WHERE actor_identifier_id IN ({marks})",
                   tuple(identifier_ids))
    db.execute("DELETE FROM actor_identifiers WHERE actor_id=?", (actor_id,))
    db.execute("DELETE FROM actor_aliases WHERE actor_id=?", (actor_id,))
    db.execute("DELETE FROM actor_observations WHERE actor_id=?", (actor_id,))
    db.execute("DELETE FROM actors WHERE id=?", (actor_id,))


def _actor_cleanup_protected_db(db: sqlite3.Connection, actor_id: int) -> bool:
    """Protect analyst-enriched actor records from automatic cleanup plans."""
    actor = db.execute("SELECT watched,analyst_status FROM actors WHERE id=?", (actor_id,)).fetchone()
    if not actor:
        return False
    if bool(actor["watched"]) or str(actor["analyst_status"] or "unreviewed") != "unreviewed":
        return True
    reviewed_connection = db.execute("""SELECT 1 FROM actor_connections
      WHERE (source_actor_id=? OR target_actor_id=?)
      AND COALESCE(analyst_decision,'unreviewed')!='unreviewed' LIMIT 1""",
      (actor_id, actor_id)).fetchone()
    if reviewed_connection:
        return True
    reviewed_candidate = db.execute("""SELECT 1 FROM actor_candidates ac
      JOIN actors a ON a.id=?
      WHERE COALESCE(ac.analyst_state,'')!='' AND (
        ac.actor_id=a.id OR (
          ac.actor_id IS NULL AND ac.onion_host=a.onion_host
          AND ac.normalized_alias=a.normalized_alias)) LIMIT 1""", (actor_id,)).fetchone()
    if reviewed_candidate:
        return True
    analyst_event = db.execute("""SELECT 1 FROM actor_events WHERE actor_id=? AND (
      event_type LIKE 'analyst_%' OR event_type IN
      ('watch_enabled','watch_disabled','connection_reviewed','observation_excluded')) LIMIT 1""",
      (actor_id,)).fetchone()
    return bool(analyst_event)


def actor_cleanup_protected(actor_id: int) -> bool:
    with get_db() as db:
        return _actor_cleanup_protected_db(db, int(actor_id))


def delete_actor_ids_safely(actor_ids: list[int] | tuple[int, ...] | set[int], *,
                            protect_analyst_state: bool = True) -> int:
    """Delete derived actor records in foreign-key-safe order.

    Callers are expected to present their candidate report/dry-run before using
    this mutation.  Analyst and source data outside the selected actor IDs is
    never touched.
    """
    selected = sorted({int(actor_id) for actor_id in actor_ids if int(actor_id) > 0})
    if not selected:
        return 0
    deleted = 0
    with get_db() as db:
        present = {int(row[0]) for row in db.execute(
            f"SELECT id FROM actors WHERE id IN ({','.join('?' for _ in selected)})",
            tuple(selected))}
        for actor_id in sorted(present):
            if protect_analyst_state and _actor_cleanup_protected_db(db, actor_id):
                continue
            _delete_actor_dependents_db(db, actor_id)
            deleted += 1
    return deleted


def _purge_restricted_entity_intelligence_db(
    db: sqlite3.Connection,
    urls: list[str] | tuple[str, ...] = (),
    *,
    url_ids: list[int] | tuple[int, ...] = (),
    site_card_ids: list[int] | tuple[int, ...] = (),
) -> None:
    """Remove page-derived entity material at a restricted-content boundary.

    Candidate/event and proposal rows contain aliases, profile routes and onion
    URLs, so they cannot survive an adult/severe blackhole transition.  Card
    scope is supplied only when the card itself is being deleted; mixed cards
    therefore retain unrelated safe-page evidence.
    """
    clean_urls = tuple(dict.fromkeys(str(value) for value in urls if value))
    clean_url_ids = tuple(sorted({int(value) for value in url_ids if int(value) > 0}))
    clean_card_ids = tuple(sorted({int(value) for value in site_card_ids if int(value) > 0}))

    candidate_where: list[str] = []
    candidate_params: list[Any] = []
    proposal_where: list[str] = []
    proposal_params: list[Any] = []
    if clean_urls:
        marks = ",".join("?" for _ in clean_urls)
        candidate_where.append(f"url IN ({marks})")
        candidate_params.extend(clean_urls)
        proposal_where.extend((f"parent_url IN ({marks})", f"proposed_url IN ({marks})"))
        proposal_params.extend(clean_urls)
        proposal_params.extend(clean_urls)
        db.execute(f"DELETE FROM actor_watch_alerts WHERE url IN ({marks})", clean_urls)
        for url in clean_urls:
            db.execute("DELETE FROM actor_events WHERE instr(COALESCE(safe_metadata_json,''),?)>0",
                       (url,))
    if clean_url_ids:
        marks = ",".join("?" for _ in clean_url_ids)
        candidate_where.append(f"onion_url_id IN ({marks})")
        candidate_params.extend(clean_url_ids)
        proposal_where.append(f"enqueued_onion_url_id IN ({marks})")
        proposal_params.extend(clean_url_ids)
    if clean_card_ids:
        marks = ",".join("?" for _ in clean_card_ids)
        candidate_where.append(f"site_card_id IN ({marks})")
        candidate_params.extend(clean_card_ids)
        proposal_where.append(f"site_card_id IN ({marks})")
        proposal_params.extend(clean_card_ids)

    if proposal_where:
        db.execute(f"DELETE FROM entity_expansion_proposals WHERE {' OR '.join(proposal_where)}",
                   tuple(proposal_params))
    if candidate_where:
        candidate_ids = [int(row[0]) for row in db.execute(
            f"SELECT id FROM actor_candidates WHERE {' OR '.join(candidate_where)}",
            tuple(candidate_params))]
        if candidate_ids:
            marks = ",".join("?" for _ in candidate_ids)
            db.execute(f"DELETE FROM actor_candidate_events WHERE candidate_id IN ({marks})",
                       tuple(candidate_ids))
            db.execute(f"DELETE FROM actor_candidates WHERE id IN ({marks})",
                       tuple(candidate_ids))


def _remove_actor_observations_db(db: sqlite3.Connection, urls: list[str]) -> None:
    if not urls:
        return
    marks = ",".join("?" for _ in urls)
    restricted_url_ids = [int(row[0]) for row in db.execute(
        f"SELECT id FROM onion_urls WHERE url IN ({marks})", tuple(urls))]
    _purge_restricted_entity_intelligence_db(
        db, urls, url_ids=restricted_url_ids)
    observations = [dict(row) for row in db.execute(
        f"SELECT id,actor_id FROM actor_observations WHERE url IN ({marks})", tuple(urls))]
    actor_ids = sorted({int(row["actor_id"]) for row in observations})
    observation_ids = [int(row["id"]) for row in observations]
    if observation_ids:
        observation_marks = ",".join("?" for _ in observation_ids)
        identifier_ids = [int(row[0]) for row in db.execute(
            f"SELECT DISTINCT actor_identifier_id FROM actor_identifier_observations "
            f"WHERE observation_id IN ({observation_marks})", tuple(observation_ids))]
        db.execute(f"DELETE FROM actor_identifier_observations WHERE observation_id IN ({observation_marks})",
                   tuple(observation_ids))
        for identifier_id in identifier_ids:
            if not db.execute("SELECT 1 FROM actor_identifier_observations WHERE actor_identifier_id=? LIMIT 1",
                              (identifier_id,)).fetchone():
                db.execute("DELETE FROM actor_identifiers WHERE id=?", (identifier_id,))
    db.execute(f"DELETE FROM actor_observations WHERE url IN ({marks})", tuple(urls))
    for actor_id in actor_ids:
        _refresh_actor_stats_db(db, actor_id)


def cleanup_adult_filtered_items(only_url: str | None = None) -> int:
    """Discard adult result artifacts while retaining a minimal anti-retry URL row."""
    where = """(primary_category IN ('adult_restricted','adult_filtered')
      OR category IN ('adult_restricted','adult_filtered'))
      AND COALESCE(safety_reason,'') NOT IN ('adult_marketplace_category','adult_marketplace_dominant')
      AND (
        (classification_evidence_source='destination_html'
          AND COALESCE(destination_html_evidence_version,0)>=?
          AND verification_state='verified'
          AND verification_reason='page_fetched_and_classified')
        OR analyst_category IN ('adult_filtered','adult_restricted')
        OR EXISTS (SELECT 1 FROM adult_filter_memory afm
          WHERE afm.onion_url_id=onion_urls.id AND afm.analyst_decision='blocked'
          AND afm.reviewed_at IS NOT NULL)
      )"""
    params: tuple = (DESTINATION_HTML_EVIDENCE_VERSION,)
    if only_url:
        where += " AND url=?"
        params += (only_url,)
    preview_paths: list[str] = []
    report_paths: list[str] = []
    remaining_cards: list[int] = []
    with get_db() as db:
        rows = [dict(row) for row in db.execute(f"SELECT * FROM onion_urls WHERE {where}", params)]
        if not rows:
            return 0
        urls = [row["url"] for row in rows]
        url_ids = [int(row["id"]) for row in rows]
        card_ids = sorted({int(row["site_card_id"]) for row in rows if row.get("site_card_id")})
        url_marks = ",".join("?" for _ in urls)
        id_marks = ",".join("?" for _ in url_ids)
        card_marks = ",".join("?" for _ in card_ids)
        preview_paths = [row[0] for row in db.execute(
            f"SELECT preview_path FROM page_previews WHERE url IN ({url_marks})", tuple(urls)) if row[0]]
        if card_ids:
            report_paths = [row[0] for row in db.execute(
                f"SELECT output_path FROM evidence_reports WHERE site_card_id IN ({card_marks})", tuple(card_ids)) if row[0]]
        legacy_report_ids = []
        for report in db.execute("SELECT id,output_path FROM evidence_reports WHERE site_card_id IS NULL"):
            try:
                report_path = Path(report["output_path"] or "").resolve()
                if (report_path.is_relative_to(REPORTS_DIR.resolve()) and report_path.is_file()
                        and any(url in report_path.read_text(encoding="utf-8", errors="ignore") for url in urls)):
                    legacy_report_ids.append(int(report["id"]))
                    report_paths.append(str(report_path))
            except (OSError, ValueError):
                pass
        hit_alert_ids = [row[0] for row in db.execute(
            f"SELECT alert_log_id FROM onion_hits WHERE url IN ({url_marks}) AND alert_log_id IS NOT NULL", tuple(urls))]

        _remove_actor_observations_db(db, urls)

        for table, column, values in (
            ("page_previews", "url", urls), ("site_profiles", "url", urls),
            ("page_topics", "url", urls), ("onion_tags", "url", urls),
            ("restricted_items", "url", urls), ("passive_exposures", "url", urls),
            ("onion_hits", "url", urls), ("mirror_urls", "url", urls),
            ("indicator_links", "source_ref", urls),
        ):
            marks = ",".join("?" for _ in values)
            db.execute(f"DELETE FROM {table} WHERE {column} IN ({marks})", tuple(values))
        db.execute(f"DELETE FROM onion_edges WHERE source_url IN ({url_marks}) OR discovered_url IN ({url_marks})",
                   tuple(urls) + tuple(urls))
        db.execute(f"DELETE FROM possible_site_card_matches WHERE onion_url_id IN ({id_marks})", tuple(url_ids))
        db.execute(f"DELETE FROM site_fingerprints WHERE onion_url_id IN ({id_marks})", tuple(url_ids))
        db.execute(f"DELETE FROM site_card_urls WHERE onion_url_id IN ({id_marks})", tuple(url_ids))
        db.execute(f"DELETE FROM page_preview_jobs WHERE onion_url_id IN ({id_marks}) OR url IN ({url_marks})",
                   tuple(url_ids) + tuple(urls))
        db.execute(f"DELETE FROM site_card_jobs WHERE onion_url_id IN ({id_marks}) OR url IN ({url_marks})",
                   tuple(url_ids) + tuple(urls))
        # Preserve the queue/lifecycle row so the verify worker can finish its
        # atomic claim, but erase all destination-derived content immediately.
        db.execute(f"""UPDATE fetched_pages SET response_status=NULL,content_type=NULL,
          headers_json='{{}}',title=NULL,meta_text='',visible_text='',link_records_json='[]',
          page_structure_json='{{}}',pre_policy_json='{{}}'
          WHERE onion_url_id IN ({id_marks}) OR url IN ({url_marks})""",
          tuple(url_ids) + tuple(urls))
        db.execute(f"DELETE FROM spain_alert_queue WHERE url IN ({url_marks}) OR payload_json LIKE '%adult_restricted%' OR payload_json LIKE '%adult_filtered%'",
                   tuple(urls))
        if hit_alert_ids:
            table_exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='alert_log'").fetchone()
            if table_exists:
                marks = ",".join("?" for _ in hit_alert_ids)
                db.execute(f"DELETE FROM alert_log WHERE id IN ({marks})", tuple(hit_alert_ids))
        if card_ids:
            db.execute(f"DELETE FROM evidence_reports WHERE site_card_id IN ({card_marks})", tuple(card_ids))
            for card_id in card_ids:
                remaining = db.execute("SELECT COUNT(*) FROM site_card_urls WHERE site_card_id=?", (card_id,)).fetchone()[0]
                if remaining:
                    remaining_cards.append(card_id)
                else:
                    _purge_restricted_entity_intelligence_db(
                        db, site_card_ids=(card_id,))
                    db.execute("DELETE FROM possible_site_card_matches WHERE candidate_site_card_id=?", (card_id,))
                    db.execute("DELETE FROM site_fingerprints WHERE site_card_id=?", (card_id,))
                    db.execute("DELETE FROM site_card_events WHERE site_card_id=?", (card_id,))
                    db.execute("DELETE FROM site_cards WHERE id=?", (card_id,))
        if legacy_report_ids:
            marks = ",".join("?" for _ in legacy_report_ids)
            db.execute(f"DELETE FROM evidence_reports WHERE id IN ({marks})", tuple(legacy_report_ids))

        now = utc_now_iso()
        db.execute(f"""UPDATE onion_urls SET status='blocked',active=0,
          primary_category='adult_filtered',category='adult_filtered',content_category='adult_filtered',
          safety_state='filtered',classification_decision='restricted',tags=NULL,
          risk_level='filtered',confidence='high',risk_flags='["adult_filtered"]',
          storage_policy='discard',review_status='filtered',safety_reason='adult_content_filtered',
          screenshot_blocked_reason='adult_content_filtered',screenshot_policy='blocked',queue_policy='blocked',
          spain_priority=0,geo_priority=NULL,spain_match_reason=NULL,spain_match_language=NULL,
          spain_confidence=NULL,spain_context_tags=NULL,spain_alert_sent=0,spain_alert_sent_at=NULL,
          spain_alert_level=NULL,spain_review_status='ignored',priority_score=0,tag_summary=NULL,
          tag_confidence=NULL,title=NULL,content_hash=NULL,fuzzy_hash=NULL,relevance_score=0,risk_score=0,
          reasons=NULL,last_error=NULL,next_crawl_at=NULL,site_card_id=NULL,canonical_site_id=NULL,
          dedupe_status='filtered',mirror_confidence='unknown',content_fingerprint=NULL,
          structure_fingerprint=NULL,safe_title_fingerprint=NULL,last_seen=COALESCE(last_seen,?)
          WHERE id IN ({id_marks})""", (now, *url_ids))

    for path in preview_paths:
        _remove_local_artifact(path, PREVIEWS_DIR)
    for path in report_paths:
        _remove_local_artifact(path, REPORTS_DIR)
    if remaining_cards:
        try:
            from site_dedupe import update_site_card_rollups
            for card_id in remaining_cards:
                update_site_card_rollups(card_id)
        except (ImportError, AttributeError):
            pass
    return len(rows)


def purge_restricted_page_artifacts(url: str) -> None:
    """Delete page-derived artifacts after a late transient safety signal (for example OCR)."""
    preview_paths = []
    with get_db() as db:
        _remove_actor_observations_db(db, [url])
        preview_paths = [row[0] for row in db.execute(
            "SELECT preview_path FROM page_previews WHERE url=?", (url,)) if row[0]]
        for table, column in (("page_previews", "url"), ("page_topics", "url"), ("site_profiles", "url"),
                              ("passive_exposures", "url"), ("onion_hits", "url"),
                              ("indicator_links", "source_ref")):
            db.execute(f"DELETE FROM {table} WHERE {column}=?", (url,))
        db.execute("UPDATE onion_urls SET title=NULL,content_hash=NULL,fuzzy_hash=NULL,reasons=NULL WHERE url=?", (url,))
    for path in preview_paths:
        _remove_local_artifact(path, PREVIEWS_DIR)


def enforce_severe_blackhole(url: str, policy: dict | None = None) -> bool:
    """Scrub a confirmed severe-abuse page down to one anti-retry tombstone.

    This operation is intentionally idempotent. It stores no matched terms,
    snippets, page text, DOM, identifiers, or classification context.
    """
    policy = dict(policy or {})
    preview_paths: list[str] = []
    report_paths: list[str] = []
    retained_cards: list[int] = []
    with get_db() as db:
        row = db.execute("SELECT * FROM onion_urls WHERE url=?", (url,)).fetchone()
        if not row:
            return False
        policy_analyst = str(policy.get("analyst_category") or "").strip()
        policy_trusted_severe = bool(
            policy_analyst == "severe_abuse_risk"
            and policy.get("classification_evidence_source") == "analyst"
            and str(policy.get("primary_category") or "") == "severe_abuse_risk"
        )
        row_analyst = str(row["analyst_category"] or "").strip()
        row_analyst_severe = row_analyst == "severe_abuse_risk"
        row_html_severe = bool(
            row["primary_category"] == "severe_abuse_risk"
            and row["classification_evidence_source"] == "destination_html"
            and row["verification_state"] == "verified"
            and row["verification_reason"] == "page_fetched_and_classified"
            and int(row["destination_html_evidence_version"] or 0)
                >= DESTINATION_HTML_EVIDENCE_VERSION
        )
        if not (policy_trusted_severe or row_analyst_severe or row_html_severe):
            return False
        source = "analyst" if (policy_trusted_severe or row_analyst_severe) else "destination_html"
        evidence_version = (0 if source == "analyst" else
                            int(row["destination_html_evidence_version"] or 0))
        verification_reason = "analyst_confirmed" if source == "analyst" else "page_fetched_and_classified"
        safe_labels = sorted({str(value)[:80] for value in (
            list(policy.get("safe_signal_labels") or [])
            + list(policy.get("evidence_families") or [])
        ) if value})[:20] if (policy_trusted_severe or row_html_severe) else []
        signal_hash = hashlib.sha256(json.dumps(
            {"category": "severe_abuse_risk", "signals": safe_labels},
            sort_keys=True, ensure_ascii=True).encode("ascii")).hexdigest()
        url_id = int(row["id"])
        card_ids = {int(row["site_card_id"])} if row["site_card_id"] else set()
        card_ids.update(int(item[0]) for item in db.execute(
            "SELECT DISTINCT site_card_id FROM site_card_urls WHERE onion_url_id=?", (url_id,)) if item[0])
        preview_paths.extend(str(item[0]) for item in db.execute(
            "SELECT preview_path FROM page_previews WHERE url=?", (url,)) if item[0])
        if card_ids:
            marks = ",".join("?" for _ in card_ids)
            report_paths.extend(str(item[0]) for item in db.execute(
                f"SELECT output_path FROM evidence_reports WHERE site_card_id IN ({marks})", tuple(card_ids))
                                if item[0])

        hit_alert_ids = [int(item[0]) for item in db.execute(
            "SELECT alert_log_id FROM onion_hits WHERE url=? AND alert_log_id IS NOT NULL", (url,))]
        _remove_actor_observations_db(db, [url])

        for table, column in (
            ("page_previews", "url"), ("page_preview_jobs", "url"),
            ("site_profiles", "url"), ("page_topics", "url"), ("onion_tags", "url"),
            ("safety_rule_matches", "url"), ("passive_exposures", "url"),
            ("onion_hits", "url"), ("mirror_urls", "url"),
            ("indicator_links", "source_ref"), ("site_card_jobs", "url"),
            ("spain_alert_queue", "url"),
        ):
            db.execute(f"DELETE FROM {table} WHERE {column}=?", (url,))
        if hit_alert_ids and db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='alert_log'").fetchone():
            marks = ",".join("?" for _ in hit_alert_ids)
            db.execute(f"DELETE FROM alert_log WHERE id IN ({marks})", tuple(hit_alert_ids))
        db.execute("DELETE FROM onion_edges WHERE source_url=? OR discovered_url=?", (url, url))
        db.execute("DELETE FROM onion_url_sources WHERE onion_url_id=?", (url_id,))
        db.execute("DELETE FROM possible_site_card_matches WHERE onion_url_id=?", (url_id,))
        db.execute("DELETE FROM site_fingerprints WHERE onion_url_id=?", (url_id,))
        db.execute("DELETE FROM site_card_urls WHERE onion_url_id=?", (url_id,))
        db.execute("DELETE FROM classification_decisions WHERE onion_url_id=? OR url=?", (url_id, url))
        db.execute("DELETE FROM page_change_events WHERE onion_url_id=? OR url=?", (url_id, url))
        db.execute("DELETE FROM spain_hits WHERE onion_url_id=? OR canonical_url=?", (url_id, url))
        db.execute("DELETE FROM frontier_deferred_urls WHERE url_id=?", (url_id,))
        db.execute("DELETE FROM adult_filter_memory WHERE onion_url_id=?", (url_id,))
        db.execute("DELETE FROM restricted_items WHERE url=?", (url,))
        db.execute("DELETE FROM crawl_audit_log WHERE url=?", (url,))

        # Retain the claimed row long enough for its owning verifier to finish,
        # but remove every fetched byte and derived structure immediately.
        db.execute("""UPDATE fetched_pages SET response_status=NULL,content_type=NULL,
          headers_json='{}',title=NULL,meta_text='',visible_text='',link_records_json='[]',
          page_structure_json='{}',pre_policy_json='{"decision":"blocked"}',error=NULL,
          classification_status=CASE WHEN classification_status='claimed' THEN 'claimed' ELSE 'done' END,
          verified_at=CASE WHEN classification_status='claimed' THEN verified_at ELSE ? END,
          next_retry_at=NULL,last_error=NULL,error_type=NULL,dead_letter_reason=NULL
          WHERE onion_url_id=?""", (utc_now_iso(), url_id))

        for card_id in sorted(card_ids):
            db.execute("DELETE FROM evidence_reports WHERE site_card_id=?", (card_id,))
            db.execute("DELETE FROM site_card_events WHERE site_card_id=? AND safe_metadata_json LIKE ?",
                       (card_id, f"%{url}%"))
            if db.execute("SELECT 1 FROM site_card_urls WHERE site_card_id=? LIMIT 1", (card_id,)).fetchone():
                retained_cards.append(card_id)
                db.execute("UPDATE site_cards SET rollup_dirty=1 WHERE id=?", (card_id,))
            else:
                _purge_restricted_entity_intelligence_db(
                    db, site_card_ids=(card_id,))
                for table in ("deep_discovery_runs", "deep_discovery_jobs", "page_preview_jobs",
                              "site_card_jobs", "spain_hits", "classification_decisions",
                              "page_change_events", "crawl_coverage", "site_card_events",
                              "site_fingerprints"):
                    db.execute(f"DELETE FROM {table} WHERE site_card_id=?", (card_id,))
                db.execute("DELETE FROM possible_site_card_matches WHERE candidate_site_card_id=?", (card_id,))
                db.execute("DELETE FROM site_cards WHERE id=?", (card_id,))

        now = utc_now_iso()
        db.execute("""INSERT INTO restricted_items
          (url,category,first_seen,last_seen,safety_reason,source_url,status)
          VALUES(?,'severe_abuse_risk',?,?, 'severe_abuse_blackhole',NULL,'blocked')
          ON CONFLICT(url) DO UPDATE SET category='severe_abuse_risk',last_seen=excluded.last_seen,
          safety_reason='severe_abuse_blackhole',source_url=NULL,status='blocked'""",
          (url, row["first_seen"] or now, now))
        db.execute("""UPDATE onion_urls SET status='blocked',active=0,
          primary_category='severe_abuse_risk',category='severe_abuse_risk',content_category='severe_abuse_risk',
          safety_state='metadata_only',tags=NULL,risk_level='filtered',confidence='high',risk_flags=NULL,
          storage_policy='metadata_only',review_status='restricted',safety_reason='severe_abuse_blackhole',
          screenshot_policy='blocked',screenshot_blocked_reason='severe_abuse_blackhole',queue_policy='blocked',
          spain_priority=0,geo_priority=NULL,spain_match_reason=NULL,spain_match_language=NULL,
          spain_confidence=NULL,spain_context_tags=NULL,spain_alert_sent=0,spain_alert_sent_at=NULL,
          spain_alert_level=NULL,spain_review_status='ignored',spain_priority_reason=NULL,
          spain_priority_evidence_type=NULL,spain_relevance='none',spain_evidence_type=NULL,
          seller_geo_confidence='none',spain_evidence_snippets=NULL,spain_evidence_source_url=NULL,
          spain_evidence_source_path=NULL,spain_context_only=0,spain_actionable=0,
          spain_evidence_score=0,spain_evidence_families=NULL,spain_evidence_direction='context_only',
          priority_score=0,review_score=0,urgent_score=0,urgent_flag=0,urgent_reason=NULL,
          alert_eligible=0,alert_reason=NULL,title=NULL,detected_title=NULL,safe_display_name=NULL,
          safe_site_name=NULL,safe_summary=NULL,content_hash=NULL,fuzzy_hash=NULL,reasons=NULL,
          tag_summary=NULL,tag_confidence=NULL,last_error=NULL,next_crawl_at=NULL,source_url=NULL,
          source_type=NULL,site_card_id=NULL,canonical_site_id=NULL,dedupe_status='filtered',
          claimed_at=NULL,claimed_by=NULL,next_retry_at=NULL,
          mirror_confidence='unknown',content_fingerprint=NULL,structure_fingerprint=NULL,
          safe_title_fingerprint=NULL,category_evidence_json=NULL,
          category_supporting_evidence_json=NULL,category_contradicting_evidence_json=NULL,
          page_type_evidence_json=NULL,parent_evidence_json=NULL,child_link_evidence_json=NULL,
          classification_evidence_source=?,destination_html_evidence_version=?,
          verification_state='verified',verification_reason=?,verified_at=COALESCE(verified_at,?),
          restricted_signal_hash=?,last_seen=COALESCE(last_seen,?) WHERE id=?""",
          (source, evidence_version, verification_reason, now, signal_hash, now, url_id))
        db.execute("DELETE FROM indicators WHERE id NOT IN (SELECT DISTINCT indicator_id FROM indicator_links)")
        db.execute("DELETE FROM mirror_clusters WHERE id NOT IN (SELECT DISTINCT cluster_id FROM mirror_urls WHERE cluster_id IS NOT NULL)")

    for path in preview_paths:
        _remove_local_artifact(path, PREVIEWS_DIR)
    for path in report_paths:
        _remove_local_artifact(path, REPORTS_DIR)
    if retained_cards:
        try:
            from site_dedupe import update_site_card_rollups
            for card_id in retained_cards:
                update_site_card_rollups(card_id)
        except (ImportError, AttributeError):
            pass
    return True


def cleanup_severe_blackhole_items(*, dry_run: bool = True) -> dict[str, Any]:
    """Find historical severe pages and scrub them without exposing matched text."""
    from safety_policy import assess_severe_abuse_signals, severe_blackhole_policy

    candidate_sql = """SELECT DISTINCT ou.url,ou.title,ou.detected_title,ou.safe_display_name,
      ou.safe_summary,fp.title AS fetched_title,fp.meta_text,fp.visible_text,fp.page_structure_json,
      fp.classification_status AS fetched_classification_status,
      sc.display_name AS card_display_name,sc.detected_title AS card_detected_title
      FROM onion_urls ou
      LEFT JOIN fetched_pages fp ON fp.onion_url_id=ou.id
      LEFT JOIN site_card_urls scu ON scu.onion_url_id=ou.id
      LEFT JOIN site_cards sc ON sc.id=COALESCE(ou.site_card_id,scu.site_card_id)
      WHERE COALESCE(ou.primary_category,'')!='severe_abuse_risk' AND (
        lower(COALESCE(ou.title,'')||' '||COALESCE(ou.detected_title,'')||' '||
          COALESCE(ou.safe_display_name,'')||' '||COALESCE(ou.safe_summary,'')||' '||
          COALESCE(fp.title,'')||' '||COALESCE(fp.meta_text,'')||' '||
          COALESCE(fp.visible_text,'')||' '||COALESCE(sc.display_name,'')||' '||
          COALESCE(sc.detected_title,'')) LIKE '%csam%'
        OR lower(COALESCE(ou.title,'')||' '||COALESCE(ou.detected_title,'')||' '||
          COALESCE(fp.title,'')||' '||COALESCE(fp.meta_text,'')||' '||COALESCE(fp.visible_text,'')||' '||
          COALESCE(sc.display_name,'')) LIKE '%pedo%'
        OR lower(COALESCE(ou.title,'')||' '||COALESCE(ou.detected_title,'')||' '||
          COALESCE(fp.title,'')||' '||COALESCE(fp.visible_text,'')||' '||COALESCE(sc.display_name,'')) LIKE '%jailbait%'
        OR lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
          COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%preteen%'
        OR lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
          COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%underage%'
        OR lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
          COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%lolicon%'
        OR lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
          COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%loli%'
        OR lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
          COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%childporn%'
        OR lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
          COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%child porn%'
        OR lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
          COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%minor porn%'
        OR ((' '||lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
          COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,''))||' ') LIKE '% cp %'
          AND lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
            COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) GLOB '*porn*'
          AND (lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
                 COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%video%'
            OR lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
                 COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%gallery%'
            OR lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
                 COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%files%'
            OR lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
                 COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%preview%'
            OR lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
                 COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%download%'
            OR lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
                 COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%trade%'
            OR lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
                 COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%exchange%'))
        OR lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
          COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%child sexual%'
        OR lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
          COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%abuso sexual infantil%'
        OR lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
          COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%pornografia infantil%'
        OR (lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
          COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) LIKE '%high school%'
          AND lower(COALESCE(fp.visible_text,'')||' '||COALESCE(fp.title,'')||' '||
          COALESCE(ou.title,'')||' '||COALESCE(sc.display_name,'')) GLOB '*sex*')
      )"""
    with get_db() as db:
        candidates = [dict(row) for row in db.execute(candidate_sql)]
    matched: list[str] = []
    policies: dict[str, tuple[dict, dict]] = {}
    for row in candidates:
        try:
            structure = json.loads(row.get("page_structure_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            structure = {}
        if (row.get("fetched_classification_status") != "done"
                or not has_current_destination_html_evidence(structure)):
            continue
        title_source = str((structure.get("identity") or {}).get("title_source") or "")
        # Only destination-owned, parser-proven title/body fields are terminal
        # cleanup evidence. URL/host fallbacks, old heading fallbacks, meta tags,
        # Site Card rollups, summaries, and parent-derived display names may
        # select a row for inspection but can never blackhole it.
        title = (row.get("fetched_title") or "") if title_source in {
            "html_title", "og_title", "twitter_title", "page_h1",
        } else ""
        body = row.get("visible_text") or ""
        assessment = assess_severe_abuse_signals(
            None, title, body, None, classification_scope="page")
        if assessment.get("block"):
            matched.append(row["url"])
            policy = severe_blackhole_policy()
            policy.update(
                safe_signal_labels=assessment.get("safe_signal_labels") or [],
                evidence_families=assessment.get("independent_signal_families") or [],
                destination_html_evidence_version=DESTINATION_HTML_EVIDENCE_VERSION,
                classification_evidence_source="destination_html",
            )
            policies[row["url"]] = (policy, structure)
    if not dry_run:
        for url in matched:
            policy, structure = policies[url]
            # Persist the parser-proven category first. The central writer then
            # invokes the blackhole using the now category-bound trusted row.
            apply_onion_policy(
                url, policy, checked=True, page_structure=structure)
    return {
        "dry_run": bool(dry_run),
        "candidates_examined": len(candidates),
        "matched": len(matched),
        "scrubbed": 0 if dry_run else len(matched),
        "url_hashes": [hashlib.sha256(url.encode("utf-8", "ignore")).hexdigest()[:16]
                       for url in matched[:100]],
    }


def _insert_or_update_onion_url_db(db: sqlite3.Connection, url: str,
                                   onion_domain: str | None = None,
                                   source_url: str | None = None,
                                   source_type: str | None = None,
                                   depth: int = 0, status: str = "queued",
                                   next_crawl_at: str | None = None,
                                   *, now: str | None = None) -> tuple[int, str]:
    """Upsert one exact frontier row using the caller's transaction.

    Keeping this primitive transaction-local lets analyst-approved expansion
    decisions serialize their policy check, decision and exact queue binding.
    It performs no policy classification and no network work.
    """
    now = now or utc_now_iso()
    canonical = canonical_url_identity(url)
    # Queue/transport status never proves page content.  A destination becomes
    # content-verified only in apply_onion_policy() after the current parser's
    # evidence-boundary marker is present (or through an explicit analyst edit).
    verification_state = "provisional" if source_url else "discovered"
    verified_at = None
    existing = db.execute("""SELECT id,url FROM onion_urls
      WHERE url=? OR canonical_url=? ORDER BY CASE WHEN url=? THEN 0 ELSE 1 END,id LIMIT 1""",
      (url, canonical, url)).fetchone()
    if existing:
        existing_url = str(existing["url"])
    else:
        existing_url = url
    db.execute("""INSERT INTO onion_urls
          (url,onion_domain,source_url,source_type,depth,first_seen,last_seen,status,next_crawl_at,
           canonical_url,original_url,seen_count,verification_state,verified_at,verification_reason)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,?,?) ON CONFLICT(url) DO UPDATE SET
          last_seen=excluded.last_seen,
          seen_count=COALESCE(onion_urls.seen_count,1)+1,
          onion_domain=COALESCE(onion_urls.onion_domain,excluded.onion_domain),
          source_url=COALESCE(onion_urls.source_url,excluded.source_url),
          source_type=COALESCE(onion_urls.source_type,excluded.source_type),
          depth=MIN(onion_urls.depth,excluded.depth),
          canonical_url=COALESCE(onion_urls.canonical_url,excluded.canonical_url),
          original_url=COALESCE(onion_urls.original_url,excluded.original_url),
          status=CASE WHEN onion_urls.status IN ('new','queued') THEN excluded.status ELSE onion_urls.status END,
          next_crawl_at=COALESCE(onion_urls.next_crawl_at,excluded.next_crawl_at),
          verification_state=CASE
            WHEN onion_urls.verification_state='verified' OR excluded.verification_state='verified' THEN 'verified'
            WHEN onion_urls.verification_state='provisional' OR excluded.verification_state='provisional' THEN 'provisional'
            ELSE 'discovered' END,
          verified_at=COALESCE(onion_urls.verified_at,excluded.verified_at),
          verification_reason=COALESCE(onion_urls.verification_reason,excluded.verification_reason)
    """, (existing_url, onion_domain, source_url, source_type, depth, now, now, status,
            next_crawl_at or now, canonical, url, verification_state, verified_at,
            "discovered_from_page" if verification_state == "provisional" else "manual_seed"))
    row_id = int(db.execute("SELECT id FROM onion_urls WHERE url=?", (existing_url,)).fetchone()[0])
    db.execute("""INSERT INTO onion_url_sources(onion_url_id,source_url,source_type,first_seen,last_seen,seen_count)
          VALUES(?,?,?,?,?,1) ON CONFLICT(onion_url_id,source_url,source_type) DO UPDATE SET
          last_seen=excluded.last_seen,seen_count=onion_url_sources.seen_count+1""",
      (row_id, source_url or "", source_type or "", now, now))
    db.execute("UPDATE onion_urls SET source_count=(SELECT COUNT(*) FROM onion_url_sources WHERE onion_url_id=?) WHERE id=?",
               (row_id, row_id))
    identity = _canonicalize(existing_url)
    db.execute("""UPDATE onion_urls SET canonical_url=?,canonical_root=?,entity_identity=?,
          path_signature=COALESCE(path_signature,?),query_signature=COALESCE(query_signature,?) WHERE id=?""",
      (identity["canonical_url"], identity["canonical_root"], identity["entity_identity"],
       identity["path_signature"], identity["query_signature"], row_id))
    return row_id, existing_url


def insert_or_update_onion_url(url: str, onion_domain: str | None = None,
                               source_url: str | None = None, source_type: str | None = None,
                               depth: int = 0, status: str = "queued",
                               next_crawl_at: str | None = None, policy: dict | None = None) -> int:
    with get_db() as db:
        row_id, existing_url = _insert_or_update_onion_url_db(
            db, url, onion_domain, source_url, source_type, depth, status,
            next_crawl_at)
    if policy:
        if str(policy.get("classification_stage") or "").casefold() == "prefetch":
            apply_prefetch_policy(existing_url, policy)
        else:
            apply_onion_policy(existing_url, policy)
    return row_id


def get_onion_url_by_url(url: str) -> dict | None:
    """Return an existing frontier row without changing its queue state."""
    canonical = canonical_url_identity(url)
    with get_db() as db:
        return _dict(db.execute("""SELECT * FROM onion_urls WHERE url=? OR canonical_url=?
          ORDER BY CASE WHEN url=? THEN 0 ELSE 1 END,id LIMIT 1""",
          (url, canonical, url)).fetchone())


def is_onion_url_verified(url: str) -> bool:
    with get_db() as db:
        row = db.execute("""SELECT verification_state,analyst_category,
          primary_category,verification_reason,destination_html_evidence_version,
          classification_evidence_source
          FROM onion_urls WHERE url=?""", (url,)).fetchone()
        return bool(row and (
            (row["analyst_category"] and row["primary_category"] == row["analyst_category"])
            or (row["verification_state"] == "verified"
                and row["verification_reason"] == "page_fetched_and_classified"
                and row["classification_evidence_source"] == "destination_html"
                and int(row["destination_html_evidence_version"] or 0)
                    >= DESTINATION_HTML_EVIDENCE_VERSION)
        ))


def get_url_decision_stats(url: str, url_family: str | None = None, source_url: str | None = None) -> dict:
    from urllib.parse import urlsplit
    host = (urlsplit(url).hostname or "").casefold()
    with get_db() as db:
        exact = db.execute("SELECT status,liveness_status,seen_count FROM onion_urls WHERE url=?", (url,)).fetchone()
        pages = db.execute("SELECT COUNT(*) FROM onion_urls WHERE lower(COALESCE(onion_domain,''))=?", (host,)).fetchone()[0]
        dead = db.execute("""SELECT COUNT(*) FROM onion_urls WHERE lower(COALESCE(onion_domain,''))=?
          AND (status='dead' OR liveness_status='hard_dead')""", (host,)).fetchone()[0]
        variants = db.execute("SELECT COUNT(*) FROM onion_urls WHERE url_family=?", (url_family,)).fetchone()[0] if url_family else 0
        source_quality = 0
        if source_url:
            source = db.execute("SELECT primary_category,spain_priority,priority_score FROM onion_urls WHERE url=?",
                                (source_url,)).fetchone()
            if source:
                source_quality = (20 if source["spain_priority"] else 0) + (15 if source["primary_category"] in {
                    "directory_index", "search_engine"} else 0) + min(20, int(source["priority_score"] or 0) // 5)
        return {
            "exact_hard_dead": bool(exact and (exact["status"] == "dead" or exact["liveness_status"] == "hard_dead")),
            "known_host": pages > 0, "pages_on_host": int(pages), "dead_paths_on_host": int(dead),
            "query_variants": int(variants), "duplicate_sightings": int(exact["seen_count"] or 0) if exact else 0,
            "source_quality": source_quality,
        }


def apply_crawl_decision(url: str, decision: dict) -> None:
    decision = dict(decision or {})
    content_restricted = (
        str(decision.get("primary_category") or "unknown") in {
            "adult_filtered", "adult_restricted", "severe_abuse_risk",
        }
        or str(decision.get("safety_reason") or "") in {
            "adult_content_filtered", "adult_restricted", "severe_abuse_risk",
            "severe_content_filtered",
        }
    )
    if content_restricted and not decision.get("independent_destination_decision"):
        # This writer is used for frontier decisions.  A URL, route, anchor, or
        # parent-context classifier must not turn its content guess into a
        # blocked destination.  Exact page/analyst memory is explicitly marked
        # independent by crawler_decide_rules; everything else remains queued.
        decision.update(
            decision="monitor", rule_id="DECIDE-009-UNVERIFIED-HINT",
            safety_reason="awaiting_page_classification",
            display_safe_reason="Unverified hint; destination HTML required",
            active=1,
        )
    rejected = decision.get("decision") in {"reject", "restrict"}
    fetch_later = decision.get("decision") == "fetch_later"
    preserve_verified_reason = (
        not rejected
        and str(decision.get("classification_stage") or "").casefold() == "prefetch"
    )
    later_at = (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat().replace("+00:00", "Z")
    with get_db() as db:
        db.execute("""UPDATE onion_urls SET decision=?,decision_rule_id=?,display_safe_reason=?,
          frontier_priority=?,path_signature=?,query_signature=?,url_family=?,trap_score=?,trap_reason=?,
          pagination_page=?,novelty_score=?,defer_reason=?,
          safety_reason=CASE WHEN ? AND verification_state='verified' THEN safety_reason ELSE ? END,
          status=CASE WHEN ? THEN 'blocked' WHEN ? THEN 'retry' ELSE status END,
          active=CASE WHEN ? THEN 0 ELSE active END,next_crawl_at=CASE WHEN ? THEN NULL ELSE next_crawl_at END,
          claimed_at=CASE WHEN ? OR ? THEN NULL ELSE claimed_at END,
          claimed_by=CASE WHEN ? OR ? THEN NULL ELSE claimed_by END
          WHERE url=?""",
          (decision.get("decision"), decision.get("rule_id"), decision.get("display_safe_reason"),
           int(decision.get("frontier_priority") or 0), decision.get("path_signature"),
           decision.get("query_signature"), decision.get("url_family"), int(decision.get("trap_score") or 0),
           decision.get("trap_reason"), int(decision.get("pagination_page") or 0),
           int(decision.get("novelty_score") or 0), decision.get("defer_reason"),
           int(preserve_verified_reason), decision.get("safety_reason"),
           int(rejected), int(fetch_later), int(rejected),
           int(rejected), int(rejected), int(fetch_later), int(rejected), int(fetch_later), url))
        if fetch_later:
            db.execute("UPDATE onion_urls SET next_crawl_at=? WHERE url=?", (later_at, url))


def defer_frontier_url(url: str, reason: str, *,
                       deferred_status: str = "deferred_deep_pagination") -> bool:
    """Remove a URL from the active frontier while retaining a reversible audit row."""
    with get_db() as db:
        row = db.execute("SELECT id,status FROM onion_urls WHERE url=?", (url,)).fetchone()
        if not row:
            return False
        now = utc_now_iso()
        db.execute("""INSERT INTO frontier_deferred_urls
          (url_id,url,old_status,deferred_status,reason,deferred_at,restored_at)
          VALUES(?,?,?,?,?,?,NULL) ON CONFLICT(url_id) DO UPDATE SET
          url=excluded.url,old_status=CASE WHEN frontier_deferred_urls.restored_at IS NOT NULL
            THEN excluded.old_status ELSE frontier_deferred_urls.old_status END,
          deferred_status=excluded.deferred_status,reason=excluded.reason,
          deferred_at=excluded.deferred_at,restored_at=NULL""",
          (row["id"], url, row["status"], deferred_status, reason, now))
        db.execute("""UPDATE onion_urls SET status=?,active=0,next_crawl_at=NULL,defer_reason=?
          WHERE id=?""", (deferred_status, reason, row["id"]))
        return True


def get_forum_thread_budget(onion_host: str, *, initial_limit: int = 25,
                            max_limit: int = 100) -> dict[str, int]:
    """Return the durable adaptive thread budget and current admitted count."""
    host = str(onion_host or "").casefold()
    initial = max(1, min(int(initial_limit), 250))
    maximum = max(initial, min(int(max_limit), 2000))
    now = utc_now_iso()
    with get_db() as db:
        db.execute("""INSERT INTO forum_crawl_state
          (onion_host,permitted_thread_budget,max_thread_budget,created_at,updated_at)
          VALUES(?,?,?,?,?) ON CONFLICT(onion_host) DO UPDATE SET
          max_thread_budget=MAX(forum_crawl_state.permitted_thread_budget,excluded.max_thread_budget),
          updated_at=excluded.updated_at""", (host, initial, maximum, now, now))
        state = db.execute("SELECT * FROM forum_crawl_state WHERE onion_host=?", (host,)).fetchone()
        admitted = db.execute("""SELECT COUNT(*) FROM onion_urls
          WHERE lower(COALESCE(onion_domain,''))=?
          AND source_type IN ('forum_thread','forum_thread_hint')
          AND status!='deferred_forum_budget'""", (host,)).fetchone()[0]
    return {"permitted": int(state["permitted_thread_budget"]),
            "maximum": int(state["max_thread_budget"]), "admitted": int(admitted)}


def expand_deferred_forum_threads(onion_host: str, trigger_url: str, reason: str, *,
                                  batch_size: int = 25, max_limit: int = 100) -> dict[str, int]:
    """Expand once per logical relevant thread and activate one bounded batch."""
    host = str(onion_host or "").casefold()
    batch = max(1, min(int(batch_size), 250))
    now = utc_now_iso()
    trigger_identity_hash = _forum_trigger_identity_hash(host, trigger_url)
    with get_db() as db:
        # Serialize the state read, identity claim, and bounded frontier update.
        # The unique logical-identity index remains the final race-safe guard.
        _begin_immediate(db, "forum_expansion")
        state = db.execute("SELECT * FROM forum_crawl_state WHERE onion_host=?", (host,)).fetchone()
        current = int(state["permitted_thread_budget"]) if state else 25
        maximum = max(current, min(int(max_limit), 2000))
        inserted = db.execute("""INSERT OR IGNORE INTO forum_expansion_events
          (trigger_url,onion_host,trigger_identity_hash,reason,expanded_by,created_at)
          VALUES(?,?,?,?,?,?)""",
          (trigger_url, host, trigger_identity_hash, reason, 0, now)).rowcount
        if not inserted:
            return {"expanded": 0, "permitted": current, "maximum": maximum, "duplicate_trigger": 1}
        new_budget = min(maximum, current + batch)
        increase = max(0, new_budget - current)
        db.execute("""INSERT INTO forum_crawl_state
          (onion_host,permitted_thread_budget,max_thread_budget,relevant_trigger_count,
           expansion_rounds,last_trigger_url,last_trigger_reason,created_at,updated_at)
          VALUES(?,?,?,?,1,?,?,?,?) ON CONFLICT(onion_host) DO UPDATE SET
          permitted_thread_budget=excluded.permitted_thread_budget,
          max_thread_budget=excluded.max_thread_budget,
          relevant_trigger_count=forum_crawl_state.relevant_trigger_count+1,
          expansion_rounds=forum_crawl_state.expansion_rounds+1,
          last_trigger_url=excluded.last_trigger_url,last_trigger_reason=excluded.last_trigger_reason,
          updated_at=excluded.updated_at""",
          (host, new_budget, maximum, 1, trigger_url, reason, now, now))
        rows = db.execute("""SELECT id FROM onion_urls
          WHERE lower(COALESCE(onion_domain,''))=?
          AND source_type IN ('forum_thread','forum_thread_hint')
          AND status='deferred_forum_budget' ORDER BY frontier_priority DESC,id LIMIT ?""",
          (host, increase)).fetchall()
        ids = [int(row["id"]) for row in rows]
        if ids:
            placeholders = ",".join("?" for _ in ids)
            db.execute(f"""UPDATE onion_urls SET status='queued',active=1,next_crawl_at=?,
              defer_reason=NULL WHERE id IN ({placeholders})""", (now, *ids))
            db.execute(f"""UPDATE frontier_deferred_urls SET restored_at=?
              WHERE url_id IN ({placeholders})""", (now, *ids))
        db.execute("""UPDATE forum_expansion_events SET expanded_by=?
          WHERE onion_host=? AND trigger_identity_hash=?""",
                   (len(ids), host, trigger_identity_hash))
    return {"expanded": len(ids), "permitted": new_budget, "maximum": maximum,
            "duplicate_trigger": 0}


def manage_deep_pagination(*, threshold: int = 10, apply: bool = False,
                           restore: bool = False, limit: int = 1000) -> dict:
    """Preview/apply/restore bounded deep-pagination deferrals without deleting rows."""
    threshold = max(2, int(threshold))
    limit = max(1, min(int(limit), 10000))
    with get_db() as db:
        if restore:
            rows = list(db.execute("""SELECT f.url_id,f.old_status FROM frontier_deferred_urls f
              JOIN onion_urls ou ON ou.id=f.url_id WHERE f.restored_at IS NULL
              AND ou.status=f.deferred_status ORDER BY f.deferred_at LIMIT ?""", (limit,)))
            if apply:
                now = utc_now_iso()
                for row in rows:
                    status = row["old_status"] if row["old_status"] in {"new", "queued", "retry"} else "queued"
                    db.execute("""UPDATE onion_urls SET status=?,active=1,next_crawl_at=?,defer_reason=NULL
                      WHERE id=?""", (status, now, row["url_id"]))
                    db.execute("UPDATE frontier_deferred_urls SET restored_at=? WHERE url_id=?",
                               (now, row["url_id"]))
            return {"mode": "restore", "matched": len(rows), "changed": len(rows) if apply else 0}
        rows = list(db.execute("""SELECT id,url FROM onion_urls WHERE active=1
          AND status IN ('new','queued','retry') AND COALESCE(pagination_page,0)>=?
          ORDER BY pagination_page DESC,id LIMIT ?""", (threshold, limit)))
    changed = 0
    if apply:
        for row in rows:
            changed += int(defer_frontier_url(row["url"], "deep_pagination_default_defer"))
    return {"mode": "defer", "matched": len(rows), "changed": changed, "threshold": threshold}


def frontier_stats() -> dict:
    """Return bounded SQL-only frontier health counters."""
    with get_db() as db:
        statuses = {str(row[0]): int(row[1]) for row in db.execute(
            "SELECT status,COUNT(*) FROM onion_urls GROUP BY status")}
        queued = int(db.execute("""SELECT COUNT(*) FROM onion_urls WHERE active=1
          AND status IN ('new','queued','retry')""").fetchone()[0])
        deep = int(db.execute("""SELECT COUNT(*) FROM onion_urls WHERE active=1
          AND status IN ('new','queued','retry') AND pagination_page>=10""").fetchone()[0])
        low = int(db.execute("""SELECT COUNT(*) FROM onion_urls WHERE active=1
          AND status IN ('new','queued','retry') AND COALESCE(novelty_score,0)<0""").fetchone()[0])
        claimed = int(db.execute("SELECT COUNT(*) FROM onion_urls WHERE status IN ('claimed','fetching')").fetchone()[0])
    return {"statuses": statuses, "active_queue": queued, "active_deep_pagination": deep,
            "active_low_novelty": low, "claimed_or_fetching": claimed,
            "low_value_ratio": round((deep + low) / max(1, queued), 3)}


def recalculate_frontier_scores(*, dry_run: bool = True, limit: int = 1000) -> dict:
    """Recalculate a bounded batch using URL shape and host coverage only."""
    from crawler_decide_rules import trap_assessment
    limit = max(1, min(int(limit), 10000))
    with get_db() as db:
        rows = [dict(row) for row in db.execute("""SELECT id,url,source_url FROM onion_urls
          WHERE status IN ('new','queued','retry','deferred_deep_pagination') ORDER BY id LIMIT ?""", (limit,))]
    updates = []
    for row in rows:
        shape = urlsplit(row["url"])
        host_count = 0
        with get_db() as db:
            host_count = int(db.execute("SELECT COUNT(*) FROM onion_urls WHERE lower(onion_domain)=lower(?)",
                                        (shape.hostname or "",)).fetchone()[0])
        result = trap_assessment(row["url"], {"known_host": host_count > 1, "pages_on_host": host_count}, {})
        updates.append((int(result.get("novelty_score") or 0), int(result.get("pagination_page") or 0), row["id"]))
    if not dry_run:
        with get_db() as db:
            db.executemany("UPDATE onion_urls SET novelty_score=?,pagination_page=? WHERE id=?", updates)
    return {"dry_run": int(dry_run), "examined": len(rows), "changed": 0 if dry_run else len(updates)}


def defer_low_value_frontier(*, dry_run: bool = True, limit: int = 1000) -> dict:
    limit = max(1, min(int(limit), 10000))
    with get_db() as db:
        rows = [dict(row) for row in db.execute("""SELECT id,url FROM onion_urls WHERE active=1
          AND status IN ('new','queued','retry') AND
          (COALESCE(pagination_page,0)>=10 OR COALESCE(novelty_score,0)<=-25)
          ORDER BY pagination_page DESC,novelty_score,id LIMIT ?""", (limit,))]
    changed = 0
    if not dry_run:
        for row in rows:
            changed += int(defer_frontier_url(row["url"], "low_value_frontier_policy"))
    return {"dry_run": int(dry_run), "matched": len(rows), "changed": changed}


def mark_site_card_dirty_for_url(url: str) -> None:
    with get_db() as db:
        db.execute("""UPDATE site_cards SET rollup_dirty=1 WHERE id=(
          SELECT site_card_id FROM onion_urls WHERE url=? AND site_card_id IS NOT NULL)""", (url,))


def set_onion_liveness(url: str, fetch_status: str, liveness_status: str,
                       content_quality: str, page_type: str | None = None) -> None:
    with get_db() as db:
        db.execute("""UPDATE onion_urls SET fetch_status=?,liveness_status=?,content_quality=?,
          page_type=COALESCE(?,page_type),last_checked_at=? WHERE url=?""",
          (fetch_status, liveness_status, content_quality, page_type, utc_now_iso(), url))
    mark_site_card_dirty_for_url(url)


def elevate_review_for_indicators(url: str, indicators: list[dict]) -> bool:
    important = {"wallet_btc", "wallet_eth", "pgp_key_block", "email", "telegram_handle",
                 "jabber_id", "matrix_id", "tox_id", "session_id"}
    if not any(item.get("type") in important and float(item.get("confidence", 0)) >= 0.7 for item in indicators):
        return False
    with get_db() as db:
        db.execute("""UPDATE onion_urls SET review_status=CASE WHEN review_status='monitor' THEN 'needs_review' ELSE review_status END,
          review_score=review_score+25,ui_priority=ui_priority+25 WHERE url=? AND storage_policy!='discard'""", (url,))
    return True


def update_outbound_restriction_summary(url: str, total: int, adult: int, severe: int,
                                        adult_category_present: bool = False, *,
                                        candidate: int = 0,
                                        safe_queued: int = 0, unknown_queued: int = 0,
                                        fraud: int = 0, file_blocked: int = 0,
                                        transaction_blocked: int = 0, existing: int = 0,
                                        external_seeded: int = 0, blocked: int = 0) -> dict:
    restricted = adult + severe + candidate
    ratio = (restricted / total) if total else 0.0
    mixed = bool(restricted and restricted < total)
    with get_db() as db:
        row = db.execute("SELECT tags,site_card_id FROM onion_urls WHERE url=?", (url,)).fetchone()
        tags = []
        if row:
            try:
                tags = json.loads(row["tags"] or "[]")
            except (TypeError, ValueError):
                tags = []
        if restricted and "restricted_child_present" not in tags:
            tags.append("restricted_child_present")
        if adult and "adult_link_present" not in tags:
            tags.append("adult_link_present")
        if adult_category_present and "adult_category_present" not in tags:
            tags.append("adult_category_present")
        db.execute("""UPDATE onion_urls SET restricted_outbound_count=?,adult_outbound_count=?,
          severe_outbound_count=?,restricted_outbound_ratio=?,mixed_directory=?,restricted_child_present=?,
          adult_category_present=?,tags=?,outbound_total=?,outbound_safe_queued=?,
          outbound_unknown_queued=?,outbound_adult_restricted=?,outbound_severe_restricted=?,
          outbound_fraud_metadata_limited=?,outbound_file_blocked=?,outbound_login_transaction_blocked=?,
          outbound_existing=?,outbound_external_seeded=?,child_adult_link_count=?,
          child_restricted_link_count=?,child_blocked_link_count=?
          WHERE url=?""", (restricted, adult, severe, ratio, int(mixed), int(bool(restricted)),
                            int(adult_category_present), json.dumps(tags, ensure_ascii=False), total,
                            safe_queued, unknown_queued, adult, severe, fraud, file_blocked,
                            transaction_blocked, existing, external_seeded, adult, restricted, blocked, url))
        if row and row["site_card_id"]:
            db.execute("""UPDATE site_cards SET restricted_outbound_count=?,adult_outbound_count=?,
              severe_outbound_count=?,restricted_outbound_ratio=?,mixed_directory=?,restricted_child_present=?,
              adult_category_present=?,child_adult_link_count=?,child_restricted_link_count=?,
              child_blocked_link_count=?
              WHERE id=?""", (restricted, adult, severe, ratio, int(mixed), int(bool(restricted)),
                               int(adult_category_present), adult, restricted, blocked, row["site_card_id"]))
    mark_site_card_dirty_for_url(url)
    return {"total": total, "restricted": restricted, "adult": adult, "severe": severe,
            "unverified_restricted_candidates": candidate,
            "ratio": ratio, "mixed_directory": mixed, "adult_category_present": adult_category_present,
            "safe_queued": safe_queued, "unknown_queued": unknown_queued, "fraud": fraud,
            "file_blocked": file_blocked, "transaction_blocked": transaction_blocked,
            "existing": existing, "external_seeded": external_seeded, "blocked": blocked}


def detach_restricted_url_from_site_card(url: str) -> None:
    """Keep restricted child metadata out of an otherwise safe parent Site Card."""
    remaining_card = None
    with get_db() as db:
        row = db.execute("SELECT id,site_card_id FROM onion_urls WHERE url=?", (url,)).fetchone()
        if not row or not row["site_card_id"]:
            return
        card_id = int(row["site_card_id"])
        db.execute("DELETE FROM possible_site_card_matches WHERE onion_url_id=?", (row["id"],))
        db.execute("DELETE FROM site_fingerprints WHERE onion_url_id=?", (row["id"],))
        db.execute("DELETE FROM site_card_urls WHERE onion_url_id=?", (row["id"],))
        db.execute("UPDATE onion_urls SET site_card_id=NULL,canonical_site_id=NULL,dedupe_status='restricted' WHERE id=?",
                   (row["id"],))
        if db.execute("SELECT 1 FROM site_card_urls WHERE site_card_id=? LIMIT 1", (card_id,)).fetchone():
            remaining_card = card_id
        else:
            db.execute("DELETE FROM possible_site_card_matches WHERE candidate_site_card_id=?", (card_id,))
            db.execute("DELETE FROM site_fingerprints WHERE site_card_id=?", (card_id,))
            db.execute("DELETE FROM site_card_events WHERE site_card_id=?", (card_id,))
            db.execute("DELETE FROM site_cards WHERE id=?", (card_id,))
    if remaining_card:
        from site_dedupe import update_site_card_rollups
        update_site_card_rollups(remaining_card)


def mark_onion_soft_dead(url: str, http_status: int | None, reason: str = "soft_dead_content") -> None:
    with get_db() as db:
        db.execute("""UPDATE onion_urls SET status='dead',active=0,http_status=?,dead_reason=?,fetch_status='success',
          liveness_status='soft_dead',content_quality='unavailable',primary_category='dead_softdead',
          category='dead_softdead',category_safe_label='Dead / unavailable',review_status='monitor',
          ui_hidden_default=1,review_score=0,next_crawl_at=NULL,last_checked_at=?,last_crawled=? WHERE url=?""",
          (http_status, reason, utc_now_iso(), utc_now_iso(), url))
    mark_site_card_dirty_for_url(url)
    insert_crawl_audit(url, "content_liveness", "soft_dead", reason)


def _adult_memory_hash(value: str) -> str:
    return hashlib.sha256(value.strip().casefold().encode("utf-8", "ignore")).hexdigest()


def remember_adult_url(url: str, confidence: str = "high", rule_id: str = "adult_content_filtered",
                       diagnostics: dict | None = None) -> int:
    """Remember a filtered destination without retaining any page content or matched terms."""
    from urllib.parse import urlsplit
    host = (urlsplit(url).hostname or "").casefold()
    now = utc_now_iso()
    diagnostics = diagnostics or {}
    safe_labels = diagnostics.get("safe_signal_labels") or [rule_id]
    with get_db() as db:
        row = db.execute("SELECT id FROM onion_urls WHERE url=?", (url,)).fetchone()
        onion_url_id = int(row[0]) if row else None
        db.execute("""INSERT INTO adult_filter_memory
          (onion_url_id,url_hash,host_hash,confidence,safe_rule_id,first_seen,last_seen,match_count,
           match_scope,matched_safe_label,confidence_reason,parent_page_type,parent_primary_category,
           child_only,false_positive_guard_applied,safe_signal_labels,signal_count,signal_ratio,
           dominance_score,context_window_count,ocr_checked,ocr_restricted_hit)
          VALUES(?,?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(url_hash) DO UPDATE SET
          onion_url_id=COALESCE(adult_filter_memory.onion_url_id,excluded.onion_url_id),
          confidence=excluded.confidence,safe_rule_id=excluded.safe_rule_id,last_seen=excluded.last_seen,
          match_count=adult_filter_memory.match_count+1,match_scope=excluded.match_scope,
          matched_safe_label=excluded.matched_safe_label,confidence_reason=excluded.confidence_reason,
          parent_page_type=excluded.parent_page_type,parent_primary_category=excluded.parent_primary_category,
          child_only=excluded.child_only,false_positive_guard_applied=excluded.false_positive_guard_applied,
          safe_signal_labels=excluded.safe_signal_labels,signal_count=excluded.signal_count,
          signal_ratio=excluded.signal_ratio,dominance_score=excluded.dominance_score,
          context_window_count=excluded.context_window_count,ocr_checked=excluded.ocr_checked,
          ocr_restricted_hit=excluded.ocr_restricted_hit""",
          (onion_url_id, _adult_memory_hash(url), _adult_memory_hash(host), confidence, rule_id, now, now,
           diagnostics.get("match_scope"), safe_labels[0] if safe_labels else rule_id,
           diagnostics.get("confidence_reason") or "policy_high_confidence",
           diagnostics.get("page_type"), diagnostics.get("parent_primary_category"),
           int(bool(diagnostics.get("child_only"))), int(bool(diagnostics.get("false_positive_guard_applied"))),
           json.dumps(safe_labels, ensure_ascii=False), int(diagnostics.get("signal_count") or 0),
           float(diagnostics.get("signal_ratio") or 0), float(diagnostics.get("dominance_score") or 0),
           int(diagnostics.get("context_window_count") or 0), int(bool(diagnostics.get("ocr_checked"))),
           int(bool(diagnostics.get("ocr_restricted_hit")))))
        return int(db.execute("SELECT id FROM adult_filter_memory WHERE url_hash=?",
                              (_adult_memory_hash(url),)).fetchone()[0])


def _get_adult_memory_decision_db(db: sqlite3.Connection, url: str) -> str | None:
    """Return only an exact, independently verified destination decision.

    Historical URL/anchor-only matches and same-host match counts are not page
    evidence.  They must never block another path or sibling destination.
    """
    exact = db.execute("""SELECT afm.analyst_decision,afm.match_scope,afm.reviewed_at,
          ou.primary_category,ou.verification_state,ou.verification_reason,
          ou.destination_html_evidence_version,
          ou.classification_evidence_source
          FROM adult_filter_memory afm LEFT JOIN onion_urls ou ON ou.id=afm.onion_url_id
          WHERE afm.url_hash=?""", (_adult_memory_hash(url),)).fetchone()
    if exact:
        decision = str(exact["analyst_decision"])
        if decision == "false_positive":
            return decision
        verified_scope = str(exact["match_scope"] or "").casefold() in {
            "title", "body", "page",
        }
        page_verified = (
            exact["primary_category"] in {"adult_filtered", "adult_restricted"}
            and exact["verification_state"] == "verified"
            and exact["verification_reason"] == "page_fetched_and_classified"
            and int(exact["destination_html_evidence_version"] or 0)
                >= DESTINATION_HTML_EVIDENCE_VERSION
            and exact["classification_evidence_source"] == "destination_html"
        )
        if decision == "blocked" and (exact["reviewed_at"] or (verified_scope and page_verified)):
            return decision
    return None


def get_adult_memory_decision(url: str) -> str | None:
    """Return only an exact, independently verified destination decision."""
    with get_db() as db:
        return _get_adult_memory_decision_db(db, url)


def review_adult_memory(memory_id: int, decision: str) -> bool:
    """Apply an analyst block/false-positive decision without exposing stored content."""
    if decision not in {"blocked", "false_positive"}:
        raise ValueError("Invalid adult-filter review decision")
    now = utc_now_iso()
    reviewed = None
    quality_baseline = None
    with get_db() as db:
        row = db.execute("""SELECT afm.onion_url_id,ou.url,ou.primary_category
          FROM adult_filter_memory afm LEFT JOIN onion_urls ou ON ou.id=afm.onion_url_id
          WHERE afm.id=?""", (memory_id,)).fetchone()
        if not row:
            return False
        if row["onion_url_id"]:
            baseline_row = db.execute("""SELECT id,classifier_version,final_category
              FROM classification_decisions WHERE onion_url_id=? AND stage='page'
              AND analyst_corrected=0 ORDER BY ts DESC,id DESC LIMIT 1""",
              (int(row["onion_url_id"]),)).fetchone()
            quality_baseline = dict(baseline_row) if baseline_row else None
        db.execute("UPDATE adult_filter_memory SET analyst_decision=?,reviewed_at=? WHERE id=?",
                   (decision, now, memory_id))
        if decision == "false_positive" and row[0]:
            db.execute("""UPDATE onion_urls SET
              primary_category='unknown',category='unknown',content_category='unknown',
              site_type='unknown',risk_category='unknown',page_type='unknown',
              category_confidence='low',category_reason='Awaiting destination HTML classification',
              category_safe_label='Needs classification',display_group='Other',
              classification_decision='unverified_hint',classification_stage='prefetch',
              classification_confidence_score=0,classification_evidence_source='unverified',
              destination_html_evidence_version=0,verification_state='discovered',verified_at=NULL,
              verification_reason='analyst_filter_false_positive',risk_level='low',confidence='low',
              storage_policy='safe_summary',review_status='monitor',safety_state='safe',
              safety_reason='analyst_false_positive',screenshot_policy='blocked',
              screenshot_blocked_reason='awaiting_destination_html',queue_policy='normal',
              status='queued',active=1,next_crawl_at=?,risk_flags=NULL,tags=NULL,
              secondary_categories='[]',marketplace_type=NULL,ui_hidden_default=0,
              ui_priority=0,review_score=0,urgent_score=0,urgent_flag=0,urgent_reason=NULL,
              context_only=0,card_ready=0,card_readiness_reason='awaiting_page_classification',
              card_readiness_confidence='low',category_evidence_json=NULL,
              category_supporting_evidence_json=NULL,category_contradicting_evidence_json=NULL,
              category_update_allowed=0,category_update_reason='awaiting_destination_html',
              spain_priority=0,geo_priority=NULL,spain_match_reason=NULL,
              spain_match_language=NULL,spain_confidence=NULL,spain_context_tags=NULL,
              spain_priority_reason=NULL,spain_priority_evidence_type=NULL,
              spain_relevance='none',spain_evidence_type=NULL,seller_geo_confidence='none',
              spain_context_only=0,spain_actionable=0,spain_evidence_score=0,
              spain_evidence_families=NULL,spain_evidence_direction='context_only'
              WHERE id=?""", (now, int(row[0])))
        reviewed = dict(row)
    if reviewed.get("url"):
        final_category = "unknown" if decision == "false_positive" else "adult_filtered"
        record_classification_decision(
            reviewed["url"], {
                "primary_category": final_category, "suggested_category": final_category,
                "category_confidence": "analyst", "classification_confidence_score": 1.0,
                "classification_decision": "analyst_confirmed", "classifier_version": "analyst-v1",
                "category_reason": f"Analyst adult-filter review: {decision}",
                "evidence_families": ["analyst_safety_review"],
            }, stage="analyst", previous_category=reviewed.get("primary_category"),
            analyst_corrected=True, safe_metadata={"scope": "adult_filter_memory"},
        )
        try:
            record_classification_feedback(
                subject=f"adult-memory:{memory_id}",
                feedback_scope="safety",
                feedback_action=(
                    "adult_false_positive"
                    if decision == "false_positive"
                    else "adult_block_confirmed"
                ),
                reason_code="analyst_adult_filter_review",
                decision_id=quality_baseline.get("id") if quality_baseline else None,
                onion_url_id=reviewed.get("onion_url_id"),
                site_card_id=None,
                previous_category=reviewed.get("primary_category"),
                final_category=final_category,
                classifier_version=(
                    quality_baseline.get("classifier_version")
                    if quality_baseline else None
                ),
                safe_metadata={
                    "scope": "adult_filter_memory",
                    "confirmed": decision == "blocked",
                },
            )
        except (TypeError, ValueError, sqlite3.Error):
            pass
    return True


def get_next_onion_url(now_iso: str | None = None, exploration: bool = False) -> dict | None:
    now_iso = now_iso or utc_now_iso()
    with get_db() as db:
        row = db.execute("""SELECT * FROM onion_urls WHERE active=1 AND status IN ('new','queued','retry')
            AND COALESCE(queue_policy,'normal')!='blocked' AND (next_crawl_at IS NULL OR next_crawl_at<=?)
            ORDER BY (COALESCE(frontier_priority,0)+COALESCE(novelty_score,0)-
              CASE WHEN status='retry' THEN 100 ELSE 0 END) DESC,spain_priority DESC,
            CASE WHEN lower(COALESCE(risk_level,'')) IN ('critico','critical','alto','high') THEN 0 ELSE 1 END,
            priority_score DESC,
            CASE WHEN source_type='onion_internal' THEN 0 ELSE 1 END,
            CASE WHEN lower(COALESCE(primary_category,'')) IN
              ('directory','forum','index','directory_index','forum_social','marketplace') THEN 0 ELSE 1 END,
            CASE status WHEN 'queued' THEN 0 WHEN 'new' THEN 1 ELSE 2 END,depth,
            CASE WHEN ? THEN RANDOM() ELSE 0 END,first_seen LIMIT 1""",
                         (now_iso, int(exploration))).fetchone()
        return _dict(row)


def worker_claims_paused(db: sqlite3.Connection | None = None) -> bool:
    """Return the durable pipeline pause flag without changing active work.

    The flag is checked inside each claim transaction.  A pause therefore
    prevents new work from entering the assembly line while allowing a unit
    that was already claimed to finish cleanly.
    """
    if db is not None:
        row = db.execute("SELECT is_paused FROM crawler_worker_state WHERE id=1").fetchone()
        return bool(row and int(row[0] or 0))
    with get_db() as connection:
        return worker_claims_paused(connection)


def claim_next_onion_url(now_iso: str | None = None, *, worker_id: str | None = None,
                         exploration: bool = False, claim_timeout_minutes: int = 45) -> dict | None:
    """Atomically claim one frontier row, committing before any network work begins."""
    now_iso = now_iso or utc_now_iso()
    worker_id = worker_id or f"pid:{os.getpid()}"
    stale_before = (datetime.now(timezone.utc) - timedelta(minutes=max(5, claim_timeout_minutes))).isoformat().replace("+00:00", "Z")
    with get_db() as db:
        _begin_immediate(db, "claim_fetch", worker_id)
        if worker_claims_paused(db):
            return None
        db.execute("""UPDATE onion_urls SET status='retry',claimed_at=NULL,claimed_by=NULL,
          next_crawl_at=COALESCE(next_retry_at,?) WHERE status IN ('claimed','fetching')
          AND claimed_at IS NOT NULL AND claimed_at<?""", (now_iso, stale_before))
        row = db.execute("""SELECT id FROM onion_urls WHERE active=1 AND status IN ('new','queued','retry')
          AND COALESCE(queue_policy,'normal')!='blocked'
          AND (next_crawl_at IS NULL OR next_crawl_at<=?)
          AND (next_retry_at IS NULL OR next_retry_at<=?)
          ORDER BY (COALESCE(frontier_priority,0)+COALESCE(novelty_score,0)-
            CASE WHEN status='retry' THEN 100 ELSE 0 END) DESC,spain_priority DESC,
          CASE WHEN lower(COALESCE(risk_level,'')) IN ('critico','critical','alto','high') THEN 0 ELSE 1 END,
          priority_score DESC,CASE WHEN source_type='onion_internal' THEN 0 ELSE 1 END,
          CASE status WHEN 'queued' THEN 0 WHEN 'new' THEN 1 ELSE 2 END,depth,
          CASE WHEN ? THEN RANDOM() ELSE 0 END,first_seen LIMIT 1""",
          (now_iso, now_iso, int(exploration))).fetchone()
        if not row:
            return None
        changed = db.execute("""UPDATE onion_urls SET status='claimed',claimed_at=?,claimed_by=?
          WHERE id=? AND status IN ('new','queued','retry')""", (now_iso, worker_id, row["id"])).rowcount
        if changed != 1:
            return None
        return _dict(db.execute("SELECT * FROM onion_urls WHERE id=?", (row["id"],)).fetchone())


def heartbeat_worker_instance(worker_id: str, worker_type: str, state: str,
                              *, current_url_id: int | None = None,
                              current_job_id: int | None = None,
                              last_error: str | None = None,
                              processed_increment: int = 0,
                              observe: bool = True) -> None:
    now = utc_now_iso()
    with get_db() as db:
        db.execute("""INSERT INTO worker_instances
          (worker_id,worker_type,pid,state,current_url_id,current_job_id,last_heartbeat_at,
           processed_total,last_error,started_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(worker_id) DO UPDATE SET worker_type=excluded.worker_type,
          pid=excluded.pid,state=excluded.state,current_url_id=excluded.current_url_id,
          current_job_id=excluded.current_job_id,last_heartbeat_at=excluded.last_heartbeat_at,
          processed_total=worker_instances.processed_total+?,
          last_error=CASE WHEN excluded.last_error IS NOT NULL THEN excluded.last_error
            WHEN excluded.state NOT IN ('error','failed') THEN NULL ELSE worker_instances.last_error END,
          updated_at=excluded.updated_at""",
          (worker_id, worker_type, os.getpid(), state, current_url_id, current_job_id,
           now, int(processed_increment), last_error, now, now, int(processed_increment)))
    if observe:
        try:
            import operational_observability as operations
            operations.record_worker_state(
                worker_type, worker_id, state, current_url_id=current_url_id,
                current_job_id=current_job_id, last_error=last_error)
        except Exception:
            pass


def store_fetched_page_snapshot(url_id: int, url: str, *, worker_id: str | None,
                                response_status: int | None, content_type: str | None,
                                headers: dict | None, title: str | None, meta_text: str,
                                visible_text: str, link_records: list[dict],
                                page_structure: dict, pre_policy: dict) -> int:
    now = utc_now_iso()
    with get_db() as db:
        _begin_immediate(db, "finish_fetch", worker_id)
        source = db.execute(
            "SELECT status,claimed_by FROM onion_urls WHERE id=?", (url_id,)
        ).fetchone()
        if not source:
            raise WorkerClaimLost(f"onion_url_missing:{url_id}")
        claim_scoped = source["status"] in {"claimed", "fetching"}
        if claim_scoped and (not worker_id or source["claimed_by"] != worker_id):
            raise WorkerClaimLost(f"fetch_claim_lost:{url_id}")
        db.execute("""INSERT INTO fetched_pages
          (onion_url_id,url,worker_id,classification_status,fetched_at,response_status,content_type,headers_json,
           title,meta_text,visible_text,link_records_json,page_structure_json,pre_policy_json)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(onion_url_id) DO UPDATE SET url=excluded.url,worker_id=excluded.worker_id,
          classification_status='pending',claimed_at=NULL,claimed_by=NULL,fetched_at=excluded.fetched_at,
          response_status=excluded.response_status,content_type=excluded.content_type,
          headers_json=excluded.headers_json,title=excluded.title,meta_text=excluded.meta_text,
          visible_text=excluded.visible_text,link_records_json=excluded.link_records_json,
          page_structure_json=excluded.page_structure_json,pre_policy_json=excluded.pre_policy_json,
          error=NULL,verified_at=NULL""",
          (url_id, url, worker_id, "pending", now, response_status, content_type,
           json.dumps(headers or {}, ensure_ascii=False), title, meta_text or "", visible_text or "",
           json.dumps(link_records or [], ensure_ascii=False),
           json.dumps(page_structure or {}, ensure_ascii=False),
           json.dumps(pre_policy or {}, ensure_ascii=False)))
        owner_clause = " AND claimed_by=?" if claim_scoped else ""
        owner_params: tuple[Any, ...] = (worker_id,) if claim_scoped else ()
        changed = db.execute("""UPDATE onion_urls SET status='classification_pending',
          verification_state='classification_pending',last_fetch_status='success',
          last_http_status=?,http_status=?,last_checked_at=?,claimed_at=NULL,claimed_by=NULL
          WHERE id=?""" + owner_clause,
          (response_status, response_status, now, url_id, *owner_params)).rowcount
        if changed != 1:
            raise WorkerClaimLost(f"fetch_claim_lost:{url_id}")
        row = db.execute("SELECT id FROM fetched_pages WHERE onion_url_id=?", (url_id,)).fetchone()
        return int(row["id"])


_CONTEXT_LINK_REPOSITORY_COUNT_FIELDS = frozenset({
    "onion_link_count", "internal_link_count", "external_onion_count",
    "external_onion_host_count", "link_observation_count", "unique_link_count",
    "duplicate_link_observation_count", "forum_link_count", "market_link_count",
    "form_count", "navigation_link_count", "repeated_link_row_count",
})
_CONTEXT_LINK_REPOSITORY_DECODING_FIELDS = frozenset({
    "charset", "source", "confidence", "fallback_used", "http_charset_declared",
    "http_charset_valid", "bom_present", "meta_charset_declared",
    "meta_charset_valid", "failed_candidates",
})
_CONTEXT_LINK_REPOSITORY_FORUM_FIELDS = frozenset({
    "role", "engine", "confidence", "stable_key", "canonical_identity_hash", "reason",
})
_SAFE_STRUCTURE_CODE = re.compile(r"^[a-z0-9][a-z0-9_.:\-]{0,319}$", re.IGNORECASE)


def _safe_structure_code(value: object, *, maximum: int = 320) -> str | None:
    text = str(value or "").strip()[:maximum]
    return text if text and _SAFE_STRUCTURE_CODE.fullmatch(text) else None


def _context_link_repository_structure(page_structure: object) -> dict:
    """Return the strict structural subset allowed for a context-only repository."""
    source = page_structure if isinstance(page_structure, dict) else {}
    summary: dict[str, object] = {}
    for key in _CONTEXT_LINK_REPOSITORY_COUNT_FIELDS:
        value = source.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)) and math.isfinite(float(value)):
            summary[key] = max(0, int(value))
    density = source.get("link_density")
    if (isinstance(density, (int, float)) and not isinstance(density, bool)
            and math.isfinite(float(density))):
        summary["link_density"] = max(0.0, min(1.0, float(density)))

    page_type_info = source.get("page_type_info") if isinstance(source.get("page_type_info"), dict) else {}
    page_type = _safe_structure_code(source.get("page_type") or page_type_info.get("page_type"), maximum=80)
    page_type_confidence = _safe_structure_code(
        source.get("page_type_confidence") or page_type_info.get("page_type_confidence"), maximum=32)
    page_type_score = source.get("page_type_score", page_type_info.get("page_type_score"))
    if page_type:
        summary["page_type"] = page_type
    if page_type_confidence:
        summary["page_type_confidence"] = page_type_confidence
    if (isinstance(page_type_score, (int, float)) and not isinstance(page_type_score, bool)
            and math.isfinite(float(page_type_score))):
        summary["page_type_score"] = max(0, int(page_type_score))

    decoding_source = source.get("decoding") if isinstance(source.get("decoding"), dict) else {}
    decoding: dict[str, object] = {}
    for key in _CONTEXT_LINK_REPOSITORY_DECODING_FIELDS:
        value = decoding_source.get(key)
        if isinstance(value, bool):
            decoding[key] = value
        elif (key == "failed_candidates" and isinstance(value, (int, float))
              and math.isfinite(float(value))):
            decoding[key] = max(0, int(value))
        elif key in {"charset", "source", "confidence"}:
            safe_value = _safe_structure_code(value, maximum=80)
            if safe_value:
                decoding[key] = safe_value
    if decoding:
        summary["decoding"] = decoding
    charset = _safe_structure_code(source.get("decoding_charset") or decoding.get("charset"), maximum=80)
    decoding_origin = _safe_structure_code(source.get("decoding_source") or decoding.get("source"), maximum=80)
    if charset:
        summary["decoding_charset"] = charset
    if decoding_origin:
        summary["decoding_source"] = decoding_origin

    forum_source = source.get("forum_route_hint")
    if not isinstance(forum_source, dict):
        # Read legacy snapshots as route hints, never as confirmed identity.
        forum_source = source.get("forum_url_identity")
    if not isinstance(forum_source, dict):
        forum_source = source.get("forum_identity") if isinstance(source.get("forum_identity"), dict) else {}
    forum_hint: dict[str, object] = {}
    for key in _CONTEXT_LINK_REPOSITORY_FORUM_FIELDS:
        safe_value = _safe_structure_code(forum_source.get(key), maximum=320)
        if safe_value:
            forum_hint[key] = safe_value
    if forum_hint:
        forum_hint.update(hint_verified=False, evidence_source="url_route")
        summary["forum_route_hint"] = forum_hint
    return summary


def sanitize_context_only_restricted_link_repository_snapshot(
        fetched_page_id: int, *, safe_title: str | None,
        sanitized_link_records: list[dict]) -> bool:
    """Retain only safe structure for one verified context-only link repository.

    ``sanitized_link_records`` is an explicit trust boundary: the caller must
    already have removed restricted child labels and raw local context.  This
    function never touches ``onion_urls``, Site Cards, analyst decisions, or
    any child URL; it updates only the identified fetched snapshot.
    """
    if not isinstance(sanitized_link_records, list) or any(
            not isinstance(record, dict) for record in sanitized_link_records):
        raise ValueError("sanitized_link_records must be a list of sanitized dictionaries")
    try:
        link_records_json = json.dumps(
            sanitized_link_records, ensure_ascii=False, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("sanitized_link_records must be JSON serializable") from exc
    retained_title = str(safe_title).strip()[:180] if safe_title is not None else None
    retained_title = retained_title or None
    with get_db() as db:
        row = db.execute("SELECT page_structure_json FROM fetched_pages WHERE id=?",
                         (int(fetched_page_id),)).fetchone()
        if not row:
            return False
        try:
            page_structure = json.loads(row["page_structure_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            page_structure = {}
        structural_summary = _context_link_repository_structure(page_structure)
        changed = db.execute("""UPDATE fetched_pages SET title=?,meta_text='',visible_text='',
          link_records_json=?,page_structure_json=? WHERE id=?""",
          (retained_title, link_records_json,
           json.dumps(structural_summary, ensure_ascii=False, sort_keys=True, allow_nan=False),
           int(fetched_page_id))).rowcount
    return changed == 1


def _worker_error_decision(error: str, attempts: int, max_attempts: int = 4) -> dict:
    text = str(error or "")
    lowered = text.casefold()
    transient_markers = ("locked", "busy", "timeout", "timed out", "temporar", "connection",
                         "tor", "playwright", "ocr", "chromium", "database is locked", "i/o")
    deterministic_markers = ("keyerror", "valueerror", "jsondecodeerror", "integrityerror",
                             "schema", "contract", "invariant", "missing required")
    transient = any(marker in lowered for marker in transient_markers)
    deterministic = any(marker in lowered for marker in deterministic_markers) and not transient
    error_type = next((marker.replace(" ", "_") for marker in deterministic_markers + transient_markers
                       if marker in lowered), type(error).__name__ if not isinstance(error, str) else "worker_error")
    next_attempt = int(attempts or 0) + 1
    if deterministic and next_attempt >= 2:
        return {"status": "dead_letter", "error_type": error_type, "retryable": False,
                "next_retry_at": None, "dead_letter_reason": error_type}
    if next_attempt >= max(1, int(max_attempts or 4)):
        return {"status": "dead_letter", "error_type": error_type, "retryable": False,
                "next_retry_at": None, "dead_letter_reason": "max_attempts_exceeded"}
    minutes = [5, 30, 120][min(next_attempt - 1, 2)]
    retry_at = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")
    return {"status": "retry", "error_type": error_type, "retryable": True,
            "next_retry_at": retry_at, "dead_letter_reason": None}


def claim_next_fetched_page(worker_id: str | None = None,
                            claim_timeout_minutes: int = 45) -> dict | None:
    worker_id = worker_id or f"verify:{os.getpid()}"
    now = utc_now_iso()
    stale_before = (datetime.now(timezone.utc) - timedelta(minutes=max(5, claim_timeout_minutes))).isoformat().replace("+00:00", "Z")
    with get_db() as db:
        _begin_immediate(db, "claim_verify", worker_id)
        if worker_claims_paused(db):
            return None
        db.execute("""UPDATE fetched_pages SET classification_status='retry',
          claimed_at=NULL,claimed_by=NULL WHERE classification_status='claimed'
          AND claimed_at IS NOT NULL AND claimed_at<?""", (stale_before,))
        row = db.execute("""SELECT id FROM fetched_pages
          WHERE classification_status IN ('pending','retry')
          AND (next_retry_at IS NULL OR next_retry_at<=?)
          ORDER BY fetched_at,id LIMIT 1""", (now,)).fetchone()
        if not row:
            return None
        changed = db.execute("""UPDATE fetched_pages SET classification_status='claimed',
          claimed_at=?,claimed_by=? WHERE id=? AND classification_status IN ('pending','retry')
          AND (next_retry_at IS NULL OR next_retry_at<=?)""",
          (now, worker_id, row["id"], now)).rowcount
        if changed != 1:
            return None
        snapshot = _dict(db.execute("""SELECT fp.*,ou.depth,ou.source_url,ou.source_type,
          ou.primary_category,ou.analyst_category,ou.classification_decision,ou.site_card_id,
          ou.verified_at AS prior_verified_at,ou.verification_reason AS prior_verification_reason,
          ou.destination_html_evidence_version AS prior_destination_html_evidence_version,
          ou.classification_evidence_source AS prior_classification_evidence_source
          FROM fetched_pages fp JOIN onion_urls ou ON ou.id=fp.onion_url_id
          WHERE fp.id=?""", (row["id"],)).fetchone())
    if snapshot:
        for key in ("headers_json", "link_records_json", "page_structure_json", "pre_policy_json"):
            try:
                snapshot[key[:-5] if key.endswith("_json") else key] = json.loads(snapshot.get(key) or "{}")
            except (TypeError, json.JSONDecodeError):
                snapshot[key[:-5] if key.endswith("_json") else key] = [] if key == "link_records_json" else {}
    return snapshot


def mark_fetched_page_verified(snapshot_id: int, worker_id: str | None = None) -> bool:
    with get_db() as db:
        owner_clause = " AND classification_status='claimed' AND claimed_by=?" if worker_id else ""
        params: tuple[Any, ...] = (utc_now_iso(), snapshot_id, worker_id) if worker_id else (
            utc_now_iso(), snapshot_id)
        changed = db.execute("""UPDATE fetched_pages SET classification_status='done',verified_at=?,
          claimed_at=NULL,claimed_by=NULL WHERE id=?""" + owner_clause, params).rowcount
        return changed == 1


def reject_unproven_fetched_page(snapshot_id: int, onion_url_id: int,
                                 worker_id: str | None = None) -> bool:
    """Scrub a legacy snapshot whose parser evidence boundary is unknown.

    The URL is returned to the fetch frontier unless an explicit analyst block
    owns it.  No legacy title/body/anchor-derived material reaches classifiers.
    """
    now = utc_now_iso()
    with get_db() as db:
        _begin_immediate(db, "finish_verify", worker_id)
        owner_clause = " AND classification_status='claimed' AND claimed_by=?" if worker_id else ""
        params: tuple[Any, ...] = (now, snapshot_id, worker_id) if worker_id else (now, snapshot_id)
        changed = db.execute("""UPDATE fetched_pages SET response_status=NULL,content_type=NULL,
          headers_json='{}',title=NULL,meta_text='',visible_text='',link_records_json='[]',
          page_structure_json='{}',pre_policy_json='{}',classification_status='failed',
          claimed_at=NULL,claimed_by=NULL,last_error='legacy_snapshot_without_content_boundary',
          next_retry_at=NULL,failed_at=? WHERE id=?""" + owner_clause, params).rowcount
        if changed != 1:
            return False
        db.execute("""UPDATE onion_urls SET status='queued',active=1,queue_policy='normal',
          storage_policy='safe_summary',verification_state='provisional',verified_at=NULL,
          verification_reason='legacy_snapshot_without_content_boundary',
          primary_category='unknown',category='unknown',content_category='unknown',
          category_confidence='low',category_reason='Awaiting destination HTML classification',
          category_safe_label='Needs classification',classification_decision='unverified_hint',
          classification_stage='prefetch',classification_confidence_score=0,
          safety_reason='awaiting_destination_html',risk_level='low',risk_flags='[]',tags='[]',
          screenshot_policy='blocked',screenshot_blocked_reason='awaiting_destination_html',
          next_crawl_at=?,claimed_at=NULL,claimed_by=NULL
          WHERE id=? AND analyst_category IS NULL
          AND NOT EXISTS (SELECT 1 FROM adult_filter_memory afm
            WHERE afm.onion_url_id=onion_urls.id AND afm.analyst_decision='blocked'
            AND afm.reviewed_at IS NOT NULL)""", (now, onion_url_id))
        return True


def mark_fetched_page_error(snapshot_id: int, error: str, retry: bool = True,
                            worker_id: str | None = None) -> bool:
    transition_status: str | None = None
    retry_count: int | None = None
    with get_db() as db:
        _begin_immediate(db, "fail_verify", worker_id)
        owner_clause = " AND classification_status='claimed' AND claimed_by=?" if worker_id else ""
        owner_params: tuple[Any, ...] = (worker_id,) if worker_id else ()
        row = db.execute("SELECT attempts,max_attempts FROM fetched_pages WHERE id=?" + owner_clause,
                         (snapshot_id, *owner_params)).fetchone()
        if not row:
            return False
        attempts = int(row["attempts"] or 0) if row else 0
        retry_count = attempts + 1
        max_attempts = int(row["max_attempts"] or 4) if row else 4
        decision = _worker_error_decision(error, attempts, max_attempts) if retry else {
            "status": "failed", "error_type": "non_retryable", "next_retry_at": None,
            "dead_letter_reason": "non_retryable_failure",
        }
        now = utc_now_iso()
        changed = db.execute("""UPDATE fetched_pages SET classification_status=?,error=?,last_error=?,
          error_type=?,attempts=attempts+1,next_retry_at=?,failed_at=?,
          dead_letter_reason=?,claimed_at=NULL,claimed_by=NULL WHERE id=?""" + owner_clause,
          (decision["status"], str(error)[:500], str(error)[:500], decision["error_type"],
           decision["next_retry_at"], now, decision["dead_letter_reason"], snapshot_id,
           *owner_params)).rowcount
        if changed == 1:
            transition_status = str(decision["status"])
    if transition_status:
        _observe_job_transition(
            "verify", worker_id, transition_status, job_id=int(snapshot_id),
            error_label=error, retry_count=retry_count)
    return transition_status is not None


def create_site_card_job(*, onion_url_id: int | None = None, url: str | None = None,
                         site_card_id: int | None = None, job_type: str = "rollup",
                         priority: int = 0) -> int:
    now = utc_now_iso()
    with get_db() as db:
        _begin_immediate(db, "enqueue_card", None)
        row = db.execute("""SELECT id,status FROM site_card_jobs WHERE job_type=?
          AND COALESCE(onion_url_id,0)=COALESCE(?,0)
          AND COALESCE(site_card_id,0)=COALESCE(?,0) LIMIT 1""",
          (job_type, onion_url_id, site_card_id)).fetchone()
        if row:
            db.execute("""UPDATE site_card_jobs SET
              status=CASE WHEN status='claimed' THEN status WHEN status='dead_letter' THEN status ELSE 'queued' END,
              priority=MAX(COALESCE(priority,0),?), url=COALESCE(?,url), updated_at=?,
              next_retry_at=CASE WHEN status='dead_letter' THEN next_retry_at ELSE NULL END
              WHERE id=?""", (int(priority), url, now, row["id"]))
            return int(row["id"])
        db.execute("""INSERT INTO site_card_jobs
          (onion_url_id,site_card_id,url,job_type,status,priority,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?)""",
          (onion_url_id, site_card_id, url, job_type, "queued", int(priority), now, now))
        row = db.execute("SELECT last_insert_rowid() AS id").fetchone()
        return int(row["id"])


def claim_next_site_card_job(worker_id: str | None = None,
                             claim_timeout_minutes: int = 45) -> dict | None:
    worker_id = worker_id or f"card:{os.getpid()}"
    now = utc_now_iso()
    stale_before = (datetime.now(timezone.utc) - timedelta(minutes=max(5, claim_timeout_minutes))).isoformat().replace("+00:00", "Z")
    with get_db() as db:
        _begin_immediate(db, "claim_card", worker_id)
        if worker_claims_paused(db):
            return None
        db.execute("""UPDATE site_card_jobs SET status='retry',claimed_at=NULL,claimed_by=NULL
          WHERE status='claimed' AND claimed_at IS NOT NULL AND claimed_at<?""", (stale_before,))
        row = db.execute("""SELECT id FROM site_card_jobs WHERE status IN ('queued','retry')
          AND (next_retry_at IS NULL OR next_retry_at<=?)
          ORDER BY priority DESC,created_at,id LIMIT 1""", (now,)).fetchone()
        if not row:
            return None
        changed = db.execute("""UPDATE site_card_jobs SET status='claimed',
          claimed_at=?,claimed_by=?,updated_at=?
          WHERE id=? AND status IN ('queued','retry') AND (next_retry_at IS NULL OR next_retry_at<=?)""",
          (now, worker_id, now, row["id"], now)).rowcount
        if changed != 1:
            return None
        return _dict(db.execute("""SELECT scj.*,ou.primary_category,ou.storage_policy,
          ou.title AS onion_title FROM site_card_jobs scj
          LEFT JOIN onion_urls ou ON ou.id=scj.onion_url_id WHERE scj.id=?""",
          (row["id"],)).fetchone())


def finish_site_card_job(job_id: int, *, success: bool = True,
                         error: str | None = None, site_card_id: int | None = None,
                         worker_id: str | None = None) -> bool:
    transition_status: str | None = None
    retry_count: int | None = None
    with get_db() as db:
        _begin_immediate(db, "finish_card", worker_id)
        owner_clause = " AND status='claimed' AND claimed_by=?" if worker_id else ""
        owner_params: tuple[Any, ...] = (worker_id,) if worker_id else ()
        if not success:
            row = db.execute("SELECT attempts,max_attempts FROM site_card_jobs WHERE id=?" + owner_clause,
                             (job_id, *owner_params)).fetchone()
            if not row:
                return False
            retry_count = int(row["attempts"] or 0) + 1
            decision = _worker_error_decision(error or "card_job_failed",
                                              int(row["attempts"] or 0) if row else 0,
                                              int(row["max_attempts"] or 4) if row else 4)
            changed = db.execute("""UPDATE site_card_jobs SET status=?,last_error=?,error_type=?,
              attempts=attempts+1,
              failed_at=?,dead_letter_reason=?,next_retry_at=?,site_card_id=COALESCE(?,site_card_id),
              claimed_at=NULL,claimed_by=NULL,updated_at=? WHERE id=?""" + owner_clause,
              (decision["status"], str(error)[:500] if error else "card_job_failed",
               decision["error_type"], utc_now_iso(), decision["dead_letter_reason"],
                decision["next_retry_at"], site_card_id, utc_now_iso(), job_id,
                *owner_params)).rowcount
            if changed == 1:
                transition_status = str(decision["status"])
        else:
            changed = db.execute("""UPDATE site_card_jobs SET status=?,last_error=?,site_card_id=COALESCE(?,site_card_id),
              claimed_at=NULL,claimed_by=NULL,updated_at=? WHERE id=?""" + owner_clause,
              ("done", None, site_card_id, utc_now_iso(), job_id, *owner_params)).rowcount
    if transition_status:
        _observe_job_transition(
            "card", worker_id, transition_status, job_id=int(job_id),
            error_label=error, retry_count=retry_count)
    return changed == 1


def defer_site_card_job(job_id: int, worker_id: str, *,
                        reason: str = "site_card_already_processing",
                        delay_seconds: int = 30) -> bool:
    """Release a claimed card job without treating ordinary lock contention as failure."""
    now_dt = datetime.now(timezone.utc)
    next_retry_at = (now_dt + timedelta(seconds=max(5, int(delay_seconds)))).isoformat().replace(
        "+00:00", "Z")
    now = now_dt.isoformat().replace("+00:00", "Z")
    with get_db() as db:
        changed = db.execute("""UPDATE site_card_jobs SET status='retry',last_error=?,
          error_type='lock_contention',next_retry_at=?,claimed_at=NULL,claimed_by=NULL,updated_at=?
          WHERE id=? AND status='claimed' AND claimed_by=?""",
          (str(reason)[:500], next_retry_at, now, job_id, worker_id)).rowcount
        return changed == 1


def acquire_site_card_processing(site_card_id: int, worker_id: str,
                                 claim_timeout_minutes: int = 45) -> bool:
    now = utc_now_iso()
    stale_before = (datetime.now(timezone.utc) - timedelta(minutes=max(5, claim_timeout_minutes))).isoformat().replace("+00:00", "Z")
    with get_db() as db:
        return db.execute("""UPDATE site_cards SET rollup_claimed_by=?,rollup_claimed_at=?
          WHERE id=? AND (rollup_claimed_by IS NULL OR rollup_claimed_at IS NULL OR rollup_claimed_at<?)""",
          (worker_id, now, site_card_id, stale_before)).rowcount == 1


def release_site_card_processing(site_card_id: int, worker_id: str | None = None) -> None:
    with get_db() as db:
        db.execute("""UPDATE site_cards SET rollup_claimed_by=NULL,rollup_claimed_at=NULL
          WHERE id=? AND (? IS NULL OR rollup_claimed_by=?)""", (site_card_id, worker_id, worker_id))


def acquire_maintenance_leader(task_name: str, worker_id: str,
                               lease_seconds: int = 1800) -> bool:
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat().replace("+00:00", "Z")
    expires = (now_dt + timedelta(seconds=max(60, lease_seconds))).isoformat().replace("+00:00", "Z")
    with get_db() as db:
        _begin_immediate(db, "claim_maintenance", worker_id)
        existing = db.execute("SELECT expires_at FROM maintenance_leases WHERE task_name=?",
                              (task_name,)).fetchone()
        if existing and str(existing["expires_at"]) > now:
            return False
        db.execute("""INSERT INTO maintenance_leases(task_name,worker_id,acquired_at,expires_at)
          VALUES(?,?,?,?) ON CONFLICT(task_name) DO UPDATE SET worker_id=excluded.worker_id,
          acquired_at=excluded.acquired_at,expires_at=excluded.expires_at""",
          (task_name, worker_id, now, expires))
        return True


def release_maintenance_leader(task_name: str, worker_id: str) -> None:
    with get_db() as db:
        db.execute("DELETE FROM maintenance_leases WHERE task_name=? AND worker_id=?",
                   (task_name, worker_id))


def mark_url_fetching(url_id: int, worker_id: str | None = None) -> bool:
    with get_db() as db:
        changed = db.execute("""UPDATE onion_urls SET status='fetching',last_fetch_status='fetching'
          WHERE id=? AND status='claimed' AND (? IS NULL OR claimed_by=?)""",
          (url_id, worker_id, worker_id)).rowcount
        return changed == 1


def release_url_claim(url: str, status: str = "blocked",
                      worker_id: str | None = None) -> bool:
    """Finish a claim for a URL resolved without a network fetch."""
    if status not in {"blocked", "retry", "deferred", "deferred_deep_pagination", "ignored", "metadata_only"}:
        raise ValueError("Invalid non-fetch claim result")
    with get_db() as db:
        owner_clause = " AND claimed_by=?" if worker_id else ""
        params: tuple[Any, ...] = (
            status, "policy_blocked" if status in {"blocked", "metadata_only"} else status,
            url, *((worker_id,) if worker_id else ()),
        )
        changed = db.execute("""UPDATE onion_urls SET status=?,claimed_at=NULL,claimed_by=NULL,
          last_fetch_status=? WHERE url=? AND status IN ('claimed','fetching')""" + owner_clause,
          params).rowcount
        return changed == 1


def mark_onion_crawled(url: str, http_status: int | None, title: str | None,
                       content_hash: str | None, fuzzy_hash: str | None,
                       relevance_score: int, risk_score: int, risk_level: str,
                       reasons: list[str], risk_flags: list[str], status: str,
                       next_crawl_at: str | None) -> None:
    with get_db() as db:
        db.execute("""UPDATE onion_urls SET last_seen=?,last_crawled=?,next_crawl_at=?,status=?,
          http_status=?,title=?,content_hash=?,fuzzy_hash=?,relevance_score=?,risk_score=?,
          risk_level=?,reasons=?,risk_flags=?,last_error=NULL,last_checked_at=?,
          claimed_at=NULL,claimed_by=NULL,
          last_fetch_status='success',last_http_status=?,next_retry_at=NULL WHERE url=?""",
          (utc_now_iso(), utc_now_iso(), next_crawl_at, status, http_status, title,
           content_hash, fuzzy_hash, relevance_score, risk_score, risk_level,
           json.dumps(reasons, ensure_ascii=False), json.dumps(risk_flags, ensure_ascii=False),
           utc_now_iso(), http_status, url))


def mark_onion_error(url: str, error: str, next_crawl_at: str | None, dead: bool = False,
                     worker_id: str | None = None) -> bool:
    with get_db() as db:
        owner_clause = " AND status IN ('claimed','fetching') AND claimed_by=?" if worker_id else ""
        owner_params: tuple[Any, ...] = (worker_id,) if worker_id else ()
        changed = db.execute("""UPDATE onion_urls SET error_count=error_count+1,retry_count=retry_count+1,
          last_error=?,next_crawl_at=?,next_retry_at=?,
          status=CASE WHEN ? THEN 'dead' ELSE 'retry' END,last_crawled=?,last_checked_at=?,
          active=CASE WHEN ? THEN 0 ELSE active END,dead_reason=CASE WHEN ? THEN 'too_many_errors' ELSE dead_reason END,
          fetch_status='error',last_fetch_status='error',claimed_at=NULL,claimed_by=NULL,
          liveness_status=CASE WHEN ? THEN 'hard_dead' ELSE 'unknown' END
          WHERE url=?""" + owner_clause,
          (str(error)[:500], next_crawl_at, next_crawl_at, int(dead), utc_now_iso(), utc_now_iso(),
           int(dead), int(dead), int(dead), url, *owner_params)).rowcount
    if changed:
        _observe_job_transition(
            "fetch", worker_id, "dead" if dead else "retry", target=url,
            error_label=error)
        mark_site_card_dirty_for_url(url)
    return changed == 1


def insert_onion_edge(source_url: str, discovered_url: str, context: dict | None = None) -> None:
    context = context or {}
    with get_db() as db:
        db.execute("""INSERT INTO onion_edges(source_url,discovered_url,first_seen,relation_type,
          safe_anchor_text,source_page_type,same_host,policy_reason,relation_verified,
          relation_evidence_source) VALUES(?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(source_url,discovered_url) DO UPDATE SET
          relation_type=excluded.relation_type,
          safe_anchor_text=COALESCE(excluded.safe_anchor_text,onion_edges.safe_anchor_text),
          source_page_type=COALESCE(excluded.source_page_type,onion_edges.source_page_type),
          same_host=excluded.same_host,policy_reason=COALESCE(excluded.policy_reason,onion_edges.policy_reason),
          relation_verified=0,relation_evidence_source=excluded.relation_evidence_source""",
          (source_url, discovered_url, utc_now_iso(), context.get("relation_type") or "unknown",
            context.get("safe_anchor_text"), context.get("source_page_type"),
            int(bool(context.get("same_host"))), context.get("policy_reason"), 0,
            context.get("evidence_source") or "discovery_metadata"))


def insert_onion_hit(url: str, title: str | None, score: int, risk_level: str,
                     reasons: list[str], snippet: str, indicators: list[dict],
                     source_chain: str | None, passive_exposures: list[dict] | None = None,
                     *, allow_unverified_legacy: bool = False) -> int:
    if not allow_unverified_legacy and not is_onion_url_verified(url):
        raise ValueError("Normal results require a fetched and verified page")
    with get_db() as db:
        cur = db.execute("""INSERT INTO onion_hits
          (ts,url,title,score,risk_level,reasons,snippet,indicators_json,source_chain,passive_exposures_json)
          VALUES(?,?,?,?,?,?,?,?,?,?)""", (utc_now_iso(), url, title, score, risk_level,
          json.dumps(reasons, ensure_ascii=False), snippet,
          json.dumps(indicators, ensure_ascii=False), source_chain,
          json.dumps(passive_exposures or [], ensure_ascii=False)))
        return int(cur.lastrowid)


def insert_alert_from_onion_hit(onion_hit_id: int) -> int:
    with get_db() as db:
        hit = db.execute("SELECT * FROM onion_hits WHERE id=?", (onion_hit_id,)).fetchone()
        if not hit:
            raise ValueError("Unknown onion hit")
        if not is_onion_url_verified(hit["url"]):
            return 0
        table = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alert_log'").fetchone()
        if not table:
            db.execute("CREATE TABLE alert_log(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, alert_type TEXT NOT NULL, details TEXT)")
        columns = {row[1] for row in db.execute("PRAGMA table_info(alert_log)")}
        candidates: dict[str, Any] = {
            "ts": utc_now_iso(), "alert_type": "onion_hit", "score": hit["score"],
            "risk_level": hit["risk_level"], "classification": "passive_osint",
            "reasons": hit["reasons"], "details": f"{hit['title'] or ''}\n{hit['url']}\n{hit['snippet'] or ''}"[:1500],
        }
        payload = {key: value for key, value in candidates.items() if key in columns}
        names = list(payload)
        cur = db.execute(f"INSERT INTO alert_log ({','.join(names)}) VALUES ({','.join('?' for _ in names)})",
                         tuple(payload[name] for name in names))
        alert_id = int(cur.lastrowid)
        db.execute("UPDATE onion_hits SET alert_log_id=? WHERE id=?", (alert_id, onion_hit_id))
        return alert_id


def upsert_indicator(indicator_type: str, value: str, normalized_value: str,
                     source_type: str, source_ref: str | None, confidence: float,
                     risk_flags: list[str] | None = None) -> int:
    now = utc_now_iso()
    with get_db() as db:
        db.execute("""INSERT INTO indicators
          (indicator_type,value,normalized_value,first_seen,last_seen,source_type,source_ref,confidence,risk_flags)
          VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(indicator_type,normalized_value) DO UPDATE SET
          last_seen=excluded.last_seen,confidence=MAX(indicators.confidence,excluded.confidence)""",
          (indicator_type, value, normalized_value, now, now, source_type, source_ref, confidence,
           json.dumps(risk_flags or [], ensure_ascii=False)))
        return int(db.execute("SELECT id FROM indicators WHERE indicator_type=? AND normalized_value=?",
                              (indicator_type, normalized_value)).fetchone()[0])


def link_indicator(indicator_id: int, source_type: str, source_ref: str,
                   context_snippet: str | None) -> None:
    with get_db() as db:
        exists = db.execute("SELECT 1 FROM indicator_links WHERE indicator_id=? AND source_type=? AND source_ref=?",
                            (indicator_id, source_type, source_ref)).fetchone()
        if not exists:
            db.execute("INSERT INTO indicator_links(indicator_id,source_type,source_ref,context_snippet,first_seen) VALUES(?,?,?,?,?)",
                       (indicator_id, source_type, source_ref, context_snippet, utc_now_iso()))


def insert_passive_exposures(url: str, exposures: list[dict]) -> None:
    with get_db() as db:
        for exposure in exposures:
            db.execute("""INSERT INTO passive_exposures
              (ts,url,exposure_type,severity,value,context,source,confidence) VALUES(?,?,?,?,?,?,?,?)""",
              (utc_now_iso(), url, exposure.get("type"), exposure.get("severity"), exposure.get("value"),
               exposure.get("context"), exposure.get("source", "normal_fetch_response"), exposure.get("confidence", 0.5)))


def create_or_update_mirror_cluster(url: str, title: str | None, content_hash: str | None,
                                    fuzzy_hash: str | None, indicators: list[dict], relevance_score: int,
                                    risk_score: int, risk_level: str, source_type: str,
                                    source_ref: str | None = None) -> int | None:
    if relevance_score <= 0 and not indicators:
        return None
    values = sorted({f"{i.get('type')}:{i.get('normalized_value', i.get('value'))}" for i in indicators})
    now = utc_now_iso()
    with get_db() as db:
        existing_url = db.execute("SELECT cluster_id FROM mirror_urls WHERE url=?", (url,)).fetchone()
        cluster_id = int(existing_url[0]) if existing_url and existing_url[0] else None
        if cluster_id is None:
            clauses, params = [], []
            if content_hash:
                clauses.append("u.content_hash=?"); params.append(content_hash)
            if fuzzy_hash:
                clauses.append("u.fuzzy_hash=?"); params.append(fuzzy_hash)
            if title:
                clauses.append("lower(u.title)=lower(?)"); params.append(title[:180])
            for value in values[:3]:
                clauses.append("c.shared_indicators_json LIKE ?"); params.append(f"%{value[:120]}%")
            candidates = (db.execute(f"""SELECT DISTINCT c.id,c.shared_indicators_json,u.title,
                u.content_hash,u.fuzzy_hash FROM mirror_clusters c
                LEFT JOIN mirror_urls u ON u.cluster_id=c.id
                WHERE {' OR '.join(clauses)} ORDER BY c.last_seen DESC LIMIT 250""", params).fetchall()
                if clauses else [])
            best_id, best_score = None, 0.0
            candidate_values = set(values)
            for row in candidates:
                shared = set(json.loads(row[1] or "[]"))
                signals = [bool(content_hash and row[3] == content_hash), bool(fuzzy_hash and row[4] == fuzzy_hash),
                           bool(title and row[2] and title.casefold() == row[2].casefold()), bool(shared & candidate_values)]
                score = max((1.0 if signals[0] else 0), (0.8 if signals[1] else 0),
                            (0.75 if signals[2] else 0), (0.8 if signals[3] else 0))
                if score > best_score:
                    best_id, best_score = int(row[0]), score
            cluster_id = best_id if best_score >= 0.75 else None
        if cluster_id is None:
            cur = db.execute("""INSERT INTO mirror_clusters
              (cluster_type,first_seen,last_seen,relevance_score,risk_score,risk_level,status,summary,shared_indicators_json)
              VALUES('unknown',?,?,?,?,?,'active',?,?)""",
              (now, now, relevance_score, risk_score, risk_level, title or "Passive mirror cluster", json.dumps(values, ensure_ascii=False)))
            cluster_id = int(cur.lastrowid)
        else:
            current = db.execute("SELECT shared_indicators_json FROM mirror_clusters WHERE id=?", (cluster_id,)).fetchone()
            merged = sorted(set(json.loads(current[0] or "[]")) | set(values))
            db.execute("""UPDATE mirror_clusters SET last_seen=?,relevance_score=MAX(relevance_score,?),
              risk_score=MAX(risk_score,?),risk_level=?,shared_indicators_json=? WHERE id=?""",
              (now, relevance_score, risk_score, risk_level, json.dumps(merged, ensure_ascii=False), cluster_id))
        db.execute("""INSERT INTO mirror_urls
          (cluster_id,url,source_type,source_ref,first_seen,last_seen,title,content_hash,fuzzy_hash)
          VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET
          cluster_id=excluded.cluster_id,last_seen=excluded.last_seen,title=excluded.title,
          content_hash=excluded.content_hash,fuzzy_hash=excluded.fuzzy_hash""",
          (cluster_id, url, source_type, source_ref, now, now, title, content_hash, fuzzy_hash))
        return cluster_id


def update_cluster_attribution_profile(cluster_id: int, profile: dict) -> None:
    with get_db() as db:
        db.execute("UPDATE mirror_clusters SET attribution_profile_json=? WHERE id=?",
                   (json.dumps(profile, ensure_ascii=False), cluster_id))


def get_pending_onion_hits(limit: int = 25) -> list[dict]:
    with get_db() as db:
        return [dict(row) for row in db.execute("SELECT * FROM onion_hits WHERE review_status='pending' ORDER BY id DESC LIMIT ?", (limit,))]


def get_mirror_clusters(limit: int = 50) -> list[dict]:
    with get_db() as db:
        return [dict(row) for row in db.execute("SELECT * FROM mirror_clusters ORDER BY last_seen DESC LIMIT ?", (limit,))]


def get_mirror_cluster(cluster_id: int) -> dict | None:
    with get_db() as db:
        cluster = _dict(db.execute("SELECT * FROM mirror_clusters WHERE id=?", (cluster_id,)).fetchone())
        if cluster:
            cluster["urls"] = [dict(row) for row in db.execute("""SELECT mu.*,
              ou.primary_category,ou.storage_policy,ou.review_status AS policy_review_status,
              ou.screenshot_policy,ou.screenshot_blocked_reason,ou.spain_priority,
              ou.spain_match_reason,ou.spain_match_language,ou.spain_confidence,
              ou.risk_level AS policy_risk_level,ou.active AS crawl_active
              FROM mirror_urls mu LEFT JOIN onion_urls ou ON ou.url=mu.url
              WHERE mu.cluster_id=? ORDER BY mu.last_seen DESC""", (cluster_id,))]
            urls = [row["url"] for row in cluster["urls"]]
            cluster["passive_exposures"] = [] if not urls else [dict(row) for row in db.execute(
                f"SELECT * FROM passive_exposures WHERE url IN ({','.join('?' for _ in urls)}) ORDER BY ts DESC", urls)]
        return cluster


def get_indicators_by_value(value: str) -> list[dict]:
    with get_db() as db:
        return [dict(row) for row in db.execute("""SELECT i.*,l.source_type AS link_source_type,
          l.source_ref AS link_source_ref,l.context_snippet FROM indicators i LEFT JOIN indicator_links l ON l.indicator_id=i.id
          WHERE i.normalized_value LIKE ? ORDER BY i.last_seen DESC""", (f"%{value.casefold()}%",))]


def set_review_status(source: str, id: int, status: str, reviewed_by: str | None = None) -> None:
    table = {"onion_hit": "onion_hits", "onion_hits": "onion_hits", "cluster": "mirror_clusters",
             "mirror_cluster": "mirror_clusters", "onion_url": "onion_urls"}.get(source)
    if not table or status not in {"pending", "relevant", "false_positive", "needs_report", "reported", "blocked"}:
        raise ValueError("Invalid review source or status")
    with get_db() as db:
        db.execute(f"UPDATE {table} SET review_status=? WHERE id=?", (status, id))


def insert_evidence_report(report_type: str, output_path: str, generated_by: str,
                           cluster_id: int | None = None, alert_log_id: int | None = None,
                           site_card_id: int | None = None) -> int:
    with get_db() as db:
        cur = db.execute("""INSERT INTO evidence_reports
          (ts,report_type,cluster_id,alert_log_id,output_path,generated_by,site_card_id)
          VALUES(?,?,?,?,?,?,?)""",
          (utc_now_iso(), report_type, cluster_id, alert_log_id, output_path, generated_by, site_card_id))
        return int(cur.lastrowid)


def get_site_card_reports(site_card_id: int, limit: int = 20) -> list[dict]:
    with get_db() as db:
        return [dict(row) for row in db.execute("""SELECT * FROM evidence_reports
          WHERE site_card_id=? ORDER BY ts DESC,id DESC LIMIT ?""",
          (site_card_id, max(1, min(int(limit), 100))))]


def mark_site_card_report_failed(site_card_id: int, error: Exception) -> None:
    with get_db() as db:
        db.execute("""UPDATE site_cards SET report_status='failed',report_error=? WHERE id=?""",
                   (f"{type(error).__name__}: {str(error)[:300]}", site_card_id))


def upsert_page_preview(url: str, preview_path: str, status: str = "available") -> int:
    now = utc_now_iso()
    with get_db() as db:
        db.execute("""INSERT INTO page_previews(url,preview_path,created_at,updated_at,status)
          VALUES(?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET preview_path=excluded.preview_path,
          updated_at=excluded.updated_at,status=excluded.status""", (url, preview_path, now, now, status))
        db.execute("""UPDATE page_preview_jobs SET status='available',preview_path=?,available_at=?,
          updated_at=?,claimed_at=NULL,claimed_by=NULL,last_error=NULL,blocked_reason=NULL
          WHERE url=?""", (preview_path, now, now, url))
        return int(db.execute("SELECT id FROM page_previews WHERE url=?", (url,)).fetchone()[0])


def get_page_preview(url: str) -> dict | None:
    with get_db() as db:
        return _dict(db.execute("SELECT * FROM page_previews WHERE url=?", (url,)).fetchone())


def block_page_preview(url: str, reason: str) -> None:
    with get_db() as db:
        now = utc_now_iso()
        db.execute("""INSERT INTO page_previews(url,preview_path,created_at,updated_at,status)
          VALUES(?,?,?,?, 'blocked') ON CONFLICT(url) DO UPDATE SET
          preview_path='',status='blocked',updated_at=excluded.updated_at""",
          (url, "", now, now))
        db.execute("""INSERT INTO page_preview_jobs
          (url,onion_url_id,site_card_id,status,blocked_reason,created_at,updated_at)
          SELECT ou.url,ou.id,ou.site_card_id,'blocked',?,?,? FROM onion_urls ou WHERE ou.url=?
          ON CONFLICT(url) DO UPDATE SET status='blocked',blocked_reason=excluded.blocked_reason,
          last_error=NULL,claimed_at=NULL,claimed_by=NULL,updated_at=excluded.updated_at""",
          (reason, now, now, url))
        db.execute("UPDATE onion_urls SET screenshot_policy='blocked',screenshot_blocked_reason=? WHERE url=?",
                   (reason, url))


def mark_page_preview_failed(url: str, error: str, *, retry: bool = True) -> None:
    """Record a runtime preview failure without changing URL crawl state."""
    now = utc_now_iso()
    with get_db() as db:
        db.execute("""INSERT INTO page_preview_jobs
          (url,onion_url_id,site_card_id,status,attempts,last_error,created_at,updated_at)
          SELECT ou.url,ou.id,ou.site_card_id,?,?,?, ?,? FROM onion_urls ou WHERE ou.url=?
          ON CONFLICT(url) DO UPDATE SET status=excluded.status,last_error=excluded.last_error,
          claimed_at=NULL,claimed_by=NULL,updated_at=excluded.updated_at""",
          (("retry" if retry else "failed"), 0, str(error)[:500], now, now, url))
        db.execute("""INSERT INTO page_previews(url,preview_path,created_at,updated_at,status)
          VALUES(?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET preview_path='',
          status=excluded.status,updated_at=excluded.updated_at""",
          (url, "", now, now, "failed"))


def get_page_preview_state(url: str) -> dict | None:
    with get_db() as db:
        return _dict(db.execute("""SELECT pp.status AS preview_status,pp.preview_path,
          pp.updated_at AS preview_updated_at,pj.status AS job_status,pj.attempts,pj.claimed_at,
          pj.claimed_by,pj.last_error,pj.blocked_reason,pj.updated_at AS job_updated_at
          FROM onion_urls ou
          LEFT JOIN page_previews pp ON pp.url=ou.url
          LEFT JOIN page_preview_jobs pj ON pj.url=ou.url
          WHERE ou.url=?""", (url,)).fetchone())


def _preview_job_eligible_where() -> str:
    return """ou.status='crawled' AND ou.active=1
      AND COALESCE(ou.screenshot_policy,'blocked')='allowed'
      AND COALESCE(ou.storage_policy,'')='safe_summary'
      AND COALESCE(ou.review_status,'') NOT IN ('restricted','filtered')
      AND COALESCE(ou.primary_category,'') NOT IN ('adult_filtered','adult_restricted','severe_abuse_risk')
      AND COALESCE(ou.queue_policy,'normal')!='blocked'
      AND ou.http_status BETWEEN 200 AND 399"""


def create_page_preview_job(url: str, *, onion_url_id: int | None = None,
                            site_card_id: int | None = None,
                            force: bool = False, priority: str = "auto",
                            requested_by: str | None = None,
                            request_reason: str | None = None) -> int | None:
    """Queue a durable preview capture job for an already-safe crawled page."""
    now = utc_now_iso()
    with get_db() as db:
        row = db.execute(f"""SELECT id,url,site_card_id FROM onion_urls ou
          WHERE ou.url=? AND {_preview_job_eligible_where()}""", (url,)).fetchone()
        if not row:
            return None
        existing_available = db.execute("""SELECT 1 FROM page_previews
          WHERE url=? AND status='available' AND preview_path!=''""", (url,)).fetchone()
        if existing_available and not force:
            return None
        current = db.execute("SELECT id,status FROM page_preview_jobs WHERE url=?", (url,)).fetchone()
        if current:
            if current["status"] in {"claimed", "available"} and not force:
                return int(current["id"])
            db.execute("""UPDATE page_preview_jobs SET status='queued',
              onion_url_id=?,site_card_id=?,claimed_at=NULL,claimed_by=NULL,last_error=NULL,
              blocked_reason=NULL,updated_at=?,priority=?,priority_score=?,
              requested_by=COALESCE(?,requested_by),requested_at=COALESCE(?,requested_at),
              request_reason=COALESCE(?,request_reason),force=? WHERE id=?""",
              (onion_url_id or row["id"], site_card_id if site_card_id is not None else row["site_card_id"],
               now, priority, 100 if priority == "manual" else 0, requested_by,
               now if requested_by else None, request_reason, int(force), current["id"]))
            return int(current["id"])
        db.execute("""INSERT INTO page_preview_jobs
          (url,onion_url_id,site_card_id,status,created_at,updated_at,priority,priority_score,
           requested_by,requested_at,request_reason,force)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
          (url, onion_url_id or row["id"],
           site_card_id if site_card_id is not None else row["site_card_id"], "queued", now, now,
           priority, 100 if priority == "manual" else 0, requested_by,
           now if requested_by else None, request_reason, int(force)))
        return int(db.execute("SELECT last_insert_rowid()").fetchone()[0])


def _is_front_preview_candidate(url: str, page_type: str | None = None) -> bool:
    try:
        path = urlsplit(url).path.casefold()
    except ValueError:
        return False
    blocked = ("/vendor", "/vendors", "/listing", "/product", "/cart", "/checkout",
               "/payment", "/account", "/login", "/upload")
    if any(path.startswith(item) for item in blocked):
        return False
    return True


def queue_preview_for_site_card(site_card_id: int, *, force: bool = False,
                                priority: str = "manual") -> dict:
    with get_db() as db:
        rows = [dict(row) for row in db.execute(f"""SELECT ou.*,fp.content_type,pp.status AS preview_status,
          pp.preview_path,pj.status AS job_status FROM onion_urls ou
          LEFT JOIN fetched_pages fp ON fp.onion_url_id=ou.id
          LEFT JOIN page_previews pp ON pp.url=ou.url
          LEFT JOIN page_preview_jobs pj ON pj.url=ou.url
          WHERE ou.site_card_id=? AND {_preview_job_eligible_where()}""", (site_card_id,))]
    safe = [row for row in rows if _is_front_preview_candidate(row["url"], row.get("page_type"))
            and (not row.get("content_type") or str(row.get("content_type")).split(";", 1)[0].strip().lower()
                 in {"text/html", "application/xhtml+xml"})]
    if not safe:
        return {"status": "no_safe_url", "site_card_id": site_card_id}
    def rank(row: dict) -> tuple:
        try:
            path = urlsplit(row["url"]).path or "/"
        except ValueError:
            path = "/zzz"
        page_type = str(row.get("page_type") or "")
        return (
            0 if path in {"", "/", "/index.html", "/index.php", "/home"} else 1,
            0 if page_type in {"homepage", "marketplace_front", "forum_index",
                                "directory_index_page", "link_repository"} else 1,
            len(path),
        )
    selected = sorted(safe, key=rank)[0]
    preview_path = selected.get("preview_path")
    if preview_path and Path(preview_path).is_file() and not force:
        return {"status": "already_available", "url": selected["url"], "preview_path": preview_path}
    if selected.get("job_status") == "claimed" and not force:
        return {"status": "already_claimed", "url": selected["url"]}
    job_id = create_page_preview_job(selected["url"], onion_url_id=int(selected["id"]),
                                     site_card_id=site_card_id, force=force,
                                     priority=priority, requested_by="dashboard",
                                     request_reason="manual_card_preview")
    return {"status": "queued" if job_id else "blocked_by_policy",
            "job_id": job_id, "url": selected["url"], "site_card_id": site_card_id}


def get_site_card_sections(site_card_id: int, limit: int = 100) -> list[dict]:
    """Return safe per-path section metadata for one Site Card/root."""
    with get_db() as db:
        rows = [dict(row) for row in db.execute("""SELECT ou.id,ou.url,scu.path,ou.title,
          ou.detected_title,ou.safe_display_name,ou.primary_category,ou.category_reason,
          ou.spain_relevance,ou.spain_evidence_type,ou.spain_priority,ou.first_seen,
          ou.last_seen,ou.last_checked_at,ou.storage_policy,ou.review_status,
          pp.status AS preview_status
          FROM site_card_urls scu JOIN onion_urls ou ON ou.id=scu.onion_url_id
          LEFT JOIN page_previews pp ON pp.url=ou.url
          WHERE scu.site_card_id=?
          ORDER BY CASE COALESCE(scu.path,'/') WHEN '/' THEN 0 ELSE 1 END,scu.path,ou.id
          LIMIT ?""", (site_card_id, max(1, min(int(limit), 500))))] 
    sections = []
    for row in rows:
        restricted = row.get("storage_policy") in {"metadata_only", "discard"} or row.get("review_status") == "restricted"
        sections.append({
            "path": row.get("path") or "/",
            "url": row.get("url"),
            "discovered_title": None if restricted else (row.get("safe_display_name") or row.get("detected_title") or row.get("title")),
            "category": row.get("primary_category") or "unknown",
            "category_evidence": row.get("category_reason"),
            "spain_evidence": row.get("spain_evidence_type") if row.get("spain_priority") else row.get("spain_relevance"),
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "last_checked_at": row.get("last_checked_at"),
            "preview_state": row.get("preview_status") or "missing",
            "restricted": int(bool(restricted)),
        })
    return sections


def preview_capture_limit_reached() -> bool:
    from config_loader import get_int
    window_seconds = max(60, get_int("SCREENSHOT_RATE_WINDOW_SECONDS", 3600))
    max_captures = max(1, get_int("SCREENSHOT_MAX_PER_RUN", 5))
    since = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat().replace("+00:00", "Z")
    with get_db() as db:
        count = db.execute("""SELECT COUNT(*) FROM page_preview_jobs
          WHERE status='available' AND COALESCE(available_at,updated_at)>=?""", (since,)).fetchone()[0]
        return int(count) >= max_captures


def claim_next_page_preview_job(worker_id: str | None = None,
                                claim_timeout_minutes: int = 45) -> dict | None:
    worker_id = worker_id or f"preview:{os.getpid()}"
    now = utc_now_iso()
    stale_before = (datetime.now(timezone.utc) - timedelta(minutes=max(5, claim_timeout_minutes))).isoformat().replace("+00:00", "Z")
    with get_db() as db:
        _begin_immediate(db, "claim_preview", worker_id)
        if worker_claims_paused(db):
            return None
        db.execute("""UPDATE page_preview_jobs SET status='retry',claimed_at=NULL,claimed_by=NULL
          WHERE status='claimed' AND claimed_at IS NOT NULL AND claimed_at<?""", (stale_before,))
        row = db.execute("""SELECT pj.id FROM page_preview_jobs pj
          JOIN onion_urls ou ON ou.url=pj.url
          WHERE pj.status IN ('queued','retry')
          AND COALESCE(pj.attempts,0)<COALESCE(pj.max_attempts,4)
          AND (pj.next_retry_at IS NULL OR pj.next_retry_at<=?)
          AND """ + _preview_job_eligible_where() + """
          ORDER BY COALESCE(pj.priority_score,0) DESC,
          CASE COALESCE(pj.priority,'auto') WHEN 'manual' THEN 0 WHEN 'retry' THEN 1 ELSE 2 END,
          pj.created_at,pj.id LIMIT 1""", (now,)).fetchone()
        if not row:
            return None
        changed = db.execute("""UPDATE page_preview_jobs SET status='claimed',
          claimed_at=?,claimed_by=?,updated_at=?
          WHERE id=? AND status IN ('queued','retry')
          AND COALESCE(attempts,0)<COALESCE(max_attempts,4)
          AND (next_retry_at IS NULL OR next_retry_at<=?)""",
          (now, worker_id, now, row["id"], now)).rowcount
        if changed != 1:
            return None
        return _dict(db.execute("""SELECT pj.*,ou.http_status,ou.storage_policy,ou.review_status,
          ou.screenshot_policy,ou.primary_category FROM page_preview_jobs pj
          JOIN onion_urls ou ON ou.url=pj.url WHERE pj.id=?""", (row["id"],)).fetchone())


def finish_page_preview_job(job_id: int, *, success: bool, preview_path: str | None = None,
                            error: str | None = None, blocked_reason: str | None = None,
                            retry: bool = False, worker_id: str | None = None,
                            preview_status: str = "available") -> bool:
    now = utc_now_iso()
    transition_status: str | None = None
    retry_count: int | None = None
    with get_db() as db:
        _begin_immediate(db, "finish_preview", worker_id)
        owner_clause = " AND status='claimed' AND claimed_by=?" if worker_id else ""
        owner_params: tuple[Any, ...] = (worker_id,) if worker_id else ()
        row = db.execute("SELECT attempts,max_attempts FROM page_preview_jobs WHERE id=?" + owner_clause,
                         (job_id, *owner_params)).fetchone()
        if not row:
            return False
        retry_count = int(row["attempts"] or 0) + (0 if success or blocked_reason else 1)
        decision = None
        if not success and not blocked_reason and retry:
            decision = _worker_error_decision(
                error or "preview_capture_failed", int(row["attempts"] or 0),
                int(row["max_attempts"] or 4))
        status = ("available" if success else "blocked" if blocked_reason else
                  decision["status"] if decision else "failed")
        changed = db.execute("""UPDATE page_preview_jobs SET status=?,preview_path=COALESCE(?,preview_path),
          available_at=CASE WHEN ? THEN ? ELSE available_at END,last_error=?,blocked_reason=?,
          attempts=attempts+CASE WHEN ? THEN 0 ELSE 1 END,
          next_retry_at=?,error_type=?,failed_at=CASE WHEN ? THEN failed_at ELSE ? END,
          dead_letter_reason=?,claimed_at=NULL,claimed_by=NULL,updated_at=? WHERE id=?""" + owner_clause,
          (status, preview_path, int(success), now, None if success else (str(error)[:500] if error else None),
           blocked_reason, int(success or bool(blocked_reason)),
           decision.get("next_retry_at") if decision else None,
           decision.get("error_type") if decision else (None if success else "non_retryable"),
           int(success), now, decision.get("dead_letter_reason") if decision else None,
           now, job_id, *owner_params)).rowcount
        if changed and success:
            safe_status = preview_status if preview_status in {"available", "available_ocr_unchecked"} else "available"
            db.execute("""INSERT INTO page_previews(url,preview_path,created_at,updated_at,status)
              SELECT url,?,?,?,? FROM page_preview_jobs WHERE id=?
              ON CONFLICT(url) DO UPDATE SET preview_path=excluded.preview_path,
              status=excluded.status,updated_at=excluded.updated_at""",
              (preview_path or "", now, now, safe_status, job_id))
        elif changed:
            preview_status = "blocked" if blocked_reason else "failed"
            db.execute("""INSERT INTO page_previews(url,preview_path,created_at,updated_at,status)
              SELECT url,'',?,?,? FROM page_preview_jobs WHERE id=?
              ON CONFLICT(url) DO UPDATE SET preview_path='',status=excluded.status,
              updated_at=excluded.updated_at""", (now, now, preview_status, job_id))
        if changed and not success and not blocked_reason:
            transition_status = str(status)
    if transition_status:
        _observe_job_transition(
            "preview", worker_id, transition_status, job_id=int(job_id),
            error_label=error, retry_count=retry_count)
    return changed == 1


def reconcile_page_preview_artifacts(limit: int = 500, *, dry_run: bool = False) -> dict:
    from screenshot_service import screenshot_path_for_url
    limit = max(1, min(int(limit), 5000))
    summary = {
        "dry_run": int(dry_run), "files_found": 0, "db_available": 0,
        "registered_existing_files": 0, "missing_files_marked_stale": 0,
        "blocked_files_deleted": 0, "orphan_files": 0, "would_change": 0,
    }
    with get_db() as db:
        previews = [dict(row) for row in db.execute(
            "SELECT * FROM page_previews WHERE status='available' LIMIT ?", (limit,))]
        urls = [dict(row) for row in db.execute(f"""SELECT ou.* FROM onion_urls ou
          WHERE {_preview_job_eligible_where()} LIMIT ?""", (limit,))]
    summary["db_available"] = len(previews)
    for row in previews:
        path = Path(row.get("preview_path") or "")
        if not path.is_file():
            summary["missing_files_marked_stale"] += 1
            summary["would_change"] += 1
            if not dry_run:
                with get_db() as db:
                    db.execute("""UPDATE page_previews SET status='missing_file',preview_path='',
                      updated_at=? WHERE id=?""", (utc_now_iso(), row["id"]))
    known_by_path = {screenshot_path_for_url(row["url"]).resolve(): row for row in urls}
    try:
        files = [path for path in PREVIEWS_DIR.glob("*.png") if path.is_file()]
    except OSError:
        files = []
    summary["files_found"] = len(files)
    seen = set()
    for path in files:
        resolved = path.resolve()
        row = known_by_path.get(resolved)
        if not row:
            summary["orphan_files"] += 1
            continue
        seen.add(row["url"])
        current = get_page_preview(row["url"])
        if not current or current.get("status") != "available" or not current.get("preview_path"):
            summary["registered_existing_files"] += 1
            summary["would_change"] += 1
            if not dry_run:
                upsert_page_preview(row["url"], str(path), status="available")
    with get_db() as db:
        blocked = [dict(row) for row in db.execute("""SELECT url,preview_path FROM page_previews
          WHERE status='available' AND url IN (SELECT url FROM onion_urls WHERE
          primary_category IN ('adult_filtered','adult_restricted','severe_abuse_risk')
          OR storage_policy IN ('metadata_only','discard') OR screenshot_policy='blocked') LIMIT ?""", (limit,))]
    for row in blocked:
        path = Path(row.get("preview_path") or "")
        if path.is_file():
            summary["blocked_files_deleted"] += 1
            summary["would_change"] += 1
            if not dry_run:
                try:
                    path.unlink()
                except OSError:
                    pass
                block_page_preview(row["url"], "preview_reconcile_policy_block")
    return summary


def upsert_site_profile(url: str, display_name: str, category: str, explanation: str,
                        source_summary: str | None = None) -> None:
    with get_db() as db:
        db.execute("""INSERT INTO site_profiles(url,display_name,category,explanation,source_summary,updated_at)
          VALUES(?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET display_name=excluded.display_name,
          category=excluded.category,explanation=excluded.explanation,
          source_summary=excluded.source_summary,updated_at=excluded.updated_at""",
          (url, display_name, category, explanation, source_summary, utc_now_iso()))


def queue_existing_onion_url(url: str) -> bool:
    """Queue an already-known URL. Blocked URLs remain blocked by policy."""
    with get_db() as db:
        cur = db.execute("""UPDATE onion_urls SET status='queued',next_crawl_at=?,last_error=NULL
          WHERE url=? AND status!='blocked' AND active=1 AND COALESCE(queue_policy,'normal')!='blocked'""", (utc_now_iso(), url))
        return cur.rowcount > 0


def queue_discovered_urls(limit: int = 50) -> int:
    """Requeue known discovered links only; never invents or fetches a URL."""
    with get_db() as db:
        rows = db.execute("""SELECT url FROM onion_urls WHERE source_url IS NOT NULL
          AND active=1 AND COALESCE(queue_policy,'normal')!='blocked'
          AND status IN ('new','retry') ORDER BY priority_score DESC,first_seen LIMIT ?""", (max(1, min(limit, 200)),)).fetchall()
        for row in rows:
            db.execute("UPDATE onion_urls SET status='queued',next_crawl_at=?,last_error=NULL WHERE url=?",
                       (utc_now_iso(), row["url"]))
        return len(rows)


def queue_missing_previews(limit: int = 20) -> int:
    """Queue preview jobs for successful, non-blocked pages without touching crawl state."""
    with get_db() as db:
        rows = db.execute("""SELECT ou.id,ou.url,ou.site_card_id FROM onion_urls ou
          LEFT JOIN page_previews pp ON pp.url=ou.url
          LEFT JOIN fetched_pages fp ON fp.onion_url_id=ou.id
          LEFT JOIN page_preview_jobs pj ON pj.url=ou.url
          WHERE """ + _preview_job_eligible_where() + """
          AND (fp.content_type IS NULL OR lower(fp.content_type) LIKE 'text/html%'
               OR lower(fp.content_type) LIKE 'application/xhtml+xml%')
          AND (pp.url IS NULL OR pp.status!='available' OR COALESCE(pp.preview_path,'')='')
          AND (pj.url IS NULL OR pj.status IN ('failed','blocked','retry','queued'))
          ORDER BY ou.last_crawled DESC LIMIT ?""", (max(1, min(limit, 100)),)).fetchall()
    queued = 0
    for row in rows:
        if create_page_preview_job(row["url"], onion_url_id=int(row["id"]),
                                   site_card_id=row["site_card_id"], force=True):
            queued += 1
    return queued


def queue_missing_topics(limit: int = 50) -> int:
    """Queue previously successful pages that have not received text topics yet."""
    with get_db() as db:
        rows = db.execute("""SELECT ou.url FROM onion_urls ou LEFT JOIN page_topics pt ON pt.url=ou.url
          WHERE ou.status='crawled' AND ou.active=1 AND ou.storage_policy!='metadata_only'
          AND ou.http_status BETWEEN 200 AND 399 AND pt.url IS NULL
          ORDER BY ou.last_crawled DESC LIMIT ?""", (max(1, min(limit, 200)),)).fetchall()
        for row in rows:
            db.execute("UPDATE onion_urls SET status='queued',next_crawl_at=? WHERE url=?",
                       (utc_now_iso(), row["url"]))
        return len(rows)


def queue_uncertain_urls(limit: int = 50) -> int:
    """Recheck fetched pages that still lack a reliable page-level classification."""
    with get_db() as db:
        rows = db.execute("""SELECT url FROM onion_urls WHERE verification_state='verified'
          AND primary_category='unknown' AND active=1 AND COALESCE(queue_policy,'normal')!='blocked'
          AND status='crawled' ORDER BY suggested_category IS NOT NULL DESC,last_checked_at LIMIT ?""",
          (max(1, min(limit, 200)),)).fetchall()
        for row in rows:
            db.execute("""UPDATE onion_urls SET status='queued',next_crawl_at=?,
              verification_reason='queued_for_deeper_page_understanding' WHERE url=?""",
              (utc_now_iso(), row["url"]))
        return len(rows)


def worker_failures_summary() -> dict:
    with get_db() as db:
        fetched = {row["classification_status"]: int(row["count"]) for row in db.execute(
            "SELECT classification_status,COUNT(*) count FROM fetched_pages GROUP BY classification_status")}
        cards = {row["status"]: int(row["count"]) for row in db.execute(
            "SELECT status,COUNT(*) count FROM site_card_jobs GROUP BY status")}
        errors = [dict(row) for row in db.execute("""SELECT 'verify' AS stage,error_type,last_error,failed_at
          FROM fetched_pages WHERE classification_status IN ('retry','failed','dead_letter')
          UNION ALL
          SELECT 'card' AS stage,error_type,last_error,failed_at
          FROM site_card_jobs WHERE status IN ('retry','failed','dead_letter')
          ORDER BY failed_at DESC LIMIT 20""")]
        common = [dict(row) for row in db.execute("""SELECT stage,error_type,COUNT(*) count FROM (
          SELECT 'verify' AS stage,COALESCE(error_type,'unknown') error_type FROM fetched_pages
          WHERE classification_status IN ('retry','failed','dead_letter')
          UNION ALL
          SELECT 'card' AS stage,COALESCE(error_type,'unknown') error_type FROM site_card_jobs
          WHERE status IN ('retry','failed','dead_letter')) GROUP BY stage,error_type
          ORDER BY count DESC,error_type LIMIT 20""")]
    return {"fetched_pages": fetched, "site_card_jobs": cards,
            "recent_errors": errors, "common_error_types": common}


def requeue_failed_verifications(*, dry_run: bool = True) -> dict:
    now = utc_now_iso()
    with get_db() as db:
        rows = db.execute("""SELECT id FROM fetched_pages
          WHERE classification_status IN ('failed','retry','dead_letter')""").fetchall()
        if not dry_run:
            db.execute("""UPDATE fetched_pages SET classification_status='retry',next_retry_at=?,
              claimed_at=NULL,claimed_by=NULL,dead_letter_reason=NULL WHERE
              classification_status IN ('failed','retry','dead_letter')""", (now,))
    return {"dry_run": int(dry_run), "matched": len(rows), "requeued": 0 if dry_run else len(rows)}


def requeue_failed_card_jobs(*, dry_run: bool = True) -> dict:
    now = utc_now_iso()
    with get_db() as db:
        rows = db.execute("""SELECT id FROM site_card_jobs
          WHERE status IN ('failed','retry','dead_letter')""").fetchall()
        if not dry_run:
            db.execute("""UPDATE site_card_jobs SET status='retry',next_retry_at=?,
              claimed_at=NULL,claimed_by=NULL,dead_letter_reason=NULL WHERE
              status IN ('failed','retry','dead_letter')""", (now,))
    return {"dry_run": int(dry_run), "matched": len(rows), "requeued": 0 if dry_run else len(rows)}


def queue_retryable_urls(limit: int = 50) -> int:
    """Queue known failed/dead URLs again after an explicit analyst request."""
    with get_db() as db:
        rows = db.execute("""SELECT url FROM onion_urls WHERE active=1 AND COALESCE(queue_policy,'normal')!='blocked'
          AND status IN ('retry','error','dead')
          ORDER BY last_crawled DESC LIMIT ?""", (max(1, min(limit, 200)),)).fetchall()
        for row in rows:
            db.execute("UPDATE onion_urls SET status='queued',next_crawl_at=?,last_error=NULL WHERE url=?",
                       (utc_now_iso(), row["url"]))
        return len(rows)


def update_worker_state(state: str, last_action: str | None = None,
                        last_url: str | None = None, message: str | None = None,
                        last_url_id: int | None = None, last_error: str | None = None,
                        progress: bool = True) -> None:
    now = utc_now_iso()
    with get_db() as db:
        db.execute("""INSERT INTO crawler_worker_state
          (id,state,last_heartbeat,last_heartbeat_at,last_action,last_url,last_url_id,message,last_error,
           worker_name,processed_date,started_at)
          VALUES(1,?,?,?,?,?,?,?,?,'onion_worker',?,?) ON CONFLICT(id) DO UPDATE SET
          state=excluded.state,last_heartbeat=excluded.last_heartbeat,
          last_heartbeat_at=excluded.last_heartbeat_at,last_action=excluded.last_action,
          last_url=COALESCE(excluded.last_url,crawler_worker_state.last_url),
          last_url_id=COALESCE(excluded.last_url_id,crawler_worker_state.last_url_id),
          message=excluded.message,last_error=COALESCE(excluded.last_error,crawler_worker_state.last_error),
          processed_today=CASE WHEN crawler_worker_state.processed_date!=excluded.processed_date
            THEN 0 ELSE crawler_worker_state.processed_today END,
          processed_date=excluded.processed_date""",
          (state, now, now, last_action, last_url, last_url_id, message, last_error,
           now[:10], now))
        db.execute("""UPDATE crawler_worker_state SET worker_pid=?,rss_mb=?,current_stage=?,
          current_url_id=COALESCE(?,current_url_id),
          last_progress_at=CASE WHEN ? THEN ? ELSE last_progress_at END,
          fetch_started_at=CASE WHEN ?='fetching' THEN COALESCE(fetch_started_at,?)
                                WHEN ?!='fetching' THEN NULL ELSE fetch_started_at END,
          last_success_at=CASE WHEN ? THEN ? ELSE last_success_at END,
          last_failure_at=CASE WHEN ? THEN ? ELSE last_failure_at END WHERE id=1""",
          (os.getpid(), current_rss_mb(), state, last_url_id, int(progress), now,
           state, now, state, int(state in {"finished", "success"} or
                                  str(last_action or "").casefold().startswith("finished")), now,
           int(bool(last_error)), now))


def start_worker() -> None:
    update_worker_state("starting", "Worker service started")
    now = utc_now_iso()
    with get_db() as db:
        db.execute("""UPDATE crawler_worker_state SET started_at=?,last_error=NULL,worker_pid=?,
          rss_mb=?,boot_id=?,last_progress_at=? WHERE id=1""",
          (now, os.getpid(), current_rss_mb(), uuid.uuid4().hex, now))


def maintenance_allowed(task_name: str, now_iso: str | None = None) -> bool:
    now_iso = now_iso or utc_now_iso()
    with get_db() as db:
        row = db.execute("SELECT next_allowed_at FROM worker_maintenance_state WHERE task_name=?",
                         (task_name,)).fetchone()
        return not row or not row[0] or str(row[0]) <= now_iso


def record_maintenance_start(task_name: str, rss_before_mb: float) -> None:
    with get_db() as db:
        db.execute("""INSERT INTO worker_maintenance_state(task_name,last_started_at,rss_before_mb)
          VALUES(?,?,?) ON CONFLICT(task_name) DO UPDATE SET
          last_started_at=excluded.last_started_at,rss_before_mb=excluded.rss_before_mb""",
          (task_name, utc_now_iso(), rss_before_mb))


def record_maintenance_result(task_name: str, *, success: bool, duration_seconds: float,
                              error: Exception | None = None, backoff_hours: int = 6) -> None:
    now = datetime.now(timezone.utc)
    next_allowed = (now + timedelta(hours=max(1, backoff_hours))).isoformat().replace("+00:00", "Z")
    with get_db() as db:
        db.execute("""INSERT INTO worker_maintenance_state
          (task_name,last_success_at,last_failure_at,failure_type,failure_message,next_allowed_at,
           duration_seconds,rss_after_mb) VALUES(?,?,?,?,?,?,?,?)
          ON CONFLICT(task_name) DO UPDATE SET
          last_success_at=CASE WHEN ? THEN excluded.last_success_at ELSE worker_maintenance_state.last_success_at END,
          last_failure_at=CASE WHEN ? THEN worker_maintenance_state.last_failure_at ELSE excluded.last_failure_at END,
          failure_type=excluded.failure_type,failure_message=excluded.failure_message,
          next_allowed_at=excluded.next_allowed_at,duration_seconds=excluded.duration_seconds,
          rss_after_mb=excluded.rss_after_mb""",
          (task_name, utc_now_iso() if success else None, None if success else utc_now_iso(),
           None if success else type(error).__name__, None if success else str(error)[:500],
           next_allowed, float(duration_seconds), current_rss_mb(), int(success), int(success)))


def set_worker_paused(paused: bool) -> None:
    update_worker_state("paused" if paused else "idle", "Crawling paused" if paused else "Crawling resumed")
    with get_db() as db:
        db.execute("UPDATE crawler_worker_state SET is_paused=? WHERE id=1", (int(paused),))


def record_worker_processed(last_url_id: int | None = None) -> None:
    now = utc_now_iso()
    with get_db() as db:
        db.execute("""UPDATE crawler_worker_state SET processed_total=COALESCE(processed_total,0)+1,
          processed_today=CASE WHEN processed_date=? THEN COALESCE(processed_today,0)+1 ELSE 1 END,
          processed_date=?,last_url_id=COALESCE(?,last_url_id) WHERE id=1""",
          (now[:10], now[:10], last_url_id))


def get_worker_state() -> dict | None:
    with get_db() as db:
        return _dict(db.execute("SELECT * FROM crawler_worker_state WHERE id=1").fetchone())


def automatic_dead_cleanup() -> int:
    """Deactivate exhausted URLs while preserving their source-chain audit rows."""
    with get_db() as db:
        seed_rows = db.execute("""UPDATE onion_urls SET status='dead',active=0,next_crawl_at=NULL,
          dead_reason=COALESCE(dead_reason,'search_seed_timeout')
          WHERE active!=0 AND source_type='search_seed' AND error_count>=2""").rowcount
    return seed_rows + clean_dead_links()


def mark_worker_maintenance() -> None:
    with get_db() as db:
        db.execute("UPDATE crawler_worker_state SET last_maintenance_at=? WHERE id=1", (utc_now_iso(),))


def compact_stale_queue_state() -> int:
    """Repair stale active flags/statuses without fetching or deleting evidence."""
    stale_worker_before = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat().replace("+00:00", "Z")
    with get_db() as db:
        changed = db.execute("""UPDATE onion_urls SET active=0,next_crawl_at=NULL
          WHERE active!=0 AND (status IN ('blocked','dead') OR COALESCE(queue_policy,'normal')='blocked')""")
        workers_removed = db.execute(
            "DELETE FROM worker_instances WHERE last_heartbeat_at<?", (stale_worker_before,)).rowcount
        return changed.rowcount + workers_removed


def rebuild_mirror_clusters_from_metadata() -> int:
    """Re-index stored safe hashes/indicators; performs no network requests."""
    from mirror_logger import update_mirror_clusters
    with get_db() as db:
        rows = [dict(row) for row in db.execute("""SELECT url,title,content_hash,fuzzy_hash FROM onion_urls
          WHERE storage_policy='safe_summary' AND primary_category!='adult_filtered'
          AND (content_hash IS NOT NULL OR fuzzy_hash IS NOT NULL)""")]
    rebuilt = 0
    for row in rows:
        with get_db() as db:
            indicators = [dict(item) for item in db.execute("""SELECT i.indicator_type AS type,i.value,i.normalized_value,i.confidence
              FROM indicators i JOIN indicator_links il ON il.indicator_id=i.id WHERE il.source_ref=?""", (row["url"],))]
        if update_mirror_clusters(row["url"], row.get("title"), "", row.get("content_hash"),
                                  row.get("fuzzy_hash"), indicators, "onion_page"):
            rebuilt += 1
    return rebuilt


def upsert_page_topics(url: str, topics: list[str], keywords: list[str]) -> None:
    with get_db() as db:
        db.execute("""INSERT INTO page_topics(url,topics_json,keywords_json,updated_at)
          VALUES(?,?,?,?) ON CONFLICT(url) DO UPDATE SET topics_json=excluded.topics_json,
          keywords_json=excluded.keywords_json,updated_at=excluded.updated_at""",
          (url, json.dumps(topics, ensure_ascii=False), json.dumps(keywords, ensure_ascii=False), utc_now_iso()))


def get_page_topics(url: str) -> dict | None:
    with get_db() as db:
        return _dict(db.execute("SELECT * FROM page_topics WHERE url=?", (url,)).fetchone())


def apply_onion_policy(url: str, policy: dict, http_status: int | None = None,
                       checked: bool = False,
                       page_structure: dict | None = None) -> None:
    """Persist only safe classifier outputs; raw matched restricted terms are never stored."""
    policy = dict(policy)
    with get_db() as db:
        existing = db.execute("""SELECT spain_priority,geo_priority,spain_match_reason,
          spain_match_language,spain_confidence,spain_context_tags,spain_alert_level,
          spain_review_status,priority_score,review_score,review_status,active,status,queue_policy,
          analyst_category,storage_policy,screenshot_policy,screenshot_blocked_reason,
          spain_analyst_suppressed,primary_category,category,content_category,
          category_confidence,category_reason,category_safe_label,display_group,risk_level,
          confidence,risk_flags,safety_reason,verification_state,verification_reason,
          destination_html_evidence_version,classification_evidence_source
          FROM onion_urls WHERE url=?""", (url,)).fetchone()
    try:
        incoming_evidence_version = int(policy.get("destination_html_evidence_version") or 0)
    except (TypeError, ValueError):
        incoming_evidence_version = 0
    incoming_category = str(policy.get("primary_category") or policy.get("category") or "unknown")
    incoming_analyst_category = str(policy.get("analyst_category") or "").strip()
    incoming_analyst_verified = bool(
        incoming_analyst_category
        and policy.get("classification_evidence_source") == "analyst"
        and incoming_category == incoming_analyst_category
    )
    incoming_html_verified = bool(
        checked
        and policy.get("classification_evidence_source") == "destination_html"
        and incoming_evidence_version >= DESTINATION_HTML_EVIDENCE_VERSION
        and has_current_destination_html_evidence(page_structure)
    )
    incoming_content_verified = incoming_analyst_verified or incoming_html_verified
    existing_analyst_category = str(existing["analyst_category"] or "").strip() if existing else ""
    existing_analyst_verified = bool(
        existing_analyst_category
        and str(existing["primary_category"] or "unknown") == existing_analyst_category
    )
    existing_html_verified = bool(existing and (
        existing["verification_state"] == "verified"
        and existing["verification_reason"] == "page_fetched_and_classified"
        and int(existing["destination_html_evidence_version"] or 0)
            >= DESTINATION_HTML_EVIDENCE_VERSION
        and existing["classification_evidence_source"] == "destination_html"
    ))
    existing_content_verified = existing_analyst_verified or existing_html_verified

    # Central fail-closed evidence boundary.  URL/host/path/anchor/parent/tag
    # policies may describe an unverified hint or routing choice, but they can
    # never create or replace a durable content category.
    if not incoming_content_verified:
        if existing_content_verified:
            # A rediscovery/routing hint has nothing authoritative to add to an
            # already classified row. Returning here prevents hybrid records in
            # which a trusted category is paired with URL-derived page type,
            # urgency, policy, or UI fields.
            return
        else:
            proposed = str(policy.get("primary_category") or policy.get("category") or "unknown")
            if proposed != "unknown":
                policy["unverified_category_hint"] = proposed
            policy.update(
                primary_category="unknown", category="unknown", content_category="unknown",
                category_confidence="low",
                category_reason="Awaiting destination HTML classification",
                category_safe_label="Needs classification", display_group="Other",
                classification_decision="unverified_hint", classification_stage="prefetch",
                classification_confidence_score=0.0, tags=[], risk_flags=[],
                risk_level="low", confidence="low",
                site_type="unknown", risk_category="unknown",
                urgent_score=0, urgent_flag=False, urgent_reason=None,
                context_only=False,
                page_type="unknown", page_type_confidence="low",
                page_type_evidence=[], secondary_categories=[], marketplace_type=None,
                category_update_allowed=False,
                category_update_reason="awaiting_destination_html",
                category_evidence={}, category_supporting_evidence=[],
                category_contradicting_evidence=[],
                card_ready=False, card_readiness_reason="awaiting_page_classification",
                card_readiness_confidence="low",
                storage_policy="safe_summary", review_status="monitor",
                safety_reason="awaiting_destination_html", queue_policy="normal",
                active=1, screenshot_policy="blocked",
                screenshot_blocked_reason="awaiting_destination_html",
                ui_hidden_default=False, ui_priority=0, review_score=0,
                spain_priority=False, geo_priority=None, spain_match_reason=None,
                spain_match_language=None, spain_confidence=None,
                spain_context_tags=[], spain_priority_reason=None,
                spain_priority_evidence_type=None, spain_relevance="none",
                spain_evidence_type=None, seller_geo_confidence="none",
                spain_evidence_snippets=[], spain_evidence_source_url=None,
                spain_evidence_source_path=None, spain_context_only=False,
                spain_actionable=False, spain_evidence_score=0,
                spain_evidence_families=[], spain_evidence_direction="context_only",
            )
            if proposed in {"adult_filtered", "adult_restricted", "severe_abuse_risk"}:
                policy.update(
                    storage_policy="safe_summary", review_status="monitor",
                    safety_reason="awaiting_destination_html", queue_policy="normal",
                    active=1, screenshot_policy="blocked",
                    screenshot_blocked_reason="awaiting_destination_html",
                )
    # Do not retain a caller-supplied parser version on a policy that failed
    # the destination-HTML boundary.  Version numbers are evidence only when
    # the source, checked fetch, and parser structure corroborate one another.
    policy["destination_html_evidence_version"] = (
        incoming_evidence_version if incoming_html_verified else 0
    )
    policy["classification_evidence_source"] = (
        "analyst" if (incoming_analyst_verified or existing_analyst_verified) else
        "destination_html" if (incoming_html_verified or existing_html_verified) else
        "unverified"
    )
    if existing and existing["spain_analyst_suppressed"]:
        policy.update(spain_priority=False, geo_priority=None, spain_match_reason=None,
                      spain_match_language=None, spain_confidence=None,
                      spain_context_tags=[], spain_alert_level=None,
                      spain_relevance="none", seller_geo_confidence="none",
                      spain_context_only=False, spain_actionable=False)
    elif existing and existing["spain_priority"] and not policy.get("spain_priority") and not checked:
        policy["spain_priority"] = True
        for key in ("geo_priority", "spain_match_reason", "spain_match_language", "spain_confidence",
                    "spain_context_tags", "spain_alert_level", "spain_review_status"):
            if not policy.get(key):
                value = existing[key]
                if key == "spain_context_tags" and isinstance(value, str):
                    try: value = json.loads(value)
                    except (TypeError, ValueError): value = []
                policy[key] = value
        policy["priority_score"] = max(int(policy.get("priority_score") or 0), int(existing["priority_score"] or 0))
        policy["review_score"] = max(int(policy.get("review_score") or 0), int(existing["review_score"] or 0))
    analyst_review_states = {"relevant", "false_positive", "needs_report", "reported", "blocked"}
    incoming_restricted = (policy.get("storage_policy") in {"metadata_only", "discard"}
                           or policy.get("review_status") in {"restricted", "filtered"})
    if existing and existing["review_status"] in analyst_review_states and not incoming_restricted:
        policy["review_status"] = existing["review_status"]
        if existing["review_status"] == "blocked":
            policy.update(active=0, queue_policy="blocked")
    if existing and existing["analyst_category"] and not incoming_restricted:
        from universal_classifier import NEUTRAL_CATEGORIES, safe_category_label
        analyst_category = existing["analyst_category"]
        limited_categories = {"weapons_arms", "drugs", "leaks_data", "credentials",
                              "malware_hacking", "fraud_financial", "extremist_recruitment"}
        limited = analyst_category in limited_categories or analyst_category.startswith("marketplace")
        discovery = analyst_category in {"directory_index", "search_engine", "forum_social"}
        neutral = analyst_category in NEUTRAL_CATEGORIES
        policy.update(primary_category=analyst_category, category=analyst_category,
                      category_confidence="analyst", category_reason="Analyst category correction",
                      category_safe_label=safe_category_label(analyst_category),
                      storage_policy="metadata_limited" if limited else "safe_summary",
                      queue_policy="reviewable" if limited else "expand" if discovery else "normal",
                      review_status="monitor" if neutral else policy.get("review_status", "pending"),
                      display_group="Neutral / informational" if neutral else policy.get("display_group", "Other"))
        if limited:
            policy.update(screenshot_policy="blocked",
                          screenshot_blocked_reason="analyst_category_metadata_limited")
        elif policy.get("screenshot_blocked_reason") != "restricted_child_present":
            policy.update(screenshot_policy="allowed", screenshot_blocked_reason=None)
    policy["url"] = url
    requested_status = existing["status"] if existing else None
    claim_in_progress = bool(
        existing and str(existing["status"] or "") in {"claimed", "fetching"}
    )
    if not incoming_content_verified and not claim_in_progress and (
            incoming_category in {"adult_filtered", "adult_restricted", "severe_abuse_risk"}
            or (existing and str(existing["safety_reason"] or "") in {
                "adult_content_filtered", "adult_restricted", "adult_marketplace_category",
                "adult_marketplace_dominant", "severe_abuse_risk",
                "severe_abuse_blackhole", "severe_content_filtered",
                "awaiting_destination_html",
            })):
        requested_status = "queued"
        policy.update(status="queued", active=1, queue_policy="normal",
                      storage_policy="safe_summary", review_status="monitor")
    elif claim_in_progress:
        # Prefetch metadata is written after the worker has atomically claimed
        # the row.  An unverified route/content hint must not release or rewrite
        # that live claim; only the owning worker's terminal fetch path may do
        # so.  Keeping the status here also preserves assembly-line ownership.
        policy["status"] = requested_status
    policy = normalize_policy_state(
        policy, fetched=incoming_html_verified,
        requested_status=requested_status
    )
    values = {
        "primary_category": policy.get("primary_category", "unknown"),
        "category": policy.get("category", policy.get("primary_category", "unknown")),
        "tags": json.dumps(policy.get("tags", []), ensure_ascii=False),
        "risk_level": policy.get("risk_level", "low"),
        "confidence": policy.get("confidence", "low"),
        "risk_flags": json.dumps(policy.get("risk_flags", []), ensure_ascii=False),
        "geo_priority": policy.get("geo_priority"),
        "spain_priority": int(bool(policy.get("spain_priority"))),
        "spain_match_reason": policy.get("spain_match_reason"),
        "spain_match_language": policy.get("spain_match_language"),
        "spain_confidence": policy.get("spain_confidence"),
        "spain_context_tags": json.dumps(policy.get("spain_context_tags", []), ensure_ascii=False),
        "storage_policy": policy.get("storage_policy", "safe_summary"),
        "review_status": policy.get("review_status", "pending"),
        "safety_reason": policy.get("safety_reason"),
        "screenshot_blocked_reason": policy.get("screenshot_blocked_reason"),
        "active": int(bool(policy.get("active", True))),
        "priority_score": int(policy.get("priority_score", 0)),
        "tag_summary": policy.get("tag_summary"), "tag_confidence": policy.get("tag_confidence"),
        "queue_policy": policy.get("queue_policy", "normal"),
        "screenshot_policy": policy.get("screenshot_policy", "blocked"),
        "secondary_categories": json.dumps(policy.get("secondary_categories", []), ensure_ascii=False),
        "marketplace_type": policy.get("marketplace_type"), "page_type": policy.get("page_type", "unknown"),
        "category_confidence": policy.get("category_confidence", policy.get("confidence", "low")),
        "category_reason": policy.get("category_reason"),
        "category_safe_label": policy.get("category_safe_label"),
        "display_group": policy.get("display_group", "Other"),
        "ui_hidden_default": int(bool(policy.get("ui_hidden_default"))),
        "ui_priority": int(policy.get("ui_priority", 0)), "review_score": int(policy.get("review_score", 0)),
        "suggested_category": policy.get("suggested_category"),
        "classification_decision": policy.get("classification_decision", "unclassified"),
        "classification_confidence_score": float(policy.get("classification_confidence_score") or 0),
        "classifier_version": policy.get("classifier_version"),
        "classification_stage": policy.get("classification_stage"),
        "status": policy.get("status", existing["status"] if existing else "queued"),
        "language": policy.get("language"), "locale_path": policy.get("locale_path"),
        "spanish_language_detected": int(bool(policy.get("spanish_language_detected"))),
        "spain_priority_reason": policy.get("spain_priority_reason"),
        "spain_priority_evidence_type": policy.get("spain_priority_evidence_type"),
        "spain_relevance": policy.get("spain_relevance", "none"),
        "spain_evidence_type": policy.get("spain_evidence_type"),
        "seller_geo_confidence": policy.get("seller_geo_confidence", "none"),
        "spain_evidence_snippets": json.dumps(policy.get("spain_evidence_snippets", []), ensure_ascii=False),
        "spain_evidence_source_url": policy.get("spain_evidence_source_url"),
        "spain_evidence_source_path": policy.get("spain_evidence_source_path"),
        "spain_context_only": int(bool(policy.get("spain_context_only"))),
        "spain_actionable": int(bool(policy.get("spain_actionable"))),
        "spain_evidence_score": int(policy.get("spain_evidence_score") or 0),
        "spain_evidence_families": json.dumps(
            policy.get("spain_evidence_families") or policy.get("spain_context_tags") or [],
            ensure_ascii=False),
        "spain_evidence_direction": policy.get("spain_evidence_direction") or "context_only",
        "importance_level": policy.get("importance_level", "normal"),
        "importance_reason": policy.get("importance_reason"),
        "safe_display_name": policy.get("safe_display_name"),
        "safe_site_name": policy.get("safe_site_name"),
        "policy_label": policy.get("policy_label"),
        "unsafe_title_hidden": int(bool(policy.get("unsafe_title_hidden"))),
        "site_type": policy.get("site_type", "unknown"),
        "risk_category": policy.get("risk_category", "unknown"),
        "urgent_score": int(policy.get("urgent_score") or 0),
        "urgent_flag": int(bool(policy.get("urgent_flag"))),
        "urgent_reason": policy.get("urgent_reason"),
        "context_only": int(bool(policy.get("context_only"))),
    }
    with get_db() as db:
        db.execute("""UPDATE onion_urls SET primary_category=?,category=?,tags=?,risk_level=?,confidence=?,
          risk_flags=?,geo_priority=?,spain_priority=?,spain_match_reason=?,spain_match_language=?,
          spain_confidence=?,spain_context_tags=?,storage_policy=?,review_status=?,safety_reason=?,
          screenshot_blocked_reason=?,active=?,priority_score=?,tag_summary=?,tag_confidence=?,
          queue_policy=?,screenshot_policy=?,http_status=COALESCE(?,http_status),
          secondary_categories=?,marketplace_type=?,page_type=?,category_confidence=?,category_reason=?,
          category_safe_label=?,display_group=?,ui_hidden_default=?,ui_priority=?,review_score=?,
          suggested_category=?,classification_decision=?,classification_confidence_score=?,
          classifier_version=?,classification_stage=?,
          language=?,locale_path=?,spanish_language_detected=?,spain_priority_reason=?,
          spain_priority_evidence_type=?,importance_level=CASE WHEN analyst_importance IS NULL THEN ? ELSE analyst_importance END,
          importance_reason=?,safe_display_name=COALESCE(?,safe_display_name),
          safe_site_name=COALESCE(?,safe_site_name),policy_label=COALESCE(?,policy_label),
          unsafe_title_hidden=?,
          site_type=?,risk_category=?,urgent_score=?,urgent_flag=?,urgent_reason=?,context_only=?,
          last_checked_at=CASE WHEN ? THEN ? ELSE last_checked_at END,
          status=? WHERE url=?""",
          tuple(values[key] for key in ("primary_category","category","tags","risk_level","confidence",
          "risk_flags","geo_priority","spain_priority","spain_match_reason","spain_match_language",
          "spain_confidence","spain_context_tags","storage_policy","review_status","safety_reason",
          "screenshot_blocked_reason","active","priority_score","tag_summary","tag_confidence",
          "queue_policy","screenshot_policy")) +
          (http_status,) + tuple(values[key] for key in ("secondary_categories","marketplace_type","page_type",
          "category_confidence","category_reason","category_safe_label","display_group","ui_hidden_default",
          "ui_priority","review_score","suggested_category","classification_decision",
          "classification_confidence_score","classifier_version","classification_stage",
          "language","locale_path","spanish_language_detected","spain_priority_reason",
          "spain_priority_evidence_type","importance_level","importance_reason","safe_display_name",
          "safe_site_name","policy_label","unsafe_title_hidden",
          "site_type","risk_category","urgent_score","urgent_flag","urgent_reason","context_only")) +
          (int(incoming_html_verified), utc_now_iso(), values["status"], url))
        db.execute("""UPDATE onion_urls SET spain_relevance=?,spain_evidence_type=?,
          seller_geo_confidence=?,spain_evidence_snippets=?,spain_evidence_source_url=?,
          spain_evidence_source_path=?,spain_context_only=?,spain_actionable=?,
          spain_evidence_score=?,spain_evidence_families=?,spain_evidence_direction=? WHERE url=?""",
          (values["spain_relevance"], values["spain_evidence_type"],
           values["seller_geo_confidence"], values["spain_evidence_snippets"],
           values["spain_evidence_source_url"], values["spain_evidence_source_path"],
           values["spain_context_only"], values["spain_actionable"],
           values["spain_evidence_score"], values["spain_evidence_families"],
           values["spain_evidence_direction"], url))
        db.execute("""UPDATE onion_urls SET match_scope=?,safe_signal_labels=?,signal_count=?,signal_ratio=?,
          dominance_score=?,context_window_count=?,child_only=?,false_positive_guard_applied=?,ocr_checked=?,
          ocr_restricted_hit=?,ocr_safe_signal_labels=?,ocr_deleted_due_to_policy=? WHERE url=?""",
          (policy.get("match_scope"), json.dumps(policy.get("safe_signal_labels", []), ensure_ascii=False),
           int(policy.get("signal_count") or 0), float(policy.get("signal_ratio") or 0),
           float(policy.get("dominance_score") or 0), int(policy.get("context_window_count") or 0),
           int(bool(policy.get("child_only"))), int(bool(policy.get("false_positive_guard_applied"))),
           int(bool(policy.get("ocr_checked"))), int(bool(policy.get("ocr_restricted_hit"))),
           json.dumps(policy.get("ocr_safe_signal_labels", []), ensure_ascii=False),
           int(bool(policy.get("ocr_deleted_due_to_policy"))), url))
        db.execute("""UPDATE onion_urls SET weapons_evidence_score=?,weapons_evidence_families=?,
          weapons_commercial_context=?,weapons_context_type=?,
          verification_state=CASE WHEN ? THEN 'verified' ELSE verification_state END,
          verified_at=CASE WHEN ? THEN COALESCE(verified_at,?) ELSE verified_at END,
          verification_reason=CASE WHEN ? THEN 'page_fetched_and_classified' ELSE verification_reason END
          WHERE url=?""",
          (int(policy.get("weapons_evidence_score") or 0),
           json.dumps(policy.get("weapons_evidence_families", []), ensure_ascii=False),
           int(bool(policy.get("weapons_commercial_context"))),
           policy.get("weapons_context_type") or "none", int(incoming_html_verified),
           int(incoming_html_verified), utc_now_iso(), int(incoming_html_verified), url))
        db.execute("""UPDATE onion_urls SET destination_html_evidence_version=?,
          classification_evidence_source=? WHERE url=?""",
          (int(policy.get("destination_html_evidence_version") or 0),
           policy.get("classification_evidence_source") or "unverified", url))
        db.execute("""UPDATE onion_urls SET detected_title=?,title_source=?,identity_confidence=?,
          page_type_confidence=?,page_type_evidence_json=?,card_ready=?,card_readiness_reason=?,
          card_readiness_confidence=?,safe_summary=?,link_repository_score=?,outbound_onion_count=?,
          internal_link_count=?,external_onion_count=? WHERE url=?""",
          (policy.get("detected_title"), policy.get("title_source"), policy.get("identity_confidence"),
           policy.get("page_type_confidence"),
           json.dumps(policy.get("page_type_evidence", []), ensure_ascii=False),
           int(bool(policy.get("card_ready"))), policy.get("card_readiness_reason"),
           policy.get("card_readiness_confidence"), policy.get("safe_summary"),
           int(policy.get("link_repository_score") or 0), int(policy.get("outbound_onion_count") or 0),
           int(policy.get("internal_link_count") or 0), int(policy.get("external_onion_count") or 0), url))
        db.execute("""UPDATE onion_urls SET content_category=?,safety_state=?,category_evidence_json=?,
          category_supporting_evidence_json=?,category_contradicting_evidence_json=?,
          category_update_allowed=?,category_update_reason=? WHERE url=?""",
          (policy.get("content_category") or values["primary_category"], policy.get("safety_state") or "safe",
           json.dumps(policy.get("category_evidence", {}), ensure_ascii=False),
           json.dumps(policy.get("category_supporting_evidence", []), ensure_ascii=False),
           json.dumps(policy.get("category_contradicting_evidence", []), ensure_ascii=False),
           int(policy.get("category_update_allowed", True)), policy.get("category_update_reason"), url))
        db.execute("""UPDATE onion_urls SET child_adult_link_count=?,child_restricted_link_count=?,
          child_blocked_link_count=?,parent_evidence_json=?,child_link_evidence_json=? WHERE url=?""",
          (int(policy.get("child_adult_link_count") or 0),
           int(policy.get("child_restricted_link_count") or 0),
           int(policy.get("child_blocked_link_count") or 0),
           json.dumps(policy.get("parent_evidence", []), ensure_ascii=False),
           json.dumps(policy.get("child_link_evidence", {}), ensure_ascii=False), url))
        now = utc_now_iso()
        for tag in ([] if values["storage_policy"] == "discard" else policy.get("tags", [])):
            db.execute("""INSERT INTO onion_tags(url,tag,confidence,first_seen,last_seen) VALUES(?,?,?,?,?)
              ON CONFLICT(url,tag) DO UPDATE SET confidence=excluded.confidence,last_seen=excluded.last_seen""",
              (url, tag, policy.get("tag_confidence", policy.get("confidence", "low")), now, now))
        if values["storage_policy"] == "metadata_only":
            db.execute("""INSERT INTO restricted_items(url,category,first_seen,last_seen,safety_reason,source_url)
              SELECT url,?,first_seen,?,?,source_url FROM onion_urls WHERE url=?
              ON CONFLICT(url) DO UPDATE SET category=excluded.category,last_seen=excluded.last_seen,
              safety_reason=excluded.safety_reason""",
              (values["primary_category"], now, values["safety_reason"], url))
    if values["primary_category"] == "severe_abuse_risk":
        enforce_severe_blackhole(url, policy)
        return
    adult_policy = values["storage_policy"] == "discard" or values["primary_category"] in {"adult_filtered", "adult_restricted"}
    adult_marketplace_category = (values["primary_category"] == "adult_restricted"
                                  and values["safety_reason"] in {
                                      "adult_marketplace_category", "adult_marketplace_dominant"})
    if adult_policy:
        safe_rule = (policy.get("safe_signal_labels") or ["adult_dominant_page"])[0]
        remember_adult_url(url, values["confidence"], safe_rule, policy)
    if adult_policy and not adult_marketplace_category:
        cleanup_adult_filtered_items(url)
    elif not adult_policy:
        mark_site_card_dirty_for_url(url)


def apply_prefetch_policy(url: str, policy: dict) -> bool:
    """Persist provisional routing policy without erasing verified page truth.

    Re-discovery metadata can change crawl routing, but a URL/path/anchor hint
    must never replace a category already derived from fetched destination HTML.
    Exact analyst/page-verified restricted memory remains a terminal exception.
    """
    with get_db() as db:
        existing = db.execute(
            """SELECT verification_state,verification_reason,primary_category,analyst_category,
              destination_html_evidence_version,classification_evidence_source
              FROM onion_urls WHERE url=?""", (url,)
        ).fetchone()
    terminal = (
        policy.get("primary_category") in {
            "adult_filtered", "adult_restricted", "severe_abuse_risk",
        }
        or policy.get("classification_decision") == "analyst_confirmed"
        or policy.get("storage_policy") == "discard"
    )
    existing_analyst = str(existing["analyst_category"] or "").strip() if existing else ""
    existing_verified = bool(existing and (
        (existing_analyst and str(existing["primary_category"] or "unknown") == existing_analyst)
        or (
            existing["verification_state"] == "verified"
            and existing["verification_reason"] == "page_fetched_and_classified"
            and existing["classification_evidence_source"] == "destination_html"
            and int(existing["destination_html_evidence_version"] or 0)
                >= DESTINATION_HTML_EVIDENCE_VERSION
        )
    ))
    if existing_verified and not terminal:
        return False
    apply_onion_policy(url, policy, checked=False)
    return True


def insert_crawl_audit(url: str | None, action: str, outcome: str, safe_reason: str | None = None) -> None:
    with get_db() as db:
        db.execute("INSERT INTO crawl_audit_log(ts,url,action,outcome,safe_reason) VALUES(?,?,?,?,?)",
                   (utc_now_iso(), url, action, outcome, safe_reason))


_QUALITY_CODE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.:+@-]{0,79}$")
_QUALITY_EVIDENCE_BUCKETS = frozenset({
    "title", "heading", "url", "body_safe_snippet", "link_pattern",
    "form_checkout_login", "negative_contradicting",
})
_DECISION_METADATA_CODE_KEYS = frozenset({
    "page_type", "display_group", "spain_confidence", "storage_policy",
    "review_status", "source", "scope", "content_category", "safety_state",
    "category_update_reason", "classification_evidence_source", "site_type",
    "risk_category", "spain_reason_code", "spain_evidence_type",
    "content_quality", "page_type_confidence", "spain_evidence_direction",
})
_DECISION_METADATA_BOOL_KEYS = frozenset({
    "spain_priority", "category_update_allowed", "destination_evidence_trusted",
    "urgent_flag", "context_only", "card_ready", "spain_actionable",
})
_DECISION_METADATA_SCORE_KEYS = frozenset({
    "spain_evidence_score", "urgent_score",
})
_DECISION_METADATA_CODE_LIST_KEYS = frozenset({
    "support_codes", "contradiction_codes", "spain_evidence_families",
    "urgent_reason_codes",
})
_FEEDBACK_ACTIONS = {
    "category": frozenset({"category_confirmed", "category_corrected"}),
    "review": frozenset({
        "review_kept", "review_ignored", "review_needs_report",
        "review_reported", "review_blocked",
    }),
    "safety": frozenset({"adult_block_confirmed", "adult_false_positive"}),
    "spain": frozenset({"spain_confirmed", "spain_removed"}),
    "urgency": frozenset({"urgent_confirmed", "urgent_dismissed"}),
    "mirror": frozenset({
        "mirror_confirmed", "mirror_not_same", "mirror_ignored",
        "split_after_merge",
    }),
}
_FEEDBACK_METADATA_KEYS = frozenset({
    "source_stage", "previous_decision", "review_status", "match_confidence",
    "match_reason_code", "spain_reason_code", "urgent_reason_code",
    "scope", "decision_code", "url_count", "member_decision_count",
    "confirmed", "would_change",
})


def _quality_safe_code(value: object) -> str | None:
    """Return a bounded metadata code, never raw evidence or an address."""
    if value is None:
        return None
    raw = str(value).strip().casefold()
    if not raw or len(raw) > 160:
        return None
    if "://" in raw or ".onion" in raw or "@" in raw or any(ord(char) < 32 for char in raw):
        return None
    normalized = re.sub(r"[^a-z0-9_.:+@-]+", "_", raw).strip("_.:+@-")
    normalized = re.sub(r"_+", "_", normalized)[:80]
    return normalized if _QUALITY_CODE_PATTERN.fullmatch(normalized) else None


def _quality_safe_code_list(value: object, *, limit: int = 20) -> list[str]:
    source = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
    result: list[str] = []
    for item in source:
        code = _quality_safe_code(item)
        if code and code not in result:
            result.append(code)
        if len(result) >= limit:
            break
    return result


def _quality_subject_hash(subject: object) -> str:
    """Hash a caller-owned subject without retaining its URL, host, title or identifier."""
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 8192:
        raise ValueError("A bounded classification-quality subject is required")
    material = "arachne-classification-quality:v1\n" + subject.strip().casefold()
    return "sha256:" + hashlib.sha256(material.encode("utf-8", "ignore")).hexdigest()


def _quality_cutoff(days: int) -> str:
    try:
        bounded = int(days)
    except (TypeError, ValueError) as exc:
        raise ValueError("days must be an integer") from exc
    if bounded < 1 or bounded > 3650:
        raise ValueError("days must be between 1 and 3650")
    return (datetime.now(timezone.utc) - timedelta(days=bounded)).isoformat().replace("+00:00", "Z")


def _sanitize_decision_metadata(value: dict | None) -> dict:
    source = value if isinstance(value, dict) else {}
    result: dict[str, Any] = {}
    for key in _DECISION_METADATA_CODE_KEYS:
        if key in source:
            code = _quality_safe_code(source.get(key))
            if code:
                result[key] = code
    for key in _DECISION_METADATA_BOOL_KEYS:
        if key in source:
            result[key] = bool(source.get(key))
    for key in _DECISION_METADATA_SCORE_KEYS:
        if key in source:
            try:
                score = int(source.get(key) or 0)
            except (TypeError, ValueError):
                continue
            result[key] = max(0, min(score, 100))
    for key in _DECISION_METADATA_CODE_LIST_KEYS:
        if key in source:
            result[key] = _quality_safe_code_list(source.get(key), limit=20)
    if "evidence_bucket_counts" in source and isinstance(source["evidence_bucket_counts"], dict):
        counts: dict[str, int] = {}
        for bucket, raw_count in source["evidence_bucket_counts"].items():
            bucket_code = _quality_safe_code(bucket)
            if bucket_code not in _QUALITY_EVIDENCE_BUCKETS:
                continue
            try:
                counts[bucket_code] = max(0, min(int(raw_count), 1000))
            except (TypeError, ValueError):
                continue
        result["evidence_bucket_counts"] = counts
    return result


def _sanitize_feedback_metadata(value: dict | None) -> dict:
    source = value if isinstance(value, dict) else {}
    result: dict[str, Any] = {}
    for key in _FEEDBACK_METADATA_KEYS:
        if key not in source:
            continue
        raw = source[key]
        if key in {"url_count", "member_decision_count"}:
            try:
                result[key] = max(0, min(int(raw), 100000))
            except (TypeError, ValueError):
                continue
        elif key in {"confirmed", "would_change"}:
            result[key] = bool(raw)
        else:
            code = _quality_safe_code(raw)
            if code:
                result[key] = code
    return result


def _sanitize_quality_metric(value: object, *, depth: int = 0) -> Any:
    """Sanitize compact aggregate metrics; raw strings and deep structures are rejected."""
    if depth > 4:
        raise ValueError("Classification-quality metrics are too deeply nested")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return max(-1_000_000_000_000, min(value, 1_000_000_000_000))
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Classification-quality metrics must be finite")
        return max(-1_000_000_000_000.0, min(value, 1_000_000_000_000.0))
    if isinstance(value, str):
        code = _quality_safe_code(value)
        if not code:
            raise ValueError("Classification-quality metrics may contain only safe codes")
        return code
    if isinstance(value, dict):
        if len(value) > 200:
            raise ValueError("Classification-quality metric maps are capped at 200 keys")
        result = {}
        for raw_key, raw_value in value.items():
            key = _quality_safe_code(raw_key)
            if not key:
                raise ValueError("Classification-quality metric keys must be safe codes")
            result[key] = _sanitize_quality_metric(raw_value, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        if len(value) > 200:
            raise ValueError("Classification-quality metric lists are capped at 200 values")
        return [_sanitize_quality_metric(item, depth=depth + 1) for item in value]
    raise ValueError("Unsupported classification-quality metric value")


def record_classification_decision(url: str, policy: dict, *, stage: str | None = None,
                                   previous_category: str | None = None,
                                   analyst_corrected: bool = False,
                                   safe_metadata: dict | None = None) -> int:
    """Append a metadata-safe classification decision to the immutable ledger."""
    metadata = _sanitize_decision_metadata(safe_metadata)
    evidence = _quality_safe_code_list(policy.get("evidence_families", []), limit=20)
    final_category = str(policy.get("primary_category") or "unknown")
    proposed = str(policy.get("suggested_category") or final_category)
    with get_db() as db:
        row = db.execute("SELECT id,site_card_id FROM onion_urls WHERE url=?", (url,)).fetchone()
        cur = db.execute("""INSERT INTO classification_decisions
          (ts,url,onion_url_id,site_card_id,stage,proposed_category,final_category,
           confidence_label,confidence_score,decision,evidence_families_json,reason,
           classifier_version,analyst_corrected,previous_category,safe_metadata_json)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (utc_now_iso(), url, row["id"] if row else None, row["site_card_id"] if row else None,
           stage or policy.get("classification_stage") or "unknown", proposed, final_category,
           policy.get("category_confidence") or policy.get("confidence") or "low",
           float(policy.get("classification_confidence_score") or 0),
           policy.get("classification_decision") or ("analyst_confirmed" if analyst_corrected else "unclassified"),
           json.dumps(evidence, ensure_ascii=False),
           str(policy.get("category_reason") or policy.get("safety_reason") or "")[:240],
           policy.get("classifier_version") or "rules-page-v4", int(analyst_corrected),
           previous_category, json.dumps(metadata, ensure_ascii=False)))
        return int(cur.lastrowid)


def record_classification_feedback(*, subject: str, feedback_scope: str,
                                   feedback_action: str, reason_code: str,
                                   decision_id: int | None = None,
                                   onion_url_id: int | None = None,
                                   site_card_id: int | None = None,
                                   previous_category: str | None = None,
                                   final_category: str | None = None,
                                   classifier_version: str | None = None,
                                   safe_metadata: dict | None = None) -> int:
    """Append one normalized analyst outcome without persisting its raw subject."""
    scope = _quality_safe_code(feedback_scope)
    action = _quality_safe_code(feedback_action)
    reason = _quality_safe_code(reason_code)
    if scope not in _FEEDBACK_ACTIONS or action not in _FEEDBACK_ACTIONS[scope]:
        raise ValueError("Unsupported classification feedback scope/action")
    if not reason:
        raise ValueError("A metadata-safe classification feedback reason code is required")
    previous = _quality_safe_code(previous_category)
    final = _quality_safe_code(final_category)
    if "severe_abuse_risk" in {previous, final}:
        raise ValueError("Severe-safety outcomes remain aggregate-only")
    version = _quality_safe_code(classifier_version)
    metadata = _sanitize_feedback_metadata(safe_metadata)
    subject_hash = _quality_subject_hash(subject)
    with get_db() as db:
        decision = None
        if decision_id is not None:
            decision = db.execute("""SELECT id,onion_url_id,site_card_id,classifier_version
              FROM classification_decisions WHERE id=?""", (int(decision_id),)).fetchone()
            if not decision:
                raise ValueError("Classification decision not found")
            onion_url_id = onion_url_id if onion_url_id is not None else decision["onion_url_id"]
            site_card_id = site_card_id if site_card_id is not None else decision["site_card_id"]
            version = version or _quality_safe_code(decision["classifier_version"])
        cur = db.execute("""INSERT INTO classification_feedback_events
          (created_at,feedback_scope,feedback_action,decision_id,onion_url_id,site_card_id,
           subject_hash,previous_category,final_category,reason_code,classifier_version,
           safe_metadata_json)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
          (utc_now_iso(), scope, action, int(decision_id) if decision_id is not None else None,
           int(onion_url_id) if onion_url_id is not None else None,
           int(site_card_id) if site_card_id is not None else None,
           subject_hash, previous, final, reason, version,
           json.dumps(metadata, sort_keys=True, separators=(",", ":"))))
        return int(cur.lastrowid)


def get_classification_feedback_events(days: int = 30, limit: int = 1000) -> list[dict]:
    """Read bounded, normalized analyst feedback without exposing subjects."""
    cutoff = _quality_cutoff(days)
    try:
        bounded_limit = max(1, min(int(limit), 5000))
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer") from exc
    with get_db() as db:
        return [dict(row) for row in db.execute("""SELECT id,created_at,feedback_scope,
          feedback_action,decision_id,onion_url_id,site_card_id,subject_hash,
          previous_category,final_category,reason_code,classifier_version,safe_metadata_json
          FROM classification_feedback_events WHERE created_at>=?
          ORDER BY created_at DESC,id DESC LIMIT ?""", (cutoff, bounded_limit))]


def get_classification_decision_snapshots(days: int = 30) -> list[dict]:
    """Return only metadata-safe decision columns for bounded quality analysis."""
    cutoff = _quality_cutoff(days)
    with get_db() as db:
        return [dict(row) for row in db.execute("""SELECT id,ts,onion_url_id,site_card_id,
          stage,proposed_category,final_category,confidence_label,confidence_score,
          decision,evidence_families_json,classifier_version,analyst_corrected,
          previous_category,safe_metadata_json
          FROM classification_decisions WHERE stage IN ('page','analyst') AND ts>=?
          ORDER BY ts DESC,id DESC LIMIT 5000""", (cutoff,))]


def upsert_classification_shadow_evaluations(evaluations: list[dict],
                                             evaluator_version: str) -> int:
    """Idempotently persist bounded advisory outputs; this never changes live policy."""
    version = _quality_safe_code(evaluator_version)
    if not version:
        raise ValueError("A metadata-safe evaluator version is required")
    if not isinstance(evaluations, list) or len(evaluations) > 1000:
        raise ValueError("Shadow evaluation batches must be a list of at most 1000 rows")
    prepared: list[tuple] = []
    decision_ids: set[int] = set()
    now = utc_now_iso()
    for evaluation in evaluations:
        if not isinstance(evaluation, dict):
            raise ValueError("Each shadow evaluation must be a mapping")
        try:
            decision_id = int(evaluation["decision_id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Each shadow evaluation requires a decision_id") from exc
        proposed = _quality_safe_code(evaluation.get("proposed_category"))
        if proposed == "severe_abuse_risk":
            raise ValueError("Severe-safety outcomes remain aggregate-only")
        decision_code = _quality_safe_code(evaluation.get("decision_code"))
        if not decision_code:
            raise ValueError("Each shadow evaluation requires a safe decision_code")
        try:
            confidence = float(evaluation.get("confidence_score") or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("Shadow confidence_score must be numeric") from exc
        if not math.isfinite(confidence):
            raise ValueError("Shadow confidence_score must be finite")
        subject = evaluation.get("subject") or f"decision:{decision_id}"
        reasons = _quality_safe_code_list(evaluation.get("reason_codes", []), limit=20)
        prepared.append((
            decision_id, _quality_subject_hash(subject), version, proposed,
            max(0.0, min(confidence, 1.0)), decision_code,
            json.dumps(reasons, separators=(",", ":")),
            int(bool(evaluation.get("would_change"))), now, now,
        ))
        decision_ids.add(decision_id)
    if not prepared:
        return 0
    with get_db() as db:
        marks = ",".join("?" for _ in decision_ids)
        existing_ids = {int(row[0]) for row in db.execute(
            f"SELECT id FROM classification_decisions WHERE id IN ({marks})",
            tuple(sorted(decision_ids)))}
        missing = decision_ids - existing_ids
        if missing:
            raise ValueError("One or more classification decisions were not found")
        for values in prepared:
            db.execute("""INSERT INTO classification_shadow_evaluations
              (decision_id,subject_hash,evaluator_version,proposed_category,confidence_score,
               decision_code,reason_codes_json,would_change,created_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(decision_id,evaluator_version) DO UPDATE SET
               subject_hash=excluded.subject_hash,proposed_category=excluded.proposed_category,
               confidence_score=excluded.confidence_score,decision_code=excluded.decision_code,
               reason_codes_json=excluded.reason_codes_json,would_change=excluded.would_change,
               updated_at=excluded.updated_at""", values)
    return len(prepared)


def get_classification_shadow_evaluations(days: int = 30,
                                          evaluator_version: str | None = None) -> list[dict]:
    cutoff = _quality_cutoff(days)
    params: list[Any] = [cutoff]
    where = "created_at>=?"
    if evaluator_version is not None:
        version = _quality_safe_code(evaluator_version)
        if not version:
            raise ValueError("Invalid evaluator version")
        where += " AND evaluator_version=?"
        params.append(version)
    with get_db() as db:
        return [dict(row) for row in db.execute(f"""SELECT id,decision_id,subject_hash,
          evaluator_version,proposed_category,confidence_score,decision_code,
          reason_codes_json,would_change,created_at,updated_at
          FROM classification_shadow_evaluations WHERE {where}
          ORDER BY created_at DESC,id DESC LIMIT 5000""", tuple(params))]


def store_classification_quality_daily(day: str, classifier_version: str,
                                       metrics: dict) -> None:
    """Upsert one compact aggregate snapshot without storing subjects or evidence."""
    try:
        normalized_day = datetime.strptime(str(day), "%Y-%m-%d").date().isoformat()
    except (TypeError, ValueError) as exc:
        raise ValueError("day must use YYYY-MM-DD") from exc
    version = _quality_safe_code(classifier_version)
    if not version:
        raise ValueError("A metadata-safe classifier version is required")
    if not isinstance(metrics, dict):
        raise ValueError("Classification-quality metrics must be a mapping")
    sanitized = _sanitize_quality_metric(metrics)
    with get_db() as db:
        db.execute("""INSERT INTO classification_quality_daily
          (day,classifier_version,metrics_json,generated_at) VALUES(?,?,?,?)
          ON CONFLICT(day,classifier_version) DO UPDATE SET
           metrics_json=excluded.metrics_json,generated_at=excluded.generated_at""",
          (normalized_day, version,
           json.dumps(sanitized, sort_keys=True, separators=(",", ":")),
           utc_now_iso()))


def get_classification_quality_daily(limit: int = 30) -> list[dict]:
    try:
        bounded_limit = max(1, min(int(limit), 3650))
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer") from exc
    with get_db() as db:
        return [dict(row) for row in db.execute("""SELECT day,classifier_version,
          metrics_json,generated_at FROM classification_quality_daily
          ORDER BY day DESC,classifier_version LIMIT ?""", (bounded_limit,))]


def record_page_change(url: str, current_content_hash: str | None,
                       current_category: str | None) -> bool:
    """Record safe hash/category changes before the current crawl overwrites the baseline."""
    with get_db() as db:
        row = db.execute("SELECT id,site_card_id,content_hash,primary_category FROM onion_urls WHERE url=?",
                         (url,)).fetchone()
        if not row or not row["content_hash"]:
            return False
        hash_changed = bool(current_content_hash and row["content_hash"] != current_content_hash)
        category_changed = bool(current_category and row["primary_category"] != current_category)
        if not hash_changed and not category_changed:
            return False
        change_type = "category_and_content" if hash_changed and category_changed else "category" if category_changed else "content"
        metadata = {"hash_changed": hash_changed, "category_changed": category_changed}
        db.execute("""INSERT INTO page_change_events
          (url,onion_url_id,site_card_id,detected_at,change_type,previous_content_hash,
           current_content_hash,previous_category,current_category,meaningful,safe_summary_json)
          VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
          (url, row["id"], row["site_card_id"], utc_now_iso(), change_type,
           row["content_hash"], current_content_hash, row["primary_category"], current_category,
           1, json.dumps(metadata)))
        if row["site_card_id"]:
            db.execute("""INSERT INTO site_card_events
              (site_card_id,event_type,event_summary,safe_metadata_json,created_at)
              VALUES(?,?,?,?,?)""", (row["site_card_id"], "meaningful_change",
              "Page content or classification changed", json.dumps(metadata), utc_now_iso()))
        return True


def refresh_crawl_coverage(host_or_url: str | None = None) -> int:
    """Rebuild per-host crawl coverage from the durable URL frontier."""
    host = (urlsplit(host_or_url).hostname if host_or_url and "://" in host_or_url else host_or_url)
    where, params = ("WHERE onion_domain=?", (host,)) if host else ("", ())
    with get_db() as db:
        rows = [dict(row) for row in db.execute(f"""SELECT onion_domain,
          COUNT(*) discovered_count,
          SUM(CASE WHEN last_checked_at IS NOT NULL OR last_crawled IS NOT NULL THEN 1 ELSE 0 END) checked_count,
          SUM(CASE WHEN active=1 AND status IN ('new','queued','retry') THEN 1 ELSE 0 END) queued_count,
          SUM(CASE WHEN status='blocked' OR COALESCE(queue_policy,'')='blocked' THEN 1 ELSE 0 END) blocked_count,
          SUM(CASE WHEN status='dead' OR COALESCE(liveness_status,'')='hard_dead' THEN 1 ELSE 0 END) dead_count,
          SUM(CASE WHEN duplicate_of IS NOT NULL OR COALESCE(dedupe_status,'')='duplicate' THEN 1 ELSE 0 END) duplicate_count,
          SUM(CASE WHEN storage_policy IN ('metadata_only','discard') THEN 1 ELSE 0 END) restricted_count,
          MIN(first_seen) first_seen,MAX(first_seen) last_discovered_at,MAX(last_checked_at) last_checked_at,
          MAX(site_card_id) site_card_id FROM onion_urls {where}
          GROUP BY onion_domain""", params)]
        now = utc_now_iso()
        for row in rows:
            discovered = int(row["discovered_count"] or 0)
            checked = int(row["checked_count"] or 0)
            queued = int(row["queued_count"] or 0)
            reason = "Pages remain queued" if queued else "Coverage complete" if checked >= discovered else "Stopped by policy or availability"
            db.execute("""INSERT INTO crawl_coverage
              (onion_host,site_card_id,discovered_count,checked_count,queued_count,blocked_count,
               dead_count,duplicate_count,restricted_count,coverage_ratio,stopping_reason,
               first_seen,last_discovered_at,last_checked_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(onion_host) DO UPDATE SET
               site_card_id=excluded.site_card_id,discovered_count=excluded.discovered_count,
               checked_count=excluded.checked_count,queued_count=excluded.queued_count,
               blocked_count=excluded.blocked_count,dead_count=excluded.dead_count,
               duplicate_count=excluded.duplicate_count,restricted_count=excluded.restricted_count,
               coverage_ratio=excluded.coverage_ratio,stopping_reason=excluded.stopping_reason,
               first_seen=excluded.first_seen,last_discovered_at=excluded.last_discovered_at,
               last_checked_at=excluded.last_checked_at,updated_at=excluded.updated_at""",
              (row["onion_domain"] or "unknown", row["site_card_id"], discovered, checked, queued,
               row["blocked_count"], row["dead_count"], row["duplicate_count"], row["restricted_count"],
               round(checked / discovered, 4) if discovered else 0, reason, row["first_seen"],
               row["last_discovered_at"], row["last_checked_at"], now))
    return len(rows)


def get_classification_quality_summary() -> dict:
    with get_db() as db:
        total = db.execute("SELECT COUNT(*) FROM classification_decisions").fetchone()[0]
        decisions = {row[0]: row[1] for row in db.execute(
            "SELECT decision,COUNT(*) FROM classification_decisions GROUP BY decision")}
        analyst = db.execute("SELECT COUNT(*) FROM classification_decisions WHERE analyst_corrected=1").fetchone()[0]
        corrections = db.execute("""SELECT COUNT(*) FROM classification_decisions
          WHERE analyst_corrected=1 AND COALESCE(previous_category,'')!=COALESCE(final_category,'')""").fetchone()[0]
        categories = [dict(row) for row in db.execute("""SELECT final_category,
          COUNT(*) decision_count,ROUND(AVG(confidence_score),2) avg_confidence,
          SUM(CASE WHEN analyst_corrected=1 THEN 1 ELSE 0 END) analyst_reviews
          FROM classification_decisions GROUP BY final_category ORDER BY decision_count DESC""")]
    return {"total": int(total), "decisions": decisions, "analyst_reviews": int(analyst),
            "corrections": int(corrections),
            "correction_rate": round(corrections / analyst, 3) if analyst else 0.0,
            "categories": categories}


def get_classification_quality_report(days: int = 30) -> dict:
    """Build an honest, metadata-only advisory report.

    Page metrics come from the latest trusted destination-HTML decision per
    URL. Analyst outcomes come from the one-event-per-action feedback ledger,
    so a Site Card with many member URLs is not counted many times.
    """
    from classification_quality import analyze_classification_quality

    decisions = get_classification_decision_snapshots(days)
    feedback = get_classification_feedback_events(days, limit=5000)
    analysis = analyze_classification_quality(decisions)

    action_counts: dict[str, dict[str, int]] = {}
    for event in feedback:
        scope = str(event.get("feedback_scope") or "unknown")
        action = str(event.get("feedback_action") or "unknown")
        action_counts.setdefault(scope, {})
        action_counts[scope][action] = action_counts[scope].get(action, 0) + 1

    def _dimension(scope: str, positive: tuple[str, ...],
                   negative: tuple[str, ...], *, exclude: tuple[str, ...] = ()) -> dict:
        counts = action_counts.get(scope, {})
        confirmed = sum(int(counts.get(action, 0)) for action in positive)
        changed = sum(int(counts.get(action, 0)) for action in negative)
        excluded = sum(int(counts.get(action, 0)) for action in exclude)
        return {
            "reviewed_count": confirmed + changed,
            "confirmed": confirmed,
            "corrected": changed,
            "excluded": excluded,
            "total_events": confirmed + changed + excluded,
        }

    feedback_by_dimension = {
        "category": _dimension(
            "category", ("category_confirmed",), ("category_corrected",)),
        "review": _dimension(
            "review",
            ("review_kept", "review_needs_report", "review_reported"),
            ("review_ignored", "review_blocked"),
        ),
        "spain": _dimension(
            "spain", ("spain_confirmed",), ("spain_removed",)),
        "urgency": _dimension(
            "urgency", ("urgent_confirmed",), ("urgent_dismissed",)),
        "restriction": _dimension(
            "safety", ("adult_block_confirmed",), ("adult_false_positive",)),
        "dedupe": _dimension(
            "mirror", ("mirror_confirmed",), ("mirror_not_same",),
            exclude=("mirror_ignored", "split_after_merge"),
        ),
    }
    category_feedback = feedback_by_dimension["category"]

    correction_pairs: dict[tuple[str, str], int] = {}
    for event in feedback:
        if event.get("feedback_scope") != "category":
            continue
        if event.get("feedback_action") != "category_corrected":
            continue
        previous = str(event.get("previous_category") or "unknown")
        final = str(event.get("final_category") or "unknown")
        correction_pairs[(previous, final)] = correction_pairs.get((previous, final), 0) + 1

    shadow_candidates = []
    persisted_shadow: dict[str, dict[str, int]] = {}
    for row in get_classification_shadow_evaluations(days):
        version = str(row.get("evaluator_version") or "advisory_shadow")
        summary = persisted_shadow.setdefault(version, {
            "sample_size": 0, "changed_count": 0,
        })
        summary["sample_size"] += 1
        summary["changed_count"] += int(bool(row.get("would_change")))
    for version, summary in sorted(persisted_shadow.items()):
        shadow_candidates.append({
            "candidate_ruleset": version,
            "sample_size": summary["sample_size"],
            "changed_count": summary["changed_count"],
            "safety_excluded": int(analysis.get("safety_excluded_count") or 0),
            "current_category": None,
            "candidate_category": None,
            "confidence": "low",
            "decision_mode": "advisory_only",
        })
    for observation in analysis.get("shadow_observations", []):
        kind = str(observation.get("observation_type") or "advisory_observation")
        shadow_candidates.append({
            "candidate_ruleset": kind,
            "sample_size": int(observation.get("sample_size") or 0),
            "changed_count": (
                int(observation.get("sample_size") or 0)
                if kind == "repeated_correction_pattern" else 0
            ),
            "safety_excluded": int(analysis.get("safety_excluded_count") or 0),
            "current_category": observation.get("baseline_category"),
            "candidate_category": observation.get("advisory_category"),
            "confidence": observation.get("confidence") or "low",
            "decision_mode": "advisory_only",
        })

    decision_counts = analysis.get("decision_counts") or {}
    unique_pages = int(analysis.get("prediction_count") or 0)
    reviewed_count = int(category_feedback["reviewed_count"])
    corrections = int(category_feedback["corrected"])
    return {
        "window_days": int(days),
        "page_decisions": int(analysis.get("prediction_event_count") or 0),
        "unique_pages": unique_pages,
        "accepted": int(decision_counts.get("accepted", 0)),
        "unsure": int(decision_counts.get("abstained", 0))
                  + int(decision_counts.get("needs_review", 0)),
        "unknown_rate": float(analysis.get("unknown_rate") or 0),
        "reviewed_count": reviewed_count,
        "category_corrections": corrections,
        "correction_rate": round(corrections / reviewed_count, 4) if reviewed_count else 0.0,
        "feedback_by_dimension": feedback_by_dimension,
        "correction_pairs": [
            {"previous_category": previous, "final_category": final, "count": count}
            for (previous, final), count in sorted(
                correction_pairs.items(), key=lambda item: (-item[1], item[0]))
        ],
        "unknown_reasons": dict(analysis.get("unknown_reason_groups") or {}),
        "shadow_candidates": shadow_candidates,
        "safety_excluded": int(analysis.get("safety_excluded_count") or 0),
        "decision_mode": "advisory_only",
        "rate_note": analysis.get("rate_note"),
    }


def get_uncertain_classifications(limit: int = 100) -> list[dict]:
    with get_db() as db:
        return [dict(row) for row in db.execute("""SELECT url,primary_category,suggested_category,
          classification_decision,classification_confidence_score,category_reason,last_checked_at,site_card_id,
          verification_state,weapons_evidence_score,weapons_evidence_families,weapons_context_type
          FROM onion_urls WHERE classification_decision IN ('abstained','needs_review')
          AND primary_category NOT IN ('adult_filtered','adult_restricted','severe_abuse_risk')
          AND COALESCE(suggested_category,'unknown') NOT IN
            ('adult_filtered','adult_restricted','severe_abuse_risk')
          AND COALESCE(storage_policy,'safe_summary') NOT IN ('discard','metadata_only')
          AND COALESCE(safety_state,'safe') NOT IN ('filtered','discarded','metadata_only')
          ORDER BY classification_confidence_score DESC,last_checked_at DESC LIMIT ?""", (limit,))]


def get_crawl_coverage(limit: int = 200, *, refresh: bool = False) -> list[dict]:
    """Read the materialized coverage snapshot.

    Normal dashboard rendering is deliberately read-only. Maintenance and
    explicit technical actions may request a refresh when they own the write.
    """
    if refresh:
        refresh_crawl_coverage()
    with get_db() as db:
        return [dict(row) for row in db.execute(
            "SELECT * FROM crawl_coverage ORDER BY queued_count DESC,coverage_ratio ASC,updated_at DESC LIMIT ?", (limit,))]


def get_meaningful_changes(limit: int = 100) -> list[dict]:
    with get_db() as db:
        return [dict(row) for row in db.execute("""SELECT id,url,site_card_id,detected_at,change_type,
          previous_category,current_category FROM page_change_events WHERE meaningful=1
          ORDER BY detected_at DESC LIMIT ?""", (limit,))]


_ACTOR_IDENTITY_TYPES = {
    "telegram_handle", "email", "wallet_btc", "wallet_eth", "matrix_id", "tox_id",
    "session_id", "jabber_id", "pgp_key_block", "pgp_fingerprint",
    "clearnet_url", "username",
}


def _actor_evidence_label(indicator_type: str) -> str:
    return {
        "pgp_key_block": "Same public PGP fingerprint",
        "pgp_fingerprint": "Same exact public PGP fingerprint",
        "clearnet_url": "Same exact public website",
        "wallet_btc": "Same public Bitcoin wallet",
        "wallet_eth": "Same public Ethereum wallet",
        "telegram_handle": "Same public Telegram handle",
        "email": "Same public contact address",
        "jabber_id": "Same public Jabber contact",
        "matrix_id": "Same public Matrix contact",
        "tox_id": "Same public Tox contact",
        "session_id": "Same public Session contact",
        "username": "Same explicit public username",
    }.get(indicator_type, "Same public identifier")


def _active_actor_identifier_map_db(db: sqlite3.Connection, actor_id: int) -> dict[str, set[str]]:
    """Return only identifiers still backed by a non-excluded observation."""
    result: dict[str, set[str]] = {}
    rows = db.execute("""SELECT ai.id,ai.indicator_type,ai.value_hash
      FROM actor_identifiers ai WHERE ai.actor_id=?
      AND COALESCE(ai.binding_method,'legacy_unscoped')!='legacy_unscoped'
      AND ai.association_confidence>=0.80
      AND (
        EXISTS (SELECT 1 FROM actor_identifier_observations aio
          JOIN actor_observations ao ON ao.id=aio.observation_id
          WHERE aio.actor_identifier_id=ai.id AND ao.analyst_excluded=0)
        OR (
          NOT EXISTS (SELECT 1 FROM actor_identifier_observations aio2
            WHERE aio2.actor_identifier_id=ai.id)
          AND EXISTS (SELECT 1 FROM actor_observations ao2
            WHERE ao2.id=ai.observation_id AND ao2.analyst_excluded=0)
        )
      )""", (actor_id,))
    for row in rows:
        result.setdefault(str(row["indicator_type"]), set()).add(str(row["value_hash"]))
    return result


def _refresh_actor_connections_db(db: sqlite3.Connection, actor_id: int) -> None:
    actor = db.execute("SELECT * FROM actors WHERE id=?", (actor_id,)).fetchone()
    if not actor:
        return
    own_identifiers = _active_actor_identifier_map_db(db, actor_id)
    candidates = {int(row[0]) for row in db.execute("""SELECT id FROM actors
      WHERE id!=? AND normalized_alias=? AND onion_host!=?""",
      (actor_id, actor["normalized_alias"], actor["onion_host"]))}
    for indicator_type, hashes in own_identifiers.items():
        for value_hash in hashes:
            candidates.update(int(row[0]) for row in db.execute("""SELECT DISTINCT actor_id
              FROM actor_identifiers WHERE actor_id!=? AND indicator_type=? AND value_hash=?
              AND COALESCE(binding_method,'legacy_unscoped')!='legacy_unscoped'
              AND association_confidence>=0.80""", (actor_id, indicator_type, value_hash)))
    # Revisit existing rows too, so exclusions can remove stale automatic weight.
    candidates.update(int(row[0]) for row in db.execute("""SELECT CASE
      WHEN source_actor_id=? THEN target_actor_id ELSE source_actor_id END
      FROM actor_connections WHERE source_actor_id=? OR target_actor_id=?""",
      (actor_id, actor_id, actor_id)))
    now = utc_now_iso()
    weights = {"pgp_key_block": 90, "wallet_btc": 85, "wallet_eth": 85,
               "telegram_handle": 80, "email": 80, "jabber_id": 80, "matrix_id": 80,
               "tox_id": 80, "session_id": 80, "username": 45}
    strong_types = {kind for kind, weight in weights.items() if weight >= 80}
    for candidate_id in sorted(candidates):
        other = db.execute("SELECT * FROM actors WHERE id=?", (candidate_id,)).fetchone()
        if not other:
            continue
        other_identifiers = _active_actor_identifier_map_db(db, candidate_id)
        same_alias = (actor["normalized_alias"] == other["normalized_alias"]
                      and actor["onion_host"] != other["onion_host"]
                      and not actor["generic_role"] and not other["generic_role"])
        shared_types = sorted(
            kind for kind in own_identifiers.keys() & other_identifiers.keys()
            if own_identifiers[kind].intersection(other_identifiers[kind]))
        conflicting_types = sorted(
            kind for kind in strong_types & own_identifiers.keys() & other_identifiers.keys()
            if own_identifiers[kind].isdisjoint(other_identifiers[kind]))
        evidence: list[dict] = []
        score = 30 if same_alias else 0
        if same_alias:
            evidence.append({"type": "same_alias", "label": "Same public alias on different onion sites"})
        for indicator_type in shared_types:
            score = max(score, weights.get(indicator_type, 50))
            evidence.append({"type": indicator_type, "label": _actor_evidence_label(indicator_type)})
        if len(shared_types) >= 2:
            score = min(95, score + min(10, (len(shared_types) - 1) * 5))
        shared_strong = sorted(strong_types.intersection(shared_types))
        warning_type = None
        warning_reason = None
        if conflicting_types:
            warning_type = "conflicting_public_identifiers"
            labels = ", ".join(kind.replace("_", " ") for kind in conflicting_types[:3])
            warning_reason = f"Conflicting exact public {labels} signals require analyst review"
            evidence.append({"type": "contradictory_identifiers", "label": warning_reason})
            # Contradictions never erase the evidence ledger, but they veto an
            # automatic high-confidence/migration interpretation.
            score = min(score, 55)
        migration_candidate = int(
            actor["onion_host"] != other["onion_host"] and bool(shared_strong)
            and not conflicting_types)
        source_id, target_id = sorted((actor_id, candidate_id))
        previous = db.execute("""SELECT id,warning_type,migration_candidate,analyst_decision
          FROM actor_connections WHERE source_actor_id=? AND target_actor_id=?""",
          (source_id, target_id)).fetchone()
        if not evidence:
            if previous and str(previous["analyst_decision"] or "unreviewed") == "unreviewed":
                db.execute("DELETE FROM actor_connections WHERE id=?", (previous["id"],))
            continue
        label = "high" if score >= 80 else "medium" if score >= 60 else "low"
        db.execute("""INSERT INTO actor_connections
          (source_actor_id,target_actor_id,confidence_score,confidence_label,evidence_json,
           first_seen,last_seen,warning_type,warning_reason,migration_candidate)
          VALUES(?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(source_actor_id,target_actor_id) DO UPDATE SET
          confidence_score=excluded.confidence_score,confidence_label=excluded.confidence_label,
          evidence_json=excluded.evidence_json,last_seen=excluded.last_seen,
          warning_type=excluded.warning_type,warning_reason=excluded.warning_reason,
          migration_candidate=excluded.migration_candidate""",
          (source_id, target_id, score, label, json.dumps(evidence, ensure_ascii=False), now, now,
           warning_type, warning_reason, migration_candidate))
        connection_id = int(db.execute("SELECT id FROM actor_connections WHERE source_actor_id=? AND target_actor_id=?",
                                       (source_id, target_id)).fetchone()[0])
        if migration_candidate and (not previous or not previous["migration_candidate"]):
            db.execute("""INSERT INTO actor_events(actor_id,connection_id,event_type,safe_metadata_json,created_at)
              VALUES(?,?,?,?,?)""", (actor_id, connection_id, "market_migration_detected",
              json.dumps({"other_actor_id": candidate_id,
                          "reason": "Public alias appeared on a new market with shared public signals"}), now))
        if warning_type and (not previous or not previous["warning_type"]):
            db.execute("""INSERT INTO actor_events(actor_id,connection_id,event_type,safe_metadata_json,created_at)
              VALUES(?,?,?,?,?)""", (actor_id, connection_id, "possible_copycat_detected",
              json.dumps({"other_actor_id": candidate_id, "reason": warning_reason}), now))


def _seller_observation_scope(policy: dict, aliases: list[dict]) -> tuple[int, str, str]:
    """Return seller flag, Spain shipping direction, and a safe marketplace category."""
    page_type = str(policy.get("page_type") or "unknown")
    category = str(policy.get("primary_category") or "unknown")
    alias_labels = " ".join(str(item.get("evidence_type") or "") for item in aliases).casefold()
    seller = bool(
        page_type in {"vendor_page", "listing_page", "product_page"}
        or category.startswith("marketplace")
        or any(marker in alias_labels for marker in ("seller", "vendor", "merchant"))
    )
    tags = {str(tag).casefold() for tag in (policy.get("spain_context_tags") or [])}
    from_spain = "trade_flow_from_spain" in tags
    to_spain = "trade_flow_to_spain" in tags
    if from_spain and to_spain:
        flow = "both"
    elif from_spain:
        flow = "from_spain"
    elif to_spain:
        flow = "to_spain"
    elif policy.get("spain_priority"):
        flow = "spain_context"
    else:
        flow = "none"
    secondary = {str(item).casefold() for item in (policy.get("secondary_categories") or [])}
    carding_markers = {"carding", "cloned_cards", "fullz", "digital_cc", "payment_card_fraud"}
    if category == "marketplace_fraud" or secondary.intersection(carding_markers):
        marketplace_category = "carding"
    else:
        marketplace_category = str(policy.get("marketplace_category") or category or "unknown")[:80]
    return int(seller), flow, marketplace_category


def _alias_seller_observation_scope(policy: dict, alias: dict) -> tuple[int, str, str]:
    """Seller status is per accepted alias, not inherited from the whole page."""
    _page_seller, flow, marketplace_category = _seller_observation_scope(policy, [alias])
    evidence_type = str(alias.get("evidence_type") or "").casefold()
    role = str(alias.get("role") or "").casefold()
    seller_evidence = bool(alias.get("seller_evidence"))
    explicit_seller_evidence = seller_evidence or role in {"vendor", "seller", "merchant"} or any(
        marker in evidence_type for marker in (
            "vendor", "seller", "merchant", "linked_vendor_field", "linked_seller_field",
            "vendor_page_identity_match", "seller_page_identity_match",
        )
    )
    # Legacy direct tests may pass seller_label/vendor_label without the v2 fields.
    legacy_explicit = evidence_type in {"seller_label", "vendor_label"}
    return int(explicit_seller_evidence or legacy_explicit), flow, marketplace_category


def _actor_alias_storage_allowed(alias: dict) -> bool:
    """Defense-in-depth gate for automatically created actor identities."""
    from entity_extractor import is_noisy_public_alias

    normalized = str(alias.get("normalized_alias") or alias.get("alias") or "")
    if is_noisy_public_alias(normalized) or float(alias.get("confidence") or 0) < 0.90:
        return False
    evidence_type = str(alias.get("evidence_type") or "").casefold()
    if alias.get("auto_store_eligible") and evidence_type == "corroborated_public_alias":
        return True
    if alias.get("auto_store_eligible") and evidence_type == "cryptographically_corroborated_alias":
        return True
    if evidence_type in {
        "explicit_label", "seller_label", "vendor_label",
        "profile_page_identity_match", "vendor_page_identity_match",
        "seller_page_identity_match", "linked_vendor_field", "linked_seller_field",
        "marketplace_vendor_card", "marketplace_seller_card",
    }:
        return True
    return evidence_type.endswith("_post_author")


def _actor_profile_identity(alias: dict) -> tuple[str | None, str | None]:
    """Return a stable safe profile identity and canonical public profile URL."""
    profile_url = str(alias.get("profile_url") or "").strip()[:500]
    if not profile_url:
        return None, None
    from entity_extractor import canonical_profile_identity
    identity = canonical_profile_identity(profile_url)
    if not identity:
        return None, None
    return identity[:120], canonical_url_identity(profile_url)


def store_actor_observations(url: str, aliases: list[dict], identity_evidence: list[dict],
                             policy: dict) -> list[int]:
    """Store public alias observations and safe correlation hashes only."""
    restricted = policy.get("primary_category") in {"adult_filtered", "adult_restricted", "severe_abuse_risk"}
    if restricted or policy.get("storage_policy") == "discard":
        with get_db() as db:
            _remove_actor_observations_db(db, [url])
        return []
    if not aliases:
        return []
    page_type = str(policy.get("page_type") or "unknown")
    category = str(policy.get("primary_category") or "unknown")
    actor_page = (bool(policy.get("spain_priority")) or page_type in {
        "thread_page", "post_page", "vendor_page", "listing_page", "profile_page", "category_page"
    } or category.startswith("marketplace") or category in {
        "forum_social", "weapons_arms", "drugs", "leaks_data", "credentials",
        "malware_hacking", "fraud_financial", "extremist_recruitment",
    })
    if not actor_page:
        return []
    host = (urlsplit(url).hostname or "").casefold()
    if not host.endswith(".onion"):
        return []
    now = utc_now_iso()
    actor_ids: list[int] = []
    stored_records: list[tuple[int, int, dict]] = []
    _page_seller_observation, _page_spain_flow, _page_marketplace_category = _seller_observation_scope(policy, aliases)
    with get_db() as db:
        page = db.execute("SELECT site_card_id FROM onion_urls WHERE url=?", (url,)).fetchone()
        shape = canonicalize_spain_hit(url)
        hit = db.execute("""SELECT id FROM spain_hits WHERE onion_host=? AND normalized_family=?
          AND hit_type=? AND COALESCE(analyst_suppressed,0)=0""",
          (shape["onion_host"], shape["normalized_family"], shape["hit_type"])).fetchone()
        for alias in aliases[:10]:
            if not _actor_alias_storage_allowed(alias):
                continue
            normalized = str(alias.get("normalized_alias") or "")[:32]
            display = str(alias.get("alias") or normalized)[:32]
            if not normalized:
                continue
            profile_identity, profile_url = _actor_profile_identity(alias)
            identity_kind = "host_profile" if profile_identity else "host_alias"
            identity_key = _actor_identity_key(host, normalized, profile_identity)
            skeleton = str(alias.get("alias_skeleton") or "")[:80]
            confidence = float(alias.get("confidence") or 0)

            actor = db.execute("SELECT * FROM actors WHERE identity_key=?", (identity_key,)).fetchone()
            if not actor and profile_identity:
                # Upgrade one unambiguous legacy handle card when its first
                # structural public profile identity becomes available.
                legacy = list(db.execute("""SELECT * FROM actors WHERE onion_host=?
                  AND normalized_alias=? AND COALESCE(canonical_profile_identity,'')=''
                  ORDER BY id""", (host, normalized)))
                if len(legacy) == 1:
                    db.execute("""UPDATE actors SET identity_key=?,identity_kind='host_profile',
                      canonical_profile_identity=?,canonical_profile_url=?,alias_skeleton=?,
                      identity_confidence=MAX(COALESCE(identity_confidence,0),?) WHERE id=?""",
                      (identity_key, profile_identity, profile_url, skeleton, confidence, legacy[0]["id"]))
                    actor = db.execute("SELECT * FROM actors WHERE id=?", (legacy[0]["id"],)).fetchone()
            elif not actor and not profile_identity:
                same_name = list(db.execute("""SELECT * FROM actors WHERE onion_host=?
                  AND normalized_alias=? ORDER BY id""", (host, normalized)))
                if len(same_name) == 1:
                    actor = same_name[0]
                elif len(same_name) > 1:
                    # A flat mention cannot choose between distinct profiles.
                    continue
            if not actor:
                db.execute("""INSERT INTO actors
                  (normalized_alias,display_alias,onion_host,generic_role,first_seen,last_seen,
                   identity_key,identity_kind,canonical_profile_identity,canonical_profile_url,
                   alias_skeleton,identity_confidence)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(identity_key) DO UPDATE SET
                  display_alias=excluded.display_alias,last_seen=excluded.last_seen,
                  canonical_profile_url=COALESCE(excluded.canonical_profile_url,actors.canonical_profile_url),
                  alias_skeleton=COALESCE(excluded.alias_skeleton,actors.alias_skeleton),
                  identity_confidence=MAX(COALESCE(actors.identity_confidence,0),excluded.identity_confidence)""",
                  (normalized, display, host, int(bool(alias.get("generic_role"))), now, now,
                   identity_key, identity_kind, profile_identity, profile_url, skeleton, confidence))
                actor = db.execute("SELECT * FROM actors WHERE identity_key=?", (identity_key,)).fetchone()
            else:
                db.execute("""UPDATE actors SET display_alias=?,last_seen=?,alias_skeleton=COALESCE(?,alias_skeleton),
                  identity_confidence=MAX(COALESCE(identity_confidence,0),?) WHERE id=?""",
                  (display, now, skeleton or None, confidence, actor["id"]))
            actor_id = int(actor["id"])
            evidence_type = alias.get("evidence_type") or "public_alias"
            existing_observation = db.execute("""SELECT * FROM actor_observations
              WHERE actor_id=? AND url=? AND evidence_type=?""",
              (actor_id, url, evidence_type)).fetchone()
            db.execute("""INSERT INTO actor_aliases
              (actor_id,normalized_alias,display_alias,alias_skeleton,first_seen,last_seen,observation_count)
              VALUES(?,?,?,?,?,?,1) ON CONFLICT(actor_id,normalized_alias,display_alias) DO UPDATE SET
              last_seen=excluded.last_seen,observation_count=actor_aliases.observation_count+?,
              alias_skeleton=COALESCE(excluded.alias_skeleton,actor_aliases.alias_skeleton)""",
              (actor_id, normalized, display, skeleton or None, now, now,
               0 if existing_observation else 1))
            seller_observation, spain_flow, marketplace_category = _alias_seller_observation_scope(policy, alias)
            actor_ids.append(actor_id)
            previous_seller = db.execute("""SELECT * FROM actor_observations
              WHERE actor_id=? AND analyst_excluded=0 AND seller_observation=1
              ORDER BY last_seen DESC,id DESC LIMIT 1""", (actor_id,)).fetchone()
            db.execute("""INSERT INTO actor_observations
              (actor_id,url,onion_host,site_card_id,spain_hit_id,observed_at,last_seen,page_type,
               primary_category,risk_level,spain_priority,spain_reason,evidence_type,
               evidence_confidence,safe_context_label,seller_observation,spain_flow,marketplace_category,
               profile_identity,profile_url,source_scope,evidence_signals_json,bound_identifier_count)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
              ON CONFLICT(actor_id,url,evidence_type) DO UPDATE SET
               site_card_id=COALESCE(excluded.site_card_id,actor_observations.site_card_id),
               spain_hit_id=COALESCE(excluded.spain_hit_id,actor_observations.spain_hit_id),
               last_seen=excluded.last_seen,page_type=excluded.page_type,
               primary_category=excluded.primary_category,risk_level=excluded.risk_level,
               spain_priority=excluded.spain_priority,spain_reason=excluded.spain_reason,
               evidence_confidence=MAX(actor_observations.evidence_confidence,excluded.evidence_confidence),
               seller_observation=excluded.seller_observation,spain_flow=excluded.spain_flow,
               marketplace_category=excluded.marketplace_category,
               profile_identity=COALESCE(excluded.profile_identity,actor_observations.profile_identity),
               profile_url=COALESCE(excluded.profile_url,actor_observations.profile_url),
               source_scope=COALESCE(excluded.source_scope,actor_observations.source_scope),
               evidence_signals_json=COALESCE(excluded.evidence_signals_json,actor_observations.evidence_signals_json)""",
              (actor_id, url, host, page["site_card_id"] if page else None, hit["id"] if hit else None,
               now, now, page_type, category, policy.get("risk_level"), int(bool(policy.get("spain_priority"))),
               policy.get("spain_match_reason"), evidence_type,
               confidence, str(alias.get("safe_context_label") or "Public alias observation")[:160],
               seller_observation, spain_flow, marketplace_category, profile_identity, profile_url,
               str(alias.get("source_scope") or "page")[:40],
               json.dumps(alias.get("evidence_signals") or [], ensure_ascii=False), 0))
            observation_id = int(db.execute("""SELECT id FROM actor_observations
              WHERE actor_id=? AND url=? AND evidence_type=?""",
              (actor_id, url, evidence_type)).fetchone()[0])
            stored_records.append((actor_id, observation_id, alias))
            watched = db.execute("SELECT watched FROM actors WHERE id=?", (actor_id,)).fetchone()[0]
            if watched and not existing_observation:
                db.execute("""INSERT OR IGNORE INTO actor_watch_alerts
                  (actor_id,related_actor_id,url,alert_type,safe_reason,created_at)
                  VALUES(?,0,?,'new_activity',?,?)""",
                  (actor_id, url, "New exact public page observed for watched alias", now))
            if seller_observation:
                event_type = None
                metadata = {"url": url, "spain_flow": spain_flow,
                            "marketplace_category": marketplace_category}
                if not previous_seller:
                    event_type = "seller_first_seen"
                elif previous_seller["spain_flow"] != spain_flow:
                    event_type = "shipping_changed"
                    metadata["previous_spain_flow"] = previous_seller["spain_flow"]
                elif previous_seller["marketplace_category"] != marketplace_category:
                    event_type = "seller_category_changed"
                    metadata["previous_marketplace_category"] = previous_seller["marketplace_category"]
                elif not existing_observation:
                    event_type = "seller_new_page"
                if event_type:
                    db.execute("""INSERT INTO actor_events(actor_id,event_type,safe_metadata_json,created_at)
                      VALUES(?,?,?,?)""", (actor_id, event_type,
                      json.dumps(metadata, ensure_ascii=False), now))
                    if watched and event_type in {"shipping_changed", "seller_category_changed"}:
                        alert_type = "shipping_change" if event_type == "shipping_changed" else "seller_category_change"
                        reason = ("Public Spain shipping direction changed" if event_type == "shipping_changed"
                                  else "Public marketplace category changed")
                        db.execute("""INSERT OR IGNORE INTO actor_watch_alerts
                          (actor_id,related_actor_id,url,alert_type,safe_reason,created_at)
                          VALUES(?,0,?,?,?,?)""",
                          (actor_id, url, alert_type, reason, now))

        from entity_extractor import normalize_public_alias
        for actor_id, observation_id, alias in stored_records:
            normalized_alias = str(alias.get("normalized_alias") or "")
            local_hashes = {f"local_sha256:{str(item.get('value_hash') or '').casefold()}"
                            for item in alias.get("bound_identifiers") or [] if item.get("value_hash")}
            bound_count = 0
            for item in identity_evidence[:50]:
                indicator_type = str(item.get("type") or "")
                if indicator_type not in _ACTOR_IDENTITY_TYPES:
                    continue
                normalized_value = str(item.get("normalized_value") or item.get("value") or "")
                comparable = normalize_public_alias(normalized_value.split("@", 1)[0] if indicator_type == "email"
                                                    else normalized_value)
                directly_named = indicator_type in {"username", "telegram_handle"} and comparable == normalized_alias
                locally_bound = normalized_value in local_hashes
                if not locally_bound and not directly_named:
                    continue
                value_hash = hashlib.sha256(f"{indicator_type}:{normalized_value}".encode("utf-8", "ignore")).hexdigest()
                association = 0.98 if locally_bound else 0.95
                binding_method = "same_structural_container" if locally_bound else "explicit_alias_label"
                db.execute("""INSERT INTO actor_identifiers
                  (actor_id,indicator_type,value_hash,safe_value_label,association_confidence,first_seen,last_seen,
                   observation_id,binding_method,source_scope)
                  VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(actor_id,indicator_type,value_hash) DO UPDATE SET
                  association_confidence=MAX(actor_identifiers.association_confidence,excluded.association_confidence),
                  last_seen=excluded.last_seen,observation_id=COALESCE(excluded.observation_id,actor_identifiers.observation_id),
                  binding_method=excluded.binding_method,source_scope=excluded.source_scope""",
                  (actor_id, indicator_type, value_hash, _actor_evidence_label(indicator_type), association,
                   now, now, observation_id, binding_method,
                   str(alias.get("source_scope") or "page")[:40]))
                identifier_id = int(db.execute("""SELECT id FROM actor_identifiers
                  WHERE actor_id=? AND indicator_type=? AND value_hash=?""",
                  (actor_id, indicator_type, value_hash)).fetchone()[0])
                db.execute("""INSERT INTO actor_identifier_observations
                  (actor_identifier_id,observation_id,first_seen,last_seen) VALUES(?,?,?,?)
                  ON CONFLICT(actor_identifier_id,observation_id) DO UPDATE SET
                  last_seen=excluded.last_seen""",
                  (identifier_id, observation_id, now, now))
                bound_count += 1
            db.execute("UPDATE actor_observations SET bound_identifier_count=? WHERE id=?",
                       (bound_count, observation_id))
        for actor_id in actor_ids:
            _refresh_actor_stats_db(db, actor_id)
            _refresh_actor_connections_db(db, actor_id)
            related = [dict(row) for row in db.execute("""SELECT c.id,c.source_actor_id,c.target_actor_id,
              c.warning_type,c.warning_reason,c.migration_candidate,
              CASE WHEN c.source_actor_id=? THEN c.target_actor_id ELSE c.source_actor_id END other_actor_id
              FROM actor_connections c WHERE c.source_actor_id=? OR c.target_actor_id=?""",
              (actor_id, actor_id, actor_id))]
            for connection in related:
                other = db.execute("SELECT watched FROM actors WHERE id=?", (connection["other_actor_id"],)).fetchone()
                if other and other["watched"]:
                    alert_type = ("market_migration" if connection.get("migration_candidate")
                                  else "possible_copycat" if connection.get("warning_type")
                                  else "possible_correspondence")
                    reason = ("Public alias appeared on another market with shared public signals"
                              if alert_type == "market_migration" else
                              connection.get("warning_reason") or
                              "New activity from a public alias with correlation evidence")
                    db.execute("""INSERT OR IGNORE INTO actor_watch_alerts
                      (actor_id,related_actor_id,url,alert_type,safe_reason,created_at)
                      VALUES(?,?,?,?,?,?)""",
                      (connection["other_actor_id"], actor_id, url,
                       alert_type, reason, now))
    return actor_ids


def attach_actor_observations_to_site_card(url: str, site_card_id: int) -> int:
    """Attach verify-stage actor observations after the card stage creates the card."""
    with get_db() as db:
        changed = db.execute("""UPDATE actor_observations SET site_card_id=?
          WHERE url=? AND (site_card_id IS NULL OR site_card_id!=?)""",
          (int(site_card_id), url, int(site_card_id))).rowcount
        return int(changed or 0)


_ACTOR_CANDIDATE_STATES = {
    "accepted_observation", "rejected_noise", "analyst_review_candidate",
    "analyst_confirmed_identity_evidence", "analyst_rejected_identity_evidence",
    "superseded_or_contradicted_observation",
}
_ACTOR_CANDIDATE_DECISIONS = {
    "confirm": "analyst_confirmed_identity_evidence",
    "reject": "analyst_rejected_identity_evidence",
    "contradict": "superseded_or_contradicted_observation",
    "supersede": "superseded_or_contradicted_observation",
}


def _bounded_candidate_json(value: object, *, default: object) -> str:
    payload = value if isinstance(value, (dict, list, tuple)) else default
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)[:12000]


def _actor_candidate_key(url: str, candidate: dict) -> str:
    material = "\n".join((
        canonical_url_identity(url),
        str(candidate.get("normalized_alias") or "").casefold(),
        str(candidate.get("extraction_method") or candidate.get("evidence_type") or "unknown").casefold(),
        str(candidate.get("profile_identity") or "").casefold(),
    ))
    return "candidate:" + hashlib.sha256(material.encode("utf-8", "ignore")).hexdigest()


def upsert_actor_candidates(url: str, candidates: list[dict], policy: dict) -> list[int]:
    """Persist explainable candidate decisions without changing actor acceptance.

    Reprocessing the same page/candidate updates ``last_seen`` but does not inflate
    the distinct-observation count. Analyst state is a separate durable override.
    """
    if (policy.get("primary_category") in {"adult_filtered", "adult_restricted", "severe_abuse_risk"}
            or policy.get("storage_policy") == "discard"):
        return []
    host = (urlsplit(url or "").hostname or "").casefold()
    if not host.endswith(".onion"):
        return []
    now = utc_now_iso()
    stored: list[int] = []
    with get_db() as db:
        page = db.execute("SELECT id,site_card_id FROM onion_urls WHERE url=?", (url,)).fetchone()
        for candidate in (candidates or [])[:100]:
            if not isinstance(candidate, dict):
                continue
            automatic_state = str(candidate.get("state") or "analyst_review_candidate")
            if automatic_state not in _ACTOR_CANDIDATE_STATES:
                automatic_state = "analyst_review_candidate"
            normalized = str(candidate.get("normalized_alias") or "").strip().casefold()[:32]
            display = str(candidate.get("alias") or candidate.get("display_alias") or normalized).strip()[:64]
            if not normalized or not display:
                continue
            candidate_key = _actor_candidate_key(url, candidate)
            existing = db.execute("SELECT id,analyst_state,effective_state FROM actor_candidates WHERE candidate_key=?",
                                  (candidate_key,)).fetchone()
            analyst_state = str(existing["analyst_state"] or "") if existing else ""
            effective_state = analyst_state or automatic_state
            db.execute("""INSERT INTO actor_candidates
              (candidate_key,url,onion_host,onion_url_id,site_card_id,actor_id,display_alias,
               normalized_alias,alias_skeleton,automatic_state,analyst_state,effective_state,
               structural_container,structural_role,extraction_method,profile_route_agreement,
               profile_identity,profile_url,page_role,forum_role,evidence_type,evidence_strength,
               evidence_confidence,reason_codes_json,blocking_signals_json,script_profile_json,
               bound_identifier_types_json,confidence_contributions_json,ruleset_version,
               first_seen,last_seen,seen_count)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
              ON CONFLICT(candidate_key) DO UPDATE SET
               onion_url_id=COALESCE(excluded.onion_url_id,actor_candidates.onion_url_id),
               site_card_id=COALESCE(excluded.site_card_id,actor_candidates.site_card_id),
               display_alias=excluded.display_alias,alias_skeleton=excluded.alias_skeleton,
               automatic_state=excluded.automatic_state,
               effective_state=CASE WHEN actor_candidates.analyst_state IS NOT NULL
                 AND actor_candidates.analyst_state!='' THEN actor_candidates.analyst_state
                 ELSE excluded.automatic_state END,
               structural_container=excluded.structural_container,
               structural_role=excluded.structural_role,extraction_method=excluded.extraction_method,
               profile_route_agreement=excluded.profile_route_agreement,
               profile_identity=COALESCE(excluded.profile_identity,actor_candidates.profile_identity),
               profile_url=COALESCE(excluded.profile_url,actor_candidates.profile_url),
               page_role=excluded.page_role,forum_role=excluded.forum_role,
               evidence_type=excluded.evidence_type,evidence_strength=excluded.evidence_strength,
               evidence_confidence=MAX(actor_candidates.evidence_confidence,excluded.evidence_confidence),
               reason_codes_json=excluded.reason_codes_json,
               blocking_signals_json=excluded.blocking_signals_json,
               script_profile_json=excluded.script_profile_json,
               bound_identifier_types_json=excluded.bound_identifier_types_json,
               confidence_contributions_json=excluded.confidence_contributions_json,
               ruleset_version=excluded.ruleset_version,last_seen=excluded.last_seen""",
              (candidate_key, url, host, page["id"] if page else None,
               page["site_card_id"] if page else None, candidate.get("actor_id"), display,
               normalized, str(candidate.get("alias_skeleton") or "")[:80], automatic_state,
               analyst_state or None, effective_state,
               str(candidate.get("structural_container") or "unknown")[:40],
               str(candidate.get("structural_role") or candidate.get("role") or "unknown")[:40],
               str(candidate.get("extraction_method") or candidate.get("evidence_type") or "unknown")[:80],
               str(candidate.get("profile_route_agreement") or "missing")[:40],
               str(candidate.get("profile_identity") or "")[:160] or None,
               str(candidate.get("profile_url") or "")[:500] or None,
               str(candidate.get("page_role") or policy.get("page_type") or "unknown")[:40],
               str(candidate.get("forum_role") or "unknown")[:40],
               str(candidate.get("evidence_type") or candidate.get("extraction_method") or "unknown")[:80],
               str(candidate.get("evidence_strength") or "unknown")[:20],
               max(0.0, min(float(candidate.get("confidence_score") or candidate.get("confidence") or 0), 1.0)),
               _bounded_candidate_json(candidate.get("reason_codes"), default=[]),
               _bounded_candidate_json(candidate.get("blocking_signals"), default=[]),
               _bounded_candidate_json(candidate.get("script_profile"), default={}),
               _bounded_candidate_json(candidate.get("bound_identifier_types"), default=[]),
               _bounded_candidate_json(candidate.get("confidence_contributions"), default={}),
               str(candidate.get("ruleset_version") or "unknown")[:80], now, now))
            candidate_id = int(db.execute("SELECT id FROM actor_candidates WHERE candidate_key=?",
                                          (candidate_key,)).fetchone()[0])
            stored.append(candidate_id)
            if not existing:
                db.execute("""INSERT INTO actor_candidate_events
                  (candidate_id,actor_id,event_type,new_state,reason_code,safe_metadata_json,created_at)
                  VALUES(?,?,?,?,?,?,?)""",
                  (candidate_id, candidate.get("actor_id"), "automatic_evaluation", automatic_state,
                   str((candidate.get("reason_codes") or ["evaluated"])[0])[:80], "{}", now))
    return stored


def link_actor_candidates(url: str, actor_ids: list[int]) -> int:
    """Attach accepted candidates using exact profile identity when available.

    A handle can legitimately name more than one profile on the same host.  A
    profile-bound candidate therefore never falls back across profiles.  Legacy
    profile-less rows are linked only when the host+alias resolves to exactly one
    actor, preserving old data without creating a new ambiguous association.
    """
    selected = sorted({int(value) for value in actor_ids if int(value) > 0})
    if not selected:
        return 0
    changed = 0
    with get_db() as db:
        for actor_id in selected:
            actor = db.execute("""SELECT normalized_alias,onion_host,
              COALESCE(canonical_profile_identity,'') canonical_profile_identity
              FROM actors WHERE id=?""", (actor_id,)).fetchone()
            if not actor:
                continue
            profile_identity = str(actor["canonical_profile_identity"] or "")
            profile_changed = db.execute("""UPDATE actor_candidates SET actor_id=?
              WHERE url=? AND onion_host=? AND normalized_alias=? AND actor_id IS NULL
              AND COALESCE(profile_identity,'')=?
              AND effective_state IN ('accepted_observation','analyst_confirmed_identity_evidence')""",
              (actor_id, url, actor["onion_host"], actor["normalized_alias"],
               profile_identity)).rowcount
            changed += int(profile_changed or 0)

            actor_count = int(db.execute("""SELECT COUNT(*) FROM actors
              WHERE onion_host=? AND normalized_alias=?""",
              (actor["onion_host"], actor["normalized_alias"])).fetchone()[0])
            if actor_count != 1:
                continue
            if profile_identity:
                # One known profile may safely absorb older profile-less evidence.
                fallback_profile = ""
            else:
                # A profile-less legacy actor may absorb one, and only one,
                # unambiguous profile identity observed on this exact page.
                identities = [str(row[0] or "") for row in db.execute("""SELECT DISTINCT
                  COALESCE(profile_identity,'') FROM actor_candidates
                  WHERE url=? AND onion_host=? AND normalized_alias=? AND actor_id IS NULL
                  AND COALESCE(profile_identity,'')!=''
                  AND effective_state IN ('accepted_observation','analyst_confirmed_identity_evidence')""",
                  (url, actor["onion_host"], actor["normalized_alias"]))]
                if len(identities) != 1:
                    continue
                fallback_profile = identities[0]
            changed += int(db.execute("""UPDATE actor_candidates SET actor_id=?
              WHERE url=? AND onion_host=? AND normalized_alias=? AND actor_id IS NULL
              AND COALESCE(profile_identity,'')=?
              AND effective_state IN ('accepted_observation','analyst_confirmed_identity_evidence')""",
              (actor_id, url, actor["onion_host"], actor["normalized_alias"],
               fallback_profile)).rowcount or 0)
    return changed


def record_actor_candidate_decision(candidate_id: int, decision: str, *,
                                    reason_code: str = "analyst_decision",
                                    analyst_id: str | None = None) -> bool:
    normalized_decision = str(decision or "").strip().casefold()
    if normalized_decision == "clear":
        target_state = None
    else:
        target_state = _ACTOR_CANDIDATE_DECISIONS.get(normalized_decision)
        if not target_state:
            raise ValueError("unsupported actor candidate decision")
    now = utc_now_iso()
    with get_db() as db:
        row = db.execute("SELECT actor_id,automatic_state,effective_state FROM actor_candidates WHERE id=?",
                         (int(candidate_id),)).fetchone()
        if not row:
            return False
        effective = target_state or str(row["automatic_state"])
        db.execute("""UPDATE actor_candidates SET analyst_state=?,effective_state=?,last_seen=? WHERE id=?""",
                   (target_state, effective, now, int(candidate_id)))
        db.execute("""INSERT INTO actor_candidate_events
          (candidate_id,actor_id,event_type,old_state,new_state,reason_code,
           safe_metadata_json,analyst_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
          (int(candidate_id), row["actor_id"], "analyst_decision", row["effective_state"],
           effective, str(reason_code or "analyst_decision")[:80], "{}",
           str(analyst_id or "analyst")[:80], now))
    return True


def get_actor_candidate_review_queue(*, search: str | None = None,
                                     states: tuple[str, ...] | None = None,
                                     limit: int = 200) -> list[dict]:
    selected_states = states or (
        "analyst_review_candidate", "analyst_rejected_identity_evidence",
        "superseded_or_contradicted_observation",
    )
    selected_states = tuple(state for state in selected_states if state in _ACTOR_CANDIDATE_STATES)
    if not selected_states:
        return []
    where = [f"ac.effective_state IN ({','.join('?' for _ in selected_states)})"]
    params: list[Any] = list(selected_states)
    if search:
        where.append("(ac.normalized_alias LIKE ? OR ac.onion_host LIKE ? OR COALESCE(sc.display_name,'') LIKE ?)")
        needle = f"%{str(search).casefold().strip()}%"
        params.extend([needle, needle, needle])
    params.append(max(1, min(int(limit or 200), 1000)))
    with get_db() as db:
        return [dict(row) for row in db.execute(f"""SELECT ac.*,
          COALESCE(sc.analyst_title,sc.display_name) site_card_name,a.watched actor_watched
          FROM actor_candidates ac LEFT JOIN actors a ON a.id=ac.actor_id
          LEFT JOIN site_cards sc ON sc.id=ac.site_card_id
          WHERE {' AND '.join(where)}
          ORDER BY CASE ac.effective_state WHEN 'superseded_or_contradicted_observation' THEN 0
            WHEN 'analyst_review_candidate' THEN 1 ELSE 2 END,
          ac.evidence_confidence DESC,ac.last_seen DESC LIMIT ?""", tuple(params))]


def get_alias_quality_audit(*, limit: int = 5000) -> dict:
    """Return deterministic dry-run metrics; this function never mutates data."""
    limit = max(1, min(int(limit or 5000), 50000))
    with get_db() as db:
        rows = [dict(row) for row in db.execute("""SELECT id,actor_id,effective_state,
          reason_codes_json,script_profile_json,normalized_alias,onion_host
          FROM actor_candidates ORDER BY id LIMIT ?""", (limit,))]
        weak_actors = int(db.execute("""SELECT COUNT(*) FROM actors WHERE observation_count<=1
          AND watched=0 AND COALESCE(analyst_status,'unreviewed')='unreviewed'""").fetchone()[0])
        broad_aliases = int(db.execute("""SELECT COUNT(*) FROM (
          SELECT normalized_alias FROM actor_candidates GROUP BY normalized_alias
          HAVING COUNT(DISTINCT onion_host)>=4)""").fetchone()[0])
    states: dict[str, int] = {}
    reasons: dict[str, int] = {}
    mixed = confusable = stored_noise = generic_leakage = 0
    for row in rows:
        state = str(row.get("effective_state") or "unknown")
        states[state] = states.get(state, 0) + 1
        try:
            row_reasons = json.loads(row.get("reason_codes_json") or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            row_reasons = []
        for reason in row_reasons if isinstance(row_reasons, list) else []:
            key = str(reason)
            reasons[key] = reasons.get(key, 0) + 1
        try:
            script = json.loads(row.get("script_profile_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            script = {}
        mixed += int(bool(isinstance(script, dict) and script.get("mixed_script")))
        confusable += int(bool(isinstance(script, dict) and script.get("confusable_character_count")))
        stored_noise += int(bool(row.get("actor_id") and state == "rejected_noise"))
        generic_leakage += int("rejected_generic_role" in row_reasons and bool(row.get("actor_id")))
    return {
        "dry_run": True, "scanned": len(rows),
        "states": {key: states[key] for key in sorted(states)},
        "top_rejection_reasons": sorted(reasons.items(), key=lambda item: (-item[1], item[0]))[:20],
        "likely_stored_noise": stored_noise, "mixed_script_review": mixed,
        "confusable_review": confusable, "generic_role_leakage": generic_leakage,
        "weak_single_observation_actors": weak_actors, "broadly_repeated_aliases": broad_aliases,
        "proposed_cleanup_actions": stored_noise + generic_leakage,
    }


def get_alias_noise_rules(*, enabled_only: bool = True) -> list[dict]:
    where = "WHERE enabled=1" if enabled_only else ""
    with get_db() as db:
        return [dict(row) for row in db.execute(f"""SELECT * FROM alias_noise_rules {where}
          ORDER BY scope,rule_type,normalized_pattern,id""")]


def upsert_alias_noise_rule(rule_type: str, pattern: str, *, action: str,
                            reason_code: str, scope: str = "global",
                            enabled: bool = True, analyst_id: str | None = None,
                            rule_version: str = "analyst.1") -> int:
    rule_type = str(rule_type or "").casefold().strip()
    action = str(action or "").casefold().strip()
    normalized_pattern = str(pattern or "").casefold().strip()
    normalized_scope = str(scope or "global").casefold().strip()
    from entity_quality import REASON_CODES as ENTITY_REASON_CODES
    if rule_type not in {"exact", "prefix", "suffix"} or action not in {"reject", "review"}:
        raise ValueError("alias noise rule must use exact/prefix/suffix and reject/review")
    if str(reason_code or "") not in ENTITY_REASON_CODES:
        raise ValueError("alias noise rule reason code is not supported")
    if not normalized_pattern or len(normalized_pattern) > 80:
        raise ValueError("alias noise rule pattern is invalid")
    if normalized_scope != "global":
        dimension, separator, value = normalized_scope.partition(":")
        if (not separator or dimension not in {"source_scope", "page_type", "forum_role"}
                or not value or len(value) > 40
                or not re.fullmatch(r"[a-z0-9_.-]+", value)):
            raise ValueError("alias noise rule scope is invalid")
    now = utc_now_iso()
    with get_db() as db:
        db.execute("""INSERT INTO alias_noise_rules
          (rule_version,rule_type,normalized_pattern,scope,action,reason_code,enabled,
           analyst_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(rule_type,normalized_pattern,scope) DO UPDATE SET
           rule_version=excluded.rule_version,action=excluded.action,
           reason_code=excluded.reason_code,enabled=excluded.enabled,
           analyst_id=excluded.analyst_id,updated_at=excluded.updated_at""",
          (str(rule_version)[:80], rule_type, normalized_pattern, normalized_scope[:80],
           action, str(reason_code or "analyst_rule")[:80], int(bool(enabled)),
           str(analyst_id or "analyst")[:80], now, now))
        return int(db.execute("""SELECT id FROM alias_noise_rules
          WHERE rule_type=? AND normalized_pattern=? AND scope=?""",
          (rule_type, normalized_pattern, normalized_scope[:80])).fetchone()[0])


_ENTITY_EXPANSION_ROLES = {
    "profile", "thread", "thread_page", "section", "about", "contact",
    "pgp", "mirrors", "faq", "rules",
}
_ENTITY_EXPANSION_VALUE = {
    "profile": 0.95, "pgp": 0.90, "contact": 0.82, "thread": 0.80,
    "thread_page": 0.72, "section": 0.62, "mirrors": 0.58,
    "about": 0.52, "faq": 0.45, "rules": 0.40,
}
_ENTITY_EXPANSION_TERMINAL_RESULTS = frozenset({
    "APPROVAL_SAFETY_BLOCKED", "APPROVAL_REVALIDATION_ERROR",
    "DESTINATION_FILTERED", "DESTINATION_SOFT_DEAD",
    "DESTINATION_USEFUL_VERIFIED", "DESTINATION_VERIFIED_NO_YIELD",
    "DESTINATION_VERIFIED_DUPLICATE",
})


def persist_entity_expansion_plan(parent_url: str, plan: dict, *, actor_id: int | None = None,
                                  site_card_id: int | None = None,
                                  parent_evidence_type: str | None = None) -> list[int]:
    """Persist a pure planner result as proposal-only review work."""
    if not isinstance(plan, dict) or not plan.get("proposal_only") or plan.get("network_performed"):
        raise ValueError("entity expansion persistence requires a pure proposal-only plan")
    host = (urlsplit(parent_url or "").hostname or "").casefold()
    if not host.endswith(".onion"):
        return []
    caps = plan.get("caps") if isinstance(plan.get("caps"), dict) else {}
    host_budget = max(1, min(int(caps.get("per_host") or 10), 10))
    resource_budget = max(1, min(int(caps.get("per_resource") or 1), 1))
    now = utc_now_iso()
    stored: list[int] = []
    with get_db() as db:
        for proposal in (plan.get("proposals") or [])[:host_budget]:
            if not isinstance(proposal, dict):
                continue
            role = str(proposal.get("role") or "")
            proposed_url = str(proposal.get("url") or "")[:2048]
            resource_identity = str(proposal.get("resource_identity") or "")[:500]
            if (role not in _ENTITY_EXPANSION_ROLES or not proposed_url or not resource_identity
                    or (urlsplit(proposed_url).hostname or "").casefold() != host):
                continue
            key_material = f"{canonical_url_identity(parent_url)}\n{resource_identity}"
            proposal_key = "expansion:" + hashlib.sha256(
                key_material.encode("utf-8", "ignore")).hexdigest()
            db.execute("""INSERT INTO entity_expansion_proposals
              (proposal_key,actor_id,site_card_id,parent_url,parent_evidence_type,onion_host,
               proposed_url,route_role,resource_family,resource_identity,reason_code,
               expected_value,novelty_score,host_budget,resource_budget,safety_state,
               decision_mode,status,created_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
              ON CONFLICT(proposal_key) DO UPDATE SET
               actor_id=COALESCE(entity_expansion_proposals.actor_id,excluded.actor_id),
               site_card_id=COALESCE(entity_expansion_proposals.site_card_id,excluded.site_card_id),
               parent_evidence_type=COALESCE(excluded.parent_evidence_type,
                 entity_expansion_proposals.parent_evidence_type),
               expected_value=MAX(entity_expansion_proposals.expected_value,excluded.expected_value),
               novelty_score=MAX(entity_expansion_proposals.novelty_score,excluded.novelty_score),
               updated_at=excluded.updated_at""",
              (proposal_key, actor_id, site_card_id, parent_url,
               str(parent_evidence_type or "verified_public_page")[:80], host, proposed_url,
               role, "forum" if role in {"thread", "thread_page", "section"} else "entity",
               resource_identity, str(proposal.get("reason_code") or "BOUNDED_PUBLIC_ROUTE")[:80],
               _ENTITY_EXPANSION_VALUE.get(role, 0.4), 1.0, host_budget, resource_budget,
               "policy_allowed_unverified_destination", "proposal_only", "proposed", now, now))
            proposal_id = int(db.execute(
                "SELECT id FROM entity_expansion_proposals WHERE proposal_key=?", (proposal_key,)).fetchone()[0])
            stored.append(proposal_id)
    return stored


def get_entity_expansion_proposals(*, status: str | None = None,
                                   actor_id: int | None = None,
                                   search: str | None = None,
                                   limit: int = 300) -> list[dict]:
    where = ["1=1"]
    params: list[Any] = []
    if status and status != "all":
        where.append("ep.status=?")
        params.append(str(status))
    if actor_id is not None:
        where.append("ep.actor_id=?")
        params.append(int(actor_id))
    if search:
        where.append("(ep.route_role LIKE ? OR ep.reason_code LIKE ? OR COALESCE(a.normalized_alias,'') LIKE ? OR COALESCE(sc.display_name,'') LIKE ?)")
        needle = f"%{str(search).casefold().strip()}%"
        params.extend([needle, needle, needle, needle])
    params.append(max(1, min(int(limit or 300), 1000)))
    with get_db() as db:
        return [dict(row) for row in db.execute(f"""SELECT ep.*,
          a.display_alias actor_alias,COALESCE(sc.analyst_title,sc.display_name) site_card_name
          FROM entity_expansion_proposals ep LEFT JOIN actors a ON a.id=ep.actor_id
          LEFT JOIN site_cards sc ON sc.id=ep.site_card_id
          WHERE {' AND '.join(where)}
          ORDER BY CASE ep.status WHEN 'proposed' THEN 0 WHEN 'approved' THEN 1
            WHEN 'enqueued' THEN 2 ELSE 3 END,ep.expected_value DESC,ep.created_at DESC LIMIT ?""",
          tuple(params))]


def decide_entity_expansion_proposal(proposal_id: int, decision: str, *,
                                     analyst_id: str | None = None,
                                     reason: str | None = None,
                                     enqueue_approved: bool = True) -> bool:
    """Serialize one analyst decision with current-policy validation and enqueue.

    The transaction contains only local database work and the pure policy
    validator.  No intermediate ``approved`` state is committed, so a crash
    cannot strand work and concurrent approve/reject requests have one durable
    order.  A rejection committed first can never be overwritten by approval.
    """
    normalized = str(decision or "").strip().casefold()
    if normalized not in {"approve", "reject"}:
        raise ValueError("entity expansion decision must be approve or reject")
    now = utc_now_iso()
    with get_db() as db:
        _begin_immediate(db, "entity_expansion_decision", str(analyst_id or "analyst"))
        row = db.execute("SELECT * FROM entity_expansion_proposals WHERE id=?",
                         (int(proposal_id),)).fetchone()
        if not row:
            return False
        status = str(row["status"] or "proposed")
        if status == "rejected":
            return normalized == "reject"
        if status == "enqueued":
            return normalized == "approve"
        if status == "completed":
            return False
        if status not in {"proposed", "approved"}:
            return False

        analyst_value = str(analyst_id or "analyst")[:80]
        reason_value = str(reason or "")[:240] or None
        if normalized == "reject":
            changed = db.execute("""UPDATE entity_expansion_proposals
              SET status='rejected',decision_mode='analyst',analyst_id=?,analyst_reason=?,
              decided_at=COALESCE(decided_at,?),updated_at=?
              WHERE id=? AND status IN ('proposed','approved')""",
              (analyst_value, reason_value, now, now, int(proposal_id))).rowcount
            return changed == 1

        proposal = dict(row)
        if not enqueue_approved:
            # Proposal-only callers keep a reviewable state; they never create a
            # half-finished approval that the UI cannot recover.
            return True

        def current_url_row(value: str) -> dict:
            canonical = canonical_url_identity(value)
            found = db.execute("""SELECT * FROM onion_urls WHERE url=? OR canonical_url=?
              ORDER BY CASE WHEN url=? THEN 0 ELSE 1 END,id LIMIT 1""",
              (value, canonical, value)).fetchone()
            return dict(found) if found else {}

        parent = current_url_row(str(proposal["parent_url"]))
        destination = current_url_row(str(proposal["proposed_url"]))
        try:
            from entity_expansion import revalidate_entity_expansion_proposal
            revalidation = revalidate_entity_expansion_proposal(
                parent, proposal, destination_page=destination)
            if _get_adult_memory_decision_db(db, str(proposal["proposed_url"])) == "blocked":
                revalidation = {"allowed": False, "reason_code": "DESTINATION_POLICY_BLOCKED"}
        except Exception:
            revalidation = {"allowed": False, "reason_code": "APPROVAL_REVALIDATION_ERROR"}
        if not revalidation.get("allowed"):
            reason_code = str(revalidation.get("reason_code") or
                              "APPROVAL_REVALIDATION_ERROR")[:80]
            result_code = ("APPROVAL_REVALIDATION_ERROR"
                           if reason_code == "APPROVAL_REVALIDATION_ERROR"
                           else "APPROVAL_SAFETY_BLOCKED")
            changed = db.execute("""UPDATE entity_expansion_proposals SET status='completed',
              decision_mode='analyst',analyst_id=?,analyst_reason=?,decided_at=COALESCE(decided_at,?),
              result_code=?,result_safe_metadata_json=?,completed_at=?,updated_at=?
              WHERE id=? AND status IN ('proposed','approved')""",
              (analyst_value, reason_value, now, result_code,
               json.dumps({"reason_code": reason_code}, sort_keys=True), now, now,
               int(proposal_id))).rowcount
            return changed == 1

        normalized_url = str(revalidation.get("normalized_url") or proposal["proposed_url"])
        normalized_host = (urlsplit(normalized_url).hostname or "").casefold()
        enqueued_url_id, _existing_url = _insert_or_update_onion_url_db(
            db, normalized_url, onion_domain=normalized_host,
            source_url=str(proposal["parent_url"]),
            source_type="entity_expansion_analyst",
            depth=min(int(parent.get("depth") or 0) + 1, 99), status="queued", now=now)
        changed = db.execute("""UPDATE entity_expansion_proposals SET status='enqueued',
          decision_mode='analyst',analyst_id=?,analyst_reason=?,decided_at=COALESCE(decided_at,?),
          enqueued_onion_url_id=?,result_code='QUEUED_AFTER_ANALYST_APPROVAL',
          result_safe_metadata_json='{}',completed_at=NULL,updated_at=?
          WHERE id=? AND status IN ('proposed','approved')""",
          (analyst_value, reason_value, now, int(enqueued_url_id), now,
           int(proposal_id))).rowcount
        return changed == 1


def _safe_entity_expansion_result_metadata(metadata: dict | None) -> dict:
    """Retain bounded enums/counts only; never persist page or identifier text."""
    source = metadata if isinstance(metadata, dict) else {}
    safe: dict[str, Any] = {}
    for key in ("verified", "card_ready", "relevant", "duplicate"):
        if key in source:
            safe[key] = bool(source[key])
    for key in ("response_status", "indicator_count", "exposure_count", "actor_count"):
        if key in source:
            try:
                safe[key] = max(0, min(int(source[key]), 1_000_000))
            except (TypeError, ValueError):
                continue
    for key in ("content_quality", "page_type", "safety_state"):
        value = str(source.get(key) or "").strip().casefold()
        if value and re.fullmatch(r"[a-z0-9_.:-]{1,80}", value):
            safe[key] = value
    return safe


def complete_entity_expansion_for_url(onion_url_id: int, result_code: str, *,
                                      safe_metadata: dict | None = None,
                                      content_hash: str | None = None) -> int:
    """Close analyst-approved proposals after destination verification.

    Matching is anchored to the URL row captured at enqueue.  Canonical URL
    fallback exists only for proposals enqueued before that migration.  The
    stored result is reason-coded metadata; fetched text and identifiers are
    never accepted by this boundary.
    """
    normalized_result = str(result_code or "").strip().upper()
    if normalized_result not in _ENTITY_EXPANSION_TERMINAL_RESULTS:
        raise ValueError("invalid entity expansion terminal result")
    metadata = _safe_entity_expansion_result_metadata(safe_metadata)
    now = utc_now_iso()
    with get_db() as db:
        url_row = db.execute(
            "SELECT id,url,canonical_url,onion_domain FROM onion_urls WHERE id=?",
            (int(onion_url_id),)).fetchone()
        if not url_row:
            return 0
        if (content_hash and normalized_result in {
                "DESTINATION_USEFUL_VERIFIED", "DESTINATION_VERIFIED_NO_YIELD"}):
            duplicate = db.execute("""SELECT 1 FROM onion_urls
              WHERE id<>? AND content_hash=? AND verification_state='verified' LIMIT 1""",
              (int(onion_url_id), str(content_hash))).fetchone()
            if duplicate:
                normalized_result = "DESTINATION_VERIFIED_DUPLICATE"
                metadata["duplicate"] = True
        rows = list(db.execute("""SELECT id,proposed_url,enqueued_onion_url_id
          FROM entity_expansion_proposals
          WHERE status IN ('approved','enqueued') AND
            (enqueued_onion_url_id=? OR (enqueued_onion_url_id IS NULL AND onion_host=?))""",
          (int(onion_url_id), str(url_row["onion_domain"] or ""))))
        canonical = str(url_row["canonical_url"] or canonical_url_identity(str(url_row["url"])))
        proposal_ids = [int(row["id"]) for row in rows
                        if int(row["enqueued_onion_url_id"] or 0) == int(onion_url_id)
                        or (row["enqueued_onion_url_id"] is None
                            and canonical_url_identity(str(row["proposed_url"])) == canonical)]
        if not proposal_ids:
            return 0
        marks = ",".join("?" for _ in proposal_ids)
        changed = db.execute(f"""UPDATE entity_expansion_proposals SET status='completed',
          result_code=?,result_safe_metadata_json=?,completed_at=?,updated_at=?
          WHERE id IN ({marks}) AND status IN ('approved','enqueued')""",
          (normalized_result, json.dumps(metadata, sort_keys=True, separators=(",", ":")),
           now, now, *proposal_ids)).rowcount
        return int(changed)


def get_entity_expansion_metrics() -> dict:
    with get_db() as db:
        counts = {str(row[0]): int(row[1]) for row in db.execute(
            "SELECT status,COUNT(*) FROM entity_expansion_proposals GROUP BY status")}
        reasons = {str(row[0]): int(row[1]) for row in db.execute("""SELECT reason_code,COUNT(*)
          FROM entity_expansion_proposals GROUP BY reason_code ORDER BY COUNT(*) DESC,reason_code LIMIT 20""")}
        roles = {str(row[0]): int(row[1]) for row in db.execute("""SELECT route_role,COUNT(*)
          FROM entity_expansion_proposals GROUP BY route_role ORDER BY COUNT(*) DESC,route_role""")}
        oldest = db.execute("""SELECT MIN(created_at) FROM entity_expansion_proposals
          WHERE status='proposed'""").fetchone()[0]
        results = {str(row[0]): int(row[1]) for row in db.execute("""SELECT result_code,COUNT(*)
          FROM entity_expansion_proposals WHERE result_code IS NOT NULL GROUP BY result_code""")}
        accepted = int(db.execute("""SELECT COUNT(*) FROM entity_expansion_proposals
          WHERE decision_mode='analyst' AND decided_at IS NOT NULL AND status!='rejected'""").fetchone()[0])
    completed = counts.get("completed", 0)
    useful = results.get("DESTINATION_USEFUL_VERIFIED", 0)
    no_yield = results.get("DESTINATION_VERIFIED_NO_YIELD", 0)
    duplicate = results.get("DESTINATION_VERIFIED_DUPLICATE", 0)
    filtered = results.get("DESTINATION_FILTERED", 0)
    soft_dead = results.get("DESTINATION_SOFT_DEAD", 0)
    return {"statuses": counts, "reasons": reasons, "roles": roles, "results": results,
            "proposed": counts.get("proposed", 0), "accepted": accepted,
            "completed": completed, "useful": useful, "no_yield": no_yield,
            "duplicate": duplicate, "filtered": filtered, "soft_dead": soft_dead,
            "completion_rate": round(completed / accepted, 4) if accepted else 0.0,
            "useful_rate": round(useful / completed, 4) if completed else 0.0,
            "oldest_pending_at": oldest}


def get_spain_actors(*, watched_only: bool = False, search: str | None = None,
                     limit: int = 300) -> list[dict]:
    where = ["""a.spain_observation_count>0 AND (
      a.watched=1
      OR EXISTS (SELECT 1 FROM actor_identifiers ai WHERE ai.actor_id=a.id
                 AND ai.association_confidence>=0.90
                 AND COALESCE(ai.binding_method,'legacy_unscoped')!='legacy_unscoped')
      OR EXISTS (SELECT 1 FROM actor_observations oq WHERE oq.actor_id=a.id
                 AND oq.analyst_excluded=0 AND oq.spain_priority=1
                 AND oq.evidence_confidence>=0.90
                 AND (oq.evidence_type LIKE '%_post_author'
                      OR oq.evidence_type IN ('corroborated_public_alias','cryptographically_corroborated_alias','profile_page_identity_match',
                         'vendor_page_identity_match','seller_page_identity_match',
                         'linked_vendor_field','linked_seller_field',
                         'marketplace_vendor_card','marketplace_seller_card')))
      OR (SELECT COUNT(DISTINCT orp.url) FROM actor_observations orp
          WHERE orp.actor_id=a.id AND orp.analyst_excluded=0
          AND orp.spain_priority=1 AND orp.evidence_confidence>=0.86)>=2
    )"""]
    params: list[Any] = []
    if watched_only:
        where.append("a.watched=1")
    if search:
        where.append("(a.normalized_alias LIKE ? OR a.onion_host LIKE ? OR a.primary_category LIKE ?)")
        needle = f"%{search.casefold().strip()}%"
        params.extend([needle, needle, needle])
    params.append(limit)
    with get_db() as db:
        return [dict(row) for row in db.execute(f"""SELECT a.*,
          COALESCE((SELECT MAX(confidence_score) FROM actor_connections c
            WHERE c.source_actor_id=a.id OR c.target_actor_id=a.id),0) connection_confidence,
          (SELECT COUNT(*) FROM actor_connections c WHERE (c.source_actor_id=a.id OR c.target_actor_id=a.id)
            AND c.analyst_decision!='not_same') connection_count
          FROM actors a WHERE {' AND '.join(where)}
          ORDER BY a.watched DESC,a.spain_observation_count DESC,a.last_seen DESC LIMIT ?""", tuple(params))]


def get_public_actors(*, watched_only: bool = False, search: str | None = None,
                      limit: int = 300) -> list[dict]:
    """Return public aliases across all eligible pages; no raw identifiers are exposed."""
    where = ["""a.observation_count>0 AND (
      a.watched=1
      OR EXISTS (SELECT 1 FROM actor_identifiers ai WHERE ai.actor_id=a.id
                 AND ai.association_confidence>=0.90
                 AND COALESCE(ai.binding_method,'legacy_unscoped')!='legacy_unscoped')
      OR EXISTS (SELECT 1 FROM actor_observations oq WHERE oq.actor_id=a.id
                 AND oq.analyst_excluded=0 AND oq.evidence_confidence>=0.90
                 AND (oq.evidence_type LIKE '%_post_author'
                      OR oq.evidence_type IN ('corroborated_public_alias','cryptographically_corroborated_alias','profile_page_identity_match',
                         'vendor_page_identity_match','seller_page_identity_match',
                         'linked_vendor_field','linked_seller_field',
                         'marketplace_vendor_card','marketplace_seller_card')))
      OR (SELECT COUNT(DISTINCT orp.url) FROM actor_observations orp
          WHERE orp.actor_id=a.id AND orp.analyst_excluded=0
          AND orp.evidence_confidence>=0.86)>=2
    )"""]
    params: list[Any] = []
    if watched_only:
        where.append("a.watched=1")
    if search:
        where.append("(a.normalized_alias LIKE ? OR a.onion_host LIKE ? OR a.primary_category LIKE ?)")
        needle = f"%{search.casefold().strip()}%"
        params.extend([needle, needle, needle])
    params.append(limit)
    with get_db() as db:
        return [dict(row) for row in db.execute(f"""SELECT a.*,
          COALESCE((SELECT MAX(confidence_score) FROM actor_connections c
            WHERE c.source_actor_id=a.id OR c.target_actor_id=a.id),0) connection_confidence,
          (SELECT COUNT(*) FROM actor_connections c WHERE (c.source_actor_id=a.id OR c.target_actor_id=a.id)
            AND c.analyst_decision!='not_same') connection_count,
          (SELECT COUNT(*) FROM actor_observations o WHERE o.actor_id=a.id
            AND o.analyst_excluded=0 AND o.seller_observation=1) seller_page_count,
          (SELECT COUNT(*) FROM actor_identifiers ai WHERE ai.actor_id=a.id) identifier_count
          FROM actors a WHERE {' AND '.join(where)}
          ORDER BY a.watched DESC,a.spain_observation_count DESC,a.observation_count DESC,
          connection_confidence DESC,a.last_seen DESC LIMIT ?""", tuple(params))]


def get_actor_candidates_by_exact_alias(normalized_alias: str, *,
                                        exclude_actor_id: int | None = None,
                                        limit: int = 50) -> list[dict]:
    """Return exact normalized-alias candidates for local correlation only.

    This intentionally does not use substring, fuzzy, or skeleton matching.
    The returned rows remain candidates and never create a relationship by
    themselves.
    """
    alias = str(normalized_alias or "").casefold().strip()
    if not alias:
        return []
    limit = max(1, min(int(limit or 50), 200))
    with get_db() as db:
        return [dict(row) for row in db.execute("""SELECT id,display_alias,
          normalized_alias,onion_host,confidence_label,observation_count
          FROM actors WHERE normalized_alias=? AND observation_count>0
          AND (? IS NULL OR id!=?)
          ORDER BY observation_count DESC,last_seen DESC,id LIMIT ?""",
          (alias, exclude_actor_id, exclude_actor_id, limit))]


def get_spain_seller_categories() -> list[dict]:
    with get_db() as db:
        return [dict(row) for row in db.execute("""SELECT marketplace_category,COUNT(DISTINCT actor_id) count
          FROM actor_observations WHERE seller_observation=1 AND spain_priority=1
          AND analyst_excluded=0 GROUP BY marketplace_category
          ORDER BY CASE marketplace_category WHEN 'weapons_arms' THEN 0 WHEN 'drugs' THEN 1
          WHEN 'carding' THEN 2 ELSE 3 END,count DESC""")]


def get_spain_sellers(*, watched_only: bool = False, search: str | None = None,
                      spain_flow: str | None = None, category: str | None = None,
                      limit: int = 300) -> list[dict]:
    """Return public marketplace sellers with exact Spain-linked observations."""
    where = ["o.seller_observation=1", "o.spain_priority=1", "o.analyst_excluded=0"]
    params: list[Any] = []
    if watched_only:
        where.append("a.watched=1")
    if spain_flow and spain_flow != "all":
        if spain_flow == "from_or_both":
            where.append("o.spain_flow IN ('from_spain','both')")
        elif spain_flow == "to_or_both":
            where.append("o.spain_flow IN ('to_spain','both')")
        else:
            where.append("o.spain_flow=?")
            params.append(spain_flow)
    if category and category != "all":
        where.append("o.marketplace_category=?")
        params.append(category)
    if search:
        where.append("(a.normalized_alias LIKE ? OR a.onion_host LIKE ? OR o.marketplace_category LIKE ?)")
        needle = f"%{search.casefold().strip()}%"
        params.extend([needle, needle, needle])
    params.append(limit)
    with get_db() as db:
        return [dict(row) for row in db.execute(f"""SELECT a.*,
          COUNT(DISTINCT o.id) seller_page_count,MAX(o.last_seen) seller_last_seen,
          SUM(CASE WHEN o.spain_flow IN ('from_spain','both') THEN 1 ELSE 0 END) from_spain_count,
          SUM(CASE WHEN o.spain_flow IN ('to_spain','both') THEN 1 ELSE 0 END) to_spain_count,
          SUM(CASE WHEN o.marketplace_category='weapons_arms' THEN 1 ELSE 0 END) weapons_page_count,
          (SELECT o2.spain_flow FROM actor_observations o2 WHERE o2.actor_id=a.id
            AND o2.seller_observation=1 AND o2.spain_priority=1 AND o2.analyst_excluded=0
            ORDER BY o2.last_seen DESC,o2.id DESC LIMIT 1) latest_spain_flow,
          (SELECT o2.marketplace_category FROM actor_observations o2 WHERE o2.actor_id=a.id
            AND o2.seller_observation=1 AND o2.spain_priority=1 AND o2.analyst_excluded=0
            ORDER BY o2.last_seen DESC,o2.id DESC LIMIT 1) latest_marketplace_category,
          (SELECT COUNT(*) FROM actor_connections c WHERE
            (c.source_actor_id=a.id OR c.target_actor_id=a.id) AND c.warning_type IS NOT NULL
            AND c.analyst_decision!='not_same') warning_count,
          (SELECT COUNT(*) FROM actor_connections c WHERE
            (c.source_actor_id=a.id OR c.target_actor_id=a.id) AND c.migration_candidate=1
            AND c.analyst_decision!='not_same') migration_count
          FROM actors a JOIN actor_observations o ON o.actor_id=a.id
          WHERE {' AND '.join(where)} GROUP BY a.id
          ORDER BY CASE WHEN SUM(CASE WHEN o.marketplace_category='weapons_arms' THEN 1 ELSE 0 END)>0
            THEN 0 ELSE 1 END,a.watched DESC,MAX(o.last_seen) DESC LIMIT ?""", tuple(params))]


def get_actor_detail(actor_id: int) -> dict | None:
    with get_db() as db:
        actor = db.execute("SELECT * FROM actors WHERE id=?", (actor_id,)).fetchone()
        if not actor:
            return None
        observations = [dict(row) for row in db.execute("""SELECT * FROM actor_observations
          WHERE actor_id=? AND analyst_excluded=0 ORDER BY spain_priority DESC,last_seen DESC""", (actor_id,))]
        aliases = [dict(row) for row in db.execute("""SELECT normalized_alias,display_alias,
          alias_skeleton,first_seen,last_seen,observation_count FROM actor_aliases
          WHERE actor_id=? ORDER BY observation_count DESC,last_seen DESC,id""", (actor_id,))]
        connections = [dict(row) for row in db.execute("""SELECT c.*,
          CASE WHEN c.source_actor_id=? THEN target.id ELSE source.id END other_actor_id,
          CASE WHEN c.source_actor_id=? THEN target.display_alias ELSE source.display_alias END other_alias,
          CASE WHEN c.source_actor_id=? THEN target.onion_host ELSE source.onion_host END other_onion_host,
          CASE WHEN c.source_actor_id=? THEN target.watched ELSE source.watched END other_watched,
          CASE WHEN c.source_actor_id=? THEN target.spain_observation_count
            ELSE source.spain_observation_count END other_spain_observation_count
          FROM actor_connections c JOIN actors source ON source.id=c.source_actor_id
          JOIN actors target ON target.id=c.target_actor_id
          WHERE c.source_actor_id=? OR c.target_actor_id=?
          ORDER BY CASE c.analyst_decision WHEN 'confirmed_same' THEN 0 WHEN 'unreviewed' THEN 1 ELSE 2 END,
          c.confidence_score DESC,c.last_seen DESC""",
          (actor_id, actor_id, actor_id, actor_id, actor_id, actor_id, actor_id))]
        identifiers = [dict(row) for row in db.execute("""SELECT indicator_type,safe_value_label,
          binding_method,source_scope,COUNT(*) count,MAX(last_seen) last_seen
          FROM actor_identifiers WHERE actor_id=?
          GROUP BY indicator_type,safe_value_label,binding_method,source_scope""", (actor_id,))]
        events = [dict(row) for row in db.execute("""SELECT id,connection_id,event_type,
          safe_metadata_json,created_at FROM actor_events WHERE actor_id=?
          ORDER BY created_at DESC,id DESC LIMIT 200""", (actor_id,))]
        candidates = [dict(row) for row in db.execute("""SELECT * FROM actor_candidates
          WHERE actor_id=? ORDER BY last_seen DESC,id DESC LIMIT 200""", (actor_id,))]
        expansion = [dict(row) for row in db.execute("""SELECT * FROM entity_expansion_proposals
          WHERE actor_id=? ORDER BY created_at DESC,id DESC LIMIT 200""", (actor_id,))]
    return {"actor": dict(actor), "aliases": aliases, "observations": observations,
            "connections": connections, "identifiers": identifiers, "events": events,
            "candidates": candidates, "expansion": expansion}


def search_entity_intelligence(query: str, *, limit: int = 50) -> dict:
    """Search safe entity/card labels without returning restricted page content."""
    needle = f"%{str(query or '').casefold().strip()}%"
    if needle == "%%":
        return {"actors": [], "site_cards": [], "candidates": []}
    limit = max(1, min(int(limit or 50), 200))
    restricted = ("adult_filtered", "adult_restricted", "severe_abuse_risk")
    marks = ",".join("?" for _ in restricted)
    with get_db() as db:
        actors = [dict(row) for row in db.execute("""SELECT id,display_alias,normalized_alias,
          onion_host,confidence_label,watched,canonical_profile_identity,last_seen
          FROM actors WHERE observation_count>0 AND
          (normalized_alias LIKE ? OR onion_host LIKE ? OR COALESCE(canonical_profile_identity,'') LIKE ?)
          ORDER BY watched DESC,last_seen DESC LIMIT ?""", (needle, needle, needle, limit))]
        cards = [dict(row) for row in db.execute(f"""SELECT id,
          COALESCE(analyst_title,display_name) display_name,onion_host,primary_category,
          risk_level,last_checked_at FROM site_cards WHERE primary_category NOT IN ({marks})
          AND storage_policy!='discard' AND (COALESCE(analyst_title,'') LIKE ?
            OR COALESCE(display_name,'') LIKE ? OR onion_host LIKE ?
            OR COALESCE(analyst_notes,'') LIKE ?)
          ORDER BY last_checked_at DESC LIMIT ?""",
          (*restricted, needle, needle, needle, needle, limit))]
        candidates = [dict(row) for row in db.execute("""SELECT id,actor_id,display_alias,
          normalized_alias,onion_host,effective_state,evidence_confidence,last_seen
          FROM actor_candidates WHERE normalized_alias LIKE ? OR onion_host LIKE ?
          OR COALESCE(profile_identity,'') LIKE ?
          ORDER BY evidence_confidence DESC,last_seen DESC LIMIT ?""",
          (needle, needle, needle, limit))]
    return {"actors": actors, "site_cards": cards, "candidates": candidates}


_DEEP_PROVIDER_QUERY_TYPES = frozenset({"pgp_fingerprint", "clearnet_domain"})
_DEEP_PROVIDER_STATUSES = frozenset({
    "pending", "running", "complete", "empty", "error", "timeout",
    "rate_limited", "disabled",
})
_DEEP_PROVIDER_TERMINAL_STATUSES = _DEEP_PROVIDER_STATUSES - {"pending", "running"}
_DEEP_PROVIDER_MIN_CACHE_TTL_SECONDS = 300
_DEEP_PROVIDER_MAX_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
_DEEP_PROVIDER_METADATA_CODE_KEYS = frozenset({
    "record_type", "result_state", "registrar", "registry", "country_code",
    "network_name", "key_algorithm", "candidate_type", "match_type",
})
_DEEP_PROVIDER_METADATA_BOOL_KEYS = frozenset({
    "dnssec", "revoked", "expired", "authoritative",
})
_DEEP_PROVIDER_METADATA_INT_KEYS = frozenset({
    "asn", "key_bits", "record_count", "certificate_count",
})
_DEEP_PROVIDER_METADATA_TIME_KEYS = frozenset({
    "source_updated_at", "not_before", "not_after",
    "key_created_at", "key_expires_at",
})


def _deep_provider_code(value: object, *, field: str) -> str:
    code = _quality_safe_code(value)
    if not code:
        raise ValueError(f"{field} must be a bounded metadata code")
    return code


def _deep_provider_iso(value: object, *, field: str) -> str:
    raw = str(value or "").strip()
    if not raw or len(raw) > 48:
        raise ValueError(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_deep_provider_query(query_type: object, query_value: object) -> tuple[str, str]:
    normalized_type = _deep_provider_code(query_type, field="query_type")
    if normalized_type not in _DEEP_PROVIDER_QUERY_TYPES:
        raise ValueError("unsupported Deep Discovery provider query type")
    raw = str(query_value or "").strip()
    if not raw or len(raw) > 4096 or any(ord(char) < 32 for char in raw):
        raise ValueError("an exact bounded provider query is required")
    if normalized_type == "pgp_fingerprint":
        fingerprint = re.sub(r"[\s:]+", "", re.sub(r"(?i)^0x", "", raw)).upper()
        if not re.fullmatch(r"(?:[A-F0-9]{40}|[A-F0-9]{64})", fingerprint):
            raise ValueError("PGP provider queries require an exact 40/64-hex fingerprint")
        return normalized_type, fingerprint

    # Providers receive a host only. URLs, credentials, IP literals, local
    # names and onion hosts are never retained as public-domain pivots.
    candidate = raw.casefold().rstrip(".")
    if ("://" in candidate or "/" in candidate or "\\" in candidate
            or "@" in candidate or ":" in candidate or candidate.startswith(".")):
        raise ValueError("domain provider queries require an exact hostname")
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("domain provider query is not valid IDNA") from exc
    if (len(candidate) > 253 or "." not in candidate or candidate.endswith(".onion")
            or candidate in {"localhost", "localhost.localdomain"}
            or re.fullmatch(r"\d+(?:\.\d+){3}", candidate)):
        raise ValueError("domain provider queries require an exact clearnet hostname")
    labels = candidate.split(".")
    if any(not re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)", label) for label in labels):
        raise ValueError("domain provider query is not a valid hostname")
    return normalized_type, candidate


def _deep_provider_query_hash(query_type: str, normalized_query: str) -> str:
    material = f"arachne-deep-provider-query:v1\n{query_type}\n{normalized_query}"
    return "sha256:" + hashlib.sha256(material.encode("utf-8", "strict")).hexdigest()


def _deep_provider_ref_hash(reference: object) -> str | None:
    if reference is None:
        return None
    raw = str(reference).strip()
    if not raw:
        return None
    if len(raw) > 8192 or any(ord(char) < 32 for char in raw):
        raise ValueError("provenance reference is not bounded")
    material = "arachne-deep-provider-provenance:v1\n" + raw
    return "sha256:" + hashlib.sha256(material.encode("utf-8", "ignore")).hexdigest()


def _sanitize_deep_provider_metadata(value: dict | None) -> dict:
    """Keep only bounded public record metadata; never bodies, contacts or URLs."""
    source = value if isinstance(value, dict) else {}
    result: dict[str, Any] = {}
    for key in _DEEP_PROVIDER_METADATA_CODE_KEYS:
        if key in source:
            code = _quality_safe_code(source[key])
            if code:
                result[key] = code
    for key in _DEEP_PROVIDER_METADATA_BOOL_KEYS:
        if key in source:
            result[key] = bool(source[key])
    for key in _DEEP_PROVIDER_METADATA_INT_KEYS:
        if key in source:
            try:
                result[key] = max(0, min(int(source[key]), 10_000_000_000))
            except (TypeError, ValueError):
                continue
    for key in _DEEP_PROVIDER_METADATA_TIME_KEYS:
        if key not in source or not source[key]:
            continue
        try:
            result[key] = _deep_provider_iso(source[key], field=key)
        except ValueError:
            continue
    domains: list[str] = []
    domain_source = source.get("domains")
    if isinstance(domain_source, (list, tuple, set, frozenset)):
        for item in domain_source:
            try:
                _kind, domain = _normalize_deep_provider_query("clearnet_domain", item)
            except ValueError:
                continue
            if domain not in domains:
                domains.append(domain)
            if len(domains) >= 20:
                break
    if domains:
        result["domains"] = domains
    if source.get("pgp_fingerprint"):
        try:
            _kind, fingerprint = _normalize_deep_provider_query(
                "pgp_fingerprint", source["pgp_fingerprint"])
        except ValueError:
            pass
        else:
            result["pgp_fingerprint"] = fingerprint
    return result


def _normalize_deep_provider_result(row: dict, *, now: str) -> dict:
    if not isinstance(row, dict):
        raise ValueError("provider result rows must be mappings")
    query_type, public_identifier = _normalize_deep_provider_query(
        row.get("identifier_type"), row.get("identifier_value"))
    identifier_hash = _deep_provider_query_hash(query_type, public_identifier)
    evidence_type = _deep_provider_code(
        row.get("evidence_type") or "exact_public_record", field="evidence_type")
    provenance_type = _deep_provider_code(
        row.get("provenance_type") or "provider_record", field="provenance_type")
    try:
        confidence = float(row.get("confidence") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("provider evidence confidence must be numeric") from exc
    confidence = max(0.0, min(confidence, 1.0))
    observed_at = None
    if row.get("observed_at"):
        observed_at = _deep_provider_iso(row["observed_at"], field="observed_at")
    retrieved_at = (
        _deep_provider_iso(row["retrieved_at"], field="retrieved_at")
        if row.get("retrieved_at") else now
    )
    return {
        "identifier_type": query_type,
        "identifier_hash": identifier_hash,
        "public_identifier": public_identifier,
        "evidence_type": evidence_type,
        "provenance_type": provenance_type,
        "provenance_ref_hash": _deep_provider_ref_hash(row.get("provenance_ref")),
        "confidence": confidence,
        "support_codes": _quality_safe_code_list(row.get("support_codes"), limit=20),
        "contradiction_codes": _quality_safe_code_list(
            row.get("contradiction_codes"), limit=20),
        "safe_metadata": _sanitize_deep_provider_metadata(row.get("safe_metadata")),
        "observed_at": observed_at,
        "retrieved_at": retrieved_at,
    }


def record_deep_discovery_provider_run(
    provider_name: str,
    query_type: str,
    query_value: str,
    *,
    provider_version: str = "1",
    status: str = "pending",
    job_id: int | None = None,
    deep_discovery_run_id: int | None = None,
    idempotency_key: str | None = None,
    cache_hit: bool = False,
    result_count: int = 0,
    error_code: str | None = None,
    safe_metadata: dict | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
) -> int:
    """Idempotently persist one redacted provider invocation.

    Raw query material is used only to derive ``query_hash`` in-process. It is
    never written to this table or returned by provider-run readers.
    """
    provider = _deep_provider_code(provider_name, field="provider_name")
    version = _deep_provider_code(provider_version, field="provider_version")
    normalized_type, normalized_query = _normalize_deep_provider_query(
        query_type, query_value)
    query_hash = _deep_provider_query_hash(normalized_type, normalized_query)
    normalized_status = _deep_provider_code(status, field="status")
    if normalized_status not in _DEEP_PROVIDER_STATUSES:
        raise ValueError("unsupported provider run status")
    if job_id is None and deep_discovery_run_id is None and not idempotency_key:
        raise ValueError("provider run needs a job, parent run, or idempotency key")
    if idempotency_key is not None:
        scope_hash = _deep_provider_ref_hash(idempotency_key)
        scope = f"external:{scope_hash}"
    else:
        scope = f"job:{int(job_id or 0)}:run:{int(deep_discovery_run_id or 0)}"
    run_material = "\n".join((
        "arachne-deep-provider-run:v1", scope, provider, version,
        normalized_type, query_hash,
    ))
    run_key = "sha256:" + hashlib.sha256(
        run_material.encode("utf-8", "strict")).hexdigest()
    now = utc_now_iso()
    started = _deep_provider_iso(started_at, field="started_at") if started_at else now
    completed = (
        _deep_provider_iso(completed_at, field="completed_at")
        if completed_at else (now if normalized_status in _DEEP_PROVIDER_TERMINAL_STATUSES else None)
    )
    normalized_error = (
        _deep_provider_code(error_code, field="error_code") if error_code else None)
    metadata_json = json.dumps(
        _sanitize_deep_provider_metadata(safe_metadata),
        ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    bounded_count = max(0, min(int(result_count or 0), 1_000_000))
    with get_db() as db:
        db.execute("""INSERT INTO deep_discovery_provider_runs
          (run_key,deep_discovery_run_id,job_id,provider_name,provider_version,
           query_type,query_hash,status,cache_hit,result_count,error_code,
           safe_metadata_json,started_at,completed_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(run_key) DO UPDATE SET
           deep_discovery_run_id=COALESCE(excluded.deep_discovery_run_id,
             deep_discovery_provider_runs.deep_discovery_run_id),
           job_id=COALESCE(excluded.job_id,deep_discovery_provider_runs.job_id),
           status=excluded.status,cache_hit=excluded.cache_hit,
           result_count=excluded.result_count,error_code=excluded.error_code,
           safe_metadata_json=excluded.safe_metadata_json,
           completed_at=COALESCE(excluded.completed_at,
             deep_discovery_provider_runs.completed_at),
           updated_at=excluded.updated_at""",
          (run_key, int(deep_discovery_run_id) if deep_discovery_run_id is not None else None,
           int(job_id) if job_id is not None else None, provider, version,
           normalized_type, query_hash, normalized_status, int(bool(cache_hit)),
           bounded_count, normalized_error, metadata_json, started, completed, now))
        row = db.execute(
            "SELECT id FROM deep_discovery_provider_runs WHERE run_key=?",
            (run_key,)).fetchone()
        return int(row["id"])


def upsert_deep_discovery_provider_evidence(
    provider_run_id: int,
    evidence_rows: list[dict] | tuple[dict, ...],
) -> int:
    """Store bounded normalized public evidence without changing actor/card state."""
    if not isinstance(evidence_rows, (list, tuple)):
        raise ValueError("provider evidence must be a bounded sequence")
    if len(evidence_rows) > 100:
        raise ValueError("provider evidence is capped at 100 rows per write")
    now = utc_now_iso()
    normalized = [_normalize_deep_provider_result(row, now=now) for row in evidence_rows]
    changed = 0
    with get_db() as db:
        if not db.execute(
                "SELECT 1 FROM deep_discovery_provider_runs WHERE id=?",
                (int(provider_run_id),)).fetchone():
            raise ValueError("unknown Deep Discovery provider run")
        for row in normalized:
            key_material = "\n".join((
                str(int(provider_run_id)), row["identifier_hash"], row["evidence_type"],
                row["provenance_type"], row["provenance_ref_hash"] or "",
            ))
            evidence_key = "sha256:" + hashlib.sha256(
                key_material.encode("utf-8", "strict")).hexdigest()
            db.execute("""INSERT INTO deep_discovery_provider_evidence
              (provider_run_id,evidence_key,identifier_type,identifier_hash,
               public_identifier,evidence_type,provenance_type,provenance_ref_hash,
               confidence,support_codes_json,contradiction_codes_json,
               safe_metadata_json,observed_at,retrieved_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
              ON CONFLICT(provider_run_id,evidence_key) DO UPDATE SET
               confidence=MAX(deep_discovery_provider_evidence.confidence,
                 excluded.confidence),
               support_codes_json=excluded.support_codes_json,
               contradiction_codes_json=excluded.contradiction_codes_json,
               safe_metadata_json=excluded.safe_metadata_json,
               observed_at=COALESCE(excluded.observed_at,
                 deep_discovery_provider_evidence.observed_at),
               retrieved_at=excluded.retrieved_at,updated_at=excluded.updated_at""",
              (int(provider_run_id), evidence_key, row["identifier_type"],
               row["identifier_hash"], row["public_identifier"], row["evidence_type"],
               row["provenance_type"], row["provenance_ref_hash"], row["confidence"],
               json.dumps(row["support_codes"], sort_keys=True, separators=(",", ":")),
               json.dumps(row["contradiction_codes"], sort_keys=True, separators=(",", ":")),
               json.dumps(row["safe_metadata"], ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")),
               row["observed_at"], row["retrieved_at"], now))
            changed += 1
    return changed


def get_deep_discovery_provider_runs(
    *,
    job_id: int | None = None,
    deep_discovery_run_id: int | None = None,
    provider_name: str | None = None,
    limit: int = 100,
) -> list[dict]:
    clauses: list[str] = []
    params: list[Any] = []
    if job_id is not None:
        clauses.append("job_id=?")
        params.append(int(job_id))
    if deep_discovery_run_id is not None:
        clauses.append("deep_discovery_run_id=?")
        params.append(int(deep_discovery_run_id))
    if provider_name is not None:
        clauses.append("provider_name=?")
        params.append(_deep_provider_code(provider_name, field="provider_name"))
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    params.append(max(1, min(int(limit or 100), 500)))
    with get_db() as db:
        return [dict(row) for row in db.execute(f"""SELECT * FROM
          deep_discovery_provider_runs{where}
          ORDER BY updated_at DESC,id DESC LIMIT ?""", tuple(params))]


def get_deep_discovery_provider_evidence(
    provider_run_id: int, *, limit: int = 100
) -> list[dict]:
    bounded = max(1, min(int(limit or 100), 500))
    with get_db() as db:
        return [dict(row) for row in db.execute("""SELECT * FROM
          deep_discovery_provider_evidence WHERE provider_run_id=?
          ORDER BY confidence DESC,retrieved_at DESC,id LIMIT ?""",
          (int(provider_run_id), bounded))]


def put_deep_discovery_provider_cache(
    provider_name: str,
    query_type: str,
    query_value: str,
    normalized_results: list[dict] | tuple[dict, ...],
    *,
    provider_version: str = "1",
    status: str = "complete",
    ttl_seconds: int = 24 * 60 * 60,
) -> str:
    """Idempotently cache only normalized public metadata for at most seven days."""
    provider = _deep_provider_code(provider_name, field="provider_name")
    version = _deep_provider_code(provider_version, field="provider_version")
    normalized_type, normalized_query = _normalize_deep_provider_query(
        query_type, query_value)
    normalized_status = _deep_provider_code(status, field="status")
    if normalized_status not in _DEEP_PROVIDER_TERMINAL_STATUSES:
        raise ValueError("cache entries require a terminal provider status")
    if not isinstance(normalized_results, (list, tuple)) or len(normalized_results) > 100:
        raise ValueError("provider cache is capped at 100 normalized rows")
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat().replace("+00:00", "Z")
    safe_rows = [_normalize_deep_provider_result(row, now=now)
                 for row in normalized_results]
    query_hash = _deep_provider_query_hash(normalized_type, normalized_query)
    key_material = "\n".join((
        "arachne-deep-provider-cache:v1", provider, version,
        normalized_type, query_hash,
    ))
    cache_key = "sha256:" + hashlib.sha256(
        key_material.encode("utf-8", "strict")).hexdigest()
    try:
        requested_ttl = int(ttl_seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError("cache TTL must be an integer") from exc
    bounded_ttl = max(
        _DEEP_PROVIDER_MIN_CACHE_TTL_SECONDS,
        min(requested_ttl, _DEEP_PROVIDER_MAX_CACHE_TTL_SECONDS))
    expires_at = (now_dt + timedelta(seconds=bounded_ttl)
                  ).isoformat().replace("+00:00", "Z")
    payload_rows = [{
        "identifier_type": row["identifier_type"],
        "identifier_hash": row["identifier_hash"],
        "public_identifier": row["public_identifier"],
        "evidence_type": row["evidence_type"],
        "provenance_type": row["provenance_type"],
        "provenance_ref_hash": row["provenance_ref_hash"],
        "confidence": row["confidence"],
        "support_codes": row["support_codes"],
        "contradiction_codes": row["contradiction_codes"],
        "safe_metadata": row["safe_metadata"],
        "observed_at": row["observed_at"],
        "retrieved_at": row["retrieved_at"],
    } for row in safe_rows]
    payload = json.dumps(
        payload_rows, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    with get_db() as db:
        db.execute("""INSERT INTO deep_discovery_provider_cache
          (cache_key,provider_name,provider_version,query_type,query_hash,status,
           result_count,normalized_result_json,stored_at,expires_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(cache_key) DO UPDATE SET status=excluded.status,
           result_count=excluded.result_count,
           normalized_result_json=excluded.normalized_result_json,
           stored_at=excluded.stored_at,expires_at=excluded.expires_at,
           updated_at=excluded.updated_at""",
          (cache_key, provider, version, normalized_type, query_hash,
           normalized_status, len(payload_rows), payload, now, expires_at, now))
    return cache_key


def get_deep_discovery_provider_cache(
    provider_name: str,
    query_type: str,
    query_value: str,
    *,
    provider_version: str = "1",
    now_iso: str | None = None,
) -> dict | None:
    provider = _deep_provider_code(provider_name, field="provider_name")
    version = _deep_provider_code(provider_version, field="provider_version")
    normalized_type, normalized_query = _normalize_deep_provider_query(
        query_type, query_value)
    query_hash = _deep_provider_query_hash(normalized_type, normalized_query)
    now = _deep_provider_iso(now_iso, field="now_iso") if now_iso else utc_now_iso()
    with get_db() as db:
        row = db.execute("""SELECT * FROM deep_discovery_provider_cache
          WHERE provider_name=? AND provider_version=? AND query_type=?
          AND query_hash=? AND expires_at>?""",
          (provider, version, normalized_type, query_hash, now)).fetchone()
    if not row:
        return None
    result = dict(row)
    try:
        result["normalized_results"] = json.loads(
            result.pop("normalized_result_json") or "[]")
    except (TypeError, ValueError):
        return None
    return result


def purge_expired_deep_discovery_provider_cache(
    *, limit: int = 500, now_iso: str | None = None
) -> int:
    bounded = max(1, min(int(limit or 500), 5000))
    now = _deep_provider_iso(now_iso, field="now_iso") if now_iso else utc_now_iso()
    with get_db() as db:
        return int(db.execute("""DELETE FROM deep_discovery_provider_cache
          WHERE cache_key IN (SELECT cache_key FROM deep_discovery_provider_cache
            WHERE expires_at<=? ORDER BY expires_at,cache_key LIMIT ?)""",
          (now, bounded)).rowcount or 0)


def get_deep_discovery_provider_pivots(
    actor_id: int, *, limit: int = 8
) -> list[dict]:
    """Resolve exact, structurally bound public pivots for provider workers.

    The returned query value is intentionally available only to the in-process
    worker. Provider-run/cache persistence hashes the query, and UI/report APIs
    do not expose this resolver. Page-wide links, aliases, restricted pages and
    legacy unscoped identifiers are excluded.
    """
    bounded = max(1, min(int(limit or 8), 20))
    allowed_types = ("pgp_fingerprint", "clearnet_url")
    marks = ",".join("?" for _ in allowed_types)
    with get_db() as db:
        rows = list(db.execute(f"""SELECT ai.indicator_type,ai.value_hash,
          ai.association_confidence,ai.binding_method,ao.url,
          ao.evidence_confidence,i.normalized_value,i.confidence
          FROM actor_identifiers ai
          JOIN actor_identifier_observations aio ON aio.actor_identifier_id=ai.id
          JOIN actor_observations ao ON ao.id=aio.observation_id
          JOIN onion_urls ou ON ou.url=ao.url
          JOIN indicator_links il ON il.source_ref=ao.url
          JOIN indicators i ON i.id=il.indicator_id
          WHERE ai.actor_id=? AND ai.indicator_type IN ({marks})
          AND i.indicator_type=ai.indicator_type
          AND ai.binding_method='same_structural_container'
          AND ai.association_confidence>=0.90
          AND ao.analyst_excluded=0 AND ao.evidence_confidence>=0.90
          AND i.confidence>=0.90
          AND ou.verification_state='verified'
          AND COALESCE(ou.destination_html_evidence_version,0)>=?
          AND COALESCE(ou.storage_policy,'')='safe_summary'
          AND COALESCE(ou.queue_policy,'normal')!='blocked'
          AND COALESCE(ou.primary_category,'unknown') NOT IN
            ('adult_filtered','adult_restricted','severe_abuse_risk')
          AND COALESCE(ou.safety_state,'safe') NOT IN
            ('filtered','discarded','metadata_only')
          ORDER BY ai.association_confidence DESC,i.confidence DESC,
            ao.evidence_confidence DESC,ai.id,il.id""",
          (int(actor_id), *allowed_types, DESTINATION_HTML_EVIDENCE_VERSION)))
    pivots: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        indicator_type = str(row["indicator_type"])
        normalized_value = str(row["normalized_value"] or "")
        local_digest = hashlib.sha256(
            f"{indicator_type}:{normalized_value}".encode("utf-8", "ignore")
        ).hexdigest()
        bound_value = f"local_sha256:{local_digest}"
        expected_at_rest_hash = hashlib.sha256(
            f"{indicator_type}:{bound_value}".encode("utf-8", "ignore")
        ).hexdigest()
        if expected_at_rest_hash != str(row["value_hash"] or ""):
            continue
        try:
            if indicator_type == "pgp_fingerprint":
                query_type, query_value = _normalize_deep_provider_query(
                    "pgp_fingerprint", normalized_value)
            else:
                parsed = urlsplit(normalized_value)
                if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                        or parsed.username or parsed.password):
                    continue
                query_type, query_value = _normalize_deep_provider_query(
                    "clearnet_domain", parsed.hostname)
        except ValueError:
            continue
        key = (query_type, query_value)
        if key in seen:
            continue
        seen.add(key)
        confidence = min(
            float(row["association_confidence"] or 0),
            float(row["evidence_confidence"] or 0),
            float(row["confidence"] or 0),
        )
        pivots.append({
            "query_type": query_type,
            "query_value": query_value,
            "identifier_type": indicator_type,
            "confidence": round(confidence, 3),
            "source_hash": _deep_provider_ref_hash(row["url"]),
            "binding_method": "same_structural_container",
        })
        if len(pivots) >= bounded:
            break
    return pivots


def _deep_discovery_anchor_hash(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8", "strict")).hexdigest()


def create_deep_discovery_job(actor_id: int, site_card_id: int | None, eligibility_score: float,
                              trigger_reason: str, anchor_snapshot: dict,
                              *, auto_queued: bool = True) -> int | None:
    """Queue one conservative Deep Discovery job per actor/card anchor.

    The job stores only a safe immutable anchor snapshot. It does not fetch
    anything by itself; workers/providers can process it later with their own
    bounded rules.
    """
    actor_id = int(actor_id)
    card_id = int(site_card_id or 0)
    now = utc_now_iso()
    payload = json.dumps(anchor_snapshot or {}, ensure_ascii=False, sort_keys=True)
    anchor_hash = _deep_discovery_anchor_hash(payload)
    with get_db() as db:
        # Serialize the get-or-create decision. The UNIQUE constraint remains a
        # backstop, while this transaction prevents concurrent creators from
        # both observing an absent/stale job revision.
        _begin_immediate(db, "enqueue_deep_discovery", None)
        existing = db.execute("""SELECT id,status,eligibility_score,anchor_snapshot_json,
          anchor_hash,anchor_revision FROM deep_discovery_jobs
          WHERE actor_id=? AND site_card_id=?""", (actor_id, card_id)).fetchone()
        if existing:
            existing_hash = str(existing["anchor_hash"] or "")
            if not existing_hash:
                existing_hash = _deep_discovery_anchor_hash(
                    str(existing["anchor_snapshot_json"] or "{}"))
            score = max(float(eligibility_score or 0),
                        float(existing["eligibility_score"] or 0))
            if existing_hash == anchor_hash:
                db.execute("""UPDATE deep_discovery_jobs SET eligibility_score=?,trigger_reason=?,
                  anchor_hash=?,updated_at=? WHERE id=?""",
                  (score, str(trigger_reason or "")[:240], anchor_hash, now, existing["id"]))
            elif existing["status"] == "claimed":
                # Preserve the immutable snapshot held by the active worker. The
                # newly observed anchor is promoted and requeued on completion.
                db.execute("""UPDATE deep_discovery_jobs SET eligibility_score=?,trigger_reason=?,
                  pending_anchor_snapshot_json=?,pending_anchor_hash=?,updated_at=? WHERE id=?""",
                  (score, str(trigger_reason or "")[:240], payload, anchor_hash,
                   now, existing["id"]))
            else:
                db.execute("""UPDATE deep_discovery_jobs SET eligibility_score=?,trigger_reason=?,
                  anchor_snapshot_json=?,anchor_hash=?,anchor_revision=COALESCE(anchor_revision,1)+1,
                  status='queued',attempts=0,next_retry_at=NULL,last_error=NULL,error_type=NULL,
                  failed_at=NULL,dead_letter_reason=NULL,completed_at=NULL,claimed_by=NULL,
                  claimed_at=NULL,pending_anchor_snapshot_json=NULL,pending_anchor_hash=NULL,
                  updated_at=? WHERE id=?""",
                  (score, str(trigger_reason or "")[:240], payload, anchor_hash,
                   now, existing["id"]))
            return int(existing["id"])
        db.execute("""INSERT INTO deep_discovery_jobs
          (actor_id,site_card_id,status,priority,eligibility_score,trigger_reason,
           anchor_snapshot_json,anchor_hash,anchor_revision,auto_queued,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
          (actor_id, card_id, "queued", 10, float(eligibility_score or 0),
           str(trigger_reason or "")[:240], payload, anchor_hash, 1,
           int(bool(auto_queued)), now, now))
        return int(db.execute("SELECT last_insert_rowid()").fetchone()[0])


def claim_next_deep_discovery_job(worker_id: str | None = None,
                                  claim_timeout_minutes: int = 45) -> dict | None:
    """Atomically claim one local Deep Discovery job.

    Claim ownership commits before local correlation begins. This mirrors the
    fetch/verify/card assembly-line lifecycle and makes multiple worker
    processes safe without introducing a second scheduler.
    """
    worker_id = worker_id or f"deep_discovery:{os.getpid()}"
    now = utc_now_iso()
    stale_before = (
        datetime.now(timezone.utc) - timedelta(minutes=max(5, claim_timeout_minutes))
    ).isoformat().replace("+00:00", "Z")
    with get_db() as db:
        _begin_immediate(db, "claim_deep_discovery", worker_id)
        if worker_claims_paused(db):
            return None
        db.execute("""UPDATE deep_discovery_jobs SET status='retry',claimed_at=NULL,
          claimed_by=NULL,next_retry_at=COALESCE(next_retry_at,?),updated_at=?
          WHERE status='claimed' AND claimed_at IS NOT NULL AND claimed_at<?""",
          (now, now, stale_before))
        row = db.execute("""SELECT id FROM deep_discovery_jobs
          WHERE status IN ('queued','retry')
          AND (next_retry_at IS NULL OR next_retry_at<=?)
          ORDER BY priority DESC,eligibility_score DESC,created_at,id LIMIT 1""",
          (now,)).fetchone()
        if not row:
            return None
        changed = db.execute("""UPDATE deep_discovery_jobs SET status='claimed',
          claimed_at=?,claimed_by=?,updated_at=? WHERE id=?
          AND status IN ('queued','retry')
          AND (next_retry_at IS NULL OR next_retry_at<=?)""",
          (now, worker_id, now, row["id"], now)).rowcount
        if changed != 1:
            return None
        return _dict(db.execute("SELECT * FROM deep_discovery_jobs WHERE id=?",
                                (row["id"],)).fetchone())


def finish_deep_discovery_job(job_id: int, worker_id: str, *,
                              local_results: dict | None = None,
                              candidate_clusters: list[dict] | None = None,
                              provider_status: dict | None = None,
                              run_status: str | None = None) -> int | None:
    """Persist one advisory run and release its owned queue claim."""
    now = utc_now_iso()
    normalized_run_status = str(run_status or "local_complete").strip().casefold()
    if normalized_run_status not in {
        "local_complete", "provider_complete", "provider_partial", "provider_empty",
    }:
        raise ValueError("unsupported Deep Discovery run status")
    with get_db() as db:
        _begin_immediate(db, "finish_deep_discovery", worker_id)
        job = db.execute("""SELECT * FROM deep_discovery_jobs
          WHERE id=? AND status='claimed' AND claimed_by=?""",
          (int(job_id), worker_id)).fetchone()
        if not job:
            return None
        db.execute("""INSERT INTO deep_discovery_runs
          (job_id,actor_id,site_card_id,run_status,anchor_snapshot_json,
           local_results_json,candidate_clusters_json,worker_id,anchor_hash,
           provider_status_json,created_at,completed_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
          (int(job_id), int(job["actor_id"]), int(job["site_card_id"] or 0),
           normalized_run_status, job["anchor_snapshot_json"],
           json.dumps(local_results or {}, ensure_ascii=False, sort_keys=True),
           json.dumps(candidate_clusters or [], ensure_ascii=False, sort_keys=True),
           worker_id, job["anchor_hash"],
            json.dumps(provider_status or {"network_enabled": False,
                                           "enabled_providers": ["local_arachne"]},
                      ensure_ascii=False, sort_keys=True),
           now, now))
        run_id = int(db.execute("SELECT last_insert_rowid()").fetchone()[0])
        pending_payload = job["pending_anchor_snapshot_json"]
        pending_hash = job["pending_anchor_hash"]
        if pending_payload and pending_hash:
            db.execute("""UPDATE deep_discovery_jobs SET status='queued',
              anchor_snapshot_json=?,anchor_hash=?,anchor_revision=COALESCE(anchor_revision,1)+1,
              pending_anchor_snapshot_json=NULL,pending_anchor_hash=NULL,attempts=0,
              next_retry_at=NULL,last_error=NULL,error_type=NULL,failed_at=NULL,
              dead_letter_reason=NULL,completed_at=NULL,claimed_at=NULL,claimed_by=NULL,
              updated_at=? WHERE id=? AND claimed_by=?""",
              (pending_payload, pending_hash, now, int(job_id), worker_id))
        else:
            db.execute("""UPDATE deep_discovery_jobs SET status='done',completed_at=?,
              claimed_at=NULL,claimed_by=NULL,last_error=NULL,error_type=NULL,
              failed_at=NULL,dead_letter_reason=NULL,next_retry_at=NULL,updated_at=?
              WHERE id=? AND claimed_by=?""", (now, now, int(job_id), worker_id))
        return run_id


def fail_deep_discovery_job(job_id: int, worker_id: str, error: str,
                            *, retry: bool = True) -> bool:
    """Release a failed owned claim using the existing bounded retry policy."""
    transition_status: str | None = None
    transition_error = error
    retry_count: int | None = None
    with get_db() as db:
        _begin_immediate(db, "fail_deep_discovery", worker_id)
        row = db.execute("""SELECT * FROM deep_discovery_jobs
          WHERE id=? AND status='claimed' AND claimed_by=?""",
          (int(job_id), worker_id)).fetchone()
        if not row:
            return False
        retry_count = int(row["attempts"] or 0) + 1
        if retry:
            decision = _worker_error_decision(
                error, int(row["attempts"] or 0), int(row["max_attempts"] or 3))
        else:
            decision = {
                "status": "failed", "error_type": "non_retryable",
                "next_retry_at": None, "dead_letter_reason": "non_retryable_failure",
            }
        now = utc_now_iso()
        pending_payload = row["pending_anchor_snapshot_json"]
        pending_hash = row["pending_anchor_hash"]
        if decision["status"] != "retry":
            # Preserve the old immutable revision's terminal result before a
            # newer pending revision is promoted.
            db.execute("""INSERT INTO deep_discovery_runs
              (job_id,actor_id,site_card_id,run_status,anchor_snapshot_json,
               local_results_json,candidate_clusters_json,worker_id,anchor_hash,
               provider_status_json,created_at,completed_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
              (int(job_id), int(row["actor_id"]), int(row["site_card_id"] or 0),
               decision["status"], row["anchor_snapshot_json"],
               json.dumps({"safe_error_type": decision["error_type"]}, sort_keys=True),
               "[]", worker_id, row["anchor_hash"],
               json.dumps({"network_enabled": False,
                           "enabled_providers": ["local_arachne"],
                           "status": "failed_before_provider_completion"}, sort_keys=True),
               now, now))
        if pending_payload and pending_hash and decision["status"] != "retry":
            changed = db.execute("""UPDATE deep_discovery_jobs SET status='queued',
              anchor_snapshot_json=?,anchor_hash=?,anchor_revision=COALESCE(anchor_revision,1)+1,
              pending_anchor_snapshot_json=NULL,pending_anchor_hash=NULL,attempts=0,
              last_error=NULL,error_type=NULL,failed_at=NULL,dead_letter_reason=NULL,
              next_retry_at=NULL,completed_at=NULL,claimed_at=NULL,claimed_by=NULL,updated_at=?
              WHERE id=? AND status='claimed' AND claimed_by=?""",
              (pending_payload, pending_hash, now, int(job_id), worker_id)).rowcount
            if changed == 1:
                transition_status = "retry"
                transition_error = "pending_revision_promoted"
                retry_count = 0
        else:
            changed = db.execute("""UPDATE deep_discovery_jobs SET status=?,attempts=attempts+1,
              last_error=?,error_type=?,failed_at=?,dead_letter_reason=?,next_retry_at=?,
              claimed_at=NULL,claimed_by=NULL,updated_at=?
              WHERE id=? AND status='claimed' AND claimed_by=?""",
              (decision["status"], str(error or "deep_discovery_failed")[:500],
               decision["error_type"], now, decision["dead_letter_reason"],
               decision["next_retry_at"], now, int(job_id), worker_id)).rowcount
            if changed == 1:
                transition_status = str(decision["status"])
    if transition_status:
        _observe_job_transition(
            "deep_discovery", worker_id, transition_status, job_id=int(job_id),
            error_label=transition_error, retry_count=retry_count)
    return changed == 1


def get_deep_discovery_runs(*, site_card_id: int | None = None,
                            job_id: int | None = None, limit: int = 100) -> list[dict]:
    limit = max(1, min(int(limit or 100), 500))
    clauses: list[str] = []
    params: list[Any] = []
    if site_card_id is not None:
        clauses.append("site_card_id=?")
        params.append(int(site_card_id))
    if job_id is not None:
        clauses.append("job_id=?")
        params.append(int(job_id))
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    params.append(limit)
    with get_db() as db:
        return [dict(row) for row in db.execute(f"""SELECT * FROM deep_discovery_runs
          {where} ORDER BY created_at DESC,id DESC LIMIT ?""", tuple(params))]


def get_deep_discovery_jobs(*, status: str | None = None,
                            site_card_id: int | None = None,
                            actor_id: int | None = None,
                            limit: int = 100) -> list[dict]:
    limit = max(1, min(int(limit or 100), 500))
    clauses: list[str] = []
    params: list[Any] = []
    if status:
        clauses.append("ddj.status=?")
        params.append(status)
    if site_card_id is not None:
        clauses.append("ddj.site_card_id=?")
        params.append(int(site_card_id))
    if actor_id is not None:
        clauses.append("ddj.actor_id=?")
        params.append(int(actor_id))
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    params.append(limit)
    with get_db() as db:
        return [dict(row) for row in db.execute(f"""SELECT ddj.*,a.display_alias,
          a.normalized_alias,a.onion_host,a.confidence_label
          FROM deep_discovery_jobs ddj JOIN actors a ON a.id=ddj.actor_id
          {where} ORDER BY ddj.eligibility_score DESC,ddj.created_at DESC LIMIT ?""",
          tuple(params))]


def get_site_card_actor_profiles(site_card_id: int, limit: int = 100) -> list[dict]:
    """Return public alias/profile observations attached to one Site Card."""
    limit = max(1, min(int(limit or 100), 500))
    with get_db() as db:
        rows = [dict(row) for row in db.execute("""SELECT a.id actor_id,a.display_alias,
          a.normalized_alias,a.generic_role,a.watched,a.watch_reason,a.observation_count,
          a.confidence_score,a.confidence_label,
          (SELECT COUNT(*) FROM actor_identifiers ai WHERE ai.actor_id=a.id) identifier_count,
          MIN(o.observed_at) first_observed,MAX(o.last_seen) last_observed,
          MAX(o.evidence_confidence) evidence_confidence,
          SUM(CASE WHEN o.seller_observation=1 THEN 1 ELSE 0 END) seller_observations,
          GROUP_CONCAT(DISTINCT o.evidence_type) evidence_types,
          GROUP_CONCAT(DISTINCT o.page_type) page_types,
          GROUP_CONCAT(DISTINCT o.url) source_urls
          FROM actor_observations o JOIN actors a ON a.id=o.actor_id
          WHERE o.site_card_id=? AND COALESCE(o.analyst_excluded,0)=0
          GROUP BY a.id
          ORDER BY seller_observations DESC,MAX(o.evidence_confidence) DESC,MAX(o.last_seen) DESC
          LIMIT ?""", (site_card_id, limit))]
        for row in rows:
            row["identifiers"] = [dict(item) for item in db.execute("""SELECT indicator_type,
              safe_value_label,COUNT(*) count,MAX(last_seen) last_seen FROM actor_identifiers
              WHERE actor_id=? GROUP BY indicator_type,safe_value_label""", (row["actor_id"],))]
    return rows


def set_actor_watch(actor_id: int, watched: bool, reason: str | None = None) -> bool:
    now = utc_now_iso()
    with get_db() as db:
        cur = db.execute("UPDATE actors SET watched=?,watch_reason=? WHERE id=?",
                         (int(watched), str(reason or "")[:240] or None, actor_id))
        if cur.rowcount:
            db.execute("""INSERT INTO actor_events(actor_id,event_type,safe_metadata_json,created_at)
              VALUES(?,?,?,?)""", (actor_id, "watch_enabled" if watched else "watch_disabled",
              json.dumps({"reason": str(reason or "")[:240]}, ensure_ascii=False), now))
        return cur.rowcount > 0


def set_actor_connection_decision(connection_id: int, decision: str) -> bool:
    if decision not in {"unreviewed", "confirmed_same", "not_same"}:
        raise ValueError("Invalid actor connection decision")
    with get_db() as db:
        row = db.execute("SELECT source_actor_id,target_actor_id FROM actor_connections WHERE id=?", (connection_id,)).fetchone()
        if not row:
            return False
        db.execute("UPDATE actor_connections SET analyst_decision=?,last_seen=? WHERE id=?",
                   (decision, utc_now_iso(), connection_id))
        db.execute("""INSERT INTO actor_events(actor_id,connection_id,event_type,safe_metadata_json,created_at)
          VALUES(?,?,?,?,?)""", (row["source_actor_id"], connection_id, "connection_reviewed",
          json.dumps({"decision": decision}), utc_now_iso()))
        if decision == "confirmed_same":
            watched = db.execute("SELECT MAX(watched) FROM actors WHERE id IN (?,?)",
                                 (row["source_actor_id"], row["target_actor_id"])).fetchone()[0]
            if watched:
                db.execute("UPDATE actors SET watched=1 WHERE id IN (?,?)",
                           (row["source_actor_id"], row["target_actor_id"]))
        return True


def get_actor_watch_alerts(*, new_only: bool = True, limit: int = 100) -> list[dict]:
    where = "WHERE awa.status='new'" if new_only else ""
    with get_db() as db:
        return [dict(row) for row in db.execute(f"""SELECT awa.*,a.display_alias,a.onion_host,
          related.display_alias related_alias,related.onion_host related_onion_host
          FROM actor_watch_alerts awa JOIN actors a ON a.id=awa.actor_id
          LEFT JOIN actors related ON related.id=awa.related_actor_id
          {where} ORDER BY awa.created_at DESC LIMIT ?""", (limit,))]


def acknowledge_actor_watch_alert(alert_id: int) -> bool:
    with get_db() as db:
        cur = db.execute("UPDATE actor_watch_alerts SET status='acknowledged',acknowledged_at=? WHERE id=?",
                         (utc_now_iso(), alert_id))
        return cur.rowcount > 0


def exclude_actor_observation(observation_id: int) -> bool:
    """Split a false-positive page occurrence away from an alias cluster."""
    with get_db() as db:
        row = db.execute("SELECT actor_id,url FROM actor_observations WHERE id=?", (observation_id,)).fetchone()
        if not row:
            return False
        if db.execute("SELECT analyst_excluded FROM actor_observations WHERE id=?",
                      (observation_id,)).fetchone()[0]:
            return True
        related_actor_ids = {int(item[0]) for item in db.execute("""SELECT CASE
          WHEN source_actor_id=? THEN target_actor_id ELSE source_actor_id END
          FROM actor_connections WHERE source_actor_id=? OR target_actor_id=?""",
          (row["actor_id"], row["actor_id"], row["actor_id"]))}
        identifier_ids = {int(item[0]) for item in db.execute("""SELECT actor_identifier_id
          FROM actor_identifier_observations WHERE observation_id=?""", (observation_id,))}
        identifier_ids.update(int(item[0]) for item in db.execute("""SELECT id FROM actor_identifiers
          WHERE observation_id=?""", (observation_id,)))
        db.execute("UPDATE actor_observations SET analyst_excluded=1 WHERE id=?", (observation_id,))
        db.execute("DELETE FROM actor_identifier_observations WHERE observation_id=?", (observation_id,))
        for identifier_id in sorted(identifier_ids):
            active = db.execute("""SELECT 1 FROM actor_identifier_observations aio
              JOIN actor_observations ao ON ao.id=aio.observation_id
              WHERE aio.actor_identifier_id=? AND ao.analyst_excluded=0 LIMIT 1""",
              (identifier_id,)).fetchone()
            if not active:
                db.execute("DELETE FROM actor_identifiers WHERE id=?", (identifier_id,))
        db.execute("""INSERT INTO actor_events(actor_id,event_type,safe_metadata_json,created_at)
          VALUES(?,?,?,?)""", (row["actor_id"], "observation_excluded",
          json.dumps({"url": row["url"]}, ensure_ascii=False), utc_now_iso()))
        candidates = [dict(item) for item in db.execute("""SELECT id,effective_state FROM actor_candidates
          WHERE actor_id=? AND url=?""", (row["actor_id"], row["url"]))]
        for candidate in candidates:
            db.execute("""UPDATE actor_candidates
              SET analyst_state='analyst_rejected_identity_evidence',
              effective_state='analyst_rejected_identity_evidence',last_seen=? WHERE id=?""",
              (utc_now_iso(), candidate["id"]))
            db.execute("""INSERT INTO actor_candidate_events
              (candidate_id,actor_id,event_type,old_state,new_state,reason_code,
               safe_metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?)""",
              (candidate["id"], row["actor_id"], "analyst_decision",
               candidate["effective_state"], "analyst_rejected_identity_evidence",
               "analyst_excluded_observation",
               "{}", utc_now_iso()))
        _refresh_actor_stats_db(db, int(row["actor_id"]))
        _refresh_actor_connections_db(db, int(row["actor_id"]))
        for related_actor_id in sorted(related_actor_ids):
            _refresh_actor_connections_db(db, related_actor_id)
        return True


def get_site_evidence_graph(site_card_id: int) -> dict:
    """Return a metadata-safe card → URL → indicator-type relationship graph."""
    restricted = {"adult_filtered", "adult_restricted", "severe_abuse_risk"}
    with get_db() as db:
        card = db.execute("SELECT id,primary_category,category_safe_label,storage_policy FROM site_cards WHERE id=?",
                          (site_card_id,)).fetchone()
        if not card:
            raise ValueError("Site Card not found")
        if card["primary_category"] in restricted or card["storage_policy"] == "discard":
            raise ValueError("Restricted safety categories cannot be graphed")
        urls = [dict(row) for row in db.execute("""SELECT scu.url,scu.active,ou.storage_policy
          FROM site_card_urls scu LEFT JOIN onion_urls ou ON ou.id=scu.onion_url_id
          WHERE scu.site_card_id=? AND COALESCE(ou.primary_category,'unknown') NOT IN
          ('adult_filtered','adult_restricted','severe_abuse_risk') ORDER BY scu.url LIMIT 40""",
          (site_card_id,))]
        indicator_rows = [dict(row) for row in db.execute("""SELECT il.source_ref,i.indicator_type,COUNT(*) count
          FROM indicator_links il JOIN indicators i ON i.id=il.indicator_id
          JOIN site_card_urls scu ON scu.url=il.source_ref
          WHERE scu.site_card_id=? GROUP BY il.source_ref,i.indicator_type""", (site_card_id,))]
        actor_rows = [dict(row) for row in db.execute("""SELECT DISTINCT a.id,a.display_alias,
          a.confidence_label,ao.url FROM actor_observations ao JOIN actors a ON a.id=ao.actor_id
          WHERE ao.site_card_id=? AND ao.analyst_excluded=0 ORDER BY a.confidence_score DESC LIMIT 40""",
          (site_card_id,))]
        actor_db_ids = sorted({int(row["id"]) for row in actor_rows})
        actor_connections = []
        if actor_db_ids:
            marks = ",".join("?" for _ in actor_db_ids)
            actor_connections = [dict(row) for row in db.execute(f"""SELECT source_actor_id,
              target_actor_id,confidence_label FROM actor_connections
              WHERE source_actor_id IN ({marks}) AND target_actor_id IN ({marks})""",
              (*actor_db_ids, *actor_db_ids))]
    nodes = [{"id": f"card:{site_card_id}", "label": card["category_safe_label"] or card["primary_category"],
              "kind": "site_card"}]
    edges = []
    url_ids = {}
    for index, row in enumerate(urls):
        node_id = f"url:{index}"
        url_ids[row["url"]] = node_id
        nodes.append({"id": node_id, "label": row["url"], "kind": "onion_url"})
        edges.append({"source": f"card:{site_card_id}", "target": node_id, "label": "observed URL"})
    type_nodes = {}
    for row in indicator_rows:
        if row["source_ref"] not in url_ids:
            continue
        kind = str(row["indicator_type"] or "unknown")
        node_id = type_nodes.setdefault(kind, f"indicator:{len(type_nodes)}")
        if not any(node["id"] == node_id for node in nodes):
            nodes.append({"id": node_id, "label": f"{kind.replace('_', ' ')} indicators", "kind": "indicator_type"})
        edges.append({"source": url_ids[row["source_ref"]], "target": node_id,
                      "label": f"{int(row['count'])} observed"})
    actor_nodes = {}
    for row in actor_rows:
        node_id = actor_nodes.setdefault(int(row["id"]), f"actor:{int(row['id'])}")
        if not any(node["id"] == node_id for node in nodes):
            nodes.append({"id": node_id, "label": str(row["display_alias"] or "Public alias"),
                          "kind": "actor"})
        if row["url"] in url_ids:
            edges.append({"source": url_ids[row["url"]], "target": node_id,
                          "label": f"public alias · {row['confidence_label'] or 'low'} confidence"})
    for connection in actor_connections:
        source = actor_nodes.get(int(connection["source_actor_id"]))
        target = actor_nodes.get(int(connection["target_actor_id"]))
        if source and target:
            edges.append({"source": source, "target": target,
                          "label": f"possible correspondence · {connection['confidence_label'] or 'low'}"})
    return {"nodes": nodes, "edges": edges}


def get_connection_workbench(limit: int = 150) -> list[dict]:
    """Return metadata-safe Site Cards with relationship counts for the workbench UI."""
    limit = max(1, min(int(limit or 150), 500))
    with get_db() as db:
        return [dict(row) for row in db.execute("""SELECT sc.id,sc.analyst_title,sc.display_name,
          sc.primary_category,sc.risk_level,sc.importance_level,sc.spain_priority,
          (SELECT scu.onion_host FROM site_card_urls scu WHERE scu.site_card_id=sc.id
           ORDER BY scu.url_role='canonical' DESC,scu.active DESC,scu.first_seen LIMIT 1) AS representative_host,
          sc.representative_url,sc.mirror_count,sc.source_count,
          sc.live_url_count,sc.dead_url_count,sc.last_seen,sc.updated_at,
          (SELECT COUNT(*) FROM site_card_urls scu WHERE scu.site_card_id=sc.id) AS url_count,
          (SELECT COUNT(DISTINCT il.indicator_id) FROM indicator_links il
             JOIN site_card_urls scu ON scu.url=il.source_ref WHERE scu.site_card_id=sc.id) AS indicator_count,
          (SELECT COUNT(DISTINCT ao.actor_id) FROM actor_observations ao
             WHERE ao.site_card_id=sc.id AND COALESCE(ao.analyst_excluded,0)=0) AS actor_count,
          (SELECT COUNT(*) FROM site_card_events sce WHERE sce.site_card_id=sc.id) AS event_count
          FROM site_cards sc
          WHERE COALESCE(sc.ui_hidden_default,0)=0
            AND COALESCE(sc.storage_policy,'safe_summary')!='discard'
            AND COALESCE(sc.primary_category,'unknown') NOT IN
              ('adult_filtered','adult_restricted','severe_abuse_risk')
          ORDER BY (actor_count+indicator_count+COALESCE(sc.mirror_count,0)+COALESCE(sc.spain_priority,0)*3) DESC,
                   COALESCE(sc.last_seen,sc.updated_at,sc.first_seen) DESC
          LIMIT ?""", (limit,))]


def get_intelligence_timeline(limit: int = 200) -> list[dict]:
    """Return a unified, metadata-safe activity timeline for dashboard review."""
    limit = max(1, min(int(limit or 200), 500))
    restricted = ("adult_filtered", "adult_restricted", "severe_abuse_risk")
    events: list[dict] = []
    with get_db() as db:
        for row in db.execute("""SELECT sce.created_at AS ts,'site_card' AS event_family,
          sce.event_type,sce.event_summary AS summary,sce.site_card_id,
          sc.analyst_title,sc.display_name,sc.primary_category,sc.risk_level,sc.spain_priority,
          sce.safe_metadata_json
          FROM site_card_events sce JOIN site_cards sc ON sc.id=sce.site_card_id
          WHERE COALESCE(sc.ui_hidden_default,0)=0
            AND COALESCE(sc.storage_policy,'safe_summary')!='discard'
            AND COALESCE(sc.primary_category,'unknown') NOT IN (?,?,?)
          ORDER BY sce.created_at DESC LIMIT ?""", (*restricted, limit)):
            events.append(dict(row))
        for row in db.execute("""SELECT ae.created_at AS ts,'actor' AS event_family,
          ae.event_type,'' AS summary,ae.actor_id,ae.connection_id,
          a.display_alias,a.onion_host,a.primary_category,a.risk_level,
          ae.safe_metadata_json
          FROM actor_events ae LEFT JOIN actors a ON a.id=ae.actor_id
          ORDER BY ae.created_at DESC LIMIT ?""", (limit,)):
            item = dict(row)
            item["summary"] = item.get("summary") or item.get("display_alias") or "Public alias event"
            events.append(item)
        for row in db.execute("""SELECT detected_at AS ts,'page_change' AS event_family,
          change_type AS event_type,url AS summary,site_card_id,previous_category,
          current_category,safe_summary_json AS safe_metadata_json
          FROM page_change_events WHERE COALESCE(meaningful,0)=1
          ORDER BY detected_at DESC LIMIT ?""", (limit,)):
            events.append(dict(row))
        for row in db.execute("""SELECT generated_at AS ts,'daily_digest' AS event_family,
          'daily_digest' AS event_type,digest_date AS summary,payload_json AS safe_metadata_json,
          telegram_status FROM daily_digests ORDER BY generated_at DESC LIMIT ?""", (min(limit, 90),)):
            events.append(dict(row))
    events.sort(key=lambda item: str(item.get("ts") or ""), reverse=True)
    return events[:limit]


def get_operational_health() -> dict:
    fresh_after = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    with get_db() as db:
        counts = dict(db.execute("""SELECT
          SUM(CASE WHEN active=1 AND status IN ('new','queued','retry') THEN 1 ELSE 0 END) queued,
          SUM(CASE WHEN status='retry' THEN 1 ELSE 0 END) retrying,
          SUM(CASE WHEN status='dead' THEN 1 ELSE 0 END) dead,
          SUM(CASE WHEN last_error IS NOT NULL THEN 1 ELSE 0 END) errors,
          COUNT(*) total FROM onion_urls""").fetchone())
        queue = dict(db.execute("""SELECT
          (SELECT COUNT(*) FROM fetched_pages WHERE classification_status IN ('pending','retry','claimed')) verify_waiting,
          (SELECT COUNT(*) FROM site_card_jobs WHERE status IN ('queued','retry','claimed')) card_waiting,
          (SELECT COUNT(*) FROM page_preview_jobs WHERE status IN ('queued','retry','claimed')) preview_waiting,
          (SELECT COUNT(*) FROM fetched_pages WHERE classification_status IN ('failed','dead_letter')) verify_failed,
          (SELECT COUNT(*) FROM site_card_jobs WHERE status IN ('failed','dead_letter')) card_failed,
          (SELECT COUNT(*) FROM page_preview_jobs WHERE status IN ('failed','dead_letter')) preview_failed
        """).fetchone())
        instances = [dict(row) for row in db.execute("""SELECT * FROM worker_instances
          WHERE last_heartbeat_at>=? AND state NOT IN ('stopped')
          ORDER BY last_heartbeat_at DESC""", (fresh_after,))]
        legacy = _dict(db.execute("SELECT * FROM crawler_worker_state WHERE id=1").fetchone()) or {}
    worker_types = {str(item.get("worker_type") or "unknown") for item in instances}
    paused = bool(legacy.get("is_paused"))
    if paused:
        state = "paused"
    elif not instances:
        state = "offline"
    elif not {"fetch", "verify", "card"}.issubset(worker_types):
        state = "degraded"
    else:
        state = "online"
    worker = {
        "state": state,
        "is_paused": int(paused),
        "active_instances": len(instances),
        "worker_types": sorted(worker_types),
        "last_heartbeat_at": instances[0]["last_heartbeat_at"] if instances else None,
        "processed_total": sum(int(item.get("processed_total") or 0) for item in instances),
    }
    counts["queued"] = int(counts.get("queued") or 0)
    counts["retrying"] = int(counts.get("retrying") or 0)
    counts["dead"] = int(counts.get("dead") or 0)
    counts["errors"] = (int(counts.get("errors") or 0) + int(queue.get("verify_failed") or 0)
                        + int(queue.get("card_failed") or 0) + int(queue.get("preview_failed") or 0))
    return {**counts, **queue, "worker": worker, "worker_instances": instances}


def mark_onion_dead(url: str, http_status: int | None, dead_reason: str,
                    worker_id: str | None = None) -> bool:
    with get_db() as db:
        owner_clause = " AND status IN ('claimed','fetching') AND claimed_by=?" if worker_id else ""
        owner_params: tuple[Any, ...] = (worker_id,) if worker_id else ()
        changed = db.execute("""UPDATE onion_urls SET status='dead',active=0,http_status=?,dead_reason=?,
          fetch_status='success',liveness_status='hard_dead',content_quality='unavailable',
          last_checked_at=?,last_crawled=?,next_crawl_at=NULL,verification_state='verified',
          verified_at=COALESCE(verified_at,?),verification_reason='fetched_hard_dead',
          claimed_at=NULL,claimed_by=NULL,last_fetch_status='dead',last_http_status=? WHERE url=?""" + owner_clause,
          (http_status, dead_reason, utc_now_iso(), utc_now_iso(), utc_now_iso(), http_status,
           url, *owner_params)).rowcount
    if changed:
        mark_site_card_dirty_for_url(url)
        insert_crawl_audit(url, "fetch", "dead", dead_reason)
    return changed == 1


def set_spain_review_status(url: str, status: str) -> None:
    if status not in {"unreviewed", "opened", "keep", "ignored", "needs_report", "reported", "blocked"}:
        raise ValueError("Invalid Spain review status")
    with get_db() as db:
        db.execute("UPDATE onion_urls SET spain_review_status=? WHERE url=? AND spain_priority=1", (status, url))
        row = db.execute("SELECT id,site_card_id,tags FROM onion_urls WHERE url=?", (url,)).fetchone()
        if row and status in {"keep", "needs_report", "reported"}:
            try:
                tags = json.loads(row["tags"] or "[]")
                if not isinstance(tags, list): tags = []
            except (TypeError, ValueError):
                tags = []
            tags.extend(["spain_priority", "spain", "spain_confirmed"])
            db.execute("UPDATE onion_urls SET tags=? WHERE id=?",
                       (json.dumps(list(dict.fromkeys(tags)), ensure_ascii=False), row["id"]))
            if row["site_card_id"]:
                db.execute("UPDATE site_cards SET rollup_dirty=1 WHERE id=?", (row["site_card_id"],))
        db.execute("UPDATE spain_alert_queue SET status='reviewed' WHERE status='pending' AND url=?", (url,))


def acknowledge_spain_card_open(site_card_id: int) -> int:
    """Clear transient Spain alerts when an analyst manually opens their Site Card."""
    now = utc_now_iso()
    with get_db() as db:
        urls = [str(row[0]) for row in db.execute("""SELECT url FROM onion_urls
          WHERE site_card_id=? AND spain_priority=1
          AND COALESCE(spain_analyst_suppressed,0)=0
          AND COALESCE(spain_review_status,'unreviewed')='unreviewed'""", (site_card_id,))]
        if not urls:
            return 0
        db.execute("""UPDATE onion_urls SET spain_review_status='opened'
          WHERE site_card_id=? AND spain_priority=1
          AND COALESCE(spain_review_status,'unreviewed')='unreviewed'""", (site_card_id,))
        db.execute("""UPDATE spain_hits SET review_status='opened'
          WHERE site_card_id=? AND COALESCE(review_status,'unreviewed')='unreviewed'""", (site_card_id,))
        db.execute("""UPDATE spain_alert_queue SET status='reviewed'
          WHERE site_card_id=? AND status='pending'""", (site_card_id,))
        db.execute("""INSERT INTO site_card_events(site_card_id,event_type,event_summary,safe_metadata_json,created_at)
          VALUES(?,?,?,?,?)""", (site_card_id, "spain_alert_opened",
          "Spain alert acknowledged when the Site Card was opened", json.dumps({"url_count": len(urls)}), now))
        return len(urls)


def get_saved_investigations() -> list[dict]:
    with get_db() as db:
        return [dict(row) for row in db.execute(
            "SELECT * FROM saved_investigations ORDER BY builtin DESC,name COLLATE NOCASE")]


def save_investigation(name: str, description: str, filters: dict) -> int:
    clean_name = " ".join(str(name or "").split())[:80]
    if not clean_name:
        raise ValueError("Investigation name is required")
    allowed = {"category", "priority", "risk", "importance", "review", "operational", "sort", "search"}
    safe_filters = {key: str(value)[:200] for key, value in filters.items()
                    if key in allowed and value not in {None, "", "All"}}
    now = utc_now_iso()
    with get_db() as db:
        db.execute("""INSERT INTO saved_investigations
          (name,description,filters_json,builtin,created_at,updated_at) VALUES(?,?,?,?,?,?)
          ON CONFLICT(name) DO UPDATE SET description=excluded.description,
          filters_json=excluded.filters_json,updated_at=excluded.updated_at""",
          (clean_name, str(description or "")[:240], json.dumps(safe_filters, ensure_ascii=False), 0, now, now))
        return int(db.execute("SELECT id FROM saved_investigations WHERE name=?", (clean_name,)).fetchone()[0])


def delete_investigation(investigation_id: int) -> bool:
    with get_db() as db:
        return db.execute("DELETE FROM saved_investigations WHERE id=? AND builtin=0",
                          (investigation_id,)).rowcount > 0


def notification_preferences() -> dict:
    with get_db() as db:
        row = db.execute("SELECT * FROM notification_control WHERE id=1").fetchone()
        return dict(row) if row else {"spain_alerts_paused": 0, "daily_digest_telegram": 0,
                                      "immediate_spain_alerts": 1}


def set_notification_preferences(*, immediate_spain: bool, daily_digest_telegram: bool,
                                 updated_by: str = "dashboard") -> None:
    with get_db() as db:
        db.execute("""INSERT INTO notification_control
          (id,spain_alerts_paused,immediate_spain_alerts,daily_digest_telegram,updated_at,updated_by)
          VALUES(1,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
          spain_alerts_paused=excluded.spain_alerts_paused,
          immediate_spain_alerts=excluded.immediate_spain_alerts,
          daily_digest_telegram=excluded.daily_digest_telegram,
          updated_at=excluded.updated_at,updated_by=excluded.updated_by""",
          (int(not immediate_spain), int(immediate_spain), int(daily_digest_telegram),
           utc_now_iso(), updated_by[:80]))


def store_daily_digest(digest_date: str, payload: dict, *, telegram_pending: bool) -> None:
    status = "pending" if telegram_pending else "dashboard_only"
    with get_db() as db:
        db.execute("""INSERT INTO daily_digests
          (digest_date,timezone,payload_json,generated_at,telegram_status)
          VALUES(?,?,?,?,?) ON CONFLICT(digest_date) DO UPDATE SET
          payload_json=excluded.payload_json,generated_at=excluded.generated_at,
          telegram_status=CASE WHEN daily_digests.telegram_status='sent' THEN 'sent'
            ELSE excluded.telegram_status END""",
          (digest_date, "Europe/Madrid", json.dumps(payload, ensure_ascii=False), utc_now_iso(), status))


def get_daily_digests(limit: int = 14) -> list[dict]:
    with get_db() as db:
        return [dict(row) for row in db.execute(
            "SELECT * FROM daily_digests ORDER BY digest_date DESC LIMIT ?", (max(1, min(limit, 90)),))]


def get_pending_daily_digests(limit: int = 3) -> list[dict]:
    with get_db() as db:
        return [dict(row) for row in db.execute("""SELECT * FROM daily_digests
          WHERE telegram_status='pending' ORDER BY digest_date LIMIT ?""", (max(1, min(limit, 10)),))]


def mark_daily_digest_sent(digest_date: str) -> None:
    with get_db() as db:
        db.execute("UPDATE daily_digests SET telegram_status='sent',telegram_sent_at=? WHERE digest_date=?",
                   (utc_now_iso(), digest_date))


def get_spain_priority_items(unreviewed_only: bool = False, limit: int = 200) -> list[dict]:
    where = "WHERE spain_priority=1 AND COALESCE(spain_analyst_suppressed,0)=0" + (" AND spain_review_status='unreviewed'" if unreviewed_only else "")
    with get_db() as db:
        return [dict(row) for row in db.execute(f"""SELECT * FROM onion_urls {where}
          ORDER BY CASE primary_category WHEN 'severe_abuse_risk' THEN 1 WHEN 'adult_restricted' THEN 2
          WHEN 'weapons_arms' THEN 3 WHEN 'leaks_data' THEN 4 WHEN 'credentials' THEN 5
          WHEN 'malware_hacking' THEN 6 WHEN 'extremist_recruitment' THEN 7 ELSE 8 END,
          priority_score DESC,first_seen DESC LIMIT ?""", (limit,))]


_NOISY_FORUM_PARAMS = {"sid", "session", "phpsessid", "utm_source", "utm_medium", "utm_campaign",
                       "utm_term", "utm_content", "ref", "cache", "cb", "timestamp"}


def canonicalize_spain_hit(url: str) -> dict:
    """Create a stable, content-free domain/family identity for a Spain URL hit."""
    parsed = urlsplit(url)
    host = (parsed.hostname or "").casefold()
    path = parsed.path or "/"
    query = {key.casefold(): value for key, value in parse_qsl(parsed.query, keep_blank_values=False)
             if key.casefold() not in _NOISY_FORUM_PARAMS}
    lower_path = path.casefold()
    hit_type = "unknown"
    identity = []
    if lower_path.endswith("viewforum.php") and query.get("f"):
        hit_type, identity = "forum_section", [("f", query["f"])]
        family = f"forum:f={query['f']}"
    elif lower_path.endswith("viewtopic.php") and query.get("t"):
        hit_type, identity = "thread", [("t", query["t"])]
        family = f"thread:t={query['t']}"
    elif lower_path.endswith("viewtopic.php") and query.get("p"):
        hit_type, identity = "post", [("p", query["p"])]
        family = f"post:p={query['p']}"
    elif lower_path.endswith("search.php") and query.get("author_id") and query.get("sr") == "posts":
        hit_type, identity = "author_posts", [("author_id", query["author_id"]), ("sr", "posts")]
        family = f"author_posts:{query['author_id']}"
    elif "search" in lower_path and query.get("q"):
        hit_type, identity = "search_result", [("q", query["q"])]
        family = "search_query:" + hashlib.sha256(query["q"].casefold().encode()).hexdigest()[:16]
    else:
        identity = sorted((key, value) for key, value in query.items() if key not in {"start", "page"})
        hit_type = "domain_home" if path in {"", "/", "/index.php", "/index.html"} else "directory"
        family = f"{hit_type}:{path.casefold()}"
        if identity:
            family += ":" + hashlib.sha256(urlencode(identity).encode()).hexdigest()[:12]
    canonical = urlunsplit((parsed.scheme or "http", host, path, urlencode(identity), ""))
    return {"onion_host": host, "site_tree_id": hashlib.sha256(host.encode()).hexdigest()[:24],
            "canonical_url": canonical, "normalized_family": family, "hit_type": hit_type}


def persist_spain_priority(url: str, policy: dict, source_url: str | None = None,
                           site_card_id: int | None = None, canonical_site_id: str | None = None) -> dict | None:
    """Durably persist the safe Spain overlay before any alert is queued or sent."""
    if policy.get("primary_category") == "severe_abuse_risk":
        return None
    shape = canonicalize_spain_hit(url)
    now = utc_now_iso()
    contexts = list(dict.fromkeys(policy.get("spain_context_tags") or []))
    reason = policy.get("spain_match_reason") or "Spain priority context"
    reason_code = policy.get("spain_priority_reason") or "spain_country_reference"
    evidence_type = policy.get("spain_priority_evidence_type") or "country_plus_threat"
    confidence = policy.get("spain_confidence") or "medium"
    language = policy.get("spain_match_language")
    evidence_score = int(policy.get("spain_evidence_score") or (
        80 if policy.get("spain_priority") and confidence == "high"
        and not policy.get("spain_context_only") and policy.get("spain_actionable", True) else 0))
    evidence_families = list(dict.fromkeys(
        policy.get("spain_evidence_families") or contexts))[:20]
    evidence_direction = str(policy.get("spain_evidence_direction") or
                             policy.get("spain_relevance") or "context_only")
    with get_db() as db:
        url_row = db.execute("SELECT id,spain_analyst_suppressed FROM onion_urls WHERE url=?", (url,)).fetchone()
        family_suppressed = db.execute("""SELECT 1 FROM spain_hits WHERE onion_host=?
          AND normalized_family=? AND hit_type=? AND COALESCE(analyst_suppressed,0)=1""",
          (shape["onion_host"], shape["normalized_family"], shape["hit_type"])).fetchone()
        if (url_row and url_row["spain_analyst_suppressed"]) or family_suppressed:
            if url_row:
                db.execute("""UPDATE onion_urls SET spain_priority=0,geo_priority=NULL,
                  spain_match_reason=NULL,spain_match_language=NULL,spain_confidence=NULL,
                  spain_context_tags=NULL,spain_alert_level=NULL,spain_review_status='ignored',
                  spain_analyst_suppressed=1 WHERE id=?""", (url_row["id"],))
            return None
    with get_db() as db:
        row = db.execute("""SELECT id,site_card_id,canonical_site_id,tags,classification_decision
          FROM onion_urls WHERE url=?""", (url,)).fetchone()
        if row:
            site_card_id = site_card_id or row["site_card_id"]
            canonical_site_id = canonical_site_id or row["canonical_site_id"]
            try:
                url_tags = json.loads(row["tags"] or "[]")
                if not isinstance(url_tags, list): url_tags = []
            except (TypeError, ValueError):
                url_tags = []
            url_tags.append("spain_priority")
            decision = policy.get("classification_decision") or row["classification_decision"]
            if decision in {"accepted", "analyst_confirmed"}:
                url_tags.extend(["spain", "spain_confirmed"])
            db.execute("""UPDATE onion_urls SET spain_priority=1,geo_priority='spain',
              spain_confidence=CASE WHEN spain_confidence='high' THEN spain_confidence ELSE COALESCE(?,spain_confidence) END,
              spain_match_language=COALESCE(spain_match_language,?),
              spain_match_reason=COALESCE(NULLIF(spain_match_reason,''),?),
              spain_priority_reason=?,spain_priority_evidence_type=?,
              spain_context_tags=CASE WHEN ?!='[]' THEN ? ELSE spain_context_tags END,
              spain_alert_level=COALESCE(?,spain_alert_level),
              spain_review_status=COALESCE(NULLIF(spain_review_status,''),'unreviewed'),
              tags=?,
              priority_score=MAX(COALESCE(priority_score,0),?),review_score=MAX(COALESCE(review_score,0),80),
              site_card_id=COALESCE(site_card_id,?),canonical_site_id=COALESCE(canonical_site_id,?) WHERE id=?""",
              (confidence, language, reason, reason_code, evidence_type,
               json.dumps(contexts), json.dumps(contexts, ensure_ascii=False),
               policy.get("spain_alert_level"), json.dumps(list(dict.fromkeys(url_tags)), ensure_ascii=False),
               max(80, int(policy.get("priority_score") or 0)),
               site_card_id, canonical_site_id, row["id"]))
            db.execute("""UPDATE onion_urls SET spain_relevance=?,spain_evidence_type=?,
              seller_geo_confidence=?,spain_evidence_snippets=?,spain_evidence_source_url=?,
              spain_evidence_source_path=?,spain_context_only=?,spain_actionable=?,
              spain_evidence_score=?,spain_evidence_families=?,spain_evidence_direction=? WHERE id=?""",
              (policy.get("spain_relevance") or "medium",
               policy.get("spain_evidence_type") or evidence_type,
               policy.get("seller_geo_confidence") or confidence,
               json.dumps(policy.get("spain_evidence_snippets", []), ensure_ascii=False),
               policy.get("spain_evidence_source_url") or url,
               policy.get("spain_evidence_source_path"),
               int(bool(policy.get("spain_context_only"))),
               int(bool(policy.get("spain_actionable", True))), evidence_score,
               json.dumps(evidence_families, ensure_ascii=False), evidence_direction, row["id"]))
            onion_url_id = int(row["id"])
        else:
            onion_url_id = None
        if site_card_id:
            current = db.execute("""SELECT spain_context_tags,tags,classification_decision,search_text
              FROM site_cards WHERE id=?""", (site_card_id,)).fetchone()
            old_contexts = []
            if current:
                try: old_contexts = json.loads(current[0] or "[]")
                except (TypeError, ValueError): old_contexts = []
            merged_contexts = list(dict.fromkeys(old_contexts + contexts))
            try:
                card_tags = json.loads(current["tags"] or "[]") if current else []
                if not isinstance(card_tags, list): card_tags = []
            except (TypeError, ValueError):
                card_tags = []
            card_tags.append("spain_priority")
            card_decision = policy.get("classification_decision") or (current["classification_decision"] if current else None)
            if card_decision in {"accepted", "analyst_confirmed"}:
                card_tags.extend(["spain", "spain_confirmed"])
            card_tags = list(dict.fromkeys(card_tags))
            search_text = ((current["search_text"] if current else "") or "") + " " + " ".join(card_tags)
            db.execute("""UPDATE site_cards SET spain_priority=1,
              spain_confidence=CASE WHEN spain_confidence='high' THEN spain_confidence ELSE COALESCE(?,spain_confidence) END,
              spain_match_language=COALESCE(spain_match_language,?),
              spain_match_reason=COALESCE(NULLIF(spain_match_reason,''),?),
              spain_priority_reason=?,spain_priority_evidence_type=?,spain_context_tags=?,
              tags=?,search_text=?,
              priority_score=MAX(COALESCE(priority_score,0),80),ui_priority=MAX(COALESCE(ui_priority,0),80),
              review_score=MAX(COALESCE(review_score,0),80),rollup_dirty=0,updated_at=? WHERE id=?""",
              (confidence, language, reason, reason_code, evidence_type,
               json.dumps(merged_contexts, ensure_ascii=False),
               json.dumps(card_tags, ensure_ascii=False), search_text.casefold()[:8000], now, site_card_id))
            db.execute("""UPDATE site_cards SET spain_relevance=?,spain_evidence_type=?,
              seller_geo_confidence=?,spain_evidence_snippets=?,spain_evidence_source_url=?,
              spain_evidence_source_path=?,spain_context_only=?,spain_actionable=?,
              spain_evidence_score=MAX(COALESCE(spain_evidence_score,0),?),
              spain_evidence_families=?,spain_evidence_direction=? WHERE id=?""",
              (policy.get("spain_relevance") or "medium",
               policy.get("spain_evidence_type") or evidence_type,
               policy.get("seller_geo_confidence") or confidence,
               json.dumps(policy.get("spain_evidence_snippets", []), ensure_ascii=False),
               policy.get("spain_evidence_source_url") or url,
               policy.get("spain_evidence_source_path"),
               int(bool(policy.get("spain_context_only"))),
               int(bool(policy.get("spain_actionable", True))), evidence_score,
               json.dumps(evidence_families, ensure_ascii=False), evidence_direction, site_card_id))
        db.execute("""INSERT INTO spain_hits(site_tree_id,site_card_id,onion_url_id,onion_host,canonical_url,
          normalized_family,hit_type,page_type,primary_category,risk_level,language,spain_reason,
          spain_confidence,source_url,first_seen,last_seen,metadata_only,safe_display_label,
          evidence_score,evidence_families_json,evidence_direction,context_only,actionable,reason_code,evidence_type)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(onion_host,normalized_family,hit_type)
          DO UPDATE SET site_card_id=COALESCE(spain_hits.site_card_id,excluded.site_card_id),
          onion_url_id=COALESCE(spain_hits.onion_url_id,excluded.onion_url_id),last_seen=excluded.last_seen,
          primary_category=excluded.primary_category,risk_level=excluded.risk_level,
          spain_reason=excluded.spain_reason,spain_confidence=excluded.spain_confidence,
          evidence_score=MAX(COALESCE(spain_hits.evidence_score,0),excluded.evidence_score),
          evidence_families_json=excluded.evidence_families_json,
          evidence_direction=excluded.evidence_direction,context_only=excluded.context_only,
          actionable=excluded.actionable,reason_code=excluded.reason_code,evidence_type=excluded.evidence_type""",
          (shape["site_tree_id"], site_card_id, onion_url_id, shape["onion_host"], shape["canonical_url"],
           shape["normalized_family"], shape["hit_type"], policy.get("page_type"),
           policy.get("primary_category"), policy.get("risk_level"), language, reason, confidence,
           source_url, now, now, int(policy.get("storage_policy") in {"metadata_only", "discard"}),
           "Spain priority " + shape["hit_type"].replace("_", " "), evidence_score,
           json.dumps(evidence_families, ensure_ascii=False), evidence_direction,
           int(bool(policy.get("spain_context_only"))), int(bool(policy.get("spain_actionable", True))),
           reason_code, evidence_type))
        hit = db.execute("SELECT * FROM spain_hits WHERE onion_host=? AND normalized_family=? AND hit_type=?",
                         (shape["onion_host"], shape["normalized_family"], shape["hit_type"])).fetchone()
    return dict(hit)


def get_spain_domain_trees(limit: int = 200) -> list[dict]:
    with get_db() as db:
        return [dict(row) for row in db.execute("""WITH eligible AS (
          SELECT *,CASE lower(risk_level) WHEN 'critical' THEN 4 WHEN 'high' THEN 3
            WHEN 'medium' THEN 2 ELSE 1 END AS row_risk_rank
          FROM spain_hits WHERE COALESCE(analyst_suppressed,0)=0
        ), ranked AS (
          SELECT *,ROW_NUMBER() OVER (PARTITION BY site_tree_id,onion_host
            ORDER BY COALESCE(evidence_score,0) DESC,row_risk_rank DESC,last_seen DESC,id DESC) AS rn
          FROM eligible
        ), totals AS (
          SELECT site_tree_id,onion_host,COUNT(*) AS total_spain_hits,
            SUM(hit_type='thread') AS direct_thread_hits,SUM(hit_type='post') AS direct_post_hits,
            SUM(hit_type IN ('search_result','author_posts')) AS search_hits,
            SUM(hit_type='forum_section') AS forum_section_hits,
            MAX(row_risk_rank) AS risk_rank,MAX(last_seen) AS last_seen,MIN(first_seen) AS first_seen
          FROM eligible GROUP BY site_tree_id,onion_host
        )
        SELECT t.*,b.site_card_id,b.primary_category,b.spain_confidence,b.spain_reason,
          b.review_status,b.evidence_score,b.evidence_families_json,b.evidence_direction,
          b.reason_code,b.evidence_type
        FROM totals t JOIN ranked b ON b.site_tree_id=t.site_tree_id
          AND b.onion_host=t.onion_host AND b.rn=1
        ORDER BY t.risk_rank DESC,COALESCE(b.evidence_score,0) DESC,t.last_seen DESC LIMIT ?""",
          (limit,))]


def get_spain_tree_hits(site_tree_id: str, hit_filter: str | None = None, limit: int = 100) -> list[dict]:
    where, params = ["site_tree_id=?", "COALESCE(analyst_suppressed,0)=0"], [site_tree_id]
    mapping = {"Direct thread/post hits": ("thread", "post"), "Search hits": ("search_result",),
               "Forum sections": ("forum_section",), "Author search hits": ("author_posts",)}
    if hit_filter in mapping:
        values = mapping[hit_filter]
        where.append("hit_type IN (" + ",".join("?" for _ in values) + ")"); params.extend(values)
    if hit_filter == "New since last review": where.append("review_status='unreviewed'")
    if hit_filter == "High risk only": where.append("lower(risk_level) IN ('high','critical','alto','critico')")
    params.append(min(500, max(1, limit)))
    with get_db() as db:
        return [dict(row) for row in db.execute(f"""SELECT * FROM spain_hits WHERE {' AND '.join(where)}
          ORDER BY CASE hit_type WHEN 'thread' THEN 1 WHEN 'post' THEN 2 WHEN 'author_posts' THEN 3
          WHEN 'search_result' THEN 4 WHEN 'forum_section' THEN 5 ELSE 6 END,last_seen DESC LIMIT ?""", params)]


def suppress_spain_hit(hit_id: int, reason: str = "analyst_removed_spain_priority") -> bool:
    """Remove one page/family from Spain Priority and persist the analyst override."""
    now = utc_now_iso()
    site_card_id = None
    url = None
    canonical_url = None
    quality_baseline = None
    quality_category = "unknown"
    quality_reason_code = None
    quality_onion_url_id = None
    with get_db() as db:
        hit = db.execute("SELECT * FROM spain_hits WHERE id=?", (hit_id,)).fetchone()
        if not hit:
            return False
        site_card_id = hit["site_card_id"]
        quality_onion_url_id = hit["onion_url_id"]
        quality_category = str(hit["primary_category"] or "unknown")
        quality_reason_code = hit["reason_code"]
        if quality_onion_url_id:
            baseline_row = db.execute("""SELECT id,classifier_version,final_category
              FROM classification_decisions WHERE onion_url_id=? AND stage='page'
              AND analyst_corrected=0 ORDER BY ts DESC,id DESC LIMIT 1""",
              (int(quality_onion_url_id),)).fetchone()
            quality_baseline = dict(baseline_row) if baseline_row else None
        canonical_url = hit["canonical_url"]
        if hit["onion_url_id"]:
            row = db.execute("SELECT url FROM onion_urls WHERE id=?", (hit["onion_url_id"],)).fetchone()
            url = row["url"] if row else None
            db.execute("""UPDATE onion_urls SET spain_priority=0,geo_priority=NULL,
              spain_match_reason=NULL,spain_match_language=NULL,spain_confidence=NULL,
              spain_context_tags=NULL,spain_alert_level=NULL,spain_alert_sent=0,
              spain_alert_sent_at=NULL,spain_review_status='ignored',spain_analyst_suppressed=1,
              spain_suppressed_at=? WHERE id=?""", (now, hit["onion_url_id"]))
        db.execute("""UPDATE spain_hits SET analyst_suppressed=1,suppressed_at=?,
          suppression_reason=?,review_status='ignored' WHERE id=?""", (now, reason, hit_id))
        db.execute("""UPDATE spain_alert_queue SET status='suppressed'
          WHERE status='pending' AND (url=? OR (site_tree_id=? AND normalized_family=?))""",
          (url or canonical_url, hit["site_tree_id"], hit["normalized_family"]))
        if site_card_id:
            db.execute("""INSERT INTO site_card_events(site_card_id,event_type,event_summary,
              safe_metadata_json,created_at) VALUES(?,?,?,?,?)""",
              (site_card_id, "spain_priority_removed", "Analyst removed page from Spain Priority",
               json.dumps({"url": url or canonical_url, "hit_id": hit_id,
                           "reason": reason}, ensure_ascii=False), now))
    if site_card_id:
        from site_dedupe import update_site_card_rollups
        update_site_card_rollups(int(site_card_id))
    insert_crawl_audit(url or canonical_url, "spain_priority", "analyst_suppressed", reason)
    if quality_category != "severe_abuse_risk":
        try:
            record_classification_feedback(
                subject=f"spain-hit:{hit_id}",
                feedback_scope="spain", feedback_action="spain_removed",
                reason_code="analyst_removed_spain_priority",
                decision_id=quality_baseline.get("id") if quality_baseline else None,
                onion_url_id=quality_onion_url_id,
                site_card_id=site_card_id,
                previous_category=quality_category,
                final_category=quality_category,
                classifier_version=(
                    quality_baseline.get("classifier_version")
                    if quality_baseline else None
                ),
                safe_metadata={
                    "scope": "spain_hit",
                    "spain_reason_code": quality_reason_code,
                    "confirmed": False,
                },
            )
        except (TypeError, ValueError, sqlite3.Error):
            pass
    return True


def queue_spain_alert(url: str, policy: dict, source_url: str | None = None) -> bool:
    if (policy.get("alert_allowed") is False
            or policy.get("classification_decision") == "unverified_restricted_candidate"
            or policy.get("primary_category") in {"adult_filtered", "adult_restricted", "severe_abuse_risk"}
            or policy.get("storage_policy") == "discard"
            or "adult_extreme_caution" in policy.get("risk_flags", [])):
        return False
    if not policy.get("spain_priority"):
        return False
    relevance = policy.get("spain_relevance")
    if policy.get("spain_context_only") or (
            relevance not in {None, "", "none"}
            and "spain_actionable" in policy and not policy.get("spain_actionable")):
        insert_crawl_audit(url, "spain_priority", "suppressed_context_only", "not_direct_spain_evidence")
        return False
    if relevance not in {None, "", "none"} and relevance not in {"medium", "high"}:
        insert_crawl_audit(url, "spain_priority", "suppressed_low_relevance", "weak_spain_signal")
        return False
    evidence_score = int(policy.get("spain_evidence_score") or (
        80 if policy.get("spain_confidence") == "high"
        and policy.get("spain_actionable", True) and not policy.get("spain_context_only") else 0))
    if evidence_score < 75:
        insert_crawl_audit(url, "spain_priority", "suppressed_below_threshold", "spain_evidence_below_75")
        return False
    if not is_onion_url_verified(url):
        insert_crawl_audit(url, "spain_priority", "suppressed_unverified", "page_not_verified")
        return False
    hit = persist_spain_priority(url, policy, source_url)
    if not hit:
        return False
    if policy.get("spain_confidence") != "high":
        return False
    category = policy.get("primary_category", "unknown")
    alert_categories = {"weapons_arms","drugs","fraud_financial","leaks_data","credentials","malware_hacking",
                        "extremist_recruitment","severe_abuse_risk","marketplace_weapons","marketplace_drugs",
                        "marketplace_fraud","marketplace_credentials","marketplace_leaks"}
    has_geo_context = "russian_geopolitical_context" in policy.get("spain_context_tags", [])
    if category not in alert_categories and not has_geo_context and "strong_institution_or_domain" not in policy.get("spain_context_tags", []):
        return False
    with get_db() as db:
        card = db.execute("""SELECT sc.* FROM site_cards sc JOIN onion_urls ou ON ou.site_card_id=sc.id
          WHERE ou.url=?""", (url,)).fetchone()
    card_data = dict(card) if card else {}
    if card_data.get("analyst_suppressed_alerts"):
        insert_crawl_audit(url, "spain_priority", "suppressed_by_analyst", "site_card_alert_suppressed")
        return False
    canonical_site_id = card_data.get("canonical_site_id") or url
    site_card_id = card_data.get("id")
    category = card_data.get("primary_category") or category
    risk_level = card_data.get("risk_level") or policy.get("risk_level")
    importance_level = card_data.get("importance_level") or policy.get("importance_level") or "normal"
    alert_level = card_data.get("spain_confidence") or policy.get("spain_confidence") or "high"
    with get_db() as db:
        prior_row = db.execute("""SELECT payload_json FROM spain_alert_queue
          WHERE site_tree_id=? OR (? IS NOT NULL AND site_card_id=?) ORDER BY id DESC LIMIT 1""",
          (hit["site_tree_id"], site_card_id, site_card_id)).fetchone()
        indicator_count = db.execute("""SELECT COUNT(DISTINCT il.indicator_id) FROM indicator_links il
          JOIN site_card_urls scu ON scu.url=il.source_ref WHERE scu.site_card_id=?""", (site_card_id,)).fetchone()[0] if site_card_id else 0
    prior = json.loads(prior_row[0]) if prior_row else {}
    has_prior = bool(prior)
    from urllib.parse import urlsplit
    source_family = (urlsplit(source_url or "").hostname or "manual").casefold()
    source_families = list(dict.fromkeys(list(prior.get("source_families") or []) + [source_family]))
    page_type = card_data.get("page_type") or policy.get("page_type") or "unknown"
    reason = card_data.get("spain_match_reason") or policy.get("spain_match_reason")
    reason_code = card_data.get("spain_priority_reason") or policy.get("spain_priority_reason") or "spain_country_reference"
    evidence_type = (card_data.get("spain_priority_evidence_type")
                     or policy.get("spain_priority_evidence_type") or "country_plus_threat")
    contexts = card_data.get("spain_context_tags") or policy.get("spain_context_tags") or []
    if isinstance(contexts, str):
        try: contexts = json.loads(contexts)
        except (TypeError, ValueError): contexts = []
    mirror_count = int(card_data.get("mirror_count") or 0)
    page_rank = {"search_page":1,"category_page":1,"directory_page":1,"homepage":1,
                 "thread_page":3,"post_page":3,"paste_page":2}.get(page_type, 0)
    previous_rank = {"search_page":1,"category_page":1,"directory_page":1,"homepage":1,
                     "thread_page":3,"post_page":3,"paste_page":2}.get(prior.get("page_type"), 0)
    direct_types = {"thread", "post"}
    hit_improved = hit["hit_type"] in direct_types and prior.get("hit_type") not in direct_types
    new_meaningful_family = (hit["normalized_family"] != prior.get("normalized_family")
                             and hit["hit_type"] in direct_types)
    risk_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4,
                 "bajo": 1, "medio": 2, "alto": 3, "critico": 4}
    importance_rank = {"low": 0, "normal": 1, "elevated": 2, "high": 3, "critical": 4}
    category_rank = {name: index for index, name in enumerate([
        "unknown", "directory_index", "forum_social", "marketplace", "fraud_financial",
        "marketplace_fraud", "drugs", "marketplace_drugs", "weapons_arms", "marketplace_weapons",
        "credentials", "marketplace_credentials", "leaks_data", "marketplace_leaks", "severe_abuse_risk",
    ])}
    material_contexts = (set(contexts) - set(prior.get("contexts") or [])) & {
        "city_plus_threat_context", "trade_flow_to_spain", "trade_flow_from_spain",
        "strong_institution_or_domain", "market_or_actor_context",
    }
    meaningful_update = (not has_prior
        or risk_rank.get(str(risk_level).casefold(), 0) > risk_rank.get(str(prior.get("risk_level")).casefold(), 0)
        or category_rank.get(str(category), 0) > category_rank.get(str(prior.get("category")), 0)
        or importance_rank.get(str(importance_level), 1) > importance_rank.get(str(prior.get("importance_level")), 1)
        or evidence_type != prior.get("evidence_type") or reason_code != prior.get("reason_code")
        or bool(material_contexts) or page_rank > previous_rank or hit_improved or new_meaningful_family
        or int(indicator_count) > int(prior.get("indicator_count") or 0)
        or mirror_count >= int(prior.get("mirror_count") or 0) + 3)
    if has_prior and not meaningful_update:
        return False
    fingerprint = hashlib.sha256(
        f"{site_card_id or hit['site_tree_id']}|{hit['onion_host']}|{category}|{risk_level}|{importance_level}|{reason_code}|{evidence_type}|{','.join(sorted(contexts))}|{page_rank}|{indicator_count}|{mirror_count // 3}".encode()
    ).hexdigest()
    payload = {
        "url": url, "source_url": source_url, "category": category,
        "risk_level": risk_level, "language": card_data.get("spain_match_language") or policy.get("spain_match_language"),
        "reason": reason, "reason_code": reason_code, "evidence_type": evidence_type,
        "confidence": alert_level, "contexts": contexts, "page_type": page_type,
        "importance_level": importance_level,
        "restricted": ((card_data.get("storage_policy") or policy.get("storage_policy")) in {"metadata_only", "metadata_limited"}
                       and category in {"marketplace_fraud", "fraud_financial", "severe_abuse_risk"}),
        "canonical_site_id": canonical_site_id, "site_card_id": site_card_id,
        "mirror_count": mirror_count, "indicator_count": int(indicator_count),
        "source_families": source_families,
        "site_tree_id": hit["site_tree_id"], "onion_host": hit["onion_host"],
        "normalized_family": hit["normalized_family"], "hit_type": hit["hit_type"],
        "total_urls": int(card_data.get("live_url_count") or 0) + int(card_data.get("dead_url_count") or 0),
        "alert_kind": "updated" if has_prior else "new",
    }
    with get_db() as db:
        cur = db.execute("""INSERT OR IGNORE INTO spain_alert_queue
          (url,fingerprint,payload_json,created_at,site_card_id,canonical_site_id,alert_kind,
           site_tree_id,normalized_family,hit_type)
          VALUES(?,?,?,?,?,?,?,?,?,?)""",
          (url, fingerprint, json.dumps(payload, ensure_ascii=False), utc_now_iso(),
           site_card_id, canonical_site_id, "updated" if has_prior else "new",
           hit["site_tree_id"], hit["normalized_family"], hit["hit_type"]))
        if cur.rowcount:
            db.execute("UPDATE spain_hits SET alert_count=alert_count+1,alert_state='alerted' WHERE id=?", (hit["id"],))
        return cur.rowcount > 0


def get_pending_spain_alerts(limit: int = 20) -> list[dict]:
    if spain_alerts_paused():
        return []
    with get_db() as db:
        return [dict(row) for row in db.execute("SELECT * FROM spain_alert_queue WHERE status='pending' ORDER BY id LIMIT ?", (limit,))]


def get_spain_alerts_for_manual_pull(limit: int = 5) -> list[dict]:
    """Return pending Spain alerts for explicit operator pull, ignoring push pause state."""
    with get_db() as db:
        return [dict(row) for row in db.execute(
            "SELECT * FROM spain_alert_queue WHERE status='pending' ORDER BY id DESC LIMIT ?",
            (max(1, min(int(limit or 5), 20)),))]


def get_urgent_cards_for_manual_pull(limit: int = 5) -> list[dict]:
    """Return safe Site Card summaries for explicit Telegram pull commands."""
    with get_db() as db:
        return [dict(row) for row in db.execute("""SELECT id,analyst_title,display_name,
          representative_url,primary_category,risk_level,importance_level,review_status,
          urgent_score,urgent_reason,spain_priority,updated_at
          FROM site_cards
          WHERE COALESCE(ui_hidden_default,0)=0
          AND (COALESCE(urgent_flag,0)=1 OR review_status='needs_report')
          AND review_status IN ('needs_review','needs_report','restricted')
          ORDER BY COALESCE(urgent_score,0) DESC,spain_priority DESC,updated_at DESC
          LIMIT ?""", (max(1, min(int(limit or 5), 20)),))]


def spain_alerts_paused() -> bool:
    with get_db() as db:
        row = db.execute("SELECT spain_alerts_paused FROM notification_control WHERE id=1").fetchone()
        return bool(row and row[0])


def set_spain_alerts_paused(paused: bool, updated_by: str = "dashboard") -> None:
    with get_db() as db:
        db.execute("""INSERT INTO notification_control(id,spain_alerts_paused,updated_at,updated_by)
          VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET spain_alerts_paused=excluded.spain_alerts_paused,
          updated_at=excluded.updated_at,updated_by=excluded.updated_by""",
          (int(paused), utc_now_iso(), updated_by[:80]))


def repair_spain_from_alert_queue(dry_run: bool = False) -> dict:
    with get_db() as db:
        rows = [dict(row) for row in db.execute("SELECT * FROM spain_alert_queue ORDER BY id")]
    result = {"alerts_read": len(rows), "onion_urls_updated": 0, "site_cards_updated": 0,
              "orphan_spain_urls": 0, "cards_flagged": 0, "dry_run": int(dry_run)}
    seen_cards = set()
    for row in rows:
        try: payload = json.loads(row.get("payload_json") or "{}")
        except (TypeError, ValueError): payload = {}
        url = row.get("url") or payload.get("url")
        if not url: continue
        with get_db() as db:
            existing = db.execute("""SELECT id,site_card_id,primary_category,risk_level,
              page_type,storage_policy FROM onion_urls WHERE url=?""", (url,)).fetchone()
        if not existing: continue
        card_id = row.get("site_card_id") or payload.get("site_card_id") or existing["site_card_id"]
        if not dry_run:
            policy = {
                "spain_priority": True, "spain_confidence": payload.get("confidence") or "high",
                "spain_match_language": payload.get("language"), "spain_match_reason": payload.get("reason"),
                "spain_context_tags": payload.get("contexts") or [],
                # Alert payloads are historical transport records, not content
                # evidence. Reuse only the current canonical URL truth here.
                "primary_category": existing["primary_category"] or "unknown",
                "risk_level": existing["risk_level"] or "low",
                "page_type": existing["page_type"] or "unknown",
                "storage_policy": existing["storage_policy"] or "safe_summary",
                "priority_score": 80,
            }
            persist_spain_priority(url, policy, payload.get("source_url"), card_id,
                                   row.get("canonical_site_id") or payload.get("canonical_site_id"))
        result["onion_urls_updated"] += 1
        if card_id: seen_cards.add(int(card_id))
        else: result["orphan_spain_urls"] += 1
    result["site_cards_updated"] = result["cards_flagged"] = len(seen_cards)
    return result


def set_spain_tree_review(site_tree_id: str, status: str) -> None:
    if status not in {"unreviewed", "keep", "ignored", "needs_report", "reported", "blocked"}:
        raise ValueError("Invalid Spain tree review status")
    quality_hit = None
    quality_baseline = None
    quality_hit_count = 0
    with get_db() as db:
        representative = db.execute("""SELECT onion_url_id,site_card_id,primary_category,
          reason_code FROM spain_hits WHERE site_tree_id=?
          ORDER BY evidence_score DESC,last_seen DESC,id DESC LIMIT 1""",
          (site_tree_id,)).fetchone()
        quality_hit = dict(representative) if representative else None
        quality_hit_count = int(db.execute(
            "SELECT COUNT(*) FROM spain_hits WHERE site_tree_id=?",
            (site_tree_id,),
        ).fetchone()[0])
        if quality_hit and quality_hit.get("onion_url_id"):
            baseline_row = db.execute("""SELECT id,classifier_version,final_category
              FROM classification_decisions WHERE onion_url_id=? AND stage='page'
              AND analyst_corrected=0 ORDER BY ts DESC,id DESC LIMIT 1""",
              (int(quality_hit["onion_url_id"]),)).fetchone()
            quality_baseline = dict(baseline_row) if baseline_row else None
        db.execute("UPDATE spain_hits SET review_status=? WHERE site_tree_id=?", (status, site_tree_id))
        db.execute("""UPDATE onion_urls SET spain_review_status=? WHERE id IN
          (SELECT onion_url_id FROM spain_hits WHERE site_tree_id=? AND onion_url_id IS NOT NULL)""",
          (status, site_tree_id))
        if status in {"keep", "needs_report", "reported"}:
            url_rows = [dict(row) for row in db.execute("""SELECT id,tags FROM onion_urls WHERE id IN
              (SELECT onion_url_id FROM spain_hits WHERE site_tree_id=? AND onion_url_id IS NOT NULL)""",
              (site_tree_id,))]
            for row in url_rows:
                try:
                    tags = json.loads(row.get("tags") or "[]")
                    if not isinstance(tags, list): tags = []
                except (TypeError, ValueError):
                    tags = []
                tags.extend(["spain_priority", "spain", "spain_confirmed"])
                db.execute("UPDATE onion_urls SET tags=? WHERE id=?",
                           (json.dumps(list(dict.fromkeys(tags)), ensure_ascii=False), row["id"]))
            card_rows = [dict(row) for row in db.execute("""SELECT id,tags,search_text FROM site_cards WHERE id IN
              (SELECT site_card_id FROM spain_hits WHERE site_tree_id=? AND site_card_id IS NOT NULL)""",
              (site_tree_id,))]
            for row in card_rows:
                try:
                    tags = json.loads(row.get("tags") or "[]")
                    if not isinstance(tags, list): tags = []
                except (TypeError, ValueError):
                    tags = []
                tags.extend(["spain_priority", "spain", "spain_confirmed"])
                tags = list(dict.fromkeys(tags))
                search_text = (str(row.get("search_text") or "") + " " + " ".join(tags)).casefold()[:8000]
                db.execute("UPDATE site_cards SET tags=?,search_text=?,updated_at=? WHERE id=?",
                           (json.dumps(tags, ensure_ascii=False), search_text, utc_now_iso(), row["id"]))
        db.execute("""UPDATE spain_alert_queue SET status='reviewed' WHERE status='pending'
          AND site_tree_id=?""", (site_tree_id,))
    feedback_action = (
        "spain_confirmed" if status in {"keep", "needs_report", "reported"}
        else "spain_removed" if status == "ignored"
        else None
    )
    quality_category = str((quality_hit or {}).get("primary_category") or "unknown")
    if feedback_action and quality_category != "severe_abuse_risk":
        try:
            record_classification_feedback(
                subject=f"spain-tree:{site_tree_id}",
                feedback_scope="spain", feedback_action=feedback_action,
                reason_code="analyst_spain_tree_review",
                decision_id=quality_baseline.get("id") if quality_baseline else None,
                onion_url_id=(quality_hit or {}).get("onion_url_id"),
                site_card_id=(quality_hit or {}).get("site_card_id"),
                previous_category=quality_category,
                final_category=quality_category,
                classifier_version=(
                    quality_baseline.get("classifier_version")
                    if quality_baseline else None
                ),
                safe_metadata={
                    "scope": "spain_tree",
                    "review_status": status,
                    "spain_reason_code": (quality_hit or {}).get("reason_code"),
                    "url_count": quality_hit_count,
                    "confirmed": feedback_action == "spain_confirmed",
                },
            )
        except (TypeError, ValueError, sqlite3.Error):
            pass


def mark_spain_alert_sent(alert_id: int, url: str, level: str) -> None:
    now = utc_now_iso()
    with get_db() as db:
        db.execute("UPDATE spain_alert_queue SET status='sent',sent_at=? WHERE id=?", (now, alert_id))
        db.execute("UPDATE onion_urls SET spain_alert_sent=1,spain_alert_sent_at=?,spain_alert_level=? WHERE url=?",
                   (now, level, url))


def queue_live_check(url: str) -> bool:
    with get_db() as db:
        cur = db.execute("""UPDATE onion_urls SET status='queued',next_crawl_at=?,priority_score=priority_score+1000
          WHERE url=? AND active=1 AND COALESCE(queue_policy,'normal')!='blocked'""", (utc_now_iso(), url))
        return cur.rowcount > 0


def clean_dead_links() -> int:
    with get_db() as db:
        cur = db.execute("""UPDATE onion_urls SET status='dead',active=0,next_crawl_at=NULL,
          dead_reason=COALESCE(dead_reason,CASE WHEN http_status=404 THEN 'http_404'
          WHEN http_status=410 THEN 'http_410' ELSE 'too_many_errors' END)
          WHERE active!=0 AND (http_status IN (404,410) OR error_count>=4)""")
        return cur.rowcount
