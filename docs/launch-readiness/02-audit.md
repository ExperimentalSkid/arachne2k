# 02 — Product and engineering audit

## Confirmed strengths

- Atomic staged claims and per-card locking are represented in code and tests.
- Tor and direct-fetch boundaries fail closed.
- Destination-scoped classification separates URL hints from fetched HTML.
- Restricted-content storage/preview/expansion boundaries have focused tests.
- Source releases are deterministic, manifest-verified, and source-selected.
- The launcher is the canonical service/control path and has broad regression
  coverage.
- Operational logs and diagnostics are bounded and redacted.

## Confirmed launch gaps at baseline

1. Required product/operations documentation was missing and not packageable.
2. Direct-folder audits could overlook a large `.venv`/`venv`.
3. Restore staging existed without a bounded launcher restore transaction.
4. In-place source rollback depended on an external prior archive but was not
   stated clearly.
5. Manual/update/config/stale-source backup retention was not consistently
   bounded.
6. Dependency ranges did not provide a fully reproducible Linux lock.
7. Linux systemd/Tor behavior still required deployment-host validation.
8. Historical reports contained stale test/file counts and compatibility
   terminology.

## Prioritized issue matrix

| ID | Severity | User impact | Technical risk / dependency | Disposition |
|---|---|---|---|---|
| UI-01 | High | Overview repeated weak metrics and actions without a clear next step. | Depended on truthful queue and worker-state queries. | Resolved with an attention-first workbench, review lanes, system health, and recent Site Cards. |
| UI-02 | High | Review work mixed urgency, classification uncertainty, and report work, producing noisy queues. | Depended on existing urgency and review semantics remaining unchanged. | Resolved with separate actionable lanes, useful filters/sort, and explicit risk-versus-importance language. |
| UI-03 | High | Collection filtered only the first 1,000 URLs in memory, so counts and later pages could be wrong. | Required SQL-safe filtering, exact counts, and bounded pagination. | Resolved with database-backed search/filter/count/pagination and record inspection. |
| UI-04 | High | Spain card-level leads and exact-page cases could show contradictory zero counts or imply evidence that was not stored. | Spain detection itself could not change. | Resolved by separating card-level leads from exact pages and never inventing a source page. |
| UI-05 | Medium | Mixed English/Spanish copy, raw internal worker terms, and competing visual layers reduced trust. | Required preserving stable widget keys and both themes. | Resolved with one design cascade, bilingual route content, localized built-ins, and consistent status terminology. |
| PERF-01 | High | Alias cleanup and consistency audits ran during ordinary page render and could block on a large database. | Required retaining explicit analyst/admin tools. | Resolved by moving both scans behind explicit authorized controls and caching only requested results. |
| SEC-01 | High | Several modular pages exposed mutation paths without one consistent capability boundary. | Required preserving analyst workflows and a read-only demo role. | Resolved with server-side capability checks plus disabled UI controls; unknown roles fail closed. |
| DATA-01 | High | Schema upgrades were additive but had no explicit durable version gate. | Required compatibility with empty and legacy SQLite files. | Resolved with main/access `PRAGMA user_version`, ordered version-0 migration, idempotence, and future-version rejection. |
| PIPE-01 | High | Verification could appear complete before all downstream card/entity work had succeeded. | Required preserving staged claims and retry ownership. | Resolved so completion is recorded only after the full verification unit succeeds. |
| OPS-01 | High | Restore and retention behavior was not one bounded, recoverable operator transaction. | Required stopped writers, integrity checks, and source/data rollback separation. | Resolved with staged database restore, verified rollback, automatic recovery, and bounded recognized retention. |
| REL-01 | Medium | Direct-folder handoff could include runtime/private state and lacked a complete runbook set. | Required deny-by-default source selection. | Resolved through hygiene checks, deterministic source manifests, and packaged operations documentation. |
| OPS-02 | High | Real Tor, installed systemd services, filesystem permissions, and journals are host-specific. | Requires the Ubuntu deployment host. | Open deployment gate; exact commands are in the release checklist. |
| DEP-01 | Medium | Dependency ranges are not a fully reproducible Linux lock. | A lock refresh needs Linux compatibility/security testing. | Accepted launch limitation; `pip check` is clean and the complete suite passes. |
| SVC-01 | Medium | Services still run as root. | Moving to a dedicated account changes database/session/runtime ownership. | Accepted post-launch hardening item; current units retain systemd restrictions. |

## Architecture and workflow outcome

- The staged fetch → verify → card → preview/deep-discovery ownership model was
  retained; launch work strengthened completion, authorization, recovery, and
  observability boundaries instead of replacing it.
- Streamlit remains the product shell, but Home, Review Inbox, Collection,
  Spain Priority, Site Card dossiers, Operations, Settings, FAQ, and secondary
  intelligence pages now have clearer responsibilities and consistent actions.
- SQLite remains appropriate for the current single-host deployment. WAL,
  bounded claims, explicit schema versions, backups, integrity checks, and
  transaction-safe restore are preferable to introducing an unproven database
  platform immediately before launch.
- Network, classification, Spain, urgency, restricted-content, crawl-depth, and
  analyst-override policies were preserved unless a confirmed correctness bug
  required a narrowly tested change.

## Decisions

- Preserve the staged worker and SQLite architecture.
- Keep one launcher and one systemd-unit source.
- Add one cross-linked documentation system instead of duplicate runbooks.
- Include `docs/` in the same authoritative release selector.
- Report virtual environments once without enumerating dependencies.
- Add a bounded database-only restore transaction with isolated failure tests;
  keep source rollback explicitly separate.
- Keep legacy server path/unit identifiers for compatibility and label them as
  such.

Security details are in [06 — Security review](06-security-review.md).
