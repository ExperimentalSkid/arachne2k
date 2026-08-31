# 04 — Data model

## Storage domains

- `messages.db`: crawler frontier, fetched pages, verification state, Site
  Cards, jobs, evidence, profiles, alerts/review state, and operations.
- `runtime/dashboard_access.db`: dashboard codes and sessions shared by the
  dashboard and Telegram control path.
- `runtime_settings.json`: allowlisted non-secret UI/operational preferences.

`storage.init_db()` is idempotent and is the canonical schema/migration entry
point. Tests initialize it against temporary empty databases.

## Explicit versions and upgrade rules

- `messages.db` uses main schema version `1`.
- `runtime/dashboard_access.db` uses access schema version `1`.
- Both versions are stored in SQLite `PRAGMA user_version`.
- A legacy version-0 database receives the existing additive normalization
  inside one controlled initialization flow and is stamped only after success.
- Reopening the same database is idempotent.
- A database with a newer version than the running source is rejected before
  application writes, so an accidental source rollback fails closed.
- Version changes require focused empty, repeat-init, copied-legacy, and
  future-version rejection tests.

## Ownership and identity

- Fetch workers own `onion_urls` claims.
- Verify workers own `fetched_pages` classification claims.
- Card workers own `site_card_jobs` and acquire a per-card lock.
- One maintenance leader owns global maintenance.
- Same-host Site Card identity is deterministic; cross-host mirror matching is
  separate and evidence-weighted.

## Data invariants

- A work item has at most one active claim.
- Stale claims recover only after their lease.
- Retries are bounded and reason-coded.
- Analyst-owned title/category/notes/importance/review/report/alert state
  survives rollup and merge.
- Restricted records retain minimal anti-retry metadata and cannot persist
  unsafe artifacts.
- Page classification provenance belongs to destination HTML.

## Migration gate

Every schema change requires an empty-database test, an idempotent second init,
and a copied-database migration test when legacy state is relevant. Never bind a
migration to the supplied reference database.

See [05 — Migrations and clean start](05-migrations-and-clean-start.md).
