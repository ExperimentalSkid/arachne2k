# Architecture

## Product boundary

Arachne is one Python application deployed as separate processes around a
shared SQLite persistence layer. Streamlit supplies the analyst interface;
Telethon supplies the private control bot; systemd owns long-running processes.
The crawler is an assembly line, not a set of workers competing for the same
URL.

## Execution flow

1. A starting onion or discovered destination enters `onion_urls`.
2. A fetch worker atomically claims one eligible URL, commits the claim, then
   performs the approved text-oriented Tor request.
3. The fetch stage stores one bounded fetched-page snapshot and discovered-link
   records, then marks classification pending.
4. A verify worker atomically claims the fetched page, classifies only the
   destination HTML, records bounded evidence, and creates one card job when
   appropriate.
5. A card worker claims that job and a per-card lease, then performs idempotent
   identity assignment, rollups, profile refresh, and mirror reconciliation.
6. A preview worker separately claims policy-eligible preview jobs. A blocked
   preview never falls back to an unrestricted path.
7. The advisory Deep Discovery worker is disabled by default and cannot become
   an authority for live identity, classification, Spain, urgency, or crawling.
8. One maintenance leader performs bounded global maintenance.

Claim transitions, retries, stale-claim recovery, and dead-letter behavior live
in `storage.py`; process orchestration lives in the worker entry points.

## Data boundaries

- Main database: `messages.db` by default.
- Access-code/session database: `runtime/dashboard_access.db`.
- Runtime settings: `runtime_settings.json`, allowlisted by `config_loader.py`.
- Generated operational data: `logs/`, `reports/`, `backups/`, and `runtime/`.
- Source identity: `SOURCE_MANIFEST.json`, generated from the authoritative
  source selector in `scripts/make_clean_release.py`.

The access database is separate so a crawler-database failure does not silently
disable the dashboard access gate or Telegram code path.

Both databases use SQLite `PRAGMA user_version` as an explicit release-schema
boundary. Version `0` is the supported legacy baseline and follows the existing
ordered, additive, idempotent migrations. A successful migration stamps the
current version only after all schema and normalization steps finish. A
database stamped by a newer Arachne release is rejected before schema writes
instead of being silently downgraded.

## Identity and classification boundaries

URL identity, page type, content category, safety state, risk, importance,
Spain relevance, urgency, and analyst overrides are separate dimensions.
Same-host Site Card identity is deterministic; cross-host mirror assignment
requires stronger safe evidence. Analyst-owned fields are never overwritten by
automated rollups.

## Deployment relationships

`RUN_AFTER_UPLOAD.sh` writes the canonical systemd units for dashboard, bot,
fetch, verify, card, preview, Deep Discovery, and maintenance. The old
`ops/install_systemd.sh` is only a compatibility wrapper around that launcher;
there is no second unit source.

See [Deployment](deployment.md), [Security](security.md), and
[Data model and clean start](launch-readiness/04-data-model.md).
