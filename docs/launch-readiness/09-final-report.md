# 09 — Final launch-pass report

## Executive summary

Arachne has completed the substantial productization stage. The staged worker,
Tor fail-closed, content-safety, analyst-override, and private access boundaries
remain intact while the analyst interface, review workflows, permissions,
schema lifecycle, recovery tooling, packaging boundary, and operator
documentation have been brought into one coherent product.

This is the **local launch-candidate report**, not Ubuntu deployment sign-off.
The final post-refinement suite passes. The adjacent release receipt records
the post-build archive hash; real Ubuntu service, Tor, backup, and journal gates
remain deployment-host requirements.

## Productization completed

### Analyst interface and information architecture

- Reworked Home into a clearer operational overview with direct paths to the
  work that needs attention.
- Clarified review lanes, classification state, actionable queues, collection
  views, and Watchlists so routine monitoring does not require technical
  database knowledge.
- Consolidated navigation and deep-link behavior across the primary product
  routes.
- Improved Spain Priority pages, evidence access, review state, card markers,
  and Spain-specific workflows without changing Spain classification policy.
- Improved Site Card density, hierarchy, titles, technical disclosure,
  analyst actions, report access, and safe restricted-state presentation.
- Replaced competing style layers with one restrained visual system for cards,
  forms, filters, tables, dialogs, empty states, and responsive layouts.
- Verified the English/Spanish route matrix and localized built-in Watchlists
  at display time while preserving canonical and user-created stored text.

### Permissions and workflow safety

- Applied RBAC capabilities to analyst mutation surfaces and made denied or
  read-only states explicit.
- Preserved analyst title, category, importance, notes, review state, reports,
  alert suppression, and Spain review state through automated recalculation.
- Kept navigation and read access separate from mutation authority.

### Schema and recovery

- Added explicit main and access database schema versions.
- Preserved the additive, rerunnable legacy migration path and added a
  fail-closed guard for databases created by newer releases.
- Added controlled database restore with candidate integrity/schema checks,
  stopped-writer enforcement, verified rollback snapshots, same-filesystem
  staging, atomic publication, post-publish validation, automatic recovery, and
  bounded retention.
- Kept crawler and dashboard-access database recovery independent.

### Packaging, operations, and documentation

- Added the product, architecture, configuration, development, deployment,
  operator, analyst, security, testing, backup/recovery, and launch-evidence
  documentation set.
- Included documentation in the authoritative deterministic source selector.
- Made runtime/private artifacts and virtual environments explicit direct-folder
  hygiene findings without traversing dependency trees.
- Kept the source selector free of reference databases, `.env`, sessions,
  runtime data, logs, reports, previews, backups, caches, virtual environments,
  and nested archives.
- Documented the distinction between a database restore point and a source-code
  rollback.

## Validation completed

The exact evidence is maintained in
[07 — Test evidence](07-test-evidence.md). Current highlights are:

- baseline full suite: **850 passed, 1 skipped**;
- integrated pre-final full suite: **885 passed, 2 skipped**;
- focused post-integration regressions: **88 passed**;
- UX/product regressions: **117 passed**;
- bilingual routes: **38/38 passed**;
- navigation routes: **19/19 passed**;
- packaging/deployment/recovery gate: **83 passed, 2 Windows-only skips**;
- repository `compileall` and `pip check`: **passed**;
- source shell syntax: **4/4 passed**;
- generated systemd unit syntax: **9/9 passed**.
- final post-refinement full suite: **902 passed, 2 skipped**.

The selector identifies 266 source files and selects no reference or runtime
data. Exact final bytes and the source-tree hash are in the embedded
`SOURCE_MANIFEST.json`.

## Database and recovery findings

The supplied archive's disposable top-level 4.38 GB main database copy failed
SQLite integrity validation. It was safely excluded before migration and no
recovery was attempted.

A clean 956 MB backup from the same archive passed integrity and foreign-key
checks, migrated from legacy schema version `0` to version `1`, and passed a
second idempotence migration. The access database did the same. The broader
database/storage migration gate completed with 103 passed tests.

The disposable backup/restore rehearsal also passed candidate rejection,
rollback preservation, atomic publish, post-publish rollback, access/main
separation, and bounded-retention behavior. No live or reference data was
modified.

## OPSEC status

Code and policy checks for fail-closed transport, direct-fetch prevention, log
redaction, preview safety, and artifact hygiene pass.

The local environment did not expose a reachable Tor SOCKS endpoint or Tor
ControlPort. A real network/control OPSEC pass cannot be claimed locally. It
must succeed on the Ubuntu host before launch; failure is a release blocker.

## Deployment

Follow [Production deployment](../deployment.md). The supported server entry
point remains:

```bash
cd /root/arachne
bash RUN_AFTER_UPLOAD.sh
```

Use `fresh-install` only for an intentional zero-state launch. Use
`safe-update` when preserving analyst data. Retain the previous verified source
archive outside the live project because database restore points do not provide
source rollback.

## Remaining deployment-host gates

1. On Ubuntu, run the Linux launcher lifecycle tests and verify the installed
   systemd units.
2. Run the real Tor SOCKS/ControlPort OPSEC audit with no direct-network
   fallback.
3. Restart the dashboard, bot, all workers, and maintenance timer; inspect
   status and recent journals.
4. Create and integrity-check a final server backup, then rehearse a disposable
   restore.

## Known limitations and accepted future work

- Source rollback requires a separately retained verified source archive;
  database restore never changes source code.
- Backup retention is count-bounded, but capacity and off-host retention still
  require operator monitoring.
- Dependency ranges are not yet a fully reproducible Linux lock.
- Current services run as root with systemd hardening. Moving to a dedicated
  service account remains a future permission migration and must not be rushed
  into this release.

## Release artifact

The clean upload folder is delivered as `deliverables/arachne` and
the matching archive as `deliverables/Arachne-launch-ready-20260728.zip`.
`Arachne-launch-ready-20260728.release.json` records the exact archive byte
size, SHA-256, selected file count, source-tree hash, and verification results.
The supplied operational backup archive is not a release artifact.
