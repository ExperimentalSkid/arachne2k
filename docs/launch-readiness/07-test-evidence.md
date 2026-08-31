# 07 — Test evidence

## Evidence status

This record separates completed local release evidence from Ubuntu-host gates.
The current full suite was run after the repository audit fixes, CI additions,
configuration inventory, and staged forum parity correction.

## Recorded automated evidence

| Gate | Result | Scope or limitation |
|---|---:|---|
| Initial full-suite baseline | **850 passed, 1 skipped** | Baseline before productization |
| Integrated full suite checkpoint | **885 passed, 2 skipped** | Completed before final language refinements |
| Final post-refinement full suite | **902 passed, 2 skipped** | Frozen local source; 210.97 seconds |
| Repository-audit full suite | **912 passed, 2 skipped** | Current source; 209.38 seconds |
| Focused post-integration regressions | **88 passed** | Completed changes only; not a substitute for the final full suite |
| UX/product regressions | **117 passed** | Home, review, collections, Spain, cards, themes, permissions, and supporting workflows |
| Bilingual route matrix | **38/38 passed** | English and Spanish route coverage |
| Navigation matrix | **19/19 passed** | Primary navigation and deep-link coverage |
| Packaging/deployment/recovery gate | **83 passed, 2 skipped** | Skips are Windows-only launcher lifecycle tests |
| Repository compilation | **Pass** | `python -m compileall .` |
| Installed dependency consistency | **Pass** | `python -m pip check` |
| Shell syntax | **4/4 passed** | `RUN_AFTER_UPLOAD.sh`, `ops/install_systemd.sh`, and two scripts |
| Generated systemd unit syntax | **9/9 passed** | `systemd-analyze verify` against the exact generated unit bodies |

The systemd verifier emitted only Windows DrvFS mode warnings for disposable
test files. The launcher explicitly installs the real units with mode `0644`;
the warnings were not unit-syntax failures.

## Packaging and privacy boundary

The authoritative selector resolves to the file count recorded in
`SOURCE_MANIFEST.json`, and no selected
database, environment file, session, runtime directory, log, report, preview,
backup, cache, virtual environment, or nested archive.

The exact final byte count and tree hash are recorded in the embedded
`SOURCE_MANIFEST.json`. The working reference directory is intentionally not a clean direct-upload
folder: it contains databases, runtime settings, caches, logs, and backups.
Those findings are expected and are excluded by the source selector.

## Migration and database evidence

Migration testing used disposable extracted copies only. No live database or
analyst data was changed.

- The supplied archive's top-level main database was **4,376,776,704 bytes**
  with a **123,315,752-byte WAL**. SQLite reported the disposable copy as
  malformed. It was rejected before migration and was not recovered, modified,
  or used as release evidence.
- A clean **956,649,472-byte** database backup from the same archive passed
  `quick_check`, `integrity_check`, and foreign-key validation.
- That clean backup migrated from legacy schema version `0` to version `1`
  twice successfully. The first pass took 0.672 seconds and the idempotence pass
  took 0.516 seconds; post-migration integrity and foreign-key checks passed.
- The disposable dashboard access database also migrated twice successfully
  from version `0` to version `1`.
- The broader database/storage migration regression set completed with
  **103 passed**.

The schema now records explicit main and access database versions, upgrades the
supported legacy version through the existing additive path, and rejects a
database created by a newer release before schema writes.

## Backup and restore evidence

The disposable backup/restore rehearsal passed:

- candidate integrity and required-schema rejection;
- verified current-state rollback snapshot creation;
- same-filesystem staging and atomic publish;
- post-publish validation and automatic rollback behavior;
- access and main database separation;
- service stop/start ordering through the mocked launcher lifecycle; and
- bounded retention that never prunes unknown operator-created directories.

The backup, restore, and retention CLI help surfaces also returned successfully.
No rehearsal touched the supplied archive or workspace databases.

## OPSEC evidence and limitation

Static direct-fetch, policy, redaction, preview-safety, artifact-hygiene, and
OPSEC regression checks passed. The local validation environment did not have a
reachable Tor SOCKS endpoint or ControlPort. Therefore the real
`onion_worker.py --opsec-audit` network/control result is **not passed here**.
It must pass fail-closed on the Ubuntu deployment host.

## Deployment-host gates still pending

The clean release build records source/archive proof in its embedded manifest
and adjacent receipt. The following host-specific checks remain:

1. Ubuntu launcher lifecycle tests and verification of the installed systemd
   units.
2. Real Tor SOCKS/ControlPort OPSEC audit on Ubuntu.
3. Real dashboard, bot, worker, timer, and maintenance status after restart.
4. Recent journal review for crash loops, SQLite errors, Tor fallback, and
   credential or content leakage.
5. A final server-side backup plus disposable restore rehearsal.

Do not convert any pending item into a pass using an estimated, historical, or
pre-refinement result.
