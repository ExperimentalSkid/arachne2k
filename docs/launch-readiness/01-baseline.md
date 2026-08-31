# 01 — Baseline

## Reproducible facts before productization edits

- Source manifest verification: passed for 236 files.
- Source tree hash:
  `3e5b27f177acc1d831dacce3bae25b7f65d7f95ba505c2681b21e7f3fb74be30`.
- Workspace hygiene: failed as expected because the isolated reference tree
  contained databases, runtime state, logs/backups, and caches.
- Focused deployment/release/handoff/fresh-state/hygiene tests:
  58 passed, 1 skipped in 3.54 seconds.
- The skip was the Linux-only launcher syntax test on the Windows inspection
  host.

## Initial documentation/package findings

- No root README or AGENTS file.
- No canonical architecture, configuration, deployment, operations, analyst,
  backup/recovery, security, or testing guides.
- No required `docs/launch-readiness/` evidence set.
- `docs/` was absent from the release selector.
- Workspace and handoff audits skipped virtual environments rather than
  reporting them.
- Data snapshots existed, but no automated restore/rollback command.
- Repeated update restore points had no explicit retention procedure.
- The existing engineering report predated the supplied archive and could not
  serve as final launch evidence.

Later results belong in [07 — Test evidence](07-test-evidence.md); this baseline
must not be rewritten to make later work appear cleaner.

