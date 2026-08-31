# 03 — Execution plan

## Ordered stages

1. **Complete** — Preserve the archive and inventory source/runtime boundaries.
2. **Complete** — Record baseline source proof, tests, and known failures.
3. **Complete** — Stabilize repository, packaging, configuration, and
   documentation.
4. **Complete** — Validate database initialization, migrations, claims, and
   clean start.
5. **Complete** — Redesign information architecture and workflows where
   evidence showed confusion, while preserving safety and analyst state.
6. **Complete locally** — Validate worker, content-safety, access, alert, and
   operational paths. Real Tor and installed-service behavior remain Ubuntu
   deployment gates.
7. **Complete locally** — Run focused/full/offline/UI tests and rendered route
   inspection.
8. **Finalization gate** — Build, verify, extract, and retest the clean source
   archive.
9. **Deployment gate** — Run Ubuntu service, Tor, backup, restart, and journal
   checks after upload.
10. **Finalization gate** — Regenerate the final manifest once, complete the
    checklist/report, and retain exact evidence.

## Change discipline

Each coherent stage must establish its baseline, add focused regressions,
compile touched modules, inspect user behavior, review the diff for accidental
deletion or duplicate systems, and update the appropriate canonical document.

The final manifest is generated only after all parallel changes have converged.
Server-only checks remain open until they actually run on Ubuntu.
