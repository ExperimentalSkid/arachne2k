# 08 — Release checklist

Checked items have exact evidence in
[07 — Test evidence](07-test-evidence.md). Unchecked items remain release
gates; they are not implied passes.

## Source and privacy

- [x] Authoritative release selector excludes reference/runtime/private data.
- [x] Required documentation is included by the selector.
- [x] Source edits frozen.
- [ ] Final source manifest regenerated after all edits.
- [ ] Exact source verification passes against that final manifest.
- [ ] Clean archive contains all required source, tests, assets, and
      documentation.
- [ ] Clean archive contains no `.env`, database, session, runtime state, log,
      report, preview, screenshot, backup, cache, virtual environment, or nested
      archive.
- [ ] Two builds from identical final source have byte-identical hashes.

The current working directory is not suitable for direct upload because it
contains intentional reference/runtime artifacts. Use the final selector-built
release.

## Engineering and data

- [x] Repository `compileall` passes.
- [x] `pip check` passes.
- [x] Baseline full suite passes with its documented skip.
- [x] Pre-final integrated full suite passes with documented skips.
- [x] Focused post-integration regression gates pass.
- [x] Final post-refinement full suite passes: 902 passed, 2 skipped.
- [x] Empty main and access databases initialize and rerun without drift.
- [x] Clean copied legacy database migration and idempotence checks pass.
- [x] Newer unsupported schema versions fail before schema writes.
- [x] Mocked staged workflow and analyst-state preservation regressions pass.
- [x] Consistency and repair dry-runs are clean on fresh/synthetic test
      databases; the visual fixture's noncanonical labels are intentionally
      excluded from the release.

## Product and analyst workflow

- [x] Home, review lanes, collections, Spain workflows, Site Cards, dialogs,
      themes, RBAC states, and recovery surfaces received the productization
      pass.
- [x] Automated UX/product regression gate passes.
- [x] Bilingual route matrix passes 38/38.
- [x] Navigation matrix passes 19/19.
- [x] Built-in Watchlists localize without rewriting canonical or user-created
      data.
- [x] Risk, importance, review state, Spain relevance, and analyst overrides
      remain separate concepts.
- [ ] Final extracted-release inspection confirms realistic-density tables,
      queues, dialogs, empty states, denied states, restricted states, and both
      themes in the shipped artifact.

## Backup, restore, and recovery

- [x] Disposable candidate rejection and schema validation pass.
- [x] Disposable rollback preservation, atomic publish, failure rollback, and
      bounded retention rehearsal passes.
- [x] Main and access database restore paths remain separate.
- [ ] Final server backup completes and is integrity-checked.
- [ ] Final server disposable restore rehearsal passes.
- [ ] Server free-space margin and retention are reviewed.
- [ ] Previous verified source release is retained outside the live project.

## Server, services, and OPSEC

- [x] All four source shell scripts pass static syntax validation.
- [x] All nine generated service/timer definitions pass static
      `systemd-analyze verify`.
- [x] OPSEC code, policy, direct-fetch, redaction, and artifact checks pass.
- [ ] Linux-only mocked launcher lifecycle tests pass on Ubuntu.
- [ ] Installed Ubuntu systemd units pass verification.
- [ ] Real Tor SOCKS and ControlPort OPSEC audit passes without fallback.
- [ ] Dashboard, Telegram bot, fetch, verify, card, preview, Deep Discovery, and
      maintenance services are stable after restart.
- [ ] Telegram access-code flow works; alert configuration matches the intended
      launch state.
- [ ] Recent journals show no crash loop, database I/O failure, Tor bypass, or
      sensitive logging.
- [ ] A freshly built sanitized diagnostic bundle is inspected for secrets and
      raw collected content.

## Sign-off

- [ ] [Final report](09-final-report.md) contains the final manifest, archive,
      extracted-release, Ubuntu service, Tor, backup/restore, and journal
      evidence.
- [ ] Operator sign-off is recorded only after every mandatory unchecked item
      above is resolved or explicitly accepted as a documented risk.
