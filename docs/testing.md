# Testing and validation

## Offline gates

```bash
python -m compileall .
python -m pytest -q
python -m pip check
```

Use focused tests while iterating, then run the complete suite. Important
focused groups include:

```bash
python -m pytest -q \
  tests/test_deployment_readiness.py \
  tests/test_release_hygiene.py \
  tests/test_handoff_receipt.py \
  tests/test_fresh_zero_state.py \
  tests/test_workspace_hygiene_and_worker_lifecycle.py
```

All database tests must use isolated temporary databases. Network tests should
mock the transport; they must not send Telegram messages, start a real crawl,
or contact clear-web providers.

## Release gates

```bash
python scripts/make_clean_release.py --audit-workspace --fail-on-dirty-workspace
python scripts/make_clean_release.py ../arachne-clean-release-a.zip
python scripts/make_clean_release.py ../arachne-clean-release-b.zip
python scripts/make_clean_release.py --verify-archive ../arachne-clean-release-a.zip
```

The two archives should have identical hashes for the same source. Extract one
into a new temporary directory, create a new virtual environment, run the full
suite, and confirm no private/runtime files are present.

## Fresh-state gate

Against a disposable directory/database:

1. Initialize schema from zero.
2. Verify the empty dashboard and access storage.
3. Run a safe mocked fetch → verify → card workflow.
4. Restart initialization and verify idempotence/persistence.
5. Confirm no crawler work exists until a seed is deliberately queued.

## UI gate

Inspect every primary page and major dialog with safe realistic fixtures plus
empty, loading, error, denied, and restricted states. Verify both themes,
English/Spanish behavior, navigation callbacks, tables at realistic density,
keyboard focus, and narrow viewport behavior.

## Ubuntu server gates

```bash
bash -n RUN_AFTER_UPLOAD.sh
systemd-analyze verify /etc/systemd/system/arachne-*.service \
  /etc/systemd/system/arachne-maintenance.timer
bash RUN_AFTER_UPLOAD.sh validate
bash RUN_AFTER_UPLOAD.sh status
bash RUN_AFTER_UPLOAD.sh diagnostics
```

Also run the real Tor OPSEC audit, a disposable backup/restore rehearsal, and
inspect recent journals after restart. Record exact results in
[`launch-readiness/07-test-evidence.md`](launch-readiness/07-test-evidence.md).

