# 00 — Inventory

## Preserved baseline

The supplied archive remains unchanged. Work is performed in the isolated
`arachne-productization-20260728` extraction. The extracted reference database
is used only to understand realistic workflow states; it is excluded from every
source release.

At extraction the authoritative manifest described 236 source files,
3,763,198 bytes, with tree SHA-256
`3e5b27f177acc1d831dacce3bae25b7f65d7f95ba505c2681b21e7f3fb74be30`.
That hash is baseline evidence, not the final post-change receipt.

## Entry points and services

- Streamlit: `dashboard.py`
- Telegram: `arachne.py`
- Staged workers: `fetch_worker.py`, `verify_worker.py`, `card_worker.py`,
  `preview_worker.py`, `deep_discovery_worker.py`
- Maintenance/CLI: `onion_worker.py`, `scripts/run_maintenance.py`
- Persistence: `storage.py`, `dashboard_auth.py`
- Server control: `RUN_AFTER_UPLOAD.sh`
- Release proof: `scripts/make_clean_release.py`,
  `scripts/handoff_receipt.py`, `SOURCE_MANIFEST.json`

## Runtime and private state found

The isolated reference tree contains expected database/runtime/cache material
used for validation. The workspace audit identifies it as non-releasable. The
source selector excludes:

- `.env` and runtime settings
- SQLite databases and sidecars
- Telegram sessions
- logs, reports, previews, screenshots, backups, and runtime directories
- virtual environments and dependency trees
- Python/test caches
- nested archives and temporary/backup files

## Repository condition

The extracted tree has no Git history. A local change review must therefore use
file/diff inspection and the deterministic source manifest. Canonical component
relationships are documented in [Architecture](../architecture.md).

