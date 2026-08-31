# Arachne

Arachne is an operator-controlled, safety-bounded collection and analysis workspace for
mapping onion sites, reviewing Site Cards, following public identity signals,
and prioritizing Spain-linked findings. Its staged pipeline separates network
fetching, page verification, Site Card rollups, previews, and optional advisory
discovery so that every expensive unit of work has one durable owner.

## Safety boundaries

- Onion traffic is fail-closed through the configured Tor transport.
- URL text, anchor text, and parent context are hints, not destination content
  classifications.
- Restricted destinations are metadata-limited and must not produce unsafe
  previews, snippets, screenshots, expansion, or raw-content fixtures.
- Clear-web discovery and automatic Telegram alerts are disabled by default.
- Tests use isolated databases and must not start a real crawl.
- Source releases exclude `.env`, databases, sessions, logs, reports, previews,
  screenshots, backups, virtual environments, and caches.

## Repository map

- `dashboard.py` and `dashboard_pages/`: Streamlit interface and workflows.
- `arachne.py`: Telegram control-bot entry point.
- `fetch_worker.py`: claims frontier URLs and performs approved Tor GETs.
- `verify_worker.py`: classifies fetched destination HTML and records evidence.
- `card_worker.py`: performs idempotent Site Card assignment and rollups.
- `preview_worker.py`: handles separately claimed, policy-eligible previews.
- `deep_discovery_worker.py`: disabled-by-default advisory enrichment.
- `storage.py`: canonical SQLite schema, migrations, claims, and persistence.
- `RUN_AFTER_UPLOAD.sh`: one supported server install/update/control entry point.
- `scripts/make_clean_release.py`: deterministic source-only release builder.

See [Architecture](docs/architecture.md) for the complete execution flow.

## Local development

Use a disposable environment and do not copy a production `.env` or database
into the source tree.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-lock.txt
python -m pytest -q
```

Start the dashboard only after configuring an isolated test database:

```bash
python -m streamlit run dashboard.py
```

See [Development](docs/development.md) and [Testing](docs/testing.md).

## Server install or update

The supported Ubuntu entry point is:

```bash
cd /root/arachne
sudo bash RUN_AFTER_UPLOAD.sh bootstrap
```

`/root/arachne` and the `arachne-*` systemd units are the canonical deployment
namespace. `bootstrap` detects a first installation versus existing state,
creates safe private configuration defaults when needed, and never invokes a
database reset. Use the guided menu for service control, diagnostics, backup,
and explicit recovery operations. A one-time migration path for
an installation using a different prior namespace is documented in
[Deployment](docs/deployment.md). Do not upload a live development folder.
Build or verify a clean source release first.

See [Deployment](docs/deployment.md), [Operator guide](docs/operator-guide.md),
and [Backup and recovery](docs/backup-and-recovery.md).

## Launch evidence

The staged launch record is under
[`docs/launch-readiness/`](docs/launch-readiness/00-inventory.md). It records
the extracted baseline separately from final validation so later fixes do not
rewrite the original evidence.

## License

Copyright is retained by ExperimentalSkid. No permission to copy, modify, or
redistribute this repository is granted; see [LICENSE](LICENSE).
