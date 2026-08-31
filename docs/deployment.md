# Production deployment

## Preconditions

- Ubuntu host with root access for systemd installation.
- Python 3 with `venv` support.
- Tor available on the configured SOCKS endpoint.
- Enough free space for the virtual environment, database, WAL growth, logs,
  and at least one verified database snapshot.
- A private `.env` containing valid Telegram administrator configuration.
- A source tree or archive that passes the authoritative manifest check.

The product is Arachne. The existing `/root/arachne` directory and
`arachne-*` systemd names are retained as compatibility identifiers.

## Build a clean source release

From a clean development tree:

```bash
python scripts/make_clean_release.py --audit-workspace --fail-on-dirty-workspace
python scripts/make_clean_release.py ../arachne-clean-release.zip
python scripts/make_clean_release.py --verify-archive ../arachne-clean-release.zip
```

The archive contains source, tests, assets, documentation, and its manifest. It
does not contain `.env`, databases, sessions, logs, reports, backups, previews,
screenshots, virtual environments, or caches.

## First installation

Extract the verified archive so its source root becomes
`/root/arachne`, then:

```bash
cd /root/arachne
bash RUN_AFTER_UPLOAD.sh configure-env
bash RUN_AFTER_UPLOAD.sh fresh-install
bash RUN_AFTER_UPLOAD.sh status
```

`fresh-install` is intentionally destructive to crawler and dashboard-access
SQLite state. It preserves source, `.env`, Telegram credentials, Telegram
sessions, and existing backups. Do not use it for an update that must preserve
analyst data.

The worker services start after a successful install, but a fresh database has
no crawl work until a starting onion is deliberately added. Use `pause` before
adding the first seed if an explicit maintenance window is required.

## Safe in-place update

Preserve the previous verified source archive outside the live source
directory. Upload only the clean source contents; do not configure FTP/SFTP to
delete `.env`, databases, runtime, sessions, or backups. Then run:

```bash
cd /root/arachne
bash RUN_AFTER_UPLOAD.sh safe-update
bash RUN_AFTER_UPLOAD.sh status
bash RUN_AFTER_UPLOAD.sh logs
```

The update verifies the exact uploaded source before mutation, quarantines only
stale source selected by the previous direct-folder layout, stops SQLite
writers, creates database/config snapshots, validates code and OPSEC, applies
idempotent initialization, and restarts services.

The automatic restore point is a data/config snapshot, not a copy of the
previous source version. The controlled `restore-db` command can restore main
or dashboard-access SQLite state, but source rollback still requires the
previous clean release archive retained before upload. See
[Backup and recovery](backup-and-recovery.md).

## System services

The launcher writes and owns:

- `arachne-dashboard.service`
- `arachne-bot.service`
- `arachne-fetch-worker.service`
- `arachne-verify-worker.service`
- `arachne-card-worker.service`
- `arachne-preview-worker.service`
- `arachne-deep-discovery-worker.service`
- `arachne-maintenance.service`
- `arachne-maintenance.timer`

After installation validate on Linux:

```bash
bash -n RUN_AFTER_UPLOAD.sh
systemd-analyze verify /etc/systemd/system/arachne-*.service \
  /etc/systemd/system/arachne-maintenance.timer
systemctl daemon-reload
bash RUN_AFTER_UPLOAD.sh validate
bash RUN_AFTER_UPLOAD.sh status
journalctl -u 'arachne-*' --since '-10 minutes' --no-pager
```

## Optional dashboard onion

```bash
bash RUN_AFTER_UPLOAD.sh deploy-onion
bash RUN_AFTER_UPLOAD.sh onion-status
```

The launcher binds the Streamlit backend to loopback when the onion service is
deployed and keeps the dashboard access-code lock enabled.

## Launch decision

Complete every item in the
[release checklist](launch-readiness/08-release-checklist.md). Do not treat a
passing source manifest as proof of database, Tor, systemd, or UI readiness.
