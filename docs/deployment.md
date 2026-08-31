# Production deployment

## Preconditions

- Ubuntu host with root access for systemd installation.
- Python 3.12 with `venv` support.
- Tor available on the configured SOCKS endpoint, or Ubuntu `apt` access so
  `bootstrap` can install and start it.
- Enough free space for the virtual environment, database, WAL growth, logs,
  and at least one verified database snapshot.
- A private `.env`, or permission for `bootstrap` to create it from safe defaults;
  Telegram administrator configuration is optional.
- A source tree or archive that passes the authoritative manifest check.

The product is Arachne. `/root/arachne` and the `arachne-*` systemd names are
its canonical deployment namespace.

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
sudo bash RUN_AFTER_UPLOAD.sh bootstrap
```

`bootstrap` requires Python 3.12, verifies the source manifest, creates a mode
`0600` root-owned `.env` from safe defaults when absent, and detects existing
databases or canonical service units. A zero-state host uses normal idempotent
initialization without a reset; detected existing state uses the restore-point-
protected update path. The first installation also prints a one-hour dashboard
access code. `fresh-install` remains an explicitly destructive recovery command
and is not part of ordinary installation.

Telegram is an optional integration. When its API ID, API hash, bot token, or
administrator ID is absent, installation continues with `arachne-bot.service`
stopped and disabled. The dashboard, crawler workers, and maintenance timer are
unaffected. After completing the Telegram settings, run
`bash RUN_AFTER_UPLOAD.sh bot-start` to validate them and enable the bot.

The worker services start after a successful install, but a fresh database has
no crawl work until a starting onion is deliberately added. Use `pause` before
adding the first seed if an explicit maintenance window is required.

## One-time migration from a prior namespace

If the server already runs this code under a different project or systemd
prefix, take a verified source and database snapshot before changing anything.
Then retire only the exact prior service namespace:

```bash
cd /root/arachne
sudo ARACHNE_PREVIOUS_SERVICE_PREFIX='<exact-prior-prefix>' \
  bash RUN_AFTER_UPLOAD.sh retire-previous-services
```

The prefix must be a simple systemd-safe name and cannot be `arachne`. The
command stops, disables, and removes only the known service suffixes under that
prefix. It does not delete project data.

If a prior SQLite file used another safe basename, pass it explicitly during
the migration run so snapshots, permission repair, diagnostics, and an
intentional wipe include it:

```bash
sudo ARACHNE_PREVIOUS_DB_FILE='<prior-file>.db' \
  bash RUN_AFTER_UPLOAD.sh safe-update
```

This does not silently merge or replace databases. The active crawler database
is `messages.db`; migrate a differently named verified database with the
controlled `restore-db main` workflow in
[Backup and recovery](backup-and-recovery.md). If daily backup archives used a
different prefix, set `ARACHNE_PREVIOUS_BACKUP_PREFIX` in the private `.env`
until their retention window expires. Remove all three migration settings once
the old namespace is no longer needed.

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

Running `bootstrap` is also safe here: existing deployment state selects this
same protected update path rather than first-install initialization.

Before either operation, run the non-mutating prerequisite check when desired:

```bash
bash RUN_AFTER_UPLOAD.sh doctor
```

`doctor` does not install packages, create files, alter databases, or change
services. The separate `post-upload-doctor` command remains a mutating verified
update workflow and is named explicitly for that reason.

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
