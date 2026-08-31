# Backup and recovery

## What is backed up

The launcher knows the main crawler database (`messages.db`, with legacy
`arachne.db` compatibility) and the dashboard access database
(`runtime/dashboard_access.db`). It uses SQLite's backup API rather than copying
an open database file.

Create a manual verified snapshot:

```bash
cd /root/arachne
bash RUN_AFTER_UPLOAD.sh backup-db
```

Automatic daily backups created by `backup_service.py` retain a bounded rolling
set and exclude preview/screenshot artifacts. The launcher also applies
count-based retention after successfully creating or using operational
artifacts:

- manual database snapshots: 7
- pre-update restore points: 3
- pre-restore database rollbacks: 5
- private configuration backups: 5
- reconciled stale-source snapshots: 3

These defaults can be changed for one control run with the documented
`ARACHNE_KEEP_*` environment flags. At least one recognized artifact is always
retained. Unknown/operator-created backup directories are never pruned.

## Recovery principles

- Never replace a live SQLite database while dashboard, bot, workers, or
  maintenance may still hold it open.
- Never restore a database before validating it with `PRAGMA quick_check` or
  `integrity_check`.
- Treat a newer `PRAGMA user_version` as an incompatible release boundary;
  deploy the matching or newer Arachne source instead of forcing a downgrade.
- Snapshot the current state before replacement when it is readable.
- Restore crawler data and access-code data independently unless the incident
  explicitly requires both.
- Preserve ownership `root:root` and mode `0600` for private database files.
- Restart services and rerun consistency checks after replacement.

## Supported restore

`backup_service.prepare_restore()` can validate and stage a daily ZIP under
`backups/restore-ready`. The server restore command accepts the resulting
standalone `messages.db` or a raw SQLite snapshot created by `backup-db`.

Interactive:

```bash
bash RUN_AFTER_UPLOAD.sh
# Data / maintenance → Restore database from verified snapshot
```

Noninteractive:

```bash
CONFIRM_RESTORE_DB="RESTORE ARACHNE DB" \
  bash RUN_AFTER_UPLOAD.sh restore-db main /absolute/path/to/messages.db
```

Use `access` instead of `main` only for a verified
`runtime/dashboard_access.db` snapshot.

The restore path:

1. requires an existing live target and an exact confirmation;
2. records which services and maintenance timer were active;
3. stops every dashboard, bot, worker, and maintenance SQLite user;
4. validates candidate integrity and required Arachne schema;
5. snapshots and validates the current target under `backups/rollback_*`;
6. creates and validates a staged SQLite copy on the target filesystem;
7. removes stopped-writer sidecars and atomically replaces the target;
8. runs application-level database/consistency validation;
9. automatically restores the preserved database if that validation fails; and
10. repairs private modes, restores the previous service state, and applies
    rollback retention.

An invalid candidate cannot create a rollback directory or alter the target.
If automatic rollback itself fails, services remain stopped. Preserve all files
and investigate with `db-doctor`; do not force a restart.

## Source rollback

An update restore point is not the previous source tree. Before an in-place
upload, retain the last verified clean source archive outside the live project.
To roll back source:

1. Verify that archive with `scripts/make_clean_release.py --verify-archive`.
2. Stop Arachne services.
3. Preserve `.env`, databases, `runtime/`, Telegram sessions, and backups.
4. replace only source-selected files with the verified prior release.
5. Run `bash RUN_AFTER_UPLOAD.sh safe-update`.
6. Verify status, logs, database consistency, Tor OPSEC, and the affected
   workflow.

If no prior verified source archive exists, source rollback is not proven.
The database restore command does not restore source code.

## Destructive reset

`fresh-install` is for an intentional zero-state deployment, not recovery. It
removes crawler and dashboard-access SQLite state while keeping credentials,
Telegram sessions, and backups. Exact confirmation is required.
