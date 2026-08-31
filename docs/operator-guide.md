# Operator guide

Start the supported control interface:

```bash
cd /root/arachne
bash RUN_AFTER_UPLOAD.sh
```

## Daily checks

1. Review the menu's dashboard, bot, staged-worker, maintenance, database, and
   queue state.
2. Open **Services / workers / logs** for recent failures.
3. Use **Data / maintenance → DB doctor** when SQLite or disk state is unclear.
4. Build a sanitized diagnostic bundle for support; never send raw logs,
   databases, `.env`, or session files.
5. Confirm free disk space before updates or large database snapshots.

Equivalent read-only commands:

```bash
bash RUN_AFTER_UPLOAD.sh status
bash RUN_AFTER_UPLOAD.sh db-info
bash RUN_AFTER_UPLOAD.sh db-doctor
bash RUN_AFTER_UPLOAD.sh logs
bash RUN_AFTER_UPLOAD.sh diagnostics
```

## Collection control

```bash
bash RUN_AFTER_UPLOAD.sh pause
bash RUN_AFTER_UPLOAD.sh resume
bash RUN_AFTER_UPLOAD.sh restart-workers
```

Pause prevents new claims; it does not terminate an in-progress bounded job.
Use service stop only for maintenance that requires every SQLite writer to be
closed.

## Dashboard and bot

```bash
bash RUN_AFTER_UPLOAD.sh dashboard-code
bash RUN_AFTER_UPLOAD.sh restart-dashboard
bash RUN_AFTER_UPLOAD.sh restart-bot
```

Dashboard codes are one-time and expire. The bot and dashboard use the same
dedicated access database. Do not delete that database as a routine repair.

## Database operations

- **Backup database** uses SQLite's online backup API and verifies the snapshot.
- **Restore database from verified snapshot** stops every SQLite user, validates
  schema/integrity, preserves the current target, publishes atomically, and
  rolls back automatically if application validation fails.
- **DB doctor** is diagnostic and non-destructive.
- **Repair DB I/O state** stops writers, preserves data, and repairs known
  ownership/sidecar conditions.
- **Reset crawler database** is destructive and requires exact confirmation.
- **Fresh/First Install** also resets dashboard access state and is only for an
  intentional zero-state launch.

See [Backup and recovery](backup-and-recovery.md) before a restore or reset.

## Failure response

- Source-manifest failure: do not install; compare missing/changed/extra paths
  and upload the complete verified source.
- Backup-space or snapshot failure: do not wipe or update; free space and rerun.
- Main DB failure: keep dashboard and bot available where possible, stop crawler
  workers, run `db-doctor`, and preserve the failing files.
- Tor/OPSEC failure: do not start crawler workers until `validate` succeeds.
- Bot failure: validate redacted configuration presence, then inspect only the
  bot unit's recent journal.

Escalate with a sanitized diagnostic bundle and the exact failed command.
