# Configuration

`.env.example` is the authoritative configuration inventory. Copy only the keys
needed for the deployment into a private `.env`; never put real values into
source control, documentation, tests, receipts, or diagnostics.

## Precedence and writable settings

Process environment and `.env` provide server configuration. The dashboard may
write only allowlisted non-secret runtime preferences to
`runtime_settings.json`. Runtime preferences must not accept credentials,
network endpoints, or unrestricted numeric values.

## Configuration groups

- Telegram: API ID/hash, bot token, authorized admin IDs, manual-pull mode, and
  automatic-alert opt-in.
- Dashboard access: lock state and externally displayed dashboard URL.
- Tor and OPSEC: SOCKS endpoint, isolation, control-port rotation, strict mode,
  and purge settings.
- Storage and retention: safe-snippet policy, generated-artifact retention,
  structured-log rotation, and diagnostic bounds.
- Deep Discovery: worker and network opt-ins plus provider request budgets.
- Crawler: enablement, delays, byte/link/page/depth budgets, trap limits, and
  forum budgets.
- Preview: disabled-by-default capture flag and bounded dimensions/timeouts.
- One-time migration: explicit prior service, database, and backup prefixes;
  these remain blank during normal operation.

Telegram is optional. Unless its API ID, API hash, bot token, and at least one
administrator ID are all present, the launcher keeps only
`arachne-bot.service` stopped and disabled. Use `bot-start` after completing
those values; other Arachne services do not depend on them.

## Launch-safe defaults

The example configuration disables automatic Telegram alerts, clear-web fetch,
Deep Discovery network providers, screenshots, raw HTML storage, and full
visible-text storage. Tor-required requests remain fail-closed.

The example currently enables the always-on crawler service. An empty database
has no work until an operator adds a starting onion. Operators who want an
additional maintenance window should run `bash RUN_AFTER_UPLOAD.sh pause`
before adding a seed and `resume` only when ready.

## Creating server configuration

```bash
cd /root/arachne
bash RUN_AFTER_UPLOAD.sh configure-env
```

Blank answers preserve existing values. The launcher backs up an existing
`.env` privately before editing, prints presence only, and enforces private
ownership/mode. Validate without exposing values:

```bash
bash RUN_AFTER_UPLOAD.sh validate
bash RUN_AFTER_UPLOAD.sh status
```

Operational backup retention can be overridden for one launcher invocation with
`ARACHNE_KEEP_MANUAL_BACKUPS`, `ARACHNE_KEEP_UPDATE_RESTORE_POINTS`,
`ARACHNE_KEEP_DATABASE_ROLLBACKS`, `ARACHNE_KEEP_CONFIG_BACKUPS`, and
`ARACHNE_KEEP_STALE_SOURCE_BACKUPS`. Values are bounded to 1–50; defaults are
documented in [Backup and recovery](backup-and-recovery.md).

`ARACHNE_PREVIOUS_SERVICE_PREFIX`, `ARACHNE_PREVIOUS_DB_FILE`, and
`ARACHNE_PREVIOUS_BACKUP_PREFIX` are narrow transition controls, not permanent
aliases. See the one-time migration section in [Deployment](deployment.md),
use exact prior identifiers, and clear them after migration.

See [Security](security.md) for secret handling and
[Deployment](deployment.md) for first launch.
