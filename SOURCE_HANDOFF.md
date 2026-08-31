# Direct folder upload safety

The intended server workflow is simple:

```bash
cd /root/arachne
bash RUN_AFTER_UPLOAD.sh
```

`RUN_AFTER_UPLOAD.sh` is the one human-facing server control file. It installs or
updates services, runs checks, manages access codes, and keeps the Telegram bot
online during normal updates.

Before copying the whole project folder, make sure the folder does not contain
local runtime junk such as databases, Telegram sessions, logs, reports, previews,
screenshots, backups, or Python caches. The read-only workspace audit can show
what runtime artifacts are present:

```bash
python scripts/make_clean_release.py --audit-workspace
```

To fail a CI/deployment check when the workspace is dirty:

```bash
python scripts/make_clean_release.py --audit-workspace --fail-on-dirty-workspace
```

Important: the audit does not delete anything. Databases, sessions, `.env`,
reports, logs, previews, screenshots, and backups should only be moved or removed
after an explicit manual decision.

Optional: `python scripts/make_clean_release.py` can still build a source-only ZIP
for handoff/testing, but direct folder upload is fine when the workspace is clean.
