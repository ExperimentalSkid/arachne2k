# 05 — Migrations and clean start

## Empty bootstrap

The release must initialize without any supplied database:

1. Use a disposable directory and private `.env`.
2. Ensure `messages.db`, its sidecars, and the access database are absent.
3. Run the canonical initialization/fresh-state test.
4. Run `storage.init_db()` twice and verify no duplicate schema/data.
5. Start the dashboard against zero records and verify useful empty states.
6. Confirm access-code storage initializes independently.
7. Run one mocked fetch → verify → card pipeline.
8. Restart initialization and verify persistence.

The production `fresh-install` path resets crawler and access SQLite state while
preserving source, credentials, Telegram sessions, and backups. It is not an
upgrade path.

## Upgrade behavior

Normal updates preserve database and analyst state. Source proof runs before
dependency, bytecode, service, database, or test mutation. SQLite writers stop
before database-wide checks and update snapshots.

## Clean production package

The source archive contains no database, queue, claim, URL, page, preview,
report, log, cache, lock, credential, session, or backup from the supplied
reference setup. Safe synthetic tests represent required workflow states.

Final zero-state and restart evidence is recorded in
[07 — Test evidence](07-test-evidence.md).

