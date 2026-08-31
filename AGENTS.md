# Arachne engineering instructions

## Durable structure

- `dashboard.py` delegates to `dashboard_pages/`; keep domain and storage logic
  outside Streamlit rendering when practical.
- `fetch_worker.py` claims `onion_urls`; `verify_worker.py` claims
  `fetched_pages`; `card_worker.py` claims `site_card_jobs`.
- `storage.py` is the canonical schema and migration boundary.
- `RUN_AFTER_UPLOAD.sh` is the single supported server-control entry point.
- `scripts/make_clean_release.py` is the authoritative source selector and
  manifest/archive verifier.

## Commands

```bash
python -m py_compile <touched Python files>
python -m pytest -q <focused tests>
python -m pytest -q
python scripts/make_clean_release.py --audit-workspace
python scripts/make_clean_release.py /tmp/arachne-release.zip
python scripts/make_clean_release.py --verify-archive /tmp/arachne-release.zip
```

Server-only validation:

```bash
bash -n RUN_AFTER_UPLOAD.sh
bash RUN_AFTER_UPLOAD.sh validate
bash RUN_AFTER_UPLOAD.sh status
```

## Non-negotiable boundaries

- Never use a live `.env`, Telegram session, auth database, or crawler database
  as a fixture.
- Never log raw onion URLs, page text, secrets, cookies, private identifiers, or
  restricted-content labels. Use existing redaction and safe hashes.
- No onion request may bypass `safe_transport`; no silent clearnet fallback.
- Destination classification comes from the destination's fetched HTML, not
  URL, anchor, parent, or sibling wording.
- Restricted content remains metadata-limited and cannot produce unsafe
  artifacts or expansion.
- Analyst titles, categories, notes, importance, review state, report state, and
  alert decisions survive recalculation and merges.
- Do not change crawl depth, Spain policy, safety policy, or alert behavior as a
  side effect of UI or packaging work.

## Database changes

- Add schema changes through the existing idempotent migration/init path.
- Preserve transaction boundaries, uniqueness, claim leases, stale recovery,
  and per-card locks.
- Test from an empty temporary database and, where relevant, from a copied
  database. Never mutate the supplied reference database in place.

## Network and crawler tests

- Prefer mocked transport and synthetic HTML.
- Do not start real workers, send Telegram messages, or perform external
  discovery merely to prove a test.
- Live Tor/systemd checks are server launch gates and must be reported
  separately from offline tests.

## Definition of done

Compile touched files, run focused and full regression tests, validate an
extracted source-only archive, inspect affected workflows, review the diff for
data loss or duplicate systems, update documentation, and report any unverified
server-only gate honestly.

