# Arachne final engineering and intelligence-quality report

Date: 2026-07-16  
Scope: source architecture, staged workers, SQLite lifecycle, passive entity intelligence,
forum identity, bounded expansion, dashboard, Telegram controls, operational observability,
OPSEC boundaries, launcher/deployment, release hygiene, and regression coverage.

## Outcome

The source-only build is ready for a clean server deployment. The staged crawler architecture,
crawl reach/depth, Spain logic, restricted-content policy, metadata-only rules, analyst overrides,
and Telegram access workflow remain authoritative. No live `.env`, database, Telegram session,
auth state, report, log, preview, screenshot, or backup was read into or packaged with the release.

The implementation adds explainable entity intelligence and a consolidated analyst workspace
without turning fuzzy matching, URL wording, parent context, or a third-party library into an
identity, safety, Spain, or crawl authority.

## Architecture verified

1. `fetch_worker.py` exclusively claims frontier URLs and performs the policy-approved Tor GET.
2. `verify_worker.py` exclusively claims fetched snapshots and performs destination-HTML
   classification, readiness, safe indicators, and terminal expansion outcomes.
3. `card_worker.py` exclusively claims card jobs and uses per-card leases for idempotent rollups.
4. `preview_worker.py` retains its separate claimed lifecycle and existing policy boundary.
5. Deep Discovery remains a claimed, advisory pipeline. Exact public OpenPGP, RDAP, and
   Certificate Transparency checks are available only after the 90% local eligibility gate,
   require two explicit network opt-ins, use the approved Tor transport, and cannot update live
   identity, classification, Spain, urgency, or crawl policy.
6. Maintenance remains leader-leased; ordinary workers do not race global maintenance.
7. Dashboard and Telegram use the same durable storage model while access sessions stay isolated.

## Implemented intelligence layer

- Canonical candidate lifecycle: accepted observation, rejected noise, analyst review,
  analyst-confirmed evidence, analyst-rejected evidence, and contradicted/superseded evidence.
- Versioned, context-bound alias noise rules with reversible analyst decisions and count-only audit.
- Unicode/confusable and RapidFuzz similarity are review evidence only; neither can auto-merge.
- Profile-aware candidate attachment prevents identical handles on distinct profiles from crossing.
- Contradictory exact identifiers cap or veto identity correspondence instead of being averaged away.
- Analyst-reviewed, watched, titled, categorized, and noted records survive recalculation/cleanup.
- Forum/thread variants use stable trigger identity and atomic, idempotent budget claims.
- Bounded same-host expansion proposes only public GET routes with explicit reasons and budgets.
  It is proposal-only by default; approval revalidates current safety policy and atomically binds
  the exact queued URL. Terminal outcomes are reason-coded and contain no raw page or identifier.
- Adult/severe blackholes now also scrub candidate events, candidate rows, expansion proposals,
  watch rows, and URL-bearing entity events, including late policy transitions.
- Restricted children remain scoped to the child and cannot poison a safe parent/card.

## Dashboard and operator workflow

- Primary navigation is reduced to Work, Intelligence, Collection, and System; old routes remain
  available under More tools for compatibility.
- Entity Intelligence consolidates Review, Entities, Evidence, Connections, Expansion, and History.
- Global search and connection filters expose confidence, analyst state, evidence family,
  contradiction, watch, Spain, and time scopes without exposing restricted content.
- Site Cards are flatter and more compact while retaining host, category, risk, state, seen time,
  URL count, last check, and completeness. Spain Priority cards show the `🇪🇸` marker.
- Home keeps review lanes, focus shortcuts, restricted-filter correction, and a truthful staged
  service snapshot. Every navigation slug and card callback is covered by Streamlit AppTest.
- English/Spanish switching and both visual themes remain available. Technical labels remain
  intentionally concise; minor translation polish is non-blocking.

## Operational observability

- Workers emit rotating structured JSONL plus concise human summaries with run/worker/job
  correlation, lifecycle transitions, latency, queue depth, DB delay, Tor/provider state, and
  reason-coded outcomes.
- Redaction forbids raw onion URLs, page content, credentials, cookies, Telegram sessions,
  category-sensitive content, and personal identifiers.
- Retention/compression, daily throughput/failure/queue/database summaries, sanitized diagnostic
  bundles, launcher access, and admin-only Telegram bundle delivery are regression-tested.
- Alias cleanup CLI output is aggregate JSON only; raw alias samples were removed.

## Open-source integration decision

- RapidFuzz (MIT) is integrated behind a bounded local review-only adapter.
- Exact public OpenPGP/RDAP/Certificate Transparency adapters are integrated behind disabled-by-
  default, Tor-routed, exact-identifier and proposal-only boundaries.
- Existing NetworkX, Beautiful Soup/lxml, Telethon, Playwright, Pillow/Tesseract, Stem, and
  Requests/SOCKS components remain within their established boundaries.
- Heavy probabilistic linkage, MinHash/LSH, archived homoglyph libraries, deprecated sanitizers,
  and a second frontend runtime were deliberately not added. Adding packages without a justified
  authority boundary would increase launch risk rather than intelligence quality.
- See `OPEN_SOURCE_INTEGRATIONS.md` for the explicit boundary and rejected alternatives.

## Security and integrity fixes found by the final gate

- Closed restricted-content leakage from entity candidates/events/expansion proposals.
- Serialized expansion approve/reject plus exact frontier upsert in one SQLite transaction;
  rejection cannot be overwritten and legacy approved rows recover idempotently.
- Scoped candidate linking to canonical profile identity with only unambiguous legacy fallback.
- Removed raw aliases from cleanup/maintenance output.
- Restored the compact Home `Worker pipeline`, Telegram, Tor, and processed-today health metrics.
- Redirected collection-time pytest Telethon sessions to disposable OS-temp paths. An extracted
  full-suite run created zero `.session` files in the source tree.

## Exact validation

- Baseline before this pass: **676 passed, 1 skipped**.
- Final source regression after security fixes: **753 passed, 1 skipped**.
- Final extracted clean-release regression including session-isolation test:
  **754 passed, 1 skipped**.
- Focused UI/AppTest gate: **83 passed**; all navigation slugs, Entity Intelligence actions,
  Site Card dialogs, compact cards, Spain marker, access lock, themes, and restricted views passed.
- Focused final security/privacy gate: **67 passed**.
- Python `compileall`: passed. `pip check`: no broken requirements.
- Clean release: **226 source files**; embedded manifest verification passed; private/runtime
  artifacts excluded.
- Extracted consistency audit: **0 conflicts**.
- Extracted consistency repair dry-run: **0 changes**.
- Extracted link-list frontier repair dry-run: **0 changes**.
- Extracted runtime-artifact purge dry-run: **0 candidates** before generated test artifacts.
- Extracted alias-quality audit: **0 proposed cleanup actions** on the clean database.
- OPSEC checks passed for `socks5h`, preview proxy/policy, direct-fetch source scan, clean-release
  boundary, and log redaction. Live Tor reachability failed only because this Windows validation
  host has no Tor SOCKS service. Invoking Python created two medium-severity `__pycache__` handoff
  findings; no private artifact was packaged.

## Validation limits and remaining debt

- Live Tor reachability, actual Linux systemd startup, and server log inspection must be verified
  after upload on the deployment host.
- The Windows host has no WSL distribution, so the Linux-only `bash -n` test is the single skip;
  launcher structure and menu paths are otherwise covered by regression tests.
- Interactive browser automation could not start because the desktop browser runtime was denied
  access by the host (`EPERM`). Streamlit AppTest supplied the complete route/callback gate.
- Existing unreachable legacy Home/navigation blocks remain maintenance debt but are not executed;
  they were not deleted in this finishing pass to avoid changing compatibility behavior.
- Migration tests use isolated SQLite databases. The user selected a clean crawler restart, so no
  multi-gigabyte live database was mutated or used as a migration target.

## Deployment handoff

Upload the verified clean-release folder contents without configuring FTP to delete remote files
that are absent locally. The release intentionally contains no private/runtime state.

On the Linux server run:

```bash
cd /root/arachne
bash RUN_AFTER_UPLOAD.sh
```

Use the normal safe install/update path for an in-place deployment, or the clearly separated fresh
install/reset path only when intentionally starting from an empty crawler database. Then verify
status, recent logs, the real Tor-backed `--opsec-audit`, and one bounded seed through the complete
fetch → verify → card assembly line.
