# Security and privacy

## Collection boundary

All onion requests must use the approved Tor transport with remote DNS
(`socks5h`) and must fail closed. Environment proxy variables are ignored.
Direct `requests`, `httpx`, `aiohttp`, or `urllib` paths in runtime source are
audited; the only narrow exception is a parsed loopback Ollama endpoint.

URL, host, path, anchor, parent, and sibling wording are unverified hints.
Destination content classification is based on that destination's fetched
HTML. Text-oriented fetches reject or avoid images, video, downloads, scripts,
embeds, and other unnecessary subresources.

## Content safety

Adult and severe restricted states are destination-scoped. Restricted material
is metadata-limited, hidden by default, and cannot produce screenshots,
previews, snippets, raw-text persistence, outbound expansion, enrichment, or
unsafe fingerprints. Restricted children do not poison a safe parent.

Tests and documentation use synthetic, non-graphic fixtures. Never copy
collected content into a fixture or report.

## Secrets and access

- `.env`, Telegram sessions, dashboard codes/sessions, databases, and Tor
  control credentials are private runtime state.
- The access-code database is separate from crawler storage.
- Codes are one-time, hashed, expiring, and revocable.
- Receipts and diagnostics report configuration presence only.
- Production files use a restrictive umask; private artifacts use mode `0600`.

Systemd currently runs the application services as root with
`NoNewPrivileges`, an empty capability bounding set, read-only home/system
protections, private temporary/devices, and bounded address families. Moving to
a dedicated service account is a post-launch hardening option that requires a
tested ownership and Tor-access migration; do not change it casually.

## Logs and diagnostics

Structured logs use safe hashes and reason codes. They must not contain raw
onion URLs, page content, credentials, cookies, Telegram session data,
category-sensitive content, or personal identifiers. Rotation, compression,
retention, total-size bounds, and sanitized diagnostic bundle limits are
configuration-controlled.

## Release boundary

The deterministic source selector excludes runtime/private artifacts and
symlinks. Direct-folder hygiene reports databases, sessions, `.env`, runtime
directories, generated data, caches, archives, and virtual environments. The
embedded manifest proves the exact source set and hashes but does not prove
runtime safety, database health, or operational configuration.

## Incident response

Pause new collection, preserve logs through the sanitized bundle, preserve
database files/sidecars without opening them unnecessarily, and record exact
commands and timestamps. Do not weaken Tor, content, or access controls to make
an incident disappear.

