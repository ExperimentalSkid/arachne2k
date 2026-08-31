# Open-source integration boundary

Arachne keeps third-party components behind small, reviewable interfaces. A
library is added only when it supplies a mature specialist primitive that is
safer and clearer than maintaining a local replacement. It must not expand
crawl reach, bypass access controls, send evidence to a third party, or change
an analyst decision by itself.

## Integrated

### RapidFuzz

- Purpose: bounded string-similarity scoring for analyst-review suggestions.
- License: MIT.
- Boundary: `entity_quality.py` uses the score only as review evidence. A fuzzy
  score is never an identity key, automatic merge instruction, confirmed
  alias, safety classification, Spain signal, or crawl decision.
- Privacy: input stays in the local process; no network provider is involved.
- Deployment: pinned to the compatible major series in `requirements.txt` and
  checked by `RUN_AFTER_UPLOAD.sh` before services start.

### Exact public identity providers

- Purpose: corroborate an already-confirmed local profile with an exact public
  OpenPGP fingerprint or an exact public domain.
- Providers: keys.openpgp.org, IANA's RDAP bootstrap registry, the selected
  authoritative RDAP service, and Cert Spotter's public CT search endpoint.
- Boundary: providers are disabled by default and require both
  `DEEP_DISCOVERY_NETWORK_ENABLED=true` and `ALLOW_CLEARNET_FETCH=true`.
  Requests use Arachne's Tor-only provider transport, never redirects, never
  browser automation, and never more than five bounded requests for one job.
- Eligibility: the local profile must pass the 90% Deep Discovery gate. A
  pivot must be exact, structurally bound to that profile on a verified safe
  page, and limited to a full OpenPGP fingerprint or public domain.
- Persistence: Arachne keeps reason-coded, normalized evidence and provenance;
  it does not retain response bodies, armored keys, certificate bodies,
  cookies, authorization headers, or unrelated search results.
- Decision safety: provider results are proposals for analyst review. They do
  not change a live Site Card, actor identity, category, risk, Spain Priority,
  urgency, or crawl policy.
- Caching: evidence cache entries are bounded and expire. IANA bootstrap data
  is kept only in the worker process because it is routing infrastructure, not
  identity evidence.

## Deliberately not integrated

- Probabilistic record-linkage frameworks: useful for large curated datasets,
  but too heavy and too easy to misapply to isolated public aliases. Arachne's
  evidence ledger and analyst confirmation remain authoritative.
- MinHash/LSH packages: the current exact hashes and SimHash pipeline already
  cover the bounded duplicate use case without another index or migration.
- Archived homoglyph packages: Unicode/confusable handling remains a local,
  deterministic, review-only implementation so an abandoned dependency cannot
  become an identity authority.
- Browser sanitizers that are deprecated or unmaintained: Arachne keeps its
  existing metadata-only and preview policy instead of introducing an unsafe
  rendering dependency.
- Full UI frameworks: visual systems may be used as design references, but
  Arachne remains a Streamlit application and does not embed a second frontend
  runtime merely for styling.
