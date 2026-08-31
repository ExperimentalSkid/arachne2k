# Arachne crawler/forum upgrade — bounded implementation brief

## Purpose

This brief is the implementation contract distilled from the larger crawler proposal. The current repository is the source of truth. The goal is to fix proven staged-pipeline gaps and improve passive forum/page understanding without increasing crawl reach, weakening policy, or replacing working architecture.

## Baseline and confirmed findings

- Production services use the staged `fetch -> verify -> card -> preview` pipeline.
- Atomic claims, stale-claim recovery, worker fencing, bounded reads, GET-only Tor transport, and per-card locking already exist and must be preserved.
- The full regression baseline before this pass is 487 passing tests; Python compilation succeeds.
- The current development database reports `integrity_check=ok` and no foreign-key violations.
- At baseline, the staged verifier did not run the forum relevance/expansion path; the staged verifier now invokes the shared bounded expansion helper.
- At baseline, Spain Priority persistence was not proven end to end; the card worker now performs the authoritative, idempotent persistence step.
- Staged regression tests now cover both side effects through the production worker paths.
- Forum URL recognition is limited and does not provide a stable thread/page/post identity.
- Response bytes are always decoded as UTF-8 with replacement.
- Repeated links retain only the first occurrence, and link context is only the nearest preceding heading.

## Selected implementation scope

1. **Staged-path parity**
   - Put deterministic page-level post-verification actions behind one shared helper.
   - Run bounded forum-budget expansion from the staged verifier after a page is fully classified and persisted.
   - Run dedicated Spain Priority persistence only after verification and Site Card creation, from the card stage where the card identity is authoritative.
   - Keep all actions idempotent and safe for job retries.
   - Keep the legacy path compatible by delegating to the same helper where practical; do not delete it until parity is test-proven.

2. **Conservative forum identity**
   - Add a pure, network-free forum URL identity module.
   - Distinguish site/index, section, thread, post/permalink, pagination, login, attachment, and unknown roles.
   - Recognize stable identities for common phpBB, vBulletin, SMF, and generic routes without claiming broad engine support from weak evidence.
   - Preserve exact evidence URLs while deriving a canonical thread identity that removes pagination, tracking, and session variants without merging different threads.
   - Feed this identity into thread detection and parsed page structure; do not add crawl depth.

3. **Deterministic decoding and bounded link observations**
   - Select encoding from a valid HTTP charset, then BOM/meta declaration, then bounded deterministic fallbacks.
   - Record encoding, source, replacement ratio, and confidence in page structure; never persist a raw response solely for encoding analysis.
   - Gather local context from bounded semantic containers in addition to headings.
   - Aggregate repeated URL observations with bounded anchor/context variants, occurrence count, source zones, and positions while preserving the existing `url`, `anchor_text`, and `section_context` fields.
   - Continue removing outbound anchor text from page-level classification text so restricted children cannot poison their parent.

4. **Regression coverage and deployment proof**
   - Exercise the real staged sequence for forum expansion and Spain persistence.
   - Test forum identities, pagination/session stripping, exact evidence preservation, encoding fallbacks, repeated-link aggregation, bounded output, and restricted-child separation.
   - Run compile, focused tests, full tests, consistency/dry-run/OPSEC checks, clean-release build, extracted-release compile/test/hygiene validation, and report exact results.

## Explicitly out of scope for this pass

- No increase to depth, pagination reach, thread budgets, or discovery aggressiveness.
- No live Tor or public-site tests.
- No login, forms, JavaScript, authentication, redirect following, downloads, or clear-web fetching.
- No speculative nine-engine adapter matrix or unproven forum-site/post warehouse.
- No host scheduler rewrite, conditional GET system, redirect frontier expansion, or adaptive recrawl rewrite in this bounded pass.
- No UI redesign; only backend data needed by existing views may change.
- No raw restricted content or unrestricted post-body persistence.
- No wholesale rewrite of `onion_worker.py` or `storage.py`.
- No database replacement or destructive migration.

## Compatibility rules

- Existing URL rows, Site Cards, analyst fields, alerts, reports, review state, and manual overrides remain authoritative.
- Safety policy wins over classification, forum expansion, Spain persistence, previews, and card creation.
- Metadata-only/discard policy must remain metadata-only/discard.
- Every new durable action must be idempotent under retries.
- Network work remains outside database transactions.
- Schema changes, if any become necessary, must be additive and idempotent; prefer existing audit/event tables when sufficient.

## Completion gate

This pass is complete only when the verified staged-path gaps are fixed through the real workers, the parser/identity changes remain bounded and backward-compatible, all regression and operational checks pass, and a clean direct-upload folder plus sealed ZIP are independently validated.
