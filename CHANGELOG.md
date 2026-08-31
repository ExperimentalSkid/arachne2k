# Change log

## Pre-launch productization pass

- Added a canonical product, deployment, operations, analyst, security, testing,
  and launch-evidence documentation set.
- Made launch documentation part of the deterministic source-only release.
- Tightened direct-folder hygiene so `.venv` and `venv` are reported once
  without recursively enumerating dependency contents.
- Expanded ignore rules for virtual environments, test/coverage output, build
  output, and generated handoff receipts.

Functional, design, database, and validation changes from the wider launch pass
are recorded in
[`docs/launch-readiness/09-final-report.md`](docs/launch-readiness/09-final-report.md).

