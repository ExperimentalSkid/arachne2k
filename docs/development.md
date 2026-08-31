# Development setup

## Supported shape

Production targets Ubuntu with Python 3.12, Tor, systemd, and the native tools
required by optional Playwright/Tesseract features. Local development may run
on Windows or Linux, but Linux-only service and Tor checks remain separate
launch gates.

## Isolated setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-lock.txt
```

Use a temporary `.env` with external networking, alerts, and preview capture
disabled. Tests should obtain storage from the isolated database fixtures in
`tests/conftest.py`.

`requirements.txt` contains the reviewed direct dependency ranges;
`requirements-lock.txt` pins the complete resolved environment used by CI and
deployment. After intentionally changing a direct dependency, regenerate the
lock, review it, and run the full suite:

```bash
pip-compile --strip-extras --output-file=requirements-lock.txt requirements.txt
```

## Change workflow

1. Map the affected entry point, storage operation, and policy boundary.
2. Record the current behavior with a focused test.
3. Make one coherent change.
4. Compile touched Python files.
5. Run focused tests and then the full suite.
6. Inspect the real Streamlit workflow when UI behavior changed.
7. Audit the workspace and build an extracted clean release.
8. Update the relevant canonical document and launch evidence.

Do not regenerate `SOURCE_MANIFEST.json` until all source edits for a release
are complete. A manifest is a receipt for an exact tree, not a development
lockfile.

See [Testing](testing.md) and the concise durable rules in
[`AGENTS.md`](../AGENTS.md).
