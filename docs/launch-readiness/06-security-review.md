# 06 — Security review

## Enforced boundaries

- Tor-required traffic uses the approved SOCKS transport and remote DNS.
- Direct-fetch source scanning covers runtime project modules.
- Destination classification is not inherited from URL/anchor/parent wording.
- Restricted destinations fail closed for artifacts, content persistence,
  expansion, enrichment, and normal UI exposure.
- Dashboard codes/sessions are isolated from crawler storage.
- Secrets and raw collected data are excluded from logs, diagnostics, receipts,
  manifests, and source archives.
- Network providers, clear-web fetching, screenshots, raw HTML, full page text,
  and automatic Telegram alerts are disabled by default.

## Packaging findings addressed

- `.venv` and `venv` are now explicit dirty-workspace/handoff findings rather
  than silently skipped dependency trees.
- Standard virtual-environment, build, coverage, lint/type cache, and handoff
  receipt paths are ignored by source control.
- Documentation is selected explicitly; the release remains deny-by-default for
  unrecognized directories and suffixes.
- Database restore validates integrity and schema before mutation, stops every
  SQLite user, preserves a verified rollback, publishes a staged file
  atomically, and restores the previous database on post-publish failure.
- Retention prunes only recognized top-level backup directories, never symlinks
  or operator-named directories, and always retains at least one.

## Residual deployment checks

- Real Tor SOCKS/control-port behavior.
- Generated systemd unit validation and post-restart journals.
- Host permissions and free-space behavior under the deployment filesystem.
- Controlled restore rehearsal on the deployment filesystem.
- Review of root-service operation versus a future dedicated account.

Canonical policy is in [Security](../security.md).
