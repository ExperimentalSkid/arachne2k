"""Bound retention for Arachne operational backup/rollback directories."""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path


DEFAULT_POLICIES = {
    "manual": ("manual_", 7),
    "restore": ("restore_", 3),
    "rollback": ("rollback_", 5),
    "config": ("config_", 5),
    "stale-source": ("stale-source-", 3),
}


def prune_backup_artifacts(
        root: Path,
        *,
        kind: str = "all",
        keeps: dict[str, int] | None = None,
        dry_run: bool = True,
) -> dict:
    """Prune only recognized top-level directories, newest first."""
    original_root = Path(root).expanduser()
    if original_root.exists() and original_root.is_symlink():
        raise ValueError("backup retention root must not be a symlink")
    root = original_root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if kind != "all" and kind not in DEFAULT_POLICIES:
        raise ValueError(f"unknown backup retention kind: {kind}")
    selected = (
        DEFAULT_POLICIES
        if kind == "all"
        else {kind: DEFAULT_POLICIES[kind]}
    )
    overrides = keeps or {}
    candidates: list[tuple[str, Path]] = []
    retained: list[tuple[str, Path]] = []
    for policy_kind, (prefix, default_keep) in selected.items():
        keep = max(1, min(int(overrides.get(policy_kind, default_keep)), 50))
        paths = sorted(
            (
                path for path in root.iterdir()
                if path.is_dir() and not path.is_symlink()
                and path.name.startswith(prefix)
            ),
            key=lambda path: (path.stat().st_mtime_ns, path.name),
            reverse=True,
        )
        retained.extend((policy_kind, path) for path in paths[:keep])
        candidates.extend((policy_kind, path) for path in paths[keep:])

    removed: list[tuple[str, Path]] = []
    if not dry_run:
        for policy_kind, path in candidates:
            resolved = path.resolve()
            if resolved.parent != root or path.is_symlink():
                continue
            shutil.rmtree(resolved)
            removed.append((policy_kind, path))
    return {
        "dry_run": bool(dry_run),
        "kind": kind,
        "candidates": [
            {"kind": item_kind, "path": path.name}
            for item_kind, path in candidates
        ],
        "removed": [
            {"kind": item_kind, "path": path.name}
            for item_kind, path in removed
        ],
        "retained": len(retained),
    }


def main() -> None:
    """Parse retention overrides and report the dry-run or applied result."""
    parser = argparse.ArgumentParser(
        description="Prune only recognized Arachne backup artifact directories"
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument(
        "--kind", choices=["all", *DEFAULT_POLICIES], default="all"
    )
    parser.add_argument("--apply", action="store_true")
    for name, (_prefix, keep) in DEFAULT_POLICIES.items():
        parser.add_argument(
            f"--keep-{name}",
            type=int,
            default=keep,
            metavar="COUNT",
        )
    args = parser.parse_args()
    keeps = {
        name: getattr(args, f"keep_{name.replace('-', '_')}")
        for name in DEFAULT_POLICIES
    }
    result = prune_backup_artifacts(
        args.root,
        kind=args.kind,
        keeps=keeps,
        dry_run=not args.apply,
    )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))


if __name__ == "__main__":
    main()
