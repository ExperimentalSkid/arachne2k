"""Validate repository-local Markdown links without making network requests."""
from __future__ import annotations

import argparse
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\((?P<target><[^>]+>|[^)\s]+)(?:\s+[^)]*)?\)")
IGNORED_SCHEMES = {"http", "https", "mailto", "tel", "data"}


def markdown_files(root: Path) -> list[Path]:
    """Return tracked-source Markdown candidates, excluding runtime trees."""
    ignored = {
        ".git", ".pytest_cache", ".venv", "venv", "node_modules",
        "runtime", "backups", "logs", "reports",
    }
    return sorted(
        path for path in root.rglob("*.md")
        if path.is_file() and not any(part.casefold() in ignored for part in path.relative_to(root).parts)
    )


def check_markdown_links(root: Path = ROOT) -> list[str]:
    """Return human-readable errors for missing or escaping local links."""
    root = root.resolve()
    errors: list[str] = []
    for source in markdown_files(root):
        text = source.read_text(encoding="utf-8-sig")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in MARKDOWN_LINK_RE.finditer(line):
                raw = match.group("target").strip("<>")
                parsed = urlsplit(raw)
                if parsed.scheme.casefold() in IGNORED_SCHEMES or raw.startswith("#"):
                    continue
                target_text = unquote(parsed.path)
                if not target_text:
                    continue
                target = (source.parent / target_text).resolve()
                try:
                    target.relative_to(root)
                except ValueError:
                    errors.append(f"{source.relative_to(root)}:{line_number}: link escapes repository: {raw}")
                    continue
                if not target.exists():
                    errors.append(f"{source.relative_to(root)}:{line_number}: missing local link: {raw}")
    return errors


def main() -> None:
    """Validate the selected repository root and exit nonzero on bad links."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=ROOT)
    options = parser.parse_args()
    errors = check_markdown_links(options.root)
    if errors:
        for error in errors:
            print(error)
        raise SystemExit(1)
    print(f"Markdown links passed ({len(markdown_files(options.root.resolve()))} files).")


if __name__ == "__main__":
    main()
