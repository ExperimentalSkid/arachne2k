"""Build and verify deterministic, source-only Arachne releases.

The source selector in this module is authoritative for both clean releases and
handoff manifests.  Keeping one selector prevents a receipt from proving a
different file set than the ZIP actually contains.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
DEFAULT_OUTPUT = ROOT.parent / "arachne_release.zip"
ARCHIVE_ROOT = "arachne"
MANIFEST_NAME = "SOURCE_MANIFEST.json"
MANIFEST_SCHEMA_VERSION = 2
MAX_MANIFEST_FILES = 10_000
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 512 * 1024 * 1024
ROOT_FILES = {
    ".env.example", ".gitattributes", ".gitignore", "requirements.txt", "pytest.ini",
    "RUN_AFTER_UPLOAD.sh",
}
ROOT_SUFFIXES = {".py", ".json", ".md"}
PRIVATE_OR_TRANSIENT_ROOT_FILES = {
    "config.json", "audit_checkpoint.md", "tmp_arachne_pdf_extract.txt",
}
TREE_RULES = {
    "dashboard_pages": {".py"},
    "dashboard_services": {".py"},
    "docs": {".md"},
    "tests": {".py", ".json", ".txt"},
    "scripts": {".py", ".sh", ".md"},
    "ops": {".service", ".conf", ".sh", ".md"},
    "assets": {".png", ".svg", ".ico"},
    ".streamlit": {".toml"},
}
FORBIDDEN_PARTS = {
    ".git", ".venv", "venv", "backups", "reports", "logs", "runtime",
    "previews", "screenshots", "__pycache__", ".pytest_cache", "node_modules",
    "handoff_receipts",
}
FORBIDDEN_SUFFIXES = {".db", ".session", ".pyc", ".bak", ".zip", ".7z", ".log"}
RELEASE_TIMESTAMP = (2026, 1, 1, 0, 0, 0)
SOURCE_ONLY_NOTICE = (
    "SOURCE-ONLY release: safe for code deployment/handoff. "
    "Live .env, sessions, databases, reports, logs, previews, screenshots, and backups are excluded."
)
DIRTY_WORKSPACE_NOTICE = (
    "Workspace contains live runtime artifacts. Clean the folder before direct upload, or use the clean release ZIP. "
    "This audit is read-only and does not delete anything."
)
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class ManifestValidationError(ValueError):
    """Raised when source proof is incomplete, unsafe, or inconsistent."""


def _has_scratch_part(relative: Path) -> bool:
    """Exclude pytest scratch roots even when a custom basename was used."""
    return any(part.casefold().startswith(".pytest-") for part in relative.parts)


def _allowed(path: Path, root: Path = ROOT) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    lowered_parts = {part.casefold() for part in relative.parts}
    if lowered_parts & FORBIDDEN_PARTS or _has_scratch_part(relative):
        return False
    name = path.name.casefold()
    if len(relative.parts) == 1 and name in PRIVATE_OR_TRANSIENT_ROOT_FILES:
        return False
    if (name in {".env", "runtime_settings.json", "runtime_settings.json.tmp",
                 "handoff_receipt.txt", MANIFEST_NAME.casefold()}
            or name.endswith((".db-wal", ".db-shm", ".session-journal"))
            or ".bak" in name
            or name.startswith("informe_") and path.suffix.casefold() in {".json", ".txt"}
            or name.startswith("log_") and path.suffix.casefold() in {".log", ".txt"}
            or name.startswith("arachne.db.empty")):
        return False
    if path.suffix.casefold() in FORBIDDEN_SUFFIXES:
        return False
    if len(relative.parts) == 1:
        return path.name in ROOT_FILES or path.suffix.casefold() in ROOT_SUFFIXES
    top = relative.parts[0]
    return top in TREE_RULES and path.suffix.casefold() in TREE_RULES[top]


def release_files(root: Path = ROOT) -> list[Path]:
    """Return the one authoritative, deterministic source file set."""
    root = Path(root).resolve()
    return sorted((path for path in root.rglob("*") if _allowed(path, root)),
                  key=lambda path: path.relative_to(root).as_posix())


def _manifest_entry(path: Path, root: Path) -> dict:
    payload = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def _tree_digest(entries: Iterable[dict]) -> str:
    lines = [f"{item['sha256']}  {item['bytes']}  {item['path']}" for item in entries]
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def build_source_manifest(root: Path = ROOT, *, files: list[Path] | None = None) -> dict:
    """Build a content-derived manifest; it never includes itself or runtime state."""
    root = Path(root).resolve()
    selected = release_files(root) if files is None else sorted(
        (Path(path).resolve() for path in files),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    entries = [_manifest_entry(path, root) for path in selected]
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "project": "Arachne",
        "root_name": ARCHIVE_ROOT,
        "file_count": len(entries),
        "total_bytes": sum(item["bytes"] for item in entries),
        "tree_sha256": _tree_digest(entries),
        "files": entries,
        "environment": {"included": False, "contents_hashed": False},
    }


def manifest_bytes(manifest: dict) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def write_source_manifest(root: Path = ROOT, destination: Path | None = None) -> dict:
    """Atomically write the authoritative manifest beside the selected source."""
    root = Path(root).resolve()
    destination = Path(destination or root / MANIFEST_NAME).resolve()
    manifest = build_source_manifest(root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="wb", prefix=f".{destination.name}.", suffix=".tmp",
                dir=destination.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(manifest_bytes(manifest))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    return manifest


def _safe_manifest_path(value: object) -> str:
    raw = str(value or "")
    if not raw or "\\" in raw or "\x00" in raw:
        raise ManifestValidationError(f"unsafe manifest path: {raw!r}")
    candidate = PurePosixPath(raw)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ManifestValidationError(f"unsafe manifest path: {raw!r}")
    normalized = candidate.as_posix()
    if normalized != raw or normalized.casefold() == MANIFEST_NAME.casefold():
        raise ManifestValidationError(f"unsafe manifest path: {raw!r}")
    return normalized


def validate_manifest(manifest: object) -> dict:
    """Validate schema, paths, sizes, hashes, ordering, counts, and tree digest."""
    if not isinstance(manifest, dict):
        raise ManifestValidationError("manifest root must be an object")
    required_keys = {
        "schema_version", "project", "root_name", "file_count", "total_bytes",
        "tree_sha256", "files", "environment",
    }
    if set(manifest) != required_keys:
        raise ManifestValidationError("manifest schema fields do not match the supported schema")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ManifestValidationError("unsupported manifest schema_version")
    if manifest.get("project") != "Arachne":
        raise ManifestValidationError("unexpected manifest project")
    if manifest.get("root_name") != ARCHIVE_ROOT:
        raise ManifestValidationError("unexpected manifest root_name")
    if manifest.get("environment") != {"included": False, "contents_hashed": False}:
        raise ManifestValidationError("manifest environment policy is invalid")
    files = manifest.get("files")
    if not isinstance(files, list) or len(files) > MAX_MANIFEST_FILES:
        raise ManifestValidationError("manifest files must be a bounded list")
    validated: list[dict] = []
    seen: set[str] = set()
    total = 0
    for raw in files:
        if not isinstance(raw, dict):
            raise ManifestValidationError("manifest file entry must be an object")
        path = _safe_manifest_path(raw.get("path"))
        key = path.casefold()
        if key in seen:
            raise ManifestValidationError(f"duplicate manifest path: {path}")
        seen.add(key)
        size = raw.get("bytes")
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= MAX_SOURCE_FILE_BYTES:
            raise ManifestValidationError(f"invalid size for {path}")
        digest = str(raw.get("sha256") or "").casefold()
        if not _SHA256_RE.fullmatch(digest):
            raise ManifestValidationError(f"invalid sha256 for {path}")
        total += size
        if total > MAX_SOURCE_TOTAL_BYTES:
            raise ManifestValidationError("manifest source size exceeds safety limit")
        validated.append({"path": path, "sha256": digest, "bytes": size})
    ordered = sorted(validated, key=lambda item: item["path"])
    if validated != ordered:
        raise ManifestValidationError("manifest file entries are not deterministically sorted")
    count = manifest.get("file_count")
    if isinstance(count, bool) or count != len(validated):
        raise ManifestValidationError("manifest file_count does not match files")
    declared_total = manifest.get("total_bytes")
    if isinstance(declared_total, bool) or declared_total != total:
        raise ManifestValidationError("manifest total_bytes does not match files")
    tree = str(manifest.get("tree_sha256") or "").casefold()
    if not _SHA256_RE.fullmatch(tree) or tree != _tree_digest(validated):
        raise ManifestValidationError("manifest tree_sha256 does not match files")
    clean = dict(manifest)
    clean["files"] = validated
    clean["tree_sha256"] = tree
    return clean


def load_manifest(path: Path) -> dict:
    path = Path(path)
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ManifestValidationError(f"manifest unavailable: {path}") from exc
    if len(payload) > MAX_MANIFEST_BYTES:
        raise ManifestValidationError("manifest exceeds safety limit")
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestValidationError("manifest is not valid UTF-8 JSON") from exc
    return validate_manifest(parsed)


def _source_differences(root: Path, manifest: dict) -> tuple[dict[str, Path], list[str], list[str], list[str]]:
    """Inspect one selected source tree without mutating it."""
    expected = {item["path"]: item for item in manifest["files"]}
    selected = {path.relative_to(root).as_posix(): path for path in release_files(root)}
    missing = sorted(set(expected) - set(selected))
    extra = sorted(set(selected) - set(expected))
    changed: list[str] = []
    for relative in sorted(set(expected).intersection(selected)):
        path = selected[relative]
        size = path.stat().st_size
        if size != expected[relative]["bytes"]:
            changed.append(relative)
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected[relative]["sha256"]:
            changed.append(relative)
    return selected, missing, extra, changed


def verify_source(root: Path = ROOT, manifest_path: Path | None = None) -> dict:
    """Verify an exact source set, including stale and extra selected files."""
    root = Path(root).resolve()
    manifest_path = Path(manifest_path or root / MANIFEST_NAME).resolve()
    manifest = load_manifest(manifest_path)
    _, missing, extra, changed = _source_differences(root, manifest)
    if missing or extra or changed:
        details = {"missing": missing, "extra": extra, "changed": changed}
        raise ManifestValidationError("source set does not match manifest: " + json.dumps(details, sort_keys=True))
    return {
        "pass": True,
        "kind": "source",
        "manifest": str(manifest_path),
        "file_count": manifest["file_count"],
        "tree_sha256": manifest["tree_sha256"],
    }


def reconcile_source_extras(root: Path = ROOT, manifest_path: Path | None = None) -> dict:
    """Quarantine stale selected source files after proving the upload itself.

    Direct folder uploads do not remove files that disappeared from a newer
    release.  This operation keeps exact manifest verification strict while
    safely reconciling that one deployment shape:

    * every manifest file must exist and match before anything moves;
    * only files selected by ``release_files`` but absent from the manifest
      are eligible;
    * runtime data, .env, databases, sessions, logs, and other excluded files
      are never selected and therefore never touched;
    * stale files are preserved under ``backups/stale-source-*``.
    """
    root = Path(root).resolve()
    manifest_path = Path(manifest_path or root / MANIFEST_NAME).resolve()
    manifest = load_manifest(manifest_path)
    selected, missing, extra, changed = _source_differences(root, manifest)
    if missing or changed:
        details = {"missing": missing, "extra": extra, "changed": changed}
        raise ManifestValidationError(
            "uploaded source is incomplete or changed; no stale files were moved: "
            + json.dumps(details, sort_keys=True)
        )
    if not extra:
        verified = verify_source(root, manifest_path)
        return {
            **verified,
            "kind": "source-reconcile",
            "quarantine": None,
            "quarantined": [],
        }

    backup_root = root / "backups"
    if backup_root.exists() and (backup_root.is_symlink() or not backup_root.is_dir()):
        raise ManifestValidationError("source quarantine root is not a safe directory")
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    quarantine = Path(tempfile.mkdtemp(
        prefix=f"stale-source-{stamp}-{os.getpid()}-",
        dir=backup_root,
    )).resolve()
    try:
        quarantine.relative_to(root)
    except ValueError as exc:
        raise ManifestValidationError("source quarantine escaped the project root") from exc

    moved: list[str] = []
    try:
        for relative in extra:
            source = selected[relative]
            if source.is_symlink() or not source.is_file() or not _allowed(source, root):
                raise ManifestValidationError(f"stale source is no longer safe to move: {relative}")
            destination = quarantine.joinpath(*PurePosixPath(relative).parts)
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.replace(source, destination)
            moved.append(relative)
    except Exception:
        # Restore already-moved files on a bounded move failure.  Expected
        # manifest files were never candidates and remain untouched.
        for relative in reversed(moved):
            source = quarantine.joinpath(*PurePosixPath(relative).parts)
            destination = root.joinpath(*PurePosixPath(relative).parts)
            if source.is_file() and not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(source, destination)
        raise

    verified = verify_source(root, manifest_path)
    record = {
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "manifest_tree_sha256": manifest["tree_sha256"],
        "quarantined": moved,
    }
    (quarantine / "RECONCILE.json").write_text(
        json.dumps(record, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return {
        **verified,
        "kind": "source-reconcile",
        "quarantine": quarantine.relative_to(root).as_posix(),
        "quarantined": moved,
    }


def _safe_archive_name(value: str) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise ManifestValidationError(f"unsafe archive path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ManifestValidationError(f"unsafe archive path: {value!r}")
    if path.as_posix() != value:
        raise ManifestValidationError(f"unsafe archive path: {value!r}")
    return value


def verify_archive(path: Path) -> dict:
    """Verify that a ZIP contains exactly its authoritative manifest source set."""
    path = Path(path).expanduser().resolve()
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ManifestValidationError(f"invalid release archive: {path}") from exc
    with archive:
        infos = archive.infolist()
        names: dict[str, zipfile.ZipInfo] = {}
        seen: set[str] = set()
        for info in infos:
            name = _safe_archive_name(info.filename)
            key = name.casefold()
            if key in seen:
                raise ManifestValidationError(f"duplicate archive path: {name}")
            seen.add(key)
            if info.is_dir() or stat.S_ISLNK((info.external_attr >> 16) & 0xFFFF):
                raise ManifestValidationError(f"non-regular archive member: {name}")
            names[name] = info
        manifest_name = f"{ARCHIVE_ROOT}/{MANIFEST_NAME}"
        if manifest_name not in names:
            raise ManifestValidationError("release archive is missing SOURCE_MANIFEST.json")
        if names[manifest_name].file_size > MAX_MANIFEST_BYTES:
            raise ManifestValidationError("archive manifest exceeds safety limit")
        try:
            manifest = validate_manifest(json.loads(archive.read(manifest_name).decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManifestValidationError("archive manifest is not valid UTF-8 JSON") from exc
        expected_names = {f"{ARCHIVE_ROOT}/{item['path']}" for item in manifest["files"]}
        expected_names.add(manifest_name)
        missing = sorted(expected_names - set(names))
        extra = sorted(set(names) - expected_names)
        if missing or extra:
            raise ManifestValidationError(
                "archive source set does not match manifest: "
                + json.dumps({"missing": missing, "extra": extra}, sort_keys=True))
        for item in manifest["files"]:
            name = f"{ARCHIVE_ROOT}/{item['path']}"
            info = names[name]
            if info.file_size != item["bytes"]:
                raise ManifestValidationError(f"archive size mismatch: {item['path']}")
            if hashlib.sha256(archive.read(info)).hexdigest() != item["sha256"]:
                raise ManifestValidationError(f"archive hash mismatch: {item['path']}")
    return {
        "pass": True,
        "kind": "archive",
        "archive": str(path),
        "file_count": manifest["file_count"],
        "tree_sha256": manifest["tree_sha256"],
    }


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, RELEASE_TIMESTAMP)
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def build_release(output: Path, *, root: Path = ROOT) -> tuple[Path, int]:
    """Build a deterministic ZIP and publish it with one atomic replace."""
    root = Path(root).resolve()
    output = Path(output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    files = release_files(root)
    manifest = build_source_manifest(root, files=files)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
                prefix=f".{output.name}.", suffix=".tmp", dir=output.parent,
                delete=False) as handle:
            temporary = Path(handle.name)
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=9) as archive:
            for path in files:
                arcname = PurePosixPath(ARCHIVE_ROOT) / path.relative_to(root).as_posix()
                archive.writestr(_zip_info(arcname.as_posix()), path.read_bytes(),
                                 compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
            archive.writestr(_zip_info(f"{ARCHIVE_ROOT}/{MANIFEST_NAME}"), manifest_bytes(manifest),
                             compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        verify_archive(temporary)
        os.replace(temporary, output)
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    return output, len(files)


def workspace_audit_notice(scan: dict) -> str:
    """Return a human warning for dirty workspaces without changing JSON audit output."""
    if scan.get("pass"):
        return "Workspace hygiene passed for source handoff."
    return DIRTY_WORKSPACE_NOTICE


def main() -> None:
    parser = argparse.ArgumentParser(description="Build or verify a deterministic source-only Arachne release ZIP")
    parser.add_argument("output", nargs="?", type=Path, default=DEFAULT_OUTPUT)
    verification = parser.add_mutually_exclusive_group()
    verification.add_argument(
        "--verify-source", nargs="?", const=ROOT / MANIFEST_NAME, type=Path,
        metavar="MANIFEST", help="Verify an exact source tree against a manifest",
    )
    verification.add_argument(
        "--verify-archive", type=Path, metavar="ZIP",
        help="Verify a clean release ZIP and its embedded manifest",
    )
    verification.add_argument(
        "--reconcile-source", nargs="?", const=ROOT / MANIFEST_NAME, type=Path,
        metavar="MANIFEST",
        help="Prove expected source, then quarantine stale selected source files",
    )
    parser.add_argument("--audit-workspace", action="store_true")
    parser.add_argument("--fail-on-dirty-workspace", action="store_true")
    options = parser.parse_args()
    if options.verify_source is not None:
        manifest_path = options.verify_source.expanduser().resolve()
        print(json.dumps(verify_source(manifest_path.parent, manifest_path), sort_keys=True))
        return
    if options.verify_archive is not None:
        print(json.dumps(verify_archive(options.verify_archive), sort_keys=True))
        return
    if options.reconcile_source is not None:
        manifest_path = options.reconcile_source.expanduser().resolve()
        print(json.dumps(
            reconcile_source_extras(manifest_path.parent, manifest_path),
            sort_keys=True,
        ))
        return
    audit_workspace = options.audit_workspace
    fail_dirty = options.fail_on_dirty_workspace
    if audit_workspace or fail_dirty:
        from artifact_hygiene import scan_workspace_hygiene
        scan = scan_workspace_hygiene(ROOT)
        print(workspace_audit_notice(scan), file=sys.stderr)
        print(json.dumps(scan, ensure_ascii=True, sort_keys=True))
        if fail_dirty and not scan["pass"]:
            raise SystemExit(2)
        if audit_workspace and options.output == DEFAULT_OUTPUT and len(sys.argv) == 2:
            return
    built, count = build_release(options.output)
    print(SOURCE_ONLY_NOTICE)
    print(f"release={built} files={count}")


if __name__ == "__main__":
    main()
