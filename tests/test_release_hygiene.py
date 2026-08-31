import ast
import copy
import json
import zipfile
from pathlib import Path

import pytest

import deep_discovery
import identity_registry
import storage
import structured_intelligence

from scripts import make_clean_release
from scripts.make_clean_release import (
    ARCHIVE_ROOT,
    DIRTY_WORKSPACE_NOTICE,
    MANIFEST_NAME,
    ManifestValidationError,
    ROOT,
    SOURCE_ONLY_NOTICE,
    build_source_manifest,
    build_release,
    reconcile_source_extras,
    release_files,
    validate_manifest,
    verify_archive,
    verify_source,
    write_source_manifest,
    workspace_audit_notice,
)


def test_clean_release_is_source_only(tmp_path):
    output, count = build_release(tmp_path / "release.zip")
    assert count > 20
    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
    lowered = [name.casefold() for name in names]
    required = {
        "arachne/.gitattributes",
        "arachne/.github/workflows/ci.yml",
        "arachne/.github/dependabot.yml",
        "arachne/.python-version",
        "arachne/LICENSE",
        "arachne/requirements-lock.txt",
        "arachne/README.md",
        "arachne/AGENTS.md",
        "arachne/dashboard.py",
        "arachne/storage.py",
        "arachne/deep_discovery_worker.py",
        "arachne/deep_discovery_providers.py",
        "arachne/operational_observability.py",
        "arachne/entity_quality.py",
        "arachne/entity_expansion.py",
        "arachne/entity_noise_rules.json",
        "arachne/dashboard_pages/entity_intelligence.py",
        "arachne/OPEN_SOURCE_INTEGRATIONS.md",
        "arachne/log_redaction.py",
        "arachne/.env.example",
        "arachne/.streamlit/config.toml",
        "arachne/SOURCE_HANDOFF.md",
        "arachne/scripts/restore_sqlite.py",
        "arachne/scripts/backup_retention.py",
        "arachne/docs/architecture.md",
        "arachne/docs/deployment.md",
        "arachne/docs/launch-readiness/08-release-checklist.md",
        "arachne/docs/launch-readiness/09-final-report.md",
        "arachne/RUN_AFTER_UPLOAD.sh",
        "arachne/tests/test_release_hygiene.py",
        "arachne/tests/test_deep_discovery_worker.py",
        "arachne/tests/test_operational_observability.py",
        "arachne/assets/brand/arachne_mark.svg",
        "arachne/assets/brand/favicon.ico",
        "arachne/SOURCE_MANIFEST.json",
    }
    assert required.issubset(set(names))
    assert "arachne/structured_demo_cards.json" not in names
    assert "arachne/design_preview.py" not in names
    assert "arachne/config.json" not in names
    assert "arachne/AUDIT_CHECKPOINT.md" not in names
    assert "arachne/tmp_arachne_pdf_extract.txt" not in names
    assert not any(name.startswith("arachne/systemd/") for name in names)
    forbidden_parts = {"backups", "reports", "logs", "previews", "screenshots", "__pycache__", ".pytest_cache"}
    for name in lowered:
        parts = set(name.rstrip("/").split("/"))
        basename = name.rsplit("/", 1)[-1]
        assert not parts.intersection(forbidden_parts)
        assert basename != ".env"
        assert basename not in {"runtime_settings.json", "runtime_settings.json.tmp"}
        assert not basename.endswith((".db", ".db-wal", ".db-shm", ".session", ".session-journal",
                                      ".pyc", ".zip", ".7z", ".log"))
        assert ".bak" not in basename
        assert not (basename.startswith("informe_") and basename.endswith((".json", ".txt")))
        assert not (basename.startswith("log_") and basename.endswith((".log", ".txt")))
        assert not basename.startswith("arachne.db.empty")
    verification = verify_archive(output)
    assert verification["pass"] is True
    with zipfile.ZipFile(output) as archive:
        manifest = json.loads(archive.read(f"{ARCHIVE_ROOT}/{MANIFEST_NAME}"))
    manifest_paths = {item["path"] for item in manifest["files"]}
    assert MANIFEST_NAME not in manifest_paths
    expected = {f"{ARCHIVE_ROOT}/{path}" for path in manifest_paths}
    expected.add(f"{ARCHIVE_ROOT}/{MANIFEST_NAME}")
    assert set(names) == expected


def test_env_example_documents_every_literal_production_config_key():
    getters = {"get_bool", "get_float", "get_int", "get_str"}
    used: set[str] = set()
    for source in release_files(ROOT):
        relative = source.relative_to(ROOT)
        if source.suffix != ".py" or relative.parts[0] == "tests":
            continue
        tree = ast.parse(source.read_text(encoding="utf-8-sig"), filename=str(source))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            function = node.func
            name = function.id if isinstance(function, ast.Name) else (
                function.attr if isinstance(function, ast.Attribute) else ""
            )
            first = node.args[0]
            if name in getters and isinstance(first, ast.Constant) and isinstance(first.value, str):
                used.add(first.value)

    documented = {
        line.split("=", 1)[0].strip()
        for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
    }
    assert used <= documented, f"undocumented configuration keys: {sorted(used - documented)}"


def test_fresh_source_has_no_preconfigured_live_telegram_groups():
    source_path = ROOT / "arachne.py"
    text = source_path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    defaults = None
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == "DEFAULT_GROUPS"
                   for target in targets):
                defaults = ast.literal_eval(node.value)
                break

    assert defaults in ([], ())
    assert "-1003310605026" not in text
    assert "-1002586105484" not in text


def test_pytest_telegram_sessions_live_outside_the_source_tree():
    """Collection-time Telegram imports must not touch deployable sessions."""
    import arachne

    root = Path(__file__).parents[1].resolve()
    for telegram_client in (arachne.client, arachne.bot):
        filename = Path(str(telegram_client.session.filename)).resolve()
        assert not filename.is_relative_to(root)


def test_clean_release_bundles_an_empty_identity_registry(tmp_path):
    output, _ = build_release(tmp_path / "release.zip")
    with zipfile.ZipFile(output) as archive:
        registry = json.loads(archive.read("arachne/identity_registry.json"))
    assert registry.get("entities") == []


def test_removed_demo_apis_are_not_exposed_by_production_modules():
    removed = {
        identity_registry: {"demo_entities"},
        structured_intelligence: {"validate_demo_cards", "get_demo_card", "reset_demo_cards"},
        deep_discovery: {"demo_deep_discovery_run", "ingest_fictional_demo_pages"},
    }
    for module, names in removed.items():
        assert not {name for name in names if hasattr(module, name)}, module.__name__


def test_legacy_bundled_examples_cleanup_is_narrow_and_idempotent(isolated_db):
    fixed_demo_url = f"http://{'n' * 56}.onion/"
    marked_demo_url = f"http://{'z' * 56}.onion/demo-profile"
    normal_url = f"http://{'a' * 56}.onion/"
    storage.insert_or_update_onion_url(normal_url)
    with storage.get_db() as db:
        now = storage.utc_now_iso()
        db.execute("INSERT INTO onion_urls(url,onion_domain,first_seen) VALUES(?,?,?)",
                   (fixed_demo_url, "n" * 56 + ".onion", now))
        db.execute("""INSERT INTO onion_urls(url,onion_domain,first_seen,safety_reason)
          VALUES(?,?,?,'fictional_demo')""",
                   (marked_demo_url, "z" * 56 + ".onion", now))
        assert storage._cleanup_legacy_bundled_examples(db) == 1
        assert storage._cleanup_legacy_bundled_examples(db) == 0
        remaining = {row[0] for row in db.execute("SELECT url FROM onion_urls")}
    assert fixed_demo_url in remaining
    assert marked_demo_url not in remaining
    assert normal_url in remaining


def test_gitignore_covers_private_runtime_patterns():
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (
            "*.db", "*.session", ".env", "runtime_settings.json", "backups/",
            "reports/", "__pycache__/", ".pytest_cache/", ".venv/", "venv/",
            "handoff_receipts/", "HANDOFF_RECEIPT.txt", "build/", "dist/",
            "*.bak*", "*.log", "informe_*.json", "arachne.db.empty*"):
        assert pattern in text


def test_clean_release_is_byte_deterministic(tmp_path):
    first, _ = build_release(tmp_path / "first.zip")
    second, _ = build_release(tmp_path / "second.zip")
    assert first.read_bytes() == second.read_bytes()


def _small_source_tree(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "app.py").write_text("print('one')\n", encoding="utf-8")
    (root / "README.md").write_text("# source\n", encoding="utf-8")
    return root


def test_source_manifest_verifies_exact_selected_set_and_excludes_scratch(tmp_path):
    root = _small_source_tree(tmp_path)
    scratch = root / ".pytest-local" / "tests"
    scratch.mkdir(parents=True)
    (scratch / "copied_test.py").write_text("assert False\n", encoding="utf-8")
    manifest_path = root / MANIFEST_NAME
    manifest = write_source_manifest(root, manifest_path)
    assert [item["path"] for item in manifest["files"]] == ["README.md", "app.py"]
    assert verify_source(root, manifest_path)["pass"] is True


@pytest.mark.parametrize("change", ["changed", "missing", "extra"])
def test_source_verification_rejects_stale_missing_changed_and_extra_files(tmp_path, change):
    root = _small_source_tree(tmp_path)
    manifest_path = root / MANIFEST_NAME
    write_source_manifest(root, manifest_path)
    if change == "changed":
        (root / "app.py").write_text("print('changed')\n", encoding="utf-8")
    elif change == "missing":
        (root / "app.py").unlink()
    else:
        (root / "new.py").write_text("NEW = True\n", encoding="utf-8")
    with pytest.raises(ManifestValidationError, match=change):
        verify_source(root, manifest_path)


def test_source_reconcile_quarantines_only_stale_selected_source(tmp_path):
    root = _small_source_tree(tmp_path)
    manifest_path = root / MANIFEST_NAME
    write_source_manifest(root, manifest_path)
    stale = root / "old_component.py"
    stale.write_text("OLD = True\n", encoding="utf-8")
    nested_stale = root / "ops" / "systemd" / "obsolete.service"
    nested_stale.parent.mkdir(parents=True)
    nested_stale.write_text("[Service]\n", encoding="utf-8")
    runtime = root / "runtime"
    runtime.mkdir()
    session = runtime / "operator.session"
    session.write_text("private-session", encoding="utf-8")
    environment = root / ".env"
    environment.write_text("TOKEN=private\n", encoding="utf-8")
    database = root / "messages.db"
    database.write_bytes(b"private-db")

    result = reconcile_source_extras(root, manifest_path)

    assert result["pass"] is True
    assert result["quarantined"] == ["old_component.py", "ops/systemd/obsolete.service"]
    quarantine = root / result["quarantine"]
    assert (quarantine / "old_component.py").read_text(encoding="utf-8") == "OLD = True\n"
    assert (quarantine / "ops/systemd/obsolete.service").read_text(encoding="utf-8") == "[Service]\n"
    assert (quarantine / "RECONCILE.json").is_file()
    assert not stale.exists()
    assert not nested_stale.exists()
    assert session.read_text(encoding="utf-8") == "private-session"
    assert environment.read_text(encoding="utf-8") == "TOKEN=private\n"
    assert database.read_bytes() == b"private-db"
    assert verify_source(root, manifest_path)["pass"] is True


@pytest.mark.parametrize("breakage", ["changed", "missing"])
def test_source_reconcile_never_moves_extras_when_expected_source_is_invalid(tmp_path, breakage):
    root = _small_source_tree(tmp_path)
    manifest_path = root / MANIFEST_NAME
    write_source_manifest(root, manifest_path)
    stale = root / "old_component.py"
    stale.write_text("OLD = True\n", encoding="utf-8")
    if breakage == "changed":
        (root / "app.py").write_text("print('tampered')\n", encoding="utf-8")
    else:
        (root / "app.py").unlink()

    with pytest.raises(ManifestValidationError, match="no stale files were moved"):
        reconcile_source_extras(root, manifest_path)

    assert stale.is_file()
    assert not (root / "backups").exists()


def test_source_reconcile_restores_already_moved_files_if_quarantine_move_fails(tmp_path, monkeypatch):
    root = _small_source_tree(tmp_path)
    manifest_path = root / MANIFEST_NAME
    write_source_manifest(root, manifest_path)
    first = root / "first_old.py"
    second = root / "second_old.py"
    first.write_text("FIRST = True\n", encoding="utf-8")
    second.write_text("SECOND = True\n", encoding="utf-8")
    real_replace = make_clean_release.os.replace
    move_attempts = 0

    def fail_second_quarantine_move(source, destination):
        nonlocal move_attempts
        if "stale-source-" in str(destination) and str(destination).endswith(".py"):
            move_attempts += 1
            if move_attempts == 2:
                raise OSError("simulated bounded move failure")
        return real_replace(source, destination)

    monkeypatch.setattr(make_clean_release.os, "replace", fail_second_quarantine_move)

    with pytest.raises(OSError, match="bounded move failure"):
        reconcile_source_extras(root, manifest_path)

    assert first.read_text(encoding="utf-8") == "FIRST = True\n"
    assert second.read_text(encoding="utf-8") == "SECOND = True\n"


def test_source_reconcile_is_idempotent_after_stale_files_are_quarantined(tmp_path):
    root = _small_source_tree(tmp_path)
    manifest_path = root / MANIFEST_NAME
    write_source_manifest(root, manifest_path)
    (root / "old_component.py").write_text("OLD = True\n", encoding="utf-8")

    first = reconcile_source_extras(root, manifest_path)
    second = reconcile_source_extras(root, manifest_path)

    assert first["quarantined"] == ["old_component.py"]
    assert second["pass"] is True
    assert second["quarantined"] == []
    assert second["quarantine"] is None
    assert (root / first["quarantine"] / "old_component.py").is_file()


def test_manifest_validation_rejects_unsafe_duplicate_and_invalid_schema(tmp_path):
    root = _small_source_tree(tmp_path)
    original = build_source_manifest(root)

    unsafe = copy.deepcopy(original)
    unsafe["files"][0]["path"] = "../outside.py"
    with pytest.raises(ManifestValidationError, match="unsafe manifest path"):
        validate_manifest(unsafe)

    duplicate = copy.deepcopy(original)
    duplicate["files"].append(copy.deepcopy(duplicate["files"][0]))
    duplicate["file_count"] += 1
    duplicate["total_bytes"] += duplicate["files"][0]["bytes"]
    with pytest.raises(ManifestValidationError, match="duplicate manifest path"):
        validate_manifest(duplicate)

    invalid_schema = copy.deepcopy(original)
    invalid_schema["unexpected"] = True
    with pytest.raises(ManifestValidationError, match="schema fields"):
        validate_manifest(invalid_schema)


def _rewrite_archive(source, destination, *, mutate=None, omit=None, extra=None):
    with zipfile.ZipFile(source) as incoming, zipfile.ZipFile(destination, "w") as outgoing:
        for name in incoming.namelist():
            if name == omit:
                continue
            payload = incoming.read(name)
            if mutate is not None and name in mutate:
                payload = mutate[name](payload)
            outgoing.writestr(name, payload)
        if extra is not None:
            outgoing.writestr(extra, b"unexpected")


@pytest.mark.parametrize("tamper", ["changed", "missing", "extra", "manifest"])
def test_archive_verification_rejects_tampering(tmp_path, tamper):
    root = _small_source_tree(tmp_path)
    release, _ = build_release(tmp_path / "release.zip", root=root)
    tampered = tmp_path / f"{tamper}.zip"
    app_member = f"{ARCHIVE_ROOT}/app.py"
    manifest_member = f"{ARCHIVE_ROOT}/{MANIFEST_NAME}"
    kwargs = {}
    if tamper == "changed":
        kwargs["mutate"] = {app_member: lambda _payload: b"print('tampered')\n"}
    elif tamper == "missing":
        kwargs["omit"] = app_member
    elif tamper == "extra":
        kwargs["extra"] = f"{ARCHIVE_ROOT}/unexpected.py"
    else:
        def corrupt_manifest(payload):
            manifest = json.loads(payload)
            manifest["file_count"] += 1
            return json.dumps(manifest).encode("utf-8")
        kwargs["mutate"] = {manifest_member: corrupt_manifest}
    _rewrite_archive(release, tampered, **kwargs)
    with pytest.raises(ManifestValidationError):
        verify_archive(tampered)


def test_release_publish_is_atomic_when_verification_fails(tmp_path, monkeypatch):
    root = _small_source_tree(tmp_path)
    output = tmp_path / "release.zip"
    output.write_bytes(b"previous-release")

    def fail_verification(_path):
        raise ManifestValidationError("forced verification failure")

    monkeypatch.setattr(make_clean_release, "verify_archive", fail_verification)
    with pytest.raises(ManifestValidationError, match="forced"):
        build_release(output, root=root)
    assert output.read_bytes() == b"previous-release"
    assert list(tmp_path.glob(f".{output.name}.*.tmp")) == []


def test_release_messages_make_raw_workspace_upload_risk_clear():
    assert "SOURCE-ONLY" in SOURCE_ONLY_NOTICE
    for phrase in ("databases", "sessions", ".env", "backups"):
        assert phrase in SOURCE_ONLY_NOTICE

    dirty = workspace_audit_notice({"pass": False})
    assert dirty == DIRTY_WORKSPACE_NOTICE
    assert "Clean the folder before direct upload" in dirty
    assert "does not delete anything" in dirty

    clean = workspace_audit_notice({"pass": True})
    assert "passed" in clean
