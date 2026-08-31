from scripts import handoff_receipt
from scripts.make_clean_release import release_files


def test_handoff_manifest_excludes_env_and_runtime_files():
    manifest = handoff_receipt.build_manifest()
    paths = {item["path"] for item in manifest["files"]}
    assert "RUN_AFTER_UPLOAD.sh" in paths
    assert ".env" not in paths
    assert "config.json" not in paths
    assert "AUDIT_CHECKPOINT.md" not in paths
    assert "tmp_arachne_pdf_extract.txt" not in paths
    assert not any(path.endswith((".db", ".session", ".pyc", ".log")) for path in paths)
    authoritative = {
        path.relative_to(handoff_receipt.ROOT).as_posix()
        for path in release_files(handoff_receipt.ROOT)
    }
    assert paths == authoritative
    assert manifest["environment"] == {"included": False, "contents_hashed": False}
    assert len(manifest["tree_sha256"]) == 64


def test_handoff_receipt_is_redacted_and_mentions_direct_commands():
    receipt, result = handoff_receipt.build_receipt(write_manifest_file=False)
    assert "ARACHNE HANDOFF RECEIPT" in receipt
    assert "Project: Arachne" in receipt
    assert "TELEGRAM_BOT_TOKEN:" in receipt
    assert "bash RUN_AFTER_UPLOAD.sh bot-start" in receipt
    assert "SOURCE_MANIFEST.json" in receipt
    assert str(handoff_receipt.ROOT) not in receipt
    assert "AA" not in receipt  # bot token bodies should never be printed
    assert "files" in result["manifest"]


def test_handoff_runtime_scan_reports_virtualenv_once(tmp_path, monkeypatch):
    virtualenv = tmp_path / "venv"
    package = virtualenv / "lib" / "python" / "site-packages" / "example"
    package.mkdir(parents=True)
    (package / "module.py").write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setattr(handoff_receipt, "ROOT", tmp_path)

    findings = handoff_receipt._runtime_findings()

    assert findings == [{"path": "venv", "type": "runtime_dir:venv"}]
