from pathlib import Path
from datetime import datetime, timezone
import os
import shlex
import shutil
import sqlite3
import subprocess
import sys

import pytest

from spain_alerts import format_spain_alert


ROOT = Path(__file__).parents[1]


def _launcher_function(text: str, name: str) -> str:
    return text.split(f"{name}() {{", 1)[1].split("\n}", 1)[0]


def _pipeline_diagnostic_python() -> str:
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    body = _launcher_function(text, "pipeline_diagnostic")
    return body.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]


def test_launcher_embeds_systemd_units_with_expected_entrypoints():
    expected = {
        "arachne-fetch-worker.service": "fetch_worker.py --loop --workers 5",
        "arachne-verify-worker.service": "verify_worker.py --loop --workers 5",
        "arachne-card-worker.service": "card_worker.py --loop --workers 2",
        "arachne-deep-discovery-worker.service": "deep_discovery_worker.py --loop --workers 1",
        "arachne-dashboard.service": "-m streamlit run dashboard.py",
        "arachne-bot.service": "arachne.py",
    }
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    assert "write_systemd_units()" in text
    assert '[[ -d "systemd" ]]' not in text
    assert '[[ -d systemd ]]' not in text
    assert "cp -f systemd" not in text
    for name, command in expected.items():
        assert name in text
        assert "WorkingDirectory=$PROJECT_DIR" in text
        assert "$PROJECT_DIR/.venv/bin/python" in text
        assert command in text
        if name in {"arachne-bot.service", "arachne-deep-discovery-worker.service"}:
            assert "Restart=on-failure" in text
        else:
            assert "Restart=always" in text
    for line in text.splitlines():
        if line.startswith("ExecStart="):
            assert "while true" not in line.casefold()
    assert not (ROOT / "systemd" / "arachne-onion-worker.service").exists()


def test_legacy_ops_systemd_installer_delegates_to_canonical_launcher():
    text = (ROOT / "ops" / "install_systemd.sh").read_text(encoding="utf-8")
    executable_lines = "\n".join(line for line in text.splitlines()
                                 if line.strip() and not line.lstrip().startswith("#"))
    assert "$PROJECT_DIR/systemd" not in executable_lines
    assert "install -m 0644" not in executable_lines
    assert 'CONTROL_SCRIPT="$PROJECT_DIR/RUN_AFTER_UPLOAD.sh"' in text
    assert 'exec bash "$CONTROL_SCRIPT" install' in text


def test_previous_service_namespace_requires_explicit_safe_prefix():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    retire = _launcher_function(text, "retire_previous_services")
    install = _launcher_function(text, "install_services")
    assert 'ARACHNE_PREVIOUS_SERVICE_PREFIX:-' in retire
    assert '[[ "$prefix" != "arachne" ]]' in retire
    assert 'systemctl disable --now "$unit"' in retire
    assert 'rm -f -- "$unit_dir/$unit"' in retire
    assert 'rm -rf -- "$unit_dir/$unit.d"' in retire
    assert "previous_service_units \"$prefix\"" in retire
    assert "retire_previous_services" in install
    assert "retire-previous-services) retire_previous_services" in text


def test_previous_database_filename_is_bounded_to_a_basename():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    assert 'PREVIOUS_DB_FILE="${ARACHNE_PREVIOUS_DB_FILE:-}"' in text
    assert '^[A-Za-z0-9][A-Za-z0-9._-]*\\.db$' in text
    assert 'DB_FILES+=("$PREVIOUS_DB_FILE")' in text


def test_database_wipe_has_one_canonical_confirmation_phrase():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    wipe = _launcher_function(text, "wipe_db")
    assert '!= "WIPE ARACHNE DB" &&' not in wipe
    assert '== "WIPE ARACHNE DB" ||' not in wipe


def test_launcher_stops_sqlite_writers_before_database_wide_checks():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    body = text.split("install_or_update() {", 1)[1].split("\n}", 1)[0]
    assert body.index("compile_check") < body.index("stop_all_services")
    assert body.index("deploy_smoke_checks") < body.index("stop_all_services")
    assert body.index("opsec_audit") < body.index("stop_all_services")
    assert body.index("stop_all_services") < body.index("prepare_runtime_storage")
    assert body.index("prepare_runtime_storage") < body.index("consistency_checks")
    assert body.index("consistency_checks") < body.index("queue_dirty_rollups")
    assert "refresh_rollups" not in body
    assert "Restarting services before exiting" in body


def test_launcher_pipeline_diagnostic_is_read_only_non_mutating_and_used_by_status():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    diagnostic = _launcher_function(text, "pipeline_diagnostic")
    overview = _launcher_function(text, "control_overview")
    compact = _launcher_function(text, "compact_status")

    assert "pipeline_diagnostic" in overview
    assert "control_overview" in compact
    assert 'as_uri() + "?mode=ro"' in diagnostic
    assert 'db.execute("PRAGMA query_only=ON")' in diagnostic
    assert "ONION_CRAWLER_ENABLED" in diagnostic
    assert "Claim intake" in diagnostic
    assert "onion_urls" in diagnostic
    assert "fetched_pages" in diagnostic
    assert "site_card_jobs" in diagnostic
    assert "worker_instances" in diagnostic
    assert "last_error" in diagnostic and "safe_error_type" in diagnostic
    assert "\nimport storage" not in diagnostic
    assert "storage.init_db" not in diagnostic
    assert "systemctl" not in diagnostic
    assert "INSERT " not in diagnostic
    assert "UPDATE " not in diagnostic
    assert "DELETE " not in diagnostic


def test_pipeline_diagnostic_reports_real_queue_pause_and_recent_workers_without_leaks(tmp_path):
    db_path = tmp_path / "messages.db"
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    with sqlite3.connect(db_path) as db:
        db.executescript("""
        CREATE TABLE crawler_worker_state(id INTEGER PRIMARY KEY, is_paused INTEGER);
        CREATE TABLE onion_urls(status TEXT);
        CREATE TABLE fetched_pages(classification_status TEXT);
        CREATE TABLE site_card_jobs(status TEXT);
        CREATE TABLE worker_instances(
          worker_type TEXT, state TEXT, last_heartbeat_at TEXT, last_error TEXT
        );
        """)
        db.execute("INSERT INTO crawler_worker_state VALUES(1,1)")
        db.executemany("INSERT INTO onion_urls(status) VALUES(?)", [
            ("new",), ("queued",), ("retry",), ("claimed",), ("fetching",),
            ("classification_pending",), ("deferred_forum_budget",),
            ("deferred_deep_pagination",), ("blocked",), ("metadata_only",),
            ("crawled",), ("dead",),
        ])
        db.executemany("INSERT INTO fetched_pages(classification_status) VALUES(?)", [
            ("pending",), ("claimed",), ("retry",), ("failed",),
            ("dead_letter",), ("done",),
        ])
        db.executemany("INSERT INTO site_card_jobs(status) VALUES(?)", [
            ("queued",), ("claimed",), ("retry",), ("failed",),
            ("dead_letter",), ("done",),
        ])
        db.executemany("INSERT INTO worker_instances VALUES(?,?,?,?)", [
            ("fetch", "idle", now, None),
            ("verify", "error", now,
             "TimeoutError: http://secret-example.onion/private?q=token"),
            ("card", "error", now, "token=super-secret-value"),
            ("preview", "idle", "2000-01-01T00:00:00Z", "ValueError: stale details"),
        ])
    before_mtime = db_path.stat().st_mtime_ns

    env = dict(os.environ)
    env["ONION_CRAWLER_ENABLED"] = "true"
    result = subprocess.run(
        [sys.executable, "-c", _pipeline_diagnostic_python()], cwd=tmp_path,
        env=env, capture_output=True, text=True, timeout=10,
    )

    assert result.returncode == 0, result.stderr
    output = result.stdout
    assert "ONION_CRAWLER_ENABLED: true" in output
    assert "Claim intake: PAUSED" in output
    assert ("onion_urls: new=1 queued=1 retry=1 claimed=2 classification_pending=1 "
            "deferred=2 blocked=2 crawled=1 dead=1") in output
    assert "fetched_pages: pending=1 claimed=1 retry=1 failed=2 done=1" in output
    assert "site_card_jobs: queued=1 claimed=1 retry=1 failed=1 dead_letter=1 done=1" in output
    assert ("Active workers (heartbeat <= 120s): fetch=1 verify=1 card=1 "
            "deep_discovery=0 preview=0 maintenance=0") in output
    assert "TimeoutError=1" in output
    assert "redacted_error=1" in output
    assert "secret-example" not in output
    assert ".onion" not in output
    assert "super-secret-value" not in output
    assert db_path.stat().st_mtime_ns == before_mtime
    assert not (tmp_path / "messages.db-wal").exists()
    assert not (tmp_path / "messages.db-shm").exists()


def test_pipeline_diagnostic_warns_but_succeeds_when_database_is_unavailable(tmp_path):
    env = dict(os.environ)
    env.pop("ONION_CRAWLER_ENABLED", None)
    (tmp_path / ".env").write_text(
        "ONION_CRAWLER_ENABLED=false\nTELEGRAM_BOT_TOKEN=must-not-print\n",
        encoding="utf-8",
    )

    missing = subprocess.run(
        [sys.executable, "-c", _pipeline_diagnostic_python()], cwd=tmp_path,
        env=env, capture_output=True, text=True, timeout=10,
    )
    assert missing.returncode == 0
    assert "ONION_CRAWLER_ENABLED: false (crawler loop disabled)" in missing.stdout
    assert "WARNING: pipeline database unavailable (messages.db missing)" in missing.stdout
    assert "must-not-print" not in missing.stdout

    (tmp_path / "messages.db").write_bytes(b"not a sqlite database")
    malformed = subprocess.run(
        [sys.executable, "-c", _pipeline_diagnostic_python()], cwd=tmp_path,
        env=env, capture_output=True, text=True, timeout=10,
    )
    assert malformed.returncode == 0
    assert "WARNING: pipeline database unavailable (DatabaseError)" in malformed.stdout
    assert "not a sqlite database" not in malformed.stdout


def test_launcher_recovers_runtime_services_when_update_fails():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    assert "recover_runtime_services_after_failure()" in text
    assert "systemctl restart \"${APP_SERVICE_NAMES[@]}\"" in text
    assert "systemctl start \"$BOT_SERVICE_NAME\"" in text
    recovery = text.split("recover_runtime_services_after_failure() {", 1)[1].split("\n}", 1)[0]
    assert "if telegram_config_ready" in recovery
    assert 'disable --now "$BOT_SERVICE_NAME"' in recovery
    install_body = text.split("install_or_update() {", 1)[1].split("\n}", 1)[0]
    safe_body = text.split("safe_update() {", 1)[1].split("\n}", 1)[0]
    assert "trap 'recover_runtime_services_after_failure' ERR" in install_body
    assert "trap 'recover_runtime_services_after_failure' ERR" in safe_body


def test_launcher_restarts_bot_after_install_only_when_configured():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    install_body = text.split("install_or_update() {", 1)[1].split("\n}", 1)[0]
    restart_body = text.split("restart_services() {", 1)[1].split("\n}", 1)[0]
    optional_bot = text.split("restart_bot_if_configured() {", 1)[1].split("\n}", 1)[0]

    assert "restart_bot_service" in text
    assert "restart_bot_if_configured" in install_body
    assert "if telegram_config_ready" in restart_body
    assert 'services+=("$BOT_SERVICE_NAME")' in restart_body
    assert 'disable --now "$BOT_SERVICE_NAME"' in restart_body
    assert "restart_bot_service" in optional_bot


def test_launcher_repairs_access_storage_before_services_without_wiping_auth():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    install_body = text.split("install_or_update() {", 1)[1].split("\n}", 1)[0]
    prepare_body = text.split("prepare_runtime_storage() {", 1)[1].split("\n}", 1)[0]

    assert install_body.index("stop_all_services") < install_body.index("prepare_runtime_storage")
    assert install_body.index("prepare_runtime_storage") < install_body.index("consistency_checks")
    assert 'install -d -m 0700 -o root -g root' in prepare_body
    assert 'runtime/dashboard_access.db' in prepare_body
    assert 'runtime/sessions/*.session*' in prepare_body
    assert 'messages.db-wal' in prepare_body
    assert '$PROJECT_DIR/.env' in prepare_body
    assert 'dashboard_auth.dashboard_access_status()' in prepare_body
    assert 'chmod 0600' in prepare_body
    assert 'rm -f' not in prepare_body
    assert 'repair-access|fix-access) repair_access_storage' in text
    assert 'Repair access-code storage (keeps codes and sessions)' in text


def test_dashboard_code_and_bot_paths_prepare_shared_access_storage():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    code_body = text.split("generate_dashboard_code() {", 1)[1].split("\n}", 1)[0]
    issue_body = text.split("issue_dashboard_code() {", 1)[1].split("\n}", 1)[0]
    bot_body = text.split("ensure_bot_service_running() {", 1)[1].split("\n}", 1)[0]
    restart_body = text.split("restart_bot_service() {", 1)[1].split("\n}", 1)[0]

    assert "issue_dashboard_code" in code_body
    assert "prepare_runtime_storage" in issue_body
    assert "prepare_runtime_storage" in bot_body
    assert "prepare_runtime_storage" in restart_body


def test_launcher_is_single_entrypoint_and_menu_failures_do_not_close_control_ui():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    command_selection = text.index('\ncmd="${1:-menu}"')
    lock_call = text.rindex("\n  acquire_control_lock\n")
    dispatch = text.index('\ncase "$cmd" in')

    assert command_selection < lock_call < dispatch
    assert 'if [[ "$cmd" != "doctor" ]]' in text[command_selection:dispatch]
    assert "run_menu_action()" in text
    assert 'if ! ("$@"); then' in text
    assert '1) run_menu_action "Bootstrap" bootstrap' in text
    assert '3) run_menu_action "Read-only doctor" doctor' in text
    assert "install_update_menu" not in text


def test_launcher_bootstrap_is_non_destructive_and_auto_detects_existing_state():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    bootstrap = _launcher_function(text, "bootstrap")
    first = _launcher_function(text, "bootstrap_first_install")
    env_setup = _launcher_function(text, "ensure_bootstrap_env")

    assert "bootstrap_has_existing_state" in bootstrap
    assert bootstrap.index("require_python_312") < bootstrap.index("validated_update_preflight")
    assert bootstrap.index("ensure_bootstrap_env") < bootstrap.index("validated_update_preflight")
    assert "safe_update" in bootstrap
    assert "bootstrap_first_install" in bootstrap
    assert "fresh_first_install" not in bootstrap
    assert "wipe_db" not in bootstrap
    assert "install_or_update" in first
    assert 'issue_dashboard_code "1h" "bootstrap_first_install"' in first
    assert "wipe_db" not in first
    assert 'install -m 0600 -- ".env.example" ".env"' in env_setup
    assert '[[ -L ".env" ]]' in env_setup
    assert "bootstrap|setup) bootstrap" in text


def test_launcher_doctor_is_read_only_and_distinct_from_post_upload_update():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    doctor = text.split("\ndoctor() {", 1)[1].split("\n}", 1)[0]
    database_checks = _launcher_function(text, "doctor_database_checks")

    assert "--verify-source" in doctor
    assert "PYTHONDONTWRITEBYTECODE=1" in doctor
    assert "doctor_database_checks" in doctor
    assert "systemctl is-active" in doctor
    assert "?mode=ro" in database_checks
    assert 'PRAGMA quick_check' in database_checks
    for mutation in (
        "ensure_venv", "prepare_runtime_storage", "set_env_key", "storage.init_db",
        "apt-get", "systemctl start", "systemctl restart", "systemctl enable",
        "systemctl disable", "rm -", "wipe_db", "install_or_update",
    ):
        assert mutation not in doctor
        assert mutation not in database_checks
    assert "doctor) doctor" in text
    assert "post-upload-doctor) post_upload_doctor" in text
    assert "post-upload-doctor|doctor" not in text


def test_launcher_enforces_exact_python_312_and_rebuilds_wrong_virtualenv():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    selector = _launcher_function(text, "system_python_bin")
    version_check = _launcher_function(text, "python_312_ready")
    requirement = _launcher_function(text, "require_python_312")
    ensure = _launcher_function(text, "ensure_venv")

    assert "python3.12" in selector
    assert "sys.version_info[:2] == (3, 12)" in version_check
    assert "Python 3.12 is required" in requirement
    assert 'system_py="$(require_python_312)"' in ensure
    assert 'python_312_ready ".venv/bin/python"' in ensure
    assert "python3.12-venv" in ensure
    assert (ROOT / ".python-version").read_text(encoding="utf-8").strip() == "3.12"


def test_launcher_proves_uploaded_source_before_any_update_mutation():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    manifest = _launcher_function(text, "verify_manifest")
    reconcile = _launcher_function(text, "reconcile_uploaded_source")
    handoff = _launcher_function(text, "verify_handoff")
    preflight = _launcher_function(text, "validated_update_preflight")
    safe = _launcher_function(text, "safe_update")
    doctor = _launcher_function(text, "post_upload_doctor")
    quick = _launcher_function(text, "quick_update")
    wipe_update = _launcher_function(text, "install_or_update_with_wipe")
    repair_update = _launcher_function(text, "install_or_update_with_repair")
    fresh = _launcher_function(text, "fresh_first_install")

    assert "ensure_venv" not in manifest
    assert "python3 scripts/make_clean_release.py --verify-source" in manifest
    assert "ensure_venv" not in reconcile
    assert "python3 scripts/make_clean_release.py --reconcile-source" in reconcile
    assert "--check --allow-runtime --no-write" in handoff
    assert "ensure_venv" in handoff
    assert "compile_check" in handoff
    assert "deploy_smoke_checks" in handoff
    assert preflight.index("reconcile_uploaded_source") < preflight.index("verify_manifest")
    assert preflight.index("verify_manifest") < preflight.index("verify_handoff")
    assert 'SOURCE_PREFLIGHT_COMPLETE=1' in preflight
    assert safe.index("validated_update_preflight") < safe.index("create_restore_point")
    assert safe.index("validated_update_preflight") < safe.index("install_or_update")
    assert safe.index("validated_update_preflight") < safe.index("trap 'recover_runtime_services_after_failure' ERR")
    assert doctor.index("validated_update_preflight") < doctor.index("create_restore_point")
    assert doctor.index("validated_update_preflight") < doctor.index("trap 'recover_runtime_services_after_failure' ERR")
    assert "safe_update" in quick
    assert "install_or_update" not in quick
    assert wipe_update.index("validated_update_preflight") < wipe_update.index("wipe_db")
    assert repair_update.index("validated_update_preflight") < repair_update.index("repair_db_io")
    assert fresh.index("validated_update_preflight") < fresh.index("ensure_tor_runtime")
    assert "install|update) safe_update" in text


def test_quick_update_really_skips_only_pytest_not_proof_or_compilation():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    quick = _launcher_function(text, "quick_update")
    smoke = _launcher_function(text, "deploy_smoke_checks")
    handoff = _launcher_function(text, "verify_handoff")

    assert "SKIP_TESTS=1" in quick
    assert "safe_update" in quick
    assert 'if [[ "${SKIP_TESTS:-0}" == "1" ]]' in smoke
    assert "Skipping deploy smoke pytest" in smoke
    assert "compile_check" in handoff


def test_launcher_can_build_and_verify_clean_handoff_zip_outside_source():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    build = _launcher_function(text, "build_clean_release")

    assert 'output="${RELEASE_OUTPUT:-$parent/arachne-clean-release-' in build
    assert "expanduser().resolve()" in build
    assert '[[ "$output" != "$PROJECT_DIR"/* ]]' in build
    assert 'python3 scripts/make_clean_release.py "$output"' in build
    assert 'python3 scripts/make_clean_release.py --verify-archive "$output"' in build
    assert "Do not upload the live project folder" in build
    assert "1) Build clean verified handoff ZIP" in text
    assert "build-release|clean-release|handoff-zip) build_clean_release" in text


@pytest.mark.skipif(os.name == "nt", reason="Windows bash resolves through WSL, not a local POSIX shell")
def test_launcher_has_valid_bash_syntax_on_linux():
    completed = subprocess.run(
        ["bash", "-n", str(ROOT / "RUN_AFTER_UPLOAD.sh")],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr


def test_launcher_telegram_validation_is_static_and_preserves_all_admins():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    body = text.split("repair_telegram_env() {", 1)[1].split("\nensure_bot_service_running()", 1)[0]

    assert "getUpdates" not in body
    assert "urllib.request" not in body
    assert "TelegramClient" not in body
    assert '",".join(admin_ids)' in body
    assert '"ADMIN_CHAT_ID": admin_ids[0]' in body
    assert 'authorized admins={len(admin_ids)}' in body


def test_launcher_treats_missing_telegram_credentials_as_optional():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    install_services = text.split("install_services() {", 1)[1].split("\n}", 1)[0]
    install = text.split("install_or_update() {", 1)[1].split("\n}", 1)[0]
    fresh = text.split("fresh_first_install() {", 1)[1].split("\n}", 1)[0]

    assert "telegram_config_ready()" in text
    assert 'systemctl enable "${APP_SERVICE_NAMES[@]}"' in install_services
    assert 'systemctl enable "$BOT_SERVICE_NAME"' in install_services
    assert 'disable --now "$BOT_SERVICE_NAME"' in install_services
    assert "if telegram_config_ready" in install
    assert "installing without the optional bot service" in install
    assert "repair_telegram_env" not in fresh


def test_launcher_blank_configuration_answers_preserve_existing_values():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    body = text.split("configure_env() {", 1)[1].split("\n}", 1)[0]

    assert '[[ -n "$lock_enabled" ]] && set_env_key DASHBOARD_LOCK_ENABLED' in body
    assert '[[ -n "$alerts_enabled" ]] && set_env_key TELEGRAM_AUTO_ALERTS_ENABLED' in body
    assert '[[ -n "$manual_pull" ]] && set_env_key TELEGRAM_MANUAL_PULL_ONLY' in body
    assert '${lock_enabled:-false}' not in body
    assert '${manual_pull:-true}' not in body


def test_launcher_private_environment_updates_use_atomic_helper():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    configure = _launcher_function(text, "configure_env")
    repair = _launcher_function(text, "repair_telegram_env")
    update = _launcher_function(text, "set_env_key")
    bootstrap = _launcher_function(text, "ensure_bootstrap_env")

    assert "ensure_bootstrap_env" in configure
    assert "read_private_env, write_private_env" in repair
    assert "read_private_env, write_private_env" in update
    assert '[[ -L ".env" ]]' in bootstrap


def test_launcher_serializes_maintenance_and_hardens_service_artifacts():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    install_services = text.split("install_services() {", 1)[1].split("\n}", 1)[0]
    install = text.split("install_or_update() {", 1)[1].split("\n}", 1)[0]
    stop_all = text.split("stop_all_services() {", 1)[1].split("\n}", 1)[0]

    assert text.count("UMask=0077") == 8
    assert 'systemctl enable "$MAINTENANCE_TIMER_NAME"' in install_services
    assert 'enable --now "$MAINTENANCE_TIMER_NAME"' not in install_services
    assert 'systemctl stop "$MAINTENANCE_TIMER_NAME" "$MAINTENANCE_SERVICE_NAME"' in install
    assert '"$MAINTENANCE_TIMER_NAME" "$MAINTENANCE_SERVICE_NAME"' in stop_all
    assert 'restore_active_service_snapshot' in text


def test_quick_update_does_not_leave_test_skipping_enabled_in_menu_process():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    body = text.split("quick_update() {", 1)[1].split("\n}", 1)[0]

    assert body.lstrip().startswith("(")
    assert "export SKIP_TESTS=1" in body


def test_spain_alert_can_include_dashboard_deep_link(monkeypatch):
    monkeypatch.setenv("DASHBOARD_URL", "http://127.0.0.1:8501")
    message = format_spain_alert({"category": "fraud_financial", "risk_level": "high"})
    assert "http://127.0.0.1:8501?view=spain" in message


def test_telegram_bot_missing_credentials_fails_service_visibly(monkeypatch):
    env = dict(os.environ)
    env.update({
        "PYTHONPATH": str(ROOT),
        "TELEGRAM_API_ID": "0",
        "TELEGRAM_API_HASH": "",
        "TELEGRAM_BOT_TOKEN": "",
        "ADMIN_CHAT_ID": "",
    })
    result = subprocess.run([sys.executable, str(ROOT / "arachne.py")],
                            cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert "Telegram bot disabled" in result.stdout


def test_launcher_uses_verified_sqlite_snapshots_and_bounded_maintenance_timer():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")

    assert "scripts/backup_sqlite.py" in text
    assert 'cp -a "$db" "$backup_dir/$db"' not in text
    assert "arachne-maintenance.service" in text
    assert "arachne-maintenance.timer" in text
    assert "--maintenance-once" in text
    assert "TimeoutStopSec=120" in text
    assert "DASHBOARD_BIND_ADDRESS" in text
    assert "TELEGRAM_AUTO_ALERTS_ENABLED" in text
    assert "TELEGRAM_ALERTS_ENABLED" not in text
    backup = _launcher_function(text, "backup_db")
    assert "backup_space_preflight" in backup
    assert "if sqlite_snapshot" in backup
    assert "return 1" in backup
    assert "No destructive action is authorized" in backup
    restore = _launcher_function(text, "create_restore_point")
    assert "backup_space_preflight" in restore
    assert "Restore point aborted before writing" in restore
    for function_name in ("safe_update", "post_upload_doctor"):
        update = _launcher_function(text, function_name)
        assert update.index("recover_runtime_services_after_failure") < update.index("stop_all_services")
        assert update.index("stop_all_services") < update.index("create_restore_point")
        assert update.index("create_restore_point") < update.index("install_or_update")


def test_launcher_exposes_only_sanitized_operational_diagnostics():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    body = _launcher_function(text, "build_diagnostic_bundle")
    compile_body = _launcher_function(text, "compile_check")

    assert "operational_observability.py" in compile_body
    assert "--daily-summary --maintain --diagnostic-bundle" in body
    assert "DIAGNOSTIC_HOURS" in body
    assert "hours < 1 || hours > 168" in body
    assert "raw URLs" in body and "credentials" in body and "sessions" in body
    assert "journalctl" not in body
    assert "messages.db" not in body
    assert "diagnostics|diagnostic-bundle|support-bundle) build_diagnostic_bundle" in text
    assert "Build sanitized diagnostic bundle" in text
    assert "alias-audit|entity-audit|identity-audit) alias_quality_audit" in text
    assert "Read-only alias quality audit" in text


def test_launcher_installs_and_compiles_entity_intelligence_runtime():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    compile_body = _launcher_function(text, "compile_check")
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")

    assert "rapidfuzz>=3.14,<4" in requirements
    assert '"rapidfuzz"' in text
    for source in (
        "actor_intelligence.py",
        "entity_extractor.py",
        "entity_quality.py",
        "entity_expansion.py",
        "structured_intelligence.py",
        "dashboard_pages/entity_intelligence.py",
    ):
        assert source in compile_body


def test_launcher_installs_the_complete_dependency_lock():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    ensure_body = _launcher_function(text, "ensure_venv")

    assert 'Path("requirements-lock.txt").read_bytes()' in ensure_body
    assert 'pip install -q -r requirements-lock.txt' in ensure_body
    assert (ROOT / ".python-version").read_text(encoding="utf-8").strip() == "3.12"


def test_observability_defaults_are_bounded_and_documented():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    expected = {
        "OPS_LOG_MAX_BYTES": "10485760",
        "OPS_LOG_BACKUP_COUNT": "5",
        "OPS_LOG_TOTAL_MAX_BYTES": "536870912",
        "OPS_QUEUE_SAMPLE_SECONDS": "60",
        "OPS_DB_SLOW_MS": "250",
        "OPS_LOG_RETENTION_DAYS": "14",
        "OPS_SUMMARY_RETENTION_DAYS": "30",
        "OPS_DIAGNOSTIC_RETENTION_COUNT": "10",
        "TELEGRAM_DIAGNOSTIC_MAX_BYTES": "10485760",
    }
    for key, value in expected.items():
        assert f"{key}={value}" in text


def test_fresh_install_is_explicit_zero_state_while_normal_wipe_fails_closed():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    fresh = _launcher_function(text, "fresh_first_install")
    wipe_update = _launcher_function(text, "install_or_update_with_wipe")
    lock_after_reset = _launcher_function(
        text, "enable_dashboard_lock_after_fresh_reset")
    wipe = _launcher_function(text, "wipe_db")
    install = _launcher_function(text, "install_or_update")

    assert "ENABLE_DASHBOARD_LOCK_AFTER_WIPE=1 WIPE_ACCESS_DB=1 WIPE_DB_BACKUP=0" in fresh
    assert "install_or_update_with_wipe" in fresh
    assert 'if [[ "${ENABLE_DASHBOARD_LOCK_AFTER_WIPE:-0}" == "1" ]]' in wipe_update
    assert wipe_update.index("wipe_db") < wipe_update.index(
        "enable_dashboard_lock_after_fresh_reset")
    assert wipe_update.index("enable_dashboard_lock_after_fresh_reset") < wipe_update.index(
        "install_or_update")
    assert 'set_dashboard_lock_enabled(True, "fresh_first_install")' in lock_after_reset
    assert 'not status.get("enabled")' in lock_after_reset
    assert "DASHBOARD_LOCK_ENABLED=true" in (
        ROOT / ".env.example").read_text(encoding="utf-8")
    assert "disposable SQLite state is NOT backed up" in fresh
    assert "Telegram credentials" in fresh
    assert "Telegram session files" in fresh
    assert "dashboard access codes/sessions" not in fresh
    assert "Resets dashboard codes/sessions" in text
    assert "Reset crawler and dashboard-access DBs" in text
    assert "Keeps .env, access codes/sessions" not in text
    assert fresh.index("ensure_tor_runtime") < fresh.index("install_or_update_with_wipe")
    assert 'if [[ "${WIPE_DB_BACKUP:-1}" != "0" ]]' in wipe
    assert 'wipe_targets+=("${AUTH_DB_FILES[@]}")' in wipe
    assert "reset cancelled because the requested verified backup failed" in wipe
    assert "Nothing was deleted" in wipe
    assert wipe.index("stop_services_checked") < wipe.index("prepare_runtime_storage")
    assert "restore_active_service_snapshot" in wipe
    assert "cp -a --" not in wipe
    assert install.index("repair_telegram_env") < install.index("stop_all_services")
    assert install.index("ensure_tor_runtime") < install.index("stop_all_services")


def test_launcher_bootstraps_tor_before_fail_closed_opsec_audit():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    tor = _launcher_function(text, "ensure_tor_runtime")
    audit = _launcher_function(text, "opsec_audit")

    assert "apt-get install -y tor" in tor
    assert "systemctl enable --now tor.service" in tor
    assert "tor@default.service" in tor
    assert "onion_worker.py --opsec-audit" in audit
    assert "no crawler service was started" in audit


def test_backup_cli_uses_sqlite_snapshot_while_source_is_open(tmp_path):
    source = tmp_path / "live.db"
    target = tmp_path / "snapshot.db"
    with sqlite3.connect(source) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE values_for_test(value TEXT)")
        db.execute("INSERT INTO values_for_test VALUES('committed')")
        db.commit()
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "backup_sqlite.py"),
             "--db", str(source), "--output", str(target)],
            cwd=ROOT, capture_output=True, text=True, timeout=20,
        )

    assert result.returncode == 0, result.stderr
    assert not list(tmp_path.glob("*.snapshot.tmp"))
    with sqlite3.connect(target) as snapshot:
        assert snapshot.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert snapshot.execute("SELECT value FROM values_for_test").fetchone()[0] == "committed"


def test_backup_cli_preserves_previous_snapshot_when_source_is_unreadable(tmp_path):
    source = tmp_path / "broken.db"
    source.write_bytes(b"not-a-sqlite-database")
    target = tmp_path / "previous-good.db"
    with sqlite3.connect(target) as db:
        db.execute("CREATE TABLE marker(value TEXT)")
        db.execute("INSERT INTO marker VALUES('preserve-me')")

    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "backup_sqlite.py"),
         "--db", str(source), "--output", str(target)],
        cwd=ROOT, capture_output=True, text=True, timeout=20,
    )

    assert result.returncode != 0
    assert "snapshot source is not readable as SQLite" in result.stderr
    with sqlite3.connect(target) as snapshot:
        assert snapshot.execute("SELECT value FROM marker").fetchone()[0] == "preserve-me"
    assert not list(tmp_path.glob("*.snapshot.tmp"))


def test_launcher_restore_path_is_explicit_atomic_and_service_controlled():
    text = (ROOT / "RUN_AFTER_UPLOAD.sh").read_text(encoding="utf-8")
    restore = _launcher_function(text, "restore_db")
    retention = _launcher_function(text, "prune_backup_artifacts")

    assert "RESTORE ARACHNE DB" in restore
    assert "RESTORE_DB_KIND" in restore and "RESTORE_DB_SOURCE" in restore
    assert restore.index("stop_services_checked") < restore.index("scripts/restore_sqlite.py")
    assert "--rollback-root" in restore
    assert "rollback_path" in restore
    assert "--no-rollback-snapshot" in restore
    assert "restore_active_service_snapshot" in restore
    assert "prune_backup_artifacts rollback" in restore
    assert 'restore-db|db-restore) restore_db "${2:-}" "${3:-}"' in text
    assert "Restore database from verified snapshot" in text
    assert "scripts/backup_retention.py" in retention
    for kind in ("manual", "restore", "rollback", "config", "stale-source"):
        assert f"--keep-{kind}" in retention


@pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None,
    reason="mocked launcher service lifecycle requires bash",
)
def test_launcher_restore_orders_mocked_service_control_around_restore(tmp_path):
    candidate = tmp_path / "candidate.db"
    target = tmp_path / "messages.db"
    candidate.write_bytes(b"candidate")
    target.write_bytes(b"current")
    rollback = tmp_path / "backups" / "rollback_test" / "messages.db"
    log = tmp_path / "calls.log"
    fake_python = tmp_path / "fake-python"
    fake_python.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "scripts/restore_sqlite.py" ]]; then
  printf 'restore\\n' >> "$MOCK_CALL_LOG"
  if [[ " $* " == *" --no-rollback-snapshot "* ]]; then
    printf '{"restored":true,"rollback_path":null}\\n'
  else
    mkdir -p "$(dirname "$MOCK_ROLLBACK")"
    : > "$MOCK_ROLLBACK"
    printf '{"restored":true,"rollback_path":"%s"}\\n' "$MOCK_ROLLBACK"
  fi
elif [[ "${1:-}" == "-" ]]; then
  printf '%s\\n' "$MOCK_ROLLBACK"
else
  exit 2
fi
""",
        encoding="utf-8",
    )
    fake_python.chmod(0o700)
    launcher = ROOT / "RUN_AFTER_UPLOAD.sh"
    shell = f"""
set -euo pipefail
export PROJECT_DIR={shlex.quote(str(tmp_path))}
export ARACHNE_CONTROL_LIBRARY_ONLY=1
export CONFIRM_RESTORE_DB='RESTORE ARACHNE DB'
export MOCK_CALL_LOG={shlex.quote(str(log))}
export MOCK_ROLLBACK={shlex.quote(str(rollback))}
source {shlex.quote(str(launcher))}
require_project() {{ :; }}
require_root_for_systemd() {{ :; }}
ensure_venv() {{ :; }}
python_bin() {{ printf '%s\\n' {shlex.quote(str(fake_python))}; }}
systemctl() {{ return 0; }}
stop_services_checked() {{ printf 'stop\\n' >> "$MOCK_CALL_LOG"; }}
main_db_ready() {{ printf 'validate\\n' >> "$MOCK_CALL_LOG"; }}
consistency_checks() {{ printf 'consistency\\n' >> "$MOCK_CALL_LOG"; }}
prepare_runtime_storage() {{ printf 'prepare\\n' >> "$MOCK_CALL_LOG"; }}
restore_active_service_snapshot() {{ printf 'restart\\n' >> "$MOCK_CALL_LOG"; }}
prune_backup_artifacts() {{ printf 'prune\\n' >> "$MOCK_CALL_LOG"; }}
restore_db main {shlex.quote(str(candidate))}
"""
    result = subprocess.run(
        ["bash", "-c", shell],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    assert log.read_text(encoding="utf-8").splitlines() == [
        "stop", "restore", "validate", "consistency", "prepare", "restart",
        "prune",
    ]
