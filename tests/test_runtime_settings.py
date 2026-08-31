import json

import pytest

import config_loader


def test_dashboard_runtime_settings_are_allowlisted_bounded_and_override_env(tmp_path, monkeypatch):
    runtime_path = tmp_path / "runtime_settings.json"
    monkeypatch.setattr(config_loader, "RUNTIME_CONFIG_PATH", runtime_path)
    monkeypatch.setenv("TOR_SOCKS_IDENTITY_INTERVAL_SECONDS", "1800")
    config_loader.get_config.cache_clear()

    saved = config_loader.save_runtime_settings({
        "TOR_SOCKS_IDENTITY_INTERVAL_SECONDS": 900,
        "TOR_NEWNYM_ENABLED": True,
        "ONION_CRAWL_DELAY_SECONDS": 15,
    })

    assert saved["TOR_SOCKS_IDENTITY_INTERVAL_SECONDS"] == 900
    assert config_loader.get_int("TOR_SOCKS_IDENTITY_INTERVAL_SECONDS", 0) == 900
    assert config_loader.get_bool("TOR_NEWNYM_ENABLED", False) is True
    assert config_loader.runtime_setting_source("TOR_SOCKS_IDENTITY_INTERVAL_SECONDS") == "runtime_settings.json"
    on_disk = json.loads(runtime_path.read_text(encoding="utf-8"))
    assert on_disk == saved
    assert not any("TOKEN" in key or "PASSWORD" in key for key in on_disk)


@pytest.mark.parametrize("key,value", [
    ("TELEGRAM_BOT_TOKEN", "secret"),
    ("TOR_SOCKS_IDENTITY_INTERVAL_SECONDS", 30),
    ("ONION_MAX_DEPTH", 99),
])
def test_dashboard_runtime_settings_reject_secrets_and_unsafe_ranges(tmp_path, monkeypatch, key, value):
    monkeypatch.setattr(config_loader, "RUNTIME_CONFIG_PATH", tmp_path / "runtime_settings.json")
    config_loader.get_config.cache_clear()
    with pytest.raises(ValueError):
        config_loader.save_runtime_settings({key: value})


def test_process_environment_change_invalidates_config_cache(monkeypatch):
    monkeypatch.setenv("ONION_CRAWLER_ENABLED", "false")
    assert config_loader.get_bool("ONION_CRAWLER_ENABLED", True) is False

    monkeypatch.setenv("ONION_CRAWLER_ENABLED", "true")
    assert config_loader.get_bool("ONION_CRAWLER_ENABLED", False) is True


@pytest.mark.parametrize(("configured", "expected"), [
    ("dark", "dark"),
    ("light", "light"),
    (" DARK ", "dark"),
    ("Light", "light"),
])
def test_runtime_ui_theme_accepts_only_supported_themes(
        tmp_path, monkeypatch, configured, expected):
    runtime_path = tmp_path / "runtime_settings.json"
    monkeypatch.setattr(config_loader, "RUNTIME_CONFIG_PATH", runtime_path)
    config_loader.get_config.cache_clear()

    saved = config_loader.save_runtime_settings({"UI_THEME": configured})

    assert saved["UI_THEME"] == expected
    assert config_loader.get_str("UI_THEME") == expected
    assert config_loader.runtime_setting_source("UI_THEME") == "runtime_settings.json"
    assert json.loads(runtime_path.read_text(encoding="utf-8"))["UI_THEME"] == expected


@pytest.mark.parametrize("configured", ["", "graphite", "system", "auto", None, 1])
def test_runtime_ui_theme_rejects_unsupported_values(tmp_path, monkeypatch, configured):
    monkeypatch.setattr(config_loader, "RUNTIME_CONFIG_PATH", tmp_path / "runtime_settings.json")
    config_loader.get_config.cache_clear()

    with pytest.raises(ValueError, match="UI_THEME"):
        config_loader.save_runtime_settings({"UI_THEME": configured})


def test_runtime_ui_theme_overrides_process_environment(tmp_path, monkeypatch):
    runtime_path = tmp_path / "runtime_settings.json"
    monkeypatch.setattr(config_loader, "RUNTIME_CONFIG_PATH", runtime_path)
    monkeypatch.setenv("UI_THEME", "dark")
    config_loader.get_config.cache_clear()

    config_loader.save_runtime_settings({"UI_THEME": "light"})

    assert config_loader.get_str("UI_THEME") == "light"
    assert config_loader.runtime_setting_source("UI_THEME") == "runtime_settings.json"
