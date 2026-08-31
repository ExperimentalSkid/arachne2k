"""Configuration loading with environment overrides and secret-safe display."""
from __future__ import annotations

import json
import hashlib
import os
from functools import lru_cache
from pathlib import Path
from threading import RLock
from typing import Any

from paths import CONFIG_PATH

try:
    from dotenv import load_dotenv
except ImportError:  # optional at import time
    load_dotenv = None

_SECRET_MARKERS = ("TOKEN", "SECRET", "PASSWORD", "API_HASH", "COOKIE", "SESSION",
                   "PRIVATE", "KEY", "BEARER", "AUTH")
RUNTIME_CONFIG_PATH = CONFIG_PATH.parent / "runtime_settings.json"
RUNTIME_SETTING_RULES: dict[str, tuple[str, int | None, int | None]] = {
    "UI_THEME": ("enum:dark,light", None, None),
    "TOR_SOCKS_IDENTITY_INTERVAL_SECONDS": ("int", 600, 3600),
    "TOR_NEWNYM_ENABLED": ("bool", None, None),
    "TOR_NEWNYM_INTERVAL_SECONDS": ("int", 600, 3600),
    "TOR_NEWNYM_EVERY_REQUESTS": ("int", 0, 10000),
    "TOR_NEWNYM_MIN_INTERVAL_SECONDS": ("int", 600, 3600),
    "ONION_CRAWL_DELAY_SECONDS": ("int", 5, 120),
    "ONION_REQUEST_TIMEOUT_SECONDS": ("int", 10, 120),
    "ONION_MAX_DEPTH": ("int", 1, 6),
    "ONION_INTERNAL_MAX_DEPTH": ("int", 2, 12),
    "ENABLE_PAGE_SCREENSHOTS": ("bool", None, None),
    "SCREENSHOT_MAX_PER_RUN": ("int", 1, 50),
    "SCREENSHOT_TIMEOUT_SECONDS": ("int", 5, 120),
}
_WRITE_LOCK = RLock()


def _is_config_env_key(key: str, data: dict[str, Any] | None = None) -> bool:
    return bool(
        (data is not None and key in data)
        or key.startswith((
            "TELEGRAM_", "ADMIN_", "TOR_", "ONION_", "ALLOW_", "ENABLE_",
            "SCREENSHOT_", "PREVIEW_", "APP_ENV", "DASHBOARD_", "DEEP_", "UI_",
        ))
    )


def _file_signature(path: Path) -> tuple[int, int]:
    try:
        stat = path.stat()
        return stat.st_mtime_ns, stat.st_size
    except OSError:
        return 0, 0


def _environment_signature() -> str:
    """Notice process-env changes without retaining secret values in cache keys."""
    digest = hashlib.sha256()
    for key, value in sorted(os.environ.items()):
        digest.update(key.encode("utf-8", "surrogatepass"))
        digest.update(b"\0")
        digest.update(value.encode("utf-8", "surrogatepass"))
        digest.update(b"\0")
    return digest.hexdigest()


def _config_signature() -> tuple[Any, ...]:
    return (_file_signature(CONFIG_PATH.parent / ".env"), _file_signature(CONFIG_PATH),
            _file_signature(RUNTIME_CONFIG_PATH), _environment_signature())


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}
    except (OSError, ValueError):
        return {}


@lru_cache(maxsize=8)
def _get_config(_signature: tuple[Any, ...]) -> dict:
    if load_dotenv:
        load_dotenv(CONFIG_PATH.parent / ".env", override=False)
    data: dict[str, Any] = _load_json_object(CONFIG_PATH)
    for key, value in os.environ.items():
        if _is_config_env_key(key, data):
            data[key] = value
    runtime = _load_json_object(RUNTIME_CONFIG_PATH)
    data.update({key: value for key, value in runtime.items() if key in RUNTIME_SETTING_RULES})
    return data


def get_config() -> dict:
    """Load configuration and automatically notice dashboard setting changes."""
    return _get_config(_config_signature())


get_config.cache_clear = _get_config.cache_clear  # type: ignore[attr-defined]


def _validated_runtime_value(key: str, value: Any) -> bool | int | str:
    if key not in RUNTIME_SETTING_RULES:
        raise ValueError(f"Setting is not editable from the dashboard: {key}")
    kind, minimum, maximum = RUNTIME_SETTING_RULES[key]
    if kind == "bool":
        if isinstance(value, bool):
            return value
        normalized = str(value).strip().casefold()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        raise ValueError(f"Invalid on/off value for {key}")
    if kind.startswith("enum:"):
        allowed = tuple(item for item in kind.removeprefix("enum:").split(",") if item)
        normalized = str(value or "").strip().casefold()
        if normalized not in allowed:
            raise ValueError(f"Invalid value for {key}; choose one of: {', '.join(allowed)}")
        return normalized
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid numeric value for {key}") from exc
    if minimum is not None and number < minimum or maximum is not None and number > maximum:
        raise ValueError(f"Value for {key} must be between {minimum} and {maximum}")
    return number


def get_runtime_settings() -> dict[str, bool | int | str]:
    runtime = _load_json_object(RUNTIME_CONFIG_PATH)
    return {key: _validated_runtime_value(key, value) for key, value in runtime.items()
            if key in RUNTIME_SETTING_RULES}


def save_runtime_settings(updates: dict[str, Any]) -> dict[str, bool | int | str]:
    """Atomically save secret-free, bounded settings editable from the GUI."""
    validated = {key: _validated_runtime_value(key, value) for key, value in updates.items()}
    with _WRITE_LOCK:
        merged = get_runtime_settings()
        merged.update(validated)
        RUNTIME_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        temporary = RUNTIME_CONFIG_PATH.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(RUNTIME_CONFIG_PATH)
        _get_config.cache_clear()
    return merged


def runtime_setting_source(key: str) -> str:
    if key in get_runtime_settings():
        return "runtime_settings.json"
    if key in os.environ:
        return "environment"
    env_path = CONFIG_PATH.parent / ".env"
    try:
        if any(line.split("=", 1)[0].strip() == key for line in env_path.read_text(
                encoding="utf-8", errors="ignore").splitlines() if "=" in line and not line.lstrip().startswith("#")):
            return ".env"
    except OSError:
        pass
    if key in _load_json_object(CONFIG_PATH):
        return "config.json"
    return "default"


def effective_config_value(key: str, default: Any = None) -> Any:
    return get_config().get(key, default)


def safe_config_summary() -> dict[str, dict[str, Any]]:
    """Return effective values and provenance without ever revealing secrets."""
    summary = {}
    for key, value in sorted(get_config().items()):
        secret = any(marker in key.upper() for marker in _SECRET_MARKERS)
        summary[key] = {
            "value": "***redacted***" if secret else value,
            "source": runtime_setting_source(key),
            "editable": key in RUNTIME_SETTING_RULES,
            "range": RUNTIME_SETTING_RULES.get(key),
        }
    return summary


def get_str(key: str, default: str | None = None) -> str | None:
    value = get_config().get(key, default)
    return default if value is None else str(value)


def get_int(key: str, default: int) -> int:
    try:
        return int(get_config().get(key, default))
    except (TypeError, ValueError):
        return default


def get_bool(key: str, default: bool = False) -> bool:
    value = get_config().get(key, default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def redact_config(config: dict) -> dict:
    result = {}
    for key, value in config.items():
        result[key] = "***redacted***" if any(marker in key.upper() for marker in _SECRET_MARKERS) else value
    return result
