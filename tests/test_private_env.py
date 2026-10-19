"""The launcher must never follow .env symlinks or truncate an old file."""
import os

import pytest

from scripts import private_env


def test_private_env_rejects_symlink_without_touching_target(tmp_path):
    target = tmp_path / "unrelated.txt"
    target.write_text("unchanged", encoding="utf-8")
    link = tmp_path / ".env"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable on this host")

    with pytest.raises(ValueError, match="symbolic link"):
        private_env.read_private_env(link)
    with pytest.raises(ValueError, match="symbolic link"):
        private_env.write_private_env("secret=synthetic\n", link)
    assert target.read_text(encoding="utf-8") == "unchanged"


def test_private_env_write_failure_preserves_previous_contents(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text("TOKEN=old\n", encoding="utf-8")

    def interrupted(_source, _destination):
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(private_env.os, "replace", interrupted)
    with pytest.raises(OSError, match="synthetic replace failure"):
        private_env.write_private_env("TOKEN=new\n", path)

    assert private_env.read_private_env(path) == "TOKEN=old\n"
    assert list(tmp_path.glob("..env.*.tmp")) == []


def test_private_env_write_uses_private_mode(tmp_path):
    path = tmp_path / ".env"
    private_env.write_private_env("TOKEN=synthetic\n", path)
    assert private_env.read_private_env(path) == "TOKEN=synthetic\n"
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
