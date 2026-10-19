"""No-follow reads and atomic writes for the launcher's private .env file."""
from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path


def read_private_env(path: Path = Path(".env")) -> str:
    path = Path(path)
    if path.is_symlink():
        raise ValueError(".env must be a private regular file, not a symbolic link")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return ""
    with os.fdopen(descriptor, "r", encoding="utf-8-sig", errors="replace") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError(".env must be a private regular file")
        return handle.read()


def write_private_env(text: str, path: Path = Path(".env")) -> None:
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(".env must be a private regular file, not a symbolic link")
    descriptor, reserved = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp",
                                            dir=path.parent)
    temporary = Path(reserved)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            os.chmod(temporary, 0o600)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ValueError(".env must be a private regular file, not a symbolic link")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
