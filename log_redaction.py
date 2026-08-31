"""Secret-safe formatting for logs and operator-facing error messages."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_SECRET_KEYS = re.compile(
    r"(?i)(access[_-]?token|api[_-]?(?:key|hash)|client[_-]?secret|auth|bearer|"
    r"bot[_-]?token|cookie|password|private[_-]?key|secret|session)"
)
_TELEGRAM_TOKEN = re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{20,}\b")
_ASSIGNMENT_SECRET = re.compile(
    r"(?i)\b(access[_-]?token|api[_-]?(?:key|hash)|client[_-]?secret|authorization|bearer|"
    r"bot[_-]?token|cookie|password|private[_-]?key|secret|session)"
    r"\s*[:=]\s*([^\s,;]+)"
)
_ONION_URL = re.compile(r"https?://([a-z2-7]{16,56}\.onion)([^\s]*)", re.IGNORECASE)
_ONION_HOST = re.compile(r"(?i)\b([a-z2-7]{16,56})\.onion\b")


def _redact_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if not parsed.scheme or not parsed.netloc:
        return value
    query = urlencode([(key, "[REDACTED]" if _SECRET_KEYS.search(key) else item)
                       for key, item in parse_qsl(parsed.query, keep_blank_values=True)])
    host = parsed.hostname or ""
    netloc = parsed.netloc
    if parsed.username is not None or parsed.password is not None:
        host_text = f"[{host}]" if ":" in host and not host.startswith("[") else host
        netloc = f"[REDACTED]@{host_text}"
        if parsed.port:
            netloc += f":{parsed.port}"
    if host.casefold().endswith(".onion") and len(host) > 24:
        short_host = f"{host[:8]}...{host[-9:]}"
        netloc = netloc.replace(host, short_host)
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))


def redact_for_log(value: object) -> str:
    """Redact secrets/query credentials while retaining useful failure context."""
    text = str(value)
    text = _TELEGRAM_TOKEN.sub("[REDACTED_TELEGRAM_TOKEN]", text)
    text = _ASSIGNMENT_SECRET.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)

    def replace_url(match: re.Match[str]) -> str:
        return _redact_url(match.group(0))

    text = re.sub(r"(?:https?|socks5h?)://[^\s<>\"']+", replace_url, text)
    text = _ONION_URL.sub(lambda match: _redact_url(match.group(0)), text)
    return _ONION_HOST.sub(lambda match: f"{match.group(1)[:8]}...{match.group(1)[-8:]}.onion", text)
