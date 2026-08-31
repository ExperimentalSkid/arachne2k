"""Central passive-collection safety policy."""
from __future__ import annotations

import html
import json
import re
import unicodedata
from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit
from pathlib import Path

ALLOWED_CONTENT_TYPES = {"text/html", "text/plain", "application/xhtml+xml"}
BLOCKED_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".exe", ".dll", ".scr",
    ".bat", ".cmd", ".ps1", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4", ".avi", ".mov",
    ".mkv", ".iso", ".apk",
}

_CREDENTIAL_LINE = re.compile(r"(?im)^.{0,40}(?:user(?:name)?|login|email)\s*[:=].{0,80}(?:pass(?:word)?|pwd|token)\s*[:=].*$")
_PASSWORD = re.compile(r"(?i)\b(pass(?:word)?|pwd)\s*[:=]\s*[^\s,;]+")
_TOKEN = re.compile(r"(?i)\b(token|bearer|session[_ -]?id)\s*[:=]\s*[A-Za-z0-9._~+/=-]{8,}")
_API_KEY = re.compile(r"(?i)\b(api[_ -]?key|secret[_ -]?key)\s*[:=]\s*[A-Za-z0-9._~+/=-]{8,}")
_COOKIE = re.compile(r"(?i)\b(cookie|set-cookie)\s*[:=]\s*[^\r\n]+")


# ``severe_abuse_risk`` is intentionally kept separate from the adult filter.
# Adult child links may be scoped/aggregated by directory pages; confirmed severe
# content is a fail-closed blackhole whose only durable result is a safe tombstone.
SEVERE_BLACKHOLE_CATEGORY = "severe_abuse_risk"
SEVERE_BLACKHOLE_REASON = "severe_abuse_blackhole"
SEVERE_BLACKHOLE_MARKER = "severe_restricted_blackhole"


def _configured_severe_context_terms() -> tuple[str, ...]:
    defaults = ("child porn", "childporn", "child pornography", "underage porn",
                "preteen porn", "minor porn", "pedo", "pedophile", "pedofilo",
                "pedofilia", "loli", "lolicon", "jailbait", "cp")
    try:
        payload = json.loads(Path(__file__).with_name("safety_filter_config.json").read_text(encoding="utf-8"))
        configured = payload.get("categories", {}).get(SEVERE_BLACKHOLE_CATEGORY, {}).get(
            "context_bound_terms", [])
        values = tuple(str(value).strip().casefold() for value in configured if str(value).strip())
        return values or defaults
    except (OSError, ValueError, TypeError, AttributeError):
        return defaults


def _context_term_pattern(values: tuple[str, ...]) -> re.Pattern[str]:
    alternatives = []
    for value in values:
        tokens = [re.escape(token) for token in re.split(r"[\W_]+", value) if token]
        if tokens:
            alternatives.append(r"[\W_]*".join(tokens))
    return re.compile(r"(?<!\w)(?:" + "|".join(sorted(set(alternatives), key=len, reverse=True)) + r")(?!\w)")


_SEVERE_CONTEXT_TERM_PATTERN = _context_term_pattern(_configured_severe_context_terms())

_SEVERE_EXPLICIT_PATTERNS = (
    # Canonical acronym plus common separator/spacing/Unicode-normalized forms.
    re.compile(r"(?<!\w)c(?:[\W_]{0,4})s(?:[\W_]{0,4})a(?:[\W_]{0,4})m(?!\w)"),
    re.compile(r"(?<!\w)child[\W_]+sexual[\W_]+abuse[\W_]+material(?!\w)"),
    re.compile(r"(?<!\w)material[\W_]+(?:de[\W_]+)?abuso[\W_]+sexual[\W_]+infantil(?!\w)"),
    re.compile(r"(?<!\w)abuso[\W_]+sexual[\W_]+infantil(?!\w)"),
    re.compile(r"(?<!\w)pornografia[\W_]+infantil(?!\w)"),
)
_SEVERE_MINOR_PATTERN = re.compile(
    r"(?<!\w)(?:child|children|minor|minors|underage|preteen|high[\W_]+school|"
    r"menor|menores|infantil)(?!\w)"
)
_SEVERE_SEXUAL_PATTERN = re.compile(
    r"(?<!\w)(?:sexual|sexually|sex|porn|pornographic|pornografia|nude|nudes|nudism|"
    r"pussy|anal|orgasm|fucked|explicit[\W_]+sexual)(?!\w)"
)
_SEVERE_EXCHANGE_PATTERN = re.compile(
    r"(?<!\w)(?:download|files?|gallery|pics?|photos?|videos?|preview|webcam|board|"
    r"trade|exchange|request|sell|sale|buy|purchase|"
    r"comprar|venta|vender|intercambio|descargar|archivo|archivos)(?!\w)"
)
_SEVERE_EUPHEMISM_PATTERN = _SEVERE_CONTEXT_TERM_PATTERN
_SEVERE_PROTECTIVE_PATTERN = re.compile(
    r"(?<!\w)(?:news[\W_]+report|report[\W_]+abuse|reporting|prevention|awareness|"
    r"child[\W_]+safety|legal[\W_]+guidance|law[\W_]+enforcement|education|research|"
    r"noticia|periodismo|denunciar|denuncia|prevencion|concienciacion|"
    r"seguridad[\W_]+infantil|orientacion[\W_]+legal|investigacion)(?!\w)"
)


def normalize_severe_signal_text(value: str | None) -> str:
    """Normalize only for in-memory severe-signal matching.

    The returned value must not be persisted as evidence. NFKC/NFKD handle
    full-width characters and accents; zero-width format characters are
    removed, while ordinary word boundaries remain intact so unrelated words
    are never joined into a match.
    """
    text = html.unescape(unquote(str(value or "")))
    text = unicodedata.normalize("NFKC", text).casefold()
    text = "".join(char for char in text if unicodedata.category(char) != "Cf")
    decomposed = unicodedata.normalize("NFKD", text)
    text = "".join(char for char in decomposed if not unicodedata.combining(char))
    return re.sub(r"\s+", " ", text).strip()


def _signal_windows(text: str, pattern: re.Pattern[str], radius: int = 220) -> list[str]:
    return [text[max(0, match.start() - radius):match.end() + radius]
            for match in pattern.finditer(text)]


def _corroborated_severe_window(text: str) -> bool:
    """Require independent minor + sexual + exchange families in one window."""
    for window in _signal_windows(text, _SEVERE_MINOR_PATTERN):
        if _SEVERE_SEXUAL_PATTERN.search(window) and _SEVERE_EXCHANGE_PATTERN.search(window):
            if not (_SEVERE_PROTECTIVE_PATTERN.search(window)
                    and not _SEVERE_EXCHANGE_PATTERN.search(window)):
                return True
    for match in _SEVERE_CONTEXT_TERM_PATTERN.finditer(text):
        window = text[max(0, match.start() - 220):match.end() + 220]
        term = re.sub(r"[\W_]+", "", match.group(0)).casefold()
        sexual = bool(_SEVERE_SEXUAL_PATTERN.search(window))
        exchange = bool(_SEVERE_EXCHANGE_PATTERN.search(window))
        explicit_sexual_term = term in {
            "childporn", "childpornography", "underageporn", "preteenporn", "minorporn",
        }
        corroborated = (exchange if explicit_sexual_term else sexual and exchange)
        if corroborated and not _SEVERE_PROTECTIVE_PATTERN.search(window):
            return True
    return False


def assess_severe_abuse_signals(url_text: str | None = None,
                                title_text: str | None = None,
                                body_text: str | None = None,
                                context_text: str | None = None,
                                *, classification_scope: str = "page") -> dict[str, Any]:
    """Return safe, bounded severe-content evidence without raw match values.

    ``classification_scope='page'`` intentionally excludes anchor/source
    context so a restricted outbound child cannot poison its parent page.
    Use ``'child'`` when classifying a discovered child URL, or ``'combined'``
    only when the caller is explicitly classifying that same target.
    """
    scope = str(classification_scope or "page").casefold()
    # URL/path and link-list context may carry hints, but they can never be
    # proof of the destination's content.  Only the destination's own returned
    # title/body fields are eligible to produce a terminal severe decision.
    fields: list[tuple[str, str]] = []
    if scope in {"child", "combined"}:
        fields.extend((
            ("url", normalize_severe_signal_text(url_text)),
            ("context", normalize_severe_signal_text(context_text)),
        ))
    if scope != "child":
        fields.extend((
            ("title", normalize_severe_signal_text(title_text)),
            ("body", normalize_severe_signal_text(body_text)),
        ))

    explicit_scopes: list[str] = []
    corroborated_explicit_scopes: list[str] = []
    corroborated_scopes: list[str] = []
    protected_scopes: list[str] = []
    euphemism_scopes: list[str] = []
    for field_scope, text in fields:
        if not text:
            continue
        explicit_windows: list[str] = []
        for pattern in _SEVERE_EXPLICIT_PATTERNS:
            explicit_windows.extend(_signal_windows(text, pattern))
        if explicit_windows:
            unprotected = any(
                not _SEVERE_PROTECTIVE_PATTERN.search(window)
                or bool(_SEVERE_EXCHANGE_PATTERN.search(window))
                for window in explicit_windows
            )
            (explicit_scopes if unprotected else protected_scopes).append(field_scope)
            if (field_scope in {"title", "body"} and unprotected
                    and any(_SEVERE_EXCHANGE_PATTERN.search(window) for window in explicit_windows)):
                corroborated_explicit_scopes.append(field_scope)
        if _corroborated_severe_window(text):
            corroborated_scopes.append(field_scope)
        if _SEVERE_EUPHEMISM_PATTERN.search(text):
            euphemism_scopes.append(field_scope)

    eligible_scopes = {"title", "body"}
    page_explicit_scopes = [value for value in explicit_scopes if value in eligible_scopes]
    # One explicit acronym/phrase is still only one signal.  It becomes a
    # terminal result only with action/exchange context in the same returned
    # field, in two independent returned fields, or via the existing
    # minor+sexual+exchange corroboration rule.
    repeated_explicit = page_explicit_scopes if len(set(page_explicit_scopes)) >= 2 else []
    blocked_scopes = list(dict.fromkeys(
        corroborated_explicit_scopes + repeated_explicit
        + [value for value in corroborated_scopes if value in eligible_scopes]
    ))
    labels: list[str] = []
    if explicit_scopes:
        labels.append("severe_explicit_signal")
    if corroborated_scopes:
        labels.append("severe_corroborated_context")
    if euphemism_scopes:
        labels.append("severe_ambiguous_signal_present")
    if protected_scopes:
        labels.append("protective_context_guard")
    return {
        "block": bool(blocked_scopes),
        "blackhole": bool(blocked_scopes),
        "scope": blocked_scopes[0] if blocked_scopes else (
            protected_scopes[0] if protected_scopes else "none"),
        "safe_signal_labels": labels,
        "signal_count": len(set(page_explicit_scopes)) + (3 * len(set(
            value for value in corroborated_scopes if value in eligible_scopes))),
        "independent_signal_families": (
            ["explicit_restricted_term"] if page_explicit_scopes else []
        ) + (["minor_context", "sexual_context", "exchange_context"]
             if any(value in eligible_scopes for value in corroborated_scopes) else []),
        "protected_context": bool(protected_scopes and not blocked_scopes),
        "unverified_hint": bool(
            any(value in {"url", "context"} for value in explicit_scopes + corroborated_scopes + euphemism_scopes)
        ),
        "raw_evidence_retention_allowed": False,
    }


def severe_blackhole_policy(base: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Apply the canonical fail-closed contract for confirmed severe content."""
    result = dict(base or {})
    result.update(
        primary_category=SEVERE_BLACKHOLE_CATEGORY,
        category=SEVERE_BLACKHOLE_CATEGORY,
        content_category=SEVERE_BLACKHOLE_CATEGORY,
        tags=[SEVERE_BLACKHOLE_CATEGORY],
        risk_level="critical",
        confidence="high",
        risk_flags=["restricted_content", SEVERE_BLACKHOLE_CATEGORY],
        storage_policy="metadata_only",
        review_status="restricted",
        safety_reason=SEVERE_BLACKHOLE_REASON,
        screenshot_policy="blocked",
        screenshot_blocked_reason=SEVERE_BLACKHOLE_REASON,
        queue_policy="blocked",
        active=0,
        priority_score=0,
        spain_priority=False,
        ui_hidden_default=1,
        blackhole_policy=SEVERE_BLACKHOLE_MARKER,
        fetch_allowed=False,
        preview_allowed=False,
        ocr_allowed=False,
        screenshot_allowed=False,
        expansion_allowed=False,
        card_allowed=False,
        actor_extraction_allowed=False,
        alert_allowed=False,
        report_allowed=False,
        enrichment_allowed=False,
        raw_content_allowed=False,
        report_required=False,
        urgent_flag=False,
    )
    return result


def _policy_value(policy: Any, key: str) -> Any:
    if policy is None:
        return None
    try:
        return policy.get(key)
    except AttributeError:
        try:
            return policy[key]
        except (KeyError, IndexError, TypeError):
            return None


def is_severe_blackhole_policy(policy: Any) -> bool:
    """Recognize both the canonical marker and legacy severe-category rows."""
    if isinstance(policy, str):
        return policy.casefold() == SEVERE_BLACKHOLE_CATEGORY
    category = str(_policy_value(policy, "primary_category")
                   or _policy_value(policy, "category") or "").casefold()
    marker = str(_policy_value(policy, "blackhole_policy") or "").casefold()
    reason = str(_policy_value(policy, "safety_reason") or "").casefold()
    return bool(
        category == SEVERE_BLACKHOLE_CATEGORY
        or marker == SEVERE_BLACKHOLE_MARKER
        or reason in {SEVERE_BLACKHOLE_REASON, "severe_abuse_risk", "severe_content_filtered"}
    )


def is_onion_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        label = host[:-6].split(".")[-1] if host.endswith(".onion") else ""
        return parsed.scheme.lower() in {"http", "https"} and bool(
            re.fullmatch(r"[a-z2-7]{56}", label)
        )
    except ValueError:
        return False


def normalize_url(url: str, base_url: str | None = None) -> str | None:
    if not isinstance(url, str) or not url.strip():
        return None
    try:
        joined = urljoin(base_url, url.strip()) if base_url else url.strip()
        parsed = urlsplit(joined)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None
        host = parsed.hostname.lower()
        port = f":{parsed.port}" if parsed.port else ""
        normalized = urlunsplit((parsed.scheme.lower(), host + port, parsed.path or "/", parsed.query, ""))
        return None if is_blocked_extension(normalized) else normalized
    except (ValueError, UnicodeError):
        return None


def is_blocked_extension(url: str) -> bool:
    try:
        return any(urlsplit(url).path.lower().endswith(ext) for ext in BLOCKED_EXTENSIONS)
    except ValueError:
        return True


def is_fetch_allowed(url: str, allow_clearnet: bool = False) -> tuple[bool, str]:
    if not isinstance(url, str) or is_blocked_extension(url):
        return False, "blocked_extension"
    normalized = normalize_url(url)
    if not normalized:
        return False, "invalid_url"
    if not is_onion_url(normalized) and not allow_clearnet:
        return False, "clearnet_disabled"
    return True, "allowed"


def is_content_type_allowed(content_type: str | None) -> bool:
    if not content_type:
        return False
    return content_type.split(";", 1)[0].strip().lower() in ALLOWED_CONTENT_TYPES


def truncate_snippet(text: str, max_chars: int = 500) -> str:
    clean = re.sub(r"\s+", " ", text or "").strip()
    return clean if len(clean) <= max_chars else clean[: max(0, max_chars - 1)].rstrip() + "…"


def redact_sensitive(text: str) -> str:
    value = _CREDENTIAL_LINE.sub("[REDACTED_CREDENTIAL_LINE]", text or "")
    value = _PASSWORD.sub(lambda m: f"{m.group(1)}=[REDACTED_PASSWORD]", value)
    value = _API_KEY.sub(lambda m: f"{m.group(1)}=[REDACTED_API_KEY]", value)
    value = _COOKIE.sub(lambda m: f"{m.group(1)}=[REDACTED_COOKIE]", value)
    value = _TOKEN.sub(lambda m: f"{m.group(1)}=[REDACTED_TOKEN]", value)
    return value


def make_safe_snippet(text: str, matched_terms: list[str] | None = None, max_chars: int = 500) -> str:
    return truncate_snippet(redact_sensitive(text), max_chars)


def classify_risk_flags(text: str, links: list[str]) -> list[str]:
    flags = []
    lowered = (text or "").lower()
    if _CREDENTIAL_LINE.search(text or "") or lowered.count("password") >= 3:
        flags.append("possible_credentials")
    blocked = sum(1 for link in links or [] if is_blocked_extension(link))
    if blocked:
        flags.append("blocked_file_links")
    if blocked >= 5 or any(word in lowered for word in ("download archive", "bulk download", "full dump")):
        flags.append("download_heavy_page")
    return flags
