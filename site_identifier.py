"""Deterministic, explainable site identity resolution.

This module does not fetch content and never infers an identity from category,
risk, or language alone.  Explicit domains always outrank descriptive hints.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import logging
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit


LOGGER = logging.getLogger(__name__)
REGISTRY_PATH = Path(__file__).with_name("site_registry.json")
_DOMAIN_RE = re.compile(
    r"(?<![@\w-])(?:https?://)?(?:www\.)?"
    r"(?P<domain>(?:[a-z0-9](?:[a-z0-9-]{0,62})\.)+(?:onion|[a-z]{2,24}))"
    r"(?::\d{1,5})?(?:[/\?#][^\s<>\"']*)?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SiteIdentity:
    site_id: str | None
    display_name: str | None
    domain: str | None
    canonical_domain: str | None
    brand: str | None
    country: str | None
    language: str | None
    source_type: str | None
    matched_from: str
    confidence: float
    evidence: list[dict[str, Any]] = field(default_factory=list)
    is_ambiguous: bool = False
    ambiguity_reason: str | None = None
    missing_fields: list[str] = field(default_factory=list)
    candidates: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_domain(value: object) -> str | None:
    """Return a safe lower-case hostname, never an email fragment."""
    text = str(value or "").strip()
    if not text or "@" in text.split("/")[0]:
        return None
    candidate = text if "://" in text else f"//{text}"
    try:
        host = (urlsplit(candidate).hostname or "").casefold().rstrip(".")
    except ValueError:
        return None
    if host.startswith("www."):
        host = host[4:]
    if not host or len(host) > 253 or ".." in host:
        return None
    labels = host.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 or
                              not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                              for label in labels):
        return None
    if host.endswith(".onion") and (len(labels) != 2 or len(labels[0]) != 56):
        return None
    return host


def extract_domains(value: object) -> list[str]:
    text = str(value or "")
    found: list[str] = []
    direct = normalize_domain(text)
    if direct:
        found.append(direct)
    for match in _DOMAIN_RE.finditer(text):
        domain = normalize_domain(match.group("domain"))
        if domain and domain not in found:
            found.append(domain)
    return found


def _load_registry(path: Path | None = None) -> list[dict[str, Any]]:
    target = path or REGISTRY_PATH
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return []
    entries = raw.get("sites", []) if isinstance(raw, dict) else raw
    return [entry for entry in entries if isinstance(entry, dict) and entry.get("active", True)]


def _entry_domains(entry: dict[str, Any]) -> list[str]:
    values = [entry.get("canonical_domain"), *(entry.get("domains") or [])]
    return list(dict.fromkeys(domain for value in values if (domain := normalize_domain(value))))


def _domain_match(domain: str, known: str) -> bool:
    return domain == known or (not known.endswith(".onion") and domain.endswith("." + known))


def _missing(entry: dict[str, Any], domain: str | None) -> list[str]:
    values = {**entry, "domain": domain}
    return [name for name in ("site_id", "display_name", "domain", "canonical_domain",
                              "brand", "country", "language") if not values.get(name)]


def identify_site(item: Any, context: dict[str, Any] | None = None,
                  *, registry_path: str | Path | None = None) -> SiteIdentity:
    """Resolve one item using explicit domain, registry alias, then source mapping."""
    data = item if isinstance(item, dict) else vars(item) if item is not None else {}
    context = context or {}
    registry = _load_registry(Path(registry_path) if registry_path else None)
    explicit_values = [data.get(key) for key in ("url", "domain", "canonical_url", "onion_url")]
    explicit_domains = list(dict.fromkeys(domain for value in explicit_values
                                           for domain in extract_domains(value)))
    text_values = [data.get(key) for key in ("text", "safe_text", "description")]
    text_domains = list(dict.fromkeys(domain for value in text_values for domain in extract_domains(value)))
    detected_domains = explicit_domains + [d for d in text_domains if d not in explicit_domains]

    matches: list[tuple[dict[str, Any], str, str, float]] = []
    for domain in detected_domains:
        for entry in registry:
            canonical = normalize_domain(entry.get("canonical_domain"))
            for known in _entry_domains(entry):
                if _domain_match(domain, known):
                    exact_canonical = bool(canonical and domain == canonical)
                    confidence = 1.0 if exact_canonical else 0.95
                    matches.append((entry, domain, "exact_canonical_domain" if exact_canonical else "exact_known_domain", confidence))
                    break

    unique_site_ids = list(dict.fromkeys(str(match[0].get("site_id")) for match in matches))
    if matches:
        matches.sort(key=lambda match: (match[3], match[1] in explicit_domains), reverse=True)
        entry, domain, matched_from, confidence = matches[0]
        ambiguous = len(unique_site_ids) > 1
        reason = ("Multiple registered sites were found: " + ", ".join(unique_site_ids)) if ambiguous else None
        evidence = [{"type": source, "value": found_domain, "site_id": match_entry.get("site_id")}
                    for match_entry, found_domain, source, _score in matches]
        result = SiteIdentity(
            site_id=entry.get("site_id"), display_name=entry.get("display_name"), domain=domain,
            canonical_domain=normalize_domain(entry.get("canonical_domain")) or domain,
            brand=entry.get("brand"), country=entry.get("country"), language=entry.get("language"),
            source_type=data.get("source_type") or context.get("source_type"), matched_from=matched_from,
            confidence=confidence, evidence=evidence, is_ambiguous=ambiguous,
            ambiguity_reason=reason, missing_fields=_missing(entry, domain), candidates=unique_site_ids,
        )
        LOGGER.debug(
            "site_identity candidate_count=%d selected_present=%s confidence=%.2f "
            "ambiguous=%s missing_count=%d",
            len(unique_site_ids), bool(result.site_id), result.confidence,
            ambiguous, len(result.missing_fields),
        )
        return result

    searchable = " ".join(str(value or "") for value in
                          (data.get("title"), data.get("detected_title"), data.get("display_name"),
                           data.get("text"), data.get("safe_text")))
    alias_matches: list[dict[str, Any]] = []
    folded = searchable.casefold()
    for entry in registry:
        aliases = [entry.get("display_name"), *(entry.get("aliases") or [])]
        if any(alias and re.search(rf"(?<!\w){re.escape(str(alias).casefold())}(?!\w)", folded)
               for alias in aliases):
            alias_matches.append(entry)
    if alias_matches:
        unique = list(dict.fromkeys(str(entry.get("site_id")) for entry in alias_matches))
        entry = alias_matches[0]
        ambiguous = len(unique) > 1
        domain = normalize_domain(entry.get("canonical_domain"))
        return SiteIdentity(entry.get("site_id"), entry.get("display_name"), domain, domain,
                            entry.get("brand"), entry.get("country"), entry.get("language"),
                            data.get("source_type") or context.get("source_type"), "exact_alias", 0.85,
                            [{"type": "exact_alias", "site_id": site_id} for site_id in unique], ambiguous,
                            "Alias matches multiple registered sites" if ambiguous else None,
                            _missing(entry, domain), unique)

    source_id = context.get("site_id") or context.get("source_site_id")
    source_entry = next((entry for entry in registry if source_id and entry.get("site_id") == source_id), None)
    if source_entry:
        domain = normalize_domain(source_entry.get("canonical_domain"))
        return SiteIdentity(source_entry.get("site_id"), source_entry.get("display_name"), domain, domain,
                            source_entry.get("brand"), source_entry.get("country"), source_entry.get("language"),
                            data.get("source_type") or context.get("source_type"), "source_mapping", 0.75,
                            [{"type": "source_mapping", "site_id": source_id}], False, None,
                            _missing(source_entry, domain), [str(source_id)])

    if explicit_domains:
        domain = explicit_domains[0]
        title = data.get("detected_title") or data.get("display_name") or data.get("title")
        clean_title = " ".join(str(title or "").split())[:180] or domain
        site_id = "domain:" + hashlib.sha256(domain.encode("ascii")).hexdigest()[:20]
        ambiguous = len(explicit_domains) > 1
        return SiteIdentity(site_id, clean_title, domain, domain, None, None,
                            data.get("language") or None,
                            data.get("source_type") or context.get("source_type"),
                            "explicit_unregistered_domain", 0.60,
                            [{"type": "explicit_unregistered_domain", "value": value}
                             for value in explicit_domains], ambiguous,
                            "Multiple explicit unregistered domains were found" if ambiguous else None,
                            ["brand", "country"] + ([] if data.get("language") else ["language"]),
                            [site_id])

    return SiteIdentity(None, None, None, None, None, None, None,
                        data.get("source_type") or context.get("source_type"), "unknown", 0.0, [], False,
                        None, ["site_id", "display_name", "domain", "canonical_domain", "brand",
                               "country", "language"], [])
