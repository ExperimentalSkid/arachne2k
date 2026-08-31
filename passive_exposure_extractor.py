"""Find disclosures already visible in a normal allowed response; never fetches."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from safety_policy import make_safe_snippet, redact_sensitive


def extract_passive_exposures(url: str, status_code: int | None, headers: dict | None,
                              title: str | None, visible_text: str, links: list[str]) -> list[dict]:
    exposures, seen = [], set()

    def add(kind, severity, value, context, confidence):
        safe_value = make_safe_snippet(redact_sensitive(str(value or "")), max_chars=180)
        safe_context = make_safe_snippet(redact_sensitive(str(context or "")), max_chars=260)
        key = (kind, safe_value)
        if key not in seen:
            seen.add(key)
            exposures.append({"type": kind, "severity": severity, "value": safe_value,
                              "context": safe_context, "source": "normal_fetch_response",
                              "confidence": confidence})

    lower_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    if lower_headers.get("server"):
        add("server_header", "info", lower_headers["server"], "Server response header", 0.9)
        if re.search(r"/\d|\d+\.\d+", lower_headers["server"]):
            add("version_disclosure", "low", lower_headers["server"], "Server header version", 0.75)
    if lower_headers.get("x-powered-by"):
        add("powered_by_header", "info", lower_headers["x-powered-by"], "X-Powered-By response header", 0.9)
    text = visible_text or ""
    patterns = [
        ("stack_trace", "high", r"(?im)(traceback \(most recent call last\)|stack trace|exception in thread)", 0.9),
        ("absolute_path_disclosure", "medium", r"(?i)(?:[A-Z]:\\(?:[^\\\s]+\\){1,}|/(?:var|home|srv|opt|usr|root)/[^\s<]+)", 0.8),
        ("directory_listing_visible", "high", r"(?i)(index of /|directory listing for)", 0.9),
        ("debug_message_visible", "medium", r"(?i)(debug mode|debugging enabled|development server)", 0.8),
        ("default_error_page", "low", r"(?i)(whitelabel error page|apache tomcat/|nginx error)", 0.75),
        ("framework_disclosure", "low", r"(?i)(django|laravel|symfony|flask|express\.js|asp\.net)", 0.65),
    ]
    for kind, severity, pattern, confidence in patterns:
        match = re.search(pattern, text)
        if match:
            add(kind, severity, match.group(0), text[max(0, match.start()-80):match.end()+120], confidence)
    if status_code is not None and status_code >= 500:
        add("server_error", "medium", str(status_code), f"Normal response returned HTTP {status_code}", 0.9)
    onion_count = sum(1 for link in links or [] if (urlsplit(link).hostname or "").lower().endswith(".onion"))
    if onion_count >= 2:
        add("mirror_list_visible", "low", f"{onion_count} onion links", "Multiple visible onion links", 0.7)
    for link in links or []:
        host = (urlsplit(link).hostname or "").lower()
        if host.endswith(".onion"):
            add("onion_link_visible", "info", link, "Visible link in normal response", 0.9)
        elif urlsplit(link).scheme in {"http", "https"}:
            add("clearnet_link_visible", "medium", link, "Visible link in normal response", 0.85)
    if re.search(r"(?i)\b(?:contact|email|telegram)\b", text):
        add("contact_visible", "low", "contact reference", "Contact reference visible; do not contact", 0.6)
    for match in re.finditer(r"\b20\d{2}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?\b", text):
        add("timestamp_visible", "info", match.group(0), "Visible page timestamp", 0.7)
        break
    match = re.search(r"\b[\w.-]+\.(?:txt|csv|sql|json|xml|log)\b", text, re.I)
    if match:
        add("file_name_visible", "info", match.group(0), "Filename visible in normal response", 0.7)
    return exposures
