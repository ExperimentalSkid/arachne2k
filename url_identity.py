"""Authoritative, network-free onion URL identity normalization."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

TRACKING_QUERY_KEYS = {
    "fbclid", "gclid", "mc_cid", "mc_eid", "ref_src", "source_tracking",
    "ref", "cache", "cb", "timestamp", "sid", "session", "phpsessid",
}
LOW_VALUE_QUERY_KEYS = {"sort", "order", "filter"}
INDEX_PATHS = {"", "/", "/index.php", "/index.html", "/index.htm", "/home", "/home/"}


def canonicalize(url: str) -> dict:
    """Separate page identity, site root, path family, and safe query identity."""
    try:
        parsed = urlsplit(str(url or "").strip())
        host = (parsed.hostname or "").casefold()
        path = re.sub(r"/{2,}", "/", parsed.path or "/")
        if path != "/":
            path = path.rstrip("/") or "/"
        if path.casefold() in INDEX_PATHS:
            path = "/"
        pairs = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)
                 if not key.casefold().startswith("utm_") and key.casefold() not in TRACKING_QUERY_KEYS]
        query = urlencode(sorted(pairs), doseq=True)
        canonical_url = urlunsplit(("http", host, path, query, "")) if host else str(url or "").strip()
        canonical_root = urlunsplit(("http", host, "/", "", "")) if host else ""
        family_path = re.sub(r"/\d+(?=/|$)", "/:n", path.casefold())
        family_path = re.sub(r"/(?:page|p)/:n(?=/|$)", "/page/:n", family_path)
        meaningful = [(key, value) for key, value in pairs if key.casefold() not in LOW_VALUE_QUERY_KEYS]
        query_signature = hashlib.sha256(urlencode(sorted(meaningful), doseq=True).encode()).hexdigest()[:16]
        path_signature = hashlib.sha256(family_path.encode()).hexdigest()[:16]
        return {
            "canonical_url": canonical_url, "canonical_root": canonical_root,
            "onion_host": host, "normalized_path": path,
            "path_signature": path_signature, "query_signature": query_signature,
            "entity_identity": f"onion:{host}" if host else "",
        }
    except (TypeError, ValueError, UnicodeError):
        return {"canonical_url": str(url or "").strip(), "canonical_root": "", "onion_host": "",
                "normalized_path": "/", "path_signature": "", "query_signature": "",
                "entity_identity": ""}


def canonical_url(url: str) -> str:
    return canonicalize(url)["canonical_url"]
