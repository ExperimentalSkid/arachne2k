"""Extract public indicators while redacting credential-like content."""
from __future__ import annotations

import hashlib
import re
import unicodedata
from urllib.parse import parse_qs, unquote, urljoin, urlsplit

from safety_policy import make_safe_snippet, normalize_url, redact_sensitive

PATTERNS = {
    "telegram_handle": re.compile(r"(?<![\w@])@[A-Za-z][A-Za-z0-9_]{4,31}\b"),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    "wallet_btc": re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "wallet_eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "matrix_id": re.compile(r"(?<!\w)@[A-Za-z0-9._=-]+:[A-Za-z0-9.-]+\b"),
    "tox_id": re.compile(r"\b[A-Fa-f0-9]{76}\b"),
    "session_id": re.compile(r"\b05[a-fA-F0-9]{64}\b"),
    "jabber_id": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.(?:onion|im|chat)\b", re.I),
    "file_name": re.compile(r"\b[\w.-]+\.(?:txt|csv|sql|json|xml|log)\b", re.I),
    "username": re.compile(r"(?i)\buser(?:name)?\s*[:=]\s*([A-Za-z][A-Za-z0-9_.-]{2,31})\b"),
}
URL_RE = re.compile(r"https?://[^\s<>\]\[\"']+", re.I)
PGP_RE = re.compile(r"-----BEGIN PGP (?:PUBLIC KEY BLOCK|MESSAGE)-----.*?-----END PGP (?:PUBLIC KEY BLOCK|MESSAGE)-----", re.I | re.S)
PGP_FINGERPRINT_RE = re.compile(
    r"(?ix)\b(?:openpgp|pgp)\s*(?:public\s+key\s*)?"
    r"(?:fingerprint|fpr)\s*[:=#-]?\s*"
    r"((?:[a-f0-9]{4}[\s:-]*){10}|(?:[a-f0-9]{4}[\s:-]*){16})\b"
)
ALIAS_LABEL_RE = re.compile(
    r"(?iu)\b(?:user(?:name)?|author|seller|vendor|member)\s*(?:name)?\s*[:=\-]\s*@?([\w][\w.\-]{2,31})\b"
)
ALIAS_BYLINE_RE = re.compile(
    r"(?iu)\b(?:posted|written|shared|listed|sold)\s+by\s+@?([\w][\w.\-]{2,31})\b"
)
ALIAS_STOPWORDS = {
    "about", "account", "accounts", "admin", "administrator", "agent", "anonymous",
    "author", "avatar", "blog", "board", "buyer", "category", "centric", "contact",
    "created", "customer", "deleted", "directory", "focused", "forum", "friendly",
    "generated", "guest", "help", "home", "index", "login", "market", "marketplace",
    "member", "mirror", "mirrors", "none", "null", "official", "oriented", "page",
    "posted", "privacy", "product", "profile", "register", "rules", "seller",
    "service", "services", "shop", "staff", "store", "sudo", "supported", "terms",
    "unknown", "user", "username", "vendor", "you",
    # Category/navigation labels frequently appear beside seller/profile
    # markup but are not identities.
    "adult", "carding", "credential", "credentials", "drug", "drugs",
    "fraud", "hacking", "leak", "leaks", "malware", "porn", "weapon",
    "weapons", "listing", "listings", "products",
}
ALIAS_PROVIDER_WORDS = {
    "gmail", "googlemail", "hotmail", "icloud", "mail2tor", "outlook", "proton",
    "protonmail", "tutanota", "yahoo", "yandex",
}
GENERIC_ROLE_ALIASES = {
    "admin", "administrator", "buyer", "guest", "member", "moderator",
    "seller", "support", "staff", "root", "user", "vendor",
}
IDENTITY_INDICATOR_TYPES = {
    "telegram_handle", "email", "wallet_btc", "wallet_eth", "matrix_id", "tox_id",
    "session_id", "jabber_id", "pgp_key_block", "pgp_fingerprint", "clearnet_url",
    "username",
}
PROFILE_ROUTE_MARKERS = (
    "/user/", "/users/", "/u/", "/id/", "/uid/", "/user_id/",
    "/member/", "/members/", "/profile/", "/profiles/",
    "/vendor/", "/vendors/", "/seller/", "/sellers/", "/merchant/", "/merchants/",
)
BLOCKING_CONTEXT_TOKENS = {
    "nav", "navigation", "navbar", "menu", "breadcrumb", "breadcrumbs", "pagination",
    "footer", "header", "toolbar", "actions", "filters", "search", "docs",
    "documentation", "glossary", "toc", "category", "categories", "product-actions",
    "cart", "checkout", "login", "register",
}
IDENTITY_CONTEXT_TOKENS = {
    "author", "byline", "user", "username", "member", "poster", "post-author",
    "post-user", "user-info", "user-card", "profile-card", "vendor", "seller",
    "merchant", "store-owner", "nickname", "handle",
}
POST_CONTAINER_TOKENS = {
    "post", "message", "comment", "reply", "thread-post", "forum-post", "article",
}
SELLER_EVIDENCE_TYPES = {
    "linked_vendor_field", "linked_seller_field", "marketplace_vendor_card",
    "marketplace_seller_card", "vendor_page_identity_match", "seller_page_identity_match",
    "vendor_profile_identity", "seller_profile_identity",
}


def normalize_indicator_value(indicator_type: str, value: str) -> str:
    value = value.strip()
    if indicator_type in {"email", "telegram_handle", "matrix_id", "jabber_id", "onion_domain", "onion_url", "clearnet_url"}:
        return value.lower()
    if indicator_type == "pgp_fingerprint":
        return re.sub(r"[^A-Fa-f0-9]", "", value).upper()
    return value


def normalize_public_alias(value: str) -> str:
    """Return the canonical alias while preserving meaningful Unicode.

    Canonical identity and visual-confusable comparison are deliberately separate:
    this value is safe for exact identity lookup, while ``public_alias_skeleton`` is
    only a review aid and must never be used to merge actors automatically.
    """
    value = unicodedata.normalize("NFKC", value or "").strip().lstrip("@").casefold()
    kept = []
    for char in value:
        category = unicodedata.category(char)
        if char in "_.-" or category[:1] in {"L", "N", "M"}:
            kept.append(char)
    return "".join(kept)[:32]


_CONFUSABLE_ASCII = str.maketrans({
    # A deliberately small review-only set of common Greek/Cyrillic homoglyphs.
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
    "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "χ": "x", "υ": "y", "ι": "i", "κ": "k", "μ": "m", "τ": "t",
})


def public_alias_skeleton(value: str) -> str:
    """Return a review-only confusable skeleton without changing identity.

    Diacritics and a conservative set of common homoglyphs are folded so an
    analyst can spot likely lookalikes. Callers must not use this as a unique key.
    """
    canonical = normalize_public_alias(value).translate(_CONFUSABLE_ASCII)
    decomposed = unicodedata.normalize("NFKD", canonical)
    return "".join(char for char in decomposed if unicodedata.category(char) != "Mn")[:32]


def _compact_token_text(value: str | None) -> str:
    return re.sub(r"[^a-z0-9_-]+", " ", str(value or "").casefold())


def _element_tokens(tag) -> set[str]:
    if not tag:
        return set()
    values = [tag.name or "", str(tag.get("id") or "")]
    classes = tag.get("class") or []
    if isinstance(classes, str):
        classes = classes.split()
    values.extend(str(item) for item in classes)
    for attr in ("role", "itemprop", "component", "data-component", "data-role"):
        values.append(str(tag.get(attr) or ""))
    return {token for value in values for token in _compact_token_text(value).split() if token}


def _has_any_token(tag, tokens: set[str]) -> bool:
    return bool(_element_tokens(tag).intersection(tokens))


def _blocked_actor_context(tag, *, max_depth: int = 5) -> bool:
    current = tag
    for _ in range(max_depth):
        if current is None:
            return False
        if current.name in {"nav", "header", "footer", "aside"}:
            return True
        if _has_any_token(current, BLOCKING_CONTEXT_TOKENS):
            return True
        current = current.parent
    return False


def parse_profile_identity(url: str) -> dict:
    """Parse a stable public profile identity from a route.

    Named slugs may corroborate a flat anchor. Numeric IDs are intentionally
    returned as structure only; they are acceptable inside a bounded author or
    vendor container but never stand in for an alias by themselves.
    """
    parsed = urlsplit(url or "")
    path = unquote(parsed.path or "")
    lowered = path.casefold()
    for marker in PROFILE_ROUTE_MARKERS:
        if marker in lowered:
            after = path[lowered.index(marker) + len(marker):].strip("/")
            if after:
                value = after.split("/", 1)[0].split(".", 1)[0].strip()
                if value:
                    kind = "numeric" if value.isdecimal() else "named"
                    return {"value": value[:80], "kind": kind, "source": "path",
                            "key": marker.strip("/")[:24]}
    query = parse_qs((parsed.query or "").replace(";", "&"), keep_blank_values=False)
    for key in ("user", "username", "name", "author", "u", "uid", "user_id", "id"):
        if query.get(key):
            value = unquote(str(query[key][0] or "")).strip()
            if value:
                kind = "numeric" if value.isdecimal() else "named"
                return {"value": value[:80], "kind": kind, "source": "query", "key": key}
    return {"value": "", "kind": "missing", "source": "", "key": ""}


def _profile_identity_from_url(url: str) -> str:
    return str(parse_profile_identity(url).get("value") or "")


def canonical_profile_identity(url: str) -> str:
    """Return a deterministic host-local profile identity, or an empty string."""
    identity = parse_profile_identity(url)
    value = str(identity.get("value") or "")
    if not value:
        return ""
    if identity.get("kind") == "named":
        value = normalize_public_alias(value)
    else:
        value = value.casefold()
    if not value:
        return ""
    return f"{identity.get('source') or 'route'}:{identity.get('key') or 'profile'}:{value}"[:160]


def _is_profile_route(url: str) -> bool:
    parsed = urlsplit(url or "")
    path_query = f"{parsed.path}?{parsed.query}".casefold()
    explicit_route = any(marker in path_query for marker in PROFILE_ROUTE_MARKERS) or any(
        marker in path_query for marker in (
            "memberlist.php?mode=viewprofile", "member.php?action=profile",
            "profile.php?id=", "action=profile;u=", "action=profile&u=",
        )
    )
    if explicit_route:
        return True
    route_path = (parsed.path or "").casefold()
    query = parse_qs((parsed.query or "").replace(";", "&"), keep_blank_values=False)
    return bool(
        any(token in route_path for token in ("member", "profile", "user", "vendor", "seller", "merchant"))
        and set(query).intersection({"user", "username", "name", "author", "u", "uid", "user_id", "id"})
    )


def _alias_agrees_with_target(alias: str, url: str, *, allow_numeric_identity: bool = False,
                              allow_missing_identity: bool = False) -> bool:
    identity = parse_profile_identity(url)
    slug = str(identity.get("value") or "")
    if identity.get("kind") == "numeric":
        return bool(allow_numeric_identity)
    if not slug:
        return bool(allow_missing_identity)
    normalized_alias = normalize_public_alias(alias)
    normalized_slug = normalize_public_alias(slug)
    return bool(normalized_alias and normalized_slug and normalized_alias == normalized_slug)


def _valid_actor_alias(value: str, *, allow_digit_leading: bool = False) -> bool:
    raw = (value or "").strip().lstrip("@")
    normalized = normalize_public_alias(raw)
    if not normalized or len(normalized) < 3 or len(normalized) > 32:
        return False
    if normalized in ALIAS_STOPWORDS or normalized in ALIAS_PROVIDER_WORDS:
        return False
    if normalized.isdigit():
        return False
    if re.search(r"\s", raw):
        return False
    if "." in normalized and normalized.rsplit(".", 1)[-1] in {"php", "html", "htm", "onion", "jpg", "png"}:
        return False
    if any(char not in "_.-" and unicodedata.category(char)[:1] not in {"L", "N", "M"}
           for char in raw):
        return False
    first = normalized[0]
    first_kind = unicodedata.category(first)[:1]
    if first_kind == "N" and not allow_digit_leading:
        return False
    if first_kind not in {"L", "N"}:
        return False
    return any(unicodedata.category(char).startswith("L") for char in normalized)


def _bounded_text(tag, limit: int = 240) -> str:
    return re.sub(r"\s+", " ", tag.get_text(" ", strip=True) if tag else "").strip()[:limit]


def _bound_identifier_hashes(container, *, base_url: str) -> list[dict]:
    """Hash identifiers proven local to one structural actor container.

    No raw contact value, key material, wallet, or surrounding text leaves this
    function. The stable first hash retains safe cross-page correlation.
    """
    if not container:
        return []
    local_text = re.sub(r"\s+", " ", container.get_text(" ", strip=True)).strip()[:20000]
    local_links = []
    for anchor in container.find_all("a", href=True, limit=40):
        href = str(anchor.get("href") or "").strip()
        if href:
            local_links.append(urljoin(base_url, href))
    result: dict[tuple[str, str], dict] = {}
    for item in actor_identity_evidence(extract_indicators(local_text, local_links)):
        indicator_type = str(item.get("type") or "")
        normalized_value = str(item.get("normalized_value") or item.get("value") or "")
        if indicator_type not in IDENTITY_INDICATOR_TYPES or not normalized_value:
            continue
        digest = hashlib.sha256(
            f"{indicator_type}:{normalized_value}".encode("utf-8", "ignore")
        ).hexdigest()
        result[(indicator_type, digest)] = {
            "type": indicator_type,
            "value_hash": digest,
            "confidence": round(float(item.get("confidence") or 0.7), 3),
            "binding": "same_structural_container",
        }
    return sorted(result.values(), key=lambda item: (item["type"], item["value_hash"]))[:20]


def _make_actor_evidence(alias: str, *, role: str, evidence_type: str, confidence: float,
                         strength: str, signals: list[str], profile_url: str | None = None,
                         engine_hint: str | None = None, source_scope: str = "actor",
                         seller_evidence: bool = False,
                         bound_identifiers: list[dict] | None = None) -> dict | None:
    if not _valid_actor_alias(alias, allow_digit_leading=True):
        return None
    return {
        "accepted": True,
        "alias": alias.strip().lstrip("@")[:32],
        "normalized_alias": normalize_public_alias(alias),
        "role": role[:40],
        "evidence_type": evidence_type[:80],
        "confidence": round(float(confidence), 3),
        "evidence_strength": strength[:20],
        "evidence_signals": list(dict.fromkeys(str(item)[:40] for item in signals if item))[:8],
        "profile_url": (profile_url or "")[:500],
        "profile_identity": canonical_profile_identity(profile_url or ""),
        "engine_hint": (engine_hint or "generic")[:40],
        "source_scope": source_scope[:40],
        "seller_evidence": bool(seller_evidence),
        "generic_role": is_generic_public_alias(alias),
        "safe_context_label": f"{role.replace('_', ' ').title()} · {evidence_type.replace('_', ' ')}",
        "alias_skeleton": public_alias_skeleton(alias),
        "bound_identifiers": list(bound_identifiers or [])[:20],
        "evidence_version": 2,
    }


def _add_evidence(result: dict[str, dict], item: dict | None) -> None:
    if not item:
        return
    key = (item["normalized_alias"], item["evidence_type"], item.get("profile_url") or "")
    previous = result.get(str(key))
    if not previous or float(previous.get("confidence") or 0) < float(item.get("confidence") or 0):
        result[str(key)] = item


def _find_profile_anchor(container, base_url: str):
    for anchor in container.find_all("a", href=True, limit=20):
        if _blocked_actor_context(anchor):
            continue
        absolute = urljoin(base_url, str(anchor.get("href") or ""))
        text = re.sub(r"\s+", " ", anchor.get_text(" ", strip=True)).strip().lstrip("@")
        if (text and _is_profile_route(absolute)
                and _valid_actor_alias(text, allow_digit_leading=True)
                and _alias_agrees_with_target(
                    text, absolute, allow_numeric_identity=True, allow_missing_identity=True)):
            return anchor, absolute, text
    return None, "", ""


def extract_actor_evidence(soup, *, base_url: str, page_identity: dict | None = None,
                           engine_hint: str | None = None) -> list[dict]:
    """Return accepted structural public-actor evidence from the live DOM.

    This intentionally validates candidates before storage. It does not persist rejected
    words, raw HTML, surrounding cards, or broad flattened-text guesses.
    """
    accepted: dict[str, dict] = {}

    # phpBB-style author blocks.
    for profile in soup.select("dl.postprofile")[:80]:
        anchor, profile_url, alias = _find_profile_anchor(profile, base_url)
        if anchor and ("memberlist.php" in profile_url.casefold() or "viewprofile" in profile_url.casefold()):
            _add_evidence(accepted, _make_actor_evidence(
                alias, role="forum_member", evidence_type="phpbb_post_author",
                confidence=0.97, strength="strong",
                signals=["phpbb_postprofile", "profile_link", "anchor_slug_match"],
                profile_url=profile_url, engine_hint="phpbb", source_scope="post_author",
                bound_identifiers=_bound_identifier_hashes(profile, base_url=base_url)))

    # Other known forum engines and generic custom forums.
    engine_selectors = [
        ("mybb", ".post__author, .post_author, .author_information", "mybb_post_author"),
        ("smf", ".poster, .user_info", "smf_post_author"),
        ("discourse", ".names.trigger-user-card, .topic-meta-data, .creator", "discourse_post_author"),
        ("xenforo", ".message-user, .message-name, .userText", "xenforo_post_author"),
        ("vbulletin", ".postbit, .post-user-info, .postbit_name", "vbulletin_post_author"),
        ("invision", ".ipsComment_meta, .ipsUserPhoto, .cAuthorPane", "invision_post_author"),
        ("nodebb", "[component='post/username'], [data-username]", "nodebb_post_author"),
        ("punbb", ".postleft, .post-user, .post-author", "punbb_post_author"),
    ]
    for engine, selector, evidence_type in engine_selectors:
        for container in soup.select(selector)[:80]:
            if _blocked_actor_context(container):
                continue
            alias = str(container.get("data-username") or "").strip()
            profile_url = ""
            if not alias:
                _anchor, profile_url, alias = _find_profile_anchor(container, base_url)
            if alias:
                _add_evidence(accepted, _make_actor_evidence(
                    alias, role="forum_member", evidence_type=evidence_type,
                    confidence=0.94, strength="strong",
                    signals=[f"{engine}_author_block", "profile_link" if profile_url else "data_username"],
                    profile_url=profile_url, engine_hint=engine, source_scope="post_author",
                    bound_identifiers=_bound_identifier_hashes(container, base_url=base_url)))

    # Generic bounded author/profile containers.
    for container in soup.find_all(True, limit=3000):
        tokens = _element_tokens(container)
        if not tokens.intersection(IDENTITY_CONTEXT_TOKENS):
            continue
        if _blocked_actor_context(container):
            continue
        if not (tokens.intersection(POST_CONTAINER_TOKENS) or tokens.intersection(IDENTITY_CONTEXT_TOKENS)):
            continue
        anchor, profile_url, alias = _find_profile_anchor(container, base_url)
        if anchor:
            role = "vendor" if tokens.intersection({"vendor", "seller", "merchant", "store-owner"}) else "forum_member"
            seller = role == "vendor"
            _add_evidence(accepted, _make_actor_evidence(
                alias, role=role, evidence_type="generic_profile_link",
                confidence=0.86 if seller else 0.84, strength="medium",
                signals=["bounded_identity_container", "profile_link", "anchor_slug_match"],
                profile_url=profile_url, engine_hint=engine_hint or "generic",
                source_scope="vendor_card" if seller else "author_block",
                seller_evidence=seller,
                bound_identifiers=_bound_identifier_hashes(container, base_url=base_url)))

    # Marketplace vendor/seller cards: label and linked alias must be in the same bounded card.
    for container in soup.find_all(["article", "li", "tr", "div", "section"], limit=2500):
        if _blocked_actor_context(container):
            continue
        text = _bounded_text(container, 360)
        if not re.search(r"(?i)\b(vendor|seller|merchant|sold by|store owner)\b", text):
            continue
        anchor, profile_url, alias = _find_profile_anchor(container, base_url)
        if anchor and re.search(r"(?i)\b(vendor|seller|merchant|sold by|store owner)\b", _bounded_text(anchor.parent, 180)):
            evidence_type = "linked_vendor_field" if "vendor" in text.casefold() else "linked_seller_field"
            _add_evidence(accepted, _make_actor_evidence(
                alias, role="vendor", evidence_type=evidence_type,
                confidence=0.93, strength="strong",
                signals=["bounded_vendor_card", "profile_link", "anchor_slug_match"],
                profile_url=profile_url, engine_hint=engine_hint or "generic_marketplace",
                source_scope="vendor_card", seller_evidence=True,
                bound_identifiers=_bound_identifier_hashes(container, base_url=base_url)))

    # Profile/vendor page identity: route + H1/title agreement.
    page_identity = page_identity or {}
    page_url = base_url
    route_alias = _profile_identity_from_url(page_url)
    if route_alias and _valid_actor_alias(route_alias, allow_digit_leading=True):
        heading_candidates = [h.get_text(" ", strip=True) for h in soup.find_all(["h1", "h2"], limit=8)]
        title = soup.title.get_text(" ", strip=True) if soup.title else ""
        comparable = " ".join(heading_candidates + [title, str(page_identity.get("detected_title") or "")])
        if normalize_public_alias(route_alias) and normalize_public_alias(route_alias) in normalize_public_alias(comparable):
            lowered = urlsplit(page_url).path.casefold()
            is_vendor = any(marker in lowered for marker in ("/vendor/", "/vendors/", "/seller/", "/sellers/", "/merchant/"))
            _add_evidence(accepted, _make_actor_evidence(
                route_alias, role="vendor" if is_vendor else "profile_owner",
                evidence_type="vendor_page_identity_match" if is_vendor else "profile_page_identity_match",
                confidence=0.96, strength="strong",
                signals=["profile_route", "heading_or_title_match"],
                profile_url=page_url, engine_hint=engine_hint or "generic_profile",
                source_scope="profile_page", seller_evidence=is_vendor))

    return sorted(accepted.values(), key=lambda item: (-float(item["confidence"]), item["normalized_alias"]))[:25]


def is_generic_public_alias(value: str) -> bool:
    return normalize_public_alias(value) in GENERIC_ROLE_ALIASES


def is_noisy_public_alias(value: str) -> bool:
    normalized = normalize_public_alias(value)
    return (
        len(normalized) < 3
        or normalized in ALIAS_STOPWORDS
        or normalized in ALIAS_PROVIDER_WORDS
        or normalized.isdigit()
    )


def _has_alias_shape(value: str, *, source: str) -> bool:
    raw = (value or "").strip().lstrip("@")
    normalized = normalize_public_alias(raw)
    if not _valid_actor_alias(raw, allow_digit_leading=False):
        return False
    if "." in normalized and normalized.rsplit(".", 1)[-1] in {"php", "html", "htm", "onion", "jpg", "png"}:
        return False
    if source in {"explicit_label", "public_byline", "public_handle"}:
        return True
    # Link anchors are much noisier than explicit "Author:" / "Vendor:" text.
    # Accept only handles that look intentional, not ordinary navigation/adjectives.
    if re.search(r"[\d_.-]", raw):
        return True
    if re.search(r"[a-z][A-Z]", raw):
        return True
    if raw[:1].isupper() and raw[1:].islower() and 3 <= len(normalized) <= 16:
        return True
    if len(normalized) >= 8 and normalized not in ALIAS_STOPWORDS:
        return True
    return False


def extract_public_aliases(text: str, link_records: list[dict] | None = None) -> list[dict]:
    """Extract alias candidates; callers must require corroboration before storage."""
    observations: dict[tuple[str, str, str], dict] = {}

    def add(value: str, evidence_type: str, confidence: float, label: str,
            *, profile_url: str = "") -> None:
        normalized = normalize_public_alias(value)
        if not _has_alias_shape(value, source=evidence_type):
            return
        key = (normalized, evidence_type, profile_url)
        item = {
            "alias": value.strip().lstrip("@")[:32],
            "normalized_alias": normalized,
            "evidence_type": evidence_type,
            "confidence": confidence,
            "safe_context_label": label,
            "generic_role": is_generic_public_alias(normalized),
            "profile_url": profile_url[:500],
            "profile_identity": canonical_profile_identity(profile_url),
            "alias_skeleton": public_alias_skeleton(value),
        }
        previous = observations.get(key)
        if not previous or float(previous.get("confidence") or 0) < confidence:
            observations[key] = item

    for pattern, evidence_type, confidence, label in (
        (ALIAS_LABEL_RE, "explicit_label", 0.90, "Explicit public username or author label"),
        (ALIAS_BYLINE_RE, "public_byline", 0.86, "Public page byline"),
    ):
        for match in pattern.finditer(text or ""):
            add(match.group(1), evidence_type, confidence, label)
    for match in PATTERNS["telegram_handle"].finditer(text or ""):
        add(match.group(0), "public_handle", 0.88, "Public contact handle")
    for record in link_records or []:
        profile_url = str(record.get("url") or "")
        if not _is_profile_route(profile_url):
            continue
        anchor = re.sub(r"\s+", " ", record.get("anchor_text") or "").strip().lstrip("@")
        identity = parse_profile_identity(profile_url)
        # Flat links are noisy: they require a named route identity and exact
        # anchor/slug agreement. Numeric IDs are accepted only by structural DOM
        # extraction where a bounded author/vendor container proves the role.
        if (identity.get("kind") != "named"
                or not _alias_agrees_with_target(anchor, profile_url)
                or not _has_alias_shape(anchor, source="profile_link")):
            continue
        add(anchor, "profile_link", 0.82, "Public profile or author link",
            profile_url=profile_url)

    by_alias: dict[str, list[dict]] = {}
    for item in observations.values():
        by_alias.setdefault(str(item["normalized_alias"]), []).append(item)

    candidates: list[dict] = []
    for normalized, alias_observations in by_alias.items():
        profile_urls = sorted({str(item.get("profile_url") or "") for item in alias_observations
                               if item.get("profile_url")})
        groups = profile_urls or [""]
        for profile_url in groups:
            selected = [item for item in alias_observations
                        if not item.get("profile_url") or item.get("profile_url") == profile_url]
            evidence_types = {str(item.get("evidence_type") or "") for item in selected}
            best = max(selected, key=lambda item: float(item.get("confidence") or 0))
            item = dict(best)
            item["profile_url"] = profile_url
            item["profile_identity"] = canonical_profile_identity(profile_url)
            item["evidence_types"] = sorted(entry for entry in evidence_types if entry)
            item["evidence_count"] = len(item["evidence_types"])
            labelled = bool(evidence_types.intersection({"explicit_label", "public_byline"}))
            linked = "profile_link" in evidence_types
            handle = "public_handle" in evidence_types
            item["auto_store_eligible"] = bool(
                len(evidence_types) >= 2 and ((labelled and (linked or handle)) or (linked and handle)))
            if item["auto_store_eligible"]:
                item["evidence_type"] = "corroborated_public_alias"
                item["confidence"] = max(0.93, float(item.get("confidence") or 0))
                item["safe_context_label"] = "Corroborated public alias evidence"
            candidates.append(item)
    return sorted(candidates, key=lambda item: (
        -float(item["confidence"]), item["normalized_alias"], item.get("profile_url") or ""))


def extract_public_alias_candidates(text: str, link_records: list[dict] | None = None) -> list[dict]:
    """Return a bounded review corpus, including candidates rejected before actor storage.

    This is intentionally separate from :func:`extract_public_aliases`: the
    accepted actor path stays conservative, while the explainable candidate
    lifecycle can account for filename/provider/navigation-shaped values instead
    of silently losing them. No surrounding body text is returned.
    """
    result: dict[tuple[str, str, str], dict] = {}

    def add(value: str, evidence_type: str, confidence: float, *, profile_url: str = "") -> None:
        display = str(value or "").strip().lstrip("@")[:64]
        if not display:
            return
        normalized = normalize_public_alias(display)
        # Preserve a sanitized shape for rejection accounting even when normal
        # actor validation would reject it. Raw surrounding text never crosses.
        if not normalized:
            normalized = unicodedata.normalize("NFKC", display).casefold()[:32]
        key = (normalized, evidence_type, profile_url[:500])
        candidate = {
            "accepted": False,
            "evidence_version": 2,
            "alias": display,
            "normalized_alias": normalized[:32],
            "alias_skeleton": public_alias_skeleton(display),
            "evidence_type": evidence_type,
            "confidence": round(float(confidence), 3),
            "evidence_strength": "weak",
            "role": "candidate",
            "source_scope": "flat_text_candidate",
            "profile_url": profile_url[:500],
            "profile_identity": canonical_profile_identity(profile_url),
            "auto_store_eligible": False,
            "bound_identifiers": [],
        }
        previous = result.get(key)
        if not previous or float(previous.get("confidence") or 0) < confidence:
            result[key] = candidate

    for pattern, evidence_type, confidence in (
        (ALIAS_LABEL_RE, "explicit_label_candidate", 0.72),
        (ALIAS_BYLINE_RE, "public_byline_candidate", 0.68),
    ):
        for match in pattern.finditer(text or ""):
            add(match.group(1), evidence_type, confidence)
    for match in PATTERNS["telegram_handle"].finditer(text or ""):
        add(match.group(0), "public_handle_candidate", 0.70)
    for record in link_records or []:
        if not isinstance(record, dict):
            continue
        profile_url = str(record.get("url") or "")
        if not _is_profile_route(profile_url):
            continue
        anchor = re.sub(r"\s+", " ", str(record.get("anchor_text") or "")).strip().lstrip("@")
        if anchor:
            add(anchor, "profile_link_candidate", 0.66, profile_url=profile_url)

    # Overlay currently accepted/corroborated flat observations so the lifecycle
    # records the same strongest evidence that the actor path actually used.
    for item in extract_public_aliases(text or "", link_records or []):
        key = (str(item.get("normalized_alias") or ""),
               str(item.get("evidence_type") or ""), str(item.get("profile_url") or ""))
        result[key] = dict(item)
    return sorted(result.values(), key=lambda item: (
        str(item.get("normalized_alias") or ""), str(item.get("evidence_type") or ""),
        str(item.get("profile_url") or "")))[:100]


def actor_identity_evidence(indicators: list[dict]) -> list[dict]:
    """Return identity-correlation inputs; callers should persist hashes, not raw values."""
    return [item for item in indicators if item.get("type") in IDENTITY_INDICATOR_TYPES
            and float(item.get("confidence") or 0) >= 0.7]


def _context(text: str, start: int, end: int) -> str:
    return make_safe_snippet(text[max(0, start - 80): min(len(text), end + 80)], max_chars=220)


def extract_indicators(text: str, links: list[str] | None = None) -> list[dict]:
    text = text or ""
    pgp_blocks = list(PGP_RE.finditer(text))
    text = PGP_RE.sub("[REDACTED PGP BLOCK]", text)
    found: list[dict] = []
    seen = set()

    def add(kind: str, value: str, confidence: float, context: str) -> None:
        normalized = normalize_indicator_value(kind, value)
        key = (kind, normalized)
        if key not in seen:
            seen.add(key)
            found.append({"type": kind, "value": value, "normalized_value": normalized,
                          "confidence": confidence, "context": make_safe_snippet(redact_sensitive(context), max_chars=220)})

    # Only an explicit, labeled OpenPGP fingerprint is eligible for a public
    # exact-key lookup. Unlabelled hexadecimal strings and key-block digests
    # remain local correlation evidence and never become provider queries.
    for match in PGP_FINGERPRINT_RE.finditer(text):
        fingerprint = normalize_indicator_value("pgp_fingerprint", match.group(1))
        if len(fingerprint) in {40, 64}:
            add("pgp_fingerprint", fingerprint, 0.98, "[REDACTED PGP FINGERPRINT]")

    for kind, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(1) if kind == "username" else match.group(0)
            add(kind, value, 0.85, _context(text, *match.span()))
    all_links = list(links or []) + URL_RE.findall(text)
    for raw in all_links:
        url = normalize_url(raw)
        if not url:
            continue
        host = (urlsplit(url).hostname or "").lower()
        if host.endswith(".onion"):
            add("onion_url", url, 0.95, raw)
            add("onion_domain", host, 0.95, raw)
        else:
            # URL syntax is exact extraction evidence. It becomes an actor
            # pivot only when a separate same-container binding also exists.
            add("clearnet_url", url, 0.92, raw)
    for match in pgp_blocks:
        digest = hashlib.sha256(match.group(0).encode("utf-8", "ignore")).hexdigest()[:16]
        add("pgp_key_block", f"PGP_BLOCK_SHA256:{digest}", 0.9, "[REDACTED PGP BLOCK]")
    for match in re.finditer(r"(?i)\b(?:official\s+)?mirrors?\s*[:\-]", text):
        add("mirror_phrase", make_safe_snippet(match.group(0), max_chars=80), 0.65, _context(text, *match.span()))
    for match in re.finditer(r"(?i)\b(?:victim|affected organization|organizaci[oó]n afectada)\s*[:\-]\s*([\w .&-]{3,80})", text):
        add("victim_or_org_name", match.group(1).strip(), 0.6, _context(text, *match.span()))
    return found
