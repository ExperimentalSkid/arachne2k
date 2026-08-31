"""Conservative, network-free forum URL role and resource identity.

This module deliberately does not decide whether a URL should be crawled.  It
only describes an already-observed URL and derives stable identities for known
forum resources.  The exact URL is always retained.  Canonical URLs remove
only known session/tracking and pagination variants; distinct thread or post
identifiers are never collapsed.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


FORUM_URL_ROLES = frozenset({
    "site_index", "section", "thread", "post_permalink", "pagination",
    "login", "attachment", "unknown",
})

_SESSION_OR_TRACKING_KEYS = frozenset({
    "sid", "session", "sessionid", "phpsessid", "jsessionid", "s",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "fbclid", "gclid", "mc_cid", "mc_eid", "ref", "ref_src",
    "source_tracking", "cache", "cb", "timestamp",
})
_PAGINATION_KEYS = frozenset({"start", "page", "page_no", "page_num", "offset"})
_INDEX_PATHS = frozenset({
    "", "/", "/index.php", "/index.html", "/index.htm", "/forum",
    "/forums", "/board", "/community",
})
_LOGIN_PATHS = frozenset({
    "/login", "/login.php", "/signin", "/sign-in", "/ucp.php",
})
_POST_FRAGMENT = re.compile(r"^(?:p|post|msg)(\d+)$", re.IGNORECASE)
_PATH_PAGE_SUFFIX = re.compile(
    r"(?:/(?:page|p)/\d+|/page-\d+|-page-\d+)/?$", re.IGNORECASE,
)


@dataclass(frozen=True)
class ForumUrlIdentity:
    exact_url: str
    engine: str
    role: str
    host: str
    canonical_url: str
    section_id: str | None = None
    thread_id: str | None = None
    post_id: str | None = None
    thread_identity: str | None = None
    post_identity: str | None = None
    case_identity: str | None = None
    confidence: str = "none"
    reason: str = "no_conservative_forum_route"


def _query_pairs(query: str) -> list[tuple[str, str]]:
    # SMF commonly separates query components with semicolons.  Treating them
    # as separators is safe here because this parser never performs a request.
    return [(str(key), str(value)) for key, value in
            parse_qsl(str(query or "").replace(";", "&"), keep_blank_values=True)]


def _query_map(pairs: list[tuple[str, str]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in pairs:
        result.setdefault(key.casefold(), value)
    return result


def _numeric(value: str | None) -> str | None:
    match = re.fullmatch(r"\s*(\d+)\s*", str(value or ""))
    return match.group(1) if match else None


def _smf_resource(value: str | None) -> tuple[str | None, str | None, bool]:
    """Return resource id, message id and whether an offset was present."""
    match = re.fullmatch(r"\s*(\d+)(?:\.(?:(\d+)|msg(\d+)))?\s*", str(value or ""), re.I)
    if not match:
        return None, None, False
    resource_id = match.group(1)
    offset = match.group(2)
    message_id = match.group(3)
    return resource_id, message_id, bool(offset and int(offset) > 0)


def _stable_slug(segment: str) -> str | None:
    value = str(segment or "").strip().casefold()
    if re.fullmatch(r"\d+", value):
        return value
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,119}", value):
        return None
    numeric = re.match(r"^(\d+)(?:[-._].*)?$", value)
    if numeric:
        return numeric.group(1)
    numeric = re.search(r"(?:^|[-._])(\d+)$", value)
    if numeric:
        return numeric.group(1)
    # Slugs can be stable on generic engines, but must never be persisted as
    # raw thread text.  A bounded hash keeps the identity metadata-safe.
    return "slug-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


def _generic_resource(path: str, kind: str) -> tuple[str | None, bool]:
    prefixes = "threads?|topics?|t" if kind == "thread" else "posts?"
    identity_path = _PATH_PAGE_SUFFIX.sub("", path) or "/"
    match = re.search(rf"/(?:{prefixes})/([^/]+)(?:/([^/]+))?", identity_path, re.I)
    if not match:
        return None, False
    candidates = [part for part in match.groups() if part]
    resource = None
    for part in reversed(candidates):
        resource = _stable_slug(part)
        if resource and not resource.startswith("slug-"):
            break
    resource = resource or (_stable_slug(candidates[0]) if candidates else None)
    pagination = bool(_PATH_PAGE_SUFFIX.search(path))
    return resource, pagination


def _canonical_url(exact_url: str, pairs: list[tuple[str, str]], *,
                   smf_topic: str | None = None, smf_board: str | None = None) -> str:
    try:
        parsed = urlsplit(exact_url)
        path = re.sub(r"/{2,}", "/", parsed.path or "/")
        path = _PATH_PAGE_SUFFIX.sub("", path) or "/"
        kept: list[tuple[str, str]] = []
        for key, value in pairs:
            lowered = key.casefold()
            if (lowered.startswith("utm_") or lowered in _SESSION_OR_TRACKING_KEYS
                    or lowered in _PAGINATION_KEYS):
                continue
            if lowered == "topic" and smf_topic:
                value = f"{smf_topic}.0"
            elif lowered == "board" and smf_board:
                value = f"{smf_board}.0"
            kept.append((key, value))
        fragment = parsed.fragment if _POST_FRAGMENT.fullmatch(parsed.fragment or "") else ""
        host = (parsed.hostname or "").casefold()
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit(((parsed.scheme or "http").casefold(), host + port, path,
                           urlencode(sorted(kept), doseq=True), fragment))
    except (TypeError, ValueError, UnicodeError):
        return exact_url


def classify_forum_url(url: str) -> ForumUrlIdentity:
    """Classify a forum URL and derive conservative same-host identities."""
    exact = str(url or "").strip()
    try:
        parsed = urlsplit(exact)
        host = (parsed.hostname or "").casefold()
        path = re.sub(r"/{2,}", "/", parsed.path or "/")
        lower_path = path.casefold().rstrip("/") or "/"
        basename = lower_path.rsplit("/", 1)[-1]
        pairs = _query_pairs(parsed.query)
        query = _query_map(pairs)
    except (TypeError, ValueError, UnicodeError):
        return ForumUrlIdentity(exact, "unknown", "unknown", "", exact)

    action = str(query.get("action") or "").casefold()
    mode = str(query.get("mode") or "").casefold()
    attachment_route = (
        basename == "attachment.php" or "/attachments/" in lower_path
        or "/attachment/" in lower_path or action == "dlattach"
        or (basename in {"download.php", "file.php"}
            and any(key in query for key in {"id", "file", "attachmentid", "attach"}))
    )
    if attachment_route:
        engine = "smf" if action == "dlattach" else "vbulletin" if basename == "attachment.php" else "generic"
        return ForumUrlIdentity(exact, engine, "attachment", host,
                                _canonical_url(exact, pairs), confidence="high",
                                reason="explicit_forum_attachment_route")

    login_route = (
        lower_path in _LOGIN_PATHS or basename == "login.php" or action == "login"
        or mode == "login" or (basename == "ucp.php" and mode in {"login", "register"})
    )
    if login_route:
        engine = "smf" if action == "login" else "phpbb" if basename == "ucp.php" else "generic"
        return ForumUrlIdentity(exact, engine, "login", host,
                                _canonical_url(exact, pairs), confidence="high",
                                reason="explicit_forum_login_route")

    fragment_post = None
    fragment_match = _POST_FRAGMENT.fullmatch(parsed.fragment or "")
    if fragment_match:
        fragment_post = fragment_match.group(1)
    has_page_variant = bool(_PATH_PAGE_SUFFIX.search(path)) or any(
        key.casefold() in _PAGINATION_KEYS and str(value).strip() not in {"", "0", "1"}
        for key, value in pairs
    )

    engine = "unknown"
    section_id = thread_id = post_id = None
    reason = "no_conservative_forum_route"
    smf_topic = smf_board = None

    if basename == "viewtopic.php":
        engine, thread_id = "phpbb", _numeric(query.get("t"))
        post_id = _numeric(query.get("p")) or fragment_post
        reason = "phpbb_viewtopic_identity"
    elif basename == "viewforum.php":
        engine, section_id = "phpbb", _numeric(query.get("f"))
        reason = "phpbb_viewforum_identity"
    elif basename == "showthread.php":
        engine, thread_id = "vbulletin", _numeric(query.get("t"))
        post_id = _numeric(query.get("p")) or fragment_post
        reason = "vbulletin_showthread_identity"
    elif basename == "showpost.php":
        engine, post_id = "vbulletin", _numeric(query.get("p")) or fragment_post
        reason = "vbulletin_showpost_identity"
    elif basename == "forumdisplay.php":
        engine, section_id = "vbulletin", _numeric(query.get("f"))
        reason = "vbulletin_forumdisplay_identity"
    elif basename == "index.php" and ("topic" in query or "board" in query):
        engine = "smf"
        if "topic" in query:
            thread_id, smf_message, smf_page = _smf_resource(query.get("topic"))
            post_id = smf_message or fragment_post
            smf_topic = thread_id if smf_page and not post_id else None
            has_page_variant = has_page_variant or smf_page
            reason = "smf_topic_identity"
        else:
            section_id, _, smf_page = _smf_resource(query.get("board"))
            smf_board = section_id if smf_page else None
            has_page_variant = has_page_variant or smf_page
            reason = "smf_board_identity"
    else:
        thread_id, generic_page = _generic_resource(path, "thread")
        if thread_id:
            engine, reason = "generic", "conservative_generic_thread_route"
            has_page_variant = has_page_variant or generic_page
        else:
            post_id, generic_page = _generic_resource(path, "post")
            if post_id:
                engine, reason = "generic", "conservative_generic_post_route"
                has_page_variant = has_page_variant or generic_page
            else:
                section_match = re.fullmatch(r"/(?:forum|forums|board)/(\d+|[a-z0-9][a-z0-9._-]{1,79})/?", path, re.I)
                if section_match:
                    engine, section_id, reason = "generic", _stable_slug(section_match.group(1)), "conservative_generic_section_route"

    canonical = _canonical_url(exact, pairs, smf_topic=smf_topic, smf_board=smf_board)
    thread_identity = f"forum:{host}:{engine}:thread:{thread_id}" if host and thread_id else None
    post_identity = f"forum:{host}:{engine}:post:{post_id}" if host and post_id else None
    section_identity = f"forum:{host}:{engine}:section:{section_id}" if host and section_id else None
    case_identity = thread_identity or post_identity

    if post_id:
        role = "post_permalink"
    elif has_page_variant and (thread_id or section_id):
        role = "pagination"
    elif thread_id:
        role = "thread"
    elif section_id:
        role = "section"
    elif lower_path in _INDEX_PATHS and not [
            pair for pair in pairs if pair[0].casefold() not in _SESSION_OR_TRACKING_KEYS]:
        role, engine, reason = "site_index", "generic", "conservative_forum_index_route"
    else:
        role = "unknown"

    confidence = "high" if engine in {"phpbb", "vbulletin", "smf"} and role != "unknown" else (
        "medium" if engine == "generic" and role != "unknown" else "none"
    )
    if role not in FORUM_URL_ROLES:
        role = "unknown"
    return ForumUrlIdentity(
        exact_url=exact, engine=engine, role=role, host=host,
        canonical_url=canonical, section_id=section_id, thread_id=thread_id,
        post_id=post_id, thread_identity=thread_identity,
        post_identity=post_identity, case_identity=case_identity,
        confidence=confidence, reason=reason,
    )
