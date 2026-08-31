"""Reusable, escaped presentation helpers for analyst-facing Streamlit views."""
from __future__ import annotations

import html
import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

from paths import PREVIEWS_DIR


def page_lead(title: object, summary: object, *, eyebrow: object | None = None,
              aside: object | None = None, show_title: bool = True) -> str:
    """Return a compact, escaped page introduction.

    These helpers intentionally return presentation-only HTML.  Callers keep
    all controls in native Streamlit widgets, while repeated headings and
    empty states share one visual language without accepting arbitrary HTML.

    ``show_title=False`` is the explicit no-duplicate-title contract for pages
    that already rendered their primary heading with a native Streamlit title.
    The title is retained as an accessible label on the lead region, but is not
    repeated visually.  The default remains ``True`` for existing callers.
    """
    eyebrow_html = (
        f'<span class="rt-page-lead-eyebrow">{html.escape(str(eyebrow))}</span>'
        if eyebrow else ""
    )
    aside_html = (
        f'<span class="rt-page-lead-aside">{html.escape(str(aside))}</span>'
        if aside else ""
    )
    safe_title = html.escape(str(title))
    title_html = f'<h2>{safe_title}</h2>' if show_title else ""
    compact_class = " rt-page-lead-no-title" if not show_title else ""
    aria_label = f' aria-label="{safe_title}"' if not show_title else ""
    return (
        f'<div class="rt-page-lead{compact_class}"{aria_label}><div>'
        f'{eyebrow_html}{title_html}'
        f'<p>{html.escape(str(summary))}</p></div>{aside_html}</div>'
    )


def empty_state(title: object, detail: object | None = None) -> str:
    """Return an escaped, low-noise empty state for result workspaces."""
    detail_html = f'<p>{html.escape(str(detail))}</p>' if detail else ""
    return (
        '<div class="rt-empty-state"><span aria-hidden="true">\u00b7</span><div>'
        f'<strong>{html.escape(str(title))}</strong>{detail_html}</div></div>'
    )


def data_row(label: object, value: object, *, state: str = "") -> str:
    """Return one escaped key/value row with an optional semantic state."""
    safe_state = state if state in {"ok", "warn", "critical", "muted"} else ""
    state_class = f" rt-data-row-{safe_state}" if safe_state else ""
    return (
        f'<div class="rt-data-row{state_class}"><span>{html.escape(str(label))}</span>'
        f'<strong>{html.escape(str(value))}</strong></div>'
    )


def section_header(title: object, detail: object | None = None, *, count: int | None = None) -> str:
    """Return a restrained section heading for dense operational pages."""
    detail_html = f'<p>{html.escape(str(detail))}</p>' if detail else ""
    count_html = (
        f'<span class="rt-section-count">{int(count)}</span>' if count is not None else ""
    )
    return (
        '<div class="rt-section-head"><div>'
        f'<h3>{html.escape(str(title))}</h3>{detail_html}</div>{count_html}</div>'
    )


def workbench_header(title: object, summary: object, *, eyebrow: object | None = None,
                     aside: object | None = None) -> str:
    """Return the heading used inside a primary operational work surface.

    It is deliberately presentation-only: native Streamlit widgets remain
    outside this markup so their keys, callbacks and accessibility behavior are
    unchanged.
    """
    eyebrow_html = (
        f'<span class="rt-workbench-eyebrow">{html.escape(str(eyebrow))}</span>'
        if eyebrow else ""
    )
    aside_html = (
        f'<span class="rt-workbench-aside">{html.escape(str(aside))}</span>'
        if aside else ""
    )
    return (
        '<div class="rt-workbench-head"><div>'
        f'{eyebrow_html}<h3>{html.escape(str(title))}</h3>'
        f'<p>{html.escape(str(summary))}</p></div>{aside_html}</div>'
    )


def metric_strip(items: Iterable[tuple[object, object, object | None, str]]) -> str:
    """Render a compact, accessible read-only metric strip.

    ``items`` contain ``(label, value, detail, state)``.  This helper never
    calculates or transforms values; it only presents values already produced
    by the caller.
    """
    rendered: list[str] = []
    for label, value, detail, state in items:
        safe_state = state if state in {"ok", "warn", "critical", "info", "muted"} else "muted"
        detail_html = f'<small>{html.escape(str(detail))}</small>' if detail else ""
        rendered.append(
            f'<div class="rt-kpi rt-kpi-{safe_state}" role="listitem">'
            f'<span>{html.escape(str(label))}</span>'
            f'<strong>{html.escape(str(value))}</strong>{detail_html}</div>'
        )
    return '<div class="rt-kpi-strip" role="list">' + "".join(rendered) + "</div>"


def stage_strip(items: Iterable[tuple[object, object, str]]) -> str:
    """Render read-only assembly-line state without introducing controls."""
    rendered: list[str] = []
    for label, value, state in items:
        safe_state = state if state in {"ok", "warn", "critical", "active", "muted"} else "muted"
        rendered.append(
            f'<div class="rt-stage rt-stage-{safe_state}">'
            f'<span>{html.escape(str(label))}</span>'
            f'<strong>{html.escape(str(value))}</strong></div>'
        )
    return '<div class="rt-stage-strip">' + "".join(rendered) + "</div>"


def mask_onion_address(value: object, *, leading: int = 8, trailing: int = 8) -> str:
    """Mask a raw onion address for list surfaces while preserving recognition.

    Detail views continue to use the original value and Streamlit's native code
    control for deliberate reveal/copy.  This helper never changes stored data.
    """
    raw = " ".join(str(value or "").split())
    try:
        host = urlsplit(raw if "://" in raw else f"http://{raw}").hostname or raw
    except ValueError:
        host = raw
    if not host:
        return "Unavailable"
    if not host.casefold().endswith(".onion"):
        return host
    stem = host[:-6]
    visible_leading = min(leading, max(2, len(stem) // 2))
    visible_trailing = min(max(2, trailing - 6), max(1, len(stem) - visible_leading))
    if len(stem) <= visible_leading + visible_trailing:
        visible_leading = max(1, len(stem) // 2)
        visible_trailing = max(1, len(stem) - visible_leading - 1)
    return f"{stem[:visible_leading]}\u2026{stem[-visible_trailing:]}.onion"


def spain_flag_badge(label: str = "Spain-linked") -> str:
    """Render a cross-platform Spain flag while retaining emoji semantics."""
    safe_label = html.escape(label)
    return (
        f'<span class="rt-spain-flag" role="img" aria-label="{safe_label}" '
        f'title="{safe_label}"><span class="rt-sr-only">🇪🇸</span></span>'
    )


def safe_display_title(*values: object, fallback: str = "Unnamed site") -> str:
    """Choose a list-safe title without promoting a raw address into a heading."""
    for value in values:
        candidate = " ".join(str(value or "").split())
        if not candidate:
            continue
        lowered = candidate.casefold()
        if ".onion" in lowered or lowered.startswith(("http://", "https://")):
            continue
        return candidate
    return fallback


def _badge(value: str | None, color: str, label: str | None = None, kind: str = "") -> str:
    display = label if label is not None else str(value or "Unknown").replace("_", " ").title()
    extra = f" badge-{kind}" if kind else ""
    return f'<span class="badge badge-{color}{extra}">{html.escape(str(display))}</span>'


def risk_badge(value: str, label: str | None = None) -> str:
    return _badge(value, {"NULO":"gray", "BAJO":"green", "MEDIO":"amber", "ALTO":"orange", "CRITICO":"red",
        "LOW":"green", "MEDIUM":"amber", "HIGH":"orange", "CRITICAL":"red"}.get((value or "").upper(), "gray"), label, "risk")


def status_badge(value: str, label: str | None = None) -> str:
    return _badge(value, {"queued":"blue", "new":"blue", "crawled":"green", "active":"green",
        "blocked":"red", "dead":"gray", "error":"red", "retry":"amber", "offline":"gray"}.get((value or "").lower(), "gray"), label)


def review_badge(value: str, label: str | None = None) -> str:
    return _badge(value, {"pending":"amber", "relevant":"green", "false_positive":"gray",
        "needs_report":"orange", "reported":"blue", "blocked":"red"}.get((value or "").lower(), "gray"), label)


def confidence_badge(value: str, label: str | None = None) -> str:
    return _badge(value, {"LOW":"gray", "MEDIUM":"amber", "HIGH":"red"}.get((value or "").upper(), "gray"), label)


def category_badge(value: str, label: str | None = None) -> str:
    # Resolve exact presentation categories before keyword fallbacks.  The old
    # order let words such as ``forum`` and ``wiki`` override their declared
    # palette, so the same category could change colour between old and
    # canonical labels.
    colors = {
        "leak / extortion context": "red",
        "recruitment context": "orange",
        "marketplace-related context": "amber",
        "contact / infrastructure": "purple",
        "hidden service directory": "blue",
        "search / index": "cyan",
        "social / forum": "blue",
        "hosting / services": "green",
        "wiki / knowledge": "green",
        "unknown / miscellaneous": "gray",
        "directory_index": "cyan",
        "link_repository": "cyan",
        "forum": "blue",
        "forum_home": "blue",
        "forum_thread": "blue",
        "wiki": "green",
        "code_repository": "purple",
        "marketplace": "amber",
        "unknown": "gray",
    }
    normalized = str(value or "").casefold()
    semantic_name = normalized.replace("_", " ").replace("-", " ")
    semantic = (colors[normalized] if normalized in colors else
                "red" if any(term in semantic_name for term in (
                    "fraud", "carding", "leak", "extortion", "credential",
                )) else
                "purple" if "adult" in semantic_name else
                "red" if "severe" in semantic_name else
                "orange" if any(term in semantic_name for term in ("weapon", "drug")) else
                "amber" if "marketplace" in semantic_name else
                "cyan" if any(term in semantic_name for term in (
                    "directory", "link repository", "link list", "search", "index",
                )) else
                "blue" if any(term in semantic_name for term in ("forum", "social", "community")) else
                "green" if any(term in semantic_name for term in (
                    "wiki", "documentation", "education", "reference", "hosting", "service",
                )) else
                "purple" if any(term in semantic_name for term in ("code", "software", "infosec")) else
                "amber" if any(term in semantic_name for term in ("crypto", "finance")) else
                "gray")
    return _badge(value, semantic, label, "category")


def importance_badge(value: str, label: str | None = None) -> str:
    return _badge(value, {"low": "gray", "normal": "blue", "elevated": "amber",
                          "high": "orange", "critical": "red"}.get(
                              str(value or "normal").casefold(), "gray"), label, "importance")


def severity_badge(value: str, label: str | None = None) -> str:
    return _badge(value, {"info":"blue", "low":"green", "medium":"amber", "high":"red"}.get((value or "").lower(), "gray"), label)


def parse_json(value, default=None):
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value or ("[]" if default is None else json.dumps(default)))
    except (TypeError, ValueError):
        return [] if default is None else default


def indicator_summary(indicators: list[dict]) -> tuple[str, list[str]]:
    counts = Counter(item.get("type", "unknown") for item in indicators if isinstance(item, dict))
    summary = ", ".join(f"{kind.replace('_', ' ').title()} ×{count}" for kind, count in counts.most_common()) or "No indicators"
    values = [f"{item.get('type','unknown').replace('_',' ').title()}: {item.get('value','Unavailable')}" for item in indicators[:8] if isinstance(item, dict)]
    return summary, values


def explain_flag(reasons: list[str], indicators: list[dict], exposures: list[dict], cluster_id=None) -> str:
    readable = [str(reason).replace("_", " ").replace("+", " + ").title() for reason in reasons if not str(reason).startswith("lang:")]
    parts = []
    if readable:
        parts.append("matched " + ", ".join(readable[:3]) + " scoring patterns")
    if indicators:
        parts.append(f"exposed {len(indicators)} public indicator(s)")
    if exposures:
        parts.append(f"contained {len(exposures)} passive technical disclosure(s)")
    if cluster_id:
        parts.append(f"is linked to passive mirror cluster #{cluster_id}")
    return "This page was flagged because it " + ", and ".join(parts) + "." if parts else "This page is kept for review using passively collected details."


def suggested_action(risk: str, review_status: str) -> str:
    if review_status == "needs_report" or risk == "CRITICO":
        return "Prepare report"
    if review_status == "pending" or risk in {"ALTO", "MEDIO"}:
        return "Review further"
    return "Monitor"


def safe_preview_path(path_value: str | None) -> Path | None:
    if not path_value:
        return None
    path = Path(path_value)
    try:
        resolved = path.resolve()
        allowed_root = PREVIEWS_DIR.resolve()
        return resolved if resolved.is_relative_to(allowed_root) and resolved.is_file() and resolved.suffix.lower() == ".png" else None
    except (OSError, ValueError):
        return None
