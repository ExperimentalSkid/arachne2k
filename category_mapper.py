"""Deprecated presentation compatibility shim.

Content labels must come from the canonical fetched-page classifier.  This
module deliberately refuses to infer a label from URL/title/reason arguments,
whose provenance cannot be proven at this boundary.
"""
from __future__ import annotations


def classify_url_category(url: str, title: str | None, reasons: list[str] | None,
                          cluster_type: str | None = None) -> str:
    del url, title, reasons, cluster_type
    return "Unknown / Miscellaneous"
