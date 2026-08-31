"""Presentation helpers that never inspect raw page content."""


def safe_count_label(label: str, value: int) -> str:
    return f"{label} ({int(value)})"
