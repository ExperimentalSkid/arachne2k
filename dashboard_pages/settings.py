"""Plain-language operational settings page renderer."""


def render(st) -> None:
    from dashboard_pages.workspace import _settings
    _settings(st)
