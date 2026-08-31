"""Add-onion page renderer."""


def render(st, query) -> None:
    from dashboard_pages.workspace import _add_onion_page
    _add_onion_page(st, query)
