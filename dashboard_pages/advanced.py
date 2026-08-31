"""Advanced maintenance page renderer."""


def render(st, query, pd) -> None:
    from dashboard_pages.workspace import _advanced_page
    _advanced_page(st, query, pd)
