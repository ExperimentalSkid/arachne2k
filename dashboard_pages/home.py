"""Home page renderer."""


def render(st, query) -> None:
    from dashboard_pages.workspace import _simple_home
    _simple_home(st, query)
