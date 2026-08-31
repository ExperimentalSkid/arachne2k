"""Reports page renderer."""


def render(st, query) -> None:
    from dashboard_pages.workspace import _simple_reports
    _simple_reports(st, query)
