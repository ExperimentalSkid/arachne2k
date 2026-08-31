"""Crawl-queue page renderer."""


def render(st, query, pd) -> None:
    from dashboard_pages.workspace import _crawl_manager
    _crawl_manager(st, query, pd)
