"""Operational Control Center page renderer."""


def render(st, query, pd) -> None:
    from dashboard_pages.workspace import _control_center
    _control_center(st, query, pd)
