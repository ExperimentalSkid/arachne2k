"""Site-card summary/detail page renderer."""


def render(st, query, *, review_only: bool = False) -> None:
    from dashboard_pages.workspace import _site_cards_page
    _site_cards_page(st, query, review_only=review_only)
