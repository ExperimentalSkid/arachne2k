"""Review Findings page renderer."""


def render(st, query) -> None:
    from dashboard_pages.site_cards import render as render_site_cards
    render_site_cards(st, query, review_only=True)
