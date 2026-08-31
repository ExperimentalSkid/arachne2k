"""Small routing adapter used by dashboard.main()."""


def render_page(page: str, renderers: dict) -> None:
    renderer = renderers.get(page) or renderers["Advanced"]
    renderer()
