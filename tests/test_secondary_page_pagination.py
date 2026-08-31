from __future__ import annotations

import pytest

from dashboard_pages import actors, entity_intelligence, spain_actors, spain_priority, spain_sellers


class _FakeStreamlit:
    def __init__(self) -> None:
        self.session_state = {}
        self.captions: list[str] = []
        self.selectboxes = 0

    def selectbox(self, _label, options, **_kwargs):
        self.selectboxes += 1
        return options[1]

    def caption(self, value):
        self.captions.append(str(value))


@pytest.mark.parametrize(
    "pager,kwargs",
    (
        (actors._page_items, {"item_name": "records"}),
        (
            entity_intelligence._page_items,
            {"language": "en", "english_name": "records", "spanish_name": "registros"},
        ),
        (
            spain_priority._page_items,
            {"language": "en", "english_name": "records", "spanish_name": "registros"},
        ),
        (
            spain_actors._page_items,
            {"language": "en", "english_name": "records", "spanish_name": "registros"},
        ),
        (
            spain_sellers._page_items,
            {"language": "en", "english_name": "records", "spanish_name": "registros"},
        ),
    ),
)
def test_secondary_page_pagers_bound_interactive_records(pager, kwargs):
    st = _FakeStreamlit()
    rows = [{"id": value} for value in range(12)]

    visible = pager(st, rows, key="test", page_size=5, **kwargs)

    assert [row["id"] for row in visible] == [5, 6, 7, 8, 9]
    assert st.selectboxes == 1
    assert any("6-10" in caption and "12" in caption for caption in st.captions)

