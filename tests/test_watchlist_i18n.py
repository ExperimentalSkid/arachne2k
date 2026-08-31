from copy import deepcopy

import dashboard_pages.investigations as investigations
from dashboard_pages.investigations import (
    _BUILTIN_WATCHLIST_ES,
    _watchlist_display_text,
)


def test_all_builtin_watchlists_have_complete_spanish_display_text():
    for canonical_name, localized in _BUILTIN_WATCHLIST_ES.items():
        row = {
            "id": 100,
            "name": canonical_name,
            "description": "Canonical English description",
            "builtin": 1,
        }

        name, description = _watchlist_display_text(row, "es")

        assert (name, description) == localized
        assert name and description
        assert name != canonical_name


def test_english_builtin_watchlist_uses_canonical_stored_text():
    row = {
        "id": 7,
        "name": "Spain · Weapons",
        "description": "Spain-linked weapons context",
        "builtin": 1,
    }

    assert _watchlist_display_text(row, "en") == (
        row["name"],
        row["description"],
    )


def test_user_created_watchlist_text_is_verbatim_in_both_languages():
    row = {
        "id": 42,
        "name": "Mi revisión · Q3",
        "description": "Texto definido por el usuario — keep exactly",
        "builtin": 0,
    }

    assert _watchlist_display_text(row, "es") == (
        row["name"],
        row["description"],
    )
    assert _watchlist_display_text(row, "en") == (
        row["name"],
        row["description"],
    )


def test_display_localization_does_not_mutate_row_or_identity_fields():
    row = {
        "id": 3,
        "name": "High risk · Unreviewed",
        "description": "High or critical results awaiting review",
        "filters_json": '{"priority":"High risk","review":"needs_review"}',
        "builtin": 1,
        "updated_at": "2026-07-28T00:00:00Z",
    }
    original = deepcopy(row)

    _watchlist_display_text(row, "es")

    assert row == original


class _FakeNode:
    def __init__(self, root):
        self.root = root

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def markdown(self, value, **_kwargs):
        self.root.markdowns.append(str(value))

    def caption(self, value):
        self.root.captions.append(str(value))

    def button(self, label, *, key=None, **_kwargs):
        self.root.buttons.append((str(label), str(key)))
        return False

    def expander(self, _label):
        return _FakeNode(self.root)


class _FakeStreamlit(_FakeNode):
    def __init__(self):
        self.root = self
        self.markdowns = []
        self.captions = []
        self.buttons = []
        self.session_state = {}

    def container(self, **_kwargs):
        return _FakeNode(self)

    def columns(self, widths):
        return [_FakeNode(self) for _ in widths]

    def expander(self, _label):
        return _FakeNode(self)

    def form(self, _key):
        return _FakeNode(self)

    def code(self, _value, **_kwargs):
        return None

    def text_input(self, _label):
        return ""

    def selectbox(self, _label, options):
        return options[0]

    def form_submit_button(self, _label, **_kwargs):
        return False


def test_spanish_render_localizes_builtin_but_not_custom_watchlist(
        monkeypatch):
    import dashboard_pages.workspace as workspace

    rows = [
        {
            "id": 11,
            "name": "Spain · Weapons",
            "description": "Spain-linked weapons context",
            "filters_json": '{"priority":"Spain + weapons"}',
            "builtin": 1,
        },
        {
            "id": 91,
            "name": "Mi vista personal",
            "description": "Descripción escrita por la persona usuaria",
            "filters_json": '{"risk":"high"}',
            "builtin": 0,
        },
    ]
    fake = _FakeStreamlit()
    monkeypatch.setattr(investigations, "current_language", lambda _st: "es")
    monkeypatch.setattr(investigations.storage, "get_saved_investigations", lambda: rows)
    monkeypatch.setattr(workspace, "_can", lambda *_args: True)
    monkeypatch.setattr(workspace, "_authorize_action", lambda *_args: True)

    investigations.render(fake, None)

    rendered = "\n".join(fake.markdowns)
    assert "#### España · Armas" in rendered
    assert "#### Spain · Weapons" not in rendered
    assert "#### Mi vista personal" in rendered
    assert "Contexto de armas vinculado a España" in fake.captions
    assert "Descripción escrita por la persona usuaria" in fake.captions
    assert ("Abrir", "open-investigation-11") in fake.buttons
    assert ("Abrir", "open-investigation-91") in fake.buttons
    assert ("Eliminar", "delete-investigation-91") in fake.buttons
