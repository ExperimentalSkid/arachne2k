from __future__ import annotations

import ast
from pathlib import Path

import pytest

from dashboard_pages import actors, spain_actors, spain_sellers


ROOT = Path(__file__).parents[1]
TARGET_PAGES = (
    "actors.py",
    "identity_signals.py",
    "quality_center.py",
    "spain_actors.py",
    "spain_sellers.py",
    "entity_intelligence.py",
    "connections.py",
    "timeline.py",
    "activity.py",
)
STORAGE_MUTATIONS = {
    "set_actor_watch",
    "exclude_actor_observation",
    "set_actor_connection_decision",
    "acknowledge_actor_watch_alert",
    "record_actor_candidate_decision",
    "decide_entity_expansion_proposal",
}


def _call_name(call: ast.Call) -> str:
    function = call.func
    if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name):
        return f"{function.value.id}.{function.attr}"
    if isinstance(function, ast.Name):
        return function.id
    return ""


def _test_has_authorizer(test: ast.AST) -> bool:
    return any(
        isinstance(node, ast.Call) and _call_name(node) == "_authorize"
        for node in ast.walk(test)
    )


def test_every_modular_page_storage_mutation_has_a_server_authorization_boundary():
    found = []
    for filename in TARGET_PAGES:
        path = ROOT / "dashboard_pages" / filename
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            mutation = (
                name.startswith("storage.")
                and name.removeprefix("storage.") in STORAGE_MUTATIONS
            )
            if name == "actor_intelligence.cleanup_public_alias_noise":
                mutation = any(
                    keyword.arg == "dry_run"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                    for keyword in node.keywords
                )
            if not mutation:
                continue
            found.append((filename, node.lineno, name))
            parent = parents.get(node)
            guarded = False
            while parent is not None:
                if isinstance(parent, ast.If) and _test_has_authorizer(parent.test):
                    guarded = True
                    break
                parent = parents.get(parent)
            assert guarded, f"{filename}:{node.lineno} mutates without _authorize: {name}"

    assert found


class _Query:
    def __init__(self):
        self.cleared = 0

    def clear(self):
        self.cleared += 1


class _Column:
    def __init__(self, streamlit):
        self.streamlit = streamlit

    def button(self, _label, **kwargs):
        self.streamlit.disabled.append(bool(kwargs.get("disabled")))
        # Simulate a forged/stale widget event even when presentation disabled it.
        return True


class _ConnectionStreamlit:
    def __init__(self):
        self.disabled = []
        self.reruns = 0

    def markdown(self, *_args, **_kwargs): pass
    def caption(self, *_args, **_kwargs): pass
    def warning(self, *_args, **_kwargs): pass
    def info(self, *_args, **_kwargs): pass

    def columns(self, count):
        count = count if isinstance(count, int) else len(count)
        return [_Column(self) for _ in range(count)]

    def rerun(self):
        self.reruns += 1


@pytest.mark.parametrize("module", (spain_actors, spain_sellers))
def test_readonly_forged_connection_click_cannot_reach_storage(module, monkeypatch):
    streamlit = _ConnectionStreamlit()
    query = _Query()
    writes = []
    authorizations = []
    monkeypatch.setattr(module, "_can", lambda _st, _capability: False)
    monkeypatch.setattr(
        module,
        "_authorize",
        lambda _st, capability: authorizations.append(capability) or False,
    )
    monkeypatch.setattr(
        module.storage,
        "set_actor_connection_decision",
        lambda *args: writes.append(args),
    )
    connection = {
        "id": 7,
        "other_alias": "public-alias",
        "other_onion_host": "a" * 56 + ".onion",
        "confidence_score": 90,
        "confidence_label": "high",
        "analyst_decision": "unreviewed",
        "evidence_json": "[]",
    }

    module._render_connection(streamlit, connection, "en", query)

    assert writes == []
    assert query.cleared == 0
    assert streamlit.reruns == 0
    assert streamlit.disabled and all(streamlit.disabled)
    assert authorizations


def test_alias_cleanup_forged_click_cannot_run_write_pass(monkeypatch):
    class _Block:
        def __enter__(self): return self
        def __exit__(self, *_args): return False

    class _Metric:
        def metric(self, *_args, **_kwargs): pass

    class _Streamlit:
        def __init__(self):
            self.disabled = []

        def expander(self, *_args, **_kwargs): return _Block()
        def caption(self, *_args, **_kwargs): pass
        def success(self, *_args, **_kwargs): pass
        def columns(self, count): return [_Metric() for _ in range(count)]
        def toggle(self, *_args, **kwargs):
            self.disabled.append(bool(kwargs.get("disabled")))
            return True
        def button(self, *_args, **kwargs):
            self.disabled.append(bool(kwargs.get("disabled")))
            return True
        def rerun(self): raise AssertionError("write path must not rerun")

    calls = []
    monkeypatch.setattr(actors, "_can", lambda _st, _capability: False)
    monkeypatch.setattr(actors, "_authorize", lambda _st, _capability: False)
    monkeypatch.setattr(
        actors.actor_intelligence,
        "cleanup_public_alias_noise",
        lambda *, dry_run: calls.append(dry_run) or {
            "noisy_aliases": 1,
            "checked": 1,
            "sample": ["noise"],
        },
    )

    actors._render_alias_quality_tools(_Streamlit(), _Query())

    assert calls == [True]
