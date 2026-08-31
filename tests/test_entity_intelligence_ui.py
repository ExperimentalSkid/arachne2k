from __future__ import annotations

from types import SimpleNamespace

import pytest

from dashboard_pages import entity_intelligence


class _Block:
    def __init__(self, st):
        self._st = st

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def __getattr__(self, name):
        return getattr(self._st, name)


class FakeStreamlit:
    """Small Streamlit surface that also records everything rendered."""

    def __init__(self, *, view="Review Inbox", spanish=False, values=None,
                 selected=None, clicked=None):
        self.session_state = {"ui_spanish": spanish}
        self.view = view
        self.values = values or {}
        self.selected = selected or {}
        self.clicked = set(clicked or ())
        self.output: list[str] = []
        self.reruns = 0

    def _record(self, *values):
        self.output.extend(str(value) for value in values if value is not None)

    def markdown(self, *values, **_kwargs): self._record(*values)
    def caption(self, *values, **_kwargs): self._record(*values)
    def write(self, *values, **_kwargs): self._record(*values)
    def info(self, *values, **_kwargs): self._record(*values)
    def warning(self, *values, **_kwargs): self._record(*values)
    def success(self, *values, **_kwargs): self._record(*values)
    def error(self, *values, **_kwargs): self._record(*values)
    def subheader(self, *values, **_kwargs): self._record(*values)
    def divider(self): self._record("---")

    def code(self, value, **_kwargs):
        self._record(value)

    def metric(self, label, value, *args, **_kwargs):
        self._record(label, value, *args)

    def columns(self, spec, **_kwargs):
        count = spec if isinstance(spec, int) else len(spec)
        return [_Block(self) for _ in range(count)]

    def expander(self, label, **_kwargs):
        self._record(label)
        return _Block(self)

    def text_input(self, label, *, key=None, value="", **_kwargs):
        self._record(label)
        return self.values.get(key, value)

    def checkbox(self, label, *, key=None, value=False, **_kwargs):
        self._record(label)
        return bool(self.values.get(key, value))

    def radio(self, label, options, *, key=None, **_kwargs):
        self._record(label)
        if key == "entity-intelligence-view":
            return self.view
        return self.selected.get(key, options[0])

    def selectbox(self, label, options, *, key=None, **_kwargs):
        self._record(label)
        return self.selected.get(key, options[0])

    def button(self, label, *, key=None, disabled=False, **_kwargs):
        self._record(label)
        return not disabled and key in self.clicked

    def rerun(self):
        self.reruns += 1


class FakeQuery:
    def __init__(self):
        self.cleared = 0

    def clear(self):
        self.cleared += 1


class ForgedClickStreamlit(FakeStreamlit):
    """Return clicked events even when a control is disabled."""

    def button(self, label, *, key=None, disabled=False, **_kwargs):
        self._record(label)
        return key in self.clicked


@pytest.fixture
def calls(monkeypatch):
    recorded = SimpleNamespace(
        search=[], queues=[], actors=[], details=[], proposals=[], decisions=[],
        candidate_decisions=[], timeline=0,
    )

    def queue(**kwargs):
        recorded.queues.append(kwargs)
        return []

    monkeypatch.setattr(entity_intelligence.storage, "search_entity_intelligence",
                        lambda query, **kwargs: recorded.search.append((query, kwargs)) or
                        {"actors": [], "site_cards": [], "candidates": []})
    monkeypatch.setattr(entity_intelligence.storage, "get_actor_candidate_review_queue", queue)
    monkeypatch.setattr(entity_intelligence.storage, "get_public_actors",
                        lambda **kwargs: recorded.actors.append(kwargs) or [])
    monkeypatch.setattr(entity_intelligence.storage, "get_alias_quality_audit",
                        lambda **_kwargs: {"states": {}})
    monkeypatch.setattr(entity_intelligence.storage, "get_entity_expansion_metrics",
                        lambda: {"proposed": 0})
    monkeypatch.setattr(entity_intelligence.storage, "get_actor_detail",
                        lambda actor_id: recorded.details.append(actor_id) or None)
    monkeypatch.setattr(entity_intelligence.storage, "get_entity_expansion_proposals",
                        lambda **kwargs: recorded.proposals.append(kwargs) or [])
    monkeypatch.setattr(entity_intelligence.storage, "decide_entity_expansion_proposal",
                        lambda proposal_id, decision, **kwargs:
                        recorded.decisions.append((proposal_id, decision, kwargs)) or True)
    monkeypatch.setattr(entity_intelligence.storage, "record_actor_candidate_decision",
                        lambda candidate_id, decision, **kwargs:
                        recorded.candidate_decisions.append((candidate_id, decision, kwargs)) or True)

    def timeline(**_kwargs):
        recorded.timeline += 1
        return []

    monkeypatch.setattr(entity_intelligence.storage, "get_intelligence_timeline", timeline)
    return recorded


def _candidate(candidate_id=7):
    return {
        "id": candidate_id,
        "display_alias": "careful-handle",
        "normalized_alias": "careful-handle",
        "onion_host": "a" * 56 + ".onion",
        "effective_state": "analyst_review_candidate",
        "evidence_confidence": 0.91,
        "evidence_type": "profile_page_identity_match",
        "structural_role": "profile",
        "extraction_method": "profile_structure",
        "reason_codes_json": '["strong_profile_route", "stable_handle"]',
    }


def test_views_are_non_eager_and_global_search_uses_safe_boundary(calls, monkeypatch):
    evidence = [_candidate()]

    def queue(**kwargs):
        calls.queues.append(kwargs)
        return evidence if kwargs.get("states") else []

    monkeypatch.setattr(entity_intelligence.storage, "get_actor_candidate_review_queue", queue)
    st = FakeStreamlit(
        view="Evidence", values={"entity-intelligence-search": "careful"})
    entity_intelligence.render(st, FakeQuery())

    assert calls.search == [("careful", {"limit": 50})]
    assert any(call.get("states") == entity_intelligence._ALL_CANDIDATE_STATES
               for call in calls.queues)
    assert calls.details == []
    assert calls.proposals == []
    assert calls.timeline == 0


def test_review_decision_uses_storage_api_and_clears_query(calls, monkeypatch):
    def queue(**kwargs):
        calls.queues.append(kwargs)
        return [_candidate()] if kwargs.get("limit") == 200 else []

    monkeypatch.setattr(entity_intelligence.storage, "get_actor_candidate_review_queue", queue)
    st = FakeStreamlit(view="Review Inbox", clicked={"entity-candidate-confirm-7"})
    query = FakeQuery()
    entity_intelligence.render(st, query)

    assert calls.candidate_decisions == [
        (7, "confirm", {"reason_code": "entity_intelligence_review"})]
    assert query.cleared == 1
    assert st.reruns == 1


def test_demo_readonly_forged_review_click_cannot_reach_storage(calls, monkeypatch):
    def queue(**kwargs):
        calls.queues.append(kwargs)
        return [_candidate()] if kwargs.get("limit") == 200 else []

    monkeypatch.setattr(entity_intelligence.storage, "get_actor_candidate_review_queue", queue)
    monkeypatch.setattr(entity_intelligence, "_can", lambda _st, _capability: False)
    authorizations = []
    monkeypatch.setattr(
        entity_intelligence, "_authorize",
        lambda _st, capability: authorizations.append(capability) or False)
    st = ForgedClickStreamlit(
        view="Review Inbox", clicked={"entity-candidate-confirm-7"})

    entity_intelligence.render(st, FakeQuery())

    assert calls.candidate_decisions == []
    assert authorizations == [
        entity_intelligence.dashboard_auth.CAPABILITY_REVIEWS_MANAGE]


def test_expansion_approval_requires_confirmation(calls, monkeypatch):
    proposal = {
        "id": 11,
        "actor_alias": "careful-handle",
        "status": "proposed",
        "route_role": "profile",
        "reason_code": "BOUNDED_PUBLIC_ROUTE",
        "expected_value": 0.95,
        "proposed_url": "http://" + "a" * 56 + ".onion/member/7",
    }
    monkeypatch.setattr(
        entity_intelligence.storage, "get_entity_expansion_proposals",
        lambda **kwargs: calls.proposals.append(kwargs) or [proposal])

    unconfirmed = FakeStreamlit(
        view="Expansion", clicked={"entity-expansion-approve-11"})
    entity_intelligence.render(unconfirmed, FakeQuery())
    assert calls.decisions == []

    confirmed = FakeStreamlit(
        view="Expansion",
        values={
            "entity-expansion-confirm-11": True,
            "entity-expansion-reason-11": "Useful public profile route",
        },
        clicked={"entity-expansion-approve-11"},
    )
    entity_intelligence.render(confirmed, FakeQuery())
    assert calls.decisions == [
        (11, "approve", {"reason": "Useful public profile route"})]


def test_analyst_can_reject_expansion_but_cannot_queue_it(calls, monkeypatch):
    proposal = {
        "id": 13,
        "actor_alias": "careful-handle",
        "status": "proposed",
        "route_role": "profile",
        "reason_code": "BOUNDED_PUBLIC_ROUTE",
        "expected_value": 0.95,
        "proposed_url": "http://" + "c" * 56 + ".onion/member/8",
    }
    monkeypatch.setattr(
        entity_intelligence.storage, "get_entity_expansion_proposals",
        lambda **kwargs: calls.proposals.append(kwargs) or [proposal])
    monkeypatch.setattr(
        entity_intelligence,
        "_can",
        lambda _st, capability:
        capability == entity_intelligence.dashboard_auth.CAPABILITY_REVIEWS_MANAGE,
    )
    monkeypatch.setattr(
        entity_intelligence,
        "_authorize",
        lambda _st, capability:
        capability == entity_intelligence.dashboard_auth.CAPABILITY_REVIEWS_MANAGE,
    )
    st = ForgedClickStreamlit(
        view="Expansion",
        values={
            "entity-expansion-confirm-13": True,
            "entity-expansion-reason-13": "Analyst review",
        },
        clicked={
            "entity-expansion-approve-13",
            "entity-expansion-reject-13",
        },
    )

    entity_intelligence.render(st, FakeQuery())

    assert calls.decisions == [
        (13, "reject", {"reason": "Analyst review"})]


def test_expansion_reject_is_a_separate_decision(calls, monkeypatch):
    proposal = {
        "id": 12,
        "site_card_name": "Example forum",
        "status": "proposed",
        "route_role": "thread",
        "reason_code": "BOUNDED_PUBLIC_ROUTE",
        "expected_value": 0.8,
        "proposed_url": "http://" + "b" * 56 + ".onion/thread/2",
    }
    monkeypatch.setattr(entity_intelligence.storage, "get_entity_expansion_proposals",
                        lambda **_kwargs: [proposal])
    st = FakeStreamlit(view="Expansion", clicked={"entity-expansion-reject-12"})
    entity_intelligence.render(st, FakeQuery())
    assert calls.decisions == [(12, "reject", {"reason": None})]


def test_entity_view_loads_selected_detail_only(calls, monkeypatch):
    actor = {
        "id": 4,
        "display_alias": "careful-handle",
        "onion_host": "a" * 56 + ".onion",
        "observation_count": 2,
    }
    detail = {
        "actor": actor,
        "aliases": [],
        "observations": [],
        "connections": [],
        "identifiers": [],
        "events": [{"safe_metadata_json": "RESTRICTED-SENTINEL"}],
        "candidates": [],
        "expansion": [],
    }
    monkeypatch.setattr(entity_intelligence.storage, "get_public_actors",
                        lambda **kwargs: calls.actors.append(kwargs) or [actor])
    monkeypatch.setattr(entity_intelligence.storage, "get_actor_detail",
                        lambda actor_id: calls.details.append(actor_id) or detail)
    st = FakeStreamlit(view="Entities")
    entity_intelligence.render(st, FakeQuery())

    assert calls.details == [4]
    assert "careful-handle" in " ".join(st.output)
    assert "RESTRICTED-SENTINEL" not in " ".join(st.output)


def test_connections_filters_use_safe_evidence_and_operational_dimensions(calls, monkeypatch):
    actor = {"id": 4, "display_alias": "careful-handle", "onion_host": "a" * 56 + ".onion"}
    detail = {
        "actor": actor,
        "connections": [
            {
                "other_alias": "high-confidence-peer",
                "other_onion_host": "b" * 56 + ".onion",
                "confidence_score": 88,
                "analyst_decision": "unreviewed",
                "evidence_json": '[{"type":"pgp_key_block"}]',
                "warning_type": "conflicting_public_identifiers",
                "other_watched": 1,
                "other_spain_observation_count": 2,
                "last_seen": "2026-07-16T10:00:00Z",
            },
            {
                "other_alias": "low-confidence-peer",
                "other_onion_host": "c" * 56 + ".onion",
                "confidence_score": 22,
                "analyst_decision": "unreviewed",
                "evidence_json": '[{"type":"same_alias"}]',
                "warning_type": None,
                "other_watched": 0,
                "other_spain_observation_count": 0,
                "last_seen": "2026-07-16T10:00:00Z",
            },
        ],
    }
    monkeypatch.setattr(entity_intelligence.storage, "get_public_actors",
                        lambda **_kwargs: [actor])
    monkeypatch.setattr(entity_intelligence.storage, "get_actor_detail",
                        lambda _actor_id: detail)
    st = FakeStreamlit(view="Connections", selected={
        "entity-connections-confidence": "high",
        "entity-connections-evidence": "Pgp Key Block",
        "entity-connections-focus": "spain",
    })

    entity_intelligence.render(st, FakeQuery())

    rendered = " ".join(st.output)
    assert "high-confidence-peer" in rendered
    assert "low-confidence-peer" not in rendered
    assert "Pgp Key Block" in rendered


def test_completed_expansion_displays_reason_coded_result_and_budget(calls, monkeypatch):
    proposal = {
        "id": 13,
        "site_card_name": "Example forum",
        "status": "completed",
        "route_role": "profile",
        "reason_code": "VERIFIED_PROFILE_ROUTE",
        "result_code": "DESTINATION_USEFUL_VERIFIED",
        "expected_value": 0.95,
        "host_budget": 10,
        "resource_budget": 1,
        "proposed_url": "http://" + "b" * 56 + ".onion/member/2",
    }
    monkeypatch.setattr(entity_intelligence.storage, "get_entity_expansion_proposals",
                        lambda **_kwargs: [proposal])
    st = FakeStreamlit(view="Expansion")

    entity_intelligence.render(st, FakeQuery())

    rendered = " ".join(st.output)
    assert "Destination Useful Verified" in rendered
    assert "host 10" in rendered


def test_spanish_history_hides_raw_page_change_summary_and_metadata(calls, monkeypatch):
    raw_url = "http://" + "x" * 56 + ".onion/private-path"
    secret = "DO-NOT-RENDER-METADATA"

    def timeline(**_kwargs):
        calls.timeline += 1
        return [{
            "ts": "2026-07-16T12:00:00Z",
            "event_family": "page_change",
            "event_type": "content_changed",
            "summary": raw_url,
            "safe_metadata_json": secret,
        }]

    monkeypatch.setattr(entity_intelligence.storage, "get_intelligence_timeline", timeline)
    st = FakeStreamlit(view="History", spanish=True)
    entity_intelligence.render(st, FakeQuery())
    rendered = " ".join(st.output)

    assert "Inteligencia de entidades" in rendered
    assert "Cambio de página registrado" in rendered
    assert raw_url not in rendered
    assert secret not in rendered


def test_structured_connection_evidence_exposes_only_safe_label():
    labels = entity_intelligence._json_labels(
        '[{"label":"Shared PGP fingerprint","raw_value":"DO-NOT-RENDER"}]')
    assert labels == ["Shared PGP fingerprint"]
