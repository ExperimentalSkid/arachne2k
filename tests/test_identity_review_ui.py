import ast
import json
from pathlib import Path

from dashboard_pages import identity_signals
from dashboard_services import i18n


ROOT = Path(__file__).parents[1]


class _Capture:
    def __init__(self):
        self.items = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def _record(self, kind, value):
        self.items.append((kind, str(value)))

    def markdown(self, value, **_kwargs):
        self._record("markdown", value)

    def caption(self, value, **_kwargs):
        self._record("caption", value)

    def info(self, value, **_kwargs):
        self._record("info", value)

    def warning(self, value, **_kwargs):
        self._record("warning", value)

    def success(self, value, **_kwargs):
        self._record("success", value)

    def error(self, value, **_kwargs):
        self._record("error", value)

    def metric(self, label, value, **_kwargs):
        self._record("metric", f"{label}: {value}")

    def columns(self, count):
        if isinstance(count, list):
            count = len(count)
        return [self for _ in range(int(count))]

    def expander(self, label, **_kwargs):
        self._record("expander", label)
        return self

    def divider(self):
        return None

    @property
    def text(self):
        return " ".join(value for _, value in self.items)


def test_identity_evidence_labels_never_render_raw_identifier_values():
    safe = identity_signals._safe_codes([
        {"type": "pgp_key_block", "label": "secret@example.invalid"},
        {"type": "domain", "label": "https://hidden.example.invalid/a"},
        "https://raw.example.invalid/profile",
        "raw.example.invalid",
        "0x1234567890abcdef1234567890abcdef12345678",
        "0123 4567 89AB CDEF 0123 4567 89AB CDEF",
        "confirmed_structured_public_profile",
    ])

    joined = " ".join(safe)
    assert "Pgp Key Block" in joined
    assert "Domain" in joined
    assert "Confirmed Structured Public Profile" in joined
    assert "secret@example.invalid" not in joined
    assert "raw.example.invalid" not in joined
    assert "0x1234567890abcdef" not in joined
    assert "0123 4567 89AB" not in joined


def test_invalid_or_non_finite_candidate_scores_render_as_zero():
    assert identity_signals._confidence_percent("not-a-number") == 0
    assert identity_signals._confidence_percent(float("nan")) == 0
    assert identity_signals._confidence_percent(float("inf")) == 0


def test_discovery_candidates_show_reason_codes_but_not_raw_provider_artifacts():
    capture = _Capture()
    run = {
        "candidate_clusters_json": json.dumps([{
            "candidate_id": "candidate-1",
            "display_name": "Atlas candidate",
            "score": 0.92,
            "decision": "strong_candidate",
            "provider": "local_arachne",
            "url": "https://raw.example.invalid/profile",
            "domain": "raw.example.invalid",
            "supporting_evidence": [
                {"type": "pgp_key_block", "label": "secret@example.invalid"},
                {"type": "domain", "label": "raw.example.invalid"},
            ],
            "contradicting_evidence": [
                {"type": "handle", "label": "different-secret-handle"},
            ],
            "evidence_chain": [
                "confirmed dark-web profile",
                "https://raw.example.invalid/profile",
                "analyst review required before any identity claim",
            ],
        }]),
    }

    identity_signals._render_discovery_candidates(capture, run, "en")

    assert "Atlas candidate" in capture.text
    assert "Pgp Key Block" in capture.text
    assert "Domain" in capture.text
    assert "Handle" in capture.text
    assert "raw.example.invalid" not in capture.text
    assert "secret@example.invalid" not in capture.text
    assert "different-secret-handle" not in capture.text
    assert "Apply" not in capture.text


def test_discovery_status_distinguishes_running_and_completed_runs():
    running = _Capture()
    identity_signals._render_provider_state(
        running,
        {"status": "claimed"},
        {"run_status": "running", "provider_status_json": "{}"},
        "en",
    )
    assert "Discovery running" in running.text
    assert "Discovery complete" not in running.text

    completed = _Capture()
    identity_signals._render_provider_state(
        completed,
        {"status": "done"},
        {
            "run_status": "local_complete",
            "provider_status_json": json.dumps({
                "network_enabled": False,
                "enabled_providers": ["local_arachne"],
                "disabled_providers": ["clearweb_network"],
                "reason": "local_only_policy",
            }),
        },
        "en",
    )
    assert "Discovery complete" in completed.text
    assert "Local-only" in completed.text
    assert "Local Arachne" in completed.text
    assert "Clearweb Network" in completed.text


def test_every_identity_copy_key_has_english_and_spanish_text():
    source = (ROOT / "dashboard_pages" / "identity_signals.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    static_keys = {
        node.args[0].value
        for node in ast.walk(tree)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "tr"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        )
    }
    static_keys.update({
        "identity_rule_exact",
        "identity_rule_contextual",
        "identity_rule_disabled",
    })

    assert static_keys
    assert all(i18n.COPY.get(key, {}).get("en") for key in static_keys)
    assert all(i18n.COPY.get(key, {}).get("es") for key in static_keys)
