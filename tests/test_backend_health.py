import socket

import backend_health
import storage


def test_backend_health_reports_staged_pipeline_not_legacy_worker(isolated_db, monkeypatch):
    storage.update_worker_state("stopped", "legacy worker is not authoritative")
    storage.heartbeat_worker_instance("fetch:test", "fetch", "idle")
    storage.heartbeat_worker_instance("verify:test", "verify", "idle")
    storage.heartbeat_worker_instance("card:test", "card", "idle")

    def unavailable(*_args, **_kwargs):
        raise OSError("not listening")

    monkeypatch.setattr(socket, "create_connection", unavailable)
    result = backend_health.snapshot()

    assert result["health"] == "healthy"
    assert result["worker"]["state"] == "online"
    assert set(result["worker"]["worker_types"]) >= {"fetch", "verify", "card"}
    assert result["tor"] == "unavailable"
