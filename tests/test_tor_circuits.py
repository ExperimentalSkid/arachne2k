import onion_worker
import tor_circuits


def test_socks_isolation_rotates_credentials_on_a_gentle_interval(monkeypatch):
    tor_circuits.reset_rotation_state_for_tests()
    monkeypatch.setattr(tor_circuits, "get_bool", lambda key, default=False: key == "TOR_SOCKS_ISOLATION")
    monkeypatch.setattr(tor_circuits, "get_int", lambda key, default: {
        "TOR_SOCKS_IDENTITY_INTERVAL_SECONDS": 900,
    }.get(key, default))
    tor_circuits.prepare_fetch_circuit(now=100)
    first = tor_circuits.requests_proxy_url()
    tor_circuits.prepare_fetch_circuit(now=999)
    same_window = tor_circuits.requests_proxy_url()
    tor_circuits.prepare_fetch_circuit(now=1000)
    rotated = tor_circuits.requests_proxy_url()
    assert first.startswith("socks5h://arachne-")
    assert "@127.0.0.1:9050" in first
    assert first == same_window
    assert first != rotated


def test_socks_isolation_can_be_disabled(monkeypatch):
    monkeypatch.setattr(tor_circuits, "get_bool", lambda _key, default=False: False)
    assert tor_circuits.requests_proxy_url() == "socks5h://127.0.0.1:9050"


def test_newnym_rotation_is_bounded_by_count_and_time(monkeypatch):
    tor_circuits.reset_rotation_state_for_tests()
    monkeypatch.setattr(tor_circuits, "get_bool", lambda key, default=False: key in {
        "TOR_SOCKS_ISOLATION", "TOR_NEWNYM_ENABLED"})
    monkeypatch.setattr(tor_circuits, "get_int", lambda key, default: {
        "TOR_NEWNYM_EVERY_REQUESTS": 2,
        "TOR_NEWNYM_INTERVAL_SECONDS": 900,
        "TOR_NEWNYM_MIN_INTERVAL_SECONDS": 600,
    }.get(key, default))
    signals = []
    monkeypatch.setattr(tor_circuits, "_signal_newnym", lambda: signals.append(True) or True)

    assert tor_circuits.prepare_fetch_circuit(now=100)["newnym_requested"] is False
    assert tor_circuits.prepare_fetch_circuit(now=700)["newnym_requested"] is True
    assert tor_circuits.prepare_fetch_circuit(now=701)["newnym_requested"] is False
    assert tor_circuits.prepare_fetch_circuit(now=1299)["newnym_requested"] is False
    assert tor_circuits.prepare_fetch_circuit(now=1300)["newnym_requested"] is False
    assert tor_circuits.prepare_fetch_circuit(now=1600)["newnym_requested"] is True
    assert len(signals) == 2


def test_newnym_can_be_time_based_without_request_count_rotation(monkeypatch):
    tor_circuits.reset_rotation_state_for_tests()
    monkeypatch.setattr(tor_circuits, "get_bool", lambda key, default=False: key == "TOR_NEWNYM_ENABLED")
    monkeypatch.setattr(tor_circuits, "get_int", lambda key, default: {
        "TOR_NEWNYM_EVERY_REQUESTS": 0,
        "TOR_NEWNYM_INTERVAL_SECONDS": 900,
        "TOR_NEWNYM_MIN_INTERVAL_SECONDS": 600,
    }.get(key, default))
    signals = []
    monkeypatch.setattr(tor_circuits, "_signal_newnym", lambda: signals.append(True) or True)

    assert tor_circuits.prepare_fetch_circuit(now=100)["newnym_requested"] is False
    assert tor_circuits.prepare_fetch_circuit(now=999)["newnym_requested"] is False
    assert tor_circuits.prepare_fetch_circuit(now=1000)["newnym_requested"] is True
    assert len(signals) == 1


def test_worker_builds_each_fetch_session_with_a_new_proxy_identity(monkeypatch):
    proxies = iter(["socks5h://one:one@127.0.0.1:9050", "socks5h://two:two@127.0.0.1:9050"])
    monkeypatch.setattr(onion_worker, "prepare_fetch_circuit", lambda: {})
    monkeypatch.setattr(onion_worker, "requests_proxy_url", lambda: next(proxies))
    first = onion_worker._session()
    second = onion_worker._session()
    assert first.proxies["http"] != second.proxies["http"]
    assert first.proxies["https"] == first.proxies["http"]
