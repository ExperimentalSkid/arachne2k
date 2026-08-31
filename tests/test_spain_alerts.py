from spain_alerts import format_spain_alert


def test_alert_is_safe_and_points_to_dashboard():
    payload = {
        "category": "leaks_data", "risk_level": "high", "language": "ES",
        "reason": "Spain reference paired with threat-related context",
        "url": "http://" + "a" * 56 + ".onion/", "source_url": "manual",
        "restricted": True,
    }
    message = format_spain_alert(payload)
    assert "SPAIN PRIORITY ALERT" in message
    assert "Spain Priority" in message
    assert "No preview/snippet/screenshot" in message
    assert "page_text" not in message

