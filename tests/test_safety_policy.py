from safety_policy import classify_risk_flags, is_content_type_allowed, is_fetch_allowed, make_safe_snippet, redact_sensitive

ONION = "http://" + "a" * 56 + ".onion"


def test_extensions_and_content_types():
    for ext in (".zip", ".pdf", ".exe", ".jpg"):
        assert not is_fetch_allowed(ONION + "/x" + ext)[0]
    assert is_content_type_allowed("text/html; charset=utf-8")
    assert not is_content_type_allowed("application/octet-stream")


def test_snippet_flags_and_redaction():
    assert len(make_safe_snippet("x" * 100, max_chars=20)) <= 20
    assert "download_heavy_page" in classify_risk_flags("full dump", [ONION + f"/{i}.zip" for i in range(5)])
    redacted = redact_sensitive("password=hunter2 api_key=abcdefghijk token=abcdefghijk Cookie: sid=123")
    assert "hunter2" not in redacted and "abcdefghijk" not in redacted
    assert "REDACTED" in redact_sensitive("username=a password=b")

