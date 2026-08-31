from safety_policy import is_fetch_allowed, is_onion_url, normalize_url

ONION = "a" * 56 + ".onion"


def test_valid_onion_and_non_onion_rejection():
    assert is_onion_url(f"http://{ONION}/")
    assert not is_fetch_allowed("https://example.com/")[0]


def test_blocked_relative_fragment_query_and_malformed():
    assert normalize_url("/file.zip", f"http://{ONION}/") is None
    assert normalize_url("/page?q=1#frag", f"http://{ONION}/") == f"http://{ONION}/page?q=1"
    assert normalize_url("not a url") is None

