from category_mapper import classify_url_category


def test_legacy_mapper_refuses_to_infer_from_untrusted_arguments():
    assert classify_url_category("http://example.onion/directory", "Onion links", []) == "Unknown / Miscellaneous"
    assert classify_url_category("http://example.onion/", "Victim list", ["leaks_extortion"]) == "Unknown / Miscellaneous"
    assert classify_url_category("http://example.onion/forum", None, []) == "Unknown / Miscellaneous"
    assert classify_url_category("http://example.onion/", None, [], "recruitment") == "Unknown / Miscellaneous"
    assert classify_url_category("http://example.onion/", None, []) == "Unknown / Miscellaneous"
