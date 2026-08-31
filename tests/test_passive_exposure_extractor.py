from passive_exposure_extractor import extract_passive_exposures


def test_extracts_only_supplied_response_data():
    onion = "http://" + "a" * 56 + ".onion/"
    text = "Traceback (most recent call last) at C:\\srv\\app\\main.py Index of / password=hunter2 api_key=abcdefghijk"
    result = extract_passive_exposures(onion, 500, {"Server":"nginx/1.2", "X-Powered-By":"PHP/8"}, "Error", text,
                                       ["https://example.com/a", onion + "mirror"])
    kinds = {item["type"] for item in result}
    assert {"server_header", "powered_by_header", "stack_trace", "absolute_path_disclosure",
            "directory_listing_visible", "clearnet_link_visible", "onion_link_visible"} <= kinds
    rendered = str(result)
    assert "hunter2" not in rendered and "abcdefghijk" not in rendered

