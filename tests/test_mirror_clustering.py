from mirror_logger import calculate_cluster_similarity


def cluster(**url):
    return {"urls": [url], "shared_indicators": url.get("indicators", [])}


def test_similarity_signals_and_threshold():
    assert calculate_cluster_similarity(cluster(content_hash="x"), {"content_hash":"x"}) == 1.0
    existing = {"urls": [{}], "shared_indicators": ["telegram_handle:@same"]}
    assert calculate_cluster_similarity(existing, {"indicators":[{"type":"telegram_handle","normalized_value":"@same"}]}) >= .75
    existing["shared_indicators"] = ["wallet_btc:abc"]
    assert calculate_cluster_similarity(existing, {"indicators":[{"type":"wallet_btc","normalized_value":"abc"}]}) >= .75
    assert calculate_cluster_similarity({"urls":[{"title":"a"}],"shared_indicators":[]}, {"title":"b","indicators":[]}) < .75

