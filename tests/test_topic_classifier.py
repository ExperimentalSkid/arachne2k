from topic_classifier import extract_page_topics


def test_extracts_adult_and_carding_topics_without_full_text_storage():
    result = extract_page_topics("Adult porn index. Carding and CVV discussion. carding resources.")
    assert "Adult content" in result["topics"]
    assert "Payment-card fraud / carding" in result["topics"]
    assert "porn" in result["keywords"] and "carding" in result["keywords"]


def test_keywords_require_repetition_unless_they_are_topic_terms():
    result = extract_page_topics("ordinary repeated repeated useful useful isolatedword")
    assert "repeated" in result["keywords"] and "useful" in result["keywords"]
    assert "isolatedword" not in result["keywords"]

