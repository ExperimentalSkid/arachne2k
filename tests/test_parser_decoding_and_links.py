import onion_worker


HOST = "p" * 56 + ".onion"
BASE_URL = f"http://{HOST}/index"


def test_http_charset_is_used_before_conflicting_html_meta():
    html = (
        '<html><head><meta charset="utf-8"><title>Caf\u00e9 Espa\u00f1a</title></head>'
        '<body><h1>Informaci\u00f3n</h1></body></html>'
    ).encode("cp1252")

    title, _meta, text, _records, structure = onion_worker._parse(
        html, 'text/html; Charset="windows-1252"', BASE_URL)

    assert title == "Caf\u00e9 Espa\u00f1a"
    assert "Informaci\u00f3n" in text
    assert structure["decoding_charset"] == "cp1252"
    assert structure["decoding_source"] == "http_header"
    assert structure["decoding"]["fallback_used"] is False


def test_invalid_http_charset_falls_through_to_bounded_html_meta():
    html = (
        '<html><head><meta http-equiv="Content-Type" '
        'content="text/html; charset=windows-1252"><title>Foro Espa\u00f1ol</title></head>'
        '<body>Secci\u00f3n p\u00fablica</body></html>'
    ).encode("cp1252")

    title, _meta, text, _records, structure = onion_worker._parse(
        html, "text/html; charset=not-a-real-codec", BASE_URL)

    assert title == "Foro Espa\u00f1ol"
    assert "Secci\u00f3n p\u00fablica" in text
    assert structure["decoding_source"] == "html_meta"
    assert structure["decoding"]["http_charset_declared"] is True
    assert structure["decoding"]["http_charset_valid"] is False
    assert structure["decoding"]["meta_charset_valid"] is True


def test_bom_then_fixed_fallbacks_are_deterministic():
    utf16_html = "<html><head><title>Sevilla</title></head><body>Espa\u00f1a</body></html>".encode("utf-16")
    title, _meta, text, _records, structure = onion_worker._parse(
        utf16_html, "text/html", BASE_URL)
    assert title == "Sevilla"
    assert "Espa\u00f1a" in text
    assert structure["decoding_source"] == "byte_order_mark"
    assert structure["decoding"]["bom_present"] is True

    cp1252_html = "<html><body>Caf\u00e9 en M\u00e1laga</body></html>".encode("cp1252")
    _title, _meta, text, _records, structure = onion_worker._parse(
        cp1252_html, "text/html", BASE_URL)
    assert "Caf\u00e9 en M\u00e1laga" in text
    assert structure["decoding_charset"] == "cp1252"
    assert structure["decoding_source"] == "fallback_windows_1252"


def test_plain_text_uses_same_bounded_decoder_without_html_meta_sniffing():
    body = "Texto espa\u00f1ol: informaci\u00f3n".encode("iso-8859-1")

    _title, _meta, text, records, structure = onion_worker._parse(
        body, "text/plain; charset=iso-8859-1", BASE_URL)

    assert text == "Texto espa\u00f1ol: informaci\u00f3n"
    assert records == []
    assert structure["decoding_source"] == "http_header"
    assert structure["decoding"]["meta_charset_declared"] is False


def test_repeated_normalized_links_keep_bounded_context_observations():
    repeated = []
    for index in range(12):
        repeated.append(
            f'<h2>Section {index}</h2><a href="/thread/42#post-{index}">Label {index}</a>'
        )
    html = ("<html><body>" + "".join(repeated) + "</body></html>").encode("utf-8")

    _title, _meta, _text, records, structure = onion_worker._parse(
        html, "text/html; charset=utf-8", BASE_URL)

    assert len(records) == 1
    record = records[0]
    assert record["url"] == f"http://{HOST}/thread/42"
    assert record["anchor_text"] == "Label 0"
    assert record["section_context"] == "Section 0"
    assert record["occurrence_count"] == 12
    assert record["anchor_texts"] == [f"Label {index}" for index in range(8)]
    assert record["section_contexts"] == [f"Section {index}" for index in range(8)]
    assert record["context_observations"] == [
        {"anchor_text": f"Label {index}", "section_context": f"Section {index}"}
        for index in range(8)
    ]
    assert structure["link_observation_count"] == 12
    assert structure["unique_link_count"] == 1
    assert structure["duplicate_link_observation_count"] == 11


def test_repeated_link_context_lists_are_unique_and_legacy_keys_remain_first():
    html = b"""<html><body>
      <h2>Forum</h2><a href='/topic'>Open topic</a>
      <a href='/topic#latest'>Open topic</a>
      <h2>Spain</h2><a href='/topic'>Spain discussion</a>
    </body></html>"""

    _title, _meta, _text, records, _structure = onion_worker._parse(
        html, "text/html", BASE_URL)

    assert records == [{
        "url": f"http://{HOST}/topic",
        "anchor_text": "Open topic",
        "section_context": "Forum",
        "occurrence_count": 3,
        "anchor_texts": ["Open topic", "Spain discussion"],
        "section_contexts": ["Forum", "Spain"],
        "context_observations": [
            {"anchor_text": "Open topic", "section_context": "Forum"},
            {"anchor_text": "Spain discussion", "section_context": "Spain"},
        ],
    }]
