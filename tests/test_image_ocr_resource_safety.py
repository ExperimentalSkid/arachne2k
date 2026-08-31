import image_ocr


def test_ocr_closes_source_and_working_images(tmp_path, monkeypatch):
    image_path = tmp_path / "sample.png"
    image_path.write_bytes(b"not-decoded-because-open-is-faked")
    state = {"source_closed": False, "working_closed": False}

    class WorkingImage:
        mode = "RGB"
        size = (320, 200)

        def close(self):
            state["working_closed"] = True

    class SourceImage:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            state["source_closed"] = True

        def load(self):
            return None

        def copy(self):
            return WorkingImage()

    from PIL import Image
    import pytesseract

    monkeypatch.setattr(Image, "open", lambda _path: SourceImage())
    monkeypatch.setattr(pytesseract, "get_languages", lambda config="": ["eng"])
    monkeypatch.setattr(pytesseract, "image_to_string", lambda *_args, **_kwargs: "safe extracted text")
    monkeypatch.setattr(image_ocr, "_AVAILABLE_LANGS_CACHE", None)

    result = image_ocr.extract_text(str(image_path))

    assert result["text"] == "safe extracted text"
    assert state == {"source_closed": True, "working_closed": True}


def test_ocr_error_details_do_not_echo_dependency_message(tmp_path, monkeypatch):
    image_path = tmp_path / "sample.png"
    image_path.write_bytes(b"placeholder")

    class WorkingImage:
        mode = "RGB"
        size = (320, 200)

        def close(self):
            return None

    class SourceImage:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def load(self):
            return None

        def copy(self):
            return WorkingImage()

    from PIL import Image
    import pytesseract

    monkeypatch.setattr(Image, "open", lambda _path: SourceImage())
    monkeypatch.setattr(pytesseract, "get_languages", lambda config="": ["eng"])
    monkeypatch.setattr(
        pytesseract,
        "image_to_string",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("secret path and hostile OCR text")),
    )
    monkeypatch.setattr(image_ocr, "_AVAILABLE_LANGS_CACHE", None)

    result = image_ocr.extract_text(str(image_path))

    assert result["error"] == "tesseract_runtime:RuntimeError"
    assert "secret path" not in result["error"]
