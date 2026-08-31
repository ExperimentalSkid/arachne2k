"""
OCR helper for the arachne bot (patch 20).

Extracts text from image attachments using Tesseract.
Returns extracted text + a confidence-ish heuristic.

Designed to fail gracefully — never raises, always returns a dict.
"""
import os
import logging
import time

from log_redaction import redact_for_log

log = logging.getLogger("image_ocr")

# ── Config ────────────────────────────────────────────────────────────
OCR_ENABLED = True
OCR_LANGS = "spa+eng+ita+por+ron+cat+rus+ara+fra"   # only langs actually installed will be used
OCR_TIMEOUT_S = 30
OCR_MIN_CHARS = 8                    # below this, treat as "no useful text"
OCR_MAX_BYTES = 20 * 1024 * 1024     # skip files >20MB
OCR_MAX_DIMENSION = 4000             # downscale anything larger to keep runtime sane

_AVAILABLE_LANGS_CACHE = None


def _available_langs():
    """Filter OCR_LANGS down to what's actually installed in tessdata."""
    global _AVAILABLE_LANGS_CACHE
    if _AVAILABLE_LANGS_CACHE is not None:
        return _AVAILABLE_LANGS_CACHE
    try:
        import pytesseract
        installed = set(pytesseract.get_languages(config=""))
    except Exception as exc:
        log.warning("Could not enumerate Tesseract languages: %s", redact_for_log(exc))
        installed = {"eng"}
    requested = OCR_LANGS.split("+")
    filtered = [l for l in requested if l in installed]
    if not filtered:
        filtered = ["eng"]
    _AVAILABLE_LANGS_CACHE = "+".join(filtered)
    return _AVAILABLE_LANGS_CACHE


def extract_text(image_path: str) -> dict:
    """
    OCR an image file. Returns:
      {
        "text": str,         # extracted text (empty if nothing useful)
        "lang": str,         # langs used (e.g. "spa+eng")
        "chars": int,        # length of extracted text
        "latency_ms": int,
        "skipped": str|None, # reason if we skipped (size, format, error)
        "error": str|None,
      }
    """
    started = time.time()
    out = {"text": "", "lang": "", "chars": 0, "latency_ms": 0,
           "skipped": None, "error": None}
    img = None

    if not OCR_ENABLED:
        out["skipped"] = "ocr_disabled"
        return out

    try:
        if not os.path.exists(image_path):
            out["skipped"] = "file_not_found"
            return out
        size = os.path.getsize(image_path)
        if size == 0:
            out["skipped"] = "empty_file"
            return out
        if size > OCR_MAX_BYTES:
            out["skipped"] = f"file_too_large_{size}"
            return out

        from PIL import Image
        try:
            with Image.open(image_path) as source_image:
                source_image.load()  # force decode while the file handle is owned
                img = source_image.copy()
        except Exception as exc:
            out["skipped"] = f"pil_open_failed:{type(exc).__name__}"
            return out

        # Convert exotic modes to RGB for tesseract sanity
        if img.mode not in ("RGB", "L"):
            try:
                img = img.convert("RGB")
            except Exception:
                pass

        # Downscale if huge (keeps memory + runtime in check)
        if max(img.size) > OCR_MAX_DIMENSION:
            ratio = OCR_MAX_DIMENSION / max(img.size)
            new_size = (int(img.size[0] * ratio), int(img.size[1] * ratio))
            try:
                img = img.resize(new_size, Image.LANCZOS)
            except Exception:
                pass

        import pytesseract
        langs = _available_langs()
        out["lang"] = langs

        try:
            text = pytesseract.image_to_string(
                img, lang=langs, timeout=OCR_TIMEOUT_S
            )
        except RuntimeError as exc:
            out["error"] = f"tesseract_runtime:{type(exc).__name__}"
            out["latency_ms"] = int((time.time() - started) * 1000)
            return out
        except Exception as exc:
            out["error"] = f"tesseract_failed:{type(exc).__name__}"
            out["latency_ms"] = int((time.time() - started) * 1000)
            return out

        text = (text or "").strip()
        # Collapse runs of whitespace; tesseract is noisy
        text = " ".join(text.split())
        out["text"] = text
        out["chars"] = len(text)
        out["latency_ms"] = int((time.time() - started) * 1000)

        if out["chars"] < OCR_MIN_CHARS:
            out["skipped"] = f"too_short_{out['chars']}_chars"
        return out

    except Exception as exc:
        out["error"] = f"unexpected:{type(exc).__name__}"
        out["latency_ms"] = int((time.time() - started) * 1000)
        return out
    finally:
        if img is not None:
            try:
                img.close()
            except (AttributeError, OSError):
                pass


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python3 image_ocr.py <image_path>")
        sys.exit(1)
    r = extract_text(sys.argv[1])
    print(f"lang:       {r['lang']}")
    print(f"chars:      {r['chars']}")
    print(f"latency_ms: {r['latency_ms']}")
    print(f"skipped:    {r['skipped']}")
    print(f"error:      {r['error']}")
    print("--- text ---")
    print(r["text"][:2000])
