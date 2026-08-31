"""Shared, config-driven scoring for Telegram and passive page collection."""
from __future__ import annotations

import json
import logging
import re

from paths import KEYWORDS_CONFIG_PATH, SCORING_CONFIG_PATH

LOGGER = logging.getLogger(__name__)
FLAGS = re.IGNORECASE | re.UNICODE
COMPILED_CATEGORIES: dict = {}
COOCCURRENCE_RULES: list[dict] = []

_DEFAULT_SCORING = {
    "thresholds": {"risk_bajo": 3, "risk_medio": 6, "risk_alto": 10, "risk_critico": 15}
}


def _load_scoring() -> dict:
    try:
        return json.loads(SCORING_CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _DEFAULT_SCORING


SCORING = _load_scoring()


def _compile_lang_patterns(patterns, no_word_boundary=False):
    if not patterns:
        return None
    valid = []
    for pattern in patterns:
        try:
            re.compile(pattern, FLAGS)
            valid.append(pattern)
        except re.error:
            LOGGER.warning("Invalid keyword pattern skipped")
    if not valid:
        return None
    body = "|".join(valid)
    return re.compile(body if no_word_boundary else r"\b(?:" + body + r")\b", FLAGS)


def load_keywords_config() -> bool:
    global COMPILED_CATEGORIES, COOCCURRENCE_RULES
    try:
        cfg = json.loads(KEYWORDS_CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        LOGGER.error("Cannot load keyword configuration: %s", type(exc).__name__)
        return False
    categories = {}
    for name, data in cfg.get("categories", {}).items():
        nwb = bool(data.get("no_word_boundary", False))
        categories[name] = {
            "tier": data.get("tier", 2), "weight": data.get("weight", 0),
            "description": data.get("description", ""), "no_word_boundary": nwb,
            "compiled_en": _compile_lang_patterns(data.get("patterns_en", []), nwb),
            "compiled_es": _compile_lang_patterns(data.get("patterns_es", []), nwb),
            "compiled_ru": _compile_lang_patterns(data.get("patterns_ru", []), nwb),
            "raw_en": list(data.get("patterns_en", [])),
            "raw_es": list(data.get("patterns_es", [])),
            "raw_ru": list(data.get("patterns_ru", [])),
        }
    COMPILED_CATEGORIES = categories
    COOCCURRENCE_RULES = list(cfg.get("cooccurrence_rules", []))
    return True


def detect_lang_cheap(text):
    if not text:
        return "unknown"
    has_cyrillic = bool(re.search(r"[\u0400-\u04FF]", text))
    lowered = text.lower()
    has_es = bool(re.search(r"[ñáéíóúü¿¡]", lowered)) or bool(
        re.search(r"\b(que|los|las|para|esta|este|hay|con|una|por|del)\b", lowered)
    )
    if has_cyrillic and not has_es:
        return "ru"
    return "es" if has_es else "en"


def score_text(text: str) -> tuple[int, list[str]]:
    lang = detect_lang_cheap(text)
    score, reasons, matched = 0, [], set()
    for name, category in COMPILED_CATEGORIES.items():
        if any(category.get(k) and category[k].search(text or "") for k in ("compiled_en", "compiled_es", "compiled_ru")):
            matched.add(name)
            score += int(category["weight"])
            reasons.append(name.lower())
    for rule in COOCCURRENCE_RULES:
        if matched & set(rule.get("requires_any_of", [])) and matched & set(rule.get("with_any_of", [])):
            score += int(rule.get("bonus", 0))
            reasons.append(rule.get("tag", "cooccur"))
    if lang != "unknown":
        reasons.append(f"lang:{lang}")
    return score, reasons


def risk_level(score: int) -> str:
    thresholds = SCORING.get("thresholds", _DEFAULT_SCORING["thresholds"])
    if score >= thresholds.get("risk_critico", 15): return "CRITICO"
    if score >= thresholds.get("risk_alto", 10): return "ALTO"
    if score >= thresholds.get("risk_medio", 6): return "MEDIO"
    if score >= thresholds.get("risk_bajo", 3): return "BAJO"
    return "NULO"


load_keywords_config()

