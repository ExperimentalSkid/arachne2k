"""
LLM-based content classifier with conversational context (patch 19).
Uses Ollama (Qwen3 8B by default). Multilingual, JSON-structured output.
"""
import json
import time
import logging
import re
import urllib.request
import urllib.error

log = logging.getLogger("llm_classifier")

# ── Config ────────────────────────────────────────────────────────────
LLM_ENABLED = True
LLM_MODEL = "qwen3:8b"
LLM_ENDPOINT = "http://localhost:11434/api/chat"
LLM_TIMEOUT_S = 20           # bumped slightly for longer context prompts
LLM_NUM_PREDICT = 220
LLM_TEMPERATURE = 0.1

CATEGORIES = [
    "violence",
    "weapons",
    "terrorism",
    "hate_speech",
    "cyber_attack",
    "illegal_activity",
    "drugs",
    "extremism",
    "infrastructure_threat",
    "none",
]

SYSTEM_PROMPT = (
    "You are a multilingual content safety classifier for Telegram messages "
    "processed in a private research and monitoring workspace. "
    "Languages encountered include Spanish, English, Russian, Arabic, French. "
    "You may receive recent conversation context and the user's recent "
    "flagged-message history before the message to classify. Use that "
    "context to judge intent, escalation, sarcasm, and reaction-to-event vs "
    "announcement-of-intent. Classify ONLY the LATEST message — context is "
    "for grounding, not for separate scoring.\n\n"
    "Output ONLY valid JSON, no markdown fences, no preamble, no chain-of-thought. "
    "Schema (all keys required):\n"
    '{"severity": <float 0.0-1.0>, '
    '"category": <one of: ' + ", ".join(CATEGORIES) + '>, '
    '"flagged": <true|false>, '
    '"reasoning": <one short sentence in the message language>}\n\n'
    "Severity scale:\n"
    "  0.0-0.2 = clearly safe / benign / academic / news / sports context\n"
    "  0.2-0.4 = suspicious wording but ambiguous (sarcasm, gaming, venting possible)\n"
    "  0.4-0.6 = concerning but not actionable (rhetoric, complaints, edgy humor)\n"
    "  0.6-0.8 = clear hostile intent or planning language\n"
    "  0.8-1.0 = explicit threat, recruitment, operational coordination\n\n"
    "Set flagged=true only when severity >= 0.4. "
    "Treat news quotes, academic discussion, and sports rivalry as safe. "
    "When the conversation context shows a user reacting to a real-world event "
    "(arrest, news, match result) without expressing intent, lean toward safe."
)


def _extract_json(raw: str):
    if not raw:
        return None
    raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL)
    raw = re.sub(r"```(?:json)?\s*", "", raw)
    raw = raw.replace("```", "").strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    return None


def _normalize(verdict):
    out = {"severity": 0.0, "category": "none", "flagged": False, "reasoning": ""}
    if not isinstance(verdict, dict):
        return out
    try:
        sev = float(verdict.get("severity", 0.0))
        out["severity"] = max(0.0, min(1.0, sev))
    except (TypeError, ValueError):
        pass
    cat = str(verdict.get("category", "none")).lower().strip()
    out["category"] = cat if cat in CATEGORIES else "none"
    flg = verdict.get("flagged", False)
    if isinstance(flg, str):
        flg = flg.lower() in ("true", "1", "yes", "si", "sí")
    out["flagged"] = bool(flg)
    out["reasoning"] = str(verdict.get("reasoning", ""))[:500]
    return out


def _format_context_block(recent_chat, user_history, chat_title):
    """Build the context preamble for the user message."""
    lines = []
    if chat_title:
        lines.append(f"[Chat: {chat_title}]")
    if recent_chat:
        lines.append("\nRecent messages in this chat (oldest first):")
        for m in recent_chat:
            ts = (m.get("ts") or "")[:19].replace("T", " ")
            user = m.get("user") or "?"
            text = (m.get("text") or "").replace("\n", " ")[:200]
            lines.append(f"  [{ts}] @{user}: {text}")
    if user_history:
        lines.append("\nThis user's recent flagged messages in this chat:")
        for m in user_history:
            ts = (m.get("ts") or "")[:19].replace("T", " ")
            text = (m.get("text") or "").replace("\n", " ")[:200]
            lines.append(f"  [{ts}] {text}")
    if lines:
        lines.append("\nLatest message to classify:")
    return "\n".join(lines)


def classify(text: str, context_hint: str = "",
             recent_chat: list = None, user_history: list = None) -> dict:
    """
    Classify a single message, optionally with conversational context.

    Args:
        text: the message to classify
        context_hint: chat title / brief framing string (legacy)
        recent_chat: list of dicts {ts, user, text} — last N messages in chat
        user_history: list of dicts {ts, text} — user's recent flagged msgs

    Returns:
        verdict dict with severity, category, flagged, reasoning, model,
        latency_ms, error, plus context_used (int count of context items).
    """
    started = time.time()
    base = {
        "severity": 0.0, "category": "none", "flagged": False, "reasoning": "",
        "model": LLM_MODEL, "latency_ms": 0, "error": None,
        "context_used": 0,
    }
    if not LLM_ENABLED:
        base["error"] = "llm_disabled"
        return base
    if not text or not text.strip():
        base["error"] = "empty_text"
        return base

    recent_chat = recent_chat or []
    user_history = user_history or []
    base["context_used"] = len(recent_chat) + len(user_history)

    ctx_block = _format_context_block(recent_chat, user_history, context_hint)
    if ctx_block:
        user_content = f"{ctx_block}\n{text.strip()}"
    else:
        user_content = text.strip()

    payload = {
        "model": LLM_MODEL,
        "stream": False,
        "think": False,
        "options": {"temperature": LLM_TEMPERATURE, "num_predict": LLM_NUM_PREDICT},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
    }
    try:
        req = urllib.request.Request(
            LLM_ENDPOINT,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=LLM_TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        raw = (data.get("message") or {}).get("content", "")
        verdict = _extract_json(raw)
        if verdict is None:
            base["error"] = f"json_parse_failed: {raw[:120]!r}"
            base["latency_ms"] = int((time.time() - started) * 1000)
            return base
        base.update(_normalize(verdict))
        base["latency_ms"] = int((time.time() - started) * 1000)
        return base
    except urllib.error.URLError as e:
        base["error"] = f"http_error: {e}"
    except (TimeoutError, ConnectionError) as e:
        base["error"] = f"timeout: {e}"
    except Exception as e:
        base["error"] = f"unexpected: {type(e).__name__}: {e}"
    base["latency_ms"] = int((time.time() - started) * 1000)
    return base


if __name__ == "__main__":
    print("─── No-context test ───")
    v = classify("Tenemos que actuar contra el enemigo, ya es hora")
    print(f"  severity={v['severity']:.2f} category={v['category']} "
          f"flagged={v['flagged']} latency={v['latency_ms']}ms ctx={v['context_used']}")
    print(f"  reasoning: {v['reasoning']}")

    print("\n─── With sports context (should be SAFE) ───")
    ctx = [
        {"ts": "2026-05-03T01:00:00", "user": "fan1", "text": "qué partido más malo"},
        {"ts": "2026-05-03T01:01:00", "user": "fan2", "text": "el árbitro nos robó otra vez"},
        {"ts": "2026-05-03T01:02:00", "user": "fan3", "text": "el equipo enemigo siempre tiene suerte"},
    ]
    v = classify("Tenemos que actuar contra el enemigo, ya es hora",
                 context_hint="Fútbol Sevilla FC",
                 recent_chat=ctx)
    print(f"  severity={v['severity']:.2f} category={v['category']} "
          f"flagged={v['flagged']} latency={v['latency_ms']}ms ctx={v['context_used']}")
    print(f"  reasoning: {v['reasoning']}")

    print("\n─── With escalation context (should be FLAGGED HIGHER) ───")
    ctx = [
        {"ts": "2026-05-03T01:00:00", "user": "u1", "text": "ya basta de aguantar"},
        {"ts": "2026-05-03T01:01:00", "user": "u2", "text": "estamos preparados"},
        {"ts": "2026-05-03T01:02:00", "user": "u1", "text": "esta semana es la buena"},
    ]
    user_hist = [
        {"ts": "2026-05-02T22:00:00", "text": "necesitamos armas"},
    ]
    v = classify("Tenemos que actuar contra el enemigo, ya es hora",
                 context_hint="Grupo X",
                 recent_chat=ctx, user_history=user_hist)
    print(f"  severity={v['severity']:.2f} category={v['category']} "
          f"flagged={v['flagged']} latency={v['latency_ms']}ms ctx={v['context_used']}")
    print(f"  reasoning: {v['reasoning']}")
