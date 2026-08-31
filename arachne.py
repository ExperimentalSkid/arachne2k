import re
import sqlite3
import threading
import logging
import asyncio
from contextlib import contextmanager
from log_redaction import redact_for_log
try:
    from llm_classifier import classify as llm_classify
    _LLM_AVAILABLE = True
except Exception as _e:
    _LLM_AVAILABLE = False
    import logging as _lg
    _lg.getLogger('arachne').warning('LLM classifier unavailable: %s', redact_for_log(_e))
try:
    from image_ocr import extract_text as _ocr_extract_text
    _OCR_AVAILABLE = True
except Exception as _e:
    _OCR_AVAILABLE = False
    import logging as _lg
    _lg.getLogger('arachne').warning('OCR module unavailable: %s', redact_for_log(_e))
_p20_ocr_helpers = True
import json
import os
from datetime import datetime, timezone, timedelta
from config_loader import get_bool, get_int, get_str
from paths import BASE_DIR, CONFIG_PATH, DB_PATH, KEYWORDS_CONFIG_PATH, REPORTS_DIR, SCORING_CONFIG_PATH, SESSIONS_DIR
import storage as osint_storage
import dashboard_auth
import operational_observability as operations

# ML models are loaded lazily on the first suspicious message. This keeps module
# imports and administrative commands safe when the optional ML runtime is absent.
sentiment_model = None
hate_model = None
_ML_LOAD_ATTEMPTED = False


def _ensure_ml_models():
    global sentiment_model, hate_model, _ML_LOAD_ATTEMPTED
    if _ML_LOAD_ATTEMPTED:
        return sentiment_model is not None and hate_model is not None
    _ML_LOAD_ATTEMPTED = True
    try:
        from transformers import pipeline
        sentiment_model = pipeline(
            "sentiment-analysis", model="cardiffnlp/twitter-xlm-roberta-base-sentiment", device=-1
        )
        hate_model = pipeline(
            "text-classification", model="Hate-speech-CNERG/dehatebert-mono-spanish", device=-1
        )
        return True
    except Exception as exc:
        logging.getLogger("arachne").warning("Optional ML models unavailable: %s", type(exc).__name__)
        return False

def analyze_ml(text: str):
    """Returns (polarity, intensity, hate_prob, sent_label). Only call on suspicious text."""
    if not _ensure_ml_models():
        return 0, 0.0, 0.0, "unavailable"
    text = text[:512]
    try:
        sent = sentiment_model(text)[0]
        polarity_map = {"positive": 1, "neutral": 0, "negative": -1}
        polarity = polarity_map.get(sent["label"].lower(), 0)
        intensity = round(sent["score"], 3)

        hate = hate_model(text)[0]
        label = hate["label"].lower()
        if "1" in label or "hate" in label:
            hate_prob = round(hate["score"], 3)
        else:
            hate_prob = round(1 - hate["score"], 3)

        return polarity, intensity, hate_prob, sent["label"]
    except Exception:
        return 0, 0.0, 0.0, "error"


# ==========================================
# 1. CREDENTIALS & IDs
# ==========================================
_telegram_api_id_configured = get_int("TELEGRAM_API_ID", 0)
_telegram_api_hash_configured = get_str("TELEGRAM_API_HASH", "") or ""
api_id = _telegram_api_id_configured or 1
api_hash = _telegram_api_hash_configured or ("0" * 32)
bot_token = get_str("TELEGRAM_BOT_TOKEN", "") or ""
admin_chat_id = get_int("ADMIN_CHAT_ID", 0)
TELEGRAM_MANUAL_PULL_ONLY = get_bool("TELEGRAM_MANUAL_PULL_ONLY", True)
TELEGRAM_AUTO_ALERTS_ENABLED = get_bool("TELEGRAM_AUTO_ALERTS_ENABLED", False)


def _configured_telegram_admin_ids() -> set[int]:
    configured = get_str("TELEGRAM_ADMIN_IDS", "") or ""
    placeholder_ids = {"0", "12345", "6789", "67890"}
    ids: set[int] = set()
    for part in configured.replace(";", ",").split(","):
        part = part.strip()
        if part.lstrip("-").isdigit() and part not in placeholder_ids:
            ids.add(int(part))
    return ids


if not admin_chat_id:
    _admin_id_fallbacks = sorted(_configured_telegram_admin_ids())
    if _admin_id_fallbacks:
        admin_chat_id = _admin_id_fallbacks[0]


def _telegram_admin_ids() -> set[int]:
    ids = {admin_chat_id} if admin_chat_id else set()
    ids.update(_configured_telegram_admin_ids())
    return ids


def _is_dashboard_admin(event) -> bool:
    sender_id = int(getattr(event, "sender_id", 0) or 0)
    allowed = _telegram_admin_ids()
    return sender_id in allowed


async def _require_dashboard_admin(event) -> bool:
    if _is_dashboard_admin(event):
        return True
    await event.respond("Not authorized.")
    return False


# Session-local chat authorization used only by the bot-added safety handler.
# Command and callback authorization always checks the sender dynamically via
# _telegram_admin_ids(), so changing configured admins does not require a restart.
ALLOWED_USERS = set(_telegram_admin_ids())
ALLOWED_CHATS = [admin_chat_id] if admin_chat_id else []

if __name__ == '__main__' and not (_telegram_api_id_configured and _telegram_api_hash_configured and bot_token and admin_chat_id):
    print("Telegram bot disabled: missing TELEGRAM/ADMIN credentials. Dashboard and staged workers are unaffected.")
    raise SystemExit(2)

try:
    from telethon import TelegramClient, events, Button
except ImportError:
    if __name__ == '__main__':
        print("Telegram bot cannot start: missing dependency 'telethon'. Install requirements.txt in the project venv.")
        raise SystemExit(1) from None
    raise

# Load externalized scoring config (editable without code changes)
try:
    with open(SCORING_CONFIG_PATH) as _f:
        SCORING = json.load(_f)
    print(f"[CONFIG] Loaded scoring config from {SCORING_CONFIG_PATH}")
except Exception as _e:
    print(f"[CONFIG] Could not load {SCORING_CONFIG_PATH}: {_e}")
    print("[CONFIG] Using fallback defaults.")
    SCORING = {
        "thresholds": {"risk_bajo": 3, "risk_medio": 6, "risk_alto": 10, "risk_critico": 15},
        "burst_detection": {"window_minutes": 10, "min_triggers": 3, "cooldown_minutes": 30},
        "escalation_detection": {"recent_window": 10, "older_window": 50, "min_ratio": 1.5},
        "user_risk_formula": {"avg_score_weight": 0.4, "trigger_rate_weight": 0.3,
                              "burst_factor_weight": 0.2, "group_factor_weight": 0.1},
        "classification_rules": {"agitator_recent_triggers_min": 3, "agitator_trigger_rate_min": 0.3,
                                 "bridge_groups_min": 2, "bridge_triggers_min": 3,
                                 "spammer_total_msgs_min": 50, "spammer_trigger_rate_max": 0.05,
                                 "active_trigger_rate_min": 0.2}
    }


DEFAULT_GROUPS: tuple[int, ...] = ()

# ─── Patch 19: conversational context config ──────────────────────────
CONTEXT_WINDOW = 5            # messages of recent chat history shown to LLM
USER_HISTORY_WINDOW = 3       # user's recent flagged msgs shown to LLM
CONTEXT_TABLE_MAX = 20        # rolling tail size kept per chat in DB
CONTEXT_TRIM_INTERVAL_S = 3600  # how often to trim chat_context (seconds)
_p19_context_helpers = True
# ──────────────────────────────────────────────────────────────────────

KEYWORDS_PATH = BASE_DIR / "custom_keywords.json"

# ==========================================
# 2. RUNTIME CONFIG
# ==========================================
def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return {"alert_threshold": 6, "active_groups": list(DEFAULT_GROUPS)}

def save_config(cfg):
    with open(CONFIG_PATH, 'w') as f:
        json.dump(cfg, f)

def load_custom_keywords():
    if os.path.exists(KEYWORDS_PATH):
        with open(KEYWORDS_PATH) as f:
            return json.load(f)
    return []

def save_custom_keywords(kws):
    with open(KEYWORDS_PATH, 'w') as f:
        json.dump(kws, f, ensure_ascii=False)

config = load_config()
custom_keywords = load_custom_keywords()

def build_custom_pattern():
    if not custom_keywords:
        return None
    escaped = [re.escape(k) for k in custom_keywords]
    return re.compile(r"\b(" + "|".join(escaped) + r")\b", re.IGNORECASE | re.UNICODE)

CUSTOM = build_custom_pattern()

# Track conversational state for multi-step menu actions
pending_action = {}  # {user_id: "add_keyword" | "remove_keyword" | "add_group" | "remove_group" | "set_threshold"}

# ==========================================
# 3. PATTERNS
# ==========================================
FLAGS = re.IGNORECASE | re.UNICODE

# ============================================================
# CONFIG-DRIVEN PATTERN ENGINE
# ============================================================

# Live, hot-swappable pattern registry
# Structure: { CATEGORY_NAME: { "tier": int, "weight": int, "compiled_en": Pattern|None,
#                               "compiled_es": Pattern|None, "compiled_ru": Pattern|None,
#                               "no_word_boundary": bool } }
COMPILED_CATEGORIES = {}
COOCCURRENCE_RULES = []

def _compile_lang_patterns(patterns, no_word_boundary=False):
    """Compile a list of regex fragments into one alternation pattern.
    Returns None if list is empty."""
    if not patterns:
        return None
    # Validate each pattern compiles standalone first
    valid = []
    for p in patterns:
        try:
            re.compile(p, FLAGS)
            valid.append(p)
        except re.error as e:
            print(f"[KW] Invalid pattern skipped: {type(e).__name__}")
    if not valid:
        return None
    body = "|".join(valid)
    full = body if no_word_boundary else r"\b(?:" + body + r")\b"
    try:
        return re.compile(full, FLAGS)
    except re.error as e:
        print(f"[KW] Failed to compile combined category pattern: {type(e).__name__}")
        return None

def load_keywords_config():
    """(Re)load keywords_config.json and recompile all categories.
    Hot-swappable: safe to call at runtime."""
    global COMPILED_CATEGORIES, COOCCURRENCE_RULES
    try:
        with open(KEYWORDS_CONFIG_PATH, encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        print(f"[KW] CRITICAL: keyword configuration unavailable: {type(e).__name__}")
        return False

    new_categories = {}
    for name, data in cfg.get("categories", {}).items():
        nwb = bool(data.get("no_word_boundary", False))
        new_categories[name] = {
            "tier": data.get("tier", 2),
            "weight": data.get("weight", 0),
            "description": data.get("description", ""),
            "no_word_boundary": nwb,
            "compiled_en": _compile_lang_patterns(data.get("patterns_en", []), nwb),
            "compiled_es": _compile_lang_patterns(data.get("patterns_es", []), nwb),
            "compiled_ru": _compile_lang_patterns(data.get("patterns_ru", []), nwb),
            "raw_en": list(data.get("patterns_en", [])),
            "raw_es": list(data.get("patterns_es", [])),
            "raw_ru": list(data.get("patterns_ru", [])),
        }

    new_rules = []
    for rule in cfg.get("cooccurrence_rules", []):
        new_rules.append({
            "requires_any_of": rule.get("requires_any_of", []),
            "with_any_of": rule.get("with_any_of", []),
            "bonus": rule.get("bonus", 0),
            "tag": rule.get("tag", "cooccur"),
        })

    COMPILED_CATEGORIES = new_categories
    COOCCURRENCE_RULES = new_rules

    n_cats = len(new_categories)
    n_pat = sum(len(c["raw_en"]) + len(c["raw_es"]) + len(c["raw_ru"])
                for c in new_categories.values())
    print(f"[KW] Loaded {n_cats} categories, {n_pat} patterns, {len(new_rules)} cooccurrence rules.")
    return True

def reload_one_category(category_name):
    """Recompile a single category from disk after edit. Used by menu add/remove."""
    try:
        with open(KEYWORDS_CONFIG_PATH, encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        print(f"[KW] category reload failed: {type(e).__name__}")
        return False
    data = cfg.get("categories", {}).get(category_name)
    if not data:
        print("[KW] reload_one_category: requested category not found")
        return False
    nwb = bool(data.get("no_word_boundary", False))
    COMPILED_CATEGORIES[category_name] = {
        "tier": data.get("tier", 2),
        "weight": data.get("weight", 0),
        "description": data.get("description", ""),
        "no_word_boundary": nwb,
        "compiled_en": _compile_lang_patterns(data.get("patterns_en", []), nwb),
        "compiled_es": _compile_lang_patterns(data.get("patterns_es", []), nwb),
        "compiled_ru": _compile_lang_patterns(data.get("patterns_ru", []), nwb),
        "raw_en": list(data.get("patterns_en", [])),
        "raw_es": list(data.get("patterns_es", [])),
        "raw_ru": list(data.get("patterns_ru", [])),
    }
    try:
        from scoring_engine import load_keywords_config as _reload_shared_scoring
        _reload_shared_scoring()
    except Exception:
        pass
    return True

def add_pattern_to_category(category_name, language, pattern):
    """Add a pattern to a category in the JSON, then hot-recompile.
    language: 'en' | 'es' | 'ru'
    Returns (success: bool, message: str)"""
    if language not in ("en", "es", "ru"):
        return False, "Idioma inválido (usa en/es/ru)"
    # Validate regex
    try:
        re.compile(pattern, FLAGS)
    except re.error as e:
        return False, f"Patrón regex inválido: {e}"
    try:
        with open(KEYWORDS_CONFIG_PATH, encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        return False, f"Error leyendo config: {e}"
    cat = cfg.get("categories", {}).get(category_name)
    if cat is None:
        return False, f"Categoría {category_name} no existe"
    key = f"patterns_{language}"
    existing = cat.setdefault(key, [])
    if pattern in existing:
        return False, f"Ya existe en {category_name}/{language}"
    existing.append(pattern)
    try:
        with open(KEYWORDS_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception as e:
        return False, f"Error guardando: {e}"
    reload_one_category(category_name)
    return True, f"Añadido a {category_name}/{language}"

def remove_pattern_from_category(category_name, language, pattern):
    """Remove a pattern. Returns (success, message)."""
    if language not in ("en", "es", "ru"):
        return False, "Idioma inválido"
    try:
        with open(KEYWORDS_CONFIG_PATH, encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        return False, f"Error leyendo config: {e}"
    cat = cfg.get("categories", {}).get(category_name)
    if cat is None:
        return False, f"Categoría {category_name} no existe"
    key = f"patterns_{language}"
    existing = cat.get(key, [])
    if pattern not in existing:
        return False, f"No encontrado en {category_name}/{language}"
    existing.remove(pattern)
    try:
        with open(KEYWORDS_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception as e:
        return False, f"Error guardando: {e}"
    reload_one_category(category_name)
    return True, f"Eliminado de {category_name}/{language}"

def get_category_summary():
    """Return list of (name, tier, weight, n_en, n_es, n_ru) tuples."""
    out = []
    for name, c in COMPILED_CATEGORIES.items():
        out.append((name, c["tier"], c["weight"],
                    len(c["raw_en"]), len(c["raw_es"]), len(c["raw_ru"])))
    out.sort(key=lambda x: (x[1], -x[2]))  # tier asc, weight desc
    return out

# Load on startup
load_keywords_config()

# Shared scoring is authoritative for both Telegram and the onion worker. The
# category editor reloads this module after every saved change.
from scoring_engine import score_text, risk_level

# ==========================================
# 5. STORAGE
# ==========================================
db: sqlite3.Connection | None = None


@contextmanager
def _telegram_db_session(timeout: int = 5):
    """Short-lived Telegram DB connection that always closes and rolls back safely."""
    connection = sqlite3.connect(DB_PATH, timeout=max(1, int(timeout)))
    connection.execute(f"PRAGMA busy_timeout={max(1000, int(timeout) * 1000)}")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _init_telegram_db() -> bool:
    """Open the legacy Telegram data store lazily.

    Dashboard access-code commands use their own database and must remain
    available even when the crawler/message database needs repair.
    """
    global db
    if db is not None:
        return True
    connection = None
    try:
        connection = sqlite3.connect(DB_PATH, timeout=10)
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("""
        CREATE TABLE IF NOT EXISTS scored (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, chat_id INTEGER, chat_title TEXT,
            user TEXT, msg_id INTEGER,
            text TEXT, score INTEGER, risk TEXT,
            reasons TEXT
        )""")
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_msg ON scored(chat_id, msg_id)")
        connection.execute("""
        CREATE TABLE IF NOT EXISTS alert_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            user TEXT, chat_id INTEGER, chat_title TEXT, score INTEGER,
            risk_level TEXT, user_risk REAL, classification TEXT,
            reasons TEXT, trigger_count INTEGER, msg_id INTEGER, details TEXT
        )""")
        for statement in (
            "CREATE INDEX IF NOT EXISTS idx_alert_log_ts ON alert_log(ts)",
            "CREATE INDEX IF NOT EXISTS idx_alert_log_user ON alert_log(user)",
            "CREATE INDEX IF NOT EXISTS idx_alert_log_type ON alert_log(alert_type)",
            "CREATE INDEX IF NOT EXISTS idx_scored_user ON scored(user)",
            "CREATE INDEX IF NOT EXISTS idx_scored_ts ON scored(ts)",
            "CREATE INDEX IF NOT EXISTS idx_scored_user_ts ON scored(user, ts)",
            "CREATE INDEX IF NOT EXISTS idx_scored_score ON scored(score)",
        ):
            connection.execute(statement)
        connection.execute("""
        CREATE TABLE IF NOT EXISTS dismissed_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL, msg_id INTEGER, chat_id INTEGER, user TEXT,
            reasons TEXT, text TEXT, dismissed_by TEXT
        )""")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_dismissed_reasons ON dismissed_alerts(reasons)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_dismissed_user ON dismissed_alerts(user)")
        try:
            connection.execute("ALTER TABLE scored ADD COLUMN content_hash TEXT")
        except sqlite3.OperationalError:
            pass
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scored_content_hash ON scored(content_hash)")
        connection.execute("""
        CREATE TABLE IF NOT EXISTS user_prefs (
            user_id INTEGER PRIMARY KEY,
            language TEXT DEFAULT 'es',
            updated_at TEXT
        )""")
        for column, definition in (
            ("reviewed_at", "TEXT"),
            ("reviewed_by", "INTEGER"),
            ("review_verdict", "TEXT"),
        ):
            try:
                connection.execute(f"ALTER TABLE alert_log ADD COLUMN {column} {definition}")
            except sqlite3.OperationalError:
                pass
        connection.execute("CREATE INDEX IF NOT EXISTS idx_alert_log_reviewed ON alert_log(reviewed_at, alert_type)")
        connection.commit()
    except (OSError, sqlite3.Error) as exc:
        if connection is not None:
            connection.close()
        db = None
        logging.getLogger("arachne").error(
            "Telegram data database unavailable; access-code controls remain online: %s",
            type(exc).__name__,
        )
        return False
    db = connection
    logging.getLogger("arachne").info("Telegram data schema ready")
    return True


async def _require_telegram_data(event) -> bool:
    if _init_telegram_db():
        try:
            osint_storage.ensure_db_initialized()
            return True
        except (OSError, sqlite3.Error):
            pass
    await event.respond(
        "Arachne data storage is temporarily unavailable. Dashboard access-code controls remain available."
    )
    return False

# ==========================================
# 6. CLIENTS
# ==========================================
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
client = TelegramClient(str(SESSIONS_DIR / get_str("TELEGRAM_USER_SESSION_NAME", "user_scraper_session")), api_id, api_hash)
bot = TelegramClient(str(SESSIONS_DIR / get_str("TELEGRAM_BOT_SESSION_NAME", "bot_alert_session")), api_id, api_hash)

# ==========================================
# 7. MESSAGE SCORING HANDLER
# ==========================================


# ─── Patch 20: OCR helper for Telethon events ─────────────────────────
async def _p20_ocr_event_image(event):
    """If the event has an image (photo or image-mime document), download it
    to a temp file, run OCR, return extracted text + lang. Cleans up after.
    Returns (text:str, lang:str, error:str|None). Empty text means no OCR
    happened or nothing useful came out."""
    import os, tempfile, logging
    if not _OCR_AVAILABLE:
        return ("", "", "ocr_unavailable")
    msg = getattr(event, "message", None)
    if msg is None:
        return ("", "", "no_message")

    is_image = False
    try:
        if getattr(msg, "photo", None) is not None:
            is_image = True
        else:
            doc = getattr(msg, "document", None)
            if doc is not None:
                mime = getattr(doc, "mime_type", "") or ""
                if mime.startswith("image/"):
                    is_image = True
    except Exception:
        pass

    if not is_image:
        return ("", "", None)  # no error, just nothing to do

    tmp_dir = tempfile.mkdtemp(prefix="arachne_ocr_")
    saved_path = None
    try:
        try:
            saved_path = await msg.download_media(file=tmp_dir)
        except Exception as e:
            logging.getLogger("arachne").warning(
                "[p20] download_media failed: %s", type(e).__name__)
            return ("", "", f"download_failed:{type(e).__name__}")
        if not saved_path or not os.path.exists(saved_path):
            return ("", "", "download_no_path")

        try:
            r = _ocr_extract_text(saved_path)
        except Exception as e:
            return ("", "", f"ocr_call_failed:{type(e).__name__}")

        if r.get("error"):
            return ("", r.get("lang", ""), r["error"])
        if r.get("skipped"):
            return ("", r.get("lang", ""), r["skipped"])
        return (r.get("text", ""), r.get("lang", ""), None)
    finally:
        # cleanup
        try:
            if saved_path and os.path.exists(saved_path):
                os.unlink(saved_path)
        except Exception:
            pass
        try:
            os.rmdir(tmp_dir)
        except Exception:
            pass


def record_chat_context_ocr(chat_id, msg_id, user, text, lang, flagged=False, ts=None):
    """Variant of record_chat_context for OCR-derived text. Marks from_ocr=1."""
    if not chat_id or not text:
        return
    try:
        from datetime import datetime, timezone
        ts = ts or datetime.now(timezone.utc).isoformat()
        with _telegram_db_session() as conn:
            conn.execute("""
                INSERT INTO chat_context
                    (chat_id, msg_id, ts, user, text, flagged, from_ocr, ocr_lang)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?)
            """, (int(chat_id), msg_id, ts, str(user) if user else None,
                  text[:1000], 1 if flagged else 0, lang or ""))
    except Exception as e:
        logging.getLogger("arachne").warning(
            "[p20] record_chat_context_ocr failed: %s", type(e).__name__)
# ──────────────────────────────────────────────────────────────────────


# ─── Patch 22: edit & deletion recorder helpers ───────────────────────
_p22_edit_delete_handlers = True

def _p22_record_message_edit(chat_id, msg_id, new_text, edited_at=None):
    """When a monitored-group message is edited, append the prior text to
    edit_history (JSON list of {ts, text}), bump edit_count, update text."""
    if not chat_id or not msg_id:
        return
    try:
        from datetime import datetime, timezone
        import json as _json
        edited_at = edited_at or datetime.now(timezone.utc).isoformat()
        with _telegram_db_session() as conn:
            row = conn.execute(
                "SELECT id, text, edit_history, edit_count "
                "FROM chat_context WHERE chat_id = ? AND msg_id = ? "
                "ORDER BY id DESC LIMIT 1",
                (int(chat_id), int(msg_id))
            ).fetchone()
            if row:
                ctx_id, prev_text, prev_history, prev_count = row
                if (prev_text or "") == (new_text or ""):
                    return
                try:
                    history = _json.loads(prev_history) if prev_history else []
                except Exception:
                    history = []
                history.append({"ts": edited_at, "text": (prev_text or "")[:500]})
                history = history[-10:]
                conn.execute("""
                    UPDATE chat_context SET text=?,edit_history=?,edit_count=?,last_edited_at=?
                    WHERE id=?
                """, ((new_text or "")[:1000], _json.dumps(history, ensure_ascii=False),
                      (prev_count or 0) + 1, edited_at, ctx_id))
            else:
                conn.execute("""
                    INSERT INTO chat_context
                      (chat_id,msg_id,ts,user,text,flagged,edit_history,edit_count,last_edited_at)
                    VALUES (?,?,?,NULL,?,0,'[]',0,?)
                """, (int(chat_id), int(msg_id), edited_at,
                      (new_text or "")[:1000], edited_at))
    except Exception as e:
        logging.getLogger("arachne").warning(
            "[p22] record_message_edit failed: %s", type(e).__name__)


def _p22_record_message_delete(chat_id, msg_ids):
    """Mark deleted_at on every chat_context row matching (chat_id, msg_id).
    msg_ids is a list/iterable of integer message IDs."""
    if not chat_id or not msg_ids:
        return
    try:
        from datetime import datetime, timezone
        deleted_at = datetime.now(timezone.utc).isoformat()
        ids = [int(m) for m in msg_ids]
        if not ids:
            return
        placeholders = ",".join("?" for _ in ids)
        params = [deleted_at, int(chat_id)] + ids
        with _telegram_db_session() as conn:
            conn.execute(f"""
                UPDATE chat_context SET deleted_at=?
                WHERE chat_id=? AND msg_id IN ({placeholders}) AND deleted_at IS NULL
            """, params)
    except Exception as e:
        logging.getLogger("arachne").warning(
            "[p22] record_message_delete failed: %s", type(e).__name__)
# ──────────────────────────────────────────────────────────────────────

# ─── Patch 19: chat_context recorder + retriever ──────────────────────
def record_chat_context(chat_id, msg_id, user, text, flagged=False, ts=None):
    """Persist a message to the rolling chat_context tail. Cheap, no LLM."""
    if not chat_id or not text:
        return
    try:
        from datetime import datetime, timezone
        ts = ts or datetime.now(timezone.utc).isoformat()
        with _telegram_db_session() as conn:
            conn.execute("""
                INSERT INTO chat_context (chat_id, msg_id, ts, user, text, flagged)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (int(chat_id), msg_id, ts, str(user) if user else None,
                  text[:1000], 1 if flagged else 0))
    except Exception as e:
        logging.getLogger("arachne").warning(
            "[p19] record_chat_context failed: %s", type(e).__name__)



# ─── Patch 19: context recorder helper for Telethon events ────────────
def _p19_record_event_context(event, flagged=False):
    """Best-effort extraction of chat/user/text from a Telethon event,
    then persist to chat_context. Safe to call without try/except in caller."""
    try:
        chat_id = None
        msg_id = None
        user = None
        text = None
        try:
            chat = event.chat if hasattr(event, "chat") else None
            chat_id = (event.chat_id if hasattr(event, "chat_id")
                       else (chat.id if chat else None))
        except Exception:
            pass
        try:
            msg_id = event.message.id if (event.message and
                                          hasattr(event.message, "id")) else None
        except Exception:
            pass
        try:
            sender = event.sender if hasattr(event, "sender") else None
            if sender is not None:
                user = (getattr(sender, "username", None)
                        or getattr(sender, "first_name", None)
                        or str(getattr(sender, "id", "?")))
        except Exception:
            pass
        try:
            text = (event.message.text if (event.message and
                                           hasattr(event.message, "text"))
                    else None) or (event.raw_text if hasattr(event, "raw_text")
                                   else None)
        except Exception:
            pass
        if chat_id and text:
            record_chat_context(chat_id, msg_id, user, text, flagged=flagged)
    except Exception as e:
        logging.getLogger("arachne").warning(
            "[p19] event context record failed: %s", type(e).__name__)
# ──────────────────────────────────────────────────────────────────────

def get_recent_chat_context(chat_id, limit=None, exclude_msg_id=None):
    """Return the last N messages in this chat (excluding the current one),
    oldest first, as a list of {ts, user, text} dicts."""
    if limit is None:
        limit = CONTEXT_WINDOW
    try:
        with _telegram_db_session() as conn:
            if exclude_msg_id is not None:
                rows = conn.execute("""
                    SELECT ts, user, text FROM chat_context
                     WHERE chat_id = ? AND (msg_id IS NULL OR msg_id != ?)
                     ORDER BY ts DESC LIMIT ?
                """, (int(chat_id), int(exclude_msg_id), int(limit))).fetchall()
            else:
                rows = conn.execute("""
                    SELECT ts, user, text FROM chat_context
                     WHERE chat_id = ? ORDER BY ts DESC LIMIT ?
                """, (int(chat_id), int(limit))).fetchall()
        # Reverse to oldest-first
        return [{"ts": r[0], "user": r[1], "text": r[2]} for r in reversed(rows)]
    except Exception as e:
        logging.getLogger("arachne").warning(
            "[p19] recent context lookup failed: %s", type(e).__name__)
        return []


def get_user_recent_flagged(chat_id, user, limit=None, exclude_msg_id=None):
    """Return this user's recent flagged messages in this chat, oldest first."""
    if limit is None:
        limit = USER_HISTORY_WINDOW
    if not user:
        return []
    try:
        with _telegram_db_session() as conn:
            if exclude_msg_id is not None:
                rows = conn.execute("""
                    SELECT ts, text FROM chat_context
                     WHERE chat_id = ? AND user = ? AND flagged = 1
                       AND (msg_id IS NULL OR msg_id != ?)
                     ORDER BY ts DESC LIMIT ?
                """, (int(chat_id), str(user), int(exclude_msg_id), int(limit))).fetchall()
            else:
                rows = conn.execute("""
                    SELECT ts, text FROM chat_context
                     WHERE chat_id = ? AND user = ? AND flagged = 1
                     ORDER BY ts DESC LIMIT ?
                """, (int(chat_id), str(user), int(limit))).fetchall()
        return [{"ts": r[0], "text": r[1]} for r in reversed(rows)]
    except Exception as e:
        logging.getLogger("arachne").warning(
            "[p19] flagged context lookup failed: %s", type(e).__name__)
        return []


def trim_chat_context():
    """Keep only the most recent CONTEXT_TABLE_MAX messages per chat.
    Run periodically; safe to call concurrently (single SQL statement)."""
    try:
        with _telegram_db_session(timeout=10) as conn:
            conn.execute("""
                DELETE FROM chat_context
                 WHERE id IN (
                    SELECT id FROM (
                        SELECT id, ROW_NUMBER() OVER (
                            PARTITION BY chat_id ORDER BY ts DESC
                        ) AS rn FROM chat_context
                    ) WHERE rn > ?
                 )
            """, (CONTEXT_TABLE_MAX,))
    except Exception as e:
        logging.getLogger("arachne").warning(
            "[p19] context trim failed: %s", type(e).__name__)


_p19_last_trim = 0
def maybe_trim_chat_context():
    """Call from hot path; only actually trims at most once per interval."""
    import time as _t
    global _p19_last_trim
    now = _t.time()
    if now - _p19_last_trim >= CONTEXT_TRIM_INTERVAL_S:
        _p19_last_trim = now
        import threading as _th
        _th.Thread(target=trim_chat_context, daemon=True,
                   name="p19_trim_chat_context").start()
# ──────────────────────────────────────────────────────────────────────


# ─── Patch 19: mark flagged in chat_context when log_alert fires ──────
def _p19_mark_flagged_in_context(chat_id, msg_id):
    try:
        if not chat_id or not msg_id:
            return
        with _telegram_db_session() as conn:
            conn.execute(
                "UPDATE chat_context SET flagged = 1 WHERE chat_id = ? AND msg_id = ?",
                (int(chat_id), int(msg_id))
            )
    except Exception as e:
        logging.getLogger("arachne").warning(
            "[p19] mark-flagged update failed: %s", type(e).__name__)
# ──────────────────────────────────────────────────────────────────────


# ─── Patch 20: mark from_ocr in alert_log if details starts with [OCR: ─
def _p20_mark_ocr_in_alert(alert_id, details):
    try:
        if not alert_id or not details or not details.startswith("[OCR:"):
            return
        # Pull lang from "[OCR:spa+eng] ..."
        lang = ""
        try:
            close = details.find("]")
            if close > 5:
                lang = details[5:close]
        except Exception:
            pass
        with _telegram_db_session() as conn:
            conn.execute(
                "UPDATE alert_log SET from_ocr = 1, ocr_lang = ? WHERE id = ?",
                (lang, alert_id)
            )
    except Exception as e:
        logging.getLogger("arachne").warning(
            "[p20] mark-OCR update failed: %s", type(e).__name__)
# ──────────────────────────────────────────────────────────────────────

# ─── Patch 18b: LLM enrichment helper ─────────────────────────────────
def _llm_enrich_alert(alert_id, message_text, chat_title="",
                       chat_id=None, user=None, msg_id=None):
    """Background-thread enricher (patch 19: now context-aware).
    Pulls recent chat context + user's flagged history from chat_context,
    then classifies. Failures land in llm_error column."""
    if not _LLM_AVAILABLE:
        return
    recent_chat = []
    user_hist = []
    try:
        if chat_id is not None:
            recent_chat = get_recent_chat_context(
                chat_id, limit=CONTEXT_WINDOW, exclude_msg_id=msg_id)
            if user:
                user_hist = get_user_recent_flagged(
                    chat_id, user, limit=USER_HISTORY_WINDOW,
                    exclude_msg_id=msg_id)
    except Exception as e:
        logging.getLogger("arachne").warning(
            "[p19] context fetch failed: %s", type(e).__name__)
    try:
        v = llm_classify(
            message_text,
            context_hint=chat_title or "",
            recent_chat=recent_chat,
            user_history=user_hist,
        )
    except Exception as e:
        v = {"severity": 0.0, "category": "none", "flagged": False,
             "reasoning": "", "model": "qwen3:8b", "latency_ms": 0,
             "error": f"call_failed:{type(e).__name__}",
             "context_used": 0}
    try:
        with _telegram_db_session(timeout=10) as conn:
            conn.execute("""
                UPDATE alert_log
                   SET llm_severity=?,llm_category=?,llm_flagged=?,llm_reasoning=?,
                       llm_model=?,llm_latency_ms=?,llm_error=?
                 WHERE id=?
            """, (v["severity"], v["category"], 1 if v["flagged"] else 0,
                  v["reasoning"], v["model"], v["latency_ms"], v["error"], alert_id))
    except Exception as e:
        logging.getLogger("arachne").warning(
            "LLM enrich DB update failed: %s", type(e).__name__)


def get_llm_verdict_for_alert(alert_id):
    """Return formatted LLM verdict string for a given alert, or empty if none."""
    try:
        with _telegram_db_session() as conn:
            row = conn.execute(
                "SELECT llm_severity, llm_category, llm_flagged, llm_reasoning, "
                "llm_model, llm_latency_ms, llm_error FROM alert_log WHERE id = ?",
                (alert_id,)
            ).fetchone()
        if not row:
            return ""
        sev, cat, flg, reason, model, lat, err = row
        if err:
            return f"\n🤖 LLM: error ({err[:60]})"
        if sev is None:
            return "\n🤖 LLM: pendiente"
        flag_emoji = "🚩" if flg else "✅"
        return (f"\n🤖 LLM ({model}, {lat}ms): {flag_emoji} "
                f"{cat} · severidad {sev:.2f}\n   📝 {reason}")
    except Exception as e:
        return f"\n🤖 LLM: lookup failed ({type(e).__name__})"
# ──────────────────────────────────────────────────────────────────────


async def register_scraper_handler():
    """Re-registers the scraper handler with the current active groups."""
    # Remove any existing handlers
    client.list_event_handlers()
    for h, _ in list(client.list_event_handlers()):
        client.remove_event_handler(h)

    @client.on(events.MessageEdited(chats=config["active_groups"]))
    async def edit_handler_p22(event):
        """Patch 22: capture edits to monitored-group messages."""
        try:
            chat_id = (event.chat_id if hasattr(event, "chat_id")
                       else (event.chat.id if hasattr(event, "chat") and event.chat else None))
            msg_id = event.message.id if (event.message and hasattr(event.message, "id")) else None
            new_text = (event.message.message if event.message else "") or ""
            if chat_id and msg_id:
                _p22_record_message_edit(chat_id, msg_id, new_text)
        except Exception as _p22ee:
            logging.getLogger("arachne").warning(
                "[p22] edit handler failed: %s", type(_p22ee).__name__)

    @client.on(events.MessageDeleted(chats=config["active_groups"]))
    async def delete_handler_p22(event):
        """Patch 22: capture deletions in monitored groups.
        Note: MessageDeleted in groups gives chat_id; in private chats it may not.
        We only act when chat_id is present."""
        try:
            chat_id = getattr(event, "chat_id", None)
            deleted_ids = getattr(event, "deleted_ids", []) or []
            if chat_id and deleted_ids:
                _p22_record_message_delete(chat_id, deleted_ids)
        except Exception as _p22de:
            logging.getLogger("arachne").warning(
                "[p22] delete handler failed: %s", type(_p22de).__name__)

    @client.on(events.NewMessage(chats=config["active_groups"]))
    async def detector_de_mensajes(event):
        # ─── Patch 19b: record every monitored-group message to chat_context ─
        try:
            _p19_record_event_context(event, flagged=False)
            maybe_trim_chat_context()
        except Exception as _p19e:
            logging.getLogger('arachne').warning(
                '[p19b] context record failed: %s', type(_p19e).__name__)
        # ─────────────────────────────────────────────────────────────────────
        # ─── Patch 20: OCR pass on image messages ──────────────────────────
        _p20_ocr_block = True
        _p20_ocr_text = ""
        _p20_ocr_lang = ""
        try:
            if _OCR_AVAILABLE:
                _p20_ocr_text, _p20_ocr_lang, _p20_ocr_err = \
                    await _p20_ocr_event_image(event)
                if _p20_ocr_text:
                    # Log OCR text as its own context entry (from_ocr=1)
                    try:
                        _p20_chat = event.chat if hasattr(event,'chat') else None
                        _p20_chat_id = (event.chat_id if hasattr(event,'chat_id')
                                        else (_p20_chat.id if _p20_chat else None))
                        _p20_msg_id = event.message.id if event.message else None
                        _p20_sender = event.sender if hasattr(event,'sender') else None
                        _p20_user = (getattr(_p20_sender,'username',None)
                                     or getattr(_p20_sender,'first_name',None)
                                     or str(getattr(_p20_sender,'id','?')))
                        record_chat_context_ocr(
                            _p20_chat_id, _p20_msg_id, _p20_user,
                            _p20_ocr_text, _p20_ocr_lang, flagged=False)
                    except Exception as _p20e2:
                        logging.getLogger('arachne').warning(
                            '[p20] OCR context log failed: %s', type(_p20e2).__name__)
        except Exception as _p20e:
            logging.getLogger('arachne').warning(
                '[p20] OCR pass failed: %s', type(_p20e).__name__)
        # ────────────────────────────────────────────────────────────────────
        texto = event.message.message or ""
        if _p20_ocr_text:
            # Prepend OCR text so scoring + LLM see it. Marker for reviewers.
            if texto.strip():
                texto = f"[OCR:{_p20_ocr_lang}] {_p20_ocr_text}\n---\n{texto}"
            else:
                texto = f"[OCR:{_p20_ocr_lang}] {_p20_ocr_text}"
        if not texto.strip():
            return

        s, reasons = score_text(texto)

        chat = await event.get_chat()
        sender = await event.get_sender()
        name = sender.username if sender and sender.username else "Anon"

        # Keyword repetition boost — apply if the same user has been hammering
        # the same trigger categories across recent messages
        rep_boost, rep_reasons = detect_keyword_repetition(name, texto)
        if rep_boost > 0:
            s += rep_boost
            reasons.extend([f"rep:{r}" for r in rep_reasons])

        # False-positive feedback: deprioritize reasons that frequently get dismissed
        fp_pen = fp_penalty(reasons)
        if fp_pen < 0:
            s += fp_pen
            reasons.append(f"fp_penalty:{fp_pen}")

        risk = risk_level(s)

        db.execute(
            "INSERT INTO scored (ts, chat_id, chat_title, user, msg_id, text, score, risk, reasons) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), chat.id, getattr(chat, "title", "?"),
             name, event.message.id, texto, s, risk, ",".join(reasons))
        )
        db.commit()

        if s >= config["alert_threshold"]:
            cid = str(chat.id)
            link = f"https://t.me/c/{cid[4:]}/{event.message.id}" if cid.startswith("-100") else ""
            await bot.send_message(
                admin_chat_id,
                f"🚨 **{risk}** (score {s})\n"
                f"**Grupo:** {chat.title}\n"
                f"**Usuario:** @{name}\n"
                f"**Motivos:** {', '.join(reasons)}\n"
                f"**Mensaje:**\n{texto[:1500]}\n"
                f"{link}"
            )
            log_alert(
                alert_type="message",
                user=name, chat_id=chat.id, chat_title=chat.title,
                score=s, risk_level=risk, reasons=reasons,
                msg_id=event.message.id, details=texto[:500]
            )

        # Burst + escalation push alerts (separate from per-message alerts)
        if name and name != "Anon" and s >= config["alert_threshold"]:
            try:
                await check_and_push_alerts(name, chat.title)
            except Exception as e:
                print(f"Burst check error: {redact_for_log(e)}")

# ==========================================
# 8. BOT MENU
# ==========================================

# ============================================================
# USER RISK ENGINE
# ============================================================
def decay_weight_sql():
    """SQL fragment that applies time decay to scores.
    Last hour = 1.0, last 24h = 0.5, older = 0.2"""
    return """
        CASE
            WHEN (julianday('now') - julianday(ts)) * 24 <= 1 THEN score * 1.0
            WHEN (julianday('now') - julianday(ts)) * 24 <= 24 THEN score * 0.5
            ELSE score * 0.2
        END
    """


def detect_keyword_repetition(user: str, current_text: str, lookback_msgs: int = 10):
    """Boost if user's recent messages repeat the same trigger keywords."""
    if not user or user == "Anon":
        return 0, []

    # Pull last N messages from this user
    rows = db.execute("""
        SELECT text FROM scored
        WHERE user = ?
        ORDER BY id DESC LIMIT ?
    """, (user, lookback_msgs)).fetchall()

    if len(rows) < 3:
        return 0, []

    # Combine recent texts
    combined = " ".join([r[0] or "" for r in rows] + [current_text])

    # Count high-signal keyword hits across the combined window.  These
    # categories are loaded from keywords_config.json; the old standalone
    # regex globals no longer exist and made this live path raise NameError.
    repeated = []
    for category_name, pattern_name in [
        ("VIOLENT_INTENT", "violent"),
        ("WEAPONS_HARD", "weapons"),
        ("EXPLOSIVES", "explosives"),
        ("TERROR", "terror"),
        ("IMMINENT", "imminent"),
    ]:
        category = COMPILED_CATEGORIES.get(category_name, {})
        match_count = sum(
            len(pattern.findall(combined))
            for pattern in (
                category.get("compiled_en"),
                category.get("compiled_es"),
                category.get("compiled_ru"),
            )
            if pattern is not None
        )
        if match_count >= 3:  # repeated 3+ times across recent activity
            repeated.append(f"{pattern_name}_x{match_count}")

    if repeated:
        return 3 * len(repeated), repeated  # +3 per repeated category
    return 0, []


def compute_user_risk(user: str):
    """Compute the unified risk profile for a single user."""
    threshold = config["alert_threshold"]
    row = db.execute(f"""
        SELECT
            COUNT(*) AS total_msgs,
            SUM(CASE WHEN score >= ? THEN 1 ELSE 0 END) AS triggers,
            AVG(score) AS avg_score,
            MAX(score) AS max_score,
            COUNT(DISTINCT chat_id) AS groups_count,
            SUM({decay_weight_sql()}) AS weighted_score,
            SUM(CASE WHEN score >= ? AND
                (julianday('now') - julianday(ts)) * 24 <= 1
                THEN 1 ELSE 0 END) AS recent_triggers_1h,
            MIN(ts) AS first_seen,
            MAX(ts) AS last_seen
        FROM scored
        WHERE user = ?
    """, (threshold, threshold, user)).fetchone()

    if not row or not row[0]:
        return None

    total, triggers, avg, mx, groups, weighted, recent_1h, first, last = row
    trigger_rate = (triggers / total) if total else 0

    # Unified risk score (0-100 normalized)
    burst_factor = min(recent_1h * 25, 100)  # 4 triggers/hour = 100
    group_factor = min(groups * 25, 100)
    avg_factor = min((avg or 0) * 10, 100)
    rate_factor = trigger_rate * 100

    w = SCORING["user_risk_formula"]
    user_risk = (
        avg_factor * w["avg_score_weight"] +
        rate_factor * w["trigger_rate_weight"] +
        burst_factor * w["burst_factor_weight"] +
        group_factor * w["group_factor_weight"]
    )

    # Classification
    cls = SCORING["classification_rules"]
    label = "LOW_SIGNAL"
    if recent_1h >= cls["agitator_recent_triggers_min"] and trigger_rate > cls["agitator_trigger_rate_min"]:
        label = "AGITATOR"
    elif groups >= cls["bridge_groups_min"] and triggers >= cls["bridge_triggers_min"]:
        label = "BRIDGE"
    elif total > cls["spammer_total_msgs_min"] and trigger_rate < cls["spammer_trigger_rate_max"]:
        label = "SPAMMER"
    elif trigger_rate > cls["active_trigger_rate_min"]:
        label = "ACTIVE"

    # Group affinity: only compute for multi-group users (saves cycles)
    group_affinity = compute_group_affinity(user) if groups >= 2 else 0

    # Boost BRIDGE classification if affinity is meaningful
    if label == "BRIDGE" and group_affinity >= 15:
        label = "BRIDGE_STRONG"
    elif groups >= 2 and group_affinity >= 25 and label == "LOW_SIGNAL":
        label = "BRIDGE"

    # Add affinity to user_risk (small boost, max +10)
    user_risk = min(user_risk + (group_affinity * 0.2), 100)

    return {
        "user": user,
        "total_msgs": total,
        "triggers": triggers,
        "trigger_rate": round(trigger_rate, 3),
        "avg_score": round(avg or 0, 2),
        "max_score": mx or 0,
        "groups_count": groups,
        "weighted_score": round(weighted or 0, 2),
        "recent_triggers_1h": recent_1h,
        "user_risk": round(user_risk, 1),
        "label": label,
        "group_affinity": group_affinity,
        "first_seen": first,
        "last_seen": last,
    }


# ============================================================
# BURST DETECTION & PUSH ALERTS
# ============================================================
# Track which users we've already burst-alerted on, to avoid spam
burst_alerted = {}  # {user: timestamp_of_last_alert}
BURST_COOLDOWN_MIN = SCORING["burst_detection"]["cooldown_minutes"]


def log_alert(alert_type: str, user: str = None, chat_id: int = None,
              chat_title: str = None, score: int = None, risk_level: str = None,
              user_risk: float = None, classification: str = None,
              reasons: list = None, trigger_count: int = None,
              msg_id: int = None, details: str = None):
    """Persist alert event to alert_log table for later review and tuning."""
    try:
        from datetime import datetime as _dt
        ts = _dt.now(timezone.utc).isoformat()
        _p18_cur = db.execute("""
            INSERT INTO alert_log
            (ts, alert_type, user, chat_id, chat_title, score, risk_level,
             user_risk, classification, reasons, trigger_count, msg_id, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, alert_type, user, chat_id, chat_title, score, risk_level,
              user_risk, classification,
              ",".join(reasons) if reasons else None,
              trigger_count, msg_id, details))
        db.commit()
        # ─── Patch 18d: dispatch LLM enrichment in background ───
        try:
            _p18_alert_id = _p18_cur.lastrowid
            _p18_msg_text = details or ""
            if _p18_alert_id and _p18_msg_text and _LLM_AVAILABLE:
                threading.Thread(
                    target=_llm_enrich_alert,
                    kwargs={
                        'alert_id': _p18_alert_id,
                        'message_text': _p18_msg_text,
                        'chat_title': chat_title or '',
                        'chat_id': chat_id,
                        'user': user,
                        'msg_id': msg_id,
                    },
                    daemon=True,
                    name=f"llm_enrich_{_p18_alert_id}",
                ).start()
        except Exception as _p18e:
            logging.getLogger('arachne').warning(
                '[p18d] enrichment dispatch failed: %s', type(_p18e).__name__)
        _p18_dispatch_enrichment = True  # patch 18d hook installed
        try:
            _p19_mark_flagged_in_context(chat_id, msg_id)
        except Exception as _p20be1:
            logging.getLogger('arachne').warning(
                '[p20b] mark-flagged call failed: %s', type(_p20be1).__name__)
        try:
            _p20_mark_ocr_in_alert(_p18_alert_id, details)
        except Exception as _p20be2:
            logging.getLogger('arachne').warning(
                '[p20b] mark-OCR call failed: %s', type(_p20be2).__name__)
        _p20b_calls_wired = True  # patch 20b marker
        # ────────────────────────────────────────────────────────
    except Exception as e:
        print(f"[AUDIT] log_alert error: {redact_for_log(e)}")



# False-positive feedback — pattern dismissals
_dismissed_reason_cache = {"data": None, "ts": 0}

def get_dismissed_reason_counts():
    """Cached count of how often each reason tag appears in dismissed alerts."""
    import time as _t
    now = _t.time()
    if _dismissed_reason_cache["data"] is not None and (now - _dismissed_reason_cache["ts"]) < 300:
        return _dismissed_reason_cache["data"]
    counts = {}
    try:
        rows = db.execute("SELECT reasons FROM dismissed_alerts WHERE reasons IS NOT NULL").fetchall()
        for (r,) in rows:
            for tag in (r or "").split(","):
                tag = tag.strip()
                if tag:
                    counts[tag] = counts.get(tag, 0) + 1
    except Exception as e:
        print(f"[FP] get_dismissed_reason_counts error: {redact_for_log(e)}")
    _dismissed_reason_cache["data"] = counts
    _dismissed_reason_cache["ts"] = now
    return counts

def fp_penalty(reasons: list) -> int:
    """Return negative score adjustment based on how often these reasons get dismissed.
    Each reason that has been dismissed >=5 times globally subtracts 1, max -3."""
    counts = get_dismissed_reason_counts()
    penalty = 0
    for r in reasons:
        if counts.get(r, 0) >= 5:
            penalty -= 1
    return max(penalty, -3)

def record_dismissal(msg_id: int, chat_id: int, user: str, reasons: str, text: str, dismissed_by: str):
    """Record that an alert was marked false positive."""
    from datetime import datetime as _dt
    try:
        db.execute("""
            INSERT INTO dismissed_alerts (ts, msg_id, chat_id, user, reasons, text, dismissed_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (_dt.now(timezone.utc).isoformat(), msg_id, chat_id, user, reasons, text, dismissed_by))
        db.commit()
        # Invalidate cache so next score uses fresh penalty
        _dismissed_reason_cache["ts"] = 0
        return True
    except Exception as e:
        print(f"[FP] record_dismissal error: {redact_for_log(e)}")
        return False



def text_hash(text):
    import hashlib
    if not text:
        return ""
    norm = re.sub(r"\s+", " ", text.lower().strip())
    norm = re.sub(r"https?://\S+", "URL", norm)
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]

def detect_amplification(content_hash, current_chat_id):
    if not content_hash:
        return None
    rows = db.execute("""
        SELECT DISTINCT chat_id, chat_title, user, ts
        FROM scored
        WHERE content_hash = ? AND chat_id != ?
        ORDER BY ts DESC LIMIT 20
    """, (content_hash, current_chat_id)).fetchall()
    if not rows:
        return None
    return {
        "groups_seen": len(set(r[0] for r in rows)),
        "users_seen": len(set(r[2] for r in rows if r[2])),
        "first_seen": rows[-1][3] if rows else None,
        "occurrences": len(rows),
    }


def detect_burst(user: str, window_minutes: int = None, min_triggers: int = None):
    if window_minutes is None:
        window_minutes = SCORING["burst_detection"]["window_minutes"]
    if min_triggers is None:
        min_triggers = SCORING["burst_detection"]["min_triggers"]
    """Return burst info if user has >= min_triggers in last window_minutes."""
    threshold = config["alert_threshold"]
    row = db.execute("""
        SELECT
            COUNT(*) AS n,
            MAX(score) AS mx,
            AVG(score) AS avg,
            GROUP_CONCAT(DISTINCT chat_title) AS groups
        FROM scored
        WHERE user = ?
          AND score >= ?
          AND (julianday('now') - julianday(ts)) * 24 * 60 <= ?
    """, (user, threshold, window_minutes)).fetchone()

    if not row or row[0] < min_triggers:
        return None
    return {
        "user": user,
        "count": row[0],
        "max_score": row[1],
        "avg_score": round(row[2] or 0, 2),
        "groups": row[3],
        "window_min": window_minutes,
    }

def detect_escalation(user: str):
    """Compare user's last 10 msgs avg vs previous 50. Return ratio if rising."""
    threshold = config["alert_threshold"]
    rows = db.execute("""
        SELECT score FROM scored
        WHERE user = ? ORDER BY id DESC LIMIT 60
    """, (user,)).fetchall()
    if len(rows) < 30:
        return None
    recent = [r[0] for r in rows[:10]]
    older = [r[0] for r in rows[10:60]]
    if not older:
        return None
    recent_avg = sum(recent) / len(recent)
    older_avg = sum(older) / len(older)
    if older_avg <= 0:
        return None
    ratio = recent_avg / older_avg
    if ratio < 1.5 or recent_avg < threshold:
        return None
    return {
        "user": user,
        "recent_avg": round(recent_avg, 2),
        "older_avg": round(older_avg, 2),
        "ratio": round(ratio, 2),
    }

async def check_and_push_alerts(user: str, chat_title: str):
    """Run after each scored message. Push alert if burst or escalation detected."""
    from datetime import datetime as _dt
    now = _dt.now(timezone.utc)

    # Cooldown check
    last_alert = burst_alerted.get(user)
    if last_alert and (now - last_alert).total_seconds() / 60 < BURST_COOLDOWN_MIN:
        return

    burst = detect_burst(user)
    escal = detect_escalation(user)

    if not (burst or escal):
        return

    burst_alerted[user] = now

    profile = compute_user_risk(user)
    msg = "⚡ **PUSH ALERT** ⚡\n━━━━━━━━━━━━━━━━━━━━\n\n"

    if burst:
        msg += (
            f"🔥 **BURST DETECTED** — @{user}\n"
            f"  {burst['count']} triggers en {burst['window_min']} min\n"
            f"  Max score: {burst['max_score']} · Avg: {burst['avg_score']}\n"
            f"  Grupo(s): {burst['groups']}\n\n"
        )

    if escal:
        msg += (
            f"📈 **ESCALATION** — @{user}\n"
            f"  Reciente avg: {escal['recent_avg']} (vs {escal['older_avg']})\n"
            f"  Ratio: x{escal['ratio']}\n\n"
        )

    if profile:
        msg += (
            f"━━━ Perfil del usuario ━━━\n"
            f"⚡ Risk score: **{profile['user_risk']}** · `{profile['label']}`\n"
            f"🚩 {profile['triggers']}/{profile['total_msgs']} msgs ({int(profile['trigger_rate']*100)}%)\n"
            f"📍 {profile['groups_count']} grupos · 🔥 {profile['recent_triggers_1h']} triggers última hora\n"
        )

    try:
        await bot.send_message(admin_chat_id, msg)
        if burst:
            log_alert(
                alert_type="burst",
                user=user, score=burst.get("max_score"),
                user_risk=profile["user_risk"] if profile else None,
                classification=profile["label"] if profile else None,
                trigger_count=burst.get("count"),
                details=f"window={burst.get('window_min')}min groups={burst.get('groups')}"
            )
        if escal:
            log_alert(
                alert_type="escalation",
                user=user,
                user_risk=profile["user_risk"] if profile else None,
                classification=profile["label"] if profile else None,
                details=f"recent_avg={escal.get('recent_avg')} older_avg={escal.get('older_avg')} ratio={escal.get('ratio')}"
            )
    except Exception as e:
        print(f"Push alert send error: {redact_for_log(e)}")



def compute_group_affinity(user: str):
    """Score how much this user's groups overlap with OTHER high-risk users.
    Higher = more meaningful bridge actor (groups share other concerning users)."""
    threshold = config["alert_threshold"]

    # User's groups
    user_groups = db.execute("""
        SELECT DISTINCT chat_id FROM scored WHERE user = ?
    """, (user,)).fetchall()
    if len(user_groups) < 2:
        return 0  # not a bridge by definition

    user_group_ids = [g[0] for g in user_groups]
    placeholders = ",".join("?" * len(user_group_ids))

    # How many OTHER triggered users appear in 2+ of those same groups?
    overlap = db.execute(f"""
        SELECT COUNT(*) FROM (
            SELECT user, COUNT(DISTINCT chat_id) AS n
            FROM scored
            WHERE chat_id IN ({placeholders})
              AND user != ?
              AND user IS NOT NULL AND user != '' AND user != 'Anon'
              AND score >= ?
            GROUP BY user
            HAVING n >= 2
        )
    """, (*user_group_ids, user, threshold)).fetchone()

    overlap_count = overlap[0] if overlap else 0
    # Affinity score: each shared high-risk peer = +5, capped at 50
    return min(overlap_count * 5, 50)


def top_users_by_risk(limit=25):
    """Return top users ranked by unified risk score."""
    threshold = config["alert_threshold"]
    cur = db.execute("""
        SELECT user FROM scored
        WHERE user IS NOT NULL AND user != '' AND user != 'Anon'
        GROUP BY user
        HAVING SUM(CASE WHEN score >= ? THEN 1 ELSE 0 END) > 0
    """, (threshold,))
    users = [r[0] for r in cur.fetchall()]
    profiles = [compute_user_risk(u) for u in users]
    profiles = [p for p in profiles if p]
    profiles.sort(key=lambda x: -x["user_risk"])
    return profiles[:limit]


MAIN_MENU_LABELS = {
    "es": {
        "header": "**ARACHNE · Panel de control**\n\nElige una opción:",
        "stats": "📊 Stats",
        "status": "ℹ️ Estado",
        "recent": "🚩 Últimas alertas",
        "session_summary": "⏱️ Resumen sesión",
        "top_users": "👥 Top usuarios",
        "user_dossier": "📑 Resumen de perfil",
        "crossgroup": "🔗 Cruces grupos",
        "search": "🔍 Buscar texto",
        "week": "📅 Resumen 7 días",
        "report": "📄 Generar informe",
        "last_group": "📥 Últimos del grupo",
        "backscan": "🔎 Escanear 7 días",
        "cats_menu": "🎯 Categorías",
        "grps_menu": "👥 Grupos",
        "thresh": "⚙️ Umbral",
        "review": "🔍 Revisar",
        "help": "❓ Ayuda",
    },
    "en": {
        "header": "**ARACHNE · Control Panel**\n\nPick an option:",
        "stats": "📊 Stats",
        "status": "ℹ️ Status",
        "recent": "🚩 Recent alerts",
        "session_summary": "⏱️ Session summary",
        "top_users": "👥 Top users",
        "user_dossier": "📑 Profile summary",
        "crossgroup": "🔗 Group crossover",
        "search": "🔍 Search text",
        "week": "📅 7-day summary",
        "report": "📄 Generate report",
        "last_group": "📥 Latest from group",
        "backscan": "🔎 Backscan 7 days",
        "cats_menu": "🎯 Categories",
        "grps_menu": "👥 Groups",
        "thresh": "⚙️ Threshold",
        "review": "🔍 Review",
        "help": "❓ Help",
    },
}

def get_user_language(user_id):
    try:
        row = db.execute("SELECT language FROM user_prefs WHERE user_id = ?", (user_id,)).fetchone()
        if row and row[0] in ("es", "en"):
            return row[0]
    except Exception:
        pass
    return "es"

def set_user_language(user_id, lang):
    if lang not in ("es", "en"):
        return False
    from datetime import datetime as _dt
    try:
        db.execute("""
            INSERT INTO user_prefs (user_id, language, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET language = excluded.language, updated_at = excluded.updated_at
        """, (user_id, lang, _dt.now(timezone.utc).isoformat()))
        db.commit()
        return True
    except Exception as e:
        print(f"[PREFS] set_user_language error: {redact_for_log(e)}")
        return False


def main_menu_buttons(uid=None):
    """Build localized main menu. Default Spanish if uid not provided."""
    lang = get_user_language(uid) if uid else "es"
    L = MAIN_MENU_LABELS[lang]
    try:
        alerts_paused = osint_storage.spain_alerts_paused()
        alert_state_known = True
    except (OSError, sqlite3.Error):
        alerts_paused = True
        alert_state_known = False
    alert_toggle_label = (("▶️ Reanudar alertas España" if lang == "es" else "▶️ Resume Spain alerts")
                          if alerts_paused else
                          ("⏸️ Pausar alertas España" if lang == "es" else "⏸️ Pause Spain alerts"))
    if not alert_state_known:
        alert_toggle_label = "Spain alert status unavailable"
    elif not _telegram_push_alerts_enabled():
        alert_toggle_label = "Spain alerts: manual pull only"
    return [
        [Button.inline(L["stats"], b"stats"), Button.inline(L["status"], b"status")],
        [Button.inline(L["recent"], b"recent"), Button.inline(L["session_summary"], b"session_summary")],
        [Button.inline(L["top_users"], b"top_users"), Button.inline(L["user_dossier"], b"user_dossier")],
        [Button.inline(L["crossgroup"], b"crossgroup"), Button.inline(L["search"], b"search")],
        [Button.inline(L["week"], b"week"), Button.inline(L["report"], b"report")],
        [Button.inline(L["last_group"], b"last_group"), Button.inline(L["backscan"], b"backscan")],
        [Button.inline(L["cats_menu"], b"cats_menu"), Button.inline(L["grps_menu"], b"grps_menu")],
        [Button.inline(L["review"], b"review"), Button.inline(L["thresh"], b"thresh")],
        [Button.inline("🧅 Onion hits", b"onion_hits"), Button.inline("🪞 Mirror clusters", b"mirror_clusters")],
        [Button.inline("🔎 Indicator search", b"indicator_search"), Button.inline("📄 Build report", b"build_cluster_report")],
        [Button.inline("🧭 Attribution", b"passive_attribution")],
        [Button.inline("Create access code", b"dashboard_code_custom")],
        [Button.inline("Access page status", b"dashboard_lock_status"), Button.inline("Clear unused codes", b"dashboard_clear_codes")],
        [Button.inline("Enable access page", b"dashboard_lock_on"), Button.inline("Disable access page", b"dashboard_lock_off")],
        [Button.inline("Sanitized diagnostics", b"ops_diagnostics")],
        [Button.inline(alert_toggle_label, b"toggle_spain_alerts")],
        [Button.inline(L["help"], b"help")],
    ]

def main_menu_header(uid=None):
    lang = get_user_language(uid) if uid else "es"
    return MAIN_MENU_LABELS[lang]["header"]



HELP_TOPICS = {
    "es": {
        "_menu_title": "❓ **AYUDA**\n━━━━━━━━━━━━━━━━━━━━\nEscoge un tema:",
        "about": {
            "label": "📖 Sobre el sistema",
            "brief": "📖 **SOBRE EL SISTEMA**\n━━━━━━━━━━━━━━━━━━━━\n\nArachne monitoriza grupos de Telegram en tiempo real y puntúa cada mensaje según su nivel de amenaza. Enfocado en contenido con nexo español: amenazas contra infraestructura, figuras públicas o territorio.\n\nEl sistema NO sustituye análisis humano — clasifica y prioriza.",
            "more": "📖 **DETALLES**\n━━━━━━━━━━━━━━━━━━━━\n\n**Arquitectura:**\n• Cuenta de usuario lee mensajes en tiempo real\n• Cuenta de bot recibe comandos del operador\n• SQLite local con índices optimizados\n• Modelos ML on-device\n\n**Privacidad:**\nDatos en el servidor. Sin envío externo, sin nube, sin terceros.\n\n**Detecta:**\n✅ Amenazas a objetivos españoles\n✅ Violencia inminente o planificada\n✅ Armas, explosivos, CBRN\n✅ Reclutamiento, financiación, logística\n✅ Organizaciones terroristas\n✅ Discurso de odio + violencia\n\n**No detecta:**\n❌ DDoS contra objetivos no españoles\n❌ Charla casual\n❌ Contexto académico/periodístico/ficción",
        },
        "detection": {
            "label": "🎯 Cómo detecta",
            "brief": "🎯 **CÓMO DETECTA**\n━━━━━━━━━━━━━━━━━━━━\n\nMotor de tiers:\n• **Tier 1** — Señales fuertes (explosivos, terror, armas, CBRN)\n• **Tier 2** — Señales medias (violencia, odio, logística)\n• **Tier 3** — Contexto español (infra, geo, figuras)\n• **Tier 4** — Reductores (académico, ficción, citas)\n\nReglas de **co-ocurrencia** suman bonus al combinar amenazas con objetivos españoles.",
            "more": "🎯 **DETALLES**\n━━━━━━━━━━━━━━━━━━━━\n\n**Pipeline:**\n1️⃣ Tokenización + idioma (es/en/ru)\n2️⃣ Match por categorías → suma `weight`\n3️⃣ CTX_DOWNGRADE/CTX_UPGRADE\n4️⃣ Co-ocurrencia (threat + es_target → +4)\n5️⃣ ML: sentiment + hate-speech\n6️⃣ Repetición: hammer de categorías → boost\n7️⃣ Amplificación: mismo texto en otros grupos → +2\n8️⃣ FP penalty: dismissed >5 → -1 (max -3)\n\n**Niveles:**\n• 3+ BAJO\n• 6+ MEDIO (umbral default)\n• 10+ ALTO\n• 15+ CRÍTICO",
        },
        "users": {
            "label": "👥 Usuarios y riesgo",
            "brief": "👥 **USUARIOS Y RIESGO**\n━━━━━━━━━━━━━━━━━━━━\n\nNo solo puntúa mensajes — puntúa **actores en el tiempo**.\n\nRisk score 0-100 + clasificación:\n• `AGITATOR` — alta tasa + actividad reciente\n• `BRIDGE` — multi-grupo + comparte miembros high-risk\n• `BRIDGE_STRONG` — bridge con afinidad alta\n• `ACTIVE` — actividad sostenida\n• `SPAMMER` — volumen alto, tasa muy baja\n• `LOW_SIGNAL` — actividad inconsistente",
            "more": "👥 **DETALLES**\n━━━━━━━━━━━━━━━━━━━━\n\n**Fórmula del risk score (0-100):**\n```\nuser_risk = (avg_score * 0.4)\n          + (trigger_rate * 100 * 0.3)\n          + (burst_factor * 0.2)\n          + (group_factor * 0.1)\n          + (group_affinity * 0.2)\n```\nPesos en `scoring_config.json`.\n\n**Decay temporal:**\n• Última hora → 1.0\n• Últimas 24h → 0.5\n• Más antiguo → 0.2\n\n**Group affinity:**\nMide solapamiento de grupos del usuario con otros high-risk. BRIDGE en grupos al azar = ruido. BRIDGE en grupos que comparten más high-risk = nodo de red real.",
        },
        "alerts": {
            "label": "⚡ Alertas push",
            "brief": "⚡ **ALERTAS PUSH**\n━━━━━━━━━━━━━━━━━━━━\n\nDos tipos:\n\n**🚨 Por mensaje** — supera umbral\n**⚡ Burst** — 3+ triggers/usuario en 10 min\n**📈 Escalation** — avg de últimos 10 msgs es 1.5x mayor que los 50 anteriores\n\nCooldown de 30 min por usuario en burst/escalation.",
            "more": "⚡ **DETALLES**\n━━━━━━━━━━━━━━━━━━━━\n\n**Cooldown:**\n30 min por usuario. Evita spam durante conversación caliente.\n\n**Cada push alert incluye:**\n• Tipo (burst, escalation, o ambos)\n• Conteo de triggers\n• Score promedio + máximo\n• Grupos activos\n• Perfil completo del usuario\n\n**Audit log:**\nToda alerta queda en tabla `alert_log` con timestamp, motivos y contexto.",
        },
        "dossiers": {
            "label": "📑 Resúmenes de perfil",
            "brief": "📑 **RESÚMENES DE PERFIL**\n━━━━━━━━━━━━━━━━━━━━\n\nPulsa **📑 Resumen de perfil** + username:\n\n• Puntuación y clasificación\n• Motivos agregados\n• Actividad por grupo con fechas\n• Cambios de actividad\n• Mensajes con señales más fuertes\n• Cronología reciente\n\nGuardado en el directorio local de informes.",
            "more": "📑 **DETALLES**\n━━━━━━━━━━━━━━━━━━━━\n\n**Estructura del TXT:**\n1. Cabecera (usuario, fecha)\n2. Perfil de riesgo completo\n3. Motivos principales agregados\n4. Actividad por grupo\n5. Burst histórico\n6. Escalation histórico\n7. Top 5 mensajes más fuertes\n8. Cronología completa\n\nResumen al chat + archivo TXT en disco para informes externos.",
        },
        "config": {
            "label": "🛠️ Configuración",
            "brief": "🛠️ **CONFIGURACIÓN**\n━━━━━━━━━━━━━━━━━━━━\n\n**🎯 Categorías** — 16 preconfiguradas + tus añadidos. Regex por idioma.\n**👥 Grupos** — Lista, añade, quita. También por reenvío de mensajes.\n**⚙️ Umbral** — Score mínimo de alerta. Default: 6.",
            "more": "🛠️ **DETALLES**\n━━━━━━━━━━━━━━━━━━━━\n\n**Editar categorías:**\n🎯 → categoría → idioma → ver/añadir/quitar\nCambios al instante, sin reinicio.\n\n**Config files:**\n• `scoring_config.json` — pesos, thresholds, fórmula\n• `keywords_config.json` — patrones por categoría e idioma\n\n**Falsos positivos:**\n`/falsepos <msg_id>` marca FP. Tras 5+ dismissals del mismo tag, deprioriza.",
        },
        "groups": {
            "label": "📥 Añadir grupos",
            "brief": "📥 **AÑADIR GRUPOS**\n━━━━━━━━━━━━━━━━━━━━\n\nTres formas:\n\n1. **Reenvío** — Reenvía un mensaje del grupo al bot.\n2. **Por ID** — 👥 Grupos → ➕ Añadir → ID `-100...`\n3. **Auto-leave** — bot abandona grupos no autorizados.",
            "more": "📥 **DETALLES**\n━━━━━━━━━━━━━━━━━━━━\n\n**Requisitos:**\n• Cuenta de usuario debe ser miembro\n• Bot privacy disable auto-join\n\n**No hay auto-backscan** — usa **🔎 Escanear 7 días** para procesar histórico.\n\n**Permisos:**\nSolo `ALLOWED_USERS` interactúan con el bot. Resto se ignora.",
        },
        "glossary": {
            "label": "❓ Glosario de tags",
            "brief": "❓ **GLOSARIO**\n━━━━━━━━━━━━━━━━━━━━\n\nTags en cada alerta:\n• **Categorías** — `explosives`, `terror`, `infra_es`, etc.\n• **Modificadores** — `cooccur:*`, `amplified:*`, `rep:*`, `fp_penalty:*`\n• **Metadata** — `lang:es/en/ru`",
            "more": "❓ **GLOSARIO COMPLETO**\n━━━━━━━━━━━━━━━━━━━━\n\n**📌 Categorías:**\n• `explosives` (T1, +5)\n• `terror` (T1, +4)\n• `weapons_hard` (T1, +3)\n• `cbrn` (T1, +5)\n• `imminent` (T1, +3)\n• `cyber` (T2, 0 — solo via co-occur)\n• `violent_intent` (T2, +2)\n• `hate_target` (T2, +2)\n• `logistics` (T2, +1)\n• `infra_es` (T3, +2)\n• `geo_es` (T3, +1)\n• `figures_es` (T3, +2)\n• `benign` (T4, -4)\n• `meta_quote` (T4, -2)\n• `ctx_downgrade` (-2)\n• `ctx_upgrade` (+3)\n\n**📌 Combinación:**\n• `threat+es_target` (+4)\n• `cyber+es_target` (+3)\n\n**📌 Comportamiento:**\n• `amplified:Ngrp/Nx` (+2)\n• `rep:CATEGORY_xN` (+3 c/u)\n• `fp_penalty:-N` (max -3)\n\n**📌 Metadata:**\n• `lang:es/en/ru`",
        },
    },
    "en": {
        "_menu_title": "❓ **HELP**\n━━━━━━━━━━━━━━━━━━━━\nPick a topic:",
        "about": {
            "label": "📖 About",
            "brief": "📖 **ABOUT**\n━━━━━━━━━━━━━━━━━━━━\n\nArachne monitors Telegram groups in real time and scores each message by threat level. Focused on Spanish-nexus content: threats against Spanish infrastructure, public figures, or territory.\n\nDoes NOT replace human analysis — classifies and prioritizes.",
            "more": "📖 **DETAILS**\n━━━━━━━━━━━━━━━━━━━━\n\n**Architecture:**\n• User account reads live messages\n• Bot account receives operator commands\n• Local SQLite with optimized indices\n• On-device ML models\n\n**Privacy:**\nData stays on server. No external sending, no cloud, no third parties.\n\n**Flags:**\n✅ Threats against Spanish targets\n✅ Imminent/planned violence\n✅ Weapons, explosives, CBRN\n✅ Recruitment, financing, logistics\n✅ Terrorist organizations\n✅ Hate speech + violence\n\n**Does not flag:**\n❌ DDoS against non-Spanish targets\n❌ Casual chatter\n❌ Academic/journalistic/fiction",
        },
        "detection": {
            "label": "🎯 How it detects",
            "brief": "🎯 **HOW IT DETECTS**\n━━━━━━━━━━━━━━━━━━━━\n\nTiered engine:\n• **Tier 1** — Hard signals\n• **Tier 2** — Medium signals\n• **Tier 3** — Spanish context\n• **Tier 4** — Dampeners\n\n**Co-occurrence rules** add bonus when threats combine with Spanish targets.",
            "more": "🎯 **DETAILS**\n━━━━━━━━━━━━━━━━━━━━\n\n**Pipeline:**\n1️⃣ Tokenization + language\n2️⃣ Category match → adds `weight`\n3️⃣ Context modifiers\n4️⃣ Co-occurrence rules\n5️⃣ ML: sentiment + hate-speech\n6️⃣ Repetition boost\n7️⃣ Cross-group amplification (+2)\n8️⃣ FP penalty (max -3)\n\n**Risk levels:**\n• 3+ LOW\n• 6+ MEDIUM (default threshold)\n• 10+ HIGH\n• 15+ CRITICAL",
        },
        "users": {
            "label": "👥 Users & risk",
            "brief": "👥 **USERS & RISK**\n━━━━━━━━━━━━━━━━━━━━\n\nScores actors over time, not just messages.\n\n0-100 risk score + classification:\n• `AGITATOR`\n• `BRIDGE`\n• `BRIDGE_STRONG`\n• `ACTIVE`\n• `SPAMMER`\n• `LOW_SIGNAL`",
            "more": "👥 **DETAILS**\n━━━━━━━━━━━━━━━━━━━━\n\n**Risk score formula:**\n```\nuser_risk = (avg_score * 0.4)\n          + (trigger_rate * 100 * 0.3)\n          + (burst_factor * 0.2)\n          + (group_factor * 0.1)\n          + (group_affinity * 0.2)\n```\n\n**Time decay:**\n• Last hour → 1.0\n• Last 24h → 0.5\n• Older → 0.2\n\n**Group affinity:**\nMeasures group overlap with other high-risk users. Random multi-group = noise. Multi-group sharing other high-risk users = real network node.",
        },
        "alerts": {
            "label": "⚡ Push alerts",
            "brief": "⚡ **PUSH ALERTS**\n━━━━━━━━━━━━━━━━━━━━\n\n**🚨 Per-message** — above threshold\n**⚡ Burst** — 3+ triggers/user in 10 min\n**📈 Escalation** — recent 10 msgs avg is 1.5x older 50\n\n30-min cooldown per user.",
            "more": "⚡ **DETAILS**\n━━━━━━━━━━━━━━━━━━━━\n\n**Cooldown:**\n30 min per user. Prevents spam during hot conversation.\n\n**Each push alert includes:**\n• Type (burst/escalation/both)\n• Trigger count\n• Avg + max score\n• Active groups\n• Full user profile\n\n**Audit log:**\nAll alerts logged to `alert_log` table.",
        },
        "dossiers": {
            "label": "📑 Profile summaries",
            "brief": "📑 **PROFILE SUMMARIES**\n━━━━━━━━━━━━━━━━━━━━\n\nTap **📑 Profile summary** + username:\n\n• Score and classification\n• Aggregated reasons\n• Per-group activity\n• Activity changes\n• Messages with the strongest signals\n• Recent chronology\n\nSaved in the local reports directory.",
            "more": "📑 **DETAILS**\n━━━━━━━━━━━━━━━━━━━━\n\n**TXT structure:**\n1. Header\n2. Full risk profile\n3. Aggregated reasons\n4. Per-group activity\n5. Burst history\n6. Escalation history\n7. Top 5 messages\n8. Full chronology\n\nChat summary + TXT file for external reports.",
        },
        "config": {
            "label": "🛠️ Configuration",
            "brief": "🛠️ **CONFIG**\n━━━━━━━━━━━━━━━━━━━━\n\n**🎯 Categories** — 16 preconfigured + your additions. Regex per language.\n**👥 Groups** — List, add, remove. Forward messages also works.\n**⚙️ Threshold** — Min alert score. Default: 6.",
            "more": "🛠️ **DETAILS**\n━━━━━━━━━━━━━━━━━━━━\n\n**Editing categories:**\n🎯 → category → language → view/add/remove\nInstant changes, no restart.\n\n**Config files:**\n• `scoring_config.json`\n• `keywords_config.json`\n\n**False positives:**\n`/falsepos <msg_id>` marks FP. After 5+ dismissals of same tag, deprioritized.",
        },
        "groups": {
            "label": "📥 Add groups",
            "brief": "📥 **ADD GROUPS**\n━━━━━━━━━━━━━━━━━━━━\n\nThree ways:\n\n1. **Forward** a message from the group\n2. **By ID** — 👥 Groups → ➕ Add → `-100...`\n3. **Auto-leave** — bot leaves unauthorized groups",
            "more": "📥 **DETAILS**\n━━━━━━━━━━━━━━━━━━━━\n\n**Requirements:**\n• User account must be member\n• Bot privacy: disable auto-join\n\n**No auto-backscan** — use **🔎 Backscan 7 days** for history.\n\n**Permissions:**\nOnly `ALLOWED_USERS` can interact. Rest ignored.",
        },
        "glossary": {
            "label": "❓ Tag glossary",
            "brief": "❓ **GLOSSARY**\n━━━━━━━━━━━━━━━━━━━━\n\nTags per alert:\n• **Categories** — `explosives`, `terror`, etc.\n• **Modifiers** — `cooccur:*`, `amplified:*`, etc.\n• **Metadata** — `lang:es/en/ru`",
            "more": "❓ **FULL GLOSSARY**\n━━━━━━━━━━━━━━━━━━━━\n\n**📌 Categories:**\n• `explosives` (T1, +5)\n• `terror` (T1, +4)\n• `weapons_hard` (T1, +3)\n• `cbrn` (T1, +5)\n• `imminent` (T1, +3)\n• `cyber` (T2, 0)\n• `violent_intent` (T2, +2)\n• `hate_target` (T2, +2)\n• `logistics` (T2, +1)\n• `infra_es` (T3, +2)\n• `geo_es` (T3, +1)\n• `figures_es` (T3, +2)\n• `benign` (T4, -4)\n• `meta_quote` (T4, -2)\n• `ctx_downgrade` (-2)\n• `ctx_upgrade` (+3)\n\n**📌 Combination:**\n• `threat+es_target` (+4)\n• `cyber+es_target` (+3)\n\n**📌 Behavior:**\n• `amplified:Ngrp/Nx` (+2)\n• `rep:CATEGORY_xN` (+3 each)\n• `fp_penalty:-N` (max -3)\n\n**📌 Metadata:**\n• `lang:es/en/ru`",
        },
    },
}


def get_pending_review_count():
    """Count alerts that haven't been reviewed."""
    try:
        row = db.execute("""
            SELECT COUNT(*) FROM alert_log
            WHERE alert_type IN ('message', 'burst', 'escalation')
              AND reviewed_at IS NULL
        """).fetchone()
        return row[0] if row else 0
    except Exception:
        return 0

def get_next_pending_alert(reviewer_id=None):
    """Fetch the oldest unreviewed alert."""
    try:
        row = db.execute("""
            SELECT id, ts, alert_type, user, chat_id, chat_title, score, risk_level,
                   user_risk, classification, reasons, msg_id, details,
                   llm_severity, llm_category, llm_flagged, llm_reasoning,
                   llm_model, llm_latency_ms, llm_error,
                   from_ocr, ocr_lang
            FROM alert_log
            WHERE alert_type IN ('message', 'burst', 'escalation')
              AND reviewed_at IS NULL
            ORDER BY ts ASC LIMIT 1
        """).fetchone()
        if not row:
            return None
        return {
            "id": row[0], "ts": row[1], "alert_type": row[2], "user": row[3],
            "chat_id": row[4], "chat_title": row[5], "score": row[6], "risk_level": row[7],
            "user_risk": row[8], "classification": row[9], "reasons": row[10],
            "msg_id": row[11], "details": row[12],
            "llm_severity": row[13], "llm_category": row[14],
            "llm_flagged": row[15], "llm_reasoning": row[16],
            "llm_model": row[17], "llm_latency_ms": row[18],
            "llm_error": row[19],
            "from_ocr": row[20], "ocr_lang": row[21],
        }
    except Exception as e:
        print(f"[REVIEW] get_next error: {redact_for_log(e)}")
        return None

def record_review(alert_id, verdict, reviewer_id):
    """Mark an alert as reviewed. verdict: 'confirmed' | 'false_pos' | 'skipped'"""
    if verdict not in ("confirmed", "false_pos", "skipped"):
        return False
    from datetime import datetime as _dt
    try:
        db.execute("""
            UPDATE alert_log
            SET reviewed_at = ?, reviewed_by = ?, review_verdict = ?
            WHERE id = ?
        """, (_dt.now(timezone.utc).isoformat(), reviewer_id, verdict, alert_id))
        db.commit()

        # If false_pos, feed it into the existing dismissal system
        if verdict == "false_pos":
            row = db.execute("""
                SELECT msg_id, chat_id, user, reasons, details FROM alert_log WHERE id = ?
            """, (alert_id,)).fetchone()
            if row and row[0]:
                msg_id, chat_id, user, reasons, details = row
                # Pull text from scored if msg_id exists there
                src = db.execute(
                    "SELECT text FROM scored WHERE msg_id = ? AND chat_id = ? LIMIT 1",
                    (msg_id, chat_id)
                ).fetchone()
                text = src[0] if src else (details or "")
                record_dismissal(msg_id, chat_id, user, reasons, text, str(reviewer_id))
        return True
    except Exception as e:
        print(f"[REVIEW] record error: {redact_for_log(e)}")
        return False

def get_review_stats(hours=24):
    """Return dict of review stats for the last N hours."""
    try:
        rows = db.execute("""
            SELECT
                SUM(CASE WHEN alert_type IN ('message','burst','escalation') THEN 1 ELSE 0 END) AS total,
                SUM(CASE WHEN review_verdict = 'confirmed' THEN 1 ELSE 0 END) AS confirmed,
                SUM(CASE WHEN review_verdict = 'false_pos' THEN 1 ELSE 0 END) AS false_pos,
                SUM(CASE WHEN review_verdict = 'skipped' THEN 1 ELSE 0 END) AS skipped,
                SUM(CASE WHEN reviewed_at IS NULL AND alert_type IN ('message','burst','escalation') THEN 1 ELSE 0 END) AS pending
            FROM alert_log
            WHERE ts >= datetime('now', ?)
        """, (f'-{hours} hours',)).fetchone()
        return {
            "total": rows[0] or 0,
            "confirmed": rows[1] or 0,
            "false_pos": rows[2] or 0,
            "skipped": rows[3] or 0,
            "pending": rows[4] or 0,
        }
    except Exception as e:
        print(f"[REVIEW] stats error: {redact_for_log(e)}")
        return {"total": 0, "confirmed": 0, "false_pos": 0, "skipped": 0, "pending": 0}

def format_review_card(alert, lang="es"):
    """Format an alert for the review screen."""
    if lang == "en":
        L = {
            "header": "🔍 **REVIEW QUEUE**",
            "type": "Type",
            "when": "When",
            "user": "User",
            "group": "Group",
            "score": "Score",
            "risk": "Risk",
            "user_risk": "User risk",
            "classification": "Class",
            "reasons": "Reasons",
            "msg": "Message",
            "link": "Link",
            "llm": "LLM verdict",
            "llm_sev": "severity",
            "llm_cat": "category",
            "llm_reason": "reasoning",
            "llm_pending": "(pending)",
            "llm_error": "error",
            "ocr": "from image (OCR)",
            "edits": "edits",
            "deleted": "DELETED at",
            "agree": "✅ agrees with regex",
            "disagree": "⚠️ disagrees with regex",
        }
    else:
        L = {
            "header": "🔍 **COLA DE REVISIÓN**",
            "type": "Tipo",
            "when": "Cuándo",
            "user": "Usuario",
            "group": "Grupo",
            "score": "Score",
            "risk": "Riesgo",
            "user_risk": "Risk usuario",
            "classification": "Clase",
            "reasons": "Motivos",
            "msg": "Mensaje",
            "link": "Enlace",
            "llm": "Veredicto LLM",
            "llm_sev": "severidad",
            "llm_cat": "categoría",
            "llm_reason": "razonamiento",
            "llm_pending": "(pendiente)",
            "llm_error": "error",
            "ocr": "desde imagen (OCR)",
            "edits": "ediciones",
            "deleted": "ELIMINADO a las",
            "agree": "✅ coincide con regex",
            "disagree": "⚠️ discrepa con regex",
        }

    reasons = alert.get("reasons") or ""
    text = alert.get("details") or ""
    if not text and alert.get("msg_id"):
        # Try pull text from scored table
        try:
            r = db.execute(
                "SELECT text FROM scored WHERE msg_id = ? AND chat_id = ? LIMIT 1",
                (alert["msg_id"], alert["chat_id"])
            ).fetchone()
            if r:
                text = r[0]
        except Exception:
            pass

    link = ""
    if alert.get("chat_id") and alert.get("msg_id"):
        cid = str(alert["chat_id"])
        if cid.startswith("-100"):
            link = f"https://t.me/c/{cid[4:]}/{alert['msg_id']}"

    msg = (
        f"{L['header']}\n━━━━━━━━━━━━━━━━━━━━\n\n"
        f"**{L['type']}:** `{alert.get('alert_type', '?')}`\n"
        f"**{L['when']}:** {(alert.get('ts') or '')[:19]}\n"
        f"**{L['user']}:** @{alert.get('user') or '?'}\n"
        f"**{L['group']}:** {alert.get('chat_title') or '?'}\n"
        f"**{L['score']}:** {alert.get('score') or '-'}  ·  **{L['risk']}:** {alert.get('risk_level') or '-'}\n"
    )
    if alert.get("user_risk") is not None:
        msg += f"**{L['user_risk']}:** {alert.get('user_risk')}  ·  **{L['classification']}:** `{alert.get('classification') or '-'}`\n"
    if reasons:
        msg += f"**{L['reasons']}:** {reasons}\n"
    if text:
        msg += f"\n**{L['msg']}:**\n{text[:1500]}\n"
    if link:
        msg += f"\n🔗 [{L['link']}]({link})\n"

    # ─── Patch 23: LLM verdict block ───────────────────────────────
    _p23_review_enriched = True
    sev = alert.get("llm_severity")
    cat = alert.get("llm_category")
    flg = alert.get("llm_flagged")
    reasoning = alert.get("llm_reasoning") or ""
    model = alert.get("llm_model") or ""
    latency = alert.get("llm_latency_ms")
    err = alert.get("llm_error")

    msg += "\n━━━━━━━━━━━━━━━━━━━━\n"
    if err:
        msg += f"🤖 **{L['llm']}:** {L['llm_error']} — `{err[:80]}`\n"
    elif sev is None:
        msg += f"🤖 **{L['llm']}:** {L['llm_pending']}\n"
    else:
        flag_emoji = "🚩" if flg else "✅"
        # Agreement signal: regex flagged (we got here), did LLM agree?
        agree_label = L["agree"] if flg else L["disagree"]
        msg += (
            f"🤖 **{L['llm']}** ({model}, {latency}ms): {flag_emoji} {agree_label}\n"
            f"   • **{L['llm_sev']}:** {sev:.2f}  ·  **{L['llm_cat']}:** `{cat or '-'}`\n"
        )
        if reasoning:
            msg += f"   • **{L['llm_reason']}:** _{reasoning[:300]}_\n"

    # ─── OCR origin marker ─────────────────────────────────────────
    if alert.get("from_ocr"):
        ocr_lang = alert.get("ocr_lang") or "?"
        msg += f"🖼 **{L['ocr']}** ({ocr_lang})\n"

    # ─── Edit / delete forensics ───────────────────────────────────
    # Look up chat_context for this msg_id to get edit_count + deleted_at
    try:
        if alert.get("chat_id") and alert.get("msg_id"):
            ctx_row = db.execute(
                "SELECT edit_count, last_edited_at, deleted_at, edit_history "
                "FROM chat_context "
                "WHERE chat_id = ? AND msg_id = ? "
                "ORDER BY id DESC LIMIT 1",
                (alert["chat_id"], alert["msg_id"])
            ).fetchone()
            if ctx_row:
                ec, last_ed, deleted, hist = ctx_row
                if ec and ec > 0:
                    last_short = (last_ed or "")[:19].replace("T", " ")
                    msg += f"✏️ **{L['edits']}:** {ec} (last: {last_short})\n"
                if deleted:
                    deleted_short = deleted[:19].replace("T", " ")
                    msg += f"🗑 **{L['deleted']}:** {deleted_short}\n"
    except Exception as _p23e:
        pass
    # ───────────────────────────────────────────────────────────────

    return msg

def review_buttons(alert_id, lang="es"):
    if lang == "en":
        return [
            [Button.inline("✅ Confirmed", f"rev_yes_{alert_id}".encode()),
             Button.inline("❌ False positive", f"rev_no_{alert_id}".encode())],
            [Button.inline("⏭️ Skip", f"rev_skip_{alert_id}".encode()),
             Button.inline("🏠 Home", b"back_main")],
        ]
    return [
        [Button.inline("✅ Confirmado", f"rev_yes_{alert_id}".encode()),
         Button.inline("❌ Falso positivo", f"rev_no_{alert_id}".encode())],
        [Button.inline("⏭️ Saltar", f"rev_skip_{alert_id}".encode()),
         Button.inline("🏠 Inicio", b"back_main")],
    ]


def help_menu_buttons(uid):
    lang = get_user_language(uid)
    other = "en" if lang == "es" else "es"
    other_flag = "🇬🇧 English" if other == "en" else "🇪🇸 Español"
    topics = HELP_TOPICS[lang]
    rows = [[Button.inline(other_flag, f"helplang_{other}".encode())]]
    for key in ("about", "detection", "users", "alerts", "dossiers", "config", "groups", "glossary"):
        rows.append([Button.inline(topics[key]["label"], f"helptopic_{key}".encode())])
    rows.append([Button.inline("⬅️ Volver" if lang == "es" else "⬅️ Back", b"back_main")])
    return rows

def help_topic_buttons(uid, topic):
    lang = get_user_language(uid)
    more_label = "🔍 Más detalles" if lang == "es" else "🔍 More details"
    back_help = "⬅️ Ayuda" if lang == "es" else "⬅️ Help"
    home = "🏠 Inicio" if lang == "es" else "🏠 Home"
    return [
        [Button.inline(more_label, f"helpmore_{topic}".encode())],
        [Button.inline(back_help, b"help"), Button.inline(home, b"back_main")],
    ]

def help_more_buttons(uid):
    lang = get_user_language(uid)
    back_help = "⬅️ Ayuda" if lang == "es" else "⬅️ Help"
    home = "🏠 Inicio" if lang == "es" else "🏠 Home"
    return [[Button.inline(back_help, b"help"), Button.inline(home, b"back_main")]]


def categories_menu_buttons():
    """Submenu listing all categories with summary."""
    rows = []
    summary = get_category_summary()
    for name, tier, weight, n_en, n_es, n_ru in summary:
        n_total = n_en + n_es + n_ru
        label = f"T{tier} w{weight:+d} {name} ({n_total})"
        rows.append([Button.inline(label[:64], f"cat_{name}".encode())])
    rows.append([Button.inline("⬅️ Volver", b"back_main")])
    return rows

def category_detail_buttons(cat_name):
    """View one category — show language tabs + add/remove."""
    cat = COMPILED_CATEGORIES.get(cat_name, {})
    n_en = len(cat.get("raw_en", []))
    n_es = len(cat.get("raw_es", []))
    n_ru = len(cat.get("raw_ru", []))
    return [
        [Button.inline(f"🇬🇧 EN ({n_en})", f"catlang_{cat_name}_en".encode()),
         Button.inline(f"🇪🇸 ES ({n_es})", f"catlang_{cat_name}_es".encode()),
         Button.inline(f"🇷🇺 RU ({n_ru})", f"catlang_{cat_name}_ru".encode())],
        [Button.inline("➕ Añadir patrón", f"catadd_{cat_name}".encode()),
         Button.inline("➖ Quitar patrón", f"catrm_{cat_name}".encode())],
        [Button.inline("⬅️ Categorías", b"cats_menu"),
         Button.inline("🏠 Inicio", b"back_main")],
    ]

def groups_menu_buttons():
    """Submenu for group management."""
    return [
        [Button.inline("📋 Ver grupos activos", b"list_grp")],
        [Button.inline("➕ Añadir grupo", b"add_grp"), Button.inline("➖ Quitar grupo", b"rm_grp")],
        [Button.inline("⬅️ Volver", b"back_main")],
    ]


def _safe_json_list(value):
    try:
        result = json.loads(value or "[]")
        return result if isinstance(result, list) else []
    except (TypeError, ValueError):
        return []


def _format_onion_hits(hits):
    if not hits:
        return "🧅 No pending onion hits."
    cards = []
    for hit in hits[:5]:
        indicators = _safe_json_list(hit.get("indicators_json"))
        exposures = _safe_json_list(hit.get("passive_exposures_json"))
        exp_summary = "\n".join(f"- {e.get('type')}: {e.get('severity')}" for e in exposures[:5]) or "- None"
        ind_summary = ", ".join(f"{i.get('type')}={i.get('value')}" for i in indicators[:5]) or "None"
        cards.append(
            "🧅 ONION HIT\n\n"
            f"Title: {(hit.get('title') or 'Untitled')[:200]}\n"
            f"URL: {hit.get('url')}\nScore: {hit.get('score')}\nRisk: {hit.get('risk_level')}\n"
            f"Reasons: {hit.get('reasons') or '[]'}\nRisk flags: stored on URL record\n"
            f"Indicators: {ind_summary}\nPassive exposures:\n{exp_summary}\n"
            f"Source: {hit.get('source_chain') or 'manual/passive discovery'}\n"
            f"Snippet: {(hit.get('snippet') or '')[:700]}\nReview status: {hit.get('review_status')}"
        )
    return "\n\n".join(cards)[:3900]


def _format_cluster_list(clusters):
    if not clusters:
        return "🪞 No mirror clusters."
    return ("🪞 MIRROR CLUSTERS\n\n" + "\n".join(
        f"#{c['id']} | {c.get('cluster_type') or 'unknown'} | {c.get('risk_level')} | {c.get('status')} | {(c.get('summary') or '')[:120]}"
        for c in clusters[:15]
    ))[:3900]


def _format_cluster(cluster):
    urls = cluster.get("urls", [])
    attribution = _safe_json_list("[]")
    try:
        attribution = json.loads(cluster.get("attribution_profile_json") or "{}")
    except (TypeError, ValueError):
        attribution = {}
    shared = _safe_json_list(cluster.get("shared_indicators_json"))
    return (
        "🪞 MIRROR CLUSTER\n\n"
        f"Cluster ID: {cluster.get('id')}\nType: {cluster.get('cluster_type')}\nRisk: {cluster.get('risk_level')}\n"
        f"Status: {cluster.get('status')}\nFirst seen: {cluster.get('first_seen')}\nLast seen: {cluster.get('last_seen')}\n"
        f"URLs: {len(urls)}\nShared indicators: {', '.join(shared[:8]) or 'None'}\n"
        f"Passive attribution: {attribution.get('confidence_level', 'not built')} {attribution.get('confidence_score', '')}\n"
        f"Summary: {(cluster.get('summary') or '')[:700]}\nReview status: {cluster.get('review_status')}"
    )[:3900]


def _telegram_push_alerts_enabled() -> bool:
    """True only when automatic Telegram pushes are explicitly enabled."""
    return bool(TELEGRAM_AUTO_ALERTS_ENABLED and not TELEGRAM_MANUAL_PULL_ONLY)


def _format_manual_spain_pull(rows):
    from spain_alerts import payload_from_queue_row
    if not rows:
        return "Spain pending: none. Quiet mode is active."
    parts = ["Spain pending (manual pull only):"]
    for row in rows[:5]:
        payload = payload_from_queue_row(row)
        title = payload.get("display_name") or payload.get("title") or payload.get("category") or "Spain item"
        parts.append(
            f"\n#{row.get('id')} {title}\n"
            f"Risk: {payload.get('risk_level') or 'unknown'} | Category: {payload.get('category') or 'unknown'}\n"
            f"Reason: {payload.get('reason') or payload.get('spain_match_reason') or 'Spain evidence'}\n"
            f"URL: {payload.get('url') or row.get('url')}"
        )
    parts.append("\nNo alerts were sent or marked sent.")
    return "\n".join(parts)[:3900]


def _format_manual_urgent_pull(rows):
    if not rows:
        return "Urgent pull: none. Quiet mode is active."
    parts = ["Urgent cards (manual pull only):"]
    for card in rows[:5]:
        title = card.get("analyst_title") or card.get("display_name") or f"Site Card #{card.get('id')}"
        parts.append(
            f"\n#{card.get('id')} {title}\n"
            f"Risk: {card.get('risk_level') or 'unknown'} | Importance: {card.get('importance_level') or 'normal'}\n"
            f"Category: {card.get('primary_category') or 'unknown'} | Review: {card.get('review_status') or 'unknown'}\n"
            f"Urgent score: {card.get('urgent_score') or 0} | Spain: {bool(card.get('spain_priority'))}\n"
            f"Reason: {card.get('urgent_reason') or 'priority evidence'}\n"
            f"URL: {card.get('representative_url') or 'not stored'}"
        )
    parts.append("\nNo alerts were sent or marked sent.")
    return "\n".join(parts)[:3900]


def _format_dashboard_access_status() -> str:
    status = dashboard_auth.dashboard_access_status()
    if status.get("storage_error"):
        return (
            "Dashboard access storage is unavailable.\n\n"
            "The access page remains locked closed. Check runtime/dashboard_access.db "
            "and runtime directory permissions, then retry."
        )
    enabled = "enabled" if status["enabled"] else "disabled"
    code = "yes" if status["active_code"] else "no"
    expires = status.get("active_code_expires_at") or "none"
    return (
        "Dashboard access lock\n\n"
        f"Lock: {enabled}\n"
        f"Active unused code: {code}\n"
        f"Code expires: {expires}\n"
        f"Active sessions: {status['active_sessions']}\n\n"
        "Commands:\n"
        "/dashboard_code <duration> [admin|analyst|demo_readonly] - create one-time code\n"
        "/dashboard_clear_codes - clear unused codes only\n"
        "/dashboard_lock_on - require access codes\n"
        "/dashboard_lock_off - disable the access-code page for development"
    )


def _format_dashboard_code_message(result: dict) -> str:
    if not result.get("code"):
        error = result.get("error") or result.get("reason") or "unknown error"
        return (
        "Dashboard access code could not be created.\n\n"
            f"Reason: {error}\n\n"
            "Check runtime/dashboard_access.db permissions and restart the bot if needed."
        )
    seconds = int(result.get("duration_seconds") or 0)
    label = f"{seconds // 3600} hour(s)" if seconds % 3600 == 0 and seconds >= 3600 else f"{seconds // 60} minute(s)" if seconds % 60 == 0 else f"{seconds} seconds"
    role = dashboard_auth.normalize_role(result.get("role")) or dashboard_auth.ROLE_ADMIN
    return (
        "Dashboard access code:\n\n"
        f"{result['code']}\n\n"
        f"Role: {role}\n"
        f"Valid for: {label}\n"
        f"Expires: {result['expires_at']}\n"
        "One-time use. After browser unlock, this code becomes obsolete."
    )


async def _send_sanitized_diagnostics(event, hours: int = 24) -> bool:
    """Build and send only the fixed-schema diagnostic bundle to an admin."""
    if not _is_dashboard_admin(event):
        await event.respond("Not authorized.")
        return False
    recipient_id = int(getattr(event, "sender_id", 0) or 0)
    if not recipient_id:
        await event.respond("Sanitized diagnostics require an authenticated private recipient.")
        return False
    bounded_hours = max(1, min(int(hours or 24), 168))
    try:
        bundle = await asyncio.to_thread(
            operations.build_sanitized_diagnostic_bundle,
            hours=bounded_hours,
        )
        max_bytes = max(1024 * 1024, min(
            get_int("TELEGRAM_DIAGNOSTIC_MAX_BYTES", 10 * 1024 * 1024),
            20 * 1024 * 1024,
        ))
        if bundle.stat().st_size > max_bytes:
            await event.respond(
                "The sanitized diagnostic bundle exceeds the configured Telegram size limit. "
                "Use the server control menu to build it locally."
            )
            return False
        await bot.send_file(
            recipient_id,
            bundle,
            caption=(
                f"Arachne sanitized operational diagnostics ({bounded_hours}h). "
                "No raw URLs, page content, credentials, sessions, or personal identifiers."
            ),
        )
        return True
    except Exception as exc:
        logging.getLogger("arachne").warning(
            "Sanitized diagnostic bundle unavailable: %s", type(exc).__name__
        )
        await event.respond("Sanitized diagnostics could not be built. Check the server control menu.")
        return False


@bot.on(events.NewMessage(pattern=r'^/(?:diagnostics|diagnostic_bundle|ops_bundle)(?:\s|$)'))
async def diagnostic_bundle_command(event):
    if not await _require_dashboard_admin(event):
        return
    parts = event.raw_text.split(maxsplit=1)
    if len(parts) == 2 and (not parts[1].isdigit() or not 1 <= int(parts[1]) <= 168):
        await event.respond("Usage: /diagnostics [hours], where hours is 1 to 168.")
        return
    await _send_sanitized_diagnostics(event, int(parts[1]) if len(parts) == 2 else 24)


@bot.on(events.NewMessage(pattern=r'^/onion_pending(?:\s|$)'))
async def onion_pending_command(event):
    if not await _require_dashboard_admin(event) or not await _require_telegram_data(event):
        return
    await event.respond(_format_onion_hits(osint_storage.get_pending_onion_hits(10)))


@bot.on(events.NewMessage(pattern=r'^/onion_status(?:\s|$)'))
async def onion_status_command(event):
    if not await _require_dashboard_admin(event) or not await _require_telegram_data(event):
        return
    osint_storage.init_db()
    with osint_storage.get_db() as conn:
        status = {name: conn.execute("SELECT COUNT(*) FROM onion_urls WHERE status=?", (name,)).fetchone()[0]
                  for name in ("queued", "crawled", "blocked", "dead")}
        status["hits"] = conn.execute("SELECT COUNT(*) FROM onion_hits").fetchone()[0]
        status["clusters"] = conn.execute("SELECT COUNT(*) FROM mirror_clusters").fetchone()[0]
    await event.respond("🧅 Onion worker status\n\n" + "\n".join(f"{k}: {v}" for k, v in status.items()))


@bot.on(events.NewMessage(pattern=r'^/(?:latest_spain|spain_pending)(?:\s|$)'))
async def latest_spain_command(event):
    if not await _require_dashboard_admin(event) or not await _require_telegram_data(event):
        return
    await event.respond(_format_manual_spain_pull(osint_storage.get_spain_alerts_for_manual_pull(5)))


@bot.on(events.NewMessage(pattern=r'^/(?:latest_urgent|urgent)(?:\s|$)'))
async def latest_urgent_command(event):
    if not await _require_dashboard_admin(event) or not await _require_telegram_data(event):
        return
    await event.respond(_format_manual_urgent_pull(osint_storage.get_urgent_cards_for_manual_pull(5)))


@bot.on(events.NewMessage(pattern=r'^/dashboard_status(?:\s|$)'))
async def dashboard_status_command(event):
    if not await _require_dashboard_admin(event):
        return
    await event.respond(_format_dashboard_access_status())


@bot.on(events.NewMessage(pattern=r'^/(?:dashboard_code|code|unlock|access_code)(?:\s|$)'))
async def dashboard_code_command(event):
    if not await _require_dashboard_admin(event):
        return
    parts = event.raw_text.split()
    if len(parts) > 3:
        await event.respond(
            "Usage: /dashboard_code <duration> [admin|analyst|demo_readonly]")
        return
    duration = dashboard_auth.duration_seconds(parts[1] if len(parts) > 1 else "1h")
    role = parts[2] if len(parts) > 2 else dashboard_auth.ROLE_ADMIN
    if dashboard_auth.normalize_role(role) is None:
        await event.respond(
            "Unknown role. Use admin, analyst, or demo_readonly.")
        return
    result = dashboard_auth.generate_dashboard_code(
        duration, event.sender_id, role=role)
    await event.respond(_format_dashboard_code_message(result))


@bot.on(events.NewMessage(pattern=r'^/dashboard_revoke(?:\s|$)'))
async def dashboard_revoke_command(event):
    if not await _require_dashboard_admin(event):
        return
    try:
        revoked = dashboard_auth.revoke_dashboard_codes(revoke_sessions=False, updated_by=f"telegram:{event.sender_id}")
    except RuntimeError:
        await event.respond("Dashboard access storage is unavailable. No codes were changed.")
        return
    await event.respond(f"Unused dashboard access codes cleared. Active sessions kept. Codes cleared: {revoked}")


@bot.on(events.NewMessage(pattern=r'^/dashboard_clear_codes(?:\s|$)'))
async def dashboard_clear_codes_command(event):
    if not await _require_dashboard_admin(event):
        return
    try:
        revoked = dashboard_auth.revoke_dashboard_codes(revoke_sessions=False, updated_by=f"telegram:{event.sender_id}")
    except RuntimeError:
        await event.respond("Dashboard access storage is unavailable. No codes were changed.")
        return
    await event.respond(f"Unused dashboard access codes cleared. Active sessions kept. Codes cleared: {revoked}")


@bot.on(events.NewMessage(pattern=r'^/dashboard_lock_on(?:\s|$)'))
async def dashboard_lock_on_command(event):
    if not await _require_dashboard_admin(event):
        return
    try:
        dashboard_auth.set_dashboard_lock_enabled(True, f"telegram:{event.sender_id}")
    except RuntimeError:
        await event.respond("Dashboard access storage is unavailable. The access page remains locked closed.")
        return
    await event.respond("Dashboard lock enabled. Generate a code with /dashboard_code 1h.")


@bot.on(events.NewMessage(pattern=r'^/dashboard_lock_off(?:\s|$)'))
async def dashboard_lock_off_command(event):
    if not await _require_dashboard_admin(event):
        return
    try:
        dashboard_auth.set_dashboard_lock_enabled(False, f"telegram:{event.sender_id}")
    except RuntimeError:
        await event.respond("Dashboard access storage is unavailable. The access page was not disabled.")
        return
    await event.respond("Dashboard lock disabled. Active codes and sessions were revoked.")


@bot.on(events.NewMessage(pattern=r'^/mirror_clusters(?:\s|$)'))
async def mirror_clusters_command(event):
    if not await _require_dashboard_admin(event) or not await _require_telegram_data(event):
        return
    await event.respond(_format_cluster_list(osint_storage.get_mirror_clusters(20)))


@bot.on(events.NewMessage(pattern=r'^/mirror_cluster(?:\s|$)'))
async def mirror_cluster_command(event):
    if not await _require_dashboard_admin(event) or not await _require_telegram_data(event):
        return
    parts = event.raw_text.split(maxsplit=1)
    if len(parts) != 2 or not parts[1].isdigit():
        await event.respond("Usage: `/mirror_cluster <id>`")
        return
    cluster = osint_storage.get_mirror_cluster(int(parts[1]))
    await event.respond(_format_cluster(cluster) if cluster else "Cluster not found.")


@bot.on(events.NewMessage(pattern=r'^/report_cluster(?:\s|$)'))
async def report_cluster_command(event):
    if not await _require_dashboard_admin(event) or not await _require_telegram_data(event):
        return
    parts = event.raw_text.split(maxsplit=1)
    if len(parts) != 2 or not parts[1].isdigit():
        await event.respond("Usage: `/report_cluster <id>`")
        return
    try:
        from report_builder import build_cluster_report
        output = build_cluster_report(int(parts[1]), generated_by=f"telegram:{event.sender_id}")
        await event.respond(f"📄 Safe Markdown report generated:\n`{output}`")
    except ValueError:
        await event.respond("Cluster not found.")


@bot.on(events.NewMessage(pattern=r'^/indicator_search(?:\s|$)'))
async def indicator_search_command(event):
    if not await _require_dashboard_admin(event) or not await _require_telegram_data(event):
        return
    parts = event.raw_text.split(maxsplit=1)
    if len(parts) != 2 or not parts[1].strip():
        await event.respond("Usage: `/indicator_search <value>`")
        return
    rows = osint_storage.get_indicators_by_value(parts[1].strip())
    message = "🔎 INDICATOR SEARCH\n\n" + ("\n".join(
        f"{r['indicator_type']}: {r['value']} | {r.get('link_source_type') or r.get('source_type')} | {(r.get('context_snippet') or '')[:250]}"
        for r in rows[:15]) if rows else "No matches.")
    await event.respond(message[:3900])


@bot.on(events.NewMessage(pattern=r'^/attribution(?:\s|$)'))
async def attribution_command(event):
    if not await _require_dashboard_admin(event) or not await _require_telegram_data(event):
        return
    parts = event.raw_text.split(maxsplit=1)
    if len(parts) != 2 or not parts[1].isdigit():
        await event.respond("Usage: `/attribution <cluster_id>`")
        return
    try:
        from passive_attribution import build_attribution_profile
        p = build_attribution_profile(int(parts[1]))
    except ValueError:
        await event.respond("Cluster not found.")
        return
    message = (
        "🧭 PASSIVE ATTRIBUTION\n\n"
        f"Cluster ID: {p['cluster_id']}\nConfidence: {p['confidence_level']} ({p['confidence_score']}/100)\n"
        f"Shared handles: {', '.join(p['shared_handles']) or 'None'}\nShared wallets: {', '.join(p['shared_wallets']) or 'None'}\n"
        f"Shared emails: {', '.join(p['shared_emails']) or 'None'}\n"
        f"Shared domains: {', '.join((p['shared_onion_domains'] + p['shared_clearnet_domains'])[:10]) or 'None'}\n"
        f"Shared hashes: {', '.join(p['shared_content_hashes'][:5]) or 'None'}\n"
        f"Explanation: {p['explanation']}\nLimitations: {p['limitations']}"
    )
    await event.respond(message[:3900])



@bot.on(events.NewMessage(pattern='/start|/menu'))
async def menu_handler(event):
    if not await _require_dashboard_admin(event):
        return
    uid = event.sender_id
    await event.respond(
        main_menu_header(uid),
        buttons=main_menu_buttons(uid)
    )

@bot.on(events.CallbackQuery)
async def callback_handler(event):
    try:
        await event.answer()
    except Exception:
        pass
    if not await _require_dashboard_admin(event):
        return
    data = event.data.decode()
    uid = event.sender_id

    # Access-code controls deliberately remain usable while messages.db is
    # unavailable; every other callback requires the normal data store.
    if not data.startswith(("dashboard_", "ops_")) and not await _require_telegram_data(event):
        return

    if data == "ops_diagnostics":
        await _send_sanitized_diagnostics(event, 24)
    elif data == "toggle_spain_alerts":
        if not _telegram_push_alerts_enabled():
            osint_storage.set_spain_alerts_paused(True, "telegram_manual_pull_mode")
            await event.respond(
                "Automatic Spain alert pushes are disabled by server configuration. "
                "Manual /latest_spain remains available.",
                buttons=main_menu_buttons(uid),
            )
            return
        paused = not osint_storage.spain_alerts_paused()
        osint_storage.set_spain_alerts_paused(paused, "telegram_admin")
        lang = get_user_language(uid)
        message = (("⏸️ Alertas de España pausadas. La cola se conserva y el bot sigue respondiendo."
                    if lang == "es" else
                    "⏸️ Spain alerts paused. The queue is retained and the bot remains controllable.")
                   if paused else
                   ("▶️ Alertas de España reanudadas." if lang == "es" else "▶️ Spain alerts resumed."))
        await event.respond(message, buttons=main_menu_buttons(uid))
    elif data == "onion_hits":
        await event.respond(_format_onion_hits(osint_storage.get_pending_onion_hits(5)), buttons=main_menu_buttons(uid))
    elif data == "latest_spain":
        await event.respond(_format_manual_spain_pull(osint_storage.get_spain_alerts_for_manual_pull(5)), buttons=main_menu_buttons(uid))
    elif data == "latest_urgent":
        await event.respond(_format_manual_urgent_pull(osint_storage.get_urgent_cards_for_manual_pull(5)), buttons=main_menu_buttons(uid))
    elif data == "quiet_mode":
        await event.respond("Quiet/manual-pull mode is active. Use /latest_spain or /latest_urgent. Automatic Telegram alert pushes remain off.", buttons=main_menu_buttons(uid))
    elif data == "mirror_clusters":
        await event.respond(_format_cluster_list(osint_storage.get_mirror_clusters(10)), buttons=main_menu_buttons(uid))
    elif data == "indicator_search":
        await event.respond("Use `/indicator_search <value>` to inspect stored passive indicators.", buttons=main_menu_buttons(uid))
    elif data == "build_cluster_report":
        await event.respond("Use `/report_cluster <id>` to build a safe Markdown evidence report.", buttons=main_menu_buttons(uid))
    elif data == "passive_attribution":
        await event.respond("Use `/attribution <cluster_id>` for a passive-only correlation profile.", buttons=main_menu_buttons(uid))
    elif data.startswith("dashboard_"):
        if data == "dashboard_code_custom":
            pending_action[uid] = "dashboard_code_minutes"
            await event.respond(
                "Send how many minutes the one-time dashboard code should remain valid "
                "(1 to 10080).",
                buttons=main_menu_buttons(uid),
            )
        elif data == "dashboard_code_15m":
            result = dashboard_auth.generate_dashboard_code(900, uid)
            await event.respond(_format_dashboard_code_message(result), buttons=main_menu_buttons(uid))
        elif data == "dashboard_code_1h":
            result = dashboard_auth.generate_dashboard_code(3600, uid)
            await event.respond(_format_dashboard_code_message(result), buttons=main_menu_buttons(uid))
        elif data == "dashboard_lock_status":
            await event.respond(_format_dashboard_access_status(), buttons=main_menu_buttons(uid))
        elif data in {"dashboard_revoke", "dashboard_clear_codes"}:
            try:
                revoked = dashboard_auth.revoke_dashboard_codes(revoke_sessions=False, updated_by=f"telegram:{uid}")
            except RuntimeError:
                await event.respond("Dashboard access storage is unavailable. No codes were changed.",
                                    buttons=main_menu_buttons(uid))
                return
            await event.respond(f"Unused dashboard access codes cleared. Active sessions kept. Codes cleared: {revoked}",
                                buttons=main_menu_buttons(uid))
        elif data == "dashboard_lock_on":
            try:
                dashboard_auth.set_dashboard_lock_enabled(True, f"telegram:{uid}")
            except RuntimeError:
                await event.respond("Dashboard access storage is unavailable. The access page remains locked closed.",
                                    buttons=main_menu_buttons(uid))
                return
            await event.respond("Access-code page enabled. Generate a code with the menu or /dashboard_code 60.",
                                buttons=main_menu_buttons(uid))
        elif data == "dashboard_lock_off":
            try:
                dashboard_auth.set_dashboard_lock_enabled(False, f"telegram:{uid}")
            except RuntimeError:
                await event.respond("Dashboard access storage is unavailable. The access page was not disabled.",
                                    buttons=main_menu_buttons(uid))
                return
            await event.respond("Access-code page disabled for development. Dashboard opens without a code until re-enabled.",
                                buttons=main_menu_buttons(uid))
    elif data == "stats":
        cur = db.execute("SELECT risk, COUNT(*) FROM scored GROUP BY risk ORDER BY MIN(score) DESC")
        rows = cur.fetchall()
        total = db.execute("SELECT COUNT(*) FROM scored").fetchone()[0]
        msg = f"📊 **Estadísticas**\n\nTotal mensajes analizados: **{total}**\n\n"
        for risk, count in rows:
            msg += f"• {risk}: {count}\n"
        await event.respond(msg, buttons=main_menu_buttons(uid))

    elif data == "recent":
        cur = db.execute(
            "SELECT ts, chat_title, user, score, risk, reasons, substr(text,1,200) "
            "FROM scored WHERE score >= ? ORDER BY id DESC LIMIT 10",
            (config["alert_threshold"],)
        )
        rows = cur.fetchall()
        if not rows:
            await event.respond("No hay alertas todavía.", buttons=main_menu_buttons(uid))
            return
        msg = "🚩 **Últimas 10 alertas**\n\n"
        for _ts, title, user, score, risk, reasons, txt in rows:
            msg += f"**{risk}** ({score}) — {title} / @{user}\n"
            msg += f"_{reasons}_\n{txt}\n\n"
        await event.respond(msg[:4000], buttons=main_menu_buttons(uid))

    elif data == "week":
        cur = db.execute(
            "SELECT risk, COUNT(*) FROM scored WHERE date(ts) >= date('now', '-7 days') GROUP BY risk"
        )
        rows = cur.fetchall()
        total = db.execute(
            "SELECT COUNT(*) FROM scored WHERE date(ts) >= date('now', '-7 days')"
        ).fetchone()[0]
        alerts = db.execute(
            "SELECT COUNT(*) FROM scored WHERE date(ts) >= date('now', '-7 days') AND score >= ?",
            (config["alert_threshold"],)
        ).fetchone()[0]
        msg = f"📅 **Últimos 7 días**\n\nTotal: **{total}** mensajes\nAlertas: **{alerts}**\n\n"
        for risk, count in rows:
            msg += f"• {risk}: {count}\n"
        await event.respond(msg, buttons=main_menu_buttons(uid))

    elif data == "search":
        pending_action[uid] = "search"
        await event.respond("Envía el texto a buscar:")

    elif data == "add_kw":
        pending_action[uid] = "add_keyword"
        await event.respond("Envía la keyword a añadir (texto plano, sin regex):")

    elif data == "rm_kw":
        pending_action[uid] = "remove_keyword"
        await event.respond("Envía la keyword exacta a eliminar:")

    elif data == "list_kw":
        if not custom_keywords:
            await event.respond("No hay keywords personalizadas.", buttons=main_menu_buttons(uid))
        else:
            msg = "📋 **Keywords personalizadas:**\n\n" + "\n".join(f"• {k}" for k in custom_keywords)
            await event.respond(msg, buttons=main_menu_buttons(uid))

    elif data == "add_grp":
        pending_action[uid] = "add_group"
        await event.respond(
            "Envía el ID del grupo a añadir (formato: `-1001234567890`).\n\n"
            "Para obtener el ID de un grupo: reenvía un mensaje del grupo a @userinfobot, "
            "o usa @getidsbot dentro del grupo."
        )

    elif data == "rm_grp":
        pending_action[uid] = "remove_group"
        current = "\n".join(f"• `{g}`" for g in config["active_groups"])
        await event.respond(f"Grupos activos:\n{current}\n\nEnvía el ID a quitar:")

    elif data == "list_grp":
        if not config["active_groups"]:
            await event.respond("No hay grupos activos.", buttons=main_menu_buttons(uid))
        else:
            msg = "📋 **Grupos monitorizados:**\n\n"
            for gid in config["active_groups"]:
                try:
                    entity = await client.get_entity(gid)
                    title = getattr(entity, "title", "?")
                    msg += f"• `{gid}` — {title}\n"
                except Exception as e:
                    msg += f"• `{gid}` — (error: {str(e)[:40]})\n"
            await event.respond(msg, buttons=main_menu_buttons(uid))

    elif data == "last_group":
        if not config["active_groups"]:
            await event.respond("No hay grupos activos.", buttons=main_menu_buttons(uid))
            return
        rows = []
        for gid in config["active_groups"]:
            try:
                entity = await client.get_entity(gid)
                title = getattr(entity, "title", str(gid))[:30]
            except Exception:
                title = str(gid)
            rows.append([Button.inline(f"📥 {title}", f"fetch_{gid}".encode())])
        rows.append([Button.inline("⬅️ Volver", b"back_main")])
        await event.respond("Elige el grupo:", buttons=rows)

    elif data.startswith("fetch_"):
        gid = int(data.split("_", 1)[1])
        try:
            entity = await client.get_entity(gid)
            title = getattr(entity, "title", str(gid))
            msgs = await client.get_messages(entity, limit=20)
            if not msgs:
                await event.respond(f"Sin mensajes en **{title}**.", buttons=main_menu_buttons(uid))
                return
            out = f"📥 **Últimos 20 en {title}**\n\n"
            for m in msgs:
                ts = m.date.strftime("%Y-%m-%d %H:%M")
                sender = ""
                if m.sender:
                    sender = f"@{m.sender.username}" if m.sender.username else (m.sender.first_name or "Anon")
                txt = (m.message or "[sin texto / media]")[:300]
                s, _ = score_text(m.message or "")
                out += f"`{ts}` {sender} _(score {s})_\n{txt}\n\n"
            await event.respond(out[:4000], buttons=main_menu_buttons(uid))
        except Exception as e:
            await event.respond(f"⚠️ Error leyendo grupo: {str(e)[:200]}",
                                buttons=main_menu_buttons(uid))

    elif data == "back_main":
        await event.respond(main_menu_header(uid), buttons=main_menu_buttons(uid))
        return

    elif data == "backscan":
        if not config["active_groups"]:
            await event.respond("No hay grupos activos.", buttons=main_menu_buttons(uid))
            return
        await event.respond("🔎 Escaneando últimos 7 días en todos los grupos... esto puede tardar un poco.")
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        total_scanned = 0
        flagged = []
        for gid in config["active_groups"]:
            try:
                entity = await client.get_entity(gid)
                title = getattr(entity, "title", str(gid))
                async for m in client.iter_messages(entity, offset_date=None, reverse=False):
                    if m.date < cutoff:
                        break
                    total_scanned += 1
                    txt = m.message or ""
                    if not txt.strip():
                        continue
                    s, reasons = score_text(txt)
                    risk = risk_level(s)
                    # Insert if not already in DB (avoid dupes from live handler)
                    sender = ""
                    if m.sender:
                        sender = m.sender.username if m.sender.username else (m.sender.first_name or "Anon")
                    exists = db.execute(
                        "SELECT id FROM scored WHERE chat_id=? AND msg_id=?",
                        (gid, m.id)
                    ).fetchone()
                    if exists:
                        db.execute(
                            "UPDATE scored SET score=?, risk=?, reasons=? WHERE id=?",
                            (s, risk, ",".join(reasons), exists[0])
                        )
                    else:
                        db.execute(
                            "INSERT INTO scored (ts, chat_id, chat_title, user, msg_id, text, score, risk, reasons) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (m.date.isoformat(), gid, title, sender, m.id, txt, s, risk, ",".join(reasons))
                        )
                    if s >= config["alert_threshold"]:
                        flagged.append((m.date, title, s, risk, reasons, txt[:200], gid, m.id))
                db.commit()
            except Exception as e:
                await event.respond(f"⚠️ Error en grupo {gid}: {str(e)[:150]}")
                continue

        flagged.sort(key=lambda x: -x[2])  # highest score first
        msg = (
            f"🔎 **ESCANEO COMPLETADO**\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"📊 Analizados: **{total_scanned}**\n"
            f"🚩 Flagged (≥{config['alert_threshold']}): **{len(flagged)}**\n"
            f"━━━━━━━━━━━━━━━━━━━━\n\n"
        )
        if flagged:
            msg += "**TOP 10 HALLAZGOS:**\n\n"
            for i, (date, title, s, risk, reasons, txt, gid, mid) in enumerate(flagged[:10], 1):
                cid = str(gid)
                link = f"https://t.me/c/{cid[4:]}/{mid}" if cid.startswith("-100") else ""
                date_str = date.strftime("%d-%m %H:%M")
                txt_clean = " ".join(txt.split())[:180]
                msg += (
                    f"**#{i} · {risk} · score {s}**\n"
                    f"📅 {date_str}  📍 {title}\n"
                    f"🏷️ {', '.join(reasons)}\n"
                    f"💬 {txt_clean}\n"
                    f"🔗 {link}\n"
                    f"────────────\n"
                )
        await event.respond(msg[:4000], buttons=main_menu_buttons(uid))

    elif data == "report":
        await event.respond("📄 Generando informe (últimos 7 días)... un momento.")
        # Pull last 7 days using date() function for reliable comparison
        cur = db.execute(
            "SELECT ts, chat_title, user, msg_id, chat_id, text, score, risk, reasons "
            "FROM scored WHERE date(ts) >= date('now', '-7 days') AND score >= ? "
            "ORDER BY score DESC, ts DESC",
            (config["alert_threshold"],)
        )
        rows = cur.fetchall()
        if not rows:
            await event.respond("Sin hallazgos en los últimos 7 días.", buttons=main_menu_buttons(uid))
            return

        total_msgs = db.execute(
            "SELECT COUNT(*) FROM scored WHERE date(ts) >= date('now', '-7 days')"
        ).fetchone()[0]
        by_risk = {}
        by_group = {}
        for r in rows:
            by_risk[r[7]] = by_risk.get(r[7], 0) + 1
            by_group[r[1]] = by_group.get(r[1], 0) + 1

        # --- Plain text report ---
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        report_path = str(REPORTS_DIR / f"informe_{datetime.now().strftime('%Y%m%d_%H%M')}.txt")
        with open(report_path, "w") as f:
            f.write("=" * 60 + "\n")
            f.write("INFORME DE VIGILANCIA — TELEGRAM\n")
            f.write(f"Generado: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
            f.write("Periodo: últimos 7 días\n")
            f.write(f"Umbral de alerta: score >= {config['alert_threshold']}\n")
            f.write("=" * 60 + "\n\n")

            f.write("RESUMEN\n")
            f.write("-" * 60 + "\n")
            f.write(f"Mensajes totales analizados: {total_msgs}\n")
            f.write(f"Hallazgos: {len(rows)}\n\n")
            f.write("Por nivel de riesgo:\n")
            for risk in ["CRITICO", "ALTO", "MEDIO", "BAJO"]:
                if risk in by_risk:
                    f.write(f"  {risk:8s}: {by_risk[risk]}\n")
            f.write("\nPor grupo:\n")
            for grp, n in sorted(by_group.items(), key=lambda x: -x[1]):
                f.write(f"  [{n:3d}] {grp}\n")
            f.write("\n" + "=" * 60 + "\n")
            f.write("HALLAZGOS DETALLADOS\n")
            f.write("=" * 60 + "\n\n")

            for i, (ts, title, user, msg_id, chat_id, text, score, risk, reasons) in enumerate(rows, 1):
                cid = str(chat_id)
                link = f"https://t.me/c/{cid[4:]}/{msg_id}" if cid.startswith("-100") else "(privado)"
                try:
                    dt = datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M UTC")
                except Exception:
                    dt = ts
                f.write(f"#{i:03d} | {risk} | score {score}\n")
                f.write(f"     Fecha:   {dt}\n")
                f.write(f"     Grupo:   {title}\n")
                f.write(f"     Usuario: @{user}\n")
                f.write(f"     Motivos: {reasons}\n")
                f.write(f"     Enlace:  {link}\n")
                f.write("     Texto:\n")
                for line in (text or "").split("\n"):
                    f.write(f"        {line}\n")
                f.write("-" * 60 + "\n\n")

        # --- JSON report (machine-readable) ---
        json_path = report_path.replace(".txt", ".json")
        json_data = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "period_days": 7,
            "threshold": config["alert_threshold"],
            "summary": {
                "total_analyzed": total_msgs,
                "total_flagged": len(rows),
                "by_risk": by_risk,
                "by_group": by_group,
            },
            "findings": [
                {
                    "n": i,
                    "timestamp": ts,
                    "group": title,
                    "user": user,
                    "msg_id": msg_id,
                    "chat_id": chat_id,
                    "link": (f"https://t.me/c/{str(chat_id)[4:]}/{msg_id}"
                             if str(chat_id).startswith("-100") else None),
                    "score": score,
                    "risk": risk,
                    "reasons": reasons.split(",") if reasons else [],
                    "text": text,
                }
                for i, (ts, title, user, msg_id, chat_id, text, score, risk, reasons)
                in enumerate(rows, 1)
            ],
        }
        with open(json_path, "w") as f:
            json.dump(json_data, f, ensure_ascii=False, indent=2)

        # Send both files
        await bot.send_file(event.chat_id, report_path,
                            caption=f"📄 Informe TXT — {len(rows)} hallazgos")
        await bot.send_file(event.chat_id, json_path,
                            caption="📄 Informe JSON")
        await event.respond("Informe generado.", buttons=main_menu_buttons(uid))

    elif data == "help":
        lang = get_user_language(uid)
        await event.respond(
            HELP_TOPICS[lang]["_menu_title"],
            buttons=help_menu_buttons(uid)
        )
        return

    elif data.startswith("helplang_"):
        new_lang = data[len("helplang_"):]
        if new_lang in ("es", "en"):
            set_user_language(uid, new_lang)
        await event.respond(
            HELP_TOPICS[new_lang]["_menu_title"],
            buttons=help_menu_buttons(uid)
        )
        return

    elif data.startswith("helptopic_"):
        topic = data[len("helptopic_"):]
        lang = get_user_language(uid)
        topic_data = HELP_TOPICS[lang].get(topic)
        if not topic_data:
            await event.respond("?", buttons=help_menu_buttons(uid))
            return
        await event.respond(topic_data["brief"], buttons=help_topic_buttons(uid, topic))
        return

    elif data.startswith("helpmore_"):
        topic = data[len("helpmore_"):]
        lang = get_user_language(uid)
        topic_data = HELP_TOPICS[lang].get(topic)
        if not topic_data:
            await event.respond("?", buttons=help_menu_buttons(uid))
            return
        await event.respond(topic_data["more"][:4000], buttons=help_more_buttons(uid))
        return

    elif data == "top_users":
        profiles = top_users_by_risk(limit=25)
        if not profiles:
            await event.respond("Sin usuarios con triggers todavía.", buttons=main_menu_buttons(uid))
            return
        msg = (
            "👥 **TOP USUARIOS POR RIESGO**\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "_Ranked by unified risk score (0-100)_\n\n"
        )
        for i, p in enumerate(profiles, 1):
            msg += (
                f"**#{i}** @{p['user']} · `{p['label']}`\n"
                f"   ⚡ Risk: **{p['user_risk']}**  ·  🚩 {p['triggers']}/{p['total_msgs']} ({int(p['trigger_rate']*100)}%)\n"
                f"   📊 avg {p['avg_score']} · max {p['max_score']} · 📍 {p['groups_count']} grupos\n"
                f"   🔥 última hora: {p['recent_triggers_1h']} triggers\n\n"
            )
        await event.respond(msg[:4000], buttons=main_menu_buttons(uid))

    elif data == "crossgroup":
        cur = db.execute(
            """
            SELECT user,
                   COUNT(DISTINCT chat_title) AS n_groups,
                   GROUP_CONCAT(DISTINCT chat_title) AS groups,
                   COUNT(*) AS n_msgs,
                   SUM(CASE WHEN score >= ? THEN 1 ELSE 0 END) AS n_triggers
            FROM scored
            WHERE user IS NOT NULL AND user != '' AND user != 'Anon'
            GROUP BY user
            HAVING n_groups >= 2
            ORDER BY n_groups DESC, n_triggers DESC, n_msgs DESC
            LIMIT 30
            """,
            (config["alert_threshold"],)
        )
        rows = cur.fetchall()
        if not rows:
            await event.respond("No hay usuarios cruzando varios grupos todavía.",
                                buttons=main_menu_buttons(uid))
            return
        msg = (
            "🔗 **USUARIOS EN MÚLTIPLES GRUPOS**\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "_(posibles cuentas puente)_\n\n"
        )
        for i, (user, n_grp, groups, n_msgs, n_trig) in enumerate(rows, 1):
            grp_list = ", ".join(groups.split(",")[:5])
            msg += (
                f"**#{i}** @{user}\n"
                f"   📍 {n_grp} grupos · 📨 {n_msgs} msgs · 🚩 {n_trig} triggers\n"
                f"   {grp_list}\n\n"
            )
        await event.respond(msg[:4000], buttons=main_menu_buttons(uid))

    elif data == "user_dossier":
        pending_action[uid] = "user_dossier"
        await event.respond(
            "Envía el username (con o sin @) para crear el resumen de perfil:"
        )

    elif data == "session_summary":
        threshold = config["alert_threshold"]
        # Last 1h activity
        h1 = db.execute("""
            SELECT COUNT(*),
                   SUM(CASE WHEN score >= ? THEN 1 ELSE 0 END),
                   COUNT(DISTINCT user)
            FROM scored WHERE (julianday('now') - julianday(ts)) * 24 <= 1
        """, (threshold,)).fetchone()
        h6 = db.execute("""
            SELECT COUNT(*),
                   SUM(CASE WHEN score >= ? THEN 1 ELSE 0 END),
                   COUNT(DISTINCT user)
            FROM scored WHERE (julianday('now') - julianday(ts)) * 24 <= 6
        """, (threshold,)).fetchone()

        # Top active users last hour
        active = db.execute("""
            SELECT user, COUNT(*),
                   SUM(CASE WHEN score >= ? THEN 1 ELSE 0 END),
                   MAX(score)
            FROM scored
            WHERE (julianday('now') - julianday(ts)) * 24 <= 1
              AND user IS NOT NULL AND user != '' AND user != 'Anon'
            GROUP BY user
            ORDER BY MAX(score) DESC, COUNT(*) DESC LIMIT 5
        """, (threshold,)).fetchall()

        msg = (
            "⏱️ **RESUMEN DE SESIÓN**\n"
            "━━━━━━━━━━━━━━━━━━━━\n\n"
            f"**Última hora:**\n"
            f"  📨 {h1[0] or 0} msgs · 🚩 {h1[1] or 0} triggers · 👥 {h1[2] or 0} usuarios\n\n"
            f"**Últimas 6h:**\n"
            f"  📨 {h6[0] or 0} msgs · 🚩 {h6[1] or 0} triggers · 👥 {h6[2] or 0} usuarios\n\n"
        )
        if active:
            msg += "**Top usuarios última hora:**\n"
            for u, n, t, mx in active:
                msg += f"  @{u} — {n} msgs, {t} triggers, max {mx}\n"
        else:
            msg += "_Sin actividad de usuarios identificados última hora._"
        await event.respond(msg[:4000], buttons=main_menu_buttons(uid))

    elif data == "cats_menu":
        await event.respond(
            "🎯 **CATEGORÍAS DE DETECCIÓN**\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Toca una categoría para ver sus patrones por idioma.\n"
            "_Tier · weight · nombre (total patrones)_",
            buttons=categories_menu_buttons()
        )
        return

    elif data == "grps_menu":
        await event.respond(
            "👥 **GESTIÓN DE GRUPOS**\n"
            "━━━━━━━━━━━━━━━━━━━━",
            buttons=groups_menu_buttons()
        )
        return

    elif data.startswith("cat_") and not data.startswith("catlang_") and not data.startswith("catadd_") and not data.startswith("catrm_"):
        cat_name = data[4:]
        cat = COMPILED_CATEGORIES.get(cat_name)
        if not cat:
            await event.respond(f"Categoría {cat_name} no encontrada.", buttons=main_menu_buttons(uid))
            return
        msg = (
            f"🎯 **{cat_name}**\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"Tier: {cat['tier']}  ·  Weight: {cat['weight']:+d}\n"
            f"_{cat.get('description', '')}_\n\n"
            f"🇬🇧 EN: {len(cat['raw_en'])} patrones\n"
            f"🇪🇸 ES: {len(cat['raw_es'])} patrones\n"
            f"🇷🇺 RU: {len(cat['raw_ru'])} patrones"
        )
        await event.respond(msg, buttons=category_detail_buttons(cat_name))
        return

    elif data.startswith("catlang_"):
        # catlang_CATEGORY_lang
        rest = data[len("catlang_"):]
        # Split from the right — last underscore separates lang
        if "_" not in rest:
            await event.respond("Comando inválido.", buttons=main_menu_buttons(uid))
            return
        cat_name, lang = rest.rsplit("_", 1)
        cat = COMPILED_CATEGORIES.get(cat_name)
        if not cat or lang not in ("en", "es", "ru"):
            await event.respond("Categoría/idioma inválido.", buttons=main_menu_buttons(uid))
            return
        patterns = cat.get(f"raw_{lang}", [])
        flag = {"en":"🇬🇧","es":"🇪🇸","ru":"🇷🇺"}[lang]
        if not patterns:
            msg = f"{flag} **{cat_name} / {lang.upper()}**\n\n_Sin patrones._"
        else:
            msg = f"{flag} **{cat_name} / {lang.upper()}** ({len(patterns)} patrones)\n━━━━━━━━━━━━━━━━━━━━\n\n"
            for i, p in enumerate(patterns, 1):
                msg += f"`{i}.` `{p}`\n"
        await event.respond(msg[:4000], buttons=category_detail_buttons(cat_name))
        return

    elif data.startswith("catadd_"):
        cat_name = data[len("catadd_"):]
        if cat_name not in COMPILED_CATEGORIES:
            await event.respond("Categoría no existe.", buttons=main_menu_buttons(uid))
            return
        pending_action[uid] = f"catadd_lang_{cat_name}"
        await event.respond(
            f"➕ Añadir patrón a **{cat_name}**\n\n"
            f"Envía el idioma del patrón: `en`, `es` o `ru`",
            buttons=Button.force_reply()
        )
        return

    elif data.startswith("catrm_"):
        cat_name = data[len("catrm_"):]
        if cat_name not in COMPILED_CATEGORIES:
            await event.respond("Categoría no existe.", buttons=main_menu_buttons(uid))
            return
        pending_action[uid] = f"catrm_lang_{cat_name}"
        await event.respond(
            f"➖ Quitar patrón de **{cat_name}**\n\n"
            f"Envía el idioma: `en`, `es` o `ru`",
            buttons=Button.force_reply()
        )
        return

    elif data == "review":
        lang = get_user_language(uid)
        alert = get_next_pending_alert(uid)
        pending = get_pending_review_count()
        if not alert:
            empty_msg = (
                "✅ Sin alertas pendientes de revisión." if lang == "es"
                else "✅ No alerts pending review."
            )
            await event.respond(empty_msg, buttons=main_menu_buttons(uid))
            return
        header = (
            f"_Pendientes: {pending}_\n\n" if lang == "es"
            else f"_Pending: {pending}_\n\n"
        )
        card = header + format_review_card(alert, lang)
        await event.respond(card[:4000], buttons=review_buttons(alert["id"], lang),
                            link_preview=False)
        return

    elif data.startswith("rev_yes_") or data.startswith("rev_no_") or data.startswith("rev_skip_"):
        lang = get_user_language(uid)
        if data.startswith("rev_yes_"):
            verdict = "confirmed"
            alert_id_str = data[len("rev_yes_"):]
        elif data.startswith("rev_no_"):
            verdict = "false_pos"
            alert_id_str = data[len("rev_no_"):]
        else:
            verdict = "skipped"
            alert_id_str = data[len("rev_skip_"):]
        try:
            alert_id = int(alert_id_str)
        except ValueError:
            await event.respond("ID inválido.", buttons=main_menu_buttons(uid))
            return
        ok = record_review(alert_id, verdict, uid)
        if not ok:
            err = "Error guardando revisión." if lang == "es" else "Error saving review."
            await event.respond(err, buttons=main_menu_buttons(uid))
            return

        # Show next pending alert immediately
        nxt = get_next_pending_alert(uid)
        pending = get_pending_review_count()
        if not nxt:
            stats = get_review_stats(hours=24)
            if lang == "es":
                msg = (
                    f"✅ Revisión completada.\n\n"
                    f"━━━━━━━━━━━━━━━━━━━━\n"
                    f"**Resumen últimas 24h:**\n"
                    f"• Alertas: {stats['total']}\n"
                    f"• Confirmadas: {stats['confirmed']}\n"
                    f"• Falsos positivos: {stats['false_pos']}\n"
                    f"• Saltadas: {stats['skipped']}\n"
                    f"• Pendientes: {stats['pending']}"
                )
            else:
                msg = (
                    f"✅ Review complete.\n\n"
                    f"━━━━━━━━━━━━━━━━━━━━\n"
                    f"**Last 24h summary:**\n"
                    f"• Alerts: {stats['total']}\n"
                    f"• Confirmed: {stats['confirmed']}\n"
                    f"• False positives: {stats['false_pos']}\n"
                    f"• Skipped: {stats['skipped']}\n"
                    f"• Pending: {stats['pending']}"
                )
            await event.respond(msg, buttons=main_menu_buttons(uid))
            return

        marker = {"confirmed": "✅", "false_pos": "❌", "skipped": "⏭️"}[verdict]
        header = (
            f"{marker} Registrado. _Pendientes: {pending}_\n\n" if lang == "es"
            else f"{marker} Recorded. _Pending: {pending}_\n\n"
        )
        card = header + format_review_card(nxt, lang)
        await event.respond(card[:4000], buttons=review_buttons(nxt["id"], lang),
                            link_preview=False)
        return

    elif data == "thresh":
        pending_action[uid] = "set_threshold"
        await event.respond(
            f"Umbral actual: **{config['alert_threshold']}**\n\n"
            f"Bandas:\n• 3+ BAJO\n• 6+ MEDIO\n• 10+ ALTO\n• 15+ CRITICO\n\n"
            f"Envía el nuevo umbral (número):"
        )

    elif data == "status":
        msg = (
            f"ℹ️ **Estado del sistema**\n\n"
            f"Umbral de alerta: **{config['alert_threshold']}**\n"
            f"Grupos activos: **{len(config['active_groups'])}**\n"
            f"Keywords personalizadas: **{len(custom_keywords)}**\n"
            f"DB: `{DB_PATH}`\n"
            f"Total mensajes: **{db.execute('SELECT COUNT(*) FROM scored').fetchone()[0]}**"
        )
        await event.respond(msg, buttons=main_menu_buttons(uid))

# ==========================================
# 9. TEXT INPUT FOR PENDING ACTIONS
# ==========================================
@bot.on(events.NewMessage)
async def text_input_handler(event):
    if not _is_dashboard_admin(event):
        return
    message_text = getattr(event.message, "text", None)
    if message_text and message_text.startswith('/'):
        return  # let command handlers deal with it

    uid = event.sender_id
    if uid not in pending_action:
        return

    if not message_text:
        await event.respond("Send text for this action, or use /menu to cancel and return.")
        return
    action = pending_action.pop(uid)
    text = message_text.strip()

    # Dashboard access controls use their own small database and deliberately
    # stay available while the crawler/message database is being repaired.
    if action == "dashboard_code_minutes":
        if not text.isdigit() or not 1 <= int(text) <= 10080:
            pending_action[uid] = action
            await event.respond("Send a whole number from 1 to 10080 minutes.")
            return
        result = dashboard_auth.generate_dashboard_code(int(text) * 60, uid)
        await event.respond(_format_dashboard_code_message(result), buttons=main_menu_buttons(uid))
        return

    if not await _require_telegram_data(event):
        pending_action[uid] = action
        return

    global custom_keywords, CUSTOM

    if action == "add_keyword":
        if text and text not in custom_keywords:
            custom_keywords.append(text)
            save_custom_keywords(custom_keywords)
            CUSTOM = build_custom_pattern()
            await event.respond(f"✅ Añadida: `{text}`", buttons=main_menu_buttons(uid))
        else:
            await event.respond("Keyword vacía o duplicada.", buttons=main_menu_buttons(uid))

    elif action == "remove_keyword":
        if text in custom_keywords:
            custom_keywords.remove(text)
            save_custom_keywords(custom_keywords)
            CUSTOM = build_custom_pattern()
            await event.respond(f"✅ Eliminada: `{text}`", buttons=main_menu_buttons(uid))
        else:
            await event.respond("No encontrada.", buttons=main_menu_buttons(uid))

    elif action == "add_group":
        try:
            gid = int(text)
            if gid in config["active_groups"]:
                await event.respond("Ya está en la lista.", buttons=main_menu_buttons(uid))
                return
            # Verify the user account can see the group
            try:
                entity = await client.get_entity(gid)
                title = getattr(entity, "title", "?")
            except Exception as e:
                await event.respond(
                    f"⚠️ No puedo acceder a ese grupo: {str(e)[:100]}\n\n"
                    f"Asegúrate de que la cuenta de usuario está dentro del grupo.",
                    buttons=main_menu_buttons(uid)
                )
                return
            config["active_groups"].append(gid)
            save_config(config)
            await register_scraper_handler()
            await event.respond(f"✅ Añadido: `{gid}` — {title}", buttons=main_menu_buttons(uid))
        except ValueError:
            await event.respond("ID inválido. Debe ser un número como `-1001234567890`.",
                                buttons=main_menu_buttons(uid))

    elif action == "remove_group":
        try:
            gid = int(text)
            if gid in config["active_groups"]:
                config["active_groups"].remove(gid)
                save_config(config)
                await register_scraper_handler()
                await event.respond(f"✅ Eliminado: `{gid}`", buttons=main_menu_buttons(uid))
            else:
                await event.respond("No encontrado.", buttons=main_menu_buttons(uid))
        except ValueError:
            await event.respond("ID inválido.", buttons=main_menu_buttons(uid))

    elif action == "set_threshold":
        try:
            n = int(text)
            config["alert_threshold"] = n
            save_config(config)
            await event.respond(f"✅ Umbral actualizado: **{n}**", buttons=main_menu_buttons(uid))
        except ValueError:
            await event.respond("Número inválido.", buttons=main_menu_buttons(uid))

    elif action == "user_dossier":
        username = text.lstrip("@").strip()
        if not username:
            await event.respond("Username vacío.", buttons=main_menu_buttons(uid))
            return

        # Aggregate stats
        stats = db.execute(
            """
            SELECT COUNT(*), SUM(CASE WHEN score >= ? THEN 1 ELSE 0 END),
                   SUM(score), MAX(score), MIN(ts), MAX(ts),
                   COUNT(DISTINCT chat_title)
            FROM scored WHERE user = ?
            """,
            (config["alert_threshold"], username)
        ).fetchone()
        n_msgs, n_trig, tot, mx, first, last, n_grp = stats
        if not n_msgs:
            await event.respond(f"Sin datos para @{username}.", buttons=main_menu_buttons(uid))
            return

        # Group breakdown
        groups = db.execute(
            """
            SELECT chat_title,
                   COUNT(*) AS n,
                   SUM(CASE WHEN score >= ? THEN 1 ELSE 0 END) AS trig,
                   MAX(score) AS mx
            FROM scored
            WHERE user = ?
            GROUP BY chat_title
            ORDER BY n DESC
            """,
            (config["alert_threshold"], username)
        ).fetchall()

        # Top flagged messages
        flagged = db.execute(
            """
            SELECT ts, chat_title, chat_id, msg_id, score, risk, reasons, text
            FROM scored
            WHERE user = ? AND score >= ?
            ORDER BY score DESC, ts DESC
            LIMIT 10
            """,
            (username, config["alert_threshold"])
        ).fetchall()

        # Write a neutral profile-summary file.
        ts = datetime.now().strftime("%Y%m%d_%H%M")
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        path_txt = str(REPORTS_DIR / f"profile_{username}_{ts}.txt")
        with open(path_txt, "w", encoding="utf-8") as f:
            f.write("=" * 60 + "\n")
            f.write(f"RESUMEN DE PERFIL — @{username}\n")
            f.write(f"Generado: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
            f.write("=" * 60 + "\n\n")

            f.write("RESUMEN\n")
            f.write("-" * 60 + "\n")
            f.write(f"Username:           @{username}\n")
            f.write(f"Mensajes totales:   {n_msgs}\n")
            f.write(f"Triggers (>= {config['alert_threshold']}):  {n_trig}\n")
            f.write(f"Score acumulado:    {tot}\n")
            f.write(f"Score máximo:       {mx}\n")
            f.write(f"Grupos:             {n_grp}\n")
            f.write(f"Primera actividad:  {first}\n")
            f.write(f"Última actividad:   {last}\n\n")

            f.write("ACTIVIDAD POR GRUPO\n")
            f.write("-" * 60 + "\n")
            for title, n, trig, gmx in groups:
                f.write(f"  [{n:4d} msgs · {trig:3d} triggers · max {gmx:3d}]  {title}\n")
            f.write("\n")

            if flagged:
                f.write("=" * 60 + "\n")
                f.write(f"MENSAJES FLAGGED (top {len(flagged)})\n")
                f.write("=" * 60 + "\n\n")
                for i, (fts, ftitle, fcid, fmid, fs, frisk, freasons, ftext) in enumerate(flagged, 1):
                    cidstr = str(fcid)
                    link = f"https://t.me/c/{cidstr[4:]}/{fmid}" if cidstr.startswith("-100") else "(privado)"
                    try:
                        dt = datetime.fromisoformat(fts).strftime("%Y-%m-%d %H:%M UTC")
                    except Exception:
                        dt = fts
                    f.write(f"#{i:03d} | {frisk} | score {fs}\n")
                    f.write(f"     Fecha:   {dt}\n")
                    f.write(f"     Grupo:   {ftitle}\n")
                    f.write(f"     Motivos: {freasons}\n")
                    f.write(f"     Enlace:  {link}\n")
                    f.write("     Texto:\n")
                    for line in (ftext or "").split("\n"):
                        f.write(f"        {line}\n")
                    f.write("-" * 60 + "\n\n")
            else:
                f.write("Sin mensajes sobre el umbral.\n")

        # Inline summary in chat
        summary = (
            f"📑 **PROFILE SUMMARY — @{username}**\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"📨 Mensajes:     **{n_msgs}**\n"
            f"🚩 Triggers:     **{n_trig}**\n"
            f"📊 Score total:  **{tot}** (max {mx})\n"
            f"📍 Grupos:       **{n_grp}**\n"
            f"📅 Periodo:      {first[:10]} → {last[:10]}\n\n"
            f"**Por grupo:**\n"
        )
        for title, n, trig, gmx in groups[:5]:
            summary += f"• {title}: {n} msgs ({trig} 🚩, max {gmx})\n"
        await event.respond(summary[:3500])
        await bot.send_file(event.chat_id, path_txt,
                            caption=f"📑 Resumen completo de @{username}")
        await event.respond("Listo.", buttons=main_menu_buttons(uid))

    elif action == "search":
        cur = db.execute(
            "SELECT ts, chat_title, user, score, risk, substr(text,1,150) "
            "FROM scored WHERE text LIKE ? ORDER BY id DESC LIMIT 15",
            (f"%{text}%",)
        )
        rows = cur.fetchall()
        if not rows:
            await event.respond(f"Sin resultados para: `{text}`", buttons=main_menu_buttons(uid))
            return
        msg = f"🔍 Resultados para `{text}`:\n\n"
        for _ts, title, user, score, risk, txt in rows:
            msg += f"**{risk}** ({score}) — {title} / @{user}\n{txt}\n\n"
        await event.respond(msg[:4000], buttons=main_menu_buttons(uid))

# ==========================================
# 10. STARTUP
# ==========================================

@bot.on(events.NewMessage(func=lambda e: e.message.fwd_from is not None))
async def forwarded_group_detect(event):
    """When admin forwards a message from a group, offer to add it."""
    if not _is_dashboard_admin(event):
        return
    if not await _require_telegram_data(event):
        return
    if event.is_group or event.is_channel:
        return  # only DMs

    fwd = event.message.fwd_from
    gid = None
    title = "?"

    # Try to extract the source channel/group ID
    if fwd.from_id:
        peer = fwd.from_id
        if hasattr(peer, "channel_id"):
            gid = int(f"-100{peer.channel_id}")
        elif hasattr(peer, "chat_id"):
            gid = -peer.chat_id
        elif hasattr(peer, "user_id"):
            await event.respond("⚠️ Reenviado desde un usuario, no un grupo. Solo puedo añadir grupos/canales.")
            return

    if gid is None:
        await event.respond("⚠️ No pude extraer el ID del grupo. El origen puede estar oculto.")
        return

    # Try to get the group title
    try:
        entity = await client.get_entity(gid)
        title = getattr(entity, "title", str(gid))
    except Exception as e:
        await event.respond(
            f"📥 ID detectado: `{gid}`\n\n"
            f"⚠️ Pero la cuenta de usuario no puede acceder al grupo: {str(e)[:100]}\n"
            f"Únete al grupo primero con la cuenta y vuelve a intentarlo."
        )
        return

    if gid in config["active_groups"]:
        await event.respond(f"ℹ️ `{gid}` — **{title}** ya está en la lista.",
                            buttons=main_menu_buttons(event.sender_id))
        return

    # Offer to add
    pending_action[event.sender_id] = f"confirm_add_{gid}"
    await event.respond(
        f"📥 Detectado grupo:\n\n"
        f"**{title}**\n`{gid}`\n\n"
        f"¿Añadirlo a la lista de monitorizados?",
        buttons=[
            [Button.inline("✅ Sí, añadir", f"addfwd_{gid}".encode()),
             Button.inline("❌ No", b"cancel_fwd")]
        ]
    )



@bot.on(events.ChatAction)
async def auto_leave_unauthorized(event):
    """Leave any group/channel the bot is added to unless it's in ALLOWED_CHATS."""
    me = await bot.get_me()
    # Only react when THIS bot was added (not other users joining)
    if not (event.user_added or event.user_joined):
        return
    if event.user_id != me.id:
        return  # someone else joined, not us

    chat_id = event.chat_id
    if chat_id in ALLOWED_CHATS:
        return  # this is our admin chat, allowed

    # Try to identify who added us
    try:
        adder = await event.get_added_by()
        adder_id = adder.id if adder else None
    except Exception:
        adder_id = None

    if adder_id in ALLOWED_USERS:
        # Authorized user added us — allow it and add to whitelist for this session
        ALLOWED_CHATS.append(chat_id)
        try:
            await bot.send_message(chat_id, "🛡️ Bot autorizado en este chat.")
        except Exception:
            pass
        # Notify admin
        try:
            await bot.send_message(
                admin_chat_id,
                f"ℹ️ Bot añadido a un nuevo chat por usuario autorizado:\n`{chat_id}`"
            )
        except Exception:
            pass
        return

    # Unauthorized — leave immediately and notify admin
    try:
        await bot.send_message(
            admin_chat_id,
            f"⚠️ Intento de añadir el bot a un chat no autorizado:\n"
            f"Chat ID: `{chat_id}`\n"
            f"Añadido por: `{adder_id}`\n"
            f"Saliendo..."
        )
    except Exception:
        pass

    try:
        await bot.delete_dialog(chat_id)
    except Exception:
        # Fallback: try leaving via the channel/chat leave method
        try:
            from telethon.tl.functions.channels import LeaveChannelRequest
            await bot(LeaveChannelRequest(chat_id))
        except Exception:
            pass


async def spain_alert_dispatch_loop():
    """Deliver deduplicated safe-metadata Spain alerts queued by the onion worker."""
    from spain_alerts import format_spain_alert, payload_from_queue_row
    while True:
        if not _telegram_push_alerts_enabled():
            await asyncio.sleep(30)
            continue
        try:
            for row in osint_storage.get_pending_spain_alerts(10):
                payload = payload_from_queue_row(row)
                if not payload.get("url"):
                    continue
                try:
                    await bot.send_message(admin_chat_id, format_spain_alert(payload), parse_mode=None, link_preview=False)
                except Exception as exc:
                    logging.getLogger("arachne").warning("Spain alert delivery deferred: %s", type(exc).__name__)
                    break
                osint_storage.mark_spain_alert_sent(row["id"], payload["url"], payload.get("risk_level") or "priority")
            from daily_activity import format_digest, payload_from_row
            for row in osint_storage.get_pending_daily_digests(2):
                payload = payload_from_row(row)
                try:
                    await bot.send_message(admin_chat_id, format_digest(payload), parse_mode=None, link_preview=False)
                except Exception as exc:
                    logging.getLogger("arachne").warning("Daily digest delivery deferred: %s", type(exc).__name__)
                    break
                osint_storage.mark_daily_digest_sent(row["digest_date"])
        except Exception as exc:
            logging.getLogger("arachne").warning("Spain alert queue check failed: %s", type(exc).__name__)
        await asyncio.sleep(15)


async def main():
    if not (_telegram_api_id_configured and _telegram_api_hash_configured and bot_token and admin_chat_id):
        raise RuntimeError("Telegram credentials are not configured. Set TELEGRAM_API_ID, TELEGRAM_API_HASH, TELEGRAM_BOT_TOKEN, and ADMIN_CHAT_ID in .env or the environment.")
    # Bring the administrative bot online before touching the crawler database.
    # Access-code controls live in dashboard_access.db and remain available while
    # messages.db is being repaired.
    await bot.start(bot_token=bot_token)

    telegram_data_ready = _init_telegram_db()
    if telegram_data_ready:
        try:
            osint_storage.init_db()
            if not _telegram_push_alerts_enabled():
                osint_storage.set_spain_alerts_paused(True, "telegram_quiet_start")
        except (OSError, sqlite3.Error) as exc:
            telegram_data_ready = False
            logging.getLogger("arachne").error(
                "Crawler database unavailable; dashboard access controls remain online: %s",
                type(exc).__name__,
            )

    user_client_ready = False
    if telegram_data_ready:
        try:
            await asyncio.wait_for(client.connect(), timeout=15)
            user_client_ready = bool(await client.is_user_authorized())
            if not user_client_ready:
                await client.disconnect()
                print("Telegram user scraper session is not authorized. Bot menu/code remains available.")
        except Exception as exc:
            print(f"Telegram user scraper session not ready: {type(exc).__name__}. Bot menu/code remains available.")

    if telegram_data_ready:
        asyncio.create_task(spain_alert_dispatch_loop())
    if user_client_ready:
        await register_scraper_handler()
    print("SISTEMA ONLINE — escribe /menu al bot para abrir el panel")
    await bot.run_until_disconnected()

if __name__ == '__main__':
    if not (_telegram_api_id_configured and _telegram_api_hash_configured and bot_token and admin_chat_id):
        print("Telegram bot disabled: missing TELEGRAM/ADMIN credentials. Dashboard and staged workers are unaffected.")
        raise SystemExit(2)
    asyncio.run(main())
