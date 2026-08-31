"""Universal passive safety, category, multilingual, and Spain-priority policy."""
from __future__ import annotations

import html
import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from classification_schema import (CONTENT_CATEGORY_LABELS, SITE_TYPES as CANONICAL_SITE_TYPES,
                                   normalize_page_type, normalize_policy_vocabulary)
from paths import BASE_DIR
from safety_policy import assess_severe_abuse_signals, severe_blackhole_policy

SAFETY_CONFIG_PATH = BASE_DIR / "safety_filter_config.json"
TAG_CONFIG_PATH = BASE_DIR / "keyword_tags_config.json"

PRIMARY_CATEGORY_LABELS = CONTENT_CATEGORY_LABELS

MARKETPLACE_CATEGORIES = {
    "marketplace", "marketplace_drugs", "marketplace_weapons", "marketplace_fraud",
    "marketplace_credentials", "marketplace_leaks", "marketplace_counterfeit", "marketplace_services",
}

# Generic single words are too ambiguous to make a final page-level threat decision.
# High-signal phrases or corroborating context are required after a page is fetched.
STRICT_PAGE_CATEGORIES = {
    "weapons_arms", "drugs", "leaks_data", "credentials", "malware_hacking",
    "extremist_recruitment", "fraud_financial",
}
THREAT_PRIMARY_CATEGORIES = set(STRICT_PAGE_CATEGORIES)
GENERIC_PAGE_STRONG = {
    "weapons_arms": {"weapons", "firearms", "guns", "armas", "оружие"},
}
THREAT_ACTION_CONTEXT = (
    "trafficking", "shipping", "shipment", "delivery", "dispatch", "vendor", "seller",
    "for sale", "buy", "purchase", "market", "store", "shop", "trade", "exchange",
    "envio", "entrega", "venta", "vendedor", "comprar", "mercado",
)

def structural_page_guard(url: str, text: str = "") -> str | None:
    """Return a structural guard from destination-owned text only.

    ``url`` is retained for API compatibility but deliberately ignored.  A
    route name can be recorded by crawl scheduling as an unverified hint; it
    cannot become a confirmed structural or content label.
    """
    _ = url
    joined = normalize_text(text)
    if any(label in joined[:1500] for label in ("gitlab", "gitea", "gogs")):
        return "code_repository"
    if any(label in joined for label in ("mediawiki", "from wikipedia")):
        return "wiki"
    if any(label in joined for label in ("phpbb", "forum index", "discussion forum")):
        return "forum"
    return None


def _scope_matches(text: str, rules: dict) -> list[str]:
    return list(dict.fromkeys(_matches(text, rules.get("strong", [])) +
                              _matches(text, rules.get("medium", []))))


def _adult_evidence(title_text: str, body_text: str,
                    rules: dict, guard: str | None) -> dict:
    """Evaluate only the destination's returned title/body HTML.

    URL, hostname, path, anchor, and source-page wording are handled separately
    as provisional discovery hints and never enter this final page decision.
    """
    title_hits = _scope_matches(title_text, rules)
    body_hits = _scope_matches(body_text, rules)
    distinct = set(map(normalize_text, title_hits + body_hits))
    explicit_child = bool(title_hits)
    dominant = bool(title_hits and len(distinct) >= 1) or len(distinct) >= 2
    if guard:
        dominant = bool(title_hits and len(distinct) >= 2)
    matched = title_hits or body_hits
    scope = "title" if title_hits else "body"
    return {
        "matched": bool(matched), "block": bool(dominant),
        "scope": scope, "signal_count": len(distinct),
        "signal_ratio": min(1.0, len(distinct) / max(1, len(normalize_text(body_text).split()) / 80)),
        "dominance_score": 1.0 if explicit_child and dominant else 0.75 if dominant else 0.2,
        "guard": guard,
    }


@lru_cache(maxsize=2)
def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def reload_configs() -> None:
    _load.cache_clear()


def normalize_text(value: str | None) -> str:
    text = html.unescape(str(value or ""))
    text = unicodedata.normalize("NFKC", text).casefold()
    decomposed = unicodedata.normalize("NFKD", text)
    text = "".join(char for char in decomposed if not unicodedata.combining(char))
    return re.sub(r"\s+", " ", text).strip()


def detect_language(*values: str) -> str:
    joined = " ".join(str(value or "") for value in values)
    has_cyrillic = bool(re.search(r"[\u0400-\u04ff]", joined))
    normalized = normalize_text(joined)
    has_es = bool(re.search(r"\b(?:espana|policia|guardia|ministerio|filtracion|credenciales|armas|reclutamiento)\b", normalized))
    has_en = bool(re.search(r"\b(?:spain|weapons|leak|credentials|malware|recruitment|marketplace)\b", normalized))
    count = sum((has_cyrillic, has_es, has_en))
    if count > 1: return "MIXED"
    if has_cyrillic: return "RU"
    if has_es: return "ES"
    return "EN"


def _term_found(text: str, term: str) -> bool:
    needle = normalize_text(term)
    if not needle:
        return False
    if any(char in needle for char in (".", "/", ":")):
        return needle in text
    return bool(re.search(r"(?<!\w)" + re.escape(needle) + r"(?!\w)", text))


def _matches(text: str, terms: list[str]) -> list[str]:
    return [term for term in terms if _term_found(text, term)]


def _strict_page_category_evidence(category: str, strong: list[str], medium: list[str],
                                   content_text: str) -> tuple[int, str] | None:
    """Require corroborated page content for final non-safety threat classification."""
    normalized_strong = {normalize_text(item) for item in strong}
    normalized_medium = {normalize_text(item) for item in medium}
    generic = {normalize_text(item) for item in GENERIC_PAGE_STRONG.get(category, set())}
    specific_strong = normalized_strong - generic
    if specific_strong:
        return 2, "page_content"
    distinct = normalized_strong | normalized_medium
    if len(distinct) >= 2:
        return 2, "corroborated_page_content"
    if normalized_strong and any(_term_found(content_text, term) for term in THREAT_ACTION_CONTEXT):
        return 2, "contextual_page_content"
    return None


def _weapons_evidence(url: str, title_text: str, body_text: str) -> dict:
    """Score weapons context from independent, safe evidence families."""
    _ = url
    text = " ".join(filter(None, (title_text, body_text)))
    weapons = _matches(text, [
        "weapon", "weapons", "firearm", "firearms", "gun", "guns", "pistol", "pistols",
        "rifle", "rifles", "handgun", "handguns", "ammunition", "ammo", "arms", "armas",
        "pistola", "pistolas", "fusil", "fusiles", "municion", "оружие", "пистолет",
    ])
    commerce = _matches(text, [
        "for sale", "sale", "selling", "buy", "vendor", "seller", "shop", "market", "marketplace",
        "listing", "catalog", "price", "stock", "order", "trafficking", "trafico", "venta",
        "торговля",
    ])
    delivery = _matches(text, [
        "shipping", "ships", "delivery", "deliver", "dispatch", "send to", "sent from",
        "envio", "entrega", "enviado", "доставка", "contact", "telegram", "jabber",
    ])
    structure = bool(_matches(text, ["vendor listing", "seller profile", "product listing",
                                    "items for sale", "weapons market", "arms market"]))
    thread = bool(_matches(text, ["forum thread", "discussion thread", "posted by"]))
    negative = _matches(text, [
        "airsoft", "paintball", "video game", "gaming", "game guide", "museum", "historical exhibit",
        "history of", "movie", "film review", "news report", "policy debate", "legislation",
        "anti gun", "anti-gun", "weapons prevention", "weapons awareness",
    ])
    families = []
    if weapons: families.append("weapon_terminology")
    if commerce: families.append("commercial_context")
    if structure: families.append("seller_or_listing_structure")
    if delivery: families.append("delivery_or_contact_context")
    if thread and weapons: families.append("thread_structure")
    score = (35 if weapons else 0) + (30 if commerce else 0) + (20 if structure else 0) + (15 if delivery else 0)
    if thread and weapons and (commerce or delivery):
        score += 10
    if negative:
        score -= 50 if not commerce and not delivery else 20
    positive_families = [value for value in families if value != "thread_structure" or commerce or delivery]
    verified = bool(weapons and len(positive_families) >= 2 and score >= 60)
    if verified and structure:
        context_type = "seller_or_listing"
    elif verified and thread:
        context_type = "commercial_thread"
    elif weapons:
        context_type = "general_or_uncertain"
    else:
        context_type = "none"
    return {
        "score": max(0, min(100, score)),
        "families": families + (["benign_context_guard"] if negative else []),
        "verified": verified,
        "commercial": bool(commerce or structure),
        "context_type": context_type,
    }


def _url_matches(text: str, terms: list[str]) -> list[str]:
    """Match semantic URL components; opaque v3 onion labels are removed upstream."""
    return [term for term in terms if normalize_text(term) and normalize_text(term) in text]


def _classification_url_text(url: str | None) -> str:
    """Return URL evidence without interpreting random v3 onion-label substrings."""
    try:
        parsed = urlsplit(url or "")
        host = (parsed.hostname or "").casefold()
        host_parts = []
        if host.endswith(".onion"):
            labels = host[:-6].split(".")
            # The terminal onion label is an address identifier, not natural language.
            # Validity is enforced separately by the URL policy; never lexical-scan it.
            host_parts.extend(labels[:-1])
        else:
            host_parts.append(host)
        return normalize_text(" ".join(filter(None, [" ".join(host_parts), parsed.path, parsed.query])))
    except (TypeError, ValueError, UnicodeError):
        return ""


def _base_result() -> dict:
    return {
        "primary_category": "unknown", "category": "unknown", "tags": ["unknown"],
        "risk_level": "low", "confidence": "low", "risk_flags": [],
        "storage_policy": "safe_summary", "review_status": "pending",
        "safety_reason": "unclassified", "priority_score": 0,
        "screenshot_policy": "blocked", "screenshot_blocked_reason": "unclassified",
        "queue_policy": "normal", "active": 1, "dead_reason": None,
        "spain_priority": False, "geo_priority": None, "spain_match_reason": None,
        "spain_match_language": None, "spain_confidence": None,
        "spain_context_tags": [], "tag_confidence": "low", "tag_summary": "No strong tags",
        "language": None, "locale_path": None, "spanish_language_detected": False,
        "spain_priority_reason": None, "spain_priority_evidence_type": None,
        "spain_relevance": "none", "spain_evidence_type": None,
        "seller_geo_confidence": "none", "spain_evidence_snippets": [],
        "spain_evidence_source_url": None, "spain_evidence_source_path": None,
        "spain_evidence_score": 0, "spain_evidence_families": [],
        "spain_context_only": False, "spain_actionable": False,
        "importance_level": "normal", "importance_reason": "routine_monitoring",
        "secondary_categories": [], "marketplace_type": None, "page_type": "unknown",
        "category_confidence": "low", "category_reason": "No reliable category signal yet",
        "category_safe_label": "Unknown", "display_group": "Other", "ui_hidden_default": 0,
        "ui_priority": 0, "review_score": 0,
        "match_scope": None, "safe_signal_labels": [], "signal_count": 0,
        "signal_ratio": 0.0, "dominance_score": 0.0, "context_window_count": 0,
        "child_only": False, "false_positive_guard_applied": False,
        "ocr_checked": False, "ocr_restricted_hit": False,
        "ocr_safe_signal_labels": [], "ocr_deleted_due_to_policy": False,
        "suggested_category": None, "classification_decision": "unclassified",
        "classification_confidence_score": 0.0, "classifier_version": "rules-page-v4",
        "classification_stage": "unknown", "evidence_families": [],
        "weapons_evidence_score": 0, "weapons_evidence_families": [],
        "weapons_commercial_context": False, "weapons_context_type": "none",
        "site_type": "unknown", "risk_category": "unknown",
        "urgent_score": 0, "urgent_flag": False, "urgent_reason": None,
        "context_only": False,
    }


CLASSIFIER_VERSION = "rules-page-v7-spain-local-evidence"
RESTRICTED_CATEGORIES = {"adult_filtered", "adult_restricted", "severe_abuse_risk"}
SITE_TYPES = set(CANONICAL_SITE_TYPES)
RISK_CATEGORIES = {"financial_fraud", "drugs", "cybercrime", "adult", "weapons", "mixed", "unknown", "needs_review"}
GENERIC_FINANCE_TERMS = {
    "bitcoin", "wallet", "payment", "escrow", "bank", "card", "account", "crypto", "money",
}

# Explicit fraud vocabulary is still evidence, but the same words commonly
# occur in defensive research, awareness material, and journalism.  Those
# pages must not become high-impact fraud records unless they also contain an
# independent actionable/transactional signal.
BENIGN_FRAUD_CONTEXT_TERMS = {
    "anti fraud", "anti-fraud", "fraud prevention", "phishing prevention",
    "carding prevention", "fraud awareness", "phishing awareness",
    "security awareness", "security research", "cybersecurity research",
    "information security research", "academic research", "responsible disclosure",
    "defensive security", "threat intelligence research", "news report",
    "investigative journalism", "educational material", "public awareness",
    "how to protect", "protect yourself", "victim support",
}
ACTIONABLE_FRAUD_CONTEXT_TERMS = {
    "for sale", "selling", "buy", "price", "order", "vendor", "seller",
    "shop", "marketplace", "in stock", "available now", "contact seller",
    "escrow", "shipping", "delivery", "deposit", "checkout", "cart",
    "dm me", "contact me", "service for hire",
}
EXPLICIT_FINANCIAL_FRAUD_PHRASES = (
    "stolen cards", "bank logs", "fullz", "cashout", "dumps", "carding",
    "phishing kits", "refund fraud", "mule accounts", "cvv", "card dumps",
    "cloned card", "cloned cards", "digital cc", "payment card fraud",
)
HIGH_CONF_FINANCIAL_FRAUD_INDICATORS = (
    "cvv", "fullz", "card dumps", "bank logs", "cashout", "carding",
    "stolen cards", "phishing kits", "refund fraud", "mule accounts",
    "cloned cards", "digital cc",
)
SPAIN_RELEVANCE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
SPAIN_STRONG_SELLER_SHIPPING = (
    "envio desde espana", "envio nacional", "envio peninsula", "envio a toda espana",
    "solo espana", "spain only", "ships from spain", "shipping from spain",
    "sent from spain", "dispatch from spain", "enviado desde espana",
    "domestic spain", "nacional only", "peninsula y baleares", "entrega nacional",
    "proveedor espana", "vendedor espanol", "vendedor en espana", "stock en espana",
    "local pickup spain", "recogida en madrid", "recogida en barcelona", "recogida en sevilla",
    "ship to spain", "ships to spain", "shipping to spain", "deliver to spain",
    "delivery to spain", "send to spain", "envios a espana", "enviamos a espana",
    "entrega en espana", "entregas en espana",
)
SPAIN_LOGISTICS_SIGNALS = (
    "correos", "correos express", "seur", "mrw", "nacex", "gls spain",
    "paack", "sending", "inpost espana",
)
SPAIN_PAYMENT_SIGNALS = (
    "bizum", "iban es", "cuenta espanola", "pago nacional",
)
SPAIN_IDENTITY_DOCUMENT_SIGNALS = (
    "dni", "nie", "pasaporte espanol", "spanish passport", "documento nacional de identidad",
    "nif", "cif", "numero de identidad", "identidad espanola",
)
SPAIN_BANK_SIGNALS = (
    "banco santander", "santander", "bbva", "caixabank", "la caixa", "bankinter",
    "sabadell", "unicaja", "kutxabank", "banco de espana", "spanish bank",
    "banco espanol", "tarjeta espanola", "cuenta bancaria espanola",
)
SPAIN_LOCATION_SIGNALS = (
    "madrid", "barcelona", "valencia", "sevilla", "malaga", "alicante",
    "murcia", "bilbao", "granada", "cadiz", "zaragoza", "cordoba",
    "valladolid", "palma", "canarias", "baleares", "espana", "spain",
)
SPAIN_COMPROMISE_SIGNALS = (
    "breach", "breached", "data breach", "leak", "leaked", "data leak",
    "database leak", "exposed", "exposed data", "compromised", "stolen data",
    "customer records", "client records", "customer data", "client data",
    "credentials", "credential dump", "database dump", "exfiltrated", "exfiltration",
    "for sale", "selling", "sale", "dump",
)
SPAIN_TRANSACTION_SIGNALS = (
    "vendor", "seller", "marketplace", "listing", "for sale", "shipping", "delivery",
    "order", "escrow", "payment", "wallet", "product", "stock", "dispatch",
    "posted by", "author", "contact",
)

# Canonical evidence families prevent aliases for the same fact from inflating a
# score (for example, ``Banco Santander`` and ``Santander`` are one bank family).
SPAIN_SHIPPING_FAMILIES = {
    "shipping_to_spain": (
        "ship to spain", "ships to spain", "shipping to spain", "deliver to spain",
        "delivery to spain", "send to spain", "envio a espana", "envios a espana",
        "enviamos a espana", "entrega en espana", "entregas en espana", "envio a toda espana",
    ),
    "shipping_from_spain": (
        "ship from spain", "ships from spain", "shipping from spain", "sent from spain",
        "dispatch from spain", "envio desde espana", "enviado desde espana", "sale de espana",
        "stock en espana", "recogida en madrid", "recogida en barcelona", "recogida en sevilla",
    ),
    "domestic_spain_seller": (
        "envio nacional", "envio peninsula", "solo espana", "spain only", "domestic spain",
        "nacional only", "peninsula y baleares", "entrega nacional", "proveedor espana",
        "vendedor espanol", "vendedor en espana", "local pickup spain",
    ),
}
SPAIN_LOGISTICS_FAMILIES = {
    "carrier_correos": ("correos express", "correos"),
    "carrier_seur": ("seur",), "carrier_mrw": ("mrw",), "carrier_nacex": ("nacex",),
    "carrier_gls": ("gls spain",), "carrier_paack": ("paack",),
    "carrier_inpost": ("inpost espana",),
}
SPAIN_PAYMENT_FAMILIES = {
    "payment_bizum": ("bizum",),
    "payment_spanish_iban": ("iban es", "cuenta espanola", "cuenta bancaria espanola"),
    "payment_domestic": ("pago nacional",),
}
SPAIN_IDENTITY_FAMILIES = {
    "identity_dni": ("documento nacional de identidad", "dni"),
    "identity_nie": ("nie",),
    "identity_passport": ("pasaporte espanol", "spanish passport"),
    "identity_tax": ("nif", "cif"),
    "identity_spanish": ("numero de identidad", "identidad espanola"),
}
SPAIN_BANK_FAMILIES = {
    "bank_santander": ("banco santander", "santander"),
    "bank_bbva": ("bbva",), "bank_caixabank": ("caixabank", "la caixa"),
    "bank_bankinter": ("bankinter",), "bank_sabadell": ("sabadell",),
    "bank_unicaja": ("unicaja",), "bank_kutxabank": ("kutxabank",),
    "bank_of_spain": ("banco de espana", "bank of spain"),
    "spanish_bank_generic": ("spanish bank", "banco espanol", "tarjeta espanola"),
}
SPAIN_INSTITUTION_FAMILIES = {
    "institution_national_police": ("policia nacional", "policia.es"),
    "institution_guardia_civil": ("guardia civil", "guardiacivil.es"),
    "institution_interior": ("ministerio del interior", "interior.gob.es"),
    "institution_defence": ("ministerio de defensa", "defensa.gob.es", "ejercito espanol"),
    "institution_government": ("gobierno de espana", "gobierno espanol", "moncloa", "gob.es"),
    "institution_cni": ("cni",), "institution_boe": ("boe.es",), "institution_ine": ("ine.es",),
}
SPAIN_LANGUAGE_ONLY_TERMS = {
    "spanish", "espanol", "espanola", "espanoles", "испанский", "испанская", "испанские",
}
THREAT_CATEGORIES = {
    "weapons_arms", "drugs", "leaks_data", "credentials", "malware_hacking",
    "fraud_financial", "extremist_recruitment",
}
DISCOVERY_CATEGORIES = {
    "directory_index", "search_engine", "forum_social", "hosting_services",
    "contact_infrastructure",
}
NEUTRAL_CATEGORIES = {
    "infosec_research", "privacy_anonymity", "news_media", "religion_spirituality",
    "education_reference", "technology_software", "finance_cryptocurrency",
    "activism_civil_society", "personal_blog", "communication_services",
    "file_storage_sharing", "arts_culture", "health_wellness",
}

CATEGORY_TAG_ALIASES = {
    "hosting_services": ["hosting", "web_hosting", "infrastructure"],
    "contact_infrastructure": ["contact", "infrastructure"],
    "infosec_research": ["infosec", "cybersecurity", "security_research"],
    "privacy_anonymity": ["privacy", "anonymity"],
    "news_media": ["news", "journalism"],
    "religion_spirituality": ["religion", "spirituality"],
    "education_reference": ["education", "reference"],
    "technology_software": ["technology", "software"],
    "finance_cryptocurrency": ["finance", "cryptocurrency"],
    "activism_civil_society": ["activism", "civil_society"],
    "personal_blog": ["blog", "writing"],
    "communication_services": ["email", "messaging", "communication"],
    "file_storage_sharing": ["file_sharing", "file_storage"],
    "arts_culture": ["arts", "culture"],
    "health_wellness": ["health", "wellbeing"],
}


def category_search_tags(category: str | None) -> list[str]:
    key = str(category or "unknown")
    if key == "unknown":
        return []
    return list(dict.fromkeys([key] + CATEGORY_TAG_ALIASES.get(key, [])))


def calibrate_classification(policy: dict, *, stage: str = "page") -> dict:
    """Attach a conservative, explainable decision without weakening safety rules.

    The score is rule calibration, not a statistical probability. Weak threat hints
    are retained as safe suggestions for analyst review instead of becoming results.
    """
    result = normalize_policy_vocabulary(policy)
    category = str(result.get("primary_category") or "unknown")
    confidence = str(result.get("category_confidence") or result.get("confidence") or "low").casefold()
    evidence = list(dict.fromkeys(str(value) for value in result.get("evidence_families", []) if value))
    if result.get("match_scope"): evidence.append(f"scope:{result['match_scope']}")
    if result.get("safe_signal_labels"): evidence.extend(
        str(value) for value in result.get("safe_signal_labels", []) if value
    )
    evidence = list(dict.fromkeys(evidence))
    restricted = category in RESTRICTED_CATEGORIES or result.get("storage_policy") == "discard"
    if restricted:
        decision, score = "restricted", 0.99
    elif confidence == "analyst":
        decision, score = "analyst_confirmed", 1.0
    elif category == "general_other":
        decision, score = "monitor_only", 0.55
    elif category == "unknown":
        decision, score = "abstained", 0.25 if result.get("suggested_category") else 0.10
    else:
        score = {"critical": 0.98, "high": 0.88, "medium": 0.68, "low": 0.42}.get(confidence, 0.42)
        if result.get("spain_priority") and result.get("spain_confidence") == "high":
            score = max(score, 0.90)
        threat = category in THREAT_CATEGORIES or category.startswith("marketplace")
        thematic_tags = {str(value) for value in result.get("tags", []) if value not in {category, "unknown"}}
        if threat and score < 0.75 and len(thematic_tags) >= 2:
            score = 0.80
            evidence.append("corroborated_safe_tags")
        if threat and score < 0.75:
            result["suggested_category"] = category
            result.update(
                primary_category="unknown", category="unknown", category_safe_label="Needs classification review",
                category_reason="Threat signal was not corroborated strongly enough",
                category_confidence="low", storage_policy="safe_summary", review_status="needs_review",
                screenshot_policy="blocked", screenshot_blocked_reason="classification_abstained",
                queue_policy="normal", risk_level="low", risk_flags=[],
            )
            decision, score = "abstained", min(score, 0.49)
        elif score >= 0.75 or category in DISCOVERY_CATEGORIES or category in NEUTRAL_CATEGORIES:
            decision = "accepted"
        else:
            result["suggested_category"] = category
            decision = "needs_review"
    result.update(
        classification_decision=decision,
        classification_confidence_score=round(float(score), 3),
        classifier_version=CLASSIFIER_VERSION,
        classification_stage=stage,
        evidence_families=evidence,
    )
    final_category = str(result.get("primary_category") or "unknown")
    result["tags"] = list(dict.fromkeys(result.get("tags", []) + category_search_tags(final_category)))
    from url_policy import default_importance
    if result.get("importance_reason") in {None, "", "routine_monitoring"}:
        result["importance_level"], result["importance_reason"] = default_importance(result)
    if result.get("spain_priority") and decision in {"accepted", "analyst_confirmed"}:
        result["tags"] = list(dict.fromkeys(result["tags"] + ["spain", "spain_confirmed"]))
    return normalize_policy_vocabulary(result)


def _detect_page_type(url: str, text: str, *, allow_url_hints: bool = False) -> str:
    """Infer page type from destination-owned text, never from its route.

    The legacy switch remains accepted so external callers do not break, but
    enabling it no longer changes classification behavior.
    """
    _ = (url, allow_url_hints)
    if any(term in text for term in ("sign in", "log in", "login required", "authentication required")):
        return "login_gate"
    if any(term in text for term in ("404 not found", "410 gone", "service unavailable", "server error")):
        return "error_page"
    if any(term in text for term in ("domain parked", "site parked", "coming soon")):
        return "parked_page"
    if "search engine" in text:
        return "search_page"
    if any(term in text for term in ("forum thread", "discussion thread", "posted by")):
        return "thread_page"
    if any(term in text for term in ("member profile", "user profile")):
        return "profile_page"
    if any(term in text for term in ("vendor profile", "seller profile")):
        return "vendor_page"
    if any(term in text for term in ("product page", "product listing", "item listing")):
        return "product_page"
    if any(term in text for term in ("category index", "browse categories")):
        return "category_page"
    if any(term in text for term in ("onion directory", "link directory", "link list", "directory index")):
        return "directory_page"
    if "paste page" in text:
        return "paste_page"
    if any(term in text for term in ("product listing", "vendor listing", "items for sale", "catalog of products")):
        return "listing_page"
    return "unknown"


def _financial_fraud_evidence(text: str) -> dict:
    explicit = _matches(text, EXPLICIT_FINANCIAL_FRAUD_PHRASES)
    indicators = _matches(text, HIGH_CONF_FINANCIAL_FRAUD_INDICATORS)
    generic = _matches(text, GENERIC_FINANCE_TERMS)
    normalized_explicit = {normalize_text(value) for value in explicit}
    normalized_indicators = {normalize_text(value) for value in indicators}
    explicit_hit = bool(normalized_explicit)
    indicator_count = len(normalized_indicators)
    benign = _matches(text, list(BENIGN_FRAUD_CONTEXT_TERMS))
    actionable = _matches(text, list(ACTIONABLE_FRAUD_CONTEXT_TERMS))
    benign_context = bool(benign) and not bool(actionable)
    strong = (explicit_hit or indicator_count >= 2) and not benign_context
    weak_context = bool(generic or indicators or explicit)
    return {
        "strong": strong,
        "explicit": explicit_hit,
        "indicator_count": indicator_count,
        "weak_context": weak_context and not strong and not benign_context,
        "benign_context": benign_context,
        "benign_labels": sorted({normalize_text(value) for value in benign} - {""}),
        "actionable_labels": sorted({normalize_text(value) for value in actionable} - {""}),
        "labels": sorted((normalized_explicit | normalized_indicators) - {""}),
        "generic_terms": sorted({normalize_text(value) for value in generic} - {""}),
    }


def _derive_site_type(primary: str, page_type: str, text: str) -> str:
    normalized_page_type = normalize_page_type(page_type)
    primary = str(primary or "unknown")
    if normalized_page_type == "login_wall" or "login required" in text:
        return "login_portal"
    if _matches(text, ["market review", "marketplace review", "vendor review", "review of market"]):
        return "market_review"
    if primary == "forum_social" or normalized_page_type in {"forum_index", "forum_thread"}:
        return "forum"
    if primary.startswith("marketplace") or normalized_page_type in {
        "marketplace_front", "marketplace_listing", "vendor_profile", "cart_checkout"}:
        return "marketplace"
    if normalized_page_type in {"link_repository"}:
        return "link_list"
    if primary in {"directory_index", "search_engine"} or normalized_page_type in {
        "directory_index_page", "search_results", "mirror_index"}:
        return "directory"
    if normalized_page_type == "paste_text":
        return "paste"
    if primary == "personal_blog" or "blog" in text:
        return "blog"
    return "unknown"


def _direct_transactional_structure(text: str, page_type: str) -> bool:
    structure_hits = _matches(text, [
        "vendor", "seller", "product", "listing", "order", "cart", "checkout",
        "wallet", "deposit", "escrow", "shipping", "ship to", "delivery",
        "dispatch", "shipment", "ship from", "sent from",
    ])
    return len({normalize_text(hit) for hit in structure_hits}) >= 2 or normalize_page_type(page_type) in {
        "vendor_profile", "marketplace_listing", "marketplace_front", "cart_checkout"}


def _apply_classification_dimensions(result: dict, url: str, text: str) -> None:
    primary = str(result.get("primary_category") or "unknown")
    page_type = str(result.get("page_type") or "unknown")
    site_type = _derive_site_type(primary, page_type, text)
    fraud = _financial_fraud_evidence(text)
    if primary in {"severe_abuse_risk", "adult_filtered", "adult_restricted"}:
        fraud = {"strong": False, "explicit": False, "indicator_count": 0,
                 "weak_context": False, "benign_context": False,
                 "benign_labels": [], "actionable_labels": [],
                 "labels": [], "generic_terms": []}
    direct_structure = _direct_transactional_structure(text, page_type)
    context_only = site_type in {"directory", "link_list"} and not direct_structure
    risk_categories: list[str] = []
    if primary in {"adult_filtered", "adult_restricted"}:
        risk_categories.append("adult")
    if primary in {"weapons_arms", "marketplace_weapons"} or int(result.get("weapons_evidence_score") or 0) >= 60:
        risk_categories.append("weapons")
    if primary in {"drugs", "marketplace_drugs"}:
        risk_categories.append("drugs")
    if primary in {"malware_hacking", "credentials", "marketplace_credentials", "leaks_data", "marketplace_leaks"}:
        risk_categories.append("cybercrime")
    if fraud["strong"]:
        risk_categories.append("financial_fraud")
    elif primary in {"fraud_financial", "marketplace_fraud"}:
        risk_categories.append("needs_review")
    risk_category = "unknown"
    unique_risks = list(dict.fromkeys(risk_categories))
    if len([item for item in unique_risks if item not in {"needs_review", "unknown"}]) > 1:
        risk_category = "mixed"
    elif unique_risks:
        risk_category = unique_risks[0]
    if risk_category == "unknown" and (fraud["weak_context"] or primary in {"marketplace", "forum_social"} and direct_structure):
        risk_category = "needs_review"

    if primary in {"fraud_financial", "marketplace_fraud"} and not fraud["strong"]:
        result["suggested_category"] = primary
        fallback = "marketplace" if site_type == "marketplace" else "forum_social" if site_type == "forum" else "unknown"
        result.update(
            primary_category=fallback, category=fallback,
            category_confidence="low",
            category_reason="Financial-fraud signal needs stronger direct evidence",
            category_safe_label=safe_category_label(fallback),
            risk_level="medium" if fallback == "marketplace" else "low",
            risk_flags=[flag for flag in result.get("risk_flags", []) if "fraud" not in str(flag)],
            storage_policy="metadata_limited" if fallback == "marketplace" else "safe_summary",
            review_status="needs_review",
        )
        primary = fallback

    urgent_score = 0
    urgent_reasons: list[str] = []
    live = result.get("active", 1) and result.get("status", "queued") != "dead"
    if primary == "severe_abuse_risk" or result.get("review_status") == "restricted":
        urgent_score += 100
        urgent_reasons.append("severe_or_control_required")
    if result.get("review_status") in {"needs_report", "report_required"}:
        urgent_score += 80
        urgent_reasons.append("report_required")
    if str(result.get("analyst_importance") or result.get("importance_level") or "").casefold() in {"high", "critical"}:
        urgent_score += 70
        urgent_reasons.append("analyst_importance_high")
    if (result.get("spain_priority") and result.get("spain_relevance") == "high"
            and result.get("spain_actionable") and not result.get("spain_context_only")
            and (direct_structure or fraud["strong"])):
        urgent_score += 70
        urgent_reasons.append("spain_direct_evidence")
    if (result.get("spain_priority") and result.get("spain_actionable")
            and not result.get("spain_context_only")
            and result.get("spain_evidence_type") in {"spanish_identity_data", "spanish_financial_target"}):
        urgent_score += 70
        urgent_reasons.append("spain_identity_or_financial_evidence")
    if (result.get("spain_priority") and result.get("spain_actionable")
            and result.get("spain_evidence_type") == "spanish_domain_threat_context"
            and (primary in {"leaks_data", "credentials", "fraud_financial"} or fraud["strong"])):
        urgent_score += 60
        urgent_reasons.append("spanish_domain_threat_context")
    if fraud["strong"] and direct_structure:
        urgent_score += 45
        urgent_reasons.append("direct_financial_fraud_needs_check")
    elif fraud["strong"]:
        urgent_score += 35
        urgent_reasons.append("financial_fraud_needs_check")
    if site_type == "marketplace" and direct_structure:
        urgent_score += 35
        urgent_reasons.append("direct_marketplace_needs_check")
    if context_only:
        urgent_score = min(urgent_score, 30)
        urgent_reasons.append("context_only_not_urgent")
    if not live and "severe_or_control_required" not in urgent_reasons:
        urgent_score = min(urgent_score, 20)
        urgent_reasons.append("not_live")
    urgent_flag = urgent_score >= 70
    result.update(
        site_type=site_type if site_type in SITE_TYPES else "unknown",
        risk_category=risk_category if risk_category in RISK_CATEGORIES else "unknown",
        context_only=bool(context_only),
        urgent_score=int(max(0, min(100, urgent_score))),
        urgent_flag=bool(urgent_flag),
        urgent_reason=", ".join(dict.fromkeys(urgent_reasons)) or None,
    )
    if fraud["labels"]:
        result["category_supporting_evidence"] = list(dict.fromkeys(
            result.get("category_supporting_evidence", []) + [f"financial_fraud:{label}" for label in fraud["labels"]]
        ))
    if fraud["weak_context"]:
        result["category_contradicting_evidence"] = list(dict.fromkeys(
            result.get("category_contradicting_evidence", []) + ["generic_finance_terms_not_enough"]
        ))
    if fraud["benign_context"]:
        result["category_contradicting_evidence"] = list(dict.fromkeys(
            result.get("category_contradicting_evidence", []) + ["defensive_or_informational_fraud_context"]
        ))


def _enrich_taxonomy(result: dict, url: str, combined: str, *, allow_url_hints: bool = False) -> None:
    primary = result.get("primary_category", "unknown")
    page_type = _detect_page_type(url, combined, allow_url_hints=allow_url_hints)
    result["page_type"] = page_type
    if primary in {"adult_filtered", "adult_restricted"}:
        result.update(category_confidence="critical", category_reason="Adult safety filter matched",
                      category_safe_label="Filtered adult content", display_group="Safety Restricted",
                      ui_hidden_default=1, ui_priority=0, review_score=0)
        return
    if primary == "severe_abuse_risk":
        result.update(category_confidence="critical", category_reason="Critical restricted safety policy matched",
                      category_safe_label="Restricted content — metadata only", display_group="Safety Restricted",
                      ui_hidden_default=1, ui_priority=90, review_score=90)
        return

    guard = structural_page_guard("", combined)
    market_words = _matches(combined, ["marketplace", "marketplaces", "market", "markets", "shop", "store", "bazaar"])
    market_tags = _matches(combined, ["vendor", "catalog", "product listings", "items for sale"])
    direct_listing = bool(market_words or _matches(combined, ["vendor listings", "items for sale", "product listing"]))
    directory_like = page_type == "directory_page" or primary == "directory_index"
    forum_like = primary == "forum_social" or page_type == "thread_page" or bool(_matches(combined, ["discussion forum", "community forum"]))
    market_context = bool(market_words or market_tags or primary == "marketplace")
    secondary = [category for category in result.get("tags", []) if category not in {primary, "unknown"}]
    if page_type == "thread_page" and primary != "forum_social" and "forum_social" not in secondary:
        secondary.append("forum_social")
    if primary != "extremist_recruitment" and _matches(combined, ["recruitment", "reclutamiento", "join our group"]):
        secondary.append("extremist_recruitment")
    forum_threat = next((category for category, terms in (
        ("leaks_data", ["data leak", "leak forum", "breach data"]),
        ("credentials", ["credential dump", "stolen credentials"]),
        ("weapons_arms", ["weapons trafficking", "firearms sale"]),
        ("drugs", ["drug market", "narcotics market"]),
        ("fraud_financial", ["carding", "financial fraud"]),
        ("malware_hacking", ["malware", "ransomware"]),
    ) if _matches(combined, terms)), None)

    if market_context and "marketplace" not in result["tags"]:
        result["tags"].append("marketplace")
    if directory_like and market_context and not _matches(combined, ["items for sale", "vendor listings"]):
        primary = "directory_index"
        result["storage_policy"] = "safe_summary"
        result["review_status"] = "pending"
        result["queue_policy"] = "expand"
    elif forum_like and market_context and not _matches(combined, ["items for sale", "vendor listings"]):
        confirmed_threat = primary if primary in THREAT_PRIMARY_CATEGORIES else forum_threat
        primary = confirmed_threat or "forum_social"
        if confirmed_threat:
            result.update(storage_policy="metadata_limited", review_status="needs_review",
                          screenshot_policy="blocked", queue_policy="reviewable")
        else:
            result.update(storage_policy="safe_summary", review_status="pending", queue_policy="expand")
    elif market_context and direct_listing:
        subtype = None
        subtype_rules = [
            ("drugs", "marketplace_drugs", ["drug", "drugs", "narcotics", "drogas"]),
            ("weapons_arms", "marketplace_weapons", ["weapon", "weapons", "gun", "guns", "firearms", "armas"]),
            ("credentials", "marketplace_credentials", ["credential", "credentials", "password list", "login data", "credenciales"]),
            ("leaks_data", "marketplace_leaks", ["leak", "breach data", "database dump", "filtracion"]),
            ("fraud_financial", "marketplace_fraud", ["fraud", "carding", "cvv", "fullz", "estafa"]),
        ]
        category_signals = set(result.get("tags", [])) | {result.get("primary_category")}
        for base, market_category, terms in subtype_rules:
            if base == "weapons_arms" and not (
                    int(result.get("weapons_evidence_score") or 0) >= 60
                    and len(result.get("weapons_evidence_families") or []) >= 2):
                continue
            if base in category_signals or _matches(combined, terms):
                subtype = market_category
                if base not in secondary: secondary.append(base)
                break
        if not subtype and _matches(combined, ["counterfeit", "replica goods", "fake documents"]):
            subtype = "marketplace_counterfeit"
        if not subtype and _matches(combined, ["services marketplace", "services for sale", "hire service"]):
            subtype = "marketplace_services"
        primary = subtype or "marketplace"
        if subtype:
            result["risk_level"] = "high"
        result.update(storage_policy="metadata_limited", review_status="needs_review",
                      screenshot_policy="blocked", screenshot_blocked_reason="marketplace_metadata_only",
                      queue_policy="reviewable", active=1)

    fraud_hits = _matches(combined, ["cloned card", "cloned cards", "digital cc", "fullz", "carding guide",
                                     "atm cashout", "cashout", "cvv", "payment card fraud", "dumps"])
    fraud_evidence = _financial_fraud_evidence(combined)
    fraud_structure = bool(market_context or page_type in {
        "vendor_page", "product_page", "listing_page", "login_gate"})
    if fraud_hits and fraud_evidence["strong"]:
        safe_labels = ["carding", "payment_card_fraud"]
        normalized_hits = " ".join(normalize_text(hit) for hit in fraud_hits)
        if "cloned card" in normalized_hits: safe_labels.append("cloned_cards")
        if "fullz" in normalized_hits: safe_labels.append("fullz")
        if "digital cc" in normalized_hits: safe_labels.append("digital_cc")
        if "cashout" in normalized_hits: safe_labels.append("cashout_fraud")
        secondary.extend(safe_labels)
        if directory_like and not _direct_transactional_structure(combined, page_type):
            primary = "directory_index"
            result.update(storage_policy="safe_summary", queue_policy="expand")
            result["risk_flags"] = list(dict.fromkeys(result.get("risk_flags", []) + ["fraud_context"]))
            result["review_status"] = "needs_review"
        else:
            primary = "marketplace_fraud" if fraud_structure else "fraud_financial"
            result.update(risk_level="critical" if fraud_structure and len(set(fraud_hits)) >= 2 else "high",
                          storage_policy="metadata_limited", screenshot_policy="blocked",
                          screenshot_blocked_reason="fraud_marketplace_metadata_only",
                          review_status="needs_review", queue_policy="reviewable", active=1,
                          safety_reason="fraud_marketplace_metadata_only")
            result["risk_flags"] = list(dict.fromkeys(result.get("risk_flags", []) + [
                "payment_card_fraud_signal", "carding_marketplace_signal" if fraud_structure else "cashout_fraud_signal"] ))
            if fraud_structure and page_type in {"homepage", "unknown", "category_page"}:
                page_type = "marketplace_home"
    elif fraud_hits and fraud_evidence["benign_context"]:
        secondary.append("fraud_context")
        result["risk_flags"] = list(dict.fromkeys(
            result.get("risk_flags", []) + ["defensive_or_informational_fraud_context"]
        ))

    if primary == "unknown" and guard == "code_repository":
        primary = "hosting_services"
        secondary.extend(["code_repository", "development_platform"])
        result.update(storage_policy="safe_summary", review_status="monitor", queue_policy="normal")
    elif primary == "unknown" and guard == "wiki":
        primary = "directory_index"
        secondary.extend(["wiki", "documentation"])
        result.update(storage_policy="safe_summary", review_status="monitor", queue_policy="expand")
    elif primary == "unknown" and guard == "forum":
        primary = "forum_social"
        result.update(storage_policy="safe_summary", review_status="monitor", queue_policy="expand")
    elif primary == "unknown" and (page_type == "search_page" or _matches(combined, ["search engine", "onion search"])):
        primary = "search_engine"
    elif primary == "directory_index" and page_type == "search_page":
        primary = "search_engine"

    result["primary_category"] = result["category"] = primary
    result["page_type"] = page_type
    result["secondary_categories"] = list(dict.fromkeys(secondary))
    result["marketplace_type"] = primary.removeprefix("marketplace_") if primary.startswith("marketplace_") else ("general" if primary == "marketplace" else None)
    result["category_confidence"] = "high" if primary in MARKETPLACE_CATEGORIES and direct_listing else result.get("confidence", "low")
    if (primary in {"directory_index", "search_engine", "forum_social"} or primary in NEUTRAL_CATEGORIES) and result["category_confidence"] == "low":
        result["category_confidence"] = "medium"
    result["category_safe_label"] = safe_category_label(primary)
    if primary in MARKETPLACE_CATEGORIES:
        result["category_reason"] = "Direct marketplace or listing structure detected"
        result["display_group"] = "Marketplaces"
    elif primary in {"directory_index", "search_engine", "forum_social", "hosting_services", "contact_infrastructure"}:
        result["category_reason"] = "Discovery or community page structure detected"
        result["display_group"] = "Discovery"
    elif primary in NEUTRAL_CATEGORIES:
        result["category_reason"] = "Neutral informational topic detected"
        result["display_group"] = "Neutral / informational"
    elif primary in {"leaks_data", "credentials", "malware_hacking", "weapons_arms", "drugs", "fraud_financial", "extremist_recruitment"}:
        result["category_reason"] = "Threat-related context detected"
        result["display_group"] = "Threats"
    else:
        result["category_reason"] = "No stronger category structure detected"
        result["display_group"] = "Other"
    if primary in ({"directory_index", "search_engine", "forum_social", "hosting_services",
                    "contact_infrastructure", "unknown"} | NEUTRAL_CATEGORIES):
        result["review_status"] = "needs_review" if result.get("spain_priority") and result.get("spain_confidence") == "high" else "monitor"
    if (result.get("storage_policy") == "metadata_limited"
            and primary in MARKETPLACE_CATEGORIES | {"fraud_financial", "drugs", "weapons_arms"}
            and not result.get("spain_priority")
            and not result.get("urgent_flag")
            and result.get("review_status") in {"pending", "needs_review"}):
        result["review_status"] = "monitor"
    risk_points = {"low": 10, "medium": 30, "high": 60, "critical": 90}.get(str(result.get("risk_level", "low")).casefold(), 10)
    market_points = 20 if primary in MARKETPLACE_CATEGORIES else 0
    result["review_score"] = risk_points + market_points + (60 if result.get("spain_priority") else 0)
    result["ui_priority"] = result["review_score"]
    if fraud_hits:
        result["review_score"] = max(85, result["review_score"])
        result["ui_priority"] = max(85, result["ui_priority"])
    result["ui_hidden_default"] = int(primary in {"spam_noise", "dead_softdead"})


def _term_spans(text: str, term: str) -> list[tuple[int, int]]:
    """Return bounded lexical spans for already-normalized classifier text."""
    needle = normalize_text(term)
    if not needle:
        return []
    if any(char in needle for char in (".", "/", ":")):
        pattern = re.escape(needle)
    else:
        pattern = r"(?<!\w)" + re.escape(needle) + r"(?!\w)"
    return [(match.start(), match.end()) for match in re.finditer(pattern, text)]


def _family_hits(text: str, families: dict[str, tuple[str, ...]]) -> dict[str, dict]:
    """Collect one canonical fact per semantic family, retaining local spans."""
    found: dict[str, dict] = {}
    for family, aliases in families.items():
        spans: list[tuple[int, int]] = []
        labels: list[str] = []
        for alias in sorted(aliases, key=lambda value: len(normalize_text(value)), reverse=True):
            alias_spans = _term_spans(text, alias)
            if not alias_spans:
                continue
            spans.extend(alias_spans)
            labels.append(normalize_text(alias))
        if spans:
            found[family] = {
                "spans": sorted(set(spans)),
                "label": max(labels, key=len),
            }
    return found


def _loose_family_hits(text: str, terms: list[str] | tuple[str, ...], prefix: str) -> dict[str, dict]:
    """Canonicalize config terms and collapse aliases occupying the same span."""
    candidates: list[tuple[int, int, str]] = []
    for term in sorted({normalize_text(value) for value in terms if normalize_text(value)}, key=len, reverse=True):
        candidates.extend((start, end, term) for start, end in _term_spans(text, term))
    accepted: list[tuple[int, int, str]] = []
    for start, end, label in sorted(candidates, key=lambda row: (row[0], -(row[1] - row[0]))):
        if any(start < other_end and other_start < end for other_start, other_end, _ in accepted):
            continue
        accepted.append((start, end, label))
    found: dict[str, dict] = {}
    for start, end, label in accepted:
        family = f"{prefix}:{label}"
        item = found.setdefault(family, {"spans": [], "label": label})
        item["spans"].append((start, end))
    return found


def _all_spans(*groups: dict[str, dict]) -> list[tuple[int, int]]:
    return [span for group in groups for item in group.values() for span in item["spans"]]


def _spans_near(left: list[tuple[int, int]], right: list[tuple[int, int]], max_gap: int = 240) -> bool:
    for left_start, left_end in left:
        for right_start, right_end in right:
            gap = max(0, max(left_start, right_start) - min(left_end, right_end))
            if gap <= max_gap:
                return True
    return False


def _safe_spain_snippets(matches: list[str], limit: int = 4) -> list[str]:
    """Store signal labels only; never persist product/listing text as Spain evidence."""
    labels = []
    for match in matches:
        normalized = normalize_text(match)
        if normalized and normalized not in labels:
            labels.append(normalized[:80])
        if len(labels) >= limit:
            break
    return labels


def _spain_context_page(result: dict, combined: str) -> bool:
    primary = str(result.get("primary_category") or "unknown")
    page_type = normalize_page_type(result.get("page_type"))
    site_type = _derive_site_type(primary, page_type, combined)
    if site_type in {"directory", "link_list", "market_review"}:
        return True
    return page_type in {
        "directory_index_page", "link_repository", "search_results", "forum_index", "category_index", "article_page"
    } and not _direct_transactional_structure(combined, page_type)


def _spain_direct_page(result: dict, combined: str) -> bool:
    primary = str(result.get("primary_category") or "unknown")
    page_type = normalize_page_type(result.get("page_type"))
    fraud = _financial_fraud_evidence(combined)
    return (
        _direct_transactional_structure(combined, page_type)
        or primary.startswith("marketplace")
        or primary in {"fraud_financial", "weapons_arms", "drugs", "credentials", "leaks_data", "malware_hacking"}
        or page_type in {"vendor_profile", "marketplace_listing", "marketplace_front", "cart_checkout"}
        or fraud["strong"]
    )


def _apply_spain(result: dict, combined: str, language: str, url: str) -> None:
    from url_policy import locale_path

    cfg = _load(SAFETY_CONFIG_PATH)["spain"]
    strong = _matches(combined, cfg["strong"] + cfg.get("strong_additional", []))
    generic_europe = {"europe", "eu", "european union", "union europea", "europa"}
    strong = [term for term in strong if normalize_text(term) not in generic_europe]
    language_only_terms = {"spanish", "espanol", "espanola", "espanoles", "испанский", "испанская", "испанские"}
    country_terms = [term for term in cfg["country"] + cfg.get("country_additional", [])
                     if normalize_text(term) not in language_only_terms]
    country = _matches(combined, country_terms)
    cities = _matches(combined, cfg["weak_cities"] + cfg.get("weak_cities_additional", []))
    threats = _matches(combined, cfg["threat_context"])
    geopolitical = _matches(combined, cfg["russian_geopolitical"])
    flow_to = _matches(combined, [
        "ship to spain", "ships to spain", "shipping to spain", "deliver to spain",
        "delivery to spain", "send to spain", "envio a espana", "envios a espana",
        "enviamos a espana", "entrega en espana", "entregas en espana",
    ])
    flow_from = _matches(combined, [
        "ship from spain", "ships from spain", "shipping from spain", "sent from spain",
        "dispatch from spain", "envio desde espana", "enviado desde espana", "sale de espana",
    ])
    category = str(result.get("primary_category") or "unknown")
    relevant_category = (category in THREAT_CATEGORIES or category.startswith("marketplace"))
    market_or_actor_context = bool(_matches(combined, [
        "vendor", "seller", "marketplace", "listing", "for sale", "shipping", "delivery",
        "thread", "posted by", "author", "contact",
    ]))
    relevant_context = bool(threats or geopolitical or relevant_category or market_or_actor_context)
    priority = bool(strong or flow_to or flow_from or ((country or cities) and relevant_context))
    locale = locale_path(url)
    spanish_language = bool(language == "ES" or locale == "es" or _matches(combined, list(language_only_terms)))
    result.update(language=language, locale_path=locale,
                  spanish_language_detected=spanish_language)
    if not priority:
        if spanish_language:
            result["spain_priority_reason"] = "spanish_language_only_not_priority"
            result["spain_priority_evidence_type"] = "language_only"
        if _matches(combined, list(generic_europe)):
            result["tags"] = list(dict.fromkeys(result.get("tags", []) + ["europe_context"]))
        return
    result["spain_priority"] = True
    result["geo_priority"] = "spain"
    result["tags"] = list(dict.fromkeys(result["tags"] + ["spain_priority"]))
    result["risk_flags"] = list(dict.fromkeys(result["risk_flags"] + ["spain_priority"]))
    result["priority_score"] += 50 if strong or flow_to or flow_from else 35 if threats or geopolitical else 25
    result["spain_match_language"] = language
    result["spain_confidence"] = "high" if strong or flow_to or flow_from or (
        country and relevant_category and (threats or market_or_actor_context)
    ) else "medium"
    contexts = []
    if strong: contexts.append("strong_institution_or_domain")
    if cities and threats: contexts.append("city_plus_threat_context")
    if geopolitical: contexts.append("russian_geopolitical_context")
    if threats: contexts.append("threat_context")
    if country and relevant_category: contexts.append("country_plus_verified_category")
    if (country or cities) and market_or_actor_context: contexts.append("market_or_actor_context")
    if flow_to: contexts.append("trade_flow_to_spain")
    if flow_from: contexts.append("trade_flow_from_spain")
    result["spain_context_tags"] = contexts
    if flow_to and flow_from:
        result["spain_match_reason"] = "Visible delivery or sending references both to and from Spain"
        result["spain_priority_reason"] = "spanish_market_targeting"
        result["spain_priority_evidence_type"] = "trade_flow_both"
    elif flow_to:
        result["spain_match_reason"] = "Visible delivery or sending reference to Spain"
        result["spain_priority_reason"] = "spanish_market_targeting"
        result["spain_priority_evidence_type"] = "shipping_to_spain"
    elif flow_from:
        result["spain_match_reason"] = "Visible delivery or sending reference from Spain"
        result["spain_priority_reason"] = "spanish_actor_or_seller"
        result["spain_priority_evidence_type"] = "shipping_from_spain"
    elif strong:
        result["spain_match_reason"] = "Strong Spanish institution or official-domain reference"
        result["spain_priority_reason"] = "spanish_financial_target" if _matches(combined, [
            "spanish bank", "banco espanol", "bank of spain", "banco de espana"
        ]) else "spain_country_reference"
        result["spain_priority_evidence_type"] = "institution_or_official_domain"
    elif geopolitical:
        result["spain_match_reason"] = "Spain reference with Russian or geopolitical threat context"
        result["spain_priority_reason"] = "spain_country_reference"
        result["spain_priority_evidence_type"] = "geopolitical_context"
    elif cities:
        result["spain_match_reason"] = "Spanish city or province paired with relevant context"
        result["spain_priority_reason"] = "spanish_city_reference"
        result["spain_priority_evidence_type"] = "city_or_province"
    elif market_or_actor_context:
        result["spain_match_reason"] = "Spain reference paired with seller, actor, or market context"
        result["spain_priority_reason"] = "spanish_actor_or_seller"
        result["spain_priority_evidence_type"] = "actor_or_market_context"
    else:
        result["spain_match_reason"] = "Spain reference paired with threat-related context"
        result["spain_priority_reason"] = "spain_country_reference"
        result["spain_priority_evidence_type"] = "country_plus_threat"


def _apply_spain_evidence(result: dict, combined: str, language: str, url: str) -> None:
    """Evidence-based Spain model: language/category context is not priority by itself."""
    from url_policy import locale_path

    cfg = _load(SAFETY_CONFIG_PATH)["spain"]
    generic_europe = {"europe", "eu", "european union", "union europea", "europa"}
    non_country_terms = SPAIN_LANGUAGE_ONLY_TERMS | generic_europe
    country_terms = [term for term in cfg["country"] + cfg.get("country_additional", [])
                     if normalize_text(term) not in non_country_terms and normalize_text(term) != ".es"]
    city_terms = [term for term in list(SPAIN_LOCATION_SIGNALS) + cfg["weak_cities"] + cfg.get("weak_cities_additional", [])
                  if normalize_text(term) not in {"spain", "espana"}]

    shipping = _family_hits(combined, SPAIN_SHIPPING_FAMILIES)
    logistics = _family_hits(combined, SPAIN_LOGISTICS_FAMILIES)
    payments = _family_hits(combined, SPAIN_PAYMENT_FAMILIES)
    identity_docs = _family_hits(combined, SPAIN_IDENTITY_FAMILIES)
    banks = _family_hits(combined, SPAIN_BANK_FAMILIES)
    institutions = _family_hits(combined, SPAIN_INSTITUTION_FAMILIES)
    configured_strong = _loose_family_hits(
        combined,
        [term for term in cfg["strong"] + cfg.get("strong_additional", [])
         if normalize_text(term) not in generic_europe],
        "institution",
    )
    existing_institution_spans = _all_spans(institutions)
    for family, item in configured_strong.items():
        if not _spans_near(item["spans"], existing_institution_spans, 0):
            institutions[family] = item
    country = _loose_family_hits(combined, country_terms, "country")
    cities = _loose_family_hits(combined, city_terms, "location")
    threats = _loose_family_hits(combined, cfg["threat_context"], "threat")
    geopolitical = _loose_family_hits(combined, cfg["russian_geopolitical"], "geopolitical")
    compromise = _loose_family_hits(combined, list(SPAIN_COMPROMISE_SIGNALS), "compromise")
    fraud_action = _loose_family_hits(
        combined, list(EXPLICIT_FINANCIAL_FRAUD_PHRASES) + list(HIGH_CONF_FINANCIAL_FRAUD_INDICATORS), "fraud"
    )
    transaction = _loose_family_hits(combined, list(SPAIN_TRANSACTION_SIGNALS), "transaction")
    dot_es_context = bool(re.search(r"\b[a-z0-9.-]+\.es\b", combined))
    flow_to = "shipping_to_spain" in shipping
    flow_from = "shipping_from_spain" in shipping
    locale = locale_path(url)
    spanish_language = bool(language == "ES" or locale == "es" or _matches(combined, list(SPAIN_LANGUAGE_ONLY_TERMS)))
    category = str(result.get("primary_category") or "unknown")
    restricted = category in {"adult_filtered", "adult_restricted", "severe_abuse_risk"} or result.get("storage_policy") == "discard"
    context_only = _spain_context_page(result, combined)
    direct_page = _spain_direct_page(result, combined) and not context_only

    spain_target_spans = _all_spans(shipping, logistics, payments, identity_docs, banks, institutions, cities, country)
    transaction_spans = _all_spans(transaction)
    action_spans = _all_spans(compromise, fraud_action, threats, geopolitical)
    shipping_spans = _all_spans(shipping)
    identity_spans = _all_spans(identity_docs)
    bank_spans = _all_spans(banks)
    institution_spans = _all_spans(institutions)
    market_or_actor_context = bool(transaction) and (
        bool(shipping) or _spans_near(spain_target_spans, transaction_spans)
    )
    local_action = _spans_near(spain_target_spans, action_spans)
    identity_action = _spans_near(identity_spans, action_spans)
    bank_action = _spans_near(bank_spans, action_spans)
    institution_action = _spans_near(institution_spans, action_spans)
    shipping_support = bool(logistics or payments or cities or country) and _spans_near(
        shipping_spans, _all_spans(logistics, payments, cities, country)
    )
    payment_action = _spans_near(_all_spans(payments), action_spans)
    location_action = _spans_near(_all_spans(cities, country), action_spans)
    independent_signal_count = sum(bool(group) for group in (
        shipping, logistics, payments, identity_docs, banks, institutions, cities, country
    ))
    contexts = []
    if spanish_language:
        contexts.append("spanish_language_detected")
    if institutions:
        contexts.append("strong_institution_or_domain")
    if cities and (shipping or payments or logistics or market_or_actor_context):
        contexts.append("city_plus_seller_context")
    if geopolitical and local_action:
        contexts.append("russian_geopolitical_context")
    if threats and local_action:
        contexts.append("threat_context")
    if shipping or logistics or payments:
        contexts.append("spanish_trade_signal")
    if identity_docs:
        contexts.append("spanish_identity_document_signal")
    if banks:
        contexts.append("spanish_financial_institution_signal")
    if dot_es_context:
        contexts.append("spanish_domain_signal")
    if (country or cities) and market_or_actor_context:
        contexts.append("market_or_actor_context")
    if flow_to:
        contexts.append("trade_flow_to_spain")
    if flow_from:
        contexts.append("trade_flow_from_spain")

    relevance = "none"
    seller_geo_confidence = "none"
    evidence_confidence = "none"
    evidence_type = None
    reason_code = None
    match_reason = None
    if _matches(combined, list(generic_europe)):
        result["tags"] = list(dict.fromkeys(result.get("tags", []) + ["europe_context"]))
    if restricted:
        relevance = "low" if (country or cities or shipping or logistics or payments or spanish_language) else "none"
        context_only = True
        reason_code = "restricted_safety_takes_precedence" if relevance != "none" else None
        evidence_type = "location_mention" if relevance != "none" else None
        match_reason = "Restricted safety policy takes precedence over Spain filtering" if relevance != "none" else None
    elif context_only and (country or cities or shipping or logistics or payments or identity_docs or banks or institutions or spanish_language):
        relevance = "low"
        evidence_type = "language_only" if spanish_language and not (
            country or cities or shipping or logistics or payments or identity_docs or banks or institutions
        ) else "location_mention"
        reason_code = "spain_context_only_not_priority"
        match_reason = "Spain signal appears on a context-only page, not a direct seller or listing page"
    elif identity_docs and identity_action:
        relevance = "high"
        evidence_confidence = "high"
        evidence_type = "spanish_identity_data"
        reason_code = "spanish_identity_target"
        match_reason = "Spanish identity-document evidence appears near leak, breach, sale, or exfiltration context"
    elif banks and bank_action:
        relevance = "high"
        evidence_confidence = "high"
        evidence_type = "spanish_financial_target"
        reason_code = "spanish_financial_target"
        match_reason = "Spanish bank evidence appears near direct fraud, leak, breach, sale, or exfiltration context"
    elif institutions and institution_action:
        relevance = "high"
        evidence_confidence = "high"
        evidence_type = "spanish_institution_target"
        reason_code = "spanish_institution_target"
        match_reason = "Spanish institution evidence appears near leak, breach, sale, or exfiltration context"
    elif payments and payment_action and direct_page:
        relevance = "high" if len(payments) >= 2 else "medium"
        evidence_confidence = "high" if len(payments) >= 2 else "medium"
        evidence_type = "spanish_financial_target"
        reason_code = "spanish_financial_target"
        match_reason = "Spanish payment evidence appears near direct fraud, leak, breach, or sale context"
    elif dot_es_context and bool(action_spans) and not context_only:
        relevance = "medium"
        evidence_confidence = "medium"
        evidence_type = "spanish_domain_threat_context"
        reason_code = "spanish_market_targeting" if market_or_actor_context else "spain_country_reference"
        match_reason = ".es or Spanish-domain evidence appears with leak, fraud, credential, or threat context"
    elif direct_page and shipping and shipping_support:
        relevance = "high"
        seller_geo_confidence = "high"
        evidence_confidence = "high"
        evidence_type = "direct_seller_geo" if flow_from else "shipping_signal"
        reason_code = "spanish_actor_or_seller" if flow_from else "spanish_market_targeting"
        if flow_from:
            match_reason = "Direct page has shipping from Spain evidence plus supporting logistics, payment, or location signal"
        elif flow_to:
            match_reason = "Direct page has shipping to Spain evidence plus supporting logistics, payment, or location signal"
        else:
            match_reason = "Direct page has Spain seller/shipping evidence plus supporting logistics, payment, or location signal"
    elif direct_page and (shipping or (independent_signal_count >= 2 and market_or_actor_context)):
        relevance = "medium"
        seller_geo_confidence = "medium" if shipping else "none"
        evidence_confidence = "medium"
        evidence_type = "shipping_signal" if shipping else "payment_signal" if payments else "logistics_signal"
        reason_code = "spanish_market_targeting"
        match_reason = "Direct page has Spain logistics, payment, seller, or shipping evidence"
    elif direct_page and (cities or country) and (market_or_actor_context or location_action):
        relevance = "low"
        evidence_confidence = "low"
        evidence_type = "location_mention"
        reason_code = "spanish_city_reference" if cities else "spain_country_reference"
        match_reason = "Spain location is mentioned with relevant context but no direct seller geo proof"
    elif spanish_language:
        relevance = "low"
        evidence_confidence = "low"
        evidence_type = "language_only"
        reason_code = "spanish_language_only_not_priority"
        match_reason = "Spanish language or locale only; not Spain targeting"

    direct_spain_evidence = evidence_type in {
        "spanish_identity_data", "spanish_financial_target", "spanish_institution_target",
        "spanish_domain_threat_context",
    }
    spain_evidence_score = 0
    if shipping:
        spain_evidence_score += 40 + min(10, max(0, len(shipping) - 1) * 5)
    if logistics and (shipping_support or market_or_actor_context):
        spain_evidence_score += 15
    if payments:
        spain_evidence_score += 20 + min(15, max(0, len(payments) - 1) * 10)
    if identity_docs:
        spain_evidence_score += 25 + min(20, max(0, len(identity_docs) - 1) * 15)
    if banks:
        spain_evidence_score += 35 + min(15, max(0, len(banks) - 1) * 10)
    if institutions:
        spain_evidence_score += 35
    if (country or cities) and not shipping:
        spain_evidence_score += 10
    if dot_es_context:
        spain_evidence_score += 10
    if local_action:
        spain_evidence_score += 25
    if direct_spain_evidence and local_action:
        spain_evidence_score += 15
    elif direct_page:
        spain_evidence_score += 15
    if market_or_actor_context:
        spain_evidence_score += 10
    spain_evidence_score = min(100, spain_evidence_score)

    actionable = (
        not restricted
        and not context_only
        and (direct_spain_evidence or (direct_page and seller_geo_confidence in {"medium", "high"}))
        and spain_evidence_score >= 75
        and bool(result.get("active", 1))
        and result.get("status", "queued") != "dead"
    )
    priority = actionable and relevance in {"medium", "high"}
    result.update(
        language=language,
        locale_path=locale,
        spanish_language_detected=spanish_language,
        spain_relevance=relevance,
        spain_evidence_type=evidence_type,
        seller_geo_confidence=seller_geo_confidence,
        spain_evidence_snippets=_safe_spain_snippets([
            item["label"] for group in (
                shipping, logistics, payments, identity_docs, banks, institutions, cities, country
            ) for item in group.values()
        ]),
        spain_evidence_families=list(dict.fromkeys(
            list(shipping) + list(logistics) + list(payments) + list(identity_docs) +
            list(banks) + list(institutions) + list(cities) + list(country)
        )),
        spain_evidence_source_url=url,
        spain_evidence_source_path=urlsplit(url or "").path or "/",
        spain_evidence_score=spain_evidence_score,
        spain_context_only=bool(context_only and relevance != "none"),
        spain_actionable=bool(actionable),
        spain_priority=bool(priority),
        geo_priority="spain" if priority else None,
        spain_match_language=language if relevance != "none" else None,
        spain_confidence=evidence_confidence if priority else ("low" if relevance == "low" else None),
        spain_context_tags=list(dict.fromkeys(contexts)),
        spain_match_reason=match_reason,
        spain_priority_reason=reason_code,
        spain_priority_evidence_type=evidence_type,
    )
    if priority:
        result["tags"] = list(dict.fromkeys(result["tags"] + ["spain_priority"]))
        result["risk_flags"] = list(dict.fromkeys(result["risk_flags"] + ["spain_priority"]))
        result["priority_score"] += 50 if relevance == "high" else 35


def extract_weighted_tags(text: str, storage_policy: str = "safe_summary") -> tuple[list[str], str, str]:
    if storage_policy in {"metadata_only", "discard"}:
        return [], "low", "Keyword extraction disabled by safety policy"
    cfg = _load(TAG_CONFIG_PATH)["tags"]
    normalized = normalize_text(text)
    tags, strongest = [], 0
    for tag, rules in cfg.items():
        strong = _matches(normalized, rules.get("strong", []))
        medium = _matches(normalized, rules.get("medium", []))
        if strong or len(medium) >= 2:
            tags.append(tag)
            strongest = max(strongest, 2 if strong else 1)
    confidence = "high" if strongest >= 2 and len(tags) >= 2 else "medium" if tags else "low"
    summary = ", ".join(tags) if tags else "No strong tags"
    return tags, confidence, summary


def _apply_page_understanding(result: dict, page_structure: dict | None, visible_text: str) -> None:
    """Resolve an otherwise unknown fetched page using its own HTML structure."""
    if result.get("primary_category") != "unknown" or not page_structure:
        return
    signals = [str(value) for value in page_structure.get("signals", []) if value]
    scores = {str(key): int(value or 0) for key, value in (page_structure.get("scores") or {}).items()}
    result["evidence_families"] = list(dict.fromkeys(result.get("evidence_families", []) + signals))
    if page_structure.get("has_password_form"):
        result.update(
            page_type="login_gate", category_safe_label="Access-limited page",
            category_reason="The fetched page is a login gate, so its underlying area cannot be classified",
            review_status="monitor", ui_hidden_default=1, display_group="Access limited",
        )
        return
    candidates = [
        (scores.get("forum", 0), "forum_social"),
        (scores.get("directory", 0), "directory_index"),
        (scores.get("marketplace", 0), "marketplace"),
        (scores.get("search", 0), "search_engine"),
    ]
    score, category = max(candidates, default=(0, "general_other"))
    if score < 3:
        category = "general_other" if len(visible_text.strip()) >= 80 or scores.get("article", 0) >= 2 else "unknown"
    if category == "unknown":
        result.update(category_safe_label="Insufficient page evidence", ui_hidden_default=1,
                      display_group="Access limited", review_status="monitor")
        return
    page_type = result.get("page_type") or "unknown"
    if category == "forum_social" and page_type in {"unknown", "homepage"}:
        page_type = "forum_home"
    elif category == "directory_index":
        page_type = "link_repository" if int(page_structure.get("onion_link_count") or 0) >= 5 else "directory_page"
    elif category == "search_engine":
        page_type = "search_page"
    elif category == "marketplace" and page_type in {"unknown", "homepage"}:
        page_type = "marketplace_home"
    elif category == "general_other" and page_type == "unknown" and scores.get("article", 0) >= 2:
        page_type = "article_page"
    result.update(
        primary_category=category, category=category, tags=list(dict.fromkeys(result.get("tags", []) + [category])),
        category_confidence="high" if score >= 4 else "medium",
        category_reason="Fetched page structure matched " + category.replace("_", " "),
        category_safe_label=safe_category_label(category), page_type=page_type,
        display_group="Marketplaces" if category == "marketplace" else "Discovery" if category in {
            "forum_social", "directory_index", "search_engine"} else "Other",
        risk_level="medium" if category == "marketplace" else "low",
        storage_policy="metadata_limited" if category == "marketplace" else "safe_summary",
        review_status="needs_review" if category == "marketplace" else "monitor",
        safety_reason="page_structure_" + category,
        screenshot_policy="blocked" if category == "marketplace" else "allowed",
        screenshot_blocked_reason="marketplace_metadata_only" if category == "marketplace" else None,
        queue_policy="reviewable" if category == "marketplace" else "expand" if category in {
            "forum_social", "directory_index", "search_engine"} else "normal",
        active=1, ui_hidden_default=1 if category == "general_other" else 0,
        ui_priority=0, review_score=20 if category == "marketplace" else 0,
    )


def classify(url: str, title: str | None = None, meta: str | None = None,
             visible_text: str | None = None, anchor_text: str | None = None,
             source_url: str | None = None, source_context: str | None = None,
             ocr_text: str | None = None, classification_scope: str = "page",
             page_structure: dict | None = None) -> dict:
    cfg = _load(SAFETY_CONFIG_PATH)
    # This function is the final fetched-page classifier. Its evidence boundary
    # is deliberately fixed to the destination's returned HTML regardless of a
    # legacy caller's ``classification_scope`` value. Discovery metadata belongs
    # in ``classify_url_prefetch`` and can never become final page evidence.
    # Meta descriptions/keywords are retained as low-trust source metadata, but
    # never merged into title evidence.  This prevents a link-list keyword blob
    # from becoming a high-confidence page classification.
    title_text = normalize_text(title)
    meta_hint_text = normalize_text(meta)
    body_text = normalize_text(visible_text)
    # OCR is a transient preview-artifact guard, not destination HTML.  Keep the
    # legacy parameter diagnostic-only so it can never alter the canonical page
    # category persisted by crawler/verify workers.
    ocr_normalized = normalize_text(ocr_text)
    content_text = " ".join(filter(None, [title_text, body_text]))
    combined = content_text
    language = detect_language(title or "", visible_text or "")
    result = _base_result()
    if meta_hint_text:
        result["html_meta_hint_present"] = True
    weapons_evidence = _weapons_evidence("", title_text, body_text)
    result.update(
        weapons_evidence_score=weapons_evidence["score"],
        weapons_evidence_families=weapons_evidence["families"],
        weapons_commercial_context=weapons_evidence["commercial"],
        weapons_context_type=weapons_evidence["context_type"],
    )
    result["ocr_checked"] = bool(ocr_text is not None)
    guard = structural_page_guard("", content_text)
    adult = _adult_evidence(
        title_text, body_text, cfg["categories"]["adult_restricted"], guard)
    severe = assess_severe_abuse_signals(
        None, title_text, body_text, None, classification_scope="page")
    if guard and adult["matched"] and not adult["block"]:
        result.update(false_positive_guard_applied=True, match_scope=adult["scope"],
                      safe_signal_labels=["adult_false_positive_guarded"],
                      signal_count=adult["signal_count"], signal_ratio=adult["signal_ratio"],
                      dominance_score=adult["dominance_score"])
    triggered: dict[str, tuple[int, str]] = {}
    weak_candidates: list[tuple[int, str]] = []
    category_text = content_text
    for category, rules in cfg["categories"].items():
        if category in {"unknown", "adult_restricted", "severe_abuse_risk"}: continue
        strong = _matches(category_text, rules.get("strong", []))
        medium = _matches(category_text, rules.get("medium", []))
        if category == "fraud_financial":
            fraud_evidence = _financial_fraud_evidence(category_text)
            if not fraud_evidence["strong"]:
                if not fraud_evidence["benign_context"] and (fraud_evidence["weak_context"] or strong or medium):
                    weak_candidates.append((len(fraud_evidence["labels"]) + len(fraud_evidence["generic_terms"]), category))
                continue
        if category == "marketplace" and _matches(category_text, [
            "no marketplace", "not a marketplace", "without a marketplace",
            "no vendors", "not a vendor", "without vendors",
        ]):
            strong, medium = [], []
        if category in STRICT_PAGE_CATEGORIES:
            evidence = ((2, "corroborated_weapons_evidence")
                        if category == "weapons_arms" and weapons_evidence["verified"]
                        else None if category == "weapons_arms"
                        else _strict_page_category_evidence(category, strong, medium, category_text))
            if evidence:
                triggered[category] = evidence
            elif strong or medium:
                weak_candidates.append((len(set(strong)) * 2 + len(set(medium)), category))
        elif category == "weapons_arms" and content_text:
            if weapons_evidence["verified"]:
                triggered[category] = (2, "corroborated_weapons_evidence")
            elif strong or medium:
                weak_candidates.append((len(set(strong)) * 2 + len(set(medium)), category))
        elif strong:
            triggered[category] = (2, "content")
        elif len(set(normalize_text(item) for item in medium)) >= 2:
            triggered[category] = (1, "content")
    if adult["block"]:
        triggered["adult_restricted"] = (2, adult["scope"])
    if severe["block"]:
        triggered["severe_abuse_risk"] = (3, severe["scope"])
    if triggered:
        preferred_primary = None
        if "fraud_financial" in triggered and "malware_hacking" in triggered:
            malware_specific = _matches(combined, ["malware infrastructure", "ransomware", "botnet",
                                                    "command and control", "intrusion", "exploit kit"])
            preferred_primary = "malware_hacking" if len(set(malware_specific)) >= 2 else "fraud_financial"
        primary = preferred_primary or next(category for category in cfg["category_precedence"] if category in triggered)
        strength, target = triggered[primary]
        rules = cfg["categories"][primary]
        result.update({
            "primary_category": primary, "category": primary,
            "risk_level": rules["risk_level"], "confidence": "high" if strength >= 2 else "medium",
            "risk_flags": list(rules.get("risk_flags", [])), "storage_policy": rules["storage_policy"],
            "review_status": rules["review_status"], "safety_reason": rules["safe_reason"],
            "screenshot_policy": rules["screenshot_policy"], "queue_policy": rules["queue_policy"],
            "active": 0 if rules["queue_policy"] == "blocked" else 1,
            "priority_score": {"critical": 100, "high": 60, "medium": 30, "low": 10}.get(rules["risk_level"], 0)
        })
        result["tags"] = list(triggered)
        if primary == "weapons_arms":
            result["evidence_families"] = list(dict.fromkeys(
                result.get("evidence_families", []) + weapons_evidence["families"]
            ))
        if primary == "severe_abuse_risk":
            result = severe_blackhole_policy(result)
            result.update(match_scope=severe["scope"],
                          safe_signal_labels=severe["safe_signal_labels"],
                          signal_count=severe["signal_count"], context_window_count=1,
                          evidence_families=severe["independent_signal_families"],
                           ocr_restricted_hit=False, ocr_deleted_due_to_policy=False,
                           ocr_safe_signal_labels=[])
        if primary == "adult_restricted":
            result.update({
                "primary_category": "adult_filtered", "category": "adult_filtered",
                "tags": ["adult_filtered"], "risk_level": "filtered", "confidence": "high",
                "risk_flags": ["adult_filtered"], "storage_policy": "discard",
                "review_status": "filtered", "safety_reason": "adult_content_filtered",
                "screenshot_policy": "blocked", "screenshot_blocked_reason": "adult_content_filtered",
                "queue_policy": "blocked", "active": 0, "priority_score": 0,
                "spain_priority": False, "geo_priority": None, "spain_match_reason": None,
                "spain_match_language": None, "spain_confidence": None, "spain_context_tags": [],
                "match_scope": adult["scope"], "safe_signal_labels": ["adult_dominant_page"],
                "signal_count": adult["signal_count"], "signal_ratio": adult["signal_ratio"],
                "dominance_score": adult["dominance_score"],
                "false_positive_guard_applied": False,
                "ocr_restricted_hit": False,
                "ocr_deleted_due_to_policy": False,
                "ocr_safe_signal_labels": [],
            })
    final_text = content_text
    tags, tag_confidence, summary = extract_weighted_tags(final_text, result["storage_policy"])
    result["tags"] = list(dict.fromkeys(result["tags"] + tags))
    result["tag_confidence"] = tag_confidence
    result["tag_summary"] = summary
    # Structural/category resolution must precede Spain evidence.  Otherwise a
    # directory or forum index can be treated as a direct seller merely because
    # one visible label contains a Spain signal.
    _enrich_taxonomy(result, "", final_text, allow_url_hints=False)
    _apply_page_understanding(result, page_structure, body_text)
    if result["primary_category"] not in {"adult_filtered", "severe_abuse_risk"}:
        _apply_spain_evidence(result, final_text, language, url)
    if result["screenshot_policy"] != "allowed":
        result["screenshot_blocked_reason"] = result["safety_reason"]
    else:
        result["screenshot_blocked_reason"] = None
    if result["primary_category"] == "unknown" and weak_candidates:
        result["suggested_category"] = max(weak_candidates)[1]
        result["category_reason"] = "A possible category signal needs corroboration"
        result["review_status"] = "needs_review"
        result["category_safe_label"] = "Needs classification"
        result["display_group"] = "Quality review"
        result["ui_hidden_default"] = 1
    _apply_classification_dimensions(result, "", final_text)
    result = calibrate_classification(result, stage="page")
    if severe["block"]:
        result = severe_blackhole_policy(result)
        result.update(match_scope=severe["scope"],
                      safe_signal_labels=severe["safe_signal_labels"],
                      signal_count=severe["signal_count"],
                      evidence_families=severe["independent_signal_families"],
                      ocr_checked=bool(ocr_text is not None),
                      ocr_restricted_hit=False,
                      ocr_deleted_due_to_policy=False,
                      ocr_safe_signal_labels=[])
    return result


def classify_preview_ocr_text(ocr_text: str | None) -> dict:
    """Classify OCR only for deletion of a transient preview artifact.

    Callers must never persist this result as URL or Site Card truth.  Supplying
    it as visible text here deliberately reuses the safety vocabulary without
    allowing OCR into ``classify(..., ocr_text=...)`` canonical evidence.
    """
    result = classify("", visible_text=ocr_text or "", classification_scope="preview_ocr")
    result.update(
        classification_stage="preview_ocr", ocr_checked=True,
        ocr_preview_safety_only=True,
        ocr_restricted_hit=result.get("primary_category") in {
            "adult_filtered", "adult_restricted", "severe_abuse_risk",
        },
    )
    return result


def classify_url_prefetch(url: str, source_url: str | None = None,
                          anchor_text: str | None = None, source_context: str | None = None) -> dict:
    """Return a provisional URL policy without assigning a content category.

    URL, path, anchor, and parent text are discovery hints only.  The fetched
    destination's own HTML is the sole source of a final page category.
    """
    cfg = _load(SAFETY_CONFIG_PATH)
    url_text = _classification_url_text(url)
    link_text = normalize_text(" ".join(filter(None, [anchor_text, source_context])))
    adult_hint_terms = cfg["categories"]["adult_restricted"].get(
        "unverified_url_hints",
        # Compatibility for an older local configuration. These values remain
        # hints only and can never become fetched-page evidence.
        cfg["categories"]["adult_restricted"].get("url_strong", []),
    )
    adult_hint = bool(_url_matches(url_text, adult_hint_terms))
    url_severe_hint = assess_severe_abuse_signals(
        url_text, None, None, None, classification_scope="child")
    link_severe_hint = assess_severe_abuse_signals(
        None, None, None, link_text, classification_scope="child")
    result = _base_result()
    result.update(
        primary_category="unknown", category="unknown", content_category="unknown",
        tags=["unknown"], risk_level="low", confidence="low", risk_flags=[],
        storage_policy="safe_summary", review_status="monitor",
        safety_reason="awaiting_page_classification", queue_policy="normal", active=1,
        priority_score=0, spain_priority=False, match_scope="none",
        url_hint_present=bool(adult_hint or url_severe_hint.get("safe_signal_labels")),
        link_text_hint_present=bool(link_text and link_severe_hint.get("safe_signal_labels")),
        hint_verified=False,
        classification_decision="unverified_hint" if (
            adult_hint or url_severe_hint.get("safe_signal_labels")
            or link_severe_hint.get("safe_signal_labels")) else "unclassified",
    )
    has_unverified_hint = bool(
        adult_hint or url_severe_hint.get("safe_signal_labels")
        or link_severe_hint.get("safe_signal_labels")
    )
    result = calibrate_classification(result, stage="prefetch")
    # Calibration normally calls an unknown result "abstained".  Preserve the
    # more precise prefetch state when discovery metadata supplied a lexical
    # hint: it is explicitly unverified and remains fetchable.
    if has_unverified_hint:
        result.update(
            classification_decision="unverified_hint",
            classification_confidence_score=0.0,
            hint_verified=False,
        )
    return result


def restricted_placeholder(category: str) -> tuple[str, str, str]:
    if category in {"adult_restricted", "adult_filtered"}:
        return "SCREENSHOT BLOCKED", "ADULT / PORNOGRAPHIC CONTENT", "Disabled by safety policy"
    return "SCREENSHOT BLOCKED", "RESTRICTED CONTENT", "Metadata only"


def safe_category_label(category: str | None) -> str:
    return PRIMARY_CATEGORY_LABELS.get(category or "unknown", "Unknown")
