"""Passive OSINT correlation only; never attempts to identify hidden origins."""
from __future__ import annotations

from collections import Counter, defaultdict
from urllib.parse import urlsplit

import storage

LIMITATIONS = ("This passive attribution profile does not reveal, verify, or claim the physical origin "
               "server, operator identity, or hosting location. It only summarizes public correlations "
               "observed in collected metadata, visible text, links, hashes, and indicators.")


def _shared_by_source_type(indicators: list[dict], kinds: set[str]) -> list[str]:
    sources: dict[str, set[str]] = defaultdict(set)
    for item in indicators:
        if item.get("type", item.get("indicator_type")) in kinds:
            value = item.get("normalized_value", item.get("value"))
            source = item.get("source_type", item.get("link_source_type", "unknown"))
            if value:
                sources[str(value)].add(str(source))
    return sorted(value for value, types in sources.items() if len(types) >= 2)


def score_passive_attribution(indicators: list[dict], urls: list[dict], texts: list[str]) -> dict:
    handles = _shared_by_source_type(indicators, {"telegram_handle"})
    wallets = _shared_by_source_type(indicators, {"wallet_btc", "wallet_eth"})
    emails = _shared_by_source_type(indicators, {"email", "jabber_id", "tox_id", "session_id", "matrix_id"})
    pgp = _shared_by_source_type(indicators, {"pgp_key_block"})
    usernames = _shared_by_source_type(indicators, {"username"})
    domains = sorted({urlsplit(u.get("url", "")).hostname for u in urls if urlsplit(u.get("url", "")).hostname})
    onion_domains = [d for d in domains if d.endswith(".onion")]
    clearnet_domains = [d for d in domains if not d.endswith(".onion")]
    hashes = defaultdict(set)
    fuzzy = defaultdict(set)
    titles = defaultdict(set)
    for item in urls:
        if item.get("content_hash"): hashes[item["content_hash"]].add(item.get("url"))
        if item.get("fuzzy_hash"): fuzzy[item["fuzzy_hash"]].add(item.get("url"))
        if item.get("title"): titles[item["title"].strip().casefold()].add(item.get("url"))
    shared_hashes = sorted(k for k, v in hashes.items() if len(v) >= 2)
    shared_fuzzy = sorted(k for k, v in fuzzy.items() if len(v) >= 2)
    shared_titles = sorted(k for k, v in titles.items() if len(v) >= 2)
    normalized_texts = [" ".join((text or "").casefold().split()) for text in texts]
    shared_phrases = sorted(text for text, count in Counter(normalized_texts).items() if text and len(text) >= 20 and count >= 2)
    score = (25 if handles else 0) + (25 if wallets else 0) + (20 if emails else 0) + (20 if pgp else 0)
    score += (20 if shared_hashes else 0) + (15 if shared_fuzzy else 0) + (15 if shared_titles else 0)
    score += (10 if usernames else 0) + (10 if onion_domains and clearnet_domains else 0)
    score += 10 if shared_phrases else 0
    score = min(100, score)
    level = "HIGH" if score >= 70 else "MEDIUM" if score >= 30 else "LOW"
    return {
        "cluster_id": 0, "confidence_score": score, "confidence_level": level,
        "shared_handles": handles, "shared_emails": emails, "shared_wallets": wallets,
        "shared_pgp_keys": pgp, "shared_usernames": usernames,
        "shared_onion_domains": onion_domains, "shared_clearnet_domains": clearnet_domains,
        "shared_titles": shared_titles, "shared_content_hashes": shared_hashes,
        "shared_fuzzy_hashes": shared_fuzzy, "shared_phrases": shared_phrases,
        "linked_telegram_sources": sorted({i.get("source_ref") for i in indicators if str(i.get("source_type", "")).startswith("telegram") and i.get("source_ref")}),
        "linked_onion_sources": sorted({u.get("url") for u in urls if (urlsplit(u.get("url", "")).hostname or "").endswith(".onion")}),
        "linked_clearnet_sources": sorted({u.get("url") for u in urls if urlsplit(u.get("url", "")).hostname and not (urlsplit(u.get("url", "")).hostname or "").endswith(".onion")}),
        "first_seen": min((u.get("first_seen") for u in urls if u.get("first_seen")), default=None),
        "last_seen": max((u.get("last_seen") for u in urls if u.get("last_seen")), default=None),
        "explanation": "This confidence score is based on passive OSINT correlation of public metadata, visible text, links, hashes, and indicators only; it does not identify a hidden server location.",
        "limitations": LIMITATIONS,
    }


def build_attribution_profile(cluster_id: int) -> dict:
    cluster = storage.get_mirror_cluster(cluster_id)
    if not cluster:
        raise ValueError("Cluster not found")
    urls = cluster.get("urls", [])
    with storage.get_db() as db:
        refs = [u["url"] for u in urls]
        if refs:
            rows = db.execute(f"""SELECT i.*,l.source_type AS link_source_type,l.source_ref AS link_source_ref
              FROM indicators i JOIN indicator_links l ON l.indicator_id=i.id
              WHERE l.source_ref IN ({','.join('?' for _ in refs)})""", refs).fetchall()
            indicators = [dict(row) | {"source_type": row["link_source_type"], "source_ref": row["link_source_ref"]} for row in rows]
        else:
            indicators = []
    profile = score_passive_attribution(indicators, urls, [])
    profile["cluster_id"] = cluster_id
    storage.update_cluster_attribution_profile(cluster_id, profile)
    return profile


def explain_attribution_score(profile: dict) -> str:
    return f"{profile.get('confidence_level', 'LOW')} ({profile.get('confidence_score', 0)}/100). {profile.get('explanation', '')} {profile.get('limitations', LIMITATIONS)}"
