"""Passive mirror clustering; no origin discovery or network activity."""
from __future__ import annotations

import json
from urllib.parse import urlsplit

import storage


def _indicator_set(items) -> set[str]:
    result = set()
    for item in items or []:
        if isinstance(item, dict):
            result.add(f"{item.get('type')}:{item.get('normalized_value', item.get('value', ''))}".casefold())
        elif isinstance(item, str):
            result.add(item.casefold())
    return result


def calculate_cluster_similarity(existing_cluster: dict, candidate: dict) -> float:
    scores = []
    existing_urls = existing_cluster.get("urls", []) or []
    if candidate.get("content_hash") and any(u.get("content_hash") == candidate["content_hash"] for u in existing_urls):
        scores.append(1.0)
    if candidate.get("fuzzy_hash") and any(u.get("fuzzy_hash") == candidate["fuzzy_hash"] for u in existing_urls):
        scores.append(0.8)
    title = (candidate.get("title") or "").strip().casefold()
    if title and any((u.get("title") or "").strip().casefold() == title for u in existing_urls):
        scores.append(0.75)
    host = (urlsplit(candidate.get("url", "")).hostname or "").casefold()
    if host and any((urlsplit(u.get("url", "")).hostname or "").casefold() == host for u in existing_urls):
        scores.append(0.75)
    existing_indicators = _indicator_set(existing_cluster.get("shared_indicators", []))
    candidate_indicators = _indicator_set(candidate.get("indicators", []))
    overlap = existing_indicators & candidate_indicators
    if overlap:
        strong = any(value.startswith(("telegram_handle:", "wallet_", "email:", "pgp_key_block:", "clearnet_url:")) for value in overlap)
        scores.append(0.85 if strong else 0.75)
    return max(scores, default=0.0)


def update_mirror_clusters(url: str, title: str | None, text: str,
                           content_hash: str | None, fuzzy_hash: str | None,
                           indicators: list[dict], source_type: str) -> int | None:
    from scoring_engine import risk_level, score_text
    score, _ = score_text(text or "")
    cluster_id = storage.create_or_update_mirror_cluster(
        url, title, content_hash, fuzzy_hash, indicators, score, score,
        risk_level(score), source_type, source_ref=url,
    )
    if cluster_id:
        lowered = (text or "").casefold()
        cluster_type = ("leak" if any(x in lowered for x in ("data leak", "victim list", "filtración de datos"))
                        else "weapons_trafficking_context" if any(x in lowered for x in ("weapons trafficking", "tráfico de armas"))
                        else "recruitment" if "recruit" in lowered or "reclut" in lowered
                        else "cyber" if any(x in lowered for x in ("malware", "phishing", "command and control"))
                        else "propaganda" if "propaganda" in lowered else "unknown")
        with storage.get_db() as db:
            db.execute("UPDATE mirror_clusters SET cluster_type=? WHERE id=?", (cluster_type, cluster_id))
            db.execute("UPDATE onion_urls SET mirror_cluster_id=? WHERE url=?", (cluster_id, url))
    return cluster_id


def summarize_cluster(cluster_id: int) -> str:
    cluster = storage.get_mirror_cluster(cluster_id)
    if not cluster:
        return "Cluster not found."
    indicators = json.loads(cluster.get("shared_indicators_json") or "[]")
    urls = cluster.get("urls", [])
    return f"Passive cluster {cluster_id}: {len(urls)} related URL(s), {len(indicators)} shared indicator(s), risk {cluster.get('risk_level', 'NULO')}."
