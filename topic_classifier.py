"""Passive topic and keyword extraction from already-visible page text."""
from __future__ import annotations

import re
from collections import Counter

TOPIC_PATTERNS = {
    "Adult content": [r"\bporn(?:ography|ographic)?\b", r"\bxxx\b", r"\badult\s+content\b", r"\bexplicit\s+sexual\b"],
    "Payment-card fraud / carding": [r"\bcarding\b", r"\bcvv\b", r"\bfullz\b", r"\bcard\s+dumps?\b", r"\bstolen\s+cards?\b", r"\bcredit\s+card\s+fraud\b"],
    "Credential abuse": [r"\bcombo\s+lists?\b", r"\bstolen\s+credentials?\b", r"\bstealer\s+logs?\b", r"\bcredential\s+dumps?\b"],
    "Leaks / exposed data": [r"\bdata\s+leaks?\b", r"\bvictim\s+lists?\b", r"\bdatabase\s+dumps?\b", r"\bbreach\s+data\b"],
    "Malware / cybercrime": [r"\bmalware\b", r"\bransomware\b", r"\bphishing\b", r"\bbotnet\b", r"\bcommand\s+and\s+control\b"],
    "Marketplace context": [r"\bmarketplace\b", r"\bvendor\s+list\b", r"\bproduct\s+listings?\b"],
    "Recruitment context": [r"\brecruit(?:ment|ing)?\b", r"\bjoin\s+our\s+(?:group|team)\b", r"\breclutamiento\b"],
}

STOPWORDS = {
    "about", "after", "also", "been", "before", "being", "between", "could", "from", "have", "here",
    "into", "more", "most", "other", "page", "site", "some", "than", "that", "their", "there", "these",
    "they", "this", "those", "through", "under", "very", "what", "when", "where", "which", "while", "with",
    "would", "your", "para", "como", "esta", "este", "estos", "estas", "desde", "donde", "entre", "sobre",
    "todos", "todas", "tiene", "hacer", "puede", "porque", "pero", "tambien", "página", "sitio",
}


def extract_page_topics(text: str, max_keywords: int = 15) -> dict:
    lowered = (text or "").casefold()
    topics: list[str] = []
    matched_terms: set[str] = set()
    for topic, patterns in TOPIC_PATTERNS.items():
        topic_matches = []
        for pattern in patterns:
            topic_matches.extend(match.group(0) for match in re.finditer(pattern, lowered, re.I))
        if topic_matches:
            topics.append(topic)
            matched_terms.update(" ".join(term.split()) for term in topic_matches)

    tokens = re.findall(r"(?u)\b[^\W\d_][^\W\d_'-]{3,29}\b", lowered)
    counts = Counter(token for token in tokens if token not in STOPWORDS)
    frequent = [word for word, count in counts.most_common(max_keywords * 2) if count >= 2]
    keywords = list(dict.fromkeys(sorted(matched_terms) + frequent))[:max_keywords]
    return {"topics": topics, "keywords": keywords}

