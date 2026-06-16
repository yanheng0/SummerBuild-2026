from __future__ import annotations
import logging
import re
from typing import List, Dict, Any
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
from services.rag.knowledge_base import KNOWLEDGE_BASE

logger = logging.getLogger(__name__)

_vectorizer = None
_tfidf_matrix = None
_corpus = None

def _build_index():
    global _vectorizer, _tfidf_matrix, _corpus
    _corpus = [_entry_to_text(e) for e in KNOWLEDGE_BASE]
    _vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        min_df=1,
        sublinear_tf=True,
        stop_words="english",
    )
    _tfidf_matrix = _vectorizer.fit_transform(_corpus)
    logger.info("TF‑IDF index built over %d entries.", len(KNOWLEDGE_BASE))

def _ensure_index():
    if _vectorizer is None:
        _build_index()

def _entry_to_text(entry: Dict[str, Any]) -> str:
    return " ".join([
        entry.get("description", ""),
        entry.get("category", ""),
        " ".join(entry.get("tags", [])),
        " ".join(entry.get("indicators", [])),
        entry.get("example", ""),
    ])

def _keyword_boost(query_lower: str, entry: Dict[str, Any]) -> float:
    score = 0.0
    for tag in entry.get("tags", []):
        if tag.lower() in query_lower:
            score += 0.2
    for ind in entry.get("indicators", []):
        for word in re.findall(r"\w+", ind.lower()):
            if len(word) > 4 and word in query_lower:
                score += 0.15
    return score

def _format_entry(entry: Dict[str, Any], rank: int) -> str:
    indicators = "\n".join(f"    • {i}" for i in entry.get("indicators", []))
    example = entry.get("example", "").strip()
    return (
        f"[CASE {rank} — {entry['category']}] {entry['description']}\n"
        f"  Expected verdict: {entry['verdict']}\n"
        f"  Key indicators:\n{indicators}\n"
        f"  Reference example: \"{example}\"\n"
        f"  Source: {entry.get('source', 'N/A')}"
    )

def retrieve_context(query: str, top_k: int = 3) -> str:
    _ensure_index()
    if not query or not query.strip():
        return ""

    query_lower = query.lower()
    q_vec = _vectorizer.transform([query_lower])
    scores = cosine_similarity(q_vec, _tfidf_matrix).flatten()

    # Apply keyword boost
    for i, entry in enumerate(KNOWLEDGE_BASE):
        scores[i] += _keyword_boost(query_lower, entry)

    threshold = 0.08  # slightly lower to catch more relevant entries
    indices = np.argsort(scores)[::-1]
    results = []
    for idx in indices:
        if scores[idx] >= threshold and len(results) < top_k:
            results.append(KNOWLEDGE_BASE[idx])

    if not results:
        return ""

    header = (
        "── VERIFIED SCAM INTELLIGENCE (Retrieved) ──\n"
        "The following cases from Singapore's scam database are relevant. "
        "Use them to ground your analysis:\n\n"
    )
    body = "\n\n".join(_format_entry(e, i + 1) for i, e in enumerate(results))
    footer = "\n── END INTELLIGENCE ──"
    return header + body + footer