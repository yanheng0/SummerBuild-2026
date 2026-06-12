from __future__ import annotations

import logging
import re
import threading
from typing import Optional

log = logging.getLogger(__name__)

# lazy imports so the module loads even without sklearn 
_sklearn_available: Optional[bool] = None
_vectorizer = None
_tfidf_matrix = None
_index_lock = threading.Lock()

from services.rag.knowledge_base import KNOWLEDGE_BASE  # noqa: E402 (after stdlib)


# Index build 

def _build_index():
    """Build TF-IDF index over the knowledge base. Called once, lazily."""
    global _sklearn_available, _vectorizer, _tfidf_matrix

    try:
        from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
        import numpy as np  # type: ignore  # noqa: F401

        corpus = [_entry_to_text(e) for e in KNOWLEDGE_BASE]
        _vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            min_df=1,
            sublinear_tf=True,
            stop_words="english",
        )
        _tfidf_matrix = _vectorizer.fit_transform(corpus)
        _sklearn_available = True
        log.info("RAG: TF-IDF index built over %d entries.", len(KNOWLEDGE_BASE))

    except ImportError:
        _sklearn_available = False
        log.warning(
            "RAG: scikit-learn not installed — falling back to keyword retrieval. "
            "Install with: pip install scikit-learn"
        )


def _ensure_index():
    with _index_lock:
        if _sklearn_available is None:
            _build_index()


#  Helpers 
def _entry_to_text(entry: dict) -> str:
    """Flatten an entry to a single string for TF-IDF."""
    parts = [
        entry.get("description", ""),
        entry.get("category", ""),
        " ".join(entry.get("tags", [])),
        " ".join(entry.get("indicators", [])),
        entry.get("example", ""),
    ]
    return " ".join(parts)


def _keyword_score(query_lower: str, entry: dict) -> float:
    """Simple tag/keyword hit count for fallback ranking."""
    score = 0.0
    for tag in entry.get("tags", []):
        if tag.lower() in query_lower:
            score += 1.0
    for ind in entry.get("indicators", []):
        # partial word match
        for word in re.findall(r"\w+", ind.lower()):
            if len(word) > 4 and word in query_lower:
                score += 0.3
    return score


def _format_entry(entry: dict, rank: int) -> str:
    """Convert a KB entry into a human-readable block for the system prompt."""
    indicators_str = "\n".join(f"    • {i}" for i in entry.get("indicators", []))
    example = entry.get("example", "").strip()
    return (
        f"[CASE {rank} — {entry['category']}] {entry['description']}\n"
        f"  Expected verdict: {entry['verdict']}\n"
        f"  Key indicators:\n{indicators_str}\n"
        f"  Reference example: \"{example}\"\n"
        f"  Source: {entry.get('source', 'N/A')}"
    )


# Public API 
def retrieve_context(query: str, top_k: int = 3) -> str:
    """
    Retrieve the top_k most relevant knowledge-base entries for `query`.
    Returns a formatted multi-line string to inject into the Reka system prompt.
    Returns an empty string if nothing scores above the threshold.
    """
    _ensure_index()

    if not query or not query.strip():
        return ""

    query_lower = query.lower()

    if _sklearn_available:
        results = _tfidf_retrieve(query_lower, top_k)
    else:
        results = _keyword_retrieve(query_lower, top_k)

    if not results:
        return ""

    header = (
        "── VERIFIED SCAM INTELLIGENCE (Retrieved) ──\n"
        "The following cases from Singapore's scam database are relevant to this submission. "
        "Use them to ground your analysis:\n\n"
    )
    body = "\n\n".join(_format_entry(e, i + 1) for i, e in enumerate(results))
    footer = "\n── END INTELLIGENCE ──"
    return header + body + footer


def _tfidf_retrieve(query_lower: str, top_k: int) -> list[dict]:
    """TF-IDF cosine similarity retrieval."""
    import numpy as np
    from sklearn.metrics.pairwise import cosine_similarity  # type: ignore

    query_vec = _vectorizer.transform([query_lower])
    scores = cosine_similarity(query_vec, _tfidf_matrix).flatten()

    # Apply a small boost for direct tag hits
    for i, entry in enumerate(KNOWLEDGE_BASE):
        for tag in entry.get("tags", []):
            if tag.lower() in query_lower:
                scores[i] += 0.15

    threshold = 0.05
    top_indices = np.argsort(scores)[::-1][:top_k]
    return [KNOWLEDGE_BASE[i] for i in top_indices if scores[i] >= threshold]


def _keyword_retrieve(query_lower: str, top_k: int) -> list[dict]:
    """Pure keyword fallback when sklearn is unavailable."""
    scored = [
        (entry, _keyword_score(query_lower, entry))
        for entry in KNOWLEDGE_BASE
    ]
    scored.sort(key=lambda x: x[1], reverse=True)
    return [e for e, s in scored[:top_k] if s > 0]