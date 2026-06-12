import logging
import re
from typing import List, Dict, Any

from services.rag.knowledge_base import KNOWLEDGE_BASE

log = logging.getLogger(__name__)

# Lazy‑loaded TF‑IDF resources
_vectorizer = None
_tfidf_matrix = None
_corpus = None


def _build_index():
    """Build TF-IDF index once."""
    global _vectorizer, _tfidf_matrix, _corpus
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        _corpus = [_entry_to_text(e) for e in KNOWLEDGE_BASE]
        _vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            min_df=1,
            sublinear_tf=True,
            stop_words="english",
        )
        _tfidf_matrix = _vectorizer.fit_transform(_corpus)
        log.info("RAG: TF‑IDF index built over %d entries.", len(KNOWLEDGE_BASE))
    except ImportError:
        log.error("scikit‑learn is required. Run: pip install scikit‑learn")
        raise


def _ensure_index():
    if _vectorizer is None:
        _build_index()


def _entry_to_text(entry: Dict[str, Any]) -> str:
    """Flatten KB entry for indexing."""
    return " ".join([
        entry.get("description", ""),
        entry.get("category", ""),
        " ".join(entry.get("tags", [])),
        " ".join(entry.get("indicators", [])),
        entry.get("example", ""),
    ])


def _expand_query(query: str) -> List[str]:
    """Generate query variants for better recall."""
    q = query.lower()
    variants = [q]
    # Add common scam context if missing
    if not any(term in q for term in ["scam", "phishing", "fraud"]):
        variants.append(q + " scam")
    # Add SG context if missing
    if not any(hint in q for hint in ["singapore", "sg", "spf", "mas"]):
        variants.append(q + " singapore")
    return variants


def _keyword_boost(query_lower: str, entry: Dict[str, Any]) -> float:
    """Additional score for direct tag/indicator matches."""
    score = 0.0
    for tag in entry.get("tags", []):
        if tag.lower() in query_lower:
            score += 0.15
    for ind in entry.get("indicators", []):
        for word in re.findall(r"\w+", ind.lower()):
            if len(word) > 4 and word in query_lower:
                score += 0.1
    return score


def _format_entry(entry: Dict[str, Any], rank: int) -> str:
    """Format KB entry for prompt injection."""
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
    """
    Retrieve top-k most relevant KB entries for `query`.
    Returns formatted string for system prompt.
    """
    if not query or not query.strip():
        return ""

    _ensure_index()

    from sklearn.metrics.pairwise import cosine_similarity
    import numpy as np

    query_lower = query.lower()
    best_scores = None
    best_indices = None

    # Try each expanded query and take the maximum similarity per entry
    for qvar in _expand_query(query):
        q_vec = _vectorizer.transform([qvar])
        scores = cosine_similarity(q_vec, _tfidf_matrix).flatten()
        if best_scores is None:
            best_scores = scores
            best_indices = np.arange(len(scores))
        else:
            # keep max per index
            best_scores = np.maximum(best_scores, scores)

    # Apply keyword boost
    for i, entry in enumerate(KNOWLEDGE_BASE):
        best_scores[i] += _keyword_boost(query_lower, entry)

    # Get top_k indices above threshold
    threshold = 0.08
    indices = np.argsort(best_scores)[::-1]
    results = []
    for idx in indices:
        if best_scores[idx] >= threshold and len(results) < top_k:
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