from __future__ import annotations

from collections import Counter
from typing import Sequence


def join_tokens(docs_tokens: Sequence[Sequence[str]]) -> list[str]:
    return [" ".join(doc) for doc in docs_tokens]


def fallback_rank(positive_docs: Sequence[Sequence[str]], negative_docs: Sequence[Sequence[str]], top_k: int) -> list[dict[str, float]]:
    pos_counter: Counter[str] = Counter()
    neg_counter: Counter[str] = Counter()

    for doc in positive_docs:
        pos_counter.update(set(doc))
    for doc in negative_docs:
        neg_counter.update(set(doc))

    scored: list[tuple[str, float]] = []
    for token, pos_count in pos_counter.items():
        score = float(pos_count - neg_counter.get(token, 0))
        if score > 0:
            scored.append((token, score))

    scored.sort(key=lambda item: item[1], reverse=True)
    return [{"feature": token, "score": round(score, 6)} for token, score in scored[:top_k]]
