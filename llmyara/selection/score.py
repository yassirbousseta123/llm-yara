from __future__ import annotations

from typing import Any

from llmyara.selection.vectorize import fallback_rank


def select_family_features(
    features_by_id: dict[str, dict[str, Any]],
    train_target: list[str],
    train_other: list[str],
    benign_dev: list[str],
    top_k: int,
) -> list[dict[str, float]]:
    pos_docs = [features_by_id[sample_id]["tokens"] for sample_id in train_target if sample_id in features_by_id]
    neg_docs = [features_by_id[sample_id]["tokens"] for sample_id in train_other if sample_id in features_by_id]
    neg_docs.extend(features_by_id[sample_id]["tokens"] for sample_id in benign_dev if sample_id in features_by_id)

    if not pos_docs:
        return []

    try:
        from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
        from sklearn.feature_selection import chi2  # type: ignore
    except ImportError:
        return fallback_rank(pos_docs, neg_docs, top_k)

    all_docs = pos_docs + neg_docs
    labels = [1] * len(pos_docs) + [0] * len(neg_docs)

    if len(set(labels)) < 2:
        return fallback_rank(pos_docs, neg_docs, top_k)

    vectorizer = TfidfVectorizer(
        analyzer=lambda doc: doc,
        lowercase=False,
        preprocessor=None,
        token_pattern=None,
    )
    matrix = vectorizer.fit_transform(all_docs)
    scores, _ = chi2(matrix, labels)
    vocab = vectorizer.get_feature_names_out()

    ranked_idx = sorted(range(len(scores)), key=lambda i: float(scores[i]), reverse=True)
    selected: list[dict[str, float]] = []
    for idx in ranked_idx[:top_k]:
        selected.append({"feature": str(vocab[idx]), "score": round(float(scores[idx]), 6)})
    return selected


def select_all_families(
    features: list[dict[str, Any]],
    splits: dict[str, Any],
    top_k: int,
) -> dict[str, Any]:
    features_by_id = {row["sample_id"]: row for row in features}
    benign_dev = splits["global"]["benign_dev"]

    output: dict[str, Any] = {"families": {}}
    for family, family_split in splits["families"].items():
        selected = select_family_features(
            features_by_id=features_by_id,
            train_target=family_split["train_target"],
            train_other=family_split["train_other"],
            benign_dev=benign_dev,
            top_k=top_k,
        )
        output["families"][family] = selected
    return output
