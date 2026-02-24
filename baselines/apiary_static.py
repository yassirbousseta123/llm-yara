from __future__ import annotations

from pathlib import Path
from typing import Any

from llmyara.yara.render import render_rule


def _extract_api_tokens(tokens: list[str]) -> set[str]:
    out: set[str] = set()
    for token in tokens:
        if not isinstance(token, str):
            continue
        if not token.startswith("imp:"):
            continue
        if "!" not in token:
            continue
        out.add(token.lower())
    return out


def _presence_counts(features_by_id: dict[str, dict[str, Any]], sample_ids: list[str]) -> tuple[dict[str, int], int]:
    counts: dict[str, int] = {}
    docs = 0
    for sample_id in sample_ids:
        row = features_by_id.get(sample_id)
        if not row:
            continue
        docs += 1
        apis = _extract_api_tokens(row.get("tokens", []))
        for api in apis:
            counts[api] = counts.get(api, 0) + 1
    return counts, docs


def select_discriminative_apis(
    *,
    features_by_id: dict[str, dict[str, Any]],
    train_target: list[str],
    train_other: list[str],
    benign_dev: list[str],
    max_items: int,
    min_score: float,
) -> list[dict[str, Any]]:
    pos_counts, pos_docs = _presence_counts(features_by_id, train_target)
    neg_counts, neg_docs = _presence_counts(features_by_id, train_other + benign_dev)

    if pos_docs == 0:
        return []

    ranked: list[dict[str, Any]] = []
    for token in sorted(set(pos_counts) | set(neg_counts)):
        pos_count = pos_counts.get(token, 0)
        neg_count = neg_counts.get(token, 0)
        pos_rate = pos_count / pos_docs if pos_docs else 0.0
        neg_rate = neg_count / neg_docs if neg_docs else 0.0
        score = pos_rate - neg_rate
        if score <= min_score:
            continue
        ranked.append(
            {
                "token": token,
                "score": round(score, 6),
                "pos_rate": round(pos_rate, 6),
                "neg_rate": round(neg_rate, 6),
                "pos_count": pos_count,
                "neg_count": neg_count,
            }
        )

    ranked.sort(key=lambda row: (-row["score"], -row["pos_count"], row["token"]))
    return ranked[:max_items]


def _api_token_to_string_literal(token: str) -> str | None:
    rhs = token.split("!", 1)[1] if "!" in token else token
    if not rhs:
        return None
    if rhs.startswith("#"):
        return None
    literal = rhs.strip().lower()
    if len(literal) < 4:
        return None
    return literal


def generate_apiary_static_rule(
    family: str,
    selected_apis: list[dict[str, Any]],
) -> tuple[str, dict[str, Any]]:
    strings: list[dict[str, Any]] = []
    picked_tokens: list[str] = []

    for item in selected_apis:
        token = item.get("token")
        if not isinstance(token, str):
            continue
        literal = _api_token_to_string_literal(token)
        if not literal:
            continue
        strings.append(
            {
                "id": f"s{len(strings)+1}",
                "value": literal,
                "nocase": True,
                "ascii": True,
                "wide": False,
            }
        )
        picked_tokens.append(token)

    if not strings:
        strings = [
            {
                "id": "s1",
                "value": family,
                "nocase": True,
                "ascii": True,
                "wide": False,
            }
        ]

    if len(strings) >= 4:
        condition = "3 of them"
    elif len(strings) >= 2:
        condition = "2 of them"
    else:
        condition = "$s1"

    payload = {
        "rule_name": f"baseline_apiary_static_{family}",
        "meta": {
            "family": family,
            "author": "baseline-apiary-static",
            "description": "apiary-inspired discriminative import baseline",
        },
        "strings": strings,
        "condition": condition,
    }
    stats = {
        "candidate_api_count": len(selected_apis),
        "string_count": len(strings),
        "selected_api_tokens": picked_tokens,
    }
    return render_rule(payload), stats


def write_baseline_rules(
    *,
    features: list[dict[str, Any]],
    splits: dict[str, Any],
    out_dir: str | Path,
    max_strings: int = 8,
    min_score: float = 0.0,
) -> dict[str, Any]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    features_by_id = {row["sample_id"]: row for row in features}
    benign_dev = splits.get("global", {}).get("benign_dev", [])

    paths: dict[str, str] = {}
    family_stats: dict[str, Any] = {}

    for family, family_split in sorted(splits.get("families", {}).items()):
        selected_apis = select_discriminative_apis(
            features_by_id=features_by_id,
            train_target=family_split.get("train_target", []),
            train_other=family_split.get("train_other", []),
            benign_dev=benign_dev,
            max_items=max_strings,
            min_score=min_score,
        )
        rule_text, stats = generate_apiary_static_rule(family, selected_apis)
        path = out / f"{family}.yar"
        path.write_text(rule_text, encoding="utf-8")
        paths[family] = str(path)
        family_stats[family] = stats

    return {
        "rule_paths": paths,
        "family_stats": family_stats,
        "max_strings": max_strings,
        "min_score": min_score,
    }
