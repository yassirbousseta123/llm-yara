from __future__ import annotations

import math
from collections import defaultdict
from pathlib import Path
from statistics import pvariance
from typing import Any

from llmyara.yara.render import render_rule

DEFAULT_NGRAM_SIZES = (8, 16, 32)


def _sample_bytes(path: str | Path, max_bytes_per_file: int) -> bytes:
    try:
        data = Path(path).read_bytes()
    except OSError:
        return b""
    if len(data) <= max_bytes_per_file:
        return data

    chunk_count = 4
    chunk_size = max(1, max_bytes_per_file // chunk_count)
    if chunk_size >= len(data):
        return data

    span = max(0, len(data) - chunk_size)
    pieces: list[bytes] = []
    for idx in range(chunk_count):
        start = round(idx * span / max(1, chunk_count - 1))
        pieces.append(data[start : start + chunk_size])
    return b"".join(pieces)[:max_bytes_per_file]


def _byte_entropy(blob: bytes) -> float:
    if not blob:
        return 0.0

    counts: dict[int, int] = {}
    for value in blob:
        counts[value] = counts.get(value, 0) + 1

    total = len(blob)
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def _padding_fraction(blob: bytes) -> float:
    if not blob:
        return 1.0
    padded = sum(1 for value in blob if value in {0x00, 0xFF})
    return padded / len(blob)


def _extract_unique_ngrams(
    data: bytes,
    ngram_size: int,
    min_entropy: float,
) -> set[bytes]:
    if len(data) < ngram_size:
        return set()

    grams: set[bytes] = set()
    for start in range(0, len(data) - ngram_size + 1, ngram_size):
        gram = data[start : start + ngram_size]
        if _byte_entropy(gram) < min_entropy:
            continue
        if _padding_fraction(gram) > 0.5:
            continue
        grams.add(gram)
    return grams


def _hexlify(blob: bytes) -> str:
    return " ".join(f"{value:02X}" for value in blob)


def _candidate_sort_key(candidate: dict[str, Any]) -> tuple[float, int, int, float, str]:
    return (
        -float(candidate["score"]),
        -int(candidate["pos_count"]),
        -int(candidate["ngram_size"]),
        -float(candidate["entropy"]),
        str(candidate["hex"]),
    )


def _jaccard_similarity(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 1.0
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def _select_clause_threshold(terms: list[dict[str, Any]]) -> int:
    if len(terms) <= 1:
        return 1

    counts = sorted(int(term["pos_count"]) for term in terms)
    best_split = 1
    best_score = float("inf")

    for split_idx in range(1, len(counts) + 1):
        left = counts[:split_idx]
        right = counts[split_idx:]
        score = len(left) * pvariance(left) + len(right) * pvariance(right) if right else len(left) * pvariance(left)
        if score < best_score:
            best_score = score
            best_split = split_idx

    return max(1, min(best_split, len(terms)))


def _clause_matches(terms: list[dict[str, Any]], threshold: int, sample_ids: list[str], match_key: str) -> set[str]:
    hits: set[str] = set()
    for sample_id in sample_ids:
        matched = sum(1 for term in terms if sample_id in term[match_key])
        if matched >= threshold:
            hits.add(sample_id)
    return hits


def _cluster_candidates(candidates: list[dict[str, Any]], similarity_threshold: float) -> list[list[dict[str, Any]]]:
    if not candidates:
        return []

    parents = list(range(len(candidates)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        root_left = find(left)
        root_right = find(right)
        if root_left != root_right:
            parents[root_right] = root_left

    for left in range(len(candidates)):
        for right in range(left + 1, len(candidates)):
            similarity = _jaccard_similarity(
                candidates[left]["pos_match_ids"],
                candidates[right]["pos_match_ids"],
            )
            if similarity >= similarity_threshold:
                union(left, right)

    grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for index, candidate in enumerate(candidates):
        grouped[find(index)].append(candidate)

    clusters = []
    for members in grouped.values():
        members.sort(key=_candidate_sort_key)
        clusters.append(members)

    clusters.sort(
        key=lambda cluster: (
            -max(int(candidate["pos_count"]) for candidate in cluster),
            -max(float(candidate["score"]) for candidate in cluster),
            cluster[0]["hex"],
        )
    )
    return clusters


def _presence_matches(doc_bytes_by_id: dict[str, bytes], sample_ids: list[str], gram: bytes) -> set[str]:
    hits: set[str] = set()
    for sample_id in sample_ids:
        data = doc_bytes_by_id.get(sample_id, b"")
        if gram and gram in data:
            hits.add(sample_id)
    return hits


def _collect_candidates_for_family(
    *,
    doc_bytes_by_id: dict[str, bytes],
    train_target: list[str],
    train_other: list[str],
    benign_dev: list[str],
    ngram_sizes: tuple[int, ...],
    max_candidates_per_size: int,
    min_score: float,
    min_entropy: float,
) -> list[dict[str, Any]]:
    candidate_pool: list[dict[str, Any]] = []
    all_negative = train_other + benign_dev

    for ngram_size in ngram_sizes:
        positive_occurrences: dict[bytes, set[str]] = {}
        for sample_id in train_target:
            grams = _extract_unique_ngrams(
                doc_bytes_by_id.get(sample_id, b""),
                ngram_size=ngram_size,
                min_entropy=min_entropy,
            )
            for gram in grams:
                positive_occurrences.setdefault(gram, set()).add(sample_id)

        ranked_by_presence = sorted(
            positive_occurrences.items(),
            key=lambda item: (-len(item[1]), -_byte_entropy(item[0]), _hexlify(item[0])),
        )
        shortlist = ranked_by_presence[: max_candidates_per_size * 4]

        deduped: dict[tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]], dict[str, Any]] = {}
        for gram, pos_matches in shortlist:
            other_matches = _presence_matches(doc_bytes_by_id, train_other, gram)
            benign_matches = _presence_matches(doc_bytes_by_id, benign_dev, gram)
            neg_total = len(other_matches) + len(benign_matches)

            pos_rate = len(pos_matches) / len(train_target) if train_target else 0.0
            neg_rate = neg_total / len(all_negative) if all_negative else 0.0
            score = pos_rate - neg_rate
            if score < min_score:
                continue

            candidate = {
                "gram": gram,
                "hex": _hexlify(gram),
                "ngram_size": ngram_size,
                "entropy": round(_byte_entropy(gram), 6),
                "pos_count": len(pos_matches),
                "other_count": len(other_matches),
                "benign_count": len(benign_matches),
                "score": round(score, 6),
                "pos_match_ids": set(pos_matches),
                "other_match_ids": set(other_matches),
                "benign_match_ids": set(benign_matches),
            }

            signature = (
                tuple(sorted(pos_matches)),
                tuple(sorted(other_matches)),
                tuple(sorted(benign_matches)),
            )
            previous = deduped.get(signature)
            if previous is None or _candidate_sort_key(candidate) < _candidate_sort_key(previous):
                deduped[signature] = candidate

        candidate_pool.extend(sorted(deduped.values(), key=_candidate_sort_key)[:max_candidates_per_size])

    candidate_pool.sort(key=_candidate_sort_key)
    return candidate_pool


def _build_rule_from_clusters(
    *,
    clusters: list[list[dict[str, Any]]],
    train_target: list[str],
    train_other: list[str],
    benign_dev: list[str],
    max_strings: int,
    max_benign_match_rate: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[str]]:
    selected_clauses: list[dict[str, Any]] = []
    selected_terms_total = 0
    covered_target: set[str] = set()

    for cluster in clusters:
        if selected_terms_total >= max_strings:
            break

        budget = min(max_strings - selected_terms_total, 6, len(cluster))
        if budget <= 0:
            break

        terms = cluster[:budget]
        threshold = _select_clause_threshold(terms)
        target_hits = _clause_matches(terms, threshold, train_target, "pos_match_ids")
        if not target_hits:
            continue

        other_hits = _clause_matches(terms, threshold, train_other, "other_match_ids")
        benign_hits = _clause_matches(terms, threshold, benign_dev, "benign_match_ids")

        benign_rate = len(benign_hits) / len(benign_dev) if benign_dev else 0.0
        if benign_rate > max_benign_match_rate:
            continue

        target_rate = len(target_hits) / len(train_target) if train_target else 0.0
        other_rate = len(other_hits) / len(train_other) if train_other else 0.0
        clause_score = target_rate - other_rate - (2.0 * benign_rate)
        if clause_score <= 0.0:
            continue

        new_hits = target_hits - covered_target
        if not new_hits:
            continue

        selected_clauses.append(
            {
                "terms": terms,
                "threshold": threshold,
                "target_hits": target_hits,
                "other_hits": other_hits,
                "benign_hits": benign_hits,
                "score": round(clause_score, 6),
            }
        )
        selected_terms_total += len(terms)
        covered_target |= target_hits

        if len(covered_target) == len(train_target):
            break

    strings: list[dict[str, Any]] = []
    condition_parts: list[str] = []

    for clause in selected_clauses:
        clause_ids: list[str] = []
        for term in clause["terms"]:
            string_id = f"s{len(strings) + 1}"
            strings.append({"id": string_id, "hex_bytes": term["hex"]})
            clause_ids.append(f"${string_id}")

        if len(clause_ids) == 1:
            condition_parts.append(clause_ids[0])
        else:
            rendered_ids = ", ".join(clause_ids)
            condition_parts.append(f"({clause['threshold']} of ({rendered_ids}))")

    return strings, selected_clauses, covered_target


def _fallback_string_item(doc_bytes_by_id: dict[str, bytes], train_target: list[str], family: str) -> dict[str, Any]:
    for sample_id in train_target:
        data = doc_bytes_by_id.get(sample_id, b"")
        if len(data) >= 4:
            return {"id": "s1", "hex_bytes": _hexlify(data[: min(16, len(data))])}
    return {
        "id": "s1",
        "value": family,
        "nocase": True,
        "ascii": True,
        "wide": False,
    }


def write_baseline_rules(
    *,
    manifest: list[dict[str, Any]],
    splits: dict[str, Any],
    out_dir: str | Path,
    ngram_sizes: tuple[int, ...] = DEFAULT_NGRAM_SIZES,
    max_strings: int = 12,
    max_candidates_per_size: int = 48,
    min_score: float = 0.4,
    min_entropy: float = 1.0,
    cluster_similarity: float = 0.8,
    max_benign_match_rate: float = 0.0,
    max_bytes_per_file: int = 262144,
) -> dict[str, Any]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    path_by_id = {str(row["sample_id"]): str(row["path"]) for row in manifest}
    sample_ids = sorted(path_by_id)
    doc_bytes_by_id = {
        sample_id: _sample_bytes(path_by_id[sample_id], max_bytes_per_file)
        for sample_id in sample_ids
    }

    benign_dev = splits.get("global", {}).get("benign_dev", [])

    rule_paths: dict[str, str] = {}
    family_stats: dict[str, Any] = {}

    for family, family_split in sorted(splits.get("families", {}).items()):
        train_target = family_split.get("train_target", [])
        train_other = family_split.get("train_other", [])

        candidates = _collect_candidates_for_family(
            doc_bytes_by_id=doc_bytes_by_id,
            train_target=train_target,
            train_other=train_other,
            benign_dev=benign_dev,
            ngram_sizes=ngram_sizes,
            max_candidates_per_size=max_candidates_per_size,
            min_score=min_score,
            min_entropy=min_entropy,
        )
        clusters = _cluster_candidates(candidates, similarity_threshold=cluster_similarity)
        strings, selected_clauses, covered_target = _build_rule_from_clusters(
            clusters=clusters,
            train_target=train_target,
            train_other=train_other,
            benign_dev=benign_dev,
            max_strings=max_strings,
            max_benign_match_rate=max_benign_match_rate,
        )

        fallback_used = False
        if not strings:
            fallback_used = True
            strings = [_fallback_string_item(doc_bytes_by_id, train_target, family)]
            condition = "$s1"
        else:
            clause_conditions: list[str] = []
            offset = 0
            for clause in selected_clauses:
                size = len(clause["terms"])
                clause_ids = [f"$s{offset + index + 1}" for index in range(size)]
                if len(clause_ids) == 1:
                    clause_conditions.append(clause_ids[0])
                else:
                    clause_conditions.append(f"({clause['threshold']} of ({', '.join(clause_ids)}))")
                offset += size
            condition = " or ".join(clause_conditions)

        payload = {
            "rule_name": f"baseline_autoyara_{family}",
            "meta": {
                "family": family,
                "author": "baseline-autoyara",
                "description": "autoyara-like byte n-gram bicluster baseline",
            },
            "strings": strings,
            "condition": condition,
        }
        rule_text = render_rule(payload)

        path = out / f"{family}.yar"
        path.write_text(rule_text, encoding="utf-8")
        rule_paths[family] = str(path)

        family_stats[family] = {
            "candidate_count": len(candidates),
            "cluster_count": len(clusters),
            "clause_count": len(selected_clauses),
            "string_count": len(strings),
            "selected_hex_strings": [string["hex_bytes"] for string in strings if "hex_bytes" in string],
            "clause_thresholds": [int(clause["threshold"]) for clause in selected_clauses],
            "train_target_coverage": round(len(covered_target) / len(train_target), 6) if train_target else 0.0,
            "fallback_used": fallback_used,
        }

    return {
        "rule_paths": rule_paths,
        "family_stats": family_stats,
        "ngram_sizes": list(ngram_sizes),
        "max_strings": max_strings,
        "max_candidates_per_size": max_candidates_per_size,
        "min_score": min_score,
        "min_entropy": min_entropy,
        "cluster_similarity": cluster_similarity,
        "max_benign_match_rate": max_benign_match_rate,
        "max_bytes_per_file": max_bytes_per_file,
    }
