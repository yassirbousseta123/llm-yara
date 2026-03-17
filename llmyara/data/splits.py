from __future__ import annotations

import random
from collections import defaultdict
from typing import Any


def _partition(ids: list[str], ratio: float, seed: int) -> tuple[list[str], list[str]]:
    ids_copy = list(ids)
    rng = random.Random(seed)
    rng.shuffle(ids_copy)
    split_idx = int(len(ids_copy) * (1.0 - ratio))
    train = sorted(ids_copy[:split_idx])
    test = sorted(ids_copy[split_idx:])
    return train, test


def build_splits(
    manifest: list[dict[str, Any]],
    seed: int,
    test_ratio: float,
    benign_dev_ratio: float,
    min_family_size: int,
) -> dict[str, Any]:
    by_family: dict[str, set[str]] = defaultdict(set)
    benign_ids: set[str] = set()

    for row in manifest:
        sample_id = row["sample_id"]
        if row["source"] == "benign":
            benign_ids.add(sample_id)
        else:
            by_family[str(row["family"])].add(sample_id)

    eligible = sorted([family for family, ids in by_family.items() if len(ids) >= min_family_size])

    family_splits: dict[str, dict[str, list[str]]] = {}
    train_by_family: dict[str, list[str]] = {}
    test_by_family: dict[str, list[str]] = {}

    for idx, family in enumerate(eligible):
        train_ids, test_ids = _partition(sorted(by_family[family]), test_ratio, seed + idx)
        train_by_family[family] = train_ids
        test_by_family[family] = test_ids

    for family in eligible:
        train_other: list[str] = []
        test_other: list[str] = []
        for other in eligible:
            if other == family:
                continue
            train_other.extend(train_by_family[other])
            test_other.extend(test_by_family[other])
        family_splits[family] = {
            "train_target": sorted(train_by_family[family]),
            "test_target": sorted(test_by_family[family]),
            "train_other": sorted(set(train_other)),
            "test_other": sorted(set(test_other)),
        }

    benign_dev, benign_test = _partition(sorted(benign_ids), 1.0 - benign_dev_ratio, seed + 100000)

    return {
        "meta": {
            "seed": seed,
            "test_ratio": test_ratio,
            "benign_dev_ratio": benign_dev_ratio,
            "min_family_size": min_family_size,
            "families": eligible,
        },
        "families": family_splits,
        "global": {
            "benign_dev": sorted(benign_dev),
            "benign_test": sorted(benign_test),
        },
    }
