from __future__ import annotations

import csv
import random
from pathlib import Path


def load_metric_by_family(path: str | Path, metric: str = "f1") -> dict[str, float]:
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    return {row["family"]: float(row.get(metric, 0.0) or 0.0) for row in rows if row.get("family")}


def paired_randomization_test(
    left: dict[str, float],
    right: dict[str, float],
    *,
    seed: int = 42,
    iterations: int = 5000,
) -> dict[str, float | int | bool | str]:
    families = sorted(set(left) & set(right))
    if not families:
        return {
            "metric": "f1",
            "n_pairs": 0,
            "observed_diff": 0.0,
            "p_value": 1.0,
            "significant_0_05": False,
            "test": "paired_randomization",
        }

    diffs = [left[family] - right[family] for family in families]
    observed = sum(diffs) / len(diffs)

    rng = random.Random(seed)
    extreme = 0
    for _ in range(iterations):
        shuffled = [diff if rng.random() >= 0.5 else -diff for diff in diffs]
        permuted = sum(shuffled) / len(shuffled)
        if abs(permuted) >= abs(observed):
            extreme += 1

    p_value = (extreme + 1) / (iterations + 1)
    return {
        "metric": "f1",
        "n_pairs": len(families),
        "observed_diff": round(observed, 6),
        "p_value": round(p_value, 6),
        "significant_0_05": p_value < 0.05,
        "test": "paired_randomization",
    }
