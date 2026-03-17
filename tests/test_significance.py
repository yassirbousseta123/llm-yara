from __future__ import annotations

from llmyara.eval.significance import paired_randomization_test


def test_paired_randomization_test_detects_large_gap() -> None:
    left = {"a": 1.0, "b": 1.0, "c": 1.0, "d": 1.0, "e": 1.0, "f": 1.0}
    right = {"a": 0.0, "b": 0.0, "c": 0.0, "d": 0.0, "e": 0.0, "f": 0.0}

    result = paired_randomization_test(left, right, iterations=4000, seed=42)

    assert result["n_pairs"] == 6
    assert float(result["observed_diff"]) == 1.0
    assert bool(result["significant_0_05"]) is True
