from __future__ import annotations

from baselines.topstrings_baseline import generate_topstrings_rule


def test_topstrings_rule_contains_expected_literals() -> None:
    rule = generate_topstrings_rule(
        family="fam_a",
        selected_features=[
            {"feature": "str:red_loader", "score": 3.2},
            {"feature": "str:mutex_red", "score": 2.1},
        ],
        max_strings=4,
    )
    assert "red_loader" in rule
    assert "mutex_red" in rule
    assert "rule baseline_topstrings_fam_a" in rule
