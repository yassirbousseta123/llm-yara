from __future__ import annotations

import json
from pathlib import Path

from baselines.apiary_static import write_baseline_rules


def test_apiary_static_baseline_prefers_discriminative_imports(tmp_path: Path) -> None:
    features = [
        {
            "sample_id": "t1",
            "tokens": [
                "imp:kernel32.dll!createfilew",
                "imp:advapi32.dll!regsetvalueexa",
                "str:alpha",
            ],
        },
        {
            "sample_id": "t2",
            "tokens": [
                "imp:kernel32.dll!createfilew",
                "imp:advapi32.dll!regsetvalueexa",
                "str:beta",
            ],
        },
        {
            "sample_id": "o1",
            "tokens": [
                "imp:ws2_32.dll!socket",
                "imp:ws2_32.dll!connect",
            ],
        },
        {
            "sample_id": "b1",
            "tokens": [
                "imp:user32.dll!messageboxa",
                "imp:ws2_32.dll!socket",
            ],
        },
    ]

    splits = {
        "families": {
            "fam_a": {
                "train_target": ["t1", "t2"],
                "test_target": [],
                "train_other": ["o1"],
                "test_other": [],
            }
        },
        "global": {
            "benign_dev": ["b1"],
            "benign_test": [],
        },
    }

    out = tmp_path / "apiary"
    result = write_baseline_rules(features=features, splits=splits, out_dir=out, max_strings=6, min_score=0.0)

    assert "fam_a" in result["rule_paths"]
    rule_path = Path(result["rule_paths"]["fam_a"])
    rule_text = rule_path.read_text(encoding="utf-8")

    assert "rule baseline_apiary_static_fam_a" in rule_text
    assert "createfilew" in rule_text
    assert "regsetvalueexa" in rule_text
    assert "socket" not in rule_text

    stats = result["family_stats"]["fam_a"]
    assert stats["string_count"] >= 2
    assert any("createfilew" in token for token in stats["selected_api_tokens"])


def test_apiary_static_baseline_writes_json_serializable_result(tmp_path: Path) -> None:
    features = [{"sample_id": "t1", "tokens": ["str:only_string"]}]
    splits = {
        "families": {
            "fam_b": {
                "train_target": ["t1"],
                "test_target": [],
                "train_other": [],
                "test_other": [],
            }
        },
        "global": {
            "benign_dev": [],
            "benign_test": [],
        },
    }

    result = write_baseline_rules(features=features, splits=splits, out_dir=tmp_path / "apiary_empty")
    payload = json.dumps(result)
    assert payload

    rule_path = Path(result["rule_paths"]["fam_b"])
    rule_text = rule_path.read_text(encoding="utf-8")
    assert "rule baseline_apiary_static_fam_b" in rule_text
    assert "fam_b" in rule_text
