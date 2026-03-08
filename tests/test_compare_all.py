from __future__ import annotations

import csv
from pathlib import Path

import pytest

from llmyara.eval import compare_all


def _sample_inputs(tmp_path: Path) -> tuple[list[dict[str, str]], dict, dict, list[dict[str, object]], dict, Path]:
    manifest = [
        {"sample_id": "t1", "path": str(tmp_path / "t1.bin")},
        {"sample_id": "t2", "path": str(tmp_path / "t2.bin")},
        {"sample_id": "o1", "path": str(tmp_path / "o1.bin")},
        {"sample_id": "o2", "path": str(tmp_path / "o2.bin")},
        {"sample_id": "b1", "path": str(tmp_path / "b1.bin")},
        {"sample_id": "b2", "path": str(tmp_path / "b2.bin")},
    ]

    splits = {
        "families": {
            "fam_a": {
                "train_target": ["t1"],
                "test_target": ["t2"],
                "train_other": ["o1"],
                "test_other": ["o2"],
            }
        },
        "global": {
            "benign_dev": ["b1"],
            "benign_test": ["b2"],
        },
    }

    selected = {
        "families": {
            "fam_a": [
                {"feature": "str:loader_a", "score": 3.0},
                {"feature": "str:mutex_a", "score": 2.0},
            ]
        }
    }

    features = [
        {
            "sample_id": "t1",
            "tokens": ["imp:kernel32.dll!createfilew"],
        }
    ]
    generation = {"backend": "mock", "rule_paths": {"fam_a": str(tmp_path / "rules" / "fam_a.yar")}}
    out_dir = tmp_path / "compare_all"
    return manifest, splits, selected, features, generation, out_dir


def test_compare_all_writes_unified_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest, splits, selected, features, generation, out_dir = _sample_inputs(tmp_path)

    monkeypatch.setattr(compare_all, "is_yara_available", lambda: True)

    def fake_evaluate_rules(manifest: list[dict[str, str]], splits: dict, rule_paths: dict[str, str]) -> tuple[list[dict], dict]:
        assert manifest
        assert splits
        assert "fam_a" in rule_paths
        method_hint = next(iter(rule_paths.values()))
        mean_f1 = 0.77 if "rules/fam_a.yar" in method_hint else 0.55
        rows = [
            {
                "family": "fam_a",
                "status": "ok",
                "f1": mean_f1,
                "tpr_target": 1.0,
                "fpr_benign": 0.0,
            }
        ]
        summary = {
            "families_total": 1,
            "families_ok": 1,
            "mean_f1": mean_f1,
            "mean_tpr_target": 1.0,
            "mean_fpr_benign": 0.0,
        }
        return rows, summary

    monkeypatch.setattr(compare_all, "evaluate_rules", fake_evaluate_rules)

    def fake_evaluate_baselines(**_: object) -> dict[str, object]:
        return {
            "comparison_csv": str(out_dir / "baselines" / "baseline_comparison.csv"),
            "comparison_json": str(out_dir / "baselines" / "baseline_comparison.json"),
            "methods": [
                {
                    "method": "topstrings",
                    "status": "reproduced",
                    "role": "baseline",
                    "output_dir": str((out_dir / "baselines" / "baseline_topstrings").resolve()),
                    "rule_count": 1,
                    "summary": {
                        "families_total": 1,
                        "families_ok": 1,
                        "mean_f1": 0.41,
                        "mean_tpr_target": 1.0,
                        "mean_fpr_benign": 0.0,
                    },
                }
            ],
        }

    monkeypatch.setattr(compare_all, "evaluate_baselines", fake_evaluate_baselines)

    result = compare_all.compare_all_methods(
        manifest=manifest,
        splits=splits,
        selected=selected,
        features=features,
        generation=generation,
        out_dir=out_dir,
    )

    comparison_csv = Path(result["comparison_csv"])
    comparison_json = Path(result["comparison_json"])
    comparison_md = Path(result["comparison_markdown"])
    assert comparison_csv.exists()
    assert comparison_json.exists()
    assert comparison_md.exists()

    with comparison_csv.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 2
    methods = {row["method"]: row for row in rows}
    assert methods["llmyara-llm"]["role"] == "primary"
    assert methods["topstrings"]["role"] == "baseline"


def test_compare_all_requires_yara(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compare_all, "is_yara_available", lambda: False)

    with pytest.raises(RuntimeError, match="yara-python is required for compare-all"):
        compare_all.compare_all_methods(
            manifest=[],
            splits={"families": {}, "global": {"benign_dev": [], "benign_test": []}},
            selected={"families": {}},
            features=[],
            generation={"rule_paths": {}},
            out_dir=tmp_path / "out",
        )
