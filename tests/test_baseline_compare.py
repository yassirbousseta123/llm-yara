from __future__ import annotations

import csv
from pathlib import Path

import pytest

from llmyara.eval import baseline_compare


def _sample_inputs(tmp_path: Path) -> tuple[list[dict[str, str]], dict, dict, list[dict[str, object]], Path]:
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
            "tokens": ["imp:kernel32.dll!createfilew", "imp:advapi32.dll!regsetvalueexa"],
        },
        {
            "sample_id": "o1",
            "tokens": ["imp:ws2_32.dll!socket"],
        },
        {
            "sample_id": "b1",
            "tokens": ["imp:user32.dll!messageboxa"],
        },
    ]

    out_dir = tmp_path / "baseline_eval"
    return manifest, splits, selected, features, out_dir


def test_evaluate_baselines_writes_comparison_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest, splits, selected, features, out_dir = _sample_inputs(tmp_path)

    monkeypatch.setattr(baseline_compare, "is_yara_available", lambda: True)

    def fake_evaluate_rules(manifest: list[dict[str, str]], splits: dict, rule_paths: dict[str, str]) -> tuple[list[dict], dict]:
        assert manifest
        assert splits
        assert "fam_a" in rule_paths
        method_hint = next(iter(rule_paths.values()))
        mean_f1 = 0.41 if "baseline_topstrings" in method_hint else 0.62
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

    monkeypatch.setattr(baseline_compare, "evaluate_rules", fake_evaluate_rules)

    result = baseline_compare.evaluate_baselines(
        manifest=manifest,
        splits=splits,
        selected=selected,
        features=features,
        out_dir=out_dir,
        topstrings_max_strings=4,
        apiary_max_strings=4,
        apiary_min_score=0.0,
    )

    comparison_csv = Path(result["comparison_csv"])
    comparison_json = Path(result["comparison_json"])
    assert comparison_csv.exists()
    assert comparison_json.exists()

    with comparison_csv.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    methods = {row["method"]: row for row in rows}
    assert methods["topstrings"]["status"] == "reproduced"
    assert methods["apiary-static"]["status"] == "re-implemented"

    topstrings_manifest = out_dir / "baseline_topstrings" / "baseline_manifest.json"
    apiary_manifest = out_dir / "baseline_apiary_static" / "baseline_manifest.json"
    assert topstrings_manifest.exists()
    assert apiary_manifest.exists()


def test_assert_split_leakage_barriers_rejects_overlap() -> None:
    bad_splits = {
        "families": {
            "fam_a": {
                "train_target": ["a"],
                "test_target": ["b"],
                "train_other": ["c"],
                "test_other": ["d"],
            }
        },
        "global": {
            "benign_dev": ["x", "z"],
            "benign_test": ["z", "y"],
        },
    }

    with pytest.raises(ValueError, match="benign_dev and benign_test overlap"):
        baseline_compare.assert_split_leakage_barriers(bad_splits)


def test_evaluate_baselines_requires_yara(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(baseline_compare, "is_yara_available", lambda: False)

    with pytest.raises(RuntimeError, match="yara-python is required for baseline-eval"):
        baseline_compare.evaluate_baselines(
            manifest=[],
            splits={"families": {}, "global": {"benign_dev": [], "benign_test": []}},
            selected={"families": {}},
            features=[],
            out_dir=tmp_path / "out",
            topstrings_max_strings=8,
            apiary_max_strings=8,
            apiary_min_score=0.0,
        )
