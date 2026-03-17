from __future__ import annotations

from pathlib import Path

import pytest

from llmyara.eval import evaluate as evaluate_mod


def _manifest(tmp_path: Path) -> list[dict[str, str]]:
    return [
        {"sample_id": "t1", "path": str(tmp_path / "t1.bin")},
        {"sample_id": "o1", "path": str(tmp_path / "o1.bin")},
        {"sample_id": "b1", "path": str(tmp_path / "b1.bin")},
    ]


def _splits() -> dict:
    return {
        "families": {
            "fam_a": {
                "train_target": [],
                "test_target": ["t1"],
                "train_other": [],
                "test_other": ["o1"],
            },
            "fam_b": {
                "train_target": [],
                "test_target": ["t1"],
                "train_other": [],
                "test_other": ["o1"],
            },
        },
        "global": {
            "benign_dev": [],
            "benign_test": ["b1"],
        },
    }


def test_evaluate_rules_reports_all_family_and_ok_only_metrics(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evaluate_mod, "compile_rule", lambda rule_text: type("Compile", (), {"ok": True, "error": None})())

    def fake_scan(rule_text: str, file_paths: list[str]) -> object:
        matches = [path for path in file_paths if path.endswith("t1.bin")]
        return type("Scan", (), {"matches": matches, "elapsed_seconds": 0.1, "error_count": 0, "errors": ()})()

    monkeypatch.setattr(evaluate_mod, "scan_rule", fake_scan)

    rule_path = tmp_path / "fam_a.yar"
    rule_path.write_text("rule x { condition: true }", encoding="utf-8")

    rows, summary = evaluate_mod.evaluate_rules(
        manifest=_manifest(tmp_path),
        splits=_splits(),
        rule_paths={"fam_a": str(rule_path)},
    )

    assert len(rows) == 2
    assert summary["families_total"] == 2
    assert summary["families_ok"] == 1
    assert summary["families_missing_rule"] == 1
    assert summary["mean_f1"] == 0.5
    assert summary["mean_tpr_target"] == 0.5
    assert summary["mean_fpr_benign"] == 0.0
    assert summary["mean_f1_ok_only"] == 1.0


def test_evaluate_rules_marks_scan_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evaluate_mod, "compile_rule", lambda rule_text: type("Compile", (), {"ok": True, "error": None})())

    def fake_scan(rule_text: str, file_paths: list[str]) -> object:
        return type(
            "Scan",
            (),
            {"matches": [], "elapsed_seconds": 0.1, "error_count": 1, "errors": ("broken.bin: scan failed",)},
        )()

    monkeypatch.setattr(evaluate_mod, "scan_rule", fake_scan)

    rule_path = tmp_path / "fam_a.yar"
    rule_path.write_text("rule x { condition: true }", encoding="utf-8")

    rows, summary = evaluate_mod.evaluate_rules(
        manifest=_manifest(tmp_path),
        splits={"families": {"fam_a": _splits()["families"]["fam_a"]}, "global": _splits()["global"]},
        rule_paths={"fam_a": str(rule_path)},
    )

    assert rows[0]["status"] == "scan_error"
    assert rows[0]["scan_error_count"] == 3
    assert summary["families_scan_error"] == 1
