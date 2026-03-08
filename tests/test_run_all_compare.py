from __future__ import annotations

from pathlib import Path

from llmyara.config import load_config
from llmyara.pipeline import run_all_compare as run_all_compare_mod


def test_run_all_compare_writes_comparison_manifest(tmp_path: Path, monkeypatch) -> None:
    out_dir = tmp_path / "out"

    monkeypatch.setattr(
        run_all_compare_mod,
        "run_all",
        lambda **kwargs: {
            "output_dir": str(out_dir.resolve()),
            "artifacts": {
                "manifest": str(tmp_path / "manifest.jsonl"),
                "splits": str(tmp_path / "splits.json"),
                "selected": str(tmp_path / "selected.json"),
                "features": str(tmp_path / "features.jsonl"),
                "generation": str(tmp_path / "generation.json"),
            },
        },
    )
    monkeypatch.setattr(
        run_all_compare_mod,
        "compare_all_methods",
        lambda **kwargs: {
            "output_dir": str((out_dir / "comparison").resolve()),
            "comparison_csv": str((out_dir / "comparison" / "results_all_methods.csv").resolve()),
            "comparison_json": str((out_dir / "comparison" / "summary_all_methods.json").resolve()),
            "comparison_markdown": str((out_dir / "comparison" / "summary_all_methods.md").resolve()),
        },
    )

    (tmp_path / "manifest.jsonl").write_text("", encoding="utf-8")
    (tmp_path / "features.jsonl").write_text("", encoding="utf-8")
    (tmp_path / "splits.json").write_text('{"families": {}, "global": {"benign_dev": [], "benign_test": []}}', encoding="utf-8")
    (tmp_path / "selected.json").write_text('{"families": {}}', encoding="utf-8")
    (tmp_path / "generation.json").write_text('{"rule_paths": {}}', encoding="utf-8")

    result = run_all_compare_mod.run_all_compare(
        cfg=load_config("configs/default.yaml"),
        malware_dir="/malware",
        benign_dir="/benign",
        out_dir=out_dir,
        backend_name="mock",
        topstrings_max_strings=8,
        apiary_max_strings=8,
        apiary_min_score=0.0,
        autoyara_max_strings=12,
        autoyara_min_score=0.4,
        autoyara_ngram_sizes=(8, 16, 32),
    )

    manifest_path = Path(result["comparison_run_manifest"])
    assert manifest_path.exists()
