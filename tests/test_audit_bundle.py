from __future__ import annotations

import csv
from pathlib import Path

from llmyara.eval.audit_bundle import export_audit_bundle
from llmyara.utils.files import write_json


def test_export_audit_bundle_sanitizes_paths(tmp_path: Path) -> None:
    primary = tmp_path / "primary"
    replay = tmp_path / "replay"
    (primary / "comparison").mkdir(parents=True)
    replay.mkdir(parents=True)

    write_json(primary / "summary.json", {"families_total": 1, "families_ok": 1, "mean_f1": 1.0})
    write_json(replay / "summary.json", {"families_total": 1, "families_ok": 1, "mean_f1": 1.0})
    write_json(
        primary / "comparison" / "summary_all_methods.json",
        {
            "comparison_rows": [
                {
                    "method": "llmyara-llm",
                    "role": "primary",
                    "status": "primary",
                    "families_total": 1,
                    "families_ok": 1,
                    "mean_f1": 1.0,
                    "mean_tpr_target": 1.0,
                    "mean_fpr_benign": 0.0,
                    "rule_count": 1,
                    "output_dir": "/secret/path",
                }
            ],
            "methods": [
                {
                    "method": "llmyara-llm",
                    "role": "primary",
                    "status": "primary",
                    "rule_count": 1,
                    "output_dir": "/secret/path",
                    "summary": {"families_total": 1, "families_ok": 1, "mean_f1": 1.0},
                }
            ],
        },
    )
    write_json(
        primary / "run_manifest.json",
        {
            "backend": "openai",
            "model": "gpt-5-mini",
            "openai_base_url": "http://localhost:11434/v1",
            "config": {"llm": {"model": "gpt-5-mini"}},
            "provenance": {"git_commit": "abc"},
            "artifact_hashes": {"summary_json": "123"},
            "output_dir": "/secret/path",
        },
    )
    with (primary / "results_per_family.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["family", "status"])
        writer.writeheader()
        writer.writerow({"family": "fam_a", "status": "ok"})

    result = export_audit_bundle(
        primary_run_dir=primary,
        replay_run_dir=replay,
        out_dir=tmp_path / "audit",
    )

    comparison_text = Path(result["comparison_summary"]).read_text(encoding="utf-8")
    manifest_text = Path(result["run_manifest"]).read_text(encoding="utf-8")
    csv_text = Path(result["comparison_rows_csv"]).read_text(encoding="utf-8")

    assert "/secret/path" not in comparison_text
    assert "/secret/path" not in manifest_text
    assert "/secret/path" not in csv_text
    assert '"provenance": {' in manifest_text


def test_export_audit_bundle_backfills_manifest_metadata(tmp_path: Path) -> None:
    primary = tmp_path / "primary"
    (primary / "comparison").mkdir(parents=True)

    write_json(primary / "summary.json", {"families_total": 1, "families_ok": 1, "mean_f1": 1.0})
    write_json(
        primary / "comparison" / "summary_all_methods.json",
        {
            "comparison_rows": [],
            "methods": [],
        },
    )
    write_json(
        primary / "run_manifest.json",
        {
            "backend": "openai",
            "model": "gpt-5-mini",
            "config": {"llm": {"model": "gpt-5-mini"}},
            "provenance": {},
            "artifact_hashes": {},
        },
    )
    write_json(primary / "generation_summary.json", {"families": {}})
    with (primary / "results_per_family.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["family", "status"])
        writer.writeheader()
        writer.writerow({"family": "fam_a", "status": "ok"})

    result = export_audit_bundle(primary_run_dir=primary, out_dir=tmp_path / "audit")
    manifest = Path(result["run_manifest"]).read_text(encoding="utf-8")

    assert '"git_commit"' in manifest
    assert '"artifact_hashes"' in manifest
