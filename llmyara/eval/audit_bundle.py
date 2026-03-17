from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from llmyara.utils.files import ensure_dir, write_json


def _read_json(path: str | Path) -> dict[str, Any]:
    import json

    return json.loads(Path(path).read_text(encoding="utf-8"))


def _copy_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")


def _sanitize_run_manifest(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "backend": data.get("backend"),
        "model": data.get("model") or data.get("config", {}).get("llm", {}).get("model"),
        "openai_base_url": data.get("openai_base_url"),
        "config": data.get("config", {}),
        "provenance": data.get("provenance", {}),
        "artifact_hashes": data.get("artifact_hashes", {}),
    }


def _comparison_from_method_summaries(primary_dir: Path) -> dict[str, Any]:
    method_specs = [
        ("llmyara-llm", "primary", "primary", primary_dir / "comparison" / "llmyara_llm" / "summary.json"),
        (
            "topstrings",
            "baseline",
            "reproduced",
            primary_dir / "comparison" / "baselines" / "baseline_topstrings" / "summary.json",
        ),
        (
            "apiary-static",
            "baseline",
            "re-implemented",
            primary_dir / "comparison" / "baselines" / "baseline_apiary_static" / "summary.json",
        ),
        (
            "autoyara-bicluster",
            "baseline",
            "re-implemented",
            primary_dir / "comparison" / "baselines" / "baseline_autoyara" / "summary.json",
        ),
    ]

    methods: list[dict[str, Any]] = []
    comparison_rows: list[dict[str, Any]] = []
    for method, role, status, path in method_specs:
        if not path.exists():
            continue
        summary = _read_json(path)
        row = {
            "method": method,
            "role": role,
            "status": status,
            "families_total": summary.get("families_total", 0),
            "families_ok": summary.get("families_ok", 0),
            "mean_f1": summary.get("mean_f1", 0.0),
            "mean_tpr_target": summary.get("mean_tpr_target", 0.0),
            "mean_fpr_benign": summary.get("mean_fpr_benign", 0.0),
            "rule_count": summary.get("families_ok", 0),
        }
        methods.append(
            {
                "method": method,
                "role": role,
                "status": status,
                "summary": summary,
                "rule_count": row["rule_count"],
            }
        )
        comparison_rows.append(row)

    return {
        "comparison_rows": comparison_rows,
        "methods": methods,
    }


def _sanitize_comparison(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "comparison_rows": [{k: v for k, v in row.items() if k != "output_dir"} for row in data.get("comparison_rows", [])],
        "methods": [{k: v for k, v in row.items() if k != "output_dir"} for row in data.get("methods", [])],
    }


def _write_comparison_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = [
        "method",
        "role",
        "status",
        "families_total",
        "families_ok",
        "mean_f1",
        "mean_tpr_target",
        "mean_fpr_benign",
        "rule_count",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name) for name in fieldnames})


def _write_bundle_readme(path: Path, primary_dir: Path, replay_dir: Path | None) -> None:
    lines = [
        "# Public Audit Bundle",
        "",
        "Safe, reviewable export of final run metrics and manifests.",
        "",
        "Contents:",
        "- `primary_summary.json`: frozen primary run summary",
        "- `replay_summary.json`: replay summary (if provided)",
        "- `comparison_summary.json`: sanitized same-split comparison summary",
        "- `comparison_rows.csv`: sanitized comparison table",
        "- `results_per_family.csv`: primary per-family results",
        "- `run_manifest.json`: sanitized primary run manifest",
        "",
        f"Primary source: `{primary_dir}`",
    ]
    if replay_dir is not None:
        lines.append(f"Replay source: `{replay_dir}`")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def export_audit_bundle(
    *,
    primary_run_dir: str | Path,
    out_dir: str | Path,
    replay_run_dir: str | Path | None = None,
) -> dict[str, str]:
    primary_dir = Path(primary_run_dir)
    replay_dir = Path(replay_run_dir) if replay_run_dir is not None else None
    out = ensure_dir(out_dir)

    primary_summary = _read_json(primary_dir / "summary.json")
    comparison_summary = _comparison_from_method_summaries(primary_dir)
    if not comparison_summary["comparison_rows"]:
        comparison_summary = _sanitize_comparison(_read_json(primary_dir / "comparison" / "summary_all_methods.json"))
    run_manifest = _sanitize_run_manifest(_read_json(primary_dir / "run_manifest.json"))

    write_json(out / "primary_summary.json", primary_summary)
    write_json(out / "comparison_summary.json", comparison_summary)
    write_json(out / "run_manifest.json", run_manifest)
    _write_comparison_csv(out / "comparison_rows.csv", comparison_summary["comparison_rows"])
    _copy_file(primary_dir / "results_per_family.csv", out / "results_per_family.csv")

    outputs = {
        "output_dir": str(Path(out).resolve()),
        "primary_summary": str((out / "primary_summary.json").resolve()),
        "comparison_summary": str((out / "comparison_summary.json").resolve()),
        "comparison_rows_csv": str((out / "comparison_rows.csv").resolve()),
        "results_per_family_csv": str((out / "results_per_family.csv").resolve()),
        "run_manifest": str((out / "run_manifest.json").resolve()),
    }

    if replay_dir is not None:
        write_json(out / "replay_summary.json", _read_json(replay_dir / "summary.json"))
        outputs["replay_summary"] = str((out / "replay_summary.json").resolve())

    _write_bundle_readme(out / "README.md", primary_dir=primary_dir, replay_dir=replay_dir)
    outputs["readme"] = str((out / "README.md").resolve())
    return outputs
