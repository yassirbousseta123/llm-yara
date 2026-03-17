from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from llmyara.eval.failure_analysis import summarize_generation_failures
from llmyara.eval.baseline_compare import assert_split_leakage_barriers, evaluate_baselines
from llmyara.eval.evaluate import evaluate_rules, write_results_csv
from llmyara.eval.reports import write_summary_markdown
from llmyara.eval.significance import load_metric_by_family, paired_randomization_test
from llmyara.utils.files import ensure_dir, write_json
from llmyara.yara.compile import is_yara_available


def _write_comparison_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fieldnames = [
        "method",
        "role",
        "status",
        "families_total",
        "families_ok",
        "mean_f1",
        "mean_tpr_target",
        "mean_fpr_benign",
        "mean_rule_specificity",
        "mean_rule_complexity",
        "rule_count",
        "output_dir",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_comparison_markdown(path: Path, rows: list[dict[str, Any]]) -> None:
    lines = [
        "# All-Method Comparison",
        "",
        "| Method | Role | Status | Families OK | Mean F1 | Mean TPR | Mean Benign FPR | Mean Rule Specificity | Mean Rule Complexity | Rules |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for row in rows:
        lines.append(
            f"| {row['method']} | {row['role']} | {row['status']} | "
            f"{row['families_ok']}/{row['families_total']} | "
            f"{float(row['mean_f1']):.4f} | "
            f"{float(row['mean_tpr_target']):.4f} | "
            f"{float(row['mean_fpr_benign']):.4f} | "
            f"{float(row.get('mean_rule_specificity', 0.0)):.4f} | "
            f"{float(row.get('mean_rule_complexity', 0.0)):.2f} | "
            f"{row['rule_count']} |"
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _evaluate_one_method(
    *,
    method: str,
    role: str,
    status: str,
    out_dir: Path,
    manifest: list[dict[str, Any]],
    splits: dict[str, Any],
    rule_paths: dict[str, str],
    extra_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    write_json(
        out_dir / "method_manifest.json",
        {
            "method": method,
            "role": role,
            "status": status,
            "rule_paths": rule_paths,
            **(extra_manifest or {}),
        },
    )

    rows, summary = evaluate_rules(manifest=manifest, splits=splits, rule_paths=rule_paths)
    write_results_csv(out_dir / "results_per_family.csv", rows)
    write_json(out_dir / "summary.json", summary)
    write_summary_markdown(out_dir / "summary.md", rows, summary)

    return {
        "method": method,
        "role": role,
        "status": status,
        "output_dir": str(out_dir.resolve()),
        "rule_count": len(rule_paths),
        "summary": summary,
    }


def _comparison_row(result: dict[str, Any]) -> dict[str, Any]:
    summary = result["summary"]
    return {
        "method": result["method"],
        "role": result["role"],
        "status": result["status"],
        "families_total": summary.get("families_total", 0),
        "families_ok": summary.get("families_ok", 0),
        "mean_f1": summary.get("mean_f1", 0.0),
        "mean_tpr_target": summary.get("mean_tpr_target", 0.0),
        "mean_fpr_benign": summary.get("mean_fpr_benign", 0.0),
        "mean_rule_specificity": summary.get("mean_rule_specificity", 0.0),
        "mean_rule_complexity": summary.get("mean_rule_complexity", 0.0),
        "rule_count": result["rule_count"],
        "output_dir": result["output_dir"],
    }


def _significance_vs_primary(method_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    primary = next((item for item in method_results if item.get("role") == "primary"), None)
    if primary is None:
        return []

    primary_rows = load_metric_by_family(Path(primary["output_dir"]) / "results_per_family.csv")
    comparisons: list[dict[str, Any]] = []
    for item in method_results:
        if item is primary:
            continue
        method_rows = load_metric_by_family(Path(item["output_dir"]) / "results_per_family.csv")
        result = paired_randomization_test(primary_rows, method_rows)
        comparisons.append(
            {
                "baseline_method": item["method"],
                "primary_method": primary["method"],
                **result,
            }
        )
    return comparisons


def compare_all_methods(
    *,
    manifest: list[dict[str, Any]],
    splits: dict[str, Any],
    selected: dict[str, Any],
    features: list[dict[str, Any]],
    generation: dict[str, Any],
    out_dir: str | Path,
    llm_method_name: str = "llmyara-llm",
    llm_status: str = "primary",
    topstrings_max_strings: int = 8,
    apiary_max_strings: int = 8,
    apiary_min_score: float = 0.0,
    autoyara_max_strings: int = 12,
    autoyara_min_score: float = 0.4,
    autoyara_ngram_sizes: tuple[int, ...] = (8, 16, 32),
) -> dict[str, Any]:
    if not is_yara_available():
        raise RuntimeError("yara-python is required for compare-all. Install with .[runtime] or use Docker.")

    assert_split_leakage_barriers(splits)

    out = ensure_dir(out_dir)

    llm_dir = ensure_dir(Path(out) / "llmyara_llm")
    llm_result = _evaluate_one_method(
        method=llm_method_name,
        role="primary",
        status=llm_status,
        out_dir=llm_dir,
        manifest=manifest,
        splits=splits,
        rule_paths=generation.get("rule_paths", {}),
        extra_manifest={"backend": generation.get("backend")},
    )

    baseline_dir = ensure_dir(Path(out) / "baselines")
    baseline_result = evaluate_baselines(
        manifest=manifest,
        splits=splits,
        selected=selected,
        features=features,
        out_dir=baseline_dir,
        topstrings_max_strings=topstrings_max_strings,
        apiary_max_strings=apiary_max_strings,
        apiary_min_score=apiary_min_score,
        autoyara_max_strings=autoyara_max_strings,
        autoyara_min_score=autoyara_min_score,
        autoyara_ngram_sizes=autoyara_ngram_sizes,
    )

    baseline_methods = [{**item, "role": "baseline"} for item in baseline_result["methods"]]
    method_results = [llm_result, *baseline_methods]
    comparison_rows = [_comparison_row(item) for item in method_results]
    significance = _significance_vs_primary(method_results)
    failure_analysis = summarize_generation_failures(generation)

    comparison_csv = Path(out) / "results_all_methods.csv"
    comparison_json = Path(out) / "summary_all_methods.json"
    comparison_md = Path(out) / "summary_all_methods.md"
    significance_json = Path(out) / "significance_vs_primary.json"
    failure_json = Path(out) / "failure_analysis.json"

    _write_comparison_csv(comparison_csv, comparison_rows)
    _write_comparison_markdown(comparison_md, comparison_rows)
    write_json(significance_json, {"comparisons": significance})
    write_json(failure_json, failure_analysis)
    write_json(
        comparison_json,
        {
            "methods": method_results,
            "comparison_rows": comparison_rows,
            "significance_vs_primary": significance,
            "failure_analysis": failure_analysis,
            "baseline_comparison_csv": baseline_result["comparison_csv"],
            "baseline_comparison_json": baseline_result["comparison_json"],
        },
    )

    return {
        "output_dir": str(Path(out).resolve()),
        "comparison_csv": str(comparison_csv.resolve()),
        "comparison_json": str(comparison_json.resolve()),
        "comparison_markdown": str(comparison_md.resolve()),
        "significance_json": str(significance_json.resolve()),
        "failure_analysis_json": str(failure_json.resolve()),
        "methods": method_results,
        "baseline_result": baseline_result,
    }
