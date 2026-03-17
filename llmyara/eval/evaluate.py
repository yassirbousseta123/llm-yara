from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from llmyara.eval.metrics import binary_metrics, safe_div
from llmyara.yara.compile import compile_rule
from llmyara.yara.scan import scan_rule
from llmyara.yara.stats import rule_statistics


def _id_to_path(manifest: list[dict[str, Any]]) -> dict[str, str]:
    return {row["sample_id"]: row["path"] for row in manifest}


def _mean(rows: list[dict[str, Any]], key: str) -> float:
    if not rows:
        return 0.0
    return round(sum(float(row.get(key, 0.0)) for row in rows) / len(rows), 6)


def evaluate_rules(
    manifest: list[dict[str, Any]],
    splits: dict[str, Any],
    rule_paths: dict[str, str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    id_to_path = _id_to_path(manifest)
    benign_test_paths = [id_to_path[sid] for sid in splits["global"]["benign_test"] if sid in id_to_path]

    rows: list[dict[str, Any]] = []

    for family, family_split in splits["families"].items():
        rule_path = rule_paths.get(family)
        if not rule_path:
            rows.append(
                {
                    "family": family,
                    "status": "missing_rule",
                    "tpr_target": 0.0,
                    "fpr_benign": 0.0,
                    "off_target_rate": 0.0,
                    "rule_specificity": 1.0,
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1": 0.0,
                    "scan_seconds": 0.0,
                    "scan_error_count": 0,
                    "compile_ok": False,
                    "rule_string_count": 0,
                    "condition_clause_count": 0,
                    "rule_complexity": 0,
                    "rule_bytes": 0,
                    "condition_length": 0,
                }
            )
            continue

        rule_text = Path(rule_path).read_text(encoding="utf-8")
        stats = rule_statistics(rule_text)
        compile_res = compile_rule(rule_text)
        if not compile_res.ok:
            rows.append(
                {
                    "family": family,
                    "status": "compile_failed",
                    "tpr_target": 0.0,
                    "fpr_benign": 0.0,
                    "off_target_rate": 0.0,
                    "rule_specificity": 1.0,
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1": 0.0,
                    "scan_seconds": 0.0,
                    "scan_error_count": 0,
                    "compile_ok": False,
                    "compile_error": compile_res.error,
                    **stats,
                }
            )
            continue

        target_paths = [id_to_path[sid] for sid in family_split["test_target"] if sid in id_to_path]
        other_paths = [id_to_path[sid] for sid in family_split["test_other"] if sid in id_to_path]

        target_scan = scan_rule(rule_text, target_paths)
        other_scan = scan_rule(rule_text, other_paths)
        benign_scan = scan_rule(rule_text, benign_test_paths)

        scan_error_count = (
            getattr(target_scan, "error_count", 0)
            + getattr(other_scan, "error_count", 0)
            + getattr(benign_scan, "error_count", 0)
        )
        if scan_error_count:
            error_examples = list(getattr(target_scan, "errors", ()))
            error_examples.extend(getattr(other_scan, "errors", ()))
            error_examples.extend(getattr(benign_scan, "errors", ()))
            rows.append(
                {
                    "family": family,
                    "status": "scan_error",
                    "tpr_target": 0.0,
                    "fpr_benign": 0.0,
                    "off_target_rate": 0.0,
                    "rule_specificity": 1.0,
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1": 0.0,
                    "scan_seconds": round(
                        target_scan.elapsed_seconds + other_scan.elapsed_seconds + benign_scan.elapsed_seconds,
                        6,
                    ),
                    "scan_error_count": scan_error_count,
                    "scan_error_examples": " | ".join(error_examples[:3]),
                    "compile_ok": True,
                    "target_test_size": len(target_paths),
                    "other_test_size": len(other_paths),
                    "benign_test_size": len(benign_test_paths),
                    **stats,
                }
            )
            continue

        tp = len(target_scan.matches)
        fn = max(0, len(target_paths) - tp)
        fp = len(other_scan.matches) + len(benign_scan.matches)

        bm = binary_metrics(tp=tp, fp=fp, fn=fn)

        row = {
            "family": family,
            "status": "ok",
            "compile_ok": True,
            "tpr_target": round(safe_div(len(target_scan.matches), len(target_paths)), 6),
            "fpr_benign": round(safe_div(len(benign_scan.matches), len(benign_test_paths)), 6),
            "off_target_rate": round(safe_div(len(other_scan.matches), len(other_paths)), 6),
            "rule_specificity": round(1.0 - safe_div(len(other_scan.matches), len(other_paths)), 6),
            "precision": round(bm["precision"], 6),
            "recall": round(bm["recall"], 6),
            "f1": round(bm["f1"], 6),
            "scan_seconds": round(target_scan.elapsed_seconds + other_scan.elapsed_seconds + benign_scan.elapsed_seconds, 6),
            "scan_error_count": 0,
            "target_test_size": len(target_paths),
            "other_test_size": len(other_paths),
            "benign_test_size": len(benign_test_paths),
            **stats,
        }
        rows.append(row)

    ok_rows = [r for r in rows if r.get("status") == "ok"]
    status_counts = {
        "missing_rule": sum(1 for r in rows if r.get("status") == "missing_rule"),
        "compile_failed": sum(1 for r in rows if r.get("status") == "compile_failed"),
        "scan_error": sum(1 for r in rows if r.get("status") == "scan_error"),
    }
    summary = {
        "families_total": len(rows),
        "families_ok": len(ok_rows),
        "families_failed": len(rows) - len(ok_rows),
        "families_missing_rule": status_counts["missing_rule"],
        "families_compile_failed": status_counts["compile_failed"],
        "families_scan_error": status_counts["scan_error"],
        "mean_f1": _mean(rows, "f1"),
        "mean_tpr_target": _mean(rows, "tpr_target"),
        "mean_fpr_benign": _mean(rows, "fpr_benign"),
        "mean_off_target_rate": _mean(rows, "off_target_rate"),
        "mean_rule_specificity": _mean(rows, "rule_specificity"),
        "mean_rule_complexity": _mean(rows, "rule_complexity"),
        "mean_rule_string_count": _mean(rows, "rule_string_count"),
        "mean_condition_clause_count": _mean(rows, "condition_clause_count"),
        "mean_rule_bytes": _mean(rows, "rule_bytes"),
        "mean_f1_ok_only": _mean(ok_rows, "f1"),
        "mean_tpr_target_ok_only": _mean(ok_rows, "tpr_target"),
        "mean_fpr_benign_ok_only": _mean(ok_rows, "fpr_benign"),
        "mean_off_target_rate_ok_only": _mean(ok_rows, "off_target_rate"),
        "mean_rule_specificity_ok_only": _mean(ok_rows, "rule_specificity"),
        "mean_rule_complexity_ok_only": _mean(ok_rows, "rule_complexity"),
        "mean_rule_string_count_ok_only": _mean(ok_rows, "rule_string_count"),
        "mean_condition_clause_count_ok_only": _mean(ok_rows, "condition_clause_count"),
        "mean_rule_bytes_ok_only": _mean(ok_rows, "rule_bytes"),
    }
    return rows, summary


def write_results_csv(path: str | Path, rows: list[dict[str, Any]]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fieldnames = sorted(set().union(*(row.keys() for row in rows)))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
