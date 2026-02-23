from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from llmyara.eval.metrics import binary_metrics, safe_div
from llmyara.yara.compile import compile_rule
from llmyara.yara.scan import scan_rule


def _id_to_path(manifest: list[dict[str, Any]]) -> dict[str, str]:
    return {row["sample_id"]: row["path"] for row in manifest}


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
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1": 0.0,
                    "scan_seconds": 0.0,
                    "compile_ok": False,
                }
            )
            continue

        rule_text = Path(rule_path).read_text(encoding="utf-8")
        compile_res = compile_rule(rule_text)
        if not compile_res.ok:
            rows.append(
                {
                    "family": family,
                    "status": "compile_failed",
                    "tpr_target": 0.0,
                    "fpr_benign": 0.0,
                    "off_target_rate": 0.0,
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1": 0.0,
                    "scan_seconds": 0.0,
                    "compile_ok": False,
                    "compile_error": compile_res.error,
                }
            )
            continue

        target_paths = [id_to_path[sid] for sid in family_split["test_target"] if sid in id_to_path]
        other_paths = [id_to_path[sid] for sid in family_split["test_other"] if sid in id_to_path]

        target_scan = scan_rule(rule_text, target_paths)
        other_scan = scan_rule(rule_text, other_paths)
        benign_scan = scan_rule(rule_text, benign_test_paths)

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
            "precision": round(bm["precision"], 6),
            "recall": round(bm["recall"], 6),
            "f1": round(bm["f1"], 6),
            "scan_seconds": round(target_scan.elapsed_seconds + other_scan.elapsed_seconds + benign_scan.elapsed_seconds, 6),
            "target_test_size": len(target_paths),
            "other_test_size": len(other_paths),
            "benign_test_size": len(benign_test_paths),
        }
        rows.append(row)

    ok_rows = [r for r in rows if r.get("status") == "ok"]
    summary = {
        "families_total": len(rows),
        "families_ok": len(ok_rows),
        "mean_f1": round(sum(r["f1"] for r in ok_rows) / len(ok_rows), 6) if ok_rows else 0.0,
        "mean_tpr_target": round(sum(r["tpr_target"] for r in ok_rows) / len(ok_rows), 6) if ok_rows else 0.0,
        "mean_fpr_benign": round(sum(r["fpr_benign"] for r in ok_rows) / len(ok_rows), 6) if ok_rows else 0.0,
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
