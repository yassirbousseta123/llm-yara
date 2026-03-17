from __future__ import annotations

from pathlib import Path
from typing import Any


def write_summary_markdown(path: str | Path, rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# LLM-YARA Evaluation Summary",
        "",
        f"- Families evaluated: {summary.get('families_total', 0)}",
        f"- Families with valid rules: {summary.get('families_ok', 0)}",
        f"- Families failed: {summary.get('families_failed', 0)}",
        f"- Missing rules: {summary.get('families_missing_rule', 0)}",
        f"- Compile failures: {summary.get('families_compile_failed', 0)}",
        f"- Scan errors: {summary.get('families_scan_error', 0)}",
        f"- Mean F1 (all families): {summary.get('mean_f1', 0.0):.4f}",
        f"- Mean TPR (all families): {summary.get('mean_tpr_target', 0.0):.4f}",
        f"- Mean benign FPR (all families): {summary.get('mean_fpr_benign', 0.0):.4f}",
        f"- Mean off-target rate (all families): {summary.get('mean_off_target_rate', 0.0):.4f}",
        f"- Mean rule specificity (all families): {summary.get('mean_rule_specificity', 0.0):.4f}",
        f"- Mean rule complexity (all families): {summary.get('mean_rule_complexity', 0.0):.2f}",
        f"- Mean F1 (ok only): {summary.get('mean_f1_ok_only', summary.get('mean_f1', 0.0)):.4f}",
        f"- Mean TPR (ok only): {summary.get('mean_tpr_target_ok_only', summary.get('mean_tpr_target', 0.0)):.4f}",
        f"- Mean benign FPR (ok only): {summary.get('mean_fpr_benign_ok_only', summary.get('mean_fpr_benign', 0.0)):.4f}",
        f"- Mean off-target rate (ok only): {summary.get('mean_off_target_rate_ok_only', summary.get('mean_off_target_rate', 0.0)):.4f}",
        f"- Mean rule specificity (ok only): {summary.get('mean_rule_specificity_ok_only', summary.get('mean_rule_specificity', 0.0)):.4f}",
        f"- Mean rule complexity (ok only): {summary.get('mean_rule_complexity_ok_only', summary.get('mean_rule_complexity', 0.0)):.2f}",
        "",
        "## Per-family",
    ]

    for row in rows:
        lines.append(
            f"- {row.get('family')}: status={row.get('status')} f1={row.get('f1', 0.0)} "
            f"tpr={row.get('tpr_target', 0.0)} fpr_benign={row.get('fpr_benign', 0.0)}"
        )

    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
