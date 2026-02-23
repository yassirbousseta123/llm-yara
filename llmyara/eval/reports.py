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
        f"- Mean F1: {summary.get('mean_f1', 0.0):.4f}",
        f"- Mean TPR: {summary.get('mean_tpr_target', 0.0):.4f}",
        f"- Mean benign FPR: {summary.get('mean_fpr_benign', 0.0):.4f}",
        "",
        "## Per-family",
    ]

    for row in rows:
        lines.append(
            f"- {row.get('family')}: status={row.get('status')} f1={row.get('f1', 0.0)} "
            f"tpr={row.get('tpr_target', 0.0)} fpr_benign={row.get('fpr_benign', 0.0)}"
        )

    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
