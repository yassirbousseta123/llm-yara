from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from baselines.apiary_static import write_baseline_rules as write_apiary_static_rules
from baselines.autoyara_bicluster import write_baseline_rules as write_autoyara_rules
from baselines.topstrings_baseline import write_baseline_rules as write_topstrings_rules
from llmyara.eval.evaluate import evaluate_rules, write_results_csv
from llmyara.eval.reports import write_summary_markdown
from llmyara.utils.files import ensure_dir, write_json
from llmyara.yara.compile import is_yara_available


def _as_set(values: list[str] | None) -> set[str]:
    if not values:
        return set()
    return {v for v in values if isinstance(v, str)}


def _assert_disjoint(name_a: str, ids_a: set[str], name_b: str, ids_b: set[str], context: str) -> None:
    overlap = ids_a & ids_b
    if overlap:
        preview = ", ".join(sorted(overlap)[:5])
        raise ValueError(
            f"split leakage in {context}: {name_a} and {name_b} overlap "
            f"(count={len(overlap)}; examples={preview})"
        )


def assert_split_leakage_barriers(splits: dict[str, Any]) -> None:
    benign_dev = _as_set(splits.get("global", {}).get("benign_dev"))
    benign_test = _as_set(splits.get("global", {}).get("benign_test"))
    _assert_disjoint("benign_dev", benign_dev, "benign_test", benign_test, "global")

    families = splits.get("families", {})
    if not isinstance(families, dict):
        raise ValueError("invalid splits format: families must be an object")

    for family, family_split in families.items():
        train_target = _as_set(family_split.get("train_target"))
        test_target = _as_set(family_split.get("test_target"))
        train_other = _as_set(family_split.get("train_other"))
        test_other = _as_set(family_split.get("test_other"))

        context = f"family={family}"
        _assert_disjoint("train_target", train_target, "test_target", test_target, context)
        _assert_disjoint("train_other", train_other, "test_other", test_other, context)
        _assert_disjoint("train_target", train_target, "train_other", train_other, context)
        _assert_disjoint("test_target", test_target, "test_other", test_other, context)
        _assert_disjoint("train_target", train_target, "test_other", test_other, context)
        _assert_disjoint("test_target", test_target, "train_other", train_other, context)
        _assert_disjoint("train_target", train_target, "benign_test", benign_test, context)
        _assert_disjoint("test_target", test_target, "benign_dev", benign_dev, context)


def _write_comparison_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fieldnames = [
        "method",
        "status",
        "families_total",
        "families_ok",
        "mean_f1",
        "mean_tpr_target",
        "mean_fpr_benign",
        "rule_count",
        "output_dir",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _evaluate_one_method(
    *,
    method: str,
    status: str,
    out_dir: Path,
    manifest: list[dict[str, Any]],
    splits: dict[str, Any],
    rule_paths: dict[str, str],
    baseline_manifest_extra: dict[str, Any],
) -> dict[str, Any]:
    baseline_manifest = {
        "method": method,
        "status": status,
        "rule_paths": rule_paths,
        **baseline_manifest_extra,
    }
    write_json(out_dir / "baseline_manifest.json", baseline_manifest)

    rows, summary = evaluate_rules(manifest=manifest, splits=splits, rule_paths=rule_paths)
    write_results_csv(out_dir / "results_per_family.csv", rows)
    write_json(out_dir / "summary.json", summary)
    write_summary_markdown(out_dir / "summary.md", rows, summary)

    return {
        "method": method,
        "status": status,
        "output_dir": str(out_dir.resolve()),
        "rule_count": len(rule_paths),
        "summary": summary,
    }


def evaluate_baselines(
    *,
    manifest: list[dict[str, Any]],
    splits: dict[str, Any],
    selected: dict[str, Any],
    features: list[dict[str, Any]],
    out_dir: str | Path,
    topstrings_max_strings: int,
    apiary_max_strings: int,
    apiary_min_score: float,
    autoyara_max_strings: int,
    autoyara_min_score: float,
    autoyara_ngram_sizes: tuple[int, ...],
) -> dict[str, Any]:
    if not is_yara_available():
        raise RuntimeError("yara-python is required for baseline-eval. Install with .[runtime] or use Docker.")

    assert_split_leakage_barriers(splits)

    out = ensure_dir(out_dir)

    topstrings_dir = ensure_dir(Path(out) / "baseline_topstrings")
    topstrings_rules_dir = ensure_dir(topstrings_dir / "rules")
    topstrings_paths = write_topstrings_rules(
        selected=selected,
        out_dir=topstrings_rules_dir,
        max_strings=topstrings_max_strings,
    )
    topstrings_result = _evaluate_one_method(
        method="topstrings",
        status="reproduced",
        out_dir=topstrings_dir,
        manifest=manifest,
        splits=splits,
        rule_paths=topstrings_paths,
        baseline_manifest_extra={
            "max_strings": topstrings_max_strings,
        },
    )

    apiary_dir = ensure_dir(Path(out) / "baseline_apiary_static")
    apiary_rules_dir = ensure_dir(apiary_dir / "rules")
    apiary_rules = write_apiary_static_rules(
        features=features,
        splits=splits,
        out_dir=apiary_rules_dir,
        max_strings=apiary_max_strings,
        min_score=apiary_min_score,
    )
    apiary_result = _evaluate_one_method(
        method="apiary-static",
        status="re-implemented",
        out_dir=apiary_dir,
        manifest=manifest,
        splits=splits,
        rule_paths=apiary_rules["rule_paths"],
        baseline_manifest_extra={
            "max_strings": apiary_max_strings,
            "min_score": apiary_min_score,
            "family_stats": apiary_rules["family_stats"],
        },
    )

    autoyara_dir = ensure_dir(Path(out) / "baseline_autoyara")
    autoyara_rules_dir = ensure_dir(autoyara_dir / "rules")
    autoyara_rules = write_autoyara_rules(
        manifest=manifest,
        splits=splits,
        out_dir=autoyara_rules_dir,
        max_strings=autoyara_max_strings,
        min_score=autoyara_min_score,
        ngram_sizes=autoyara_ngram_sizes,
    )
    autoyara_result = _evaluate_one_method(
        method="autoyara-bicluster",
        status="re-implemented",
        out_dir=autoyara_dir,
        manifest=manifest,
        splits=splits,
        rule_paths=autoyara_rules["rule_paths"],
        baseline_manifest_extra={
            "max_strings": autoyara_max_strings,
            "min_score": autoyara_min_score,
            "ngram_sizes": list(autoyara_ngram_sizes),
            "family_stats": autoyara_rules["family_stats"],
        },
    )

    method_results = [topstrings_result, apiary_result, autoyara_result]
    comparison_rows = []
    for row in method_results:
        summary = row["summary"]
        comparison_rows.append(
            {
                "method": row["method"],
                "status": row["status"],
                "families_total": summary.get("families_total", 0),
                "families_ok": summary.get("families_ok", 0),
                "mean_f1": summary.get("mean_f1", 0.0),
                "mean_tpr_target": summary.get("mean_tpr_target", 0.0),
                "mean_fpr_benign": summary.get("mean_fpr_benign", 0.0),
                "rule_count": row["rule_count"],
                "output_dir": row["output_dir"],
            }
        )

    comparison_csv = Path(out) / "baseline_comparison.csv"
    comparison_json = Path(out) / "baseline_comparison.json"

    _write_comparison_csv(comparison_csv, comparison_rows)
    write_json(
        comparison_json,
        {
            "methods": method_results,
            "comparison_rows": comparison_rows,
        },
    )

    return {
        "output_dir": str(Path(out).resolve()),
        "comparison_csv": str(comparison_csv.resolve()),
        "comparison_json": str(comparison_json.resolve()),
        "methods": method_results,
    }
