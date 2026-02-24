from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from baselines.apiary_static import write_baseline_rules as write_apiary_static_rules
from baselines.topstrings_baseline import write_baseline_rules
from llmyara.config import load_config
from llmyara.data.demo_data import create_demo_dataset
from llmyara.data.indexer import build_manifest
from llmyara.data.splits import build_splits
from llmyara.eval.baseline_compare import evaluate_baselines
from llmyara.eval.evaluate import evaluate_rules, write_results_csv
from llmyara.eval.reports import write_summary_markdown
from llmyara.features.extract import extract_features
from llmyara.pipeline.generate import generate_rules
from llmyara.pipeline.run_all import run_all
from llmyara.selection.score import select_all_families
from llmyara.utils.files import ensure_dir, write_json
from llmyara.utils.jsonl import read_jsonl, write_jsonl


def _read_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def cmd_make_demo_data(args: argparse.Namespace) -> None:
    out = ensure_dir(args.out)
    stats = create_demo_dataset(out)
    print(json.dumps({"out": str(Path(out).resolve()), "stats": stats}, indent=2))


def cmd_index(args: argparse.Namespace) -> None:
    manifest = build_manifest(args.malware_dir, args.benign_dir)
    write_jsonl(args.out, manifest)
    print(f"manifest_written={args.out} entries={len(manifest)}")


def cmd_split(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    manifest = list(read_jsonl(args.manifest))
    splits = build_splits(
        manifest=manifest,
        seed=cfg.seed,
        test_ratio=cfg.split.test_ratio,
        benign_dev_ratio=cfg.split.benign_dev_ratio,
        min_family_size=cfg.split.min_family_size,
    )
    write_json(args.out, splits)
    print(f"splits_written={args.out} families={len(splits['families'])}")


def cmd_extract(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    manifest = list(read_jsonl(args.manifest))
    features = extract_features(manifest, cfg.features)
    write_jsonl(args.out, features)
    print(f"features_written={args.out} entries={len(features)}")


def cmd_select(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    features = list(read_jsonl(args.features))
    splits = _read_json(args.splits)
    selected = select_all_families(features, splits, top_k=cfg.selection.top_k_features)
    write_json(args.out, selected)
    print(f"selected_written={args.out} families={len(selected['families'])}")


def cmd_generate(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    manifest = list(read_jsonl(args.manifest))
    splits = _read_json(args.splits)
    selected = _read_json(args.selected)

    out_dir = ensure_dir(args.out)
    generation = generate_rules(
        manifest=manifest,
        splits=splits,
        selected=selected,
        cfg=cfg,
        backend_name=args.backend,
        out_dir=out_dir,
        cache_path=Path(out_dir) / "llm_cache.jsonl",
    )
    write_json(Path(out_dir) / "generation_summary.json", generation)
    print(f"generation_written={Path(out_dir) / 'generation_summary.json'}")


def cmd_evaluate(args: argparse.Namespace) -> None:
    out_dir = ensure_dir(args.out)
    manifest = list(read_jsonl(args.manifest))
    splits = _read_json(args.splits)
    generation = _read_json(args.generation)
    rows, summary = evaluate_rules(manifest=manifest, splits=splits, rule_paths=generation.get("rule_paths", {}))
    write_results_csv(Path(out_dir) / "results_per_family.csv", rows)
    write_json(Path(out_dir) / "summary.json", summary)
    write_summary_markdown(Path(out_dir) / "summary.md", rows, summary)
    print(f"evaluation_written={Path(out_dir) / 'summary.json'}")


def cmd_run_all(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    result = run_all(
        cfg=cfg,
        malware_dir=args.malware_dir,
        benign_dir=args.benign_dir,
        out_dir=args.out,
        backend_name=args.backend,
    )
    print(json.dumps(result, indent=2))


def cmd_baseline_topstrings(args: argparse.Namespace) -> None:
    selected = _read_json(args.selected)
    paths = write_baseline_rules(selected=selected, out_dir=args.out, max_strings=args.max_strings)
    write_json(Path(args.out) / "baseline_manifest.json", {"rule_paths": paths, "status": "reproduced"})
    print(f"baseline_rules_written={len(paths)} out={args.out}")


def cmd_baseline_apiary_static(args: argparse.Namespace) -> None:
    features = list(read_jsonl(args.features))
    splits = _read_json(args.splits)
    result = write_apiary_static_rules(
        features=features,
        splits=splits,
        out_dir=args.out,
        max_strings=args.max_strings,
        min_score=args.min_score,
    )
    manifest = {
        "method": "apiary-static",
        "status": "re-implemented",
        **result,
    }
    write_json(Path(args.out) / "baseline_manifest.json", manifest)
    print(f"baseline_rules_written={len(result['rule_paths'])} out={args.out}")


def cmd_baseline_eval(args: argparse.Namespace) -> None:
    manifest = list(read_jsonl(args.manifest))
    splits = _read_json(args.splits)
    selected = _read_json(args.selected)
    features = list(read_jsonl(args.features))

    result = evaluate_baselines(
        manifest=manifest,
        splits=splits,
        selected=selected,
        features=features,
        out_dir=args.out,
        topstrings_max_strings=args.topstrings_max_strings,
        apiary_max_strings=args.apiary_max_strings,
        apiary_min_score=args.apiary_min_score,
    )
    print(f"baseline_comparison_written={result['comparison_csv']}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LLM-YARA pipeline CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    make_demo = sub.add_parser("make-demo-data", help="Create synthetic demo dataset")
    make_demo.add_argument("--out", required=True)
    make_demo.set_defaults(func=cmd_make_demo_data)

    index = sub.add_parser("index", help="Index malware/benign datasets into manifest")
    index.add_argument("--malware-dir", required=True)
    index.add_argument("--benign-dir", required=True)
    index.add_argument("--out", required=True)
    index.set_defaults(func=cmd_index)

    split = sub.add_parser("split", help="Create deterministic train/test splits")
    split.add_argument("--manifest", required=True)
    split.add_argument("--config", default="configs/default.yaml")
    split.add_argument("--out", required=True)
    split.set_defaults(func=cmd_split)

    extract = sub.add_parser("extract", help="Extract static features")
    extract.add_argument("--manifest", required=True)
    extract.add_argument("--config", default="configs/default.yaml")
    extract.add_argument("--out", required=True)
    extract.set_defaults(func=cmd_extract)

    select = sub.add_parser("select", help="Select discriminative features")
    select.add_argument("--features", required=True)
    select.add_argument("--splits", required=True)
    select.add_argument("--config", default="configs/default.yaml")
    select.add_argument("--out", required=True)
    select.set_defaults(func=cmd_select)

    generate = sub.add_parser("generate", help="Generate YARA rules")
    generate.add_argument("--manifest", required=True)
    generate.add_argument("--splits", required=True)
    generate.add_argument("--selected", required=True)
    generate.add_argument("--config", default="configs/default.yaml")
    generate.add_argument("--backend", default="mock", choices=["mock", "replay", "openai"])
    generate.add_argument("--out", required=True)
    generate.set_defaults(func=cmd_generate)

    evaluate = sub.add_parser("evaluate", help="Evaluate generated rules")
    evaluate.add_argument("--manifest", required=True)
    evaluate.add_argument("--splits", required=True)
    evaluate.add_argument("--generation", required=True)
    evaluate.add_argument("--out", required=True)
    evaluate.set_defaults(func=cmd_evaluate)

    run_all_parser = sub.add_parser("run-all", help="Run full pipeline")
    run_all_parser.add_argument("--config", default="configs/default.yaml")
    run_all_parser.add_argument("--malware-dir", required=True)
    run_all_parser.add_argument("--benign-dir", required=True)
    run_all_parser.add_argument("--backend", default="mock", choices=["mock", "replay", "openai"])
    run_all_parser.add_argument("--out", required=True)
    run_all_parser.set_defaults(func=cmd_run_all)

    baseline = sub.add_parser("baseline-topstrings", help="Generate deterministic topstrings baseline rules")
    baseline.add_argument("--selected", required=True)
    baseline.add_argument("--out", required=True)
    baseline.add_argument("--max-strings", type=int, default=8)
    baseline.set_defaults(func=cmd_baseline_topstrings)

    baseline_apiary = sub.add_parser(
        "baseline-apiary-static",
        help="Generate APIARY-inspired static discriminative import baseline rules",
    )
    baseline_apiary.add_argument("--features", required=True)
    baseline_apiary.add_argument("--splits", required=True)
    baseline_apiary.add_argument("--out", required=True)
    baseline_apiary.add_argument("--max-strings", type=int, default=8)
    baseline_apiary.add_argument("--min-score", type=float, default=0.0)
    baseline_apiary.set_defaults(func=cmd_baseline_apiary_static)

    baseline_eval = sub.add_parser(
        "baseline-eval",
        help="Generate and evaluate shipped baselines, then write a comparison table",
    )
    baseline_eval.add_argument("--manifest", required=True)
    baseline_eval.add_argument("--splits", required=True)
    baseline_eval.add_argument("--selected", required=True)
    baseline_eval.add_argument("--features", required=True)
    baseline_eval.add_argument("--out", required=True)
    baseline_eval.add_argument("--topstrings-max-strings", type=int, default=8)
    baseline_eval.add_argument("--apiary-max-strings", type=int, default=8)
    baseline_eval.add_argument("--apiary-min-score", type=float, default=0.0)
    baseline_eval.set_defaults(func=cmd_baseline_eval)

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
