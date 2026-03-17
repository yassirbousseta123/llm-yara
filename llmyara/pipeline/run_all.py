from __future__ import annotations

from dataclasses import asdict
import os
from pathlib import Path
from typing import Any

from llmyara.config import AppConfig
from llmyara.data.indexer import build_manifest
from llmyara.data.splits import build_splits
from llmyara.eval.evaluate import evaluate_rules, write_results_csv
from llmyara.eval.reports import write_summary_markdown
from llmyara.features.extract import extract_features
from llmyara.pipeline.generate import generate_rules
from llmyara.selection.score import select_all_families
from llmyara.utils.files import ensure_dir, write_json
from llmyara.utils.provenance import build_provenance, file_hashes
from llmyara.utils.jsonl import write_jsonl
from llmyara.yara.compile import is_yara_available


def run_all(
    cfg: AppConfig,
    malware_dir: str,
    benign_dir: str,
    out_dir: str | Path,
    backend_name: str,
) -> dict[str, Any]:
    if not is_yara_available():
        raise RuntimeError("yara-python is required for generate/evaluate stages. Install with .[runtime] or use Docker.")

    out_dir = ensure_dir(out_dir)

    manifest = build_manifest(malware_dir, benign_dir)
    write_jsonl(out_dir / "manifest.jsonl", manifest)

    splits = build_splits(
        manifest=manifest,
        seed=cfg.seed,
        test_ratio=cfg.split.test_ratio,
        benign_dev_ratio=cfg.split.benign_dev_ratio,
        min_family_size=cfg.split.min_family_size,
    )
    write_json(out_dir / "splits.json", splits)

    features = extract_features(manifest, cfg.features)
    write_jsonl(out_dir / "features.jsonl", features)

    selected = select_all_families(features, splits, top_k=cfg.selection.top_k_features)
    write_json(out_dir / "selected_features.json", selected)

    generation = generate_rules(
        manifest=manifest,
        splits=splits,
        selected=selected,
        cfg=cfg,
        backend_name=backend_name,
        out_dir=out_dir,
        cache_path=out_dir / "llm_cache.jsonl",
    )
    write_json(out_dir / "generation_summary.json", generation)

    eval_rows, eval_summary = evaluate_rules(
        manifest=manifest,
        splits=splits,
        rule_paths=generation["rule_paths"],
    )
    write_results_csv(out_dir / "results_per_family.csv", eval_rows)
    write_json(out_dir / "summary.json", eval_summary)
    write_summary_markdown(out_dir / "summary.md", eval_rows, eval_summary)

    artifacts = {
        "manifest": str((out_dir / "manifest.jsonl").resolve()),
        "splits": str((out_dir / "splits.json").resolve()),
        "features": str((out_dir / "features.jsonl").resolve()),
        "selected": str((out_dir / "selected_features.json").resolve()),
        "generation": str((out_dir / "generation_summary.json").resolve()),
        "llm_cache": str((out_dir / "llm_cache.jsonl").resolve()),
        "results_csv": str((out_dir / "results_per_family.csv").resolve()),
        "summary_json": str((out_dir / "summary.json").resolve()),
        "summary_markdown": str((out_dir / "summary.md").resolve()),
    }
    write_json(
        out_dir / "run_manifest.json",
        {
            "config": asdict(cfg),
            "backend": backend_name,
            "model": cfg.llm.model,
            "openai_base_url": os.getenv("OPENAI_BASE_URL") or None,
            "malware_dir": malware_dir,
            "benign_dir": benign_dir,
            "output_dir": str(Path(out_dir).resolve()),
            "llm_cache": artifacts["llm_cache"],
            "provenance": build_provenance(
                backend=backend_name,
                model=cfg.llm.model,
                base_url=os.getenv("OPENAI_BASE_URL") or None,
                cwd=Path(__file__).resolve().parents[2],
            ),
            "artifact_hashes": file_hashes(artifacts),
        },
    )

    return {
        "output_dir": str(Path(out_dir).resolve()),
        "families": len(splits["families"]),
        "families_with_rules": len(generation["rule_paths"]),
        "summary": eval_summary,
        "artifacts": {
            **artifacts,
            "run_manifest": str((out_dir / "run_manifest.json").resolve()),
        },
    }
