from __future__ import annotations

from dataclasses import asdict
import os
from pathlib import Path
from typing import Any

from llmyara.config import AppConfig
from llmyara.eval.compare_all import compare_all_methods
from llmyara.pipeline.run_all import run_all
from llmyara.utils.files import write_json
from llmyara.utils.provenance import build_provenance, file_hashes
from llmyara.utils.jsonl import read_jsonl


def run_all_compare(
    *,
    cfg: AppConfig,
    malware_dir: str,
    benign_dir: str,
    out_dir: str | Path,
    backend_name: str,
    topstrings_max_strings: int,
    apiary_max_strings: int,
    apiary_min_score: float,
    autoyara_max_strings: int,
    autoyara_min_score: float,
    autoyara_ngram_sizes: tuple[int, ...],
) -> dict[str, Any]:
    run_result = run_all(
        cfg=cfg,
        malware_dir=malware_dir,
        benign_dir=benign_dir,
        out_dir=out_dir,
        backend_name=backend_name,
    )

    artifacts = run_result["artifacts"]
    comparison = compare_all_methods(
        manifest=list(read_jsonl(artifacts["manifest"])),
        splits=read_json_like(artifacts["splits"]),
        selected=read_json_like(artifacts["selected"]),
        features=list(read_jsonl(artifacts["features"])),
        generation=read_json_like(artifacts["generation"]),
        out_dir=Path(out_dir) / "comparison",
        topstrings_max_strings=topstrings_max_strings,
        apiary_max_strings=apiary_max_strings,
        apiary_min_score=apiary_min_score,
        autoyara_max_strings=autoyara_max_strings,
        autoyara_min_score=autoyara_min_score,
        autoyara_ngram_sizes=autoyara_ngram_sizes,
    )

    hash_inputs = {
        "comparison_csv": comparison["comparison_csv"],
        "comparison_json": comparison["comparison_json"],
        "comparison_markdown": comparison["comparison_markdown"],
        "significance_json": comparison["significance_json"],
        "failure_analysis_json": comparison["failure_analysis_json"],
    }
    run_manifest_path = run_result["artifacts"].get("run_manifest")
    if run_manifest_path:
        hash_inputs["run_manifest"] = run_manifest_path

    manifest = {
        "config": asdict(cfg),
        "backend": backend_name,
        "model": cfg.llm.model,
        "openai_base_url": os.getenv("OPENAI_BASE_URL") or None,
        "malware_dir": malware_dir,
        "benign_dir": benign_dir,
        "output_dir": str(Path(out_dir).resolve()),
        "comparison": {
            "output_dir": comparison["output_dir"],
            "comparison_csv": comparison["comparison_csv"],
            "comparison_json": comparison["comparison_json"],
            "comparison_markdown": comparison["comparison_markdown"],
        },
        "provenance": build_provenance(
            backend=backend_name,
            model=cfg.llm.model,
            base_url=os.getenv("OPENAI_BASE_URL") or None,
            cwd=Path(__file__).resolve().parents[2],
        ),
        "artifact_hashes": file_hashes(hash_inputs),
    }
    manifest_path = Path(out_dir) / "comparison_run_manifest.json"
    write_json(manifest_path, manifest)

    return {
        "run_all": run_result,
        "comparison": comparison,
        "comparison_run_manifest": str(manifest_path.resolve()),
    }


def read_json_like(path: str | Path) -> dict[str, Any]:
    import json

    return json.loads(Path(path).read_text(encoding="utf-8"))
