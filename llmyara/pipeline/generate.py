from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from llmyara.config import AppConfig
from llmyara.llm.cache import PromptCache
from llmyara.llm.factory import build_backend
from llmyara.llm.prompts import generation_prompt, repair_prompt
from llmyara.yara.compile import compile_rule
from llmyara.yara.render import render_rule
from llmyara.yara.scan import scan_rule
from llmyara.yara.validate import RuleConstraints, validate_rule_text


def _extract_json_blob(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    while start != -1:
        depth = 0
        for idx in range(start, len(text)):
            if text[idx] == "{":
                depth += 1
            elif text[idx] == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start : idx + 1]
                    try:
                        obj = json.loads(candidate)
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)

    raise ValueError("LLM response does not contain a valid JSON object")


def _lookup_paths(manifest: list[dict[str, Any]], sample_ids: list[str]) -> list[str]:
    id_to_path = {row["sample_id"]: row["path"] for row in manifest}
    return [id_to_path[sid] for sid in sample_ids if sid in id_to_path]


def generate_rules(
    manifest: list[dict[str, Any]],
    splits: dict[str, Any],
    selected: dict[str, Any],
    cfg: AppConfig,
    backend_name: str,
    out_dir: str | Path,
    cache_path: str | Path,
) -> dict[str, Any]:
    out_dir = Path(out_dir)
    rules_dir = out_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)

    cache = PromptCache(cache_path)
    backend = build_backend(backend_name, cfg.llm, cache)

    constraints = RuleConstraints(
        max_strings=cfg.yara.max_strings,
        max_rule_bytes=cfg.yara.max_rule_bytes,
        max_condition_length=cfg.yara.max_condition_length,
    )

    family_results: dict[str, Any] = {}
    rule_paths: dict[str, str] = {}

    for family in splits["families"]:
        top_items = selected.get("families", {}).get(family, [])
        top_features = [item["feature"] for item in top_items[: cfg.selection.top_k_features]]

        prompt = generation_prompt(family=family, top_features=top_features, max_strings=cfg.yara.max_strings)
        prompt_source = "generated"

        cached = cache.get(prompt) if backend_name in {"mock", "openai"} else None
        if cached is not None:
            response = cached.response
            prompt_source = "cache"
        else:
            response = backend.generate(prompt, metadata={"family": family, "top_features": top_features})
            if backend_name in {"mock", "openai"}:
                cache.add(prompt, response, backend=backend_name, model=cfg.llm.model, metadata={"family": family})

        repairs = 0
        compile_error: str | None = None
        validation_errors: list[str] = []

        while True:
            try:
                payload = _extract_json_blob(response)
            except Exception as exc:
                compile_error = f"json_parse_failed:{exc}"
                payload = {
                    "rule_name": f"llmyara_{family}",
                    "meta": {"family": family, "author": "llmyara", "description": "fallback parse failure"},
                    "strings": [{"id": "s1", "value": family, "ascii": True, "nocase": True, "wide": False}],
                    "condition": "$s1",
                }

            rule_text = render_rule(payload)
            validation_errors = validate_rule_text(rule_text, constraints)
            compile_res = compile_rule(rule_text)
            compile_error = compile_res.error

            if compile_res.ok and not validation_errors:
                break

            if repairs >= cfg.yara.max_repairs:
                break

            repairs += 1
            repair = repair_prompt(previous_rule=rule_text, compiler_error=str(compile_error), max_strings=cfg.yara.max_strings)
            response = backend.generate(repair, metadata={"family": family, "top_features": top_features})
            if backend_name in {"mock", "openai"}:
                cache.add(repair, response, backend=backend_name, model=cfg.llm.model, metadata={"family": family, "repair": repairs})

        compile_res = compile_rule(rule_text)
        if not compile_res.ok or validation_errors:
            family_results[family] = {
                "status": "rejected",
                "reason": compile_res.error or ",".join(validation_errors),
                "repairs": repairs,
                "backend": backend_name,
                "model": cfg.llm.model,
                "prompt_source": prompt_source,
                "top_features": top_features,
            }
            rejected_path = rules_dir / f"{family}.rejected.yar"
            rejected_path.write_text(rule_text, encoding="utf-8")
            continue

        benign_paths = _lookup_paths(manifest, splits["global"]["benign_dev"])
        scan = scan_rule(rule_text, benign_paths)
        benign_fpr = len(scan.matches) / len(benign_paths) if benign_paths else 0.0

        if benign_fpr > cfg.yara.benign_dev_fpr_threshold:
            family_results[family] = {
                "status": "rejected",
                "reason": f"benign_dev_fpr_exceeded:{benign_fpr:.6f}",
                "repairs": repairs,
                "benign_dev_fpr": round(benign_fpr, 6),
                "backend": backend_name,
                "model": cfg.llm.model,
                "prompt_source": prompt_source,
                "top_features": top_features,
            }
            rejected_path = rules_dir / f"{family}.rejected.yar"
            rejected_path.write_text(rule_text, encoding="utf-8")
            continue

        rule_path = rules_dir / f"{family}.yar"
        rule_path.write_text(rule_text, encoding="utf-8")
        rule_paths[family] = str(rule_path)

        family_results[family] = {
            "status": "accepted",
            "repairs": repairs,
            "benign_dev_fpr": round(benign_fpr, 6),
            "rule_path": str(rule_path),
            "backend": backend_name,
            "model": cfg.llm.model,
            "prompt_source": prompt_source,
            "top_features": top_features,
        }

    return {
        "backend": backend_name,
        "model": cfg.llm.model,
        "cache_path": str(Path(cache_path).resolve()),
        "families": family_results,
        "rule_paths": rule_paths,
    }
