from __future__ import annotations

import json
import re
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


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _is_informative_string_feature(feature: str) -> bool:
    value = feature[4:].strip()
    if len(value) < 6:
        return False
    if value.lower().startswith("this program cannot be run"):
        return False
    if re.fullmatch(r"[a-z ]+", value):
        return False
    return True


def _curate_prompt_features(features: list[str], max_features: int) -> list[str]:
    imports: list[str] = []
    sections: list[str] = []
    strings: list[str] = []
    fallback_strings: list[str] = []

    for feature in features:
        if feature.startswith("imp:"):
            imports.append(feature)
            continue
        if feature.startswith("sec:"):
            section_name = feature[4:].strip()
            if re.fullmatch(r"[A-Za-z0-9._-]{1,16}", section_name):
                sections.append(f"sec:{section_name}")
            continue
        if feature.startswith("str:"):
            value = feature[4:].strip()
            if _is_informative_string_feature(feature):
                strings.append(f"str:{value}")
            elif len(value) >= 6:
                fallback_strings.append(f"str:{value}")

    curated = _dedupe(imports)[:6]
    remaining = max(max_features - len(curated), 0)
    curated.extend(_dedupe(sections)[: min(4, remaining)])
    remaining = max(max_features - len(curated), 0)
    curated.extend(_dedupe(strings)[:remaining])

    if not any(feature.startswith("str:") for feature in curated):
        remaining = max(max_features - len(curated), 0)
        curated.extend(_dedupe(fallback_strings)[:remaining])

    return curated[:max_features]


def _normalize_signal_token(value: Any, prefix: str) -> str | None:
    if isinstance(value, dict):
        if prefix == "imp:":
            dll = str(value.get("dll", "")).strip().lower()
            func = str(value.get("function", value.get("name", ""))).strip().lower()
            if dll and func:
                return f"{dll}!{func}"
            return None
        if prefix == "sec:":
            text = str(value.get("name", "")).strip()
            return text or None

    text = str(value).strip()
    if text.startswith(prefix):
        text = text[len(prefix) :].strip()
    if not text:
        return None
    return text


def _normalize_candidate_payload(payload: dict[str, Any], family: str, top_features: list[str], max_strings: int) -> dict[str, Any]:
    raw_rule_keys = ("fixed_rule", "repaired_rule", "rule_text", "yara_rule")
    if any(isinstance(payload.get(key), str) and str(payload.get(key)).strip() for key in raw_rule_keys):
        return payload

    allowed_strings = [feature[4:] for feature in top_features if feature.startswith("str:")]
    allowed_imports = [feature[4:] for feature in top_features if feature.startswith("imp:")]
    allowed_sections = [feature[4:] for feature in top_features if feature.startswith("sec:")]

    allowed_string_set = set(allowed_strings)
    allowed_import_set = set(allowed_imports)
    allowed_section_set = set(allowed_sections)
    grounded_string_fallbacks = {
        part
        for token in allowed_imports
        for part in token.split("!")
        if part
    }

    normalized_strings: list[dict[str, Any]] = []
    for index, item in enumerate(payload.get("strings", []) or [], start=1):
        value = _normalize_signal_token(item.get("value", ""), "str:")
        if value is None:
            continue
        if allowed_string_set and value not in allowed_string_set:
            continue
        if not allowed_string_set:
            if grounded_string_fallbacks and value.lower() not in grounded_string_fallbacks:
                continue
            if not grounded_string_fallbacks and top_features:
                continue
            if not (4 <= len(value) <= 120 and all(ch.isprintable() for ch in value)):
                continue
        normalized_strings.append(
            {
                "id": str(item.get("id", f"s{index}")),
                "value": value,
                "ascii": bool(item.get("ascii", True)),
                "wide": bool(item.get("wide", False)),
                "nocase": bool(item.get("nocase", True)),
            }
        )

    if not normalized_strings and allowed_strings:
        for index, value in enumerate(allowed_strings[: min(max_strings, 6)], start=1):
            normalized_strings.append(
                {
                    "id": f"s{index}",
                    "value": value,
                    "ascii": True,
                    "wide": False,
                    "nocase": True,
                }
            )

    normalized_imports: list[str] = []
    for item in payload.get("imports", []) or []:
        token = _normalize_signal_token(item, "imp:")
        if token is None:
            continue
        if not allowed_import_set:
            continue
        if token not in allowed_import_set:
            continue
        normalized_imports.append(token)

    normalized_sections: list[str] = []
    for item in payload.get("sections", []) or []:
        token = _normalize_signal_token(item, "sec:")
        if token is None:
            continue
        if not allowed_section_set:
            continue
        if token not in allowed_section_set:
            continue
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,16}", token):
            continue
        normalized_sections.append(token)

    min_strings = payload.get("min_strings", payload.get("string_threshold"))

    normalized_payload: dict[str, Any] = {
        "rule_name": str(payload.get("rule_name", f"llmyara_{family}")),
        "meta": {
            "family": family,
            "author": str((payload.get("meta", {}) or {}).get("author", "llmyara")),
            "description": str((payload.get("meta", {}) or {}).get("description", f"{family} structured candidate")),
        },
        "strings": normalized_strings[:max_strings],
        "auto_condition": True,
        "min_strings": min_strings if min_strings is not None else (2 if len(normalized_strings) >= 2 else 1),
    }

    if normalized_imports:
        normalized_payload["imports"] = _dedupe(normalized_imports)[:3]
        normalized_payload["require_pe"] = True
        normalized_payload["import_mode"] = str(payload.get("import_mode", "any"))

    if normalized_sections:
        normalized_payload["sections"] = _dedupe(normalized_sections)[:2]
        normalized_payload["require_pe"] = True

    return normalized_payload


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
        raw_top_features = [item["feature"] for item in top_items[: cfg.selection.top_k_features]]
        top_features = _curate_prompt_features(raw_top_features, cfg.selection.top_k_features)
        family_split = splits["families"][family]
        train_target_paths = _lookup_paths(manifest, family_split["train_target"])
        benign_paths = _lookup_paths(manifest, splits["global"]["benign_dev"])

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
        accepted = False
        benign_fpr: float | None = None
        train_target_hits = 0
        failure_reason: str | None = None

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

            payload = _normalize_candidate_payload(payload, family=family, top_features=top_features, max_strings=cfg.yara.max_strings)
            rule_text = render_rule(payload)
            validation_errors = validate_rule_text(rule_text, constraints)
            compile_res = compile_rule(rule_text)
            compile_error = compile_res.error

            if not compile_res.ok or validation_errors:
                failure_reason = compile_res.error or ",".join(validation_errors)
            else:
                train_scan = scan_rule(rule_text, train_target_paths)
                train_target_hits = len(train_scan.matches)
                if train_target_paths and train_target_hits < cfg.yara.min_train_target_hits:
                    failure_reason = f"train_target_hits_below_min:{train_target_hits}<{cfg.yara.min_train_target_hits}"
                else:
                    scan = scan_rule(rule_text, benign_paths)
                    benign_fpr = len(scan.matches) / len(benign_paths) if benign_paths else 0.0
                    if benign_fpr > cfg.yara.benign_dev_fpr_threshold:
                        failure_reason = f"benign_dev_fpr_exceeded:{benign_fpr:.6f}"
                    else:
                        accepted = True
                        failure_reason = None
                        break

            if repairs >= cfg.yara.max_repairs:
                break

            repairs += 1
            repair = repair_prompt(
                previous_rule=rule_text,
                failure_reason=str(failure_reason),
                max_strings=cfg.yara.max_strings,
                top_features=top_features,
            )
            response = backend.generate(repair, metadata={"family": family, "top_features": top_features})
            if backend_name in {"mock", "openai"}:
                cache.add(repair, response, backend=backend_name, model=cfg.llm.model, metadata={"family": family, "repair": repairs})

        if not accepted:
            family_results[family] = {
                "status": "rejected",
                "reason": failure_reason or compile_error or ",".join(validation_errors),
                "repairs": repairs,
                "benign_dev_fpr": round(benign_fpr, 6) if benign_fpr is not None else None,
                "train_target_hits": train_target_hits,
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
            "train_target_hits": train_target_hits,
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
