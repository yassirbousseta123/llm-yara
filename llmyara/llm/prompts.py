from __future__ import annotations

import json
from typing import Sequence


def generation_prompt(family: str, top_features: Sequence[str], max_strings: int) -> str:
    schema = {
        "rule_name": "string",
        "meta": {
            "family": "string",
            "author": "string",
            "description": "string",
        },
        "strings": [
            {
                "id": "a1",
                "value": "string literal",
                "nocase": True,
                "wide": False,
                "ascii": True,
            }
        ],
        "imports": ["kernel32.dll!sleep"],
        "sections": [".text"],
        "min_strings": 1,
        "import_mode": "any",
    }

    return (
        "Generate a strict JSON object for a structured YARA rule candidate.\n"
        "No markdown. No prose. JSON only.\n"
        f"Target malware family: {family}\n"
        f"Use at most {max_strings} strings.\n"
        "Use only the given discriminative signals and avoid generic tokens.\n"
        "Interpret prefixes carefully: `str:` values are literal strings; emit them without the prefix inside `strings`.\n"
        "Use `imports` only for selected `imp:` hints. Use `sections` only for selected `sec:` hints.\n"
        "Do not emit a freeform `condition` field. The renderer builds the final condition from `strings`, `imports`, `sections`, `min_strings`, and `import_mode`.\n"
        "Choose short, high-signal subsets. Avoid generic catch-all strings.\n"
        f"Top signals: {json.dumps(list(top_features), ensure_ascii=True)}\n"
        f"Required schema: {json.dumps(schema, ensure_ascii=True)}\n"
        "Return only fields from the schema. Omit `imports` or `sections` if none apply.\n"
    )


def repair_prompt(previous_rule: str, failure_reason: str, max_strings: int, top_features: Sequence[str]) -> str:
    return (
        "You are repairing a weak or invalid structured YARA candidate. Return strict JSON only.\n"
        f"Failure reason: {failure_reason}\n"
        f"Current invalid rule:\n{previous_rule}\n"
        f"Top signals: {json.dumps(list(top_features), ensure_ascii=True)}\n"
        f"Keep at most {max_strings} strings. Preserve intent while fixing syntax/semantics.\n"
        "Return the same structured schema as generation: `strings`, optional `imports`, optional `sections`, `min_strings`, `import_mode`.\n"
        "Do not return raw YARA text unless strictly necessary. Increase target specificity and reduce benign matches.\n"
    )
