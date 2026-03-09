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
        "condition": "string",
    }

    return (
        "Generate a strict JSON object for a YARA rule candidate.\n"
        "No markdown. No prose. JSON only.\n"
        f"Target malware family: {family}\n"
        f"Use at most {max_strings} strings.\n"
        "Use only the given discriminative signals and avoid generic tokens.\n"
        "Interpret prefixes carefully: `str:` values are literal file strings and must be emitted without the `str:` prefix.\n"
        "Do not emit `imp:` or `sec:` hints as literal strings; use them in the YARA `pe` module condition only if needed.\n"
        "Never return `condition: false`. Avoid generic catch-all rules like `N of ($a*)` over common words.\n"
        f"Top signals: {json.dumps(list(top_features), ensure_ascii=True)}\n"
        f"Required schema: {json.dumps(schema, ensure_ascii=True)}\n"
        "Condition must be safe and concise; avoid filesize-only logic.\n"
    )


def repair_prompt(previous_rule: str, compiler_error: str, max_strings: int) -> str:
    return (
        "You are repairing an invalid YARA candidate. Return strict JSON only.\n"
        f"Compiler error: {compiler_error}\n"
        f"Current invalid rule:\n{previous_rule}\n"
        f"Keep at most {max_strings} strings. Preserve intent while fixing syntax/semantics.\n"
    )
