from __future__ import annotations

import json
from typing import Any

from llmyara.llm.base import LLMBackend


class MockBackend(LLMBackend):
    def generate(self, prompt: str, metadata: dict[str, Any] | None = None) -> str:
        metadata = metadata or {}
        family = metadata.get("family", "unknown")
        features: list[str] = metadata.get("top_features", [])

        selected: list[str] = []
        imports: list[str] = []
        sections: list[str] = []
        for token in features:
            if token.startswith("imp:"):
                imports.append(token[4:])
            elif token.startswith("sec:"):
                sections.append(token[4:])
            elif token.startswith("str:"):
                val = token[4:]
                if 4 <= len(val) <= 40 and all(c.isprintable() for c in val):
                    selected.append(val)
            if len(selected) >= 5:
                break

        if not selected:
            selected = [f"{family}_marker"]

        payload = {
            "rule_name": f"llmyara_{family}",
            "meta": {
                "family": family,
                "author": "llmyara-mock",
                "description": "mock generated rule",
            },
            "strings": [
                {
                    "id": f"s{i+1}",
                    "value": val,
                    "nocase": True,
                    "wide": False,
                    "ascii": True,
                }
                for i, val in enumerate(selected)
            ],
            "imports": imports[:2],
            "sections": sections[:1],
            "min_strings": 2 if len(selected) >= 2 else 1,
            "import_mode": "any",
        }
        return json.dumps(payload, ensure_ascii=True)
