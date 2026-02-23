from __future__ import annotations

from pathlib import Path
from typing import Any

from llmyara.yara.render import render_rule


def generate_topstrings_rule(family: str, selected_features: list[dict[str, Any]], max_strings: int = 8) -> str:
    strings: list[dict[str, Any]] = []
    for item in selected_features:
        token = item.get("feature", "")
        if not isinstance(token, str):
            continue
        if not token.startswith("str:"):
            continue
        value = token[4:]
        if len(value) < 4:
            continue
        strings.append(
            {
                "id": f"s{len(strings)+1}",
                "value": value,
                "nocase": True,
                "ascii": True,
                "wide": False,
            }
        )
        if len(strings) >= max_strings:
            break

    if not strings:
        strings = [
            {
                "id": "s1",
                "value": family,
                "nocase": True,
                "ascii": True,
                "wide": False,
            }
        ]

    payload = {
        "rule_name": f"baseline_topstrings_{family}",
        "meta": {
            "family": family,
            "author": "baseline-topstrings",
            "description": "deterministic top-string baseline",
        },
        "strings": strings,
        "condition": "2 of them" if len(strings) >= 2 else "$s1",
    }
    return render_rule(payload)


def write_baseline_rules(selected: dict[str, Any], out_dir: str | Path, max_strings: int = 8) -> dict[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    for family, features in selected.get("families", {}).items():
        rule_text = generate_topstrings_rule(family, features, max_strings=max_strings)
        path = out / f"{family}.yar"
        path.write_text(rule_text, encoding="utf-8")
        paths[family] = str(path)
    return paths
