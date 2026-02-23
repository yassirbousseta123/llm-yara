from __future__ import annotations

import re
from typing import Any


def sanitize_identifier(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", text)
    if not cleaned:
        cleaned = "llmyara_rule"
    if cleaned[0].isdigit():
        cleaned = f"r_{cleaned}"
    return cleaned


def _escape_yara_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return escaped


def render_rule(payload: dict[str, Any]) -> str:
    rule_name = sanitize_identifier(str(payload.get("rule_name", "llmyara_rule")))
    meta = payload.get("meta", {}) or {}
    strings = payload.get("strings", []) or []
    condition = str(payload.get("condition", "false"))

    meta_lines = []
    for key, value in sorted(meta.items()):
        key_clean = sanitize_identifier(str(key))
        meta_lines.append(f'        {key_clean} = "{_escape_yara_string(str(value))}"')

    string_lines = []
    for item in strings:
        sid = sanitize_identifier(str(item.get("id", "s")))
        if not sid.startswith("s"):
            sid = f"s_{sid}"
        val = _escape_yara_string(str(item.get("value", "")))
        modifiers = []
        if item.get("ascii", True):
            modifiers.append("ascii")
        if item.get("wide", False):
            modifiers.append("wide")
        if item.get("nocase", True):
            modifiers.append("nocase")
        mods = " ".join(modifiers)
        string_lines.append(f'        ${sid} = "{val}" {mods}'.rstrip())

    return "\n".join(
        [
            f"rule {rule_name} {{",
            "    meta:",
            *meta_lines,
            "    strings:",
            *string_lines,
            "    condition:",
            f"        {condition}",
            "}",
            "",
        ]
    )
