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


def _normalize_string_value(value: str) -> str:
    if value.startswith("str:"):
        return value[4:]
    return value


def _string_to_hex_bytes(value: str) -> str | None:
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return " ".join(f"{byte:02X}" for byte in value.encode("utf-8"))
    return None


def render_rule(payload: dict[str, Any]) -> str:
    for key in ("fixed_rule", "repaired_rule", "rule_text", "yara_rule"):
        raw_rule = payload.get(key)
        if isinstance(raw_rule, str) and raw_rule.strip():
            text = raw_rule.strip()
            return f"{text}\n"

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
        hex_bytes = item.get("hex_bytes")
        if isinstance(hex_bytes, str) and hex_bytes.strip():
            string_lines.append(f"        ${sid} = {{ {hex_bytes.strip()} }}")
            continue

        raw_value = _normalize_string_value(str(item.get("value", "")))
        derived_hex = _string_to_hex_bytes(raw_value)
        if derived_hex:
            string_lines.append(f"        ${sid} = {{ {derived_hex} }}")
            continue

        val = _escape_yara_string(raw_value)
        modifiers = []
        if item.get("ascii", True):
            modifiers.append("ascii")
        if item.get("wide", False):
            modifiers.append("wide")
        if item.get("nocase", True):
            modifiers.append("nocase")
        mods = " ".join(modifiers)
        string_lines.append(f'        ${sid} = "{val}" {mods}'.rstrip())

    lines = []
    if "pe." in condition:
        lines.append('import "pe"')
        lines.append("")
    lines.extend(
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
    return "\n".join(lines)
