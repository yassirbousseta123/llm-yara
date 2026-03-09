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


def _normalize_import_token(value: Any) -> str | None:
    if isinstance(value, dict):
        dll = str(value.get("dll", "")).strip().lower()
        func = str(value.get("function", value.get("name", ""))).strip().lower()
        if dll and func:
            return f"{dll}!{func}"
        return None

    text = str(value).strip().lower()
    if text.startswith("imp:"):
        text = text[4:]
    if "!" not in text:
        return None
    dll, func = text.split("!", 1)
    if not dll or not func:
        return None
    return f"{dll}!{func}"


def _normalize_section_name(value: Any) -> str | None:
    text = str(value).strip()
    if text.startswith("sec:"):
        text = text[4:].strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,16}", text):
        return None
    return text


def _clamp_match_count(value: Any, size: int) -> int:
    if size <= 0:
        return 0
    try:
        count = int(value)
    except (TypeError, ValueError):
        count = 2 if size >= 2 else 1
    return max(1, min(size, count))


def _build_auto_condition(payload: dict[str, Any], string_count: int) -> str:
    imports = []
    for item in payload.get("imports", []) or []:
        token = _normalize_import_token(item)
        if token is not None:
            imports.append(token)

    sections = []
    for item in payload.get("sections", []) or []:
        name = _normalize_section_name(item)
        if name is not None:
            sections.append(name)

    clauses: list[str] = []
    if imports or sections or payload.get("require_pe"):
        clauses.append("uint16(0) == 0x5A4D")

    if imports:
        expressions = []
        for token in dict.fromkeys(imports):
            dll, func = token.split("!", 1)
            expressions.append(f'pe.imports("{_escape_yara_string(dll)}", "{_escape_yara_string(func)}")')

        import_mode = str(payload.get("import_mode", "any")).strip().lower()
        joiner = " and " if import_mode == "all" else " or "
        clauses.append(f"({joiner.join(expressions)})")

    if sections:
        section_checks = " or ".join(
            f'pe.sections[i].name == "{_escape_yara_string(name)}"' for name in dict.fromkeys(sections)
        )
        clauses.append(f"for any i in (0..pe.number_of_sections - 1) : ( {section_checks} )")

    if string_count > 0:
        min_strings = _clamp_match_count(payload.get("min_strings"), string_count)
        if min_strings >= string_count:
            clauses.append("all of them")
        else:
            clauses.append(f"{min_strings} of them")

    return " and ".join(clauses) if clauses else str(payload.get("condition", "false"))


def render_rule(payload: dict[str, Any]) -> str:
    for key in ("fixed_rule", "repaired_rule", "rule_text", "yara_rule"):
        raw_rule = payload.get(key)
        if isinstance(raw_rule, str) and raw_rule.strip():
            text = raw_rule.strip()
            return f"{text}\n"

    rule_name = sanitize_identifier(str(payload.get("rule_name", "llmyara_rule")))
    meta = payload.get("meta", {}) or {}
    strings = payload.get("strings", []) or []
    condition = _build_auto_condition(payload, len(strings)) if payload.get("auto_condition") else str(payload.get("condition", "false"))

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
