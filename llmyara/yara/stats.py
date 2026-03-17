from __future__ import annotations

import re


def extract_condition_text(rule_text: str) -> str:
    marker = "condition:"
    idx = rule_text.find(marker)
    if idx == -1:
        return ""

    condition_text = rule_text[idx + len(marker) :].strip()
    if condition_text.endswith("}"):
        condition_text = condition_text[:-1].rstrip()
    return condition_text


def rule_statistics(rule_text: str) -> dict[str, int]:
    lines = rule_text.splitlines()
    string_lines = [line for line in lines if line.strip().startswith("$")]
    condition_text = extract_condition_text(rule_text)

    condition_clause_count = 0
    condition_clause_count += len(re.findall(r"\$[A-Za-z0-9_]+", condition_text))
    condition_clause_count += len(re.findall(r'pe\.imports\(', condition_text))
    condition_clause_count += len(re.findall(r"pe\.sections\[", condition_text))
    condition_clause_count += 1 if "uint16(0) == 0x5A4D" in condition_text else 0
    condition_clause_count += len(re.findall(r"\b(?:all|\d+)\s+of\s+them\b", condition_text))

    if condition_text and condition_clause_count == 0:
        condition_clause_count = 1

    rule_string_count = len(string_lines)
    rule_bytes = len(rule_text.encode("utf-8"))
    condition_length = len(condition_text)

    return {
        "rule_string_count": rule_string_count,
        "condition_clause_count": condition_clause_count,
        "rule_complexity": rule_string_count + condition_clause_count,
        "rule_bytes": rule_bytes,
        "condition_length": condition_length,
    }
