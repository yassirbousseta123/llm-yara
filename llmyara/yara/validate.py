from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleConstraints:
    max_strings: int
    max_rule_bytes: int
    max_condition_length: int


def validate_rule_text(rule_text: str, constraints: RuleConstraints) -> list[str]:
    errors: list[str] = []

    lines = rule_text.splitlines()
    string_lines = [line for line in lines if line.strip().startswith("$")]
    if len(string_lines) > constraints.max_strings:
        errors.append(f"too_many_strings:{len(string_lines)}>{constraints.max_strings}")

    if len(rule_text.encode("utf-8")) > constraints.max_rule_bytes:
        errors.append("rule_too_large")

    cond_marker = "condition:"
    idx = rule_text.find(cond_marker)
    if idx != -1:
        condition_text = rule_text[idx + len(cond_marker):].strip()
        if len(condition_text) > constraints.max_condition_length:
            errors.append("condition_too_long")
        if condition_text == "false":
            errors.append("always_false_condition")

    if "strings:" in rule_text and not string_lines:
        errors.append("no_strings_declared")

    return errors
