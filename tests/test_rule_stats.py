from __future__ import annotations

from llmyara.yara.stats import rule_statistics


def test_rule_statistics_counts_strings_and_condition_clauses() -> None:
    rule_text = """
import "pe"

rule sample_rule {
    strings:
        $s1 = "alpha" ascii nocase
        $s2 = "beta" ascii nocase
    condition:
        uint16(0) == 0x5A4D and pe.imports("kernel32.dll", "createfilew") and 1 of them
}
""".strip()

    stats = rule_statistics(rule_text)

    assert stats["rule_string_count"] == 2
    assert stats["condition_clause_count"] == 3
    assert stats["rule_complexity"] == 5
    assert stats["rule_bytes"] > 0
