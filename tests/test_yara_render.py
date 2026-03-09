from __future__ import annotations

from llmyara.yara.render import render_rule


def test_render_rule_supports_hex_strings() -> None:
    rule = render_rule(
        {
            "rule_name": "hex_rule",
            "meta": {"family": "fam_a"},
            "strings": [{"id": "s1", "hex_bytes": "4D 41 4C 57 41 52 45 21"}],
            "condition": "$s1",
        }
    )

    assert "$s1 = { 4D 41 4C 57 41 52 45 21 }" in rule


def test_render_rule_preserves_prompt_string_ids() -> None:
    rule = render_rule(
        {
            "rule_name": "id_rule",
            "meta": {"family": "fam_a"},
            "strings": [{"id": "a1", "value": "abcd", "ascii": True, "wide": False, "nocase": True}],
            "condition": "$a1",
        }
    )

    assert '$a1 = "abcd" ascii nocase' in rule
    assert "condition:\n        $a1" in rule


def test_render_rule_returns_fixed_rule_directly() -> None:
    fixed_rule = 'rule repaired {\n    condition:\n        false\n}'
    assert render_rule({"fixed_rule": fixed_rule}) == f"{fixed_rule}\n"


def test_render_rule_returns_repaired_rule_directly() -> None:
    repaired_rule = 'rule repaired {\n    meta:\n        author = "x"\n    condition:\n        false\n}'
    assert render_rule({"repaired_rule": repaired_rule}) == f"{repaired_rule}\n"


def test_render_rule_strips_string_prefix_and_null_bytes() -> None:
    rule = render_rule(
        {
            "rule_name": "norm_rule",
            "meta": {"family": "fam_a"},
            "strings": [
                {"id": "a1", "value": "str:mutex_red", "ascii": True, "wide": False, "nocase": True},
                {"id": "a2", "value": "\x00", "ascii": True, "wide": False, "nocase": False},
            ],
            "condition": "$a1 and $a2",
        }
    )

    assert '$a1 = "mutex_red" ascii nocase' in rule
    assert "$a2 = { 00 }" in rule


def test_render_rule_adds_pe_import_when_condition_uses_pe_module() -> None:
    rule = render_rule(
        {
            "rule_name": "pe_rule",
            "meta": {"family": "fam_a"},
            "strings": [{"id": "a1", "value": "str:mutex_red", "ascii": True, "wide": False, "nocase": True}],
            "condition": 'pe.imports("kernel32.dll", "lstrcpy") and $a1',
        }
    )

    assert rule.startswith('import "pe"\n\nrule pe_rule')
