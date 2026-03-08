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
