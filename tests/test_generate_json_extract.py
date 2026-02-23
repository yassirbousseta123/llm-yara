from __future__ import annotations

from llmyara.pipeline.generate import _extract_json_blob


def test_extract_json_blob_direct_json() -> None:
    obj = _extract_json_blob('{"a": 1}')
    assert obj["a"] == 1


def test_extract_json_blob_wrapped_text() -> None:
    obj = _extract_json_blob('text before {"rule_name":"x","strings":[],"condition":"false"} text after')
    assert obj["rule_name"] == "x"
