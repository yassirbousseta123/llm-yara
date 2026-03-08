from __future__ import annotations

from pathlib import Path

import pytest

from llmyara.config import AppConfig
from llmyara.pipeline import generate as generate_mod


class _FakeBackend:
    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)

    def generate(self, prompt: str, metadata: dict[str, object] | None = None) -> str:
        assert prompt
        return self._responses.pop(0)


def _cfg() -> AppConfig:
    return AppConfig()


def test_generate_rules_accepts_fallback_when_json_parse_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _FakeBackend(["not-json"])
    monkeypatch.setattr(generate_mod, "build_backend", lambda name, cfg, cache: backend)
    monkeypatch.setattr(generate_mod, "compile_rule", lambda rule_text: type("Compile", (), {"ok": True, "error": None})())
    monkeypatch.setattr(
        generate_mod,
        "scan_rule",
        lambda rule_text, file_paths: type("Scan", (), {"matches": [], "elapsed_seconds": 0.0})(),
    )

    result = generate_mod.generate_rules(
        manifest=[],
        splits={"families": {"fam_a": {"train_target": [], "test_target": [], "train_other": [], "test_other": []}}, "global": {"benign_dev": []}},
        selected={"families": {"fam_a": []}},
        cfg=_cfg(),
        backend_name="mock",
        out_dir=tmp_path,
        cache_path=tmp_path / "llm_cache.jsonl",
    )

    family = result["families"]["fam_a"]
    assert family["status"] == "accepted"
    assert family["prompt_source"] == "generated"
    assert Path(family["rule_path"]).exists()
    assert result["cache_path"].endswith("llm_cache.jsonl")


def test_generate_rules_repairs_after_initial_compile_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _FakeBackend(
        [
            '{"rule_name":"llmyara_fam_a","meta":{"family":"fam_a","author":"x","description":"x"},"strings":[{"id":"s1","value":"abcd","ascii":true,"wide":false,"nocase":true}],"condition":"invalid syntax"}',
            '{"rule_name":"llmyara_fam_a","meta":{"family":"fam_a","author":"x","description":"x"},"strings":[{"id":"s1","value":"abcd","ascii":true,"wide":false,"nocase":true}],"condition":"$s1"}',
        ]
    )
    monkeypatch.setattr(generate_mod, "build_backend", lambda name, cfg, cache: backend)

    compile_calls = {"count": 0}

    def fake_compile(rule_text: str) -> object:
        compile_calls["count"] += 1
        ok = "condition:\n        $s1" in rule_text
        error = None if ok else "syntax error"
        return type("Compile", (), {"ok": ok, "error": error})()

    monkeypatch.setattr(generate_mod, "compile_rule", fake_compile)
    monkeypatch.setattr(
        generate_mod,
        "scan_rule",
        lambda rule_text, file_paths: type("Scan", (), {"matches": [], "elapsed_seconds": 0.0})(),
    )

    result = generate_mod.generate_rules(
        manifest=[],
        splits={"families": {"fam_a": {"train_target": [], "test_target": [], "train_other": [], "test_other": []}}, "global": {"benign_dev": []}},
        selected={"families": {"fam_a": [{"feature": "str:abcd", "score": 1.0}]}},
        cfg=_cfg(),
        backend_name="mock",
        out_dir=tmp_path,
        cache_path=tmp_path / "llm_cache.jsonl",
    )

    assert compile_calls["count"] >= 2
    assert result["families"]["fam_a"]["status"] == "accepted"
    assert result["families"]["fam_a"]["repairs"] == 1
