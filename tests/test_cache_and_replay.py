from __future__ import annotations

from pathlib import Path

from llmyara.llm.cache import PromptCache
from llmyara.llm.replay_backend import ReplayBackend


def test_cache_roundtrip(tmp_path: Path) -> None:
    cache = PromptCache(tmp_path / "cache.jsonl")
    cache.add("p", "r", backend="mock", model="mock")
    row = cache.get("p")
    assert row is not None
    assert row.response == "r"


def test_replay_backend_uses_cache(tmp_path: Path) -> None:
    cache = PromptCache(tmp_path / "cache.jsonl")
    cache.add("prompt", "response", backend="mock", model="mock")
    backend = ReplayBackend(cache)
    assert backend.generate("prompt") == "response"


def test_replay_backend_cache_miss_reports_hash_and_path(tmp_path: Path) -> None:
    cache = PromptCache(tmp_path / "cache.jsonl")
    backend = ReplayBackend(cache)
    try:
        backend.generate("missing-prompt")
    except RuntimeError as exc:
        message = str(exc)
        assert "prompt_hash=" in message
        assert str(cache.path) in message
    else:
        raise AssertionError("expected replay cache miss")
