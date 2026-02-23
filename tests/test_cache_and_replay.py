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
