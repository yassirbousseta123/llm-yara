from __future__ import annotations

from llmyara.config import LLMConfig
from llmyara.llm.base import LLMBackend
from llmyara.llm.cache import PromptCache
from llmyara.llm.mock_backend import MockBackend
from llmyara.llm.openai_backend import OpenAIBackend
from llmyara.llm.replay_backend import ReplayBackend


def build_backend(name: str, cfg: LLMConfig, cache: PromptCache) -> LLMBackend:
    normalized = name.strip().lower()
    if normalized == "mock":
        return MockBackend()
    if normalized == "replay":
        return ReplayBackend(cache)
    if normalized == "openai":
        return OpenAIBackend(model=cfg.model, temperature=cfg.temperature, timeout_seconds=cfg.timeout_seconds)
    raise ValueError(f"Unsupported backend: {name}")
