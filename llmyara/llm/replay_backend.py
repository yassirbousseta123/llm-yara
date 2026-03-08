from __future__ import annotations

from typing import Any

from llmyara.llm.base import LLMBackend
from llmyara.llm.cache import PromptCache
from llmyara.utils.hashing import sha256_text


class ReplayBackend(LLMBackend):
    def __init__(self, cache: PromptCache) -> None:
        self.cache = cache

    def generate(self, prompt: str, metadata: dict[str, Any] | None = None) -> str:
        row = self.cache.get(prompt)
        if row is None:
            raise RuntimeError(
                f"Replay cache miss for prompt_hash={sha256_text(prompt)} cache={self.cache.path}"
            )
        return row.response
