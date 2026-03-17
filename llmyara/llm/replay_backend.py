from __future__ import annotations

from typing import Any

from llmyara.llm.base import LLMBackend
from llmyara.llm.cache import PromptCache
from llmyara.utils.hashing import sha256_text


class ReplayBackend(LLMBackend):
    def __init__(
        self,
        cache: PromptCache,
        *,
        source_backend: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
    ) -> None:
        self.cache = cache
        self.source_backend = source_backend
        self.model = model
        self.base_url = base_url

    def generate(self, prompt: str, metadata: dict[str, Any] | None = None) -> str:
        row = self.cache.get(
            prompt,
            backend=self.source_backend,
            model=self.model,
            base_url=self.base_url,
        )
        if row is None:
            raise RuntimeError(
                "Replay cache miss for "
                f"prompt_hash={sha256_text(prompt)} cache={self.cache.path} "
                f"backend={self.source_backend or 'any'} model={self.model or 'any'} "
                f"base_url={self.base_url or ''}"
            )
        return row.response
