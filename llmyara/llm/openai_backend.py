from __future__ import annotations

import os
from typing import Any

from llmyara.llm.base import LLMBackend


class OpenAIBackend(LLMBackend):
    def __init__(self, model: str, temperature: float, timeout_seconds: int) -> None:
        self.model = model
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds
        self.base_url = os.getenv("OPENAI_BASE_URL") or None

    def generate(self, prompt: str, metadata: dict[str, Any] | None = None) -> str:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY missing")

        try:
            from openai import OpenAI  # type: ignore
        except ImportError as exc:
            raise RuntimeError("openai package is not installed") from exc

        client_kwargs: dict[str, Any] = {"api_key": api_key}
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
        client = OpenAI(**client_kwargs)
        response = client.responses.create(
            model=self.model,
            input=prompt,
            temperature=self.temperature,
            timeout=self.timeout_seconds,
        )
        text = getattr(response, "output_text", None)
        if text:
            return text

        # Fallback parse for clients without output_text convenience.
        parts: list[str] = []
        for item in getattr(response, "output", []) or []:
            for content in getattr(item, "content", []) or []:
                text_value = getattr(content, "text", None)
                if text_value:
                    parts.append(text_value)
        if not parts:
            raise RuntimeError("OpenAI response did not contain text output")
        return "\n".join(parts)
