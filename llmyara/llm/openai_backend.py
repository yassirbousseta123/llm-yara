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

    def _request_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "timeout": self.timeout_seconds,
        }
        # Older GPT-5 family models reject temperature overrides; use server defaults.
        if not self.model.startswith("gpt-5"):
            kwargs["temperature"] = self.temperature
        return kwargs

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
        request_kwargs = self._request_kwargs()
        responses_api = getattr(client, "responses", None)
        if responses_api is not None:
            response = responses_api.create(
                input=prompt,
                **request_kwargs,
            )
            text = getattr(response, "output_text", None)
            if text:
                return text

            parts: list[str] = []
            for item in getattr(response, "output", []) or []:
                for content in getattr(item, "content", []) or []:
                    text_value = getattr(content, "text", None)
                    if text_value:
                        parts.append(text_value)
            if parts:
                return "\n".join(parts)

        chat_api = getattr(getattr(client, "chat", None), "completions", None)
        if chat_api is None:
            raise RuntimeError("OpenAI client missing responses and chat.completions APIs")

        response = chat_api.create(
            messages=[{"role": "user", "content": prompt}],
            **request_kwargs,
        )
        choices = getattr(response, "choices", None) or []
        if not choices:
            raise RuntimeError("OpenAI chat completion did not contain choices")
        message = getattr(choices[0], "message", None)
        content = getattr(message, "content", None) if message else None
        if isinstance(content, str) and content:
            return content
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict):
                    text_value = item.get("text")
                else:
                    text_value = getattr(item, "text", None)
                if text_value:
                    parts.append(str(text_value))
            if parts:
                return "\n".join(parts)
        raise RuntimeError("OpenAI chat completion did not contain text output")
