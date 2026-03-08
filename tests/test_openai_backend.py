from __future__ import annotations

import os
import types

import pytest

from llmyara.llm.openai_backend import OpenAIBackend


def test_openai_backend_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    backend = OpenAIBackend(model="gpt-test", temperature=0.0, timeout_seconds=30)

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY missing"):
        backend.generate("hello")


def test_openai_backend_passes_base_url_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:11434/v1")

    captured: dict[str, object] = {}

    class _FakeClient:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)
            self.responses = types.SimpleNamespace(
                create=lambda **create_kwargs: types.SimpleNamespace(output_text="{}")
            )

    monkeypatch.setitem(os.environ, "OPENAI_API_KEY", "k")
    monkeypatch.setitem(os.environ, "OPENAI_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setitem(__import__("sys").modules, "openai", types.SimpleNamespace(OpenAI=_FakeClient))

    backend = OpenAIBackend(model="gpt-test", temperature=0.0, timeout_seconds=30)
    assert backend.generate("hello") == "{}"
    assert captured["api_key"] == "k"
    assert captured["base_url"] == "http://localhost:11434/v1"
