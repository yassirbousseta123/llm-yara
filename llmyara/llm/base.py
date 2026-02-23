from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class LLMBackend(ABC):
    @abstractmethod
    def generate(self, prompt: str, metadata: dict[str, Any] | None = None) -> str:
        raise NotImplementedError
