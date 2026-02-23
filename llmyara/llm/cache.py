from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from llmyara.utils.hashing import sha256_text


@dataclass
class CacheRecord:
    prompt_hash: str
    prompt: str
    response: str
    backend: str
    model: str
    metadata: dict[str, Any]


class PromptCache:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def prompt_hash(self, prompt: str) -> str:
        return sha256_text(prompt)

    def get(self, prompt: str) -> CacheRecord | None:
        h = self.prompt_hash(prompt)
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                if row.get("prompt_hash") == h:
                    return CacheRecord(
                        prompt_hash=row["prompt_hash"],
                        prompt=row["prompt"],
                        response=row["response"],
                        backend=row.get("backend", "unknown"),
                        model=row.get("model", "unknown"),
                        metadata=row.get("metadata", {}),
                    )
        return None

    def add(self, prompt: str, response: str, backend: str, model: str, metadata: dict[str, Any] | None = None) -> None:
        row = {
            "prompt_hash": self.prompt_hash(prompt),
            "prompt": prompt,
            "response": response,
            "backend": backend,
            "model": model,
            "metadata": metadata or {},
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
