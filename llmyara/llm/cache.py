from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from llmyara.utils.hashing import sha256_text


CACHE_IDENTITY_VERSION = "v2"


@dataclass
class CacheRecord:
    cache_key: str
    prompt_hash: str
    prompt: str
    response: str
    backend: str
    model: str
    base_url: str | None
    schema_version: str
    metadata: dict[str, Any]


class PromptCache:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def prompt_hash(self, prompt: str) -> str:
        return sha256_text(prompt)

    def cache_key(self, prompt: str, backend: str, model: str, base_url: str | None = None) -> str:
        payload = {
            "prompt_hash": self.prompt_hash(prompt),
            "backend": backend,
            "model": model,
            "base_url": base_url or "",
            "schema_version": CACHE_IDENTITY_VERSION,
        }
        return sha256_text(json.dumps(payload, sort_keys=True))

    def get(
        self,
        prompt: str,
        *,
        backend: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
    ) -> CacheRecord | None:
        h = self.prompt_hash(prompt)
        expected_key = self.cache_key(prompt, backend, model, base_url) if backend and model else None
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                row_prompt_hash = row.get("prompt_hash")
                row_backend = row.get("backend", "unknown")
                row_model = row.get("model", "unknown")
                row_base_url = row.get("base_url")
                row_cache_key = row.get("cache_key")

                if expected_key is not None:
                    if row_cache_key == expected_key:
                        return CacheRecord(
                            cache_key=row_cache_key,
                            prompt_hash=row["prompt_hash"],
                            prompt=row["prompt"],
                            response=row["response"],
                            backend=row_backend,
                            model=row_model,
                            base_url=row_base_url,
                            schema_version=row.get("schema_version", "v1"),
                            metadata=row.get("metadata", {}),
                        )
                    if row_prompt_hash != h:
                        continue
                    if row_backend not in {backend, "unknown"}:
                        continue
                    if row_model not in {model, "unknown"}:
                        continue
                    if row_base_url is not None and row_base_url != base_url:
                        continue
                elif row_prompt_hash != h:
                    continue

                return CacheRecord(
                    cache_key=row_cache_key or "",
                    prompt_hash=row["prompt_hash"],
                    prompt=row["prompt"],
                    response=row["response"],
                    backend=row_backend,
                    model=row_model,
                    base_url=row_base_url,
                    schema_version=row.get("schema_version", "v1"),
                    metadata=row.get("metadata", {}),
                )
        return None

    def add(
        self,
        prompt: str,
        response: str,
        backend: str,
        model: str,
        metadata: dict[str, Any] | None = None,
        *,
        base_url: str | None = None,
        schema_version: str = CACHE_IDENTITY_VERSION,
    ) -> None:
        row = {
            "cache_key": self.cache_key(prompt, backend, model, base_url),
            "prompt_hash": self.prompt_hash(prompt),
            "prompt": prompt,
            "response": response,
            "backend": backend,
            "model": model,
            "base_url": base_url,
            "schema_version": schema_version,
            "metadata": metadata or {},
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
