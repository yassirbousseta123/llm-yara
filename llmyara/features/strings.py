from __future__ import annotations

import re
from pathlib import Path


def extract_ascii_strings(
    path: str | Path,
    min_len: int,
    max_items: int,
    max_file_bytes: int | None = None,
) -> list[str]:
    path_obj = Path(path)
    try:
        if max_file_bytes is not None and path_obj.stat().st_size > max_file_bytes:
            return []
        raw = path_obj.read_bytes()
    except OSError:
        return []
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode("ascii") + rb",}"
    matches = re.findall(pattern, raw)
    normalized: list[str] = []
    for item in matches:
        if len(normalized) >= max_items:
            break
        try:
            text = item.decode("utf-8", errors="ignore").strip()
        except UnicodeDecodeError:
            continue
        if not text:
            continue
        normalized.append(text.lower())
    return normalized
