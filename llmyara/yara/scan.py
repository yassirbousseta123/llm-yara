from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScanResult:
    matches: list[str]
    elapsed_seconds: float


def scan_rule(rule_text: str, file_paths: list[str]) -> ScanResult:
    try:
        import yara  # type: ignore
    except ImportError as exc:
        raise RuntimeError("yara-python not installed") from exc

    rules = yara.compile(source=rule_text)
    matches: list[str] = []
    start = time.perf_counter()
    for path in file_paths:
        try:
            result = rules.match(filepath=str(Path(path)))
        except Exception:
            result = []
        if result:
            matches.append(path)
    elapsed = time.perf_counter() - start
    return ScanResult(matches=matches, elapsed_seconds=elapsed)
