from __future__ import annotations

from pathlib import Path

from llmyara.features.strings import extract_ascii_strings


def test_extract_ascii_strings_skips_oversized_file(tmp_path: Path) -> None:
    sample = tmp_path / "huge.bin"
    sample.write_bytes(b"A" * 32)
    assert extract_ascii_strings(sample, min_len=4, max_items=10, max_file_bytes=16) == []
