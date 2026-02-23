from __future__ import annotations

from pathlib import Path

from llmyara.features.strings import extract_ascii_strings


def test_extract_ascii_strings(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00hello_world\x00abc\x00RED_SIGNAL_123\x00")

    strings = extract_ascii_strings(sample, min_len=4, max_items=10)
    assert "hello_world" in strings
    assert "red_signal_123" in strings
