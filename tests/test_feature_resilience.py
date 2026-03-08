from __future__ import annotations

from pathlib import Path

from llmyara.config import FeatureConfig
from llmyara.features.extract import extract_features
from llmyara.features.strings import extract_ascii_strings


def test_extract_ascii_strings_missing_file_returns_empty(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"
    assert extract_ascii_strings(missing, min_len=4, max_items=10) == []


def test_extract_ascii_strings_respects_max_items_on_large_input(tmp_path: Path) -> None:
    sample = tmp_path / "large.bin"
    sample.write_bytes(b"\x00".join([f"STRING_{idx:03d}".encode("ascii") for idx in range(50)]))

    strings = extract_ascii_strings(sample, min_len=6, max_items=7)
    assert len(strings) == 7


def test_extract_features_missing_file_is_safe(tmp_path: Path) -> None:
    missing = tmp_path / "gone.bin"
    rows = extract_features(
        [
            {
                "sample_id": "s1",
                "path": str(missing),
                "source": "malware",
                "family": "fam_missing",
            }
        ],
        FeatureConfig(strings_min_len=4, strings_max_per_file=10),
    )

    assert len(rows) == 1
    assert rows[0]["strings"] == []
    assert rows[0]["imports"] == []
    assert rows[0]["pe_meta"]["is_pe"] is False
