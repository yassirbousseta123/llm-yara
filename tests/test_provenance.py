from __future__ import annotations

from pathlib import Path

from llmyara.utils.provenance import build_provenance, file_hashes


def test_file_hashes_only_hash_existing_files(tmp_path: Path) -> None:
    present = tmp_path / "present.txt"
    present.write_text("hello", encoding="utf-8")
    hashes = file_hashes({"present": present, "missing": tmp_path / "missing.txt"})
    assert set(hashes) == {"present"}


def test_build_provenance_contains_cache_identity_version() -> None:
    provenance = build_provenance(backend="mock", model="demo-model")
    assert provenance["backend"] == "mock"
    assert provenance["model"] == "demo-model"
    assert provenance["cache_identity_version"] == "v2"
