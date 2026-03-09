from __future__ import annotations

import types

from llmyara.features.pe_meta import extract_pe_metadata


def test_extract_pe_metadata_normalizes_section_names(monkeypatch) -> None:
    class _Section:
        def __init__(self, name: bytes) -> None:
            self.Name = name

    class _PE:
        def __init__(self, path: str, fast_load: bool = True) -> None:
            self.sections = [
                _Section(b".text\x00\x00"),
                _Section(b"   \x00    "),
                _Section(b".idata  "),
                _Section(b"@@@@@@@\x00"),
            ]

        def get_imphash(self) -> str:
            return "abc123"

    fake_pefile = types.SimpleNamespace(PE=_PE)
    monkeypatch.setitem(__import__("sys").modules, "pefile", fake_pefile)

    meta = extract_pe_metadata("dummy.exe")
    assert meta["sections"] == [".idata", ".text"]
    assert meta["section_count"] == 2
    assert meta["imphash"] == "abc123"
