from __future__ import annotations

import sys
import types
from pathlib import Path

from llmyara.yara.scan import scan_rule


def test_scan_rule_reports_match_errors(tmp_path: Path, monkeypatch) -> None:
    sample_ok = tmp_path / "ok.bin"
    sample_bad = tmp_path / "bad.bin"
    sample_ok.write_bytes(b"MZdemo")
    sample_bad.write_bytes(b"MZdemo")

    class _Rules:
        def match(self, filepath: str) -> list[str]:
            if filepath.endswith("bad.bin"):
                raise RuntimeError("cannot scan")
            return ["hit"]

    fake_yara = types.SimpleNamespace(compile=lambda source: _Rules())
    monkeypatch.setitem(sys.modules, "yara", fake_yara)

    result = scan_rule("rule x { condition: true }", [str(sample_ok), str(sample_bad)])
    assert result.matches == [str(sample_ok)]
    assert result.error_count == 1
    assert "bad.bin" in result.errors[0]
