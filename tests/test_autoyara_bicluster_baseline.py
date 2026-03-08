from __future__ import annotations

import json
from pathlib import Path

from baselines.autoyara_bicluster import write_baseline_rules


def test_autoyara_baseline_emits_hex_rule_from_shared_bytes(tmp_path: Path) -> None:
    target_a = tmp_path / "t1.bin"
    target_b = tmp_path / "t2.bin"
    other = tmp_path / "o1.bin"
    benign = tmp_path / "b1.bin"

    target_a.write_bytes(b"MZ" + b"MALWARE!" + b"shared-block" + b"\x01\x02\x03\x04")
    target_b.write_bytes(b"MZ" + b"MALWARE!" + b"shared-block" + b"\x05\x06\x07\x08")
    other.write_bytes(b"MZ" + b"BENIGN!!" + b"other-block" + b"\xAA\xBB\xCC\xDD")
    benign.write_bytes(b"MZ" + b"UTILITY!" + b"clean-data!" + b"\x10\x11\x12\x13")

    manifest = [
        {"sample_id": "t1", "path": str(target_a)},
        {"sample_id": "t2", "path": str(target_b)},
        {"sample_id": "o1", "path": str(other)},
        {"sample_id": "b1", "path": str(benign)},
    ]
    splits = {
        "families": {
            "fam_a": {
                "train_target": ["t1", "t2"],
                "test_target": [],
                "train_other": ["o1"],
                "test_other": [],
            }
        },
        "global": {
            "benign_dev": ["b1"],
            "benign_test": [],
        },
    }

    result = write_baseline_rules(
        manifest=manifest,
        splits=splits,
        out_dir=tmp_path / "autoyara",
        ngram_sizes=(8,),
        max_strings=4,
        min_score=0.5,
    )

    rule_path = Path(result["rule_paths"]["fam_a"])
    rule_text = rule_path.read_text(encoding="utf-8")

    assert "rule baseline_autoyara_fam_a" in rule_text
    assert "{ " in rule_text

    stats = result["family_stats"]["fam_a"]
    assert stats["string_count"] >= 1
    assert stats["fallback_used"] is False
    assert any("73 68 61 72 65 64" in hex_string or "4D 41 4C 57" in hex_string for hex_string in stats["selected_hex_strings"])


def test_autoyara_baseline_result_is_json_serializable(tmp_path: Path) -> None:
    sample = tmp_path / "short.bin"
    sample.write_bytes(b"\x01\x02\x03")

    result = write_baseline_rules(
        manifest=[{"sample_id": "t1", "path": str(sample)}],
        splits={
            "families": {
                "fam_short": {
                    "train_target": ["t1"],
                    "test_target": [],
                    "train_other": [],
                    "test_other": [],
                }
            },
            "global": {"benign_dev": [], "benign_test": []},
        },
        out_dir=tmp_path / "autoyara_short",
        ngram_sizes=(8,),
    )

    payload = json.dumps(result)
    assert payload

    rule_text = Path(result["rule_paths"]["fam_short"]).read_text(encoding="utf-8")
    assert "rule baseline_autoyara_fam_short" in rule_text
