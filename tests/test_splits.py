from __future__ import annotations

from llmyara.data.splits import build_splits


def _manifest() -> list[dict[str, object]]:
    rows = []
    for i in range(10):
        rows.append({"sample_id": f"A{i}", "source": "malware", "family": "fam_a"})
    for i in range(10):
        rows.append({"sample_id": f"B{i}", "source": "malware", "family": "fam_b"})
    for i in range(12):
        rows.append({"sample_id": f"G{i}", "source": "benign", "family": "benign"})
    return rows


def test_splits_are_deterministic() -> None:
    manifest = _manifest()
    first = build_splits(manifest, seed=42, test_ratio=0.3, benign_dev_ratio=0.6, min_family_size=6)
    second = build_splits(manifest, seed=42, test_ratio=0.3, benign_dev_ratio=0.6, min_family_size=6)
    assert first == second


def test_split_disjointness() -> None:
    splits = build_splits(_manifest(), seed=7, test_ratio=0.3, benign_dev_ratio=0.6, min_family_size=6)

    for family_split in splits["families"].values():
        train = set(family_split["train_target"])
        test = set(family_split["test_target"])
        assert train.isdisjoint(test)

    benign_dev = set(splits["global"]["benign_dev"])
    benign_test = set(splits["global"]["benign_test"])
    assert benign_dev.isdisjoint(benign_test)


def test_splits_deduplicate_duplicate_sample_ids() -> None:
    manifest = _manifest() + [
        {"sample_id": "A0", "source": "malware", "family": "fam_a"},
        {"sample_id": "G0", "source": "benign", "family": "benign"},
    ]

    splits = build_splits(manifest, seed=7, test_ratio=0.3, benign_dev_ratio=0.6, min_family_size=6)

    fam_a_ids = set(splits["families"]["fam_a"]["train_target"]) | set(splits["families"]["fam_a"]["test_target"])
    benign_ids = set(splits["global"]["benign_dev"]) | set(splits["global"]["benign_test"])

    assert len(fam_a_ids) == 10
    assert len(benign_ids) == 12
    assert set(splits["global"]["benign_dev"]).isdisjoint(set(splits["global"]["benign_test"]))
