from __future__ import annotations

from llmyara.selection.score import select_family_features


def test_select_family_features_preserves_tokens_with_spaces() -> None:
    features_by_id = {
        "t1": {"tokens": ["str:alpha beta", "imp:kernel32.dll!sleep"]},
        "t2": {"tokens": ["str:alpha beta", "str:mutex red"]},
        "o1": {"tokens": ["str:generic token", "imp:user32.dll!messageboxa"]},
        "b1": {"tokens": ["str:generic token"]},
    }

    selected = select_family_features(
        features_by_id=features_by_id,
        train_target=["t1", "t2"],
        train_other=["o1"],
        benign_dev=["b1"],
        top_k=5,
    )

    features = {item["feature"] for item in selected}
    assert "str:alpha beta" in features
    assert "str:mutex red" in features
    assert "alpha" not in features
    assert "beta" not in features
