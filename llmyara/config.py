from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class SplitConfig:
    test_ratio: float = 0.3
    benign_dev_ratio: float = 0.6
    min_family_size: int = 6


@dataclass(frozen=True)
class FeatureConfig:
    strings_min_len: int = 6
    strings_max_per_file: int = 150


@dataclass(frozen=True)
class SelectionConfig:
    top_k_features: int = 30


@dataclass(frozen=True)
class YaraConfig:
    max_strings: int = 20
    max_rule_bytes: int = 2048
    max_condition_length: int = 320
    max_repairs: int = 3
    benign_dev_fpr_threshold: float = 0.02


@dataclass(frozen=True)
class LLMConfig:
    model: str = "gpt-5.2-pro"
    temperature: float = 0.0
    timeout_seconds: int = 90


@dataclass(frozen=True)
class RuntimeConfig:
    workers: int = 1


@dataclass(frozen=True)
class AppConfig:
    seed: int = 42
    split: SplitConfig = SplitConfig()
    features: FeatureConfig = FeatureConfig()
    selection: SelectionConfig = SelectionConfig()
    yara: YaraConfig = YaraConfig()
    llm: LLMConfig = LLMConfig()
    runtime: RuntimeConfig = RuntimeConfig()


def _merge_dict(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge_dict(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str | Path | None) -> AppConfig:
    default = {
        "seed": 42,
        "split": {
            "test_ratio": 0.3,
            "benign_dev_ratio": 0.6,
            "min_family_size": 6,
        },
        "features": {
            "strings_min_len": 6,
            "strings_max_per_file": 150,
        },
        "selection": {
            "top_k_features": 30,
        },
        "yara": {
            "max_strings": 20,
            "max_rule_bytes": 2048,
            "max_condition_length": 320,
            "max_repairs": 3,
            "benign_dev_fpr_threshold": 0.02,
        },
        "llm": {
            "model": "gpt-5.2-pro",
            "temperature": 0.0,
            "timeout_seconds": 90,
        },
        "runtime": {
            "workers": 1,
        },
    }

    if path is not None:
        with Path(path).open("r", encoding="utf-8") as handle:
            user = yaml.safe_load(handle) or {}
        merged = _merge_dict(default, user)
    else:
        merged = default

    return AppConfig(
        seed=int(merged["seed"]),
        split=SplitConfig(**merged["split"]),
        features=FeatureConfig(**merged["features"]),
        selection=SelectionConfig(**merged["selection"]),
        yara=YaraConfig(**merged["yara"]),
        llm=LLMConfig(**merged["llm"]),
        runtime=RuntimeConfig(**merged["runtime"]),
    )
