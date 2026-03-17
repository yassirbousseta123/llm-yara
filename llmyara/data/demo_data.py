from __future__ import annotations

from pathlib import Path
import random


FAMILY_TOKENS = {
    "family_red": ["red_loader", "mutex_red", "beacon_red"],
    "family_blue": ["blue_dropper", "svc_blue", "domain_blue"],
    "family_green": ["green_unpack", "pipe_green", "cfg_green"],
}

BENIGN_TOKENS = ["normal_app", "office_plugin", "windows_update", "installer"]


def _write_sample(path: Path, tokens: list[str], noise: list[str]) -> None:
    content = "\x00".join(tokens + noise).encode("utf-8", errors="ignore")
    path.write_bytes(content)


def create_demo_dataset(root: str | Path, seed: int = 42) -> dict[str, int]:
    root = Path(root)
    malware_root = root / "malware"
    benign_root = root / "benign"
    malware_root.mkdir(parents=True, exist_ok=True)
    benign_root.mkdir(parents=True, exist_ok=True)

    rng = random.Random(seed)
    counts: dict[str, int] = {}

    for family, core_tokens in FAMILY_TOKENS.items():
        family_dir = malware_root / family
        family_dir.mkdir(parents=True, exist_ok=True)
        counts[family] = 0
        for idx in range(12):
            noise = [f"noise_{rng.randint(1, 500)}" for _ in range(8)]
            extra = [core_tokens[idx % len(core_tokens)]]
            path = family_dir / f"sample_{idx:03d}.bin"
            _write_sample(path, core_tokens + extra, noise)
            counts[family] += 1

    counts["benign"] = 0
    for idx in range(24):
        noise = [f"noise_{rng.randint(1, 500)}" for _ in range(8)]
        tokens = BENIGN_TOKENS + [f"benign_marker_{idx % 5}"]
        path = benign_root / f"benign_{idx:03d}.bin"
        _write_sample(path, tokens, noise)
        counts["benign"] += 1

    return counts
