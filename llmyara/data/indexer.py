from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from llmyara.utils.hashing import sha256_file


@dataclass(frozen=True)
class ManifestEntry:
    sample_id: str
    path: str
    source: str
    family: str
    size: int
    is_pe: bool


def _iter_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if path.is_file():
            yield path


def _is_pe(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(2) == b"MZ"
    except OSError:
        return False


def _family_for_malware(root: Path, path: Path) -> str:
    rel = path.relative_to(root)
    if len(rel.parts) <= 1:
        return "unknown"
    return rel.parts[0]


def build_manifest(malware_root: str | Path, benign_root: str | Path) -> list[dict[str, object]]:
    malware_root = Path(malware_root)
    benign_root = Path(benign_root)

    entries: list[ManifestEntry] = []

    for file_path in _iter_files(malware_root):
        sample_id = sha256_file(file_path)
        entries.append(
            ManifestEntry(
                sample_id=sample_id,
                path=str(file_path.resolve()),
                source="malware",
                family=_family_for_malware(malware_root, file_path),
                size=file_path.stat().st_size,
                is_pe=_is_pe(file_path),
            )
        )

    for file_path in _iter_files(benign_root):
        sample_id = sha256_file(file_path)
        entries.append(
            ManifestEntry(
                sample_id=sample_id,
                path=str(file_path.resolve()),
                source="benign",
                family="benign",
                size=file_path.stat().st_size,
                is_pe=_is_pe(file_path),
            )
        )

    entries.sort(key=lambda x: x.sample_id)
    return [
        {
            "sample_id": e.sample_id,
            "path": e.path,
            "source": e.source,
            "family": e.family,
            "size": e.size,
            "is_pe": e.is_pe,
        }
        for e in entries
    ]
