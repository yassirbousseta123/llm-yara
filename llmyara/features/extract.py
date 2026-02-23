from __future__ import annotations

from typing import Any

from llmyara.config import FeatureConfig
from llmyara.features.imports import extract_import_tokens
from llmyara.features.pe_meta import extract_pe_metadata
from llmyara.features.strings import extract_ascii_strings


def _tokenize(strings: list[str], imports: list[str], pe_meta: dict[str, Any]) -> list[str]:
    tokens = [f"str:{s}" for s in strings]
    tokens.extend(imports)
    for section in pe_meta.get("sections", []):
        tokens.append(f"sec:{section}")
    if pe_meta.get("imphash"):
        tokens.append(f"imphash:{pe_meta['imphash']}")
    tokens.append(f"sec_count:{pe_meta.get('section_count', 0)}")
    return sorted(set(tokens))


def extract_features(manifest: list[dict[str, Any]], cfg: FeatureConfig) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for sample in manifest:
        sample_id = sample["sample_id"]
        path = sample["path"]
        strings = extract_ascii_strings(path, min_len=cfg.strings_min_len, max_items=cfg.strings_max_per_file)
        imports = extract_import_tokens(path)
        pe_meta = extract_pe_metadata(path)
        tokens = _tokenize(strings, imports, pe_meta)

        rows.append(
            {
                "sample_id": sample_id,
                "path": path,
                "source": sample["source"],
                "family": sample["family"],
                "strings": strings,
                "imports": imports,
                "pe_meta": pe_meta,
                "tokens": tokens,
            }
        )
    return rows
