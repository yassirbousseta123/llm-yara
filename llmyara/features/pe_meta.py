from __future__ import annotations

from pathlib import Path
from typing import Any


def _normalize_section_name(raw_name: str) -> str:
    cleaned = "".join(ch for ch in raw_name if 0x20 <= ord(ch) <= 0x7E).strip().lower()
    if not cleaned:
        return ""
    if not any(ch.isalnum() for ch in cleaned):
        return ""
    return cleaned


def extract_pe_metadata(path: str | Path) -> dict[str, Any]:
    try:
        import pefile  # type: ignore
    except ImportError:
        return {"is_pe": False, "sections": [], "section_count": 0, "imphash": None}

    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return {"is_pe": False, "sections": [], "section_count": 0, "imphash": None}

    sections: list[str] = []
    for section in getattr(pe, "sections", []) or []:
        name = _normalize_section_name(section.Name.decode(errors="ignore"))
        if name:
            sections.append(name)

    imphash = None
    try:
        imphash = pe.get_imphash()
    except Exception:
        imphash = None

    return {
        "is_pe": True,
        "sections": sorted(set(sections)),
        "section_count": len(sections),
        "imphash": imphash,
    }
