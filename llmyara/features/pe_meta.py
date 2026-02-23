from __future__ import annotations

from pathlib import Path
from typing import Any


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
        name = section.Name.decode(errors="ignore").strip("\x00").lower()
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
