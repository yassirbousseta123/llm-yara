from __future__ import annotations

from pathlib import Path


def extract_import_tokens(path: str | Path) -> list[str]:
    try:
        import pefile  # type: ignore
    except ImportError:
        return []

    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception:
        return []

    tokens: set[str] = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = getattr(entry, "dll", b"")
        dll_name = dll.decode(errors="ignore").lower() if isinstance(dll, bytes) else str(dll).lower()
        for imp in getattr(entry, "imports", []) or []:
            name_raw = getattr(imp, "name", b"")
            name = name_raw.decode(errors="ignore").lower() if isinstance(name_raw, bytes) else str(name_raw).lower()
            if name:
                tokens.add(f"imp:{dll_name}!{name}")
    return sorted(tokens)
