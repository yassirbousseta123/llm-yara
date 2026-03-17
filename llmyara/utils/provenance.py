from __future__ import annotations

import platform
import subprocess
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

from llmyara.llm.cache import CACHE_IDENTITY_VERSION
from llmyara.utils.hashing import sha256_file


def package_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def git_commit_sha(cwd: str | Path | None = None) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            cwd=str(cwd) if cwd is not None else None,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip() or None


def file_hashes(paths: dict[str, str | Path]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for name, path in paths.items():
        path_obj = Path(path)
        if path_obj.exists() and path_obj.is_file():
            hashes[name] = sha256_file(path_obj)
    return hashes


def build_provenance(
    *,
    backend: str,
    model: str,
    base_url: str | None = None,
    cwd: str | Path | None = None,
) -> dict[str, Any]:
    return {
        "backend": backend,
        "model": model,
        "base_url": base_url,
        "git_commit": git_commit_sha(cwd=cwd),
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "cache_identity_version": CACHE_IDENTITY_VERSION,
        "dependencies": {
            "openai": package_version("openai"),
            "PyYAML": package_version("PyYAML"),
            "scikit-learn": package_version("scikit-learn"),
            "yara-python": package_version("yara-python"),
        },
    }
