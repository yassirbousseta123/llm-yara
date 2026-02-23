from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CompileResult:
    ok: bool
    error: str | None


def is_yara_available() -> bool:
    try:
        import yara  # type: ignore # noqa: F401

        return True
    except ImportError:
        return False


def compile_rule(rule_text: str) -> CompileResult:
    try:
        import yara  # type: ignore
    except ImportError:
        return CompileResult(ok=False, error="yara-python not installed")

    try:
        yara.compile(source=rule_text)
        return CompileResult(ok=True, error=None)
    except Exception as exc:
        return CompileResult(ok=False, error=str(exc))
