# Checkpoint

## Objective
Build a production-grade, reproducible LLM-YARA system with deterministic data handling, secure static-only analysis, and professional research-grade evaluation artifacts.

## Scope Locked (Current)
- Keep static analysis only (no malware execution).
- Prioritize reproducibility and leakage-safe evaluation.
- Implement one additional research-motivated baseline now: APIARY-style static API discriminative baseline (`re-implemented`).

## Progress Log
- [x] Repo/doc contract reviewed (`README.md`, `docs/ARCHITECTURE.md`).
- [x] Existing baseline/eval/CLI flow reviewed.
- [x] Add APIARY-style baseline module (`baselines/apiary_static.py`).
- [x] Wire CLI command for baseline generation (`baseline-apiary-static`).
- [x] Add baseline tests (`tests/test_apiary_static_baseline.py`).
- [x] Run tests and verify no regressions.
- [x] Update docs/README with new command.
- [x] Add baseline comparison orchestration (`llmyara/eval/baseline_compare.py`).
- [x] Wire CLI baseline comparison command (`baseline-eval`).
- [x] Add baseline comparison tests (`tests/test_baseline_compare.py`).
- [x] Update docs for `baseline-eval` outputs and usage.
- [x] Add explicit runtime guard for missing `yara-python` in baseline evaluation.

## Validation Notes
- Initial `pytest -q` failed due local import path setup: `ModuleNotFoundError: No module named 'llmyara'`.
- Verified code correctness with explicit path: `PYTHONPATH=. pytest -q` -> all tests passed.
- New baseline command documented in `README.md` with invocation example.
- Baseline contract updated in `docs/ARCHITECTURE.md`.
- CLI sanity check passed: `python -m llmyara.cli --help` lists `baseline-apiary-static`.
- `baseline-eval --help` validated expected inputs and options.
- Current suite status: `PYTHONPATH=. pytest -q` -> `13 passed`.

## Quality Gates
- Deterministic outputs for fixed inputs.
- No use of test sets in baseline feature scoring.
- YARA rule render path uses existing safe renderer.
- No destructive git operations; no secret material committed.
