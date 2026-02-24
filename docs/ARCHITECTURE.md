# Architecture

Read when:
- adding a new pipeline stage
- changing evaluation semantics
- debugging reproducibility differences

## Principles
- Static analysis only; no malware execution.
- Deterministic outputs for a fixed config and cache.
- Explicit leakage barriers between dev and test sets.
- Bounded LLM repair loop; never unbounded generation.

## Pipeline Contract
1. `index`: Build manifest with `sha256`, label, source, path metadata.
2. `split`: Deterministic train/test splits per family + benign dev/test.
3. `extract`: Static tokens (strings/imports/PE metadata).
4. `select`: Train-only discriminative feature ranking.
5. `generate`: LLM JSON -> YARA template -> compile/repair/gates.
6. `evaluate`: Report family-level and aggregate metrics.
7. `report`: Persist machine-readable and human-readable artifacts.

## Baseline Contract
- Baselines write one YARA file per family plus `baseline_manifest.json`.
- Baseline manifest must include `status` label from: `reproduced`, `re-implemented`, `paper-only`.
- Current shipped baselines:
  - `baseline-topstrings` (`reproduced`)
  - `baseline-apiary-static` (`re-implemented`)
- `baseline-eval` writes:
  - per-method folders with `rules/`, `baseline_manifest.json`, `results_per_family.csv`, `summary.json`, `summary.md`
  - top-level `baseline_comparison.csv` and `baseline_comparison.json`

## Output Layout
Each run writes a self-contained artifact bundle:
- `run_manifest.json`: command + config snapshot
- `manifest.jsonl`, `splits.json`, `features.jsonl`, `selected_features.json`
- `rules/*.yar`, `generation_summary.json`
- `results_per_family.csv`, `summary.json`, `summary.md`
