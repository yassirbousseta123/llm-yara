# Architecture

Read when:
- adding a new pipeline stage
- changing evaluation semantics
- debugging reproducibility differences
- implementing research baselines

## Principles
- Static analysis only; no malware execution.
- Deterministic outputs for a fixed config and cache.
- Explicit leakage barriers between dev and test sets.
- Bounded LLM repair loop; never unbounded generation.
- Semantic acceptance gates; compile-only rules are not enough.

## Pipeline Contract
1. `index`: Build manifest with `sha256`, label, source, path metadata.
2. `split`: Deterministic train/test splits per family + benign dev/test.
3. `extract`: Static tokens (strings/imports/PE metadata).
4. `select`: Train-only discriminative feature ranking.
5. `generate`: LLM JSON -> YARA template -> compile/repair/gates.
6. `evaluate`: Report family-level and aggregate metrics.
7. `report`: Persist machine-readable and human-readable artifacts.

## Generation Acceptance Contract
- Candidate rules must compile and pass structural validation.
- Candidate rules must hit training-target samples before they can be accepted.
- Candidate rules must stay below the configured `benign_dev` false-positive threshold.
- `condition: false` is invalid, even if it compiles.
- Default LLM path is structured, not freeform: model payloads choose strings/imports/sections, then the renderer assembles a bounded condition template.
- Repair payloads may return full YARA text (`fixed_rule`, `repaired_rule`, `rule_text`, `yara_rule`) and the renderer must preserve it.

## Feature Contract
- Selection operates on full extracted tokens, not whitespace-split fragments.
- `str:` tokens represent literal file strings and are rendered without the `str:` prefix.
- `imp:` and `sec:` tokens are signals for reasoning and condition building, not literal strings.
- Section names are normalized to printable, non-empty identifiers before tokenization.
- Structured generation normalizes model output back to the allowed signal set before rendering when selected signals are available.

## Baseline Contract
- Baselines write one YARA file per family plus `baseline_manifest.json`.
- Baseline manifest must include `status` label from: `reproduced`, `re-implemented`, `paper-only`.
- Current shipped baselines:
  - `baseline-topstrings` (`reproduced`)
  - `baseline-apiary-static` (`re-implemented`)
  - `baseline-autoyara` (`re-implemented`)
- `baseline-eval` writes:
  - per-method folders with `rules/`, `baseline_manifest.json`, `results_per_family.csv`, `summary.json`, `summary.md`
  - top-level `baseline_comparison.csv` and `baseline_comparison.json`
- `compare-all` writes:
  - primary method folder `llmyara_llm/` with `method_manifest.json`, `results_per_family.csv`, `summary.json`, `summary.md`
  - nested `baselines/` comparison bundle from `baseline-eval`
  - top-level `results_all_methods.csv`, `summary_all_methods.json`, `summary_all_methods.md`

## Output Layout
Each run writes a self-contained artifact bundle:
- `run_manifest.json`: command + config snapshot
- `manifest.jsonl`, `splits.json`, `features.jsonl`, `selected_features.json`
- `rules/*.yar`, `generation_summary.json`
- `results_per_family.csv`, `summary.json`, `summary.md`
- `llm_cache.jsonl` for prompt replay/freeze
- optional `comparison/` bundle for same-split method comparison
