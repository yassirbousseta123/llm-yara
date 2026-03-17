# Operations

Read when:
- running full dataset experiments
- reproducing a previous result bundle
- preparing final submission artifacts

## Standard Run Modes
- `demo`: synthetic dataset, zero external dependencies.
- `full`: real dataset directories provided by operator.

## Runtime Environment
- Prefer Docker or an isolated Python virtualenv for local full runs.
- Avoid shared scientific/conda environments for `runtime,ml` installs; compiled wheel ABI conflicts can break `numpy`, `pandas`, or `scikit-learn`.
- Keep secrets outside git; `.openai_key` is local-only and ignored.

## Mandatory Artifacts
Every production run should include:
- `manifest.jsonl`
- `splits.json`
- `features.jsonl`
- `selected_features.json`
- `generation_summary.json`
- `failure_analysis.json`
- `llm_cache.jsonl`
- `results_per_family.csv`
- `summary.json`
- `summary.md`
- provenance in `run_manifest.json`

For research baseline comparison runs also keep:
- `baseline_comparison.csv`
- `baseline_comparison.json`
- per-method `baseline_manifest.json`

For final same-split comparison runs also keep:
- `comparison/results_all_methods.csv`
- `comparison/summary_all_methods.json`
- `comparison/summary_all_methods.md`
- `comparison/significance_vs_primary.json`
- `comparison/failure_analysis.json`
- `comparison/llmyara_llm/method_manifest.json`
- `comparison_run_manifest.json`

## Baseline Labeling
Use one of:
- `reproduced`
- `re-implemented`
- `paper-only`

Use `paper-only` only for cited related work that was not executed from this repository.
Never present `paper-only` metrics as directly comparable to your own split.

## Recommended Final Run
- Use `run-all-compare` for the final comparison bundle.
- Prefer `--backend replay` after a real LLM run has been cached and frozen.
- If using a non-OpenAI provider with compatible API semantics, set `OPENAI_BASE_URL`.
- Run a small smoke subset first with the real backend before the full dataset.
- Export a public-safe audit bundle before sharing results outside the local environment.

Audit export:
```bash
python -m llmyara.cli export-audit-bundle \
  --primary-run-dir /absolute/path/to/outputs/final_compare \
  --replay-run-dir /absolute/path/to/outputs/final_compare_replay \
  --out /absolute/path/to/artifacts/final_audit_bundle
```

## Acceptance Triage
- If a family is rejected with `train_target_hits_below_min`, the rule is syntactically valid but semantically useless; improve features/prompting before rerunning full experiments.
- If a family is rejected with `benign_dev_fpr_exceeded`, the rule is too broad; tighten signal quality or condition structure.
- If a family ends in `scan_error`, treat the evaluation as invalid until the underlying file-level scan failure is understood.
- Use `failure_analysis.json` to track missing-rule families and dominant rejection buckets.
- Do not report compile-only or always-false rules as successful generations.
