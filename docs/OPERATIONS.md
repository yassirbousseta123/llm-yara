# Operations

Read when:
- running full dataset experiments
- reproducing a previous result bundle
- preparing final submission artifacts

## Standard Run Modes
- `demo`: synthetic dataset, zero external dependencies.
- `full`: real dataset directories provided by operator.

## Mandatory Artifacts
Every production run should include:
- `manifest.jsonl`
- `splits.json`
- `features.jsonl`
- `selected_features.json`
- `generation_summary.json`
- `results_per_family.csv`
- `summary.json`
- `summary.md`

## Baseline Labeling
Use one of:
- `reproduced`
- `re-implemented`
- `paper-only`

Never present `paper-only` metrics as directly comparable to your own split.
