# LLM-YARA: Reproducible Static-Analysis YARA Generation

A production-oriented pipeline for generating and evaluating YARA rules from malware family samples using deterministic preprocessing and bounded LLM-assisted synthesis.

## Security Posture
- Static analysis only.
- No malware execution.
- Dataset directories can be mounted read-only.
- Deterministic splits and replayable LLM responses.

## What This Repository Delivers
- End-to-end CLI pipeline:
  - `index -> split -> extract -> select -> generate -> evaluate`
- Bounded compile-repair loop for rule validity.
- Explicit leakage control: `benign_dev` for gating, `benign_test` for final FPR.
- Dockerized execution with `start.sh`.

## Project Layout
- `llmyara/`: core implementation
- `baselines/`: deterministic non-LLM baseline(s)
- `configs/default.yaml`: default thresholds and runtime settings
- `start.sh`: entrypoint for demo/full runs
- `docs/ARCHITECTURE.md`: design contract

## Quickstart (Docker, recommended)
```bash
docker compose build
docker compose run --rm llmyara --mode demo
```

## Quickstart (Local)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .[dev]
# Required for generate/evaluate stages outside Docker:
pip install -e .[runtime,ml]
./start.sh --mode demo
```

## Full Run (Local)
```bash
./start.sh --mode full \
  --malware-dir /absolute/path/to/malware \
  --benign-dir /absolute/path/to/benign \
  --out /absolute/path/to/outputs/final_run \
  --backend mock
```

Use `--backend openai` only when `OPENAI_API_KEY` is set.

## CLI Reference
```bash
python -m llmyara.cli --help
```

Key commands:
- `make-demo-data`
- `index`
- `split`
- `extract`
- `select`
- `generate`
- `evaluate`
- `run-all`
- `baseline-topstrings`

## Reproducibility
- Use fixed seeds from `configs/default.yaml`.
- Use backend `replay` for deterministic regeneration from cached responses.
- Each run persists artifacts in one folder (`outputs/<run_id>/`).

## Baseline Labeling Policy
When reporting comparisons, label each method as one of:
- `reproduced`
- `re-implemented`
- `paper-only`

Avoid presenting `paper-only` results as directly comparable to your own split.

## Limitations
- Current feature set is static PE-oriented.
- Non-PE files are safely skipped for PE-specific fields.
- LLM quality depends on selected features and model availability.
