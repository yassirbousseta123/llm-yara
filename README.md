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
- LLM rule acceptance is semantic, not syntax-only: accepted rules must compile, stay below the benign-dev threshold, and hit training-target samples.
- LLM generation is structured: the model selects strings/imports/sections; the renderer builds the final YARA condition deterministically.
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

Use an isolated virtualenv for local runtime work. Shared conda/scientific environments can break compiled dependencies used by `runtime,ml`.

## Full Run (Local)
```bash
./start.sh --mode full \
  --malware-dir /absolute/path/to/malware \
  --benign-dir /absolute/path/to/benign \
  --out /absolute/path/to/outputs/final_run \
  --backend mock
```

## Expected Dataset Layout
Malware samples should be grouped by family:
```text
malware/
  family_one/
    sample_001.bin
    sample_002.bin
  family_two/
    sample_001.bin
benign/
  benign_001.bin
  benign_002.bin
```

Rules:
- each malware family should live in its own first-level directory
- benign files can live directly under `benign/`
- files are treated as static inputs only; nothing is executed

Primary comparison run:
```bash
./start.sh --mode full \
  --compare-all \
  --malware-dir /absolute/path/to/malware \
  --benign-dir /absolute/path/to/benign \
  --out /absolute/path/to/outputs/final_compare \
  --backend openai
```

Use `--backend openai` only when `OPENAI_API_KEY` is set.
Set `OPENAI_BASE_URL` if using an OpenAI-compatible local or hosted endpoint.

## Recommended Final Workflow
1. Run a real backend once and freeze the cache:
```bash
./start.sh --mode full \
  --compare-all \
  --malware-dir /absolute/path/to/malware \
  --benign-dir /absolute/path/to/benign \
  --out /absolute/path/to/outputs/final_compare \
  --backend openai
```
2. Reproduce the same outputs from cache:
```bash
./start.sh --mode full \
  --compare-all \
  --malware-dir /absolute/path/to/malware \
  --benign-dir /absolute/path/to/benign \
  --out /absolute/path/to/outputs/final_compare_replay \
  --backend replay
```
3. Write the report from the frozen artifact bundle, not from ad hoc reruns.

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
- `run-all-compare`
- `baseline-topstrings`
- `baseline-apiary-static`
- `baseline-autoyara`
- `baseline-eval`
- `compare-all`

## Baselines
- `baseline-topstrings`: deterministic string-only baseline (`reproduced`).
- `baseline-apiary-static`: APIARY-inspired static import discriminative baseline (`re-implemented`).
- `baseline-autoyara`: AutoYara-inspired byte n-gram bicluster baseline (`re-implemented`).

Research baseline mapping lives in [docs/paper_baseline_matrix.md](docs/paper_baseline_matrix.md).

Example:
```bash
python -m llmyara.cli baseline-apiary-static \
  --features /absolute/path/to/features.jsonl \
  --splits /absolute/path/to/splits.json \
  --out /absolute/path/to/outputs/baseline_apiary \
  --max-strings 8 \
  --min-score 0.0
```

```bash
python -m llmyara.cli baseline-autoyara \
  --manifest /absolute/path/to/manifest.jsonl \
  --splits /absolute/path/to/splits.json \
  --out /absolute/path/to/outputs/baseline_autoyara \
  --ngram-sizes 8,16,32 \
  --max-strings 12 \
  --min-score 0.4
```

Evaluate shipped baselines side-by-side:
```bash
python -m llmyara.cli baseline-eval \
  --manifest /absolute/path/to/manifest.jsonl \
  --splits /absolute/path/to/splits.json \
  --selected /absolute/path/to/selected_features.json \
  --features /absolute/path/to/features.jsonl \
  --out /absolute/path/to/outputs/baseline_eval \
  --topstrings-max-strings 8 \
  --apiary-max-strings 8 \
  --apiary-min-score 0.0 \
  --autoyara-max-strings 12 \
  --autoyara-ngram-sizes 8,16,32 \
  --autoyara-min-score 0.4
```

Compare the primary LLM run and baselines on identical splits from existing artifacts:
```bash
python -m llmyara.cli compare-all \
  --manifest /absolute/path/to/manifest.jsonl \
  --splits /absolute/path/to/splits.json \
  --selected /absolute/path/to/selected_features.json \
  --features /absolute/path/to/features.jsonl \
  --generation /absolute/path/to/generation_summary.json \
  --out /absolute/path/to/outputs/comparison \
  --topstrings-max-strings 8 \
  --apiary-max-strings 8 \
  --apiary-min-score 0.0 \
  --autoyara-max-strings 12 \
  --autoyara-ngram-sizes 8,16,32 \
  --autoyara-min-score 0.4
```

Single-command final experiment flow:
```bash
python -m llmyara.cli run-all-compare \
  --config configs/default.yaml \
  --malware-dir /absolute/path/to/malware \
  --benign-dir /absolute/path/to/benign \
  --out /absolute/path/to/outputs/final_compare \
  --backend openai
```

## Final Artifact Bundle
A `run-all-compare` output should contain:
- `manifest.jsonl`
- `splits.json`
- `features.jsonl`
- `selected_features.json`
- `generation_summary.json`
- `llm_cache.jsonl`
- `results_per_family.csv`
- `summary.json`
- `summary.md`
- `run_manifest.json`
- `comparison_run_manifest.json`
- `comparison/results_all_methods.csv`
- `comparison/summary_all_methods.json`
- `comparison/summary_all_methods.md`
- `comparison/llmyara_llm/method_manifest.json`
- `comparison/baselines/...`

## Reproducibility
- Use fixed seeds from `configs/default.yaml`.
- Use backend `replay` for deterministic regeneration from cached responses.
- Each run persists artifacts in one folder (`outputs/<run_id>/`).
- `run-all-compare` writes unified all-method comparison artifacts under `comparison/`.
- Primary runs also persist `llm_cache.jsonl` and `comparison_run_manifest.json` for replay/freeze workflows.

## Baseline Labeling Policy
When reporting comparisons, label each method as one of:
- `reproduced`
- `re-implemented`
- `paper-only`

Avoid presenting `paper-only` results as directly comparable to your own split.

## Scope and Limitations
- Static analysis only.
- No dynamic analysis or malware execution in this repository.
- Current feature extraction is PE-oriented; non-PE files are handled conservatively.
- Shipped baselines are:
  - `topstrings`
  - `apiary-static`
  - `autoyara-bicluster`
- `mock` backend is for development/tests; final evaluation should use a real backend or replay from a real cached run.
- Current feature set is static PE-oriented.
- Non-PE files are safely skipped for PE-specific fields.
- LLM quality depends on selected features and model availability.
- Token ranking preserves full extracted features, including strings that contain spaces.
