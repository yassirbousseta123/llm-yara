# LLM-YARA: Reproducible Static-Analysis YARA Generation

A pipeline for generating and evaluating YARA rules from malware family samples using deterministic preprocessing and bounded LLM-assisted synthesis.

## Security Posture
- Static analysis only.
- No malware execution.
- Dataset directories can be mounted read-only.
- Deterministic splits and replayable LLM responses.
- Run manifests with git/dependency metadata and artifact hashes.

## What This Repository Delivers
- End-to-end CLI pipeline:
  - `index -> split -> extract -> select -> generate -> evaluate`
- Bounded compile-repair loop for rule validity.
- Explicit leakage control: `benign_dev` contributes negative examples for feature ranking and acceptance gating, while `benign_test` is reserved for final FPR.
- LLM rule acceptance is semantic, not syntax-only: accepted rules must compile, stay below the benign-dev threshold, and hit training-target samples.
- LLM generation is structured: the model selects strings/imports/sections; the renderer builds the final YARA condition deterministically.
- Dockerized execution with `start.sh`.
- Startup preflight for required Python dependencies.

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

Demo mode does **not** require `OPENAI_API_KEY`.

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

## OpenAI Backend Setup
Use the OpenAI backend only when you want a real LLM run. The easiest setup is to export the key in the same shell where you run the commands:

### Local shell
```bash
export OPENAI_API_KEY="your-key-here"
# optional, only for OpenAI-compatible endpoints:
# export OPENAI_BASE_URL="http://host:port/v1"
```

### Docker
`docker compose` reads the same shell environment, so export the key first, then use a real OpenAI-backed command:

```bash
export OPENAI_API_KEY="your-key-here"
docker compose build
docker compose run --rm llmyara \
  --mode full \
  --compare-all \
  --malware-dir /data/malware \
  --benign-dir /data/benign \
  --out /outputs/final_compare \
  --backend openai
```

If `OPENAI_API_KEY` is not set, use `--backend mock` or `--backend replay` instead of `--backend openai`.

## Recommended Run Path
1. Run demo mode first to confirm the environment works:
```bash
./start.sh --mode demo
```
2. If you want a real LLM run, export `OPENAI_API_KEY` in the same shell.
3. Arrange malware and benign samples using the dataset layout below.
4. Run the full comparison flow with `--backend openai`.

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
export OPENAI_API_KEY="your-key-here"
./start.sh --mode full \
  --compare-all \
  --malware-dir /absolute/path/to/malware \
  --benign-dir /absolute/path/to/benign \
  --out /absolute/path/to/outputs/final_compare \
  --backend openai
```

Use `--backend openai` only when `OPENAI_API_KEY` is set.
Set `OPENAI_BASE_URL` if using an OpenAI-compatible local or hosted endpoint.

## Full Run (Docker)
Place samples under:
- `./data/malware`
- `./data/benign`

Then run:

```bash
export OPENAI_API_KEY="your-key-here"
docker compose build
docker compose run --rm llmyara \
  --mode full \
  --compare-all \
  --malware-dir /data/malware \
  --benign-dir /data/benign \
  --out /outputs/final_compare \
  --backend openai
```

## Final Run Sequence
1. Run a real backend once and save the cache:
```bash
export OPENAI_API_KEY="your-key-here"
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
3. Write the report from the saved result bundle, not from ad hoc reruns.

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
- `export-audit-bundle`

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

`summary.json` now reports both:
- all-family aggregates in `mean_f1`, `mean_tpr_target`, `mean_fpr_benign`
- all-family research metrics in `mean_rule_specificity`, `mean_rule_complexity`
- ok-only aggregates in `mean_f1_ok_only`, `mean_tpr_target_ok_only`, `mean_fpr_benign_ok_only`

This avoids overstating performance when some families end in `missing_rule`, `compile_failed`, or `scan_error`.

`results_per_family.csv` also includes:
- `off_target_rate`
- `rule_specificity`
- `rule_string_count`
- `condition_clause_count`
- `rule_complexity`
- `rule_bytes`

## Audit Bundle Export
To export a safe, reviewable subset of saved results without copying the entire `outputs/` tree:

```bash
python -m llmyara.cli export-audit-bundle \
  --primary-run-dir /absolute/path/to/outputs/final_compare \
  --replay-run-dir /absolute/path/to/outputs/final_compare_replay \
  --out /absolute/path/to/artifacts/final_audit_bundle
```

The exported bundle contains sanitized summaries and manifests with local output paths removed.
It also includes:
- `significance_vs_primary.json`
- `failure_analysis.json`

## Reproducibility
- Use fixed seeds from `configs/default.yaml`.
- Use backend `replay` for deterministic regeneration from cached responses.
- Each run persists artifacts in one folder (`outputs/<run_id>/`).
- `run-all-compare` writes unified all-method comparison artifacts under `comparison/`.
- Primary runs also persist `llm_cache.jsonl` and `comparison_run_manifest.json` for replay and result export.
- `run_manifest.json` and `comparison_run_manifest.json` include run metadata and artifact hashes.
- audit export backfills missing manifest metadata when older runs do not contain those fields.

## Baseline Labeling Policy
When reporting comparisons, label each method as one of:
- `reproduced`
- `re-implemented`
- `paper-only`

Use `paper-only` only for cited related work that was not executed from this repository.
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
