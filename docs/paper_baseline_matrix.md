# Paper Baseline Matrix

Read when:
- mapping literature claims to repo commands
- preparing the final comparison table
- deciding `reproduced` vs `re-implemented` vs `paper-only`

## Current Mapping

| Paper / method | Repo command or artifact | Status label | Notes |
|---|---|---|---|
| APIARY (2025) | `python -m llmyara.cli baseline-apiary-static ...` | `re-implemented` | Static import/API discriminative proxy. Same evaluation split as repo pipeline. |
| AutoYara (2020) | `python -m llmyara.cli baseline-autoyara ...` | `re-implemented` | Practical byte n-gram + bicluster-style rule synthesis. Deterministic, bounded, static-only approximation. |
| YAMME (2023) | not shipped yet | pending | Reserved for optional mutation/post-processing stage. Do not report as implemented. |
| PackGenome (2023) | citation only | `paper-only` | Hybrid / packer-oriented. Not directly comparable on this repo split. |
| RULELLM (2025) | design reference only | design reference | Informs bounded LLM + repair flow; not a standalone baseline command here. |

## Reporting Guardrails
- Use `reproduced` only when the original implementation is actually executed.
- Use `re-implemented` for repo-native approximations built from paper descriptions.
- Use `paper-only` for cited numbers that were not run on the repo split.
- Do not mix `paper-only` metrics into the same “same split” claim as repo-evaluated methods.
