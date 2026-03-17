# Paper Baseline Matrix

Read when:
- mapping literature claims to repo commands
- preparing the final comparison table
- explaining which methods were actually executed on the repo split
- deciding `reproduced` vs `re-implemented` vs `paper-only`

## Repo-Executed Comparison Set

These are the methods actually run on the frozen repo split and included in the final same-split comparison bundle.

| Executed method | Repo command or artifact | Status label | Type | Notes |
|---|---|---|---|---|
| `llmyara-llm` | `python -m llmyara.cli run-all-compare ...` | `primary` | LLM-based method | Static-only structured generation with compile/repair/gating. |
| `topstrings` | `python -m llmyara.cli baseline-topstrings ...` | `reproduced` | Deterministic repo baseline | Same evaluation split as the primary method. Included because it is a strong, auditable static baseline on this repo. |
| `apiary-static` | `python -m llmyara.cli baseline-apiary-static ...` | `re-implemented` | Literature-inspired baseline | Static import/API discriminative proxy evaluated on the same split. |
| `autoyara-bicluster` | `python -m llmyara.cli baseline-autoyara ...` | `re-implemented` | Literature-inspired baseline | Deterministic byte n-gram + bicluster-style approximation evaluated on the same split. |

## Paper-to-Repo Mapping

| Paper / method | Repo command or artifact | Status label | Notes |
|---|---|---|---|
| APIARY (2025) | `python -m llmyara.cli baseline-apiary-static ...` | `re-implemented` | Static import/API discriminative proxy. Same evaluation split as repo pipeline. |
| AutoYara (2020) | `python -m llmyara.cli baseline-autoyara ...` | `re-implemented` | Practical byte n-gram + bicluster-style rule synthesis. Deterministic, bounded, static-only approximation. |
| YAMME (2023) | not shipped | `paper-only` | Cited related work. Not executed on the repo split. Do not report as implemented. |
| PackGenome (2023) | citation only | `paper-only` | Hybrid / packer-oriented. Not directly comparable on this repo split. |
| RULELLM (2025) | design reference only | design reference | Informs the structured LLM + repair flow. Not a standalone baseline command here. |

## Reporting Guidance
- Use the **Repo-Executed Comparison Set** for any same-split empirical claim.
- Use the **Paper-to-Repo Mapping** to explain literature coverage, deviations, and why some cited methods were not run.
- If a method was not executed from this repo on this split, do not place it in the same quantitative table as repo-run methods unless it is explicitly labeled `paper-only`.

## Reporting Guardrails
- Use `reproduced` only when the original implementation is actually executed.
- Use `re-implemented` for repo-native approximations built from paper descriptions.
- Use `paper-only` for cited numbers that were not run on the repo split.
- Use `primary` only for the main LLM method shipped in this repo.
- Treat `topstrings` as a repo-executed baseline, not as a paper reproduction claim.
- Do not mix `paper-only` metrics into the same “same split” claim as repo-evaluated methods.
