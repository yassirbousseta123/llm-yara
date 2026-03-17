# Public Audit Bundle

Safe, reviewable export of final run metrics and manifests.

Contents:
- `primary_summary.json`: frozen primary run summary
- `replay_summary.json`: replay summary (if provided)
- `comparison_summary.json`: sanitized same-split comparison summary
- `comparison_rows.csv`: sanitized comparison table
- `results_per_family.csv`: primary per-family results
- `run_manifest.json`: sanitized primary run manifest

Primary source: `outputs/final_motif_openai`
Replay source: `outputs/final_motif_replay`
