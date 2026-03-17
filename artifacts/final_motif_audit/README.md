# Public Audit Bundle

Safe, reviewable export of final run metrics and manifests.

Contents:
- `primary_summary.json`: frozen primary run summary
- `replay_summary.json`: replay summary (if provided)
- `comparison_summary.json`: sanitized same-split comparison summary
- `comparison_rows.csv`: sanitized comparison table
- `significance_vs_primary.json`: paired significance checks for per-family F1
- `failure_analysis.json`: missing-rule / rejection breakdown
- `results_per_family.csv`: primary per-family results
- `run_manifest.json`: sanitized primary run manifest

Primary source: `/Users/boussetayassir/Desktop/malware analysis/project/outputs/final_motif_openai`
Replay source: `/Users/boussetayassir/Desktop/malware analysis/project/outputs/final_motif_replay`
