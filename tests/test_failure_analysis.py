from __future__ import annotations

from llmyara.eval.failure_analysis import summarize_generation_failures


def test_summarize_generation_failures_buckets_rejections() -> None:
    summary = summarize_generation_failures(
        {
            "families": {
                "fam_ok": {"status": "accepted"},
                "fam_a": {"status": "rejected", "reason": "train_target_hits_below_min:0<1"},
                "fam_b": {"status": "rejected", "reason": "benign_dev_fpr_exceeded:0.25"},
            }
        }
    )

    assert summary["families_total"] == 3
    assert summary["families_accepted"] == 1
    assert summary["families_rejected"] == 2
    assert summary["reason_counts"]["train_target_hits_below_min"] == 1
    assert summary["reason_counts"]["benign_dev_fpr_exceeded"] == 1
