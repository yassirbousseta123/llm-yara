from __future__ import annotations

from collections import Counter
from typing import Any


def _reason_bucket(reason: str | None) -> str:
    if not reason:
        return "unknown"
    if ":" in reason:
        return reason.split(":", 1)[0]
    return reason


def summarize_generation_failures(generation: dict[str, Any]) -> dict[str, Any]:
    families = generation.get("families", {})
    accepted = [family for family, payload in families.items() if payload.get("status") == "accepted"]
    rejected = {
        family: payload
        for family, payload in families.items()
        if payload.get("status") != "accepted"
    }

    reason_counts = Counter(_reason_bucket(payload.get("reason")) for payload in rejected.values())
    failure_families = [
        {
            "family": family,
            "reason": payload.get("reason"),
            "reason_bucket": _reason_bucket(payload.get("reason")),
            "repairs": int(payload.get("repairs", 0) or 0),
            "train_target_hits": int(payload.get("train_target_hits", 0) or 0),
            "scan_error_count": int(payload.get("scan_error_count", 0) or 0),
        }
        for family, payload in sorted(rejected.items())
    ]

    return {
        "families_total": len(families),
        "families_accepted": len(accepted),
        "families_rejected": len(rejected),
        "reason_counts": dict(sorted(reason_counts.items())),
        "failure_families": failure_families,
    }
