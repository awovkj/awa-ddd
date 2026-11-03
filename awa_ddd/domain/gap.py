"""Explicit gaps: missing surface, semantics, family coverage or provider readiness."""
from __future__ import annotations

from .common import enum, optional_text, sequence, stable_id, text

KINDS = {"route", "page", "function", "operation", "input", "consumer", "family", "capability",
         "prerequisite", "unknown_extent"}
NEXT_ACTIONS = {"recon.snapshot", "recon.import", "recon.routes", "recon.capabilities",
                "review.disposition", "test.run", "campaign.next", "preparation"}


def new_gap(*, kind, scope, reason, next_action, detail=None, hypothesis_id=None):
    enum(kind, "gap_kind", KINDS)
    text(scope, "gap_scope", maximum=512)
    text(reason, "gap_reason", maximum=1024)
    enum(next_action, "gap_next_action", NEXT_ACTIONS)
    identity = {"kind": kind, "scope": scope, "reason": reason, "hypothesis": hypothesis_id}
    return {
        "id": stable_id("GAP", identity),
        "schema": 2,
        "kind": kind,
        "scope": scope,
        "reason": reason,
        "next_action": next_action,
        "detail": detail if isinstance(detail, dict) else {},
        "hypothesis_id": optional_text(hypothesis_id, "hypothesis_id", maximum=128),
        "status": "open",
        "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
    }


def summary(gaps):
    counts = {}
    for gap in gaps:
        if gap.get("status", "open") == "open":
            counts[gap["kind"]] = counts.get(gap["kind"], 0) + 1
    return {"open_total": sum(counts.values()), "by_kind": counts}
