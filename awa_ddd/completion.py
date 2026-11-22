"""One completion authority shared by legacy/V2 facades, hosts and publishers."""
from __future__ import annotations

import hashlib

from .store import EngineError, canonical

SCHEMA = "awa-completion/v1"


class CompletionEvaluator:
    @staticmethod
    def evaluate(*, model, subject_id, has_scope, coverage_complete, counts,
                 frontier_current, material_current=True, source_complete=True,
                 checkpoint_current=True,
                 finalized=False, partial_accepted=False, stopped=False, next_action=None):
        if model not in {"v1", "v2"} or not isinstance(subject_id, str):
            raise EngineError("completion_subject", "Completion requires a concrete model and scope identity")
        if not isinstance(counts, dict) or any(type(value) is not int or value < 0 for value in counts.values()):
            raise EngineError("completion_counts", "Completion counts must be nonnegative integers")
        unresolved = sum(counts.values())
        # Acceptance of a bounded partial delivery is an independent decision.
        # Even a campaign whose current work happens to be exhausted cannot
        # acquire completion or automatic-stop authority through that path.
        ready = bool(has_scope and coverage_complete and not unresolved and frontier_current
                     and material_current and source_complete and checkpoint_current
                     and not stopped and not partial_accepted)
        can_claim = ready and finalized is True
        blocked = not material_current or not source_complete or bool(counts.get("blocked", 0)
            or counts.get("effect_unknown", 0) or counts.get("unresolved", 0))
        state = ("complete_for_declared_scope" if ready else "partial_accepted" if partial_accepted
                 else "blocked" if blocked else "partial_available")
        reasons = [key for key, value in sorted(counts.items()) if value]
        for condition, label in ((has_scope, "declared_scope_missing"), (coverage_complete, "coverage_incomplete"),
                                 (frontier_current, "frontier_review_required"), (material_current, "material_not_current"),
                                 (source_complete, "source_incomplete"),
                                 (checkpoint_current, "checkpoint_stale"),
                                 (not stopped, "authorized_stop")):
            if not condition:
                reasons.append(label)
        facts = {"schema": SCHEMA, "model": model, "subject_id": subject_id, "state": state,
                 "counts": dict(sorted(counts.items())), "material_current": bool(material_current),
                 "source_complete": bool(source_complete), "frontier_current": bool(frontier_current),
                 "checkpoint_current": bool(checkpoint_current),
                 "can_finalize": ready, "can_claim_complete": can_claim, "finalized": finalized is True,
                 "partial_report_allowed": True, "registered_scope_only": True,
                 "site_wide_discovery_allowed": False, "continue_required": not (can_claim or stopped),
                 "reason_codes": reasons, "next_action": next_action}
        facts["id"] = "CD-" + hashlib.sha256(canonical(facts).encode("utf-8")).hexdigest()
        return facts


def declared_scope_ready(*, has_scope, coverage_complete, counts, frontier_current,
                         material_current=True, source_complete=True):
    return CompletionEvaluator.evaluate(model="v1", subject_id="declared", has_scope=has_scope,
        coverage_complete=coverage_complete, counts=counts, frontier_current=frontier_current,
        material_current=material_current, source_complete=source_complete)["can_finalize"]
