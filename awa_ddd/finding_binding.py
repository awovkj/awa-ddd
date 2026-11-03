"""Replace an unbound reviewed finding using existing, current typed proof."""
from __future__ import annotations

from . import assessment, engine, workflow
from .store import EngineError


def _arguments(args):
    if not isinstance(args, dict) or set(args) - {"project_id", "finding_id", "decision_id", "reviewer", "reason"}:
        raise EngineError("finding_binding", "finding.bind accepts finding_id, decision_id, reviewer and reason")
    for field in ("finding_id", "decision_id", "reviewer", "reason"):
        value = args.get(field)
        limit = 128 if field.endswith("_id") else 4000
        if not isinstance(value, str) or not value.strip() or len(value) > limit:
            raise EngineError("finding_binding", f"{field} must be a nonempty string of at most {limit} characters")


def bind_finding(project, args):
    """No target traffic: preserve the old proof and append a supported replacement."""
    _arguments(args)
    with project.transaction():
        original = project.get("finding", args["finding_id"])
        if original.get("mode") != "analyst" or original.get("status") != "confirmed" \
                or original.get("lifecycle_status", "active") != "active" \
                or original.get("replacement_finding_id"):
            raise EngineError("finding_binding_lifecycle", "Only a current active analyst finding without a replacement can be bound")
        if assessment.is_xss_category(original.get("category")):
            raise EngineError("finding_binding_channel", "XSS binding uses finding.record with the existing reviewed runtime and exact input controls",
                              {"next_action": "finding.record", "help_input": {"name": "finding.record"}})
        original_decision = project.get("decision", original["decision_id"])
        if original_decision.get("mode") != "analyst" or original_decision.get("outcome") != "confirmed" \
                or original_decision.get("evidence_ids") != original.get("evidence_ids"):
            raise EngineError("finding_binding_source", "The original analyst decision and its immutable supporting evidence must match")
        engine._decision_valid(project, original_decision)
        assessment.validate_confirmation(project, original_decision, original["category"])
        prior_item = project.get("obligation", original_decision.get("obligation_id"), required=False)
        if prior_item and not prior_item.get("superseded") and prior_item.get("status") == "evaluated":
            raise EngineError("finding_binding_duplicate", "This analyst finding already has a valid evaluated obligation")

        proof, item, operation = assessment.current_machine_proof(project, args["decision_id"], original["category"])
        support = original.get("evidence_ids")
        if not isinstance(support, list) or not 1 <= len(support) <= 100 \
                or any(not isinstance(identity, str) or not identity for identity in support) \
                or len(set(support)) != len(support) or not set(proof["evidence_ids"]).issubset(support):
            raise EngineError("evidence_binding", "Every typed proof observation must already belong to the original finding's distinct supporting evidence")
        proof_operations = {project.get("evidence", identity)["operation_id"] for identity in proof["evidence_ids"]}
        if proof["oracle"]["type"] != "state_transition" and proof_operations != {operation["id"]}:
            raise EngineError("evidence_binding", "The typed proof must belong to the finding's exact operation")
        # A state_transition was fully revalidated by current_machine_proof,
        # including its genuine scenario checkpoints and explicit readback scope.
        # No other cross-operation source can use this exception.
        for identity in support:
            current, _ = engine.verify_current_evidence(project, identity)
            if current["operation_id"] not in proof_operations:
                raise EngineError("evidence_binding", "An unrelated operation in the original finding cannot be merged into this typed proof")
        if original_decision.get("operation_id") not in {None, operation["id"]}:
            raise EngineError("evidence_binding", "The original reviewed operation differs from the typed proof's action operation")

        for existing in project.list("finding"):
            if existing["id"] == original["id"] or existing.get("lifecycle_status", "active") != "active":
                continue
            existing_decision = project.get("decision", existing.get("decision_id"), required=False) or {}
            if existing.get("decision_id") == proof["id"] or existing_decision.get("proof_decision_id") == proof["id"]:
                raise EngineError("finding_binding_duplicate", "The selected typed proof already supports another active finding")

        replacement = assessment.record_finding(project, {
            "mode": "machine", "decision_id": proof["id"],
            **{field: original[field] for field in ("title", "category", "impact", "remediation")},
            "severity": original.get("severity", "medium"), "origin": original.get("origin", "independent"),
            "limitations": list(original.get("limitations", [])),
        })
        lifecycle = workflow.update_finding(project, {
            "finding_id": original["id"], "status": "superseded", "replacement_finding_id": replacement["id"],
            "reviewer": args["reviewer"], "reason": args["reason"],
        })
        project.event("finding.proof_bound", {
            "finding_id": replacement["id"], "source_finding_id": original["id"],
            "proof_decision_id": proof["id"], "obligation_id": item["id"],
            "revision_id": lifecycle["revision"]["id"], "reviewer": args["reviewer"].strip(), "reason": args["reason"].strip(),
        })
        return {"finding": replacement, "previous_finding": lifecycle["finding"], "revision": lifecycle["revision"],
                "decision_id": proof["id"], "obligation_id": item["id"], "requests_sent": 0,
                "original_proof_preserved": True}
