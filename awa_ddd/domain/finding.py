"""Findings: machine-confirmed and reviewed-confirmed detection are equal detections
but unequal evidence quality.  A hint is never a finding."""
from __future__ import annotations

from .common import digest, enum, optional_text, sequence, stable_id, string_list, text, utc_now

MODES = {"machine", "reviewed"}
STATUSES = {"machine_confirmed", "reviewed_confirmed", "rejected", "withdrawn"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}


def new_finding(*, hypothesis_id, run_id=None, review_id=None, mode, severity, title,
                category, impact, remediation, evidence_ids, proof_scope,
                confidence=None, limitations=None, decision_id=None, legacy_unlinked=False):
    enum(mode, "finding_mode", MODES)
    enum(severity, "finding_severity", SEVERITIES)
    title = text(title, "title", maximum=512)
    category = text(category, "category", maximum=128)
    impact = text(impact, "impact")
    remediation = text(remediation, "remediation")
    evidence_ids = sequence(evidence_ids, "evidence_ids", maximum=256)
    text(proof_scope, "proof_scope", maximum=128)
    if mode == "machine" and not decision_id:
        from .common import fail
        fail("v2_finding_proof", "machine finding requires a current machine decision")
    if mode == "reviewed" and not review_id:
        from .common import fail
        fail("v2_finding_review", "reviewed finding requires an accepted review contract")
    status = "machine_confirmed" if mode == "machine" else "reviewed_confirmed"
    identity = {"hypothesis": hypothesis_id, "run": run_id, "review": review_id,
                "title": title, "category": category}
    return {
        "id": stable_id("FND", identity),
        "schema": 2,
        "hypothesis_id": text(hypothesis_id, "hypothesis_id", maximum=128),
        "run_id": optional_text(run_id, "run_id", maximum=128),
        "test_run_id": optional_text(run_id, "test_run_id", maximum=128),
        "review_id": optional_text(review_id, "review_id", maximum=128),
        "decision_id": optional_text(decision_id, "decision_id", maximum=128),
        "mode": mode,
        "status": status,
        "severity": severity,
        "confidence": confidence if isinstance(confidence, str) else None,
        "title": title,
        "category": category,
        "impact": impact,
        "remediation": remediation,
        "evidence_ids": evidence_ids,
        "proof_scope": proof_scope,
        "limitations": string_list(limitations or [], "limitations", maximum=64),
        "legacy_unlinked": bool(legacy_unlinked),
        "current": True,
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }


def update_status(finding, status, *, reviewer, reason, replacement_id=None):
    enum(status, "finding_status", {"active", "withdrawn", "superseded"})
    text(reviewer, "reviewer", maximum=200)
    text(reason, "reason")
    if status == "superseded":
        if not replacement_id or replacement_id == finding["id"]:
            from .common import fail
            fail("v2_finding_replacement", "Superseded findings require a distinct replacement")
        finding["superseded_by"] = replacement_id
    if status == "withdrawn":
        finding["current"] = False
    finding.setdefault("lifecycle", []).append({
        "status": status, "reviewer": reviewer, "reason": reason,
        "replacement_id": replacement_id, "at": utc_now()})
    finding["status"] = finding["status"] if status == "active" else status
    finding["current"] = status == "active"
    finding["updated_at"] = utc_now()
    return finding


def summary(findings):
    current = [row for row in findings if row.get("current")]
    return {
        "current_total": len(current),
        "machine_confirmed": sum(row.get("mode") == "machine" for row in current),
        "reviewed_confirmed": sum(row.get("mode") == "reviewed" for row in current),
        "legacy_unlinked": sum(bool(row.get("legacy_unlinked")) for row in current),
        "all_total": len(findings),
    }
