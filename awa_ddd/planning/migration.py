"""Legacy v1 → v2 projections and migration ledger.

Old decisions are evaluations, not new target executions.  Migration creates
``legacy_evaluation`` projection rows that reference the original decision and
its actual evidence/run relations; it never fabricates a TestRun.  The v1
store remains writable while v2 profiles are shadow/read-only until an
explicit migration ledger is applied.
"""
from __future__ import annotations

import hashlib

from .. import engine
from ..domain.hypothesis import FAMILIES, new_hypothesis
from ..domain.repository import Repository
from ..store import canonical
from .campaign import build_universe


def project_legacy(project, *, apply=False, confirm=False):
    repository = Repository(project, read_only=not apply)
    obligations = [row for row in project.list("obligation") if not row.get("superseded")]
    operations = {row["id"]: row for row in project.list("operation")}
    decisions = project.list("decision")
    findings = project.list("finding")
    evidence_by_id = {row["id"]: row for row in project.list("evidence")}
    universe = build_universe(project, read_only=not apply)
    hypotheses = []
    for obligation in obligations:
        operation = operations.get(obligation.get("operation_id"))
        if operation is None:
            continue
        family = obligation.get("test_family") or obligation.get("scope_family") or "generic"
        prop = obligation.get("kind", "legacy_obligation")
        hypothesis = new_hypothesis(
            family=family if family in FAMILIES else "generic",
            security_property=prop, operation_id=operation["id"],
            input_key=None, scope_epoch=universal_scope(project), target_build=universe["target_build"],
            source_kind="legacy_obligation", statement=f"Legacy obligation {obligation['id']} ({prop}); preserved as history.",
            status="ready" if obligation.get("status") in {"open", "evaluated"} else "blocked")
        hypothesis["legacy_obligation_id"] = obligation["id"]
        hypothesis["legacy_status"] = obligation.get("status")
        hypotheses.append(hypothesis)
    legacy_evaluations = []
    for decision in decisions:
        run_ids = sorted({evidence_by_id[eid].get("run_id") for eid in decision.get("evidence_ids", [])
                          if eid in evidence_by_id and evidence_by_id[eid].get("run_id")})
        legacy_evaluations.append({
            "id": "LEV-" + hashlib.sha256(decision["id"].encode()).hexdigest()[:24],
            "schema": 2,
            "kind": "legacy_evaluation",
            "decision_id": decision["id"],
            "obligation_id": decision.get("obligation_id"),
            "operation_id": decision.get("operation_id"),
            "outcome": decision.get("outcome"),
            "oracle": decision.get("oracle"),
            "evidence_ids": decision.get("evidence_ids", []),
            "actual_run_ids": run_ids,
            "completion_facts_available": bool(run_ids),
            "mode": decision.get("mode"),
            "created_at": decision.get("created_at"),
            "notice": "Legacy evaluation preserved; no new TestRun was created and missing execution facts stay unavailable.",
        })
    projected_findings = []
    for finding in findings:
        decision = next((row for row in decisions if row["id"] == finding.get("decision_id")), None)
        linked = bool(decision and decision.get("obligation_id"))
        projected_findings.append({
            "id": "LFD-" + hashlib.sha256(finding["id"].encode()).hexdigest()[:24],
            "schema": 2,
            "source_finding_id": finding["id"],
            "decision_id": finding.get("decision_id"),
            "hypothesis_id": None,
            "legacy_unlinked": not linked,
            "mode": finding.get("mode"),
            "status": finding.get("status"),
            "title": finding.get("title"),
        })
    projection = {
        "schema": 2,
        "source_schema": "v1",
        "universe_snapshot_hash": universe["snapshot_hash"],
        "source_counts": {"obligations": len(obligations), "decisions": len(decisions),
                          "findings": len(findings), "operations": len(operations)},
        "hypotheses": hypotheses,
        "legacy_evaluations": legacy_evaluations,
        "findings": projected_findings,
        "synthetic_test_runs": 0,
        "v1_writable": True,
        "v2_access": "shadow_read_only" if not apply else "migrated",
    }
    projection["projection_sha256"] = hashlib.sha256(canonical(projection).encode()).hexdigest()
    if apply:
        if not confirm:
            from ..store import EngineError
            raise EngineError("v2_migration_confirm", "Migration apply requires confirm:true")
        if repository.list("migration", limit=1)[0]:
            from ..store import EngineError
            raise EngineError("v2_migration_exists", "A migration ledger already exists; use rollback before re-applying")
        ledger = {
            "id": "MIG-" + projection["projection_sha256"][:24],
            "schema": 2,
            "source_schema": "v1",
            "source_counts": projection["source_counts"],
            "projection_sha256": projection["projection_sha256"],
            "synthetic_test_runs": 0,
            "applied_at": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc).isoformat(),
            "rollback": "config.assessment_model=v1; v2 records remain immutable history",
        }
        repository.add("migration", ledger, immutable=True)
        for hypothesis in projection["hypotheses"]:
            if repository.get("hypothesis", hypothesis["id"], required=False) is None:
                repository.add("hypothesis", hypothesis, immutable=False)
        for evaluation in projection["legacy_evaluations"]:
            repository.add("legacy_evaluation", evaluation, immutable=True)
        config = dict(project.config)
        config["assessment_model"] = "v2"
        project.set_config(config)
        return {"ledger": ledger, "projection": _summary(projection)}
    return {"projection": _summary(projection), "writes": 0}


def universal_scope(project):
    from ..domain.common import digest
    config = project.config
    return digest([config.get("scope"), config.get("exclude")])


def _summary(projection):
    return {key: projection[key] for key in (
        "source_schema", "universe_snapshot_hash", "source_counts", "synthetic_test_runs",
        "v1_writable", "v2_access", "projection_sha256")} | {
        "legacy_evaluation_total": len(projection["legacy_evaluations"]),
        "legacy_hypothesis_total": len(projection["hypotheses"]),
        "legacy_unlinked_findings": sum(row["legacy_unlinked"] for row in projection["findings"]),
    }


def rollback(project, args):
    ledger_id = args.get("ledger_id")
    repository = Repository(project)
    ledger = repository.get("migration", ledger_id)
    config = dict(project.config)
    config["assessment_model"] = "v1"
    project.set_config(config)
    return {"rolled_back_to": "v1", "ledger_id": ledger["id"],
            "v2_history_preserved": True}
