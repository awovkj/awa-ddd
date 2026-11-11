"""Review acceptance, disposition and proof binding for 2.0 findings."""
from __future__ import annotations

from .. import engine
from ..domain import new_finding, new_review_contract, validate_cross_role
from ..domain.common import digest, fail, text
from ..domain.repository import Repository
from ..domain.review import public_view as review_public
from ..domain.test_run import public_view as run_public
from ..domain.hypothesis import transition


def _current_evidence(project, evidence_id):
    try:
        evidence, artifact = engine.verify_current_evidence(project, evidence_id)
    except (engine.EngineError, OSError, ValueError, KeyError) as exc:
        fail("v2_review_material", f"Reviewed evidence is not current: {evidence_id}")
    return evidence, artifact


def accept(project, args):
    repository = Repository(project)
    hypothesis = repository.get("hypothesis", args["hypothesis_id"])
    run_row = repository.get("run", args["run_id"])
    if run_row.get("status") not in {"evaluated", "published"}:
        fail("v2_review_run", "Reviewed findings require a completed evaluated run")
    if run_row.get("hypothesis_id") != hypothesis["id"]:
        fail("v2_review_hypothesis", "Run and hypothesis do not match")
    evidence_ids = args.get("evidence_ids") or run_row.get("evidence_ids") or []
    run_evidence = set(run_row.get("evidence_ids") or [])
    if not set(evidence_ids).issubset(run_evidence):
        fail("v2_review_material", "Review may only cite evidence produced by its run")
    material = args.get("material") or {}
    material_ids = material.get("evidence_ids") or evidence_ids
    if not set(material_ids).issubset(run_evidence):
        fail("v2_review_material", "Review material must be a subset of the run evidence")
    digests = {}
    for evidence_id in material_ids:
        evidence, _artifact = _current_evidence(project, evidence_id)
        digests[evidence_id] = evidence.get("sha256")
    supplied = material.get("digests") or {}
    if supplied and supplied != digests:
        fail("v2_review_material", "Review material digest does not match current evidence")
    mechanism = args.get("mechanism") or {}
    mechanism.setdefault("family", hypothesis["family"])
    mechanism.setdefault("security_property", hypothesis["security_property"])
    mechanism.setdefault("operation_id", hypothesis["operation_id"])
    mechanism.setdefault("input_key", hypothesis["input_key"])
    identity = args.get("identity") or {}
    recipe = repository.get("recipe", run_row["recipe_id"], required=False) if run_row.get("recipe_id") else None
    if recipe:
        binding_session = (recipe.get("bindings") or {}).get("session") or {}
        binding_resource = (recipe.get("bindings") or {}).get("resource") or {}
        if identity.get("actor_id") and binding_session.get("actor_id") \
                and identity.get("actor_id") != binding_session.get("actor_id"):
            fail("v2_review_identity", "Review actor does not match the frozen recipe session")
        if identity.get("resource_id") and binding_resource.get("resource_id") \
                and identity.get("resource_id") != binding_resource.get("resource_id"):
            fail("v2_review_identity", "Review resource does not match the frozen recipe")
    contract = new_review_contract(
        hypothesis=hypothesis, run=run_row, mechanism=mechanism, identity=identity,
        control_groups=args.get("control_groups") or [], observation=args.get("observation") or {},
        consumer_point=args.get("consumer_point") or {}, source_trust=args.get("source_trust") or {},
        reviewer=args.get("reviewer") or {}, proof_scope=args.get("proof_scope") or {},
        material={"evidence_ids": material_ids, "digests": digests},
        verification=args.get("verification") or {})
    validate_cross_role(contract, hypothesis=hypothesis, run=run_row)
    repository.add("review", contract, immutable=True)
    finding = new_finding(
        hypothesis_id=hypothesis["id"], run_id=run_row["id"], review_id=contract["id"],
        mode="reviewed", severity=args.get("severity") or "medium",
        title=args.get("title") or f"Reviewed: {hypothesis['security_property']}",
        category=hypothesis["family"], impact=args.get("impact") or "Reviewed detection accepted under a bounded proof scope.",
        remediation=args.get("remediation") or "Apply the mechanism-specific fix and re-test.",
        evidence_ids=material_ids, proof_scope=contract["proof_scope"]["accepted"][0],
        confidence=args.get("confidence") or "reviewed",
        limitations=contract["proof_scope"]["not_proven"] or ["Reviewed detection is not machine proof."])
    repository.add("finding", finding, immutable=False)
    hypothesis["finding_ids"] = sorted(set(hypothesis.get("finding_ids", []) + [finding["id"]]))
    if hypothesis["status"] not in {"supported"}:
        transition(hypothesis, "supported", reason="reviewed detection accepted")
    repository.save("hypothesis", hypothesis)
    from ..assessment_mode import record_stop
    record_stop(project, operation_id=hypothesis["operation_id"], evidence_ids=material_ids,
                finding_id=finding["id"], oracle_type="analyst_review")
    return {"review": review_public(contract), "finding": finding,
            "machine_proof": False, "detection": True,
            "reviewer_independent": contract["reviewer"]["independent_human"]}


def disposition(project, args):
    repository = Repository(project)
    hypothesis = repository.get("hypothesis", args["hypothesis_id"])
    status = args["status"]
    if status not in {"blocked", "not_applicable", "ready"}:
        fail("v2_review_disposition", "status must be blocked, not_applicable or ready")
    if status == "blocked":
        prerequisite = text(args.get("prerequisite"), "prerequisite", maximum=1024)
        missing = args.get("missing_context") or hypothesis.get("missing_context") or []
        if not missing:
            fail("v2_review_disposition", "Blocked disposition requires concrete missing_context")
        hypothesis["missing_context"] = list(missing)
        hypothesis["blocked_prerequisite"] = prerequisite
        transition(hypothesis, "blocked", reason=prerequisite, missing_context=missing)
    elif status == "not_applicable":
        basis = args.get("applicability_basis") or {}
        if not isinstance(basis, dict) or not basis.get("business_fact"):
            fail("v2_review_disposition", "not_applicable requires a business-fact applicability basis")
        evidence_ids = args.get("evidence_ids") or []
        if not evidence_ids:
            fail("v2_review_disposition", "not_applicable requires current applicability evidence")
        for evidence_id in evidence_ids:
            _current_evidence(project, evidence_id)
        hypothesis["applicability_basis"] = {"business_fact": text(basis["business_fact"], "business_fact"),
                                             "evidence_ids": evidence_ids,
                                             "declared_by": args.get("reviewer")}
        transition(hypothesis, "not_applicable", reason=basis["business_fact"])
    else:
        transition(hypothesis, "ready", reason=args.get("reason") or "prerequisites rechecked")
    repository.save("hypothesis", hypothesis)
    return {"hypothesis": hypothesis, "status": hypothesis["status"],
            "counts_as_tested": False if status == "not_applicable" else None}


def bind(project, args):
    """Upgrade a reviewed finding using an existing machine evaluation, preserving history."""
    repository = Repository(project)
    finding = repository.get("finding", args["finding_id"])
    if finding.get("status") != "reviewed_confirmed" or not finding.get("current"):
        fail("v2_review_bind", "Only a current reviewed finding can be bound")
    run_row = repository.get("run", args["run_id"])
    if run_row.get("status") != "evaluated" or run_row.get("hypothesis_id") != finding["hypothesis_id"]:
        fail("v2_review_bind", "Machine proof must be an evaluated run for the same hypothesis")
    evaluation = run_row.get("evaluation") or {}
    if evaluation.get("outcome") != "supported" or not evaluation.get("finding_allowed"):
        fail("v2_review_bind", "Machine run did not produce a confirmable result")
    if not set(finding.get("evidence_ids") or []).issubset(set(run_row.get("evidence_ids") or [])):
        fail("v2_review_bind", "Reviewed evidence is not a subset of the machine run evidence")
    machine = new_finding(
        hypothesis_id=finding["hypothesis_id"], run_id=run_row["id"], mode="machine",
        severity=finding["severity"], title=finding["title"], category=finding["category"],
        impact=finding["impact"], remediation=finding["remediation"],
        evidence_ids=finding["evidence_ids"], proof_scope=evaluation.get("proof_scope") or "machine",
        decision_id=run_row["id"], limitations=evaluation.get("limitations") or [])
    repository.add("finding", machine, immutable=False)
    finding["current"] = False
    finding["superseded_by"] = machine["id"]
    finding.setdefault("lifecycle", []).append({"status": "superseded", "reviewer": args.get("reviewer"),
                                                "reason": args.get("reason"), "replacement_id": machine["id"],
                                                "at": __import__("datetime").datetime.now(
                                                    __import__("datetime").timezone.utc).isoformat()})
    repository.save("finding", finding)
    return {"finding": machine, "superseded_finding_id": finding["id"], "machine_proof": True}


def evidence_view(project, args):
    repository = Repository(project)
    if args.get("review_id"):
        return {"review": review_public(repository.get("review", args["review_id"]))}
    if args.get("run_id"):
        return {"run": run_public(repository.get("run", args["run_id"]))}
    fail("v2_review_evidence", "review.evidence requires review_id or run_id")
