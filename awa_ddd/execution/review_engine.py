"""Review acceptance, disposition and proof binding for 2.0 findings."""
from __future__ import annotations

from .. import applicability, engine, reviewed_detection
from ..domain import (
    new_applicability_receipt,
    new_finding,
    new_proof_receipt,
    new_review_contract,
    validate_cross_role,
)
from ..domain.common import digest, fail, text
from ..domain.receipt import (
    entity_dependency,
    evaluate_receipt,
    evidence_dependencies,
    new_dependency,
    scope_dependency,
    target_build_dependency,
)
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


def _context_dependencies(project, campaign, hypothesis, *, run=None, recipe=None,
                          review=None, evidence_ids=None):
    repository = Repository(project)
    universe = repository.get("universe", campaign.get("universe_id"))
    dependencies = [
        scope_dependency(project),
        target_build_dependency(project, universe),
        entity_dependency(
            project, "campaign", campaign["id"], fingerprint_fields=(
                "id", "project_id", "target", "objective", "model", "scope_snapshot",
                "exclude_snapshot", "scope_epoch", "max_rounds", "allow_mutation")),
        entity_dependency(
            project, "universe", universe["id"],
            fingerprint_fields=("id", "snapshot_hash", "scope_epoch")),
        entity_dependency(
            project, "hypothesis", hypothesis["id"], fingerprint_fields=(
                "id", "campaign_id", "universe_id", "mechanism_key", "identity_hash")),
    ]
    if recipe is not None:
        dependencies.append(entity_dependency(
            project, "recipe", recipe["id"], fingerprint_fields=(
                "id", "campaign_id", "universe_id", "hypothesis_id", "spec_hash")))
    if run is not None:
        dependencies.append(entity_dependency(
            project, "run", run["id"], fingerprint_fields=(
                "id", "campaign_id", "hypothesis_id", "recipe_id", "recipe_spec_hash",
                "mode", "evidence_ids", "evaluation", "outcome", "effect")))
    if review is not None:
        dependencies.append(new_dependency(
            kind="review",
            identity=review["id"],
            fingerprint=review["contract_hash"],
        ))
    dependencies.extend(evidence_dependencies(project, evidence_ids or []))
    return dependencies


def _campaign_for_entity(repository, entity, requested=None):
    actual = entity.get("campaign_id")
    campaign_id = requested or actual
    if not campaign_id or actual != campaign_id:
        fail("v2_campaign_scope", "Review requires one explicit campaign for every entity",
             expected_campaign_id=campaign_id, actual_campaign_id=actual)
    campaign = repository.get("campaign", campaign_id)
    if campaign.get("state") != "active":
        fail("v2_campaign_state", "Review actions require an active campaign")
    return campaign


def _applicability_item(repository, hypothesis):
    """Resolve a hypothesis input key to one exact campaign Universe input."""
    input_key = hypothesis.get("input_key")
    if not input_key:
        fail(
            "applicability_scope",
            "Not-applicable requires a hypothesis bound to one registered input",
        )
    universe = repository.get("universe", hypothesis.get("universe_id"))
    matches = []
    for operation in universe.get("operations", []):
        if operation.get("operation_id") != hypothesis.get("operation_id"):
            continue
        for item in operation.get("inputs", []):
            if item.get("input_key") == input_key:
                matches.append((operation, item))
    unique = {
        (
            operation["operation_id"],
            item.get("input_key"),
            item.get("location"),
            item.get("selector"),
            item.get("schema_branch"),
        )
        for operation, item in matches
    }
    if len(unique) != 1:
        fail(
            "applicability_scope",
            "Hypothesis input must resolve to exactly one Universe input branch",
            matches=len(unique),
        )
    _operation, input_row = matches[0]
    return {
        "id": hypothesis["id"],
        "kind": "hypothesis",
        "operation_id": hypothesis["operation_id"],
        "family": hypothesis["family"],
        "input_location": input_row["location"],
        "input_selector": input_row["selector"],
        "schema_branch": input_row.get("schema_branch"),
    }


def _reviewed_spec(args):
    direct = args.get("reviewed_proof")
    embedded = (args.get("verification") or {}).get("spec")
    if direct is not None and embedded is not None and digest(direct) != digest(embedded):
        fail("reviewed_proof", "reviewed_proof and verification.spec must be identical")
    return direct if direct is not None else embedded


def _prepare_reviewed(project, repository, campaign, hypothesis, args):
    """Validate reviewed detection and derive every review field from evidence."""
    spec = _reviewed_spec(args)
    if spec is None:
        fail(
            "reviewed_proof",
            "This mechanism family requires a typed reviewed detection specification",
        )
    if hypothesis.get("universe_id") != campaign.get("universe_id"):
        fail("v2_campaign_scope", "Review hypothesis belongs to a different Universe")
    reviewer = args.get("reviewer") or {}
    if not isinstance(reviewer, dict):
        fail("reviewed_reviewer", "reviewer must be an object")
    reason = args.get("reason")
    if reason is not None and spec.get("reason") is not None \
            and str(reason) != str(spec.get("reason")):
        fail("reviewed_reviewer", "Review reason conflicts with the reviewed proof")
    reason = reason if reason is not None else spec.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        fail("reviewed_reviewer", "Reviewed detection requires one explicit reason")
    if spec.get("reviewer") is not None and reviewer.get("id") is not None \
            and str(spec.get("reviewer")) != str(reviewer.get("id")):
        fail("reviewed_reviewer", "Reviewer conflicts with the reviewed proof")
    reviewer_id = reviewer.get("id") or spec.get("reviewer")
    if not isinstance(reviewer_id, str) or not reviewer_id.strip():
        fail("reviewed_reviewer", "Reviewed detection requires an explicit reviewer ID")
    reviewer_type = reviewer.get("type") or spec.get("reviewer_type") or "agent_recorded"
    normalized_spec = {
        **spec,
        "reviewer": reviewer_id,
        "reviewer_type": reviewer_type,
        "reason": reason,
    }
    item = _applicability_item(repository, hypothesis)
    prepared = reviewed_detection.prepare(project, item, normalized_spec)
    receipt = prepared["receipt"]
    bindings = receipt["bindings"]
    accepted_scope = {
        "unexpected_expression_evaluation": "template_evaluation",
        "bounded_side_effect": "bounded_side_effect",
        "unsafe_type_instantiation": "unsafe_type_instantiation",
        "upload_path_escape": "upload_path_escape",
    }.get(receipt["proof_scope"])
    if accepted_scope is None:
        fail("reviewed_profile", "Reviewed profile has no review proof scope")
    controls = [
        {
            "id": role,
            "role": role,
            "evidence_id": evidence_id,
        }
        for role, evidence_id in zip(
            ("normal", "attack", "negative"), receipt["evidence_ids"])
    ]
    selector = normalized_spec.get("selector") \
        or normalized_spec.get("readback_selector") or "/"
    if not isinstance(selector, str) or not selector.startswith("/"):
        fail("reviewed_selector", "Reviewed proof needs an exact JSON selector")
    mechanism = {
        "family": hypothesis["family"],
        "security_property": hypothesis["security_property"],
        "operation_id": hypothesis["operation_id"],
        "input_key": hypothesis["input_key"],
        "location": bindings["input_location"],
        "selector": bindings["input_selector"],
        "schema_branch": bindings.get("schema_branch"),
        "mechanism_note": receipt["profile"],
    }
    identity = {
        "actor_id": bindings.get("actor_id"),
        "session_generation": bindings.get("session_generation"),
        "resource_id": bindings.get("resource_id"),
    }
    return {
        "prepared": prepared,
        "receipt": receipt,
        "spec": normalized_spec,
        "item": item,
        "mechanism": mechanism,
        "identity": identity,
        "control_groups": [{
            "id": "reviewed-controls",
            "identity_role": str(bindings.get("actor_id") or "anonymous"),
            "resource_version": str(
                bindings.get("resource_id") or "unbound"),
            "controls": controls,
        }],
        "observation": {
            "selector": selector,
            "expected": receipt["profile"],
            "actual": receipt["observation_sha256"],
        },
        "consumer_point": {
            "type": "business_state",
            "identity_role": str(bindings.get("actor_id") or "anonymous"),
        },
        "source_trust": {
            "kind": "reviewed_detection",
            "trust": "unverified",
        },
        "reviewer": {
            "type": "agent_recorded",
            "id": reviewer_id,
            "source": reviewer.get("source") or "reviewed_detection",
        },
        "proof_scope": {
            "accepted": [accepted_scope],
            "not_proven": receipt["not_proven"],
        },
        "reason": reason,
    }


def _generic_control_ids(control_groups, run_evidence):
    if not isinstance(control_groups, list):
        fail("v2_review_controls", "Review control_groups must be an array")
    ids = []
    for group in control_groups:
        if not isinstance(group, dict) or not isinstance(group.get("controls"), list):
            fail("v2_review_controls", "Each review group requires controls")
        for control in group["controls"]:
            if not isinstance(control, dict):
                fail("v2_review_controls", "Review controls must be objects")
            evidence_id = control.get("evidence_id")
            if not isinstance(evidence_id, str) or evidence_id not in run_evidence:
                fail("v2_review_material",
                     "Every control evidence item must belong to the reviewed run",
                     evidence_id=evidence_id)
            ids.append(evidence_id)
    if len(set(ids)) != len(ids):
        fail("v2_review_controls", "A control evidence item cannot be rebound to multiple controls")
    return ids


def _generic_review_facts(project, hypothesis, run_row, recipe, args, material_ids):
    """Derive reviewer-visible facts instead of trusting ordinary tool arguments."""
    run_evidence = set(run_row.get("evidence_ids") or [])
    groups = args.get("control_groups") or []
    control_ids = _generic_control_ids(groups, run_evidence)
    observation = dict(args.get("observation") or {})
    attack_ids = [
        control["evidence_id"]
        for group in groups for control in group.get("controls", [])
        if control.get("role") == "attack"
    ]
    source_id = observation.get("evidence_id")
    if source_id is None and len(attack_ids) == 1:
        source_id = attack_ids[0]
    if source_id not in control_ids or source_id not in material_ids:
        fail("v2_review_observation",
             "Observation must name one attack/control evidence item from this run")
    evidence, artifact = _current_evidence(project, source_id)
    selector = observation.get("selector")
    if not isinstance(selector, str) or not selector:
        fail("v2_review_observation", "Observation requires an exact evidence selector")
    from .test_runner import _evidence_value
    actual = _evidence_value(project, source_id, selector)
    if actual is None:
        fail("v2_review_observation", "Observation selector has no actual value in the evidence")
    if "actual" in observation and digest(observation["actual"]) != digest(actual):
        fail("v2_review_observation",
             "Declared actual value does not match the selected run evidence")
    observation["actual"] = actual
    observation["evidence_id"] = source_id

    consumer = dict(args.get("consumer_point") or {})
    consumer_type = consumer.get("type")
    if consumer_type == "business_state" \
            and evidence.get("operation_id") != hypothesis.get("operation_id"):
        fail("v2_review_identity", "Business-state evidence belongs to another operation")
    captured_url = (artifact.get("request") or {}).get("url")
    if consumer_type != "business_state" and consumer.get("url") != captured_url:
        fail("v2_review_identity", "Consumer URL does not match its actual run evidence")
    observed_role = str(evidence.get("actor_id") or "anonymous")
    if str(consumer.get("identity_role") or observed_role) != observed_role:
        fail("v2_review_identity", "Consumer identity differs from the observed evidence")
    consumer["identity_role"] = observed_role

    supplied_identity = args.get("identity") or {}
    if not isinstance(supplied_identity, dict):
        fail("v2_review_identity", "Review identity must be an object")
    actor = project.get("actor", evidence.get("actor_id"), required=False) \
        if evidence.get("actor_id") else None
    fixture_id = run_row.get("fixture_id")
    if fixture_id is None and recipe is not None:
        fixture_id = ((recipe.get("bindings") or {}).get("fixture") or {}).get("fixture_id")
    derived_identity = {
        "actor_id": evidence.get("actor_id"),
        "tenant_id": actor.get("tenant_id") if actor else None,
        "session_generation": evidence.get("session_generation"),
        "resource_id": evidence.get("resource_id"),
        "fixture_id": fixture_id,
    }
    if recipe is not None \
            and evidence.get("operation_id") == (recipe.get("bindings") or {}).get("operation_id"):
        expected_session = (recipe.get("bindings") or {}).get("session") or {}
        expected_resource = (recipe.get("bindings") or {}).get("resource") or {}
        expected = {
            "actor_id": expected_session.get("actor_id"),
            "session_generation": expected_session.get("generation"),
            "resource_id": expected_resource.get("resource_id"),
        }
        if any(derived_identity[key] != value for key, value in expected.items()):
            fail("v2_review_identity", "Observation identity/resource differs from the frozen recipe")
    for key, value in supplied_identity.items():
        if key in derived_identity and value != derived_identity[key]:
            fail("v2_review_identity", "Declared review identity does not match evidence",
                 field=key)
    return {
        "observation": observation,
        "consumer_point": consumer,
        "identity": derived_identity,
        "source_trust": {"kind": "current_run_evidence", "trust": "verified"},
    }


def _generic_reviewer(args):
    reviewer = dict(args.get("reviewer") or {})
    if reviewer.get("type") == "human_independent" \
            or reviewer.get("human_approved") is True \
            or reviewer.get("independent_human") is True:
        fail("v2_review_reviewer",
             "Ordinary tool arguments cannot authenticate independent human approval")
    return reviewer


def accept(project, args):
    repository = Repository(project)
    hypothesis = repository.get("hypothesis", args["hypothesis_id"])
    run_row = repository.get("run", args["run_id"])
    campaign = _campaign_for_entity(
        repository, hypothesis, args.get("campaign_id"))
    hypothesis = repository.require_campaign(
        "hypothesis", hypothesis["id"], campaign["id"])
    run_row = repository.require_campaign("run", run_row["id"], campaign["id"])
    if run_row.get("status") not in {"evaluated", "published"}:
        fail("v2_review_run", "Reviewed findings require a completed evaluated run")
    if run_row.get("hypothesis_id") != hypothesis["id"]:
        fail("v2_review_hypothesis", "Run and hypothesis do not match")
    evidence_ids = args.get("evidence_ids") or run_row.get("evidence_ids") or []
    run_evidence = set(run_row.get("evidence_ids") or [])
    if not set(evidence_ids).issubset(run_evidence):
        fail("v2_review_material", "Review may only cite evidence produced by its run")
    reviewed = (
        _prepare_reviewed(
            project, repository, campaign, hypothesis, args)
        if hypothesis["family"] in reviewed_detection.PROFILES else None)
    if reviewed is None and _reviewed_spec(args) is not None:
        fail(
            "reviewed_profile",
            "Typed reviewed detection is implemented only for the four declared families",
        )
    material = args.get("material") or {}
    if reviewed is not None:
        material_ids = list(reviewed["receipt"]["evidence_ids"])
        supplied_ids = material.get("evidence_ids")
        if supplied_ids is not None and list(supplied_ids) != material_ids:
            fail(
                "reviewed_controls",
                "Review material must be the normal, attack, negative and readback evidence in exact order",
            )
    else:
        material_ids = material.get("evidence_ids") or evidence_ids
    if not set(material_ids).issubset(run_evidence):
        fail("v2_review_material", "Review material must be a subset of the run evidence")
    digests = {}
    for evidence_id in material_ids:
        evidence, _artifact = _current_evidence(project, evidence_id)
        digests[evidence_id] = evidence.get("sha256")
    if reviewed is not None and reviewed["receipt"]["digests"] != digests:
        fail("reviewed_controls", "Reviewed evidence digests changed after validation")
    supplied = material.get("digests") or {}
    if supplied and supplied != digests:
        fail("v2_review_material", "Review material digest does not match current evidence")
    mechanism = (
        reviewed["mechanism"] if reviewed is not None
        else args.get("mechanism") or {})
    if reviewed is None:
        mechanism.setdefault("family", hypothesis["family"])
        mechanism.setdefault(
            "security_property", hypothesis["security_property"])
        mechanism.setdefault("operation_id", hypothesis["operation_id"])
        mechanism.setdefault("input_key", hypothesis["input_key"])
    identity = (
        reviewed["identity"] if reviewed is not None
        else args.get("identity") or {})
    recipe = repository.get("recipe", run_row["recipe_id"], required=False) if run_row.get("recipe_id") else None
    if recipe:
        recipe = repository.require_campaign("recipe", recipe["id"], campaign["id"])
        binding_session = (recipe.get("bindings") or {}).get("session") or {}
        binding_resource = (recipe.get("bindings") or {}).get("resource") or {}
        if identity.get("actor_id") and binding_session.get("actor_id") \
                and identity.get("actor_id") != binding_session.get("actor_id"):
            fail("v2_review_identity", "Review actor does not match the frozen recipe session")
        if identity.get("resource_id") and binding_resource.get("resource_id") \
                and identity.get("resource_id") != binding_resource.get("resource_id"):
            fail("v2_review_identity", "Review resource does not match the frozen recipe")
    generic_facts = (
        _generic_review_facts(
            project, hypothesis, run_row, recipe, args, material_ids)
        if reviewed is None else None)
    if generic_facts is not None:
        identity = generic_facts["identity"]
    contract = new_review_contract(
        hypothesis=hypothesis, run=run_row, mechanism=mechanism, identity=identity,
        control_groups=(
            reviewed["control_groups"] if reviewed is not None
            else args.get("control_groups") or []),
        observation=(
            reviewed["observation"] if reviewed is not None
            else generic_facts["observation"]),
        consumer_point=(
            reviewed["consumer_point"] if reviewed is not None
            else generic_facts["consumer_point"]),
        source_trust=(
            reviewed["source_trust"] if reviewed is not None
            else generic_facts["source_trust"]),
        reviewer=(
            reviewed["reviewer"] if reviewed is not None
            else _generic_reviewer(args)),
        proof_scope=(
            reviewed["proof_scope"] if reviewed is not None
            else args.get("proof_scope") or {}),
        material={"evidence_ids": material_ids, "digests": digests},
        verification=args.get("verification") or {},
        review_proof_receipt_id=(
            reviewed["receipt"]["id"] if reviewed is not None else None),
        reason=(reviewed["reason"] if reviewed is not None else args.get("reason")))
    validate_cross_role(contract, hypothesis=hypothesis, run=run_row)
    dependencies = _context_dependencies(
        project, campaign, hypothesis, run=run_row, recipe=recipe,
        review=contract, evidence_ids=material_ids)
    if reviewed is not None:
        receipt = reviewed["receipt"]
        dependencies.append(new_dependency(
            kind="material",
            identity=receipt["material_id"],
            fingerprint=receipt["material_sha256"],
            metadata={"material_id": receipt["material_id"]},
        ))
    proof_receipt = new_proof_receipt(
        campaign_id=campaign["id"],
        hypothesis_id=hypothesis["id"],
        run_id=run_row["id"],
        review_id=contract["id"],
        mode="reviewed",
        proof_scope=contract["proof_scope"],
        not_proven=contract["proof_scope"]["not_proven"],
        material={"evidence_ids": material_ids, "digests": digests},
        reviewer=contract["reviewer"],
        dependencies=dependencies,
        review_proof_receipt_id=(
            reviewed["receipt"]["id"] if reviewed is not None else None),
    )
    finding = new_finding(
        campaign_id=campaign["id"],
        hypothesis_id=hypothesis["id"], run_id=run_row["id"], review_id=contract["id"],
        proof_receipt_id=proof_receipt["id"],
        mode="reviewed", severity=args.get("severity") or "medium",
        title=args.get("title") or f"Reviewed: {hypothesis['security_property']}",
        category=hypothesis["family"], impact=args.get("impact") or "Reviewed detection accepted under a bounded proof scope.",
        remediation=args.get("remediation") or "Apply the mechanism-specific fix and re-test.",
        evidence_ids=material_ids, proof_scope=contract["proof_scope"]["accepted"][0],
        confidence=args.get("confidence") or "reviewed",
        limitations=contract["proof_scope"]["not_proven"] or ["Reviewed detection is not machine proof."])
    if reviewed is not None:
        finding["review_proof_receipt_id"] = reviewed["receipt"]["id"]
        finding["reviewer_assurance"] = "agent_recorded"
        finding["machine_proof"] = False
        finding["verified_observation_sha256"] = reviewed["receipt"]["observation_sha256"]
    from ..assessment_mode import record_stop
    with project.transaction():
        review_proof_receipt = (
            reviewed_detection.persist(project, reviewed["prepared"])
            if reviewed is not None else None)
        if reviewed is not None \
                and review_proof_receipt["id"] != reviewed["receipt"]["id"]:
            fail("reviewed_receipt", "Persisted reviewed proof changed identity")
        repository.add("review", contract, immutable=True)
        repository.add("proof_receipt", proof_receipt, immutable=True)
        repository.add("finding", finding, immutable=False)
        hypothesis["finding_ids"] = sorted(set(
            hypothesis.get("finding_ids", []) + [finding["id"]]))
        hypothesis["proof_receipt_id"] = proof_receipt["id"]
        if hypothesis["status"] != "supported":
            transition(hypothesis, "supported", reason="reviewed detection accepted")
        repository.save("hypothesis", hypothesis)
        record_stop(
            project, operation_id=hypothesis["operation_id"],
            evidence_ids=material_ids, finding_id=finding["id"],
            oracle_type="analyst_review")
    return {"review": review_public(contract), "finding": finding,
            "proof_receipt": proof_receipt,
            "review_proof_receipt": (
                reviewed["receipt"] if reviewed is not None else None),
            "machine_proof": False, "detection": True,
            "reviewer_independent": contract["reviewer"]["independent_human"]}


def disposition(project, args):
    repository = Repository(project)
    hypothesis = repository.get("hypothesis", args["hypothesis_id"])
    campaign = _campaign_for_entity(
        repository, hypothesis, args.get("campaign_id"))
    hypothesis = repository.require_campaign(
        "hypothesis", hypothesis["id"], campaign["id"])
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
        item = _applicability_item(repository, hypothesis)
        proof = args.get("proof")
        exact, build_evidence, material, public_proof = applicability.capture_manifest(
            project, item, proof)
        universe = repository.get("universe", campaign["universe_id"])
        target_build = universe.get("target_build")
        if target_build not in {None, "", "unknown"} \
                and public_proof.get("deployment_id") != target_build:
            fail(
                "applicability_build",
                "Deployment manifest does not match the campaign target build",
            )
        evidence_ids = [build_evidence["id"]]
        digests = {build_evidence["id"]: build_evidence["sha256"]}
        dependencies = _context_dependencies(
            project, campaign, hypothesis, evidence_ids=evidence_ids)
        dependencies.append(new_dependency(
            kind="material",
            identity=material["id"],
            fingerprint=material["sha256"],
            metadata={
                "material_id": material["id"],
                "build_evidence_id": build_evidence["id"],
            },
        ))
        receipt = new_applicability_receipt(
            campaign_id=campaign["id"],
            hypothesis_id=hypothesis["id"],
            security_property=hypothesis["security_property"],
            input_key=hypothesis.get("input_key"),
            bindings=exact,
            input_branch={
                "location": exact["input_location"],
                "selector": exact["input_selector"],
                "schema_branch": exact.get("schema_branch"),
            },
            predicate={
                "operator": "equals",
                "subject": "deployment_manifest_precondition",
                "selector": public_proof["predicate_selector"],
                "expected": False,
            },
            verifier={
                "type": "deployment_manifest",
                "id": material["id"],
                "version": public_proof.get("version") or "awa-applicability/v1",
                "method": "exact_sha256_and_deployment_build",
            },
            evidence_ids=evidence_ids,
            digests=digests,
            reviewer={
                "type": "analyst_recorded",
                "id": public_proof["reviewer"],
                "source": "review.disposition",
            },
            dependencies=dependencies,
            reason=args.get("reason") or public_proof["reason"],
            proof=public_proof,
            manifest_material={
                "material_id": material["id"],
                "material_sha256": material["sha256"],
                "build_evidence_sha256": build_evidence["sha256"],
                "schema": applicability.SCHEMA,
            },
        )
        with project.transaction():
            repository.add("applicability_receipt", receipt, immutable=True)
            hypothesis["applicability_receipt_id"] = receipt["id"]
            transition(
                hypothesis, "not_applicable",
                reason=args.get("reason") or public_proof["reason"])
            repository.save("hypothesis", hypothesis)
        return {
            "hypothesis": hypothesis,
            "status": hypothesis["status"],
            "applicability_receipt": receipt,
            "bindings": exact,
            "counts_as_tested": False,
        }
    else:
        transition(hypothesis, "ready", reason=args.get("reason") or "prerequisites rechecked")
    repository.save("hypothesis", hypothesis)
    return {"hypothesis": hypothesis, "status": hypothesis["status"],
            "counts_as_tested": False if status == "not_applicable" else None}


def bind(project, args):
    """Upgrade a reviewed finding using an existing machine evaluation, preserving history."""
    repository = Repository(project)
    finding = repository.get("finding", args["finding_id"])
    campaign = _campaign_for_entity(
        repository, finding, args.get("campaign_id"))
    finding = repository.require_campaign("finding", finding["id"], campaign["id"])
    if finding.get("status") != "reviewed_confirmed" or not finding.get("current"):
        fail("v2_review_bind", "Only a current reviewed finding can be bound")
    reviewed_receipt = repository.get(
        "proof_receipt", finding.get("proof_receipt_id"))
    reviewed_evaluation = evaluate_receipt(project, reviewed_receipt)
    if not reviewed_evaluation["current"]:
        fail("v2_review_bind", "Reviewed proof receipt is expired or invalid")
    run_row = repository.get("run", args["run_id"])
    run_row = repository.require_campaign("run", run_row["id"], campaign["id"])
    if run_row.get("status") != "evaluated" or run_row.get("hypothesis_id") != finding["hypothesis_id"]:
        fail("v2_review_bind", "Machine proof must be an evaluated run for the same hypothesis")
    evaluation = run_row.get("evaluation") or {}
    if evaluation.get("outcome") != "supported" or not evaluation.get("finding_allowed"):
        fail("v2_review_bind", "Machine run did not produce a confirmable result")
    if not set(finding.get("evidence_ids") or []).issubset(set(run_row.get("evidence_ids") or [])):
        fail("v2_review_bind", "Reviewed evidence is not a subset of the machine run evidence")
    hypothesis = repository.require_campaign(
        "hypothesis", finding["hypothesis_id"], campaign["id"])
    review = repository.require_campaign(
        "review", finding["review_id"], campaign["id"])
    digests = {}
    for evidence_id in finding["evidence_ids"]:
        evidence, _artifact = _current_evidence(project, evidence_id)
        digests[evidence_id] = evidence["sha256"]
    proof_receipt = new_proof_receipt(
        campaign_id=campaign["id"],
        hypothesis_id=hypothesis["id"],
        run_id=run_row["id"],
        review_id=finding.get("review_id"),
        mode="machine",
        proof_scope={
            "accepted": [evaluation.get("proof_scope") or "semantic_refutation"],
            "not_proven": evaluation.get("limitations") or [],
        },
        material={"evidence_ids": finding["evidence_ids"], "digests": digests},
        reviewer={
            "type": "analyst_recorded",
            "id": text(args.get("reviewer") or "machine-binding", "reviewer", maximum=200),
            "source": "review.bind",
        },
        dependencies=_context_dependencies(
            project, campaign, hypothesis, run=run_row,
            review=review, evidence_ids=finding["evidence_ids"]),
    )
    machine = new_finding(
        campaign_id=campaign["id"],
        hypothesis_id=finding["hypothesis_id"], run_id=run_row["id"], mode="machine",
        proof_receipt_id=proof_receipt["id"],
        severity=finding["severity"], title=finding["title"], category=finding["category"],
        impact=finding["impact"], remediation=finding["remediation"],
        evidence_ids=finding["evidence_ids"], proof_scope=evaluation.get("proof_scope") or "machine",
        decision_id=run_row["id"], limitations=evaluation.get("limitations") or [])
    with project.transaction():
        repository.add("proof_receipt", proof_receipt, immutable=True)
        repository.add("finding", machine, immutable=False)
        finding["current"] = False
        finding["status"] = "superseded"
        finding["superseded_by"] = machine["id"]
        finding.setdefault("lifecycle", []).append({"status": "superseded", "reviewer": args.get("reviewer"),
                                                    "reason": args.get("reason"),
                                                    "replacement_id": machine["id"],
                                                    "at": __import__("datetime").datetime.now(
                                                        __import__("datetime").timezone.utc).isoformat()})
        repository.save("finding", finding)
        hypothesis["proof_receipt_id"] = proof_receipt["id"]
        repository.save("hypothesis", hypothesis)
    return {"finding": machine, "proof_receipt": proof_receipt,
            "superseded_finding_id": finding["id"], "machine_proof": True}


def evidence_view(project, args):
    repository = Repository(project)
    if args.get("review_id"):
        return {"review": review_public(repository.get("review", args["review_id"]))}
    if args.get("run_id"):
        return {"run": run_public(repository.get("run", args["run_id"]))}
    fail("v2_review_evidence", "review.evidence requires review_id or run_id")
