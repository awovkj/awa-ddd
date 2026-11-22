"""Durable 2.0 test runner: one call performs preflight, controlled execution,
evidence persistence, oracle evaluation and coverage delta — while keeping each
durable step separate and never replaying uncertain writes.
"""
from __future__ import annotations

import base64
import json

from .. import engine
from .. import execution_coordinator as coordinator
from ..domain import new_finding, new_proof_receipt, new_run
from ..domain.common import digest, fail, integer, stable_id, text, utc_now
from ..domain.receipt import (
    entity_dependency,
    evidence_dependencies,
    new_dependency,
    scope_dependency,
    target_build_dependency,
)
from ..domain.repository import Repository
from ..domain.test_recipe import assert_current, public_view as recipe_public, render
from ..domain.test_run import add_step, claim as claim_run, mark_effect_unknown, public_view as run_public, transition as run_transition
from ..store import EngineError
from . import oracle_profiles


READ_ONLY_METHODS = {"GET", "HEAD", "OPTIONS"}
TERMINAL_PROOF_OUTCOMES = {"supported", "refuted"}


def _campaign(project, campaign_id):
    campaign = Repository(project).get("campaign", campaign_id)
    if campaign.get("state") != "active":
        fail("v2_campaign_state", "Campaign is not active")
    return campaign


def _campaign_entities(repository, campaign, recipe=None, hypothesis=None):
    """Resolve all runner facts through one explicit campaign boundary."""
    if recipe is not None:
        recipe = repository.require_campaign("recipe", recipe["id"], campaign["id"])
        if recipe.get("universe_id") != campaign.get("universe_id"):
            fail("v2_campaign_scope", "Recipe universe does not belong to the campaign")
    if hypothesis is not None:
        hypothesis = repository.require_campaign(
            "hypothesis", hypothesis["id"], campaign["id"])
        if hypothesis.get("universe_id") != campaign.get("universe_id"):
            fail("v2_campaign_scope", "Hypothesis universe does not belong to the campaign")
    if recipe is not None and hypothesis is not None \
            and recipe.get("hypothesis_id") != hypothesis.get("id"):
        fail("v2_recipe_hypothesis", "Recipe and hypothesis do not match")
    return recipe, hypothesis


def _operation(project, recipe):
    operation = project.get("operation", recipe["bindings"]["operation_id"], required=False)
    if operation is None:
        fail("v2_recipe_stale", "Recipe operation no longer exists")
    return operation


def _session_context(project, recipe):
    session = recipe.get("bindings", {}).get("session")
    if not session:
        return None
    current = project.get("session", session["session_id"], required=False)
    if current is None:
        fail("v2_recipe_stale", "Recipe session no longer exists")
    return {"session_id": current["id"], "generation": current.get("generation", 1),
            "actor_id": current.get("actor_id")}


def _resource_context(project, recipe):
    resource = recipe.get("bindings", {}).get("resource")
    if not resource:
        return None
    current = project.get("resource", resource["resource_id"], required=False)
    if current is None:
        fail("v2_recipe_stale", "Recipe resource no longer exists")
    return {"resource_id": current["id"], "revision": current.get("revision", 1)}


def _fixture_context(project, recipe):
    binding = recipe.get("bindings", {}).get("fixture")
    if not binding:
        return None
    row = Repository(project).get("fixture", binding["fixture_id"], required=False)
    if row is None:
        fail("v2_recipe_stale", "Recipe fixture no longer exists")
    return {"fixture_id": row["id"], "revision": row.get("revision", 1), "state": row.get("state")}


def context(project, campaign, recipe):
    operation = _operation(project, recipe)
    universe = Repository(project).get("universe", campaign.get("universe_id"), required=False)
    if universe is None or universe.get("id") != campaign.get("universe_id"):
        fail("v2_campaign_scope", "Campaign universe is missing or does not match")
    return {
        "scope_epoch": campaign.get("scope_epoch"),
        "target_build": universe.get("target_build"),
        "operation_signature": engine.operation_signature(operation),
        "session": _session_context(project, recipe),
        "resource": _resource_context(project, recipe),
        "fixture": _fixture_context(project, recipe),
    }


def _existing(project, campaign_id, idempotency_key):
    for row in Repository(project).list_campaign(
            "run", campaign_id, limit=None)[0]:
        if row.get("idempotency_key") == idempotency_key:
            return row
    return None


def _control_effect(control, operation):
    """Classify a control conservatively from both the declaration and operation."""
    declared = control.get("effect")
    method = str((control.get("request") or {}).get("method") or operation.get("method") or "")
    if declared not in {None, "read_only", "test_resource_write"}:
        fail("v2_recipe_effect", "Control effect must be read_only or test_resource_write")
    if declared == "test_resource_write" or operation.get("method") not in READ_ONLY_METHODS \
            or method.upper() not in READ_ONLY_METHODS:
        return "test_resource_write"
    return "read_only"


def _planned_controls(recipe, args, mode):
    executable = render(recipe, args.get("variables"))
    groups = executable.get("control_groups") or recipe.get("control_groups", [])
    if not groups:
        fail("v2_recipe_controls", "Executable recipe has no control group")
    group = groups[0]
    planned = list(group.get("controls") or [])
    if group.get("execution_strategy") == "single_write_attack_only":
        planned = [control for control in planned if control.get("dispatch", True)]
    elif any(not control.get("dispatch", True) for control in planned):
        fail("v2_recipe_controls", "Skipped controls require an explicit execution strategy")
    if mode == "observe":
        planned = [control for control in planned if control.get("role") == "normal"][:1]
        if not planned:
            fail("v2_observe_controls", "Observe mode requires a dispatchable normal control")
    return executable, planned


def _validate_dispatch_budget(recipe, operation, planned):
    limits = recipe.get("limits") or {}
    request_total = len(planned)
    write_total = sum(
        _control_effect(control, operation) == "test_resource_write"
        for control in planned)
    if request_total > int(limits.get("step_total", request_total)):
        fail("v2_dispatch_budget", "Planned controls exceed the recipe step budget",
             planned_requests=request_total, max_requests=limits.get("step_total"))
    if write_total > int(limits.get("max_writes", 0)):
        fail(
            "v2_dispatch_budget",
            "Planned write controls exceed the recipe write budget; split the experiment or use independent fixtures",
            planned_writes=write_total,
            max_writes=limits.get("max_writes", 0),
            requests_sent=0,
        )
    recipe_effect = limits.get("effect", "read_only")
    if recipe_effect == "read_only" and write_total:
        fail("v2_dispatch_budget",
             "Read-only recipe contains a write control", requests_sent=0)
    return {
        "requests": request_total,
        "writes": write_total,
        "effect": "test_resource_write" if write_total else "read_only",
    }


def _run_fingerprint(run_row):
    return digest({key: run_row.get(key) for key in (
        "id", "campaign_id", "hypothesis_id", "recipe_id", "recipe_spec_hash",
        "mode", "evidence_ids", "evaluation", "outcome", "effect",
    )})


def _proof_dependencies(project, campaign, hypothesis, recipe, run_row, evidence_ids):
    """Dependencies required before a machine or offline verification proof is current."""
    repository = Repository(project)
    universe = repository.get("universe", campaign["universe_id"])
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
        entity_dependency(
            project, "recipe", recipe["id"], fingerprint_fields=(
                "id", "campaign_id", "universe_id", "hypothesis_id", "spec_hash")),
        new_dependency(
            kind="run",
            identity=run_row["id"],
            fingerprint=_run_fingerprint(run_row),
            metadata={
                "campaign_id": campaign["id"],
                "hypothesis_id": hypothesis["id"],
                "recipe_id": recipe["id"],
            },
        ),
    ]
    bindings = recipe.get("bindings") or {}
    for binding_kind, binding_key, identity_key in (
            ("session", "session", "session_id"),
            ("resource", "resource", "resource_id"),
            ("fixture", "fixture", "fixture_id")):
        binding = bindings.get(binding_key) or {}
        identity = binding.get(identity_key)
        if identity:
            dependencies.append(entity_dependency(
                project, binding_kind, identity,
                metadata={"campaign_id": campaign["id"]}))
    dependencies.extend(evidence_dependencies(project, evidence_ids))
    return dependencies


def _new_proof(project, campaign, hypothesis, recipe, run_row, evaluation, evidence_ids):
    if evaluation.get("outcome") not in TERMINAL_PROOF_OUTCOMES:
        return None
    proof_scope = evaluation.get("proof_scope") or (recipe.get("oracle") or {}).get("proof_scope")
    if not proof_scope:
        fail("v2_proof_scope", "Supported/refuted runs require a bounded proof scope")
    for evidence_id in evidence_ids:
        evidence, _artifact = engine.verify_current_evidence(project, evidence_id)
        if not evidence.get("complete"):
            fail("v2_proof_material", "Incomplete evidence cannot support a proof receipt",
                 evidence_id=evidence_id, requests_sent=0)
    digests = {
        evidence_id: engine.verify_current_evidence(project, evidence_id)[0]["sha256"]
        for evidence_id in evidence_ids
    }
    return new_proof_receipt(
        campaign_id=campaign["id"],
        hypothesis_id=hypothesis["id"],
        run_id=run_row["id"],
        mode="machine",
        proof_scope={"accepted": [proof_scope], "not_proven": []},
        not_proven=evaluation.get("limitations") or [],
        material={"evidence_ids": evidence_ids, "digests": digests},
        reviewer={
            "type": "analyst_recorded",
            "id": (recipe.get("oracle") or {}).get("id") or "machine-oracle",
            "source": "awa-ddd.oracle",
        },
        dependencies=_proof_dependencies(
            project, campaign, hypothesis, recipe, run_row, evidence_ids),
    )


def _capture_args(recipe, control, *, idempotency_key):
    request = control["request"]
    args = {
        "operation_id": recipe["bindings"]["operation_id"],
        "url": request["url"],
        "method": request.get("method"),
        "headers": request.get("headers") or {},
        "idempotency_key": idempotency_key,
        "timeout": 30,
    }
    if "body" in request:
        args["body"] = request["body"]
    if "body_base64" in request:
        args["body_base64"] = request["body_base64"]
    session = recipe["bindings"].get("session")
    if session:
        args["session_id"] = session["session_id"]
    resource = recipe["bindings"].get("resource")
    if resource:
        args["resource_id"] = resource["resource_id"]
    effect = recipe.get("limits", {}).get("effect", "read_only")
    args["effect"] = effect
    return args


def _evidence_value(project, evidence_id, selector):
    evidence = project.get("evidence", evidence_id)
    artifact = project.read_artifact(evidence)
    response = artifact.get("response", {})
    try:
        body = base64.b64decode(response.get("body_base64", ""), validate=True)
    except (ValueError, TypeError):
        body = b""
    content_type = ""
    for pair in response.get("headers", []):
        if isinstance(pair, (list, tuple)) and len(pair) == 2 and str(pair[0]).lower() == "content-type":
            content_type = str(pair[1]).lower()
    text_body = body.decode("utf-8", errors="replace")
    parsed = None
    if "json" in content_type or text_body.lstrip()[:1] in "[{":
        try:
            parsed = json.loads(text_body)
        except json.JSONDecodeError:
            parsed = None
    if selector == "status":
        return response.get("status")
    if selector == "body":
        return text_body
    if selector.startswith("header:"):
        name = selector.split(":", 1)[1].lower()
        for pair in response.get("headers", []):
            if len(pair) == 2 and str(pair[0]).lower() == name:
                return pair[1]
        return None
    if selector.startswith("text:"):
        return selector.split(":", 1)[1] in text_body
    pointer_path = selector[5:] if selector.startswith("json:") else selector
    if parsed is not None and isinstance(pointer_path, str) and pointer_path.startswith("/"):
        from ..transport import pointer as resolve_pointer
        try:
            return resolve_pointer(parsed, pointer_path)
        except (KeyError, IndexError, TypeError):
            return None
    return text_body


def _observation_map(recipe, control_results):
    observations = {}
    for control, result in control_results:
        role = control["role"]
        actual = result.get("actual")
        if control.get("observe_as"):
            observations[control["observe_as"]] = actual
        observations[role + "_actual"] = actual
        observations[role + "_matched"] = result.get("matched")
        observations[role + "_expected"] = control.get("expected", {}).get("value")
    family = recipe.get("family")
    oracle = recipe.get("oracle", {})
    if family == "access_control":
        observations.setdefault("allowed_role_result", observations.get("normal_actual"))
        observations.setdefault("forbidden_role_result", observations.get("attack_actual"))
        observations.setdefault("anonymous_result", observations.get("negative_actual"))
        observations.setdefault("server_role_evidence", bool((recipe.get("bindings") or {}).get("session")))
    if family == "template_injection":
        attack_payload = observations.get("attack_expected")
        observations.setdefault("declared_formula_field", oracle.get("type") == "unexpected_expression_evaluation")
        if "normal_actual" in observations:
            observations.setdefault("normal_plain_value", observations.get("normal_actual"))
        observations.setdefault("attack_arithmetic_value", observations.get("attack_actual"))
        if "negative_actual" in observations:
            observations.setdefault("negative_literal_value", observations.get("negative_actual"))
        observations.setdefault("expected_arithmetic_result", oracle.get("expected_value"))
        observations.setdefault("normal_expected", observations.get("normal_actual"))
        observations.setdefault("negative_expected", observations.get("negative_actual"))
        observations.setdefault("reflection_exclusion", observations.get("attack_actual") != attack_payload)
    if family == "deserialization":
        observations.setdefault("attack_type_marker", observations.get("attack_actual"))
        observations.setdefault("bounded_canary_effect", observations.get("canary_effect"))
        observations.setdefault("negative_unknown_type", observations.get("negative_actual"))
    if family == "file_upload":
        observations.setdefault("stored_path", observations.get("attack_actual"))
        observations.setdefault("allowed_root", oracle.get("allowed_root"))
    return observations


def _eval_from_results(recipe, control_results):
    observations = _observation_map(recipe, control_results)
    oracle_type = recipe.get("oracle", {}).get("type")
    result = oracle_profiles.evaluate(oracle_type, observations)
    result["oracle_type"] = oracle_type
    result["proof_scope"] = recipe.get("oracle", {}).get("proof_scope") if result.get("outcome") == "supported" else None
    result["observations"] = observations
    return result


def run(project, args):
    """Execute observe/test/verify under one durable run record."""
    mode = args.get("mode", "test")
    campaign = _campaign(project, args.get("campaign_id"))
    repository = Repository(project)
    recipe = None
    hypothesis = None
    if args.get("recipe_id"):
        recipe = repository.get("recipe", args["recipe_id"])
        hypothesis = repository.get("hypothesis", recipe["hypothesis_id"])
        recipe, hypothesis = _campaign_entities(
            repository, campaign, recipe=recipe, hypothesis=hypothesis)
    elif args.get("hypothesis_id"):
        hypothesis = repository.get("hypothesis", args["hypothesis_id"])
        _, hypothesis = _campaign_entities(
            repository, campaign, hypothesis=hypothesis)
        if mode != "verify":
            from .recipe_builder import build
            universe = repository.get("universe", campaign.get("universe_id"))
            built = build(project, campaign, universe, hypothesis)
            if built["status"] != "ready":
                fail("v2_recipe_blocked", built.get("reason", "Hypothesis prerequisites are missing"),
                     missing=built.get("missing", []), next_action="campaign.next")
            recipe = built["recipe"]
            existing_recipe = repository.get("recipe", recipe["id"], required=False)
            if existing_recipe is not None:
                recipe, hypothesis = _campaign_entities(
                    repository, campaign, recipe=existing_recipe,
                    hypothesis=hypothesis)
            else:
                repository.add("recipe", recipe, immutable=True)
    if hypothesis is None and mode == "verify" and args.get("run_id"):
        prior = repository.require_campaign(
            "run", args["run_id"], campaign["id"])
        hypothesis = repository.get("hypothesis", prior.get("hypothesis_id"))
        if prior.get("recipe_id"):
            recipe = repository.get("recipe", prior["recipe_id"], required=False)
        recipe, hypothesis = _campaign_entities(
            repository, campaign, recipe=recipe, hypothesis=hypothesis)
    if hypothesis is None:
        fail("v2_run_recipe", "test.run requires recipe_id, hypothesis_id or a bound verify run_id")
    if mode == "verify":
        return _verify(project, args, campaign, hypothesis, recipe)
    idempotency_key = text(args.get("idempotency_key") or ("run:" + hypothesis["id"] + ":" + utc_now()),
                           "idempotency_key", maximum=256)
    existing = _existing(project, campaign["id"], idempotency_key)
    if existing:
        existing = repository.require_campaign("run", existing["id"], campaign["id"])
        if recipe is not None and existing.get("recipe_id") != recipe["id"]:
            fail("idempotency_conflict", "Idempotency key already belongs to a different recipe")
        if existing.get("hypothesis_id") != hypothesis["id"]:
            fail("idempotency_conflict", "Idempotency key already belongs to a different hypothesis")
        return {"run": run_public(existing), "replayed": False,
                "notice": "Idempotency key already belongs to a durable run; no request was sent again."}
    if recipe is None:
        fail("v2_run_recipe", "No recipe is available")
    recipe, hypothesis = _campaign_entities(
        repository, campaign, recipe=recipe, hypothesis=hypothesis)
    assert_current(recipe, context(project, campaign, recipe))
    operation = _operation(project, recipe)
    from ..assessment_mode import capture_policy
    capture_policy(project, operation,
                   {"effect": recipe.get("limits", {}).get("effect", "read_only")})
    executable, planned = _planned_controls(recipe, args, mode)
    budget = _validate_dispatch_budget(recipe, operation, planned)
    effect = budget["effect"]
    if mode == "observe" and effect != "read_only":
        fail("v2_observe_effect",
             "Observe mode is read-only; use test mode with an authorized fixture for writes",
             requests_sent=0)
    if effect == "test_resource_write" \
            and not (campaign.get("allow_mutation") and project.config.get("allow_mutation")):
        fail("v2_write_authorization",
             "Write recipe requires campaign/project allow_mutation",
             requests_sent=0)
    fixture = None
    if effect == "test_resource_write":
        fixture_binding = recipe.get("bindings", {}).get("fixture") or {}
        fixture = repository.get(
            "fixture", fixture_binding.get("fixture_id"), required=False)
        if fixture is None:
            fail("v2_recipe_fixture", "Write recipe fixture no longer exists",
                 requests_sent=0)
        if fixture.get("state") != "leased":
            fail("v2_fixture_state",
                 "Write recipe requires the frozen fixture revision to be actively leased",
                 fixture_state=fixture.get("state"), requests_sent=0)
        resource_binding = (recipe.get("bindings", {}).get("resource") or {})
        bound_resource = project.get("resource", resource_binding.get("resource_id"), required=False)
        if bound_resource is None \
                or fixture.get("resource_id") != bound_resource.get("id") \
                or fixture.get("owner_actor_id") != bound_resource.get("owner_actor_id") \
                or bound_resource.get("operation_id") != operation.get("id"):
            fail("v2_recipe_fixture",
                 "Recipe resource and fixture must identify the same operation, owner and resource",
                 requests_sent=0)
        from .fixtures import _active_lease, _validate_binding
        _validate_binding(project, fixture)
        _active_lease(fixture, worker_id=args.get("worker_id", "local"))

    run_row = new_run(recipe=recipe, campaign_id=campaign["id"], idempotency_key=idempotency_key,
                      actor_id=(recipe["bindings"].get("session") or {}).get("actor_id"), mode=mode)
    run_row["universe_id"] = campaign["universe_id"]
    run_row["fixture_id"] = fixture.get("id") if fixture else None
    run_row["dispatch_budget"] = {
        "max_requests": budget["requests"],
        "max_writes": budget["writes"],
        "requests_used": 0,
        "writes_used": 0,
    }
    run_row["dispatch_receipt_ids"] = []
    run_row["proof_receipt_id"] = None
    run_row["finding_ids"] = []
    try:
        repository.add("run", run_row, immutable=False, create_only=True)
    except EngineError as exc:
        if exc.code != "immutable_record":
            raise
        existing = _existing(project, campaign["id"], idempotency_key)
        if existing is None or existing.get("recipe_id") != recipe["id"] \
                or existing.get("hypothesis_id") != hypothesis["id"]:
            fail("idempotency_conflict",
                 "Idempotency key belongs to a conflicting durable run")
        return {
            "run": run_public(existing),
            "replayed": False,
            "notice": "A concurrent request created this durable run; no request was sent again.",
        }
    worker_id = text(args.get("worker_id", "local"), "worker_id", maximum=128)
    worker_lease = _claim_run_execution(
        project, run_row, worker_id, ttl_seconds=args.get("lease_seconds", 300))
    coordinator.reserve_budget(
        project, _execution_budget_name(run_row["id"]),
        budget["requests"], budget["writes"])
    repository.save("run", run_row, expected_revision=1)

    from ..domain.hypothesis import transition as hypothesis_transition
    hypothesis_revision = repository.get_revision("hypothesis", hypothesis["id"])
    if hypothesis.get("status") == "unplanned":
        hypothesis_transition(
            hypothesis, "ready", reason="scheduler selected the hypothesis")
    if hypothesis.get("status") != "ready":
        run_transition(run_row, "failed", note="hypothesis is not ready for execution")
        repository.save("run", run_row, expected_revision=2)
        coordinator.release(project, worker_lease, reconciled=False)
        fail("v2_hypothesis_state",
             "Only a ready hypothesis can start a new execution",
             hypothesis_status=hypothesis.get("status"), requests_sent=0)
    hypothesis_transition(
        hypothesis, "running", reason="durable test run started")
    hypothesis["recipe_ids"] = sorted(set(
        hypothesis.get("recipe_ids", []) + [recipe["id"]]))
    hypothesis["run_ids"] = sorted(set(
        hypothesis.get("run_ids", []) + [run_row["id"]]))
    repository.save(
        "hypothesis", hypothesis, expected_revision=hypothesis_revision)

    control_results = []
    evidence_ids = []
    dispatch_receipts = []
    started = False
    try:
        for control in planned:
            if fixture is not None:
                current_fixture = repository.get("fixture", fixture["id"])
                binding_revision = (
                    recipe.get("bindings", {}).get("fixture") or {}).get("revision")
                if current_fixture.get("revision") != binding_revision:
                    fail("v2_recipe_stale",
                         "Fixture revision changed before dispatch",
                         binding="fixture", requests_sent=0)
            capture_args = _capture_args(recipe, control, idempotency_key=idempotency_key + ":" + control["id"])
            prepared = engine.preflight_capture(project, capture_args)
            dispatch_spec = prepared["dispatch_spec"]
            if not started:
                run_transition(
                    run_row, "dispatch_started", note="first control dispatch")
                run_row["dispatch_started_at"] = utc_now()
                started = True
            step = add_step(
                run_row, step_id=control["id"], action="http.capture",
                request_digest=dispatch_spec["request_hash"],
                status="dispatch_started")
            _save_run(repository, run_row)
            dispatch_receipt = _dispatch_control(
                project, run_row, worker_lease, prepared,
                effect=_control_effect(control, operation))
            dispatch_receipts.append(dispatch_receipt)
            run_row["dispatch_receipt_ids"].append(dispatch_receipt["id"])
            step["dispatch_receipt_id"] = dispatch_receipt["id"]
            _save_run(repository, run_row)
            if _control_effect(control, operation) == "test_resource_write":
                # The durable dispatch exists but engine.capture has not sent any
                # bytes yet. Reserve the fixture before crossing that boundary;
                # cancellation or failure deliberately leaves the marker intact.
                from . import fixtures as fixture_lifecycle
                fixture = fixture_lifecycle.begin_execution(
                    project, fixture["id"], worker_id=worker_id, run_id=run_row["id"])
            evidence = engine.capture(
                project, capture_args, dispatch_context={
                    "receipt_id": dispatch_receipt["id"],
                    **dispatch_spec,
                    "run_id": run_row["id"],
                    "lease_name": dispatch_receipt["lease_name"],
                    "fence": dispatch_receipt["fence"],
                })
            if not evidence.get("complete"):
                fail("v2_evidence_incomplete",
                     "Capture completed without a trustworthy artifact",
                     evidence_id=evidence.get("id"), requests_sent=1)
            evidence_ids.append(evidence["id"])
            actual = _evidence_value(project, evidence["id"], control.get("expected", {}).get("selector", "body"))
            expected = control.get("expected", {}).get("value")
            matched = str(actual).strip() == str(expected).strip() if expected is not None else None
            control_results.append((control, {"evidence_id": evidence["id"], "actual": actual, "matched": matched}))
            if _control_effect(control, operation) == "test_resource_write":
                from . import fixtures as fixture_lifecycle
                fixture = fixture_lifecycle.mutate(
                    project, fixture["id"], worker_id=worker_id,
                    intended_effect={
                        "kind": "observed_http_control",
                        "control_id": control["id"],
                        "evidence_id": evidence["id"],
                        "dispatch_receipt_id": dispatch_receipt["id"],
                        "request_digest": dispatch_spec["request_hash"],
                        "actual": actual,
                    },
                    run_id=run_row["id"])
                step["fixture_revision"] = fixture["revision"]
                step["fixture_fence"] = fixture["fence"]
            step.update({
                "status": "completed",
                "response_digest": evidence.get("sha256"),
                "evidence_id": evidence["id"],
                "dispatch_receipt_id": dispatch_receipt["id"],
                "completed_at": utc_now(),
            })
            _save_run(repository, run_row)
    except EngineError as exc:
        if effect == "test_resource_write" and (
                exc.details.get("run_id") or dispatch_receipts):
            mark_effect_unknown(run_row, reason=str(exc))
            run_row["evidence_ids"] = evidence_ids
            _save_run(repository, run_row)
            hypothesis_revision = repository.get_revision(
                "hypothesis", hypothesis["id"])
            hypothesis_transition(
                hypothesis, "blocked", reason="effect_unknown",
                missing_context=["state_readback"])
            hypothesis["attempt"] = {**hypothesis.get("attempt", {}), "last_outcome": "effect_unknown",
                                     "consecutive_failures": hypothesis.get("attempt", {}).get("consecutive_failures", 0) + 1,
                                     "last_attempt_at": utc_now()}
            repository.save(
                "hypothesis", hypothesis,
                expected_revision=hypothesis_revision)
            return {"run": run_public(run_row), "outcome": "effect_unknown", "requires_reconciliation": True,
                    "dispatch_receipts": dispatch_receipts,
                    "notice": "A write may have reached the target; inspect its run and read back fixture state before any retry."}
        run_transition(run_row, "failed", note=str(exc))
        run_row["error"] = {"code": exc.code, "message": str(exc)}
        run_row["evidence_ids"] = evidence_ids
        _save_run(repository, run_row)
        if hypothesis:
            hypothesis_revision = repository.get_revision(
                "hypothesis", hypothesis["id"])
            hypothesis["attempt"] = {**hypothesis.get("attempt", {}), "last_outcome": "execution_failed",
                                     "consecutive_failures": hypothesis.get("attempt", {}).get("consecutive_failures", 0) + 1,
                                     "last_attempt_at": utc_now()}
            repository.save(
                "hypothesis", hypothesis,
                expected_revision=hypothesis_revision)
        if dispatch_receipts and effect == "read_only":
            coordinator.release(project, worker_lease, reconciled=True)
        elif not dispatch_receipts:
            coordinator.release(project, worker_lease, reconciled=False)
        raise
    run_row["evidence_ids"] = evidence_ids
    run_transition(run_row, "response_saved", note="all planned controls captured")
    if mode == "observe":
        run_row["evaluation"] = {"outcome": "observed", "finding_allowed": False,
                                 "limitations": ["Observe mode records evidence but does not test a hypothesis."]}
        run_row["outcome"] = "observed"
        run_transition(run_row, "evaluation_pending", note="observation evaluation")
        run_transition(run_row, "evaluated", note="observation only")
        _save_run(repository, run_row)
        coordinator.release(project, worker_lease, reconciled=True)
        return {
            "run": run_public(run_row),
            "outcome": "observed",
            "dispatch_receipts": dispatch_receipts,
            "coverage_delta": {"tested": 0},
        }
    run_transition(run_row, "evaluation_pending", note="oracle evaluation")
    evaluation = _eval_from_results(recipe, control_results)
    run_row["evaluation"] = evaluation
    run_row["outcome"] = evaluation.get("outcome")
    finding, proof_receipt = _commit_evaluation(
        project, repository, campaign, hypothesis, recipe, run_row,
        evaluation, evidence_ids)
    if finding is not None:
        from ..assessment_mode import record_stop
        record_stop(project, operation_id=hypothesis["operation_id"], evidence_ids=evidence_ids,
                    decision_id=run_row["id"], finding_id=finding["id"],
                    oracle_type=recipe.get("oracle", {}).get("type"))
    coordinator.release(project, worker_lease, reconciled=True)
    return {"run": run_public(run_row), "outcome": evaluation["outcome"],
            "finding": finding, "proof_receipt": proof_receipt,
            "dispatch_receipts": dispatch_receipts,
            "coverage_delta": {"tested": 1 if evaluation["outcome"] in {"supported", "refuted", "inconclusive"} else 0,
                               "finding_created": bool(finding), "family": hypothesis["family"]}}


def _save_run(repository, run_row):
    revision = repository.get_revision("run", run_row["id"])
    run_row["updated_at"] = utc_now()
    return repository.save("run", run_row, expected_revision=revision)


def _execution_budget_name(run_id):
    return "v2-execution:" + run_id


def _execution_lease_name(run_id):
    return "v2-run:" + run_id


def _claim_run_execution(project, run_row, worker_id, *, ttl_seconds):
    lease = coordinator.claim(
        project, _execution_lease_name(run_row["id"]),
        owner=worker_id, ttl=ttl_seconds)
    claim_run(
        run_row, worker_id, ttl_seconds=ttl_seconds)
    run_row["lease"].update({
        "campaign_id": run_row.get("campaign_id"),
        "universe_id": run_row.get("universe_id"),
        "coordinator_name": lease["name"],
        "owner": lease["owner"],
        "fence": lease["fence"],
        "token": stable_id("RLT", {
            "run_id": run_row["id"],
            "campaign_id": run_row.get("campaign_id"),
            "worker_id": worker_id,
            "claimed_at": run_row["lease"]["claimed_at"],
        }),
        "expires_at": __import__("datetime").datetime.fromtimestamp(
            lease["expires_at"],
            tz=__import__("datetime").timezone.utc).isoformat(),
    })
    return lease


def _dispatch_control(project, run_row, lease, prepared, *, effect):
    """Persist one fenced dispatch receipt immediately before sending."""
    planned = run_row.get("dispatch_budget") or {}
    dispatch_spec = prepared["dispatch_spec"]
    receipt = coordinator.dispatch(
        project,
        lease,
        action=dispatch_spec["action"],
        run_id=run_row["id"],
        request_hash=dispatch_spec["request_hash"],
        budget=_execution_budget_name(run_row["id"]),
        max_requests=integer(
            planned.get("max_requests"), "max_requests",
            minimum=0, maximum=25),
        max_writes=integer(
            planned.get("max_writes"), "max_writes",
            minimum=0, maximum=1),
        effect=effect,
        requests=1,
        writes=1 if effect == "test_resource_write" else 0,
    )
    run_row["dispatch_budget"]["requests_used"] = (
        run_row["dispatch_budget"]["max_requests"]
        - receipt["requests_remaining"])
    run_row["dispatch_budget"]["writes_used"] = (
        run_row["dispatch_budget"]["max_writes"]
        - receipt["writes_remaining"])
    return receipt


def _severity(family):
    return {"sql_injection": "high", "command_injection": "critical", "template_injection": "high",
            "deserialization": "high", "xss": "medium", "ssrf": "medium", "xxe": "medium",
            "file_upload": "high", "path_traversal": "medium", "access_control": "high",
            "business_logic": "medium", "generic": "low"}.get(family, "low")


def _finding_title(hypothesis, recipe):
    return f"{recipe.get('family', 'generic')}: {hypothesis.get('security_property')} ({hypothesis.get('operation_id')})"


def _commit_evaluation(project, repository, campaign, hypothesis, recipe, run_row,
                       evaluation, evidence_ids):
    """Atomically commit proof material, findings, run evaluation and hypothesis state."""
    from ..domain.hypothesis import record_attempt, transition

    outcome = evaluation.get("outcome")
    if outcome not in {"supported", "refuted", "inconclusive"}:
        fail("v2_oracle_outcome", "Oracle returned an unsupported terminal outcome",
             outcome=outcome)
    proof_receipt = _new_proof(
        project, campaign, hypothesis, recipe, run_row, evaluation, evidence_ids)
    finding = None
    if outcome == "supported" and evaluation.get("finding_allowed"):
        if proof_receipt is None:
            fail("v2_finding_proof", "Supported finding requires a current ProofReceipt")
        proof_scope = proof_receipt["proof_scope"]["accepted"][0]
        finding = new_finding(
            campaign_id=campaign["id"],
            hypothesis_id=hypothesis["id"], run_id=run_row["id"], mode="machine",
            proof_receipt_id=proof_receipt["id"],
            severity=_severity(recipe.get("family")),
            title=_finding_title(hypothesis, recipe),
            category=recipe.get("family", "generic"),
            impact="A controlled test met the declared proof scope; see limitations for what is not proven.",
            remediation="Apply the mechanism-specific fix and re-run the same frozen recipe.",
            evidence_ids=evidence_ids, proof_scope=proof_scope,
            decision_id=run_row["id"],
            limitations=evaluation.get("limitations") or [])

    run_revision = repository.get_revision("run", run_row["id"])
    hypothesis_revision = repository.get_revision(
        "hypothesis", hypothesis["id"])
    run_transition(run_row, "evaluated", note="oracle evaluated")
    if proof_receipt is not None:
        run_row["proof_receipt_id"] = proof_receipt["id"]
        hypothesis["proof_receipt_id"] = proof_receipt["id"]
    if finding is not None:
        run_row["finding_ids"] = sorted(set(
            run_row.get("finding_ids", []) + [finding["id"]]))
        hypothesis["finding_ids"] = sorted(set(
            hypothesis.get("finding_ids", []) + [finding["id"]]))
    transition(
        hypothesis, outcome,
        reason=f"oracle {outcome}")
    record_attempt(
        hypothesis, outcome=outcome, run_id=run_row["id"],
        reason="; ".join(evaluation.get("limitations") or []))
    run_row["hypothesis_status"] = hypothesis["status"]

    known_case = None
    known_case_revision = None
    known_case_id = hypothesis.get("known_case_id")
    if known_case_id:
        known_case = repository.get(
            "known_case", known_case_id, required=False)
        if known_case is not None and outcome in {
                "supported", "refuted", "inconclusive"}:
            known_case_revision = repository.get_revision(
                "known_case", known_case["id"])
            memberships = dict(known_case.get("campaign_memberships") or {})
            membership = dict(memberships.get(campaign["id"]) or {})
            membership.update({
                "universe_id": campaign["universe_id"],
                "status": (
                    "reported" if outcome == "supported" and finding is not None
                    else "verified" if outcome in {"supported", "refuted"}
                    else "blocked"
                ),
                "hypothesis_id": hypothesis["id"],
                "run_id": run_row["id"],
                "proof_receipt_id": (
                    proof_receipt.get("id") if proof_receipt else None),
                "updated_at": utc_now(),
            })
            memberships[campaign["id"]] = membership
            known_case["campaign_memberships"] = memberships

    with project.transaction():
        if proof_receipt is not None:
            repository.add(
                "proof_receipt", proof_receipt, immutable=True)
        if finding is not None:
            repository.add("finding", finding, immutable=False)
        repository.save(
            "run", run_row, expected_revision=run_revision)
        repository.save(
            "hypothesis", hypothesis,
            expected_revision=hypothesis_revision)
        if known_case is not None:
            repository.save(
                "known_case", known_case,
                expected_revision=known_case_revision)
    return finding, proof_receipt


def _verify_reject(message, *, legacy=False, **details):
    fail("v2_run_verify", message,
         binding_status="legacy_unverified" if legacy else "unverified",
         legacy=bool(legacy), requests_sent=0, finding_created=False,
         **details)


def _verify_request_control(project, operation, control, artifact):
    """Bind the bytes in the capture artifact back to this exact recipe control."""
    request = control.get("request") or {}
    captured = artifact.get("request") or {}
    try:
        expected_url = engine.require_scope(project.config, request.get("url"))
    except EngineError as exc:
        _verify_reject("Control request URL is no longer valid for the recipe",
                       control_id=control.get("id"), cause=exc.code)
    if captured.get("url") != expected_url:
        _verify_reject("Evidence URL does not match its persisted run control",
                       control_id=control.get("id"),
                       expected_url=expected_url, actual_url=captured.get("url"))
    expected_method = str(request.get("method") or "").upper()
    if expected_method != operation.get("method") \
            or captured.get("method") != operation.get("method"):
        _verify_reject("Evidence HTTP method does not match its control and operation",
                       control_id=control.get("id"))
    actual_headers = {
        str(key).lower(): value
        for key, value in (captured.get("headers") or {}).items()
    }
    for key, value in (request.get("headers") or {}).items():
        if actual_headers.get(str(key).lower()) != value:
            _verify_reject("Evidence request headers do not match the control",
                           control_id=control.get("id"), header=str(key).lower())
    try:
        raw_body = base64.b64decode(captured.get("body_base64", ""), validate=True)
    except (TypeError, ValueError):
        _verify_reject("Evidence request body is not canonical base64",
                       control_id=control.get("id"), legacy=True)
    if "body" in request:
        expected = request["body"]
        try:
            if isinstance(expected, (dict, list)):
                actual = json.loads(raw_body.decode("utf-8"))
            elif isinstance(expected, str):
                actual = raw_body.decode("utf-8")
            else:
                actual = None
        except (UnicodeError, ValueError):
            _verify_reject("Evidence request body cannot be compared to the control",
                           control_id=control.get("id"))
        if actual is None or digest(actual) != digest(expected):
            _verify_reject("Evidence request body does not match the control",
                           control_id=control.get("id"))
    elif "body_base64" in request:
        try:
            expected_body = base64.b64decode(request["body_base64"], validate=True)
        except (TypeError, ValueError):
            _verify_reject("Control request body is invalid base64",
                           control_id=control.get("id"))
        if raw_body != expected_body:
            _verify_reject("Evidence raw body does not match the control",
                           control_id=control.get("id"))
    elif raw_body:
        _verify_reject("Evidence contains a body absent from the control",
                       control_id=control.get("id"))


def _verify_fixture_control(project, recipe, prior, control, step, evidence, actual):
    """Validate the fixture lineage created by the real write, including cleanup later."""
    binding = (recipe.get("bindings") or {}).get("fixture")
    if not binding:
        if prior.get("fixture_id") is not None:
            _verify_reject("Run names a fixture absent from its recipe",
                           control_id=control.get("id"))
        return False
    fixture = project.get("v2_fixture", binding.get("fixture_id"), required=False)
    if fixture is None or prior.get("fixture_id") != binding.get("fixture_id"):
        _verify_reject("Run and recipe do not share the same persisted fixture",
                       control_id=control.get("id"))
    resource_binding = (recipe.get("bindings") or {}).get("resource") or {}
    if fixture.get("operation_id") != (recipe.get("bindings") or {}).get("operation_id") \
            or fixture.get("resource_id") != resource_binding.get("resource_id"):
        _verify_reject("Fixture operation/resource differs from the frozen recipe",
                       control_id=control.get("id"), fixture_id=fixture.get("id"))
    is_write = control.get("effect") == "test_resource_write" \
        or str((control.get("request") or {}).get("method", "")).upper() \
        not in READ_ONLY_METHODS
    if not is_write:
        return False
    required = ("fixture_revision", "fixture_fence", "dispatch_receipt_id", "request_digest")
    if any(step.get(key) in {None, ""} for key in required) \
            or type(step.get("fixture_revision")) is not int \
            or type(step.get("fixture_fence")) is not int:
        _verify_reject("Legacy write step lacks its fixture mutation binding",
                       control_id=control.get("id"), legacy=True)
    mutations = []
    for mutation in fixture.get("mutations") or []:
        effect = mutation.get("intended_effect") or {}
        if effect.get("evidence_id") == evidence.get("id"):
            mutations.append((mutation, effect))
    if len(mutations) != 1:
        _verify_reject("Write evidence has no unique persisted fixture mutation",
                       control_id=control.get("id"), evidence_id=evidence.get("id"))
    mutation, effect = mutations[0]
    if effect.get("kind") != "observed_http_control" \
            or effect.get("control_id") != control.get("id") \
            or effect.get("dispatch_receipt_id") != step.get("dispatch_receipt_id") \
            or effect.get("request_digest") != step.get("request_digest") \
            or digest(effect.get("actual")) != digest(actual) \
            or mutation.get("fence") != step.get("fixture_fence") \
            or fixture.get("fence") != step.get("fixture_fence") \
            or not binding.get("revision", 0) < step["fixture_revision"] <= fixture.get("revision", 0):
        _verify_reject("Fixture mutation/fence does not match the write control",
                       control_id=control.get("id"), evidence_id=evidence.get("id"))
    return True


def _bind_verify_run(project, args, campaign, hypothesis, recipe, prior, operation):
    """Return observations only from a complete persisted per-control binding chain."""
    if prior.get("mode") != "test":
        _verify_reject("verify requires a persisted test run, not an observe/verify or legacy run",
                       run_id=prior.get("id"), legacy=prior.get("mode") is None)
    if prior.get("status") not in {"response_saved", "evaluation_pending", "evaluated", "published"}:
        _verify_reject("Persisted run is incomplete or has an unresolved effect",
                       run_id=prior.get("id"), run_status=prior.get("status"))
    if prior.get("recipe_id") != recipe.get("id") \
            or prior.get("recipe_spec_hash") != recipe.get("spec_hash") \
            or prior.get("hypothesis_id") != hypothesis.get("id") \
            or prior.get("campaign_id") != campaign.get("id"):
        _verify_reject("Run, recipe, hypothesis and campaign do not match",
                       run_id=prior.get("id"))
    _executable, planned = _planned_controls(recipe, args, "test")
    steps = prior.get("steps")
    if not isinstance(steps, list) or len(steps) != len(planned) or not planned:
        _verify_reject("Legacy run lacks one durable step for every planned control",
                       run_id=prior.get("id"), legacy=True)
    step_evidence = [step.get("evidence_id") for step in steps]
    step_receipts = [step.get("dispatch_receipt_id") for step in steps]
    if any(not isinstance(value, str) or not value for value in step_evidence + step_receipts):
        _verify_reject("Legacy run steps lack evidence or dispatch receipt IDs",
                       run_id=prior.get("id"), legacy=True)
    if len(set(step_evidence)) != len(step_evidence) \
            or len(set(step_receipts)) != len(step_receipts):
        _verify_reject("Run evidence and dispatch receipts must be distinct per control",
                       run_id=prior.get("id"))
    evidence_ids = list(prior.get("evidence_ids") or [])
    supplied = list(args.get("evidence_ids") or [])
    if supplied and supplied != evidence_ids:
        _verify_reject("Explicit evidence must exactly match the persisted run evidence",
                       run_id=prior.get("id"))
    if evidence_ids != step_evidence \
            or list(prior.get("dispatch_receipt_ids") or []) != step_receipts:
        _verify_reject("Run-level evidence/dispatch lists do not match its control steps",
                       run_id=prior.get("id"),
                       legacy=not prior.get("evidence_ids") or not prior.get("dispatch_receipt_ids"))
    results = []
    control_bindings = []
    fixture_history = False
    bindings = recipe.get("bindings") or {}
    expected_session = bindings.get("session") or {}
    expected_resource = bindings.get("resource") or {}
    for control, step, evidence_id, receipt_id in zip(planned, steps, evidence_ids, step_receipts):
        if step.get("step_id") != control.get("id") \
                or step.get("status") != "completed" \
                or step.get("action") != "http.capture":
            _verify_reject("Run step does not match its exact frozen control",
                           run_id=prior.get("id"), control_id=control.get("id"),
                           legacy=not step.get("step_id"))
        receipt = project.get("execution_dispatch", receipt_id, required=False)
        if receipt is None:
            _verify_reject("Run step has no persisted dispatch receipt",
                           control_id=control.get("id"), legacy=True)
        try:
            evidence, artifact = engine.verify_current_evidence(project, evidence_id)
        except EngineError as exc:
            _verify_reject("Run evidence is not current and complete",
                           control_id=control.get("id"), evidence_id=evidence_id,
                           cause=exc.code)
        native = project.get("run", evidence.get("run_id"), required=False)
        if native is None:
            _verify_reject("Legacy evidence lacks its native capture run",
                           control_id=control.get("id"), evidence_id=evidence_id,
                           legacy=True)
        if evidence.get("operation_id") != operation.get("id") \
                or native.get("operation_id") != operation.get("id") \
                or evidence.get("operation_signature") != bindings.get("operation_signature") \
                or native.get("operation_signature") != bindings.get("operation_signature"):
            _verify_reject("Evidence operation differs from the frozen recipe",
                           control_id=control.get("id"), evidence_id=evidence_id)
        expected_identity = {
            "session_id": expected_session.get("session_id"),
            "session_generation": expected_session.get("generation"),
            "actor_id": expected_session.get("actor_id"),
        }
        if any(evidence.get(key) != value or native.get(key) != value
               for key, value in expected_identity.items()) \
                or prior.get("actor_id") != expected_identity["actor_id"]:
            _verify_reject("Evidence identity/session differs from the frozen recipe and run",
                           control_id=control.get("id"), evidence_id=evidence_id)
        expected_resource_id = expected_resource.get("resource_id")
        if evidence.get("resource_id") != expected_resource_id \
                or native.get("resource_id") != expected_resource_id \
                or evidence.get("resource_signature") != native.get("resource_signature"):
            _verify_reject("Evidence resource differs from the frozen recipe and native capture",
                           control_id=control.get("id"), evidence_id=evidence_id)
        if native.get("dispatch_id") != receipt_id \
                or native.get("dispatch_run_id") != prior.get("id") \
                or native.get("dispatch_attempted") is not True \
                or native.get("evidence_id") != evidence_id \
                or native.get("status") != "succeeded" \
                or native.get("lease_fence") != receipt.get("fence") \
                or receipt.get("run_id") != prior.get("id") \
                or receipt.get("action") != "http.capture" \
                or receipt.get("requests") != 1 \
                or receipt.get("budget_unit", "request") != "request" \
                or receipt.get("dispatch_attempted") is not True:
            _verify_reject("Evidence is not the result of this run's durable dispatch",
                           control_id=control.get("id"), evidence_id=evidence_id)
        expected_hash = digest([
            native.get("request_signature"), native.get("operation_signature"),
            native.get("session_generation"), native.get("resource_signature")])
        if step.get("request_digest") != expected_hash \
                or receipt.get("request_hash") != expected_hash \
                or step.get("response_digest") != evidence.get("sha256"):
            _verify_reject("Request/response digest does not bind evidence to its control",
                           control_id=control.get("id"), evidence_id=evidence_id,
                           legacy=not step.get("request_digest") or not step.get("response_digest"))
        effect = _control_effect(control, operation)
        if receipt.get("effect") != effect \
                or receipt.get("writes") != (1 if effect == "test_resource_write" else 0) \
                or native.get("effect") != effect:
            _verify_reject("Dispatch effect/write accounting differs from its control",
                           control_id=control.get("id"), evidence_id=evidence_id)
        _verify_request_control(project, operation, control, artifact)
        actual = _evidence_value(
            project, evidence_id, control.get("expected", {}).get("selector", "body"))
        expected = control.get("expected", {}).get("value")
        fixture_history = _verify_fixture_control(
            project, recipe, prior, control, step, evidence, actual) or fixture_history
        results.append((control, {
            "evidence_id": evidence_id,
            "actual": actual,
            "matched": str(actual).strip() == str(expected).strip() if expected is not None else None,
        }))
        control_bindings.append({
            "control_id": control["id"], "step_id": step["step_id"],
            "evidence_id": evidence_id, "dispatch_receipt_id": receipt_id,
            "native_run_id": native["id"], "request_digest": expected_hash,
        })
    current_context = context(project, campaign, recipe)
    if fixture_history:
        # assert_current still checks every non-fixture binding.  The exact
        # mutation/fence chain above authorizes the fixture's later revisions.
        current_context["fixture"] = dict(bindings.get("fixture") or {})
    assert_current(recipe, current_context)
    return evidence_ids, results, control_bindings


def _verify(project, args, campaign, hypothesis, recipe):
    """Zero-request re-evaluation of one fully bound persisted test run."""
    repository = Repository(project)
    if not args.get("run_id"):
        _verify_reject(
            "verify requires a persisted run_id from the same recipe; bare evidence_ids are unverified")
    prior = repository.require_campaign(
        "run", args["run_id"], campaign["id"])
    if prior.get("hypothesis_id") != hypothesis["id"]:
        _verify_reject("Prior run and hypothesis do not belong to the same experiment",
                       run_id=prior.get("id"))
    if recipe is None and prior.get("recipe_id"):
        recipe = repository.get("recipe", prior["recipe_id"], required=False)
    if not recipe:
        _verify_reject("verify requires the persisted run's frozen recipe",
                       run_id=prior.get("id"), legacy=True)
    recipe, hypothesis = _campaign_entities(
        repository, campaign, recipe=recipe, hypothesis=hypothesis)
    if prior.get("recipe_id") != recipe["id"]:
        _verify_reject("Prior run and recipe do not match", run_id=prior.get("id"))
    operation = _operation(project, recipe)
    evidence_ids, results, control_bindings = _bind_verify_run(
        project, args, campaign, hypothesis, recipe, prior, operation)
    idempotency_key = text(
        args.get("idempotency_key")
        or ("verify:" + digest({
            "campaign_id": campaign["id"],
            "hypothesis_id": hypothesis["id"],
            "recipe_id": recipe["id"],
            "source_run_id": prior["id"],
            "evidence_ids": evidence_ids,
        })),
        "idempotency_key", maximum=256)
    existing = _existing(project, campaign["id"], idempotency_key)
    if existing is not None:
        return {
            "run": run_public(existing),
            "outcome": existing.get("outcome"),
            "proof_receipt": (
                repository.get(
                    "proof_receipt", existing["proof_receipt_id"],
                    required=False)
                if existing.get("proof_receipt_id") else None
            ),
            "requests_sent": 0,
            "replayed": False,
            "notice": "This offline verification is already durable; evidence was not re-sent or re-evaluated.",
        }
    evaluation = _eval_from_results(recipe, results)
    run_row = new_run(recipe=recipe, campaign_id=campaign["id"],
                      idempotency_key=idempotency_key, mode="verify")
    run_row["universe_id"] = campaign["universe_id"]
    run_row["verification_of_run_id"] = prior["id"]
    run_row["control_bindings"] = control_bindings
    run_row["binding_status"] = "verified"
    run_row["evidence_ids"] = evidence_ids
    run_row["dispatch_budget"] = {
        "max_requests": 0, "max_writes": 0,
        "requests_used": 0, "writes_used": 0,
    }
    run_row["dispatch_receipt_ids"] = []
    run_row["proof_receipt_id"] = None
    run_row["finding_ids"] = []
    run_row["evaluation"] = evaluation
    run_row["outcome"] = evaluation.get("outcome")
    try:
        repository.add(
            "run", run_row, immutable=False, create_only=True)
    except EngineError as exc:
        if exc.code != "immutable_record":
            raise
        existing = _existing(project, campaign["id"], idempotency_key)
        if existing is None:
            fail("idempotency_conflict",
                 "Concurrent offline verification could not be reloaded")
        return {
            "run": run_public(existing),
            "outcome": existing.get("outcome"),
            "requests_sent": 0,
            "replayed": False,
        }
    worker_lease = _claim_run_execution(
        project, run_row, args.get("worker_id", "local"),
        ttl_seconds=args.get("lease_seconds", 300))
    coordinator.reserve_budget(
        project, _execution_budget_name(run_row["id"]), 0, 0)
    repository.save("run", run_row, expected_revision=1)
    run_transition(
        run_row, "dispatch_started",
        note="offline verification; no request dispatch")
    run_transition(run_row, "response_saved", note="existing evidence bound")
    run_transition(run_row, "evaluation_pending", note="offline oracle evaluation")
    repository.save("run", run_row, expected_revision=2)
    if hypothesis.get("status") != "running" \
            and hypothesis.get("status") != evaluation.get("outcome"):
        hypothesis_revision = repository.get_revision(
            "hypothesis", hypothesis["id"])
        from ..domain.hypothesis import transition
        if hypothesis.get("status") != "ready":
            transition(
                hypothesis, "ready",
                reason="offline verification reopened the prior outcome")
        transition(
            hypothesis, "running",
            reason="offline verification evaluation")
        repository.save(
            "hypothesis", hypothesis,
            expected_revision=hypothesis_revision)
    finding, proof_receipt = _commit_evaluation(
        project, repository, campaign, hypothesis, recipe, run_row,
        evaluation, evidence_ids)
    coordinator.release(project, worker_lease, reconciled=False)
    return {
        "run": run_public(run_row),
        "outcome": evaluation["outcome"],
        "finding": finding,
        "proof_receipt": proof_receipt,
        "verification_of_run_id": prior["id"],
        "control_bindings": control_bindings,
        "requests_sent": 0,
    }


def inspect(project, args):
    repository = Repository(project)
    if args.get("run_id"):
        run_row = repository.get("run", args["run_id"])
        return {"run": run_public(run_row),
                "recipe": recipe_public(repository.get("recipe", run_row["recipe_id"])) if run_row.get("recipe_id") else None}
    if args.get("recipe_id"):
        recipe = repository.get("recipe", args["recipe_id"])
        return {"recipe": recipe_public(recipe), "private_capsule_available": True,
                "control_count": sum(len(group.get("controls", [])) for group in recipe.get("control_groups", []))}
    fail("v2_run_inspect", "Inspect requires run_id or recipe_id")
