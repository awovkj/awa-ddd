"""Durable 2.0 test runner: one call performs preflight, controlled execution,
evidence persistence, oracle evaluation and coverage delta — while keeping each
durable step separate and never replaying uncertain writes.
"""
from __future__ import annotations

import base64
import json

from .. import engine
from ..domain import new_finding, new_run
from ..domain.common import digest, fail, text, utc_now
from ..domain.repository import Repository
from ..domain.test_recipe import assert_current, public_view as recipe_public, render
from ..domain.test_run import add_step, claim as claim_run, mark_effect_unknown, public_view as run_public, transition as run_transition
from ..store import EngineError
from . import oracle_profiles


def _campaign(project, campaign_id):
    campaign = Repository(project).get("campaign", campaign_id)
    if campaign.get("state") != "active":
        fail("v2_campaign_state", "Campaign is not active")
    return campaign


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
    return {
        "scope_epoch": campaign.get("scope_epoch"),
        "target_build": (universe or {}).get("target_build"),
        "operation_signature": engine.operation_signature(operation),
        "session": _session_context(project, recipe),
        "resource": _resource_context(project, recipe),
        "fixture": _fixture_context(project, recipe),
    }


def _existing(project, idempotency_key):
    for row in Repository(project).list("run", limit=None)[0]:
        if row.get("idempotency_key") == idempotency_key:
            return row
    return None


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
        observations.setdefault("normal_plain_value", observations.get("normal_actual"))
        observations.setdefault("attack_arithmetic_value", observations.get("attack_actual"))
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
    elif args.get("hypothesis_id"):
        hypothesis = repository.get("hypothesis", args["hypothesis_id"])
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
                recipe = existing_recipe
            else:
                repository.add("recipe", recipe, immutable=True)
    if hypothesis is None:
        fail("v2_run_recipe", "test.run requires recipe_id or hypothesis_id")
    if mode == "verify":
        if recipe is None:
            rows = [row for row in repository.list("recipe", limit=None)[0]
                    if row.get("hypothesis_id") == hypothesis["id"]]
            recipe = rows[-1] if rows else None
        return _verify(project, args, campaign, hypothesis, recipe)
    idempotency_key = text(args.get("idempotency_key") or ("run:" + hypothesis["id"] + ":" + utc_now()),
                           "idempotency_key", maximum=256)
    existing = _existing(project, idempotency_key)
    if existing:
        if recipe is not None and existing.get("recipe_id") != recipe["id"]:
            fail("idempotency_conflict", "Idempotency key already belongs to a different recipe")
        return {"run": run_public(existing), "replayed": False,
                "notice": "Idempotency key already belongs to a durable run; no request was sent again."}
    if recipe is None:
        fail("v2_run_recipe", "No recipe is available")
    assert_current(recipe, context(project, campaign, recipe))
    from ..domain.hypothesis import transition as hypothesis_transition
    if hypothesis.get("status") == "unplanned":
        hypothesis_transition(hypothesis, "ready", reason="scheduler selected the hypothesis")
    if mode == "test" and hypothesis.get("status") == "ready":
        hypothesis_transition(hypothesis, "running", reason="durable test run started")
        repository.save("hypothesis", hypothesis)
    run_row = new_run(recipe=recipe, campaign_id=campaign["id"], idempotency_key=idempotency_key,
                      actor_id=(recipe["bindings"].get("session") or {}).get("actor_id"), mode=mode)
    repository.add("run", run_row, immutable=False)
    claim_run(run_row, args.get("worker_id", "local"), ttl_seconds=args.get("lease_seconds", 300))
    run_transition(run_row, "dispatch_started", note="first control dispatch")
    run_row["dispatch_started_at"] = utc_now()
    repository.save("run", run_row)
    effect = recipe.get("limits", {}).get("effect", "read_only")
    if mode == "observe" and effect != "read_only":
        run_transition(run_row, "failed", note="observe cannot send a write")
        repository.save("run", run_row)
        fail("v2_observe_effect", "Observe mode is read-only; use test mode with an authorized fixture for writes")
    if effect == "test_resource_write" and not (campaign.get("allow_mutation") and project.config.get("allow_mutation")):
        run_transition(run_row, "failed", note="write authorization missing")
        run_row["error"] = {"code": "v2_write_authorization", "message": "Write recipe requires campaign/project allow_mutation"}
        repository.save("run", run_row)
        fail("v2_write_authorization", "Write recipe requires campaign and project allow_mutation")
    if effect == "test_resource_write":
        fixture_binding = recipe.get("bindings", {}).get("fixture") or {}
        fixture = repository.get("fixture", fixture_binding.get("fixture_id"), required=False)
        if fixture is None:
            fail("v2_recipe_fixture", "Write recipe fixture no longer exists")
        if fixture.get("state") not in {"verified", "leased", "readback_ok"}:
            fail("v2_fixture_state", "Write recipe fixture is not verified and leaseable")
        if fixture.get("state") == "leased" and (fixture.get("lease") or {}).get("worker_id") != args.get("worker_id", "local"):
            fail("v2_fixture_lease", "Fixture is leased by another worker")
        run_row["fixture_id"] = fixture["id"]
    control_results = []
    evidence_ids = []
    executable = render(recipe, args.get("variables"))
    groups = executable.get("control_groups") or recipe.get("control_groups", [])
    planned = groups[0].get("controls", []) if groups else []
    if mode == "observe":
        planned = [control for control in planned if control.get("role") == "normal"][:1]
    try:
        for control in planned:
            capture_args = _capture_args(recipe, control, idempotency_key=idempotency_key + ":" + control["id"])
            evidence = engine.capture(project, capture_args)
            evidence_ids.append(evidence["id"])
            actual = _evidence_value(project, evidence["id"], control.get("expected", {}).get("selector", "body"))
            expected = control.get("expected", {}).get("value")
            matched = str(actual).strip() == str(expected).strip() if expected is not None else None
            control_results.append((control, {"evidence_id": evidence["id"], "actual": actual, "matched": matched}))
            add_step(run_row, step_id=control["id"], action="http.capture",
                     response_digest=evidence.get("sha256"), status="completed")
            repository.save("run", run_row)
    except EngineError as exc:
        if effect == "test_resource_write" and exc.details.get("run_id"):
            mark_effect_unknown(run_row, reason=str(exc))
            run_row["evidence_ids"] = evidence_ids
            repository.save("run", run_row)
            hypothesis["status"] = "blocked"
            hypothesis["state_reason"] = "effect_unknown"
            hypothesis["attempt"] = {**hypothesis.get("attempt", {}), "last_outcome": "effect_unknown",
                                     "consecutive_failures": hypothesis.get("attempt", {}).get("consecutive_failures", 0) + 1,
                                     "last_attempt_at": utc_now()}
            repository.save("hypothesis", hypothesis)
            return {"run": run_public(run_row), "outcome": "effect_unknown", "requires_reconciliation": True,
                    "notice": "A write may have reached the target; inspect its run and read back fixture state before any retry."}
        run_transition(run_row, "failed", note=str(exc))
        run_row["error"] = {"code": exc.code, "message": str(exc)}
        run_row["evidence_ids"] = evidence_ids
        repository.save("run", run_row)
        if hypothesis:
            hypothesis["attempt"] = {**hypothesis.get("attempt", {}), "last_outcome": "execution_failed",
                                     "consecutive_failures": hypothesis.get("attempt", {}).get("consecutive_failures", 0) + 1,
                                     "last_attempt_at": utc_now()}
            repository.save("hypothesis", hypothesis)
        raise
    run_row["evidence_ids"] = evidence_ids
    run_transition(run_row, "response_saved", note="all planned controls captured")
    if mode == "observe":
        run_row["evaluation"] = {"outcome": "observed", "finding_allowed": False,
                                 "limitations": ["Observe mode records evidence but does not test a hypothesis."]}
        run_row["outcome"] = "observed"
        run_transition(run_row, "evaluation_pending", note="observation evaluation")
        run_transition(run_row, "evaluated", note="observation only")
        repository.save("run", run_row)
        return {"run": run_public(run_row), "outcome": "observed", "coverage_delta": {"tested": 0}}
    run_transition(run_row, "evaluation_pending", note="oracle evaluation")
    evaluation = _eval_from_results(recipe, control_results)
    finding = None
    if evaluation["outcome"] == "supported" and evaluation.get("finding_allowed"):
        finding = new_finding(
            hypothesis_id=hypothesis["id"], run_id=run_row["id"], mode="machine",
            severity=_severity(recipe.get("family")), title=_finding_title(hypothesis, recipe),
            category=recipe.get("family", "generic"),
            impact="A controlled test met the declared proof scope; see limitations for what is not proven.",
            remediation="Apply the mechanism-specific fix and re-run the same frozen recipe.",
            evidence_ids=evidence_ids, proof_scope=evaluation.get("proof_scope") or recipe["oracle"]["proof_scope"],
            decision_id=run_row["id"], limitations=evaluation.get("limitations") or [])
        repository.add("finding", finding, immutable=False)
        run_row["finding_ids"] = [finding["id"]]
        hypothesis["finding_ids"] = sorted(set(hypothesis.get("finding_ids", []) + [finding["id"]]))
    _apply_outcome(project, repository, hypothesis, run_row, evaluation, mode=mode)
    run_row["evaluation"] = evaluation
    run_row["outcome"] = evaluation.get("outcome")
    run_transition(run_row, "evaluated", note="oracle evaluated")
    repository.save("run", run_row)
    return {"run": run_public(run_row), "outcome": evaluation["outcome"], "finding": finding,
            "coverage_delta": {"tested": 1 if evaluation["outcome"] in {"supported", "refuted", "inconclusive"} else 0,
                               "finding_created": bool(finding), "family": hypothesis["family"]}}


def _severity(family):
    return {"sql_injection": "high", "command_injection": "critical", "template_injection": "high",
            "deserialization": "high", "xss": "medium", "ssrf": "medium", "xxe": "medium",
            "file_upload": "high", "path_traversal": "medium", "access_control": "high",
            "business_logic": "medium", "generic": "low"}.get(family, "low")


def _finding_title(hypothesis, recipe):
    return f"{recipe.get('family', 'generic')}: {hypothesis.get('security_property')} ({hypothesis.get('operation_id')})"


def _apply_outcome(project, repository, hypothesis, run_row, evaluation, *, mode):
    from ..domain.hypothesis import record_attempt, transition
    outcome = evaluation.get("outcome")
    if outcome == "supported":
        transition(hypothesis, "supported", reason="oracle supported")
    elif outcome == "refuted":
        transition(hypothesis, "refuted", reason="oracle refuted")
    elif outcome == "inconclusive":
        transition(hypothesis, "inconclusive", reason="oracle inconclusive")
    record_attempt(hypothesis, outcome=outcome, run_id=run_row["id"],
                   reason="; ".join(evaluation.get("limitations") or []))
    repository.save("hypothesis", hypothesis)
    known_case_id = hypothesis.get("known_case_id")
    if known_case_id:
        known_case = repository.get("known_case", known_case_id, required=False)
        if known_case is not None and outcome in {"supported", "refuted", "inconclusive"}:
            known_case["status"] = "reported" if outcome == "supported" and run_row.get("finding_ids") else \
                "verified" if outcome in {"supported", "refuted"} else "blocked"
            repository.save("known_case", known_case)
    run_row["hypothesis_status"] = hypothesis["status"]
    return hypothesis


def _verify(project, args, campaign, hypothesis, recipe):
    """Zero-request re-evaluation of existing evidence or a persisted run."""
    evidence_ids = args.get("evidence_ids") or []
    if not evidence_ids and args.get("run_id"):
        prior = Repository(project).get("run", args["run_id"])
        evidence_ids = prior.get("evidence_ids") or []
        recipe = recipe or Repository(project).get("recipe", prior["recipe_id"], required=False)
    if not recipe:
        fail("v2_run_verify", "verify requires recipe_id or a run_id with a recipe")
    if not evidence_ids:
        fail("v2_run_verify", "verify requires existing evidence IDs; it never sends requests")
    controls = recipe.get("control_groups", [{}])[0].get("controls", [])
    results = []
    for index, evidence_id in enumerate(evidence_ids):
        control = controls[index] if index < len(controls) else {"id": str(index), "role": "normal", "expected": {"selector": "body"}}
        actual = _evidence_value(project, evidence_id, control.get("expected", {}).get("selector", "body"))
        expected = control.get("expected", {}).get("value")
        results.append((control, {"evidence_id": evidence_id, "actual": actual,
                                  "matched": str(actual).strip() == str(expected).strip() if expected is not None else None}))
    evaluation = _eval_from_results(recipe, results)
    run_row = new_run(recipe=recipe, campaign_id=campaign["id"],
                      idempotency_key="verify:" + digest(evidence_ids), mode="verify")
    run_row["evidence_ids"] = evidence_ids
    run_row["status"] = "evaluated"
    run_row["evaluation"] = evaluation
    run_row["outcome"] = evaluation.get("outcome")
    Repository(project).add("run", run_row, immutable=False)
    _apply_outcome(project, Repository(project), hypothesis, run_row, evaluation, mode="verify")
    return {"run": run_public(run_row), "outcome": evaluation["outcome"], "requests_sent": 0}


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
