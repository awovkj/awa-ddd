"""Bounded business workflows with checkpoints and explicit variable binding.

Steps are sequential by default. A step may declare `concurrent: N` (2..40) to fire the
same request N times against a shared barrier; every attempt is captured as its own
evidence record. Concurrency is required to express check-then-act races, which cannot be
represented by sequential steps: a recharge callback replayed concurrently credited one
order many times while sequential replays were correctly rejected.
"""
from __future__ import annotations
import threading
import re
import base64
from concurrent.futures import ThreadPoolExecutor
from .store import EngineError, now, canonical
from .engine import capture, verify_evidence, verify_current_evidence, preflight_capture, stable
from .transport import response_json, pointer


def substitute(value, variables):
    if isinstance(value,str):
        if value.startswith("${") and value.endswith("}") and value.count("${")==1:
            key=value[2:-1]
            if key not in variables:
                raise EngineError("variable", "Missing scenario variable: "+key)
            return variables[key]
        result=value
        for key,actual in variables.items():
            if "${"+key+"}" in result:
                from urllib.parse import quote
                result=result.replace("${"+key+"}",quote(str(actual),safe=""))
        if "${" in result:
            raise EngineError("variable", "Unresolved scenario variable")
        return result
    if isinstance(value,list):
        return [substitute(x,variables) for x in value]
    if isinstance(value,dict):
        return {k:substitute(v,variables) for k,v in value.items()}
    return value


def _references(value):
    if isinstance(value, str):
        return set(re.findall(r"\$\{([^}]+)\}", value))
    if isinstance(value, list):
        return set().union(*(_references(item) for item in value)) if value else set()
    if isinstance(value, dict):
        return set().union(*(_references(item) for item in value.values())) if value else set()
    return set()


def _pointer_syntax(value):
    return isinstance(value, str) and value.startswith("/") and not re.search(r"~(?![01])", value) and not _references(value)


def _steps(args):
    spec = args.get("scenario")
    if not isinstance(spec, dict):
        raise EngineError("scenario_shape", "scenario must be an object with steps")
    steps = spec.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 25 or any(not isinstance(step, dict) for step in steps):
        raise EngineError("scenario_budget", "Scenario needs 1..25 step objects")
    identifiers = [step.get("id") for step in steps]
    if any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value) for value in identifiers) \
            or len(set(identifiers)) != len(identifiers):
        raise EngineError("step_id", "Step IDs must be unique bounded names, not expressions")
    total = 0
    known = set()
    for step in steps:
        repeats = step.get("concurrent", 1)
        if "concurrent" in step and (type(repeats) is not int or not 2 <= repeats <= 40):
            raise EngineError("scenario_budget", "concurrent must be an integer 2..40")
        total += repeats
        current = {key: value for key, value in step.items() if key not in {"extract", "assertions", "concurrent"}}
        if "operation_id" not in current:
            raise EngineError("scenario_shape", "Every step requires operation_id", {"step_id": step["id"]})
        if _references(current) - known:
            raise EngineError("scenario_variable", "Request variables must be extracted by an earlier step", {"step_id": step["id"]})
        for field in ("operation_id", "session_id", "resource_id", "body_file", "effect", "idempotency_key", "timeout", "max_bytes"):
            if _references(current.get(field)):
                raise EngineError("scenario_control", "Target-derived values cannot select local files, identity, resource, operation or execution policy",
                                  {"step_id": step["id"], "field": field})
        extracts = step.get("extract", {})
        assertions = step.get("assertions", [])
        if not isinstance(extracts, dict) or len(extracts) > 25 or any(
                not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", key)
                or not _pointer_syntax(selector) for key, selector in extracts.items()):
            raise EngineError("scenario_extract", "extract requires bounded names and JSON Pointer selectors", {"step_id": step["id"]})
        known.update(step["id"] + "." + key for key in extracts)
        if not isinstance(assertions, list) or len(assertions) > 25 or any(
                not isinstance(assertion, dict) or "equals" not in assertion
                or not _pointer_syntax(assertion.get("selector"))
                or _references(assertion) - known for assertion in assertions):
            raise EngineError("scenario_assertion", "Assertions require a JSON Pointer and equals using known variables", {"step_id": step["id"]})
    if total > 200:
        raise EngineError("scenario_budget", "Scenario permits at most 200 total request attempts")
    return spec, steps, total


def _static_request_checks(project, current, dynamic):
    """Reject independent static failures even when another field is deferred."""
    from . import engine
    from .scope import require_scope, bind_operation
    from .transport import headers_map
    operation = project.get("operation", current["operation_id"])
    url = current.get("url") or operation["url"]
    params = None
    if "url" not in dynamic:
        url = require_scope(project.config, url)
        params = bind_operation(operation, url, operation["method"])
        if "{" in url or "}" in url:
            raise EngineError("unbound_url", "Resolve the static operation URL before execution")
    session = project.get("session", current["session_id"]) if current.get("session_id") else None
    if session:
        engine.session_valid(project, session)
        if "url" not in dynamic:
            engine.require_session_origin(project, session, url)
    raw_headers = current.get("headers", {})
    if not isinstance(raw_headers, dict):
        raise EngineError("headers", "Request headers must be an object")
    # Placeholder values validate syntax only; no credential/payload is sent here.
    headers = headers_map({key: "AWA-PREFLIGHT" if _references(value) else value for key, value in raw_headers.items()})
    if any(key in headers for key in ("host", "content-length", "transfer-encoding", "connection")):
        raise EngineError("headers", "Transport framing headers are managed by the executor")
    if any(key in headers for key in ("cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token", "x-session-token")):
        raise EngineError("credential_override", "Authentication headers belong to a registered session")
    if session:
        for name, value in raw_headers.items():
            key = name.lower()
            if key in session["headers"] and (_references(value) or headers[key] != session["headers"][key]):
                raise EngineError("credential_override", "Scenario headers cannot replace verified session defaults")
    cookie = current.get("anonymous_cookie")
    if cookie is not None:
        if session or operation["auth"] != "public":
            raise EngineError("anonymous_cookie", "Anonymous state must not replace a verified identity")
        if not _references(cookie) and (not isinstance(cookie, str) or not cookie.strip()
                                       or len(cookie) > 8192 or "\r" in cookie or "\n" in cookie):
            raise EngineError("anonymous_cookie", "Anonymous state requires a single-line cookie value")
    resource = project.get("resource", current["resource_id"]) if current.get("resource_id") else None
    if resource and resource["operation_id"] != operation["id"]:
        raise EngineError("resource_mismatch", "Resource belongs to another operation")
    if operation["method"] not in {"GET", "HEAD", "OPTIONS"}:
        if not project.config.get("allow_mutation") or current.get("effect") != "test_resource_write":
            raise EngineError("operation_effect", "Dynamic writes still require project permission and test_resource_write")
        if not resource and not (operation.get("state_scope") == "actor" and session):
            raise EngineError("operation_effect", "Dynamic writes still need an explicit resource or actor-scoped identity")
    timeout, max_bytes = current.get("timeout", 15), current.get("max_bytes", 1024 * 1024)
    if type(timeout) not in (int, float) or not 0 < timeout <= 60 \
            or type(max_bytes) is not int or not 1 <= max_bytes <= 4 * 1024 * 1024:
        raise EngineError("budget", "Invalid static request budget")
    if sum(current.get(key) is not None for key in ("body", "body_file", "body_base64")) > 1:
        raise EngineError("body", "Supply only one body source")
    known_body = current.get("body")
    if current.get("body_file") is not None:
        known_body = engine._read_body_file(project, current["body_file"])
    elif current.get("body_base64") is not None and "body_base64" not in dynamic:
        try:
            body_bytes = base64.b64decode(current["body_base64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise EngineError("body", "Invalid static base64 body") from exc
        if len(body_bytes) > 1024 * 1024:
            raise EngineError("body_budget", "Request body exceeds budget")
        known_body = body_bytes
    elif current.get("body") is not None:
        body = current["body"]
        if not isinstance(body, (dict, list, str, bytes)):
            raise EngineError("body", "Body must be JSON, text or bytes")
        body_bytes = body if isinstance(body, bytes) else (body.encode("utf-8") if isinstance(body, str) else canonical(body).encode("utf-8"))
        if len(body_bytes) > 1024 * 1024:
            raise EngineError("body_budget", "Known body content already exceeds budget")
    if operation["method"] not in {"GET", "HEAD", "OPTIONS"} and not resource:
        if any(field in dynamic for field in ("body", "body_base64")) or not engine._actor_bound_write(
                operation, session, url=url, body=known_body):
            raise EngineError("operation_effect", "Fixture-free actor writes must have no query or body; bind an explicit test resource for business inputs")
    if resource and ((resource["request_binding"]["location"] in {"path", "query"} and params is not None)
                     or (resource["request_binding"]["location"] == "body"
                         and not any(field in dynamic for field in ("body", "body_base64")))):
        engine._resource_binding(resource, params or {}, url, known_body,
                                 content_type=headers.get("content-type") or operation.get("content_type", ""))
    media = operation.get("content_type")
    if media and "content-type" in headers and not _references(raw_headers.get("content-type", raw_headers.get("Content-Type"))):
        if headers["content-type"].split(";", 1)[0].lower() != media.split(";", 1)[0]:
            raise EngineError("media_binding", "Static content type does not match the operation")


def _execution_context(project, current):
    from .engine import actor_signature, resource_signature

    operation = project.get("operation", current["operation_id"])
    session = project.get("session", current["session_id"]) if current.get("session_id") else None
    actor = project.get("actor", session["actor_id"]) if session else None
    resource = project.get("resource", current["resource_id"]) if current.get("resource_id") else None
    return {"operation_id": operation["id"], "method": operation["method"],
            "effect": "read_only" if operation["method"] in {"GET", "HEAD", "OPTIONS"} else "test_resource_write",
            "session_id": session["id"] if session else None, "actor_id": actor["id"] if actor else None,
            "actor_signature": actor_signature(actor) if actor else None,
            "resource_id": resource["id"] if resource else None,
            "resource_signature": resource_signature(resource) if resource else None}


def preflight(project, args):
    """Check all static requests before execution; dependent values stay deferred."""
    _, steps, total = _steps(args)
    checked, errors = [], []
    for step in steps:
        current = {key: value for key, value in step.items() if key not in {"extract", "assertions", "concurrent"}}
        dynamic = [key for key, value in current.items() if _references(value)]
        if dynamic:
            # Do not approve a placeholder as if it were the eventual resource/session.
            # Independent scope, permission and budget failures must still stop early.
            try:
                _static_request_checks(project, current, dynamic)
                checked.append({"step_id": step["id"], "status": "deferred", "dynamic_fields": dynamic,
                                **_execution_context(project, current),
                                "next_action": "Runtime preflight after extracting the prior step's values"})
            except (EngineError, KeyError, TypeError, ValueError) as exc:
                errors.append({"step_id": step["id"], "error_code": getattr(exc, "code", "invalid_input")})
            continue
        try:
            prepared = preflight_capture(project, current)
            checked.append({"step_id": step["id"], "status": "static_valid", **_execution_context(project, current),
                            "body_bytes": prepared["body_bytes"],
                            "request_signature": prepared["request_signature"]})
        except (EngineError, KeyError, TypeError, ValueError) as exc:
            errors.append({"step_id": step["id"], "error_code": getattr(exc, "code", "invalid_input")})
    return {"valid_spec": True, "static_valid": not errors, "steps": checked, "errors": errors,
            "deferred_steps": sum(row["status"] == "deferred" for row in checked),
            "total_attempts": total, "requests_sent": 0,
            "limitation": "Future extracted values are not approved by static preflight; every resolved request is checked again before execution."}


def run_scenario(project,args):
    spec, steps, _ = _steps(args)
    identity=stable("SC",args["idempotency_key"]) if args.get("idempotency_key") else project.id("SC")
    signature=stable("SPEC",spec)
    previous=project.get("run",identity,required=False)
    if previous:
        if previous.get("spec_signature")!=signature:
            raise EngineError("idempotency_conflict", "Scenario key belongs to a different specification")
        if previous["status"]=="succeeded":
            for eid in previous["evidence_ids"]:
                verify_current_evidence(project,eid)
            return previous
        raise EngineError("scenario_uncertain", "Inspect prior checkpoints and resource state; interrupted scenarios are never blindly replayed",
                          {"run_id": identity, "next_action": "run.inspect", "requests_replayed": 0})
    checked = preflight(project, args)
    if not checked["static_valid"]:
        raise EngineError("scenario_preflight", "Static scenario preflight failed; no requests or run claims were made",
                          {"next_action": "scenario.preflight", "steps": checked["errors"], "requests_sent": 0})
    run={"id":identity,"kind":"scenario","status":"running","started_at":now(),"spec_signature":signature,
         "checkpoints":[],"evidence_ids":[], "preflight": checked}
    project.claim(run)
    variables={}
    phase = "capture"
    step = steps[0]
    try:
        for step in steps:
            phase = "capture"
            current=substitute({k:v for k,v in step.items() if k not in {"extract","assertions","concurrent"}},variables)
            # Resolve future values before any sequential or concurrent attempt.
            preflight_capture(project, current)
            repeats=step.get("concurrent")
            if repeats is None:
                current["idempotency_key"]=identity+":"+step["id"]
                evidence=capture(project,current)
                run["evidence_ids"].append(evidence["id"])
                run["checkpoints"].append({"step_id":step["id"],"evidence_id":evidence["id"],"status":"captured"})
                project.put("run",run)
                _,artifact=verify_evidence(project,evidence["id"])
            else:
                base_id=identity+":"+step["id"]
                # A shared barrier keeps the requests genuinely concurrent; without it
                # thread startup serializes them and the race window closes.
                barrier=threading.Barrier(repeats, timeout=int(step.get("timeout",15))+5)
                def fire(index):
                    barrier.wait()
                    attempt=dict(current)
                    attempt["idempotency_key"]=base_id+":"+str(index)
                    return capture(project,attempt)
                with ThreadPoolExecutor(max_workers=repeats) as pool:
                    futures=[pool.submit(fire,i) for i in range(repeats)]
                    results=[]
                    for future in futures:
                        try:
                            results.append(future.result())
                        except Exception as exc:
                            results.append(exc)
                successes=[r for r in results if isinstance(r,dict)]
                failures=[r for r in results if isinstance(r,BaseException)]
                run["evidence_ids"].extend(r["id"] for r in successes)
                # Failure reasons are part of the observation: a race that only manifests
                # because N-1 callers lost a lock is different from one where N-1 were
                # rejected by application logic.
                reasons={}
                for exc in failures:
                    key=getattr(exc,"code",None) or type(exc).__name__
                    reasons[key]=reasons.get(key,0)+1
                run["checkpoints"].append({"step_id":step["id"],"concurrent":repeats,
                    "evidence_ids":[r["id"] for r in successes],
                    "attempt_run_ids": [r.get("run_id") for r in successes if r.get("run_id")]
                        + [r.details["run_id"] for r in failures if isinstance(r, EngineError) and r.details.get("run_id")],
                    "failed_attempts":len(failures),"failure_reasons":reasons,"status":"captured" if successes else "failed"})
                project.put("run",run)
                if not successes:
                    raise EngineError("scenario_failed", "Every concurrent attempt failed at step "+step["id"])
                _,artifact=verify_evidence(project,successes[0]["id"])
            phase = "extract"
            for key,selector in step.get("extract",{}).items():
                variables[step["id"]+"."+key]=pointer(response_json(artifact),selector)
            phase = "assertion"
            for assertion in step.get("assertions",[]):
                if pointer(response_json(artifact),assertion["selector"])!=substitute(assertion["equals"],variables):
                    raise EngineError("scenario_assertion", "Business assertion failed at step "+step["id"])
            run["checkpoints"][-1]["status"]="verified"
            project.put("run",run)
        run.update(status="succeeded",finished_at=now())
    except Exception as exc:
        error_code = getattr(exc,"code",type(exc).__name__)
        if not run["checkpoints"] or run["checkpoints"][-1]["step_id"] != step["id"]:
            run["checkpoints"].append({"step_id": step["id"], "status": "failed", "error_code": error_code,
                                       "attempt_run_id": getattr(exc, "details", {}).get("run_id")})
        else:
            run["checkpoints"][-1].update(status="failed", error_code=error_code, failed_phase=phase)
        run.update(status="failed",finished_at=now(),error=getattr(exc,"code",type(exc).__name__),
                   next_action="Inspect persisted evidence and reconcile test-resource state before a new run")
        project.put("run",run)
        project.event("scenario.failed",{"run_id":identity,"completed_steps":len(run["checkpoints"])})
        raise EngineError(error_code, "Scenario stopped at step " + step["id"] + "; inspect persisted evidence/checkpoints before a new run",
                          {"run_id": identity, "step_id": step["id"], "next_action": "run.inspect", "requests_replayed": 0}) from exc
    project.put("run",run)
    project.event("scenario.completed",{"run_id":identity,"steps":len(steps)})
    return run
