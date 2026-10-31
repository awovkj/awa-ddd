"""Typed, reproducible decisions. A transport difference alone is not a finding."""
from __future__ import annotations
from decimal import Decimal, InvalidOperation
import base64
import json
import re
from urllib.parse import urlsplit, parse_qsl, unquote
from .store import EngineError, now, canonical
from .engine import verify_current_evidence, operation_signature, stamp, atomic, credential_header_names
from .transport import response_json, pointer, headers_map
from .scope import bind_operation, normalize_url


def _observations(project, ids, obligation, allow_related_inputs=False):
    if not isinstance(ids,list) or not ids or len(ids)>25 or len(set(ids))!=len(ids):
        raise EngineError("independent_evidence", "Use 1..25 distinct evidence IDs")
    result=[]
    run_ids=set()
    for eid in ids:
        meta, artifact = verify_current_evidence(project,eid)
        if meta["operation_id"]!=obligation["operation_id"]:
            raise EngineError("evidence_binding", "Evidence belongs to another operation")
        if meta["run_id"] in run_ids:
            raise EngineError("independent_evidence", "Each observation needs an independent execution")
        run_ids.add(meta["run_id"])
        result.append((meta,artifact))
    return result


def _value(observation, selector):
    return pointer(response_json(observation[1]),selector)


def _nonempty(value):
    return value is not None and value != "" and value != [] and value != {}


def _same_identity(observations):
    keys={(m.get("actor_id"),m.get("session_id"),m.get("session_generation")) for m,a in observations}
    if len(keys)!=1:
        raise EngineError("control_identity", "Business controls require the same actor/session generation")


def _input_view(observation, item, operation):
    """Bind an input experiment to the captured bytes, retaining other inputs."""
    from .inputs import input_view
    return input_view(observation[1]["request"], item, operation)


def _input_controls(observations, item, operation):
    _same_identity(observations)
    views = [_input_view(o,item,operation) for o in observations]
    if any(context != views[0][1] for value,context in views[1:]):
        raise EngineError("input_binding", "Business controls must change only the bound test input")
    values = [v for v,c in views]
    if any(values[i] == values[j] for i in range(len(values)) for j in range(i)):
        raise EngineError("input_binding", "Normal, variant and sensitivity controls require distinct tested input values")


def _scenario_observations(project, ids, item, oracle):
    """Only a completed, genuine sequential scenario may join different operations."""
    from .engine import stable
    run_id = oracle.get("scenario_run_id")
    if not isinstance(run_id, str) or not run_id:
        raise EngineError("state_scenario", "state_transition requires a completed scenario_run_id")
    run = project.get("run", run_id, required=False)
    if not run or run.get("kind") != "scenario" or run.get("status") != "succeeded":
        raise EngineError("state_scenario", "The named run is not a successfully completed scenario")
    checkpoints = run.get("checkpoints")
    checked = run.get("preflight") or {}
    if not isinstance(checked, dict):
        raise EngineError("state_scenario", "The scenario preflight ledger is invalid")
    if not isinstance(checkpoints, list) or not 3 <= len(checkpoints) <= 25 or any(not isinstance(row, dict) for row in checkpoints) \
            or not checked.get("valid_spec") or not checked.get("static_valid") or checked.get("errors"):
        raise EngineError("state_scenario", "A complete scenario with valid preflight and checkpoints is required")
    step_ids = [checkpoint.get("step_id") for checkpoint in checkpoints]
    if any(not isinstance(value, str) or not value for value in step_ids) or len(set(step_ids)) != len(step_ids) or any(
            checkpoint.get("status") != "verified" or "concurrent" in checkpoint
            or not isinstance(checkpoint.get("evidence_id"), str) for checkpoint in checkpoints):
        raise EngineError("state_scenario", "State chains require unique, verified, non-concurrent scenario steps")
    if not isinstance(checked.get("steps"), list) or any(not isinstance(row, dict) for row in checked["steps"]) \
            or [step.get("step_id") for step in checked["steps"]] != step_ids \
            or run.get("evidence_ids") != [checkpoint["evidence_id"] for checkpoint in checkpoints]:
        raise EngineError("state_scenario", "Scenario checkpoint order differs from the executed preflight/evidence ledger")
    selected = [oracle.get(field) for field in ("before_step_id", "action_step_id", "after_step_id")]
    if any(not isinstance(value, str) or value not in step_ids for value in selected) or len(set(selected)) != 3:
        raise EngineError("state_scenario", "Declare distinct actual before/action/after step IDs")
    positions = [step_ids.index(value) for value in selected]
    if positions != list(range(positions[0], positions[0] + 3)):
        raise EngineError("state_order", "Before/action/after must be consecutive actual scenario steps")
    chain = [checkpoints[index] for index in positions]
    if not isinstance(ids, list) or ids != [checkpoint["evidence_id"] for checkpoint in chain] or len(set(ids)) != 3:
        raise EngineError("state_scenario", "evidence_ids must be exactly the selected before/action/after checkpoint IDs in order")
    with project._lock:
        events = project.connection.execute("SELECT document FROM events WHERE type='scenario.completed'").fetchall()
    if not any(json.loads(row[0]) == {"run_id": run_id, "steps": len(checkpoints)} for row in events):
        raise EngineError("state_scenario", "The scenario has no genuine completion event")
    observations = []
    for index, checkpoint in zip(positions, chain):
        meta, artifact = verify_current_evidence(project, checkpoint["evidence_id"])
        if meta.get("run_id") != stable("RUN", run_id + ":" + checkpoint["step_id"]):
            raise EngineError("state_scenario", "A capture was not executed by this scenario step")
        attempt = project.get("run", meta["run_id"])
        static = checked["steps"][index]
        if attempt.get("kind") != "http" or attempt.get("status") != "succeeded" \
                or attempt.get("evidence_id") != meta["id"] \
                or static.get("status") == "static_valid" and static.get("request_signature") != attempt.get("request_signature"):
            raise EngineError("state_scenario", "The checkpoint does not match a successful scenario-owned HTTP execution")
        observations.append((meta, artifact))
    starts = [stamp(artifact.get("started_at")) for meta, artifact in observations]
    ends = [stamp(artifact.get("completed_at")) for meta, artifact in observations]
    if any(start > end for start, end in zip(starts, ends)) \
            or any(ends[index] > starts[index + 1] for index in range(2)) \
            or stamp(run.get("started_at")) > starts[0] or ends[-1] > stamp(run.get("finished_at")):
        raise EngineError("state_order", "State observations must be non-overlapping executions inside the scenario interval")
    if observations[1][0]["operation_id"] != item["operation_id"]:
        raise EngineError("evidence_binding", "The action must belong to the obligation's actual operation")
    _same_identity(observations)
    if any(not meta.get("actor_id") or not meta.get("session_id") or not meta.get("session_generation")
           for meta, artifact in observations):
        raise EngineError("control_identity", "State chains require one actual verified actor/session generation")
    return observations, run


def _state_json(observation):
    from .inputs import json_document
    return json_document(base64.b64decode(observation[1]["response"]["body_base64"], validate=True))


def _state_readback(project, observations, action_resource, scope):
    from .engine import actor_signature, resource_signature
    before, action, after = observations
    actor = project.get("actor", action[0]["actor_id"])
    if not isinstance(scope, dict) or not isinstance(scope.get("relation"), str) \
            or not scope["relation"].strip() or len(scope["relation"]) > 2048:
        raise EngineError("state_scope", "readback_scope needs an explicit type and a bounded explanation of its relation to the action")
    if before[0]["operation_id"] != after[0]["operation_id"] \
            or before[1]["request"] != after[1]["request"]:
        raise EngineError("state_readback", "Before/after must repeat exactly the same registered read request")
    request = before[1]["request"]
    if request["method"] not in {"GET", "HEAD"} or base64.b64decode(request["body_base64"], validate=True):
        raise EngineError("state_readback", "State observers must be actual body-free read-only requests")
    for meta, artifact in observations:
        if meta.get("actor_signature") != actor_signature(actor):
            raise EngineError("control_identity", "Each state capture must retain the actual verified actor signature")
    operation = project.get("operation", before[0]["operation_id"])
    bind_operation(operation, request["url"], request["method"])
    if scope.get("type") == "actor":
        if operation.get("state_scope") != "actor" or urlsplit(request["url"]).query \
                or any(entry.get("location") in {"path", "query", "body", "graphql"} for entry in operation.get("inputs", [])) \
                or before[0].get("resource_id") or after[0].get("resource_id"):
            raise EngineError("state_scope", "Actor readback requires a declared concrete actor-scoped operation without business query/body/resource inputs")
        selector = scope.get("subject_selector")
        if not isinstance(selector, str) or not selector.startswith("/"):
            raise EngineError("state_scope", "Actor readback must identify the server-side account with subject_selector")
        if any(canonical(pointer(_state_json(observation), selector)) != canonical(actor["subject"])
               for observation in (before, after)):
            raise EngineError("state_scope", "The readback state is not attributed to the actual acting account")
        return {"type": "actor", "actor_signature": actor_signature(actor), "subject_selector": selector,
                "relation": scope["relation"], "operation_id": operation["id"]}
    if scope.get("type") == "resource":
        resource_id = scope.get("resource_id")
        if not isinstance(resource_id, str) or not resource_id or any(observation[0].get("resource_id") != resource_id for observation in (before, after)):
            raise EngineError("state_scope", "Resource readback must name the real fixture bound to both read requests")
        resource = project.get("resource", resource_id)
        if resource["operation_id"] != operation["id"] \
                or any(resource.get(key) != action_resource.get(key) for key in ("external_id", "owner_actor_id", "tenant_id")):
            raise EngineError("state_scope", "Read/action fixtures must identify the same actual business resource, owner and tenant")
        if any(observation[0].get("resource_signature") != resource_signature(resource) for observation in (before, after)):
            raise EngineError("state_scope", "Readback fixture signatures must match their current request bindings")
        return {"type": "resource", "resource_id": resource_id, "resource_signature": resource_signature(resource),
                "relation": scope["relation"], "operation_id": operation["id"]}
    raise EngineError("state_scope", "readback_scope.type must be actor or resource")


def _state_transition(project, item, operation, ids, oracle):
    from .engine import resource_signature
    if item.get("kind") != "input_test":
        raise EngineError("oracle_binding", "state_transition needs a business input-test obligation")
    observations, run = _scenario_observations(project, ids, item, oracle)
    before, action, after = observations
    if operation["method"] in {"GET", "HEAD", "OPTIONS"} or action[1]["request"]["method"] != operation["method"]:
        raise EngineError("state_action", "The action must be a captured state-changing request")
    if not all(200 <= observation[1]["response"]["status"] < 300 for observation in observations):
        raise EngineError("control_invalid", "State chains require successful HTTP business responses")
    resource_id = action[0].get("resource_id")
    if not resource_id:
        raise EngineError("resource_binding", "The state-changing action requires a currently bound test fixture")
    resource = project.get("resource", resource_id)
    if resource["owner_actor_id"] != action[0]["actor_id"] \
            or action[0].get("resource_signature") != resource_signature(resource):
        raise EngineError("resource_binding", "The action must use the acting account's current fixture and request binding")
    action_input, context = _input_view(action, item, operation)
    try:
        input_matches = "action_input_expected" in oracle and canonical(action_input) == canonical(oracle["action_input_expected"])
    except (ValueError, TypeError):
        input_matches = False
    if not input_matches:
        raise EngineError("state_input", "Declare the exact action_input_expected at the obligation's tested selector")
    success_selector, expected = oracle.get("action_success_selector"), oracle.get("action_success_expected")
    if not isinstance(success_selector, str) or not success_selector.startswith("/") \
            or success_selector.rsplit("/", 1)[-1].lower() not in {"success", "ok", "status", "result"} \
            or not (expected is True or isinstance(expected, str) and expected.casefold() in {"ok", "success", "succeeded", "completed"}):
        raise EngineError("state_action_success", "Declare a positive action_success_selector/expected business success assertion")
    action_response = _state_json(action)
    if not isinstance(action_response, dict) or action_response.get("success") is False or action_response.get("ok") is False \
            or pointer(action_response, success_selector) != expected:
        raise EngineError("state_action_success", "The state-changing action did not report actual business success")
    scope = _state_readback(project, observations, resource, oracle.get("readback_scope"))
    selector = oracle.get("selector")
    leaf = re.sub(r"[^a-z0-9]", "", str(selector).rsplit("/", 1)[-1].lower())
    if not isinstance(selector, str) or not selector.startswith("/") or leaf in {
            "success", "ok", "message", "error", "code", "statuscode", "requestid", "traceid", "correlationid",
            "timestamp", "nonce", "elapsedms", "duration", "length", "responselength"}:
        raise EngineError("state_selector", "State proof needs a concrete business state, not response flags or transport noise")
    old, new = [pointer(_state_json(observation), selector) for observation in (before, after)]
    if "before_expected" not in oracle or old != oracle["before_expected"]:
        raise EngineError("baseline_invalid", "The initial associated business state did not match before_expected")
    if ("max_delta" in oracle) == ("forbidden_after" in oracle):
        raise EngineError("state_oracle", "Specify exactly one bounded max_delta or forbidden_after")
    if "max_delta" in oracle:
        try:
            if any(isinstance(value, bool) or not isinstance(value, (str, int, float)) for value in (old, new, oracle["max_delta"])):
                raise InvalidOperation()
            values = [Decimal(str(value)) for value in (old, new, oracle["max_delta"])]
            if not all(value.is_finite() for value in values) or values[2] < 0:
                raise InvalidOperation()
            violation = abs(values[1] - values[0]) > values[2]
        except (InvalidOperation, ValueError):
            raise EngineError("numeric_invariant", "Finite numeric states and a nonnegative maximum delta are required")
    else:
        forbidden = oracle["forbidden_after"]
        if any(not isinstance(value, (str, bool, int, float)) or isinstance(value, float) and not Decimal(str(value)).is_finite()
               for value in (old, new, forbidden)) or old == forbidden:
            raise EngineError("baseline_invalid", "forbidden_after needs finite scalar states and a non-violating initial baseline")
        violation = new == forbidden
    proof = {"scope": "bounded_state_transition", "scenario_run_id": run["id"],
             "before_evidence_id": ids[0], "action_evidence_id": ids[1], "after_evidence_id": ids[2],
             "step_ids": [oracle[field] for field in ("before_step_id", "action_step_id", "after_step_id")],
             "action_resource_id": resource_id, "action_resource_signature": resource_signature(resource),
             "readback_scope": scope, "selector": selector, "before_value": old, "after_value": new,
             "limitation": "Only this associated account/resource and completed sequential scenario was observed; no universal vulnerability absence claim."}
    return ("confirmed" if violation else "inconclusive",
            "The explicitly associated scenario business-state invariant was violated" if violation else
            "No violation observed; this bounded chain does not refute the hypothesis", proof)


SQL_METADATA_VERSION = 2


def is_sql_category(value):
    text = str(value).casefold()
    normalized = re.sub(r"[^a-z0-9]", "", text)
    if ("nosql" in normalized and "sql" not in normalized.replace("nosql", "")) or normalized in {"sqlmap", "graphql"}:
        return False
    if "\u6570\u636e\u5e93\u6ce8\u5165" in text or "\u7ed3\u6784\u5316\u67e5\u8be2\u8bed\u8a00\u6ce8\u5165" in text:
        return True
    # Match "SQL Injection", "SQLi", "blind SQL", "Unparameterised SQL / ...",
    # and DBMS-qualified names without requiring the string to start with SQL.
    return ("sql" in normalized or normalized in {"sqli", "blindsqli", "cwe89", "unioninjection"}
            or normalized.startswith(("mysql", "mssql", "postgresql", "sqlite")))


def is_xss_category(value):
    text = str(value).casefold()
    normalized = re.sub(r"[^a-z0-9]", "", text)
    return "\u8de8\u7ad9\u811a\u672c" in text or "\u8de8\u7ad9\u70b9\u811a\u672c" in text \
        or bool(re.search(r"(?<![a-z0-9])xss(?![a-z0-9])", text)) \
        or "crosssitescripting" in normalized or normalized.startswith((
            "xss", "storedxss", "reflectedxss", "domxss", "persistentxss", "cwe79"))


def _sql_input(item, operation):
    return item.get("test_family") == "sql_injection" or is_sql_category(item.get("category")) or any(
        entry.get("location") == item.get("input_location")
        and entry.get("selector", entry.get("name")) == item.get("input_selector")
        and entry.get("schema_branch") == item.get("schema_branch")
        and is_sql_category(entry.get("consumer")) for entry in operation.get("inputs", []))


def _oracle_family(item, operation, oracle):
    if item.get("kind") != "input_test":
        return
    kind, family = oracle.get("type"), item.get("test_family")
    if _sql_input(item, operation) and kind not in {"sql_metadata", "error_channel"} \
            and not (family == "xss" and kind == "analyst_runtime"):
        raise EngineError("sql_metadata_required", "A declared SQL input requires metadata/error proof, not a generic observable")
    if family is None:
        return
    from .engine import TEST_FAMILIES
    if family not in TEST_FAMILIES or oracle.get("test_family") != family:
        raise EngineError("oracle_family", "oracle.test_family must match this obligation's explicit test_family")
    if family == "xss":
        if kind != "analyst_runtime":
            raise EngineError("xss_runtime_required", "Static input observations cannot close an XSS runtime obligation; use a real application-triggered browser observation and reviewed finding")
        return
    allowed = {"sql_injection": {"sql_metadata", "error_channel"},
               "business_logic": {"semantic_negative", "state_invariant", "state_transition"},
               "generic": {"semantic_negative"},
               "xxe": {"semantic_negative", "extraction"}, "ssrf": {"semantic_negative", "extraction"},
               "path_traversal": {"semantic_negative", "extraction"}}
    if kind not in allowed.get(family, {"semantic_negative"}):
        raise EngineError("oracle_family", "This oracle does not implement the declared family's proof channel")


def _category_family(value):
    if is_sql_category(value):
        return "sql_injection"
    if is_xss_category(value):
        return "xss"
    normalized = re.sub(r"[^a-z0-9]", "", str(value).casefold())
    aliases = {"business_logic": ("businesslogic",), "ssrf": ("ssrf", "serversiderequestforgery"),
               "xxe": ("xxe", "xmlexternalentity"), "path_traversal": ("pathtraversal", "directorytraversal", "localfileinclusion"),
               "command_injection": ("commandinjection",), "template_injection": ("templateinjection", "ssti"),
               "deserialization": ("deserialization",), "file_upload": ("fileupload", "unrestrictedupload")}
    return next((family for family, terms in aliases.items() if any(term in normalized for term in terms)), None)


def _family_extraction(item, operation, observations, oracle, value, control_value):
    family = item.get("test_family")
    if family is None:
        return None
    expected, source = oracle.get("expected_value"), oracle.get("source_reference")
    if family not in {"xxe", "ssrf", "path_traversal"} or not isinstance(expected, str) \
            or not expected or len(expected) > 4096 or value != expected or control_value == expected \
            or not isinstance(source, str) or not source or len(source) > 2048:
        raise EngineError("family_proof", "Typed extraction needs an exact expected_value, source_reference and discriminating negative control")
    inputs = [_input_view(observation, item, operation)[0] for observation in observations]
    try:
        texts = [entry.decode("utf-8") if isinstance(entry, bytes) else str(entry) for entry in inputs]
    except UnicodeError as exc:
        raise EngineError("family_proof", "The selected attack input does not expose a verifiable source reference") from exc
    for index in range(len(texts)):
        for _ in range(3):
            decoded = unquote(texts[index])
            if decoded == texts[index]:
                break
            texts[index] = decoded
    if source not in texts[0] or source in texts[1] or expected in texts[0]:
        raise EngineError("family_proof", "Recovery must exercise the declared source, negative control must omit it, and a reflected attack value is not extraction")
    if family == "xxe":
        declarations = re.findall(r"<!ENTITY\s+([A-Za-z_][\w.:-]*)\s+SYSTEM\s+[\"']([^\"']+)[\"']\s*>", texts[0], re.I)
        if not re.search(r"<!DOCTYPE\b", texts[0], re.I) or not any(
                reference == source and "&" + name + ";" in texts[0] for name, reference in declarations):
            raise EngineError("family_proof", "XXE extraction needs a referenced external entity in the captured input; entities are never resolved locally")
    if family == "path_traversal" and "../" not in source and "..\\" not in source:
        raise EngineError("family_proof", "Path traversal needs an actual parent-path expression in the selected input")
    if family == "ssrf":
        try:
            url = urlsplit(source)
            valid = url.scheme in {"http", "https"} and bool(url.hostname) and url.username is None \
                and url.password is None and not url.fragment and not any(ord(char) < 33 for char in source) \
                and (url.port is None or 1 <= url.port <= 65535)
        except ValueError:
            valid = False
        if not valid:
            raise EngineError("family_proof", "SSRF extraction requires a concrete HTTP(S) source URL")
    return {"test_family": family, "source_reference": source, "recovered_value": expected,
            "scope": "bounded_input_extraction"}


def _extract_value(observation, oracle):
    selector, expression = oracle.get("selector"), oracle.get("response_pattern")
    if bool(selector) == bool(expression):
        raise EngineError("selector", "Use exactly one JSON selector or response_pattern with a named value group")
    if selector:
        if not isinstance(selector, str) or not selector.startswith("/"):
            raise EngineError("selector", "A JSON Pointer is required")
        return _value(observation, selector)
    if not isinstance(expression, str) or len(expression) > 512:
        raise EngineError("selector", "response_pattern must be at most 512 characters")
    try:
        pattern = re.compile(expression)
        if "value" not in pattern.groupindex:
            raise EngineError("selector", "response_pattern requires a named (?P<value>...) group")
        raw = base64.b64decode(observation[1]["response"]["body_base64"], validate=True).decode("utf-8")
        matched = pattern.search(raw)
        return matched.group("value") if matched else None
    except (re.error, UnicodeError, ValueError) as exc:
        raise EngineError("selector", "The response pattern or response encoding is invalid") from exc


def _metadata_expression(value, metadata_type):
    text = str(value)
    for _ in range(3):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    patterns = {
        "database": r"\b(database\s*\(|current_database\s*\(|db_name\s*\(|pragma_database_list\b)",
        "current_user": r"\b(current_user\b|session_user\b|system_user\b|user\s*\()",
    }
    matched = re.search(patterns[metadata_type], text, re.I)
    return re.sub(r"\s", "", matched.group(1).lower()) if matched else None


def _sql_metadata(project, item, operation, observations, oracle):
    if item.get("kind") != "input_test" or not _sql_input(item, operation) or len(observations) != 3:
        raise EngineError("sql_metadata_binding", "SQL metadata needs a SQL input obligation and baseline/recovery/negative captures")
    _same_identity(observations)
    _input_controls(observations, item, operation)
    baseline, recovered, negative = observations
    if not 200 <= baseline[1]["response"]["status"] < 300:
        raise EngineError("baseline_invalid", "SQL metadata requires a successful normal business baseline")
    if not oracle.get("tool_run_id") and not 200 <= negative[1]["response"]["status"] < 300:
        raise EngineError("baseline_invalid", "The direct-extraction negative control must be a successful business response")
    if not 200 <= recovered[1]["response"]["status"] < 600:
        raise EngineError("control_invalid", "The recovery must contain an actual server response")
    baseline_selector = oracle.get("baseline_selector")
    baseline_pattern = oracle.get("baseline_response_pattern")
    baseline_channel = {"selector": baseline_selector, "response_pattern": baseline_pattern}
    if bool(baseline_selector) == bool(baseline_pattern) or "baseline_expected" not in oracle or not _nonempty(oracle["baseline_expected"]):
        raise EngineError("baseline_invalid", "Declare a nonempty normal business baseline assertion")
    if _extract_value(baseline, baseline_channel) != oracle["baseline_expected"]:
        raise EngineError("baseline_invalid", "The normal business baseline assertion did not match")
    metadata_type = oracle.get("metadata_type")
    if metadata_type not in {"database", "current_user"}:
        raise EngineError("sql_metadata_type", "Recover database or current_user; a version, table name or product ID is insufficient")
    expected = oracle.get("expected_value")
    if not isinstance(expected, str) or not expected.strip() or len(expected) > 256 or any(ord(c) < 32 for c in expected):
        raise EngineError("sql_metadata_value", "Declare the exact nonempty database name or database user actually recovered")
    if expected.strip().lower() in {"unknown", "none", "null", "error", "true", "false"}:
        raise EngineError("sql_metadata_value", "A placeholder is not recovered database metadata")
    inputs = [_input_view(obs, item, operation)[0] for obs in observations]
    # A real sqlmap metadata transcript is direct proof: the DBMS returned
    # database()/current_user() through the tested parameter. ORDER BY / LIKE
    # injection points cannot satisfy a constant equality template because the
    # predicate degenerates, so the transcript path must come before that check.
    if oracle.get("tool_run_id"):
        return _sqlmap_metadata(project, item, operation, observations, oracle, inputs)
    expressions = [_metadata_expression(v, metadata_type) for v in inputs]
    if expressions[0] or not expressions[1] or expressions[1] != expressions[2]:
        raise EngineError("sql_metadata_expression", "Recovery and negative control must exercise the same SQL metadata expression; baseline must be normal")
    if expected.casefold() in str(inputs[1]).casefold():
        raise EngineError("sql_metadata_reflection", "The recovered value occurs in the submitted input and could be reflection")
    try:
        value = _extract_value(recovered, oracle)
    except EngineError as exc:
        raise EngineError("sql_metadata_value", "The recovery response contains no selected metadata value") from exc
    if value != expected:
        raise EngineError("sql_metadata_value", "The exact declared metadata value was not recovered from the response")
    for obs in (baseline, negative):
        try:
            other = _extract_value(obs, oracle)
        except EngineError as exc:
            if exc.code not in {"selector", "response_json"}:
                raise
            other = None
        if other == value:
            raise EngineError("sql_metadata_control", "Normal or negative control also exposes the claimed metadata")
    return {"metadata_type": metadata_type, "recovered_value": value,
            "scope": "database_metadata", "baseline_evidence_id": baseline[0]["id"],
            "recovery_evidence_id": recovered[0]["id"], "negative_evidence_id": negative[0]["id"]}


def _sqlmap_metadata(project, item, operation, observations, oracle, inputs):
    """Accept blind recovery only with a real tool transcript and independent equality controls."""
    from .external import inspect as inspect_tool, verify_metadata_controls
    run = inspect_tool(project, {"run_id": oracle["tool_run_id"]})
    if (run.get("integrity") != "valid" or run.get("adapter") != "sqlmap"
            or run.get("action") != "metadata" or run.get("status") != "succeeded"
            or run.get("exit_code") != 0 or not run.get("metadata_only")
            or not run.get("traffic_requests") or not run.get("traffic_responses")):
        raise EngineError("sql_metadata_tool", "Blind metadata requires an intact, successful metadata-only sqlmap run with request/response traffic")
    if (run.get("operation_id") != operation["id"] or run.get("input_location") != item.get("input_location")
            or run.get("input_selector") != item.get("input_selector")):
        raise EngineError("sql_metadata_binding", "The metadata tool run belongs to another operation or input")
    if run.get("lineage") != "current" or not run.get("usable_for_confirmation"):
        raise EngineError(run.get("lineage_reason_code") or "sql_metadata_lineage",
                          "Tool metadata requires a current capture-time actor, credential, input and request binding; historical output remains inspectable but cannot be relabelled as proof")
    verify_metadata_controls(project, run, observations)
    identity = observations[0][0]
    if (run.get("session_id"), run.get("session_generation")) != (identity.get("session_id"), identity.get("session_generation")):
        raise EngineError("control_identity", "The tool run must use the same verified session as the controls")
    from .lineage import compatibility
    if not compatibility(operation, run, operation_signature(operation))[0]:
        raise EngineError("sql_metadata_binding", "The operation policy changed after tool execution")
    value = oracle["expected_value"]
    field = oracle["metadata_type"]
    if value.casefold() in str(inputs[1]).casefold():
        raise EngineError("sql_metadata_reflection", "The recovered value occurs in the submitted input and could be reflection")
    artifact = project.read_artifact(run)
    if artifact.get("metadata_candidates", {}).get(field) != value or run.get("metadata_candidates", {}).get(field) != value:
        raise EngineError("sql_metadata_value", "The declared database name/user was not recovered in the original sqlmap run")
    baseline_channel = {"selector": oracle.get("baseline_selector"), "response_pattern": oracle.get("baseline_response_pattern")}
    negative = oracle.get("negative_value")
    # The hand-written equality predicate is an optional strengthening control.
    # It is only evaluated when the caller declares negative_value AND the baseline
    # input is numeric; otherwise the transcript itself is the proof (this is the
    # ORDER BY / LIKE case where a constant predicate necessarily degenerates).
    numeric_baseline = isinstance(inputs[0], str) and bool(re.fullmatch(r"-?\d+", inputs[0].strip()))
    if numeric_baseline and isinstance(negative, str) and negative and negative != value:
        expression = (r"(?:DATABASE\s*\(\s*\)|CURRENT_DATABASE\s*\(\s*\)|DB_NAME\s*\(\s*\)|"
                      r"\(\s*SELECT\s+name\s+FROM\s+pragma_database_list\s+ORDER\s+BY\s+seq\s+LIMIT\s+1\s*\))"
                      if field == "database" else r"(?:CURRENT_USER(?:\s*\(\s*\))?|SESSION_USER|SYSTEM_USER|USER\s*\(\s*\))")
        pattern = re.compile(r"^\s*" + re.escape(inputs[0].strip()) + r"\s+AND\s+" + expression
                             + r"\s*=\s*'((?:[^']|'')*)'\s*$", re.I)
        matched = [pattern.fullmatch(str(v)) for v in inputs[1:]]
        if not all(matched) or matched[0].group(1).replace("''", "'") != value \
                or matched[1].group(1).replace("''", "'") != negative:
            raise EngineError("sql_metadata_predicate",
                              "When negative_value is supplied, recovery and negative inputs must use exact metadata equality "
                              "predicates; omit negative_value to rely on the sqlmap transcript directly")
        if not all(200 <= obs[1]["response"]["status"] < 300 for obs in observations):
            raise EngineError("control_invalid", "Blind equality controls must reach successful business responses")
        if _extract_value(observations[1], baseline_channel) != oracle["baseline_expected"]:
            raise EngineError("sql_metadata_control", "The recovered-value predicate did not preserve the valid baseline result")
        try:
            false_result = _extract_value(observations[2], baseline_channel)
        except EngineError as exc:
            if exc.code not in {"selector", "response_json"}:
                raise
            false_result = None
        if false_result == oracle["baseline_expected"]:
            raise EngineError("sql_metadata_control", "The false metadata predicate returned the same business result")
        return {"metadata_type": field, "recovered_value": value, "scope": "database_metadata",
                "channel": "sqlmap_with_independent_predicates", "tool_run_id": run["id"],
                "baseline_evidence_id": observations[0][0]["id"], "recovery_evidence_id": observations[1][0]["id"],
                "negative_evidence_id": observations[2][0]["id"]}
    # Transcript channel: controls must still be real, distinct executions; a
    # scanner banner or an unreachable target is not enough.
    if not all(200 <= obs[1]["response"]["status"] < 600 for obs in observations):
        raise EngineError("control_invalid", "Each baseline/recovery/negative capture must contain an actual server response")
    return {"metadata_type": field, "recovered_value": value, "scope": "database_metadata",
            "channel": "sqlmap_metadata_transcript", "tool_run_id": run["id"],
            "baseline_evidence_id": observations[0][0]["id"], "recovery_evidence_id": observations[1][0]["id"],
            "negative_evidence_id": observations[2][0]["id"]}


def _sql_behaviour_proof(project, proof):
    """Require a controlled write-side SQL input and a concrete business observable."""
    if not isinstance(proof, dict):
        raise EngineError("sql_evidence", "sql_evidence must be an object")
    control_id = proof.get("control_evidence_id")
    inject_id = proof.get("injection_evidence_id")
    change = proof.get("observed_change")
    if not isinstance(control_id, str) or not isinstance(inject_id, str) or control_id == inject_id:
        raise EngineError("sql_evidence", "sql_evidence needs two distinct evidence IDs")
    if not isinstance(change, str) or not change.strip():
        raise EngineError("sql_evidence", "Describe what changed between the control and the injection")
    location, selector = proof.get("input_location"), proof.get("input_selector")
    response_selector = proof.get("response_selector")
    if location not in {"path", "query", "body", "graphql", "header"} \
            or not isinstance(selector, str) or not selector \
            or not isinstance(response_selector, str) or not response_selector.startswith("/"):
        raise EngineError("sql_behaviour_proof_required", "Write-side SQL proof needs input_location, input_selector and a numeric business response_selector; legacy response differences are not sufficient")
    control_meta, control_art = verify_current_evidence(project, control_id, allow_expired_session=True)
    inject_meta, inject_art = verify_current_evidence(project, inject_id, allow_expired_session=True)
    if control_meta["operation_id"] != inject_meta["operation_id"]:
        raise EngineError("sql_evidence", "Both captures must belong to the same operation")
    if control_art["request"]["method"] != inject_art["request"]["method"]:
        raise EngineError("sql_evidence", "Both captures must use the same HTTP method")
    if inject_art["request"]["method"] in {"GET", "HEAD", "OPTIONS"}:
        raise EngineError("sql_behaviour_proof_required", "Behavioural SQL proof is limited to write-side/destructive operations; read-only SQL requires a metadata/error channel")
    observations = [(control_meta, control_art), (inject_meta, inject_art)]
    _same_identity(observations)
    if control_meta.get("run_id") == inject_meta.get("run_id"):
        raise EngineError("independent_evidence", "Control and injection need independent executions")
    if stamp(control_art["completed_at"]) > stamp(inject_art["started_at"]):
        raise EngineError("state_order", "Supply control then injection in non-overlapping execution order")
    operation = project.get("operation", control_meta["operation_id"])
    item = {"kind": "input_test", "operation_id": operation["id"],
            "input_location": location, "input_selector": selector, "schema_branch": proof.get("schema_branch")}
    if not _sql_input(item, operation):
        raise EngineError("sql_evidence", "Behavioural proof must identify a registered SQL consumer input")
    _input_controls(observations, item, operation)
    injected_value = str(_input_view(observations[1], item, operation)[0])
    for _ in range(3):
        decoded = unquote(injected_value)
        if decoded == injected_value:
            break
        injected_value = decoded
    if not re.search(r"(?i)\b(?:or|and)\b\s+|\bunion\s+select\b|\|\||--|/\*|;\s*(?:delete|update|insert|drop)\b", injected_value):
        raise EngineError("sql_evidence", "The changed SQL input must contain an injection expression; an ordinary business value change is not SQL proof")
    leaf = re.sub(r"[^a-z0-9]", "", response_selector.rsplit("/", 1)[-1].lower())
    if leaf in {"message", "error", "status", "statuscode", "code", "success", "ok", "timestamp", "nonce",
                "requestid", "traceid", "correlationid", "elapsedms", "duration", "length", "responselength"}:
        raise EngineError("sql_evidence", "Generic status, messages and transport noise cannot establish a SQL business effect")
    if not 200 <= inject_art["response"]["status"] < 300 \
            or not (200 <= control_art["response"]["status"] < 300 or control_art["response"]["status"] == 404):
        raise EngineError("control_invalid", "SQL behaviour requires a successful write response and a normal/not-found control")
    values = [_value(observation, response_selector) for observation in observations]
    try:
        numbers = [Decimal(str(value)) for value in values]
        if any(not isinstance(value, (int, float)) or isinstance(value, bool) for value in values) \
                or not all(number.is_finite() for number in numbers) or numbers[0] == numbers[1]:
            raise InvalidOperation()
    except (InvalidOperation, ValueError) as exc:
        raise EngineError("sql_evidence", "response_selector must expose different finite numeric business values, such as affected/deleted row counts; messages or timing do not suffice") from exc
    return {"channel": "behavioural_diff", "proof_version": 2, "operation_id": operation["id"],
            "control_evidence_id": control_id, "injection_evidence_id": inject_id,
            "input_location": location, "input_selector": selector, "schema_branch": item["schema_branch"],
            "response_selector": response_selector, "control_value": values[0], "injection_value": values[1],
            "observed_change": change.strip()}


def _error_channel(project, item, operation, observations, oracle):
    """Error-based metadata recovery: the DBMS echoes the value in its own error text."""
    if item.get("kind") != "input_test" or not _sql_input(item, operation) or len(observations) != 3:
        raise EngineError("oracle_binding",
                          "error_channel needs a SQL input obligation plus baseline/recovery/negative captures")
    _same_identity(observations)
    _input_controls(observations, item, operation)
    baseline, recovered, negative = observations
    metadata_type = oracle.get("metadata_type")
    if metadata_type not in {"database", "current_user"}:
        raise EngineError("sql_metadata_type", "Declare metadata_type database or current_user")
    expected = oracle.get("expected_value")
    if not isinstance(expected, str) or not expected.strip() or len(expected) > 256:
        raise EngineError("sql_metadata_value", "Declare the exact metadata value the error text returned")
    if expected.strip().lower() in {"unknown", "none", "null", "error", "true", "false"}:
        raise EngineError("sql_metadata_value", "A placeholder is not recovered database metadata")
    inputs = [_input_view(obs, item, operation)[0] for obs in observations]
    if _metadata_expression(str(inputs[0]), metadata_type):
        raise EngineError("sql_metadata_expression", "The baseline capture must be a normal request, not a metadata expression")
    if not _metadata_expression(str(inputs[1]), metadata_type):
        raise EngineError("sql_metadata_expression",
                          "The recovery capture must submit DATABASE()/CURRENT_USER() inside the tested input")
    if _metadata_expression(str(inputs[2]), metadata_type):
        raise EngineError("sql_metadata_expression", "The negative control must exercise a different expression")
    if expected.casefold() in str(inputs[1]).casefold():
        raise EngineError("sql_metadata_reflection", "The recovered value occurs in the submitted input and could be reflection")
    if not 200 <= baseline[1]["response"]["status"] < 300:
        raise EngineError("baseline_invalid", "The normal baseline must be a successful business response")
    if not 200 <= recovered[1]["response"]["status"] < 600:
        raise EngineError("control_invalid", "The recovery capture must contain an actual server response")
    if not 200 <= negative[1]["response"]["status"] < 600:
        raise EngineError("control_invalid", "The negative control must contain an actual server response")
    pattern = oracle.get("response_pattern")
    try:
        compiled = re.compile(pattern) if isinstance(pattern, str) else None
    except re.error as exc:
        raise EngineError("selector", "response_pattern is not a valid regular expression") from exc
    if compiled is None or "value" not in compiled.groupindex:
        raise EngineError("selector", "response_pattern requires a named (?P<value>...) group")
    channel = {"response_pattern": pattern}
    baseline_value = _extract_value(baseline, channel)
    if baseline_value is not None:
        raise EngineError("sql_metadata_control", "The normal baseline already exposes the claimed metadata")
    value = _extract_value(recovered, channel)
    if value is None or value.strip() != expected.strip():
        raise EngineError("sql_metadata_value", "The exact declared metadata value was not recovered from the error text")
    if _extract_value(negative, channel) is not None:
        raise EngineError("sql_metadata_control", "The negative control also returned a metadata value")
    return {"metadata_type": metadata_type, "recovered_value": value, "scope": "database_metadata",
            "channel": "error_text", "baseline_evidence_id": baseline[0]["id"],
            "recovery_evidence_id": recovered[0]["id"], "negative_evidence_id": negative[0]["id"]}


def _runtime_proof(project, decision):
    runtime = decision.get("runtime") or {}
    marker = runtime.get("marker")
    if not isinstance(marker, str) or not re.fullmatch(r"AWA-XSS-[a-fA-F0-9]{16,64}", marker):
        raise EngineError("xss_runtime_required", "XSS requires an application-triggered browser observation with a unique AWA-XSS-<hex nonce> marker")
    visit_id = runtime.get("visit_id")
    consumer_url = runtime.get("consumer_url")
    if not isinstance(visit_id, str) or not isinstance(consumer_url, str):
        raise EngineError("xss_runtime_required", "Declare runtime_visit_id and consumer_url for the actual consumption page")
    from .browser import _verified_visit, _visit_target
    visit, raw = _verified_visit(project, visit_id, consumer_url)
    found, arrival_index = _visit_target(raw, consumer_url)
    dialogs = [d for d in raw.get("dialogs", []) if isinstance(d, dict) and d.get("message") == marker]
    if arrival_index is not None:
        # The dialog must occur on the page that was reached, not on an earlier
        # login page that happened to render the same marker.
        dialogs = [d for d in dialogs if d.get("action_index") is None or d.get("action_index") >= arrival_index]
    if not dialogs:
        raise EngineError("xss_runtime_required", "The original browser observation contains no matching application-triggered dialog on the consumer page")
    from .scope import origin
    bound = False
    for evidence_id in decision.get("evidence_ids", []):
        meta, artifact = verify_current_evidence(project, evidence_id)
        request = artifact["request"]
        text = unquote(request["url"]) + "\n" + base64.b64decode(request["body_base64"], validate=True).decode("utf-8", errors="replace")
        if marker in text and origin(request["url"]) == origin(consumer_url):
            bound = True
    if not bound:
        raise EngineError("xss_runtime_binding", "The runtime marker must originate in a captured same-origin attack input")
    return {"scope": "browser_execution", "runtime_visit_id": visit["id"], "consumer_url": consumer_url,
            "runtime_marker": marker, "source": visit["source"], "artifact_sha256": visit["sha256"]}


def _bound_xss_proof(project, decision):
    """Only a reviewed, precisely controlled runtime experiment closes a typed XSS input."""
    from .browser import _verified_visit, _navigation_trail, _network
    from .engine import DEFAULT_CREDENTIAL_HEADER_NAMES, stable

    oracle = decision.get("oracle") or {}
    item = project.get("obligation", decision.get("obligation_id"))
    operation = project.get("operation", item["operation_id"])
    if decision.get("mode") != "analyst" or decision.get("outcome") != "confirmed" \
            or oracle.get("type") != "analyst_runtime" or oracle.get("test_family") != "xss" \
            or item.get("superseded") or item.get("kind") != "input_test" or item.get("test_family") != "xss":
        raise EngineError("analyst_obligation", "Only a current explicit XSS input-test obligation can use reviewed runtime closure")
    entries = [entry for entry in operation.get("inputs", [])
               if entry.get("location") == item.get("input_location")
               and entry.get("selector", entry.get("name")) == item.get("input_selector")
               and entry.get("schema_branch") == item.get("schema_branch")]
    if len(entries) != 1 or "xss" not in entries[0].get("test_families", []) \
            or item.get("input_signature") != stable("I", entries[0]) \
            or decision.get("operation_id") != operation["id"] \
            or decision.get("operation_signature") != operation_signature(operation):
        raise EngineError("analyst_obligation", "The reviewed runtime proof must match the current exact operation and declared input")
    observations = _observations(project, decision.get("evidence_ids"), item)
    if len(observations) != 2:
        raise EngineError("xss_input_binding", "Use exactly two independent captures in normal-baseline, attack order")
    _input_controls(observations, item, operation)
    baseline, attack = observations
    if not all(200 <= raw["response"]["status"] < 300 for meta, raw in observations):
        raise EngineError("baseline_invalid", "Reviewed XSS controls require successful normal and attack responses")
    if baseline[0].get("resource_id") != attack[0].get("resource_id"):
        raise EngineError("xss_input_binding", "The normal and attack controls must use the same fixture")
    if stamp(baseline[1].get("completed_at")) > stamp(attack[1].get("started_at")):
        raise EngineError("xss_input_binding", "The normal baseline must finish before the selected attack capture")
    marker = (decision.get("runtime") or {}).get("marker")
    if not isinstance(marker, str) or not re.fullmatch(r"AWA-XSS-[a-fA-F0-9]{16,64}", marker):
        raise EngineError("xss_runtime_required", "A unique application-triggered AWA-XSS-<hex nonce> marker is required")
    values = [_input_view(observation, item, operation)[0] for observation in observations]
    if any(not isinstance(value, (str, bytes)) for value in values) \
            or (marker.encode("ascii") if isinstance(values[0], bytes) else marker) in values[0] \
            or (marker.encode("ascii") if isinstance(values[1], bytes) else marker) not in values[1]:
        raise EngineError("xss_input_binding", "The runtime marker must occur in the selected attack input, not the selected normal input")
    normal_request = baseline[1]["request"]
    normal_text = (unquote(normal_request["url"]) + "\n"
                   + base64.b64decode(normal_request["body_base64"], validate=True).decode("utf-8", errors="replace")
                   + "\n" + canonical(normal_request.get("headers", {})))
    if marker in normal_text:
        raise EngineError("xss_input_binding", "The complete normal request must be free of the runtime marker")
    proof = _runtime_proof(project, decision)
    visit, raw = _verified_visit(project, proof["runtime_visit_id"], proof["consumer_url"])
    with project._lock:
        events = project.connection.execute(
            "SELECT document FROM events WHERE type IN ('browser.visited','browser.imported_mcp')").fetchall()
    if not any((event := json.loads(row[0])).get("visit_id") == visit["id"]
               and event.get("source") == visit.get("source") and event.get("sha256") == visit.get("sha256")
               for row in events):
        raise EngineError("xss_runtime_binding", "Browser provenance must match the original recorded observation event")
    identity_keys = ("actor_id", "session_id", "session_generation")
    identity = {key: attack[0].get(key) for key in identity_keys}
    if any(visit.get(key) != identity[key] for key in identity_keys):
        raise EngineError("xss_runtime_identity", "The actual consumer visit must use the control captures' actor/session generation")
    consumer = normalize_url(proof["consumer_url"])
    if operation["method"] in {"HEAD", "OPTIONS"}:
        raise EngineError("xss_runtime_binding", "A GET browser rendering cannot close an input experiment captured with HEAD or OPTIONS")
    if operation["method"] == "GET" and (
            normalize_url(attack[1]["request"]["url"]) != consumer
            or base64.b64decode(attack[1]["request"]["body_base64"], validate=True)):
        raise EngineError("xss_runtime_binding", "Read-only XSS closure requires the exact body-free captured attack URL as its consumer document")
    # Current dialog records have action indices but no page URL. Multi-page trails
    # cannot prove which document emitted a dialog and remain explicitly unbound.
    if any(entry["url"] != consumer for entry in _navigation_trail(raw)):
        raise EngineError("xss_runtime_binding", "Reviewed input closure requires an unambiguous single-consumer navigation trail")
    actions = raw.get("actions") or []
    if any(action.get("action", action.get("type")) == "fill" for action in actions):
        raise EngineError("xss_runtime_binding", "Browser fill values are not captured in the current runtime format and cannot establish selected-input attribution")
    dialogs = [dialog for dialog in raw.get("dialogs", []) if isinstance(dialog, dict)
               and dialog.get("message") == marker
               and (dialog.get("action_index") is None or type(dialog.get("action_index")) is int
                    and 0 <= dialog["action_index"] < len(actions)
                    and actions[dialog["action_index"]].get("ok") is True)]
    if not dialogs:
        raise EngineError("xss_runtime_binding", "The matching dialog must belong to a successful consumer-page interaction")
    consumer_requests = []
    for entry in _network(raw):
        request = entry.get("request", entry)
        if entry.get("type") != "document":
            continue
        if normalize_url(request["url"]) != consumer:
            raise EngineError("xss_runtime_binding", "A different document was loaded during this runtime observation")
        if request.get("method", "GET").upper() != "GET":
            raise EngineError("xss_runtime_binding", "The original consumer document must be a read-only browser navigation")
        recorded_headers = entry.get("request_headers", request.get("headers"))
        if recorded_headers is None:
            raise EngineError("xss_runtime_identity", "Consumer identity needs original digested document request headers")
        consumer_requests.append(headers_map(recorded_headers))
    if not consumer_requests:
        raise EngineError("xss_runtime_identity", "Consumer identity needs an actual document request and its digested headers")
    credential_names = set(DEFAULT_CREDENTIAL_HEADER_NAMES) | {"proxy-authorization"}
    for session in project.list("session"):
        credential_names.update(credential_header_names(session))
    if identity["session_id"]:
        credential_names.update(project.get("session", identity["session_id"]).get("headers", {}))
    expected_headers = headers_map(attack[1]["request"].get("headers", {}))
    expected_credentials = {key: value for key, value in expected_headers.items() if key in credential_names}
    if not identity["session_id"] and expected_credentials:
        raise EngineError("xss_runtime_identity", "Credential-bearing controls need a verified session, not an anonymous identity label")
    if any({key: value for key, value in headers.items() if key in credential_names} != expected_credentials
           for headers in consumer_requests):
        raise EngineError("xss_runtime_identity", "The consumer document's credential bytes differ from the captured control identity")
    return {**proof, "binding_version": 1, "obligation_id": item["id"], "operation_id": operation["id"],
            "operation_signature": decision["operation_signature"], "input_signature": item["input_signature"],
            "input_location": item["input_location"], "input_selector": item["input_selector"],
            "schema_branch": item.get("schema_branch"), "baseline_evidence_id": baseline[0]["id"],
            "attack_evidence_id": attack[0]["id"], "resource_id": attack[0].get("resource_id"),
            "identity": identity, "credential_binding": stable("XC", expected_credentials)}


def validate_confirmation(project, decision, category=None):
    """Reopen legacy SQL confirmations and prevent analyst review bypassing proof."""
    oracle = decision.get("oracle") or {}
    bound_item = project.get("obligation", decision["obligation_id"]) if decision.get("obligation_id") else None
    bound_operation = project.get("operation", bound_item["operation_id"]) if bound_item else None
    if bound_item:
        _oracle_family(bound_item, bound_operation, oracle)
        claimed_family = _category_family(category)
        if bound_item.get("test_family") and claimed_family and bound_item["test_family"] != claimed_family:
            code = "sql_metadata_required" if claimed_family == "sql_injection" else "xss_runtime_required" if claimed_family == "xss" else "oracle_family"
            raise EngineError(code, "The explicitly claimed finding family does not match its supporting input-test obligation")
        if oracle.get("type") == "analyst_runtime":
            if category is not None and not is_xss_category(category):
                raise EngineError("oracle_family", "A bound reviewed XSS runtime proof can only support an XSS finding")
            if _bound_xss_proof(project, decision) != decision.get("proof"):
                raise EngineError("xss_runtime_binding", "Stored reviewed runtime proof differs from its current controls or browser observation")
            return
        if oracle.get("type") == "state_transition" and decision.get("outcome") == "confirmed":
            outcome, reason, proof = _state_transition(project, bound_item, bound_operation, decision["evidence_ids"], oracle)
            if outcome != "confirmed" or proof != decision.get("proof"):
                raise EngineError("state_proof", "The stored scenario-state proof differs from its current checkpoints or observations")
        if oracle.get("type") == "extraction" and bound_item.get("test_family") and decision.get("outcome") == "confirmed":
            observations = _observations(project, decision["evidence_ids"], bound_item)
            if len(observations) != 2:
                raise EngineError("family_proof", "Typed extraction needs two independent input controls")
            _input_controls(observations, bound_item, bound_operation)
            try:
                control = _value(observations[1], oracle["selector"])
            except EngineError:
                control = None
            actual = _family_extraction(bound_item, bound_operation, observations, oracle,
                                        _value(observations[0], oracle["selector"]), control)
            if actual != decision.get("proof"):
                raise EngineError("family_proof", "The stored family-specific extraction proof differs from its observations")
    if oracle.get("type") == "authorization":
        item = project.get("obligation", decision["obligation_id"])
        operation = project.get("operation", item["operation_id"])
        observations = _observations(project, decision["evidence_ids"], item)
        if len(observations) != 2:
            raise EngineError("oracle_binding", "Authorization proof requires two independent controls")
        _authorization_requests(project, observations)
        _independent_principals(project, observations[0], observations[1])
        _require_verified_roles(project, operation, observations)
    if decision.get("outcome") != "confirmed":
        return
    if is_xss_category(category) or decision.get("runtime"):
        _runtime_proof(project, decision)
        if is_xss_category(category):
            return
    item = project.get("obligation", decision["obligation_id"]) if decision.get("obligation_id") else None
    operation = project.get("operation", item["operation_id"]) if item else None
    proof = decision.get("proof") or {}
    required = is_sql_category(category) or bool(item and _sql_input(item, operation)) \
               or proof.get("channel") == "behavioural_diff"
    if not required:
        return
    if proof.get("channel") == "behavioural_diff":
        actual = _sql_behaviour_proof(project, proof)
        if actual != proof:
            raise EngineError("sql_metadata_proof", "Stored behavioural proof differs from the supporting observations")
        return
    oracle = decision.get("oracle") or {}
    if not item or oracle.get("type") not in {"sql_metadata", "error_channel"} \
            or decision.get("oracle_version", 0) < SQL_METADATA_VERSION:
        raise EngineError("sql_metadata_required",
                          "SQL injection requires database/current-user proof (or paired behavioural evidence for "
                          "write-side/destructive injection); legacy extraction or analyst assertions must be re-evaluated")
    observations = _observations(project, decision["evidence_ids"], item)
    actual = (_error_channel(project, item, operation, observations, oracle)
              if oracle.get("type") == "error_channel"
              else _sql_metadata(project, item, operation, observations, oracle))
    if decision.get("proof") != actual:
        raise EngineError("sql_metadata_proof", "Stored metadata proof differs from the supporting observations")


def _authorization_requests(project, observations):
    identity_headers = set()
    for meta,artifact in observations:
        if meta.get("session_id"):
            identity_headers.update(credential_header_names(project.get("session",meta["session_id"])))
    requests = []
    for meta,artifact in observations:
        request = artifact["request"]
        requests.append({**request,"headers":{k:v for k,v in request["headers"].items() if k not in identity_headers}})
    if requests[0] != requests[1]:
        raise EngineError("control_request", "Authorization controls must send the same request except explicitly classified credential headers; business headers must remain unchanged")


def _require_verified_roles(project, operation, observations):
    if operation.get("auth") != "restricted":
        return
    for meta, artifact in observations:
        if not meta.get("actor_id"):
            continue
        session = project.get("session", meta["session_id"])
        if not (session.get("verification_assertion") or {}).get("roles_selector"):
            raise EngineError("roles_unverified", "Restricted authorization cannot treat unknown roles as a denied role; verify a server-side roles_selector, including an explicitly empty role set",
                              {"actor_id": meta["actor_id"], "session_id": session["id"], "next_action": "identity.verify"})


def _authorized(project, operation, actor_id):
    if operation["auth"]=="unknown":
        raise EngineError("access_policy", "Declare the expected access policy before evaluating it")
    if operation["auth"]=="public":
        return True
    if not actor_id:
        return False
    actor=project.get("actor",actor_id)
    return operation["auth"]=="authenticated" or bool(set(actor["roles"]) & set(operation["allowed_roles"]))


def _independent_principals(project, baseline, variant):
    principals = []
    sessions = []
    for meta, artifact in (baseline, variant):
        actor = project.get("actor", meta["actor_id"]) if meta.get("actor_id") else None
        principals.append((canonical(actor["subject"]), actor.get("tenant_id", "")) if actor else None)
        sessions.append(project.get("session", meta["session_id"]) if meta.get("session_id") else None)
    if principals[0] == principals[1]:
        raise EngineError("actor_independence", "A cross-identity comparison requires different actual actors with distinct verified server-side subjects/tenants, not aliases")
    credentials = [{name: session["headers"][name] for name in credential_header_names(session)} if session else None
                   for session in sessions]
    if all(sessions) and credentials[0] == credentials[1]:
        raise EngineError("actor_independence", "Independent authorization controls cannot use identical registered credentials")


@atomic
def evaluate(project,args):
    item=project.get("obligation",args["obligation_id"])
    if item.get("superseded"):
        raise EngineError("superseded", "Use the current obligation after replanning")
    operation=project.get("operation",item["operation_id"])
    oracle=args.get("oracle")
    if not isinstance(oracle,dict):
        raise EngineError("oracle", "A typed oracle is required")
    kind=oracle.get("type")
    ids=args.get("evidence_ids",[])
    _oracle_family(item, operation, oracle)
    observations=[] if kind == "state_transition" else _observations(project,ids,item)
    outcome,reason="inconclusive","Experiment did not establish the requested invariant"
    proof = None
    if kind=="state_transition":
        outcome, reason, proof = _state_transition(project, item, operation, ids, oracle)
    elif kind=="baseline":
        if item["kind"]!="baseline" or len(observations)!=1 or "expected" not in oracle:
            raise EngineError("oracle_binding", "A baseline obligation needs one capture and an expected JSON value")
        if observations[0][0].get("actor_id") != item.get("actor_id"):
            raise EngineError("actor_binding", "Baseline used a different actor")
        if 200<=observations[0][1]["response"]["status"]<300 and _value(observations[0],oracle["selector"])==oracle["expected"]:
            outcome,reason="refuted","Declared normal response assertion matched; this is a baseline, not a vulnerability absence claim"
    elif kind=="authorization":
        if item["kind"] not in {"access","ownership"} or len(observations)!=2:
            raise EngineError("oracle_binding", "Authorization needs a permission obligation and independent allowed/variant captures")
        baseline,variant=observations
        _authorization_requests(project,observations)
        _require_verified_roles(project, operation, observations)
        if baseline[0].get("actor_id")==variant[0].get("actor_id"):
            raise EngineError("actor_independence", "A cross-identity comparison requires different actual actors")
        _independent_principals(project, baseline, variant)
        if variant[0].get("actor_id") != item.get("actor_id"):
            raise EngineError("actor_binding", "Variant actor does not match the obligation")
        if not _authorized(project,operation,baseline[0].get("actor_id")):
            raise EngineError("baseline_identity", "Baseline actor is not allowed by the declared access policy")
        expected_allowed=_authorized(project,operation,variant[0].get("actor_id"))
        if item["kind"]=="ownership":
            resource=project.get("resource",item["resource_id"])
            if baseline[0].get("resource_id")!=resource["id"] or variant[0].get("resource_id")!=resource["id"]:
                raise EngineError("resource_binding", "Both captures must use the same registered test resource")
            if baseline[0].get("actor_id") != resource["owner_actor_id"] or variant[0].get("actor_id")==resource["owner_actor_id"]:
                raise EngineError("resource_owner", "A real owner baseline and a different actor are required")
            expected_allowed=False
        if not 200<=baseline[1]["response"]["status"]<300:
            raise EngineError("baseline_invalid", "Allowed actor did not reach a valid normal response")
        protected=_value(baseline,oracle["selector"])
        if not _nonempty(protected):
            raise EngineError("baseline_invalid", "Protected baseline value must be present")
        status=variant[1]["response"]["status"]
        denied=oracle.get("deny_statuses",[401,403])
        if not isinstance(denied,list) or any(s not in [401,403,404] for s in denied):
            raise EngineError("deny_statuses", "Only explicit authentication/authorization denial statuses can refute access")
        if status in denied and not expected_allowed:
            outcome,reason="refuted","The distinct verified actor was denied for this concrete operation/resource"
        elif 200<=status<300:
            try:
                matches=_value(variant,oracle["selector"])==protected
            except EngineError:
                matches=False
            if matches:
                outcome="refuted" if expected_allowed else "confirmed"
                reason="Expected allowed access matched" if expected_allowed else "A disallowed verified actor received the protected value from the valid allowed baseline"
    elif kind=="semantic_negative":
        if item["kind"]!="input_test" or len(observations)!=3:
            raise EngineError("oracle_binding", "Semantic refutation needs an input test and normal/variant/sensitivity captures")
        _same_identity(observations)
        leaf = re.sub(r"[^a-z0-9]", "", str(oracle.get("selector", "")).rsplit("/",1)[-1].lower())
        if leaf in {"requestid","traceid","correlationid","timestamp","nonce","elapsedms","duration"}:
            raise EngineError("sensitivity", "Transport noise cannot establish business sensitivity")
        baseline,variant,control=observations
        if not all(200<=a["response"]["status"]<300 for m,a in observations):
            raise EngineError("control_invalid", "Error responses cannot be used as normal business sensitivity controls")
        if "baseline_expected" not in oracle or "control_expected" not in oracle or oracle["baseline_expected"]==oracle["control_expected"]:
            raise EngineError("sensitivity", "Declare distinct normal and sensitivity business values")
        values=[_value(o,oracle["selector"]) for o in observations]
        if values[0]!=oracle["baseline_expected"] or values[2]!=oracle["control_expected"]:
            raise EngineError("sensitivity", "Business assertions did not match the controls")
        _input_controls(observations,item,operation)
        if values[1]==values[0]:
            outcome,reason="refuted","No change in the specified business observable under a valid discriminating control; limited to this hypothesis"
        else:
            reason="Business observable changed; difference requires impact analysis and does not automatically confirm a vulnerability"
    elif kind=="state_invariant":
        if item["kind"]!="input_test" or len(observations)<3:
            raise EngineError("oracle_binding", "State invariant needs before/action/after captures on an input-test obligation")
        before,after=observations[0],observations[-1]
        _same_identity(observations)
        if not all(200<=a["response"]["status"]<300 for m,a in observations):
            raise EngineError("control_invalid", "State observations require successful business responses")
        resource=before[0].get("resource_id")
        if not resource or any(m.get("resource_id")!=resource for m,a in observations):
            raise EngineError("resource_binding", "State experiment requires the same bound resource")
        times=[stamp(a["started_at"]) for m,a in observations]
        if times!=sorted(times) or any(stamp(observations[i-1][1]["completed_at"]) > times[i] for i in range(1,len(times))):
            raise EngineError("state_order", "State captures must be supplied in actual execution order")
        if operation["method"] in {"GET","HEAD","OPTIONS"}:
            raise EngineError("state_action", "State conclusions require a captured state-changing action")
        views = [_input_view(o,item,operation) for o in observations]
        if any(context != views[0][1] for value,context in views[1:]) or views[-1][0] != views[0][0]:
            raise EngineError("input_binding", "State readbacks must repeat the baseline input and keep other request inputs fixed")
        if all(value == views[0][0] for value,context in views[1:-1]):
            raise EngineError("input_binding", "The state-changing action must vary the bound test input")
        old,new=_value(before,oracle["selector"]),_value(after,oracle["selector"])
        if "before_expected" not in oracle or old!=oracle["before_expected"]:
            raise EngineError("baseline_invalid", "Initial business state did not match")
        if "forbidden_after" in oracle:
            if old == oracle["forbidden_after"]:
                raise EngineError("baseline_invalid", "Initial state already violates the declared invariant")
            violation=new==oracle["forbidden_after"]
        elif "max_delta" in oracle:
            try:
                if any(isinstance(x,bool) for x in [old,new,oracle["max_delta"]]):
                    raise InvalidOperation()
                values=[Decimal(str(x)) for x in [old,new,oracle["max_delta"]]]
                if not all(x.is_finite() for x in values) or values[2]<0:
                    raise InvalidOperation()
                violation=abs(values[1]-values[0])>values[2]
            except (InvalidOperation,ValueError):
                raise EngineError("numeric_invariant", "Finite numeric states and a nonnegative maximum delta are required")
        else:
            raise EngineError("state_oracle", "Specify forbidden_after or max_delta")
        outcome="confirmed" if violation else "inconclusive"
        reason="Declared resource-state invariant was violated" if violation else "No violation observed; a discriminating normal state-transition control is still required for refutation"
    elif kind=="sql_metadata":
        proof = _sql_metadata(project, item, operation, observations, oracle)
        outcome, reason = "confirmed", "A database name or current database user was recovered through the bound SQL input with a normal baseline and discriminating negative control"
    elif kind=="extraction":
        # Data-exfiltration oracle. A timing delay alone is a *signal*, not a result:
        # this oracle requires an actual recovered value that matches a declared
        # pattern, plus a control capture where the same channel returns nothing.
        if item.get("kind") != "input_test" or len(observations)!=2:
            raise EngineError("oracle_binding",
                              "Extraction needs an input-test obligation, recovering capture and negative control")
        if _sql_input(item, operation):
            raise EngineError("sql_metadata_required", "Use sql_metadata with database/current-user proof; generic strings cannot confirm SQL injection")
        _same_identity(observations)
        _input_controls(observations, item, operation)
        recovered,control=observations
        selector=oracle.get("selector")
        if not isinstance(selector,str) or not selector.startswith("/"):
            raise EngineError("selector", "A JSON Pointer is required for the recovered value")
        patterned=oracle.get("expect")
        if not isinstance(patterned,str) or not patterned:
            raise EngineError("oracle_binding", "Declare expect: the pattern the recovered value satisfies")
        try:
            pattern=re.compile(patterned)
        except re.error as exc:
            raise EngineError("oracle_binding", "expect must be a valid regular expression") from exc
        if not 200<=recovered[1]["response"]["status"]<300:
            raise EngineError("control_invalid", "The recovering capture must be a successful response")
        if not 200<=control[1]["response"]["status"]<300:
            raise EngineError("control_invalid", "The negative control must be a successful response")
        try:
            value=_value(recovered,selector)
        except EngineError:
            raise EngineError("sensitivity",
                              "The recovering capture has no value at " + selector
                              + "; declare a selector the successful response actually populates")
        try:
            control_value=_value(control,selector)
        except EngineError:
            # The control legitimately lacks the value (that is what makes it a control).
            control_value=None
        if not isinstance(value,str) or not value:
            raise EngineError("sensitivity", "The recovering capture returned no value to match")
        if value==control_value:
            raise EngineError("sensitivity",
                              "Control and recovering captures returned the same value; no discriminating control")
        if not pattern.search(value):
            raise EngineError("sensitivity",
                              "Recovered value does not satisfy the declared expect pattern")
        proof = _family_extraction(item, operation, observations, oracle, value, control_value)
        outcome="confirmed"
        reason="A concrete value was extracted through the tested input and satisfies the declared pattern; timing or error signals alone would not be sufficient"
    elif kind=="error_channel":
        proof = _error_channel(project, item, operation, observations, oracle)
        outcome = "confirmed"
        reason = ("The DBMS error text carried the requested metadata value, which the normal and negative controls did not"
                  if proof["metadata_type"] == "database" else
                  "The DBMS error text carried the current database user, which the normal and negative controls did not")
    else:
        raise EngineError("unsupported_oracle",
                          "Supported oracles: baseline, authorization, semantic_negative, state_invariant, state_transition, "
                          "extraction, error_channel, sql_metadata; runtime labels are not proof")
    decision={"id":project.id("D"),"obligation_id":item["id"],"operation_id":operation["id"],
              "operation_signature":operation_signature(operation),"oracle":oracle,"outcome":outcome,
              "evidence_ids":ids,"reason":reason,"mode":"machine","oracle_version":SQL_METADATA_VERSION,"created_at":now()}
    if proof:
        decision["proof"] = proof
    item.update(status="evaluated" if outcome!="inconclusive" else "open",decision_id=decision["id"],reason=reason)
    with project.transaction():
        project.put("decision",decision,create_only=True)
        project.put("obligation",item)
        project.event("assessment.decided",{"decision_id":decision["id"],"outcome":outcome,"obligation_id":item["id"]})
    return decision


@atomic
def record_finding(project,args):
    for key in ("title","category","impact","remediation"):
        if not isinstance(args.get(key),str) or not args[key].strip():
            raise EngineError("finding_fields", f"Finding requires {key}")
    # Syntactic arguments are validated before evidence lookups. A typo in origin
    # must name the legal values, not hide behind "Unknown evidence ID".
    origin = args.get("origin", "independent")
    if origin not in {"independent", "hint_guided", "imported"}:
        raise EngineError("origin",
                          "origin must be one of independent | hint_guided | imported; got " + repr(origin)
                          + " (independent = found by your own testing, hint_guided = a range checklist or scanner "
                            "hint pointed you there, imported = legacy import; defaults to independent)")
    severity = args.get("severity", "medium")
    if severity not in {"info", "low", "medium", "high", "critical"}:
        raise EngineError("severity", "severity must be one of info | low | medium | high | critical")
    limitations = args.get("limitations", [])
    if not isinstance(limitations, list) or any(not isinstance(value, str) for value in limitations):
        raise EngineError("finding_fields", "limitations must be an array of strings")
    mode = args.get("mode", "machine")
    requested_obligation = args.get("obligation_id")
    if requested_obligation is not None and (not isinstance(requested_obligation, str) or not requested_obligation
            or mode != "analyst" or not is_xss_category(args["category"])):
        raise EngineError("analyst_obligation", "obligation_id is only supported for an explicitly reviewed XSS runtime finding")
    sql_evidence = None
    if mode == "machine":
        if not isinstance(args.get("decision_id"), str) or not args["decision_id"]:
            raise EngineError("finding_decision",
                              "machine mode requires decision_id from assessment.evaluate; analyst mode requires "
                              "reviewer, reason and evidence_ids (SQL also needs proof_decision_id or sql_evidence)")
        decision = project.get("decision", args["decision_id"])
        from .engine import _decision_valid
        _decision_valid(project, decision)
        if decision["outcome"] != "confirmed":
            raise EngineError("finding_decision", "A confirmed decision is required")
        validate_confirmation(project, decision, args["category"])
    elif mode == "analyst":
        if not str(args.get("reviewer", "")).strip() or not str(args.get("reason", "")).strip():
            raise EngineError("analyst_review", "Explicit reviewer and impact reasoning required")
        if is_sql_category(args["category"]):
            proof_id = args.get("proof_decision_id", args.get("decision_id"))
            if proof_id:
                source_decision = project.get("decision", proof_id)
                validate_confirmation(project, source_decision, args["category"])
                if source_decision.get("outcome") != "confirmed":
                    raise EngineError("finding_decision", "The metadata proof must be confirmed")
                ids = list(source_decision["evidence_ids"])
                if args.get("evidence_ids") is not None and args["evidence_ids"] != ids:
                    raise EngineError("evidence_binding", "Analyst evidence must match the metadata proof")
            else:
                # Write-side/destructive SQL may expose no metadata. Accept a
                # paired behavioural diff instead of forcing a false metadata
                # claim or a non-SQL category dodge.
                sql_evidence = args.get("sql_evidence")
                if not isinstance(sql_evidence, dict):
                    raise EngineError("sql_metadata_required",
                                      "Analyst SQL findings need either a sql_metadata proof_decision_id, or "
                                      "sql_evidence {control_evidence_id, injection_evidence_id, observed_change, "
                                      "input_location, input_selector, response_selector} "
                                      "for injections that do not exfiltrate metadata (write-side/destructive)")
                validated = _sql_behaviour_proof(project, sql_evidence)
                sql_evidence = validated
                ids = [validated["control_evidence_id"], validated["injection_evidence_id"]]
                if args.get("evidence_ids") is not None and args["evidence_ids"] != ids:
                    raise EngineError("evidence_binding", "Analyst evidence must match sql_evidence")
                source_decision = None
        else:
            source_decision = None
            ids = args.get("evidence_ids", [])
        if not ids:
            raise EngineError("analyst_evidence", "Analyst review requires actual complete evidence")
        for eid in ids:
            verify_current_evidence(project, eid, allow_expired_session=True)
        decision = {"id": project.id("D"), "outcome": "confirmed", "mode": "analyst",
                    "oracle": {"type": "analyst_review"}, "reviewer": args["reviewer"],
                    "reason": args["reason"], "evidence_ids": ids, "created_at": now()}
        if source_decision:
            for key in ("obligation_id", "operation_id", "operation_signature", "oracle", "oracle_version", "proof"):
                decision[key] = source_decision[key]
            decision["proof_decision_id"] = source_decision["id"]
        if sql_evidence:
            decision["proof"] = sql_evidence
            decision["operation_id"] = sql_evidence["operation_id"]
            decision["operation_signature"] = operation_signature(project.get("operation", sql_evidence["operation_id"]))
        if is_xss_category(args["category"]):
            decision["runtime"] = {"visit_id": args.get("runtime_visit_id"),
                                   "consumer_url": args.get("consumer_url"), "marker": args.get("runtime_marker")}
            if requested_obligation is not None:
                bound_item = project.get("obligation", requested_obligation)
                decision.update(obligation_id=bound_item["id"], operation_id=bound_item["operation_id"],
                                operation_signature=operation_signature(project.get("operation", bound_item["operation_id"])),
                                oracle={"type": "analyst_runtime", "test_family": "xss"})
                decision["proof"] = _bound_xss_proof(project, decision)
            else:
                decision["proof"] = _runtime_proof(project, decision)
        project.put("decision", decision, create_only=True)
    else:
        raise EngineError("finding_mode", "mode must be machine or analyst")
    finding={"id":project.id("F"),"title":args["title"],"category":args["category"],"impact":args["impact"],
             "remediation":args["remediation"],"severity":severity,"decision_id":decision["id"],
             "evidence_ids":decision["evidence_ids"],"mode":decision["mode"],"origin":origin,"status":"confirmed",
             "limitations":list(limitations),"created_at":now()}
    if is_sql_category(args["category"]):
        proof = decision.get("proof") or {}
        finding["proof"] = proof
        if proof.get("channel") == "behavioural_diff":
            finding["confirmed_scope"] = "sql_behaviour"
            finding["limitations"].append(
                "Confirmed by server-side SQL behaviour change (control vs injection), not by recovering "
                "database()/current_user(); the exact injected statement is inferred from observed effects.")
        else:
            finding["confirmed_scope"] = "database_metadata"
            finding["limitations"].append(
                "Only the recorded database metadata was recovered; broader table access and database modification were not tested.")
    if is_xss_category(args["category"]):
        finding["proof"] = decision["proof"]
        finding["confirmed_scope"] = "browser_execution"
        if decision["proof"].get("source") == "imported_mcp":
            finding["limitations"].append("Browser MCP output is externally imported and explicitly reviewed; it is not a machine-authenticated browser execution.")
    project.put("finding",finding,create_only=True)
    if requested_obligation is not None:
        bound_item.update(status="evaluated", decision_id=decision["id"], reason=args["reason"])
        project.put("obligation", bound_item)
        project.event("assessment.analyst_bound", {"obligation_id": bound_item["id"], "decision_id": decision["id"],
                                                 "finding_id": finding["id"], "test_family": "xss"})
    project.event("finding.recorded",{"finding_id":finding["id"],"decision_id":decision["id"]})
    return finding
