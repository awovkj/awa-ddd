"""Build a frozen recipe from a ready hypothesis and the current ledger.

Only hypotheses whose prerequisites are present become executable recipes.  A
blocked hypothesis returns a preparation row instead; the builder never invents
a session, fixture or URL authorization.
"""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from .. import engine
from ..domain import new_recipe
from ..domain.repository import Repository

FAMILY_ORACLE = {
    "sql_injection": "sql_metadata",
    "xss": "browser_runtime",
    "ssrf": "extraction",
    "xxe": "extraction",
    "path_traversal": "extraction",
    "command_injection": "bounded_side_effect",
    "template_injection": "unexpected_expression_evaluation",
    "deserialization": "unsafe_type_instantiation",
    "file_upload": "upload_path_escape",
    "business_logic": "state_transition",
    "access_control": "authorization",
    "generic": "semantic_negative",
}

PAYLOADS = {
    "sql_injection": ("AWA-NORMAL", "AWA' OR '1'='1", "AWA-NORMAL-2"),
    "xss": ("AWA-NORMAL", "AWA-XSS-<svg/onload=alert(1)>", "AWA-NORMAL-2"),
    "template_injection": ("AWA-NORMAL", "7*7", "AWA-NORMAL-2"),
    "command_injection": ("AWA-NORMAL", "AWA-CANARY", "AWA-NORMAL-2"),
    "deserialization": ("AWA-NORMAL", '{"@type":"AWA-Canary"}', "AWA-NORMAL-2"),
    "file_upload": ("AWA-NORMAL.txt", "AWA-ATTACK.txt", "AWA-NORMAL-2.txt"),
    "ssrf": ("https://awa.invalid/normal", "http://127.0.0.1:9/awa-canary", "https://awa.invalid/normal-2"),
    "path_traversal": ("AWA-NORMAL", "../../awa-canary", "AWA-NORMAL-2"),
    "business_logic": ("AWA-NORMAL", "AWA-ATTACK", "AWA-NORMAL-2"),
    "access_control": ("AWA-NORMAL", "AWA-ATTACK", "AWA-NORMAL-2"),
    "generic": ("AWA-NORMAL", "AWA-ATTACK", "AWA-NORMAL-2"),
}


def _first_session(project, operation):
    sessions = [row for row in project.list("session") if row.get("actor_id")]
    for session in sessions:
        if operation.get("auth") == "restricted" and session.get("actor_id"):
            actor = project.get("actor", session["actor_id"], required=False) or {}
            if set(actor.get("roles") or []) & set(operation.get("allowed_roles") or []):
                return session
        elif operation.get("auth") != "restricted":
            return session
    return sessions[0] if sessions else None


def _resource(project, operation, session):
    for resource in project.list("resource"):
        if resource.get("operation_id") == operation.get("id") and (
                not session or resource.get("owner_actor_id") == session.get("actor_id")):
            return resource
    return None


def _input(operation, input_key):
    from ..domain.common import stable_id
    for entry in operation.get("inputs", []):
        key = stable_id("IN", {"operation": operation["id"], "location": entry.get("location"),
                               "selector": entry.get("selector", entry.get("name")),
                               "branch": entry.get("schema_branch")})
        if key == input_key:
            return entry
    return None


def _request_for(operation, entry, value):
    parsed = urlsplit(operation["url"])
    query = ""
    body = None
    headers = None
    if entry and entry.get("location") == "query":
        query = f"{entry.get('selector', entry.get('name'))}={value}"
    elif entry and entry.get("location") == "body":
        body = {entry.get("selector", entry.get("name")) or "input": value}
    elif entry and entry.get("location") == "header":
        headers = {entry.get("selector", entry.get("name")): value}
    elif entry and entry.get("location") == "path":
        parsed = urlsplit(operation["url"].replace(
            "{" + str(entry.get("name")) + "}", str(value)).replace(
            ":" + str(entry.get("name")), str(value)))
    url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))
    request = {"url": url, "method": operation.get("method"), "headers": headers or {}}
    if body is not None:
        request["body"] = body
    return request


def build(project, campaign, universe, hypothesis):
    """Return {status:ready, recipe} or {status:blocked, missing, preparation}."""
    operation = next((row for row in project.list("operation")
                      if row.get("id") == hypothesis.get("operation_id")), None)
    if operation is None:
        return {"status": "blocked", "missing": ["exact_authorized_url"],
                "reason": "No registered operation matches this hypothesis; bind the operation first."}
    entry = _input(operation, hypothesis.get("input_key"))
    if entry is None and hypothesis.get("input_key"):
        return {"status": "blocked", "missing": ["actual_input_consumer"],
                "reason": "The hypothesis input no longer exists in the current operation signature."}
    session = _first_session(project, operation)
    resource = _resource(project, operation, session)
    if hypothesis.get("family") == "access_control":
        return {"status": "blocked", "missing": ["verified_principal_and_roles"],
                "reason": "Access-control recipes require a dedicated 3-way principal control provider (anonymous/allowed/forbidden); do not reuse one session."}
    from ..domain.repository import Repository
    fixture = next((row for row in Repository(project).list("fixture", limit=None)[0]
                    if row.get("operation_id") == operation["id"]
                    and row.get("state") in {"verified", "leased"}), None)
    if operation.get("auth") != "public" and session is None:
        return {"status": "blocked", "missing": ["verified_principal_and_roles"],
                "reason": "No verified session exists for this operation."}
    if hypothesis.get("family") in {"business_logic"} and resource is None and operation.get("method") not in {"GET", "HEAD", "OPTIONS"}:
        return {"status": "blocked", "missing": ["owned_test_fixture"],
                "reason": "A writable business-logic test requires an owned, reversible fixture."}
    family = hypothesis.get("family", "generic")
    oracle_type = FAMILY_ORACLE.get(family, "semantic_negative")
    normal, attack, negative = PAYLOADS.get(family, PAYLOADS["generic"])
    if family == "template_injection":
        oracle = {"id": "OR-EXPR-1", "type": "unexpected_expression_evaluation", "version": "1",
                  "proof_scope": "unexpected_expression_evaluation", "selector": "/value",
                  "expected_value": "49"}
        normal, attack, negative = "AWA-NORMAL", "7*7", "AWA-NORMAL-2"
    elif family == "deserialization":
        oracle = {"id": "OR-PARSE-1", "type": "unsafe_type_instantiation", "version": "1",
                  "proof_scope": "unsafe_type_instantiation", "selector": "/type", "expected_value": "AWA-Canary"}
    elif family == "file_upload":
        oracle = {"id": "OR-UPLOAD-1", "type": "upload_path_escape", "version": "1",
                  "proof_scope": "upload_path_escape", "selector": "/path", "expected_value": "outside_root"}
    else:
        selector = "/count" if oracle_type in {"sql_metadata", "semantic_negative", "state_invariant", "baseline"} else "status"
        oracle = {"id": "OR-" + oracle_type.upper(), "type": oracle_type, "version": "1",
                  "proof_scope": "authorization_boundary" if oracle_type == "authorization" else
                                 "semantic_refutation" if oracle_type == "semantic_negative" else
                                 "baseline_observation" if oracle_type == "baseline" else
                                 "state_transition" if oracle_type == "state_transition" else
                                 "sql_metadata_observation" if oracle_type == "sql_metadata" else
                                 "extraction_observation" if oracle_type == "extraction" else
                                 "browser_runtime_xss" if oracle_type == "browser_runtime" else
                                 "bounded_side_effect",
                  "selector": selector, "expected_value": "AWA-ATTACK"}
    controls = []
    for role, value in (("normal", normal), ("attack", attack), ("negative", negative)):
        request = _request_for(operation, entry, value)
        controls.append({"id": role, "role": role, "request": request,
                         "expected": {"selector": oracle["selector"], "value": value},
                         "observe_as": {"normal": "normal_control", "attack": "attack_control",
                                        "negative": "negative_control"}[role]})
    bindings = {
        "scope_epoch": campaign.get("scope_epoch") or universe.get("scope_epoch"),
        "target_build": universe.get("target_build") or universe.get("snapshot_hash", "")[:16],
        "operation_id": operation["id"],
        "operation_signature": engine.operation_signature(operation),
        "session": None if session is None else {
            "session_id": session["id"], "generation": session.get("generation", 1),
            "actor_id": session.get("actor_id")},
        "resource": None if resource is None else {
            "resource_id": resource["id"], "revision": resource.get("revision", 1)},
        "fixture": None if fixture is None else {
            "fixture_id": fixture["id"], "revision": fixture.get("revision", 1)},
        "consumer_context": {"input_key": hypothesis.get("input_key"), "input": entry},
    }
    effect = "read_only" if operation.get("method") in {"GET", "HEAD", "OPTIONS"} else "test_resource_write"
    if effect == "test_resource_write" and (resource is None or fixture is None):
        missing = []
        if resource is None:
            missing.append("owned_test_fixture")
        if fixture is None:
            missing.append("owned_test_fixture")
        return {"status": "blocked", "missing": sorted(set(missing)),
                "reason": "Write recipes require an owned disposable resource and a verified fixture."}
    recipe = new_recipe(
        hypothesis=hypothesis,
        provider={"name": "http", "profile": "native_http_read" if effect == "read_only" else "native_http_fixture_write", "version": "1"},
        bindings=bindings,
        control_groups=[{"id": "primary", "identity_role": session.get("actor_id") if session else "anonymous",
                         "controls": controls}],
        oracle=oracle,
        steps=["发送正常对照", "发送攻击对照", "发送阴性对照", "按 oracle 读取证据"],
        limits={"step_total": 3, "time_ms": 120000, "max_writes": 1 if effect == "test_resource_write" else 0,
                "effect": effect},
        variables={"label": {"source": "caller", "max_length": 128}},
        private_manifest={"control_groups": [{"id": "primary", "controls": controls}], "bindings": bindings},
    )
    return {"status": "ready", "recipe": recipe}
