"""Build a frozen recipe from a ready hypothesis and the current ledger.

Only hypotheses whose prerequisites are present become executable recipes.  A
blocked hypothesis returns a preparation row instead; the builder never invents
a session, fixture or URL authorization.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

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


def _json_assign(document, selector, value):
    """Set a root field or JSON Pointer without string-replacing request structure."""
    if not selector or not selector.startswith("/"):
        if document is None:
            document = {}
        if not isinstance(document, dict):
            raise ValueError("A root form field requires a JSON object")
        document[selector or "input"] = value
        return document
    tokens = [token.replace("~1", "/").replace("~0", "~") for token in selector[1:].split("/")]
    if re.search(r"~(?![01])", selector):
        raise ValueError("Invalid JSON Pointer")
    def assign(node, parts):
        token, remaining = parts[0], parts[1:]
        if token.isdigit() and (token == "0" or not token.startswith("0")):
            if node is None:
                node = []
            if not isinstance(node, list):
                raise ValueError("JSON Pointer array branch does not match the request schema")
            index = int(token)
            while len(node) <= index:
                node.append(None)
            if remaining:
                node[index] = assign(node[index], remaining)
            else:
                node[index] = value
            return node
        if node is None:
            node = {}
        if not isinstance(node, dict):
            raise ValueError("JSON Pointer object branch does not match the request schema")
        if remaining:
            node[token] = assign(node.get(token), remaining)
        else:
            node[token] = value
        return node
    return assign(document, tokens)


def _request_for(operation, entry, value, resource=None):
    parsed = urlsplit(operation["url"])
    query = parsed.query
    body = None
    headers = None
    if entry and entry.get("location") == "query":
        tested = urlencode({entry.get("selector", entry.get("name")): value})
        query = "&".join(part for part in (query, tested) if part)
    elif entry and entry.get("location") == "body":
        body = _json_assign(None, entry.get("selector", entry.get("name")), value)
    elif entry and entry.get("location") == "header":
        headers = {entry.get("selector", entry.get("name")): value}
    elif entry and entry.get("location") == "path":
        encoded = quote(str(value), safe="")
        parsed = urlsplit(operation["url"].replace(
            "{" + str(entry.get("name")) + "}", encoded).replace(
            ":" + str(entry.get("name")), encoded))
    if resource:
        binding = resource.get("request_binding") or {}
        location, selector = binding.get("location"), binding.get("selector")
        external_id = resource.get("external_id")
        if entry and location == entry.get("location") \
                and selector == entry.get("selector", entry.get("name")):
            raise ValueError("The tested input and immutable resource binding must be distinct")
        if location == "body":
            body = _json_assign(body, selector, external_id)
        elif location == "query":
            pairs = [(key, item) for key, item in parse_qsl(query, keep_blank_values=True) if key != selector]
            pairs.append((selector, str(external_id)))
            query = urlencode(pairs)
        elif location == "path":
            parsed = urlsplit(parsed._replace(path=parsed.path.replace(
                "{" + str(selector) + "}", quote(str(external_id), safe=""))))
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
                    and resource is not None
                    and row.get("resource_id") == resource["id"]
                    and row.get("owner_actor_id") == resource.get("owner_actor_id")
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
    effect = "read_only" if operation.get("method") in {"GET", "HEAD", "OPTIONS"} else "test_resource_write"
    controls = []
    for role, value in (("normal", normal), ("attack", attack), ("negative", negative)):
        request = _request_for(operation, entry, value, resource)
        controls.append({"id": role, "role": role, "request": request,
                         "effect": effect,
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
    if effect == "test_resource_write" and (resource is None or fixture is None):
        missing = []
        if resource is None:
            missing.append("owned_test_fixture")
        if fixture is None:
            missing.append("owned_test_fixture")
        return {"status": "blocked", "missing": sorted(set(missing)),
                "reason": "Write recipes require an owned disposable resource and a verified fixture."}
    execution_strategy = "single_write_attack_only" if effect == "test_resource_write" else None
    if execution_strategy:
        # Keep all three declarations for review, but dispatch only the attack.
        # Normal/negative are explicitly unobserved, never mislabeled as reads.
        for control in controls:
            control["dispatch"] = control["role"] == "attack"
    recipe = new_recipe(
        hypothesis=hypothesis,
        provider={"name": "http", "profile": "native_http_read" if effect == "read_only" else "native_http_fixture_write", "version": "1"},
        bindings=bindings,
        control_groups=[{"id": "primary", "identity_role": session.get("actor_id") if session else "anonymous",
                         **({"execution_strategy": execution_strategy} if execution_strategy else {}),
                         "controls": controls}],
        oracle=oracle,
        steps=(["发送单次攻击写", "按 oracle 读取证据", "保留正常/阴性控制为未分派"]
               if execution_strategy else ["发送正常对照", "发送攻击对照", "发送阴性对照", "按 oracle 读取证据"]),
        limits={"step_total": 3, "time_ms": 120000, "max_writes": 1 if effect == "test_resource_write" else 0,
                "effect": effect,
                **({"control_strategy": execution_strategy} if execution_strategy else {})},
        variables={"label": {"source": "caller", "max_length": 128}},
        private_manifest={"control_groups": [{
            "id": "primary",
            **({"execution_strategy": execution_strategy} if execution_strategy else {}),
            "controls": controls,
        }], "bindings": bindings},
        campaign_id=campaign["id"],
        universe_id=universe["id"],
    )
    return {"status": "ready", "recipe": recipe}
