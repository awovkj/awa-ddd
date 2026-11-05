"""Single-source assessment semantics shared by tools, plans, and reports."""
from __future__ import annotations
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import secrets
import stat
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, parse_qs, parse_qsl
from .store import Project, EngineError, canonical, now, contained
from .scope import normalize_url, require_scope, bind_operation, validate_config
from .transport import request, response_json, pointer, headers_map


TEST_FAMILIES = ("sql_injection", "xss", "ssrf", "xxe", "path_traversal", "command_injection",
                 "template_injection", "deserialization", "file_upload", "business_logic", "generic")
MAX_OWNERSHIP_CONTEXTS = 16
MAX_OWNERSHIP_VARIANTS = 16


def normalize_test_families(value):
    if not isinstance(value, list) or not value or len(value) > len(TEST_FAMILIES) \
            or any(not isinstance(family, str) or family not in TEST_FAMILIES for family in value):
        raise EngineError("test_families", "test_families must be a nonempty array drawn from: "
                          + ", ".join(TEST_FAMILIES))
    if len(set(value)) != len(value):
        raise EngineError("test_families", "test_families must not contain duplicate hypotheses")
    return sorted(value)


def _validate_input_identity(entry, operation_id=None):
    details = {"next_action": "surface.inspect", "help_action": "action.help",
               "help_input": {"name": "surface.register"}}
    if operation_id is not None:
        details["operation_id"] = operation_id
    if not isinstance(entry, dict) or not isinstance(entry.get("name"), str) or not entry["name"].strip() \
            or not isinstance(entry.get("location"), str) \
            or entry["location"] not in {"query", "path", "header", "cookie", "body", "graphql"}:
        raise EngineError("input", "Input requires a nonempty name and supported location", details)
    selector = entry.get("selector", entry["name"])
    root_selector = selector == "" and entry["location"] in {"body", "graphql"}
    if not isinstance(selector, str) or not selector.strip() and not root_selector:
        raise EngineError("input_selector", "Input selector must be an exact string; omit it to use the name or explicitly declare a JSON root",
                          {**details, "field": "selector"})
    branch = entry.get("schema_branch")
    if branch is not None and not isinstance(branch, str):
        raise EngineError("input_schema_branch", "Input schema_branch must be a string or null",
                          {**details, "field": "schema_branch"})


def _validate_operation_inputs(operation, *, registered=True):
    entries = operation.get("inputs", [])
    if (registered and "id" in operation and "inputs" not in operation) \
            or not isinstance(entries, list) or len(entries) > 4096:
        raise EngineError("input", "Operation inputs must be an array of at most 4096 entries",
                          {"operation_id": operation.get("id"), "next_action": "surface.inspect"})
    for entry in entries:
        _validate_input_identity(entry, operation.get("id"))
        if registered and "selector" not in entry:
            raise EngineError("input_selector", "Registered input is missing its exact selector; inspect its source before repair",
                              {"operation_id": operation.get("id"), "field": "selector", "next_action": "surface.inspect"})


def stamp(value):
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed
    except (ValueError, TypeError) as exc:
        raise EngineError("timestamp", "Timezone-aware timestamp required") from exc


def stable(prefix, value):
    return prefix + "-" + hashlib.sha256(canonical(value).encode()).hexdigest()[:24]


def atomic(function):
    @wraps(function)
    def wrapped(project, *args, **kwargs):
        with project.transaction():
            return function(project, *args, **kwargs)
    return wrapped


def create_project(workspace, args):
    config = validate_config({"project_id": args["project_id"], "target": args["target"],
        "scope": args.get("scope"), "exclude": args.get("exclude", []),
        "allow_mutation": args.get("allow_mutation") is True, "created_at": now(), "schema_version":1})
    with Project(workspace, args["project_id"], create=True) as project:
        if project.config:
            raise EngineError("project_exists", "Project already exists; resume it without reinitializing")
        project.set_config(config)
        project.event("project.created", {"project_id":args["project_id"]})
        return {"project_id":args["project_id"], "path":str(project.base), "config":config}


def operation_signature(operation):
    fields = ("url","method","protocol","operation_name","content_type","auth","allowed_roles","ownership")
    policy = {k: operation.get(k) for k in fields}
    if operation.get("state_scope") == "actor":
        policy["state_scope"] = "actor"
    return stable("S", policy)


def actor_signature(actor):
    return stable("AS", {k: actor.get(k) for k in ("subject", "tenant_id", "roles")}
                  | {"security_revision": actor.get("security_revision", 1)})


def resource_signature(resource):
    return stable("RS", {k: resource.get(k) for k in (
        "operation_id", "owner_actor_id", "tenant_id", "external_id", "request_binding")})


@atomic
def register_operation(project, hint):
    url = require_scope(project.config, hint["url"])
    method = str(hint.get("method") or "").upper()
    if method not in {"GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"}:
        raise EngineError("operation_method", "Known HTTP method required; unresolved methods remain candidates")
    parsed = urlsplit(url)
    url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    protocol = str(hint.get("protocol", "http")).strip().lower()
    # `https` is a URL scheme, not an executor protocol; callers regularly confuse
    # the two. Treat http/https/http1 as the HTTP executor instead of failing.
    if protocol in {"http", "https", "http1", "http/1.1"}:
        protocol = "http"
    if protocol == "graphql":
        protocol = "graphql"
    if protocol not in {"http", "graphql"}:
        raise EngineError("protocol", "protocol must be http (HTTP executor) or graphql; https is selected by the URL scheme")
    name = hint.get("operation_name", "")
    if protocol == "graphql" and (not isinstance(name, str) or not name):
        raise EngineError("operation_name", "GraphQL operations require an explicit operation name")
    media = str(hint.get("content_type", "")).lower()
    identity = stable("O", [url, method, protocol, name, media])
    existing = project.get("operation", identity, required=False) or {}
    _validate_operation_inputs(existing)
    _validate_operation_inputs({"id": identity, "inputs": hint.get("inputs", [])}, registered=False)
    inputs = {}
    for entry in existing.get("inputs", []) + list(hint.get("inputs", [])):
        normalized = {k:entry[k] for k in ("name","location","selector","source","consumer","schema_branch","schema_type","required","array_template","schema_locator","test_families") if k in entry}
        if "test_families" in normalized:
            normalized["test_families"] = normalize_test_families(normalized["test_families"])
        normalized.setdefault("selector", normalized["name"])
        normalized.setdefault("consumer", "unknown")
        if normalized["consumer"] is None:
            normalized["consumer"] = "unknown"
        if not isinstance(normalized["consumer"], str):
            raise EngineError("consumer", "consumer must be a concrete sink string or unknown")
        normalized.setdefault("source", "declared")
        key = canonical([normalized["location"],normalized["selector"],normalized.get("schema_branch")])
        if "test_families" not in normalized and "test_families" in inputs.get(key, {}):
            normalized["test_families"] = inputs[key]["test_families"]
        inputs[key] = normalized
    declared_query_selectors = {entry["selector"] for entry in inputs.values() if entry["location"] == "query"}
    for key in parse_qs(parsed.query, keep_blank_values=True):
        # A URL value does not declare another schema branch. Keep every saved
        # branch, but only fill inputs the caller has not declared at all.
        if key not in declared_query_selectors:
            inputs[canonical(["query",key,None])] = {"name":key,"location":"query","selector":key,"source":"declared","consumer":"unknown"}
    if len(inputs) > 4096:
        raise EngineError("input_budget", "Too many inputs in one operation")
    auth = hint.get("auth", existing.get("auth", "unknown"))
    auth_aliases = {"none": "public", "anonymous": "public", "no_auth": "public",
                    "session": "authenticated", "required": "authenticated", "login": "authenticated",
                    "role": "restricted", "roles": "restricted"}
    if isinstance(auth, str):
        auth = auth_aliases.get(auth.strip().lower(), auth.strip().lower())
    if auth not in {"public","authenticated","restricted","unknown"}:
        raise EngineError("auth", "auth must be one of: public (no session needed), authenticated (any verified session), restricted (specific allowed_roles), unknown (not yet declared); aliases none/anonymous are accepted for public")
    roles = hint.get("allowed_roles", existing.get("allowed_roles", []))
    if not isinstance(roles,list) or any(not isinstance(x,str) or not x for x in roles):
        raise EngineError("roles", "allowed_roles must be an array of role names, e.g. [\"admin\"]")
    if auth == "restricted" and not roles:
        raise EngineError("roles", "auth=restricted requires allowed_roles, e.g. [\"admin\"]")
    # A caller passing ownership:"none"/"true" almost certainly means the boolean; the
    # old `is True` test silently recorded ownership=false instead of surfacing a typo.
    raw_ownership = hint.get("ownership", existing.get("ownership", False))
    if isinstance(raw_ownership, bool):
        ownership = raw_ownership
    elif isinstance(raw_ownership, str) and raw_ownership.strip().lower() in {"true","false","yes","no","none","self","actor"}:
        ownership = raw_ownership.strip().lower() in {"true","yes","self","actor"}
    else:
        raise EngineError("ownership", "ownership must be a boolean (true when the resource belongs to a single actor); "
                                       "none/no are accepted as false")
    state_scope = hint.get("state_scope", existing.get("state_scope"))
    if state_scope not in {None, "actor"}:
        raise EngineError("state_scope", "state_scope must be actor for an explicitly declared self-state action, or null")
    if state_scope == "actor" and inputs:
        raise EngineError("state_scope", "Actor-scoped self-state actions must not declare resource-bearing inputs; bind a test resource instead")
    if state_scope == "actor" and (protocol != "http" or "{" in parsed.path or "}" in parsed.path):
        raise EngineError("state_scope", "Actor-scoped writes require a concrete HTTP path without resource placeholders")
    sources = existing.get("sources", []) + hint.get("sources", [])
    sources = list({canonical(s):s for s in sources}.values())[:256]
    record = {"id":identity,"url":url,"method":method,"protocol":protocol,"operation_name":name,
        "content_type":media,"inputs":list(inputs.values()),"sources":sources,"auth":auth,
        "allowed_roles":sorted(set(roles)),"ownership":ownership,
        "created_at":existing.get("created_at",now())}
    if state_scope is not None:
        record["state_scope"] = state_scope
    project.put("operation",record)
    project.event("surface.registered", {"operation_id":identity,"inputs":len(inputs)})
    return record


@atomic
def update_project(project, args):
    """Narrow, auditable project-config changes that do not require reinitializing.

    Previously `allow_mutation` could only be set at creation: enabling writes on an
    existing project meant deleting and rebuilding it, losing every actor, operation,
    resource and capture. Only explicitly supported keys are writable here, and every
    change is recorded as an event so the widening of privilege stays visible.
    """
    config = dict(project.config)
    changes = {}
    if "allow_mutation" in args:
        value = args["allow_mutation"]
        if not isinstance(value, bool):
            raise EngineError("config", "allow_mutation must be a boolean")
        if value != config.get("allow_mutation"):
            changes["allow_mutation"] = {"from": config.get("allow_mutation"), "to": value}
            config["allow_mutation"] = value
    if "exclude" in args:
        value = args["exclude"]
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise EngineError("config", "exclude must be an array of URL prefixes")
        from .scope import normalize_url
        for rule in value:
            normalize_url(rule)
        if value != (config.get("exclude") or []):
            changes["exclude"] = {"from": config.get("exclude") or [], "to": value}
            config["exclude"] = value
    if not changes:
        return {"project_id": project.project_id, "config": config, "changed": False}
    project.set_config(validate_config(config))
    project.event("project.config_changed", {"changes": changes})
    return {"project_id": project.project_id, "config": project.config, "changed": True, "changes": changes}


@atomic
def add_actor(project, args):
    identity = args.get("actor_id") or project.id("ACT")
    existing = project.get("actor", identity, required=False) or {}
    roles = args.get("roles", existing.get("roles", []))
    if not isinstance(roles,list) or any(not isinstance(x,str) or not x for x in roles):
        raise EngineError("roles", "roles must be an array, e.g. [\"user\"]; pass [] when the role set is unknown")
    subject = args.get("subject", existing.get("subject", identity))
    if not isinstance(subject, (str, int)) or isinstance(subject, bool) or subject == "":
        raise EngineError("actor_subject", "subject must be a nonempty server-side account ID (string or integer)")
    actor = {"id":identity,"label":str(args.get("label",existing.get("label", identity))),"subject":subject,
             "tenant_id":str(args.get("tenant_id",existing.get("tenant_id", ""))),
             "roles":sorted(set(roles)),"created_at":existing.get("created_at", now()),
             "security_revision":existing.get("security_revision", 1)}
    if existing:
        # Roles often need correcting after identity verification reveals the server's
        # actual role set; refusing the update forced callers to invent a second actor
        # id, which then duplicated the same human across the ledger.
        if existing.get("roles") == actor["roles"] and existing.get("subject") == actor["subject"] \
                and existing.get("label") == actor["label"] and existing.get("tenant_id") == actor["tenant_id"]:
            return existing
        security_changed = any(existing.get(k) != actor[k] for k in ("subject", "tenant_id", "roles"))
        if security_changed:
            actor["security_revision"] += 1
        project.put("actor", actor)
        project.event("actor.updated", {"actor_id": identity,
                                        "security_changed": security_changed,
                                        "security_revision": actor["security_revision"],
                                        "roles": {"from": existing.get("roles"), "to": actor["roles"]}})
        return actor
    project.put("actor",actor,create_only=True)
    project.event("actor.created", {"actor_id":identity})
    return actor


def public_session(session):
    return {k:v for k,v in session.items() if k not in {"headers", "credential_signature", "credential_nonce"}}


DEFAULT_SESSION_TTL = 7200
DEFAULT_CREDENTIAL_HEADER_NAMES = frozenset({"cookie", "authorization", "x-api-key", "x-auth-token", "x-session-token"})


def _normalize_credential_header_names(names, headers):
    if not isinstance(names, list) or len(names) > 64:
        raise EngineError("credential_header_names", "credential_header_names must be an array of at most 64 registered header names")
    normalized = []
    for name in names:
        if not isinstance(name, str) or len(name) > 128 \
                or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise EngineError("credential_header_names", "Credential classification requires valid bounded HTTP header names")
        key = name.lower()
        if key not in headers or key in normalized:
            raise EngineError("credential_header_names", "Each credential header must occur once and already exist in the registered headers")
        normalized.append(key)
    return sorted(normalized)


def credential_header_names(session):
    headers = session.get("headers") or {}
    if "credential_header_names" not in session:
        return sorted(DEFAULT_CREDENTIAL_HEADER_NAMES.intersection(headers))
    return _normalize_credential_header_names(session["credential_header_names"], headers)


def credential_signature(session):
    names = credential_header_names(session)
    context = {"names": names, "credentials": {name: session["headers"][name] for name in names}}
    if "credential_nonce" in session:
        nonce = session["credential_nonce"]
        if not isinstance(nonce, str) or not re.fullmatch(r"[a-f0-9]{64}", nonce):
            raise EngineError("credential_changed", "Private session credential context is missing or changed")
        context["nonce"] = nonce
    return stable("CH", context)


def _verify_credential_snapshot(session, evidence, artifact):
    names, signature = credential_header_names(session), credential_signature(session)
    if "credential_header_names" in session and session.get("credential_signature") is None:
        raise EngineError("credential_changed", "Session credential classification has no creation-time integrity snapshot; create a new session")
    if session.get("credential_signature") is not None and session["credential_signature"] != signature:
        raise EngineError("credential_changed", "Registered credentials or their classification changed without a new session generation")
    captured_headers = artifact.get("request", {}).get("headers", {})
    if "credential_header_names" in evidence:
        recorded_names = _normalize_credential_header_names(evidence["credential_header_names"], captured_headers)
        if evidence.get("credential_signature") is None:
            raise EngineError("credential_changed", "Captured credential classification lacks its integrity snapshot")
    else:
        recorded_names = sorted(DEFAULT_CREDENTIAL_HEADER_NAMES.intersection(captured_headers))
    if recorded_names != names or (evidence.get("credential_signature") is not None
                                  and evidence["credential_signature"] != signature):
        raise EngineError("credential_changed", "Credential classification or values differ from the captured identity; old observations cannot be relabelled")
    captured = {"headers": captured_headers, "credential_header_names": recorded_names}
    if "credential_nonce" in session:
        captured["credential_nonce"] = session["credential_nonce"]
    if credential_signature(captured) != signature:
        raise EngineError("credential_changed", "Captured credential bytes do not match the registered session credentials")


@atomic
def add_session(project, args):
    if "credential_nonce" in args or "credential_signature" in args:
        raise EngineError("credential_context", "Private session credential context is generated by the engine, not caller-selected")
    identity = args.get("session_id") or project.id("SES")
    previous = project.get("session",identity,required=False)
    renew = args.get("renew", False)
    if not isinstance(renew, bool):
        raise EngineError("renew_shape", "renew must be true or false")
    if renew and not previous:
        raise EngineError("renew_missing", "renew:true needs an existing session_id to renew")
    actor_id = args.get("actor_id", previous["actor_id"] if renew else None)
    if actor_id is None:
        raise EngineError("argument_missing", "Creating a session requires actor_id; renewal needs only session_id and renew:true")
    if previous and previous["actor_id"] != actor_id:
        raise EngineError("identity_mismatch", "A session ID cannot be reassigned to another actor")
    actor = project.get("actor", actor_id)
    ttl = args.get("ttl_seconds", DEFAULT_SESSION_TTL)
    if type(ttl) is not int or not 1 <= ttl <= 86400:
        raise EngineError("session_ttl", "Session TTL must be 1..86400 seconds")
    if renew:
        # Renewal is deliberately not a recreate. Recreating bumps the generation,
        # which silently invalidates every capture already recorded against the old
        # identity. Renewal keeps id/generation/headers/verification and only moves
        # the liveness deadline, so historical evidence stays current.
        if args.get("headers") or args.get("headers_file") or "credential_header_names" in args:
            raise EngineError("renew_shape",
                              "Renewal keeps the registered headers and credential_header_names; create a new session to change credentials or classification")
        session = dict(previous)
        session["expires_at"] = (datetime.now(timezone.utc)+timedelta(seconds=ttl)).isoformat()
        session["renewed_at"] = now()
        project.put("session", session)
        project.event("session.renewed", {"session_id": identity, "generation": session["generation"],
                                          "expires_at": session["expires_at"]})
        return public_session(session)
    header_input = args.get("headers", {})
    if args.get("headers_file"):
        path = Path(args["headers_file"])
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 65536:
            raise EngineError("headers_file", "Expected a bounded local header JSON file")
        header_input = json.loads(path.read_text(encoding="utf-8-sig"))
    headers = headers_map(header_input)
    names = _normalize_credential_header_names(args["credential_header_names"], headers) \
            if "credential_header_names" in args else sorted(DEFAULT_CREDENTIAL_HEADER_NAMES.intersection(headers))
    session = {"id":identity,"actor_id":actor["id"],"generation":previous["generation"]+1 if previous else 1,
               "headers":headers,"verified_at":None,"verification_evidence_id":None,
               "credential_header_names": names, "credential_nonce": secrets.token_hex(32),
               "expires_at":(datetime.now(timezone.utc)+timedelta(seconds=ttl)).isoformat(),"created_at":now()}
    session["credential_signature"] = credential_signature(session)
    project.put("session",session)
    project.event("session.created", {"session_id":identity,"actor_id":actor["id"],"generation":session["generation"]})
    return public_session(session)


def verify_evidence(project, identity):
    from .lineage import compatibility
    evidence = project.get("evidence",identity)
    artifact = project.read_artifact(evidence)
    if not evidence.get("complete") or not artifact.get("complete") or evidence.get("trust") != "observed":
        raise EngineError("evidence_incomplete", "A complete locally observed capture is required")
    operation = project.get("operation",evidence["operation_id"])
    ok, detail = compatibility(operation, evidence, operation_signature(operation))
    if not ok:
        # Name the differing fields: a bare "policy changed" cost real time when the
        # only change was a re-registration that added content_type.
        changes = detail.get("changes") or []
        if changes:
            summary = ", ".join(f"{c['field']}: {c['captured']!r} -> {c['current']!r}" for c in changes[:6])
            raise EngineError("operation_changed", "Operation policy changed after this capture (" + summary + ")")
        raise EngineError("operation_changed", "Operation policy changed after this capture")
    return evidence, artifact


def _verified_session_actor(project, session):
    if not session.get("verified_at") or not session.get("verification_evidence_id"):
        raise EngineError("identity_unverified", "Verify the actual server-side identity before using this session")
    if stamp(session["verified_at"]) > datetime.now(timezone.utc) or stamp(session["verified_at"]) < stamp(session["created_at"]):
        raise EngineError("identity_stale", "Identity verification does not belong to this session generation")
    evidence, artifact = verify_evidence(project,session["verification_evidence_id"])
    if (evidence.get("session_id") != session["id"]
            or evidence.get("session_generation") != session["generation"]
            or evidence.get("actor_id") != session["actor_id"]):
        raise EngineError("identity_stale", "Identity evidence belongs to a different session generation")
    _verify_credential_snapshot(session, evidence, artifact)
    actor = project.get("actor",session["actor_id"])
    signature = actor_signature(actor)
    for recorded in (session.get("actor_signature"), evidence.get("actor_signature")):
        if recorded is not None and recorded != signature:
            raise EngineError("actor_changed", "Actor subject, tenant or roles changed after verification; re-verify before making new requests")
    if session.get("actor_signature") is None and actor.get("security_revision", 1) > 1:
        raise EngineError("actor_changed", "Legacy verification predates a security-property change; re-verify the actual server-side identity")
    assertion = session.get("verification_assertion")
    if not isinstance(assertion, dict) or not assertion.get("subject_selector"):
        raise EngineError("identity_unverified", "Identity verification lacks a server-side subject assertion; run identity.verify")
    _assert_identity(actor,response_json(artifact),assertion)
    return actor


def session_valid(project, session):
    if stamp(session["expires_at"]) <= datetime.now(timezone.utc):
        raise EngineError("session_expired",
                          "Session " + str(session["id"]) + " expired at " + str(session["expires_at"])
                          + "; evidence already captured remains valid. Renew it with identity.session "
                            "renew:true (same id/generation/headers) or create a new session and re-run identity.verify.")
    return _verified_session_actor(project, session)


def require_session_origin(project, session, url):
    """An established identity never forwards its headers to another origin."""
    identity = session.get("verification_evidence_id")
    if not identity:
        # The first explicit identity.verify selects the scoped identity endpoint.
        return
    evidence = project.get("evidence", identity)
    if (evidence.get("session_id") != session["id"]
            or evidence.get("session_generation") != session["generation"]
            or evidence.get("actor_id") != session["actor_id"]):
        raise EngineError("identity_stale", "Identity endpoint belongs to a different session generation")
    artifact = project.read_artifact(evidence)
    from .scope import origin
    if origin(artifact["request"]["url"]) != origin(url):
        raise EngineError("identity_origin", "A session cannot be sent to an origin different from its verified identity endpoint; register and verify a separate session")


def verify_current_evidence(project, identity, *, allow_expired_session=True):
    """Check that a capture is still usable.

    TTL expiry is *liveness*, not evidence integrity. The old implementation called
    session_valid() here, so every 30 minutes a previously verified finding silently
    became ``current: false`` and had to be re-run. What actually protects against
    replay is the generation/actor binding below; liveness is only required by the
    callers that are about to send a new request (session_valid itself).
    """
    evidence, artifact = verify_evidence(project, identity)
    if evidence.get("session_id"):
        session = project.get("session", evidence["session_id"])
        if evidence["session_generation"] != session["generation"] or evidence["actor_id"] != session["actor_id"]:
            raise EngineError("session_changed", "Evidence belongs to an older or different session identity")
        actor = _verified_session_actor(project, session)
        _verify_credential_snapshot(session, evidence, artifact)
        require_session_origin(project, session, artifact["request"]["url"])
        recorded = evidence.get("actor_signature")
        if recorded is not None and recorded != actor_signature(actor):
            raise EngineError("actor_changed", "Captured actor security properties changed; old observations cannot be relabelled by a new verification")
        if recorded is None and actor.get("security_revision", 1) > 1:
            raise EngineError("actor_changed", "Legacy observation has no actor snapshot and predates a security-property change")
        if not allow_expired_session:
            session_valid(project, session)
    if evidence.get("resource_id"):
        resource = project.get("resource", evidence["resource_id"])
        recorded = evidence.get("resource_signature")
        if recorded is not None and recorded != resource_signature(resource):
            raise EngineError("resource_changed", "Test resource identity or request binding changed after capture; preserve the old fixture or recapture")
        operation = project.get("operation", evidence["operation_id"])
        raw = artifact["request"]
        if resource["operation_id"] != operation["id"]:
            raise EngineError("resource_changed", "Test resource belongs to a different operation")
        try:
            _resource_binding(resource, bind_operation(operation, raw["url"], raw["method"]),
                              raw["url"], base64.b64decode(raw["body_base64"], validate=True),
                              content_type=raw.get("headers", {}).get("content-type", ""))
        except EngineError as exc:
            raise EngineError("resource_changed", "Capture no longer has an unambiguous test resource binding") from exc
    else:
        operation = project.get("operation", evidence["operation_id"])
        if operation["method"] not in {"GET", "HEAD", "OPTIONS"}:
            raw = artifact["request"]
            session = project.get("session", evidence["session_id"]) if evidence.get("session_id") else None
            if not _actor_bound_write(operation, session, url=raw["url"],
                                      body=base64.b64decode(raw["body_base64"], validate=True), headers=raw.get("headers", {})):
                raise EngineError("resource_unbound", "A fixture-free historical write contains business inputs; it cannot become a current proof without an explicit test resource")
    return evidence, artifact


def _pointer_exists(response, selector):
    try:
        pointer(response, selector)
        return True
    except EngineError:
        return False


def _identity_selector_boundary(assertion):
    selected = {}
    for field in ("subject_selector", "tenant_selector", "roles_selector"):
        selector = assertion.get(field)
        if selector is None:
            continue
        if not isinstance(selector, str) or not selector.startswith("/") or re.search(r"~(?![01])", selector):
            raise EngineError("identity_assertion", field + " must be a nonempty JSON Pointer")
        tokens = tuple(token.replace("~1", "/").replace("~0", "~") for token in selector[1:].split("/"))
        if tokens in selected:
            raise EngineError("identity_selector_boundary", field + " and " + selected[tokens]
                              + " must select distinct subject, tenant and role fields; an account identifier is not role membership")
        selected[tokens] = field


def _assert_identity(actor, response, assertion):
    _identity_selector_boundary(assertion)
    effective = dict(assertion)
    try:
        observed = pointer(response,assertion["subject_selector"])
    except EngineError:
        raise EngineError("identity_assertion",
                          "subject_selector " + str(assertion["subject_selector"])
                          + " does not resolve in the profile response; pick a pointer that identifies the account")
    if not isinstance(observed, (str, int)) or isinstance(observed, bool) or observed == "":
        raise EngineError("identity_assertion", "subject_selector must identify a concrete server-side account ID, not a status flag or container")
    if observed != actor["subject"]:
        raise EngineError("identity_mismatch",
                          "Server returned a different actor: expected " + repr(actor["subject"])
                          + ", got " + repr(observed))
    if actor["tenant_id"]:
        selector = assertion.get("tenant_selector")
        if not selector:
            selector = next((candidate for candidate in ("/tenant_id", "/tenant", "/data/tenant_id",
                                                         "/data/tenant", "/merchant/id")
                             if _pointer_exists(response, candidate)), None)
        if not selector:
            raise EngineError("tenant_mismatch",
                              "Actor declares tenant_id " + repr(actor["tenant_id"])
                              + "; supply tenant_selector, or create the actor without tenant_id when the server does not expose one")
        effective["tenant_selector"] = selector
        _identity_selector_boundary(effective)
        tenant = pointer(response, selector)
        if not isinstance(tenant, (str, int)) or isinstance(tenant, bool) or str(tenant) != actor["tenant_id"]:
            raise EngineError("tenant_mismatch", "Tenant assertion differs from the declared tenant_id")
    if actor["roles"] or assertion.get("roles_selector"):
        selector = assertion.get("roles_selector")
        if not selector:
            selector = next((candidate for candidate in ("/roles", "/role", "/authorities",
                                                         "/data/roles", "/data/role", "/user/roles")
                             if _pointer_exists(response, candidate)), None)
        if not selector:
            raise EngineError("roles_unverified",
                              "Actor declares roles " + repr(actor["roles"])
                              + "; supply roles_selector pointing at the server-side role list, or create the actor with roles=[] and rely on access-policy checks instead")
        effective["roles_selector"] = selector
        _identity_selector_boundary(effective)
        roles = pointer(response, selector)
        roles = [roles] if isinstance(roles,str) else roles
        if not isinstance(roles,list) or any(not isinstance(role, str) for role in roles) or set(roles) != set(actor["roles"]):
            raise EngineError("roles_mismatch", "Server returned a different role set")


@atomic
def add_resource(project,args):
    owner = project.get("actor",args["owner_actor_id"])
    operation = project.get("operation",args["operation_id"])
    binding = args.get("request_binding")
    if not isinstance(binding,dict):
        raise EngineError("resource_binding", "Resource requires request_binding {location,selector}")
    location = binding.get("location")
    if location == "multipart":
        location = "body"
    if location not in {"path","query","body"} or not isinstance(binding.get("selector"),str) or not binding["selector"]:
        raise EngineError("resource_binding",
                          "request_binding requires location path|query|body (multipart is an alias for body) "
                          "and a nonempty selector; JSON arrays use a pointer such as /0/product_no, "
                          "multipart uses the form field name such as file.")
    selector = binding["selector"]
    if location == "body" and selector.startswith("/") and not re.fullmatch(r"(?:/[^/]+)+", selector):
        raise EngineError("resource_binding", "JSON Pointer selectors look like /0/product_no")
    external = args.get("external_id")
    if not isinstance(external, str) or not external.strip() or len(external) > 4096:
        raise EngineError("resource_binding", "external_id must be a nonempty bounded string")
    record = {"id":args.get("resource_id") or project.id("RES"),"external_id":external,
              "owner_actor_id":owner["id"],"tenant_id":owner["tenant_id"],"operation_id":operation["id"],
              "request_binding":{"location":location,"selector":selector,
                                 **({"format": binding["format"]} if binding.get("format") in {"auto","json","multipart","text"} else {})},
              "state":args.get("state",{}),"created_at":now()}
    existing = project.get("resource", record["id"], required=False)
    if existing:
        if existing.get("operation_id") != record["operation_id"] or existing.get("owner_actor_id") != record["owner_actor_id"]:
            raise EngineError("resource_binding", "An existing resource ID cannot be rebound to another operation/owner")
        record["created_at"] = existing.get("created_at", record["created_at"])
        project.put("resource", record)
        project.event("identity.resource_updated", {"resource_id": record["id"], "operation_id": operation["id"]})
        return record
    return project.put("resource",record,create_only=True)


_ACTOR_STATE_METADATA_HEADERS = frozenset({"accept", "accept-language", "user-agent", "cache-control", "pragma", "content-type"})
_EXECUTOR_HEADERS = frozenset({"host", "content-length", "accept-encoding", "connection"})


def _actor_bound_write(operation, session, *, url=None, body=None, headers=None):
    """A write may be bound to the acting identity when the operation has no
    resource-bearing input at all (audit/status, logout, self state transitions).
    It is still gated by allow_mutation and a verified session."""
    if not session or not session.get("verified_at") or not session.get("verification_evidence_id") \
            or operation.get("state_scope") != "actor":
        return False
    if operation.get("inputs"):
        return False
    if operation.get("protocol") != "http" or "{" in operation["url"] or "}" in operation["url"]:
        return False
    parsed = urlsplit(url or operation["url"])
    if parsed.query or not (body is None or body == b"" or body == ""):
        return False
    actual = headers_map(session.get("headers", {}) if headers is None else headers)
    allowed = _ACTOR_STATE_METADATA_HEADERS | _EXECUTOR_HEADERS | set(credential_header_names(session))
    if set(actual) - allowed:
        return False
    # The private capture includes executor framing, never model-owned inputs.
    managed = {"host": parsed.netloc, "content-length": "0", "accept-encoding": "identity", "connection": "close"}
    return all(key not in actual or actual[key] == expected for key, expected in managed.items())


def _unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EngineError("resource_ambiguous", "Duplicate JSON object keys cannot identify a unique test resource")
        result[key] = value
    return result


def _jsonish(value):
    if isinstance(value, str):
        stripped = value.strip()
        if stripped[:1] in {"{", "["}:
            try:
                return json.loads(stripped, object_pairs_hook=_unique_json_pairs)
            except EngineError:
                raise
            except ValueError:
                return value
    return value


def _same_binding_value(candidate, expected):
    if isinstance(candidate, bool) or isinstance(expected, bool):
        return False
    if isinstance(candidate, bytes) or isinstance(expected, bytes):
        return type(candidate) is type(expected) and candidate == expected
    left, right = _jsonish(candidate), _jsonish(expected)
    if isinstance(left, (dict, list)) or isinstance(right, (dict, list)):
        try:
            return canonical(left) == canonical(right)
        except (TypeError, ValueError):
            return False
    return str(left).strip() == str(right).strip()


def _search_json_key(value, key):
    found = []
    if isinstance(value, dict):
        if key in value:
            found.append(value[key])
        for child in value.values():
            found.extend(_search_json_key(child, key))
    elif isinstance(value, list):
        for child in value:
            found.extend(_search_json_key(child, key))
    return found


def _multipart_parts(raw, content_type):
    if (content_type or "").split(";", 1)[0].strip().lower() != "multipart/form-data":
        return {}
    from .inputs import parse_multipart
    wire = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
    try:
        parsed = parse_multipart(wire, content_type)
    except EngineError as exc:
        if exc.code == "input_ambiguous":
            raise EngineError("resource_ambiguous", "Multipart framing or disposition does not identify a unique test resource", exc.details) from exc
        raise
    return {name: {**part, "content": wire[part["content_span"][0]:part["content_span"][1]]}
            for name, part in parsed["parts"].items()}


def _multipart_binding_value(value):
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="strict")
        except UnicodeError:
            return value
    return value


def _body_candidates(body, selector, content_type):
    """Return every concrete value a body binding may refer to.

    Accepts JSON Pointer, plain JSON key (recursive) and multipart form-field
    names. A file part contributes both its content and filename; callers may bind
    either the uploaded bytes or the client-supplied filename.
    """
    multipart_media = (content_type or "").split(";", 1)[0].strip().lower() == "multipart/form-data"
    if isinstance(body, (bytes, bytearray)):
        wire = bytes(body)
        raw = "" if multipart_media else bytes(body).decode("utf-8", "replace")
    elif isinstance(body, str):
        wire = body.encode("utf-8")
        raw = body
    elif body is None:
        return []
    else:
        raw = canonical(body)
        wire = raw.encode("utf-8")
    parts = _multipart_parts(wire, content_type)
    if parts:
        from .inputs import multipart_selection
        aliases = {"filename", "file.filename", "content", "file.content"}
        if selector in parts and selector not in aliases and not selector.endswith((".filename", ".content")):
            values = [_multipart_binding_value(parts[selector]["content"])]
            if parts[selector]["filename"] is not None:
                values.append(parts[selector]["filename"])
            return values
        try:
            _, _, _, value = multipart_selection({"parts": parts}, wire, selector)
        except EngineError as exc:
            if exc.code == "input_binding":
                return []
            if exc.code == "input_ambiguous":
                raise EngineError("resource_ambiguous", "Multipart selector matches multiple part or attribute interpretations", exc.details) from exc
            raise
        return [_multipart_binding_value(value)]
    if selector.startswith("/"):
        parsed = _jsonish(raw)
        try:
            return [pointer(parsed, selector)]
        except EngineError:
            return []
    parsed = _jsonish(raw)
    found = _search_json_key(parsed, selector)
    if len(found) > 1:
        raise EngineError("resource_ambiguous", "A plain JSON key matches multiple values; select the exact test resource with a JSON Pointer")
    if found:
        return found
    if isinstance(parsed, str) and selector in {"", "body", "raw", "text"}:
        return [parsed]
    return []


def _resource_binding(resource, params, url, body, *, session=None, content_type=""):
    binding = resource["request_binding"]
    location, selector = binding["location"], binding["selector"]
    candidates = []
    if location == "path":
        candidates = [params.get(selector)]
    elif location == "query":
        candidates = parse_qs(urlsplit(url).query, keep_blank_values=True).get(selector, [])
        if len(candidates) > 1:
            raise EngineError("resource_ambiguous", "A query resource selector must occur exactly once, including when repeated values are equal")
    else:
        candidates = _body_candidates(body, selector, content_type)
    expected = resource["external_id"]
    if any(candidate is not None and _same_binding_value(candidate, expected) for candidate in candidates):
        return
    actual = candidates[0] if candidates else None
    actual_text = str(actual)
    expected_text = str(expected)
    raise EngineError("resource_mismatch",
                      "Request is not bound to the declared test resource: expected "
                      + repr(expected_text[:120]) + " at " + location + " " + repr(selector)
                      + ", got " + repr(actual_text[:120])
                      + ". Use a JSON Pointer (/0/field) for JSON arrays, the form field name for multipart, "
                        "or create a resource whose external_id matches the value this request actually sends.")


def _read_body_file(project, value):
    if not isinstance(value, str) or not value:
        raise EngineError("body_file", "body_file must name a bounded local file")
    path = Path(value)
    path = contained(path, Path(path.anchor)) if path.is_absolute() else contained(project.base / path, project.base)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        with os.fdopen(os.open(path, flags), "rb", buffering=0) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                raise EngineError("body_file", "body_file must be a regular local file no larger than 1 MiB")
            data = bytearray()
            while len(data) <= 1024 * 1024:
                chunk = stream.read(1024 * 1024 + 1 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > 1024 * 1024:
                raise EngineError("body_budget", "Request body exceeds budget")
            return bytes(data)
    except OSError as exc:
        raise EngineError("body_file", "body_file is not an available regular local file") from exc


def preflight_capture(project, args, *, for_identity=False):
    """Resolve and validate the exact capture request without claiming or sending it."""
    if not isinstance(args, dict):
        raise EngineError("arguments", "Capture arguments must be an object")
    operation = project.get("operation",args["operation_id"])
    _validate_operation_inputs(operation)
    url = require_scope(project.config,args.get("url") or operation["url"])
    params = bind_operation(operation,url,operation["method"])
    if "{" in url or "}" in url:
        raise EngineError("unbound_url", "Resolve path variables using an actual test resource")
    session = project.get("session",args["session_id"]) if args.get("session_id") else None
    actor = None
    if session:
        if for_identity:
            if stamp(session["expires_at"]) <= datetime.now(timezone.utc):
                raise EngineError("session_expired",
                                  "Renew the session with identity.session renew:true, or create a new one and re-run identity.verify")
            actor = project.get("actor", session["actor_id"])
        else:
            actor = session_valid(project,session)
        require_session_origin(project, session, url)
    extra = headers_map(args.get("headers",{}))
    # Some state is bound to an anonymous cookie jar rather than an identity
    # (captcha, CSRF token, cart, SMS verification session). Refusing every Cookie
    # header pushed those flows into ad-hoc curl and broke the evidence chain. An
    # anonymous_cookie is accepted only without a registered session, and is
    # stamped on the evidence so its meaning is not confused with an identity.
    anonymous_cookie = args.get("anonymous_cookie")
    if anonymous_cookie is not None:
        if not isinstance(anonymous_cookie, str) or not anonymous_cookie.strip() \
                or len(anonymous_cookie) > 8192 or "\n" in anonymous_cookie or "\r" in anonymous_cookie:
            raise EngineError("anonymous_cookie", "anonymous_cookie must be a single-line Cookie header value")
        if session:
            raise EngineError("credential_override",
                              "A capture cannot mix a registered session with an anonymous cookie jar; "
                              "register that state as its own session instead")
        if "cookie" in extra:
            raise EngineError("credential_override", "Supply either anonymous_cookie or a Cookie header, not both")
        if operation["auth"] != "public":
            raise EngineError("anonymous_cookie",
                              "anonymous_cookie is for public state-bound flows; register a verified session for authenticated operations")
        extra["cookie"] = anonymous_cookie.strip()
    forbidden_credentials = {"cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token", "x-session-token"}
    # Project-known custom authentication must not be labelled anonymous merely
    # because it arrived through the per-request business-header object.
    for stored_session in project.list("session"):
        forbidden_credentials.update(credential_header_names(stored_session))
    if anonymous_cookie:
        forbidden_credentials.remove("cookie")
    if forbidden_credentials.intersection(extra):
        raise EngineError("credential_override", "Authentication headers belong to a registered session; do not override the verified session")
    if session and any(key in session["headers"] and value != session["headers"][key] for key,value in extra.items()):
        raise EngineError("credential_override", "Request headers cannot replace headers bound to the verified session")
    headers = {**(session["headers"] if session else {}),**extra}
    body = args.get("body")
    body_sources = sum(args.get(key) is not None for key in ("body", "body_base64", "body_file"))
    if body_sources > 1:
        raise EngineError("body", "Supply only one of body, body_base64 or body_file")
    if args.get("body_file") is not None:
        body = _read_body_file(project, args["body_file"])
    if args.get("body_base64") is not None:
        # Raw-bytes bodies (multipart/form-data, XML, protobuf) cannot survive a
        # JSON string round-trip, so accept them as base64 and decode to bytes.
        encoded = args["body_base64"]
        if not isinstance(encoded, str):
            raise EngineError("body", "body_base64 must be a base64 string")
        if len(encoded) > 4 * ((1024 * 1024 + 2) // 3):
            raise EngineError("body_budget", "Request body exceeds budget")
        try:
            body = base64.b64decode(encoded, validate=True)
        except Exception:
            raise EngineError("body", "body_base64 is not valid base64") from None
        if len(body) > 1024*1024:
            raise EngineError("body_budget", "Request body exceeds budget")
    if isinstance(body, (dict, list)):
        try:
            encoded_body = json.dumps(body, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise EngineError("body", "Request JSON must contain only finite JSON-compatible values") from exc
        headers.setdefault("content-type", "application/json")
    elif body is None:
        encoded_body = b""
    elif isinstance(body, bytes):
        encoded_body = body
    elif isinstance(body, str):
        encoded_body = body.encode("utf-8")
    else:
        raise EngineError("body", "Body must be JSON, text, bytes or null")
    if len(encoded_body) > 1024 * 1024:
        raise EngineError("body_budget", "Request body exceeds budget")
    if operation["content_type"]:
        if "content-type" in headers and headers["content-type"].split(";",1)[0].lower() != operation["content_type"].split(";",1)[0]:
            raise EngineError("media_binding", "Request content type does not match operation")
        headers.setdefault("content-type",operation["content_type"])
    if (headers.get("content-type") or "").split(";", 1)[0].strip().lower() == "multipart/form-data":
        _multipart_parts(encoded_body, headers["content-type"])
    if operation["protocol"] == "graphql":
        try:
            doc = json.loads(body) if isinstance(body, (str, bytes)) else body
        except (ValueError, UnicodeError) as exc:
            raise EngineError("graphql_binding", "GraphQL request requires a JSON document") from exc
        if not isinstance(doc,dict) or doc.get("operationName") != operation["operation_name"]:
            raise EngineError("graphql_binding", "GraphQL operationName must match the registered operation")
    resource = project.get("resource",args["resource_id"]) if args.get("resource_id") else None
    if resource:
        if resource["operation_id"] != operation["id"]:
            raise EngineError("resource_mismatch", "Resource belongs to another operation")
        _resource_binding(resource, params, url, body, session=session,
                          content_type=headers.get("content-type") or operation.get("content_type", ""))
    if operation["method"] not in {"GET","HEAD","OPTIONS"}:
        if not project.config.get("allow_mutation") or args.get("effect") != "test_resource_write":
            raise EngineError("operation_effect",
                              "Mutating requests require project permission (project.update allow_mutation:true) "
                              "and effect:test_resource_write")
        if not resource and not _actor_bound_write(operation, session, url=url, body=body, headers=headers):
            raise EngineError("operation_effect",
                              "Mutating requests require a bound test resource. Only a concrete, query-free and "
                              "body-free state_scope:actor request with no declared or actual business headers/cookies may use its verified session instead; "
                              "register identity.resource and pass resource_id for business inputs.")
    timeout, max_bytes = args.get("timeout", 15), args.get("max_bytes", 1024 * 1024)
    if type(timeout) not in (int, float) or not 0 < timeout <= 60 \
            or type(max_bytes) is not int or not 1 <= max_bytes <= 4 * 1024 * 1024:
        raise EngineError("budget", "HTTP timeout must be greater than zero and no more than 60 seconds; max_bytes must be 1..4194304")
    headers = headers_map(headers)
    if any(key in headers for key in ("host", "content-length", "transfer-encoding", "connection")):
        raise EngineError("headers", "Transport framing headers are managed by the executor")
    run_id = stable("RUN", args["idempotency_key"]) if args.get("idempotency_key") else None
    existing = project.get("run", run_id, required=False) if run_id else None
    # Raw bytes are not JSON-serializable; sign their base64 form so the
    # signature stays stable across retries without decoding the payload.
    signed_body = base64.b64encode(body).decode() if isinstance(body,(bytes,bytearray)) else body
    signature = stable("REQ",[operation_signature(operation),url,signed_body,headers,args.get("resource_id"),
                              session["id"] if session else None,session["generation"] if session else None,
                              actor_signature(actor) if actor else None,
                              resource_signature(resource) if resource else None,
                              credential_signature(session) if session else None])
    if existing:
        if existing.get("request_signature") != signature:
            raise EngineError("idempotency_conflict", "Idempotency key already belongs to another request",
                              {"run_id": run_id, "operation_id": existing.get("operation_id"), "next_action": "run.inspect"})
        if existing["status"] == "succeeded":
            verify_current_evidence(project, existing["evidence_id"])
        else:
            raise EngineError("run_uncertain", "Prior request is incomplete or failed; reconcile its resource state before retrying",
                              {"run_id": run_id, "operation_id": existing.get("operation_id"), "next_action": "run.inspect"})
    return {"operation": operation, "url": url, "params": params, "session": session,
            "actor": actor, "headers": headers, "body": body, "body_bytes": len(encoded_body),
            "resource": resource, "request_signature": signature, "run_id": run_id, "existing": existing,
            "timeout": timeout, "max_bytes": max_bytes,
            "auth_mode": "anonymous_cookie" if anonymous_cookie else ("session" if session else "none")}


def capture(project,args, *, for_identity=False):
    prepared = preflight_capture(project, args, for_identity=for_identity)
    if prepared["existing"]:
        return project.get("evidence", prepared["existing"]["evidence_id"])
    operation, url, session, actor, resource = (prepared[key] for key in ("operation", "url", "session", "actor", "resource"))
    headers, body = prepared["headers"], prepared["body"]
    run_id = prepared["run_id"] or project.id("RUN")
    signature = prepared["request_signature"]
    run = {"id":run_id,"kind":"http","status":"running","started_at":now(),"request_signature":signature,
           "operation_id":operation["id"],"method":operation["method"],"operation_signature":operation_signature(operation),
           "session_id":session["id"] if session else None,"session_generation":session["generation"] if session else None,
           "actor_id":actor["id"] if actor else None,"actor_signature":actor_signature(actor) if actor else None,
           "resource_id":resource["id"] if resource else None,"resource_signature":resource_signature(resource) if resource else None,
           "effect":"read_only" if operation["method"] in {"GET","HEAD","OPTIONS"} else "test_resource_write"}
    project.claim(run)
    try:
        artifact = request(url,operation["method"],headers,body,prepared["timeout"],prepared["max_bytes"])
        identity = project.id("E")
        path,digest = project.artifact(identity,artifact)
        from .lineage import policy_snapshot, policy_digest
        evidence = {"id":identity,"kind":"http","operation_id":operation["id"],"operation_signature":operation_signature(operation),
            "policy_digest":policy_digest(operation),"policy_snapshot":policy_snapshot(operation),
            "session_id":session["id"] if session else None,"session_generation":session["generation"] if session else None,
            "actor_id":session["actor_id"] if session else None,"resource_id":resource["id"] if resource else None,
            "actor_signature":actor_signature(actor) if actor else None,
            "resource_signature":resource_signature(resource) if resource else None,
            "credential_header_names":credential_header_names(session) if session else [],
            "credential_signature":credential_signature(session) if session else None,
            "artifact_path":path,"sha256":digest,"complete":artifact["complete"],"created_at":now(),"trust":"observed",
            "run_id":run_id,"status_code":artifact["response"]["status"],"response_bytes":artifact["response"]["length"],
            "auth_mode": prepared["auth_mode"]}
        run.update(status="succeeded" if evidence["complete"] else "failed",evidence_id=identity,finished_at=now())
        if not evidence["complete"]:
            run.update(error_code=artifact.get("error", "evidence_incomplete"), next_action="run.inspect")
            evidence.update(error_code=run["error_code"], next_action=run["next_action"])
        with project.transaction():
            project.put("evidence",evidence,create_only=True)
            project.put("run",run)
            project.event("http.captured", {"run_id":run_id,"evidence_id":identity,"complete":evidence["complete"]})
        return evidence
    except Exception as exc:
        code = exc.code if isinstance(exc, EngineError) else "capture_failed"
        run.update(status="failed",finished_at=now(),error="capture_failed", error_code=code, next_action="run.inspect")
        message = str(exc) if isinstance(exc, EngineError) else "Capture failed after the run was claimed; inspect its checkpoint before attempting another request"
        try:
            project.put("run",run)
        except Exception:
            message += "; the final checkpoint could not be saved, so the claimed run must be reconciled"
        raise EngineError(code, message, {"run_id": run_id, "operation_id": operation["id"], "next_action": "run.inspect"}) from exc


def verify_identity(project,args):
    session = project.get("session",args["session_id"])
    actor = project.get("actor",session["actor_id"])
    assertion = {k:args.get(k) for k in ("subject_selector","tenant_selector","roles_selector")}
    if not assertion["subject_selector"]:
        raise EngineError("identity_assertion", "A server-side subject JSON Pointer is required")
    _identity_selector_boundary(assertion)
    evidence = capture(project,args,for_identity=True)
    artifact = project.read_artifact(evidence)
    if not evidence["complete"] or artifact["response"]["status"] != 200:
        raise EngineError("identity_response", "Identity check requires a complete successful response")
    profile = response_json(artifact)
    if actor["roles"] and not assertion.get("roles_selector"):
        assertion["roles_selector"] = next((candidate for candidate in ("/roles", "/role", "/authorities",
                                                                        "/data/roles", "/data/role", "/user/roles")
                                            if _pointer_exists(profile, candidate)), None)
    _assert_identity(actor,profile,assertion)
    with project.transaction():
        current = project.get("session",session["id"])
        if current["generation"] != session["generation"]:
            raise EngineError("session_changed", "Session changed while identity verification was running")
        if actor_signature(project.get("actor", actor["id"])) != actor_signature(actor):
            raise EngineError("actor_changed", "Actor security properties changed while identity verification was running; retry verification")
        session.update(verified_at=now(),verification_evidence_id=evidence["id"],verification_assertion=assertion,
                       actor_signature=actor_signature(actor))
        project.put("session",session)
    return {"session":public_session(session),"evidence_id":evidence["id"],
            "identity_assertion_limitation": "Distinct selectors verify declared values, not arbitrary field semantics. Use an authorized self-profile endpoint and actual subject-bound role and tenant membership; another account's fields are not identity proof."}


def _path_shape(url):
    """Normalise a URL to its routable shape: host + path with ids collapsed.

    /api/merchant/products/{productNo} and /api/merchant/products/SP1 are the same
    shape. A path probed only with GET must still advertise its DELETE/PUT/PATCH
    siblings; otherwise a clean GET can hide a destructive verb.
    """
    parts = urlsplit(str(url))
    path = re.sub(r"\{[^}]+\}", "{}", parts.path)
    placeholder = re.compile(r"^(?:\d+|(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{4,})$")
    segments = [seg if (seg in {"{}", ""} or not placeholder.match(seg)) else "{}"
                for seg in path.split("/")]
    return (parts.scheme, parts.netloc.lower(), "/".join(segments).rstrip("/") or "/")


_SIBLING_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def _may_own(operation, actor):
    if operation.get("auth") == "authenticated":
        return True
    roles = set(actor.get("roles") or [])
    if not roles or roles == {"anonymous"}:
        return False
    if operation.get("auth") == "restricted":
        return bool(roles & set(operation.get("allowed_roles") or []))
    return True


def _role_key(actor):
    return tuple(sorted(actor.get("roles") or []))


def _tenant_boundary(owner, actor):
    left, right = owner.get("tenant_id"), actor.get("tenant_id")
    if not left or not right:
        return "unknown_tenant"
    return "same_tenant" if left == right else "cross_tenant"


def _ownership_samples(operation, actors, resources, previous):
    actors_by_id = {actor["id"]: actor for actor in actors}
    groups = {}
    for resource in resources:
        owner = actors_by_id.get(resource.get("owner_actor_id"))
        if owner is None or (operation["auth"] == "restricted" and not _may_own(operation, owner)):
            continue
        key = (owner.get("tenant_id") or "", _role_key(owner), canonical(resource.get("request_binding") or {}))
        groups.setdefault(key, []).append(resource)
    preferred = {item.get("resource_id") for item in previous
                 if item.get("kind") == "ownership" and not item.get("superseded")}
    ordered_groups = sorted(groups.items(), key=lambda pair: (not any(
        resource["id"] in preferred for resource in pair[1]), pair[0]))
    cases, variant_total, selected_fixtures = [], 0, []
    for context, fixtures in ordered_groups[:MAX_OWNERSHIP_CONTEXTS]:
        ordered = sorted(fixtures, key=lambda item: (item.get("created_at") or "", item["id"]))
        representative = next((item for item in ordered if item["id"] in preferred), ordered[0])
        selected_fixtures.append(representative["id"])
        owner = actors_by_id[representative["owner_actor_id"]]
        variants = {}
        for actor in actors:
            if actor["id"] == owner["id"] or not _may_own(operation, actor) or (
                    actor["subject"], actor.get("tenant_id", "")) == (owner["subject"], owner.get("tenant_id", "")):
                continue
            boundary = _tenant_boundary(owner, actor)
            key = (_role_key(actor), boundary, actor.get("tenant_id") or "")
            variants.setdefault(key, []).append(actor)
        variant_total += len(variants)
        # Each boundary gets a turn before another role/tenant at that boundary.
        lanes = {boundary: [] for boundary in ("same_tenant", "cross_tenant", "unknown_tenant")}
        for key in sorted(variants):
            lanes[key[1]].append((key, variants[key]))
        balanced = []
        while any(lanes.values()):
            for lane in lanes.values():
                if lane:
                    balanced.append(lane.pop(0))
        old_variants = {item.get("actor_id") for item in previous if not item.get("superseded")
                        and item.get("resource_id") == representative["id"] and item.get("kind") == "ownership"}
        for variant_context, members in balanced[:MAX_OWNERSHIP_VARIANTS]:
            members = sorted(members, key=lambda actor: (actor.get("created_at") or "", actor["id"]))
            actor = next((member for member in members if member["id"] in old_variants), members[0])
            cases.append({"kind": "ownership", "actor_id": actor["id"], "baseline_actor_id": owner["id"],
                          "resource_id": representative["id"], "tenant_boundary": variant_context[1],
                          "owner_context": stable("OC", context), "variant_context": stable("VC", variant_context)})
    sampled_contexts = min(len(groups), MAX_OWNERSHIP_CONTEXTS)
    summary = {"strategy": "tenant_role_request_binding", "representative_sampling": True,
               "contexts_total": len(groups), "contexts_sampled": sampled_contexts,
               "fixtures_total": sum(len(items) for items in groups.values()), "fixtures_sampled": len(selected_fixtures),
               "variant_contexts_total": variant_total, "variant_contexts_sampled": len(cases),
               "omitted_contexts": len(groups) - sampled_contexts,
               "omitted_variant_contexts": variant_total - len(cases),
               "limited": len(groups) > MAX_OWNERSHIP_CONTEXTS or variant_total > len(cases),
               "limits": {"owner_contexts": MAX_OWNERSHIP_CONTEXTS, "variants_per_owner_context": MAX_OWNERSHIP_VARIANTS},
               "limitations_zh": ["每个所有者租户、角色和请求绑定上下文仅选择代表资源，不代表全部资源或业务状态。",
                                  "攻击者按角色、租户及同租户/跨租户/未知租户边界分组；未知租户不视为同租户。",
                                  "超出有界样本预算的上下文保留为覆盖盲区，不自动标记为已测或不适用。"]}
    return cases, summary


def _case_identity(case):
    # Sampling annotations do not invalidate an existing experiment's identity.
    return stable("OB", {key: value for key, value in case.items()
                         if key not in {"tenant_boundary", "owner_context", "variant_context", "scope_family", "consumer_family"}})


@atomic
def build_plan(project):
    added = 0
    actors = project.list("actor")
    resources = project.list("resource")
    owned_by_operation = {}
    obligations_by_operation = {}
    for obligation in project.list("obligation"):
        obligations_by_operation.setdefault(obligation["operation_id"], []).append(obligation)
    for resource in resources:
        owned_by_operation.setdefault(resource["operation_id"], []).append(resource)
    for operation in project.list("operation"):
        _validate_operation_inputs(operation)
        cases = []
        if operation["auth"] == "unknown":
            cases.append({"kind":"auth_review"})
        if operation["auth"] == "public":
            cases.append({"kind":"baseline","actor_id":None})
        else:
            cases.append({"kind":"access","actor_id":None})
            allowed = []
            for actor in actors:
                permitted = operation["auth"] == "authenticated" or (operation["auth"] == "restricted" and bool(set(actor["roles"]) & set(operation["allowed_roles"])))
                cases.append({"kind":"baseline" if permitted else "access","actor_id":actor["id"]})
                if permitted:
                    allowed.append(actor)
            if operation["auth"] != "unknown" and not allowed:
                cases.append({"kind":"identity_setup"})
        for entry in operation["inputs"]:
            case = {"kind":"input_review" if str(entry.get("consumer") or "unknown").strip().lower() in {"unknown","other",""} else "input_test",
                    "input_selector":entry["selector"],"input_location":entry["location"],"schema_branch":entry.get("schema_branch"),
                    "input_signature":stable("I",entry)}
            if case["kind"] == "input_test" and "test_families" in entry:
                for family in normalize_test_families(entry["test_families"]):
                    cases.append({**case, "test_family": family})
            else:
                cases.append(case)
        if operation["ownership"]:
            ownership_cases, sampling = _ownership_samples(operation, actors,
                owned_by_operation.get(operation["id"], []), obligations_by_operation.get(operation["id"], []))
            if operation.get("ownership_sampling") != sampling:
                operation["ownership_sampling"] = sampling
                project.put("operation", operation)
            if not ownership_cases:
                cases.append({"kind":"ownership_setup"})
            else:
                cases.extend(ownership_cases)
        expected = set()
        for case in cases:
            case["operation_id"] = operation["id"]
            if case["kind"] == "input_test":
                from .completeness import obligation_family
                consumer_case = {key: value for key, value in case.items() if key != "test_family"}
                case["consumer_family"] = obligation_family(consumer_case, operation)
                case["scope_family"] = obligation_family(case, operation)
            identity = _case_identity(case)
            expected.add(identity)
            current = project.get("obligation",identity,required=False)
            if not current:
                project.put("obligation",{"id":identity,**case,"status":"open","created_at":now()},create_only=True)
                added += 1
            else:
                changed = False
                if current.get("superseded"):
                    current["superseded"] = False
                    current.pop("superseded_at", None)
                    changed = True
                if case["kind"] == "input_test" and current.get("input_signature") == case["input_signature"]:
                    for field in ("scope_family", "consumer_family"):
                        if field not in current:
                            current[field] = case[field]
                            changed = True
                if any(current.get(key) != case.get(key) for key in ("tenant_boundary", "owner_context", "variant_context")):
                    current.update({key: case[key] for key in ("tenant_boundary", "owner_context", "variant_context") if key in case})
                    changed = True
                if changed:
                    project.put("obligation", current)
        # Superseded planning obligations remain auditable, never count as tested.
        for old in obligations_by_operation.get(operation["id"], []):
            if old["id"] not in expected and not old.get("superseded"):
                old["superseded"] = True
                old["superseded_at"] = now()
                project.put("obligation",old)
    project.event("plan.generated",{"added":added})
    return {"added":added,**evaluate_coverage(project)}


def _decision_valid(project, decision):
    if decision["outcome"] == "inconclusive":
        raise EngineError("inconclusive", "Experiment did not establish a result")
    for eid in decision["evidence_ids"]:
        verify_current_evidence(project,eid)
    if decision.get("obligation_id"):
        item = project.get("obligation",decision["obligation_id"])
        if item.get("superseded"):
            raise EngineError("superseded", "Input or applicability changed after this decision")
    from .assessment import validate_confirmation
    validate_confirmation(project, decision)


# gap 的 reason_code 是稳定枚举：next / 门禁 / 报告消费同一份投影，不允许各自
# 派生一套“为什么没完成”的解释。每个 code 绑定一个可执行的 next_action。
GAP_REASONS = {
    "evidence_invalid": {"next_action": "repair_evidence",
        "message": "The supporting decision or its evidence is no longer valid; recapture or re-evaluate."},
    "decision_missing": {"next_action": "repair_evidence",
        "message": "The obligation is marked evaluated but carries no decision record."},
    "obligation_superseded": {"next_action": "replan",
        "message": "The operation or input changed after this obligation was planned."},
    "exclusion_evidence_invalid": {"next_action": "repair_evidence",
        "message": "A not_applicable disposition lost its business-fact evidence and reverted to open."},
    "not_started": {"next_action": "execute",
        "message": "No experiment has been recorded for this obligation yet."},
    "blocked_precondition": {"next_action": "resolve_precondition",
        "message": "A declared precondition (identity, resource or capability) is unavailable."},
}

# obligation.kind → 该 gap 在下一步该被当作什么。identity_setup / ownership_setup
# 是“先补前提”的任务，不是可直接执行的实验。
#
# 注意：kind 只在“尚未开始时”决定下一步。已求值但证据失效的 gap 必须仍然指向
# repair_evidence —— 覆盖 kind 会把修复动作藏起来，正是“门禁不通过但没人告诉我
# 怎么修”的断层。因此 _gap_view 只对 not_started 应用此表。
GAP_ACTIONS = {
    "identity_setup": "create_identity",
    "ownership_setup": "create_test_resource",
    "auth_review": "declare_access_policy",
    "input_review": "trace_consumer",
}


@atomic
def declare_consumer(project, args):
    """Bind a named consumer to a registered input, upgrading input_review to input_test.

    Without this, an input whose consumer is unknown only ever yields `input_review`
    (next_action: trace_consumer) and there is no action that satisfies it — observed
    directly when ~200 SQLi extraction requests could not be attached to any obligation.
    Declaring the consumer re-plans; the stale input_review is superseded automatically.
    """
    operation = project.get("operation", args["operation_id"])
    _validate_operation_inputs(operation)
    location = args["input_location"]
    selector = args["input_selector"]
    selected = {"name": "selected input", "location": location, "selector": selector}
    if "schema_branch" in args:
        selected["schema_branch"] = args["schema_branch"]
    _validate_input_identity(selected, operation["id"])
    if not isinstance(args["consumer"], str) or not args["consumer"].strip():
        raise EngineError("consumer", "consumer must be a nonempty concrete sink string")
    consumer = args["consumer"].strip()
    if consumer.lower() in {"unknown", "other"}:
        raise EngineError("consumer", "Declare a concrete consumer name, not a placeholder")
    families = normalize_test_families(args["test_families"]) if "test_families" in args else None
    inputs = list(operation.get("inputs") or [])
    matches = [entry for entry in inputs if entry.get("location") == location and entry.get("selector") == selector
               and ("schema_branch" not in args or entry.get("schema_branch") == args["schema_branch"])]
    if not matches:
        raise EngineError("input", "No registered input matches that location and selector")
    if len(matches) != 1:
        raise EngineError("input_ambiguous", "Select an exact schema_branch when multiple inputs share a selector; use null for the unbranched input",
                          {"operation_id": operation["id"], "next_action": "surface.inspect",
                           "help_action": "action.help", "help_input": {"name": "surface.declare_consumer"}})
    updated = matches[0]
    updated["consumer"] = consumer
    if families is not None:
        updated["test_families"] = families
    project.put("operation", operation)
    project.event("surface.consumer_declared",
                  {"operation_id": operation["id"], "input_selector": selector, "consumer": consumer,
                   **({"test_families": families} if families is not None else {})})
    plan = build_plan(project)
    return {"operation_id": operation["id"], "input": updated, "plan": {"added": plan.get("added")}}


def _gap_id(item):
    """对 obligation 身份做稳定投影：同一条义务在任何视图里得到同一 gap_id。"""
    return "G-" + hashlib.sha256(canonical({"obligation": item["id"]}).encode()).hexdigest()[:24]


def _gap_view(item, status, reason_code):
    """单一投影：状态、稳定 ID、结构化原因和可执行下一步同时给出。

    结构化 reason_code 供机器编排；operator_reason 保留人工填写的原始说明，
    两者都出现，避免把“为什么被阻塞”降级成一句通用文案而丢失现场信息。
    """
    reason = GAP_REASONS.get(reason_code, GAP_REASONS["not_started"])
    kind = item.get("kind")
    # 计算得出的原因码优先；仅在状态未被求值器改写时透传操作者填写的说明。
    raw_reason = item.get("reason")
    operator_reason = raw_reason.strip() if isinstance(raw_reason, str) else ""
    view = {**{k: v for k, v in item.items() if k not in {"evidence_ids"}},
            "gap_id": _gap_id(item),
            "status": status,
            "reason_code": reason_code,
            "reason": reason["message"],
            "next_action": (GAP_ACTIONS.get(kind, reason["next_action"])
                            if reason_code == "not_started" else reason["next_action"]),
            "obligation_kind": kind}
    if operator_reason and operator_reason != reason["message"]:
        view["operator_reason"] = operator_reason
    if "reason" in item and not isinstance(raw_reason, str):
        view["operator_reason_invalid_type"] = True
    return view


def _tested_surfaces(obligations, status_by_id=None):
    evaluated = [item for item in obligations
                 if not item.get("superseded")
                 and (status_by_id or {}).get(item["id"], item.get("status")) == "evaluated"]
    operation_ids = {item["operation_id"] for item in evaluated}
    inputs = {(item["operation_id"], item.get("input_location"), item.get("input_selector"), item.get("schema_branch"))
              for item in evaluated if item.get("kind") == "input_test"}
    return operation_ids, inputs


def _method_coverage(project, tested_operation_ids=None, *, current_observations=None):
    """Keep registration, complete observations and evaluated tests distinct."""
    if tested_operation_ids is None:
        tested_operation_ids = set()
        for item in project.list("obligation"):
            if item.get("superseded") or item.get("status") != "evaluated" or not item.get("decision_id"):
                continue
            try:
                _decision_valid(project, project.get("decision", item["decision_id"]))
                tested_operation_ids.add(item["operation_id"])
            except (EngineError, OSError, ValueError, KeyError):
                pass
    observed_operation_ids = set()
    if current_observations is not None:
        observed_operation_ids.update(evidence["operation_id"] for evidence in current_observations)
    else:
        for evidence in project.list("evidence"):
            try:
                verify_current_evidence(project, evidence["id"])
                observed_operation_ids.add(evidence["operation_id"])
            except (EngineError, OSError, ValueError, KeyError):
                pass
    matrix = {}
    for operation in project.list("operation"):
        shape = _path_shape(operation["url"])
        key = (shape, operation.get("auth"))
        bucket = matrix.setdefault(key, {"path_shape": list(shape), "auth": operation.get("auth"),
                                         "registered": set(), "observed": set(), "tested": set(), "operations": set()})
        method = operation["method"].upper()
        bucket["registered"].add(method)
        if operation["id"] in observed_operation_ids:
            bucket["observed"].add(method)
        if operation["id"] in tested_operation_ids:
            bucket["tested"].add(method)
        bucket["operations"].add(operation["id"])
    rows = []
    for (shape, auth), bucket in sorted(matrix.items(), key=lambda kv: str(kv[0])):
        tested = bucket["tested"]
        rows.append({"path_shape": bucket["path_shape"], "auth": auth, "tested": sorted(tested),
                     "registered_methods": sorted(bucket["registered"]),
                     "observed_methods": sorted(bucket["observed"]),
                     "untested_registered_methods": sorted(bucket["registered"] - tested),
                     "untested_siblings": [m for m in _SIBLING_METHODS if m not in bucket["registered"]],
                     "operations": sorted(bucket["operations"]),
                     "note": "tested requires a current evaluated obligation; observed only records complete current captures. "
                             "untested_siblings are unregistered method candidates, not proven endpoints."})
    return rows


def _coverage_metrics(project, obligations, status_by_id=None):
    """Break the raw obligation ratio down so the denominator stays readable."""
    by_kind = {}
    for item in obligations:
        if item.get("superseded"):
            continue
        bucket = by_kind.setdefault(item.get("kind", "unknown"),
                                     {"total": 0, "evaluated": 0, "open": 0, "blocked": 0, "not_applicable": 0})
        bucket["total"] += 1
        status = (status_by_id or {}).get(item["id"], item.get("status", "open"))
        bucket[status] = bucket.get(status, 0) + 1
    for bucket in by_kind.values():
        count = bucket["total"] - bucket["not_applicable"]
        bucket["ratio"] = bucket["evaluated"] / count if count else None
    operations = project.list("operation")
    operation_ids, tested_inputs = _tested_surfaces(obligations, status_by_id)
    input_total = sum(len(operation.get("inputs") or []) for operation in operations)
    surface_numerator = len(operation_ids) + len(tested_inputs)
    surface_denominator = len(operations) + input_total
    return {
        "coverage_by_kind": dict(sorted(by_kind.items())),
        "surface_coverage": {
            "operations_total": len(operations),
            "operations_tested": len(operation_ids),
            "inputs_total": input_total,
            "inputs_tested": len(tested_inputs),
            "ratio": surface_numerator / surface_denominator if surface_denominator else None,
            "note": "Operation/input coverage is intentionally separate from obligation-weighted coverage; "
                    "one operation can create many role/resource obligations.",
        },
    }


def evaluate_coverage(project):
    for operation in project.list("operation"):
        _validate_operation_inputs(operation)
    gaps, totals = [], {"total":0,"evaluated":0,"open":0,"blocked":0,"not_applicable":0}
    dependent = {}
    status_by_id = {}
    all_obligations = project.list("obligation")
    for item in all_obligations:
        if item.get("superseded"):
            continue
        status, reason_code = item["status"], "not_started"
        if status == "evaluated":
            try:
                if not item.get("decision_id"):
                    raise EngineError("decision_missing", "Missing decision")
                _decision_valid(project,project.get("decision",item["decision_id"]))
            except (EngineError, OSError, ValueError, KeyError) as exc:
                status = "open"
                reason_code = ("decision_missing" if getattr(exc,"code","")=="decision_missing"
                               else "obligation_superseded" if getattr(exc,"code","")=="superseded"
                               else "evidence_invalid")
        elif status == "not_applicable":
            try:
                for eid in item.get("evidence_ids",[]):
                    verify_current_evidence(project,eid)
                if not item.get("evidence_ids") or item.get("basis") != "business_fact":
                    raise EngineError("basis_missing", "N/A requires evidence and a business fact")
            except (EngineError,OSError,ValueError):
                status, reason_code = "open","exclusion_evidence_invalid"
        elif status == "blocked":
            reason_code = "blocked_precondition"
        status_by_id[item["id"]] = status
        totals["total"]+=1
        totals[status]+=1
        if status not in {"evaluated","not_applicable"}:
            gap = _gap_view(item, status, reason_code)
            gaps.append(gap)
            dependent.setdefault(gap["next_action"], 0)
            dependent[gap["next_action"]] += 1
    gaps.sort(key=lambda gap: (gap["operation_id"], gap["obligation_kind"], gap["gap_id"]))
    findings = []
    for finding in project.list("finding"):
        row = dict(finding)
        try:
            decision = project.get("decision",finding["decision_id"])
            _decision_valid(project,decision)
            from .assessment import validate_confirmation
            validate_confirmation(project, decision, finding.get("category"))
            row["evidence_current"] = True
        except (EngineError,OSError,ValueError,KeyError) as exc:
            row["evidence_current"] = False
            row["reason_code"] = getattr(exc, "code", "evidence_invalid")
            row["evidence_reason_code"] = row["reason_code"]
            row["limitation"] = ("Supporting decision/evidence is no longer valid or its proof channel is missing; "
                                 "original finding preserved. Inspect reason_code and re-record only with real evidence.")
        lifecycle = row.get("lifecycle_status", "active")
        row["current"] = row["evidence_current"] and lifecycle == "active"
        if lifecycle in {"withdrawn", "superseded"}:
            row["reason_code"] = "finding_" + lifecycle
            row["limitation"] = "Finding was explicitly " + lifecycle + "; its original evidence and decision remain preserved."
        findings.append(row)
    count = totals["total"]-totals["not_applicable"]
    metrics = _coverage_metrics(project, all_obligations, status_by_id)
    evaluated = {"operations":len(project.list("operation")),"inputs":sum(len(o["inputs"]) for o in project.list("operation")),
        "obligations":totals["total"],**totals,"coverage_ratio":totals["evaluated"]/count if count else None,
        **metrics,
        "gaps":gaps,"gap_dependencies":dict(sorted(dependent.items())),"findings":findings,
        "limitations":["Coverage is limited to registered operations; an empty queue does not prove absence of vulnerabilities.",
            "coverage_ratio is obligation-weighted; surface_coverage is operation/input-weighted and is usually more readable.",
            "Imported or simulated artifacts do not satisfy execution evidence."]}
    from .completeness import summarize
    evaluated.update(summarize(project, evaluated))
    return evaluated


@atomic
def disposition(project,args):
    item = project.get("obligation",args["obligation_id"])
    if item.get("superseded"):
        raise EngineError("obligation_superseded", "Superseded obligations are history, not mutable current work. "
                          "Refresh plan.next and use the actual current obligation_id; restore a removed boundary through its surface declaration.",
                          {"obligation_id": item["id"], "operation_id": item["operation_id"], "field": "obligation_id",
                           "next_action": "plan.next", "help_action": "action.help", "help_input": {"name": "plan.disposition"}})
    status = args["status"]
    reason = args.get("reason")
    if not isinstance(status, str) or status not in {"open","blocked","not_applicable"} \
            or not isinstance(reason, str) or not reason.strip() or len(reason) > 4000:
        raise EngineError("disposition", "Disposition requires open/blocked/not_applicable and a nonempty string reason of at most 4000 characters")
    evidence_ids = args.get("evidence_ids",[])
    if status=="not_applicable":
        if args.get("basis")!="business_fact" or not evidence_ids:
            raise EngineError("exclusion", "N/A requires a business fact and supporting evidence")
        for eid in evidence_ids:
            evidence,_ = verify_current_evidence(project,eid)
            if evidence["operation_id"] != item["operation_id"]:
                raise EngineError("evidence_binding", "Exclusion evidence belongs to another operation")
    previous = {key: item.get(key) for key in ("status", "reason", "basis", "evidence_ids")}
    item.update(status=status,reason=reason,basis=args.get("basis"),evidence_ids=evidence_ids)
    project.put("obligation",item)
    project.event("plan.disposition", {"obligation_id": item["id"], "operation_id": item["operation_id"],
                  "reason_basis": "caller_declaration", "previous": previous,
                  "current": {key: item.get(key) for key in ("status", "reason", "basis", "evidence_ids")}})
    return item


def recover_runs(project,args):
    age = args.get("stale_seconds",300)
    if type(age) is not int or age < 60:
        raise EngineError("recovery_age", "Recovery requires a stale interval of at least 60 seconds")
    recovered=[]
    for run in project.list("run"):
        if run["status"]=="running" and (datetime.now(timezone.utc)-stamp(run["started_at"])).total_seconds()>=age:
            run.update(status="interrupted",finished_at=now(),reason="Execution ended without a terminal checkpoint; reconcile before retrying")
            run.update(error_code="execution_interrupted", next_action="run.inspect")
            project.put("run",run)
            recovered.append(run["id"])
    return {"recovered":recovered,"requests_replayed":0}
