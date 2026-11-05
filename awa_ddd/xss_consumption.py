"""Offline, controlled writer -> JSON readback -> native consumer XSS binding."""
from __future__ import annotations

import base64
import hashlib
from html import unescape
import json
import re

from .engine import (DEFAULT_CREDENTIAL_HEADER_NAMES, _same_binding_value, credential_header_names,
                     operation_signature, resource_signature, stable, stamp, verify_current_evidence)
from .scope import normalize_url, origin
from .store import EngineError
from .transport import headers_map, json_equal, pointer, response_json


_FIELDS = {"type", "normal_read_evidence_id", "attack_read_evidence_id", "normal_runtime_visit_id",
           "content_selector", "resource_selector", "write_success_selector", "write_success_expected"}
_IDENTITY = ("actor_id", "session_id", "session_generation")
_EMPTY_BODY_SHA = hashlib.sha256(b"").hexdigest()
_NAVIGATION_KEYS = {"Enter", "Tab", "Escape", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight",
                    "Home", "End", "PageUp", "PageDown"}


def _text_versions(value):
    """Bounded data decoding for attribution, never evaluation or request rewriting."""
    from urllib.parse import unquote

    current, seen = [value], {value}
    for depth in range(5):
        following = []
        for text in current:
            candidates = [unquote(text), unescape(text), re.sub(r"\\(?:u([a-fA-F0-9]{4})|x([a-fA-F0-9]{2}))",
                lambda match: chr(int(match[1] or match[2], 16)), text)]
            if len(text) >= 16 and re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", text):
                try:
                    candidates.append(base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True).decode("utf-8"))
                except (ValueError, UnicodeError):
                    pass
            for decoded in candidates:
                if decoded not in seen:
                    seen.add(decoded)
                    if len(seen) > 32:
                        raise EngineError("xss_runtime_binding", "Source attribution decoding exceeded its bounded profile")
                    following.append(decoded)
        if not following:
            break
        if depth == 4:
            raise EngineError("xss_runtime_binding", "Deeply encoded attribution inputs remain unsupported; decoded absence is not proof")
        current = following
    return seen


def _request_has_marker(request, marker):
    from urllib.parse import parse_qsl, urlsplit

    body = base64.b64decode(request["body_base64"], validate=True).decode("utf-8", errors="replace")
    values = [request["url"], body, *headers_map(request.get("headers", {})).values(),
              *(value for _, value in parse_qsl(urlsplit(request["url"]).query, keep_blank_values=True))]
    try:
        pending = [json.loads(body)]
    except (ValueError, RecursionError):
        values.extend(value for _, value in parse_qsl(body, keep_blank_values=True))
        pending = []
    while pending:
        value = pending.pop()
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, dict):
            values.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return any(marker in decoded for value in values if isinstance(value, str) for decoded in _text_versions(value))


def specification(value):
    if not isinstance(value, dict) or set(value) != _FIELDS or value.get("type") != "stored_api":
        raise EngineError("xss_runtime_binding", "xss_consumption requires the exact stored_api source/readback/runtime shape")
    for field in _FIELDS - {"type", "write_success_expected"}:
        if not isinstance(value[field], str) or not value[field] or len(value[field]) > 1024:
            raise EngineError("xss_runtime_binding", "xss_consumption requires a bounded " + field)
    for field in ("content_selector", "resource_selector", "write_success_selector"):
        if not value[field].startswith("/"):
            raise EngineError("xss_runtime_binding", field + " must identify one actual JSON field")
    return dict(value)


def _window(raw):
    start, end = raw.get("started_at"), raw.get("completed_at")
    if not isinstance(start, str) or not isinstance(end, str):
        raise EngineError("xss_runtime_binding", "Stored consumption needs original start/completion timestamps for every capture and visit")
    try:
        start, end = stamp(start), stamp(end)
    except (EngineError, TypeError, ValueError):
        raise EngineError("xss_runtime_binding", "Stored consumption timestamps must be valid absolute times") from None
    if start > end:
        raise EngineError("xss_runtime_binding", "A consumption observation cannot finish before it starts")
    return start, end


def _credentials(project, headers):
    names = set(DEFAULT_CREDENTIAL_HEADER_NAMES) | {"proxy-authorization"}
    for session in project.list("session"):
        names.update(credential_header_names(session))
        names.update(headers_map(session.get("headers", {})))
    return {key: value for key, value in headers_map(headers).items() if key in names}


def _action_controls(raw, marker):
    result = []
    for action in raw.get("actions") or []:
        kind = action.get("action", action.get("type"))
        shape = {"type": kind, "selector": action.get("selector"), "ok": action.get("ok")}
        if action.get("ok") is not True:
            raise EngineError("xss_runtime_binding", "Consumer interactions must succeed in both normal and attack observations")
        if kind == "fill":
            raise EngineError("xss_runtime_binding", "Stored source attribution requires consumer observations without fill; captured fill values can be an independent source")
        if kind == "press":
            if action.get("key") not in _NAVIGATION_KEYS:
                raise EngineError("xss_runtime_binding", "Stored consumer proof only supports recorded navigation/confirmation keys; typing and clipboard shortcuts remain unbound")
            shape["key"] = action["key"]
        result.append(shape)
    return result


def _consumer(project, visit_id, consumer_url, readback, marker, *, normal):
    from .browser import _network, _verified_visit

    visit, raw = _verified_visit(project, visit_id, consumer_url)
    identity = {key: readback[0].get(key) for key in _IDENTITY}
    if visit.get("source") != "local_playwright" or visit.get("machine_authenticated") is not True \
            or visit.get("scope_enforced") is not True or any(visit.get(key) != identity[key] for key in _IDENTITY):
        raise EngineError("xss_runtime_identity", "Stored consumption needs native viewer observations bound to the readback actor/session generation")
    if raw.get("write_requests") or raw.get("write_authorized"):
        raise EngineError("xss_runtime_binding", "Stored consumer visits must be read-only; writer effects belong to the captured fixture controls")
    with project._lock:
        events = project.connection.execute("SELECT document FROM events WHERE type='browser.visited'").fetchall()
    if not any((event := json.loads(row[0])).get("visit_id") == visit["id"]
               and event.get("sha256") == visit["sha256"] and event.get("source") == "local_playwright"
               and event.get("started_at") == raw.get("started_at")
               and event.get("completed_at") == raw.get("completed_at") for row in events):
        raise EngineError("xss_runtime_binding", "Consumer timestamps and digest must match the original native observation event")
    window = _window(raw)
    dialogs = [entry for entry in raw.get("dialogs") or []
               if isinstance(entry, dict) and entry.get("message") == marker]
    if normal and dialogs:
        raise EngineError("xss_runtime_binding", "The normal consumer must not execute the attack marker")
    if not normal:
        if not dialogs or any(entry.get("document_url") != consumer_url for entry in dialogs):
            raise EngineError("xss_runtime_binding", "The matching dialog needs the original actual consumer document URL")
        actions = raw.get("actions") or []
        if any(entry.get("action_index") is not None and (
                type(entry["action_index"]) is not int or not 0 <= entry["action_index"] < len(actions)
                or actions[entry["action_index"]].get("ok") is not True) for entry in dialogs):
            raise EngineError("xss_runtime_binding", "The dialog must belong to a successful consumer interaction")
    request = readback[1]["request"]
    response = readback[1]["response"]
    response_bytes = base64.b64decode(response["body_base64"], validate=True)
    expected_digest = hashlib.sha256(response_bytes).hexdigest()
    expected_credentials = _credentials(project, request.get("headers", {}))
    if not identity["session_id"] and expected_credentials:
        raise EngineError("xss_runtime_identity", "Credential-bearing readbacks require a verified viewer session")
    documents, reads = [], []
    for entry in _network(raw):
        original = entry.get("request", entry)
        method = original.get("method", "GET").upper()
        if method not in {"GET", "HEAD", "OPTIONS"}:
            raise EngineError("xss_runtime_binding", "No consumer network write may supply a stored-source proof")
        is_document = entry.get("type") == "document"
        is_read = entry.get("type") in {"xhr", "fetch"} and normalize_url(original["url"]) == normalize_url(request["url"])
        if not is_document and not is_read:
            continue
        recorded_headers = entry.get("request_headers", original.get("headers"))
        if recorded_headers is None or _credentials(project, recorded_headers) != expected_credentials:
            raise EngineError("xss_runtime_identity", "Original consumer/API request credentials must match the verified viewer readbacks")
        if is_document:
            if normalize_url(original["url"]) != consumer_url or method != "GET":
                raise EngineError("xss_runtime_binding", "Stored runtime proof requires an unambiguous consumer document")
            documents.append(entry)
        if is_read:
            if method != "GET" or entry.get("blocked") or entry.get("error") \
                    or entry.get("request_body_sha256") != _EMPTY_BODY_SHA \
                    or entry.get("response_body_complete") is not True \
                    or entry.get("response_body_sha256") != expected_digest \
                    or type(entry.get("response_body_bytes")) is not int or entry["response_body_bytes"] != len(response_bytes) \
                    or entry.get("status") != response["status"]:
                raise EngineError("xss_runtime_binding", "The native API response must match the exact captured readback content version")
            reads.append(entry)
    if not documents or not reads:
        raise EngineError("xss_runtime_binding", "Stored consumption needs an original consumer document and digested API readback in each visit")
    return visit, raw, window, stable("XC", expected_credentials)


def bound_proof(project, decision, item, operation):
    from .assessment import (_authorized, _input_controls, _input_view, _observations,
                             _require_verified_roles, _runtime_proof, _same_identity)

    spec = specification(decision["runtime"].get("consumption"))
    ids = decision.get("evidence_ids")
    read_ids = [spec["normal_read_evidence_id"], spec["attack_read_evidence_id"]]
    if not isinstance(ids, list) or len(ids) != 4 or ids[2:] != read_ids or len(set(ids)) != 4:
        raise EngineError("xss_input_binding", "Stored consumption needs four distinct captures in writer-normal, writer-attack, reader-normal, reader-attack order")
    if operation["method"] not in {"POST", "PUT", "PATCH"}:
        raise EngineError("xss_input_binding", "Bind stored XSS to the actual writing source input; a GET search locator is not the stored source")
    writers = _observations(project, ids[:2], item)
    _input_controls(writers, item, operation)
    _require_verified_roles(project, operation, writers)
    if operation.get("auth") == "unknown" or not _authorized(project, operation, writers[0][0].get("actor_id")):
        raise EngineError("xss_runtime_identity", "The writer must match the current declared operation policy")
    values = [_input_view(capture, item, operation)[0] for capture in writers]
    marker = (decision.get("runtime") or {}).get("marker")
    if not isinstance(marker, str) or not re.fullmatch(r"AWA-XSS-[a-fA-F0-9]{16,64}", marker) \
            or any(not isinstance(value, str) for value in values) or marker in values[0] or marker not in values[1]:
        raise EngineError("xss_input_binding", "Only the selected writer attack value may carry the unique runtime marker")
    canary = re.compile(r"\b(?:alert|confirm|prompt)\s*\(\s*(['\"])" + re.escape(marker) + r"\1\s*\)")
    if not any(canary.search(value) for value in _text_versions(values[1])):
        raise EngineError("xss_input_binding", "The writing source must carry the literal marker-executing script canary; a text flag or search locator cannot prove stored code execution")
    normal_request = writers[0][1]["request"]
    if _request_has_marker(normal_request, marker):
        raise EngineError("xss_input_binding", "The entire normal writer request must be free of the attack marker")
    resource_id = writers[1][0].get("resource_id")
    if not resource_id or writers[0][0].get("resource_id") != resource_id:
        raise EngineError("xss_input_binding", "Writer controls must bind the same explicit disposable resource")
    resource = project.get("resource", resource_id)
    if resource.get("owner_actor_id") != writers[0][0].get("actor_id"):
        raise EngineError("xss_runtime_identity", "The writing fixture must belong to the verified writer")
    for capture in writers:
        if not 200 <= capture[1]["response"]["status"] < 300 \
                or not json_equal(pointer(response_json(capture[1]), spec["write_success_selector"]), spec["write_success_expected"]):
            raise EngineError("xss_input_binding", "Both original writer captures must satisfy the declared successful write assertion")
    reads = [verify_current_evidence(project, identity) for identity in read_ids]
    if reads[0][0]["operation_id"] != reads[1][0]["operation_id"]:
        raise EngineError("xss_runtime_binding", "Normal and attack readbacks must use the same reader operation")
    reader = project.get("operation", reads[0][0]["operation_id"])
    if reader["method"] != "GET" or reader.get("auth") == "unknown" \
            or reads[0][1]["request"] != reads[1][1]["request"] \
            or base64.b64decode(reads[0][1]["request"]["body_base64"], validate=True):
        raise EngineError("xss_runtime_binding", "Readbacks must repeat the same declared, body-free GET request")
    _same_identity(reads)
    _require_verified_roles(project, reader, reads)
    if not _authorized(project, reader, reads[0][0].get("actor_id")):
        raise EngineError("xss_runtime_identity", "The reader must match the current declared operation policy")
    consumer_url = normalize_url(decision["runtime"].get("consumer_url"))
    if any(origin(capture[1]["request"]["url"]) != origin(consumer_url) for capture in [*writers, *reads]):
        raise EngineError("xss_runtime_binding", "Writer, readback and consumer must share the verified scoped origin")
    for capture, expected in zip(reads, values):
        if not 200 <= capture[1]["response"]["status"] < 300 or _request_has_marker(capture[1]["request"], marker):
            raise EngineError("xss_input_binding", "The marker must reach the consumer from stored content, never from a reader request")
        data = response_json(capture[1])
        if not json_equal(pointer(data, spec["content_selector"]), expected) \
                or not _same_binding_value(pointer(data, spec["resource_selector"]), resource["external_id"]):
            raise EngineError("xss_input_binding", "Each JSON readback must expose the exact selected writer value and the same fixture identity")
    normal_visit, normal_raw, normal_window, viewer_binding = _consumer(
        project, spec["normal_runtime_visit_id"], consumer_url, reads[0], marker, normal=True)
    attack_visit, attack_raw, attack_window, attack_binding = _consumer(
        project, decision["runtime"].get("visit_id"), consumer_url, reads[1], marker, normal=False)
    if normal_visit["id"] == attack_visit["id"] or not json_equal(
            _action_controls(normal_raw, marker), _action_controls(attack_raw, marker)):
        raise EngineError("xss_runtime_binding", "Normal and attack need independent consumer observations with identical successful interactions")
    windows = [_window(writers[0][1]), _window(reads[0][1]), normal_window,
               _window(writers[1][1]), _window(reads[1][1]), attack_window]
    if any(left[1] > right[0] for left, right in zip(windows, windows[1:])):
        raise EngineError("xss_runtime_binding", "Use actual nonoverlapping writer/readback/consumer normal-then-attack execution order")
    proof = _runtime_proof(project, decision)
    return {**proof, "binding_version": 2, "mechanism": "stored_api_consumer", "obligation_id": item["id"],
            "operation_id": operation["id"], "operation_signature": operation_signature(operation),
            "input_signature": item["input_signature"], "input_location": item["input_location"],
            "input_selector": item["input_selector"], "schema_branch": item.get("schema_branch"),
            "baseline_evidence_id": ids[0], "attack_evidence_id": ids[1], "resource_id": resource_id,
            "resource_signature": resource_signature(resource), "readback_evidence_ids": read_ids,
            "read_operation_id": reader["id"], "read_operation_signature": operation_signature(reader),
            "normal_runtime_visit_id": normal_visit["id"], "normal_artifact_sha256": normal_visit["sha256"],
            "identity": {key: writers[0][0].get(key) for key in _IDENTITY},
            "viewer_identity": {key: reads[0][0].get(key) for key in _IDENTITY},
            "credential_binding": stable("XC", _credentials(project, writers[0][1]["request"]["headers"])),
            "viewer_credential_binding": viewer_binding,
            "content_selector": spec["content_selector"], "resource_selector": spec["resource_selector"],
            "consumption_signature": stable("XCHAIN", [spec, [capture[0]["sha256"] for capture in [*writers, *reads]],
                normal_visit["sha256"], attack_visit["sha256"], viewer_binding, attack_binding])}
