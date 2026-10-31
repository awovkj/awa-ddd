"""Explicit TscanPlus MCP profiles; remote results never become engine evidence."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from urllib.parse import unquote, urlsplit

from . import engine
from .contracts import _validate_json
from .mcp_http import DEFAULT_ENDPOINT, StreamableHTTPClient, _decode_json, validate_endpoint
from .reporting import safe_text, safe_url
from .scope import require_scope
from .store import EngineError, canonical, contained, now


MCP_BYTES = 2 * 1024 * 1024
HTTP_BYTES = 1024 * 1024
TABLES = frozenset({"ipscan", "urlscan", "poccheck", "dirscan", "jsfinder", "subdomain", "pwdcrack", "cyber", "info"})
PROBE_ARGS = {"project_id", "adapter", "mcp_url", "scanner_project", "timeout"}
REQUEST_ARGS = {"project_id", "operation_id", "url", "session_id", "resource_id", "headers", "anonymous_cookie",
                "body", "body_base64", "body_file", "effect", "timeout", "max_bytes", "max_lines",
                "mcp_url", "scanner_project", "idempotency_key"}
QUERY_ARGS = {"project_id", "table", "scanner_project", "instance_id", "limit", "result_limit", "timeout", "mcp_url"}
SUMMARY_ARGS = {"project_id", "scanner_project", "mcp_url", "timeout"}
ROUTE_ARGS = SUMMARY_ARGS | {"limit"}
HTTP_SCHEMA = {"url": "string", "method": "string", "headers": "string", "cookie": "string", "body": "string",
               "follow_redirect": "boolean", "path_as_is": "boolean", "max_bytes": "number",
               "max_lines": "number", "timeout": "number"}
QUERY_SCHEMA = {"table": "string", "project": "string", "instance_id": "string", "result_limit": "number",
                "finger": "string", "keyword": "string", "poc_name": "string", "port": "string"}
SUMMARY_SCHEMA = {"project": "string"}
ROUTE_SCHEMA = {"project": "string"}
PROFILE_SCHEMAS = {"http_request": HTTP_SCHEMA, "query_results": QUERY_SCHEMA,
                   "project_summary": SUMMARY_SCHEMA, "route_candidates": ROUTE_SCHEMA}
ROUTE_TOOLS = frozenset({"http_request", "poc_scan", "pwd_crack", "dir_scan", "js_scan"})
PRIVATE = frozenset({"pass", "match", "password", "passwd", "pwd", "secret", "secretkey", "accesskey", "apikey",
                     "privatekey", "authorization", "proxyauthorization", "cookie", "cookies", "setcookie", "headers",
                     "requestheaders", "responseheaders", "sessionheaders", "mcpsessionid", "token", "sessiontoken",
                     "accesstoken", "refreshtoken", "credential", "credentials", "body", "bodybase64", "response",
                     "request", "raw", "rawdata", "banner", "requestbodybase64", "rawhttpbase64", "prompt",
                     "instructions", "systemprompt"})
ASSIGNED = re.compile(r'''(?i)\b(?:pass|match|access[_-]?key|secret[_-]?key|password|passwd|pwd|token|secret)\b["']?\s*[:=]\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\r\n,;]+)''')


def _arguments(args, allowed):
    if not isinstance(args, dict) or set(args) - allowed:
        raise EngineError("tscanplus_arguments", "Unsupported TscanPlus action fields; use action.help rather than forwarding arbitrary MCP arguments")
    _validate_json(args)


def _hash(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _namespace(value, max_length=30):
    if not isinstance(value, str) or value.lower() == "mcp":
        raise EngineError("tscanplus_project", "Use an explicit nondefault short TscanPlus project namespace")
    normalized = value if value.startswith("MCP-") else "MCP-" + value
    if len(normalized) > max_length or not re.fullmatch(r"MCP-[A-Za-z0-9][A-Za-z0-9_-]*", normalized):
        raise EngineError("tscanplus_project", f"Use a nondefault MCP- short namespace of at most {max_length} characters; older servers truncate longer names")
    return normalized


def _default_namespace(project):
    # TscanPlus 3.5.4 truncates at 20, despite the skill's newer 30-char contract.
    return "MCP-awa-" + _hash([str(project.base.resolve()), project.project_id])[:12]


def _settings(project):
    value = project.config.get("external_tools", {}).get("tscanplus")
    if not isinstance(value, dict):
        raise EngineError("tscanplus_unconfigured", "Run tool.probe with adapter:tscanplus before selecting a target or querying scanner data")
    state = dict(value)
    state["mcp_url"], state["scanner_project"] = validate_endpoint(state.get("mcp_url")), _namespace(state.get("scanner_project"), max_length=20)
    probe_run = project.get("run", state.get("probe_run_id"))
    document = _document(project, probe_run)
    if probe_run.get("status") != "succeeded" or probe_run.get("action") != "probe" \
            or probe_run.get("mcp_url") != state["mcp_url"] or probe_run.get("scanner_project") != state["scanner_project"] \
            or state.get("catalog") != {"artifact_path": probe_run.get("artifact_path"), "sha256": probe_run.get("sha256")} \
            or state.get("catalog_sha256") != _hash(document.get("tools")):
        raise EngineError("tscanplus_configuration", "The recorded MCP endpoint/catalog does not match its immutable probe artifact")
    return state, document["tools"]


def _same_settings(project, state):
    current = project.config.get("external_tools", {}).get("tscanplus")
    if current != state:
        raise EngineError("tscanplus_configuration", "TscanPlus configuration changed during this operation; do not automatically replay")


def _select(catalog, name):
    matches = [tool for tool in catalog if isinstance(tool, dict) and tool.get("name") == name]
    if len(matches) != 1:
        raise EngineError("mcp_schema", "The catalog has no unique tool for this supported TscanPlus profile")
    return matches[0]


def _gate(catalog, saved, name, values):
    selected, original = _select(catalog, name), _select(saved, name)
    schema = selected.get("inputSchema")
    types = PROFILE_SCHEMAS[name]
    if not isinstance(schema, dict) or _hash(schema) != _hash(original.get("inputSchema")) or schema.get("type") != "object" \
            or not isinstance(schema.get("properties"), dict) or set(schema["properties"]) - set(types):
        raise EngineError("mcp_schema", "The live TscanPlus schema changed or is outside the bounded supported profile; probe and review it explicitly")
    required = schema.get("required", [])
    if not isinstance(required, list) or any(not isinstance(key, str) or key not in values for key in required):
        raise EngineError("mcp_schema", "The live tool requires unsupported fields")
    for key, value in values.items():
        prop = schema["properties"].get(key)
        expected = types[key]
        if not isinstance(prop, dict) or prop.get("type") not in ({"number", "integer"} if expected == "number" else {expected}) \
                or any(field in prop for field in ("$ref", "oneOf", "anyOf", "allOf")):
            raise EngineError("mcp_schema", "The selected tool lacks explicit typed safety controls")
        if prop["type"] == "integer" and (type(value) not in {int, float} or not float(value).is_integer()):
            raise EngineError("mcp_schema", "An integer-only tool control cannot accept a fractional value")
        if "enum" in prop and (not isinstance(prop["enum"], list) or not any(canonical(item) == canonical(value) for item in prop["enum"])) \
                or "const" in prop and canonical(prop["const"]) != canonical(value):
            raise EngineError("mcp_schema", "A required fixed safety control is not accepted by the live schema")
        if expected == "number" and ("minimum" in prop and value < prop["minimum"] or "maximum" in prop and value > prop["maximum"]):
            raise EngineError("mcp_schema", "The requested bound is outside the live tool schema")
    _validate_json(values)
    if len(canonical(values).encode("utf-8")) > 1024 * 1024:
        raise EngineError("tscanplus_argument_budget", "Encoded MCP tool arguments exceed the byte budget; body strings are never cropped")
    return selected


def _tool_result(result):
    if not isinstance(result, dict) or result.get("isError") is True:
        raise EngineError("tscanplus_tool_error", "TscanPlus reported an error; inspect its private artifact")
    structured = result.get("structuredContent")
    content = result.get("content", [])
    if not isinstance(content, list):
        raise EngineError("tscanplus_result", "The MCP content envelope is unsupported")
    blocks = [block.get("text") for block in content if isinstance(block, dict) and block.get("type") == "text"]
    text = "\n".join(blocks) if blocks and all(isinstance(block, str) for block in blocks) else None
    parsed = _decode_json(text.encode("utf-8")) if text is not None and (structured is None or text.lstrip().startswith(("{", "["))) else None
    if structured is not None:
        _validate_json(structured)
        if parsed is not None and parsed != structured:
            raise EngineError("tscanplus_result", "The structured and text MCP results disagree")
        parsed = structured
    if not isinstance(parsed, dict) or type(parsed.get("success")) is not bool or not isinstance(parsed.get("data"), dict):
        raise EngineError("tscanplus_result", "The scanner result is not a recognized success/message/data object")
    if not parsed["success"]:
        raise EngineError("tscanplus_tool_error", "The scanner did not complete the requested profile successfully")
    return parsed


def _body(value):
    if value is None:
        return b""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if isinstance(value, str):
        return value.encode("utf-8", errors="strict")
    if isinstance(value, bytes):
        return value
    raise EngineError("tscanplus_body", "The selected body cannot be represented exactly by this MCP profile")


def _supplied_body(project, args):
    if sum(args.get(key) is not None for key in ("body", "body_file", "body_base64")) > 1:
        raise EngineError("body", "Select only one body source")
    if args.get("body_file") is not None:
        return engine._read_body_file(project, args["body_file"])
    if args.get("body_base64") is not None:
        try:
            return base64.b64decode(args["body_base64"], validate=True)
        except (ValueError, TypeError):
            raise EngineError("tscanplus_body", "The body_base64 value is invalid") from None
    return _body(args.get("body"))


def _input_signature(project, args, state, raw=None):
    operation = project.get("operation", args["operation_id"])
    raw = _supplied_body(project, args) if raw is None else raw
    return _hash({"endpoint": state["mcp_url"], "namespace": state["scanner_project"], "catalog": state["catalog_sha256"],
                  "operation_id": operation["id"], "url": require_scope(project.config, args.get("url") or operation["url"]),
                  "session_id": args.get("session_id"), "resource_id": args.get("resource_id"),
                  "headers": engine.headers_map(args.get("headers", {})), "anonymous_cookie": args.get("anonymous_cookie"),
                  "body_sha256": hashlib.sha256(raw).hexdigest(), "effect": args.get("effect", "read_only"),
                  "timeout": args.get("timeout", 15), "max_bytes": args.get("max_bytes", 8192), "max_lines": args.get("max_lines", 80)})


def _prepare(project, args):
    fields = {key: value for key, value in args.items() if key in {
        "operation_id", "url", "session_id", "resource_id", "headers", "anonymous_cookie", "body", "body_base64", "body_file", "effect", "timeout", "max_bytes"}}
    fields.setdefault("max_bytes", 8192)
    prepared = engine.preflight_capture(project, fields)
    operation, raw = prepared["operation"], _body(prepared["body"])
    if operation.get("protocol") != "http" or operation["method"] not in {"GET", "HEAD", "POST"}:
        raise EngineError("tscanplus_profile", "TscanPlus supports only registered HTTP GET/HEAD or explicitly fixture-bound POST")
    if operation["method"] == "POST" and prepared.get("resource") is None:
        raise EngineError("tscanplus_fixture", "A POST MCP request requires an explicit exact test fixture, not only actor state")
    if operation["method"] != "POST" and (raw or args.get("effect", "read_only") != "read_only"):
        raise EngineError("tscanplus_profile", "The read-only MCP profile requires a body-free GET/HEAD and effect:read_only")
    try:
        text = raw.decode("utf-8", errors="strict")
        if text.encode("utf-8") != raw:
            raise UnicodeError()
    except UnicodeError:
        raise EngineError("tscanplus_body", "This MCP tool accepts exact UTF-8 text bodies only; use the native engine for other byte encodings") from None
    request = {"url": prepared["url"], "method": operation["method"], "headers": prepared["headers"],
               "body_base64": base64.b64encode(raw).decode("ascii")}
    fingerprint = _hash({"request": request, "policy": engine.operation_signature(operation), "inputs": operation.get("inputs", []),
                         "session_id": prepared["session"]["id"] if prepared["session"] else None,
                         "session_generation": prepared["session"]["generation"] if prepared["session"] else None,
                         "resource": engine.resource_signature(prepared["resource"]) if prepared["resource"] else None})
    values = {"url": request["url"], "method": request["method"], "headers": canonical(request["headers"]),
              "cookie": "", "body": text, "follow_redirect": False, "path_as_is": True,
              "max_bytes": args.get("max_bytes", 8192), "max_lines": args.get("max_lines", 80), "timeout": prepared["timeout"]}
    if len(canonical(values).encode("utf-8")) > 1024 * 1024:
        raise EngineError("tscanplus_argument_budget", "Encoded MCP arguments exceed the byte budget; no target request was made")
    return prepared, request, values, fingerprint


def _document(project, run):
    if run.get("kind") != "external_tool" or run.get("adapter") != "tscanplus" or not run.get("artifact_path") or not run.get("sha256"):
        raise EngineError("tscanplus_artifact", "This is not a finalized TscanPlus tool artifact")
    document = project.read_artifact(run)
    if not isinstance(document, dict) or not isinstance(document.get("execution"), dict) \
            or any(run.get(key) != value for key, value in document["execution"].items()):
        raise EngineError("tscanplus_artifact", "The TscanPlus execution differs from its immutable artifact")
    reference = document.get("exchanges_ref")
    if reference is not None:
        if not isinstance(reference, dict):
            raise EngineError("tscanplus_artifact", "The private MCP transcript reference is invalid")
        entries = [entry for entry in run.get("files", []) if entry.get("path") == reference.get("path")]
        if len(entries) != 1 or not entries[0].get("complete") or any(entries[0].get(key) != reference.get(key) for key in ("bytes", "sha256")):
            raise EngineError("tscanplus_artifact", "The private MCP transcript differs from its signed file metadata")
        path = contained(project.base / reference["path"], project.base)
        if not path.is_file() or path.stat().st_size > 12 * 1024 * 1024:
            raise EngineError("tscanplus_artifact", "The private MCP transcript is missing or exceeds its read budget")
        raw = path.read_bytes()
        if len(raw) != reference["bytes"] or hashlib.sha256(raw).hexdigest() != reference["sha256"]:
            raise EngineError("tscanplus_artifact", "The private MCP transcript was changed")
        document["exchanges"] = json.loads(raw)
    return document


def _finish_saved(project, run, document):
    from .external import _finish
    # Split, rather than crop, duplicate wire/JSON views so both signed artifacts
    # remain below the engine's 12 MiB per-file read limit.
    exchanges = document.pop("exchanges", [])
    raw = canonical(exchanges).encode("utf-8")
    path = contained(project.base / "tools" / run["id"] / "mcp-exchanges.json", project.base)
    with path.open("xb") as stream:
        stream.write(raw)
    document["exchanges_ref"] = {"path": path.relative_to(project.base).as_posix(), "bytes": len(raw),
                                 "sha256": hashlib.sha256(raw).hexdigest()}
    return _finish(project, run, document, (path,))


def _public(run, **extra):
    fields = ("id", "adapter", "action", "status", "available", "operation_id", "session_id", "session_generation", "actor_id",
              "resource_id", "effect", "mcp_url", "scanner_project", "selected_tool", "tool_name", "tool_count", "catalog_sha256",
              "verification_level", "error_code", "artifact_path", "sha256", "target_traffic_sent", "dispatch_attempted",
              "remote_may_continue", "remote_stopped_verified", "response_truncated", "results_complete", "parser_status",
              "table", "instance_id", "result_limit", "reported_count", "returned_rows", "candidate_count", "new_candidates",
              "duplicate_candidates", "out_of_scope_rows", "unmapped_rows", "unretrieved_results", "reported_http_status",
              "reported_total", "reported_matched", "namespace_verified", "instance_verified", "counts", "has_assets",
              "import_limit", "processed_rows", "omitted_candidates", "unsupported_rows", "asset_count")
    return {**{key: run[key] for key in fields if key in run}, "run_id": run["id"], "trust": "untrusted_tool_output",
            "finding_status": "unverified", "usable_for_confirmation": False, **extra}


def _record_error(project, run, document, error):
    run.update(status="failed", error_code=getattr(error, "code", "tscanplus_failed"),
               remote_may_continue=bool(run.get("dispatch_attempted")), remote_stopped_verified=False)
    document["error_type"] = type(error).__name__
    result = _finish_saved(project, run, document)
    raise EngineError(run["error_code"], "The bounded TscanPlus operation failed; inspect its immutable artifact before any new execution",
                      {"run_id": result["run_id"], "remote_may_continue": run["remote_may_continue"], "next_action": "tool.inspect"}) from None


def probe(project, args):
    from .external import _finish, _start, _timeout
    _arguments(args, PROBE_ARGS)
    if args.get("adapter", "tscanplus") != "tscanplus":
        raise EngineError("tool_adapter", "This adapter is tscanplus")
    prior = project.config.get("external_tools", {}).get("tscanplus", {})
    endpoint = validate_endpoint(args.get("mcp_url", prior.get("mcp_url", DEFAULT_ENDPOINT)))
    namespace = _namespace(args.get("scanner_project", prior.get("scanner_project", _default_namespace(project))), max_length=20)
    timeout = _timeout(args)
    run, _ = _start(project, "tscanplus", "probe")
    run.update(mcp_url=endpoint, scanner_project=namespace, remote_may_continue=False, remote_stopped_verified=False)
    document, client = {}, None
    try:
        client = StreamableHTTPClient(endpoint, timeout=timeout, max_bytes=MCP_BYTES)
        initialized, catalog = client.initialize(), client.list_tools()
        document.update(initialize=initialized, tools=catalog)
        run.update(status="succeeded", available=True, verification_level="mcp_discovery", tool_count=len(catalog), catalog_sha256=_hash(catalog))
    except (EngineError, OSError, ValueError, TypeError) as exc:
        run.update(status="failed", available=False, error_code=getattr(exc, "code", "tscanplus_probe_failed"))
        document["error_type"] = type(exc).__name__
    finally:
        if client:
            client.close()
            document["exchanges"] = client.exchanges
    result = _finish_saved(project, run, document)
    if run.get("available"):
        state = {"mcp_url": endpoint, "scanner_project": namespace, "probe_run_id": run["id"],
                 "catalog_sha256": run["catalog_sha256"], "catalog": {"artifact_path": result["artifact_path"], "sha256": result["sha256"]}}
        config = project.config
        project.set_config({**config, "external_tools": {**config.get("external_tools", {}), "tscanplus": state}})
    return _public(result, limitation="Catalog discovery did not invoke a scanner, touch target URLs, clear a database or prove any vulnerability")


def request_run(project, args):
    from .external import _start, _finish, _timeout
    _arguments(args, REQUEST_ARGS)
    state, saved = _settings(project)
    if "mcp_url" in args and validate_endpoint(args["mcp_url"]) != state["mcp_url"] \
            or "scanner_project" in args and _namespace(args["scanner_project"]) != state["scanner_project"]:
        raise EngineError("tscanplus_configuration", "A request cannot silently change the recorded MCP endpoint or namespace")
    timeout = _timeout(args)
    if args.get("timeout", 15) > 60 or type(args.get("max_bytes", 8192)) is not int or not 1 <= args.get("max_bytes", 8192) <= HTTP_BYTES \
            or type(args.get("max_lines", 80)) is not int or not 1 <= args.get("max_lines", 80) <= 200:
        raise EngineError("tscanplus_budget", "HTTP timeout must be at most 60 seconds, max_bytes 1..1048576 and max_lines 1..200")
    key, run_id = args.get("idempotency_key"), None
    if key is not None:
        if not isinstance(key, str) or not key.strip() or len(key) > 200 or any(ord(character) < 32 for character in key):
            raise EngineError("tscanplus_idempotency", "idempotency_key must be a bounded nonempty string")
        run_id = engine.stable("RUN", ["tscanplus", state["mcp_url"], key])
        previous = project.get("run", run_id, required=False)
        if previous:
            if previous.get("status") != "succeeded" or previous.get("remote_may_continue"):
                raise EngineError("run_uncertain", "The prior TscanPlus execution is incomplete or uncertain; it is never automatically replayed", {"run_id": run_id})
            view = inspect(project, {"run_id": run_id})
            if view["integrity"] != "valid" or view["lineage"] != "current" \
                    or previous.get("call_input_signature") != _input_signature(project, args, state):
                raise EngineError("idempotency_conflict", "The key belongs to a different or no-longer-current TscanPlus request", {"run_id": run_id})
            return _public(previous, idempotent_reuse=True)
    prepared, request, values, fingerprint = _prepare(project, args)
    _gate(saved, saved, "http_request", values)
    operation, session, resource = prepared["operation"], prepared["session"], prepared["resource"]
    run, _ = _start(project, "tscanplus", "http_request", operation, session, target_url=prepared["url"],
                    request_snapshot=request, resource=resource, effect=args.get("effect", "read_only"), run_id=run_id)
    run.update(mcp_url=state["mcp_url"], scanner_project=state["scanner_project"], catalog_sha256=state["catalog_sha256"],
               selected_tool="http_request", tool_name="http_request", dispatch_attempted=False, remote_may_continue=False,
               remote_stopped_verified=False, request_fingerprint=fingerprint,
               call_input_signature=_input_signature(project, args, state, base64.b64decode(request["body_base64"])))
    document, client, error = {"request": request, "arguments": values}, None, None
    try:
        client = StreamableHTTPClient(state["mcp_url"], timeout=timeout, max_bytes=MCP_BYTES)
        document["initialize"] = client.initialize()
        catalog = client.list_tools()
        document["live_catalog"] = catalog
        document["selected_tool"] = _gate(catalog, saved, "http_request", values)
        _same_settings(project, state)
        if _prepare(project, args)[3] != fingerprint:
            raise EngineError("tscanplus_context", "Request or security context changed during discovery")
        run.update(dispatch_attempted=True, remote_may_continue=True)
        project.put("run", run)
        document["result"] = client.call_tool("http_request", values)
        parsed = document["parsed_result"] = _tool_result(document["result"])
        data = parsed["data"]
        statuses = [data[key] for key in ("status_code", "statusCode", "StatusCode", "status") if type(data.get(key)) is int and 100 <= data[key] <= 599]
        truncated, complete = _result_flags(data)
        run.update(status="succeeded", verification_level="mcp_execution_untrusted", remote_may_continue=False,
                   reported_http_status=statuses[0] if statuses else None, target_traffic_sent=bool(statuses),
                   response_truncated=truncated,
                   results_complete=not truncated and complete is not False if truncated is not None else False if complete is False else None,
                   parser_status="recognized", limitation="A tool-reported HTTP result is not independent engine evidence; response completeness is unknown unless explicitly reported")
    except (EngineError, OSError, ValueError, TypeError, KeyError) as exc:
        error = exc
    finally:
        if client:
            client.close()
            document["exchanges"] = client.exchanges
            document.setdefault("result", client.last_tool_result)
    if error:
        return _record_error(project, run, document, error)
    return _public(_finish_saved(project, run, document))


def _row_value(row, names):
    normalized = {re.sub(r"[^a-z0-9]", "", str(key).lower()): value for key, value in row.items()}
    return next((normalized[name] for name in names if name in normalized), None)


def _profile_settings(project, args):
    state, saved = _settings(project)
    if "mcp_url" in args and validate_endpoint(args["mcp_url"]) != state["mcp_url"]:
        raise EngineError("tscanplus_configuration", "A read profile cannot change the recorded MCP endpoint")
    if "scanner_project" in args and _namespace(args["scanner_project"]) != state["scanner_project"]:
        raise EngineError("tscanplus_namespace", "Read only the recorded explicit scanner namespace")
    return state, saved


def _result_flags(data):
    flags = [data[key] for key in ("response_truncated", "body_truncated", "results_truncated", "truncated", "has_more") if key in data]
    complete = data.get("results_complete")
    if any(type(flag) is not bool for flag in flags) or "results_complete" in data and type(complete) is not bool:
        raise EngineError("tscanplus_result", "The result completeness flags have unsupported types")
    return (any(flags) if flags else None), complete


def _echo(row, names):
    values = [value for key, value in row.items() if re.sub(r"[^a-z0-9]", "", key.lower()) in names]
    if values and any(canonical(value) != canonical(values[0]) for value in values[1:]):
        raise EngineError("tscanplus_namespace", "Conflicting project or instance aliases cannot establish result provenance")
    return values[0] if values else None


def _echo_instance(row):
    value = _echo(row, ("instanceid",))
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", value):
        raise EngineError("tscanplus_namespace", "A result instance echo is invalid")
    return value


def _bindings(data, rows, namespace, instance=None):
    echoed = _echo(data, ("project", "scannerproject"))
    projects = [_echo(row, ("project", "scannerproject")) for row in rows]
    for value in [echoed, *projects]:
        if value is not None and _namespace(value) != namespace:
            raise EngineError("tscanplus_namespace", "The result belongs to another namespace; older servers require a shorter explicitly probed project name")
    top_instance = _echo_instance(data)
    instances = [_echo_instance(row) for row in rows]
    for value in [top_instance, *instances]:
        if value is not None and instance is not None and value != instance:
            raise EngineError("tscanplus_namespace", "A result disagrees with the requested instance filter")
    if top_instance is not None and any(value is not None and value != top_instance for value in instances):
        raise EngineError("tscanplus_namespace", "The result rows disagree with the top-level instance echo")
    return {"namespace_verified": echoed is not None or bool(rows) and all(value is not None for value in projects),
            "instance_verified": instance is None or top_instance == instance or bool(rows) and all(value == instance for value in instances),
            "echoed_project": echoed, "echoed_instance": top_instance}


def _query_rows(parsed, table, namespace, instance, limit):
    data, results = parsed["data"], parsed["data"].get("results")
    if "table" in data and data["table"] != table:
        raise EngineError("tscanplus_result", "The query table echo disagrees with the requested table")
    if isinstance(results, dict):
        rows, counts = results.get(table), data.get("counts")
        count = counts.get(table) if isinstance(counts, dict) else None
        matched, locator = count, "parsed_result.data.results." + table
    elif isinstance(results, list) and data.get("table") == table:
        rows, count, matched, locator = results, data.get("total"), data.get("matched"), "parsed_result.data.results"
    else:
        raise EngineError("tscanplus_result", "The query result collection is not a supported table-keyed or flat row array")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows) or len(rows) > limit \
            or type(count) is not int or type(matched) is not int or not count >= matched >= len(rows) \
            or "result_limit" in data and (type(data["result_limit"]) is not int or data["result_limit"] != limit):
        raise EngineError("tscanplus_result", "The query row/count/limit structure is inconsistent; no absence claim is inferred")
    truncated, complete = _result_flags(data)
    return {"rows": rows, "reported_count": count, "reported_total": count, "reported_matched": matched,
            "locator": locator, "truncated": truncated, "complete": complete,
            **_bindings(data, rows, namespace, instance)}


def _public_locator(url, secrets):
    visible, decoded = safe_url(url), safe_url(url)
    # Inspect intermediate encodings too: a secret may itself contain "%41".
    for attempt in range(4):
        segments = urlsplit(decoded).path.split("/")
        if safe_text(decoded) != decoded or any(secret in segments or len(secret) >= 4 and secret in decoded for secret in secrets):
            return "[private URL omitted]", True
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        if attempt == 3:
            return "[private URL omitted]", True
        decoded = next_value
    return visible, False


def _candidate_plan(project, state, row, url, secrets, kind, discriminator, locator, binding):
    if not isinstance(url, str) or not url.lower().startswith(("http://", "https://")):
        return None, "unmapped"
    try:
        url = require_scope(project.config, url)
    except EngineError as exc:
        return None, "outside" if exc.code == "out_of_scope" else "unmapped"
    digest = _hash(row)
    actual_instance = _echo_instance(row) or binding["echoed_instance"]
    identity = "C-" + _hash(["tscanplus", state["mcp_url"], state["scanner_project"], kind, discriminator, actual_instance, digest])[:24]
    visible, redacted = _public_locator(url, secrets)
    return {"id": identity, "kind": kind, "url": visible, "url_redacted": redacted, "mcp_url": state["mcp_url"],
            "scanner_project": state["scanner_project"], "namespace_verified": binding["echoed_project"] is not None
                or _echo(row, ("project", "scannerproject")) is not None,
            "instance_id": _text(actual_instance, secrets) if actual_instance is not None else None,
            "instance_verified": actual_instance is not None, "row_digest": digest, "source_locator": locator}, None


def _candidate_counts(project, run, plans, repeated, outside, unmapped):
    existing = sum(project.get("candidate", plan["id"], required=False) is not None for plan in plans)
    run.update(candidate_count=len(plans), new_candidates=len(plans) - existing, duplicate_candidates=existing + repeated,
               out_of_scope_rows=outside, unmapped_rows=unmapped)


def _read_run(project, args, name, state, saved, values, parser, metadata=None):
    from .external import _start, _timeout
    _gate(saved, saved, name, values)
    timeout = _timeout(args)
    run, _ = _start(project, "tscanplus", name)
    run.update(mcp_url=state["mcp_url"], scanner_project=state["scanner_project"], catalog_sha256=state["catalog_sha256"],
               selected_tool=name, tool_name=name, dispatch_attempted=False, remote_may_continue=False,
               remote_stopped_verified=False, results_complete=False, namespace_verified=False, **(metadata or {}))
    document, client, error, plans = {"arguments": values}, None, None, []
    try:
        client = StreamableHTTPClient(state["mcp_url"], timeout=timeout, max_bytes=MCP_BYTES)
        document["initialize"] = client.initialize()
        catalog = document["live_catalog"] = client.list_tools()
        document["selected_tool"] = _gate(catalog, saved, name, values)
        _same_settings(project, state)
        run.update(dispatch_attempted=True, remote_may_continue=True)
        project.put("run", run)
        document["result"] = client.call_tool(name, values)
        parsed = document["parsed_result"] = _tool_result(document["result"])
        plans = parser(run, parsed, _secrets({"result": document["result"], "parsed_result": parsed}))
        _same_settings(project, state)
        run.update(status="succeeded", remote_may_continue=False)
        document["candidate_ids"] = [plan["id"] for plan in plans]
    except (EngineError, OSError, ValueError, TypeError, KeyError) as exc:
        run.update(parser_status="blocked", results_complete=False)
        error = exc
    finally:
        if client:
            client.close()
            document["exchanges"] = client.exchanges
            document.setdefault("result", client.last_tool_result)
    if error:
        return _record_error(project, run, document, error)
    with project.transaction():
        result = _finish_saved(project, run, document)
        for plan in plans:
            if project.get("candidate", plan["id"], required=False) is not None:
                continue
            locator = plan.pop("source_locator")
            source = {"artifact_path": result["artifact_path"], "sha256": result["sha256"], "locator": locator,
                      "trust": "untrusted_tool_output", "mcp_url": state["mcp_url"]}
            project.put("candidate", {**plan, "status": "unverified", "origin": "imported", "source": source,
                                      "sources": [source], "created_at": now(), "updated_at": now()}, create_only=True)
            project.event("candidate.tscanplus_imported", {"candidate_id": plan["id"], "run_id": run["id"]})
    return _public(result, candidate_ids=document["candidate_ids"],
                   limitation="Scanner data and routing suggestions are unverified; database counts are not a security negative, target authorization or full assessment coverage")


def query_results(project, args):
    _arguments(args, QUERY_ARGS)
    state, saved = _profile_settings(project, args)
    table, limit, instance = args.get("table", "urlscan"), args.get("limit", args.get("result_limit", 25)), args.get("instance_id")
    if "limit" in args and "result_limit" in args and (type(args["limit"]) is not int or type(args["result_limit"]) is not int
                                                       or args["limit"] != args["result_limit"]):
        raise EngineError("tscanplus_query", "limit and result_limit must be the same integer when both are supplied")
    if not isinstance(table, str) or table not in TABLES or type(limit) is not int or not 1 <= limit <= 100 \
            or instance is not None and (not isinstance(instance, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", instance)):
        raise EngineError("tscanplus_query", "Select a supported table, limit 1..100 and optional bounded instance_id")
    values = {"table": table, "project": state["scanner_project"], "result_limit": limit}
    if instance is not None:
        values["instance_id"] = instance

    def parse(run, parsed, secrets):
        info = _query_rows(parsed, table, state["scanner_project"], instance, limit)
        rows, plans, seen = info["rows"], [], set()
        outside = unmapped = repeated = 0
        for index, row in enumerate(rows):
            plan, reason = _candidate_plan(project, state, row, _row_value(row, ("url", "targeturl", "target")), secrets,
                "tscanplus_row", table, info["locator"] + "[" + str(index) + "]", info)
            if plan is None:
                outside += reason == "outside"
                unmapped += reason == "unmapped"
                continue
            if plan["id"] in seen:
                repeated += 1
                continue
            seen.add(plan["id"])
            plan.update(table=table, name=_text(_row_value(row, ("name", "pocname", "vulnname", "title")) or table, secrets),
                        category=_text(_row_value(row, ("category", "type", "vulntype")) or "scanner_signal", secrets))
            plans.append(plan)
        bound = info["namespace_verified"] and info["instance_verified"]
        status = "namespace_echo_missing" if not info["namespace_verified"] else "instance_echo_missing" if not info["instance_verified"] else "recognized"
        run.update(verification_level="mcp_results_untrusted", parser_status=status,
                   reported_count=info["reported_count"], reported_total=info["reported_total"], reported_matched=info["reported_matched"],
                   returned_rows=len(rows), namespace_verified=info["namespace_verified"], instance_verified=info["instance_verified"],
                   response_truncated=info["truncated"],
                   results_complete=bound and info["reported_count"] == len(rows) and info["truncated"] is not True and info["complete"] is not False,
                   unretrieved_results=info["reported_count"] > len(rows) or info["truncated"] is True)
        _candidate_counts(project, run, plans, repeated, outside, unmapped)
        return plans

    return _read_run(project, args, "query_results", state, saved, values, parse,
                     {"table": table, "instance_id": instance, "result_limit": limit})


def project_summary(project, args):
    _arguments(args, SUMMARY_ARGS)
    state, saved = _profile_settings(project, args)

    def parse(run, parsed, secrets):
        data, counts = parsed["data"], parsed["data"].get("counts")
        if not isinstance(counts, dict) or any(type(counts.get(table)) is not int or counts[table] < 0 for table in TABLES) \
                or type(data.get("has_assets")) is not bool:
            raise EngineError("tscanplus_result", "A summary requires explicit nonnegative known-table counts and a boolean asset flag")
        binding, flags = _bindings(data, [], state["scanner_project"]), _result_flags(data)
        run.update(verification_level="mcp_summary_untrusted", counts={table: counts[table] for table in sorted(TABLES)},
                   has_assets=data["has_assets"], namespace_verified=binding["namespace_verified"],
                   parser_status="recognized" if binding["namespace_verified"] else "namespace_echo_missing",
                   response_truncated=flags[0], results_complete=binding["namespace_verified"] and flags[0] is not True and flags[1] is not False)
        return []

    return _read_run(project, args, "project_summary", state, saved, {"project": state["scanner_project"]}, parse)


def _route_target(row):
    values = [row[key] for key in ("url", "target", "targets") if key in row]
    for key in ("arguments", "args"):
        arguments = row.get(key)
        if isinstance(arguments, dict):
            values.extend(arguments[field] for field in ("url", "targets", "urls") if field in arguments)
    if not values or any(not isinstance(value, str) for value in values) or any(value != values[0] for value in values[1:]):
        return None
    return values[0]


def route_candidates(project, args):
    _arguments(args, ROUTE_ARGS)
    state, saved = _profile_settings(project, args)
    limit = args.get("limit", 25)
    if type(limit) is not int or not 1 <= limit <= 100:
        raise EngineError("tscanplus_query", "The local route import limit must be an integer 1..100; it is not a remote cursor")

    def parse(run, parsed, secrets):
        data, rows = parsed["data"], parsed["data"].get("candidates")
        counts, assets = data.get("counts", {}), data.get("assets", [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows) or not isinstance(assets, list) \
                or not isinstance(counts, dict) or any(type(value) is not int or value < 0 for key, value in counts.items() if key in TABLES) \
                or "has_assets" in data and type(data["has_assets"]) is not bool:
            raise EngineError("tscanplus_result", "The route result collection/count structure is unsupported")
        binding, flags = _bindings(data, rows, state["scanner_project"]), _result_flags(data)
        plans, seen = [], set()
        outside = unmapped = repeated = unsupported = 0
        for index, row in enumerate(rows[:limit]):
            tool = _row_value(row, ("tool", "toolname"))
            if not isinstance(tool, str) or tool not in ROUTE_TOOLS:
                unsupported += 1
                continue
            plan, reason = _candidate_plan(project, state, row, _route_target(row), secrets, "tscanplus_route", tool,
                                           "parsed_result.data.candidates[" + str(index) + "]", binding)
            if plan is None:
                outside += reason == "outside"
                unmapped += reason == "unmapped"
                continue
            if plan["id"] in seen:
                repeated += 1
                continue
            seen.add(plan["id"])
            containers = [row] + [row[key] for key in ("arguments", "args") if isinstance(row.get(key), dict)]
            methods = [value["method"] for value in containers if "method" in value] or ["GET"]
            safe_methods = all(isinstance(method, str) and method in {"GET", "HEAD"} and method == methods[0] for method in methods)
            has_body = any(value.get(key) for value in containers for key in ("body", "body_base64", "body_file"))
            supported = tool == "http_request" and safe_methods and not has_body and not plan["url_redacted"]
            plan.update(suggested_tool=tool, execution_supported=supported, requires_review=True,
                        name="TscanPlus route: " + tool, category="scanner_route")
            plans.append(plan)
        omitted = max(0, len(rows) - limit)
        run.update(verification_level="mcp_routes_untrusted", parser_status="recognized" if binding["namespace_verified"] else "namespace_echo_missing",
                   namespace_verified=binding["namespace_verified"], reported_count=len(rows), returned_rows=len(rows),
                   processed_rows=min(len(rows), limit), omitted_candidates=omitted, unsupported_rows=unsupported, asset_count=len(assets),
                   counts={table: counts[table] for table in sorted(TABLES) if table in counts}, has_assets=data.get("has_assets"),
                   response_truncated=flags[0], unretrieved_results=bool(omitted) or flags[0] is True,
                   results_complete=binding["namespace_verified"] and not omitted and flags[0] is not True and flags[1] is not False
                       and (flags[0] is False or flags[1] is True))
        _candidate_counts(project, run, plans, repeated, outside, unmapped)
        return plans

    return _read_run(project, args, "route_candidates", state, saved, {"project": state["scanner_project"]}, parse,
                     {"import_limit": limit})


def inspect(project, args):
    _arguments(args, {"project_id", "run_id"})
    run = project.get("run", args["run_id"])
    try:
        document = _document(project, run)
        if run.get("operation_id"):
            from .external import _verify_tool_lineage
            _verify_tool_lineage(project, run, document)
            require_scope(project.config, document["request"]["url"])
            values = document["arguments"]
            raw = base64.b64decode(document["request"]["body_base64"], validate=True)
            if values.get("follow_redirect") is not False or values.get("path_as_is") is not True or values.get("cookie") != "" \
                    or values.get("url") != document["request"]["url"] or values.get("method") != document["request"]["method"] \
                    or values.get("body", "").encode("utf-8") != raw or _decode_json(values["headers"].encode("utf-8")) != document["request"]["headers"]:
                raise EngineError("tscanplus_context", "The selected safety controls or request bytes changed")
        return _public(run, integrity="valid", lineage="current" if run.get("operation_id") else "not_applicable")
    except (EngineError, OSError, ValueError, TypeError, KeyError) as exc:
        return _public(run, integrity="invalid" if not run.get("artifact_path") else "invalid_or_stale", lineage="stale",
                       lineage_reason_code=getattr(exc, "code", "tscanplus_context"))


def _private(key):
    normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
    return normalized in PRIVATE or "base64" in normalized or normalized.endswith(("password", "token", "secret", "accesskey", "secretkey", "privatekey"))


def _secrets(document):
    values = set()

    def learn(node, private=False):
        if isinstance(node, dict):
            for key, value in node.items():
                learn(value, private or _private(key))
        elif isinstance(node, list):
            for value in node:
                learn(value, private)
        elif isinstance(node, str):
            if private and node:
                values.add(node)
                if "=" in node:
                    values.update(part.partition("=")[2].strip() for part in node.split(";") if "=" in part)
                if node.lower().startswith(("bearer ", "basic ")):
                    values.add(node.partition(" ")[2].strip())
            for assignment in ASSIGNED.finditer(node):
                literal = assignment.group(1).strip()
                values.add(literal[1:-1] if literal[:1] in {"\"", "'"} and literal[-1:] == literal[:1] else literal)
            if node.lstrip().startswith(("{", "[")):
                try:
                    learn(_decode_json(node.encode("utf-8")))
                except EngineError:
                    pass
        elif private and node is not None and not isinstance(node, bool):
            values.add(str(node))

    for key in ("request", "arguments", "result", "parsed_result"):
        if key in document:
            # A request is a private container, not a reason to hide every ordinary URL word.
            learn(document[key])
    for exchange in document.get("exchanges", []):
        if isinstance(exchange, dict):
            headers = exchange.get("headers", {})
            if isinstance(headers, dict):
                learn(headers)
            elif isinstance(headers, list):
                for header in headers:
                    if isinstance(header, (list, tuple)) and len(header) == 2 and _private(header[0]):
                        learn(header[1], True)
    return sorted((value for value in values if value), key=len, reverse=True)


def _text(value, secrets):
    text = str(value)
    text = re.sub(r"https?://[^\s<>\"']+", lambda match: _public_locator(match.group(0), secrets)[0], text, flags=re.IGNORECASE)
    for secret in secrets:
        if len(secret) >= 4 or text == secret:
            text = text.replace(secret, "[private value omitted]")
    return safe_text(ASSIGNED.sub("[private assignment omitted]", text), 4000)


def _redact(value, secrets, depth=0):
    if depth > 24:
        return "[nested data omitted]"
    if isinstance(value, dict):
        return {_text(key, secrets): "[private field omitted]" if _private(key) else _redact(item, secrets, depth + 1)
                for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, secrets, depth + 1) for item in value]
    if isinstance(value, str):
        if value.lstrip().startswith(("{", "[")):
            try:
                return _redact(_decode_json(value.encode("utf-8")), secrets, depth + 1)
            except EngineError:
                pass
        return _text(value, secrets)
    if value is not None and not isinstance(value, bool) and str(value) in secrets:
        return "[private value omitted]"
    return value


def read_artifact(project, args):
    _arguments(args, {"project_id", "run_id", "name", "offset", "limit"})
    if args.get("name", "result") != "result":
        raise EngineError("tool_artifact_unavailable", "TscanPlus only exposes a redacted result view; process stdout/stderr are not available")
    offset, limit = args.get("offset", 0), args.get("limit", 2000)
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 8000:
        raise EngineError("pagination", "offset must be nonnegative and limit 1..8000 characters")
    run = project.get("run", args["run_id"])
    document = _document(project, run)
    view = {"execution": _public(run), "result": document.get("result"), "parsed_result": document.get("parsed_result")}
    content = json.dumps(_redact(view, _secrets(document)), ensure_ascii=False, indent=2)
    return {"run_id": run["id"], "name": "result", "content": content[offset:offset + limit], "offset": offset, "limit": limit,
            "total_chars": len(content), "next_offset": offset + limit if offset + limit < len(content) else None,
            "source_sha256": run["sha256"], "integrity": "valid", "redacted": True,
            "trust": "untrusted_tool_output", "finding_status": "unverified", "usable_for_confirmation": False}


def report_context(project):
    """Private Redactor seed; invalid artifacts are ignored rather than relabelled."""
    values = set()
    for run in project.list("run"):
        if run.get("adapter") != "tscanplus" or run.get("kind") != "external_tool":
            continue
        try:
            values.update(_secrets(_document(project, run)))
        except (EngineError, OSError, ValueError, TypeError, KeyError):
            continue
    return {"secret_values": sorted(values, key=len, reverse=True)}
