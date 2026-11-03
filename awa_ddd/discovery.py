"""Bounded offline discovery adapters. Source declarations never become verdicts.

The ARTEX adapter implements its documented export shape independently; it does
not import or execute ARTEX code. Normalized results contain input names and
locations, not credential, parameter, request-body, or response-body values.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from .inputs import json_document

MAX_BYTES = 8 * 1024 * 1024
MAX_ROWS = 10000
MAX_DEPTH = 24
MAX_NODES = 50000
FORMATS = {"openapi", "javascript", "har", "artex", "sarif", "assessment_hints"}
METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
_MIME = re.compile(r"^[\w.+-]+/[\w.+-]+$")


def _pointer(value):
    return str(value).replace("~", "~0").replace("/", "~1")


def _media(value):
    value = str(value or "").split(";", 1)[0].strip().lower()
    return value if _MIME.fullmatch(value) else ""


def _name(value):
    return isinstance(value, str) and 0 < len(value) <= 1024 and not any(ord(c) < 32 for c in value)


def _bounded_json(text):
    """Shared strict JSON decoding plus bounded Unicode-scalar validation."""
    try:
        document = json_document(text)
        pending, visited = [(document, 0)], 0
        while pending:
            value, depth = pending.pop()
            visited += 1
            if visited > MAX_NODES or depth > MAX_DEPTH:
                raise ValueError("discovery JSON traversal budget exceeded")
            if isinstance(value, str):
                value.encode("utf-8", errors="strict")
            elif isinstance(value, dict):
                for key, item in value.items():
                    key.encode("utf-8", errors="strict")
                    pending.append((item, depth + 1))
            elif isinstance(value, list):
                pending.extend((item, depth + 1) for item in value)
        return document
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        if isinstance(exc, ValueError) and "budget" in str(exc):
            raise ValueError("discovery JSON traversal budget exceeded") from exc
        raise ValueError("discovery input is not an unambiguous finite UTF-8 JSON document") from exc


def _url(raw, base=None, schemes=("http", "https")):
    if not isinstance(raw, str) or not raw or len(raw) > 8192 or any(ord(c) < 32 for c in raw) or "\\" in raw:
        raise ValueError("invalid URL")
    absolute = urljoin(base or "", raw)
    parsed = urlsplit(absolute)
    if parsed.scheme.lower() not in schemes or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("an absolute URL without embedded credentials is required")
    port = parsed.port
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    if ":" in host:
        host = "[" + host + "]"
    if port is not None and port != {"http": 80, "https": 443, "ws": 80, "wss": 443}.get(parsed.scheme.lower()):
        host += ":" + str(port)
    # Query values may be credentials. They are never part of the output URL.
    query = [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=2048) if _name(name)]
    return urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", "", "")), query


class _Output:
    def __init__(self, path, raw):
        self.path = str(path)
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self.operations = {}
        self.candidates = []
        self.limitations = []
        self._limits = set()
        self.nodes = 0

    def source(self, locator, trust):
        return {"path": self.path, "sha256": self.sha256, "locator": locator, "trust": trust}

    def limit(self, code, locator="#", message=""):
        key = code, locator
        if key not in self._limits and len(self.limitations) < 2000:
            self._limits.add(key)
            self.limitations.append({"code": code, "locator": locator, "message": message or code.replace("_", " ")})

    def tick(self, depth=0):
        self.nodes += 1
        if self.nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ValueError("discovery traversal budget exceeded")

    def candidate(self, row):
        if len(self.candidates) + len(self.operations) >= MAX_ROWS:
            raise ValueError("discovery row budget exceeded")
        self.candidates.append(row)

    def operation(self, url, method, inputs, locator, trust, base=None, content_type="", protocol="http", operation_name="", candidate=False, **extra):
        try:
            clean, query = _url(url, base)
        except (ValueError, UnicodeError):
            self.limit("unresolved_or_invalid_url", locator)
            return
        src = "observed" if trust == "observed" else "declared" if trust == "declared" else "inferred"
        inputs = list(inputs) + [_input(name, "query", name, src) for name in query]
        if method is not None:
            method = str(method).upper()
            if not re.fullmatch(r"[A-Z][A-Z0-9_-]{0,31}", method):
                method = None
        row = {"url": clean, "method": method, "protocol": protocol, "operation_name": operation_name,
               "content_type": _media(content_type), "inputs": _dedupe_inputs(inputs),
               "sources": [self.source(locator, trust)], **extra}
        if method and method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            self.limit("method_requires_specialized_executor", locator)
            candidate = True
        if protocol == "graphql" and not operation_name:
            self.limit("graphql_operation_name_unresolved", locator)
            candidate = True
        if extra.get("path_template"):
            self.limit("path_template_requires_resource_binding", locator)
        if candidate or not method:
            self.candidate({"kind": "operation_hint", **row})
            return
        key = clean, method, protocol, operation_name, row["content_type"]
        if key in self.operations:
            known = self.operations[key]
            known["inputs"] = _dedupe_inputs(known["inputs"] + row["inputs"])
            if row["sources"][0] not in known["sources"]:
                known["sources"].extend(row["sources"])
        else:
            if len(self.candidates) + len(self.operations) >= MAX_ROWS:
                raise ValueError("discovery row budget exceeded")
            self.operations[key] = row

    def result(self):
        return {"operations": list(self.operations.values()), "candidates": self.candidates, "limitations": self.limitations}


def _input(name, location, selector, source, **extra):
    return {"name": name, "location": location, "selector": selector, "source": source, "consumer": "unknown", **extra}


def _dedupe_inputs(inputs):
    found = {}
    for field in inputs:
        if not _name(field.get("name")):
            continue
        key = field["name"], field["location"], field["selector"], field.get("schema_branch", "")
        found.setdefault(key, field)
        if len(found) > 2048:
            raise ValueError("operation input budget exceeded")
    return list(found.values())


def _json_fields(value, source, out, locator, location="body", pointer="", depth=0):
    out.tick(depth)
    rows = []
    if isinstance(value, dict):
        for name, child in value.items():
            if not _name(name):
                continue
            child_pointer = pointer + "/" + _pointer(name)
            if isinstance(child, (dict, list)) and child:
                rows.extend(_json_fields(child, source, out, locator, location, child_pointer, depth + 1))
            else:
                rows.append(_input(name, location, child_pointer, source))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_pointer = pointer + "/" + str(index)
            if isinstance(child, (dict, list)):
                rows.extend(_json_fields(child, source, out, locator, location, child_pointer, depth + 1))
            else:
                rows.append(_input(pointer.rsplit("/", 1)[-1] or "$item", location, child_pointer, source))
    return rows


def _graphql_document(query):
    """Extract top-level operation names, without claiming schema validation.

    Ignore comments and string contents so words/braces in values cannot select
    an operation. Multiple definitions stay unresolved without operationName.
    """
    if not isinstance(query, str) or len(query) > MAX_BYTES:
        return None
    stripped = re.sub(r'"""(?:\\.|[^\\])*?"""|"(?:\\.|[^"\\])*"|#[^\r\n]*',
                      lambda match: '""' if match[0].startswith('"') else "", query)
    tokens = []
    for match in re.finditer(r"[A-Za-z_][A-Za-z0-9_]*|[^\s,\ufeff]", stripped):
        tokens.append(match[0])
        if len(tokens) > MAX_NODES:
            return None
    names, cursor = [], 0
    while cursor < len(tokens):
        keyword = tokens[cursor]
        if keyword not in {"query", "mutation", "subscription", "fragment", "{"}:
            return None
        name = ""
        if keyword != "{":
            cursor += 1
            if cursor < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tokens[cursor]):
                name = tokens[cursor]
                cursor += 1
        stack = []
        while cursor < len(tokens):
            token = tokens[cursor]
            if token == "{" and not stack:
                break
            if token in {"(", "[", "{"}:
                stack.append(token)
            elif token in {")", "]", "}"}:
                if not stack or stack.pop() != {")": "(", "]": "[", "}": "{"}[token]:
                    return None
            cursor += 1
        if cursor == len(tokens):
            return None
        depth = 1
        cursor += 1
        while cursor < len(tokens) and depth:
            depth += (tokens[cursor] == "{") - (tokens[cursor] == "}")
            cursor += 1
        if depth:
            return None
        if keyword != "fragment":
            names.append(name if len(name) <= 128 else "")
    return names if names else None


def _graphql_identity(query, explicit_name, out, locator):
    names = _graphql_document(query)
    explicit = explicit_name if isinstance(explicit_name, str) and re.fullmatch(r"[A-Za-z_]\w{0,127}", explicit_name, re.ASCII) else ""
    if not explicit and names is None:
        return False, ""
    out.limit("graphql_selection_requires_review", locator)
    if explicit and names is not None and explicit not in names:
        out.limit("graphql_operation_selection_mismatch", locator)
        return True, ""
    if explicit:
        return True, explicit
    return True, names[0] if len(names) == 1 else ""


def _body(text, mime, source, out, locator):
    if text is None or text == "":
        return [], "http", ""
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_BYTES:
        out.limit("unsupported_request_body", locator)
        return [], "http", ""
    if mime == "application/x-www-form-urlencoded":
        try:
            return [_input(name, "body", name, source) for name, _ in parse_qsl(text, keep_blank_values=True, max_num_fields=2048) if _name(name)], "http", ""
        except ValueError:
            out.limit("form_input_budget_exceeded", locator)
            return [], "http", ""
    if mime == "application/graphql":
        _, name = _graphql_identity(text, None, out, locator)
        out.limit("graphql_variable_definitions_require_review", locator)
        return [], "graphql", name
    if "json" in mime or text.lstrip().startswith(("{", "[")):
        try:
            obj = json.loads(text)
        except (ValueError, RecursionError):
            out.limit("unparseable_or_truncated_json_body", locator)
            return [], "http", ""
        if isinstance(obj, dict) and ("query" in obj or "operationName" in obj) and isinstance(obj.get("variables", {}), dict):
            graphql, name = _graphql_identity(obj.get("query"), obj.get("operationName"), out, locator)
            if graphql:
                return _json_fields(obj.get("variables", {}), source, out, locator, "graphql", "/variables"), "graphql", name
        return _json_fields(obj, source, out, locator), "http", ""
    out.limit("body_format_requires_review", locator)
    return [], "http", ""


def _openapi(spec, base_url, out):
    if not isinstance(spec, dict) or not str(spec.get("openapi", "")).startswith("3."):
        raise ValueError("openapi requires an OpenAPI 3.x JSON document")

    def resolve(node, locator, chain=()):
        out.tick(len(chain))
        if not isinstance(node, dict):
            return {}
        ref = node.get("$ref")
        if ref is None:
            return node
        if not isinstance(ref, str) or not ref.startswith("#/"):
            out.limit("external_reference_not_loaded", locator)
            return {}
        if ref in chain or len(chain) >= MAX_DEPTH:
            out.limit("recursive_reference_requires_review", locator)
            return {}
        target = spec
        try:
            for part in ref[2:].split("/"):
                target = target[part.replace("~1", "/").replace("~0", "~")]
        except (KeyError, TypeError):
            out.limit("unresolved_local_reference", locator)
            return {}
        target = resolve(target, locator, (*chain, ref))
        return {**target, **{k: v for k, v in node.items() if k != "$ref"}}

    def bases(node, inherited, locator):
        if "servers" not in node:
            return inherited
        if not isinstance(node["servers"], list):
            raise ValueError("OpenAPI servers must be an array")
        result = []
        for i, server in enumerate(node["servers"]):
            value = server.get("url") if isinstance(server, dict) else None
            at = locator + "/servers/" + str(i)
            if not isinstance(value, str) or "{" in value or "}" in value:
                out.limit("server_variable_requires_explicit_resolution", at)
            else:
                try:
                    url, _ = _url(value, base_url)
                    result.append(url)
                except (ValueError, UnicodeError):
                    out.limit("server_url_requires_base_url", at)
        return result

    def fields(raw, locator, pointer="", name="", required=False, branch="", refs=(), depth=0, inherited_required=()):
        out.tick(depth)
        if not isinstance(raw, dict):
            return []
        ref = raw.get("$ref")
        if ref in refs:
            out.limit("recursive_schema_reference", locator)
            return []
        node = resolve(raw, locator)
        refs = (*refs, ref) if ref else refs
        rows = []
        required_names = node.get("required", [])
        if not isinstance(required_names, list):
            raise ValueError("schema required must be an array")
        required_names = set(x for x in required_names if isinstance(x, str)) | set(inherited_required)
        # allOf combines constraints on the same instance, even when the
        # required array and properties appear in different sibling schemas.
        for child in node.get("allOf", []) if isinstance(node.get("allOf", []), list) else []:
            child_required = resolve(child, locator).get("required", [])
            if isinstance(child_required, list):
                required_names.update(x for x in child_required if isinstance(x, str))
        for union in ("allOf", "oneOf", "anyOf"):
            variants = node.get(union, [])
            if not isinstance(variants, list):
                raise ValueError("schema composition must be an array")
            for i, child in enumerate(variants):
                child_at = locator + "/" + union + "/" + str(i)
                rows.extend(fields(child, child_at, pointer, name, required,
                                   child_at if union != "allOf" else branch, refs, depth + 1, required_names))
        props = node.get("properties", {})
        if not isinstance(props, dict):
            raise ValueError("schema properties must be an object")
        for key, child in props.items():
            if _name(key):
                rows.extend(fields(child, locator + "/properties/" + _pointer(key),
                                   pointer + "/" + _pointer(key), key, key in required_names, branch, refs, depth + 1))
        if "items" in node:
            children = fields(node["items"], locator + "/items", pointer + "/0", name or "$item", required, branch, refs, depth + 1)
            for child in children:
                child["array_template"] = True
            rows.extend(children)
        if node.get("additionalProperties") is True or isinstance(node.get("additionalProperties"), dict):
            out.limit("dynamic_property_names_require_runtime_observation", locator)
        if name and not props and "items" not in node and not any(node.get(c) for c in ("allOf", "oneOf", "anyOf")):
            schema_type = node.get("type")
            if not isinstance(schema_type, (str, list)):
                schema_type = "unknown"
            rows.append(_input(name, "body", pointer, "declared", required=required,
                               schema_type=schema_type, schema_branch=branch, schema_locator=locator))
        return rows

    default_bases = []
    if base_url:
        try:
            base, _ = _url("/", base_url)
            default_bases = [base]
        except (ValueError, UnicodeError):
            pass
    global_bases = bases(spec, default_bases, "#")
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI paths must be an object")
    for path, raw_path in paths.items():
        out.tick()
        at = "#/paths/" + _pointer(path)
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path:
            out.limit("invalid_path_template", at)
            continue
        item = resolve(raw_path, at)
        path_bases = bases(item, global_bases, at)
        for method, raw_op in item.items():
            if method not in METHODS or not isinstance(raw_op, dict):
                continue
            op_at = at + "/" + method
            op = resolve(raw_op, op_at)
            params = {}
            for param_owner in (item, op):
                if not isinstance(param_owner.get("parameters", []), list):
                    raise ValueError("OpenAPI parameters must be an array")
                for i, raw in enumerate(param_owner.get("parameters", [])):
                    param = resolve(raw, op_at + "/parameters/" + str(i))
                    name, location = param.get("name"), param.get("in")
                    if _name(name) and location in {"query", "path", "header", "cookie"}:
                        params[location, name] = _input(name, location, name, "declared", required=param.get("required") is True)
            request = resolve(op.get("requestBody", {}), op_at + "/requestBody")
            content = request.get("content", {})
            if not isinstance(content, dict):
                raise ValueError("requestBody content must be an object")
            variants = []
            for mime, media in content.items():
                if not isinstance(media, dict):
                    continue
                body_at = op_at + "/requestBody/content/" + _pointer(mime) + "/schema"
                body_fields = fields(media.get("schema", {}), body_at)
                variants.append((mime, body_fields))
            if not variants:
                variants = [("", [])]
            op_bases = bases(op, path_bases, op_at)
            if not op_bases:
                out.limit("operation_has_no_resolved_server", op_at)
            for base in op_bases:
                for mime, body_fields in variants:
                    security = op.get("security", spec.get("security", []))
                    out.operation(base.rstrip("/") + path, method, list(params.values()) + body_fields,
                                  op_at, "declared", content_type=mime,
                                  auth="authenticated" if isinstance(security, list) and security and all(isinstance(alt, dict) and alt for alt in security) else "unknown",
                                  path_template="{" in path or "}" in path)
    out.limit("specification_is_not_runtime_evidence")


def _har(doc, base_url, out):
    entries = doc.get("log", {}).get("entries") if isinstance(doc, dict) and isinstance(doc.get("log"), dict) else None
    if not isinstance(entries, list):
        raise ValueError("har requires log.entries array")
    for index, entry in enumerate(entries):
        out.tick()
        at = "#/log/entries/" + str(index)
        req = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(req, dict):
            out.limit("missing_har_request", at)
            continue
        trust = "mock" if entry.get("_capture_mode") == "mock" else "observed"
        src = "observed" if trust == "observed" else "inferred"
        post = req.get("postData") or {}
        if not isinstance(post, dict):
            post = {}
        mime = _media(post.get("mimeType"))
        for header in req.get("headers", []):
            if isinstance(header, dict) and str(header.get("name", "")).lower() == "content-type" and not mime:
                mime = _media(header.get("value"))
        fields, protocol, name = _body(post.get("text"), mime, src, out, at + "/request/postData")
        for header in req.get("headers", []):
            if isinstance(header, dict) and _name(header.get("name")):
                fields.append(_input(header["name"], "header", header["name"].lower(), src))
        for cookie in req.get("cookies", []):
            if isinstance(cookie, dict) and _name(cookie.get("name")):
                fields.append(_input(cookie["name"], "cookie", cookie["name"], src))
        for param in post.get("params", []):
            if isinstance(param, dict) and _name(param.get("name")):
                fields.append(_input(param["name"], "body", param["name"], src))
        for param in req.get("queryString", []):
            if isinstance(param, dict) and _name(param.get("name")):
                fields.append(_input(param["name"], "query", param["name"], src))
        out.operation(req.get("url"), req.get("method"), fields, at, trust, base_url,
                      content_type=mime, protocol=protocol, operation_name=name, candidate=trust == "mock")
    out.limit("imported_har_is_not_a_verified_assessment_run")


def _artex(doc, base_url, out):
    if not isinstance(doc, dict):
        raise ValueError("artex requires an export object")
    if not any(key in doc for key in ("rec", "__API_RECON_DETAIL__", "ws", "wsEndpoints", "sse")):
        raise ValueError("artex export has no supported discovery records")
    base = base_url or (doc.get("shell", {}).get("url") if isinstance(doc.get("shell"), dict) else None)
    rows = doc.get("rec", doc.get("__API_RECON_DETAIL__", []))
    if not isinstance(rows, list):
        raise ValueError("artex request records must be an array")
    route_contexts = {}
    per_route = doc.get("perRoute", {})
    if isinstance(per_route, dict):
        for route, requests in per_route.items():
            out.tick()
            try:
                page_url, _ = _url(route, base)
            except (ValueError, UnicodeError):
                continue
            if not isinstance(requests, list):
                continue
            for request in requests:
                out.tick()
                if not isinstance(request, str) or " " not in request:
                    continue
                request_method, request_url = request.split(" ", 1)
                try:
                    request_url, _ = _url(request_url, base)
                except (ValueError, UnicodeError):
                    continue
                context = route_contexts.setdefault((request_method.upper(), request_url), set())
                if len(context) < 100:
                    context.add(page_url)
    global_mode = doc.get("capture_mode", "unknown")
    for index, row in enumerate(rows):
        out.tick()
        at = ("#/rec/" if "rec" in doc else "#/__API_RECON_DETAIL__/") + str(index)
        if not isinstance(row, dict):
            out.limit("invalid_runtime_record", at)
            continue
        mode = row.get("capture_mode", global_mode)
        mock = global_mode == "mock" or mode == "mock" or row.get("source") == "mock"
        trust = "mock" if mock else "observed" if mode == "observed" else "unknown"
        src = "observed" if trust == "observed" else "inferred"
        text = row.get("b", row.get("reqBody"))
        # The ARTEX stock exporter caps b at 400 characters and does not record
        # whether its synthesized environment or response rewriting was active.
        if isinstance(text, str) and "b" in row and len(text) >= 400:
            out.limit("request_body_may_be_truncated", at)
        mime = ""
        for key, value in (row.get("reqHeaders") or {}).items() if isinstance(row.get("reqHeaders"), dict) else []:
            if key.lower() == "content-type":
                mime = _media(value)
        fields, protocol, name = _body(text, mime, src, out, at)
        raw_url = row.get("full") or row.get("url") or row.get("u")
        raw_method = row.get("m", row.get("method"))
        contexts = []
        try:
            resolved_url, _ = _url(raw_url, base)
            contexts = sorted(route_contexts.get((str(raw_method).upper(), resolved_url), []))
        except (ValueError, UnicodeError):
            pass
        out.operation(raw_url, raw_method, fields, at, trust, base, content_type=mime, protocol=protocol,
                      operation_name=name, candidate=trust != "observed", **({"contexts": contexts} if contexts else {}))
    for key, protocol in (("wsEndpoints", "websocket"), ("ws", "websocket"), ("sse", "sse")):
        values = doc.get(key, [])
        if not isinstance(values, list):
            out.limit("invalid_protocol_endpoint_list", "#/" + key)
            continue
        for index, raw in enumerate(values):
            out.tick()
            at = "#/" + key + "/" + str(index)
            if key == "ws" and isinstance(raw, dict):
                raw = raw.get("url")
            if not isinstance(raw, str):
                continue
            try:
                if protocol == "websocket":
                    ws_base = re.sub(r"^http", "ws", base or "")
                    url, _ = _url(raw, ws_base, ("ws", "wss"))
                else:
                    url, _ = _url(raw, base)
            except (ValueError, UnicodeError):
                out.limit("unresolved_protocol_endpoint", at)
                continue
            out.candidate({"kind": "protocol_hint", "url": url, "protocol": protocol,
                           "sources": [out.source(at, "mock" if global_mode == "mock" else "unknown")]})
    out.limit("artex_export_may_contain_simulated_or_modified_traffic")
    out.limit("artex_response_samples_are_not_confirmation_evidence")


def _sarif(doc, out):
    if not isinstance(doc, dict) or not str(doc.get("version", "")).startswith("2.") or not isinstance(doc.get("runs"), list):
        raise ValueError("sarif requires a SARIF 2.x document with runs")

    def safe_uri(value):
        if not isinstance(value, str) or not 0 < len(value) <= 4096 or any(ord(c) < 32 for c in value):
            return None
        try:
            parsed = urlsplit(value)
            if parsed.username is not None or parsed.password is not None:
                return None
            # Only a source location is imported; never resolve or read this URI.
            return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        except ValueError:
            return None

    def physical_location(location, artifacts):
        if not isinstance(location, dict) or not isinstance(location.get("physicalLocation"), dict):
            return None
        physical = location["physicalLocation"]
        artifact = physical.get("artifactLocation")
        if not isinstance(artifact, dict):
            return None
        index = artifact.get("index")
        referenced = artifacts[index] if type(index) is int and 0 <= index < len(artifacts) else {}
        if not isinstance(referenced, dict):
            referenced = {}
        referenced_location = referenced.get("location", {})
        if not isinstance(referenced_location, dict):
            referenced_location = {}
        uri = safe_uri(artifact.get("uri", referenced_location.get("uri")))
        if not uri:
            return None
        row = {"uri": uri}
        region = physical.get("region")
        if isinstance(region, dict) and type(region.get("startLine")) is int and region["startLine"] > 0:
            row["line"] = region["startLine"]
        referenced_uri = safe_uri(referenced_location.get("uri"))
        hashes = referenced.get("hashes") if referenced_uri == uri else None
        if isinstance(hashes, dict):
            digest = hashes.get("sha-256", hashes.get("sha256"))
            if isinstance(digest, str) and re.fullmatch(r"[0-9A-Fa-f]{64}", digest):
                row["declared_artifact_sha256"] = digest.lower()
        return row

    for run_index, run in enumerate(doc["runs"]):
        out.tick()
        if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
            continue
        artifacts = run.get("artifacts", [])
        if not isinstance(artifacts, list):
            artifacts = []
        tool = run.get("tool", {})
        driver = tool.get("driver", {}) if isinstance(tool, dict) else {}
        tool_info = {}
        if isinstance(driver, dict):
            for key, value in (("name", driver.get("name")), ("version", driver.get("semanticVersion", driver.get("version")))):
                if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ /+()-]{0,127}", value):
                    tool_info[key] = value
        for index, finding in enumerate(run.get("results", [])):
            out.tick()
            at = f"#/runs/{run_index}/results/{index}"
            if not isinstance(finding, dict):
                continue
            locations = []
            raw_locations = finding.get("locations", [])
            if not isinstance(raw_locations, list):
                out.limit("invalid_sarif_locations", at)
                raw_locations = []
            if len(raw_locations) > 100:
                out.limit("sarif_locations_truncated", at)
            for location in raw_locations[:100]:
                out.tick()
                row = physical_location(location, artifacts)
                if row:
                    locations.append(row)
            call_paths = []
            code_flows = finding.get("codeFlows", [])
            if not isinstance(code_flows, list):
                out.limit("invalid_sarif_code_flows", at)
                code_flows = []
            for flow_index, flow in enumerate(code_flows[:100]):
                out.tick()
                threads = flow.get("threadFlows", []) if isinstance(flow, dict) else []
                if not isinstance(threads, list):
                    continue
                for thread_index, thread in enumerate(threads[:100]):
                    out.tick()
                    steps = thread.get("locations", []) if isinstance(thread, dict) else []
                    if not isinstance(steps, list):
                        continue
                    path = []
                    for step in steps[:200]:
                        out.tick()
                        row = physical_location(step.get("location"), artifacts) if isinstance(step, dict) else None
                        if row:
                            path.append(row)
                    complete = len(steps) <= 200 and len(path) == len(steps)
                    if not complete:
                        out.limit("sarif_call_path_incomplete", at)
                    if path:
                        call_paths.append({"locations": path, "complete": complete,
                                           "source_locator": f"{at}/codeFlows/{flow_index}/threadFlows/{thread_index}"})
                if len(threads) > 100:
                    out.limit("sarif_call_paths_truncated", at)
            if len(code_flows) > 100:
                out.limit("sarif_call_paths_truncated", at)
            rule = finding.get("ruleId")
            rule = rule if _name(rule) else "unknown"
            level = finding.get("level", "warning")
            out.candidate({"kind": "source_finding", "rule_id": rule,
                           "level": level if isinstance(level, str) and level in {"none", "note", "warning", "error"} else "warning",
                           "locations": locations, "sources": [out.source(at, "declared")],
                           **({"call_paths": call_paths} if call_paths else {}),
                           **({"analysis_tool": tool_info} if tool_info else {}),
                           "status": "unverified"})
    out.limit("sarif_findings_require_reachability_and_dynamic_verification")
    out.limit("sarif_messages_snippets_and_values_not_imported")


def _client_sink_candidates(rows, out):
    """Join syntactic field names, not taint or execution, within this one bundle."""
    by_name = {}
    for operation in out.operations.values():
        for entry in operation.get("inputs", []):
            by_name.setdefault(entry["name"], []).append((operation, entry))
    known_sinks = {"innerHTML.assignment", "innerHTML.object_property", "insertAdjacentHTML",
                   "location.href", "location.assign", "location.replace"}
    for row in rows:
        out.tick()
        if not isinstance(row, dict) or row.get("sink") not in known_sinks:
            continue
        at = row.get("locator", "#")
        names = sorted({name for name in row.get("referenced_fields", []) if _name(name)})[:64]
        bindings, seen = [], set()
        limited = False
        for name in names:
            for operation, entry in by_name.get(name, []):
                identity = (operation["url"], operation["method"], operation["protocol"], operation["operation_name"],
                            operation["content_type"], entry["location"], entry["selector"], entry.get("schema_branch"))
                if identity in seen:
                    continue
                seen.add(identity)
                if len(bindings) >= 50:
                    limited = True
                    continue
                sources = operation.get("sources", [])
                bindings.append({"url": operation["url"], "method": operation["method"],
                    "protocol": operation["protocol"], "operation_name": operation["operation_name"],
                    "content_type": operation["content_type"], "input_name": entry["name"],
                    "input_location": entry["location"], "input_selector": entry["selector"],
                    "schema_branch": entry.get("schema_branch"),
                    "request_locator": sources[0]["locator"] if sources else "#",
                    "request_locator_count": len(sources), "matching_basis": "same_bundle_field_name_only"})
        category = "html_execution" if row["sink"] in {"innerHTML.assignment", "innerHTML.object_property", "insertAdjacentHTML"} else "client_navigation"
        out.candidate({"kind": "client_sink", "sink": row["sink"], "category": category,
            "test_family": "xss" if category == "html_execution" else "generic",
            "referenced_fields": names, "possible_input_bindings": bindings,
            "binding_status": "ambiguous" if len(bindings) > 1 or limited else "possible" if bindings else "unresolved",
            "references_limited": row.get("references_limited") is True, "bindings_limited": limited,
            "value_kind": row.get("value_kind") if row.get("value_kind") in {"static", "reference", "dynamic"} else "dynamic",
            "source_line": row.get("source_line"), "source_column": row.get("source_column"),
            "sources": [out.source(at, "inferred")], "status": "unverified", "verification_level": "hint_only",
            "hints_only": True, "taint_proven": False, "consumer_declaration_allowed": False,
            "independent_evidence_required": True, "usable_for_confirmation": False, "requestable": False})
        if limited:
            out.limit("client_sink_input_bindings_truncated", at)
    if rows:
        out.limit("client_sink_name_matches_are_not_taint_or_runtime_proof")


def _javascript(text, base_url, out):
    node = shutil.which("node")
    helper = Path(__file__).resolve().parents[1] / "src" / "parse-js.mjs"
    if not node or not helper.is_file():
        out.limit("javascript_ast_parser_unavailable")
        return
    try:
        proc = subprocess.run([node, "--max-old-space-size=192", str(helper)],
                              input=json.dumps({"source": text}), text=True, encoding="utf-8",
                              capture_output=True, timeout=15, cwd=str(helper.parent.parent))
        if proc.returncode or len(proc.stdout.encode("utf-8")) > 16 * 1024 * 1024:
            out.limit("javascript_ast_parser_failed")
            return
        result = _bounded_json(proc.stdout)
        if not isinstance(result, dict):
            raise ValueError("invalid AST result")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        out.limit("javascript_ast_parser_failed")
        return
    for limitation in result.get("limitations", []):
        if isinstance(limitation, dict):
            out.limit(limitation.get("code", "javascript_analysis_incomplete"), limitation.get("locator", "#"))
    for row in result.get("operations", []) + result.get("candidates", []):
        out.tick()
        if not isinstance(row, dict):
            continue
        at = row.get("locator", "#")
        if not row.get("url"):
            out.candidate({"kind": "dynamic_request", "sources": [out.source(at, "unknown")], "reason": "unresolved_url_or_method"})
            continue
        fields = [_input(f["name"], f["location"], f["selector"], "inferred") for f in row.get("inputs", []) if isinstance(f, dict) and _name(f.get("name"))]
        out.operation(row["url"], row.get("method"), fields, at, "declared", base_url,
                      content_type=row.get("content_type", ""), protocol=row.get("protocol", "http"),
                      operation_name=row.get("operation_name", ""), candidate=not row.get("method"))
    _client_sink_candidates(result.get("client_sinks", []), out)
    out.limit("static_javascript_does_not_prove_runtime_reachability")


def discover(path, format, base_url=None):
    """Read one explicit local file and return non-executable discovery hints."""
    if format not in FORMATS:
        raise ValueError("unsupported discovery format")
    path = Path(path)
    if path.is_symlink() or path.name.lower().startswith(".env") or path.suffix.lower() in {".key", ".pem"}:
        raise ValueError("secret files and symbolic links are not discovery inputs")
    path = path.resolve(strict=True)
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("discovery input must be a file of at most 8 MiB")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("discovery input exceeds byte budget")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("discovery input must be UTF-8") from exc
    out = _Output(path, raw)
    if format == "javascript":
        _javascript(text, base_url, out)
    else:
        doc = _bounded_json(text)
        if format == "openapi":
            _openapi(doc, base_url, out)
        elif format == "har":
            _har(doc, base_url, out)
        elif format == "artex":
            _artex(doc, base_url, out)
        elif format == "sarif":
            _sarif(doc, out)
        else:
            from .assessment_hints import ingest
            ingest(doc, base_url, out)
    return out.result()
