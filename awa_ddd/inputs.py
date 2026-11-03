"""Unambiguous input views over captured requests; never interpret XML entities."""
from __future__ import annotations

import base64
from copy import deepcopy
import json
import math
import re
from urllib.parse import parse_qsl, urlsplit

from .scope import bind_operation
from .store import EngineError
from .transport import headers_map


def _ambiguous(message):
    raise EngineError("input_ambiguous", message, {"blocked": True})


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _ambiguous("Duplicate JSON keys do not identify one input")
        result[key] = value
    return result


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("Non-finite JSON number")
    return result


def json_document(raw):
    """Decode UTF-8 JSON without duplicate keys or non-finite numbers."""
    try:
        text = raw.decode("utf-8-sig") if isinstance(raw, bytes) else raw
        return json.loads(text, object_pairs_hook=_unique_pairs, parse_float=_finite_float,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        if isinstance(exc, EngineError):
            raise
        raise EngineError("input_binding", "The body is not unambiguous finite UTF-8 JSON") from exc


def locate_json(document, selector):
    """Plain names select root object fields; nested fields need an exact Pointer."""
    if not isinstance(selector, str) or re.search(r"~(?![01])", selector) and selector.startswith("/"):
        raise EngineError("input_binding", "Use a root field name or an exact JSON Pointer")
    if selector in {"", "$"}:
        return document, ()
    tokens = tuple(token.replace("~1", "/").replace("~0", "~") for token in selector[1:].split("/")) \
        if selector.startswith("/") else (selector,)
    if len(tokens) > 64:
        raise EngineError("input_binding", "The input Pointer exceeds the depth budget")
    value = document
    try:
        for token in tokens:
            if isinstance(value, list):
                if not re.fullmatch(r"0|[1-9][0-9]*", token):
                    raise ValueError()
                value = value[int(token)]
            elif isinstance(value, dict):
                value = value[token]
            else:
                raise ValueError()
    except (KeyError, ValueError, TypeError, IndexError) as exc:
        raise EngineError("input_binding", "The input selector does not identify one concrete JSON value") from exc
    return value, tokens


def parse_form(raw):
    """Return exact, unique UTF-8 URL-encoded fields, preserving their order."""
    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        if not isinstance(text, str) or re.search(r"%(?![0-9A-Fa-f]{2})", text):
            raise ValueError()
        pairs = parse_qsl(text, keep_blank_values=True, encoding="utf-8", errors="strict",
                          max_num_fields=4096)
        if len({key for key, value in pairs}) != len(pairs):
            _ambiguous("Repeated encoded field names do not identify one input")
        return pairs
    except (ValueError, UnicodeError, TypeError) as exc:
        if isinstance(exc, EngineError):
            raise
        raise EngineError("input_binding", "Encoded fields must be unambiguous UTF-8") from exc


_MIME_TOKEN = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_MIME_WHITESPACE = rb"(?:[ \t]|\r\n[ \t]+)*"


def _multipart_framing(issue="invalid_multipart"):
    bom = issue == "utf8_bom"
    raise EngineError("multipart_framing",
                      "Multipart starts with a UTF-8 BOM; rewrite the source without BOM and preflight the exact bytes"
                      if bom else "Multipart needs exact CRLF framing, one declared boundary and a closing delimiter",
                      {"blocked": True, "validation_stage": "multipart_framing", "next_action": "http.preflight",
                       "help_input": {"name": "http.capture"}, "framing_issue": issue,
                       "repair": "rewrite_utf8_without_bom" if bom else "rebuild_exact_multipart"})


def _mime_parameters(raw, expected):
    """Parse unique MIME parameters while retaining the original value spans."""
    first = raw.find(b";")
    prefix = raw if first < 0 else raw[:first]
    if prefix.strip().lower() != expected:
        _ambiguous("Multipart header has an unexpected media type or disposition")
    params, position = {}, len(raw) if first < 0 else first
    whitespace = re.compile(_MIME_WHITESPACE)
    while position < len(raw):
        position = whitespace.match(raw, position).end()
        if position == len(raw):
            break
        if raw[position:position + 1] != b";":
            _ambiguous("Multipart parameters must use an unambiguous MIME grammar")
        position = whitespace.match(raw, position + 1).end()
        key_match = re.compile(_MIME_TOKEN).match(raw, position)
        if not key_match:
            _ambiguous("Multipart parameters need exact names")
        key = key_match.group().decode("ascii").lower()
        if key in params or key.startswith(("name*", "filename*", "boundary*")):
            _ambiguous("Repeated or encoded multipart disposition parameters are not exact inputs")
        position = whitespace.match(raw, key_match.end()).end()
        if raw[position:position + 1] != b"=":
            _ambiguous("Multipart parameters need one explicit value")
        position = whitespace.match(raw, position + 1).end()
        start = position
        if raw[position:position + 1] == b'"':
            position += 1
            value = bytearray()
            while position < len(raw) and raw[position:position + 1] != b'"':
                byte = raw[position]
                if byte == 92:
                    position += 1
                    if position == len(raw):
                        _ambiguous("Multipart quoted parameters must be complete")
                    byte = raw[position]
                if byte < 32 and byte != 9 or byte == 127:
                    _ambiguous("Multipart parameter values cannot contain control characters")
                value.append(byte)
                position += 1
            if raw[position:position + 1] != b'"':
                _ambiguous("Multipart quoted parameters must be complete")
            position += 1
            value = bytes(value)
        else:
            value_match = re.compile(_MIME_TOKEN).match(raw, position)
            if not value_match:
                _ambiguous("Multipart parameter values must be tokens or quoted strings")
            value, position = value_match.group(), value_match.end()
        params[key] = {"value": value, "span": (start, position)}
    return params


def _multipart_headers(raw):
    if re.search(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", raw):
        _ambiguous("Multipart headers cannot contain control characters")
    entries, offset, current = {}, 0, None
    for line in raw.split(b"\r\n"):
        if b"\r" in line or b"\n" in line:
            _ambiguous("Multipart headers must use CRLF line endings")
        if line[:1] in {b" ", b"\t"}:
            if current is None:
                _ambiguous("Multipart header continuation has no header")
            entries[current][1] = offset + len(line)
        else:
            name, colon, value = line.partition(b":")
            if not colon or not re.fullmatch(_MIME_TOKEN, name):
                _ambiguous("Multipart part headers must use exact field names")
            current = name.decode("ascii").lower()
            if current in entries:
                _ambiguous("Repeated multipart part headers cannot identify an exact input")
            entries[current] = [offset + len(name) + 1, offset + len(line)]
        offset += len(line) + 2
    return entries


def parse_multipart(raw, content_type):
    """Strict, lossless multipart parsing shared by execution and experiment gates."""
    if not isinstance(raw, bytes) or not isinstance(content_type, str) or "\r" in content_type or "\n" in content_type:
        _multipart_framing()
    # A BOM before the first delimiter is not a MIME line-start preamble. Never
    # strip it silently: execution and later assessment must see identical bytes.
    if raw.startswith(b"\xef\xbb\xbf--"):
        _multipart_framing("utf8_bom")
    try:
        media_raw = content_type.encode("ascii")
    except UnicodeError:
        _multipart_framing()
    parameters = _mime_parameters(media_raw, b"multipart/form-data")
    if "boundary" not in parameters:
        _multipart_framing()
    boundary = parameters["boundary"]["value"]
    if not 1 <= len(boundary) <= 70 or boundary.endswith(b" ") \
            or re.search(rb"[^0-9A-Za-z'()+_,\-./:=? ]", boundary):
        _multipart_framing()
    delimiter_pattern = (rb"(?P<lead>\A|\r\n)--" + re.escape(boundary)
                         + rb"(?P<close>--)?(?P<padding>[ \t]*)(?P<ending>\r\n|\Z)")
    delimiters = list(re.finditer(delimiter_pattern, raw))
    if len(delimiters) < 2 or delimiters[0].group("close") or not delimiters[-1].group("close") \
            or any(entry.group("close") or entry.group("ending") != b"\r\n" for entry in delimiters[:-1]):
        _multipart_framing()
    parts = {}
    for left, right in zip(delimiters, delimiters[1:]):
        start, end = left.end(), right.start()
        separator = raw.find(b"\r\n\r\n", start, end)
        if separator < 0:
            _multipart_framing()
        header_raw = raw[start:separator]
        headers = _multipart_headers(header_raw)
        if "content-disposition" not in headers:
            _ambiguous("Multipart parts need one form-data disposition")
        disposition_start, disposition_end = headers["content-disposition"]
        disposition = _mime_parameters(header_raw[disposition_start:disposition_end], b"form-data")
        if "name" not in disposition:
            _ambiguous("Multipart disposition must identify one exact field")
        try:
            name = disposition["name"]["value"].decode("utf-8", errors="strict")
            filename = disposition["filename"]["value"].decode("utf-8", errors="strict") if "filename" in disposition else None
        except UnicodeError as exc:
            raise EngineError("input_binding", "Multipart field names and filenames require intact UTF-8; binary content stays raw") from exc
        if not name or name in parts:
            _ambiguous("Repeated multipart fields cannot be used as input controls")
        filename_span = disposition.get("filename", {}).get("span")
        parts[name] = {"name": name, "filename": filename, "content_span": (separator + 4, end),
                       "headers_span": (start, separator), "headers_raw": header_raw,
                       "filename_span": tuple(start + disposition_start + position for position in filename_span)
                       if filename_span else None}
    first_marker = delimiters[0].start() + len(delimiters[0].group("lead"))
    normalized_delimiters = [entry.group("lead") + b"--<multipart-boundary>" + (entry.group("close") or b"")
                             + entry.group("padding") + entry.group("ending") for entry in delimiters]
    boundary_start, boundary_end = parameters["boundary"]["span"]
    return {"parts": parts, "preamble": raw[:first_marker], "epilogue": raw[delimiters[-1].end():],
            "normalized_delimiters": normalized_delimiters,
            "content_type_context": (media_raw[:boundary_start] + b"<multipart-boundary>" + media_raw[boundary_end:]).decode("ascii")}


def multipart_selection(parsed, raw, selector):
    """Select an exact part body or filename; aliases must have one interpretation."""
    parts, choices = parsed["parts"], []
    if selector in parts:
        choices.append((parts[selector], "content"))
    if selector.endswith((".filename", ".content")):
        field, component = selector.rsplit(".", 1)
        if field in parts and (component == "content" or parts[field]["filename"] is not None):
            choices.append((parts[field], component))
    if selector == "filename" or selector == "file.filename" and not any(
            part["name"] == "file" and component == "filename" for part, component in choices):
        choices.extend((part, "filename") for part in parts.values() if part["filename"] is not None)
    if selector == "content" or selector == "file.content" and not any(
            part["name"] == "file" and component == "content" for part, component in choices):
        choices.extend((part, "content") for part in parts.values())
    choices = list({(part["name"], component): (part, component) for part, component in choices}.values())
    if len(choices) > 1:
        _ambiguous("Multipart selector has multiple part or attribute interpretations; use an exact part selector")
    if not choices:
        raise EngineError("input_binding", "The declared multipart input identifies no exact part or filename")
    part, component = choices[0]
    span = part["filename_span"] if component == "filename" else part["content_span"]
    value = part["filename"] if component == "filename" else raw[span[0]:span[1]]
    return part, component, span, value


def _multipart(raw, content_type):
    return {name: part["content_span"] for name, part in parse_multipart(raw, content_type)["parts"].items()}


class _MultipartInputContext(dict):
    def __init__(self, context, media_type):
        super().__init__(context)
        self._adapter = "multipart"
        self._media_type = media_type


def control_context(context):
    """Compare parsed parts, not their changing wire boundary or saved byte slices."""
    # Adapter provenance is created locally, not inferred from target JSON keys.
    if type(context) is not _MultipartInputContext or context._adapter != "multipart" \
            or context._media_type != "multipart/form-data":
        return context
    media = (context.get("headers", {}).get("content-type") or "").split(";", 1)[0].lower().strip()
    body = context.get("body") if isinstance(context, dict) else None
    if media != "multipart/form-data" or not isinstance(body, dict) \
            or body.get("format") != "multipart" or "control_parts" not in body:
        return context
    return {**context, "body": {key: value for key, value in body.items()
                               if key not in {"prefix_base64", "suffix_base64"}}}


def _declared_root(item, operation):
    return any(entry.get("location") == item.get("input_location")
               and entry.get("selector", entry.get("name")) in {"", "$"}
               and entry.get("schema_branch") == item.get("schema_branch")
               for entry in operation.get("inputs", []))


def _json_view(raw, item, operation):
    document = json_document(raw)
    value, tokens = locate_json(document, item["input_selector"])
    if not tokens:
        if not _declared_root(item, operation):
            raise EngineError("input_binding", "Whole JSON input controls require an explicitly declared root selector")
        return value, None
    masked = deepcopy(document)
    parent = masked
    for token in tokens[:-1]:
        parent = parent[int(token)] if isinstance(parent, list) else parent[token]
    parent[int(tokens[-1]) if isinstance(parent, list) else tokens[-1]] = None
    return value, masked


def _cookie_view(raw, selector):
    found = None
    names = set()
    for match in re.finditer(r"[^;]+", raw):
        chunk = match.group(0)
        name, equals, value = chunk.partition("=")
        name = name.strip()
        if not equals or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or name in names:
            _ambiguous("Cookie controls require exact, unique cookie names")
        names.add(name)
        if name == selector:
            start = match.start() + chunk.index("=") + 1
            end = match.end()
            found = (value, raw[:start] + "<bound-input>" + raw[end:])
    if found is None:
        raise EngineError("input_binding", "The named cookie must occur exactly once")
    return found


def input_view(request, item, operation):
    """Return (selected value, JSON-serializable context with only that value masked).

    Multipart values are bytes; all non-selected bytes remain in the base64 context.
    GET/query context intentionally retains the pre-existing assessment API shape.
    """
    try:
        url = urlsplit(request["url"])
        parameters = bind_operation(operation, request["url"], request["method"])
        headers = {key: value for key, value in headers_map(request.get("headers", {})).items()
                   if key not in {"content-length", "connection"}}
        raw = base64.b64decode(request.get("body_base64", ""), validate=True)
        query = sorted(parse_form(url.query))
        try:
            body = raw.decode("utf-8")
        except UnicodeError:
            body = {"format": "bytes", "body_base64": base64.b64encode(raw).decode("ascii")}
        path = url.path
        location, selector = item["input_location"], item["input_selector"]
        multipart_context = False
        if location == "query":
            values = [value for key, value in query if key == selector]
            if len(values) != 1:
                raise ValueError()
            value = values[0]
            query = [(key, value) for key, value in query if key != selector]
        elif location == "path":
            value = parameters.pop(selector)
            path = [operation["url"], parameters]
        elif location in {"body", "graphql"}:
            media = (headers.get("content-type") or operation.get("content_type", "")).split(";", 1)[0].lower().strip()
            if media == "application/x-www-form-urlencoded":
                fields = parse_form(raw)
                values = [value for key, value in fields if key == selector]
                if len(values) != 1:
                    raise ValueError()
                value = values[0]
                body = {"format": "form", "fields": [(key, other) for key, other in fields if key != selector]}
            elif media == "multipart/form-data":
                parsed = parse_multipart(raw, headers.get("content-type") or operation.get("content_type", ""))
                selected, component, (start, end), value = multipart_selection(parsed, raw, selector)
                if component == "filename":
                    declarations = [entry for entry in operation.get("inputs", [])
                                    if entry.get("location") == location
                                    and entry.get("selector", entry.get("name")) == selector
                                    and entry.get("schema_branch") == item.get("schema_branch")]
                    if len(declarations) != 1:
                        _ambiguous("Multipart filename controls require one exact declared input and schema branch")
                control_parts = []
                for part in parsed["parts"].values():
                    header_raw = part["headers_raw"]
                    content_start, content_end = part["content_span"]
                    if part is selected and component == "filename":
                        filename_start, filename_end = part["filename_span"]
                        header_start = part["headers_span"][0]
                        header_raw = (header_raw[:filename_start - header_start] + b"<bound-filename>"
                                      + header_raw[filename_end - header_start:])
                    control_parts.append({"headers_base64": base64.b64encode(header_raw).decode("ascii"),
                                          "content_base64": None if part is selected and component == "content"
                                          else base64.b64encode(raw[content_start:content_end]).decode("ascii")})
                body = {"format": "multipart", "prefix_base64": base64.b64encode(raw[:start]).decode("ascii"),
                        "suffix_base64": base64.b64encode(raw[end:]).decode("ascii"), "control_parts": control_parts,
                        "preamble_base64": base64.b64encode(parsed["preamble"]).decode("ascii"),
                        "epilogue_base64": base64.b64encode(parsed["epilogue"]).decode("ascii"),
                        "delimiters_base64": [base64.b64encode(entry).decode("ascii") for entry in parsed["normalized_delimiters"]]}
                if "content-type" in headers:
                    headers["content-type"] = parsed["content_type_context"]
                multipart_context = True
            elif media in {"application/xml", "text/xml"} or media.endswith("+xml") or raw.lstrip().startswith(b"<"):
                raise EngineError("input_adapter_blocked", "XML needs a dedicated unique input adapter; DTD and entities are never parsed locally",
                                  {"blocked": True, "next_action": "use_exact_multipart_field_or_dedicated_adapter"})
            elif not media or media == "application/json" or media.endswith("+json") or location == "graphql":
                value, body = _json_view(raw, item, operation)
            else:
                raise EngineError("input_adapter_blocked", "This body media type has no unique input experiment adapter", {"blocked": True})
        elif location == "header":
            if selector.lower() in {"host", "content-length", "transfer-encoding", "connection"}:
                raise EngineError("input_binding", "Transport framing is not a business input")
            value = headers.pop(selector.lower())
        elif location == "cookie":
            value, headers["cookie"] = _cookie_view(headers["cookie"], selector)
        else:
            raise EngineError("input_adapter_blocked", "This input location needs a dedicated experiment adapter", {"blocked": True})
        context = {"method": request["method"], "path": path, "query": query, "headers": headers, "body": body}
        if multipart_context:
            actual_media = (headers.get("content-type") or "").split(";", 1)[0].lower().strip()
            context = _MultipartInputContext(context, actual_media)
        return value, context
    except (KeyError, ValueError, TypeError, IndexError) as exc:
        if isinstance(exc, EngineError):
            raise
        raise EngineError("input_binding", "Controls must contain one concrete value at the tested input selector") from exc
