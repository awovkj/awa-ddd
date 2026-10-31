"""Unambiguous input views over captured requests; never interpret XML entities."""
from __future__ import annotations

import base64
from copy import deepcopy
from email.parser import BytesHeaderParser
from email import policy
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


def _multipart(raw, content_type):
    try:
        message = BytesHeaderParser(policy=policy.compat32).parsebytes(
            ("Content-Type: " + content_type + "\r\n\r\n").encode("ascii"))
        params = message.get_params([], header="content-type", unquote=True)[1:]
        boundaries = [value for key, value in params if key.lower() == "boundary"]
        if len(boundaries) != 1 or not isinstance(boundaries[0], str):
            _ambiguous("Multipart needs exactly one boundary parameter")
        boundary = boundaries[0].encode("ascii")
        if not 1 <= len(boundary) <= 70 or any(byte < 33 or byte > 126 for byte in boundary):
            raise ValueError()
        delimiters = list(re.finditer(rb"(?:\A|\r\n)--" + re.escape(boundary)
                                     + rb"(?:(--)(?:\r\n|$)|\r\n)", raw))
        if len(delimiters) < 2 or delimiters[0].start() != 0 or delimiters[0].group(1) \
                or not delimiters[-1].group(1) or delimiters[-1].end() != len(raw) \
                or any(part.group(1) for part in delimiters[:-1]):
            raise ValueError()
        parts = {}
        for left, right in zip(delimiters, delimiters[1:]):
            start, end = left.end(), right.start()
            separator = raw.find(b"\r\n\r\n", start, end)
            if separator < 0:
                raise ValueError()
            header = BytesHeaderParser(policy=policy.compat32).parsebytes(raw[start:separator] + b"\r\n\r\n")
            names = [name.lower() for name in header.keys()]
            if header.defects or len(set(names)) != len(names):
                _ambiguous("Multipart part headers are malformed or repeated")
            dispositions = header.get_all("content-disposition", [])
            if len(dispositions) != 1 or header.get_content_disposition() != "form-data":
                _ambiguous("Multipart parts need one form-data disposition")
            parameters = header.get_params([], header="content-disposition", unquote=True)[1:]
            field_names = [value for key, value in parameters if key.lower() == "name"]
            filenames = [value for key, value in parameters if key.lower() == "filename"]
            if len(field_names) != 1 or len(filenames) > 1 or not isinstance(field_names[0], str):
                _ambiguous("Multipart disposition parameters do not identify one exact field")
            name = field_names[0]
            if not name or name in parts:
                _ambiguous("Repeated multipart fields cannot be used as input controls")
            parts[name] = (separator + 4, end)
        return parts
    except (ValueError, UnicodeError, TypeError, IndexError) as exc:
        if isinstance(exc, EngineError):
            raise
        raise EngineError("input_binding", "Multipart framing is not unambiguous") from exc


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
                parts = _multipart(raw, headers.get("content-type") or operation.get("content_type", ""))
                start, end = parts[selector]
                value = raw[start:end]
                body = {"format": "multipart", "prefix_base64": base64.b64encode(raw[:start]).decode("ascii"),
                        "suffix_base64": base64.b64encode(raw[end:]).decode("ascii")}
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
        return value, {"method": request["method"], "path": path, "query": query, "headers": headers, "body": body}
    except (KeyError, ValueError, TypeError, IndexError) as exc:
        if isinstance(exc, EngineError):
            raise
        raise EngineError("input_binding", "Controls must contain one concrete value at the tested input selector") from exc
