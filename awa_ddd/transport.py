"""One bounded HTTP request, no retries, no proxy inheritance or redirects."""
from __future__ import annotations
import base64
import hashlib
import http.client
import json
import re
import socket
import ssl
import time
from urllib.parse import urlsplit
from .store import EngineError, now


def headers_map(headers):
    if not isinstance(headers, dict) or len(headers) > 128:
        raise EngineError("headers", "Headers must be a bounded object")
    result = {}
    for key, value in headers.items():
        if not isinstance(key, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
            raise EngineError("headers", "Invalid header name")
        if not isinstance(value, str) or "\r" in value or "\n" in value or "\x00" in value:
            raise EngineError("headers", "Invalid header value")
        if key.lower() in result:
            raise EngineError("headers", "Ambiguous duplicate header name")
        result[key.lower()] = value
    if sum(len(k) + len(v) for k, v in result.items()) > 64 * 1024:
        raise EngineError("headers", "Headers exceed budget")
    return result


def request(url, method="GET", headers=None, body=None, timeout=15, max_bytes=1024*1024):
    if type(timeout) not in (int, float) or not 0 < timeout <= 60 or type(max_bytes) is not int or not 1 <= max_bytes <= 4*1024*1024:
        raise EngineError("budget", "Invalid HTTP timeout or capture budget")
    method = method.upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise EngineError("method", "Unsupported HTTP method")
    u = urlsplit(url)
    hdrs = headers_map(headers or {})
    if any(k in hdrs for k in ("host", "content-length", "transfer-encoding", "connection")):
        raise EngineError("headers", "Transport framing headers are managed by the executor")
    if isinstance(body, (dict, list)):
        data = json.dumps(body, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        hdrs.setdefault("content-type", "application/json")
    elif body is None:
        data = None
    elif isinstance(body, bytes):
        data = body
    elif isinstance(body, str):
        data = body.encode("utf-8")
    else:
        raise EngineError("body", "Body must be JSON, text, bytes or null")
    if data is not None and len(data) > 1024*1024:
        raise EngineError("body_budget", "Request body exceeds budget")
    hdrs.update({"host":u.netloc,"accept-encoding":"identity","connection":"close"})
    if data is not None:
        hdrs["content-length"] = str(len(data))
    conn = (http.client.HTTPSConnection(u.hostname, u.port, timeout=timeout, context=ssl.create_default_context())
            if u.scheme == "https" else http.client.HTTPConnection(u.hostname, u.port, timeout=timeout))
    started, stamp, raw = time.monotonic(), now(), bytearray()
    result = {"request":{"url":url,"method":method,"headers":hdrs,
                         "body_base64":base64.b64encode(data or b"").decode()},
              "response":{"status":None,"headers":[],"complete":False},
              "started_at":stamp,"completed_at":None,"complete":False,
              "transport":"python-http-client","redirect_followed":False}
    try:
        conn.request(method, u.path + ("?"+u.query if u.query else ""), body=data, headers=hdrs)
        response = conn.getresponse()
        result["response"].update(status=response.status, headers=response.getheaders())
        expected = response.length
        complete = False
        while True:
            if time.monotonic() - started >= timeout:
                raise TimeoutError("Total capture deadline exceeded")
            chunk = response.read1(min(65536, max_bytes + 1 - len(raw)))
            if not chunk:
                complete = expected is None or len(raw) == expected
                if not complete:
                    result["error"] = "short_response"
                break
            raw.extend(chunk)
            if len(raw) > max_bytes:
                del raw[max_bytes:]
                result["error"] = "capture_budget_exceeded"
                break
        result["complete"] = result["response"]["complete"] = complete
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        if isinstance(exc, http.client.IncompleteRead):
            raw.extend(exc.partial[:max_bytes-len(raw)])
        # Error classes are safe to return; URLs or headers need not be echoed.
        result["error"] = type(exc).__name__
    finally:
        conn.close()
    result["response"].update(length=len(raw), body_base64=base64.b64encode(raw).decode(),
                               body_sha256=hashlib.sha256(raw).hexdigest())
    result.update(elapsed_ms=round((time.monotonic()-started)*1000, 3), completed_at=now())
    return result


def response_json(artifact):
    try:
        return json.loads(base64.b64decode(artifact["response"]["body_base64"], validate=True))
    except (ValueError, KeyError, UnicodeError) as exc:
        raise EngineError("response_json", "Complete JSON response required for this assertion") from exc


def pointer(value, path):
    if path == "":
        return value
    if not isinstance(path, str) or not path.startswith("/") or re.search(r"~(?![01])", path):
        raise EngineError("selector", "A JSON Pointer is required")
    try:
        for token in path[1:].split("/"):
            key = token.replace("~1", "/").replace("~0", "~")
            value = value[int(key)] if isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", key) else value[key]
        return value
    except (KeyError, IndexError, ValueError, TypeError) as exc:
        raise EngineError("selector", "JSON Pointer does not identify a value") from exc
