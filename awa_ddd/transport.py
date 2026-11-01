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
import unicodedata
from urllib.parse import urlsplit
from .store import EngineError, now


CONTROL_SIGNAL_FIELDS = frozenset({
    "ok", "success", "successful", "authenticated", "authorized", "allowed", "denied",
    "isok", "issuccess", "issuccessful", "isauthenticated", "isauthorized", "isallowed", "isdenied",
    "\u6210\u529f", "\u662f\u5426\u6210\u529f", "\u64cd\u4f5c\u6210\u529f",
})
CONTROL_METADATA_FIELDS = frozenset({
    "ok", "success", "successful", "status", "statuscode", "httpstatus", "httpstatuscode", "code",
    "message", "msg", "error", "errors", "err", "errorcode", "requestid", "traceid", "correlationid",
    "timestamp", "nonce", "elapsedms", "duration", "length", "responselength", "responsebytes",
    "authenticated", "authorized", "allowed", "denied", "isauthenticated", "isauthorized",
    "\u72b6\u6001", "\u6d88\u606f", "\u9519\u8bef", "\u6210\u529f", "\u65f6\u95f4\u6233",
}) | CONTROL_SIGNAL_FIELDS
CONTROL_METADATA_VALUES = frozenset({
    "ok", "success", "succeeded", "failed", "error", "denied", "forbidden",
    "unauthorized", "true", "false", "notfound", "permissiondenied", "authenticationrequired",
    "accessdenied", "notauthorized", "notauthenticated", "authenticationfailed", "authorizationfailed",
    "insufficientpermissions", "insufficientprivileges", "loginrequired", "notloggedin",
    "\u65e0\u6743\u9650", "\u7121\u6b0a\u9650", "\u6ca1\u6709\u6743\u9650", "\u6c92\u6709\u6b0a\u9650",
    "\u6743\u9650\u4e0d\u8db3", "\u6b0a\u9650\u4e0d\u8db3", "\u8bbf\u95ee\u88ab\u62d2\u7edd", "\u8a2a\u554f\u88ab\u62d2\u7d55",
    "\u62d2\u7edd\u8bbf\u95ee", "\u62d2\u7d55\u8a2a\u554f", "\u7981\u6b62\u8bbf\u95ee", "\u7981\u6b62\u8a2a\u554f",
    "\u672a\u6388\u6743", "\u672a\u6388\u6b0a", "\u672a\u767b\u5f55", "\u672a\u767b\u9304",
    "\u8bf7\u5148\u767b\u5f55", "\u8acb\u5148\u767b\u9304", "\u8ba4\u8bc1\u5931\u8d25", "\u8a8d\u8b49\u5931\u6557",
    "\u9274\u6743\u5931\u8d25", "\u6388\u6743\u5931\u8d25", "\u6388\u6b0a\u5931\u6557", "\u767b\u5f55\u5931\u8d25", "\u767b\u9304\u5931\u6557",
    "\u6210\u529f", "\u64cd\u4f5c\u6210\u529f", "\u8bf7\u6c42\u6210\u529f", "\u8acb\u6c42\u6210\u529f", "\u5904\u7406\u6210\u529f", "\u8655\u7406\u6210\u529f",
    "\u4fdd\u5b58\u6210\u529f", "\u63d0\u4ea4\u6210\u529f", "\u66f4\u65b0\u6210\u529f", "\u5220\u9664\u6210\u529f", "\u522a\u9664\u6210\u529f",
    "\u5931\u8d25", "\u5931\u6557", "\u64cd\u4f5c\u5931\u8d25", "\u64cd\u4f5c\u5931\u6557", "\u9519\u8bef", "\u932f\u8aa4",
})


_ENGLISH_DENIAL = re.compile(
    r"^(?:(?:http\s*)?(?:401|403|404|500)\s*[:\-]?\s*)?(?:"
    r"(?:access|permission|authentication|authorization)[\s_-]*(?:is[\s_-]+)?(?:denied|forbidden|required|failed)"
    r"|unauthori[sz]ed|forbidden|denied|not[\s_-]+found|not[\s_-]+(?:authori[sz]ed|authenticated|logged[\s_-]+in)"
    r"|insufficient\s+(?:permissions?|privileges?)|(?:please\s+)?(?:log\s*in|login)\s+required"
    r"|please\s+(?:log\s*in|login)|(?:you\s+)?(?:do\s+not|don't)\s+have\s+(?:the\s+)?(?:permission|access)"
    r"|(?:you\s+are\s+)?not\s+allowed\s+to\s+(?:access|view|read|perform))(?:\b|$)")
_ENGLISH_ACK_OR_ERROR = re.compile(
    r"^(?:(?:ok|success|succeeded|failed|error)\s*[^\w\s]"
    r"|(?:operation|request|action|update|save|submission)\s+(?:was\s+)?(?:successful|succeeded|failed|completed)\b"
    r"|(?:saved|submitted|updated|deleted|completed)\s+successfully\b)")
_CHINESE_DENIAL = re.compile(
    r"^(?:(?:\u63d0\u793a|\u7cfb\u7edf\u63d0\u793a)[\s,.:!;]+)?"
    r"(?:(?:\u62b1\u6b49|\u5bf9\u4e0d\u8d77|\u5c0d\u4e0d\u8d77|\u5f88\u62b1\u6b49)[\s,.:!;]*)?"
    r"(?:(?:\u60a8|\u4f60|\u5f53\u524d\u7528\u6237|\u7576\u524d\u7528\u6236|\u7528\u6237|\u7528\u6236)\s*)?(?:"
    r"(?:\u65e0|\u7121|\u6ca1\u6709|\u6c92\u6709|\u6682\u65e0|\u66ab\u7121)(?:\u8bbf\u95ee|\u8a2a\u554f|\u64cd\u4f5c|\u67e5\u770b)?(?:\u6743\u9650|\u6b0a\u9650)"
    r"(?=$|[^\w]|\u8bbf\u95ee|\u8a2a\u554f|\u64cd\u4f5c|\u67e5\u770b|\u8bfb\u53d6|\u8b80\u53d6|\u6267\u884c|\u57f7\u884c|\u4e0b\u8f7d|\u4e0b\u8f09)"
    r"|(?:\u65e0\u6743|\u7121\u6b0a)(?:\u8bbf\u95ee|\u8a2a\u554f|\u64cd\u4f5c|\u67e5\u770b|\u8bfb\u53d6|\u8b80\u53d6)"
    r"|(?:\u6743\u9650\u4e0d\u8db3|\u6b0a\u9650\u4e0d\u8db3|\u8bbf\u95ee\u88ab\u62d2\u7edd|\u8a2a\u554f\u88ab\u62d2\u7d55|\u62d2\u7edd\u8bbf\u95ee|\u62d2\u7d55\u8a2a\u554f"
    r"|\u672a\u6388\u6743|\u672a\u6388\u6b0a|\u672a\u767b\u5f55|\u672a\u767b\u9304|\u7981\u6b62\u8bbf\u95ee|\u7981\u6b62\u8a2a\u554f)"
    r"(?=$|[^\w]|\u8bf7|\u8acb|\u65e0\u6cd5|\u7121\u6cd5|\u4e0d\u80fd)"
    r"|(?:\u8bf7|\u8acb)(?:\u5148|\u91cd\u65b0)?(?:\u767b\u5f55|\u767b\u9304|\u767b\u5165|\u767b\u9646))")
_CHINESE_ACK_OR_ERROR = re.compile(
    r"^(?:(?:\u64cd\u4f5c|\u8bf7\u6c42|\u8acb\u6c42|\u5904\u7406|\u8655\u7406|\u4fdd\u5b58|\u63d0\u4ea4|\u66f4\u65b0|\u5220\u9664|\u522a\u9664|\u67e5\u8be2|\u67e5\u8a62)"
    r"(?:\u6210\u529f|\u5931\u8d25|\u5931\u6557|\u5b8c\u6210)|\u6210\u529f|\u5931\u8d25|\u5931\u6557|\u9519\u8bef|\u932f\u8aa4"
    r"|(?:\u8ba4\u8bc1|\u8a8d\u8b49|\u9274\u6743|\u6388\u6743|\u6388\u6b0a|\u767b\u5f55|\u767b\u9304)(?:\u5931\u8d25|\u5931\u6557))(?=$|[^\w])")


def _control_token(value):
    return "".join(character for character in unicodedata.normalize("NFKC", str(value)).casefold() if character.isalnum())


def control_metadata_field(value):
    return _control_token(value) in CONTROL_METADATA_FIELDS


def control_signal_field(value):
    """A closed response-flag set, not arbitrary status/code or named domain state."""
    return _control_token(value) in CONTROL_SIGNAL_FIELDS


def control_signal_selector(value):
    return isinstance(value, str) and value.startswith("/") \
        and control_signal_field(value.rsplit("/", 1)[-1].replace("~1", "/").replace("~0", "~"))


def control_metadata_value(value):
    """Recognize explicit denial/ACK messages without discarding non-ASCII business text."""
    if not isinstance(value, str):
        return False
    text = unicodedata.normalize("NFKC", value).casefold().strip()
    if _control_token(text) in CONTROL_METADATA_VALUES:
        return True
    # Ignore decorative message prefixes, not letters from any language.
    start = next((index for index, character in enumerate(text) if character.isalnum()), len(text))
    text = text[start:]
    return any(pattern.match(text) for pattern in (_ENGLISH_DENIAL, _ENGLISH_ACK_OR_ERROR,
                                                  _CHINESE_DENIAL, _CHINESE_ACK_OR_ERROR))


def json_equal(left, right):
    """JSON value equality without Python's boolean/number aliasing."""
    from .contracts import _validate_json

    try:
        _validate_json(left)
        _validate_json(right)
    except (EngineError, TypeError, ValueError, RecursionError):
        return False

    def same(a, b):
        if type(a) in (int, float):
            return type(b) in (int, float) and a == b
        if type(a) is not type(b):
            return False
        if type(a) is dict:
            return a.keys() == b.keys() and all(same(value, b[key]) for key, value in a.items())
        if type(a) is list:
            return len(a) == len(b) and all(same(value, other) for value, other in zip(a, b))
        return a == b

    return same(left, right)


def has_business_state(value):
    """Named booleans and zero qualify; control-only containers do not."""
    from .contracts import _validate_json

    try:
        _validate_json(value)
    except (EngineError, TypeError, ValueError, RecursionError):
        return False

    def meaningful(node):
        if type(node) is dict:
            return any(not control_metadata_field(key) and meaningful(child) for key, child in node.items())
        if type(node) is list:
            return any(meaningful(child) for child in node)
        if type(node) is str:
            return bool(node.strip()) and not control_metadata_value(node)
        return type(node) in (bool, int, float)

    return meaningful(value)


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
    from .contracts import _validate_json
    from .inputs import json_document

    try:
        document = json_document(base64.b64decode(artifact["response"]["body_base64"], validate=True))
        _validate_json(document)
        return document
    except (EngineError, ValueError, KeyError, UnicodeError, TypeError, RecursionError) as exc:
        raise EngineError("response_json", "Assertions require bounded, unambiguous, finite UTF-8 JSON with valid Unicode scalars") from exc


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
