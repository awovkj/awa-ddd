"""Derive redacted, explicitly manual reproduction material from intact captures."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
from urllib.parse import parse_qsl, quote, quote_plus, unquote_plus, urlsplit, urlunsplit

from .store import EngineError


_SECRET_KEYS = {
    "password", "passwd", "pwd", "paypassword", "paymentpassword", "secret", "clientsecret",
    "token", "accesstoken", "refreshtoken", "authtoken", "resettoken", "sessiontoken",
    "idtoken", "authorization", "proxyauthorization", "cookie", "setcookie", "apikey",
    "privatekey", "credential", "credentials", "jwt", "signature", "sign", "paysign",
    "smscode", "verificationcode", "verifycode", "otp", "pin", "code", "phone", "mobile", "email",
}
_AUTH_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
                 "x-auth-token", "x-session-token"}
_MANAGED_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "accept-encoding"}
_PLACEHOLDER = re.compile(r"<AWA_[A-Z0-9_]+>")
_CHINESE_VALUE = re.compile(
    r"(?:支付密码|登录密码|数据库密码|数据库口令|明文密码|验证码|短信码|重置令牌|签名密钥|回调密钥)"
    r"\s*(?:(?:为|是|=|:|：)\s*){0,6}[\"'（(]?([A-Za-z0-9._~+/-]{4,})"
)
_ASSIGNED_VALUE = re.compile(
    r"(?i)\b(?:password|passwd|(?:access|refresh|auth|reset|session|id)[_-]?token|token|"
    r"api[_-]?key|(?:client[_-]?)?secret)\s*[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9._~+/-]{4,})"
)
_XML_VALUE = re.compile(r"<([A-Za-z_][\w:.-]*)\b[^>]*>([^<>]+)</\1\s*>")
_MAX_EXCERPT = 3500


def _normal_key(value):
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _secret_key(value):
    name = _normal_key(value)
    return name in _SECRET_KEYS or any(word in name for word in ("password", "passwd", "secret", "privatekey")) \
        or name.endswith(("token", "apikey", "signature", "smscode", "verificationcode"))


class Redactor:
    """Keep the same replacement for a secret in prose, URLs, and HTTP templates."""

    def __init__(self):
        self.values = {}
        self.aliases = {}
        self._pattern = None

    def slot(self, value, kind="SECRET"):
        if value is None or isinstance(value, (dict, list, bool)):
            return "<AWA_" + kind + "_REPLACE>"
        text = str(value)
        if not text or text in self.values.values():
            return text
        if text not in self.values:
            label = re.sub(r"[^A-Z0-9_]", "_", kind.upper())[:40] or "SECRET"
            self.values[text] = "<AWA_" + label + "_" + str(len(self.values) + 1) + ">"
            # Very short values are replaced by field, not across unrelated prose.
            if len(text) >= 4:
                for alias in {text, quote(text, safe=""), quote_plus(text),
                              json.dumps(text, ensure_ascii=True)[1:-1],
                              json.dumps(text, ensure_ascii=False)[1:-1]}:
                    self.aliases[alias] = self.values[text]
                self._pattern = None
            if "\n" in text or "\r" in text:
                for line in text.splitlines():
                    if len(line.strip()) >= 8 and not line.strip().startswith("-----"):
                        self.slot(line.strip(), kind + "_LINE")
        return self.values[text]

    def replace(self, value):
        text = "" if value is None else str(value)
        if self.aliases:
            if self._pattern is None:
                def literal(item):
                    escaped = re.escape(item)
                    if len(item) <= 8 and re.fullmatch(r"[A-Za-z0-9_]+", item):
                        return r"(?<![A-Za-z0-9_])" + escaped + r"(?![A-Za-z0-9_])"
                    return escaped
                self._pattern = re.compile(_PLACEHOLDER.pattern + "|" + "|".join(literal(item) for item in
                                                                              sorted(self.aliases, key=len, reverse=True)))
            text = self._pattern.sub(lambda match: self.aliases.get(match.group(0), match.group(0)), text)
        text = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "<AWA_JWT_REPLACE>", text)
        text = re.sub(r"\b(?:sk-|ghp_|github_pat_)[A-Za-z0-9_-]{16,}\b", "<AWA_TOKEN_REPLACE>", text)
        return text

    def learn_text(self, text):
        for pattern in (_CHINESE_VALUE, _ASSIGNED_VALUE):
            for match in pattern.finditer(str(text)):
                self.slot(match.group(1))
        for match in _XML_VALUE.finditer(str(text)):
            if _secret_key(match.group(1)):
                self.slot(match.group(2), "XML_SECRET")

    def learn(self, value, sensitive=False, key="SECRET"):
        if isinstance(value, dict):
            declared = value.get("name")
            for name, item in value.items():
                private = sensitive or _secret_key(name) or (name == "value" and _secret_key(declared))
                self.learn(item, private, _normal_key(name).upper() or key)
        elif isinstance(value, list):
            for item in value:
                self.learn(item, sensitive, key)
        elif sensitive:
            self.slot(value, key)
        elif isinstance(value, str):
            self.learn_text(value)

    def structured(self, value, sensitive=False, key="SECRET"):
        if isinstance(value, dict):
            declared = value.get("name")
            return {name: self.structured(item, sensitive or _secret_key(name) or
                                          (name == "value" and _secret_key(declared)),
                                          _normal_key(name).upper() or key)
                    for name, item in value.items()}
        if isinstance(value, list):
            return [self.structured(item, sensitive, key) for item in value]
        if sensitive and value is not None:
            return self.slot(value, key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and len(str(value)) >= 4 and str(value) in self.values:
            return self.values[str(value)]
        return self.replace(value) if isinstance(value, str) else value

    def prose(self, value, limit=4000):
        from .reporting import safe_text
        self.learn_text(value)
        return safe_text(self.replace(value), limit, preserve_placeholders=set(self.values.values()))

    def metadata(self, value):
        from .reporting import safe_metadata
        if isinstance(value, dict):
            return safe_metadata({key: self.metadata(item) for key, item in value.items()},
                                 preserve_placeholders=set(self.values.values()))
        if isinstance(value, list):
            return [self.metadata(item) for item in value]
        return self.prose(value) if isinstance(value, str) else value

    def scrub_generated(self, value):
        if isinstance(value, dict):
            return {name: self.scrub_generated(item) for name, item in value.items()}
        if isinstance(value, list):
            return [self.scrub_generated(item) for item in value]
        return self.replace(value) if isinstance(value, str) else value

    def form(self, text):
        result = []
        for field in text.split("&"):
            name, separator, value = field.partition("=")
            if separator and _secret_key(unquote_plus(name)):
                value = self.slot(unquote_plus(value), _normal_key(unquote_plus(name)).upper())
            result.append(self.replace(name) + separator + self.replace(value))
        return "&".join(result)

    def url(self, value):
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Invalid captured URL")
        return urlunsplit((parsed.scheme, self.replace(parsed.netloc), self.replace(parsed.path or "/"),
                           self.form(parsed.query), ""))


def _body_bytes(document, side):
    return base64.b64decode(document[side].get("body_base64", ""), validate=True)


def _learn_header(redactor, name, value):
    redactor.slot(value, "HEADER_" + _normal_key(name).upper())
    lower = str(name).lower()
    if lower in {"cookie", "set-cookie"}:
        fields = str(value).split(";")
        for field in fields[:1] if lower == "set-cookie" else fields:
            _, separator, token = field.strip().partition("=")
            if separator and token:
                redactor.slot(token, "COOKIE_VALUE")
    elif lower in {"authorization", "proxy-authorization"}:
        scheme, separator, token = str(value).partition(" ")
        if separator and token:
            redactor.slot(token.strip(), "AUTH_TOKEN")
            if scheme.lower() == "basic":
                try:
                    decoded = base64.b64decode(token.strip(), validate=True).decode("utf-8")
                    redactor.slot(decoded, "BASIC_CREDENTIAL")
                    _, separator, password = decoded.partition(":")
                    if separator:
                        redactor.slot(password, "PASSWORD")
                except (ValueError, UnicodeError):
                    pass


def _content_type(headers):
    items = headers.items() if isinstance(headers, dict) else headers
    return next((str(value) for key, value in items if str(key).lower() == "content-type"), "")


def _learn_body(redactor, data, content_type):
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        return
    redactor.learn_text(text)
    if _json_media(text, content_type):
        from .inputs import json_document
        try:
            redactor.learn(json_document(data))
        except EngineError:
            # Learn every duplicate occurrence for prose redaction, but never use
            # this permissive pass as a request template or assessment proof.
            def learn_pairs(pairs):
                declared = next((item for name, item in pairs if name == "name"), None)
                for name, item in pairs:
                    redactor.learn(item, _secret_key(name) or (name == "value" and _secret_key(declared)),
                                   _normal_key(name).upper())
                return dict(pairs)
            try:
                json.loads(text, object_pairs_hook=learn_pairs)
            except (ValueError, TypeError, RecursionError):
                pass
    elif "application/x-www-form-urlencoded" in content_type:
        redactor.form(text)
    elif "multipart/" in content_type:
        from .inputs import _multipart
        try:
            for name, (start, end) in _multipart(data, content_type).items():
                field = data[start:end].decode("utf-8")
                if _secret_key(name):
                    redactor.slot(field, "FORM_SECRET")
                else:
                    redactor.learn_text(field)
        except (EngineError, UnicodeError):
            pass


def _json_media(text, content_type):
    return "json" in content_type.lower() or text.lstrip("\ufeff \t\r\n")[:1] in {"{", "["}


def _multipart_body(redactor, data, content_type):
    from .inputs import _multipart
    parts = _multipart(data, content_type)
    segments, previous = [], 0
    for name, (start, end) in sorted(parts.items(), key=lambda item: item[1][0]):
        prefix = data[:start - 4]
        header_start = max(prefix.rfind(b"\r\n--"), 0)
        part_headers = prefix[header_start:]
        if re.search(rb'(?i)\bfilename\*?\s*=', part_headers):
            media = re.search(rb"(?im)^content-type:\s*([^\r\n;]+)", part_headers)
            media = media.group(1).decode("ascii").lower() if media else "application/octet-stream"
            if not (media.startswith("text/") or media in {"application/json", "application/xml"} or media.endswith(("+json", "+xml"))):
                raise EngineError("reproduction_binary", "An opaque multipart file cannot be safely redacted")
        text = data[start:end].decode("utf-8")
        clean = redactor.slot(text, "FORM_SECRET") if _secret_key(name) else redactor.replace(text)
        segments += [data[previous:start], clean.encode("utf-8")]
        previous = end
    segments.append(data[previous:])
    return b"".join(segments)


def _safe_body(redactor, data, content_type):
    if not data:
        return b"", "", False
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        return None, "二进制或非 UTF-8 正文未导出；必须从授权原始材料单独核对。", False
    if any(ord(character) < 32 and character not in "\t\r\n" for character in text):
        return None, "含二进制控制字节的正文未导出，不能猜测其秘密边界。", False
    if _json_media(text, content_type):
        from .inputs import json_document
        try:
            structured = json_document(data)
            sanitized = redactor.structured(structured)
            clean = text if sanitized == structured else json.dumps(sanitized, ensure_ascii=False, separators=(",", ":"))
        except EngineError:
            return None, "JSON 含重复键、非有限数或无效结构；不能安全定位秘密，正文及执行模板未导出。", False
    elif "multipart/" in content_type:
        try:
            clean = _multipart_body(redactor, data, content_type).decode("utf-8")
        except (EngineError, ValueError, UnicodeError):
            return None, "multipart 边界/字段不唯一，或包含不透明文件；正文及执行模板未导出。", False
    else:
        clean = redactor.form(text) if "application/x-www-form-urlencoded" in content_type else redactor.replace(text)
    return clean.encode("utf-8"), clean, clean != text


def _component(value, prefix):
    value = str(value)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", value) and ".." not in value:
        return value
    return prefix + "-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


def _commands(arguments, executable="curl"):
    return {"posix": shlex.join([executable, *arguments]),
            "powershell": "& '" + ("curl.exe" if executable == "curl" else executable) + "' " +
            " ".join("'" + item.replace("'", "''") + "'" for item in arguments)}


def _role(decision, identity, index):
    proof = decision.get("proof") or {}
    for field, name in (("baseline_evidence_id", "正常业务基线"), ("recovery_evidence_id", "注入/恢复元信息观察"),
                        ("negative_evidence_id", "阴性/敏感性对照"), ("control_evidence_id", "正常控制请求"),
                        ("injection_evidence_id", "注入请求及业务变化")):
        if proof.get(field) == identity:
            return name
    if (decision.get("oracle") or {}).get("type") == "authorization":
        return "有权主体基线" if index == 0 else "另一主体的权限对照"
    return "实际观察 " + str(index + 1)


def _response_observables(redactor, artifact, decision):
    from .inputs import json_document
    try:
        value = json_document(_body_bytes(artifact, "response"))
    except EngineError:
        return []
    result = []
    from .transport import pointer
    oracle, proof = decision.get("oracle") or {}, decision.get("proof") or {}
    for selector in dict.fromkeys(item for item in (oracle.get("selector"), oracle.get("baseline_selector"), proof.get("response_selector")) if isinstance(item, str)):
        try:
            observed = pointer(value, selector)
            preview = json.dumps(redactor.structured(observed), ensure_ascii=False)
            result.append({"selector": selector, "observed_excerpt": preview[:_MAX_EXCERPT],
                           "truncated": len(preview) > _MAX_EXCERPT, "source": "original_response"})
        except EngineError:
            pass

    def walk(item, path="", sensitive=False, key="SECRET"):
        if len(result) >= 30:
            return
        if isinstance(item, dict):
            declared = item.get("name")
            for name, child in item.items():
                leaf = str(name).replace("~", "~0").replace("/", "~1")
                walk(child, path + "/" + leaf, sensitive or _secret_key(name) or
                     (name == "value" and _secret_key(declared)), _normal_key(name).upper())
        elif isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, path + "/" + str(index), sensitive, key)
        elif sensitive and item is not None and len(str(item)) >= 4:
            result.append({"selector": redactor.replace(path), "observed_excerpt": redactor.slot(item, key),
                           "sensitive_value_present": True, "source": "original_response"})

    walk(value)
    return result


def _step(project, redactor, evidence, artifact, decision, index, folder, files):
    request, response = artifact["request"], artifact["response"]
    method = request["method"]
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise ValueError("Unsupported captured method")
    raw_headers = request.get("headers") or {}
    names = set(evidence.get("credential_header_names") or []) | _AUTH_HEADERS
    headers = {}
    for name, value in raw_headers.items():
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or any(c in str(value) for c in "\r\n\x00"):
            raise ValueError("Invalid captured header framing")
        if name.lower() not in _MANAGED_HEADERS:
            headers[name] = redactor.slot(value, "HEADER_" + _normal_key(name).upper()) \
                if name.lower() in names or _secret_key(name) else redactor.replace(value)
    url = redactor.url(request["url"])
    body, body_text, changed = _safe_body(redactor, _body_bytes(artifact, "request"), _content_type(raw_headers))
    response_data, response_text, _ = _safe_body(redactor, _body_bytes(artifact, "response"), _content_type(response.get("headers") or []))
    identity = evidence["id"]
    stem = f"{index + 1:02d}-" + _component(identity, "E")
    step = {"number": index + 1, "role": _role(decision, identity, index), "evidence_id": identity,
            "operation_id": evidence.get("operation_id"), "run_id": evidence.get("run_id"),
            "actor_id": evidence.get("actor_id"), "session_id": evidence.get("session_id"),
            "session_generation": evidence.get("session_generation"), "resource_id": evidence.get("resource_id"),
            "auth_mode": evidence.get("auth_mode", "session" if evidence.get("session_id") else "none"),
            "method": method, "url": url, "status_code": response.get("status"),
            "captured_at": artifact.get("started_at") or evidence.get("created_at"),
            "source_artifact": evidence.get("artifact_path"), "source_sha256": evidence.get("sha256"),
            "response_sha256": hashlib.sha256(_body_bytes(artifact, "response")).hexdigest(),
            "request_body_excerpt": body_text[:_MAX_EXCERPT], "request_body_truncated": len(body_text) > _MAX_EXCERPT,
            "response_excerpt": response_text[:_MAX_EXCERPT], "response_truncated": len(response_text) > _MAX_EXCERPT,
            "body_redacted": changed, "request_template_available": body is not None,
            "response_body_available": response_data is not None, "state_changing": method not in {"GET", "HEAD", "OPTIONS"}}
    step["response_observables"] = _response_observables(redactor, artifact, decision)
    if evidence.get("actor_id"):
        actor = project.get("actor", evidence["actor_id"], required=False) or {}
        step["subject"] = redactor.prose(actor.get("subject"))
        step["roles"] = redactor.metadata(actor.get("roles") or [])
    if evidence.get("resource_id"):
        resource = project.get("resource", evidence["resource_id"], required=False) or {}
        step["resource"] = redactor.metadata({key: resource.get(key) for key in
                                            ("owner_actor_id", "external_id", "request_binding", "state")})
    if body is not None:
        parsed = urlsplit(url)
        head = method + " " + parsed.path + ("?" + parsed.query if parsed.query else "") + " HTTP/1.1\r\nHost: " + parsed.netloc + "\r\n"
        head += "".join(name + ": " + value + "\r\n" for name, value in headers.items())
        if body:
            head += "Content-Length: " + str(len(body)) + "\r\n"
        step["request_file"] = folder + "/" + stem + ".http"
        files[step["request_file"]] = head.encode("utf-8") + b"\r\n" + body
        arguments = ["--http1.1", "--globoff", "--path-as-is", "--request", method, "--url", url,
                     "--connect-timeout", "5", "--max-time", "15", "--max-redirs", "0", "--noproxy", "*",
                     "--proto", "=http,https"]
        for name, value in headers.items():
            arguments += ["--header", name + ": " + value]
        if body:
            content_type = _content_type(raw_headers)
            extension = ".json" if "json" in content_type else ".xml" if "xml" in content_type else ".body"
            step["body_file"] = folder + "/" + stem + extension
            files[step["body_file"]] = body
            arguments += ["--data-binary", "@" + step["body_file"]]
        step["curl"] = _commands(arguments)
        step["placeholders"] = sorted(set(_PLACEHOLDER.findall(head + body_text)))
    else:
        step["unavailable_reason"] = body_text
        step["placeholders"] = sorted(set(_PLACEHOLDER.findall(url)))
    operation = project.get("operation", evidence["operation_id"])
    step["registered_inputs"] = redactor.metadata(operation.get("inputs") or [])
    return step


def _manual_sql_parameter(project, step, location, selector):
    from .inputs import json_document, locate_json, parse_form
    evidence = project.get("evidence", step["evidence_id"])
    artifact = project.read_artifact(evidence)
    request = artifact["request"]
    method = request["method"]
    if method not in {"GET", "POST"} or location not in {"query", "body"}:
        raise ValueError("This input needs a dedicated sqlmap marker/profile")
    raw = _body_bytes(artifact, "request")
    if method == "GET" and (raw or location != "query"):
        raise ValueError("The GET profile supports one query input and no body")
    query = parse_form(urlsplit(request["url"]).query)
    document, form = None, None
    if method == "POST":
        if not step.get("resource_id"):
            raise ValueError("POST needs a disposable resource before repeated probes")
        media = _content_type(request.get("headers") or {}).split(";", 1)[0].strip().lower()
        if media == "application/json" or media.endswith("+json"):
            document = json_document(raw)
        elif media == "application/x-www-form-urlencoded":
            form = parse_form(raw)
        elif raw:
            raise ValueError("The POST body format has no proven sqlmap profile")

    def count_names(item, name):
        if isinstance(item, dict):
            return sum(key == name for key in item) + sum(count_names(child, name) for child in item.values())
        return sum(count_names(child, name) for child in item) if isinstance(item, list) else 0

    parameter = selector
    if location == "query":
        if sum(name == selector for name, value in query) != 1:
            raise ValueError("The selected query parameter is not unique")
        if (document is not None and count_names(document, selector)) or (form is not None and any(name == selector for name, value in form)):
            raise ValueError("Query and body share the selected parameter name")
    elif document is not None:
        value, tokens = locate_json(document, selector)
        if not tokens or isinstance(document, list) or isinstance(value, (dict, list, bool)) or value is None:
            raise ValueError("sqlmap needs a uniquely named scalar JSON field")
        parameter = tokens[-1]
        if count_names(document, parameter) != 1 or any(name == parameter for name, value in query):
            raise ValueError("A repeated JSON leaf/query name makes -p ambiguous")
    elif form is not None:
        if sum(name == selector for name, value in form) != 1 or any(name == selector for name, value in query):
            raise ValueError("A form/query name makes -p ambiguous")
    else:
        raise ValueError("No supported concrete body field")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", parameter):
        raise ValueError("The parameter name needs a dedicated sqlmap marker")
    return parameter


def _sqlmap(project, redactor, finding, decision, steps, folder):
    proof = decision.get("proof") or finding.get("proof") or {}
    if proof.get("channel") == "behavioural_diff":
        return {"available": False, "reason": "已确认写侧 SQL 业务变化；对这类状态写执行 sqlmap 会重复修改资源，不能将其冒充只读元信息验证。"}
    baseline_id = proof.get("baseline_evidence_id") or proof.get("control_evidence_id")
    step = next((item for item in steps if item["evidence_id"] == baseline_id), steps[0] if steps else None)
    if step is None or not step.get("request_file"):
        return {"available": False, "reason": "缺少可校验、可导出的正常 SQL 请求，不能猜造 sqlmap 命令。"}
    obligation = project.get("obligation", decision.get("obligation_id"), required=False) if decision.get("obligation_id") else {}
    run = project.get("run", proof.get("tool_run_id"), required=False) if proof.get("tool_run_id") else {}
    recorded = {}
    if run:
        try:
            document = project.read_artifact(run)
            recorded = document.get("execution") or {}
        except (EngineError, ValueError, KeyError, TypeError, OSError):
            return {"available": False, "reason": "历史 sqlmap 配置的摘要不可校验；不能把当前可改记录冒充实际执行参数。"}
    location = proof.get("input_location") or (obligation or {}).get("input_location") or (run or {}).get("input_location")
    selector = proof.get("input_selector") or (obligation or {}).get("input_selector") or (run or {}).get("input_selector")
    if not isinstance(selector, str) or not selector or location not in {"query", "body", "graphql", "header"}:
        return {"available": False, "reason": "SQL 输入位置/选择器缺失，或路径注入需要专用标记；不生成貌似可用的命令。"}
    parameter = selector
    if recorded.get("tool_parameter"):
        parameter = recorded["tool_parameter"]
    else:
        try:
            parameter = _manual_sql_parameter(project, step, location, selector)
        except (EngineError, ValueError, KeyError, TypeError):
            return {"available": False, "reason": "没有实际 tool_parameter 绑定，且请求不满足唯一 query / 标量 JSON / 表单输入配置；需要专用标记或适配前提，不输出貌似可用的 -p 命令。"}
    arguments = ["-r", step["request_file"], "-p", redactor.replace(parameter), "--batch", "--level=1", "--risk=1",
                 "--threads=1", "--technique=BEU", "--timeout=5", "--retries=0", "--ignore-redirects", "--ignore-proxy", "--disable-coloring",
                 "--output-dir=sqlmap-results/" + _component(finding["id"], "F"), "--fresh-queries"]
    if step["url"].startswith("https://"):
        arguments += ["--force-ssl"]
    dbms = recorded.get("dbms")
    if dbms in {"MySQL", "PostgreSQL", "Microsoft SQL Server", "Oracle", "SQLite"}:
        arguments += ["--dbms=" + dbms]
    if dbms == "SQLite":
        from .external import SQLITE_DATABASE_QUERY
        arguments += ["--sql-query=" + SQLITE_DATABASE_QUERY]
        scope = "SQLite 仅验证 pragma_database_list 的只读数据库元信息，不使用 database()/current_user()。"
    else:
        arguments += ["--current-db", "--current-user"]
        scope = "只验证当前数据库名和当前数据库用户；不枚举业务表、不导出数据、不修改数据库。"
    commands = {"posix": 'python3 -X utf8 "$AWA_SQLMAP_PATH" ' + shlex.join(arguments),
                "powershell": "& 'python' '-X' 'utf8' $env:AWA_SQLMAP_PATH " +
                " ".join("'" + item.replace("'", "''") + "'" for item in arguments)}
    return {"available": True, "parameter": redactor.replace(parameter), "input_location": location,
            "input_selector": redactor.replace(selector), "baseline_evidence_id": step["evidence_id"],
            "request_file": step["request_file"], "tool_run_id": proof.get("tool_run_id"),
            "request_method": step["method"], "recorded_profile": redactor.metadata(recorded.get("profile")),
            "commands": commands, "scope": scope, "manual_only": True, "executed_by_report": False,
            "expected_recorded_metadata": redactor.structured(proof.get("recovered_value")),
            "note": "这是待人工执行的验证模板，不是本次报告新执行的结果。先设置 AWA_SQLMAP_PATH 并替换 HTTP 文件中的占位符。"
                    + " 建议配置仅含 BEU，不覆盖时间盲注 T 或高风险/带外技术；未记录的历史 profile 不冒充已执行。"
                    + (" JSON 参数按字段名交给 sqlmap；嵌套同名字段必须人工确认实际注入点。" if location in {"body", "graphql"} else "")}


def prepare_reproduction(project, findings, *, context=None):
    """Return sanitized descriptions and bytes; never write files or send requests."""
    redactor, files, warnings = Redactor(), {}, []
    redactor.learn(context)
    sessions = project.list("session")
    redactor.learn(project.config)
    for kind in ("actor", "resource"):
        for row in project.list(kind):
            redactor.learn(row)
    ids = {identity for finding in findings for identity in finding.get("evidence_ids", [])}
    ids.update(session["verification_evidence_id"] for session in sessions if session.get("verification_evidence_id"))
    # Context learning is not export or confirmation: another intact capture may
    # contain the reset token/code later quoted without a label in an impact.
    ids.update(row["id"] for row in project.list("evidence") if row.get("kind") == "http")
    for session in sessions:
        names = set(session.get("credential_header_names") or []) | _AUTH_HEADERS
        for name, value in (session.get("headers") or {}).items():
            if name.lower() in names or _secret_key(name):
                _learn_header(redactor, name, value)
    for identity in sorted(ids):
        try:
            evidence = project.get("evidence", identity)
            artifact = project.read_artifact(evidence)
            for side in ("request", "response"):
                headers = artifact.get(side, {}).get("headers") or {}
                items = headers.items() if isinstance(headers, dict) else headers
                names = set(evidence.get("credential_header_names") or []) | _AUTH_HEADERS
                for name, value in items:
                    if str(name).lower() in names or _secret_key(name):
                        _learn_header(redactor, name, value)
                _learn_body(redactor, _body_bytes(artifact, side), _content_type(headers))
            redactor.url(artifact["request"]["url"])
        except (EngineError, OSError, ValueError, KeyError, TypeError):
            continue
    for finding in findings:
        if finding.get("decision_id"):
            try:
                redactor.learn(project.get("decision", finding["decision_id"]))
            except EngineError:
                pass
        for key in ("title", "impact", "remediation", "limitations", "lifecycle_reason"):
            redactor.learn(finding.get(key))
    details = {}
    from .engine import _decision_valid, verify_current_evidence
    from .assessment import is_sql_category, validate_confirmation
    for finding in findings:
        if finding.get("current") is not True:
            continue
        folder = "reproduction/" + _component(finding["id"], "F")
        detail = {"available": False, "steps": [], "prerequisites": [
            "仅在原授权范围和隔离测试环境复现；不要使用真实用户、生产订单或生产资金。",
            "从本报告目录运行命令。所有 <AWA_...> 均为待替换占位符，未替换的模板不能直接复现。"],
            "limitations": [], "manual_only": True, "executed_by_report": False}
        try:
            decision = project.get("decision", finding["decision_id"])
            _decision_valid(project, decision)
            validate_confirmation(project, decision, finding.get("category"))
            for index, identity in enumerate(decision.get("evidence_ids") or []):
                try:
                    evidence, artifact = verify_current_evidence(project, identity)
                    detail["steps"].append(_step(project, redactor, evidence, artifact, decision, index, folder, files))
                except (EngineError, OSError, ValueError, KeyError, TypeError) as exc:
                    detail["limitations"].append("证据 " + redactor.prose(identity) + " 无法生成复现材料：" +
                                                 redactor.prose(getattr(exc, "code", type(exc).__name__)))
            detail["available"] = bool(detail["steps"]) and all(item.get("request_template_available") for item in detail["steps"])
            detail["partial"] = len(detail["steps"]) != len(decision.get("evidence_ids") or [])
            detail["available"] = detail["available"] and not detail["partial"]
            if any(item.get("session_id") for item in detail["steps"]):
                detail["prerequisites"].append("为各主体重新登录并核验身份/角色，分别替换其认证占位符；历史 session_id 只是血缘引用，不是可重用凭据。")
            if any(item["state_changing"] for item in detail["steps"]):
                detail["prerequisites"].append("包含状态变更：先准备自建测试资源，保存初始状态，按编号顺序单次执行，避免重复退款/发货/重置。")
                detail["limitations"].append("原台账未自动提供回滚脚本；人工复现后须恢复或删除自建资源并核对业务状态。")
            resources = {item["resource_id"]: item.get("resource") for item in detail["steps"] if item.get("resource_id")}
            for identity, resource in resources.items():
                detail["prerequisites"].append("历史测试资源 " + str(identity) + " 的 external_id 仅定位原证据；原登记绑定/状态为 " +
                    json.dumps(resource, ensure_ascii=False) + "。复测必须按 request_binding 的 location/selector 将历史资源号换成新建、可回退的 fixture；全部正常/攻击/多主体对照保持同一个新资源值。")
                detail["limitations"].append("未自动补造资源创建步骤：先自行创建并验证初始状态，再替换历史资源绑定值；写后通过正常读取核对状态、余额或属主，最后恢复/删除 fixture。")
            if decision.get("mode") == "analyst":
                detail["limitations"].append("该结论经过人工复核；响应摘录是实际材料，不把人工影响推断升级为机器验证或更大攻击范围。")
            detail["decision_reason"] = redactor.prose(decision.get("reason"))
            detail["oracle_type"] = (decision.get("oracle") or {}).get("type")
            if is_sql_category(finding.get("category")):
                detail["sqlmap"] = _sqlmap(project, redactor, finding, decision, detail["steps"], folder)
            if not detail["available"]:
                detail["unavailable_reason"] = "原始材料不完整、不可校验或正文不能安全导出；本报告不猜造缺失请求。"
        except (EngineError, OSError, ValueError, KeyError, TypeError) as exc:
            detail["unavailable_reason"] = "结论或证据不可校验：" + redactor.prose(getattr(exc, "code", type(exc).__name__))
        details[finding["id"]] = detail
    if details:
        files["reproduction/README.md"] = (
            "# 人工复现材料\n\n这些文件由经过摘要和当前血缘校验的真实 HTTP 观察派生。报告生成未发送请求。\n\n"
            "1. 仅在授权测试环境操作，准备自建账号/资源并保存初始状态。\n"
            "2. 从报告目录运行。先替换每个 `<AWA_...>` 占位符；认证、验证码、密码、签名等不能使用历史明文。\n"
            "3. 按 report.md 的编号顺序核对 curl 请求和结果；HTTP 文件可导入 Burp、Yakit 或 sqlmap。\n"
            "4. SQL 验证先将 `AWA_SQLMAP_PATH` 设置为本机可信 sqlmap.py 的绝对路径；命令仅验证只读元信息。\n"
            "5. JSON 的敏感字段替换可能规范化 JSON 格式；XML/文本/multipart 除秘密替换外保留已捕获 UTF-8 字节。"
            "二进制正文不自动导出。HTTP Content-Length 根据导出字节重新计算。\n"
            "6. 状态变更只执行于自建资源，结束后人工清理并核对业务状态。不要把模板命令视作已执行结果。\n"
        ).encode("utf-8")
    # A final pass uses the complete secret registry for both bytes and metadata.
    # Recompute framing after any late replacement, not only the displayed curl.
    for path, data in list(files.items()):
        if path.endswith(".http"):
            head, separator, body = data.partition(b"\r\n\r\n")
            head_text = redactor.replace(head.decode("utf-8"))
            media = re.search(r"(?im)^content-type:\s*([^\r\n]+)", head_text)
            clean_body, _, _ = _safe_body(redactor, body, media.group(1) if media else "")
            if not separator or clean_body is None:
                raise ValueError("A generated request no longer has safe framing")
            head_text = re.sub(r"(?im)^content-length:\s*[^\r\n]+", "Content-Length: " + str(len(clean_body)), head_text)
            files[path] = head_text.encode("utf-8") + separator + clean_body
        elif path.endswith(".json"):
            clean, _, _ = _safe_body(redactor, data, "application/json")
            if clean is None:
                raise ValueError("A generated JSON template became ambiguous")
            files[path] = clean
        else:
            files[path] = redactor.replace(data.decode("utf-8")).encode("utf-8")
    return {"finding_details": redactor.scrub_generated(details), "files": files, "redactor": redactor, "warnings": warnings}
