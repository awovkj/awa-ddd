"""Unresolved discovery线索的生命周期：列出、检查、关联到操作、显式处置。

M3-04 的关闭条件：未解析线索不会因为来源文件变化或静默丢弃而消失，而是
保留稳定 ID、可分页读取、可被显式关联到 Operation/Input，或被显式驳回并
保留理由。驳回文字不是耗尽证明，只有当前可重验证的范围或真实重复操作
依据可关闭发现复核。这里没有任何自动确认路径：candidate 永远不是证据。
"""
from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from urllib.parse import unquote, urlsplit, urlunsplit

from .store import EngineError, canonical, now

# These are lifecycle labels, not evidence or automatic stopping permissions.
UNVERIFIED = "unverified"
LINKED = "linked"
DISMISSED = "dismissed"

STATUSES = (UNVERIFIED, LINKED, DISMISSED)

MAX_PAGE = 500
DISMISSAL_BASES = {"outside_scope", "duplicate_operation"}
_LIFECYCLE_FIELDS = {"status", "reason", "created_at", "updated_at", "link",
                     "candidate_closure", "candidate_closure_context"}


def _closure_context(candidate):
    return deepcopy({key: value for key, value in candidate.items() if key not in _LIFECYCLE_FIELDS})


_PUBLIC_KEYS = {"id", "kind", "url", "finalUrl", "method", "protocol", "name", "status", "category", "severity",
                "origin", "operation_id", "legacy_id", "reason", "candidate_closure", "version", "basis",
                "created_at", "updated_at", "source", "sources", "hint", "inputs", "selector", "location",
                "consumer", "schema_branch", "schema_type", "schema_locator", "array_template", "required",
                "test_families", "content_type", "operation_name", "auth", "allowed_roles", "ownership", "state_scope",
                "locator", "path", "sha256", "trust", "link", "input_location", "input_selector", "linked_at",
                "previous_operation_id", "url_redacted", "native_input_requires_binding", "locator_requires_binding",
                "requestable", "candidate", "operation", "candidates", "candidate_total", "offset", "limit", "next_offset",
                "counts", "limitations", "unverified", "linked", "dismissed"}
_LOCATOR_KEYS = {"url", "finalUrl", "path", "locator", "schema_locator", "source_locator", "selector",
                 "input_selector", "location", "consumer_url", "source_url"}
_PRIVATE_LOCATOR = "[candidate locator omitted: protected context]"
_PRIVATE_CONTENT = "[candidate content omitted: redaction context unavailable]"


def _publication_metadata(project, value):
    from .browser import _learn_private_value, learn_redaction_context
    from .engine import credential_header_names
    from .reporting import public_integrity_metadata
    from .reproduction import Redactor, _learn_header, _PLACEHOLDER
    from .tscanplus import report_context

    original = public_integrity_metadata(value)
    redactor = Redactor()
    unavailable = learn_redaction_context(project, redactor)
    redactor.learn(original)

    def learn_keys(node):
        if isinstance(node, dict):
            for key, item in node.items():
                redactor.learn_text(key)
                learn_keys(item)
        elif isinstance(node, list):
            for item in node:
                learn_keys(item)

    learn_keys(original)
    for session in project.list("session"):
        for name in credential_header_names(session):
            secret = (session.get("headers") or {}).get(name)
            if secret is not None:
                _learn_header(redactor, name, secret)
    for secret in report_context(project)["secret_values"]:
        _learn_private_value(redactor, secret)
    for secret in list(redactor.values):
        _learn_private_value(redactor, secret)
    # Candidate/source prose is untrusted; short secrets must not survive inside
    # a path or annotation. Only separately bound handles/codes are restored.
    redactor._pattern = re.compile(_PLACEHOLDER.pattern + "|" + "|".join(
        re.escape(alias) for alias in sorted(redactor.aliases, key=len, reverse=True))) if redactor.aliases else None
    missing = any(unavailable.values())
    numeric = {int(secret): placeholder for secret, placeholder in redactor.values.items()
               if re.fullmatch(r"[0-9]{1,64}", secret)}

    def prose(text):
        if missing:
            return _PRIVATE_CONTENT
        decoded = text
        for _ in range(5):
            if decoded != text and redactor.replace(decoded) != decoded:
                return "[candidate content omitted: encoded credential]"
            next_value = unquote(decoded)
            if next_value == decoded:
                break
            decoded = next_value
        return redactor.prose(text)

    def scrub(node):
        if isinstance(node, dict):
            result = {}
            protected_locators = set()
            for key, item in node.items():
                if missing and key not in _PUBLIC_KEYS:
                    continue
                public_key = key if key in _PUBLIC_KEYS else prose(str(key))
                result[public_key] = scrub(item)
                if key in _LOCATOR_KEYS and isinstance(item, str) and (result[public_key] != item or item == _PRIVATE_LOCATOR):
                    result[public_key] = _PRIVATE_LOCATOR
                    protected_locators.add(public_key)
            if protected_locators:
                result.update({key + "_redacted": True for key in protected_locators})
                result.update(locator_requires_binding=True, native_input_requires_binding=True, requestable=False)
            return result
        if isinstance(node, list):
            return [scrub(item) for item in node]
        if isinstance(node, str):
            return prose(node)
        if node is not None and missing:
            return _PRIVATE_CONTENT
        if isinstance(node, (int, float)) and not isinstance(node, bool):
            if str(node) in redactor.values:
                return redactor.values[str(node)]
            if node in numeric:
                return numeric[node]
        return node

    public = redactor.metadata(scrub(original))
    if missing:
        public["redaction_context_status"] = "unavailable"
        public["redaction_context_unavailable"] = unavailable
    return public


def _control_handles(project):
    with project._lock:
        rows = project.connection.execute("SELECT kind,id FROM entities WHERE kind IN ('candidate','operation')").fetchall()
    return {identity for kind, identity in rows if kind == "candidate"}, {identity for kind, identity in rows if kind == "operation"}


def _restore_candidate_controls(project, original, public, handles=None):
    candidate_ids, operation_ids = _control_handles(project) if handles is None else handles

    def handle(key, expected):
        value = original.get(key)
        if isinstance(value, str) and value in expected and re.fullmatch(r"[CO]-[a-f0-9]{24,32}", value):
            public[key] = value

    handle("id", candidate_ids)
    handle("operation_id", operation_ids)
    if original.get("status") in STATUSES:
        public["status"] = original["status"]
    for field in ("link", "candidate_closure"):
        row, result = original.get(field), public.get(field)
        if isinstance(row, dict) and isinstance(result, dict):
            identity = row.get("operation_id")
            if isinstance(identity, str) and identity in operation_ids and re.fullmatch(r"O-[a-f0-9]{24,32}", identity):
                result["operation_id"] = identity
    if _nonrequestable_metadata(public):
        public.update(url_redacted=True, locator_requires_binding=True, native_input_requires_binding=True, requestable=False)
    return public


def _walk_metadata(value):
    yield value
    if isinstance(value, dict):
        for item in value.values():
            yield from _walk_metadata(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_metadata(item)


def _nonrequestable_metadata(value):
    return any(isinstance(item, dict) and any(item.get(key) is True for key in
               ("url_redacted", "native_input_requires_binding", "locator_requires_binding"))
               for item in _walk_metadata(value))


def _public_candidate(project, candidate):
    return _restore_candidate_controls(project, candidate, _publication_metadata(project, candidate))


def _concrete_url(candidate):
    from .scope import normalize_url

    hint = candidate.get("hint") if isinstance(candidate.get("hint"), dict) else candidate
    if any(node.get("url_redacted") or node.get("native_input_requires_binding") for node in (candidate, hint)):
        raise EngineError("candidate_closure", "A private or unbound locator cannot establish candidate closure")
    url = normalize_url(hint.get("url"))
    if any(character in url for character in "{}<>$"):
        raise EngineError("candidate_closure", "An unresolved URL cannot establish candidate closure")
    return url, hint


def _duplicate_operation(project, candidate, closure, evaluated):
    # Endpoint coverage cannot dismiss a scanner finding, metadata clue or a
    # dynamic expression whose actual route/method has not been established.
    if candidate.get("kind") != "operation_hint":
        return False
    if not isinstance(closure.get("operation_id"), str) or not 1 <= len(closure["operation_id"]) <= 200:
        return False
    operation = project.get("operation", closure.get("operation_id"), required=False)
    if not operation:
        return False
    from .scope import normalize_url, require_scope
    from .transport import json_equal

    url, hint = _concrete_url(candidate)
    if urlsplit(url).query or require_scope(project.config, url) != normalize_url(operation["url"]):
        return False
    method = hint.get("method")
    if not isinstance(method, str) or method.upper() != operation.get("method"):
        return False
    protocol = hint.get("protocol", "http")
    if protocol in {"https", "http1", "http/1.1"}:
        protocol = "http"
    if protocol != operation.get("protocol") or hint.get("operation_name", "") != operation.get("operation_name", ""):
        return False
    if "content_type" in hint and hint["content_type"] != operation.get("content_type"):
        return False
    for key in ("auth", "ownership", "state_scope"):
        if key in hint and hint[key] not in (None, "unknown") and not json_equal(hint[key], operation.get(key)):
            return False
    if "allowed_roles" in hint and sorted(hint["allowed_roles"]) != operation.get("allowed_roles", []):
        return False
    inputs = hint.get("inputs", [])
    if not isinstance(inputs, list):
        return False
    for entry in inputs:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            return False
        registered = next((item for item in operation.get("inputs", [])
                           if item.get("location") == entry.get("location")
                           and item.get("selector", item.get("name")) == entry.get("selector", entry["name"])
                           and item.get("schema_branch") == entry.get("schema_branch")), None)
        if registered is None:
            return False
        for key in ("schema_type", "required", "array_template", "schema_locator"):
            if key in entry and not json_equal(entry[key], registered.get(key)):
                return False
        if entry.get("consumer") not in (None, "", "unknown") and entry["consumer"] != registered.get("consumer"):
            return False
        if "test_families" in entry and (not isinstance(entry["test_families"], list)
                or sorted(entry["test_families"]) != sorted(registered.get("test_families", []))):
            return False
    obligations = [item for item in project.list("obligation")
                   if item.get("operation_id") == operation["id"] and not item.get("superseded")]
    gaps = {item["id"] for item in evaluated.get("gaps", [])}
    completion = evaluated.get("completion", {})
    return bool(obligations) and any(item.get("kind") != "baseline" for item in obligations) \
        and all(item.get("status") == "evaluated" and item["id"] not in gaps for item in obligations) \
        and all(type(completion.get(key)) is int and completion[key] == 0
                for key in ("applicability_review_total", "scope_reduction_review_total"))


def dismissal_valid(project, candidate, evaluated):
    """Recheck actual source/scope/typed coverage; caller prose never proves exhaustion."""
    closure = candidate.get("candidate_closure")
    if candidate.get("status") != DISMISSED or not isinstance(closure, dict) \
            or type(closure.get("version")) is not int or closure["version"] != 1 \
            or not isinstance(closure.get("basis"), str) or closure["basis"] not in DISMISSAL_BASES \
            or set(closure) != ({"version", "basis", "operation_id"} if closure["basis"] == "duplicate_operation"
                                else {"version", "basis"}):
        return False
    try:
        if canonical(candidate.get("candidate_closure_context")) != canonical(_closure_context(candidate)):
            return False
        if closure["basis"] == "duplicate_operation":
            return _duplicate_operation(project, candidate, closure, evaluated)
        from .scope import normalize_url, require_scope

        url, _ = _concrete_url(candidate)
        # Mutable caller exclusions cannot manufacture a verified discovery
        # exclusion. Lossy query locators must also fail closed; this wider
        # proof-only comparison never changes actual request authorization.
        rules = []
        for rule in project.config.get("scope", []):
            parsed = urlsplit(normalize_url(rule))
            rules.append(urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")))
        try:
            require_scope({**project.config, "scope": rules, "exclude": []}, url)
        except EngineError as exc:
            return exc.code == "out_of_scope"
        return False
    except (EngineError, OSError, ValueError, TypeError, KeyError):
        return False


def _primary_source(candidate):
    """发现路径给出 sources 列表，导入路径给出单个 source；两者都可定位。"""
    if isinstance(candidate.get("source"), dict):
        return candidate["source"]
    sources = candidate.get("sources")
    if isinstance(sources, list) and sources and isinstance(sources[0], dict):
        return sources[0]
    hint = candidate.get("hint")
    if isinstance(hint, dict):
        if isinstance(hint.get("source"), dict):
            return hint["source"]
        sources = hint.get("sources")
        if isinstance(sources, list) and sources and isinstance(sources[0], dict):
            return sources[0]
    return {}


_PROFILE_FIELDS = {"protocol", "operation_name", "content_type", "inputs", "auth", "allowed_roles",
                   "ownership", "state_scope", "path_template", "contexts", "url_redacted",
                   "native_input_requires_binding"}
_SOURCE_FIELDS = {"source", "sources", "locator"}


def _source_definition(candidate):
    omitted = _LIFECYCLE_FIELDS | {"id", "kind", "operation_id"}
    if isinstance(candidate.get("hint"), dict):
        definition = candidate["hint"]
        envelope = {key: value for key, value in candidate.items() if key not in omitted | {"hint"}}
    else:
        definition = {key: value for key, value in candidate.items() if key not in omitted}
        envelope = {}
    return {"kind": candidate.get("kind"), "definition": definition, "envelope": envelope}


def _request_profile(candidate):
    if candidate.get("kind") != "operation_hint":
        return None
    source = _source_definition(candidate)
    definition, envelope = source["definition"], source["envelope"]
    if not any(key in definition or key in envelope for key in _PROFILE_FIELDS):
        return None
    omitted = _LIFECYCLE_FIELDS | _SOURCE_FIELDS | {"id", "kind", "operation_id"}
    profile = {key: value for key, value in definition.items() if key not in omitted}
    outer = {key: value for key, value in envelope.items() if key not in omitted}
    return {"definition": profile, "envelope": outer}


def _candidate_key(candidate):
    if not isinstance(candidate, dict):
        raise EngineError("candidate", "Candidate must be an object")
    source = _primary_source(candidate)
    hint = candidate.get("hint") if isinstance(candidate.get("hint"), dict) else {}
    profiled = _request_profile(candidate) is not None
    key = [source.get("sha256"), source.get("locator"), candidate.get("kind"),
           candidate.get("url", hint.get("url")), candidate.get("method", hint.get("method")),
           candidate.get("name", hint.get("name")) if profiled else candidate.get("name"),
           candidate.get("locator", hint.get("locator")) if profiled else candidate.get("locator"),
           candidate.get("legacy_id", hint.get("legacy_id")) if profiled else candidate.get("legacy_id")]
    if not any(key):
        raise EngineError("candidate_identity", "Candidate needs a source digest or locator")
    return key


def _identity(key):
    return "C-" + hashlib.sha256(canonical(key).encode()).hexdigest()[:24]


def _profile_identity(candidate, *, force=False):
    key = _candidate_key(candidate)
    profile = _request_profile(candidate)
    if profile is not None or force:
        key.append(profile if profile is not None else {})
    return _identity(key)


def candidate_id(candidate):
    """Stable source/profile identity; bare legacy clues retain their original key."""
    return _profile_identity(candidate)


def _legacy_rejected_id(candidate):
    source = candidate.get("source")
    if not isinstance(source, dict):
        sources = candidate.get("sources") or []
        source = sources[0] if isinstance(sources, list) and sources and isinstance(sources[0], dict) else {}
    key = [source.get("sha256"), source.get("locator"), candidate.get("kind"),
           candidate.get("url"), candidate.get("method"), candidate.get("name"),
           candidate.get("locator"), candidate.get("legacy_id")]
    return _identity(key)


def _legacy_nested_id(candidate):
    source = _primary_source(candidate)
    hint = candidate.get("hint") if isinstance(candidate.get("hint"), dict) else {}
    key = [source.get("sha256"), source.get("locator"), candidate.get("kind"),
           candidate.get("url", hint.get("url")), candidate.get("method", hint.get("method")), candidate.get("name"),
           candidate.get("locator"), candidate.get("legacy_id")]
    return _identity(key)


def _legacy_profile_match(prior, candidate):
    # Canonical JSON preserves literal types; Python equality conflates true/1.
    return canonical(_source_definition(prior)) == canonical(_source_definition(candidate))


def _legacy_profile_ids(candidate):
    identities = [_legacy_nested_id(candidate), _legacy_rejected_id(candidate)]
    if candidate.get("kind") == "operation_hint":
        definition = _source_definition(candidate)["definition"]
        wrapped = {"kind": candidate["kind"], "hint": definition}
        identities.extend((_legacy_nested_id(wrapped),
                           _legacy_rejected_id({**definition, "kind": candidate["kind"]}),
                           _legacy_rejected_id(wrapped)))
    return dict.fromkeys(identities)


def _merge_actual_sources(existing, candidate):
    merged = dict(existing)
    profiled = existing.get("kind") == "operation_hint"
    target = existing["hint"] if profiled and isinstance(existing.get("hint"), dict) else existing
    incoming = candidate["hint"] if profiled and isinstance(candidate.get("hint"), dict) else candidate
    current = target.get("sources")
    sources = list(current) if isinstance(current, list) else []
    seen = {canonical(source) for source in sources if isinstance(source, dict)}
    if profiled and isinstance(target.get("source"), dict):
        seen.add(canonical(target["source"]))
    additions = incoming.get("sources")
    additions = list(additions) if isinstance(additions, list) else []
    if profiled and isinstance(incoming.get("source"), dict):
        additions.append(incoming["source"])
    changed = False
    for source in additions:
        if isinstance(source, dict) and canonical(source) not in seen:
            seen.add(canonical(source))
            sources.append(source)
            changed = True
    if changed:
        if target is existing:
            merged["sources"] = sources[:256]
        else:
            # Keep the existing wrapper and its safety envelope intact.
            merged["hint"] = {**target, "sources": sources[:256]}
    return merged


def _paging(args):
    offset = args.get("offset", 0)
    limit = args.get("limit", 50)
    if type(offset) is not int or offset < 0:
        raise EngineError("pagination", "offset must be a nonnegative integer")
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE:
        raise EngineError("pagination", "limit must be 1..%d" % MAX_PAGE)
    return offset, limit


def _summary(candidate):
    """列表视图：省略完整输入树和来源正文，只留可判定身份与状态的字段。"""
    return {k: candidate[k] for k in
            ("id", "kind", "status", "url", "method", "protocol", "name",
             "category", "severity", "origin", "operation_id", "legacy_id",
             "reason", "candidate_closure", "created_at", "updated_at", "url_redacted",
             "native_input_requires_binding", "locator_requires_binding", "requestable")
            if k in candidate}


def list_candidates(project, args):
    """只读分页。默认只返回仍未处置的线索，便于模型继续处理而不是回看历史。"""
    offset, limit = _paging(args)
    status = args.get("status", UNVERIFIED)
    if status not in STATUSES and status != "any":
        raise EngineError("candidate_status", "status must be one of unverified/linked/dismissed/any")
    kind = args.get("kind")
    rows = []
    for candidate in project.list("candidate"):
        current = candidate.get("status", UNVERIFIED)
        if status != "any" and current != status:
            continue
        if isinstance(kind, str) and kind and candidate.get("kind") != kind:
            continue
        rows.append(candidate)
    rows.sort(key=lambda item: (item.get("created_at", ""), item.get("id", "")))
    total = len(rows)
    window = rows[offset:offset + limit]
    counts = {name: 0 for name in STATUSES}
    for candidate in project.list("candidate"):
        counts[candidate.get("status", UNVERIFIED)] = counts.get(candidate.get("status", UNVERIFIED), 0) + 1
    result = {"candidates": [_summary(item) for item in window], "candidate_total": total,
            "offset": offset, "next_offset": offset + limit if offset + limit < total else None,
            "counts": counts,
            "limitations": ["An unresolved candidate is a discovery线索, not验证过的攻击面或漏洞。"]}
    public = _publication_metadata(project, result)
    handles = _control_handles(project)
    public["candidates"] = [_restore_candidate_controls(project, item, value, handles)
                            for item, value in zip(result["candidates"], public["candidates"])]
    for field in ("candidate_total", "offset", "next_offset"):
        public[field] = result[field]
    public["counts"] = counts
    return public


def inspect_candidate(project, args):
    """读取单条线索的完整记录，用于判断能否关联到已登记操作。"""
    candidate = project.get("candidate", args["candidate_id"])
    operation = project.get("operation", candidate["operation_id"], required=False) if candidate.get("operation_id") else None
    value = {"candidate": candidate, "operation": operation}
    public = _publication_metadata(project, value)
    public["candidate"] = _restore_candidate_controls(project, candidate, public["candidate"])
    if isinstance(operation, dict) and isinstance(public.get("operation"), dict):
        result = public["operation"]
        if re.fullmatch(r"O-[a-f0-9]{24,32}", operation["id"]):
            result["id"] = operation["id"]
        for key, allowed in (("method", {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}),
                             ("protocol", {"http", "graphql"}), ("auth", {"public", "authenticated", "restricted", "unknown"})):
            if operation.get(key) in allowed:
                result[key] = operation[key]
        if _nonrequestable_metadata(result):
            result.update(url_redacted=True, locator_requires_binding=True, native_input_requires_binding=True, requestable=False)
    return public


def _assert_operation_inputs(project, operation_id, location, selector):
    """关联到具体输入时必须真的存在于该操作，避免把线索挂到不存在的字段上。"""
    operation = project.get("operation", operation_id)
    for entry in operation.get("inputs", []):
        if entry.get("location") == location and entry.get("selector") == selector:
            return operation
    raise EngineError("candidate_input",
                      "The linked input must already be registered on that operation")


def link_candidate(project, args):
    """把未解析线索记录成对应 Operation（可选到具体 Input）的关联。

    只建立来源关系，不产生输入、不关闭义务、不生成证据：语义提升仍然要求
    调用方显式 register 输入或执行实验。
    """
    with project.transaction():
        candidate = project.get("candidate", args["candidate_id"])
        if candidate.get("status") == DISMISSED:
            raise EngineError("candidate_dismissed", "A dismissed candidate must be reopened explicitly")
        operation_id = args["operation_id"]
        location, selector = args.get("input_location"), args.get("input_selector")
        if (location is None) != (selector is None):
            raise EngineError("candidate_input", "Supply both input_location and input_selector, or neither")
        operation = project.get("operation", operation_id)
        if location is not None and selector is not None:
            operation = _assert_operation_inputs(project, operation_id, location, selector)
        if candidate.get("url") and operation.get("url") and candidate["url"] != operation["url"]:
            raise EngineError("candidate_scope",
                              "The operation URL differs from the线索 URL; register the intended operation first")
        previous = candidate.get("operation_id")
        candidate.update(status=LINKED, operation_id=operation_id, updated_at=now(),
                         link={"operation_id": operation_id,
                               "input_location": location, "input_selector": selector,
                               "linked_at": now(), "previous_operation_id": previous})
        project.put("candidate", candidate)
        project.event("candidate.linked", {"candidate_id": candidate["id"],
                                           "operation_id": operation_id,
                                           "input_selector": selector})
        return _public_candidate(project, candidate)


def dismiss_candidate(project, args):
    """Retain a declaration; only a current verified basis can close discovery work."""
    unknown = set(args) - {"project_id", "candidate_id", "reason", "basis", "operation_id"}
    if unknown:
        raise EngineError("arguments", "Candidate dismissal does not accept force, override or imported authority fields",
                          {"unknown_fields": sorted(unknown), "help_action": "action.help",
                           "help_input": {"name": "candidate.dismiss"}})
    reason = args.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise EngineError("candidate_reason", "Dismissal requires a reason")
    basis = args.get("basis")
    if basis is not None and (not isinstance(basis, str) or basis not in DISMISSAL_BASES):
        raise EngineError("candidate_closure", "basis must be outside_scope or duplicate_operation")
    operation_id = args.get("operation_id")
    if (basis == "duplicate_operation" and (not isinstance(operation_id, str) or not operation_id)) \
            or (basis != "duplicate_operation" and operation_id is not None):
        raise EngineError("candidate_closure", "Only duplicate_operation requires a concrete operation_id")
    with project.transaction():
        candidate = project.get("candidate", args["candidate_id"])
        if candidate.get("status") == LINKED:
            raise EngineError("candidate_linked",
                              "A linked candidate is part of the operation lineage; unlink is not supported")
        previous = {key: candidate.get(key) for key in ("status", "reason", "candidate_closure")}
        candidate.update(status=DISMISSED, reason=reason.strip()[:1000], updated_at=now())
        candidate.pop("candidate_closure", None)
        candidate.pop("candidate_closure_context", None)
        if basis is not None:
            from .engine import evaluate_coverage

            candidate["candidate_closure"] = {"version": 1, "basis": basis}
            if operation_id is not None:
                candidate["candidate_closure"]["operation_id"] = operation_id
            candidate["candidate_closure_context"] = _closure_context(candidate)
            if not dismissal_valid(project, candidate, evaluate_coverage(project)):
                raise EngineError("candidate_closure", "The source, declared scope or current typed coverage does not establish this dismissal basis",
                                  {"candidate_id": candidate["id"], "next_action": "candidate.inspect"})
        project.put("candidate", candidate)
        project.event("candidate.dismissed", {"candidate_id": candidate["id"],
                                              "reason": candidate["reason"], "previous": previous,
                                              "candidate_closure": candidate.get("candidate_closure"),
                                              "reason_basis": "engine_revalidated" if basis else "caller_declaration"})
        return _public_candidate(project, candidate)


def reopen_candidate(project, args):
    """来源文件更新后允许重新打开，但必须给出依据。"""
    reason = args.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise EngineError("candidate_reason", "Reopening requires a reason")
    with project.transaction():
        candidate = project.get("candidate", args["candidate_id"])
        previous = {key: candidate.get(key) for key in ("status", "reason", "candidate_closure")}
        candidate.update(status=UNVERIFIED, reason=reason.strip()[:1000], updated_at=now())
        candidate.pop("link", None)
        candidate.pop("candidate_closure", None)
        candidate.pop("candidate_closure_context", None)
        project.put("candidate", candidate)
        project.event("candidate.reopened", {"candidate_id": candidate["id"], "previous": previous})
        return _public_candidate(project, candidate)


def store_candidate(project, candidate, *, default_status=UNVERIFIED):
    """导入路径共用的写入入口：稳定 ID、幂等、不覆盖已有处置。

    返回 (id, created)。已存在的线索只更新来源集合，保留人工处置状态。
    """
    identity = candidate_id(candidate)
    existing = project.get("candidate", identity, required=False)
    if existing is not None and candidate.get("kind") == "operation_hint" \
            and canonical(_request_profile(existing)) != canonical(_request_profile(candidate)):
        # A bare new clue must not overwrite a richer profile at a legacy ID.
        identity = _profile_identity(candidate, force=True)
        existing = project.get("candidate", identity, required=False)
    if existing is None and (candidate.get("kind") == "operation_hint" or isinstance(candidate.get("hint"), dict)):
        for legacy_id in _legacy_profile_ids(candidate):
            prior = project.get("candidate", legacy_id, required=False)
            if prior and _legacy_profile_match(prior, candidate):
                identity, existing = prior["id"], prior
                break
    if existing is not None:
        merged = _merge_actual_sources(existing, candidate)
        merged["updated_at"] = now()
        project.put("candidate", merged)
        return identity, False
    record = dict(candidate)
    # Imported lifecycle text cannot import an engine-created closure receipt.
    record.pop("candidate_closure", None)
    record.pop("candidate_closure_context", None)
    record["id"] = identity
    record.setdefault("status", default_status)
    record.setdefault("created_at", now())
    record["updated_at"] = now()
    project.put("candidate", record, create_only=True)
    return identity, True
