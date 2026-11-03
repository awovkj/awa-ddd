"""Offline target-definition and validator hints; scores never establish proof."""
from __future__ import annotations

from urllib.parse import urlsplit


FAMILIES = {"access_control", "sql_injection", "xss", "ssrf", "xxe", "path_traversal", "command_injection",
            "template_injection", "deserialization", "file_upload", "business_logic", "generic"}
SOURCE_KINDS = {"target_definition", "validator_export", "assessment_checklist"}
RESULTS = {"hint", "valid", "type_error", "param_error", "unregistered"}
LOCATIONS = {"GET": "query", "POST": "body", "PATH": "path", "FILES": "body", "HEAD": "header",
             "query": "query", "body": "body", "path": "path", "header": "header", "cookie": "cookie"}
TYPE_HINTS = {
    "SQL注入": ["sql_injection"], "越权访问": ["access_control"], "XSS注入": ["xss"], "XSS": ["xss"],
    "SSRF": ["ssrf"], "XXE": ["xxe"], "路径穿越": ["path_traversal"], "文件上传": ["file_upload"],
    "RCE": ["command_injection", "template_injection", "deserialization"],
    "交易篡改": ["business_logic"], "竞态重放": ["business_logic"], "用户枚举": ["business_logic"],
    "暴力破解": ["business_logic"], "绕过验证": ["business_logic"], "URL任意跳转": ["generic"],
    "反序列化": ["deserialization"], "命令注入": ["command_injection"], "模板注入": ["template_injection"],
}


def _score(value):
    return type(value) is int and 0 <= value <= 1000000000


def _fields(values, native):
    from .discovery import _input, _name

    if not isinstance(values, list) or len(values) > 2048:
        raise ValueError("assessment hint inputs must be a bounded array")
    fields = []
    for value in values:
        if native:
            if not isinstance(value, list) or len(value) != 2:
                raise ValueError("native definition parameters need [name,location]")
            name, location = value
            selector = name
        else:
            if not isinstance(value, dict):
                raise ValueError("normalized hint inputs must be objects")
            name, location = value.get("name"), value.get("location")
            selector = value.get("selector", name)
        if not _name(name) or not isinstance(location, str) or location not in LOCATIONS or not _name(selector):
            raise ValueError("assessment hint input identity is invalid")
        fields.append(_input(name, LOCATIONS[location], selector, "inferred", declared_location=location))
    return fields


def ingest(doc, base_url, out):
    """Support a normalized export or the exact [url,params,type,score] definition."""
    from .discovery import METHODS, _dedupe_inputs, _input, _url

    if not isinstance(doc, dict):
        raise ValueError("assessment hints require an object")
    native = "vulns" in doc
    if native:
        if "entries" in doc or not isinstance(doc.get("version"), str) or not 1 <= len(doc["version"]) <= 100 \
                or not _score(doc.get("maxScore")):
            raise ValueError("native definition needs version, vulns and maxScore")
        source_kind, rows = "target_definition", doc["vulns"]
    else:
        if doc.get("schema_version") != 1 or type(doc.get("schema_version")) is not int \
                or not isinstance(doc.get("source_kind"), str) or doc["source_kind"] not in SOURCE_KINDS:
            raise ValueError("normalized hints need schema_version:1 and a declared source_kind")
        source_kind, rows = doc["source_kind"], doc.get("entries")
    if not isinstance(rows, list) or len(rows) > 10000:
        raise ValueError("assessment hint entries must be a bounded array")
    scores = []
    for index, entry in enumerate(rows):
        out.tick()
        locator = ("#/vulns/" if native else "#/entries/") + str(index)
        try:
            if native:
                if not isinstance(entry, list) or len(entry) != 4 or not _score(entry[3]):
                    raise ValueError("native hint needs [url,params,type,score]")
                raw_url, parameters, declared_type, score = entry
                method, family, result = None, None, "hint"
                scores.append(score)
            else:
                if not isinstance(entry, dict) or "params" in entry and "inputs" in entry:
                    raise ValueError("normalized hint must be unambiguous")
                raw_url, declared_type, family = entry.get("url"), entry.get("type"), entry.get("test_family")
                parameters = entry.get("inputs", entry.get("params", []))
                method, result = entry.get("method"), entry.get("result", "hint")
                if family is not None and (not isinstance(family, str) or family not in FAMILIES):
                    raise ValueError("unsupported hinted family")
                if not isinstance(result, str) or result not in RESULTS:
                    raise ValueError("unsupported validator result")
            if not isinstance(raw_url, str) or len(raw_url) > 8192:
                raise ValueError("hint URL is invalid")
            if method is not None:
                if not isinstance(method, str) or method.lower() not in METHODS:
                    raise ValueError("hint method is invalid")
                method = method.upper()
            clean, query = _url(raw_url, base_url)
            fields = _fields(parameters, native)
            fields.extend(_input(name, "query", name, "inferred") for name in query)
            fields = _dedupe_inputs(fields)
            suggestions = [family] if family else TYPE_HINTS.get(declared_type, []) if isinstance(declared_type, str) else []
            if not suggestions:
                out.limit("assessment_hint_family_requires_review", locator)
            row = {"kind": "answer_key_hint" if source_kind == "target_definition" else "validator_hint" if source_kind == "validator_export" else "assessment_hint",
                   "url": clean, "method": method, "inputs": fields,
                   "source_kind": source_kind, "sources": [out.source(locator, "unknown")],
                   "suggested_test_families": list(suggestions), "validator_result": result,
                   "verification_level": "hint_only", "hints_only": True,
                   "independent_evidence_required": True, "usable_for_confirmation": False,
                   "requestable": False, "method_requires_binding": method is None,
                   "reason": "External definitions and validation responses prioritize hypotheses only; independently bind and test before any finding."}
            if isinstance(declared_type, str) and declared_type in TYPE_HINTS:
                row["declared_type"] = declared_type
            if any(token in urlsplit(clean).path for token in ("{", "}", "<", ">")):
                row["locator_requires_binding"] = True
            out.candidate(row)
        except (ValueError, UnicodeError, TypeError):
            out.limit("invalid_assessment_hint", locator)
    if native and sum(scores) != doc["maxScore"]:
        out.limit("assessment_hint_score_mismatch")
    out.limit("assessment_hints_are_not_independent_vulnerability_evidence")
    out.limit("assessment_hint_scores_do_not_measure_security_coverage")
    out.limit("assessment_hint_import_never_executes_or_registers_operations")
