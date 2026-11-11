"""Persisted discovery-only policy; a session prompt cannot widen this boundary."""
from __future__ import annotations

import hashlib
from urllib.parse import urlsplit, urlunsplit

from .store import EngineError, now

MODES = {"assessment", "src"}
SRC_MAX_RESPONSE = 64 * 1024
SRC_MAX_TIMEOUT = 15
SRC_DENIED_ACTIONS = frozenset({
    "tool.sqlmap", "tool.yakit_replay", "tool.tscanplus_request",
    "test.run_external", "scenario.run", "test.run_scenario",
})


def normalize_mode(value):
    selected = "assessment" if value is None else value
    if not isinstance(selected, str) or selected not in MODES:
        raise EngineError("assessment_mode", "assessment_mode must be assessment or src")
    return selected


def mode(project):
    return normalize_mode(project.config.get("assessment_mode"))


def require_mode(project, args):
    required = args.get("required_assessment_mode")
    if required is not None and normalize_mode(required) != mode(project):
        raise EngineError("assessment_mode_mismatch",
                          "The session requires a project created in the same assessment mode; existing project mode is immutable",
                          {"assessment_mode": mode(project), "required_assessment_mode": required,
                           "next_action": "project.create", "requests_sent": 0})


def require_action(project, action, args):
    require_mode(project, args)
    if mode(project) == "src" and action in SRC_DENIED_ACTIONS:
        raise EngineError("src_action_denied",
                          "SRC uses bounded read-only discovery and offline evidence review; this execution action is unavailable",
                          {"action": action, "assessment_mode": "src", "requests_sent": 0,
                           "next_action": "assessment.prepare"})


def _stop_id(operation_id):
    return "SRC-" + hashlib.sha256(operation_id.encode("utf-8")).hexdigest()[:24]


def _endpoint(url):
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def record_stop(project, *, operation_id, evidence_ids, decision_id=None, finding_id=None,
                oracle_type=None):
    """Freeze an accepted direct finding; later evidence changes never reopen execution."""
    if mode(project) != "src":
        return None
    operation = project.get("operation", operation_id)
    if not evidence_ids:
        raise EngineError("evidence_binding", "A SRC stopping receipt requires direct evidence")
    from .engine import verify_current_evidence
    evidence = [verify_current_evidence(project, identity)[0] for identity in evidence_ids]
    identity = _stop_id(operation_id)
    with project.transaction():
        existing = project.get("src_stop", identity, required=False)
        if existing:
            return existing
        receipt = {"id": identity, "operation_id": operation_id,
                   "endpoint": _endpoint(operation["url"]), "method": operation["method"],
                   "decision_id": decision_id, "finding_id": finding_id,
                   "oracle_type": oracle_type, "evidence_ids": list(evidence_ids),
                   "evidence_hashes": [{"evidence_id": row["id"], "sha256": row["sha256"]} for row in evidence],
                   "policy": "stop_at_direct_evidence", "created_at": now()}
        project.put("src_stop", receipt, create_only=True)
        project.event("src.stopped_at_evidence", {"operation_id": operation_id,
                                                 "decision_id": decision_id, "finding_id": finding_id,
                                                 "evidence_ids": list(evidence_ids)})
        return receipt


def record_decision(project, decision):
    if mode(project) != "src" or decision.get("outcome") != "confirmed" \
            or decision.get("mode") != "machine" or (decision.get("oracle") or {}).get("type") == "baseline":
        return None
    from .engine import _decision_valid
    _decision_valid(project, decision)
    return record_stop(project, operation_id=decision["operation_id"],
                       evidence_ids=decision["evidence_ids"], decision_id=decision["id"],
                       oracle_type=(decision.get("oracle") or {}).get("type"))


def stop_receipt(project, operation):
    if mode(project) != "src":
        return None
    receipt = project.get("src_stop", _stop_id(operation["id"]), required=False)
    if receipt is None:
        endpoint = _endpoint(operation["url"])
        receipt = next((row for row in project.list("src_stop")
                        if row.get("endpoint") == endpoint and row.get("method") == operation["method"]), None)
    if receipt is None:
        from .scope import bind_operation
        for row in project.list("src_stop"):
            if row.get("method") != operation["method"]:
                continue
            template = project.get("operation", row["operation_id"], required=False)
            template = template or {"url": row["endpoint"], "method": row["method"]}
            try:
                bind_operation(template, operation["url"], operation["method"])
            except EngineError:
                continue
            receipt = row
            break
    return receipt


def require_not_stopped(project, operation):
    receipt = stop_receipt(project, operation)
    if receipt:
        raise EngineError("stopped_at_evidence",
                          "SRC already has direct evidence for this operation; continue with offline review/reporting or a different candidate",
                          {"operation_id": receipt["operation_id"], "decision_id": receipt.get("decision_id"),
                           "evidence_ids": receipt["evidence_ids"], "assessment_mode": "src",
                           "requests_sent": 0, "next_action": "evidence.inspect"})


def capture_policy(project, operation, args, *, existing=False):
    if mode(project) != "src":
        return
    if operation["method"] not in {"GET", "HEAD", "OPTIONS"} or args.get("effect", "read_only") != "read_only":
        raise EngineError("src_write_denied", "SRC does not submit writes or create mutation fixtures",
                          {"operation_id": operation["id"], "requests_sent": 0, "assessment_mode": "src"})
    if not existing:
        require_not_stopped(project, operation)


def browser_policy(project, url, args):
    if mode(project) != "src":
        return
    if args.get("allow_write") is True:
        raise EngineError("src_write_denied", "SRC browser visits remain read-only", {"requests_sent": 0})
    allowed = {"wait", "waitForSelector", "waitForDialog", "waitForURL"}
    for action in args.get("actions", []):
        if not isinstance(action, dict) or action.get("type", action.get("action")) not in allowed:
            raise EngineError("src_action_denied", "SRC browser actions support observation and waits only",
                              {"requests_sent": 0, "assessment_mode": "src"})
    from .scope import bind_operation
    for row in project.list("src_stop"):
        operation = project.get("operation", row["operation_id"], required=False)
        if operation is None:
            continue
        try:
            bind_operation(operation, url, "GET")
        except EngineError:
            continue
        raise EngineError("stopped_at_evidence", "SRC already has direct evidence for this page; use offline review",
                          {"requests_sent": 0, "assessment_mode": "src", "next_action": "evidence.inspect"})


def work_policy(project, row, operation):
    """Do not schedule prohibited controls to fill discovery-only coverage gaps."""
    if mode(project) != "src":
        return row
    receipt = stop_receipt(project, operation)
    reason = "stopped_at_evidence" if receipt else "src_write_denied" if operation["method"] not in {"GET", "HEAD", "OPTIONS"} else None
    if reason is None:
        return row
    row.update(execution_blocked=True, stop_reason=reason,
               note_zh="SRC 仅保留已发现问题的直接证据；本操作的后续测试保留为未测范围，继续离线复核或处理其他候选。")
    if "queue_status" in row:
        row["queue_status"] = "blocked"
        row["missing_prerequisites"] = list(dict.fromkeys(row.get("missing_prerequisites", []) + [reason]))
    if "preparation_state" in row:
        row["preparation_state"] = "stopped_at_evidence" if receipt else "src_discovery_only"
    row["suggested_action"] = "evidence.inspect" if receipt else "surface.inspect"
    row["input_template"] = {"evidence_id": receipt["evidence_ids"][0]} if receipt else {"operation_id": operation["id"]}
    row["help_input"] = {"name": row["suggested_action"]}
    row["recommended_tools"] = []
    row["preparation_actions"] = []
    browser = row.get("browser_testing")
    if isinstance(browser, dict):
        browser.update(stage="blocked", call_needed=False, invoke_now=False, execution_blocked=True,
                       required_input_fields=[reason])
        browser.pop("native_visit_input", None)
    return row


def status(project):
    selected = mode(project)
    return {"assessment_mode": selected,
            "stop_policy": "stop_at_direct_evidence" if selected == "src" else "existing_assessment_policy",
            "allow_mutation": False if selected == "src" else bool(project.config.get("allow_mutation")),
            "stopped_operations": [{"operation_id": row["operation_id"], "decision_id": row.get("decision_id"),
                                    "evidence_ids": row["evidence_ids"]} for row in project.list("src_stop")],
            "max_response_bytes": SRC_MAX_RESPONSE if selected == "src" else None}
