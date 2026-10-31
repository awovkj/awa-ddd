"""Read-only assessment closure: observations and baselines are not security coverage."""
from __future__ import annotations

from collections import deque
import hashlib
import re

from .store import EngineError, canonical


FAMILY_LABELS = {
    "access_control": "身份、角色与资源权限", "sql_injection": "SQL 注入", "xss": "跨站脚本",
    "ssrf": "服务端请求伪造", "xxe": "XML 外部实体", "path_traversal": "路径穿越与文件读取",
    "command_injection": "命令注入", "template_injection": "模板注入", "deserialization": "不安全反序列化",
    "file_upload": "文件上传", "business_logic": "业务逻辑与状态链", "generic": "待明确的输入假设",
}
PROOF_CHANNELS = {
    "sql_injection": ["sql_metadata", "error_channel"], "xss": ["analyst_runtime"],
    "business_logic": ["semantic_negative", "state_invariant", "state_transition"],
    "xxe": ["extraction"], "ssrf": ["extraction"], "path_traversal": ["extraction"],
    "command_injection": ["semantic_negative", "analyst_review"], "template_injection": ["semantic_negative", "analyst_review"],
    "deserialization": ["semantic_negative", "analyst_review"], "file_upload": ["semantic_negative", "analyst_review"],
    "generic": ["semantic_negative"], "access_control": ["authorization"],
}


def suggested_families(entry, operation):
    """Untrusted review hints only; never declare a consumer or create an obligation."""
    name = str(entry.get("name") or entry.get("selector") or "").lower()
    media = str(operation.get("content_type") or "").lower()
    hints = set()
    if re.search(r"sort|order_by|keyword|search|query|^q$|^id$", name):
        hints.add("sql_injection")
    if re.search(r"url|webhook|callback|endpoint|target|remote", name):
        hints.add("ssrf")
    if re.search(r"html|description|comment|content|message|nickname", name):
        hints.add("xss")
    if "xml" in media or "xml" in name:
        hints.add("xxe")
    if re.search(r"path|filename|directory|template", name):
        hints.add("path_traversal")
    if re.search(r"file|upload|avatar", name) or "multipart/form-data" in media:
        hints.add("file_upload")
    if re.search(r"amount|price|balance|refund|weight|probabil|token|quantity|use_points|points|coupon|discount|qty|order_time|timestamp|sign", name):
        hints.add("business_logic")
    if re.search(r"command|shell|cmd|exec", name):
        hints.add("command_injection")
    if re.search(r"template|expression|render", name):
        hints.add("template_injection")
    if re.search(r"serialized|deserialize|pickle|object_data", name):
        hints.add("deserialization")
    route = str(operation.get("url") or "").lower()
    if "promo-rule" in route and re.search(r"rules?|expression|formula", name):
        hints.update({"template_injection", "business_logic"})
    if "import-json" in route and entry.get("location") in {"body", "graphql"}:
        hints.update({"deserialization", "generic"})
    return sorted(hints)


def _entry(operation, item):
    return next((entry for entry in operation.get("inputs", [])
                 if entry.get("location") == item.get("input_location")
                 and entry.get("selector", entry.get("name")) == item.get("input_selector")
                 and entry.get("schema_branch") == item.get("schema_branch")), {})


def obligation_family(item, operation):
    if item.get("test_family"):
        return item["test_family"]
    if item.get("kind") in {"access", "ownership", "auth_review", "identity_setup", "ownership_setup"}:
        return "access_control"
    consumer = re.sub(r"[^a-z0-9]", "", str(_entry(operation, item).get("consumer") or "").lower())
    if "sql" in consumer and not consumer.startswith("nosql"):
        return "sql_injection"
    for family, terms in (
        ("xss", ("xss", "innerhtml", "htmlrender")), ("ssrf", ("ssrf", "outboundhttp")),
        ("xxe", ("xxe", "xmlparser")), ("path_traversal", ("pathtraversal", "filepath")),
        ("command_injection", ("command", "shell")), ("template_injection", ("template",)),
        ("deserialization", ("deserial",)), ("file_upload", ("upload",)),
        ("business_logic", ("state", "weight", "amount", "refund", "business", "price", "balance")),
    ):
        if any(term in consumer for term in terms):
            return family
    return "generic"


def _status(item, gaps):
    return gaps.get(item["id"], {}).get("status", item.get("status", "open"))


def _bucket():
    return {"total": 0, "evaluated": 0, "open": 0, "blocked": 0, "not_applicable": 0}


def _ratio(row):
    denominator = row["total"] - row["not_applicable"]
    return row["evaluated"] / denominator if denominator else None


def _tscanplus_incomplete(run):
    tool = run.get("selected_tool", run.get("action"))
    # A result-only HTTP receipt is not a remote job or a dispatched request.
    bounded_read = isinstance(tool, str) and (tool in {"query_results", "project_summary", "route_candidates"}
        or tool == "http_request" and run.get("dispatch_attempted") is True)
    return run.get("remote_may_continue") is True or run.get("response_truncated") is True \
        or run.get("unretrieved_results") is True or bounded_read and run.get("results_complete") is False


def _inventory(project, evaluated):
    from . import browser, engine

    operations = {operation["id"]: operation for operation in project.list("operation")}
    gaps = {gap["id"]: gap for gap in evaluated["gaps"]}
    obligations = [item for item in project.list("obligation") if not item.get("superseded")]
    decisions = {decision["id"]: decision for decision in project.list("decision")}
    valid_decision_ids = {item.get("decision_id") for item in obligations if _status(item, gaps) == "evaluated"}
    current_findings = [finding for finding in evaluated["findings"] if finding.get("current") is True]
    finding_decision_ids = set()
    for finding in current_findings:
        finding_decision_ids.add(finding.get("decision_id"))
        decision = decisions.get(finding.get("decision_id"), {})
        valid_decision_ids.add(decision.get("id"))
        if decision.get("proof_decision_id"):
            valid_decision_ids.add(decision["proof_decision_id"])
            finding_decision_ids.add(decision["proof_decision_id"])
    for finding in evaluated["findings"]:
        finding_decision_ids.add(finding.get("decision_id"))
        source = decisions.get(finding.get("decision_id"), {})
        if source.get("proof_decision_id"):
            finding_decision_ids.add(source["proof_decision_id"])
    valid_decisions = [decisions[identity] for identity in valid_decision_ids if identity in decisions]
    used_evidence = {identity for decision in valid_decisions for identity in decision.get("evidence_ids", [])}
    identity_evidence = {session.get("verification_evidence_id") for session in project.list("session")}
    current_observations = []
    for evidence in project.list("evidence"):
        if evidence.get("kind") != "http":
            continue
        try:
            engine.verify_current_evidence(project, evidence["id"])
            current_observations.append(evidence)
        except (EngineError, OSError, ValueError, TypeError, KeyError):
            continue
    unassessed = [evidence for evidence in current_observations
                  if evidence["id"] not in used_evidence and evidence["id"] not in identity_evidence]
    active_obligations = {item["id"]: item for item in obligations}
    unlinked_analyst = []
    for finding in current_findings:
        if finding.get("mode") != "analyst":
            continue
        decision = decisions.get(finding.get("decision_id"), {})
        item = active_obligations.get(decision.get("obligation_id"))
        if item is None or _status(item, gaps) != "evaluated":
            unlinked_analyst.append(finding)
    unrecorded = [decision for decision in valid_decisions if decision.get("outcome") == "confirmed"
                  and decision["id"] not in finding_decision_ids]
    unresolved_candidates = []
    proof_resolved_candidates = []
    for candidate in project.list("candidate"):
        if candidate.get("status", "unverified") == "dismissed":
            continue
        # A precisely bound accepted metadata proof can account for its original
        # tool clue. Merely linking a clue to an operation never resolves it.
        resolved = candidate.get("kind") == "tool_metadata" and any(
            decision.get("outcome") == "confirmed"
            and decision.get("operation_id") == candidate.get("operation_id")
            and (decision.get("oracle") or {}).get("tool_run_id") == candidate.get("tool_run_id")
            and candidate.get("tool_run_id")
            and (decision.get("oracle") or {}).get("metadata_type") == candidate.get("name")
            and (decision.get("oracle") or {}).get("expected_value") == candidate.get("recovered_value")
            for decision in valid_decisions)
        (proof_resolved_candidates if resolved else unresolved_candidates).append(candidate)
    page_coverage = browser.coverage(project)
    bad_pages = {item["page_id"] for item in page_coverage["unvisited"]}
    bad_functions = {item["function_id"] for item in page_coverage["untriggered"]}
    used_visits = set()
    for page in project.list("page"):
        if page["id"] not in bad_pages:
            used_visits.add(page.get("page_visit_id", page.get("visit_id")))
        for function in page.get("functions", []):
            if function["id"] not in bad_functions:
                used_visits.add(function.get("page_visit_id", function.get("visit_id")))
    for decision in valid_decisions:
        used_visits.add((decision.get("runtime") or {}).get("visit_id"))
        used_visits.add((decision.get("proof") or {}).get("visit_id"))
    orphan_visits = []
    for visit in project.list("page_visit"):
        if visit["id"] in used_visits:
            continue
        row = dict(visit)
        try:
            browser._verified_visit(project, visit["id"], visit["url"])
            row["adopt_ready"] = True
        except (EngineError, OSError, ValueError, TypeError, KeyError) as exc:
            row.update(adopt_ready=False, review_reason_code=getattr(exc, "code", "page_evidence_invalid"))
        orphan_visits.append(row)
    pending_runs = [run for run in project.list("run") if run.get("status") in {"running", "interrupted"}
                    or run.get("status") == "failed" and run.get("kind") in {"http", "scenario"}]
    partial_tools = [run for run in project.list("run") if run.get("adapter") in {"sqlmap", "yakit"}
        and run.get("status") == "failed" and (run.get("target_traffic_sent") or run.get("traffic_requests")
                                             or run.get("effect") == "test_resource_write")
        and (run.get("error_code") in {"tool_timeout", "tool_output_budget", "tool_cancelled"}
             or run.get("diagnostic") == "timeout" or run.get("injection_signal") or run.get("metadata_candidates"))]
    partial_tools.extend(run for run in project.list("run") if run.get("adapter") == "tscanplus"
        and run.get("status") not in {"running", "interrupted"} and _tscanplus_incomplete(run))
    inventory = {"operations": operations, "obligations": obligations, "gaps": gaps, "decisions": decisions,
            "valid_decisions": valid_decisions, "current_findings": current_findings,
            "observations": current_observations, "unassessed": unassessed,
            "unlinked_analyst": unlinked_analyst, "unrecorded": unrecorded,
            "candidates": unresolved_candidates, "proof_resolved_candidates": proof_resolved_candidates,
            "page_coverage": page_coverage, "orphan_visits": orphan_visits, "pending_runs": pending_runs,
            "partial_tools": partial_tools}
    from .continuation import apply_reviews
    return apply_reviews(project, inventory)


def _security(inventory):
    from .engine import TEST_FAMILIES

    total, by_family, by_operation = _bucket(), {}, {}
    for item in inventory["obligations"]:
        if item.get("kind") == "baseline":
            continue
        operation = inventory["operations"].get(item.get("operation_id"), {})
        family = obligation_family(item, operation)
        status = _status(item, inventory["gaps"])
        for bucket in (total, by_family.setdefault(family, _bucket()),
                       by_operation.setdefault(item["operation_id"], _bucket())):
            bucket["total"] += 1
            bucket[status] = bucket.get(status, 0) + 1
    matrix = []
    for family in ("access_control", *TEST_FAMILIES):
        row = {"test_family": family, "label_zh": FAMILY_LABELS[family], **by_family.get(family, _bucket())}
        row["ratio"] = _ratio(row)
        row["status"] = ("not_planned" if not row["total"] else "open" if row["open"] else
                         "blocked" if row["blocked"] else "not_applicable" if not row["evaluated"] else "completed")
        row["declared_inputs"] = sum(family in entry.get("test_families", [])
            for operation in inventory["operations"].values() for entry in operation.get("inputs", []))
        row["untraced_inputs"] = sum(family in entry.get("test_families", []) and
            str(entry.get("consumer", "unknown")).strip().lower() in {"unknown", "other", ""}
            for operation in inventory["operations"].values() for entry in operation.get("inputs", []))
        if row["untraced_inputs"]:
            row["status"] = "review_required"
        row["proof_channels"] = PROOF_CHANNELS[family]
        matrix.append(row)
    complete = sum(not bucket["open"] and not bucket["blocked"]
                   and not inventory["operations"][identity].get("ownership_sampling", {}).get("limited")
                   for identity, bucket in by_operation.items())
    return {**total, "ratio": _ratio(total), "operations_total": len(inventory["operations"]),
            "operations_with_security_tests": len(by_operation), "operations_complete": complete,
            "operations_without_security_tests": len(inventory["operations"]) - len(by_operation),
            "by_family": [{key: value for key, value in row.items() if key not in {"proof_channels", "declared_inputs", "untraced_inputs"}}
                          for row in matrix if row["total"]],
            "note_zh": "安全义务不包含正常基线；完成仅限登记的具体假设及代表样本，不能证明其他类别、输入或资源安全。"}, matrix


def _completion(inventory, security, evaluated):
    pending = {
        "open_obligations": evaluated["open"] + evaluated["blocked"],
        "open_security_obligations": security["open"] + security["blocked"],
        "unresolved_candidates": len(inventory["candidates"]),
        "unassessed_observations": len(inventory["unassessed"]),
        "unlinked_analyst_findings": len(inventory["unlinked_analyst"]),
        "unrecorded_confirmations": len(inventory["unrecorded"]),
        "orphan_browser_visits": len(inventory["orphan_visits"]),
        "pages_unvisited": len(inventory["page_coverage"]["unvisited"]),
        "functions_untriggered": len(inventory["page_coverage"]["untriggered"]),
        "unreconciled_runs": len(inventory["pending_runs"]),
        "failed_partial_tools": len(inventory["partial_tools"]),
        "limited_ownership_sampling": sum(operation.get("ownership_sampling", {}).get("limited") is True
                                          for operation in inventory["operations"].values()),
    }
    names = {"open_obligations": "登记义务仍未闭环", "unresolved_candidates": "候选线索仍待复核",
             "unassessed_observations": "有效 HTTP 观察尚未归档为判据或结论",
             "unlinked_analyst_findings": "人工发现尚未绑定可关闭的测试义务",
             "unrecorded_confirmations": "已确认判据尚未登记当前发现", "orphan_browser_visits": "浏览器观察未绑定页面、功能或运行时证明",
             "pages_unvisited": "登记页面尚未完成真实访问", "functions_untriggered": "登记功能尚未完成真实触发",
             "unreconciled_runs": "执行记录仍需检查或恢复，不能自动重放", "failed_partial_tools": "工具失败、远端执行未决或结果未完整归档仍需复核",
             "limited_ownership_sampling": "权限测试超过有界样本预算"}
    reasons = [f"{label}：{pending[key]} 项。" for key, label in names.items() if pending[key]]
    if security["operations_without_security_tests"]:
        reasons.append(f"{security['operations_without_security_tests']} 个操作仅登记或仅有基线，没有明确的安全测试义务。")
    if not security["total"]:
        reasons.append("尚未建立可验证的安全测试义务；正常响应和请求数量不能替代漏洞测试。")
    if not inventory["operations"]:
        reasons.append("尚未建立操作清单，无法评价已登记攻击面的测试完整性。")
    status = "partial" if reasons else "complete"
    if not inventory["operations"] and not inventory["observations"] and not inventory["current_findings"] \
            and not inventory["orphan_visits"] and not inventory["page_coverage"]["pages"] \
            and not inventory["candidates"] and not inventory["pending_runs"] and not inventory["partial_tools"]:
        status = "not_started"
    return {"status": status, "label_zh": {"partial": "部分完成，仍有覆盖或归档缺口",
            "complete": "已登记安全任务完成闭环（不代表目标完整安全）", "not_started": "尚未建立可评价的测试清单"}[status],
            "registered_scope_only": True, **pending, "reasons_zh": reasons,
            "limitations_zh": ["没有未决项只说明已登记任务闭环，不证明没有未发现的接口或漏洞。",
                               "未声明、未执行的漏洞类别必须保留为未规划或未测，不能自动记为不适用。",
                               "基线、观察次数、工具版本和页面登记均不等于安全测试完成。",
                               "代表资源及同角色样本有明确边界，不代表全部租户、资源和业务状态。"]}


def summarize(project, evaluated):
    """Consume an existing evaluator result; do not recurse into evaluate_coverage."""
    inventory = _inventory(project, evaluated)
    security, _ = _security(inventory)
    completion = _completion(inventory, security, evaluated)
    from .continuation import control
    return {"security_coverage": security, "completion": completion,
            "continuation": control(project, evaluated, inventory=inventory, security=security, completion=completion)}


def _review_id(kind, identity):
    return "CL-" + hashlib.sha256(canonical([kind, identity]).encode("utf-8")).hexdigest()[:24]


def _checklist(inventory):
    rows = []
    labels = {"baseline": "补齐正常业务基线", "input_review": "追踪真实输入消费点", "input_test": "完成具体输入安全假设",
              "access": "验证身份或角色访问边界", "ownership": "验证资源所有权与租户边界",
              "auth_review": "明确实际访问策略", "identity_setup": "补齐服务端核验身份", "ownership_setup": "补齐权限测试资源和独立主体"}
    for item in inventory["obligations"]:
        gap = inventory["gaps"].get(item["id"])
        if gap is None:
            continue
        kind = item.get("kind", "unknown")
        row = {"id": _review_id("obligation", item["id"]), "kind": "obligation", "status": gap["status"],
               "label_zh": labels.get(kind, "复核未完成的测试义务"), "reason_zh": "该义务尚未形成当前有效判据或有证据支持的不适用结论。",
               "operation_id": item["operation_id"], "obligation_id": item["id"], "gap_id": gap["gap_id"],
               "action": "plan.next", "reason_code": gap["reason_code"]}
        for key in ("input_location", "input_selector", "test_family", "tenant_boundary"):
            if key in item:
                row[key] = item[key]
        if kind == "input_review":
            operation = inventory["operations"].get(item["operation_id"], {})
            row.update(action="surface.declare_consumer", suggested_test_families=suggested_families(_entry(operation, item), operation),
                       unverified_hint=True, reason_zh="字段名或媒体类型只提供待追踪方向，不是已证明的危险消费点。")
        rows.append(row)
    extras = (
        ("candidate", inventory["candidates"], "候选线索待复核", "候选登记或关联不能替代真实验证。", "candidate.inspect", "candidate_id"),
        ("unassessed_observation", inventory["unassessed"], "有效观察尚未形成判据", "先检查已有响应和绑定，不要仅为归档重复发送请求。", "evidence.inspect", "evidence_id"),
        ("unlinked_analyst_finding", inventory["unlinked_analyst"], "人工发现尚未进入义务闭环", "人工结论保留，但未关闭具体输入、权限或状态链测试义务。", "finding.list", "finding_id"),
        ("unrecorded_confirmation", inventory["unrecorded"], "确认判据尚未登记发现", "复核真实影响后使用 finding.record；此检查不会自动确认或创建发现。", "finding.record", "decision_id"),
        ("orphan_browser_visit", inventory["orphan_visits"], "浏览器观察未归档", "将已有真实观察绑定到页面、功能或具体运行时证明；访问记录不是 HTTP 测试。", "page.adopt", "page_visit_id"),
        ("unreconciled_run", inventory["pending_runs"], "执行状态仍需恢复检查", "检查已有 checkpoint 和证据，不自动重放可能已生效的请求。", "run.inspect", "run_id"),
        ("failed_partial_tool", inventory["partial_tools"], "工具执行或结果仍待复核", "已有目标流量、部分结果、未知远端执行或 POST 写效应不能当作安全阴性；检查原始 run/artifact，不自动重复执行。", "tool.inspect", "run_id"),
    )
    for kind, items, label, reason, action, field in extras:
        for item in items:
            row = {"id": _review_id(kind, item["id"]), "kind": kind, "status": "open", "label_zh": label,
                   "reason_zh": reason, "action": action, field: item["id"]}
            if item.get("operation_id"):
                row["operation_id"] = item["operation_id"]
            if kind == "orphan_browser_visit":
                if item.get("adopt_ready"):
                    row.update(suggested_action="page.adopt", input_template={"page_visit_id": item["id"]})
                else:
                    row.update(status="blocked", action="plan.audit", suggested_action="plan.audit",
                               reason_code=item.get("review_reason_code"), reason_zh="已有浏览器观察失败、受阻或摘要/血缘失效，不能收编为成功页面覆盖。")
            if kind == "unassessed_observation" and item.get("review_source_invalid"):
                row.update(status="blocked", reason_code=item.get("review_reason_code"),
                           reason_zh="曾归档的 HTTP 来源或血缘失效，必须修复或保留明确受阻，不能从闭环台账中消失。")
            rows.append(row)
    for operation in inventory["operations"].values():
        if operation.get("ownership_sampling", {}).get("limited"):
            rows.append({"id": _review_id("ownership_sample_limit", operation["id"]), "kind": "ownership_sample_limit",
                         "status": "blocked", "label_zh": "权限测试样本预算不足", "reason_zh": "部分租户、角色或请求绑定上下文未纳入有界计划，不能宣称全部覆盖。",
                         "operation_id": operation["id"], "action": "surface.inspect"})
        security_items = [item for item in inventory["obligations"] if item.get("operation_id") == operation["id"]
                          and item.get("kind") != "baseline"]
        if not security_items:
            rows.append({"id": _review_id("security_plan_missing", operation["id"]), "kind": "security_plan_missing",
                         "status": "open", "label_zh": "操作没有明确安全测试义务", "reason_zh": "正常基线不能替代权限、具体输入假设或业务安全检查。",
                         "operation_id": operation["id"], "action": "surface.inspect"})
    for kind, items, label, action in (("unvisited_page", inventory["page_coverage"]["unvisited"], "登记页面尚未完成访问", "page.mark"),
                                      ("untriggered_function", inventory["page_coverage"]["untriggered"], "登记功能尚未完成触发", "page.mark")):
        for item in items:
            identity = item.get("function_id", item["page_id"])
            row = {"id": _review_id(kind, identity), "kind": kind, "status": "blocked" if item.get("status") == "BLOCKED" else "open",
                   "label_zh": label, "reason_zh": "需要真实成功观察，登记或阻塞状态不会满足页面/功能覆盖。", "action": action, "page_id": item["page_id"]}
            if item.get("function_id"):
                row["function_id"] = item["function_id"]
            rows.append(row)
    for row in rows:
        review = inventory.get("blocked_reviews", {}).get(row["id"])
        if review:
            row.update(status="blocked", review_id=review["id"], reason_zh=review["reason"],
                       action="plan.review", suggested_action="plan.review",
                       input_template={"checklist_id": row["id"], "status": "reopen"})
    return sorted(rows, key=lambda row: (row["kind"] == "obligation", row["kind"], row["id"]))


def _blindspots(inventory, matrix):
    operations = list(inventory["operations"].values())
    unknown = [operation["id"] for operation in operations if any(
        str(entry.get("consumer", "unknown")).strip().lower() in {"unknown", "other", ""}
        for entry in operation.get("inputs", []))]
    legacy = [operation["id"] for operation in operations if any("test_families" not in entry for entry in operation.get("inputs", []))]
    rows = []
    def add(code, label, detail, affected=(), action="plan.next"):
        rows.append({"code": code, "label_zh": label, "detail_zh": detail,
                     "affected_operations": list(affected), "required_action": action})
    if unknown:
        add("untraced_consumers", "消费点未追踪", "未知消费点只产生复核义务；启发式建议不能当作已确认 SQL、HTML 或其他消费点。", unknown, "surface.declare_consumer")
    if legacy:
        add("legacy_single_hypothesis", "旧输入只有单一测试义务", "未声明 test_families 的旧输入保留原 ID 和单一义务，某个假设的否定不能代表其他漏洞类别安全。", legacy, "surface.declare_consumer")
    absent = [row["label_zh"] for row in matrix if not row["total"] and not row["declared_inputs"]]
    if absent:
        add("unplanned_families", "部分漏洞类别未建立测试计划", "未规划不等于不适用：" + "、".join(absent) + "。应结合实际输入、页面与业务功能明确测试假设。", action="surface.register")
    sql_operations = [operation["id"] for operation in operations if any(
        "sql" in str(entry.get("consumer") or "").lower() or "sql_injection" in entry.get("test_families", [])
        for entry in operation.get("inputs", []))]
    if sql_operations:
        add("sqlmap_profile_boundaries", "SQL 工具技术与上下文有边界", "每次工具结果仅覆盖绑定的参数、方法、身份和本次技术策略；未执行的时间、堆叠等技术及其他参数仍未测。no_injection、缺元数据和超时不是通用安全结论。", sql_operations, "tool.inspect")
    ssrf_operations = [operation["id"] for operation in operations if any(
        "ssrf" in str(entry.get("consumer") or "").lower() or "ssrf" in entry.get("test_families", [])
        or "ssrf" in suggested_families(entry, operation) for entry in operation.get("inputs", []))]
    if ssrf_operations:
        add("ssrf_observer_reachability", "SSRF 观察器和网络命名空间尚需核对", "没有提取结果可能是观察器不可达或基础设施错误。先核验 listener 可达性、Windows/WSL/容器 loopback 与请求来源；无数据、连接失败或超时不能自动判定 SSRF 已被否定。", ssrf_operations, "runtime.probe")
    if not inventory["page_coverage"]["pages"]:
        add("empty_page_ledger", "页面与功能清单为空", "HTTP 操作清单不能证明客户端路由、DOM 消费点、真实功能和浏览器运行时已经覆盖。", action="page.register")
    blocked_writes = [operation["id"] for operation in operations if operation.get("method") not in {"GET", "HEAD", "OPTIONS"}]
    if blocked_writes:
        add("write_experiment_prerequisites", "写侧业务实验需要显式前提", "写操作需要项目权限、精确测试资源与时序判据；读写分离状态链需绑定真实 scenario_run_id，不能靠重复写请求补齐前后状态。", blocked_writes, "scenario.preflight")
    sampled = [operation["id"] for operation in operations if operation.get("ownership_sampling")]
    if sampled:
        add("representative_ownership_sampling", "权限测试采用代表样本", "按所有者租户、角色、请求绑定及攻击者租户边界保留代表项；未采样资源和业务状态仍是限制。超过预算的上下文明确保留覆盖缺口。", sampled, "surface.inspect")
    limited_families = {"command_injection", "template_injection", "deserialization", "file_upload"}
    limited = [operation["id"] for operation in operations if any(
        limited_families.intersection(entry.get("test_families", [])) for entry in operation.get("inputs", []))]
    if limited:
        add("missing_positive_machine_adapter", "部分类别没有通用正向机器确认适配器", "命令、模板、反序列化和上传类别目前只能在明确假设下有限否定，或由人工复核实际证据；不能靠响应差异或文本描述宣称已执行。", limited, "action.help")
    return rows


def audit(project, args):
    from . import engine
    from .reporting import safe_metadata

    offset, limit = args.get("offset", 0), args.get("limit", 25)
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise EngineError("pagination", "offset must be a nonnegative integer; limit must be 1..100")
    evaluated = engine.evaluate_coverage(project)
    inventory = _inventory(project, evaluated)
    security, matrix = _security(inventory)
    checklist = _checklist(inventory)
    observed_operations = {item["operation_id"] for item in inventory["observations"]}
    observed_by_id = {item["id"]: item["operation_id"] for item in inventory["observations"]}
    assessed_operations = {decision.get("operation_id") for decision in inventory["valid_decisions"] if decision.get("operation_id")}
    assessed_operations.update(observed_by_id[identity] for decision in inventory["valid_decisions"]
                               for identity in decision.get("evidence_ids", []) if identity in observed_by_id)
    return safe_metadata({"project_id": project.project_id, "requests_sent": 0,
        "continuation": evaluated["continuation"],
        "completion": _completion(inventory, security, evaluated), "security_coverage": security,
        "layers": {"registered": {"operations": len(inventory["operations"]), "inputs": evaluated["inputs"]},
                   "observed": {"operations": len(observed_operations), "http_observations": len(inventory["observations"]),
                                "browser_visits": len(project.list("page_visit"))},
                   "assessed": {"operations": len(assessed_operations), "valid_decisions": len(inventory["valid_decisions"]),
                                "current_findings": len(inventory["current_findings"])},
                   "security": {"operations_complete": security["operations_complete"], "evaluated_obligations": security["evaluated"]}},
        "category_matrix": matrix, "technical_blindspots": _blindspots(inventory, matrix),
        "checklist": checklist[offset:offset + limit], "checklist_total": len(checklist), "offset": offset, "limit": limit,
        "next_offset": offset + limit if offset + limit < len(checklist) else None,
        "candidate_proof_accounted": len(inventory["proof_resolved_candidates"]),
        "administrative_reviews": len(inventory.get("reviewed_admin", [])),
        "next_action": "plan.next", "note_zh": "本检查仅读取现有材料，不发请求、不补造证据、不自动关闭义务，也不把启发式线索确认成漏洞。"})


def followups(project, evaluated, limit=5):
    from .reporting import safe_metadata

    rows = [row for row in _checklist(_inventory(project, evaluated)) if row["kind"] != "obligation"]
    lanes = {}
    for row in rows:
        lanes.setdefault(row["kind"], deque()).append(row)
    sample = []
    while any(lanes.values()) and len(sample) < limit:
        for lane in lanes.values():
            if lane and len(sample) < limit:
                sample.append(lane.popleft())
    return {"review_followups": safe_metadata(sample), "review_followup_total": len(rows),
            "review_followup_action": "plan.audit"}
