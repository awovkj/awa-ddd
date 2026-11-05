"""Read-only assessment closure: observations and baselines are not security coverage."""
from __future__ import annotations

from collections import deque
from bisect import bisect_left
from contextvars import ContextVar
import hashlib
import re

from .store import EngineError, canonical


_INVENTORY_RECEIVER = ContextVar("awa_ddd_inventory_receiver", default=None)


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
    if re.search(r"sort|order_by|keyword|search|query|^q$|^id$|^order$", name):
        hints.add("sql_injection")
    if re.search(r"url|webhook|callback|endpoint|target|remote", name):
        hints.add("ssrf")
    if re.search(r"html|description|comment|content|message|nickname|shop_name|^label$", name):
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
    if "promo-rule" in route and re.search(r"rules?|expression|formula|^label$", name):
        hints.update({"template_injection", "business_logic"})
    if re.search(r"username|password|captcha|sms.?code|otp|verify.?code|verification.?code|auth.?token", name) or re.search(r"/login(?:[/?.#]|$)", route):
        hints.update({"business_logic", "generic"})
    if re.search(r"redirect|return_?url|next_?url|redirect_?uri", name):
        hints.update({"business_logic", "generic"})
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
    if isinstance(item.get("scope_family"), str) and item["scope_family"] in FAMILY_LABELS:
        return item["scope_family"]
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


def _scope_key(item, operation):
    kind, identity = item.get("kind"), item.get("operation_id")
    if kind == "input_test":
        family = next((item[key] for key in ("test_family", "scope_family")
                       if isinstance(item.get(key), str) and item[key] in FAMILY_LABELS), None)
        if family is None:
            family = "legacy_signature:" + str(item.get("input_signature") or item["id"])
        return (identity, kind, item.get("input_location"), item.get("input_selector"),
                item.get("schema_branch"), family)
    if kind in {"baseline", "access"}:
        return (identity, kind, item.get("actor_id"))
    if kind == "ownership":
        return (identity, kind, item.get("actor_id"), item.get("baseline_actor_id"), item.get("resource_id"))
    return None


def _unknown_policy_replacements(project, obligations):
    """Recognize the first actual plan transaction replacing unknown-policy work."""
    from .engine import stamp

    with project._lock:
        metadata = project.connection.execute(
            "SELECT id,created_at,updated_at FROM entities WHERE kind='obligation'").fetchall()
        generated = project.connection.execute(
            "SELECT created_at FROM events WHERE type='plan.generated' ORDER BY seq").fetchall()
    try:
        boundaries = sorted({stamp(row[0]) for row in generated})
        times = {row[0]: (stamp(row[1]), stamp(row[2])) for row in metadata}
        for item in obligations:
            if item.get("superseded_at") is not None and item["id"] in times:
                times[item["id"]] = (times[item["id"]][0], stamp(item["superseded_at"]))
    except (EngineError, ValueError, TypeError, KeyError):
        return set()

    def generation(identity, column):
        if identity not in times:
            return None
        index = bisect_left(boundaries, times[identity][column])
        return index if index < len(boundaries) else None

    replacements = {}
    for item in obligations:
        if item.get("kind") == "auth_review" and item.get("superseded"):
            cycle = generation(item["id"], 1)
            if cycle is not None:
                replacements[item["operation_id"]] = cycle
    prior_known = set()
    for item in obligations:
        cycle = replacements.get(item["operation_id"])
        created = generation(item["id"], 0)
        if cycle is not None and created is not None and created < cycle \
                and (item.get("kind") == "identity_setup" or item.get("kind") == "baseline" and item.get("actor_id")):
            prior_known.add(item["operation_id"])
    return {item["id"] for item in obligations if item.get("kind") == "access" and item.get("superseded")
            and item["operation_id"] not in prior_known and item["operation_id"] in replacements
            and generation(item["id"], 1) == replacements[item["operation_id"]]}


def _historically_closed(project, item, decisions, key):
    from . import engine
    from .assessment import validate_confirmation

    decision = decisions.get(item.get("decision_id"), {})
    if item.get("status") != "evaluated" or decision.get("obligation_id") != item["id"] \
            or decision.get("outcome") not in {"confirmed", "refuted"} or not decision.get("evidence_ids"):
        return False
    if item.get("kind") == "input_test":
        oracle = decision.get("oracle") or {}
        if isinstance(key[-1], str) and key[-1].startswith("legacy_signature:"):
            return False
        if key[-1] == "sql_injection" and oracle.get("type") not in {"sql_metadata", "error_channel"}:
            return False
        if key[-1] == "xss" and (oracle.get("type") != "analyst_runtime" or oracle.get("test_family") != "xss"):
            return False
    try:
        for identity in decision["evidence_ids"]:
            engine.verify_current_evidence(project, identity)
        # The old record stays superseded; only its real proof is checked here.
        validate_confirmation(project, decision)
    except (EngineError, OSError, ValueError, TypeError, KeyError, AttributeError):
        return False
    return True


def _consumer_requirements(operations, obligations):
    result = []
    for operation in operations.values():
        for entry in operation.get("inputs", []):
            probe = {"operation_id": operation["id"], "input_location": entry.get("location"),
                     "input_selector": entry.get("selector", entry.get("name")), "schema_branch": entry.get("schema_branch")}
            family = obligation_family(probe, operation)
            families = entry.get("test_families", [])
            missing = family == "xss" and "xss" not in families \
                or family == "sql_injection" and "test_families" in entry and "sql_injection" not in families
            if not missing:
                continue
            references = [item["id"] for item in obligations if not item.get("superseded")
                          and item.get("operation_id") == operation["id"] and item.get("kind") in {"input_test", "input_review"}
                          and all(item.get(key) == value for key, value in probe.items())]
            result.append({**probe, "test_family": family, "consumer": entry.get("consumer"),
                           "scope_key": (operation["id"], "input_test", probe["input_location"], probe["input_selector"],
                                         probe["schema_branch"], family), "source_obligation_ids": references})
    return result


def _scope_reductions(project, obligations, operations, decisions, consumer_requirements):
    active = set()
    for item in obligations:
        if not item.get("superseded"):
            key = _scope_key(item, operations.get(item["operation_id"], {}))
            if key is not None:
                active.add(key)
            if item.get("kind") == "access":
                active.add((item["operation_id"], "baseline", item.get("actor_id")))
    active.update(item["scope_key"] for item in consumer_requirements)
    candidates = []
    for item in obligations:
        if not item.get("superseded"):
            continue
        key = _scope_key(item, operations.get(item["operation_id"], {}))
        keys = [key] if key is not None else []
        if item.get("kind") == "input_test" and isinstance(item.get("consumer_family"), str) \
                and item["consumer_family"] in {"sql_injection", "xss"}:
            keys.append((*key[:-1], item["consumer_family"]))
        for key in set(keys):
            if key not in active:
                candidates.append((key, item))
    unknown_replaced = _unknown_policy_replacements(project, obligations) \
        if any(item.get("kind") == "access" for key, item in candidates) else set()
    groups = {}
    for key, item in candidates:
        if item["id"] not in unknown_replaced and not _historically_closed(project, item, decisions, key):
            groups.setdefault(key, []).append(item)
    result = []
    for key, items in sorted(groups.items(), key=lambda row: canonical(row[0])):
        items.sort(key=lambda row: (row.get("created_at", ""), row["id"]))
        result.append({**items[0], "scope_key": key, "source_obligation_ids": [item["id"] for item in items]})
    return result


def _inventory(project, evaluated):
    from . import browser, engine
    from .parameter_coverage import ObservationProfiles, annotate_queue, snapshot as parameter_snapshot

    operations = {operation["id"]: operation for operation in project.list("operation")}
    gaps = {gap["id"]: gap for gap in evaluated["gaps"]}
    all_obligations = project.list("obligation")
    obligations = [item for item in all_obligations if not item.get("superseded")]
    # A current source authenticates the observation, not the caller's assertion
    # that the whole obligation is inapplicable. Invalid sources already reopen
    # the ordinary obligation gap and must not create a second review row.
    applicability_reviews = [item for item in obligations if _status(item, gaps) == "not_applicable"]
    decisions = {decision["id"]: decision for decision in project.list("decision")}
    consumer_requirements = _consumer_requirements(operations, all_obligations)
    scope_reductions = _scope_reductions(project, all_obligations, operations, decisions, consumer_requirements)
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
    method_observations = []
    parameter_profiles = ObservationProfiles(operations)
    for evidence in project.list("evidence"):
        try:
            current, artifact = engine.verify_current_evidence(project, evidence["id"])
            method_observations.append(current)
            if evidence.get("kind") == "http":
                current_observations.append(current)
                parameter_profiles.observe(current, artifact["request"])
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
    from .candidates import dismissal_valid, hint_proof_valid
    candidate_coverage = {**evaluated, "completion": {
        "applicability_review_total": len(applicability_reviews),
        "scope_reduction_review_total": len(scope_reductions) + len(consumer_requirements)}}
    for candidate in project.list("candidate"):
        if candidate.get("status", "unverified") == "dismissed":
            if dismissal_valid(project, candidate, candidate_coverage):
                continue
            candidate = {**candidate, "disposition_review_required": True}
        # A precisely bound accepted metadata proof can account for its original
        # tool clue. Merely linking a clue to an operation never resolves it.
        resolved = hint_proof_valid(project, candidate, candidate_coverage) or candidate.get("kind") == "tool_metadata" and any(
            decision.get("outcome") == "confirmed"
            and decision.get("operation_id") == candidate.get("operation_id")
            and (decision.get("oracle") or {}).get("tool_run_id") == candidate.get("tool_run_id")
            and candidate.get("tool_run_id")
            and (decision.get("oracle") or {}).get("metadata_type") == candidate.get("name")
            and (decision.get("oracle") or {}).get("expected_value") == candidate.get("recovered_value")
            for decision in valid_decisions)
        (proof_resolved_candidates if resolved else unresolved_candidates).append(candidate)
    page_coverage = browser.coverage(project)
    bad_functions = {item["function_id"] for item in page_coverage["untriggered"]}
    validated_browser_adoptions = browser.validated_adoptions(project)
    used_visits = {entry["page_visit_id"] for entry in validated_browser_adoptions}
    for page in project.list("page"):
        for function in page.get("functions", []):
            if function["id"] not in bad_functions:
                used_visits.add(function.get("page_visit_id", function.get("visit_id")))
    for decision in valid_decisions:
        used_visits.add((decision.get("runtime") or {}).get("visit_id"))
        used_visits.add((decision.get("proof") or {}).get("visit_id"))
    orphan_visits = []
    browser_origins, _ = browser._adoption_history(project)
    for visit in project.list("page_visit"):
        if visit["id"] in used_visits:
            continue
        row = dict(visit)
        try:
            browser._verified_visit(project, visit["id"], visit["url"], origin_events=browser_origins)
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
    config = project.config
    inventory = {"operations": operations, "obligations": obligations, "gaps": gaps, "decisions": decisions,
            "valid_decisions": valid_decisions, "current_findings": current_findings,
            "observations": current_observations, "method_observations": method_observations, "unassessed": unassessed,
            "unlinked_analyst": unlinked_analyst, "unrecorded": unrecorded,
            "candidates": unresolved_candidates, "proof_resolved_candidates": proof_resolved_candidates,
            "page_coverage": page_coverage, "orphan_visits": orphan_visits, "pending_runs": pending_runs,
            "validated_browser_adoptions": validated_browser_adoptions,
            "partial_tools": partial_tools, "applicability_reviews": applicability_reviews,
            "scope_reductions": scope_reductions,
            "consumer_requirements": consumer_requirements,
            "parameter_profiles": parameter_profiles,
            "browser_scope_config": {"scope": config.get("scope", []), "exclude": config.get("exclude", [])}}
    from .continuation import apply_reviews
    from .workflow import queue_inventory
    inventory = apply_reviews(project, inventory)
    inventory["parameter_coverage_snapshot"] = parameter_snapshot(project, evaluated, inventory=inventory)
    inventory["queue"] = queue_inventory(project, evaluated, inventory)
    annotate_queue(inventory["parameter_coverage_snapshot"], inventory["queue"])
    return inventory


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
        "applicability_review_total": len(inventory.get("applicability_reviews", [])),
        "scope_reduction_review_total": len(inventory.get("scope_reductions", [])) + len(inventory.get("consumer_requirements", [])),
        "limited_ownership_sampling": sum(operation.get("ownership_sampling", {}).get("limited") is True
                                          for operation in inventory["operations"].values()),
    }
    names = {"open_obligations": "登记义务仍未闭环", "unresolved_candidates": "候选线索仍待复核",
             "unassessed_observations": "有效 HTTP 观察尚未归档为判据或结论",
             "unlinked_analyst_findings": "人工发现尚未绑定可关闭的测试义务",
             "unrecorded_confirmations": "已确认判据尚未登记当前发现", "orphan_browser_visits": "浏览器观察未绑定页面、功能或运行时证明",
             "pages_unvisited": "登记页面尚未完成真实访问", "functions_untriggered": "登记功能尚未完成真实触发",
             "unreconciled_runs": "执行记录仍需检查或恢复，不能自动重放", "failed_partial_tools": "工具失败、远端执行未决或结果未完整归档仍需复核",
             "limited_ownership_sampling": "权限测试超过有界样本预算",
             "applicability_review_total": "人工不适用声明尚未形成可验证的测试闭环",
             "scope_reduction_review_total": "未测义务因计划缩减而被隐藏，仍需恢复真实测试边界"}
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


def evaluate_with_inventory(project):
    """Reuse the evaluator's own inventory for this call, never across snapshots."""
    from . import engine

    captured = []
    token = _INVENTORY_RECEIVER.set((project, captured))
    try:
        evaluated = engine.evaluate_coverage(project)
    finally:
        _INVENTORY_RECEIVER.reset(token)
    inventory = captured[-1] if captured else _inventory(project, evaluated)
    return evaluated, inventory


def summarize(project, evaluated):
    """Consume an existing evaluator result; do not recurse into evaluate_coverage."""
    from . import engine

    inventory = _inventory(project, evaluated)
    security, _ = _security(inventory)
    completion = _completion(inventory, security, evaluated)
    tested_operations = {item["operation_id"] for item in inventory["obligations"]
                         if item.get("status") == "evaluated" and item["id"] not in inventory["gaps"]}
    from .continuation import control
    result = {"security_coverage": security, "completion": completion,
            "parameter_coverage_summary": inventory["parameter_coverage_snapshot"]["summary"],
            "method_coverage": engine._method_coverage(project, tested_operations,
                                                     current_observations=inventory["method_observations"]),
            "continuation": control(project, evaluated, inventory=inventory, security=security, completion=completion)}
    receiver = _INVENTORY_RECEIVER.get()
    if receiver is not None and receiver[0] is project:
        receiver[1].append(inventory)
    return result


def _review_id(kind, identity):
    return "CL-" + hashlib.sha256(canonical([kind, identity]).encode("utf-8")).hexdigest()[:24]


def _checklist(inventory):
    from .browser_policy import for_page
    rows = []
    queue = {item["obligation_id"]: item for item in inventory.get("queue", [])}
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
        work = queue.get(item["id"], {})
        if work:
            row.update(queue_status=work["queue_status"], missing_prerequisites=work["missing_prerequisites"])
            for key in ("preparation_actions", "session_continuity", "parameter_coverage_id", "parameter_test_status",
                        "selected_input_observation_count", "selected_input_variant_observed", "controls_are_candidates_only",
                        "control_candidate_evidence_ids", "control_candidate_review_required"):
                if key in work:
                    row[key] = work[key]
        if work.get("scope_binding_review_required") is True and work.get("queue_status") != "blocked":
            # The audit handoff only inspects local metadata; it never supplies a request URL.
            for key in ("scope_binding_review_required", "url_requires_binding", "native_input_requires_binding",
                        "requestable", "scope_handoff_note", "scope_binding_followup_action",
                        "scope_binding_required_input_fields", "execution_blocked"):
                if key in work:
                    row[key] = work[key]
            row.update(action="surface.inspect", suggested_action="surface.inspect",
                       input_template={"operation_id": item["operation_id"]}, help_input={"name": "surface.inspect"},
                       scope_binding_followup_template={"operation_id": item["operation_id"]})
        if work.get("blocker_reconciliation_required"):
            row.update(status="open", declared_status="blocked", action="plan.disposition",
                       suggested_action="plan.disposition", blocker_reconciliation_required=True,
                       underlying_queue_status=work["underlying_queue_status"], execution_blocked=True,
                       input_template=dict(work["input_template"]), help_input={"name": "plan.disposition"},
                       operator_reason=work.get("operator_reason"), reason_code="declared_blocker_unverified")
        rows.append(row)
    for item in inventory.get("scope_reductions", []):
        row = {"id": _review_id("scope_reduction", canonical(item["scope_key"])), "kind": "scope_reduction",
               "status": "open", "label_zh": "被缩减的未测边界仍需闭环",
               "reason_zh": "变更输入族、分支或访问/所有权声明只能重建计划，不能把已登记但未测试的边界当作耗尽。保留旧义务来源，恢复对应边界后执行真实 typed 测试；行政复核或受阻文字不能关闭此项。",
               "reason_code": "scope_reduction_unverified", "operation_id": item["operation_id"],
               "obligation_id": item["id"], "obligation_kind": item.get("kind"),
               "source_obligation_ids": item["source_obligation_ids"], "action": "surface.inspect",
               "suggested_action": "surface.declare_consumer" if item.get("kind") == "input_test" else "surface.register",
               "administrative_review_allowed": False,
               "required_experiment_fields": ["Restore the exact previously planned family/input/branch or principal/fixture boundary from actual authorized sources.",
                                              "Close the restored current obligation using accepted evidence-bound assessment; never replay uncertain writes."]}
        row["help_input"] = {"name": row["suggested_action"]}
        for key in ("input_location", "input_selector", "test_family", "schema_branch", "actor_id", "baseline_actor_id", "resource_id"):
            if key in item:
                row[key] = item[key]
        if item.get("kind") == "input_test" and item["scope_key"][-1] in FAMILY_LABELS:
            row["test_family"] = item["scope_key"][-1]
        rows.append(row)
    for item in inventory.get("consumer_requirements", []):
        row = {"id": _review_id("consumer_family_required", canonical(item["scope_key"])), "kind": "consumer_family_required",
               "status": "open", "label_zh": "已声明消费点缺少必需测试族",
               "reason_zh": "明确 SQL 或 HTML 执行消费点不能靠只声明 generic 省略相应 SQL 元数据或 XSS 运行时验证。补齐具体族，再执行其真实 typed 闭环；这不是从字段名推测漏洞。",
               "reason_code": "consumer_family_missing", "operation_id": item["operation_id"],
               "input_location": item["input_location"], "input_selector": item["input_selector"],
               "schema_branch": item.get("schema_branch"), "test_family": item["test_family"],
               "source_obligation_ids": item["source_obligation_ids"], "action": "surface.declare_consumer",
               "suggested_action": "surface.declare_consumer", "administrative_review_allowed": False,
               "help_input": {"name": "surface.declare_consumer"},
               "required_experiment_fields": ["Preserve the declared concrete consumer and include its required test_family.",
                                              "Close each family independently with actual accepted evidence; this review is not a finding."]}
        rows.append(row)
    for item in inventory.get("applicability_reviews", []):
        row = {"id": _review_id("unverified_applicability", item["id"]), "kind": "unverified_applicability",
               "status": "open", "label_zh": "人工不适用声明仍需验证",
               "reason_zh": "同操作正常观察和业务文字不能证明整个义务不适用。原声明与来源保留；重新打开义务后按实际前提和 typed 判据闭环，不能用行政复核或受阻声明归档。",
               "reason_code": "applicability_unverified", "operation_id": item["operation_id"],
               "obligation_id": item["id"], "obligation_kind": item.get("kind"),
               "declared_status": "not_applicable", "basis": item.get("basis"),
               "evidence_ids": item.get("evidence_ids", []), "action": "plan.disposition",
               "suggested_action": "plan.disposition", "administrative_review_allowed": False,
               "input_template": {"obligation_id": item["id"], "status": "open",
                                  "reason": "Reopen the caller-declared exclusion for an accepted evidence-bound assessment."},
               "help_input": {"name": "plan.disposition"}}
        for key in ("input_location", "input_selector", "test_family", "schema_branch", "tenant_boundary"):
            if key in item:
                row[key] = item[key]
        rows.append(row)
    extras = (
        ("candidate", inventory["candidates"], "候选线索待复核", "候选登记或关联不能替代真实验证。", "candidate.inspect", "candidate_id"),
        ("unassessed_observation", inventory["unassessed"], "有效观察尚未形成判据", "先检查已有响应和绑定，不要仅为归档重复发送请求。", "evidence.inspect", "evidence_id"),
        ("unlinked_analyst_finding", inventory["unlinked_analyst"], "人工发现尚未进入义务闭环", "先离线检查原有控制与当前义务，补齐真实判据；已有有效机器证明可显式绑定，人工文字不关闭测试。", "assessment.prepare", "finding_id"),
        ("unrecorded_confirmation", inventory["unrecorded"], "确认判据尚未登记发现", "复核真实影响后使用 finding.record；此检查不会自动确认或创建发现。", "finding.record", "decision_id"),
        ("orphan_browser_visit", inventory["orphan_visits"], "浏览器观察未归档", "将已有真实观察绑定到页面、功能或具体运行时证明；访问记录不是 HTTP 测试。", "page.adopt", "page_visit_id"),
        ("unreconciled_run", inventory["pending_runs"], "执行状态仍需恢复检查", "检查已有 checkpoint 和证据，不自动重放可能已生效的请求。", "run.inspect", "run_id"),
        ("failed_partial_tool", inventory["partial_tools"], "工具执行或结果仍待复核", "已有目标流量、部分结果、未知远端执行或 POST 写效应不能当作安全阴性；检查原始 run/artifact，不自动重复执行。", "tool.inspect", "run_id"),
    )
    for kind, items, label, reason, action, field in extras:
        for item in items:
            row = {"id": _review_id(kind, item["id"]), "kind": kind, "status": "open", "label_zh": label,
                   "reason_zh": reason, "action": action, field: item["id"]}
            prerequisites = inventory.get("review_prerequisites", {}).get(row["id"], [])
            if prerequisites:
                row.update(status="blocked", execution_blocked=True, missing_prerequisites=list(prerequisites),
                           reason_code="review_prerequisite_missing")
            if item.get("operation_id"):
                row["operation_id"] = item["operation_id"]
            if kind == "unlinked_analyst_finding":
                row.update(suggested_action="assessment.prepare", input_template={"finding_id": item["id"]},
                           help_input={"name": "assessment.prepare"})
            if kind == "candidate" and item.get("disposition_review_required"):
                row.update(declared_status="dismissed", disposition_review_required=True,
                           reason_code="candidate_dismissal_unverified", administrative_review_allowed=False,
                           action="candidate.reopen", suggested_action="candidate.reopen",
                           input_template={"candidate_id": item["id"], "reason": "Reopen the caller-declared dismissal for source-bound scope or duplicate review."},
                           help_input={"name": "candidate.reopen"},
                           reason_zh="Caller-only candidate dismissal is not verified scope exclusion or duplicate proof. Reopen the local clue for evidence-bound review; do not infer a finding or replay requests.")
            if kind == "orphan_browser_visit":
                if item.get("adopt_ready"):
                    row.update(status="open", suggested_action="page.adopt", input_template={"page_visit_id": item["id"]},
                               administrative_review_allowed=False)
                    if prerequisites:
                        row.update(administrative_missing_prerequisites=list(prerequisites), missing_prerequisites=[],
                                   reason_code="verified_browser_adoption")
                elif not prerequisites:
                    row.update(action="plan.review", suggested_action="plan.review",
                               input_template={"checklist_id": row["id"], "status": "reviewed"},
                               help_input={"name": "plan.review"},
                               required_experiment_fields=["Inspect the complete read-only failed observation and supply the actual reviewer and reason.",
                                                           "Administrative archive does not adopt a page, close an obligation, or authorize replay."],
                               reason_code="failed_read_only_browser_review")
                else:
                    row.update(status="blocked", action="plan.audit", suggested_action="plan.audit",
                               reason_code=item.get("review_reason_code"), reason_zh="已有浏览器观察失败、受阻或摘要/血缘失效，不能收编为成功页面覆盖。")
                row["browser_testing"] = for_page(item["url"], blocked=not item.get("adopt_ready"),
                                                   existing_visit_id=item["id"] if item.get("adopt_ready") else None,
                                                   config=inventory["browser_scope_config"])
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
            existing = next((visit["id"] for visit in reversed(inventory["orphan_visits"]) if visit.get("adopt_ready")
                             and any(entry.get("url") == item["url"] for entry in visit.get("navigation_trail", []))), None)
            blocked = row["status"] == "blocked" or item.get("reason") == "out_of_scope"
            policy = row["browser_testing"] = for_page(item["url"], function=kind == "untriggered_function",
                                                       blocked=blocked, existing_visit_id=existing,
                                                       config=inventory["browser_scope_config"])
            if policy["stage"] == "review_existing":
                row.update(action="page.adopt", suggested_action="page.adopt", input_template={"page_visit_id": existing})
            elif not policy["execution_blocked"]:
                row.update(action="browser.visit", suggested_action="browser.visit", input_template=dict(policy["native_visit_input"]))
                row["required_experiment_fields"] = policy["required_input_fields"]
            else:
                row["status"] = "blocked"
            rows.append(row)
    for row in rows:
        review = inventory.get("blocked_reviews", {}).get(row["id"])
        if review:
            row.update(declared_status="blocked", review_id=review["id"], operator_reason=review["reason"])
            if row["status"] != "blocked":
                row.update(underlying_queue_status="review", blocker_reconciliation_required=True,
                           execution_blocked=True, action="plan.review", suggested_action="plan.review",
                           input_template={"checklist_id": row["id"], "status": "reopen"},
                           help_input={"name": "plan.review"},
                           required_experiment_fields=["Inspect the current source and prerequisites offline before recording a new source-bound review."],
                           reason_code="declared_review_blocker_unverified",
                           reason_zh="The caller-declared blocker does not suppress feasible offline review. Reopen the local receipt; do not replay requests or infer a security result.")
            else:
                row.update(reason_zh=review["reason"], action="plan.audit", suggested_action="plan.audit")
                row.pop("input_template", None)
            if "browser_testing" in row:
                row["browser_testing"].update(stage="blocked", call_needed=False, invoke_now=False, execution_blocked=True)
                row["browser_testing"].pop("native_visit_input", None)
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
    from .parameter_coverage import public_page as parameter_page

    offset, limit = args.get("offset", 0), args.get("limit", 25)
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise EngineError("pagination", "offset must be a nonnegative integer; limit must be 1..100")
    evaluated, inventory = evaluate_with_inventory(project)
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
        "parameter_coverage": parameter_page(inventory["parameter_coverage_snapshot"],
            {"parameter_limit": min(limit, 3), **args}),
        "checklist": checklist[offset:offset + limit], "checklist_total": len(checklist), "offset": offset, "limit": limit,
        "next_offset": offset + limit if offset + limit < len(checklist) else None,
        "candidate_proof_accounted": len(inventory["proof_resolved_candidates"]),
        "administrative_reviews": len(inventory.get("reviewed_admin", [])),
        "next_action": "plan.next", "note_zh": "本检查仅读取现有材料，不发请求、不补造证据、不自动关闭义务，也不把启发式线索确认成漏洞。"})


def followups(project, evaluated, limit=5, *, inventory=None):
    from .reporting import safe_metadata
    from .browser_policy import summarize

    rows = [row for row in _checklist(inventory if inventory is not None else _inventory(project, evaluated)) if row["kind"] != "obligation"]
    lanes = {}
    for row in rows:
        lanes.setdefault(row["kind"], deque()).append(row)
    sample = []
    while any(lanes.values()) and len(sample) < limit:
        for lane in lanes.values():
            if lane and len(sample) < limit:
                sample.append(lane.popleft())
    policies = [row["browser_testing"] for row in rows if "browser_testing" in row]
    return {"review_followups": safe_metadata(sample), "review_followup_total": len(rows),
            "browser_followup_summary": summarize(policies, followup_total=len(policies)),
            "review_followup_action": "plan.audit"}
