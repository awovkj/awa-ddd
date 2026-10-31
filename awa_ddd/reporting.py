"""Credential-free report snapshots backed by the engine's single evaluator."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4


_PRIVATE_KEYS = {
    "headers", "request", "response", "body", "body_preview", "body_base64",
    "raw", "raw_request", "raw_response", "password", "passwd", "secret", "token",
    "access_token", "refresh_token", "authorization", "cookie", "cookies",
    "api_key", "apikey", "x_api_key", "storage_state", "credentials", "sample", "value",
    "request_headers", "response_headers", "session_headers", "proxy_authorization", "set_cookie",
    "client_secret", "id_token", "session_token", "private_key", "credential", "jwt",
    "auth_token", "api_token", "x_auth_token", "x_session_token", "basic",
}
_PRIVATE_KEYS = {re.sub(r"[^a-z0-9]", "", name) for name in _PRIVATE_KEYS}
_QUOTED_VALUE = r'''(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')'''
_REPORT_PLACEHOLDER = r"<AWA_[A-Z0-9_]+>"
_COOKIE_ASSIGNMENT = re.compile(
    r'''(?i)\b(?:set[_-]?cookie|cookie)["']?\s*[:=]\s*(?P<cookie_value>'''
    + _REPORT_PLACEHOLDER + "|" + _QUOTED_VALUE + r"|[^\r\n]+)"
)
_ASSIGNMENT = re.compile(
    r'''(?i)\b(?:authorization|proxy[_-]?authorization|password|passwd|token|'''
    r'''(?:access|refresh|id|session|auth|api)[_-]?token|x[_-]?(?:auth|session)[_-]?token|api[_-]?key|(?:client[_-]?)?secret)["']?\s*[:=]\s*(?P<credential_value>'''
    + _REPORT_PLACEHOLDER + "|" + _QUOTED_VALUE + r"|[^\r\n,;，。；、]+)"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_BASIC = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/]+=*")
_URL = re.compile(r"https?://[^\s<>\"']+")
_CHINESE_CREDENTIAL = re.compile(
    r"((?:支付密码|登录密码|数据库密码|数据库口令|明文密码|验证码|短信码|重置令牌|签名密钥|回调密钥)"
    r"\s*(?:(?:为|是|=|:|：)\s*){0,6}[\"'（(]?)[A-Za-z0-9._~+/-]{4,}"
)


def safe_url(value):
    """A report locator includes no userinfo, query values, or fragment."""
    try:
        parsed = urlsplit(str(value))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return "[invalid URL]"
        host = parsed.hostname
        host = "[" + host + "]" if ":" in host else host
        if parsed.port is not None:
            host += ":" + str(parsed.port)
        return urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", "", ""))
    except (TypeError, ValueError):
        return "[invalid URL]"


def safe_text(value, limit=4000, *, preserve_placeholders=False):
    if value is None:
        return ""
    text = str(value)
    text = _URL.sub(lambda m: safe_url(m.group(0)), text)
    def assignment(match, group, marker):
        candidate = match.group(group).strip()
        if len(candidate) >= 2 and candidate[0] in {"'", '"'} and candidate[-1] == candidate[0]:
            candidate = candidate[1:-1]
        known = preserve_placeholders is True or candidate in (preserve_placeholders or ())
        return match.group(0) if known and re.fullmatch(_REPORT_PLACEHOLDER, candidate) else marker
    text = _COOKIE_ASSIGNMENT.sub(lambda match: assignment(match, "cookie_value", "[cookie redacted]"), text)
    text = _ASSIGNMENT.sub(lambda match: assignment(match, "credential_value", "[credential assignment redacted]"), text)
    text = _BEARER.sub("Bearer [redacted]", text)
    text = _BASIC.sub("Basic [redacted]", text)
    text = _CHINESE_CREDENTIAL.sub(r"\1[已脱敏]", text)
    # Common structured secret formats can appear without an assignment label.
    text = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[token redacted]", text)
    text = re.sub(r"\b(?:sk-|ghp_|github_pat_)[A-Za-z0-9_-]{16,}\b", "[token redacted]", text)
    return text[:limit]


def safe_metadata(value, depth=0, *, preserve_placeholders=False):
    """Only metadata, never arbitrary HTTP artifacts, belongs in public output."""
    if depth > 12:
        return "[metadata depth limit]"
    if isinstance(value, dict):
        return {safe_text(key): safe_metadata(item, depth + 1, preserve_placeholders=preserve_placeholders) for key, item in value.items()
                if re.sub(r"[^a-z0-9]", "", str(key).lower()) not in _PRIVATE_KEYS}
    if isinstance(value, (list, tuple)):
        return [safe_metadata(item, depth + 1, preserve_placeholders=preserve_placeholders) for item in value]
    if isinstance(value, str):
        return safe_text(value, preserve_placeholders=preserve_placeholders)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return safe_text(value)


def coverage(project):
    from .engine import evaluate_coverage
    # No filtering of gap states or alternate calculation of completion here.
    return safe_metadata(evaluate_coverage(project))


def _pick(row, names):
    return safe_metadata({name: row[name] for name in names if name in row})


_TOOL_REPORT_FIELDS = ("id", "adapter", "action", "status", "verification_level", "tool_version",
    "server_info", "tool_count", "tool_name", "exit_code", "error_code", "target_traffic_sent",
    "traffic_requests", "traffic_responses", "traffic_observation", "transport_warning",
    "metadata_candidates", "diagnostic", "next_action", "artifact_path", "sha256", "limitation")
_TSCAN_REPORT_FIELDS = ("scanner_project", "instance_id", "remote_run_id", "selected_tool", "results_complete",
    "returned_rows", "total_rows", "result_limit", "remote_execution_state", "remote_may_continue",
    "remote_stopped_verified", "namespace_cleared", "declared_flags", "control_endpoint", "context_binding",
    "mcp_url", "catalog_sha256", "table", "reported_count", "dispatch_attempted", "parser_status",
    "response_truncated", "unretrieved_results", "candidate_count", "new_candidates", "duplicate_candidates",
    "out_of_scope_rows", "unmapped_rows", "reported_http_status", "request_fingerprint", "call_input_signature",
    "operation_id", "session_id", "session_generation", "actor_id", "resource_id", "effect", "request_method",
    "namespace_verified", "instance_verified", "reported_total", "reported_matched", "counts", "has_assets",
    "import_limit", "processed_rows", "omitted_candidates", "unsupported_rows", "asset_count")


def _tool_report_metadata(run):
    if run.get("adapter") != "tscanplus":
        return _pick(run, _TOOL_REPORT_FIELDS)
    result = _pick(run, tuple(name for name in _TOOL_REPORT_FIELDS if name != "metadata_candidates") + _TSCAN_REPORT_FIELDS)
    result.update(finding_status="unverified", usable_for_confirmation=False)
    return result


def _scope(config):
    result = {}
    for key in ("target", "scope", "exclude"):
        value = config.get(key)
        if value is not None:
            result[key] = safe_metadata(value)
    return result


def _md(value):
    text = safe_text(value, preserve_placeholders=True).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]<>|])", r"\\\1", text)


def _format_ratio(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{value:.1%}"
    return "未定义（无可计算义务）"


def _finding_groups(findings):
    severity_order = ("critical", "high", "medium", "low", "info")
    current = [item for item in findings if item.get("current") is True]
    historical = [item for item in findings if item.get("current") is not True]
    groups = []
    for severity in severity_order:
        rows = sorted((item for item in current if item.get("severity") == severity),
                      key=lambda item: (item.get("category") or "", item.get("id") or ""))
        if rows:
            groups.append({"severity": severity, "count": len(rows),
                           "findings": [{"id": item.get("id"), "title": item.get("title"),
                                          "category": item.get("category"),
                                          "confirmed_scope": item.get("confirmed_scope")}
                                         for item in rows]})
    categories = {}
    for item in current:
        key = item.get("category") or "Uncategorised"
        categories[key] = categories.get(key, 0) + 1
    return {"current": len(current), "historical": len(historical), "by_severity": groups,
            "by_category": [{"category": key, "count": value}
                            for key, value in sorted(categories.items(), key=lambda kv: (-kv[1], kv[0]))],
            "historical_findings": [{"id": item.get("id"), "title": item.get("title"),
                                      "category": item.get("category"), "severity": item.get("severity"),
                                      "reason_code": item.get("reason_code"),
                                      "lifecycle_status": item.get("lifecycle_status", "active"),
                                      "lifecycle_reason": item.get("lifecycle_reason"),
                                      "replacement_finding_id": item.get("replacement_finding_id"),
                                      "evidence_current": item.get("evidence_current")} for item in historical]}


_ZH = {
    "critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息",
    "machine": "机器判据", "analyst": "人工复核", "open": "待完成", "blocked": "受阻",
    "evaluated": "已求值", "not_applicable": "有证据的不适用", "baseline": "正常基线",
    "access": "访问控制", "ownership": "资源属主", "ownership_setup": "测试资源准备",
    "input_review": "输入消费点追踪", "input_test": "输入安全实验", "security_test": "专项安全实验",
    "execute": "执行并求值", "trace_consumer": "追踪消费点", "create_test_resource": "准备测试资源",
    "repair_evidence": "修复证据", "database_metadata": "数据库元信息读取",
    "sql_behaviour": "受控 SQL 业务行为差异", "browser_execution": "浏览器实际执行",
    "target": "目标", "scope": "授权范围", "exclude": "排除范围",
}
_ZH_PROSE = {
    "No experiment has been recorded for this obligation yet.": "尚未为该义务记录已求值实验。",
    "Coverage is limited to registered operations; an empty queue does not prove absence of vulnerabilities.": "覆盖率仅针对已登记操作；空队列不证明目标无漏洞。",
    "coverage_ratio is obligation-weighted; surface_coverage is operation/input-weighted and is usually more readable.": "旧 coverage_ratio 按义务加权，surface_coverage 按操作和输入计算；均不是漏洞召回率。",
    "Imported or simulated artifacts do not satisfy execution evidence.": "导入或模拟材料不能满足真实执行证据要求。",
    "Only the recorded database metadata was recovered; broader table access and database modification were not tested.": "仅取回已记录数据库元信息；未测试更广泛的业务表访问或数据库修改。",
    "Confirmed by server-side SQL behaviour change (control vs injection), not by recovering database()/current_user(); the exact injected statement is inferred from observed effects.": "由服务端正常/注入控制的业务变化确认，不是 database()/current_user() 读取证明；具体语句来自效果推断。",
    "Browser MCP output is externally imported and explicitly reviewed; it is not a machine-authenticated browser execution.": "浏览器 MCP 输出为外部导入并经过人工复核，不是机器认证的本地浏览器执行。",
}
_ZH_CATEGORIES = {
    "sqlinjection": "SQL 注入", "sqli": "SQL 注入", "brokenaccesscontrol": "访问控制缺陷",
    "idor": "对象级越权", "businesslogicflaw": "业务逻辑漏洞", "sensitivedataexposure": "敏感数据泄露",
    "informationdisclosure": "信息泄露", "brokenauthentication": "身份认证缺陷",
    "xmlexternalentityxxe": "XML 外部实体注入（XXE）", "xxe": "XML 外部实体注入（XXE）",
    "crosssitescripting": "跨站脚本（XSS）", "xss": "跨站脚本（XSS）",
    "ssrf": "服务端请求伪造（SSRF）", "serversiderequestforgery": "服务端请求伪造（SSRF）",
    "pathtraversal": "路径穿越", "commandinjection": "命令注入", "fileupload": "不安全文件上传",
    "csrf": "跨站请求伪造（CSRF）", "racecondition": "并发竞态", "deserialization": "不安全反序列化",
}


def _zh(value):
    return _ZH.get(str(value), str(value or "未记录"))


def _prose_zh(value):
    return _ZH_PROSE.get(str(value), str(value or ""))


def _category_zh(value):
    original = str(value or "未分类")
    key = re.sub(r"[^a-z0-9]", "", original.lower())
    name = _ZH_CATEGORIES.get(key)
    return name + "（原分类：" + original + "）" if name and name != original else original


def _literal(value):
    """Generated reproduction strings have already passed the context redactor."""
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]<>|])", r"\\\1", text)


def _code(value, language="text"):
    text = str(value or "")
    longest = max((len(item) for item in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + language, text, fence]


def _render_reproduction(detail):
    rows = ["", "#### 人工复现前提", ""]
    rows.extend("- " + _literal(item) for item in detail.get("prerequisites") or [])
    if not detail.get("available"):
        rows.append("- 复现资料不完整：" + _literal(detail.get("unavailable_reason") or "部分正文无法安全导出。"))
    rows += ["", "#### 渗透步骤与实际结果", "",
             "下面是原台账的实际捕获顺序；命令仅为人工复核模板，报告生成未再次执行。响应内容为不可信、已脱敏摘录。", ""]
    for step in detail.get("steps") or []:
        rows += [str(step["number"]) + ". " + _literal(step["role"]) + "：" + _literal(step["method"] + " " + step["url"]), "",
                 "- 主体：" + _literal(step.get("actor_id") or "匿名") + "; 会话引用：" + _literal(step.get("session_id") or "无")
                 + "; 资源引用：" + _literal(step.get("resource_id") or "未绑定"),
                 "- 操作 / 执行 / 证据：" + _literal(step.get("operation_id")) + " / " + _literal(step.get("run_id")) + " / " + _literal(step["evidence_id"])]
        if step.get("subject"):
            rows.append("- 当时服务端主体 / 角色：" + _literal(step["subject"]) + " / " + _literal(json.dumps(step.get("roles") or [], ensure_ascii=False)))
        if step.get("resource"):
            rows.append("- 测试资源归属与请求绑定：" + _literal(json.dumps(step["resource"], ensure_ascii=False)))
        inputs = step.get("registered_inputs") or []
        if inputs:
            rows.append("- 登记输入：" + _literal("; ".join(str(item.get("location")) + ":" + str(item.get("selector", item.get("name")))
                                                            + "（" + str(item.get("consumer") or "消费点未知") + "）" for item in inputs)))
        if step.get("request_file"):
            rows.append("- 脱敏 HTTP 请求文件：[" + _literal(step["request_file"]) + "](" + step["request_file"] + ")")
        if step.get("body_file"):
            rows.append("- 正文文件：[" + _literal(step["body_file"]) + "](" + step["body_file"] + ")")
        if step.get("placeholders"):
            rows.append("- 执行前必须替换：" + _literal(", ".join(step["placeholders"])))
        if step.get("request_body_excerpt"):
            rows += ["", "请求正文" + ("（摘录已截断，完整脱敏正文见文件）" if step.get("request_body_truncated") else "（已脱敏）") + "：", ""]
            rows += _code(step["request_body_excerpt"])
        if step.get("curl"):
            rows += ["", "PowerShell 验证模板（使用 curl.exe，不是 Invoke-WebRequest）：", ""]
            rows += _code(step["curl"]["powershell"], "powershell")
            rows += ["", "Linux / macOS / WSL 验证模板：", ""]
            rows += _code(step["curl"]["posix"], "bash")
        else:
            rows.append("- 未生成执行模板：" + _literal(step.get("unavailable_reason")))
        rows += ["", "- 原捕获结果：HTTP " + str(step.get("status_code")) + "；捕获时间：" + _literal(step.get("captured_at")),
                 "- 原材料：" + _literal(step.get("source_artifact")) + "；SHA-256：" + _literal(step.get("source_sha256")),
                 "- 原响应正文 SHA-256：" + _literal(step.get("response_sha256")), "",
                 "实际响应摘录" + ("（已截断，不代表完整响应）" if step.get("response_truncated") else "（已脱敏）") + "：", ""]
        rows += _code(step.get("response_excerpt") or "[空正文]")
        if step.get("response_observables"):
            rows += ["", "原响应中实际命中的判据字段 / 敏感值存在位置（敏感值仅保留占位符）：", ""]
            rows += _code(json.dumps(step["response_observables"], ensure_ascii=False, indent=2), "json")
        rows.append("")
    if detail.get("decision_reason"):
        rows.append("- 原判定依据：" + _literal(detail["decision_reason"]))
    sqlmap = detail.get("sqlmap")
    if sqlmap:
        rows += ["", "#### sqlmap 最终结果复核", ""]
        if sqlmap.get("available"):
            rows += ["- SQL 输入：" + _literal(sqlmap["input_location"] + ":" + sqlmap["input_selector"])
                     + "；sqlmap 参数：" + _literal(sqlmap["parameter"]),
                     "- 正常请求证据：" + _literal(sqlmap["baseline_evidence_id"]) + "；历史工具执行：" + _literal(sqlmap.get("tool_run_id") or "未执行工具，以 HTTP 证明为准"),
                     "- " + _literal(sqlmap["scope"]), "- " + _literal(sqlmap["note"]),
                     "- 原证明记录的元信息：" + _literal(json.dumps(sqlmap.get("expected_recorded_metadata"), ensure_ascii=False)), "",
                     "PowerShell（先设置可信本机 sqlmap.py 的绝对路径到 $env:AWA_SQLMAP_PATH）：", ""]
            if sqlmap.get("recorded_profile"):
                rows += ["历史实际执行配置（与建议复核模板分别列出）：", ""]
                rows += _code(json.dumps(sqlmap["recorded_profile"], ensure_ascii=False, indent=2), "json")
                rows.append("")
            rows += _code(sqlmap["commands"]["powershell"], "powershell")
            rows += ["", "Linux / WSL（先设置可信本机 sqlmap.py 的绝对路径到 AWA_SQLMAP_PATH）：", ""]
            rows += _code(sqlmap["commands"]["posix"], "bash")
        else:
            rows.append("- 未生成命令：" + _literal(sqlmap.get("reason")))
    if detail.get("limitations"):
        rows += ["", "#### 复现与血缘限制", ""]
        rows.extend("- " + _literal(item) for item in detail["limitations"])
    return rows


def _render(summary):
    evaluated = summary["coverage"]
    groups = summary.get("finding_groups") or {}
    completion = evaluated.get("completion") or {}
    stage = summary.get("stage", "draft")
    continuation = summary.get("continuation") or {}
    finalization = summary.get("finalization") or {}
    delivery = summary.get("delivery_status", "draft")
    stage_labels = {"draft": "草稿 / 阶段快照（非完成凭证）",
                    "final-partial": "最终部分交付（仍有覆盖限制）",
                    "final-completed": "最终交付（仅限已登记授权任务）"}
    stage_warnings = {
        "draft": "报告生成成功不代表评估结束。继续检查 plan.checkpoint、plan.next 和 plan.audit；不得据此宣称已经测无可测。",
        "final-partial": "仅校验停止记录与当前快照的绑定。调用方声明的外部退出或阻塞事实不因此获独立核验；未完成和范围限制仍保留，不代表完整覆盖。",
        "final-completed": "引擎确认已登记任务满足当前闭环规则；范围适用性仍来自复核声明，不证明未知接口、未测试业务状态或未知漏洞不存在。",
    }
    stop_labels = {"completed": "已登记任务通过引擎闭环门禁（仅限登记范围）",
                   "blocked": "登记计划暂无可推进项（阻塞事实来自台账声明，未独立核验）",
                   "budget_exhausted": "调用方声明预算耗尽（未独立计量或核验预算）",
                   "user_stop": "调用方声明用户要求结束（未独立核验宿主事件）",
                   "authorization_boundary": "调用方声明达到授权边界（未独立核验，禁止自动扩大范围）"}
    basis_labels = {"engine_gate": "引擎闭环门禁（登记范围内）",
                    "projected_declared_blockers": "按台账声明的阻塞前提投影；阻塞事实未独立核验",
                    "caller_declared_external_constraint": "调用方声明的外部退出约束；宿主事件、预算或授权事实未独立核验"}
    partial = evaluated.get("open", 0) or evaluated.get("blocked", 0)
    label = completion.get("label_zh") or ("部分评估，仍有未完成工作" if partial else "仅限已登记范围的评估快照")
    rows = ["# awa-ddd 中文渗透测试报告", "", "- 项目：" + _md(summary["project_id"]),
            "- 生成时间（UTC）：" + _md(summary["generated_at"]), "- 评估状态：**" + _md(label) + "**", "",
            "## " + stage_labels.get(delivery, stage_labels["draft"]), "",
            "**" + stage_warnings.get(delivery, stage_warnings["draft"]) + "**", "",
            "frontier_review 两轮记录属于引用已有证据的范围复核声明，不是两次独立安全实验。", "",
            "- 报告阶段：" + _md(stage),
            "- 当前续接判定：" + ("仍需继续" if continuation.get("continue_required") else "已按停止记录退出；不等于完整覆盖"),
            "- 剩余 ready / review / blocked：" + str(continuation.get("ready_total", 0)) + " / "
            + str(continuation.get("review_total", 0)) + " / " + str(continuation.get("blocked_total", 0)),
            "- 停止记录：" + _md(finalization.get("id") or "无（草稿不能作为结束授权）"),
            "- 停止理由：" + _md(stop_labels.get(finalization.get("reason"), "无（阶段快照不能授权停止）")),
            "- 停止依据：" + _md(basis_labels.get(finalization.get("reason_basis"), "未提供可区分的停止依据，不能据此声称外部事实获核验")),
            "- 调用方停止说明：" + _md(finalization.get("explanation") or "未提交停止记录"),
            "- 后续检查 / 恢复入口：plan.checkpoint", "",
            "## 执行摘要", "",
            "本报告来自当前证据求值快照，不是漏洞全集。接口登记、成功请求、工具安装和人工发现数量均不等于安全测试完成。",
            "报告生成没有发送新请求。凭据、令牌、验证码、敏感配置及支付密码被替换；复现包仅包含经过校验的脱敏请求模板。", "",
            "- 当前有效发现：" + str(groups.get("current", 0)) + "；历史 / 已撤回 / 当前不可验证：" + str(groups.get("historical", 0)),
            "- 已求值义务：" + str(evaluated.get("evaluated", 0)) + " / " + str(evaluated.get("obligations", 0))
            + "；待完成：" + str(evaluated.get("open", 0)) + "；受阻：" + str(evaluated.get("blocked", 0)),
            "- 已登记操作 / 输入：" + str(evaluated.get("operations", 0)) + " / " + str(evaluated.get("inputs", 0))]
    security = evaluated.get("security_coverage") or {}
    if security:
        rows.append("- 安全专项已求值：" + str(security.get("evaluated", 0)) + " / " + str(security.get("total", 0))
                    + "；安全专项覆盖率：" + _format_ratio(security.get("ratio")))
    rows.extend("- 未完成原因：" + _md(item) for item in completion.get("reasons_zh") or [])
    rows += ["", "### 风险分布", "", "| 风险 | 数量 | 当前发现 |", "|---|---|---|"]
    for group in groups.get("by_severity") or []:
        names = "; ".join(item.get("title") or item.get("category") or item.get("id") or "" for item in group.get("findings") or [])
        rows.append("| " + _zh(group["severity"]) + " | " + str(group["count"]) + " | " + _md(names) + " |")
    if not groups.get("current"):
        rows.append("| 未返回当前有效发现 | 0 | 不代表目标不存在漏洞 |")
    rows += ["", "## 授权范围", ""]
    rows.extend("- " + _zh(key) + "：" + _md(json.dumps(value, ensure_ascii=False)) for key, value in summary["scope"].items())
    rows += ["", "## 漏洞详情与人工复现", "",
             "所有命令均为人工复核模板：先核对授权范围、重新获取测试身份、替换 <AWA_...> 占位符，再按编号执行。",
             "正常基线、攻击/另一主体对照和阴性控制只在原证据存在时展示，不补造缺失实验。"]
    severity_order = {name: index for index, name in enumerate(("critical", "high", "medium", "low", "info"))}
    findings = sorted((item for item in evaluated.get("findings") or [] if item.get("current") is True),
                      key=lambda item: (severity_order.get(item.get("severity"), 99), item.get("id", "")))
    for item in findings:
        rows += ["", "### " + _zh(item.get("severity")) + "：" + _md(item.get("title")), "",
                 "- 漏洞 / 判定：" + _md(item.get("id")) + " / " + _md(item.get("decision_id")),
                 "- 分类 / 复核方式：" + _md(_category_zh(item.get("category"))) + " / " + _zh(item.get("mode")),
                 "- 已确认范围：" + _md(_zh(item.get("confirmed_scope") or "仅限已复核的具体观察，详见限制")),
                 "- 影响与原复核描述：" + _md(item.get("impact")), "- 修复建议：" + _md(item.get("remediation")),
                 "- 证据引用：" + _md(", ".join(item.get("evidence_ids") or []))]
        if item.get("confirmed_scope") == "database_metadata":
            rows.append("- SQL 证明边界：只确认已记录数据库元信息；未验证业务表读取、全库导出或数据库修改，不能据此宣称已完成这些操作。")
        rows.extend("- 结论限制：" + _md(_prose_zh(value)) for value in item.get("limitations") or [])
        detail = summary.get("reproduction", {}).get(item["id"], {})
        rows += _render_reproduction(detail) if detail else ["- 复现资料缺失：未找到可校验材料，不能猜造请求。"]
    historical = groups.get("historical_findings") or []
    if historical:
        rows += ["", "## 历史 / 当前不可验证发现", "", "这些条目不计入当前风险分布，不生成当前漏洞复现命令。", ""]
        for item in historical:
            rows.append("- " + _md(item.get("id")) + "：" + _md(item.get("title") or item.get("category"))
                        + "；状态原因：" + _md(item.get("reason_code")))
            if item.get("lifecycle_reason"):
                rows.append("- 更正说明：" + _md(item["lifecycle_reason"])
                            + ("；替代发现：" + _md(item["replacement_finding_id"]) if item.get("replacement_finding_id") else ""))
    rows += ["", "## 覆盖率与未完成工作", "", "义务覆盖率不是漏洞召回率；正常基线也不是对某类漏洞的否定证明。", "",
             "| 指标 | 当前求值结果 |", "|---|---|"]
    metrics = {"operations": "已登记操作", "inputs": "已登记输入", "obligations": "义务总数",
               "evaluated": "已求值", "open": "待完成", "blocked": "受阻", "not_applicable": "有证据的不适用"}
    for key, name in metrics.items():
        rows.append("| " + name + " | " + str(evaluated.get(key, 0)) + " |")
    rows.append("| 义务加权覆盖率（旧指标） | " + _format_ratio(evaluated.get("coverage_ratio")) + " |")
    surface = evaluated.get("surface_coverage") or {}
    rows.append("| 操作 / 输入已测试（旧指标） | " + str(surface.get("operations_tested", 0)) + " / " + str(surface.get("operations_total", 0))
                + "；" + str(surface.get("inputs_tested", 0)) + " / " + str(surface.get("inputs_total", 0)) + " |")
    if security:
        rows += ["", "### 安全专项覆盖矩阵", "", "| 专项 | 总数 | 已求值 | 待完成 | 受阻 | 比例 |", "|---|---|---|---|---|---|"]
        for item in security.get("by_family") or []:
            rows.append("| " + _md(item.get("label_zh") or item.get("test_family")) + " | " + str(item.get("total", 0)) + " | " + str(item.get("evaluated", 0))
                        + " | " + str(item.get("open", 0)) + " | " + str(item.get("blocked", 0)) + " | " + _format_ratio(item.get("ratio")) + " |")
    if evaluated.get("coverage_by_kind"):
        rows += ["", "### 按义务类型", "", "| 类型 | 总数 | 已求值 | 待完成 | 受阻 | 比例 |", "|---|---|---|---|---|---|"]
        for kind, data in evaluated["coverage_by_kind"].items():
            rows.append("| " + _md(_zh(kind)) + " | " + str(data.get("total", 0)) + " | " + str(data.get("evaluated", 0))
                        + " | " + str(data.get("open", 0)) + " | " + str(data.get("blocked", 0)) + " | " + _format_ratio(data.get("ratio")) + " |")
    rows += ["", "### 后续动作", ""]
    rows.extend("- " + _md(_zh(action)) + "（" + _md(action) + "）：" + str(count) for action, count in (evaluated.get("gap_dependencies") or {}).items())
    rows += ["", "### 完整未完成义务明细", "",
             "下列 gap_id 与计划/求值器一致；原判据说明保留用于定位，未完成项不会被登记或人工描述自动关闭。", ""]
    for gap in evaluated.get("gaps") or []:
        reason = gap.get("operator_reason") or gap.get("reason") or ""
        rows.append("- " + _md(gap.get("gap_id") or gap.get("id")) + "：" + _md(_zh(gap.get("status"))) + " / "
                    + _md(_zh(gap.get("next_action"))) + " / " + _md(gap.get("operation_id")) + " / "
                    + _md(_zh(gap.get("obligation_kind"))) + "；原说明：" + _md(_prose_zh(reason)))
    rows += ["", "## 附录：方法与浏览器覆盖", "", "方法登记、实际观察、已求值测试分别记录；未知方法只是候选。", "",
             "| 路径 | 已登记 | 已观察 | 已测试 | 登记但未测 | 未知方法候选 |", "|---|---|---|---|---|---|"]
    for item in evaluated.get("method_coverage") or []:
        shape = item.get("path_shape") or ["", "", ""]
        display = str(shape[0]) + "://" + str(shape[1]) + str(shape[2]) if len(shape) >= 3 else "/".join(shape)
        rows.append("| " + _md(display) + " | " + " | ".join(_md(", ".join(item.get(key) or [])) for key in
                                                              ("registered_methods", "observed_methods", "tested", "untested_registered_methods", "untested_siblings")) + " |")
    rows += ["", "浏览器台账：", ""] + _code(json.dumps(summary["browser_coverage"], ensure_ascii=False, indent=2), "json")
    rows += ["", "## 附录：外部工具与来源", "", "工具运行不自动等于漏洞确认；版本探测不等于发送目标请求。", ""]
    rows.extend("- " + _md(json.dumps(tool, ensure_ascii=False, sort_keys=True)) for tool in summary["external_tools"])
    rows.append("- 未验证候选数：" + str(summary["unverified_candidates"]))
    rows += ["", "### 操作来源与可信度", ""]
    rows.extend("- " + _md(json.dumps(operation, ensure_ascii=False, sort_keys=True)) for operation in summary["operation_metadata"])
    rows += ["", "## 交付限制与校验", "",
             "- 只报告已登记和已观察范围；队列为空也不证明未发现的攻击面不存在漏洞。",
             "- 两轮 frontier_review 是有证据引用的范围复核声明，不是两次独立实验；阻塞或外部退出声明不会因此成为独立核验的事实。",
             "- XSS 绑定覆盖仅限已验证的精确消费链：POST 存储型 JSON、GET 精确攻击 URL；多页面 dialog 归因歧义、未捕获 fill 值或缺少摘要绑定的文档请求头时仍保留部分或未绑定，不能用空白页或无弹窗外推排除。",
             "- 导入结论、扫描告警和模拟材料不会自动变为当前执行证明。",
             "- 原始凭据和未经筛选的响应正文不公开；原材料需单独授权访问。", 
             "- 复现包含敏感字段占位符；JSON 可能因安全替换规范化，二进制正文不自动导出，不能冒充原字节重放。",
             "- manifest.json 保存本批次报告、摘要和复现文件的摘要；摘要检测字节改变，不认证远端服务的事实。"]
    rows.extend("- " + _md(item) for item in completion.get("limitations_zh") or [])
    rows.extend("- 原求值器限制：" + _md(_prose_zh(item)) for item in evaluated.get("limitations") or [])
    return "\n".join(rows) + "\n"


def _check_plain_path(path):
    """Reject symlink/reparse redirection before creating report files."""
    path = Path(os.path.abspath(path))
    for ancestor in [*reversed(path.parents), path]:
        if ancestor.is_symlink():
            raise ValueError("Report destination may not contain symlinks")
        if ancestor.exists():
            attributes = getattr(ancestor.lstat(), "st_file_attributes", 0)
            if attributes & 0x400:
                raise ValueError("Report destination may not contain reparse points")
    return path


def build_report(project, output_dir=None, *, stage="draft", finalization_id=None):
    from .store import EngineError
    if not isinstance(stage, str) or stage not in {"draft", "final"}:
        raise EngineError("report_stage", "Report stage must be draft or final")
    if stage == "draft" and finalization_id is not None:
        raise EngineError("report_stage", "A finalization_id requires stage=final")
    # A concurrent importer must not change source counts between evaluation and
    # serialization. This snapshot transaction performs no project mutations.
    with project.transaction():
        from .engine import evaluate_coverage
        from .continuation import control, require_finalization
        from .reproduction import prepare_reproduction
        original = evaluate_coverage(project)
        finalization = require_finalization(project, finalization_id, evaluated=original) if stage == "final" else None
        continuation = control(project, evaluated=original)
        source_context = {"continuation": continuation, "finalization": finalization}
        if any(run.get("kind") == "external_tool" and run.get("adapter") == "tscanplus" for run in project.list("run")):
            from .tscanplus import report_context
            source_context["tscanplus"] = report_context(project)
        reproduction = prepare_reproduction(project, original.get("findings") or [],
            context=source_context)
        redactor = reproduction["redactor"]
        evaluated = redactor.metadata(original)
        delivery = "draft" if stage == "draft" else (
            "final-completed" if finalization.get("can_claim_complete") is True
            and evaluated.get("completion", {}).get("status") == "complete" else "final-partial")
        from .browser import coverage as browser_coverage
        from .candidates import UNVERIFIED
        operation_metadata = []
        for operation in project.list("operation"):
            row = _pick(operation, ("id", "url", "method", "protocol", "operation_name", "content_type",
                                    "auth", "consumer_state", "sources"))
            if "url" in row:
                row["url"] = safe_url(row["url"])
            row["input_count"] = len(operation.get("inputs") or [])
            operation_metadata.append(row)
        generated = datetime.now(timezone.utc)
        summary = {
            "format_version": 5,
            "language": "zh-CN",
            "stage": stage,
            "delivery_status": delivery,
            "completion": evaluated.get("completion") or {},
            "continuation": redactor.metadata(continuation),
            "finalization": redactor.metadata(finalization),
            "project_id": redactor.prose(project.config.get("project_id") or project.base.name, 128),
            "generated_at": generated.isoformat(),
            "scope": redactor.metadata(_scope(project.config)),
            "coverage": evaluated,
            "finding_groups": redactor.metadata(_finding_groups(evaluated.get("findings") or [])),
            "operation_metadata": redactor.metadata(operation_metadata),
            "unverified_candidates": sum(row.get("status", UNVERIFIED) == UNVERIFIED for row in project.list("candidate")),
            "browser_coverage": redactor.metadata(browser_coverage(project)),
            "external_tools": [_tool_report_metadata(run)
                for run in project.list("run") if run.get("kind") == "external_tool"],
            "reproduction": reproduction["finding_details"],
            "artifacts": [{"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
                          for path, data in sorted(reproduction["files"].items())],
        }
        summary["external_tools"] = redactor.metadata(summary["external_tools"])
        if stage == "final":
            # SQLite does not freeze artifact bytes. Recheck them after source
            # preparation; this is not a lock against later external changes.
            current = evaluate_coverage(project)
            current_stop = require_finalization(project, finalization_id, evaluated=current)
            if current_stop != finalization or current["continuation"]["snapshot_id"] != original["continuation"]["snapshot_id"]:
                raise EngineError("finalization_stale", "Report sources changed during preparation; create a current stop record",
                    {"continuation": control(project, evaluated=current), "next_action": "plan.checkpoint"})
    report_bytes = _render(summary).encode("utf-8")
    digest = hashlib.sha256(report_bytes).hexdigest()
    summary["report_sha256"] = digest
    summary_bytes = (json.dumps(summary, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
    parent = _check_plain_path(output_dir if output_dir is not None else project.base / "reports")
    parent.mkdir(parents=True, exist_ok=True)
    batch = generated.strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:12]
    destination = parent / batch
    staging = Path(tempfile.mkdtemp(prefix=".report-", dir=parent))
    written, directories = [], set()
    try:
        material = {"report.md": report_bytes, "summary.json": summary_bytes, **reproduction["files"]}
        manifest = {"format_version": 1, "generated_at": summary["generated_at"], "project_id": summary["project_id"],
                    "stage": summary["stage"], "delivery_status": summary["delivery_status"],
                    "completion": summary["completion"], "continuation": summary["continuation"],
                    "finalization": summary["finalization"],
                    "files": [{"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
                              for path, data in sorted(material.items())], "credentials_redacted": True,
                    "executed_by_report": False}
        manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
        material["manifest.json"] = manifest_bytes
        for relative, data in material.items():
            relative_path = Path(relative)
            path = staging / relative_path
            if relative_path.is_absolute() or ".." in relative_path.parts or staging.resolve() not in path.resolve().parents:
                raise ValueError("Report artifact escaped staging")
            path.parent.mkdir(parents=True, exist_ok=True)
            directories.update(item for item in path.parents if item != staging and staging in item.parents)
            with path.open("xb") as stream:
                written.append(path)
                stream.write(data)
        if staging.resolve().parent != parent.resolve() or destination.resolve().parent != parent.resolve():
            raise ValueError("Report rename escaped destination parent")
        os.rename(staging, destination)
    finally:
        # Only known files in our fresh staging directory are removed on failure.
        if staging.exists():
            for path in written:
                path.unlink(missing_ok=True)
            for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
                path.rmdir()
            staging.rmdir()
    return {"stage": summary["stage"], "completion": summary["completion"], "continuation": summary["continuation"],
            "delivery_status": summary["delivery_status"], "finalization": summary["finalization"],
            "report": str(destination / "report.md"), "summary": str(destination / "summary.json"),
            "report_sha256": digest, "summary_sha256": hashlib.sha256(summary_bytes).hexdigest(),
            "manifest": str(destination / "manifest.json"), "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "reproduction_dir": str(destination / "reproduction") if reproduction["files"] else None,
            "snapshot": True, "generated_at": summary["generated_at"]}
