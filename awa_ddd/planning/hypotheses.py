"""Deterministic hypothesis generation from the Universe and KnownCases.

Every declared test family produces a hypothesis even when its consumer is
unknown; unknown consumers become blocked ``needs_consumer`` hypotheses, never
silent ``input_review`` rows.  Field semantics, access policy, writes, login
flows and page functions add property-specific hypotheses with stable identity.
"""
from __future__ import annotations

import re

from ..domain.common import digest, stable_id
from ..domain.hypothesis import new_hypothesis

MAX_HYPOTHESES = 20000
UNKNOWN_CONSUMERS = {"", "unknown", "other", "untraced", "unspecified"}

_FIELD_RULES = [
    (r"amount|price|balance|refund|quantity|qty|stock|points|discount|coupon|probabilit|weight|金额|价格|数量|概率",
     "business_logic", "numeric_business_bounds", ["server_authoritative_bounds", "owned_test_fixture", "state_readback"]),
    (r"time|timestamp|expires?|expiry|deadline|date|时间|日期",
     "business_logic", "time_window_enforcement", ["server_time_reference", "business_time_window", "state_readback"]),
    (r"state|status|approved?|role|is_?admin|tenant|owner|状态|角色|租户",
     "access_control", "state_transition_authorization", ["declared_transition_policy", "owned_test_fixture", "state_readback"]),
    (r"redirect|return_?url|next_?url|redirect_?uri|navigation|跳转",
     "generic", "navigation_destination_policy", ["browser_consumer_context", "allowed_navigation_policy"]),
    (r"url|uri|webhook|callback|endpoint|remote|outbound_?http",
     "ssrf", "outbound_destination_policy", ["outbound_destination_policy", "non_executing_canary_fixture", "independent_negative_control"]),
    (r"xml|xml_?parser|serialized?|deserialize|deserialization|pickle|object_?data|document|payload",
     "deserialization", "structured_parser_safety", ["declared_parser_contract", "non_executing_canary_fixture", "independent_negative_control"]),
    (r"file|filename|upload|avatar|attachment|文件|上传",
     "file_upload", "upload_path_and_content", ["upload_storage_contract", "owned_test_fixture", "independent_negative_control"]),
    (r"token|nonce|otp|captcha|sms_?code|verify_?code|verification_?code|验证码|令牌",
     "business_logic", "token_single_use", ["token_issuance_context", "lifecycle_policy", "state_readback"]),
]


def _field_text(entry):
    return " ".join(str(entry.get(key) or "") for key in ("name", "selector", "consumer")).lower()


def _semantic_rules(entry):
    text = _field_text(entry)
    matches = []
    for pattern, family, prop, missing in _FIELD_RULES:
        if re.search(pattern, text):
            matches.append((family, prop, list(missing)))
    return matches


def _operation_lookup(universe):
    return {operation["operation_id"]: operation for operation in universe.get("operations", [])}


def _known_case_operation(case, operations):
    for operation in operations.values():
        if operation.get("method") != case.get("method"):
            continue
        if operation.get("url_template") and operation["url_template"] == _template_suffix(case.get("url", "")):
            return operation["operation_id"]
    return stable_id("OPX", {"url": case.get("url"), "method": case.get("method")})


def _template_suffix(url):
    from urllib.parse import urlsplit
    path = urlsplit(url).path or "/"
    parts = []
    for segment in path.split("/"):
        if not segment:
            continue
        if segment.isdigit():
            parts.append("{id}")
        else:
            parts.append(segment)
    return "/" + "/".join(parts)


def _push(rows, seen, hypothesis):
    if hypothesis["id"] in seen:
        return
    if len(rows) >= MAX_HYPOTHESES:
        return
    seen.add(hypothesis["id"])
    rows.append(hypothesis)


def generate_hypotheses(universe, known_cases=None):
    """Return (hypotheses, limited) without writing to the repository."""
    operations = _operation_lookup(universe)
    hypothesis_rows, seen = [], set()
    limited = False
    scope_epoch = universe.get("scope_epoch")
    target_build = universe.get("target_build") or universe.get("snapshot_hash", "")[:16]

    for operation in universe.get("operations", []):
        op_id = operation.get("operation_id")
        inputs = operation.get("inputs", [])
        for entry in inputs:
            families = [family for family in entry.get("test_families") or [] if isinstance(family, str)]
            consumer_unknown = str(entry.get("consumer") or "").strip().lower() in UNKNOWN_CONSUMERS
            context = ["actual_input_consumer"] if consumer_unknown else ["normal_business_assertion", "property_specific_controls"]
            semantic = _semantic_rules(entry)
            if not families:
                families = []
            planned = [(family, family + "_property", context) for family in families]
            planned.extend((family, prop, context + missing) for family, prop, missing in semantic)
            if consumer_unknown and not planned:
                planned.append(("generic", "needs_consumer", context))
            for family, prop, missing in planned:
                status = "blocked" if consumer_unknown or any(item in {"actual_input_consumer"} for item in missing) else "ready"
                _push(hypothesis_rows, seen, new_hypothesis(
                    family=family,
                    security_property=prop,
                    operation_id=op_id,
                    input_key=entry.get("input_key"),
                    relation={"actor": "any", "resource": "any"},
                    business_precondition=None,
                    scope_epoch=scope_epoch,
                    target_build=target_build,
                    source_kind="field_semantics" if not families else "declared_family",
                    statement=f"{operation.get('method')} {operation.get('url_template')} 的 {entry.get('name')} "
                              f"可能触发 {family}（{prop}）；需要独立对照，当前不是已证实漏洞。",
                    label=entry.get("name"),
                    priority={"family": family, "input": entry.get("name")},
                    missing_context=missing if status == "blocked" else [],
                    status=status,
                ))

        auth = operation.get("auth")
        route_text = str(operation.get("url_template") or "") + " " + str(operation.get("operation_id") or "")
        if auth and auth != "public":
            _push(hypothesis_rows, seen, new_hypothesis(
                family="access_control", security_property="authentication_enforcement",
                operation_id=op_id, scope_epoch=scope_epoch, target_build=target_build,
                source_kind="access_policy",
                statement=f"{operation.get('method')} {operation.get('url_template')} 是否强制要求服务端可验证身份；未认证对照需要独立证据。",
                missing_context=["verified_principal_and_roles"],
                status="blocked"))
        if operation.get("ownership"):
            _push(hypothesis_rows, seen, new_hypothesis(
                family="access_control", security_property="principal_tenant_boundary",
                operation_id=op_id, scope_epoch=scope_epoch, target_build=target_build,
                source_kind="access_policy",
                statement=f"{operation.get('method')} {operation.get('url_template')} 的资源访问是否受主体/租户边界约束。",
                missing_context=["verified_principal_and_roles", "verified_tenant_membership", "owned_test_fixture"],
                status="blocked"))
        if operation.get("method") not in {"GET", "HEAD", "OPTIONS"}:
            for prop in ("state_transition_authorization", "operation_idempotency"):
                _push(hypothesis_rows, seen, new_hypothesis(
                    family="business_logic" if prop == "operation_idempotency" else "access_control",
                    security_property=prop, operation_id=op_id, scope_epoch=scope_epoch,
                    target_build=target_build, source_kind="access_policy",
                    statement=f"{operation.get('method')} {operation.get('url_template')} 的 {prop} 需要真实状态读回；不自动重放未知写入。",
                    missing_context=["owned_test_fixture", "state_readback", "declared_transition_policy"],
                    status="blocked"))
        if re.search(r"login|signin|auth|password|验证码|密码", route_text, re.I):
            _push(hypothesis_rows, seen, new_hypothesis(
                family="business_logic", security_property="authentication_retry_limits",
                operation_id=op_id, scope_epoch=scope_epoch, target_build=target_build,
                source_kind="access_policy",
                statement="认证失败重试是否存在锁定、冷却或验证码窗口；需要获准测试账号和限制策略。",
                missing_context=["authorized_test_account", "retry_window_policy", "state_readback"],
                status="blocked"))

    for function in universe.get("functions", []):
        _push(hypothesis_rows, seen, new_hypothesis(
            family="access_control", security_property="page_function_authorization",
            operation_id="PAGE:" + str(function.get("page_id")),
            input_key=function.get("function_id"), scope_epoch=scope_epoch, target_build=target_build,
            source_kind="page_function",
            statement=f"页面功能 {function.get('name') or function.get('function_id')} 是否按真实角色与业务前置状态授权。",
            missing_context=["verified_principal_and_roles", "browser_consumer_context"],
            status="blocked"))

    for case in known_cases or []:
        case = case if isinstance(case, dict) else {}
        op_id = _known_case_operation(case, operations)
        _push(hypothesis_rows, seen, new_hypothesis(
            family=case.get("family") or "generic",
            security_property=case.get("mechanism") or "known_case_mechanism",
            operation_id=op_id,
            input_key=case.get("dedupe_key"),
            scope_epoch=scope_epoch, target_build=case.get("build") or target_build,
            source_kind="known_case", source_ref=case.get("source_ref"),
            known_case_id=case.get("id"),
            statement=f"已知案例 {case.get('id')}：{case.get('mechanism')} 在 {case.get('method')} {case.get('url')} 是否真实存在；案例只作选题。",
            missing_context=["exact_authorized_url"] if not operations else [],
            status="ready" if operations else "blocked"))

    hypothesis_rows.sort(key=lambda row: (row["family"], row["operation_id"], row.get("input_key") or "", row["id"]))
    limited = len(hypothesis_rows) >= MAX_HYPOTHESES
    return hypothesis_rows, limited


def family_applicability(hypotheses):
    """Return the 12-family matrix; a family with no rows is explicitly not_planned."""
    from ..domain.hypothesis import FAMILIES
    matrix = []
    for family in FAMILIES:
        rows = [row for row in hypotheses if row.get("family") == family]
        counts = {}
        for row in rows:
            counts[row.get("status", "unknown")] = counts.get(row.get("status", "unknown"), 0) + 1
        matrix.append({
            "test_family": family,
            "total": len(rows),
            "status": "not_planned" if not rows else
                      "planned" if counts.get("ready") or counts.get("unplanned") or counts.get("running") else
                      "blocked" if counts.get("blocked") else
                      "not_applicable" if counts.get("not_applicable") == len(rows) else "completed",
            "counts": counts,
        })
    return matrix
