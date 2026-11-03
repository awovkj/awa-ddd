"""Passive security-property review hints from current authorized ledger sources."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

from . import engine
from .scope import bind_operation, require_scope
from .store import EngineError, canonical


MAX_HYPOTHESES = 4096
MAX_OBSERVATION_REFERENCES = 3
_READ_METHODS = {"GET", "HEAD", "OPTIONS"}
_UNKNOWN_CONSUMERS = {"", "unknown", "other", "untraced", "unspecified"}

# Properties remain independent review questions. Their names and suggested
# families do not declare a sink, authorize an experiment or implement an oracle.
PROPERTIES = {
    "authentication_enforcement": ("认证要求是否强制", ["access_control"],
        ["verified_principal_and_roles", "declared_access_policy"],
        ["按实际访问约定，用获准身份与未认证对照读取同一测试资源，核对受保护业务数据。"]),
    "authentication_factor_enforcement": ("认证因子是否强制", ["business_logic", "generic"],
        ["authorized_test_account", "required_factor_policy"],
        ["保持同一获准测试账号及会话，分别核对正常因子、缺失因子和无效因子后的实际认证状态。"]),
    "authentication_retry_limits": ("认证重试限制", ["business_logic", "generic"],
        ["authorized_test_account", "retry_window_policy", "state_readback"],
        ["先确认允许的测试次数和限制窗口，再核对有限失败对照后的锁定、冷却或验证状态。"]),
    "token_single_use": ("令牌是否只能使用一次", ["business_logic"],
        ["token_issuance_context", "lifecycle_policy", "state_readback"],
        ["使用同一自建流程签发的正常令牌，核对首次使用与获准重复使用后的实际状态，避免重放未知写入。"]),
    "token_expiry_invalidation": ("令牌过期与失效", ["business_logic"],
        ["token_issuance_context", "lifecycle_policy", "state_readback"],
        ["按真实有效期及撤销规则，核对有效、过期或已失效令牌；保持主体与签发上下文一致。"]),
    "principal_tenant_boundary": ("主体、角色与租户边界", ["access_control"],
        ["verified_principal_and_roles", "verified_tenant_membership", "owned_test_fixture"],
        ["核验独立获准主体及其角色、租户，以同一自建资源比较允许主体与边界外主体的实际访问结果。"]),
    "numeric_business_bounds": ("金额、数量与额度边界", ["business_logic"],
        ["server_authoritative_bounds", "owned_test_fixture", "state_readback"],
        ["依据服务端权威金额或数量，用正常值与合法边界对照，读取同一自建资源的实际金额、库存或权益。"]),
    "time_window_enforcement": ("业务时间窗口", ["business_logic"],
        ["server_time_reference", "business_time_window", "state_readback"],
        ["依据服务端时间和真实业务窗口比较正常时间与窗口边界，核对实际折扣、权限或状态。"]),
    "state_transition_authorization": ("状态变更权限与前置条件", ["access_control", "business_logic"],
        ["declared_transition_policy", "owned_test_fixture", "state_readback"],
        ["按真实角色和前置状态准备自建资源，比较允许与禁止的变更，并用独立读回核对最终状态。"]),
    "operation_idempotency": ("重复操作的生效次数", ["business_logic"],
        ["replay_semantics", "owned_test_fixture", "state_readback"],
        ["先确认动作是否要求一次生效，再核对同一自建资源的受控重复和业务审计；不自动重放未知写入。"]),
    "navigation_destination_policy": ("浏览器导航目标约束", ["generic"],
        ["browser_consumer_context", "allowed_navigation_policy"],
        ["在真实获准浏览器流程中比较允许目标与测试目标，记录实际导航终点及正常阴性对照。"]),
    "outbound_destination_policy": ("服务端访问目标约束", ["ssrf"],
        ["outbound_destination_policy", "non_executing_canary_fixture", "independent_negative_control"],
        ["先追踪真实服务端消费点，再用获准可观测来源与无该来源的阴性对照核对独立响应。"]),
    "structured_parser_safety": ("结构化解析边界", ["generic"],
        ["declared_parser_contract", "non_executing_canary_fixture", "independent_negative_control"],
        ["核对实际解析器及类型、实体或多态配置，以不执行代码的隔离标记和正常格式对照验证具体机制。"]),
    "upload_path_and_content": ("上传内容、文件名与保存边界", ["file_upload", "path_traversal"],
        ["upload_storage_contract", "owned_test_fixture", "independent_negative_control"],
        ["分别核对文件内容和文件名，使用自建可回退文件及正常对照，读取实际保存位置和消费结果。"]),
    "public_sensitive_exposure": ("公开内容中的敏感数据边界", ["generic"],
        ["public_field_classification", "operation_level_proof_channel"],
        ["依据真实公开字段约定核对匿名可读内容；敏感项需独立来源确认，正常响应不等于安全证明。"]),
}
SECURITY_PROPERTIES = frozenset(PROPERTIES)
MISSING_CONTEXT_CODES = frozenset({"current_http_observation", "normal_business_assertion", "property_specific_controls",
    "declared_access_policy", "actual_input_consumer", "schema_branch_controls", "exact_authorized_url",
    *(code for _, _, required, _ in PROPERTIES.values() for code in required)})


def _text(value):
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value or "")).lower()


def _has(text, names):
    return bool(re.search(r"(?<![a-z0-9])(?:" + names + r")(?![a-z0-9])", text))


def _current_references(project, operation, identities):
    references = []
    for identity in list(dict.fromkeys(identities or []))[-MAX_OBSERVATION_REFERENCES:]:
        if not isinstance(identity, str):
            continue
        try:
            record, artifact = engine.verify_current_evidence(project, identity)
            if record.get("kind") != "http" or record.get("operation_id") != operation["id"]:
                continue
            request = artifact["request"]
            require_scope(project.config, request["url"])
            bind_operation(operation, request["url"], request["method"])
        except (EngineError, OSError, ValueError, TypeError, KeyError):
            continue
        references.append(identity)
    return references


def _target(operation, entry, obligations):
    matches = [item for item in obligations if item.get("operation_id") == operation["id"]
        and item.get("input_location") == (entry.get("location") if entry else None)
        and item.get("input_selector") == (entry.get("selector", entry.get("name")) if entry else None)
        and item.get("schema_branch") == (entry.get("schema_branch") if entry else None)]
    return {"obligation_id": matches[0]["id"]} if len(matches) == 1 else {"operation_id": operation["id"]}


def build(project, operations, observed_evidence_by_operation=None):
    """Read-only metadata; actual capture references never verify a property."""
    observations = observed_evidence_by_operation or {}
    obligations = {}
    for item in project.list("obligation"):
        if not item.get("superseded"):
            obligations.setdefault(item["operation_id"], []).append(item)
    rows, seen, limited = [], set(), False

    for operation in operations:
        references = _current_references(project, operation, observations.get(operation["id"], []))
        try:
            require_scope(project.config, operation["url"])
            needs_exact_url = False
        except (EngineError, ValueError, TypeError):
            # A query-free inventory locator alone cannot authorize an exact
            # query scope. Only a current independently scoped capture can
            # supply a source for this nonrequestable metadata review.
            if not references:
                continue
            needs_exact_url = True
        inputs = [entry for entry in operation.get("inputs", []) if isinstance(entry, dict)]
        route = _text(urlsplit(operation["url"]).path + " " + str(operation.get("operation_name") or ""))
        media = str(operation.get("content_type") or "").partition(";")[0].lower()
        field_texts = [_text(" ".join(str(entry.get(key) or "") for key in ("name", "selector", "consumer"))) for entry in inputs]
        credentials = r"username|login_?name|password|passwd|pin|captcha|otp|sms_?code|verify_?code|verification_?code|验证码|密码"
        login_like = _has(route, r"login|signin|authenticate|authentication|verify") or any(_has(text, credentials) for text in field_texts)

        def add(prop, entry=None, *, families=None, basis=()):
            nonlocal limited
            identity = [operation["id"], prop, entry.get("location") if entry else None,
                        entry.get("selector", entry.get("name")) if entry else None, entry.get("schema_branch") if entry else None]
            key = canonical(identity)
            if key in seen:
                return
            if len(rows) >= MAX_HYPOTHESES:
                limited = True
                return
            seen.add(key)
            label, suggested, missing, controls = PROPERTIES[prop]
            context = ["normal_business_assertion", "property_specific_controls", *missing]
            if not references:
                context.append("current_http_observation")
            if operation.get("auth") == "unknown":
                context.append("declared_access_policy")
            if needs_exact_url:
                context.append("exact_authorized_url")
            if entry and str(entry.get("consumer") or "").strip().lower() in _UNKNOWN_CONSUMERS:
                context.append("actual_input_consumer")
            if entry and entry.get("schema_branch") is not None:
                context.append("schema_branch_controls")
            row = {"id": "HYP-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:24],
                "operation_id": operation["id"], "security_property": prop, "label_zh": label,
                "suggested_test_families": sorted(set(families if families is not None else suggested)),
                "source": {"kind": "registered_operation", "operation_id": operation["id"],
                    "operation_signature": engine.operation_signature(operation), "context_trust": "declared"},
                "inference_basis": list(basis), "observed_evidence_ids": list(references),
                "observations_are_property_proof": False, "missing_context": list(dict.fromkeys(context)),
                "controls_zh": list(controls), "hint_only": True, "requestable": False, "usable_for_confirmation": False,
                "note_zh": "同族已有证明只覆盖原判据范围；本条安全属性仍需独立对照。",
                "next_action": "assessment.prepare", "input_template": _target(operation, entry, obligations.get(operation["id"], [])),
                "help_input": {"name": "assessment.prepare"}}
            if entry:
                row.update(input_location=entry["location"], input_selector=entry.get("selector", entry["name"]))
                if "schema_branch" in entry:
                    row["schema_branch"] = entry["schema_branch"]
            rows.append(row)

        if operation.get("auth") != "public":
            add("authentication_enforcement", basis=("declared_access_policy",))
        if operation.get("auth") in {"authenticated", "restricted"} or operation.get("ownership"):
            add("principal_tenant_boundary", basis=("declared_access_policy", "declared_ownership"))
        if operation.get("auth") == "public" and operation.get("method") in {"GET", "HEAD"}:
            add("public_sensitive_exposure", basis=("declared_access_policy", "operation_method"))
        if login_like:
            add("authentication_retry_limits", basis=("operation_semantics", "input_name"))
        if operation.get("method") not in _READ_METHODS:
            add("state_transition_authorization", basis=("operation_method",))
            add("operation_idempotency", basis=("operation_method",))
        if "xml" in media:
            add("structured_parser_safety", families=("xxe", "generic"), basis=("declared_media_type",))
        elif "json" in media and _has(route, r"import|parse|decode|deserialize|convert"):
            add("structured_parser_safety", families=("deserialization", "generic"), basis=("declared_media_type", "operation_semantics"))
        if "multipart/form-data" in media:
            add("upload_path_and_content", basis=("declared_media_type",))

        for entry, text in zip(inputs, field_texts):
            if _has(text, credentials):
                add("authentication_factor_enforcement", entry, basis=("input_name", "declared_consumer"))
            if _has(text, r"token|nonce|otp|captcha|sms_?code|verify_?code|verification_?code|验证码|令牌"):
                add("token_single_use", entry, basis=("input_name", "declared_consumer"))
                add("token_expiry_invalidation", entry, basis=("input_name", "declared_consumer"))
            if _has(text, r"amount|price|balance|refund|quantity|qty|stock|points|discount|coupon|probabilit(?:y|ies)|weight|金额|价格|数量|概率"):
                add("numeric_business_bounds", entry, basis=("input_name", "declared_consumer"))
            if _has(text, r"time|timestamp|expires?|expiry|deadline|date|时间|日期"):
                add("time_window_enforcement", entry, basis=("input_name", "declared_consumer"))
            if _has(text, r"state|status|approved?|role|is_?admin|tenant|owner|状态|角色|租户"):
                add("state_transition_authorization", entry, basis=("input_name", "declared_consumer"))
            navigation = _has(text, r"redirect|return_?url|next_?url|redirect_?uri|navigation|跳转")
            if navigation:
                add("navigation_destination_policy", entry, basis=("input_name", "declared_consumer"))
            if _has(text, r"url|uri|webhook|callback|endpoint|remote|outbound_?http") and not navigation:
                add("outbound_destination_policy", entry, basis=("input_name", "declared_consumer"))
            if _has(text, r"xml|xml_?parser|serialized?|deserialize|deserialization|pickle|object_?data|json|document|payload") \
                    or entry.get("schema_type") in {"object", "array"}:
                parser_families = ["generic", "xxe"] if _has(text, r"xml|xml_?parser") else ["generic", "deserialization"]
                add("structured_parser_safety", entry, families=parser_families, basis=("input_name", "declared_consumer", "declared_schema"))
            if _has(text, r"file|filename|upload|avatar|attachment|文件|上传"):
                add("upload_path_and_content", entry, basis=("input_name", "declared_consumer"))
        if limited:
            break
    rows.sort(key=lambda row: (row["operation_id"], row["security_property"], row.get("input_location") or "",
                               row.get("input_selector") or "", canonical(row.get("schema_branch"))))
    return {"items": rows, "limited": limited}
