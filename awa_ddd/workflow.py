"""Bounded inventory, actionable handoff, and append-only finding corrections."""
from __future__ import annotations

from collections import Counter, deque
import re
from urllib.parse import urlsplit, urlunsplit

from . import engine
from .reporting import safe_metadata, safe_text, safe_url
from .store import EngineError, now


def page_args(args, *, default=25, maximum=100):
    offset, limit = args.get("offset", 0), args.get("limit", default)
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= maximum:
        raise EngineError("pagination", f"offset must be a nonnegative integer; limit must be 1..{maximum}")
    return offset, limit


def page(rows, args, *, default=25, maximum=100):
    offset, limit = page_args(args, default=default, maximum=maximum)
    return {"items": rows[offset:offset + limit], "total": len(rows), "offset": offset, "limit": limit,
            "next_offset": offset + limit if offset + limit < len(rows) else None}


def pick(row, fields):
    return safe_metadata({key: row[key] for key in fields if key in row})


def operation_view(operation, *, detail=False):
    row = pick(operation, ("id", "url", "method", "protocol", "auth", "allowed_roles", "ownership", "state_scope", "content_type", "operation_name", "ownership_sampling"))
    row["url"] = safe_url(operation["url"])
    entries = operation.get("inputs")
    row["input_count"] = len(entries) if isinstance(entries, list) else None
    if detail:
        # Arbitrary imported source text stays in the local record, not the model context.
        row["inputs"] = [pick(entry, ("name", "location", "selector", "consumer", "schema_branch", "schema_type", "required", "test_families"))
                         if isinstance(entry, dict) else {"registration_error": "input_not_object"}
                         for entry in (entries if isinstance(entries, list) else [])[:100]]
        row["inputs_truncated"] = isinstance(entries, list) and len(entries) > 100
    return row


def list_surfaces(project, args):
    rows = [operation_view(operation) for operation in project.list("operation")
            if (not args.get("method") or operation["method"] == str(args["method"]).upper())
            and (not args.get("auth") or operation["auth"] == args["auth"])]
    window = page(rows, args)
    return {"operations": window.pop("items"), "operation_total": window.pop("total"), **window,
            "next_action": "surface.inspect", "registration_is_testing": False}


def inspect_surface(project, args):
    operation = project.get("operation", args["operation_id"])
    # Inputs have their own cursor so a large schema cannot hide precise selectors.
    entries = operation.get("inputs")
    inputs = [pick(entry, ("name", "location", "selector", "consumer", "schema_branch", "schema_type", "required", "test_families"))
              if isinstance(entry, dict) else {"registration_error": "input_not_object"}
              for entry in entries] if isinstance(entries, list) else []
    input_page = page(inputs, args)
    identity_error = None
    try:
        gaps = {gap["id"]: gap for gap in engine.evaluate_coverage(project)["gaps"]}
    except EngineError as exc:
        if exc.code not in {"input", "input_selector", "input_schema_branch"}:
            raise
        # The repair pointer must remain readable, but no saved status may be
        # presented as accepted coverage when identity validation failed.
        gaps = {}
        identity_error = {"code": exc.code, "operation_id": exc.details.get("operation_id"),
                          "field": exc.details.get("field", "inputs")}
    obligations = []
    for obligation in project.list("obligation"):
        if obligation.get("operation_id") != operation["id"] or obligation.get("superseded"):
            continue
        row = pick(obligation, ("id", "kind", "actor_id", "baseline_actor_id", "resource_id", "status", "input_selector", "input_location", "schema_branch", "test_family", "tenant_boundary", "decision_id"))
        if identity_error is not None:
            row.update(status="open", reason_code="input_identity_invalid", next_action="action.help")
        elif obligation["id"] in gaps:
            row.update(pick(gaps[obligation["id"]], ("status", "gap_id", "reason_code", "reason", "next_action", "operator_reason")))
        obligations.append(row)
    total = input_page.pop("total")
    return {"operation": operation_view(operation), "inputs": input_page.pop("items"),
            "input_total": total if isinstance(entries, list) else None, **input_page,
            "obligation_total": len(obligations), "obligations": obligations[:25],
            "obligations_truncated": len(obligations) > 25,
            "resources": [pick(row, ("id", "owner_actor_id", "request_binding")) for row in project.list("resource")
                          if row.get("operation_id") == operation["id"]][:10],
            "next_action": "action.help" if identity_error is not None else "plan.next",
            **({"inspection_limited": True, "input_identity_error": identity_error,
                "help_input": {"name": "surface.register"}} if identity_error is not None else {})}


def register_batch(project, args):
    operations = args.get("operations")
    if not isinstance(operations, list) or not 1 <= len(operations) <= 50 or any(not isinstance(row, dict) for row in operations):
        raise EngineError("surface_batch", "operations must be an array of 1..50 operation objects")
    rows = []
    with project.transaction():
        for index, operation in enumerate(operations):
            try:
                result = engine.register_operation(project, operation)
                rows.append({"index": index, "status": "accepted", "operation_id": result["id"], "input_count": len(result["inputs"])})
            except (EngineError, KeyError, TypeError, ValueError) as exc:
                rows.append({"index": index, "status": "rejected", "error_code": getattr(exc, "code", "invalid_operation"),
                             "message": safe_text(str(exc), 300), "next_action": "action.help",
                             "help_input": {"name": "surface.register"}})
        planned = engine.build_plan(project)
    return {"results": rows, "accepted": sum(row["status"] == "accepted" for row in rows),
            "rejected": sum(row["status"] == "rejected" for row in rows), "plan_added": planned["added"],
            "requests_sent": 0, "next_action": "plan.next"}


def plan_page(project, result, args):
    gaps = {gap["id"]: gap for gap in result["gaps"]}
    rows = []
    for obligation in project.list("obligation"):
        if obligation.get("superseded"):
            continue
        row = pick(obligation, ("id", "kind", "operation_id", "actor_id", "baseline_actor_id", "resource_id",
                                "input_location", "input_selector", "schema_branch", "test_family", "tenant_boundary", "status", "decision_id"))
        if obligation["id"] in gaps:
            row.update(pick(gaps[obligation["id"]], ("status", "reason_code", "next_action", "gap_id")))
        rows.append(row)
    window = page(rows, args)
    return {"continuation": result["continuation"], "added": result.get("added", 0), "obligations": result["obligations"],
            "obligation_items": window.pop("items"), "obligation_total": window.pop("total"), **window,
            "coverage_ratio": result["coverage_ratio"], "surface_coverage": result["surface_coverage"],
            "security_coverage": result["security_coverage"], "completion": result["completion"],
            "gap_total": len(result["gaps"]), "next_action": "plan.next"}


def coverage_view(result, args, *, include_gaps=True, default=25):
    window = page(result["gaps"], args, default=default)
    row = safe_metadata({key: value for key, value in result.items() if key not in {"gaps", "findings", "method_coverage"}})
    row.update(gap_total=window["total"], finding_total=len(result["findings"]),
               current_findings=sum(item.get("current") is True for item in result["findings"]),
               historical_findings=sum(item.get("current") is not True for item in result["findings"]))
    if include_gaps:
        row.update(gaps=safe_metadata(window.pop("items")), **{k: v for k, v in window.items() if k != "total"})
    methods = page(result.get("method_coverage", []),
                   {"offset": args.get("method_offset", 0), "limit": args.get("method_limit", 10)})
    row.update(method_coverage=safe_metadata(methods["items"]), method_total=methods["total"],
               method_offset=methods["offset"], method_next_offset=methods["next_offset"])
    return row


def project_status(project, args):
    evaluated = engine.evaluate_coverage(project)
    row = coverage_view(evaluated, args, include_gaps=False, default=10)
    candidates = Counter(item.get("status", "unverified") for item in project.list("candidate"))
    row.update(project_id=project.project_id, path=str(project.base), config=safe_metadata(project.config),
               candidates=candidates.get("unverified", 0), candidate_states=dict(candidates),
               gap_sample=safe_metadata(evaluated["gaps"][:5]), next_action="plan.next")
    fields = {
        "actor": ("id", "label", "subject", "tenant_id", "roles", "security_revision"),
        "session": ("id", "actor_id", "generation", "verified_at", "expires_at", "verification_evidence_id"),
        "run": ("id", "kind", "status", "started_at", "finished_at", "operation_id", "error", "error_code", "diagnostic"),
    }
    offset, limit = page_args(args, default=10)
    for kind, names in fields.items():
        rows = project.list(kind)
        if kind == "run":
            rows.reverse()
        row[kind + "s"] = [pick(item, names) for item in rows[offset:offset + limit]]
        row[kind + "_total"] = len(rows)
        row[kind + "_next_offset"] = offset + limit if offset + limit < len(rows) else None
    row.update(offset=offset, limit=limit)
    return row


def capture_preflight(project, args):
    prepared = engine.preflight_capture(project, args)
    session, resource, operation = (prepared[key] for key in ("session", "resource", "operation"))
    return {"ready": True, "requests_sent": 0, "operation_id": operation["id"], "method": operation["method"],
            "url": safe_url(prepared["url"]), "request_signature": prepared["request_signature"],
            "body_bytes": prepared["body_bytes"], "auth_mode": prepared["auth_mode"],
            "session_id": session["id"] if session else None, "resource_id": resource["id"] if resource else None,
            "timeout": prepared["timeout"], "max_bytes": prepared["max_bytes"],
            "existing_run_id": prepared["existing"]["id"] if prepared["existing"] else None,
            "next_action": "http.capture", "limitation": "Preflight is a point-in-time check; capture rechecks the same gates before execution."}


def _live_sessions(project, *, renewable=None):
    live = {}
    for session in project.list("session"):
        try:
            engine.session_valid(project, session)
            live.setdefault(session["actor_id"], []).append(session)
        except EngineError as exc:
            if renewable is None or exc.code != "session_expired":
                continue
            try:
                actor = engine._verified_session_actor(project, session)
                if actor.get("roles") and not session.get("verification_assertion", {}).get("roles_selector"):
                    continue
                renewable.setdefault(session["actor_id"], []).append(session)
            except (EngineError, OSError, ValueError, TypeError, KeyError):
                continue
        except (OSError, ValueError, KeyError):
            continue
    return live


def _operation_sessions(project, operation, live):
    """Never suggest credentials verified at a different origin for this operation."""
    compatible, foreign = {}, set()
    for actor_id, sessions in live.items():
        ordered = sessions
        if operation["auth"] == "restricted":
            ordered = sorted(sessions, key=lambda session: not bool(
                (session.get("verification_assertion") or {}).get("roles_selector")))
        for session in ordered:
            try:
                engine.require_session_origin(project, session, operation["url"])
                compatible[actor_id] = session
                break
            except (EngineError, OSError, ValueError, KeyError):
                foreign.add(actor_id)
        if actor_id in compatible:
            foreign.discard(actor_id)
    return compatible, foreign


def _observations(project):
    by_operation = {}
    for evidence in project.list("evidence"):
        if evidence.get("kind") != "http":
            continue
        try:
            engine.verify_current_evidence(project, evidence["id"])
            by_operation.setdefault(evidence["operation_id"], []).append(evidence)
        except (EngineError, OSError, ValueError, KeyError):
            continue
    return by_operation


def _query_scope_binding_possible(config, url):
    """A proof-only path check, never a URL template or new scope authorization."""
    from .scope import _matches, normalize_url

    try:
        target = normalize_url(url)
        if urlsplit(target).query:
            return False

        def path_matches(rule):
            parsed = urlsplit(normalize_url(rule))
            widened = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
            return parsed, _matches(widened, target)

        excluded = [path_matches(rule) for rule in config.get("exclude", [])]
        for rule in config.get("scope", []):
            parsed, matched = path_matches(rule)
            if matched and parsed.query and not any(matches and (not exclusion.query or exclusion.query == parsed.query)
                                                     for exclusion, matches in excluded):
                return True
    except (EngineError, ValueError, TypeError, KeyError):
        pass
    return False


def _work_item(project, gap, operations, live, observations, foreign_actors=(), parameter=None, *, resources=None, config=None):
    operation = operations[gap["operation_id"]]
    config = project.config if config is None else config
    kind = gap["obligation_kind"]
    row = pick(gap, ("id", "gap_id", "operation_id", "obligation_kind", "input_location", "input_selector", "schema_branch", "test_family", "tenant_boundary", "actor_id", "baseline_actor_id", "resource_id", "status", "reason_code", "next_action", "operator_reason"))
    row["obligation_id"] = gap["id"]
    row["method"], row["url"] = operation["method"], safe_url(operation["url"])
    row["missing_prerequisites"] = []
    if parameter is not None:
        row.update(parameter_coverage_id=parameter["id"], parameter_test_status=parameter["status"],
                   selected_input_observation_count=parameter["observation_count"],
                   selected_input_variant_observed=parameter["has_input_variant"],
                   controls_are_candidates_only=True)
    setup = {"auth_review": "surface.register", "input_review": "surface.declare_consumer",
             "identity_setup": "identity.actor", "ownership_setup": "identity.resource"}
    if kind in setup:
        row.update(queue_status="review", suggested_action=setup[kind], help_input={"name": setup[kind]})
        if kind == "input_review":
            from .completeness import suggested_families
            entry = next((item for item in operation.get("inputs", []) if item.get("location") == gap.get("input_location")
                          and item.get("selector") == gap.get("input_selector")
                          and item.get("schema_branch") == gap.get("schema_branch")), {})
            row.update(suggested_test_families=suggested_families(entry, operation), hints_only=True,
                       declared_test_families=entry.get("test_families", []),
                       input_template={"operation_id": operation["id"], "input_location": gap["input_location"],
                                       "input_selector": gap["input_selector"]},
                       required_experiment_fields=["consumer", "actual consumer source or observed business flow; field-name hints are not evidence"],
                       note_zh="先从实际源码或业务流程追踪消费点，再填写真实 consumer 并选择测试族；字段名提示不是已证实的 sink，不会自动创建或确认漏洞。")
            if gap.get("schema_branch") is not None:
                row["input_template"]["schema_branch"] = gap["schema_branch"]
        return row
    from .assessment import _authorized
    try:
        engine.require_scope(config, operation["url"])
    except (EngineError, ValueError, TypeError):
        row["missing_prerequisites"].append("exact_scoped_url_query_binding" if
            _query_scope_binding_possible(config, operation["url"]) else "authorized_operation_scope")
        row["execution_blocked"] = True
    allowed = [session for actor_id, session in live.items() if _authorized(project, operation, actor_id)] if operation["auth"] != "unknown" else []
    actor_id = gap.get("actor_id")
    session = live.get(actor_id) if actor_id else (allowed[0] if allowed and kind == "input_test" and operation["auth"] != "public" else None)
    if actor_id and not session:
        row["missing_prerequisites"].append("live_verified_session_for_actor")
        if actor_id in foreign_actors:
            row["missing_prerequisites"].append("verified_session_for_target_origin")
    if kind in {"access", "ownership"} and not allowed:
        row["missing_prerequisites"].append("verified_allowed_baseline")
    if kind == "ownership" and gap.get("baseline_actor_id") not in live:
        row["missing_prerequisites"].append("live_verified_owner_baseline")
        if gap.get("baseline_actor_id") in foreign_actors:
            row["missing_prerequisites"].append("verified_session_for_target_origin")
    if kind in {"access", "ownership"} and operation["auth"] == "restricted" and session \
            and not session.get("verification_assertion", {}).get("roles_selector"):
        row["missing_prerequisites"].append("server_verified_role_membership")
    if kind == "input_test" and operation["auth"] != "public" and not session:
        row["missing_prerequisites"].append("live_verified_allowed_session")
    needs_allowed_session = kind in {"access", "ownership"} or (kind == "input_test" and operation["auth"] != "public")
    if not allowed and needs_allowed_session and operation["auth"] != "unknown" \
            and any(_authorized(project, operation, actor) for actor in foreign_actors):
        row["missing_prerequisites"].append("verified_session_for_target_origin")
    if operation["auth"] == "unknown":
        row["missing_prerequisites"].append("declared_access_policy")
    if resources is None:
        resources = [item for item in project.list("resource") if item["operation_id"] == operation["id"]]
    resource = next((item for item in resources if item["id"] == gap.get("resource_id")), None)
    if resource is None and session:
        resource = next((item for item in resources if item["owner_actor_id"] == session["actor_id"]), None)
    if "{" in operation["url"] or "}" in operation["url"]:
        row["missing_prerequisites"].append("concrete_url_with_bound_path_values")
    if operation["method"] not in {"GET", "HEAD", "OPTIONS"}:
        if not config.get("allow_mutation"):
            row["missing_prerequisites"].append("project_allow_mutation")
        if not resource and not (operation.get("state_scope") == "actor" and session):
            row["missing_prerequisites"].append("matching_test_resource_or_declared_actor_state")
    evidence_actor = session["actor_id"] if kind == "input_test" and session else actor_id
    evidence = [item for item in observations.get(operation["id"], []) if item.get("actor_id") == evidence_actor]
    row["evidence_ids"] = [item["id"] for item in evidence[-5:]]
    row["observation_total"] = len(evidence)
    row["missing_prerequisites"] = list(dict.fromkeys(row["missing_prerequisites"]))
    row["queue_status"] = "blocked" if row["missing_prerequisites"] else "ready"
    template = {"operation_id": operation["id"]}
    if session:
        template["session_id"] = session["id"]
    if resource:
        template["resource_id"] = resource["id"]
    if operation["method"] not in {"GET", "HEAD", "OPTIONS"}:
        template["effect"] = "test_resource_write"
    row.update(suggested_action="http.preflight", input_template=template,
               required_experiment_fields=["concrete input values", "oracle-specific business assertions"])
    successful = [item for item in evidence if 200 <= item.get("status_code", 0) < 300]
    if kind == "baseline" and successful and operation["auth"] != "unknown":
        row.update(queue_status="ready", missing_prerequisites=[], suggested_action="assessment.evaluate",
                   input_template={"obligation_id": gap["id"], "evidence_ids": [successful[-1]["id"]]},
                   required_experiment_fields=["oracle.type:baseline", "oracle.selector", "oracle.expected"])
    if kind == "input_test":
        entry = next((item for item in operation["inputs"] if item["location"] == gap.get("input_location")
                      and item["selector"] == gap.get("input_selector")
                      and item.get("schema_branch") == gap.get("schema_branch")), {})
        from .completeness import PROOF_CHANNELS, obligation_family
        family = obligation_family(gap, operation)
        row.update(proof_channels=PROOF_CHANNELS.get(family, []), hypothesis_family=family,
                   hypothesis_note_zh="判据只关闭本条具体假设，不代表同输入的其他漏洞类别已测试。")
        if gap.get("test_family"):
            row["required_experiment_fields"].append("oracle.test_family:" + gap["test_family"])
        if family in {"xxe", "ssrf", "path_traversal"}:
            row["required_experiment_fields"] += ["oracle.source_reference", "oracle.expected_value", "recovery and source-free negative captures"]
        if family == "xss":
            row["required_experiment_fields"] += ["runtime_visit_id", "consumer_url", "runtime_marker from an application-triggered browser dialog"]
            row.update(manual_followup_action="finding.record", positive_machine_adapter=False,
                       analyst_binding_supported=True, proof_channels=["analyst_runtime"],
                       hypothesis_note_zh="XSS 可用绑定本义务的人工运行时证明闭环：正常与攻击输入对照、实际消费页面、真实交互及同身份浏览器信号。静态反射、存储或无弹窗访问不能否定整类 XSS。")
            if not row["missing_prerequisites"]:
                row.update(queue_status="review", suggested_action="http.preflight",
                           help_input={"name": "http.preflight"})
        if family in {"command_injection", "template_injection", "deserialization", "file_upload"}:
            row["positive_machine_adapter"] = False
            row["hypothesis_note_zh"] += " 当前没有通用正向机器确认适配器，有限否定或人工复核不能冒充全面完成。"
        from .assessment import is_sql_category
        if is_sql_category(entry.get("consumer")) and gap.get("test_family", "sql_injection") == "sql_injection":
            tools = []
            query_profile = operation.get("protocol") == "http" and operation["method"] == "GET" \
                and entry.get("location") == "query" and isinstance(entry.get("selector"), str) and bool(entry["selector"])
            if query_profile and row["queue_status"] == "ready":
                if operation["auth"] == "public" and session is None:
                    tools.append("tool.yakit_replay")
                if operation["auth"] == "public" or session is not None:
                    tools.append("tool.sqlmap")
            media = operation.get("content_type", "").split(";", 1)[0].strip().lower()
            post_profile = operation.get("protocol") == "http" and operation["method"] == "POST" \
                and entry.get("location") in {"query", "body"} and resource is not None \
                and (entry.get("location") == "query" or media in {"application/json", "application/x-www-form-urlencoded"} or media.endswith("+json"))
            if post_profile and row["queue_status"] == "ready":
                tools.append("tool.sqlmap")
                row["tool_prerequisites_zh"] = "POST 工具会重复写请求，必须填写实际 JSON/form 标量输入和匹配的可丢弃资源；仅提示不代表预检通过。"
            row["recommended_tools"] = tools
            row["proof_channels"] = ["sql_metadata", "error_channel"]
            if operation["method"] not in {"GET", "HEAD", "OPTIONS"}:
                row["proof_channels"].append("analyst_write_side_business_proof")
        candidates = parameter.get("control_candidate_evidence_ids", []) if parameter is not None else []
        if candidates and operation["auth"] != "unknown":
            row.update(queue_status="review", suggested_action="evidence.inspect", help_input={"name": "evidence.inspect"},
                       input_template={"evidence_id": candidates[0]}, evidence_ids=list(candidates),
                       observation_total=len(candidates), control_candidate_evidence_ids=list(candidates),
                       control_candidate_review_required=True,
                       assessment_followup_action="finding.record" if family == "xss" else "assessment.evaluate",
                       note_zh="Saved same-context exact-input captures are comparison candidates only. Inspect their inputs and responses offline before choosing control roles and an oracle; do not replay requests or close the obligation from these references.")
            row["required_experiment_fields"].append(
                "Verify the saved baseline/variant/control roles, business assertions and family-specific proof requirements; comparison candidates are not accepted evidence by themselves.")
            if row["missing_prerequisites"]:
                row["execution_blocked"] = True
    if row["missing_prerequisites"]:
        existing = observations.get(operation["id"], [])
        if operation["auth"] == "unknown":
            # Unknown policy allows evidence inspection, never an inferred allowed actor.
            existing = [item for item in existing if kind == "input_test"
                        or item.get("actor_id") == actor_id]
        elif kind in {"access", "ownership"}:
            existing = [item for item in existing if item.get("actor_id") == actor_id
                        or _authorized(project, operation, item.get("actor_id"))]
        elif kind == "input_test":
            existing = [item for item in existing if operation["auth"] == "public"
                        or _authorized(project, operation, item.get("actor_id"))]
        else:
            existing = [item for item in existing if item.get("actor_id") == actor_id]
        if existing and not row.get("control_candidate_review_required"):
            row.update(queue_status="review", execution_blocked=True, suggested_action="evidence.inspect",
                       input_template={"evidence_id": existing[-1]["id"]},
                       evidence_ids=[item["id"] for item in existing[-5:]],
                       observation_total=len(existing),
                       assessment_followup_action="finding.record" if row.get("hypothesis_family") == "xss" else "assessment.evaluate",
                       note_zh="新请求的前提不可用，但已有完整观察仍可离线复核；会话过期不等于历史证据失效。复核不通过时登记具体阻塞，不自动重放。")
            if operation["auth"] == "unknown":
                row.update(assessment_followup_action="surface.register", help_input={"name": "surface.register"},
                           note_zh="已有观察可离线检查，但未知访问策略不能推断允许或拒绝。先声明实际访问策略，再选择匹配的身份、控制与判据；不得据此发包或关闭义务。")
    if row["queue_status"] == "blocked" and row["missing_prerequisites"] == ["exact_scoped_url_query_binding"]:
        row.update(queue_status="review", suggested_action="surface.inspect", input_template={"operation_id": operation["id"]},
                   help_input={"name": "surface.inspect"}, execution_blocked=True, scope_binding_review_required=True,
                   url_requires_binding=True, native_input_requires_binding=True, requestable=False,
                   scope_binding_followup_action="http.preflight", scope_binding_required_input_fields=["url"],
                   scope_binding_followup_template={"operation_id": operation["id"]},
                   scope_handoff_note="The query-free operation locator is not a permitted request. Select the exact current intended URL from authorized sources, not by copying a scope rule or replaying an imported URL.")
        row["required_experiment_fields"] += [
            "Supply an exact current authorized URL with its real query binding before http.preflight; no URL value is supplied by this review.",
            "Every baseline, variant and sensitivity-control request must independently satisfy fixed scope query constraints; selecting a binding does not authorize changing them."]
        if "recommended_tools" in row:
            row["recommended_tools"] = []
    elif row["queue_status"] == "blocked" and "authorized_operation_scope" in row["missing_prerequisites"]:
        row.update(suggested_action="surface.inspect", input_template={"operation_id": operation["id"]},
                   help_input={"name": "surface.inspect"},
                   required_experiment_fields=["Inspect the existing scope boundary offline; only actual authorization may change it."],
                   scope_handoff_note="The current scope forbids execution. Do not widen scope or replay a request to remove this gap.")
    return row


def _reconcile_declared_blocker(row, gap):
    """Preserve caller history, but never let prose suppress feasible offline work."""
    if gap["status"] != "blocked":
        return row
    row["declared_status"] = "blocked"
    if row["queue_status"] == "blocked":
        return row
    row.update(underlying_queue_status=row["queue_status"],
               underlying_suggested_action=row["suggested_action"], queue_status="review",
               blocker_reconciliation_required=True, execution_blocked=True,
               suggested_action="plan.disposition", help_input={"name": "plan.disposition"},
               input_template={"obligation_id": gap["id"], "status": "open",
                               "reason": "Reopen the caller-declared blocker for offline prerequisite reconciliation; preflight remains required before any new request."},
               required_experiment_fields=["Reconcile the declared blocker against the current prerequisites and existing evidence offline.",
                                           "Reopening is not execution approval; preserve actual authorization, identity, fixture and browser limits."],
               blocker_handoff_note="Caller-only blocked prose is not a missing prerequisite. This generated template only reopens local work; do not automatically replay a target request.")
    if "recommended_tools" in row:
        row["recommended_tools"] = []
    for field in ("manual_followup_action", "assessment_followup_action", "browser_handoff_note"):
        row.pop(field, None)
    policy = row["browser_testing"]
    policy.update(stage="blocked", call_needed=False, invoke_now=False, execution_blocked=True,
                  required_input_fields=["offline_obligation_blocker_reconciliation"])
    policy.pop("native_visit_input", None)
    return row


def _coverage_priority(row):
    if row["suggested_action"] in {"evidence.inspect", "finding.record"}:
        return 2
    if row["obligation_kind"] in {"input_test", "input_review"}:
        if not row.get("selected_input_variant_observed"):
            return 0 if not row.get("selected_input_observation_count", 0) else 1
        return 2
    if row["suggested_action"] in {"evidence.inspect", "assessment.evaluate", "finding.record"}:
        return 2
    return 4 if row["obligation_kind"] == "baseline" else 3


def _renewal_candidates(project, row, operation, sessions):
    from .assessment import _authorized

    if operation["auth"] == "unknown" or {"authorized_operation_scope", "exact_scoped_url_query_binding"}.intersection(row["missing_prerequisites"]):
        return []
    eligible = {actor_id: session for actor_id, session in sessions.items()
                if operation["auth"] != "restricted" or session.get("verification_assertion", {}).get("roles_selector")}
    allowed = [actor_id for actor_id in eligible if _authorized(project, operation, actor_id)]
    selected = {}
    for prerequisite in row["missing_prerequisites"]:
        if prerequisite == "live_verified_session_for_actor":
            identities = [row.get("actor_id")]
        elif prerequisite == "live_verified_owner_baseline":
            identities = [row.get("baseline_actor_id")]
        elif prerequisite in {"live_verified_allowed_session", "verified_allowed_baseline"}:
            identities = allowed[:1]
        else:
            continue
        for identity in identities:
            if identity not in eligible:
                continue
            session = eligible[identity]
            candidate = selected.setdefault(session["id"], {
                "session_id": session["id"], "actor_id": identity, "generation": session["generation"],
                "expires_at": session["expires_at"], "prerequisites": [], "action": "identity.session",
                "input_template": {"session_id": session["id"], "renew": True},
                "automatic_execution_allowed": False, "renewal_is_login": False})
            candidate["prerequisites"].append(prerequisite)
    return list(selected.values())


def _preparation_actions(row, operation):
    """Concrete offline handoff, not invented target workflows or execution approval."""
    mappings = {
        "authorized_operation_scope": ("surface.inspect", ["actual_authorization"],
            "Inspect the fixed scope offline. Only actual authorization may change it; do not widen scope to remove a blocker."),
        "exact_scoped_url_query_binding": ("surface.inspect", ["exact_authorized_url"],
            "Choose the intended exact URL from authorized sources. Scope rules are not request values and each control must remain in scope."),
        "concrete_url_with_bound_path_values": ("surface.inspect", ["exact_test_resource_values", "url"],
            "Inspect the registered path selector and bind a real permitted test resource before preflight; do not guess another user's resource."),
        "declared_access_policy": ("surface.register", ["auth", "allowed_roles_if_restricted"],
            "Declare the actual access policy from trusted authorization documentation. A past HTTP 200 is not a policy declaration."),
        "project_allow_mutation": ("project.status", ["explicit_write_authorization"],
            "Verify explicit write authorization first. Do not set allow_mutation merely to bypass a failed preflight."),
        "matching_test_resource_or_declared_actor_state": ("identity.resource", ["owner_actor_id", "external_id", "request_binding"],
            "Prepare a disposable owned fixture with an exact request binding. Business inputs cannot be relabeled as fixture-free actor state."),
        "server_verified_role_membership": ("identity.verify", ["session_id", "operation_id", "subject_selector", "roles_selector"],
            "Use an authorized identity endpoint that actually returns subject and role membership. Do not infer roles from a label, a client UI or a 200 response."),
        "verified_session_for_target_origin": ("identity.verify", ["session_id", "operation_id", "subject_selector"],
            "Register and verify a separate session at this target origin. Never forward credentials verified at another origin."),
    }
    session_prerequisites = {"live_verified_session_for_actor", "live_verified_allowed_session", "verified_allowed_baseline",
                             "live_verified_owner_baseline"}
    actions = []
    for prerequisite in row["missing_prerequisites"]:
        if prerequisite in session_prerequisites:
            candidate = next((item for item in row.get("session_renewal_candidates", [])
                              if prerequisite in item["prerequisites"]), None)
            if candidate is not None:
                actions.append({"prerequisite": prerequisite, "action": "identity.session",
                    "help_input": {"name": "identity.session"}, "input_template": dict(candidate["input_template"]),
                    "required_input_fields": ["confirm_unchanged_server_credentials"],
                    "instruction": "This expired session retains current identity and credential bindings for this origin. Manually renew its local liveness only if the server credentials are unchanged; renewal is not login. Changed credentials need a new generation and actual verification. Never automatically replay a request.",
                    "automatic_execution_allowed": False})
                continue
            action, required, instruction = "identity.session", ["actor_id", "headers", "identity.verify"], (
                "Use a real authorized test account, register its current credentials privately, then run identity.verify with the exact subject selector. "
                "Same-generation renewal requires unchanged credentials; changed credentials need a new generation and verification. Existing evidence may still be reviewed offline.")
        else:
            action, required, instruction = mappings.get(prerequisite, ("action.help", [prerequisite],
                "Inspect the named capability or browser prerequisite offline and supply the exact required fields; do not automatically replay a target request."))
        item = {"prerequisite": prerequisite, "action": action, "help_input": {"name": action if action != "action.help" else "browser.import_mcp"},
                "required_input_fields": required, "instruction": instruction, "automatic_execution_allowed": False}
        if action == "surface.inspect":
            item["input_template"] = {"operation_id": operation["id"]}
        elif action == "identity.resource":
            item["input_template"] = {"operation_id": operation["id"]}
        elif prerequisite == "live_verified_session_for_actor" and row.get("actor_id"):
            item["input_template"] = {"actor_id": row["actor_id"]}
        actions.append(item)
    row["preparation_actions"] = actions
    if any(re.search(r"captcha|sms.?code|otp|verify.?code|verification.?code|auth.?token", str(entry.get("name") or entry.get("selector") or ""), re.I)
           for entry in operation.get("inputs", [])):
        row["session_continuity"] = {
            "hint_only": True, "automatic_cookie_forwarding": False,
            "anonymous_input_field": "anonymous_cookie", "authenticated_input_field": "session_id",
            "instructions": [
                "Preserve the same-origin anonymous cookie jar privately across captcha/SMS issuance and verification; Set-Cookie attributes are not Cookie request values.",
                "Use anonymous_cookie only for public flows and never together with session_id. Authenticated work requires a registered verified session.",
                "A failed factor or a satisfied captcha does not test every factor. Test each registered factor and token lifecycle separately with exact controls.",
                "Do not assume exhausted attempts, missing OTP state or unpaid resources require a payment. Inspect authorized workflow documentation and prepare a disposable fixture or authorized test account."],
        }
    return row


def _fair_work_items(rows):
    lanes = {}
    for row in rows:
        kind = row["obligation_kind"]
        lane = ("input_test:" + row.get("hypothesis_family", "generic") if kind == "input_test" else
                "access" if kind in {"access", "ownership"} else
                kind if kind in {"baseline", "input_review"} else "setup")
        lanes.setdefault(lane, []).append(row)
    for key, values in lanes.items():
        values.sort(key=lambda row: (_coverage_priority(row), row["queue_status"] != "ready",
                                    row["suggested_action"] not in {"assessment.evaluate", "evidence.inspect", "finding.record"},
                                    row["method"] not in {"GET", "HEAD", "OPTIONS"}, row["operation_id"], row["gap_id"]))
        def by_operation(items):
            operations = {}
            for row in items:
                operations.setdefault(row["operation_id"], deque()).append(row)
            result = deque()
            active = deque(operations.values())
            while active:
                pending = active.popleft()
                result.append(pending.popleft())
                if pending:
                    active.append(pending)
            return result
        primary = by_operation([row for row in values if _coverage_priority(row) < 2])
        followup = by_operation([row for row in values if _coverage_priority(row) >= 2])
        balanced = deque()
        # Fresh parameters lead, but existing evidence gets a bounded review slot.
        while primary or followup:
            for _ in range(2):
                if primary:
                    balanced.append(primary.popleft())
            if followup:
                balanced.append(followup.popleft())
        lanes[key] = balanced
    security = ["input_test:" + family for family in engine.TEST_FAMILIES if "input_test:" + family in lanes]
    first = security + (["access"] if "access" in lanes else [])
    order = first + (["input_review", "baseline", "setup"] if first else ["input_review", "baseline", "setup"])
    order += sorted(key for key in lanes if key not in order)
    balanced = []
    while any(lanes.values()):
        for key in order:
            if lanes.get(key):
                balanced.append(lanes[key].popleft())
    if not balanced:
        return balanced

    def existing_review(row):
        action = row.get("underlying_suggested_action") if row.get("blocker_reconciliation_required") else row["suggested_action"]
        return row["queue_status"] in {"ready", "review"} and bool(row.get("evidence_ids")) \
            and (action in {"evidence.inspect", "assessment.evaluate", "finding.record"}
                 or row.get("control_candidate_review_required") is True)

    # Small pages must expose both saved-evidence review and unknown-consumer
    # preparation. Keep the coverage-first lead and the remaining fair order.
    opening = list(range(min(3, len(balanced))))
    protected = {0}
    for predicate in (existing_review, lambda row: row["obligation_kind"] == "input_review"):
        present = next((index for index in opening if predicate(balanced[index])), None)
        if present is not None:
            protected.add(present)
            continue
        candidates = [index for index, row in enumerate(balanced) if predicate(row)]
        if not candidates:
            continue
        candidate = min(candidates, key=lambda index: (
            balanced[index]["obligation_kind"] == "baseline",
            balanced[index].get("hypothesis_family") == balanced[0].get("hypothesis_family"),
            balanced[index]["operation_id"] == balanced[0]["operation_id"], index))
        slot = next(position for position in reversed(range(len(opening))) if opening[position] not in protected)
        opening[slot] = candidate
        protected.add(candidate)
    opening.sort()
    selected = set(opening)
    return [balanced[index] for index in opening] + [row for index, row in enumerate(balanced) if index not in selected]


def queue_inventory(project, evaluated, inventory=None):
    """Build readiness without evaluating again or claiming a network request."""
    operations = inventory["operations"] if inventory is not None else {item["id"]: item for item in project.list("operation")}
    config = project.config
    resources_by_operation = {}
    for resource in project.list("resource"):
        resources_by_operation.setdefault(resource["operation_id"], []).append(resource)
    renewable = {}
    live = _live_sessions(project, renewable=renewable)
    if inventory is None:
        observations = _observations(project)
    else:
        observations = {}
        for item in inventory["observations"]:
            observations.setdefault(item["operation_id"], []).append(item)
    from .parameter_coverage import snapshot as parameter_snapshot
    parameters = parameter_snapshot(project, evaluated, inventory=inventory)
    by_obligation = {identity: parameter for parameter in parameters["items"] for identity in parameter["obligation_ids"]}
    from .browser_policy import Context, for_work_item
    browser_context = Context(project)
    sessions_by_operation, renewable_by_operation, rows = {}, {}, []
    for gap in evaluated["gaps"]:
        operation_id = gap["operation_id"]
        if operation_id not in sessions_by_operation:
            sessions_by_operation[operation_id] = _operation_sessions(project, operations[operation_id], live)
        compatible, foreign = sessions_by_operation[operation_id]
        row = _work_item(project, gap, operations, compatible, observations, foreign, by_obligation.get(gap["id"]),
                         resources=resources_by_operation.get(operation_id, []), config=config)
        if renewable and row["missing_prerequisites"]:
            if operation_id not in renewable_by_operation:
                renewable_by_operation[operation_id] = _operation_sessions(project, operations[operation_id], renewable)[0]
            candidates = _renewal_candidates(project, row, operations[operation_id], renewable_by_operation[operation_id])
            if candidates:
                row["session_renewal_candidates"] = candidates
        evidence_ids = set(row.get("evidence_ids", []))
        evidence = [item for item in observations.get(operation_id, []) if item["id"] in evidence_ids]
        policy = row["browser_testing"] = for_work_item(browser_context, operations[operation_id], gap, row, evidence)
        family = row.get("hypothesis_family") or gap.get("test_family")
        binding_review = row.get("scope_binding_review_required") is True
        if binding_review and policy["requirement"] == "required":
            linked = browser_context.linked_pages(operations[operation_id])
            if linked and all(page.get("visit_status") == "BLOCKED" for page in linked):
                row.update(queue_status="blocked", execution_blocked=True)
                row["missing_prerequisites"].append("explicit_consumer_page_unblock_or_authorized_alternative")
                policy.update(stage="blocked", invoke_now=False, execution_blocked=True,
                              required_input_fields=list(row["missing_prerequisites"]))
            else:
                policy.update(stage="prepare", invoke_now=False, execution_blocked=True, native_input_requires_binding=True,
                              required_input_fields=["exact_scoped_url_query_binding", "scoped_consumer_url"])
                policy.pop("native_visit_input", None)
        offline = row["suggested_action"] in {"evidence.inspect", "assessment.evaluate", "surface.register",
                                               "surface.declare_consumer", "identity.actor", "identity.resource"} \
            or binding_review and row["suggested_action"] == "surface.inspect"
        if policy["stage"] == "blocked" and policy["requirement"] == "required" and not offline:
            row.update(queue_status="blocked", execution_blocked=True)
            row["missing_prerequisites"] = list(dict.fromkeys(
                row["missing_prerequisites"] + policy.get("required_input_fields", [])))
        if policy["stage"] == "review_existing" and family == "xss":
            refs = policy["existing_observation"]
            row.update(queue_status="review", suggested_action="finding.record", help_input={"name": "finding.record"},
                       input_template={"mode": "analyst", "obligation_id": gap["id"],
                           "evidence_ids": [refs["baseline_evidence_id"], refs["attack_evidence_id"]],
                           "runtime_visit_id": refs["runtime_visit_id"]})
            row["required_experiment_fields"] += ["consumer_url", "runtime_marker", "analyst reviewer/reason and supported impact"]
        elif policy["must_call_playwright"] and policy["stage"] in {"identify_consumer", "browser_runtime", "browser_assist"} \
                and not row.get("control_candidate_review_required"):
            row["queue_status"] = "review"
            if policy["native_supported"]:
                row.update(suggested_action="browser.visit", help_input={"name": "browser.visit"},
                           input_template=dict(policy.get("native_visit_input", {})))
            else:
                row.update(suggested_action="action.help", help_input={"name": "browser.import_mcp"},
                           input_template={"name": "browser.import_mcp"})
            row["required_experiment_fields"] += policy["required_input_fields"]
            row["browser_handoff_note"] = "Use actual host Playwright tools first; this template is a bounded native fallback, not authorization. Fill the missing exact URL/interaction inputs before invocation."
        rows.append(_preparation_actions(_reconcile_declared_blocker(row, gap), operations[operation_id]))
    return rows


def next_work(project, args):
    offset, limit = page_args(args, default=10, maximum=25)
    include_blocked = args.get("include_blocked", False)
    if type(include_blocked) is not bool:
        raise EngineError("arguments", "include_blocked must be a boolean")
    from .completeness import evaluate_with_inventory, followups
    from .parameter_coverage import public_page as parameter_page
    evaluated, inventory = evaluate_with_inventory(project)
    rows = inventory["queue"]
    counts = Counter(row["queue_status"] for row in rows)
    selected = _fair_work_items([row for row in rows if row["queue_status"] != "blocked"])
    blocked = _fair_work_items([row for row in rows if row["queue_status"] == "blocked"])
    if include_blocked:
        selected += blocked
    closure = followups(project, evaluated, min(limit, 10), inventory=inventory)
    from .browser_policy import summarize
    browser_summary = summarize([row["browser_testing"] for row in rows])
    followup_summary = closure.pop("browser_followup_summary")
    for key, count in followup_summary.items():
        browser_summary[key] += count
    return {"continuation": evaluated["continuation"],
            "work_items": selected[offset:offset + limit], "queue_total": len(selected),
            "ready_total": counts["ready"], "review_total": counts["review"], "blocked_total": counts["blocked"],
            "offset": offset, "limit": limit, "next_offset": offset + limit if offset + limit < len(selected) else None,
            "blocked_sample": blocked[:min(5, limit)], **closure,
            "requests_sent": 0, "coverage_ratio": evaluated["coverage_ratio"],
            "security_coverage": evaluated["security_coverage"], "completion": evaluated["completion"],
            "parameter_coverage": parameter_page(inventory["parameter_coverage_snapshot"],
                {"parameter_limit": min(limit, 3), **args}),
            "queue_policy": "coverage_first", "queue_fairness": "family_and_operation_round_robin", "closure_action": "plan.audit",
            "browser_testing_summary": browser_summary,
            "limitation": "Readiness is not approval, execution, or completed coverage. Fill the exact experiment fields and preflight every request; imported tool output remains untrusted."}


def findings_page(project, args):
    if "current" in args and type(args["current"]) is not bool:
        raise EngineError("arguments", "current must be a boolean")
    lifecycle = args.get("lifecycle_status")
    if lifecycle is not None and lifecycle not in {"active", "withdrawn", "superseded"}:
        raise EngineError("finding_lifecycle", "lifecycle_status must be active, withdrawn or superseded")
    rows = engine.evaluate_coverage(project)["findings"]
    rows = [row for row in rows if ("current" not in args or row.get("current") is args["current"])
            and (lifecycle is None or row.get("lifecycle_status", "active") == lifecycle)]
    window = page(rows, args)
    return {"findings": safe_metadata(window.pop("items")), "finding_total": window.pop("total"), **window}


def update_finding(project, args):
    status = args.get("status")
    if status not in {"active", "withdrawn", "superseded"}:
        raise EngineError("finding_lifecycle", "status must be active, withdrawn or superseded")
    for field in ("reviewer", "reason"):
        if not isinstance(args.get(field), str) or not args[field].strip() or len(args[field]) > 4000:
            raise EngineError("finding_lifecycle", f"{field} must be a nonempty string of at most 4000 characters")
    forbidden = {"decision_id", "evidence_ids", "proof", "title", "category", "severity", "impact", "remediation"} & set(args)
    if forbidden:
        raise EngineError("finding_immutable", "Lifecycle updates cannot change original finding fields or proof; record a supported replacement instead")
    with project.transaction():
        finding = project.get("finding", args["finding_id"])
        replacement = args.get("replacement_finding_id")
        if status == "superseded":
            if not isinstance(replacement, str) or replacement == finding["id"]:
                raise EngineError("finding_replacement", "superseded requires a distinct replacement_finding_id")
            candidates = {item["id"]: item for item in engine.evaluate_coverage(project)["findings"]}
            if replacement not in candidates or candidates[replacement].get("current") is not True:
                raise EngineError("finding_replacement", "Replacement must be a current active finding in this project with valid proof")
            seen, cursor = {finding["id"]}, replacement
            while cursor:
                if cursor in seen:
                    raise EngineError("finding_replacement", "Finding replacement chains cannot contain a cycle")
                seen.add(cursor)
                cursor = project.get("finding", cursor).get("replacement_finding_id")
        elif replacement is not None:
            raise EngineError("finding_replacement", "replacement_finding_id is only valid with status:superseded")
        revision = {"id": project.id("FR"), "finding_id": finding["id"], "previous_status": finding.get("lifecycle_status", "active"),
                    "status": status, "reviewer": args["reviewer"].strip(), "reason": args["reason"].strip(),
                    "replacement_finding_id": replacement, "created_at": now()}
        finding.update(lifecycle_status=status, lifecycle_reviewer=revision["reviewer"], lifecycle_reason=revision["reason"],
                       lifecycle_updated_at=revision["created_at"], lifecycle_revision_id=revision["id"],
                       lifecycle_revision_count=finding.get("lifecycle_revision_count", 0) + 1)
        if replacement:
            finding["replacement_finding_id"] = replacement
        else:
            finding.pop("replacement_finding_id", None)
        project.put("finding_revision", revision, create_only=True)
        project.put("finding", finding)
        project.event("finding.lifecycle_changed", {"finding_id": finding["id"], "revision_id": revision["id"], "status": status,
                                                     "replacement_finding_id": replacement})
    evaluated = next(row for row in engine.evaluate_coverage(project)["findings"] if row["id"] == finding["id"])
    return {"finding": safe_metadata(evaluated), "revision": safe_metadata(revision), "original_proof_preserved": True}
