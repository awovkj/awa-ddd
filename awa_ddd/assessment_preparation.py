"""Bounded offline proof preparation from the current ledger, without replay."""
from __future__ import annotations

import hashlib
import json

from . import engine, loop_guard
from .completeness import PROOF_CHANNELS, evaluate_with_inventory, obligation_family, suggested_families
from .oracle_contracts import ORACLES
from .store import EngineError
from .workflow import page_args


_TARGETS = {"obligation_id": "obligation", "finding_id": "finding",
            "evidence_id": "evidence", "operation_id": "operation"}
_POSITIVE_INPUT_FAMILIES = {"sql_injection", "xxe", "ssrf", "path_traversal", "business_logic"}
_OBSERVATION_FIELDS = ("id", "operation_id", "actor_id", "session_id", "session_generation",
                       "resource_id", "run_id", "status_code")


def _target(args):
    if set(args) - {*_TARGETS, "project_id", "evidence_ids", "offset", "limit"}:
        raise EngineError("arguments", "assessment.prepare accepts one target, evidence_ids, offset and limit; use action.help for its fields")
    targets = [key for key in _TARGETS if key in args]
    if len(targets) != 1 or not isinstance(args[targets[0]], str) or not args[targets[0]]:
        raise EngineError("arguments", "assessment.prepare requires exactly one of obligation_id, finding_id, evidence_id or operation_id",
                          {"next_action": "action.help", "help_input": {"name": "assessment.prepare"}})
    supplied = args.get("evidence_ids")
    if supplied is not None and (not isinstance(supplied, list) or not 1 <= len(supplied) <= 25
            or any(not isinstance(identity, str) or not identity for identity in supplied)
            or len(set(supplied)) != len(supplied)):
        raise EngineError("independent_evidence", "evidence_ids must contain 1..25 distinct actual capture IDs")
    if targets[0] == "evidence_id" and supplied is not None and args[targets[0]] not in supplied:
        raise EngineError("evidence_binding", "The selected evidence_id must remain in an explicit evidence selection")
    return targets[0], args[targets[0]], supplied


def _input(operation, obligation):
    return next((entry for entry in operation.get("inputs", [])
                 if entry.get("location") == obligation.get("input_location")
                 and entry.get("selector") == obligation.get("input_selector")
                 and entry.get("schema_branch") == obligation.get("schema_branch")), None)


def _authorization_candidates(project, item, operation, observations, anchor_id=None):
    """Classified, request-matched references; the protected selector is still reviewed."""
    from .assessment import _authorized, _authorization_requests, _independent_principals, _require_verified_roles

    if operation.get("auth") == "unknown":
        return [], ["declared_access_policy"]
    if item["kind"] == "ownership":
        baseline_actor = item.get("baseline_actor_id")
        allowed = [row for row in observations if row.get("actor_id") == baseline_actor
                   and row.get("resource_id") == item.get("resource_id")]
        variants = [row for row in observations if row.get("actor_id") == item.get("actor_id")
                    and row.get("resource_id") == item.get("resource_id")]
    else:
        allowed = [row for row in observations if _authorized(project, operation, row.get("actor_id"))]
        variants = [row for row in observations if row.get("actor_id") == item.get("actor_id")
                    and not _authorized(project, operation, row.get("actor_id"))]
    blockers = []
    for baseline in reversed(allowed[-25:]):
        if not 200 <= baseline.get("status_code", 0) < 300:
            continue
        for variant in reversed(variants[-25:]):
            if baseline["run_id"] == variant["run_id"]:
                continue
            if anchor_id is not None and anchor_id not in {baseline["id"], variant["id"]}:
                continue
            try:
                pair = [engine.verify_current_evidence(project, row["id"]) for row in (baseline, variant)]
                _authorization_requests(project, pair)
                _require_verified_roles(project, operation, pair)
                _independent_principals(project, *pair)
            except EngineError as exc:
                if exc.code in {"roles_unverified", "actor_independence"} and exc.code not in blockers:
                    blockers.append(exc.code)
                continue
            except (OSError, ValueError, TypeError, KeyError):
                continue
            return [baseline["id"], variant["id"]], []
    return [], blockers


def _oracle_options(item, family):
    if item["kind"] == "baseline":
        names = ["baseline"]
    elif item["kind"] in {"access", "ownership"}:
        names = ["authorization"]
    elif item["kind"] != "input_test" or family == "xss":
        names = []
    else:
        names = [name for name in PROOF_CHANNELS.get(family, []) if name in ORACLES]
    options = []
    for name in names:
        contract = ORACLES[name]
        template = {"type": name}
        if item.get("test_family"):
            template["test_family"] = item["test_family"]
        required = list(contract["required"])
        if name == "extraction" and family in {"xxe", "ssrf", "path_traversal"}:
            required += contract.get("required_for_typed", [])
        options.append({"oracle_type": name, "oracle_template": template,
                        "evidence_order": list(contract["evidence_order"]),
                        "required_fields": list(dict.fromkeys(required)),
                        "conditional_fields": list(contract.get("conditional", [])),
                        "can_confirm": name in {"authorization", "extraction", "sql_metadata", "error_channel", "state_invariant", "state_transition"},
                        "help_input": {"name": "assessment.evaluate"}})
    return options


def _scenario_candidates(project, item, allowed_ids, observations):
    from .assessment import _scenario_observations

    candidates = []
    for run in reversed(project.list("run")):
        if run.get("kind") != "scenario" or run.get("status") != "succeeded":
            continue
        steps = run.get("checkpoints", [])
        for index in range(max(0, len(steps) - 2)):
            sequence = steps[index:index + 3]
            if any(not isinstance(step, dict) or step.get("status") != "verified" or "concurrent" in step
                   or not isinstance(step.get("evidence_id"), str) for step in sequence):
                continue
            ids = [step["evidence_id"] for step in sequence]
            if len(set(ids)) != 3 or not all(identity in observations for identity in ids) \
                    or allowed_ids is not None and not set(ids).issubset(allowed_ids):
                continue
            before, action, after = [observations[identity] for identity in ids]
            if action["operation_id"] != item["operation_id"] or before["operation_id"] != after["operation_id"]:
                continue
            if project.get("operation", before["operation_id"])["method"] not in {"GET", "HEAD"} \
                    or project.get("operation", action["operation_id"])["method"] in {"GET", "HEAD", "OPTIONS"}:
                continue
            try:
                captures, _ = _scenario_observations(project, ids, item, {"scenario_run_id": run["id"],
                    **dict(zip(("before_step_id", "action_step_id", "after_step_id"),
                               (step.get("step_id") for step in sequence)))})
                if captures[0][1]["request"] != captures[2][1]["request"]:
                    continue
            except (EngineError, OSError, ValueError, TypeError, KeyError):
                continue
            candidates.append(run["id"])
            break
    return candidates[:3]


def _prepare_item(project, item, inventory, observations, allowed_ids, source_finding):
    operation = inventory["operations"][item["operation_id"]]
    family = obligation_family(item, operation)
    current_gap = inventory["gaps"].get(item["id"])
    row = {"obligation_id": item["id"], "operation_id": item["operation_id"],
           "obligation_kind": item["kind"], "test_family": family,
           "status": current_gap.get("status", "open") if current_gap else item.get("status", "open"),
           "controls_are_candidates_only": True, "evidence_review_required": True,
           "positive_machine_adapter": family in _POSITIVE_INPUT_FAMILIES or item["kind"] in {"access", "ownership"},
           "control_candidate_evidence_ids": [], "required_experiment_fields": []}
    for field in ("input_location", "input_selector", "schema_branch", "actor_id", "baseline_actor_id", "resource_id"):
        if field in item:
            row[field] = item[field]
    entry = _input(operation, item)
    profile = inventory.get("parameter_profiles")
    evidence = [record for record in observations if record["operation_id"] == item["operation_id"]]
    if entry and profile:
        candidates, required = profile.control_candidates(operation["id"], entry, family,
            allowed_evidence_ids=allowed_ids, anchor=inventory.get("preparation_anchor"))
        row.update(control_candidate_evidence_ids=candidates, control_candidate_required_values=required,
                   observations_limited=profile.view(operation["id"], entry)["observations_limited"],
                   schema_branch_requires_binding=profile.view(operation["id"], entry)["schema_branch_requires_binding"])
    elif item["kind"] == "baseline":
        candidates = [record["id"] for record in evidence
                      if record.get("actor_id") == item.get("actor_id") and 200 <= record.get("status_code", 0) < 300]
        row.update(control_candidate_evidence_ids=candidates[-1:], control_candidate_required_values=1,
                   positive_machine_adapter=False)
    elif item["kind"] in {"access", "ownership"}:
        anchor = inventory.get("preparation_anchor")
        candidates, blockers = _authorization_candidates(project, item, operation, evidence,
            anchor_id=anchor[0]["id"] if anchor else None)
        row.update(control_candidate_evidence_ids=candidates, control_candidate_required_values=2,
                   control_review_blockers=blockers)

    source_decision = inventory["decisions"].get(item.get("decision_id"))
    if current_gap is None and item.get("status") == "evaluated" and source_decision:
        if allowed_ids is not None and not set(source_decision.get("evidence_ids", [])).issubset(allowed_ids):
            selected_evidence = [record["id"] for record in evidence]
            row.update(preparation_state="proof_outside_selection", suggested_action="evidence.inspect" if selected_evidence else "action.help",
                       input_template={"evidence_id": selected_evidence[0]} if selected_evidence else {"name": "assessment.prepare"},
                       required_experiment_fields=["review the original proof's evidence selection; no new request is required"],
                       note_zh="本义务已有证明，但完整对照不在本次选择的证据内。仅复核选中材料；不会替换证据或要求重放实验。")
            return row
        row.update(preparation_state="proof_current", decision_id=source_decision["id"],
                   outcome=source_decision.get("outcome"), suggested_action="evidence.inspect",
                   input_template={"evidence_id": source_decision["evidence_ids"][0]})
        if source_finding and source_decision.get("mode") == "machine" and source_decision.get("outcome") == "confirmed" \
                and set(source_decision.get("evidence_ids", [])).issubset(allowed_ids):
            from .assessment import current_machine_proof
            try:
                current_machine_proof(project, source_decision["id"], source_finding["category"])
            except (EngineError, OSError, ValueError, TypeError, KeyError):
                pass
            else:
                row.update(suggested_action="finding.bind", input_template={"finding_id": source_finding["id"],
                           "decision_id": source_decision["id"]}, required_experiment_fields=["reviewer", "reason"])
        return row

    if item["kind"] == "input_review":
        row.update(preparation_state="needs_consumer", suggested_action="surface.declare_consumer",
                   positive_machine_adapter=False, suggested_test_families=suggested_families(entry or {}, operation),
                   hints_only=True, input_template={"operation_id": item["operation_id"],
                       "input_location": item["input_location"], "input_selector": item["input_selector"], "schema_branch": item.get("schema_branch")},
                   required_experiment_fields=["consumer", "test_families"],
                   note_zh="先从真实功能追踪消费点，再独立选择测试族；提示不自动声明 sink 或建立漏洞证明。")
        return row
    setup_actions = {"auth_review": "surface.register", "identity_setup": "identity.actor",
                     "ownership_setup": "identity.resource"}
    if item["kind"] in setup_actions:
        row.update(preparation_state="needs_policy_or_identity", suggested_action="action.help",
                   input_template={"name": setup_actions[item["kind"]]}, positive_machine_adapter=False,
                   required_experiment_fields=["actual policy, verified identity and owned fixture"])
        return row

    candidates = row["control_candidate_evidence_ids"]
    row.update(preparation_state="inspect_existing" if candidates else "needs_controls",
               suggested_action="evidence.inspect" if candidates else "action.help",
               input_template={"evidence_id": candidates[0]} if candidates else {"name": "http.preflight"},
               assessment_action="assessment.evaluate", oracle_options=_oracle_options(item, family))
    if candidates:
        row["assessment_template"] = {"obligation_id": item["id"], "evidence_ids": candidates}
        row["required_experiment_fields"] = ["review control roles and order", "oracle with actual business assertions"]
    else:
        row["required_experiment_fields"] = ["inspect saved evidence and reconcile effects before preparing missing controls"]
    if family == "business_logic" and item["kind"] == "input_test":
        row["scenario_run_ids"] = _scenario_candidates(project, item, allowed_ids,
            {observation["id"]: observation for observation in inventory["observations"]
             if allowed_ids is None or observation["id"] in allowed_ids})
        row["note_zh"] = "状态链需要原生 scenario 的实际读/写/读检查点；独立请求或并发竞态不能伪装为已验证状态链。先复核已有写入影响，再准备新可回退资源。"
    elif family == "xss" and item["kind"] == "input_test":
        row.update(assessment_action="finding.record", positive_machine_adapter=False,
                   runtime_binding_supported=True, help_input={"name": "finding.record"},
                   required_experiment_fields=["title", "category", "impact", "remediation", "obligation_id", "reviewer", "reason",
                       "normal/attack controls in actual order", "runtime_visit_id", "consumer_url", "runtime_marker"],
                   note_zh="绑定实际源输入：GET 直接消费须同身份精确文档；存储 API 到 SPA 用写入源、JSON 回读内容版本和正常/攻击 native viewer 的 xss_consumption。搜索定位词和页面弹窗不能替代源输入证明。")
        row["assessment_template"] = {"mode": "analyst", "obligation_id": item["id"], "evidence_ids": candidates}
        row["runtime_binding_modes"] = ["direct_document"]
        if operation["method"] in {"POST", "PUT", "PATCH"}:
            row["runtime_binding_modes"].append("stored_api")
            row["required_experiment_fields"].append(
                "For stored_api: xss_consumption, writer-normal/writer-attack/reader-normal/reader-attack evidence IDs; exact JSON content/fixture selectors, successful write assertion and original native normal/attack viewer visits. Readbacks and visits execute between their respective writes; a locator is not the source.")
    elif item["kind"] == "input_test" and family not in _POSITIVE_INPUT_FAMILIES:
        row.update(positive_machine_adapter=False,
                   note_zh="当前没有本假设的通用正向机器证明；有限否定与人工发现保留具体边界，不替代完整安全测试。")
    return row


def prepare(project, args):
    """Read the same current snapshot as coverage; suggestions never create decisions."""
    key, identity, supplied = _target(args)
    offset, limit = page_args(args, default=3, maximum=10)
    source = project.get(_TARGETS[key], identity)
    if key == "obligation_id" and source.get("superseded"):
        raise EngineError("obligation_superseded", "Refresh the current obligation before preparing evidence",
                          {"next_action": "plan.next", "operation_id": source["operation_id"]})
    anchor = engine.verify_current_evidence(project, identity) if key == "evidence_id" else None
    evaluated, inventory = evaluate_with_inventory(project)
    if anchor:
        inventory = {**inventory, "preparation_anchor": (anchor[0], anchor[1]["request"])}
    finding = source if key == "finding_id" else None
    if finding:
        current = next((row for row in inventory["current_findings"] if row["id"] == identity), None)
        if current is None or finding.get("mode") != "analyst":
            raise EngineError("finding_lifecycle", "Prepare a current active analyst finding; inspect historical or machine findings separately")
        allowed_ids = set(finding["evidence_ids"])
        if supplied is not None and not set(supplied).issubset(allowed_ids):
            raise EngineError("evidence_binding", "Finding preparation cannot substitute evidence absent from the original finding")
        allowed_ids = set(supplied) if supplied is not None else allowed_ids
    else:
        allowed_ids = set(supplied) if supplied is not None else None
    all_observations = {row["id"]: row for row in inventory["observations"]}
    if supplied is not None:
        for evidence_id in supplied:
            if evidence_id not in all_observations:
                engine.verify_current_evidence(project, evidence_id)
                raise EngineError("evidence_binding", "Only current complete HTTP captures can be prepared")
    operation_ids = ({source["operation_id"]} if key in {"obligation_id", "evidence_id"} else
                     {identity} if key == "operation_id" else
                     {all_observations[evidence_id]["operation_id"] for evidence_id in allowed_ids if evidence_id in all_observations})
    if supplied is not None and not finding and any(all_observations[evidence_id]["operation_id"] not in operation_ids
                                                   for evidence_id in supplied):
        raise EngineError("evidence_binding", "Supplied captures must belong to the selected operation; related state-chain evidence requires finding preparation")
    observations = [row for row in inventory["observations"]
                    if row["operation_id"] in operation_ids and (allowed_ids is None or row["id"] in allowed_ids)]
    if allowed_ids is not None:
        # The global profile retains representative IDs for distinct values.
        # Rebuild from the selected original captures so later same-value runs
        # cannot hide an existing finding's complete controls and suggest replay.
        from .parameter_coverage import ObservationProfiles
        scoped_profiles = ObservationProfiles({operation_id: inventory["operations"][operation_id]
                                               for operation_id in operation_ids})
        for observation in observations:
            current, artifact = engine.verify_current_evidence(project, observation["id"])
            scoped_profiles.observe(current, artifact["request"])
        inventory = {**inventory, "parameter_profiles": scoped_profiles}
    items = [item for item in inventory["obligations"] if item["operation_id"] in operation_ids
             and (key != "obligation_id" or item["id"] == identity)]
    # Existing typed proof and security controls take precedence over redundant baselines.
    priorities = {"input_test": 1, "ownership": 2, "access": 2, "input_review": 3,
                  "auth_review": 4, "identity_setup": 4, "ownership_setup": 4, "baseline": 5}
    items.sort(key=lambda item: (0 if item.get("status") == "evaluated" and item["id"] not in inventory["gaps"] else
                                priorities.get(item["kind"], 4), item["id"]))
    selected = items[offset:offset + limit]
    rows = [_prepare_item(project, item, inventory, observations, allowed_ids, finding) for item in selected]
    from .assessment_mode import work_policy
    rows = [work_policy(project, row, inventory["operations"][row["operation_id"]]) for row in rows]
    if rows:
        signature = hashlib.sha256(json.dumps([
            {"obligation_id": row.get("obligation_id"),
             "state": row.get("preparation_state"),
             "evidence_ids": row.get("control_candidate_evidence_ids") or []}
            for row in rows
        ], ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
        if loop_guard.repeat_seen(project, "assessment.prepare", signature):
            for row in rows:
                row["preparation_state"] = "frozen"
                row["assessment_action"] = "plan.review"
                row["suggested_action"] = "plan.review"
                row["note_zh"] = ("This exact preparation set has been returned repeatedly without a state or evidence change; "
                                  "frozen by loop guard. Reopen only after changing the prerequisite, identity, resource, or evidence.")
    reviewed_ids = list(dict.fromkeys(identity for row in rows for identity in row["control_candidate_evidence_ids"]))
    if key == "evidence_id":
        reviewed_ids = list(dict.fromkeys([identity, *reviewed_ids]))
    reviews = [{field: all_observations[evidence_id][field] for field in _OBSERVATION_FIELDS
                if field in all_observations[evidence_id]}
               for evidence_id in reviewed_ids[:25] if evidence_id in all_observations]
    return {"source": {key: identity}, "items": rows, "total": len(items), "offset": offset, "limit": limit,
            "next_offset": offset + limit if offset + limit < len(items) else None,
            "evidence_reviews": reviews, "source_evidence_total": len(observations),
            "requests_sent": 0, "decisions_created": 0, "automatic_execution_allowed": False,
            "controls_are_candidates_only": True, "continuation": evaluated["continuation"],
            "completion": evaluated["completion"], "next_action": "assessment.prepare" if offset + limit < len(items) else "plan.next",
            "note_zh": "仅复用当前台账准备证明：先检查实际对照顺序、精确输入与消费点，补齐真实判据再求值。现有观察、准备模板和报告答案均不是漏洞证明，不会重放请求或修改覆盖。"}
