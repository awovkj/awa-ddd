"""Persisted continuation and honest, bounded stop gates; never execute requests."""
from __future__ import annotations

from collections import Counter
import hashlib

from .store import EngineError, canonical, contained, now


ALL_FAMILIES = ("access_control", "sql_injection", "xss", "ssrf", "xxe", "path_traversal",
                "command_injection", "template_injection", "deserialization", "file_upload",
                "business_logic", "generic")
MIN_FRONTIER_ROUNDS = 2
STOP_REASONS = {"completed", "blocked", "budget_exhausted", "user_stop", "authorization_boundary"}
REVIEW_LISTS = {"unassessed_observation": "unassessed", "failed_partial_tool": "partial_tools",
               "unreconciled_run": "pending_runs", "orphan_browser_visit": "orphan_visits",
               "unlinked_analyst_finding": "unlinked_analyst"}
SOURCE_KINDS = {"unassessed_observation": "evidence", "failed_partial_tool": "run",
                "unreconciled_run": "run", "orphan_browser_visit": "page_visit",
                "unlinked_analyst_finding": "finding"}
STATE_KINDS = ("operation", "actor", "session", "resource", "obligation", "evidence", "decision", "finding",
               "candidate", "page", "page_visit", "run", "closure_review")


def _digest(prefix, value):
    return prefix + "-" + hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _text(value, name, maximum=4000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise EngineError("continuation_arguments", f"{name} must be a nonempty string of at most {maximum} characters")
    return value.strip()


def _ids(value, name):
    if not isinstance(value, list) or len(value) > 100 \
            or any(not isinstance(item, str) or not item or len(item) > 200 for item in value) \
            or len(set(value)) != len(value):
        raise EngineError("continuation_arguments", f"{name} must contain at most 100 distinct record IDs")
    return value


def _public(project, value):
    from .engine import credential_header_names
    from .reproduction import Redactor, _learn_header

    redactor = Redactor()
    redactor.learn(value)
    for session in project.list("session"):
        for name in credential_header_names(session):
            secret = session.get("headers", {}).get(name)
            if secret is not None:
                redactor.slot(secret, "SESSION_CREDENTIAL")
                _learn_header(redactor, name, secret)
    return redactor.metadata(value)


def _material(project, record):
    """Bind reviews to actual bytes, including missing/changed tool log files."""
    states = []
    references = []
    if record.get("artifact_path"):
        references.append({"path": record["artifact_path"], "sha256": record.get("sha256")})
    files = record.get("files") or []
    references.extend(item for item in files if isinstance(item, dict) and item.get("path"))
    for reference in references:
        state = {"path": reference["path"], "declared": reference.get("sha256")}
        try:
            path = contained(project.base / reference["path"], project.base)
            if not path.is_file():
                state["state"] = "missing"
            elif path.stat().st_size > 12 * 1024 * 1024:
                stat = path.stat()
                state.update(state="over_budget", size_bytes=stat.st_size,
                             mtime_ns=stat.st_mtime_ns, ctime_ns=stat.st_ctime_ns)
            else:
                state["actual"] = hashlib.sha256(path.read_bytes()).hexdigest()
        except (EngineError, OSError, ValueError, TypeError):
            state["state"] = "unreadable"
        states.append(state)
    return states


def _evidence_reference(project, identity):
    from .engine import verify_current_evidence

    record = project.get("evidence", identity, required=False)
    if not record:
        return {"id": identity, "state": "missing"}
    try:
        verify_current_evidence(project, identity)
        state = "current"
    except (EngineError, OSError, ValueError, TypeError, KeyError) as exc:
        state = getattr(exc, "code", "invalid")
    return {"id": identity, "record": record, "material": _material(project, record), "state": state}


def _source_signature(project, kind, item):
    record = project.get(SOURCE_KINDS[kind], item["id"], required=False) or item
    related = []
    evidence_ids = set(record.get("evidence_ids", []))
    for field in ("evidence_id", "verification_evidence_id"):
        if record.get(field):
            evidence_ids.add(record[field])
    if kind == "unassessed_observation":
        evidence_ids.add(record["id"])
    if kind == "unlinked_analyst_finding":
        decision = project.get("decision", record.get("decision_id"), required=False)
        if decision:
            related.append(decision)
            evidence_ids.update(decision.get("evidence_ids", []))
            runtime = decision.get("runtime") or {}
            if runtime.get("visit_id"):
                visit = project.get("page_visit", runtime["visit_id"], required=False)
                if visit:
                    related.extend([visit, _material(project, visit)])
    for entity, field in (("operation", "operation_id"), ("session", "session_id"),
                          ("actor", "actor_id"), ("resource", "resource_id")):
        if record.get(field):
            related.append(project.get(entity, record[field], required=False))
    if record.get("kind") == "scenario":
        for context in (record.get("preflight") or {}).get("steps", []):
            for entity, field in (("operation", "operation_id"), ("session", "session_id"),
                                  ("actor", "actor_id"), ("resource", "resource_id")):
                if isinstance(context, dict) and context.get(field):
                    related.append(project.get(entity, context[field], required=False))
    return _digest("RV", {"config": project.config, "source": record,
                          "material": _material(project, record), "related": related,
                          "evidence": [_evidence_reference(project, identity) for identity in sorted(evidence_ids)]})


def _review_valid(project, review, item):
    if review.get("source_signature") != _source_signature(project, review["kind"], item):
        return False
    references = [_evidence_reference(project, identity) for identity in review.get("evidence_ids", [])]
    return all(row["state"] == "current" for row in references) \
        and review.get("support_signature") == _digest("SP", references)


def apply_reviews(project, inventory):
    """Administrative receipts never count as decisions or security coverage."""
    from .completeness import _review_id, _tscanplus_incomplete

    latest = {}
    for record in project.list("closure_review"):
        latest[record["checklist_id"]] = record
    # A previously archived observation must not vanish when its bytes become
    # invalid: keep an administrative repair gap, without counting valid coverage.
    known = {row["id"] for row in inventory["unassessed"]}
    for record in latest.values():
        if record["kind"] != "unassessed_observation" or record["source_id"] in known:
            continue
        item = project.get("evidence", record["source_id"], required=False)
        if item:
            reference = _evidence_reference(project, item["id"])
            if reference["state"] != "current":
                inventory["unassessed"].append({**item, "review_source_invalid": True,
                                                "review_reason_code": reference["state"]})
                known.add(item["id"])
        else:
            inventory["unassessed"].append({"id": record["source_id"], "kind": "http",
                "review_source_invalid": True, "review_reason_code": "evidence_missing"})
            known.add(record["source_id"])
    inventory["reviewed_admin"], inventory["blocked_reviews"] = [], {}
    for kind, key in REVIEW_LISTS.items():
        retained = []
        for item in inventory[key]:
            identity = _review_id(kind, item["id"])
            review = latest.get(identity)
            if review and _review_valid(project, review, item):
                remote_incomplete = kind in {"failed_partial_tool", "unreconciled_run"} \
                    and item.get("adapter") == "tscanplus" and _tscanplus_incomplete(item)
                if review["status"] == "reviewed" and kind != "unlinked_analyst_finding" and not remote_incomplete:
                    inventory["reviewed_admin"].append(review)
                    continue
                if review["status"] == "blocked":
                    inventory["blocked_reviews"][identity] = review
            retained.append(item)
        inventory[key] = retained
    return inventory


def _references(project, declaration, *, required=False, cache=None):
    from . import browser

    cache = cache if cache is not None else {}

    evidence_ids = _ids(declaration.get("evidence_ids", []), "evidence_ids")
    visit_ids = _ids(declaration.get("page_visit_ids", []), "page_visit_ids")
    if required and not evidence_ids and not visit_ids:
        raise EngineError("frontier_evidence", "Reviewed scope/applicability needs actual current HTTP or browser references, not just text")
    references = []
    for identity in evidence_ids:
        key = ("evidence", identity)
        if key not in cache:
            cache[key] = _evidence_reference(project, identity)
        if cache[key]["state"] != "current":
            raise EngineError("frontier_evidence", "A scope review reference is not a current complete observation")
        references.append(cache[key])
    for identity in visit_ids:
        key = ("page_visit", identity)
        if key not in cache:
            visit = project.get("page_visit", identity)
            verified, _ = browser._verified_visit(project, identity, visit["url"])
            cache[key] = {"id": identity, "record": verified, "material": _material(project, verified)}
        references.append(cache[key])
    return _digest("FP", references)


def _frontier_review(project, value, inventory, cache=None):
    from .completeness import obligation_family

    if not isinstance(value, dict) or set(value) != {"discovery", "categories", "pages"}:
        raise EngineError("frontier_review", "frontier_review requires discovery, categories and pages declarations")
    result, reference_signatures = {}, {}
    cache = cache if cache is not None else {}
    for name, allowed in (("discovery", {"reviewed", "blocked"}), ("pages", {"reviewed", "api_only", "blocked"})):
        declaration = value[name]
        if not isinstance(declaration, dict) or declaration.get("status") not in allowed:
            raise EngineError("frontier_review", f"Invalid {name} review status")
        result[name] = {"status": declaration["status"], "reason": _text(declaration.get("reason"), name + ".reason"),
                        "evidence_ids": _ids(declaration.get("evidence_ids", []), "evidence_ids"),
                        "page_visit_ids": _ids(declaration.get("page_visit_ids", []), "page_visit_ids")}
        reference_signatures[name] = _references(project, result[name], required=declaration["status"] != "blocked", cache=cache)
    known_browser = inventory["page_coverage"]["pages"] or any(
        row.get("runtime") for row in inventory["valid_decisions"])
    if result["pages"]["status"] == "api_only" and known_browser:
        raise EngineError("frontier_pages", "An existing page/function ledger cannot be discarded by declaring API-only")
    if result["pages"]["status"] == "reviewed" and (not inventory["page_coverage"]["pages"]
            or inventory["page_coverage"]["unvisited"] or inventory["page_coverage"]["untriggered"]):
        raise EngineError("frontier_pages", "Reviewed pages require the actual registered page/function ledger to be closed")
    categories = value["categories"]
    if not isinstance(categories, list) or len(categories) != len(ALL_FAMILIES) \
            or any(not isinstance(row, dict) or not isinstance(row.get("test_family"), str) for row in categories) \
            or {row.get("test_family") for row in categories} != set(ALL_FAMILIES):
        raise EngineError("frontier_categories", "Review all 12 category applicability boundaries exactly once; unplanned is not N/A")
    planned = {obligation_family(item, inventory["operations"].get(item["operation_id"], {}))
               for item in inventory["obligations"] if item["kind"] in {"input_test", "access", "ownership"}}
    result["categories"] = []
    for declaration in sorted(categories, key=lambda row: row["test_family"]):
        family, status = declaration["test_family"], declaration.get("status")
        if status not in {"planned", "not_applicable", "blocked"}:
            raise EngineError("frontier_categories", "Category status must be planned, not_applicable or blocked")
        if status == "planned" and family not in planned:
            raise EngineError("frontier_categories", "A planned family needs actual current security-test obligations")
        if status == "not_applicable" and family in planned:
            raise EngineError("frontier_categories", "Applicability review cannot exclude an existing family's test obligations")
        row = {"test_family": family, "status": status, "reason": _text(declaration.get("reason"), family + ".reason"),
               "evidence_ids": _ids(declaration.get("evidence_ids", []), "evidence_ids"),
               "page_visit_ids": _ids(declaration.get("page_visit_ids", []), "page_visit_ids")}
        reference_signatures[family] = _references(project, row, required=status == "not_applicable", cache=cache)
        result["categories"].append(row)
    result["reference_signatures"] = reference_signatures
    result["complete"] = result["discovery"]["status"] == "reviewed" \
        and result["pages"]["status"] != "blocked" \
        and all(row["status"] != "blocked" for row in result["categories"])
    return result


def _valid_frontier(project, checkpoint, inventory, cache=None):
    review = checkpoint.get("frontier_review")
    if not review:
        return False
    try:
        checked = _frontier_review(project, {key: review[key] for key in ("discovery", "categories", "pages")}, inventory, cache)
        return checked == review
    except (EngineError, OSError, ValueError, TypeError, KeyError):
        return False


def _state(project, evaluated, inventory, completion):
    from .completeness import _checklist
    from .workflow import queue_inventory

    queue = queue_inventory(project, evaluated, inventory)
    extras = [row for row in _checklist(inventory) if row["kind"] != "obligation"]
    counts = Counter(row["queue_status"] for row in queue)
    ready, review = counts["ready"], counts["review"] + sum(row["status"] == "open" for row in extras)
    blocked = counts["blocked"] + sum(row["status"] == "blocked" for row in extras)
    rows = {kind: project.list(kind) for kind in STATE_KINDS}
    validity = {"obligations": [(row["id"], row["status"], row["reason_code"]) for row in evaluated["gaps"]],
                "findings": [(row["id"], row.get("current"), row.get("reason_code")) for row in evaluated["findings"]],
                "queue": [(row["gap_id"], row["queue_status"], row["missing_prerequisites"]) for row in queue],
                "extras": [(row["id"], row["status"]) for row in extras],
                "reviews": [row["id"] for row in inventory.get("reviewed_admin", [])]}
    material = {kind: [(row["id"], _material(project, row)) for row in rows[kind]]
                for kind in ("evidence", "page_visit", "run")}
    snapshot = _digest("CS", {"config": project.config, "rows": rows, "material": material, "validity": validity,
                               "completion": completion})
    # Raw captures and repeated plan/tool calls deliberately do not count as progress.
    bad_pages = {row["page_id"] for row in inventory["page_coverage"]["unvisited"]}
    bad_functions = {row["function_id"] for row in inventory["page_coverage"]["untriggered"]}
    progress = _digest("PR", {
        "operations": [{key: row.get(key) for key in ("id", "url", "method", "protocol", "auth", "allowed_roles",
            "ownership", "state_scope", "content_type", "inputs", "ownership_sampling")} for row in rows["operation"]],
        "pages": [{"id": row["id"], "url": row["url"], "visited": row["id"] not in bad_pages,
                   "functions": [{key: function.get(key) for key in ("id", "trigger", "apis")}
                                 | {"triggered": function["id"] not in bad_functions}
                                 for function in row.get("functions", [])]} for row in rows["page"]],
        "candidates": [{key: row.get(key) for key in ("id", "kind", "status", "operation_id")}
                       | {"input_binding": {key: (row.get("link") or {}).get(key)
                                             for key in ("input_location", "input_selector")}}
                       for row in rows["candidate"]],
        "obligations": [(row["id"], inventory["gaps"].get(row["id"], {}).get("status", row.get("status")), row.get("superseded"))
                        for row in rows["obligation"]],
        "valid_decisions": sorted({_digest("PD", {key: row.get(key) for key in
            ("obligation_id", "operation_id", "outcome", "oracle", "proof")}) for row in inventory["valid_decisions"]}),
        "recorded_findings": sorted({_digest("PF", {key: inventory["decisions"].get(row.get("decision_id"), {}).get(key)
            for key in ("obligation_id", "operation_id", "evidence_ids", "oracle", "proof")})
            for row in inventory["current_findings"]}),
        "prerequisites": validity["queue"],
        "reviewed": [(row["checklist_id"], row["source_signature"], row["status"]) for row in inventory.get("reviewed_admin", [])],
        "blocked_reviews": sorted(inventory.get("blocked_reviews", {}))})
    checkpoints = project.list("checkpoint")
    no_progress = 0
    for row in reversed(checkpoints):
        if row.get("progress_id") != progress:
            break
        no_progress += 1
    no_progress = max(0, no_progress - 1)
    candidates = [row for row in checkpoints if row.get("snapshot_id") == snapshot and row.get("frontier_review")][-MIN_FRONTIER_ROUNDS:]
    cache = {}
    frontier = [row for row in candidates if _valid_frontier(project, row, inventory, cache)]
    unresolved = len(queue) + len(extras)
    return {"snapshot_id": snapshot, "progress_id": progress, "ready_total": ready, "review_total": review,
            "blocked_total": blocked, "actionable_total": ready + review, "unresolved_total": unresolved,
            "no_progress_rounds": no_progress, "checkpoint_id": checkpoints[-1]["id"] if checkpoints else None,
            "frontier_rounds": len(frontier), "frontier_complete": bool(frontier and frontier[-1]["frontier_review"]["complete"]),
            "current_checkpoint": bool(checkpoints and checkpoints[-1].get("snapshot_id") == snapshot),
            "current_frontier": bool(frontier and checkpoints and frontier[-1]["id"] == checkpoints[-1]["id"]),
            "checkpoints": checkpoints}


def control(project, evaluated=None, *, inventory=None, security=None, completion=None):
    from . import completeness, engine

    if evaluated is None:
        return engine.evaluate_coverage(project)["continuation"]
    if inventory is None and evaluated.get("continuation") is not None:
        return dict(evaluated["continuation"])
    inventory = inventory if inventory is not None else completeness._inventory(project, evaluated)
    if security is None:
        security, _ = completeness._security(inventory)
    completion = completion if completion is not None else completeness._completion(inventory, security, evaluated)
    state = _state(project, evaluated, inventory, completion)
    frontier_ready = state["frontier_rounds"] >= MIN_FRONTIER_ROUNDS and state["current_checkpoint"] and state["current_frontier"]
    can_finalize = not state["actionable_total"] and frontier_ready and bool(inventory["operations"])
    finalization = next((row for row in reversed(project.list("finalization"))
                         if row.get("snapshot_id") == state["snapshot_id"]
                         and row.get("checkpoint_id") == state["checkpoint_id"]), None)
    reason = ("work_remaining" if state["actionable_total"] else "frontier_review_required" if not frontier_ready
              else "blocked_preconditions" if state["blocked_total"] else "registered_scope_exhausted")
    status = "continue" if state["actionable_total"] else "review_frontier" if not frontier_ready \
        else "blocked" if state["blocked_total"] else "ready_to_finalize"
    next_action = "plan.next" if state["actionable_total"] else "plan.checkpoint" if not frontier_ready else "plan.finalize"
    if state["no_progress_rounds"] >= 2 and state["actionable_total"]:
        status, reason, next_action = "stalled", "no_closure_progress", "plan.audit"
    if not inventory["operations"]:
        status, reason, next_action = "not_started", "inventory_missing", "surface.list"
    if finalization:
        status, reason, next_action = "finalized", finalization["reason"], "report.build"
    return {"contract_version": 1, "continue_required": finalization is None,
            "can_finalize": can_finalize, "can_claim_complete": bool(finalization and finalization.get("can_claim_complete")),
            "state": status, "reason_code": reason, "next_action": next_action,
            **{key: state[key] for key in ("snapshot_id", "progress_id", "checkpoint_id", "ready_total", "review_total",
                "blocked_total", "actionable_total", "unresolved_total", "no_progress_rounds", "frontier_rounds")},
            "frontier_review_required": not frontier_ready,
            "finalization_id": finalization["id"] if finalization else None,
            "coverage_status": completion["status"], "registered_scope_only": True}


def checkpoint(project, args):
    from . import completeness, engine

    label = _text(args.get("label", "Assessment round checkpoint"), "label", 200)
    with project.transaction():
        evaluated = engine.evaluate_coverage(project)
        inventory = completeness._inventory(project, evaluated)
        current = evaluated["continuation"]
        previous = project.list("checkpoint")
        frontier = _frontier_review(project, args["frontier_review"], inventory) if "frontier_review" in args else None
        record = {"id": project.id("CP"), "label": label, "created_at": now(),
                  "snapshot_id": current["snapshot_id"], "progress_id": current["progress_id"],
                  "previous_checkpoint_id": previous[-1]["id"] if previous else None,
                  "progress_changed": bool(previous and previous[-1].get("progress_id") != current["progress_id"]),
                  "remaining": {key: current[key] for key in ("ready_total", "review_total", "blocked_total", "unresolved_total")},
                  "completion_status": evaluated["completion"]["status"], "frontier_review": frontier}
        project.put("checkpoint", record, create_only=True)
        project.event("plan.checkpoint", {"checkpoint_id": record["id"], "progress_changed": record["progress_changed"]})
        updated = engine.evaluate_coverage(project)["continuation"]
    return _public(project, {"checkpoint": record, "continuation": updated, "requests_sent": 0,
            "note": "Repeated calls or captures are not closure progress. Review existing evidence or change the bounded hypothesis; never auto-replay uncertain writes."})


def _write_contexts(project, kind, item):
    from . import engine

    if kind not in {"unreconciled_run", "failed_partial_tool", "orphan_browser_visit"}:
        return []
    if kind == "orphan_browser_visit":
        if item.get("write_requests") or item.get("write_authorized"):
            return [{"unknown": True}]
        try:
            raw = project.read_artifact(item)
            network = raw.get("network") or []
            if any(isinstance(row, dict) and (row.get("write") or
                    str((row.get("request") or row).get("method", "GET")).upper() not in {"GET", "HEAD", "OPTIONS"})
                   for row in network):
                return [{"unknown": True}]
        except (EngineError, OSError, ValueError, TypeError, KeyError, AttributeError):
            return [{"unknown": True}]
        return []
    if item.get("kind") == "scenario":
        contexts = (item.get("preflight") or {}).get("steps") or []
        if not contexts or any(not isinstance(row, dict) or not row.get("method") for row in contexts):
            return [{"unknown": True}]
    else:
        operation = project.get("operation", item.get("operation_id"), required=False) or {}
        method = item.get("method") or item.get("request_method") or operation.get("method")
        if not method:
            return [{"unknown": True}]
        context = dict(item, method=method)
        if item.get("evidence_id") and not context.get("resource_id"):
            evidence = project.get("evidence", item["evidence_id"], required=False) or {}
            context.update({key: evidence.get(key) for key in ("resource_id", "resource_signature", "actor_id", "actor_signature")})
        contexts = [context]
    return [row for row in contexts if row["method"] not in {"GET", "HEAD", "OPTIONS"}
            or row.get("effect") == "test_resource_write"]


def _readback_bindings(project, item, contexts, support, bindings):
    from . import engine
    from .transport import pointer, response_json

    if not isinstance(bindings, list) or not 1 <= len(bindings) <= 25 or any(not isinstance(row, dict) for row in bindings):
        raise EngineError("reconciliation_evidence", "Uncertain writes require explicit readback_bindings and later read-only business-state evidence")
    if any(row.get("unknown") or not row.get("resource_id") or not row.get("resource_signature") for row in contexts):
        raise EngineError("reconciliation_context", "This legacy, actor-only or browser write lacks a captured fixture context; keep it blocked, never replay to archive it")
    required = {row["resource_id"] for row in contexts}
    if {row.get("source_resource_id") for row in bindings} != required or len(bindings) != len(required):
        raise EngineError("reconciliation_evidence", "Bind every uncertain source fixture exactly once")
    result = []
    for binding in bindings:
        relation = _text(binding.get("relation"), "readback relation", 200)
        source = project.get("resource", binding["source_resource_id"])
        read_resource = project.get("resource", binding.get("resource_id"))
        context_rows = [row for row in contexts if row["resource_id"] == source["id"]]
        if any(row["resource_signature"] != engine.resource_signature(source) for row in context_rows) \
                or any(source.get(key) != read_resource.get(key) for key in ("owner_actor_id", "tenant_id", "external_id")):
            raise EngineError("reconciliation_context", "Readback must preserve the captured fixture's owner, tenant and exact external ID")
        selector = binding.get("selector")
        if not isinstance(selector, str) or not selector.startswith("/") or len(selector) > 512 \
                or "expected" not in binding or selector.rsplit("/", 1)[-1].lower() in {
                    "success", "ok", "message", "error", "code", "status", "statuscode", "timestamp", "nonce",
                    "requestid", "traceid", "correlationid", "duration", "elapsedms"}:
            raise EngineError("reconciliation_evidence", "Declare an expected concrete business state, not merely a later 200/ok flag")
        matches = []
        for evidence, artifact in support:
            operation = project.get("operation", evidence["operation_id"])
            if evidence.get("resource_id") != read_resource["id"]:
                continue
            if operation["method"] not in {"GET", "HEAD", "OPTIONS"} or artifact["request"]["method"] not in {"GET", "HEAD", "OPTIONS"} \
                    or not 200 <= artifact["response"]["status"] < 300 \
                    or any(evidence.get("actor_id") != row.get("actor_id") for row in context_rows) \
                    or engine.stamp(artifact["started_at"]) < engine.stamp(item.get("finished_at") or item["started_at"]):
                continue
            try:
                if pointer(response_json(artifact), selector) == binding["expected"]:
                    matches.append(evidence["id"])
            except EngineError:
                continue
        if not matches:
            raise EngineError("reconciliation_evidence", "No later same-identity, bound read-only observation establishes the declared fixture state")
        result.append({"source_resource_id": source["id"], "resource_id": read_resource["id"], "relation": relation,
                       "selector": selector, "expected": binding["expected"], "evidence_ids": matches})
    return result


def review(project, args):
    from . import completeness, engine

    identity = _text(args.get("checklist_id"), "checklist_id", 100)
    reviewer, reason = _text(args.get("reviewer"), "reviewer", 200), _text(args.get("reason"), "reason")
    status = args.get("status")
    if not isinstance(status, str) or status not in {"reviewed", "blocked", "reopen"}:
        raise EngineError("closure_review", "status must be reviewed, blocked or reopen")
    support_ids = _ids(args.get("evidence_ids", []), "evidence_ids")
    with project.transaction():
        evaluated = engine.evaluate_coverage(project)
        inventory = completeness._inventory(project, evaluated)
        checklist = {row["id"]: row for row in completeness._checklist(inventory)}
        row = checklist.get(identity)
        if row is None and status == "reopen":
            prior = next((item for item in reversed(project.list("closure_review")) if item["checklist_id"] == identity), None)
            if prior:
                row = {"kind": prior["kind"], "source_id": prior["source_id"]}
        if not row or row["kind"] not in REVIEW_LISTS:
            raise EngineError("closure_review", "Only administrative checklist items may be reviewed; use typed assessment/candidate/page actions for substantive work")
        kind = row["kind"]
        field = {"unassessed_observation": "evidence_id", "failed_partial_tool": "run_id",
                 "unreconciled_run": "run_id", "orphan_browser_visit": "page_visit_id", "unlinked_analyst_finding": "finding_id"}[kind]
        source_id = row.get(field, row.get("source_id"))
        item = project.get(SOURCE_KINDS[kind], source_id)
        if kind == "unreconciled_run" and item.get("status") not in {"interrupted", "failed"}:
            raise EngineError("run_active", "A running run cannot be reconciled away; recover a genuinely stale run and inspect its effects first")
        if kind == "unlinked_analyst_finding" and status == "reviewed":
            raise EngineError("analyst_obligation", "Analyst text cannot close a security obligation; bind a supported proof or leave this limitation blocked")
        if kind in {"failed_partial_tool", "unreconciled_run"} and item.get("adapter") == "tscanplus" and status == "reviewed" \
                and completeness._tscanplus_incomplete(item):
            raise EngineError("remote_execution_unverified", "Caller text cannot verify remote cancellation or missing scanner results; retain blocked with explicit limits, never replay or clear the shared server")
        if kind == "orphan_browser_visit" and status != "reopen":
            try:
                from .browser import _verified_visit
                _verified_visit(project, item["id"], item["url"])
            except (EngineError, OSError, ValueError, TypeError, KeyError):
                pass
            else:
                raise EngineError("page_adoption_required", "A valid successful browser observation must use page.adopt, not administrative dismissal")
        contexts = _write_contexts(project, kind, item)
        if status == "reviewed" and any(row.get("state") or row.get("declared")
                and row.get("actual") != row["declared"] for row in _material(project, item)):
            raise EngineError("review_material", "Missing, changed or over-budget material must remain an explicit blocked review, not verified archive")
        support, observations = [], []
        for evidence_id in support_ids:
            evidence, artifact = engine.verify_current_evidence(project, evidence_id)
            if not contexts and item.get("operation_id") and evidence["operation_id"] != item["operation_id"]:
                raise EngineError("evidence_binding", "Reconciliation evidence must match this item's operation")
            support.append(_evidence_reference(project, evidence_id))
            observations.append((evidence, artifact))
        bindings = _readback_bindings(project, item, contexts, observations, args.get("readback_bindings")) \
            if status == "reviewed" and contexts else []
        if kind == "unassessed_observation" and status == "reviewed":
            engine.verify_current_evidence(project, item["id"])
        record = {"id": project.id("CR"), "checklist_id": identity, "kind": kind, "source_id": source_id,
                  "source_signature": _source_signature(project, kind, item), "support_signature": _digest("SP", support),
                  "status": status, "reviewer": reviewer, "reason": reason, "evidence_ids": support_ids,
                  "readback_bindings": bindings, "created_at": now()}
        project.put("closure_review", record, create_only=True)
        project.event("plan.review", {"review_id": record["id"], "checklist_id": identity, "status": status})
        updated = engine.evaluate_coverage(project)
    return _public(project, {"review": record, "continuation": updated["continuation"], "completion": updated["completion"],
            "requests_sent": 0, "security_obligations_closed": 0})


def finalize(project, args):
    from . import completeness, engine

    checkpoint_id = _text(args.get("checkpoint_id"), "checkpoint_id", 100)
    reason = args.get("reason")
    if not isinstance(reason, str) or reason not in STOP_REASONS:
        raise EngineError("stop_reason", "reason must be completed, blocked, budget_exhausted, user_stop or authorization_boundary")
    explanation = _text(args.get("explanation"), "explanation")
    reviewer = _text(args.get("reviewer"), "reviewer", 200)
    with project.transaction():
        evaluated = engine.evaluate_coverage(project)
        current = evaluated["continuation"]
        record = project.get("checkpoint", checkpoint_id)
        checkpoints = project.list("checkpoint")
        if not checkpoints or checkpoints[-1]["id"] != checkpoint_id or record["snapshot_id"] != current["snapshot_id"]:
            raise EngineError("checkpoint_stale", "Create a current checkpoint before stopping; scope, evidence or task state changed",
                              {"continuation": current, "next_action": "plan.checkpoint"})
        if reason in {"completed", "blocked"}:
            if current["actionable_total"]:
                raise EngineError("continue_required", "Ready or review work remains; a report or one blocked proof channel is not a finish line",
                                  {"continuation": current, "next_action": "plan.next"})
            if not current["can_finalize"]:
                raise EngineError("frontier_review_required", "Two current, evidence-bound discovery/category/page review rounds are required for bounded exhaustion",
                                  {"continuation": current, "next_action": "plan.checkpoint"})
        inventory = completeness._inventory(project, evaluated)
        frontier_complete = bool(record.get("frontier_review", {}).get("complete")) if record.get("frontier_review") else False
        if reason == "completed" and (evaluated["completion"]["status"] != "complete"
                or current["blocked_total"] or not frontier_complete):
            raise EngineError("assessment_partial", "Unresolved blockers or applicability boundaries require an explicitly partial stop, not completed",
                              {"continuation": current, "next_action": "plan.audit"})
        if reason == "blocked" and not current["blocked_total"] and frontier_complete \
                and evaluated["completion"]["status"] == "complete":
            raise EngineError("stop_reason", "No blocked work remains; use completed for this registered scope")
        if reason == "completed" and not inventory["operations"]:
            raise EngineError("assessment_not_started", "An empty project is not a completed assessment")
        stop = {"id": project.id("FN"), "checkpoint_id": checkpoint_id, "snapshot_id": current["snapshot_id"],
                "reason": reason, "explanation": explanation, "reviewer": reviewer, "created_at": now(),
                "completion_status": evaluated["completion"]["status"], "can_claim_complete": reason == "completed",
                "frontier_reviewed": current["frontier_rounds"] >= MIN_FRONTIER_ROUNDS,
                "reason_basis": "engine_gate" if reason == "completed" else "projected_declared_blockers" if reason == "blocked"
                                else "caller_declared_external_constraint",
                "external_constraint_verified": False, "blocker_facts_verified": False,
                "remaining": {key: current[key] for key in ("ready_total", "review_total", "blocked_total", "unresolved_total")}}
        project.put("finalization", stop, create_only=True)
        project.event("plan.finalized", {"finalization_id": stop["id"], "reason": reason, "can_claim_complete": stop["can_claim_complete"]})
        updated = engine.evaluate_coverage(project)["continuation"]
    return _public(project, {"finalization": stop, "continuation": updated, "requests_sent": 0,
            "note": "This is a snapshot-bound registered-scope stop record, not proof that unknown surfaces or vulnerabilities do not exist. External exits and blocker facts are caller declarations, not authenticated host events."})


def require_finalization(project, finalization_id, evaluated=None):
    from . import engine

    evaluated = evaluated if evaluated is not None else engine.evaluate_coverage(project)
    current = evaluated["continuation"]
    if not isinstance(finalization_id, str) or not finalization_id:
        raise EngineError("finalization_required", "A final report needs a current plan.finalize record; draft reports do not authorize stopping",
                          {"continuation": current, "next_action": "plan.checkpoint"})
    stop = project.get("finalization", finalization_id, required=False)
    if not stop:
        raise EngineError("finalization_required", "Unknown finalization record in this project", {"continuation": current})
    if stop.get("snapshot_id") != current["snapshot_id"] or current.get("finalization_id") != stop["id"]:
        raise EngineError("finalization_stale", "The project changed after finalization; continue work and create a new stop record",
                          {"continuation": current, "next_action": "plan.next"})
    if stop.get("can_claim_complete") and (current["actionable_total"] or current["blocked_total"]
            or evaluated["completion"]["status"] != "complete"):
        raise EngineError("continue_required", "Current coverage cannot support a completed final report", {"continuation": current})
    return stop
