"""Persisted continuation and evidence-bound exhaustion gates; never execute requests."""
from __future__ import annotations

from collections import Counter
import hashlib

from .store import EngineError, canonical, contained, now


ALL_FAMILIES = ("access_control", "sql_injection", "xss", "ssrf", "xxe", "path_traversal",
                "command_injection", "template_injection", "deserialization", "file_upload",
                "business_logic", "generic")
MIN_FRONTIER_ROUNDS = 2
MAX_PARAMETER_PROGRESS_KEYS = 50000
MAX_SEMANTIC_PROGRESS_FACTS = 12000
STOP_REASONS = {"completed"}
REJECTED_STOP_REASONS = {"blocked", "budget_exhausted", "user_stop", "authorization_boundary"}
STOP_POLICY = "exhaustion_only"
STOP_POLICY_VERSION = 1
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
    from .browser import learn_redaction_context
    from .engine import credential_header_names
    from .reproduction import Redactor, _learn_header

    redactor = Redactor()
    unavailable = learn_redaction_context(project, redactor)
    redactor.learn(value)
    for session in project.list("session"):
        for name in credential_header_names(session):
            secret = session.get("headers", {}).get(name)
            if secret is not None:
                redactor.slot(secret, "SESSION_CREDENTIAL")
                _learn_header(redactor, name, secret)
    public = redactor.metadata(value)
    if isinstance(value, dict) and isinstance(public, dict):
        # Continuation contains generated handles, enums and counts, never caller
        # prose. A fill value coinciding with a code must not corrupt its contract.
        if isinstance(value.get("continuation"), dict):
            public["continuation"] = dict(value["continuation"])
        if isinstance(value.get("completion"), dict):
            public["completion"] = dict(value["completion"])
        with project._lock:
            known_ids = {row[0] for row in project.connection.execute("SELECT id FROM entities").fetchall()}

        def restore_handles(original, sanitized):
            if isinstance(original, dict) and isinstance(sanitized, dict):
                for key, item in original.items():
                    if key not in sanitized:
                        continue
                    if (key == "id" or key.endswith("_id")) and isinstance(item, str) and item in known_ids:
                        sanitized[key] = item
                    elif key.endswith("_ids") and isinstance(item, list) and all(
                            isinstance(identity, str) and identity in known_ids for identity in item):
                        sanitized[key] = list(item)
                    elif key == "status" and isinstance(item, str) and item in {
                            "reviewed", "blocked", "reopen", "planned", "completed", "not_applicable", "api_only"}:
                        sanitized[key] = item
                    elif key == "test_family" and isinstance(item, str) and item in ALL_FAMILIES:
                        sanitized[key] = item
                    elif key == "completion_status" and isinstance(item, str) and item in {"complete", "partial", "not_started"}:
                        sanitized[key] = item
                    else:
                        restore_handles(item, sanitized[key])
            elif isinstance(original, list) and isinstance(sanitized, list):
                for item, safe_item in zip(original, sanitized):
                    restore_handles(item, safe_item)

        restore_handles(value, public)
        if any(unavailable.values()):
            def omit_prose(node):
                if isinstance(node, dict):
                    for key, item in node.items():
                        if key in {"label", "reviewer", "explanation", "reason", "relation"} and isinstance(item, str):
                            node[key] = "[prose omitted: browser redaction context unavailable]"
                        else:
                            omit_prose(item)
                elif isinstance(node, list):
                    for item in node:
                        omit_prose(item)

            omit_prose(public)
            public["redaction_context_status"] = "unavailable"
            public["redaction_context_unavailable"] = unavailable
        if isinstance(value.get("finalization"), dict) and isinstance(public.get("finalization"), dict):
            for key, expected in (("reason", "completed"), ("reason_basis", "engine_gate"), ("stop_policy", STOP_POLICY)):
                if value["finalization"].get(key) == expected:
                    public["finalization"][key] = expected
    return public


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


def _review_prerequisites(project, kind, item, observations):
    from . import engine
    from .completeness import _tscanplus_incomplete

    missing = []
    for material in _material(project, item):
        if material.get("state"):
            missing.append("review_material_" + material["state"])
        elif material.get("declared") and material.get("actual") != material["declared"]:
            missing.append("review_material_changed")
    if kind == "unassessed_observation" and item.get("review_source_invalid"):
        missing.append("current_complete_http_observation")
    if kind == "unreconciled_run" and item.get("status") == "running":
        missing.append("terminal_or_genuinely_stale_run_checkpoint")
    if kind in {"failed_partial_tool", "unreconciled_run"} and item.get("adapter") == "tscanplus" \
            and _tscanplus_incomplete(item):
        missing.append("verified_remote_stop_and_complete_results")
    if kind == "orphan_browser_visit" or kind == "unreconciled_run" and item.get("kind") == "browser":
        try:
            raw = project.read_artifact(item) if item.get("artifact_path") else item
            if item.get("blocked_requests") or raw.get("blocked_requests") or raw.get("scope_error"):
                missing.append("resolved_explicit_browser_request_boundary")
            if raw.get("network_truncated"):
                missing.append("complete_browser_network_context")
        except (EngineError, OSError, ValueError, TypeError, AttributeError):
            missing.append("complete_browser_review_material")
    contexts = _write_contexts(project, kind, item)
    if not contexts:
        return list(dict.fromkeys(missing))
    if any(row.get("unknown") or not row.get("resource_id") or not row.get("resource_signature") for row in contexts):
        missing.append("captured_fixture_write_context")
        return list(dict.fromkeys(missing))
    # A current bound readback only enables offline inspection. The reviewer
    # must still supply and validate each actual business-state assertion.
    for identity in {row["resource_id"] for row in contexts}:
        source = project.get("resource", identity, required=False)
        bound = [row for row in contexts if row["resource_id"] == identity]
        if not source or any(row["resource_signature"] != engine.resource_signature(source) for row in bound):
            missing.append("unchanged_captured_fixture_context")
            continue
        available = False
        for evidence in observations:
            read_resource = project.get("resource", evidence.get("resource_id"), required=False)
            operation = project.get("operation", evidence.get("operation_id"), required=False)
            if not read_resource or not operation or operation["method"] not in {"GET", "HEAD", "OPTIONS"} \
                    or any(source.get(key) != read_resource.get(key) for key in ("owner_actor_id", "tenant_id", "external_id")) \
                    or any(evidence.get("actor_id") != row.get("actor_id") for row in bound):
                continue
            try:
                artifact = project.read_artifact(evidence)
                available = artifact["request"]["method"] in {"GET", "HEAD", "OPTIONS"} \
                    and 200 <= artifact["response"]["status"] < 300 \
                    and engine.stamp(artifact["started_at"]) >= engine.stamp(item.get("finished_at") or item["started_at"])
            except (EngineError, OSError, ValueError, TypeError, KeyError):
                continue
            if available:
                break
        if not available:
            missing.append("later_same_identity_fixture_bound_readback_to_inspect")
    return list(dict.fromkeys(missing))


def _review_archive_allowed(project, kind, item, review, prerequisites):
    from . import engine

    if prerequisites or kind == "unlinked_analyst_finding" \
            or kind == "orphan_browser_visit" and item.get("adopt_ready") \
            or kind == "unreconciled_run" and item.get("status") not in {"interrupted", "failed"}:
        return False
    try:
        contexts = _write_contexts(project, kind, item)
        if contexts:
            support = [engine.verify_current_evidence(project, identity) for identity in review.get("evidence_ids", [])]
            # A historical receipt must satisfy today's business-state gates,
            # not merely have intact bytes and a possible readback elsewhere.
            _readback_bindings(project, item, contexts, support, review.get("readback_bindings"))
        return True
    except (EngineError, OSError, ValueError, TypeError, KeyError, AttributeError):
        return False


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
    inventory["reviewed_admin"], inventory["blocked_reviews"], inventory["review_prerequisites"] = [], {}, {}
    for kind, key in REVIEW_LISTS.items():
        retained = []
        for item in inventory[key]:
            identity = _review_id(kind, item["id"])
            review = latest.get(identity)
            prerequisites = _review_prerequisites(project, kind, item, inventory["observations"])
            if review and _review_valid(project, review, item):
                remote_incomplete = kind in {"failed_partial_tool", "unreconciled_run"} \
                    and item.get("adapter") == "tscanplus" and _tscanplus_incomplete(item)
                if review["status"] == "reviewed" and kind != "unlinked_analyst_finding" \
                        and not remote_incomplete and _review_archive_allowed(project, kind, item, review, prerequisites):
                    inventory["reviewed_admin"].append(review)
                    continue
                if review["status"] == "blocked":
                    inventory["blocked_reviews"][identity] = review
            inventory["review_prerequisites"][identity] = prerequisites
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


def _completed_family(project, family, inventory, cache):
    from .completeness import _status, obligation_family

    def incomplete(message):
        return EngineError("frontier_categories", family + ": " + message,
                           {"test_family": family, "next_action": "plan.audit", "help_action": "action.help",
                            "help_input": {"name": "plan.checkpoint"}})

    items = [item for item in inventory["obligations"] if item["kind"] != "baseline"
             and obligation_family(item, inventory["operations"].get(item["operation_id"], {})) == family]
    if not items or any(_status(item, inventory["gaps"]) != "evaluated" for item in items):
        raise incomplete("completed requires nonempty, currently evaluated security obligations; inspect plan.audit")
    if any(row.get("test_family") == family for key in ("scope_reductions", "consumer_requirements")
           for row in inventory.get(key, [])):
        raise incomplete("completed cannot hide a scope-reduction or untraced-consumer review")
    decisions = []
    for item in sorted(items, key=lambda row: row["id"]):
        decision = inventory["decisions"].get(item.get("decision_id"))
        if not decision or decision.get("obligation_id") != item["id"]:
            raise incomplete("completed requires an accepted decision for every current obligation")
        references = {"evidence_ids": decision.get("evidence_ids", []), "page_visit_ids": []}
        visit_id = (decision.get("runtime") or {}).get("visit_id")
        if visit_id:
            references["page_visit_ids"].append(visit_id)
        decisions.append({"obligation_id": item["id"], "decision": decision,
                          "references": _references(project, references, required=True, cache=cache)})
    # Bind completion to the accepted experiments, not a caller's label or an
    # unrelated successful response. Revalidation reopens stale checkpoints.
    return _digest("FC", decisions)


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
        if status not in {"planned", "completed", "not_applicable", "blocked"}:
            raise EngineError("frontier_categories", "Category status must be planned, completed, not_applicable or blocked")
        if status == "planned" and family not in planned:
            raise EngineError("frontier_categories", family + ": planned requires actual current security-test obligations; input_review is not testing", {
                "test_family": family, "next_action": "plan.audit", "help_input": {"name": "surface.declare_consumer"}})
        if status == "not_applicable" and family in planned:
            raise EngineError("frontier_categories", family + ": not_applicable cannot exclude an existing family's test obligations", {
                "test_family": family, "next_action": "plan.audit", "help_input": {"name": "plan.checkpoint"}})
        row = {"test_family": family, "status": status, "reason": _text(declaration.get("reason"), family + ".reason"),
               "evidence_ids": _ids(declaration.get("evidence_ids", []), "evidence_ids"),
               "page_visit_ids": _ids(declaration.get("page_visit_ids", []), "page_visit_ids")}
        reference_signatures[family] = _references(project, row, required=status == "not_applicable", cache=cache)
        if status == "completed":
            reference_signatures[family] = _digest("FP", {
                "declaration": reference_signatures[family],
                "evaluated_family": _completed_family(project, family, inventory, cache)})
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


def _semantic_projection(project, inventory, rows):
    """Separate evidence-backed closure and concrete preparation from receipts.

    The original PR stays a state fingerprint for compatible readers. These
    private, bounded hashes track achievements; caller disposition, administrative
    review prose and failed/inconclusive decisions cannot mint an achievement.
    """
    from . import engine

    security, preparation = set(), set()

    def fact(target, kind, value):
        target.add(_digest("SF", {"kind": kind, "value": value}))

    for decision in inventory["valid_decisions"]:
        oracle = decision.get("oracle") or {}
        if decision.get("outcome") in {"confirmed", "refuted"} and oracle.get("type") != "analyst_review":
            fact(security, "decision", {key: decision.get(key) for key in
                 ("obligation_id", "operation_id", "outcome", "oracle", "proof")})
    for finding in inventory["current_findings"]:
        decision = inventory["decisions"].get(finding.get("decision_id"), {})
        # A real unbound runtime finding retains its observed browser proof, but
        # an opaque analyst narrative is not typed security closure.
        if (decision.get("oracle") or {}).get("type") != "analyst_review" or decision.get("runtime"):
            fact(security, "finding", {key: decision.get(key) for key in
                 ("obligation_id", "operation_id", "outcome", "oracle", "proof", "runtime")})

    for operation in rows["operation"]:
        fact(preparation, "operation", {key: operation.get(key) for key in
             ("id", "url", "method", "protocol", "auth", "allowed_roles", "ownership", "state_scope", "content_type")})
        for entry in operation.get("inputs", []):
            fields = ("location", "selector", "schema_branch", "schema_type", "required", "consumer",
                      "array_template", "schema_locator")
            context = {"operation_id": operation["id"], **{key: entry.get(key) for key in fields}}
            if str(entry.get("consumer") or "unknown").strip().lower() not in {"unknown", "other"}:
                context["test_families"] = entry.get("test_families")
            fact(preparation, "input", context)
    for item in inventory["obligations"]:
        fact(preparation, "hypothesis", {key: item.get(key) for key in
             ("operation_id", "kind", "input_location", "input_selector", "schema_branch", "test_family",
              "actor_id", "baseline_actor_id", "resource_id", "tenant_boundary")})

    for session in rows["session"]:
        try:
            actor = engine.session_valid(project, session)
        except (EngineError, OSError, ValueError, TypeError, KeyError):
            continue
        assertion = session.get("verification_assertion") or {}
        # Another attestation ID is traffic, not a new principal or capability.
        # session_valid has checked nonempty role/tenant declarations against
        # the original server profile, including its supported selector fallback.
        # An empty tenant with only a caller-supplied pointer proves no membership.
        fact(preparation, "verified_identity", {"id": session["id"], "generation": session.get("generation"),
             "actor_signature": engine.actor_signature(actor), "credential_signature": session.get("credential_signature"),
             "roles_verified": bool(actor.get("roles")) or bool(assertion.get("roles_selector")),
             "tenant_verified": bool(actor.get("tenant_id"))})
    referenced_resources = {item.get("resource_id") for item in inventory["obligations"]}
    for resource in rows["resource"]:
        if resource["id"] in referenced_resources:
            fact(preparation, "fixture", {"id": resource["id"], "signature": engine.resource_signature(resource)})

    coverage = inventory["page_coverage"]
    bad_pages = {item["page_id"] for item in coverage["unvisited"]}
    bad_functions = {item["function_id"] for item in coverage["untriggered"]}
    for page in rows["page"]:
        if page["id"] not in bad_pages:
            fact(preparation, "visited_page", {"id": page["id"], "url": page["url"]})
        for function in page.get("functions", []):
            if function["id"] not in bad_functions:
                fact(preparation, "triggered_function", {"page_id": page["id"],
                     **{key: function.get(key) for key in ("id", "trigger", "apis")}})
    for relation in inventory.get("validated_browser_adoptions", []):
        fact(preparation, "browser_adoption", {key: relation.get(key) for key in
             ("page_id", "url", "page_visit_id", "sha256", "source", "actor_id", "session_id", "session_generation")})
    for candidate in rows["candidate"]:
        fact(preparation, "candidate_context", {key: candidate.get(key) for key in ("id", "kind", "operation_id")}
             | {"input_binding": {key: (candidate.get("link") or {}).get(key)
                                  for key in ("input_location", "input_selector", "schema_branch")}})

    # The queue retains actual prerequisites under a caller-only blocked wrapper.
    # Administrative blocked/open flags themselves are deliberately absent.
    missing = {item["gap_id"]: sorted(set(item.get("missing_prerequisites", []))
               - {"offline_obligation_blocker_reconciliation"}) for item in inventory["queue"]}
    missing.update({identity: sorted(set(values)) for identity, values in
                    inventory.get("review_prerequisites", {}).items()})
    complete = len(security) + len(preparation) <= MAX_SEMANTIC_PROGRESS_FACTS \
        and len(missing) <= MAX_SEMANTIC_PROGRESS_FACTS
    return {"version": 1, "complete": complete,
            "security_facts": sorted(security)[:MAX_SEMANTIC_PROGRESS_FACTS],
            "preparation_facts": sorted(preparation)[:max(0, MAX_SEMANTIC_PROGRESS_FACTS - len(security))],
            "missing_prerequisites": dict(sorted(missing.items())[:MAX_SEMANTIC_PROGRESS_FACTS])}


def _semantic_progress(project, inventory, rows, checkpoints):
    projection = _semantic_projection(project, inventory, rows)
    previous = checkpoints[-1] if checkpoints else {}
    prior = previous.get("semantic_progress")
    keys = ("security_facts", "preparation_facts")
    previous_id = previous.get("semantic_progress_id")
    valid_id = isinstance(previous_id, str) and len(previous_id) == 67 and previous_id.startswith("PR-") \
        and all(char in "0123456789abcdef" for char in previous_id[3:])
    # A limited projection cannot establish a new achievement or resurrect a
    # forgotten one. Finalization remains tied to the full current snapshot.
    if not projection["complete"] or isinstance(prior, dict) and prior.get("complete") is False:
        projection["complete"] = False
        return previous_id if valid_id else _digest("PR", {"semantic_version": 1, "projection_limited": True}), projection, False
    valid = isinstance(prior, dict) and type(prior.get("version")) is int and prior["version"] == 1 and prior.get("complete") is True \
        and isinstance(prior.get("missing_prerequisites"), dict) \
        and len(prior["missing_prerequisites"]) <= MAX_SEMANTIC_PROGRESS_FACTS \
        and all(isinstance(identity, str) and isinstance(values, list) and len(values) <= 100
                and all(isinstance(value, str) and len(value) <= 200 for value in values)
                for identity, values in prior["missing_prerequisites"].items()) \
        and all(isinstance(prior.get(key), list) and len(prior[key]) <= MAX_SEMANTIC_PROGRESS_FACTS
                and all(isinstance(value, str) and len(value) == 67 and value.startswith("SF-")
                        and all(char in "0123456789abcdef" for char in value[3:]) for value in prior[key])
                for key in keys) \
        and sum(len(prior[key]) for key in keys) <= MAX_SEMANTIC_PROGRESS_FACTS and valid_id
    if not valid:
        return _digest("PR", {"semantic_version": 1, "baseline": projection}), projection, False

    added = {key: sorted(set(projection[key]) - set(prior[key])) for key in keys}
    resolved = {identity: sorted(set(prior["missing_prerequisites"].get(identity, [])) - set(values))
                for identity, values in projection["missing_prerequisites"].items()
                if isinstance(prior["missing_prerequisites"].get(identity), list)}
    resolved = {identity: values for identity, values in resolved.items() if values}
    advanced = any(added.values()) or bool(resolved)
    progress = _digest("PR", {"semantic_version": 1, "previous": previous["semantic_progress_id"],
                       "added": added, "resolved_prerequisites": resolved}) if advanced else previous["semantic_progress_id"]
    # Preserve seen achievements across metadata changes and reversals. Restoring
    # a genuinely lost prerequisite is still a fresh improvement; caller prose
    # does not alter the objective missing-prerequisite map above.
    for key in keys:
        projection[key] = sorted(set(prior[key]) | set(projection[key]))
    if sum(len(projection[key]) for key in keys) > MAX_SEMANTIC_PROGRESS_FACTS:
        projection["complete"] = False
        projection["security_facts"] = projection["security_facts"][:MAX_SEMANTIC_PROGRESS_FACTS]
        projection["preparation_facts"] = projection["preparation_facts"][:max(0,
            MAX_SEMANTIC_PROGRESS_FACTS - len(projection["security_facts"]))]
        return previous["semantic_progress_id"], projection, False
    return progress, projection, advanced


def _state(project, evaluated, inventory, completion):
    from .completeness import _checklist
    from .workflow import queue_inventory

    queue = inventory.get("queue")
    if queue is None:
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
    snapshot_completion = dict(completion)
    # Empty derived review counters extend the public schema, not the material
    # snapshot. Keep genuinely closed legacy checkpoints usable after upgrade.
    for key in ("applicability_review_total", "scope_reduction_review_total"):
        if snapshot_completion.get(key) == 0:
            snapshot_completion.pop(key, None)
    snapshot = _digest("CS", {"config": project.config, "rows": rows, "material": material, "validity": validity,
                               "completion": snapshot_completion})
    # Raw captures and repeated plan/tool calls deliberately do not count as progress.
    bad_pages = {row["page_id"] for row in inventory["page_coverage"]["unvisited"]}
    bad_functions = {row["function_id"] for row in inventory["page_coverage"]["untriggered"]}
    unresolved_candidates = {row["id"] for row in inventory["candidates"]}
    progress = _digest("PR", {
        "operations": [{key: row.get(key) for key in ("id", "url", "method", "protocol", "auth", "allowed_roles",
            "ownership", "state_scope", "content_type", "inputs", "ownership_sampling")} for row in rows["operation"]],
        "pages": [{"id": row["id"], "url": row["url"], "visited": row["id"] not in bad_pages,
                   "functions": [{key: function.get(key) for key in ("id", "trigger", "apis")}
                                 | {"triggered": function["id"] not in bad_functions}
                                 for function in row.get("functions", [])]} for row in rows["page"]],
        "candidates": [{key: row.get(key) for key in ("id", "kind", "status", "operation_id")}
                       | {"status": "unverified" if row.get("status") == "dismissed" and row["id"] in unresolved_candidates
                                      else row.get("status")}
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
    semantic_progress, _, _ = _semantic_progress(project, inventory, rows, checkpoints)
    no_progress = 0
    for row in reversed(checkpoints):
        if row.get("semantic_progress_id", row.get("progress_id")) != semantic_progress:
            break
        no_progress += 1
    no_progress = max(0, no_progress - 1)
    candidates = [row for row in checkpoints if row.get("snapshot_id") == snapshot and row.get("frontier_review")][-MIN_FRONTIER_ROUNDS:]
    cache = {}
    frontier = [row for row in candidates if isinstance(row["frontier_review"], dict)
                and row["frontier_review"].get("complete") is True
                and _valid_frontier(project, row, inventory, cache)]
    unresolved = len(queue) + len(extras)
    return {"snapshot_id": snapshot, "progress_id": progress, "semantic_progress_id": semantic_progress,
            "ready_total": ready, "review_total": review,
            "blocked_total": blocked, "actionable_total": ready + review, "unresolved_total": unresolved,
            "applicability_review_total": len(inventory.get("applicability_reviews", [])),
            "scope_reduction_review_total": len(inventory.get("scope_reductions", [])) + len(inventory.get("consumer_requirements", [])),
            "no_progress_rounds": no_progress, "checkpoint_id": checkpoints[-1]["id"] if checkpoints else None,
            "frontier_rounds": len(frontier), "frontier_complete": bool(frontier and frontier[-1]["frontier_review"]["complete"]),
            "current_checkpoint": bool(checkpoints and checkpoints[-1].get("snapshot_id") == snapshot),
            "current_frontier": bool(frontier and checkpoints and frontier[-1]["id"] == checkpoints[-1]["id"]),
            "checkpoints": checkpoints}


def _exhausted(state, completion, has_operations):
    """One predicate governs the advertised gate, stop records and final reports."""
    return bool(has_operations and completion.get("status") == "complete"
        and not state["actionable_total"] and not state["blocked_total"] and not state["unresolved_total"]
        and not state.get("applicability_review_total", 0)
        and not state.get("scope_reduction_review_total", 0)
        and state["frontier_rounds"] >= MIN_FRONTIER_ROUNDS and state["frontier_complete"]
        and state["current_checkpoint"] and state["current_frontier"])


def _valid_stop(stop, state, can_finalize):
    if not can_finalize or not stop or stop.get("reason") != "completed" \
            or stop.get("can_claim_complete") is not True or stop.get("completion_status") != "complete" \
            or stop.get("frontier_reviewed") is not True or stop.get("reason_basis") != "engine_gate" \
            or stop.get("snapshot_id") != state["snapshot_id"] or stop.get("checkpoint_id") != state["checkpoint_id"]:
        return False
    if "automatic_stop_allowed" in stop and stop["automatic_stop_allowed"] is not True:
        return False
    # Revalidate legacy completed receipts against actual current work, not their
    # labels. Legacy partial receipts never acquire exhaustion permission.
    if "stop_policy" in stop or "stop_policy_version" in stop:
        if stop.get("stop_policy") != STOP_POLICY or type(stop.get("stop_policy_version")) is not int \
                or stop["stop_policy_version"] != STOP_POLICY_VERSION or stop.get("automatic_stop_allowed") is not True:
            return False
    remaining = stop.get("remaining")
    return isinstance(remaining, dict) and all(type(remaining.get(key)) is int and remaining[key] == 0
        for key in ("ready_total", "review_total", "blocked_total", "unresolved_total"))


def _recovery(current):
    return {"continuation": current, "next_action": current["next_action"],
            "stop_policy": STOP_POLICY, "checkpoint_action": "plan.checkpoint",
            "progress_export": {"action": "report.build", "input": {"stage": "draft"}}, "requests_sent": 0}


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
    frontier_ready = state["frontier_rounds"] >= MIN_FRONTIER_ROUNDS and state["frontier_complete"] \
        and state["current_checkpoint"] and state["current_frontier"]
    can_finalize = _exhausted(state, completion, bool(inventory["operations"]))
    latest_stop = next((row for row in reversed(project.list("finalization"))
                       if row.get("snapshot_id") == state["snapshot_id"]
                       and row.get("checkpoint_id") == state["checkpoint_id"]), None)
    finalization = latest_stop if _valid_stop(latest_stop, state, can_finalize) else None
    reason = ("work_remaining" if state["actionable_total"] else "blocked_preconditions" if state["blocked_total"]
              else "coverage_incomplete" if completion["status"] != "complete"
              else "frontier_review_required" if not frontier_ready else "registered_scope_exhausted")
    status = "continue" if state["actionable_total"] else "blocked" if state["blocked_total"] \
        else "review_coverage" if completion["status"] != "complete" \
        else "review_frontier" if not frontier_ready else "ready_to_finalize"
    next_action = "plan.next" if state["actionable_total"] else "plan.audit" if state["blocked_total"] \
        or completion["status"] != "complete" else "plan.checkpoint" if not frontier_ready else "plan.finalize"
    if state["no_progress_rounds"] >= 2 and state["actionable_total"]:
        status, reason, next_action = "stalled", "no_closure_progress", "plan.audit"
    if not inventory["operations"]:
        status, reason, next_action = "not_started", "inventory_missing", "surface.list"
    if finalization:
        status, reason, next_action = "finalized", finalization["reason"], "report.build"
    return {"contract_version": 2, "stop_policy": STOP_POLICY, "stop_policy_version": STOP_POLICY_VERSION,
            "continue_required": finalization is None, "automatic_stop_allowed": finalization is not None,
            "can_finalize": can_finalize, "can_claim_complete": finalization is not None,
            "legacy_finalization_ignored": latest_stop is not None and finalization is None,
            "applicability_review_total": state.get("applicability_review_total", 0),
            "scope_reduction_review_total": state.get("scope_reduction_review_total", 0),
            "state": status, "reason_code": reason, "next_action": next_action,
            **{key: state[key] for key in ("snapshot_id", "progress_id", "semantic_progress_id", "checkpoint_id", "ready_total", "review_total",
                "blocked_total", "actionable_total", "unresolved_total", "no_progress_rounds", "frontier_rounds")
                if key != "semantic_progress_id" or key in state},
            "frontier_review_required": not frontier_ready,
            "finalization_id": finalization["id"] if finalization else None,
            "coverage_status": completion["status"], "registered_scope_only": True}


def checkpoint(project, args):
    from . import completeness, engine, parameter_coverage

    label = _text(args.get("label", "Assessment round checkpoint"), "label", 200)
    with project.transaction():
        evaluated, inventory = completeness.evaluate_with_inventory(project)
        current = evaluated["continuation"]
        previous = project.list("checkpoint")
        _, semantic_projection, semantic_changed = _semantic_progress(project, inventory,
            {kind: project.list(kind) for kind in STATE_KINDS}, previous)
        frontier = _frontier_review(project, args["frontier_review"], inventory) if "frontier_review" in args else None
        parameters = parameter_coverage.snapshot(project, evaluated, inventory=inventory)
        projection = parameter_coverage.progress(project, evaluated, inventory=inventory)
        tested_complete = parameters["summary"]["cell_total"] <= MAX_PARAMETER_PROGRESS_KEYS
        variant_complete = tested_complete and parameters["summary"]["observations_limited_total"] == 0
        if not tested_complete:
            projection = {key: [] for key in projection}
        elif not variant_complete:
            projection["variant_keys"] = []
        projection_complete = tested_complete and variant_complete
        projection.update(version=2, tested_complete=tested_complete, variant_complete=variant_complete)
        projection["complete"] = projection_complete
        prior_projection = previous[-1].get("parameter_progress") if previous else None
        prior_valid = isinstance(prior_projection, dict) and all(
            isinstance(prior_projection.get(key), list) and len(prior_projection[key]) <= MAX_PARAMETER_PROGRESS_KEYS
            and all(isinstance(identity, str) and len(identity) == 27 and identity.startswith("PC-")
                    and all(char in "0123456789abcdef" for char in identity[3:]) for identity in prior_projection[key])
            and len(set(prior_projection[key])) == len(prior_projection[key])
            for key in ("tested_keys", "variant_keys", "consumer_review_keys"))
        versioned = prior_valid and type(prior_projection.get("version")) is int and prior_projection["version"] == 2 \
            and type(prior_projection.get("tested_complete")) is bool and type(prior_projection.get("variant_complete")) is bool \
            and prior_projection.get("complete") is (prior_projection["tested_complete"] and prior_projection["variant_complete"]) \
            and (prior_projection["tested_complete"] or not prior_projection["tested_keys"]) \
            and (prior_projection["variant_complete"] or not prior_projection["variant_keys"])
        # Legacy projections did not record observation-budget completeness.
        # Their typed keys remain usable, but variants need a new honest baseline.
        prior_tested = prior_valid and (versioned and prior_projection["tested_complete"] is True
            or "version" not in prior_projection and prior_projection.get("complete") is True)
        prior_variants = versioned and prior_projection["tested_complete"] is True and prior_projection["variant_complete"] is True
        tested_comparable, variants_comparable = tested_complete and prior_tested, variant_complete and prior_variants
        comparable = tested_comparable and variants_comparable
        newly_tested = set(projection["tested_keys"]) - set(prior_projection.get("tested_keys", [])) if tested_comparable else set()
        newly_varied = set(projection["variant_keys"]) - set(prior_projection.get("variant_keys", [])) if variants_comparable else set()
        reopened = set(prior_projection.get("tested_keys", [])) - set(projection["tested_keys"]) if tested_comparable else set()
        fields = ("id", "operation_id", "input_name", "input_location", "input_selector", "schema_branch", "test_family")

        def changes(keys):
            if not keys:
                return []
            return [{field: row.get(field) for field in fields} for row in parameters["items"] if row["id"] in keys][:10]

        delta = {"comparison_available": comparable, "projection_complete": projection_complete,
                 "tested_comparison_available": tested_comparable, "variant_comparison_available": variants_comparable,
                 "tested_projection_complete": tested_complete, "variant_projection_complete": variant_complete,
                 "newly_tested_total": len(newly_tested), "newly_observed_variants_total": len(newly_varied),
                 "reopened_total": len(reopened), "newly_tested": changes(newly_tested),
                 "newly_observed_variants": changes(newly_varied),
                 "items_truncated": len(newly_tested) > 10 or len(newly_varied) > 10,
                 "observation_is_testing": False}
        record = {"id": project.id("CP"), "label": label, "created_at": now(),
                  "snapshot_id": current["snapshot_id"], "progress_id": current["progress_id"],
                  "semantic_progress_id": current["semantic_progress_id"], "semantic_progress": semantic_projection,
                  "semantic_progress_changed": semantic_changed,
                  "previous_checkpoint_id": previous[-1]["id"] if previous else None,
                  "progress_changed": bool(previous and previous[-1].get("progress_id") != current["progress_id"]),
                  "remaining": {key: current[key] for key in ("ready_total", "review_total", "blocked_total", "unresolved_total")},
                  "completion_status": evaluated["completion"]["status"], "frontier_review": frontier,
                  "parameter_progress": projection, "parameter_delta": delta}
        project.put("checkpoint", record, create_only=True)
        project.event("plan.checkpoint", {"checkpoint_id": record["id"], "progress_changed": record["progress_changed"]})
        updated = engine.evaluate_coverage(project)["continuation"]
        public_record = {key: value for key, value in record.items() if key not in {"parameter_progress", "semantic_progress"}}
        from .publication import publish
        public = publish(project, "plan.checkpoint", {"checkpoint": public_record, "continuation": updated, "requests_sent": 0,
            "note": "Repeated calls or captures are not closure progress. Review existing evidence or change the bounded hypothesis; never auto-replay uncertain writes."})
    return public


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
    from .transport import pointer, response_json, json_equal, has_business_state, control_metadata_field

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
                or "expected" not in binding or control_metadata_field(selector.rsplit("/", 1)[-1].replace("~1", "/").replace("~0", "~")) \
                or not has_business_state(binding["expected"]):
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
                actual = pointer(response_json(artifact), selector)
                if has_business_state(actual) and json_equal(actual, binding["expected"]):
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
        if status == "reviewed" and set(inventory.get("review_prerequisites", {}).get(identity, [])) & {
                "resolved_explicit_browser_request_boundary", "complete_browser_network_context",
                "complete_browser_review_material"}:
            raise EngineError("browser_execution_blocked", "An explicit browser request boundary or incomplete browser context remains unresolved; preserve the limitation, never replay or archive it by text")
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
        public = _public(project, {"review": record, "continuation": updated["continuation"], "completion": updated["completion"],
            "requests_sent": 0, "security_obligations_closed": 0})
    return public


def finalize(project, args):
    from . import completeness, engine

    checkpoint_id = _text(args.get("checkpoint_id"), "checkpoint_id", 100)
    reason = args.get("reason")
    if not isinstance(reason, str) or reason not in STOP_REASONS:
        current = engine.evaluate_coverage(project)["continuation"]
        if isinstance(reason, str) and reason in REJECTED_STOP_REASONS:
            raise EngineError("stop_policy", "Only evidence-bound completed exhaustion permits automatic finalization. "
                              "Blockers, claimed budgets, user stops and authorization boundaries do not authorize a final stop. "
                              "Preserve a checkpoint and draft progress for an actual user or host interruption; do not invent a constraint.",
                              _recovery(current))
        raise EngineError("stop_reason", "reason must be completed; only evidence-bound exhaustion permits automatic finalization",
                          _recovery(current))
    if set(args) - {"checkpoint_id", "reason", "explanation", "reviewer", "project_id"}:
        raise EngineError("continuation_arguments", "plan.finalize accepts only checkpoint_id, reason, explanation and reviewer. "
                          "Model flags, policy overrides and purported host events cannot grant stop authority.",
                          _recovery(engine.evaluate_coverage(project)["continuation"]))
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
        if current["actionable_total"]:
            raise EngineError("continue_required", "Ready or review work remains; a report or one blocked proof channel is not a finish line",
                              _recovery(current))
        inventory = completeness._inventory(project, evaluated)
        frontier = record.get("frontier_review")
        frontier_complete = isinstance(frontier, dict) and frontier.get("complete") is True
        if not inventory["operations"]:
            raise EngineError("assessment_not_started", "An empty project is not a completed assessment", _recovery(current))
        if evaluated["completion"]["status"] != "complete" or current["blocked_total"] or current["unresolved_total"]:
            raise EngineError("assessment_partial", "Unresolved blockers and incomplete coverage are not exhaustion. "
                              "Repair or inspect prerequisites and retain draft progress; automatic partial finalization is forbidden.",
                              _recovery(current))
        if not frontier_complete or not current["can_finalize"]:
            raise EngineError("frontier_review_required", "Two current, complete, evidence-bound discovery/category/page review rounds "
                              "and the latest complete frontier are required for bounded exhaustion", _recovery(current))
        stop = {"id": project.id("FN"), "checkpoint_id": checkpoint_id, "snapshot_id": current["snapshot_id"],
                "reason": reason, "explanation": explanation, "reviewer": reviewer, "created_at": now(),
                "stop_policy": STOP_POLICY, "stop_policy_version": STOP_POLICY_VERSION,
                "completion_status": evaluated["completion"]["status"], "can_claim_complete": True,
                "automatic_stop_allowed": True,
                "frontier_reviewed": current["frontier_rounds"] >= MIN_FRONTIER_ROUNDS,
                "reason_basis": "engine_gate",
                "external_constraint_verified": False, "blocker_facts_verified": False,
                "remaining": {key: current[key] for key in ("ready_total", "review_total", "blocked_total", "unresolved_total")}}
        project.put("finalization", stop, create_only=True)
        project.event("plan.finalized", {"finalization_id": stop["id"], "reason": reason, "can_claim_complete": stop["can_claim_complete"]})
        updated = engine.evaluate_coverage(project)["continuation"]
        public = _public(project, {"finalization": stop, "continuation": updated, "requests_sent": 0,
            "note": "Only current evidence-bound registered-scope exhaustion permits this automatic final stop. "
                    "It is not proof that unknown surfaces or vulnerabilities do not exist. "
                    "User/host interruption retains checkpoint and draft progress, not permission to finalize early."})
    return public


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
    if stop.get("snapshot_id") != current["snapshot_id"] or stop.get("checkpoint_id") != current["checkpoint_id"]:
        raise EngineError("finalization_stale", "The project changed after finalization; continue work and create a new stop record",
                          _recovery(current))
    if not _valid_stop(stop, current, current["can_finalize"]):
        raise EngineError("finalization_policy", "This stop record does not satisfy the current evidence-bound exhaustion policy. "
                          "Legacy partial exits remain historical records, never final-report permission; preserve draft progress and continue.",
                          _recovery(current))
    if current.get("finalization_id") != stop["id"]:
        raise EngineError("finalization_stale", "Only the latest current eligible finalization may authorize a final report", _recovery(current))
    if current["continue_required"] is not False or current["automatic_stop_allowed"] is not True \
            or current["can_claim_complete"] is not True or evaluated["completion"]["status"] != "complete":
        raise EngineError("continue_required", "Current coverage cannot support a completed final report", _recovery(current))
    return stop
