"""Durable SQL query pages backed by the shared strong evaluator.

An unchanged, incomplete project uses advisory projections for ordinary reads.
Proof consumption, checkpoint/finalization and publication still call the strong
evaluator. A projection that could grant completion is refreshed strongly before
returning it, so cached artifacts never acquire completion authority.
"""
from __future__ import annotations

from collections import Counter, deque
import hashlib
import json
import os
from pathlib import Path
import time

from .store import EngineError, canonical, now

NAME = "v1_queries"
VERSION = 1


def _config_hash(project):
    return hashlib.sha256(canonical([project.config, project.get_metadata("storage_mode")]).encode("utf-8")).hexdigest()


def _material_locators(project):
    """Cache only locators, bound to the durable entity change watermark."""
    with project._lock:
        generation = project.generation()
        cached = getattr(project, "_query_material_locators", None)
        if cached is not None and cached[0] == generation:
            return cached[1], cached[2]
        paths = project.connection.execute("""
            SELECT json_extract(document,'$.artifact_path') AS path FROM entities
                WHERE json_type(document,'$.artifact_path')='text'
            UNION SELECT CASE WHEN file.type='object' THEN json_extract(file.value,'$.path') END
                FROM entities, json_each(entities.document,'$.files') AS file
                WHERE json_type(entities.document,'$.files')='array'
            UNION SELECT json_extract(document,'$.screenshot') FROM entities
                WHERE json_type(document,'$.screenshot')='text'
            UNION SELECT json_extract(document,'$.html') FROM entities
                WHERE json_type(document,'$.html')='text'
            UNION SELECT json_extract(document,'$.after_actions_html') FROM entities
                WHERE json_type(document,'$.after_actions_html')='text'
            ORDER BY 1
        """).fetchall()
        references, directories = [], {}
        for row in paths:
            relative = row[0]
            if not isinstance(relative, str) or not relative:
                continue
            index = len(references)
            references.append(relative)
            path = Path(relative)
            if not path.is_absolute() and ".." not in path.parts:
                full = project.base / path
                siblings = directories.setdefault(full.parent, {})
                siblings.setdefault(os.path.normcase(full.name), []).append((index, full))
        project._query_material_locators = (generation, references, directories)
        return references, directories


def _material_fingerprint(project):
    """Read fresh file metadata without hydrating or hashing artifact contents.

    Sibling materials use a single directory enumeration. On Windows DirEntry
    supplies file metadata directly, avoiding one filesystem call per artifact.
    Statistics are never cached across queries and never establish proof.
    """
    references, directories = _material_locators(project)
    entries = [[relative, None] for relative in references]
    directory_reads = 0
    for directory, siblings in directories.items():
        if len(siblings) >= 4:
            directory_reads += 1
            try:
                with os.scandir(directory) as listing:
                    for entry in listing:
                        targets = siblings.get(os.path.normcase(entry.name))
                        if targets is None:
                            continue
                        try:
                            stat = entry.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        metadata = [stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_mode]
                        for index, _ in targets:
                            entries[index][1] = metadata
            except OSError:
                pass
        else:
            for targets in siblings.values():
                try:
                    stat = targets[0][1].stat(follow_symlinks=False)
                    metadata = [stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_mode]
                except OSError:
                    metadata = None
                for index, _ in targets:
                    entries[index][1] = metadata
    project.metrics["artifact_directory_reads"] = project.metrics.get("artifact_directory_reads", 0) + directory_reads
    project.metrics["artifact_stats"] = project.metrics.get("artifact_stats", 0) + len(entries)
    return hashlib.sha256(canonical(entries).encode("utf-8")).hexdigest()


def _saved(project, generation):
    try:
        saved = project.projection_get(NAME, generation, schema_version=VERSION)
    except (ValueError, TypeError):
        return None
    required = {"config_sha256", "material_fingerprint", "evaluated", "finding_counts", "gap_total",
                "gap_sample", "queue_counts", "candidate_states", "assessment_policy", "parameter_summary",
                "browser_testing_summary", "browser_followup_summary", "category_matrix", "technical_blindspots",
                "candidate_proof_accounted", "administrative_reviews", "layers"}
    if not isinstance(saved, dict) or not required.issubset(saved) or saved.get("schema") != "awa-query-projection/v1" \
            or saved.get("name") != NAME or saved.get("generation") != generation \
            or type(saved.get("valid_until")) not in {int, float}:
        return None
    evaluated = saved["evaluated"]
    if not isinstance(evaluated, dict) or not isinstance(evaluated.get("continuation"), dict) \
            or not isinstance(evaluated.get("completion"), dict) or not isinstance(evaluated.get("completion_decision"), dict):
        return None
    return saved


def _build(project):
    from . import completeness, workflow
    from .assessment_mode import status as mode_status
    from .browser_policy import summarize

    evaluated, inventory = completeness.evaluate_with_inventory(project)
    security, matrix = completeness._security(inventory)
    checklist = completeness._checklist(inventory)
    work = workflow._fair_work_items([row for row in inventory["queue"] if row["queue_status"] != "blocked"])
    work += workflow._fair_work_items([row for row in inventory["queue"] if row["queue_status"] == "blocked"])
    lanes, followups = {}, []
    for row in checklist:
        if row["kind"] != "obligation":
            lanes.setdefault(row["kind"], deque()).append(row)
    while any(lanes.values()):
        for lane in lanes.values():
            if lane:
                followups.append(lane.popleft())
    policies = [row["browser_testing"] for row in followups if "browser_testing" in row]
    browser_summary = summarize([row["browser_testing"] for row in inventory["queue"]])
    followup_summary = summarize(policies, followup_total=len(policies))
    for key, count in followup_summary.items():
        browser_summary[key] += count
    candidates = dict(project.connection.execute(
        "SELECT COALESCE(json_extract(document,'$.status'),'unverified'),COUNT(*) FROM entities "
        "WHERE kind='candidate' GROUP BY COALESCE(json_extract(document,'$.status'),'unverified')").fetchall())
    observed = {row["operation_id"] for row in inventory["observations"]}
    by_evidence = {row["id"]: row["operation_id"] for row in inventory["observations"]}
    assessed = {row["operation_id"] for row in inventory["valid_decisions"] if row.get("operation_id")}
    assessed.update(by_evidence[identity] for row in inventory["valid_decisions"]
                    for identity in row.get("evidence_ids", []) if identity in by_evidence)
    future_expiry = []
    from .engine import stamp
    for row in project.list("session"):
        try:
            expiry = stamp(row["expires_at"]).timestamp()
            if expiry > time.time():
                future_expiry.append(expiry)
        except (EngineError, ValueError, TypeError, KeyError):
            pass
    result = {
        "schema": "awa-query-projection/v1", "name": NAME, "generated_at": now(),
        "config_sha256": _config_hash(project), "valid_until": min(future_expiry, default=time.time() + 86400),
        "evaluated": {key: value for key, value in evaluated.items() if key not in {"gaps", "findings", "method_coverage"}},
        "finding_counts": {"finding_total": len(evaluated["findings"]),
                           "current_findings": sum(row.get("current") is True for row in evaluated["findings"]),
                           "historical_findings": sum(row.get("current") is not True for row in evaluated["findings"])},
        "gap_total": len(evaluated["gaps"]), "gap_sample": evaluated["gaps"][:5],
        "queue_counts": dict(Counter(row["queue_status"] for row in inventory["queue"])),
        "candidate_states": candidates, "assessment_policy": mode_status(project),
        "parameter_summary": inventory["parameter_coverage_snapshot"]["summary"],
        "browser_testing_summary": browser_summary, "browser_followup_summary": followup_summary,
        "category_matrix": matrix, "technical_blindspots": completeness._blindspots(inventory, matrix),
        "candidate_proof_accounted": len(inventory["proof_resolved_candidates"]),
        "administrative_reviews": len(inventory.get("reviewed_admin", [])),
        "layers": {"registered": {"operations": len(inventory["operations"]), "inputs": evaluated["inputs"]},
                   "observed": {"operations": len(observed), "http_observations": len(inventory["observations"]),
                                "browser_visits": project.connection.execute("SELECT COUNT(*) FROM entities WHERE kind='page_visit'").fetchone()[0]},
                   "assessed": {"operations": len(assessed), "valid_decisions": len(inventory["valid_decisions"]),
                                "current_findings": len(inventory["current_findings"])},
                   "security": {"operations_complete": security["operations_complete"], "evaluated_obligations": security["evaluated"]}},
    }
    queues = {"work": work, "checklist": checklist, "followup": followups,
              "parameter": inventory["parameter_coverage_snapshot"]["items"],
              "method": evaluated.get("method_coverage", [])}
    return result, queues


def _write_queue(project, name, rows):
    queue = NAME + "/" + name
    stored = {row[0]: (row[1], row[2], row[3]) for row in project.connection.execute(
        "SELECT id,position,status,document FROM ready_queue_items WHERE queue=?", (queue,)).fetchall()}
    retained, changed = set(), 0
    for position, row in enumerate(rows):
        identity = str(row.get("id") or row.get("gap_id") or "row-" + str(position))
        if identity in retained:
            raise EngineError("projection_identity", "Projected query contains duplicate row identities")
        retained.add(identity)
        status = row.get("queue_status") or row.get("status") or "any"
        text = canonical(row)
        if stored.get(identity) != (position, status, text):
            project.connection.execute("INSERT INTO ready_queue_items VALUES(?,?,?,?,?,?) ON CONFLICT(queue,id) DO UPDATE SET "
                "position=excluded.position,status=excluded.status,operation_id=excluded.operation_id,document=excluded.document",
                (queue, identity, position, status, row.get("operation_id"), text))
            changed += 1
    for identity in stored.keys() - retained:
        project.connection.execute("DELETE FROM ready_queue_items WHERE queue=? AND id=?", (queue, identity))
        changed += 1
    return changed


def snapshot(project, *, force=False):
    for attempt in range(2):
        generation = project.generation()
        config_sha256 = _config_hash(project)
        material_fingerprint = _material_fingerprint(project)
        saved = None if force else _saved(project, generation)
        if saved and saved.get("config_sha256") == config_sha256 \
                and saved.get("material_fingerprint") == material_fingerprint \
                and saved.get("valid_until", 0) > time.time():
            continuation = saved["evaluated"]["continuation"]
            if not (continuation.get("can_finalize") or continuation.get("can_claim_complete")
                    or saved["evaluated"].get("completion", {}).get("status") == "complete"):
                return saved, True
        metadata, queues = _build(project)
        with project.transaction():
            if generation != project.generation() or metadata["config_sha256"] != _config_hash(project) \
                    or material_fingerprint != _material_fingerprint(project):
                continue
            metadata["generation"] = generation
            metadata["material_fingerprint"] = material_fingerprint
            metadata["projection_written_rows"] = sum(_write_queue(project, name, rows) for name, rows in queues.items())
            project.projection_put(NAME, generation, metadata, schema_version=VERSION)
        return metadata, False
    raise EngineError("projection_changed", "Project facts changed while its query projection was rebuilt; retry the page")


def _window(project, queue, *, offset=0, limit=25, where="", params=()):
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise EngineError("pagination", "offset must be nonnegative and limit between 1 and 100")
    clauses = "queue=?" + (" AND " + where if where else "")
    values = [NAME + "/" + queue, *params]
    with project._lock:
        total = project.connection.execute("SELECT COUNT(*) FROM ready_queue_items WHERE " + clauses, values).fetchone()[0]
        rows = project.connection.execute("SELECT document FROM ready_queue_items WHERE " + clauses +
                                          " ORDER BY position,id LIMIT ? OFFSET ?", [*values, limit, offset]).fetchall()
    project.metrics["records_decoded"] += len(rows)
    project.metrics["sql_pages"] += 1
    return {"items": [json.loads(row[0]) for row in rows], "total": total, "offset": offset, "limit": limit,
            "next_offset": offset + len(rows) if offset + len(rows) < total else None}


def _diagnostics(metadata, reused):
    return {"projection_reused": reused, "projection_revision": metadata["generation"],
            "material_verification": "cached_advisory" if reused else "strong_artifacts"}


def _methods(project, args):
    from .workflow import method_page_args

    offset, limit, operation_offset, operation_limit = method_page_args(args)
    queue = NAME + "/method"
    with project._lock:
        total = project.connection.execute("SELECT COUNT(*) FROM ready_queue_items WHERE queue=?", (queue,)).fetchone()[0]
        rows = project.connection.execute(
            "SELECT id,json_remove(document,'$.operations'),json_array_length(document,'$.operations') "
            "FROM ready_queue_items WHERE queue=? ORDER BY position,id LIMIT ? OFFSET ?",
            (queue, limit, offset)).fetchall()
        items, identity_total = [], 0
        for identity, document, operation_total in rows:
            if type(operation_total) is not int:
                raise EngineError("projection_changed", "The saved method membership is invalid; rebuild its projection")
            memberships = project.connection.execute(
                "SELECT member.value FROM ready_queue_items AS saved,json_each(saved.document,'$.operations') AS member "
                "WHERE saved.queue=? AND saved.id=? AND member.key>=? AND member.key<? ORDER BY member.key",
                (queue, identity, operation_offset, operation_offset + operation_limit)).fetchall()
            selected = [row[0] for row in memberships]
            identity_total += len(selected)
            items.append({**json.loads(document), "operations": selected, "operations_total": operation_total,
                          "operation_offset": operation_offset, "operation_limit": operation_limit,
                          "operation_next_offset": operation_offset + len(selected)
                              if operation_offset + len(selected) < operation_total else None})
    project.metrics["records_decoded"] += len(rows)
    project.metrics["method_operation_ids_returned"] = project.metrics.get("method_operation_ids_returned", 0) + identity_total
    project.metrics["sql_pages"] += 1
    return {"items": items, "total": total, "offset": offset,
            "next_offset": offset + len(rows) if offset + len(rows) < total else None,
            "operation_offset": operation_offset, "operation_limit": operation_limit}


def _parameters(project, metadata, args, default=10):
    from .parameter_coverage import STATUS_FILTERS
    from .workflow import page_args
    from .reporting import safe_metadata, safe_url

    offset, limit = page_args({"offset": args.get("parameter_offset", 0), "limit": args.get("parameter_limit", default)})
    status = args.get("parameter_status", "any")
    if not isinstance(status, str) or status not in STATUS_FILTERS:
        raise EngineError("arguments", "Unknown exact-input matrix status filter")
    where, params = "", []
    if status in {"needs_controls", "consumer_review"}:
        where, params = "json_extract(document,'$.status')=?", [status]
    elif status in {"tested", "untested"}:
        where, params = "json_extract(document,'$.typed_tested')=?", [int(status == "tested")]
    elif status == "observed":
        where = "json_extract(document,'$.observation_count')>0"
    window = _window(project, "parameter", offset=offset, limit=limit, where=where, params=params)
    window["items"] = [{**row, "url": safe_url(row["url"])} for row in window["items"]]
    return safe_metadata({"summary": metadata["parameter_summary"], **window, "filter": status,
                          "limitation": "Exact-input observations and comparison candidates are not oracle acceptance, vulnerability proof or completion. Input values and their digests are not published."})


def project_status(project, args):
    from .workflow import page_args, pick
    from .reporting import safe_metadata
    offset, limit = page_args(args, default=10)
    metadata, reused = snapshot(project)
    evaluated = metadata["evaluated"]
    result = safe_metadata(evaluated)
    result.update(**metadata["finding_counts"], gap_total=metadata["gap_total"], project_id=project.project_id,
                  path=str(project.base), config=safe_metadata(project.config),
                  candidates=metadata["candidate_states"].get("unverified", 0), candidate_states=metadata["candidate_states"],
                  gap_sample=safe_metadata(metadata["gap_sample"]), assessment_policy=metadata["assessment_policy"], next_action="plan.next")
    method = _methods(project, args)
    result.update(method_coverage=safe_metadata(method["items"]), method_total=method["total"],
                  method_offset=method["offset"], method_next_offset=method["next_offset"],
                  method_operation_offset=method["operation_offset"], method_operation_limit=method["operation_limit"])
    fields = {"actor": ("id", "label", "subject", "tenant_id", "roles", "security_revision"),
              "session": ("id", "actor_id", "generation", "verified_at", "expires_at", "verification_evidence_id"),
              "run": ("id", "kind", "status", "started_at", "finished_at", "operation_id", "error", "error_code", "diagnostic",
                      "dispatch_id", "dispatch_attempted", "effect_unknown", "reconciliation_id")}
    for kind, names in fields.items():
        window = project.list_page(kind, offset=offset, limit=limit, order_desc=kind == "run")
        result[kind + "s"] = [pick(row, names) for row in window["items"]]
        result[kind + "_total"] = window["total"]
        result[kind + "_next_offset"] = window["next_offset"]
    result.update(offset=offset, limit=limit, **_diagnostics(metadata, reused))
    return result


def next_work(project, args):
    from . import loop_guard, workflow
    from .reporting import safe_metadata

    offset, limit = workflow.page_args(args, default=10, maximum=25)
    blocked, compact = args.get("include_blocked", False), args.get("compact", False)
    if type(blocked) is not bool or type(compact) is not bool:
        raise EngineError("arguments", "include_blocked and compact must be booleans")
    metadata, reused = snapshot(project)
    evaluated = metadata["evaluated"]
    window = _window(project, "work", offset=offset, limit=limit, where="" if blocked else "status!='blocked'")
    rows = window.pop("items")
    repeated = loop_guard.observe_next_page(project, offset, limit, rows)
    if repeated:
        loop_guard.mark_frozen(rows, repeated)
    counts = metadata["queue_counts"]
    closure = _window(project, "followup", limit=min(limit, 3))
    result = {"continuation": evaluated["continuation"], "completion_decision": evaluated["completion_decision"],
              "completion": evaluated["completion"], "source_inventory": evaluated["source_inventory"],
              "work_items": rows, "queue_total": window.pop("total"), **window,
              "ready_total": counts.get("ready", 0), "review_total": counts.get("review", 0), "blocked_total": counts.get("blocked", 0),
              "review_followups": closure["items"], "requests_sent": 0, **_diagnostics(metadata, reused)}
    if compact:
        result.update(work_items=[workflow._compact_work_item(row) for row in rows],
                      review_followups=[workflow._compact_followup(row) for row in closure["items"][:5]],
                      compact=True, next_action="plan.next", limitation="Compact readiness view only; it is not approval, execution or completed coverage.")
        return result
    result.update(blocked_sample=_window(project, "work", limit=min(5, limit), where="status='blocked'")["items"],
                  review_followup_total=closure["total"], review_followup_action="plan.audit",
                  coverage_ratio=evaluated["coverage_ratio"], security_coverage=evaluated["security_coverage"],
                  parameter_coverage=_parameters(project, metadata, args, min(limit, 3)),
                  queue_policy="coverage_first", queue_fairness="family_and_operation_round_robin", closure_action="plan.audit",
                  browser_testing_summary=metadata["browser_testing_summary"],
                  limitation="Readiness is not approval, execution, or completed coverage. Fill the exact experiment fields and preflight every request; imported tool output remains untrusted.")
    return safe_metadata(result)


def audit(project, args):
    from .workflow import page_args
    from .reporting import safe_metadata

    offset, limit = page_args(args)
    metadata, reused = snapshot(project)
    evaluated = metadata["evaluated"]
    window = _window(project, "checklist", offset=offset, limit=limit)
    return safe_metadata({"project_id": project.project_id, "requests_sent": 0,
        "continuation": evaluated["continuation"], "completion_decision": evaluated["completion_decision"],
        "completion": evaluated["completion"], "security_coverage": evaluated["security_coverage"],
        "source_inventory": evaluated["source_inventory"], "layers": metadata["layers"],
        "category_matrix": metadata["category_matrix"], "technical_blindspots": metadata["technical_blindspots"],
        "parameter_coverage": _parameters(project, metadata, args, min(limit, 3)),
        "checklist": window.pop("items"), "checklist_total": window.pop("total"), **window,
        "candidate_proof_accounted": metadata["candidate_proof_accounted"], "administrative_reviews": metadata["administrative_reviews"],
        "next_action": "plan.next", **_diagnostics(metadata, reused),
        "note_zh": "本检查仅读取现有材料，不发请求、不补造证据、不自动关闭义务，也不把启发式线索确认成漏洞。"})


def maintain(project, args):
    if not isinstance(args, dict):
        raise EngineError("projection_mode", "Projection arguments must be an object")
    mode = args.get("mode", "inspect")
    if not isinstance(mode, str) or mode not in {"inspect", "rebuild", "compare"}:
        raise EngineError("projection_mode", "Projection mode must be inspect, rebuild or compare")
    generation = project.generation()
    saved = _saved(project, generation)
    result = {"schema": "awa-query-projection/v1", "name": NAME, "generation": generation,
              "projection_reused": saved is not None, "rebuilt": False, "requests_sent": 0, "next_action": "plan.next"}
    if mode == "rebuild":
        metadata, _ = snapshot(project, force=True)
        result.update(rebuilt=True, generation=metadata["generation"], material_verification="strong_artifacts")
    elif mode == "compare":
        metadata, queues = _build(project)
        differences = []
        if saved is None:
            differences.append("projection_missing")
        elif any(metadata[key] != saved.get(key) for key in metadata if key not in {"generated_at", "valid_until"}):
            differences.append("summary")
        for name, rows in queues.items():
            expected = [canonical(row) for row in rows]
            actual = [row[0] for row in project.connection.execute(
                "SELECT document FROM ready_queue_items WHERE queue=? ORDER BY position,id", (NAME + "/" + name,)).fetchall()]
            if actual != expected:
                differences.append(name)
        result.update(comparison={"equal": not differences, "differences": differences}, material_verification="strong_artifacts")
    else:
        result["material_verification"] = "cached_advisory"
    result["metrics"] = dict(project.metrics)
    return result
