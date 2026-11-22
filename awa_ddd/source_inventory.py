"""Offline discovery snapshots, exact registration differences and bounded handoff.

The source denominator is the material the caller supplied.  Saving, importing
or binding that material never grants a security verdict or target permission.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
from urllib.parse import urlsplit

from . import engine
from .scope import require_scope
from .store import EngineError, canonical, now


SOURCE_KIND = "discovery_source"
SNAPSHOT_KIND = "discovery_snapshot"
ITEM_KIND = "discovery_item"
INGEST_KIND = "discovery_ingest"
MAX_STORED_ITEMS = 50000
STATUSES = {"pending_import", "registered", "needs_binding", "conflict", "rejected", "candidate"}
_UNRESOLVED_LIMITS = {
    "unresolved_or_invalid_url", "unsupported_request_body", "form_input_budget_exceeded",
    "unparseable_or_truncated_json_body", "body_format_requires_review", "external_reference_not_loaded",
    "recursive_reference_requires_review", "unresolved_local_reference", "server_variable_requires_explicit_resolution",
    "server_url_requires_base_url", "recursive_schema_reference", "dynamic_property_names_require_runtime_observation",
    "invalid_path_template", "operation_has_no_resolved_server", "missing_har_request", "invalid_runtime_record",
    "request_body_may_be_truncated", "invalid_protocol_endpoint_list", "unresolved_protocol_endpoint",
    "invalid_sarif_locations", "sarif_locations_truncated", "invalid_sarif_code_flows", "sarif_call_path_incomplete",
    "sarif_call_paths_truncated", "client_sink_input_bindings_truncated", "javascript_ast_parser_unavailable",
    "javascript_ast_parser_failed", "javascript_analysis_incomplete", "invalid_assessment_hint",
    "tscanplus_namespace_echo_missing", "tscanplus_instance_echo_missing", "tscanplus_results_truncated",
    "tscanplus_results_incomplete", "tscanplus_rows_omitted",
}


def _snapshot_digest(snapshot):
    material = {key: value for key, value in snapshot.items() if key not in {"created_at", "normalized_sha256"}}
    return hashlib.sha256(canonical(material).encode("utf-8")).hexdigest()


def _snapshot_valid(snapshot):
    try:
        return snapshot["id"] == engine.stable("DSS", [snapshot["source_id"], snapshot["sha256"], snapshot["parser_version"]]) \
            and snapshot["normalized_sha256"] == _snapshot_digest(snapshot)
    except (KeyError, ValueError, TypeError):
        return False


def _source_matches(snapshot, source):
    return bool(source) and source.get("id") == engine.stable("DS", [snapshot.get("format"), snapshot.get("path"), snapshot.get("base_url")]) \
        and all(source.get(key) == snapshot.get(key) for key in ("format", "path", "base_url"))


def _unresolved_snapshot(snapshot):
    metadata = snapshot.get("inventory", {})
    if isinstance(metadata, dict) and type(metadata.get("unresolved_mapping_total")) is int \
            and metadata["unresolved_mapping_total"] >= 0:
        # The mapping parser already accounts for each unresolved record once.
        return metadata["unresolved_mapping_total"]
    # Runtime-evidence disclaimers and template binding notes are advisory, not
    # missing parser rows. Actual unsupported/truncated material remains a gap.
    return sum(row.get("code") in _UNRESOLVED_LIMITS for row in snapshot.get("limitations", []) if isinstance(row, dict))


def _base_url(value):
    if value is None:
        return None
    from .discovery import _url

    clean, _ = _url(value)
    return clean


def _operation_id(hint):
    return engine.stable("O", [hint["url"], hint["method"], hint.get("protocol", "http"),
                               hint.get("operation_name", ""), hint.get("content_type", "")])


def _input_key(entry):
    return canonical([entry.get("location"), entry.get("selector", entry.get("name")), entry.get("schema_branch")])


def _known(value):
    return value is not None and value not in ("", "unknown", "other", "untraced", "unspecified")


def _merge_operation(existing, hint):
    """Keep local policy and input declarations; expose contradictory known claims."""
    merged = deepcopy(hint)
    conflicts = []
    if not existing:
        return merged, conflicts
    for field in ("auth", "allowed_roles", "ownership", "state_scope"):
        prior, incoming = existing.get(field), hint.get(field)
        if field in hint and _known(incoming) and field in existing and _known(prior):
            left, right = prior, incoming
            if field == "allowed_roles" and isinstance(left, list) and isinstance(right, list):
                left, right = sorted(left), sorted(right)
            if canonical(left) != canonical(right):
                conflicts.append(field)
        if field in existing:
            # An imported declaration cannot relax or replace local authorization.
            # Unknown local auth may be enriched by a concrete source declaration.
            if field != "auth" or _known(prior) or not _known(incoming):
                merged[field] = deepcopy(prior)
    prior_inputs = {_input_key(entry): entry for entry in existing.get("inputs", [])}
    inputs = []
    for incoming in hint.get("inputs", []):
        entry = deepcopy(incoming)
        prior = prior_inputs.get(_input_key(entry))
        if prior:
            for field in ("consumer", "test_families", "schema_type", "required", "array_template", "schema_locator"):
                if field not in prior:
                    continue
                if field in entry and _known(entry[field]) and _known(prior[field]):
                    left, right = prior[field], entry[field]
                    if field == "test_families" and isinstance(left, list) and isinstance(right, list):
                        left, right = sorted(left), sorted(right)
                    if canonical(left) != canonical(right):
                        conflicts.append("input:" + _input_key(entry) + ":" + field)
                entry[field] = deepcopy(prior[field])
            if "source" in prior:
                entry["source"] = prior["source"]
        inputs.append(entry)
    merged["inputs"] = inputs
    return merged, sorted(set(conflicts))


def _registration_changed(existing, merged, *, provenance_saved=False):
    if not existing:
        return True
    prior_inputs = {_input_key(entry): entry for entry in existing.get("inputs", [])}
    for incoming in merged.get("inputs", []):
        prior = prior_inputs.get(_input_key(incoming))
        if prior is None or any(canonical(prior.get(field)) != canonical(value)
                                for field, value in incoming.items() if field != "source"):
            return True
    for field in ("auth", "allowed_roles", "ownership", "state_scope"):
        if field in merged and canonical(existing.get(field)) != canonical(merged[field]):
            return True
    if provenance_saved:
        return False
    known_sources = {canonical(source) for source in existing.get("sources", [])}
    return any(canonical(source) not in known_sources for source in merged.get("sources", []))


def _candidate(project, item, *, reason=None, conflicts=()):
    hint = deepcopy(item["hint"])
    if item["item_kind"] == "operation":
        candidate = {"kind": "operation_hint", "hint": hint, "reason": reason or "registration_required"}
        if conflicts:
            candidate["conflict_fields"] = list(conflicts)
    else:
        candidate = hint
    from .candidates import candidate_id

    identity = candidate_id(candidate)
    return candidate, identity, project.get("candidate", identity, required=False)


def _item_state(project, item, operations):
    hint = item["hint"]
    if item["item_kind"] == "candidate":
        _, candidate_id, saved = _candidate(project, item)
        state = "needs_binding" if hint.get("native_input_requires_binding") or hint.get("path_template") else "candidate"
        locator = hint.get("hint") if isinstance(hint.get("hint"), dict) else hint
        reason = None
        if locator.get("url"):
            try:
                require_scope(project.config, locator["url"])
            except EngineError as exc:
                state, reason = "rejected", exc.code
        reason = reason or hint.get("reason_code")
        return {"status": state, "candidate_id": candidate_id if saved else None,
                "pending_import": saved is None, "needs_binding": state == "needs_binding",
                **({"reason_code": reason} if reason else {})}
    try:
        require_scope(project.config, hint["url"])
    except EngineError as exc:
        _, candidate_id, saved = _candidate(project, item, reason=exc.code)
        return {"status": "rejected", "reason_code": exc.code, "candidate_id": candidate_id if saved else None,
                "pending_import": saved is None, "needs_binding": False}
    identity = _operation_id(hint)
    existing = operations.get(identity)
    merged, conflicts = _merge_operation(existing, hint)
    if conflicts:
        _, candidate_id, saved = _candidate(project, item, reason="source_conflict", conflicts=conflicts)
        return {"status": "conflict", "operation_id": identity, "candidate_id": candidate_id if saved else None,
                "reason_code": "source_conflict", "conflict_fields": conflicts, "pending_import": saved is None, "needs_binding": False}
    receipt = project.get(INGEST_KIND, item["id"], required=False) or {}
    if not existing and receipt.get("candidate_id") and receipt.get("reason_code"):
        saved = project.get("candidate", receipt["candidate_id"], required=False)
        if saved:
            return {"status": "rejected", "reason_code": receipt["reason_code"],
                    "candidate_id": saved["id"], "pending_import": False, "needs_binding": False}
    changed = _registration_changed(existing, merged, provenance_saved=receipt.get("operation_id") == identity)
    needs_binding = bool(hint.get("path_template") or any(character in urlsplit(hint["url"]).path for character in "{}*"))
    return {"status": "pending_import" if changed else "needs_binding" if needs_binding else "registered",
            "operation_id": identity if existing else None, "pending_import": changed,
            "needs_binding": needs_binding}


def _items(project, snapshot):
    with project._lock:
        rows = project.connection.execute(
            "SELECT document FROM entities WHERE kind=? AND json_extract(document,'$.snapshot_id')=? ORDER BY id",
            (ITEM_KIND, snapshot["id"])).fetchall()
    by_id = {row["id"]: row for row in (json.loads(value[0]) for value in rows)}
    expected = snapshot.get("item_ids", [])
    selected = [by_id[identity] for identity in expected if identity in by_id]
    valid = [item for item in selected if item.get("source_id") == snapshot.get("source_id")
             and item.get("snapshot_id") == snapshot.get("id") and item.get("item_kind") in {"operation", "candidate"}
             and item.get("id") == engine.stable("DI", [snapshot["id"], item["item_kind"], item.get("hint")])]
    return valid, len(set(expected)) - len(valid)


def _save_snapshot(project, parsed, format, base_url):
    source_meta = parsed["source"]
    source_id = engine.stable("DS", [format, source_meta["path"], base_url])
    snapshot_id = engine.stable("DSS", [source_id, source_meta["sha256"], source_meta["parser_version"]])
    prior = project.get(SNAPSHOT_KIND, snapshot_id, required=False)
    snapshot_items = []
    for item_kind, hints in (("operation", parsed["operations"]), ("candidate", parsed.get("candidates", []))):
        for hint in hints:
            identity = engine.stable("DI", [snapshot_id, item_kind, hint])
            snapshot_items.append({"id": identity, "source_id": source_id, "snapshot_id": snapshot_id,
                                   "item_kind": item_kind, "hint": hint})
    # Parsers may report the same candidate twice. Preserve all provenance in a
    # parser's merged row, but never multiply identical inventory entries.
    snapshot_items = list({item["id"]: item for item in snapshot_items}.values())
    document = {"id": snapshot_id, "source_id": source_id, **source_meta, "base_url": base_url,
                "inventory": parsed.get("inventory", {}), "limitations": parsed.get("limitations", []),
                "item_ids": [item["id"] for item in snapshot_items]}
    document["normalized_sha256"] = _snapshot_digest(document)
    if prior:
        # Authenticate stored material before comparing a fresh parser result.
        # Damaged inventory must not be repaired by silently re-reading a file.
        _saved_snapshot(project, snapshot_id)
        if canonical({key: value for key, value in prior.items() if key != "created_at"}) != canonical(document):
            raise EngineError("source_snapshot_conflict", "Parser output changed for an existing source snapshot; use a new parser version")
    else:
        with project._lock:
            current_count = project.connection.execute("SELECT COUNT(*) FROM entities WHERE kind=?", (ITEM_KIND,)).fetchone()[0]
        if current_count + len(snapshot_items) > MAX_STORED_ITEMS:
            raise EngineError("source_inventory_budget", "Discovery inventory exceeds 50000 retained items; use a separate bounded project")
        created_at = now()
        for item in snapshot_items:
            project.put(ITEM_KIND, {**item, "created_at": created_at}, create_only=True)
        document["created_at"] = created_at
        project.put(SNAPSHOT_KIND, document, create_only=True)
        project.event("discovery.snapshot_saved", {"source_id": source_id, "snapshot_id": snapshot_id,
                      "sha256": source_meta["sha256"], "items": len(snapshot_items)})
    source = project.get(SOURCE_KIND, source_id, required=False)
    if source is None or source.get("latest_snapshot_id") != snapshot_id:
        source = {"id": source_id, "format": format, "path": source_meta["path"], "base_url": base_url,
                  "latest_snapshot_id": snapshot_id, "created_at": (source or {}).get("created_at", now())}
        project.put(SOURCE_KIND, source)
    return source, prior or document, snapshot_items, prior is not None


def _saved_snapshot(project, identity):
    snapshot = project.get(SNAPSHOT_KIND, identity, required=False)
    if snapshot is None:
        raise EngineError("source_snapshot_changed", "Saved discovery snapshot is missing")
    if not _snapshot_valid(snapshot):
        raise EngineError("source_snapshot_changed", "Saved discovery manifest differs from its immutable identity")
    source = project.get(SOURCE_KIND, snapshot["source_id"], required=False)
    if source is None:
        raise EngineError("source_snapshot_changed", "Saved discovery source is missing")
    items, missing = _items(project, snapshot)
    if missing or not _source_matches(snapshot, source):
        raise EngineError("source_snapshot_changed", "Saved discovery items are missing or differ from their snapshot identities")
    return source, snapshot, items, True


def _store_candidate_once(project, item, *, reason=None, conflicts=()):
    from .candidates import store_candidate

    candidate, identity, existing = _candidate(project, item, reason=reason, conflicts=conflicts)
    if existing:
        return identity, False
    identity, created = store_candidate(project, candidate)
    return identity, created


def _receipt(project, item, **fields):
    record = {"id": item["id"], "source_item_id": item["id"], **fields}
    existing = project.get(INGEST_KIND, item["id"], required=False)
    if existing is None or canonical(existing) != canonical(record):
        project.put(INGEST_KIND, record)


def _route_key(hint):
    hint = hint.get("hint") if isinstance(hint.get("hint"), dict) else hint
    if isinstance(hint.get("url"), str) and isinstance(hint.get("method"), str):
        return hint["url"], hint["method"]
    return None


def inventory(project, *, operations=None):
    """Recompute the known-source difference against the current ledger, offline."""
    operations = operations if operations is not None else {row["id"]: row for row in project.list("operation")}
    snapshots = project.list(SNAPSHOT_KIND)
    sources = {row["id"]: row for row in project.list(SOURCE_KIND)}
    registered_routes = {(row["url"], row["method"]) for row in operations.values()}
    known_routes, rows, missing_items = set(), [], 0
    snapshot_issues = {}
    unresolved = 0
    for snapshot in snapshots:
        source = sources.get(snapshot["source_id"], {})
        current = source.get("latest_snapshot_id") == snapshot["id"]
        valid_snapshot = _snapshot_valid(snapshot) and _source_matches(snapshot, source)
        if valid_snapshot:
            items, missing = _items(project, snapshot)
        else:
            # A changed immutable manifest cannot authenticate any item.
            missing, items = max(1, len(snapshot.get("item_ids", []))), []
        snapshot_issues[snapshot["id"]] = missing
        missing_items += missing
        if current and valid_snapshot:
            unresolved += _unresolved_snapshot(snapshot)
        for item in items:
            state = _item_state(project, item, operations)
            route = _route_key(item["hint"])
            if route:
                known_routes.add(route)
            row = {"id": item["id"], "source_id": item["source_id"], "snapshot_id": item["snapshot_id"],
                   "item_kind": item["item_kind"], "hint": item["hint"], "current_snapshot": current, **state}
            rows.append(row)
    # Different snapshots keep their provenance. Pending totals are profile
    # counts; route totals deduplicate method/URL independently of media variants.
    snapshot_ids = {snapshot["id"] for snapshot in snapshots}
    source_issues = {source["id"]: 1 for source in sources.values() if source.get("latest_snapshot_id") not in snapshot_ids}
    # A lost snapshot is an unknown container, not an invented route/item count.
    unresolved += len(source_issues)
    counts = Counter(row["status"] for row in rows)
    pending = [row for row in rows if row["pending_import"]]
    summary = {"source_total": len(sources), "snapshot_total": len(snapshots), "source_item_total": len(rows) + missing_items,
               "known_route_total": len(known_routes), "registered_route_total": len(known_routes & registered_routes),
               "known_not_registered_total": len(known_routes - registered_routes), "pending_import_total": len(pending) + missing_items,
               "needs_binding_total": sum(row["needs_binding"] for row in rows), "conflict_total": counts["conflict"],
               "rejected_total": counts["rejected"], "candidate_total": counts["candidate"],
               "unresolved_total": unresolved + missing_items,
               "historical_pending_total": sum(not row["current_snapshot"] for row in pending),
               "completeness_level": "source_inventory" if snapshots else "declared_only",
               "site_wide_discovery_allowed": False}
    # A conflicting imported claim already in the candidate ledger is handled by
    # the existing proof gate. It must not acquire authority from a source count.
    return {"summary": summary, "items": rows, "pending": pending, "sources": sources,
            "snapshots": {snapshot["id"]: snapshot for snapshot in snapshots}, "missing_items": missing_items,
            "snapshot_issues": snapshot_issues, "source_issues": source_issues}


def _item_view(row):
    hint = row["hint"].get("hint") if isinstance(row["hint"].get("hint"), dict) else row["hint"]
    result = {key: row[key] for key in ("source_id", "snapshot_id", "item_kind", "status", "current_snapshot", "pending_import",
                                      "operation_id", "candidate_id", "reason_code", "conflict_fields", "needs_binding") if key in row}
    result["source_item_id"] = row["id"]
    for field in ("url", "method", "protocol", "operation_name", "content_type", "path_template", "native_input_requires_binding", "requestable"):
        if field in hint:
            result[field] = hint[field]
    inputs = hint.get("inputs", [])
    result.update(input_count=len(inputs), inputs=inputs[:20], inputs_truncated=len(inputs) > 20,
                  automatic_execution_allowed=False, usable_for_confirmation=False)
    return result


def _status_matches(row, status):
    if status == "pending_import":
        return row["pending_import"]
    return status == "any" or row["status"] == status


def import_source(project, args, *, _parsed=None):
    from .discovery import discover
    from .workflow import page_args

    mode = args.get("mode", "apply")
    if not isinstance(mode, str) or mode not in {"preview", "apply"}:
        raise EngineError("source_import_mode", "surface.import mode must be preview or apply")
    offset, limit = page_args(args)
    snapshot_id = args.get("snapshot_id")
    if snapshot_id is not None and (mode != "apply" or any(field in args for field in ("path", "format", "base_url"))):
        raise EngineError("source_snapshot_binding", "An exact snapshot_id can only be applied without path, format or base_url")
    base_url = _base_url(args.get("base_url")) if snapshot_id is None else None
    parsed = (_parsed if _parsed is not None else discover(args["path"], args["format"], base_url)) if snapshot_id is None else None
    counts = {key: 0 for key in ("created", "reused", "conflicts", "rejected", "needs_binding", "candidate_created", "candidate_reused")}
    registered, candidate_ids, dispositions = [], [], {}
    with project.transaction():
        source, snapshot, items, reused = (_saved_snapshot(project, snapshot_id) if snapshot_id is not None
                                         else _save_snapshot(project, parsed, args["format"], base_url))
        operations = {row["id"]: row for row in project.list("operation")}
        changed = False
        window_items = items[offset:offset + limit]
        for item in window_items:
            state = _item_state(project, item, operations)
            counts["needs_binding"] += state["needs_binding"]
            counts["conflicts"] += state["status"] == "conflict"
            counts["rejected"] += state["status"] == "rejected"
            if mode == "preview":
                continue
            if item["item_kind"] == "candidate" or state["status"] in {"conflict", "rejected"}:
                candidate_id, created = _store_candidate_once(project, item, reason=state.get("reason_code", "source_conflict"),
                                                               conflicts=state.get("conflict_fields", []))
                _receipt(project, item, candidate_id=candidate_id, reason_code=state.get("reason_code"),
                         conflict_fields=state.get("conflict_fields", []))
                candidate_ids.append(candidate_id)
                counts["candidate_created" if created else "candidate_reused"] += 1
                dispositions[item["id"]] = "candidate_created" if created else "candidate_reused"
                continue
            hint = item["hint"]
            identity = _operation_id(hint)
            existing = operations.get(identity)
            merged, _ = _merge_operation(existing, hint)
            receipt = project.get(INGEST_KIND, item["id"], required=False) or {}
            if _registration_changed(existing, merged, provenance_saved=receipt.get("operation_id") == identity):
                try:
                    operation = engine.register_operation(project, merged)
                except EngineError as exc:
                    candidate_id, created = _store_candidate_once(project, item, reason=exc.code)
                    _receipt(project, item, candidate_id=candidate_id, reason_code=exc.code)
                    candidate_ids.append(candidate_id)
                    counts["rejected"] += 1
                    counts["candidate_created" if created else "candidate_reused"] += 1
                    dispositions[item["id"]] = "rejected"
                    continue
                operations[identity] = operation
                changed = True
                dispositions[item["id"]] = "updated" if existing else "created"
            else:
                dispositions[item["id"]] = "reused"
            registered.append(identity)
            counts["reused" if existing else "created"] += 1
            _receipt(project, item, operation_id=identity)
        if changed:
            engine.build_plan(project)
        current = inventory(project, operations=operations)
    selected = [row for row in current["items"] if row["snapshot_id"] == snapshot["id"]]
    results = [{**_item_view(row), "disposition": dispositions.get(row["id"], "not_applied")}
               for row in selected[offset:offset + limit]]
    next_offset = (next((index for index in range(offset + limit, len(selected)) if selected[index]["pending_import"]), None)
                   if mode == "apply" else offset + limit if offset + limit < len(selected) else None)
    next_action = "surface.import" if mode == "apply" and next_offset is not None else "surface.sources"
    next_input = ({"snapshot_id": snapshot["id"], "mode": "apply", "offset": next_offset, "limit": limit}
                  if mode == "apply" else {"source_id": source["id"], "snapshot_id": snapshot["id"],
                                           "offset": next_offset, "limit": limit}) if next_offset is not None else None
    return {"source_id": source["id"], "snapshot_id": snapshot["id"], "snapshot_reused": reused,
            "mode": mode, "counts": counts, "source_inventory": current["summary"], "results": results,
            "result_total": len(selected), "offset": offset, "limit": limit,
            "next_offset": next_offset, "next_input": next_input,
            "operation_ids": list(dict.fromkeys(registered)), "candidate_ids": list(dict.fromkeys(candidate_ids)),
            "candidates": counts["candidate_created"], "candidate_total": len(project.list("candidate")),
            "limitations": snapshot["limitations"], "requests_sent": 0, "automatic_execution_allowed": False,
            "usable_for_confirmation": False, "next_action": next_action}


def import_parsed(project, parsed, args):
    """Ingest a provider-owned envelope through the same offline snapshot command.

    The provider supplies source bytes/digest and fixed provenance. Callers cannot
    turn this interface into a file reader or a scanner execution instruction.
    """
    metadata = parsed.get("source") if isinstance(parsed, dict) else None
    if not isinstance(metadata, dict) or metadata.get("format") not in {"tscanplus_results", "tscanplus_routes"}:
        raise EngineError("provider_source", "Provider source requires a supported fixed envelope")
    import re
    if not isinstance(metadata.get("path"), str) or not metadata["path"].startswith("tscanplus://") \
            or not isinstance(metadata.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"]) \
            or type(metadata.get("parser_version")) is not int or metadata["parser_version"] < 1 \
            or type(metadata.get("byte_count")) is not int or not 0 <= metadata["byte_count"] <= 8 * 1024 * 1024:
        raise EngineError("provider_source", "Provider envelope identity or material budget is invalid")
    if parsed.get("operations") or not isinstance(parsed.get("candidates"), list) or len(parsed["candidates"]) > 10000:
        raise EngineError("provider_source", "Provider discovery only imports bounded unverified candidates")
    if any(key in args for key in ("path", "format", "snapshot_id")):
        raise EngineError("provider_source", "Provider ingest cannot mix caller paths, formats or snapshot handles")
    return import_source(project, {"format": metadata["format"], "mode": args.get("mode", "preview"),
        "offset": args.get("offset", 0), "limit": args.get("limit", 25)}, _parsed=parsed)


def _legacy_list_sources(project, args):
    from .workflow import page_args

    offset, limit = page_args(args)
    status = args.get("status", "any")
    if not isinstance(status, str) or status not in STATUSES | {"any"}:
        raise EngineError("source_status", "Unsupported source inventory status")
    current = inventory(project)
    source_id, snapshot_id = args.get("source_id"), args.get("snapshot_id")
    if snapshot_id is not None:
        snapshot = project.get(SNAPSHOT_KIND, snapshot_id, required=False)
        if snapshot is None:
            bound_sources = [source for source in current["sources"].values() if source.get("latest_snapshot_id") == snapshot_id]
            if not bound_sources:
                project.get(SNAPSHOT_KIND, snapshot_id)
            if source_id is not None and source_id not in {source["id"] for source in bound_sources}:
                raise EngineError("source_snapshot_binding", "snapshot_id must belong to source_id")
            source_id = source_id or bound_sources[0]["id"]
        else:
            if source_id is not None and source_id != snapshot["source_id"]:
                raise EngineError("source_snapshot_binding", "snapshot_id must belong to source_id")
            source_id = snapshot["source_id"]
    result = {"source_inventory": current["summary"], "offset": offset, "limit": limit,
              "requests_sent": 0, "automatic_execution_allowed": False, "usable_for_confirmation": False}
    if source_id is not None:
        source = project.get(SOURCE_KIND, source_id, required=False)
        if source is None and snapshot_id is None:
            project.get(SOURCE_KIND, source_id)
        snapshot_id = snapshot_id or source.get("latest_snapshot_id")
        snapshot = current["snapshots"].get(snapshot_id)
        rows = [row for row in current["items"] if row["snapshot_id"] == snapshot_id and _status_matches(row, status)]
        source_view = deepcopy(source)
        if source_view is not None and source_view.get("latest_snapshot_id") not in current["snapshots"]:
            source_view["latest_snapshot_id"] = None
        result.update(source_id=source_id if source else None, snapshot_id=snapshot_id if snapshot else None, source=source_view,
                      snapshot={key: snapshot[key] for key in ("id", "source_id", "format", "sha256", "normalized_sha256", "parser_version", "byte_count", "inventory", "limitations", "created_at") if key in snapshot} if snapshot else None,
                      items=[_item_view(row) for row in rows[offset:offset + limit]], total=len(rows), status=status)
        result["snapshot_integrity"] = "missing" if snapshot is None else "changed" if current["snapshot_issues"].get(snapshot_id) else "valid"
        result["missing_item_total"] = current["snapshot_issues"].get(snapshot_id, 0) if snapshot else 1
        if snapshot is None:
            result["reason_code"] = "source_snapshot_missing"
    else:
        rows = []
        for source in current["sources"].values():
            snapshot = current["snapshots"].get(source.get("latest_snapshot_id"))
            source_items = [item for item in current["items"] if item["source_id"] == source["id"]]
            counts = Counter(item["status"] for item in source_items)
            related_snapshots = [row for row in current["snapshots"].values() if row["source_id"] == source["id"]]
            missing_items = sum(current["snapshot_issues"].get(row["id"], 0) for row in related_snapshots)
            source_issue = current["source_issues"].get(source["id"], 0)
            matches = (any(item["pending_import"] for item in source_items) or missing_items or source_issue) if status == "pending_import" else counts[status]
            if status != "any" and not matches:
                continue
            rows.append({"source_id": source["id"], "snapshot_id": snapshot["id"] if snapshot else None,
                         **{key: source[key] for key in ("format", "path", "base_url") if key in source},
                         **{key: snapshot[key] for key in ("sha256", "parser_version") if snapshot and key in snapshot},
                         "snapshot_integrity": "missing" if snapshot is None else "changed" if current["snapshot_issues"].get(snapshot["id"]) else "valid",
                         "missing_item_total": missing_items + source_issue,
                         **({"reason_code": "source_snapshot_missing"} if snapshot is None else {}),
                         "snapshot_total": len(related_snapshots),
                         "source_item_total": len(source_items) + missing_items, "pending_import_total": sum(item["pending_import"] for item in source_items) + missing_items,
                         "historical_pending_total": sum(item["pending_import"] and not item["current_snapshot"] for item in source_items),
                         "counts": dict(counts), "next_action": "surface.sources"})
        result.update(sources=rows[offset:offset + limit], total=len(rows), status=status)
    result.update(next_offset=offset + limit if offset + limit < result["total"] else None, next_action="surface.sources")
    return result


def compare_snapshots(project, base_id, latest_id, *, offset=0, limit=25):
    """Compare immutable normalized material, without rereading the source file."""
    from .workflow import page_args
    page_args({"offset": offset, "limit": limit})
    _, base, before, _ = _saved_snapshot(project, base_id)
    _, latest, after, _ = _saved_snapshot(project, latest_id)
    if base["source_id"] != latest["source_id"]:
        raise EngineError("source_snapshot_binding", "Snapshot comparison requires the same discovery source")
    def normalized(item):
        hint = deepcopy(item["hint"])
        hint.pop("source", None)
        hint.pop("sources", None)
        return hint
    def key(item):
        hint = normalized(item)
        locator = hint.get("hint") if isinstance(hint.get("hint"), dict) else hint
        return canonical([item["item_kind"], locator.get("kind"), locator.get("url"), locator.get("method"),
                          locator.get("protocol"), locator.get("operation_name"), locator.get("content_type"),
                          locator.get("input_location"), locator.get("input_selector")])
    before_by_key, after_by_key = {}, {}
    for items, destination in ((before, before_by_key), (after, after_by_key)):
        for item in items:
            identity = key(item)
            if identity in destination:
                # Ambiguous items remain individually visible; do not silently
                # invent a correspondence from equal endpoint labels.
                identity = canonical([identity, normalized(item)])
            destination[identity] = item
    changes, unchanged = [], 0
    for identity in sorted(set(before_by_key) | set(after_by_key)):
        prior, current = before_by_key.get(identity), after_by_key.get(identity)
        if prior is None:
            changes.append({"status": "added", "source_item_id": current["id"]})
        elif current is None:
            changes.append({"status": "removed", "previous_item_id": prior["id"]})
        elif canonical(normalized(prior)) != canonical(normalized(current)):
            left, right = normalized(prior), normalized(current)
            fields = sorted(field for field in set(left) | set(right) if canonical(left.get(field)) != canonical(right.get(field)))
            changes.append({"status": "changed", "previous_item_id": prior["id"], "source_item_id": current["id"],
                            "changed_fields": fields})
        else:
            unchanged += 1
    counts = Counter(row["status"] for row in changes)
    return {"source_id": base["source_id"], "base_snapshot_id": base_id, "latest_snapshot_id": latest_id,
            "added": counts["added"], "removed": counts["removed"], "changed": counts["changed"], "unchanged": unchanged,
            "items": changes[offset:offset + limit], "total": len(changes), "offset": offset, "limit": limit,
            "next_offset": offset + limit if offset + limit < len(changes) else None, "requests_sent": 0}


def list_sources(project, args):
    from .source_projection import list_sources as projected_sources
    result = projected_sources(project, args)
    if args.get("compare_snapshot_id") is not None:
        if not result.get("snapshot_id"):
            raise EngineError("source_snapshot_binding", "Select a saved snapshot for comparison")
        result["comparison"] = compare_snapshots(project, args["compare_snapshot_id"], result["snapshot_id"],
            offset=args.get("offset", 0), limit=args.get("limit", 25))
    return result
