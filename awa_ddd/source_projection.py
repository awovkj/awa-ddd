"""SQL source pages, with incremental updates for changed ledger bindings.

This read model never authorizes proof or completion. Strong source consumers
use source_inventory.inventory, which authenticates the immutable manifests.
"""
from __future__ import annotations

import base64
from collections import Counter
import hashlib
import json

from .store import EngineError, canonical

NAME = "source.inventory/v1"
KINDS = ("operation", "candidate", "discovery_source", "discovery_snapshot", "discovery_item", "discovery_ingest")


def _config_key(project):
    return hashlib.sha256(canonical([project.config.get("scope"), project.config.get("exclude")]).encode("utf-8")).hexdigest()


def _keys(project, item, operations, state):
    from .source_inventory import _operation_id, _candidate
    operation_key = _operation_id(item["hint"]) if item["item_kind"] == "operation" else None
    candidate_key = state.get("candidate_id")
    if item["item_kind"] == "candidate":
        candidate_key = _candidate(project, item)[1]
    return operation_key, candidate_key


def _row(project, item, operations, state, position):
    from .source_inventory import _route_key
    operation, candidate = _keys(project, item, operations, state)
    route = _route_key(item["hint"]) or (None, None)
    return (item["id"], item["source_id"], item["snapshot_id"], position, state["status"],
            int(state["pending_import"]), int(state["current_snapshot"]), int(state["needs_binding"]),
            operation, candidate, route[0], route[1], canonical(state))


def _source_rows(project, metadata):
    rows = []
    for position, source in enumerate(project.list("discovery_source")):
        snapshots = project.connection.execute(
            "SELECT id,json_remove(document,'$.item_ids') FROM entities WHERE kind='discovery_snapshot' "
            "AND json_extract(document,'$.source_id')=?", (source["id"],)).fetchall()
        latest = next((json.loads(row[1]) for row in snapshots if row[0] == source.get("latest_snapshot_id")), None)
        grouped = project.connection.execute("SELECT status,COUNT(*) FROM source_projection_items WHERE source_id=? GROUP BY status",
                                             (source["id"],)).fetchall()
        counts = {row[0]: row[1] for row in grouped}
        totals = project.connection.execute("SELECT COUNT(*),COALESCE(SUM(pending_import),0),"
            "COALESCE(SUM(pending_import AND NOT current_snapshot),0),COALESCE(SUM(needs_binding),0) "
            "FROM source_projection_items WHERE source_id=?", (source["id"],)).fetchone()
        missing = sum(metadata["snapshot_issues"].get(row[0], 0) for row in snapshots)
        source_issue = metadata["source_issues"].get(source["id"], 0)
        view = {"source_id": source["id"], "snapshot_id": latest["id"] if latest else None,
                **{key: source[key] for key in ("format", "path", "base_url") if key in source},
                **{key: latest[key] for key in ("sha256", "parser_version") if latest and key in latest},
                "snapshot_integrity": "missing" if latest is None else "changed" if metadata["snapshot_issues"].get(latest["id"]) else "valid",
                "missing_item_total": missing + source_issue,
                "snapshot_total": len(snapshots), "source_item_total": totals[0] + missing,
                "pending_import_total": totals[1] + missing, "historical_pending_total": totals[2],
                "needs_binding_total": totals[3], "counts": counts, "next_action": "surface.sources"}
        if latest is None:
            view["reason_code"] = "source_snapshot_missing"
        rows.append((source["id"], position, canonical(view)))
    project.connection.execute("DELETE FROM source_projection_sources")
    project.connection.executemany("INSERT INTO source_projection_sources VALUES(?,?,?)", rows)


def _summary(project, previous):
    totals = project.connection.execute("SELECT COUNT(*),COALESCE(SUM(pending_import),0),COALESCE(SUM(needs_binding),0),"
        "COALESCE(SUM(pending_import AND NOT current_snapshot),0) FROM source_projection_items").fetchone()
    routes = project.connection.execute("SELECT COUNT(*) FROM (SELECT route_url,route_method FROM source_projection_items "
        "WHERE route_url IS NOT NULL GROUP BY route_url,route_method)").fetchone()[0]
    registered = project.connection.execute("SELECT COUNT(*) FROM (SELECT route_url,route_method FROM source_projection_items s "
        "WHERE route_url IS NOT NULL AND EXISTS (SELECT 1 FROM entities e WHERE e.kind='operation' "
        "AND json_extract(e.document,'$.url')=s.route_url AND json_extract(e.document,'$.method')=s.route_method) "
        "GROUP BY route_url,route_method)").fetchone()[0]
    counts = dict(project.connection.execute("SELECT status,COUNT(*) FROM source_projection_items GROUP BY status").fetchall())
    missing = sum(previous["snapshot_issues"].values())
    summary = dict(previous["summary"])
    summary.update(source_item_total=totals[0] + missing, known_route_total=routes, registered_route_total=registered,
                   known_not_registered_total=routes - registered, pending_import_total=totals[1] + missing,
                   needs_binding_total=totals[2], historical_pending_total=totals[3],
                   conflict_total=counts.get("conflict", 0), rejected_total=counts.get("rejected", 0),
                   candidate_total=counts.get("candidate", 0))
    return summary


def ensure(project, *, rebuild=False):
    from .source_inventory import inventory, _item_state, _operation_id
    with project.transaction():
        generation, config_key = project.generation(KINDS), _config_key(project)
        stored = project.connection.execute("SELECT generation,document FROM projection_store WHERE name=? AND schema_version=1", (NAME,)).fetchone()
        previous = json.loads(stored[1]) if stored else None
        if not rebuild and previous and stored[0] == generation and previous.get("config_key") == config_key:
            return previous
        changes = project.connection.execute("SELECT kind,id FROM entity_changes WHERE seq>? AND kind IN (" +
            ",".join("?" for _ in KINDS) + ")", (stored[0], *KINDS)).fetchall() if stored else []
        incremental = bool(not rebuild and previous and previous.get("config_key") == config_key and changes
                           and all(row[0] in {"operation", "candidate", "discovery_ingest"} for row in changes))
        affected = set()
        if incremental:
            for kind, identity in changes:
                column = {"operation": "operation_key", "candidate": "candidate_key", "discovery_ingest": "id"}[kind]
                affected.update(row[0] for row in project.connection.execute(
                    "SELECT id FROM source_projection_items WHERE " + column + "=?", (identity,)).fetchall())
            for identity in sorted(affected):
                item = project.get("discovery_item", identity)
                operation_key = _operation_id(item["hint"]) if item["item_kind"] == "operation" else None
                operation = project.get("operation", operation_key, required=False) if operation_key else None
                operations = {operation_key: operation} if operation else {}
                old = project.connection.execute("SELECT position,current_snapshot FROM source_projection_items WHERE id=?", (identity,)).fetchone()
                state = {"id": identity, "source_id": item["source_id"], "snapshot_id": item["snapshot_id"],
                         "item_kind": item["item_kind"], "hint": item["hint"], "current_snapshot": bool(old[1]),
                         **_item_state(project, item, operations)}
                project.connection.execute("INSERT OR REPLACE INTO source_projection_items VALUES(" + ",".join("?" for _ in range(13)) + ")",
                                           _row(project, item, operations, state, old[0]))
            previous["summary"] = _summary(project, previous)
            previous["work"] = {"mode": "incremental", "items_rebuilt": len(affected)}
        else:
            current = inventory(project)
            operations = {row["id"]: row for row in project.list("operation")}
            project.connection.execute("DELETE FROM source_projection_items")
            project.connection.executemany("INSERT INTO source_projection_items VALUES(" + ",".join("?" for _ in range(13)) + ")",
                [_row(project, state, operations, state, position) for position, state in enumerate(current["items"])])
            previous = {"summary": current["summary"], "snapshot_issues": current["snapshot_issues"],
                        "source_issues": current["source_issues"], "config_key": config_key,
                        "work": {"mode": "rebuild", "items_rebuilt": len(current["items"])}}
        _source_rows(project, previous)
        previous["generation"] = generation
        project.projection_put(NAME, generation, previous)
        return previous


def _page(project, table, where, params, args, generation):
    from .workflow import page_args
    offset, limit = page_args(args)
    key = hashlib.sha256(canonical([project.project_id, table, where, params]).encode("utf-8")).hexdigest()
    after = None
    if args.get("cursor") is not None:
        try:
            token = json.loads(base64.urlsafe_b64decode(args["cursor"].encode("ascii")))
            if token["query"] != key or token["generation"] != generation:
                raise EngineError("cursor_stale", "Source facts changed; restart this page")
            after, offset = token["after"], token["offset"]
            if type(after) is not int or type(offset) is not int or min(after, offset) < 0:
                raise ValueError("cursor")
        except EngineError:
            raise
        except (ValueError, TypeError, KeyError, UnicodeError, AttributeError):
            raise EngineError("cursor_invalid", "Invalid source query cursor") from None
    total = project.connection.execute("SELECT COUNT(*) FROM " + table + " WHERE " + where, params).fetchone()[0]
    page_where, page_params = where, list(params)
    if after is not None:
        page_where += " AND position>?"
        page_params.append(after)
    sql = "SELECT document,position FROM " + table + " WHERE " + page_where + " ORDER BY position LIMIT ?"
    page_params.append(limit + 1)
    if after is None:
        sql += " OFFSET ?"
        page_params.append(offset)
    rows = project.connection.execute(sql, page_params).fetchall()
    more, rows = len(rows) > limit, rows[:limit]
    next_offset = offset + len(rows) if more else None
    cursor = base64.urlsafe_b64encode(canonical({"query": key, "generation": generation, "offset": next_offset,
        "after": rows[-1][1]}).encode("utf-8")).decode("ascii") if more else None
    return {"items": [json.loads(row[0]) for row in rows], "total": total, "offset": offset, "limit": limit,
            "next_offset": next_offset, "cursor": cursor, "projection_revision": generation}


def list_sources(project, args):
    from .source_inventory import STATUSES, _item_view
    status = args.get("status", "any")
    if not isinstance(status, str) or status not in STATUSES | {"any"}:
        raise EngineError("source_status", "Unsupported source inventory status")
    with project.transaction():
        metadata = ensure(project)
        source_id, snapshot_id = args.get("source_id"), args.get("snapshot_id")
        snapshot = None
        if snapshot_id is not None:
            row = project.connection.execute("SELECT json_remove(document,'$.item_ids') FROM entities WHERE kind='discovery_snapshot' AND id=?", (snapshot_id,)).fetchone()
            snapshot = json.loads(row[0]) if row else None
            bound = snapshot["source_id"] if snapshot else next((row[0] for row in project.connection.execute(
                "SELECT id FROM entities WHERE kind='discovery_source' AND json_extract(document,'$.latest_snapshot_id')=?", (snapshot_id,))), None)
            if bound is None:
                project.get("discovery_snapshot", snapshot_id)
            if source_id is not None and source_id != bound:
                raise EngineError("source_snapshot_binding", "snapshot_id must belong to source_id")
            source_id = bound
        result = {"source_inventory": metadata["summary"], "requests_sent": 0, "automatic_execution_allowed": False,
                  "usable_for_confirmation": False, "status": status}
        if source_id is not None:
            source = project.get("discovery_source", source_id)
            snapshot_id = snapshot_id or source.get("latest_snapshot_id")
            if snapshot is None:
                row = project.connection.execute("SELECT json_remove(document,'$.item_ids') FROM entities WHERE kind='discovery_snapshot' AND id=?", (snapshot_id,)).fetchone()
                snapshot = json.loads(row[0]) if row else None
            where, params = "snapshot_id=?", [snapshot_id]
            if status != "any":
                where += " AND " + ("pending_import=1" if status == "pending_import" else "status=?")
                if status != "pending_import":
                    params.append(status)
            window = _page(project, "source_projection_items", where, params, args, metadata["generation"])
            if snapshot is None:
                source = {**source, "latest_snapshot_id": None}
                result["reason_code"] = "source_snapshot_missing"
            result.update(source_id=source_id, snapshot_id=snapshot["id"] if snapshot else None, source=source,
                          snapshot=snapshot, items=[_item_view(row) for row in window.pop("items")],
                          snapshot_integrity="missing" if snapshot is None else "changed" if metadata["snapshot_issues"].get(snapshot_id) else "valid",
                          missing_item_total=metadata["snapshot_issues"].get(snapshot_id, 0) if snapshot else 1, **window)
        else:
            where, params = "1=1", []
            if status == "pending_import":
                where = "(json_extract(document,'$.pending_import_total')>0 OR json_extract(document,'$.missing_item_total')>0)"
            elif status != "any":
                where = "json_extract(document,?)>0"
                params = ["$.counts." + status]
            window = _page(project, "source_projection_sources", where, params, args, metadata["generation"])
            result.update(sources=window.pop("items"), **window)
        result["next_action"] = "surface.sources"
        return result
