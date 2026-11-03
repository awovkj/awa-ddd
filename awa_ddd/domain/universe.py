"""Universe: the versioned, source-bound inventory of the authorized surface.

A Universe never claims to know the true unknown attack surface.  It records
what was observed, where it came from, and how complete that source was; any
percentage is scoped to that known denominator and site-wide discovery is
disabled unless a trusted, complete source inventory was imported.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from .common import digest, enum, integer, mapping, optional_text, sequence, stable_id, text, utc_now

SOURCE_KINDS = {"scope_declaration", "registered_operation", "page_ledger", "imported_route",
                "imported_operation", "runtime_observation", "manual_declaration"}
COMPLETENESS_LEVELS = {"declared_only", "source_inventory", "complete_snapshot"}
CONSUMER_STATUSES = {"declared", "inferred", "unknown"}


def _route_template(url):
    path = urlsplit(url).path or "/"
    # Concrete IDs/numbers become dynamic segments for template grouping; the
    # unmodified URL remains on the page/operation record.
    parts = []
    dynamic = []
    for segment in path.split("/"):
        if not segment:
            continue
        if segment.isdigit() or (len(segment) >= 16 and all(c in "0123456789abcdefABCDEF-" for c in segment)):
            dynamic.append(segment)
            parts.append("{id}")
        elif segment.startswith(":") or (segment.startswith("{") and segment.endswith("}")):
            dynamic.append(segment)
            parts.append(segment if segment.startswith("{") else "{" + segment[1:] + "}")
        else:
            parts.append(segment)
    return "/" + "/".join(parts), dynamic


def new_universe(*, scope_epoch, origins, routes, pages, functions, operations, inputs,
                 consumers, sources, unknown_counts, completeness_level="declared_only"):
    enum(completeness_level, "completeness_level", COMPLETENESS_LEVELS)
    document = {
        "schema": 2,
        "version": 1,
        "scope_epoch": text(scope_epoch, "scope_epoch", maximum=256),
        "origins": sequence(origins, "origins", maximum=256),
        "routes": sequence(routes, "routes", maximum=200000),
        "pages": sequence(pages, "pages", maximum=200000),
        "functions": sequence(functions, "functions", maximum=200000),
        "operations": sequence(operations, "operations", maximum=200000),
        "inputs": sequence(inputs, "inputs", maximum=500000),
        "consumers": sequence(consumers, "consumers", maximum=500000),
        "sources": sequence(sources, "sources", maximum=1024),
        "unknown_counts": mapping(unknown_counts, "unknown_counts"),
        "completeness_level": completeness_level,
        "site_wide_discovery_allowed": completeness_level == "complete_snapshot",
        "created_at": utc_now(),
        "limitations": [],
    }
    document["snapshot_hash"] = digest({key: document[key] for key in (
        "scope_epoch", "origins", "routes", "pages", "functions", "operations", "inputs",
        "consumers", "sources", "unknown_counts", "completeness_level")})
    document["id"] = stable_id("UNI", document["snapshot_hash"])
    return document


def route_record(*, path_template, source_kind, source_ref, dynamic_params=None,
                 page_ids=None, operation_ids=None, limitations=None, aliases=None,
                 redirect=None, catch_all=False, lazy=False, unresolved=False):
    enum(source_kind, "route_source_kind", SOURCE_KINDS)
    path_template = text(path_template, "path_template", maximum=2048)
    record = {
        "route_id": stable_id("R", {"path": path_template, "source": source_kind, "ref": source_ref}),
        "path_template": path_template,
        "dynamic_params": sequence(dynamic_params or [], "dynamic_params", maximum=64),
        "source_kind": source_kind,
        "source_ref": source_ref,
        "page_ids": sequence(page_ids or [], "page_ids", maximum=1024),
        "operation_ids": sequence(operation_ids or [], "operation_ids", maximum=4096),
        "aliases": sequence(aliases or [], "aliases", maximum=64),
        "redirect": optional_text(redirect, "redirect", maximum=2048),
        "catch_all": bool(catch_all),
        "lazy": bool(lazy),
        "unresolved": bool(unresolved),
        "limitations": sequence(limitations or [], "limitations", maximum=64),
    }
    return record


def operation_record(operation, consumers=None):
    consumers = consumers if consumers is not None else []
    inputs = []
    for entry in operation.get("inputs", []) if isinstance(operation.get("inputs"), list) else []:
        if not isinstance(entry, dict):
            continue
        consumer = str(entry.get("consumer") or "").strip()
        status = "unknown" if consumer.lower() in {"", "unknown", "other", "untraced", "unspecified"} else "declared"
        key = stable_id("IN", {"operation": operation["id"], "location": entry.get("location"),
                               "selector": entry.get("selector", entry.get("name")),
                               "branch": entry.get("schema_branch")})
        inputs.append({
            "input_key": key,
            "operation_id": operation["id"],
            "name": entry.get("name"),
            "location": entry.get("location"),
            "selector": entry.get("selector", entry.get("name")),
            "schema_branch": entry.get("schema_branch"),
            "consumer": consumer or None,
            "consumer_status": status,
            "test_families": list(entry.get("test_families") or []),
            "source_kind": "registered_operation",
        })
        consumers.append({
            "input_key": key,
            "consumer": consumer or None,
            "status": status,
            "source": "registered_operation",
        })
    template, dynamic = _route_template(operation["url"])
    return {
        "operation_id": operation["id"],
        "method": operation.get("method"),
        "url_template": template,
        "protocol": operation.get("protocol", "http"),
        "auth": operation.get("auth"),
        "operation_signature": None,
        "dynamic_segments": dynamic,
        "inputs": inputs,
        "source_kind": "registered_operation",
    }


def page_record(page):
    template, dynamic = _route_template(page.get("url", ""))
    functions = []
    for function in page.get("functions", []) if isinstance(page.get("functions"), list) else []:
        if isinstance(function, dict) and function.get("id"):
            functions.append({
                "function_id": function["id"],
                "page_id": page["id"],
                "name": function.get("name"),
                "trigger": function.get("trigger"),
                "source_kind": "page_ledger",
            })
    return {
        "page_id": page["id"],
        "url": page.get("url"),
        "name": page.get("name"),
        "route_template": template,
        "dynamic_segments": dynamic,
        "functions": functions,
        "source_kind": "page_ledger",
    }


def summary(universe):
    return {
        "id": universe.get("id"),
        "version": universe.get("version"),
        "snapshot_hash": universe.get("snapshot_hash"),
        "completeness_level": universe.get("completeness_level"),
        "site_wide_discovery_allowed": bool(universe.get("site_wide_discovery_allowed")),
        "origin_total": len(universe.get("origins", [])),
        "route_total": len(universe.get("routes", [])),
        "page_total": len(universe.get("pages", [])),
        "function_total": len(universe.get("functions", [])),
        "operation_total": len(universe.get("operations", [])),
        "input_total": len(universe.get("inputs", [])),
        "consumer_total": len(universe.get("consumers", [])),
        "unknown_counts": dict(universe.get("unknown_counts", {})),
    }
