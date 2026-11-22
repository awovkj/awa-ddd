"""Provider-backed discovery snapshots with explicit control-plane receipts.

This module reads already existing TscanPlus result records and converts only
the bounded, normalized clues into the same discovery envelope used by local
files.  It never starts a scan, follows a discovered URL or grants proof.
"""
from __future__ import annotations

import hashlib
import re

from . import tscanplus
from .contracts import _validate_json
from .discovery import _url
from .reporting import safe_url
from .scope import require_scope
from .store import EngineError, canonical, now


FORMAT_RESULTS = "tscanplus_results"
FORMAT_ROUTES = "tscanplus_routes"
PARSER_VERSION = 1
INGEST_ARGS = {"project_id", "source_kind", "table", "result_limit", "instance_id",
               "timeout", "mcp_url", "scanner_project", "mode", "offset", "limit"}
PUBLIC_RECEIPT_FIELDS = (
    "provider", "profile_version", "source_kind", "source_sha256",
    "server_version", "protocol_version", "catalog_sha256", "tool_name",
    "tool_schema_sha256", "input_sha256", "instance_id", "table", "reported_count",
    "reported_total", "reported_matched", "returned_count", "processed_count",
    "unretrieved_count", "truncated", "results_complete", "namespace_verified",
    "instance_verified", "remote_cursor", "remote_may_continue",
    "dispatch_attempted", "query_budget", "active_scan_started", "artifact_sha256",
    "captured_at", "capture_run_id",
)
PUBLIC_CAPTURE_FIELDS = (
    "run_id", "adapter", "action", "status", "tool_name", "catalog_sha256",
    "verification_level", "error_code", "sha256", "target_traffic_sent",
    "dispatch_attempted", "remote_may_continue", "remote_stopped_verified",
    "response_truncated", "results_complete", "parser_status", "table",
    "instance_id", "result_limit", "reported_count", "returned_rows",
    "candidate_count", "new_candidates", "duplicate_candidates",
    "out_of_scope_rows", "unmapped_rows", "unretrieved_results",
    "reported_http_status", "reported_total", "reported_matched",
    "namespace_verified", "instance_verified", "processed_rows",
    "omitted_candidates", "unsupported_rows", "asset_count",
)


def public_receipt(receipt):
    """Return only fixed provider receipt fields, never endpoints or titles."""
    if not isinstance(receipt, dict):
        return {}
    return {key: receipt[key] for key in PUBLIC_RECEIPT_FIELDS if key in receipt}


def public_capture(capture):
    """Remove remote tool descriptions, endpoints and local artifact locators."""
    if not isinstance(capture, dict):
        return {}
    return {key: capture[key] for key in PUBLIC_CAPTURE_FIELDS if key in capture}


def public_inventory(inventory):
    """Publish typed provider state with an allowlisted nested receipt."""
    if not isinstance(inventory, dict) or inventory.get("provider") != "tscanplus":
        return inventory
    allowed = {
        "provider", "provider_profile_version", "source_kind", "table",
        "result_total", "reported_count", "returned_count", "processed_count",
        "unretrieved_count", "truncated", "results_complete",
        "namespace_verified", "instance_verified", "remote_cursor",
        "control_tool_calls", "target_requests_sent", "completeness",
        "site_wide_discovery_allowed", "capture_run_id",
    }
    result = {key: inventory[key] for key in allowed if key in inventory}
    result["provider_receipt"] = public_receipt(inventory.get("provider_receipt"))
    return result


def public_sources_view(value):
    """Project saved provider source pages without endpoints or local file paths."""
    from copy import deepcopy

    if not isinstance(value, dict):
        return value
    result = deepcopy(value)

    def source_row(row):
        if isinstance(row, dict) and row.get("format") in {FORMAT_RESULTS, FORMAT_ROUTES}:
            row.pop("path", None)
            row.pop("base_url", None)

    source_row(result.get("source"))
    for row in result.get("sources") or []:
        source_row(row)
    snapshot = result.get("snapshot")
    if isinstance(snapshot, dict) and snapshot.get("format") in {FORMAT_RESULTS, FORMAT_ROUTES}:
        snapshot.pop("path", None)
        snapshot.pop("base_url", None)
        snapshot["inventory"] = public_inventory(snapshot.get("inventory"))
        if isinstance(snapshot.get("provider_receipt"), dict):
            snapshot["provider_receipt"] = public_receipt(snapshot["provider_receipt"])
    comparison = result.get("comparison")
    if isinstance(comparison, dict):
        item_fields = ("status", "previous_item_id", "source_item_id", "changed_fields")
        count_fields = ("added", "removed", "changed", "unchanged", "total", "offset", "limit",
                        "next_offset", "requests_sent")
        result["comparison"] = {
            **{key: comparison[key] for key in ("source_id", "base_snapshot_id", "latest_snapshot_id")
               if key in comparison},
            **{key: comparison[key] for key in count_fields if key in comparison},
            "items": [
                {key: row[key] for key in item_fields if key in row}
                for row in comparison.get("items") or [] if isinstance(row, dict)
            ],
        }
    return result


def _digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _arguments(args):
    if not isinstance(args, dict) or set(args) - INGEST_ARGS:
        raise EngineError(
            "tscanplus_arguments",
            "Tscan source ingestion accepts only existing-result reads and bounded source pagination",
        )
    _validate_json(args)


def _safe_name(value, secrets, fallback):
    return tscanplus._text(value, secrets) if isinstance(value, str) and value else fallback


def _method(row):
    values = [row.get(key) for key in ("method", "request_method") if key in row]
    for key in ("arguments", "args"):
        arguments = row.get(key)
        if isinstance(arguments, dict):
            values.extend(arguments[field] for field in ("method", "request_method") if field in arguments)
    return values[0] if values and all(value == values[0] for value in values) \
        and isinstance(values[0], str) and values[0] in {
            "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
        } else None


def _normalized_url(value):
    if not isinstance(value, str):
        return None, "unmapped"
    try:
        clean, _ = _url(value)
        return clean, None
    except (EngineError, UnicodeError, ValueError):
        return None, "invalid_url"


def _item(project, state, receipt, secrets, row, index, kind, table):
    target = tscanplus._route_target(row) if kind == "routes" else \
        tscanplus._row_value(row, ("url", "targeturl", "target", "scripturl"))
    clean, reason = _normalized_url(target)
    visible, url_redacted = (None, False)
    if clean is not None:
        try:
            require_scope(project.config, clean)
            scope_status = "within_scope"
        except EngineError as exc:
            scope_status = "outside_scope" if exc.code == "out_of_scope" else "scope_unknown"
        visible, url_redacted = tscanplus._public_locator(clean, secrets)
    else:
        scope_status = "unmapped"
    tool = tscanplus._row_value(row, ("tool", "toolname"))
    if kind == "routes" and tool not in tscanplus.ROUTE_TOOLS:
        scope_status = "unsupported_route_tool"
    source_sha = receipt["source_sha256"]
    base_locator = "parsed_result.data.results" if kind == "results" else "parsed_result.data.candidates"
    locator = f"{base_locator}[{index}]"
    name = _safe_name(tscanplus._row_value(row, ("name", "pocname", "vulnname", "title")),
                      secrets, "TscanPlus route suggestion" if kind == "routes" else str(table or "result"))
    category = _safe_name(tscanplus._row_value(row, ("category", "type", "vulntype")),
                          secrets, "scanner_route" if kind == "routes" else "scanner_signal")
    source = {
        "path": receipt["source_path"],
        "sha256": source_sha,
        "locator": locator,
        "trust": "untrusted_provider_output",
        "provider": "tscanplus",
        "artifact_sha256": receipt["artifact_sha256"],
        "catalog_sha256": receipt["catalog_sha256"],
        "tool_schema_sha256": receipt["tool_schema_sha256"],
        "mcp_url": state["mcp_url"],
    }
    hint = {
        "kind": "tscanplus_route" if kind == "routes" else "tscanplus_row",
        "url": visible,
        "url_redacted": url_redacted,
        "method": _method(row),
        "name": name,
        "category": category,
        "table": table,
        "instance_id": tscanplus._echo_instance(row) or receipt.get("instance_id"),
        "scope_status": scope_status,
        "unmapped_reason": reason,
        "suggested_tool": tool if kind == "routes" and isinstance(tool, str)
            and tool in tscanplus.ROUTE_TOOLS else None,
        "execution_supported": False,
        "requires_review": True,
        "status": "unverified",
        "verification_level": "hint_only",
        "hints_only": True,
        "independent_evidence_required": True,
        "usable_for_confirmation": False,
        "requestable": False,
        "native_input_requires_binding": True,
        "sources": [source],
    }
    return hint


def _inventory(capture, info, count, truncated, unretrieved, provider_receipt):
    return {
        "provider": "tscanplus",
        "provider_profile_version": PARSER_VERSION,
        "source_kind": provider_receipt["source_kind"],
        "table": provider_receipt.get("table"),
        "result_total": count,
        "reported_count": provider_receipt.get("reported_count"),
        "returned_count": provider_receipt.get("returned_count"),
        "processed_count": provider_receipt.get("processed_count"),
        "unretrieved_count": unretrieved,
        "truncated": truncated,
        "results_complete": bool(provider_receipt.get("results_complete")),
        "remote_cursor": None,
        "namespace_verified": bool(provider_receipt.get("namespace_verified")),
        "instance_verified": bool(provider_receipt.get("instance_verified")),
        "control_tool_calls": 1,
        "target_requests_sent": 0,
        "completeness": "provider_inventory",
        "site_wide_discovery_allowed": False,
        "provider_receipt": provider_receipt,
        "capture_run_id": capture["run_id"],
    }


def _limitations(info, count, omitted):
    rows = []
    if not info.get("namespace_verified"):
        rows.append({"code": "tscanplus_namespace_echo_missing", "locator": "#",
                     "message": "The provider response did not bind itself to the requested namespace."})
    if info.get("instance_id") and not info.get("instance_verified"):
        rows.append({"code": "tscanplus_instance_echo_missing", "locator": "#",
                     "message": "The provider response did not bind rows to the requested instance."})
    if info.get("truncated") is True:
        rows.append({"code": "tscanplus_results_truncated", "locator": "#",
                     "message": "The provider explicitly marked this result page truncated."})
    if info.get("complete") is False:
        rows.append({"code": "tscanplus_results_incomplete", "locator": "#",
                     "message": "The provider explicitly marked this result collection incomplete."})
    if omitted:
        rows.append({"code": "tscanplus_rows_omitted", "locator": "#",
                     "message": "Rows beyond the bounded per-capture collection limit were not ingested."})
    rows.append({"code": "tscanplus_provider_clues_are_not_proof", "locator": "#",
                 "message": "Scanner records are untrusted discovery clues; they do not confirm findings, authorization or site-wide completeness."})
    return rows[:2000]


def active_capability():
    """Return the current active-discovery gate without contacting a scanner."""
    return {
        "profile": "active_web_discovery",
        "available": False,
        "missing_capabilities": [
            "explicit_outbound_request_budget",
            "scope_enforced_redirect_policy",
            "reliable_remote_cancel_receipt",
            "complete_remote_task_status",
            "cursor_or_unretrieved_result_contract",
        ],
        "scanner_invoked": False,
        "target_requests_sent": 0,
        "automatic_execution_allowed": False,
    }


def ingest(project, args):
    """Read one existing result profile and save it in the shared source ledger."""
    _arguments(args)
    from .workflow import page_args

    mode = args.get("mode", "apply")
    if not isinstance(mode, str) or mode not in {"preview", "apply"}:
        raise EngineError("source_import_mode", "tool.tscanplus_ingest mode must be preview or apply")
    page_args(args)
    kind = args.get("source_kind", "results")
    capture_args = {key: value for key, value in args.items() if key in tscanplus.SOURCE_CAPTURE_ARGS - {"project_id"}}
    capture, document, parsed_result, info, state = tscanplus.capture_source(project, capture_args)
    secrets = tscanplus._secrets({"result": document.get("result"), "parsed_result": parsed_result})
    source_kind = "routes" if kind == "routes" else "results"
    table = None if source_kind == "routes" else info.get("table", args.get("table", "urlscan"))
    server = document.get("initialize", {}).get("serverInfo", {})
    selected = document.get("selected_tool", {})
    input_values = document.get("arguments", {})
    omitted = int(info.get("omitted_count", 0) or 0)
    unretrieved = max(int(capture.get("unretrieved_results") or 0),
                      int(capture.get("reported_count") or 0) - int(capture.get("returned_rows") or 0),
                      omitted)
    source_path = "tscanplus://" + "/".join([
        _digest(state["mcp_url"])[:16],
        state["scanner_project"],
        source_kind,
        str(table or "routes"),
    ])
    receipt = {
        "provider": "tscanplus",
        "profile_version": PARSER_VERSION,
        "source_kind": source_kind,
        "source_path": source_path,
        "server_name": server.get("name"),
        "server_version": server.get("version"),
        "protocol_version": document.get("initialize", {}).get("protocolVersion"),
        "mcp_url": state["mcp_url"],
        "scanner_project": state["scanner_project"],
        "catalog_sha256": state["catalog_sha256"],
        "tool_name": capture["tool_name"],
        "tool_schema_sha256": _digest(selected.get("inputSchema")),
        "input_sha256": _digest(input_values),
        "instance_id": args.get("instance_id"),
        "table": table,
        "reported_count": capture.get("reported_count"),
        "reported_total": capture.get("reported_total"),
        "reported_matched": capture.get("reported_matched"),
        "returned_count": capture.get("returned_rows"),
        "processed_count": info.get("processed_count", capture.get("returned_rows")),
        "unretrieved_count": unretrieved,
        "truncated": capture.get("response_truncated"),
        "results_complete": capture.get("results_complete") is True,
        "namespace_verified": capture.get("namespace_verified") is True,
        "instance_verified": capture.get("instance_verified") is True,
        "remote_cursor": None,
        "remote_may_continue": capture.get("remote_may_continue") is True,
        "dispatch_attempted": capture.get("dispatch_attempted") is True,
        "query_budget": {
            "control_tool_calls": 1,
            "target_requests": 0,
            "result_limit": int(args.get("result_limit", 25)),
            "timeout_seconds": args.get("timeout", 30),
        },
        "active_scan_started": False,
        "artifact_path": capture.get("artifact_path"),
        "artifact_sha256": capture.get("sha256"),
        "captured_at": now(),
        "capture_run_id": capture["run_id"],
    }
    safe_rows = []
    for index, row in enumerate(info.get("rows", [])):
        safe_rows.append(_item(project, state, {**receipt, "source_sha256": ""},
                               secrets, row, index, source_kind, table))
    # The item identity includes the source digest.  Hash the bounded normalized
    # rows and provider receipt first, then fill the digest into each source.
    digest_material = {"provider_receipt": receipt, "items": safe_rows}
    source_sha = _digest(digest_material)
    receipt["source_sha256"] = source_sha
    for index, hint in enumerate(safe_rows):
        hint["sources"][0]["sha256"] = source_sha
    raw = canonical(digest_material).encode("utf-8")
    envelope = {
        "source": {
            "path": source_path,
            "sha256": source_sha,
            "byte_count": len(raw),
            "format": FORMAT_ROUTES if source_kind == "routes" else FORMAT_RESULTS,
            "parser_version": PARSER_VERSION,
        },
        "operations": [],
        "candidates": safe_rows,
        "limitations": _limitations(info, len(safe_rows), omitted),
        "inventory": _inventory(capture, info, len(safe_rows), omitted or
                                capture.get("response_truncated") is True, unretrieved, receipt),
        "provider_receipt": receipt,
    }
    from .source_inventory import import_parsed

    import_args = {key: value for key, value in args.items() if key in {"offset", "limit"}}
    import_args["mode"] = mode
    imported = import_parsed(project, envelope, import_args)
    return {
        **imported,
        "provider": "tscanplus",
        "provider_receipt": public_receipt(receipt),
        "provider_capture": public_capture(capture),
        "control_tool_calls": 1,
        "target_requests_sent": 0,
        "scanner_invoked": False,
        "active_capability": active_capability(),
        "trust": "untrusted_provider_output",
        "usable_for_confirmation": False,
        "automatic_execution_allowed": False,
    }
