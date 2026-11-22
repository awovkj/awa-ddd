"""One information baseline from existing authorized material, never a crawler."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from urllib.parse import urljoin, urlsplit

from . import browser, engine
from .reporting import safe_url
from .scope import bind_operation, origin, require_scope
from .store import EngineError, canonical, now


SECTIONS = ("overview", "technologies", "functions", "clues", "collection", "hypotheses")
MAX_OBSERVATIONS = 1000
MAX_CLUES = 2000
MAX_BODY_BYTES = 262144
MAX_INPUT_PREVIEW = 10
MAX_API_REFERENCES = 100
WORKFLOW = ("scope_and_identity", "pages_assets_and_api_sources", "functions_and_inputs",
            "information_baseline", "targeted_hypotheses")


def _material_fingerprint(project, mode):
    """Fingerprint only material that can affect the selected recon projection."""
    with project._lock:
        evidence_rows = project.connection.execute(
            """SELECT kind,id,
                      json_extract(document,'$.artifact_path'),
                      json_extract(document,'$.sha256')
                 FROM (
                    SELECT kind,id,document,created_at,rowid
                      FROM entities
                     WHERE kind='evidence' AND json_extract(document,'$.kind')='http'
                     ORDER BY created_at DESC,rowid DESC
                     LIMIT ?
                 )
                ORDER BY created_at,rowid""",
            (MAX_OBSERVATIONS,),
        ).fetchall() if mode == "aggregate" else []
        visit_rows = project.connection.execute(
            """WITH refs(id) AS (
                   SELECT json_extract(document,'$.page_visit_id') FROM entities
                    WHERE kind='page' AND json_type(document,'$.page_visit_id')='text'
                   UNION SELECT json_extract(document,'$.visit_id') FROM entities
                    WHERE kind='page' AND json_type(document,'$.visit_id')='text'
                   UNION SELECT json_extract(function.value,'$.page_visit_id')
                     FROM entities,json_each(entities.document,'$.functions') AS function
                    WHERE entities.kind='page'
                      AND json_type(entities.document,'$.functions')='array'
                      AND json_type(function.value,'$.page_visit_id')='text'
                   UNION SELECT json_extract(function.value,'$.visit_id')
                     FROM entities,json_each(entities.document,'$.functions') AS function
                    WHERE entities.kind='page'
                      AND json_type(entities.document,'$.functions')='array'
                      AND json_type(function.value,'$.visit_id')='text'
               )
               SELECT visit.kind,visit.id,
                      json_extract(visit.document,'$.artifact_path'),
                      json_extract(visit.document,'$.sha256')
                 FROM entities AS visit JOIN refs ON refs.id=visit.id
                WHERE visit.kind='page_visit'
                ORDER BY visit.id"""
        ).fetchall()
    rows = [*evidence_rows, *visit_rows]
    entries = []
    for kind, identity, path, digest in rows:
        metadata = None
        if isinstance(path, str) and path:
            try:
                stat = (project.base / path).stat(follow_symlinks=False)
                metadata = [stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]
            except OSError:
                metadata = None
        entries.append([kind, identity, digest, metadata])
    project.metrics["artifact_stats"] = project.metrics.get("artifact_stats", 0) + len(entries)
    return hashlib.sha256(canonical(entries).encode("utf-8")).hexdigest()


def _arguments(args):
    if not isinstance(args, dict):
        raise EngineError("arguments", "surface.recon input must be an object")
    if set(args) - {"project_id", "mode", "section", "offset", "limit", "refresh"}:
        raise EngineError("arguments", "surface.recon accepts only mode, section, offset, limit and refresh")
    if type(args.get("refresh", False)) is not bool:
        raise EngineError("arguments", "refresh must be a boolean")
    mode, section = args.get("mode", "prepare"), args.get("section", "overview")
    offset, limit = args.get("offset", 0), args.get("limit", 10)
    if mode not in ("prepare", "aggregate") or section not in SECTIONS:
        raise EngineError("arguments", "mode must be prepare or aggregate; use action.help for sections")
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 50:
        raise EngineError("pagination", "offset must be nonnegative and limit must be 1..50")
    return mode, section, offset, limit


def _scoped(config, url):
    try:
        return require_scope(config, url)
    except (EngineError, TypeError, ValueError):
        return None


def _inventory_scope(config, operation):
    if _scoped(config, operation.get("url")):
        return True
    # A sanitized query-free inventory row can still need exact scope binding.
    # It is metadata only; actual observations below require the complete URL.
    from .workflow import _query_scope_binding_possible

    return _query_scope_binding_possible(config, operation.get("url"))


def _task(kind, action, reason, *, operation=None, page=None, function=None):
    template = {}
    row = {"kind": kind, "action": action, "reason": reason,
           "automatic_execution_allowed": False, "locator_requires_binding": True,
           "required_input_fields": [], "input_template": template}
    if operation:
        row.update(operation_id=operation["id"], url=safe_url(operation["url"]))
        template["operation_id"] = operation["id"]
    if page:
        row.update(page_id=page["id"], url=safe_url(page["url"]))
        template["page_id"] = page["id"]
    if function:
        row["function_id"] = function["id"]
    if action == "http.preflight":
        row["required_input_fields"] = ["exact_authorized_url", "verified_identity_if_required",
                                        "fixture_and_write_authorization_if_required"]
    elif action == "browser.import_mcp":
        # Only an import is named, not a guessed host tool or an executable URL.
        template.clear()
        row["required_input_fields"] = ["actual_authorized_playwright_observation_path"]
    elif action == "surface.inspect":
        row["required_input_fields"] = ["actual_access_policy_and_input_consumer"]
    return row


def _api_function(operation, observed):
    inputs = operation.get("inputs") if isinstance(operation.get("inputs"), list) else []
    valid = [entry for entry in inputs if isinstance(entry, dict)]
    unknown = [entry for entry in valid if str(entry.get("consumer") or "").strip().lower()
               in {"", "unknown", "other", "untraced", "unspecified"}]
    families = sorted({family for entry in valid if isinstance(entry.get("test_families"), list)
                       for family in entry["test_families"] if family in engine.TEST_FAMILIES})
    return {"kind": "api_operation", "operation_id": operation["id"], "url": safe_url(operation["url"]),
            "name": operation.get("operation_name") or urlsplit(operation["url"]).path,
            "method": operation.get("method"), "auth": operation.get("auth"),
            "input_total": len(inputs), "unknown_consumer_total": len(unknown),
            "inputs": [{key: entry.get(key) for key in ("name", "location", "selector", "consumer", "schema_branch")}
                       for entry in valid[:MAX_INPUT_PREVIEW]],
            "inputs_preview_truncated": len(inputs) > MAX_INPUT_PREVIEW,
            "declared_test_families": families,
            "observation_state": "observed" if operation["id"] in observed else "not_observed",
            "detail_action": "surface.inspect", "testing_action": "plan.next",
            "locator_requires_binding": True, "profile_is_security_evidence": False}


def _fact_key(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _function_key(row, by_operation):
    value = {key: row.get(key) for key in ("kind", "operation_id", "page_id", "function_id", "name",
        "trigger", "apis", "operation_ids", "observation_state", "interaction_state")}
    operation = by_operation.get(row.get("operation_id"))
    if operation:
        value["policy"] = {key: operation.get(key) for key in
            ("method", "protocol", "auth", "allowed_roles", "ownership", "state_scope", "content_type")}
        value["inputs"] = [{key: entry.get(key) for key in ("name", "location", "selector", "consumer",
            "schema_branch", "test_families", "schema_type", "required")}
            for entry in operation.get("inputs", []) if isinstance(entry, dict)]
    return _fact_key(value)


def _function_apis(config, page, function, by_operation, registered_ids):
    references = function.get("apis")
    references = references if isinstance(references, list) else []
    urls, operations, rejected = [], [], 0
    for value in references[:MAX_API_REFERENCES]:
        if not isinstance(value, str):
            rejected += 1
        elif value in registered_ids or re.fullmatch(r"O-[a-f0-9]{24,32}", value):
            if value in by_operation:
                operations.append(value)
            else:
                rejected += 1
        else:
            try:
                url = _scoped(config, urljoin(page["url"], value))
            except (TypeError, ValueError):
                url = None
            if url:
                urls.append(safe_url(url))
            else:
                rejected += 1
    return sorted(set(urls)), sorted(set(operations)), rejected, len(references) > MAX_API_REFERENCES


def _clue_bindings(clue, url, operations):
    method = clue.get("method")
    if method is None and clue["kind"] in {"link", "script"}:
        method = "GET"
    matches = []
    if method:
        for operation in operations:
            if operation.get("method") != method:
                continue
            try:
                bind_operation(operation, url, method)
                matches.append(operation)
            except (EngineError, TypeError, ValueError):
                pass
    declared = {(entry.get("location"), entry.get("selector")) for row in matches
                for entry in row.get("inputs", []) if isinstance(entry, dict)}
    fields = {(entry.get("location"), entry.get("selector")) for entry in clue["inputs"]}
    unmapped = len(fields - declared)
    return [row["id"] for row in matches], unmapped


def _html_source(headers, body):
    entries = headers.items() if isinstance(headers, dict) else headers if isinstance(headers, (list, tuple)) else []
    for pair in list(entries)[:64]:
        if isinstance(pair, (list, tuple)) and len(pair) == 2 and str(pair[0]).lower() == "content-type":
            return str(pair[1]).partition(";")[0].strip().lower() in {"text/html", "application/xhtml+xml"}
    prefix = body[:512].lstrip().lower()
    return prefix.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<form"))


def _save_baseline(project, semantic, technology_keys, function_keys, clue_keys):
    fingerprint = _fact_key(semantic)
    previous = project.list("recon_baseline")
    last = previous[-1] if previous else None
    changed = last is None or last.get("fingerprint") != fingerprint
    keys = {"technology": sorted(technology_keys), "function": sorted(function_keys), "clue": sorted(clue_keys)}
    delta = {}
    for name, current in keys.items():
        old = set((last or {}).get("fact_keys", {}).get(name, []))
        delta["new_" + name + "_total"] = len(set(current) - old)
        delta["removed_" + name + "_total"] = len(old - set(current))
    if changed:
        record = {"id": project.id("RC"), "fingerprint": fingerprint, "fact_keys": keys,
                  "created_at": now(), "profile_is_security_evidence": False}
        project.put("recon_baseline", record, create_only=True)
    else:
        record = last
    # Small private semantic hashes are NOT public digests of possible secrets.
    return record["id"], not changed, changed, delta


def _build(project, mode):
    from .recon_parsing import parse_response

    config = project.config
    registered = project.list("operation")
    registered_ids = {row["id"] for row in registered}
    operations = [row for row in registered if _inventory_scope(config, row)]
    by_operation = {row["id"]: row for row in operations}
    all_pages = project.list("page")
    pages = [row for row in all_pages if _scoped(config, row.get("url"))]
    with project._lock:
        evidence_total = project.connection.execute("SELECT COUNT(*) FROM entities WHERE kind='evidence' AND json_extract(document,'$.kind')='http'").fetchone()[0]
        evidence_rows = project.connection.execute("SELECT document FROM entities WHERE kind='evidence' AND json_extract(document,'$.kind')='http' "
            "ORDER BY created_at DESC,rowid DESC LIMIT ?", (MAX_OBSERVATIONS,)).fetchall() if mode == "aggregate" else []
    all_evidence = [json.loads(row[0]) for row in reversed(evidence_rows)]
    technologies, clues, html_sources, observed, unusable = {}, {}, {}, set(), 0
    observed_evidence_by_operation = {}
    out_of_scope_clues = omitted_clues = parse_errors = processed = truncated = 0
    parse_cache_hits = parsed_artifacts = 0
    hashed_before = project.metrics["artifact_bytes_hashed"]
    selected = all_evidence[-MAX_OBSERVATIONS:] if mode == "aggregate" else []

    for record in selected:
        if record.get("operation_id") not in by_operation:
            continue
        processed += 1
        try:
            evidence, artifact = engine.verify_current_evidence(project, record["id"])
            requested = artifact["request"]["url"]
            if not _scoped(config, requested):
                unusable += 1
                continue
            response = artifact["response"]
            body = base64.b64decode(response.get("body_base64", ""), validate=True)
            cache_version = "recon-response/v2:" + str(MAX_BODY_BYTES)
            with project._lock:
                cached = project.connection.execute("SELECT document FROM artifact_parse_cache WHERE sha256=? AND parser_version=?",
                                                    (evidence["sha256"], cache_version)).fetchone()
            parsed = json.loads(cached[0]) if cached else None
            if isinstance(parsed, dict) and all(key in parsed for key in ("technologies", "clues", "truncated", "parse_errors")):
                parse_cache_hits += 1
            else:
                parsed = parse_response(requested, response.get("headers", []), body, max_bytes=MAX_BODY_BYTES)
                with project.transaction():
                    project.connection.execute("INSERT OR REPLACE INTO artifact_parse_cache VALUES(?,?,?)",
                                               (evidence["sha256"], cache_version, canonical(parsed)))
                parsed_artifacts += 1
        except (EngineError, OSError, ValueError, TypeError, KeyError):
            unusable += 1
            continue
        observed_evidence_by_operation.setdefault(evidence["operation_id"], []).append(evidence["id"])
        if type(response.get("status")) is int and 200 <= response["status"] < 300:
            observed.add(evidence["operation_id"])
        if _html_source(response.get("headers", []), body):
            html_sources.setdefault(safe_url(requested), evidence)
        truncated += int(parsed["truncated"])
        parse_errors += len(parsed["parse_errors"])
        for fact in parsed["technologies"]:
            key = (origin(requested), fact["name"], fact.get("version"), fact["signal"])
            technologies.setdefault(key, {**fact, "target_origin": origin(requested),
                "operation_id": evidence["operation_id"], "evidence_id": evidence["id"],
                "profile_is_security_evidence": False})
        for clue in parsed["clues"]:
            url = _scoped(config, clue["url"])
            if not url:
                out_of_scope_clues += 1
                continue
            public = {**clue, "url": safe_url(url), "operation_id": evidence["operation_id"],
                      "evidence_id": evidence["id"],
                      "trust": "unverified", "automatic_execution_allowed": False,
                      "locator_requires_binding": True}
            key = _fact_key({name: public.get(name) for name in ("kind", "url", "method", "inputs", "ambiguous")})
            if key in clues:
                continue
            if key not in clues and len(clues) >= MAX_CLUES:
                omitted_clues += 1
                continue
            # Template/path matches are possible correlations, not resource or policy approval.
            matches, unmapped = _clue_bindings(clue, url, operations)
            public.update(matched_operation_ids=matches, unmapped_input_total=unmapped,
                          input_review_required=bool(unmapped or clue["ambiguous"]))
            clues[key] = public

    bad_pages, bad_functions = set(), set()
    if mode == "aggregate":
        coverage = browser.coverage(project)
        bad_pages = {row["page_id"] for row in coverage["unvisited"]}
        bad_functions = {row["function_id"] for row in coverage["untriggered"]}
    else:
        bad_pages = {row["id"] for row in pages}
        bad_functions = {function["id"] for row in pages for function in row.get("functions", [])}

    functions, tasks = [], []
    rejected_api_references, limited_api_references = 0, False
    for operation in operations:
        item = _api_function(operation, observed)
        if mode == "prepare":
            item["observation_state"] = "not_checked"
        functions.append(item)
        if operation["id"] not in observed:
            tasks.append(_task("http_baseline", "http.preflight",
                "Review existing material first; collect a normal business response only with exact current prerequisites.",
                operation=operation))
        if operation.get("auth") == "unknown" or item["unknown_consumer_total"]:
            tasks.append(_task("policy_and_input_context", "surface.inspect",
                "Map actual access policy and input consumers before choosing a vulnerability family.", operation=operation))
    for page in pages:
        if page["id"] in bad_pages:
            tasks.append(_task("page_observation", "browser.import_mcp",
                "Explore the actual authorized UI with a real Playwright provider, then preserve its output.", page=page))
        for function in page.get("functions", []):
            known = function["id"] not in bad_functions
            apis, operation_ids, rejected, references_limited = _function_apis(config, page, function, by_operation, registered_ids)
            rejected_api_references += rejected
            limited_api_references |= references_limited
            functions.append({"kind": "page_function", "page_id": page["id"], "function_id": function["id"],
                "url": safe_url(page["url"]), "name": function.get("name"), "trigger": function.get("trigger"),
                "apis": apis, "operation_ids": operation_ids, "apis_preview_truncated": references_limited,
                "interaction_state": "observed" if known else "not_checked" if mode == "prepare" else "not_observed",
                "page_visit_id": function.get("page_visit_id") or function.get("visit_id") if known else None,
                "detail_action": "page.coverage", "testing_action": "plan.next",
                "locator_requires_binding": True, "profile_is_security_evidence": False})
            if not known:
                tasks.append(_task("function_interaction", "browser.import_mcp",
                    "Record a real successful application interaction; labels or API registration are not a functional observation.",
                    page=page, function=function))
    known_page_locators = {safe_url(page["url"]) for page in pages}
    unregistered_ui = sorted(set(html_sources) - known_page_locators)
    for locator in unregistered_ui:
        source = html_sources[locator]
        task = _task("page_observation", "browser.import_mcp",
            "A stored HTML source is not an explored UI. Collect a real authorized Playwright observation and adopt its reached pages.",
            operation=by_operation[source["operation_id"]])
        task.update(url=locator, evidence_id=source["id"])
        tasks.append(task)
    if not operations and not pages:
        tasks.append({"kind": "scope_seed", "action": "surface.batch",
            "reason": "Start from actual authorized entry URLs and declared policies; do not guess hidden endpoints or widen a path scope.",
            "required_input_fields": ["operations"], "input_template": {},
            "automatic_execution_allowed": False, "locator_requires_binding": True})
    for clue in clues.values():
        if not clue["matched_operation_ids"] or clue["input_review_required"]:
            tasks.append({"kind": "discovery_review", "action": "surface.batch", "url": clue["url"],
                "evidence_id": clue["evidence_id"], "operation_id": clue["operation_id"],
                "reason": "Inspect this source-only clue and declare its real policy/inputs before any independent authorized execution.",
                "required_input_fields": ["exact_authorized_url", "actual_method_policy_and_inputs"], "input_template": {},
                "automatic_execution_allowed": False, "locator_requires_binding": True})

    technology_items = sorted(technologies.values(), key=lambda row: (row["target_origin"], row["name"], row.get("version") or "", row["signal"]))
    clue_items = sorted(clues.values(), key=lambda row: (row["url"], row["kind"], row.get("method") or ""))
    origins = sorted({origin(rule) for rule in config.get("scope", [])})
    overview = [{"kind": "site", "target_origin": value,
        "operation_total": sum(origin(row["url"]) == value for row in operations),
        "page_total": sum(origin(row["url"]) == value for row in pages),
        "technologies": sorted({row["name"] for row in technology_items if row["target_origin"] == value}),
        "locator_requires_binding": True, "profile_is_security_evidence": False} for value in origins]
    from .security_hypotheses import build as security_hypotheses
    hypothesis_profile = security_hypotheses(project, operations, observed_evidence_by_operation)
    hypothesis_items = hypothesis_profile["items"]
    limited = evidence_total > MAX_OBSERVATIONS or bool(truncated or omitted_clues or parse_errors or limited_api_references or hypothesis_profile["limited"])
    summary = {"origin_total": len(origins), "operation_total": len(operations), "page_total": len(pages),
        "function_total": len(functions), "input_total": sum(item.get("input_total", 0) for item in functions),
        "technology_total": len(technology_items), "clue_total": len(clue_items), "collection_task_total": len(tasks),
        "hypothesis_total": len(hypothesis_items), "hypothesis_limited": hypothesis_profile["limited"],
        "http_observation_total": evidence_total, "processed_observation_total": processed,
        "current_observation_total": processed - unusable if mode == "aggregate" else None,
        "unusable_observation_total": unusable if mode == "aggregate" else None,
        "omitted_observation_total": max(0, evidence_total - MAX_OBSERVATIONS) if mode == "aggregate" else 0,
        "unobserved_operation_total": len(operations) - len(observed) if mode == "aggregate" else None,
        "unvisited_page_total": len(bad_pages & {row["id"] for row in pages}),
        "unregistered_ui_page_total": len(unregistered_ui),
        "unknown_consumer_total": sum(item.get("unknown_consumer_total", 0) for item in functions),
        "out_of_scope_clue_total": out_of_scope_clues, "out_of_scope_operation_total": len(registered) - len(operations),
        "out_of_scope_api_reference_total": rejected_api_references,
        "truncated_source_total": truncated, "parse_error_total": parse_errors, "source_limited": limited}
    baseline_id, reused, changed, delta = None, False, False, {}
    if mode == "aggregate":
        technology_keys = {_fact_key({key: row.get(key) for key in ("target_origin", "name", "category", "version", "signal")}) for row in technology_items}
        function_keys = {_function_key(row, by_operation) for row in functions}
        semantic = {"scope": config.get("scope"), "exclude": config.get("exclude"),
            "operations": [(row["id"], engine.operation_signature(row)) for row in operations],
            "technologies": sorted(technology_keys), "functions": sorted(function_keys), "clues": sorted(clues),
            "ui_collection_locators": unregistered_ui, "limited": limited,
            "hypotheses": sorted(_fact_key({key: row.get(key) for key in ("id", "suggested_test_families", "missing_context")})
                                  for row in hypothesis_items)}
        baseline_id, reused, changed, delta = _save_baseline(project, semantic, technology_keys, function_keys, set(clues))
    stage = "prepare_collection" if mode == "prepare" else "collect_missing_information" if tasks or limited else "ready_for_hypotheses"
    return {"overview": overview, "technologies": technology_items, "functions": functions, "clues": clue_items,
            "collection": tasks, "hypotheses": hypothesis_items, "summary": summary, "stage": stage, "baseline_id": baseline_id,
            "baseline_reused": reused, "baseline_changed": changed, "delta": delta,
            "next_action": "surface.recon" if mode == "prepare" else tasks[0]["action"] if tasks else "plan.next",
            "parsing_work": {"parsed_artifacts": parsed_artifacts, "parse_cache_hits": parse_cache_hits,
                             "bytes_hashed": project.metrics["artifact_bytes_hashed"] - hashed_before}}


def profile(project, args):
    mode, section, offset, limit = _arguments(args)
    # Pages read a durable advisory projection. The fingerprint covers bounded
    # projection inputs; selected aggregate evidence is strongly read on rebuild.
    with project.transaction():
        kinds = ("operation", "page", "page_visit", "evidence", "actor", "session", "resource", "run")
        generation = project.generation(kinds)
        config_key = hashlib.sha256(canonical(project.config).encode("utf-8")).hexdigest()
        name = "recon/" + mode
        built = project.projection_get(name, generation, schema_version=3)
        reusable = bool(built and built.get("config_key") == config_key and not args.get("refresh", False))
        material_fingerprint = _material_fingerprint(project, mode)
        reused = bool(reusable and built.get("material_fingerprint") == material_fingerprint)
        if not reused:
            built = _build(project, mode)
            project.connection.execute("DELETE FROM recon_projection_items WHERE mode=?", (mode,))
            for name_section in SECTIONS:
                project.connection.executemany("INSERT INTO recon_projection_items VALUES(?,?,?,?)",
                    [(mode, name_section, index, canonical(item)) for index, item in enumerate(built.pop(name_section))])
            built["config_key"] = config_key
            built["material_fingerprint"] = material_fingerprint
            built["refreshed_at"] = now()
            project.projection_put(name, generation, built, schema_version=3)
        total = project.connection.execute("SELECT COUNT(*) FROM recon_projection_items WHERE mode=? AND section=?", (mode, section)).fetchone()[0]
        rows = project.connection.execute("SELECT document FROM recon_projection_items WHERE mode=? AND section=? "
            "ORDER BY position LIMIT ? OFFSET ?", (mode, section, limit, offset)).fetchall()
    built = dict(built)
    built.pop("config_key", None)
    built.pop("material_fingerprint", None)
    if reused:
        built["baseline_reused"], built["baseline_changed"] = built.get("baseline_id") is not None, False
        built["delta"] = {
            key: 0 for key in built.get("delta", {})
            if key.startswith(("new_", "removed_")) and key.endswith("_total")
        }
        built["parsing_work"] = {"parsed_artifacts": 0, "parse_cache_hits": 0, "bytes_hashed": 0}
    return {**built, "mode": mode, "section": section, "items": [json.loads(row[0]) for row in rows],
        "total": total, "offset": offset, "limit": limit,
        "next_offset": offset + limit if offset + limit < total else None,
        "projection_reused": reused, "projection_revision": generation,
        "material_verification": "cached_advisory" if reused else "strong_artifacts",
        "workflow": list(WORKFLOW), "requests_sent": 0,
        "automatic_execution_allowed": False, "profile_is_security_evidence": False,
        "completion_claim_allowed": False, "unknown_surface_exhausted": False,
        "collection_entry": {"action": "surface.recon", "input": {"mode": "aggregate", "section": "collection", "limit": 10}},
        "hypothesis_entry": {"action": "surface.recon", "input": {"mode": "aggregate", "section": "hypotheses", "limit": 10}},
        "limitations": [
            "This aggregates existing authorized observations, not a crawl, exploit, DNS/TLS scan or guarantee of complete unknown-surface discovery.",
            "Headers, cookie names, framework markers and versions are spoofable hints. Functional labels and imported sources do not confirm vulnerabilities.",
            "Inspect collection gaps and real identities/resources, collect normal UI/API/source material in one coordinated phase, then choose typed tests with plan.next.",
            "Clues are source-only profile metadata, not automatic candidate/operation registration. Review and explicitly register their real policies and precise inputs.",
            "Reuse unchanged information instead of repeating collection traffic; new facts update the baseline. Prior evidence and security obligations are never rewritten.",
            "Queries are stripped from public locators; exact authorized URLs and prerequisites must be independently bound before execution.",
        ]}
