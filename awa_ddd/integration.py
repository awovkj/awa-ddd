"""Versioned, offline exchanges with dsh-purge; external claims never become proof."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import re
from urllib.parse import urlsplit, urlunsplit

from .store import EngineError, canonical, now
from .scope import normalize_url, require_scope

SCHEMA = "dsh-purge-awa/v1"
MAX_EXCHANGE = 2 * 1024 * 1024
MAX_ROWS = 200
MAX_PROOFS = 20
METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
LIMITATIONS = [
    "External scanner status and hashes are source claims; imports are unverified candidates, not captured evidence or confirmed findings.",
    "Import/export send no target requests. Raw HTTP, credentials and executable content are discarded; exact operations and controls need independent binding.",
]


def _text(value, field, maximum=512, *, optional=False):
    if optional and value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > maximum \
            or any(ord(char) < 32 for char in value):
        raise EngineError("integration_shape", "Exchange requires a bounded plain-text " + field)
    return value.strip()


def _source_id(value, field):
    if type(value) is int:
        value = str(value)
    value = _text(value, field, 128)
    if re.fullmatch(r"[A-Za-z0-9_.:@-]{1,128}", value) is None:
        raise EngineError("integration_shape", "Exchange source identifiers must use bounded ASCII handles")
    return value


def _rows(exchange, name):
    rows = exchange.get(name, [])
    if not isinstance(rows, list) or len(rows) > MAX_ROWS or any(not isinstance(row, dict) for row in rows):
        raise EngineError("integration_budget", "Exchange " + name + " must contain at most 200 objects")
    return rows


def _method(value):
    if value is None:
        return None
    if not isinstance(value, str) or value.upper() not in METHODS:
        raise EngineError("integration_shape", "Exchange method must be a known HTTP method or omitted")
    return value.upper()


def _digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _learn_http(redactor, row):
    from .reproduction import _learn_header
    for side in ("request", "response"):
        value = row.get(side)
        if isinstance(value, dict):
            headers = value.get("headers")
            pairs = headers.items() if isinstance(headers, dict) else headers if isinstance(headers, list) else []
            for pair in pairs:
                if isinstance(pair, (tuple, list)) and len(pair) == 2:
                    name, secret = pair
                    if str(name).lower() in {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "x-session-token"}:
                        _learn_header(redactor, str(name), secret)
        elif isinstance(value, str):
            for line in value.splitlines():
                name, separator, secret = line.partition(":")
                if separator and name.lower() in {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "x-session-token"}:
                    _learn_header(redactor, name, secret.strip())


def _locator(project, redactor, value):
    scoped = require_scope(project.config, _text(value, "url", 8192))
    parsed = urlsplit(scoped)
    query_free = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    try:
        public = redactor.url(query_free)
    except ValueError:
        raise EngineError("integration_locator", "A protected URL locator must be replaced by a safe, explicit endpoint binding") from None
    if public != query_free or "<AWA_" in public:
        raise EngineError("integration_locator", "A protected URL locator must be replaced by a safe, explicit endpoint binding")
    return public, bool(parsed.query)


def import_exchange(project, args):
    exchange = args.get("exchange")
    if not isinstance(exchange, dict) or exchange.get("schema") != SCHEMA:
        raise EngineError("integration_schema", "Exchange schema must be dsh-purge-awa/v1")
    from .contracts import _validate_json
    _validate_json(exchange)
    raw_size = len(canonical(exchange).encode("utf-8"))
    if raw_size > MAX_EXCHANGE:
        raise EngineError("integration_budget", "Exchange exceeds 2 MiB")
    engagement = exchange.get("engagement")
    if not isinstance(engagement, dict):
        raise EngineError("integration_shape", "Exchange engagement metadata is required")
    engagement_id = _source_id(engagement.get("id"), "engagement.id")
    candidates, http_rows = _rows(exchange, "candidates"), _rows(exchange, "http_evidence")
    from .publication import PublicationContext
    context = PublicationContext(project)
    if any(context.unavailable.values()):
        raise EngineError("integration_redaction", "Project redaction context is unavailable; no exchange was stored")
    redactor = context.redactor
    redactor.learn(exchange)
    for row in http_rows:
        _learn_http(redactor, row)
    if redactor.content(engagement_id) != engagement_id:
        raise EngineError("integration_redaction", "A protected value cannot be used as an exchange identifier")
    source_sha256 = _digest(exchange)
    import_id = "IMP-" + _digest([engagement_id, source_sha256])[:24]
    seen, prepared, evidence_metadata = set(), [], {}
    for row in http_rows:
        external_id = _source_id(row.get("external_id"), "http_evidence.external_id")
        if redactor.content(external_id) != external_id:
            raise EngineError("integration_redaction", "A protected value cannot be used as an exchange identifier")
        if external_id in evidence_metadata:
            raise EngineError("integration_shape", "Exchange HTTP identifiers must be unique")
        url, query_omitted = _locator(project, redactor, row.get("url"))
        status_code = row.get("status_code")
        if status_code is not None and (type(status_code) is not int or not 100 <= status_code <= 599):
            raise EngineError("integration_shape", "HTTP status_code must be an integer 100..599")
        digest_value = row.get("sha256")
        if digest_value is not None and (not isinstance(digest_value, str) or re.fullmatch(r"[a-fA-F0-9]{64}", digest_value) is None):
            raise EngineError("integration_shape", "Source HTTP sha256 must contain 64 hexadecimal digits")
        evidence_metadata[external_id] = {"external_id": external_id, "url": url,
            "method": _method(row.get("method")), "status_code": status_code,
            "claimed_sha256": digest_value.lower() if digest_value else None,
            "hash_scope": "metadata", "raw_material_included": False,
            "query_omitted": query_omitted, "trust": "unverified_external"}
    for row in candidates:
        external_id = _source_id(row.get("external_id"), "candidate.external_id")
        if external_id in seen:
            raise EngineError("integration_shape", "Exchange candidate identifiers must be unique")
        seen.add(external_id)
        if redactor.content(external_id) != external_id:
            raise EngineError("integration_redaction", "A protected value cannot be used as an exchange identifier")
        url, query_omitted = _locator(project, redactor, row.get("url"))
        query_omitted = query_omitted or row.get("query_omitted") is True
        method = _method(row.get("method"))
        refs = row.get("evidence_refs", [])
        if not isinstance(refs, list) or len(refs) > 32:
            raise EngineError("integration_budget", "Candidate evidence_refs must be a bounded array")
        refs = [_source_id(value, "evidence_ref") for value in refs]
        if any(redactor.content(value) != value for value in refs):
            raise EngineError("integration_redaction", "A protected value cannot be used as an exchange evidence identifier")
        source = {"provider": "dsh-purge", "engagement_id": engagement_id,
                  "external_id": external_id, "import_id": import_id, "sha256": source_sha256,
                  "trust": "unverified_external"}
        identity = "C-" + _digest(["dsh-purge", engagement_id, external_id])[:24]
        record = {"id": identity, "kind": "external_redteam", "url": url, "method": method,
                  "title": redactor.prose(_text(row.get("title", "External candidate"), "title", 1024)),
                  "category": redactor.prose(_text(row.get("category", "generic"), "category", 256)),
                  "severity": row.get("severity") if row.get("severity") in {"info", "low", "medium", "high", "critical"} else "info",
                  "source_status": redactor.prose(_text(row.get("source_status", "unverified"), "source_status", 64)),
                  "source": source, "sources": [source], "external_id": external_id,
                  "engagement_id": engagement_id, "evidence_refs": refs,
                  "external_http_metadata": [evidence_metadata[value] for value in refs if value in evidence_metadata],
                  "query_omitted": query_omitted, "locator_requires_binding": query_omitted,
                  "requestable": False, "trust": "unverified_external", "status": "unverified",
                  "created_at": now(), "updated_at": now()}
        prepared.append(record)
    with project.transaction():
        rows = []
        for record in prepared:
            existing = project.get("candidate", record["id"], required=False)
            if existing and (existing.get("url") != record["url"] or existing.get("method") != record["method"]):
                raise EngineError("integration_identity_conflict", "An external candidate identifier already belongs to another URL or method")
            if existing:
                merged = deepcopy(existing)
                known = {canonical(value) for value in merged.get("sources", [])}
                if canonical(record["source"]) not in known:
                    merged["sources"] = (merged.get("sources", []) + [record["source"]])[-256:]
                merged["source"] = record["source"]
                for key in ("title", "category", "severity", "source_status", "evidence_refs", "external_http_metadata", "query_omitted"):
                    merged[key] = record[key]
                merged["updated_at"] = now()
                project.put("candidate", merged)
            else:
                project.put("candidate", record, create_only=True)
            rows.append({"external_id": record["external_id"], "candidate_id": record["id"],
                         "status": "unverified", "created": existing is None})
        receipt = project.get("integration_import", import_id, required=False)
        if receipt is None:
            receipt = {"id": import_id, "engagement_id": engagement_id, "source_sha256": source_sha256,
                       "candidate_ids": [row["candidate_id"] for row in rows],
                       "http_metadata": list(evidence_metadata.values()), "created_at": now()}
            project.put("integration_import", receipt, create_only=True)
            project.event("integration.imported", {"import_id": import_id, "engagement_id": engagement_id,
                                                   "candidates": len(rows), "http_metadata": len(evidence_metadata)})
    created = sum(row["created"] for row in rows)
    return {"schema": SCHEMA, "project_id": project.project_id, "import_id": import_id,
            "assessment_mode": project.config.get("assessment_mode", "assessment"),
            "candidates": rows, "candidate_ids": [row["candidate_id"] for row in rows],
            "counts": {"candidates": len(rows), "created": created, "reused": len(rows) - created,
                       "http_metadata": len(evidence_metadata)}, "requests_sent": 0,
            "usable_for_confirmation": False, "limitations": list(LIMITATIONS)}


def _evidence_metadata(project, ids):
    from .engine import verify_current_evidence
    rows = []
    for identity in ids:
        meta, _ = verify_current_evidence(project, identity)
        rows.append({"evidence_id": meta["id"], "sha256": meta["sha256"],
                     "kind": meta.get("kind"), "trust": meta.get("trust"), "complete": meta.get("complete") is True})
    return rows


def _decision(project, decision, category=None, link=None):
    from .assessment import current_machine_proof, _category_family
    from .engine import _decision_valid
    ids = list(decision.get("evidence_ids") or [])
    result = {"decision_id": decision["id"], "outcome": decision.get("outcome"),
              "mode": decision.get("mode"), "proof_mode": decision.get("mode"),
              "oracle_type": (decision.get("oracle") or {}).get("type"), "evidence_ids": ids,
              "evidence_hashes": [], "current": False, "validated": False,
              "usable_for_confirmation": False, "category": category}
    try:
        _decision_valid(project, decision)
        result["evidence_hashes"] = _evidence_metadata(project, ids)
        result["current"] = True
        if decision.get("mode") == "machine" and decision.get("outcome") == "confirmed":
            item = project.get("obligation", decision.get("obligation_id"))
            family = "access_control" if item.get("kind") in {"access", "ownership"} else item.get("test_family") or category
            requested_family = _category_family(category)
            if requested_family is not None and family != requested_family:
                raise EngineError("oracle_family", "The imported candidate and local decision have different vulnerability families")
            current_machine_proof(project, decision["id"], family)
            result.update(validated=True, usable_for_confirmation=True, category=family)
            if item.get("kind") == "input_test" and (not isinstance(link, dict)
                    or link.get("input_location") != item.get("input_location")
                    or link.get("input_selector") != item.get("input_selector")):
                result.update(usable_for_confirmation=False, reason="input_binding_required")
        else:
            result["validated"] = decision.get("mode") == "analyst"
    except (EngineError, OSError, ValueError, KeyError, TypeError) as exc:
        result["reason"] = getattr(exc, "code", "evidence_invalid")
        result["current"] = False
    return result


def _v2_machine(project, finding):
    """Recheck frozen recipe, each exact request and the oracle without execution."""
    from .domain.repository import Repository
    from .domain.test_recipe import assert_current, render
    from .engine import verify_current_evidence
    from .execution.test_runner import context, _evidence_value, _eval_from_results
    repository = Repository(project, read_only=True)
    run = repository.get("run", finding["run_id"])
    recipe = repository.get("recipe", run["recipe_id"])
    campaign = repository.get("campaign", run["campaign_id"])
    if run.get("status") not in {"evaluated", "published"} or run.get("hypothesis_id") != finding.get("hypothesis_id") \
            or run.get("recipe_spec_hash") != recipe.get("spec_hash") or finding.get("decision_id") != run["id"]:
        raise EngineError("finding_proof_current", "V2 finding does not bind a current managed run and frozen recipe")
    assert_current(recipe, context(project, campaign, recipe))
    operation = project.get("operation", recipe["bindings"]["operation_id"])
    input_binding = (recipe.get("bindings", {}).get("consumer_context") or {}).get("input")
    if isinstance(input_binding, dict):
        bound_input = next((entry for entry in operation.get("inputs", [])
                            if entry.get("location") == input_binding.get("location")
                            and entry.get("selector", entry.get("name")) == input_binding.get("selector", input_binding.get("name"))
                            and entry.get("schema_branch") == input_binding.get("schema_branch")), None)
        if bound_input is None or canonical(bound_input) != canonical(input_binding):
            raise EngineError("input_binding", "V2 frozen input or consumer contract has changed")
    executable = render(recipe, {})
    groups = executable.get("control_groups") or recipe.get("control_groups", [])
    controls = groups[0].get("controls", []) if groups else []
    ids = run.get("evidence_ids") or []
    if len(ids) != len(controls) or not set(finding.get("evidence_ids") or []).issubset(set(ids)):
        raise EngineError("evidence_binding", "V2 finding needs every exact control observation")
    results = []
    for control, identity in zip(controls, ids):
        meta, artifact = verify_current_evidence(project, identity)
        session_binding = recipe.get("bindings", {}).get("session") or {}
        resource_binding = recipe.get("bindings", {}).get("resource") or {}
        if meta.get("session_id") != session_binding.get("session_id") \
                or meta.get("session_generation") != session_binding.get("generation") \
                or meta.get("actor_id") != session_binding.get("actor_id") \
                or meta.get("resource_id") != resource_binding.get("resource_id"):
            raise EngineError("control_identity", "V2 evidence belongs to another recipe identity or resource")
        request = control.get("request", {})
        actual_request = artifact.get("request", {})
        expected_body = request.get("body")
        if "body_base64" in request:
            raw_body = base64.b64decode(request["body_base64"], validate=True)
        elif isinstance(expected_body, (dict, list)):
            raw_body = json.dumps(expected_body, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        else:
            raw_body = expected_body.encode("utf-8") if isinstance(expected_body, str) else b""
        if meta.get("operation_id") != recipe["bindings"]["operation_id"] \
                or normalize_url(actual_request["url"]) != normalize_url(request["url"]) \
                or actual_request.get("method") != str(request.get("method")).upper() \
                or base64.b64decode(actual_request.get("body_base64", ""), validate=True) != raw_body:
            raise EngineError("control_request", "V2 evidence no longer matches its frozen control request")
        actual_headers = actual_request.get("headers", {})
        from .transport import headers_map
        expected_headers = headers_map(request.get("headers") or {})
        if session_binding:
            expected_headers = {**project.get("session", session_binding["session_id"])["headers"], **expected_headers}
        if isinstance(expected_body, (dict, list)):
            expected_headers.setdefault("content-type", "application/json")
        if operation.get("content_type"):
            expected_headers.setdefault("content-type", operation["content_type"])
        if actual_headers != expected_headers:
            raise EngineError("control_request", "V2 evidence headers differ from the frozen control")
        selector = control.get("expected", {}).get("selector", "body")
        actual = _evidence_value(project, identity, selector)
        expected = control.get("expected", {}).get("value")
        results.append((control, {"evidence_id": identity, "actual": actual,
                                  "matched": str(actual).strip() == str(expected).strip() if expected is not None else None}))
    evaluation = _eval_from_results(recipe, results)
    if evaluation.get("outcome") != "supported" or not evaluation.get("finding_allowed") \
            or canonical(evaluation) != canonical(run.get("evaluation")):
        raise EngineError("finding_proof", "V2 oracle re-evaluation did not reproduce the stored positive proof")
    return {"decision_id": run["id"], "outcome": "confirmed", "mode": "machine", "proof_mode": "machine",
            "oracle_type": recipe.get("oracle", {}).get("type"), "category": finding.get("category"),
            "evidence_ids": ids, "evidence_hashes": _evidence_metadata(project, ids),
            "current": True, "validated": True, "usable_for_confirmation": True}


def export_exchange(project, args):
    from .publication import PublicationContext, _TEXT
    public_context = PublicationContext(project)

    def finding_title(finding):
        # Keep the actual local finding wording, independently of scanner
        # labels, while protecting direct internal calls as well as dispatch.
        return public_context.metadata({"title": finding.get("title")},
                                       schema={"title": _TEXT}).get("title")

    offset, limit = args.get("offset", 0), args.get("limit", 25)
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise EngineError("pagination", "Integration export uses a nonnegative offset and limit 1..100")
    import_id = args.get("import_id")
    allowed = None
    if import_id is not None:
        receipt = project.get("integration_import", _text(import_id, "import_id", 128))
        allowed = set(receipt["candidate_ids"])
    selected = [row for row in project.list("candidate") if row.get("kind") == "external_redteam"
                and (allowed is None or row["id"] in allowed)]
    rows = []
    all_decisions, all_findings = project.list("decision"), project.list("finding")
    v2_findings = project.list("v2_finding")
    for candidate in selected[offset:offset + limit]:
        row = {key: candidate.get(key) for key in ("external_id", "engagement_id", "url", "method", "title", "category", "severity", "source_status", "status", "source")}
        row.update(candidate_id=candidate["id"], operation_id=candidate.get("operation_id"),
                   decisions=[], findings=[], usable_for_confirmation=False)
        operation = project.get("operation", candidate.get("operation_id"), required=False) if candidate.get("operation_id") else None
        if operation and operation["url"] == candidate.get("url") and (candidate.get("method") is None or operation["method"] == candidate["method"]):
            relevant = [decision for decision in all_decisions if decision.get("operation_id") == operation["id"]]
            row["proofs_truncated"] = len(relevant) > MAX_PROOFS
            decision_views = {decision["id"]: _decision(project, decision, candidate.get("category"), candidate.get("link")) for decision in relevant[-MAX_PROOFS:]}
            for finding in all_findings:
                if finding.get("decision_id") not in decision_views:
                    continue
                proof = decision_views[finding["decision_id"]]
                row["findings"].append({"finding_id": finding["id"], "decision_id": finding["decision_id"],
                    "mode": finding.get("mode"), "status": finding.get("status"), "category": finding.get("category"),
                    "severity": finding.get("severity"), "title": finding_title(finding), "evidence_ids": finding.get("evidence_ids", []),
                    "current": proof["current"] and finding.get("status") == "confirmed" and not finding.get("superseded_by"),
                    "usable_for_confirmation": proof["usable_for_confirmation"] and finding.get("status") == "confirmed" and not finding.get("superseded_by")})
                if len(row["findings"]) >= MAX_PROOFS:
                    row["proofs_truncated"] = True
                    break
            row["decisions"] = list(decision_views.values())
            for finding in v2_findings:
                hypothesis = project.get("v2_hypothesis", finding.get("hypothesis_id"), required=False)
                if not hypothesis or hypothesis.get("operation_id") != operation["id"]:
                    continue
                if len(row["decisions"]) >= MAX_PROOFS or len(row["findings"]) >= MAX_PROOFS:
                    row["proofs_truncated"] = True
                    break
                proof = {"decision_id": finding.get("decision_id"), "mode": "machine" if finding.get("mode") == "machine" else "analyst",
                         "proof_mode": "machine" if finding.get("mode") == "machine" else "analyst", "outcome": "confirmed",
                         "evidence_ids": finding.get("evidence_ids") or [], "evidence_hashes": [], "current": False,
                         "validated": False, "usable_for_confirmation": False}
                if finding.get("mode") == "machine" and finding.get("current") and finding.get("status") == "machine_confirmed":
                    try:
                        proof = _v2_machine(project, finding)
                        from .assessment import _category_family
                        expected_family = _category_family(candidate.get("category"))
                        if expected_family is not None and expected_family != finding.get("category"):
                            proof.update(usable_for_confirmation=False, reason="oracle_family")
                        recipe = project.get("v2_recipe", (project.get("v2_run", finding["run_id"]) or {}).get("recipe_id")) or {}
                        selected_input = ((recipe.get("bindings") or {}).get("consumer_context") or {}).get("input") or {}
                        link = candidate.get("link") or {}
                        if selected_input and (link.get("input_location") != selected_input.get("location")
                                or link.get("input_selector") != selected_input.get("selector")):
                            proof.update(usable_for_confirmation=False, reason="input_binding_required")
                    except (EngineError, OSError, ValueError, KeyError, TypeError) as exc:
                        proof["reason"] = getattr(exc, "code", "evidence_invalid")
                row["decisions"].append(proof)
                row["findings"].append({"finding_id": finding["id"], "decision_id": proof["decision_id"],
                    "mode": proof["mode"], "status": finding.get("status"), "category": finding.get("category"),
                    "severity": finding.get("severity"), "title": finding_title(finding),
                    "evidence_ids": proof["evidence_ids"], "current": proof["current"],
                    "usable_for_confirmation": proof["usable_for_confirmation"]})
            row["usable_for_confirmation"] = any(proof.get("usable_for_confirmation") for proof in row["decisions"])
        if len(canonical(rows + [row]).encode("utf-8")) > MAX_EXCHANGE - 8192:
            break
        rows.append(row)
    return {"schema": SCHEMA, "project_id": project.project_id, "assessment_mode": project.config.get("assessment_mode", "assessment"),
            "import_id": import_id, "candidates": rows, "candidate_total": len(selected),
            "offset": offset, "limit": limit, "next_offset": offset + len(rows) if offset + len(rows) < len(selected) else None,
            "limited": len(rows) < min(limit, max(0, len(selected) - offset)),
            "counts": {"candidates": len(rows), "verified_candidates": sum(row["usable_for_confirmation"] for row in rows)},
            "requests_sent": 0, "limitations": list(LIMITATIONS)}
