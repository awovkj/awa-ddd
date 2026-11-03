"""Read-only exact-input coverage; captured variants are not accepted test results."""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import math

from .inputs import control_context, input_view
from .store import EngineError, canonical


MAX_INPUT_VIEWS = 50000
MAX_INPUT_VIEW_BYTES = 64 * 1024 * 1024
MAX_CONTEXTS_PER_INPUT = 512
STATUS_FILTERS = {"any", "untested", "observed", "needs_controls", "tested", "consumer_review"}


def _input_key(operation_id, location, selector, branch):
    return operation_id, location, selector, branch


def row_id(operation_id, location, selector, branch, family):
    identity = canonical([operation_id, location, selector, branch, family])
    return "PC-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


def _normalized(value):
    # Match JSON numeric equality without merging booleans with zero or one.
    if isinstance(value, float) and math.isfinite(value) and value.is_integer():
        return int(value)
    if isinstance(value, (list, tuple)):
        return [_normalized(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalized(item) for key, item in value.items()}
    return value


def _private_digest(value):
    raw = b"bytes:" + value if isinstance(value, bytes) else canonical(_normalized(value)).encode("utf-8")
    return hashlib.sha256(raw).digest()


def _request_bytes(request):
    # Estimate decoded body bytes without decoding them once per selected input.
    # Charge the whole URL/header context because every input view retains it.
    try:
        encoded = request.get("body_base64", "")
        if not isinstance(encoded, str):
            return MAX_INPUT_VIEW_BYTES + 1
        body = (len(encoded) * 3 + 3) // 4
        return max(1, body + len(request.get("url", "").encode("utf-8"))
                   + len(canonical(request.get("headers", {})).encode("utf-8")))
    except (ValueError, UnicodeError, TypeError, AttributeError, RecursionError):
        return MAX_INPUT_VIEW_BYTES + 1


class ObservationProfiles:
    """Transient comparison groups; input/context digests never leave this object."""

    def __init__(self, operations):
        self.operations = operations
        self.entries = {}
        self.by_operation = defaultdict(list)
        self.operation_counts = Counter()
        self.calls = 0
        self.parsed_bytes = 0
        for operation_id, operation in operations.items():
            duplicates = Counter((entry.get("location"), entry.get("selector")) for entry in operation.get("inputs", []))
            for entry in operation.get("inputs", []):
                key = _input_key(operation_id, entry.get("location"), entry.get("selector"), entry.get("schema_branch"))
                profile = {"observation_count": 0, "evidence_ids": [], "groups": {}, "errors": Counter(),
                           "branch_ambiguous": duplicates[(entry.get("location"), entry.get("selector"))] > 1,
                           "limited": False}
                self.entries[key] = profile
                self.by_operation[operation_id].append((entry, profile))

    def observe(self, evidence, request):
        operation_id = evidence["operation_id"]
        self.operation_counts[operation_id] += 1
        operation = self.operations.get(operation_id)
        if not operation:
            return
        request_bytes = _request_bytes(request)
        for entry, profile in self.by_operation[operation_id]:
            if profile["branch_ambiguous"]:
                profile["errors"]["schema_branch_requires_binding"] += 1
                continue
            if self.calls >= MAX_INPUT_VIEWS or self.parsed_bytes + request_bytes > MAX_INPUT_VIEW_BYTES:
                profile["limited"] = True
                continue
            self.calls += 1
            self.parsed_bytes += request_bytes
            item = {"input_location": entry["location"], "input_selector": entry["selector"],
                    "schema_branch": entry.get("schema_branch")}
            try:
                value, context = input_view(request, item, operation)
                identity = [evidence.get("actor_id"), evidence.get("session_id"),
                            evidence.get("session_generation"), evidence.get("resource_id")]
                key = _private_digest([identity, control_context(context)])
                digest = _private_digest(value)
            except (EngineError, ValueError, TypeError, KeyError, IndexError, RecursionError):
                profile["errors"]["input_view_unavailable"] += 1
                continue
            profile["observation_count"] += 1
            profile["evidence_ids"] = (profile["evidence_ids"] + [evidence["id"]])[-5:]
            group = profile["groups"].get(key)
            if group is None:
                if len(profile["groups"]) >= MAX_CONTEXTS_PER_INPUT:
                    profile["limited"] = True
                    continue
                group = profile["groups"][key] = {"values": {}, "successful_values": {}}
            # Three distinct values only identify a possible sensitivity experiment.
            # No response or oracle is evaluated by this observational projection.
            successful = 200 <= evidence.get("status_code", 0) < 300
            values = group["values"]
            if digest in values:
                if successful or not values[digest][1]:
                    values[digest] = (evidence["id"], successful)
            elif len(values) < 3:
                values[digest] = (evidence["id"], successful)
            elif successful and not any(item[1] for item in values.values()):
                values.pop(next(iter(values)))
                values[digest] = (evidence["id"], True)
            successes = group["successful_values"]
            if successful and (digest in successes or len(successes) < 3):
                successes[digest] = evidence["id"]

    def view(self, operation_id, entry):
        profile = self.entries[_input_key(operation_id, entry["location"], entry["selector"], entry.get("schema_branch"))]
        maximum = max((len(group["values"]) for group in profile["groups"].values()), default=0)
        return {"operation_observation_count": self.operation_counts[operation_id],
                "observation_count": profile["observation_count"], "evidence_ids": list(profile["evidence_ids"]),
                "has_input_variant": maximum >= 2,
                "control_candidate_state": "three_values" if maximum >= 3 else "two_values" if maximum >= 2 else "no_variant",
                "observation_errors": dict(profile["errors"]), "observations_limited": profile["limited"],
                "schema_branch_requires_binding": profile["branch_ambiguous"]}

    def control_candidates(self, operation_id, entry, family, *, allowed_evidence_ids=None, anchor=None):
        """Return bounded capture references from one exact-input comparison group."""
        profile = self.entries[_input_key(operation_id, entry["location"], entry["selector"], entry.get("schema_branch"))]
        required = 2 if family in {"xxe", "ssrf", "path_traversal", "xss"} else 3
        groups = list(profile["groups"].values())
        if anchor is not None:
            meta, request = anchor
            try:
                _, context = input_view(request, {"input_location": entry["location"], "input_selector": entry["selector"],
                                                 "schema_branch": entry.get("schema_branch")}, self.operations[operation_id])
                identity = [meta.get("actor_id"), meta.get("session_id"), meta.get("session_generation"), meta.get("resource_id")]
                key = _private_digest([identity, control_context(context)])
            except (EngineError, ValueError, TypeError, KeyError, IndexError, RecursionError):
                return [], required
            groups = [profile["groups"][key]] if key in profile["groups"] else []
        for group in reversed(groups):
            if family == "sql_injection":
                values = [value for value in group["values"].values()
                          if allowed_evidence_ids is None or value[0] in allowed_evidence_ids]
                # Error-channel controls can include actual non-2xx responses,
                # but a set of failures alone cannot stand in for a normal run.
                if len(values) >= required and any(successful for _, successful in values):
                    return [identity for identity, _ in values[:required]], required
            else:
                values = [identity for identity in group["successful_values"].values()
                          if allowed_evidence_ids is None or identity in allowed_evidence_ids]
                if len(values) >= required:
                    return values[:required], required
        return [], required


def snapshot(project, evaluated, *, inventory=None):
    """Stable input identities and current proof/observation states, without writes."""
    from . import engine
    from .completeness import _consumer_requirements, obligation_family

    if inventory is not None and "parameter_coverage_snapshot" in inventory:
        return inventory["parameter_coverage_snapshot"]
    inventory = inventory or {}
    operations = inventory.get("operations") or {row["id"]: row for row in project.list("operation")}
    obligations = inventory.get("obligations")
    if obligations is None:
        obligations = [row for row in project.list("obligation") if not row.get("superseded")]
    gaps = inventory.get("gaps") or {row["id"]: row for row in evaluated["gaps"]}
    decisions = inventory.get("decisions") or {row["id"]: row for row in project.list("decision")}
    profiles = inventory.get("parameter_profiles")
    if profiles is None:
        profiles = ObservationProfiles(operations)
        for evidence in inventory.get("observations", project.list("evidence")):
            if evidence.get("kind") != "http":
                continue
            try:
                current, artifact = engine.verify_current_evidence(project, evidence["id"])
                profiles.observe(current, artifact["request"])
            except (EngineError, OSError, ValueError, TypeError, KeyError):
                continue
    by_input = defaultdict(list)
    for item in obligations:
        if item.get("kind") in {"input_test", "input_review"}:
            by_input[_input_key(item["operation_id"], item.get("input_location"), item.get("input_selector"),
                                item.get("schema_branch"))].append(item)
    required_by_input = defaultdict(set)
    requirements = inventory.get("consumer_requirements")
    if requirements is None:
        requirements = _consumer_requirements(operations, obligations)
    for item in requirements:
        required_by_input[_input_key(item["operation_id"], item.get("input_location"), item.get("input_selector"),
                                     item.get("schema_branch"))].add(item["test_family"])
    rows = []
    for operation_id, operation in sorted(operations.items()):
        for entry in operation.get("inputs", []):
            bound = by_input[_input_key(operation_id, entry["location"], entry["selector"], entry.get("schema_branch"))]
            unknown = str(entry.get("consumer") or "unknown").strip().lower() in {"unknown", "other", ""}
            families = sorted(set(entry.get("test_families") or
                                  [obligation_family(item, operation) for item in bound if item.get("kind") == "input_test"] or
                                  ["unclassified" if unknown else obligation_family({"input_location": entry["location"],
                                      "input_selector": entry["selector"], "schema_branch": entry.get("schema_branch")}, operation)]))
            required = required_by_input[_input_key(operation_id, entry["location"], entry["selector"], entry.get("schema_branch"))]
            families = sorted(set(families) | required)
            observation = profiles.view(operation_id, entry)
            for family in families:
                candidate_ids, candidate_required = profiles.control_candidates(operation_id, entry, family)
                matching = [item for item in bound if item.get("kind") == "input_review"
                            or obligation_family(item, operation) == family]
                tested = next((item for item in matching if item.get("kind") == "input_test"
                               and item["id"] not in gaps and item.get("status") == "evaluated"
                               and decisions.get(item.get("decision_id"), {}).get("outcome") in {"confirmed", "refuted"}), None)
                status = ("consumer_review" if unknown else "tested" if tested else
                          "observed_unassessed" if observation["has_input_variant"] else
                          "observation_limited" if observation["observations_limited"] or observation["schema_branch_requires_binding"] else
                          "needs_controls" if observation["observation_count"] else "unobserved")
                row = {"id": row_id(operation_id, entry["location"], entry["selector"], entry.get("schema_branch"), family),
                       "operation_id": operation_id, "method": operation["method"], "url": operation["url"],
                       "input_name": entry["name"], "input_location": entry["location"], "input_selector": entry["selector"],
                       "schema_branch": entry.get("schema_branch"), "test_family": family, "consumer": entry.get("consumer", "unknown"),
                       "status": status, "typed_tested": tested is not None and not unknown,
                       "obligation_ids": [item["id"] for item in matching], **observation,
                       "control_candidate_evidence_ids": candidate_ids,
                       "control_candidate_required_values": candidate_required,
                       "observation_is_testing": False,
                       "next_action": "surface.declare_consumer" if unknown or family in required else
                           "evidence.inspect" if tested or candidate_ids else "http.preflight"}
                if tested:
                    decision = decisions[tested["decision_id"]]
                    row.update(decision_id=decision["id"], outcome=decision["outcome"], proof_mode=decision.get("mode", "machine"),
                               evidence_ids=list(decision.get("evidence_ids", [])))
                rows.append(row)
    rows.sort(key=lambda row: (row["operation_id"], row["input_location"], row["input_selector"],
                               row.get("schema_branch") or "", row["test_family"]))
    counts = Counter(row["status"] for row in rows)
    unique_inputs = {_input_key(row["operation_id"], row["input_location"], row["input_selector"], row.get("schema_branch")) for row in rows}
    summary = {"parameter_total": len(unique_inputs), "cell_total": len(rows),
               "typed_tested_total": sum(row["typed_tested"] for row in rows),
               "untested_total": sum(not row["typed_tested"] for row in rows),
               "observed_total": sum(row["observation_count"] > 0 for row in rows),
               "variant_observed_total": sum(row["has_input_variant"] for row in rows),
               "needs_controls_total": counts["needs_controls"], "unobserved_total": counts["unobserved"],
               "consumer_review_total": counts["consumer_review"],
               "observations_limited_total": sum(row["observations_limited"] or row["schema_branch_requires_binding"] for row in rows),
               "observation_is_testing": False}
    return {"summary": summary, "items": rows}


def progress(project, evaluated, *, inventory=None):
    """Only identity keys may be persisted for checkpoint deltas, never value hashes."""
    rows = snapshot(project, evaluated, inventory=inventory)["items"]
    return {"tested_keys": [row["id"] for row in rows if row["typed_tested"]],
            "variant_keys": [row["id"] for row in rows if row["has_input_variant"]],
            "consumer_review_keys": [row["id"] for row in rows if row["status"] == "consumer_review"]}


def annotate_queue(value, queue):
    """Readiness is a separate axis from proof and observed-input coverage."""
    by_obligation = {item["obligation_id"]: item for item in queue}
    for row in value["items"]:
        work = [by_obligation[identity] for identity in row["obligation_ids"] if identity in by_obligation]
        statuses = {item["queue_status"] for item in work}
        row["queue_status"] = ("closed" if row["typed_tested"] else "ready" if "ready" in statuses else
                               "review" if "review" in statuses else "blocked" if "blocked" in statuses else "unplanned")
        row["missing_prerequisites"] = list(dict.fromkeys(prerequisite for item in work for prerequisite in item["missing_prerequisites"]))
    return value


def public_page(value, args):
    from .reporting import safe_metadata, safe_url

    offset, limit = args.get("parameter_offset", 0), args.get("parameter_limit", 10)
    status = args.get("parameter_status", "any")
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
        raise EngineError("pagination", "parameter_offset must be a nonnegative integer; parameter_limit must be 1..100")
    if not isinstance(status, str) or status not in STATUS_FILTERS:
        raise EngineError("arguments", "parameter_status must be any, untested, observed, needs_controls, tested or consumer_review")
    def selected(row):
        return (status == "any" or status == "untested" and not row["typed_tested"]
                or status == "observed" and row["observation_count"] > 0
                or status == "tested" and row["typed_tested"]
                or status in {"needs_controls", "consumer_review"} and row["status"] == status)
    rows = [row for row in value["items"] if selected(row)]
    page = [{**row, "url": safe_url(row["url"])} for row in rows[offset:offset + limit]]
    return safe_metadata({"summary": value["summary"], "items": page, "total": len(rows), "offset": offset, "limit": limit,
                          "next_offset": offset + limit if offset + limit < len(rows) else None, "filter": status,
                          "limitation": "Exact-input observations and comparison candidates are not oracle acceptance, vulnerability proof or completion. Input values and their digests are not published."})
