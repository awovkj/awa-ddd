"""Discoverable proof shapes and offline recovery, not new proof channels."""
from __future__ import annotations


ORACLES = {
    "baseline": {
        "obligation_kinds": ["baseline"], "evidence_order": ["normal"],
        "required": ["type", "selector", "expected"],
        "example": {"type": "baseline", "selector": "/data/subject", "expected": "<actual normal subject>"},
        "constraints": ["One successful current capture from the declared actor.",
                        "A baseline is not a vulnerability-negative result."],
    },
    "authorization": {
        "obligation_kinds": ["access", "ownership"], "evidence_order": ["allowed", "variant"],
        "required": ["type", "selector"], "optional": ["deny_statuses"],
        "example": {"type": "authorization", "selector": "/data/order", "deny_statuses": [401, 403]},
        "constraints": ["Use actual protected business data, not /success, /message, a boolean or metadata-only ACK.",
                        "Requests must be identical apart from verified, classified credentials; ownership binds the same fixture.",
                        "Restricted actors require server-verified roles; unknown roles are not a denied role."],
    },
    "semantic_negative": {
        "obligation_kinds": ["input_test"], "evidence_order": ["normal", "variant", "sensitivity"],
        "required": ["type", "selector", "baseline_expected", "control_expected"],
        "conditional": ["test_family must exactly match an explicitly declared family."],
        "example": {"type": "semantic_negative", "test_family": "business_logic", "selector": "/data/price",
                    "baseline_expected": 100, "control_expected": 200},
        "constraints": ["Three successful captures, three distinct input values, one actor/session generation, only the selected input changes.",
                        "Normal and sensitivity values must be distinct, finite business observables, not transport noise or ACKs.",
                        "Refutation is limited to this input and hypothesis; it does not refute siblings or an entire family.",
                        "This oracle cannot close SQL or XSS obligations."],
    },
    "extraction": {
        "obligation_kinds": ["input_test"], "evidence_order": ["recovery", "negative"],
        "required": ["type", "selector", "expect"],
        "required_for_typed": ["test_family", "expected_value", "source_reference"],
        "conditional": ["Typed xxe/ssrf/path_traversal also require test_family, expected_value and source_reference."],
        "example": {"type": "extraction", "test_family": "xxe", "selector": "/data/preview",
                    "expect": "^<exact recovered canary>$", "expected_value": "<exact recovered canary>",
                    "source_reference": "<source URI present only in the recovering input>"},
        "constraints": ["Two successful same-identity controls vary only the selected input; the negative omits the source.",
                        "The recovered value must not be a submitted literal or reflection.",
                        "XXE requires a referenced SYSTEM entity; SSRF requires an HTTP(S) source; traversal requires a parent-path expression.",
                        "Multipart file contents and Content-Disposition filenames are separate inputs: file versus file.filename."],
    },
    "sql_metadata": {
        "obligation_kinds": ["input_test"], "evidence_order": ["baseline", "recovery", "negative"],
        "required": ["type", "metadata_type", "expected_value", "baseline_expected"],
        "optional": ["tool_run_id", "negative_value"],
        "conditional": ["baseline_selector XOR baseline_response_pattern; selector XOR response_pattern with named (?P<value>...) group.",
                        "Explicit SQL obligations require test_family:sql_injection."],
        "example": {"type": "sql_metadata", "test_family": "sql_injection", "metadata_type": "database",
                    "expected_value": "<actual database name>", "baseline_selector": "/data/product_no",
                    "baseline_expected": "<normal fixture product>", "selector": "/data/recovered"},
        "constraints": ["metadata_type is database or current_user, not version, product ID or table name.",
                        "Same identity and only the selected input changes; direct recovery/negative exercise the same metadata expression.",
                        "An intact successful metadata-only sqlmap tool_run_id supplies the transcript channel; optional predicates are strengthening only.",
                        "Boolean/timing signals or sqlmap no_injection alone are not confirmation or refutation; retain open if no accepted channel exists."],
    },
    "error_channel": {
        "obligation_kinds": ["input_test"], "evidence_order": ["baseline", "recovery", "negative"],
        "required": ["type", "metadata_type", "expected_value", "response_pattern"],
        "conditional": ["Explicit SQL obligations require test_family:sql_injection."],
        "example": {"type": "error_channel", "test_family": "sql_injection", "metadata_type": "database",
                    "expected_value": "<actual database name>", "response_pattern": "<DBMS error wrapper (?P<value>...)>"},
        "constraints": ["A successful normal baseline and two actual server responses, same identity, only the selected input changes.",
                        "The recovering input exercises database/current_user; the negative uses a different expression.",
                        "The DBMS error regex contains a named value group and matches neither baseline nor negative; no reflected literals."],
    },
    "state_invariant": {
        "obligation_kinds": ["input_test"], "evidence_order": ["before", "action(s)", "after"],
        "required": ["type", "selector", "before_expected"],
        "conditional": ["Choose max_delta or forbidden_after; explicit family must match."],
        "example": {"type": "state_invariant", "test_family": "business_logic", "selector": "/data/balance",
                    "before_expected": 100, "max_delta": 10},
        "constraints": ["Legacy same-operation chain with the same identity and bound resource, actual nonoverlapping execution order.",
                        "After repeats the before input; intervening actions vary only the tested input.",
                        "A POST ACK is not business readback. Prefer state_transition for separate GET/write/GET operations."],
    },
    "state_transition": {
        "obligation_kinds": ["input_test"], "evidence_order": ["before", "action", "after"],
        "required": ["type", "scenario_run_id", "before_step_id", "action_step_id", "after_step_id", "selector",
                     "before_expected", "action_input_expected", "action_success_selector", "action_success_expected", "readback_scope"],
        "conditional": ["Choose exactly one of finite nonnegative max_delta or forbidden_after; explicit family must match.",
                        "readback_scope is {type:actor,relation,subject_selector} or {type:resource,relation,resource_id}."],
        "example": {"type": "state_transition", "test_family": "business_logic", "scenario_run_id": "<actual succeeded SC ID>",
                    "before_step_id": "before", "action_step_id": "action", "after_step_id": "after", "selector": "/balance",
                    "before_expected": 100, "action_input_expected": 10000, "action_success_selector": "/success",
                    "action_success_expected": True, "max_delta": 10,
                    "readback_scope": {"type": "actor", "subject_selector": "/subject", "relation": "<why the fixture write changes this actor state>"}},
        "constraints": ["Three consecutive nonconcurrent verified checkpoints from a genuine succeeded scenario, same actor/session generation.",
                        "The static authorized fixture matches the writing actor; before and after repeat the same bound read request.",
                        "Check the positive write assertion and actual finite business state, not metadata-only ACKs.",
                        "Concurrent race observations remain unverified here; inspect the saved run instead of replaying an uncertain write."],
    },
}


def recover(project, args, error, *, action="assessment.evaluate"):
    """Enrich an existing failure with bounded local inspection pointers only."""
    oracle = args.get("oracle")
    kind = oracle.get("type") if isinstance(oracle, dict) else None
    details = dict(error.details) if isinstance(error.details, dict) else {}
    details.setdefault("help_action", "action.help")
    details.setdefault("help_input", {"name": action})
    details.setdefault("next_action", "action.help")
    if isinstance(kind, str) and kind in ORACLES:
        details.setdefault("oracle_type", kind)
        details.setdefault("required_fields", list(ORACLES[kind]["required"]))
    try:
        obligation = project.get("obligation", args.get("obligation_id"), required=False)
        if obligation:
            details.setdefault("obligation_id", obligation["id"])
            details.setdefault("operation_id", obligation["operation_id"])
            if isinstance(kind, str) and kind in ORACLES and obligation.get("test_family"):
                required = list(ORACLES[kind]["required"])
                required.extend(ORACLES[kind].get("required_for_typed", ["test_family"]))
                details.setdefault("test_family", obligation["test_family"])
                details["required_fields"] = list(dict.fromkeys(required))
        scenario = project.get("run", oracle.get("scenario_run_id"), required=False) if isinstance(oracle, dict) else None
        if scenario and scenario.get("kind") == "scenario":
            details.setdefault("run_id", scenario["id"])
            details["next_action"] = "run.inspect"
        elif error.code in {"sensitivity", "input_binding", "selector", "protected_selector", "protected_value", "control_invalid"}:
            ids = args.get("evidence_ids")
            evidence = project.get("evidence", ids[0], required=False) if isinstance(ids, list) and ids else None
            if evidence:
                details.setdefault("evidence_id", evidence["id"])
                details["next_action"] = "evidence.inspect"
    except (ValueError, TypeError, KeyError):
        pass
    error.details = details
    return error
