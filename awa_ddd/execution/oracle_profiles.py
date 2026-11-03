"""Proof profiles for 2.0 oracles.

Each profile states *what it can and cannot prove*.  Weak signals (parser type
echoes, arithmetic calculator output, reflected canaries, timing jitter, a
returned upload path) are explicitly ``not_proof`` and never become confirmed
findings without their required scope/controls.
"""
from __future__ import annotations

from ..store import EngineError

PROFILES = {
    "baseline": {
        "version": "1", "proof_scope": "baseline_observation", "confirmable": False,
        "requires": ["normal_response"],
        "not_proof": ["any vulnerability"], "severity_cap": None,
        "mechanism_contract": "Describes a normal response; it is not a security test.",
    },
    "authorization": {
        "version": "1", "proof_scope": "authorization_boundary", "confirmable": True,
        "requires": ["allowed_role_result", "forbidden_role_result", "anonymous_result", "server_role_evidence"],
        "not_proof": ["missing authorization for other roles/resources"],
        "severity_cap": "high",
        "mechanism_contract": "Same operation/resource and fixed non-identity inputs; only the principal changes.",
    },
    "semantic_negative": {
        "version": "1", "proof_scope": "semantic_refutation", "confirmable": False,
        "requires": ["normal_control", "attack_control"],
        "not_proof": ["unrelated mechanisms", "whole family absence"],
        "severity_cap": None,
        "mechanism_contract": "A bounded refutation of one declared mechanism; never a universal negative.",
    },
    "state_invariant": {
        "version": "1", "proof_scope": "state_invariant_observation", "confirmable": True,
        "requires": ["before_state", "after_state", "invariant"],
        "not_proof": ["state transitions not observed"],
        "severity_cap": "high",
        "mechanism_contract": "Business state invariant violated by a real read/write/read sequence.",
    },
    "state_transition": {
        "version": "1", "proof_scope": "state_transition", "confirmable": True,
        "requires": ["before_state", "action_result", "after_state", "same_actor_session"],
        "not_proof": ["concurrency", "other resources"],
        "severity_cap": "high",
        "mechanism_contract": "A forbidden or incorrect transition completed and was read back under the same identity.",
    },
    "extraction": {
        "version": "1", "proof_scope": "extraction_observation", "confirmable": True,
        "requires": ["normal_value", "attack_value", "expected_extraction", "reflection_exclusion"],
        "not_proof": ["arbitrary file read", "command execution"],
        "severity_cap": "high",
        "mechanism_contract": "Expected controlled data extraction, not mere byte difference.",
    },
    "error_channel": {
        "version": "1", "proof_scope": "error_channel_observation", "confirmable": True,
        "requires": ["baseline", "attack", "error_recovery", "negative_control"],
        "not_proof": ["data extraction", "code execution"],
        "severity_cap": "medium",
        "mechanism_contract": "DBMS error signature appears only under the attack input and recovers with the baseline.",
    },
    "sql_metadata": {
        "version": "1", "proof_scope": "sql_metadata_observation", "confirmable": True,
        "requires": ["baseline", "attack", "business_count_change", "same_identity"],
        "not_proof": ["all-table access", "data dump"],
        "severity_cap": "medium",
        "mechanism_contract": "A bounded business-count difference caused only by the registered SQL input.",
    },
    "parser_identification": {
        "version": "1", "proof_scope": "parser_identification", "confirmable": False,
        "requires": ["normal_parse", "attack_parse"],
        "not_proof": ["unsafe deserialization", "type instantiation", "code execution"],
        "severity_cap": None,
        "mechanism_contract": "Identifies a parser response only; a secure type allowlist rejection also matches.",
    },
    "unexpected_expression_evaluation": {
        "version": "1", "proof_scope": "unexpected_expression_evaluation", "confirmable": True,
        "requires": ["declared_formula_field", "normal_plain_value", "attack_arithmetic_value",
                     "negative_literal_value", "expected_arithmetic_result", "reflection_exclusion"],
        "not_proof": ["arbitrary code execution", "OS command execution", "other template engines"],
        "severity_cap": "medium",
        "mechanism_contract": "A field outside a declared formula feature evaluates an arithmetic expression; normal and negative controls keep the same input type.",
    },
    "unsafe_type_instantiation": {
        "version": "1", "proof_scope": "unsafe_type_instantiation", "confirmable": True,
        "requires": ["normal_object", "attack_type_marker", "negative_unknown_type", "bounded_canary_effect",
                     "server_parser"],
        "not_proof": ["arbitrary gadget chains", "code execution", "other classes"],
        "severity_cap": "high",
        "mechanism_contract": "Server-side parser instantiates the exact attack type and a bounded canary changes; unknown-type negative does not.",
    },
    "bounded_side_effect": {
        "version": "1", "proof_scope": "bounded_side_effect", "confirmable": True,
        "requires": ["normal_control", "attack_canary", "negative_control", "isolated_canary",
                     "reflection_exclusion", "timing_not_sole_evidence"],
        "not_proof": ["destructive commands", "arbitrary command execution"],
        "severity_cap": "high",
        "mechanism_contract": "A controlled canary effect occurs only for the attack and is not explained by reflection or scheduling jitter.",
    },
    "upload_path_escape": {
        "version": "1", "proof_scope": "upload_path_escape", "confirmable": True,
        "requires": ["declared_storage_contract", "owned_upload", "stored_path", "readback_content",
                     "filename_content_separated", "outside_allowed_root"],
        "not_proof": ["code execution", "server misconfiguration beyond storage root"],
        "severity_cap": "high",
        "mechanism_contract": "Owned file content is readable at a path outside the declared storage root; filename and content are independently controlled.",
    },
    "browser_runtime": {
        "version": "1", "proof_scope": "browser_runtime_xss", "confirmable": True,
        "requires": ["application_triggered_dialog", "attack_controls", "normal_control_no_dialog",
                     "consumer_page", "same_identity_control_group", "content_version"],
        "not_proof": ["manual evaluate(alert)", "static HTML", "unbound imported MCP output"],
        "severity_cap": "high",
        "mechanism_contract": "The application stores/reflects attacker content and the consumer page itself triggers the marker dialog in a real browser.",
    },
    "race": {
        "version": "1", "proof_scope": "race_condition", "confirmable": True,
        "requires": ["sequential_control", "concurrent_barrier", "stable_business_key",
                     "effect_count", "late_effect_observation"],
        "not_proof": ["single ACK", "lock error", "sequential replay anomaly", "timing jitter"],
        "severity_cap": "high",
        "mechanism_contract": "Overlapping requests with a real barrier produce an effect count impossible in the sequential control, confirmed by final state.",
    },
    "token_lifecycle": {
        "version": "1", "proof_scope": "token_lifecycle", "confirmable": True,
        "requires": ["issue_context", "first_use", "reuse", "expiry_or_revocation", "state_readback"],
        "not_proof": ["other tokens", "other accounts"],
        "severity_cap": "medium",
        "mechanism_contract": "A token issued by the real flow remains usable beyond its declared single-use or expiry policy.",
    },
}


def profile(oracle_type):
    if oracle_type not in PROFILES:
        raise EngineError("v2_oracle", "Unknown oracle type")
    return dict(PROFILES[oracle_type])


def _value(observations, key):
    return observations.get(key)


def _eq(left, right):
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return abs(float(left) - float(right)) < 1e-9
    return str(left).strip() == str(right).strip()


def evaluate(oracle_type, observations, controls=None):
    """Evaluate one oracle from extracted control observations.

    ``observations`` contains values already extracted from real evidence; this
    function performs no network access and never invents evidence.
    """
    if oracle_type not in PROFILES:
        raise EngineError("v2_oracle", "Unknown oracle type")
    controls = controls or {}
    required = PROFILES[oracle_type]["requires"]
    missing = [key for key in required if key not in observations and key not in controls]
    if missing:
        return {"outcome": "inconclusive", "proof_scope": PROFILES[oracle_type]["proof_scope"],
                "missing": missing, "finding_allowed": False,
                "limitations": ["missing required observations: " + ", ".join(missing)]}
    if oracle_type == "baseline":
        return _result("observed", False, ["Baseline observation is not a vulnerability decision."])
    if oracle_type == "parser_identification":
        return _result("inconclusive", False,
                       ["Parser identification alone does not prove unsafe deserialization or code execution."])
    if oracle_type == "semantic_negative":
        normal, attack = observations.get("normal_control"), observations.get("attack_control")
        outcome = "refuted" if _eq(normal, attack) else "inconclusive"
        return _result(outcome, False, ["A bounded mechanism refutation only."])
    if oracle_type == "authorization":
        allowed = observations.get("allowed_role_result")
        forbidden = observations.get("forbidden_role_result")
        anonymous = observations.get("anonymous_result")
        denied = {"denied", "forbidden", "unauthorized", "not_found", 401, 403, 404}
        if allowed not in denied and forbidden in denied and anonymous in denied:
            return _result("refuted", False, ["Forbidden and anonymous principals were denied."])
        if allowed not in denied and forbidden not in denied:
            return _result("supported", True, ["Forbidden principal accessed the same operation/resource."])
        return _result("inconclusive", False, ["Role outcomes do not discriminate access policy."])
    if oracle_type == "unexpected_expression_evaluation":
        if any(observations.get(key) in {"reflected", True} for key in ("reflection", "attack_reflected")):
            return _result("refuted", False, ["Attack value was reflected, not evaluated."])
        expected = observations.get("expected_arithmetic_result")
        actual = observations.get("attack_arithmetic_value")
        normal_ok = _eq(observations.get("normal_plain_value"), observations.get("normal_expected", observations.get("normal_plain_value")))
        negative_ok = _eq(observations.get("negative_literal_value"), observations.get("negative_expected", observations.get("negative_literal_value")))
        if _eq(actual, expected) and normal_ok and negative_ok:
            return _result("supported", True,
                           ["Arithmetic result observed; proof is limited to expression evaluation, not code execution."])
        return _result("inconclusive", False, ["Controls do not exclude normal calculator behavior or reflection."])
    if oracle_type == "unsafe_type_instantiation":
        marker = observations.get("attack_type_marker")
        canary = observations.get("bounded_canary_effect")
        negative = observations.get("negative_unknown_type")
        if marker and canary is True and negative in {None, False, "rejected"}:
            return _result("supported", True, ["Exact type marker with bounded canary; gadget/RCE not proven."])
        return _result("inconclusive", False, ["Type marker without a bounded canary is insufficient."])
    if oracle_type == "bounded_side_effect":
        if observations.get("reflection_excluded") is not True or observations.get("timing_not_sole_evidence") is not True:
            return _result("inconclusive", False, ["Reflection or timing alone cannot prove a side effect."])
        if observations.get("attack_canary") is True and observations.get("normal_control") is False \
                and observations.get("negative_control") is False:
            return _result("supported", True, ["Isolated canary effect; only a bounded side effect is proven."])
        return _result("inconclusive", False, ["Canary effect lacks independent normal/negative control."])
    if oracle_type == "upload_path_escape":
        root = str(observations.get("allowed_root") or "").rstrip("/")
        stored = str(observations.get("stored_path") or "")
        if not root or not stored:
            return _result("inconclusive", False, ["Storage contract or stored path missing."])
        readback_ok = _eq(observations.get("readback_content"), observations.get("owned_content"))
        if readback_ok and not stored.startswith(root + "/") and observations.get("filename_content_separated") is True:
            return _result("supported", True, ["File read back outside the declared root; code execution not proven."])
        return _result("inconclusive", False, ["Returned path alone does not prove escape."])
    if oracle_type == "browser_runtime":
        if observations.get("trigger_source") != "application" or observations.get("application_triggered") is not True:
            return _result("inconclusive", False, ["Only application-triggered runtime dialogs count; manual evaluate is not proof."])
        if observations.get("attack_dialog") is True and observations.get("normal_dialog") is False \
                and observations.get("consumer_page") and observations.get("same_identity") is True \
                and observations.get("content_version"):
            return _result("supported", True, ["Application-triggered runtime dialog on the real consumer page."])
        return _result("inconclusive", False, ["Runtime dialog is not bound to the consumer and attack content version."])
    if oracle_type == "race":
        if observations.get("barrier_used") is not True:
            return _result("inconclusive", False, ["No real concurrent barrier; sequential replay is not a race."])
        if observations.get("effect_count", 0) > observations.get("sequential_effect_count", 0):
            return _result("supported", True, ["Concurrent effect count exceeds the sequential control."])
        return _result("inconclusive", False, ["Concurrency did not produce a discriminating effect."])
    if oracle_type == "token_lifecycle":
        if observations.get("reuse_worked") is True or observations.get("expired_worked") is True:
            return _result("supported", True, ["Token remained usable beyond its declared lifecycle."])
        return _result("refuted", False, ["Token was rejected on reuse/expiry in this bounded check."])
    if oracle_type == "state_invariant":
        if observations.get("invariant_violated") is True:
            return _result("supported", True, ["Business invariant violated by a real read/write/read sequence."])
        return _result("refuted", False, ["Invariant held in this bounded check."])
    if oracle_type == "state_transition":
        if observations.get("forbidden_transition_succeeded") is True:
            return _result("supported", True, ["Forbidden transition completed and was read back."])
        return _result("refuted", False, ["Transition was rejected or state unchanged."])
    if oracle_type == "extraction":
        if observations.get("extraction_matched") is True and observations.get("reflection_excluded") is True:
            return _result("supported", True, ["Expected controlled extraction observed."])
        return _result("inconclusive", False, ["No discriminating extraction."])
    if oracle_type == "error_channel":
        if observations.get("attack_error") and observations.get("baseline_ok") and observations.get("recovery_ok") \
                and observations.get("negative_ok"):
            return _result("supported", True, ["DBMS error signature isolated to the attack input."])
        return _result("inconclusive", False, ["Error signature is not isolated or not a DBMS channel."])
    if oracle_type == "sql_metadata":
        if observations.get("business_count_changed") is True and observations.get("same_identity") is True:
            return _result("supported", True, ["Bounded business-count change under the same identity."])
        return _result("inconclusive", False, ["No discriminating business-count change."])
    return _result("inconclusive", False, ["No evaluator for this profile."])


def _result(outcome, finding_allowed, limitations):
    return {"outcome": outcome, "finding_allowed": bool(finding_allowed),
            "limitations": limitations, "proof_scope": None}


def describe(oracle_type):
    profile_row = profile(oracle_type)
    return {
        "type": oracle_type,
        "version": profile_row["version"],
        "proof_scope": profile_row["proof_scope"],
        "confirmable": profile_row["confirmable"],
        "requires": profile_row["requires"],
        "not_proof": profile_row["not_proof"],
        "mechanism_contract": profile_row["mechanism_contract"],
        "severity_cap": profile_row["severity_cap"],
        "invalidation": ["recipe spec hash", "operator/rule version", "target build", "consumer evidence", "evidence digest"],
    }
