"""Hypothesis: a precise, stable security question, not a renamed obligation.

Identity is the stable mechanism key from the review contract:
``family/property + operation/protocol + input location/selector/branch +
actor-role/resource relation + business precondition + scope epoch + target
build``.  A statement may change wording without creating a second task.
"""
from __future__ import annotations

from .common import digest, enum, mapping, optional_text, sequence, stable_id, string_list, text, utc_now

STATUSES = {"unplanned", "ready", "running", "supported", "refuted", "inconclusive", "blocked", "not_applicable"}
TERMINAL = {"supported", "refuted", "inconclusive", "not_applicable"}
TRANSITIONS = {
    "unplanned": {"ready", "blocked", "not_applicable"},
    "ready": {"running", "blocked", "not_applicable", "unplanned"},
    "running": {"supported", "refuted", "inconclusive", "blocked"},
    "blocked": {"ready", "not_applicable"},
    "inconclusive": {"ready", "blocked", "supported"},
    "supported": {"ready"},
    "refuted": {"ready"},
    "not_applicable": {"ready"},
}
FAMILIES = ("access_control", "sql_injection", "xss", "ssrf", "xxe", "path_traversal",
            "command_injection", "template_injection", "deserialization", "file_upload",
            "business_logic", "generic")
SOURCE_KINDS = {"known_case", "declared_family", "field_semantics", "access_policy",
                "page_function", "imported_hint", "legacy_obligation", "manual"}
MISSING_CONTEXT = {
    "actual_input_consumer", "verified_principal_and_roles", "verified_tenant_membership",
    "owned_test_fixture", "server_authoritative_bounds", "server_time_reference",
    "business_time_window", "browser_consumer_context", "allowed_navigation_policy",
    "outbound_destination_policy", "non_executing_canary_fixture", "independent_negative_control",
    "upload_storage_contract", "declared_parser_contract", "declared_transition_policy",
    "replay_semantics", "state_readback", "token_issuance_context", "lifecycle_policy",
    "required_factor_policy", "retry_window_policy", "exact_authorized_url", "current_http_observation",
    "normal_business_assertion", "property_specific_controls", "scope_epoch", "target_build",
}


def identity(**kwargs):
    """Return the canonical mechanism identity dictionary."""
    required = ("family", "security_property", "operation_id", "input_key", "relation",
                "business_precondition", "scope_epoch", "target_build", "source_kind")
    missing = [key for key in required if key not in kwargs]
    if missing:
        from .common import fail
        fail("v2_hypothesis_identity", "Hypothesis identity is missing: " + ", ".join(missing))
    row = {key: kwargs[key] for key in required}
    row["protocol"] = kwargs.get("protocol", "http")
    row["input_key"] = kwargs["input_key"]
    return row


def new_hypothesis(*, family, security_property, operation_id, input_key=None, relation=None,
                   business_precondition=None, scope_epoch, target_build, source_kind,
                   protocol="http", statement, label=None, source_ref=None, priority=None,
                   missing_context=None, status="unplanned", known_case_id=None):
    enum(family, "hypothesis_family", set(FAMILIES))
    enum(source_kind, "hypothesis_source", SOURCE_KINDS)
    enum(status, "hypothesis_status", STATUSES)
    security_property = text(security_property, "security_property", maximum=128)
    operation_id = text(operation_id, "operation_id", maximum=128)
    statement = text(statement, "statement")
    relation_row = mapping(relation or {"actor": "any", "resource": "any"}, "relation")
    identity_row = identity(
        family=family, security_property=security_property, operation_id=operation_id,
        input_key=input_key, relation=relation_row,
        business_precondition=business_precondition, scope_epoch=scope_epoch,
        target_build=target_build, source_kind=source_kind, protocol=protocol)
    hypothesis_id = stable_id("HYP", identity_row)
    return {
        "id": hypothesis_id,
        "identity": identity_row,
        "identity_hash": digest(identity_row),
        "family": family,
        "security_property": security_property,
        "operation_id": operation_id,
        "input_key": input_key,
        "input_id": input_key,
        "protocol": protocol,
        "relation": relation_row,
        "business_precondition": business_precondition,
        "scope_epoch": scope_epoch,
        "target_build": target_build,
        "source_kind": source_kind,
        "source_ref": optional_text(source_ref, "source_ref", maximum=2048),
        "known_case_id": optional_text(known_case_id, "known_case_id", maximum=128),
        "statement": statement,
        "label": optional_text(label, "label", maximum=512),
        "priority": priority if isinstance(priority, dict) else {},
        "status": status,
        "state_reason": None,
        "missing_context": string_list(missing_context or [], "missing_context", allowed=MISSING_CONTEXT),
        "attempt": {
            "attempt_count": 0,
            "consecutive_failures": 0,
            "last_attempt_at": None,
            "last_outcome": None,
            "blocked_reason": None,
        },
        "recipe_ids": [],
        "run_ids": [],
        "finding_ids": [],
        "superseded": False,
        "superseded_at": None,
        "revision": 1,
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }


def transition(hypothesis, status, *, reason=None, missing_context=None):
    enum(status, "hypothesis_status", STATUSES)
    current = hypothesis.get("status", "unplanned")
    if current == status:
        return hypothesis
    if status not in TRANSITIONS.get(current, set()):
        from .common import fail
        fail("v2_hypothesis_transition", f"Hypothesis cannot move from {current} to {status}")
    if status == "not_applicable" and not hypothesis.get("applicability_basis"):
        from .common import fail
        fail("v2_hypothesis_applicability", "not_applicable requires a business-fact applicability basis")
    hypothesis["status"] = status
    hypothesis["state_reason"] = optional_text(reason, "state_reason")
    if missing_context is not None:
        hypothesis["missing_context"] = string_list(missing_context, "missing_context", allowed=MISSING_CONTEXT)
    hypothesis["updated_at"] = utc_now()
    hypothesis["revision"] = int(hypothesis.get("revision", 1)) + 1
    return hypothesis


def record_attempt(hypothesis, *, outcome, run_id, reason=None, cooldown_seconds=300):
    enum(outcome, "attempt_outcome", {"supported", "refuted", "inconclusive", "blocked", "execution_failed", "effect_unknown"})
    attempt = hypothesis.setdefault("attempt", {})
    attempt["attempt_count"] = int(attempt.get("attempt_count", 0)) + 1
    if outcome in {"blocked", "inconclusive", "execution_failed", "effect_unknown"}:
        attempt["consecutive_failures"] = int(attempt.get("consecutive_failures", 0)) + 1
    else:
        attempt["consecutive_failures"] = 0
    attempt["last_attempt_at"] = utc_now()
    attempt["last_outcome"] = outcome
    attempt["blocked_reason"] = optional_text(reason, "blocked_reason", maximum=1024)
    attempt["revision_at_attempt"] = hypothesis.get("revision", 1)
    if attempt["consecutive_failures"] >= 2:
        from datetime import datetime, timedelta, timezone
        attempt["cooldown_until"] = (datetime.now(timezone.utc)
                                      + timedelta(seconds=int(cooldown_seconds))).isoformat()
    else:
        attempt.pop("cooldown_until", None)
    if run_id and run_id not in hypothesis.setdefault("run_ids", []):
        hypothesis["run_ids"].append(run_id)
    hypothesis["updated_at"] = utc_now()
    hypothesis["revision"] = int(hypothesis.get("revision", 1)) + 1
    return hypothesis


def requires_preparation(hypothesis):
    """A hypothesis with missing context is a preparation task, never N/A."""
    if hypothesis.get("status") == "blocked" or hypothesis.get("missing_context"):
        return True
    return False


def public_view(hypothesis):
    return {
        key: hypothesis.get(key) for key in (
            "id", "family", "security_property", "operation_id", "input_key", "input_id", "protocol",
            "relation", "business_precondition", "source_kind", "source_ref", "known_case_id",
            "statement", "label", "status", "state_reason", "missing_context", "attempt",
            "recipe_ids", "run_ids", "finding_ids", "revision", "superseded")
    }
