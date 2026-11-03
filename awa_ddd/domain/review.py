"""Structured ReviewAcceptanceContract for reviewed detection.

A reviewer/reason pair alone is not enough: the contract binds the exact
mechanism, input/branch, control roles, observations, consumer point, source
trust, reviewer provenance and material digests.  It can close a *detection*
hypothesis, but it never becomes machine proof and the reviewer type is
reported honestly (agent-recorded reviews are not independent human approval).
"""
from __future__ import annotations

from .common import digest, enum, fail, mapping, optional_text, sequence, stable_id, string_list, text, utc_now

PROOF_SCOPES = {
    "authorization_boundary", "semantic_refutation", "state_transition",
    "stored_xss_cross_role", "reflected_xss", "dom_xss", "template_evaluation",
    "parser_identification", "unsafe_type_instantiation", "bounded_side_effect",
    "upload_path_escape", "business_logic", "information_exposure", "other",
}
REVIEWER_TYPES = {"human_independent", "analyst_recorded", "agent_recorded"}
CONSUMER_TYPES = {"http_json", "html", "browser_runtime", "business_state", "http_error"}
SOURCE_TRUST = {"verified", "declared", "unverified"}


def new_review_contract(*, hypothesis, run, mechanism, identity, control_groups,
                        observation, consumer_point, source_trust, reviewer,
                        proof_scope, material, verification):
    """Validate and freeze a review contract.  Currency checks happen in execution/review."""
    mapping(mechanism, "mechanism")
    for field in ("family", "security_property", "operation_id"):
        text(mechanism.get(field), "mechanism_" + field, maximum=128)
    if mechanism["family"] != hypothesis.get("family"):
        fail("v2_review_mechanism", "Review family does not match its hypothesis")
    if mechanism.get("security_property") != hypothesis.get("security_property"):
        fail("v2_review_mechanism", "Review security property does not match its hypothesis")
    if mechanism.get("input_key") != hypothesis.get("input_key"):
        fail("v2_review_mechanism", "Review input identity does not match its hypothesis")
    mapping(identity, "identity")
    groups = sequence(control_groups, "control_groups", maximum=8)
    if not groups:
        fail("v2_review_controls", "Review requires at least one control group")
    group_ids = set()
    for group in groups:
        mapping(group, "control_group")
        group_id = text(group.get("id"), "control_group_id", maximum=64)
        if group_id in group_ids:
            fail("v2_review_controls", "Control group IDs must be unique")
        group_ids.add(group_id)
        controls = sequence(group.get("controls"), "controls", maximum=8)
        roles = [enum(control.get("role"), "control_role", {"normal", "attack", "negative", "sensitivity"})
                 for control in controls]
        if "normal" not in roles or "attack" not in roles:
            fail("v2_review_controls", f"Control group {group_id} needs normal and attack evidence")
        for control in controls:
            text(control.get("evidence_id"), "control_evidence_id", maximum=128)
    observation = mapping(observation, "observation")
    text(observation.get("selector"), "observation_selector", maximum=1024)
    if "expected" not in observation or "actual" not in observation:
        fail("v2_review_observation", "Observation requires expected and actual values")
    consumer = mapping(consumer_point, "consumer_point")
    enum(consumer.get("type"), "consumer_type", CONSUMER_TYPES)
    if consumer.get("type") != "business_state":
        text(consumer.get("url"), "consumer_url", maximum=8192)
    text(consumer.get("identity_role"), "consumer_identity_role", maximum=64)
    source = mapping(source_trust, "source_trust")
    enum(source.get("trust"), "source_trust_level", SOURCE_TRUST)
    reviewer = mapping(reviewer, "reviewer")
    reviewer_type = enum(reviewer.get("type"), "reviewer_type", REVIEWER_TYPES)
    text(reviewer.get("id"), "reviewer_id", maximum=200)
    text(reviewer.get("source"), "reviewer_source", maximum=200)
    if reviewer_type == "agent_recorded" and reviewer.get("human_approved") is True:
        fail("v2_review_reviewer", "An agent-recorded review cannot self-declare human approval")
    scope = mapping(proof_scope, "proof_scope")
    accepted = string_list(scope.get("accepted") or [], "accepted_proof_scopes", allowed=PROOF_SCOPES)
    if not accepted:
        fail("v2_review_scope", "Review must declare at least one accepted proof scope")
    not_proven = string_list(scope.get("not_proven") or [], "not_proven", maximum=64)
    material = mapping(material, "material")
    evidence_ids = sequence(material.get("evidence_ids"), "material_evidence_ids", maximum=256)
    if not evidence_ids:
        fail("v2_review_material", "Review material must reference current evidence")
    digests = mapping(material.get("digests"), "material_digests")
    for evidence_id in evidence_ids:
        if not isinstance(evidence_id, str) or len(evidence_id) > 128:
            fail("v2_review_material", "Review evidence IDs must be strings")
        if not isinstance(digests.get(evidence_id), str) or len(digests[evidence_id]) != 64:
            fail("v2_review_material", "Each reviewed evidence item requires its SHA-256 digest")
    verification = mapping(verification, "verification")
    contract = {
        "schema": 2,
        "hypothesis_id": hypothesis["id"],
        "run_id": run.get("id") if run else None,
        "mechanism": {key: mechanism.get(key) for key in (
            "family", "security_property", "operation_id", "input_key", "location", "selector",
            "schema_branch", "branch", "mechanism_note")},
        "identity": {key: identity.get(key) for key in (
            "actor_id", "tenant_id", "session_generation", "resource_id", "fixture_id")},
        "control_groups": groups,
        "observation": dict(observation),
        "consumer_point": dict(consumer),
        "source_trust": dict(source),
        "reviewer": {"type": reviewer_type, "id": reviewer["id"], "source": reviewer["source"],
                     "independent_human": reviewer_type == "human_independent"},
        "proof_scope": {"accepted": accepted, "not_proven": not_proven},
        "material": {"evidence_ids": evidence_ids, "digests": dict(digests)},
        "verification": {"version": text(verification.get("version", "1"), "verification_version", maximum=32),
                         "method": text(verification.get("method", "manual_review"), "verification_method", maximum=128),
                         "checked_at": verification.get("checked_at") or utc_now()},
        "created_at": utc_now(),
    }
    contract["id"] = stable_id("REV", contract)
    contract["contract_hash"] = digest(contract)
    return contract


def validate_cross_role(contract, *, hypothesis, run):
    """Stored XSS style writer/viewer chains require two independently bound groups."""
    family = hypothesis.get("family")
    if family != "xss" or contract["consumer_point"].get("type") != "browser_runtime":
        return True
    groups = {group["id"]: group for group in contract["control_groups"]}
    if "writer" not in groups or "viewer" not in groups:
        fail("v2_review_cross_role", "Cross-role browser XSS requires writer and viewer control groups")
    writer_attack = next((control for control in groups["writer"]["controls"] if control["role"] == "attack"), None)
    viewer_attack = next((control for control in groups["viewer"]["controls"] if control["role"] == "attack"), None)
    if not writer_attack or not viewer_attack:
        fail("v2_review_cross_role", "Writer and viewer groups both require attack controls")
    if groups["writer"].get("resource_version") != groups["viewer"].get("resource_version"):
        fail("v2_review_cross_role", "Writer and viewer must observe the same resource/content version")
    if writer_attack.get("content_digest") != viewer_attack.get("content_digest"):
        fail("v2_review_cross_role", "Writer attack content and viewer consumed content digests differ")
    if contract["consumer_point"].get("identity_role") != groups["viewer"].get("identity_role"):
        fail("v2_review_cross_role", "Consumer identity does not match the viewer control group")
    return True


def public_view(contract):
    return {
        key: contract.get(key) for key in (
            "id", "hypothesis_id", "run_id", "mechanism", "identity", "control_groups",
            "observation", "consumer_point", "source_trust", "reviewer", "proof_scope",
            "verification", "created_at", "contract_hash")
    }
