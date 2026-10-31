"""Evidence lineage: capture-time policy snapshot so re-registration does not silently void evidence.

Problem observed in two rounds (heasec-mall): registering an operation twice (e.g. to add
`content_type` after the first capture) changes `operation_signature`, which made every
prior capture unusable with the opaque error "Operation policy changed after this capture".
The captures were still valid observations of the same URL/method; only the declared
policy changed.

This module records the *policy fields that actually affect evidence interpretation*
at capture time and computes whether a later operation record is still compatible.
"""
from __future__ import annotations

import hashlib
import json

# Fields that change what a capture means. Ordering is fixed so the digest is stable.
POLICY_FIELDS = ("url", "method", "protocol", "operation_name", "content_type",
                 "auth", "allowed_roles", "ownership", "state_scope")

# Fields whose change is purely additive/descriptive and never invalidates a capture.
BENIGN_FIELDS = ("inputs", "sources", "created_at")


def policy_snapshot(operation):
    """The interpretation-relevant subset of an operation record."""
    snapshot = {name: operation.get(name) for name in POLICY_FIELDS}
    if snapshot.get("state_scope") is None:
        # Keep legacy digests stable unless self-state write authority is declared.
        snapshot.pop("state_scope")
    if isinstance(snapshot.get("allowed_roles"), list):
        snapshot["allowed_roles"] = sorted(snapshot["allowed_roles"])
    if isinstance(snapshot.get("content_type"), str):
        # `application/json` and `application/json;charset=UTF-8` are the same media type
        # for evidence purposes; the transport sends whatever the operation declares.
        snapshot["content_type"] = snapshot["content_type"].split(";", 1)[0].strip().lower()
    return snapshot


def policy_digest(operation):
    payload = json.dumps(policy_snapshot(operation), ensure_ascii=False,
                         sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "P-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def describe_change(before, after):
    """Human-readable list of interpretation-relevant differences (for error messages)."""
    left, right = policy_snapshot(before), policy_snapshot(after)
    changes = []
    for name in POLICY_FIELDS:
        if left.get(name) != right.get(name):
            changes.append({"field": name, "captured": left.get(name), "current": right.get(name)})
    return changes


def compatibility(operation, evidence, signature):
    """Return (ok, detail).

    An evidence record captured under this operation stays usable when either
    - its recorded policy digest equals the current interpretation-relevant policy, or
    - (legacy evidence written before digests existed) its operation signature matches.

    `signature` is the caller's operation_signature(operation); passing it in keeps this
    module free of a circular import with engine.py.
    """
    current = policy_digest(operation)
    recorded = evidence.get("policy_digest")
    if recorded is None:
        # Legacy evidence predates digest stamping; the coarse signature is all we have.
        return evidence.get("operation_signature") == signature, {"mode": "legacy_signature"}
    if recorded == current:
        return True, {"mode": "policy_digest"}
    return False, {
        "mode": "policy_digest",
        "recorded": recorded,
        "current": current,
        "changes": describe_change(evidence.get("policy_snapshot") or {}, operation),
    }
