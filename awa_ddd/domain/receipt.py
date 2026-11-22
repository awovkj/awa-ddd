"""Immutable proof, applicability and frontier receipts.

Mutable status projections are not proof.  Receipts freeze the accepted claim,
its exact material and the dependency revisions that gave it meaning.  Whether
a receipt remains current is derived by rechecking those dependencies.
"""
from __future__ import annotations

from .common import digest, enum, fail, mapping, optional_text, sequence, stable_id, string_list, text, utc_now
from .taxonomy import require_family


RECEIPT_DECISIONS = {"proposed", "accepted", "rejected"}
DEPENDENCY_KINDS = {
    "scope", "target_build", "campaign", "universe", "operation", "evidence",
    "session", "resource", "fixture", "source_snapshot", "page", "material",
    "known_case", "hypothesis", "recipe", "run", "review", "finding", "receipt",
}
PROOF_MODES = {"machine", "reviewed"}
_ACCEPTED_RECEIPT_DEPENDENCIES = {
    "applicability": {"scope", "target_build", "campaign", "hypothesis", "evidence", "material"},
    "proof": {"scope", "target_build", "campaign", "hypothesis", "run", "evidence"},
    "frontier": {"campaign", "universe"},
}

_STORE_KINDS = {
    "campaign": "v2_campaign",
    "universe": "v2_universe",
    "operation": "operation",
    "session": "session",
    "resource": "resource",
    "fixture": "v2_fixture",
    "known_case": "v2_known_case",
    "hypothesis": "v2_hypothesis",
    "recipe": "v2_recipe",
    "run": "v2_run",
    "review": "v2_review",
    "finding": "v2_finding",
}
_RECEIPT_KINDS = {
    "applicability": "v2_applicability_receipt",
    "proof": "v2_review_proof_receipt",
    "frontier": "v2_frontier_receipt",
}


def _material_hash(project, evidence_id):
    from .. import engine

    evidence, _artifact = engine.verify_current_evidence(project, evidence_id)
    return evidence.get("sha256")


def new_dependency(*, kind, identity, revision=None, fingerprint=None, metadata=None):
    enum(kind, "receipt_dependency_kind", DEPENDENCY_KINDS)
    identity = text(identity, "receipt_dependency_id", maximum=512)
    if revision is None and fingerprint is None:
        fail("v2_receipt_dependency", "A receipt dependency requires a revision or fingerprint")
    if revision is not None and (type(revision) is not int or revision < 1):
        fail("v2_receipt_dependency", "Dependency revision must be a positive integer")
    if fingerprint is not None:
        fingerprint = text(fingerprint, "receipt_dependency_fingerprint", maximum=256)
    row = {
        "kind": kind,
        "id": identity,
        "revision": revision,
        "fingerprint": fingerprint,
        "metadata": mapping(metadata or {}, "receipt_dependency_metadata"),
    }
    row["key"] = stable_id("DEP", row)
    return row


def evidence_dependencies(project, evidence_ids):
    rows = []
    for evidence_id in string_list(evidence_ids, "receipt_evidence_ids", maximum=256):
        from .. import engine

        evidence, _artifact = engine.verify_current_evidence(project, evidence_id)
        rows.append(new_dependency(
            kind="evidence", identity=evidence_id,
            fingerprint=evidence.get("sha256"),
            metadata={"artifact_path": evidence.get("artifact_path")}))
    return rows


def entity_dependency(project, kind, identity, *, fingerprint_fields=None, metadata=None):
    """Freeze a receipt dependency on one existing project entity.

    Callers should pass ``fingerprint_fields`` for mutable aggregates so an
    unrelated revision (for example a scheduler cursor or attempt counter) does
    not invalidate a proof.  Without a field projection, the current revision is
    used and every mutation intentionally expires the dependency.
    """
    enum(kind, "receipt_dependency_kind", DEPENDENCY_KINDS - {
        "scope", "target_build", "evidence", "material", "receipt"})
    store_kind = _STORE_KINDS.get(kind)
    if store_kind is None:
        fail("v2_receipt_dependency", f"Entity dependency kind is not addressable: {kind}")
    row = project.get(store_kind, identity)
    revision = project.get_revision(store_kind, identity)
    fields = tuple(fingerprint_fields or ())
    fingerprint = digest({field: row.get(field) for field in fields}) if fields else None
    if fingerprint is None:
        fingerprint = _entity_fingerprint(kind, row)
    metadata = dict(metadata or {})
    if fields:
        # The validation path must project the live row through the same fields.
        # Otherwise the frozen projection can never match the entity's default
        # fingerprint and a fresh receipt is reported as expired immediately.
        metadata["fingerprint_fields"] = list(fields)
    return new_dependency(
        kind=kind,
        identity=identity,
        revision=None if fingerprint is not None else revision,
        fingerprint=fingerprint,
        metadata=metadata,
    )


def scope_dependency(project):
    config = project.config
    return new_dependency(
        kind="scope",
        identity="project_scope",
        fingerprint=digest({
            "scope": config.get("scope") or [],
            "exclude": config.get("exclude") or [],
        }),
    )


def target_build_dependency(project, universe):
    return new_dependency(
        kind="target_build",
        identity=universe["id"],
        fingerprint=universe.get("snapshot_hash"),
        metadata={
            "universe_id": universe["id"],
            "target_build": universe.get("target_build") or "unknown",
            "requires_platform_build": universe.get("target_build") not in {None, "", "unknown"},
        },
    )


def receipt_dependency(receipt):
    return new_dependency(
        kind="receipt",
        identity=receipt["id"],
        fingerprint=receipt["receipt_hash"],
        metadata={"receipt_kind": receipt["kind"]},
    )


def _receipt_identity_requirements(receipt):
    requirements = []
    for kind, identity in (
            ("campaign", receipt.get("campaign_id")),
            ("hypothesis", receipt.get("hypothesis_id")),
            ("run", receipt.get("run_id")),
            ("review", receipt.get("review_id"))):
        if identity:
            requirements.append((kind, identity))
    evidence_ids = (receipt.get("material") or {}).get("evidence_ids") or []
    requirements.extend(("evidence", identity) for identity in evidence_ids)
    return requirements


def _receipt_dependency_issues(receipt):
    """Return structural gaps that prevent a receipt from carrying authority."""
    kind = receipt.get("kind")
    dependencies = receipt.get("dependencies")
    if not isinstance(dependencies, list):
        return ["dependencies are missing"]
    indexes = {}
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            return ["dependencies contain a non-object"]
        indexes.setdefault(dependency.get("kind"), []).append(dependency.get("id"))
    issues = [
        "missing " + required + " dependency"
        for required in sorted(_ACCEPTED_RECEIPT_DEPENDENCIES.get(kind, set())
                               - set(indexes))
    ]
    for dependency_kind, identity in _receipt_identity_requirements(receipt):
        if dependency_kind in _ACCEPTED_RECEIPT_DEPENDENCIES.get(kind, set()) \
                and identity not in indexes.get(dependency_kind, []):
            issues.append(
                f"{dependency_kind} dependency does not bind {identity}")
    if kind == "proof" and receipt.get("mode") == "reviewed" \
            and not receipt.get("review_id"):
        issues.append("reviewed proof is missing review_id")
    return issues


def _current_entity(project, dependency):
    kind = dependency["kind"]
    identity = dependency["id"]
    if kind in _STORE_KINDS:
        store_kind = _STORE_KINDS[kind]
        row = project.get(store_kind, identity, required=False)
        return row, _revision(project, store_kind, identity, row)
    if kind == "receipt":
        for store_kind in _RECEIPT_KINDS.values():
            row = project.get(store_kind, identity, required=False)
            if row is not None:
                return row, _revision(project, store_kind, identity, row)
        return None, None
    if kind == "source_snapshot":
        row = project.get("discovery_snapshot", identity, required=False)
        return row, _revision(project, "discovery_snapshot", identity, row)
    if kind == "page":
        row = project.get("page", identity, required=False)
        return row, _revision(project, "page", identity, row)
    return None, None


def _revision(project, store_kind, identity, row):
    if row is None:
        return None
    try:
        return project.get_revision(store_kind, identity)
    except Exception:
        return None


def _entity_fingerprint(kind, row):
    if kind == "universe":
        return row.get("snapshot_hash")
    if kind == "hypothesis":
        return row.get("identity_hash")
    if kind == "recipe":
        return row.get("spec_hash")
    if kind == "review":
        return row.get("contract_hash")
    if kind == "run":
        identity = {key: row.get(key) for key in (
            "id", "campaign_id", "hypothesis_id", "recipe_id", "recipe_spec_hash",
            "mode", "evidence_ids", "evaluation", "outcome", "effect",
        )}
        return digest(identity)
    if kind == "fixture":
        return digest({key: row.get(key) for key in (
            "id", "operation_id", "owner_actor_id", "resource_id", "revision", "state",
            "unresolved", "cleanup_status",
        )})
    if kind == "session":
        return digest({key: row.get(key) for key in (
            "id", "actor_id", "generation", "expires_at", "revoked_at",
            "credential_signature", "actor_signature",
        )})
    if kind == "resource":
        return digest({key: row.get(key) for key in (
            "id", "operation_id", "owner_actor_id", "external_id", "request_binding",
            "revision",
        )})
    return row.get("snapshot_hash") or row.get("sha256") or row.get("hash")


def dependency_current(project, dependency, *, seen=None):
    """Return (current, reason, observed) for one dependency."""
    seen = set() if seen is None else set(seen)
    kind, identity = dependency.get("kind"), dependency.get("id")
    expected_revision = dependency.get("revision")
    expected_fingerprint = dependency.get("fingerprint")
    metadata = dependency.get("metadata") or {}
    if kind == "scope":
        current_fingerprint = digest({
            "scope": project.config.get("scope") or [],
            "exclude": project.config.get("exclude") or [],
        })
        return _compare_fingerprint(expected_fingerprint, current_fingerprint,
                                    "project scope changed")
    if kind == "target_build":
        universe = project.get("v2_universe", metadata.get("universe_id") or identity,
                               required=False)
        if universe is None:
            return False, "target-build universe is missing", None
        current_fingerprint = universe.get("target_build") or "unknown"
        provenance = universe.get("target_build_provenance") or {}
        expected_build = metadata.get("target_build") or "unknown"
        if current_fingerprint != expected_build:
            return False, "target build changed", {
                "expected": expected_build, "current": current_fingerprint}
        if metadata.get("requires_platform_build") and provenance.get("status") not in {
                "observed", "verified"}:
            return False, "target build is no longer verifiable", {
                "target_build": current_fingerprint,
                "provenance": provenance,
            }
        return True, "current", {
            "target_build": current_fingerprint, "provenance_status": provenance.get("status")}
    if kind == "evidence":
        try:
            from .. import engine

            evidence, _artifact = engine.verify_current_evidence(project, identity)
        except Exception as exc:
            return False, "evidence is missing or changed: " + str(exc), None
        return _compare_fingerprint(expected_fingerprint, evidence.get("sha256"),
                                    "evidence digest changed")
    if kind == "material":
        try:
            material_id = metadata.get("material_id")
            if material_id:
                record, _data = project.read_material(material_id)
                return _compare_fingerprint(
                    expected_fingerprint, record.get("sha256"),
                    "content-addressed material changed",
                )
            current_fingerprint = _material_hash(project, metadata.get("evidence_id") or identity)
        except Exception as exc:
            return False, "material is missing or changed: " + str(exc), None
        return _compare_fingerprint(expected_fingerprint, current_fingerprint,
                                    "material digest changed")
    if kind == "receipt":
        if identity in seen:
            return False, "receipt dependency cycle", None
        receipt = None
        for store_kind in _RECEIPT_KINDS.values():
            receipt = project.get(store_kind, identity, required=False)
            if receipt is not None:
                break
        if receipt is None:
            return False, "dependent receipt is missing", None
        expected_kind = metadata.get("receipt_kind")
        if expected_kind and receipt.get("kind") != expected_kind:
            return False, "dependent receipt kind changed", {
                "expected": expected_kind, "current": receipt.get("kind")}
        if expected_fingerprint and receipt.get("receipt_hash") != expected_fingerprint:
            return False, "dependent receipt changed", {
                "expected": expected_fingerprint, "current": receipt.get("receipt_hash")}
        child_seen = set(seen)
        child_seen.add(identity)
        evaluation = evaluate_receipt(project, receipt, seen=child_seen)
        return evaluation["current"], evaluation["reason"], {
            "receipt_id": identity, "status": evaluation["status"]}
    row, current_revision = _current_entity(project, dependency)
    if row is None:
        return False, f"{kind} no longer exists", None
    if expected_revision is not None and current_revision != expected_revision:
        return False, f"{kind} revision changed", {
            "expected_revision": expected_revision,
            "current_revision": current_revision,
        }
    if expected_fingerprint is not None:
        fields = metadata.get("fingerprint_fields")
        if fields:
            observed_fingerprint = digest({field: row.get(field) for field in fields})
        else:
            observed_fingerprint = _entity_fingerprint(kind, row)
        if observed_fingerprint != expected_fingerprint:
            return False, f"{kind} fingerprint changed", {
                "expected": expected_fingerprint, "current": observed_fingerprint}
        for key, expected in metadata.items():
            if key.startswith("expect_") and row.get(key[7:]) != expected:
                return False, f"{kind} {key[7:]} changed", {
                    "expected": expected, "current": row.get(key[7:])}
    return True, "current", {"revision": current_revision}


def _compare_fingerprint(expected, actual, reason):
    if expected != actual:
        return False, reason, {"expected": expected, "current": actual}
    return True, "current", {"fingerprint": actual}


def evaluate_dependencies(project, dependencies, *, seen=None):
    sequence(dependencies, "receipt_dependencies", maximum=512)
    stale = []
    for dependency in dependencies:
        mapping(dependency, "receipt_dependency")
        current, reason, observed = dependency_current(project, dependency, seen=seen)
        if not current:
            stale.append({
                "dependency": dependency,
                "reason": reason,
                "observed": observed,
            })
    return {
        "current": not stale,
        "status": "current" if not stale else "expired",
        "dependencies": len(dependencies),
        "stale": stale,
    }


def new_applicability_receipt(*, campaign_id, hypothesis_id, security_property, input_key,
                              input_branch, predicate, verifier, evidence_ids, digests,
                              reviewer, dependencies, decision="accepted", reason=None,
                              manifest_material=None, bindings=None, proof=None):
    """Freeze an exact not-applicable predicate and its verifier material."""
    enum(decision, "applicability_decision", RECEIPT_DECISIONS)
    predicate = mapping(predicate, "applicability_predicate")
    operator = text(predicate.get("operator"), "applicability_operator", maximum=64)
    if operator in {"", "unknown", "guess"}:
        fail("v2_applicability_predicate", "Applicability requires a concrete predicate operator")
    for field in ("subject", "expected"):
        if field not in predicate:
            fail("v2_applicability_predicate", "Applicability predicate requires " + field)
    verifier = mapping(verifier, "applicability_verifier")
    for field in ("type", "id", "version"):
        text(verifier.get(field), "applicability_verifier_" + field, maximum=128)
    reviewer = mapping(reviewer, "applicability_reviewer")
    for field in ("type", "id", "source"):
        text(reviewer.get(field), "applicability_reviewer_" + field, maximum=200)
    evidence_ids = string_list(evidence_ids, "applicability_evidence_ids", maximum=256)
    if decision == "accepted" and not evidence_ids:
        fail("v2_applicability_evidence", "Accepted applicability requires current evidence")
    dependencies = sequence(dependencies, "applicability_dependencies", maximum=512)
    body = {
        "schema": 2,
        "kind": "applicability",
        "campaign_id": text(campaign_id, "campaign_id", maximum=128),
        "hypothesis_id": text(hypothesis_id, "hypothesis_id", maximum=128),
        "security_property": text(security_property, "security_property", maximum=128),
        "input_key": optional_text(input_key, "input_key", maximum=128),
        "bindings": mapping(bindings or {}, "applicability_bindings"),
        "input_branch": mapping(input_branch or {}, "input_branch"),
        "predicate": dict(predicate),
        "verifier": {key: verifier.get(key) for key in ("type", "id", "version", "method")},
        "evidence_ids": evidence_ids,
        "material": {
            "evidence_ids": evidence_ids,
            "digests": {key: digests.get(key) for key in evidence_ids},
        },
        "reviewer": {key: reviewer.get(key) for key in ("type", "id", "source")},
        "proof": mapping(proof or {}, "applicability_proof"),
        "manifest_material": mapping(
            manifest_material or {}, "applicability_manifest_material"),
        "dependencies": dependencies,
        "decision": decision,
        "reason": optional_text(reason, "applicability_reason", maximum=1024),
        "created_at": utc_now(),
    }
    for evidence_id in evidence_ids:
        if not isinstance(digests.get(evidence_id), str) or len(digests[evidence_id]) != 64:
            fail("v2_applicability_evidence",
                 "Applicability material requires current SHA-256 digests")
    if decision == "accepted":
        for field in (
                "operation_id", "operation_signature", "input_location",
                "input_selector", "test_family"):
            if field not in body["bindings"]:
                fail(
                    "v2_applicability_evidence",
                    "Accepted applicability requires exact Universe bindings",
                    missing=field,
                )
        required_manifest = ("material_id", "material_sha256", "build_evidence_sha256")
        for field in required_manifest:
            value = body["manifest_material"].get(field)
            if not isinstance(value, str) or not value:
                fail(
                    "v2_applicability_evidence",
                    "Accepted applicability requires an exact deployment manifest and build evidence",
                    missing=field,
                )
        for field in (
                "type", "build_evidence_id", "build_selector", "deployment_id",
                "manifest_sha256_selector", "predicate_selector", "reviewer",
                "reason"):
            if not body["proof"].get(field):
                fail(
                    "v2_applicability_evidence",
                    "Accepted applicability requires the exact deployment proof selectors",
                    missing=field,
                )
    body["id"] = stable_id("ARC", body)
    issues = _receipt_dependency_issues(body)
    if decision == "accepted" and issues:
        fail(
            "v2_receipt_dependency",
            "Accepted applicability receipt has an incomplete dependency spine",
            missing=issues,
        )
    body["receipt_hash"] = digest(body)
    return body


def new_proof_receipt(*, campaign_id, hypothesis_id, run_id, mode, proof_scope,
                      not_proven, material, reviewer, dependencies, review_id=None,
                      review_proof_receipt_id=None, decision="accepted"):
    """Freeze one machine or reviewed proof and its exact acceptance scope."""
    enum(mode, "proof_receipt_mode", PROOF_MODES)
    enum(decision, "proof_receipt_decision", RECEIPT_DECISIONS)
    run_id = text(run_id, "run_id", maximum=128)
    proof_scope = mapping(proof_scope, "proof_scope")
    accepted = string_list(proof_scope.get("accepted") or [], "proof_accepted", maximum=64)
    if decision == "accepted" and not accepted:
        fail("v2_proof_scope", "Accepted proof requires a bounded proof scope")
    material = mapping(material, "proof_material")
    evidence_ids = string_list(material.get("evidence_ids") or [], "proof_evidence_ids", maximum=256)
    if decision == "accepted" and not evidence_ids:
        fail("v2_proof_material", "Accepted proof requires current evidence")
    reviewer = mapping(reviewer, "proof_reviewer")
    for field in ("type", "id", "source"):
        text(reviewer.get(field), "proof_reviewer_" + field, maximum=200)
    dependencies = sequence(dependencies, "proof_dependencies", maximum=512)
    review_id = optional_text(review_id, "review_id", maximum=128)
    if mode == "reviewed" and not review_id:
        fail("v2_proof_receipt", "Reviewed proof requires a review_id")
    body = {
        "schema": 2,
        "kind": "proof",
        "campaign_id": text(campaign_id, "campaign_id", maximum=128),
        "hypothesis_id": text(hypothesis_id, "hypothesis_id", maximum=128),
        "run_id": run_id,
        "review_id": review_id,
        "review_proof_receipt_id": optional_text(
            review_proof_receipt_id, "review_proof_receipt_id", maximum=128),
        "mode": mode,
        "proof_scope": {
            "accepted": sorted(set(accepted)),
            "not_proven": string_list(not_proven or [], "not_proven", maximum=64),
        },
        "material": {
            "evidence_ids": evidence_ids,
            "digests": dict(material.get("digests") or {}),
        },
        "reviewer": {key: reviewer.get(key) for key in ("type", "id", "source")},
        "dependencies": dependencies,
        "decision": decision,
        "created_at": utc_now(),
    }
    for evidence_id in evidence_ids:
        if not isinstance(body["material"]["digests"].get(evidence_id), str) \
                or len(body["material"]["digests"][evidence_id]) != 64:
            fail("v2_proof_material", "Proof material requires current SHA-256 digests")
    body["id"] = stable_id("PRC", body)
    issues = _receipt_dependency_issues(body)
    if decision == "accepted" and issues:
        fail(
            "v2_receipt_dependency",
            "Accepted proof receipt has an incomplete dependency spine",
            missing=issues,
        )
    body["receipt_hash"] = digest(body)
    return body


def new_frontier_receipt(*, campaign_id, topic, material, dependencies, reviewer,
                         unresolved_items, limitations=None, decision="accepted"):
    enum(decision, "frontier_decision", RECEIPT_DECISIONS)
    dependencies = sequence(dependencies, "frontier_dependencies", maximum=512)
    material = mapping(material, "frontier_material")
    reviewer = mapping(reviewer, "frontier_reviewer")
    unresolved_items = string_list(
        unresolved_items or [], "frontier_unresolved", maximum=256)
    if decision == "accepted":
        for field in ("universe_id", "universe_snapshot_hash", "round_key"):
            text(material.get(field), "frontier_material_" + field, maximum=256)
        if material.get("campaign_id") != campaign_id:
            fail(
                "v2_frontier_scope",
                "Accepted frontier material belongs to a different campaign",
            )
        if unresolved_items:
            fail(
                "v2_frontier_unresolved",
                "Accepted frontier material cannot carry unresolved items",
            )
        for field in ("type", "id", "source"):
            text(
                reviewer.get(field),
                "frontier_reviewer_" + field,
                maximum=200,
            )
        if not any(
                dependency.get("kind") == "universe"
                and dependency.get("id") == material["universe_id"]
                for dependency in dependencies):
            fail(
                "v2_frontier_scope",
                "Accepted frontier receipt must bind its exact Universe",
            )
    body = {
        "schema": 2,
        "kind": "frontier",
        "campaign_id": text(campaign_id, "campaign_id", maximum=128),
        "topic": text(topic, "frontier_topic", maximum=256),
        "material": material,
        "dependencies": dependencies,
        "reviewer": reviewer,
        "unresolved_items": unresolved_items,
        "limitations": string_list(limitations or [], "frontier_limitations", maximum=64),
        "decision": decision,
        "created_at": utc_now(),
    }
    body["id"] = stable_id("FRC", body)
    issues = _receipt_dependency_issues(body)
    if decision == "accepted" and issues:
        fail(
            "v2_receipt_dependency",
            "Accepted frontier receipt has an incomplete dependency spine",
            missing=issues,
        )
    body["receipt_hash"] = digest(body)
    return body


def evaluate_receipt(project, receipt, *, seen=None):
    if not isinstance(receipt, dict) or receipt.get("kind") not in {
            "applicability", "proof", "frontier"}:
        fail("v2_receipt", "Unknown receipt")
    if receipt.get("decision") != "accepted":
        return {
            "id": receipt.get("id"),
            "status": receipt.get("decision") or "rejected",
            "current": False,
            "reason": "receipt decision is " + str(receipt.get("decision")),
            "dependencies": {"current": False, "stale": []},
        }
    expected_hash = receipt.get("receipt_hash")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_hash"}
    if not isinstance(expected_hash, str) or digest(unsigned) != expected_hash:
        return {
            "id": receipt.get("id"),
            "status": "invalid",
            "current": False,
            "reason": "receipt hash does not match immutable content",
            "dependencies": {"current": False, "stale": []},
        }
    issues = _receipt_dependency_issues(receipt)
    if issues:
        return {
            "id": receipt.get("id"),
            "status": "legacy",
            "current": False,
            "quarantined": True,
            "reason": "receipt has an incomplete or legacy dependency spine",
            "missing": issues,
            "dependencies": {"current": False, "stale": []},
        }
    dependency = evaluate_dependencies(
        project, receipt.get("dependencies") or [], seen=seen)
    semantic_current, semantic_reason = True, "current"
    if receipt.get("kind") == "applicability":
        from ..applicability import v2_receipt_current

        semantic_current, semantic_reason = v2_receipt_current(project, receipt)
    current = dependency["current"] and semantic_current
    return {
        "id": receipt.get("id"),
        "status": "accepted" if current else "expired",
        "current": current,
        "reason": (
            "current" if current
            else "dependency_invalidated" if not dependency["current"]
            else semantic_reason
        ),
        "dependencies": dependency,
    }


def current_receipts(project, receipt_kind, campaign_id):
    from .repository import Repository

    store_kind = _RECEIPT_KINDS.get(receipt_kind)
    if store_kind is None:
        fail("v2_receipt", "Unknown receipt kind")
    current = []
    for receipt in Repository(project, read_only=True).list_campaign(
            receipt_kind + "_receipt", campaign_id, limit=None)[0]:
        if receipt.get("campaign_id") != campaign_id:
            continue
        evaluation = evaluate_receipt(project, receipt)
        if evaluation["current"]:
            current.append((receipt, evaluation))
    return current


def public_view(receipt):
    return {
        key: receipt.get(key) for key in (
            "id", "kind", "campaign_id", "hypothesis_id", "run_id", "review_id",
            "security_property", "input_key", "input_branch", "predicate", "proof_scope",
            "material", "reviewer", "decision", "topic", "unresolved_items",
            "limitations", "created_at", "receipt_hash")
        if receipt.get(key) is not None
    }
