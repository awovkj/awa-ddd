"""Evidence-backed public fixture lifecycle; never accept caller-only state claims."""
from __future__ import annotations

from .. import engine
from ..domain.common import digest
from ..domain.repository import Repository
from ..store import EngineError, canonical
from ..transport import pointer, response_json
from . import fixtures


def _view(row):
    lease = row.get("lease") or {}
    readback = row.get("readback") or {}
    return {
        "id": row["id"], "operation_id": row["operation_id"],
        "owner_actor_id": row["owner_actor_id"], "resource_id": row["resource_id"],
        "readback_operation_id": row.get("readback_operation_id") or row["operation_id"],
        "readback_resource_id": row.get("readback_resource_id") or row["resource_id"],
        "state": row["state"], "revision": row.get("revision", 1),
        "lease": ({key: lease[key] for key in ("worker_id", "expires_at", "fence") if key in lease} or None),
        "unresolved": bool(row.get("unresolved")),
        "mutation_count": len(row.get("mutations") or []),
        "readback_ok": readback.get("ok") is True,
        "cleanup_count": len(row.get("compensation") or []),
        "in_flight": ({
            key: row["in_flight"][key]
            for key in ("run_id", "worker_id", "fence", "started_at")
            if key in row["in_flight"]
        } if isinstance(row.get("in_flight"), dict) else None),
    }


def _state_from_evidence(project, fixture, evidence_id, selector, *, after=None):
    if not isinstance(selector, str) or not selector.startswith("/"):
        raise EngineError("v2_fixture_selector", "Fixture state requires a JSON Pointer selector")
    evidence, artifact = engine.verify_current_evidence(project, evidence_id)
    if after is not None and engine.stamp(evidence["created_at"]) < after:
        raise EngineError(
            "v2_fixture_evidence_stale",
            "Fixture readback/cleanup requires new evidence captured after the current mutation or lease",
        )
    if not evidence.get("complete") or artifact.get("complete") is not True:
        raise EngineError("v2_fixture_evidence", "Fixture state requires a complete capture")
    request = artifact.get("request") or {}
    if str(request.get("method", "")).upper() not in {"GET", "HEAD", "OPTIONS"}:
        raise EngineError("v2_fixture_evidence", "Fixture state may only be asserted from a read-only capture")
    fixtures._validate_binding(project, fixture)
    if evidence.get("operation_id") != (fixture.get("readback_operation_id") or fixture["operation_id"]) \
            or evidence.get("actor_id") != fixture["owner_actor_id"] \
            or evidence.get("resource_id") != (fixture.get("readback_resource_id") or fixture["resource_id"]):
        raise EngineError(
            "v2_fixture_evidence_binding",
            "Fixture evidence must bind the declared readback operation, owner actor and resource",
        )
    return pointer(response_json(artifact), selector)


def _resource(project, args):
    operation = project.get("operation", args["operation_id"])
    actor = project.get("actor", args["owner_actor_id"])
    resource = project.get("resource", args["resource_id"])
    if resource.get("operation_id") != operation["id"] or resource.get("owner_actor_id") != actor["id"]:
        raise EngineError("v2_fixture_binding", "Fixture operation, owner and resource do not match")
    return operation, actor, resource


def _readback_binding(project, args, operation, actor, resource):
    operation_id = args.get("readback_operation_id", operation["id"])
    resource_id = args.get("readback_resource_id", resource["id"])
    readback_operation = project.get("operation", operation_id)
    readback_resource = project.get("resource", resource_id)
    if readback_resource.get("operation_id") != readback_operation["id"] \
            or readback_resource.get("owner_actor_id") != actor["id"] \
            or canonical(readback_resource.get("external_id")) != canonical(resource.get("external_id")):
        raise EngineError(
            "v2_fixture_binding",
            "Readback operation/resource must preserve owner and external resource identity",
        )
    return operation_id, resource_id


def create(project, args):
    operation, actor, resource = _resource(project, args)
    readback_operation_id, readback_resource_id = _readback_binding(project, args, operation, actor, resource)
    prototype = {
        "operation_id": operation["id"], "owner_actor_id": actor["id"], "resource_id": resource["id"],
        "readback_operation_id": readback_operation_id, "readback_resource_id": readback_resource_id,
    }
    observed = _state_from_evidence(project, prototype, args["initial_evidence_id"], args["state_selector"])
    identity = {
        "operation": operation["id"], "owner": actor["id"], "resource": resource["id"],
        "initial": observed, "effect": "test_resource_write",
        "readback_operation": readback_operation_id, "readback_resource": readback_resource_id,
    }
    fixture_id = "FX-" + digest(identity)[:24]
    existing = Repository(project).get("fixture", fixture_id, required=False)
    if existing is not None:
        if canonical(existing.get("initial_state")) != canonical(observed) \
                or (existing.get("readback_operation_id") or existing["operation_id"]) != readback_operation_id \
                or (existing.get("readback_resource_id") or existing["resource_id"]) != readback_resource_id:
            raise EngineError("v2_fixture_identity", "A fixture identity cannot be rebound to different state or readback binding")
        return {"fixture": _view(existing), "requests_sent": 0, "idempotent": True}
    row = fixtures.create(
        project,
        operation_id=operation["id"],
        owner_actor_id=actor["id"],
        resource_id=resource["id"],
        initial_state=observed,
        cleanup_plan=args.get("cleanup_plan") or {},
        readback_operation_id=readback_operation_id,
        readback_resource_id=readback_resource_id,
    )
    try:
        row = fixtures.verify(project, row["id"], observed_state=observed)
    except Exception:
        current = fixtures._get(project, row["id"])
        if current.get("state") != "quarantined":
            current["state"] = "quarantined"
            current["unresolved"] = True
            fixtures._save(project, current, expected_revision=project.get_revision("v2_fixture", current["id"]))
        raise
    return {"fixture": _view(row), "requests_sent": 0}


def verify(project, args):
    row = fixtures._get(project, args["fixture_id"])
    observed = _state_from_evidence(project, row, args["evidence_id"], args["state_selector"])
    row = fixtures.verify(project, row["id"], observed_state=observed)
    return {"fixture": _view(row), "requests_sent": 0}


def lease(project, args):
    if not project.config.get("allow_mutation"):
        raise EngineError("v2_write_authorization", "A mutation lease requires project allow_mutation")
    row = fixtures.lease(
        project,
        args["fixture_id"],
        worker_id=args["worker_id"],
        ttl_seconds=args.get("ttl_seconds", 300),
    )
    return {"fixture": _view(row), "requests_sent": 0}


def inspect(project, args):
    row = fixtures._get(project, args["fixture_id"])
    return {"fixture": _view(row), "requests_sent": 0}


def _mutation_after(row):
    mutations = row.get("mutations") or []
    if mutations:
        return engine.stamp(mutations[-1]["at"])
    lease = row.get("lease") or {}
    if lease.get("claimed_at"):
        return engine.stamp(lease["claimed_at"])
    raise EngineError("v2_fixture_state", "Fixture has no mutation or lease transition to bind readback evidence")


def _expected_effect(row):
    effect = (row.get("current_state") or {}).get("intended_effect")
    if isinstance(effect, dict) and effect.get("kind") == "observed_http_control":
        return effect.get("actual")
    return effect if effect is not None else row.get("current_state")


def readback(project, args):
    # The snapshot, evidence freshness and state transition share one write
    # transaction, so a concurrent mutation cannot cross the validation window.
    with project.transaction():
        row = fixtures._get(project, args["fixture_id"])
        observed = _state_from_evidence(
            project, row, args["evidence_id"], args["state_selector"], after=_mutation_after(row))
        row = fixtures.readback(
            project,
            row["id"],
            observed_state=observed,
            expected_state=_expected_effect(row),
        )
    return {"fixture": _view(row), "requests_sent": 0}


def cleanup(project, args):
    # Freshness is re-evaluated against the same locked fixture snapshot used by
    # the transition; pre-mutation evidence can never clean a later mutation.
    with project.transaction():
        row = fixtures._get(project, args["fixture_id"])
        succeeded = args.get("succeeded")
        if type(succeeded) is not bool:
            raise EngineError("v2_fixture_cleanup", "cleanup succeeded must be a boolean")
        if succeeded:
            observed = _state_from_evidence(
                project, row, args["evidence_id"], args["state_selector"], after=_mutation_after(row))
            if canonical(observed) != canonical(row.get("initial_state")):
                raise EngineError("v2_fixture_cleanup_state", "Cleanup readback does not match the frozen initial state")
        row = fixtures.cleanup(
            project,
            row["id"],
            worker_id=args["worker_id"],
            succeeded=succeeded,
            observed_state=observed if succeeded else None,
            error=args.get("error"),
        )
    return {"fixture": _view(row), "requests_sent": 0}
