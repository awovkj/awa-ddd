"""Fixture lifecycle and leases: create → verify → lease → mutate → readback → cleanup.

A database transaction cannot roll back a refund, approval or SMS.  A failed
cleanup therefore remains an explicit unresolved effect and is never treated
as a clean state.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..domain.common import digest, fail, integer, text, utc_now
from ..domain.repository import Repository
from ..store import canonical

STATES = {"created", "verified", "leased", "mutated", "readback_ok", "cleanup_pending",
          "cleaned", "cleanup_failed", "quarantined"}


def create(project, *, operation_id, owner_actor_id, resource_id, initial_state,
           cleanup_plan, effect="test_resource_write", readback_operation_id=None, readback_resource_id=None):
    repository = Repository(project)
    readback_operation_id = readback_operation_id or operation_id
    readback_resource_id = readback_resource_id or resource_id
    identity = {"operation": operation_id, "owner": owner_actor_id, "resource": resource_id,
                "initial": initial_state, "effect": effect,
                "readback_operation": readback_operation_id, "readback_resource": readback_resource_id}
    row = {
        "id": "FX-" + digest(identity)[:24],
        "schema": 2,
        "operation_id": text(operation_id, "operation_id", maximum=128),
        "owner_actor_id": text(owner_actor_id, "owner_actor_id", maximum=128),
        "resource_id": text(resource_id, "resource_id", maximum=128),
        "readback_operation_id": text(readback_operation_id, "readback_operation_id", maximum=128),
        "readback_resource_id": text(readback_resource_id, "readback_resource_id", maximum=128),
        "initial_state": initial_state,
        "current_state": initial_state,
        "cleanup_plan": cleanup_plan if isinstance(cleanup_plan, dict) else {},
        "effect": effect,
        "state": "created",
        "revision": 1,
        "fence": 0,
        "lease": None,
        "in_flight": None,
        "mutations": [],
        "compensation": [],
        "unresolved": False,
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    return repository.add("fixture", row, immutable=False)


def _get(project, fixture_id):
    return Repository(project).get("fixture", fixture_id)


def _save(project, row, *, expected_revision):
    """Persist one lifecycle transition with a storage-level compare-and-swap."""
    row["revision"] = int(row.get("revision", 1)) + 1
    row["updated_at"] = utc_now()
    return Repository(project).save(
        "fixture", row, expected_revision=expected_revision)


def _validate_binding(project, row):
    """A lease is valid only for the exact persisted operation/owner/resource."""
    operation = project.get("operation", row.get("operation_id"), required=False)
    resource = project.get("resource", row.get("resource_id"), required=False)
    owner = project.get("actor", row.get("owner_actor_id"), required=False)
    if operation is None or resource is None or owner is None \
            or resource.get("operation_id") != row.get("operation_id") \
            or resource.get("owner_actor_id") != row.get("owner_actor_id"):
        fail("v2_fixture_binding",
             "Fixture operation, owner and resource bindings are missing or inconsistent",
             fixture_id=row.get("id"))
    readback_operation_id = row.get("readback_operation_id") or row.get("operation_id")
    readback_resource_id = row.get("readback_resource_id") or row.get("resource_id")
    readback_operation = project.get("operation", readback_operation_id, required=False)
    readback_resource = project.get("resource", readback_resource_id, required=False)
    if readback_operation is None or readback_resource is None \
            or readback_resource.get("operation_id") != readback_operation_id \
            or readback_resource.get("owner_actor_id") != row.get("owner_actor_id") \
            or canonical(readback_resource.get("external_id")) != canonical(resource.get("external_id")):
        fail("v2_fixture_binding",
             "Fixture readback must bind the same owner and external resource identity",
             fixture_id=row.get("id"))
    return operation, resource, owner


def _expiry(lease):
    try:
        value = datetime.fromisoformat(lease.get("expires_at"))
        if value.tzinfo is None:
            raise ValueError()
        return value
    except (AttributeError, TypeError, ValueError):
        fail("v2_fixture_lease", "Fixture lease has no valid timezone-aware TTL")


def _active_lease(row, *, worker_id=None, now=None):
    lease = row.get("lease")
    if not isinstance(lease, dict) or type(lease.get("fence")) is not int \
            or lease.get("fence") < 1 or row.get("fence") != lease.get("fence"):
        fail("v2_fixture_lease", "Fixture lease has no current persisted fence")
    if worker_id is not None and lease.get("worker_id") != worker_id:
        fail("v2_fixture_lease", "Fixture is exclusively leased by another worker")
    if _expiry(lease) <= (now or datetime.now(timezone.utc)):
        fail("v2_fixture_lease", "Fixture lease expired; reconcile its state before a new transition")
    return lease


def verify(project, fixture_id, *, observed_state):
    row = _get(project, fixture_id)
    expected_revision = project.get_revision("v2_fixture", fixture_id)
    if row["state"] not in {"created", "verified"}:
        fail("v2_fixture_state", "Fixture can only be verified before leasing")
    if canonical(observed_state) != canonical(row["initial_state"]):
        row["state"] = "quarantined"
        row["unresolved"] = True
        _save(project, row, expected_revision=expected_revision)
        fail("v2_fixture_initial_state", "Initial fixture state does not match the frozen baseline")
    row["state"] = "verified"
    return _save(project, row, expected_revision=expected_revision)


def lease(project, fixture_id, *, worker_id, ttl_seconds=300):
    worker_id = text(worker_id, "worker_id", maximum=128)
    ttl_seconds = integer(ttl_seconds, "ttl_seconds", minimum=1, maximum=86400)
    now = datetime.now(timezone.utc)
    # BEGIN IMMEDIATE serializes this read/check/CAS across independent SQLite
    # connections and processes; no in-process lock is relied upon.
    with project.transaction():
        row = _get(project, fixture_id)
        expected_revision = project.get_revision("v2_fixture", fixture_id)
        _validate_binding(project, row)
        current = row.get("lease")
        if current is not None and _expiry(current) > now:
            _active_lease(row, now=now)
            if current.get("worker_id") != worker_id:
                fail("v2_fixture_lease", "Fixture is exclusively leased by another worker")
            # Renewing the same owner's live lease keeps its fence stable so an
            # in-flight mutate/readback cannot be invalidated by a mere renewal.
            row["lease"] = {**current, "expires_at": (
                now + timedelta(seconds=ttl_seconds)).isoformat()}
            return _save(project, row, expected_revision=expected_revision)
        if row["state"] not in {"verified", "leased"}:
            fail("v2_fixture_state", "Fixture must be verified or safely leased before leasing")
        previous_fence = row.get("fence", 0)
        if type(previous_fence) is not int or previous_fence < 0:
            fail("v2_fixture_lease", "Fixture fence is legacy or invalid")
        fence = previous_fence + 1
        row["fence"] = fence
        row["lease"] = {
            "worker_id": worker_id,
            "fence": fence,
            "claimed_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
        }
        row["state"] = "leased"
        return _save(project, row, expected_revision=expected_revision)


def begin_execution(project, fixture_id, *, worker_id, run_id):
    """Reserve the fixture before a dispatched write can touch the target.

    The marker survives cancellation and unknown outcomes. Readback and cleanup
    therefore cannot certify a resource while its write is still in flight.
    """
    run_id = text(run_id, "run_id", maximum=128)
    with project.transaction():
        row = _get(project, fixture_id)
        expected_revision = project.get_revision("v2_fixture", fixture_id)
        _validate_binding(project, row)
        lease_row = _active_lease(row, worker_id=worker_id)
        if row["state"] != "leased" or row.get("in_flight") is not None:
            fail("v2_fixture_state", "Fixture already has an in-flight or completed execution")
        row["in_flight"] = {
            "run_id": run_id, "worker_id": worker_id, "fence": lease_row["fence"],
            "started_at": utc_now(),
        }
        return _save(project, row, expected_revision=expected_revision)


def mutate(project, fixture_id, *, worker_id, intended_effect, run_id=None):
    from ..assessment_mode import mode
    if mode(project) == "src":
        fail("src_write_denied", "SRC cannot mutate test fixtures")
    with project.transaction():
        row = _get(project, fixture_id)
        expected_revision = project.get_revision("v2_fixture", fixture_id)
        _validate_binding(project, row)
        lease_row = _active_lease(row, worker_id=worker_id)
        if row["state"] != "leased":
            fail("v2_fixture_state", "Mutation requires a leased fixture without a later state transition")
        in_flight = row.get("in_flight")
        if run_id is not None:
            if not isinstance(in_flight, dict) or in_flight.get("run_id") != run_id \
                    or in_flight.get("worker_id") != worker_id \
                    or in_flight.get("fence") != lease_row["fence"]:
                fail("v2_fixture_state", "Mutation does not own the current fixture execution")
        elif in_flight is not None:
            fail("v2_fixture_state", "An in-flight fixture execution must complete before another mutation")
        row["mutations"].append({
            "intended_effect": intended_effect,
            "fence": lease_row["fence"],
            **({"run_id": run_id} if run_id is not None else {}),
            "at": utc_now(),
        })
        row["current_state"] = {"intended_effect": intended_effect}
        row["in_flight"] = None
        row["state"] = "mutated"
        return _save(project, row, expected_revision=expected_revision)


def readback(project, fixture_id, *, observed_state, expected_state):
    with project.transaction():
        row = _get(project, fixture_id)
        expected_revision = project.get_revision("v2_fixture", fixture_id)
        _validate_binding(project, row)
        lease_row = _active_lease(row)
        if row.get("in_flight") is not None:
            fail("v2_fixture_state", "Readback cannot close an in-flight fixture execution")
        if row["state"] not in {"mutated", "readback_ok"}:
            fail("v2_fixture_state", "Readback requires a mutated fixture")
        ok = canonical(observed_state) == canonical(expected_state)
        row["readback"] = {
            "observed": observed_state,
            "expected": expected_state,
            "ok": ok,
            "fence": lease_row["fence"],
            "at": utc_now(),
        }
        row["state"] = "readback_ok" if ok else "quarantined"
        if not ok:
            row["unresolved"] = True
        return _save(project, row, expected_revision=expected_revision)


def cleanup(project, fixture_id, *, worker_id, succeeded, observed_state=None, error=None):
    with project.transaction():
        row = _get(project, fixture_id)
        if row["state"] == "cleaned":
            previous = (row.get("compensation") or [{}])[-1]
            if previous.get("worker_id") != worker_id:
                fail("v2_fixture_lease", "Only the cleanup owner can replay its terminal cleanup fact")
            return row
        expected_revision = project.get_revision("v2_fixture", fixture_id)
        _validate_binding(project, row)
        lease_row = _active_lease(row, worker_id=worker_id)
        if row.get("in_flight") is not None:
            fail("v2_fixture_state", "Cleanup cannot close a fixture while its write is in flight or unknown")
        if row["state"] not in {"leased", "mutated", "readback_ok", "cleanup_pending"}:
            fail("v2_fixture_state", "Cleanup requires an active leased fixture")
        entry = {"worker_id": worker_id, "fence": lease_row["fence"],
                 "succeeded": bool(succeeded), "observed_state": observed_state,
                 "error": error, "at": utc_now()}
        row["compensation"].append(entry)
        if succeeded:
            row["state"] = "cleaned"
            row["lease"] = None
            row["unresolved"] = False
        else:
            row["state"] = "cleanup_failed"
            row["unresolved"] = True
            row["lease"] = None
        return _save(project, row, expected_revision=expected_revision)


def public_view(row):
    return {key: row.get(key) for key in (
        "id", "operation_id", "owner_actor_id", "resource_id", "state", "revision",
        "lease", "mutations", "readback", "compensation", "unresolved")}
