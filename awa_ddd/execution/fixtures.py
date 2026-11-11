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
           cleanup_plan, effect="test_resource_write"):
    repository = Repository(project)
    identity = {"operation": operation_id, "owner": owner_actor_id, "resource": resource_id,
                "initial": initial_state, "effect": effect}
    row = {
        "id": "FX-" + digest(identity)[:24],
        "schema": 2,
        "operation_id": text(operation_id, "operation_id", maximum=128),
        "owner_actor_id": text(owner_actor_id, "owner_actor_id", maximum=128),
        "resource_id": text(resource_id, "resource_id", maximum=128),
        "initial_state": initial_state,
        "current_state": initial_state,
        "cleanup_plan": cleanup_plan if isinstance(cleanup_plan, dict) else {},
        "effect": effect,
        "state": "created",
        "revision": 1,
        "lease": None,
        "mutations": [],
        "compensation": [],
        "unresolved": False,
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    return repository.add("fixture", row, immutable=False)


def _get(project, fixture_id):
    return Repository(project).get("fixture", fixture_id)


def _save(project, row):
    row["revision"] = int(row.get("revision", 1)) + 1
    row["updated_at"] = utc_now()
    return Repository(project).save("fixture", row)


def verify(project, fixture_id, *, observed_state):
    row = _get(project, fixture_id)
    if row["state"] not in {"created", "verified"}:
        fail("v2_fixture_state", "Fixture can only be verified before leasing")
    if canonical(observed_state) != canonical(row["initial_state"]):
        row["state"] = "quarantined"
        row["unresolved"] = True
        _save(project, row)
        fail("v2_fixture_initial_state", "Initial fixture state does not match the frozen baseline")
    row["state"] = "verified"
    return _save(project, row)


def lease(project, fixture_id, *, worker_id, ttl_seconds=300):
    row = _get(project, fixture_id)
    if row["state"] != "verified":
        fail("v2_fixture_state", "Fixture must be verified before leasing")
    current = row.get("lease")
    if current and current.get("expires_at"):
        try:
            if datetime.fromisoformat(current["expires_at"]) > datetime.now(timezone.utc) \
                    and current.get("worker_id") != worker_id:
                fail("v2_fixture_lease", "Fixture is exclusively leased by another worker")
        except (TypeError, ValueError):
            pass
    row["lease"] = {"worker_id": text(worker_id, "worker_id", maximum=128),
                    "expires_at": (datetime.now(timezone.utc) + timedelta(
                        seconds=integer(ttl_seconds, "ttl_seconds", minimum=1, maximum=86400))).isoformat()}
    row["state"] = "leased"
    return _save(project, row)


def mutate(project, fixture_id, *, worker_id, intended_effect):
    from ..assessment_mode import mode
    if mode(project) == "src":
        fail("src_write_denied", "SRC cannot mutate test fixtures")
    row = _get(project, fixture_id)
    if row["state"] != "leased" or (row.get("lease") or {}).get("worker_id") != worker_id:
        fail("v2_fixture_lease", "Mutation requires the active exclusive lease")
    row["mutations"].append({"intended_effect": intended_effect, "at": utc_now()})
    row["current_state"] = {"intended_effect": intended_effect}
    row["state"] = "mutated"
    return _save(project, row)


def readback(project, fixture_id, *, observed_state, expected_state):
    row = _get(project, fixture_id)
    if row["state"] not in {"mutated", "readback_ok"}:
        fail("v2_fixture_state", "Readback requires a mutated fixture")
    ok = canonical(observed_state) == canonical(expected_state)
    row["readback"] = {"observed": observed_state, "expected": expected_state, "ok": ok, "at": utc_now()}
    row["state"] = "readback_ok" if ok else "quarantined"
    if not ok:
        row["unresolved"] = True
    return _save(project, row)


def cleanup(project, fixture_id, *, worker_id, succeeded, observed_state=None, error=None):
    row = _get(project, fixture_id)
    if row["state"] in {"cleaned",}:
        return row
    entry = {"worker_id": worker_id, "succeeded": bool(succeeded),
             "observed_state": observed_state, "error": error, "at": utc_now()}
    row["compensation"].append(entry)
    if succeeded:
        row["state"] = "cleaned"
        row["lease"] = None
        row["unresolved"] = False
    else:
        row["state"] = "cleanup_failed"
        row["unresolved"] = True
        row["lease"] = None
    return _save(project, row)


def public_view(row):
    return {key: row.get(key) for key in (
        "id", "operation_id", "owner_actor_id", "resource_id", "state", "revision",
        "lease", "mutations", "readback", "compensation", "unresolved")}
