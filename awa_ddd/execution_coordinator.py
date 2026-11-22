"""Short durable execution claims, fencing, budget reservations and dispatch facts.

Remote effects cannot be committed atomically with SQLite. A dispatched lease is
never reclaimed merely because its time expired; trusted reconciliation is needed.
"""
from __future__ import annotations

import hashlib
import re
import time
from uuid import uuid4

from .store import EngineError, canonical, now


def _name(value):
    if not isinstance(value, str) or not value or len(value) > 512 or any(ord(char) < 32 for char in value):
        raise EngineError("execution_claim", "Execution claim requires a bounded name")
    return value


def _integer(value, label, minimum=0):
    if type(value) is not int or not minimum <= value <= 1000000000:
        raise EngineError("execution_budget", label + " must be a bounded nonnegative integer")
    return value


def claim(project, name, owner=None, ttl=300):
    name, owner = _name(name), _name(uuid4().hex if owner is None else owner)
    _integer(ttl, "lease ttl", 1)
    if ttl > 3600:
        raise EngineError("execution_lease", "Lease ttl cannot exceed 3600 seconds")
    current_time = time.time()
    with project.transaction():
        row = project.connection.execute("SELECT * FROM execution_leases WHERE name=?", (name,)).fetchone()
        previous = project.connection.execute(
            "SELECT COALESCE(MAX(json_extract(document,'$.fence')),0) FROM entities "
            "WHERE kind='execution_dispatch' AND json_extract(document,'$.lease_name')=?", (name,)).fetchone()[0]
        # Fences survive release, including claims that never dispatched. This
        # prevents an old token from becoming current after an ABA-style claim.
        project.connection.execute(
            "INSERT INTO execution_fences(name,fence) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET "
            "fence=MAX(execution_fences.fence,excluded.fence)",
            (name, max(previous, row["fence"] if row else 0)))
        if row:
            if row["owner"] == owner and row["expires_at"] > current_time:
                return dict(row)
            if row["dispatched"] or row["expires_at"] > current_time:
                raise EngineError("execution_lease_busy", "Execution is already claimed or its remote effect is unresolved",
                                  {"effect_unknown": bool(row["dispatched"]), "requests_replayed": 0})
        project.connection.execute("UPDATE execution_fences SET fence=fence+1 WHERE name=?", (name,))
        fence = project.connection.execute("SELECT fence FROM execution_fences WHERE name=?", (name,)).fetchone()[0]
        expires_at = current_time + ttl
        project.connection.execute("INSERT INTO execution_leases VALUES(?,?,?,?,0) ON CONFLICT(name) DO UPDATE SET "
            "owner=excluded.owner,fence=excluded.fence,expires_at=excluded.expires_at,dispatched=0",
            (name, owner, fence, expires_at))
    return {"name": name, "owner": owner, "fence": fence, "expires_at": expires_at, "dispatched": 0}


def _current(project, lease):
    if not isinstance(lease, dict) or not isinstance(lease.get("name"), str) \
            or not isinstance(lease.get("owner"), str) or type(lease.get("fence")) is not int:
        raise EngineError("execution_fence", "Execution requires an exact persisted lease token")
    row = project.connection.execute("SELECT * FROM execution_leases WHERE name=?", (lease["name"],)).fetchone()
    if row is None or row["owner"] != lease.get("owner") or row["fence"] != lease.get("fence"):
        raise EngineError("execution_fence", "Execution lease changed; dispatch is forbidden")
    if row["expires_at"] <= time.time():
        raise EngineError("execution_lease_expired", "Execution lease expired; inspect its dispatch before recovery")
    return row


def renew(project, lease, ttl=300):
    _integer(ttl, "lease ttl", 1)
    if ttl > 3600:
        raise EngineError("execution_lease", "Lease ttl cannot exceed 3600 seconds")
    with project.transaction():
        _current(project, lease)
        expires = time.time() + ttl
        project.connection.execute("UPDATE execution_leases SET expires_at=? WHERE name=?", (expires, lease["name"]))
    return {**lease, "expires_at": expires}


def reserve_budget(project, name, max_requests, max_writes, *, budget_unit="request"):
    name = _name(name)
    _integer(max_requests, "max_requests")
    _integer(max_writes, "max_writes")
    if not isinstance(budget_unit, str) or budget_unit not in {"request", "provider_invocation", "request_slots"}:
        raise EngineError("execution_budget", "Execution budget has an unknown counting unit")
    if max_writes > max_requests:
        raise EngineError("execution_budget", "Write budget cannot exceed total request budget")
    with project.transaction():
        row = project.connection.execute("SELECT * FROM execution_budget WHERE name=?", (name,)).fetchone()
        if row and (row["max_requests"] != max_requests or row["max_writes"] != max_writes or row["budget_unit"] != budget_unit):
            raise EngineError("execution_budget_changed", "A claimed experiment cannot change its authorization budget")
        if not row:
            project.connection.execute("INSERT INTO execution_budget(name,max_requests,max_writes,budget_unit) VALUES(?,?,?,?)",
                                       (name, max_requests, max_writes, budget_unit))
        return dict(project.connection.execute("SELECT * FROM execution_budget WHERE name=?", (name,)).fetchone())


def consume_budget(project, name, *, requests=1, writes=0):
    name = _name(name)
    _integer(requests, "requests")
    _integer(writes, "writes")
    if writes > requests:
        raise EngineError("execution_budget", "Writes must count toward total requests")
    with project.transaction():
        changed = project.connection.execute("UPDATE execution_budget SET requests_used=requests_used+?,writes_used=writes_used+? "
            "WHERE name=? AND requests_used+?<=max_requests AND writes_used+?<=max_writes",
            (requests, writes, name, requests, writes)).rowcount
        if changed != 1:
            raise EngineError("execution_budget_exhausted", "Experiment request or write budget is exhausted; no dispatch occurred")
        return dict(project.connection.execute("SELECT * FROM execution_budget WHERE name=?", (name,)).fetchone())


def dispatch(project, lease, *, action, run_id, request_hash, budget=None, max_requests=1, max_writes=0,
             effect="read_only", requests=1, writes=None, emit_ipc=True, budget_unit="request"):
    _name(action)
    _name(run_id)
    _integer(requests, "requests", 1)
    if type(emit_ipc) is not bool:
        raise EngineError("execution_dispatch", "IPC emission must be a boolean")
    if not isinstance(budget_unit, str) or budget_unit not in {"request", "provider_invocation", "request_slots"}:
        raise EngineError("execution_budget", "Execution must state the unit its budget actually enforces")
    if not isinstance(effect, str) or effect not in {"read_only", "test_resource_write", "cleanup_write"}:
        raise EngineError("execution_effect", "Dispatch effect requires an explicit reviewed classification")
    if not isinstance(request_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", request_hash):
        raise EngineError("execution_dispatch_hash", "Dispatch requires a SHA-256 request specification digest")
    writes = requests if effect != "read_only" and writes is None else 0 if writes is None else writes
    _integer(writes, "writes")
    if effect == "read_only" and writes:
        raise EngineError("execution_effect", "Read-only dispatch cannot reserve or submit writes")
    if effect != "read_only" and writes < requests:
        raise EngineError("execution_effect", "Every declared write request must consume write budget")
    budget_name = _name(budget or "run:" + run_id)
    if not isinstance(lease, dict) or "name" not in lease or "fence" not in lease:
        raise EngineError("execution_fence", "Dispatch requires an exact current lease")
    identity = "DSP-" + hashlib.sha256(canonical([lease["name"], lease["fence"], action, run_id, request_hash]).encode("utf-8")).hexdigest()
    with project.transaction():
        _current(project, lease)
        if project.get("execution_dispatch", identity, required=False):
            raise EngineError("dispatch_already_attempted", "This request was already dispatched; automatic replay is forbidden",
                              {"run_id": run_id, "requests_replayed": 0, "effect_unknown": True})
        reserve_budget(project, budget_name, max_requests, max_writes, budget_unit=budget_unit)
        remaining = consume_budget(project, budget_name, requests=requests, writes=writes)
        receipt = {"id": identity, "run_id": run_id, "action": action, "lease_name": lease["name"],
                   "fence": lease["fence"], "request_hash": request_hash, "effect": effect, "requests": requests,
                   "writes": writes, "budget_name": budget_name, "budget_unit": budget_unit,
                   "created_at": now(), "dispatch_attempted": True,
                   "requests_remaining": remaining["max_requests"] - remaining["requests_used"],
                   "writes_remaining": remaining["max_writes"] - remaining["writes_used"]}
        project.put("execution_dispatch", receipt, create_only=True)
        project.connection.execute("UPDATE execution_leases SET dispatched=1 WHERE name=?", (lease["name"],))
        project.event("execution.dispatch_attempted", {"dispatch_id": identity, "run_id": run_id, "effect": effect})
    if emit_ipc:
        from .ipc import emit_dispatch
        emit_dispatch(action, run_id, request_hash)
    return receipt


def release(project, lease, *, reconciled=False):
    if type(reconciled) is not bool:
        raise EngineError("execution_effect_unknown", "Trusted terminal release is an internal boolean contract")
    with project.transaction():
        row = project.connection.execute("SELECT * FROM execution_leases WHERE name=?", (lease["name"],)).fetchone()
        if row is None:
            return False
        if row["owner"] != lease.get("owner") or row["fence"] != lease.get("fence"):
            raise EngineError("execution_fence", "Only the current lease owner can release an execution")
        if row["dispatched"] and not reconciled:
            raise EngineError("execution_effect_unknown", "Dispatched execution needs trusted readback or a terminal provider receipt")
        project.connection.execute("DELETE FROM execution_leases WHERE name=?", (lease["name"],))
    return True


def reconcile(project, args):
    """Validate retained terminal/readback material, never repeat a request.

    Caller flags cannot clear unknown effects. Writable runs need a later,
    same-identity business-state readback for every captured fixture. Legacy
    browser writes without an exact fixture binding stay blocked.
    """
    from . import engine
    from .continuation import _readback_bindings, _write_contexts

    facts_generation, config_before = project.generation(), canonical(project.config)
    run_id = _name(args.get("run_id"))
    run = project.get("run", run_id, required=False)
    kind = "run"
    if run is None:
        run, kind = project.get("v2_run", run_id), "v2_run"
    with project._lock:
        entries = project.connection.execute(
            "SELECT document FROM entities WHERE kind='execution_dispatch' AND "
            "json_extract(document,'$.run_id')=? ORDER BY created_at,id", (run_id,)).fetchall()
    import json
    dispatches = [json.loads(row[0]) for row in entries]
    if not dispatches:
        raise EngineError("reconciliation_context", "Run has no durable dispatch facts to reconcile")
    ids = args.get("evidence_ids", [])
    if not isinstance(ids, list) or not 1 <= len(ids) <= 25 \
            or any(not isinstance(identity, str) or not identity or len(identity) > 200 for identity in ids) \
            or len(set(ids)) != len(ids):
        raise EngineError("reconciliation_evidence", "Supply distinct current terminal or fixture-readback evidence IDs")
    support = [engine.verify_current_evidence(project, identity) for identity in ids]
    writes = any(row.get("writes", 0) for row in dispatches)
    for dispatch_row in dispatches:
        active = project.connection.execute(
            "SELECT expires_at FROM execution_leases WHERE name=? AND fence=?",
            (dispatch_row["lease_name"], dispatch_row["fence"])).fetchone()
        if active and active[0] > time.time():
            raise EngineError("run_active", "A live worker still owns this run; wait for its terminal checkpoint")
    if kind == "v2_run":
        recipe = project.get("v2_recipe", run.get("recipe_id"))
        if recipe.get("campaign_id") != run.get("campaign_id") or recipe.get("universe_id") != run.get("universe_id"):
            raise EngineError("reconciliation_context", "The interrupted run and frozen recipe must belong to the same campaign and universe")
        bindings = recipe.get("bindings") or {}
        operation = project.get("operation", bindings.get("operation_id"))
        resource = project.get("resource", (bindings.get("resource") or {}).get("resource_id"), required=False)
        session = bindings.get("session") or {}
        context = {**run, "operation_id": operation["id"], "method": operation["method"],
                   "effect": "test_resource_write" if writes else "read_only",
                   "resource_id": resource["id"] if resource else None,
                   "resource_signature": engine.resource_signature(resource) if resource else None,
                   "actor_id": session.get("actor_id")}
        if bindings.get("operation_signature") != engine.operation_signature(operation):
            raise EngineError("reconciliation_context", "The recipe's operation binding changed")
        if resource and (bindings.get("resource") or {}).get("revision", 1) != resource.get("revision", 1):
            raise EngineError("reconciliation_context", "The recipe's captured fixture revision changed")
    else:
        context = run
    if writes:
        if kind == "v2_run":
            children = [json.loads(row[0]) for row in project.connection.execute(
                "SELECT document FROM entities WHERE kind='run' AND json_extract(document,'$.dispatch_run_id')=?",
                (run_id,)).fetchall()]
            contexts = []
            for dispatch_row in dispatches:
                if not dispatch_row.get("writes", 0):
                    continue
                matches = [child for child in children if child.get("dispatch_id") == dispatch_row["id"]]
                if len(matches) != 1 or dispatch_row.get("action") != "http.capture" \
                        or dispatch_row.get("requests") != 1 or dispatch_row.get("budget_unit", "request") != "request":
                    raise EngineError("reconciliation_context", "Every interrupted write requires its actual native fixture dispatch context")
                child = matches[0]
                expected_hash = hashlib.sha256(canonical([child.get("request_signature"),
                    child.get("operation_signature"), child.get("session_generation"),
                    child.get("resource_signature")]).encode("utf-8")).hexdigest()
                if dispatch_row.get("request_hash") != expected_hash or child.get("operation_id") != operation["id"] \
                        or child.get("operation_signature") != bindings.get("operation_signature") \
                        or child.get("resource_id") != (bindings.get("resource") or {}).get("resource_id") \
                        or child.get("session_id") != session.get("session_id") \
                        or child.get("session_generation") != session.get("generation") \
                        or child.get("actor_id") != session.get("actor_id"):
                    raise EngineError("reconciliation_context", "The native dispatch differs from the frozen recipe context")
                contexts.extend(_write_contexts(project, "unreconciled_run", child))
        else:
            contexts = _write_contexts(project, "unreconciled_run", context)
        if not contexts:
            raise EngineError("reconciliation_context", "The dispatched write has no exact captured fixture binding")
        readbacks = _readback_bindings(project, context, contexts, support, args.get("readback_bindings"))
    else:
        readbacks = []
        # An unrelated later GET cannot establish that a failed read-only
        # dispatch completed. Require its exact durable response relation.
        covered = set()
        for meta, artifact in support:
            native = project.get("run", meta.get("run_id"), required=False) or {}
            if not artifact.get("complete") or not (meta.get("run_id") == run_id
                    or kind == "v2_run" and native.get("dispatch_run_id") == run_id):
                continue
            expected_hash = hashlib.sha256(canonical([native.get("request_signature"),
                meta.get("operation_signature"), meta.get("session_generation"),
                meta.get("resource_signature")]).encode("utf-8")).hexdigest()
            for dispatch_row in dispatches:
                if native.get("dispatch_id") == dispatch_row["id"] \
                        and dispatch_row.get("action") == "http.capture" and dispatch_row.get("requests") == 1 \
                        and dispatch_row.get("request_hash") == expected_hash \
                        and dispatch_row.get("budget_unit", "request") == "request":
                    covered.add(dispatch_row["id"])
        if covered != {row["id"] for row in dispatches}:
            raise EngineError("reconciliation_evidence", "Read-only recovery requires an actual complete response from this dispatch")
    previous = project.get("execution_reconciliation", run.get("reconciliation_id"), required=False)
    if previous is not None:
        sealed = {key: value for key, value in previous.items() if key not in {"id", "created_at"}}
        if previous.get("id") == "REC-" + hashlib.sha256(canonical(sealed).encode("utf-8")).hexdigest() \
                and previous.get("run_id") == run_id and previous.get("run_kind") == kind \
                and run.get("effect_unknown") is False and run.get("remote_state_unknown") is False \
                and run.get("status") != "effect_unknown" \
                and previous.get("dispatch_ids") == [row["id"] for row in dispatches] \
                and previous.get("evidence_ids") == ids and previous.get("readback_bindings") == readbacks \
                and previous.get("evidence_sha256") == {meta["id"]: meta["sha256"] for meta, _ in support}:
            return {"run_id": run_id, "reconciliation_id": previous["id"], "dispatch_ids": previous["dispatch_ids"],
                    "evidence_ids": ids, "lease_released": False, "effect_unknown": False,
                    "requests_replayed": 0, "requests_sent": 0, "next_action": "run.inspect"}
    facts = {"schema": "awa-reconciliation/v1", "run_id": run_id, "run_kind": kind,
             "run_sha256": hashlib.sha256(canonical(run).encode("utf-8")).hexdigest(),
             "dispatch_ids": [row["id"] for row in dispatches], "evidence_ids": ids,
             "evidence_sha256": {meta["id"]: meta["sha256"] for meta, _ in support},
             "readback_bindings": readbacks, "effect_unknown": False, "requests_replayed": 0}
    identity = "REC-" + hashlib.sha256(canonical(facts).encode("utf-8")).hexdigest()
    receipt = {"id": identity, **facts, "created_at": now()}
    released = False
    with project.transaction():
        if facts_generation != project.generation() or config_before != canonical(project.config):
            raise EngineError("revision_conflict", "Project context changed during readback validation; inspect it again")
        if project.get_revision(kind, run_id) < 1 or project.get(kind, run_id) != run:
            raise EngineError("revision_conflict", "Run changed during readback validation; inspect it again")
        if not project.get("execution_reconciliation", identity, required=False):
            project.put("execution_reconciliation", receipt, create_only=True)
        for name, fence in sorted({(row["lease_name"], row["fence"]) for row in dispatches}):
            current = project.connection.execute("SELECT * FROM execution_leases WHERE name=?", (name,)).fetchone()
            if current:
                if current["fence"] != fence:
                    raise EngineError("execution_fence", "A newer lease owns this execution; an old readback cannot release it")
                if current["expires_at"] > time.time():
                    raise EngineError("run_active", "The worker renewed its lease during readback validation")
                released = release(project, dict(current), reconciled=True) or released
        changed = {**run, "effect_unknown": False, "remote_state_unknown": False,
                   "reconciliation_id": identity, "reconciled_at": now(), "next_action": "run.inspect"}
        if run.get("status") == "effect_unknown":
            changed["status"] = "interrupted"
        if isinstance(run.get("effect"), dict):
            changed["effect"] = {**run["effect"], "unknown": False, "reconciled": True}
        project.compare_and_swap(kind, changed, project.get_revision(kind, run_id))
        project.event("execution.reconciled", {"run_id": run_id, "reconciliation_id": identity,
                                               "requests_replayed": 0})
    return {"run_id": run_id, "reconciliation_id": identity, "dispatch_ids": facts["dispatch_ids"],
            "evidence_ids": ids, "lease_released": released, "effect_unknown": False,
            "requests_replayed": 0, "requests_sent": 0, "next_action": "run.inspect"}
