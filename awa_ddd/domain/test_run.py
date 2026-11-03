"""TestRun: durable execution facts, separate from evaluation and publication."""
from __future__ import annotations

from .common import digest, enum, integer, mapping, optional_text, sequence, stable_id, text, utc_now

STATES = ("prepared", "claimed", "dispatch_started", "response_saved", "effect_unknown",
          "evaluation_pending", "evaluated", "published", "failed", "cancelled", "interrupted")
TERMINAL = {"evaluated", "published", "failed", "cancelled", "interrupted"}
TRANSITIONS = {
    "prepared": {"claimed", "cancelled", "failed"},
    "claimed": {"dispatch_started", "cancelled", "failed", "prepared"},
    "dispatch_started": {"response_saved", "effect_unknown", "failed", "interrupted"},
    "response_saved": {"evaluation_pending", "failed"},
    "effect_unknown": {"evaluation_pending", "failed"},
    "evaluation_pending": {"evaluated", "failed"},
    "evaluated": {"published"},
    "published": set(),
    "failed": {"evaluation_pending"},
    "cancelled": set(),
    "interrupted": {"evaluation_pending"},
}


def new_run(*, recipe, campaign_id, idempotency_key, actor_id=None, mode="test"):
    enum(mode, "run_mode", {"observe", "test", "verify"})
    text(idempotency_key, "idempotency_key", maximum=256)
    identity = {"recipe": recipe["id"], "spec": recipe["spec_hash"], "campaign": campaign_id,
                "idempotency_key": idempotency_key, "mode": mode}
    return {
        "id": stable_id("RUN2", identity),
        "schema": 2,
        "campaign_id": campaign_id,
        "hypothesis_id": recipe["hypothesis_id"],
        "recipe_id": recipe["id"],
        "recipe_revision": recipe.get("revision"),
        "recipe_spec_hash": recipe.get("spec_hash"),
        "mode": mode,
        "actor_id": optional_text(actor_id, "actor_id", maximum=128),
        "idempotency_key": idempotency_key,
        "idempotency_scope": digest(identity),
        "status": "prepared",
        "status_history": [{"status": "prepared", "at": utc_now(), "note": "run record created"}],
        "steps": [],
        "evidence_ids": [],
        "decision_ids": [],
        "evaluation": None,
        "outcome": None,
        "error": None,
        "effect": {"kind": recipe.get("limits", {}).get("effect", "read_only"),
                   "unknown": False, "reconciled": False},
        "lease": None,
        "dispatch_started_at": None,
        "completed_at": None,
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }


def transition(run, status, *, note=None, **fields):
    enum(status, "run_status", set(STATES))
    current = run.get("status")
    if status != current and status not in TRANSITIONS.get(current, set()):
        from .common import fail
        fail("v2_run_transition", f"Run cannot move from {current} to {status}")
    run["status"] = status
    run["updated_at"] = utc_now()
    run.setdefault("status_history", []).append({"status": status, "at": utc_now(),
                                                 "note": optional_text(note, "note", maximum=1024)})
    for key, value in fields.items():
        if key in {"status", "id"}:
            continue
        run[key] = value
    if status in TERMINAL:
        run["completed_at"] = utc_now()
    return run


def claim(run, worker_id, *, ttl_seconds=300):
    from .common import fail
    if run.get("status") != "prepared":
        fail("v2_run_claim", "Only a prepared run can be claimed")
    text(worker_id, "worker_id", maximum=128)
    integer(ttl_seconds, "ttl_seconds", minimum=1, maximum=86400)
    run["lease"] = {"worker_id": worker_id, "expires_at": _expiry(ttl_seconds), "claimed_at": utc_now()}
    return transition(run, "claimed", note="worker claimed the run")


def _expiry(seconds):
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def add_step(run, *, step_id, action, request_digest=None, response_digest=None,
             status="completed", error_code=None):
    row = {"step_id": text(step_id, "step_id", maximum=64), "action": text(action, "step_action", maximum=64),
           "request_digest": request_digest, "response_digest": response_digest,
           "status": enum(status, "step_status", {"prepared", "dispatch_started", "completed", "failed", "skipped"}),
           "error_code": optional_text(error_code, "error_code", maximum=128),
           "at": utc_now()}
    run.setdefault("steps", []).append(row)
    run["updated_at"] = utc_now()
    return row


def mark_effect_unknown(run, *, reason, dispatch_started=True):
    """A write whose dispatch began but whose response cannot be trusted is never replayed."""
    if not dispatch_started:
        return run
    run["effect"]["unknown"] = True
    run["error"] = {"code": "effect_unknown", "message": text(reason, "reason", maximum=1024)}
    return transition(run, "effect_unknown", note="dispatch began; target effect requires read-only reconciliation")


def public_view(run):
    evaluation = run.get("evaluation")
    if isinstance(evaluation, dict):
        evaluation = {key: evaluation.get(key) for key in
                      ("outcome", "finding_allowed", "proof_scope", "oracle_type", "limitations", "missing")}
    return {
        key: run.get(key) for key in (
            "id", "campaign_id", "hypothesis_id", "recipe_id", "recipe_revision", "recipe_spec_hash",
            "mode", "status", "steps", "evidence_ids", "decision_ids", "error",
            "effect", "dispatch_started_at", "completed_at", "created_at", "updated_at")
    } | {"evaluation": evaluation, "outcome": run.get("outcome")}
