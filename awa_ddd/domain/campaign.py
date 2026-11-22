"""Campaign: a persistent, bounded assessment objective (never a chat turn)."""
from __future__ import annotations

from .common import boolean, digest, enum, integer, mapping, optional_text, stable_id, text, utc_now

CAMPAIGN_STATES = {"active", "paused", "delivered_partial", "completed", "abandoned"}
DELIVERY_REASONS = {"partial_accepted", "completed"}
MODEL_VERSIONS = {"v1", "v2"}


def new_campaign(project_id, *, target, objective, model="v2", scope_snapshot=None,
                 exclude_snapshot=None, max_rounds=40, allow_mutation=False):
    target = text(target, "target", maximum=2048)
    objective = text(objective, "objective")
    if model not in MODEL_VERSIONS:
        enum(model, "model", MODEL_VERSIONS)
    rounds = integer(max_rounds, "max_rounds", minimum=1, maximum=10000)
    scope = scope_snapshot if isinstance(scope_snapshot, list) else []
    exclude = exclude_snapshot if isinstance(exclude_snapshot, list) else []
    identity = {"project_id": project_id, "target": target, "objective": objective,
                "model": model, "scope": scope, "exclude": exclude, "created": utc_now()}
    campaign_id = stable_id("CAM", identity)
    return {
        "id": campaign_id,
        "project_id": project_id,
        "target": target,
        "objective": objective,
        "model": model,
        "mode": model,
        "scope_snapshot": list(scope),
        "exclude_snapshot": list(exclude),
        "scope_epoch": digest(scope + ["--exclude--"] + exclude),
        "max_rounds": rounds,
        "rounds": 0,
        "state": "active",
        "state_reason": None,
        "allow_mutation": boolean(allow_mutation, "allow_mutation"),
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "delivery": None,
        "user_stop": False,
        "notification_watermark": {"progress_id": None, "recipe_hashes": [], "stall_budget": 3},
        "cursor": {"family_index": 0, "operation_index": 0, "offset": 0},
        "version": 1,
    }


def transition(campaign, state, *, reason=None):
    enum(state, "campaign_state", CAMPAIGN_STATES)
    if campaign.get("state") in {"completed", "abandoned"} and state != campaign["state"]:
        from .common import fail
        fail("v2_campaign_frozen", "Completed or abandoned campaign cannot change state")
    campaign["state"] = state
    campaign["state_reason"] = optional_text(reason, "state_reason")
    campaign["updated_at"] = utc_now()
    campaign["version"] = int(campaign.get("version", 1)) + 1
    return campaign


def deliver(campaign, *, reason, accepted_by=None, explanation=None,
            checkpoint_id=None, completion_decision=None, acceptance_id=None):
    """Record a delivery decision. Only ``completed`` grants exhaustion authority."""
    enum(reason, "delivery_reason", DELIVERY_REASONS)
    if campaign.get("state") != "active" or campaign.get("delivery") is not None:
        from .common import fail
        fail("v2_campaign_frozen",
             "A campaign delivery is immutable and can be recorded only once")
    state = "completed" if reason == "completed" else "delivered_partial"
    if reason == "partial_accepted":
        text(accepted_by, "accepted_by")
    text(explanation, "explanation")
    campaign["delivery"] = {
        "reason": reason,
        "accepted_by": optional_text(accepted_by, "accepted_by"),
        "explanation": optional_text(explanation, "explanation"),
        "delivered_at": utc_now(),
        "exhausted_authority": reason == "completed",
        "checkpoint_id": optional_text(
            checkpoint_id, "checkpoint_id", maximum=128),
        "completion_decision_id": optional_text(
            (completion_decision or {}).get("id"),
            "completion_decision_id",
            maximum=128,
        ),
        "acceptance_id": optional_text(
            acceptance_id, "acceptance_id", maximum=128),
    }
    campaign["state"] = state
    campaign["updated_at"] = utc_now()
    campaign["version"] = int(campaign.get("version", 1)) + 1
    return campaign


def delivery_acceptance(campaign, *, reason, accepted_by=None, explanation=None,
                        checkpoint_id=None, completion_decision=None,
                        remaining=None):
    """Freeze the public delivery facts and the exact shared decision."""
    enum(reason, "delivery_reason", DELIVERY_REASONS)
    decision = mapping(completion_decision, "completion_decision")
    completed = reason == "completed"
    body = {
        "schema": "awa-completion-acceptance/v1",
        "campaign_id": campaign.get("id"),
        "state": "completed" if completed else "delivered_partial",
        "reason": reason,
        "accepted_by": optional_text(
            accepted_by, "accepted_by"),
        "explanation": optional_text(explanation, "explanation"),
        "checkpoint_id": optional_text(
            checkpoint_id, "checkpoint_id", maximum=128),
        "completion_decision_id": optional_text(
            decision.get("id"), "completion_decision_id", maximum=128),
        "completion_decision": dict(decision),
        "remaining": list(remaining or []),
        "exhausted_authority": bool(
            completed and decision.get("can_claim_complete") is True),
        "automatic_stop_allowed": bool(
            completed and decision.get("can_claim_complete") is True),
        "created_at": utc_now(),
    }
    body["id"] = stable_id("CDA", body)
    return body


def public_view(campaign):
    return mapping(campaign, "campaign") and {
        key: campaign.get(key) for key in (
            "id", "project_id", "target", "objective", "model", "mode", "scope_epoch", "max_rounds",
            "rounds", "state", "state_reason", "allow_mutation", "created_at", "updated_at",
            "delivery", "user_stop", "cursor")
    }
