"""Bounded anti-repeat guards for queues and preflight.

The engine intentionally keeps a complete evidence ledger.  That completeness
must not turn into an infinite preparation loop: the same page or the same
preflight must not be consumed repeatedly without a state/evidence change.
This module stores only small JSON counters in private project-local sidecar
files and never sends requests or changes obligations.
"""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from .store import canonical


_NEXT_WORK_LIMIT = 512
_PREFLIGHT_LIMIT = 2048
_PREFLIGHT_TTL_SECONDS = 24 * 60 * 60


def _digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _row_signature(row):
    """Stable signature for one returned queue row, not a security decision."""
    return _digest({
        "obligation_id": row.get("obligation_id"),
        "queue_status": row.get("queue_status"),
        "suggested_action": row.get("suggested_action"),
        "next_action": row.get("next_action"),
        "missing_prerequisites": row.get("missing_prerequisites") or [],
        "evidence_ids": row.get("evidence_ids") or [],
        "input_template": row.get("input_template") or {},
        "actor_id": row.get("actor_id"),
        "baseline_actor_id": row.get("baseline_actor_id"),
        "resource_id": row.get("resource_id"),
    })


def _state_path(project, name):
    folder = Path(project.base) / ".loop_guard"
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    return folder / (name + ".json")


def _read_state(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (OSError, ValueError, TypeError):
        value = {}
    return value if isinstance(value, dict) else {}


def _write_state(path, value):
    try:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        # Scheduling state is advisory; a read-only project must still be able
        # to run its normal read-only pages.
        pass


def observe_next_page(project, offset, limit, rows, *, threshold=3):
    """Return obligation ids that have been shown unchanged too many times.

    Only the exact returned page is counted.  Reading a later page does not
    freeze unrelated work.  A changed row signature resets its counter, so new
    evidence, a new prerequisite, or a new suggested action naturally unlocks
    the task.
    """
    page_key = f"{int(offset)}:{int(limit)}"
    signature_rows = []
    for row in rows:
        obligation = project.get("obligation", row.get("obligation_id"), required=False) \
            if row.get("obligation_id") else None
        signature_rows.append({
            "id": row.get("obligation_id"),
            "signature": _row_signature(row),
            # A caller changing the persisted obligation (status/reason) is real
            # state movement even when the displayed queue row looks unchanged.
            "obligation": _digest(obligation) if isinstance(obligation, dict) else None,
        })
    signature = _digest(signature_rows)
    path = _state_path(project, "next_work")
    state = _read_state(path)
    entry = state.get(page_key) if isinstance(state.get(page_key), dict) else {}
    count = int(entry.get("count", 0)) + 1 if entry.get("signature") == signature else 1
    frozen = []
    state[page_key] = {
        "signature": signature,
        "count": count,
        "updated_at": _now(),
        "obligation_ids": [row.get("obligation_id") for row in rows if row.get("obligation_id")],
    }
    if count >= threshold and not rows == []:
        frozen = [row["obligation_id"] for row in rows
                  if row.get("obligation_id") and row.get("queue_status") != "blocked"]
        state[page_key]["count"] = 0
        state[page_key]["frozen_signature"] = signature
        state[page_key]["frozen_at"] = _now()
    # Keep scheduling state bounded; old pages are not security evidence.
    if len(state) > _NEXT_WORK_LIMIT:
        ordered = sorted(state.items(), key=lambda item: str(item[1].get("updated_at", "")))
        state = dict(ordered[-_NEXT_WORK_LIMIT:])
    _write_state(path, state)
    return set(frozen)


def mark_frozen(rows, obligation_ids):
    """Annotate frozen rows using only existing public work-item fields."""
    target = set(obligation_ids)
    changed = []
    for row in rows:
        if row.get("obligation_id") not in target:
            continue
        row["queue_status"] = "blocked"
        row["execution_blocked"] = True
        row["suggested_action"] = "plan.review"
        row["next_action"] = "plan.review"
        # Keep the underlying execution instruction available for a deliberate
        # plan.review reopen, but cap the displayed action set.
        row["hypothesis_hint"] = (
            "No state or evidence change after repeated queue views; task frozen by loop guard. "
            "Reopen only after supplying a changed prerequisite, identity, resource, or evidence."
        )
        prereqs = list(row.get("missing_prerequisites") or [])
        if "no_progress_frozen" not in prereqs:
            prereqs.append("no_progress_frozen")
        row["missing_prerequisites"] = list(dict.fromkeys(prereqs))
        changed.append(row)
    return changed


def _preflight_file(project):
    folder = Path(project.base) / ".loop_guard"
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    return folder / "preflight.json"


def repeat_seen(project, name, signature, *, threshold=3):
    """Count a named action signature and return true at the threshold."""
    path = _state_path(project, "repeat-" + str(name))
    state = _read_state(path)
    entry = state.get(signature) if isinstance(state.get(signature), dict) else {}
    count = int(entry.get("count", 0)) + 1
    state[signature] = {"count": count, "updated_at": _now()}
    if len(state) > _NEXT_WORK_LIMIT:
        ordered = sorted(state.items(), key=lambda item: str(item[1].get("updated_at", "")))
        state = dict(ordered[-_NEXT_WORK_LIMIT:])
    _write_state(path, state)
    return count >= threshold


def preflight_seen(project, request_signature, *, ttl_seconds=_PREFLIGHT_TTL_SECONDS):
    """Record a preflight signature and report whether it was already seen.

    This is intentionally only a preflight gate.  `http.capture` calls the
    engine directly and is not blocked by this cache.  The cache lives in a
    private sidecar file rather than the SQLite ledger because preflight must
    not mutate project entities/events/metadata.
    """
    if not isinstance(request_signature, str) or not request_signature:
        return False
    path = _preflight_file(project)
    try:
        state = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (OSError, ValueError, TypeError):
        state = {}
    if not isinstance(state, dict):
        state = {}
    now = time.time()
    # Drop expired entries before comparing.
    state = {key: value for key, value in state.items()
             if isinstance(value, (int, float)) and now - value <= ttl_seconds}
    previous = state.get(request_signature)
    state[request_signature] = now
    if len(state) > _PREFLIGHT_LIMIT:
        state = dict(sorted(state.items(), key=lambda item: item[1])[-_PREFLIGHT_LIMIT:])
    try:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        # The guard is advisory if a read-only project cannot persist it; it
        # must never break a legitimate first preflight.
        pass
    return isinstance(previous, (int, float))
