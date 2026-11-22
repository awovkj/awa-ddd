"""Atomic, bounded repeat hints; viewing work never changes its readiness."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import time
from datetime import datetime, timezone

from .store import canonical

_NEXT_WORK_LIMIT = 512
_PREFLIGHT_LIMIT = 2048
_PREFLIGHT_TTL_SECONDS = 24 * 60 * 60


def _digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _row_signature(row):
    return _digest({key: row.get(key) for key in (
        "obligation_id", "queue_status", "suggested_action", "next_action", "missing_prerequisites",
        "evidence_ids", "input_template", "actor_id", "baseline_actor_id", "resource_id")})


def _update(project, name, mutation, default):
    """Serialize cross-process updates without modifying entities/events.

    Old sidecars are retained. Their counters may seed the advisory table once,
    but they never acquire execution or proof authority.
    """
    def update(state):
        if not state:
            path = Path(project.base) / ".loop_guard" / (name + ".json")
            try:
                if path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024 * 1024:
                    legacy = json.loads(path.read_text(encoding="utf-8-sig"))
                    if isinstance(legacy, dict):
                        state.update(legacy)
            except (OSError, ValueError, TypeError):
                pass
        return mutation(state)
    try:
        return project.advisory_update("loop_guard:" + name, update)
    except (OSError, sqlite3.Error):
        return default


def _trim(state, limit, key):
    if len(state) > limit:
        retained = sorted(state.items(), key=key)[-limit:]
        state.clear()
        state.update(retained)


def observe_next_page(project, offset, limit, rows, *, threshold=3):
    """Return unchanged displayed IDs that merit a repeat hint, never a lock."""
    signature_rows = []
    for row in rows:
        obligation = project.get("obligation", row.get("obligation_id"), required=False) if row.get("obligation_id") else None
        signature_rows.append({"id": row.get("obligation_id"), "signature": _row_signature(row),
                               "obligation": _digest(obligation) if isinstance(obligation, dict) else None})
    signature = _digest(signature_rows)
    page_key = f"{int(offset)}:{int(limit)}"
    def mutation(state):
        previous = state.get(page_key, {})
        previous = previous if isinstance(previous, dict) else {}
        count = int(previous.get("count", 0)) + 1 if previous.get("signature") == signature else 1
        ids = [row["obligation_id"] for row in rows if row.get("obligation_id")]
        state[page_key] = {"signature": signature, "count": min(count, 1000000), "updated_at": _now(),
                           "obligation_ids": ids}
        _trim(state, _NEXT_WORK_LIMIT, lambda item: str(item[1].get("updated_at", "")))
        return set(ids) if count >= threshold else set()
    return _update(project, "next_work", mutation, set())


def mark_frozen(rows, obligation_ids):
    """Compatibility name: annotate a repeated view without changing actions."""
    changed = []
    for row in rows:
        if row.get("obligation_id") in obligation_ids:
            row["repeat_advisory"] = True
            row["hypothesis_hint"] = (
                "This work item has been viewed repeatedly with unchanged prerequisites. "
                "Inspect the current blocker or carry out the prepared next action; readiness is unchanged.")
            changed.append(row)
    return changed


def repeat_seen(project, name, signature, *, threshold=3):
    def mutation(state):
        previous = state.get(signature, {})
        count = int(previous.get("count", 0)) + 1 if isinstance(previous, dict) else 1
        state[signature] = {"count": min(count, 1000000), "updated_at": _now()}
        _trim(state, _NEXT_WORK_LIMIT, lambda item: str(item[1].get("updated_at", "")))
        return count >= threshold
    return _update(project, "repeat-" + str(name), mutation, False)


def preflight_seen(project, request_signature, *, ttl_seconds=_PREFLIGHT_TTL_SECONDS):
    if not isinstance(request_signature, str) or not request_signature:
        return False
    def mutation(state):
        current = time.time()
        expired = [key for key, value in state.items() if not isinstance(value, (int, float))
                   or current - value > ttl_seconds]
        for key in expired:
            state.pop(key, None)
        previous = state.get(request_signature)
        state[request_signature] = current
        _trim(state, _PREFLIGHT_LIMIT, lambda item: item[1])
        return isinstance(previous, (int, float))
    return _update(project, "preflight", mutation, False)
