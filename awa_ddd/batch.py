"""Bounded sequential batch wrapping the exact single-obligation evaluator.

The batch action intentionally does not synthesize oracles.  Each item is the
same payload `assessment.evaluate` accepts, so identity, resource, evidence,
oracle and write gates remain identical to a single evaluation.
"""
from __future__ import annotations

from .store import EngineError


def assessment_batch(project, args, evaluate_fn=None, recover_fn=None):
    items = args.get("items")
    if not isinstance(items, list) or not 1 <= len(items) <= 50 \
            or any(not isinstance(item, dict) for item in items):
        raise EngineError("assessment_batch", "items must be an array of 1..50 objects")
    if evaluate_fn is None:
        from .assessment import evaluate as evaluate_fn
    if recover_fn is None:
        from .oracle_contracts import recover as recover_fn
    results = []
    for index, item in enumerate(items):
        entry = {"index": index, "obligation_id": item.get("obligation_id")}
        try:
            decision = evaluate_fn(project, item)
        except EngineError as exc:
            detail = {}
            try:
                detail = recover_fn(project, item, exc)
            except Exception:
                detail = {}
            entry.update(ok=False, error_code=getattr(exc, "code", "assessment_error"),
                         message=str(exc)[:500], recovery=detail)
        except Exception as exc:  # defensive: one malformed item must not abort later items
            entry.update(ok=False, error_code="assessment_error", message=str(exc)[:500])
        else:
            entry.update(ok=True, decision_id=decision.get("id"), outcome=decision.get("outcome"),
                         mode=decision.get("mode"))
        results.append(entry)
    return {"results": results, "evaluated": sum(item["ok"] for item in results),
            "failed": sum(not item["ok"] for item in results), "requests_sent": 0,
            "next_action": "plan.next",
            "limitation": "Each item used the exact single-evaluation contract. A failed item is not retried and no assertion is inferred."}
