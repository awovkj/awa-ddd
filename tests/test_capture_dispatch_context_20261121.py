"""Internal capture dispatch contexts cannot bypass their durable request binding."""
from __future__ import annotations

import unittest
from unittest.mock import patch

import v2_fixtures as fx
from awa_ddd import engine
from awa_ddd import execution_coordinator as coordinator
from awa_ddd.domain.common import digest
from awa_ddd.store import EngineError


class CaptureDispatchContextTests(unittest.TestCase):
    def setUp(self):
        self.temporary, self.root = fx.workspace()
        self.addCleanup(self.temporary.cleanup)
        self.project = fx.project(self.root)
        self.addCleanup(self.project.close)
        self.operation = fx.register(
            self.project, "http://fixture.invalid/items", "GET", "public", [
                {"name": "q", "location": "query", "selector": "q",
                 "consumer": "business_input", "test_families": ["generic"]},
            ])

    def _context(self, args, run_id="RUN2-CONTEXT"):
        prepared = engine.preflight_capture(self.project, args)
        lease = coordinator.claim(
            self.project, "v2-run:" + run_id,
            owner="worker", ttl=60)
        receipt = coordinator.dispatch(
            self.project, lease, action="http.capture", run_id=run_id,
            request_hash=prepared["dispatch_spec"]["request_hash"],
            budget="v2-execution:" + run_id,
            max_requests=1, max_writes=0, effect="read_only")
        self.project.put("v2_run", {
            "id": run_id,
            "campaign_id": "CAM-context",
            "hypothesis_id": "HYP-context",
            "status": "dispatch_started",
            "dispatch_receipt_ids": [receipt["id"]],
        }, create_only=True)
        return prepared, {
            "receipt_id": receipt["id"],
            **prepared["dispatch_spec"],
            "run_id": run_id,
            "lease_name": receipt["lease_name"],
            "fence": receipt["fence"],
        }

    def test_tampered_request_hash_is_rejected_before_dispatch_or_claim(self):
        args = {
            "operation_id": self.operation["id"],
            "url": self.operation["url"] + "?q=normal",
            "idempotency_key": "capture-context-tampered",
        }
        _prepared, context = self._context(args)
        context["request_hash"] = digest("different request")
        transport = fx.Sequence([{"value": "must-not-be-sent"}])
        with patch("awa_ddd.engine.request", side_effect=transport):
            with self.assertRaises(EngineError) as caught:
                engine.capture(
                    self.project, args, dispatch_context=context)
        self.assertEqual(
            "capture_dispatch_context", caught.exception.code)
        self.assertEqual(0, transport.calls)
        self.assertEqual([], self.project.list("run"))
        self.assertEqual([], self.project.list("evidence"))

    def test_valid_context_sends_once_and_does_not_claim_again(self):
        args = {
            "operation_id": self.operation["id"],
            "url": self.operation["url"] + "?q=normal",
            "idempotency_key": "capture-context-valid",
        }
        _prepared, context = self._context(args)
        transport = fx.Sequence([{"value": "normal"}])
        with patch("awa_ddd.engine.request", side_effect=transport), \
                patch(
                    "awa_ddd.execution_coordinator.claim",
                    side_effect=AssertionError("must not create a second lease")):
            evidence = engine.capture(
                self.project, args, dispatch_context=context)
        self.assertTrue(evidence["complete"])
        self.assertEqual(1, transport.calls)
        self.assertEqual(
            1, len(self.project.list("execution_dispatch")))


if __name__ == "__main__":
    unittest.main()
