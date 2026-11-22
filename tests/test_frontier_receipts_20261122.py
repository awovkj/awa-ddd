"""A receipt binds actual frontier material; labels cannot create extra rounds."""
from __future__ import annotations

from copy import deepcopy
import unittest

import test_continuation_20261030 as fixtures
from awa_ddd import browser, continuation, engine
from awa_ddd.__main__ import dispatch
from awa_ddd.store import EngineError, canonical
from awa_test_support import record_observation


class FrontierReceiptTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ContinuationTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.project = self.fixture.project

    def test_repeated_review_and_new_labels_remain_one_material_round(self):
        self.fixture.close_generic()
        first = self.fixture.checkpoint(self.fixture.frontier())
        review = self.fixture.frontier()
        review["discovery"]["reason"] = "A second label still reviews the same actual observation."
        for index in range(5):
            last = self.fixture.checkpoint(review, label="Review label " + str(index))
            self.assertEqual(1, last["continuation"]["frontier_rounds"])
            self.assertFalse(last["continuation"]["can_finalize"])
            self.assertEqual(first["checkpoint"]["frontier_observation_key"], last["checkpoint"]["frontier_observation_key"])
        with self.assertRaises(EngineError):
            self.fixture.finish(last)
        self.assertEqual([], self.project.list("finalization"))

    def test_new_capture_of_the_same_wire_material_is_not_another_round(self):
        baseline = self.fixture.close_generic()
        first = self.fixture.checkpoint(self.fixture.frontier(baseline))
        duplicate = self.fixture.capture(url=self.fixture.operation["url"] + "?q=normal")
        self.assertNotEqual(baseline["id"], duplicate["id"])
        second = self.fixture.checkpoint(self.fixture.frontier(duplicate))
        self.assertEqual(first["checkpoint"]["frontier_observation_key"], second["checkpoint"]["frontier_observation_key"])
        self.assertEqual(1, second["continuation"]["frontier_rounds"])
        self.assertFalse(second["continuation"]["can_finalize"])

    def test_browser_transport_clocks_and_dispatch_handles_do_not_create_independence(self):
        url = "http://fixture.invalid/view"
        raw = {"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1},
               "network": [{"url": url, "method": "GET", "status": 200, "guard_dispatch_id": "DSP-first",
                            "timestamp": "2026-11-21T00:00:00Z", "response_headers": {"date": "first", "content-type": "text/html"}}],
               "actions": [{"action": "click", "ok": True, "finalUrl": url, "elapsed_ms": 12}]}
        record_observation(self.project, raw, "PV-clock-first", "local_playwright")
        repeated = deepcopy(raw)
        repeated["network"][0].update(guard_dispatch_id="DSP-second", timestamp="2026-11-22T00:00:00Z")
        repeated["network"][0]["response_headers"]["date"] = "second"
        repeated["actions"][0]["elapsed_ms"] = 50
        record_observation(self.project, repeated, "PV-clock-second", "local_playwright")
        review = {"discovery": {"page_visit_ids": ["PV-clock-first"]}, "pages": {}, "categories": []}
        first = continuation._frontier_material(self.project, review)
        review["discovery"]["page_visit_ids"] = ["PV-clock-second"]
        self.assertEqual(first, continuation._frontier_material(self.project, review))
        changed = deepcopy(raw)
        changed["signals"]["forms"] = 2
        record_observation(self.project, changed, "PV-content-change", "local_playwright")
        review["discovery"]["page_visit_ids"] = ["PV-content-change"]
        self.assertNotEqual(first, continuation._frontier_material(self.project, review))

    def test_receiptless_history_is_retained_but_cannot_grant_completion(self):
        self.fixture.close_generic()
        first = self.fixture.checkpoint(self.fixture.frontier())
        second = self.fixture.checkpoint(self.fixture.frontier(self.fixture.variant_evidence))
        self.assertTrue(second["continuation"]["can_finalize"])
        for checkpoint in (first["checkpoint"], second["checkpoint"]):
            old = self.project.get("checkpoint", checkpoint["id"])
            old.pop("frontier_receipt_id")
            old.pop("frontier_observation_key")
            self.project.connection.execute("UPDATE entities SET document=? WHERE kind='checkpoint' AND id=?",
                                            (canonical(old), old["id"]))
        result = engine.evaluate_coverage(self.project)["continuation"]
        self.assertEqual(0, result["frontier_rounds"])
        self.assertFalse(result["can_finalize"])
        self.assertEqual(2, len(self.project.list("checkpoint")))
        with self.assertRaises(EngineError):
            self.fixture.finish(second)

    def test_public_partial_receipt_is_idempotent_and_expires_on_new_checkpoint(self):
        checkpoint = self.fixture.checkpoint()
        args = {"project_id": self.project.project_id, "checkpoint_id": checkpoint["checkpoint"]["id"],
                "accepted_by": "fixture-delivery-owner", "explanation": "Deliver current partial evidence and retain the remaining work."}
        first = dispatch(self.fixture.root, "plan.accept_partial", args)
        second = dispatch(self.fixture.root, "plan.accept_partial", args)
        self.assertEqual(first["partial_acceptance"]["id"], second["partial_acceptance"]["id"])
        self.assertEqual("partial_accepted", first["completion_decision"]["state"])
        for flag in ("can_finalize", "can_claim_complete", "automatic_stop_allowed"):
            self.assertFalse(first["continuation"][flag])
        self.assertTrue(first["continuation"]["continue_required"])
        current = self.fixture.checkpoint(label="New checkpoint invalidates the prior delivery acceptance")
        self.assertIsNone(current["continuation"]["partial_acceptance_id"])
        with self.assertRaises(EngineError) as stale:
            dispatch(self.fixture.root, "plan.accept_partial", args)
        self.assertEqual("checkpoint_stale", stale.exception.code)
        self.assertEqual(1, len(self.project.list("completion_acceptance")))


if __name__ == "__main__":
    unittest.main()
