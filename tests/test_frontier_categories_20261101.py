"""Closed families are explicit, evidence-bound, and never erase untraced inputs."""
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import continuation, engine
from awa_ddd.__main__ import dispatch
from awa_ddd.assessment import evaluate
from awa_ddd.store import EngineError, Project, now


class FrontierCategoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-frontier-category-")
        self.addCleanup(temporary.cleanup)
        self.root = temporary.name
        self.base = "http://fixture.invalid"
        engine.create_project(self.root, {"project_id": "frontier", "target": self.base})
        self.project = Project(self.root, "frontier")
        self.addCleanup(self.project.close)
        self.operation = engine.register_operation(self.project, {
            "url": self.base + "/deserialize", "method": "GET", "auth": "public",
            "inputs": [{"name": "payload", "location": "query", "consumer": "deserialize",
                        "test_families": ["deserialization"]}]})
        engine.build_plan(self.project)

    def capture(self, value="normal", count=1):
        def response(url, method, headers, body, timeout, max_bytes):
            raw = json.dumps({"count": count}).encode("utf-8")
            return {"request": {"url": url, "method": method, "headers": headers, "body_base64": ""},
                    "response": {"status": 200, "headers": [["content-type", "application/json"]],
                                 "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
                    "started_at": now(), "completed_at": now(), "complete": True}

        with patch.object(engine, "request", side_effect=response):
            return engine.capture(self.project, {"operation_id": self.operation["id"],
                                                 "url": self.operation["url"] + "?payload=" + value})

    def close_family(self):
        controls = [self.capture(), self.capture("variant"), self.capture("sensitive", 2)]
        items = {item["kind"]: item for item in self.project.list("obligation") if not item.get("superseded")}
        evaluate(self.project, {"obligation_id": items["baseline"]["id"], "evidence_ids": [controls[0]["id"]],
                                "oracle": {"type": "baseline", "selector": "/count", "expected": 1}})
        evaluate(self.project, {"obligation_id": items["input_test"]["id"],
                                "evidence_ids": [item["id"] for item in controls],
                                "oracle": {"type": "semantic_negative", "test_family": "deserialization",
                                           "selector": "/count", "baseline_expected": 1, "control_expected": 2}})
        return controls

    def frontier(self, evidence, status="completed"):
        refs = {"evidence_ids": [evidence["id"]]}
        return {"discovery": {"status": "reviewed", "reason": "Reviewed the finite isolated API scope.", **refs},
                "pages": {"status": "api_only", "reason": "The fixture has no registered browser pages.", **refs},
                "categories": [{"test_family": family,
                                "status": status if family == "deserialization" else "not_applicable",
                                "reason": "Reviewed the declared fixture hypothesis and its current controls.", **refs}
                               for family in continuation.ALL_FAMILIES]}

    def test_legacy_planned_already_accepts_a_fully_evaluated_family(self):
        evidence = self.close_family()[0]
        saved = continuation.checkpoint(self.project, {"frontier_review": self.frontier(evidence, "planned")})
        self.assertEqual(1, saved["continuation"]["frontier_rounds"])
        self.assertTrue(saved["checkpoint"]["frontier_review"]["complete"])

    def test_completed_family_allows_two_current_rounds_and_strict_finalization(self):
        evidence = self.close_family()[0]
        frontier = self.frontier(evidence)
        continuation.checkpoint(self.project, {"frontier_review": frontier})
        saved = dispatch(self.root, "plan.checkpoint", {"project_id": "frontier", "frontier_review": frontier})
        self.assertEqual(2, saved["continuation"]["frontier_rounds"])
        self.assertTrue(saved["continuation"]["can_finalize"])
        row = next(item for item in saved["checkpoint"]["frontier_review"]["categories"]
                   if item["test_family"] == "deserialization")
        self.assertEqual("completed", row["status"])
        stopped = continuation.finalize(self.project, {"checkpoint_id": saved["checkpoint"]["id"],
            "reason": "completed", "reviewer": "fixture-reviewer",
            "explanation": "Current bounded obligations and both evidence-bound review rounds are closed."})
        self.assertTrue(stopped["continuation"]["can_claim_complete"])

    def test_completed_is_not_a_text_only_claim_or_an_na_alias(self):
        evidence = self.capture()
        with self.assertRaises(EngineError) as caught:
            continuation.checkpoint(self.project, {"frontier_review": self.frontier(evidence)})
        self.assertEqual("frontier_categories", caught.exception.code)
        self.assertEqual([], self.project.list("checkpoint"))
        self.close_family()
        frontier = self.frontier(evidence)
        next(row for row in frontier["categories"] if row["test_family"] == "generic")["status"] = "completed"
        with self.assertRaises(EngineError) as caught:
            continuation.checkpoint(self.project, {"frontier_review": frontier})
        self.assertEqual("frontier_categories", caught.exception.code)

    def test_untraced_generic_is_the_named_failure_not_the_closed_family(self):
        evidence = self.close_family()[0]
        engine.register_operation(self.project, {"url": self.base + "/unknown", "method": "GET", "auth": "public",
            "inputs": [{"name": "q", "location": "query"}]})
        engine.build_plan(self.project)
        frontier = self.frontier(evidence, "planned")
        next(row for row in frontier["categories"] if row["test_family"] == "generic")["status"] = "planned"
        with self.assertRaises(EngineError) as caught:
            dispatch(self.root, "plan.checkpoint", {"project_id": "frontier", "frontier_review": frontier})
        self.assertEqual("frontier_categories", caught.exception.code)
        self.assertIn("generic:", str(caught.exception))
        self.assertEqual("generic", caught.exception.details["test_family"])
        self.assertEqual("plan.audit", caught.exception.details["next_action"])

    def test_stale_attack_material_reopens_a_completed_family(self):
        controls = self.close_family()
        frontier = self.frontier(controls[0])
        continuation.checkpoint(self.project, {"frontier_review": frontier})
        continuation.checkpoint(self.project, {"frontier_review": frontier})
        artifact = self.project.base / controls[1]["artifact_path"]
        artifact.write_bytes(artifact.read_bytes() + b" ")
        current = engine.evaluate_coverage(self.project)["continuation"]
        self.assertFalse(current["can_finalize"])
        self.assertEqual(0, current["frontier_rounds"])
        with self.assertRaises(EngineError) as caught:
            continuation.checkpoint(self.project, {"frontier_review": frontier})
        self.assertEqual("frontier_categories", caught.exception.code)


if __name__ == "__main__":
    unittest.main()
