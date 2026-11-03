"""Checkpoint deltas describe exact-input progress without publishing test values."""
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import continuation, engine
from awa_ddd.__main__ import dispatch
from awa_ddd.assessment import evaluate
from awa_ddd.store import Project, now


class ParameterCheckpointTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-parameter-checkpoint-")
        self.addCleanup(temporary.cleanup)
        self.root = temporary.name
        self.base = "http://fixture.invalid"
        engine.create_project(self.root, {"project_id": "progress", "target": self.base})
        self.project = Project(self.root, "progress")
        self.addCleanup(self.project.close)
        self.operation = engine.register_operation(self.project, {"url": self.base + "/items", "method": "GET", "auth": "public",
            "inputs": [{"name": "q", "location": "query", "consumer": "business_input", "test_families": ["generic"]}]})
        engine.build_plan(self.project)

    def capture(self, value, count=1):
        def response(url, method, headers, body, timeout, max_bytes):
            raw = json.dumps({"count": count}).encode("utf-8")
            return {"request": {"url": url, "method": method, "headers": headers, "body_base64": ""},
                    "response": {"status": 200, "headers": [["content-type", "application/json"]], "length": len(raw),
                                 "body_base64": base64.b64encode(raw).decode("ascii")},
                    "started_at": now(), "completed_at": now(), "complete": True}
        with patch.object(engine, "request", side_effect=response):
            return engine.capture(self.project, {"operation_id": self.operation["id"], "url": self.operation["url"] + "?q=" + value})

    def checkpoint(self):
        return dispatch(self.root, "plan.checkpoint", {"project_id": "progress"})

    def controls(self):
        return [self.capture("normal-private-value"), self.capture("variant-private-value"), self.capture("sensitivity-private-value", 2)]

    def decide(self, controls):
        item = next(item for item in self.project.list("obligation") if item["kind"] == "input_test")
        return evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in controls],
            "oracle": {"type": "semantic_negative", "test_family": "generic", "selector": "/count", "baseline_expected": 1, "control_expected": 2}})

    def test_first_projection_establishes_a_baseline_not_invented_progress(self):
        self.decide(self.controls())
        saved = self.checkpoint()
        delta = saved["checkpoint"]["parameter_delta"]
        self.assertFalse(delta["comparison_available"])
        self.assertEqual(0, delta["newly_tested_total"])
        self.assertNotIn("parameter_progress", saved["checkpoint"])
        internal = self.project.get("checkpoint", saved["checkpoint"]["id"])
        self.assertEqual(1, len(internal["parameter_progress"]["tested_keys"]))
        self.assertTrue(internal["parameter_progress"]["complete"])

    def test_variants_and_typed_tests_have_separate_identity_only_deltas(self):
        self.checkpoint()
        controls = self.controls()
        observed = self.checkpoint()["checkpoint"]["parameter_delta"]
        self.assertTrue(observed["comparison_available"])
        self.assertEqual(1, observed["newly_observed_variants_total"])
        self.assertEqual(0, observed["newly_tested_total"])
        self.assertFalse(observed["observation_is_testing"])
        self.decide(controls)
        tested = self.checkpoint()["checkpoint"]["parameter_delta"]
        self.assertEqual(1, tested["newly_tested_total"])
        self.assertEqual(0, tested["newly_observed_variants_total"])
        self.assertEqual("q", tested["newly_tested"][0]["input_selector"])
        self.assertEqual("generic", tested["newly_tested"][0]["test_family"])
        self.assertNotIn("private-value", json.dumps({"observed": observed, "tested": tested}))

    def test_duplicate_captures_do_not_add_delta_or_obligations(self):
        self.checkpoint()
        controls = self.controls()
        self.decide(controls)
        self.checkpoint()
        total = len(self.project.list("obligation"))
        self.capture("normal-private-value")
        saved = self.checkpoint()["checkpoint"]["parameter_delta"]
        self.assertEqual(0, saved["newly_tested_total"])
        self.assertEqual(0, saved["newly_observed_variants_total"])
        self.assertEqual(total, len(self.project.list("obligation")))

    def test_changed_material_reopens_coverage_instead_of_retaining_a_delta_claim(self):
        controls = self.controls()
        self.decide(controls)
        self.checkpoint()
        artifact = self.project.base / controls[1]["artifact_path"]
        artifact.write_bytes(artifact.read_bytes() + b" ")
        saved = self.checkpoint()
        self.assertEqual(1, saved["checkpoint"]["parameter_delta"]["reopened_total"])
        self.assertEqual(0, saved["checkpoint"]["parameter_delta"]["newly_tested_total"])
        self.assertFalse(saved["continuation"]["can_claim_complete"])

    def test_legacy_or_budget_limited_projection_does_not_fabricate_comparison(self):
        saved = self.checkpoint()["checkpoint"]
        internal = self.project.get("checkpoint", saved["id"])
        internal.pop("parameter_progress")
        internal.update(id=self.project.id("CP"), created_at=now())
        self.project.put("checkpoint", internal, create_only=True)
        self.assertFalse(self.checkpoint()["checkpoint"]["parameter_delta"]["comparison_available"])
        with patch.object(continuation, "MAX_PARAMETER_PROGRESS_KEYS", 0):
            limited = self.checkpoint()["checkpoint"]["parameter_delta"]
        self.assertFalse(limited["projection_complete"])
        self.assertFalse(limited["comparison_available"])
        self.assertEqual(0, limited["newly_tested_total"])


if __name__ == "__main__":
    unittest.main()
