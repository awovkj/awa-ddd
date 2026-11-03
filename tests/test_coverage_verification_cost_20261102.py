"""Coverage shares verified observations and queue resources only within one call."""
from __future__ import annotations

import base64
from collections import Counter
import json
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import completeness, engine, workflow
from awa_ddd.store import Project, now


def observation(url, method, headers, body, timeout, max_bytes):
    raw = json.dumps({"count": 1, "subject": "fixture-subject"}).encode("utf-8")
    sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else b""
    return {"request": {"url": url, "method": method, "headers": headers,
                        "body_base64": base64.b64encode(sent).decode("ascii")},
            "response": {"status": 200, "headers": [["content-type", "application/json"]],
                         "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
            "started_at": now(), "completed_at": now(), "complete": True}


class CoverageVerificationCostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-coverage-cost-")
        self.addCleanup(temporary.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(temporary.name, {"project_id": "cost", "target": self.base, "allow_mutation": True})
        self.project = Project(temporary.name, "cost")
        self.addCleanup(self.project.close)

    def operation(self, path="/items", **extra):
        return engine.register_operation(self.project, {"url": self.base + path, "method": "GET", "auth": "public",
            "inputs": [{"name": "q", "location": "query", "consumer": "business_input", "test_families": ["generic"]}],
            **extra})

    def capture(self, operation, **extra):
        with patch.object(engine, "request", side_effect=observation):
            return engine.capture(self.project, {"operation_id": operation["id"], **extra})

    def test_method_matrix_reuses_the_current_inventory_verification(self):
        operation = self.operation()
        engine.build_plan(self.project)
        captures = [self.capture(operation, url=operation["url"] + "?q=" + value)
                    for value in ("normal", "variant", "sensitivity")]
        with patch.object(engine, "verify_current_evidence", wraps=engine.verify_current_evidence) as verified:
            evaluated, inventory = completeness.evaluate_with_inventory(self.project)
        counts = Counter(call.args[1] for call in verified.call_args_list)
        self.assertEqual({capture["id"]: 1 for capture in captures}, dict(counts))
        self.assertEqual(3, len(inventory["observations"]))
        self.assertEqual(["GET"], evaluated["method_coverage"][0]["observed_methods"])
        self.assertEqual([], evaluated["method_coverage"][0]["tested"])

    def test_next_call_rechecks_bytes_and_does_not_cache_current_observations(self):
        operation = self.operation()
        engine.build_plan(self.project)
        evidence = self.capture(operation, url=operation["url"] + "?q=fixture")
        first = engine.evaluate_coverage(self.project)
        self.assertEqual(["GET"], first["method_coverage"][0]["observed_methods"])
        path = self.project.base / evidence["artifact_path"]
        path.write_bytes(path.read_bytes() + b" ")
        with patch.object(engine, "verify_current_evidence", wraps=engine.verify_current_evidence) as verified:
            second = engine.evaluate_coverage(self.project)
        self.assertIn(evidence["id"], [call.args[1] for call in verified.call_args_list])
        self.assertEqual([], second["method_coverage"][0]["observed_methods"])
        self.assertEqual(0, second["parameter_coverage_summary"]["observed_total"])
        self.assertEqual(1, len(self.project.list("evidence")))

    def test_operation_lineage_change_reopens_method_observations_next_call(self):
        operation = self.operation()
        engine.build_plan(self.project)
        self.capture(operation, url=operation["url"] + "?q=fixture")
        self.assertEqual(["GET"], engine.evaluate_coverage(self.project)["method_coverage"][0]["observed_methods"])
        engine.register_operation(self.project, {"url": operation["url"], "method": "GET", "auth": "authenticated"})
        engine.build_plan(self.project)
        result = engine.evaluate_coverage(self.project)
        self.assertEqual([], result["method_coverage"][0]["observed_methods"])
        self.assertFalse(result["continuation"]["automatic_stop_allowed"])

    def test_non_http_current_records_remain_method_observations_only(self):
        operation = self.operation()
        engine.build_plan(self.project)
        evidence = self.capture(operation, url=operation["url"] + "?q=fixture")
        artifact = self.project.read_artifact(evidence)
        identity = self.project.id("E")
        path, digest = self.project.artifact(identity, artifact)
        extra = {**evidence, "id": identity, "kind": "non_http_observation", "artifact_path": path, "sha256": digest}
        self.project.put("evidence", extra)
        with patch.object(engine, "verify_current_evidence", wraps=engine.verify_current_evidence) as verified:
            evaluated, inventory = completeness.evaluate_with_inventory(self.project)
        self.assertEqual(1, len(inventory["observations"]))
        self.assertEqual(2, len(inventory["method_observations"]))
        self.assertEqual({evidence["id"]: 1, extra["id"]: 1}, dict(Counter(call.args[1] for call in verified.call_args_list)))
        self.assertEqual(["GET"], evaluated["method_coverage"][0]["observed_methods"])
        self.assertEqual(1, inventory["parameter_coverage_snapshot"]["items"][0]["observation_count"])

    def test_queue_resources_are_read_once_per_call_not_once_per_obligation(self):
        for index in range(4):
            engine.add_actor(self.project, {"actor_id": "A-" + str(index), "subject": "fixture-" + str(index), "roles": []})
        for index in range(8):
            operation = self.operation("/items/" + str(index), auth="authenticated")
            engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": "A-0",
                "external_id": "fixture-resource", "request_binding": {"location": "query", "selector": "q"}})
        engine.build_plan(self.project)
        with patch.object(self.project, "list", wraps=self.project.list) as listed, patch.object(engine, "request") as network:
            result = workflow.next_work(self.project, {"limit": 1, "parameter_limit": 1})
        network.assert_not_called()
        self.assertGreater(result["blocked_total"], 25)
        self.assertLessEqual(sum(call.args == ("resource",) for call in listed.call_args_list), 2)
        self.assertEqual(8, len(self.project.list("resource")))

    def test_queue_resource_snapshot_does_not_survive_the_next_call(self):
        engine.add_actor(self.project, {"actor_id": "fixture-owner", "subject": "fixture-subject", "roles": []})
        engine.add_actor(self.project, {"actor_id": "other-owner", "subject": "other-subject", "roles": []})
        session = engine.add_session(self.project, {"actor_id": "fixture-owner",
            "headers": {"Cookie": "fixture-principal=fixture-subject"}})
        identity = self.operation("/whoami", auth="authenticated", inputs=[])
        with patch.object(engine, "request", side_effect=observation):
            engine.verify_identity(self.project, {"operation_id": identity["id"], "session_id": session["id"],
                "subject_selector": "/subject"})
        operation = self.operation("/write", method="POST", auth="authenticated",
            inputs=[{"name": "q", "location": "body", "consumer": "business_input", "test_families": ["generic"]}])
        resource_args = {"operation_id": operation["id"], "owner_actor_id": "fixture-owner",
                         "external_id": "fixture-resource", "request_binding": {"location": "body", "selector": "q"}}
        first = engine.add_resource(self.project, resource_args)
        engine.build_plan(self.project)

        def selected_resource():
            with patch.object(engine, "request") as network, patch.object(workflow, "_work_item", wraps=workflow._work_item) as work:
                result = workflow.next_work(self.project, {"limit": 25})
            network.assert_not_called()
            row = next(row for row in result["work_items"] if row["operation_id"] == operation["id"]
                       and row["obligation_kind"] == "input_test")
            projected = next(call.kwargs["resources"] for call in work.call_args_list
                             if call.args[1]["operation_id"] == operation["id"])
            return row["input_template"]["resource_id"], projected[0]["external_id"]

        self.assertEqual((first["id"], "fixture-resource"), selected_resource())
        engine.add_resource(self.project, {**resource_args, "resource_id": first["id"], "external_id": "changed-fixture-resource"})
        self.assertEqual((first["id"], "changed-fixture-resource"), selected_resource())
        self.assertEqual(1, len(self.project.list("resource")))


if __name__ == "__main__":
    unittest.main()
