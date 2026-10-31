"""No-network preflight and durable failure checkpoints for bounded workflows."""
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import engine
from awa_ddd.scenario import preflight, run_scenario
from awa_ddd.store import EngineError, Project, now


def observation(*args):
    url, method, headers, body, _, _ = args
    raw = json.dumps({"ok": True, "value": "fixture", "next": "http://outside.invalid/no"}).encode("utf-8")
    return {"request": {"url": url, "method": method, "headers": headers, "body_base64": ""},
            "response": {"status": 200, "headers": [], "body_base64": base64.b64encode(raw).decode("ascii"), "length": len(raw)},
            "complete": True, "started_at": now(), "completed_at": now()}


class ScenarioPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-scenario-")
        self.addCleanup(self.tmp.cleanup)
        engine.create_project(self.tmp.name, {"project_id": "scenario", "target": "http://fixture.invalid"})
        self.project = Project(self.tmp.name, "scenario")
        self.addCleanup(self.project.close)
        self.operation = engine.register_operation(self.project, {"url": "http://fixture.invalid/echo", "method": "GET", "auth": "public"})

    def step(self, id="one", **extra):
        return {"id": id, "operation_id": self.operation["id"], **extra}

    def test_later_bad_request_is_found_before_the_first_capture(self):
        args = {"scenario": {"steps": [self.step(), self.step("two", url="http://outside.invalid/echo")]}}
        with patch.object(engine, "request") as network:
            result = preflight(self.project, args)
            with self.assertRaises(EngineError) as caught:
                run_scenario(self.project, args)
        self.assertFalse(result["static_valid"])
        self.assertEqual(caught.exception.code, "scenario_preflight")
        self.assertEqual(caught.exception.details["requests_sent"], 0)
        self.assertEqual(self.project.list("run"), [])
        network.assert_not_called()

    def test_bad_concurrency_is_rejected_without_a_claim(self):
        for repeats in (True, 1, 41, "2"):
            with self.assertRaises(EngineError):
                run_scenario(self.project, {"scenario": {"steps": [self.step(concurrent=repeats)]}})
        self.assertEqual(self.project.list("run"), [])

    def test_total_attempt_budget_is_not_per_step_only(self):
        with self.assertRaises(EngineError) as caught:
            preflight(self.project, {"scenario": {"steps": [self.step("s" + str(index), concurrent=40) for index in range(6)]}})
        self.assertEqual(caught.exception.code, "scenario_budget")

    def test_future_values_are_deferred_not_approved(self):
        args = {"scenario": {"steps": [self.step(extract={"value": "/value"}), self.step("two", body={"value": "${one.value}"})]}}
        result = preflight(self.project, args)
        self.assertTrue(result["static_valid"])
        self.assertEqual(result["deferred_steps"], 1)
        self.assertEqual(result["steps"][1]["status"], "deferred")
        self.assertEqual(self.project.list("evidence"), [])

    def test_unknown_or_forward_variable_is_rejected_early(self):
        with self.assertRaises(EngineError) as caught:
            preflight(self.project, {"scenario": {"steps": [self.step(body={"x": "${future.value}"})]}})
        self.assertEqual(caught.exception.code, "scenario_variable")

    def test_target_values_cannot_choose_a_local_body_file_or_identity(self):
        for field in ("body_file", "session_id", "resource_id", "operation_id", "effect", "timeout"):
            args = {"scenario": {"steps": [self.step(extract={"value": "/value"}), self.step("two", **{field: "${one.value}"})]}}
            with self.assertRaises(EngineError) as caught:
                preflight(self.project, args)
            self.assertEqual(caught.exception.code, "scenario_control")
        self.assertEqual(self.project.list("run"), [])

    def test_dynamic_body_does_not_hide_static_wrong_path_or_headers(self):
        for extra in ({"url": "http://fixture.invalid/not-the-operation"}, {"headers": {"Host": "fixture.invalid"}},
                      {"headers": {"Authorization": "Bearer fixture"}}, {"body_base64": "eA=="}):
            args = {"scenario": {"steps": [self.step(extract={"value": "/value"}), self.step("two", body={"value": "${one.value}"}, **extra)]}}
            with patch.object(engine, "request") as network:
                result = preflight(self.project, args)
                with self.assertRaises(EngineError):
                    run_scenario(self.project, args)
            self.assertFalse(result["static_valid"])
            network.assert_not_called()
        self.assertEqual(self.project.list("run"), [])

    def test_invalid_pointer_escape_is_rejected_before_side_effects(self):
        for extra in ({"extract": {"value": "/bad~2escape"}}, {"assertions": [{"selector": "/bad~2escape", "equals": True}]}):
            with self.assertRaises(EngineError):
                preflight(self.project, {"scenario": {"steps": [self.step(**extra)]}})
        self.assertEqual(self.project.list("run"), [])

    def test_dynamic_url_is_checked_before_the_dependent_request(self):
        args = {"scenario": {"steps": [self.step(extract={"url": "/next"}), self.step("two", url="${one.url}")]}}
        with patch.object(engine, "request", side_effect=observation) as network:
            with self.assertRaises(EngineError) as caught:
                run_scenario(self.project, args)
        self.assertEqual(network.call_count, 1)
        run = self.project.get("run", caught.exception.details["run_id"])
        self.assertEqual(run["status"], "failed")
        self.assertEqual(run["checkpoints"][0]["status"], "verified")
        self.assertEqual(run["checkpoints"][1]["status"], "failed")
        self.assertEqual(len(run["evidence_ids"]), 1)

    def test_assertion_failure_preserves_capture_and_returns_run_id(self):
        args = {"scenario": {"steps": [self.step(assertions=[{"selector": "/ok", "equals": False}])]}}
        with patch.object(engine, "request", side_effect=observation):
            with self.assertRaises(EngineError) as caught:
                run_scenario(self.project, args)
        self.assertEqual(caught.exception.code, "scenario_assertion")
        self.assertEqual(caught.exception.details["next_action"], "run.inspect")
        run = self.project.get("run", caught.exception.details["run_id"])
        self.assertEqual(len(run["evidence_ids"]), 1)
        self.assertEqual(run["checkpoints"][0]["failed_phase"], "assertion")

    def test_all_concurrent_failures_keep_attempt_checkpoints(self):
        args = {"scenario": {"steps": [self.step(concurrent=3)]}}
        with patch.object(engine, "request", side_effect=OSError("fixture transport error")):
            with self.assertRaises(EngineError) as caught:
                run_scenario(self.project, args)
        run = self.project.get("run", caught.exception.details["run_id"])
        self.assertEqual(run["checkpoints"][0]["failed_attempts"], 3)
        self.assertEqual(run["checkpoints"][0]["failure_reasons"], {"capture_failed": 3})
        self.assertEqual(len(run["checkpoints"][0]["attempt_run_ids"]), 3)

    def test_uncertain_scenario_is_not_replayed(self):
        args = {"idempotency_key": "fixture-key", "scenario": {"steps": [self.step(assertions=[{"selector": "/ok", "equals": False}])]}}
        with patch.object(engine, "request", side_effect=observation) as network:
            with self.assertRaises(EngineError):
                run_scenario(self.project, args)
            with self.assertRaises(EngineError) as caught:
                run_scenario(self.project, args)
        self.assertEqual(network.call_count, 1)
        self.assertEqual(caught.exception.code, "scenario_uncertain")
        self.assertEqual(caught.exception.details["requests_replayed"], 0)


if __name__ == "__main__":
    unittest.main()
