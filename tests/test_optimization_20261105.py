import base64
import tempfile
import unittest

from awa_ddd import engine
from awa_ddd.store import Project, EngineError
from awa_ddd import workflow
from awa_ddd.batch import assessment_batch
from awa_ddd import browser
from awa_ddd.assessment import _json_oracle_result
from awa_ddd.reporting_legacy import _executive_markdown, build_report
from awa_ddd.oracle_contracts import ORACLES


class OptimizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-opt-")
        self.addCleanup(self.tmp.cleanup)
        engine.create_project(self.tmp.name, {
            "project_id": "opt",
            "target": "http://127.0.0.1:8081/",
            "coverage_policy": "subject",
        })
        self.project = Project(self.tmp.name, "opt")
        self.addCleanup(self.project.close)

    def test_subject_policy_collapses_duplicate_actors(self):
        operation = engine.register_operation(self.project, {
            "url": "http://127.0.0.1:8081/api/items",
            "method": "GET",
            "auth": "authenticated",
        })
        for actor_id, subject, roles, tenant in (
            ("alice", "alice", ["user"], "shop"),
            ("alice-r0", "alice", [], ""),
            ("bob", "bob", ["user"], "shop"),
        ):
            engine.add_actor(self.project, {"actor_id": actor_id, "subject": subject,
                                             "roles": roles, "tenant_id": tenant})
        engine.build_plan(self.project)
        baselines = [item for item in self.project.list("obligation")
                     if item.get("operation_id") == operation["id"]
                     and item.get("kind") == "baseline" and not item.get("superseded")]
        self.assertEqual(2, len(baselines))
        actor_ids = {item.get("actor_id") for item in baselines}
        self.assertEqual({"alice", "bob"}, actor_ids)

    def test_legacy_policy_keeps_each_actor(self):
        engine.create_project(self.tmp.name, {
            "project_id": "legacy", "target": "http://127.0.0.1:8081/",
            "coverage_policy": "legacy"})
        project = Project(self.tmp.name, "legacy")
        self.addCleanup(project.close)
        operation = engine.register_operation(project, {
            "url": "http://127.0.0.1:8081/api/items", "method": "GET", "auth": "authenticated"})
        for actor_id, subject in (("alice", "alice"), ("alice-r0", "alice"), ("bob", "bob")):
            engine.add_actor(project, {"actor_id": actor_id, "subject": subject, "roles": ["user"]})
        engine.build_plan(project)
        baselines = [item for item in project.list("obligation")
                     if item.get("operation_id") == operation["id"]
                     and item.get("kind") == "baseline" and not item.get("superseded")]
        self.assertEqual(3, len(baselines))

    def test_project_update_coverage_policy(self):
        result = engine.update_project(self.project, {"coverage_policy": "legacy"})
        self.assertTrue(result["changed"])
        self.assertEqual("legacy", self.project.config["coverage_policy"])
        with self.assertRaises(EngineError):
            engine.update_project(self.project, {"coverage_policy": "unknown"})

    def test_plan_next_compact_is_smaller_and_bounded(self):
        engine.register_operation(self.project, {
            "url": "http://127.0.0.1:8081/api/items", "method": "GET", "auth": "authenticated",
            "inputs": [{"name": "q", "location": "query", "selector": "q",
                        "consumer": "product_search", "test_families": ["sql_injection"]}]})
        engine.build_plan(self.project)
        compact = workflow.next_work(self.project, {"limit": 5, "compact": True})
        full = workflow.next_work(self.project, {"limit": 5})
        self.assertTrue(compact["compact"])
        self.assertNotIn("security_coverage", compact)
        self.assertLess(len(str(compact)), len(str(full)))
        self.assertLessEqual(len(compact["work_items"]), 5)

    def test_plan_why_returns_offline_diagnosis(self):
        engine.register_operation(self.project, {
            "url": "http://127.0.0.1:8081/api/items", "method": "GET", "auth": "public"})
        engine.build_plan(self.project)
        obligation = next(item for item in self.project.list("obligation")
                          if item.get("kind") == "baseline" and not item.get("superseded"))
        explanation = workflow.explain_obligation(self.project, {"obligation_id": obligation["id"]})
        self.assertEqual(obligation["id"], explanation["obligation_id"])
        self.assertEqual(0, explanation["requests_sent"])
        self.assertIn("next_action", explanation)

    def test_assessment_batch_continues_after_item_error(self):
        calls = []

        def fake_evaluate(project, item):
            calls.append(item["obligation_id"])
            if item["obligation_id"] == "bad":
                raise EngineError("bad_item", "synthetic failure")
            return {"id": "D-1", "outcome": "confirmed", "mode": "machine"}

        result = assessment_batch(None, {"items": [
            {"obligation_id": "good", "evidence_ids": ["E-1"], "oracle": {"type": "baseline"}},
            {"obligation_id": "bad", "evidence_ids": ["E-2"], "oracle": {"type": "baseline"}},
            {"obligation_id": "good2", "evidence_ids": ["E-3"], "oracle": {"type": "baseline"}},
        ]}, evaluate_fn=fake_evaluate, recover_fn=lambda *_: {"next_action": "action.help"})
        self.assertEqual(["good", "bad", "good2"], calls)
        self.assertEqual(2, result["evaluated"])
        self.assertEqual(1, result["failed"])
        self.assertEqual("bad_item", result["results"][1]["error_code"])

    def test_browser_actions_accept_action_alias_and_text(self):
        actions = browser._actions({"actions": [
            {"action": "fill", "selector": "#q", "text": "hello"},
            {"type": "wait", "ms": 10},
            {"type": "waitForDialog", "timeout": 1000},
            {"type": "waitForURL", "value": "/dashboard"},
        ]})
        self.assertEqual("fill", actions[0]["type"])
        self.assertEqual("hello", actions[0]["value"])
        self.assertEqual("wait", actions[1]["type"])
        self.assertEqual("waitForDialog", actions[2]["type"])
        self.assertEqual("waitForURL", actions[3]["type"])

    def test_raw_baseline_matches_non_json_body(self):
        body = b"var config = {version: '1.0'};"
        observation = ({}, {"response": {"status": 200,
                                         "body_base64": base64.b64encode(body).decode("ascii")}})
        outcome, _ = _json_oracle_result(None, {"kind": "baseline", "actor_id": None}, None,
                                         [observation], {"type": "baseline", "selector": "@raw",
                                                         "expected_text": body.decode("utf-8")})
        self.assertEqual("refuted", outcome)

    def test_executive_markdown_is_compact_and_decision_oriented(self):
        markdown = _executive_markdown({
            "project_id": "opt", "generated_at": "2026-11-05T00:00:00Z", "stage": "draft",
            "scope": {"target": "http://127.0.0.1:8081/"},
            "finding_groups": {"by_severity": [{"severity": "high", "count": 1, "findings": [
                {"title": "Synthetic finding", "category": "test"}]}]},
            "completion": {"status": "partial"}, "continuation": {"ready_total": 1, "review_total": 2,
                                                                   "blocked_total": 3},
            "coverage": {"evaluated": 1, "total": 2},
        })
        self.assertIn("风险总览", markdown)
        self.assertIn("Synthetic finding", markdown)
        self.assertLess(len(markdown), 2000)

    def test_report_build_rejects_unknown_profile_before_work(self):
        with self.assertRaises(EngineError):
            build_report(self.project, profile="unknown")

    def test_sql_boolean_oracle_is_discoverable(self):
        self.assertIn("sql_boolean", ORACLES)
        self.assertEqual("input_test", ORACLES["sql_boolean"]["obligation_kinds"][0])


if __name__ == "__main__":
    unittest.main()
