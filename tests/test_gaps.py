"""Gap projection: one stable identity and reason code shared by plan, gates and report."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from awa_ddd import engine
from awa_ddd.engine import GAP_ACTIONS, GAP_REASONS, _gap_id, evaluate_coverage
from awa_ddd.reporting import build_report, coverage
from awa_ddd.store import Project


class GapProjectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-gap-")
        self.addCleanup(self.tmp.cleanup)
        engine.create_project(self.tmp.name, {"project_id": "gap", "target": "http://127.0.0.1:9",
                                              "scope": ["http://127.0.0.1:9"]})
        self.project = Project(self.tmp.name, "gap")
        self.addCleanup(self.project.close)

    def _operation(self, auth="unknown", ownership=False, inputs=None, roles=None):
        hint = {"url": "http://127.0.0.1:9/api/orders", "method": "POST",
                "protocol": "http", "auth": auth, "ownership": ownership,
                "inputs": inputs or []}
        if roles:
            hint["allowed_roles"] = roles
        operation = engine.register_operation(self.project, hint)
        engine.build_plan(self.project)
        return operation

    def test_gap_id_is_stable_and_unique_per_obligation(self):
        self._operation(inputs=[{"name": "amount", "location": "body", "selector": "/amount"}])
        first = evaluate_coverage(self.project)["gaps"]
        second = evaluate_coverage(self.project)["gaps"]
        self.assertTrue(first)
        self.assertEqual([g["gap_id"] for g in first], [g["gap_id"] for g in second],
                         "repeated evaluation must not renumber gaps")
        identifiers = [g["gap_id"] for g in first]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        for gap in first:
            self.assertEqual("G-" + _gap_id({"id": gap["id"]})[2:], gap["gap_id"])

    def test_every_gap_carries_a_known_reason_code_and_action(self):
        self._operation(auth="restricted", ownership=True, roles=["user"],
                        inputs=[{"name": "amount", "location": "body", "selector": "/amount"}])
        for gap in evaluate_coverage(self.project)["gaps"]:
            self.assertIn(gap["reason_code"], GAP_REASONS)
            self.assertTrue(gap["next_action"])
            self.assertIn("reason", gap)
            self.assertIn("obligation_kind", gap)

    def test_setup_obligations_get_setup_actions_not_execution(self):
        # auth=unknown 才会产生 auth_review；未声明消费点的输入产生 input_review。
        self._operation(auth="unknown",
                        inputs=[{"name": "amount", "location": "body", "selector": "/amount"}])
        review = {gap["obligation_kind"]: gap for gap in evaluate_coverage(self.project)["gaps"]
                  if gap["reason_code"] == "not_started"}
        self.assertEqual("declare_access_policy", review["auth_review"]["next_action"])
        self.assertEqual("trace_consumer", review["input_review"]["next_action"])

    def test_ownership_without_resources_asks_for_a_test_resource(self):
        self._operation(auth="unknown", ownership=True)
        gaps = evaluate_coverage(self.project)["gaps"]
        setup = [gap for gap in gaps if gap["obligation_kind"] == "ownership_setup"]
        self.assertTrue(setup, "ownership without a registered resource must stay visible")
        self.assertEqual("create_test_resource", setup[0]["next_action"])

    def test_repair_actions_are_never_overridden_by_the_obligation_kind(self):
        # 一个 auth_review 义务即使求值后被判失效，也必须指向 repair_evidence，
        # 否则“怎么修”会被 kind 的动作掩盖。
        self._operation(auth="unknown")
        review = next((item for item in self.project.list("obligation")
                       if item["kind"] == "auth_review"), None)
        if review is None:
            self.skipTest("this fixture produced no auth_review obligation")
        self.project.put("obligation", dict(review, status="evaluated"))
        gap = {item["id"]: item for item in evaluate_coverage(self.project)["gaps"]}[review["id"]]
        self.assertEqual("repair_evidence", gap["next_action"])
        self.assertEqual("decision_missing", gap["reason_code"])

    def test_operator_reason_is_preserved_alongside_the_code(self):
        operation = self._operation()
        obligations = self.project.list("obligation")
        blocked = dict(obligations[0], status="blocked", reason="Missing a valid test actor")
        self.project.put("obligation", blocked)
        gaps = {gap["id"]: gap for gap in evaluate_coverage(self.project)["gaps"]}
        gap = gaps[blocked["id"]]
        self.assertEqual("blocked_precondition", gap["reason_code"])
        self.assertEqual("resolve_precondition", gap["next_action"])
        self.assertEqual("Missing a valid test actor", gap["operator_reason"])

    def test_gap_dependencies_are_aggregated(self):
        self._operation(auth="restricted", ownership=True, roles=["user"],
                        inputs=[{"name": "amount", "location": "body", "selector": "/amount"}])
        result = evaluate_coverage(self.project)
        self.assertIn("gap_dependencies", result)
        self.assertEqual(sum(result["gap_dependencies"].values()), len(result["gaps"]))

    def test_plan_report_and_gates_share_one_projection(self):
        self._operation(inputs=[{"name": "amount", "location": "body", "selector": "/amount"}])
        evaluated = evaluate_coverage(self.project)
        self.assertEqual(coverage(self.project)["gaps"], evaluated["gaps"],
                         "report.coverage must return the evaluator projection unchanged")
        summary = json.loads(Path(build_report(self.project)["summary"]).read_text(encoding="utf-8"))
        self.assertEqual(summary["coverage"]["gaps"], evaluated["gaps"])

    def test_invalid_evidence_reopens_with_a_repair_code(self):
        operation = self._operation()
        obligation = self.project.list("obligation")[0]
        # 断言一个已求值但缺少 decision 的义务：应回落为可修复的 gap，而不是消失。
        self.project.put("obligation", dict(obligation, status="evaluated"))
        gap = {item["id"]: item for item in evaluate_coverage(self.project)["gaps"]}.get(obligation["id"])
        self.assertIsNotNone(gap, "a broken evaluatd obligation must stay visible")
        self.assertEqual("open", gap["status"])
        self.assertEqual("decision_missing", gap["reason_code"])
        self.assertEqual("repair_evidence", gap["next_action"])

    def test_gaps_sort_deterministically(self):
        self._operation(auth="restricted", ownership=True, roles=["user"],
                        inputs=[{"name": "a", "location": "query", "selector": "a"},
                                {"name": "b", "location": "query", "selector": "b"}])
        first = [(g["operation_id"], g["obligation_kind"], g["gap_id"])
                 for g in evaluate_coverage(self.project)["gaps"]]
        self.assertEqual(first, sorted(first))


if __name__ == "__main__":
    unittest.main()
