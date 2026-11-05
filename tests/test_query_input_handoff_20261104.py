"""Query discovery fills missing inputs without inventing or erasing branches."""
from __future__ import annotations

from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from awa_ddd import engine
from awa_ddd.__main__ import dispatch
from awa_ddd.assessment import evaluate
from awa_ddd.store import EngineError
import test_continuation_20261030 as fixtures


class QueryInputHandoffTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ContinuationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.project = self.fixture.project

    def state(self):
        return {table: [tuple(row) for row in self.project.connection.execute("SELECT * FROM " + table + " ORDER BY 1,2")]
                for table in ("entities", "events", "metadata")}

    def call(self, action, **args):
        return dispatch(self.project.workspace, action, {"project_id": self.project.project_id, **args})

    def register(self, path, inputs):
        operation = engine.register_operation(self.project, {"url": self.fixture.base + path,
            "method": "GET", "auth": "public", "inputs": inputs})
        engine.build_plan(self.project)
        return operation

    def active(self, operation, kind=None):
        return [item for item in self.project.list("obligation") if item["operation_id"] == operation["id"]
                and not item.get("superseded") and (kind is None or item["kind"] == kind)]

    def test_query_value_does_not_add_a_null_branch_to_a_declared_default(self):
        with patch.object(engine, "request") as network:
            operation = self.register("/import?confirm=true", [
                {"name": "confirmation flag", "location": "query", "selector": "confirm", "schema_branch": "default"}])
        network.assert_not_called()
        self.assertEqual([("query", "confirm", "default")],
                         [(item["location"], item["selector"], item.get("schema_branch")) for item in operation["inputs"]])
        self.assertEqual(1, len(self.active(operation, "input_review")))
        again = self.register("/import?confirm=false", operation["inputs"])
        self.assertEqual(operation["inputs"], again["inputs"])
        self.assertEqual(1, len(self.active(operation, "input_review")))

    def test_multiple_declared_branches_do_not_gain_an_unattributed_query_branch(self):
        operation = self.register("/branched?confirm=true", [
            {"name": "confirm", "location": "query", "schema_branch": branch}
            for branch in ("default", "oneOf/1", "")])
        self.assertEqual({"default", "oneOf/1", ""}, {item.get("schema_branch") for item in operation["inputs"]})
        self.assertEqual(3, len(self.active(operation, "input_review")))
        self.assertEqual(3, len({item["id"] for item in self.active(operation, "input_review")}))

    def test_url_still_discovers_an_undeclared_query_input_with_other_locations(self):
        operation = self.register("/discovered?confirm=true", [
            {"name": "confirm", "location": "header", "schema_branch": "default"}])
        self.assertEqual({("header", "default"), ("query", None)},
                         {(item["location"], item.get("schema_branch")) for item in operation["inputs"]})

    def test_legacy_null_default_pair_has_executable_exact_templates_and_keeps_both_histories(self):
        operation = self.register("/legacy?confirm=QUERY-PRIVATE-CONFIRM-20261104", [
            {"name": "confirm", "location": "query", "schema_branch": branch}
            for branch in (None, "default")])
        original = {item.get("schema_branch"): deepcopy(item) for item in self.active(operation, "input_review")}
        before = self.state()
        with patch.object(engine, "request") as network:
            queued = self.call("plan.next", limit=25, parameter_limit=100)
            rows = [row for row in queued["work_items"] if row["operation_id"] == operation["id"]
                    and row["obligation_kind"] == "input_review"]
            prepared = [self.call("assessment.prepare", obligation_id=row["obligation_id"])["items"][0] for row in rows]
        network.assert_not_called()
        self.assertEqual(before, self.state())
        self.assertEqual({None, "default"}, {row["input_template"]["schema_branch"] for row in rows})
        self.assertNotIn("QUERY-PRIVATE-CONFIRM-20261104", json.dumps([queued, prepared]))
        for row, preparation in zip(rows, prepared):
            self.assertEqual(row["input_template"], preparation["input_template"])
        null_row = next(row for row in rows if row["input_template"]["schema_branch"] is None)
        self.call(null_row["suggested_action"], **null_row["input_template"],
                  consumer="import_confirmation", test_families=["business_logic"])
        current = self.project.get("operation", operation["id"])
        self.assertEqual("unknown", next(item for item in current["inputs"] if item.get("schema_branch") == "default")["consumer"])
        self.assertEqual(original["default"], self.project.get("obligation", original["default"]["id"]))
        self.assertTrue(self.project.get("obligation", original[None]["id"])["superseded"])
        self.assertEqual({None}, {item.get("schema_branch") for item in self.active(operation, "input_test")})
        default_row = next(row for row in rows if row["input_template"]["schema_branch"] == "default")
        self.call(default_row["suggested_action"], **default_row["input_template"],
                  consumer="import_confirmation", test_families=["business_logic"])
        self.assertEqual({None, "default"}, {item.get("schema_branch") for item in self.active(operation, "input_test")})
        self.assertTrue(all(item["status"] == "open" for item in self.active(operation)))
        for item in original.values():
            self.assertTrue(self.project.get("obligation", item["id"])["superseded"])
            self.assertEqual(item["input_signature"], self.project.get("obligation", item["id"])["input_signature"])

    def test_reregistration_and_other_branch_declaration_preserve_accepted_decision_lineage(self):
        operation = self.register("/accepted?confirm=true", [
            {"name": "confirm", "location": "query", "schema_branch": "default", "consumer": "business_input",
             "test_families": ["generic"]},
            {"name": "confirm", "location": "query", "schema_branch": None}])
        obligation = self.active(operation, "input_test")[0]
        controls = [self.fixture.capture(operation=operation, url=operation["url"] + "?confirm=" + value,
                                        response={"count": count})
                    for value, count in (("normal", 1), ("variant", 1), ("sensitive", 2))]
        decision = evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": [item["id"] for item in controls],
            "oracle": {"type": "semantic_negative", "test_family": "generic", "selector": "/count",
                       "baseline_expected": 1, "control_expected": 2}})
        saved_decision = deepcopy(self.project.get("decision", decision["id"]))
        saved_evidence = {item["id"]: deepcopy(self.project.get("evidence", item["id"])) for item in controls}
        saved_obligation = deepcopy(self.project.get("obligation", obligation["id"]))
        again = self.register("/accepted?confirm=false", [operation["inputs"][0]])
        self.assertEqual({None, "default"}, {item.get("schema_branch") for item in again["inputs"]})
        self.call("surface.declare_consumer", operation_id=operation["id"], input_location="query", input_selector="confirm",
                  schema_branch=None, consumer="import_confirmation", test_families=["business_logic"])
        self.assertEqual(saved_decision, self.project.get("decision", decision["id"]))
        self.assertEqual(saved_obligation, self.project.get("obligation", obligation["id"]))
        for identity, evidence in saved_evidence.items():
            self.assertEqual(evidence, self.project.get("evidence", identity))
        engine._decision_valid(self.project, saved_decision)
        coverage = engine.evaluate_coverage(self.project)
        self.assertNotIn(obligation["id"], {row["id"] for row in coverage["gaps"]})
        matrix = self.call("plan.audit", parameter_limit=100)["parameter_coverage"]["items"]
        default = next(row for row in matrix if row["operation_id"] == operation["id"] and row["schema_branch"] == "default")
        null = next(row for row in matrix if row["operation_id"] == operation["id"] and row["schema_branch"] is None)
        self.assertTrue(default["typed_tested"])
        self.assertEqual(saved_decision["id"], default["decision_id"])
        self.assertFalse(null["typed_tested"])
        self.assertNotIn("decision_id", null)

    def test_ambiguous_missing_or_malformed_branch_selection_fails_before_mutation(self):
        operation = self.register("/selection", [
            {"name": "confirm", "location": "query", "schema_branch": branch} for branch in (None, "default", "alternate")])
        args = {"operation_id": operation["id"], "input_location": "query", "input_selector": "confirm", "consumer": "import_confirmation"}
        invalid = [{}, {"schema_branch": "missing"}]
        invalid += [{"schema_branch": value} for value in (False, 0, [], {})]
        invalid += [{"input_selector": value} for value in (None, False, 3, [], " ")]
        invalid += [{"input_location": value} for value in (None, False, [], "QUERY")]
        invalid += [{"consumer": value} for value in (None, False, 3, [], {}, " ")]
        for override in invalid:
            with self.subTest(override=override):
                before = self.state()
                with patch.object(engine, "request") as network, self.assertRaises(EngineError):
                    engine.declare_consumer(self.project, {**args, **override})
                network.assert_not_called()
                self.assertEqual(before, self.state())

    def test_consumer_declaration_can_select_an_explicit_json_root(self):
        operation = engine.register_operation(self.project, {"url": self.fixture.base + "/json-root",
            "method": "POST", "auth": "public", "content_type": "application/json",
            "inputs": [{"name": "document", "location": "body", "selector": "", "schema_branch": None}]})
        engine.build_plan(self.project)
        result = self.call("surface.declare_consumer", operation_id=operation["id"], input_location="body", input_selector="",
                           schema_branch=None, consumer="json_document", test_families=["generic"])
        self.assertEqual("", result["input"]["selector"])
        self.assertEqual("json_document", result["input"]["consumer"])


if __name__ == "__main__":
    unittest.main()
