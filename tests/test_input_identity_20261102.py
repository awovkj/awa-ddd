"""Exact-input identities fail before mutation, planning or target dispatch."""
from __future__ import annotations

from copy import deepcopy
import unittest
from unittest.mock import patch

import test_continuation_20261030 as fixtures
from awa_ddd import engine
from awa_ddd.__main__ import dispatch
from awa_ddd.store import EngineError


class InputIdentityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ContinuationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.project, self.root = self.fixture.project, self.fixture.root

    def state(self):
        return {table: [tuple(row) for row in self.project.connection.execute("SELECT * FROM " + table + " ORDER BY 1,2")]
                for table in ("entities", "events", "metadata")}

    def test_bad_declared_identity_is_rejected_without_partial_registration(self):
        entries = [{"name": "q", "location": "query", "selector": value}
                   for value in (None, 23, True, [], {}, "", " ")]
        entries.extend({"name": "q", "location": "query", "schema_branch": value}
                       for value in (23, True, [], {}))
        entries.extend(({"name": "", "location": "query"}, {"name": " ", "location": "query"},
                        {"name": "q", "location": []}))
        for entry in entries:
            with self.subTest(entry=entry):
                before = self.state()
                with patch.object(engine, "request") as network, self.assertRaises(EngineError):
                    dispatch(self.root, "surface.register", {"project_id": "continuation",
                        "url": self.fixture.base + "/new-input", "method": "GET", "auth": "public", "inputs": [entry]})
                network.assert_not_called()
                self.assertEqual(before, self.state())

    def test_non_array_inputs_are_rejected_atomically(self):
        for entries in (None, {}, "q", 23, True):
            with self.subTest(entries=entries):
                before = self.state()
                with self.assertRaises(EngineError) as caught:
                    engine.register_operation(self.project, {"url": self.fixture.base + "/invalid-array",
                        "method": "GET", "inputs": entries})
                self.assertEqual("input", caught.exception.code)
                self.assertEqual(before, self.state())

    def test_omitted_selector_defaults_to_name_and_null_branch_is_supported(self):
        operation = engine.register_operation(self.project, {"url": self.fixture.base + "/valid-input",
            "method": "GET", "auth": "public", "inputs": [{"name": "q", "location": "query", "schema_branch": None}]})
        self.assertEqual("q", operation["inputs"][0]["selector"])
        engine.build_plan(self.project)
        matrix = dispatch(self.root, "plan.audit", {"project_id": "continuation"})["parameter_coverage"]
        row = next(row for row in matrix["items"] if row["operation_id"] == operation["id"])
        self.assertEqual("q", row["input_selector"])
        self.assertIsNone(row.get("schema_branch"))

    def test_explicit_json_root_selector_remains_supported(self):
        for selector in ("", "$"):
            with self.subTest(selector=selector):
                operation = engine.register_operation(self.project, {"url": self.fixture.base + "/json-root-" + str(len(selector)),
                    "method": "POST", "auth": "public", "content_type": "application/json",
                    "inputs": [{"name": "document", "location": "body", "selector": selector}]})
                engine.build_plan(self.project)
                engine.evaluate_coverage(self.project)
                self.assertEqual(selector, operation["inputs"][0]["selector"])

    def test_empty_openapi_branch_is_a_valid_exact_legacy_string(self):
        operation = engine.register_operation(self.project, {"url": self.fixture.base + "/empty-branch",
            "method": "GET", "auth": "public", "inputs": [{"name": "q", "location": "query", "schema_branch": ""}]})
        engine.build_plan(self.project)
        engine.evaluate_coverage(self.project)
        self.assertEqual("", operation["inputs"][0]["schema_branch"])

    def test_corrupt_legacy_identity_fails_closed_in_plan_audit_and_preflight(self):
        original = deepcopy(self.fixture.operation)
        for field, value in (("selector", None), ("selector", []), ("selector", 23), ("schema_branch", {})):
            with self.subTest(field=field, value=value):
                changed = deepcopy(original)
                changed["inputs"][0][field] = value
                self.project.put("operation", changed)
                before = self.state()
                for invoke in (lambda: engine.build_plan(self.project),
                               lambda: engine.evaluate_coverage(self.project),
                               lambda: engine.preflight_capture(self.project, {"operation_id": changed["id"]})):
                    with patch.object(engine, "request") as network, self.assertRaises(EngineError) as caught:
                        invoke()
                    network.assert_not_called()
                    self.assertEqual(changed["id"], caught.exception.details["operation_id"])
                    self.assertEqual("surface.inspect", caught.exception.details["next_action"])
                    self.assertEqual(before, self.state())
                self.project.put("operation", original)

    def test_invalid_source_inspection_is_readable_but_never_borrows_saved_coverage(self):
        self.fixture.close_generic()
        original = deepcopy(self.fixture.operation)
        for entries in ([{**original["inputs"][0], "selector": None}], [23], {"invalid": "declaration"}):
            with self.subTest(entries=entries):
                self.project.put("operation", {**original, "inputs": entries})
                before = self.state()
                with patch.object(engine, "request") as network:
                    result = dispatch(self.root, "surface.inspect", {"project_id": "continuation", "operation_id": original["id"]})
                network.assert_not_called()
                self.assertTrue(result["inspection_limited"])
                self.assertEqual(original["id"], result["input_identity_error"]["operation_id"])
                self.assertEqual("action.help", result["next_action"])
                self.assertEqual({"name": "surface.register"}, result["help_input"])
                self.assertTrue(all(row["status"] == "open" and row["reason_code"] == "input_identity_invalid"
                                    for row in result["obligations"]))
                if not isinstance(entries, list):
                    self.assertIsNone(result["input_total"])
                    self.assertIsNone(result["operation"]["input_count"])
                self.assertEqual(before, self.state())
                self.project.put("operation", original)

    def test_an_unrelated_bad_identity_does_not_block_safe_declaration_inspection(self):
        self.fixture.close_generic()
        other = engine.register_operation(self.project, {"url": self.fixture.base + "/damaged-source",
            "method": "GET", "auth": "public", "inputs": [{"name": "q", "location": "query"}]})
        engine.build_plan(self.project)
        changed = deepcopy(other)
        changed["inputs"][0]["schema_branch"] = {}
        self.project.put("operation", changed)
        before = self.state()
        result = dispatch(self.root, "surface.inspect", {"project_id": "continuation", "operation_id": self.fixture.operation["id"]})
        self.assertTrue(result["inspection_limited"])
        self.assertEqual(other["id"], result["input_identity_error"]["operation_id"])
        self.assertTrue(all(row["status"] == "open" for row in result["obligations"]))
        self.assertEqual(before, self.state())


if __name__ == "__main__":
    unittest.main()
