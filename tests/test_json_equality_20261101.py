"""Typed JSON assertions and immutable legacy decision revalidation, offline."""
from __future__ import annotations

import base64
from copy import deepcopy
import math
import json
import unittest
from unittest.mock import patch

import test_continuation_20261030 as fixtures
import test_state_transition_20261030 as state_fixtures
from awa_ddd import assessment, browser, engine
from awa_ddd.__main__ import dispatch
from awa_ddd.store import EngineError
from awa_ddd.transport import json_equal, has_business_state


class JsonEqualityTests(unittest.TestCase):
    def test_boolean_and_numeric_values_are_distinct_in_both_directions(self):
        for left, right in ((True, 1), (False, 0), (True, 1.0), (False, -0.0)):
            with self.subTest(left=left, right=right):
                self.assertFalse(json_equal(left, right))
                self.assertFalse(json_equal(right, left))
        self.assertTrue(json_equal(True, True))
        self.assertTrue(json_equal(False, False))

    def test_finite_numeric_value_equivalence_preserves_zero_and_precision(self):
        for left, right in ((1, 1.0), (0, -0.0), (12, 12.0), (2**53, float(2**53))):
            with self.subTest(left=left, right=right):
                self.assertTrue(json_equal(left, right))
                self.assertTrue(json_equal(right, left))
        self.assertFalse(json_equal(2**53 + 1, float(2**53 + 1)))
        self.assertFalse(json_equal(1, 1.5))
        self.assertTrue(json_equal(2**1024, 2**1024))

    def test_recursive_arrays_and_objects_keep_value_types_and_exact_keys(self):
        self.assertTrue(json_equal({"rows": [{"balance": 0, "enabled": False}]},
                                   {"rows": [{"enabled": False, "balance": 0.0}]}))
        self.assertFalse(json_equal({"rows": [{"balance": 0, "enabled": False}]},
                                    {"rows": [{"balance": False, "enabled": 0}]}))
        self.assertFalse(json_equal([1, 2], [1]))
        self.assertFalse(json_equal([1, 2], [2, 1]))
        self.assertFalse(json_equal({"1": "value"}, {1: "value"}))
        self.assertFalse(json_equal({"value": 1}, {"other": 1}))
        self.assertFalse(json_equal([1], {"0": 1}))

    def test_strings_null_and_empty_containers_do_not_coerce(self):
        for left, right in (("1", 1), ("true", True), ("null", None), ([], {}), ("", None)):
            with self.subTest(left=left, right=right):
                self.assertFalse(json_equal(left, right))
        self.assertTrue(json_equal(None, None))
        self.assertTrue(json_equal("normal", "normal"))
        self.assertTrue(json_equal([], []))
        self.assertTrue(json_equal({}, {}))

    def test_nonfinite_unsupported_or_invalid_unicode_values_fail_closed(self):
        class IntSubclass(int):
            pass

        for value in (math.nan, math.inf, -math.inf, b"value", (1,), {1}, object(), IntSubclass(1), "\ud800"):
            with self.subTest(value=repr(value)):
                self.assertFalse(json_equal(value, value))
                self.assertFalse(json_equal({"value": value}, {"value": value}))
        circular = []
        circular.append(circular)
        self.assertFalse(json_equal(circular, circular))

    def test_control_metadata_only_containers_are_not_business_state(self):
        for value in ({"ok": True, "status": 200}, [{"success": True}],
                      {"data": {"Status_Code": 200, "RequestId": "fixture"}},
                      {"payload": [{"result": {"ok": True}}]}, ["ok", "success"], "permission denied",
                      {"data": ["OK", "forbidden"]}, {}, [], None, ""):
            with self.subTest(value=value):
                self.assertFalse(has_business_state(value))
        self.assertTrue(has_business_state({"balance": 0, "enabled": False}))
        self.assertTrue(has_business_state({"data": [{"count": 0}, {"enabled": True}]}))
        self.assertTrue(has_business_state(0))
        self.assertTrue(has_business_state(False))
        self.assertTrue(has_business_state({"state": "paid", "balance": 0}))


class JsonDecisionEqualityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ContinuationTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.project = self.fixture.project

    def controls(self, normal, variant, sensitivity):
        return [self.fixture.capture(url=self.fixture.operation["url"] + "?q=" + name, response={"count": value})
                for name, value in zip(("normal", "variant", "sensitive"), (normal, variant, sensitivity))]

    def semantic(self, captures, normal, sensitivity):
        with patch.object(engine, "request") as network:
            result = dispatch(self.fixture.root, "assessment.evaluate", {
                "project_id": self.project.project_id, "obligation_id": self.fixture.obligation("input_test")["id"],
                "evidence_ids": [evidence["id"] for evidence in captures],
                "oracle": {"type": "semantic_negative", "test_family": "generic", "selector": "/count",
                           "baseline_expected": normal, "control_expected": sensitivity}})
        network.assert_not_called()
        return result

    def test_number_to_boolean_response_change_is_not_a_semantic_refutation(self):
        captures = self.controls(1, True, 2)
        result = self.semantic(captures, 1, 2)
        self.assertEqual("inconclusive", result["outcome"])
        self.assertEqual("open", self.project.get("obligation", result["obligation_id"])["status"])

    def test_nested_type_changes_are_not_unchanged_business_observables(self):
        normal, variant, sensitivity = {"values": [1, 0]}, {"values": [True, False]}, {"values": [2, 3]}
        result = self.semantic(self.controls(normal, variant, sensitivity), normal, sensitivity)
        self.assertEqual("inconclusive", result["outcome"])

    def test_numeric_equivalence_still_supports_a_bounded_typed_negative(self):
        result = self.semantic(self.controls(1.0, 1, 2.0), 1, 2)
        self.assertEqual("refuted", result["outcome"])
        with patch.object(engine, "request") as network:
            engine._decision_valid(self.project, self.project.get("decision", result["id"]))
        network.assert_not_called()

    def test_boolean_and_number_sensitivity_values_are_distinct_json_controls(self):
        result = self.semantic(self.controls(True, True, 1), True, 1)
        self.assertEqual("refuted", result["outcome"])
        self.assertEqual("evaluated", self.project.get("obligation", result["obligation_id"])["status"])

    def test_legacy_refuted_json_decision_is_reopened_without_rewriting_it(self):
        captures = self.controls(1, True, 2)
        # Mint through the real action, changing only the earlier value-equality
        # policy; records, capture hashes, bindings and events are engine-created.
        with patch.object(assessment, "json_equal", side_effect=lambda left, right: left == right):
            legacy = self.semantic(captures, 1, 2)
        self.assertEqual("refuted", legacy["outcome"])
        original = self.project.get("decision", legacy["id"])
        item = self.project.get("obligation", legacy["obligation_id"])
        with patch.object(engine, "request") as network:
            evaluated = engine.evaluate_coverage(self.project)
        network.assert_not_called()
        gap = next(row for row in evaluated["gaps"] if row["id"] == item["id"])
        self.assertEqual("open", gap["status"])
        self.assertEqual("evidence_invalid", gap["reason_code"])
        self.assertEqual(original, self.project.get("decision", legacy["id"]))
        self.assertEqual(item, self.project.get("obligation", item["id"]))

    def test_fresh_and_legacy_baseline_boolean_number_mismatches_cannot_close(self):
        evidence = self.fixture.capture(response={"count": True})
        args = {"project_id": self.project.project_id, "obligation_id": self.fixture.obligation("baseline")["id"],
                "evidence_ids": [evidence["id"]], "oracle": {"type": "baseline", "selector": "/count", "expected": 1}}
        current = dispatch(self.fixture.root, "assessment.evaluate", args)
        self.assertEqual("inconclusive", current["outcome"])
        with patch.object(assessment, "json_equal", side_effect=lambda left, right: left == right):
            legacy = dispatch(self.fixture.root, "assessment.evaluate", args)
        original = self.project.get("decision", legacy["id"])
        with self.assertRaises(EngineError) as caught:
            engine._decision_valid(self.project, original)
        self.assertEqual("json_assertion", caught.exception.code)
        self.assertEqual(original, self.project.get("decision", legacy["id"]))

    def test_parse_failure_is_never_an_absent_negative_or_unchanged_value(self):
        normal = self.fixture.capture(url=self.fixture.operation["url"] + "?q=normal", response={"count": 1})
        variant = self.fixture.capture(url=self.fixture.operation["url"] + "?q=variant", response={"count": 1})
        raw = b'{"count":2,"count":1}'

        def observation(*values):
            artifact = fixtures.observation(*values, {"count": 2})
            artifact["response"].update(length=len(raw), body_base64=base64.b64encode(raw).decode("ascii"))
            return artifact

        with patch.object(engine, "request", side_effect=observation):
            sensitivity = engine.capture(self.project, {"operation_id": self.fixture.operation["id"],
                                         "url": self.fixture.operation["url"] + "?q=sensitive"})
        before = self.project.list("decision")
        with self.assertRaises(EngineError) as caught:
            self.semantic([normal, variant, sensitivity], 1, 2)
        self.assertEqual("response_json", caught.exception.code)
        self.assertEqual(before, self.project.list("decision"))

    def test_invalid_oracle_discriminator_returns_a_structured_error_before_effects(self):
        evidence = self.fixture.capture()
        for kind in (None, [], {}, True, 1):
            with self.subTest(kind=kind):
                before = self.project.list("decision")
                with self.assertRaises(EngineError) as caught:
                    dispatch(self.fixture.root, "assessment.evaluate", {
                        "project_id": self.project.project_id, "obligation_id": self.fixture.obligation("baseline")["id"],
                        "evidence_ids": [evidence["id"]], "oracle": {"type": kind}})
                self.assertEqual("unsupported_oracle", caught.exception.code)
                self.assertEqual(before, self.project.list("decision"))

    def test_unselected_json_boolean_number_change_is_a_confounder(self):
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice", "roles": []})
        operation = self.fixture.register("/json-controls", method="POST", content_type="application/json", inputs=[
            {"name": "id", "location": "body", "selector": "/id", "consumer": "resource_reference"},
            {"name": "q", "location": "body", "selector": "/q", "consumer": "business_input", "test_families": ["generic"]}])
        resource = engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": "alice",
            "external_id": "7", "request_binding": {"location": "body", "selector": "/id"}})
        captures = [self.fixture.capture(operation, resource_id=resource["id"], effect="test_resource_write",
                    body=json.dumps({"id": "7", "q": name, "other": other}),
                    headers={"Content-Type": "application/json"}, response={"count": result})
                    for name, other, result in (("normal", 1, 1), ("variant", True, 1), ("sensitive", 1, 2))]
        item = next(row for row in self.project.list("obligation") if row["operation_id"] == operation["id"]
                    and row.get("input_selector") == "/q" and row.get("kind") == "input_test")
        args = {"project_id": self.project.project_id, "obligation_id": item["id"],
                "evidence_ids": [row["id"] for row in captures],
                "oracle": {"type": "semantic_negative", "test_family": "generic", "selector": "/count",
                           "baseline_expected": 1, "control_expected": 2}}
        with self.assertRaises(EngineError) as caught:
            dispatch(self.fixture.root, "assessment.evaluate", args)
        self.assertEqual("input_binding", caught.exception.code)
        with patch.object(assessment, "_input_context_equal", side_effect=lambda left, right: left == right):
            legacy = dispatch(self.fixture.root, "assessment.evaluate", args)
        original = self.project.get("decision", legacy["id"])
        with self.assertRaises(EngineError) as caught:
            engine._decision_valid(self.project, original)
        self.assertEqual("input_binding", caught.exception.code)
        self.assertEqual(original, self.project.get("decision", original["id"]))

    def test_identity_boolean_subject_cannot_verify_a_numeric_actor(self):
        actor = engine.add_actor(self.project, {"actor_id": "numeric-subject", "subject": 1, "roles": []})
        session = engine.add_session(self.project, {"actor_id": actor["id"], "headers": {"Cookie": "fixture-subject=one"}})
        operation = self.fixture.register("/typed-identity", auth="authenticated")
        with patch.object(engine, "request", side_effect=lambda *values: fixtures.observation(*values, {"subject": True})):
            with self.assertRaises(EngineError) as caught:
                dispatch(self.fixture.root, "identity.verify", {"project_id": self.project.project_id,
                    "operation_id": operation["id"], "session_id": session["id"], "subject_selector": "/subject"})
        self.assertEqual("identity_assertion", caught.exception.code)
        stored = self.project.get("session", session["id"])
        self.assertIsNone(stored["verified_at"])
        self.assertIsNone(stored["verification_evidence_id"])

    def test_scenario_json_assertion_does_not_coerce_boolean_and_number(self):
        for actual, expected in ((1, True), (False, 0), ({"values": [1]}, {"values": [True]})):
            with self.subTest(actual=actual, expected=expected):
                args = {"project_id": self.project.project_id, "scenario": {"steps": [{
                    "id": "read", "operation_id": self.fixture.operation["id"],
                    "url": self.fixture.operation["url"] + "?q=normal",
                    "assertions": [{"selector": "/count", "equals": expected}]}]}}
                with patch.object(engine, "request", side_effect=lambda *values: fixtures.observation(*values, {"count": actual})):
                    with self.assertRaises(EngineError) as caught:
                        dispatch(self.fixture.root, "scenario.run", args)
                self.assertEqual("scenario_assertion", caught.exception.code)
                run = self.project.get("run", caught.exception.details["run_id"])
                self.assertEqual("failed", run["status"])
                self.assertEqual(1, len(run["evidence_ids"]))

    def test_scenario_numeric_value_equivalence_remains_a_successful_readonly_run(self):
        args = {"project_id": self.project.project_id, "scenario": {"steps": [{
            "id": "read", "operation_id": self.fixture.operation["id"],
            "url": self.fixture.operation["url"] + "?q=normal",
            "assertions": [{"selector": "/count", "equals": 1.0}]}]}}
        with patch.object(engine, "request", side_effect=lambda *values: fixtures.observation(*values, {"count": 1})):
            result = dispatch(self.fixture.root, "scenario.run", args)
        self.assertEqual("succeeded", result["status"])
        self.assertEqual(1, len(result["evidence_ids"]))

    def test_state_transition_numeric_acknowledgement_cannot_impersonate_boolean_success(self):
        fixture = state_fixtures.StateTransitionTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        fixture.write_success = 1
        run = fixture.scenario()
        self.assertEqual("succeeded", run["status"])
        with self.assertRaises(EngineError) as caught:
            fixture.decide(run)
        self.assertEqual("state_action_success", caught.exception.code)
        with patch.object(assessment, "json_equal", side_effect=lambda left, right: left == right):
            legacy = fixture.decide(run)
        original = fixture.project.get("decision", legacy["id"])
        with self.assertRaises(EngineError) as caught:
            engine._decision_valid(fixture.project, original)
        self.assertEqual("state_action_success", caught.exception.code)
        self.assertEqual(original, fixture.project.get("decision", original["id"]))

    def test_boolean_resource_id_does_not_alias_an_opaque_string_id(self):
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice", "roles": []})
        operation = self.fixture.register("/typed-fixture-id", method="POST", content_type="application/json", inputs=[{
            "name": "id", "location": "body", "selector": "/id", "consumer": "resource_reference"}])
        for expected, actual in (("True", True), ("False", False)):
            with self.subTest(expected=expected, actual=actual):
                resource = engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": "alice",
                    "external_id": expected, "request_binding": {"location": "body", "selector": "/id"}})
                args = {"project_id": self.project.project_id, "operation_id": operation["id"],
                        "resource_id": resource["id"], "effect": "test_resource_write", "body": {"id": actual}}
                with patch.object(engine, "request") as network:
                    with self.assertRaises(EngineError) as caught:
                        dispatch(self.fixture.root, "http.preflight", args)
                    ready = dispatch(self.fixture.root, "http.preflight", {**args, "body": {"id": expected}})
                network.assert_not_called()
                self.assertEqual("resource_mismatch", caught.exception.code)
                self.assertTrue(ready["ready"])
                self.assertEqual(0, ready["requests_sent"])
        self.assertTrue(engine._same_binding_value(7, "7"))
        self.assertTrue(engine._same_binding_value("True", "True"))
        self.assertFalse(engine._same_binding_value(True, "True"))

    def test_invalid_disposition_text_is_rejected_before_any_database_change(self):
        item = self.fixture.obligation("baseline")
        for status, reason in (([], "valid text"), ({}, "valid text"), (True, "valid text"),
                               ("blocked", True), ("blocked", False), ("blocked", []),
                               ("blocked", {"note": "untrusted"}), ("blocked", " "), ("blocked", "x" * 4001)):
            with self.subTest(status=status, reason_type=type(reason).__name__):
                before = {table: [tuple(row) for row in self.project.connection.execute("SELECT * FROM " + table + " ORDER BY 1,2")]
                          for table in ("entities", "events", "metadata")}
                with patch.object(engine, "request") as network, self.assertRaises(EngineError) as caught:
                    dispatch(self.fixture.root, "plan.disposition", {"project_id": self.project.project_id,
                        "obligation_id": item["id"], "status": status, "reason": reason})
                network.assert_not_called()
                self.assertEqual("disposition", caught.exception.code)
                after = {table: [tuple(row) for row in self.project.connection.execute("SELECT * FROM " + table + " ORDER BY 1,2")]
                         for table in ("entities", "events", "metadata")}
                self.assertEqual(before, after)

    def test_legacy_malformed_reason_keeps_safe_readonly_reconciliation_and_private_history(self):
        item = self.fixture.obligation("baseline")
        for reason in (True, False, ["previous invalid caller prose"], {"note": "previous invalid caller prose"}, 7):
            with self.subTest(reason_type=type(reason).__name__):
                # This simulates previously persisted invalid text, not a
                # decision, source signature or authority to stop testing.
                legacy = {**item, "status": "blocked", "reason": reason}
                self.project.put("obligation", legacy)
                before = self.project.get("obligation", item["id"])
                with patch.object(engine, "request") as network:
                    audit = dispatch(self.fixture.root, "plan.audit", {"project_id": self.project.project_id, "limit": 100})
                    queue = dispatch(self.fixture.root, "plan.next", {"project_id": self.project.project_id, "limit": 25})
                    coverage = dispatch(self.fixture.root, "plan.list", {"project_id": self.project.project_id, "limit": 100})
                network.assert_not_called()
                row = next(row for row in queue["work_items"] if row["obligation_id"] == item["id"])
                self.assertEqual("review", row["queue_status"])
                gap = next(row for row in coverage["gaps"] if row["id"] == item["id"])
                self.assertTrue(gap["operator_reason_invalid_type"])
                self.assertNotIn("operator_reason", row)
                self.assertTrue(row["blocker_reconciliation_required"])
                self.assertEqual(before, self.project.get("obligation", item["id"]))
                self.assertTrue(audit["continuation"]["continue_required"])
                with patch.object(engine, "request") as network:
                    dispatch(self.fixture.root, "plan.disposition", {"project_id": self.project.project_id, **row["input_template"]})
                network.assert_not_called()
                event = self.project.connection.execute("SELECT document FROM events WHERE type='plan.disposition' ORDER BY seq DESC LIMIT 1").fetchone()
                saved = json.loads(event[0])
                self.assertEqual(reason, saved["previous"]["reason"])
                self.assertEqual("open", saved["current"]["status"])


if __name__ == "__main__":
    unittest.main()
