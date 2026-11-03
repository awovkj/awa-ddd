"""Exact-input planning coverage, bounded publication and safe preparation hints."""
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import completeness, engine, parameter_coverage, workflow
from awa_ddd.assessment import evaluate
from awa_ddd.store import EngineError, Project, now


def observation(url, method, headers, body, timeout, max_bytes, response):
    sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else b""
    raw = json.dumps(response).encode("utf-8")
    return {"request": {"url": url, "method": method, "headers": headers,
                        "body_base64": base64.b64encode(sent).decode("ascii")},
            "response": {"status": 200, "headers": [["content-type", "application/json"]],
                         "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
            "started_at": now(), "completed_at": now(), "complete": True}


class ParameterCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="awa-parameters-")
        self.addCleanup(self.temporary.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.temporary.name, {"project_id": "parameters", "target": self.base})
        self.project = Project(self.temporary.name, "parameters")
        self.addCleanup(self.project.close)

    def operation(self, path="/orders", **extra):
        operation = engine.register_operation(self.project, {"url": self.base + path,
            "method": "GET", "auth": "public", **extra})
        engine.build_plan(self.project)
        return operation

    def capture(self, operation, response=None, **extra):
        with patch.object(engine, "request", side_effect=lambda *args: observation(*args,
                {"count": 1} if response is None else response)):
            return engine.capture(self.project, {"operation_id": operation["id"], **extra})

    def matrix(self, **args):
        with patch.object(engine, "request") as network:
            result = completeness.audit(self.project, {"parameter_limit": 100, **args})
        network.assert_not_called()
        return result["parameter_coverage"]

    def row(self, rows, selector, family="generic"):
        return next(row for row in rows if row["input_selector"] == selector and row["test_family"] == family)

    def test_registration_and_carrying_other_fields_are_not_parameter_testing(self):
        operation = self.operation(inputs=[
            {"name": "keyword", "location": "query", "consumer": "business_input", "test_families": ["generic", "business_logic"]},
            {"name": "order_time", "location": "query", "consumer": "business_input", "test_families": ["business_logic"]},
            {"name": "shop_name", "location": "query", "consumer": "unknown", "test_families": ["xss"]},
        ])
        before = self.matrix()
        self.assertEqual(before["summary"]["parameter_total"], 3)
        self.assertEqual(before["summary"]["cell_total"], 4)
        self.assertEqual(before["summary"]["typed_tested_total"], 0)
        captures = [self.capture(operation, url=operation["url"] + "?keyword=" + value + "&order_time=old&shop_name=stable",
                                 response={"count": count})
                    for value, count in (("normal", 1), ("variant", 1), ("sensitive", 2))]
        items = self.matrix()["items"]
        keyword = self.row(items, "keyword")
        self.assertEqual(keyword["status"], "observed_unassessed")
        self.assertTrue(keyword["has_input_variant"])
        self.assertFalse(keyword["typed_tested"])
        time = self.row(items, "order_time", "business_logic")
        self.assertEqual(time["status"], "needs_controls")
        self.assertEqual(time["observation_count"], 3)
        self.assertFalse(time["has_input_variant"])
        self.assertEqual(self.row(items, "shop_name", "xss")["status"], "consumer_review")
        obligation = next(item for item in self.project.list("obligation") if item.get("input_selector") == "keyword"
                          and item.get("test_family") == "generic" and not item.get("superseded"))
        evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": [row["id"] for row in captures],
            "oracle": {"type": "semantic_negative", "test_family": "generic", "selector": "/count",
                       "baseline_expected": 1, "control_expected": 2}})
        items = self.matrix()["items"]
        self.assertTrue(self.row(items, "keyword")["typed_tested"])
        self.assertFalse(self.row(items, "keyword", "business_logic")["typed_tested"])
        self.assertFalse(self.row(items, "order_time", "business_logic")["typed_tested"])

    def test_other_input_changes_and_anonymous_cookie_changes_do_not_form_controls(self):
        operation = self.operation(inputs=[{"name": name, "location": "query", "consumer": "business_input", "test_families": ["generic"]}
                                           for name in ("q", "other")])
        for q, other, cookie in (("one", "stable", "fixture=a"), ("two", "changed", "fixture=a"),
                                 ("three", "stable", "fixture=b")):
            self.capture(operation, url=operation["url"] + "?q=" + q + "&other=" + other, anonymous_cookie=cookie)
        q = self.row(self.matrix()["items"], "q")
        self.assertEqual(q["observation_count"], 3)
        self.assertFalse(q["has_input_variant"])
        self.assertEqual(q["status"], "needs_controls")

    def test_repeated_capture_does_not_add_matrix_cells_or_coverage_progress(self):
        operation = self.operation(inputs=[{"name": "q", "location": "query", "consumer": "business_input", "test_families": ["generic"]}])
        self.capture(operation, url=operation["url"] + "?q=normal")
        first = parameter_coverage.progress(self.project, engine.evaluate_coverage(self.project))
        total = len(self.project.list("obligation"))
        for _ in range(3):
            self.capture(operation, url=operation["url"] + "?q=normal")
        second = parameter_coverage.progress(self.project, engine.evaluate_coverage(self.project))
        self.assertEqual(first, second)
        self.assertEqual(len(self.project.list("obligation")), total)
        self.assertEqual(self.matrix()["summary"]["cell_total"], 1)
        self.assertEqual(self.row(self.matrix()["items"], "q")["observation_count"], 4)

    def test_matrix_cursor_and_filter_are_independent_of_audit_and_queue_cursors(self):
        operation = self.operation(inputs=[{"name": "q" + str(index), "location": "query", "consumer": "business_input"}
                                           for index in range(27)])
        self.capture(operation, url=operation["url"] + "?q0=one")
        matrix = self.matrix(offset=999, limit=1, parameter_offset=10, parameter_limit=7, parameter_status="untested")
        self.assertEqual((matrix["offset"], matrix["limit"], matrix["total"], matrix["next_offset"]), (10, 7, 27, 17))
        self.assertEqual(len(matrix["items"]), 7)
        result = workflow.next_work(self.project, {"offset": 999, "limit": 1, "parameter_status": "needs_controls"})
        self.assertEqual(result["work_items"], [])
        self.assertEqual(result["parameter_coverage"]["total"], 1)
        self.assertEqual(result["parameter_coverage"]["items"][0]["input_selector"], "q0")
        for bad in ({"parameter_offset": True}, {"parameter_limit": 0}, {"parameter_limit": 101}, {"parameter_status": "not_vulnerable"}):
            with self.subTest(bad=bad), self.assertRaises(EngineError):
                self.matrix(**bad)

    def test_progress_exports_identity_keys_but_no_input_or_credential_digests(self):
        operation = self.operation(inputs=[{"name": "q", "location": "query", "consumer": "business_input", "test_families": ["generic"]}])
        for value in ("SYNTHETIC_LOW_ENTROPY_01", "SYNTHETIC_LOW_ENTROPY_02"):
            self.capture(operation, url=operation["url"] + "?q=" + value, anonymous_cookie="fixture=SYNTHETIC_PRIVATE_COOKIE")
        evaluated = engine.evaluate_coverage(self.project)
        snapshot = parameter_coverage.snapshot(self.project, evaluated)
        progress = parameter_coverage.progress(self.project, evaluated)
        self.assertEqual(progress["variant_keys"], [snapshot["items"][0]["id"]])
        public = json.dumps(self.matrix()) + json.dumps(progress)
        for secret in ("SYNTHETIC_LOW_ENTROPY", "SYNTHETIC_PRIVATE_COOKIE"):
            self.assertNotIn(secret, public)
        self.assertNotIn("groups", public)
        self.assertNotIn("value_digest", public)
        self.assertNotIn("context_digest", public)

    def test_changed_evidence_does_not_remain_observed_or_tested(self):
        operation = self.operation(inputs=[{"name": "q", "location": "query", "consumer": "business_input", "test_families": ["generic"]}])
        evidence = self.capture(operation, url=operation["url"] + "?q=normal")
        path = self.project.base / evidence["artifact_path"]
        path.write_text("{}", encoding="utf-8")
        row = self.row(self.matrix()["items"], "q")
        self.assertEqual(row["observation_count"], 0)
        self.assertFalse(row["typed_tested"])

    def test_missing_required_consumer_family_is_an_unplanned_untested_cell(self):
        operation = self.operation(inputs=[{"name": "q", "location": "query", "consumer": "sql_like",
                                           "test_families": ["generic"]}])
        captures = [self.capture(operation, url=operation["url"] + "?q=" + value, response={"count": count})
                    for value, count in (("normal", 1), ("variant", 1), ("sensitive", 2))]
        obligation = next(item for item in self.project.list("obligation") if item.get("test_family") == "generic"
                          and not item.get("superseded"))
        evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": [row["id"] for row in captures],
            "oracle": {"type": "semantic_negative", "test_family": "generic", "selector": "/count",
                       "baseline_expected": 1, "control_expected": 2}})
        matrix = self.matrix()
        self.assertEqual(matrix["summary"]["cell_total"], 2)
        self.assertEqual(matrix["summary"]["typed_tested_total"], 1)
        self.assertEqual(matrix["summary"]["untested_total"], 1)
        generic = self.row(matrix["items"], "q", "generic")
        sql = self.row(matrix["items"], "q", "sql_injection")
        self.assertTrue(generic["typed_tested"])
        self.assertFalse(sql["typed_tested"])
        self.assertEqual(sql["obligation_ids"], [])
        self.assertEqual(sql["queue_status"], "unplanned")
        self.assertEqual(sql["next_action"], "surface.declare_consumer")
        declared = engine.declare_consumer(self.project, {"operation_id": operation["id"], "input_location": "query",
            "input_selector": "q", "consumer": "sql_like", "test_families": ["generic", "sql_injection"]})
        self.assertIsNotNone(declared)
        reopened = self.row(self.matrix()["items"], "q", "sql_injection")
        self.assertEqual(reopened["id"], sql["id"])
        self.assertTrue(reopened["obligation_ids"])
        self.assertFalse(reopened["typed_tested"])

    def test_projection_byte_budget_never_invalidates_an_existing_typed_decision(self):
        operation = self.operation(inputs=[{"name": "q", "location": "query", "consumer": "business_input",
                                           "test_families": ["generic"]}])
        captures = [self.capture(operation, url=operation["url"] + "?q=" + value, response={"count": count})
                    for value, count in (("normal", 1), ("variant", 1), ("sensitive", 2))]
        obligation = next(item for item in self.project.list("obligation") if item.get("test_family") == "generic"
                          and not item.get("superseded"))
        decision = evaluate(self.project, {"obligation_id": obligation["id"], "evidence_ids": [row["id"] for row in captures],
            "oracle": {"type": "semantic_negative", "test_family": "generic", "selector": "/count",
                       "baseline_expected": 1, "control_expected": 2}})
        with patch.object(parameter_coverage, "MAX_INPUT_VIEW_BYTES", 0):
            row = self.row(self.matrix()["items"], "q")
        self.assertTrue(row["observations_limited"])
        self.assertEqual(row["observation_count"], 0)
        self.assertFalse(row["has_input_variant"])
        self.assertTrue(row["typed_tested"])
        self.assertEqual(row["decision_id"], decision["id"])
        self.assertEqual(row["status"], "tested")
        self.assertEqual(len(self.project.list("evidence")), 3)

    def test_queue_and_audit_reuse_one_inventory_without_cross_call_caching(self):
        operation = self.operation(inputs=[{"name": "q", "location": "query", "consumer": "business_input",
                                           "test_families": ["generic"]}])
        with patch.object(completeness, "_inventory", wraps=completeness._inventory) as builder:
            first = workflow.next_work(self.project, {})
        self.assertEqual(builder.call_count, 1)
        self.assertEqual(first["parameter_coverage"]["summary"]["observed_total"], 0)
        for value in ("normal", "variant"):
            self.capture(operation, url=operation["url"] + "?q=" + value)
        with patch.object(completeness, "_inventory", wraps=completeness._inventory) as builder:
            second = self.matrix()
        self.assertEqual(builder.call_count, 1)
        self.assertEqual(second["summary"]["variant_observed_total"], 1)
        self.assertIsNone(completeness._INVENTORY_RECEIVER.get())

    def test_coverage_first_prioritizes_never_varied_inputs_and_rotates_operations(self):
        first = self.operation("/many", inputs=[{"name": "q" + str(index), "location": "query", "consumer": "business_input"}
                                              for index in range(8)])
        second = self.operation("/other", inputs=[{"name": "q", "location": "query", "consumer": "business_input"}])
        for value in ("normal", "variant"):
            self.capture(first, url=first["url"] + "?q0=" + value)
        result = workflow.next_work(self.project, {"limit": 8})
        tests = [row for row in result["work_items"] if row["obligation_kind"] == "input_test"]
        self.assertEqual(result["queue_policy"], "coverage_first")
        self.assertEqual(result["queue_fairness"], "family_and_operation_round_robin")
        self.assertFalse(tests[0]["selected_input_variant_observed"])
        self.assertIn(second["id"], {row["operation_id"] for row in tests[:2]})
        self.assertFalse(any(row["input_selector"] == "q0" and row["operation_id"] == first["id"] for row in tests[:2]))
        self.assertTrue(any(row["input_selector"] == "q0" and row["operation_id"] == first["id"] for row in tests[:3]))

    def test_blocked_factor_work_has_concrete_safe_preparation_and_continuity_hints(self):
        operation = self.operation("/register", method="POST", content_type="application/json",
            inputs=[{"name": "sms_code", "location": "body", "selector": "/sms_code", "consumer": "business_input"}])
        before = len(self.project.list("evidence"))
        with patch.object(engine, "request") as network:
            result = workflow.next_work(self.project, {"include_blocked": True, "limit": 25})
        network.assert_not_called()
        item = next(row for row in result["work_items"] if row.get("input_selector") == "/sms_code")
        self.assertEqual(item["queue_status"], "blocked")
        self.assertIn("project_allow_mutation", item["missing_prerequisites"])
        self.assertTrue(item["preparation_actions"])
        self.assertTrue(all(row["automatic_execution_allowed"] is False for row in item["preparation_actions"]))
        self.assertEqual(item["session_continuity"]["anonymous_input_field"], "anonymous_cookie")
        self.assertFalse(item["session_continuity"]["automatic_cookie_forwarding"])
        parameter = result["parameter_coverage"]["items"][0]
        self.assertEqual(parameter["queue_status"], "blocked")
        self.assertEqual(parameter["missing_prerequisites"], item["missing_prerequisites"])
        self.assertEqual(before, len(self.project.list("evidence")))
        text = json.dumps(item)
        self.assertNotIn("/api/pay/", text)
        self.assertNotIn('"allow_mutation": true', text)


class ObservationProfileUnitTests(unittest.TestCase):
    def operation(self, entries):
        return {"id": "OP-unit", "url": "http://fixture.invalid/data", "method": "POST",
                "content_type": "application/json", "inputs": entries}

    def observe(self, profiles, value, index):
        profiles.observe({"id": "E-" + str(index), "operation_id": "OP-unit"},
            {"url": "http://fixture.invalid/data", "method": "POST", "headers": {"content-type": "application/json"},
             "body_base64": base64.b64encode(json.dumps({"q": value}).encode("utf-8")).decode("ascii")})

    def test_number_equivalence_is_not_a_variant_but_boolean_change_is(self):
        entry = {"name": "q", "location": "body", "selector": "/q"}
        profiles = parameter_coverage.ObservationProfiles({"OP-unit": self.operation([entry])})
        self.observe(profiles, 1, 1)
        self.observe(profiles, 1.0, 2)
        self.assertFalse(profiles.view("OP-unit", entry)["has_input_variant"])
        self.observe(profiles, True, 3)
        self.assertTrue(profiles.view("OP-unit", entry)["has_input_variant"])

    def test_nested_input_values_keep_numeric_equality_and_boolean_type(self):
        entry = {"name": "q", "location": "body", "selector": "/q"}
        profiles = parameter_coverage.ObservationProfiles({"OP-unit": self.operation([entry])})
        self.observe(profiles, {"rows": [{"count": 1, "enabled": False}], "items": [0]}, 1)
        self.observe(profiles, {"rows": [{"count": 1.0, "enabled": False}], "items": [-0.0]}, 2)
        self.assertFalse(profiles.view("OP-unit", entry)["has_input_variant"])
        self.observe(profiles, {"rows": [{"count": 1.0, "enabled": 0}], "items": [0]}, 3)
        self.assertTrue(profiles.view("OP-unit", entry)["has_input_variant"])

    def test_valid_random_multipart_boundaries_do_not_hide_filename_variants(self):
        entry = {"name": "filename", "location": "body", "selector": "file.filename"}
        operation = {**self.operation([entry]), "content_type": "multipart/form-data"}
        profiles = parameter_coverage.ObservationProfiles({"OP-unit": operation})
        for index, (boundary, filename) in enumerate(((b"First", b"one.png"), (b"Second", b"two.png"))):
            raw = (b"--" + boundary + b'\r\nContent-Disposition: form-data; name="file"; filename="' + filename
                   + b'"\r\nContent-Type: application/octet-stream\r\n\r\nfixed-binary\x00\xff\r\n--' + boundary + b"--\r\n")
            profiles.observe({"id": "E-" + str(index), "operation_id": operation["id"]},
                {"url": operation["url"], "method": "POST", "headers": {
                    "content-type": "multipart/form-data; boundary=" + boundary.decode("ascii")},
                 "body_base64": base64.b64encode(raw).decode("ascii")})
        self.assertTrue(profiles.view("OP-unit", entry)["has_input_variant"])

    def test_ambiguous_schema_branches_do_not_share_unattributed_control_candidates(self):
        entries = [{"name": "q", "location": "body", "selector": "/q", "schema_branch": branch}
                   for branch in ("oneOf:0", "oneOf:1")]
        profiles = parameter_coverage.ObservationProfiles({"OP-unit": self.operation(entries)})
        self.observe(profiles, "one", 1)
        self.observe(profiles, "two", 2)
        for entry in entries:
            view = profiles.view("OP-unit", entry)
            self.assertTrue(view["schema_branch_requires_binding"])
            self.assertFalse(view["has_input_variant"])

    def test_profile_budget_is_explicit_and_never_becomes_tested(self):
        entry = {"name": "q", "location": "body", "selector": "/q"}
        profiles = parameter_coverage.ObservationProfiles({"OP-unit": self.operation([entry])})
        with patch.object(parameter_coverage, "MAX_INPUT_VIEWS", 1):
            self.observe(profiles, "one", 1)
            self.observe(profiles, "two", 2)
        view = profiles.view("OP-unit", entry)
        self.assertTrue(view["observations_limited"])
        self.assertFalse(view["has_input_variant"])

    def test_small_byte_budget_keeps_history_but_does_not_infer_unseen_variants(self):
        entry = {"name": "q", "location": "body", "selector": "/q"}
        operation = self.operation([entry])
        profiles = parameter_coverage.ObservationProfiles({"OP-unit": operation})
        request = {"url": operation["url"], "method": "POST", "headers": {"content-type": "application/json"},
                   "body_base64": base64.b64encode(b'{"q": "one"}').decode("ascii")}
        budget = parameter_coverage._request_bytes(request)
        with patch.object(parameter_coverage, "MAX_INPUT_VIEW_BYTES", budget):
            self.observe(profiles, "one", 1)
            self.observe(profiles, "two", 2)
        view = profiles.view("OP-unit", entry)
        self.assertEqual(profiles.calls, 1)
        self.assertLessEqual(profiles.parsed_bytes, budget)
        self.assertEqual(view["operation_observation_count"], 2)
        self.assertEqual(view["observation_count"], 1)
        self.assertTrue(view["observations_limited"])
        self.assertFalse(view["has_input_variant"])


if __name__ == "__main__":
    unittest.main()
