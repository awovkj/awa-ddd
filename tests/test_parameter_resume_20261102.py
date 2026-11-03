"""Exact-control handoff and honest checkpoint deltas across bounded projections."""
from __future__ import annotations

import base64
from copy import deepcopy
import json
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import completeness, continuation, engine, parameter_coverage, workflow
from awa_ddd.__main__ import dispatch
from awa_ddd.assessment import evaluate
from awa_ddd.store import EngineError, Project, now


def observation(url, method, headers, body, timeout, max_bytes, *, response=None, status=200, complete=True):
    raw = json.dumps({"count": 1} if response is None else response).encode("utf-8")
    sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else b""
    return {"request": {"url": url, "method": method, "headers": headers,
                        "body_base64": base64.b64encode(sent).decode("ascii")},
            "response": {"status": status, "headers": [["content-type", "application/json"]],
                         "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
            "started_at": now(), "completed_at": now(), "complete": complete}


class ParameterResumeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-parameter-resume-")
        self.addCleanup(temporary.cleanup)
        self.root, self.base = temporary.name, "http://fixture.invalid"
        engine.create_project(self.root, {"project_id": "resume", "target": self.base})
        self.project = Project(self.root, "resume")
        self.addCleanup(self.project.close)
        self.operation = self.operation_at("/items")

    def operation_at(self, path, **extra):
        entry = {"name": "q", "location": "query", "consumer": "business_input", "test_families": ["generic"]}
        operation = engine.register_operation(self.project, {"url": self.base + path, "method": "GET",
            "auth": "public", "inputs": [entry], **extra})
        engine.build_plan(self.project)
        return operation

    def capture(self, value, *, operation=None, suffix="", status=200, complete=True, count=1, **extra):
        operation = operation or self.operation
        with patch.object(engine, "request", side_effect=lambda *args: observation(*args,
                response={"count": count}, status=status, complete=complete)):
            return engine.capture(self.project, {"operation_id": operation["id"],
                "url": operation["url"] + "?q=" + value + suffix, **extra})

    def controls(self, **extra):
        return [self.capture("normal-fixture", **extra), self.capture("variant-fixture", **extra),
                self.capture("sensitivity-fixture", count=2, **extra)]

    def decision(self, captures):
        item = next(row for row in self.project.list("obligation") if row["operation_id"] == self.operation["id"]
                    and row["kind"] == "input_test" and row.get("input_selector") == "q" and not row.get("superseded"))
        return evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in captures],
            "oracle": {"type": "semantic_negative", "test_family": "generic", "selector": "/count",
                       "baseline_expected": 1, "control_expected": 2}})

    def checkpoint(self):
        with patch.object(engine, "request") as network:
            result = dispatch(self.root, "plan.checkpoint", {"project_id": "resume"})
        network.assert_not_called()
        return result

    def next_row(self, operation=None):
        operation = operation or self.operation
        with patch.object(engine, "request") as network:
            result = dispatch(self.root, "plan.next", {"project_id": "resume", "include_blocked": True, "limit": 25,
                                                       "parameter_limit": 100})
        network.assert_not_called()
        row = next(row for row in result["work_items"] if row["operation_id"] == operation["id"]
                   and row["obligation_kind"] == "input_test" and row.get("input_selector") == "q")
        parameter = next(row for row in result["parameter_coverage"]["items"] if row["operation_id"] == operation["id"]
                         and row["input_selector"] == "q")
        return row, parameter

    def session(self, subject):
        engine.add_actor(self.project, {"actor_id": subject, "subject": subject, "roles": []})
        session = engine.add_session(self.project, {"actor_id": subject,
            "headers": {"Cookie": "fixture-principal=" + subject}})
        identity = engine.register_operation(self.project, {"url": self.base + "/whoami", "method": "GET", "auth": "authenticated"})
        with patch.object(engine, "request", side_effect=lambda *args: observation(*args, response={"subject": subject})):
            engine.verify_identity(self.project, {"operation_id": identity["id"], "session_id": session["id"],
                                                  "subject_selector": "/subject"})
        engine.build_plan(self.project)
        return self.project.get("session", session["id"])

    def assert_preparation(self, row, parameter):
        self.assertEqual("http.preflight", row["suggested_action"])
        self.assertFalse(row.get("control_candidate_review_required", False))
        self.assertEqual([], parameter["control_candidate_evidence_ids"])
        self.assertEqual("http.preflight", parameter["next_action"])
        self.assertFalse(parameter["typed_tested"])

    def test_budget_recovery_does_not_invent_new_variants_or_reopen_typed_work(self):
        captures = self.controls()
        self.decision(captures)
        self.checkpoint()
        with patch.object(parameter_coverage, "MAX_INPUT_VIEW_BYTES", 0):
            limited = self.checkpoint()["checkpoint"]["parameter_delta"]
            matrix = completeness.audit(self.project, {})["parameter_coverage"]["items"][0]
        self.assertTrue(matrix["typed_tested"])
        self.assertEqual([capture["id"] for capture in captures], matrix["evidence_ids"])
        self.assertEqual("evidence.inspect", matrix["next_action"])
        self.assertTrue(limited["tested_projection_complete"])
        self.assertTrue(limited["tested_comparison_available"])
        self.assertFalse(limited["variant_projection_complete"])
        self.assertFalse(limited["variant_comparison_available"])
        self.assertFalse(limited["projection_complete"])
        self.assertEqual(0, limited["reopened_total"])
        recovered = self.checkpoint()["checkpoint"]["parameter_delta"]
        self.assertFalse(recovered["variant_comparison_available"])
        self.assertEqual(0, recovered["newly_observed_variants_total"])
        self.assertEqual(0, recovered["newly_tested_total"])
        self.assertEqual(0, recovered["reopened_total"])
        settled = self.checkpoint()["checkpoint"]["parameter_delta"]
        self.assertTrue(settled["comparison_available"])
        self.assertEqual(0, settled["newly_observed_variants_total"])

    def test_first_budget_limited_projection_cannot_be_a_variant_baseline(self):
        self.controls()
        with patch.object(parameter_coverage, "MAX_INPUT_VIEWS", 0):
            first = self.checkpoint()
        internal = self.project.get("checkpoint", first["checkpoint"]["id"])["parameter_progress"]
        self.assertEqual(2, internal["version"])
        self.assertFalse(internal["variant_complete"])
        self.assertEqual([], internal["variant_keys"])
        recovered = self.checkpoint()["checkpoint"]["parameter_delta"]
        self.assertTrue(recovered["tested_comparison_available"])
        self.assertFalse(recovered["variant_comparison_available"])
        self.assertEqual(0, recovered["newly_observed_variants_total"])

    def test_typed_progress_and_damage_are_reported_while_observations_are_limited(self):
        self.checkpoint()
        captures = self.controls()
        self.decision(captures)
        with patch.object(parameter_coverage, "MAX_INPUT_VIEW_BYTES", 0):
            tested = self.checkpoint()["checkpoint"]["parameter_delta"]
            self.assertEqual(1, tested["newly_tested_total"])
            self.assertEqual(0, tested["newly_observed_variants_total"])
            artifact = self.project.base / captures[1]["artifact_path"]
            artifact.write_bytes(artifact.read_bytes() + b" ")
            reopened = self.checkpoint()["checkpoint"]["parameter_delta"]
        self.assertEqual(1, reopened["reopened_total"])
        self.assertEqual(0, reopened["newly_tested_total"])
        self.assertFalse(reopened["variant_comparison_available"])

    def test_legacy_projection_keeps_typed_keys_but_establishes_a_variant_baseline(self):
        captures = self.controls()
        self.decision(captures)
        saved = self.checkpoint()["checkpoint"]
        internal = self.project.get("checkpoint", saved["id"])
        for key in ("version", "tested_complete", "variant_complete"):
            internal["parameter_progress"].pop(key)
        internal.update(id=self.project.id("CP"), created_at=now())
        self.project.put("checkpoint", internal, create_only=True)
        result = self.checkpoint()["checkpoint"]["parameter_delta"]
        self.assertTrue(result["tested_comparison_available"])
        self.assertFalse(result["variant_comparison_available"])
        self.assertEqual(0, result["newly_tested_total"])
        self.assertEqual(0, result["newly_observed_variants_total"])

    def test_absent_and_invalid_old_projections_do_not_fabricate_comparisons(self):
        first = self.checkpoint()["checkpoint"]
        for projection in (None, {"complete": True, "tested_keys": ["not-an-input-key"],
                                  "variant_keys": [], "consumer_review_keys": []}):
            internal = self.project.get("checkpoint", first["id"])
            if projection is None:
                internal.pop("parameter_progress")
            else:
                internal["parameter_progress"] = projection
            internal.update(id=self.project.id("CP"), created_at=now())
            self.project.put("checkpoint", internal, create_only=True)
            delta = self.checkpoint()["checkpoint"]["parameter_delta"]
            self.assertFalse(delta["tested_comparison_available"])
            self.assertFalse(delta["variant_comparison_available"])
            self.assertEqual(0, delta["newly_tested_total"])

    def test_exact_three_value_controls_handoff_to_offline_inspection_without_writes(self):
        captures = self.controls()
        before = {kind: deepcopy(self.project.list(kind)) for kind in ("obligation", "evidence", "decision", "finding", "run")}
        row, parameter = self.next_row()
        ids = [capture["id"] for capture in captures]
        self.assertEqual("review", row["queue_status"])
        self.assertEqual("evidence.inspect", row["suggested_action"])
        self.assertEqual(ids, row["control_candidate_evidence_ids"])
        self.assertEqual(ids, row["evidence_ids"])
        self.assertEqual({"evidence_id": ids[0]}, row["input_template"])
        self.assertTrue(row["control_candidate_review_required"])
        self.assertTrue(row["controls_are_candidates_only"])
        self.assertEqual(ids, parameter["control_candidate_evidence_ids"])
        self.assertEqual(3, parameter["control_candidate_required_values"])
        self.assertEqual("evidence.inspect", parameter["next_action"])
        self.assertNotIn("oracle", row["input_template"])
        self.assertFalse(parameter["typed_tested"])
        self.assertEqual(before, {kind: self.project.list(kind) for kind in before})
        self.assertNotIn("fixture", json.dumps(row["control_candidate_evidence_ids"]))

    def test_candidate_references_do_not_use_unrelated_recent_observations(self):
        operation = self.operation_at("/with-other", inputs=[
            {"name": name, "location": "query", "consumer": "business_input", "test_families": ["generic"]}
            for name in ("q", "other")])
        captures = self.controls(operation=operation, suffix="&other=stable")
        recent = [self.capture("new-" + str(index), operation=operation, suffix="&other=" + str(index))
                  for index in range(6)]
        row, parameter = self.next_row(operation)
        self.assertEqual([capture["id"] for capture in captures], row["control_candidate_evidence_ids"])
        self.assertFalse(set(row["evidence_ids"]) & {capture["id"] for capture in recent})
        self.assertNotEqual(parameter["evidence_ids"], parameter["control_candidate_evidence_ids"])

    def test_two_values_are_not_full_semantic_negative_controls(self):
        self.capture("normal")
        self.capture("variant")
        row, parameter = self.next_row()
        self.assertTrue(parameter["has_input_variant"])
        self.assertEqual("two_values", parameter["control_candidate_state"])
        self.assert_preparation(row, parameter)

    def test_damaged_control_artifacts_are_not_offered_as_current_candidates(self):
        captures = self.controls()
        artifact = self.project.base / captures[1]["artifact_path"]
        artifact.write_bytes(artifact.read_bytes() + b" ")
        row, parameter = self.next_row()
        self.assert_preparation(row, parameter)
        self.assertNotIn(captures[1]["id"], row["evidence_ids"])

    def test_xss_http_controls_are_inspected_without_guessing_or_invoking_a_consumer(self):
        operation = self.operation_at("/xss", inputs=[
            {"name": "q", "location": "query", "consumer": "html_render", "test_families": ["xss"]}])
        captures = [self.capture(value, operation=operation) for value in ("normal", "variant")]
        row, parameter = self.next_row(operation)
        self.assertEqual("evidence.inspect", row["suggested_action"])
        self.assertEqual([capture["id"] for capture in captures], row["control_candidate_evidence_ids"])
        self.assertEqual("required", row["browser_testing"]["requirement"])
        self.assertEqual("identify_consumer", row["browser_testing"]["stage"])
        self.assertFalse(row["browser_testing"]["invoke_now"])
        self.assertIsNone(row["browser_testing"].get("native_visit_input"))
        self.assertNotIn("url", row["input_template"])
        self.assertFalse(parameter["typed_tested"])
        self.assertEqual([], self.project.list("decision"))
        self.assertEqual([], self.project.list("finding"))

    def test_cross_actor_and_session_captures_are_not_combined(self):
        alice, bob = self.session("alice"), self.session("bob")
        self.capture("normal", session_id=alice["id"])
        self.capture("variant", session_id=bob["id"])
        self.capture("sensitivity", session_id=alice["id"])
        self.assert_preparation(*self.next_row())

    def test_cross_fixture_captures_are_not_combined_even_with_the_same_bound_value(self):
        session = self.session("alice")
        operation = self.operation_at("/owned", auth="authenticated", inputs=[
            {"name": name, "location": "query", "consumer": "business_input", "test_families": ["generic"]}
            for name in ("q", "id")])
        resources = [engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": "alice",
            "external_id": "same-owned-fixture", "request_binding": {"location": "query", "selector": "id"}}) for _ in range(2)]
        for value, resource in zip(("normal", "variant", "sensitivity"), (resources[0], resources[1], resources[0])):
            self.capture(value, operation=operation, suffix="&id=same-owned-fixture", session_id=session["id"], resource_id=resource["id"])
        self.assert_preparation(*self.next_row(operation))

    def test_other_inputs_and_anonymous_cookie_changes_prevent_candidate_controls(self):
        operation = self.operation_at("/contexts", inputs=[
            {"name": name, "location": "query", "consumer": "business_input", "test_families": ["generic"]}
            for name in ("q", "other")])
        for index, value in enumerate(("normal", "variant", "sensitivity")):
            self.capture(value, operation=operation, suffix="&other=" + str(index), anonymous_cookie="fixture=" + str(index))
        self.assert_preparation(*self.next_row(operation))

    def test_cross_operation_captures_are_not_combined(self):
        other = self.operation_at("/other")
        self.capture("normal")
        self.capture("variant", operation=other)
        self.capture("sensitivity")
        self.assert_preparation(*self.next_row())

    def test_incomplete_and_failed_only_responses_cannot_replace_control_preparation(self):
        for index, value in enumerate(("normal", "variant", "sensitivity")):
            self.capture(value, complete=index != 2)
        self.assert_preparation(*self.next_row())
        operation = self.operation_at("/failed")
        for value in ("normal", "variant", "sensitivity"):
            self.capture(value, operation=operation, status=500)
        self.assert_preparation(*self.next_row(operation))

    def test_extraction_pairs_and_sql_error_controls_have_family_specific_handoffs(self):
        extraction = self.operation_at("/extraction", inputs=[
            {"name": "q", "location": "query", "consumer": "xml_parser", "test_families": ["xxe"]}])
        pair = [self.capture(value, operation=extraction) for value in ("recovery", "negative")]
        row, parameter = self.next_row(extraction)
        self.assertEqual("evidence.inspect", row["suggested_action"])
        self.assertEqual([capture["id"] for capture in pair], parameter["control_candidate_evidence_ids"])
        self.assertEqual(2, parameter["control_candidate_required_values"])
        sql = self.operation_at("/sql", inputs=[
            {"name": "q", "location": "query", "consumer": "sql_like", "test_families": ["sql_injection"]}])
        captures = [self.capture(value, operation=sql, status=status) for value, status in
                    (("normal", 200), ("recovery", 500), ("negative", 500))]
        row, parameter = self.next_row(sql)
        self.assertEqual("evidence.inspect", row["suggested_action"])
        self.assertEqual([capture["id"] for capture in captures], parameter["control_candidate_evidence_ids"])
        self.assertFalse(parameter["typed_tested"])
        self.assertEqual([], self.project.list("decision"))

    def test_new_inputs_still_lead_and_existing_control_review_gets_a_fair_slot(self):
        many = self.operation_at("/many", inputs=[
            {"name": "q" + str(index), "location": "query", "consumer": "business_input", "test_families": ["generic"]}
            for index in range(8)])
        for value in ("normal", "variant", "sensitivity"):
            with patch.object(engine, "request", side_effect=observation):
                engine.capture(self.project, {"operation_id": many["id"], "url": many["url"] + "?q0=" + value})
        self.operation_at("/fresh")
        with patch.object(engine, "request") as network:
            result = workflow.next_work(self.project, {"limit": 8})
        network.assert_not_called()
        tests = [row for row in result["work_items"] if row["obligation_kind"] == "input_test"]
        self.assertTrue(all(not row.get("control_candidate_review_required") for row in tests[:2]))
        self.assertEqual(2, len({row["operation_id"] for row in tests[:2]}))
        self.assertTrue(tests[2]["control_candidate_review_required"])
        self.assertEqual("evidence.inspect", tests[2]["suggested_action"])


class CompletedFamilyRecoveryTests(unittest.TestCase):
    def inventory(self, *, items=None, decisions=None, reductions=None):
        return {"obligations": items or [], "operations": {"O-fixture": {"inputs": []}}, "gaps": {},
                "decisions": decisions or {}, "consumer_requirements": reductions or [], "scope_reductions": []}

    def assert_family_error(self, inventory):
        with self.assertRaises(EngineError) as caught:
            continuation._completed_family(None, "generic", inventory, {})
        self.assertEqual("frontier_categories", caught.exception.code)
        self.assertIn("generic:", str(caught.exception))
        self.assertEqual("generic", caught.exception.details["test_family"])
        self.assertEqual("plan.audit", caught.exception.details["next_action"])
        self.assertEqual({"name": "plan.checkpoint"}, caught.exception.details["help_input"])

    def test_empty_unevaluated_and_untraced_completed_families_identify_the_failure(self):
        self.assert_family_error(self.inventory())
        item = {"id": "OB-fixture", "kind": "input_test", "operation_id": "O-fixture", "test_family": "generic", "status": "open"}
        self.assert_family_error(self.inventory(items=[item]))
        item["status"] = "evaluated"
        self.assert_family_error(self.inventory(items=[item], reductions=[{"test_family": "generic"}]))
        self.assert_family_error(self.inventory(items=[item]))

    def test_real_completed_frontier_error_preserves_family_and_has_no_checkpoint_side_effect(self):
        from test_frontier_categories_20261101 import FrontierCategoryTests

        fixture = FrontierCategoryTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        evidence = fixture.capture()
        with patch.object(engine, "request") as network, self.assertRaises(EngineError) as caught:
            dispatch(fixture.root, "plan.checkpoint", {"project_id": "frontier", "frontier_review": fixture.frontier(evidence)})
        network.assert_not_called()
        self.assertEqual("deserialization", caught.exception.details["test_family"])
        self.assertEqual("plan.audit", caught.exception.details["next_action"])
        self.assertIn("deserialization:", str(caught.exception))
        self.assertEqual([], fixture.project.list("checkpoint"))


if __name__ == "__main__":
    unittest.main()
