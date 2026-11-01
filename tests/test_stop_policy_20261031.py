"""Exhaustion-only stop regressions; no target requests or host-event claims."""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

import test_continuation_20261030 as fixtures
from awa_ddd import continuation, contracts, engine
from awa_ddd.__main__ import dispatch
from awa_ddd.reporting import build_report
from awa_ddd.store import EngineError, now


REMAINING = ("ready_total", "review_total", "blocked_total", "unresolved_total")


class StopPolicyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ContinuationTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.project = self.fixture.project

    def database_state(self):
        return {table: [tuple(row) for row in self.project.connection.execute(f"SELECT * FROM {table} ORDER BY 1,2")]
                for table in ("entities", "events", "metadata")}

    def completed_frontier(self):
        self.fixture.close_generic()
        self.fixture.checkpoint(self.fixture.frontier())
        return self.fixture.checkpoint(self.fixture.frontier())

    def historical_stop(self, checkpoint, reason="user_stop", **extra):
        current = checkpoint["continuation"]
        record = {"id": self.project.id("FN"), "checkpoint_id": checkpoint["checkpoint"]["id"],
                  "snapshot_id": current["snapshot_id"], "reason": reason,
                  "explanation": "Historical caller-declared stop; this text is not an authenticated host event.",
                  "reviewer": "historical-fixture", "created_at": now(),
                  "completion_status": "complete" if reason == "completed" else "partial",
                  "can_claim_complete": reason == "completed", "frontier_reviewed": current["frontier_rounds"] == 2,
                  "reason_basis": "engine_gate" if reason == "completed" else "caller_declared_external_constraint",
                  "remaining": {key: current[key] for key in REMAINING}, **extra}
        self.project.put("finalization", record, create_only=True)
        return record

    def test_only_completed_is_in_the_discoverable_stop_contract(self):
        self.assertEqual({"completed"}, continuation.STOP_REASONS)
        help_result = contracts.action_help({"name": "plan.finalize"})
        self.assertIn("completed only", help_result["fields"]["reason"])
        self.assertIn("exhaustion_only", str(help_result))

    def test_all_caller_declared_exits_are_rejected_without_database_or_network_effects(self):
        checkpoint = self.fixture.checkpoint()
        for reason in ("blocked", "budget_exhausted", "user_stop", "authorization_boundary"):
            before = self.database_state()
            with self.subTest(reason=reason), patch.object(engine, "request") as network:
                with self.assertRaises(EngineError) as caught:
                    self.fixture.finish(checkpoint, reason)
                network.assert_not_called()
            self.assertEqual("stop_policy", caught.exception.code)
            details = caught.exception.details
            self.assertTrue(details["continuation"]["continue_required"])
            self.assertFalse(details["continuation"]["can_finalize"])
            self.assertFalse(details["continuation"]["automatic_stop_allowed"])
            self.assertEqual("plan.checkpoint", details["checkpoint_action"])
            self.assertEqual({"action": "report.build", "input": {"stage": "draft"}}, details["progress_export"])
            self.assertEqual(0, details["requests_sent"])
            self.assertEqual(before, self.database_state())

    def test_disallowed_reason_is_not_accepted_even_after_real_exhaustion(self):
        checkpoint = self.completed_frontier()
        self.assertTrue(checkpoint["continuation"]["can_finalize"])
        for reason in ("blocked", "budget_exhausted", "user_stop", "authorization_boundary"):
            before = self.database_state()
            with self.subTest(reason=reason), self.assertRaises(EngineError) as caught:
                self.fixture.finish(checkpoint, reason)
            self.assertEqual("stop_policy", caught.exception.code)
            self.assertEqual(before, self.database_state())
        self.assertEqual([], self.project.list("finalization"))

    def test_model_arguments_cannot_override_the_stop_policy_or_attest_a_host_event(self):
        checkpoint = self.completed_frontier()
        for field, value in (("stop_policy", "allow_partial"), ("stop_policy_version", 0),
                             ("external_constraint_verified", True), ("host_event", {"type": "user_stop"}),
                             ("force", True)):
            before = self.database_state()
            with self.subTest(field=field), self.assertRaises(EngineError) as caught:
                dispatch(self.fixture.root, "plan.finalize", {"project_id": "continuation",
                    "checkpoint_id": checkpoint["checkpoint"]["id"], "reason": "completed",
                    "explanation": "A model-provided flag must not grant stop authority.", "reviewer": "fixture", field: value})
            self.assertEqual("continuation_arguments", caught.exception.code)
            self.assertEqual(before, self.database_state())

    def test_unknown_and_nonstring_stop_reasons_fail_with_continuation(self):
        checkpoint = self.fixture.checkpoint()
        for reason in ("low_yield", "max_requests", "exhausted", "", None, [], {}, 1, True):
            before = self.database_state()
            with self.subTest(reason=reason), self.assertRaises(EngineError) as caught:
                self.fixture.finish(checkpoint, reason)
            self.assertEqual("stop_reason", caught.exception.code)
            self.assertTrue(caught.exception.details["continuation"]["continue_required"])
            self.assertEqual(before, self.database_state())

    def test_complete_obligations_with_only_blocked_frontiers_are_not_exhaustion(self):
        self.fixture.close_generic()
        first = self.fixture.checkpoint(self.fixture.frontier(blocked=True))
        second = self.fixture.checkpoint(self.fixture.frontier(blocked=True))
        self.assertEqual(first["checkpoint"]["snapshot_id"], second["checkpoint"]["snapshot_id"])
        self.assertEqual("complete", second["checkpoint"]["completion_status"])
        self.assertEqual(0, second["continuation"]["frontier_rounds"])
        self.assertFalse(second["continuation"]["can_finalize"])
        with self.assertRaises(EngineError) as caught:
            self.fixture.finish(second)
        self.assertEqual("frontier_review_required", caught.exception.code)
        self.assertEqual([], self.project.list("finalization"))

    def test_a_new_incomplete_frontier_cannot_reuse_two_earlier_complete_rounds(self):
        checkpoint = self.completed_frontier()
        blocked = self.fixture.checkpoint(self.fixture.frontier(blocked=True))
        self.assertEqual(checkpoint["checkpoint"]["snapshot_id"], blocked["checkpoint"]["snapshot_id"])
        self.assertEqual(1, blocked["continuation"]["frontier_rounds"])
        self.assertFalse(blocked["continuation"]["can_finalize"])
        with self.assertRaises(EngineError) as caught:
            self.fixture.finish(blocked)
        self.assertEqual("frontier_review_required", caught.exception.code)

    def test_latest_checkpoint_needs_its_own_complete_frontier(self):
        complete = self.completed_frontier()
        latest = self.fixture.checkpoint()
        self.assertEqual(complete["checkpoint"]["snapshot_id"], latest["checkpoint"]["snapshot_id"])
        self.assertEqual(2, latest["continuation"]["frontier_rounds"])
        self.assertFalse(latest["continuation"]["can_finalize"])
        with self.assertRaises(EngineError) as caught:
            self.fixture.finish(latest)
        self.assertEqual("frontier_review_required", caught.exception.code)
        with self.assertRaises(EngineError) as caught:
            self.fixture.finish(complete)
        self.assertEqual("checkpoint_stale", caught.exception.code)

    def test_malformed_legacy_frontier_is_not_a_complete_round_or_a_crash(self):
        checkpoint = self.completed_frontier()["checkpoint"]
        for frontier in ("untrusted legacy review", {**checkpoint["frontier_review"], "complete": 1}):
            record = {**checkpoint, "id": self.project.id("CP"), "frontier_review": frontier}
            self.project.put("checkpoint", record, create_only=True)
            current = engine.evaluate_coverage(self.project)["continuation"]
            self.assertTrue(current["continue_required"])
            self.assertFalse(current["can_finalize"])
            self.assertLess(current["frontier_rounds"], 2)
            with self.assertRaises(EngineError) as caught:
                self.fixture.finish({"checkpoint": record})
            self.assertEqual("frontier_review_required", caught.exception.code)

    def test_empty_inventory_cannot_be_completed(self):
        engine.create_project(self.fixture.root, {"project_id": "empty-stop", "target": "http://fixture.invalid"})
        from awa_ddd.store import Project
        with Project(self.fixture.root, "empty-stop") as project:
            checkpoint = continuation.checkpoint(project, {})
            with self.assertRaises(EngineError) as caught:
                continuation.finalize(project, {"checkpoint_id": checkpoint["checkpoint"]["id"],
                    "reason": "completed", "explanation": "No inventory is not evidence of exhaustion.", "reviewer": "fixture"})
            self.assertEqual("assessment_not_started", caught.exception.code)
            self.assertEqual([], project.list("finalization"))

    def test_legacy_partial_receipts_cannot_stop_ready_work_or_build_final_files(self):
        checkpoint = self.fixture.checkpoint()
        for reason in ("blocked", "budget_exhausted", "user_stop", "authorization_boundary"):
            stop = self.historical_stop(checkpoint, reason)
            before = self.database_state()
            current = engine.evaluate_coverage(self.project)["continuation"]
            self.assertTrue(current["continue_required"])
            self.assertTrue(current["legacy_finalization_ignored"])
            self.assertFalse(current["automatic_stop_allowed"])
            self.assertFalse(current["can_claim_complete"])
            self.assertIsNone(current["finalization_id"])
            destination = self.fixture.root / ("rejected-" + reason)
            with self.subTest(reason=reason), patch.object(engine, "request") as network, \
                    patch("awa_ddd.reproduction.prepare_reproduction") as prepare:
                with self.assertRaises(EngineError) as caught:
                    build_report(self.project, destination, stage="final", finalization_id=stop["id"])
                network.assert_not_called()
                prepare.assert_not_called()
            self.assertEqual("finalization_policy", caught.exception.code)
            self.assertFalse(destination.exists())
            self.assertEqual(stop, self.project.get("finalization", stop["id"]))
            self.assertEqual(before, self.database_state())

    def test_legacy_partial_reason_cannot_be_relabelled_completed_by_permission_flags(self):
        checkpoint = self.completed_frontier()
        stop = self.historical_stop(checkpoint, "budget_exhausted", can_claim_complete=True,
                                    completion_status="complete", reason_basis="engine_gate", frontier_reviewed=True)
        current = engine.evaluate_coverage(self.project)["continuation"]
        self.assertTrue(current["can_finalize"])
        self.assertTrue(current["continue_required"])
        self.assertFalse(current["automatic_stop_allowed"])
        with self.assertRaises(EngineError) as caught:
            continuation.require_finalization(self.project, stop["id"])
        self.assertEqual("finalization_policy", caught.exception.code)

    def test_legacy_completed_receipt_requires_actual_current_exhaustion(self):
        checkpoint = self.fixture.checkpoint()
        stop = self.historical_stop(checkpoint, "completed", frontier_reviewed=True,
                                    remaining={key: 0 for key in REMAINING})
        current = engine.evaluate_coverage(self.project)["continuation"]
        self.assertTrue(current["continue_required"])
        self.assertFalse(current["can_finalize"])
        with self.assertRaises(EngineError) as caught:
            continuation.require_finalization(self.project, stop["id"])
        self.assertEqual("finalization_policy", caught.exception.code)

    def test_legacy_completed_receipt_is_retained_after_real_gate_revalidation(self):
        checkpoint = self.completed_frontier()
        stop = self.historical_stop(checkpoint, "completed")
        before = self.database_state()
        current = engine.evaluate_coverage(self.project)["continuation"]
        self.assertTrue(current["can_finalize"])
        self.assertTrue(current["automatic_stop_allowed"])
        self.assertTrue(current["can_claim_complete"])
        self.assertFalse(current["continue_required"])
        self.assertFalse(current["legacy_finalization_ignored"])
        self.assertEqual(stop, continuation.require_finalization(self.project, stop["id"]))
        self.assertEqual(before, self.database_state())

    def test_unknown_policy_versions_cannot_self_authorize_a_receipt(self):
        checkpoint = self.completed_frontier()
        for extra in ({"stop_policy": "allow_partial", "stop_policy_version": 1},
                      {"stop_policy": "exhaustion_only", "stop_policy_version": 999},
                      {"stop_policy": "exhaustion_only", "stop_policy_version": True},
                      {"stop_policy_version": 1}):
            with self.subTest(extra=extra):
                stop = self.historical_stop(checkpoint, "completed", **extra)
                current = engine.evaluate_coverage(self.project)["continuation"]
                self.assertTrue(current["can_finalize"])
                self.assertTrue(current["continue_required"])
                with self.assertRaises(EngineError) as caught:
                    continuation.require_finalization(self.project, stop["id"])
                self.assertEqual("finalization_policy", caught.exception.code)

    def test_truthy_permission_or_boolean_remaining_is_not_a_valid_record(self):
        checkpoint = self.completed_frontier()
        for extra in ({"can_claim_complete": 1}, {"frontier_reviewed": 1}, {"automatic_stop_allowed": False},
                      {"reason_basis": "caller_declared_external_constraint"},
                      {"remaining": {key: False for key in REMAINING}}):
            with self.subTest(extra=extra):
                stop = self.historical_stop(checkpoint, "completed", **extra)
                self.assertTrue(engine.evaluate_coverage(self.project)["continuation"]["continue_required"])
                with self.assertRaises(EngineError) as caught:
                    continuation.require_finalization(self.project, stop["id"])
                self.assertEqual("finalization_policy", caught.exception.code)

    def test_latest_ineligible_receipt_does_not_resurrect_an_earlier_stop(self):
        checkpoint = self.completed_frontier()
        completed = self.historical_stop(checkpoint, "completed")
        ignored = self.historical_stop(checkpoint, "user_stop")
        current = engine.evaluate_coverage(self.project)["continuation"]
        self.assertTrue(current["continue_required"])
        self.assertTrue(current["legacy_finalization_ignored"])
        with self.assertRaises(EngineError) as caught:
            continuation.require_finalization(self.project, completed["id"])
        self.assertEqual("finalization_stale", caught.exception.code)
        with self.assertRaises(EngineError) as caught:
            continuation.require_finalization(self.project, ignored["id"])
        self.assertEqual("finalization_policy", caught.exception.code)

    def test_actual_finite_negative_evidence_and_complete_frontier_allow_one_final_stop(self):
        checkpoint = self.completed_frontier()
        self.assertTrue(checkpoint["continuation"]["continue_required"])
        self.assertFalse(checkpoint["continuation"]["automatic_stop_allowed"])
        with patch.object(engine, "request") as network:
            result = self.fixture.finish(checkpoint)
            network.assert_not_called()
        current, stop = result["continuation"], result["finalization"]
        self.assertEqual(2, current["contract_version"])
        self.assertEqual("exhaustion_only", current["stop_policy"])
        self.assertEqual(1, current["stop_policy_version"])
        self.assertIs(current["automatic_stop_allowed"], True)
        self.assertIs(current["can_claim_complete"], True)
        self.assertIs(current["continue_required"], False)
        self.assertEqual("completed", stop["reason"])
        self.assertEqual("exhaustion_only", stop["stop_policy"])
        self.assertEqual(1, stop["stop_policy_version"])
        self.assertEqual({key: 0 for key in REMAINING}, stop["remaining"])
        self.assertEqual(stop, continuation.require_finalization(self.project, stop["id"]))
        self.assertTrue(current["registered_scope_only"])

    def test_changed_scope_invalidates_an_actual_completed_record(self):
        checkpoint = self.completed_frontier()
        stop = self.fixture.finish(checkpoint)["finalization"]
        config = copy.deepcopy(self.project.config)
        config["exclude"] = [self.fixture.base + "/items"]
        self.project.set_config(config)
        current = engine.evaluate_coverage(self.project)["continuation"]
        self.assertTrue(current["continue_required"])
        self.assertFalse(current["automatic_stop_allowed"])
        with self.assertRaises(EngineError) as caught:
            continuation.require_finalization(self.project, stop["id"])
        self.assertEqual("finalization_stale", caught.exception.code)


if __name__ == "__main__":
    unittest.main()
