"""Semantic advancement survives disposition cycles without relaxing exhaustion."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import unittest
from unittest.mock import patch

from awa_ddd import browser, completeness, continuation, engine
from awa_ddd.assessment import evaluate
from awa_ddd.store import EngineError
import test_continuation_20261030 as fixtures
import test_workflow_20261029 as workflow_fixtures


class SemanticProgressTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ContinuationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.project = self.fixture.project

    def checkpoint(self):
        result = self.fixture.checkpoint()
        return self.project.get("checkpoint", result["checkpoint"]["id"]), result["continuation"]

    def test_blocked_open_and_reason_cycles_do_not_reset_stalled_work(self):
        first, _ = self.checkpoint()
        self.checkpoint()
        self.checkpoint()
        identity = self.fixture.obligation("input_test")["id"]
        for index in range(9):
            for status in ("blocked", "open"):
                engine.disposition(self.project, {"obligation_id": identity, "status": status,
                    "reason": f"Caller disposition {index}; no actual prerequisite changed."})
                record, state = self.checkpoint()
                self.assertEqual(first["semantic_progress_id"], record["semantic_progress_id"])
                self.assertFalse(record["semantic_progress_changed"])
                self.assertGreaterEqual(state["no_progress_rounds"], 2)
                self.assertEqual("stalled", state["state"])
                self.assertTrue(state["continue_required"])
                self.assertFalse(state["can_finalize"])
        self.assertTrue(any(row["progress_id"] != first["progress_id"]
                            for row in self.project.list("checkpoint")), "legacy PR still records caller state changes")

    def test_administrative_archive_reopen_is_not_new_security_progress(self):
        evidence = self.fixture.capture(url=self.fixture.operation["url"] + "?q=unused")
        row = self.fixture.checklist("unassessed_observation", evidence["id"])
        first, _ = self.checkpoint()
        self.checkpoint()
        for _ in range(4):
            self.fixture.review(row)
            archived, _ = self.checkpoint()
            self.assertEqual(first["semantic_progress_id"], archived["semantic_progress_id"])
            self.fixture.review(row, "reopen")
            record, state = self.checkpoint()
            self.assertEqual(first["semantic_progress_id"], record["semantic_progress_id"])
            self.assertFalse(record["semantic_progress_changed"])
            self.assertGreaterEqual(state["no_progress_rounds"], 2)
            self.assertEqual(0, engine.evaluate_coverage(self.project)["security_coverage"]["evaluated"])
            self.assertFalse(state["automatic_stop_allowed"])

    def test_inconclusive_or_failed_evaluation_does_not_clear_stall(self):
        baseline = self.fixture.capture(url=self.fixture.operation["url"] + "?q=normal", response={"count": 1})
        attack = self.fixture.capture(url=self.fixture.operation["url"] + "?q=variant", response={"count": 2})
        sensitivity = self.fixture.capture(url=self.fixture.operation["url"] + "?q=sensitive", response={"count": 3})
        first, _ = self.checkpoint()
        self.checkpoint()
        self.checkpoint()
        args = {"obligation_id": self.fixture.obligation("input_test")["id"],
                "evidence_ids": [baseline["id"], attack["id"], sensitivity["id"]],
                "oracle": {"type": "semantic_negative", "test_family": "generic", "selector": "/count",
                           "baseline_expected": 1, "control_expected": 3}}
        self.assertEqual("inconclusive", evaluate(self.project, args)["outcome"])
        record, state = self.checkpoint()
        self.assertEqual(first["semantic_progress_id"], record["semantic_progress_id"])
        self.assertGreaterEqual(state["no_progress_rounds"], 2)
        with self.assertRaises(EngineError):
            evaluate(self.project, {**args, "oracle": {**args["oracle"], "selector": "/missing"}})
        record, state = self.checkpoint()
        self.assertEqual(first["semantic_progress_id"], record["semantic_progress_id"])
        self.assertGreaterEqual(state["no_progress_rounds"], 2)

    def test_real_typed_closure_resets_semantic_stall_once(self):
        before, _ = self.checkpoint()
        self.checkpoint()
        self.checkpoint()
        self.fixture.close_generic()
        record, state = self.checkpoint()
        self.assertNotEqual(before["semantic_progress_id"], record["semantic_progress_id"])
        self.assertTrue(record["semantic_progress_changed"])
        self.assertEqual(0, state["no_progress_rounds"])
        duplicate, _ = self.checkpoint()
        self.assertEqual(record["semantic_progress_id"], duplicate["semantic_progress_id"])
        self.assertFalse(duplicate["semantic_progress_changed"])

    def test_real_consumer_preparation_advances_once_and_state_reversals_do_not(self):
        operation = self.fixture.register("/unknown-input", inputs=[{"name": "q", "location": "query"}])
        before, _ = self.checkpoint()
        self.checkpoint()
        self.checkpoint()
        args = {"operation_id": operation["id"], "input_location": "query", "input_selector": "q",
                "consumer": "documented_business_filter", "test_families": ["generic"]}
        engine.declare_consumer(self.project, args)
        record, state = self.checkpoint()
        self.assertNotEqual(before["semantic_progress_id"], record["semantic_progress_id"])
        self.assertTrue(record["semantic_progress_changed"])
        self.assertEqual(0, state["no_progress_rounds"])
        engine.declare_consumer(self.project, args)
        same, _ = self.checkpoint()
        self.assertEqual(record["semantic_progress_id"], same["semantic_progress_id"])
        engine.register_operation(self.project, {"url": operation["url"], "method": "GET", "auth": "public",
            "inputs": [{"name": "q", "location": "query", "consumer": "unknown", "test_families": ["generic"]}]})
        engine.build_plan(self.project)
        reverted, _ = self.checkpoint()
        self.assertEqual(record["semantic_progress_id"], reverted["semantic_progress_id"])
        engine.declare_consumer(self.project, args)
        restored, _ = self.checkpoint()
        self.assertEqual(record["semantic_progress_id"], restored["semantic_progress_id"])

    def test_semantic_comparison_projection_is_private_and_audits_remain_read_only(self):
        before = {kind: self.project.list(kind) for kind in ("checkpoint", "decision", "closure_review", "run")}
        with patch.object(engine, "request") as network:
            state = completeness.audit(self.project, {})
            again = engine.evaluate_coverage(self.project)
        network.assert_not_called()
        self.assertEqual(before, {kind: self.project.list(kind) for kind in before})
        self.assertEqual(state["continuation"]["semantic_progress_id"], again["continuation"]["semantic_progress_id"])
        result = self.fixture.checkpoint()
        record = self.project.get("checkpoint", result["checkpoint"]["id"])
        self.assertIn("semantic_progress", record)
        self.assertNotIn("security_facts", json.dumps(result))
        self.assertNotIn("preparation_facts", json.dumps(result))

    def test_two_validated_same_page_adoptions_advance_once_each_without_pointer_churn(self):
        visits = []
        for number in (1, 2):
            source = self.fixture.root / f"semantic-visit-{number}.json"
            url = self.fixture.base + "/page"
            source.write_text(json.dumps({"url": url, "finalUrl": url, "status": 200,
                "signals": {"forms": number}, "network": [{"url": url, "method": "GET", "status": 200}]}), encoding="utf-8")
            visits.append(browser.import_observation(self.project, {"path": str(source)})["id"])
        before, _ = self.checkpoint()
        browser.adopt_visit(self.project, {"page_visit_id": visits[0]})
        first, _ = self.checkpoint()
        self.assertTrue(first["semantic_progress_changed"])
        self.assertNotEqual(before["semantic_progress_id"], first["semantic_progress_id"])
        browser.adopt_visit(self.project, {"page_visit_id": visits[1]})
        second, _ = self.checkpoint()
        self.assertTrue(second["semantic_progress_changed"])
        self.assertNotEqual(first["semantic_progress_id"], second["semantic_progress_id"])
        browser.adopt_visit(self.project, {"page_visit_id": visits[0]})
        repeated, _ = self.checkpoint()
        self.assertFalse(repeated["semantic_progress_changed"])
        self.assertEqual(second["semantic_progress_id"], repeated["semantic_progress_id"])

    def test_limited_semantic_projections_cannot_reset_stall_from_truncated_state(self):
        with patch.object(continuation, "MAX_SEMANTIC_PROGRESS_FACTS", 2):
            first, _ = self.checkpoint()
            for index in range(3):
                self.fixture.register("/additional-" + str(index), inputs=[{"name": "q", "location": "query"}])
                record, state = self.checkpoint()
                self.assertEqual(first["semantic_progress_id"], record["semantic_progress_id"])
                self.assertFalse(record["semantic_progress_changed"])
                self.assertFalse(record["semantic_progress"]["complete"])
                self.assertLessEqual(len(record["semantic_progress"]["security_facts"])
                                     + len(record["semantic_progress"]["preparation_facts"]), 2)
            self.assertGreaterEqual(state["no_progress_rounds"], 2)
            self.assertFalse(state["can_finalize"])

    def test_new_verified_identity_and_genuine_renewal_restore_preparation(self):
        fixture = workflow_fixtures.WorkflowTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        project = fixture.project
        operation = fixture.operation("/authenticated", auth="authenticated")
        identity = fixture.operation("/whoami", auth="authenticated")
        engine.add_actor(project, {"actor_id": "alice", "subject": "alice", "roles": []})
        session = engine.add_session(project, {"actor_id": "alice", "headers": {"cookie": "private-fixture-credential"}})
        engine.build_plan(project)

        def checkpoint():
            result = continuation.checkpoint(project, {})
            return project.get("checkpoint", result["checkpoint"]["id"]), result["continuation"]

        before, _ = checkpoint()
        checkpoint()
        checkpoint()
        with patch.object(engine, "request", side_effect=lambda *values: workflow_fixtures.observed(
                *values, response={"subject": "alice", "roles": []})):
            engine.verify_identity(project, {"operation_id": identity["id"], "session_id": session["id"],
                                           "subject_selector": "/subject"})
        engine.build_plan(project)
        verified, state = checkpoint()
        self.assertTrue(verified["semantic_progress_changed"])
        self.assertNotEqual(before["semantic_progress_id"], verified["semantic_progress_id"])
        self.assertEqual(0, state["no_progress_rounds"])
        checkpoint()
        checkpoint()
        session = project.get("session", session["id"])
        session["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        project.put("session", session)
        expired, state = checkpoint()
        self.assertEqual(verified["semantic_progress_id"], expired["semantic_progress_id"])
        self.assertGreaterEqual(state["no_progress_rounds"], 2, "lost readiness is not an improvement")
        with patch.object(engine, "request") as network:
            engine.add_session(project, {"session_id": session["id"], "renew": True})
            renewed, state = checkpoint()
        network.assert_not_called()
        self.assertTrue(renewed["semantic_progress_changed"])
        self.assertEqual(0, state["no_progress_rounds"])
        self.assertNotEqual(expired["semantic_progress_id"], renewed["semantic_progress_id"])
        self.assertTrue(any(row["operation_id"] == operation["id"] for row in project.list("obligation")))

    def test_identical_identity_attestations_do_not_reset_semantic_stall(self):
        fixture = workflow_fixtures.WorkflowTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        project = fixture.project
        fixture.operation("/authenticated", auth="authenticated")
        session = fixture.session()
        identity = project.get("operation", project.get("evidence", session["verification_evidence_id"])["operation_id"])
        first = continuation.checkpoint(project, {})["continuation"]["semantic_progress_id"]
        continuation.checkpoint(project, {})
        continuation.checkpoint(project, {})
        original_evidence = session["verification_evidence_id"]
        with patch.object(engine, "request", side_effect=lambda *values: workflow_fixtures.observed(
                *values, response={"subject": "alice", "roles": []})):
            for _ in range(4):
                engine.verify_identity(project, {"operation_id": identity["id"], "session_id": session["id"],
                                               "subject_selector": "/subject"})
                result = continuation.checkpoint(project, {})
                current = project.get("session", session["id"])
                self.assertNotEqual(original_evidence, current["verification_evidence_id"])
                self.assertEqual(first, result["continuation"]["semantic_progress_id"])
                self.assertFalse(result["checkpoint"]["semantic_progress_changed"])
                self.assertGreaterEqual(result["continuation"]["no_progress_rounds"], 2)
                self.assertTrue(result["continuation"]["continue_required"])
                self.assertFalse(result["continuation"]["automatic_stop_allowed"])

    def test_first_actual_membership_assertion_advances_once_without_receipt_identity(self):
        fixture = workflow_fixtures.WorkflowTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        project = fixture.project
        fixture.operation("/authenticated", auth="authenticated")
        session = fixture.session()
        identity = project.get("operation", project.get("evidence", session["verification_evidence_id"])["operation_id"])
        before = continuation.checkpoint(project, {})["continuation"]["semantic_progress_id"]
        actor_signature = engine.actor_signature(project.get("actor", session["actor_id"]))
        with patch.object(engine, "request", side_effect=lambda *values: workflow_fixtures.observed(
                *values, response={"subject": "alice", "roles": []})):
            args = {"operation_id": identity["id"], "session_id": session["id"],
                    "subject_selector": "/subject", "roles_selector": "/roles"}
            engine.verify_identity(project, args)
            first = continuation.checkpoint(project, {})
            self.assertEqual(actor_signature, engine.actor_signature(project.get("actor", session["actor_id"])))
            self.assertTrue(first["checkpoint"]["semantic_progress_changed"])
            self.assertNotEqual(before, first["continuation"]["semantic_progress_id"])
            engine.verify_identity(project, args)
            duplicate = continuation.checkpoint(project, {})
            self.assertFalse(duplicate["checkpoint"]["semantic_progress_changed"])
            self.assertEqual(first["continuation"]["semantic_progress_id"], duplicate["continuation"]["semantic_progress_id"])
            # No nonempty tenant was asserted, so a syntactic pointer that the
            # identity profile does not use cannot manufacture another capability.
            engine.verify_identity(project, {**args, "tenant_selector": "/unused"})
            pointer_only = continuation.checkpoint(project, {})
            self.assertFalse(pointer_only["checkpoint"]["semantic_progress_changed"])
            self.assertEqual(first["continuation"]["semantic_progress_id"], pointer_only["continuation"]["semantic_progress_id"])


if __name__ == "__main__":
    unittest.main()
