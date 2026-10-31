"""Offline stop-gate, resume, progress and source-bound reconciliation regressions."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import browser, completeness, continuation, engine, workflow
from awa_ddd.__main__ import dispatch
from awa_ddd.assessment import evaluate
from awa_ddd.candidates import store_candidate
from awa_ddd.store import EngineError, Project, now


def observation(url, method, headers, body, timeout, max_bytes, response):
    encoded = json.dumps(response).encode("utf-8")
    sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else b""
    return {"request": {"url": url, "method": method, "headers": headers,
                        "body_base64": base64.b64encode(sent).decode("ascii")},
            "response": {"status": 200, "headers": [["content-type", "application/json"]],
                         "length": len(encoded), "body_base64": base64.b64encode(encoded).decode("ascii")},
            "started_at": now(), "completed_at": now(), "complete": True}


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="awa-continuation-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = "http://fixture.invalid"
        engine.create_project(self.root, {"project_id": "continuation", "target": self.base, "allow_mutation": True})
        self.project = Project(self.root, "continuation")
        self.addCleanup(self.project.close)
        self.operation = self.register("/items", inputs=[{"name": "q", "location": "query",
            "consumer": "business_input", "test_families": ["generic"]}])

    def register(self, path, **extra):
        operation = engine.register_operation(self.project, {"url": self.base + path, "method": "GET", "auth": "public", **extra})
        engine.build_plan(self.project)
        return operation

    def capture(self, operation=None, response=None, **args):
        operation = operation or self.operation
        with patch.object(engine, "request", side_effect=lambda *values: observation(*values,
                {"count": 1} if response is None else response)):
            return engine.capture(self.project, {"operation_id": operation["id"], **args})

    def obligation(self, kind):
        return next(row for row in self.project.list("obligation") if row["operation_id"] == self.operation["id"]
                    and row["kind"] == kind and not row.get("superseded"))

    def baseline(self, evidence):
        return evaluate(self.project, {"obligation_id": self.obligation("baseline")["id"], "evidence_ids": [evidence["id"]],
            "oracle": {"type": "baseline", "selector": "/count", "expected": 1}})

    def close_generic(self):
        baseline = self.capture(url=self.operation["url"] + "?q=normal")
        variant = self.capture(url=self.operation["url"] + "?q=variant")
        control = self.capture(url=self.operation["url"] + "?q=sensitive", response={"count": 2})
        self.baseline(baseline)
        evaluate(self.project, {"obligation_id": self.obligation("input_test")["id"],
            "evidence_ids": [baseline["id"], variant["id"], control["id"]],
            "oracle": {"type": "semantic_negative", "test_family": "generic", "selector": "/count",
                       "baseline_expected": 1, "control_expected": 2}})
        self.baseline_evidence = baseline
        return baseline

    def frontier(self, evidence=None, blocked=False):
        evidence = evidence or getattr(self, "baseline_evidence", None)
        references = {"evidence_ids": [evidence["id"]]} if evidence and not blocked else {}
        return {"discovery": {"status": "blocked" if blocked else "reviewed",
                             "reason": "Reviewed the finite fixture API discovery boundary.", **references},
                "pages": {"status": "blocked" if blocked else "api_only",
                          "reason": "This isolated fixture is an API-only declared assessment.", **references},
                "categories": [{"test_family": family,
                    "status": "planned" if family == "generic" else "blocked" if blocked else "not_applicable",
                    "reason": "Only the explicitly modeled fixture input contract is in this finite scope.", **references}
                    for family in continuation.ALL_FAMILIES]}

    def checkpoint(self, frontier=None, **extra):
        return continuation.checkpoint(self.project, {**extra, **({"frontier_review": frontier} if frontier else {})})

    def finish(self, checkpoint, reason="completed", **extra):
        return continuation.finalize(self.project, {"checkpoint_id": checkpoint["checkpoint"]["id"], "reason": reason,
            "explanation": "The actual fixture reviewer explicitly reviewed this bounded stop.", "reviewer": "fixture-reviewer", **extra})

    def review(self, row, status="reviewed", **extra):
        return continuation.review(self.project, {"checklist_id": row["id"], "status": status,
            "reviewer": "fixture-reviewer", "reason": "Reviewed the original immutable fixture record.", **extra})

    def checklist(self, kind, source_id=None):
        rows = completeness.audit(self.project, {"limit": 100})["checklist"]
        return next(row for row in rows if row["kind"] == kind and (source_id is None or source_id in row.values()))

    def test_ready_work_rejects_completed_and_blocked_stop_without_side_effects(self):
        checkpoint = self.checkpoint()
        before = self.project.list("finalization")
        for reason in ("completed", "blocked"):
            with self.subTest(reason=reason), self.assertRaises(EngineError) as caught:
                self.finish(checkpoint, reason)
            self.assertEqual("continue_required", caught.exception.code)
            self.assertGreater(caught.exception.details["continuation"]["actionable_total"], 0)
        self.assertEqual(before, self.project.list("finalization"))

    def test_one_closed_generic_family_does_not_prove_discovery_exhaustion(self):
        self.close_generic()
        audit = completeness.audit(self.project, {})
        self.assertEqual("complete", audit["completion"]["status"])
        self.assertEqual(0, audit["continuation"]["actionable_total"])
        self.assertTrue(audit["continuation"]["continue_required"])
        self.assertFalse(audit["continuation"]["can_finalize"])
        self.assertEqual("frontier_review_required", audit["continuation"]["reason_code"])
        with self.assertRaises(EngineError) as caught:
            self.finish(self.checkpoint())
        self.assertEqual("frontier_review_required", caught.exception.code)

    def test_two_current_frontier_reviews_then_completed_stop(self):
        self.close_generic()
        first = self.checkpoint(self.frontier())
        self.assertEqual(1, first["continuation"]["frontier_rounds"])
        self.assertFalse(first["continuation"]["can_finalize"])
        with self.assertRaises(EngineError):
            self.finish(first)
        second = self.checkpoint(self.frontier())
        self.assertEqual(first["checkpoint"]["snapshot_id"], second["checkpoint"]["snapshot_id"])
        self.assertTrue(second["continuation"]["can_finalize"])
        self.assertFalse(second["continuation"]["can_claim_complete"])
        result = self.finish(second)
        self.assertFalse(result["continuation"]["continue_required"])
        self.assertTrue(result["continuation"]["can_claim_complete"])
        self.assertEqual("engine_gate", result["finalization"]["reason_basis"])
        self.assertEqual(result["finalization"], continuation.require_finalization(self.project, result["finalization"]["id"]))

    def test_empty_page_is_not_empty_work_queue(self):
        result = workflow.next_work(self.project, {"offset": 100000, "limit": 1})
        self.assertEqual([], result["work_items"])
        self.assertGreater(result["queue_total"], 0)
        self.assertTrue(result["continuation"]["continue_required"])
        self.assertGreater(result["continuation"]["actionable_total"], 0)

    def test_unresolved_candidate_keeps_review_active_when_obligations_close(self):
        self.close_generic()
        store_candidate(self.project, {"kind": "unresolved_fixture_clue", "url": self.operation["url"],
            "source": {"sha256": "a" * 64, "locator": "fixture#clue"}})
        result = workflow.next_work(self.project, {})
        self.assertEqual([], result["work_items"])
        self.assertGreater(result["continuation"]["review_total"], 0)
        self.assertFalse(result["continuation"]["can_finalize"])

    def test_declared_blocked_queue_allows_only_partial_stop(self):
        for row in self.project.list("obligation"):
            engine.disposition(self.project, {"obligation_id": row["id"], "status": "blocked",
                                             "reason": "The declared fixture observer is unavailable."})
        result = workflow.next_work(self.project, {})
        self.assertEqual([], result["work_items"])
        self.assertGreater(result["blocked_total"], 0)
        self.assertTrue(result["continuation"]["continue_required"])
        self.checkpoint(self.frontier(blocked=True))
        second = self.checkpoint(self.frontier(blocked=True))
        with self.assertRaises(EngineError) as caught:
            self.finish(second)
        self.assertEqual("assessment_partial", caught.exception.code)
        result = self.finish(second, "blocked")
        self.assertFalse(result["continuation"]["can_claim_complete"])
        self.assertEqual("projected_declared_blockers", result["finalization"]["reason_basis"])

    def test_explicit_external_exit_is_partial_and_not_authenticated_budget_proof(self):
        for reason in ("user_stop", "budget_exhausted", "authorization_boundary"):
            checkpoint = self.checkpoint(label="An actual externally requested fixture pause.")
            result = self.finish(checkpoint, reason)
            self.assertGreater(result["finalization"]["remaining"]["ready_total"], 0)
            self.assertFalse(result["finalization"]["can_claim_complete"])
            self.assertFalse(result["finalization"]["external_constraint_verified"])
            self.assertEqual("caller_declared_external_constraint", result["finalization"]["reason_basis"])

    def test_new_checkpoint_resumes_even_without_new_material(self):
        checkpoint = self.checkpoint()
        finished = self.finish(checkpoint, "user_stop")
        resumed = self.checkpoint()
        self.assertEqual(checkpoint["checkpoint"]["snapshot_id"], resumed["checkpoint"]["snapshot_id"])
        self.assertTrue(resumed["continuation"]["continue_required"])
        with self.assertRaises(EngineError) as caught:
            continuation.require_finalization(self.project, finished["finalization"]["id"])
        self.assertEqual("finalization_stale", caught.exception.code)

    def test_new_capture_invalidates_previous_checkpoint(self):
        checkpoint = self.checkpoint()
        self.capture(url=self.operation["url"] + "?q=new")
        with self.assertRaises(EngineError) as caught:
            self.finish(checkpoint, "user_stop")
        self.assertEqual("checkpoint_stale", caught.exception.code)

    def test_repeated_captures_are_not_closure_progress_or_stop_permission(self):
        first = self.checkpoint()
        for index in range(2):
            self.capture(url=self.operation["url"] + "?q=" + str(index))
            last = self.checkpoint()
            self.assertFalse(last["checkpoint"]["progress_changed"])
            self.assertEqual(first["checkpoint"]["progress_id"], last["checkpoint"]["progress_id"])
        self.assertEqual("stalled", last["continuation"]["state"])
        self.assertTrue(last["continuation"]["continue_required"])
        self.assertFalse(last["continuation"]["can_finalize"])

    def test_duplicate_semantic_decision_does_not_fake_progress(self):
        evidence = self.capture(url=self.operation["url"] + "?q=normal")
        self.baseline(evidence)
        first = self.checkpoint()
        self.baseline(evidence)
        second = self.checkpoint()
        self.assertNotEqual(first["checkpoint"]["snapshot_id"], second["checkpoint"]["snapshot_id"])
        self.assertEqual(first["checkpoint"]["progress_id"], second["checkpoint"]["progress_id"])
        self.assertFalse(second["checkpoint"]["progress_changed"])

    def test_repeated_candidate_poll_sources_do_not_fake_closure_progress(self):
        clue = {"kind": "fixture_clue", "url": self.operation["url"],
                "source": {"sha256": "b" * 64, "locator": "row#1"}}
        store_candidate(self.project, clue)
        first = self.checkpoint()
        store_candidate(self.project, {**clue, "sources": [{"sha256": "c" * 64, "locator": "later-query#row1"}]})
        second = self.checkpoint()
        self.assertEqual(first["checkpoint"]["progress_id"], second["checkpoint"]["progress_id"])
        self.assertFalse(second["checkpoint"]["progress_changed"])

    def test_repeated_operation_source_metadata_does_not_fake_closure_progress(self):
        first = self.checkpoint()
        engine.register_operation(self.project, {"url": self.operation["url"], "method": "GET", "auth": "public",
            "sources": [{"kind": "later source annotation"}]})
        engine.build_plan(self.project)
        second = self.checkpoint()
        self.assertEqual(first["checkpoint"]["progress_id"], second["checkpoint"]["progress_id"])
        self.assertFalse(second["checkpoint"]["progress_changed"])

    def test_real_decision_closure_resets_stall(self):
        self.checkpoint()
        self.checkpoint()
        self.checkpoint()
        self.close_generic()
        result = self.checkpoint()
        self.assertTrue(result["checkpoint"]["progress_changed"])
        self.assertEqual(0, result["continuation"]["no_progress_rounds"])

    def test_admin_review_never_closes_security_obligations(self):
        evidence = self.capture(url=self.operation["url"] + "?q=unused")
        before = self.project.list("obligation")
        row = self.checklist("unassessed_observation", evidence["id"])
        result = self.review(row)
        self.assertEqual(0, result["security_obligations_closed"])
        self.assertEqual(before, self.project.list("obligation"))
        self.assertEqual(0, result["completion"]["unassessed_observations"])
        self.assertEqual(0, engine.evaluate_coverage(self.project)["security_coverage"]["evaluated"])
        self.assertTrue(result["continuation"]["continue_required"])
        self.review(row, "reopen")
        self.assertEqual(1, completeness.audit(self.project, {})["completion"]["unassessed_observations"])

    def test_security_obligation_and_candidate_cannot_be_admin_archived(self):
        row = self.checklist("obligation")
        with self.assertRaises(EngineError) as caught:
            self.review(row)
        self.assertEqual("closure_review", caught.exception.code)
        self.assertEqual([], self.project.list("closure_review"))

    def test_archived_http_artifact_tampering_reopens_as_blocker(self):
        self.close_generic()
        extra = self.capture(url=self.operation["url"] + "?q=unused")
        row = self.checklist("unassessed_observation", extra["id"])
        self.review(row)
        self.assertEqual("complete", completeness.audit(self.project, {})["completion"]["status"])
        path = self.project.base / extra["artifact_path"]
        path.write_bytes(path.read_bytes() + b" ")
        audit = completeness.audit(self.project, {})
        self.assertEqual("partial", audit["completion"]["status"])
        self.assertEqual(1, audit["completion"]["unassessed_observations"])
        row = self.checklist("unassessed_observation", extra["id"])
        self.assertEqual("blocked", row["status"])
        with self.assertRaises(EngineError):
            self.review(row)
        self.review(row, "blocked")
        self.assertEqual(1, completeness.audit(self.project, {})["completion"]["unassessed_observations"])
        self.assertEqual("blocked", self.checklist("unassessed_observation", extra["id"])["status"])

    def test_archived_http_artifact_deletion_does_not_disappear(self):
        extra = self.capture(url=self.operation["url"] + "?q=unused")
        self.review(self.checklist("unassessed_observation", extra["id"]))
        (self.project.base / extra["artifact_path"]).unlink()
        self.assertEqual("blocked", self.checklist("unassessed_observation", extra["id"])["status"])

    def tool_run(self, **extra):
        record = {"id": self.project.id("RUN"), "kind": "external_tool", "adapter": "sqlmap", "status": "failed",
                  "operation_id": self.operation["id"], "effect": "read_only", "target_traffic_sent": True,
                  "error_code": "tool_timeout", "started_at": now(), "finished_at": now(), **extra}
        path, digest = self.project.artifact(self.project.id("TA"), {"execution": record, "diagnostic": "timeout"})
        record.update(artifact_path=path, sha256=digest)
        self.project.put("run", record)
        return record

    def test_partial_read_tool_review_is_source_bound_not_security_negative(self):
        run = self.tool_run()
        row = self.checklist("failed_partial_tool", run["id"])
        result = self.review(row)
        self.assertEqual(0, result["completion"]["failed_partial_tools"])
        self.assertEqual("failed", self.project.get("run", run["id"])["status"])
        path = self.project.base / run["artifact_path"]
        path.write_bytes(path.read_bytes() + b" ")
        self.assertEqual(run["id"], self.checklist("failed_partial_tool", run["id"])["run_id"])

    def test_over_budget_tool_material_cannot_be_verified_archive(self):
        path = self.project.base / "large-log.txt"
        with path.open("wb") as stream:
            stream.write(b"x" * (12 * 1024 * 1024 + 1))
        run = self.tool_run(files=[{"path": "large-log.txt", "complete": False}])
        row = self.checklist("failed_partial_tool", run["id"])
        with self.assertRaises(EngineError) as caught:
            self.review(row)
        self.assertEqual("review_material", caught.exception.code)
        self.review(row, "blocked")
        self.assertEqual("blocked", self.checklist("failed_partial_tool", run["id"])["status"])

    def test_running_run_cannot_be_reconciled_away(self):
        run = {"id": self.project.id("RUN"), "kind": "http", "status": "running", "started_at": now(),
               "operation_id": self.operation["id"]}
        self.project.put("run", run)
        with self.assertRaises(EngineError) as caught:
            self.review(self.checklist("unreconciled_run", run["id"]))
        self.assertEqual("run_active", caught.exception.code)
        self.assertEqual([], self.project.list("closure_review"))

    def test_interrupted_legacy_post_and_scenario_writes_need_context(self):
        post = self.register("/legacy-write", method="POST")
        for extra in ({"kind": "http", "operation_id": post["id"]},
                      {"kind": "scenario", "preflight": {"steps": [{"operation_id": post["id"]}]}}):
            run = {"id": self.project.id("RUN"), "status": "interrupted", "started_at": now(), "finished_at": now(), **extra}
            self.project.put("run", run)
            row = self.checklist("unreconciled_run", run["id"])
            with self.subTest(kind=run["kind"]), self.assertRaises(EngineError):
                self.review(row)
            self.review(row, "blocked")
            self.assertEqual("blocked", self.checklist("unreconciled_run", run["id"])["status"])

    def test_failed_native_read_is_reviewable_without_replaying_it(self):
        with patch.object(engine, "request", side_effect=OSError("fixture transport stopped")):
            with self.assertRaises(EngineError) as caught:
                engine.capture(self.project, {"operation_id": self.operation["id"], "url": self.operation["url"] + "?q=normal"})
        run_id = caught.exception.details["run_id"]
        with patch.object(engine, "request") as network:
            result = self.review(self.checklist("unreconciled_run", run_id))
        network.assert_not_called()
        self.assertEqual(0, result["completion"]["unreconciled_runs"])
        self.assertEqual("failed", self.project.get("run", run_id)["status"])

    def write_fixture(self):
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice", "roles": []})
        operation = self.register("/write-fixture", method="POST", content_type="application/json",
            inputs=[{"name": "id", "location": "body", "selector": "/id", "consumer": "resource_reference"},
                    {"name": "balance", "location": "body", "selector": "/balance", "consumer": "business_state"}])
        resource = engine.add_resource(self.project, {"operation_id": operation["id"], "owner_actor_id": "alice",
            "external_id": "7", "request_binding": {"location": "body", "selector": "/id"}})
        with patch.object(engine, "request", side_effect=OSError("fixture interrupted after dispatch")):
            with self.assertRaises(EngineError) as caught:
                engine.capture(self.project, {"operation_id": operation["id"], "resource_id": resource["id"],
                    "effect": "test_resource_write", "body": {"id": "7", "balance": 10}})
        return operation, resource, self.project.get("run", caught.exception.details["run_id"])

    def test_failed_native_write_enters_inventory_and_cannot_clear_with_text(self):
        operation, resource, run = self.write_fixture()
        self.assertEqual("test_resource_write", run["effect"])
        self.assertEqual(resource["id"], run["resource_id"])
        self.assertEqual(engine.resource_signature(resource), run["resource_signature"])
        row = self.checklist("unreconciled_run", run["id"])
        with self.assertRaises(EngineError):
            self.review(row)
        self.assertEqual([], self.project.list("closure_review"))

    def test_uncertain_write_requires_bound_read_only_business_readback(self):
        operation, resource, run = self.write_fixture()
        read_operation = self.register("/fixture-state", inputs=[{"name": "id", "location": "query", "consumer": "resource_reference"}])
        read_resource = engine.add_resource(self.project, {"operation_id": read_operation["id"], "owner_actor_id": "alice",
            "external_id": "7", "request_binding": {"location": "query", "selector": "id"}})
        read = self.capture(read_operation, url=read_operation["url"] + "?id=7", resource_id=read_resource["id"], response={"balance": 10})
        row = self.checklist("unreconciled_run", run["id"])
        binding = {"source_resource_id": resource["id"], "resource_id": read_resource["id"],
                   "relation": "fixture balance", "selector": "/balance", "expected": 10}
        with patch.object(engine, "request") as network:
            result = self.review(row, evidence_ids=[read["id"]], readback_bindings=[binding])
        network.assert_not_called()
        self.assertEqual(0, result["completion"]["unreconciled_runs"])
        self.assertEqual("failed", self.project.get("run", run["id"])["status"])
        self.assertEqual(0, result["security_obligations_closed"])

    def test_repeat_post_or_business_noise_cannot_reconcile_uncertain_write(self):
        operation, resource, run = self.write_fixture()
        repeat = self.capture(operation, resource_id=resource["id"], effect="test_resource_write",
                              body={"id": "7", "balance": 10}, response={"balance": 10, "success": True})
        row = self.checklist("unreconciled_run", run["id"])
        binding = {"source_resource_id": resource["id"], "resource_id": resource["id"],
                   "relation": "fixture balance", "selector": "/balance", "expected": 10}
        with self.assertRaises(EngineError):
            self.review(row, evidence_ids=[repeat["id"]], readback_bindings=[binding])
        binding.update(selector="/success", expected=True)
        with self.assertRaises(EngineError):
            self.review(row, evidence_ids=[repeat["id"]], readback_bindings=[binding])
        self.assertEqual([], self.project.list("closure_review"))

    def test_failed_browser_after_write_stays_blocked_without_fixture_snapshot(self):
        raw = {"url": self.base + "/consumer", "finalUrl": self.base + "/consumer", "status": 200,
               "error": "fixture browser failed after an authorized write", "write_authorized": True,
               "write_requests": [{"url": self.base + "/write", "method": "POST", "status": 200}],
               "network": [{"url": self.base + "/consumer", "method": "GET", "status": 200}]}
        visit = browser._record_observation(self.project, raw, self.project.id("PV"), "imported_mcp")
        row = self.checklist("orphan_browser_visit", visit["id"])
        with self.assertRaises(EngineError):
            self.review(row)
        self.review(row, "blocked")
        self.assertEqual("blocked", self.checklist("orphan_browser_visit", visit["id"])["status"])

    def test_valid_orphan_browser_requires_adoption_not_note_archive(self):
        raw = {"url": self.base + "/consumer", "finalUrl": self.base + "/consumer", "status": 200, "signals": {"forms": 1},
               "network": [{"url": self.base + "/consumer", "method": "GET", "status": 200}]}
        visit = browser._record_observation(self.project, raw, self.project.id("PV"), "imported_mcp")
        with self.assertRaises(EngineError) as caught:
            self.review(self.checklist("orphan_browser_visit", visit["id"]))
        self.assertEqual("page_adoption_required", caught.exception.code)

    def test_frontier_reviews_need_observations_and_do_not_exclude_real_tests(self):
        baseline = self.close_generic()
        frontier = self.frontier(baseline)
        next(row for row in frontier["categories"] if row["test_family"] == "generic")["status"] = "not_applicable"
        before = self.project.list("obligation")
        with self.assertRaises(EngineError) as caught:
            self.checkpoint(frontier)
        self.assertEqual("frontier_categories", caught.exception.code)
        self.assertEqual([], self.project.list("checkpoint"))
        self.assertEqual(before, self.project.list("obligation"))
        frontier = self.frontier(baseline)
        frontier["discovery"]["evidence_ids"] = []
        with self.assertRaises(EngineError) as caught:
            self.checkpoint(frontier)
        self.assertEqual("frontier_evidence", caught.exception.code)

    def test_all_twelve_categories_are_required_without_auto_filling(self):
        baseline = self.close_generic()
        for categories in (self.frontier(baseline)["categories"][:1], []):
            frontier = self.frontier(baseline)
            frontier["categories"] = categories
            with self.assertRaises(EngineError) as caught:
                self.checkpoint(frontier)
            self.assertEqual("frontier_categories", caught.exception.code)
        self.assertEqual([], self.project.list("checkpoint"))

    def test_public_round_and_stop_receipts_redact_text_but_keep_private_original(self):
        result = self.checkpoint(label="auth_token=private-round-value")
        self.assertNotIn("private-round-value", json.dumps(result))
        self.assertIn("private-round-value", self.project.get("checkpoint", result["checkpoint"]["id"])["label"])
        result = self.finish(result, "user_stop", explanation="password=private-stop-value", reviewer="token=private-reviewer-value")
        self.assertNotIn("private-stop-value", json.dumps(result))
        self.assertNotIn("private-reviewer-value", json.dumps(result))
        self.assertIn("private-stop-value", self.project.get("finalization", result["finalization"]["id"])["explanation"])

    def test_known_bare_session_credentials_are_not_echoed_in_round_prose(self):
        actor = engine.add_actor(self.project, {"actor_id": "private-actor", "subject": "private-actor", "roles": []})
        secret = "private-bare-session-value"
        engine.add_session(self.project, {"actor_id": actor["id"], "headers": {"X-Actor": secret},
                                        "credential_header_names": ["x-actor"]})
        result = self.checkpoint(label="The fixture credential is " + secret)
        self.assertNotIn(secret, json.dumps(result))
        self.assertIn(secret, self.project.get("checkpoint", result["checkpoint"]["id"])["label"])

    def test_completed_report_uses_real_gate_not_only_user_stop(self):
        from awa_ddd.reporting import build_report
        self.close_generic()
        self.checkpoint(self.frontier())
        stopped = self.finish(self.checkpoint(self.frontier()))
        result = build_report(self.project, stage="final", finalization_id=stopped["finalization"]["id"])
        self.assertEqual("final-completed", result["delivery_status"])
        self.assertTrue(result["continuation"]["can_claim_complete"])
        self.assertEqual("complete", result["completion"]["status"])

    def test_tscan_remote_uncertainty_cannot_disappear_with_no_observed_traffic(self):
        run = self.tool_run(adapter="tscanplus", action="http_request", selected_tool="http_request",
                            target_traffic_sent=False, remote_may_continue=True, remote_stopped_verified=False)
        row = self.checklist("failed_partial_tool", run["id"])
        with self.assertRaises(EngineError) as caught:
            self.review(row)
        self.assertEqual("remote_execution_unverified", caught.exception.code)
        self.assertEqual([], self.project.list("closure_review"))
        self.review(row, "blocked")
        self.assertEqual("blocked", self.checklist("failed_partial_tool", run["id"])["status"])
        self.assertEqual(1, completeness.audit(self.project, {})["completion"]["failed_partial_tools"])

    def test_tscan_truncated_query_results_remain_partial_despite_success(self):
        run = self.tool_run(adapter="tscanplus", action="query_results", selected_tool="query_results", status="succeeded",
                            target_traffic_sent=False, remote_may_continue=False, results_complete=False)
        row = self.checklist("failed_partial_tool", run["id"])
        with self.assertRaises(EngineError) as caught:
            self.review(row)
        self.assertEqual("remote_execution_unverified", caught.exception.code)
        self.review(row, "blocked")
        self.assertEqual(1, completeness.audit(self.project, {})["completion"]["failed_partial_tools"])

    def test_tool_only_http_reply_is_not_itself_machine_coverage_or_remote_job(self):
        self.tool_run(adapter="tscanplus", action="http_request", selected_tool="http_request", status="succeeded",
                      target_traffic_sent=False, remote_may_continue=False, results_complete=False)
        audit = completeness.audit(self.project, {})
        self.assertEqual(0, audit["completion"]["failed_partial_tools"])
        self.assertEqual(0, audit["security_coverage"]["evaluated"])
        self.assertTrue(audit["continuation"]["continue_required"])

    def test_receipts_cannot_be_overwritten(self):
        record = self.checkpoint()["checkpoint"]
        with self.assertRaises(EngineError) as caught:
            self.project.put("checkpoint", {**record, "label": "replace history"})
        self.assertEqual("immutable_record", caught.exception.code)

    def test_audit_and_next_never_persist_checkpoints_or_execute_requests(self):
        before = [tuple(row) for row in self.project.connection.execute("SELECT * FROM entities ORDER BY kind,id")]
        with patch.object(engine, "request") as network:
            audit = completeness.audit(self.project, {})
            next_work = workflow.next_work(self.project, {})
        network.assert_not_called()
        self.assertEqual(audit["continuation"], next_work["continuation"])
        self.assertEqual(before, [tuple(row) for row in self.project.connection.execute("SELECT * FROM entities ORDER BY kind,id")])

    def test_old_frontier_history_is_not_revalidated_without_bound(self):
        self.close_generic()
        for _ in range(2):
            self.checkpoint(self.frontier())
        with patch.object(engine, "verify_current_evidence", wraps=engine.verify_current_evidence) as verify:
            engine.evaluate_coverage(self.project)
            small = verify.call_count
        for _ in range(6):
            self.checkpoint(self.frontier())
        with patch.object(engine, "verify_current_evidence", wraps=engine.verify_current_evidence) as verify:
            result = engine.evaluate_coverage(self.project)
            large = verify.call_count
        self.assertEqual(2, result["continuation"]["frontier_rounds"])
        self.assertLessEqual(large, small + 2)

    def test_new_actions_dispatch_using_public_protocol(self):
        result = dispatch(self.root, "plan.checkpoint", {"project_id": "continuation", "label": "protocol fixture"})
        stopped = dispatch(self.root, "plan.finalize", {"project_id": "continuation",
            "checkpoint_id": result["checkpoint"]["id"], "reason": "user_stop", "reviewer": "fixture user",
            "explanation": "The actual fixture user explicitly paused this test."})
        report = dispatch(self.root, "report.build", {"project_id": "continuation", "stage": "final",
                           "finalization_id": stopped["finalization"]["id"]})
        self.assertEqual("final-partial", report["delivery_status"])
        self.assertFalse(report["continuation"]["can_claim_complete"])


if __name__ == "__main__":
    unittest.main()
