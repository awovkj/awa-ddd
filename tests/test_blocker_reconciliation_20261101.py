"""Caller declarations cannot suppress feasible offline continuation work."""
from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import json
import subprocess
import unittest
from unittest.mock import patch

import test_continuation_20261030 as fixtures
from awa_ddd import browser, completeness, continuation, engine, workflow
from awa_ddd.__main__ import dispatch
from awa_ddd.store import EngineError, now


class BlockerReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ContinuationTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.project = self.fixture.project
        self.operation = self.fixture.operation

    def state(self):
        return {table: [tuple(row) for row in self.project.connection.execute(f"SELECT * FROM {table} ORDER BY 1,2")]
                for table in ("entities", "events", "metadata")}

    def obligations(self, operation=None):
        operation = operation or self.operation
        return [item for item in self.project.list("obligation")
                if item["operation_id"] == operation["id"] and not item.get("superseded")]

    def block(self, operation=None, kinds=None):
        for item in self.obligations(operation):
            if kinds is None or item["kind"] in kinds:
                engine.disposition(self.project, {"obligation_id": item["id"], "status": "blocked",
                    "reason": "Synthetic caller declaration only; no prerequisite or authorization fact changed."})

    def next_rows(self, operation=None):
        operation = operation or self.operation
        with patch.object(engine, "request") as network, patch.object(browser, "visit") as playwright:
            result = workflow.next_work(self.project, {"include_blocked": True, "limit": 25})
        network.assert_not_called()
        playwright.assert_not_called()
        self.assertEqual(0, result["requests_sent"])
        return [row for row in result["work_items"] if row["operation_id"] == operation["id"]], result

    def assert_reconciliation(self, row, underlying):
        self.assertEqual("blocked", row["status"])
        self.assertEqual("blocked", row["declared_status"])
        self.assertEqual("review", row["queue_status"])
        self.assertEqual(underlying, row["underlying_queue_status"])
        self.assertTrue(row["blocker_reconciliation_required"])
        self.assertTrue(row["execution_blocked"])
        self.assertEqual("plan.disposition", row["suggested_action"])
        self.assertEqual("open", row["input_template"]["status"])
        self.assertEqual(row["obligation_id"], row["input_template"]["obligation_id"])
        self.assertFalse(row["browser_testing"]["invoke_now"])
        self.assertEqual([], row.get("recommended_tools", []))

    def test_ready_caller_blocked_rows_are_offline_reviews_without_database_mutation(self):
        self.block()
        before = self.state()
        rows, result = self.next_rows()
        self.assertEqual(2, len(rows))
        for row in rows:
            self.assert_reconciliation(row, "ready")
        self.assertEqual((0, 2, 0), tuple(result["continuation"][key]
                                        for key in ("ready_total", "review_total", "blocked_total")))
        self.assertTrue(result["continuation"]["continue_required"])
        self.assertFalse(result["continuation"]["automatic_stop_allowed"])
        audit = completeness.audit(self.project, {"limit": 100})
        self.assertEqual(result["continuation"], audit["continuation"])
        self.assertTrue(all(row["status"] == "open" and row["declared_status"] == "blocked"
                            and row["blocker_reconciliation_required"] for row in audit["checklist"]
                            if row["kind"] == "obligation"))
        self.assertEqual(before, self.state())

    def test_generated_reopen_restores_readiness_without_replaying_and_preserves_history(self):
        self.block()
        rows, _ = self.next_rows()
        original = {item["id"]: item for item in self.obligations()}
        with patch.object(engine, "request") as network:
            for row in rows:
                dispatch(self.fixture.root, row["suggested_action"],
                         {"project_id": self.project.project_id, **row["input_template"]})
        network.assert_not_called()
        reopened, result = self.next_rows()
        self.assertEqual(2, result["ready_total"])
        self.assertTrue(all(row["queue_status"] == "ready" and row["status"] == "open" for row in reopened))
        events = [json.loads(row[0]) for row in self.project.connection.execute(
            "SELECT document FROM events WHERE type='plan.disposition' ORDER BY seq")]
        reopens = [row for row in events if row["current"]["status"] == "open"]
        self.assertEqual(2, len(reopens))
        for event in reopens:
            self.assertEqual("caller_declaration", event["reason_basis"])
            self.assertEqual(original[event["obligation_id"]]["reason"], event["previous"]["reason"])
            self.assertEqual("blocked", event["previous"]["status"])
        self.assertEqual([], self.project.list("run"))

    def test_caller_blocked_setup_keeps_offline_tracing_and_real_unknown_policy_blocker(self):
        operation = self.fixture.register("/unknown", auth="unknown", inputs=[{"name": "opaque", "location": "query"}])
        self.block(operation, {"auth_review", "input_review"})
        rows, _ = self.next_rows(operation)
        setup = [row for row in rows if row["obligation_kind"] in {"auth_review", "input_review"}]
        self.assertEqual(2, len(setup))
        for row in setup:
            self.assert_reconciliation(row, "review")
        access = next(row for row in rows if row["obligation_kind"] == "access")
        self.assertEqual("blocked", access["queue_status"])
        self.assertIn("declared_access_policy", access["missing_prerequisites"])
        for row in setup:
            engine.disposition(self.project, row["input_template"])
        reopened, _ = self.next_rows(operation)
        self.assertEqual({"surface.register", "surface.declare_consumer"},
                         {row["suggested_action"] for row in reopened if row["queue_status"] == "review"})

    def test_real_write_permission_and_fixture_absence_are_not_blindly_reopened(self):
        engine.update_project(self.project, {"allow_mutation": False})
        operation = self.fixture.register("/write", method="POST", inputs=[{"name": "q", "location": "body",
            "consumer": "fixture_predicate", "test_families": ["generic"]}])
        self.block(operation)
        rows, _ = self.next_rows(operation)
        self.assertEqual(2, len(rows))
        for row in rows:
            self.assertEqual("blocked", row["queue_status"])
            self.assertEqual("blocked", row["declared_status"])
            self.assertIn("project_allow_mutation", row["missing_prerequisites"])
            self.assertIn("matching_test_resource_or_declared_actor_state", row["missing_prerequisites"])
            self.assertNotIn("blocker_reconciliation_required", row)

    def test_real_missing_verified_identity_remains_blocked(self):
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice", "roles": []})
        operation = self.fixture.register("/private", auth="authenticated", inputs=[{"name": "q", "location": "query",
            "consumer": "fixture_predicate", "test_families": ["generic"]}])
        self.block(operation)
        rows, _ = self.next_rows(operation)
        row = next(row for row in rows if row["obligation_kind"] == "input_test")
        self.assertEqual("blocked", row["queue_status"])
        self.assertIn("live_verified_allowed_session", row["missing_prerequisites"])
        self.assertNotIn("blocker_reconciliation_required", row)

    def test_real_unbound_path_stays_blocked(self):
        operation = self.fixture.register("/objects/{id}", inputs=[{"name": "id", "location": "path",
            "consumer": "fixture_predicate", "test_families": ["generic"]}])
        self.block(operation)
        rows, _ = self.next_rows(operation)
        self.assertTrue(all(row["queue_status"] == "blocked"
                            and "concrete_url_with_bound_path_values" in row["missing_prerequisites"]
                            and not row.get("blocker_reconciliation_required") for row in rows))

    def test_current_scope_exclusion_is_a_real_execution_blocker(self):
        engine.update_project(self.project, {"exclude": [self.operation["url"]]})
        self.block()
        before = self.state()
        rows, _ = self.next_rows()
        self.assertTrue(all(row["queue_status"] == "blocked"
                            and "authorized_operation_scope" in row["missing_prerequisites"] for row in rows))
        self.assertTrue(all(row["suggested_action"] == "surface.inspect" for row in rows))
        self.assertTrue(all(not row.get("blocker_reconciliation_required") for row in rows))
        self.assertEqual(before, self.state())

    def test_existing_offline_baseline_survives_scope_execution_gate(self):
        evidence = self.fixture.capture(url=self.operation["url"] + "?q=normal")
        engine.update_project(self.project, {"exclude": [self.operation["url"]]})
        self.block(kinds={"baseline"})
        rows, _ = self.next_rows()
        baseline = next(row for row in rows if row["obligation_kind"] == "baseline")
        self.assert_reconciliation(baseline, "ready")
        engine.disposition(self.project, baseline["input_template"])
        reopened, _ = self.next_rows()
        baseline = next(row for row in reopened if row["obligation_kind"] == "baseline")
        self.assertEqual("assessment.evaluate", baseline["suggested_action"])
        self.assertEqual([evidence["id"]], baseline["input_template"]["evidence_ids"])
        self.assertTrue(baseline["execution_blocked"])
        self.assertEqual([self.operation["url"]], self.project.config["exclude"])

    def test_setup_review_outside_current_scope_never_widens_authorization(self):
        operation = self.fixture.register("/review-only", auth="unknown", inputs=[{"name": "q", "location": "query"}])
        engine.update_project(self.project, {"exclude": [operation["url"]]})
        self.block(operation, {"auth_review", "input_review"})
        rows, _ = self.next_rows(operation)
        for row in rows:
            if row["obligation_kind"] in {"auth_review", "input_review"}:
                self.assert_reconciliation(row, "review")
            else:
                self.assertIn("authorized_operation_scope", row["missing_prerequisites"])
        self.assertEqual([operation["url"]], self.project.config["exclude"])

    def linked_page(self, operation):
        page = browser.register_page(self.project, {"url": self.fixture.base + "/ui"})
        browser.register_function(self.project, {"page_id": page["id"], "name": "Fixture interaction",
            "trigger": "button#fixture", "apis": [{"operation_id": operation["id"]}]})
        browser.mark(self.project, {"page_id": page["id"], "target": "page", "status": "BLOCKED",
            "reason": "Actual isolated fixture page is explicitly unavailable; do not reopen it."})
        return page

    def test_required_browser_page_blocker_is_not_blindly_reopened(self):
        operation = self.fixture.register("/xss", inputs=[{"name": "q", "location": "query",
            "consumer": "html_render", "test_families": ["xss"]}])
        page = self.linked_page(operation)
        self.block(operation, {"input_test"})
        rows, _ = self.next_rows(operation)
        row = next(row for row in rows if row["obligation_kind"] == "input_test")
        self.assertEqual("blocked", row["queue_status"])
        self.assertIn("explicit_consumer_page_unblock_or_authorized_alternative", row["missing_prerequisites"])
        self.assertNotIn("blocker_reconciliation_required", row)
        self.assertEqual("BLOCKED", self.project.get("page", page["id"])["visit_status"])

    def test_blocked_optional_browser_assistance_does_not_hide_independent_http_work(self):
        operation = self.fixture.register("/sql", inputs=[{"name": "q", "location": "query",
            "consumer": "sql_like", "test_families": ["sql_injection"]}])
        page = self.linked_page(operation)
        self.block(operation, {"input_test"})
        rows, _ = self.next_rows(operation)
        row = next(row for row in rows if row["obligation_kind"] == "input_test")
        self.assert_reconciliation(row, "ready")
        self.assertEqual("assisted", row["browser_testing"]["requirement"])
        self.assertEqual("BLOCKED", self.project.get("page", page["id"])["visit_status"])
        engine.disposition(self.project, row["input_template"])
        reopened, _ = self.next_rows(operation)
        row = next(row for row in reopened if row["obligation_kind"] == "input_test")
        self.assertEqual("ready", row["queue_status"])
        self.assertEqual("http.preflight", row["suggested_action"])
        self.assertFalse(row["browser_testing"]["invoke_now"])

    def test_existing_evidence_review_survives_expired_session_and_caller_blocked_status(self):
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice", "roles": []})
        session = engine.add_session(self.project, {"actor_id": "alice", "headers": {"Cookie": "fixture-principal=alice"}})
        identity = self.fixture.register("/identity", auth="authenticated")
        with patch.object(engine, "request", side_effect=lambda *values: fixtures.observation(*values, {"subject": "alice"})):
            engine.verify_identity(self.project, {"operation_id": identity["id"], "session_id": session["id"],
                "subject_selector": "/subject"})
        operation = self.fixture.register("/protected", auth="authenticated", inputs=[{"name": "q", "location": "query",
            "consumer": "fixture_predicate", "test_families": ["generic"]}])
        evidence = self.fixture.capture(operation, session_id=session["id"], url=operation["url"] + "?q=normal")
        current = self.project.get("session", session["id"])
        current["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        self.project.put("session", current)
        self.block(operation, {"input_test"})
        rows, _ = self.next_rows(operation)
        row = next(row for row in rows if row["obligation_kind"] == "input_test")
        self.assert_reconciliation(row, "review")
        self.assertIn("live_verified_allowed_session", row["missing_prerequisites"])
        engine.disposition(self.project, row["input_template"])
        reopened, _ = self.next_rows(operation)
        row = next(row for row in reopened if row["obligation_kind"] == "input_test")
        self.assertEqual("evidence.inspect", row["suggested_action"])
        self.assertEqual(evidence["id"], row["input_template"]["evidence_id"])
        self.assertTrue(row["execution_blocked"])

    def test_caller_blocked_valid_unused_observation_still_has_offline_review(self):
        evidence = self.fixture.capture(url=self.operation["url"] + "?q=unused")
        row = self.fixture.checklist("unassessed_observation", evidence["id"])
        receipt = self.fixture.review(row, "blocked")
        before = self.state()
        with patch.object(engine, "request") as network:
            row = self.fixture.checklist("unassessed_observation", evidence["id"])
        network.assert_not_called()
        self.assertEqual("open", row["status"])
        self.assertEqual("blocked", row["declared_status"])
        self.assertEqual("review", row["underlying_queue_status"])
        self.assertTrue(row["blocker_reconciliation_required"])
        self.assertEqual("plan.review", row["suggested_action"])
        self.assertEqual("reopen", row["input_template"]["status"])
        self.assertEqual(before, self.state())
        with patch.object(engine, "request") as network:
            self.fixture.review(row, "reopen")
        network.assert_not_called()
        self.assertEqual("blocked", self.project.get("closure_review", receipt["review"]["id"])["status"])
        self.assertEqual(1, completeness.audit(self.project, {})["completion"]["unassessed_observations"])

    def test_caller_blocked_complete_read_only_tool_and_native_run_keep_review(self):
        tool = self.fixture.tool_run()
        native = {"id": self.project.id("RUN"), "kind": "http", "status": "interrupted", "method": "GET",
                  "operation_id": self.operation["id"], "started_at": now(), "finished_at": now()}
        self.project.put("run", native)
        for kind, item in (("failed_partial_tool", tool), ("unreconciled_run", native)):
            row = self.fixture.checklist(kind, item["id"])
            self.fixture.review(row, "blocked")
            row = self.fixture.checklist(kind, item["id"])
            self.assertEqual("open", row["status"])
            self.assertTrue(row["blocker_reconciliation_required"])
            self.assertEqual("reopen", row["input_template"]["status"])
            self.fixture.review(row, "reopen")
            result = self.fixture.review(row)
            self.assertEqual(0, result["security_obligations_closed"])
            self.assertEqual(item["status"], self.project.get("run", item["id"])["status"])

    def test_real_tool_material_limit_remains_blocked_when_old_receipt_becomes_stale(self):
        run = self.fixture.tool_run()
        row = self.fixture.checklist("failed_partial_tool", run["id"])
        self.fixture.review(row, "blocked")
        path = self.project.base / run["artifact_path"]
        path.write_bytes(path.read_bytes() + b" ")
        row = self.fixture.checklist("failed_partial_tool", run["id"])
        self.assertEqual("blocked", row["status"])
        self.assertIn("review_material_changed", row["missing_prerequisites"])
        self.assertNotIn("blocker_reconciliation_required", row)
        with self.assertRaises(EngineError) as caught:
            self.fixture.review(row)
        self.assertEqual("review_material", caught.exception.code)

    def test_unknown_write_context_and_remote_execution_cannot_be_reconciled_by_text(self):
        operation = self.fixture.register("/unknown-write", method="POST")
        native = {"id": self.project.id("RUN"), "kind": "http", "status": "interrupted",
                  "operation_id": operation["id"], "started_at": now(), "finished_at": now()}
        self.project.put("run", native)
        scanner = self.fixture.tool_run(adapter="tscanplus", selected_tool="query_results",
            remote_may_continue=True, response_truncated=True)
        for kind, run, prerequisite in (("unreconciled_run", native, "captured_fixture_write_context"),
                                       ("failed_partial_tool", scanner, "verified_remote_stop_and_complete_results")):
            row = self.fixture.checklist(kind, run["id"])
            self.fixture.review(row, "blocked")
            row = self.fixture.checklist(kind, run["id"])
            self.assertEqual("blocked", row["status"])
            self.assertIn(prerequisite, row["missing_prerequisites"])
            self.assertNotIn("blocker_reconciliation_required", row)

    def test_failed_read_only_browser_material_has_offline_review_but_no_adoption(self):
        raw = {"url": self.fixture.base + "/failed-ui", "finalUrl": self.fixture.base + "/failed-ui", "status": 200,
               "error": "The isolated read-only observation failed after receiving its response.",
               "network": [{"url": self.fixture.base + "/failed-ui", "method": "GET", "status": 200}]}
        visit = browser._record_observation(self.project, raw, self.project.id("PV"), "imported_mcp")
        row = self.fixture.checklist("orphan_browser_visit", visit["id"])
        self.assertEqual("open", row["status"])
        self.assertEqual("plan.review", row["suggested_action"])
        self.fixture.review(row, "blocked")
        row = self.fixture.checklist("orphan_browser_visit", visit["id"])
        self.assertEqual("reopen", row["input_template"]["status"])
        self.assertTrue(row["blocker_reconciliation_required"])
        self.fixture.review(row, "reopen")
        with self.assertRaises(EngineError):
            browser.adopt_visit(self.project, {"page_visit_id": visit["id"]})
        with patch.object(engine, "request") as network:
            reviewed = self.fixture.review(row)
        network.assert_not_called()
        self.assertEqual(0, reviewed["completion"]["orphan_browser_visits"])
        self.assertEqual([], self.project.list("page"))
        self.assertEqual(0, browser.coverage(self.project)["pages_visited"])

    def test_actual_blocked_browser_requests_stay_unresolved(self):
        raw = {"url": self.fixture.base + "/blocked-ui", "finalUrl": self.fixture.base + "/blocked-ui", "status": 200,
               "blocked_requests": [{"url": self.fixture.base + "/write", "method": "POST",
                                      "reason": "write_operation_not_authorized"}],
               "network": [{"url": self.fixture.base + "/blocked-ui", "method": "GET", "status": 200}]}
        visit = browser._record_observation(self.project, raw, self.project.id("PV"), "imported_mcp")
        row = self.fixture.checklist("orphan_browser_visit", visit["id"])
        self.assertEqual("blocked", row["status"])
        self.assertIn("resolved_explicit_browser_request_boundary", row["missing_prerequisites"])
        self.fixture.review(row, "blocked")
        row = self.fixture.checklist("orphan_browser_visit", visit["id"])
        self.assertNotIn("blocker_reconciliation_required", row)
        with self.assertRaises(EngineError) as caught:
            self.fixture.review(row)
        self.assertEqual("browser_execution_blocked", caught.exception.code)
        self.assertEqual(1, completeness.audit(self.project, {})["completion"]["orphan_browser_visits"])

    def test_uncertain_fixture_write_only_becomes_reviewable_with_existing_bound_readback(self):
        _, resource, run = self.fixture.write_fixture()
        row = self.fixture.checklist("unreconciled_run", run["id"])
        self.fixture.review(row, "blocked")
        row = self.fixture.checklist("unreconciled_run", run["id"])
        self.assertEqual("blocked", row["status"])
        self.assertIn("later_same_identity_fixture_bound_readback_to_inspect", row["missing_prerequisites"])
        read_operation = self.fixture.register("/read-fixture", inputs=[{"name": "id", "location": "query",
            "consumer": "resource_reference"}])
        read_resource = engine.add_resource(self.project, {"operation_id": read_operation["id"], "owner_actor_id": "alice",
            "external_id": "7", "request_binding": {"location": "query", "selector": "id"}})
        read = self.fixture.capture(read_operation, url=read_operation["url"] + "?id=7",
                                    resource_id=read_resource["id"], response={"balance": 10})
        row = self.fixture.checklist("unreconciled_run", run["id"])
        self.assertEqual("open", row["status"])
        self.assertTrue(row["blocker_reconciliation_required"])
        self.assertEqual("reopen", row["input_template"]["status"])
        self.fixture.review(row, "reopen")
        self.assertEqual(1, completeness.audit(self.project, {})["completion"]["unreconciled_runs"])
        binding = {"source_resource_id": resource["id"], "resource_id": read_resource["id"],
                   "relation": "Isolated fixture balance", "selector": "/balance", "expected": 10}
        with patch.object(engine, "request") as network:
            reviewed = self.fixture.review(row, evidence_ids=[read["id"]], readback_bindings=[binding])
        network.assert_not_called()
        self.assertEqual(0, reviewed["completion"]["unreconciled_runs"])
        self.assertEqual(0, reviewed["security_obligations_closed"])

    def imported_browser(self, raw):
        source = self.fixture.root / (self.project.id("browser-source") + ".json")
        source.write_text(json.dumps(raw), encoding="utf-8")
        return dispatch(self.fixture.root, "browser.import_mcp",
                        {"project_id": self.project.project_id, "path": str(source)})

    def legacy_browser_archive(self, raw, *, old_write_policy=False):
        visit = self.imported_browser(raw)
        row = self.fixture.checklist("orphan_browser_visit", visit["id"])
        # Mint a real source-bound receipt through dispatch, simulating only the
        # missing old policy gates. No receipt hashes or documents are fabricated.
        with ExitStack() as old_policy:
            old_policy.enter_context(patch.object(continuation, "_review_prerequisites", return_value=[]))
            if old_write_policy:
                old_policy.enter_context(patch.object(continuation, "_write_contexts", return_value=[]))
            receipt = dispatch(self.fixture.root, "plan.review", {
                "project_id": self.project.project_id, "checklist_id": row["id"], "status": "reviewed",
                "reviewer": "isolated-upgrade-fixture",
                "reason": "Source-bound administrative receipt minted under the simulated earlier review policy."})
        private = self.project.get("closure_review", receipt["review"]["id"])
        source = self.project.get("page_visit", visit["id"])
        self.assertTrue(continuation._review_valid(self.project, private, source))
        return visit, private

    def legacy_browser_raw(self, **changes):
        url = self.fixture.base + "/legacy-ui"
        return {"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1},
                "error": "Isolated browser observation failed without claiming security coverage.",
                "network": [{"url": url, "method": "GET", "status": 200}], **changes}

    def assert_legacy_browser_blocked(self, visit, receipt, prerequisite):
        row = self.fixture.checklist("orphan_browser_visit", visit["id"])
        self.assertEqual("blocked", row["status"])
        self.assertIn(prerequisite, row["missing_prerequisites"])
        self.assertNotIn("blocker_reconciliation_required", row)
        self.assertEqual("reviewed", self.project.get("closure_review", receipt["id"])["status"])
        audit = completeness.audit(self.project, {"limit": 100})
        self.assertEqual(1, audit["completion"]["orphan_browser_visits"])
        self.assertEqual(0, audit["administrative_reviews"])
        self.assertFalse(audit["continuation"]["automatic_stop_allowed"])
        self.assertTrue(audit["continuation"]["continue_required"])

    def test_legacy_reviewed_browser_boundary_cannot_hide_current_blocker_or_finalize(self):
        self.fixture.close_generic()
        raw = self.legacy_browser_raw(blocked_requests=[{"url": self.fixture.base + "/write", "method": "POST",
            "reason": "write_operation_not_authorized"}])
        visit, receipt = self.legacy_browser_archive(raw)
        self.assert_legacy_browser_blocked(visit, receipt, "resolved_explicit_browser_request_boundary")
        self.fixture.checkpoint(self.fixture.frontier())
        checkpoint = self.fixture.checkpoint(self.fixture.frontier())
        with self.assertRaises(EngineError) as caught:
            self.fixture.finish(checkpoint)
        self.assertEqual("assessment_partial", caught.exception.code)
        self.assertEqual([], self.project.list("finalization"))

    def test_legacy_reviewed_truncated_browser_context_keeps_current_material_gap(self):
        visit, receipt = self.legacy_browser_archive(self.legacy_browser_raw(network_truncated=True))
        self.assert_legacy_browser_blocked(visit, receipt, "complete_browser_network_context")
        with self.assertRaises(EngineError) as caught:
            self.fixture.review(self.fixture.checklist("orphan_browser_visit", visit["id"]))
        self.assertEqual("browser_execution_blocked", caught.exception.code)

    def test_legacy_reviewed_unknown_browser_write_keeps_fixture_context_gap(self):
        raw = self.legacy_browser_raw(write_authorized=True,
            write_requests=[{"url": self.fixture.base + "/write", "method": "POST", "status": 200}])
        raw["network"].append({"url": self.fixture.base + "/write", "method": "POST", "status": 200, "write": True})
        visit, receipt = self.legacy_browser_archive(raw, old_write_policy=True)
        self.assert_legacy_browser_blocked(visit, receipt, "captured_fixture_write_context")
        with self.assertRaises(EngineError) as caught:
            self.fixture.review(self.fixture.checklist("orphan_browser_visit", visit["id"]))
        self.assertIn(caught.exception.code, {"reconciliation_context", "reconciliation_evidence"})

    def test_genuine_complete_read_only_browser_archive_remains_current_after_revalidation(self):
        visit = self.imported_browser(self.legacy_browser_raw())
        row = self.fixture.checklist("orphan_browser_visit", visit["id"])
        with patch.object(engine, "request") as network:
            receipt = dispatch(self.fixture.root, "plan.review", {
                "project_id": self.project.project_id, "checklist_id": row["id"], "status": "reviewed",
                "reviewer": "actual-fixture-reviewer", "reason": "Inspected the complete read-only failed observation offline."})
        network.assert_not_called()
        private = self.project.get("closure_review", receipt["review"]["id"])
        self.assertTrue(continuation._review_valid(self.project, private, self.project.get("page_visit", visit["id"])))
        audit = completeness.audit(self.project, {"limit": 100})
        self.assertEqual(0, audit["completion"]["orphan_browser_visits"])
        self.assertEqual(1, audit["administrative_reviews"])
        self.assertFalse(any(row.get("page_visit_id") == visit["id"] for row in audit["checklist"]))
        self.assertEqual(0, browser.coverage(self.project)["pages_visited"])
        self.assertEqual(0, receipt["security_obligations_closed"])

    def successful_write_browser_raw(self):
        raw = self.legacy_browser_raw(write_authorized=True,
            write_requests=[{"url": self.fixture.base + "/reported-write", "method": "POST", "status": 200}])
        raw.pop("error")
        raw["network"].append({"url": self.fixture.base + "/reported-write", "method": "POST", "status": 200, "write": True})
        return raw

    def test_verified_successful_orphan_can_adopt_offline_without_archiving_write_context(self):
        self.fixture.close_generic()
        before_obligations = self.project.list("obligation")
        before_decisions = self.project.list("decision")
        before_runs = self.project.list("run")
        visit = self.imported_browser(self.successful_write_browser_raw())
        row = self.fixture.checklist("orphan_browser_visit", visit["id"])
        audit = completeness.audit(self.project, {"limit": 100})
        self.assertEqual("open", row["status"])
        self.assertEqual("page.adopt", row["suggested_action"])
        self.assertEqual([], row["missing_prerequisites"])
        self.assertIn("captured_fixture_write_context", row["administrative_missing_prerequisites"])
        self.assertFalse(row["administrative_review_allowed"])
        self.assertEqual(1, audit["continuation"]["review_total"])
        self.assertEqual(0, audit["continuation"]["blocked_total"])
        with self.assertRaises(EngineError) as caught:
            self.fixture.review(row)
        self.assertEqual("page_adoption_required", caught.exception.code)
        with patch.object(engine, "request") as network, patch.object(browser.subprocess, "run") as runtime:
            adopted = dispatch(self.fixture.root, row["suggested_action"],
                               {"project_id": self.project.project_id, **row["input_template"]})
        network.assert_not_called()
        runtime.assert_not_called()
        self.assertEqual(0, adopted["requests_sent"])
        self.assertEqual(1, adopted["pages_adopted"])
        self.assertEqual(0, adopted["functions_marked"])
        self.assertEqual(1, browser.coverage(self.project)["pages_visited"])
        self.assertEqual(before_obligations, self.project.list("obligation"))
        self.assertEqual(before_decisions, self.project.list("decision"))
        self.assertEqual(before_runs, self.project.list("run"))
        self.assertEqual([], self.project.list("closure_review"))
        self.assertTrue(self.project.get("page_visit", visit["id"])["write_requests"])

    def test_offline_successful_page_adoption_preserves_existing_uncertain_native_write_ledger(self):
        self.fixture.close_generic()
        state = {"available": True, "node": "fixture-node", "module_root": "fixture-runtime"}
        with patch.object(browser, "probe", return_value=state), patch.object(browser.subprocess, "run",
                side_effect=subprocess.TimeoutExpired("isolated-fixture-runtime", 20)):
            with self.assertRaises(EngineError) as caught:
                dispatch(self.fixture.root, "browser.visit", {"project_id": self.project.project_id,
                    "url": self.fixture.base + "/uncertain-ui", "allow_write": True,
                    "actions": [{"type": "click", "selector": "#submit"}]})
        self.assertEqual("browser_timeout", caught.exception.code)
        run = self.project.get("run", caught.exception.details["run_id"])
        self.assertEqual("interrupted", run["status"])
        self.assertEqual("test_resource_write", run["effect"])
        visit = self.imported_browser(self.successful_write_browser_raw())
        row = self.fixture.checklist("orphan_browser_visit", visit["id"])
        self.assertEqual("open", row["status"])
        with patch.object(engine, "request") as network, patch.object(browser.subprocess, "run") as runtime:
            dispatch(self.fixture.root, "page.adopt", {"project_id": self.project.project_id,
                                                     "page_visit_id": visit["id"]})
            audit = completeness.audit(self.project, {"limit": 100})
        network.assert_not_called()
        runtime.assert_not_called()
        remaining = self.fixture.checklist("unreconciled_run", run["id"])
        self.assertEqual("blocked", remaining["status"])
        self.assertIn("captured_fixture_write_context", remaining["missing_prerequisites"])
        self.assertEqual(1, audit["completion"]["unreconciled_runs"])
        self.assertFalse(audit["continuation"]["automatic_stop_allowed"])
        self.assertEqual(run, self.project.get("run", run["id"]))


if __name__ == "__main__":
    unittest.main()
