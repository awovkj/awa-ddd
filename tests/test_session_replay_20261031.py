"""Sanitized structural replay of premature budget exits, never historical traffic."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import completeness, continuation, engine, workflow
from awa_ddd.__main__ import dispatch
from awa_ddd.assessment import evaluate, record_finding
from awa_ddd.reporting import build_report
from awa_ddd.store import EngineError, Project, now


REMAINING = ("ready_total", "review_total", "blocked_total", "unresolved_total")
SESSION_COUNTS = {"ready_total": 98, "review_total": 134, "blocked_total": 149, "unresolved_total": 381}


def observed(url, method, headers, body, timeout, max_bytes, *, response=None):
    raw = json.dumps({"count": 1} if response is None else response).encode("utf-8")
    sent = body if isinstance(body, bytes) else body.encode("utf-8") if isinstance(body, str) else b""
    return {"request": {"url": url, "method": method, "headers": headers,
                        "body_base64": base64.b64encode(sent).decode("ascii")},
            "response": {"status": 200, "headers": [["content-type", "application/json"]],
                         "length": len(raw), "body_base64": base64.b64encode(raw).decode("ascii")},
            "started_at": now(), "completed_at": now(), "complete": True}


class SessionReplayTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-session-replay-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.base = "http://fixture.invalid"
        self.project_id = "session-replay"
        engine.create_project(self.root, {"project_id": self.project_id, "target": self.base})
        self.project = Project(self.root, self.project_id)
        self.addCleanup(self.project.close)

    def invoke(self, action, **args):
        return dispatch(self.root, action, {"project_id": self.project_id, **args})

    def database_state(self, project=None):
        project = self.project if project is None else project
        return {table: [tuple(row) for row in project.connection.execute(f"SELECT * FROM {table} ORDER BY 1,2")]
                for table in ("entities", "events", "metadata")}

    def operation(self, path, **extra):
        return engine.register_operation(self.project, {"url": self.base + path, "method": "GET", "auth": "public", **extra})

    def capture(self, operation, *, response=None, **args):
        with patch.object(engine, "request", side_effect=lambda *values: observed(*values, response=response)):
            return engine.capture(self.project, {"operation_id": operation["id"], **args})

    def seed_partial_work(self, *, findings=False):
        # A small real ledger has the same ready/review/blocked structure as the session.
        public = self.operation("/items", inputs=[{"name": "q", "location": "query", "consumer": "unknown"}])
        self.operation("/private", auth="authenticated")
        if findings:
            for index in range(2):
                operation = self.operation("/reviewed-" + str(index), inputs=[
                    {"name": "value", "location": "query", "consumer": "unknown"}])
                evidence = self.capture(operation, response={"count": 1, "fixture_note": "reviewed observation " + str(index)})
                record_finding(self.project, {"mode": "analyst", "title": "Reviewed fixture observation " + str(index),
                    "category": "Information Disclosure", "severity": "medium", "impact": "Only this isolated fixture observation.",
                    "remediation": "Restrict the modeled fixture response.", "reviewer": "fixture-analyst",
                    "reason": "Reviewed actual mock capture bytes; this does not close the unrelated test obligations.",
                    "evidence_ids": [evidence["id"]]})
        engine.build_plan(self.project)
        current = engine.evaluate_coverage(self.project)["continuation"]
        for key in ("ready_total", "review_total", "blocked_total"):
            self.assertGreater(current[key], 0)
        self.assertEqual(0, current["frontier_rounds"])
        self.assertTrue(current["continue_required"])
        return public, current

    def assert_continuing(self, current, *, counts=None):
        self.assertEqual("exhaustion_only", current["stop_policy"])
        self.assertTrue(current["continue_required"])
        self.assertFalse(current["automatic_stop_allowed"])
        self.assertFalse(current["can_claim_complete"])
        self.assertFalse(current["can_finalize"])
        self.assertIsNone(current["finalization_id"])
        if counts is not None:
            self.assertEqual(counts, {key: current[key] for key in REMAINING})

    def legacy_budget_record(self, checkpoint):
        # Historical record fields are data only; no source transcript or credentials are copied.
        record = {"id": self.project.id("FN"), "checkpoint_id": checkpoint["checkpoint"]["id"],
            "snapshot_id": checkpoint["continuation"]["snapshot_id"], "reason": "budget_exhausted",
            "reviewer": "historical-fixture-agent", "explanation": "The caller asserted an unmeasured practical turn budget.",
            "completion_status": "partial", "can_claim_complete": False, "frontier_reviewed": False,
            "external_constraint_verified": False, "blocker_facts_verified": False,
            "reason_basis": "caller_declared_external_constraint", "remaining": dict(SESSION_COUNTS), "created_at": now()}
        self.project.put("finalization", record)
        return record

    def test_two_checkpoint_budget_attempts_do_not_stop_work_or_create_finalizations(self):
        _, current = self.seed_partial_work(findings=True)
        counts = {key: current[key] for key in REMAINING}
        findings = copy.deepcopy(self.project.list("finding"))
        self.assertEqual(2, len(findings))
        snapshots = []
        with patch.object(engine, "request") as network:
            for index in range(2):
                checkpoint = self.invoke("plan.checkpoint", label="Partial fixture round " + str(index))
                snapshots.append(checkpoint["checkpoint"]["snapshot_id"])
                self.assert_continuing(checkpoint["continuation"], counts=counts)
                before = self.database_state()
                with self.assertRaises(EngineError) as caught:
                    self.invoke("plan.finalize", checkpoint_id=checkpoint["checkpoint"]["id"],
                        reason="budget_exhausted", reviewer="fixture-agent",
                        explanation="The caller claims its practical single-turn budget is exhausted after finding issues.")
                self.assertEqual("stop_policy", caught.exception.code)
                self.assert_continuing(caught.exception.details["continuation"], counts=counts)
                self.assertEqual(before, self.database_state())
                self.assertEqual([], self.project.list("finalization"))
                draft = self.invoke("report.build", stage="draft", output_dir=str(self.root / ("draft-" + str(index))))
                self.assertEqual("draft", draft["delivery_status"])
                self.assert_continuing(draft["continuation"], counts=counts)
                summary = json.loads(Path(draft["summary"]).read_text(encoding="utf-8"))
                manifest = json.loads(Path(draft["manifest"]).read_text(encoding="utf-8"))
                self.assertEqual(draft["continuation"], summary["continuation"])
                self.assertEqual(summary["continuation"], manifest["continuation"])
                self.assertIsNone(summary["finalization"])
                self.assertEqual(before, self.database_state())
            stalled = self.invoke("plan.checkpoint", label="Same ledger without closure progress")
            self.assertEqual("stalled", stalled["continuation"]["state"])
            self.assertGreaterEqual(stalled["continuation"]["no_progress_rounds"], 2)
            self.assert_continuing(stalled["continuation"], counts=counts)
            self.assertEqual(snapshots[0], snapshots[1])
            self.assertFalse(stalled["checkpoint"]["progress_changed"])
            self.assertEqual(findings, self.project.list("finding"))
            self.assertEqual([], self.project.list("finalization"))
            network.assert_not_called()

    def test_original_session_counts_remain_nonexhausted_even_if_coverage_is_relabelled(self):
        state = {**SESSION_COUNTS, "actionable_total": 232, "frontier_rounds": 0,
                 "frontier_complete": False, "current_checkpoint": True, "current_frontier": False,
                 "snapshot_id": "CS-sanitized-session", "progress_id": "PR-sanitized-session",
                 "checkpoint_id": "CP-sanitized-session", "no_progress_rounds": 1, "checkpoints": []}
        with patch.object(continuation, "_state", return_value=state), patch.object(engine, "request") as network:
            current = continuation.control(self.project, evaluated={}, inventory={"operations": {"O-fixture": {}}},
                security={}, completion={"status": "partial"})
            self.assert_continuing(current, counts=SESSION_COUNTS)
            self.assertEqual(232, current["actionable_total"])
            network.assert_not_called()
        self.assertFalse(continuation._exhausted(state, {"status": "partial"}, True))
        forged_completion = {**state, "frontier_rounds": 2, "frontier_complete": True, "current_frontier": True}
        self.assertFalse(continuation._exhausted(forged_completion, {"status": "complete"}, True))
        zero = {**forged_completion, **{key: 0 for key in REMAINING}, "actionable_total": 0}
        self.assertTrue(continuation._exhausted(zero, {"status": "complete"}, True))
        for key in REMAINING:
            with self.subTest(key=key):
                remaining = {**zero, key: SESSION_COUNTS[key]}
                if key in ("ready_total", "review_total"):
                    remaining["actionable_total"] = remaining["ready_total"] + remaining["review_total"]
                self.assertFalse(continuation._exhausted(remaining, {"status": "complete"}, True))

    def test_two_legacy_budget_receipts_stay_historical_after_readonly_load(self):
        _, current = self.seed_partial_work(findings=True)
        counts = {key: current[key] for key in REMAINING}
        first_checkpoint = continuation.checkpoint(self.project, {"label": "Historical first budget-exit checkpoint"})
        first_stop = self.legacy_budget_record(first_checkpoint)
        second_checkpoint = continuation.checkpoint(self.project, {"label": "Historical corrected delivery checkpoint"})
        latest_stop = self.legacy_budget_record(second_checkpoint)
        self.assertEqual(first_stop["snapshot_id"], latest_stop["snapshot_id"])
        before = self.database_state()
        with Project(self.root, self.project_id) as loaded, patch.object(engine, "request") as network:
            current = engine.evaluate_coverage(loaded)["continuation"]
            self.assert_continuing(current, counts=counts)
            self.assertTrue(current["legacy_finalization_ignored"])
            self.assertEqual(latest_stop["checkpoint_id"], current["checkpoint_id"])
            self.assertEqual([first_stop, latest_stop], loaded.list("finalization"))
            for record, code in ((first_stop, "finalization_stale"), (latest_stop, "finalization_policy")):
                destination = self.root / ("rejected-legacy-" + code)
                self.assertFalse(destination.exists())
                with self.subTest(record=record["id"]), patch("awa_ddd.reproduction.prepare_reproduction") as prepare:
                    with self.assertRaises(EngineError) as caught:
                        build_report(loaded, destination, stage="final", finalization_id=record["id"])
                    self.assertEqual(code, caught.exception.code)
                    self.assert_continuing(caught.exception.details["continuation"], counts=counts)
                    prepare.assert_not_called()
                self.assertFalse(destination.exists())
            self.assertEqual(before, self.database_state(loaded))
            self.assertEqual([first_stop, latest_stop], loaded.list("finalization"))
            network.assert_not_called()
        self.assertEqual(before, self.database_state())

    def test_draft_with_legacy_budget_record_exports_only_progress_not_stop_permission(self):
        self.seed_partial_work(findings=True)
        checkpoint = continuation.checkpoint(self.project, {"label": "Legacy fixture progress snapshot"})
        record = self.legacy_budget_record(checkpoint)
        before = self.database_state()
        with patch.object(engine, "request") as network:
            draft = build_report(self.project, self.root / "legacy-draft")
            next_work = workflow.next_work(self.project, {"limit": 5})
            audit = completeness.audit(self.project, {"limit": 5})
            network.assert_not_called()
        for result in (draft, next_work, audit):
            self.assert_continuing(result["continuation"])
            self.assertTrue(result["continuation"]["legacy_finalization_ignored"])
        self.assertEqual("draft", draft["stage"])
        self.assertEqual("draft", draft["delivery_status"])
        self.assertIsNone(draft["finalization"])
        self.assertGreater(next_work["ready_total"], 0)
        self.assertGreater(next_work["review_total"], 0)
        summary = json.loads(Path(draft["summary"]).read_text(encoding="utf-8"))
        manifest = json.loads(Path(draft["manifest"]).read_text(encoding="utf-8"))
        self.assertEqual(draft["continuation"], summary["continuation"])
        self.assertEqual(summary["continuation"], manifest["continuation"])
        self.assertEqual(record, self.project.get("finalization", record["id"]))
        self.assertEqual(before, self.database_state())

    def test_live_work_without_any_stop_record_rejects_final_before_output_preparation(self):
        self.seed_partial_work()
        destination = self.root / "no-final-record"
        before = self.database_state()
        with patch.object(engine, "request") as network, patch("awa_ddd.reproduction.prepare_reproduction") as prepare:
            with self.assertRaises(EngineError) as caught:
                self.invoke("report.build", stage="final", output_dir=str(destination))
            self.assertEqual("finalization_required", caught.exception.code)
            self.assert_continuing(caught.exception.details["continuation"])
            network.assert_not_called()
            prepare.assert_not_called()
        self.assertFalse(destination.exists())
        self.assertEqual(before, self.database_state())

    def test_real_closed_obligations_still_need_two_current_complete_frontier_rounds(self):
        operation = self.operation("/finite-api", inputs=[{"name": "q", "location": "query",
            "consumer": "fixture_predicate", "test_families": ["generic"]}])
        engine.build_plan(self.project)
        baseline = self.capture(operation, url=operation["url"] + "?q=normal")
        variant = self.capture(operation, url=operation["url"] + "?q=variant")
        control = self.capture(operation, url=operation["url"] + "?q=sensitive", response={"count": 2})
        obligations = {row["kind"]: row for row in self.project.list("obligation") if row["operation_id"] == operation["id"]}
        evaluate(self.project, {"obligation_id": obligations["baseline"]["id"], "evidence_ids": [baseline["id"]],
            "oracle": {"type": "baseline", "selector": "/count", "expected": 1}})
        evaluate(self.project, {"obligation_id": obligations["input_test"]["id"],
            "evidence_ids": [baseline["id"], variant["id"], control["id"]],
            "oracle": {"type": "semantic_negative", "test_family": "generic", "selector": "/count",
                       "baseline_expected": 1, "control_expected": 2}})
        references = {"evidence_ids": [baseline["id"]]}
        frontier = {"discovery": {"status": "reviewed", "reason": "Reviewed this finite API fixture boundary.", **references},
            "pages": {"status": "api_only", "reason": "This modeled fixture declares no browser surface.", **references},
            "categories": [{"test_family": family, "status": "planned" if family == "generic" else "not_applicable",
                "reason": "Only the modeled generic predicate is applicable in this isolated fixture.", **references}
                for family in continuation.ALL_FAMILIES]}
        empty_frontier = self.invoke("plan.checkpoint", label="Closed fixture without discovery review")
        self.assertEqual("complete", empty_frontier["continuation"]["coverage_status"])
        self.assertEqual({key: 0 for key in REMAINING}, {key: empty_frontier["continuation"][key] for key in REMAINING})
        self.assert_continuing(empty_frontier["continuation"])
        with self.assertRaises(EngineError) as caught:
            self.invoke("plan.finalize", checkpoint_id=empty_frontier["checkpoint"]["id"], reason="completed",
                explanation="Closed modeled obligations alone do not prove the finite frontier was reviewed.", reviewer="fixture-reviewer")
        self.assertEqual("frontier_review_required", caught.exception.code)
        first = self.invoke("plan.checkpoint", frontier_review=frontier)
        self.assertEqual(1, first["continuation"]["frontier_rounds"])
        self.assert_continuing(first["continuation"])
        second = self.invoke("plan.checkpoint", frontier_review=frontier)
        self.assertEqual(first["checkpoint"]["snapshot_id"], second["checkpoint"]["snapshot_id"])
        self.assertEqual(2, second["continuation"]["frontier_rounds"])
        self.assertTrue(second["continuation"]["can_finalize"])
        self.assertTrue(second["continuation"]["continue_required"])
        self.assertFalse(second["continuation"]["automatic_stop_allowed"])
        with patch.object(engine, "request") as network:
            stopped = self.invoke("plan.finalize", checkpoint_id=second["checkpoint"]["id"], reason="completed",
                explanation="Only this evidence-bound finite fixture ledger is exhausted.", reviewer="fixture-reviewer")
            final = self.invoke("report.build", stage="final", finalization_id=stopped["finalization"]["id"],
                output_dir=str(self.root / "allowed-final"))
            network.assert_not_called()
        self.assertFalse(stopped["continuation"]["continue_required"])
        self.assertTrue(stopped["continuation"]["automatic_stop_allowed"])
        self.assertEqual("final-completed", final["delivery_status"])
        self.assertTrue(final["continuation"]["registered_scope_only"])
        self.assertEqual({key: 0 for key in REMAINING}, final["finalization"]["remaining"])
        self.assertEqual(1, len(self.project.list("finalization")))
        self.assertTrue(Path(final["report"]).is_file())


if __name__ == "__main__":
    unittest.main()
