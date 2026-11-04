"""Small planning pages retain exact consumer and saved-evidence handoffs."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from awa_ddd import engine
from awa_ddd.__main__ import dispatch
from awa_ddd.assessment_preparation import prepare
import test_workflow_20261029 as fixtures


class WorkflowReviewHandoffTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.WorkflowTests("test_next_work_is_offline_and_does_not_close_obligations")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.project = self.fixture.project

    def operation(self, path, **extra):
        operation = self.fixture.operation(path, **extra)
        engine.build_plan(self.project)
        return operation

    def input_operation(self, path, family, *, auth="public"):
        consumers = {"sql_injection": "sql_query", "xss": "html_render", "ssrf": "outbound_http"}
        return self.operation(path, auth=auth,
            inputs=[{"name": "q", "location": "query", "consumer": consumers[family], "test_families": [family]}])

    def snapshot(self):
        return {"config": self.project.config, **{kind: self.project.list(kind) for kind in
            ("operation", "obligation", "actor", "session", "resource", "evidence", "run", "decision", "finding", "closure_review", "checkpoint")}}

    def next(self, **args):
        return dispatch(self.project.workspace, "plan.next", {"project_id": self.project.project_id, **args})

    def test_unknown_input_has_an_exact_public_consumer_template_without_declaring_it(self):
        operation = self.operation("/billing", inputs=[{"name": "amount", "location": "query", "consumer": "unknown"}])
        before = self.snapshot()
        with patch.object(engine, "request") as network:
            result = self.next(limit=3)
            row = next(item for item in result["work_items"] if item["obligation_kind"] == "input_review")
            prepared = prepare(self.project, {"obligation_id": row["obligation_id"]})["items"][0]
        network.assert_not_called()
        self.assertEqual(before, self.snapshot())
        self.assertEqual({"operation_id": operation["id"], "input_location": "query", "input_selector": "amount"}, row["input_template"])
        self.assertEqual(prepared["input_template"], row["input_template"])
        self.assertEqual("surface.declare_consumer", row["suggested_action"])
        self.assertIn("consumer", row["required_experiment_fields"])
        self.assertTrue(any("source" in field and "hints are not evidence" in field for field in row["required_experiment_fields"]))
        self.assertTrue(row["hints_only"])
        self.assertNotIn("consumer", row["input_template"])
        self.assertTrue(result["continuation"]["continue_required"])

    def test_shared_selectors_keep_the_exact_schema_branch_in_each_template(self):
        operation = self.operation("/schema", method="POST", content_type="application/json", inputs=[
            {"name": "amount", "location": "body", "selector": "/amount", "schema_branch": branch, "consumer": "unknown"}
            for branch in ("branch-a", "branch-b")])
        before = self.snapshot()
        with patch.object(engine, "request") as network:
            result = self.next(limit=3)
        network.assert_not_called()
        rows = [row for row in result["work_items"] if row["obligation_kind"] == "input_review"]
        self.assertEqual({"branch-a", "branch-b"}, {row["input_template"]["schema_branch"] for row in rows})
        for row in rows:
            self.assertEqual({"operation_id": operation["id"], "input_location": "body", "input_selector": "/amount",
                              "schema_branch": row["schema_branch"]}, row["input_template"])
            self.assertNotIn("consumer", row["input_template"])
        self.assertEqual(before, self.snapshot())

    def test_three_item_page_exposes_saved_security_review_and_unknown_consumer(self):
        fresh = self.input_operation("/fresh-sql", "sql_injection")
        self.input_operation("/fresh-xss", "xss")
        self.input_operation("/fresh-ssrf", "ssrf")
        reviewed = self.input_operation("/saved-ssrf", "ssrf")
        controls = [self.fixture.captured(reviewed, url=reviewed["url"] + "?q=" + value) for value in ("normal", "variant")]
        unknown = self.operation("/unknown", inputs=[{"name": "amount", "location": "query", "consumer": "unknown"}])
        before = self.snapshot()
        with patch.object(engine, "request") as network:
            result = self.next(limit=3)
            again = self.next(limit=3)
            full = self.next(limit=25)
        network.assert_not_called()
        self.assertEqual(before, self.snapshot())
        rows = result["work_items"]
        self.assertEqual(fresh["id"], rows[0]["operation_id"])
        self.assertFalse(rows[0]["selected_input_variant_observed"])
        review = next(row for row in rows if row.get("control_candidate_review_required"))
        self.assertEqual(reviewed["id"], review["operation_id"])
        self.assertEqual("evidence.inspect", review["suggested_action"])
        self.assertEqual([row["id"] for row in controls], review["control_candidate_evidence_ids"])
        consumer = next(row for row in rows if row["obligation_kind"] == "input_review")
        self.assertEqual(unknown["id"], consumer["operation_id"])
        self.assertEqual("surface.declare_consumer", consumer["suggested_action"])
        self.assertEqual([row["gap_id"] for row in rows], [row["gap_id"] for row in again["work_items"]])
        self.assertEqual([row["gap_id"] for row in rows], [row["gap_id"] for row in full["work_items"][:3]])
        self.assertEqual(full["queue_total"], len({row["gap_id"] for row in full["work_items"]}))
        self.assertEqual({"sql_injection", "xss", "ssrf"}, {row["hypothesis_family"] for row in full["work_items"] if row["obligation_kind"] == "input_test"})
        self.assertEqual("coverage_first", result["queue_policy"])
        self.assertEqual("family_and_operation_round_robin", result["queue_fairness"])
        self.assertTrue(result["continuation"]["continue_required"])
        self.assertEqual(0, result["security_coverage"]["evaluated"])

    def test_unknown_consumer_gets_a_slot_when_no_saved_review_exists(self):
        fresh = self.input_operation("/fresh-sql", "sql_injection")
        self.input_operation("/fresh-xss", "xss")
        self.input_operation("/fresh-ssrf", "ssrf")
        self.operation("/unknown", inputs=[{"name": "amount", "location": "query", "consumer": "unknown"}])
        result = self.next(limit=3)
        self.assertEqual(fresh["id"], result["work_items"][0]["operation_id"])
        self.assertTrue(any(row["obligation_kind"] == "input_review" for row in result["work_items"]))
        self.assertFalse(any(row.get("control_candidate_review_required") for row in result["work_items"]))

    def test_saved_review_gets_a_slot_when_no_unknown_consumer_exists(self):
        self.input_operation("/fresh-sql", "sql_injection")
        self.input_operation("/fresh-xss", "xss")
        self.input_operation("/fresh-ssrf", "ssrf")
        reviewed = self.input_operation("/saved-ssrf", "ssrf")
        for value in ("normal", "variant"):
            self.fixture.captured(reviewed, url=reviewed["url"] + "?q=" + value)
        result = self.next(limit=3)
        self.assertTrue(any(row.get("control_candidate_review_required") and row["operation_id"] == reviewed["id"]
                            for row in result["work_items"]))

    def test_promoted_expired_session_review_keeps_execution_blocked(self):
        session = self.fixture.session()
        self.input_operation("/fresh-sql", "sql_injection")
        self.input_operation("/fresh-xss", "xss")
        self.input_operation("/fresh-ssrf", "ssrf")
        reviewed = self.input_operation("/saved-authenticated", "ssrf", auth="authenticated")
        for value in ("normal", "variant"):
            self.fixture.captured(reviewed, url=reviewed["url"] + "?q=" + value, session_id=session["id"])
        session["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        self.project.put("session", session)
        self.operation("/unknown", inputs=[{"name": "amount", "location": "query", "consumer": "unknown"}])
        before = self.snapshot()
        with patch.object(engine, "request") as network:
            result = self.next(limit=3)
        network.assert_not_called()
        review = next(row for row in result["work_items"] if row["suggested_action"] == "evidence.inspect")
        evidence = self.project.get("evidence", review["input_template"]["evidence_id"])
        self.assertEqual(session["id"], evidence["session_id"])
        self.assertEqual(review["operation_id"], evidence["operation_id"])
        self.assertEqual("review", review["queue_status"])
        self.assertEqual("evidence.inspect", review["suggested_action"])
        self.assertTrue(review["execution_blocked"])
        self.assertTrue({"live_verified_allowed_session", "verified_allowed_baseline"}.intersection(review["missing_prerequisites"]))
        self.assertEqual(before, self.snapshot())


if __name__ == "__main__":
    unittest.main()
