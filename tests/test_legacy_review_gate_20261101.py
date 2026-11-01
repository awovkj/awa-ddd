"""Current offline review gates revalidate real engine-created legacy receipts."""
from __future__ import annotations

from copy import deepcopy
import json
import unittest
from unittest.mock import patch

import test_continuation_20261030 as fixtures
from awa_ddd import browser, completeness, continuation, engine
from awa_ddd.__main__ import dispatch
from awa_ddd.store import EngineError


class LegacyReviewGateTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ContinuationTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.project = self.fixture.project

    def browser_import(self, *, success=True):
        url = self.fixture.base + "/legacy-reviewed-page"
        raw = {"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1},
               "network": [{"url": url, "method": "GET", "status": 200}]}
        if not success:
            raw["error"] = "This isolated read-only observation failed after receiving a response."
        source = self.fixture.root / "legacy-review-page.json"
        source.write_text(json.dumps(raw), encoding="utf-8")
        with patch.object(engine, "request") as network, patch.object(browser.subprocess, "run") as runtime:
            result = dispatch(self.fixture.root, "browser.import_mcp", {
                "project_id": self.project.project_id, "path": str(source)})
        network.assert_not_called()
        runtime.assert_not_called()
        return result

    def review(self, row, **changes):
        args = {"project_id": self.project.project_id, "checklist_id": row["id"], "status": "reviewed",
                "reviewer": "isolated-current-reviewer", "reason": "Review existing fixture material without replay."}
        args.update(changes)
        with patch.object(engine, "request") as network, patch.object(browser.subprocess, "run") as runtime:
            result = dispatch(self.fixture.root, "plan.review", args)
        network.assert_not_called()
        runtime.assert_not_called()
        return result

    def audit(self):
        with patch.object(engine, "request") as network, patch.object(browser.subprocess, "run") as runtime:
            result = dispatch(self.fixture.root, "plan.audit", {"project_id": self.project.project_id, "limit": 100})
        network.assert_not_called()
        runtime.assert_not_called()
        self.assertEqual(0, result["requests_sent"])
        return result

    def read_operation(self):
        return self.fixture.register("/current-business-readback", inputs=[{
            "name": "id", "location": "query", "consumer": "resource_reference"}])

    def readback(self, operation, *, external="7", response=None):
        resource = engine.add_resource(self.project, {
            "operation_id": operation["id"], "owner_actor_id": "alice", "external_id": external,
            "request_binding": {"location": "query", "selector": "id"}})
        evidence = self.fixture.capture(operation, resource_id=resource["id"],
            url=operation["url"] + "?id=" + external, response={"balance": 10} if response is None else response)
        return resource, evidence

    def write_and_read(self, *, response=None):
        _, resource, run = self.fixture.write_fixture()
        read_resource, read = self.readback(self.read_operation(), response=response)
        return resource, run, read_resource, read

    def binding(self, source, read_resource, *, selector="/balance", expected=10):
        return {"source_resource_id": source["id"], "resource_id": read_resource["id"],
                "relation": "Current isolated fixture business state", "selector": selector, "expected": expected}

    def legacy_write_receipt(self, run, read, bindings):
        row = self.fixture.checklist("unreconciled_run", run["id"])
        saved = [dict(binding, evidence_ids=[read["id"]]) for binding in bindings]
        # Simulate only the earlier business-state gate. The public engine still
        # creates and persists the real source/support signatures and event.
        with patch.object(continuation, "_readback_bindings", return_value=deepcopy(saved)):
            receipt = self.review(row, evidence_ids=[read["id"]], readback_bindings=bindings,
                                  reason="Engine receipt under the simulated earlier business-state review gate.")
        private = self.project.get("closure_review", receipt["review"]["id"])
        self.assertTrue(continuation._review_valid(self.project, private, self.project.get("run", run["id"])))
        return private

    def assert_legacy_write_retained(self, run, receipt):
        before = deepcopy(receipt)
        audit = self.audit()
        row = next(item for item in audit["checklist"] if item.get("run_id") == run["id"])
        self.assertEqual("open", row["status"])
        self.assertEqual([], row.get("missing_prerequisites", []))
        self.assertEqual(1, audit["completion"]["unreconciled_runs"])
        self.assertEqual(0, audit["administrative_reviews"])
        self.assertTrue(audit["continuation"]["continue_required"])
        self.assertFalse(audit["continuation"]["automatic_stop_allowed"])
        self.assertEqual(before, self.project.get("closure_review", receipt["id"]))
        self.assertEqual("failed", self.project.get("run", run["id"])["status"])
        return row

    def test_current_successful_readonly_orphan_cannot_be_hidden_by_a_legacy_archive(self):
        self.fixture.close_generic()
        visit = self.browser_import()
        row = self.fixture.checklist("orphan_browser_visit", visit["id"])
        with self.assertRaises(EngineError) as caught:
            self.review(row)
        self.assertEqual("page_adoption_required", caught.exception.code)
        before_obligations, before_decisions = self.project.list("obligation"), self.project.list("decision")
        # Only the earlier adoption check is absent while minting this receipt;
        # hashes and documents are produced by real public dispatch, not forged.
        with patch.object(browser, "_verified_visit", side_effect=EngineError("legacy_policy", "Earlier adoption check unavailable")):
            receipt = self.review(row, reason="Receipt minted under the simulated earlier browser-adoption policy.")
        private = self.project.get("closure_review", receipt["review"]["id"])
        self.assertTrue(continuation._review_valid(self.project, private, self.project.get("page_visit", visit["id"])))
        audit = self.audit()
        current = next(item for item in audit["checklist"] if item.get("page_visit_id") == visit["id"])
        self.assertEqual("open", current["status"])
        self.assertEqual("page.adopt", current["suggested_action"])
        self.assertFalse(current["administrative_review_allowed"])
        self.assertEqual(1, audit["completion"]["orphan_browser_visits"])
        self.assertEqual(0, audit["administrative_reviews"])
        self.assertEqual(1, audit["continuation"]["review_total"])
        self.assertEqual(private, self.project.get("closure_review", private["id"]))
        with patch.object(engine, "request") as network, patch.object(browser.subprocess, "run") as runtime:
            adopted = dispatch(self.fixture.root, "page.adopt", {
                "project_id": self.project.project_id, **current["input_template"]})
        network.assert_not_called()
        runtime.assert_not_called()
        self.assertEqual(0, adopted["requests_sent"])
        self.assertEqual(1, adopted["pages_adopted"])
        self.assertEqual(1, browser.coverage(self.project)["pages_visited"])
        self.assertEqual(before_obligations, self.project.list("obligation"))
        self.assertEqual(before_decisions, self.project.list("decision"))
        self.assertEqual(private, self.project.get("closure_review", private["id"]))

    def test_current_failed_readonly_browser_archive_remains_valid_without_page_coverage(self):
        visit = self.browser_import(success=False)
        row = self.fixture.checklist("orphan_browser_visit", visit["id"])
        receipt = self.review(row)
        private = self.project.get("closure_review", receipt["review"]["id"])
        self.assertTrue(continuation._review_valid(self.project, private, self.project.get("page_visit", visit["id"])))
        audit = self.audit()
        self.assertEqual(0, audit["completion"]["orphan_browser_visits"])
        self.assertEqual(1, audit["administrative_reviews"])
        self.assertEqual(0, browser.coverage(self.project)["pages_visited"])
        self.assertEqual(0, receipt["security_obligations_closed"])
        self.assertEqual(private, self.project.get("closure_review", private["id"]))

    def test_legacy_ok_only_readback_receipt_does_not_close_an_uncertain_write(self):
        source, run, read_resource, read = self.write_and_read(response={"ok": True, "balance": 10})
        bad = self.binding(source, read_resource, selector="/ok", expected=True)
        row = self.fixture.checklist("unreconciled_run", run["id"])
        with self.assertRaises(EngineError) as caught:
            self.review(row, evidence_ids=[read["id"]], readback_bindings=[bad])
        self.assertEqual("reconciliation_evidence", caught.exception.code)
        receipt = self.legacy_write_receipt(run, read, [bad])
        self.assert_legacy_write_retained(run, receipt)

    def test_legacy_wrong_business_state_is_not_authorized_by_any_existing_readback(self):
        source, run, read_resource, read = self.write_and_read()
        bad = self.binding(source, read_resource, expected=999)
        receipt = self.legacy_write_receipt(run, read, [bad])
        row = self.assert_legacy_write_retained(run, receipt)
        valid = self.binding(source, read_resource)
        reviewed = self.review(row, evidence_ids=[read["id"]], readback_bindings=[valid])
        self.assertEqual(0, reviewed["completion"]["unreconciled_runs"])
        self.assertEqual(0, reviewed["security_obligations_closed"])
        self.assertEqual(receipt, self.project.get("closure_review", receipt["id"]))
        self.assertEqual("failed", self.project.get("run", run["id"])["status"])

    def test_legacy_earlier_readback_stays_unresolved_when_a_different_later_read_exists(self):
        engine.add_actor(self.project, {"actor_id": "alice", "subject": "alice", "roles": []})
        read_operation = self.read_operation()
        read_resource, earlier = self.readback(read_operation)
        _, source, run = self.fixture.write_fixture()
        later_resource, later = self.readback(read_operation)
        self.assertLess(engine.stamp(self.project.read_artifact(earlier)["started_at"]), engine.stamp(run["finished_at"]))
        bad = self.binding(source, read_resource)
        receipt = self.legacy_write_receipt(run, earlier, [bad])
        row = self.assert_legacy_write_retained(run, receipt)
        reviewed = self.review(row, evidence_ids=[later["id"]], readback_bindings=[self.binding(source, later_resource)])
        self.assertEqual(0, reviewed["completion"]["unreconciled_runs"])
        self.assertEqual(receipt, self.project.get("closure_review", receipt["id"]))

    def test_legacy_foreign_fixture_readback_is_not_equivalent_to_the_real_later_fixture(self):
        source, run, read_resource, read = self.write_and_read()
        foreign_resource, foreign = self.readback(self.read_operation(), external="99")
        bad = self.binding(source, foreign_resource)
        receipt = self.legacy_write_receipt(run, foreign, [bad])
        row = self.assert_legacy_write_retained(run, receipt)
        with self.assertRaises(EngineError) as caught:
            self.review(row, evidence_ids=[foreign["id"]], readback_bindings=[bad])
        self.assertEqual("reconciliation_context", caught.exception.code)
        reviewed = self.review(row, evidence_ids=[read["id"]], readback_bindings=[self.binding(source, read_resource)])
        self.assertEqual(0, reviewed["completion"]["unreconciled_runs"])
        self.assertEqual(receipt, self.project.get("closure_review", receipt["id"]))

    def test_legacy_empty_readback_bindings_do_not_archive_an_intact_uncertain_run(self):
        _, run, _, read = self.write_and_read()
        receipt = self.legacy_write_receipt(run, read, [])
        self.assert_legacy_write_retained(run, receipt)

    def test_current_wrapped_metadata_is_not_concrete_business_readback(self):
        for acknowledgement in ({"ok": True, "status": 200}, [{"ok": True}, {"status": 200}],
                                {"data": {"ok": True, "code": 200}}, ["ok", "success"],
                                {"data": ["OK", "permission denied"]}):
            with self.subTest(acknowledgement=acknowledgement):
                source, run, read_resource, read = self.write_and_read(response={"state": acknowledgement})
                row = self.fixture.checklist("unreconciled_run", run["id"])
                before = self.project.list("closure_review")
                with self.assertRaises(EngineError) as caught:
                    self.review(row, evidence_ids=[read["id"]], readback_bindings=[
                        self.binding(source, read_resource, selector="/state", expected=acknowledgement)])
                self.assertEqual("reconciliation_evidence", caught.exception.code)
                self.assertEqual(before, self.project.list("closure_review"))

    def test_legacy_wrapped_metadata_receipt_is_revalidated_as_unfinished(self):
        acknowledgement = {"ok": True, "status": 200}
        source, run, read_resource, read = self.write_and_read(response={"state": acknowledgement})
        bad = self.binding(source, read_resource, selector="/state", expected=acknowledgement)
        receipt = self.legacy_write_receipt(run, read, [bad])
        self.assert_legacy_write_retained(run, receipt)

    def test_legacy_acknowledgement_string_array_does_not_establish_business_state(self):
        acknowledgement = ["ok", "success"]
        source, run, read_resource, read = self.write_and_read(response={"state": acknowledgement})
        bad = self.binding(source, read_resource, selector="/state", expected=acknowledgement)
        receipt = self.legacy_write_receipt(run, read, [bad])
        self.assert_legacy_write_retained(run, receipt)

    def test_current_structured_business_state_with_zero_and_boolean_remains_valid(self):
        state = {"balance": 0, "enabled": True}
        source, run, read_resource, read = self.write_and_read(response={"state": state})
        row = self.fixture.checklist("unreconciled_run", run["id"])
        reviewed = self.review(row, evidence_ids=[read["id"]], readback_bindings=[
            self.binding(source, read_resource, selector="/state", expected=state)])
        self.assertEqual(0, reviewed["completion"]["unreconciled_runs"])
        self.assertEqual(0, reviewed["security_obligations_closed"])
        self.assertEqual("failed", self.project.get("run", run["id"])["status"])

    def test_current_valid_business_readback_is_revalidated_and_preserves_the_run(self):
        source, run, read_resource, read = self.write_and_read(response={"balance": 0})
        row = self.fixture.checklist("unreconciled_run", run["id"])
        reviewed = self.review(row, evidence_ids=[read["id"]], readback_bindings=[self.binding(source, read_resource, expected=0)])
        self.assertEqual(0, reviewed["completion"]["unreconciled_runs"])
        self.assertEqual(0, reviewed["security_obligations_closed"])
        private = self.project.get("closure_review", reviewed["review"]["id"])
        with patch.object(continuation, "_readback_bindings", wraps=continuation._readback_bindings) as gate:
            audit = self.audit()
        self.assertGreater(gate.call_count, 0)
        self.assertEqual(0, audit["completion"]["unreconciled_runs"])
        self.assertEqual("failed", self.project.get("run", run["id"])["status"])
        self.assertEqual(private, self.project.get("closure_review", private["id"]))

    def test_current_boolean_business_expectation_cannot_match_numeric_state(self):
        for actual, expected in ((1, True), (0, False), (True, 1), (False, 0)):
            with self.subTest(actual=actual, expected=expected):
                source, run, read_resource, read = self.write_and_read(response={"balance": actual})
                row = self.fixture.checklist("unreconciled_run", run["id"])
                before = self.project.list("closure_review")
                with self.assertRaises(EngineError) as caught:
                    self.review(row, evidence_ids=[read["id"]], readback_bindings=[self.binding(source, read_resource, expected=expected)])
                self.assertEqual("reconciliation_evidence", caught.exception.code)
                self.assertEqual(before, self.project.list("closure_review"))

    def test_legacy_boolean_number_alias_is_rechecked_in_nested_business_state(self):
        source, run, read_resource, read = self.write_and_read(response={"state": {"balance": [1, 0]}})
        bad = self.binding(source, read_resource, selector="/state", expected={"balance": [True, False]})
        receipt = self.legacy_write_receipt(run, read, [bad])
        self.assert_legacy_write_retained(run, receipt)

    def test_actual_boolean_business_state_remains_a_valid_current_readback(self):
        source, run, read_resource, read = self.write_and_read(response={"enabled": True})
        row = self.fixture.checklist("unreconciled_run", run["id"])
        reviewed = self.review(row, evidence_ids=[read["id"]], readback_bindings=[self.binding(source, read_resource, selector="/enabled", expected=True)])
        self.assertEqual(0, reviewed["completion"]["unreconciled_runs"])
        self.assertEqual(0, reviewed["security_obligations_closed"])
        self.assertEqual("failed", self.project.get("run", run["id"])["status"])


if __name__ == "__main__":
    unittest.main()
