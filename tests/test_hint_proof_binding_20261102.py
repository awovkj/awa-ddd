"""Hint investigation uses exact current proof, never answer-key authority."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.parse import quote

import test_continuation_20261030 as fixtures
from awa_ddd import browser, candidates, completeness, engine
from awa_ddd.__main__ import dispatch
from awa_ddd.assessment import evaluate
from awa_ddd.reporting import build_report, public_integrity_metadata, safe_metadata
from awa_ddd.store import EngineError, canonical


class HintProofBindingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ContinuationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.project, self.root = self.fixture.project, self.fixture.root
        self.serial = 0

    def import_hint(self, *, source_kind="validator_export", native=False, **changes):
        self.serial += 1
        entry = {"url": self.fixture.operation["url"], "method": "GET", "test_family": "generic",
                 "inputs": [{"name": "q", "location": "query"}], "result": "valid", **changes}
        if native:
            document = {"version": "fixture-v1", "maxScore": 1, "vulns": [
                [entry["url"], [[row["name"], row.get("declared_location", "GET")] for row in entry["inputs"]],
                 entry.get("type", "XXE"), 1]]}
        else:
            document = {"schema_version": 1, "source_kind": source_kind, "entries": [entry]}
        source = self.root / ("hint-" + str(self.serial) + ".json")
        source.write_text(canonical(document), encoding="utf-8")
        with patch.object(engine, "request") as network:
            result = dispatch(self.root, "surface.import", {"project_id": "continuation", "format": "assessment_hints",
                "path": str(source), "base_url": self.fixture.base})
        network.assert_not_called()
        self.assertEqual([], result["operation_ids"])
        return next(row for row in self.project.list("candidate")
                    if row["sources"][0]["path"] == str(source.resolve()))

    def generic_decision(self):
        self.fixture.close_generic()
        return self.project.get("decision", self.fixture.obligation("input_test")["decision_id"])

    def link(self, candidate, *, operation=None, **changes):
        with patch.object(engine, "request") as network:
            result = dispatch(self.root, "candidate.link", {"project_id": "continuation", "candidate_id": candidate["id"],
                "operation_id": (operation or self.fixture.operation)["id"], **changes})
        network.assert_not_called()
        return result

    def audit(self):
        with patch.object(engine, "request") as network:
            result = dispatch(self.root, "plan.audit", {"project_id": "continuation", "limit": 100})
        network.assert_not_called()
        self.assertEqual(0, result["requests_sent"])
        return result

    def state(self):
        return {table: [tuple(row) for row in self.project.connection.execute("SELECT * FROM " + table + " ORDER BY 1,2")]
                for table in ("entities", "events", "metadata")}

    def rejection(self, candidate, **changes):
        before = self.state()
        with self.assertRaises(EngineError) as caught:
            self.link(candidate, **changes)
        self.assertIn(caught.exception.code, {"candidate_closure", "candidate_input", "candidate_scope"})
        self.assertEqual(before, self.state())

    def test_link_without_explicit_proof_stays_unresolved_even_when_input_is_tested(self):
        self.generic_decision()
        candidate = self.import_hint()
        result = self.link(candidate, input_location="query", input_selector="q")
        self.assertEqual("linked", result["status"])
        self.assertNotIn("candidate_closure", result)
        self.assertEqual(1, self.audit()["completion"]["unresolved_candidates"])

    def test_exact_normalized_hint_can_be_reviewed_without_new_security_records_or_requests(self):
        decision = self.generic_decision()
        candidate = self.import_hint()
        before = self.project.list("evidence"), self.project.list("decision"), self.project.list("finding")
        result = self.link(candidate, proof_decision_ids=[decision["id"]], input_location="query", input_selector="q")
        self.assertEqual("linked", result["status"])
        self.assertEqual("assessed_hint", result["candidate_closure"]["basis"])
        self.assertEqual([decision["id"]], result["candidate_closure"]["decision_ids"])
        self.assertFalse(result["usable_for_confirmation"])
        self.assertNotIn("candidate_closure_context", result)
        audit = self.audit()
        self.assertEqual(0, audit["completion"]["unresolved_candidates"])
        self.assertEqual(1, audit["candidate_proof_accounted"])
        self.assertEqual(before, (self.project.list("evidence"), self.project.list("decision"), self.project.list("finding")))

    def test_a_baseline_or_validator_result_is_not_hint_proof(self):
        evidence = self.fixture.capture()
        baseline = self.fixture.baseline(evidence)
        candidate = self.import_hint()
        self.rejection(candidate, proof_decision_ids=[baseline["id"]])
        self.assertEqual("unverified", self.project.get("candidate", candidate["id"])["status"])
        self.assertEqual(1, self.audit()["completion"]["unresolved_candidates"])

    def test_missing_method_cannot_be_refuted_from_parameter_location_or_one_tested_method(self):
        decision = self.generic_decision()
        candidate = self.import_hint(method=None)
        self.rejection(candidate, proof_decision_ids=[decision["id"]])
        self.assertIsNone(self.project.get("candidate", candidate["id"])["method"])

    def test_native_hint_needs_an_independent_positive_at_the_exact_input(self):
        operation = self.fixture.register("/xml", inputs=[{
            "name": "xml", "location": "query", "consumer": "xml_parser", "test_families": ["xxe"]}])
        item = next(row for row in self.project.list("obligation") if row["operation_id"] == operation["id"]
                    and row["kind"] == "input_test" and not row.get("superseded"))
        payloads = ['<!DOCTYPE doc [<!ENTITY sample SYSTEM "file:///fixture/canary.txt">]><doc>&sample;</doc>',
                    "<doc>normal</doc>"]
        evidence = [self.fixture.capture(operation, url=operation["url"] + "?xml=" + quote(payload, safe=""),
            response={"data": {"preview": value}}) for payload, value in zip(payloads, ("FIXTURE-CANARY", "normal"))]
        decision = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in evidence],
            "oracle": {"type": "extraction", "test_family": "xxe", "selector": "/data/preview", "expect": "^FIXTURE-CANARY$",
                       "expected_value": "FIXTURE-CANARY", "source_reference": "file:///fixture/canary.txt"}})
        candidate = self.import_hint(native=True, url=operation["url"], inputs=[{"name": "xml", "location": "query"}], type="XXE")
        result = self.link(candidate, operation=operation, proof_decision_ids=[decision["id"]])
        self.assertIsNone(result["method"])
        self.assertEqual("assessed_hint", result["candidate_closure"]["basis"])
        self.assertEqual(0, self.audit()["completion"]["unresolved_candidates"])
        self.assertEqual([], self.project.list("finding"))
        self.assertGreater(self.audit()["completion"]["unrecorded_confirmations"], 0)

    def test_wrong_url_method_input_family_or_branch_cannot_borrow_coverage(self):
        decision = self.generic_decision()
        cases = ({"method": "POST"}, {"url": self.fixture.base + "/different"}, {"test_family": "xxe"},
                 {"inputs": [{"name": "other", "location": "query"}]},
                 {"inputs": [{"name": "q", "location": "body"}]})
        for changes in cases:
            with self.subTest(changes=changes):
                self.rejection(self.import_hint(**changes), proof_decision_ids=[decision["id"]])
        candidate = self.import_hint()
        changed = deepcopy(candidate)
        changed["inputs"][0]["schema_branch"] = "unobserved-branch"
        self.project.put("candidate", changed)
        self.rejection(changed, proof_decision_ids=[decision["id"]])

    def test_a_negative_for_one_rce_mechanism_does_not_refute_all_hypotheses(self):
        families = ["command_injection", "template_injection", "deserialization"]
        operation = self.fixture.register("/rce", inputs=[{
            "name": "q", "location": "query", "consumer": "business_input", "test_families": families}])
        evidence = [self.fixture.capture(operation, url=operation["url"] + "?q=" + value, response={"count": count})
                    for value, count in (("normal", 1), ("variant", 1), ("sensitive", 2))]
        candidate = self.import_hint(url=operation["url"], test_family=None, type="RCE")
        decisions = []
        for family in families:
            item = next(row for row in self.project.list("obligation") if row["operation_id"] == operation["id"]
                        and row.get("test_family") == family and not row.get("superseded"))
            decision = evaluate(self.project, {"obligation_id": item["id"], "evidence_ids": [row["id"] for row in evidence],
                "oracle": {"type": "semantic_negative", "test_family": family, "selector": "/count",
                           "baseline_expected": 1, "control_expected": 2}})
            decisions.append(decision["id"])
            if len(decisions) < len(families):
                self.rejection(candidate, operation=operation, proof_decision_ids=list(decisions))
        self.link(candidate, operation=operation, proof_decision_ids=decisions)
        self.assertEqual(0, self.audit()["completion"]["unresolved_candidates"])

    def test_all_declared_inputs_need_proof_not_just_the_first_parameter(self):
        decision = self.generic_decision()
        operation = engine.register_operation(self.project, {**self.fixture.operation, "inputs": [
            {"name": "other", "location": "query", "consumer": "business_input", "test_families": ["generic"]}]})
        engine.build_plan(self.project)
        candidate = self.import_hint(inputs=[{"name": "q", "location": "query"}, {"name": "other", "location": "query"}])
        self.rejection(candidate, operation=operation, proof_decision_ids=[decision["id"]])

    def test_client_sink_name_matches_do_not_qualify_for_hint_closure(self):
        decision = self.generic_decision()
        candidate = self.import_hint()
        changed = {**candidate, "kind": "client_sink", "test_family": "generic", "taint_proven": False}
        self.project.put("candidate", changed)
        self.rejection(changed, proof_decision_ids=[decision["id"]])

    def test_evidence_or_source_context_change_reopens_review_without_rewriting_receipt(self):
        decision = self.generic_decision()
        candidate = self.import_hint()
        self.link(candidate, proof_decision_ids=[decision["id"]])
        saved = self.project.get("candidate", candidate["id"])
        evidence = self.project.get("evidence", decision["evidence_ids"][0])
        path = self.project.base / evidence["artifact_path"]
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        self.assertEqual(1, self.audit()["completion"]["unresolved_candidates"])
        self.assertEqual(saved, self.project.get("candidate", candidate["id"]))
        path.write_bytes(original)
        self.assertEqual(0, self.audit()["completion"]["unresolved_candidates"])
        incoming = deepcopy(candidate)
        incoming["sources"].append({**incoming["sources"][0], "locator": "#/entries/extra"})
        candidates.store_candidate(self.project, incoming)
        self.assertEqual(1, self.audit()["completion"]["unresolved_candidates"])
        self.assertEqual(saved["candidate_closure"], self.project.get("candidate", candidate["id"])["candidate_closure"])

    def test_imported_or_malformed_receipts_never_poison_audit_or_inherit_proof(self):
        decision = self.generic_decision()
        candidate = self.import_hint()
        self.link(candidate, proof_decision_ids=[decision["id"]])
        saved = self.project.get("candidate", candidate["id"])
        for receipt in (None, [], {"version": True, "basis": "assessed_hint"},
                        {**saved["candidate_closure"], "decision_ids": []},
                        {**saved["candidate_closure"], "decision_ids": [{}]},
                        {**saved["candidate_closure"], "force": True}):
            with self.subTest(receipt=receipt):
                self.project.put("candidate", {**saved, "candidate_closure": receipt})
                self.assertEqual(1, self.audit()["completion"]["unresolved_candidates"])
        incoming = {**saved, "sources": [{**saved["sources"][0], "locator": "#/entries/new"}]}
        identity, created = candidates.store_candidate(self.project, incoming)
        self.assertTrue(created)
        imported = self.project.get("candidate", identity)
        self.assertNotIn("candidate_closure", imported)
        self.assertNotIn("candidate_closure_context", imported)

    def test_relink_without_proof_and_reopen_drop_the_current_receipt(self):
        decision = self.generic_decision()
        candidate = self.import_hint()
        self.link(candidate, proof_decision_ids=[decision["id"]])
        self.link(candidate)
        self.assertEqual(1, self.audit()["completion"]["unresolved_candidates"])
        self.link(candidate, proof_decision_ids=[decision["id"]])
        result = dispatch(self.root, "candidate.reopen", {"project_id": "continuation", "candidate_id": candidate["id"],
            "reason": "Recheck the original source and current proof."})
        self.assertNotIn("candidate_closure", result)
        self.assertNotIn("candidate_closure_context", result)
        self.assertEqual(1, self.audit()["completion"]["unresolved_candidates"])

    def test_malformed_legacy_kind_stays_reviewable_instead_of_poisoning_audit(self):
        candidate = self.import_hint()
        for kind in (None, [], {}):
            with self.subTest(kind=kind):
                changed = {**candidate, "kind": kind}
                self.project.put("candidate", changed)
                self.assertFalse(candidates.hint_proof_valid(self.project, changed, {}))
                self.assertEqual(1, self.audit()["completion"]["unresolved_candidates"])

    def test_receipt_controls_survive_secret_collision_without_exposing_private_context(self):
        decision = self.generic_decision()
        candidate = self.import_hint()
        url = self.fixture.base + "/context"
        raw = {"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1},
               "network": [{"url": url, "method": "GET", "status": 200}],
               "actions": [{"type": "fill", "selector": "#private", "ok": True, "value": "assessed_hint", "finalUrl": url}]}
        source = self.root / "context.json"
        source.write_text(canonical(raw), encoding="utf-8")
        browser.import_observation(self.project, {"path": str(source)})
        self.link(candidate, proof_decision_ids=[decision["id"]])
        result = dispatch(self.root, "candidate.inspect", {"project_id": "continuation", "candidate_id": candidate["id"]})
        self.assertEqual("assessed_hint", result["candidate"]["candidate_closure"]["basis"])
        self.assertEqual([decision["id"]], result["candidate"]["candidate_closure"]["decision_ids"])
        saved = self.project.get("candidate", candidate["id"])
        for projection in (result, public_integrity_metadata(saved), safe_metadata(saved)):
            self.assertNotIn("candidate_closure_context", canonical(projection))

    def test_reviewed_hint_provenance_stays_separate_from_runtime_findings_in_reports(self):
        decision = self.generic_decision()
        candidate = self.import_hint(source_kind="assessment_checklist")
        self.link(candidate, proof_decision_ids=[decision["id"]])
        with patch.object(engine, "request") as network:
            report = build_report(self.project)
        network.assert_not_called()
        summary = json.loads(Path(report["summary"]).read_text(encoding="utf-8"))
        self.assertEqual(0, summary["unverified_candidates"])
        self.assertEqual(1, summary["verification_assurance"]["hint_only"])
        self.assertEqual(0, summary["verification_assurance"]["runtime_verified"])
        self.assertFalse(summary["verification_assurance"]["hints_count_as_findings"])

    def test_reviewed_hint_still_requires_current_frontier_rounds_and_stale_evidence_reopens_stop(self):
        decision = self.generic_decision()
        candidate = self.import_hint()
        self.link(candidate, proof_decision_ids=[decision["id"]])
        self.assertFalse(self.audit()["continuation"]["can_finalize"])
        self.fixture.checkpoint(self.fixture.frontier())
        checkpoint = self.fixture.checkpoint(self.fixture.frontier())
        final = self.fixture.finish(checkpoint)
        self.assertTrue(final["continuation"]["automatic_stop_allowed"])
        evidence = self.project.get("evidence", decision["evidence_ids"][1])
        (self.project.base / evidence["artifact_path"]).write_bytes(b"changed synthetic evidence")
        self.assertFalse(self.audit()["continuation"]["automatic_stop_allowed"])
        self.assertEqual(1, self.audit()["completion"]["unresolved_candidates"])


if __name__ == "__main__":
    unittest.main()
