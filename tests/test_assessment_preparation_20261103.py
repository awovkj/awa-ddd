"""Saved proof recovery without replay, substituted controls or implicit closure."""
from __future__ import annotations

import json
from copy import deepcopy
import unittest
from unittest.mock import patch

from awa_ddd import completeness, engine
from awa_ddd.__main__ import _dispatch
from awa_ddd.assessment import record_finding
from awa_ddd.assessment_preparation import prepare
from awa_ddd.store import EngineError
import test_finding_binding_20261103 as binding_fixtures


class AssessmentPreparationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = binding_fixtures.FindingBindingTests(
            "test_binding_appends_a_typed_finding_and_preserves_old_proof_with_a_lifecycle_revision")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.project = self.fixture.project

    def call(self, action, **args):
        return _dispatch(self.project.workspace, action, {"project_id": self.project.project_id, **args})

    def controls(self):
        source = "http://canary.invalid/bounded-fixture"
        rows = [self.fixture.capture(source, response={"value": "CANARY-2048-FIXTURE"}),
                self.fixture.capture("http://ordinary.invalid/bounded-fixture")]
        item = next(item for item in self.project.list("obligation") if item.get("test_family") == "ssrf")
        return rows, item

    def test_saved_exact_input_controls_are_reviewed_without_mutation_or_network(self):
        controls, item = self.controls()
        before = self.fixture.snapshot()
        with patch.object(engine, "request") as network:
            result = self.call("assessment.prepare", obligation_id=item["id"])
        network.assert_not_called()
        self.assertEqual(before, self.fixture.snapshot())
        self.assertEqual([row["id"] for row in controls], result["items"][0]["control_candidate_evidence_ids"])
        self.assertEqual("inspect_existing", result["items"][0]["preparation_state"])
        option = result["items"][0]["oracle_options"][0]
        self.assertEqual({"type": "extraction", "test_family": "ssrf"}, option["oracle_template"])
        self.assertIn("source_reference", option["required_fields"])
        self.assertNotIn("expected_value", option["oracle_template"])
        self.assertEqual(0, result["requests_sent"])
        self.assertEqual(0, result["decisions_created"])
        self.assertIs(result["automatic_execution_allowed"], False)
        self.assertIs(result["continuation"]["can_claim_complete"], False)
        self.assertNotIn("CANARY-2048-FIXTURE", json.dumps(result))
        self.assertNotIn("http://canary.invalid", json.dumps(result))

    def test_later_same_value_captures_cannot_hide_an_original_findings_controls(self):
        controls, item = self.controls()
        finding = self.fixture.original(controls)
        self.fixture.capture("http://canary.invalid/bounded-fixture", response={"value": "CANARY-2048-FIXTURE"})
        self.fixture.capture("http://ordinary.invalid/bounded-fixture")
        with patch.object(engine, "request") as network:
            result = self.call("assessment.prepare", finding_id=finding["id"], limit=10)
        network.assert_not_called()
        row = next(row for row in result["items"] if row["obligation_id"] == item["id"])
        self.assertEqual([capture["id"] for capture in controls], row["control_candidate_evidence_ids"])
        self.assertEqual("inspect_existing", row["preparation_state"])

    def test_narrowed_support_never_substitutes_excluded_proof_or_suggests_replay(self):
        proof, controls, item = self.fixture.proof()
        finding = self.fixture.original(controls)
        excluded, selected = controls
        result = self.call("assessment.prepare", finding_id=finding["id"], evidence_ids=[selected["id"]], limit=10)
        row = next(row for row in result["items"] if row["obligation_id"] == item["id"])
        self.assertEqual("proof_outside_selection", row["preparation_state"])
        self.assertEqual({"evidence_id": selected["id"]}, row["input_template"])
        self.assertNotEqual("finding.bind", row["suggested_action"])
        self.assertNotIn(excluded["id"], json.dumps(result))
        self.assertEqual([], row["control_candidate_evidence_ids"])

    def test_current_proof_has_an_atomic_binding_pointer_for_its_original_manual_finding(self):
        proof, controls, item = self.fixture.proof()
        finding = self.fixture.original(controls)
        before = self.fixture.snapshot()
        result = self.call("assessment.prepare", finding_id=finding["id"], limit=10)
        row = next(row for row in result["items"] if row["obligation_id"] == item["id"])
        self.assertEqual("finding.bind", row["suggested_action"])
        self.assertEqual({"finding_id": finding["id"], "decision_id": proof["id"]}, row["input_template"])
        self.assertEqual(before, self.fixture.snapshot())
        with patch.object(engine, "request") as network:
            bound = self.call("finding.bind", **row["input_template"], reviewer="fixture reviewer", reason="Reviewed original controls")
        network.assert_not_called()
        self.assertEqual(proof["id"], bound["decision_id"])
        self.assertEqual("superseded", bound["previous_finding"]["lifecycle_status"])
        self.assertEqual(0, completeness.audit(self.project, {})["completion"]["unlinked_analyst_findings"])
        self.assertIs(bound["original_proof_preserved"], True)

    def test_unknown_business_input_has_a_valid_declaration_template_without_automatic_planning(self):
        operation = engine.register_operation(self.project, {"url": self.fixture.base + "/billing", "method": "GET", "auth": "public",
            "inputs": [{"name": "amount", "location": "query", "consumer": "unknown"}]})
        engine.build_plan(self.project)
        before = self.fixture.snapshot()
        result = self.call("assessment.prepare", operation_id=operation["id"], limit=10)
        row = next(row for row in result["items"] if row["obligation_kind"] == "input_review")
        self.assertEqual("needs_consumer", row["preparation_state"])
        self.assertIn("business_logic", row["suggested_test_families"])
        self.assertIs(row["positive_machine_adapter"], False)
        self.assertEqual(before, self.fixture.snapshot())
        self.assertEqual({"operation_id": operation["id"], "input_location": "query", "input_selector": "amount"}, row["input_template"])
        self.call(row["suggested_action"], **row["input_template"], consumer="business_amount", test_families=["business_logic"])
        active = [item for item in self.project.list("obligation") if item["operation_id"] == operation["id"] and not item.get("superseded")]
        self.assertTrue(any(item.get("test_family") == "business_logic" for item in active))
        self.assertTrue(all(item["status"] == "open" for item in active))

    def test_evidence_target_anchors_the_input_context_instead_of_selecting_another_fixture(self):
        operation = engine.register_operation(self.project, {"url": self.fixture.base + "/fetch", "method": "GET", "auth": "public",
            "inputs": [{"name": "url", "location": "query", "consumer": "outbound_http", "test_families": ["ssrf"]},
                       {"name": "id", "location": "query"}]})
        engine.build_plan(self.project)
        own = [self.fixture.capture(value, operation=operation, url=operation["url"] + "?url=" + value + "&id=own")
               for value in ("source-one", "negative-one")]
        other = [self.fixture.capture(value, operation=operation, url=operation["url"] + "?url=" + value + "&id=other")
                 for value in ("source-two", "negative-two")]
        result = self.call("assessment.prepare", evidence_id=own[0]["id"], limit=10)
        row = next(row for row in result["items"] if row.get("test_family") == "ssrf")
        self.assertEqual([capture["id"] for capture in own], row["control_candidate_evidence_ids"])
        self.assertTrue(set(row["control_candidate_evidence_ids"]).isdisjoint(capture["id"] for capture in other))

    def test_repeated_state_readbacks_use_a_real_saved_scenario_without_replaying_writes(self):
        proof, controls, run = self.fixture.state_proof()
        item = self.project.get("obligation", proof["obligation_id"])
        item.update(status="open")
        self.project.put("obligation", item)
        finding = record_finding(self.project, self.fixture.analyst_args([capture["id"] for capture in controls], category="交易篡改"))
        with patch.object(engine, "request") as network:
            result = self.call("assessment.prepare", finding_id=finding["id"], limit=10)
        network.assert_not_called()
        row = next(row for row in result["items"] if row["obligation_id"] == item["id"])
        self.assertEqual([run["id"]], row["scenario_run_ids"])
        self.assertIn("state_transition", [option["oracle_type"] for option in row["oracle_options"]])
        by_obligation = self.call("assessment.prepare", obligation_id=item["id"])
        self.assertEqual([run["id"]], by_obligation["items"][0]["scenario_run_ids"])
        forged = deepcopy(run)
        forged["id"] = self.project.id("SC")
        self.project.put("run", forged)
        self.project.event("scenario.completed", {"run_id": forged["id"], "steps": 3})
        by_obligation = self.call("assessment.prepare", obligation_id=item["id"])
        self.assertEqual([run["id"]], by_obligation["items"][0]["scenario_run_ids"])
        run["checkpoints"][1]["concurrent"] = 2
        self.project.put("run", run)
        result = self.call("assessment.prepare", finding_id=finding["id"], limit=10)
        row = next(row for row in result["items"] if row["obligation_id"] == item["id"])
        self.assertEqual([], row["scenario_run_ids"])

    def test_xss_runtime_template_uses_analyst_mode_and_never_invents_a_runtime(self):
        operation = engine.register_operation(self.project, {"url": self.fixture.base + "/render", "method": "GET", "auth": "public",
            "inputs": [{"name": "content", "location": "query", "consumer": "html_render", "test_families": ["xss"]}]})
        engine.build_plan(self.project)
        controls = [self.fixture.capture(value, operation=operation) for value in ("normal", "variant")]
        item = next(row for row in self.project.list("obligation") if row.get("test_family") == "xss")
        result = self.call("assessment.prepare", obligation_id=item["id"])
        row = result["items"][0]
        self.assertEqual("finding.record", row["assessment_action"])
        self.assertEqual("analyst", row["assessment_template"]["mode"])
        self.assertEqual([capture["id"] for capture in controls], row["assessment_template"]["evidence_ids"])
        self.assertEqual({"name": "finding.record"}, row["help_input"])
        self.assertNotIn("runtime_visit_id", row["assessment_template"])
        self.assertIs(row["positive_machine_adapter"], False)

    def test_unlinked_findings_receive_a_precise_offline_preparation_handoff(self):
        controls, item = self.controls()
        finding = self.fixture.original(controls)
        result = self.call("plan.audit", limit=100)
        row = next(row for row in result["checklist"] if row.get("finding_id") == finding["id"])
        self.assertEqual("assessment.prepare", row["suggested_action"])
        self.assertEqual({"finding_id": finding["id"]}, row["input_template"])
        before = self.fixture.snapshot()
        with patch.object(engine, "request") as network:
            self.call(row["suggested_action"], **row["input_template"])
        network.assert_not_called()
        self.assertEqual(before, self.fixture.snapshot())

    def test_targets_and_selections_fail_without_mutation(self):
        controls, item = self.controls()
        other = engine.register_operation(self.project, {"url": self.fixture.base + "/other", "method": "GET", "auth": "public"})
        unrelated = self.fixture.capture(operation=other)
        for args in ({}, {"obligation_id": item["id"], "operation_id": self.fixture.operation["id"]},
                     {"obligation_id": item["id"], "evidence_ids": [unrelated["id"]]},
                     {"evidence_id": controls[0]["id"], "evidence_ids": [controls[1]["id"]]},
                     {"obligation_id": item["id"], "limit": True}):
            with self.subTest(args=args):
                before = self.fixture.snapshot()
                with patch.object(engine, "request") as network, self.assertRaises(EngineError):
                    self.call("assessment.prepare", **args)
                network.assert_not_called()
                self.assertEqual(before, self.fixture.snapshot())

    def test_current_plan_pointer_is_required_after_input_changes(self):
        controls, item = self.controls()
        engine.declare_consumer(self.project, {"operation_id": self.fixture.operation["id"], "input_location": "query",
                                              "input_selector": "url", "consumer": "outbound_http", "test_families": ["generic"]})
        with self.assertRaises(EngineError) as error:
            self.call("assessment.prepare", obligation_id=item["id"])
        self.assertEqual("obligation_superseded", error.exception.code)

    def test_private_collisions_preserve_only_engine_control_fields(self):
        controls, item = self.controls()
        actor = engine.add_actor(self.project, {"subject": "publication subject"})
        engine.add_session(self.project, {"actor_id": actor["id"], "headers": {"Authorization": "Bearer ssrf"}})
        result = self.call("assessment.prepare", obligation_id=item["id"])
        row = result["items"][0]
        self.assertEqual("ssrf", row["test_family"])
        self.assertEqual({"type": "extraction", "test_family": "ssrf"}, row["oracle_options"][0]["oracle_template"])
        self.assertNotIn("Bearer ssrf", json.dumps(result))
        self.assertNotIn("control_context_sha256", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
