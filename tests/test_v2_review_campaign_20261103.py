"""2.0 review acceptance, campaign delivery, migration and report regressions."""
from __future__ import annotations

import unittest
from unittest.mock import patch

import v2_fixtures as fx
from awa_ddd import engine
from awa_ddd.assessment import evaluate
from awa_ddd.domain import new_hypothesis, new_review_contract
from awa_ddd.domain.repository import Repository
from awa_ddd.domain.review import validate_cross_role
from awa_ddd.store import EngineError


class ReviewContractTests(unittest.TestCase):
    def _contract(self, **changes):
        hypothesis = new_hypothesis(
            family="xss", security_property="stored_xss", operation_id="O-1", input_key="IN-1",
            scope_epoch="scope", target_build="build", source_kind="declared_family",
            statement="stored xss", status="ready")
        base = dict(
            hypothesis=hypothesis, run={"id": "RUN-1"},
            mechanism={"family": "xss", "security_property": "stored_xss",
                       "operation_id": "O-1", "input_key": "IN-1", "location": "body",
                       "selector": "label", "schema_branch": None},
            identity={"actor_id": "merchant", "resource_id": "RES-1"},
            control_groups=[
                {"id": "writer", "identity_role": "merchant", "resource_version": "v1", "controls": [
                    {"id": "normal", "role": "normal", "evidence_id": "E-1"},
                    {"id": "attack", "role": "attack", "evidence_id": "E-2", "content_digest": "d1"}]},
                {"id": "viewer", "identity_role": "admin", "resource_version": "v1", "controls": [
                    {"id": "normal", "role": "normal", "evidence_id": "E-3"},
                    {"id": "attack", "role": "attack", "evidence_id": "E-4", "content_digest": "d1"}]},
            ],
            observation={"selector": "dialog", "expected": "AWA-XSS", "actual": "AWA-XSS"},
            consumer_point={"type": "browser_runtime", "url": "http://fixture.invalid/admin", "identity_role": "admin"},
            source_trust={"kind": "independent_analyst", "trust": "verified"},
            reviewer={"type": "human_independent", "id": "reviewer-1", "source": "manual"},
            proof_scope={"accepted": ["stored_xss_cross_role"], "not_proven": ["code execution"]},
            material={"evidence_ids": ["E-1", "E-2", "E-3", "E-4"],
                      "digests": {name: "a" * 64 for name in ("E-1", "E-2", "E-3", "E-4")}},
            verification={"version": "1", "method": "manual_review"},
        )
        base.update(changes)
        return new_review_contract(**base)

    def test_cross_role_chain_requires_writer_viewer_and_same_content_version(self):
        contract = self._contract()
        hypothesis = new_hypothesis(
            family="xss", security_property="stored_xss", operation_id="O-1", input_key="IN-1",
            scope_epoch="scope", target_build="build", source_kind="declared_family",
            statement="stored xss", status="ready")
        self.assertTrue(validate_cross_role(contract, hypothesis=hypothesis, run={"id": "RUN-1"}))
        groups = contract["control_groups"]
        groups[1]["resource_version"] = "v2"
        with self.assertRaises(EngineError) as caught:
            validate_cross_role(contract, hypothesis=hypothesis, run={"id": "RUN-1"})
        self.assertEqual("v2_review_cross_role", caught.exception.code)

    def test_agent_recorded_review_cannot_self_declare_human_approval(self):
        with self.assertRaises(EngineError):
            self._contract(reviewer={"type": "agent_recorded", "id": "agent", "source": "model",
                                     "human_approved": True})

    def test_control_roles_are_mandatory(self):
        with self.assertRaises(EngineError):
            self._contract(control_groups=[{"id": "writer", "identity_role": "merchant",
                                            "controls": [{"id": "normal", "role": "normal", "evidence_id": "E-1"}]}])


class CampaignDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary, self.root = fx.workspace()
        self.addCleanup(self.temporary.cleanup)
        row = fx.project(self.root)
        fx.register(row, "http://fixture.invalid/render", "GET", "public", [
            {"name": "label", "location": "query", "selector": "label",
             "consumer": "template_engine", "test_families": ["template_injection"]}])
        row.close()
        self.campaign = fx.start(self.root)["campaign"]["id"]

    def test_partial_accepted_delivery_never_grants_exhaustion(self):
        result = fx.dispatch(self.root, "campaign.finish", {
            "project_id": "v2", "campaign_id": self.campaign, "reason": "partial_accepted",
            "accepted_by": "owner", "explanation": "bounded delivery"})
        self.assertEqual("delivered_partial", result["campaign"]["state"])
        self.assertFalse(result["delivery"]["exhausted_authority"])
        with self.assertRaises(EngineError) as caught:
            fx.dispatch(self.root, "report.build", {"project_id": "v2", "campaign_id": self.campaign,
                                                    "stage": "final"})
        self.assertEqual("v2_report_final", caught.exception.code)

    def test_completed_finish_rejects_remaining_work(self):
        with self.assertRaises(EngineError) as caught:
            fx.dispatch(self.root, "campaign.finish", {"project_id": "v2", "campaign_id": self.campaign,
                                                        "reason": "completed", "explanation": "premature"})
        self.assertEqual("v2_campaign_not_exhausted", caught.exception.code)

    def test_all_not_applicable_or_blocked_never_grants_exhaustion(self):
        row = fx.project(self.root)
        hypotheses = Repository(row).list("hypothesis", limit=None)[0]
        for item in hypotheses:
            item["status"] = "not_applicable"
            item["applicability_basis"] = {"business_fact": "fixture says no"}
            Repository(row).save("hypothesis", item)
        row.close()
        matrix = fx.dispatch(self.root, "report.matrix", {"project_id": "v2", "campaign_id": self.campaign})
        self.assertFalse(matrix["delivery"]["exhausted_authority"])
        self.assertEqual(0, matrix["dimensions"]["hypothesis"]["denominator"])

    def test_report_matrix_lists_12_families_and_denominators(self):
        result = fx.dispatch(self.root, "report.matrix", {"project_id": "v2", "campaign_id": self.campaign})
        self.assertEqual(12, len(result["family_matrix"]))
        self.assertEqual(5, len(result["dimensions"]))
        self.assertIn("denominators", result)
        self.assertEqual("engine", result["computed_by"])


class MigrationTests(unittest.TestCase):
    def test_legacy_decision_is_legacy_evaluation_not_synthetic_test_run(self):
        temporary, root = fx.workspace()
        self.addCleanup(temporary.cleanup)
        row = fx.project(root)
        operation = fx.register(row, "http://fixture.invalid/items", "GET", "public", [
            {"name": "q", "location": "query", "selector": "q", "consumer": "business_input",
             "test_families": ["generic"]}])
        engine.build_plan(row)
        obligation = next(item for item in row.list("obligation") if item["operation_id"] == operation["id"]
                          and item["kind"] == "baseline")
        with patch("awa_ddd.engine.request", side_effect=fx.Sequence([{"count": 1}])):
            evidence = engine.capture(row, {"operation_id": operation["id"],
                                            "url": operation["url"] + "?q=normal"})
        evaluate(row, {"obligation_id": obligation["id"], "evidence_ids": [evidence["id"]],
                       "oracle": {"type": "baseline", "selector": "/count", "expected": 1}})
        before_runs = len(row.list("run"))
        row.close()
        projection = fx.dispatch(root, "campaign.migrate", {"project_id": "v2"})
        self.assertEqual(0, projection["projection"]["synthetic_test_runs"])
        applied = fx.dispatch(root, "campaign.migrate", {"project_id": "v2", "apply": True, "confirm": True})
        self.assertGreater(applied["ledger"]["source_counts"]["decisions"], 0)
        row = fx.project(root)
        self.assertGreater(len(row.list("v2_legacy_evaluation")), 0)
        self.assertEqual(0, len(row.list("v2_run")))
        self.assertEqual(before_runs, len(row.list("run")))
        self.assertTrue(row.list("decision"))
        row.close()


if __name__ == "__main__":
    unittest.main()
