"""Receipt authority and campaign isolation regressions for the V2 closure path."""
from __future__ import annotations

import unittest
from unittest.mock import patch

import v2_fixtures as fx
from awa_ddd.domain import new_dependency, new_proof_receipt
from awa_ddd.domain.common import digest, stable_id, utc_now
from awa_ddd.domain.receipt import evaluate_receipt
from awa_ddd.domain.repository import Repository
from awa_ddd.execution import review_engine
from awa_ddd.planning import coverage, scheduler
from awa_ddd.store import EngineError


def _proof_scope():
    return {"accepted": ["unexpected_expression_evaluation"], "not_proven": []}


def _proof_dependencies(*, campaign="CAM-1", hypothesis="HYP-1", run="RUN2-1",
                        evidence="E-1"):
    return [
        new_dependency(
            kind="scope", identity="project_scope", fingerprint="1" * 64),
        new_dependency(
            kind="target_build", identity="UNI-1", fingerprint="2" * 64,
            metadata={"universe_id": "UNI-1", "target_build": "build-1"}),
        new_dependency(
            kind="campaign", identity=campaign, fingerprint="3" * 64),
        new_dependency(
            kind="hypothesis", identity=hypothesis, fingerprint="4" * 64),
        new_dependency(
            kind="run", identity=run, fingerprint="5" * 64),
        new_dependency(
            kind="evidence", identity=evidence, fingerprint="6" * 64),
    ]


def _new_proof(*, dependencies=None, evidence_ids=None, run_id="RUN2-1"):
    evidence_ids = evidence_ids or ["E-1"]
    return new_proof_receipt(
        campaign_id="CAM-1",
        hypothesis_id="HYP-1",
        run_id=run_id,
        mode="machine",
        proof_scope=_proof_scope(),
        not_proven=[],
        material={
            "evidence_ids": evidence_ids,
            "digests": {identity: digest(identity) for identity in evidence_ids},
        },
        reviewer={
            "type": "analyst_recorded",
            "id": "machine-oracle",
            "source": "awa-ddd.oracle",
        },
        dependencies=_proof_dependencies() if dependencies is None else dependencies,
    )


class AcceptedReceiptTests(unittest.TestCase):
    def test_proof_requires_the_complete_dependency_spine(self):
        complete = _new_proof()
        self.assertEqual("proof", complete["kind"])
        for index, dependency in enumerate(complete["dependencies"]):
            self.assertIn(dependency["kind"], {
                "scope", "target_build", "campaign", "hypothesis", "run", "evidence"})
            self.assertGreaterEqual(index, 0)
        with self.assertRaises(EngineError) as caught:
            _new_proof(dependencies=_proof_dependencies()[:-1])
        self.assertEqual("v2_receipt_dependency", caught.exception.code)

    def test_legacy_receipt_is_quarantined_instead_of_current(self):
        receipt = {
            "schema": 2,
            "kind": "proof",
            "campaign_id": "CAM-1",
            "hypothesis_id": "HYP-1",
            "run_id": "RUN2-1",
            "review_id": None,
            "mode": "machine",
            "proof_scope": _proof_scope(),
            "material": {
                "evidence_ids": ["E-1"],
                "digests": {"E-1": digest("E-1")},
            },
            "reviewer": {
                "type": "analyst_recorded",
                "id": "legacy",
                "source": "migration",
            },
            "dependencies": [],
            "decision": "accepted",
            "created_at": utc_now(),
        }
        receipt["id"] = stable_id("PRC", receipt)
        receipt["receipt_hash"] = digest(receipt)
        temporary, root = fx.workspace()
        self.addCleanup(temporary.cleanup)
        row = fx.project(root)
        evaluation = evaluate_receipt(row, receipt)
        row.close()
        self.assertEqual("legacy", evaluation["status"])
        self.assertFalse(evaluation["current"])
        self.assertTrue(evaluation["quarantined"])


class CampaignIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temporary, self.root = fx.workspace()
        self.addCleanup(self.temporary.cleanup)
        row = fx.project(self.root)
        fx.register(row, "http://fixture.invalid/render", "GET", "public", [
            {"name": "label", "location": "query", "selector": "label",
             "consumer": "template_engine",
             "test_families": ["template_injection"]},
        ])
        row.close()
        self.campaign_a = fx.start(self.root)["campaign"]["id"]
        self.campaign_b = fx.start(
            self.root, new_campaign=True, objective="isolated campaign")["campaign"]["id"]

    def _recipe(self, campaign_id):
        return fx.dispatch(self.root, "campaign.next", {
            "project_id": "v2", "campaign_id": campaign_id, "limit": 1,
        })["recipes"][0]

    def test_run_proof_finding_lease_and_review_do_not_cross_campaigns(self):
        selected_a = self._recipe(self.campaign_a)
        selected_b = self._recipe(self.campaign_b)
        self.assertNotEqual(
            selected_a["hypothesis"]["id"], selected_b["hypothesis"]["id"])

        row = fx.project(self.root)
        scheduler.claim(
            row, selected_a["hypothesis"]["id"], worker_id="worker-a",
            campaign_id=self.campaign_a, ttl_seconds=60)
        with self.assertRaises(EngineError) as lease_error:
            scheduler.claim(
                row, selected_a["hypothesis"]["id"], worker_id="worker-b",
                campaign_id=self.campaign_b, ttl_seconds=60)
        self.assertEqual("v2_campaign_scope", lease_error.exception.code)
        scheduler.release(
            row, selected_a["hypothesis"]["id"], worker_id="worker-a",
            campaign_id=self.campaign_a)
        row.close()

        transport = fx.Sequence([
            {"value": "AWA-NORMAL"}, {"value": "49"}, {"value": "AWA-NORMAL-2"},
        ])
        with patch("awa_ddd.engine.request", side_effect=transport):
            result = fx.dispatch(self.root, "test.run", {
                "project_id": "v2",
                "campaign_id": self.campaign_a,
                "recipe_id": selected_a["recipe"]["id"],
                "idempotency_key": "campaign-a-proof",
            })
        self.assertEqual("supported", result["outcome"])
        self.assertEqual(self.campaign_a, result["finding"]["campaign_id"])
        self.assertEqual(self.campaign_a, result["proof_receipt"]["campaign_id"])

        matrix_project = fx.project(self.root)
        try:
            matrix_a = coverage.compute(matrix_project, self.campaign_a)
            matrix_b = coverage.compute(matrix_project, self.campaign_b)
        finally:
            matrix_project.close()
        self.assertEqual(1, matrix_a["finding_summary"]["current_total"])
        self.assertEqual(0, matrix_b["finding_summary"]["current_total"])
        self.assertNotEqual(
            selected_a["hypothesis"]["id"], selected_b["hypothesis"]["id"])
        self.assertNotEqual(
            selected_a["recipe"]["id"], selected_b["recipe"]["id"])

        row = fx.project(self.root)
        repository = Repository(row)
        run_a = repository.require_campaign(
            "run", result["run"]["id"], self.campaign_a)
        self.assertEqual(self.campaign_b, repository.require_campaign(
            "hypothesis", selected_b["hypothesis"]["id"], self.campaign_b)["campaign_id"])
        self.assertEqual([], repository.list_campaign(
            "finding", self.campaign_b, limit=None)[0])
        self.assertEqual([], repository.list_campaign(
            "proof_receipt", self.campaign_b, limit=None)[0])
        for gap in repository.list_campaign("gap", self.campaign_b, limit=None)[0]:
            self.assertEqual(self.campaign_b, gap["campaign_id"])

        with self.assertRaises(EngineError) as review_error:
            review_engine.accept(row, {
                "campaign_id": self.campaign_b,
                "hypothesis_id": selected_a["hypothesis"]["id"],
                "run_id": run_a["id"],
            })
        self.assertEqual("v2_campaign_scope", review_error.exception.code)

        with self.assertRaises(EngineError) as run_error:
            fx.dispatch(self.root, "test.run", {
                "project_id": "v2",
                "campaign_id": self.campaign_b,
                "recipe_id": selected_a["recipe"]["id"],
                "idempotency_key": "wrong-campaign",
            })
        self.assertEqual("v2_campaign_scope", run_error.exception.code)
        row.close()


if __name__ == "__main__":
    unittest.main()
