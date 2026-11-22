"""V1 frontier and partial-acceptance receipt regressions."""
from __future__ import annotations

import re
import unittest
from unittest.mock import patch

import test_continuation_20261030 as fixtures
from awa_ddd import continuation, engine, publication
from awa_ddd.store import EngineError


FRONTIER_RECEIPT = re.compile(r"FRC-[a-f0-9]{64}")
COMPLETION_ACCEPTANCE = re.compile(r"CA-[a-f0-9]{64}")


class V1ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ContinuationTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.project = self.fixture.project

    def database_state(self):
        return {
            table: [tuple(row) for row in self.project.connection.execute(
                f"SELECT * FROM {table} ORDER BY 1,2")]
            for table in ("entities", "events", "metadata")
        }

    def test_frontier_receipt_is_content_addressed_and_deduplicates_labels(self):
        self.fixture.close_generic()
        frontier = self.fixture.frontier()
        first = self.fixture.checkpoint(frontier, label="frontier round one")
        repeated = self.fixture.checkpoint(frontier, label="renamed duplicate")

        first_id = first["frontier_receipt_id"]
        repeated_id = repeated["frontier_receipt_id"]
        self.assertRegex(first_id, FRONTIER_RECEIPT)
        self.assertEqual(first_id, repeated_id)
        self.assertEqual(
            first["frontier_receipt"], repeated["frontier_receipt"])
        self.assertEqual(1, repeated["continuation"]["frontier_rounds"])
        self.assertEqual(first_id, repeated["continuation"]["frontier_receipt_id"])
        self.assertFalse(repeated["continuation"]["can_finalize"])
        self.assertEqual(1, len(self.project.list("frontier_receipt")))

        changed = self.fixture.checkpoint(
            self.fixture.frontier(self.fixture.variant_evidence),
            label="new actual observation",
        )
        changed_id = changed["frontier_receipt_id"]
        self.assertRegex(changed_id, FRONTIER_RECEIPT)
        self.assertNotEqual(first_id, changed_id)
        self.assertEqual(2, changed["continuation"]["frontier_rounds"])
        self.assertTrue(changed["continuation"]["can_finalize"])
        self.assertEqual(2, len(self.project.list("frontier_receipt")))

    def test_frontier_receipt_tamper_is_not_counted_by_round_or_finalization(self):
        self.fixture.close_generic()
        first = self.fixture.checkpoint(self.fixture.frontier())
        receipt = self.project.get("frontier_receipt", first["frontier_receipt_id"])
        with self.project.transaction():
            self.project.connection.execute(
                "UPDATE entities SET document=? WHERE kind='frontier_receipt' AND id=?",
                (self.project.connection.execute(
                    "SELECT json_set(document,'$.observation_key',? ) FROM entities "
                    "WHERE kind='frontier_receipt' AND id=?",
                    ("FOM-" + "0" * 64, receipt["id"]),
                ).fetchone()[0], receipt["id"]),
            )
        current = engine.evaluate_coverage(self.project)["continuation"]
        self.assertEqual(0, current["frontier_rounds"])
        self.assertFalse(current["can_finalize"])
        self.assertIsNone(current["frontier_receipt_id"])

    def test_partial_acceptance_is_immutable_and_never_grants_exhaustion(self):
        checkpoint = self.fixture.checkpoint()
        accepted = continuation.accept_partial(self.project, {
            "checkpoint_id": checkpoint["checkpoint"]["id"],
            "accepted_by": "fixture-owner",
            "explanation": "Deliver the currently inspected evidence; restore the saved review queue.",
        })
        acceptance = accepted["partial_acceptance"]
        self.assertRegex(acceptance["id"], COMPLETION_ACCEPTANCE)
        self.assertFalse(acceptance["can_claim_complete"])
        self.assertFalse(acceptance["automatic_stop_allowed"])
        self.assertTrue(acceptance["continue_required"])
        self.assertEqual(
            acceptance["id"], accepted["continuation"]["partial_acceptance_id"])
        self.assertEqual(
            "partial_accepted",
            accepted["completion_decision"]["state"],
        )
        self.assertFalse(accepted["continuation"]["can_finalize"])
        self.assertFalse(accepted["continuation"]["automatic_stop_allowed"])
        self.assertTrue(accepted["continuation"]["continue_required"])
        self.assertEqual(
            acceptance, self.project.get("completion_acceptance", acceptance["id"]))

        before = self.database_state()
        repeated = continuation.accept_partial(self.project, {
            "checkpoint_id": checkpoint["checkpoint"]["id"],
            "accepted_by": "fixture-owner",
            "explanation": "Deliver the currently inspected evidence; restore the saved review queue.",
        })
        self.assertEqual(acceptance["id"], repeated["partial_acceptance"]["id"])
        self.assertEqual(before, self.database_state())
        self.assertEqual(1, len(self.project.list("completion_acceptance")))

    def test_partial_acceptance_rejects_stale_snapshot(self):
        checkpoint = self.fixture.checkpoint()
        self.fixture.register("/changed-after-checkpoint", inputs=[{
            "name": "q", "location": "query", "consumer": "business_input",
            "test_families": ["generic"],
        }])
        before = self.database_state()
        with patch.object(engine, "request") as network:
            with self.assertRaises(EngineError) as caught:
                continuation.accept_partial(self.project, {
                    "checkpoint_id": checkpoint["checkpoint"]["id"],
                    "accepted_by": "fixture-owner",
                    "explanation": "Stale snapshots must never be accepted as current.",
                })
            network.assert_not_called()
        self.assertEqual("checkpoint_stale", caught.exception.code)
        self.assertEqual(before, self.database_state())

    def test_partial_acceptance_rejects_already_exhausted_snapshot(self):
        self.fixture.close_generic()
        self.fixture.checkpoint(self.fixture.frontier())
        second = self.fixture.checkpoint(
            self.fixture.frontier(self.fixture.variant_evidence))
        self.assertTrue(second["continuation"]["can_finalize"])
        before = self.database_state()
        with self.assertRaises(EngineError) as caught:
            continuation.accept_partial(self.project, {
                "checkpoint_id": second["checkpoint"]["id"],
                "accepted_by": "fixture-owner",
                "explanation": "An exhausted current snapshot is not partial.",
            })
        self.assertEqual("partial_acceptance", caught.exception.code)
        self.assertEqual(before, self.database_state())

    def test_public_error_contract_contains_receipt_and_query_reasons(self):
        required = {
            "partial_acceptance",
            "frontier_receipt",
            "query_order",
            "projection_identity",
            "reconciliation_context",
            "reconciliation_evidence",
            "read_only",
        }
        self.assertEqual(set(), required - publication._ERROR_CODES)

    def test_reconciliation_run_handle_accepts_only_materialized_v2_runs(self):
        context = publication.PublicationContext(self.project)
        real = "RUN2-" + "a" * 32
        forged = "RUN2-" + "b" * 32
        self.project.put("v2_run", {"id": real})
        self.assertTrue(context.bound_handle("run", real))
        self.assertFalse(context.bound_handle("run", forged))


if __name__ == "__main__":
    unittest.main()
