"""V2 campaign continuation uses one completion authority and current receipts."""
from __future__ import annotations

import hashlib
import unittest
from unittest.mock import patch

import v2_fixtures as fx
from awa_ddd import engine
from awa_ddd.domain import (
    new_dependency,
    new_frontier_receipt,
)
from awa_ddd.domain.common import digest
from awa_ddd.domain.receipt import entity_dependency
from awa_ddd.domain.repository import Repository
from awa_ddd.completion import CompletionEvaluator
from awa_ddd.planning import campaign as campaign_planning
from awa_ddd.store import EngineError


class CampaignCompletionTests(unittest.TestCase):
    def setUp(self):
        self.temporary, self.root = fx.workspace()
        self.addCleanup(self.temporary.cleanup)
        project = fx.project(self.root)
        fx.register(
            project,
            "http://fixture.invalid/render",
            "GET",
            "public",
            [{
                "name": "label",
                "location": "query",
                "selector": "label",
                "consumer": "template_engine",
                "test_families": ["template_injection"],
            }],
        )
        project.close()
        self.campaign_id = fx.start(self.root)["campaign"]["id"]

    def test_status_and_checkpoint_expose_the_same_completion_object(self):
        status = fx.dispatch(self.root, "campaign.status", {
            "project_id": "v2",
            "campaign_id": self.campaign_id,
        })
        self.assertEqual(
            status["completion_decision"],
            status["continuation"]["completion_decision"],
        )
        checkpoint = fx.dispatch(self.root, "campaign.checkpoint", {
            "project_id": "v2",
            "campaign_id": self.campaign_id,
            "label": "completion authority",
        })
        self.assertEqual(
            checkpoint["completion_decision"],
            checkpoint["continuation"]["completion_decision"],
        )
        self.assertEqual(
            status["completion_decision"]["schema"],
            checkpoint["completion_decision"]["schema"],
        )

    def test_running_work_is_recoverable_but_interrupted_or_unknown_is_review(self):
        hypotheses = [
            {"id": "H-RECOVER", "status": "running"},
            {"id": "H-STALE", "status": "running"},
            {"id": "H-UNKNOWN", "status": "running"},
            {
                "id": "H-BLOCKED",
                "status": "blocked",
                "missing_context": ["state_readback"],
                "attempt": {"last_outcome": "effect_unknown"},
            },
            {
                "id": "H-RECONCILED",
                "status": "blocked",
                "missing_context": ["state_readback"],
                "attempt": {"last_outcome": "effect_unknown"},
            },
            {"id": "H-READY", "status": "ready"},
        ]
        runs = [
            {
                "hypothesis_id": "H-RECOVER",
                "status": "evaluation_pending",
                "effect": {"unknown": False},
            },
            {
                "hypothesis_id": "H-STALE",
                "status": "interrupted",
                "effect": {"unknown": False},
            },
            {
                "hypothesis_id": "H-UNKNOWN",
                "status": "effect_unknown",
                "effect": {"unknown": True},
            },
            {
                "hypothesis_id": "H-BLOCKED",
                "status": "effect_unknown",
                "effect": {"unknown": True},
            },
            {
                "hypothesis_id": "H-RECONCILED",
                "status": "interrupted",
                "effect": {"unknown": False},
                "effect_unknown": False,
                "reconciliation_id": "REC-verified",
            },
        ]
        work = campaign_planning._work_categories(
            hypotheses,
            runs,
            [{"id": "G-1", "kind": "consumer", "scope": "IN-1"}],
            {
                "consumers": [{
                    "input_key": "IN-1",
                    "status": "unknown",
                }],
                "routes": [],
                "unknown_counts": {"truncated_source_total": 1},
            },
        )
        self.assertIn("H-RECOVER", work["recoverable"])
        self.assertIn("H-RECOVER", work["ready"])
        self.assertIn("H-READY", work["ready"])
        self.assertIn("running:H-STALE", work["review"])
        self.assertIn("H-UNKNOWN", work["effect_unknown"])
        self.assertIn("H-BLOCKED", work["effect_unknown"])
        self.assertIn("effect-unknown:H-RECONCILED", work["review"])
        self.assertNotIn("H-BLOCKED", work["blocked"])
        self.assertNotIn("H-RECONCILED", work["blocked"])
        self.assertEqual(
            {"consumer:IN-1", "source-truncated:0"},
            work["unresolved"],
        )

    def test_frontier_rounds_require_distinct_current_bound_material(self):
        project = fx.project(self.root)
        repository = Repository(project)
        campaign = repository.get("campaign", self.campaign_id)
        universe = repository.get("universe", campaign["universe_id"])
        matrix = campaign_planning.coverage.compute(
            project, self.campaign_id)
        dependencies = [
            entity_dependency(
                project, "campaign", campaign["id"],
                fingerprint_fields=(
                    "id", "project_id", "target", "objective", "model",
                    "scope_snapshot", "exclude_snapshot", "scope_epoch",
                    "max_rounds", "allow_mutation")),
            entity_dependency(
                project, "universe", universe["id"],
                fingerprint_fields=("id", "snapshot_hash", "scope_epoch")),
        ]

        def add(round_key, round_hash):
            receipt = new_frontier_receipt(
                campaign_id=campaign["id"],
                topic="Universe-reviewed frontier",
                material={
                    "campaign_id": campaign["id"],
                    "universe_id": universe["id"],
                    "universe_snapshot_hash": universe["snapshot_hash"],
                    "round_key": round_key,
                    "round_sha256": round_hash,
                    "boundary_complete": True,
                },
                dependencies=dependencies,
                reviewer={
                    "type": "agent_recorded",
                    "id": "frontier-agent",
                    "source": "fixture",
                },
                unresolved_items=[],
            )
            repository.add("frontier_receipt", receipt, immutable=True)

        first_hash = hashlib.sha256(b"frontier-one").hexdigest()
        add("round-a", first_hash)
        add("round-b-rewording", first_hash)
        state = campaign_planning._frontier_state(
            project, campaign, matrix)
        self.assertEqual(1, state["frontier_rounds"])
        self.assertFalse(state["frontier_current"])

        second_hash = hashlib.sha256(b"frontier-two").hexdigest()
        add("round-c", second_hash)
        state = campaign_planning._frontier_state(
            project, campaign, matrix)
        self.assertEqual(2, state["frontier_rounds"])
        self.assertTrue(state["frontier_current"])
        project.close()

    def test_public_frontier_reviews_support_completed_delivery(self):
        temporary, root = fx.workspace()
        self.addCleanup(temporary.cleanup)
        project = fx.project(root)
        fx.register(
            project,
            "http://fixture.invalid/render",
            "GET",
            "public",
            [{
                "name": "label",
                "location": "query",
                "selector": "label",
                "consumer": "template_engine",
                "test_families": ["template_injection"],
            }],
        )
        project.close()
        # Keep this end-to-end fixture focused on one mechanism. All campaign
        # state transitions and every receipt below still use public actions;
        # in particular no test-internal FrontierReceipt write is involved.
        with patch.object(campaign_planning, "_gaps", return_value=[]):
            started = fx.start(root)
        real_family_matrix = campaign_planning.coverage.family_applicability

        def single_mechanism_family_matrix(hypotheses):
            rows = real_family_matrix(hypotheses)
            for row in rows:
                if not row["total"]:
                    row["status"] = "not_applicable"
            return rows

        self.enterContext(patch.object(
            campaign_planning.coverage, "family_applicability",
            new=single_mechanism_family_matrix))
        campaign_id = started["campaign"]["id"]
        next_page = fx.dispatch(root, "campaign.next", {
            "project_id": "v2", "campaign_id": campaign_id, "limit": 1,
        })
        recipe_id = next_page["recipes"][0]["recipe"]["id"]
        hypothesis_id = next_page["recipes"][0]["hypothesis"]["id"]

        def run(key, normal, negative):
            with patch("awa_ddd.engine.request", side_effect=fx.Sequence([
                    {"value": normal, "observation": key},
                    {"value": "49", "observation": key},
                    {"value": negative, "observation": key}])):
                return fx.dispatch(root, "test.run", {
                    "project_id": "v2", "campaign_id": campaign_id,
                    "recipe_id": recipe_id, "idempotency_key": key,
                })

        first_run = run("public-frontier-one", "AWA-NORMAL", "AWA-NORMAL-2")
        self.assertEqual("supported", first_run["outcome"])
        first = fx.dispatch(root, "campaign.review_frontier", {
            "project_id": "v2", "campaign_id": campaign_id,
            "reviewer_id": "public-frontier-reviewer",
        })
        self.assertTrue(first["receipt_current"])
        self.assertFalse(first["reused"])
        self.assertEqual(1, first["frontier_rounds"])
        self.assertEqual(
            "accepted", first["frontier_receipt"]["decision"])
        duplicate = fx.dispatch(root, "campaign.review_frontier", {
            "project_id": "v2", "campaign_id": campaign_id,
            "reviewer_id": "public-frontier-reviewer",
            "topic": "A new label is not another semantic round",
        })
        self.assertTrue(duplicate["reused"])
        self.assertEqual(
            first["frontier_receipt"]["id"],
            duplicate["frontier_receipt"]["id"],
        )
        self.assertEqual(1, duplicate["frontier_rounds"])

        fx.dispatch(root, "review.disposition", {
            "project_id": "v2", "campaign_id": campaign_id,
            "hypothesis_id": hypothesis_id, "status": "ready",
            "reason": "Collect an independent semantic observation round",
        })
        second_run = run(
            "public-frontier-two", "AWA-NORMAL", "AWA-NORMAL-2")
        self.assertEqual("supported", second_run["outcome"])
        second = fx.dispatch(root, "campaign.review_frontier", {
            "project_id": "v2", "campaign_id": campaign_id,
            "reviewer_id": "public-frontier-reviewer",
        })
        self.assertEqual(2, second["frontier_rounds"])
        self.assertNotEqual(
            first["frontier_receipt"]["material"]["round_sha256"],
            second["frontier_receipt"]["material"]["round_sha256"],
        )
        checkpoint = fx.dispatch(root, "campaign.checkpoint", {
            "project_id": "v2", "campaign_id": campaign_id,
            "label": "two public semantic frontier rounds",
        })
        self.assertEqual(2, len(
            checkpoint["checkpoint"]["frontier_receipt_ids"]))
        delivered = fx.dispatch(root, "campaign.finish", {
            "project_id": "v2", "campaign_id": campaign_id,
            "reason": "completed", "explanation": "Public API completion",
        })
        self.assertEqual("completed", delivered["campaign"]["state"])
        self.assertTrue(delivered["completion_decision"]["can_claim_complete"])
        self.assertTrue(delivered["delivery"]["exhausted_authority"])
        self.assertTrue(delivered["delivery"]["acceptance_id"].startswith("CDA-"))
        status = fx.dispatch(root, "campaign.status", {
            "project_id": "v2", "campaign_id": campaign_id,
        })
        self.assertTrue(status["continuation"]["automatic_stop_allowed"])

    def test_finish_uses_gated_revision_and_rolls_back_acceptance_on_conflict(self):
        fx.dispatch(self.root, "campaign.checkpoint", {
            "project_id": "v2", "campaign_id": self.campaign_id,
            "label": "revision gate",
        })
        original_deliver = campaign_planning.deliver

        def advance_during_gate(*args, **kwargs):
            other = fx.project(self.root)
            try:
                repository = Repository(other)
                current = repository.get("campaign", self.campaign_id)
                current["cursor"] = {
                    **(current.get("cursor") or {}), "offset": 17,
                }
                repository.save("campaign", current)
            finally:
                other.close()
            return original_deliver(*args, **kwargs)

        with patch.object(
                campaign_planning, "deliver", side_effect=advance_during_gate):
            with self.assertRaises(EngineError) as caught:
                fx.dispatch(self.root, "campaign.finish", {
                    "project_id": "v2", "campaign_id": self.campaign_id,
                    "reason": "partial_accepted",
                    "accepted_by": "fixture-owner",
                    "explanation": "stale revision must not deliver",
                })
        self.assertEqual("revision_conflict", caught.exception.code)
        project = fx.project(self.root)
        try:
            repository = Repository(project)
            current = repository.get("campaign", self.campaign_id)
            self.assertEqual("active", current["state"])
            self.assertIsNone(current["delivery"])
            self.assertEqual([], repository.list_campaign(
                "completion_acceptance", self.campaign_id, limit=None)[0])
        finally:
            project.close()

    def test_completion_rejects_stale_checkpoint_even_when_work_is_empty(self):
        project = fx.project(self.root)
        repository = Repository(project)
        campaign = repository.get("campaign", self.campaign_id)
        universe = repository.get("universe", campaign["universe_id"])
        empty = {
            "ready": set(),
            "review": set(),
            "blocked": set(),
            "unresolved": set(),
            "effect_unknown": set(),
        }
        matrix = {
            "universe": {
                "unknown_counts": {
                    "registered_operation_total": 1,
                    "page_total": 0,
                    "source_inventory_complete": True,
                },
                "snapshot_hash": universe["snapshot_hash"],
            },
            "delivery": {"exhausted_authority": True},
            "receipt_summary": {
                "applicability_reopened": 0,
                "proof_reopened": 0,
            },
            "finding_summary": {"expired_or_invalid_total": 0},
            "_work": empty,
            "_frontier": {
                "frontier_current": True,
                "frontier_rounds": 2,
            },
        }
        decision = campaign_planning._completion(
            project,
            campaign,
            matrix,
            checkpoint_current=False,
            next_action="campaign.checkpoint",
        )
        self.assertFalse(decision["can_finalize"])
        self.assertIn("checkpoint_stale", decision["reason_codes"])
        decision = campaign_planning._completion(
            project,
            campaign,
            matrix,
            checkpoint_current=True,
            next_action="campaign.finish",
        )
        self.assertTrue(decision["can_finalize"])
        project.close()

    def test_delivery_does_not_self_invalidate_its_checkpoint(self):
        checkpoint = fx.dispatch(self.root, "campaign.checkpoint", {
            "project_id": "v2",
            "campaign_id": self.campaign_id,
            "label": "delivery binding",
        })
        delivered = fx.dispatch(self.root, "campaign.finish", {
            "project_id": "v2",
            "campaign_id": self.campaign_id,
            "reason": "partial_accepted",
            "accepted_by": "fixture-owner",
            "explanation": "bounded compatibility delivery",
        })
        self.assertEqual(
            checkpoint["checkpoint_id"],
            delivered["delivery"]["checkpoint_id"],
        )
        self.assertTrue(
            delivered["continuation"]["completion_decision"][
                "checkpoint_current"
            ]
        )
        self.assertFalse(
            delivered["completion_decision"]["can_finalize"])
        self.assertFalse(
            delivered["completion_decision"]["can_claim_complete"])
        self.assertFalse(
            delivered["continuation"]["automatic_stop_allowed"])
        acceptance_id = delivered["delivery"]["acceptance_id"]
        self.assertTrue(acceptance_id.startswith("CDA-"))
        project = fx.project(self.root)
        try:
            acceptance = Repository(project).get(
                "completion_acceptance", acceptance_id)
        finally:
            project.close()
        self.assertEqual(self.campaign_id, acceptance["campaign_id"])
        self.assertEqual("partial_accepted", acceptance["reason"])
        self.assertEqual("fixture-owner", acceptance["accepted_by"])
        self.assertEqual(
            delivered["completion_decision"]["id"],
            acceptance["completion_decision_id"],
        )
        self.assertFalse(acceptance["exhausted_authority"])
        self.assertFalse(acceptance["automatic_stop_allowed"])

        with self.assertRaises(EngineError) as caught:
            fx.dispatch(self.root, "campaign.finish", {
                "project_id": "v2",
                "campaign_id": self.campaign_id,
                "reason": "partial_accepted",
                "accepted_by": "replacement-owner",
                "explanation": "attempted overwrite",
            })
        self.assertEqual("v2_campaign_frozen", caught.exception.code)

    def test_partial_acceptance_cannot_borrow_a_ready_completion_decision(self):
        decision = CompletionEvaluator.evaluate(
            model="v2",
            subject_id="CAM-PARTIAL",
            has_scope=True,
            coverage_complete=True,
            counts={
                "ready": 0,
                "review": 0,
                "blocked": 0,
                "unresolved": 0,
                "effect_unknown": 0,
            },
            frontier_current=True,
            finalized=False,
            partial_accepted=True,
        )
        self.assertEqual("partial_accepted", decision["state"])
        self.assertFalse(decision["can_finalize"])
        self.assertFalse(decision["can_claim_complete"])
        self.assertTrue(decision["continue_required"])

    def test_partial_delivery_and_bounded_ids_survive_redaction_without_stopping(self):
        checkpoint = fx.dispatch(self.root, "campaign.checkpoint", {
            "project_id": "v2",
            "campaign_id": self.campaign_id,
            "label": "publication binding",
        })
        delivered = fx.dispatch(self.root, "campaign.finish", {
            "project_id": "v2",
            "campaign_id": self.campaign_id,
            "reason": "partial_accepted",
            "accepted_by": "fixture-owner",
            "explanation": "private bounded delivery explanation",
        })
        baseline = fx.dispatch(self.root, "campaign.status", {
            "project_id": "v2",
            "campaign_id": self.campaign_id,
        })
        secrets = {
            value
            for bucket in baseline["bounded_ids"].values()
            for value in bucket["ids"]
        }
        secrets.update({
            delivered["delivery"]["completion_decision_id"],
            delivered["delivery"]["acceptance_id"],
            checkpoint["checkpoint_id"],
            baseline["universe"]["snapshot_hash"],
            "partial_accepted",
            "private bounded delivery explanation",
        })
        with patch.object(
                engine, "request",
                side_effect=AssertionError("Unexpected target traffic")) as network:
            project = fx.project(self.root)
            try:
                actor = engine.add_actor(project, {
                    "subject": "fixture-publication-collision",
                })
                for secret in sorted(secrets):
                    engine.add_session(project, {
                        "actor_id": actor["id"],
                        "headers": {"Authorization": "Bearer " + secret},
                    })
            finally:
                project.close()

            for unavailable in (False, True):
                with self.subTest(unavailable=unavailable), patch(
                        "awa_ddd.browser.learn_redaction_context",
                        return_value={
                            "page_visit_ids": ["PV-unavailable"] if unavailable else [],
                            "run_ids": [],
                        }):
                    public = fx.dispatch(self.root, "campaign.status", {
                        "project_id": "v2",
                        "campaign_id": self.campaign_id,
                    })
                self.assertEqual(self.campaign_id, public["campaign"]["id"])
                self.assertEqual(
                    baseline["bounded_ids"], public["bounded_ids"])
                self.assertEqual(
                    baseline["universe"]["snapshot_hash"],
                    public["universe"]["snapshot_hash"],
                )
                for delivery in (public["delivery"], public["campaign"]["delivery"]):
                    for key in ("checkpoint_id", "completion_decision_id", "acceptance_id"):
                        self.assertEqual(delivered["delivery"][key], delivery[key])
                    self.assertEqual("partial_accepted", delivery["reason"])
                    self.assertIs(False, delivery["exhausted_authority"])
                    self.assertNotEqual(
                        "private bounded delivery explanation", delivery["explanation"])
                self.assertIs(False, public["completion_decision"]["can_claim_complete"])
                self.assertIs(False, public["continuation"]["automatic_stop_allowed"])
                self.assertIs(True, public["completion_decision"]["continue_required"])
                if unavailable:
                    self.assertEqual("unavailable", public["redaction_context_status"])
            network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
