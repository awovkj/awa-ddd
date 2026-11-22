"""V2 blocked work always names a concrete preparation path."""
from __future__ import annotations

import unittest

import v2_fixtures as fx
from awa_ddd.domain.repository import Repository
from awa_ddd.planning import scheduler


class BlockerPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary, self.root = fx.workspace()
        self.addCleanup(self.temporary.cleanup)
        project = fx.project(self.root)
        fx.register(
            project,
            "http://fixture.invalid/payments/7",
            "POST",
            "authenticated",
            [{
                "name": "amount",
                "location": "body",
                "selector": "amount",
                "consumer": "payment_service",
                "test_families": ["business_logic"],
            }],
        )
        project.close()
        self.campaign_id = fx.start(self.root)["campaign"]["id"]

    def test_state_readback_preparation_is_not_a_disposition_loop(self):
        project = fx.project(self.root)
        repository = Repository(project)
        hypothesis = next(
            row for row in repository.list_campaign(
                "hypothesis", self.campaign_id, limit=None)[0]
            if row.get("security_property") == "operation_idempotency"
        )
        project.close()

        fx.dispatch(self.root, "review.disposition", {
            "project_id": "v2",
            "campaign_id": self.campaign_id,
            "hypothesis_id": hypothesis["id"],
            "status": "blocked",
            "prerequisite": "A same-identity readback is required before the write.",
            "missing_context": ["state_readback"],
        })
        result = fx.dispatch(self.root, "campaign.next", {
            "project_id": "v2",
            "campaign_id": self.campaign_id,
            "limit": 25,
        })
        preparation = next(
            row for row in result["preparation"]
            if row.get("hypothesis_id") == hypothesis["id"]
        )
        self.assertEqual("scenario.preflight", preparation["next_action"])
        self.assertEqual(
            ["scenario.preflight"],
            [row["action"] for row in preparation["preparation_actions"]],
        )
        self.assertTrue(all(
            row["automatic_execution_allowed"] is False
            for row in preparation["preparation_actions"]
        ))

    def test_unknown_typed_context_uses_help_instead_of_circular_disposition(self):
        preparation = scheduler._preparation_entry({
            "id": "HYP-test",
            "family": "business_logic",
            "operation_id": "OP-test",
            "status": "blocked",
            "missing_context": ["browser_consumer_context"],
        })
        self.assertEqual("action.help", preparation["next_action"])
        self.assertEqual({
            "missing_context": "browser_consumer_context",
            "action": "action.help",
            "reason": (
                "Inspect the exact inputs, existing evidence and collection path."
            ),
            "help_input": {"name": "action.help"},
            "automatic_execution_allowed": False,
        }, preparation["preparation_actions"][0])


if __name__ == "__main__":
    unittest.main()
