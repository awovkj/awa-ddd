"""2.0 Universe, route parsing and attempt-aware scheduling regressions."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import v2_fixtures as fx
from awa_ddd.domain.repository import Repository
from awa_ddd.domain.universe import new_universe
from awa_ddd.planning import campaign as campaign_planning
from awa_ddd.planning import coverage, scheduler
from awa_ddd.planning.hypotheses import family_applicability, generate_hypotheses
from awa_ddd.planning.route_parser import parse_route_manifest


class RouteParserTests(unittest.TestCase):
    def test_nested_dynamic_hash_lazy_alias_and_catch_all_are_explicit(self):
        import tempfile
        from pathlib import Path
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "routes.json"
        path.write_text(json.dumps({
            "mode": "hash", "base": "/app",
            "routes": [
                {"path": "/", "name": "home", "children": [
                    {"path": "users/:id", "name": "user", "component": "() => import('x')"},
                    {"path": "alias", "alias": "/old", "redirect": "/new"},
                ]},
                {"path": "*", "name": "catch"},
                {"path": "${dynamic()}", "name": "unresolved"},
            ]}), encoding="utf-8")
        result = parse_route_manifest(path)
        paths = {row["path_template"] for row in result["routes"]}
        self.assertIn("/app/users/:id", paths)
        self.assertIn("/app/*", paths)
        self.assertTrue(any(row["lazy"] for row in result["routes"]))
        self.assertTrue(any(row["aliases"] for row in result["routes"]))
        self.assertGreaterEqual(result["unresolved_total"], 1)
        self.assertEqual("hash", result["mode"])


class UniverseAndSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.temporary, self.root = fx.workspace()
        self.addCleanup(self.temporary.cleanup)
        row = fx.project(self.root)
        fx.register(row, "http://fixture.invalid/api/search", "GET", "public", [
            {"name": "q", "location": "query", "selector": "q", "consumer": "sql_like",
             "test_families": ["sql_injection"]},
            {"name": "amount", "location": "query", "selector": "amount", "consumer": "unknown",
             "test_families": ["business_logic"]},
        ])
        fx.register(row, "http://fixture.invalid/api/orders", "GET", "public", [
            {"name": "id", "location": "query", "selector": "id", "consumer": "resource_reference",
             "test_families": ["xss"]},
        ])
        row.close()

    def test_universe_keeps_unknown_consumer_and_never_claims_site_wide(self):
        row = fx.project(self.root)
        universe = campaign_planning.build_universe(row)
        row.close()
        self.assertEqual("source_inventory", universe["completeness_level"])
        self.assertFalse(universe["site_wide_discovery_allowed"])
        self.assertEqual(1, universe["unknown_counts"]["unknown_consumer_total"])
        unknown = [item for item in universe["consumers"] if item["status"] == "unknown"]
        self.assertEqual(1, len(unknown))

    def test_complete_snapshot_alone_never_enables_site_wide_discovery(self):
        universe = new_universe(
            scope_epoch="scope",
            origins=["http://fixture.invalid"],
            routes=[], pages=[], functions=[], operations=[], inputs=[],
            consumers=[], sources=[], unknown_counts={},
            completeness_level="complete_snapshot",
        )
        self.assertEqual("complete_snapshot", universe["completeness_level"])
        self.assertFalse(universe["site_wide_discovery_allowed"])

    def test_saved_snapshot_advances_universe_and_invalidates_old_authority(self):
        temporary, root = fx.workspace()
        self.addCleanup(temporary.cleanup)
        project = fx.project(root)
        fx.register(project, "http://fixture.invalid/render", "GET", "public", [{
            "name": "label", "location": "query", "selector": "label",
            "consumer": "template_engine",
            "test_families": ["template_injection"],
        }])
        project.close()
        with patch.object(campaign_planning, "_gaps", return_value=[]):
            started = fx.start(root)
        real_family_matrix = coverage.family_applicability

        def single_mechanism_family_matrix(hypotheses):
            rows = real_family_matrix(hypotheses)
            for row in rows:
                if not row["total"]:
                    row["status"] = "not_applicable"
            return rows

        self.enterContext(patch.object(
            coverage, "family_applicability",
            new=single_mechanism_family_matrix))
        campaign_id = started["campaign"]["id"]
        recipe_id = fx.dispatch(root, "campaign.next", {
            "project_id": "v2", "campaign_id": campaign_id, "limit": 1,
        })["recipes"][0]["recipe"]["id"]
        with patch("awa_ddd.engine.request", side_effect=fx.Sequence([
                {"value": "AWA-NORMAL"}, {"value": "49"},
                {"value": "AWA-NORMAL-2"}])):
            run = fx.dispatch(root, "test.run", {
                "project_id": "v2", "campaign_id": campaign_id,
                "recipe_id": recipe_id, "idempotency_key": "before-advance",
            })
        self.assertEqual("supported", run["outcome"])
        reviewed = fx.dispatch(root, "campaign.review_frontier", {
            "project_id": "v2", "campaign_id": campaign_id,
        })
        self.assertEqual(1, reviewed["frontier_rounds"])
        checkpoint = fx.dispatch(root, "campaign.checkpoint", {
            "project_id": "v2", "campaign_id": campaign_id,
        })
        before = fx.dispatch(root, "campaign.status", {
            "project_id": "v2", "campaign_id": campaign_id,
        })
        self.assertEqual(1, before["continuation"]["frontier_rounds"])

        fx.dispatch(root, "surface.register", {
            "project_id": "v2",
            "url": "http://fixture.invalid/new-operation",
            "method": "GET", "auth": "public",
            "inputs": [{
                "name": "q", "location": "query", "selector": "q",
                "consumer": "business_input", "test_families": ["generic"],
            }],
        })
        snapshot = fx.dispatch(root, "recon.snapshot", {
            "project_id": "v2", "campaign_id": campaign_id, "save": True,
        })
        self.assertNotEqual(
            before["universe"]["id"], snapshot["universe"]["id"])
        after = fx.dispatch(root, "campaign.status", {
            "project_id": "v2", "campaign_id": campaign_id,
        })
        self.assertEqual(snapshot["universe"]["id"], after["universe"]["id"])
        self.assertEqual(0, after["continuation"]["frontier_rounds"])
        self.assertTrue(after["continuation"]["frontier_review_required"])
        self.assertFalse(after["completion_decision"]["checkpoint_current"])
        self.assertIn(
            "checkpoint_stale",
            after["completion_decision"]["reason_codes"],
        )
        self.assertGreater(after["open_hypothesis_count"], 0)
        self.assertFalse(after["continuation"]["can_finalize"])

        project = fx.project(root)
        try:
            repository = Repository(project)
            hypotheses = repository.list_campaign(
                "hypothesis", campaign_id, limit=None)[0]
            current = [row for row in hypotheses
                       if row.get("universe_id") == after["universe"]["id"]
                       and not row.get("superseded")]
            carried = next(
                row for row in current
                if row.get("family") == "template_injection")
            self.assertIn(run["run"]["id"], carried["run_ids"])
            self.assertTrue(any(row.get("family") == "generic"
                                for row in current))
            old = repository.get("checkpoint", checkpoint["checkpoint_id"])
            self.assertEqual(
                before["universe"]["snapshot_hash"],
                old["universe_snapshot_hash"],
            )
        finally:
            project.close()

    def test_hypothesis_generation_keeps_needs_consumer_and_all_families_visible(self):
        row = fx.project(self.root)
        universe = campaign_planning.build_universe(row)
        hypotheses, limited = generate_hypotheses(universe, [])
        row.close()
        self.assertFalse(limited)
        self.assertTrue(any(h["status"] == "blocked" and "actual_input_consumer" in h["missing_context"]
                            for h in hypotheses))
        matrix = family_applicability(hypotheses)
        self.assertEqual(12, len(matrix))
        business = next(item for item in matrix if item["test_family"] == "business_logic")
        self.assertGreater(business["total"], 0)

    def test_campaign_status_exposes_five_dimensions_and_twelve_families(self):
        fx.start(self.root)
        result = fx.dispatch(self.root, "campaign.status", {"project_id": "v2"})
        self.assertEqual({"discovery", "consumer", "hypothesis", "known_case", "machine_proof"},
                         set(result["dimensions"]))
        self.assertEqual(12, len(result["family_matrix"]))
        for name in ("discovery", "consumer", "hypothesis"):
            self.assertIn("denominator", result["dimensions"][name])

    def test_scheduler_returns_distinct_families_and_does_not_fabricate(self):
        row = fx.project(self.root)
        campaign = campaign_planning.start(row, {})
        c = Repository(row).get("campaign", campaign["campaign"]["id"])
        universe = Repository(row).get("universe", c["universe_id"])
        selected, preparation, queue = scheduler.next_hypotheses(row, c, universe, limit=3)
        families = [row["family"] for _, row in selected]
        self.assertEqual(len(families), len(set(families)))
        # Only ready families are returned; blocked preparation never becomes a fake recipe.
        self.assertTrue(all(status == "ready" for _, hypothesis in selected for status in [hypothesis["status"]]))
        row.close()

    def test_two_failures_trigger_cooldown_instead_of_repetition(self):
        row = fx.project(self.root)
        campaign = campaign_planning.start(row, {})
        c = Repository(row).get("campaign", campaign["campaign"]["id"])
        universe = Repository(row).get("universe", c["universe_id"])
        hypotheses = [h for h in Repository(row).list("hypothesis", limit=None)[0] if h["status"] == "ready"]
        target = hypotheses[0]
        target["attempt"] = {"attempt_count": 2, "consecutive_failures": 2,
                             "last_outcome": "inconclusive",
                             "cooldown_until": "2999-01-01T00:00:00+00:00"}
        Repository(row).save("hypothesis", target)
        selected, preparation, _ = scheduler.next_hypotheses(row, c, universe, limit=10)
        self.assertNotIn(target["id"], [h["id"] for _, h in selected])
        self.assertTrue(any(item.get("reason") == "attempt_cooldown" for item in preparation))
        row.close()

    def test_claim_is_exclusive_and_release_requires_owner(self):
        row = fx.project(self.root)
        campaign_planning.start(row, {})
        hypotheses = Repository(row).list("hypothesis", limit=None)[0]
        target = hypotheses[0]
        scheduler.claim(row, target["id"], worker_id="worker-a", ttl_seconds=60)
        with self.assertRaises(Exception):
            scheduler.claim(row, target["id"], worker_id="worker-b", ttl_seconds=60)
        with self.assertRaises(Exception):
            scheduler.release(row, target["id"], worker_id="worker-b")
        scheduler.release(row, target["id"], worker_id="worker-a")
        row.close()


if __name__ == "__main__":
    unittest.main()
