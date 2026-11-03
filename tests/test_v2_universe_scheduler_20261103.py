"""2.0 Universe, route parsing and attempt-aware scheduling regressions."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import v2_fixtures as fx
from awa_ddd.domain.repository import Repository
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
