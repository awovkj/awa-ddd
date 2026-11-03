"""Small queue pages retain bounded independent parameter cursors without target traffic."""
from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import completeness, engine, workflow
from awa_ddd.store import Project


class ProjectionPaginationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="awa-projection-pagination-")
        self.addCleanup(self.temporary.cleanup)
        engine.create_project(self.temporary.name, {"project_id": "paging", "target": "http://fixture.invalid"})
        self.project = Project(self.temporary.name, "paging")
        self.addCleanup(self.project.close)
        engine.register_operation(self.project, {"url": "http://fixture.invalid/items", "method": "GET", "auth": "public",
            "inputs": [{"name": f"field_{index}", "location": "query", "consumer": "business_input",
                        "test_families": ["generic"]} for index in range(12)]})
        engine.build_plan(self.project)

    def test_independent_default_follows_small_primary_page(self):
        for action in (workflow.next_work, completeness.audit):
            for limit in (1, 2, 10):
                with self.subTest(action=action.__name__, limit=limit), patch.object(engine, "request") as network:
                    result = action(self.project, {"limit": limit, "parameter_offset": 4, "parameter_status": "untested"})
                network.assert_not_called()
                parameters = result["parameter_coverage"]
                self.assertEqual(parameters["limit"], min(limit, 3))
                self.assertEqual(parameters["offset"], 4)
                self.assertEqual(parameters["next_offset"], 4 + min(limit, 3))
                self.assertEqual(parameters["filter"], "untested")
                self.assertEqual(parameters["summary"]["cell_total"], 12)
                self.assertEqual(parameters["summary"]["typed_tested_total"], 0)
                self.assertTrue(result["continuation"]["continue_required"])

    def test_explicit_independent_page_is_preserved(self):
        for action in (workflow.next_work, completeness.audit):
            with self.subTest(action=action.__name__), patch.object(engine, "request") as network:
                result = action(self.project, {"limit": 1, "parameter_limit": 5,
                    "parameter_offset": 3, "parameter_status": "untested"})
            network.assert_not_called()
            parameters = result["parameter_coverage"]
            self.assertEqual(parameters["limit"], 5)
            self.assertEqual(len(parameters["items"]), 5)
            self.assertEqual(parameters["next_offset"], 8)
            self.assertEqual(result["limit"], 1)


if __name__ == "__main__":
    unittest.main()
