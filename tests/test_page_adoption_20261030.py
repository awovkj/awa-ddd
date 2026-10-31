"""Saved rendering observations cannot disappear behind an empty page ledger."""
from __future__ import annotations

import tempfile
import unittest

from awa_ddd import browser, engine
from awa_ddd.store import EngineError, Project


class PageAdoptionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-page-adoption-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.tmp.name, {"project_id": "pages", "target": self.base})
        self.project = Project(self.tmp.name, "pages")
        self.addCleanup(self.project.close)

    def raw(self, **changes):
        return {"url": self.base + "/login", "finalUrl": self.base + "/home", "status": 200,
                "signals": {"hasApp": True, "forms": 1, "buttons": 1},
                "actions": [{"action": "click", "ok": True, "finalUrl": self.base + "/home"}],
                "network": [{"url": self.base + "/login", "method": "GET", "status": 200},
                            {"url": self.base + "/home", "method": "GET", "status": 200}], **changes}

    def test_successful_local_visit_adopts_navigation_without_http_or_function_claims(self):
        visit = browser._record_observation(self.project, self.raw(), "PV-local", "local_playwright")
        self.assertEqual(visit["page_adoption"], "adopted")
        self.assertEqual(len(visit["page_ids"]), 2)
        self.assertEqual(browser.coverage(self.project)["pages_visited"], 2)
        self.assertEqual(self.project.list("evidence"), [])
        self.assertEqual(self.project.list("finding"), [])
        page = browser.register_page(self.project, {"url": self.base + "/home", "name": "Home"})
        self.assertEqual(len(self.project.list("page")), 2)
        function = browser.register_function(self.project, {"page_id": page["id"], "name": "Payment"})
        self.assertFalse(function["triggered"])
        self.assertFalse(browser.coverage(self.project)["complete"])

    def test_imported_observation_needs_explicit_adoption_and_retains_provenance(self):
        visit = browser._record_observation(self.project, self.raw(), "PV-imported", "imported_mcp")
        self.assertEqual(self.project.list("page"), [])
        result = browser.adopt_visit(self.project, {"page_visit_id": visit["id"], "url": self.base + "/home"})
        self.assertEqual(result["requests_sent"], 0)
        self.assertEqual(result["source"], "imported_mcp")
        self.assertEqual(result["pages_adopted"], 1)
        self.assertFalse(self.project.get("page_visit", visit["id"])["machine_authenticated"])
        self.assertEqual(self.project.list("evidence"), [])

    def test_failed_or_corrupted_visits_do_not_manufacture_pages(self):
        visit = browser._record_observation(self.project, self.raw(status=404), "PV-failed", "local_playwright")
        self.assertEqual(self.project.list("page"), [])
        with self.assertRaises(EngineError):
            browser.adopt_visit(self.project, {"page_visit_id": visit["id"]})
        good = browser._record_observation(self.project, self.raw(), "PV-saved", "imported_mcp")
        (self.project.base / good["artifact_path"]).write_text("{}", encoding="utf-8")
        with self.assertRaises(EngineError):
            browser.adopt_visit(self.project, {"page_visit_id": good["id"]})
        self.assertEqual(self.project.list("page"), [])

    def test_repeated_adoption_reuses_pages_and_unrelated_url_is_rejected(self):
        visit = browser._record_observation(self.project, self.raw(), "PV-saved", "imported_mcp")
        first = browser.adopt_visit(self.project, {"page_visit_id": visit["id"]})
        second = browser.adopt_visit(self.project, {"page_visit_id": visit["id"]})
        self.assertEqual(first["page_ids"], second["page_ids"])
        with self.assertRaises(EngineError):
            browser.adopt_visit(self.project, {"page_visit_id": visit["id"], "url": self.base + "/not-observed"})
        self.assertEqual(len(self.project.list("page")), 2)


if __name__ == "__main__":
    unittest.main()
