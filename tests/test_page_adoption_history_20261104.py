"""Multiple real observations of one page retain separate, revalidated archives."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import browser, completeness, engine
from awa_ddd.store import EngineError, Project, canonical


class PageAdoptionHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-page-adoption-history-")
        self.addCleanup(self.tmp.cleanup)
        self.base = "http://fixture.invalid"
        engine.create_project(self.tmp.name, {"project_id": "history", "target": self.base})
        self.project = Project(self.tmp.name, "history")
        self.addCleanup(self.project.close)

    def visit(self, identity, source="local_playwright", path="/home"):
        url = self.base + path
        raw = {"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1},
               "title": identity, "network": [{"url": url, "method": "GET", "status": 200}],
               "actions": [{"action": "click", "ok": True, "finalUrl": url}]}
        browser._record_observation(self.project, raw, identity, source)
        return self.project.get("page_visit", identity)

    def audit(self):
        with patch.object(engine, "request") as requests, patch.object(browser.subprocess, "run") as runtime:
            result = completeness.audit(self.project, {"limit": 100})
        requests.assert_not_called()
        runtime.assert_not_called()
        return result

    def snapshot(self):
        return ([tuple(row) for row in self.project.connection.execute("SELECT * FROM entities ORDER BY kind,id")],
                [tuple(row) for row in self.project.connection.execute("SELECT * FROM events ORDER BY seq")],
                self.project.config)

    def legacy(self):
        """Recreate the exact pre-upgrade entity and event shapes in a fixture."""
        with self.project.transaction():
            for visit in self.project.list("page_visit"):
                visit.pop("page_adoptions", None)
                self.project.put("page_visit", visit)
            for row in self.project.connection.execute("SELECT seq,type,document FROM events").fetchall():
                event = json.loads(row[2])
                if row[1] in {"browser.visited", "browser.imported_mcp"}:
                    for key in ("actor_id", "session_id", "session_generation"):
                        event.pop(key, None)
                elif row[1] in {"page.marked", "page.visit_adopted"}:
                    event.pop("sha256", None)
                self.project.connection.execute("UPDATE events SET document=? WHERE seq=?", (canonical(event), row[0]))

    def test_two_local_visits_to_the_same_page_remain_archived(self):
        first = self.visit("PV-first")
        second = self.visit("PV-second")
        page = self.project.list("page")[0]
        self.assertEqual("PV-second", page["page_visit_id"])
        self.assertEqual(1, len(first["page_adoptions"]))
        self.assertEqual(1, len(second["page_adoptions"]))
        self.assertEqual(0, self.audit()["completion"]["orphan_browser_visits"])
        self.assertEqual({"PV-first", "PV-second"},
                         {entry["page_visit_id"] for entry in browser.validated_adoptions(self.project)})
        self.assertEqual(1, browser.coverage(self.project)["pages_visited"])
        self.assertEqual([], self.project.list("evidence"))
        self.assertEqual([], self.project.list("decision"))

    def test_explicit_imported_adoptions_keep_both_visits_without_upgrading_provenance(self):
        first = self.visit("PV-imported-first", "imported_mcp")
        second = self.visit("PV-imported-second", "imported_mcp")
        self.assertEqual(2, self.audit()["completion"]["orphan_browser_visits"])
        for visit in (first, second):
            receipt = browser.adopt_visit(self.project, {"page_visit_id": visit["id"]})
            self.assertEqual(0, receipt["requests_sent"])
            self.assertEqual(0, receipt["functions_marked"])
        self.assertEqual(0, self.audit()["completion"]["orphan_browser_visits"])
        for visit in self.project.list("page_visit"):
            self.assertEqual("imported_mcp", visit["source"])
            self.assertFalse(visit["machine_authenticated"])
            self.assertIsNone(visit["actor_id"])
        self.assertEqual([], self.project.list("finding"))

    def test_repeated_old_adoption_does_not_move_latest_pointer_or_create_progress(self):
        first = self.visit("PV-first")
        self.visit("PV-second")
        self.audit()
        before = self.snapshot()
        progress = engine.evaluate_coverage(self.project)["continuation"]
        for _ in range(3):
            receipt = browser.adopt_visit(self.project, {"page_visit_id": first["id"]})
            self.assertEqual(1, receipt["pages_adopted"])
        self.assertEqual(before, self.snapshot())
        after = engine.evaluate_coverage(self.project)["continuation"]
        for key in ("progress_id", "semantic_progress_id", "snapshot_id"):
            if key in progress:
                self.assertEqual(progress[key], after[key])
        self.assertEqual("PV-second", self.project.list("page")[0]["page_visit_id"])

    def test_corrupted_older_artifact_reopens_only_that_observation(self):
        first = self.visit("PV-first")
        self.visit("PV-second")
        path = self.project.base / first["artifact_path"]
        original = path.read_bytes()
        path.write_text("{}", encoding="utf-8")
        audit = self.audit()
        self.assertEqual(1, audit["completion"]["orphan_browser_visits"])
        orphan = next(row for row in audit["checklist"] if row["kind"] == "orphan_browser_visit")
        self.assertEqual(first["id"], orphan["page_visit_id"])
        self.assertTrue(orphan["browser_testing"]["execution_blocked"])
        self.assertFalse(orphan["browser_testing"]["invoke_now"])
        self.assertEqual(1, browser.coverage(self.project)["pages_visited"])
        with self.assertRaises(EngineError):
            browser.adopt_visit(self.project, {"page_visit_id": first["id"]})
        path.write_bytes(original)
        self.assertEqual(0, self.audit()["completion"]["orphan_browser_visits"])

    def test_rewriting_artifact_and_mutable_digest_cannot_replace_the_original_receipt(self):
        first = self.visit("PV-first")
        self.visit("PV-second")
        raw = self.project.read_artifact(first)
        raw["title"] = "replacement"
        data = canonical(raw).encode("utf-8")
        (self.project.base / first["artifact_path"]).write_bytes(data)
        first["sha256"] = hashlib.sha256(data).hexdigest()
        self.project.put("page_visit", first)
        self.assertEqual(1, self.audit()["completion"]["orphan_browser_visits"])
        with self.assertRaises(EngineError) as caught:
            browser.adopt_visit(self.project, {"page_visit_id": first["id"]})
        self.assertEqual("page_evidence_invalid", caught.exception.code)

    def test_changed_source_or_identity_reopens_archived_observation(self):
        first = self.visit("PV-first", "imported_mcp")
        browser.adopt_visit(self.project, {"page_visit_id": first["id"]})
        original = self.project.get("page_visit", first["id"])
        for changes in ({"source": "local_playwright"}, {"actor_id": "unobserved-actor"},
                        {"session_id": "unobserved-session"}, {"session_generation": 42}):
            with self.subTest(changes=changes):
                self.project.put("page_visit", {**original, **changes})
                self.assertEqual([], browser.validated_adoptions(self.project))
                self.assertEqual(1, self.audit()["completion"]["orphan_browser_visits"])
        self.project.put("page_visit", original)
        self.assertEqual(0, self.audit()["completion"]["orphan_browser_visits"])

    def test_current_scope_exclusion_reopens_all_archives_without_a_target_request(self):
        self.visit("PV-first")
        self.visit("PV-second")
        config = self.project.config
        self.project.set_config({**config, "exclude": [self.base + "/home"]})
        before = self.snapshot()
        audit = self.audit()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(2, audit["completion"]["orphan_browser_visits"])
        self.assertEqual(0, browser.coverage(self.project)["pages_visited"])
        self.assertEqual([], browser.validated_adoptions(self.project))
        self.project.set_config(config)
        self.assertEqual(0, self.audit()["completion"]["orphan_browser_visits"])

    def test_blocker_invalidates_old_adoptions_until_each_is_explicitly_reviewed_again(self):
        first = self.visit("PV-first")
        second = self.visit("PV-second")
        page = self.project.list("page")[0]
        browser.mark(self.project, {"page_id": page["id"], "target": "page", "status": "BLOCKED",
                                    "reason": "The consumer page must be reviewed again."})
        self.assertEqual(2, self.audit()["completion"]["orphan_browser_visits"])
        self.visit("PV-third")
        # A new observation can cover the current page, but cannot retroactively
        # adopt the two observations preceding its explicit blocker.
        self.assertEqual(2, self.audit()["completion"]["orphan_browser_visits"])
        for visit in (first, second):
            browser.adopt_visit(self.project, {"page_visit_id": visit["id"]})
        self.assertEqual(0, self.audit()["completion"]["orphan_browser_visits"])

    def test_legacy_adoption_events_restore_multiple_visits_read_only(self):
        self.visit("PV-legacy-first")
        self.visit("PV-legacy-second")
        self.legacy()
        self.audit()
        before = self.snapshot()
        self.assertEqual({"PV-legacy-first", "PV-legacy-second"},
                         {entry["page_visit_id"] for entry in browser.validated_adoptions(self.project)})
        self.assertEqual(0, self.audit()["completion"]["orphan_browser_visits"])
        self.assertEqual(before, self.snapshot())
        self.visit("PV-new")
        self.assertEqual(0, self.audit()["completion"]["orphan_browser_visits"])

    def test_legacy_flags_without_actual_adoption_events_leave_the_observation_unreviewed(self):
        first = self.visit("PV-first")
        self.visit("PV-second")
        self.legacy()
        with self.project.transaction():
            for row in self.project.connection.execute("SELECT seq,type,document FROM events").fetchall():
                event = json.loads(row[2])
                if row[1] in {"page.marked", "page.visit_adopted"} \
                        and event.get("visit_id", event.get("page_visit_id")) == first["id"]:
                    self.project.connection.execute("DELETE FROM events WHERE seq=?", (row[0],))
        self.assertEqual(1, self.audit()["completion"]["orphan_browser_visits"])
        self.assertEqual({"PV-second"}, {entry["page_visit_id"] for entry in browser.validated_adoptions(self.project)})

    def test_adoption_does_not_mark_an_unobserved_function_triggered(self):
        self.visit("PV-first")
        self.visit("PV-second")
        page = self.project.list("page")[0]
        function = browser.register_function(self.project, {"page_id": page["id"], "name": "Payment"})
        self.assertFalse(function["triggered"])
        self.assertEqual(0, self.audit()["completion"]["orphan_browser_visits"])
        self.assertEqual(1, browser.coverage(self.project)["functions"])
        self.assertEqual(0, browser.coverage(self.project)["functions_triggered"])


if __name__ == "__main__":
    unittest.main()
