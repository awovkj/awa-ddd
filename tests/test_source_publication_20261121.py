"""Source handoff controls survive redaction; source locators stay private."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from awa_ddd import __main__ as entry, engine, publication
from awa_ddd.store import EngineError, Project, canonical


class SourcePublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="awa-source-publication-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.base = "https://source-fixture.invalid"
        engine.create_project(self.root, {"project_id": "sources", "target": self.base})
        self.project = Project(self.root, "sources")
        self.addCleanup(self.project.close)
        guard = patch.object(engine, "request", side_effect=AssertionError("Unexpected target traffic"))
        self.network = guard.start()
        self.addCleanup(guard.stop)

    def call(self, action, **args):
        return entry.dispatch(self.root, action, {"project_id": "sources", **args})

    def source(self, name="pending_import"):
        path = self.root / "source.json"
        path.write_text(canonical({"openapi": "3.0.3", "servers": [{"url": self.base}],
            "paths": {"/records/" + name: {"get": {"parameters": [{"name": name, "in": "query"}]}}}}),
            encoding="utf-8")
        return path

    def credential(self, secret):
        actor = engine.add_actor(self.project, {"subject": "fixture-principal"})
        engine.add_session(self.project, {"actor_id": actor["id"], "headers": {"Authorization": "Bearer " + secret}})

    def missing_context(self):
        url = self.base + "/form"
        path = self.root / "browser.json"
        path.write_text(canonical({"url": url, "finalUrl": url, "status": 200, "signals": {"forms": 1},
            "network": [{"url": url, "method": "GET", "status": 200}],
            "actions": [{"type": "fill", "selector": "#field", "ok": True, "finalUrl": url}]}),
            encoding="utf-8")
        self.call("browser.import_mcp", path=str(path))

    def test_colliding_credentials_preserve_bound_ids_counts_and_handoff_but_scrub_locators(self):
        for secret in ("pending_import", "1", "preview", "apply", "surface.sources"):
            self.credential(secret)
        path = self.source()
        preview = self.call("surface.import", path=str(path), format="openapi", mode="preview")
        self.assertEqual("preview", preview["mode"])
        self.assertEqual(1, preview["source_inventory"]["pending_import_total"])
        self.assertIs(type(preview["source_inventory"]["known_route_total"]), int)
        self.assertEqual("pending_import", preview["results"][0]["status"])
        self.assertNotEqual("pending_import", preview["results"][0]["inputs"][0]["name"])
        self.assertFalse(preview["results"][0]["requestable"])
        original = self.project.get("discovery_item", preview["results"][0]["source_item_id"])
        self.assertEqual("pending_import", original["hint"]["inputs"][0]["name"])
        for secret in (preview["source_id"], preview["snapshot_id"], preview["results"][0]["source_item_id"]):
            self.credential(secret)
        listed = self.call("surface.sources", snapshot_id=preview["snapshot_id"])
        self.assertEqual(preview["source_id"], listed["source_id"])
        self.assertEqual(preview["snapshot_id"], listed["snapshot_id"])
        self.assertEqual(original["id"], listed["items"][0]["source_item_id"])
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), listed["snapshot"]["sha256"])
        self.assertEqual("valid", listed["snapshot_integrity"])
        self.assertFalse(listed["source_inventory"]["site_wide_discovery_allowed"])
        self.network.assert_not_called()

    def test_unavailable_context_keeps_source_pages_and_exact_closure_templates(self):
        self.missing_context()
        path = self.source("synthetic-private-route")
        preview = self.call("surface.import", path=str(path), format="openapi", mode="preview")
        self.assertEqual("unavailable", preview["redaction_context_status"])
        self.assertEqual(1, preview["result_total"])
        listed = self.call("surface.sources", snapshot_id=preview["snapshot_id"])
        self.assertEqual(preview["source_id"], listed["source"]["id"])
        self.assertEqual(preview["snapshot_id"], listed["snapshot"]["id"])
        self.assertEqual("pending_import", listed["items"][0]["status"])
        self.assertFalse(listed["items"][0]["requestable"])
        self.assertNotIn("synthetic-private-route", canonical(listed))
        for action, args, page in (("plan.audit", {}, "checklist"), ("plan.next", {"compact": True}, "review_followups")):
            public = self.call(action, **args)
            row = next(row for row in public[page] if row["kind"] == "discovery_source")
            self.assertEqual(preview["source_id"], row["discovery_source_id"])
            self.assertEqual(preview["snapshot_id"], row["snapshot_id"])
            self.assertEqual({"snapshot_id": preview["snapshot_id"], "mode": "apply"}, row["input_template"])
            self.assertIs(type(public["completion"]["unimported_source_items"]), int)
            self.assertFalse(public["continuation"]["can_finalize"])
        self.network.assert_not_called()

    def test_failed_publication_rolls_back_preview_source_items_and_events(self):
        path = self.source("atomic-preview")
        before = {table: [tuple(row) for row in self.project.connection.execute("SELECT * FROM " + table + " ORDER BY 1,2")]
                  for table in ("entities", "events", "metadata")}
        with patch.object(publication, "publish", side_effect=EngineError("publication_failed", "synthetic publication failure")):
            with self.assertRaises(EngineError):
                self.call("surface.import", path=str(path), format="openapi", mode="preview")
        after = {table: [tuple(row) for row in self.project.connection.execute("SELECT * FROM " + table + " ORDER BY 1,2")]
                 for table in ("entities", "events", "metadata")}
        self.assertEqual(before, after)
        self.network.assert_not_called()

    def test_complex_template_keeps_reason_and_binding_flags_when_reason_is_a_credential(self):
        self.credential("regex_pattern")
        self.credential("needs_binding")
        path = self.root / "complex-openapi.json"
        path.write_text(canonical({"openapi": "3.0.3", "servers": [{"url": self.base}],
            "paths": {"/records/{record:[0-9]+}": {"get": {}}}}), encoding="utf-8")
        preview = self.call("surface.import", path=str(path), format="openapi", mode="preview")
        self.assertEqual([], preview["operation_ids"])
        self.assertEqual(1, preview["source_inventory"]["needs_binding_total"])
        row = preview["results"][0]
        self.assertEqual("needs_binding", row["status"])
        self.assertEqual("regex_pattern", row["reason_code"])
        self.assertTrue(row["native_input_requires_binding"])
        self.assertFalse(row["requestable"])
        self.assertEqual([], row["inputs"])
        applied = self.call("surface.import", snapshot_id=preview["snapshot_id"], mode="apply")
        self.assertEqual(1, len(applied["candidate_ids"]))
        self.assertEqual([], applied["operation_ids"])
        self.assertFalse(applied["usable_for_confirmation"])
        self.network.assert_not_called()

    def test_actuator_unknown_container_retains_gap_and_readonly_handoff_without_rows(self):
        self.credential("1")
        path = self.root / "malformed-mappings.json"
        path.write_text(canonical({"contexts": {"synthetic": {"mappings": {"dispatcherServlets": "unknown"}}}}),
                        encoding="utf-8")
        preview = self.call("surface.import", path=str(path), format="actuator_mappings", base_url=self.base, mode="preview")
        self.assertEqual(0, preview["result_total"])
        self.assertEqual(1, preview["source_inventory"]["unresolved_total"])
        listed = self.call("surface.sources", snapshot_id=preview["snapshot_id"])
        self.assertEqual(1, listed["snapshot"]["inventory"]["unresolved_mapping_total"])
        self.assertFalse(listed["snapshot"]["inventory"]["site_wide_discovery_allowed"])
        audit = self.call("plan.audit")
        self.assertEqual("partial", audit["completion"]["status"])
        self.assertEqual(1, audit["completion"]["source_unresolved_total"])
        row = next(row for row in audit["checklist"] if row["kind"] == "discovery_source")
        self.assertEqual("surface.sources", row["suggested_action"])
        self.assertEqual({"snapshot_id": preview["snapshot_id"], "source_id": preview["source_id"]}, row["input_template"])
        self.assertFalse(row["administrative_review_allowed"])
        self.assertFalse(audit["continuation"]["can_finalize"])
        self.network.assert_not_called()

    def test_draft_summary_keeps_known_unregistered_source_denominator(self):
        preview = self.call("surface.import", path=str(self.source("draft-route")), format="openapi", mode="preview")
        report = self.call("report.build", stage="draft", output_dir=str(self.root / "reports"))
        summary = json.loads(Path(report["summary"]).read_text(encoding="utf-8"))
        self.assertEqual(preview["source_inventory"], summary["coverage"]["source_inventory"])
        self.assertEqual(1, summary["completion"]["unimported_source_items"])
        self.assertEqual("partial", summary["completion"]["status"])
        self.assertFalse(summary["continuation"]["can_finalize"])
        self.network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
