"""Unresolved-candidate lifecycle: stable identity, no silent loss, no auto-confirmation."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from awa_ddd import engine
from awa_ddd.candidates import (DISMISSED, LINKED, UNVERIFIED, candidate_id,
                                dismiss_candidate, inspect_candidate,
                                link_candidate, list_candidates, reopen_candidate,
                                store_candidate)
from awa_ddd.store import EngineError, Project
from awa_ddd.__main__ import dispatch


def discovery_candidate(**overrides):
    row = {"kind": "operation_hint", "url": "http://127.0.0.1:9/api/items",
           "method": None, "sources": [{"path": "app.js", "sha256": "a" * 64,
                                        "locator": "line:12", "trust": "declared"}]}
    row.update(overrides)
    return row


class CandidateLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-cand-")
        self.addCleanup(self.tmp.cleanup)
        engine.create_project(self.tmp.name, {"project_id": "cand", "target": "http://127.0.0.1:9",
                                              "scope": ["http://127.0.0.1:9"]})
        self.project = Project(self.tmp.name, "cand")
        self.addCleanup(self.project.close)

    def _operation(self, url="http://127.0.0.1:9/api/items", method="GET", inputs=None):
        return engine.register_operation(self.project, {
            "url": url, "method": method, "protocol": "http", "auth": "unknown",
            "inputs": inputs or []})

    def test_identity_is_stable_across_repeated_imports(self):
        row = discovery_candidate()
        first, created = store_candidate(self.project, row)
        second, again = store_candidate(self.project, row)
        self.assertEqual(first, second, "the same source location must keep one identity")
        self.assertTrue(created)
        self.assertFalse(again, "a repeat import must not report a new线索")
        self.assertEqual(1, len(self.project.list("candidate")))

    def test_identity_uses_source_digest_local_only(self):
        # 同一 locator 但不同来源摘要（文件已变）得到不同身份，线索不会互相覆盖。
        a = candidate_id(discovery_candidate())
        changed = discovery_candidate(sources=[{"path": "app.js", "sha256": "b" * 64,
                                                "locator": "line:12", "trust": "declared"}])
        self.assertNotEqual(a, candidate_id(changed))

    def test_merging_sources_preserves_human_disposition(self):
        row = discovery_candidate()
        identity, _ = store_candidate(self.project, row)
        dismiss_candidate(self.project, {"candidate_id": identity, "reason": "duplicate of a registered operation"})
        second = discovery_candidate(sources=row["sources"] + [
            {"path": "app.js", "sha256": "a" * 64, "locator": "line:40", "trust": "declared"}])
        store_candidate(self.project, second)
        stored = self.project.get("candidate", identity)
        self.assertEqual(DISMISSED, stored["status"], "re-import must not silently revive a dismissed线索")
        self.assertEqual(2, len(stored["sources"]))

    def test_list_pages_and_reports_counts(self):
        for index in range(3):
            store_candidate(self.project, discovery_candidate(
                url="http://127.0.0.1:9/api/item%d" % index))
        page = list_candidates(self.project, {"limit": 2})
        self.assertEqual(2, len(page["candidates"]))
        self.assertEqual(3, page["candidate_total"])
        self.assertEqual(2, page["next_offset"])
        tail = list_candidates(self.project, {"offset": page["next_offset"], "limit": 2})
        self.assertIsNone(tail["next_offset"])
        self.assertEqual(UNVERIFIED, page["candidates"][0]["status"])

    def test_list_rejects_unbounded_limits(self):
        for args in ({"limit": 0}, {"limit": 501}, {"offset": -1}, {"limit": "2"}):
            with self.assertRaises(EngineError):
                list_candidates(self.project, args)

    def test_link_requires_registered_operation_input(self):
        operation = self._operation(inputs=[{"name": "id", "location": "query", "selector": "id"}])
        identity, _ = store_candidate(self.project, discovery_candidate(
            url=operation["url"]))
        with self.assertRaises(EngineError):
            link_candidate(self.project, {"candidate_id": identity, "operation_id": operation["id"],
                                          "input_location": "query", "input_selector": "absent"})
        linked = link_candidate(self.project, {"candidate_id": identity, "operation_id": operation["id"],
                                               "input_location": "query", "input_selector": "id"})
        self.assertEqual(LINKED, linked["status"])
        self.assertEqual(operation["id"], linked["link"]["operation_id"])

    def test_link_rejects_operation_with_a_different_url(self):
        operation = self._operation(url="http://127.0.0.1:9/api/other")
        identity, _ = store_candidate(self.project, discovery_candidate())
        with self.assertRaises(EngineError):
            link_candidate(self.project, {"candidate_id": identity, "operation_id": operation["id"]})

    def test_link_requires_both_input_fields(self):
        operation = self._operation()
        identity, _ = store_candidate(self.project, discovery_candidate(url=operation["url"]))
        with self.assertRaises(EngineError):
            link_candidate(self.project, {"candidate_id": identity, "operation_id": operation["id"],
                                          "input_location": "query"})

    def test_linking_closes_no_obligation_and_creates_no_evidence(self):
        operation = self._operation()
        identity, _ = store_candidate(self.project, discovery_candidate(url=operation["url"]))
        before = engine.evaluate_coverage(self.project)
        link_candidate(self.project, {"candidate_id": identity, "operation_id": operation["id"]})
        after = engine.evaluate_coverage(self.project)
        self.assertEqual(before["evaluated"], after["evaluated"],
                         "a discovery线索 must never satisfy a coverage obligation")
        self.assertEqual([], self.project.list("evidence"))
        self.assertEqual([], self.project.list("decision"))

    def test_dismissal_requires_a_reason_and_is_not_a_test(self):
        identity, _ = store_candidate(self.project, discovery_candidate())
        with self.assertRaises(EngineError):
            dismiss_candidate(self.project, {"candidate_id": identity})
        with self.assertRaises(EngineError):
            dismiss_candidate(self.project, {"candidate_id": identity, "reason": "   "})
        dismissed = dismiss_candidate(self.project, {"candidate_id": identity, "reason": "out of the current run"})
        self.assertEqual(DISMISSED, dismissed["status"])
        with self.assertRaises(EngineError):
            link_candidate(self.project, {"candidate_id": identity,
                                          "operation_id": self._operation()["id"]})

    def test_linked_candidate_cannot_be_dismissed(self):
        operation = self._operation()
        identity, _ = store_candidate(self.project, discovery_candidate(url=operation["url"]))
        link_candidate(self.project, {"candidate_id": identity, "operation_id": operation["id"]})
        with self.assertRaises(EngineError):
            dismiss_candidate(self.project, {"candidate_id": identity, "reason": "changed my mind"})

    def test_reopen_restores_unverified_and_drops_link(self):
        operation = self._operation()
        identity, _ = store_candidate(self.project, discovery_candidate(url=operation["url"]))
        link_candidate(self.project, {"candidate_id": identity, "operation_id": operation["id"]})
        reopened = reopen_candidate(self.project, {"candidate_id": identity, "reason": "source file changed"})
        self.assertEqual(UNVERIFIED, reopened["status"])
        self.assertNotIn("link", reopened)

    def test_inspect_returns_linked_operation(self):
        operation = self._operation()
        identity, _ = store_candidate(self.project, discovery_candidate(url=operation["url"]))
        self.assertIsNone(inspect_candidate(self.project, {"candidate_id": identity})["operation"])
        link_candidate(self.project, {"candidate_id": identity, "operation_id": operation["id"]})
        view = inspect_candidate(self.project, {"candidate_id": identity})
        self.assertEqual(operation["id"], view["operation"]["id"])

    def test_unknown_candidate_fails_closed(self):
        with self.assertRaises(EngineError):
            inspect_candidate(self.project, {"candidate_id": "C-missing"})


class CandidateSurfaceImportTests(unittest.TestCase):
    """surface.import 必须把解析不了的线索真的写进台账，而不是只计数。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awa-import-")
        self.addCleanup(self.tmp.cleanup)
        dispatch(self.tmp.name, "project.create", {"project_id": "imp", "target": "http://127.0.0.1:9",
                                                   "scope": ["http://127.0.0.1:9"]})
        self.source = Path(self.tmp.name) / "app.js"
        self.source.write_text(
            "const a = axios.post('/api/orders', {amount: 1});\n"
            "const b = fetch('/api/secret-' + name);\n", encoding="utf-8")

    def test_unresolved_method_becomes_a_persisted_candidate(self):
        result = dispatch(self.tmp.name, "surface.import",
                          {"project_id": "imp", "path": str(self.source), "format": "javascript"})
        self.assertGreaterEqual(result["candidates"], 1)
        listed = dispatch(self.tmp.name, "candidate.list", {"project_id": "imp"})
        self.assertGreaterEqual(listed["candidate_total"], 1)
        self.assertTrue(all(item["status"] == UNVERIFIED for item in listed["candidates"]))

    def test_reimport_does_not_multiply_candidates(self):
        first = dispatch(self.tmp.name, "surface.import",
                         {"project_id": "imp", "path": str(self.source), "format": "javascript"})
        second = dispatch(self.tmp.name, "surface.import",
                          {"project_id": "imp", "path": str(self.source), "format": "javascript"})
        self.assertGreaterEqual(first["candidate_total"], 1)
        self.assertEqual(0, second["candidates"], "identical source must not create new线索")
        self.assertEqual(first["candidate_total"], second["candidate_total"])

    def test_project_status_separates_candidate_states(self):
        dispatch(self.tmp.name, "surface.import",
                 {"project_id": "imp", "path": str(self.source), "format": "javascript"})
        status = dispatch(self.tmp.name, "project.status", {"project_id": "imp"})
        self.assertIn("candidate_states", status)
        self.assertEqual(status["candidates"], status["candidate_states"].get(UNVERIFIED, 0))


if __name__ == "__main__":
    unittest.main()
